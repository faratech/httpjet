//! HTTP/3 over **pure io_uring**: a monoio io_uring UDP loop driving quinn's
//! sans-IO state machine (`quinn-proto`). This is the path quinn's high-level
//! `AsyncUdpSocket` can't take (its `try_send` is synchronous, so it can't use
//! io_uring) — instead we own the datagram loop: `recv_from` (io_uring) →
//! `Endpoint::handle` → `accept`/`poll_transmit` → `send_to` (io_uring), reusing
//! ALL of quinn-proto's QUIC + TLS-1.3 + loss-recovery logic (no fork, no QUIC
//! rewrite).
//!
//! The real-pipeline listener is the sole production H3 transport used by `serve`;
//! it shares the same request pipeline as H1/H2. A separate fixed-response entrypoint
//! remains below for isolated transport smoke tests.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use std::os::fd::{AsRawFd, BorrowedFd};

use bytes::{Bytes, BytesMut};
use hj_core::body_deadline::BodyProgress;
use monoio::net::udp::UdpSocket;
use quinn_proto::{
    ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event, ServerConfig,
    StreamEvent, StreamId, WriteError,
};
use quinn_udp::{Transmit as UdpTransmit, UdpSockRef, UdpSocketState};

use socket2::{Domain, Protocol, Socket, Type};

/// Max UDP datagram we read in one recv (QUIC datagrams are <= the path MTU;
/// 64 KiB covers any GRO-coalesced jumbo the kernel hands up).
const MAX_DATAGRAM: usize = 64 * 1024;
const GRO_BATCH: usize = 8;
/// Keep each readiness pass finite without falling back to one syscall at a time.
/// A full pass accepts up to 64 message slots, each of which may itself contain
/// multiple GRO-coalesced QUIC datagrams.
const MAX_RECV_DRAIN_BATCHES: usize = 8;
/// Keep a continuously-refilled completion queue from starving absolute request
/// deadlines and the shutdown drain deadline. The first awaited completion is
/// included in this total.
const MAX_COMPLETION_DRAIN_BATCH: usize = 64;
const MAX_PEER_UNI_STREAMS: usize = 16;
/// Advertised MAX_STREAMS for client request streams, and the admission bound the
/// accept loop enforces itself so a transport bug that over-reports peer streams
/// cannot turn into an unbounded loop or allocation.
const MAX_CONCURRENT_BIDI_STREAMS: u32 = 256;
/// Once this many connections on a core are still handshaking, an Initial from an
/// unvalidated address draws a stateless Retry. A spoofed source never returns the
/// token, so it costs one datagram and no connection state.
const H3_RETRY_THRESHOLD_PER_CORE: u64 = 64;
/// Hard per-core bound on concurrent QUIC handshakes, validated or not.
const H3_HANDSHAKING_CAP_PER_CORE: u32 = 256;
/// An amplification-limited handshake arms no quinn timer, so without this bound a
/// spoofed Initial would hold its handshake slot for the whole idle timeout.
const H3_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

static H3_RETRIES_SENT: AtomicU64 = AtomicU64::new(0);
static H3_REFUSED_BUDGET: AtomicU64 = AtomicU64::new(0);
static H3_REFUSED_HANDSHAKES: AtomicU64 = AtomicU64::new(0);
static H3_HANDSHAKE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static H3_SEND_STALL_RESETS: AtomicU64 = AtomicU64::new(0);

/// Process-wide HTTP/3 admission counters for the metrics endpoint.
pub(crate) struct H3AdmissionCounts {
    pub retries_sent: u64,
    pub refused_budget: u64,
    pub refused_handshakes: u64,
    pub handshake_timeouts: u64,
    pub send_stall_resets: u64,
}

pub(crate) fn admission_counts() -> H3AdmissionCounts {
    use std::sync::atomic::Ordering::Relaxed;
    H3AdmissionCounts {
        retries_sent: H3_RETRIES_SENT.load(Relaxed),
        refused_budget: H3_REFUSED_BUDGET.load(Relaxed),
        refused_handshakes: H3_REFUSED_HANDSHAKES.load(Relaxed),
        handshake_timeouts: H3_HANDSHAKE_TIMEOUTS.load(Relaxed),
        send_stall_resets: H3_SEND_STALL_RESETS.load(Relaxed),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IncomingDecision {
    Accept,
    Retry,
    Refuse,
}

/// Admission for a new QUIC connection on one core. `handshaking` counts this
/// core's connections that have not completed the handshake.
fn incoming_decision(
    accepting: bool,
    budget_available: bool,
    address_validated: bool,
    may_retry: bool,
    handshaking: u64,
) -> IncomingDecision {
    if !accepting || !budget_available || handshaking >= u64::from(H3_HANDSHAKING_CAP_PER_CORE) {
        return IncomingDecision::Refuse;
    }
    if !address_validated && handshaking >= H3_RETRY_THRESHOLD_PER_CORE {
        return if may_retry {
            IncomingDecision::Retry
        } else {
            IncomingDecision::Refuse
        };
    }
    IncomingDecision::Accept
}

enum Admission {
    Accepted(
        ConnectionHandle,
        quinn_proto::Connection,
        super::ConnectionPermit,
    ),
    /// A Retry, refusal or accept-error response is staged in `scratch`.
    Transmit(quinn_proto::Transmit),
    Dropped,
}

/// Decide and apply admission for one new connection. Accepting takes only a
/// per-core handshake slot; the shared connection budget is charged at
/// `Connected`, so unvalidated Initials can never hold the budget TCP draws from.
fn admit_incoming(
    endpoint: &mut Endpoint,
    incoming: quinn_proto::Incoming,
    now: Instant,
    scratch: &mut Vec<u8>,
    accepting: bool,
    runtime: &H3RuntimeConfig,
    handshakes: &Arc<AtomicU64>,
) -> Admission {
    use std::sync::atomic::Ordering::Relaxed;
    let decision = incoming_decision(
        accepting,
        connection_budget_available(&runtime.active_conns, runtime.max_connections()),
        incoming.remote_address_validated(),
        incoming.may_retry(),
        handshakes.load(Relaxed),
    );
    let slot = (decision == IncomingDecision::Accept)
        .then(|| {
            super::ConnectionPermit::try_acquire(handshakes.clone(), H3_HANDSHAKING_CAP_PER_CORE)
        })
        .flatten();
    let Some(slot) = slot else {
        if decision == IncomingDecision::Retry {
            match endpoint.retry(incoming, scratch) {
                Ok(transmit) => {
                    H3_RETRIES_SENT.fetch_add(1, Relaxed);
                    return Admission::Transmit(transmit);
                }
                Err(error) => {
                    H3_REFUSED_HANDSHAKES.fetch_add(1, Relaxed);
                    return Admission::Transmit(endpoint.refuse(error.into_incoming(), scratch));
                }
            }
        }
        if accepting {
            H3_REFUSED_HANDSHAKES.fetch_add(1, Relaxed);
        }
        return Admission::Transmit(endpoint.refuse(incoming, scratch));
    };
    match endpoint.accept(incoming, now, scratch, None) {
        Ok((handle, conn)) => Admission::Accepted(handle, conn, slot),
        Err(error) => {
            tracing::debug!(error = ?error.cause, "uring h3: accept rejected");
            error
                .response
                .map_or(Admission::Dropped, Admission::Transmit)
        }
    }
}

fn connection_budget_available(active: &AtomicU64, cap: u32) -> bool {
    cap == 0 || active.load(std::sync::atomic::Ordering::Relaxed) < u64::from(cap)
}

/// A handshaking connection's claim on the process-wide connection budget, which
/// is shared with the TCP accept loops. It is converted into a held permit only
/// when the handshake completes.
struct PendingConnectionBudget {
    active: Arc<AtomicU64>,
    cap: u32,
}

const H3_NO_ERROR: u32 = 0x0100;
const H3_INTERNAL_ERROR: u32 = 0x0102;
const H3_STREAM_CREATION_ERROR: u32 = 0x0103;
const H3_CLOSED_CRITICAL_STREAM: u32 = 0x0104;
const H3_FRAME_UNEXPECTED: u32 = 0x0105;
const H3_EXCESSIVE_LOAD: u32 = 0x0107;
const H3_SETTINGS_ERROR: u32 = 0x0109;
const H3_MISSING_SETTINGS: u32 = 0x010a;
const H3_REQUEST_CANCELLED: u32 = 0x010c;
const H3_MESSAGE_ERROR: u32 = 0x010e;
const MAX_SETTINGS_PAYLOAD: usize = 64 * 1024;

/// One coherent accept-time QUIC policy. The quinn configuration and serving
/// view must move together: a connection may use either the old or new policy
/// during publication, but must never combine one generation's TLS verifier
/// with another generation's request policy.
struct QuicServerPolicy {
    config: Arc<ServerConfig>,
    serving_view: Option<crate::serving_generation::ServingView>,
    client_auth: crate::uring::ClientAuth,
}

/// Fully validated replacement for future QUIC handshakes. Preparing this is
/// fallible; publishing it is one infallible ArcSwap store.
pub(crate) struct PreparedQuicPolicy(Arc<QuicServerPolicy>);

impl PreparedQuicPolicy {
    pub(crate) fn prepare(
        serving_view: crate::serving_generation::ServingView,
        rustls: Arc<rustls::ServerConfig>,
        client_auth: crate::uring::ClientAuth,
    ) -> io::Result<Self> {
        Ok(Self(Arc::new(QuicServerPolicy {
            config: Arc::new(server_config(rustls)?),
            serving_view: Some(serving_view),
            client_auth,
        })))
    }

    fn prepare_unscoped(
        rustls: Arc<rustls::ServerConfig>,
        client_auth: crate::uring::ClientAuth,
    ) -> io::Result<Self> {
        Ok(Self(Arc::new(QuicServerPolicy {
            config: Arc::new(server_config(rustls)?),
            serving_view: None,
            client_auth,
        })))
    }

    pub(crate) fn is_prepared_for(&self, epoch: &Arc<()>) -> bool {
        self.0
            .serving_view
            .as_ref()
            .is_some_and(|view| Arc::ptr_eq(&view.trust_epoch(), epoch))
    }
}

/// Shared by the coordinator and every per-core endpoint. Workers observe the
/// replacement without restarting or rebinding UDP sockets; quinn-proto applies
/// `set_server_config` only to future connections.
#[derive(Clone)]
pub(crate) struct QuicReloadHandle(Arc<ArcSwap<QuicServerPolicy>>);

impl QuicReloadHandle {
    fn new(initial: PreparedQuicPolicy) -> Self {
        Self(Arc::new(ArcSwap::from(initial.0)))
    }

    pub(crate) fn publish(&self, next: PreparedQuicPolicy) {
        self.0.store(next.0);
    }

    fn load_full(&self) -> Arc<QuicServerPolicy> {
        self.0.load_full()
    }

    #[cfg(test)]
    pub(crate) fn test_snapshot(&self) -> (bool, Option<Arc<()>>) {
        let policy = self.load_full();
        (
            policy.client_auth.required(),
            policy
                .serving_view
                .as_ref()
                .map(crate::serving_generation::ServingView::trust_epoch),
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) struct H3RequestLimits {
    max_header_bytes: usize,
    max_body_bytes: usize,
    max_request_wire_bytes: usize,
    max_connection_bytes: usize,
}

impl H3RequestLimits {
    pub(crate) fn new(max_header_bytes: usize, max_body_bytes: usize) -> Self {
        let framing_allowance = 64 * 1024;
        let max_request_wire_bytes = max_header_bytes
            .saturating_add(max_body_bytes)
            .saturating_add(framing_allowance);
        let max_connection_bytes = max_body_bytes.saturating_mul(4).max(max_request_wire_bytes);
        Self {
            max_header_bytes,
            max_body_bytes,
            max_request_wire_bytes,
            max_connection_bytes,
        }
    }
}

/// (#509) Request-stream limits captured together from one configuration generation.
/// `timeout` is the budget from stream acceptance through FIN. Only the stream's own
/// progress extends it: each `BODY_MIN_PROGRESS` received restarts the window, up to
/// `body_ceiling` from acceptance (#1035).
#[derive(Clone, Copy)]
pub(crate) struct H3RequestConfig {
    limits: H3RequestLimits,
    timeout: Option<Duration>,
    body_ceiling: Duration,
}

impl H3RequestConfig {
    pub(crate) fn new(limits: H3RequestLimits, timeout: Option<Duration>) -> Self {
        Self {
            limits,
            timeout,
            body_ceiling: hj_core::body_deadline::BODY_DEADLINE_CEILING,
        }
    }

    pub(crate) fn with_body_ceiling(mut self, body_ceiling: Duration) -> Self {
        self.body_ceiling = body_ceiling;
        self
    }
}

/// The one application/configuration generation selected when a request stream
/// is accepted. A compatible reload may change the snapshot for later streams
/// on the same connection, but never for a stream already being received.
#[derive(Clone)]
struct H3RequestSnapshot {
    config: H3RequestConfig,
    generation: Option<crate::serving_generation::RequestGeneration>,
    deadline: Option<H3RequestDeadlineKey>,
    /// Extension state for `deadline`, armed with it (#1035).
    progress: Option<BodyProgress<Instant>>,
    /// Queued in `H3State::readable_requests`.
    read_queued: bool,
}

impl H3RequestSnapshot {
    #[cfg(test)]
    fn unscoped(config: H3RequestConfig) -> Self {
        Self {
            config,
            generation: None,
            deadline: None,
            progress: None,
            read_queued: false,
        }
    }
}

/// Ordered node for one unfinished request stream. Sequence, rather than
/// StreamId, is the tie-breaker because a whole accept batch commonly shares
/// one deadline.
#[derive(Clone, Copy, Debug)]
struct H3RequestDeadlineKey {
    when: Instant,
    sequence: u64,
    stream: StreamId,
}

impl PartialEq for H3RequestDeadlineKey {
    fn eq(&self, other: &Self) -> bool {
        self.when == other.when && self.sequence == other.sequence
    }
}

impl Eq for H3RequestDeadlineKey {}

impl PartialOrd for H3RequestDeadlineKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for H3RequestDeadlineKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.when
            .cmp(&other.when)
            .then_with(|| self.sequence.cmp(&other.sequence))
    }
}

#[derive(Clone)]
pub(crate) struct H3RuntimeConfig {
    config: Arc<dyn Fn() -> (H3RequestConfig, u32) + Send + Sync>,
    serving_view: Option<crate::serving_generation::ServingView>,
    active_conns: Arc<AtomicU64>,
    /// (#236 residual) Server-wide buffered-body cap shared with H1/H2/LSAPI. H3 commits
    /// the whole request-stream buffer before parse, so the reservation is taken when a
    /// finished request is taken for dispatch (per-connection wire bytes are already
    /// bounded separately by `total_req_bytes`).
    body_budget: std::sync::Arc<hj_core::budget::BodyBufferBudget>,
    /// The serving core's shutdown token, handed to every accepted connection so a
    /// streamed response idle on its backend ends during the drain (#1034).
    shutdown: Option<CancellationToken>,
}

impl H3RuntimeConfig {
    pub(crate) fn new<F>(
        config: F,
        active_conns: Arc<AtomicU64>,
        body_budget: std::sync::Arc<hj_core::budget::BodyBufferBudget>,
    ) -> Self
    where
        F: Fn() -> (H3RequestConfig, u32) + Send + Sync + 'static,
    {
        Self {
            config: Arc::new(config),
            serving_view: None,
            active_conns,
            body_budget,
            shutdown: None,
        }
    }

    fn with_shutdown(mut self, shutdown: CancellationToken) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    pub(crate) fn with_serving_view(
        mut self,
        view: crate::serving_generation::ServingView,
    ) -> Self {
        self.serving_view = Some(view);
        self
    }

    fn request_config(&self) -> H3RequestConfig {
        (self.config)().0
    }

    #[cfg(test)]
    fn request_limits(&self) -> H3RequestLimits {
        self.request_config().limits
    }

    fn max_connections(&self) -> u32 {
        (self.config)().1
    }

    #[cfg(test)]
    fn accepted_state(&self, permit: super::ConnectionPermit, epoch: u64) -> H3State {
        H3State {
            _connection_permit: Some(permit),
            serving_view: self.serving_view.as_ref().map(|view| view.pin_connection()),
            epoch,
            body_budget: Some(self.body_budget.clone()),
            egress_budget: Some(H3EgressBudget::new(self.body_budget.clone())),
            ..Default::default()
        }
    }

    fn accepted_state_with_policy(
        &self,
        handshake_slot: super::ConnectionPermit,
        accepted_at: Instant,
        epoch: u64,
        policy: &QuicServerPolicy,
    ) -> H3State {
        H3State {
            pending_budget: Some(PendingConnectionBudget {
                active: self.active_conns.clone(),
                cap: self.max_connections(),
            }),
            handshake_slot: Some(handshake_slot),
            accepted_at: Some(accepted_at),
            serving_view: policy
                .serving_view
                .as_ref()
                .map(|view| view.pin_connection()),
            client_auth: policy.client_auth,
            epoch,
            body_budget: Some(self.body_budget.clone()),
            egress_budget: Some(H3EgressBudget::new(self.body_budget.clone())),
            shutdown: self.shutdown.clone(),
            ..Default::default()
        }
    }
}

/// A single H3 connection may retain one maximum-sized cacheable response plus
/// framing, but cannot pin an arbitrary multiple of those responses while its
/// peer withholds QUIC flow-control credit. The process-wide side reuses the
/// existing 512 MiB buffered-memory budget shared by all transports.
const H3_CONNECTION_EGRESS_MEM: u64 = 128 * 1024 * 1024;

#[derive(Clone)]
struct H3EgressBudget {
    global: Arc<hj_core::budget::BodyBufferBudget>,
    connection: Arc<hj_core::budget::BodyBufferBudget>,
    /// The connection's bridge-side share for response streams (`BridgeCtx::response_budget`).
    bridge: Arc<hj_core::budget::BodyBufferBudget>,
}

impl H3EgressBudget {
    fn new(global: Arc<hj_core::budget::BodyBufferBudget>) -> Self {
        Self {
            global,
            connection: Arc::new(hj_core::budget::BodyBufferBudget::new(
                H3_CONNECTION_EGRESS_MEM,
            )),
            bridge: crate::uring::bridge::connection_response_budget(),
        }
    }

    fn reserve(&self, bytes: usize) -> Option<H3EgressLease> {
        let bytes = u64::try_from(bytes).ok()?;
        let mut connection = hj_core::budget::BodyBufferLease::new(self.connection.clone());
        if !connection.reserve(bytes) {
            return None;
        }
        let mut global = hj_core::budget::BodyBufferLease::new(self.global.clone());
        if !global.reserve(bytes) {
            return None;
        }
        Some(H3EgressLease {
            _global: global,
            _connection: connection,
        })
    }
}

struct H3EgressLease {
    _global: hj_core::budget::BodyBufferLease,
    _connection: hj_core::budget::BodyBufferLease,
}

fn reserve_h3_egress(
    budget: Option<&H3EgressBudget>,
    bytes: usize,
) -> Result<Option<H3EgressLease>, ()> {
    match budget {
        Some(budget) => budget.reserve(bytes).map(Some).ok_or(()),
        None => Ok(None),
    }
}

/// Build a `SO_REUSEPORT` UDP socket (std) for a monoio runtime to adopt — the
/// per-core QUIC listener, mirroring the TCP reuseport model.
fn reuseport_udp(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// Self-signed rustls server config with the `h3` ALPN, for the smoke entrypoint
/// (the real driver takes hj-tls's cert resolver). Mirrors the h3_roundtrip test.
pub(crate) fn self_signed_config() -> io::Result<Arc<rustls::ServerConfig>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("rcgen: {e}")))?;
    let cert_der = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("key der: {e}")))?;
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("rustls: {e}")))?;
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    cfg.max_early_data_size = 0;
    Ok(Arc::new(cfg))
}

/// Build the quinn-proto server [`ServerConfig`] from a rustls config that already
/// advertises the `h3` ALPN (aws-lc-rs crypto, matching the process provider).
fn server_config(rustls_cfg: Arc<rustls::ServerConfig>) -> io::Result<ServerConfig> {
    let quic = quinn_proto::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("quic crypto: {e}")))?;
    let mut cfg = ServerConfig::with_crypto(Arc::new(quic));
    // (N3) Bound the uring H3 transport like the tokio path (hj-http::quic_server_config),
    // which previously used pure defaults here: cap concurrent streams, add an IDLE DEADLINE
    // (cuts a post-handshake slowloris that otherwise pins the connection forever), and set
    // stream + connection RECEIVE WINDOWS so the peer can't buffer unbounded request data at
    // the QUIC layer. The app-level req_buf cap (below) bounds the post-read accumulation.
    let mut transport = quinn_proto::TransportConfig::default();
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams((MAX_PEER_UNI_STREAMS as u32).into());
    let idle = std::time::Duration::from_secs(60)
        .try_into()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("idle timeout: {e:?}")))?;
    transport.max_idle_timeout(Some(idle));
    // quinn holds out-of-order STREAM data up to these windows before httpjet reads (and
    // budgets) any of it, so they bound what a peer can park per connection.
    transport.stream_receive_window((1024u32 * 1024).into());
    transport.receive_window((8u32 * 1024 * 1024).into());
    // No RFC 9297 support: the default advertised max_datagram_frame_size and buffered
    // up to 1.25 MB of DATAGRAM frames nothing reads for the connection's life (#1047).
    // Unadvertised, a peer DATAGRAM is a PROTOCOL_VIOLATION (RFC 9221 §3).
    transport.datagram_receive_buffer_size(None);
    cfg.transport_config(Arc::new(transport));
    // Linux SO_REUSEPORT hashes a rebinding tuple independently for every datagram. Each
    // worker owns a separate sans-I/O endpoint, so a migrated tuple can land on a worker
    // that has no state for its DCID. Keep migration disabled until the listener steers by
    // destination connection ID rather than by the kernel's 4-tuple hash.
    cfg.migration(false);
    Ok(cfg)
}

/// (N3) Max bytes accumulated for one H3 request (header block + body) before the stream is
/// reset. Bounds the app-side `req_buf` growth that the QUIC receive window alone doesn't
/// cap (the app drains the window as it reads, so a single body could otherwise grow to the
/// whole upload). This const is the SMOKE-path default; the production pipeline path threads
/// `max_req_bytes` from the LiteSpeed config (`maxReqBodySize` + `maxReqHeaderSize`) so a
/// valid large upload is not wrongly rejected (and the cap tracks the operator's setting).
const MAX_H3_REQ_BYTES: usize = 64 * 1024 * 1024;

/// H3 smoke entrypoint: per-core monoio io_uring runtimes, each adopting its own
/// `SO_REUSEPORT` UDP socket and driving a quinn-proto endpoint. Blocks.
/// Reachable via the gated `HJ_URING_H3_SMOKE=<addr>` dev hook.
pub(crate) fn serve_h3_smoke(
    addr: SocketAddr,
    workers: usize,
    rustls_cfg: Arc<rustls::ServerConfig>,
) -> io::Result<()> {
    let workers = workers.max(1);
    let mut handles = Vec::with_capacity(workers);
    for core in 0..workers {
        let std_sock = reuseport_udp(addr)?;
        let cfg = rustls_cfg.clone();
        let handle = std::thread::Builder::new()
            .name(format!("hj-uring-h3-{core}"))
            .stack_size(crate::RUNTIME_THREAD_STACK_BYTES)
            .spawn(move || per_core_h3(core, std_sock, cfg))?;
        handles.push(handle);
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn per_core_h3(core: usize, std_sock: std::net::UdpSocket, rustls_cfg: Arc<rustls::ServerConfig>) {
    let server_cfg = match server_config(rustls_cfg) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(core, error = %e, "uring h3: server config build failed");
            return;
        }
    };
    let mut rt = super::build_core_runtime().expect("build monoio io_uring runtime");
    rt.block_on(async move {
        let udp = match UdpSocket::from_std(std_sock) {
            Ok(u) => u,
            Err(e) => {
                tracing::error!(core, error = %e, "uring h3: adopt reuseport udp failed");
                return;
            }
        };
        let endpoint = Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(server_cfg),
            true,
            None,
        );
        tracing::info!(
            core,
            "uring h3: per-core quinn-proto endpoint serving (fixed-response smoke)"
        );
        // Fixed-response handler (the original smoke behavior).
        let smoke = |_bytes: Bytes, _cc: bool, _peer: SocketAddr| async { h3_response_bytes() };
        if let Err(e) = endpoint_loop(udp, endpoint, smoke).await {
            tracing::error!(core, error = %e, "uring h3: endpoint loop ended");
        }
    });
}

/// Per-connection HTTP/3 state.
#[derive(Default)]
struct H3State {
    _connection_permit: Option<super::ConnectionPermit>,
    pending_budget: Option<PendingConnectionBudget>,
    /// Released when the handshake completes or the connection is rejected; the
    /// per-core count of these is the Retry/refuse pressure signal.
    handshake_slot: Option<super::ConnectionPermit>,
    accepted_at: Option<Instant>,
    serving_view: Option<crate::serving_generation::ServingView>,
    connected: bool,
    control_setup: bool,
    control_stream: Option<StreamId>,
    control_stream_off: usize,
    qpack_encoder_stream: Option<StreamId>,
    qpack_encoder_stream_off: usize,
    qpack_decoder_stream: Option<StreamId>,
    qpack_decoder_stream_off: usize,
    goaway_sent: bool,
    goaway_buf: Vec<u8>,
    goaway_off: usize,
    draining: bool,
    next_request_stream_index: u64,
    client_leaf: Option<rustls::pki_types::CertificateDer<'static>>,
    /// The connection's TLS parameters, built once at `Connected` (as the TCP paths do) and
    /// shared by every request.
    tls: Option<hj_core::TlsParams>,
    /// TLS SNI from the QUIC handshake: the routing fallback, like H2's
    /// `server_name()`, never derived from `:authority`.
    server_name: Option<Arc<str>>,
    /// In-flight client request bidi streams (removed once served), so we never
    /// re-scan already-served streams — bounded by concurrent requests, not total.
    requests: std::collections::HashSet<StreamId>,
    /// Receive deadlines for unfinished request streams. The same key is held
    /// in `request_snapshots`, so completion removes it directly in O(log N).
    /// Equal batch deadlines never trigger a scan of the remaining streams.
    request_deadlines: BTreeSet<H3RequestDeadlineKey>,
    next_request_deadline_sequence: u64,
    /// Limits and dispatch generation captured once when each stream is accepted.
    /// This travels with the buffered request until dispatch or reclamation.
    request_snapshots: std::collections::HashMap<StreamId, H3RequestSnapshot>,
    /// Unfinished request streams with data, FIN or a reset to read: each newly
    /// accepted stream and each `StreamEvent::Readable`, at most once per stream
    /// (`H3RequestSnapshot::read_queued`). A drive reads only these.
    readable_requests: Vec<StreamId>,
    /// Accumulated request bytes per in-flight bidi stream (a request's HEADERS+DATA
    /// frames may arrive across several datagrams); drained + handled on stream fin.
    req_buf: std::collections::HashMap<StreamId, Vec<u8>>,
    req_frames: std::collections::HashMap<StreamId, H3FrameCounter>,
    /// (security #263) Server-wide buffered-body budget shared with H1/H2/LSAPI,
    /// installed by the connection driver. Accumulated request bytes reserve
    /// against it so pre-dispatch buffering stays server-bounded.
    body_budget: Option<std::sync::Arc<hj_core::budget::BodyBufferBudget>>,
    /// Owned reservations follow request buffers into dispatch or release on every
    /// state teardown, including a connection lost before a request finishes.
    body_leases: std::collections::HashMap<StreamId, hj_core::budget::BodyBufferLease>,
    /// Byte-weighted response retention guard. A lease follows every encoded
    /// response part until quinn accepts it or the stream/connection is reset.
    egress_budget: Option<H3EgressBudget>,
    /// Every accepted peer unidirectional stream remains here until FIN/reset. HTTP/3
    /// control and QPACK streams are critical and must be continuously drained; accepting
    /// and reading them once loses split stream-type/SETTINGS delivery and hides closure.
    peer_uni: std::collections::HashMap<StreamId, PeerUniStream>,
    peer_control: Option<StreamId>,
    peer_qpack_encoder: Option<StreamId>,
    peer_qpack_decoder: Option<StreamId>,
    peer_settings: Option<PeerSettings>,
    peer_max_field_section_size: std::rc::Rc<std::cell::Cell<Option<u64>>>,
    /// Total raw request bytes retained across all unfinished streams on this connection.
    total_req_bytes: std::rc::Rc<std::cell::Cell<usize>>,
    /// Set once a required-client-certificate decision closes the connection.
    rejected: bool,
    /// Accept-time mTLS policy. Established connections retain the decision
    /// from the QUIC configuration that authenticated their handshake.
    client_auth: crate::uring::ClientAuth,
    /// Encoded response bytes not yet fully written to the send stream, with the
    /// byte offset already accepted. QUIC stream flow control bounds how much
    /// `SendStream::write` accepts at once, so a large response (> the peer's stream
    /// window, e.g. a multi-MB file) is written incrementally: the remainder is pumped
    /// as the peer grants more window (`StreamEvent::Writable`). Without this, a large
    /// response is silently truncated to the first window.
    pending: std::collections::HashMap<StreamId, PendingSend>,
    /// Live `header_read_timeout`, refreshed per drive: how long a response may wait
    /// on the peer's flow-control credit without [`SEND_STALL_MIN_PROGRESS`] progress.
    send_stall_timeout: Option<Duration>,
    /// Cancellation handles for requests already dispatched through the bridge. A peer
    /// STOP_SENDING must drop the monoio request task so the bridge drops its response
    /// receiver, cancels the tokio pipeline future, and releases the global slot.
    request_cancellations: RequestCancellations,
    cancel_budget: CancelBudget,
    /// Per-connection generation, assigned from a per-core counter at accept. quinn-proto
    /// reuses `ConnectionHandle` indices after a connection drains, so a response from a
    /// spawned task that finished AFTER its connection closed (and the handle was reused by
    /// a NEW connection) must be dropped — guarded by comparing this epoch (see
    /// [`Completion`] / `write_completion`).
    epoch: u64,
    /// The serving core's shutdown token (see [`H3RuntimeConfig`]).
    shutdown: Option<CancellationToken>,
}

impl H3State {
    fn request_snapshot(&self, fallback: H3RequestConfig) -> H3RequestSnapshot {
        let generation = self
            .serving_view
            .as_ref()
            .map(|view| crate::serving_generation::RequestGeneration(view.load_full()));
        let config = generation
            .as_ref()
            .map(|generation| {
                H3RequestConfig::new(
                    H3RequestLimits::new(
                        generation.0.serve_config.max_req_header_size,
                        generation.0.serve_config.max_req_body_size,
                    ),
                    generation.0.serve_config.header_read_timeout,
                )
                .with_body_ceiling(generation.0.serve_config.request_body_ceiling)
            })
            .unwrap_or(fallback);
        H3RequestSnapshot {
            config,
            generation,
            deadline: None,
            progress: None,
            read_queued: false,
        }
    }

    fn track_request_stream(
        &mut self,
        id: StreamId,
        accepted_at: Instant,
        mut snapshot: H3RequestSnapshot,
    ) {
        // accept(Dir::Bi) yields each stream once. Keeping the insertion guard
        // makes a re-accept unable to restart the deadline even if that assumption
        // ever changes in quinn-proto.
        if self.requests.insert(id) {
            self.req_buf.entry(id).or_default();
            if let Some(timeout) = snapshot.config.timeout {
                let deadline = accepted_at + timeout;
                let key = H3RequestDeadlineKey {
                    when: deadline,
                    sequence: self.next_request_deadline_sequence,
                    stream: id,
                };
                snapshot.deadline = Some(key);
                snapshot.progress = Some(BodyProgress::new(
                    accepted_at,
                    snapshot.config.body_ceiling,
                    0,
                ));
                self.request_deadlines.insert(key);
                self.next_request_deadline_sequence =
                    self.next_request_deadline_sequence.wrapping_add(1);
            }
            // Its first bytes arrived with the frame that opened it, which quinn
            // reports as `Opened`, never as `Readable`.
            snapshot.read_queued = true;
            self.readable_requests.push(id);
            self.request_snapshots.insert(id, snapshot);
        }
    }

    /// Queue request stream `id` for the next receive pass after a
    /// `StreamEvent::Readable`; false if it is not an unfinished request stream.
    fn queue_readable_request(&mut self, id: StreamId) -> bool {
        match self.request_snapshots.get_mut(&id) {
            Some(snapshot) => {
                if !std::mem::replace(&mut snapshot.read_queued, true) {
                    self.readable_requests.push(id);
                }
                true
            }
            None if self.requests.contains(&id) => {
                // A tracked stream without a snapshot is reclaimed by the receive pass.
                self.readable_requests.push(id);
                true
            }
            None => false,
        }
    }

    fn next_request_deadline(&self) -> Option<Instant> {
        self.request_deadlines.first().map(|key| key.when)
    }

    /// (#1035) The request stream `id` has `buffered` bytes: once that is
    /// `BODY_MIN_PROGRESS` past its last extension, move its deadline (re-keyed in the
    /// ordered set) to `now + timeout`, capped at its ceiling.
    fn extend_request_deadline(&mut self, id: StreamId, buffered: usize, now: Instant) {
        let Some(snapshot) = self.request_snapshots.get_mut(&id) else {
            return;
        };
        let (Some(timeout), Some(key), Some(progress)) = (
            snapshot.config.timeout,
            snapshot.deadline.as_mut(),
            snapshot.progress.as_mut(),
        ) else {
            return;
        };
        let mut when = key.when;
        if progress.extend(&mut when, buffered as u64, timeout, || now) {
            self.request_deadlines.remove(key);
            key.when = when;
            self.request_deadlines.insert(*key);
        }
    }

    fn handshake_deadline(&self) -> Option<Instant> {
        match self.accepted_at {
            Some(at) if !self.connected && !self.rejected => Some(at + H3_HANDSHAKE_TIMEOUT),
            _ => None,
        }
    }

    fn next_send_stall_deadline(&self) -> Option<Instant> {
        let timeout = self.send_stall_timeout?;
        self.pending
            .values()
            .filter_map(|p| p.stall.map(|s| s.since + timeout))
            .min()
    }

    /// The earliest instant the driver must revisit this connection on its own.
    fn next_deadline(&self) -> Option<Instant> {
        [
            self.handshake_deadline(),
            self.next_request_deadline(),
            self.next_send_stall_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn first_expired_request(&self, now: Instant) -> Option<StreamId> {
        self.request_deadlines
            .first()
            .filter(|key| key.when <= now)
            .map(|key| key.stream)
    }
}

fn request_local_addr(bound: SocketAddr, dst_ip: Option<std::net::IpAddr>) -> SocketAddr {
    match dst_ip {
        // A dual-stack `[::]` socket reports an IPv4 destination as `::ffff:a.b.c.d`.
        Some(ip) if bound.ip().is_unspecified() => SocketAddr::new(ip.to_canonical(), bound.port()),
        _ => bound,
    }
}

fn recv_drain_should_continue(completed_batches: usize, received_messages: usize) -> bool {
    received_messages == GRO_BATCH && completed_batches < MAX_RECV_DRAIN_BATCHES
}

#[derive(Clone, Copy)]
struct ConnectionDeadlineKey {
    when: Instant,
    sequence: u64,
    handle: ConnectionHandle,
}

impl PartialEq for ConnectionDeadlineKey {
    fn eq(&self, other: &Self) -> bool {
        self.when == other.when && self.sequence == other.sequence
    }
}

impl Eq for ConnectionDeadlineKey {}

impl PartialOrd for ConnectionDeadlineKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConnectionDeadlineKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.when
            .cmp(&other.when)
            .then_with(|| self.sequence.cmp(&other.sequence))
    }
}

/// Per-core index of each connection's next deadline: its QUIC timer or an HTTP/3
/// handshake, request or send-stall deadline ([`connection_deadline`]). There is
/// exactly one node per connection, so neither packet processing nor the timer wait
/// scans every connection, and the index cannot accumulate lazy tombstones. Every
/// path that touches a connection drives it, and every drive re-syncs its node.
#[derive(Default)]
struct ConnectionDeadlineIndex {
    ordered: BTreeSet<ConnectionDeadlineKey>,
    by_connection: HashMap<ConnectionHandle, ConnectionDeadlineKey>,
    next_sequence: u64,
}

impl ConnectionDeadlineIndex {
    fn sync(&mut self, handle: ConnectionHandle, deadline: Option<Instant>) {
        let Some(when) = deadline else {
            self.remove(handle);
            return;
        };
        let sequence = self.next_sequence;
        match self.by_connection.entry(handle) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().when == when {
                    return;
                }
                self.ordered.remove(entry.get());
                let key = entry.get_mut();
                key.when = when;
                key.sequence = sequence;
                self.ordered.insert(*key);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                self.ordered.insert(*entry.insert(ConnectionDeadlineKey {
                    when,
                    sequence,
                    handle,
                }));
            }
        }
        self.next_sequence = sequence.wrapping_add(1);
    }

    fn remove(&mut self, handle: ConnectionHandle) {
        if let Some(key) = self.by_connection.remove(&handle) {
            self.ordered.remove(&key);
        }
    }

    fn next(&self) -> Option<Instant> {
        self.ordered.first().map(|key| key.when)
    }

    fn extend_due(
        &mut self,
        affected: &mut std::collections::HashSet<ConnectionHandle>,
        now: Instant,
    ) {
        while let Some(key) = self.ordered.first().copied() {
            if key.when > now {
                break;
            }
            self.ordered.remove(&key);
            self.by_connection.remove(&key.handle);
            affected.insert(key.handle);
        }
    }
}

/// When the driver must next revisit `hd` on its own: the earlier of its QUIC timer
/// (which only quinn calls on the connection can move) and its HTTP/3 deadlines.
fn connection_deadline(
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &HashMap<ConnectionHandle, H3State>,
    hd: ConnectionHandle,
) -> Option<Instant> {
    let quic = conns
        .get_mut(&hd)
        .and_then(quinn_proto::Connection::poll_timeout);
    let h3 = h3.get(&hd).and_then(H3State::next_deadline);
    match (quic, h3) {
        (Some(quic), Some(h3)) => Some(quic.min(h3)),
        (quic, h3) => quic.or(h3),
    }
}

#[derive(Default)]
struct RequestCancellations(std::collections::HashMap<StreamId, CancellationToken>);

impl std::ops::Deref for RequestCancellations {
    type Target = std::collections::HashMap<StreamId, CancellationToken>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RequestCancellations {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for RequestCancellations {
    fn drop(&mut self) {
        for token in self.values() {
            token.cancel();
        }
    }
}

/// A response (or response fragment) handed back from a spawned per-request task to the
/// connection-owning driver loop (the concurrent H3 path). The driver writes onto the owning
/// connection's send stream — but only if the connection still exists AND its `epoch` still
/// matches (else the handle was reused by a different connection → drop it).
struct Completion {
    conn: ConnectionHandle,
    stream: StreamId,
    epoch: u64,
    kind: CompletionKind,
}

/// What a [`Completion`] carries. A small/HIT/buffered response is one `Full`; a large
/// (bridge-streamed) response is a `Head` (HEADERS frame) then a sequence of `Chunk`s, so
/// the body flows out as the backend produces it instead of being buffered whole.
enum CompletionKind {
    /// Whole encoded response (HEADERS [+ DATA]) — finish the stream once drained.
    Full(
        Vec<u8>,
        Option<hj_core::ResponseCompletion>,
        Option<H3EgressLease>,
    ),
    /// HEADERS frame only; DATA `Chunk`s follow. The stream stays open until `Chunk{fin}`.
    Head(
        Vec<u8>,
        Option<hj_core::ResponseCompletion>,
        Option<H3EgressLease>,
    ),
    /// One DATA payload; the driver emits its frame header without copying the payload.
    /// `fin` marks the last chunk (then finish the stream).
    Chunk {
        data: Bytes,
        fin: bool,
        ack: Option<flume::Sender<()>>,
        lease: Option<H3EgressLease>,
    },
    /// Reset the send stream with this RFC 9114 code: a mid-stream upstream abort, or a
    /// body left idle on its backend through the shutdown grace (#1034).
    Abort(u32),
}

/// A response buffered in the driver awaiting the QUIC flow-control window. Parts retain an
/// offset rather than deleting their written prefix, so partial writes never memmove a body.
/// Streamed DATA keeps the bridge's original `Bytes` and an inline frame header, avoiding both
/// copies formerly made while framing and appending each chunk.
struct PendingSend {
    completion: Option<hj_core::ResponseCompletion>,
    parts: std::collections::VecDeque<PendingPart>,
    fin: bool,
    /// Runs while queued bytes wait on the peer's flow-control credit (#599 on h2).
    stall: Option<SendStall>,
}

/// Bytes a response must deliver per send-stall window while it waits on credit, so
/// a peer granting a byte at a time cannot restart the deadline forever (as on h2).
const SEND_STALL_MIN_PROGRESS: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug)]
struct SendStall {
    since: Instant,
    progressed: u64,
}

/// Advance a response's send-stall clock after a pump that accepted `sent` bytes. The
/// clock runs only while bytes remain `waiting` (a slow backend leaves none queued).
fn advance_send_stall(
    stall: Option<SendStall>,
    sent: u64,
    waiting: bool,
    now: Instant,
) -> Option<SendStall> {
    if !waiting {
        return None;
    }
    match stall {
        Some(s) if s.progressed.saturating_add(sent) < SEND_STALL_MIN_PROGRESS => Some(SendStall {
            since: s.since,
            progressed: s.progressed + sent,
        }),
        _ => Some(SendStall {
            since: now,
            progressed: 0,
        }),
    }
}
impl PendingSend {
    /// Report completion only after every queued byte has entered QUIC and its
    /// FIN is accepted. This is not acknowledgement by the remote application.
    fn finish_if_drained(&mut self, finish: impl FnOnce() -> bool) -> bool {
        if !self.fin || !self.parts.is_empty() {
            return false;
        }
        let accepted = finish();
        if let Some(completion) = self.completion.take() {
            completion.finish(if accepted {
                hj_core::ResponseEnd::Complete
            } else {
                hj_core::ResponseEnd::Cancelled
            });
        }
        true
    }
}

enum PendingPart {
    Contiguous {
        data: Bytes,
        off: usize,
        ack: Option<flume::Sender<()>>,
        _lease: Option<H3EgressLease>,
    },
    DataFrame {
        header: [u8; 16],
        header_len: usize,
        header_off: usize,
        data: Bytes,
        data_off: usize,
        ack: Option<flume::Sender<()>>,
        _lease: Option<H3EgressLease>,
    },
}

impl PendingPart {
    fn contiguous(data: Vec<u8>, lease: Option<H3EgressLease>) -> Self {
        Self::Contiguous {
            data: Bytes::from(data),
            off: 0,
            ack: None,
            _lease: lease,
        }
    }

    fn data_frame(
        data: Bytes,
        ack: Option<flume::Sender<()>>,
        lease: Option<H3EgressLease>,
    ) -> Self {
        let mut header = [0u8; 16];
        let mut header_len = 0;
        write_varint_fixed(&mut header, &mut header_len, 0x00);
        write_varint_fixed(&mut header, &mut header_len, data.len() as u64);
        Self::DataFrame {
            header,
            header_len,
            header_off: 0,
            data,
            data_off: 0,
            ack,
            _lease: lease,
        }
    }

    fn acknowledge(mut self) {
        let ack = match &mut self {
            Self::Contiguous { ack, .. } | Self::DataFrame { ack, .. } => ack.take(),
        };
        if let Some(ack) = ack {
            let _ = ack.try_send(());
        }
    }

    /// Write until the part is complete (`Ok(true)`) or the stream reports
    /// `Err(Blocked)`. MUST NOT stop after a partial write while another
    /// `write()` call would still be accepted: quinn-proto registers the
    /// CONNECTION-flow-control waker (`Streams::connection_blocked`, the only
    /// source of a `StreamEvent::Writable` after MAX_DATA arrives) exclusively
    /// inside a `write()` call that finds the window at zero and returns
    /// `Blocked`. Returning early after a partial write that landed exactly on
    /// the connection window left the stream unregistered and the response
    /// stalled forever — any body larger than the client's initial MAX_DATA
    /// (aioquic/Chrome default 1 MiB) hung mid-transfer (found by
    /// h3_transfer_check.sh: stall at exactly 1 MiB of stream bytes).
    /// `Ok(false)` remains only as a defensive can't-spin exit for a
    /// zero-progress `Ok(0)`, which quinn-proto never produces for non-empty
    /// input.
    fn write(
        &mut self,
        stream: &mut quinn_proto::SendStream<'_>,
        sent: &mut u64,
    ) -> Result<bool, WriteError> {
        match self {
            Self::Contiguous { data, off, .. } => {
                while *off < data.len() {
                    let n = stream.write(&data[*off..])?;
                    *off += n;
                    *sent += n as u64;
                    if n == 0 {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::DataFrame {
                header,
                header_len,
                header_off,
                data,
                data_off,
                ..
            } => {
                while *header_off < *header_len {
                    let n = stream.write(&header[*header_off..*header_len])?;
                    *header_off += n;
                    *sent += n as u64;
                    if n == 0 {
                        return Ok(false);
                    }
                }
                while *data_off < data.len() {
                    let n = stream.write(&data[*data_off..])?;
                    *data_off += n;
                    *sent += n as u64;
                    if n == 0 {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }
}

/// Peer cancellations (RESET_STREAM or STOP_SENDING) of request streams that were still
/// being received or still had dispatched work: a burst of `H3_CANCEL_BURST`, then one
/// per `H3_CANCEL_REFILL`. Completed responses never refund it, so open→cancel churn
/// cannot keep it level the way a net counter can; a browser abandoning a page's
/// in-flight requests stays far inside the burst.
const H3_CANCEL_BURST: u32 = 200;
const H3_CANCEL_REFILL: Duration = Duration::from_millis(100);

/// GCRA form of a token bucket: one instant per connection, O(1) per charge.
#[derive(Default)]
struct CancelBudget {
    /// When the charges so far are fully paid back at the refill rate.
    debt_until: Option<Instant>,
}

impl CancelBudget {
    /// Charge one cancellation at `now`; true once the burst is exhausted.
    fn charge(&mut self, now: Instant) -> bool {
        let debt_until = self.debt_until.filter(|t| *t > now).unwrap_or(now) + H3_CANCEL_REFILL;
        self.debt_until = Some(debt_until);
        debt_until - now > H3_CANCEL_REFILL * H3_CANCEL_BURST
    }
}

/// Charge one peer cancellation of an unanswered request stream. Once the budget is
/// exhausted every dispatched request is cancelled and the error to close with returned.
fn charge_request_cancel(st: &mut H3State, now: Instant) -> Option<H3ConnectionError> {
    if !st.cancel_budget.charge(now) {
        return None;
    }
    cancel_all_dispatched_requests(st);
    st.rejected = true;
    Some(H3ConnectionError::new(
        H3_EXCESSIVE_LOAD,
        b"excessive HTTP/3 request cancellation",
    ))
}

fn cancel_dispatched_request(st: &mut H3State, id: StreamId) {
    if let Some(token) = st.request_cancellations.remove(&id) {
        token.cancel();
    }
    st.pending.remove(&id);
}

fn cancel_all_dispatched_requests(st: &mut H3State) {
    for (_, token) in st.request_cancellations.drain() {
        token.cancel();
    }
    st.pending.clear();
}

fn reject_stopped_local_critical_stream(
    st: &mut H3State,
    id: StreamId,
) -> Option<H3ConnectionError> {
    let critical = st.control_stream == Some(id)
        || st.qpack_encoder_stream == Some(id)
        || st.qpack_decoder_stream == Some(id);
    if !critical {
        return None;
    }
    cancel_all_dispatched_requests(st);
    st.rejected = true;
    Some(H3ConnectionError::new(
        H3_CLOSED_CRITICAL_STREAM,
        b"local HTTP/3 critical stream stopped",
    ))
}

async fn run_cancelable_request<F>(cancel: CancellationToken, work: F)
where
    F: std::future::Future<Output = ()>,
{
    monoio::select! {
        biased;
        _ = cancel.cancelled() => {}
        _ = work => {}
    }
}

fn acknowledge_front_part(entry: &mut PendingSend) -> bool {
    let Some(part) = entry.parts.pop_front() else {
        return false;
    };
    part.acknowledge();
    true
}

/// RAII slot for the per-core in-flight-request cap: incremented before spawn, decremented
/// when the spawned task ends (covers normal completion, drop, and panic). Single-threaded
/// monoio core ⇒ `Rc<Cell>`, no atomics.
struct InflightGuard(std::rc::Rc<std::cell::Cell<usize>>);
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

struct RequestChargeGuard {
    total: std::rc::Rc<std::cell::Cell<usize>>,
    bytes: usize,
}

impl Drop for RequestChargeGuard {
    fn drop(&mut self) {
        self.total.set(self.total.get().saturating_sub(self.bytes));
    }
}

/// Per-core cap on concurrently-dispatched H3 requests (bounds RAM: each in-flight request
/// pins its bytes + a PHP/pipeline request). At the cap the driver sheds with a 503 rather
/// than spawning, so a flood can't OOM the core.
const MAX_INFLIGHT_PER_CORE: usize = 1024;

/// Write a QUIC/HTTP-3 variable-length integer (RFC 9000 §16).
fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 64 {
        out.push(v as u8);
    } else if v < 16384 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1_073_741_824 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn write_varint_fixed(out: &mut [u8; 16], pos: &mut usize, v: u64) {
    if v < 64 {
        out[*pos] = v as u8;
        *pos += 1;
    } else if v < 16384 {
        let bytes = ((v as u16) | 0x4000).to_be_bytes();
        out[*pos..*pos + 2].copy_from_slice(&bytes);
        *pos += 2;
    } else if v < 1_073_741_824 {
        let bytes = ((v as u32) | 0x8000_0000).to_be_bytes();
        out[*pos..*pos + 4].copy_from_slice(&bytes);
        *pos += 4;
    } else {
        let bytes = (v | 0xc000_0000_0000_0000).to_be_bytes();
        out[*pos..*pos + 8].copy_from_slice(&bytes);
        *pos += 8;
    }
}

/// HPACK/QPACK integer with an `prefix_bits`-bit prefix (RFC 7541 §5.1).
fn qpack_int(out: &mut Vec<u8>, flags: u8, prefix_bits: u32, mut val: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if val < max {
        out.push(flags | val as u8);
        return;
    }
    out.push(flags | max as u8);
    val -= max;
    while val >= 128 {
        out.push((val as u8 & 0x7f) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

/// QPACK "Literal Field Line with Literal Name" (RFC 9204 §4.5.6), no Huffman, not
/// never-indexed. Always valid regardless of the peer's dynamic-table capacity, so
/// the response needs no QPACK static table / dynamic table / Huffman machinery.
fn qpack_literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    qpack_int(out, 0b0010_0000, 3, name.len() as u64); // 001 N=0 H=0 + 3-bit name len
    out.extend_from_slice(name);
    qpack_int(out, 0x00, 7, value.len() as u64); // H=0 + 7-bit value len
    out.extend_from_slice(value);
}

/// (#287) Encode-side view of [`QPACK_STATIC`]: header name → (lowest static
/// index carrying that name, the table's non-empty (value, index) pairs for
/// it). Derived once from the decode table so the two can never diverge.
struct QpackNameEntry {
    name_idx: u8,
    values: Vec<(&'static str, u8)>,
}

fn qpack_encode_map() -> &'static std::collections::HashMap<&'static str, QpackNameEntry> {
    static MAP: std::sync::OnceLock<std::collections::HashMap<&'static str, QpackNameEntry>> =
        std::sync::OnceLock::new();
    MAP.get_or_init(|| {
        let mut by_name = std::collections::HashMap::new();
        for (i, (name, value)) in QPACK_STATIC.iter().enumerate() {
            let entry = by_name.entry(*name).or_insert(QpackNameEntry {
                name_idx: i as u8,
                values: Vec::new(),
            });
            if !value.is_empty() {
                entry.values.push((*value, i as u8));
            }
        }
        by_name
    })
}

/// (#287) Emit one response field line using the static table where it helps:
/// an exact (name, value) match becomes an Indexed Field Line (RFC 9204
/// §4.5.2, 1-2 bytes); a known name becomes a Literal Field Line With Name
/// Reference (§4.5.4); anything else keeps the always-valid
/// literal-with-literal-name form. Static references only — no dynamic table,
/// no Huffman, no encoder state.
fn qpack_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    if let Some(entry) = qpack_encode_map().get(name) {
        if let Some((_, idx)) = entry.values.iter().find(|(v, _)| v.as_bytes() == value) {
            qpack_int(out, 0b1100_0000, 6, *idx as u64); // 1 T=1 + 6-bit index
            return;
        }
        qpack_int(out, 0b0101_0000, 4, entry.name_idx as u64); // 01 N=0 T=1 + 4-bit name index
        qpack_int(out, 0x00, 7, value.len() as u64); // H=0 + 7-bit value len
        out.extend_from_slice(value);
        return;
    }
    qpack_literal(out, name.as_bytes(), value);
}

/// The fixed HTTP/3 response (HEADERS frame with a QPACK field section + DATA
/// frame) — the H3 echo-level analog of the H1/H2 smoke responses.
fn h3_response_bytes() -> Vec<u8> {
    let body: &[u8] = b"httpjet-uring-h3\n";
    let mut field = Vec::new();
    field.extend_from_slice(&[0x00, 0x00]); // QPACK field section prefix: RIC=0, Base=0
    qpack_literal(&mut field, b":status", b"200");
    qpack_literal(&mut field, b"content-type", b"text/plain");
    qpack_literal(
        &mut field,
        b"content-length",
        body.len().to_string().as_bytes(),
    );
    let mut out = Vec::new();
    write_varint(&mut out, 0x01); // HEADERS frame
    write_varint(&mut out, field.len() as u64);
    out.extend_from_slice(&field);
    write_varint(&mut out, 0x00); // DATA frame
    write_varint(&mut out, body.len() as u64);
    out.extend_from_slice(body);
    out
}

/// How a `read_stream` pass ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadEnd {
    /// No more bytes available right now, but the stream is still open (no FIN yet).
    Open,
    /// Clean end of stream — FIN received; the buffered request is complete.
    Fin,
    /// The stream is gone: peer `RESET_STREAM`, or it is otherwise closed/unreadable.
    /// Its per-connection bookkeeping MUST be reclaimed — leaving it in `requests`
    /// would strand the slot + buffered bytes until the whole connection drains, which
    /// a client can abuse (open many streams, send partial bodies, reset without FIN)
    /// to pin per-connection memory.
    Gone,
}

fn for_each_stream_chunk<E, F>(
    conn: &mut quinn_proto::Connection,
    id: StreamId,
    mut consume: F,
) -> (ReadEnd, Result<(), E>)
where
    F: FnMut(&[u8]) -> Result<(), E>,
{
    let mut end = ReadEnd::Open;
    let mut result = Ok(());
    match conn.recv_stream(id).read(true) {
        Ok(mut chunks) => {
            loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(c)) => {
                        if let Err(error) = consume(&c.bytes) {
                            result = Err(error);
                            break;
                        }
                    }
                    Ok(None) => {
                        end = ReadEnd::Fin; // clean end of stream
                        break;
                    }
                    Err(quinn_proto::ReadError::Blocked) => break, // no more right now
                    Err(quinn_proto::ReadError::Reset(_)) => {
                        end = ReadEnd::Gone; // peer abandoned the stream
                        break;
                    }
                }
            }
            let _ = chunks.finalize();
        }
        // ClosedStream / IllegalOrderedRead: the stream can't be read again — reclaim it.
        Err(_) => end = ReadEnd::Gone,
    }
    (end, result)
}

/// Reclaim a request stream's per-connection bookkeeping (slot + buffered bytes),
/// returning whatever body was buffered. Used when a stream is gone (reset/closed),
/// oversize, or fully received — every removal from `requests` goes through here so a
/// stream can never be dropped from one map but left in the other.
fn reclaim_request(st: &mut H3State, id: StreamId) -> Bytes {
    let taken = take_request_for_dispatch(st, id);
    release_request_charge(st, taken.frames.charged);
    match taken.lease {
        Some(lease) => lease.into_bytes(taken.body),
        None => Bytes::from(taken.body),
    }
}

/// A request stream's receive state, removed from the connection in one step.
struct TakenRequest {
    body: Vec<u8>,
    frames: H3FrameCounter,
    lease: Option<hj_core::budget::BodyBufferLease>,
    snapshot: Option<H3RequestSnapshot>,
}

fn take_request_for_dispatch(st: &mut H3State, id: StreamId) -> TakenRequest {
    st.requests.remove(&id);
    let snapshot = st.request_snapshots.remove(&id);
    if let Some(deadline) = snapshot.as_ref().and_then(|snapshot| snapshot.deadline) {
        st.request_deadlines.remove(&deadline);
    }
    TakenRequest {
        body: st.req_buf.remove(&id).unwrap_or_default(),
        frames: st.req_frames.remove(&id).unwrap_or_default(),
        lease: st.body_leases.remove(&id),
        snapshot,
    }
}

/// Release unfinished request allocations as soon as the connection is lost.
/// Dispatched requests own separate leases and keep their remaining charge.
fn reclaim_buffered_requests(st: &mut H3State) {
    let bytes: usize = st.req_frames.values().map(|frames| frames.charged).sum();
    st.requests.clear();
    st.readable_requests.clear();
    st.request_deadlines.clear();
    st.request_snapshots.clear();
    st.req_frames.clear();
    st.req_buf.clear();
    st.body_leases.clear();
    release_request_charge(st, bytes);
}

/// Reclaim every request stream whose receive deadline has elapsed.
/// The caller resets both QUIC halves for each returned id so MAX_STREAMS credit
/// is released. The empty fast path does not allocate.
fn reclaim_expired_requests(st: &mut H3State, now: Instant) -> Vec<StreamId> {
    let mut expired = Vec::new();
    while let Some(id) = st.first_expired_request(now) {
        drop(reclaim_request(st, id));
        expired.push(id);
    }
    expired
}

fn release_request_charge(st: &mut H3State, bytes: usize) {
    st.total_req_bytes
        .set(st.total_req_bytes.get().saturating_sub(bytes));
}

/// A decoded request field section and its RFC 9114 §4.2.2 size.
type DecodedFieldSection = (Vec<(Vec<u8>, Vec<u8>)>, usize);

/// The request head as the frame counter sees it. It is decoded when the first DATA
/// frame header arrives (a body-less request is never decoded here), so a declared
/// content-length bounds the body while it is received (#1049). Dispatch reuses it.
#[derive(Default)]
enum H3RequestHead {
    #[default]
    Pending,
    /// QPACK rejected the field section; dispatch answers 400.
    Undecodable,
    Decoded {
        fields: DecodedFieldSection,
        content_length: Option<usize>,
    },
}

fn decode_request_head(field: &[u8], max_header_bytes: usize) -> H3RequestHead {
    let Some(fields) = qpack_decode_limited(field, max_header_bytes) else {
        return H3RequestHead::Undecodable;
    };
    // An unresolvable length is left to dispatch, which answers 400 for it.
    let content_length = super::codec::resolve_content_length(
        fields
            .0
            .iter()
            .filter(|(name, _)| name.as_slice() == b"content-length")
            .map(|(_, value)| value.as_slice()),
    )
    .ok()
    .flatten();
    H3RequestHead::Decoded {
        fields,
        content_length,
    }
}

/// Heap a decoded field section retains until dispatch: each field's slot and its
/// owned name and value, plus RFC 9114's 32 bytes per field for allocator rounding.
/// A one-byte static reference decodes to about 80 bytes, so this, not the wire
/// size, is what the request must hold against its budgets.
fn decoded_head_footprint(fields: &[(Vec<u8>, Vec<u8>)], slots: usize) -> usize {
    fields.iter().fold(
        slots.saturating_mul(std::mem::size_of::<(Vec<u8>, Vec<u8>)>()),
        |sum, (name, value)| {
            sum.saturating_add(32)
                .saturating_add(name.capacity())
                .saturating_add(value.capacity())
        },
    )
}

/// Frames one request may carry that advance neither its head nor its body: empty
/// DATA or HEADERS, and extension or reserved (grease) frames. A client sends a
/// handful; each costs a frame parse but no buffered progress, so a flood of them is
/// closed with H3_EXCESSIVE_LOAD (H2 bounds the same class at this count).
const H3_NO_PROGRESS_FRAMES: u32 = 10_000;

/// Incremental parser for one request stream. The receive path validates every frame
/// once, as it arrives, and keeps only what dispatch needs: the field sections and the
/// DATA payloads, compacted into the stream's body buffer. Dispatch never reparses.
#[derive(Default)]
struct H3FrameCounter {
    phase: H3FramePhase,
    varint: [u8; 8],
    varint_len: usize,
    varint_need: usize,
    frame_type: u64,
    header_bytes: usize,
    body_bytes: usize,
    /// Request-stream bytes received, framing included.
    wire_bytes: usize,
    /// Bytes this stream holds against the connection's `total_req_bytes`: its wire
    /// bytes and its decoded head.
    charged: usize,
    /// [`decoded_head_footprint`] of `head` once decoded.
    head_footprint: usize,
    no_progress_frames: u32,
    /// The first HEADERS frame's payload (the request field section).
    field: Option<Vec<u8>>,
    trailers: Option<Vec<u8>>,
    /// The frame sequence is not a request (dispatch answers 400): DATA before the
    /// head or after trailers, or a third HEADERS frame.
    malformed: bool,
    head: H3RequestHead,
}

#[derive(Clone, Copy, Default)]
enum H3FramePhase {
    #[default]
    Type,
    Length,
    Payload(usize, PayloadSink),
}

/// Where a frame payload's bytes are kept.
#[derive(Clone, Copy)]
enum PayloadSink {
    Field,
    Trailers,
    Body,
    Discard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestFrameError {
    Limit,
    Unexpected,
    /// The request's header section is over `maxReqHeaderSize`: answered 431, as H1/H2.
    HeadersTooLarge,
    /// The body is over the configured maximum and its head decoded: answered 413.
    TooLarge,
    /// DATA past the declared content-length (RFC 9114 §4.1.2): H3_MESSAGE_ERROR.
    Malformed,
    /// Over [`H3_NO_PROGRESS_FRAMES`]: the connection is closed with H3_EXCESSIVE_LOAD.
    ExcessiveLoad,
}

fn request_frame_forbidden(frame_type: u64) -> bool {
    matches!(
        frame_type,
        0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0d
    )
}

impl H3FrameCounter {
    fn reset_varint(&mut self) {
        self.varint_len = 0;
        self.varint_need = 0;
    }

    fn consume_varint(&mut self, input: &[u8], pos: &mut usize) -> Option<u64> {
        while *pos < input.len() {
            let byte = input[*pos];
            *pos += 1;
            if self.varint_len == 0 {
                self.varint_need = 1usize << (byte >> 6);
            }
            self.varint[self.varint_len] = byte;
            self.varint_len += 1;
            if self.varint_len == self.varint_need {
                let mut value = u64::from(self.varint[0] & 0x3f);
                for byte in &self.varint[1..self.varint_need] {
                    value = (value << 8) | u64::from(*byte);
                }
                self.reset_varint();
                return Some(value);
            }
        }
        None
    }

    /// Validate `input`, the next bytes of the request stream, appending its DATA
    /// payloads to `body`.
    fn consume(
        &mut self,
        input: &[u8],
        body: &mut Vec<u8>,
        limits: H3RequestLimits,
    ) -> Result<(), RequestFrameError> {
        let mut pos = 0usize;
        while pos < input.len() {
            match self.phase {
                H3FramePhase::Type => {
                    let Some(frame_type) = self.consume_varint(input, &mut pos) else {
                        break;
                    };
                    self.frame_type = frame_type;
                    self.phase = H3FramePhase::Length;
                }
                H3FramePhase::Length => {
                    let Some(length) = self.consume_varint(input, &mut pos) else {
                        break;
                    };
                    if request_frame_forbidden(self.frame_type) {
                        return Err(RequestFrameError::Unexpected);
                    }
                    let Ok(length) = usize::try_from(length) else {
                        return Err(RequestFrameError::Limit);
                    };
                    if length == 0 || !matches!(self.frame_type, 0x00 | 0x01) {
                        self.no_progress_frames += 1;
                        if self.no_progress_frames > H3_NO_PROGRESS_FRAMES {
                            return Err(RequestFrameError::ExcessiveLoad);
                        }
                    }
                    let sink = match self.frame_type {
                        0x01 => {
                            let Some(total) = self.header_bytes.checked_add(length) else {
                                return Err(RequestFrameError::HeadersTooLarge);
                            };
                            if total > limits.max_header_bytes {
                                return Err(RequestFrameError::HeadersTooLarge);
                            }
                            self.header_bytes = total;
                            if self.field.is_none() {
                                self.field = Some(Vec::new());
                                PayloadSink::Field
                            } else if self.trailers.is_none() {
                                self.trailers = Some(Vec::new());
                                PayloadSink::Trailers
                            } else {
                                self.malformed = true;
                                PayloadSink::Discard
                            }
                        }
                        0x00 => {
                            self.data_frame(length, limits)?;
                            if self.field.is_none() || self.trailers.is_some() {
                                self.malformed = true;
                            }
                            if self.malformed {
                                PayloadSink::Discard
                            } else {
                                PayloadSink::Body
                            }
                        }
                        _ => PayloadSink::Discard,
                    };
                    self.phase = if length == 0 {
                        H3FramePhase::Type
                    } else {
                        H3FramePhase::Payload(length, sink)
                    };
                }
                H3FramePhase::Payload(remaining, sink) => {
                    let consumed = remaining.min(input.len() - pos);
                    let payload = &input[pos..pos + consumed];
                    match sink {
                        PayloadSink::Field => self
                            .field
                            .get_or_insert_default()
                            .extend_from_slice(payload),
                        PayloadSink::Trailers => self
                            .trailers
                            .get_or_insert_default()
                            .extend_from_slice(payload),
                        PayloadSink::Body => body.extend_from_slice(payload),
                        PayloadSink::Discard => {}
                    }
                    pos += consumed;
                    self.phase = if consumed == remaining {
                        H3FramePhase::Type
                    } else {
                        H3FramePhase::Payload(remaining - consumed, sink)
                    };
                }
            }
        }
        Ok(())
    }

    /// Admit the next DATA frame's declared `length`. The frame header is checked
    /// before any of its payload is buffered, as H2 checks each DATA frame (#1014).
    fn data_frame(
        &mut self,
        length: usize,
        limits: H3RequestLimits,
    ) -> Result<(), RequestFrameError> {
        if matches!(self.head, H3RequestHead::Pending)
            && let Some(field) = self.field.as_deref()
        {
            self.head = decode_request_head(field, limits.max_header_bytes);
            if let H3RequestHead::Decoded {
                fields: (fields, _),
                ..
            } = &self.head
            {
                self.head_footprint = decoded_head_footprint(fields, fields.capacity());
            }
        }
        let Some(total) = self.body_bytes.checked_add(length) else {
            return Err(RequestFrameError::Limit);
        };
        let declared = match &self.head {
            H3RequestHead::Decoded { content_length, .. } => Some(*content_length),
            _ => None,
        };
        if let Some(Some(content_length)) = declared {
            if content_length > limits.max_body_bytes {
                return Err(RequestFrameError::TooLarge);
            }
            if total > content_length {
                return Err(RequestFrameError::Malformed);
            }
        }
        if total > limits.max_body_bytes {
            // Without a decoded head there is no request to answer.
            return Err(if declared.is_some() {
                RequestFrameError::TooLarge
            } else {
                RequestFrameError::Limit
            });
        }
        self.body_bytes = total;
        Ok(())
    }

    /// The request received through FIN: its field sections, `body` (carrying `lease`)
    /// and the head decoded on the receive path, if any. `None` when the stream does not
    /// hold exactly one request (dispatch answers 400).
    fn finish(
        self,
        body: Vec<u8>,
        lease: Option<hj_core::budget::BodyBufferLease>,
    ) -> Option<(ParsedH3Request, Option<DecodedFieldSection>)> {
        let at_frame_boundary = matches!(self.phase, H3FramePhase::Type) && self.varint_len == 0;
        if self.malformed || !at_frame_boundary {
            return None;
        }
        let field = self.field?;
        let body = if body.is_empty() {
            Bytes::new()
        } else {
            match lease {
                // Dispatch consumes the decoded head before its first await; only the
                // wire bytes stay reserved for the body's lifetime.
                Some(mut lease) => {
                    lease.release(self.head_footprint as u64);
                    lease.into_bytes(body)
                }
                None => Bytes::from(body),
            }
        };
        let head = match self.head {
            H3RequestHead::Decoded { fields, .. } => Some(fields),
            _ => None,
        };
        Some((
            ParsedH3Request {
                field,
                body,
                trailers: self.trailers,
            },
            head,
        ))
    }

    #[cfg(test)]
    fn decoded_head(&self) -> Option<&DecodedFieldSection> {
        match &self.head {
            H3RequestHead::Decoded { fields, .. } => Some(fields),
            _ => None,
        }
    }
}

/// Returns the stream's received bytes, framing included.
fn append_request_bytes(
    st: &mut H3State,
    id: StreamId,
    bytes: &[u8],
    limits: H3RequestLimits,
) -> Result<usize, RequestFrameError> {
    let Some(total) = st.total_req_bytes.get().checked_add(bytes.len()) else {
        return Err(RequestFrameError::Limit);
    };
    if total > limits.max_connection_bytes {
        return Err(RequestFrameError::Limit);
    }
    let frames = st.req_frames.entry(id).or_default();
    let decoded_before = frames.head_footprint;
    frames.consume(bytes, st.req_buf.entry(id).or_default(), limits)?;
    // The head decodes at most once, at the first DATA frame header.
    let charge = bytes.len() + (frames.head_footprint - decoded_before);
    let Some(total) = total.checked_add(charge - bytes.len()) else {
        return Err(RequestFrameError::Limit);
    };
    if total > limits.max_connection_bytes {
        return Err(RequestFrameError::Limit);
    }
    // (security #263) Reserve against the server-wide budget before accounting, so
    // pre-dispatch accumulation is bounded by the same cap as H1/H2/LSAPI. The
    // owned reservation follows the body through dispatch and every drop path.
    if let Some(budget) = st.body_budget.clone() {
        let lease = st
            .body_leases
            .entry(id)
            .or_insert_with(|| hj_core::budget::BodyBufferLease::new(budget));
        if !lease.reserve(charge as u64) {
            return Err(RequestFrameError::Limit);
        }
    }
    frames.charged += charge;
    frames.wire_bytes += bytes.len();
    st.total_req_bytes.set(total);
    if frames.wire_bytes > limits.max_request_wire_bytes {
        Err(RequestFrameError::Limit)
    } else {
        Ok(frames.wire_bytes)
    }
}

#[derive(Default)]
struct IncrementalVarInt {
    bytes: [u8; 8],
    len: usize,
    need: usize,
}

impl IncrementalVarInt {
    fn consume(&mut self, input: &[u8], pos: &mut usize) -> Option<u64> {
        while *pos < input.len() {
            let byte = input[*pos];
            *pos += 1;
            if self.len == 0 {
                self.need = 1usize << (byte >> 6);
            }
            self.bytes[self.len] = byte;
            self.len += 1;
            if self.len == self.need {
                let mut value = u64::from(self.bytes[0] & 0x3f);
                for byte in &self.bytes[1..self.need] {
                    value = (value << 8) | u64::from(*byte);
                }
                self.len = 0;
                self.need = 0;
                return Some(value);
            }
        }
        None
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PeerSettings {
    qpack_max_table_capacity: Option<u64>,
    max_field_section_size: Option<u64>,
    qpack_blocked_streams: Option<u64>,
    enable_connect_protocol: Option<u64>,
    h3_datagram: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct H3ConnectionError {
    code: u32,
    reason: &'static [u8],
}

impl H3ConnectionError {
    const fn new(code: u32, reason: &'static [u8]) -> Self {
        Self { code, reason }
    }
}

#[derive(Default)]
struct SettingsParser {
    varint: IncrementalVarInt,
    pending_id: Option<u64>,
    seen: std::collections::HashSet<u64>,
    parsed: PeerSettings,
}

impl SettingsParser {
    fn consume(&mut self, input: &[u8]) -> Result<(), H3ConnectionError> {
        let mut pos = 0;
        while pos < input.len() {
            let Some(value) = self.varint.consume(input, &mut pos) else {
                break;
            };
            if let Some(id) = self.pending_id.take() {
                if !self.seen.insert(id) {
                    return Err(H3ConnectionError::new(
                        H3_SETTINGS_ERROR,
                        b"duplicate HTTP/3 setting",
                    ));
                }
                match id {
                    0x01 => self.parsed.qpack_max_table_capacity = Some(value),
                    0x02..=0x05 => {
                        return Err(H3ConnectionError::new(
                            H3_SETTINGS_ERROR,
                            b"reserved HTTP/2 setting identifier",
                        ));
                    }
                    0x06 => self.parsed.max_field_section_size = Some(value),
                    0x07 => self.parsed.qpack_blocked_streams = Some(value),
                    0x08 if value <= 1 => self.parsed.enable_connect_protocol = Some(value),
                    0x08 => {
                        return Err(H3ConnectionError::new(
                            H3_SETTINGS_ERROR,
                            b"invalid enable-connect setting",
                        ));
                    }
                    0x33 if value <= 1 => self.parsed.h3_datagram = Some(value),
                    0x33 => {
                        return Err(H3ConnectionError::new(
                            H3_SETTINGS_ERROR,
                            b"invalid H3 datagram setting",
                        ));
                    }
                    _ => {}
                }
            } else {
                self.pending_id = Some(value);
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<PeerSettings, H3ConnectionError> {
        if self.varint.len != 0 || self.pending_id.is_some() {
            Err(H3ConnectionError::new(
                H3_SETTINGS_ERROR,
                b"truncated HTTP/3 setting",
            ))
        } else {
            Ok(self.parsed)
        }
    }
}

#[derive(Default)]
struct ControlStreamParser {
    phase: ControlFramePhase,
    varint: IncrementalVarInt,
    frame_type: u64,
    settings_received: bool,
    settings: Option<SettingsParser>,
    completed_settings: Option<PeerSettings>,
}

#[derive(Clone, Copy, Default)]
enum ControlFramePhase {
    #[default]
    Type,
    Length,
    Payload(usize),
}

impl ControlStreamParser {
    fn finish_payload(&mut self) -> Result<(), H3ConnectionError> {
        if self.frame_type == 0x04 {
            let settings = self.settings.take().unwrap_or_default().finish()?;
            self.completed_settings = Some(settings);
        }
        self.phase = ControlFramePhase::Type;
        Ok(())
    }

    fn consume(&mut self, input: &[u8]) -> Result<(), H3ConnectionError> {
        let mut pos = 0;
        while pos < input.len() {
            match self.phase {
                ControlFramePhase::Type => {
                    let Some(frame_type) = self.varint.consume(input, &mut pos) else {
                        break;
                    };
                    if !self.settings_received && frame_type != 0x04 {
                        return Err(H3ConnectionError::new(
                            H3_MISSING_SETTINGS,
                            b"SETTINGS is not the first control frame",
                        ));
                    }
                    if frame_type == 0x04 && self.settings_received {
                        return Err(H3ConnectionError::new(
                            H3_FRAME_UNEXPECTED,
                            b"duplicate SETTINGS frame",
                        ));
                    }
                    if matches!(frame_type, 0x00 | 0x01 | 0x02 | 0x05 | 0x06 | 0x08 | 0x09) {
                        return Err(H3ConnectionError::new(
                            H3_FRAME_UNEXPECTED,
                            b"frame is forbidden on the control stream",
                        ));
                    }
                    self.frame_type = frame_type;
                    self.phase = ControlFramePhase::Length;
                }
                ControlFramePhase::Length => {
                    let Some(length) = self.varint.consume(input, &mut pos) else {
                        break;
                    };
                    let length = usize::try_from(length).map_err(|_| {
                        H3ConnectionError::new(H3_SETTINGS_ERROR, b"control frame too large")
                    })?;
                    if self.frame_type == 0x04 {
                        if length > MAX_SETTINGS_PAYLOAD {
                            return Err(H3ConnectionError::new(
                                H3_EXCESSIVE_LOAD,
                                b"HTTP/3 SETTINGS payload is excessive",
                            ));
                        }
                        self.settings_received = true;
                        self.settings = Some(SettingsParser::default());
                    }
                    if length == 0 {
                        self.finish_payload()?;
                    } else {
                        self.phase = ControlFramePhase::Payload(length);
                    }
                }
                ControlFramePhase::Payload(remaining) => {
                    let consumed = remaining.min(input.len() - pos);
                    if self.frame_type == 0x04 {
                        self.settings
                            .as_mut()
                            .expect("SETTINGS parser exists while its payload is active")
                            .consume(&input[pos..pos + consumed])?;
                    }
                    pos += consumed;
                    if consumed == remaining {
                        self.finish_payload()?;
                    } else {
                        self.phase = ControlFramePhase::Payload(remaining - consumed);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum PeerUniKind {
    #[default]
    Pending,
    Control,
    QpackEncoder,
    QpackDecoder,
    Unknown,
}

#[derive(Default)]
struct PeerUniStream {
    kind: PeerUniKind,
    stream_type: IncrementalVarInt,
    control: ControlStreamParser,
}

fn register_peer_uni_type(
    state: &mut H3State,
    id: StreamId,
    stream_type: u64,
) -> Result<PeerUniKind, H3ConnectionError> {
    let (slot, kind) = match stream_type {
        0x00 => (&mut state.peer_control, PeerUniKind::Control),
        0x01 => {
            return Err(H3ConnectionError::new(
                H3_STREAM_CREATION_ERROR,
                b"client opened an HTTP/3 push stream",
            ));
        }
        0x02 => (&mut state.peer_qpack_encoder, PeerUniKind::QpackEncoder),
        0x03 => (&mut state.peer_qpack_decoder, PeerUniKind::QpackDecoder),
        _ => return Ok(PeerUniKind::Unknown),
    };
    if slot.is_some() {
        return Err(H3ConnectionError::new(
            H3_STREAM_CREATION_ERROR,
            b"duplicate HTTP/3 critical stream",
        ));
    }
    *slot = Some(id);
    Ok(kind)
}

fn consume_peer_uni(
    state: &mut H3State,
    id: StreamId,
    stream: &mut PeerUniStream,
    input: &[u8],
) -> Result<(), H3ConnectionError> {
    let mut pos = 0;
    if stream.kind == PeerUniKind::Pending {
        let Some(stream_type) = stream.stream_type.consume(input, &mut pos) else {
            return Ok(());
        };
        stream.kind = register_peer_uni_type(state, id, stream_type)?;
    }
    if stream.kind == PeerUniKind::Control {
        stream.control.consume(&input[pos..])?;
        if let Some(settings) = stream.control.completed_settings.take() {
            state
                .peer_max_field_section_size
                .set(settings.max_field_section_size);
            state.peer_settings = Some(settings);
        }
    }
    Ok(())
}

fn finish_peer_uni(stream: &PeerUniStream) -> Result<(), H3ConnectionError> {
    match stream.kind {
        // RFC 9114 §6.2: a receiver MUST tolerate a unidirectional stream closed or reset
        // before its stream type arrives.
        PeerUniKind::Pending => Ok(()),
        PeerUniKind::Control if !stream.control.settings_received => Err(H3ConnectionError::new(
            H3_MISSING_SETTINGS,
            b"control stream closed before SETTINGS",
        )),
        PeerUniKind::Control | PeerUniKind::QpackEncoder | PeerUniKind::QpackDecoder => Err(
            H3ConnectionError::new(H3_CLOSED_CRITICAL_STREAM, b"HTTP/3 critical stream closed"),
        ),
        PeerUniKind::Unknown => Ok(()),
    }
}

fn service_peer_uni(
    conn: &mut quinn_proto::Connection,
    state: &mut H3State,
) -> Result<(), H3ConnectionError> {
    while let Some(id) = conn.streams().accept(Dir::Uni) {
        state.peer_uni.entry(id).or_default();
    }
    let mut ids = [None; MAX_PEER_UNI_STREAMS];
    for (slot, id) in ids.iter_mut().zip(state.peer_uni.keys().copied()) {
        *slot = Some(id);
    }
    for id in ids.into_iter().flatten() {
        let Some(mut stream) = state.peer_uni.remove(&id) else {
            continue;
        };
        let (end, consumed) = for_each_stream_chunk(conn, id, |bytes| {
            consume_peer_uni(state, id, &mut stream, bytes)
        });
        consumed?;
        match end {
            ReadEnd::Open => {
                state.peer_uni.insert(id, stream);
            }
            ReadEnd::Fin | ReadEnd::Gone => finish_peer_uni(&stream)?,
        }
    }
    Ok(())
}

async fn send_endpoint_datagram(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    payload: &[u8],
    destination: SocketAddr,
    src_ip: Option<std::net::IpAddr>,
) {
    // Reply from the address the client's Initial was sent to: on a wildcard bind a
    // plain send_to lets the kernel pick another local address, and a connected
    // client socket drops the Retry/refusal (#894).
    let transmit = UdpTransmit {
        destination,
        ecn: None,
        contents: payload,
        segment_size: None,
        src_ip,
    };
    loop {
        // SAFETY: `udp` owns the fd and outlives this borrow.
        let bfd = unsafe { BorrowedFd::borrow_raw(udp.as_raw_fd()) };
        match udp_state.try_send(UdpSockRef::from(&bfd), &transmit) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if udp.writable(false).await.is_err() {
                    return;
                }
            }
            _ => return,
        }
    }
}

/// The per-core datagram loop. On loopback, QUIC is driven by the packet exchange
/// (client Initial → our response → ...), so servicing connection timers after each
/// received datagram suffices for handshake + request/response; precise timer
/// scheduling (idle/retransmit on a quiet link) is a later refinement.
async fn endpoint_loop<H, Fut>(
    udp: UdpSocket,
    mut endpoint: Endpoint,
    handle_request: H,
) -> io::Result<()>
where
    H: Fn(Bytes, bool, SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Vec<u8>>,
{
    let mut conns: HashMap<ConnectionHandle, quinn_proto::Connection> = HashMap::new();
    let mut h3: HashMap<ConnectionHandle, H3State> = HashMap::new();
    let mut scratch: Vec<u8> = Vec::with_capacity(MAX_DATAGRAM);
    let mut tx_scratch: Vec<u8> = Vec::with_capacity(MAX_DATAGRAM);
    let udp_state = {
        let bfd = unsafe { BorrowedFd::borrow_raw(udp.as_raw_fd()) };
        UdpSocketState::new(UdpSockRef::from(&bfd))?
    };
    // Reused across recvs — monoio's recv_from takes the buffer by value and hands it
    // back, so threading one buffer avoids a per-datagram heap allocation.
    let mut recv_buf: Vec<u8> = vec![0u8; MAX_DATAGRAM];
    loop {
        crate::memtrim::collect_if_requested_on_thread();
        let (res, buf) = udp.recv_from(recv_buf).await;
        recv_buf = buf;
        let (n, remote) = match res {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let now = Instant::now();
        let data = BytesMut::from(&recv_buf[..n]);
        scratch.clear();
        if let Some(ev) = endpoint.handle(now, remote, None, None, data, &mut scratch) {
            match ev {
                DatagramEvent::Response(t) => {
                    send_endpoint_datagram(
                        &udp,
                        &udp_state,
                        &scratch[..t.size],
                        t.destination,
                        t.src_ip,
                    )
                    .await;
                }
                DatagramEvent::NewConnection(incoming) => {
                    scratch.clear();
                    match endpoint.accept(incoming, now, &mut scratch, None) {
                        Ok((handle, conn)) => {
                            conns.insert(handle, conn);
                            h3.insert(handle, H3State::default());
                        }
                        Err(e) => {
                            if let Some(t) = e.response {
                                send_endpoint_datagram(
                                    &udp,
                                    &udp_state,
                                    &scratch[..t.size],
                                    t.destination,
                                    t.src_ip,
                                )
                                .await;
                            }
                            tracing::debug!(error = ?e.cause, "uring h3: accept rejected");
                        }
                    }
                }
                DatagramEvent::ConnectionEvent(handle, cev) => {
                    if let Some(conn) = conns.get_mut(&handle) {
                        conn.handle_event(cev);
                    }
                }
            }
        }
        drive_connections(
            &udp,
            &udp_state,
            &mut endpoint,
            &mut conns,
            &mut h3,
            now,
            &handle_request,
            &mut tx_scratch,
        )
        .await;
        conns.retain(|hd, c| {
            let drained = c.is_drained();
            if drained {
                h3.remove(hd);
            }
            !drained
        });
    }
}

const LOCAL_CONTROL_PREFIX: &[u8] = &[0x00, 0x04, 0x00];
const LOCAL_QPACK_ENCODER_PREFIX: &[u8] = &[0x02];
const LOCAL_QPACK_DECODER_PREFIX: &[u8] = &[0x03];

trait LocalUniIo {
    fn open_uni(&mut self) -> Option<StreamId>;
    fn write_uni(&mut self, id: StreamId, bytes: &[u8]) -> Result<usize, WriteError>;
}

impl LocalUniIo for quinn_proto::Connection {
    fn open_uni(&mut self) -> Option<StreamId> {
        self.streams().open(Dir::Uni)
    }

    fn write_uni(&mut self, id: StreamId, bytes: &[u8]) -> Result<usize, WriteError> {
        self.send_stream(id).write(bytes)
    }
}

fn pump_local_uni_prefix<I: LocalUniIo>(
    io: &mut I,
    stream: &mut Option<StreamId>,
    offset: &mut usize,
    prefix: &[u8],
) -> Result<bool, WriteError> {
    if *offset == prefix.len() {
        return Ok(true);
    }
    if stream.is_none() {
        *stream = io.open_uni();
    }
    let Some(id) = *stream else {
        return Ok(false);
    };
    match io.write_uni(id, &prefix[*offset..]) {
        Ok(0) | Err(WriteError::Blocked) => Ok(false),
        Ok(written) => {
            assert!(
                written <= prefix.len() - *offset,
                "QUIC stream write exceeded the supplied prefix"
            );
            *offset += written;
            Ok(*offset == prefix.len())
        }
        Err(error) => Err(error),
    }
}

fn pump_local_h3_setup<I: LocalUniIo>(io: &mut I, st: &mut H3State) -> Result<(), WriteError> {
    if st.control_setup {
        return Ok(());
    }
    if !pump_local_uni_prefix(
        io,
        &mut st.control_stream,
        &mut st.control_stream_off,
        LOCAL_CONTROL_PREFIX,
    )? {
        return Ok(());
    }
    if !pump_local_uni_prefix(
        io,
        &mut st.qpack_encoder_stream,
        &mut st.qpack_encoder_stream_off,
        LOCAL_QPACK_ENCODER_PREFIX,
    )? {
        return Ok(());
    }
    if !pump_local_uni_prefix(
        io,
        &mut st.qpack_decoder_stream,
        &mut st.qpack_decoder_stream_off,
        LOCAL_QPACK_DECODER_PREFIX,
    )? {
        return Ok(());
    }
    st.control_setup = true;
    Ok(())
}

/// Service one connection's non-request I/O (shared by the smoke + concurrent drivers):
/// a due timeout, the endpoint↔connection event feedback loop, app events (Connected →
/// open the HTTP/3 control + QPACK streams + SETTINGS per RFC 9114 §6.2), and accept +
/// drain client uni (control/QPACK) streams + accept new request bidi streams. Request
/// serving + datagram flush are the caller's job (they differ between drivers).
fn service_conn(
    endpoint: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    hd: ConnectionHandle,
    now: Instant,
    accepting_requests: bool,
    fallback_request_config: H3RequestConfig,
) {
    let due = conns
        .get_mut(&hd)
        .and_then(|c| c.poll_timeout())
        .is_some_and(|t| t <= now);
    if due {
        if let Some(c) = conns.get_mut(&hd) {
            c.handle_timeout(now);
        }
    }
    while let Some(ev) = conns.get_mut(&hd).and_then(|c| c.poll_endpoint_events()) {
        if let Some(cev) = endpoint.handle_event(hd, ev) {
            if let Some(c) = conns.get_mut(&hd) {
                c.handle_event(cev);
            }
        }
    }
    let st = h3.entry(hd).or_default();
    if !accepting_requests {
        st.draining = true;
    }
    let mut writable: Vec<StreamId> = Vec::new();
    let mut readable: Vec<StreamId> = Vec::new();
    let mut stopped: Vec<StreamId> = Vec::new();
    let mut connection_lost = false;
    while let Some(ev) = conns.get_mut(&hd).and_then(|c| c.poll()) {
        match ev {
            Event::Connected => {
                let leaf = conns.get(&hd).and_then(|conn| {
                    conn.crypto_session()
                        .peer_identity()
                        .and_then(|identity| {
                            identity
                                .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                                .ok()
                        })
                        .and_then(|certificates| {
                            certificate_chain_present(&certificates)
                                .then(|| certificates[0].clone())
                        })
                });
                let eligible = conns.get(&hd).is_some_and(|conn| {
                    h3_client_eligible(
                        st.client_auth.required(),
                        leaf.is_some(),
                        conn.remote_address(),
                    )
                });
                let budget = match st.pending_budget.take() {
                    Some(pending) => {
                        super::ConnectionPermit::try_acquire(pending.active, pending.cap)
                            .map(Some)
                            .ok_or(())
                    }
                    None => Ok(None),
                };
                if !eligible {
                    st.rejected = true;
                    if let Some(conn) = conns.get_mut(&hd) {
                        conn.close(
                            now,
                            quinn_proto::VarInt::from_u32(0x010b),
                            bytes::Bytes::from_static(b"client certificate required"),
                        );
                    }
                } else if let Ok(permit) = budget {
                    if permit.is_some() {
                        st._connection_permit = permit;
                    }
                    // always TLS 1.3 (RFC 9001); quinn-proto exposes the client cert chain but
                    // not the negotiated cipher, so report the QUIC-mandatory AEAD — same as
                    // the tokio H3 path — and parse the client leaf for SSL_CLIENT_* CGI vars.
                    st.tls = Some(hj_tls::tls_params_from_parts(
                        "TLSv1.3",
                        "TLS_AES_128_GCM_SHA256".to_string(),
                        leaf.as_ref(),
                    ));
                    st.client_leaf = leaf;
                    st.server_name = conns.get(&hd).and_then(h3_handshake_server_name);
                    st.connected = true;
                    tracing::info!("uring h3: QUIC handshake complete (Connected)");
                } else {
                    H3_REFUSED_BUDGET.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    st.rejected = true;
                    if let Some(conn) = conns.get_mut(&hd) {
                        conn.close(
                            now,
                            quinn_proto::VarInt::from_u32(H3_EXCESSIVE_LOAD),
                            bytes::Bytes::from_static(b"connection budget exhausted"),
                        );
                    }
                }
            }
            // A previously flow-control-blocked response stream can now write more.
            Event::Stream(StreamEvent::Writable { id }) => writable.push(id),
            Event::Stream(StreamEvent::Readable { id }) => readable.push(id),
            Event::Stream(StreamEvent::Stopped { id, .. }) => stopped.push(id),
            Event::ConnectionLost { .. } => connection_lost = true,
            _ => {}
        }
    }
    if connection_lost {
        cancel_all_dispatched_requests(st);
        reclaim_buffered_requests(st);
        st.rejected = true;
        st.handshake_slot = None;
        return;
    }
    if st
        .handshake_deadline()
        .is_some_and(|deadline| deadline <= now)
    {
        H3_HANDSHAKE_TIMEOUTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        st.rejected = true;
        if let Some(conn) = conns.get_mut(&hd) {
            conn.close(
                now,
                quinn_proto::VarInt::from_u32(H3_EXCESSIVE_LOAD),
                Bytes::from_static(b"handshake timeout"),
            );
        }
    }
    if st.connected || st.rejected {
        st.handshake_slot = None;
    }
    for id in readable {
        if st.queue_readable_request(id) || !st.request_cancellations.contains_key(&id) {
            continue;
        }
        let reset = conns.get_mut(&hd).is_some_and(|conn| {
            conn.recv_stream(id)
                .received_reset()
                .ok()
                .flatten()
                .is_some()
        });
        if reset {
            cancel_dispatched_request(st, id);
            if let Some(conn) = conns.get_mut(&hd) {
                let _ = conn
                    .send_stream(id)
                    .reset(quinn_proto::VarInt::from_u32(H3_REQUEST_CANCELLED));
            }
            if let Some(error) = charge_request_cancel(st, now) {
                close_h3_connection(conns, hd, now, error);
                return;
            }
        }
    }
    if st.rejected {
        cancel_all_dispatched_requests(st);
        return;
    }
    // Resume any large responses that were blocked on the stream window.
    for id in writable {
        if let Some(c) = conns.get_mut(&hd) {
            pump_stream(c, st, id);
        }
    }
    if st.connected && !st.control_setup {
        if let Some(c) = conns.get_mut(&hd) {
            // Each prefix retains its accepted offset. QUIC may accept only a prefix or return
            // Blocked when the peer's uni-stream data window is small; setup remains unlatched
            // and retries after the corresponding Writable/MAX_STREAM_DATA event.
            if pump_local_h3_setup(c, st).is_err() {
                st.rejected = true;
                c.close(
                    now,
                    quinn_proto::VarInt::from_u32(H3_CLOSED_CRITICAL_STREAM),
                    Bytes::from_static(b"local HTTP/3 critical stream closed"),
                );
            }
        }
    }
    if st.draining {
        if let Some(c) = conns.get_mut(&hd) {
            send_h3_goaway(c, st);
        }
    }
    if let Some(c) = conns.get_mut(&hd) {
        if let Err(error) = service_peer_uni(c, st) {
            st.rejected = true;
            c.close(
                now,
                quinn_proto::VarInt::from_u32(error.code),
                Bytes::from_static(error.reason),
            );
            return;
        }
    }
    // Read the clock only if this drive actually accepts a request stream. All
    // streams already available in the batch share one fresh acceptance time
    // and configuration generation. Keeping both lazy avoids an Arc clone and
    // clock read on the much more common packet drive with no newly accepted
    // request stream.
    let mut accepted_at = None;
    let mut request_snapshot = None;
    let mut accepted_this_drive = 0u32;
    while let Some(id) = conns.get_mut(&hd).and_then(|c| c.streams().accept(Dir::Bi)) {
        if let Err(error) = admit_request_stream(st, &mut accepted_this_drive) {
            st.rejected = true;
            if let Some(c) = conns.get_mut(&hd) {
                c.close(
                    now,
                    quinn_proto::VarInt::from_u32(error.code),
                    Bytes::from_static(error.reason),
                );
            }
            break;
        }
        if accepting_requests {
            st.next_request_stream_index = st.next_request_stream_index.max(id.index() + 1);
            let accepted_at = *accepted_at.get_or_insert_with(Instant::now);
            if request_snapshot.is_none() {
                request_snapshot = Some(st.request_snapshot(fallback_request_config));
            }
            st.track_request_stream(
                id,
                accepted_at,
                request_snapshot
                    .as_ref()
                    .expect("accepted request snapshot was initialized")
                    .clone(),
            );
        } else if let Some(c) = conns.get_mut(&hd) {
            let code = quinn_proto::VarInt::from_u32(0x010b);
            let _ = c.recv_stream(id).stop(code);
            let _ = c.send_stream(id).reset(code);
        }
    }
    if st.rejected {
        return;
    }
    // After the accept loop: a STOP_SENDING that arrived with its request must find the
    // stream tracked, or the stream would later be dispatched with no cancellation token.
    for id in stopped {
        if let Some(error) = reject_stopped_local_critical_stream(st, id) {
            close_h3_connection(conns, hd, now, error);
            return;
        }
        let receiving = st.requests.contains(&id);
        let unanswered = receiving || st.request_cancellations.contains_key(&id);
        if receiving {
            reclaim_request(st, id);
        }
        cancel_dispatched_request(st, id);
        if let Some(conn) = conns.get_mut(&hd) {
            let _ = conn
                .send_stream(id)
                .reset(quinn_proto::VarInt::from_u32(H3_REQUEST_CANCELLED));
            if receiving {
                let _ = conn
                    .recv_stream(id)
                    .stop(quinn_proto::VarInt::from_u32(H3_REQUEST_CANCELLED));
            }
        }
        if unanswered && let Some(error) = charge_request_cancel(st, now) {
            close_h3_connection(conns, hd, now, error);
            return;
        }
    }
}

fn close_h3_connection(
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    hd: ConnectionHandle,
    now: Instant,
    error: H3ConnectionError,
) {
    if let Some(conn) = conns.get_mut(&hd) {
        conn.close(
            now,
            quinn_proto::VarInt::from_u32(error.code),
            Bytes::from_static(error.reason),
        );
    }
}

/// Bound request-stream admission independently of the QUIC layer. A conformant
/// peer can never have more than the advertised MAX_STREAMS open, so one drive can
/// accept at most that many. The live-request bound keeps a 2x margin because a
/// stream leaves `requests` only when this driver observes its completion.
fn admit_request_stream(
    st: &H3State,
    accepted_this_drive: &mut u32,
) -> Result<(), H3ConnectionError> {
    *accepted_this_drive += 1;
    if *accepted_this_drive > MAX_CONCURRENT_BIDI_STREAMS
        || st.requests.len() >= 2 * MAX_CONCURRENT_BIDI_STREAMS as usize
    {
        return Err(H3ConnectionError::new(
            H3_EXCESSIVE_LOAD,
            b"request streams exceed the advertised limit",
        ));
    }
    Ok(())
}

fn send_h3_goaway(conn: &mut quinn_proto::Connection, st: &mut H3State) {
    if st.goaway_sent || !st.control_setup {
        return;
    }
    let Some(control) = st.control_stream else {
        return;
    };
    if st.goaway_buf.is_empty() {
        let id = quinn_proto::VarInt::from(StreamId::new(
            quinn_proto::Side::Client,
            Dir::Bi,
            st.next_request_stream_index,
        ))
        .into_inner();
        let mut payload = Vec::new();
        write_varint(&mut payload, id);
        write_varint(&mut st.goaway_buf, 0x07);
        write_varint(&mut st.goaway_buf, payload.len() as u64);
        st.goaway_buf.extend_from_slice(&payload);
    }
    match conn
        .send_stream(control)
        .write(&st.goaway_buf[st.goaway_off..])
    {
        Ok(n) => {
            st.goaway_off += n;
            if st.goaway_off == st.goaway_buf.len() {
                st.goaway_sent = true;
            }
        }
        Err(WriteError::Blocked) => {}
        Err(_) => st.goaway_sent = true,
    }
}

fn h3_client_eligible(require_client_cert: bool, has_client_cert: bool, peer: SocketAddr) -> bool {
    !require_client_cert || has_client_cert || hj_core::is_trusted_internal_peer(peer.ip())
}

fn certificate_chain_present(certificates: &[rustls::pki_types::CertificateDer<'static>]) -> bool {
    !certificates.is_empty()
}

/// GSO segments per `poll_transmit` and datagrams per flush — mirrors quinn's own driver
/// (`MAX_TRANSMIT_SEGMENTS` / `MAX_TRANSMIT_DATAGRAMS`). The point is NOT batch size — it's
/// that draining the WHOLE congestion window in one synchronous burst (our old behavior, GSO
/// 64, loop-until-None) starves incoming ACK processing, so quinn-proto's loss detection
/// misfires → spurious loss → cwnd collapse (measured ~48% "loss" on large transfers). Sending
/// a bounded chunk then RETURNING lets the loop process ACKs (recv arm) before sending more,
/// exactly like quinn's send/yield interleave. Returns true if more remains (caller re-drives).
const MAX_TX_SEGMENTS: usize = 10;
const MAX_TX_DATAGRAMS: usize = 20;

/// Read per transmit, never cached: quinn-udp drops its GSO cap to 1 after a
/// segmented send fails with EIO/EINVAL (IPsec, no checksum offload), and every
/// later multi-segment transmit would fail the same way (#1048).
fn tx_segment_cap(udp_state: &UdpSocketState) -> usize {
    udp_state.max_gso_segments().clamp(1, MAX_TX_SEGMENTS)
}

async fn flush_conn(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    hd: ConnectionHandle,
    now: Instant,
    tbuf: &mut Vec<u8>,
) -> bool {
    let mut datagrams = 0usize;
    loop {
        tbuf.clear();
        let seg_cap = tx_segment_cap(udp_state);
        let t = match conns
            .get_mut(&hd)
            .and_then(|c| c.poll_transmit(now, seg_cap, tbuf))
        {
            Some(t) => t,
            None => return false,
        };
        datagrams += t.segment_size.map_or(1, |s| t.size.div_ceil(s));
        // quinn-proto and quinn-udp each define EcnCodepoint; map by codepoint bits.
        let ecn = t
            .ecn
            .and_then(|e| quinn_udp::EcnCodepoint::from_bits(e as u8));
        let transmit = UdpTransmit {
            destination: t.destination,
            ecn,
            contents: &tbuf[..t.size],
            segment_size: t.segment_size,
            src_ip: t.src_ip,
        };
        loop {
            let bfd = unsafe { BorrowedFd::borrow_raw(udp.as_raw_fd()) };
            match udp_state.try_send(UdpSockRef::from(&bfd), &transmit) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if udp.writable(false).await.is_err() {
                        return false;
                    }
                }
                Err(_) => break, // drop this transmit; QUIC loss recovery retransmits
            }
        }
        if datagrams >= MAX_TX_DATAGRAMS {
            return true; // more may remain — yield so ACKs are processed before sending more
        }
    }
}

/// The SMOKE driver (fixed-response A/B): service each connection, serve request streams
/// INLINE (await the handler in the connection loop — serializes requests per core), flush.
/// The production path is [`drive_connections_concurrent`].
#[allow(clippy::too_many_arguments)]
async fn drive_connections<H, Fut>(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    endpoint: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    now: Instant,
    handle_request: &H,
    tx_scratch: &mut Vec<u8>,
) where
    H: Fn(Bytes, bool, SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Vec<u8>>,
{
    let handles: Vec<ConnectionHandle> = conns.keys().copied().collect();
    for hd in handles {
        // The fixed-response smoke driver has no ServerState/config generation;
        // production deadlines are enforced by endpoint_loop_concurrent below.
        let smoke_config =
            H3RequestConfig::new(H3RequestLimits::new(64 * 1024, MAX_H3_REQ_BYTES), None);
        service_conn(endpoint, conns, h3, hd, now, true, smoke_config);
        if h3.get(&hd).is_some_and(|state| state.rejected) {
            flush_conn(udp, udp_state, conns, hd, now, tx_scratch).await;
            continue;
        }
        let st = h3.entry(hd).or_default();
        let finished = match conns.get_mut(&hd) {
            Some(c) => receive_request_streams(c, st, now),
            None => Vec::new(),
        };
        if st.rejected {
            for id in finished {
                reclaim_request(st, id);
            }
        } else {
            for id in finished {
                let req_bytes = reclaim_request(st, id);
                let peer = conns
                    .get(&hd)
                    .map(|c| c.remote_address())
                    .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                let has_client_cert = conns
                    .get(&hd)
                    .map(|c| c.crypto_session().peer_identity().is_some())
                    .unwrap_or(false);
                let resp = handle_request(req_bytes, has_client_cert, peer).await;
                if let Some(c) = conns.get_mut(&hd) {
                    let mut ss = c.send_stream(id);
                    let _ = ss.write(&resp);
                    let _ = ss.finish();
                }
            }
        }
        flush_conn(udp, udp_state, conns, hd, now, tx_scratch).await;
    }
}

/// A future that resolves at `deadline` (a quinn-proto timer), or never if `None`.
async fn sleep_until_opt(deadline: Option<Instant>, now: Instant) {
    match deadline {
        Some(t) => monoio::time::sleep(t.saturating_duration_since(now)).await,
        None => std::future::pending::<()>().await,
    }
}

/// Write a spawned request's finished response back onto its connection's send stream, then
/// flush. Dropped if the connection is gone OR its epoch changed (the `ConnectionHandle` was
/// reused by a NEWER connection while the request was in flight) — never cross-writes.
/// A spawned request's response may write back only if its connection still exists, remains
/// protocol-eligible, and its epoch is unchanged (the `ConnectionHandle` was not reused by a
/// newer connection while the request was in flight). Pure so it can be unit-tested.
fn completion_is_live(
    h3: &HashMap<ConnectionHandle, H3State>,
    conn: ConnectionHandle,
    epoch: u64,
) -> bool {
    h3.get(&conn)
        .is_some_and(|state| state.epoch == epoch && !state.rejected)
}

/// Write as much of a stream's pending response as the QUIC flow-control window allows,
/// advancing its offset; `finish()` + drop the entry once fully written. On `Blocked` it
/// stops (resumes on the next `StreamEvent::Writable`); on `Stopped`/`ClosedStream` (peer
/// cancelled) it drops the entry. This is what makes responses larger than one stream
/// window (e.g. multi-MB files) stream out correctly instead of truncating.
fn pump_stream(conn: &mut quinn_proto::Connection, st: &mut H3State, id: StreamId) {
    let Some(entry) = st.pending.get_mut(&id) else {
        return;
    };
    let mut ss = conn.send_stream(id);
    let mut cancelled = false;
    let mut sent = 0u64;
    let done = loop {
        let Some(part) = entry.parts.front_mut() else {
            break entry.finish_if_drained(|| ss.finish().is_ok());
        };
        match part.write(&mut ss, &mut sent) {
            Ok(true) => {
                acknowledge_front_part(entry);
            }
            Ok(false) | Err(WriteError::Blocked) => break false,
            // The peer's STOP_SENDING is also queued as `StreamEvent::Stopped`, which
            // cancels the dispatched work and charges the cancellation budget.
            Err(WriteError::Stopped(_)) => break true,
            Err(_) => {
                cancelled = true;
                break true;
            }
        }
    };
    if cancelled {
        cancel_dispatched_request(st, id);
    } else if done {
        st.pending.remove(&id);
    } else {
        entry.stall =
            advance_send_stall(entry.stall, sent, !entry.parts.is_empty(), Instant::now());
    }
}

/// Reset every response whose send-stall window expired, releasing its bridge
/// admission slot, backend body and egress leases (the H3 form of h2's #599).
fn reclaim_stalled_sends(st: &mut H3State, now: Instant) -> Vec<StreamId> {
    let Some(timeout) = st.send_stall_timeout else {
        return Vec::new();
    };
    let expired: Vec<StreamId> = st
        .pending
        .iter()
        .filter(|(_, p)| p.stall.is_some_and(|s| s.since + timeout <= now))
        .map(|(id, _)| *id)
        .collect();
    for id in &expired {
        H3_SEND_STALL_RESETS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cancel_dispatched_request(st, *id);
    }
    expired
}

#[allow(clippy::too_many_arguments)]
/// Queue a finished request's response on its stream. The caller then drives the
/// connection, whose flush sends every completion of the batch together.
fn write_completion(
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    c: Completion,
) {
    if !completion_is_live(h3, c.conn, c.epoch)
        || !h3
            .get(&c.conn)
            .is_some_and(|state| state.request_cancellations.contains_key(&c.stream))
    {
        return; // connection/stream gone, or handle reused by a different connection
    }
    let Completion {
        conn: ch,
        stream,
        kind,
        ..
    } = c;
    let (Some(conn), Some(st)) = (conns.get_mut(&ch), h3.get_mut(&ch)) else {
        return;
    };
    match kind {
        // A whole buffered response: send and finish when drained.
        CompletionKind::Full(resp, completion, lease) => {
            st.request_cancellations.remove(&stream);
            st.pending.insert(
                stream,
                PendingSend {
                    completion,
                    parts: std::iter::once(PendingPart::contiguous(resp, lease)).collect(),
                    fin: true,
                    stall: None,
                },
            );
        }
        // HEADERS of a streamed response: DATA chunks follow, so don't finish yet.
        CompletionKind::Head(head, completion, lease) => {
            st.pending.insert(
                stream,
                PendingSend {
                    completion,
                    parts: std::iter::once(PendingPart::contiguous(head, lease)).collect(),
                    fin: false,
                    stall: None,
                },
            );
        }
        // Append a DATA chunk to the open stream; `fin` marks the body complete. No live
        // pending entry ⇒ the stream was cancelled / its conn went away → drop the chunk.
        CompletionKind::Chunk {
            data,
            fin,
            ack,
            lease,
        } => match st.pending.get_mut(&stream) {
            Some(entry) => {
                if !data.is_empty() {
                    entry
                        .parts
                        .push_back(PendingPart::data_frame(data, ack, lease));
                }
                if fin {
                    entry.fin = true;
                    st.request_cancellations.remove(&stream);
                }
            }
            None => return,
        },
        // Mid-stream abort: reset the send stream rather than a clean finish, so the
        // peer sees the body was truncated (mirrors the H1 path).
        CompletionKind::Abort(code) => {
            st.request_cancellations.remove(&stream);
            if let Some(mut pending) = st.pending.remove(&stream) {
                if let Some(completion) = pending.completion.take() {
                    completion.finish(hj_core::ResponseEnd::Error);
                }
            }
            let _ = conn
                .send_stream(stream)
                .reset(quinn_proto::VarInt::from_u32(code));
            return;
        }
    }
    pump_stream(conn, st, stream); // write what the window allows; remainder pumps on Writable
}

/// Read every unfinished request stream into its buffer, retiring the ones that
/// are gone or refused, and return those that reached FIN. A forbidden frame closes
/// the connection (`st.rejected`), which ends the pass.
fn receive_request_streams(
    c: &mut quinn_proto::Connection,
    st: &mut H3State,
    now: Instant,
) -> Vec<StreamId> {
    let mut req_ids = std::mem::take(&mut st.readable_requests);
    let mut finished = Vec::new();
    for &id in &req_ids {
        let Some((request_limits, progress)) = st.request_snapshots.get_mut(&id).map(|snapshot| {
            snapshot.read_queued = false;
            (snapshot.config.limits, snapshot.progress)
        }) else {
            if st.requests.contains(&id) {
                // Internal invariant failure: never receive under a live-reloaded
                // policy chosen after this stream began. Reclaim and fail closed.
                reclaim_request(st, id);
                refuse_request_stream(c, st, id, RequestFrameError::Limit);
            }
            // Otherwise reclaimed (stopped, expired or refused) since it was queued.
            continue;
        };
        let mut buffered = None;
        let (end, append) = for_each_stream_chunk(c, id, |bytes| {
            append_request_bytes(st, id, bytes, request_limits).map(|len| buffered = Some(len))
        });
        if end == ReadEnd::Gone {
            // Peer RESET_STREAM (or the stream is otherwise gone): reclaim the slot +
            // buffer now. Without this, a reset-without-FIN stream stays in `requests`
            // and its buffered bytes in `req_buf` until the whole connection drains —
            // a per-connection memory-exhaustion vector on the H3 path.
            reclaim_request(st, id);
            // Also retire the server's SEND half of this client-initiated BIDI stream.
            // quinn-proto reissues the remote-bidi MAX_STREAMS credit only when the stream is
            // FULLY freed, which for the recv half requires the send half to be finished/reset
            // too. A client that RESET_STREAMs its send side (our recv) WITHOUT STOP_SENDING our
            // send side would otherwise leave `self.send` holding the id forever — 256 such
            // recv-only resets exhaust max_concurrent_bidi_streams and wedge the connection.
            let _ = c
                .send_stream(id)
                .reset(quinn_proto::VarInt::from_u32(H3_REQUEST_CANCELLED));
            if let Some(error) = charge_request_cancel(st, now) {
                c.close(
                    now,
                    quinn_proto::VarInt::from_u32(error.code),
                    Bytes::from_static(error.reason),
                );
                break;
            }
            continue;
        }
        match append {
            Err(error @ (RequestFrameError::Unexpected | RequestFrameError::ExcessiveLoad)) => {
                reclaim_request(st, id);
                st.rejected = true;
                let (code, reason): (u32, &'static [u8]) = if error == RequestFrameError::Unexpected
                {
                    (
                        H3_FRAME_UNEXPECTED,
                        b"frame is forbidden on a request stream",
                    )
                } else {
                    (H3_EXCESSIVE_LOAD, b"request stream frames make no progress")
                };
                c.close(
                    now,
                    quinn_proto::VarInt::from_u32(code),
                    Bytes::from_static(reason),
                );
                break;
            }
            Err(error) => {
                reclaim_request(st, id);
                refuse_request_stream(c, st, id, error);
                continue;
            }
            Ok(()) => {}
        }
        if end == ReadEnd::Fin {
            finished.push(id);
        } else if let Some(buffered) = buffered
            && progress.is_some_and(|progress| progress.due(buffered as u64))
        {
            st.extend_request_deadline(id, buffered, now);
        }
    }
    // Keep the allocation for the next pass.
    req_ids.clear();
    if st.readable_requests.is_empty() {
        st.readable_requests = req_ids;
    }
    finished
}

/// Retire a request stream the receive path refused, closing both halves so
/// quinn-proto frees it and reissues the peer's MAX_STREAMS credit.
fn refuse_request_stream(
    c: &mut quinn_proto::Connection,
    st: &mut H3State,
    id: StreamId,
    error: RequestFrameError,
) {
    let code = match error {
        RequestFrameError::TooLarge | RequestFrameError::HeadersTooLarge => {
            // (#1049) As H1/H2 (#1014): a complete 413/431 rather than a reset the
            // client may retry with the whole request, then STOP_SENDING(H3_NO_ERROR) so
            // it stops sending and keeps the response (RFC 9114 §4.1). Dispatch waits
            // for FIN, so no response has started on this stream.
            let _ = c
                .recv_stream(id)
                .stop(quinn_proto::VarInt::from_u32(H3_NO_ERROR));
            let response = if error == RequestFrameError::TooLarge {
                h3_payload_too_large()
            } else {
                h3_error(http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
            };
            queue_final_response(c, st, id, response);
            return;
        }
        RequestFrameError::Malformed => H3_MESSAGE_ERROR,
        RequestFrameError::ExcessiveLoad => H3_EXCESSIVE_LOAD,
        RequestFrameError::Limit | RequestFrameError::Unexpected => H3_REQUEST_CANCELLED,
    };
    let code = quinn_proto::VarInt::from_u32(code);
    let _ = c.recv_stream(id).stop(code);
    let _ = c.send_stream(id).reset(code);
}

/// Drive ONE connection: service its I/O, spawn a task per finished request (QPACK decode +
/// bridge dispatch to PHP/pipeline + response encode → handed back over `comp_tx`, so a slow
/// request never head-of-line-blocks other streams/connections), then flush. Backpressure: at
/// `MAX_INFLIGHT_PER_CORE`, shed a 503. A received datagram affects exactly ONE connection, so
/// the loop drives only that handle — O(1) per packet, not O(conns) (the latter collapsed
/// large-transfer throughput to ~0.34× tokio/quinn).
#[allow(clippy::too_many_arguments)]
async fn drive_one_conn(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    endpoint: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    hd: ConnectionHandle,
    now: Instant,
    local: SocketAddr,
    bridge: &Bridge,
    inflight: &std::rc::Rc<std::cell::Cell<usize>>,
    comp_tx: &flume::Sender<Completion>,
    fallback_request_config: H3RequestConfig,
    accepting_requests: bool,
    tx_scratch: &mut Vec<u8>,
) -> bool {
    if !conns.contains_key(&hd) {
        return false;
    }
    service_conn(
        endpoint,
        conns,
        h3,
        hd,
        now,
        accepting_requests,
        fallback_request_config,
    );
    if h3.get(&hd).is_some_and(|state| state.rejected) {
        if let Some(state) = h3.get_mut(&hd) {
            cancel_all_dispatched_requests(state);
            reclaim_buffered_requests(state);
        }
        return flush_conn(udp, udp_state, conns, hd, now, tx_scratch).await;
    }
    let epoch = h3.get(&hd).map(|s| s.epoch).unwrap_or(0);
    let st = h3.entry(hd).or_default();
    let client_auth = st.client_auth;

    // A live connection can receive traffic on other streams forever, so QUIC's
    // connection-wide idle timer cannot bound an unfinished request. Expire these
    // streams independently and reset both halves to return MAX_STREAMS credit.
    for id in reclaim_expired_requests(st, now) {
        if let Some(c) = conns.get_mut(&hd) {
            let code = quinn_proto::VarInt::from_u32(H3_REQUEST_CANCELLED);
            let _ = c.recv_stream(id).stop(code);
            let _ = c.send_stream(id).reset(code);
        }
    }
    // QUIC's idle timer restarts on any peer packet (a PING), so it cannot bound a
    // response the peer starves of flow-control credit.
    st.send_stall_timeout = fallback_request_config.timeout;
    for id in reclaim_stalled_sends(st, now) {
        if let Some(c) = conns.get_mut(&hd) {
            let _ = c
                .send_stream(id)
                .reset(quinn_proto::VarInt::from_u32(H3_REQUEST_CANCELLED));
        }
    }
    let finished = match conns.get_mut(&hd) {
        Some(c) => receive_request_streams(c, st, now),
        None => Vec::new(),
    };
    if st.rejected {
        for id in finished {
            reclaim_request(st, id);
        }
        cancel_all_dispatched_requests(st);
        reclaim_buffered_requests(st);
        return flush_conn(udp, udp_state, conns, hd, now, tx_scratch).await;
    }
    for id in finished {
        let TakenRequest {
            body: req_body,
            frames: req_frames,
            lease: body_lease,
            snapshot: request_snapshot,
        } = take_request_for_dispatch(st, id);
        let req_charge = req_frames.charged;
        let Some(request_snapshot) = request_snapshot else {
            release_request_charge(st, req_charge);
            if let Some(c) = conns.get_mut(&hd) {
                let code = quinn_proto::VarInt::from_u32(H3_REQUEST_CANCELLED);
                let _ = c.recv_stream(id).stop(code);
                let _ = c.send_stream(id).reset(code);
            }
            continue;
        };
        // Peer + TLS params captured up front (no connection borrow into the task).
        let peer = conns
            .get(&hd)
            .map(|c| c.remote_address())
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        // SERVER_ADDR is the interface the client reached, not a wildcard bind (the
        // TCP paths take it from getsockname; QUIC from the datagram's IP_PKTINFO).
        let local = request_local_addr(local, conns.get(&hd).and_then(|c| c.local_ip()));
        let sni = st.server_name.clone();
        let has_client_cert = st.client_leaf.is_some();
        let tls = st.tls.clone();
        if inflight.get() >= MAX_INFLIGHT_PER_CORE {
            // Backpressure: shed inline rather than spawning (bounds RAM under a flood).
            if let Some(c) = conns.get_mut(&hd) {
                queue_final_response(c, st, id, h3_error(http::StatusCode::SERVICE_UNAVAILABLE));
            }
            release_request_charge(st, req_charge);
            continue;
        }
        inflight.set(inflight.get() + 1);
        let guard = InflightGuard(inflight.clone());
        let charge = RequestChargeGuard {
            total: st.total_req_bytes.clone(),
            bytes: req_charge,
        };
        let cancel = CancellationToken::new();
        st.request_cancellations.insert(id, cancel.clone());
        let egress_budget = st.egress_budget.clone();
        let shutdown = st.shutdown.clone();
        let peer_max_field_section = st.peer_max_field_section_size.clone();
        let bridge = bridge.clone();
        let tx = comp_tx.clone();
        let request_limits = request_snapshot.config.limits;
        let request_generation = request_snapshot.generation;
        // spawn() is synchronous (no await) — `st`'s borrow of `h3` is not held across an await.
        let work = async move {
            let _g = guard; // frees the in-flight slot on completion / drop / panic
            let send = |kind| {
                tx.send_async(Completion {
                    conn: hd,
                    stream: id,
                    epoch,
                    kind,
                })
            };
            let outcome = handle_h3_request(
                req_frames,
                req_body,
                body_lease,
                has_client_cert,
                tls,
                sni,
                peer,
                local,
                &bridge,
                client_auth,
                request_limits,
                request_generation,
                egress_budget.clone(),
                peer_max_field_section,
            )
            .await;
            drop(charge);
            let _ = async {
                let H3Outcome { body, completion } = outcome;
                match body {
                    H3Body::Full { data, lease } => {
                        send(CompletionKind::Full(data, completion, lease))
                            .await
                            .map_err(|_| ())?;
                    }
                    H3Body::Stream {
                        head,
                        head_lease,
                        mut rx,
                    } => {
                        // The driver is the sole stream writer: send the HEADERS, then forward each
                        // DATA chunk in order. Each chunk is acknowledged only after QUIC drains it.
                        send(CompletionKind::Head(head, completion, head_lease))
                            .await
                            .map_err(|_| ())?;
                        let mut stopping = false;
                        loop {
                            let next = match &shutdown {
                                Some(shutdown) => {
                                    super::next_stream_chunk(&mut rx, shutdown, &mut stopping).await
                                }
                                None => Ok(rx.recv().await),
                            };
                            let Ok(next) = next else {
                                send(CompletionKind::Abort(H3_REQUEST_CANCELLED))
                                    .await
                                    .map_err(|_| ())?;
                                break;
                            };
                            match next {
                                Some(Ok(chunk)) => {
                                    if chunk.is_empty() {
                                        continue;
                                    }
                                    let (ack_tx, ack_rx) = flume::bounded(1);
                                    let lease = match egress_budget.as_ref() {
                                        Some(budget) => {
                                            let Some(lease) =
                                                budget.reserve(chunk.len().saturating_add(16))
                                            else {
                                                send(CompletionKind::Abort(H3_INTERNAL_ERROR))
                                                    .await
                                                    .map_err(|_| ())?;
                                                break;
                                            };
                                            Some(lease)
                                        }
                                        None => None,
                                    };
                                    send(CompletionKind::Chunk {
                                        data: chunk,
                                        fin: false,
                                        ack: Some(ack_tx),
                                        lease,
                                    })
                                    .await
                                    .map_err(|_| ())?;
                                    ack_rx.recv_async().await.map_err(|_| ())?;
                                }
                                Some(Err(())) => {
                                    send(CompletionKind::Abort(H3_INTERNAL_ERROR))
                                        .await
                                        .map_err(|_| ())?;
                                    break;
                                }
                                None => {
                                    send(CompletionKind::Chunk {
                                        data: Bytes::new(),
                                        fin: true,
                                        ack: None,
                                        lease: None,
                                    })
                                    .await
                                    .map_err(|_| ())?;
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok::<(), ()>(())
            }
            .await;
        };
        monoio::spawn(run_cancelable_request(cancel, work));
    }
    flush_conn(udp, udp_state, conns, hd, now, tx_scratch).await
}

/// recvmmsg slots: fixed, initialized storage the kernel writes into on every pass.
/// Nothing handed to quinn-proto ever borrows from them (see [`received_segments`]).
type RecvSlots = [Vec<u8>; GRO_BATCH];

fn recv_slots() -> RecvSlots {
    std::array::from_fn(|_| vec![0u8; MAX_DATAGRAM])
}

fn recv_iovecs(slots: &mut RecvSlots) -> [std::io::IoSliceMut<'_>; GRO_BATCH] {
    slots.each_mut().map(|slot| std::io::IoSliceMut::new(slot))
}

/// Copy one received message out of its slot as one exact-size buffer per GRO
/// segment (`stride` 0 = not coalesced). quinn-proto retains received CRYPTO and
/// STREAM frames as slices of the datagram it is handed but charges only the packet
/// payload, so a datagram sharing a larger allocation (the 64 KiB slot, or the
/// coalesced message) let a peer pin that whole allocation per tiny packet (#1046).
fn received_segments(message: &[u8], stride: usize) -> impl Iterator<Item = BytesMut> + '_ {
    let stride = if stride == 0 { message.len() } else { stride };
    message.chunks(stride.max(1)).map(BytesMut::from)
}

/// Non-blocking GRO drain: pull up to [`MAX_RECV_DRAIN_BATCHES`] batches (recvmmsg into
/// reused slots, GRO-coalesced, split by `stride`), feed quinn-proto, and return the set
/// of connections that got new state. Connections whose absolute request deadline became
/// due during the bounded drain are included so the caller drives them immediately.
#[allow(clippy::too_many_arguments)]
async fn recv_drain(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    recv_bufs: &mut RecvSlots,
    recv_metas: &mut [quinn_udp::RecvMeta; GRO_BATCH],
    scratch: &mut Vec<u8>,
    endpoint: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    deadlines: &mut ConnectionDeadlineIndex,
    epoch_ctr: &mut u64,
    handshakes: &Arc<AtomicU64>,
    runtime: &H3RuntimeConfig,
    policy: &QuicServerPolicy,
    accepting_connections: bool,
    now: Instant,
) -> std::collections::HashSet<ConnectionHandle> {
    let mut affected: std::collections::HashSet<ConnectionHandle> =
        std::collections::HashSet::new();
    let mut completed_batches = 0;
    loop {
        let nmsg = {
            let mut iov = recv_iovecs(recv_bufs);
            // SAFETY: `udp` owns the fd and outlives this borrow.
            let bfd = unsafe { BorrowedFd::borrow_raw(udp.as_raw_fd()) };
            match udp_state.recv(UdpSockRef::from(&bfd), &mut iov, recv_metas) {
                Ok(n) => n,
                Err(_) => break, // WouldBlock (drained) or error → stop
            }
        };
        if nmsg == 0 {
            break;
        }
        completed_batches += 1;
        for (meta, buf) in recv_metas.iter().zip(recv_bufs.iter()).take(nmsg) {
            let Some(message) = buf.get(..meta.len) else {
                continue;
            };
            let pecn = meta
                .ecn
                .and_then(|e| quinn_proto::EcnCodepoint::from_bits(e as u8));
            for seg in received_segments(message, meta.stride) {
                scratch.clear();
                if let Some(ev) = endpoint.handle(now, meta.addr, meta.dst_ip, pecn, seg, scratch) {
                    match ev {
                        DatagramEvent::Response(t) => {
                            send_endpoint_datagram(
                                udp,
                                udp_state,
                                &scratch[..t.size],
                                t.destination,
                                t.src_ip,
                            )
                            .await;
                        }
                        DatagramEvent::NewConnection(incoming) => {
                            scratch.clear();
                            let accepting = accepting_connections
                                && policy
                                    .serving_view
                                    .as_ref()
                                    .is_none_or(|view| view.is_current_trust_epoch());
                            match admit_incoming(
                                endpoint, incoming, now, scratch, accepting, runtime, handshakes,
                            ) {
                                Admission::Accepted(handle, conn, slot) => {
                                    *epoch_ctr += 1;
                                    conns.insert(handle, conn);
                                    h3.insert(
                                        handle,
                                        runtime.accepted_state_with_policy(
                                            slot, now, *epoch_ctr, policy,
                                        ),
                                    );
                                    affected.insert(handle);
                                }
                                Admission::Transmit(transmit) => {
                                    send_endpoint_datagram(
                                        udp,
                                        udp_state,
                                        &scratch[..transmit.size],
                                        transmit.destination,
                                        transmit.src_ip,
                                    )
                                    .await;
                                }
                                Admission::Dropped => {}
                            }
                        }
                        DatagramEvent::ConnectionEvent(handle, cev) => {
                            if let Some(conn) = conns.get_mut(&handle) {
                                conn.handle_event(cev);
                                affected.insert(handle);
                            }
                        }
                    }
                }
            }
        }
        if !recv_drain_should_continue(completed_batches, nmsg) {
            break; // short batch drained the socket; full batches stop at the cooperative cap
        }
    }
    deadlines.extend_due(&mut affected, Instant::now());
    affected
}

/// Cooperative send/recv pump (mirrors quinn's drive_transmit + wake_by_ref interleave):
/// drive the `to_drive` connections (each sends a bounded ≤20-datagram chunk), then process
/// any ACKs those sends elicited, and repeat — so a connection streams its whole
/// congestion-window of data back-to-back WITHOUT a per-chunk RTT wait, while ACK processing
/// stays interleaved so loss detection doesn't misfire. Bounded by `MAX_PUMP_ROUNDS` so one
/// connection can't monopolize the core; the remainder resumes on the next readiness wake.
#[allow(clippy::too_many_arguments)]
async fn pump(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    recv_bufs: &mut RecvSlots,
    recv_metas: &mut [quinn_udp::RecvMeta; GRO_BATCH],
    scratch: &mut Vec<u8>,
    tx_scratch: &mut Vec<u8>,
    endpoint: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    deadlines: &mut ConnectionDeadlineIndex,
    epoch_ctr: &mut u64,
    handshakes: &Arc<AtomicU64>,
    inflight: &std::rc::Rc<std::cell::Cell<usize>>,
    bridge: &Bridge,
    local: SocketAddr,
    comp_tx: &flume::Sender<Completion>,
    runtime: &H3RuntimeConfig,
    policy: &QuicServerPolicy,
    accepting: bool,
    mut to_drive: std::collections::HashSet<ConnectionHandle>,
) {
    const MAX_PUMP_ROUNDS: usize = 64;
    let mut rounds = 0;
    let mut touched: Vec<ConnectionHandle> = Vec::new();
    while !to_drive.is_empty() && rounds < MAX_PUMP_ROUNDS {
        rounds += 1;
        let mut next: std::collections::HashSet<ConnectionHandle> =
            std::collections::HashSet::new();
        for hd in to_drive.drain() {
            touched.push(hd);
            // Earlier handles can await UDP writability. Refresh the clock per
            // handle so QUIC timers and request deadlines never use a stale round
            // timestamp under load.
            let now = Instant::now();
            let more_to_send = drive_one_conn(
                udp,
                udp_state,
                endpoint,
                conns,
                h3,
                hd,
                now,
                local,
                bridge,
                inflight,
                comp_tx,
                runtime.request_config(),
                accepting,
                tx_scratch,
            )
            .await;
            deadlines.sync(hd, connection_deadline(conns, h3, hd));
            if more_to_send {
                next.insert(hd); // hit the per-flush datagram cap → more to send
            }
        }
        // Process ACKs our sends elicited so cwnd/loss-detection stay current.
        let now = Instant::now();
        for hd in recv_drain(
            udp, udp_state, recv_bufs, recv_metas, scratch, endpoint, conns, h3, deadlines,
            epoch_ctr, handshakes, runtime, policy, accepting, now,
        )
        .await
        {
            next.insert(hd);
        }
        to_drive = next;
    }
    // A deadline can become due in recv_drain() after the final cooperative
    // round, and that drain's events can move a QUIC timer. extend_due() removes
    // a due node while adding the handle to `to_drive`; if the round cap then ends
    // the loop, re-sync every such handle so the endpoint's outer pre-select check
    // (or its timer) drives it. Transmit work keeps the pre-existing wakeup path.
    for hd in &to_drive {
        deadlines.sync(*hd, connection_deadline(conns, h3, *hd));
    }
    touched.extend(to_drive.iter().copied());
    // A connection drains only inside a quinn call on its own handle, and this pump made
    // those calls on the handles it touched; scanning every connection after every event
    // made each wakeup cost O(connections). A full scan still runs at most once a second.
    let full = LAST_FULL_REAP.with(|last| {
        let now = Instant::now();
        let due = now.duration_since(last.get()) >= FULL_REAP_EVERY;
        if due {
            last.set(now);
        }
        due
    });
    let drained: Vec<ConnectionHandle> = if full {
        conns
            .iter()
            .filter(|(_, c)| c.is_drained())
            .map(|(hd, _)| *hd)
            .collect()
    } else {
        touched.retain(|hd| conns.get(hd).is_some_and(|c| c.is_drained()));
        touched
    };
    for hd in drained {
        if conns.remove(&hd).is_some() {
            h3.remove(&hd);
            deadlines.remove(hd);
        }
    }
}

/// How often [`pump`] also checks every connection for a drained one (see its end).
const FULL_REAP_EVERY: Duration = Duration::from_secs(1);

thread_local! {
    static LAST_FULL_REAP: std::cell::Cell<Instant> = std::cell::Cell::new(Instant::now());
}

fn h3_drain_complete(
    h3: &HashMap<ConnectionHandle, H3State>,
    inflight: usize,
    completion_queue_empty: bool,
) -> bool {
    inflight == 0
        && completion_queue_empty
        && h3.values().all(|state| {
            state.requests.is_empty()
                && state.pending.is_empty()
                && state.total_req_bytes.get() == 0
        })
}

async fn close_h3_connections(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    reason: &'static [u8],
    tx_scratch: &mut Vec<u8>,
) {
    let now = Instant::now();
    let handles: Vec<ConnectionHandle> = conns.keys().copied().collect();
    for hd in handles {
        if let Some(conn) = conns.get_mut(&hd) {
            conn.close(
                now,
                quinn_proto::VarInt::from_u32(0x0100),
                bytes::Bytes::from_static(reason),
            );
        }
        flush_conn(udp, udp_state, conns, hd, now, tx_scratch).await;
    }
}

/// The production io_uring H3 per-core loop: `select!` over (1) a finished-request completion
/// (write its response back + flush), (2) an inbound datagram (feed quinn-proto), (3) the
/// nearest QUIC, request-stream, or drain timer. Per-request dispatch runs in spawned tasks (see
/// [`drive_one_conn`]), so PHP/pipeline latency never stalls the datagram loop.
async fn endpoint_loop_concurrent(
    udp: UdpSocket,
    mut endpoint: Endpoint,
    local: SocketAddr,
    bridge: Bridge,
    policy_handle: QuicReloadHandle,
    runtime: H3RuntimeConfig,
    shutdown: CancellationToken,
    ready: super::WorkerReadyTx,
    activation: super::worker_group::ActivationGate,
) -> io::Result<()> {
    let runtime = runtime.with_shutdown(shutdown.clone());
    let mut conns: HashMap<ConnectionHandle, quinn_proto::Connection> = HashMap::new();
    let mut h3: HashMap<ConnectionHandle, H3State> = HashMap::new();
    let mut scratch: Vec<u8> = Vec::with_capacity(MAX_DATAGRAM);
    let mut tx_scratch: Vec<u8> = Vec::with_capacity(MAX_DATAGRAM);
    let (comp_tx, comp_rx) = flume::bounded::<Completion>(MAX_INFLIGHT_PER_CORE * 2);
    let inflight = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let mut epoch_ctr: u64 = 0;
    let handshakes = Arc::new(AtomicU64::new(0));
    // quinn-udp socket state for GSO send (probes UDP_SEGMENT support once per core;
    // flush_conn re-reads the cap it may lower later).
    let udp_state = {
        let bfd = unsafe { BorrowedFd::borrow_raw(udp.as_raw_fd()) };
        UdpSocketState::new(UdpSockRef::from(&bfd))?
    };
    // GRO recv: drain many datagrams per readiness wake into reused buffers (one recvmmsg
    // returns up to GRO_BATCH messages, each GRO-coalescing up to ~64 segments). Batching ACK
    // processing into ONE flush per wake stops the send-bunching (one flush per ACK) that
    // overwhelmed the path and caused ~48% loss on large transfers.
    let mut recv_bufs = recv_slots();
    let mut recv_metas = [quinn_udp::RecvMeta::default(); GRO_BATCH];
    let mut deadlines = ConnectionDeadlineIndex::default();
    let mut draining = false;
    let mut drain_deadline: Option<Instant> = None;
    // Socket capability probing and driver allocations belong to preparation,
    // not the published serving lifetime. No packet is consumed before release.
    if ready.send(Ok(())).is_err() || !activation.wait().await {
        return Ok(());
    }
    let mut policy = policy_handle.load_full();
    loop {
        crate::memtrim::collect_if_requested_on_thread();
        let latest = policy_handle.load_full();
        if !Arc::ptr_eq(&policy, &latest) {
            endpoint.set_server_config(Some(latest.config.clone()));
            policy = latest;
        }
        if draining && h3_drain_complete(&h3, inflight.get(), comp_rx.is_empty()) {
            close_h3_connections(&udp, &udp_state, &mut conns, b"shutdown", &mut tx_scratch).await;
            return Ok(());
        }
        let now = Instant::now();
        if drain_deadline.is_some_and(|deadline| now >= deadline) {
            close_h3_connections(
                &udp,
                &udp_state,
                &mut conns,
                b"drain deadline",
                &mut tx_scratch,
            )
            .await;
            return Ok(());
        }
        // The select is intentionally biased toward completions and socket input.
        // Service overdue connections before re-entering it so traffic on unrelated
        // connections cannot starve a QUIC timer or absolute deadline indefinitely.
        let mut due = std::collections::HashSet::new();
        deadlines.extend_due(&mut due, now);
        if !due.is_empty() {
            pump(
                &udp,
                &udp_state,
                &mut recv_bufs,
                &mut recv_metas,
                &mut scratch,
                &mut tx_scratch,
                &mut endpoint,
                &mut conns,
                &mut h3,
                &mut deadlines,
                &mut epoch_ctr,
                &handshakes,
                &inflight,
                &bridge,
                local,
                &comp_tx,
                &runtime,
                &policy,
                !draining,
                due,
            )
            .await;
            continue;
        }
        let next_timeout = deadlines.next().into_iter().chain(drain_deadline).min();
        let timer_base = Instant::now();
        let shutdown_wait = async {
            if draining {
                std::future::pending::<()>().await;
            } else {
                shutdown.cancelled().await;
            }
        };
        monoio::select! {
            biased;
            // (0) Stop new admissions, send GOAWAY, and keep driving established streams
            // until every response drains or the same bounded grace used by TCP expires.
            _ = shutdown_wait => {
                draining = true;
                let now = Instant::now();
                drain_deadline = Some(now + super::URING_DRAIN_GRACE);
                let handles = conns.keys().copied().collect();
                pump(&udp, &udp_state, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut tx_scratch, &mut endpoint, &mut conns, &mut h3, &mut deadlines, &mut epoch_ctr, &handshakes, &inflight, &bridge, local, &comp_tx, &runtime, &policy, false, handles).await;
            }
            // (1) Finished request(s): write each response into its stream, then pump the
            // sends (the response streams out cooperatively, interleaved with ACK processing).
            comp = comp_rx.recv_async() => {
                let mut to_drive: std::collections::HashSet<ConnectionHandle> = std::collections::HashSet::new();
                let mut completed = 0;
                if let Ok(c) = comp {
                    let hd = c.conn;
                    write_completion(&mut conns, &mut h3, c);
                    to_drive.insert(hd);
                    completed = 1;
                }
                while completed < MAX_COMPLETION_DRAIN_BATCH {
                    let Ok(c) = comp_rx.try_recv() else {
                        break;
                    };
                    let hd = c.conn;
                    write_completion(&mut conns, &mut h3, c);
                    to_drive.insert(hd);
                    completed += 1;
                }
                pump(&udp, &udp_state, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut tx_scratch, &mut endpoint, &mut conns, &mut h3, &mut deadlines, &mut epoch_ctr, &handshakes, &inflight, &bridge, local, &comp_tx, &runtime, &policy, !draining, to_drive).await;
            }
            // (2) Socket readable: GRO-drain queued datagrams, then pump (drive affected conns
            // + interleave further ACK processing). `readable()` is a poll op (cancel-safe).
            _ = udp.readable(false) => {
                let now = Instant::now();
                let affected = recv_drain(&udp, &udp_state, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut endpoint, &mut conns, &mut h3, &mut deadlines, &mut epoch_ctr, &handshakes, &runtime, &policy, !draining, now).await;
                pump(&udp, &udp_state, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut tx_scratch, &mut endpoint, &mut conns, &mut h3, &mut deadlines, &mut epoch_ctr, &handshakes, &inflight, &bridge, local, &comp_tx, &runtime, &policy, !draining, affected).await;
            }
            // (3) A QUIC timer (handshake retransmit / idle / pacing) or absolute
            // HTTP/3 deadline fired — pump every connection the index holds as due.
            _ = sleep_until_opt(next_timeout, timer_base) => {
                let now = Instant::now();
                let mut due = std::collections::HashSet::new();
                deadlines.extend_due(&mut due, now);
                pump(&udp, &udp_state, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut tx_scratch, &mut endpoint, &mut conns, &mut h3, &mut deadlines, &mut epoch_ctr, &handshakes, &inflight, &bridge, local, &comp_tx, &runtime, &policy, !draining, due).await;
            }
        }
    }
}

// ───────────────────────── real-pipeline H3 ─────────────────────────
// Decode the client's QPACK request headers + H3 frames, build an hj_core::Request,
// dispatch it through the cross-runtime bridge (the SAME pipeline the H1/H2 uring paths
// use), and encode the real response. This is the production H3 implementation; the
// tokio/quinn transport adapter no longer exists.

#[cfg(test)]
use super::qpack::qpack_decode;
use super::qpack::{QPACK_STATIC, qpack_decode_limited};
use crate::uring::bridge::{Bridge, BridgeCtx};
use hj_core::Proto;
use tokio_util::sync::CancellationToken;

/// Read a QUIC/HTTP-3 variable-length integer (RFC 9000 §16) at `*pos`.
#[cfg(test)]
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(*pos..*pos + len)?;
    *pos += len;
    let mut v = (first & 0x3f) as u64;
    for &b in &bytes[1..] {
        v = (v << 8) | b as u64;
    }
    Some(v)
}

struct ParsedH3Request {
    field: Vec<u8>,
    body: Bytes,
    trailers: Option<Vec<u8>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H3RequestParseError {
    Malformed,
    UnexpectedFrame,
}

/// Parse a whole HTTP/3 message stream with the receive path's incremental parser.
#[cfg(test)]
fn parse_h3_request(data: Vec<u8>) -> Result<ParsedH3Request, H3RequestParseError> {
    let mut frames = H3FrameCounter::default();
    let mut body = Vec::new();
    frames
        .consume(
            &data,
            &mut body,
            H3RequestLimits::new(usize::MAX, usize::MAX),
        )
        .map_err(|error| match error {
            RequestFrameError::Unexpected => H3RequestParseError::UnexpectedFrame,
            _ => H3RequestParseError::Malformed,
        })?;
    frames
        .finish(body, None)
        .map(|(parsed, _)| parsed)
        .ok_or(H3RequestParseError::Malformed)
}

fn prepare_h3_response_headers(
    headers: &mut http::HeaderMap,
    is_head: bool,
    status: http::StatusCode,
    streaming_unknown_len: bool,
) -> bool {
    hj_core::strip_hop_by_hop_response(headers);
    hj_core::sanitize_h2_h3_body_headers(headers, is_head, status, streaming_unknown_len);
    hj_core::response_body_forbidden(is_head, status)
}

/// Encode an HTTP/3 response HEADERS frame (QPACK field section using static-table
/// references where they help, literals otherwise — see [`qpack_field`]). Split out so the
/// streaming path can send the head before the body and frame each DATA chunk separately.
/// RFC 9114 §7.2.4.1 field-section size: sum of name+value lengths plus 32
/// bytes of overhead per field (the HTTP/2 §6.5.2 accounting H3 reuses).
fn h3_field_section_size(status: http::StatusCode, headers: &http::HeaderMap) -> u64 {
    let mut size: u64 = 32 + 7 + status.as_str().len() as u64;
    for (name, value) in headers {
        size = size.saturating_add(32 + name.as_str().len() as u64 + value.len() as u64);
    }
    size
}

fn encode_h3_headers_frame(status: http::StatusCode, headers: &http::HeaderMap) -> Vec<u8> {
    // (#288) The field section goes into a REUSED per-thread scratch (cleared per
    // call, capacity retained) so a response allocates only its final wire buffer;
    // QUIC/H3 varints must be minimally encoded, so the HEADERS length cannot be
    // backfilled into a fixed-size slot.
    FIELD_SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        let field: &mut Vec<u8> = scratch.get_or_insert_with(Vec::new);
        field.clear();
        let cap = 2 + 16 + headers.len() * 24;
        if field.capacity() < cap {
            field.reserve(cap);
        }
        field.extend_from_slice(&[0x00, 0x00]); // RIC=0, Base=0
        qpack_field(field, ":status", status.as_str().as_bytes());
        for (name, value) in headers {
            qpack_field(field, name.as_str(), value.as_bytes());
        }
        let mut out = Vec::with_capacity(field.len() + 12);
        write_varint(&mut out, 0x01); // HEADERS
        write_varint(&mut out, field.len() as u64);
        out.extend_from_slice(field);
        out
    })
}

thread_local! {
    static FIELD_SCRATCH: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}
/// Frame one DATA chunk (`0x00` type + length + payload). Concatenated DATA frames
/// reassemble byte-identically to one big DATA frame, so the streaming path is wire-equal
/// to the buffered path for the same body.
fn encode_h3_data_frame(out: &mut Vec<u8>, chunk: &[u8]) {
    write_varint(out, 0x00); // DATA
    write_varint(out, chunk.len() as u64);
    out.extend_from_slice(chunk);
}

/// Encode a complete HTTP/3 response: HEADERS frame + (optional) single DATA frame.
fn encode_h3_response(status: http::StatusCode, headers: &http::HeaderMap, body: &[u8]) -> Vec<u8> {
    let mut out = encode_h3_headers_frame(status, headers);
    if !body.is_empty() {
        encode_h3_data_frame(&mut out, body);
    }
    out
}

/// Send `response` as the stream's whole response through the pending-send machinery, so a
/// blocked stream drains on Writable instead of being cut short.
fn queue_final_response(
    c: &mut quinn_proto::Connection,
    st: &mut H3State,
    id: StreamId,
    response: Vec<u8>,
) {
    st.pending.insert(
        id,
        PendingSend {
            completion: None,
            parts: std::iter::once(PendingPart::contiguous(response, None)).collect(),
            fin: true,
            stall: None,
        },
    );
    pump_stream(c, st, id);
}

/// A minimal HTTP/3 error response (status only).
fn h3_error(status: http::StatusCode) -> Vec<u8> {
    encode_h3_response(status, &http::HeaderMap::new(), b"")
}

/// The bodiless 413 H1 and H2 send for an over-limit request body.
fn h3_payload_too_large() -> Vec<u8> {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("0"),
    );
    encode_h3_response(http::StatusCode::PAYLOAD_TOO_LARGE, &headers, b"")
}

/// The result of dispatching an H3 request: either a whole buffered response (errors,
/// small/HIT bodies — sent as one `Completion::Full`) or a streamed response (HEADERS frame
/// + a chunk source the spawn task forwards as `Completion::Chunk`s, so a large body flows
/// out as the backend produces it instead of buffering whole).
struct H3Outcome {
    body: H3Body,
    completion: Option<hj_core::ResponseCompletion>,
}
impl H3Outcome {
    fn full(data: Vec<u8>) -> Self {
        Self {
            body: H3Body::Full { data, lease: None },
            completion: None,
        }
    }
}
enum H3Body {
    Full {
        data: Vec<u8>,
        lease: Option<H3EgressLease>,
    },
    Stream {
        head: Vec<u8>,
        head_lease: Option<H3EgressLease>,
        rx: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, ()>>,
    },
}

struct H3RequestHeaders {
    method: Vec<u8>,
    path: Vec<u8>,
    authority: Option<Vec<u8>>,
    regular: Vec<(Vec<u8>, Vec<u8>)>,
}

fn h3_handshake_server_name(conn: &quinn_proto::Connection) -> Option<Arc<str>> {
    conn.crypto_session()
        .handshake_data()?
        .downcast::<quinn_proto::crypto::rustls::HandshakeData>()
        .ok()?
        .server_name
        .map(|name| Arc::from(name.as_str()))
}

fn split_h3_request_headers(headers: Vec<(Vec<u8>, Vec<u8>)>) -> Option<H3RequestHeaders> {
    let (mut method, mut scheme, mut path, mut authority) = (None, None, None, None);
    let mut regular = Vec::new();
    let mut seen_regular = false;
    for (name, value) in headers {
        if name.first() == Some(&b':') {
            if seen_regular {
                return None;
            }
            let duplicate = match name.as_slice() {
                b":method" => method.replace(value).is_some(),
                b":scheme" => scheme.replace(value).is_some(),
                b":path" => path.replace(value).is_some(),
                b":authority" => authority.replace(value).is_some(),
                _ => return None,
            };
            if duplicate {
                return None;
            }
        } else {
            seen_regular = true;
            regular.push((name, value));
        }
    }
    if scheme.as_deref() != Some(b"https") || method.as_deref() == Some(b"CONNECT") {
        return None;
    }
    Some(H3RequestHeaders {
        method: method?,
        path: path?,
        authority,
        regular,
    })
}

fn valid_h3_trailers(field: &[u8], max_field_section_size: usize) -> bool {
    qpack_decode_limited(field, max_field_section_size).is_some_and(|(headers, _)| {
        headers.into_iter().all(|(name, value)| {
            if name.first() == Some(&b':') || name.iter().any(|b| b.is_ascii_uppercase()) {
                return false;
            }
            let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(&name),
                http::HeaderValue::from_bytes(&value),
            ) else {
                return false;
            };
            !hj_core::is_connection_specific_request_header(name.as_str())
                && !(name == http::header::TE
                    && !value.as_bytes().eq_ignore_ascii_case(b"trailers"))
                && !matches!(value.as_bytes().first(), Some(b' ' | b'\t'))
                && !matches!(value.as_bytes().last(), Some(b' ' | b'\t'))
        })
    })
}

/// Validate the decoded H3 request head and construct the HTTP request builder.
/// Keeping raw pseudo-header checks here avoids `http::Uri` silently discarding
/// fragments, and gives tests a seam that consumes real QPACK-decoded fields.
fn build_h3_request_head(head: H3RequestHeaders) -> Option<http::request::Builder> {
    let H3RequestHeaders {
        method,
        path,
        authority,
        regular,
    } = head;
    let method = http::Method::from_bytes(&method).ok()?;
    let path_str = std::str::from_utf8(&path).ok()?;
    if path.contains(&b'#') || !(path.starts_with(b"/") || path.as_slice() == b"*") {
        return None;
    }
    // Network-path reference (//authority/...): http::Uri would parse the
    // authority out of :path, diverging from the routed :authority (#587).
    if path.starts_with(b"//") {
        return None;
    }
    if path.as_slice() == b"*" && method != http::Method::OPTIONS {
        return None;
    }

    let authority_value = match authority.as_deref() {
        Some(raw) => {
            let text = std::str::from_utf8(raw).ok()?;
            // H3 is HTTPS-only here. RFC 9113/9114 forbid empty HTTP(S)
            // authorities and userinfo even though generic URI syntax permits both.
            if !hj_core::valid_http_authority(text) {
                return None;
            }
            Some(http::HeaderValue::from_bytes(raw).ok()?)
        }
        None => None,
    };
    let mut builder = http::Request::builder()
        .version(http::Version::HTTP_3)
        .method(method)
        .uri(path_str);
    let mut regular_host: Option<http::HeaderValue> = None;
    for (raw_name, raw_value) in regular {
        if raw_name.iter().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        let name = http::HeaderName::from_bytes(&raw_name).ok()?;
        let value = http::HeaderValue::from_bytes(&raw_value).ok()?;
        if hj_core::is_connection_specific_request_header(name.as_str()) {
            return None;
        }
        if name == http::header::TE && !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
            return None;
        }
        if matches!(value.as_bytes().first(), Some(b' ' | b'\t'))
            || matches!(value.as_bytes().last(), Some(b' ' | b'\t'))
        {
            return None;
        }
        if name == http::header::HOST {
            let text = value.to_str().ok()?;
            if !hj_core::valid_http_authority(text) {
                return None;
            }
            if regular_host.replace(value).is_some() {
                return None;
            }
        } else {
            builder = builder.header(name, value);
        }
    }

    match (authority_value, regular_host) {
        (Some(authority), Some(host)) if authority.as_bytes() != host.as_bytes() => return None,
        (Some(authority), _) => builder = builder.header(http::header::HOST, authority),
        (None, Some(host)) => builder = builder.header(http::header::HOST, host),
        // RFC 9114 §4.3.1: an https request MUST carry :authority or Host
        // (H1 answers the same shape with 400).
        (None, None) => return None,
    }
    Some(builder)
}

/// Decode one io_uring-H3 request, dispatch it through the bridge (real pipeline), and
/// encode the response. App-layer mTLS mirrors the TCP TLS path.
async fn handle_h3_request(
    req_frames: H3FrameCounter,
    req_body: Vec<u8>,
    body_lease: Option<hj_core::budget::BodyBufferLease>,
    has_client_cert: bool,
    tls: Option<hj_core::TlsParams>,
    sni: Option<Arc<str>>,
    peer: SocketAddr,
    local: SocketAddr,
    bridge: &Bridge,
    client_auth: crate::uring::ClientAuth,
    request_limits: H3RequestLimits,
    request_generation: Option<crate::serving_generation::RequestGeneration>,
    egress_budget: Option<H3EgressBudget>,
    max_field_section_size: std::rc::Rc<std::cell::Cell<Option<u64>>>,
) -> H3Outcome {
    if client_auth.required() && !has_client_cert && !hj_core::is_trusted_internal_peer(peer.ip()) {
        return H3Outcome::full(h3_error(http::StatusCode::FORBIDDEN));
    }
    let Some((parsed, decoded_head)) = req_frames.finish(req_body, body_lease) else {
        return H3Outcome::full(h3_error(http::StatusCode::BAD_REQUEST));
    };
    if parsed.body.len() > request_limits.max_body_bytes {
        return H3Outcome::full(h3_error(http::StatusCode::BAD_REQUEST));
    }
    // The receive path decodes the head of a request with a body; it is the same
    // field section under the same limit.
    let decoded = decoded_head
        .or_else(|| qpack_decode_limited(&parsed.field, request_limits.max_header_bytes));
    let Some((headers, initial_field_size)) = decoded else {
        return H3Outcome::full(h3_error(http::StatusCode::BAD_REQUEST));
    };
    if parsed.trailers.as_deref().is_some_and(|field| {
        !valid_h3_trailers(
            field,
            request_limits
                .max_header_bytes
                .saturating_sub(initial_field_size),
        )
    }) {
        return H3Outcome::full(h3_error(http::StatusCode::BAD_REQUEST));
    }
    let head = match split_h3_request_headers(headers) {
        Some(h) => h,
        None => return H3Outcome::full(h3_error(http::StatusCode::BAD_REQUEST)),
    };
    // (N2) §4.1.2: a Content-Length that disagrees with the DATA length is malformed.
    // Parsed with the SAME strict resolver as H1 (#232 residual): ASCII-OWS trim,
    // digit-only — the old `trim().parse()` accepted "+5" (unsigned FromStr sign) and
    // obs-text-padded values that every conformant stack rejects.
    let declared_cl = {
        let values = head
            .regular
            .iter()
            .filter(|(n, _)| n.as_slice() == b"content-length")
            .map(|(_, v)| v.as_slice());
        match super::codec::resolve_content_length(values) {
            Ok(cl) => cl,
            Err(()) => return H3Outcome::full(h3_error(http::StatusCode::BAD_REQUEST)),
        }
    };
    if declared_cl.is_some_and(|cl| cl != parsed.body.len()) {
        return H3Outcome::full(h3_error(http::StatusCode::BAD_REQUEST));
    }
    let builder = match build_h3_request_head(head) {
        Some(head) => head,
        None => return H3Outcome::full(h3_error(http::StatusCode::BAD_REQUEST)),
    };
    let body_b = parsed.body;
    let inbody: hj_core::IncomingBody = if body_b.is_empty() {
        hj_core::empty_incoming()
    } else {
        use http_body_util::BodyExt;
        http_body_util::Full::new(body_b)
            .map_err(|n| match n {})
            .boxed()
    };
    let mut req = match builder.body(inbody) {
        Ok(r) => r,
        Err(_) => return H3Outcome::full(h3_error(http::StatusCode::BAD_REQUEST)),
    };
    hj_core::coalesce_cookie_crumbs(req.headers_mut());
    let ctx = BridgeCtx {
        peer,
        local,
        proto: Proto::Http3,
        is_tls: true,
        direct_file_egress: false,
        peer_unix: false,
        client_auth_requested: client_auth.requested(),
        sni,
        tls,
        request_generation,
        response_budget: egress_budget
            .as_ref()
            .map_or_else(crate::uring::bridge::connection_response_budget, |budget| {
                budget.bridge.clone()
            }),
    };
    // A HEAD response must carry no DATA (RFC 9114): even if the pipeline streams a body,
    // emit headers only and don't open a streamed body.
    let is_head = req.method() == http::Method::HEAD;
    match bridge
        .dispatch(req, ctx)
        .await
        .map(crate::uring::bridge::no_upgrade_final)
    {
        Some(mut r) => {
            let mut completion = r.completion;
            let status = r.status;
            let mut headers = r.headers;
            let streaming_unknown_len = match &r.body {
                crate::uring::bridge::BridgeBody::Stream { len: Some(n), .. } => {
                    // The bridge stripped the file's framing; restate its known length.
                    headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(*n));
                    false
                }
                crate::uring::bridge::BridgeBody::Stream { len: None, .. } => true,
                _ => false,
            };
            let body_forbidden =
                prepare_h3_response_headers(&mut headers, is_head, status, streaming_unknown_len);
            // #626 (RFC 9114 §7.2.4.1): never emit a field section larger than
            // the peer's SETTINGS_MAX_FIELD_SECTION_SIZE — a conforming client
            // would abort the stream with H3_MESSAGE_ERROR. Fall back to a
            // minimal 500 head (status only, the smallest legal section).
            if max_field_section_size
                .get()
                .is_some_and(|limit| h3_field_section_size(status, &headers) > limit)
            {
                if let crate::uring::bridge::BridgeBody::Stream { rx, .. } = &mut r.body {
                    rx.close();
                }
                if let Some(completion) = completion.take() {
                    completion.finish(hj_core::ResponseEnd::Cancelled);
                }
                return H3Outcome::full(h3_error(http::StatusCode::INTERNAL_SERVER_ERROR));
            }
            match r.body {
                // Small / HIT / sub-threshold dynamic bodies: buffered + sent whole — byte-identical
                // to the previous path.
                crate::uring::bridge::BridgeBody::Full(b) => {
                    let body = if body_forbidden { &[][..] } else { &b[..] };
                    let mut data = encode_h3_headers_frame(status, &headers);
                    let retained = data.len().saturating_add(if body.is_empty() {
                        0
                    } else {
                        body.len().saturating_add(16)
                    });
                    let lease = match reserve_h3_egress(egress_budget.as_ref(), retained) {
                        Ok(lease) => lease,
                        Err(()) => {
                            if let Some(completion) = completion.take() {
                                completion.finish(hj_core::ResponseEnd::Cancelled);
                            }
                            return H3Outcome::full(h3_error(
                                http::StatusCode::SERVICE_UNAVAILABLE,
                            ));
                        }
                    };
                    if !body.is_empty() {
                        encode_h3_data_frame(&mut data, body);
                    }
                    H3Outcome {
                        body: H3Body::Full { data, lease },
                        completion,
                    }
                }
                crate::uring::bridge::BridgeBody::File(_) => {
                    unreachable!("direct file bridge bodies are plaintext H1-only")
                }
                // Large / SSE / proxy bodies: stream the HEADERS now and forward DATA chunks as the
                // backend produces them, instead of buffering the whole body first.
                crate::uring::bridge::BridgeBody::Stream { mut rx, .. } => {
                    let head = encode_h3_headers_frame(status, &headers);
                    let head_lease = match reserve_h3_egress(egress_budget.as_ref(), head.len()) {
                        Ok(lease) => lease,
                        Err(()) => {
                            rx.close();
                            if let Some(completion) = completion.take() {
                                completion.finish(hj_core::ResponseEnd::Cancelled);
                            }
                            return H3Outcome::full(h3_error(
                                http::StatusCode::SERVICE_UNAVAILABLE,
                            ));
                        }
                    };
                    if body_forbidden {
                        rx.close();
                        H3Outcome {
                            body: H3Body::Full {
                                data: head,
                                lease: head_lease,
                            },
                            completion,
                        }
                    } else {
                        H3Outcome {
                            body: H3Body::Stream {
                                head,
                                head_lease,
                                rx,
                            },
                            completion,
                        }
                    }
                }
            }
        }
        None => H3Outcome::full(h3_error(http::StatusCode::BAD_GATEWAY)),
    }
}

/// Real-pipeline io_uring H3 listener: per-core monoio runtimes driving quinn-proto, each
/// dispatching requests through `bridge`. This is the ONLY H3 transport (the tokio/quinn
/// adapter was removed 2026-06-21); production serves H3 here unconditionally.
/// The returned group is prepared, not serving; its owner must call `activate`.
pub(crate) fn serve_h3_pipeline(
    addr: SocketAddr,
    workers: usize,
    rustls_cfg: Arc<rustls::ServerConfig>,
    bridge: Bridge,
    client_auth: crate::uring::ClientAuth,
    runtime: H3RuntimeConfig,
    inherited: Option<Vec<std::net::UdpSocket>>,
    shutdown: CancellationToken,
) -> io::Result<(super::WorkerGroup, QuicReloadHandle)> {
    let serving_view = runtime.serving_view.clone();
    let policy = match serving_view.clone() {
        Some(view) => PreparedQuicPolicy::prepare(view, rustls_cfg, client_auth)?,
        None => PreparedQuicPolicy::prepare_unscoped(rustls_cfg, client_auth)?,
    };
    let policy_handle = QuicReloadHandle::new(policy);
    let sockets = h3_udp_sockets(inherited, addr, workers)?;
    let worker_count = sockets.len();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let mut group = match serving_view {
        Some(view) => super::WorkerGroup::for_epoch(&shutdown, view.trust_epoch()),
        None => super::WorkerGroup::new(&shutdown),
    };
    for (core, std_sock) in sockets.into_iter().enumerate() {
        let bridge = bridge.clone();
        let runtime = runtime.clone();
        let policy_handle = policy_handle.clone();
        let ready = ready_tx.clone();
        let activation = group.activation_gate();
        group.spawn(
            std::thread::Builder::new()
                .name(format!("hj-uring-h3p-{core}"))
                .stack_size(crate::RUNTIME_THREAD_STACK_BYTES),
            move |shutdown| {
                super::maybe_pin_core_thread(core, worker_count);
                per_core_h3_pipeline(
                    core,
                    std_sock,
                    addr,
                    bridge,
                    policy_handle,
                    runtime,
                    shutdown,
                    ready,
                    activation,
                )
            },
        )?;
    }
    drop(ready_tx);
    super::wait_for_worker_readiness("HTTP/3", worker_count, ready_rx)?;
    Ok((group, policy_handle))
}

/// The per-core UDP socket set for the io_uring H3 transport: the inherited
/// socket-activation fds when present (kernel SO_REUSEPORT fan-out, already bound as
/// root by the `.socket` unit) — the process runs as `nobody` and CANNOT self-bind
/// privileged :443, so adopting these is mandatory in prod. One monoio core per
/// inherited fd; self-bind `workers`-many only for non-activated alt-port / manual runs.
/// Mirrors `server::take_or_bind_udp` (the tokio H3 path) and `uring::uring_listeners`.
fn h3_udp_sockets(
    inherited: Option<Vec<std::net::UdpSocket>>,
    addr: SocketAddr,
    workers: usize,
) -> io::Result<Vec<std::net::UdpSocket>> {
    let socks: Vec<std::net::UdpSocket> = match inherited {
        Some(v) if !v.is_empty() => {
            for s in &v {
                s.set_nonblocking(true)?;
            }
            v
        }
        _ => (0..workers.max(1))
            .map(|_| reuseport_udp(addr))
            .collect::<io::Result<_>>()?,
    };
    // Bump SO_SNDBUF/SO_RCVBUF: the default (~208 KiB) caps a single send burst, so a
    // response > ~256 KiB fills the kernel send buffer mid-burst → EWOULDBLOCK → a
    // writability stall per refill (the measured >256 KiB throughput cliff). A larger
    // socket buffer lets quinn-proto's congestion-window-sized bursts leave in one go.
    // (Capped by net.core.{w,r}mem_max; best-effort.)
    for s in &socks {
        let r = socket2::SockRef::from(s);
        let _ = r.set_send_buffer_size(8 << 20);
        let _ = r.set_recv_buffer_size(8 << 20);
    }
    Ok(socks)
}

fn per_core_h3_pipeline(
    core: usize,
    std_sock: std::net::UdpSocket,
    local: SocketAddr,
    bridge: Bridge,
    policy_handle: QuicReloadHandle,
    runtime: H3RuntimeConfig,
    shutdown: CancellationToken,
    ready: super::WorkerReadyTx,
    activation: super::worker_group::ActivationGate,
) {
    let initial_policy = policy_handle.load_full();
    let mut rt = match super::build_core_runtime() {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(format!("build monoio runtime: {error}")));
            return;
        }
    };
    rt.block_on(async move {
        let udp = match UdpSocket::from_std(std_sock) {
            Ok(u) => u,
            Err(e) => {
                let _ = ready.send(Err(format!("adopt UDP listener: {e}")));
                tracing::error!(core, error = %e, "uring h3-pipeline: adopt reuseport udp failed");
                return;
            }
        };
        let endpoint = Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(initial_policy.config.clone()),
            true,
            None,
        );
        if let Err(e) = endpoint_loop_concurrent(
            udp,
            endpoint,
            local,
            bridge,
            policy_handle,
            runtime,
            shutdown,
            ready.clone(),
            activation,
        )
        .await
        {
            // Before readiness this rejects the entire candidate; after readiness
            // the receiver is gone and the error is a serving-runtime failure.
            let _ = ready.send(Err(format!("prepare or drive QUIC endpoint: {e}")));
            tracing::error!(core, error = %e, "uring h3-pipeline: endpoint loop ended");
        }
    });
}

#[cfg(test)]
mod h3_codec_tests {
    use super::*;

    #[test]
    fn wildcard_bind_reports_the_datagram_destination_as_local() {
        let bound: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let dst = Some("203.0.113.5".parse().unwrap());
        assert_eq!(
            request_local_addr(bound, dst),
            "203.0.113.5:443".parse().unwrap()
        );
        assert_eq!(request_local_addr(bound, None), bound);
        let dual: SocketAddr = "[::]:443".parse().unwrap();
        let mapped = Some("::ffff:203.0.113.5".parse().unwrap());
        assert_eq!(
            request_local_addr(dual, mapped),
            "203.0.113.5:443".parse().unwrap()
        );
        let specific: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert_eq!(request_local_addr(specific, dst), specific);
    }

    #[derive(Default)]
    struct FlowLimitedLocalUni {
        next_index: u64,
        opened: Vec<StreamId>,
        credit: HashMap<StreamId, usize>,
        written: HashMap<StreamId, Vec<u8>>,
    }

    impl FlowLimitedLocalUni {
        fn grant(&mut self, id: StreamId, bytes: usize) {
            *self.credit.entry(id).or_default() += bytes;
        }
    }

    impl LocalUniIo for FlowLimitedLocalUni {
        fn open_uni(&mut self) -> Option<StreamId> {
            let id = StreamId::new(quinn_proto::Side::Server, Dir::Uni, self.next_index);
            self.next_index += 1;
            self.opened.push(id);
            Some(id)
        }

        fn write_uni(&mut self, id: StreamId, bytes: &[u8]) -> Result<usize, WriteError> {
            let credit = self.credit.entry(id).or_default();
            if *credit == 0 {
                return Err(WriteError::Blocked);
            }
            let written = bytes.len().min(*credit);
            *credit -= written;
            self.written
                .entry(id)
                .or_default()
                .extend_from_slice(&bytes[..written]);
            Ok(written)
        }
    }

    #[test]
    fn local_control_setup_retries_blocked_and_partial_prefixes() {
        let mut io = FlowLimitedLocalUni::default();
        let mut state = H3State::default();

        pump_local_h3_setup(&mut io, &mut state).unwrap();
        let control = state
            .control_stream
            .expect("control stream must open first");
        assert!(!state.control_setup);
        assert_eq!(state.control_stream_off, 0);
        assert_eq!(io.opened, vec![control]);

        io.grant(control, 1);
        pump_local_h3_setup(&mut io, &mut state).unwrap();
        assert_eq!(state.control_stream_off, 1);
        assert!(!state.control_setup);
        assert_eq!(
            io.opened,
            vec![control],
            "a partial write must not open a replacement stream"
        );

        io.grant(control, LOCAL_CONTROL_PREFIX.len() - 1);
        pump_local_h3_setup(&mut io, &mut state).unwrap();
        let encoder = state
            .qpack_encoder_stream
            .expect("encoder stream opens after SETTINGS is complete");
        assert_eq!(state.control_stream_off, LOCAL_CONTROL_PREFIX.len());
        assert_eq!(state.qpack_encoder_stream_off, 0);
        assert!(!state.control_setup);

        io.grant(encoder, LOCAL_QPACK_ENCODER_PREFIX.len());
        pump_local_h3_setup(&mut io, &mut state).unwrap();
        let decoder = state
            .qpack_decoder_stream
            .expect("decoder stream opens after the encoder prefix is complete");
        assert_eq!(
            state.qpack_encoder_stream_off,
            LOCAL_QPACK_ENCODER_PREFIX.len()
        );
        assert!(!state.control_setup);

        io.grant(decoder, LOCAL_QPACK_DECODER_PREFIX.len());
        pump_local_h3_setup(&mut io, &mut state).unwrap();
        assert!(state.control_setup);
        assert_eq!(io.written[&control], LOCAL_CONTROL_PREFIX);
        assert_eq!(io.written[&encoder], LOCAL_QPACK_ENCODER_PREFIX);
        assert_eq!(io.written[&decoder], LOCAL_QPACK_DECODER_PREFIX);

        let opened = io.opened.clone();
        pump_local_h3_setup(&mut io, &mut state).unwrap();
        assert_eq!(io.opened, opened, "completed setup must remain latched");
    }

    // Decode a request block exercising: indexed static field lines, literal-with-name-ref
    // (static), and literal-with-literal-name. Byte layouts per RFC 9204 §4.5.
    #[tokio::test]
    async fn bridge_sni_is_the_handshake_server_name_not_authority() {
        let seen = Arc::new(std::sync::Mutex::new(None::<Option<Arc<str>>>));
        let observed = seen.clone();
        let bridge = crate::uring::bridge::spawn_on_current(1, move |_req, ctx| {
            *observed.lock().unwrap() = Some(ctx.sni.clone());
            async { http::Response::new(hj_core::Body::Empty) }
        });
        let request = |authority: Option<&'static [u8]>| {
            let mut fields: Vec<(&[u8], &[u8])> = vec![
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":path", b"/"),
            ];
            if let Some(authority) = authority {
                fields.push((b":authority", authority));
            }
            let fields = literal_qpack_fields(&fields);
            let mut wire = Vec::new();
            write_varint(&mut wire, 1);
            write_varint(&mut wire, fields.len() as u64);
            wire.extend(fields);
            wire
        };
        let run = |wire: Vec<u8>| {
            let (frames, body) = received_request(&wire);
            handle_h3_request(
                frames,
                body,
                None,
                false,
                None,
                Some(Arc::from("a.test")),
                "127.0.0.1:32000".parse().unwrap(),
                "127.0.0.1:8443".parse().unwrap(),
                &bridge,
                crate::uring::ClientAuth::None,
                H3RequestLimits::new(4096, 4096),
                None,
                None,
                Default::default(),
            )
        };
        let _ = run(request(Some(b"b.test:443"))).await;
        assert_eq!(
            seen.lock().unwrap().take(),
            Some(Some(Arc::from("a.test"))),
            "BridgeCtx.sni must be the QUIC SNI, like H2"
        );
        let response = run(request(None)).await;
        assert!(
            seen.lock().unwrap().is_none(),
            "host-less request never dispatches"
        );
        let H3Body::Full { data, .. } = response.body else {
            panic!("full error response")
        };
        assert_eq!(data, h3_error(http::StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn peer_settings_received_during_dispatch_limit_the_response() {
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let bridge = crate::uring::bridge::spawn_on_current(1, {
            let started = started.clone();
            let release = release.clone();
            move |_req, _ctx| {
                let started = started.clone();
                let release = release.clone();
                async move {
                    started.notify_one();
                    release.notified().await;
                    http::Response::builder()
                        .header("x-large", "x".repeat(128))
                        .body(hj_core::Body::Empty)
                        .unwrap()
                }
            }
        });
        let fields = literal_qpack_fields(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"canon.test"),
            (b":path", b"/"),
        ]);
        let mut wire = Vec::new();
        write_varint(&mut wire, 1);
        write_varint(&mut wire, fields.len() as u64);
        wire.extend(fields);
        let mut state = H3State::default();
        let limit = state.peer_max_field_section_size.clone();
        let (frames, body) = received_request(&wire);
        let request = handle_h3_request(
            frames,
            body,
            None,
            false,
            None,
            None,
            "127.0.0.1:32000".parse().unwrap(),
            "127.0.0.1:8443".parse().unwrap(),
            &bridge,
            crate::uring::ClientAuth::None,
            H3RequestLimits::new(4096, 4096),
            None,
            None,
            limit,
        );
        let update = async {
            started.notified().await;
            let mut payload = Vec::new();
            write_varint(&mut payload, 6);
            write_varint(&mut payload, 80);
            let mut control = vec![0, 4]; // uni control stream, SETTINGS
            write_varint(&mut control, payload.len() as u64);
            control.extend(payload);
            let mut stream = PeerUniStream::default();
            consume_peer_uni(
                &mut state,
                StreamId::new(quinn_proto::Side::Client, Dir::Uni, 0),
                &mut stream,
                &control,
            )
            .unwrap();
            assert_eq!(state.peer_max_field_section_size.get(), Some(80));
            release.notify_one();
        };
        let (response, ()) = tokio::join!(request, update);
        let H3Body::Full { data, .. } = response.body else {
            panic!("full error response")
        };
        assert_eq!(data, h3_error(http::StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn qpack_decode_static_and_literals() {
        let mut buf = vec![0x00, 0x00]; // field section prefix: RIC=0, Base=0
        buf.push(0xC0 | 17); // Indexed (T=static) :method GET  (static idx 17)
        buf.push(0xC0 | 1); // Indexed :path /                  (static idx 1)
        buf.push(0xC0 | 23); // Indexed :scheme https           (static idx 23)
        buf.push(0x50); // Literal w/ Name Ref (T=static, idx 0 = :authority)
        buf.push(6); // value: H=0, len 6
        buf.extend_from_slice(b"h.test");
        buf.push(0x20 | 5); // Literal w/ Literal Name: 001 N=0 H=0, name len 5
        buf.extend_from_slice(b"x-foo");
        buf.push(3); // value: H=0, len 3
        buf.extend_from_slice(b"bar");
        let hdrs = qpack_decode(&buf).expect("decode");
        assert_eq!(
            hdrs,
            vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":scheme".to_vec(), b"https".to_vec()),
                (b":authority".to_vec(), b"h.test".to_vec()),
                (b"x-foo".to_vec(), b"bar".to_vec()),
            ]
        );
    }

    // Huffman-coded value + a multi-byte QPACK integer (static name index 31 needs a
    // continuation byte past the 4-bit prefix).
    #[test]
    fn qpack_decode_huffman_and_long_index() {
        let mut val = Vec::new();
        hj_h2::hpack::huffman::encode(&mut val, b"gzip, deflate, br");
        let mut buf = vec![0x00, 0x00];
        buf.push(0x50 | 0x0f); // Literal w/ Name Ref, static, index prefix maxed (15)
        buf.push(31 - 15); // continuation: index 31 (accept-encoding)
        buf.push(0x80 | val.len() as u8); // value: H=1, len
        buf.extend_from_slice(&val);
        let hdrs = qpack_decode(&buf).expect("decode");
        assert_eq!(
            hdrs,
            vec![(b"accept-encoding".to_vec(), b"gzip, deflate, br".to_vec())]
        );
    }

    #[test]
    fn qpack_huffman_expansion_is_bounded_during_decode() {
        let value = vec![b'a'; 1024];
        let mut encoded = Vec::new();
        hj_h2::hpack::huffman::encode(&mut encoded, &value);
        assert!(encoded.len() < value.len());

        let mut field = vec![0x00, 0x00];
        field.push(0x50 | 0x0f);
        field.push(31 - 15); // static name index 31 = accept-encoding
        qpack_int(&mut field, 0x80, 7, encoded.len() as u64);
        field.extend_from_slice(&encoded);
        let decoded_size = b"accept-encoding".len() + value.len() + 32;
        assert!(qpack_decode_limited(&field, decoded_size).is_some());
        assert!(qpack_decode_limited(&field, decoded_size - 1).is_none());
    }

    /// (#287) The response encoder's static-table forms (indexed field line,
    /// literal with name reference) must decode back to exactly the input head
    /// — checked against the in-tree decoder, which already decodes every real
    /// client's use of those forms — and must actually shrink the wire bytes
    /// vs the old literal-only encoding.
    #[test]
    fn qpack_response_static_references_roundtrip_and_shrink() {
        fn read_vi(buf: &[u8], pos: &mut usize) -> u64 {
            let b0 = buf[*pos];
            let len = 1usize << (b0 >> 6);
            let mut v = (b0 & 0x3f) as u64;
            for i in 1..len {
                v = (v << 8) | buf[*pos + i] as u64;
            }
            *pos += len;
            v
        }

        let mut headers = http::HeaderMap::new();
        // Exact (name, value) static hits -> indexed field lines.
        headers.insert("content-encoding", "gzip".parse().unwrap());
        headers.insert("accept-ranges", "bytes".parse().unwrap());
        headers.insert("content-type", "text/html; charset=utf-8".parse().unwrap());
        // Known name, novel value -> literal with name reference.
        headers.insert("etag", "\"abc123\"".parse().unwrap());
        headers.insert("content-length", "152034".parse().unwrap());
        // Unknown name -> literal with literal name (unchanged form).
        headers.insert("x-litespeed-cache", "hit".parse().unwrap());

        // #626: field-section size accounting (name+value+32 per field).
        assert_eq!(
            h3_field_section_size(http::StatusCode::OK, &http::HeaderMap::new()),
            32 + 7 + 3
        );
        assert!(
            h3_field_section_size(http::StatusCode::OK, &headers)
                > h3_field_section_size(http::StatusCode::OK, &http::HeaderMap::new())
        );

        let frame = encode_h3_headers_frame(http::StatusCode::OK, &headers);
        let mut pos = 0usize;
        assert_eq!(read_vi(&frame, &mut pos), 0x01, "HEADERS frame type");
        let flen = read_vi(&frame, &mut pos) as usize;
        let field = &frame[pos..pos + flen];
        assert_eq!(pos + flen, frame.len());

        let decoded = qpack_decode(field).expect("decoder accepts our static references");
        let mut expect = vec![(b":status".to_vec(), b"200".to_vec())];
        for (n, v) in &headers {
            expect.push((n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()));
        }
        assert_eq!(decoded, expect, "byte-exact head after roundtrip");

        let mut literal_only = vec![0x00, 0x00];
        qpack_literal(&mut literal_only, b":status", b"200");
        for (n, v) in &headers {
            qpack_literal(&mut literal_only, n.as_str().as_bytes(), v.as_bytes());
        }
        assert!(
            field.len() < literal_only.len(),
            "static references shrink the field section ({} vs {})",
            field.len(),
            literal_only.len()
        );
    }

    // A dynamic-table reference (we advertise capacity 0) must be rejected, not misdecoded.
    #[test]
    fn qpack_decode_rejects_dynamic() {
        let buf = vec![0x00, 0x00, 0x80 | 5]; // Indexed, T=dynamic (bit6=0)
        assert!(qpack_decode(&buf).is_none());
    }

    /// Regression (#588): a nonzero Required Insert Count (or Delta Base)
    /// names dynamic state we do not have; it must not decode as static lines.
    #[test]
    fn qpack_decode_rejects_nonzero_insert_count() {
        // RIC=1, Delta=0, then a valid static indexed line (:method: GET = 17|0xc0).
        let buf = vec![0x01, 0x00, 0xc0 | 17];
        assert!(qpack_decode(&buf).is_none());
        // RIC=0 but Delta Base magnitude 1.
        let buf = vec![0x00, 0x01, 0xc0 | 17];
        assert!(qpack_decode(&buf).is_none());
        // The zero-prefix form still decodes.
        let buf = vec![0x00, 0x00, 0xc0 | 17];
        assert!(qpack_decode(&buf).is_some());
    }

    #[test]
    fn qpack_decoded_field_section_obeys_configured_limit() {
        let mut buf = vec![0x00, 0x00];
        qpack_literal(&mut buf, b"x-name", b"expanded-value");
        let decoded_size = 6 + 14 + 32;
        assert!(qpack_decode_limited(&buf, decoded_size).is_some());
        assert!(qpack_decode_limited(&buf, decoded_size - 1).is_none());
    }

    #[test]
    fn live_header_limit_counts_decoded_fields_not_compressed_bytes() {
        const LIVE_HEADER_LIMIT: usize = 16_380;

        let mut exact = vec![0x00, 0x00];
        qpack_literal(&mut exact, b"x", &vec![b'a'; LIVE_HEADER_LIMIT - 1 - 32]);
        assert_eq!(
            qpack_decode_limited(&exact, LIVE_HEADER_LIMIT)
                .expect("exact decoded boundary")
                .1,
            LIVE_HEADER_LIMIT
        );

        let mut over = vec![0x00, 0x00];
        qpack_literal(&mut over, b"x", &vec![b'a'; LIVE_HEADER_LIMIT - 1 - 31]);
        assert!(qpack_decode_limited(&over, LIVE_HEADER_LIMIT).is_none());

        let mut compressed = vec![0x00, 0x00];
        let decoded_per_field = b":method".len() + b"GET".len() + 32;
        for _ in 0..=(LIVE_HEADER_LIMIT / decoded_per_field) {
            compressed.push(0xc0 | 17); // static-indexed :method=GET
        }
        assert!(compressed.len() < 512, "wire block remains small");
        assert!(
            qpack_decode_limited(&compressed, LIVE_HEADER_LIMIT).is_none(),
            "a compact field block whose decoded list is oversized must be rejected"
        );
    }

    // Epoch guard: a spawned request's response is written back only when its connection
    // still exists AND its epoch matches. quinn-proto reuses ConnectionHandle indices after a
    // connection drains, so a stale completion (handle reused by a newer connection, or the
    // connection gone) must be dropped — never cross-written to the wrong connection.
    #[test]
    fn completion_epoch_guard_drops_stale() {
        let mut h3: HashMap<ConnectionHandle, H3State> = HashMap::new();
        let hd = ConnectionHandle(7);
        h3.insert(
            hd,
            H3State {
                epoch: 42,
                ..Default::default()
            },
        );
        // Same handle + same epoch → live (write back).
        assert!(completion_is_live(&h3, hd, 42));
        // Same handle, OLD epoch → handle was reused by a newer connection → drop.
        assert!(!completion_is_live(&h3, hd, 41));
        // Unknown handle (connection drained/removed) → drop.
        assert!(!completion_is_live(&h3, ConnectionHandle(99), 42));
        h3.get_mut(&hd).unwrap().rejected = true;
        assert!(
            !completion_is_live(&h3, hd, 42),
            "a protocol-closed connection must drop late backend completions"
        );
    }

    #[test]
    fn stop_sending_on_each_local_critical_stream_closes_and_cancels_requests() {
        let control = StreamId::new(quinn_proto::Side::Server, Dir::Uni, 0);
        let encoder = StreamId::new(quinn_proto::Side::Server, Dir::Uni, 1);
        let decoder = StreamId::new(quinn_proto::Side::Server, Dir::Uni, 2);

        for stopped in [control, encoder, decoder] {
            let request = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
            let token = CancellationToken::new();
            let mut state = H3State {
                control_setup: true,
                control_stream: Some(control),
                qpack_encoder_stream: Some(encoder),
                qpack_decoder_stream: Some(decoder),
                ..Default::default()
            };
            state.request_cancellations.insert(request, token.clone());

            let error = reject_stopped_local_critical_stream(&mut state, stopped)
                .expect("every local control/QPACK stream is critical");

            assert_eq!(error.code, H3_CLOSED_CRITICAL_STREAM);
            assert!(state.rejected);
            assert!(state.request_cancellations.is_empty());
            assert!(token.is_cancelled());
        }
    }

    #[test]
    fn h3_config_accessor_observes_reload_changes() {
        use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

        let cap = Arc::new(AtomicU32::new(2));
        let header = Arc::new(AtomicUsize::new(16_380));
        let body = Arc::new(AtomicUsize::new(100 * 1024 * 1024));
        let timeout_secs = Arc::new(AtomicU64::new(30));
        let cap_read = cap.clone();
        let header_read = header.clone();
        let body_read = body.clone();
        let timeout_read = timeout_secs.clone();
        let runtime = H3RuntimeConfig::new(
            move || {
                (
                    H3RequestConfig::new(
                        H3RequestLimits::new(
                            header_read.load(Ordering::Relaxed),
                            body_read.load(Ordering::Relaxed),
                        ),
                        Some(Duration::from_secs(timeout_read.load(Ordering::Relaxed))),
                    ),
                    cap_read.load(Ordering::Relaxed),
                )
            },
            Arc::new(AtomicU64::new(0)),
            Arc::new(hj_core::budget::BodyBufferBudget::new(
                hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
            )),
        );
        assert_eq!(runtime.max_connections(), 2);
        assert_eq!(runtime.request_limits().max_header_bytes, 16_380);
        assert_eq!(
            runtime.request_config().timeout,
            Some(Duration::from_secs(30))
        );
        cap.store(7, Ordering::Relaxed);
        header.store(8_192, Ordering::Relaxed);
        body.store(32 * 1024 * 1024, Ordering::Relaxed);
        timeout_secs.store(45, Ordering::Relaxed);
        assert_eq!(runtime.max_connections(), 7);
        assert_eq!(runtime.request_limits().max_header_bytes, 8_192);
        assert_eq!(runtime.request_limits().max_body_bytes, 32 * 1024 * 1024);
        assert_eq!(
            runtime.request_config().timeout,
            Some(Duration::from_secs(45))
        );
    }

    #[tokio::test]
    async fn accepted_quic_view_pins_limits_and_dispatch_generation() {
        use crate::serving_generation::ServingView;
        use std::sync::atomic::Ordering;
        let root = std::env::temp_dir().join(format!(
            "hj-quic-generation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let initial = crate::pipeline::e2e::build_state(root.clone());
        let server_root = initial.server.server_root.clone();
        let holder = Arc::new(arc_swap::ArcSwap::from(initial.clone()));
        let runtime = H3RuntimeConfig::new(
            || {
                (
                    H3RequestConfig::new(H3RequestLimits::new(1, 1), Some(Duration::from_secs(1))),
                    8,
                )
            },
            Arc::new(AtomicU64::new(0)),
            initial.body_budget.clone(),
        )
        .with_serving_view(ServingView::new(holder.clone()));
        let permit = || {
            crate::uring::ConnectionPermit::try_acquire(runtime.active_conns.clone(), 8).unwrap()
        };
        let mut early = runtime.accepted_state(permit(), 1);
        let accepted_at = Instant::now();
        let first_stream = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let first_snapshot = early.request_snapshot(runtime.request_config());
        assert!(Arc::ptr_eq(
            &first_snapshot.generation.as_ref().unwrap().0,
            &initial
        ));
        early.track_request_stream(first_stream, accepted_at, first_snapshot);
        let mut application =
            crate::state::ServerState::reload(&initial, initial.server.clone()).unwrap();
        Arc::get_mut(&mut application)
            .unwrap()
            .serve_config
            .max_req_body_size = 512;
        Arc::get_mut(&mut application)
            .unwrap()
            .serve_config
            .header_read_timeout = Some(Duration::from_secs(11));
        holder.store(application.clone());
        let request_snapshot = early.request_snapshot(runtime.request_config());
        assert_eq!(request_snapshot.config.limits.max_body_bytes, 512);
        assert_eq!(
            request_snapshot.config.timeout,
            application.serve_config.header_read_timeout
        );
        assert!(Arc::ptr_eq(
            &request_snapshot.generation.as_ref().unwrap().0,
            &application
        ));
        let second_stream = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 1);
        early.track_request_stream(second_stream, accepted_at, request_snapshot.clone());
        let retained = early.request_snapshots.get(&first_stream).unwrap();
        assert_eq!(
            retained.config.limits.max_body_bytes,
            initial.serve_config.max_req_body_size
        );
        assert_eq!(
            retained.config.timeout,
            initial.serve_config.header_read_timeout
        );
        assert!(Arc::ptr_eq(
            &retained.generation.as_ref().unwrap().0,
            &initial
        ));
        assert!(Arc::ptr_eq(
            &early
                .request_snapshots
                .get(&second_stream)
                .unwrap()
                .generation
                .as_ref()
                .unwrap()
                .0,
            &application
        ));
        let dispatched_snapshot = take_request_for_dispatch(&mut early, first_stream)
            .snapshot
            .expect("accepted stream keeps its snapshot");
        assert_eq!(
            dispatched_snapshot.config.limits.max_body_bytes,
            initial.serve_config.max_req_body_size
        );
        assert!(Arc::ptr_eq(
            &dispatched_snapshot.generation.unwrap().0,
            &initial
        ));
        assert!(!early.request_snapshots.contains_key(&first_stream));
        let later = runtime.accepted_state(permit(), 2);
        let mut replacement =
            crate::state::ServerState::reload(&application, application.server.clone()).unwrap();
        Arc::get_mut(&mut replacement).unwrap().trust_epoch = Arc::new(());
        Arc::get_mut(&mut replacement)
            .unwrap()
            .serve_config
            .max_req_body_size = 4096;
        Arc::get_mut(&mut replacement)
            .unwrap()
            .serve_config
            .header_read_timeout = Some(Duration::from_secs(22));
        holder.store(replacement);
        let old_snapshot = early.request_snapshot(runtime.request_config());
        assert_eq!(
            old_snapshot.config.limits.max_body_bytes,
            initial.serve_config.max_req_body_size
        );
        assert_eq!(
            old_snapshot.config.timeout,
            initial.serve_config.header_read_timeout
        );
        assert!(Arc::ptr_eq(&old_snapshot.generation.unwrap().0, &initial));
        let later_snapshot = later.request_snapshot(runtime.request_config());
        assert_eq!(later_snapshot.config.limits.max_body_bytes, 512);
        assert_eq!(
            later_snapshot.config.timeout,
            application.serve_config.header_read_timeout
        );
        assert!(Arc::ptr_eq(
            &later_snapshot.generation.unwrap().0,
            &application
        ));

        // Decode a real H3 HEADERS frame and prove the generation selected before
        // publication travels through dispatch, rather than reloading live state.
        let seen = Arc::new(AtomicU64::new(0));
        let observed = seen.clone();
        let bridge = crate::uring::bridge::spawn_on_current(2, move |_req, ctx| {
            observed.store(
                ctx.request_generation.as_ref().unwrap().0.generation,
                Ordering::SeqCst,
            );
            async { http::Response::new(hj_core::Body::Empty) }
        });
        let fields = literal_qpack_fields(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"canon.test"),
            (b":path", b"/"),
        ]);
        let mut wire = Vec::new();
        write_varint(&mut wire, 1);
        write_varint(&mut wire, fields.len() as u64);
        wire.extend(fields);
        let (frames, body) = received_request(&wire);
        let _response = handle_h3_request(
            frames,
            body,
            None,
            false,
            None,
            None,
            "127.0.0.1:32000".parse().unwrap(),
            "127.0.0.1:8443".parse().unwrap(),
            &bridge,
            crate::uring::ClientAuth::None,
            request_snapshot.config.limits,
            request_snapshot.generation,
            None,
            Default::default(),
        )
        .await;
        assert_eq!(seen.load(Ordering::SeqCst), application.generation);
        reclaim_buffered_requests(&mut early);
        assert!(early.request_snapshots.is_empty());
        assert!(early.request_deadlines.is_empty());
        drop(early);
        drop(later);
        assert_eq!(runtime.active_conns.load(Ordering::SeqCst), 0);
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(server_root).unwrap();
    }

    #[tokio::test]
    async fn quic_policy_publication_is_coherent_and_preserves_old_views() {
        use crate::serving_generation::ServingView;

        let root = std::env::temp_dir().join(format!(
            "hj-quic-policy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let initial = crate::pipeline::e2e::build_state(root.clone());
        let server_root = initial.server.server_root.clone();
        let holder = Arc::new(arc_swap::ArcSwap::from(initial.clone()));
        let old = PreparedQuicPolicy::prepare(
            ServingView::new(holder.clone()),
            self_signed_config().unwrap(),
            crate::uring::ClientAuth::None,
        )
        .unwrap();
        let old_policy = old.0.clone();
        let handle = QuicReloadHandle::new(old);

        let mut candidate =
            crate::state::ServerState::reload(&initial, initial.server.clone()).unwrap();
        Arc::get_mut(&mut candidate).unwrap().trust_epoch = Arc::new(());
        let replacement = PreparedQuicPolicy::prepare(
            ServingView::candidate(holder.clone(), candidate.clone()),
            self_signed_config().unwrap(),
            crate::uring::ClientAuth::Required,
        )
        .unwrap();
        let replacement_policy = replacement.0.clone();

        assert!(
            old_policy
                .serving_view
                .as_ref()
                .unwrap()
                .is_current_trust_epoch()
        );
        assert!(
            !replacement_policy
                .serving_view
                .as_ref()
                .unwrap()
                .is_current_trust_epoch()
        );
        holder.store(candidate.clone());
        assert!(
            !old_policy
                .serving_view
                .as_ref()
                .unwrap()
                .is_current_trust_epoch()
        );
        assert!(
            replacement_policy
                .serving_view
                .as_ref()
                .unwrap()
                .is_current_trust_epoch()
        );

        handle.publish(replacement);
        let published = handle.load_full();
        assert!(Arc::ptr_eq(&published, &replacement_policy));
        assert!(published.client_auth.required());
        assert!(Arc::ptr_eq(
            &published.serving_view.as_ref().unwrap().load_full(),
            &candidate
        ));
        assert!(Arc::ptr_eq(
            &old_policy.serving_view.as_ref().unwrap().load_full(),
            &initial
        ));

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(server_root).unwrap();
    }

    #[test]
    fn reuseport_server_disables_connection_migration() {
        let config = server_config(self_signed_config().unwrap()).unwrap();
        assert!(
            format!("{config:?}").contains("migration: false"),
            "per-core reuseport endpoints cannot safely accept tuple migration"
        );
    }

    #[test]
    fn split_control_stream_delivery_parses_peer_settings() {
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Uni, 0);
        let mut payload = Vec::new();
        write_varint(&mut payload, 0x01);
        write_varint(&mut payload, 0);
        write_varint(&mut payload, 0x06);
        write_varint(&mut payload, 16_380);
        write_varint(&mut payload, 0x08);
        write_varint(&mut payload, 1);

        let mut wire = Vec::new();
        write_varint(&mut wire, 0x00);
        write_varint(&mut wire, 0x04);
        write_varint(&mut wire, payload.len() as u64);
        wire.extend_from_slice(&payload);

        let mut state = H3State::default();
        let mut stream = PeerUniStream::default();
        for byte in wire.chunks(1) {
            consume_peer_uni(&mut state, id, &mut stream, byte).unwrap();
        }
        assert_eq!(state.peer_control, Some(id));
        assert_eq!(
            state.peer_settings,
            Some(PeerSettings {
                qpack_max_table_capacity: Some(0),
                max_field_section_size: Some(16_380),
                enable_connect_protocol: Some(1),
                ..Default::default()
            })
        );
    }

    #[test]
    fn duplicate_and_closed_critical_streams_are_connection_errors() {
        let control = StreamId::new(quinn_proto::Side::Client, Dir::Uni, 0);
        let duplicate = StreamId::new(quinn_proto::Side::Client, Dir::Uni, 1);
        let encoder = StreamId::new(quinn_proto::Side::Client, Dir::Uni, 2);
        let mut state = H3State::default();
        let mut first = PeerUniStream::default();
        consume_peer_uni(&mut state, control, &mut first, &[0x00, 0x04, 0x00]).unwrap();

        let mut second = PeerUniStream::default();
        let error = consume_peer_uni(&mut state, duplicate, &mut second, &[0x00]).unwrap_err();
        assert_eq!(error.code, H3_STREAM_CREATION_ERROR);
        assert_eq!(
            finish_peer_uni(&first).unwrap_err().code,
            H3_CLOSED_CRITICAL_STREAM
        );

        let mut qpack = PeerUniStream::default();
        consume_peer_uni(&mut state, encoder, &mut qpack, &[0x02]).unwrap();
        assert_eq!(
            finish_peer_uni(&qpack).unwrap_err().code,
            H3_CLOSED_CRITICAL_STREAM
        );

        let unknown = StreamId::new(quinn_proto::Side::Client, Dir::Uni, 3);
        let mut extension = PeerUniStream::default();
        consume_peer_uni(&mut state, unknown, &mut extension, &[0x21, 1, 2, 3]).unwrap();
        assert!(finish_peer_uni(&extension).is_ok());

        // RFC 9114 §6.2: closed or reset before its type arrived is not an error.
        assert!(finish_peer_uni(&PeerUniStream::default()).is_ok());
    }

    #[test]
    fn duplicate_settings_frames_and_identifiers_are_rejected() {
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Uni, 0);
        let mut state = H3State::default();
        let mut stream = PeerUniStream::default();
        consume_peer_uni(&mut state, id, &mut stream, &[0x00, 0x04, 0x00]).unwrap();
        assert_eq!(
            consume_peer_uni(&mut state, id, &mut stream, &[0x04, 0x00])
                .unwrap_err()
                .code,
            H3_FRAME_UNEXPECTED
        );

        let mut state = H3State::default();
        let mut stream = PeerUniStream::default();
        let duplicate_identifier = [0x00, 0x04, 0x04, 0x06, 0x01, 0x06, 0x02];
        assert_eq!(
            consume_peer_uni(&mut state, id, &mut stream, &duplicate_identifier)
                .unwrap_err()
                .code,
            H3_SETTINGS_ERROR
        );

        let mut state = H3State::default();
        let mut stream = PeerUniStream::default();
        let mut excessive = vec![0x00, 0x04];
        write_varint(&mut excessive, (MAX_SETTINGS_PAYLOAD + 1) as u64);
        assert_eq!(
            consume_peer_uni(&mut state, id, &mut stream, &excessive)
                .unwrap_err()
                .code,
            H3_EXCESSIVE_LOAD
        );
    }

    #[test]
    fn h3_connection_permit_lives_through_bounded_drain() {
        use std::sync::atomic::Ordering;

        let active = Arc::new(AtomicU64::new(0));
        let permit = super::super::ConnectionPermit::try_acquire(active.clone(), 1).unwrap();
        let handle = ConnectionHandle(1);
        let request = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let mut state = H3State {
            _connection_permit: Some(permit),
            ..Default::default()
        };
        state.requests.insert(request);
        let mut states = HashMap::new();
        states.insert(handle, state);

        assert!(!h3_drain_complete(&states, 1, true));
        assert_eq!(active.load(Ordering::Relaxed), 1);
        states.get_mut(&handle).unwrap().requests.clear();
        assert!(h3_drain_complete(&states, 0, true));
        assert_eq!(
            active.load(Ordering::Relaxed),
            1,
            "the shared gauge remains held until the drained connection state is dropped"
        );
        drop(states);
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn required_client_certificate_eligibility_matches_tcp_rules() {
        let public: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert!(h3_client_eligible(false, false, public));
        assert!(h3_client_eligible(true, true, public));
        assert!(!h3_client_eligible(true, false, public));
        assert!(h3_client_eligible(true, false, loopback));

        let empty: Vec<rustls::pki_types::CertificateDer<'static>> = Vec::new();
        assert!(!certificate_chain_present(&empty));
        let present = vec![rustls::pki_types::CertificateDer::from(vec![1u8])];
        assert!(certificate_chain_present(&present));
    }

    /// Feed `stream` to `counter` in `chunk`-byte reads, as the receive path does.
    fn consume_in_chunks(
        counter: &mut H3FrameCounter,
        stream: &[u8],
        chunk: usize,
        limits: H3RequestLimits,
    ) -> Result<(), RequestFrameError> {
        let mut body = Vec::new();
        for piece in stream.chunks(chunk) {
            counter.consume(piece, &mut body, limits)?;
        }
        Ok(())
    }

    /// The receive path's state for a whole request stream delivered at once.
    fn received_request(wire: &[u8]) -> (H3FrameCounter, Vec<u8>) {
        let mut frames = H3FrameCounter::default();
        let mut body = Vec::new();
        frames
            .consume(wire, &mut body, H3RequestLimits::new(64 * 1024, 64 * 1024))
            .expect("a well-framed request stream");
        (frames, body)
    }

    #[test]
    fn incremental_frame_counter_enforces_independent_limits() {
        let limits = H3RequestLimits {
            max_header_bytes: 4,
            max_body_bytes: 5,
            max_request_wire_bytes: 32,
            max_connection_bytes: 64,
        };
        let mut valid = Vec::new();
        write_varint(&mut valid, 0x01);
        write_varint(&mut valid, 4);
        valid.extend_from_slice(b"head");
        write_varint(&mut valid, 0x00);
        write_varint(&mut valid, 5);
        valid.extend_from_slice(b"12345");
        let mut counter = H3FrameCounter::default();
        assert!(consume_in_chunks(&mut counter, &valid, 1, limits).is_ok());
        assert_eq!(counter.header_bytes, 4);
        assert_eq!(counter.body_bytes, 5);

        let mut header_too_large = H3FrameCounter::default();
        assert_eq!(
            header_too_large.consume(&[0x01, 5], &mut Vec::new(), limits),
            Err(RequestFrameError::HeadersTooLarge)
        );
        let mut body_too_large = H3FrameCounter::default();
        assert_eq!(
            body_too_large.consume(&[0x00, 6], &mut Vec::new(), limits),
            Err(RequestFrameError::Limit)
        );
    }

    #[test]
    fn forbidden_request_frames_are_rejected_even_when_split() {
        let limits = H3RequestLimits::new(64, 64);
        for frame_type in [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0d] {
            let mut stream = Vec::new();
            write_varint(&mut stream, 0x01);
            write_varint(&mut stream, 2);
            stream.extend_from_slice(&[0x00, 0x00]);
            write_varint(&mut stream, frame_type);
            write_varint(&mut stream, 0);
            assert!(
                matches!(
                    parse_h3_request(stream),
                    Err(H3RequestParseError::UnexpectedFrame)
                ),
                "frame type {frame_type:#x} must be forbidden on requests"
            );

            let mut encoded = Vec::new();
            write_varint(&mut encoded, frame_type);
            write_varint(&mut encoded, 0);
            let mut counter = H3FrameCounter::default();
            let split = encoded.len() - 1;
            assert!(consume_in_chunks(&mut counter, &encoded[..split], 1, limits).is_ok());
            assert_eq!(
                counter.consume(&encoded[split..], &mut Vec::new(), limits),
                Err(RequestFrameError::Unexpected)
            );
        }

        let extension = vec![0x01, 0x02, 0x00, 0x00, 0x21, 0x00];
        assert!(parse_h3_request(extension).is_ok());
    }

    #[test]
    fn frames_without_progress_are_bounded_per_request() {
        let limits = H3RequestLimits::new(1024, 1 << 20);
        let head = request_stream(&UPLOAD_HEAD, &[]);
        let flood = |frame: &[u8], count: usize| {
            let mut stream = head.clone();
            for _ in 0..count {
                stream.extend_from_slice(frame);
            }
            let mut counter = H3FrameCounter::default();
            consume_in_chunks(&mut counter, &stream, 7, limits)
        };
        let budget = H3_NO_PROGRESS_FRAMES as usize;
        // Empty DATA, empty HEADERS (after the head and trailers) and grease frames.
        for frame in [&[0x00, 0x00][..], &[0x21, 0x01, b'x'], &[0x40, 0x21, 0x00]] {
            assert_eq!(flood(frame, budget), Ok(()), "{frame:?}");
            assert_eq!(
                flood(frame, budget + 1),
                Err(RequestFrameError::ExcessiveLoad),
                "{frame:?}"
            );
        }
        let mut headers = head.clone();
        headers.extend_from_slice(&[0x01, 0x00]);
        for _ in 0..budget {
            headers.extend_from_slice(&[0x01, 0x00]);
        }
        assert_eq!(
            H3FrameCounter::default().consume(&headers, &mut Vec::new(), limits),
            Err(RequestFrameError::ExcessiveLoad)
        );
        // DATA payload is progress: many small frames are only bounded by the body cap.
        let mut body = Vec::new();
        let mut counter = H3FrameCounter::default();
        let mut stream = request_stream(&upload_fields(None), &[]);
        for _ in 0..3 * budget {
            stream.extend_from_slice(&[0x00, 0x01, b'b']);
        }
        assert_eq!(counter.consume(&stream, &mut body, limits), Ok(()));
        assert_eq!(body.len(), 3 * budget);
    }

    #[test]
    fn live_request_limits_accept_exact_large_body_and_reject_plus_one() {
        const LIVE_HEADER_LIMIT: usize = 16_380;
        const LIVE_BODY_LIMIT: usize = 100 * 1024 * 1024;
        let limits = H3RequestLimits::new(LIVE_HEADER_LIMIT, LIVE_BODY_LIMIT);
        assert_eq!(limits.max_header_bytes, LIVE_HEADER_LIMIT);
        assert_eq!(limits.max_body_bytes, LIVE_BODY_LIMIT);
        assert_eq!(limits.max_connection_bytes, 4 * LIVE_BODY_LIMIT);

        let mut exact = Vec::new();
        write_varint(&mut exact, 0x01);
        write_varint(&mut exact, 2);
        exact.extend_from_slice(&[0x00, 0x00]);
        write_varint(&mut exact, 0x00);
        write_varint(&mut exact, LIVE_BODY_LIMIT as u64);
        let mut counter = H3FrameCounter::default();
        assert!(counter.consume(&exact, &mut Vec::new(), limits).is_ok());
        assert_eq!(counter.header_bytes, 2);
        assert_eq!(counter.body_bytes, LIVE_BODY_LIMIT);

        let mut body_over = Vec::new();
        write_varint(&mut body_over, 0x00);
        write_varint(&mut body_over, (LIVE_BODY_LIMIT + 1) as u64);
        assert_eq!(
            H3FrameCounter::default().consume(&body_over, &mut Vec::new(), limits),
            Err(RequestFrameError::Limit)
        );

        let mut header_exact = Vec::new();
        write_varint(&mut header_exact, 0x01);
        write_varint(&mut header_exact, LIVE_HEADER_LIMIT as u64);
        assert!(
            H3FrameCounter::default()
                .consume(&header_exact, &mut Vec::new(), limits)
                .is_ok()
        );
        let mut header_over = Vec::new();
        write_varint(&mut header_over, 0x01);
        write_varint(&mut header_over, (LIVE_HEADER_LIMIT + 1) as u64);
        assert_eq!(
            H3FrameCounter::default().consume(&header_over, &mut Vec::new(), limits),
            Err(RequestFrameError::HeadersTooLarge)
        );
    }

    /// A request stream: HEADERS with `fields`, then one DATA frame per `bodies` length.
    pub(super) fn request_stream(fields: &[(&[u8], &[u8])], bodies: &[usize]) -> Vec<u8> {
        let field = literal_qpack_fields(fields);
        let mut wire = Vec::new();
        write_varint(&mut wire, 0x01);
        write_varint(&mut wire, field.len() as u64);
        wire.extend(field);
        for (index, len) in bodies.iter().enumerate() {
            write_varint(&mut wire, 0x00);
            write_varint(&mut wire, *len as u64);
            wire.extend(std::iter::repeat_n(b'a' + index as u8, *len));
        }
        wire
    }

    pub(super) const UPLOAD_HEAD: [(&[u8], &[u8]); 4] = [
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"upload.test"),
        (b":path", b"/upload"),
    ];

    fn upload_fields(content_length: Option<&'static [u8]>) -> Vec<(&'static [u8], &'static [u8])> {
        let mut fields = UPLOAD_HEAD.to_vec();
        if let Some(length) = content_length {
            fields.push((b"content-length", length));
        }
        fields
    }

    #[test]
    fn declared_content_length_bounds_the_body_as_it_arrives() {
        let limits = H3RequestLimits::new(1024, 1024);
        let fields = upload_fields(Some(b"10"));
        for chunk in [1, 3, 7, usize::MAX] {
            // The second DATA frame header already overruns: refused before its payload.
            let overrun = request_stream(&fields, &[6, 5]);
            let mut counter = H3FrameCounter::default();
            assert_eq!(
                consume_in_chunks(&mut counter, &overrun, chunk, limits),
                Err(RequestFrameError::Malformed),
                "chunk={chunk}"
            );
            assert_eq!(counter.body_bytes, 6, "chunk={chunk}");

            let mut single = H3FrameCounter::default();
            assert_eq!(
                consume_in_chunks(&mut single, &request_stream(&fields, &[11]), chunk, limits),
                Err(RequestFrameError::Malformed),
                "chunk={chunk}"
            );

            let exact = request_stream(&fields, &[4, 6]);
            let mut counter = H3FrameCounter::default();
            assert!(consume_in_chunks(&mut counter, &exact, chunk, limits).is_ok());
            assert_eq!(counter.body_bytes, 10);
            let parsed = parse_h3_request(exact).unwrap();
            assert_eq!(
                counter.decoded_head().cloned(),
                qpack_decode_limited(&parsed.field, limits.max_header_bytes),
                "dispatch reuses the head decoded while receiving (chunk={chunk})"
            );
        }
        // A request without a body is never decoded on the receive path.
        let mut bodiless = H3FrameCounter::default();
        assert!(
            bodiless
                .consume(&request_stream(&fields, &[]), &mut Vec::new(), limits)
                .is_ok()
        );
        assert!(bodiless.decoded_head().is_none());
    }

    #[test]
    fn over_cap_body_is_too_large_only_once_its_head_decodes() {
        let limits = H3RequestLimits::new(1024, 16);
        let refused = |stream: Vec<u8>| {
            let mut counter = H3FrameCounter::default();
            consume_in_chunks(&mut counter, &stream, 5, limits)
        };
        assert_eq!(
            refused(request_stream(&upload_fields(Some(b"17")), &[1])),
            Err(RequestFrameError::TooLarge),
            "a declared length over the cap is refused at the first DATA frame"
        );
        assert_eq!(
            refused(request_stream(&upload_fields(None), &[10, 7])),
            Err(RequestFrameError::TooLarge),
            "an undeclared body is refused when it crosses the cap"
        );
        assert_eq!(
            refused(request_stream(&upload_fields(Some(b"16")), &[16])),
            Ok(())
        );
        let mut undecodable = Vec::new();
        write_varint(&mut undecodable, 0x01);
        write_varint(&mut undecodable, 2);
        undecodable.extend_from_slice(&[0x01, 0x00]); // nonzero Required Insert Count
        write_varint(&mut undecodable, 0x00);
        write_varint(&mut undecodable, 17);
        assert_eq!(refused(undecodable), Err(RequestFrameError::Limit));
        let mut headless = Vec::new();
        write_varint(&mut headless, 0x00);
        write_varint(&mut headless, 17);
        assert_eq!(refused(headless), Err(RequestFrameError::Limit));
    }

    fn numbered(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn retained_datagram_never_pins_or_moves_a_recv_slot() {
        let mut slots = recv_slots();
        let bases: Vec<*const u8> = recv_iovecs(&mut slots)
            .iter()
            .map(|iov| {
                assert_eq!(iov.len(), MAX_DATAGRAM);
                iov.as_ptr()
            })
            .collect();
        let first = numbered(2900);
        slots[0][..first.len()].copy_from_slice(&first);
        let mut segments: Vec<BytesMut> =
            received_segments(&slots[0][..first.len()], 1200).collect();
        let retained = segments.remove(1);
        drop(segments);

        // Pass 2 receives into the same slot memory while pass 1's segment is held.
        let again: Vec<*const u8> = recv_iovecs(&mut slots)
            .iter()
            .map(|iov| iov.as_ptr())
            .collect();
        assert_eq!(bases, again);
        slots[0].fill(0xee);
        assert_eq!(&retained[..], &first[1200..2400]);
        assert!(!slots[0].as_ptr_range().contains(&retained.as_ptr()));
    }

    #[test]
    fn retained_segment_owns_an_allocation_no_larger_than_its_message() {
        let message = numbered(2900);
        for (stride, kept, len) in [(1200, 1, 1200), (1200, 2, 500), (0, 0, 2900)] {
            let mut segments: Vec<BytesMut> = received_segments(&message, stride).collect();
            let retained = segments.remove(kept);
            drop(segments);
            let owned = retained
                .freeze()
                .try_into_mut()
                .expect("the retained segment is the sole owner of its allocation");
            assert_eq!(owned.len(), len);
            assert!(owned.capacity() <= message.len(), "stride={stride}");
            assert_eq!(owned.capacity(), len, "stride={stride}");
        }
    }

    #[test]
    fn gro_stride_split_yields_the_original_segment_bytes() {
        let message = numbered(2900);
        let split = |stride| -> Vec<Vec<u8>> {
            received_segments(&message, stride)
                .map(|segment| segment.to_vec())
                .collect()
        };
        assert_eq!(
            split(1200),
            vec![
                message[..1200].to_vec(),
                message[1200..2400].to_vec(),
                message[2400..].to_vec(),
            ]
        );
        for whole in [0, 2900, 4096] {
            assert_eq!(split(whole), vec![message.clone()], "stride={whole}");
        }
        assert_eq!(received_segments(&[], 1200).count(), 0);
    }

    #[test]
    fn aggregate_request_buffer_is_charged_and_reclaimed() {
        let limits = H3RequestLimits {
            max_header_bytes: 16,
            max_body_bytes: 16,
            max_request_wire_bytes: 32,
            max_connection_bytes: 10,
        };
        let first = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let second = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 1);
        let mut st = H3State::default();
        st.requests.extend([first, second]);
        assert!(append_request_bytes(&mut st, first, &[0x00, 4, 1, 2, 3, 4], limits).is_ok());
        assert_eq!(st.total_req_bytes.get(), 6);
        assert!(append_request_bytes(&mut st, second, &[0x00, 4, 5, 6, 7, 8], limits).is_err());
        assert_eq!(st.total_req_bytes.get(), 6);
        reclaim_request(&mut st, second);
        reclaim_request(&mut st, first);
        assert_eq!(st.total_req_bytes.get(), 0);
    }

    /// HEADERS with `refs` one-byte static references (`age: 0`), then `body` in one DATA frame.
    fn static_ref_request(refs: usize, body: &[u8]) -> Vec<u8> {
        let mut field = vec![0x00, 0x00];
        field.extend(std::iter::repeat_n(0xC0 | 2, refs));
        let mut wire = Vec::new();
        write_varint(&mut wire, 0x01);
        write_varint(&mut wire, field.len() as u64);
        wire.extend(field);
        write_varint(&mut wire, 0x00);
        write_varint(&mut wire, body.len() as u64);
        wire.extend_from_slice(body);
        wire
    }

    /// Heap the decoded head of `frames` occupies, at least.
    fn decoded_heap(frames: &H3FrameCounter) -> usize {
        let (fields, _) = frames.decoded_head().expect("decoded head");
        fields.capacity() * std::mem::size_of::<(Vec<u8>, Vec<u8>)>()
            + fields
                .iter()
                .map(|(name, value)| name.capacity() + value.capacity())
                .sum::<usize>()
    }

    #[test]
    fn decoded_request_heads_are_charged_to_every_request_budget() {
        const REFS: usize = 455;
        let limits = H3RequestLimits::new(16_380, 1 << 20);
        let wire = static_ref_request(REFS, b"");
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(1 << 20));
        let mut connections: Vec<H3State> = Vec::new();
        let mut accepted = 0usize;
        let mut decoded = 0usize;
        // 20 connections of 256 streams: the probe that grew RSS 168 MB on 2.4 MB charged.
        'probe: for _ in 0..20 {
            let mut st = H3State {
                body_budget: Some(budget.clone()),
                ..Default::default()
            };
            for index in 0..256 {
                let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, index);
                st.requests.insert(id);
                if append_request_bytes(&mut st, id, &wire, limits).is_err() {
                    connections.push(st);
                    break 'probe;
                }
                let frames = &st.req_frames[&id];
                assert!(frames.head_footprint >= REFS * 80);
                assert_eq!(frames.charged, wire.len() + frames.head_footprint);
                decoded += decoded_heap(frames);
                accepted += 1;
            }
            connections.push(st);
        }
        assert!(
            accepted < (1 << 20) / (REFS * 80),
            "{accepted} decoded heads fit a budget meant for far fewer"
        );
        assert!(budget.in_flight() >= (decoded + accepted * wire.len()) as u64);
        let charged: usize = connections.iter().map(|st| st.total_req_bytes.get()).sum();
        assert_eq!(charged as u64, budget.in_flight());
        for st in &mut connections {
            reclaim_buffered_requests(st);
            assert_eq!(st.total_req_bytes.get(), 0);
        }
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn decoded_head_charge_ends_when_dispatch_consumes_the_head() {
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(1 << 20));
        let mut st = H3State {
            body_budget: Some(budget.clone()),
            ..Default::default()
        };
        st.requests.insert(id);
        let wire = static_ref_request(100, b"body");
        append_request_bytes(&mut st, id, &wire, H3RequestLimits::new(16_380, 1024)).unwrap();
        let footprint = st.req_frames[&id].head_footprint;
        assert_eq!(budget.in_flight(), (wire.len() + footprint) as u64);
        let taken = take_request_for_dispatch(&mut st, id);
        let charge = RequestChargeGuard {
            total: st.total_req_bytes.clone(),
            bytes: taken.frames.charged,
        };
        assert_eq!(st.total_req_bytes.get(), wire.len() + footprint);
        let (parsed, head) = taken.frames.finish(taken.body, taken.lease).unwrap();
        assert_eq!(head.map(|(fields, _)| fields.len()), Some(100));
        assert_eq!(
            budget.in_flight(),
            wire.len() as u64,
            "the body keeps only its wire reservation"
        );
        drop(parsed);
        assert_eq!(budget.in_flight(), 0);
        drop(charge);
        assert_eq!(st.total_req_bytes.get(), 0);
    }

    #[test]
    fn finished_request_stays_charged_until_pipeline_task_releases_it() {
        let limits = H3RequestLimits {
            max_header_bytes: 16,
            max_body_bytes: 16,
            max_request_wire_bytes: 32,
            max_connection_bytes: 10,
        };
        let first = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let second = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 1);
        let mut st = H3State::default();
        st.requests.extend([first, second]);
        assert!(append_request_bytes(&mut st, first, &[0x00, 4, 1, 2, 3, 4], limits).is_ok());
        let dispatched = take_request_for_dispatch(&mut st, first);
        assert_eq!(dispatched.frames.charged, 6);
        assert_eq!(
            st.total_req_bytes.get(),
            6,
            "spawned ownership remains charged"
        );
        assert!(append_request_bytes(&mut st, second, &[0x00, 4, 5, 6, 7, 8], limits).is_err());
        reclaim_request(&mut st, second);
        let charge = RequestChargeGuard {
            total: st.total_req_bytes.clone(),
            bytes: dispatched.frames.charged,
        };
        drop(charge);
        assert_eq!(st.total_req_bytes.get(), 0);
        assert!(append_request_bytes(&mut st, second, &[0x00, 4, 5, 6, 7, 8], limits).is_ok());
    }

    #[test]
    fn global_request_budget_is_released_on_connection_loss_and_state_drop() {
        let limits = H3RequestLimits::new(16, 16);
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(16));
        for explicit_loss in [false, true] {
            let mut st = H3State {
                body_budget: Some(budget.clone()),
                ..Default::default()
            };
            st.requests.insert(id);
            append_request_bytes(&mut st, id, &[0x00, 4, 1, 2, 3, 4], limits).unwrap();
            assert_eq!(budget.in_flight(), 6);
            if explicit_loss {
                // The same helper is called when quinn reports ConnectionLost.
                reclaim_buffered_requests(&mut st);
                assert_eq!(budget.in_flight(), 0);
                assert_eq!(st.total_req_bytes.get(), 0);
                assert!(st.requests.is_empty());
            }
            // Covers direct cancellation/error/drop as well as the drained map's
            // removal; explicit-loss followed by drop must not double-release.
            let mut states = HashMap::new();
            states.insert(ConnectionHandle(1), st);
            states.remove(&ConnectionHandle(1));
            assert_eq!(budget.in_flight(), 0);
            assert!(budget.try_acquire(16), "an unrelated upload must still fit");
            budget.release(16);
        }
    }

    #[test]
    fn reclaim_return_keeps_global_request_budget_until_bytes_drop() {
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(16));
        let mut st = H3State {
            body_budget: Some(budget.clone()),
            ..Default::default()
        };
        st.requests.insert(id);
        append_request_bytes(
            &mut st,
            id,
            &[0x00, 4, 1, 2, 3, 4],
            H3RequestLimits::new(16, 16),
        )
        .unwrap();
        let bytes = reclaim_request(&mut st, id);
        assert_eq!(st.total_req_bytes.get(), 0);
        assert_eq!(
            budget.in_flight(),
            6,
            "smoke/reclaim callers still own these bytes"
        );
        drop(st);
        assert_eq!(budget.in_flight(), 6);
        drop(bytes);
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn dispatched_body_retains_global_budget_through_compaction_and_cloning() {
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(16));
        let mut st = H3State {
            body_budget: Some(budget.clone()),
            ..Default::default()
        };
        st.requests.insert(id);
        let wire = [0x01, 2, 0, 0, 0x00, 4, 1, 2, 3, 4];
        append_request_bytes(&mut st, id, &wire, H3RequestLimits::new(16, 16)).unwrap();
        let allocation = st.req_buf[&id].as_ptr();
        let taken = take_request_for_dispatch(&mut st, id);
        assert_eq!(
            budget.in_flight(),
            10,
            "dispatch must transfer, never release/reacquire"
        );
        drop(st);
        let (parsed, _) = taken.frames.finish(taken.body, taken.lease).unwrap();
        assert_eq!(parsed.body.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(
            parsed.body.as_ptr(),
            allocation,
            "dispatch must hand over the body the receive path compacted"
        );
        assert_eq!(
            budget.in_flight(),
            10,
            "the received wire bytes remain charged while the body lives"
        );
        assert!(!budget.try_acquire(7));
        let slice = parsed.body.slice(1..);
        drop(parsed);
        assert_eq!(budget.in_flight(), 10);
        drop(slice);
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn malformed_dispatched_request_returns_global_budget() {
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(16));
        let mut lease = hj_core::budget::BodyBufferLease::new(budget.clone());
        assert!(lease.reserve(3));
        // Truncated field section fails before any body is dispatched.
        let mut frames = H3FrameCounter::default();
        let mut body = Vec::new();
        frames
            .consume(&[0x01, 4, 0], &mut body, H3RequestLimits::new(16, 16))
            .unwrap();
        assert!(frames.finish(body, Some(lease)).is_none());
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn response_egress_budget_is_global_per_connection_and_raii_released() {
        const MIB: usize = 1024 * 1024;
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(200 * MIB as u64));
        let first_connection = H3EgressBudget::new(global.clone());
        let second_connection = H3EgressBudget::new(global.clone());

        let first = first_connection
            .reserve(100 * MIB)
            .expect("one maximum cache response must fit");
        assert_eq!(global.in_flight(), 100 * MIB as u64);
        let extra = first_connection
            .reserve(28 * MIB)
            .expect("framing and a parallel response must fit at the connection cap");
        assert!(
            first_connection.reserve(1).is_none(),
            "one peer cannot exceed its 128 MiB retained-response cap"
        );
        assert!(
            second_connection.reserve(73 * MIB).is_none(),
            "independent peers still share the process-wide cap"
        );

        drop(first);
        assert!(second_connection.reserve(72 * MIB).is_some());
        drop(extra);
    }

    #[tokio::test]
    async fn bridged_h3_requests_share_their_connections_response_budget() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = seen.clone();
        let bridge = crate::uring::bridge::spawn_on_current(2, move |_req, ctx: BridgeCtx| {
            observed.lock().unwrap().push(ctx.response_budget.clone());
            async { http::Response::new(hj_core::Body::Empty) }
        });
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(1 << 20));
        let connection = H3EgressBudget::new(global.clone());
        let other = H3EgressBudget::new(global);
        for egress in [&connection, &connection, &other] {
            let fields = literal_qpack_fields(&[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a.test"),
                (b":path", b"/"),
            ]);
            let mut wire = Vec::new();
            write_varint(&mut wire, 1);
            write_varint(&mut wire, fields.len() as u64);
            wire.extend(fields);
            let (frames, body) = received_request(&wire);
            let _ = handle_h3_request(
                frames,
                body,
                None,
                false,
                None,
                None,
                "127.0.0.1:32000".parse().unwrap(),
                "127.0.0.1:8443".parse().unwrap(),
                &bridge,
                crate::uring::ClientAuth::None,
                H3RequestLimits::new(4096, 4096),
                None,
                Some(egress.clone()),
                Default::default(),
            )
            .await;
        }
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert!(Arc::ptr_eq(&seen[0], &connection.bridge));
        assert!(Arc::ptr_eq(&seen[1], &connection.bridge));
        assert!(Arc::ptr_eq(&seen[2], &other.bridge));
        assert!(!Arc::ptr_eq(&connection.bridge, &other.bridge));
        assert_eq!(
            connection.bridge.capacity(),
            crate::uring::bridge::CONNECTION_RESPONSE_MEM
        );
    }

    #[test]
    fn pending_response_releases_egress_budget_on_reset() {
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(16));
        let budget = H3EgressBudget::new(global.clone());
        let lease = budget.reserve(8).expect("test reservation");
        let pending = PendingSend {
            completion: None,
            parts: std::iter::once(PendingPart::contiguous(vec![1, 2, 3], Some(lease))).collect(),
            fin: true,
            stall: None,
        };
        assert_eq!(global.in_flight(), 8);
        drop(pending);
        assert_eq!(global.in_flight(), 0);
    }

    #[test]
    fn streamed_chunk_ack_waits_until_driver_buffer_is_drained() {
        let (ack_tx, ack_rx) = flume::bounded(1);
        let part = PendingPart::data_frame(Bytes::from_static(b"abc"), Some(ack_tx), None);
        let mut pending = PendingSend {
            completion: None,
            parts: std::iter::once(part).collect(),
            fin: false,
            stall: None,
        };
        assert!(matches!(ack_rx.try_recv(), Err(flume::TryRecvError::Empty)));
        assert!(acknowledge_front_part(&mut pending));
        assert_eq!(ack_rx.try_recv(), Ok(()));
    }

    #[test]
    fn completion_waits_for_drained_parts_and_accepted_fin() {
        for accepted in [false, true] {
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let copy = events.clone();
            let mut pending = PendingSend {
                completion: Some(hj_core::ResponseCompletion::new(move |end| {
                    copy.lock().unwrap().push(end)
                })),
                parts: std::iter::once(PendingPart::contiguous(vec![1, 2, 3], None)).collect(),
                fin: false,
                stall: None,
            };
            assert!(!pending.finish_if_drained(|| panic!("body not drained")));
            assert!(acknowledge_front_part(&mut pending));
            assert!(!pending.finish_if_drained(|| panic!("FIN not available")));
            assert!(events.lock().unwrap().is_empty());
            pending.fin = true;
            assert!(pending.finish_if_drained(|| accepted));
            drop(pending);
            assert_eq!(
                *events.lock().unwrap(),
                vec![if accepted {
                    hj_core::ResponseEnd::Complete
                } else {
                    hj_core::ResponseEnd::Cancelled
                }]
            );
        }
    }

    #[test]
    fn streamed_data_frame_retains_the_bridge_chunk_allocation() {
        let chunk = Bytes::from(vec![0x5a; 4096]);
        let pointer = chunk.as_ptr();
        let part = PendingPart::data_frame(chunk, None, None);
        let PendingPart::DataFrame {
            header,
            header_len,
            data,
            ..
        } = part
        else {
            panic!("DATA chunk must remain a split header/payload part");
        };
        assert_eq!(
            data.as_ptr(),
            pointer,
            "payload must not be copied while framing"
        );
        let mut pos = 0;
        assert_eq!(read_varint(&header[..header_len], &mut pos), Some(0));
        assert_eq!(
            read_varint(&header[..header_len], &mut pos),
            Some(data.len() as u64)
        );
        assert_eq!(pos, header_len);
    }

    #[test]
    fn dropping_reset_stream_disconnects_chunk_acknowledgement() {
        let (ack_tx, ack_rx) = flume::bounded(1);
        let part = PendingPart::data_frame(Bytes::from_static(b"abc"), Some(ack_tx), None);
        let pending = PendingSend {
            completion: None,
            parts: std::iter::once(part).collect(),
            fin: false,
            stall: None,
        };
        drop(pending);
        assert!(matches!(
            ack_rx.try_recv(),
            Err(flume::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn send_stall_clock_needs_real_progress_to_restart() {
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(5);
        let started = advance_send_stall(None, 0, true, t0).unwrap();
        assert_eq!(started.since, t0);
        // A trickle below the progress floor keeps the original clock.
        let trickled = advance_send_stall(Some(started), 100, true, later).unwrap();
        assert_eq!((trickled.since, trickled.progressed), (t0, 100));
        let restarted =
            advance_send_stall(Some(trickled), SEND_STALL_MIN_PROGRESS, true, later).unwrap();
        assert_eq!((restarted.since, restarted.progressed), (later, 0));
        // Nothing queued (backend slow, or all bytes accepted): no clock.
        assert!(advance_send_stall(Some(started), 0, false, later).is_none());
    }

    #[test]
    fn credit_starved_response_is_reset_at_the_stall_deadline() {
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let other = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 1);
        let t0 = Instant::now();
        let timeout = Duration::from_millis(300);
        let token = CancellationToken::new();
        let mut st = H3State::default();
        st.send_stall_timeout = Some(timeout);
        st.request_cancellations.insert(id, token.clone());
        for (stream, stall) in [
            (
                id,
                Some(SendStall {
                    since: t0,
                    progressed: 0,
                }),
            ),
            (other, None),
        ] {
            st.pending.insert(
                stream,
                PendingSend {
                    completion: None,
                    parts: std::iter::once(PendingPart::contiguous(vec![0; 64], None)).collect(),
                    fin: false,
                    stall,
                },
            );
        }
        assert_eq!(st.next_deadline(), Some(t0 + timeout));
        assert!(reclaim_stalled_sends(&mut st, t0 + timeout - Duration::from_nanos(1)).is_empty());
        let resets = admission_counts().send_stall_resets;
        assert_eq!(reclaim_stalled_sends(&mut st, t0 + timeout), vec![id]);
        assert!(
            admission_counts().send_stall_resets > resets,
            "the reset is exported through the admission counters"
        );
        assert!(
            token.is_cancelled(),
            "the bridge request and its slot are released"
        );
        assert!(!st.pending.contains_key(&id));
        assert!(
            st.pending.contains_key(&other),
            "a response not waiting on credit stays"
        );
        assert_eq!(st.next_deadline(), None);
        st.send_stall_timeout = None;
        st.pending.get_mut(&other).unwrap().stall = Some(SendStall {
            since: t0,
            progressed: 0,
        });
        assert!(reclaim_stalled_sends(&mut st, t0 + timeout * 10).is_empty());
    }

    #[test]
    fn cancelling_response_stream_cancels_dispatch_and_drops_pending_chunks() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let copy = events.clone();
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let token = CancellationToken::new();
        let (ack_tx, ack_rx) = flume::bounded(1);
        let mut state = H3State::default();
        state.request_cancellations.insert(id, token.clone());
        state.pending.insert(
            id,
            PendingSend {
                completion: Some(hj_core::ResponseCompletion::new(move |end| {
                    copy.lock().unwrap().push(end)
                })),
                parts: std::iter::once(PendingPart::data_frame(
                    Bytes::from_static(b"backend chunk"),
                    Some(ack_tx),
                    None,
                ))
                .collect(),
                fin: false,
                stall: None,
            },
        );

        cancel_dispatched_request(&mut state, id);

        assert!(token.is_cancelled());
        assert!(!state.request_cancellations.contains_key(&id));
        assert!(!state.pending.contains_key(&id));
        assert_eq!(
            *events.lock().unwrap(),
            vec![hj_core::ResponseEnd::Cancelled]
        );
        assert!(matches!(
            ack_rx.try_recv(),
            Err(flume::TryRecvError::Disconnected)
        ));
    }

    #[tokio::test]
    async fn cancellation_drops_the_running_request_future() {
        struct DropSignal(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let cancelled = CancellationToken::new();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = DropSignal(dropped.clone());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let work = async move {
            let _signal = signal;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        };
        let task = tokio::spawn(run_cancelable_request(cancelled.clone(), work));
        started_rx.await.unwrap();

        cancelled.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("cancelled request task must finish")
            .unwrap();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    // Reclaiming a request stream must clear BOTH the `requests` slot and the `req_buf`
    // bytes (a reset-without-FIN stream otherwise strands per-connection memory until the
    // whole connection drains). Mirrors the drive-loop `ReadEnd::Gone` / oversize / FIN
    // branches, which all route removals through `reclaim_request`.
    #[test]
    fn reclaim_request_clears_slot_and_buffer() {
        let mut st = H3State::default();
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0); // first client bidi stream
        st.requests.insert(id);
        st.req_buf.insert(id, b"partial body".to_vec());
        st.req_frames.insert(
            id,
            H3FrameCounter {
                charged: b"partial body".len(),
                ..Default::default()
            },
        );
        st.request_snapshots.insert(
            id,
            H3RequestSnapshot::unscoped(H3RequestConfig::new(H3RequestLimits::new(16, 16), None)),
        );
        // A second, still-open stream must be untouched.
        let other = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 1);
        st.requests.insert(other);
        st.req_buf.insert(other, b"keep".to_vec());
        st.req_frames.insert(
            other,
            H3FrameCounter {
                charged: b"keep".len(),
                ..Default::default()
            },
        );
        st.request_snapshots.insert(
            other,
            H3RequestSnapshot::unscoped(H3RequestConfig::new(H3RequestLimits::new(16, 16), None)),
        );
        st.total_req_bytes
            .set(b"partial body".len() + b"keep".len());

        let drained = reclaim_request(&mut st, id);
        assert_eq!(drained.as_ref(), b"partial body");
        assert!(!st.requests.contains(&id), "slot must be removed");
        assert!(!st.req_buf.contains_key(&id), "buffer must be removed");
        assert!(!st.request_snapshots.contains_key(&id));
        // The unrelated open stream is retained.
        assert!(st.requests.contains(&other));
        assert_eq!(
            st.req_buf.get(&other).map(|b| b.as_slice()),
            Some(&b"keep"[..])
        );
        assert!(st.request_snapshots.contains_key(&other));
        assert_eq!(st.total_req_bytes.get(), b"keep".len());

        // Reclaiming an unknown stream is a harmless no-op returning empty.
        assert!(
            reclaim_request(
                &mut st,
                StreamId::new(quinn_proto::Side::Client, Dir::Bi, 99)
            )
            .is_empty()
        );
    }

    #[test]
    fn unfinished_request_deadline_is_absolute_and_reclaims_all_state() {
        let accepted = Instant::now();
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let mut st = H3State::default();
        st.track_request_stream(
            id,
            accepted,
            H3RequestSnapshot::unscoped(H3RequestConfig::new(
                H3RequestLimits::new(16, 16),
                Some(Duration::from_secs(10)),
            )),
        );
        let deadline = accepted + Duration::from_secs(10);
        assert_eq!(st.next_request_deadline(), Some(deadline));
        assert_eq!(
            st.request_snapshots[&id].deadline.map(|key| key.when),
            Some(deadline)
        );

        append_request_bytes(
            &mut st,
            id,
            &[0x00, 4, 1, 2, 3, 4],
            H3RequestLimits::new(16, 16),
        )
        .unwrap();
        // Receiving progress does not slide the acceptance-time deadline.
        assert_eq!(
            st.request_snapshots[&id].deadline.map(|key| key.when),
            Some(deadline)
        );
        assert!(reclaim_expired_requests(&mut st, deadline - Duration::from_nanos(1)).is_empty());

        assert_eq!(reclaim_expired_requests(&mut st, deadline), vec![id]);
        assert!(!st.requests.contains(&id));
        assert!(!st.req_buf.contains_key(&id));
        assert!(!st.req_frames.contains_key(&id));
        assert!(!st.body_leases.contains_key(&id));
        assert!(!st.request_snapshots.contains_key(&id));
        assert!(st.request_deadlines.is_empty());
        assert_eq!(st.next_request_deadline(), None);
        assert_eq!(st.total_req_bytes.get(), 0);
    }

    /// (#1035) Each `BODY_MIN_PROGRESS` of request bytes re-keys the stream's deadline
    /// to `now + timeout`, never past `accepted + ceiling`; less progress never moves it.
    #[test]
    fn progressing_request_deadline_is_rekeyed_and_capped_at_the_ceiling() {
        use hj_core::body_deadline::BODY_MIN_PROGRESS;
        let accepted = Instant::now();
        let timeout = Duration::from_secs(10);
        let ceiling = Duration::from_secs(25);
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let other = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 1);
        let mut st = H3State::default();
        let config = H3RequestConfig::new(H3RequestLimits::new(16, 1 << 20), Some(timeout))
            .with_body_ceiling(ceiling);
        st.track_request_stream(id, accepted, H3RequestSnapshot::unscoped(config));
        st.track_request_stream(other, accepted, H3RequestSnapshot::unscoped(config));
        let floor = BODY_MIN_PROGRESS as usize;

        st.extend_request_deadline(id, floor - 1, accepted + Duration::from_secs(5));
        assert_eq!(
            st.request_snapshots[&id].deadline.map(|key| key.when),
            Some(accepted + timeout)
        );
        let at = accepted + Duration::from_secs(8);
        st.extend_request_deadline(id, floor, at);
        assert_eq!(
            st.request_snapshots[&id].deadline.map(|key| key.when),
            Some(at + timeout)
        );
        assert_eq!(st.request_deadlines.len(), 2, "the old node is replaced");
        assert_eq!(st.next_request_deadline(), Some(accepted + timeout));
        assert_eq!(
            reclaim_expired_requests(&mut st, accepted + timeout),
            vec![other]
        );
        assert!(
            reclaim_expired_requests(&mut st, at + timeout - Duration::from_nanos(1)).is_empty()
        );

        let late = accepted + Duration::from_secs(17);
        st.extend_request_deadline(id, 2 * floor, late);
        assert_eq!(st.next_request_deadline(), Some(accepted + ceiling));
        st.extend_request_deadline(id, 3 * floor, accepted + Duration::from_secs(20));
        assert_eq!(st.next_request_deadline(), Some(accepted + ceiling));
        assert_eq!(
            reclaim_expired_requests(&mut st, accepted + ceiling),
            vec![id]
        );
        assert!(st.request_deadlines.is_empty());
    }

    #[test]
    fn request_deadline_minimum_advances_and_disabled_timeout_stays_unarmed() {
        let now = Instant::now();
        let first = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let second = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 1);
        let disabled = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 2);
        let mut st = H3State::default();
        let snapshot = |timeout| {
            H3RequestSnapshot::unscoped(H3RequestConfig::new(H3RequestLimits::new(16, 16), timeout))
        };
        st.track_request_stream(first, now, snapshot(Some(Duration::from_secs(5))));
        st.track_request_stream(second, now, snapshot(Some(Duration::from_secs(9))));
        st.track_request_stream(disabled, now, snapshot(None));
        assert_eq!(
            st.next_request_deadline(),
            Some(now + Duration::from_secs(5))
        );
        assert_eq!(st.request_snapshots[&disabled].deadline, None);

        let _ = take_request_for_dispatch(&mut st, first);
        assert_eq!(
            st.next_request_deadline(),
            Some(now + Duration::from_secs(9))
        );
        let _ = take_request_for_dispatch(&mut st, second);
        assert_eq!(st.next_request_deadline(), None);
        assert!(st.requests.contains(&disabled));
        assert!(st.request_snapshots.contains_key(&disabled));

        reclaim_buffered_requests(&mut st);
        assert!(st.requests.is_empty());
        assert!(st.request_deadlines.is_empty());
        assert!(st.request_snapshots.is_empty());
        assert_eq!(st.next_request_deadline(), None);
    }

    #[test]
    fn equal_request_deadlines_retire_from_the_ordered_set_incrementally() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        let mut st = H3State::default();
        let mut ids = Vec::with_capacity(256);
        for index in 0..256 {
            let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, index);
            ids.push(id);
            st.track_request_stream(
                id,
                now,
                H3RequestSnapshot::unscoped(H3RequestConfig::new(
                    H3RequestLimits::new(16, 16),
                    Some(Duration::from_secs(5)),
                )),
            );
        }
        assert_eq!(st.request_deadlines.len(), ids.len());

        for (position, id) in ids.into_iter().enumerate() {
            let _ = take_request_for_dispatch(&mut st, id);
            let expected = (position != 255).then_some(deadline);
            assert_eq!(st.next_request_deadline(), expected);
        }
        assert!(st.request_deadlines.is_empty());
        assert!(st.request_snapshots.is_empty());
    }

    #[test]
    fn cooperative_drains_are_bounded_and_deadline_index_is_incremental() {
        assert!(
            MAX_RECV_DRAIN_BATCHES > 1,
            "a drain must retain syscall batching"
        );
        assert!(
            (2..=MAX_INFLIGHT_PER_CORE).contains(&MAX_COMPLETION_DRAIN_BATCH),
            "completion batching must retain throughput without monopolizing the endpoint loop"
        );
        assert!(recv_drain_should_continue(1, GRO_BATCH));
        assert!(recv_drain_should_continue(
            MAX_RECV_DRAIN_BATCHES - 1,
            GRO_BATCH
        ));
        assert!(!recv_drain_should_continue(
            MAX_RECV_DRAIN_BATCHES,
            GRO_BATCH
        ));
        assert!(!recv_drain_should_continue(1, GRO_BATCH - 1));

        let now = Instant::now();
        let packet_affected = ConnectionHandle(10);
        let deadline_due = ConnectionHandle(11);
        let deadline_future = ConnectionHandle(12);
        let mut deadlines = ConnectionDeadlineIndex::default();
        deadlines.sync(deadline_due, Some(now));
        deadlines.sync(deadline_future, Some(now + Duration::from_secs(1)));
        deadlines.sync(deadline_due, Some(now));
        assert_eq!(deadlines.ordered.len(), 2, "same deadline is a no-op");
        assert_eq!(deadlines.next(), Some(now));

        let mut affected = std::collections::HashSet::from([packet_affected]);
        deadlines.extend_due(&mut affected, now);

        assert!(affected.contains(&packet_affected));
        assert!(affected.contains(&deadline_due));
        assert!(!affected.contains(&deadline_future));
        assert_eq!(deadlines.next(), Some(now + Duration::from_secs(1)));
        assert!(!deadlines.by_connection.contains_key(&deadline_due));

        // A deadline popped by the receive drain at the pump round cap is
        // reinserted from the connection's unchanged cached minimum before
        // pump returns; the outer loop can therefore select it again.
        deadlines.sync(deadline_due, Some(now));
        assert_eq!(deadlines.next(), Some(now));
        let mut requeued = std::collections::HashSet::new();
        deadlines.extend_due(&mut requeued, now);
        assert_eq!(requeued, std::collections::HashSet::from([deadline_due]));

        deadlines.sync(deadline_future, Some(now + Duration::from_secs(2)));
        assert_eq!(deadlines.ordered.len(), 1, "reschedule replaces its node");
        assert_eq!(deadlines.next(), Some(now + Duration::from_secs(2)));
        deadlines.remove(deadline_future);
        assert!(deadlines.ordered.is_empty());
        assert!(deadlines.by_connection.is_empty());
    }

    // Full H3 request stream: HEADERS frame + DATA frame -> (field section, body).
    #[test]
    fn parse_h3_request_frames() {
        let mut field = vec![0x00, 0x00];
        field.push(0xC0 | 17); // :method GET
        field.push(0xC0 | 1); // :path /
        let mut stream = Vec::new();
        write_varint(&mut stream, 0x01); // HEADERS
        write_varint(&mut stream, field.len() as u64);
        stream.extend_from_slice(&field);
        write_varint(&mut stream, 0x00); // DATA
        write_varint(&mut stream, 5);
        stream.extend_from_slice(b"hello");
        let parsed = parse_h3_request(stream).expect("parse");
        assert_eq!(parsed.body.as_ref(), b"hello");
        assert_eq!(
            qpack_decode(&parsed.field).unwrap(),
            vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":path".to_vec(), b"/".to_vec())
            ]
        );
    }

    #[test]
    fn request_body_is_compacted_as_received_and_dispatched_without_a_copy() {
        let field = [0x00, 0x00];
        let mut stream = Vec::new();
        write_varint(&mut stream, 0x01);
        write_varint(&mut stream, field.len() as u64);
        stream.extend_from_slice(&field);
        for chunk in [b"first".as_slice(), b"-second".as_slice()] {
            write_varint(&mut stream, 0x00);
            write_varint(&mut stream, chunk.len() as u64);
            stream.extend_from_slice(chunk);
        }
        // An extension frame between DATA frames is validated and dropped, never kept.
        write_varint(&mut stream, 0x21);
        write_varint(&mut stream, 3);
        stream.extend_from_slice(b"ext");
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        for chunk in [1, 4, usize::MAX] {
            let mut st = H3State::default();
            st.requests.insert(id);
            for piece in stream.chunks(chunk) {
                append_request_bytes(&mut st, id, piece, H3RequestLimits::new(64, 64)).unwrap();
            }
            assert_eq!(st.req_buf[&id], b"first-second", "chunk={chunk}");
            let allocation = st.req_buf[&id].as_ptr();
            let taken = take_request_for_dispatch(&mut st, id);
            assert_eq!(taken.frames.charged, stream.len(), "chunk={chunk}");
            let (parsed, _) = taken.frames.finish(taken.body, None).unwrap();
            assert_eq!(parsed.field, field);
            assert_eq!(parsed.body.as_ref(), b"first-second");
            assert_eq!(
                parsed.body.as_ptr(),
                allocation,
                "dispatch must reuse the receive-time body allocation (chunk={chunk})"
            );
        }
    }

    #[test]
    fn parse_h3_rejects_data_after_trailers() {
        let field = [0x00, 0x00];
        let mut stream = Vec::new();
        write_varint(&mut stream, 0x01);
        write_varint(&mut stream, field.len() as u64);
        stream.extend_from_slice(&field);
        write_varint(&mut stream, 0x00);
        write_varint(&mut stream, 1);
        stream.push(b'a');
        write_varint(&mut stream, 0x01);
        write_varint(&mut stream, field.len() as u64);
        stream.extend_from_slice(&field);

        let parsed = parse_h3_request(stream.clone()).expect("valid trailer section");
        assert_eq!(parsed.body.as_ref(), b"a");
        assert_eq!(parsed.trailers.as_deref(), Some(&field[..]));

        write_varint(&mut stream, 0x00);
        write_varint(&mut stream, 1);
        stream.push(b'b');
        assert!(
            parse_h3_request(stream).is_err(),
            "DATA after trailing HEADERS is malformed"
        );
    }

    #[test]
    fn request_pseudo_headers_require_one_scheme() {
        let base = vec![
            (b":method".to_vec(), b"GET".to_vec()),
            (b":path".to_vec(), b"/".to_vec()),
        ];
        assert!(split_h3_request_headers(base.clone()).is_none());

        let mut valid = base.clone();
        valid.insert(1, (b":scheme".to_vec(), b"https".to_vec()));
        assert!(split_h3_request_headers(valid.clone()).is_some());

        let mut non_https = base.clone();
        non_https.insert(1, (b":scheme".to_vec(), b"http".to_vec()));
        assert!(
            split_h3_request_headers(non_https).is_none(),
            "QUIC requests must use :scheme=https"
        );

        let mut connect = valid.clone();
        connect[0].1 = b"CONNECT".to_vec();
        assert!(
            split_h3_request_headers(connect).is_none(),
            "CONNECT is rejected until its distinct pseudo-header rules are implemented"
        );

        valid.insert(2, (b":scheme".to_vec(), b"https".to_vec()));
        assert!(
            split_h3_request_headers(valid).is_none(),
            "duplicate :scheme must be rejected"
        );
    }

    pub(super) fn literal_qpack_fields(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut block = vec![0x00, 0x00]; // RIC=0, Base=0
        for (name, value) in fields {
            // Literal Field Line With Literal Name, both strings non-Huffman.
            qpack_int(&mut block, 0x20, 3, name.len() as u64);
            block.extend_from_slice(name);
            qpack_int(&mut block, 0, 7, value.len() as u64);
            block.extend_from_slice(value);
        }
        block
    }

    fn request_from_raw_qpack(fields: &[(&[u8], &[u8])]) -> Option<http::Request<()>> {
        let decoded = qpack_decode(&literal_qpack_fields(fields))?;
        let head = split_h3_request_headers(decoded)?;
        let builder = build_h3_request_head(head)?;
        builder.body(()).ok()
    }

    #[test]
    fn raw_qpack_request_head_requires_authority_or_host() {
        let pseudo = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
        ];
        assert!(
            request_from_raw_qpack(&pseudo).is_none(),
            "RFC 9114 4.3.1: neither :authority nor Host is malformed"
        );
        let mut with_host = pseudo.to_vec();
        with_host.push((b"host".as_slice(), b"a.test".as_slice()));
        let req = request_from_raw_qpack(&with_host).expect("Host alone suffices");
        assert_eq!(req.headers()[http::header::HOST], "a.test");
        let mut with_authority = pseudo.to_vec();
        with_authority.push((b":authority".as_slice(), b"a.test".as_slice()));
        let req = request_from_raw_qpack(&with_authority).expect(":authority alone suffices");
        assert_eq!(req.headers()[http::header::HOST], "a.test");
    }

    #[test]
    fn raw_qpack_request_head_rejects_malformed_path_authority_and_host() {
        let request = |method: &'static [u8], path: &'static [u8], authority: &'static [u8]| {
            [
                (b":method".as_slice(), method),
                (b":scheme".as_slice(), b"https".as_slice()),
                (b":path".as_slice(), path),
                (b":authority".as_slice(), authority),
            ]
        };
        assert!(
            request_from_raw_qpack(&request(b"GET", b"/safe#ignored", b"example.com")).is_none()
        );
        // (#587) Network-path :path must not smuggle its own authority.
        assert!(
            request_from_raw_qpack(&request(b"GET", b"//evil.example/x", b"example.com")).is_none()
        );
        assert!(request_from_raw_qpack(&request(b"GET", b"*", b"example.com")).is_none());
        for authority in [
            b"bad host".as_slice(),
            b"host/path".as_slice(),
            b"[::1".as_slice(),
            b"example.com:abc".as_slice(),
            b"user@example.com".as_slice(),
            b":443".as_slice(),
        ] {
            assert!(request_from_raw_qpack(&request(b"GET", b"/", authority)).is_none());
        }

        let duplicate_host = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
            (b"host".as_slice(), b"example.com".as_slice()),
            (b"host".as_slice(), b"example.com".as_slice()),
        ];
        assert!(request_from_raw_qpack(&duplicate_host).is_none());
        let conflicting_host = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
            (b":authority".as_slice(), b"good.example".as_slice()),
            (b"host".as_slice(), b"evil.example".as_slice()),
        ];
        assert!(request_from_raw_qpack(&conflicting_host).is_none());

        for host in [
            b"bad host".as_slice(),
            b"user@example.com".as_slice(),
            b"example.com:abc".as_slice(),
            b":443".as_slice(),
        ] {
            let host_only = [
                (b":method".as_slice(), b"GET".as_slice()),
                (b":scheme".as_slice(), b"https".as_slice()),
                (b":path".as_slice(), b"/".as_slice()),
                (b"host".as_slice(), host),
            ];
            assert!(request_from_raw_qpack(&host_only).is_none(), "{host:?}");
        }
    }

    #[test]
    fn raw_qpack_request_head_keeps_valid_asterisk_ipv6_and_matching_host() {
        let options = [
            (b":method".as_slice(), b"OPTIONS".as_slice()),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":path".as_slice(), b"*".as_slice()),
            (b":authority".as_slice(), b"[2001:db8::1]:8443".as_slice()),
            (b"host".as_slice(), b"[2001:db8::1]:8443".as_slice()),
        ];
        let req = request_from_raw_qpack(&options).expect("valid OPTIONS asterisk request");
        assert_eq!(req.method(), http::Method::OPTIONS);
        assert_eq!(req.uri(), "*");
        assert_eq!(req.headers()[http::header::HOST], "[2001:db8::1]:8443");
    }

    #[test]
    fn raw_qpack_trailers_validate_generic_field_syntax_before_discard() {
        let valid = literal_qpack_fields(&[(b"x-trailer", b"ok")]);
        assert!(valid_h3_trailers(&valid, 4096));
        for invalid in [
            literal_qpack_fields(&[(b"bad name", b"value")]),
            literal_qpack_fields(&[(b"X-Bad", b"value")]),
            literal_qpack_fields(&[(b"x-bad", b"nul\0value")]),
            literal_qpack_fields(&[(b"te", b"gzip")]),
        ] {
            assert!(!valid_h3_trailers(&invalid, 4096));
        }
    }

    #[test]
    fn split_cookie_fields_are_coalesced_before_dispatch() {
        let mut req = http::Request::builder()
            .header(http::header::COOKIE, "xf_session=abc")
            .header(http::header::COOKIE, "xf_user=42")
            .body(())
            .unwrap();
        hj_core::coalesce_cookie_crumbs(req.headers_mut());
        let values: Vec<_> = req.headers().get_all(http::header::COOKIE).iter().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "xf_session=abc; xf_user=42");
    }

    // Response encode round-trips through the request parser/decoder (responses are also
    // HEADERS+DATA with a QPACK field section), proving the encoder's framing + literals.
    #[test]
    fn encode_response_roundtrip() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        headers.insert(http::header::CONNECTION, "keep-alive".parse().unwrap()); // must be stripped
        prepare_h3_response_headers(&mut headers, false, http::StatusCode::OK, false);
        let enc = encode_h3_response(http::StatusCode::OK, &headers, b"hi");
        let parsed = parse_h3_request(enc).expect("parse response");
        assert_eq!(parsed.body.as_ref(), b"hi");
        let hdrs = qpack_decode(&parsed.field).expect("decode response");
        assert!(hdrs.contains(&(b":status".to_vec(), b"200".to_vec())));
        assert!(hdrs.contains(&(b"content-type".to_vec(), b"text/plain".to_vec())));
        assert!(!hdrs.iter().any(|(n, _)| n == b"connection")); // hop-by-hop stripped
    }

    #[test]
    fn response_sanitizer_removes_connection_nominated_fields_and_te() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONNECTION, "x-remove".parse().unwrap());
        headers.insert(http::header::TE, "trailers".parse().unwrap());
        headers.insert("x-remove", "secret".parse().unwrap());
        headers.insert("x-keep", "ok".parse().unwrap());
        prepare_h3_response_headers(&mut headers, false, http::StatusCode::OK, false);
        assert!(!headers.contains_key(http::header::CONNECTION));
        assert!(!headers.contains_key(http::header::TE));
        assert!(!headers.contains_key("x-remove"));
        assert_eq!(headers.get("x-keep").unwrap(), "ok");
    }

    #[test]
    fn body_forbidden_statuses_and_head_encode_no_data() {
        for (is_head, status) in [
            (true, http::StatusCode::OK),
            (false, http::StatusCode::NO_CONTENT),
            (false, http::StatusCode::RESET_CONTENT),
            (false, http::StatusCode::NOT_MODIFIED),
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::CONTENT_LENGTH, "7".parse().unwrap());
            let forbidden = prepare_h3_response_headers(&mut headers, is_head, status, false);
            assert!(forbidden);
            let wire =
                encode_h3_response(status, &headers, if forbidden { b"" } else { b"payload" });
            assert!(parse_h3_request(wire).unwrap().body.is_empty());
            if !is_head {
                assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
            }
        }
    }

    #[test]
    fn streamed_multi_data_frames_are_wire_equal_to_buffered() {
        // The streaming path emits a HEADERS frame then one DATA frame per chunk; the
        // buffered path emits HEADERS + one DATA frame for the whole body. Reassembled,
        // they must be byte-identical — that is what makes streaming safe.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/octet-stream".parse().unwrap(),
        );
        let chunks: [&[u8]; 3] = [b"chunk-one ", b"chunk-two ", b"chunk-three"];

        // Streaming wire bytes: head + per-chunk DATA frames.
        let mut streamed = encode_h3_headers_frame(http::StatusCode::OK, &headers);
        for c in &chunks {
            encode_h3_data_frame(&mut streamed, c);
        }

        // Buffered wire bytes: one DATA frame for the concatenated body.
        let full: Vec<u8> = chunks.concat();
        let buffered = encode_h3_response(http::StatusCode::OK, &headers, &full);

        // Both reassemble (via the frame parser) to the same headers + body.
        let streamed = parse_h3_request(streamed).expect("parse streamed");
        let buffered = parse_h3_request(buffered).expect("parse buffered");
        assert_eq!(
            streamed.body.as_ref(),
            full.as_slice(),
            "streamed body must reassemble to the whole body"
        );
        assert_eq!(
            streamed.body, buffered.body,
            "streamed vs buffered body mismatch"
        );
        assert_eq!(
            qpack_decode(&streamed.field),
            qpack_decode(&buffered.field),
            "header sections must match"
        );
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::sync::atomic::Ordering::Relaxed;

    const SERVER: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 4433);

    fn spoofed(i: u16) -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, (i % 250) as u8 + 1)),
            10_000 + i,
        )
    }

    struct Harness {
        server: Endpoint,
        server_config: Arc<ServerConfig>,
        client: Endpoint,
        client_config: quinn_proto::ClientConfig,
        runtime: H3RuntimeConfig,
        active: Arc<AtomicU64>,
        handshakes: Arc<AtomicU64>,
        scratch: Vec<u8>,
    }

    impl Harness {
        fn new(max_connections: u32) -> Self {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let certified =
                rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
            let key =
                rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                    .unwrap();
            let mut server_tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key)
                .unwrap();
            server_tls.alpn_protocols = vec![b"h3".to_vec()];
            server_tls.max_early_data_size = 0;
            let server_config = Arc::new(server_config(Arc::new(server_tls)).unwrap());
            let server = Endpoint::new(
                Arc::new(EndpointConfig::default()),
                Some(server_config.clone()),
                true,
                None,
            );
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            let mut client_tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client_tls.alpn_protocols = vec![b"h3".to_vec()];
            let client_config = quinn_proto::ClientConfig::new(Arc::new(
                quinn_proto::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls))
                    .unwrap(),
            ));
            let client = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
            let active = Arc::new(AtomicU64::new(0));
            let runtime = H3RuntimeConfig::new(
                move || {
                    (
                        H3RequestConfig::new(H3RequestLimits::new(1024, 1024), None),
                        max_connections,
                    )
                },
                active.clone(),
                Arc::new(hj_core::budget::BodyBufferBudget::new(1 << 20)),
            );
            Self {
                server,
                server_config,
                client,
                client_config,
                runtime,
                active,
                handshakes: Arc::new(AtomicU64::new(0)),
                scratch: Vec::new(),
            }
        }

        fn policy(&self) -> QuicServerPolicy {
            QuicServerPolicy {
                config: self.server_config.clone(),
                serving_view: None,
                client_auth: crate::uring::ClientAuth::None,
            }
        }

        fn connect(&mut self, now: Instant) -> (ConnectionHandle, quinn_proto::Connection) {
            self.client
                .connect(now, self.client_config.clone(), SERVER, "localhost")
                .unwrap()
        }

        fn first_datagram(conn: &mut quinn_proto::Connection, now: Instant) -> Vec<u8> {
            let mut buf = Vec::new();
            let transmit = conn
                .poll_transmit(now, 1, &mut buf)
                .expect("client Initial");
            buf.truncate(transmit.size);
            buf
        }

        fn incoming(
            &mut self,
            from: SocketAddr,
            datagram: &[u8],
            now: Instant,
        ) -> quinn_proto::Incoming {
            self.scratch.clear();
            match self.server.handle(
                now,
                from,
                None,
                None,
                BytesMut::from(datagram),
                &mut self.scratch,
            ) {
                Some(DatagramEvent::NewConnection(incoming)) => incoming,
                _ => panic!("expected a new connection"),
            }
        }

        fn admit(&mut self, incoming: quinn_proto::Incoming, now: Instant) -> Admission {
            self.scratch.clear();
            admit_incoming(
                &mut self.server,
                incoming,
                now,
                &mut self.scratch,
                true,
                &self.runtime,
                &self.handshakes,
            )
        }

        /// Exchange datagrams until the server reports the handshake outcome.
        fn drive_handshake(
            &mut self,
            conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
            h3: &mut HashMap<ConnectionHandle, H3State>,
            hd: ConnectionHandle,
            client_handle: ConnectionHandle,
            client: &mut quinn_proto::Connection,
            client_addr: SocketAddr,
            now: Instant,
        ) {
            let config = H3RequestConfig::new(H3RequestLimits::new(1024, 1024), None);
            for _ in 0..64 {
                service_conn(&mut self.server, conns, h3, hd, now, true, config);
                if h3[&hd].connected || h3[&hd].rejected {
                    return;
                }
                self.to_client(conns.get_mut(&hd).unwrap(), client_handle, client, now);
                while client.poll().is_some() {}
                self.to_server(conns, client, client_addr, now);
            }
            panic!("handshake did not finish");
        }

        /// Deliver every datagram the server connection has queued to the client.
        fn to_client(
            &mut self,
            server: &mut quinn_proto::Connection,
            client_handle: ConnectionHandle,
            client: &mut quinn_proto::Connection,
            now: Instant,
        ) {
            let mut buf = Vec::new();
            let mut scratch = Vec::new();
            loop {
                buf.clear();
                let Some(transmit) = server.poll_transmit(now, 1, &mut buf) else {
                    break;
                };
                scratch.clear();
                if let Some(DatagramEvent::ConnectionEvent(_, event)) = self.client.handle(
                    now,
                    SERVER,
                    None,
                    None,
                    BytesMut::from(&buf[..transmit.size]),
                    &mut scratch,
                ) {
                    client.handle_event(event);
                }
            }
            while let Some(event) = client.poll_endpoint_events() {
                if let Some(event) = self.client.handle_event(client_handle, event) {
                    client.handle_event(event);
                }
            }
        }

        /// Deliver every datagram the client has queued to the server.
        fn to_server(
            &mut self,
            conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
            client: &mut quinn_proto::Connection,
            client_addr: SocketAddr,
            now: Instant,
        ) {
            let mut buf = Vec::new();
            let mut scratch = Vec::new();
            loop {
                buf.clear();
                let Some(transmit) = client.poll_transmit(now, 1, &mut buf) else {
                    break;
                };
                scratch.clear();
                if let Some(DatagramEvent::ConnectionEvent(handle, event)) = self.server.handle(
                    now,
                    client_addr,
                    None,
                    None,
                    BytesMut::from(&buf[..transmit.size]),
                    &mut scratch,
                ) {
                    conns.get_mut(&handle).unwrap().handle_event(event);
                }
            }
        }

        /// Accept one client from `client_addr` and complete its handshake.
        fn establish(&mut self, client_addr: SocketAddr, now: Instant) -> Established {
            let policy = self.policy();
            let (client_handle, mut client) = self.connect(now);
            let initial = Self::first_datagram(&mut client, now);
            let incoming = self.incoming(client_addr, &initial, now);
            let Admission::Accepted(hd, conn, slot) = self.admit(incoming, now) else {
                panic!("an idle server accepts the connection");
            };
            let mut conns = HashMap::from([(hd, conn)]);
            let mut h3 = HashMap::from([(
                hd,
                self.runtime
                    .accepted_state_with_policy(slot, now, 1, &policy),
            )]);
            self.drive_handshake(
                &mut conns,
                &mut h3,
                hd,
                client_handle,
                &mut client,
                client_addr,
                now,
            );
            assert!(h3[&hd].connected);
            Established {
                conns,
                h3,
                hd,
                client_handle,
                client,
            }
        }
    }

    struct Established {
        conns: HashMap<ConnectionHandle, quinn_proto::Connection>,
        h3: HashMap<ConnectionHandle, H3State>,
        hd: ConnectionHandle,
        client_handle: ConnectionHandle,
        client: quinn_proto::Connection,
    }

    #[test]
    fn server_does_not_advertise_quic_datagrams() {
        let mut h = Harness::new(65_000);
        let mut e = h.establish(spoofed(5), Instant::now());
        assert_eq!(
            e.client.datagrams().max_size(),
            None,
            "max_datagram_frame_size must not be advertised without RFC 9297 support"
        );
        assert!(matches!(
            e.client.datagrams().send(Bytes::from_static(b"x"), true),
            Err(quinn_proto::SendDatagramError::UnsupportedByPeer)
        ));
    }

    #[test]
    fn recv_drain_hands_quinn_owned_copies_of_each_datagram() {
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let policy = h.policy();
        let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let udp_state = UdpSocketState::new(UdpSockRef::from(&server_sock)).unwrap();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_, mut client) = h
            .client
            .connect(now, h.client_config.clone(), server_addr, "localhost")
            .unwrap();
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let Some(transmit) = client.poll_transmit(now, 1, &mut buf) else {
                break;
            };
            client_sock
                .send_to(&buf[..transmit.size], server_addr)
                .unwrap();
        }
        let mut slots = recv_slots();
        let bases: Vec<*const u8> = slots.iter().map(|slot| slot.as_ptr()).collect();
        let mut metas = [quinn_udp::RecvMeta::default(); GRO_BATCH];
        let mut scratch = Vec::new();
        let mut conns = HashMap::new();
        let mut h3 = HashMap::new();
        let mut deadlines = ConnectionDeadlineIndex::default();
        let mut epoch = 0;
        let mut rt = crate::uring::build_core_runtime().unwrap();
        let affected = rt.block_on(async {
            let udp = UdpSocket::from_std(server_sock).unwrap();
            recv_drain(
                &udp,
                &udp_state,
                &mut slots,
                &mut metas,
                &mut scratch,
                &mut h.server,
                &mut conns,
                &mut h3,
                &mut deadlines,
                &mut epoch,
                &h.handshakes,
                &h.runtime,
                &policy,
                true,
                now,
            )
            .await
        });
        assert_eq!(
            affected.len(),
            1,
            "the client's Initial opened a connection"
        );
        assert_eq!(conns.len(), 1);
        let after: Vec<*const u8> = slots.iter().map(|slot| slot.as_ptr()).collect();
        assert_eq!(bases, after, "recv slots are reused in place");
        assert!(slots.iter().all(|slot| slot.len() == MAX_DATAGRAM));
    }

    #[test]
    fn flush_conn_follows_quinn_udp_disabling_segmentation_offload() {
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sink.set_nonblocking(true).unwrap();
        let sink_addr = sink.local_addr().unwrap();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        // The kernel refuses UDP GSO on a socket that sends without checksums
        // (EINVAL), the failure shape of a route or NIC without segmentation offload.
        let one: libc::c_int = 1;
        // SAFETY: `sock` owns a live fd; the option value is a c_int of the stated size.
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NO_CHECK,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0);
        let udp_state = UdpSocketState::new(UdpSockRef::from(&sock)).unwrap();
        let at_startup = udp_state.max_gso_segments();
        if at_startup < 2 {
            eprintln!("skipped: this kernel has no UDP GSO");
            return;
        }
        assert_eq!(tx_segment_cap(&udp_state), at_startup.min(MAX_TX_SEGMENTS));
        let probe = [0u8; 2400];
        let segmented = UdpTransmit {
            destination: sink_addr,
            ecn: None,
            contents: &probe,
            segment_size: Some(1200),
            src_ip: None,
        };
        assert!(
            udp_state
                .try_send(UdpSockRef::from(&sock), &segmented)
                .is_err()
        );
        assert_eq!(udp_state.max_gso_segments(), 1, "quinn-udp halted GSO");
        assert_eq!(tx_segment_cap(&udp_state), 1);

        // A connection with many datagrams queued must still reach its peer.
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let mut e = h.establish(sink_addr, now);
        let conn = e.conns.get_mut(&e.hd).unwrap();
        let id = conn.streams().open(Dir::Uni).unwrap();
        let written = conn.send_stream(id).write(&[0x5a; 16 * 1024]).unwrap();
        assert!(written > 4 * 1200);
        let mut tbuf = Vec::new();
        let mut rt = crate::uring::build_core_runtime().unwrap();
        rt.block_on(async {
            let udp = UdpSocket::from_std(sock).unwrap();
            flush_conn(&udp, &udp_state, &mut e.conns, e.hd, now, &mut tbuf).await;
        });
        let mut received = 0;
        let mut datagram = [0u8; MAX_DATAGRAM];
        while let Ok(n) = sink.recv(&mut datagram) {
            assert!(n <= 1500, "a {n}-byte receive was not a single datagram");
            received += 1;
        }
        assert!(
            received >= 2,
            "only {received} datagrams arrived: transmits kept requesting GSO"
        );
    }

    fn read_response(conn: &mut quinn_proto::Connection, id: StreamId) -> Result<Vec<u8>, u64> {
        let mut stream = conn.recv_stream(id);
        let mut chunks = stream.read(true).expect("the response stream is readable");
        let mut body = Vec::new();
        let end = loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => body.extend_from_slice(&chunk.bytes),
                Ok(None) => break Ok(()),
                Err(quinn_proto::ReadError::Reset(code)) => break Err(code.into_inner()),
                Err(quinn_proto::ReadError::Blocked) => panic!("the response did not finish"),
            }
        };
        let _ = chunks.finalize();
        end.map(|()| body)
    }

    #[test]
    fn oversized_and_overrunning_uploads_are_refused_like_h1_and_h2() {
        use super::h3_codec_tests::{UPLOAD_HEAD, request_stream};
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let addr = spoofed(11);
        let mut e = h.establish(addr, now);
        let with_length = |length: &'static [u8]| {
            let mut fields = UPLOAD_HEAD.to_vec();
            fields.push((b"content-length", length));
            fields
        };
        // The harness accepts request streams with 1024-byte header and body caps.
        let requests = [
            (request_stream(&with_length(b"5000"), &[100]), false),
            (request_stream(&with_length(b"10"), &[11]), false),
            (request_stream(&UPLOAD_HEAD, &[600, 600]), false),
            (request_stream(&with_length(b"4"), &[4]), true),
        ];
        let ids: Vec<StreamId> = requests
            .iter()
            .map(|(wire, fin)| {
                let id = e.client.streams().open(Dir::Bi).unwrap();
                let mut send = e.client.send_stream(id);
                assert_eq!(send.write(wire).unwrap(), wire.len());
                if *fin {
                    send.finish().unwrap();
                }
                id
            })
            .collect();
        h.to_server(&mut e.conns, &mut e.client, addr, now);
        let config = H3RequestConfig::new(H3RequestLimits::new(1024, 1024), None);
        service_conn(
            &mut h.server,
            &mut e.conns,
            &mut e.h3,
            e.hd,
            now,
            true,
            config,
        );
        let st = e.h3.get_mut(&e.hd).unwrap();
        let conn = e.conns.get_mut(&e.hd).unwrap();
        assert_eq!(receive_request_streams(conn, st, now), vec![ids[3]]);
        assert!(
            st.req_frames
                .get(&ids[3])
                .and_then(H3FrameCounter::decoded_head)
                .is_some(),
            "the accepted upload carries its decoded head to dispatch"
        );
        for id in &ids[..3] {
            assert!(!st.requests.contains(id) && !st.req_buf.contains_key(id));
        }
        assert!(st.pending.is_empty(), "each 413 was written whole");
        h.to_client(conn, e.client_handle, &mut e.client, now);

        let mut stopped = HashMap::new();
        while let Some(event) = e.client.poll() {
            if let Event::Stream(StreamEvent::Stopped { id, error_code }) = event {
                stopped.insert(id, error_code.into_inner());
            }
        }
        let too_large = h3_payload_too_large();
        let no_error = u64::from(H3_NO_ERROR);
        let message_error = u64::from(H3_MESSAGE_ERROR);
        assert_eq!(read_response(&mut e.client, ids[0]), Ok(too_large.clone()));
        assert_eq!(stopped.get(&ids[0]), Some(&no_error));
        assert_eq!(read_response(&mut e.client, ids[1]), Err(message_error));
        assert_eq!(stopped.get(&ids[1]), Some(&message_error));
        assert_eq!(read_response(&mut e.client, ids[2]), Ok(too_large));
        assert_eq!(stopped.get(&ids[2]), Some(&no_error));
        assert!(!stopped.contains_key(&ids[3]));
    }

    /// An over-limit header section gets a complete 431 and STOP_SENDING(H3_NO_ERROR), as
    /// H1 and H2 answer, not a stream reset the browser reports as a network error.
    #[test]
    fn oversized_request_headers_are_answered_431() {
        use super::h3_codec_tests::request_stream;
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let addr = spoofed(12);
        let mut e = h.establish(addr, now);
        let big = vec![b'a'; 2000];
        let mut fields = GET_HEAD.to_vec();
        fields.push((b"x-big", &big));
        let wire = request_stream(&fields, &[]);
        let id = e.client.streams().open(Dir::Bi).unwrap();
        // Left open, like an upload still in flight: STOP_SENDING tells it to stop.
        let mut send = e.client.send_stream(id);
        assert_eq!(send.write(&wire).unwrap(), wire.len());
        h.to_server(&mut e.conns, &mut e.client, addr, now);
        let config = H3RequestConfig::new(H3RequestLimits::new(1024, 1024), None);
        service_conn(
            &mut h.server,
            &mut e.conns,
            &mut e.h3,
            e.hd,
            now,
            true,
            config,
        );
        let st = e.h3.get_mut(&e.hd).unwrap();
        let conn = e.conns.get_mut(&e.hd).unwrap();
        assert!(receive_request_streams(conn, st, now).is_empty());
        assert!(st.pending.is_empty(), "the 431 was written whole");
        h.to_client(conn, e.client_handle, &mut e.client, now);
        let mut stopped = None;
        while let Some(event) = e.client.poll() {
            if let Event::Stream(StreamEvent::Stopped {
                id: stream,
                error_code,
            }) = event
                && stream == id
            {
                stopped = Some(error_code.into_inner());
            }
        }
        assert_eq!(
            read_response(&mut e.client, id),
            Ok(h3_error(http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE))
        );
        assert_eq!(stopped, Some(u64::from(H3_NO_ERROR)));
    }

    const GET_HEAD: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"churn.test"),
        (b":path", b"/"),
    ];

    /// The application error code the client saw the server close with, if it has.
    fn client_close_code(client: &mut quinn_proto::Connection) -> Option<u64> {
        let mut code = None;
        while let Some(event) = client.poll() {
            if let Event::ConnectionLost {
                reason: quinn_proto::ConnectionError::ApplicationClosed(close),
            } = event
            {
                code = Some(close.error_code.into_inner());
            }
        }
        code
    }

    /// Drive one server pass in `drive_one_conn`'s order and return the request
    /// streams that reached dispatch.
    fn serve_pass(h: &mut Harness, e: &mut Established, now: Instant) -> Vec<StreamId> {
        let config = H3RequestConfig::new(H3RequestLimits::new(1024, 1024), None);
        service_conn(
            &mut h.server,
            &mut e.conns,
            &mut e.h3,
            e.hd,
            now,
            true,
            config,
        );
        let st = e.h3.get_mut(&e.hd).unwrap();
        if st.rejected {
            return Vec::new();
        }
        let conn = e.conns.get_mut(&e.hd).unwrap();
        receive_request_streams(conn, st, now)
    }

    #[test]
    fn stop_sending_with_its_request_is_never_dispatched_and_churn_closes() {
        use super::h3_codec_tests::request_stream;
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let addr = spoofed(21);
        let mut e = h.establish(addr, now);
        let wire = request_stream(&GET_HEAD, &[]);
        let mut rounds = 0;
        let mut close_code = None;
        while close_code.is_none() && rounds < 2000 {
            rounds += 1;
            // Request, FIN and STOP_SENDING all reach the server in one flight.
            let id = e.client.streams().open(Dir::Bi).expect("stream credit");
            let mut send = e.client.send_stream(id);
            assert_eq!(send.write(&wire).unwrap(), wire.len());
            send.finish().unwrap();
            e.client
                .recv_stream(id)
                .stop(quinn_proto::VarInt::from_u32(H3_REQUEST_CANCELLED))
                .unwrap();
            h.to_server(&mut e.conns, &mut e.client, addr, now);
            let dispatched = serve_pass(&mut h, &mut e, now);
            assert!(
                dispatched.is_empty(),
                "round {rounds}: a stopped stream was dispatched without a cancellation token"
            );
            let st = &e.h3[&e.hd];
            assert!(!st.requests.contains(&id) && st.request_cancellations.is_empty());
            h.to_client(
                e.conns.get_mut(&e.hd).unwrap(),
                e.client_handle,
                &mut e.client,
                now,
            );
            close_code = client_close_code(&mut e.client);
        }
        assert_eq!(close_code, Some(u64::from(H3_EXCESSIVE_LOAD)));
        assert_eq!(rounds, H3_CANCEL_BURST as usize + 1);
        assert!(e.h3[&e.hd].rejected);
    }

    #[test]
    fn cancelling_dispatched_requests_exhausts_a_budget_completions_never_refund() {
        use super::h3_codec_tests::request_stream;
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let addr = spoofed(22);
        let mut e = h.establish(addr, now);
        const COMPLETED: usize = 50;
        let wire = request_stream(&GET_HEAD, &[]);
        let mut tokens = Vec::new();
        let mut close_code = None;
        let mut rounds = 0;
        while close_code.is_none() && rounds < 2000 {
            rounds += 1;
            let id = e.client.streams().open(Dir::Bi).expect("stream credit");
            let mut send = e.client.send_stream(id);
            assert_eq!(send.write(&wire).unwrap(), wire.len());
            send.finish().unwrap();
            // Requests the same client lets complete must not buy back budget. The
            // harness never advances time, so total streams stay within one credit.
            let completed = (rounds <= COMPLETED).then(|| {
                let completed = e.client.streams().open(Dir::Bi).expect("stream credit");
                let mut send = e.client.send_stream(completed);
                assert_eq!(send.write(&wire).unwrap(), wire.len());
                send.finish().unwrap();
                completed
            });
            h.to_server(&mut e.conns, &mut e.client, addr, now);
            let mut dispatched = serve_pass(&mut h, &mut e, now);
            dispatched.sort();
            assert_eq!(
                dispatched,
                [Some(id), completed]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
            );
            let st = e.h3.get_mut(&e.hd).unwrap();
            for stream in dispatched {
                drop(take_request_for_dispatch(st, stream));
                let token = CancellationToken::new();
                st.request_cancellations.insert(stream, token.clone());
                tokens.push(token);
            }
            if let Some(completed) = completed {
                st.request_cancellations.remove(&completed);
                let conn = e.conns.get_mut(&e.hd).unwrap();
                let mut response = conn.send_stream(completed);
                response.write(&h3_error(http::StatusCode::OK)).unwrap();
                response.finish().unwrap();
            }

            e.client
                .recv_stream(id)
                .stop(quinn_proto::VarInt::from_u32(H3_REQUEST_CANCELLED))
                .unwrap();
            h.to_server(&mut e.conns, &mut e.client, addr, now);
            serve_pass(&mut h, &mut e, now);
            assert!(!e.h3[&e.hd].request_cancellations.contains_key(&id));
            h.to_client(
                e.conns.get_mut(&e.hd).unwrap(),
                e.client_handle,
                &mut e.client,
                now,
            );
            close_code = client_close_code(&mut e.client);
        }
        assert_eq!(close_code, Some(u64::from(H3_EXCESSIVE_LOAD)));
        assert_eq!(rounds, H3_CANCEL_BURST as usize + 1);
        // The completed requests' tokens were retired before the close.
        assert_eq!(
            tokens.iter().filter(|t| t.is_cancelled()).count(),
            tokens.len() - COMPLETED,
            "every cancelled request's work was cancelled"
        );
    }

    #[test]
    fn empty_data_flood_closes_the_connection_with_excessive_load() {
        use super::h3_codec_tests::{UPLOAD_HEAD, request_stream};
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let addr = spoofed(23);
        let mut e = h.establish(addr, now);
        let mut wire = request_stream(&UPLOAD_HEAD, &[]);
        for _ in 0..=H3_NO_PROGRESS_FRAMES {
            wire.extend_from_slice(&[0x00, 0x00]);
        }
        let id = e.client.streams().open(Dir::Bi).unwrap();
        let mut send = e.client.send_stream(id);
        assert_eq!(send.write(&wire).unwrap(), wire.len());
        // The client's congestion window spreads the stream over several flights.
        let mut close_code = None;
        for _ in 0..64 {
            h.to_server(&mut e.conns, &mut e.client, addr, now);
            assert!(serve_pass(&mut h, &mut e, now).is_empty());
            h.to_client(
                e.conns.get_mut(&e.hd).unwrap(),
                e.client_handle,
                &mut e.client,
                now,
            );
            close_code = client_close_code(&mut e.client);
            if close_code.is_some() {
                break;
            }
        }
        assert_eq!(close_code, Some(u64::from(H3_EXCESSIVE_LOAD)));
        let st = &e.h3[&e.hd];
        assert!(st.rejected && st.requests.is_empty() && st.total_req_bytes.get() == 0);
    }

    #[test]
    fn a_receive_pass_reads_only_streams_with_new_data() {
        use super::h3_codec_tests::{UPLOAD_HEAD, request_stream};
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let addr = spoofed(24);
        let mut e = h.establish(addr, now);
        let head = request_stream(&UPLOAD_HEAD, &[]);
        let ids: Vec<StreamId> = (0..MAX_CONCURRENT_BIDI_STREAMS)
            .map(|_| {
                let id = e.client.streams().open(Dir::Bi).unwrap();
                assert_eq!(e.client.send_stream(id).write(&head).unwrap(), head.len());
                id
            })
            .collect();
        let config = H3RequestConfig::new(H3RequestLimits::new(1024, 1024), None);
        let mut accepted = 0;
        for _ in 0..64 {
            h.to_server(&mut e.conns, &mut e.client, addr, now);
            service_conn(
                &mut h.server,
                &mut e.conns,
                &mut e.h3,
                e.hd,
                now,
                true,
                config,
            );
            let st = e.h3.get_mut(&e.hd).unwrap();
            accepted = st.requests.len();
            let conn = e.conns.get_mut(&e.hd).unwrap();
            assert!(receive_request_streams(conn, st, now).is_empty());
            assert!(st.readable_requests.is_empty());
            h.to_client(conn, e.client_handle, &mut e.client, now);
            if accepted == ids.len() {
                break;
            }
        }
        assert_eq!(accepted, ids.len(), "every unfinished stream is tracked");

        // Two separate STREAM frames for one stream, then its FIN: one queued read.
        let target = ids[ids.len() / 2];
        for piece in [&[0x00, 0x02, b'o'][..], b"k"] {
            assert_eq!(
                e.client.send_stream(target).write(piece).unwrap(),
                piece.len()
            );
            h.to_server(&mut e.conns, &mut e.client, addr, now);
        }
        e.client.send_stream(target).finish().unwrap();
        h.to_server(&mut e.conns, &mut e.client, addr, now);
        service_conn(
            &mut h.server,
            &mut e.conns,
            &mut e.h3,
            e.hd,
            now,
            true,
            config,
        );
        let st = e.h3.get_mut(&e.hd).unwrap();
        assert_eq!(st.readable_requests, vec![target]);
        let conn = e.conns.get_mut(&e.hd).unwrap();
        assert_eq!(receive_request_streams(conn, st, now), vec![target]);
        assert_eq!(st.req_buf[&target], b"ok");
        assert!(st.readable_requests.is_empty());
        assert!(st.request_snapshots.values().all(|s| !s.read_queued));
    }

    #[test]
    fn quic_timers_share_the_connection_deadline_index() {
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let mut e = h.establish(spoofed(25), now);
        let quic = e.conns.get_mut(&e.hd).unwrap().poll_timeout();
        assert!(
            quic.is_some(),
            "an established connection arms its idle timer"
        );
        let mut deadlines = ConnectionDeadlineIndex::default();
        deadlines.sync(e.hd, connection_deadline(&mut e.conns, &e.h3, e.hd));
        assert_eq!(deadlines.next(), quic);

        // An earlier HTTP/3 deadline takes over the connection's single node.
        let request = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let timeout = Duration::from_millis(1);
        e.h3.get_mut(&e.hd).unwrap().track_request_stream(
            request,
            now,
            H3RequestSnapshot::unscoped(H3RequestConfig::new(
                H3RequestLimits::new(16, 16),
                Some(timeout),
            )),
        );
        deadlines.sync(e.hd, connection_deadline(&mut e.conns, &e.h3, e.hd));
        assert_eq!(deadlines.next(), Some(now + timeout));
        assert_eq!(deadlines.ordered.len(), 1);

        // Once that deadline is gone the QUIC timer is due on its own.
        reclaim_request(e.h3.get_mut(&e.hd).unwrap(), request);
        deadlines.sync(e.hd, connection_deadline(&mut e.conns, &e.h3, e.hd));
        assert_eq!(deadlines.next(), quic);
        let mut due = std::collections::HashSet::new();
        deadlines.extend_due(&mut due, quic.unwrap());
        assert_eq!(due, std::collections::HashSet::from([e.hd]));

        e.conns.clear();
        e.h3.clear();
        deadlines.sync(e.hd, connection_deadline(&mut e.conns, &e.h3, e.hd));
        assert!(deadlines.ordered.is_empty() && deadlines.by_connection.is_empty());
    }

    /// (#1035) How a paced H3 upload ended, measured from stream acceptance on the
    /// harness's virtual clock.
    #[derive(Debug)]
    enum PacedUpload {
        /// FIN reached with every byte buffered: the request goes to dispatch.
        Finished(Duration, usize),
        /// The receive deadline expired; `drive_one_conn` resets both halves.
        Expired(Duration),
    }

    /// Upload `total` body bytes on one request stream, `chunk` bytes every `gap` of
    /// virtual time, driving the server in `drive_one_conn`'s order (expire, then
    /// receive) under `config`.
    fn paced_h3_upload(
        config: H3RequestConfig,
        chunk: usize,
        gap: Duration,
        total: usize,
    ) -> PacedUpload {
        use super::h3_codec_tests::{UPLOAD_HEAD, request_stream};
        let mut h = Harness::new(65_000);
        let start = Instant::now();
        let addr = spoofed(40);
        let mut e = h.establish(addr, start);
        let length = total.to_string();
        let mut fields = UPLOAD_HEAD.to_vec();
        fields.push((b"content-length", length.as_bytes()));
        let wire = request_stream(&fields, &[total]);
        let head = wire.len() - total;
        let id = e.client.streams().open(Dir::Bi).unwrap();
        let mut written = 0;
        let mut finished = false;
        let mut accepted = None;
        let mut now = start;
        while now - start < Duration::from_secs(120) {
            let chunks = ((now - start).as_nanos() / gap.as_nanos()) as usize + 1;
            let goal = (head + chunks * chunk).min(wire.len());
            let mut send = e.client.send_stream(id);
            while written < goal {
                match send.write(&wire[written..goal]) {
                    Ok(n) if n > 0 => written += n,
                    _ => break,
                }
            }
            if written == wire.len() && !finished {
                send.finish().unwrap();
                finished = true;
            }
            if e.client.poll_timeout().is_some_and(|t| t <= now) {
                e.client.handle_timeout(now);
            }
            h.to_server(&mut e.conns, &mut e.client, addr, now);
            if let Some(conn) = e.conns.get_mut(&e.hd)
                && conn.poll_timeout().is_some_and(|t| t <= now)
            {
                conn.handle_timeout(now);
            }
            service_conn(
                &mut h.server,
                &mut e.conns,
                &mut e.h3,
                e.hd,
                now,
                true,
                config,
            );
            let st = e.h3.get_mut(&e.hd).unwrap();
            // `service_conn` stamps acceptance with the real clock; recover it from the
            // stream's initial deadline.
            if accepted.is_none()
                && let (Some(key), Some(timeout)) = (
                    st.request_snapshots.get(&id).and_then(|s| s.deadline),
                    config.timeout,
                )
            {
                accepted = Some(key.when - timeout);
            }
            let since_accept = now - accepted.unwrap_or(now);
            if reclaim_expired_requests(st, now).contains(&id) {
                return PacedUpload::Expired(since_accept);
            }
            let conn = e.conns.get_mut(&e.hd).unwrap();
            if receive_request_streams(conn, st, now).contains(&id) {
                let body = st.req_buf.get(&id).map_or(0, Vec::len);
                return PacedUpload::Finished(since_accept, body);
            }
            h.to_client(conn, e.client_handle, &mut e.client, now);
            now += STEP;
        }
        panic!("the upload neither finished nor expired");
    }

    /// The virtual clock's resolution in [`paced_h3_upload`].
    const STEP: Duration = Duration::from_millis(1);

    fn paced_config(timeout: Duration) -> H3RequestConfig {
        H3RequestConfig::new(H3RequestLimits::new(1024, 1 << 20), Some(timeout))
    }

    #[test]
    fn steady_upload_outlasting_the_timeout_is_received_whole() {
        let timeout = Duration::from_secs(1);
        // 16 KiB per half window for 2.5 windows: past the old absolute deadline.
        let total = 6 * 16 * 1024;
        match paced_h3_upload(
            paced_config(timeout),
            16 * 1024,
            Duration::from_millis(500),
            total,
        ) {
            PacedUpload::Finished(at, body) => {
                assert!(at > 2 * timeout, "{at:?}");
                assert_eq!(body, total);
            }
            other => panic!("a steady upload must not be cut: {other:?}"),
        }
    }

    #[test]
    fn trickled_upload_is_cut_at_the_timeout() {
        let timeout = Duration::from_secs(1);
        match paced_h3_upload(paced_config(timeout), 1, Duration::from_millis(100), 100) {
            PacedUpload::Expired(at) => assert!(at >= timeout && at < timeout + STEP, "{at:?}"),
            other => panic!("a trickle below the floor must be cut: {other:?}"),
        }
    }

    #[test]
    fn steady_upload_is_cut_at_the_ceiling() {
        let timeout = Duration::from_secs(1);
        let ceiling = Duration::from_millis(1500);
        match paced_h3_upload(
            paced_config(timeout).with_body_ceiling(ceiling),
            16 * 1024,
            Duration::from_millis(300),
            10 * 16 * 1024,
        ) {
            PacedUpload::Expired(at) => assert!(at >= ceiling && at < ceiling + STEP, "{at:?}"),
            other => panic!("progress must not outlast the ceiling: {other:?}"),
        }
    }

    #[test]
    fn incoming_decision_admits_retries_and_refuses_by_pressure() {
        use IncomingDecision::*;
        let threshold = H3_RETRY_THRESHOLD_PER_CORE;
        let cap = u64::from(H3_HANDSHAKING_CAP_PER_CORE);
        let cases = [
            (true, true, false, true, 0, Accept),
            (true, true, false, true, threshold - 1, Accept),
            (true, true, false, true, threshold, Retry),
            (true, true, false, false, threshold, Refuse),
            (true, true, true, false, threshold, Accept),
            (true, true, true, false, cap - 1, Accept),
            (true, true, true, false, cap, Refuse),
            (true, false, true, false, 0, Refuse),
            (false, true, true, false, 0, Refuse),
        ];
        for (accepting, budget, validated, may_retry, handshaking, expected) in cases {
            assert_eq!(
                incoming_decision(accepting, budget, validated, may_retry, handshaking),
                expected,
                "accepting={accepting} budget={budget} validated={validated} handshaking={handshaking}"
            );
        }
    }

    #[test]
    fn unvalidated_initial_gets_retry_when_handshaking_cap_exceeded() {
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let mut held = Vec::new();
        for i in 0..H3_RETRY_THRESHOLD_PER_CORE as u16 {
            let (_, mut conn) = h.connect(now);
            let initial = Harness::first_datagram(&mut conn, now);
            let incoming = h.incoming(spoofed(i), &initial, now);
            match h.admit(incoming, now) {
                Admission::Accepted(handle, conn, slot) => held.push((handle, conn, slot)),
                _ => panic!("below the threshold every Initial is accepted"),
            }
        }
        assert_eq!(h.handshakes.load(Relaxed), H3_RETRY_THRESHOLD_PER_CORE);
        assert_eq!(
            h.active.load(Relaxed),
            0,
            "handshakes never charge the shared budget"
        );

        let retried_from = spoofed(999);
        let (client_handle, mut client) = h.connect(now);
        let initial = Harness::first_datagram(&mut client, now);
        let incoming = h.incoming(retried_from, &initial, now);
        let Admission::Transmit(transmit) = h.admit(incoming, now) else {
            panic!("an unvalidated Initial over the threshold must not be accepted");
        };
        let retry = h.scratch[..transmit.size].to_vec();
        assert_eq!(retry[0] & 0xf0, 0xf0, "a QUIC v1 Retry long header");
        assert_eq!(h.handshakes.load(Relaxed), H3_RETRY_THRESHOLD_PER_CORE);

        let mut scratch = Vec::new();
        match h.client.handle(
            now,
            SERVER,
            None,
            None,
            BytesMut::from(&retry[..]),
            &mut scratch,
        ) {
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                assert_eq!(handle, client_handle);
                client.handle_event(event);
            }
            _ => panic!("the client must route the Retry to its connection"),
        }
        let token_initial = Harness::first_datagram(&mut client, now);
        let incoming = h.incoming(retried_from, &token_initial, now);
        assert!(incoming.remote_address_validated());
        let accepted = h.admit(incoming, now);
        assert!(
            matches!(accepted, Admission::Accepted(..)),
            "a token-bearing Initial is accepted under pressure"
        );
        drop(held);
        assert_eq!(h.handshakes.load(Relaxed), 1);
        drop(accepted);
        assert_eq!(h.handshakes.load(Relaxed), 0);
    }

    #[test]
    fn h3_cannot_exhaust_tcp_connection_budget() {
        let cap = 8;
        let mut h = Harness::new(cap);
        let now = Instant::now();
        let policy = h.policy();
        let mut conns = HashMap::new();
        let mut h3 = HashMap::new();
        let mut clients = Vec::new();
        for i in 0..20u16 {
            let (client_handle, mut client) = h.connect(now);
            let initial = Harness::first_datagram(&mut client, now);
            let incoming = h.incoming(spoofed(i), &initial, now);
            let Admission::Accepted(handle, conn, slot) = h.admit(incoming, now) else {
                panic!("half-open connections below the threshold are accepted");
            };
            conns.insert(handle, conn);
            h3.insert(
                handle,
                h.runtime
                    .accepted_state_with_policy(slot, now, u64::from(i), &policy),
            );
            clients.push((handle, client_handle, client, spoofed(i)));
        }
        assert_eq!(h.active.load(Relaxed), 0);
        assert!(
            crate::uring::ConnectionPermit::try_acquire(h.active.clone(), cap).is_some(),
            "TCP accepts still get the shared budget while 20 H3 handshakes are pending"
        );

        let (hd, client_handle, mut client, addr) = clients.remove(0);
        h.drive_handshake(
            &mut conns,
            &mut h3,
            hd,
            client_handle,
            &mut client,
            addr,
            now,
        );
        assert!(h3[&hd].connected);
        assert_eq!(
            h3[&hd].server_name.as_deref(),
            Some("localhost"),
            "the routing SNI comes from the QUIC handshake"
        );
        assert_eq!(
            h.active.load(Relaxed),
            1,
            "the budget is charged at Connected"
        );
        assert_eq!(
            h.handshakes.load(Relaxed),
            19,
            "the handshake slot is released"
        );

        let tcp: Vec<_> = (0..cap - 1)
            .map(|_| crate::uring::ConnectionPermit::try_acquire(h.active.clone(), cap).unwrap())
            .collect();
        let (hd, client_handle, mut client, addr) = clients.remove(0);
        h.drive_handshake(
            &mut conns,
            &mut h3,
            hd,
            client_handle,
            &mut client,
            addr,
            now,
        );
        assert!(h3[&hd].rejected && !h3[&hd].connected);
        assert_eq!(
            h.active.load(Relaxed),
            u64::from(cap),
            "a full budget is never exceeded"
        );
        drop(tcp);
    }

    #[test]
    fn half_open_h3_connection_is_closed_after_handshake_timeout() {
        let mut h = Harness::new(65_000);
        let now = Instant::now();
        let policy = h.policy();
        let (_, mut client) = h.connect(now);
        let initial = Harness::first_datagram(&mut client, now);
        let incoming = h.incoming(spoofed(1), &initial, now);
        let Admission::Accepted(hd, conn, slot) = h.admit(incoming, now) else {
            panic!("accepted");
        };
        let mut conns = HashMap::from([(hd, conn)]);
        let mut h3 = HashMap::from([(
            hd,
            h.runtime.accepted_state_with_policy(slot, now, 1, &policy),
        )]);
        assert_eq!(h3[&hd].next_deadline(), Some(now + H3_HANDSHAKE_TIMEOUT));

        let config = H3RequestConfig::new(H3RequestLimits::new(1024, 1024), None);
        let before = H3_HANDSHAKE_TIMEOUTS.load(Relaxed);
        service_conn(
            &mut h.server,
            &mut conns,
            &mut h3,
            hd,
            now + Duration::from_secs(9),
            true,
            config,
        );
        assert!(!h3[&hd].rejected);
        assert_eq!(h.handshakes.load(Relaxed), 1);
        service_conn(
            &mut h.server,
            &mut conns,
            &mut h3,
            hd,
            now + H3_HANDSHAKE_TIMEOUT,
            true,
            config,
        );
        assert!(h3[&hd].rejected);
        assert_eq!(
            h.handshakes.load(Relaxed),
            0,
            "the handshake slot is released"
        );
        assert_eq!(h3[&hd].next_deadline(), None);
        assert!(H3_HANDSHAKE_TIMEOUTS.load(Relaxed) > before);
    }

    #[test]
    fn handshake_deadline_never_outlives_the_handshake() {
        let t0 = Instant::now();
        let mut st = H3State {
            accepted_at: Some(t0),
            ..Default::default()
        };
        assert_eq!(st.next_deadline(), Some(t0 + H3_HANDSHAKE_TIMEOUT));
        st.connected = true;
        assert_eq!(st.next_deadline(), None);
        assert_eq!(H3State::default().next_deadline(), None);
    }

    #[test]
    fn cancel_budget_allows_a_burst_then_refills_at_its_rate() {
        let t0 = Instant::now();
        let mut budget = CancelBudget::default();
        for _ in 0..H3_CANCEL_BURST {
            assert!(!budget.charge(t0));
        }
        assert!(budget.charge(t0), "one past the burst is excessive");

        let mut budget = CancelBudget::default();
        for _ in 0..H3_CANCEL_BURST {
            assert!(!budget.charge(t0));
        }
        let later = t0 + H3_CANCEL_REFILL * 10;
        for _ in 0..10 {
            assert!(!budget.charge(later), "elapsed time refills the bucket");
        }
        assert!(budget.charge(later));

        // A client cancelling a page's worth of requests now and then never trips it.
        let mut budget = CancelBudget::default();
        for page in 0..100u32 {
            let at = t0 + Duration::from_secs(15) * page;
            for _ in 0..150 {
                assert!(!budget.charge(at));
            }
        }
    }

    #[test]
    fn request_stream_admission_caps_one_drive_at_the_advertised_limit() {
        let st = H3State::default();
        let mut accepted = 0;
        for _ in 0..MAX_CONCURRENT_BIDI_STREAMS {
            assert!(admit_request_stream(&st, &mut accepted).is_ok());
        }
        let error = admit_request_stream(&st, &mut accepted).unwrap_err();
        assert_eq!(error.code, H3_EXCESSIVE_LOAD);
    }

    #[test]
    fn request_stream_admission_caps_live_requests() {
        let mut st = H3State::default();
        for index in 0..u64::from(2 * MAX_CONCURRENT_BIDI_STREAMS - 1) {
            st.requests
                .insert(StreamId::new(quinn_proto::Side::Client, Dir::Bi, index));
        }
        let mut accepted = 0;
        assert!(admit_request_stream(&st, &mut accepted).is_ok());
        st.requests.insert(StreamId::new(
            quinn_proto::Side::Client,
            Dir::Bi,
            u64::from(2 * MAX_CONCURRENT_BIDI_STREAMS),
        ));
        let mut accepted = 0;
        assert_eq!(
            admit_request_stream(&st, &mut accepted).unwrap_err().code,
            H3_EXCESSIVE_LOAD
        );
    }
}
