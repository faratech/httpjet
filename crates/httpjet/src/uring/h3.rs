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

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use std::os::fd::{AsRawFd, BorrowedFd};

use bytes::{Bytes, BytesMut};
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
const MAX_PEER_UNI_STREAMS: usize = 16;

const H3_STREAM_CREATION_ERROR: u32 = 0x0103;
const H3_CLOSED_CRITICAL_STREAM: u32 = 0x0104;
const H3_FRAME_UNEXPECTED: u32 = 0x0105;
const H3_EXCESSIVE_LOAD: u32 = 0x0107;
const H3_SETTINGS_ERROR: u32 = 0x0109;
const H3_MISSING_SETTINGS: u32 = 0x010a;
const MAX_SETTINGS_PAYLOAD: usize = 64 * 1024;

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

#[derive(Clone)]
pub(crate) struct H3RuntimeConfig {
    config: Arc<dyn Fn() -> (H3RequestLimits, u32) + Send + Sync>,
    active_conns: Arc<AtomicU64>,
    /// (#236 residual) Server-wide buffered-body cap shared with H1/H2/LSAPI. H3 commits
    /// the whole request-stream buffer before parse, so the reservation is taken when a
    /// finished request is taken for dispatch (per-connection wire bytes are already
    /// bounded separately by `total_req_bytes`).
    body_budget: std::sync::Arc<hj_core::budget::BodyBufferBudget>,
}

impl H3RuntimeConfig {
    pub(crate) fn new<F>(
        config: F,
        active_conns: Arc<AtomicU64>,
        body_budget: std::sync::Arc<hj_core::budget::BodyBufferBudget>,
    ) -> Self
    where
        F: Fn() -> (H3RequestLimits, u32) + Send + Sync + 'static,
    {
        Self {
            config: Arc::new(config),
            active_conns,
            body_budget,
        }
    }

    fn request_limits(&self) -> H3RequestLimits {
        (self.config)().0
    }

    fn max_connections(&self) -> u32 {
        (self.config)().1
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
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams((MAX_PEER_UNI_STREAMS as u32).into());
    let idle = std::time::Duration::from_secs(60)
        .try_into()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("idle timeout: {e:?}")))?;
    transport.max_idle_timeout(Some(idle));
    transport.stream_receive_window((4u32 * 1024 * 1024).into());
    transport.receive_window((64u32 * 1024 * 1024).into());
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
    let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .build()
        .expect("build monoio io_uring runtime");
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
        let smoke = |_bytes: Vec<u8>, _cc: bool, _peer: SocketAddr| async { h3_response_bytes() };
        if let Err(e) = endpoint_loop(udp, endpoint, smoke).await {
            tracing::error!(core, error = %e, "uring h3: endpoint loop ended");
        }
    });
}

/// Per-connection HTTP/3 state.
#[derive(Default)]
struct H3State {
    _connection_permit: Option<super::ConnectionPermit>,
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
    /// In-flight client request bidi streams (removed once served), so we never
    /// re-scan already-served streams — bounded by concurrent requests, not total.
    requests: std::collections::HashSet<StreamId>,
    /// Accumulated request bytes per in-flight bidi stream (a request's HEADERS+DATA
    /// frames may arrive across several datagrams); drained + handled on stream fin.
    req_buf: std::collections::HashMap<StreamId, Vec<u8>>,
    req_frames: std::collections::HashMap<StreamId, H3FrameCounter>,
    /// Every accepted peer unidirectional stream remains here until FIN/reset. HTTP/3
    /// control and QPACK streams are critical and must be continuously drained; accepting
    /// and reading them once loses split stream-type/SETTINGS delivery and hides closure.
    peer_uni: std::collections::HashMap<StreamId, PeerUniStream>,
    peer_control: Option<StreamId>,
    peer_qpack_encoder: Option<StreamId>,
    peer_qpack_decoder: Option<StreamId>,
    peer_settings: Option<PeerSettings>,
    /// Total raw request bytes retained across all unfinished streams on this connection.
    total_req_bytes: std::rc::Rc<std::cell::Cell<usize>>,
    /// Set once a required-client-certificate decision closes the connection.
    rejected: bool,
    /// Encoded response bytes not yet fully written to the send stream, with the
    /// byte offset already accepted. QUIC stream flow control bounds how much
    /// `SendStream::write` accepts at once, so a large response (> the peer's stream
    /// window, e.g. a multi-MB file) is written incrementally: the remainder is pumped
    /// as the peer grants more window (`StreamEvent::Writable`). Without this, a large
    /// response is silently truncated to the first window.
    pending: std::collections::HashMap<StreamId, PendingSend>,
    /// Cancellation handles for requests already dispatched through the bridge. A peer
    /// STOP_SENDING must drop the monoio request task so the bridge drops its response
    /// receiver, cancels the tokio pipeline future, and releases the global slot.
    request_cancellations: RequestCancellations,
    /// Per-connection generation, assigned from a per-core counter at accept. quinn-proto
    /// reuses `ConnectionHandle` indices after a connection drains, so a response from a
    /// spawned task that finished AFTER its connection closed (and the handle was reused by
    /// a NEW connection) must be dropped — guarded by comparing this epoch (see
    /// [`Completion`] / `write_completion`).
    epoch: u64,
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
    Full(Vec<u8>),
    /// HEADERS frame only; DATA `Chunk`s follow. The stream stays open until `Chunk{fin}`.
    Head(Vec<u8>),
    /// One DATA payload; the driver emits its frame header without copying the payload.
    /// `fin` marks the last chunk (then finish the stream).
    Chunk {
        data: Bytes,
        fin: bool,
        ack: Option<flume::Sender<()>>,
    },
    /// Mid-stream upstream abort — reset the send stream (RFC 9114 stream error).
    Abort,
}

/// A response buffered in the driver awaiting the QUIC flow-control window. Parts retain an
/// offset rather than deleting their written prefix, so partial writes never memmove a body.
/// Streamed DATA keeps the bridge's original `Bytes` and an inline frame header, avoiding both
/// copies formerly made while framing and appending each chunk.
struct PendingSend {
    parts: std::collections::VecDeque<PendingPart>,
    fin: bool,
}

enum PendingPart {
    Contiguous {
        data: Bytes,
        off: usize,
        ack: Option<flume::Sender<()>>,
    },
    DataFrame {
        header: [u8; 16],
        header_len: usize,
        header_off: usize,
        data: Bytes,
        data_off: usize,
        ack: Option<flume::Sender<()>>,
    },
}

impl PendingPart {
    fn contiguous(data: Vec<u8>) -> Self {
        Self::Contiguous {
            data: Bytes::from(data),
            off: 0,
            ack: None,
        }
    }

    fn data_frame(data: Bytes, ack: Option<flume::Sender<()>>) -> Self {
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

    fn write(&mut self, stream: &mut quinn_proto::SendStream<'_>) -> Result<bool, WriteError> {
        match self {
            Self::Contiguous { data, off, .. } => {
                if *off == data.len() {
                    return Ok(true);
                }
                let n = stream.write(&data[*off..])?;
                *off += n;
                Ok(*off == data.len())
            }
            Self::DataFrame {
                header,
                header_len,
                header_off,
                data,
                data_off,
                ..
            } => {
                if *header_off < *header_len {
                    let n = stream.write(&header[*header_off..*header_len])?;
                    *header_off += n;
                    if *header_off < *header_len || n == 0 {
                        return Ok(false);
                    }
                }
                if *data_off < data.len() {
                    let n = stream.write(&data[*data_off..])?;
                    *data_off += n;
                    if *data_off < data.len() || n == 0 {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }
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

/// RAII reservation of a finished request's committed bytes against the server-wide
/// buffered-body cap shared with H1/H2/LSAPI (#236 residual). Held for the life of the
/// dispatched task; released on completion, drop, or panic.
struct BudgetGuard {
    budget: std::sync::Arc<hj_core::budget::BodyBufferBudget>,
    bytes: u64,
}

impl BudgetGuard {
    fn acquire(budget: &std::sync::Arc<hj_core::budget::BodyBufferBudget>, n: u64) -> Option<Self> {
        if n == 0 || budget.try_acquire(n) {
            Some(Self {
                budget: budget.clone(),
                bytes: n,
            })
        } else {
            None
        }
    }
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
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
/// returning whatever was buffered. Used when a stream is gone (reset/closed),
/// oversize, or fully received — every removal from `requests` goes through here so a
/// stream can never be dropped from one map but left in the other.
fn reclaim_request(st: &mut H3State, id: StreamId) -> Vec<u8> {
    st.requests.remove(&id);
    st.req_frames.remove(&id);
    let bytes = st.req_buf.remove(&id).unwrap_or_default();
    st.total_req_bytes
        .set(st.total_req_bytes.get().saturating_sub(bytes.len()));
    bytes
}

fn take_request_for_dispatch(st: &mut H3State, id: StreamId) -> Vec<u8> {
    st.requests.remove(&id);
    st.req_frames.remove(&id);
    st.req_buf.remove(&id).unwrap_or_default()
}

fn release_request_charge(st: &mut H3State, bytes: usize) {
    st.total_req_bytes
        .set(st.total_req_bytes.get().saturating_sub(bytes));
}

#[derive(Default)]
struct H3FrameCounter {
    phase: H3FramePhase,
    varint: [u8; 8],
    varint_len: usize,
    varint_need: usize,
    frame_type: u64,
    header_bytes: usize,
    body_bytes: usize,
}

#[derive(Clone, Copy, Default)]
enum H3FramePhase {
    #[default]
    Type,
    Length,
    Payload(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestFrameError {
    Limit,
    Unexpected,
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

    fn consume(&mut self, input: &[u8], limits: H3RequestLimits) -> Result<(), RequestFrameError> {
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
                    let total = match self.frame_type {
                        0x01 => self.header_bytes.checked_add(length),
                        0x00 => self.body_bytes.checked_add(length),
                        _ => Some(0),
                    };
                    let Some(total) = total else {
                        return Err(RequestFrameError::Limit);
                    };
                    match self.frame_type {
                        0x01 => {
                            if total > limits.max_header_bytes {
                                return Err(RequestFrameError::Limit);
                            }
                            self.header_bytes = total;
                        }
                        0x00 => {
                            if total > limits.max_body_bytes {
                                return Err(RequestFrameError::Limit);
                            }
                            self.body_bytes = total;
                        }
                        _ => {}
                    }
                    self.phase = if length == 0 {
                        H3FramePhase::Type
                    } else {
                        H3FramePhase::Payload(length)
                    };
                }
                H3FramePhase::Payload(remaining) => {
                    let consumed = remaining.min(input.len() - pos);
                    pos += consumed;
                    self.phase = if consumed == remaining {
                        H3FramePhase::Type
                    } else {
                        H3FramePhase::Payload(remaining - consumed)
                    };
                }
            }
        }
        Ok(())
    }
}

fn append_request_bytes(
    st: &mut H3State,
    id: StreamId,
    bytes: &[u8],
    limits: H3RequestLimits,
) -> Result<(), RequestFrameError> {
    let Some(total) = st.total_req_bytes.get().checked_add(bytes.len()) else {
        return Err(RequestFrameError::Limit);
    };
    if total > limits.max_connection_bytes {
        return Err(RequestFrameError::Limit);
    }
    st.req_frames
        .entry(id)
        .or_default()
        .consume(bytes, limits)?;
    let buffer = st.req_buf.entry(id).or_default();
    buffer.extend_from_slice(bytes);
    st.total_req_bytes.set(total);
    if buffer.len() > limits.max_request_wire_bytes {
        Err(RequestFrameError::Limit)
    } else {
        Ok(())
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
            state.peer_settings = Some(settings);
        }
    }
    Ok(())
}

fn finish_peer_uni(stream: &PeerUniStream) -> Result<(), H3ConnectionError> {
    match stream.kind {
        PeerUniKind::Pending => Err(H3ConnectionError::new(
            H3_STREAM_CREATION_ERROR,
            b"truncated HTTP/3 unidirectional stream type",
        )),
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
    reusable: &mut Vec<u8>,
    payload: &[u8],
    destination: SocketAddr,
) {
    let mut owned = std::mem::take(reusable);
    owned.clear();
    owned.extend_from_slice(payload);
    let (_, owned) = udp.send_to(owned, destination).await;
    *reusable = owned;
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
    H: Fn(Vec<u8>, bool, SocketAddr) -> Fut,
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
    let max_gso = udp_state.max_gso_segments();
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
                        &mut tx_scratch,
                        &scratch[..t.size],
                        t.destination,
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
                                    &mut tx_scratch,
                                    &scratch[..t.size],
                                    t.destination,
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
            max_gso,
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
    require_client_cert: bool,
    accepting_requests: bool,
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
                    h3_client_eligible(require_client_cert, leaf.is_some(), conn.remote_address())
                });
                if eligible {
                    st.client_leaf = leaf;
                    st.connected = true;
                    tracing::info!("uring h3: QUIC handshake complete (Connected)");
                } else {
                    st.rejected = true;
                    if let Some(conn) = conns.get_mut(&hd) {
                        conn.close(
                            now,
                            quinn_proto::VarInt::from_u32(0x010b),
                            bytes::Bytes::from_static(b"client certificate required"),
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
        st.rejected = true;
        return;
    }
    for id in readable {
        if !st.request_cancellations.contains_key(&id) {
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
                    .reset(quinn_proto::VarInt::from_u32(0x010c));
            }
        }
    }
    for id in stopped {
        if let Some(error) = reject_stopped_local_critical_stream(st, id) {
            if let Some(conn) = conns.get_mut(&hd) {
                conn.close(
                    now,
                    quinn_proto::VarInt::from_u32(error.code),
                    Bytes::from_static(error.reason),
                );
            }
            return;
        }
        let receiving = st.requests.contains(&id);
        if receiving {
            reclaim_request(st, id);
        }
        cancel_dispatched_request(st, id);
        if let Some(conn) = conns.get_mut(&hd) {
            let _ = conn
                .send_stream(id)
                .reset(quinn_proto::VarInt::from_u32(0x010c));
            if receiving {
                let _ = conn
                    .recv_stream(id)
                    .stop(quinn_proto::VarInt::from_u32(0x010c));
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
    while let Some(id) = conns.get_mut(&hd).and_then(|c| c.streams().accept(Dir::Bi)) {
        if accepting_requests {
            st.next_request_stream_index = st.next_request_stream_index.max(id.index() + 1);
            st.requests.insert(id);
            st.req_buf.entry(id).or_default();
        } else if let Some(c) = conns.get_mut(&hd) {
            let code = quinn_proto::VarInt::from_u32(0x010b);
            let _ = c.recv_stream(id).stop(code);
            let _ = c.send_stream(id).reset(code);
        }
    }
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

async fn flush_conn(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    max_gso: usize,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    hd: ConnectionHandle,
    now: Instant,
    tbuf: &mut Vec<u8>,
) -> bool {
    let seg_cap = max_gso.min(MAX_TX_SEGMENTS).max(1);
    let mut datagrams = 0usize;
    loop {
        tbuf.clear();
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
            match udp_state.send(UdpSockRef::from(&bfd), &transmit) {
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
    max_gso: usize,
    endpoint: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    now: Instant,
    handle_request: &H,
    tx_scratch: &mut Vec<u8>,
) where
    H: Fn(Vec<u8>, bool, SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Vec<u8>>,
{
    let handles: Vec<ConnectionHandle> = conns.keys().copied().collect();
    for hd in handles {
        service_conn(endpoint, conns, h3, hd, now, false, true);
        if h3.get(&hd).is_some_and(|state| state.rejected) {
            flush_conn(udp, udp_state, max_gso, conns, hd, now, tx_scratch).await;
            continue;
        }
        let st = h3.entry(hd).or_default();
        let req_ids: Vec<StreamId> = st.requests.iter().copied().collect();
        let mut finished = Vec::new();
        for id in req_ids {
            let limits = H3RequestLimits::new(64 * 1024, MAX_H3_REQ_BYTES);
            let (end, append) = conns
                .get_mut(&hd)
                .map(|c| {
                    for_each_stream_chunk(c, id, |bytes| {
                        append_request_bytes(st, id, bytes, limits)
                    })
                })
                .unwrap_or((ReadEnd::Open, Ok(())));
            if end == ReadEnd::Gone {
                // Peer reset / stream gone: reclaim the slot + buffer (see the concurrent
                // driver — same per-connection memory-exhaustion vector).
                reclaim_request(st, id);
                continue;
            }
            if append == Err(RequestFrameError::Unexpected) {
                reclaim_request(st, id);
                st.rejected = true;
                if let Some(c) = conns.get_mut(&hd) {
                    c.close(
                        now,
                        quinn_proto::VarInt::from_u32(H3_FRAME_UNEXPECTED),
                        Bytes::from_static(b"frame is forbidden on a request stream"),
                    );
                }
                break;
            }
            if append == Err(RequestFrameError::Limit) {
                // (N3) Oversize request (header+body) — reset the stream and drop the buffer
                // rather than accumulate an unbounded Vec until FIN.
                reclaim_request(st, id);
                if let Some(c) = conns.get_mut(&hd) {
                    let _ = c
                        .recv_stream(id)
                        .stop(quinn_proto::VarInt::from_u32(0x010c)); // H3_REQUEST_CANCELLED
                }
                continue;
            }
            if end == ReadEnd::Fin {
                finished.push(id);
            }
        }
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
        flush_conn(udp, udp_state, max_gso, conns, hd, now, tx_scratch).await;
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
    let done = loop {
        let Some(part) = entry.parts.front_mut() else {
            if entry.fin {
                let _ = ss.finish();
                break true;
            }
            break false;
        };
        match part.write(&mut ss) {
            Ok(true) => {
                acknowledge_front_part(entry);
            }
            Ok(false) | Err(WriteError::Blocked) => break false,
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
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_completion(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    max_gso: usize,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    c: Completion,
    now: Instant,
    tx_scratch: &mut Vec<u8>,
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
        CompletionKind::Full(resp) => {
            st.request_cancellations.remove(&stream);
            st.pending.insert(
                stream,
                PendingSend {
                    parts: std::iter::once(PendingPart::contiguous(resp)).collect(),
                    fin: true,
                },
            );
        }
        // HEADERS of a streamed response: DATA chunks follow, so don't finish yet.
        CompletionKind::Head(head) => {
            st.pending.insert(
                stream,
                PendingSend {
                    parts: std::iter::once(PendingPart::contiguous(head)).collect(),
                    fin: false,
                },
            );
        }
        // Append a DATA chunk to the open stream; `fin` marks the body complete. No live
        // pending entry ⇒ the stream was cancelled / its conn went away → drop the chunk.
        CompletionKind::Chunk { data, fin, ack } => match st.pending.get_mut(&stream) {
            Some(entry) => {
                if !data.is_empty() {
                    entry.parts.push_back(PendingPart::data_frame(data, ack));
                }
                if fin {
                    entry.fin = true;
                    st.request_cancellations.remove(&stream);
                }
            }
            None => return,
        },
        // Mid-stream upstream abort: reset the send stream (H3_INTERNAL_ERROR) rather than
        // a clean finish, so the peer sees the body was truncated (mirrors the H1 path).
        CompletionKind::Abort => {
            st.request_cancellations.remove(&stream);
            st.pending.remove(&stream);
            let _ = conn
                .send_stream(stream)
                .reset(quinn_proto::VarInt::from_u32(0x0102));
            flush_conn(udp, udp_state, max_gso, conns, ch, now, tx_scratch).await;
            return;
        }
    }
    pump_stream(conn, st, stream); // write what the window allows; remainder pumps on Writable
    flush_conn(udp, udp_state, max_gso, conns, ch, now, tx_scratch).await;
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
    max_gso: usize,
    endpoint: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    hd: ConnectionHandle,
    now: Instant,
    local: SocketAddr,
    bridge: &Bridge,
    require_client_cert: bool,
    inflight: &std::rc::Rc<std::cell::Cell<usize>>,
    comp_tx: &flume::Sender<Completion>,
    request_limits: H3RequestLimits,
    body_budget: &std::sync::Arc<hj_core::budget::BodyBufferBudget>,
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
        require_client_cert,
        accepting_requests,
    );
    if h3.get(&hd).is_some_and(|state| state.rejected) {
        return flush_conn(udp, udp_state, max_gso, conns, hd, now, tx_scratch).await;
    }
    let epoch = h3.get(&hd).map(|s| s.epoch).unwrap_or(0);
    let st = h3.entry(hd).or_default();
    let req_ids: Vec<StreamId> = st.requests.iter().copied().collect();
    let mut finished = Vec::new();
    for id in req_ids {
        let (end, append) = conns
            .get_mut(&hd)
            .map(|c| {
                for_each_stream_chunk(c, id, |bytes| {
                    append_request_bytes(st, id, bytes, request_limits)
                })
            })
            .unwrap_or((ReadEnd::Open, Ok(())));
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
            if let Some(c) = conns.get_mut(&hd) {
                let _ = c
                    .send_stream(id)
                    .reset(quinn_proto::VarInt::from_u32(0x010c));
            }
            continue;
        }
        if append == Err(RequestFrameError::Unexpected) {
            reclaim_request(st, id);
            st.rejected = true;
            if let Some(c) = conns.get_mut(&hd) {
                c.close(
                    now,
                    quinn_proto::VarInt::from_u32(H3_FRAME_UNEXPECTED),
                    Bytes::from_static(b"frame is forbidden on a request stream"),
                );
            }
            break;
        }
        if append == Err(RequestFrameError::Limit) {
            // (N3) Oversize request — reset the stream and drop the buffer.
            reclaim_request(st, id);
            if let Some(c) = conns.get_mut(&hd) {
                let _ = c
                    .recv_stream(id)
                    .stop(quinn_proto::VarInt::from_u32(0x010c));
                // Retire the send half too so the bidi stream is fully freed and its
                // MAX_STREAMS credit is reissued (same reason as the Gone branch).
                let _ = c
                    .send_stream(id)
                    .reset(quinn_proto::VarInt::from_u32(0x010c));
            }
            continue;
        }
        if end != ReadEnd::Fin {
            continue;
        }
        finished.push(id);
    }
    if st.rejected {
        for id in finished {
            reclaim_request(st, id);
        }
        return flush_conn(udp, udp_state, max_gso, conns, hd, now, tx_scratch).await;
    }
    for id in finished {
        let req_bytes = take_request_for_dispatch(st, id);
        let req_charge = req_bytes.len();
        // Peer + TLS params captured up front (no connection borrow into the task). QUIC is
        // always TLS 1.3 (RFC 9001); quinn-proto exposes the client cert chain but not the
        // negotiated cipher, so report the QUIC-mandatory AEAD — same as the tokio H3 path —
        // and parse the client leaf cert for SSL_CLIENT_* CGI vars.
        let peer = conns
            .get(&hd)
            .map(|c| c.remote_address())
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let leaf = st.client_leaf.clone();
        let has_client_cert = leaf.is_some();
        let tls = Some(hj_tls::tls_params_from_parts(
            "TLSv1.3",
            "TLS_AES_128_GCM_SHA256".to_string(),
            leaf.as_ref(),
        ));
        if inflight.get() >= MAX_INFLIGHT_PER_CORE {
            // Backpressure: shed inline rather than spawning (bounds RAM under a flood).
            if let Some(c) = conns.get_mut(&hd) {
                let mut ss = c.send_stream(id);
                let _ = ss.write(&h3_error(http::StatusCode::SERVICE_UNAVAILABLE));
                let _ = ss.finish();
            }
            release_request_charge(st, req_charge);
            continue;
        }
        inflight.set(inflight.get() + 1);
        let guard = InflightGuard(inflight.clone());
        // (#236 residual) Reserve the request's committed bytes against the server-wide
        // cap before spawning its work; the guard releases them when the task ends.
        let Some(budget_guard) = BudgetGuard::acquire(body_budget, req_charge as u64) else {
            if let Some(c) = conns.get_mut(&hd) {
                let mut ss = c.send_stream(id);
                let _ = ss.write(&h3_error(http::StatusCode::SERVICE_UNAVAILABLE));
                let _ = ss.finish();
            }
            release_request_charge(st, req_charge);
            continue;
        };
        let charge = RequestChargeGuard {
            total: st.total_req_bytes.clone(),
            bytes: req_charge,
        };
        let cancel = CancellationToken::new();
        st.request_cancellations.insert(id, cancel.clone());
        let bridge = bridge.clone();
        let tx = comp_tx.clone();
        // spawn() is synchronous (no await) — `st`'s borrow of `h3` is not held across an await.
        let work = async move {
            let _g = guard; // frees the in-flight slot on completion / drop / panic
            let _bg = budget_guard; // releases the server-wide body reservation likewise
            let send = |kind| {
                tx.send_async(Completion {
                    conn: hd,
                    stream: id,
                    epoch,
                    kind,
                })
            };
            let outcome = handle_h3_request(
                req_bytes,
                has_client_cert,
                tls,
                peer,
                local,
                &bridge,
                require_client_cert,
                request_limits,
            )
            .await;
            drop(charge);
            let _ = async {
                match outcome {
                    H3Outcome::Full(resp) => {
                        send(CompletionKind::Full(resp)).await.map_err(|_| ())?;
                    }
                    H3Outcome::Stream { head, mut rx } => {
                        // The driver is the sole stream writer: send the HEADERS, then forward each
                        // DATA chunk in order. Each chunk is acknowledged only after QUIC drains it.
                        send(CompletionKind::Head(head)).await.map_err(|_| ())?;
                        loop {
                            match rx.recv().await {
                                Some(Ok(chunk)) => {
                                    if chunk.is_empty() {
                                        continue;
                                    }
                                    let (ack_tx, ack_rx) = flume::bounded(1);
                                    send(CompletionKind::Chunk {
                                        data: chunk,
                                        fin: false,
                                        ack: Some(ack_tx),
                                    })
                                    .await
                                    .map_err(|_| ())?;
                                    ack_rx.recv_async().await.map_err(|_| ())?;
                                }
                                Some(Err(())) => {
                                    send(CompletionKind::Abort).await.map_err(|_| ())?;
                                    break;
                                }
                                None => {
                                    send(CompletionKind::Chunk {
                                        data: Bytes::new(),
                                        fin: true,
                                        ack: None,
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
    flush_conn(udp, udp_state, max_gso, conns, hd, now, tx_scratch).await
}

/// Non-blocking GRO drain: pull all currently-queued datagrams (recvmmsg into the reused
/// buffers, GRO-coalesced, split by `stride`), feed quinn-proto, and return the set of
/// connections that got new state (to be driven). Stops at `WouldBlock` (socket empty).
#[allow(clippy::too_many_arguments)]
async fn recv_drain(
    udp: &UdpSocket,
    udp_state: &UdpSocketState,
    recv_bufs: &mut [Vec<u8>; GRO_BATCH],
    recv_metas: &mut [quinn_udp::RecvMeta; GRO_BATCH],
    scratch: &mut Vec<u8>,
    tx_scratch: &mut Vec<u8>,
    endpoint: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    epoch_ctr: &mut u64,
    runtime: &H3RuntimeConfig,
    accepting_connections: bool,
    now: Instant,
) -> std::collections::HashSet<ConnectionHandle> {
    let mut affected: std::collections::HashSet<ConnectionHandle> =
        std::collections::HashSet::new();
    loop {
        let nmsg = {
            let [b0, b1, b2, b3, b4, b5, b6, b7] = recv_bufs.each_mut();
            let mut iov = [
                std::io::IoSliceMut::new(b0.as_mut_slice()),
                std::io::IoSliceMut::new(b1.as_mut_slice()),
                std::io::IoSliceMut::new(b2.as_mut_slice()),
                std::io::IoSliceMut::new(b3.as_mut_slice()),
                std::io::IoSliceMut::new(b4.as_mut_slice()),
                std::io::IoSliceMut::new(b5.as_mut_slice()),
                std::io::IoSliceMut::new(b6.as_mut_slice()),
                std::io::IoSliceMut::new(b7.as_mut_slice()),
            ];
            let bfd = unsafe { BorrowedFd::borrow_raw(udp.as_raw_fd()) };
            match udp_state.recv(UdpSockRef::from(&bfd), &mut iov, recv_metas) {
                Ok(n) => n,
                Err(_) => break, // WouldBlock (drained) or error → stop
            }
        };
        if nmsg == 0 {
            break;
        }
        for i in 0..nmsg {
            let meta = recv_metas[i];
            if meta.len == 0 {
                continue;
            }
            let stride = if meta.stride == 0 {
                meta.len
            } else {
                meta.stride
            };
            let pecn = meta
                .ecn
                .and_then(|e| quinn_proto::EcnCodepoint::from_bits(e as u8));
            let mut off = 0usize;
            while off < meta.len {
                let end = (off + stride).min(meta.len);
                let seg = BytesMut::from(&recv_bufs[i][off..end]);
                off = end;
                scratch.clear();
                if let Some(ev) = endpoint.handle(now, meta.addr, meta.dst_ip, pecn, seg, scratch) {
                    match ev {
                        DatagramEvent::Response(t) => {
                            send_endpoint_datagram(
                                udp,
                                tx_scratch,
                                &scratch[..t.size],
                                t.destination,
                            )
                            .await;
                        }
                        DatagramEvent::NewConnection(incoming) => {
                            scratch.clear();
                            let permit = accepting_connections.then(|| {
                                super::ConnectionPermit::try_acquire(
                                    runtime.active_conns.clone(),
                                    runtime.max_connections(),
                                )
                            });
                            let Some(Some(permit)) = permit else {
                                let transmit = endpoint.refuse(incoming, scratch);
                                send_endpoint_datagram(
                                    udp,
                                    tx_scratch,
                                    &scratch[..transmit.size],
                                    transmit.destination,
                                )
                                .await;
                                continue;
                            };
                            match endpoint.accept(incoming, now, scratch, None) {
                                Ok((handle, conn)) => {
                                    *epoch_ctr += 1;
                                    conns.insert(handle, conn);
                                    h3.insert(
                                        handle,
                                        H3State {
                                            _connection_permit: Some(permit),
                                            epoch: *epoch_ctr,
                                            ..Default::default()
                                        },
                                    );
                                    affected.insert(handle);
                                }
                                Err(e) => {
                                    if let Some(t) = e.response {
                                        send_endpoint_datagram(
                                            udp,
                                            tx_scratch,
                                            &scratch[..t.size],
                                            t.destination,
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
                                affected.insert(handle);
                            }
                        }
                    }
                }
            }
        }
        if nmsg < GRO_BATCH {
            break; // fewer than a full batch ⇒ socket drained
        }
    }
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
    max_gso: usize,
    recv_bufs: &mut [Vec<u8>; GRO_BATCH],
    recv_metas: &mut [quinn_udp::RecvMeta; GRO_BATCH],
    scratch: &mut Vec<u8>,
    tx_scratch: &mut Vec<u8>,
    endpoint: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, quinn_proto::Connection>,
    h3: &mut HashMap<ConnectionHandle, H3State>,
    epoch_ctr: &mut u64,
    inflight: &std::rc::Rc<std::cell::Cell<usize>>,
    bridge: &Bridge,
    local: SocketAddr,
    require_client_cert: bool,
    comp_tx: &flume::Sender<Completion>,
    runtime: &H3RuntimeConfig,
    accepting: bool,
    mut to_drive: std::collections::HashSet<ConnectionHandle>,
) {
    const MAX_PUMP_ROUNDS: usize = 64;
    let mut rounds = 0;
    while !to_drive.is_empty() && rounds < MAX_PUMP_ROUNDS {
        rounds += 1;
        let now = Instant::now();
        let mut next: std::collections::HashSet<ConnectionHandle> =
            std::collections::HashSet::new();
        for hd in to_drive.drain() {
            if drive_one_conn(
                udp,
                udp_state,
                max_gso,
                endpoint,
                conns,
                h3,
                hd,
                now,
                local,
                bridge,
                require_client_cert,
                inflight,
                comp_tx,
                runtime.request_limits(),
                &runtime.body_budget,
                accepting,
                tx_scratch,
            )
            .await
            {
                next.insert(hd); // hit the per-flush datagram cap → more to send
            }
        }
        // Process ACKs our sends elicited so cwnd/loss-detection stay current.
        for hd in recv_drain(
            udp, udp_state, recv_bufs, recv_metas, scratch, tx_scratch, endpoint, conns, h3,
            epoch_ctr, runtime, accepting, now,
        )
        .await
        {
            next.insert(hd);
        }
        to_drive = next;
    }
    conns.retain(|hd, c| {
        let drained = c.is_drained();
        if drained {
            h3.remove(hd);
        }
        !drained
    });
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
    max_gso: usize,
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
        flush_conn(udp, udp_state, max_gso, conns, hd, now, tx_scratch).await;
    }
}

/// The production io_uring H3 per-core loop: `select!` over (1) a finished-request completion
/// (write its response back + flush), (2) an inbound datagram (feed quinn-proto), (3) the
/// nearest quinn-proto timer. Per-request dispatch runs in spawned tasks (see
/// [`drive_one_conn`]), so PHP/pipeline latency never stalls the datagram loop.
async fn endpoint_loop_concurrent(
    udp: UdpSocket,
    mut endpoint: Endpoint,
    local: SocketAddr,
    bridge: Bridge,
    require_client_cert: bool,
    runtime: H3RuntimeConfig,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let mut conns: HashMap<ConnectionHandle, quinn_proto::Connection> = HashMap::new();
    let mut h3: HashMap<ConnectionHandle, H3State> = HashMap::new();
    let mut scratch: Vec<u8> = Vec::with_capacity(MAX_DATAGRAM);
    let mut tx_scratch: Vec<u8> = Vec::with_capacity(MAX_DATAGRAM);
    let (comp_tx, comp_rx) = flume::bounded::<Completion>(MAX_INFLIGHT_PER_CORE * 2);
    let inflight = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let mut epoch_ctr: u64 = 0;
    // quinn-udp socket state for GSO send (probes UDP_SEGMENT support once per core).
    let udp_state = {
        let bfd = unsafe { BorrowedFd::borrow_raw(udp.as_raw_fd()) };
        UdpSocketState::new(UdpSockRef::from(&bfd))?
    };
    let max_gso = udp_state.max_gso_segments();
    // GRO recv: drain many datagrams per readiness wake into reused buffers (one recvmmsg
    // returns up to GRO_BATCH messages, each GRO-coalescing up to ~64 segments). Batching ACK
    // processing into ONE flush per wake stops the send-bunching (one flush per ACK) that
    // overwhelmed the path and caused ~48% loss on large transfers.
    let mut recv_bufs: [Vec<u8>; GRO_BATCH] = std::array::from_fn(|_| vec![0u8; MAX_DATAGRAM]);
    let mut recv_metas = [quinn_udp::RecvMeta::default(); GRO_BATCH];
    let mut draining = false;
    let mut drain_deadline: Option<Instant> = None;
    loop {
        crate::memtrim::collect_if_requested_on_thread();
        if draining && h3_drain_complete(&h3, inflight.get(), comp_rx.is_empty()) {
            close_h3_connections(
                &udp,
                &udp_state,
                max_gso,
                &mut conns,
                b"shutdown",
                &mut tx_scratch,
            )
            .await;
            return Ok(());
        }
        let now = Instant::now();
        if drain_deadline.is_some_and(|deadline| now >= deadline) {
            close_h3_connections(
                &udp,
                &udp_state,
                max_gso,
                &mut conns,
                b"drain deadline",
                &mut tx_scratch,
            )
            .await;
            return Ok(());
        }
        let next_timeout = conns
            .values_mut()
            .filter_map(|c| c.poll_timeout())
            .chain(drain_deadline)
            .min();
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
                pump(&udp, &udp_state, max_gso, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut tx_scratch, &mut endpoint, &mut conns, &mut h3, &mut epoch_ctr, &inflight, &bridge, local, require_client_cert, &comp_tx, &runtime, false, handles).await;
            }
            // (1) Finished request(s): write each response into its stream, then pump the
            // sends (the response streams out cooperatively, interleaved with ACK processing).
            comp = comp_rx.recv_async() => {
                let now = Instant::now();
                let mut to_drive: std::collections::HashSet<ConnectionHandle> = std::collections::HashSet::new();
                if let Ok(c) = comp {
                    let hd = c.conn;
                    write_completion(&udp, &udp_state, max_gso, &mut conns, &mut h3, c, now, &mut tx_scratch).await;
                    to_drive.insert(hd);
                }
                while let Ok(c) = comp_rx.try_recv() {
                    let hd = c.conn;
                    write_completion(&udp, &udp_state, max_gso, &mut conns, &mut h3, c, now, &mut tx_scratch).await;
                    to_drive.insert(hd);
                }
                pump(&udp, &udp_state, max_gso, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut tx_scratch, &mut endpoint, &mut conns, &mut h3, &mut epoch_ctr, &inflight, &bridge, local, require_client_cert, &comp_tx, &runtime, !draining, to_drive).await;
            }
            // (2) Socket readable: GRO-drain queued datagrams, then pump (drive affected conns
            // + interleave further ACK processing). `readable()` is a poll op (cancel-safe).
            _ = udp.readable(false) => {
                let now = Instant::now();
                let affected = recv_drain(&udp, &udp_state, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut tx_scratch, &mut endpoint, &mut conns, &mut h3, &mut epoch_ctr, &runtime, !draining, now).await;
                pump(&udp, &udp_state, max_gso, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut tx_scratch, &mut endpoint, &mut conns, &mut h3, &mut epoch_ctr, &inflight, &bridge, local, require_client_cert, &comp_tx, &runtime, !draining, affected).await;
            }
            // (3) A quinn-proto timer fired (handshake retransmit / idle / pacing) — pump the
            // connections whose timer is due.
            _ = sleep_until_opt(next_timeout, timer_base) => {
                let now = Instant::now();
                let due: std::collections::HashSet<ConnectionHandle> = conns
                    .iter_mut()
                    .filter_map(|(hd, c)| c.poll_timeout().filter(|t| *t <= now).map(|_| *hd))
                    .collect();
                pump(&udp, &udp_state, max_gso, &mut recv_bufs, &mut recv_metas, &mut scratch, &mut tx_scratch, &mut endpoint, &mut conns, &mut h3, &mut epoch_ctr, &inflight, &bridge, local, require_client_cert, &comp_tx, &runtime, !draining, due).await;
            }
        }
    }
}

// ───────────────────────── real-pipeline H3 ─────────────────────────
// Decode the client's QPACK request headers + H3 frames, build an hj_core::Request,
// dispatch it through the cross-runtime bridge (the SAME pipeline the H1/H2 uring paths
// use), and encode the real response. This is the production H3 implementation; the
// tokio/quinn transport adapter no longer exists.

use crate::uring::bridge::{Bridge, BridgeCtx};
use hj_core::Proto;
use tokio_util::sync::CancellationToken;

/// RFC 9204 Appendix A QPACK static table (index 0..=98). The dynamic table is unused
/// (we advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY=0), so this + literals + Huffman fully
/// decode any conformant request header block.
static QPACK_STATIC: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Read a QUIC/HTTP-3 variable-length integer (RFC 9000 §16) at `*pos`.
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

/// Read a QPACK prefixed integer (RFC 7541 §5.1) starting at the type byte `buf[*pos]`,
/// using the low `prefix_bits` bits; consumes the first byte + any continuation bytes.
fn qpack_read_int(buf: &[u8], pos: &mut usize, prefix_bits: u32) -> Option<u64> {
    let first = *buf.get(*pos)?;
    *pos += 1;
    let max = (1u64 << prefix_bits) - 1;
    let mut val = (first as u64) & max;
    if val < max {
        return Some(val);
    }
    let mut m = 0u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        val = val.checked_add(((b & 0x7f) as u64) << m)?;
        if b & 0x80 == 0 {
            break;
        }
        m += 7;
        if m > 62 {
            return None;
        }
    }
    Some(val)
}

/// Read a QPACK string literal: an `H` (Huffman) bit at bit position `prefix_bits`, a
/// `prefix_bits`-prefixed length, then the bytes (Huffman-decoded when H=1).
fn qpack_read_str_limited(
    buf: &[u8],
    pos: &mut usize,
    prefix_bits: u32,
    max_output: usize,
) -> Option<Vec<u8>> {
    let huff = (*buf.get(*pos)? >> prefix_bits) & 1 == 1;
    let len = qpack_read_int(buf, pos, prefix_bits)? as usize;
    let raw = buf.get(*pos..(*pos).checked_add(len)?)?;
    *pos += len;
    if huff {
        hj_h2::hpack::huffman::decode_limited(raw, max_output)
    } else {
        (raw.len() <= max_output).then(|| raw.to_vec())
    }
}

/// Decode a QPACK encoded field section (RFC 9204 §4.5) into (name, value) pairs. Supports
/// the static table + literals + Huffman; rejects any dynamic/post-base reference (unused).
#[cfg(test)]
fn qpack_decode(buf: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    qpack_decode_limited(buf, usize::MAX).map(|(headers, _)| headers)
}

fn qpack_decode_limited(
    buf: &[u8],
    max_field_section_size: usize,
) -> Option<(Vec<(Vec<u8>, Vec<u8>)>, usize)> {
    let mut pos = 0usize;
    qpack_read_int(buf, &mut pos, 8)?; // Required Insert Count (0)
    qpack_read_int(buf, &mut pos, 7)?; // Delta Base (sign bit + 7-bit prefix; 0)
    let mut out = Vec::new();
    let mut decoded_size = 0usize;
    while pos < buf.len() {
        let first = buf[pos];
        if first & 0x80 != 0 {
            // Indexed Field Line; T (bit6): 1=static.
            let is_static = (first >> 6) & 1 == 1;
            let idx = qpack_read_int(buf, &mut pos, 6)? as usize;
            if !is_static {
                return None;
            }
            let (n, v) = QPACK_STATIC.get(idx)?;
            decoded_size = decoded_size
                .checked_add(n.len())?
                .checked_add(v.len())?
                .checked_add(32)?;
            if decoded_size > max_field_section_size {
                return None;
            }
            out.push((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
        } else if first & 0x40 != 0 {
            // Literal Field Line with Name Reference; T (bit4): 1=static.
            let is_static = (first >> 4) & 1 == 1;
            let idx = qpack_read_int(buf, &mut pos, 4)? as usize;
            if !is_static {
                return None;
            }
            let name_bytes = QPACK_STATIC.get(idx)?.0.as_bytes();
            let base = decoded_size
                .checked_add(name_bytes.len())?
                .checked_add(32)?;
            if base > max_field_section_size {
                return None;
            }
            let value = qpack_read_str_limited(buf, &mut pos, 7, max_field_section_size - base)?;
            decoded_size = base.checked_add(value.len())?;
            let name = name_bytes.to_vec();
            out.push((name, value));
        } else if first & 0x20 != 0 {
            // Literal Field Line with Literal Name (001 N H + 3-bit name length).
            let base = decoded_size.checked_add(32)?;
            if base > max_field_section_size {
                return None;
            }
            let name = qpack_read_str_limited(buf, &mut pos, 3, max_field_section_size - base)?;
            let with_name = base.checked_add(name.len())?;
            let value =
                qpack_read_str_limited(buf, &mut pos, 7, max_field_section_size - with_name)?;
            decoded_size = with_name.checked_add(value.len())?;
            out.push((name, value));
        } else {
            return None; // post-base / dynamic — unsupported (table capacity 0)
        }
    }
    Some((out, decoded_size))
}

struct ParsedH3Request {
    field: Vec<u8>,
    body: Bytes,
    trailers: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H3RequestParseError {
    Malformed,
    UnexpectedFrame,
}

/// Parse an HTTP/3 request stream while preserving the initial and trailing field sections.
/// DATA payloads are compacted into the input allocation as frames are decoded, so a large
/// request never coexists with a second full-body allocation.
fn parse_h3_request(mut data: Vec<u8>) -> Result<ParsedH3Request, H3RequestParseError> {
    let mut pos = 0usize;
    let mut field: Option<Vec<u8>> = None;
    let mut body_len = 0usize;
    let mut trailers: Option<Vec<u8>> = None;
    while pos < data.len() {
        let ty = read_varint(&data, &mut pos).ok_or(H3RequestParseError::Malformed)?;
        let len =
            usize::try_from(read_varint(&data, &mut pos).ok_or(H3RequestParseError::Malformed)?)
                .map_err(|_| H3RequestParseError::Malformed)?;
        let end = pos
            .checked_add(len)
            .filter(|end| *end <= data.len())
            .ok_or(H3RequestParseError::Malformed)?;
        match ty {
            0x01 => {
                if field.is_none() {
                    field = Some(data[pos..end].to_vec());
                } else if trailers.is_none() {
                    trailers = Some(data[pos..end].to_vec());
                } else {
                    return Err(H3RequestParseError::Malformed);
                }
            }
            0x00 => {
                if field.is_none() || trailers.is_some() {
                    return Err(H3RequestParseError::Malformed);
                }
                let body_end = body_len
                    .checked_add(len)
                    .ok_or(H3RequestParseError::Malformed)?;
                data.copy_within(pos..end, body_len);
                body_len = body_end;
            }
            ty if request_frame_forbidden(ty) => {
                return Err(H3RequestParseError::UnexpectedFrame);
            }
            _ => {} // extension and grease frame types are ignored as required
        }
        pos = end;
    }
    let field = field.ok_or(H3RequestParseError::Malformed)?;
    let body = if body_len == 0 {
        Bytes::new()
    } else {
        data.truncate(body_len);
        Bytes::from(data)
    };
    Ok(ParsedH3Request {
        field,
        body,
        trailers,
    })
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

/// Encode an HTTP/3 response HEADERS frame (QPACK literal field section). Split out so the
/// streaming path can send the head before the body and frame each DATA chunk separately.
fn encode_h3_headers_frame(status: http::StatusCode, headers: &http::HeaderMap) -> Vec<u8> {
    let mut field = Vec::new();
    field.extend_from_slice(&[0x00, 0x00]); // field section prefix: RIC=0, Base=0
    qpack_literal(&mut field, b":status", status.as_str().as_bytes());
    for (name, value) in headers {
        qpack_literal(&mut field, name.as_str().as_bytes(), value.as_bytes());
    }
    let mut out = Vec::new();
    write_varint(&mut out, 0x01); // HEADERS
    write_varint(&mut out, field.len() as u64);
    out.extend_from_slice(&field);
    out
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

/// A minimal HTTP/3 error response (status only).
fn h3_error(status: http::StatusCode) -> Vec<u8> {
    encode_h3_response(status, &http::HeaderMap::new(), b"")
}

/// The result of dispatching an H3 request: either a whole buffered response (errors,
/// small/HIT bodies — sent as one `Completion::Full`) or a streamed response (HEADERS frame
/// + a chunk source the spawn task forwards as `Completion::Chunk`s, so a large body flows
/// out as the backend produces it instead of buffering whole).
enum H3Outcome {
    Full(Vec<u8>),
    Stream {
        head: Vec<u8>,
        rx: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, ()>>,
    },
}

struct H3RequestHeaders {
    method: Vec<u8>,
    path: Vec<u8>,
    authority: Option<Vec<u8>>,
    regular: Vec<(Vec<u8>, Vec<u8>)>,
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
            name.first() != Some(&b':')
                && !name.iter().any(|b| b.is_ascii_uppercase())
                && !hj_core::is_connection_specific_request_header(
                    std::str::from_utf8(&name).unwrap_or(""),
                )
                && !(name.as_slice() == b"te"
                    && !value.as_slice().eq_ignore_ascii_case(b"trailers"))
                && !matches!(value.first(), Some(b' ' | b'\t'))
                && !matches!(value.last(), Some(b' ' | b'\t'))
        })
    })
}

/// Decode one io_uring-H3 request, dispatch it through the bridge (real pipeline), and
/// encode the response. App-layer mTLS mirrors the TCP TLS path.
async fn handle_h3_request(
    req_bytes: Vec<u8>,
    has_client_cert: bool,
    tls: Option<hj_core::TlsParams>,
    peer: SocketAddr,
    local: SocketAddr,
    bridge: &Bridge,
    require_client_cert: bool,
    request_limits: H3RequestLimits,
) -> H3Outcome {
    if require_client_cert && !has_client_cert && !hj_core::is_trusted_internal_peer(peer.ip()) {
        return H3Outcome::Full(h3_error(http::StatusCode::FORBIDDEN));
    }
    let parsed = match parse_h3_request(req_bytes) {
        Ok(v) => v,
        Err(_) => return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST)),
    };
    if parsed.body.len() > request_limits.max_body_bytes {
        return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST));
    }
    let (headers, initial_field_size) =
        match qpack_decode_limited(&parsed.field, request_limits.max_header_bytes) {
            Some(decoded) => decoded,
            None => return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST)),
        };
    if parsed.trailers.as_deref().is_some_and(|field| {
        !valid_h3_trailers(
            field,
            request_limits
                .max_header_bytes
                .saturating_sub(initial_field_size),
        )
    }) {
        return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST));
    }
    let H3RequestHeaders {
        method,
        path,
        authority,
        regular,
    } = match split_h3_request_headers(headers) {
        Some(h) => h,
        None => return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST)),
    };
    // RFC 9114 §4.3.1 (mirrors RFC 9113 §8.3.1): :path MUST be origin-form ("/…") or "*"
    // (OPTIONS) — never absolute-form. An absolute-form :path carrying its own scheme/authority
    // would let uri().host() disagree with the routed :authority/Host (foreign-host
    // CDN-cache-protection bypass) and is malformed regardless.
    if !(path.first() == Some(&b'/') || path.as_slice() == b"*") {
        return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST));
    }
    // (N2) §4.1.2: a Content-Length that disagrees with the DATA length is malformed.
    // Parsed with the SAME strict resolver as H1 (#232 residual): ASCII-OWS trim,
    // digit-only — the old `trim().parse()` accepted "+5" (unsigned FromStr sign) and
    // obs-text-padded values that every conformant stack rejects.
    let declared_cl = {
        let values = regular
            .iter()
            .filter(|(n, _)| n.as_slice() == b"content-length")
            .map(|(_, v)| v.as_slice());
        match super::codec::resolve_content_length(values) {
            Ok(cl) => cl,
            Err(()) => return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST)),
        }
    };
    if declared_cl.is_some_and(|cl| cl != parsed.body.len()) {
        return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST));
    }
    let body_b = parsed.body;
    let inbody: hj_core::IncomingBody = if body_b.is_empty() {
        hj_core::empty_incoming()
    } else {
        use http_body_util::BodyExt;
        http_body_util::Full::new(body_b)
            .map_err(|n| match n {})
            .boxed()
    };
    let mut builder = http::Request::builder().version(http::Version::HTTP_3);
    builder = match (std::str::from_utf8(&method), std::str::from_utf8(&path)) {
        (Ok(m), Ok(p)) => builder.method(m).uri(p),
        _ => return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST)),
    };
    // Host comes solely from :authority (matches the native H2 path, which inserts/replaces HOST).
    // The builder APPENDS, so a client-supplied regular `host` forwarded alongside :authority would
    // reach the backend as two values joined to HTTP_HOST="real, attacker" — a host-header
    // injection unique to H3. Drop any regular host; fall back to a single one only if :authority
    // is absent.
    let mut host_set = false;
    if let Some(a) = &authority {
        builder = builder.header("host", &a[..]);
        host_set = true;
    }
    for (n, v) in &regular {
        // RFC 9114 §4.1.2 / §8.2.1 (mirrors the native H2 stack, hj-h2/server/recv.rs): reject as
        // malformed when (a) a field NAME contains ASCII uppercase (http::HeaderName would silently
        // lowercase it, diverging from H2 which RSTs), (b) `te` carries any value other than
        // `trailers`, or (c) a value starts/ends with SP/HTAB. An unvalidated field is a smuggling
        // surface once re-serialized to a backend over HTTP/1.x; H2 and H3 must agree on what they
        // reject.
        if n.iter().any(|b| b.is_ascii_uppercase()) {
            return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST));
        }
        if hj_core::is_connection_specific_request_header(std::str::from_utf8(n).unwrap_or("")) {
            return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST));
        }
        if n.as_slice() == b"te" && !v.as_slice().eq_ignore_ascii_case(b"trailers") {
            return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST));
        }
        if matches!(v.first(), Some(b' ' | b'\t')) || matches!(v.last(), Some(b' ' | b'\t')) {
            return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST));
        }
        if n.as_slice().eq_ignore_ascii_case(b"host") {
            if !host_set {
                builder = builder.header("host", &v[..]);
                host_set = true;
            }
            continue; // never forward a second host
        }
        builder = builder.header(&n[..], &v[..]);
    }
    let mut req = match builder.body(inbody) {
        Ok(r) => r,
        Err(_) => return H3Outcome::Full(h3_error(http::StatusCode::BAD_REQUEST)),
    };
    hj_core::coalesce_cookie_crumbs(req.headers_mut());
    // SNI/routing key from :authority — the secure-listener router key. IPv6-aware
    // (a naive `split(':')` mangles a bracketed `[::1]:443` to `[`); `host_without_port`
    // also matches how `Router::resolve` normalizes the key, so an IPv6 :authority
    // routes to the intended vhost instead of falling through to the default.
    let sni: Option<Arc<str>> = authority
        .as_deref()
        .and_then(|a| std::str::from_utf8(a).ok())
        .map(|s| Arc::from(hj_core::host_without_port(s).as_str()));
    let ctx = BridgeCtx {
        peer,
        local,
        proto: Proto::Http3,
        is_tls: true,
        mtls_required: require_client_cert,
        sni,
        tls,
    };
    // A HEAD response must carry no DATA (RFC 9114): even if the pipeline streams a body,
    // emit headers only and don't open a streamed body.
    let is_head = req.method() == http::Method::HEAD;
    match bridge.dispatch(req, ctx).await {
        Some(r) => {
            let status = r.status;
            let mut headers = r.headers;
            let streaming_unknown_len = matches!(
                &r.body,
                crate::uring::bridge::BridgeBody::Stream { len: None, .. }
            );
            let body_forbidden =
                prepare_h3_response_headers(&mut headers, is_head, status, streaming_unknown_len);
            match r.body {
                // Small / HIT / sub-threshold dynamic bodies: buffered + sent whole — byte-identical
                // to the previous path.
                crate::uring::bridge::BridgeBody::Full(b) => {
                    let body = if body_forbidden { &[][..] } else { &b[..] };
                    H3Outcome::Full(encode_h3_response(status, &headers, body))
                }
                // Large / SSE / proxy bodies: stream the HEADERS now and forward DATA chunks as the
                // backend produces them, instead of buffering the whole body first.
                crate::uring::bridge::BridgeBody::Stream { mut rx, .. } => {
                    let head = encode_h3_headers_frame(status, &headers);
                    if body_forbidden {
                        rx.close();
                        H3Outcome::Full(head)
                    } else {
                        H3Outcome::Stream { head, rx }
                    }
                }
            }
        }
        None => H3Outcome::Full(h3_error(http::StatusCode::BAD_GATEWAY)),
    }
}

/// Real-pipeline io_uring H3 listener: per-core monoio runtimes driving quinn-proto, each
/// dispatching requests through `bridge`. This is the ONLY H3 transport (the tokio/quinn
/// adapter was removed 2026-06-21); production serves H3 here unconditionally.
pub(crate) fn serve_h3_pipeline(
    addr: SocketAddr,
    workers: usize,
    rustls_cfg: Arc<rustls::ServerConfig>,
    bridge: Bridge,
    require_client_cert: bool,
    runtime: H3RuntimeConfig,
    inherited: Option<Vec<std::net::UdpSocket>>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let sockets = h3_udp_sockets(inherited, addr, workers)?;
    let worker_count = sockets.len();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    for (core, std_sock) in sockets.into_iter().enumerate() {
        let cfg = rustls_cfg.clone();
        let bridge = bridge.clone();
        let runtime = runtime.clone();
        let shutdown = shutdown.clone();
        let ready = ready_tx.clone();
        std::thread::Builder::new()
            .name(format!("hj-uring-h3p-{core}"))
            .stack_size(crate::RUNTIME_THREAD_STACK_BYTES)
            .spawn(move || {
                per_core_h3_pipeline(
                    core,
                    std_sock,
                    addr,
                    cfg,
                    bridge,
                    require_client_cert,
                    runtime,
                    shutdown,
                    ready,
                )
            })?;
    }
    drop(ready_tx);
    super::wait_for_worker_readiness("HTTP/3", worker_count, ready_rx)?;
    Ok(())
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
    rustls_cfg: Arc<rustls::ServerConfig>,
    bridge: Bridge,
    require_client_cert: bool,
    runtime: H3RuntimeConfig,
    shutdown: CancellationToken,
    ready: super::WorkerReadyTx,
) {
    let server_cfg = match server_config(rustls_cfg) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            let _ = ready.send(Err(format!("build QUIC server config: {e}")));
            tracing::error!(core, error = %e, "uring h3-pipeline: server config build failed");
            return;
        }
    };
    let mut rt = match monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .build()
    {
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
        let endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), Some(server_cfg), true, None);
        let _ = ready.send(Ok(()));
        tracing::info!(core, "uring h3-pipeline: per-core quinn-proto endpoint serving (real pipeline via bridge, concurrent dispatch)");
        if let Err(e) = endpoint_loop_concurrent(udp, endpoint, local, bridge, require_client_cert, runtime, shutdown).await {
            tracing::error!(core, error = %e, "uring h3-pipeline: endpoint loop ended");
        }
    });
}

#[cfg(test)]
mod h3_codec_tests {
    use super::*;

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

    // A dynamic-table reference (we advertise capacity 0) must be rejected, not misdecoded.
    #[test]
    fn qpack_decode_rejects_dynamic() {
        let buf = vec![0x00, 0x00, 0x80 | 5]; // Indexed, T=dynamic (bit6=0)
        assert!(qpack_decode(&buf).is_none());
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
        use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

        let cap = Arc::new(AtomicU32::new(2));
        let header = Arc::new(AtomicUsize::new(16_380));
        let body = Arc::new(AtomicUsize::new(100 * 1024 * 1024));
        let cap_read = cap.clone();
        let header_read = header.clone();
        let body_read = body.clone();
        let runtime = H3RuntimeConfig::new(
            move || {
                (
                    H3RequestLimits::new(
                        header_read.load(Ordering::Relaxed),
                        body_read.load(Ordering::Relaxed),
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
        cap.store(7, Ordering::Relaxed);
        header.store(8_192, Ordering::Relaxed);
        body.store(32 * 1024 * 1024, Ordering::Relaxed);
        assert_eq!(runtime.max_connections(), 7);
        assert_eq!(runtime.request_limits().max_header_bytes, 8_192);
        assert_eq!(runtime.request_limits().max_body_bytes, 32 * 1024 * 1024);
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
        for byte in valid.chunks(1) {
            assert!(counter.consume(byte, limits).is_ok());
        }
        assert_eq!(counter.header_bytes, 4);
        assert_eq!(counter.body_bytes, 5);

        let mut header_too_large = H3FrameCounter::default();
        assert_eq!(
            header_too_large.consume(&[0x01, 5], limits),
            Err(RequestFrameError::Limit)
        );
        let mut body_too_large = H3FrameCounter::default();
        assert_eq!(
            body_too_large.consume(&[0x00, 6], limits),
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
            for byte in &encoded[..encoded.len() - 1] {
                assert!(counter.consume(std::slice::from_ref(byte), limits).is_ok());
            }
            assert_eq!(
                counter.consume(&encoded[encoded.len() - 1..], limits),
                Err(RequestFrameError::Unexpected)
            );
        }

        let extension = vec![0x01, 0x02, 0x00, 0x00, 0x21, 0x00];
        assert!(parse_h3_request(extension).is_ok());
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
        assert!(counter.consume(&exact, limits).is_ok());
        assert_eq!(counter.header_bytes, 2);
        assert_eq!(counter.body_bytes, LIVE_BODY_LIMIT);

        let mut body_over = Vec::new();
        write_varint(&mut body_over, 0x00);
        write_varint(&mut body_over, (LIVE_BODY_LIMIT + 1) as u64);
        assert_eq!(
            H3FrameCounter::default().consume(&body_over, limits),
            Err(RequestFrameError::Limit)
        );

        let mut header_exact = Vec::new();
        write_varint(&mut header_exact, 0x01);
        write_varint(&mut header_exact, LIVE_HEADER_LIMIT as u64);
        assert!(
            H3FrameCounter::default()
                .consume(&header_exact, limits)
                .is_ok()
        );
        let mut header_over = Vec::new();
        write_varint(&mut header_over, 0x01);
        write_varint(&mut header_over, (LIVE_HEADER_LIMIT + 1) as u64);
        assert_eq!(
            H3FrameCounter::default().consume(&header_over, limits),
            Err(RequestFrameError::Limit)
        );
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
        assert_eq!(dispatched.len(), 6);
        assert_eq!(
            st.total_req_bytes.get(),
            6,
            "spawned ownership remains charged"
        );
        assert!(append_request_bytes(&mut st, second, &[0x00, 4, 5, 6, 7, 8], limits).is_err());
        reclaim_request(&mut st, second);
        let charge = RequestChargeGuard {
            total: st.total_req_bytes.clone(),
            bytes: dispatched.len(),
        };
        drop(charge);
        assert_eq!(st.total_req_bytes.get(), 0);
        assert!(append_request_bytes(&mut st, second, &[0x00, 4, 5, 6, 7, 8], limits).is_ok());
    }

    #[test]
    fn streamed_chunk_ack_waits_until_driver_buffer_is_drained() {
        let (ack_tx, ack_rx) = flume::bounded(1);
        let part = PendingPart::data_frame(Bytes::from_static(b"abc"), Some(ack_tx));
        let mut pending = PendingSend {
            parts: std::iter::once(part).collect(),
            fin: false,
        };
        assert!(matches!(ack_rx.try_recv(), Err(flume::TryRecvError::Empty)));
        assert!(acknowledge_front_part(&mut pending));
        assert_eq!(ack_rx.try_recv(), Ok(()));
    }

    #[test]
    fn streamed_data_frame_retains_the_bridge_chunk_allocation() {
        let chunk = Bytes::from(vec![0x5a; 4096]);
        let pointer = chunk.as_ptr();
        let part = PendingPart::data_frame(chunk, None);
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
        let part = PendingPart::data_frame(Bytes::from_static(b"abc"), Some(ack_tx));
        let pending = PendingSend {
            parts: std::iter::once(part).collect(),
            fin: false,
        };
        drop(pending);
        assert!(matches!(
            ack_rx.try_recv(),
            Err(flume::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn cancelling_response_stream_cancels_dispatch_and_drops_pending_chunks() {
        let id = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 0);
        let token = CancellationToken::new();
        let (ack_tx, ack_rx) = flume::bounded(1);
        let mut state = H3State::default();
        state.request_cancellations.insert(id, token.clone());
        state.pending.insert(
            id,
            PendingSend {
                parts: std::iter::once(PendingPart::data_frame(
                    Bytes::from_static(b"backend chunk"),
                    Some(ack_tx),
                ))
                .collect(),
                fin: false,
            },
        );

        cancel_dispatched_request(&mut state, id);

        assert!(token.is_cancelled());
        assert!(!state.request_cancellations.contains_key(&id));
        assert!(!state.pending.contains_key(&id));
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
        // A second, still-open stream must be untouched.
        let other = StreamId::new(quinn_proto::Side::Client, Dir::Bi, 1);
        st.requests.insert(other);
        st.req_buf.insert(other, b"keep".to_vec());
        st.total_req_bytes
            .set(b"partial body".len() + b"keep".len());

        let drained = reclaim_request(&mut st, id);
        assert_eq!(drained, b"partial body");
        assert!(!st.requests.contains(&id), "slot must be removed");
        assert!(!st.req_buf.contains_key(&id), "buffer must be removed");
        // The unrelated open stream is retained.
        assert!(st.requests.contains(&other));
        assert_eq!(
            st.req_buf.get(&other).map(|b| b.as_slice()),
            Some(&b"keep"[..])
        );
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
    fn request_body_is_compacted_in_place_without_a_second_full_copy() {
        let field = [0x00, 0x00];
        let mut stream = Vec::with_capacity(64 * 1024);
        write_varint(&mut stream, 0x01);
        write_varint(&mut stream, field.len() as u64);
        stream.extend_from_slice(&field);
        for chunk in [b"first".as_slice(), b"-second".as_slice()] {
            write_varint(&mut stream, 0x00);
            write_varint(&mut stream, chunk.len() as u64);
            stream.extend_from_slice(chunk);
        }
        let allocation = stream.as_ptr();
        let parsed = parse_h3_request(stream).unwrap();
        assert_eq!(parsed.body.as_ref(), b"first-second");
        assert_eq!(
            parsed.body.as_ptr(),
            allocation,
            "body compaction must reuse the request-wire allocation"
        );
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
