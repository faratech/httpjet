//! Per-upstream keep-alive connection pooling.
//!
//! Each [`Upstream`] owns an idle pool of established HTTP/1.1 client
//! connections to a single authority. Connections are checked out for one
//! request, then returned to the pool if they are still reusable and have not
//! exceeded `pc_keep_alive_timeout`. The pool is bounded by `max_conns`.
//!
//! We use `hyper::client::conn::http1` directly (rather than the higher-level
//! pooled `hyper_util` client) so we control the request/response body type
//! ([`hj_core::Body`] outbound, a boxed stream inbound) and so we can stream the
//! response straight through with no read-idle timeout — essential for SSE and
//! long-lived proxied streams.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hyper::client::conn::http1::SendRequest;
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;

use crate::error::ProxyError;
use crate::target::{ProxyTarget, TargetTransport};

/// Process-shared rustls client config for upstream TLS, built once on first use: the webpki
/// (Mozilla) root store, server-auth only, no client certificate. The default crypto provider
/// (aws-lc-rs) is installed at server startup by `hj-tls`, so `builder()` resolves it.
fn client_tls_config(http2: bool) -> Arc<rustls::ClientConfig> {
    static H1_CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static H2_CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let slot = if http2 { &H2_CFG } else { &H1_CFG };
    slot.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(with_upstream_alpn(config, http2))
    })
    .clone()
}

/// Keep TLS protocol negotiation aligned with the explicitly selected upstream
/// transport. `https://` is the HTTP/1 arm and therefore offers no ALPN; `h2s://`
/// offers only `h2` and is checked again after the handshake before any HTTP bytes
/// are sent.
fn with_upstream_alpn(mut config: rustls::ClientConfig, http2: bool) -> rustls::ClientConfig {
    config.alpn_protocols = if http2 {
        vec![b"h2".to_vec()]
    } else {
        Vec::new()
    };
    config
}

fn require_h2_alpn(authority: &str, negotiated: Option<&[u8]>) -> Result<(), ProxyError> {
    if negotiated == Some(b"h2".as_slice()) {
        Ok(())
    } else {
        Err(ProxyError::Handshake(format!(
            "TLS upstream {authority} negotiated no h2 ALPN"
        )))
    }
}

/// (Tier 2) Build a TLS client config with upstream mTLS client authentication.
/// The cert/key pair authenticates this origin to the upstream backend.
fn client_tls_config_with_cert(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    http2: bool,
) -> Result<Arc<rustls::ClientConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(
        cert_path,
    )?))
    .collect::<Result<Vec<_>, _>>()?;
    let key =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key_path)?))?
            .ok_or("no private key found")?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?;
    Ok(Arc::new(with_upstream_alpn(config, http2)))
}

/// Resolve the explicitly configured upstream TLS identity. Anonymous TLS is
/// valid only when neither credential path is configured; an incomplete or
/// unusable identity must remain a hard dial error rather than silently
/// disabling client authentication.
fn upstream_tls_config(
    cert_path: Option<&std::path::Path>,
    key_path: Option<&std::path::Path>,
    http2: bool,
) -> Result<Arc<rustls::ClientConfig>, String> {
    match (cert_path, key_path) {
        (None, None) => Ok(client_tls_config(http2)),
        (Some(cert), Some(key)) => client_tls_config_with_cert(cert, key, http2)
            .map_err(|e| format!("invalid upstream client TLS certificate/key: {e}")),
        _ => Err(
            "upstream client TLS authentication requires both clientCertFile and clientKeyFile"
                .to_string(),
        ),
    }
}

/// Consecutive connect failures before the circuit breaker opens.
const CB_THRESHOLD: u32 = 3;
/// How long the breaker stays open before allowing a half-open trial dial.
const CB_HALF_OPEN_AFTER: Duration = Duration::from_secs(10);
/// Default upstream response-head timeout: how long to wait for the upstream to
/// return response *headers* (the streamed body is unaffected, so SSE / long
/// downloads still flow freely). Bounds a hung backend that accepts the
/// connection then never replies, which would otherwise pin the pool slot.
const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// The outbound request body type sent to upstreams.
///
/// This is the workspace `StreamBody` (`BoxBody<Bytes, BoxError>`), i.e. the
/// same type as an inbound request body, so the client request body is
/// forwarded verbatim with no buffering and a real `http_body::Body` impl.
pub(crate) type OutBody = hj_core::StreamBody;

/// (Tier 2) Protocol-agnostic pooled sender. hyper 1.x types the http1 and
/// http2 client senders as DISTINCT types, so the pool (and `forward`) erase
/// the arm behind this enum and delegate the three calls they need.
pub(crate) enum AnySender {
    H1(SendRequest<OutBody>),
    H2(hyper::client::conn::http2::SendRequest<OutBody>),
}

impl AnySender {
    pub(crate) fn is_h2(&self) -> bool {
        matches!(self, AnySender::H2(_))
    }

    pub(crate) fn is_ready(&self) -> bool {
        match self {
            AnySender::H1(s) => s.is_ready(),
            AnySender::H2(s) => s.is_ready(),
        }
    }

    pub(crate) async fn ready(&mut self) -> Result<(), hyper::Error> {
        match self {
            AnySender::H1(s) => s.ready().await,
            AnySender::H2(s) => s.ready().await,
        }
    }

    pub(crate) async fn send_request(
        &mut self,
        req: http::Request<OutBody>,
    ) -> Result<http::Response<hyper::body::Incoming>, hyper::Error> {
        match self {
            AnySender::H1(s) => s.send_request(req).await,
            AnySender::H2(s) => s.send_request(req).await,
        }
    }
}

/// A pooled, ready-to-use upstream connection.
pub(crate) struct PooledConn {
    pub(crate) sender: AnySender,
    /// When this connection was last returned to the pool (for idle expiry).
    idle_since: Instant,
}

/// A single reverse-proxy upstream: an authority plus its idle connection pool.
pub struct Upstream {
    /// Logical name / pool key.
    pub name: String,
    /// `host:port` (or `localhost` for UDS) used for the upstream `Host`
    /// fallback and TCP dial.
    pub authority: String,
    transport: TargetTransport,
    /// (Tier 2) Speak HTTP/2 prior knowledge to this upstream (`h2://`/`h2s://`).
    requires_h2: bool,
    /// SNI / cert-verification name for the TLS handshake (the authority host, no port). When
    /// `requires_tls` is set but this is `None` (unparseable authority), a dial fails closed
    /// rather than silently falling back to plaintext.
    tls_server_name: Option<ServerName<'static>>,
    /// Max simultaneous + idle connections retained.
    max_conns: u32,
    /// Concurrency limiter (LiteSpeed `maxConns`): at most `max_conns` requests may be in
    /// flight to this upstream at once. A permit is held for the whole request+response
    /// lifetime, so this bounds active concurrency — not just idle-pool retention.
    sem: Arc<Semaphore>,
    /// Idle keep-alive lifetime; connections idle longer than this are dropped.
    keep_alive: Duration,
    /// Dial / handshake timeout.
    connect_timeout: Duration,
    /// Max time to wait for upstream response *headers* (not the body).
    response_timeout: Duration,
    idle: Mutex<Vec<PooledConn>>,
    /// Consecutive connect-failure count feeding the circuit breaker.
    fail_count: AtomicU32,
    /// When the breaker opened (`None` = closed). While open, checkout fast-fails
    /// without dialing, avoiding a connect-timeout storm against a dead upstream.
    tripped_at: Mutex<Option<Instant>>,
    /// TLS client configuration is built at pool construction. Retaining an
    /// error makes every dial fail before opening a socket until config reload.
    tls_config: Option<Result<Arc<rustls::ClientConfig>, Arc<str>>>,
    /// (Tier 1.2) Shared with the owning [`UpstreamPool`]: epoch-ms until which the
    /// POOL skips this peer for new requests (failover). Set when the breaker trips,
    /// cleared on a successful dial.
    bad_until: Mutex<Option<Arc<AtomicU64>>>,
}

impl Upstream {
    /// Create an upstream from a [`ProxyTarget`] with the given pool limits.
    pub(crate) fn new(
        target: &ProxyTarget,
        max_conns: u32,
        keep_alive: Duration,
        connect_timeout: Duration,
    ) -> Arc<Upstream> {
        let max_conns = max_conns.max(1);
        let requires_tls = target.is_tls();
        let requires_h2 = target.http2;
        let tls_config = requires_tls.then(|| {
            upstream_tls_config(
                target.client_cert_file.as_deref(),
                target.client_key_file.as_deref(),
                requires_h2,
            )
            .map_err(Arc::<str>::from)
        });
        let tls_server_name = if requires_tls {
            // SNI + cert-verification name = the authority host (port/brackets removed).
            match ServerName::try_from(hj_core::host_without_port(&target.authority)) {
                Ok(name) => Some(name),
                Err(e) => {
                    tracing::warn!(
                        authority = %target.authority, error = %e,
                        "proxy: TLS upstream has an unparseable server name; dials will fail closed"
                    );
                    None
                }
            }
        } else {
            None
        };
        Arc::new(Upstream {
            name: target.pool_key(),
            authority: target.authority.clone(),
            transport: target.transport.clone(),
            requires_h2,
            tls_server_name,
            sem: Arc::new(Semaphore::new(max_conns as usize)),
            max_conns,
            keep_alive,
            connect_timeout: if connect_timeout.is_zero() {
                Duration::from_secs(10)
            } else {
                connect_timeout
            },
            response_timeout: DEFAULT_RESPONSE_TIMEOUT,
            idle: Mutex::new(Vec::new()),
            fail_count: AtomicU32::new(0),
            tripped_at: Mutex::new(None),
            tls_config,
            bad_until: Mutex::new(None),
        })
    }

    /// Upper bound on how long a request PARKS waiting for a `maxConns` slot.
    /// `connect_timeout` doubles as this wait for extProcessor targets, and prod
    /// configures `initTimeout=600s` there — parking every new request ~10 minutes
    /// while holding bridge admission slots (audit) is worse than shedding. Cap the
    /// QUEUE wait at 10 s; the CONNECT itself still gets the full `connect_timeout`.
    const MAX_QUEUE_WAIT: Duration = Duration::from_secs(10);

    /// Acquire a concurrency permit (LiteSpeed `maxConns`): at most `max_conns` requests may
    /// be in flight to this upstream concurrently. Waits up to [`Self::MAX_QUEUE_WAIT`] for a
    /// free slot; `None` means the upstream is saturated and the caller should return `503`. The
    /// returned permit is held for the whole request+response lifetime (see [`crate::Proxy::forward`]).
    pub(crate) async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        let wait = self.connect_timeout.min(Self::MAX_QUEUE_WAIT);
        match tokio::time::timeout(wait, self.sem.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Some(permit),
            _ => None,
        }
    }

    /// The configured response-head timeout (see [`Proxy::forward`]).
    pub(crate) fn response_timeout(&self) -> Duration {
        self.response_timeout
    }

    /// True if the circuit breaker is currently open (recent connect failures).
    /// Side effect: once the open window has elapsed it admits ONE half-open trial
    /// dial and re-arms the window, so concurrent checkouts stay fast-failed until
    /// that trial resolves.
    fn breaker_open(&self) -> bool {
        let mut tripped = self.tripped_at.lock();
        match *tripped {
            Some(at) if at.elapsed() < CB_HALF_OPEN_AFTER => true,
            Some(_) => {
                // Half-open: admit EXACTLY ONE trial dial per window. RE-ARM the window
                // (rather than clearing to None) so any concurrent/subsequent checkout sees
                // "open" again until this trial reports back — a success clears `tripped_at`
                // (closing the breaker), a failure leaves it armed. Clearing to None let an
                // entire burst dial a still-dead upstream at once. Re-arming (vs a separate
                // in-flight flag) self-heals: a trial that never reports back simply lets the
                // window elapse again and admit one more probe — never a stuck-open breaker.
                *tripped = Some(Instant::now());
                false
            }
            None => false,
        }
    }

    /// Record a successful dial: reset the failure count and close the breaker
    /// (and clear the pool-level failover mark).
    fn note_dial_success(&self) {
        self.fail_count.store(0, Ordering::Relaxed);
        *self.tripped_at.lock() = None;
        if let Some(b) = self.bad_until.lock().as_ref() {
            b.store(0, Ordering::Relaxed);
        }
    }

    /// Record a failed dial: trip the breaker once the threshold is reached. A
    /// trip also marks the peer bad at the POOL level for one half-open window,
    /// so new requests fail over to the next peer instead of fast-failing here.
    fn note_dial_failure(&self) {
        let n = self.fail_count.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= CB_THRESHOLD {
            *self.tripped_at.lock() = Some(Instant::now());
            if let Some(b) = self.bad_until.lock().as_ref() {
                let until = now_epoch_ms() + CB_HALF_OPEN_AFTER.as_millis() as u64;
                b.store(until, Ordering::Relaxed);
            }
        }
    }

    /// Install the pool-shared failover handle (called once at pool creation).
    fn set_bad_until_handle(&self, handle: Arc<AtomicU64>) {
        *self.bad_until.lock() = Some(handle);
    }

    /// Number of connections currently idle in the pool (for tests/metrics).
    pub fn idle_count(&self) -> usize {
        self.idle.lock().len()
    }

    /// Check out a usable connection, reusing a live idle one if available, else
    /// dialing a new connection and driving it on a background task.
    pub(crate) async fn checkout(&self) -> Result<AnySender, ProxyError> {
        // Breaker open: fast-fail (502) instead of dialing a known-dead upstream
        // and eating a full connect timeout. Checked before idle reuse, since idle
        // entries to a dead upstream are stale anyway. Half-open trials fall through.
        if self.breaker_open() {
            return Err(ProxyError::CircuitOpen);
        }
        // Try to reuse a non-expired, still-open idle connection.
        loop {
            let candidate = {
                let mut idle = self.idle.lock();
                // (#27) Prune expired connections from ALL positions, not just the back.
                // `release` pushes fresh entries to the back, so the OLDEST live entries sit
                // at the front; popping only the back leaves stale front entries to linger,
                // inflating idle_count() and causing a cluster of is_ready()-false rejects +
                // extra dials under a burst. A single retain drops every expired entry in one
                // pass regardless of position; we then reuse the freshest (back).
                idle.retain(|c| c.idle_since.elapsed() <= self.keep_alive);
                idle.pop()
            };
            match candidate {
                Some(c) => {
                    if c.sender.is_ready() {
                        return Ok(c.sender);
                    }
                    // Closed/half-broken: drop and try the next idle entry.
                    continue;
                }
                None => break,
            }
        }
        // No reusable idle connection: dial fresh, feeding the breaker so a run of
        // connect failures opens it (and a success closes it).
        self.dial_tracked().await
    }

    /// Check out a connection for the one-shot retry in [`crate::Proxy::forward`]: ALWAYS a
    /// fresh dial, never a pooled entry.
    ///
    /// The retry exists because a pooled connection lost the idle-close race in
    /// [`Self::checkout`]'s `is_ready()` gate, and a backend that closed one idle connection
    /// has usually closed the whole batch (a worker recycle — uvicorn defaults to a 5 s
    /// keep-alive against our `pcKeepAliveTimeout` of 600 s). Taking another pooled entry
    /// would lose the same race with no third attempt left. Bounded like [`Self::acquire`]'s
    /// queue wait, because prod sets `initTimeout=600` on ext processors and a retry must not
    /// park for ten minutes.
    pub(crate) async fn checkout_fresh(&self) -> Result<AnySender, ProxyError> {
        if self.breaker_open() {
            return Err(ProxyError::CircuitOpen);
        }
        let budget = self.connect_timeout.min(Self::MAX_QUEUE_WAIT);
        match tokio::time::timeout(budget, self.dial_tracked()).await {
            Ok(r) => r,
            Err(_) => {
                // This budget is shorter than `dial`'s own `connect_timeout`, so it is the arm
                // that fires against a black-holed upstream. Cancelling `dial_tracked` skips
                // its bookkeeping, so record the failure here or the breaker never trips.
                self.note_dial_failure();
                Err(ProxyError::ConnectTimeout)
            }
        }
    }

    /// Dial, feeding the breaker so a run of connect failures opens it (and a success
    /// closes it).
    async fn dial_tracked(&self) -> Result<AnySender, ProxyError> {
        match self.dial().await {
            Ok(sender) => {
                self.note_dial_success();
                Ok(sender)
            }
            Err(e) => {
                self.note_dial_failure();
                Err(e)
            }
        }
    }

    /// Establish a fresh connection, spawn its background driver task, and
    /// return the request sender. The driver task differs per transport (its
    /// `Connection` type is IO-specific), so each arm spawns its own.
    async fn dial(&self) -> Result<AnySender, ProxyError> {
        match &self.transport {
            TargetTransport::Tcp(hostport) => {
                // Resolve configured TLS credentials before opening a socket. A
                // bad or incomplete identity is deterministic configuration,
                // not a transient backend failure and never falls back to
                // anonymous TLS.
                let tls_cfg = match self.tls_config.as_ref() {
                    Some(Ok(config)) => Some(config.clone()),
                    Some(Err(error)) => return Err(ProxyError::Other(error.to_string())),
                    None => None,
                };
                let connect = TcpStream::connect(hostport.clone());
                let stream = tokio::time::timeout(self.connect_timeout, connect)
                    .await
                    .map_err(|_| ProxyError::ConnectTimeout)?
                    .map_err(ProxyError::Connect)?;
                let _ = stream.set_nodelay(true);
                crate::set_tcp_keepalive(&stream);
                if let Some(tls_cfg) = tls_cfg {
                    // Complete the TLS handshake before HTTP. Fail closed if the server name
                    // never parsed (so an `https` target is never spoken to in cleartext).
                    let server_name = self.tls_server_name.clone().ok_or_else(|| {
                        ProxyError::Other(format!(
                            "TLS upstream {} has no valid server name",
                            self.authority
                        ))
                    })?;
                    let connector = TlsConnector::from(tls_cfg);
                    let tls = tokio::time::timeout(
                        self.connect_timeout,
                        connector.connect(server_name, stream),
                    )
                    .await
                    .map_err(|_| ProxyError::ConnectTimeout)?
                    .map_err(ProxyError::Connect)?;
                    if self.requires_h2 {
                        // h2s: the upstream MUST have negotiated h2 via ALPN —
                        // falling back to h1 over the same port would silently
                        // speak the wrong protocol.
                        require_h2_alpn(&self.authority, tls.get_ref().1.alpn_protocol())?;
                    }
                    self.http_handshake(tls).await
                } else {
                    self.http_handshake(stream).await
                }
            }
            #[cfg(unix)]
            TargetTransport::Uds(path) => {
                let connect = tokio::net::UnixStream::connect(path.clone());
                let stream = tokio::time::timeout(self.connect_timeout, connect)
                    .await
                    .map_err(|_| ProxyError::ConnectTimeout)?
                    .map_err(ProxyError::Connect)?;
                self.http_handshake(stream).await
            }
            #[cfg(not(unix))]
            TargetTransport::Uds(_) => Err(ProxyError::Other(
                "unix sockets unsupported on this platform".into(),
            )),
        }
    }

    /// Complete the HTTP/1.1 client handshake over an already-connected (optionally
    /// TLS-wrapped) stream and spawn its background connection driver, returning the sender.
    async fn h1_handshake<IO>(&self, io: IO) -> Result<AnySender, ProxyError>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(io);
        let (sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| ProxyError::Handshake(e.to_string()))?;
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!(error = %e, "upstream connection closed");
            }
        });
        Ok(AnySender::H1(sender))
    }

    /// Complete the HTTP client handshake appropriate for this upstream —
    /// HTTP/1.1, or HTTP/2 prior knowledge for `h2`/`h2s` targets — over an
    /// already-connected (optionally TLS-wrapped) stream. Both return the same
    /// hyper `SendRequest`, so checkout/release/forward are protocol-agnostic.
    async fn http_handshake<IO>(&self, io: IO) -> Result<AnySender, ProxyError>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        if self.requires_h2 {
            self.h2_handshake(io).await
        } else {
            self.h1_handshake(io).await
        }
    }

    /// HTTP/2 prior-knowledge client handshake. The connection driver is spawned
    /// WITHOUT upgrade relay (h2 has none); one multiplexed connection carries
    /// every concurrent stream, so an `!is_ready()` sender is not unhealthy —
    /// `release` simply lets it drop and the next checkout dials a fresh one.
    async fn h2_handshake<IO>(&self, io: IO) -> Result<AnySender, ProxyError>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(io);
        let (sender, conn): (hyper::client::conn::http2::SendRequest<OutBody>, _) =
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .handshake(io)
                .await
                .map_err(|e| ProxyError::Handshake(e.to_string()))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "upstream h2 connection closed");
            }
        });
        // Unlike h1, an h2 sender rejects send_request until the preface +
        // SETTINGS exchange completes — await it under the dial, not per request
        // (a send on a not-yet-ready h2 sender fails with hyper's Canceled).
        let mut sender = sender;
        sender
            .ready()
            .await
            .map_err(|e| ProxyError::Handshake(e.to_string()))?;
        Ok(AnySender::H2(sender))
    }

    /// Return a connection to the idle pool after a completed request, if it is
    /// still healthy and the pool has room.
    pub(crate) fn release(&self, sender: AnySender) {
        if !sender.is_ready() {
            return;
        }
        let mut idle = self.idle.lock();
        if idle.len() >= self.max_conns as usize {
            return; // pool full: let this connection drop & close
        }
        idle.push(PooledConn {
            sender,
            idle_since: Instant::now(),
        });
    }
}

/// A registry of upstreams keyed by [`ProxyTarget::pool_key`]. Lets the proxy
/// reuse pools across requests for both configured ext-processors and ad-hoc
/// rewrite targets.
#[derive(Default)]
pub struct UpstreamPool {
    pools: Mutex<HashMap<PoolKey, Arc<Upstream>>>,
    /// (Tier 1.2) Per-peer failover marks: epoch-ms until which the peer is skipped
    /// for NEW requests (set when the peer's breaker trips, cleared on a successful
    /// dial). Keyed by the same PoolKey as `pools`.
    bad_until: Mutex<HashMap<PoolKey, Arc<AtomicU64>>>,
    /// (Tier 1.2) Requests served by a failover peer because the primary was marked.
    failovers: AtomicU64,
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    name: Option<String>,
    scheme: String,
    authority: String,
    transport: TargetTransport,
    client_cert_file: Option<std::path::PathBuf>,
    client_key_file: Option<std::path::PathBuf>,
    max_conns: u32,
    keep_alive: Duration,
    connect_timeout: Duration,
}

impl PoolKey {
    fn new(
        target: &ProxyTarget,
        max_conns: u32,
        keep_alive: Duration,
        connect_timeout: Duration,
    ) -> Self {
        PoolKey {
            name: target.name.clone(),
            scheme: target.scheme.to_ascii_lowercase(),
            authority: target.authority.clone(),
            transport: target.transport.clone(),
            client_cert_file: target.client_cert_file.clone(),
            client_key_file: target.client_key_file.clone(),
            max_conns: max_conns.max(1),
            keep_alive,
            connect_timeout: if connect_timeout.is_zero() {
                Duration::from_secs(10)
            } else {
                connect_timeout
            },
        }
    }

    fn has_configured_tls_identity(&self) -> bool {
        self.client_cert_file.is_some() || self.client_key_file.is_some()
    }
}

impl UpstreamPool {
    pub fn new() -> Self {
        UpstreamPool {
            pools: Mutex::new(HashMap::new()),
            bad_until: Mutex::new(HashMap::new()),
            failovers: AtomicU64::new(0),
        }
    }

    /// Get (or lazily create) the [`Upstream`] for `target`, applying the given
    /// limits the first time it is seen.
    ///
    /// (Tier 1.2) When the target carries failover peers, a peer whose breaker
    /// tripped recently (marked bad for one half-open window by its own dial
    /// failures) is skipped in favor of the next peer; the primary is retried once
    /// its mark expires, so recovery is automatic and needs no active probing.
    pub fn get_or_create(
        &self,
        target: &ProxyTarget,
        max_conns: u32,
        keep_alive: Duration,
        connect_timeout: Duration,
    ) -> Arc<Upstream> {
        let peers = target.peers();
        let now_ms = now_epoch_ms();
        for (idx, peer) in peers.iter().enumerate() {
            let key = PoolKey::new(peer, max_conns, keep_alive, connect_timeout);
            let bad = {
                let bad = self.bad_until.lock();
                bad.get(&key)
                    .map(|a| a.load(Ordering::Relaxed))
                    .unwrap_or(0)
            };
            if bad > now_ms {
                continue; // peer in its failover cooldown — try the next
            }
            let handle = {
                let mut bad = self.bad_until.lock();
                Arc::clone(
                    bad.entry(key.clone())
                        .or_insert_with(|| Arc::new(AtomicU64::new(0))),
                )
            };
            let upstream = {
                let mut pools = self.pools.lock();
                pools
                    .entry(key)
                    .or_insert_with(|| {
                        let up = Upstream::new(peer, max_conns, keep_alive, connect_timeout);
                        up.set_bad_until_handle(handle);
                        up
                    })
                    .clone()
            };
            if idx > 0 {
                self.failovers.fetch_add(1, Ordering::Relaxed);
            }
            return upstream;
        }
        // Every peer marked bad: serve from the primary (its breaker half-open
        // window decides fast-fail vs trial dial) rather than refusing outright.
        let primary = &peers[0];
        let key = PoolKey::new(primary, max_conns, keep_alive, connect_timeout);
        let mut pools = self.pools.lock();
        pools
            .entry(key)
            .or_insert_with(|| Upstream::new(primary, max_conns, keep_alive, connect_timeout))
            .clone()
    }

    /// Requests served by a failover peer (Tier 1.2, for metrics).
    pub fn failovers_total(&self) -> u64 {
        self.failovers.load(Ordering::Relaxed)
    }

    /// Number of distinct upstream pools (for tests/metrics).
    pub fn len(&self) -> usize {
        self.pools.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.pools.lock().is_empty()
    }

    pub(crate) fn retained_generation(
        &self,
        named_targets: impl IntoIterator<Item = ProxyTarget>,
        default_max_conns: u32,
        default_keep_alive: Duration,
        default_connect_timeout: Duration,
    ) -> Self {
        let retained_named: HashSet<PoolKey> = named_targets
            .into_iter()
            .filter(|target| target.name.is_some())
            .map(|target| {
                PoolKey::new(
                    &target,
                    target.max_conns.unwrap_or(default_max_conns),
                    target.keep_alive.unwrap_or(default_keep_alive),
                    target.connect_timeout.unwrap_or(default_connect_timeout),
                )
            })
            .collect();
        let pools = self.pools.lock();
        let retained = pools
            .iter()
            // Credential files can rotate in place without changing their paths. Rebuild any
            // explicitly authenticated TLS upstream for the new generation so it re-reads the
            // identity (or retains a new load error) while the old generation's in-flight handles
            // drain naturally. Anonymous pools still retain their live connections.
            .filter(|(key, _)| {
                !key.has_configured_tls_identity()
                    && (key.name.is_none() || retained_named.contains(*key))
            })
            .map(|(key, upstream)| (key.clone(), upstream.clone()))
            .collect();
        UpstreamPool {
            pools: Mutex::new(retained),
            bad_until: Mutex::new(HashMap::new()),
            failovers: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Proxy;

    fn ensure_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    // (Tier 1.2) A target with failover peers hands out the primary until its
    // breaker trips, then the next peer; the primary is retried once its
    // failover mark (one half-open window) expires.
    #[test]
    fn failover_peers_skips_marked_primary_then_recovers() {
        use hj_core::config::{ExtAddress, ExtKind, ExtProcessor};

        let ep = ExtProcessor {
            name: "lb".into(),
            kind: ExtKind::Proxy,
            address: ExtAddress::Tcp("127.0.0.1:29001".parse().unwrap()),
            extra_addresses: vec![ExtAddress::Tcp("127.0.0.1:29002".parse().unwrap())],
            max_conns: 10,
            init_timeout: Duration::from_secs(1),
            retry_timeout: Duration::from_secs(0),
            pc_keep_alive_timeout: Duration::from_secs(5),
            resp_buffer: false,
            env: vec![],
            auto_start: 0,
            path: None,
            backlog: 0,
            client_cert_file: None,
            client_key_file: None,
            instances: 1,
            run_on_startup: 0,
        };
        let target = ProxyTarget::from_ext_processor(&ep);
        let pool = UpstreamPool::new();

        let primary =
            pool.get_or_create(&target, 10, Duration::from_secs(5), Duration::from_secs(1));
        assert_eq!(primary.authority, "127.0.0.1:29001");

        // Trip the primary's breaker (CB_THRESHOLD consecutive dial failures) —
        // the pool-level failover mark is installed by the pool itself.
        for _ in 0..3 {
            primary.note_dial_failure();
        }

        let next = pool.get_or_create(&target, 10, Duration::from_secs(5), Duration::from_secs(1));
        assert_eq!(
            next.authority, "127.0.0.1:29002",
            "over-rate primary must be skipped in favor of the failover peer"
        );
        assert_eq!(pool.failovers_total(), 1);

        // The primary recovers after the failover mark expires.
        std::thread::sleep(crate::pool::CB_HALF_OPEN_AFTER + Duration::from_millis(50));
        let recovered =
            pool.get_or_create(&target, 10, Duration::from_secs(5), Duration::from_secs(1));
        assert_eq!(recovered.authority, "127.0.0.1:29001");
    }

    #[test]
    fn pool_dedups_by_key() {
        let pool = UpstreamPool::new();
        let t1 = ProxyTarget::parse_url("http://127.0.0.1:8002/a").unwrap();
        let t2 = ProxyTarget::parse_url("http://127.0.0.1:8002/b").unwrap();
        let u1 = pool.get_or_create(&t1, 10, Duration::from_secs(60), Duration::from_secs(5));
        let u2 = pool.get_or_create(&t2, 10, Duration::from_secs(60), Duration::from_secs(5));
        assert!(Arc::ptr_eq(&u1, &u2), "same authority => same pool");
        assert_eq!(pool.len(), 1);

        let t3 = ProxyTarget::parse_url("http://127.0.0.1:8003/a").unwrap();
        let _u3 = pool.get_or_create(&t3, 10, Duration::from_secs(60), Duration::from_secs(5));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn configured_pool_identity_includes_endpoint_and_limits() {
        let pool = UpstreamPool::new();
        let mut a = ProxyTarget::parse_url("http://127.0.0.1:8002/").unwrap();
        a.name = Some("api".into());
        let mut b = ProxyTarget::parse_url("http://127.0.0.1:8003/").unwrap();
        b.name = Some("api".into());

        let ua = pool.get_or_create(&a, 10, Duration::from_secs(60), Duration::from_secs(5));
        let ub = pool.get_or_create(&b, 10, Duration::from_secs(60), Duration::from_secs(5));
        assert!(!Arc::ptr_eq(&ua, &ub));
        assert_eq!(ua.authority, "127.0.0.1:8002");
        assert_eq!(ub.authority, "127.0.0.1:8003");

        let changed_limits =
            pool.get_or_create(&a, 20, Duration::from_secs(30), Duration::from_secs(7));
        assert!(!Arc::ptr_eq(&ua, &changed_limits));
        assert_eq!(pool.len(), 3);

        let unchanged = pool.get_or_create(&a, 10, Duration::from_secs(60), Duration::from_secs(5));
        assert!(Arc::ptr_eq(&ua, &unchanged));
        assert_eq!(pool.len(), 3);
    }

    fn named_target(url: &str) -> ProxyTarget {
        let mut target = ProxyTarget::parse_url(url).unwrap();
        target.name = Some("api".into());
        target
    }

    #[test]
    fn reload_generation_does_not_accumulate_replaced_named_upstreams() {
        let limits = (10, Duration::from_secs(60), Duration::from_secs(5));
        let a = named_target("http://127.0.0.1:8002/");
        let b = named_target("http://127.0.0.1:8003/");
        let mut generation = UpstreamPool::new();
        generation.get_or_create(&a, limits.0, limits.1, limits.2);

        for target in [&b, &a, &b, &a, &b] {
            generation =
                generation.retained_generation([target.clone()], limits.0, limits.1, limits.2);
            assert_eq!(generation.len(), 0, "obsolete named pool must be dropped");
            generation.get_or_create(target, limits.0, limits.1, limits.2);
            assert_eq!(generation.len(), 1, "one active definition, one pool");
        }
    }

    #[test]
    fn reload_generation_retains_same_name_multi_endpoint_upstreams() {
        let limits = (10, Duration::from_secs(60), Duration::from_secs(5));
        let a = named_target("http://127.0.0.1:8002/");
        let b = named_target("http://127.0.0.1:8003/");
        let old = UpstreamPool::new();
        let ua = old.get_or_create(&a, limits.0, limits.1, limits.2);
        let ub = old.get_or_create(&b, limits.0, limits.1, limits.2);

        let both = old.retained_generation([a.clone(), b.clone()], limits.0, limits.1, limits.2);
        assert_eq!(both.len(), 2);
        assert!(Arc::ptr_eq(
            &ua,
            &both.get_or_create(&a, limits.0, limits.1, limits.2)
        ));
        assert!(Arc::ptr_eq(
            &ub,
            &both.get_or_create(&b, limits.0, limits.1, limits.2)
        ));

        let only_b = both.retained_generation([b.clone()], limits.0, limits.1, limits.2);
        assert_eq!(only_b.len(), 1);
        assert!(Arc::ptr_eq(
            &ub,
            &only_b.get_or_create(&b, limits.0, limits.1, limits.2)
        ));
    }

    #[test]
    fn reload_generation_keeps_unnamed_ad_hoc_upstreams() {
        let limits = (10, Duration::from_secs(60), Duration::from_secs(5));
        let target = ProxyTarget::parse_url("http://127.0.0.1:9000/").unwrap();
        let old = UpstreamPool::new();
        let upstream = old.get_or_create(&target, limits.0, limits.1, limits.2);
        let next = old.retained_generation([], limits.0, limits.1, limits.2);
        assert_eq!(next.len(), 1);
        assert!(Arc::ptr_eq(
            &upstream,
            &next.get_or_create(&target, limits.0, limits.1, limits.2)
        ));
    }

    #[test]
    fn upstream_starts_with_empty_idle() {
        let t = ProxyTarget::parse_url("http://127.0.0.1:8002/").unwrap();
        let u = Upstream::new(&t, 4, Duration::from_secs(30), Duration::from_secs(5));
        assert_eq!(u.idle_count(), 0);
        assert_eq!(u.authority, "127.0.0.1:8002");
    }

    /// Build a ready-to-use `SendRequest<OutBody>` over an in-memory duplex, returning the
    /// kept peer end so the connection stays open (and `is_ready()`). Dropping the returned
    /// peer closes the connection.
    async fn live_sender() -> (SendRequest<OutBody>, tokio::io::DuplexStream) {
        let (client_io, server_io) = tokio::io::duplex(1024);
        let io = hyper_util::rt::TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, OutBody>(io)
            .await
            .expect("handshake over duplex");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        // Drive the connection until the sender reports ready, so is_ready() is true and the
        // entry is reusable (the peer end is held open, so it never goes not-ready).
        sender.ready().await.expect("sender becomes ready");
        (sender, server_io)
    }

    #[tokio::test]
    async fn checkout_prunes_expired_from_front_not_just_back() {
        // (#27) `release` pushes fresh entries to the back, so the oldest live entries sit at
        // the front. The expiry pass must drop an expired FRONT entry, not only the back.
        let t = ProxyTarget::parse_url("http://127.0.0.1:8002/").unwrap();
        let u = Upstream::new(&t, 8, Duration::from_secs(30), Duration::from_secs(5));

        let (s_old, _peer_old) = live_sender().await;
        let (s_fresh1, _peer_f1) = live_sender().await;
        let (s_fresh2, _peer_f2) = live_sender().await;

        {
            let mut idle = u.idle.lock();
            // Front: expired (idle longer than keep_alive). Back: two fresh entries.
            idle.push(PooledConn {
                sender: AnySender::H1(s_old),
                idle_since: Instant::now() - Duration::from_secs(120),
            });
            idle.push(PooledConn {
                sender: AnySender::H1(s_fresh1),
                idle_since: Instant::now(),
            });
            idle.push(PooledConn {
                sender: AnySender::H1(s_fresh2),
                idle_since: Instant::now(),
            });
        }
        assert_eq!(u.idle_count(), 3);

        // checkout() prunes the expired front entry (retain), then reuses a fresh one (pop).
        let reused = u
            .checkout()
            .await
            .expect("a fresh idle connection is reusable");
        assert!(reused.is_ready(), "the reused connection is live");

        // Only the two fresh entries existed after pruning; one was consumed, one remains.
        assert_eq!(
            u.idle_count(),
            1,
            "expired front entry pruned; one fresh consumed, one fresh left"
        );
    }

    #[test]
    fn https_target_enables_upstream_tls_with_authority_server_name() {
        let t = ProxyTarget::parse_url("https://backend.internal/api").unwrap();
        let u = Upstream::new(&t, 4, Duration::from_secs(30), Duration::from_secs(5));
        assert!(u.tls_config.is_some(), "https target dials TLS");
        assert!(
            u.tls_server_name.is_some(),
            "TLS upstream resolves an SNI server name"
        );

        // Plain http stays cleartext.
        let t2 = ProxyTarget::parse_url("http://127.0.0.1:8002/").unwrap();
        let u2 = Upstream::new(&t2, 4, Duration::from_secs(30), Duration::from_secs(5));
        assert!(u2.tls_config.is_none());
        assert!(u2.tls_server_name.is_none());
    }

    #[test]
    fn tls_client_configs_offer_only_the_selected_protocol() {
        ensure_crypto_provider();
        assert!(
            client_tls_config(false).alpn_protocols.is_empty(),
            "the explicit https:// HTTP/1 arm must not negotiate h2"
        );
        assert_eq!(
            client_tls_config(true).alpn_protocols,
            [b"h2".to_vec()],
            "h2s:// must offer exactly h2"
        );
        assert!(require_h2_alpn("backend.test", Some(b"h2")).is_ok());
        assert!(require_h2_alpn("backend.test", None).is_err());
        assert!(require_h2_alpn("backend.test", Some(b"http/1.1")).is_err());
    }

    #[test]
    fn mtls_h2_config_keeps_client_certificate_and_h2_alpn() {
        ensure_crypto_provider();
        let generated = rcgen::generate_simple_self_signed(vec!["client.test".to_string()])
            .expect("client certificate");
        let unique = format!(
            "hj-proxy-mtls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let cert_path = std::env::temp_dir().join(format!("{unique}.cert.pem"));
        let key_path = std::env::temp_dir().join(format!("{unique}.key.pem"));
        std::fs::write(&cert_path, generated.cert.pem()).expect("write client cert");
        std::fs::write(&key_path, generated.signing_key.serialize_pem()).expect("write client key");

        let config =
            client_tls_config_with_cert(&cert_path, &key_path, true).expect("build mTLS h2 config");
        assert_eq!(config.alpn_protocols, [b"h2".to_vec()]);
        assert!(
            config.client_auth_cert_resolver.has_certs(),
            "adding h2 ALPN must retain the configured client certificate"
        );

        std::fs::remove_file(cert_path).expect("remove client cert");
        std::fs::remove_file(key_path).expect("remove client key");
    }

    #[test]
    fn configured_mtls_never_falls_back_to_anonymous_tls() {
        ensure_crypto_provider();
        let unique = format!(
            "hj-proxy-mtls-invalid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let missing_cert = std::env::temp_dir().join(format!("{unique}.missing-cert.pem"));
        let missing_key = std::env::temp_dir().join(format!("{unique}.missing-key.pem"));
        assert!(
            upstream_tls_config(Some(&missing_cert), Some(&missing_key), false).is_err(),
            "missing configured credentials must fail instead of selecting anonymous HTTPS"
        );
        assert!(
            upstream_tls_config(Some(&missing_cert), None, false).is_err(),
            "a one-sided HTTPS identity must fail closed"
        );
        assert!(
            upstream_tls_config(None, Some(&missing_key), true).is_err(),
            "a one-sided h2s identity must fail closed"
        );
        let mut target = ProxyTarget::parse_url("https://127.0.0.1:9/").unwrap();
        target.client_cert_file = Some(missing_cert.clone());
        let upstream = Upstream::new(&target, 1, Duration::from_secs(1), Duration::from_secs(1));
        assert!(
            upstream.tls_config.as_ref().is_some_and(Result::is_err),
            "the pool must retain the credential error for every dial"
        );

        let bad_cert = std::env::temp_dir().join(format!("{unique}.bad-cert.pem"));
        let bad_key = std::env::temp_dir().join(format!("{unique}.bad-key.pem"));
        std::fs::write(&bad_cert, b"not a certificate").unwrap();
        std::fs::write(&bad_key, b"not a private key").unwrap();
        assert!(
            upstream_tls_config(Some(&bad_cert), Some(&bad_key), false).is_err(),
            "malformed HTTPS credentials must fail closed"
        );
        assert!(
            upstream_tls_config(Some(&bad_cert), Some(&bad_key), true).is_err(),
            "malformed h2s credentials must fail closed"
        );
        std::fs::remove_file(bad_cert).unwrap();
        std::fs::remove_file(bad_key).unwrap();

        assert!(
            upstream_tls_config(None, None, false).is_ok(),
            "HTTPS without configured credentials remains anonymous"
        );
        assert!(
            upstream_tls_config(None, None, true).is_ok(),
            "h2s without configured credentials remains anonymous"
        );
    }

    fn named_mtls_target(cert: std::path::PathBuf, key: std::path::PathBuf) -> ProxyTarget {
        let mut target = ProxyTarget::parse_url("https://127.0.0.1:9443/").unwrap();
        target.name = Some("named-mtls".into());
        target.max_conns = Some(4);
        target.keep_alive = Some(Duration::from_secs(30));
        target.connect_timeout = Some(Duration::from_secs(5));
        target.client_cert_file = Some(cert);
        target.client_key_file = Some(key);
        target
    }

    fn target_upstream(proxy: &Proxy, target: &ProxyTarget) -> Arc<Upstream> {
        proxy.pool().get_or_create(
            target,
            target.max_conns.unwrap(),
            target.keep_alive.unwrap(),
            target.connect_timeout.unwrap(),
        )
    }

    #[test]
    fn credential_paths_are_part_of_pool_identity() {
        ensure_crypto_provider();
        let first = named_mtls_target(
            "/tmp/hj-proxy-first-client.pem".into(),
            "/tmp/hj-proxy-first-key.pem".into(),
        );
        let second = named_mtls_target(
            "/tmp/hj-proxy-second-client.pem".into(),
            "/tmp/hj-proxy-second-key.pem".into(),
        );
        let proxy = Proxy::new();
        let first_upstream = target_upstream(&proxy, &first);
        let second_upstream = target_upstream(&proxy, &second);
        assert!(!Arc::ptr_eq(&first_upstream, &second_upstream));
        assert_eq!(proxy.pool().len(), 2);
    }

    #[test]
    fn configured_identity_is_reloaded_each_generation_at_the_same_paths() {
        ensure_crypto_provider();
        let generated = rcgen::generate_simple_self_signed(vec!["client.test".to_string()])
            .expect("client certificate");
        let unique = format!(
            "hj-proxy-mtls-reload-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let cert_path = std::env::temp_dir().join(format!("{unique}.cert.pem"));
        let key_path = std::env::temp_dir().join(format!("{unique}.key.pem"));
        let write_valid = || {
            std::fs::write(&cert_path, generated.cert.pem()).unwrap();
            std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();
        };
        write_valid();

        let target = named_mtls_target(cert_path.clone(), key_path.clone());
        let first_proxy = Proxy::new();
        let valid = target_upstream(&first_proxy, &target);
        assert!(valid.tls_config.as_ref().is_some_and(Result::is_ok));

        std::fs::write(&cert_path, b"invalid rotated certificate").unwrap();
        std::fs::write(&key_path, b"invalid rotated key").unwrap();
        let invalid_proxy = first_proxy.next_generation([target.clone()]);
        let invalid = target_upstream(&invalid_proxy, &target);
        assert!(
            !Arc::ptr_eq(&valid, &invalid),
            "configured identities must not retain a stale upstream across reload"
        );
        assert!(invalid.tls_config.as_ref().is_some_and(Result::is_err));

        write_valid();
        let recovered_proxy = invalid_proxy.next_generation([target.clone()]);
        let recovered = target_upstream(&recovered_proxy, &target);
        assert!(!Arc::ptr_eq(&invalid, &recovered));
        assert!(recovered.tls_config.as_ref().is_some_and(Result::is_ok));

        std::fs::remove_file(cert_path).unwrap();
        std::fs::remove_file(key_path).unwrap();
    }

    #[test]
    fn anonymous_tls_pool_is_retained_across_generation() {
        let mut target = ProxyTarget::parse_url("https://127.0.0.1:9443/").unwrap();
        target.name = Some("anonymous-tls".into());
        target.max_conns = Some(4);
        target.keep_alive = Some(Duration::from_secs(30));
        target.connect_timeout = Some(Duration::from_secs(5));
        let proxy = Proxy::new();
        let before = target_upstream(&proxy, &target);
        let next = proxy.next_generation([target.clone()]);
        let after = target_upstream(&next, &target);
        assert!(Arc::ptr_eq(&before, &after));
    }

    #[test]
    fn valid_mtls_identity_builds_for_https_and_h2s() {
        ensure_crypto_provider();
        let generated = rcgen::generate_simple_self_signed(vec!["client.test".to_string()])
            .expect("client certificate");
        let unique = format!(
            "hj-proxy-mtls-valid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let cert_path = std::env::temp_dir().join(format!("{unique}.cert.pem"));
        let key_path = std::env::temp_dir().join(format!("{unique}.key.pem"));
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();

        let https = upstream_tls_config(Some(&cert_path), Some(&key_path), false).unwrap();
        assert!(https.alpn_protocols.is_empty());
        assert!(https.client_auth_cert_resolver.has_certs());
        let h2s = upstream_tls_config(Some(&cert_path), Some(&key_path), true).unwrap();
        assert_eq!(h2s.alpn_protocols, [b"h2".to_vec()]);
        assert!(h2s.client_auth_cert_resolver.has_certs());

        std::fs::remove_file(cert_path).unwrap();
        std::fs::remove_file(key_path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn trusted_local_tls_fixture_negotiates_and_speaks_h2() {
        use http_body_util::{BodyExt, Empty, Full};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        ensure_crypto_provider();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("server certificate");
        let cert_der = generated.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ));

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server TLS config");
        server_config.alpn_protocols = vec![b"h2".to_vec()];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS fixture");
        let addr = listener.local_addr().expect("fixture address");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("fixture accept");
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await
                .expect("server TLS handshake");
            let service = hyper::service::service_fn(|_req| async move {
                Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                    bytes::Bytes::from_static(b"h2s-ok"),
                )))
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("trust fixture certificate");
        let client_config = with_upstream_alpn(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
            true,
        );
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect TLS fixture");
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .expect("verified TLS handshake");
        require_h2_alpn("localhost", tls.get_ref().1.alpn_protocol())
            .expect("fixture must negotiate h2");

        let target = ProxyTarget::parse_url(&format!("h2://{addr}")).unwrap();
        let upstream = Upstream::new(&target, 1, Duration::from_secs(5), Duration::from_secs(2));
        let mut sender = upstream.h2_handshake(tls).await.expect("h2 handshake");
        let body: OutBody = Empty::<bytes::Bytes>::new().map_err(|e| match e {}).boxed();
        let request = http::Request::builder()
            .method(http::Method::GET)
            .version(http::Version::HTTP_2)
            .uri("https://localhost/probe")
            .header(http::header::HOST, "localhost")
            .body(body)
            .unwrap();
        let response = sender.send_request(request).await.expect("h2 request");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "h2s-ok"
        );

        drop(sender);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn max_conns_semaphore_caps_concurrent_checkouts() {
        let t = ProxyTarget::parse_url("http://127.0.0.1:8002/").unwrap();
        // max_conns = 2, short acquire budget so the over-cap wait fails fast.
        let u = Upstream::new(&t, 2, Duration::from_secs(30), Duration::from_millis(50));
        let p1 = u.acquire().await;
        let p2 = u.acquire().await;
        assert!(
            p1.is_some() && p2.is_some(),
            "first max_conns permits acquire"
        );
        assert!(
            u.acquire().await.is_none(),
            "an over-cap acquire is refused (caller 503s)"
        );
        drop(p1);
        assert!(
            u.acquire().await.is_some(),
            "a freed slot can be re-acquired"
        );
        drop(p2);
    }

    #[test]
    fn circuit_breaker_trips_at_threshold_and_resets_on_success() {
        let t = ProxyTarget::parse_url("http://127.0.0.1:8002/").unwrap();
        let u = Upstream::new(&t, 4, Duration::from_secs(30), Duration::from_secs(5));
        assert!(!u.breaker_open(), "breaker starts closed");
        // Failures below the threshold keep it closed.
        for _ in 0..CB_THRESHOLD - 1 {
            u.note_dial_failure();
        }
        assert!(!u.breaker_open(), "stays closed below threshold");
        // Reaching the threshold opens it (fast-fail without dialing).
        u.note_dial_failure();
        assert!(u.breaker_open(), "opens at the failure threshold");
        // A successful dial closes it and clears the counter.
        u.note_dial_success();
        assert!(!u.breaker_open(), "success closes the breaker");
        assert_eq!(u.fail_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn circuit_breaker_half_open_admits_exactly_one_trial() {
        let t = ProxyTarget::parse_url("http://127.0.0.1:8002/").unwrap();
        let u = Upstream::new(&t, 4, Duration::from_secs(30), Duration::from_secs(5));
        for _ in 0..CB_THRESHOLD {
            u.note_dial_failure();
        }
        assert!(u.breaker_open(), "tripped");
        // Simulate the open window having elapsed (without sleeping CB_HALF_OPEN_AFTER).
        *u.tripped_at.lock() = Some(Instant::now() - CB_HALF_OPEN_AFTER - Duration::from_millis(1));
        // The first checkout after the window is the single half-open trial (reads closed)...
        assert!(!u.breaker_open(), "half-open admits exactly one trial dial");
        // ...and the window is RE-ARMED, so concurrent/subsequent checkouts stay fast-failed
        // instead of a herd all dialing the still-dead upstream.
        assert!(
            u.breaker_open(),
            "subsequent checkouts stay open until the trial resolves"
        );
        assert!(u.breaker_open(), "still open");
        // A successful trial closes the breaker.
        u.note_dial_success();
        assert!(!u.breaker_open(), "trial success closes the breaker");
    }

    #[test]
    fn upstream_has_response_head_timeout() {
        let t = ProxyTarget::parse_url("http://127.0.0.1:8002/").unwrap();
        let u = Upstream::new(&t, 4, Duration::from_secs(30), Duration::from_secs(5));
        // SEC3: a non-zero response-head timeout bounds a hung upstream.
        assert!(u.response_timeout() >= Duration::from_secs(1));
    }
}
