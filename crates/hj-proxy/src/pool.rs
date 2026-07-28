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
use std::sync::atomic::{AtomicU32, Ordering};
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
fn client_tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
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

/// A pooled, ready-to-use upstream connection.
pub(crate) struct PooledConn {
    pub(crate) sender: SendRequest<OutBody>,
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
    /// The upstream leg is TLS (`https`/`wss` target): dial TCP then complete a TLS
    /// handshake before speaking HTTP. Without this an `https` target would speak cleartext
    /// HTTP to a TLS port (silent failure).
    requires_tls: bool,
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
            requires_tls,
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
        })
    }

    /// Acquire a concurrency permit (LiteSpeed `maxConns`): at most `max_conns` requests may
    /// be in flight to this upstream concurrently. Waits up to `connect_timeout` for a free
    /// slot; `None` means the upstream is saturated and the caller should return `503`. The
    /// returned permit is held for the whole request+response lifetime (see [`crate::Proxy::forward`]).
    pub(crate) async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        match tokio::time::timeout(self.connect_timeout, self.sem.clone().acquire_owned()).await {
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

    /// Record a successful dial: reset the failure count and close the breaker.
    fn note_dial_success(&self) {
        self.fail_count.store(0, Ordering::Relaxed);
        *self.tripped_at.lock() = None;
    }

    /// Record a failed dial: trip the breaker once the threshold is reached.
    fn note_dial_failure(&self) {
        let n = self.fail_count.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= CB_THRESHOLD {
            *self.tripped_at.lock() = Some(Instant::now());
        }
    }

    /// Number of connections currently idle in the pool (for tests/metrics).
    pub fn idle_count(&self) -> usize {
        self.idle.lock().len()
    }

    /// Check out a usable connection, reusing a live idle one if available, else
    /// dialing a new connection and driving it on a background task.
    pub(crate) async fn checkout(&self) -> Result<SendRequest<OutBody>, ProxyError> {
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
    async fn dial(&self) -> Result<SendRequest<OutBody>, ProxyError> {
        match &self.transport {
            TargetTransport::Tcp(hostport) => {
                let connect = TcpStream::connect(hostport.clone());
                let stream = tokio::time::timeout(self.connect_timeout, connect)
                    .await
                    .map_err(|_| ProxyError::ConnectTimeout)?
                    .map_err(ProxyError::Connect)?;
                let _ = stream.set_nodelay(true);
                crate::set_tcp_keepalive(&stream);
                if self.requires_tls {
                    // Complete the TLS handshake before HTTP. Fail closed if the server name
                    // never parsed (so an `https` target is never spoken to in cleartext).
                    let server_name = self.tls_server_name.clone().ok_or_else(|| {
                        ProxyError::Other(format!(
                            "TLS upstream {} has no valid server name",
                            self.authority
                        ))
                    })?;
                    let connector = TlsConnector::from(client_tls_config());
                    let tls = tokio::time::timeout(
                        self.connect_timeout,
                        connector.connect(server_name, stream),
                    )
                    .await
                    .map_err(|_| ProxyError::ConnectTimeout)?
                    .map_err(ProxyError::Connect)?;
                    self.h1_handshake(tls).await
                } else {
                    self.h1_handshake(stream).await
                }
            }
            #[cfg(unix)]
            TargetTransport::Uds(path) => {
                let connect = tokio::net::UnixStream::connect(path.clone());
                let stream = tokio::time::timeout(self.connect_timeout, connect)
                    .await
                    .map_err(|_| ProxyError::ConnectTimeout)?
                    .map_err(ProxyError::Connect)?;
                self.h1_handshake(stream).await
            }
            #[cfg(not(unix))]
            TargetTransport::Uds(_) => Err(ProxyError::Other(
                "unix sockets unsupported on this platform".into(),
            )),
        }
    }

    /// Complete the HTTP/1.1 client handshake over an already-connected (optionally
    /// TLS-wrapped) stream and spawn its background connection driver, returning the sender.
    async fn h1_handshake<IO>(&self, io: IO) -> Result<SendRequest<OutBody>, ProxyError>
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
        Ok(sender)
    }

    /// Return a connection to the idle pool after a completed request, if it is
    /// still healthy and the pool has room.
    pub(crate) fn release(&self, sender: SendRequest<OutBody>) {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    name: Option<String>,
    scheme: String,
    authority: String,
    transport: TargetTransport,
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
            max_conns: max_conns.max(1),
            keep_alive,
            connect_timeout: if connect_timeout.is_zero() {
                Duration::from_secs(10)
            } else {
                connect_timeout
            },
        }
    }
}

impl UpstreamPool {
    pub fn new() -> Self {
        UpstreamPool {
            pools: Mutex::new(HashMap::new()),
        }
    }

    /// Get (or lazily create) the [`Upstream`] for `target`, applying the given
    /// limits the first time it is seen.
    pub fn get_or_create(
        &self,
        target: &ProxyTarget,
        max_conns: u32,
        keep_alive: Duration,
        connect_timeout: Duration,
    ) -> Arc<Upstream> {
        let key = PoolKey::new(target, max_conns, keep_alive, connect_timeout);
        let mut pools = self.pools.lock();
        pools
            .entry(key)
            .or_insert_with(|| Upstream::new(target, max_conns, keep_alive, connect_timeout))
            .clone()
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
            .filter(|(key, _)| key.name.is_none() || retained_named.contains(*key))
            .map(|(key, upstream)| (key.clone(), upstream.clone()))
            .collect();
        UpstreamPool {
            pools: Mutex::new(retained),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                sender: s_old,
                idle_since: Instant::now() - Duration::from_secs(120),
            });
            idle.push(PooledConn {
                sender: s_fresh1,
                idle_since: Instant::now(),
            });
            idle.push(PooledConn {
                sender: s_fresh2,
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
        assert!(u.requires_tls, "https target dials TLS");
        assert!(
            u.tls_server_name.is_some(),
            "TLS upstream resolves an SNI server name"
        );

        // Plain http stays cleartext.
        let t2 = ProxyTarget::parse_url("http://127.0.0.1:8002/").unwrap();
        let u2 = Upstream::new(&t2, 4, Duration::from_secs(30), Duration::from_secs(5));
        assert!(!u2.requires_tls);
        assert!(u2.tls_server_name.is_none());
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
