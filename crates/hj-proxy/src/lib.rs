//! hj-proxy — the httpjet reverse-proxy, WebSocket, and SSE forwarding layer.
//!
//! This crate forwards requests to upstream backends (FastAPI/uvicorn,
//! MCP servers, status apps, ...), the same way LiteSpeed's reverse-proxy
//! "external app" contexts and rewrite `[P]` rules do.
//!
//! # Components
//! - [`ProxyTarget`] — where to forward, parsed from an `ExtProcessor`, a vhost
//!   `WebSocketMap`, or an ad-hoc rewrite URL (`http://127.0.0.1:8002/$1`).
//! - [`Upstream`] / [`UpstreamPool`] — per-authority keep-alive connection pools
//!   honoring `pc_keep_alive_timeout` and `max_conns`.
//! - [`Proxy`] — the forwarding engine:
//!   - [`Proxy::forward`] proxies an ordinary request and **streams** the
//!     response body straight through (`Body::Stream`) with no buffering and no
//!     read-idle timeout. This is what makes `Accept: text/event-stream` (SSE)
//!     and other long-lived streams work: bytes are passed through frame by
//!     frame, never aggregated or compressed here.
//!   - [`Proxy::proxy_websocket`] performs the upstream WebSocket bring-up:
//!     it opens a TCP connection to the upstream, replays the (header-rewritten)
//!     upgrade request, and on a `101` hands back the response plus the upstream
//!     [`tokio::net::TcpStream`] for the orchestrator to splice.
//!   - [`Proxy::relay`] copies bytes bidirectionally between the upgraded client
//!     IO and the upstream socket until either side closes.
//!
//! # Header semantics (see [`headers`])
//! The original `Host` is preserved; `X-Forwarded-For` is *appended to*;
//! `X-Forwarded-Proto`/`-Host` and `X-Real-IP` are set; hop-by-hop headers are
//! stripped on both legs.
//!
//! # Integration
//! The orchestrator constructs one [`Proxy`] per config generation. Reloads
//! retain the [`Upstream`] Arcs for unchanged named definitions while obsolete
//! definitions drain with the old generation. For a matched proxy context / `[P]`
//! rule it calls [`Proxy::forward`]. For a WebSocket upgrade it calls
//! [`Proxy::proxy_websocket`], returns the `101` to the client, then — once
//! hyper yields the upgraded client IO — calls [`Proxy::relay`] with that IO and
//! the returned upstream socket.

mod error;
mod headers;
mod pool;
mod target;

use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderValue, Request as HttpRequest, Uri, Version};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub use headers::is_websocket_upgrade;
pub use pool::{Upstream, UpstreamPool};
pub use target::{ProxyTarget, TargetParseError};

use crate::error::ProxyError;
use crate::target::TargetTransport;
use hj_core::{Body, BoxError, HandlerError, IncomingBody, ReqCtx, Request, Response, StreamBody};

/// Default connect timeout used when the ext-processor `init_timeout` is zero.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default idle keep-alive when `pc_keep_alive_timeout` is zero.
const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(60);
/// Inactivity timeout for forwarding a request body upstream. The deadline is
/// reset on every chunk we hand to the upstream, so a legitimately slow but
/// *progressing* upload survives indefinitely while a trickling / never-terminating
/// chunked upload (no terminal chunk) is dropped — releasing the maxConns permit
/// instead of pinning it. (#14)
const BODY_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);

/// TCP keepalive idle + probe interval for every socket that can outlive one request: the
/// dialed upstream, the WebSocket upstream leg, and the ACCEPTED CLIENT socket (armed by the
/// io_uring accept loop, which imports these). Without keepalive a peer that vanishes with no
/// FIN/RST (dead NAT/conntrack entry, hard-powered-off box) is never surfaced to the app, so
/// the drain task's `sender.ready()` — and the WebSocket relay's client-side read — never
/// resolve, pinning a maxConns permit / relay task / two fds for the dead connection's
/// lifetime. The `#70` drain design already *assumes* "a dead one is reaped by TCP keepalive".
///
/// Probe COUNT is left at the OS default (`tcp_keepalive_probes`, 9), so an idle dead peer is
/// detected in ~195 s. Note the timer does not run while data is in flight — a push-only feed
/// with a vanished reader is bounded by `tcp_retries2` (~15 min) instead.
pub const PROXY_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
pub const PROXY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Enable TCP keepalive (idle 60s, then probe every 15s) on a connected stream.
/// Best-effort — a failure to set the socket option is non-fatal (`set_nodelay`
/// is treated the same way at every call site).
pub fn set_tcp_keepalive(stream: &TcpStream) {
    let ka = socket2::TcpKeepalive::new()
        .with_time(PROXY_KEEPALIVE_IDLE)
        .with_interval(PROXY_KEEPALIVE_INTERVAL);
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}

/// The reverse-proxy engine. Cheap to clone-by-`Arc`; holds a shared
/// [`UpstreamPool`].
pub struct Proxy {
    pool: UpstreamPool,
    /// Connection limit applied to lazily-created upstreams.
    default_max_conns: u32,
    default_keep_alive: Duration,
    default_connect_timeout: Duration,
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy::new()
    }
}

impl Proxy {
    /// Create a proxy with default pool limits.
    pub fn new() -> Self {
        Proxy {
            pool: UpstreamPool::new(),
            default_max_conns: 100,
            default_keep_alive: DEFAULT_KEEP_ALIVE,
            default_connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Create a proxy with explicit default pool limits (applied to upstreams
    /// the first time each authority is seen).
    pub fn with_limits(
        default_max_conns: u32,
        default_keep_alive: Duration,
        default_connect_timeout: Duration,
    ) -> Self {
        Proxy {
            pool: UpstreamPool::new(),
            default_max_conns: default_max_conns.max(1),
            default_keep_alive: if default_keep_alive.is_zero() {
                DEFAULT_KEEP_ALIVE
            } else {
                default_keep_alive
            },
            default_connect_timeout: if default_connect_timeout.is_zero() {
                DEFAULT_CONNECT_TIMEOUT
            } else {
                default_connect_timeout
            },
        }
    }

    /// Access the shared upstream pool (for metrics/inspection).
    pub fn pool(&self) -> &UpstreamPool {
        &self.pool
    }

    /// Build a config-reload generation that reuses only still-configured named
    /// upstreams. Removed or changed named definitions remain owned by the old
    /// generation until its in-flight requests drain; ad-hoc unnamed targets stay
    /// warm because they are not represented in the parsed ext-processor list.
    pub fn next_generation(&self, named_targets: impl IntoIterator<Item = ProxyTarget>) -> Self {
        Proxy {
            pool: self.pool.retained_generation(
                named_targets,
                self.default_max_conns,
                self.default_keep_alive,
                self.default_connect_timeout,
            ),
            default_max_conns: self.default_max_conns,
            default_keep_alive: self.default_keep_alive,
            default_connect_timeout: self.default_connect_timeout,
        }
    }

    /// Forward an ordinary HTTP request to `target` and stream the response back.
    ///
    /// Behavior:
    /// - reuses or opens a pooled keep-alive connection to the upstream;
    /// - rewrites headers per [`headers::rewrite_request_headers`] (Host kept,
    ///   XFF appended, XFP/XFH/X-Real-IP set, hop-by-hop stripped);
    /// - builds the upstream request-URI from `target.path_and_query` when set,
    ///   otherwise the inbound path-and-query;
    /// - returns the upstream response with its body wrapped as
    ///   [`Body::Stream`] — **no buffering, no compression, no read-idle
    ///   timeout** — so SSE / chunked / long-lived streams flow through frame by
    ///   frame;
    /// - retries a BODYLESS IDEMPOTENT request once, on a freshly dialed connection, when the
    ///   first attempt's pooled connection died before response headers. Both attempts share
    ///   one head deadline (`response_timeout`), so a retry neither shrinks nor doubles the
    ///   budget an un-retried request would have had.
    ///
    /// The upstream's `retry_timeout` is deliberately NOT consulted here. In LiteSpeed it is a
    /// worker bad-mark *cooldown* (0 means "never mark the worker bad", and the per-request
    /// retry is bounded by an attempt count instead) — the analogue of this pool's breaker
    /// half-open delay, not a per-request deadline. Reading it as one made every prod
    /// extProcessor, all of which set 0, land on an arbitrary 5 s floor.
    pub async fn forward(
        &self,
        ctx: &ReqCtx,
        req: Request,
        target: &ProxyTarget,
    ) -> Result<Response, HandlerError> {
        let upstream = self.pool.get_or_create(
            target,
            target.max_conns.unwrap_or(self.default_max_conns),
            target.keep_alive.unwrap_or(self.default_keep_alive),
            target
                .connect_timeout
                .unwrap_or(self.default_connect_timeout),
        );

        // (#6/#14/#33) Whether the inbound request carries a request body. For a
        // body-bearing forward the upstream's response *head* does not arrive until it
        // has read the whole (client-paced, possibly slow) request body, so the fixed
        // head timeout below would measure the UPLOAD duration and abort a legitimate
        // slow upload with a spurious 504. So the head wait is bounded only for bodyless
        // requests; body-bearing requests are instead bounded by an inactivity timeout
        // on the upload itself (see `InactivityBody`).
        //
        // Detect from the *actual* body, not just headers: hj-h2/h3 reject
        // Transfer-Encoding and a legal h2/h3 POST conveys its length only in DATA frames
        // (no Content-Length), so a header-only test mis-flags it bodyless (#33). And a
        // bogus `Transfer-Encoding: identity` (no body) must NOT count as body-bearing —
        // only `chunked` or a real positive Content-Length do (#14).
        let has_request_body = body_is_present(&req);

        // (audit) A pooled keep-alive connection can die between checkout()'s
        // `is_ready()` check and send(). For a BODYLESS IDEMPOTENT request the
        // retry is safe (nothing reached the upstream — send_request only
        // resolves on response headers) and turns the classic monit-vs-uvicorn
        // idle-close race from a 502 into an invisible fresh-connection retry.
        // Snapshot the PRE-rewrite head so the rebuild re-runs the full header
        // rewrite exactly once more; proxy legs are low-volume internal backends,
        // so the clones are noise. Bounded by the upstream's LiteSpeed
        // `retryTimeout` when configured, else 5 s.
        let retry_head = if !has_request_body && req.method().is_idempotent() {
            Some((
                req.method().clone(),
                req.uri().clone(),
                req.headers().clone(),
            ))
        } else {
            None
        };

        // Build the upstream request (URI/headers) from the inbound request.
        let out_req = build_forward_request(ctx, req, target, &upstream.authority)
            .map_err(|e| HandlerError::Other(e.to_string()))?;

        // (maxConns) Bound concurrent in-flight requests to this upstream. The permit is held
        // for the whole request+response+drain lifetime (moved into the drain task below), so
        // this limits active concurrency — not merely idle-pool retention. A saturated
        // upstream returns 503 instead of opening unbounded backend connections.
        let permit = match upstream.acquire().await {
            Some(p) => p,
            None => return Err(HandlerError::ServiceUnavailable),
        };

        let mut sender = upstream.checkout().await.map_err(HandlerError::from)?;

        // (SEC3) Bound the wait for upstream response *headers*. Without this a
        // backend that accepts the connection then never replies pins this task and
        // its pool slot forever, eventually draining the pool. The streamed RESPONSE
        // body is NOT subject to this timeout (send_request resolves on headers), so
        // SSE and long downloads are unaffected. A timed-out sender is dropped, not
        // pooled.
        let upstream_resp = if has_request_body {
            // (#14) The fixed head timeout can't bound a body-bearing request (it would
            // measure the legitimately slow upload), so instead wrap the outgoing body in
            // an inactivity timeout that fires only when *no chunk makes progress* within
            // the window. A trickling / never-terminating chunked upload then surfaces as a
            // body error here, `send_request` resolves, and the maxConns permit is released
            // — rather than the task awaiting the terminal chunk forever.
            let (out_req2, eof_rx) = wrap_body_inactivity_timeout(out_req, BODY_INACTIVITY_TIMEOUT);
            // (#69) Once the upload reaches EOF, bound the wait for response HEADERS by
            // response_timeout. A slow-but-progressing upload is unaffected (the clock starts
            // only at EOF); but a backend that drains the body then never sends headers can no
            // longer pin this task — and with it the maxConns permit and the pooled connection
            // — forever (the body-inactivity timer cannot fire once the body has ended).
            let head_timeout = upstream.response_timeout();
            tokio::select! {
                biased;
                r = sender.send_request(out_req2) => match r {
                    Ok(r) => r,
                    Err(e) => {
                        // Distinguish the upload-stall case so the caller gets a 504, not a 502.
                        if is_body_timeout(&e) {
                            return Err(ProxyError::BodyTimeout.into());
                        }
                        return Err(ProxyError::Request(e.to_string()).into());
                    }
                },
                _ = async move { let _ = eof_rx.await; tokio::time::sleep(head_timeout).await; } => {
                    return Err(ProxyError::ResponseTimeout.into());
                }
            }
        } else {
            // ONE head deadline for the whole request, shared by both attempts. Bounding the
            // retry separately narrowed a 60 s budget to 5 s and failed a slow-but-healthy
            // backend that would otherwise have answered; sharing the deadline also keeps the
            // total from reaching 2x response_timeout. The trade is deliberate: a first
            // attempt that fails late leaves the retry less than the old fixed floor.
            let head_deadline = tokio::time::Instant::now() + upstream.response_timeout();
            match tokio::time::timeout_at(head_deadline, sender.send_request(out_req)).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    let Some((m, u, h)) = retry_head else {
                        return Err(ProxyError::Request(e.to_string()).into());
                    };
                    tracing::debug!(
                        error = %e,
                        "hj-proxy: pooled connection died before send — retrying once on a fresh connection"
                    );
                    // The dead connection is discarded, NEVER re-pooled.
                    drop(sender);
                    // `checkout` prefers a pooled entry, and a backend that closed one idle
                    // connection has usually closed the batch — so it would hand back a sibling
                    // of the connection that just died and lose the same race, with no third
                    // attempt left.
                    let mut sender2 = match upstream.checkout_fresh().await {
                        Ok(s) => s,
                        Err(err) => return Err(err.into()),
                    };
                    let inbound2 = match rebuild_retry_request(m, u, h) {
                        Ok(r) => r,
                        Err(err) => return Err(HandlerError::Other(err.to_string())),
                    };
                    let out_req2 =
                        build_forward_request(ctx, inbound2, target, &upstream.authority)?;
                    match tokio::time::timeout_at(head_deadline, sender2.send_request(out_req2))
                        .await
                    {
                        // Retry succeeded: hand the LIVE connection to the
                        // normal drain/pool path below by replacing `sender`.
                        Ok(Ok(resp)) => {
                            sender = sender2;
                            resp
                        }
                        Ok(Err(err)) => return Err(ProxyError::Request(err.to_string()).into()),
                        Err(_) => return Err(ProxyError::ResponseTimeout.into()),
                    }
                }
                Err(_) => return Err(ProxyError::ResponseTimeout.into()),
            }
        };

        // Return the connection to the pool once it is free again. The response
        // body streams straight through to the client, so the connection only
        // becomes reusable after that body has fully drained. We don't block the
        // request on that here (it would defeat streaming); instead a detached
        // task waits for `sender.ready()` — which resolves when the in-flight
        // response is done (or the client disconnected, dropping the response
        // body and stopping the upstream read) — and returns the sender to the
        // idle pool. A short cap keeps a never-finishing stream (e.g. an SSE feed
        // held open for hours) from pinning the task forever; in that case the
        // connection is simply not reused.
        //
        // (#28) The maxConns permit is MOVED INTO this drain task (not attached to
        // the response body). On a mid-stream client disconnect the body drops and
        // frees nothing on its own; the slot is released only once this task finishes
        // draining (or its keep_alive_window cap fires). That way the semaphore counts
        // running + draining connections, so a fresh request can't acquire a permit,
        // find the idle pool empty, and dial a second connection while the old one is
        // still being drained — which would let the upstream transiently see up to
        // 2× max_conns sockets.
        let up = upstream.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // (#70) Hold the maxConns permit until the upstream connection is ACTUALLY free.
            // `sender.ready()` resolves when the in-flight response is fully consumed by the
            // client, the client disconnects (the response body drops -> connection error), or
            // the upstream closes. A previous `keep_alive_window` cap (<=75s) released the
            // permit while a long-lived stream (SSE / large download) was STILL in flight,
            // letting a new request dial a 2nd connection (up to 2x max_conns) and defeating
            // the anti-double-dial guarantee. No time cap now: a genuinely-busy connection
            // holds its slot for its real lifetime, and a dead one is reaped by TCP keepalive
            // (which resolves ready() with an error, exiting this task without re-pooling).
            if sender.ready().await.is_ok() {
                up.release(sender);
            }
            // _permit drops here: the slot frees only after the connection is truly free.
        });

        Ok(into_streaming_response(upstream_resp))
    }

    /// Begin a WebSocket proxy to `target`: open a TCP connection to the
    /// upstream, replay the (rewritten) upgrade request, and read the upstream's
    /// HTTP response.
    ///
    /// On a `101 Switching Protocols` this returns the upstream [`TcpStream`]
    /// (positioned just past the response headers) together with the response
    /// head to relay to the client. The orchestrator should:
    /// 1. send the returned [`Response`] (status `101`, upstream's
    ///    `Sec-WebSocket-Accept`, etc.) to the client,
    /// 2. obtain the upgraded client IO (via `hyper::upgrade::on`), and
    /// 3. call [`Proxy::relay`] with that IO and the returned [`TcpStream`].
    ///
    /// If the upstream answers with a non-`101` status, that response is
    /// returned as a normal (buffered) response so the client sees the failure.
    pub async fn proxy_websocket(
        &self,
        ctx: &ReqCtx,
        req: Request,
        target: &ProxyTarget,
    ) -> Result<WebSocketUpgrade, HandlerError> {
        let hostport = match &target.transport {
            TargetTransport::Tcp(hp) => hp.clone(),
            TargetTransport::Uds(_) => {
                return Err(HandlerError::Other(
                    "websocket over unix socket is not supported".into(),
                ));
            }
        };
        if target.is_tls() {
            return Err(HandlerError::BadGateway(
                "secure websocket upstreams are not supported by the raw websocket relay".into(),
            ));
        }

        let connect_timeout = target
            .connect_timeout
            .unwrap_or(self.default_connect_timeout);
        let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(&hostport))
            .await
            .map_err(|_| HandlerError::GatewayTimeout)?
            .map_err(|e| HandlerError::BadGateway(format!("ws connect: {e}")))?;
        let _ = stream.set_nodelay(true);
        set_tcp_keepalive(&stream);

        // The WebSocket handshake leg must carry NO request body (RFC 6455) — use the
        // upgrade-request builder (forces an Empty body + strips Content-Length/Transfer-Encoding),
        // not build_forward_request which replays the inbound body verbatim. A client sending an
        // upgrade WITH a body would otherwise produce a non-conformant upstream handshake.
        let out_req = Self::build_upstream_upgrade_request(ctx, req, target)?;

        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| HandlerError::BadGateway(format!("ws handshake: {e}")))?;

        // Drive the connection with upgrade support so we can reclaim the IO. The
        // task resolves to the parts (including the io) once an upgrade completes,
        // or an error / clean close otherwise.
        let conn = conn.with_upgrades();
        let driver = tokio::spawn(conn);

        // (#5) Bound the wait for the upstream's 101/handshake response head, mirroring
        // the SEC3 timeout in `forward`. Without it a WS upstream that accepts the
        // connection + handshake but never replies pins this request task and the
        // upstream socket forever (a slow FD/task leak under repeated hits).
        let upstream_resp =
            match tokio::time::timeout(connect_timeout, sender.send_request(out_req)).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => return Err(HandlerError::BadGateway(format!("ws request: {e}"))),
                Err(_) => return Err(HandlerError::GatewayTimeout),
            };

        let status = upstream_resp.status();
        if status == http::StatusCode::SWITCHING_PROTOCOLS {
            // Capture the upstream's exact 101 head (incl. Sec-WebSocket-Accept,
            // Sec-WebSocket-Protocol/-Extensions) BEFORE consuming the response
            // for the upgrade — the client must receive these verbatim.
            let mut client_headers = upstream_resp.headers().clone();
            headers::sanitize_response_headers(&mut client_headers, true);

            // Reclaim the upgraded upstream IO from the response.
            let upstream_io = hyper::upgrade::on(upstream_resp)
                .await
                .map_err(|e| HandlerError::BadGateway(format!("ws upgrade: {e}")))?;
            // We no longer need the driver task to do more work; it will resolve
            // once the connection is torn down.
            drop(driver);

            let mut resp = http::Response::new(Body::Empty);
            *resp.status_mut() = http::StatusCode::SWITCHING_PROTOCOLS;
            *resp.headers_mut() = client_headers;
            resp.headers_mut()
                .entry(http::header::UPGRADE)
                .or_insert_with(|| HeaderValue::from_static("websocket"));
            resp.headers_mut()
                .entry(http::header::CONNECTION)
                .or_insert_with(|| HeaderValue::from_static("upgrade"));

            return Ok(WebSocketUpgrade {
                response: resp,
                upstream: UpstreamUpgraded::Hyper(upstream_io),
            });
        }

        // Non-101: surface the upstream's response (buffered) to the client.
        drop(driver);
        let mut resp = into_streaming_response(upstream_resp);
        headers::sanitize_response_headers(resp.headers_mut(), false);
        Ok(WebSocketUpgrade {
            response: resp,
            upstream: UpstreamUpgraded::Rejected(status),
        })
    }

    /// Build (but do not send) the upstream upgrade request, for orchestrators
    /// that prefer to drive the upgrade themselves (e.g. raw socket replay).
    ///
    /// The returned request has the WebSocket upgrade headers preserved and the
    /// forward headers (XFF/XFP/XFH/X-Real-IP) applied. The body is `Empty`
    /// (WebSocket handshakes carry no request body).
    pub fn build_upstream_upgrade_request(
        ctx: &ReqCtx,
        req: Request,
        target: &ProxyTarget,
    ) -> Result<HttpRequest<StreamBody>, HandlerError> {
        let (mut parts, _body) = req.into_parts();
        // Force an empty body for the handshake leg.
        // Normalize to HTTP/1.1 — the upstream handshake speaks h1 and would panic
        // on a downstream `HTTP/3.0`/`HTTP/2.0` version (see `build_forward_request`).
        parts.version = Version::HTTP_11;
        let uri = upstream_uri(&parts.uri, target)?;
        parts.uri = uri;
        ensure_host(&mut parts.headers, target, &target.authority);
        headers::rewrite_request_headers(&mut parts.headers, ctx, true);
        // The handshake leg carries NO request body, so strip any framing headers — otherwise a
        // client that sent `Upgrade: websocket` together with a Content-Length (+ body) would
        // replay that declared length onto the empty handshake and the upstream would block waiting
        // for body bytes that never come. `rewrite_request_headers` drops Transfer-Encoding as
        // hop-by-hop but NOT Content-Length, so remove both explicitly.
        parts.headers.remove(http::header::CONTENT_LENGTH);
        parts.headers.remove(http::header::TRANSFER_ENCODING);
        Ok(HttpRequest::from_parts(parts, empty_stream_body()))
    }

    /// Bidirectionally copy bytes between the upgraded client IO and the
    /// upstream socket until either side closes. Returns the (client→upstream,
    /// upstream→client) byte counts.
    ///
    /// This is generic over the IO types so it works with a hyper
    /// `Upgraded`/`TokioIo<Upgraded>`, a raw [`TcpStream`], or an in-memory
    /// duplex (used in tests).
    pub async fn relay<C, U>(mut client: C, mut upstream: U) -> std::io::Result<(u64, u64)>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
    }

    /// Convenience for the common case: relay between the upgraded client IO and
    /// a hyper-upgraded upstream (e.g. from [`UpstreamUpgraded::into_io`]). The
    /// upstream `Upgraded` is wrapped in [`hyper_util::rt::TokioIo`] so it
    /// satisfies the tokio IO traits.
    pub async fn relay_upgraded<C>(
        client: C,
        upstream: hyper::upgrade::Upgraded,
    ) -> std::io::Result<(u64, u64)>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let upstream = hyper_util::rt::TokioIo::new(upstream);
        Proxy::relay(client, upstream).await
    }
}

/// Result of [`Proxy::proxy_websocket`].
pub struct WebSocketUpgrade {
    /// The response to return to the downstream client (status `101` on
    /// success, or the upstream's rejection response).
    pub response: Response,
    /// The upstream side once upgraded (or a rejection marker).
    pub upstream: UpstreamUpgraded,
}

impl WebSocketUpgrade {
    /// True when the upstream agreed to switch protocols.
    pub fn is_switching(&self) -> bool {
        matches!(self.upstream, UpstreamUpgraded::Hyper(_))
    }
}

/// The upstream end of a WebSocket after the bring-up attempt.
pub enum UpstreamUpgraded {
    /// Upgraded IO reclaimed from hyper; relay it with [`Proxy::relay_upgraded`]
    /// or wrap in [`hyper_util::rt::TokioIo`] for [`Proxy::relay`].
    Hyper(hyper::upgrade::Upgraded),
    /// Upstream rejected the upgrade with this status; nothing to relay.
    Rejected(http::StatusCode),
}

impl UpstreamUpgraded {
    /// Take the upgraded upstream IO if the upstream agreed to switch protocols.
    pub fn into_io(self) -> Option<hyper::upgrade::Upgraded> {
        match self {
            UpstreamUpgraded::Hyper(io) => Some(io),
            UpstreamUpgraded::Rejected(_) => None,
        }
    }
}

// ---- request/response construction helpers ----

/// Compute the upstream request URI: use the target's explicit path-and-query
/// when present, otherwise the inbound URI's path-and-query. The authority/host
/// the connection dials is independent (it lives in [`ProxyTarget::transport`]);
/// the URI we send upstream over HTTP/1.1 is origin-form (path only).
fn upstream_uri(inbound: &Uri, target: &ProxyTarget) -> Result<Uri, HandlerError> {
    let pq = if target.path_and_query.is_empty() {
        inbound
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    } else {
        target.path_and_query.clone()
    };
    let pq = if pq.is_empty() { "/".to_string() } else { pq };
    pq.parse::<Uri>()
        .map_err(|e| HandlerError::Other(format!("bad upstream uri {pq:?}: {e}")))
}

/// Ensure a `Host` header exists. The original client `Host` is preserved when
/// present; if the inbound request carried none (e.g. HTTP/2 with only
/// `:authority`), fall back to the upstream authority.
fn ensure_host(headers: &mut http::HeaderMap, _target: &ProxyTarget, fallback_authority: &str) {
    if headers.contains_key(HOST) {
        return;
    }
    if let Ok(v) = HeaderValue::from_str(fallback_authority) {
        headers.insert(HOST, v);
    }
}

/// Rebuild the inbound request for the one bodyless retry from the pre-rewrite head
/// snapshotted before the first attempt.
///
/// The client's headers must ride along: on an empty map [`ensure_host`] finds no `Host`
/// and substitutes the upstream authority (and `X-Forwarded-Host` then inherits that wrong
/// value), while `Cookie` / `Authorization` / `Accept` / `Range` / conditional headers never
/// reach the backend — so the "retry" would be a materially different request than the one
/// the dead connection took. `Content-Length` is dropped because the replay carries an empty
/// body and [`body_is_present`] also classifies an unparseable value as bodyless. Hop-by-hop
/// headers and the `X-Forwarded-For` hop are handled by [`build_forward_request`], which runs
/// over this head exactly once, as it did on the first attempt.
fn rebuild_retry_request(
    method: http::Method,
    uri: Uri,
    headers: http::HeaderMap,
) -> Result<Request, http::Error> {
    let mut req = HttpRequest::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_11)
        .body(hj_core::empty_incoming())?;
    *req.headers_mut() = headers;
    req.headers_mut().remove(http::header::CONTENT_LENGTH);
    Ok(req)
}

/// Build the full outbound request (URI + rewritten headers + passthrough body)
/// for an ordinary (non-upgrade) forward.
fn build_forward_request(
    ctx: &ReqCtx,
    req: Request,
    target: &ProxyTarget,
    fallback_authority: &str,
) -> Result<HttpRequest<StreamBody>, HandlerError> {
    // This is the ORDINARY forward path; it has NO upgrade relay (the dedicated
    // WebSocket path uses `build_upstream_upgrade_request`). Never carry the inbound
    // `Upgrade` / `Connection: upgrade` headers downstream — replaying them to a
    // backend whose 101 we cannot relay produces a non-conformant handshake / a
    // wedged 101 and pins a pool slot. Strip them (they are hop-by-hop regardless).
    let keep_upgrade = false;
    let (mut parts, body) = req.into_parts();
    // The upstream pool speaks HTTP/1 (`conn::http1`), so the request line must be
    // HTTP/1.1. The inbound `parts.version` reflects the *downstream* protocol; for an
    // HTTP/3 (QUIC) client that is `HTTP/3.0`, which hyper's h1 request encoder hits
    // with `panic!("unexpected request version")` — aborting the task and dropping the
    // connection (HTTP/2.0 is silently coerced, but still wrong to forward). The
    // upstream wire protocol is independent of the client's, so normalize it here.
    parts.version = Version::HTTP_11;
    parts.uri = upstream_uri(&parts.uri, target)?;
    ensure_host(&mut parts.headers, target, fallback_authority);
    headers::rewrite_request_headers(&mut parts.headers, ctx, keep_upgrade);
    // The inbound body (IncomingBody = BoxBody<Bytes, BoxError>) is forwarded
    // verbatim — it is already the streaming body type, so request bodies
    // (uploads, POSTs, chunked uploads) pass through with no buffering.
    let out_body: StreamBody = forward_body(body);
    Ok(HttpRequest::from_parts(parts, out_body))
}

/// Forward an inbound request body to the upstream verbatim. `IncomingBody` and
/// `StreamBody` are the same `BoxBody<Bytes, BoxError>` type, so this is a
/// no-op move that keeps the streaming, unbuffered semantics.
fn forward_body(body: IncomingBody) -> StreamBody {
    body
}

/// An empty streaming body for handshake (upgrade) requests.
fn empty_stream_body() -> StreamBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

/// Convert a hyper upstream response into an [`hj_core::Response`] whose body is
/// a pass-through [`Body::Stream`]. Hop-by-hop headers are stripped.
fn into_streaming_response(resp: hyper::Response<Incoming>) -> Response {
    let (mut parts, incoming) = resp.into_parts();
    // Run BEFORE sanitize (which strips TE), while we can still see that the upstream framed by
    // Transfer-Encoding and thus that any Content-Length it also sent is stale.
    drop_stale_content_length_on_te(&mut parts.headers);
    headers::sanitize_response_headers(&mut parts.headers, false);
    let stream: StreamBody = box_incoming(incoming);
    http::Response::from_parts(parts, Body::Stream(stream))
}

/// If the upstream framed the body with `Transfer-Encoding` (chunked), drop any `Content-Length`
/// it ALSO sent — a conflicting CL+TE response (a response-smuggling/desync precursor) whose real
/// body length is the decoded chunk stream, NOT the CL. The body becomes a passthrough
/// `Body::Stream`; left in place, the stale CL would make the downstream h1 encoder frame by it
/// (truncating the body) and the h2/h3 encoder emit `content-length != sum(DATA)` (RFC 9113
/// §8.1.1 → Cloudflare rejects it). A CL-only response keeps its (correct) Content-Length.
fn drop_stale_content_length_on_te(headers: &mut http::HeaderMap) {
    if headers.contains_key(http::header::TRANSFER_ENCODING) {
        headers.remove(http::header::CONTENT_LENGTH);
    }
}

/// Box a hyper `Incoming` body into the workspace `StreamBody`
/// (`BoxBody<Bytes, BoxError>`), mapping hyper's error into [`BoxError`].
fn box_incoming(incoming: Incoming) -> BoxBody<Bytes, BoxError> {
    incoming.map_err(|e| Box::new(e) as BoxError).boxed()
}

/// Whether the inbound request actually carries a body to forward upstream.
///
/// Header-only detection is wrong in two directions and both matter here:
/// - h2/h3 reject `Transfer-Encoding` and a legal h2/h3 POST conveys its length only in
///   DATA frames (no `Content-Length`), so a header test mis-flags it bodyless (#33);
/// - a bogus `Transfer-Encoding: identity` (or any TE that isn't `chunked`) with no body
///   must NOT count as body-bearing (#14).
///
/// So we consult the actual body's `size_hint` first (the streaming `IncomingBody` reports a
/// non-zero / unknown length when bytes are coming), then fall back to a *real* positive
/// `Content-Length` or a `chunked` transfer-coding.
fn body_is_present(req: &Request) -> bool {
    let hint = req.body().size_hint();
    if hint.lower() > 0 || hint.upper() != Some(0) {
        return true;
    }
    if req
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .is_some_and(|n| n > 0)
    {
        return true;
    }
    req.headers()
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        })
}

/// Marker error surfaced when a forwarded request body makes no progress within the
/// inactivity window. Boxed into the body's `BoxError`, hyper propagates it out of
/// `send_request`; [`is_body_timeout`] recognizes it by walking the error source chain.
#[derive(Debug)]
struct BodyInactivityTimeout;

impl std::fmt::Display for BodyInactivityTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body upload stalled (inactivity timeout)")
    }
}

impl std::error::Error for BodyInactivityTimeout {}

/// True if `err`'s source chain contains a [`BodyInactivityTimeout`] — i.e. the
/// `send_request` failure was caused by our upload inactivity guard, not the upstream.
fn is_body_timeout(err: &hyper::Error) -> bool {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = src {
        if e.is::<BodyInactivityTimeout>() {
            return true;
        }
        src = e.source();
    }
    false
}

/// Wrap the outbound request body in an inactivity timeout that is reset on every
/// forwarded chunk (see [`InactivityBody`]).
fn wrap_body_inactivity_timeout(
    req: HttpRequest<StreamBody>,
    timeout: Duration,
) -> (HttpRequest<StreamBody>, tokio::sync::oneshot::Receiver<()>) {
    let (parts, body) = req.into_parts();
    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
    let wrapped: StreamBody = InactivityBody::new(body, timeout, Some(eof_tx)).boxed();
    (HttpRequest::from_parts(parts, wrapped), eof_rx)
}

/// A request-body wrapper that fails the body if no frame is produced within `timeout`.
/// The deadline is reset every time the inner body yields a frame, so a slow but
/// *progressing* upload survives while a trickling / never-terminating chunked upload
/// (no terminal chunk) is dropped — releasing the upstream's maxConns permit. (#14)
struct InactivityBody {
    inner: StreamBody,
    timeout: Duration,
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
    // (#69) Fired once when the upload reaches its terminal end (EOF) or errors, so the
    // forward path can start a response-HEAD timeout for the wait that follows. `None` once
    // fired (or when no signal was requested).
    eof_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl InactivityBody {
    fn new(
        inner: StreamBody,
        timeout: Duration,
        eof_tx: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Self {
        InactivityBody {
            inner,
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
            eof_tx,
        }
    }
}

impl HttpBody for InactivityBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // `StreamBody` is a `BoxBody` (Unpin) and `sleep` is a separately-pinned Box, so
        // projecting out of the pin via `get_mut` is sound.
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(opt) => {
                // Progress (or terminal end / error): reset the inactivity deadline.
                this.sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + this.timeout);
                // (#69) On terminal end (None) or error, signal the forward path that the
                // upload is done so it can bound the remaining wait for response headers.
                if matches!(opt, None | Some(Err(_))) {
                    if let Some(tx) = this.eof_tx.take() {
                        let _ = tx.send(());
                    }
                }
                std::task::Poll::Ready(opt)
            }
            std::task::Poll::Pending => match this.sleep.as_mut().poll(cx) {
                std::task::Poll::Ready(()) => {
                    std::task::Poll::Ready(Some(Err(Box::new(BodyInactivityTimeout) as BoxError)))
                }
                std::task::Poll::Pending => std::task::Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use hj_core::Proto;
    use hj_core::config::{ServerConfig, VHostConfig};
    use http_body_util::Empty;

    fn ctx(client_ip: &str, is_tls: bool) -> ReqCtx {
        let server = ServerConfig {
            server_root: Default::default(),
            server_name: String::new(),
            user: String::new(),
            group: String::new(),
            index_files: vec![],
            tuning: Default::default(),
            quic_enable: false,
            use_ip_in_proxy_header: 0,
            expires: Default::default(),
            cache: Default::default(),
            security: Default::default(),
            suexec: Default::default(),
            ext_processors: vec![],
            php_config: None,
            listeners: vec![],
            vhosts: Default::default(),
            vhost_order: vec![],
            mime: Default::default(),
        };
        ReqCtx {
            server: Arc::new(server),
            vhost_name: "t".into(),
            vhost: Arc::new(VHostConfig::default()),
            peer_ip: client_ip.parse().unwrap(),
            client_ip: client_ip.parse().unwrap(),
            is_tls,
            protocol: Proto::Http1,
            trusted_proxy: false,
            env: vec![],
            local_addr: "127.0.0.1:8080".parse().unwrap(),
            peer_port: 0,
            request_time: std::time::SystemTime::now(),
            request_id: Default::default(),
            tls: None,
            redirect_guard: None,
        }
    }

    fn empty_req(host: &str, path: &str) -> Request {
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        http::Request::builder()
            .uri(path)
            .header(HOST, host)
            .body(body)
            .unwrap()
    }

    fn full_req(host: &str, path: &str, payload: &'static [u8]) -> Request {
        let body: hj_core::IncomingBody = http_body_util::Full::new(Bytes::from_static(payload))
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        http::Request::builder()
            .uri(path)
            .header(HOST, host)
            .body(body)
            .unwrap()
    }

    #[test]
    fn body_present_detects_real_body_without_content_length() {
        // (#33) An h2/h3 POST conveys its length in DATA frames with no Content-Length;
        // detection must see the body via size_hint, not the (absent) header.
        let req = full_req("h", "/x", b"payload");
        assert!(
            body_is_present(&req),
            "non-empty body w/o CL is body-bearing"
        );
    }

    #[test]
    fn body_present_false_for_empty_get() {
        let req = empty_req("h", "/x");
        assert!(
            !body_is_present(&req),
            "an empty-body request is not body-bearing"
        );
    }

    #[test]
    fn body_present_false_for_transfer_encoding_identity() {
        // (#14) `Transfer-Encoding: identity` (no body) must NOT be treated as body-bearing,
        // which is what would route it onto the no-head-timeout path.
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/x")
            .header(HOST, "h")
            .header(http::header::TRANSFER_ENCODING, "identity")
            .body(body)
            .unwrap();
        assert!(
            !body_is_present(&req),
            "identity TE with no body is not body-bearing"
        );
    }

    #[test]
    fn body_present_true_for_chunked() {
        // A chunked upload (no Content-Length, body not yet known) is body-bearing even when
        // the stub body reports empty — `chunked` is the signal.
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/x")
            .header(HOST, "h")
            .header(http::header::TRANSFER_ENCODING, "chunked")
            .body(body)
            .unwrap();
        assert!(
            body_is_present(&req),
            "chunked transfer-encoding is body-bearing"
        );
    }

    #[test]
    fn body_present_true_for_positive_content_length() {
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/x")
            .header(HOST, "h")
            .header(http::header::CONTENT_LENGTH, "5")
            .body(body)
            .unwrap();
        assert!(body_is_present(&req), "CL>0 is body-bearing");
    }

    /// Test body: yields `first` once, then is permanently `Pending` (simulates a chunked
    /// upload that delivered one chunk and then stalled — never sending more / the terminator).
    struct OneThenStall {
        first: Option<Bytes>,
    }

    impl HttpBody for OneThenStall {
        type Data = Bytes;
        type Error = BoxError;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if let Some(b) = self.first.take() {
                return std::task::Poll::Ready(Some(Ok(Frame::data(b))));
            }
            std::task::Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn inactivity_body_errors_on_stall() {
        // A body that never yields its next chunk must surface a BodyInactivityTimeout once
        // the inactivity window elapses, so the upstream send resolves and the permit frees.
        let inner: StreamBody = OneThenStall {
            first: Some(Bytes::from_static(b"first")),
        }
        .boxed();
        let mut wrapped = InactivityBody::new(inner, Duration::from_secs(5), None);

        // The first chunk passes straight through and resets the deadline.
        let f1 = std::future::poll_fn(|cx| std::pin::Pin::new(&mut wrapped).poll_frame(cx)).await;
        assert!(matches!(f1, Some(Ok(_))), "first chunk passes through");

        // The inner body now stalls forever; advance virtual time past the window.
        let stalled = std::future::poll_fn(|cx| std::pin::Pin::new(&mut wrapped).poll_frame(cx));
        tokio::pin!(stalled);
        // Poll once so the sleep arms against the current (paused) clock, then advance.
        assert!(
            futures_poll_once(stalled.as_mut()).is_pending(),
            "still pending before the window elapses"
        );
        tokio::time::advance(Duration::from_secs(6)).await;
        match stalled.await {
            Some(Err(e)) => assert!(
                e.downcast_ref::<BodyInactivityTimeout>().is_some(),
                "stall surfaces a BodyInactivityTimeout"
            ),
            other => panic!("expected a body timeout error, present={}", other.is_some()),
        }
    }

    /// Poll a pinned future exactly once with a no-op waker, returning the `Poll`.
    fn futures_poll_once<F: Future>(mut fut: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        fut.as_mut().poll(&mut cx)
    }

    #[test]
    fn forward_request_uses_target_path_when_set() {
        let c = ctx("9.9.9.9", false);
        let req = empty_req("client.example", "/orig/path?x=1");
        let target = ProxyTarget::parse_url("http://127.0.0.1:8002/tools.json").unwrap();
        let out = build_forward_request(&c, req, &target, &target.authority).unwrap();
        assert_eq!(out.uri().path(), "/tools.json");
        // Host preserved as the client's.
        assert_eq!(out.headers().get(HOST).unwrap(), "client.example");
        assert_eq!(out.headers().get("x-forwarded-for").unwrap(), "9.9.9.9");
        assert_eq!(out.headers().get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn forward_request_uses_inbound_path_when_target_pathless() {
        let c = ctx("9.9.9.9", true);
        let req = empty_req("client.example", "/api/v1/items?q=2");
        let target = ProxyTarget::parse_url("http://127.0.0.1:8000").unwrap();
        let out = build_forward_request(&c, req, &target, &target.authority).unwrap();
        assert_eq!(out.uri().path_and_query().unwrap(), "/api/v1/items?q=2");
        assert_eq!(out.headers().get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn forward_request_fills_host_fallback_when_absent() {
        let c = ctx("9.9.9.9", false);
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder().uri("/x").body(body).unwrap();
        let target = ProxyTarget::parse_url("http://127.0.0.1:8000/y").unwrap();
        let out = build_forward_request(&c, req, &target, &target.authority).unwrap();
        assert_eq!(out.headers().get(HOST).unwrap(), "127.0.0.1:8000");
    }

    #[test]
    fn forward_request_normalizes_h3_version_to_h11() {
        // Regression: an HTTP/3 (QUIC) client hitting a proxied context must not
        // forward `HTTP/3.0` to the h1 upstream pool — hyper's h1 request encoder
        // panics on it ("unexpected request version"), dropping the connection.
        let c = ctx("9.9.9.9", true);
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/x")
            .version(Version::HTTP_3)
            .header(HOST, "client.example")
            .body(body)
            .unwrap();
        let target = ProxyTarget::parse_url("http://127.0.0.1:8000/y").unwrap();
        let out = build_forward_request(&c, req, &target, &target.authority).unwrap();
        assert_eq!(out.version(), Version::HTTP_11);
    }

    #[test]
    fn forward_request_strips_websocket_upgrade_headers() {
        // The ORDINARY forward path has no upgrade relay, so an inbound WebSocket
        // handshake must NOT carry its `Upgrade` / `Connection: upgrade` headers to the
        // backend — replaying them yields a non-conformant handshake / wedged 101. They
        // are stripped (hop-by-hop), so the backend just sees a plain request.
        let c = ctx("9.9.9.9", false);
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/ws")
            .header(HOST, "client.example")
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::CONNECTION, "upgrade")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(body)
            .unwrap();
        let target = ProxyTarget::parse_url("http://127.0.0.1:8000").unwrap();
        let out = build_forward_request(&c, req, &target, &target.authority).unwrap();
        assert!(
            out.headers().get(http::header::UPGRADE).is_none(),
            "Upgrade must be stripped"
        );
        let conn = out
            .headers()
            .get(http::header::CONNECTION)
            .map(|v| v.to_str().unwrap_or("").to_ascii_lowercase());
        assert!(
            conn.as_deref()
                .map(|c| !c.contains("upgrade"))
                .unwrap_or(true),
            "Connection must not still advertise upgrade, got {conn:?}",
        );
    }

    #[test]
    fn retry_rebuild_replays_the_client_head() {
        // The one retry must be the SAME request the dead connection took. Without the
        // snapshotted head, ensure_host substitutes the upstream authority for the client
        // Host and X-Forwarded-Host silently inherits it.
        let c = ctx("9.9.9.9", false);
        let mut h = http::HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("client.example"));
        h.insert(
            http::header::COOKIE,
            HeaderValue::from_static("xf_session=abc"),
        );
        h.insert(
            http::header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        h.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer t0ken"),
        );
        h.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        let uri: Uri = "/tools.json?a=1".parse().unwrap();
        let req = rebuild_retry_request(http::Method::GET, uri, h).unwrap();
        let target = ProxyTarget::parse_url("http://127.0.0.1:8002").unwrap();
        let out = build_forward_request(&c, req, &target, &target.authority).unwrap();

        assert_eq!(out.headers().get(HOST).unwrap(), "client.example");
        assert_eq!(
            out.headers().get("x-forwarded-host").unwrap(),
            "client.example"
        );
        assert_eq!(
            out.headers().get(http::header::COOKIE).unwrap(),
            "xf_session=abc"
        );
        assert_eq!(
            out.headers().get(http::header::ACCEPT).unwrap(),
            "text/event-stream"
        );
        assert_eq!(
            out.headers().get(http::header::AUTHORIZATION).unwrap(),
            "Bearer t0ken"
        );
        // The snapshot is pre-rewrite, so the rewrite appends our hop exactly once.
        assert_eq!(
            out.headers().get("x-forwarded-for").unwrap(),
            "198.51.100.7, 9.9.9.9"
        );
        assert_eq!(out.uri().path_and_query().unwrap(), "/tools.json?a=1");
    }

    #[test]
    fn retry_rebuild_drops_framing_and_hop_by_hop() {
        let c = ctx("9.9.9.9", false);
        let mut h = http::HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("client.example"));
        h.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        h.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("identity"),
        );
        h.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-hop"),
        );
        h.insert("x-hop", HeaderValue::from_static("secret"));
        let uri: Uri = "/x".parse().unwrap();
        let req = rebuild_retry_request(http::Method::GET, uri, h).unwrap();
        assert!(req.headers().get(http::header::CONTENT_LENGTH).is_none());

        let target = ProxyTarget::parse_url("http://127.0.0.1:8002").unwrap();
        let out = build_forward_request(&c, req, &target, &target.authority).unwrap();
        assert!(out.headers().get(http::header::TRANSFER_ENCODING).is_none());
        assert!(out.headers().get(http::header::CONNECTION).is_none());
        assert!(out.headers().get("x-hop").is_none());
        assert_eq!(out.headers().get(HOST).unwrap(), "client.example");
    }

    #[test]
    fn connection_host_token_does_not_delete_the_host() {
        // RFC 9110 7.6.1 forbids naming Host in Connection; honoring it would let a client
        // strip the Host and make the backend answer 400.
        let c = ctx("9.9.9.9", false);
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/")
            .header(HOST, "ai.windowsforum.com")
            .header(http::header::CONNECTION, "keep-alive, host")
            .body(body)
            .unwrap();
        let target = ProxyTarget::parse_url("http://127.0.0.1:8001").unwrap();
        let out = build_forward_request(&c, req, &target, &target.authority).unwrap();
        assert_eq!(out.headers().get(HOST).unwrap(), "ai.windowsforum.com");
        assert_eq!(
            out.headers().get("x-forwarded-host").unwrap(),
            "ai.windowsforum.com"
        );
    }

    #[test]
    fn upgrade_request_normalizes_version_to_h11() {
        let c = ctx("9.9.9.9", false);
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/socket")
            .version(Version::HTTP_2)
            .header(HOST, "client.example")
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .body(body)
            .unwrap();
        let target = ProxyTarget::from_websocket_map(&hj_core::config::WebSocketMap {
            uri: "/".into(),
            address: "127.0.0.1:8001".into(),
        });
        let out = Proxy::build_upstream_upgrade_request(&c, req, &target).unwrap();
        assert_eq!(out.version(), Version::HTTP_11);
    }

    #[test]
    fn upgrade_request_preserves_ws_headers() {
        let c = ctx("9.9.9.9", false);
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/socket")
            .header(HOST, "client.example")
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .body(body)
            .unwrap();
        let target = ProxyTarget::from_websocket_map(&hj_core::config::WebSocketMap {
            uri: "/".into(),
            address: "127.0.0.1:8001".into(),
        });
        let out = Proxy::build_upstream_upgrade_request(&c, req, &target).unwrap();
        assert_eq!(out.uri().path(), "/socket");
        assert_eq!(
            out.headers().get(http::header::UPGRADE).unwrap(),
            "websocket"
        );
        assert!(out.headers().contains_key("sec-websocket-key"));
        assert!(out.headers().contains_key("sec-websocket-version"));
        assert_eq!(out.headers().get("x-forwarded-for").unwrap(), "9.9.9.9");
    }

    #[tokio::test]
    async fn secure_websocket_upstream_fails_closed() {
        let c = ctx("9.9.9.9", false);
        let body: hj_core::IncomingBody = Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/socket")
            .header(HOST, "client.example")
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .body(body)
            .unwrap();
        let target = ProxyTarget::parse_url("wss://127.0.0.1:1/socket").unwrap();
        match Proxy::new().proxy_websocket(&c, req, &target).await {
            Err(HandlerError::BadGateway(e)) => assert!(e.contains("secure websocket")),
            Err(e) => panic!("expected BadGateway, got {e}"),
            Ok(_) => panic!("wss upstream should fail closed before dialing"),
        }
    }

    #[tokio::test]
    async fn upgrade_request_drops_body_and_framing_headers() {
        // Regression (#13): the WS handshake leg must carry NO body and NO framing headers, even
        // when the client sent an upgrade WITH a Content-Length + body (an attacker / buggy-client
        // shape). The old live path used build_forward_request, which replayed the inbound body.
        use http_body_util::BodyExt as _;
        let c = ctx("9.9.9.9", false);
        let body: hj_core::IncomingBody = http_body_util::Full::new(Bytes::from_static(b"hello"))
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let req = http::Request::builder()
            .uri("/socket")
            .header(HOST, "client.example")
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::CONTENT_LENGTH, "5")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(body)
            .unwrap();
        let target = ProxyTarget::from_websocket_map(&hj_core::config::WebSocketMap {
            uri: "/".into(),
            address: "127.0.0.1:8001".into(),
        });
        let out = Proxy::build_upstream_upgrade_request(&c, req, &target).unwrap();
        assert!(
            out.headers().get(http::header::CONTENT_LENGTH).is_none(),
            "no Content-Length on the handshake leg"
        );
        assert!(
            out.headers().get(http::header::TRANSFER_ENCODING).is_none(),
            "no Transfer-Encoding on the handshake leg"
        );
        assert!(
            out.headers().contains_key(http::header::UPGRADE),
            "ws upgrade header preserved"
        );
        let collected = out.into_body().collect().await.unwrap().to_bytes();
        assert!(collected.is_empty(), "the handshake leg body must be empty");
    }

    #[test]
    fn stale_content_length_dropped_only_on_transfer_encoding() {
        // Regression (#14): a conflicting CL+TE upstream response has the stale CL removed (the real
        // length is the chunk stream); a CL-only response keeps its (correct) CL.
        let mut both = http::HeaderMap::new();
        both.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("100"),
        );
        both.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        drop_stale_content_length_on_te(&mut both);
        assert!(
            both.get(http::header::CONTENT_LENGTH).is_none(),
            "CL+TE: stale Content-Length dropped"
        );

        let mut cl_only = http::HeaderMap::new();
        cl_only.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("100"),
        );
        drop_stale_content_length_on_te(&mut cl_only);
        assert_eq!(
            cl_only.get(http::header::CONTENT_LENGTH).unwrap(),
            "100",
            "CL-only: correct Content-Length kept"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_echoes_bytes_over_duplex() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Topology: client_end <-> proxy_a  |  proxy_b <-> upstream_end.
        // The proxy relays bytes between proxy_a and proxy_b.
        let (client_end, proxy_a) = tokio::io::duplex(1024);
        let (proxy_b, upstream_end) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move { Proxy::relay(proxy_a, proxy_b).await });

        // Echo upstream: read until EOF, echoing everything back, then close.
        // `copy_bidirectional` only returns once *both* directions hit EOF, so
        // the client below must shut down its write half after sending.
        let upstream = tokio::spawn(async move {
            let mut up = upstream_end;
            let mut buf = [0u8; 64];
            loop {
                match up.read(&mut buf).await.unwrap() {
                    0 => break,
                    n => {
                        up.write_all(&buf[..n]).await.unwrap();
                        up.flush().await.unwrap();
                    }
                }
            }
            up.shutdown().await.unwrap(); // closes upstream->client direction
        });

        let mut client = client_end;
        client.write_all(b"ping-123").await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap(); // EOF on client->upstream direction

        // Read the echoed bytes back from the relay until it closes.
        let mut out = Vec::new();
        let mut tmp = [0u8; 64];
        loop {
            match client.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        assert_eq!(&out, b"ping-123");

        upstream.await.unwrap();
        let (c2u, u2c) = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay must terminate once both halves EOF")
            .unwrap()
            .unwrap();
        assert_eq!(c2u, 8, "client->upstream byte count");
        assert_eq!(u2c, 8, "upstream->client byte count");
    }

    #[test]
    fn response_sanitize_strips_hop_by_hop_keeps_sse_content_type() {
        // `Incoming` cannot be constructed outside hyper, so we exercise the
        // response-header sanitizer directly. This guards the SSE path: the
        // streaming content-type must survive while hop-by-hop headers go.
        let mut hm = http::HeaderMap::new();
        hm.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        hm.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        hm.insert(
            "content-type",
            HeaderValue::from_static("text/event-stream"),
        );
        hm.insert(
            "x-cache-optimizer",
            HeaderValue::from_static("redirect-301"),
        );
        headers::sanitize_response_headers(&mut hm, false);
        assert!(!hm.contains_key(http::header::CONNECTION));
        assert!(!hm.contains_key("keep-alive"));
        assert!(
            !hm.contains_key("x-cache-optimizer"),
            "internal cache policy labels must not cross the proxy boundary"
        );
        assert_eq!(hm.get("content-type").unwrap(), "text/event-stream");
    }
}
