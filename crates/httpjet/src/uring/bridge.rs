//! Cross-runtime bridge: the monoio io_uring request cores hand each request to a
//! **tokio side-runtime** that owns `ServerState` and runs the (tokio-coupled)
//! httpjet pipeline (`pipeline::handle` → vhost/cache/rewrite/lsphp/proxy), then
//! the response is buffered back to the monoio caller to write over io_uring.
//!
//! This lets the io_uring TCP transports (H1/H2) serve the REAL pipeline without
//! porting lsphp/proxy/cache off tokio. The hop is a channel send + a oneshot
//! await; the oneshot is awaited on the monoio executor and woken by the tokio
//! side — wakers are runtime-agnostic, so it crosses the boundary cleanly. The
//! per-request cost (~µs) is negligible against PHP/pipeline work.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bytes::Bytes;
use http_body_util::BodyExt;
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use hj_core::{Body, Proto, Request, Response};

use crate::serving_generation::RequestGeneration;

/// Per-request connection context the pipeline needs (peer/local addr, protocol,
/// TLS + mTLS state, SNI, SSL_* params). Carried across the runtime boundary
/// alongside the request. Its connection metadata is built once per handshake
/// and cloned per request; dispatch may then attach a request-generation snapshot.
#[derive(Clone)]
pub(crate) struct BridgeCtx {
    pub peer: std::net::SocketAddr,
    pub local: std::net::SocketAddr,
    pub proto: Proto,
    pub is_tls: bool,
    /// This connection's H1 writer can consume a pinned `Body::File` directly.
    /// True only for plain TCP H1 and successfully upgraded TLS 1.3 kTLS H1;
    /// userspace TLS, H2/H3, and UDS must stream through their existing paths.
    pub direct_file_egress: bool,
    /// (Tier 2) UDS connection: peer/local are loopback fabrications.
    pub peer_unix: bool,
    /// The listener requests a client certificate (`clientVerify` >= 1), so only a
    /// presented one lets forwarded client identity through (real IP, forwarding
    /// headers). Refusing a cert-less peer (`clientVerify` 2) happens at accept.
    pub client_auth_requested: bool,
    /// TLS SNI server_name (vhost routing key on the secure listener).
    pub sni: Option<std::sync::Arc<str>>,
    /// SSL_* CGI params (protocol/cipher/client-cert) for the LSAPI env, mirroring
    /// the tokio TLS path's `extract_tls_meta`.
    pub tls: Option<hj_core::TlsParams>,
    /// Application generation selected by the transport before dispatch. This
    /// travels beside the request instead of through `http::Extensions`, so a
    /// normal bridged request does not allocate an extension map merely to pin
    /// its reload snapshot.
    pub request_generation: Option<RequestGeneration>,
    /// This connection's share of the server-wide body budget for bridged
    /// response streams, shared by every request the connection carries
    /// (see [`CONNECTION_RESPONSE_MEM`]).
    pub response_budget: Arc<hj_core::budget::BodyBufferBudget>,
}

impl BridgeCtx {
    /// A unix-domain-socket context: peer/local are fabricated loopback, the
    /// filesystem mode is the real access boundary.
    pub(crate) fn unix(local: std::net::SocketAddr, proto: Proto) -> Self {
        BridgeCtx {
            peer: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            local,
            proto,
            is_tls: false,
            direct_file_egress: false,
            peer_unix: true,
            client_auth_requested: false,
            sni: None,
            tls: None,
            request_generation: None,
            response_budget: connection_response_budget(),
        }
    }

    /// A plaintext (non-TLS) context for the given peer/local/proto.
    pub(crate) fn plain(
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
        proto: Proto,
    ) -> Self {
        BridgeCtx {
            peer,
            local,
            proto,
            is_tls: false,
            direct_file_egress: proto == Proto::Http1,
            peer_unix: false,
            client_auth_requested: false,
            sni: None,
            tls: None,
            request_generation: None,
            response_budget: connection_response_budget(),
        }
    }
}

/// The body half of a [`BridgeResp`]: either fully buffered (the common small / cache-HIT
/// case — byte-identical to the pre-streaming path) or a chunk channel the monoio side
/// drains incrementally (large files, large renders, SSE).
pub(crate) enum BridgeBody {
    Full(Bytes),
    /// A pinned file/range retained across the runtime boundary. Produced only
    /// when the H1 writer can use `sendfile(2)` (plain TCP or TLS 1.3 kTLS).
    File(hj_core::FileBody),
    /// Incremental chunks from the tokio forwarder. `len` is `Some` when the total length
    /// is known up front (a `Body::File`) so H1 can emit `Content-Length`; `None` ⇒ H1
    /// frames it `Transfer-Encoding: chunked`. An `Err(())` item signals a mid-stream
    /// upstream error AFTER headers were sent — the transport aborts the response
    /// (connection close / RST_STREAM) rather than finishing it cleanly.
    Stream {
        rx: mpsc::Receiver<Result<Bytes, ()>>,
        len: Option<u64>,
    },
}

/// A response handed back across the runtime boundary.
pub(crate) struct BridgeResp {
    pub completion: Option<hj_core::ResponseCompletion>,
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: BridgeBody,
    /// (Tier 2) Per-connection egress rate (bytes/sec) the H1 writer should pace this
    /// response with; None ⇒ the connection-wide ServeConfig default. Popped from the
    /// pipeline's `PerConnBandwidth` response extension.
    pub bw_rate: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct UringUpgradeRequest {
    ready: mpsc::Sender<UringUpgradeIo>,
}

pub(crate) struct UringUpgradeIo {
    pub to_upstream: mpsc::Sender<Bytes>,
    pub from_upstream: mpsc::Receiver<Result<Bytes, ()>>,
}

impl UringUpgradeRequest {
    pub(crate) fn channel() -> (Self, mpsc::Receiver<UringUpgradeIo>) {
        let (ready, receiver) = mpsc::channel(1);
        (Self { ready }, receiver)
    }

    pub(crate) async fn handoff(self, io: UringUpgradeIo) -> Result<(), UringUpgradeIo> {
        self.ready.send(io).await.map_err(|e| e.0)
    }
}

struct BridgeReq {
    req: Request,
    ctx: BridgeCtx,
    resp: oneshot::Sender<BridgeResp>,
    cancel: CancellationToken,
    permit: AdmissionPermit,
    body_budget: Arc<hj_core::budget::BodyBufferBudget>,
}

/// Buffer-vs-stream cutoff for a `Body::Stream`: a response that fully buffers within this
/// stays `Full` (so the dominant dynamic MISS path — forum pages are <100 KiB — keeps its
/// byte-identical `Content-Length` framing); a stream that exceeds it switches to
/// incremental delivery. SSE and `Body::File` bypass this and stream immediately.
const STREAM_THRESHOLD: usize = 256 * 1024;
/// Disk read chunk for a streamed `Body::File`.
const FILE_CHUNK: usize = 64 * 1024;
/// Bounded backpressure between the tokio forwarder and the monoio drainer.
const STREAM_CHANNEL_DEPTH: usize = 8;
/// File chunks read ahead of the drainer. Each one holds up to a 1 MiB body-budget
/// lease, so this (not `STREAM_CHANNEL_DEPTH`) bounds what a stalled reader pins.
const FILE_READ_AHEAD: usize = 2;
/// Bridged response bytes one connection may hold queued across all its streams, so
/// a peer that stops reading (h2 window 0 on up to 256 streams) stalls only its own
/// streams instead of pinning the 512 MiB server-wide budget. A stalled >4 MiB file
/// stream pins ~3 MiB (`FILE_READ_AHEAD` 1 MiB chunks plus the one the h2 sender
/// pulls even at window 0), so ~10 fit; a stream whose reader keeps up holds at most
/// `FILE_READ_AHEAD + 1` chunks, so draining downloads never wait on it.
pub(crate) const CONNECTION_RESPONSE_MEM: u64 = 32 * 1024 * 1024;
/// Connection share a stream claims before pulling its next upstream frame, held
/// while the backend produces it (unbounded for SSE). The connection's maximum
/// concurrent streams (256) all holding it idle take half of
/// [`CONNECTION_RESPONSE_MEM`].
const FRAME_CLAIM: u64 = 64 * 1024;
/// A buffered body below this size is not charged to the response budgets: a peer
/// withholding flow-control credit can pin at most 256 streams x this uncharged per
/// connection, and the lease would cost more than the bytes it accounts.
const FULL_LEASE_MIN: usize = 16 * 1024;
/// Global cap across every monoio core sharing this bridge. This stays above the
/// normal backend pool sizes while preventing multiplexed H2/H3 connections from
/// creating an unbounded number of pipeline futures.
pub(crate) const MAX_IN_FLIGHT_REQUESTS: usize = 2048;

/// (security #263/M-2) Upper bound on how long a request waits for a bridge
/// admission slot before being shed with 503. Generous enough that a genuinely
/// busy server queues briefly; short enough that a slow-stream flood cannot park
/// unbounded numbers of waiters.
const BRIDGE_ADMISSION_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

fn bridge_admission_wait() -> std::time::Duration {
    if cfg!(test) {
        std::time::Duration::from_millis(200)
    } else {
        BRIDGE_ADMISSION_WAIT
    }
}

pub(crate) fn capacity_for_connection_limit(max_connections: u32) -> usize {
    match max_connections {
        0 => MAX_IN_FLIGHT_REQUESTS,
        configured => (configured as usize).min(MAX_IN_FLIGHT_REQUESTS),
    }
}

type LimitProvider = dyn Fn() -> usize + Send + Sync;

struct AdmissionGate {
    active: AtomicUsize,
    limit: Arc<LimitProvider>,
    generation: AtomicU64,
    changed: Notify,
}

impl AdmissionGate {
    fn new(limit: Arc<LimitProvider>) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            limit,
            generation: AtomicU64::new(0),
            changed: Notify::new(),
        })
    }

    fn current_limit(&self) -> usize {
        (self.limit)().clamp(1, MAX_IN_FLIGHT_REQUESTS)
    }

    fn try_acquire(self: &Arc<Self>) -> Option<AdmissionPermit> {
        loop {
            let limit = self.current_limit();
            let active = self.active.load(Ordering::Acquire);
            if active >= limit {
                return None;
            }
            let next = active + 1;
            if self
                .active
                .compare_exchange_weak(active, next, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            // A concurrent reload may lower the live limit between the first read and the
            // successful CAS. Confirm it before returning the permit; if this admission no
            // longer fits, roll back our own increment and wait under the new limit.
            if next <= self.current_limit() {
                return Some(AdmissionPermit { gate: self.clone() });
            }
            self.active.fetch_sub(1, Ordering::AcqRel);
            self.changed.notify_one();
        }
    }

    async fn acquire(self: &Arc<Self>) -> AdmissionPermit {
        loop {
            let generation = self.generation.load(Ordering::Acquire);
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(permit) = self.try_acquire() {
                return permit;
            }
            // `notify_waiters` does not retain a permit when no waiter is registered. The
            // generation closes that race for a limit raise between our snapshot and `enable`.
            if self.generation.load(Ordering::Acquire) != generation {
                continue;
            }
            notified.await;
        }
    }

    fn limit_changed(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_waiters();
    }
}

struct AdmissionPermit {
    gate: Arc<AdmissionGate>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let previous = self.gate.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "bridge admission count underflow");
        self.gate.changed.notify_one();
    }
}

#[derive(Clone)]
pub(crate) struct BridgeAdmission {
    gate: Arc<AdmissionGate>,
}

impl BridgeAdmission {
    pub(crate) fn dynamic<L>(limit: L) -> Self
    where
        L: Fn() -> usize + Send + Sync + 'static,
    {
        let limit: Arc<LimitProvider> = Arc::new(limit);
        Self {
            gate: AdmissionGate::new(limit),
        }
    }

    #[cfg(test)]
    fn fixed(limit: usize) -> Self {
        assert!(limit > 0, "bridge capacity must be non-zero");
        Self::dynamic(move || limit)
    }

    pub(crate) fn limit_changed(&self) {
        self.gate.limit_changed();
    }
}

struct CancelOnDrop {
    token: CancellationToken,
    armed: bool,
}

impl CancelOnDrop {
    fn new(token: CancellationToken) -> Self {
        Self { token, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.token.cancel();
        }
    }
}

/// Clonable handle the monoio cores use to dispatch a request to the side-runtime.
#[derive(Clone)]
pub(crate) struct Bridge {
    tx: mpsc::Sender<BridgeReq>,
    admission: Arc<AdmissionGate>,
    timer: tokio::runtime::Handle,
    body_budget: Arc<hj_core::budget::BodyBufferBudget>,
}

impl Bridge {
    /// Send `req` (+ its connection context) to the tokio side-runtime and await
    /// the buffered response. `None` if the side-runtime is gone.
    pub(crate) async fn dispatch(&self, req: Request, ctx: BridgeCtx) -> Option<BridgeResp> {
        // (security #263/M-2) Bound the WAIT for admission. A flood of slow streaming
        // responses otherwise parks every new request on this gate forever — each
        // waiter holds a monoio task + transport buffers while slots drain at the
        // upstream's pace. Try non-blocking first (the common case pays nothing),
        // then wait at most [`BRIDGE_ADMISSION_WAIT`] before shedding 503.
        let permit = match self.admission.try_acquire() {
            Some(p) => p,
            None => {
                let wait = async { self.admission.acquire().await };
                // (#344) The sleep must be CREATED under the side-runtime's
                // handle: dispatch() polls on monoio transport threads, where a
                // bare tokio::time::sleep panics ("no reactor running") — with
                // panic=abort that took every TLS worker down the first time a
                // flood actually exhausted admission (found by the #329
                // harness; prod had never fired this path). The entered handle
                // binds the timer to the tokio side-runtime, whose wheel wakes
                // us across the runtime boundary; the future stays Send.
                let shed_timer = {
                    let _guard = self.timer.enter();
                    tokio::time::sleep(bridge_admission_wait())
                };
                tokio::select! {
                    p = wait => p,
                    _ = shed_timer => {
                        tracing::debug!("bridge admission wait exceeded; shedding request");
                        return Some(service_unavailable_resp());
                    }
                }
            }
        };
        let (rtx, rrx) = oneshot::channel();
        let cancel = CancellationToken::new();
        let mut cancel_on_drop = CancelOnDrop::new(cancel.clone());
        self.tx
            .send(BridgeReq {
                req,
                ctx,
                resp: rtx,
                cancel,
                permit,
                body_budget: self.body_budget.clone(),
            })
            .await
            .ok()?;
        match rrx.await {
            Ok(resp) => {
                cancel_on_drop.disarm();
                Some(resp)
            }
            Err(_) => None,
        }
    }

    /// Dispatch and reassemble a full `hj_core::Response` (with a `Body::Full`
    /// body). Used by the H2 monoio handler, whose service contract is
    /// `Fn(Request) -> Future<Response>` (they re-frame the response themselves),
    /// unlike the H1 path which writes the wire bytes directly from a `BridgeResp`.
    pub(crate) async fn dispatch_response(&self, req: Request, ctx: BridgeCtx) -> Response {
        match self.dispatch(req, ctx).await {
            Some(r) => bridge_resp_to_response(no_upgrade_final(r)),
            None => hj_core::text_response(http::StatusCode::BAD_GATEWAY, "bridge unavailable\n"),
        }
    }
}

/// H2/H3 have no `101` (RFC 9113 §8.6, RFC 9114 §4.5) and carry no upgrade, so a
/// backend's `101` final response becomes a 502, as the H1 writer already answers a 101
/// it has no upgrade for.
pub(crate) fn no_upgrade_final(r: BridgeResp) -> BridgeResp {
    if r.status != http::StatusCode::SWITCHING_PROTOCOLS {
        return r;
    }
    let mut out = bad_gateway();
    out.completion = r.completion;
    out
}

/// Reassemble a [`BridgeResp`] into an `hj_core::Response`. A `Full` body becomes
/// `Body::Full`; a `Stream` becomes a channel-backed `Body::Stream` the native h2/h3
/// framers stream frame-by-frame (their `pulls` machinery). Status + every header are
/// preserved verbatim; the H2/H3 framers recompute their own framing from this.
pub(crate) fn bridge_resp_to_response(r: BridgeResp) -> Response {
    let body = match r.body {
        BridgeBody::Full(b) => Body::Full(b),
        BridgeBody::File(f) => Body::File(f),
        BridgeBody::Stream { rx, len } => {
            let mut headers = r.headers;
            // A known-length stream (an uncached file) keeps its Content-Length:
            // the exact size hint tells the h2 framer the header is truthful.
            if let Some(n) = len {
                headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(n));
            }
            let body = Body::Stream(ChannelBody { rx, remaining: len }.boxed());
            let mut resp = http::Response::new(body);
            *resp.status_mut() = r.status;
            *resp.headers_mut() = headers;
            if let Some(completion) = r.completion {
                resp.extensions_mut().insert(completion);
            }
            return resp;
        }
    };
    let mut resp = http::Response::new(body);
    *resp.status_mut() = r.status;
    *resp.headers_mut() = r.headers;
    if let Some(completion) = r.completion {
        resp.extensions_mut().insert(completion);
    }
    resp
}

/// A response body the monoio side reconstructs from the bridge's chunk channel for the
/// H2/H3 framers (which re-frame a `Response` themselves). The tokio forwarder polls the
/// REAL upstream body and sends frames here; `mpsc::Receiver::poll_recv` is
/// runtime-agnostic, so this is safe to poll on the monoio executor. An `Err(())` item
/// surfaces as a body error, which the h2/h3 stack turns into a stream reset.
struct ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, ()>>,
    /// Bytes still owed when the total is known (the forwarder aborts a short
    /// body with an error item, so the count never undershoots silently).
    remaining: Option<u64>,
}

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = hj_core::BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(b))) => {
                if let Some(r) = self.remaining.as_mut() {
                    *r = r.saturating_sub(b.len() as u64);
                }
                Poll::Ready(Some(Ok(http_body::Frame::data(b))))
            }
            Poll::Ready(Some(Err(()))) => {
                Poll::Ready(Some(Err("bridged upstream body error".into())))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self.remaining {
            Some(n) => http_body::SizeHint::with_exact(n),
            None => http_body::SizeHint::default(),
        }
    }
}

/// Spawn the tokio side-runtime (its own threads) running `handler` per bridged
/// request and buffering each response body to `Bytes`. The returned [`Bridge`] is
/// cloned to every monoio core. `handler` is typically a closure capturing
/// `Arc<ServerState>` and calling `pipeline::handle`.
/// The receiver loop: spawn `handler` per bridged request, buffer the response.
async fn run_receiver<F, Fut>(mut rx: mpsc::Receiver<BridgeReq>, handler: Arc<F>)
where
    F: Fn(Request, BridgeCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::error!(%error, "bridge request task failed");
                }
            }
            request = rx.recv() => {
                let Some(BridgeReq {
                    req,
                    ctx,
                    resp,
                    cancel,
                    permit,
                    body_budget,
                }) = request else {
                    break;
                };
                if resp.is_closed() {
                    continue;
                }
                let handler = handler.clone();
                // The request future is ~15 KiB; a recycled slot keeps the tokio task
                // small and the future's memory resident across requests on this worker.
                tasks.spawn(hj_core::Recycled::new(async move {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {}
                        _ = async move {
                            let direct_file = ctx.direct_file_egress;
                            let budget = ResponseBudget {
                                global: body_budget,
                                connection: ctx.response_budget.clone(),
                            };
                            let response = handler(req, ctx).await;
                            forward_response_with_budget(response, resp, direct_file, &budget).await;
                        } => {}
                    }
                    drop(permit);
                }));
            }
        }
    }
    tasks.shutdown().await;
}

/// A clean 502 substituted when an upstream body errors BEFORE any byte has crossed to the
/// client (still fully buffered) — a partial body under the backend's `Content-Length`
/// would be a malformed response. Once headers/bytes have been sent (streaming), a
/// mid-stream error instead aborts the response (see `BridgeBody::Stream`).
pub(crate) fn bad_gateway() -> BridgeResp {
    BridgeResp {
        completion: None,
        status: http::StatusCode::BAD_GATEWAY,
        headers: http::HeaderMap::new(),
        body: BridgeBody::Full(Bytes::from_static(b"upstream body truncated\n")),
        bw_rate: None,
    }
}

/// (security #263/M-2) Shed with 503 when admission can't be obtained in time —
/// server capacity, not a client error.
pub(crate) fn service_unavailable_resp() -> BridgeResp {
    BridgeResp {
        completion: None,
        status: http::StatusCode::SERVICE_UNAVAILABLE,
        headers: http::HeaderMap::new(),
        body: BridgeBody::Full(Bytes::from_static(b"server busy\n")),
        bw_rate: None,
    }
}

#[inline]
fn take_response_completion(
    extensions: &mut http::Extensions,
) -> Option<hj_core::ResponseCompletion> {
    if extensions.is_empty() {
        None
    } else {
        extensions.remove::<hj_core::ResponseCompletion>()
    }
}

fn full_resp(mut parts: http::response::Parts, body: Bytes, bw_rate: Option<u64>) -> BridgeResp {
    let status = parts.status;
    observe_response_head(&mut parts, status);
    // The Full arms own `parts` outright — move the header map instead of cloning it per
    // bridged response.
    BridgeResp {
        completion: take_response_completion(&mut parts.extensions),
        status: parts.status,
        headers: parts.headers,
        body: BridgeBody::Full(body),
        bw_rate,
    }
}

/// Convert an on-core fast-path response without discarding a direct-egress H1
/// file descriptor. Non-file bodies retain the historical fully-buffered fast
/// path; only an uncached `Body::File` eligible for direct egress stays a file.
pub(crate) async fn fast_response(r: Response, direct_file: bool) -> BridgeResp {
    let (mut parts, body) = r.into_parts();
    let bw_rate = parts
        .extensions
        .remove::<crate::pipeline::PerConnBandwidth>()
        .map(|b| b.0);
    match body {
        Body::Empty => full_resp(parts, Bytes::new(), bw_rate),
        Body::Full(bytes) => full_resp(parts, bytes, bw_rate),
        Body::File(file) if file.cached.is_some() => {
            full_resp(parts, file.cached_ranged().unwrap_or_default(), bw_rate)
        }
        Body::File(file) if direct_file => {
            let status = parts.status;
            observe_response_head(&mut parts, status);
            BridgeResp {
                completion: take_response_completion(&mut parts.extensions),
                status: parts.status,
                headers: strip_framing(parts.headers),
                body: BridgeBody::File(file),
                bw_rate,
            }
        }
        body => {
            let (bytes, truncated) = buffer_body(body).await;
            if truncated {
                bad_gateway_for(parts)
            } else {
                full_resp(parts, bytes, bw_rate)
            }
        }
    }
}

fn bad_gateway_for(mut parts: http::response::Parts) -> BridgeResp {
    observe_response_head(&mut parts, http::StatusCode::BAD_GATEWAY);
    let mut response = bad_gateway();
    response.completion = take_response_completion(&mut parts.extensions);
    response
}

fn service_unavailable_for(mut parts: http::response::Parts) -> BridgeResp {
    observe_response_head(&mut parts, http::StatusCode::SERVICE_UNAVAILABLE);
    let mut response = service_unavailable_resp();
    response.completion = take_response_completion(&mut parts.extensions);
    response
}

fn observe_response_head(parts: &mut http::response::Parts, status: http::StatusCode) {
    #[cfg(feature = "otel")]
    if let Some(head) = parts.extensions.remove::<crate::otel::ResponseHead>() {
        head.record(status);
    }
    #[cfg(not(feature = "otel"))]
    let _ = (parts, status);
}

/// Hop-by-hop framing headers the bridge re-derives when it streams a response (it picks
/// `Content-Length` vs `Transfer-Encoding: chunked` itself / the h2 framer reframes).
fn strip_framing(mut h: http::HeaderMap) -> http::HeaderMap {
    h.remove(http::header::CONTENT_LENGTH);
    h.remove(http::header::TRANSFER_ENCODING);
    h
}

/// An SSE response must start streaming immediately (it is open-ended / slow — buffering
/// to the threshold would never complete).
fn is_event_stream(h: &http::HeaderMap) -> bool {
    h.get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
        })
        .unwrap_or(false)
}

/// Classify the handler's `Body` and hand it back across the bridge. Small / in-memory
/// bodies stay `Full` (byte-identical to the pre-streaming path, zero extra copy); large
/// files and large/SSE streams are forwarded incrementally.
#[cfg(test)]
async fn forward_response(r: Response, resp: oneshot::Sender<BridgeResp>, direct_file: bool) {
    let budget = ResponseBudget {
        global: Arc::new(hj_core::budget::BodyBufferBudget::new(
            hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
        )),
        connection: connection_response_budget(),
    };
    forward_response_with_budget(r, resp, direct_file, &budget).await;
}

async fn forward_response_with_budget(
    r: Response,
    resp: oneshot::Sender<BridgeResp>,
    direct_file: bool,
    body_budget: &ResponseBudget,
) {
    let (mut parts, body) = r.into_parts();
    let bw_rate = parts
        .extensions
        .remove::<crate::pipeline::PerConnBandwidth>()
        .map(|b| b.0);
    match body {
        Body::Empty => {
            let _ = resp.send(full_resp(parts, Bytes::new(), bw_rate));
        }
        Body::Full(b) => {
            let fresh = parts
                .extensions
                .get::<hj_core::FreshBody>()
                .is_some_and(|mark| mark.names(&b));
            send_full(parts, b, fresh, resp, bw_rate, body_budget).await
        }
        Body::File(f) if f.cached.is_some() => {
            // `cached` holds the WHOLE file; apply the range (single-sourced, bounds-clamped) so a
            // 206 served here matches the native-H2 path — previously this emitted the whole file
            // under a partial Content-Range.
            let body = f.cached_ranged().unwrap_or_default();
            send_full(parts, body, false, resp, bw_rate, body_budget).await;
        }
        Body::File(f) if direct_file => {
            let status = parts.status;
            observe_response_head(&mut parts, status);
            let _ = resp.send(BridgeResp {
                completion: take_response_completion(&mut parts.extensions),
                status: parts.status,
                headers: strip_framing(parts.headers),
                body: BridgeBody::File(f),
                bw_rate,
            });
        }
        Body::File(f) => forward_file(parts, f, resp, bw_rate, body_budget).await,
        Body::Stream(s) => forward_stream(parts, s, resp, bw_rate, body_budget).await,
    }
}

pub(crate) fn connection_response_budget() -> Arc<hj_core::budget::BodyBufferBudget> {
    Arc::new(hj_core::budget::BodyBufferBudget::new(
        CONNECTION_RESPONSE_MEM,
    ))
}

/// The server-wide body budget and the connection's share of it; every bridged
/// response chunk is charged to both.
#[derive(Clone)]
struct ResponseBudget {
    global: Arc<hj_core::budget::BodyBufferBudget>,
    connection: Arc<hj_core::budget::BodyBufferBudget>,
}

impl ResponseBudget {
    fn lease(&self) -> ResponseLease {
        ResponseLease {
            connection: hj_core::budget::BodyBufferLease::new(self.connection.clone()),
            global: hj_core::budget::BodyBufferLease::new(self.global.clone()),
        }
    }

    /// `preferred` capped to what both budgets can ever hold at once.
    fn chunk_size(&self, preferred: usize) -> usize {
        let fits = |budget: &hj_core::budget::BodyBufferBudget| match budget.capacity() {
            0 => usize::MAX,
            cap => usize::try_from(cap).unwrap_or(usize::MAX),
        };
        preferred
            .min(fits(&self.global))
            .min(fits(&self.connection))
    }

    /// A frame larger than the whole connection share is charged all of it, so it
    /// still queues (alone) instead of being refused.
    fn connection_share(&self, n: u64) -> u64 {
        match self.connection.capacity() {
            0 => n,
            cap => n.min(cap),
        }
    }
}

/// Bytes held on both budgets of a [`ResponseBudget`]; dropping it releases both.
struct ResponseLease {
    connection: hj_core::budget::BodyBufferLease,
    global: hj_core::budget::BodyBufferLease,
}

impl ResponseLease {
    fn release(&mut self, n: u64) {
        self.connection.release(n);
        self.global.release(n);
    }
}

fn leased_bytes(data: Bytes, lease: ResponseLease) -> Bytes {
    struct Owned {
        data: Bytes,
        _lease: ResponseLease,
    }
    impl AsRef<[u8]> for Owned {
        fn as_ref(&self) -> &[u8] {
            &self.data
        }
    }
    Bytes::from_owner(Owned {
        data,
        _lease: lease,
    })
}

/// Hand back a buffered response, first charging a FRESH body to both budgets for as long
/// as the transport holds it: an h2 peer withholding WINDOW_UPDATE keeps every queued body
/// alive. A body that shares its allocation (page-cache, memo or static-cache bytes, a
/// static) is accounted where it lives and passes uncharged, so a hit pays one atomic
/// load. `fresh` vouches for pooled bytes, which `is_unique` cannot recognize. Like a
/// stream frame, server-wide pressure sheds the response; the connection's own share
/// waits for its other streams to drain.
async fn send_full(
    parts: http::response::Parts,
    body: Bytes,
    fresh: bool,
    mut resp: oneshot::Sender<BridgeResp>,
    bw_rate: Option<u64>,
    budget: &ResponseBudget,
) {
    if body.len() < FULL_LEASE_MIN || !(fresh || body.is_unique()) {
        let _ = resp.send(full_resp(parts, body, bw_rate));
        return;
    }
    let n = body.len() as u64;
    let mut lease = budget.lease();
    if !lease.global.reserve(n) {
        drop(body);
        let _ = resp.send(service_unavailable_for(parts));
        return;
    }
    let share = budget.connection_share(n);
    if !lease.connection.reserve(share) {
        let reserved = tokio::select! {
            biased;
            reserved = lease.connection.reserve_wait(share) => reserved,
            _ = resp.closed() => false,
        };
        if !reserved {
            return;
        }
    }
    let _ = resp.send(full_resp(parts, leased_bytes(body, lease), bw_rate));
}

/// Wait for `bytes` on the connection's share, then on the server-wide budget, so a
/// connection whose streams stall waits on itself. `None` once the receiver is gone.
async fn reserve_queue_bytes(
    tx: &mpsc::Sender<Result<Bytes, ()>>,
    budget: &ResponseBudget,
    bytes: usize,
) -> Option<ResponseLease> {
    let bytes = bytes as u64;
    let mut lease = budget.lease();
    let reserved = tokio::select! {
        biased;
        reserved = async {
            lease.connection.reserve_wait(bytes).await && lease.global.reserve_wait(bytes).await
        } => reserved,
        _ = tx.closed() => false,
    };
    reserved.then_some(lease)
}

/// Queue one already-pulled frame. `Err` ends the stream: the receiver is gone, or the
/// frame was refused and the abort is already queued in its place.
async fn send_leased_chunk(
    tx: &mpsc::Sender<Result<Bytes, ()>>,
    budget: &ResponseBudget,
    data: Bytes,
) -> Result<(), ()> {
    if data.is_empty() {
        return Ok(());
    }
    let permit = tx.reserve().await.map_err(|_| ())?;
    send_leased(permit, tx, budget, budget.lease(), data).await
}

/// Charge `data` and queue it into the slot `permit` holds. The upstream has already
/// allocated this frame, so server-wide pressure refuses rather than waits: the frame
/// is released and the slot carries the abort instead. The connection's own share
/// (`lease` may already hold a claim on it) waits for the connection's other streams
/// to drain.
async fn send_leased(
    permit: mpsc::Permit<'_, Result<Bytes, ()>>,
    tx: &mpsc::Sender<Result<Bytes, ()>>,
    budget: &ResponseBudget,
    mut lease: ResponseLease,
    data: Bytes,
) -> Result<(), ()> {
    // Reserve the whole frame: splitting Bytes would pin its entire allocation
    // behind every slice and release accounting before the allocation dies.
    let n = data.len() as u64;
    if !lease.global.reserve(n) {
        drop(data);
        permit.send(Err(()));
        return Err(());
    }
    let share = budget.connection_share(n);
    let claimed = lease.connection.held();
    if claimed >= share {
        lease.connection.release(claimed - share);
    } else if !lease.connection.reserve(share - claimed) {
        // Wait holding none of the share: streams that each hold a claim while
        // waiting for more could otherwise exhaust the connection between them.
        lease.connection.release(claimed);
        let reserved = tokio::select! {
            biased;
            reserved = lease.connection.reserve_wait(share) => reserved,
            _ = tx.closed() => false,
        };
        if !reserved {
            return Err(());
        }
    }
    permit.send(Ok(leased_bytes(data, lease)));
    Ok(())
}

/// Stream an uncached `Body::File` from disk (the fast path already buffered small/cached
/// files, so one reaching the bridge is large or ranged). `Content-Length` is known, so H1
/// emits it and writes raw (resumable downloads); a mid-read error aborts.
async fn forward_file(
    mut parts: http::response::Parts,
    mut f: hj_core::FileBody,
    resp: oneshot::Sender<BridgeResp>,
    bw_rate: Option<u64>,
    body_budget: &ResponseBudget,
) {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let (start, len) = match f.range {
        Some((s, e)) => (s, e.saturating_sub(s) + 1),
        None => (0, f.len),
    };
    let pinned = f.file.is_some();
    let mut file = match f.file.take() {
        Some(file) => tokio::fs::File::from_std(file),
        None => match tokio::fs::File::open(&f.path).await {
            Ok(file) => file,
            Err(_) => {
                let _ = resp.send(bad_gateway_for(parts));
                return;
            }
        },
    };
    if (pinned || start > 0) && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        let _ = resp.send(bad_gateway_for(parts));
        return;
    }
    let status = parts.status;
    observe_response_head(&mut parts, status);
    let headers = strip_framing(parts.headers);
    let (tx, rrx) = mpsc::channel(FILE_READ_AHEAD);
    let _ = resp.send(BridgeResp {
        completion: take_response_completion(&mut parts.extensions),
        status: parts.status,
        headers,
        body: BridgeBody::Stream {
            rx: rrx,
            len: Some(len),
        },
        bw_rate,
    });
    let mut remaining = len;
    // (#349 D1) Parity with hj-h2's file streamer: adaptive chunks (4-16x
    // fewer blocking-pool hops + channel sends per MiB than the old fixed
    // 64 KiB), the read lands directly in the Bytes we ship (no
    // copy_from_slice), and the kernel gets a sequential-readahead hint.
    let chunk_size: usize = if len > 4 * 1024 * 1024 {
        1024 * 1024
    } else {
        FILE_CHUNK.max(256 * 1024)
    };
    {
        use std::os::unix::io::AsRawFd;
        let _ = rustix::fs::fadvise(
            unsafe { std::os::fd::BorrowedFd::borrow_raw(file.as_raw_fd()) },
            start,
            Some(std::num::NonZeroU64::new(len).unwrap_or(std::num::NonZeroU64::MIN)),
            rustix::fs::Advice::Sequential,
        );
    }
    let chunk_size = body_budget.chunk_size(chunk_size);
    while remaining > 0 {
        // Queue slot first, then budget (the connection's share, then the server's),
        // then the read: a reader that stops draining parks this loop holding no
        // lease, so it pins only the chunks already queued.
        let Ok(permit) = tx.reserve().await else {
            return; // client gone
        };
        let want = remaining.min(chunk_size as u64) as usize;
        let Some(mut lease) = reserve_queue_bytes(&tx, body_budget, want).await else {
            return;
        };
        let mut buf = bytes::BytesMut::with_capacity(want);
        match (&mut file).take(want as u64).read_buf(&mut buf).await {
            Ok(0) => {
                // Short file (truncated since stat): we already committed Content-Length, so
                // signal an abort rather than finish a short body under the wrong CL.
                permit.send(Err(()));
                return;
            }
            Ok(n) => {
                lease.release((want - n) as u64);
                permit.send(Ok(leased_bytes(buf.freeze(), lease)));
                remaining -= n as u64;
            }
            Err(_) => {
                permit.send(Err(()));
                return;
            }
        }
    }
}

/// A proxied upstream body that must reach the client as it arrives: hj-proxy marked
/// it (unsized upstream framing or `X-Accel-Buffering: no`), and it still has no
/// `Content-Length` or still says `X-Accel-Buffering: no`. A sized proxied body keeps
/// the buffered path below, so small proxied responses stay `Full` and byte-identical.
fn is_unbuffered_proxy_body(parts: &http::response::Parts) -> bool {
    if parts.extensions.get::<hj_core::ProxiedBody>().is_none() {
        return false;
    }
    let accel_off = parts
        .headers
        .get_all("x-accel-buffering")
        .iter()
        .any(|v| v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"no"));
    accel_off || !parts.headers.contains_key(http::header::CONTENT_LENGTH)
}

const READY_FRAME_YIELD_INTERVAL: usize = 64;

/// Keep an always-ready stream of empty DATA or metadata frames from monopolizing
/// a bridge worker. These frames make no response progress, so periodically yield
/// before polling the body again; a real payload resets the counter.
async fn yield_after_skipped_frame(skipped: &mut usize) {
    *skipped += 1;
    if *skipped >= READY_FRAME_YIELD_INTERVAL {
        *skipped = 0;
        tokio::task::yield_now().await;
    }
}

/// Forward a `Body::Stream`. SSE and an unbuffered proxied body stream immediately and a
/// progressive body from its first byte; everything else buffers up to `STREAM_THRESHOLD`
/// (so small dynamic responses stay `Full` + byte-identical) and only switches to
/// incremental delivery past it. An error BEFORE the switch is a clean 502; after it, the
/// stream is aborted. A receiver that goes away while buffering drops the body at once.
async fn forward_stream(
    mut parts: http::response::Parts,
    mut s: hj_core::StreamBody,
    mut resp: oneshot::Sender<BridgeResp>,
    bw_rate: Option<u64>,
    body_budget: &ResponseBudget,
) {
    use http_body_util::BodyExt;
    if is_event_stream(&parts.headers) || is_unbuffered_proxy_body(&parts) {
        let status = parts.status;
        observe_response_head(&mut parts, status);
        let headers = strip_framing(parts.headers);
        let (tx, rrx) = mpsc::channel(STREAM_CHANNEL_DEPTH);
        let _ = resp.send(BridgeResp {
            completion: take_response_completion(&mut parts.extensions),
            status: parts.status,
            headers,
            body: BridgeBody::Stream { rx: rrx, len: None },
            bw_rate,
        });
        pump_body(s, tx, body_budget).await;
        return;
    }
    // A progressive body (a page-cache miss stored while it streams) switches at its first
    // byte: its early frames are the page head.
    let threshold = if parts
        .extensions
        .get::<hj_compress::ProgressiveBody>()
        .is_some()
    {
        0
    } else {
        STREAM_THRESHOLD
    };
    // Presize from the declared length (bounded: the buffer never needs more than the stream
    // threshold before it switches to streaming) instead of doubling up from zero.
    let declared = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let mut acc: Vec<u8> = if threshold == 0 {
        Vec::new()
    } else {
        hj_core::BODY_BUFS.take_buf(
            declared.map_or(0, |n| n.min(threshold)),
            hj_core::BODY_BUF_CAP,
        )
    };
    let freeze = |acc: Vec<u8>| hj_core::BODY_BUFS.freeze(acc, hj_core::BODY_BUF_CAP);
    let mut skipped_frames = 0usize;
    loop {
        // The client side dropping its receiver (disconnect, stream reset) must drop
        // the upstream body here: it can hold a backend maxConns permit for as long as
        // the backend keeps producing.
        let frame = tokio::select! {
            biased;
            frame = s.frame() => frame,
            _ = resp.closed() => return,
        };
        match frame {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(d) if !d.is_empty() => {
                    skipped_frames = 0;
                    if acc.len().saturating_add(d.len()) > threshold {
                        let status = parts.status;
                        observe_response_head(&mut parts, status);
                        let headers = strip_framing(parts.headers);
                        let (tx, rrx) = mpsc::channel(STREAM_CHANNEL_DEPTH);
                        let _ = resp.send(BridgeResp {
                            completion: take_response_completion(&mut parts.extensions),
                            status: parts.status,
                            headers,
                            body: BridgeBody::Stream { rx: rrx, len: None },
                            bw_rate,
                        });
                        if send_leased_chunk(&tx, body_budget, freeze(acc))
                            .await
                            .is_err()
                            || send_leased_chunk(&tx, body_budget, d).await.is_err()
                        {
                            return;
                        }
                        pump_body(s, tx, body_budget).await;
                        return;
                    }
                    acc.extend_from_slice(&d);
                }
                Ok(_) | Err(_) => yield_after_skipped_frame(&mut skipped_frames).await,
            },
            Some(Err(_)) => {
                let _ = resp.send(bad_gateway_for(parts));
                return;
            }
            None => {
                send_full(parts, freeze(acc), true, resp, bw_rate, body_budget).await;
                return;
            }
        }
    }
}

/// Pump the remaining frames of a stream body into the chunk channel until EOF, an error
/// (→ `Err(())` abort), or the drainer drops the receiver (client gone).
async fn pump_body(
    mut s: hj_core::StreamBody,
    tx: mpsc::Sender<Result<Bytes, ()>>,
    body_budget: &ResponseBudget,
) {
    use http_body_util::BodyExt;
    let claim = body_budget.connection_share(FRAME_CLAIM);
    let mut skipped_frames = 0usize;
    loop {
        // Claim the queue slot and a frame's worth of the connection's share before
        // pulling: while the reader (or the whole connection) stalls, the next frame
        // stays with the backend instead of sitting here uncharged.
        let Ok(permit) = tx.reserve().await else {
            return;
        };
        let mut lease = body_budget.lease();
        let claimed = tokio::select! {
            biased;
            claimed = lease.connection.reserve_wait(claim) => claimed,
            _ = tx.closed() => false,
        };
        if !claimed {
            return;
        }
        let data = loop {
            let frame = tokio::select! {
                frame = s.frame() => frame,
                _ = tx.closed() => return,
            };
            match frame {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(d) if !d.is_empty() => {
                        skipped_frames = 0;
                        break d;
                    }
                    Ok(_) | Err(_) => yield_after_skipped_frame(&mut skipped_frames).await,
                },
                Some(Err(_)) => {
                    permit.send(Err(()));
                    return;
                }
                None => return,
            }
        };
        if send_leased(permit, &tx, body_budget, lease, data)
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Spawn the bridge on its OWN tokio side-runtime (own threads). Used when there
/// is no ambient runtime (e.g. the bridge unit test running on monoio).
#[cfg(test)]
pub(crate) fn spawn_bridge<F, Fut>(threads: usize, handler: F) -> std::io::Result<Bridge>
where
    F: Fn(Request, BridgeCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    spawn_bridge_with_capacity(threads, MAX_IN_FLIGHT_REQUESTS, handler)
}

#[cfg(test)]
fn spawn_bridge_with_capacity<F, Fut>(
    threads: usize,
    max_in_flight: usize,
    handler: F,
) -> std::io::Result<Bridge>
where
    F: Fn(Request, BridgeCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads.max(1))
        .thread_stack_size(crate::RUNTIME_THREAD_STACK_BYTES)
        .enable_all()
        .build()?;
    let (bridge, rx) = bridge_channel(
        BridgeAdmission::fixed(max_in_flight),
        rt.handle().clone(),
        Arc::new(hj_core::budget::BodyBufferBudget::new(
            hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
        )),
    );
    let handler = Arc::new(handler);
    std::thread::Builder::new()
        .name("hj-uring-bridge".into())
        .stack_size(crate::RUNTIME_THREAD_STACK_BYTES)
        .spawn(move || {
            rt.block_on(run_receiver(rx, handler));
        })?;
    Ok(bridge)
}

/// Spawn the bridge receiver on the CURRENT (ambient) tokio runtime — used when
/// `ServerState` is built inside an existing runtime (the real serve path), so the
/// handler shares that runtime (and its lsphp pool / cache / timers).
#[cfg(test)]
pub(crate) fn spawn_on_current<F, Fut>(max_in_flight: usize, handler: F) -> Bridge
where
    F: Fn(Request, BridgeCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    spawn_on_current_with_admission(BridgeAdmission::fixed(max_in_flight), handler)
}

#[cfg(test)]
pub(crate) fn spawn_on_current_with_admission<F, Fut>(
    admission: BridgeAdmission,
    handler: F,
) -> Bridge
where
    F: Fn(Request, BridgeCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    spawn_on_current_with_budget(
        admission,
        Arc::new(hj_core::budget::BodyBufferBudget::new(
            hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
        )),
        handler,
    )
}

pub(crate) fn spawn_on_current_with_budget<F, Fut>(
    admission: BridgeAdmission,
    body_budget: Arc<hj_core::budget::BodyBufferBudget>,
    handler: F,
) -> Bridge
where
    F: Fn(Request, BridgeCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let (bridge, rx) = bridge_channel(admission, tokio::runtime::Handle::current(), body_budget);
    tokio::spawn(run_receiver(rx, Arc::new(handler)));
    bridge
}

fn bridge_channel(
    admission: BridgeAdmission,
    timer: tokio::runtime::Handle,
    body_budget: Arc<hj_core::budget::BodyBufferBudget>,
) -> (Bridge, mpsc::Receiver<BridgeReq>) {
    let (tx, rx) = mpsc::channel(MAX_IN_FLIGHT_REQUESTS);
    (
        Bridge {
            tx,
            admission: admission.gate,
            timer,
            body_budget,
        },
        rx,
    )
}

/// Buffer a response body to `Bytes`. The bridge returns a complete response; a
/// streaming / zero-copy egress path is a later refinement (SSE/large files
/// currently buffer).
/// Returns `(bytes, truncated)`. `truncated` is true if a streaming body errored
/// mid-flight or a file read failed — the bytes are then partial/empty and the caller
/// MUST NOT frame them under the original headers (a short body under a stale
/// Content-Length is a malformed response); the bridge substitutes a 502 instead.
pub(crate) async fn buffer_body(body: Body) -> (Bytes, bool) {
    match body {
        Body::Empty => (Bytes::new(), false),
        Body::Full(b) => (b, false),
        Body::Stream(s) => match s.collect().await {
            Ok(c) => (c.to_bytes(), false),
            Err(_) => (Bytes::new(), true),
        },
        Body::File(f) => match f.cached_ranged() {
            // `cached` holds the WHOLE file; apply the range (single-sourced) so a buffered ranged
            // cache hit yields the slice, not the whole file.
            Some(b) => (b, false),
            None => read_uncached_file_body(f).await,
        },
    }
}

/// Run blocking file I/O off the calling thread on the pipeline runtime's blocking
/// pool, inline when no runtime is reachable. `None` = the blocking task died.
async fn run_file_blocking<T: Send + 'static>(
    op: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    match crate::lscache::pipeline_handle() {
        Some(h) => h.spawn_blocking(op).await.ok(),
        None => Some(op()),
    }
}

/// NO tokio::fs here: `buffer_body` is reached from the io_uring on-core fast path (a
/// monoio thread with no tokio reactor), where tokio file I/O panics and `panic=abort`
/// takes the process down — the same class as the h2 `file_stream_body` crash loop
/// (2026-07-12). Positional `read_at` also leaves a pinned descriptor's cursor untouched.
///
/// On the inline no-runtime fallback each op runs on the event-loop thread itself, so
/// reads go ONE bounded op per `FILE_CHUNK` with an await between: the per-op bound —
/// not the file size — caps the stall (and lets the loop interleave with the other
/// connections multiplexed on that core). On the blocking pool one op reads the range:
/// each extra op was only another pool round trip.
async fn read_uncached_file_body(f: hj_core::FileBody) -> (Bytes, bool) {
    use std::sync::Arc;
    let (start, len) = match f.range {
        Some((start, end)) => {
            let Some(len) = end.checked_sub(start).and_then(|n| n.checked_add(1)) else {
                return (Bytes::new(), true);
            };
            (start, len)
        }
        None => (0, f.len),
    };
    // An unpinned whole-file read must also fail closed on a GROWN file (= replaced
    // under us), exactly like the old std::fs::read arm — probed one byte past the
    // expected end after a full read. A pinned fd needs no probe: it holds the exact
    // inode the cache handed out.
    let probe_growth = f.range.is_none() && f.file.is_none();
    let mut f = f;
    let file = match f.file.take() {
        Some(file) => Arc::new(file),
        None => {
            let path = f.path;
            match run_file_blocking(move || std::fs::File::open(&path)).await {
                Some(Ok(file)) => Arc::new(file),
                _ => return (Bytes::new(), true),
            }
        }
    };
    let op_bytes = if crate::lscache::pipeline_handle().is_some() {
        u64::MAX
    } else {
        FILE_CHUNK as u64
    };
    let mut out: Vec<u8> = Vec::with_capacity(len.min(FILE_CHUNK as u64) as usize);
    while (out.len() as u64) < len {
        let want = (len - out.len() as u64).min(op_bytes) as usize;
        let off = start + out.len() as u64;
        let reader = Arc::clone(&file);
        // The accumulator shuttles through the op and back (no per-chunk copy).
        let mut buf = std::mem::take(&mut out);
        let step = run_file_blocking(move || {
            let cur = buf.len();
            buf.resize(cur + want, 0);
            let mut filled = 0usize;
            let mut err = false;
            while filled < want {
                match std::os::unix::fs::FileExt::read_at(
                    &*reader,
                    &mut buf[cur + filled..],
                    off + filled as u64,
                ) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        err = true;
                        break;
                    }
                }
            }
            buf.truncate(cur + filled);
            (buf, err, filled)
        })
        .await;
        match step {
            Some((buf, false, filled)) => {
                out = buf;
                if filled == 0 {
                    break; // EOF short of `len` — the length check below fails closed
                }
            }
            // Read error or the blocking task died — partial bytes are discarded
            // by the caller (truncated => 502), so don't carry them.
            _ => return (Bytes::new(), true),
        }
    }
    let mut truncated = out.len() as u64 != len;
    if probe_growth && !truncated {
        let reader = Arc::clone(&file);
        let end = start + len;
        let grown = run_file_blocking(move || {
            let mut b = [0u8; 1];
            loop {
                match std::os::unix::fs::FileExt::read_at(&*reader, &mut b, end) {
                    Ok(n) => return Ok(n > 0),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(()),
                }
            }
        })
        .await;
        truncated = !matches!(grown, Some(Ok(false)));
    }
    (Bytes::from(out), truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_ctx() -> BridgeCtx {
        BridgeCtx::plain(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            Proto::Http1,
        )
    }

    fn test_request(sequence: usize) -> Request {
        http::Request::get(format!("/bridge-test/{sequence}"))
            .body(hj_core::empty_incoming())
            .unwrap()
    }

    async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while counter.load(Ordering::SeqCst) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "counter did not reach {expected}; current={}",
                counter.load(Ordering::SeqCst)
            )
        });
    }

    struct ActiveGuard(Arc<AtomicUsize>);

    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn connection_limit_configures_bridge_capacity_with_a_hard_ceiling() {
        assert_eq!(capacity_for_connection_limit(0), MAX_IN_FLIGHT_REQUESTS);
        assert_eq!(capacity_for_connection_limit(17), 17);
        assert_eq!(
            capacity_for_connection_limit(u32::MAX),
            MAX_IN_FLIGHT_REQUESTS
        );
    }

    #[tokio::test]
    async fn dynamic_admission_applies_live_lower_and_raise() {
        let limit = Arc::new(AtomicUsize::new(3));
        let gate = AdmissionGate::new({
            let limit = limit.clone();
            Arc::new(move || limit.load(Ordering::Acquire))
        });
        let first = gate.acquire().await;
        let second = gate.acquire().await;
        let third = gate.acquire().await;
        assert_eq!(gate.active.load(Ordering::Acquire), 3);

        limit.store(1, Ordering::Release);
        gate.limit_changed();
        let blocked = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.acquire().await })
        };
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());

        drop(first);
        drop(second);
        tokio::task::yield_now().await;
        assert_eq!(gate.active.load(Ordering::Acquire), 1);
        assert!(
            !blocked.is_finished(),
            "lowering below active work must admit nothing until the count drains below the new limit"
        );
        drop(third);
        let fourth = tokio::time::timeout(std::time::Duration::from_secs(1), blocked)
            .await
            .expect("a released slot must wake the waiter")
            .expect("waiter task must not fail");
        assert_eq!(gate.active.load(Ordering::Acquire), 1);

        let raised_a = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.acquire().await })
        };
        let raised_b = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.acquire().await })
        };
        tokio::task::yield_now().await;
        assert!(!raised_a.is_finished() && !raised_b.is_finished());
        limit.store(3, Ordering::Release);
        gate.limit_changed();
        let raised_a = tokio::time::timeout(std::time::Duration::from_secs(1), raised_a)
            .await
            .expect("raising the limit must wake queued acquisition immediately")
            .expect("first raised waiter must not fail");
        let raised_b = tokio::time::timeout(std::time::Duration::from_secs(1), raised_b)
            .await
            .expect("raising the limit must wake every newly eligible acquisition")
            .expect("second raised waiter must not fail");
        assert_eq!(gate.active.load(Ordering::Acquire), 3);

        drop((fourth, raised_a, raised_b));
        assert_eq!(gate.active.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn cancelled_admission_waiter_leaks_no_slot_and_permits_release() {
        let gate = AdmissionGate::new(Arc::new(|| 1));
        let held = gate.acquire().await;
        let cancelled = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.acquire().await })
        };
        tokio::task::yield_now().await;
        assert!(!cancelled.is_finished());
        cancelled.abort();
        let _ = cancelled.await;

        drop(held);
        let replacement = tokio::time::timeout(std::time::Duration::from_secs(1), gate.acquire())
            .await
            .expect("cancelling a waiter must not consume the released slot");
        assert_eq!(gate.active.load(Ordering::Acquire), 1);
        drop(replacement);
        assert_eq!(gate.active.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn buffer_uncached_file_body_applies_range_and_detects_short_read() {
        let path = std::env::temp_dir().join(format!(
            "hj-buffer-range-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let bytes = b"HJPC-metadata|page payload|container suffix";
        std::fs::write(&path, bytes).unwrap();
        let payload_start = b"HJPC-metadata|".len() as u64;
        let payload_len = b"page payload".len() as u64;

        let (body, truncated) = buffer_body(Body::File(hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: bytes.len() as u64,
            range: Some((payload_start, payload_start + payload_len - 1)),
            cached: None,
        }))
        .await;
        assert!(!truncated);
        assert_eq!(&body[..], b"page payload");

        let (body, truncated) = buffer_body(Body::File(hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: bytes.len() as u64,
            range: Some((bytes.len() as u64 - 3, bytes.len() as u64 + 10)),
            cached: None,
        }))
        .await;
        assert!(truncated);
        assert_eq!(&body[..], &bytes[bytes.len() - 3..]);

        let (body, truncated) = buffer_body(Body::File(hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: bytes.len() as u64,
            range: None,
            cached: None,
        }))
        .await;
        assert!(!truncated);
        assert_eq!(&body[..], bytes);

        std::fs::write(&path, b"short").unwrap();
        let (body, truncated) = buffer_body(Body::File(hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: bytes.len() as u64,
            range: None,
            cached: None,
        }))
        .await;
        assert!(truncated);
        assert_eq!(&body[..], b"short");

        // Grown file (= replaced under us): the growth PROBE flags it — the read
        // itself is bounded to the expected length, so the body holds the first
        // `len` bytes (immaterial: the caller discards bytes when truncated).
        let grown = [bytes.as_slice(), b"extra"].concat();
        std::fs::write(&path, &grown).unwrap();
        let (body, truncated) = buffer_body(Body::File(hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: bytes.len() as u64,
            range: None,
            cached: None,
        }))
        .await;
        assert!(truncated);
        assert_eq!(&body[..], bytes);
        let _ = std::fs::remove_file(path);
    }

    /// The chunked read must hold its bounded-op shape on multi-chunk files:
    /// every chunk lands byte-exact and a whole-file read spanning several
    /// FILE_CHUNK ops is not flagged truncated.
    #[tokio::test]
    async fn buffer_uncached_file_body_spans_multiple_chunks() {
        let path = std::env::temp_dir().join(format!(
            "hj-buffer-chunks-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut bytes = vec![0u8; FILE_CHUNK * 3 + 17];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        std::fs::write(&path, &bytes).unwrap();

        let (body, truncated) = buffer_body(Body::File(hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: bytes.len() as u64,
            range: None,
            cached: None,
        }))
        .await;
        assert!(!truncated);
        assert_eq!(&body[..], &bytes[..]);

        // Ranged read crossing a chunk boundary, on a PINNED fd.
        let start = FILE_CHUNK as u64 - 9;
        let end = 2 * FILE_CHUNK as u64 + 8;
        let (body, truncated) = buffer_body(Body::File(hj_core::FileBody {
            path: path.clone(),
            file: Some(std::fs::File::open(&path).unwrap()),
            len: bytes.len() as u64,
            range: Some((start, end)),
            cached: None,
        }))
        .await;
        assert!(!truncated);
        assert_eq!(&body[..], &bytes[start as usize..=end as usize]);
        let _ = std::fs::remove_file(path);
    }

    /// Validate the monoio→tokio→monoio round trip: a monoio task dispatches a
    /// request to the tokio side-runtime (which does real async work), and awaits
    /// the buffered response across the runtime boundary.
    #[test]
    fn cross_runtime_round_trip() {
        let bridge = spawn_bridge(1, |req: Request, _ctx: BridgeCtx| async move {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await; // real tokio async hop
            let path = req.uri().path().to_string();
            hj_core::text_response(http::StatusCode::OK, format!("bridged {path}"))
        })
        .unwrap();
        let mut rt = crate::uring::build_core_runtime().unwrap();
        rt.block_on(async move {
            let req = http::Request::get("/hello")
                .body(hj_core::empty_incoming())
                .unwrap();
            let ctx = BridgeCtx {
                peer: "127.0.0.1:1".parse().unwrap(),
                local: "127.0.0.1:80".parse().unwrap(),
                proto: Proto::Http1,
                is_tls: false,
                direct_file_egress: true,
                peer_unix: false,
                client_auth_requested: false,
                sni: None,
                tls: None,
                request_generation: None,
                response_budget: connection_response_budget(),
            };
            let resp = bridge.dispatch(req, ctx).await.expect("bridged response");
            assert_eq!(resp.status, http::StatusCode::OK);
            match resp.body {
                BridgeBody::Full(b) => assert_eq!(&b[..], b"bridged /hello"),
                BridgeBody::Stream { .. } => panic!("small response must stay Full"),
                BridgeBody::File(_) => panic!("small response must not become File"),
            }
        });
    }

    /// (#344) Admission exhaustion reached from a MONOIO thread must shed 503
    /// after the bounded wait. The tokio-timer sleep this path used to poll
    /// there panicked ("no reactor running") and, with panic=abort, took the
    /// whole transport worker down under a connection flood.
    #[test]
    fn admission_shed_on_monoio_thread_does_not_panic() {
        let bridge =
            spawn_bridge_with_capacity(1, 1, |_req: Request, _ctx: BridgeCtx| async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                hj_core::text_response(http::StatusCode::OK, "slow".to_string())
            })
            .unwrap();
        let mut rt = crate::uring::build_core_runtime().unwrap();
        rt.block_on(async move {
            let holder = {
                let bridge = bridge.clone();
                monoio::spawn(async move { bridge.dispatch(test_request(1), test_ctx()).await })
            };
            monoio::time::sleep(std::time::Duration::from_millis(50)).await;
            let start = std::time::Instant::now();
            let resp = bridge
                .dispatch(test_request(2), test_ctx())
                .await
                .expect("shed response");
            assert_eq!(resp.status, http::StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                start.elapsed() >= std::time::Duration::from_millis(150),
                "shed fired before the bounded admission wait"
            );
            drop(holder);
        });
    }

    #[tokio::test]
    async fn admission_bounds_active_handlers_and_reuses_slots() {
        const LIMIT: usize = 3;
        const REQUESTS: usize = 12;
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let bridge = spawn_on_current(LIMIT, {
            let active = active.clone();
            let peak = peak.clone();
            let started = started.clone();
            let gate = gate.clone();
            move |_req, _ctx| {
                let active = active.clone();
                let peak = peak.clone();
                let started = started.clone();
                let gate = gate.clone();
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    let _active = ActiveGuard(active);
                    peak.fetch_max(current, Ordering::SeqCst);
                    started.fetch_add(1, Ordering::SeqCst);
                    let _gate = gate.acquire().await.unwrap();
                    hj_core::text_response(http::StatusCode::OK, "done")
                }
            }
        });

        let mut requests = Vec::new();
        for sequence in 0..REQUESTS {
            let bridge = bridge.clone();
            requests.push(tokio::spawn(async move {
                bridge.dispatch(test_request(sequence), test_ctx()).await
            }));
        }

        wait_for_count(&started, LIMIT).await;
        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::SeqCst), LIMIT);
        assert_eq!(active.load(Ordering::SeqCst), LIMIT);
        assert_eq!(peak.load(Ordering::SeqCst), LIMIT);

        gate.add_permits(REQUESTS);
        for request in requests {
            assert!(request.await.unwrap().is_some());
        }
        assert_eq!(started.load(Ordering::SeqCst), REQUESTS);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(peak.load(Ordering::SeqCst), LIMIT);
    }

    #[tokio::test]
    async fn shared_admission_caps_independent_transport_bridges_globally() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let handlers = Arc::new(Semaphore::new(0));
        let admission = BridgeAdmission::fixed(2);
        let make_handler = || {
            let active = active.clone();
            let peak = peak.clone();
            let started = started.clone();
            let handlers = handlers.clone();
            move |_req, _ctx| {
                let active = active.clone();
                let peak = peak.clone();
                let started = started.clone();
                let handlers = handlers.clone();
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    let _active = ActiveGuard(active);
                    peak.fetch_max(current, Ordering::SeqCst);
                    started.fetch_add(1, Ordering::SeqCst);
                    let _handler = handlers.acquire().await.unwrap();
                    hj_core::text_response(http::StatusCode::OK, "done")
                }
            }
        };
        let http = spawn_on_current_with_admission(admission.clone(), make_handler());
        let https = spawn_on_current_with_admission(admission, make_handler());

        let first = tokio::spawn({
            let http = http.clone();
            async move { http.dispatch(test_request(1), test_ctx()).await }
        });
        let second = tokio::spawn({
            let https = https.clone();
            async move { https.dispatch(test_request(2), test_ctx()).await }
        });
        let third = tokio::spawn(async move { https.dispatch(test_request(3), test_ctx()).await });
        wait_for_count(&started, 2).await;
        tokio::task::yield_now().await;
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert!(!third.is_finished());

        handlers.add_permits(3);
        assert!(first.await.unwrap().is_some());
        assert!(second.await.unwrap().is_some());
        assert!(third.await.unwrap().is_some());
        assert_eq!(started.load(Ordering::SeqCst), 3);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dropped_response_receivers_cancel_handlers_and_release_slots() {
        const LIMIT: usize = 2;
        const REQUESTS: usize = 6;
        let active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let blocker = Arc::new(tokio::sync::Notify::new());
        let bridge = spawn_on_current(LIMIT, {
            let active = active.clone();
            let started = started.clone();
            let completed = completed.clone();
            let blocker = blocker.clone();
            move |_req, _ctx| {
                let active = active.clone();
                let started = started.clone();
                let completed = completed.clone();
                let blocker = blocker.clone();
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _active = ActiveGuard(active);
                    started.fetch_add(1, Ordering::SeqCst);
                    blocker.notified().await;
                    completed.fetch_add(1, Ordering::SeqCst);
                    hj_core::text_response(http::StatusCode::OK, "unexpected")
                }
            }
        });

        let mut requests = Vec::new();
        for sequence in 0..REQUESTS {
            let bridge = bridge.clone();
            requests.push(tokio::spawn(async move {
                bridge.dispatch(test_request(sequence), test_ctx()).await
            }));
        }
        wait_for_count(&started, LIMIT).await;

        for request in &requests {
            request.abort();
        }
        for request in requests {
            let _ = request.await;
        }
        wait_for_count(&active, 0).await;
        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::SeqCst), LIMIT);
        assert_eq!(completed.load(Ordering::SeqCst), 0);

        let replacement = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.dispatch(test_request(REQUESTS), test_ctx()).await })
        };
        wait_for_count(&started, LIMIT + 1).await;
        replacement.abort();
        let _ = replacement.await;
        wait_for_count(&active, 0).await;
        assert_eq!(completed.load(Ordering::SeqCst), 0);
    }

    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    fn poll_once<F: std::future::Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        std::future::Future::poll(future, &mut cx)
    }

    /// A test stream body yielding preset data frames, then optionally one error.
    struct VecStream {
        frames: VecDeque<Bytes>,
        err_at_end: bool,
    }
    impl http_body::Body for VecStream {
        type Data = Bytes;
        type Error = hj_core::BoxError;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            if let Some(b) = self.frames.pop_front() {
                return Poll::Ready(Some(Ok(http_body::Frame::data(b))));
            }
            if self.err_at_end {
                self.err_at_end = false;
                return Poll::Ready(Some(Err("boom".into())));
            }
            Poll::Ready(None)
        }
    }

    fn stream_resp(chunks: Vec<Bytes>, err_at_end: bool, content_type: Option<&str>) -> Response {
        let body = Body::Stream(
            VecStream {
                frames: chunks.into(),
                err_at_end,
            }
            .boxed(),
        );
        let mut b = http::Response::builder().status(200);
        if let Some(ct) = content_type {
            b = b.header(http::header::CONTENT_TYPE, ct);
        }
        b.body(body).unwrap()
    }

    #[tokio::test]
    async fn idle_stream_disconnect_drops_upstream_and_releases_admission() {
        struct Idle(ActiveGuard);
        impl http_body::Body for Idle {
            type Data = Bytes;
            type Error = hj_core::BoxError;
            fn poll_frame(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
                let _ = &self.0;
                std::task::Poll::Pending
            }
        }
        let alive = Arc::new(AtomicUsize::new(0));
        let bridge = spawn_on_current(1, {
            let alive = alive.clone();
            move |_req, _ctx| {
                alive.fetch_add(1, Ordering::SeqCst);
                let guard = ActiveGuard(alive.clone());
                async move {
                    http::Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(Body::Stream(Idle(guard).boxed()))
                        .unwrap()
                }
            }
        });
        let response = bridge.dispatch(test_request(1), test_ctx()).await.unwrap();
        assert_eq!(alive.load(Ordering::SeqCst), 1);
        drop(response);
        wait_for_count(&alive, 0).await;
        let next = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            bridge.dispatch(test_request(2), test_ctx()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(next.status, http::StatusCode::OK);
        drop(next);
        wait_for_count(&alive, 0).await;
    }

    #[tokio::test]
    async fn streamed_queue_budget_follows_last_alias_and_refuses_oversized_frames() {
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(12));
        let conn = one_connection(&budget);
        let (tx, mut rx) = mpsc::channel(8);
        send_leased_chunk(&tx, &conn, Bytes::from(vec![1; 8]))
            .await
            .unwrap();
        let data = rx.recv().await.unwrap().unwrap();
        let alias = data.slice(0..1);
        drop(data);
        assert_eq!(budget.in_flight(), 8);
        assert_eq!(conn.connection.in_flight(), 8);
        assert!(
            send_leased_chunk(&tx, &conn, Bytes::from(vec![2; 8]))
                .await
                .is_err()
        );
        drop(alias);
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(conn.connection.in_flight(), 0);
        assert!(
            send_leased_chunk(&tx, &conn, Bytes::from(vec![3; 13]))
                .await
                .is_err()
        );
        send_leased_chunk(&tx, &conn, Bytes::from(vec![4; 12]))
            .await
            .unwrap();
        assert_eq!(budget.in_flight(), 12);
        drop(rx);
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(conn.connection.in_flight(), 0);
    }

    #[tokio::test]
    async fn file_queue_wait_is_cancelled_when_client_disconnects() {
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(4));
        let conn = one_connection(&budget);
        let (tx, rx) = mpsc::channel(1);
        let held = reserve_queue_bytes(&tx, &conn, 4).await.unwrap();
        let waiter = tokio::spawn({
            let conn = conn.clone();
            async move { reserve_queue_bytes(&tx, &conn, 4).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(rx);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        drop(held);
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(conn.connection.in_flight(), 0);
        assert_eq!(conn.chunk_size(256 * 1024), 4);
    }

    struct Tracked(ActiveGuard);

    impl AsRef<[u8]> for Tracked {
        fn as_ref(&self) -> &[u8] {
            let _ = &self.0;
            b"overflow"
        }
    }

    fn tracked_stream(alive: &Arc<AtomicUsize>) -> hj_core::StreamBody {
        let frame = Bytes::from_owner(Tracked(ActiveGuard(alive.clone())));
        VecStream {
            frames: vec![frame].into(),
            err_at_end: false,
        }
        .boxed()
    }

    #[tokio::test]
    async fn stalled_stream_queue_leaves_the_next_frame_with_the_upstream() {
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(8));
        let conn = one_connection(&budget);
        let (tx, mut rx) = mpsc::channel(1);
        send_leased_chunk(&tx, &conn, Bytes::from(vec![0; 8]))
            .await
            .unwrap();
        let alive = Arc::new(AtomicUsize::new(1));
        let body = tracked_stream(&alive);
        let pump = tokio::spawn({
            let conn = conn.clone();
            async move { pump_body(body, tx, &conn).await }
        });
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            alive.load(Ordering::SeqCst),
            1,
            "a full queue must not pull (and hold uncharged) the next upstream frame"
        );
        assert!(!pump.is_finished());
        drop(rx.recv().await.unwrap().unwrap());
        assert_eq!(&rx.recv().await.unwrap().unwrap()[..], b"overflow");
        assert!(rx.recv().await.is_none());
        pump.await.unwrap();
        assert_eq!(alive.load(Ordering::SeqCst), 0);
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(budget.rejected(), 0);
    }

    #[tokio::test]
    async fn stream_frame_refused_by_the_budget_is_released_and_aborts() {
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(8));
        let mut hog = hj_core::budget::BodyBufferLease::new(budget.clone());
        assert!(hog.reserve(8));
        let (tx, mut rx) = mpsc::channel(1);
        let alive = Arc::new(AtomicUsize::new(1));
        let conn = one_connection(&budget);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            pump_body(tracked_stream(&alive), tx, &conn),
        )
        .await
        .expect("a refused frame aborts instead of waiting for budget");
        assert_eq!(
            alive.load(Ordering::SeqCst),
            0,
            "the refused frame is freed"
        );
        assert!(rx.recv().await.unwrap().is_err());
        assert!(rx.recv().await.is_none());
        assert_eq!(budget.rejected(), 1);
        assert_eq!(
            conn.connection.in_flight(),
            0,
            "the refused frame's claim is freed"
        );
        drop(hog);
        assert_eq!(budget.in_flight(), 0);
    }

    fn forward_full(body: Body, budget: &ResponseBudget) -> oneshot::Receiver<BridgeResp> {
        let (tx, rx) = oneshot::channel();
        let budget = budget.clone();
        tokio::spawn(async move {
            forward_response_with_budget(http::Response::new(body), tx, false, &budget).await
        });
        rx
    }

    fn full_body(resp: BridgeResp) -> Bytes {
        match resp.body {
            BridgeBody::Full(b) => b,
            _ => panic!("a buffered body stays Full"),
        }
    }

    // A peer that withholds WINDOW_UPDATE keeps every queued body alive (held here):
    // fresh buffered bodies stop at the connection's share instead of pinning
    // 256 streams' worth.
    #[tokio::test]
    async fn withheld_window_full_bodies_stop_at_the_connection_share() {
        const STREAMS: usize = 256;
        const LEN: usize = 200 * 1024;
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(
            hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
        ));
        let conn = one_connection(&global);
        let mut pending: VecDeque<_> = (0..STREAMS)
            .map(|_| forward_full(Body::Full(Bytes::from(vec![7; LEN])), &conn))
            .collect();
        let fits = (CONNECTION_RESPONSE_MEM / LEN as u64) as usize;
        wait_for_in_flight(&global, (STREAMS * LEN) as u64).await;
        let mut held = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while held.len() < fits {
                pending.retain_mut(|rx| match rx.try_recv() {
                    Ok(resp) => {
                        held.push(full_body(resp));
                        false
                    }
                    Err(_) => true,
                });
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the share's worth of bodies is delivered");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(pending.iter_mut().all(|rx| rx.try_recv().is_err()));
        assert_eq!(held.len(), fits);
        assert_eq!(conn.connection.in_flight(), (fits * LEN) as u64);
        assert!(conn.connection.in_flight() <= CONNECTION_RESPONSE_MEM);

        held.pop();
        let next = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pending.pop_front().unwrap(),
        )
        .await
        .expect("a drained body admits a waiting one")
        .unwrap();
        held.push(full_body(next));
        assert_eq!(conn.connection.in_flight(), (fits * LEN) as u64);

        drop(held);
        drop(pending);
        wait_for_in_flight(&global, 0).await;
        assert_eq!(conn.connection.in_flight(), 0);
        assert_eq!(global.rejected(), 0);
    }

    #[tokio::test]
    async fn a_pooled_body_is_charged_only_under_its_fresh_mark() {
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(
            hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
        ));
        let conn = one_connection(&global);
        let pooled = || {
            let mut buf = hj_core::BODY_BUFS.take_buf(64 * 1024, hj_core::BODY_BUF_CAP);
            buf.resize(64 * 1024, 7);
            hj_core::BODY_BUFS.freeze(buf, hj_core::BODY_BUF_CAP)
        };
        let marked = |body: Bytes, mark: &Bytes| {
            let mut resp = http::Response::new(Body::Full(body));
            resp.extensions_mut().insert(hj_core::FreshBody::of(mark));
            resp
        };
        let send = |resp: http::Response<Body>| {
            let (tx, rx) = oneshot::channel();
            let conn = conn.clone();
            tokio::spawn(async move { forward_response_with_budget(resp, tx, false, &conn).await });
            rx
        };

        let body = pooled();
        let fresh = full_body(send(marked(body.clone(), &body)).await.unwrap());
        drop(body);
        assert_eq!(
            global.in_flight(),
            64 * 1024,
            "a marked pooled body is charged"
        );
        drop(fresh);
        assert_eq!(global.in_flight(), 0);

        let (body, other) = (pooled(), Bytes::from(vec![0; 16]));
        let unmarked = full_body(
            send(http::Response::new(Body::Full(body.clone())))
                .await
                .unwrap(),
        );
        let stale = full_body(send(marked(body.clone(), &other)).await.unwrap());
        assert_eq!(
            global.in_flight(),
            0,
            "unmarked or swapped bytes pass uncharged"
        );
        drop((unmarked, stale, body));
    }

    #[tokio::test]
    async fn shared_and_small_full_bodies_are_not_charged() {
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(
            hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
        ));
        let conn = one_connection(&global);
        let stored = Bytes::from(vec![1; 64 * 1024]);
        let cached = hj_core::FileBody {
            path: "/nonexistent".into(),
            file: None,
            len: stored.len() as u64,
            range: None,
            cached: Some(stored.clone()),
        };
        let mut held = Vec::new();
        for body in [
            Body::Full(stored.clone()),
            Body::File(cached),
            Body::Full(Bytes::from_static(&[2; 64 * 1024])),
            Body::Full(Bytes::from(vec![3; FULL_LEASE_MIN - 1])),
        ] {
            held.push(full_body(forward_full(body, &conn).await.unwrap()));
        }
        assert_eq!(global.in_flight(), 0);
        assert_eq!(conn.connection.in_flight(), 0);

        let fresh = full_body(
            forward_full(Body::Full(Bytes::from(vec![4; FULL_LEASE_MIN])), &conn)
                .await
                .unwrap(),
        );
        assert_eq!(conn.connection.in_flight(), FULL_LEASE_MIN as u64);
        assert_eq!(global.in_flight(), FULL_LEASE_MIN as u64);
        drop(fresh);
        assert_eq!(global.in_flight(), 0);
        assert_eq!(conn.connection.in_flight(), 0);
    }

    #[tokio::test]
    async fn buffered_stream_body_is_charged_and_global_pressure_sheds() {
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(256 * 1024));
        let conn = one_connection(&global);
        let chunks = vec![Bytes::from(vec![5; 100 * 1024]); 2];
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn({
            let conn = conn.clone();
            async move {
                forward_response_with_budget(stream_resp(chunks, false, None), tx, false, &conn)
                    .await
            }
        });
        let body = full_body(rx.await.unwrap());
        task.await.unwrap();
        assert_eq!(body.len(), 200 * 1024);
        assert_eq!(conn.connection.in_flight(), 200 * 1024);

        let shed = forward_full(Body::Full(Bytes::from(vec![6; 100 * 1024])), &conn)
            .await
            .unwrap();
        assert_eq!(shed.status, http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(global.rejected(), 1);
        drop(body);
        assert_eq!(global.in_flight(), 0);
        assert_eq!(conn.connection.in_flight(), 0);
    }

    const MIB: usize = 1024 * 1024;

    fn one_connection(global: &Arc<hj_core::budget::BodyBufferBudget>) -> ResponseBudget {
        ResponseBudget {
            global: global.clone(),
            connection: connection_response_budget(),
        }
    }

    fn temp_file(tag: &str, len: usize) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("httpjet-bridge-{tag}-{}.bin", std::process::id()));
        std::fs::write(&path, vec![0x5a; len]).unwrap();
        path
    }

    async fn start_file_stream(
        path: &std::path::Path,
        len: u64,
        budget: &ResponseBudget,
    ) -> (
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<Result<Bytes, ()>>,
    ) {
        let response = http::Response::new(Body::File(hj_core::FileBody {
            path: path.to_path_buf(),
            file: None,
            len,
            range: None,
            cached: None,
        }));
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn({
            let budget = budget.clone();
            async move { forward_response_with_budget(response, tx, false, &budget).await }
        });
        let BridgeBody::Stream { rx, len: Some(n) } = rx.await.unwrap().body else {
            panic!("a large uncached file must stream with its length");
        };
        assert_eq!(n, len);
        (task, rx)
    }

    async fn wait_for_in_flight(budget: &hj_core::budget::BodyBufferBudget, n: u64) {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while budget.in_flight() != n {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("in_flight stuck at {} (want {n})", budget.in_flight()));
    }

    async fn settled_in_flight(budget: &hj_core::budget::BodyBufferBudget) -> u64 {
        let mut last = u64::MAX;
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let now = budget.in_flight();
            if now == last && now != 0 {
                return now;
            }
            last = now;
        }
        last
    }

    async fn drain_len(mut rx: mpsc::Receiver<Result<Bytes, ()>>) -> usize {
        let mut total = 0;
        while let Some(chunk) = rx.recv().await {
            let chunk = chunk.expect("file stream must not abort");
            assert!(chunk.iter().all(|&b| b == 0x5a));
            total += chunk.len();
        }
        total
    }

    #[tokio::test]
    async fn stalled_file_streams_keep_the_body_budget_bounded() {
        const STREAMS: usize = 8;
        const LEN: usize = 12 * MIB;
        let path = temp_file("stalled-file", LEN);
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(64 * MIB as u64));
        let mut streams = Vec::new();
        for _ in 0..STREAMS {
            let conn = one_connection(&budget);
            streams.push(start_file_stream(&path, LEN as u64, &conn).await);
        }
        let pinned = settled_in_flight(&budget).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(budget.in_flight(), pinned, "undrained streams stop reading");
        assert!(
            pinned <= (STREAMS * FILE_READ_AHEAD * MIB) as u64,
            "undrained file streams pinned {pinned} bytes"
        );
        assert_eq!(
            budget.rejected(),
            0,
            "a stream waiting on its queue is not a refusal"
        );
        let mut fresh = hj_core::budget::BodyBufferLease::new(budget.clone());
        assert!(fresh.reserve(64 * 1024), "unrelated bodies still fit");
        drop(fresh);

        let (first_task, first_rx) = streams.remove(0);
        assert_eq!(drain_len(first_rx).await, LEN);
        first_task.await.unwrap();
        for (task, rx) in streams {
            drop(rx);
            task.await.unwrap();
        }
        assert_eq!(budget.in_flight(), 0);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn file_streams_waiting_on_an_exhausted_budget_wake_on_release() {
        const LEN: usize = 12 * MIB;
        let path = temp_file("budget-wait", LEN);
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(2 * MIB as u64));
        let (a_task, a_rx) = start_file_stream(&path, LEN as u64, &one_connection(&budget)).await;
        let (b_task, b_rx) = start_file_stream(&path, LEN as u64, &one_connection(&budget)).await;
        assert_eq!(settled_in_flight(&budget).await, 2 * MIB as u64);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::join!(drain_len(a_rx), drain_len(b_rx))
        })
        .await
        .expect("a waiter must wake when the budget is released");
        assert_eq!((a, b), (LEN, LEN));
        a_task.await.unwrap();
        b_task.await.unwrap();
        assert_eq!(budget.rejected(), 0, "waiting for budget is not a refusal");
        assert_eq!(budget.in_flight(), 0);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn one_connections_stalled_streams_wait_on_its_own_share() {
        const STREAMS: usize = 32;
        const LEN: usize = 12 * MIB;
        let path = temp_file("conn-share", LEN);
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(64 * MIB as u64));
        let stalled = one_connection(&budget);
        let mut streams = Vec::new();
        for _ in 0..STREAMS {
            streams.push(start_file_stream(&path, LEN as u64, &stalled).await);
        }
        // 32 streams x FILE_READ_AHEAD chunks ask for twice the share: it fills.
        let pinned = CONNECTION_RESPONSE_MEM;
        wait_for_in_flight(&stalled.connection, pinned).await;
        // A window-0 h2 sender still pulls one chunk per stream and holds it.
        let mut pulled = Vec::new();
        for (_, rx) in &mut streams {
            if let Ok(chunk) = rx.try_recv() {
                pulled.push(chunk.unwrap());
            }
        }
        assert!(!pulled.is_empty());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            stalled.connection.in_flight(),
            pinned,
            "the stalled streams stop at the connection's share"
        );
        assert_eq!(
            budget.in_flight(),
            pinned,
            "one connection pins no more than its share of the server-wide budget"
        );
        assert_eq!(
            budget.rejected(),
            0,
            "waiting on the share is not a refusal"
        );
        let mut fresh = hj_core::budget::BodyBufferLease::new(budget.clone());
        assert!(fresh.reserve(64 * 1024), "unrelated bodies still fit");
        drop(fresh);

        let (other_task, other_rx) =
            start_file_stream(&path, LEN as u64, &one_connection(&budget)).await;
        let drained = tokio::time::timeout(std::time::Duration::from_secs(20), drain_len(other_rx))
            .await
            .expect("another connection must not wait behind the stalled one");
        assert_eq!(drained, LEN);
        other_task.await.unwrap();
        assert_eq!(
            budget.in_flight(),
            pinned,
            "the stalled connection is untouched"
        );

        drop(pulled);
        for (task, rx) in streams {
            drop(rx);
            task.await.unwrap();
        }
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(stalled.connection.in_flight(), 0);
        assert_eq!(budget.rejected(), 0);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn draining_streams_never_reach_the_connection_share() {
        const STREAMS: usize = 8;
        const LEN: usize = 10 * MIB;
        let path = temp_file("conn-drain", LEN);
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(
            hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
        ));
        let conn = one_connection(&budget);
        let mut streams = Vec::new();
        for _ in 0..STREAMS {
            streams.push(start_file_stream(&path, LEN as u64, &conn).await);
        }
        let peak = Arc::new(AtomicU64::new(0));
        let mut drains = tokio::task::JoinSet::new();
        for (task, mut rx) in streams {
            let conn = conn.clone();
            let peak = peak.clone();
            drains.spawn(async move {
                let mut total = 0;
                // Like the h2 sender, hold one chunk (the one being written) at a time.
                let mut pending: Option<Bytes> = None;
                loop {
                    drop(pending.take());
                    let Some(chunk) = rx.recv().await else {
                        break;
                    };
                    let chunk = chunk.expect("file stream must not abort");
                    peak.fetch_max(conn.connection.in_flight(), Ordering::SeqCst);
                    total += chunk.len();
                    pending = Some(chunk);
                }
                task.await.unwrap();
                total
            });
        }
        let totals = tokio::time::timeout(std::time::Duration::from_secs(30), drains.join_all())
            .await
            .expect("draining streams complete");
        assert_eq!(totals, vec![LEN; STREAMS]);
        let peak = peak.load(Ordering::SeqCst);
        assert!(
            peak <= (STREAMS * (FILE_READ_AHEAD + 1) * MIB) as u64
                && peak < CONNECTION_RESPONSE_MEM,
            "draining 1 MiB-chunk streams peaked at {peak} bytes of the connection share"
        );
        assert_eq!(conn.connection.in_flight(), 0);
        assert_eq!(budget.in_flight(), 0);
        let _ = std::fs::remove_file(path);
    }

    fn frames_stream(frames: Vec<Bytes>) -> hj_core::StreamBody {
        VecStream {
            frames: frames.into(),
            err_at_end: false,
        }
        .boxed()
    }

    #[tokio::test]
    async fn pump_body_yields_during_ready_empty_frames_and_reaches_eof() {
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(MIB as u64));
        let conn = one_connection(&global);
        let (tx, mut rx) = mpsc::channel(8);
        let mut frames = vec![Bytes::new(); READY_FRAME_YIELD_INTERVAL + 1];
        frames.push(Bytes::from_static(b"payload"));
        let mut pump = Box::pin(pump_body(frames_stream(frames), tx, &conn));

        assert!(
            matches!(poll_once(pump.as_mut()), Poll::Pending),
            "a long ready empty run must yield before its payload"
        );
        pump.await;
        assert_eq!(rx.recv().await.unwrap().unwrap(), "payload");
        assert!(rx.recv().await.is_none());

        let (tx, mut rx) = mpsc::channel(8);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            pump_body(frames_stream(vec![Bytes::new(); 10_000]), tx, &conn),
        )
        .await
        .expect("a finite empty run reaches EOF");
        assert!(rx.recv().await.is_none());
        assert_eq!(conn.connection.in_flight(), 0);
        assert_eq!(global.in_flight(), 0);
    }

    fn connection_of(global: &Arc<hj_core::budget::BodyBufferBudget>, cap: u64) -> ResponseBudget {
        ResponseBudget {
            global: global.clone(),
            connection: Arc::new(hj_core::budget::BodyBufferBudget::new(cap)),
        }
    }

    #[tokio::test]
    async fn a_full_connection_share_leaves_the_next_frame_with_the_upstream() {
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(MIB as u64));
        let conn = connection_of(&global, FRAME_CLAIM);
        let (a_tx, mut a_rx) = mpsc::channel(8);
        send_leased_chunk(&a_tx, &conn, Bytes::from(vec![1; FRAME_CLAIM as usize]))
            .await
            .unwrap();
        let alive = Arc::new(AtomicUsize::new(1));
        let (b_tx, mut b_rx) = mpsc::channel(8);
        let pump = tokio::spawn({
            let conn = conn.clone();
            let body = tracked_stream(&alive);
            async move { pump_body(body, b_tx, &conn).await }
        });
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            alive.load(Ordering::SeqCst),
            1,
            "a stream on a full connection must not pull its next upstream frame"
        );
        drop(a_rx.recv().await.unwrap().unwrap());
        assert_eq!(&b_rx.recv().await.unwrap().unwrap()[..], b"overflow");
        assert!(b_rx.recv().await.is_none());
        pump.await.unwrap();
        assert_eq!(conn.connection.in_flight(), 0);
        assert_eq!(global.in_flight(), 0);
        assert_eq!(global.rejected(), 0);
    }

    #[tokio::test]
    async fn frames_larger_than_the_claim_are_charged_in_full_and_never_refused() {
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(4 * MIB as u64));
        let cap = 256 * 1024;
        let conn = connection_of(&global, cap);
        let (tx, mut rx) = mpsc::channel(8);
        let body = frames_stream(vec![
            Bytes::from(vec![1; 200 * 1024]),
            Bytes::from(vec![2; 200 * 1024]),
            Bytes::from(vec![3; 300 * 1024]),
        ]);
        let pump = tokio::spawn({
            let conn = conn.clone();
            async move { pump_body(body, tx, &conn).await }
        });
        let first = rx.recv().await.unwrap().unwrap();
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(first.len(), 200 * 1024);
        assert_eq!(
            conn.connection.in_flight(),
            200 * 1024,
            "the second frame waits for its claim instead of being pulled"
        );
        drop(first);
        let second = rx.recv().await.unwrap().unwrap();
        assert_eq!(second.len(), 200 * 1024);
        drop(second);
        let third = rx.recv().await.unwrap().unwrap();
        assert_eq!(third.len(), 300 * 1024);
        assert_eq!(
            conn.connection.in_flight(),
            cap,
            "a frame beyond the whole share holds all of it"
        );
        assert_eq!(global.in_flight(), 300 * 1024);
        drop(third);
        assert!(rx.recv().await.is_none());
        pump.await.unwrap();
        assert_eq!(conn.connection.in_flight(), 0);
        assert_eq!(global.in_flight(), 0);
        assert_eq!(global.rejected(), 0);
    }

    #[tokio::test]
    async fn a_pulled_frame_waits_for_its_share_holding_no_claim() {
        let global = Arc::new(hj_core::budget::BodyBufferBudget::new(MIB as u64));
        let conn = connection_of(&global, 128 * 1024);
        let (a_tx, mut a_rx) = mpsc::channel(8);
        send_leased_chunk(&a_tx, &conn, Bytes::from(vec![1; 60 * 1024]))
            .await
            .unwrap();
        let (b_tx, mut b_rx) = mpsc::channel(8);
        let pump = tokio::spawn({
            let conn = conn.clone();
            let body = frames_stream(vec![Bytes::from(vec![2; 100 * 1024])]);
            async move { pump_body(body, b_tx, &conn).await }
        });
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(
            b_rx.try_recv().is_err(),
            "the frame does not fit beside A's chunk"
        );
        assert_eq!(
            conn.connection.in_flight(),
            60 * 1024,
            "the waiting frame gave its claim back"
        );
        assert_eq!(
            global.in_flight(),
            160 * 1024,
            "the pulled frame stays charged server-wide"
        );
        drop(a_rx.recv().await.unwrap().unwrap());
        let b = b_rx.recv().await.unwrap().unwrap();
        assert_eq!(b.len(), 100 * 1024);
        assert_eq!(conn.connection.in_flight(), 100 * 1024);
        drop(b);
        assert!(b_rx.recv().await.is_none());
        pump.await.unwrap();
        assert_eq!(conn.connection.in_flight(), 0);
        assert_eq!(global.in_flight(), 0);
        assert_eq!(global.rejected(), 0);
    }

    #[tokio::test]
    async fn bridged_streams_charge_their_own_connections_share() {
        let bridge = spawn_on_current(4, |_req: Request, _ctx: BridgeCtx| async move {
            let body = frames_stream(vec![Bytes::from(vec![7; 1024])]);
            http::Response::builder()
                .header(http::header::CONTENT_TYPE, "text/event-stream")
                .body(Body::Stream(body))
                .unwrap()
        });
        let ctx = test_ctx();
        let other = test_ctx();
        assert!(Arc::ptr_eq(
            &ctx.response_budget,
            &ctx.clone().response_budget
        ));
        assert!(!Arc::ptr_eq(&ctx.response_budget, &other.response_budget));
        assert_eq!(ctx.response_budget.capacity(), CONNECTION_RESPONSE_MEM);
        let resp = bridge.dispatch(test_request(1), ctx.clone()).await.unwrap();
        let BridgeBody::Stream { mut rx, len: None } = resp.body else {
            panic!("an event stream is forwarded incrementally");
        };
        let chunk = rx.recv().await.unwrap().unwrap();
        assert!(rx.recv().await.is_none());
        assert_eq!(ctx.response_budget.in_flight(), 1024);
        assert_eq!(other.response_budget.in_flight(), 0);
        drop(chunk);
        assert_eq!(ctx.response_budget.in_flight(), 0);
    }

    async fn run_forward(r: Response) -> BridgeResp {
        let (tx, rx) = oneshot::channel();
        forward_response(r, tx, false).await;
        rx.await.unwrap()
    }

    async fn run_forward_direct(r: Response) -> BridgeResp {
        let (tx, rx) = oneshot::channel();
        forward_response(r, tx, true).await;
        rx.await.unwrap()
    }

    #[tokio::test]
    async fn direct_plain_h1_forwarding_preserves_pinned_file_and_range() {
        let path = std::env::temp_dir().join(format!(
            "httpjet-bridge-direct-file-{}.bin",
            std::process::id()
        ));
        std::fs::write(&path, b"0123456789").unwrap();
        let response = http::Response::new(Body::File(hj_core::FileBody {
            path: path.clone(),
            file: Some(std::fs::File::open(&path).unwrap()),
            len: 10,
            range: Some((2, 7)),
            cached: None,
        }));
        match run_forward_direct(response).await.body {
            BridgeBody::File(file) => {
                assert!(file.file.is_some(), "the selected inode must stay pinned");
                assert_eq!(file.range, Some((2, 7)));
            }
            _ => panic!("eligible plaintext H1 file must remain a file"),
        }
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn forwarding_preserves_completion_for_buffered_streamed_and_error_responses() {
        for (mut response, status) in [
            (
                http::Response::new(Body::Full(Bytes::from_static(b"full"))),
                200,
            ),
            (
                stream_resp(vec![Bytes::from_static(b"small")], false, None),
                200,
            ),
            (
                stream_resp(
                    vec![Bytes::from_static(b"event")],
                    false,
                    Some("text/event-stream"),
                ),
                200,
            ),
            (stream_resp(vec![], true, None), 502),
            (
                http::Response::new(Body::File(hj_core::FileBody {
                    path: "/nonexistent-httpjet-test/path".into(),
                    file: None,
                    len: 4,
                    range: None,
                    cached: None,
                })),
                502,
            ),
        ] {
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let copy = events.clone();
            response
                .extensions_mut()
                .insert(hj_core::ResponseCompletion::new(move |end| {
                    copy.lock().unwrap().push(end)
                }));
            let mut forwarded = run_forward(response).await;
            assert_eq!(forwarded.status.as_u16(), status);
            assert!(
                events.lock().unwrap().is_empty(),
                "bridge production is not transport completion"
            );
            forwarded
                .completion
                .take()
                .unwrap()
                .finish(hj_core::ResponseEnd::Complete);
            drop(forwarded);
            assert_eq!(
                *events.lock().unwrap(),
                vec![hj_core::ResponseEnd::Complete]
            );
        }
    }

    async fn drain(mut rx: mpsc::Receiver<Result<Bytes, ()>>) -> Result<Vec<u8>, ()> {
        let mut out = Vec::new();
        while let Some(item) = rx.recv().await {
            out.extend_from_slice(&item?);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn per_conn_bandwidth_extension_is_carried_into_bridge_resp() {
        let full = |bytes: bytes::Bytes| {
            http::Response::builder()
                .status(200)
                .body(Body::Full(bytes))
                .unwrap()
        };
        let mut r = full(Bytes::from_static(b"hello"));
        r.extensions_mut()
            .insert(crate::pipeline::PerConnBandwidth(1234));
        let out = run_forward(r).await;
        assert_eq!(out.bw_rate, Some(1234));

        let plain = full(Bytes::from_static(b"plain"));
        assert_eq!(run_forward(plain).await.bw_rate, None);
    }

    #[tokio::test]
    async fn small_stream_buffers_to_full_byte_identical() {
        let r = stream_resp(
            vec![Bytes::from_static(b"hello "), Bytes::from_static(b"world")],
            false,
            None,
        );
        match run_forward(r).await.body {
            BridgeBody::Full(b) => assert_eq!(&b[..], b"hello world"),
            BridgeBody::Stream { .. } => panic!("sub-threshold stream must buffer to Full"),
            BridgeBody::File(_) => panic!("stream must not become File"),
        }
    }

    #[tokio::test]
    async fn forward_stream_yields_during_ready_empty_frames_and_reaches_eof() {
        let mut frames = vec![Bytes::new(); READY_FRAME_YIELD_INTERVAL + 1];
        frames.push(Bytes::from_static(b"payload"));
        let mut forward = Box::pin(run_forward(stream_resp(frames, false, None)));
        assert!(
            matches!(poll_once(forward.as_mut()), Poll::Pending),
            "a long ready empty run must yield before buffering its payload"
        );
        match forward.await.body {
            BridgeBody::Full(body) => assert_eq!(body, "payload"),
            _ => panic!("a sub-threshold payload stays buffered"),
        }

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_forward(stream_resp(vec![Bytes::new(); 10_000], false, None)),
        )
        .await
        .expect("a finite empty run reaches EOF");
        match response.body {
            BridgeBody::Full(body) => assert!(body.is_empty()),
            _ => panic!("an empty finite stream stays buffered"),
        }
    }

    #[tokio::test]
    async fn large_stream_switches_to_chunked_stream_with_prefix() {
        // First chunk already exceeds the threshold → switch; the accumulated prefix must
        // be delivered first, then the remainder, losslessly and in order.
        let big = Bytes::from(vec![b'a'; STREAM_THRESHOLD + 1]);
        let tail = Bytes::from_static(b"TAIL");
        let r = stream_resp(vec![big.clone(), tail.clone()], false, None);
        let resp = run_forward(r).await;
        match resp.body {
            BridgeBody::Stream { rx, len } => {
                assert_eq!(
                    len, None,
                    "a switched Body::Stream is chunked (no Content-Length)"
                );
                let got = drain(rx).await.expect("clean stream");
                assert_eq!(got.len(), big.len() + tail.len());
                assert_eq!(&got[..big.len()], &big[..]);
                assert_eq!(&got[big.len()..], &tail[..]);
            }
            BridgeBody::Full(_) => panic!("over-threshold stream must switch to Stream"),
            BridgeBody::File(_) => panic!("stream must not become File"),
        }
        // Framing headers are stripped on the streamed path.
        assert!(resp.headers.get(http::header::CONTENT_LENGTH).is_none());
    }

    /// A progressive body (a page-cache miss stored while it streams) sends its head with
    /// the first byte, while the backend is still writing.
    #[tokio::test]
    async fn progressive_stream_sends_its_head_with_the_first_byte() {
        struct ChanBody(mpsc::Receiver<Bytes>);
        impl http_body::Body for ChanBody {
            type Data = Bytes;
            type Error = hj_core::BoxError;
            fn poll_frame(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
                self.0
                    .poll_recv(cx)
                    .map(|b| b.map(|b| Ok(http_body::Frame::data(b))))
            }
        }
        let (feed, body_rx) = mpsc::channel(4);
        let mut r = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/html")
            .body(Body::Stream(ChanBody(body_rx).boxed()))
            .unwrap();
        r.extensions_mut().insert(hj_compress::ProgressiveBody);
        let (tx, rx) = oneshot::channel();
        let pump = tokio::spawn(forward_response(r, tx, false));
        feed.send(Bytes::from_static(b"<head>")).await.unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .expect("head is sent before the backend finishes")
            .unwrap();
        let BridgeBody::Stream { mut rx, len } = resp.body else {
            panic!("a progressive body streams");
        };
        assert_eq!(len, None);
        assert_eq!(rx.recv().await.unwrap().unwrap(), "<head>");
        feed.send(Bytes::from_static(b"<body>")).await.unwrap();
        drop(feed);
        assert_eq!(drain(rx).await.unwrap(), b"<body>");
        pump.await.unwrap();
    }

    #[tokio::test]
    async fn sse_streams_immediately() {
        let r = stream_resp(
            vec![Bytes::from_static(b"data: 1\n\n")],
            false,
            Some("text/event-stream"),
        );
        match run_forward(r).await.body {
            BridgeBody::Stream { rx, len } => {
                assert_eq!(len, None);
                assert_eq!(drain(rx).await.unwrap(), b"data: 1\n\n");
            }
            BridgeBody::Full(_) => panic!("SSE must stream immediately, not buffer"),
            BridgeBody::File(_) => panic!("SSE must not become File"),
        }
    }

    /// A backend body fed by the test, that records being dropped.
    struct FeedBody {
        rx: mpsc::Receiver<Bytes>,
        _dropped: Option<oneshot::Sender<()>>,
    }
    impl http_body::Body for FeedBody {
        type Data = Bytes;
        type Error = hj_core::BoxError;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            self.rx
                .poll_recv(cx)
                .map(|b| b.map(|b| Ok(http_body::Frame::data(b))))
        }
    }

    fn feed_resp(
        proxied: bool,
        headers: &[(&str, &str)],
    ) -> (Response, mpsc::Sender<Bytes>, oneshot::Receiver<()>) {
        let (feed, rx) = mpsc::channel(4);
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let mut b = http::Response::builder().status(200);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut r = b
            .body(Body::Stream(
                FeedBody {
                    rx,
                    _dropped: Some(dropped_tx),
                }
                .boxed(),
            ))
            .unwrap();
        if proxied {
            r.extensions_mut().insert(hj_core::ProxiedBody);
        }
        (r, feed, dropped_rx)
    }

    /// #866: a proxied body of unknown length (TTS audio, ndjson) reaches the client
    /// frame by frame instead of being buffered to the threshold or EOF.
    #[tokio::test]
    async fn proxied_unknown_length_stream_is_forwarded_as_it_arrives() {
        let (r, feed, _dropped) = feed_resp(true, &[("content-type", "audio/ogg")]);
        let (tx, rx) = oneshot::channel();
        let pump = tokio::spawn(forward_response(r, tx, false));
        feed.send(Bytes::from_static(b"OggS-1")).await.unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .expect("head is sent while the upstream is still producing")
            .unwrap();
        let BridgeBody::Stream { mut rx, len } = resp.body else {
            panic!("a proxied unknown-length body streams");
        };
        assert_eq!(len, None);
        assert_eq!(rx.recv().await.unwrap().unwrap(), "OggS-1");
        feed.send(Bytes::from_static(b"OggS-2")).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().unwrap(), "OggS-2");
        drop(feed);
        assert!(rx.recv().await.is_none());
        pump.await.unwrap();
    }

    /// #866: `X-Accel-Buffering: no` streams a proxied body even with a Content-Length.
    #[tokio::test]
    async fn proxied_accel_buffering_off_streams_despite_content_length() {
        let (r, feed, _dropped) = feed_resp(
            true,
            &[("content-length", "8"), ("x-accel-buffering", "no")],
        );
        let (tx, rx) = oneshot::channel();
        let pump = tokio::spawn(forward_response(r, tx, false));
        feed.send(Bytes::from_static(b"part")).await.unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .expect("X-Accel-Buffering: no is honoured")
            .unwrap();
        assert!(matches!(resp.body, BridgeBody::Stream { .. }));
        drop(feed);
        pump.await.unwrap();
    }

    /// #866: a small proxied response WITH a Content-Length keeps the buffered,
    /// byte-identical `Full` path.
    #[tokio::test]
    async fn proxied_small_response_with_content_length_stays_full() {
        let mut r = stream_resp(vec![Bytes::from_static(b"hello")], false, None);
        r.headers_mut()
            .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(5));
        r.extensions_mut().insert(hj_core::ProxiedBody);
        let out = run_forward(r).await;
        assert_eq!(out.headers[http::header::CONTENT_LENGTH], "5");
        match out.body {
            BridgeBody::Full(b) => assert_eq!(&b[..], b"hello"),
            _ => panic!("a small proxied response with Content-Length must buffer"),
        }
    }

    /// #866: an unmarked (LSAPI-style) stream of unknown length still buffers: its
    /// head is not sent while the backend is still producing.
    #[tokio::test]
    async fn unmarked_lsapi_style_stream_still_buffers() {
        let (r, feed, _dropped) = feed_resp(false, &[("content-type", "text/html")]);
        let (tx, mut rx) = oneshot::channel();
        let pump = tokio::spawn(forward_response(r, tx, false));
        feed.send(Bytes::from_static(b"<html>")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            rx.try_recv().is_err(),
            "an LSAPI-style body must keep buffering until EOF or the threshold"
        );
        feed.send(Bytes::from_static(b"</html>")).await.unwrap();
        drop(feed);
        match rx.await.unwrap().body {
            BridgeBody::Full(b) => assert_eq!(&b[..], b"<html></html>"),
            _ => panic!("an LSAPI-style sub-threshold body buffers to Full"),
        }
        pump.await.unwrap();
    }

    /// #866: while buffering, a receiver that goes away (client disconnect / stream
    /// reset) drops the backend body at once, releasing whatever it holds.
    #[tokio::test]
    async fn buffering_stream_is_dropped_when_the_receiver_goes_away() {
        let (r, feed, dropped) = feed_resp(true, &[("content-length", "100000")]);
        let (tx, rx) = oneshot::channel();
        let pump = tokio::spawn(forward_response(r, tx, false));
        feed.send(Bytes::from_static(b"partial")).await.unwrap();
        drop(rx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), dropped)
            .await
            .expect("the backend body is dropped promptly");
        tokio::time::timeout(std::time::Duration::from_secs(5), pump)
            .await
            .expect("the forwarder returns")
            .unwrap();
        drop(feed);
    }

    /// #871: a 101 final response is never framed on H2/H3.
    #[test]
    fn switching_protocols_final_becomes_bad_gateway_off_h1() {
        let resp = |status| BridgeResp {
            completion: None,
            status,
            headers: http::HeaderMap::new(),
            body: BridgeBody::Full(Bytes::new()),
            bw_rate: None,
        };
        assert_eq!(
            no_upgrade_final(resp(http::StatusCode::SWITCHING_PROTOCOLS)).status,
            http::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            no_upgrade_final(resp(http::StatusCode::OK)).status,
            http::StatusCode::OK
        );
    }

    #[tokio::test]
    async fn error_before_threshold_is_a_clean_502() {
        let r = stream_resp(vec![Bytes::from_static(b"partial")], true, None);
        let resp = run_forward(r).await;
        assert_eq!(resp.status, http::StatusCode::BAD_GATEWAY);
        match resp.body {
            BridgeBody::Full(b) => assert_eq!(&b[..], b"upstream body truncated\n"),
            BridgeBody::Stream { .. } => panic!("pre-header error must be a buffered 502"),
            BridgeBody::File(_) => panic!("stream error must not become File"),
        }
    }

    #[tokio::test]
    async fn error_after_switch_aborts_the_stream() {
        let big = Bytes::from(vec![b'x'; STREAM_THRESHOLD + 1]);
        let r = stream_resp(vec![big], true, None);
        match run_forward(r).await.body {
            BridgeBody::Stream { rx, .. } => {
                assert!(
                    drain(rx).await.is_err(),
                    "a mid-stream error must surface as an abort"
                );
            }
            BridgeBody::Full(_) => panic!("over-threshold stream must switch to Stream"),
            BridgeBody::File(_) => panic!("stream must not become File"),
        }
    }

    #[tokio::test]
    async fn file_shorter_than_content_length_aborts() {
        // #48: forward_file streams a disk file under the Content-Length computed from an EARLIER
        // stat. If the file is shorter than that advertised length (truncated/replaced since the
        // stat), it MUST abort the stream rather than emit a clean short body under the wrong
        // Content-Length — a short body would desync H1 framing / enable request smuggling. This
        // locks in the short-read guard (the dangerous case of the ranged-disk-stream race).
        let path = std::env::temp_dir().join(format!("hj-bridge-trunc-{}.bin", std::process::id()));
        std::fs::write(&path, vec![b'a'; 4096]).unwrap(); // real file: 4096 bytes
        let f = hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: 1 << 20, // advertised Content-Length: 1 MiB, far larger than the file
            range: None,
            cached: None,
        };
        let resp = http::Response::builder()
            .status(200)
            .body(Body::File(f))
            .unwrap();
        match run_forward(resp).await.body {
            BridgeBody::Stream { rx, len } => {
                assert_eq!(
                    len,
                    Some(1 << 20),
                    "the advertised Content-Length is committed in the head"
                );
                assert!(
                    drain(rx).await.is_err(),
                    "#48: a file shorter than the advertised Content-Length must abort, not finish short"
                );
            }
            BridgeBody::Full(_) => panic!("an uncached Body::File must stream via forward_file"),
            BridgeBody::File(_) => panic!("non-direct forwarding must stream files"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// (#777) A non-direct file stream keeps its known length through the
    /// rebuilt response the H2/H3 framers see.
    #[tokio::test]
    async fn bridged_file_stream_restates_content_length() {
        use http_body::Body as _;
        use http_body_util::BodyExt;
        let path = std::env::temp_dir().join(format!("hj-bridge-len-{}.bin", std::process::id()));
        std::fs::write(&path, vec![b'c'; 5000]).unwrap();
        let resp = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_LENGTH, "5000")
            .body(Body::File(hj_core::FileBody {
                path: path.clone(),
                file: None,
                len: 5000,
                range: None,
                cached: None,
            }))
            .unwrap();
        let rebuilt = bridge_resp_to_response(run_forward(resp).await);
        assert_eq!(rebuilt.headers()[http::header::CONTENT_LENGTH], "5000");
        let Body::Stream(body) = rebuilt.into_body() else {
            panic!("a large uncached file streams");
        };
        assert_eq!(body.size_hint().exact(), Some(5000));
        assert_eq!(body.collect().await.unwrap().to_bytes().len(), 5000);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn file_matching_content_length_streams_cleanly() {
        // Control for the guard above: a file whose real size matches the advertised len streams
        // cleanly to completion (no spurious abort).
        let path = std::env::temp_dir().join(format!("hj-bridge-exact-{}.bin", std::process::id()));
        let data = vec![b'b'; 5000];
        std::fs::write(&path, &data).unwrap();
        let f = hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: data.len() as u64,
            range: None,
            cached: None,
        };
        let resp = http::Response::builder()
            .status(200)
            .body(Body::File(f))
            .unwrap();
        match run_forward(resp).await.body {
            BridgeBody::Stream { rx, len } => {
                assert_eq!(len, Some(data.len() as u64));
                assert_eq!(drain(rx).await.expect("clean stream"), data);
            }
            BridgeBody::Full(_) => panic!("an uncached Body::File must stream via forward_file"),
            BridgeBody::File(_) => panic!("non-direct forwarding must stream files"),
        }
        let _ = std::fs::remove_file(&path);
    }
}
