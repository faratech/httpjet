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

/// Per-request connection context the pipeline needs (peer/local addr, protocol,
/// TLS + mTLS state, SNI, SSL_* params). Carried across the runtime boundary
/// alongside the request. Built once per connection (TLS metadata is per-handshake)
/// and cloned per request.
#[derive(Clone)]
pub(crate) struct BridgeCtx {
    pub peer: std::net::SocketAddr,
    pub local: std::net::SocketAddr,
    pub proto: Proto,
    pub is_tls: bool,
    /// clientVerify=2 in effect for this listener (app-layer mTLS enforced at accept;
    /// passed through so the pipeline applies the same real-IP / trust semantics as
    /// the tokio path).
    pub mtls_required: bool,
    /// TLS SNI server_name (vhost routing key on the secure listener).
    pub sni: Option<std::sync::Arc<str>>,
    /// SSL_* CGI params (protocol/cipher/client-cert) for the LSAPI env, mirroring
    /// the tokio TLS path's `extract_tls_meta`.
    pub tls: Option<hj_core::TlsParams>,
}

impl BridgeCtx {
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
            mtls_required: false,
            sni: None,
            tls: None,
        }
    }
}

/// The body half of a [`BridgeResp`]: either fully buffered (the common small / cache-HIT
/// case — byte-identical to the pre-streaming path) or a chunk channel the monoio side
/// drains incrementally (large files, large renders, SSE).
pub(crate) enum BridgeBody {
    Full(Bytes),
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
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: BridgeBody,
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
            Some(r) => bridge_resp_to_response(r),
            None => hj_core::text_response(http::StatusCode::BAD_GATEWAY, "bridge unavailable\n"),
        }
    }
}

/// Reassemble a [`BridgeResp`] into an `hj_core::Response`. A `Full` body becomes
/// `Body::Full`; a `Stream` becomes a channel-backed `Body::Stream` the native h2/h3
/// framers stream frame-by-frame (their `pulls` machinery). Status + every header are
/// preserved verbatim; the H2/H3 framers recompute their own framing from this.
pub(crate) fn bridge_resp_to_response(r: BridgeResp) -> Response {
    let body = match r.body {
        BridgeBody::Full(b) => Body::Full(b),
        BridgeBody::Stream { rx, .. } => Body::Stream(ChannelBody { rx }.boxed()),
    };
    let mut resp = http::Response::new(body);
    *resp.status_mut() = r.status;
    *resp.headers_mut() = r.headers;
    resp
}

/// A response body the monoio side reconstructs from the bridge's chunk channel for the
/// H2/H3 framers (which re-frame a `Response` themselves). The tokio forwarder polls the
/// REAL upstream body and sends frames here; `mpsc::Receiver::poll_recv` is
/// runtime-agnostic, so this is safe to poll on the monoio executor. An `Err(())` item
/// surfaces as a body error, which the h2/h3 stack turns into a stream reset.
struct ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, ()>>,
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
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(http_body::Frame::data(b)))),
            Poll::Ready(Some(Err(()))) => {
                Poll::Ready(Some(Err("bridged upstream body error".into())))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
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
                }) = request else {
                    break;
                };
                if resp.is_closed() {
                    continue;
                }
                let handler = handler.clone();
                tasks.spawn(async move {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {}
                        _ = async move {
                            let response = handler(req, ctx).await;
                            forward_response(response, resp).await;
                        } => {}
                    }
                    drop(permit);
                });
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
        status: http::StatusCode::BAD_GATEWAY,
        headers: http::HeaderMap::new(),
        body: BridgeBody::Full(Bytes::from_static(b"upstream body truncated\n")),
    }
}

/// (security #263/M-2) Shed with 503 when admission can't be obtained in time —
/// server capacity, not a client error.
pub(crate) fn service_unavailable_resp() -> BridgeResp {
    BridgeResp {
        status: http::StatusCode::SERVICE_UNAVAILABLE,
        headers: http::HeaderMap::new(),
        body: BridgeBody::Full(Bytes::from_static(b"server busy\n")),
    }
}

fn full_resp(parts: http::response::Parts, body: Bytes) -> BridgeResp {
    // The Full arms own `parts` outright — move the header map instead of cloning it per
    // bridged response.
    BridgeResp {
        status: parts.status,
        headers: parts.headers,
        body: BridgeBody::Full(body),
    }
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
async fn forward_response(r: Response, resp: oneshot::Sender<BridgeResp>) {
    let (parts, body) = r.into_parts();
    match body {
        Body::Empty => {
            let _ = resp.send(full_resp(parts, Bytes::new()));
        }
        Body::Full(b) => {
            let _ = resp.send(full_resp(parts, b));
        }
        Body::File(f) if f.cached.is_some() => {
            // `cached` holds the WHOLE file; apply the range (single-sourced, bounds-clamped) so a
            // 206 served here matches the native-H2 path — previously this emitted the whole file
            // under a partial Content-Range.
            let _ = resp.send(full_resp(parts, f.cached_ranged().unwrap_or_default()));
        }
        Body::File(f) => forward_file(parts, f, resp).await,
        Body::Stream(s) => forward_stream(parts, s, resp).await,
    }
}

/// Stream an uncached `Body::File` from disk (the fast path already buffered small/cached
/// files, so one reaching the bridge is large or ranged). `Content-Length` is known, so H1
/// emits it and writes raw (resumable downloads); a mid-read error aborts.
async fn forward_file(
    parts: http::response::Parts,
    mut f: hj_core::FileBody,
    resp: oneshot::Sender<BridgeResp>,
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
                let _ = resp.send(bad_gateway());
                return;
            }
        },
    };
    if (pinned || start > 0) && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        let _ = resp.send(bad_gateway());
        return;
    }
    let headers = strip_framing(parts.headers);
    let (tx, rrx) = mpsc::channel(STREAM_CHANNEL_DEPTH);
    let _ = resp.send(BridgeResp {
        status: parts.status,
        headers,
        body: BridgeBody::Stream {
            rx: rrx,
            len: Some(len),
        },
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
    while remaining > 0 {
        let want = remaining.min(chunk_size as u64) as usize;
        let mut buf = bytes::BytesMut::with_capacity(want);
        match file.read_buf(&mut buf).await {
            Ok(0) => {
                // Short file (truncated since stat): we already committed Content-Length, so
                // signal an abort rather than finish a short body under the wrong CL.
                let _ = tx.send(Err(())).await;
                return;
            }
            Ok(n) => {
                if tx.send(Ok(buf.freeze())).await.is_err() {
                    return; // client gone
                }
                remaining -= n as u64;
            }
            Err(_) => {
                let _ = tx.send(Err(())).await;
                return;
            }
        }
    }
}

/// Forward a `Body::Stream`. SSE streams immediately; everything else buffers up to
/// `STREAM_THRESHOLD` (so small dynamic responses stay `Full` + byte-identical) and only
/// switches to incremental delivery past it. An error BEFORE the switch is a clean 502;
/// after it, the stream is aborted.
async fn forward_stream(
    parts: http::response::Parts,
    mut s: hj_core::StreamBody,
    resp: oneshot::Sender<BridgeResp>,
) {
    use http_body_util::BodyExt;
    if is_event_stream(&parts.headers) {
        let headers = strip_framing(parts.headers);
        let (tx, rrx) = mpsc::channel(STREAM_CHANNEL_DEPTH);
        let _ = resp.send(BridgeResp {
            status: parts.status,
            headers,
            body: BridgeBody::Stream { rx: rrx, len: None },
        });
        pump_body(s, tx).await;
        return;
    }
    let mut acc: Vec<u8> = Vec::new();
    loop {
        match s.frame().await {
            Some(Ok(frame)) => {
                if let Some(d) = frame.data_ref() {
                    acc.extend_from_slice(d);
                    if acc.len() > STREAM_THRESHOLD {
                        let headers = strip_framing(parts.headers);
                        let (tx, rrx) = mpsc::channel(STREAM_CHANNEL_DEPTH);
                        let _ = resp.send(BridgeResp {
                            status: parts.status,
                            headers,
                            body: BridgeBody::Stream { rx: rrx, len: None },
                        });
                        if tx.send(Ok(Bytes::from(acc))).await.is_err() {
                            return;
                        }
                        pump_body(s, tx).await;
                        return;
                    }
                }
            }
            Some(Err(_)) => {
                let _ = resp.send(bad_gateway());
                return;
            }
            None => {
                let _ = resp.send(BridgeResp {
                    status: parts.status,
                    headers: parts.headers,
                    body: BridgeBody::Full(Bytes::from(acc)),
                });
                return;
            }
        }
    }
}

/// Pump the remaining frames of a stream body into the chunk channel until EOF, an error
/// (→ `Err(())` abort), or the drainer drops the receiver (client gone).
async fn pump_body(mut s: hj_core::StreamBody, tx: mpsc::Sender<Result<Bytes, ()>>) {
    use http_body_util::BodyExt;
    loop {
        match s.frame().await {
            Some(Ok(frame)) => {
                if let Ok(d) = frame.into_data() {
                    if !d.is_empty() && tx.send(Ok(d)).await.is_err() {
                        return;
                    }
                }
            }
            Some(Err(_)) => {
                let _ = tx.send(Err(())).await;
                return;
            }
            None => return,
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
    let (bridge, rx) = bridge_channel(BridgeAdmission::fixed(max_in_flight), rt.handle().clone());
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

pub(crate) fn spawn_on_current_with_admission<F, Fut>(
    admission: BridgeAdmission,
    handler: F,
) -> Bridge
where
    F: Fn(Request, BridgeCtx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let (bridge, rx) = bridge_channel(admission, tokio::runtime::Handle::current());
    tokio::spawn(run_receiver(rx, Arc::new(handler)));
    bridge
}

fn bridge_channel(
    admission: BridgeAdmission,
    timer: tokio::runtime::Handle,
) -> (Bridge, mpsc::Receiver<BridgeReq>) {
    let (tx, rx) = mpsc::channel(MAX_IN_FLIGHT_REQUESTS);
    (
        Bridge {
            tx,
            admission: admission.gate,
            timer,
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
/// ONE bounded blocking op per `FILE_CHUNK`, with an await between: on the inline
/// no-runtime fallback each op runs on the event-loop thread itself, so the per-op
/// bound — not the file size — is what caps the stall (and lets the loop interleave
/// with the other connections multiplexed on that core).
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
    let mut out: Vec<u8> = Vec::with_capacity(len.min(FILE_CHUNK as u64) as usize);
    while (out.len() as u64) < len {
        let want = (len - out.len() as u64).min(FILE_CHUNK as u64) as usize;
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
                mtls_required: false,
                sni: None,
                tls: None,
            };
            let resp = bridge.dispatch(req, ctx).await.expect("bridged response");
            assert_eq!(resp.status, http::StatusCode::OK);
            match resp.body {
                BridgeBody::Full(b) => assert_eq!(&b[..], b"bridged /hello"),
                BridgeBody::Stream { .. } => panic!("small response must stay Full"),
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

    async fn run_forward(r: Response) -> BridgeResp {
        let (tx, rx) = oneshot::channel();
        forward_response(r, tx).await;
        rx.await.unwrap()
    }

    async fn drain(mut rx: mpsc::Receiver<Result<Bytes, ()>>) -> Result<Vec<u8>, ()> {
        let mut out = Vec::new();
        while let Some(item) = rx.recv().await {
            out.extend_from_slice(&item?);
        }
        Ok(out)
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
        }
        // Framing headers are stripped on the streamed path.
        assert!(resp.headers.get(http::header::CONTENT_LENGTH).is_none());
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
        }
    }

    #[tokio::test]
    async fn error_before_threshold_is_a_clean_502() {
        let r = stream_resp(vec![Bytes::from_static(b"partial")], true, None);
        let resp = run_forward(r).await;
        assert_eq!(resp.status, http::StatusCode::BAD_GATEWAY);
        match resp.body {
            BridgeBody::Full(b) => assert_eq!(&b[..], b"upstream body truncated\n"),
            BridgeBody::Stream { .. } => panic!("pre-header error must be a buffered 502"),
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
        }
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
        }
        let _ = std::fs::remove_file(&path);
    }
}
