//! HTTP/2 server connection driver.
//!
//! [`serve`] runs a full connection: the SETTINGS handshake, then a dispatch loop that
//! assembles request HEADERS (+CONTINUATION) and DATA into an [`hj_core::Request`] via
//! the HPACK decoder, invokes the service, and writes the response back as a HEADERS
//! frame (HPACK-encoded) plus DATA frames, alongside control-frame handling (SETTINGS,
//! PING, WINDOW_UPDATE, GOAWAY, RST_STREAM).
//!
//! All of a connection's streams are multiplexed **concurrently on this one task**: handler
//! futures run in a `FuturesUnordered`, response bodies are written incrementally under HTTP/2
//! send flow control, and streaming bodies (LSAPI / proxy / SSE) are pulled chunk-by-chunk via a
//! second `FuturesUnordered`. Responses are batched into one vectored write per wake. Request
//! bodies are buffered before dispatch (request-side flow control is permissive); send-side flow
//! control is enforced.
//!
//! Handlers normally run **inline** on this task (no per-stream spawn — the cheap common case).
//! The exception is when there are fewer live h2 connections than worker threads ([`spare_cores`]):
//! then a connection's handlers are `tokio::spawn`ed so they work-steal across the otherwise-idle
//! cores, because one connection multiplexing many streams would otherwise be pinned to a single
//! core. See the dispatch site in [`recv`] for the full rationale.
//!
//! The connection loop and shared output machinery (`OutQueue`/`flush`) live here; the
//! inbound frame processing is in [`recv`], the response writing in [`send`], and the
//! per-connection/per-stream state structs in [`state`].

mod recv;
mod send;
mod state;

pub use send::{is_early_hint_link, set_io_handle};

use std::collections::VecDeque;
use std::future::Future;
// FxHashMap/FxHashSet (rustc-hash): the per-connection stream maps are keyed by u32 stream IDs,
// where SipHash's DoS resistance is pure overhead. Internal/trusted keys only.
use rustc_hash::{FxHashMap, FxHashSet};

use crate::hpack::{Decoder, Encoder};
use bytes::Bytes;
use futures_util::future::{AbortHandle, Abortable};
use hj_core::body_deadline::BodyProgress;
use hj_core::{Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::frame::{self, FrameHeader, error_code, settings};
use recv::{FrameOutcome, process_frame};
use send::{
    Pulls, apply_pull, begin_response, cancel_outstream, pump_streams, reset_drain_idle_streams,
    reset_stalled_streams,
};
use state::{OutStream, PeerSettings, Recv, StreamState};

use std::sync::atomic::{AtomicUsize, Ordering};

/// Number of HTTP/2 connections currently being served in this process (one h2 server per
/// process). Maintained by [`ConnGuard`] around each [`serve`] call; read by [`spare_cores`].
static ACTIVE_H2_CONNS: AtomicUsize = AtomicUsize::new(0);

/// Connections this server closed on its idle timer vs. ones the peer closed first. Behind a
/// pooling proxy the split shows who is the closer: if the idle timer dominates, the proxy
/// would have reused the connection and every close costs it a fresh handshake.
static IDLE_CLOSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PEER_CLOSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Responses reset because they moved too little while waiting on the peer's flow-control
/// credit for [`Config::send_stall_timeout`] (#599).
pub(super) static SEND_STALL_RESETS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Responses reset by the send-stall deadline (both serve loops).
pub fn send_stall_resets() -> u64 {
    SEND_STALL_RESETS.load(Ordering::Relaxed)
}

/// Connections sent GOAWAY(ENHANCE_YOUR_CALM) for exhausting the rapid-reset budget.
pub(super) static RAPID_RESET_GOAWAYS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Connections closed for exhausting the rapid-reset budget (both serve loops).
pub fn rapid_reset_goaways() -> u64 {
    RAPID_RESET_GOAWAYS.load(Ordering::Relaxed)
}

/// `(closed by our idle timer, closed by the peer)` for the io_uring (monoio) loop.
pub fn connection_close_counts() -> (u64, u64) {
    (
        IDLE_CLOSES.load(Ordering::Relaxed),
        PEER_CLOSES.load(Ordering::Relaxed),
    )
}

/// Responses that entered a flow-control-blocked state with bytes pending, split by the
/// window that ran out: the connection window vs. the stream's own window.
pub(super) static SEND_BLOCKED_CONN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub(super) static SEND_BLOCKED_STREAM: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// `(blocked on the connection window, blocked on the stream window)` transitions.
pub fn send_blocked_counts() -> (u64, u64) {
    (
        SEND_BLOCKED_CONN.load(Ordering::Relaxed),
        SEND_BLOCKED_STREAM.load(Ordering::Relaxed),
    )
}

/// Inclusive upper bounds of the peer-SETTINGS buckets; a value above the last bound lands
/// in one trailing overflow bucket. INITIAL_WINDOW_SIZE ≤ 2^31-1 and MAX_FRAME_SIZE ≤ 2^24-1
/// by RFC 9113 §6.5.2, so only HEADER_TABLE_SIZE can reach its overflow bucket.
const PEER_IWS_BOUNDS: [u64; 18] = [
    1 << 14,
    1 << 15,
    1 << 16,
    1 << 17,
    1 << 18,
    1 << 19,
    1 << 20,
    1 << 21,
    1 << 22,
    1 << 23,
    1 << 24,
    1 << 25,
    1 << 26,
    1 << 27,
    1 << 28,
    1 << 29,
    1 << 30,
    1 << 31,
];
const PEER_HTS_BOUNDS: [u64; 10] = [0, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];
const PEER_MFS_BOUNDS: [u64; 11] = [
    1 << 14,
    1 << 15,
    1 << 16,
    1 << 17,
    1 << 18,
    1 << 19,
    1 << 20,
    1 << 21,
    1 << 22,
    1 << 23,
    1 << 24,
];
static PEER_IWS: [std::sync::atomic::AtomicU64; PEER_IWS_BOUNDS.len() + 1] =
    [const { std::sync::atomic::AtomicU64::new(0) }; PEER_IWS_BOUNDS.len() + 1];
static PEER_HTS: [std::sync::atomic::AtomicU64; PEER_HTS_BOUNDS.len() + 1] =
    [const { std::sync::atomic::AtomicU64::new(0) }; PEER_HTS_BOUNDS.len() + 1];
static PEER_MFS: [std::sync::atomic::AtomicU64; PEER_MFS_BOUNDS.len() + 1] =
    [const { std::sync::atomic::AtomicU64::new(0) }; PEER_MFS_BOUNDS.len() + 1];

fn peer_settings_bucket(bounds: &[u64], value: u64) -> usize {
    bounds
        .iter()
        .position(|&b| value <= b)
        .unwrap_or(bounds.len())
}

/// Count one connection's effective values after its FIRST peer SETTINGS frame (parameters
/// the frame omits keep their RFC defaults).
pub(super) fn record_peer_settings(initial_window: u64, header_table: u64, max_frame: u64) {
    for (counts, bounds, value) in [
        (&PEER_IWS[..], &PEER_IWS_BOUNDS[..], initial_window),
        (&PEER_HTS[..], &PEER_HTS_BOUNDS[..], header_table),
        (&PEER_MFS[..], &PEER_MFS_BOUNDS[..], max_frame),
    ] {
        if let Some(count) = counts.get(peer_settings_bucket(bounds, value)) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// `(param, bucket, connections)` for every bucket, zeros included: `bucket` is `<=N` for an
/// inclusive upper bound or `>N` for the overflow above the last bound. Non-cumulative.
pub fn peer_settings_counts() -> Vec<(&'static str, String, u64)> {
    let params: [(&'static str, &[u64], &[std::sync::atomic::AtomicU64]); 3] = [
        ("initial_window_size", &PEER_IWS_BOUNDS, &PEER_IWS),
        ("header_table_size", &PEER_HTS_BOUNDS, &PEER_HTS),
        ("max_frame_size", &PEER_MFS_BOUNDS, &PEER_MFS),
    ];
    let mut out = Vec::new();
    for (param, bounds, counts) in params {
        for (i, count) in counts.iter().enumerate() {
            let bucket = match bounds.get(i) {
                Some(b) => format!("<={b}"),
                None => format!(">{}", bounds.last().copied().unwrap_or_default()),
            };
            out.push((param, bucket, count.load(Ordering::Relaxed)));
        }
    }
    out
}

const H2_INBUF_IDLE: usize = 8 * 1024;
/// Upper bound on the closing flush of a connection that is shutting down.
const FINAL_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Default [`Config::goaway_drain_timeout`].
const GOAWAY_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// Default [`Config::shutdown_idle_stream_timeout`].
const SHUTDOWN_IDLE_STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

const H2_READ_CHUNK: usize = 8 * 1024;
const H2_INBUF_SHRINK_TRIGGER: usize = 64 * 1024;

/// The tokio runtime's worker-thread count, cached on first use (it never changes at runtime).
fn worker_count() -> usize {
    use std::sync::OnceLock;
    static W: OnceLock<usize> = OnceLock::new();
    *W.get_or_init(|| {
        tokio::runtime::Handle::try_current()
            .map(|h| h.metrics().num_workers())
            .ok()
            .filter(|&n| n > 0)
            .unwrap_or(1)
    })
}

/// True when there are fewer live h2 connections than worker threads — i.e. connection-level
/// parallelism alone cannot keep every core busy. In that regime the dispatch site spawns a
/// connection's handlers so a single heavily-multiplexed connection fans out across the idle
/// cores instead of being pinned to one. At/above the worker count, inline is optimal and
/// spawning only adds a cross-thread hop, so this returns false (the common many-connection case).
pub(super) fn spare_cores() -> bool {
    ACTIVE_H2_CONNS.load(Ordering::Relaxed) < worker_count()
}

/// RAII counter for [`ACTIVE_H2_CONNS`]: increments on construction, decrements on drop, so the
/// count stays correct across every `serve` exit path (preface timeout, I/O error, clean close).
struct ConnGuard;
impl ConnGuard {
    fn new() -> Self {
        ACTIVE_H2_CONNS.fetch_add(1, Ordering::Relaxed);
        ConnGuard
    }
}
impl Drop for ConnGuard {
    fn drop(&mut self) {
        ACTIVE_H2_CONNS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The head of a request whose body is still to come, as offered to
/// [`Config::early_reject`].
pub struct RequestHead<'a> {
    pub method: &'a http::Method,
    pub uri: &'a http::Uri,
    /// `:authority`, which the dispatched request carries as its `Host` header.
    pub authority: Option<&'a http::HeaderValue>,
    pub headers: &'a http::HeaderMap,
}

/// Decides from its head whether a body-carrying request is refused outright. A
/// `Some((status, headers))` is sent as a complete bodiless response before any DATA is
/// accepted or `100 Continue` is sent; the stream is then reset with NO_ERROR and its
/// remaining DATA discarded.
pub type EarlyRejectFn =
    dyn Fn(&RequestHead<'_>) -> Option<(http::StatusCode, http::HeaderMap)> + Send + Sync;

#[derive(Clone)]
pub struct EarlyReject(pub std::sync::Arc<EarlyRejectFn>);

impl std::fmt::Debug for EarlyReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EarlyReject(..)")
    }
}

/// Server-side HTTP/2 connection parameters we advertise + enforce.
#[derive(Debug, Clone)]
pub struct Config {
    pub header_table_size: u32,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (RFC 7540 §6.5.2): the cap we advertise + enforce on the
    /// *decoded* header list (summed per field as name+value+32). Bounds the "HTTP/2 Bomb"
    /// where a tiny block of indexed entries expands to a huge header map. 128 KiB sits well
    /// above any real CF request yet an order of magnitude below the bomb's ~2 MB.
    pub header_list_size: u32,
    /// Max buffered request body, PER STREAM (LiteSpeed `maxReqBodySize`). The native stack
    /// buffers the whole request body before dispatch, so an over-cap stream is answered
    /// 413 (#1014). The per-connection aggregate is bounded at `4 ×` this value.
    pub max_request_body: usize,
    /// Server-wide buffered-body budget shared with the other transports (#236 residual).
    /// `None` (default) skips global accounting — per-stream/per-connection caps still apply.
    /// Body-pending streams also reserve their decoded request headers from it.
    pub body_budget: Option<std::sync::Arc<hj_core::budget::BodyBufferBudget>>,
    /// Per-connection cap on the decoded request headers held by streams whose body is
    /// still arriving (each field charged at name + value + its map overhead). A new
    /// body-pending stream past it is refused with REFUSED_STREAM. The 4 MiB default
    /// leaves 100 concurrent uploads with ~6 KiB of headers each well under it, while 256
    /// streams at a 16 KiB list cap would otherwise pin ~22 MB per connection.
    pub pending_header_mem: usize,
    /// Connection-idle timeout: if no frame arrives within this window, send a graceful GOAWAY
    /// and drain (defense-in-depth against slowloris-style holds — e.g. a HEADERS block left
    /// open without END_STREAM pinning its decoded map). `None` disables the timer.
    /// Deliberately SEPARATE from [`Config::preface_timeout`]: this one may be raised so a
    /// pooling proxy (Cloudflare holds idle origin conns ~90s) closes first and keeps reusing
    /// the connection, without widening the pre-request slowloris hold window.
    pub conn_idle_timeout: Option<std::time::Duration>,
    /// Deadline for the 24-byte client preface after transport setup. A peer that completes
    /// TCP/TLS then stalls is cut here; keep it short regardless of `conn_idle_timeout`.
    /// `None` falls back to `conn_idle_timeout` (the pre-split behavior).
    pub preface_timeout: Option<std::time::Duration>,
    /// Absolute deadline for completing one frame once any byte of its header
    /// or payload has arrived. Progress on that frame does not reset it.
    pub frame_read_timeout: Option<std::time::Duration>,
    /// Deadline for completing a request body after its initial HEADERS block. Only
    /// that stream's own progress extends it: each `BODY_MIN_PROGRESS` of its DATA
    /// restarts the window, up to [`Config::request_body_ceiling`] (#1035). Traffic on
    /// other streams does not.
    pub request_body_timeout: Option<std::time::Duration>,
    /// Hard bound on receiving one request body from its initial HEADERS block,
    /// however steadily it progresses.
    pub request_body_ceiling: std::time::Duration,
    /// (Tier 2) Per-connection egress cap in bytes/sec. 0 (default) = unlimited. When set,
    /// EVERY DATA/header flush on this connection is paced through one token bucket —
    /// connection-level semantics: all streams share the pipe, so a paced stream
    /// head-of-line-blocks the connection by design. The H1 path refines per context;
    /// h2 multiplexing makes a per-response rate ill-defined.
    pub bandwidth_limit: u64,
    /// Send-progress deadline, per response: a response with bytes waiting on the peer's
    /// flow-control credit that delivers less than `SEND_STALL_MIN_PROGRESS` within this
    /// window is reset (RST_STREAM CANCEL), releasing its pinned body and backend. Each
    /// response is judged on its own progress, so traffic on other streams cannot keep a
    /// starved one alive (#599). `None` disables it.
    pub send_stall_timeout: Option<std::time::Duration>,
    /// Hard bound on a graceful drain after a peer GOAWAY (and, on the tokio `serve`
    /// path, after our own shutdown GOAWAY; the monoio accept loop bounds that one).
    /// Reads continue while streams are pending so window-blocked bodies still get
    /// credit; each piece of work is bounded by its own handler / send-stall deadline.
    /// If this elapses first, every pending stream is RST_STREAM(CANCEL)ed and a
    /// GOAWAY is sent, never a silent truncation (#906).
    pub goaway_drain_timeout: std::time::Duration,
    /// (#1034) After the shutdown signal, a response that waits this long on its backend
    /// with nothing left to send (an SSE or long-poll body) is reset with
    /// RST_STREAM(CANCEL) rather than holding the drain to the transport's bound.
    /// Responses still producing, window-blocked bodies and handlers that have not
    /// answered are unaffected. `None` keeps every response until the drain bound.
    pub shutdown_idle_stream_timeout: Option<std::time::Duration>,
    /// Consulted only for a request whose header block completes without END_STREAM;
    /// `None` (default) never inspects a request before its body.
    pub early_reject: Option<EarlyReject>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            header_table_size: 4096,
            max_concurrent_streams: 256,
            initial_window_size: 1 << 21,
            max_frame_size: 16384,
            header_list_size: 131072,
            max_request_body: 64 * 1024 * 1024,
            body_budget: None,
            pending_header_mem: 4 << 20,
            conn_idle_timeout: Some(std::time::Duration::from_secs(60)),
            preface_timeout: None,
            frame_read_timeout: Some(std::time::Duration::from_secs(15)),
            request_body_timeout: Some(std::time::Duration::from_secs(60)),
            request_body_ceiling: hj_core::body_deadline::BODY_DEADLINE_CEILING,
            bandwidth_limit: 0,
            send_stall_timeout: Some(std::time::Duration::from_secs(60)),
            goaway_drain_timeout: GOAWAY_DRAIN_TIMEOUT,
            shutdown_idle_stream_timeout: Some(SHUTDOWN_IDLE_STREAM_TIMEOUT),
            early_reject: None,
        }
    }
}

/// Start the body deadline of every stream whose initial header block completed with a
/// body to come, and extend each body that received `BODY_MIN_PROGRESS` since its last
/// extension (#1035). Extension state lives beside `StreamState`, not in it, and only
/// for streams with a body: a larger per-stream entry moved the stream map into an
/// allocation class that re-faulted pages under `MIMALLOC_PURGE_DELAY=0` (see
/// `reset_drain_idle_streams`). Entries of streams that left the map are dropped here;
/// stream ids are never reused, so a stale entry is never applied to another stream.
fn advance_body_deadlines(
    streams: &mut FxHashMap<u32, StreamState>,
    progress: &mut FxHashMap<u32, BodyProgress<tokio::time::Instant>>,
    timeout: std::time::Duration,
    ceiling: std::time::Duration,
) {
    let now = tokio::time::Instant::now();
    for (&sid, st) in streams.iter_mut() {
        if st.headers_done && !st.end_stream && st.body_deadline.is_none() {
            st.body_deadline = Some(now + timeout);
            progress.insert(sid, BodyProgress::new(now, ceiling, st.body.len() as u64));
        }
    }
    if progress.is_empty() {
        return;
    }
    progress.retain(|sid, progress| {
        let Some(st) = streams.get_mut(sid) else {
            return false;
        };
        if let Some(deadline) = st.body_deadline.as_mut() {
            progress.extend(deadline, st.body.len() as u64, timeout, || now);
        }
        true
    });
}

/// (#906) The drain bound elapsed with streams still pending: reset each one and send
/// our GOAWAY so the peer sees an explicit end rather than a truncated response.
fn abandon_drain(
    recv: &mut Recv,
    streams: &mut FxHashMap<u32, StreamState>,
    outstreams: &mut FxHashMap<u32, OutStream>,
    inflight_sids: &mut FxHashMap<u32, AbortHandle>,
    cancelled: &mut FxHashSet<u32>,
    pending_window: &mut FxHashMap<u32, i64>,
    out: &mut OutQueue,
) {
    let receiving: Vec<u32> = streams.keys().copied().collect();
    for sid in receiving {
        if recv.expire_receiving(streams, sid) {
            out.frames(|b| frame::write_rst_stream(b, sid, error_code::CANCEL));
        }
    }
    for (sid, abort) in inflight_sids.drain() {
        abort.abort();
        if cancelled.len() < recv.max_concurrent.saturating_mul(2) {
            cancelled.insert(sid);
        }
        out.frames(|b| frame::write_rst_stream(b, sid, error_code::CANCEL));
    }
    let sending: Vec<u32> = outstreams.keys().copied().collect();
    for sid in sending {
        out.frames(|b| frame::write_rst_stream(b, sid, error_code::CANCEL));
        cancel_outstream(outstreams, sid);
    }
    pending_window.clear();
    let last = recv.goaway_last_stream_id();
    out.frames(|b| frame::write_goaway(b, last, error_code::NO_ERROR));
}

/// Boxed request-handler future tagged with its stream id and whether the request was a
/// HEAD (so the response is sent headers-only, never DATA), multiplexed in one task.
/// A request-handler future tagged with its stream id and HEAD flag, kept as ONE concrete
/// type so it goes into [`Inflight`] WITHOUT a per-request `Box::pin`. `FuturesUnordered`
/// pins its members internally; the box only ever existed to type-erase the two spawn/inline
/// arms into a homogeneous trait object — a single concrete future removes that heap alloc
/// from the connection task's per-request hot path.
pub(super) struct Tagged<F> {
    sid: u32,
    is_head: bool,
    inner: Abortable<TaggedInner<F>>,
}

pub(super) enum TaggedInner<F> {
    /// Polled inline on the connection task (the at/above-worker-count case: spawning would
    /// only add a cross-thread hop). The handler future is several KiB; a recycled slot keeps
    /// the per-stream `FuturesUnordered` node small and its memory resident across streams.
    Inline(hj_core::Recycled<F>),
    /// Work-stolen onto an idle worker (`spare_cores()`), so one heavily-multiplexed
    /// connection fans across cores instead of pinning ~1. Wrapped in [`AbortOnDrop`] so
    /// cancelling this stream also aborts the spawned task rather than detaching backend work.
    Spawned(AbortOnDrop<Response>),
}

/// A `JoinHandle` that aborts its task when dropped (instead of tokio's default detach). Wraps
/// only the (`Unpin`) handle, so [`Tagged`] itself needs no `Drop` impl and its structural pin
/// projection of the `Inline` future stays sound.
pub(super) struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(cx)
    }
}

impl<F: Future<Output = Response>> Future for TaggedInner<F> {
    type Output = Response;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.get_mut() {
            TaggedInner::Inline(f) => std::pin::Pin::new(f).poll(cx),
            TaggedInner::Spawned(h) => std::pin::Pin::new(h).poll(cx).map(|r| {
                // A panic in ONE spawned handler must not tear down the whole connection (every
                // other multiplexed stream): on a JoinError, isolate it to this stream with a 500.
                // (tokio's default panic hook already logs the panic itself.)
                let resp = r.unwrap_or_else(|_e| {
                    hj_core::text_response(
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        "internal server error",
                    )
                });
                resp
            }),
        }
    }
}

impl<F: Future<Output = Response>> Tagged<F> {
    fn cancellable(sid: u32, is_head: bool, inner: TaggedInner<F>) -> (Self, AbortHandle) {
        let (abort, registration) = AbortHandle::new_pair();
        (
            Self {
                sid,
                is_head,
                inner: Abortable::new(inner, registration),
            },
            abort,
        )
    }
}

impl<F: Future<Output = Response>> Future for Tagged<F> {
    type Output = (u32, bool, Option<Response>);

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // SAFETY: `Tagged` has no Drop impl and `inner` is structurally pinned in place.
        let this = unsafe { self.get_unchecked_mut() };
        let (sid, is_head) = (this.sid, this.is_head);
        // SAFETY: `inner` is never moved after `Tagged` is pinned.
        unsafe { std::pin::Pin::new_unchecked(&mut this.inner) }
            .poll(cx)
            .map(|result| (sid, is_head, result.ok()))
    }
}

type Inflight<F> = futures_util::stream::FuturesUnordered<Tagged<F>>;

/// Drive an HTTP/2 server connection to completion, multiplexing all of its streams
/// concurrently **on this single task** (no per-stream spawn): inbound frames are
/// parsed from a persistent buffer, each completed request's `service(req)` future is
/// pushed into a connection-local [`Inflight`], and responses are encoded as those
/// futures resolve. The read side uses a cancel-safe `read_buf`, so the multiplexing
/// `select!` never corrupts a partially-read frame.
pub async fn serve<I, S, F>(
    io: I,
    service: S,
    config: Config,
    shutdown: Option<tokio_util::sync::CancellationToken>,
) -> std::io::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send,
    S: Fn(Request) -> F,
    F: Future<Output = Response> + Send + 'static,
{
    use futures_util::stream::StreamExt;

    // Count this connection for the duration of serve() so spare_cores() (the spawn-vs-inline
    // dispatch decision) sees the live connection count. Dropped on every exit path.
    let _conn_guard = ConnGuard::new();

    let (mut reader, mut writer) = tokio::io::split(io);
    // Bound the preface read by its own (short) deadline: a peer that completes the
    // transport (TCP accept / h2c sniff / TLS handshake) then stalls before/inside the
    // 24-byte preface previously pinned this task with no deadline (the per-frame idle
    // timer below only starts once the preface is read). `None` leaves it unbounded.
    // (#1034) No stream exists yet, so the shutdown signal closes at once.
    let preface = async {
        match config.preface_timeout.or(config.conn_idle_timeout) {
            Some(d) => match tokio::time::timeout(d, read_preface(&mut reader)).await {
                Ok(r) => r,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP/2 connection preface not received before idle timeout",
                )),
            },
            None => read_preface(&mut reader).await,
        }
    };
    tokio::select! {
        result = preface => result?,
        _ = shutdown_signal(shutdown.as_ref()) => return Ok(()),
    }

    let mut out = OutQueue::default();
    // Per-connection scratch for the HPACK response header block, reused across every
    // response on this connection (capacity stays warm) — see begin_response.
    let mut block_scratch: Vec<u8> = Vec::new();
    out.frames(|b| {
        frame::write_settings(
            b,
            &[
                (settings::HEADER_TABLE_SIZE, config.header_table_size),
                (
                    settings::MAX_CONCURRENT_STREAMS,
                    config.max_concurrent_streams,
                ),
                (settings::INITIAL_WINDOW_SIZE, config.initial_window_size),
                (settings::MAX_FRAME_SIZE, config.max_frame_size),
                // Advertise the decoded header-list cap so well-behaved peers (CF) self-limit;
                // we also enforce it in the HPACK decoder (anti-"HTTP/2 Bomb", RFC 7540 §6.5.2).
                (settings::MAX_HEADER_LIST_SIZE, config.header_list_size),
            ],
        );
        // Grow the CONNECTION-level receive window to match the per-stream window.
        // SETTINGS_INITIAL_WINDOW_SIZE governs only STREAM windows (§6.9.2); the connection
        // window stays at the §6.9.1 default of 65535 until an explicit stream-0
        // WINDOW_UPDATE. Without this, concurrent CF→origin request-body uploads (XenForo
        // attachments/avatars/imports multiplexed on one h2 conn) share a single 64 KiB
        // connection budget and stall ~1 RTT per 64 KiB even though each stream is allowed
        // `initial_window_size`. The reactive per-DATA top-up below then maintains this level.
        if let Some(delta) = config
            .initial_window_size
            .checked_sub(65535)
            .filter(|&d| d > 0)
        {
            frame::write_window_update(b, 0, delta);
        }
    });
    flush(&mut writer, &mut out).await?;

    let mut dec = Decoder::new(
        config.header_table_size as usize,
        config.header_list_size as usize,
    );
    let mut enc = Encoder::new();
    let mut peer = PeerSettings::default();
    let mut recv = Recv {
        seen_settings: false,
        last_client_stream: 0,
        goaway_last: None,
        open_header_block: None,
        discarding_header_block: false,
        discard_header_block: Vec::new(),
        discard_rst_code: error_code::STREAM_CLOSED,
        reset_ids: Default::default(),
        sent_reset_ids: Default::default(),
        max_concurrent: config.max_concurrent_streams as usize,
        // The connection receive window we advertise = the level grown to above (the §6.9.2
        // default 65535, raised to initial_window_size via the stream-0 WINDOW_UPDATE sent above).
        conn_recv_window: (config.initial_window_size.max(65535)) as i64,
        our_initial_window: config.initial_window_size as i64,
        header_count_hint: 0,
        reset_debt_until: None,
        total_buffered: 0,
        max_request_body: config.max_request_body,
        per_conn_request_body: config.max_request_body.saturating_mul(4),
        pending_header_bytes: 0,
        pending_header_mem: config.pending_header_mem,
        body_budget: config.body_budget.clone(),
        no_progress_frames: 0,
        early_reject: config.early_reject.clone(),
    };
    // The per-stream maps start EMPTY and grow with the first streams. Pre-sizing them to 32
    // streams saved a few early reallocations on busy connections but made every connection
    // hold 64-bucket tables of `StreamState`/`OutStream` — and most Cloudflare connections
    // carry a couple of requests (29% none) while sitting idle for the keep-alive window.
    let mut streams: FxHashMap<u32, StreamState> = FxHashMap::default();
    let mut inflight: Inflight<F> = Inflight::new();
    // Outgoing response bodies still being written, plus their async chunk pulls and the
    // connection-level send window (RFC 7540 §6.9, default 65535 until the peer grows it).
    let mut outstreams: FxHashMap<u32, OutStream> = FxHashMap::default();
    let mut drain_idle: FxHashMap<u32, std::time::Instant> = FxHashMap::default();
    let mut send_schedule = VecDeque::new();
    let mut pulls: Pulls = Pulls::new();
    let mut send_conn: i64 = 65535;
    // Per-stream send-window credit that arrived (WINDOW_UPDATE) before the response was
    // generated — clients optimistically grant window right after HEADERS, well before a
    // slow handler (LSAPI render) produces the body. Held here and folded into the stream's
    // window when `begin_response` creates it; without this a streamed body stalls at the
    // 65535 initial window. Consumed/cleared in `begin_response` and on RST.
    let mut pending_window: FxHashMap<u32, i64> = FxHashMap::default();
    // Streams the peer reset (RST_STREAM) whose cancelled handler still has an aborted
    // completion queued in `inflight`. The marker is consumed with that completion and is a
    // second guard against ever sending a response on the closed stream.
    let mut cancelled: FxHashSet<u32> = FxHashSet::default();
    // Per-stream cancellation handles for handler futures in `inflight`. A reset removes and
    // fires the handle immediately; the two drain sites remove it on normal completion.
    let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();

    let mut inbuf: Vec<u8> = Vec::with_capacity(H2_INBUF_IDLE);
    let mut cursor = 0usize;
    let mut reading = true;
    let mut accepting = true;
    let mut draining = false;
    let mut shutdown_drain = false;
    let cap = config.max_frame_size.min(1 << 24);
    let frame_read_timeout = config.frame_read_timeout;
    let request_body_timeout = config.request_body_timeout;
    let request_body_ceiling = config.request_body_ceiling;
    let mut body_progress: FxHashMap<u32, BodyProgress<tokio::time::Instant>> =
        FxHashMap::default();
    let send_stall_timeout = config.send_stall_timeout;
    let mut partial_frame_deadline: Option<tokio::time::Instant> = None;
    let mut header_block_deadline: Option<tokio::time::Instant> = None;

    // (HTTP/2-Bomb hardening) Connection-idle deadline, reset at the top of every iteration so
    // it measures time spent blocked in `select` with nothing happening. If it elapses, GOAWAY
    // gracefully and drain — releasing what a silent peer pins, notably a HEADERS block opened
    // without END_STREAM whose decoded map would otherwise sit in `streams` forever (there was
    // previously no per-connection h2 read timeout: `Config::default()` discarded it). `None`
    // parks the timer far out and the select arm is gated off, so the timeout is fully opt-in.
    let idle_timeout = config.conn_idle_timeout;
    let idle = tokio::time::sleep(idle_timeout.unwrap_or(std::time::Duration::from_secs(86_400)));
    tokio::pin!(idle);
    let drain = tokio::time::sleep(std::time::Duration::from_secs(86_400));
    tokio::pin!(drain);

    loop {
        if let Some(d) = idle_timeout {
            idle.as_mut().reset(tokio::time::Instant::now() + d);
        }
        // Drain every complete frame already buffered (synchronous — no await, so
        // cancellation can never split a frame). Each completed request is pushed into
        // `inflight`; control responses are queued into `wbuf`.
        let mut completed_frame = false;
        while reading && inbuf.len() - cursor >= FrameHeader::LEN {
            // The loop guard guarantees 9 bytes, so parse always succeeds; fail closed with
            // a GOAWAY rather than panicking the connection task if that ever breaks.
            let Some(hdr) = FrameHeader::parse(&inbuf[cursor..]) else {
                {
                    // Report the streams already processed (RFC 9113 §6.8, #876).
                    let last = recv.goaway_last_stream_id();
                    out.frames(|b| frame::write_goaway(b, last, error_code::PROTOCOL_ERROR));
                }
                reading = false;
                accepting = false;
                draining = false;
                break;
            };
            if hdr.length > cap {
                {
                    // Report the streams already processed (RFC 9113 §6.8, #876).
                    let last = recv.goaway_last_stream_id();
                    out.frames(|b| frame::write_goaway(b, last, error_code::FRAME_SIZE_ERROR));
                }
                reading = false;
                accepting = false;
                draining = false;
                break;
            }
            let total = FrameHeader::LEN + hdr.length as usize;
            if inbuf.len() - cursor < total {
                break; // wait for the rest of this frame
            }
            let payload = cursor + FrameHeader::LEN..cursor + total;
            cursor += total;
            completed_frame = true;
            let block_was_open = recv.open_header_block.is_some();
            let outcome = process_frame(
                hdr,
                &inbuf[payload],
                &mut streams,
                &mut dec,
                &mut enc,
                &mut out,
                &mut peer,
                &mut recv,
                outstreams.len(),
                accepting,
                &service,
                &mut inflight,
                &mut cancelled,
                &mut inflight_sids,
            );
            header_block_deadline = next_header_block_deadline(
                block_was_open,
                recv.open_header_block.is_some(),
                header_block_deadline,
                || frame_read_timeout.map(|d| tokio::time::Instant::now() + d),
            );
            match outcome {
                FrameOutcome::Continue => {}
                FrameOutcome::StopReading => {
                    reading = false;
                    accepting = false;
                    draining = false;
                    break;
                }
                FrameOutcome::PeerGoaway => {
                    if !draining {
                        draining = true;
                        drain
                            .as_mut()
                            .reset(tokio::time::Instant::now() + config.goaway_drain_timeout);
                    }
                    accepting = false;
                }
                FrameOutcome::ResetStream(sid) => {
                    cancel_outstream(&mut outstreams, sid);
                    pending_window.remove(&sid);
                }
                FrameOutcome::WindowUpdate {
                    stream_id: 0,
                    increment,
                } => {
                    // (#241) Only a grant that unblocks genuinely-blocked credit is
                    // forward progress; an unblocked conn window absorbing +1s is not.
                    let was_blocked = send_conn <= 0;
                    send_conn += increment as i64;
                    if send_conn > i32::MAX as i64 {
                        {
                            // Report the streams already processed (RFC 9113 §6.8, #876).
                            let last = recv.goaway_last_stream_id();
                            out.frames(|b| {
                                frame::write_goaway(b, last, error_code::FLOW_CONTROL_ERROR)
                            });
                        }
                        reading = false;
                        accepting = false;
                        draining = false;
                        break;
                    }
                    if was_blocked && send_conn > 0 {
                        recv.no_progress_frames = 0;
                    }
                }
                FrameOutcome::WindowUpdate {
                    stream_id,
                    increment,
                } => {
                    if let Some(st) = outstreams.get_mut(&stream_id) {
                        let was_blocked = st.window <= 0;
                        st.window += increment as i64;
                        if st.window > i32::MAX as i64 {
                            out.frames(|b| {
                                frame::write_rst_stream(
                                    b,
                                    stream_id,
                                    error_code::FLOW_CONTROL_ERROR,
                                )
                            });
                            st.done = true;
                        } else if was_blocked && st.window > 0 {
                            // (#241) Real forward progress: a blocked response body can
                            // now write again. Grants on idle/closed/never-blocked
                            // streams do NOT clear the flood counter.
                            recv.no_progress_frames = 0;
                        }
                    } else {
                        // Credit granted before the response exists — remember it for when
                        // `begin_response` creates the stream (effective window = initial +
                        // credit). §6.9.1: that must not exceed 2^31-1. Bound the map too.
                        // Bound the map against a peer flooding WINDOW_UPDATE for
                        // never-opened stream IDs. Track this grant only when there's room
                        // OR we already track the stream; a brand-new stream past the cap
                        // is dropped (it just uses the initial window when its response
                        // begins, and the peer can re-grant). Streams already tracked keep
                        // accruing credit. (Don't insert-then-remove the same entry.)
                        //
                        // Only a stream still receiving its request or awaiting its handler
                        // can take pre-response credit: a WINDOW_UPDATE racing the END_STREAM
                        // of a finished response (§6.9 allows ignoring it) would otherwise be
                        // parked forever and fill the map on a long-lived connection.
                        let awaiting_response = streams.contains_key(&stream_id)
                            || inflight_sids.contains_key(&stream_id);
                        if awaiting_response
                            && (pending_window.len() < 4096
                                || pending_window.contains_key(&stream_id))
                        {
                            let c = pending_window.entry(stream_id).or_insert(0);
                            *c += increment as i64;
                            if peer.initial_window + *c > i32::MAX as i64 {
                                out.frames(|b| {
                                    frame::write_rst_stream(
                                        b,
                                        stream_id,
                                        error_code::FLOW_CONTROL_ERROR,
                                    )
                                });
                                pending_window.remove(&stream_id);
                                // The server just reset this stream: tear down the receiving
                                // side so later DATA cannot dispatch it (#598), and stop any
                                // backend work. `Abortable` yields no response when it drains.
                                recv.teardown_receiving(&mut streams, stream_id);
                                if let Some(abort) = inflight_sids.remove(&stream_id) {
                                    abort.abort();
                                    if cancelled.len() < recv.max_concurrent.saturating_mul(2) {
                                        cancelled.insert(stream_id);
                                    }
                                    // (#905) A provoked reset of live work draws on the
                                    // rapid-reset budget like a peer RST_STREAM.
                                    if recv.charge_inflight_reset() {
                                        let last = recv.goaway_last_stream_id();
                                        out.frames(|b| {
                                            frame::write_goaway(
                                                b,
                                                last,
                                                error_code::ENHANCE_YOUR_CALM,
                                            )
                                        });
                                        reading = false;
                                        accepting = false;
                                        draining = false;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                FrameOutcome::InitialWindowDelta(delta) => {
                    // §6.9.2: shift every in-flight stream's send window by the change.
                    let mut overflow = false;
                    for st in outstreams.values_mut() {
                        st.window += delta;
                        overflow |= st.window > i32::MAX as i64;
                    }
                    if overflow {
                        {
                            // Report the streams already processed (RFC 9113 §6.8, #876).
                            let last = recv.goaway_last_stream_id();
                            out.frames(|b| {
                                frame::write_goaway(b, last, error_code::FLOW_CONTROL_ERROR)
                            });
                        }
                        reading = false;
                        accepting = false;
                        draining = false;
                        break;
                    }
                }
            }
        }
        if cursor > 0 {
            inbuf.drain(..cursor);
            cursor = 0;
        }
        // A deadline begins with the first bytes of an incomplete frame and is
        // retained across partial reads. Completing a frame permits a fresh
        // deadline only for a distinct trailing frame already in the buffer.
        if inbuf.is_empty() {
            partial_frame_deadline = None;
        } else if completed_frame || partial_frame_deadline.is_none() {
            partial_frame_deadline = frame_read_timeout.map(|d| tokio::time::Instant::now() + d);
        }
        // Checked on every pass, not only by the timer arm, so a peer keeping the
        // biased read arm ready cannot starve it.
        if reading && header_block_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
            let last = recv.goaway_last_stream_id();
            out.frames(|b| frame::write_goaway(b, last, error_code::PROTOCOL_ERROR));
            reading = false;
            accepting = false;
            draining = false;
        }

        // Start body deadlines only after the initial header block is fully
        // decoded. END_STREAM requests are dispatched synchronously above.
        if let Some(d) = request_body_timeout {
            advance_body_deadlines(&mut streams, &mut body_progress, d, request_body_ceiling);
        }
        let now = tokio::time::Instant::now();
        let expired: Vec<u32> = streams
            .iter()
            .filter_map(|(&sid, st)| {
                st.body_deadline
                    .filter(|&deadline| deadline <= now)
                    .map(|_| sid)
            })
            .collect();
        for sid in expired {
            pending_window.remove(&sid);
            if recv.expire_receiving(&mut streams, sid) {
                out.frames(|b| frame::write_rst_stream(b, sid, error_code::CANCEL));
            }
        }
        // Release a read buffer that a large body / frame burst grew, once it has fully
        // drained between frames; idle CF keep-alives should not pin their peak capacity.
        // The floor handles normal request HEADERS in one read and grows on demand for
        // larger frames/uploads.
        if inbuf.is_empty() && inbuf.capacity() > H2_INBUF_SHRINK_TRIGGER {
            inbuf.shrink_to(H2_INBUF_IDLE);
        }

        // Drain every handler ready right now (non-blocking): encode each response head
        // and register its body, so a connection multiplexing many streams flushes them
        // together rather than one syscall per response.
        while let Some((sid, is_head, resp)) =
            futures_util::FutureExt::now_or_never(inflight.next()).flatten()
        {
            // This future has left `inflight`; drop its id so a later RST can't record a stale
            // `cancelled` entry for an already-finished stream.
            inflight_sids.remove(&sid);
            let Some(resp) = resp else {
                cancelled.remove(&sid);
                continue;
            };
            // Drop the response for a stream the peer reset while its handler was running.
            if cancelled.remove(&sid) {
                continue;
            }
            begin_response(
                sid,
                is_head,
                resp,
                &mut enc,
                &mut out,
                &mut outstreams,
                &mut send_schedule,
                &mut pending_window,
                &peer,
                &mut block_scratch,
            );
        }
        // Drain every body chunk ready right now into its stream's send buffer.
        while let Some((sid, body, res)) =
            futures_util::FutureExt::now_or_never(pulls.next()).flatten()
        {
            if !drain_idle.is_empty() {
                drain_idle.remove(&sid);
            }
            apply_pull(sid, body, res, &mut outstreams, &mut out);
        }
        // Write as much body as the send windows allow (and queue further chunk pulls).
        pump_streams(
            &mut outstreams,
            &mut send_schedule,
            &mut out,
            &mut send_conn,
            &mut pulls,
            &peer,
        );
        // Checked on every pass (not only by the timer arm below) so a peer that keeps
        // the biased, first-polled read arm ready cannot starve the deadline.
        let stall_deadline = reset_stalled_streams(&mut outstreams, &mut out, send_stall_timeout);
        let drain_idle_deadline = match config.shutdown_idle_stream_timeout {
            Some(grace) if shutdown_drain => {
                reset_drain_idle_streams(&mut outstreams, &mut drain_idle, &mut out, grace)
            }
            _ => None,
        };

        // Flush queued output (ACKs, WINDOW_UPDATEs, and the batch of DATA) BEFORE the
        // select blocks on a read — otherwise the peer waits for bytes still queued and
        // the connection deadlocks.
        flush(&mut writer, &mut out).await?;

        if should_close(
            reading,
            draining,
            inflight.is_empty(),
            pulls.is_empty(),
            outstreams.is_empty(),
            streams.is_empty(),
        ) {
            break;
        }

        let far_future = tokio::time::Instant::now() + std::time::Duration::from_secs(86_400);
        let read_deadline = earliest(partial_frame_deadline, header_block_deadline);
        let frame_deadline = read_deadline.unwrap_or(far_future);
        let body_deadline = streams
            .values()
            .filter_map(|st| st.body_deadline)
            .min()
            .unwrap_or(far_future);
        let frame_timer = tokio::time::sleep_until(frame_deadline);
        let body_timer = tokio::time::sleep_until(body_deadline);
        let stall_timer = tokio::time::sleep_until(
            stall_deadline.map_or(far_future, tokio::time::Instant::from_std),
        );
        let drain_idle_timer = tokio::time::sleep_until(
            drain_idle_deadline.map_or(far_future, tokio::time::Instant::from_std),
        );
        tokio::pin!(frame_timer);
        tokio::pin!(body_timer);
        tokio::pin!(stall_timer);
        tokio::pin!(drain_idle_timer);

        tokio::select! {
            biased;
            // A handler completed: begin its response (the rest batch at the next loop top),
            // unless the peer reset the stream while the handler was still running.
            Some((sid, is_head, resp)) = inflight.next(), if !inflight.is_empty() => {
                inflight_sids.remove(&sid);
                if let Some(resp) = resp && !cancelled.remove(&sid) {
                    begin_response(sid, is_head, resp, &mut enc, &mut out, &mut outstreams, &mut send_schedule, &mut pending_window, &peer, &mut block_scratch);
                } else {
                    cancelled.remove(&sid);
                }
            }
            // A streaming body produced a chunk (or ended): buffer it for the next pump.
            Some((sid, body, res)) = pulls.next(), if !pulls.is_empty() => {
                if !drain_idle.is_empty() {
                drain_idle.remove(&sid);
            }
            apply_pull(sid, body, res, &mut outstreams, &mut out);
            }
            // (OPS2) Graceful drain: on the shutdown signal, send GOAWAY and stop accepting
            // new streams. Keep reading frames so existing response bodies can receive flow
            // control credit and finish instead of being truncated at the initial window.
            _ = shutdown_signal(shutdown.as_ref()), if !shutdown_drain => {
                shutdown_drain = true;
                if reading && accepting {
                    let last = recv.goaway_last_stream_id();
                    out.frames(|b| frame::write_goaway(b, last, error_code::NO_ERROR));
                    accepting = false;
                    draining = true;
                    drain.as_mut().reset(tokio::time::Instant::now() + config.goaway_drain_timeout);
                }
            }
            // More inbound bytes (read_buf is cancel-safe; a cancelled read loses nothing).
            r = read_more(&mut reader, &mut inbuf), if reading => {
                match r {
                    Ok(0) => {
                        reading = false;
                        accepting = false;
                        draining = false;
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        reading = false;
                        accepting = false;
                        draining = false;
                    }
                    Err(e) => return Err(e),
                }
            }
            _ = &mut frame_timer, if reading && read_deadline.is_some() => {
                let last = recv.goaway_last_stream_id();
                out.frames(|b| frame::write_goaway(b, last, error_code::PROTOCOL_ERROR));
                reading = false;
                accepting = false;
                draining = false;
            }
            // Wake the loop so its centralized expiry pass releases body
            // accounting and resets every stream whose deadline has elapsed.
            _ = &mut body_timer, if reading && streams.values().any(|st| st.body_deadline.is_some()) => {}
            // (HTTP/2-Bomb hardening) The connection went idle — no frame for `conn_idle_timeout`.
            // GOAWAY gracefully and stop reading; the loop then drains any in-flight work and
            // closes, freeing streams a silent peer held open. Lowest-priority (biased) so real
            // work always preempts it; gated on a configured timeout and `if reading` so it fires
            // at most once.
            _ = &mut idle, if reading && idle_timeout.is_some() => {
                let last = recv.goaway_last_stream_id();
                out.frames(|b| frame::write_goaway(b, last, error_code::NO_ERROR));
                reading = false;
                accepting = false;
                draining = false;
            }
            _ = &mut drain, if reading && draining => {
                abandon_drain(&mut recv, &mut streams, &mut outstreams, &mut inflight_sids, &mut cancelled, &mut pending_window, &mut out);
                reading = false;
                accepting = false;
                draining = false;
            }
            // Wake the loop at the earliest send-stall deadline; the pass at the loop
            // top resets the expired responses.
            _ = &mut stall_timer, if stall_deadline.is_some() => {}
            _ = &mut drain_idle_timer, if drain_idle_deadline.is_some() => {}
        }
    }

    match tokio::time::timeout(FINAL_FLUSH_TIMEOUT, flush(&mut writer, &mut out)).await {
        Ok(result) => result?,
        Err(_) => return Ok(()),
    }
    // Graceful TCP close. Half-close the write side so the peer sees a clean FIN, then
    // drain whatever inbound remains before the socket drops. Closing a socket that still
    // has unread bytes in the kernel receive buffer makes the OS emit a RST instead of a
    // FIN — and a peer can legitimately have bytes in flight at close: a PING right after
    // its own GOAWAY (h2spec §6.8), or frames that raced a fast response. Peers read that
    // RST as an abrupt reset (the CF "reused-socket reset" class), not an orderly close.
    // Bounded so a peer that holds its write side open cannot pin the task.
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = writer.shutdown().await;
        let mut sink = [0u8; 2048];
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            while reader.read(&mut sink).await.map(|n| n > 0).unwrap_or(false) {}
        })
        .await;
    }
    Ok(())
}

/// (#1012) An open header block gets `frame_read_timeout` from the frame that opened it to
/// reach END_HEADERS. Unlike the partial-frame deadline, completed CONTINUATION frames do not
/// restart it: each one empties the read buffer and restarts the idle timer, so periodic empty
/// CONTINUATIONs would otherwise pin the stream's block (and the connection) indefinitely.
fn next_header_block_deadline<T>(
    was_open: bool,
    open: bool,
    current: Option<T>,
    arm: impl FnOnce() -> Option<T>,
) -> Option<T> {
    match (was_open, open) {
        (_, false) => None,
        (false, true) => arm(),
        (true, true) => current,
    }
}

/// Resolves once `shutdown` is cancelled; never without a token.
async fn shutdown_signal(shutdown: Option<&tokio_util::sync::CancellationToken>) {
    match shutdown {
        Some(token) => token.cancelled().await,
        None => std::future::pending().await,
    }
}

fn earliest<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Should the connection loop close *now*, after pumping output but before it blocks
/// on the next read? Shared by the tokio `serve` and monoio `serve_local_with_prefix`
/// loops so the two cannot drift apart (a past drift abandoned in-flight responses on
/// the monoio path when a client half-closed mid-request).
///
/// Two close cases: (1) reads have stopped and there is nothing left to *produce* —
/// `inflight` (running handlers) and `pulls` (streaming bodies) are drained; remaining
/// `outstreams` are deliberately ignored because they are window-blocked and can only
/// advance via a peer WINDOW_UPDATE, impossible once reads stop. (2) a graceful drain
/// (post-GOAWAY) has cleared all in-flight work *including* outstreams (reads continue
/// during a drain, so window-blocked streams can still finish).
fn should_close(
    reading: bool,
    draining: bool,
    inflight_empty: bool,
    pulls_empty: bool,
    outstreams_empty: bool,
    receiving_empty: bool,
) -> bool {
    if !reading && inflight_empty && pulls_empty {
        return true;
    }
    // A request still uploading its body has no handler yet (dispatch waits for
    // END_STREAM) but was admitted below our GOAWAY's last-stream-id, so the peer
    // cannot retry it: a drain must let it finish (#695).
    if draining && inflight_empty && pulls_empty && outstreams_empty && receiving_empty {
        return true;
    }
    false
}

async fn read_preface<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 24];
    r.read_exact(&mut buf).await?;
    if &buf != crate::conn::PREFACE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HTTP/2 connection preface",
        ));
    }
    Ok(())
}

/// Read more bytes into `inbuf` (cancel-safe). `Ok(0)` is EOF.
async fn read_more<R: AsyncRead + Unpin>(r: &mut R, inbuf: &mut Vec<u8>) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt;
    if inbuf.capacity() - inbuf.len() < 4096 {
        inbuf.reserve(H2_READ_CHUNK);
    }
    r.read_buf(inbuf).await
}

/// One ordered output segment: either a run of small frame bytes copied into the inline
/// buffer (control frames, HEADERS blocks, DATA frame *headers*), or a large DATA body
/// referenced by `Bytes` and never copied — it is gathered straight into the socket
/// write via `writev`, so the TLS layer encrypts it in place with no prior body memcpy.
enum Seg {
    /// `(offset, len)` into [`OutQueue::inline`].
    Inline(usize, usize),
    /// A response body chunk, held by reference (zero copy).
    Body(Bytes),
}

/// Vectored output queue. Small frames are coalesced into one contiguous `inline` buffer
/// while large bodies are appended by reference; a single vectored flush writes the whole
/// batch. This keeps the multiplexing win (one flush for many streams) while removing the
/// body→buffer copy that dominated large-response CPU — the bytes go page-cache `Bytes` →
/// TLS record directly.
#[derive(Default)]
pub(super) struct OutQueue {
    inline: Vec<u8>,
    segs: Vec<Seg>,
    completions: Vec<hj_core::ResponseCompletion>,
}
#[cfg(test)]
mod completion_tests;

impl OutQueue {
    #[inline]
    fn finish_responses(&mut self, success: bool) {
        if self.completions.is_empty() {
            return;
        }
        for completion in self.completions.drain(..) {
            completion.finish(if success {
                hj_core::ResponseEnd::Complete
            } else {
                hj_core::ResponseEnd::Error
            });
        }
    }
    #[inline]
    fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }
    /// (Tier 2) Total queued wire bytes — the token bucket's acquire size.
    #[inline]
    fn total_bytes(&self) -> usize {
        self.segs
            .iter()
            .map(|s| match s {
                Seg::Inline(_, l) => *l,
                Seg::Body(b) => b.len(),
            })
            .sum()
    }
    /// Append small frame bytes via `f` (control frames / a HEADERS block / a DATA frame
    /// header), recording the written span as one inline segment.
    #[inline]
    pub(super) fn frames(&mut self, f: impl FnOnce(&mut Vec<u8>)) {
        let start = self.inline.len();
        f(&mut self.inline);
        let len = self.inline.len() - start;
        if len > 0 {
            self.segs.push(Seg::Inline(start, len));
        }
    }
    /// Append a DATA body chunk by reference — zero copy.
    #[inline]
    pub(super) fn body(&mut self, b: Bytes) {
        if !b.is_empty() {
            self.segs.push(Seg::Body(b));
        }
    }
    fn clear(&mut self) {
        self.inline.clear();
        self.segs.clear();
    }
}

/// Flush the queue in a single vectored write (`writev`): the TLS/socket layer gathers the
/// inline runs and referenced bodies into records without us concatenating them first, so
/// large bodies skip the body→buffer copy. Handles short writes by advancing the slices.
async fn flush<W: AsyncWrite + Unpin>(w: &mut W, q: &mut OutQueue) -> std::io::Result<()> {
    let result = flush_inner(w, q).await;
    q.finish_responses(result.is_ok());
    result
}

async fn flush_inner<W: AsyncWrite + Unpin>(w: &mut W, q: &mut OutQueue) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    if q.is_empty() {
        return Ok(());
    }
    // Build the vectored-write slice list. The common batch (a HEADERS block + a body, plus
    // maybe a 103 block, ×N multiplexed streams) fits a stack array — avoiding a per-flush heap
    // Vec; only an unusually large batch (> STACK_SLICES segs) falls back to a heap Vec. `heap`
    // stays unallocated (Vec::new) in the stack case.
    const STACK_SLICES: usize = 64;
    let n_segs = q.segs.len();
    let mut stack: [std::io::IoSlice<'_>; STACK_SLICES] =
        std::array::from_fn(|_| std::io::IoSlice::new(&[]));
    let mut heap: Vec<std::io::IoSlice<'_>> = Vec::new();
    let slices: &mut [std::io::IoSlice<'_>] = if n_segs <= STACK_SLICES {
        for (i, seg) in q.segs.iter().enumerate() {
            stack[i] = match seg {
                Seg::Inline(off, len) => std::io::IoSlice::new(&q.inline[*off..*off + *len]),
                Seg::Body(b) => std::io::IoSlice::new(&b[..]),
            };
        }
        &mut stack[..n_segs]
    } else {
        heap.reserve(n_segs);
        for seg in &q.segs {
            heap.push(match seg {
                Seg::Inline(off, len) => std::io::IoSlice::new(&q.inline[*off..*off + *len]),
                Seg::Body(b) => std::io::IoSlice::new(&b[..]),
            });
        }
        &mut heap[..]
    };
    let mut bufs: &mut [std::io::IoSlice<'_>] = slices;
    while !bufs.is_empty() {
        let n = w.write_vectored(bufs).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        std::io::IoSlice::advance_slices(&mut bufs, n);
    }
    w.flush().await?;
    q.clear();
    Ok(())
}

/// Flush an [`OutQueue`] over a monoio stream. The normal path retains the inline frame
/// allocation and every body [`Bytes`] inside an owned iovec buffer until io_uring returns
/// completion, so cancellation cannot leave kernel-visible pointers dangling.
/// (Tier 2) Paced wrapper around [`monoio_flush`]: one token bucket per
/// connection, acquiring for the queued byte count before the write goes out.
#[cfg(feature = "monoio")]
async fn paced_flush<IO: monoio::io::AsyncWriteRent>(
    wh: &mut IO,
    q: &mut OutQueue,
    ktls_fd: Option<i32>,
    pacer: &mut Option<hj_core::budget::BandwidthThrottle>,
) -> std::io::Result<()> {
    if let Some(p) = pacer.as_mut()
        && !q.is_empty()
    {
        let wait = p.acquire(q.total_bytes() as u64);
        if wait > 0 {
            monoio::time::sleep(std::time::Duration::from_micros(wait)).await;
        }
    }
    monoio_flush(wh, q, ktls_fd).await
}

#[cfg(feature = "monoio")]
async fn monoio_flush<IO: monoio::io::AsyncWriteRent>(
    stream: &mut IO,
    q: &mut OutQueue,
    ktls_fd: Option<i32>,
) -> std::io::Result<()> {
    let result = monoio_flush_inner(stream, q, ktls_fd).await;
    q.finish_responses(result.is_ok());
    result
}

#[cfg(feature = "monoio")]
async fn monoio_flush_inner<IO: monoio::io::AsyncWriteRent>(
    stream: &mut IO,
    q: &mut OutQueue,
    ktls_fd: Option<i32>,
) -> std::io::Result<()> {
    use monoio::io::AsyncWriteRentExt;
    if q.is_empty() {
        return Ok(());
    }
    // kTLS zero-copy fast path: on a kTLS socket the app writes PLAINTEXT (kernel encrypts),
    // so we can `writev(2)` DIRECTLY from the OutQueue segments — no coalesce copy (the ~1 MiB
    // memcpy that hurt large-body throughput) and one syscall. This is the win monoio-rustls's
    // writev-stub blocked on the userspace TLS path, but a kTLS fd takes raw iovecs. Falls back
    // to the coalesce path for huge bodies (>IOV_MAX segments) and, on a short write/EAGAIN, for
    // just the unwritten remainder (the O_NONBLOCK fd's io_uring write waits via the ring).
    #[cfg(feature = "monoio")]
    if let Some(fd) = ktls_fd {
        if q.segs.len() <= 1024 {
            let mut iov: Vec<libc::iovec> = Vec::with_capacity(q.segs.len());
            let mut total = 0usize;
            for seg in &q.segs {
                let (ptr, len) = match seg {
                    Seg::Inline(off, l) => (
                        unsafe { q.inline.as_ptr().add(*off) } as *mut libc::c_void,
                        *l,
                    ),
                    Seg::Body(b) => (b.as_ptr() as *mut libc::c_void, b.len()),
                };
                if len > 0 {
                    iov.push(libc::iovec {
                        iov_base: ptr,
                        iov_len: len,
                    });
                    total += len;
                }
            }
            // SAFETY: every iovec points into a segment of `q` (inline Vec or a refcounted
            // `Bytes`) that outlives this synchronous syscall; `iov` has <= 1024 entries.
            let n = unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) };
            let written = if n >= 0 { n as usize } else { 0 };
            if written < total {
                let mut rest = Vec::with_capacity(total - written);
                let mut skip = written;
                for seg in &q.segs {
                    let bytes: &[u8] = match seg {
                        Seg::Inline(o, l) => &q.inline[*o..*o + *l],
                        Seg::Body(b) => &b[..],
                    };
                    if skip >= bytes.len() {
                        skip -= bytes.len();
                        continue;
                    }
                    rest.extend_from_slice(&bytes[skip..]);
                    skip = 0;
                }
                if !rest.is_empty() {
                    let (res, _) = stream.write_all(rest).await;
                    res?;
                }
            }
            q.clear();
            return Ok(());
        }
    }
    // Non-kTLS writev: move the queue's allocations into the submitted IoVecBuf. Monoio
    // retains that value after future cancellation until the kernel completion is reaped;
    // retaining only raw iovecs that borrowed `q` would leave dangling pointers when the
    // connection task is dropped. The inline allocation is recovered after a complete write.
    #[cfg(feature = "monoio")]
    if q.segs.len() <= 1024 {
        use crate::owned_iovec::{IoVecSpan, OwnedIoVec, write_all_owned};

        let inline = Bytes::from(std::mem::take(&mut q.inline));
        let segments = std::mem::take(&mut q.segs);
        let mut backings = Vec::with_capacity(segments.len() + 1);
        let mut spans = Vec::with_capacity(segments.len());
        backings.push(inline);
        for segment in segments {
            match segment {
                Seg::Inline(offset, len) => spans.push(IoVecSpan::new(0, offset, len)),
                Seg::Body(body) => {
                    let backing = backings.len();
                    let len = body.len();
                    backings.push(body);
                    spans.push(IoVecSpan::new(backing, 0, len));
                }
            }
        }
        let buffer = OwnedIoVec::from_backings(backings, spans)?;
        let buffer = write_all_owned(stream, buffer).await?;
        q.inline = buffer
            .into_backings()
            .into_iter()
            .next()
            .map(Vec::from)
            .unwrap_or_default();
        q.inline.clear();
        return Ok(());
    }
    // COALESCE fallback: reached on the non-monoio (tokio) build, or when there are >IOV_MAX
    // (1024) segments so the vectored path above does not apply. Gather all segments (inline
    // frame headers + body chunks) into one buffer and write it in FLUSH_CAP-sized batches to
    // bound memory + pipeline writes for huge bodies. The per-chunk memcpy is cheap (never the
    // bottleneck — see the B3 finding); ~one socket buffer's worth keeps the kernel pipe full
    // without unbounded buffering. (On the io_uring build the vectored `writev` path above —
    // backed by the vendored monoio-rustls fork's real `writev` — is primary; this is the fallback.)
    const FLUSH_CAP: usize = 256 * 1024;
    let cap = q
        .segs
        .iter()
        .map(|s| match s {
            Seg::Inline(_, l) => *l,
            Seg::Body(b) => b.len(),
        })
        .sum::<usize>()
        .min(FLUSH_CAP + 16 * 1024);
    let mut pending: Vec<u8> = Vec::with_capacity(cap.max(q.inline.len() + 64));
    for seg in &q.segs {
        match seg {
            Seg::Inline(off, len) => pending.extend_from_slice(&q.inline[*off..*off + *len]),
            Seg::Body(b) => pending.extend_from_slice(&b[..]),
        }
        if pending.len() >= FLUSH_CAP {
            let (res, _) = stream.write_all(std::mem::take(&mut pending)).await;
            res?;
        }
    }
    if !pending.is_empty() {
        let (res, _) = stream.write_all(pending).await;
        res?;
    }
    q.clear();
    Ok(())
}

/// Pure-io_uring HTTP/2 over a monoio `TcpStream`, used by httpjet's production
/// transport. The `monoio` feature remains optional only at the `hj-h2` library boundary.
/// Reuses all the runtime-agnostic
/// machinery ([`process_frame`], the HPACK codec, [`begin_response`]/[`pump_streams`],
/// [`OutQueue`]) with a SEQUENTIAL monoio loop: process buffered frames → drain
/// ready handlers (`now_or_never`) → flush → blocking io_uring read.
///
/// A [`ConnGuard`] keeps [`spare_cores`] false
/// so `process_frame` never takes the `tokio::spawn` arm on this (tokio-less)
/// monoio thread; the surrounding loop drives handler concurrency and streaming.
#[cfg(feature = "monoio")]
pub async fn serve_local<IO, S, F>(stream: IO, service: S, config: Config) -> std::io::Result<()>
where
    IO: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Splitable + 'static,
    IO::OwnedRead: monoio::io::AsyncReadRent + 'static,
    IO::OwnedWrite: monoio::io::AsyncWriteRent + 'static,
    S: Fn(Request) -> F,
    F: Future<Output = Response> + Send + 'static,
{
    serve_local_with_prefix(stream, Vec::new(), service, config, None, None).await
}

#[cfg(feature = "monoio")]
fn monoio_read_once<R>(
    mut reader: R,
    buffer: Vec<u8>,
) -> impl Future<Output = (std::io::Result<usize>, Vec<u8>, R)>
where
    R: monoio::io::AsyncReadRent,
{
    async move {
        let (result, buffer) = reader.read(buffer).await;
        (result, buffer, reader)
    }
}

/// Like [`serve_local`] but seeds the inbound buffer with `prefix` bytes already
/// read from the socket — used by the uring plaintext listener, which must peek
/// the first bytes to distinguish H1 from the h2c prior-knowledge preface and so
/// consumes them before deciding to route here (monoio streams aren't peekable).
#[cfg(feature = "monoio")]
pub async fn serve_local_with_prefix<IO, S, F>(
    stream: IO,
    prefix: Vec<u8>,
    service: S,
    config: Config,
    shutdown: Option<tokio_util::sync::CancellationToken>,
    ktls_fd: Option<i32>,
) -> std::io::Result<()>
where
    IO: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Splitable + 'static,
    IO::OwnedRead: monoio::io::AsyncReadRent + 'static,
    IO::OwnedWrite: monoio::io::AsyncWriteRent + 'static,
    S: Fn(Request) -> F,
    F: Future<Output = Response> + Send + 'static,
{
    use futures_util::stream::StreamExt;
    use monoio::io::{AsyncReadRent, AsyncWriteRent};

    let _conn_guard = ConnGuard::new();
    // (Tier 2) One bucket per h2 CONNECTION: every flush is paced when a rate is
    // configured. Connection-level semantics — multiplexed streams share the pipe.
    let mut pacer = hj_core::budget::BandwidthThrottle::new(config.bandwidth_limit);

    // Split into owned read/write halves so the step-5 read future can persist
    // ACROSS select! iterations (a handler completing must NOT cancel an in-flight
    // read — some monoio stream wrappers, e.g. monoio-rustls's SafeRead, lose their
    // buffer when a read future is dropped mid-flight). The write half flushes
    // independently. `Splitable` lets wrappers provide structurally separate halves
    // instead of monoio's UnsafeCell-based generic `Split` implementation.
    let (mut rh, mut wh) = stream.into_split();

    // Client connection preface (24 bytes). Seeded with any pre-read prefix, which
    // becomes the inbound buffer itself rather than a copy kept for the connection.
    let mut inbuf = prefix;
    inbuf.reserve(H2_INBUF_IDLE.saturating_sub(inbuf.len()));
    // Bound the preface read so a peer that completes the TCP/TLS handshake then stalls
    // cannot pin this connection task forever (the monoio path otherwise had no deadline,
    // unlike the tokio `serve`). On timeout we close, so cancelling the in-flight read is
    // harmless (the stream is never reused).
    let preface_deadline = config
        .preface_timeout
        .or(config.conn_idle_timeout)
        .map(|duration| monoio::time::Instant::now() + duration);
    if inbuf.len() < crate::conn::PREFACE.len() {
        // Scoped so the read buffer is freed once the preface is in, not held by the
        // connection future for its whole lifetime.
        let mut preface_buffer = vec![0u8; 4096];
        while inbuf.len() < crate::conn::PREFACE.len() {
            // (#1034) No stream exists yet, so the shutdown signal closes at once instead
            // of letting a silent peer hold the drain to its bound.
            let (res, b) = monoio::select! {
                rb = rh.read(preface_buffer) => rb,
                _ = async { match preface_deadline { Some(deadline) => monoio::time::sleep_until(deadline).await, None => std::future::pending::<()>().await } } => {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "h2 preface timeout"));
                }
                _ = shutdown_signal(shutdown.as_ref()) => return Ok(()),
            };
            let n = res?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            inbuf.extend_from_slice(&b[..n]);
            preface_buffer = b;
        }
    }
    if &inbuf[..crate::conn::PREFACE.len()] != crate::conn::PREFACE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad HTTP/2 preface",
        ));
    }
    inbuf.drain(..crate::conn::PREFACE.len());

    let mut out = OutQueue::default();
    let mut block_scratch: Vec<u8> = Vec::new();
    out.frames(|b| {
        frame::write_settings(
            b,
            &[
                (settings::HEADER_TABLE_SIZE, config.header_table_size),
                (
                    settings::MAX_CONCURRENT_STREAMS,
                    config.max_concurrent_streams,
                ),
                (settings::INITIAL_WINDOW_SIZE, config.initial_window_size),
                (settings::MAX_FRAME_SIZE, config.max_frame_size),
                (settings::MAX_HEADER_LIST_SIZE, config.header_list_size),
            ],
        );
        if let Some(delta) = config
            .initial_window_size
            .checked_sub(65535)
            .filter(|&d| d > 0)
        {
            frame::write_window_update(b, 0, delta);
        }
    });
    paced_flush(&mut wh, &mut out, ktls_fd, &mut pacer).await?;

    let mut dec = Decoder::new(
        config.header_table_size as usize,
        config.header_list_size as usize,
    );
    let mut enc = Encoder::new();
    let mut peer = PeerSettings::default();
    let mut recv = Recv {
        seen_settings: false,
        last_client_stream: 0,
        goaway_last: None,
        open_header_block: None,
        discarding_header_block: false,
        discard_header_block: Vec::new(),
        discard_rst_code: error_code::STREAM_CLOSED,
        reset_ids: Default::default(),
        sent_reset_ids: Default::default(),
        max_concurrent: config.max_concurrent_streams as usize,
        conn_recv_window: (config.initial_window_size.max(65535)) as i64,
        our_initial_window: config.initial_window_size as i64,
        header_count_hint: 0,
        reset_debt_until: None,
        total_buffered: 0,
        max_request_body: config.max_request_body,
        per_conn_request_body: config.max_request_body.saturating_mul(4),
        pending_header_bytes: 0,
        pending_header_mem: config.pending_header_mem,
        body_budget: config.body_budget.clone(),
        no_progress_frames: 0,
        early_reject: config.early_reject.clone(),
    };
    // Empty until the first streams arrive (see the tokio loop above).
    let mut streams: FxHashMap<u32, StreamState> = FxHashMap::default();
    let mut inflight: Inflight<F> = Inflight::new();
    let mut outstreams: FxHashMap<u32, OutStream> = FxHashMap::default();
    let mut drain_idle: FxHashMap<u32, std::time::Instant> = FxHashMap::default();
    let mut send_schedule = VecDeque::new();
    let mut pulls: Pulls = Pulls::new();
    let mut send_conn: i64 = 65535;
    let mut pending_window: FxHashMap<u32, i64> = FxHashMap::default();
    let mut cancelled: FxHashSet<u32> = FxHashSet::default();
    let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();
    let mut cursor = 0usize;
    let mut reading = true;
    let mut accepting = true;
    // Graceful-drain state (mirrors the tokio `serve` path): on the shutdown signal we
    // GOAWAY, stop accepting new streams (`accepting=false`), keep reading so in-flight
    // bodies still get flow-control credit, and `draining=true` so the loop exits once
    // in-flight work clears. The overall drain is bounded by the per-core accept loop,
    // which abandons still-running connection tasks after a grace window.
    let mut draining = false;
    // The shutdown signal has been observed (whatever GOAWAY state the connection was in);
    // from here a response idle on its backend is ended (#1034).
    let mut shutdown_drain = false;
    let mut peer_goaway_deadline: Option<std::time::Instant> = None;
    let cap = config.max_frame_size.min(1 << 24);
    // Deadline state mirroring the tokio `serve` loop: a partially-received frame
    // gets `frame_read_timeout` to complete, and a request whose headers arrived
    // but whose END_STREAM body never does gets `request_body_timeout`. Without
    // these the production (monoio) loop only enforced the preface + idle bounds,
    // so a peer trickling one byte per idle window could pin the connection and
    // its buffers indefinitely.
    let frame_read_timeout = config.frame_read_timeout;
    let request_body_timeout = config.request_body_timeout;
    let request_body_ceiling = config.request_body_ceiling;
    let mut body_progress: FxHashMap<u32, BodyProgress<tokio::time::Instant>> =
        FxHashMap::default();
    let send_stall_timeout = config.send_stall_timeout;
    let mut partial_frame_deadline: Option<std::time::Instant> = None;
    let mut header_block_deadline: Option<std::time::Instant> = None;

    // The read future stays pinned across select iterations because cancelling a monoio-rustls
    // read can lose its owned buffer. The box is allocated once; after a completed read,
    // `Pin::set` replaces the future in place with the same concrete future type and hands its
    // returned Vec straight into the next read.
    let mut read_fut = Box::pin(monoio_read_once(rh, vec![0u8; H2_READ_CHUNK]));
    // A completed `read_fut` must never be polled again; only EOF leaves it so.
    let mut read_eof = false;

    loop {
        // 1) Process every complete buffered frame (mirrors serve()).
        let mut completed_frame = false;
        while reading && inbuf.len() - cursor >= FrameHeader::LEN {
            let Some(hdr) = FrameHeader::parse(&inbuf[cursor..]) else {
                {
                    // Report the streams already processed (RFC 9113 §6.8, #876).
                    let last = recv.goaway_last_stream_id();
                    out.frames(|b| frame::write_goaway(b, last, error_code::PROTOCOL_ERROR));
                }
                reading = false;
                accepting = false;
                break;
            };
            if hdr.length > cap {
                {
                    // Report the streams already processed (RFC 9113 §6.8, #876).
                    let last = recv.goaway_last_stream_id();
                    out.frames(|b| frame::write_goaway(b, last, error_code::FRAME_SIZE_ERROR));
                }
                reading = false;
                accepting = false;
                break;
            }
            let total = FrameHeader::LEN + hdr.length as usize;
            if inbuf.len() - cursor < total {
                break;
            }
            let payload = cursor + FrameHeader::LEN..cursor + total;
            cursor += total;
            completed_frame = true;
            let block_was_open = recv.open_header_block.is_some();
            let outcome = process_frame(
                hdr,
                &inbuf[payload],
                &mut streams,
                &mut dec,
                &mut enc,
                &mut out,
                &mut peer,
                &mut recv,
                outstreams.len(),
                accepting,
                &service,
                &mut inflight,
                &mut cancelled,
                &mut inflight_sids,
            );
            header_block_deadline = next_header_block_deadline(
                block_was_open,
                recv.open_header_block.is_some(),
                header_block_deadline,
                || frame_read_timeout.map(|d| std::time::Instant::now() + d),
            );
            match outcome {
                FrameOutcome::Continue => {}
                FrameOutcome::StopReading => {
                    reading = false;
                    accepting = false;
                    break;
                }
                FrameOutcome::PeerGoaway => {
                    if !draining {
                        draining = true;
                        peer_goaway_deadline =
                            Some(std::time::Instant::now() + config.goaway_drain_timeout);
                    }
                    accepting = false;
                }
                FrameOutcome::ResetStream(sid) => {
                    cancel_outstream(&mut outstreams, sid);
                    pending_window.remove(&sid);
                }
                FrameOutcome::WindowUpdate {
                    stream_id: 0,
                    increment,
                } => {
                    // (#241) Only a grant that unblocks genuinely-blocked credit is
                    // forward progress; see the matching arm in the main loop.
                    let was_blocked = send_conn <= 0;
                    send_conn += increment as i64;
                    if send_conn > i32::MAX as i64 {
                        {
                            // Report the streams already processed (RFC 9113 §6.8, #876).
                            let last = recv.goaway_last_stream_id();
                            out.frames(|b| {
                                frame::write_goaway(b, last, error_code::FLOW_CONTROL_ERROR)
                            });
                        }
                        reading = false;
                        accepting = false;
                        break;
                    }
                    if was_blocked && send_conn > 0 {
                        recv.no_progress_frames = 0;
                    }
                }
                FrameOutcome::WindowUpdate {
                    stream_id,
                    increment,
                } => {
                    if let Some(st) = outstreams.get_mut(&stream_id) {
                        let was_blocked = st.window <= 0;
                        st.window += increment as i64;
                        if st.window > i32::MAX as i64 {
                            out.frames(|b| {
                                frame::write_rst_stream(
                                    b,
                                    stream_id,
                                    error_code::FLOW_CONTROL_ERROR,
                                )
                            });
                            st.done = true;
                        } else if was_blocked && st.window > 0 {
                            // (#241) Real forward progress; grants on idle/closed/
                            // never-blocked streams do NOT clear the flood counter.
                            recv.no_progress_frames = 0;
                        }
                    } else if (streams.contains_key(&stream_id)
                        || inflight_sids.contains_key(&stream_id))
                        && (pending_window.len() < 4096 || pending_window.contains_key(&stream_id))
                    {
                        // Pre-response credit only (see the tokio loop): a grant racing a
                        // finished response's END_STREAM is ignored rather than leaked.
                        let c = pending_window.entry(stream_id).or_insert(0);
                        *c += increment as i64;
                        if peer.initial_window + *c > i32::MAX as i64 {
                            out.frames(|b| {
                                frame::write_rst_stream(
                                    b,
                                    stream_id,
                                    error_code::FLOW_CONTROL_ERROR,
                                )
                            });
                            pending_window.remove(&stream_id);
                            recv.teardown_receiving(&mut streams, stream_id);
                            if let Some(abort) = inflight_sids.remove(&stream_id) {
                                abort.abort();
                                if cancelled.len() < recv.max_concurrent.saturating_mul(2) {
                                    cancelled.insert(stream_id);
                                }
                                // (#905) Same rapid-reset charge as the tokio loop.
                                if recv.charge_inflight_reset() {
                                    let last = recv.goaway_last_stream_id();
                                    out.frames(|b| {
                                        frame::write_goaway(b, last, error_code::ENHANCE_YOUR_CALM)
                                    });
                                    reading = false;
                                    accepting = false;
                                    break;
                                }
                            }
                        }
                    }
                }
                FrameOutcome::InitialWindowDelta(delta) => {
                    let mut overflow = false;
                    for st in outstreams.values_mut() {
                        st.window += delta;
                        overflow |= st.window > i32::MAX as i64;
                    }
                    if overflow {
                        {
                            // Report the streams already processed (RFC 9113 §6.8, #876).
                            let last = recv.goaway_last_stream_id();
                            out.frames(|b| {
                                frame::write_goaway(b, last, error_code::FLOW_CONTROL_ERROR)
                            });
                        }
                        reading = false;
                        accepting = false;
                        break;
                    }
                }
            }
        }
        if cursor > 0 {
            inbuf.drain(..cursor);
            cursor = 0;
        }
        if inbuf.is_empty() && inbuf.capacity() > H2_INBUF_SHRINK_TRIGGER {
            inbuf.shrink_to(H2_INBUF_IDLE);
        }

        // Deadline bookkeeping mirroring the tokio `serve` loop. A deadline begins
        // with the first bytes of an incomplete frame and is retained across partial
        // reads; completing a frame permits a fresh deadline only for a distinct
        // trailing frame already in the buffer.
        if inbuf.is_empty() {
            partial_frame_deadline = None;
        } else if completed_frame || partial_frame_deadline.is_none() {
            partial_frame_deadline = frame_read_timeout.map(|d| std::time::Instant::now() + d);
        }
        // Checked on every pass, not only by the timer arm, so a peer keeping the
        // biased read arm ready cannot starve it.
        if reading && header_block_deadline.is_some_and(|d| d <= std::time::Instant::now()) {
            let last = recv.goaway_last_stream_id();
            out.frames(|b| frame::write_goaway(b, last, error_code::PROTOCOL_ERROR));
            reading = false;
            accepting = false;
        }

        // Start body deadlines only after the initial header block is fully decoded
        // (END_STREAM requests dispatch synchronously) and extend those that progressed,
        // then expire any stream whose body stalled: release its body accounting and RST it.
        if let Some(d) = request_body_timeout {
            advance_body_deadlines(&mut streams, &mut body_progress, d, request_body_ceiling);
        }
        let now = std::time::Instant::now();
        let expired: Vec<u32> = streams
            .iter()
            .filter_map(|(&sid, st)| {
                st.body_deadline
                    .filter(|&deadline| deadline.into_std() <= now)
                    .map(|_| sid)
            })
            .collect();
        for sid in expired {
            pending_window.remove(&sid);
            if recv.expire_receiving(&mut streams, sid) {
                out.frames(|b| frame::write_rst_stream(b, sid, error_code::CANCEL));
            }
        }

        // 2) Drain handlers + body pulls ready right now (immediate handlers resolve here).
        while let Some((sid, is_head, resp)) =
            futures_util::FutureExt::now_or_never(inflight.next()).flatten()
        {
            inflight_sids.remove(&sid);
            let Some(resp) = resp else {
                cancelled.remove(&sid);
                continue;
            };
            if cancelled.remove(&sid) {
                continue;
            }
            begin_response(
                sid,
                is_head,
                resp,
                &mut enc,
                &mut out,
                &mut outstreams,
                &mut send_schedule,
                &mut pending_window,
                &peer,
                &mut block_scratch,
            );
        }
        while let Some((sid, body, res)) =
            futures_util::FutureExt::now_or_never(pulls.next()).flatten()
        {
            if !drain_idle.is_empty() {
                drain_idle.remove(&sid);
            }
            apply_pull(sid, body, res, &mut outstreams, &mut out);
        }
        pump_streams(
            &mut outstreams,
            &mut send_schedule,
            &mut out,
            &mut send_conn,
            &mut pulls,
            &peer,
        );
        // Checked on every pass (not only by the timer arm below) so a peer that keeps
        // the biased, first-polled read arm ready cannot starve the deadline.
        let stall_deadline = reset_stalled_streams(&mut outstreams, &mut out, send_stall_timeout);
        let drain_idle_deadline = match config.shutdown_idle_stream_timeout {
            Some(grace) if shutdown_drain => {
                reset_drain_idle_streams(&mut outstreams, &mut drain_idle, &mut out, grace)
            }
            _ => None,
        };

        // 3) Flush queued output.
        paced_flush(&mut wh, &mut out, ktls_fd, &mut pacer).await?;

        // 4) Termination — shared `should_close` with the tokio `serve` loop. Once
        // `reading` stops we must still drain `inflight` (running handlers) and `pulls`
        // (streaming bodies) so a client that half-closes / GOAWAYs while a slow response
        // is in flight still gets its response. The read select arm below is gated
        // `if reading`, so a completed-but-not-recreated `read_fut` is never re-polled
        // after EOF.
        if should_close(
            reading,
            draining,
            inflight.is_empty(),
            pulls.is_empty(),
            outstreams.is_empty(),
            streams.is_empty(),
        ) {
            break;
        }

        // 5) Wait for the next event: a completed read (persistent `read_fut`), a handler
        // or body-pull completing, or the shutdown signal. `biased` polls the read FIRST.
        // Awaiting `&mut read_fut` (a `Pin<Box<_>>`, Unpin) does NOT consume it, so a
        // losing branch leaves the in-flight read intact (recreated only after it
        // resolves) — this is what makes the non-cancel-safe monoio-rustls read safe.
        // On shutdown: GOAWAY + stop accepting new streams, but keep reading so in-flight
        // response bodies still receive flow-control credit and finish (matches `serve`).
        let mut read_done: Option<(std::io::Result<usize>, Vec<u8>, IO::OwnedRead)> = None;
        let frame_wait = earliest(partial_frame_deadline, header_block_deadline)
            .map(|dl| dl.saturating_duration_since(std::time::Instant::now()));
        let body_wait = streams
            .values()
            .filter_map(|st| st.body_deadline)
            .map(|dl| dl.into_std())
            .min()
            .map(|dl| dl.saturating_duration_since(std::time::Instant::now()));
        let stall_wait =
            stall_deadline.map(|dl| dl.saturating_duration_since(std::time::Instant::now()));
        let peer_goaway_wait =
            peer_goaway_deadline.map(|dl| dl.saturating_duration_since(std::time::Instant::now()));
        let drain_idle_wait =
            drain_idle_deadline.map(|dl| dl.saturating_duration_since(std::time::Instant::now()));
        monoio::select! {
            biased;
            rb = read_fut.as_mut(), if reading => { read_done = Some(rb); }
            // (c03e287 parity) A partially-received frame or an unfinished header block
            // (#1012) that outlives `frame_read_timeout` is a slowloris: GOAWAY
            // PROTOCOL_ERROR, stop reading.
            _ = async { match frame_wait { Some(d) => monoio::time::sleep(d).await, None => std::future::pending::<()>().await } }, if reading && frame_wait.is_some() => {
                let last = recv.goaway_last_stream_id();
                out.frames(|b| frame::write_goaway(b, last, error_code::PROTOCOL_ERROR));
                reading = false;
                accepting = false;
            }
            // Wake the loop when the nearest request-body deadline elapses; the
            // centralized expiry pass at the loop top releases the accounting.
            _ = async { match body_wait { Some(d) => monoio::time::sleep(d).await, None => std::future::pending::<()>().await } }, if reading && body_wait.is_some() => {}
            _ = async { match stall_wait { Some(d) => monoio::time::sleep(d).await, None => std::future::pending::<()>().await } }, if stall_wait.is_some() => {}
            _ = async { match drain_idle_wait { Some(d) => monoio::time::sleep(d).await, None => std::future::pending::<()>().await } }, if drain_idle_wait.is_some() => {}
            _ = async { match peer_goaway_wait { Some(d) => monoio::time::sleep(d).await, None => std::future::pending::<()>().await } }, if reading && peer_goaway_wait.is_some() => {
                abandon_drain(&mut recv, &mut streams, &mut outstreams, &mut inflight_sids, &mut cancelled, &mut pending_window, &mut out);
                reading = false;
                accepting = false;
            }
            Some((sid, is_head, resp)) = inflight.next(), if !inflight.is_empty() => {
                inflight_sids.remove(&sid);
                if let Some(resp) = resp && !cancelled.remove(&sid) {
                    begin_response(sid, is_head, resp, &mut enc, &mut out, &mut outstreams, &mut send_schedule, &mut pending_window, &peer, &mut block_scratch);
                } else {
                    cancelled.remove(&sid);
                }
            }
            Some((sid, body, res)) = pulls.next(), if !pulls.is_empty() => {
                if !drain_idle.is_empty() {
                drain_idle.remove(&sid);
            }
            apply_pull(sid, body, res, &mut outstreams, &mut out);
            }
            _ = shutdown_signal(shutdown.as_ref()), if !shutdown_drain => {
                shutdown_drain = true;
                if reading && accepting {
                    let last = recv.goaway_last_stream_id();
                    out.frames(|b| frame::write_goaway(b, last, error_code::NO_ERROR));
                    accepting = false;
                    draining = true;
                }
            }
            // Idle bound: no inbound frame within `conn_idle_timeout`. The sleep is
            // recreated each iteration, so it measures time since the last event. First
            // fire GOAWAY + drain (let in-flight responses finish); a second idle while
            // already draining forces the close — bounds a post-handshake slowloris that
            // the monoio path otherwise never timed out (the tokio `serve` does this).
            _ = async { match config.conn_idle_timeout { Some(d) => monoio::time::sleep(d).await, None => std::future::pending::<()>().await } }, if reading => {
                if accepting {
                    IDLE_CLOSES.fetch_add(1, Ordering::Relaxed);
                    let last = recv.goaway_last_stream_id();
                    out.frames(|b| frame::write_goaway(b, last, error_code::NO_ERROR));
                    accepting = false;
                    draining = true;
                } else {
                    reading = false;
                }
            }
        }
        if let Some((res, b, reader)) = read_done {
            match res {
                Ok(0) => {
                    if accepting {
                        PEER_CLOSES.fetch_add(1, Ordering::Relaxed);
                    }
                    reading = false;
                    accepting = false;
                    read_eof = true;
                }
                Ok(n) => inbuf.extend_from_slice(&b[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    if accepting {
                        PEER_CLOSES.fetch_add(1, Ordering::Relaxed);
                    }
                    reading = false;
                    accepting = false;
                    read_eof = true;
                }
                Err(e) => return Err(e),
            }
            if reading {
                read_fut.as_mut().set(monoio_read_once(reader, b));
            }
        }
    }

    // Bounded: a peer that stopped reading at the TCP level would otherwise pin the task
    // on its full send buffer after the send-stall deadline already gave up on it.
    match monoio::time::timeout(
        FINAL_FLUSH_TIMEOUT,
        paced_flush(&mut wh, &mut out, ktls_fd, &mut pacer),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => return Ok(()),
    }
    let _ = AsyncWriteRent::shutdown(&mut wh).await;
    // Mirrors the tokio `serve` close: unread inbound bytes (WINDOW_UPDATEs for
    // the last response, a PING after the peer's GOAWAY) make the kernel answer
    // the close with a RST that discards our unsent tail. Bounded so a peer
    // holding its write side open cannot pin the task.
    if !read_eof {
        let _ = monoio::time::timeout(std::time::Duration::from_millis(500), async {
            loop {
                let (res, b, reader) = read_fut.as_mut().await;
                if !matches!(res, Ok(n) if n > 0) {
                    break;
                }
                read_fut.as_mut().set(monoio_read_once(reader, b));
            }
        })
        .await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream::StreamExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_preface_timeout_is_absolute_across_partial_reads() {
        use std::io::Write;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            for byte in crate::conn::PREFACE.iter().take(12) {
                if stream.write_all(std::slice::from_ref(byte)).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });

        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        let result = runtime.block_on(async move {
            let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let config = Config {
                conn_idle_timeout: None,
                preface_timeout: Some(Duration::from_millis(80)),
                ..Config::default()
            };
            serve_local_with_prefix(
                stream,
                Vec::new(),
                |_| {
                    std::future::ready(hj_core::text_response(
                        http::StatusCode::OK,
                        "unexpected request",
                    ))
                },
                config,
                None,
                None,
            )
            .await
        });
        client.join().unwrap();
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    /// Regression (c03e287 parity): the production monoio loop must enforce
    /// `frame_read_timeout` on a partially-received frame. The old loop only had
    /// the preface + idle bounds, so a peer trickling one byte at a time kept the
    /// connection (and its buffers) pinned forever. The idle timeout is DISABLED
    /// here so only the frame deadline can close the connection.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_partial_frame_deadline_closes_slow_trickle() {
        use std::io::{Read, Write};
        use std::time::Instant;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();

        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            let mut wire = crate::conn::PREFACE.to_vec();
            frame::write_settings(&mut wire, &[]);
            // A HEADERS frame announcing 20 payload bytes; only the first 5 arrive,
            // then the rest trickle one byte per 30 ms — well past the deadline.
            let mut block = Vec::new();
            let mut encoder = Encoder::new();
            for (name, value) in [
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "https"),
                (":authority", "example.com"),
            ] {
                encoder.encode_header(&mut block, name, value);
            }
            let mut head = [0u8; 9];
            let len = block.len().min(20) as u32;
            head[0] = (len >> 16) as u8;
            head[1] = (len >> 8) as u8;
            head[2] = len as u8;
            head[3] = frame::kind::HEADERS;
            head[4] = frame::flags::END_HEADERS;
            head[5..9].copy_from_slice(&1u32.to_be_bytes());
            wire.extend_from_slice(&head);
            wire.extend_from_slice(&block[..5]);
            stream.write_all(&wire).unwrap();

            let started = Instant::now();
            let mut last_byte = Instant::now();
            let mut eof_at: Option<Duration> = None;
            let mut buf = [0u8; 4096];
            stream
                .set_read_timeout(Some(Duration::from_millis(5)))
                .unwrap();
            let mut sent = 5usize;
            while started.elapsed() < Duration::from_secs(3) {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        eof_at = Some(started.elapsed());
                        break;
                    }
                    Ok(_) => {}
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => break,
                }
                if sent < len as usize && last_byte.elapsed() >= Duration::from_millis(30) {
                    stream.write_all(&block[sent..sent + 1]).unwrap();
                    sent += 1;
                    last_byte = Instant::now();
                }
            }
            (eof_at, block.len())
        });

        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        let result = runtime.block_on(async move {
            let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let config = Config {
                conn_idle_timeout: None,
                frame_read_timeout: Some(Duration::from_millis(150)),
                ..Config::default()
            };
            serve_local_with_prefix(
                stream,
                Vec::new(),
                |_| {
                    std::future::ready(hj_core::text_response(
                        http::StatusCode::OK,
                        "unexpected request",
                    ))
                },
                config,
                None,
                None,
            )
            .await
        });

        let (eof_at, block_len) = client.join().unwrap();
        assert!(result.is_ok(), "the connection should close cleanly");
        let eof = eof_at.expect("server must close while the frame is still trickling");
        assert!(
            eof < Duration::from_millis(2500),
            "the frame deadline must close the connection well before the \
             3 s trickle budget is exhausted (closed after {eof:?}); the frame \
             needed {} more bytes at 30 ms each",
            block_len - 5
        );
    }

    /// Client half of the header-block deadline tests: HEADERS without END_HEADERS, then
    /// `continuation_gap`-spaced empty CONTINUATIONs; `None` instead sends the closing
    /// CONTINUATION in the same write. Returns (time of EOF, GOAWAY code, response seen).
    #[cfg(feature = "monoio")]
    fn header_block_client(
        address: std::net::SocketAddr,
        continuation_gap: Option<Duration>,
    ) -> (Option<Duration>, Option<u32>, bool) {
        use std::io::{Read, Write};
        use std::time::Instant;

        let mut stream = std::net::TcpStream::connect(address).unwrap();
        let mut block = Vec::new();
        let mut encoder = Encoder::new();
        for (name, value) in [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            (":authority", "example.com"),
        ] {
            encoder.encode_header(&mut block, name, value);
        }
        let (first, rest) = block.split_at(block.len() / 2);
        let mut wire = crate::conn::PREFACE.to_vec();
        frame::write_settings(&mut wire, &[]);
        frame::write_frame(
            &mut wire,
            frame::kind::HEADERS,
            frame::flags::END_STREAM,
            1,
            first,
        );
        if continuation_gap.is_none() {
            frame::write_frame(
                &mut wire,
                frame::kind::CONTINUATION,
                frame::flags::END_HEADERS,
                1,
                rest,
            );
        }
        stream.write_all(&wire).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();

        let started = Instant::now();
        let mut last_continuation = Instant::now();
        let (mut seen, mut at) = (Vec::new(), 0usize);
        let (mut eof_at, mut goaway, mut responded) = (None, None, false);
        let mut buf = [0u8; 4096];
        while started.elapsed() < Duration::from_secs(3) {
            match stream.read(&mut buf) {
                Ok(0) => {
                    eof_at = Some(started.elapsed());
                    break;
                }
                Ok(n) => seen.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
            while let Some(header) = seen.get(at..at + 9) {
                let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
                let Some(payload) = seen.get(at + 9..at + 9 + len) else {
                    break;
                };
                let sid = u32::from_be_bytes(header[5..9].try_into().unwrap());
                match header[3] {
                    frame::kind::HEADERS if sid == 1 => responded = true,
                    frame::kind::GOAWAY => {
                        goaway = Some(u32::from_be_bytes(payload[4..8].try_into().unwrap()));
                    }
                    _ => {}
                }
                at += 9 + len;
            }
            if responded && continuation_gap.is_none() {
                break;
            }
            if let Some(gap) = continuation_gap
                && last_continuation.elapsed() >= gap
            {
                let mut empty = Vec::new();
                frame::write_frame(&mut empty, frame::kind::CONTINUATION, 0, 1, &[]);
                if stream.write_all(&empty).is_err() {
                    break;
                }
                last_continuation = Instant::now();
            }
        }
        (eof_at, goaway, responded)
    }

    #[cfg(feature = "monoio")]
    fn header_block_server(std_listener: std::net::TcpListener) -> std::io::Result<()> {
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let config = Config {
                conn_idle_timeout: None,
                frame_read_timeout: Some(Duration::from_millis(150)),
                ..Config::default()
            };
            serve_local_with_prefix(
                stream,
                Vec::new(),
                |_| std::future::ready(hj_core::text_response(http::StatusCode::OK, "ok")),
                config,
                None,
                None,
            )
            .await
        })
    }

    /// Regression (#1012): a header block kept open by periodic empty CONTINUATION frames
    /// gets one absolute `frame_read_timeout` deadline. Every frame is complete (so the
    /// partial-frame deadline never runs) and the idle timeout is disabled, so only the
    /// header-block deadline can close the connection.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_unfinished_header_block_deadline_closes_continuation_trickle() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || header_block_server(std_listener));
        let (eof_at, goaway, responded) =
            header_block_client(address, Some(Duration::from_millis(30)));
        assert!(server.join().unwrap().is_ok());
        assert!(!responded, "the unfinished block must never be dispatched");
        assert_eq!(goaway, Some(error_code::PROTOCOL_ERROR));
        let eof = eof_at.expect("server must close while CONTINUATIONs keep arriving");
        assert!(
            eof < Duration::from_millis(1500),
            "CONTINUATION frames must not extend the header-block deadline (closed after {eof:?})"
        );
    }

    /// Control for #1012: HEADERS + CONTINUATION arriving in one burst is served.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_header_block_completed_in_one_burst_is_served() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || header_block_server(std_listener));
        let (_, goaway, responded) = header_block_client(address, None);
        assert!(responded, "a completed header block must be served");
        assert_eq!(goaway, None);
        assert!(server.join().unwrap().is_ok());
    }

    /// Regression (c03e287 parity): the production monoio loop must enforce
    /// `request_body_timeout` — headers complete but the promised request body
    /// never arrives → RST_STREAM(CANCEL) on that stream. The idle timeout is
    /// DISABLED here so only the body deadline can act.
    #[cfg(feature = "monoio")]
    #[derive(Clone, Copy, PartialEq)]
    enum Credit {
        /// Never grant stream credit.
        Withhold,
        /// Grant plenty of credit once.
        Grant,
        /// One byte of credit on stream 1 every 100 ms.
        Trickle,
        /// Starve streams 1-7 while downloading a fresh, fully granted request every
        /// 100 ms, so the CONNECTION keeps making progress.
        ProgressElsewhere,
    }

    #[cfg(feature = "monoio")]
    #[derive(Default)]
    struct StallReport {
        resets: std::collections::HashMap<u32, u32>,
        data: std::collections::HashMap<u32, usize>,
        goaway: Option<u32>,
        all_starved_reset_at: Option<Duration>,
    }

    /// Client side of the send-stall tests: open with INITIAL_WINDOW_SIZE=0, issue GETs on
    /// streams 1-7, PING every 50 ms (so the idle timer never fires) and apply `credit`.
    #[cfg(feature = "monoio")]
    fn send_stall_client(address: std::net::SocketAddr, credit: Credit) -> StallReport {
        use std::io::{Read, Write};
        use std::time::Instant;

        let starved = [1u32, 3, 5, 7];
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        let mut enc = Encoder::new();
        let mut get = |sid: u32, wire: &mut Vec<u8>| {
            let mut block = Vec::new();
            enc.encode_header(&mut block, ":method", "GET");
            enc.encode_header(&mut block, ":path", "/big");
            enc.encode_header(&mut block, ":scheme", "https");
            enc.encode_header(&mut block, ":authority", "example.com");
            frame::write_frame(
                wire,
                frame::kind::HEADERS,
                frame::flags::END_HEADERS | frame::flags::END_STREAM,
                sid,
                &block,
            );
        };
        let mut wire = crate::conn::PREFACE.to_vec();
        frame::write_settings(&mut wire, &[(settings::INITIAL_WINDOW_SIZE, 0)]);
        for sid in starved {
            get(sid, &mut wire);
        }
        stream.write_all(&wire).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();

        let started = Instant::now();
        let run_for = Duration::from_millis(if credit == Credit::Grant { 900 } else { 2500 });
        let mut report = StallReport::default();
        let (mut seen, mut at) = (Vec::new(), 0usize);
        let (mut last_ping, mut last_tick) = (Instant::now(), Instant::now());
        let mut granted = false;
        let mut next_sid = 9u32;
        let mut buf = [0u8; 16384];
        while started.elapsed() < run_for {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => seen.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
            while let Some(header) = seen.get(at..at + 9) {
                let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
                let Some(payload) = seen.get(at + 9..at + 9 + len) else {
                    break;
                };
                let (kind, sid) = (
                    header[3],
                    u32::from_be_bytes(header[5..9].try_into().unwrap()),
                );
                match kind {
                    frame::kind::DATA => *report.data.entry(sid).or_default() += len,
                    frame::kind::RST_STREAM => {
                        report
                            .resets
                            .insert(sid, u32::from_be_bytes(payload[..4].try_into().unwrap()));
                    }
                    frame::kind::GOAWAY => {
                        report.goaway = Some(u32::from_be_bytes(payload[4..8].try_into().unwrap()));
                    }
                    _ => {}
                }
                at += 9 + len;
            }
            if report.all_starved_reset_at.is_none()
                && starved.iter().all(|sid| report.resets.contains_key(sid))
            {
                report.all_starved_reset_at = Some(started.elapsed());
            }
            let mut send = Vec::new();
            if last_ping.elapsed() >= Duration::from_millis(50) {
                frame::write_frame(&mut send, frame::kind::PING, 0, 0, &[0u8; 8]);
                last_ping = Instant::now();
            }
            let tick = last_tick.elapsed() >= Duration::from_millis(100);
            match credit {
                Credit::Grant if !granted && started.elapsed() > Duration::from_millis(100) => {
                    for sid in [0u32, 1, 3, 5, 7] {
                        frame::write_window_update(&mut send, sid, 1 << 20);
                    }
                    granted = true;
                }
                Credit::Trickle if tick => {
                    frame::write_window_update(&mut send, 0, 1);
                    frame::write_window_update(&mut send, 1, 1);
                    last_tick = Instant::now();
                }
                Credit::ProgressElsewhere if tick => {
                    get(next_sid, &mut send);
                    frame::write_window_update(&mut send, 0, 64 * 1024);
                    frame::write_window_update(&mut send, next_sid, 64 * 1024);
                    next_sid += 2;
                    last_tick = Instant::now();
                }
                _ => {}
            }
            if !send.is_empty() && stream.write_all(&send).is_err() {
                break;
            }
        }
        report
    }

    #[cfg(feature = "monoio")]
    fn send_stall_server(std_listener: std::net::TcpListener) {
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let config = Config {
                conn_idle_timeout: Some(Duration::from_secs(10)),
                send_stall_timeout: Some(Duration::from_millis(300)),
                ..Config::default()
            };
            let _ = serve_local_with_prefix(
                stream,
                Vec::new(),
                |_| {
                    std::future::ready(Response::new(hj_core::Body::Full(Bytes::from(vec![
                        b'x';
                        64 * 1024
                    ]))))
                },
                config,
                None,
                None,
            )
            .await;
        });
    }

    #[cfg(feature = "monoio")]
    fn run_send_stall(credit: Credit) -> StallReport {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || send_stall_server(std_listener));
        send_stall_client(address, credit)
    }

    #[cfg(feature = "monoio")]
    fn assert_starved_streams_reset(report: &StallReport, mode: &str) {
        for sid in [1u32, 3, 5, 7] {
            assert_eq!(
                report.resets.get(&sid),
                Some(&frame::error_code::CANCEL),
                "{mode}: stream {sid} must be reset with CANCEL"
            );
        }
        let at = report.all_starved_reset_at.unwrap();
        assert!(
            at < Duration::from_millis(1500),
            "{mode}: reset after {at:?}"
        );
        assert_eq!(
            report.goaway, None,
            "{mode}: only the starved responses are reset"
        );
    }

    /// Regression (#599): a reader that withholds flow-control credit (while keeping the
    /// connection alive with PINGs) can no longer pin finished responses indefinitely.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_send_stall_resets_responses_of_a_credit_withholding_reader() {
        let before = send_stall_resets();
        let report = run_send_stall(Credit::Withhold);
        assert_starved_streams_reset(&report, "withhold");
        assert!(report.data.is_empty(), "no credit, no DATA");
        assert!(send_stall_resets() >= before + 4);
    }

    /// A reader granting a byte at a time does not restart a response's clock: it only
    /// restarts after `SEND_STALL_MIN_PROGRESS` bytes of that response's own progress.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_send_stall_resets_a_trickled_response() {
        let report = run_send_stall(Credit::Trickle);
        assert_starved_streams_reset(&report, "trickle");
        let trickled = report.data.get(&1).copied().unwrap_or(0);
        assert!(trickled > 0, "the trickle delivered some bytes");
        assert!((trickled as u64) < send::SEND_STALL_MIN_PROGRESS);
    }

    /// Progress on OTHER streams cannot keep a starved response alive: each response is
    /// judged on its own delivery.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_send_stall_judges_each_response_on_its_own_progress() {
        let report = run_send_stall(Credit::ProgressElsewhere);
        assert_starved_streams_reset(&report, "progress elsewhere");
        let elsewhere: usize = report
            .data
            .iter()
            .filter(|(sid, _)| **sid >= 9)
            .map(|(_, n)| n)
            .sum();
        assert!(
            elsewhere >= 64 * 1024,
            "the connection kept making progress"
        );
        assert!(
            report.resets.keys().all(|sid| *sid < 9),
            "fully granted responses are never reset: {:?}",
            report.resets
        );
    }

    /// Control: a reader that grants credit receives every body and nothing is reset.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_send_stall_spares_a_reader_that_grants_credit() {
        let report = run_send_stall(Credit::Grant);
        assert!(report.resets.is_empty(), "{:?}", report.resets);
        for sid in [1u32, 3, 5, 7] {
            assert_eq!(report.data.get(&sid), Some(&(64 * 1024)), "stream {sid}");
        }
    }

    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_body_deadline_resets_withheld_request_body() {
        use std::io::{Read, Write};
        use std::time::Instant;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();

        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            let wire = body_budget_request_wire(false);
            stream.write_all(&wire).unwrap();

            // Wait for the RST_STREAM(CANCEL) on stream 1.
            let started = Instant::now();
            let mut seen = Vec::new();
            stream
                .set_read_timeout(Some(Duration::from_millis(5)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let rst_at: Option<Duration> = loop {
                if started.elapsed() > Duration::from_secs(3) {
                    break None;
                }
                match stream.read(&mut buf) {
                    Ok(0) => break None,
                    Ok(n) => {
                        seen.extend_from_slice(&buf[..n]);
                        let hit = seen.windows(9).any(|w| {
                            w[3] == frame::kind::RST_STREAM
                                && u32::from_be_bytes([w[5], w[6], w[7], w[8]]) == 1
                        });
                        if hit {
                            break Some(started.elapsed());
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => break None,
                }
            };
            drop(stream);
            rst_at
        });

        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        let result = runtime.block_on(async move {
            let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let config = Config {
                conn_idle_timeout: None,
                request_body_timeout: Some(Duration::from_millis(200)),
                ..Config::default()
            };
            serve_local_with_prefix(
                stream,
                Vec::new(),
                |_| {
                    std::future::ready(hj_core::text_response(
                        http::StatusCode::OK,
                        "unexpected request",
                    ))
                },
                config,
                None,
                None,
            )
            .await
        });

        let rst_at = client.join().unwrap();
        assert!(result.is_ok(), "the connection should close cleanly on EOF");
        let rst = rst_at.expect("an incomplete request body must be reset by the deadline");
        assert!(
            rst < Duration::from_secs(2),
            "the body deadline must RST the stream promptly (took {rst:?})"
        );
    }

    /// (#1035) How stream 1 of a paced upload ended, and when (from its HEADERS).
    #[cfg(feature = "monoio")]
    #[derive(Debug)]
    enum PacedEnd {
        /// The response completed with this body.
        Answered(Vec<u8>, Duration),
        /// RST_STREAM with this code.
        Reset(u32, Duration),
        /// The connection closed with neither.
        Closed,
    }

    /// (#1035) POSTs `chunks` DATA frames of `chunk` bytes on stream 1, one every `gap`,
    /// to a monoio connection whose request-body timeout is 1 s and ceiling `ceiling`.
    /// The handler answers with the body length it received.
    #[cfg(feature = "monoio")]
    fn paced_h2_upload(ceiling: Duration, chunk: usize, chunks: usize, gap: Duration) -> PacedEnd {
        use std::io::{Read, Write};
        use std::time::Instant;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                .enable_timer()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let config = Config {
                    conn_idle_timeout: None,
                    request_body_timeout: Some(Duration::from_secs(1)),
                    request_body_ceiling: ceiling,
                    ..Config::default()
                };
                let _ = serve_local_with_prefix(
                    stream,
                    Vec::new(),
                    |req: Request| async move {
                        let body = http_body_util::BodyExt::collect(req.into_body())
                            .await
                            .unwrap()
                            .to_bytes();
                        hj_core::text_response(http::StatusCode::OK, body.len().to_string())
                    },
                    config,
                    None,
                    None,
                )
                .await;
            });
        });

        let mut stream = std::net::TcpStream::connect(address).unwrap();
        let mut wire = crate::conn::PREFACE.to_vec();
        frame::write_settings(&mut wire, &[]);
        let mut block = Vec::new();
        let mut encoder = Encoder::new();
        let length = (chunk * chunks).to_string();
        for (name, value) in [
            (":method", "POST"),
            (":path", "/upload"),
            (":scheme", "https"),
            (":authority", "example.com"),
            ("content-length", length.as_str()),
        ] {
            encoder.encode_header(&mut block, name, value);
        }
        frame::write_frame(
            &mut wire,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS,
            1,
            &block,
        );
        stream.write_all(&wire).unwrap();
        let started = Instant::now();
        let mut writer = stream.try_clone().unwrap();
        std::thread::spawn(move || {
            for index in 0..chunks {
                let mut data = Vec::new();
                let flags = if index + 1 == chunks {
                    frame::flags::END_STREAM
                } else {
                    0
                };
                frame::write_frame(&mut data, frame::kind::DATA, flags, 1, &vec![b'x'; chunk]);
                if writer.write_all(&data).is_err() {
                    return;
                }
                if index + 1 < chunks {
                    std::thread::sleep(gap);
                }
            }
        });

        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut seen = Vec::new();
        let mut body = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        let end = 'read: loop {
            while seen.len() >= FrameHeader::LEN {
                let hdr = FrameHeader::parse(&seen).unwrap();
                let total = FrameHeader::LEN + hdr.length as usize;
                if seen.len() < total {
                    break;
                }
                let payload = seen[FrameHeader::LEN..total].to_vec();
                seen.drain(..total);
                if hdr.stream_id != 1 {
                    continue;
                }
                match hdr.kind {
                    frame::kind::RST_STREAM => {
                        let code = u32::from_be_bytes(payload[..4].try_into().unwrap());
                        break 'read PacedEnd::Reset(code, started.elapsed());
                    }
                    frame::kind::DATA => {
                        body.extend_from_slice(&payload);
                        if hdr.flags & frame::flags::END_STREAM != 0 {
                            break 'read PacedEnd::Answered(body, started.elapsed());
                        }
                    }
                    _ => {}
                }
            }
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => seen.extend_from_slice(&buf[..n]),
                _ => break PacedEnd::Closed,
            }
        };
        // Ends the writer and the server's connection.
        let _ = stream.shutdown(std::net::Shutdown::Both);
        end
    }

    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_steady_upload_outlasting_the_body_timeout_is_answered() {
        // 16 KiB every 400 ms for 2.4 s: past twice the 1 s body timeout.
        match paced_h2_upload(
            hj_core::body_deadline::BODY_DEADLINE_CEILING,
            16 * 1024,
            7,
            Duration::from_millis(400),
        ) {
            PacedEnd::Answered(body, took) => {
                assert_eq!(body, b"114688");
                assert!(took > Duration::from_secs(2), "{took:?}");
            }
            other => panic!("a steady upload must not be reset: {other:?}"),
        }
    }

    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_trickled_upload_is_reset_at_the_body_timeout() {
        match paced_h2_upload(
            hj_core::body_deadline::BODY_DEADLINE_CEILING,
            1,
            100,
            Duration::from_millis(100),
        ) {
            PacedEnd::Reset(code, took) => {
                assert_eq!(code, frame::error_code::CANCEL);
                assert!(
                    took >= Duration::from_millis(950) && took < Duration::from_millis(1700),
                    "{took:?}"
                );
            }
            other => panic!("a trickle below the floor must be reset: {other:?}"),
        }
    }

    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_steady_upload_is_reset_at_the_body_ceiling() {
        let ceiling = Duration::from_millis(1500);
        match paced_h2_upload(ceiling, 16 * 1024, 10, Duration::from_millis(300)) {
            PacedEnd::Reset(code, took) => {
                assert_eq!(code, frame::error_code::CANCEL);
                assert!(
                    took >= ceiling - Duration::from_millis(50)
                        && took < ceiling + Duration::from_millis(700),
                    "{took:?}"
                );
            }
            other => panic!("progress must not outlast the ceiling: {other:?}"),
        }
    }

    /// Regression for the monoio-loop in-flight abandonment bug: once reads stop, the loop
    /// must keep running while `inflight` or `pulls` is non-empty so a slow handler's
    /// response is still delivered to a client that half-closed / GOAWAYed mid-request.
    /// The old monoio path had an unconditional `if !reading { break }` that closed first.
    #[test]
    fn should_close_drains_inflight_after_reads_stop() {
        // reading stopped, a handler still running -> must NOT close (the bug).
        assert!(!should_close(
            false, false, /*inflight*/ false, /*pulls*/ true, true, true
        ));
        // reading stopped, a streaming body still producing -> must NOT close.
        assert!(!should_close(
            false, false, true, /*pulls*/ false, true, true
        ));
        // reading stopped, nothing left to produce -> close (window-blocked outstreams
        // can't advance without reads, so they are intentionally ignored).
        assert!(should_close(
            false, false, true, true, /*outstreams*/ false, true
        ));
        assert!(should_close(false, false, true, true, true, true));
        // still reading -> never close here (the select drives the next read).
        assert!(!should_close(true, false, true, true, true, true));
        // graceful drain keeps reading, so it only closes once EVERYTHING (incl.
        // outstreams) has drained.
        assert!(!should_close(
            true, true, true, true, /*outstreams*/ false, true
        ));
        assert!(should_close(true, true, true, true, true, true));
        // #695: a graceful drain waits for a request still uploading its body.
        assert!(!should_close(true, true, true, true, true, false));
    }

    /// `AbortOnDrop` must CANCEL its in-flight task on drop (not tokio's default detach), so a
    /// connection that exits early on an I/O error doesn't leave spawned handlers burning CPU /
    /// holding backend sockets. Starts the task, drops the guard mid-flight, and confirms the
    /// task's completion side effect never happens.
    #[tokio::test]
    async fn abort_on_drop_cancels_in_flight_task() {
        let done = Arc::new(AtomicBool::new(false));
        let d2 = done.clone();
        let guard = AbortOnDrop(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            d2.store(true, Ordering::SeqCst);
        }));
        tokio::time::sleep(Duration::from_millis(20)).await; // let the task reach its await point
        drop(guard); // abort it mid-flight
        tokio::time::sleep(Duration::from_millis(300)).await; // well past when it would have completed
        assert!(
            !done.load(Ordering::SeqCst),
            "AbortOnDrop must abort the in-flight task, not detach it (a detached task would set the flag)"
        );
    }

    struct DropPending {
        started: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl Future for DropPending {
        type Output = Response;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            self.started.store(true, Ordering::Release);
            std::task::Poll::Pending
        }
    }

    impl Drop for DropPending {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    fn peer_settings_count(param: &str, bucket: &str) -> u64 {
        peer_settings_counts()
            .into_iter()
            .find(|(p, b, _)| *p == param && b == bucket)
            .map(|(_, _, n)| n)
            .unwrap_or_else(|| panic!("no bucket {param} {bucket}"))
    }

    #[test]
    fn peer_settings_buckets_are_inclusive_powers_of_two() {
        assert_eq!(peer_settings_bucket(&PEER_IWS_BOUNDS, 0), 0);
        assert_eq!(peer_settings_bucket(&PEER_IWS_BOUNDS, 65_535), 2);
        assert_eq!(peer_settings_bucket(&PEER_IWS_BOUNDS, 65_536), 2);
        assert_eq!(peer_settings_bucket(&PEER_IWS_BOUNDS, 65_537), 3);
        assert_eq!(
            peer_settings_bucket(&PEER_IWS_BOUNDS, i32::MAX as u64),
            PEER_IWS_BOUNDS.len() - 1
        );
        assert_eq!(peer_settings_bucket(&PEER_HTS_BOUNDS, 0), 0);
        assert_eq!(peer_settings_bucket(&PEER_HTS_BOUNDS, 4096), 5);
        assert_eq!(
            peer_settings_bucket(&PEER_HTS_BOUNDS, u32::MAX as u64),
            PEER_HTS_BOUNDS.len()
        );
        assert_eq!(
            peer_settings_bucket(&PEER_MFS_BOUNDS, (1 << 24) - 1),
            PEER_MFS_BOUNDS.len() - 1
        );
        let counts = peer_settings_counts();
        assert_eq!(
            counts.len(),
            PEER_IWS_BOUNDS.len() + PEER_HTS_BOUNDS.len() + PEER_MFS_BOUNDS.len() + 3
        );
        assert!(
            counts
                .iter()
                .any(|(p, b, _)| *p == "header_table_size" && b == ">65536")
        );
        assert!(
            counts
                .iter()
                .any(|(p, b, _)| *p == "initial_window_size" && b == "<=2147483648")
        );
    }

    /// Only a connection's FIRST SETTINGS frame is counted; a later one (and omitted
    /// parameters, which keep their defaults) must not add samples.
    #[test]
    fn first_peer_settings_frame_is_counted_once_per_connection() {
        use super::recv::process_frame;
        use crate::frame::kind;

        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));
        let mut streams = FxHashMap::default();
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = recv_for_header_test(0);
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled = FxHashSet::default();
        let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();
        let mut payload = Vec::new();
        for (id, value) in [
            (settings::INITIAL_WINDOW_SIZE, 999_999_999u32),
            (settings::MAX_FRAME_SIZE, 1 << 20),
        ] {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        let iws_before = peer_settings_count("initial_window_size", "<=1073741824");
        let mfs_before = peer_settings_count("max_frame_size", "<=1048576");
        let hts_before = peer_settings_count("header_table_size", "<=4096");
        for _ in 0..3 {
            let outcome = process_frame(
                FrameHeader {
                    length: payload.len() as u32,
                    kind: kind::SETTINGS,
                    flags: 0,
                    stream_id: 0,
                },
                &payload,
                &mut streams,
                &mut dec,
                &mut enc,
                &mut out,
                &mut peer,
                &mut recv,
                0,
                true,
                &service,
                &mut inflight,
                &mut cancelled,
                &mut inflight_sids,
            );
            assert!(!matches!(outcome, FrameOutcome::StopReading));
        }
        assert!(peer.first_settings_recorded);
        assert_eq!(
            peer_settings_count("initial_window_size", "<=1073741824") - iws_before,
            1
        );
        assert!(peer_settings_count("max_frame_size", "<=1048576") > mfs_before);
        assert!(peer_settings_count("header_table_size", "<=4096") > hts_before);
    }

    #[tokio::test]
    async fn rst_stream_cancels_the_running_handler() {
        use super::recv::process_frame;
        use crate::frame::{flags, kind};

        let started = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let service = {
            let started = started.clone();
            let dropped = dropped.clone();
            move |_req: Request| DropPending {
                started: started.clone(),
                dropped: dropped.clone(),
            }
        };
        let mut streams = FxHashMap::default();
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = recv_for_header_test(0);
        let mut inflight: Inflight<DropPending> = Inflight::new();
        let mut cancelled = FxHashSet::default();
        let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();
        let headers = [0x82, 0x87, 0x84];

        let outcome = process_frame(
            FrameHeader {
                length: headers.len() as u32,
                kind: kind::HEADERS,
                flags: flags::END_HEADERS | flags::END_STREAM,
                stream_id: 1,
            },
            &headers,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        assert!(matches!(outcome, FrameOutcome::Continue));
        assert!(inflight_sids.contains_key(&1));

        let _ = futures_util::FutureExt::now_or_never(inflight.next());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("handler must start before the reset");

        let outcome = process_frame(
            FrameHeader {
                length: 4,
                kind: kind::RST_STREAM,
                flags: 0,
                stream_id: 1,
            },
            &error_code::CANCEL.to_be_bytes(),
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        assert!(matches!(outcome, FrameOutcome::ResetStream(1)));
        assert!(!inflight_sids.contains_key(&1));
        let completed = tokio::time::timeout(Duration::from_secs(1), inflight.next())
            .await
            .expect("aborted handler must become ready")
            .expect("aborted handler must remain queued until drained");
        assert_eq!((completed.0, completed.1), (1, false));
        assert!(
            completed.2.is_none(),
            "a reset stream must yield no response"
        );
        cancelled.remove(&1);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("RST_STREAM must drop the handler instead of leaving backend work running");
    }

    /// A panic in ONE spawned handler must be isolated to its stream: `Tagged` turns the
    /// `JoinError` into a 500 rather than propagating the panic into the connection task
    /// (which would tear down every multiplexed stream). Regime-independent — exercises the
    /// `Spawned` arm directly rather than relying on `spare_cores()`.
    #[tokio::test]
    async fn spawned_handler_panic_becomes_500_not_a_connection_panic() {
        let h: tokio::task::JoinHandle<Response> =
            tokio::spawn(async move { panic!("handler boom") });
        let (tagged, _abort) = Tagged::<std::future::Ready<Response>>::cancellable(
            7,
            false,
            TaggedInner::Spawned(AbortOnDrop(h)),
        );
        let (sid, is_head, resp) = std::pin::pin!(tagged).await;
        assert_eq!(sid, 7);
        assert!(!is_head);
        let resp = resp.expect("the handler was not cancelled");
        assert_eq!(
            resp.status(),
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "a panicking spawned handler must yield a 500 for its stream, not crash the connection"
        );
    }

    fn recv_for_header_test(last_client_stream: u32) -> Recv {
        Recv {
            seen_settings: true,
            last_client_stream,
            goaway_last: None,
            open_header_block: None,
            discarding_header_block: false,
            discard_header_block: Vec::new(),
            discard_rst_code: error_code::STREAM_CLOSED,
            reset_ids: Default::default(),
            sent_reset_ids: Default::default(),
            max_concurrent: 100,
            conn_recv_window: 65535,
            our_initial_window: 65535,
            header_count_hint: 0,
            reset_debt_until: None,
            total_buffered: 0,
            max_request_body: 1 << 20,
            per_conn_request_body: 4 << 20,
            pending_header_bytes: 0,
            pending_header_mem: 4 << 20,
            body_budget: None,
            no_progress_frames: 0,
            early_reject: None,
        }
    }

    /// The rapid-reset budget is a burst refilled by time alone: nothing but elapsed time
    /// pays reset debt back, the refill never banks more than one burst, and a steady
    /// cancel rate at the refill rate is sustainable indefinitely.
    #[test]
    fn rapid_reset_budget_refills_with_time_only() {
        let t0 = tokio::time::Instant::now();
        let mut recv = recv_for_header_test(0);
        for n in 1..=200 {
            assert!(
                !recv.charge_inflight_reset_at(t0),
                "reset {n} is in the burst"
            );
        }
        assert!(
            recv.charge_inflight_reset_at(t0),
            "reset 201 exceeds the burst"
        );

        let mut recv = recv_for_header_test(0);
        for _ in 0..200 {
            recv.charge_inflight_reset_at(t0);
        }
        let t1 = t0 + Duration::from_secs(1);
        for n in 1..=10 {
            assert!(
                !recv.charge_inflight_reset_at(t1),
                "credit {n} refilled in 1 s"
            );
        }
        assert!(
            recv.charge_inflight_reset_at(t1),
            "only 10 credits refill per second"
        );

        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..200 {
            assert!(!recv.charge_inflight_reset_at(t2));
        }
        assert!(
            recv.charge_inflight_reset_at(t2),
            "idle time banks one burst, no more"
        );

        let mut recv = recv_for_header_test(0);
        let mut t = t0;
        for _ in 0..10_000 {
            assert!(!recv.charge_inflight_reset_at(t));
            t += Duration::from_millis(100);
        }
    }

    /// Every way a body-pending stream leaves the receive map returns its decoded-header
    /// charge; a leak would refuse uploads on a long-lived connection.
    #[tokio::test]
    async fn pending_header_charge_is_returned_on_every_teardown() {
        use super::recv::process_frame;
        use crate::frame::{flags, kind};

        let mut streams: FxHashMap<u32, StreamState> = FxHashMap::default();
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut client = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = recv_for_header_test(0);
        recv.max_request_body = 8;
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled: FxHashSet<u32> = FxHashSet::default();
        let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();
        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));
        macro_rules! send {
            ($kind:expr, $flags:expr, $sid:expr, $payload:expr) => {{
                let payload: &[u8] = $payload;
                process_frame(
                    FrameHeader {
                        length: payload.len() as u32,
                        kind: $kind,
                        flags: $flags,
                        stream_id: $sid,
                    },
                    payload,
                    &mut streams,
                    &mut dec,
                    &mut enc,
                    &mut out,
                    &mut peer,
                    &mut recv,
                    0,
                    true,
                    &service,
                    &mut inflight,
                    &mut cancelled,
                    &mut inflight_sids,
                )
            }};
        }
        let open = |client: &mut Encoder, extra: &[(&str, &str)]| {
            let mut block = Vec::new();
            for (name, value) in [
                (":method", "POST"),
                (":path", "/upload"),
                (":scheme", "https"),
                (":authority", "example.com"),
            ]
            .iter()
            .chain(extra)
            {
                client.encode_header(&mut block, name, value);
            }
            block
        };

        let teardowns: [(&str, u32); 8] = [
            ("peer RST_STREAM", 1),
            ("dispatch", 3),
            ("413 past max_request_body", 5),
            ("provoked reset", 7),
            ("body deadline", 9),
            ("malformed trailers", 11),
            ("content-length mismatch", 13),
            ("unterminated trailers", 15),
        ];
        for (how, sid) in teardowns {
            let extra: &[(&str, &str)] = if sid == 13 {
                &[("content-length", "2")]
            } else {
                &[]
            };
            let block = open(&mut client, extra);
            send!(kind::HEADERS, flags::END_HEADERS, sid, &block);
            assert!(streams.contains_key(&sid), "{how}: stream admitted");
            assert!(recv.pending_header_bytes > 0, "{how}: headers charged");
            match sid {
                1 => {
                    send!(kind::RST_STREAM, 0, sid, &error_code::CANCEL.to_be_bytes());
                }
                3 | 13 => {
                    send!(kind::DATA, flags::END_STREAM, sid, b"x");
                }
                5 => {
                    send!(kind::DATA, 0, sid, b"123456789");
                }
                7 => {
                    send!(kind::WINDOW_UPDATE, 0, sid, &[0, 0, 0, 0]);
                }
                9 => {
                    recv.expire_receiving(&mut streams, sid);
                }
                11 => {
                    let mut trailers = Vec::new();
                    client.encode_header(&mut trailers, ":path", "/");
                    send!(
                        kind::HEADERS,
                        flags::END_HEADERS | flags::END_STREAM,
                        sid,
                        &trailers
                    );
                }
                _ => {
                    let mut trailers = Vec::new();
                    client.encode_header(&mut trailers, "x-trailer", "1");
                    send!(kind::HEADERS, flags::END_HEADERS, sid, &trailers);
                }
            }
            assert!(!streams.contains_key(&sid), "{how}: stream left the map");
            assert_eq!(recv.pending_header_bytes, 0, "{how}: charge returned");
        }
        assert_eq!(
            inflight.len(),
            1,
            "only the dispatched stream reached a handler"
        );
    }

    fn request_block_referencing_first_dynamic_entry() -> Vec<u8> {
        vec![0x82, 0x87, 0x84, 0xbe]
    }

    #[tokio::test]
    async fn first_frame_must_be_non_ack_settings() {
        // #625 (RFC 9113 §3.4)
        use super::recv::process_frame;
        use crate::frame::{flags, kind};
        let run = |kind: u8, flags_v: u8, payload: &[u8]| {
            let mut streams = FxHashMap::default();
            let mut dec = Decoder::new(4096, 8192);
            let mut enc = Encoder::new();
            let mut out = OutQueue::default();
            let mut peer = PeerSettings::default();
            let mut recv = recv_for_header_test(0);
            recv.seen_settings = false;
            let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
            let mut cancelled = FxHashSet::default();
            let mut inflight_sids = FxHashMap::default();
            let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));
            process_frame(
                FrameHeader {
                    length: payload.len() as u32,
                    kind,
                    flags: flags_v,
                    stream_id: if kind == kind::HEADERS { 1 } else { 0 },
                },
                payload,
                &mut streams,
                &mut dec,
                &mut enc,
                &mut out,
                &mut peer,
                &mut recv,
                0,
                true,
                &service,
                &mut inflight,
                &mut cancelled,
                &mut inflight_sids,
            )
        };
        assert!(matches!(
            run(kind::HEADERS, flags::END_HEADERS, &[0x82, 0x87, 0x84]),
            FrameOutcome::StopReading
        ));
        assert!(matches!(
            run(kind::SETTINGS, flags::ACK, &[]),
            FrameOutcome::StopReading
        ));
        assert!(!matches!(
            run(kind::SETTINGS, 0, &[]),
            FrameOutcome::StopReading
        ));
    }

    #[tokio::test]
    async fn self_priority_error_decodes_hpack_before_reset() {
        use super::recv::process_frame;
        use crate::frame::{flags, kind};

        let mut streams = FxHashMap::default();
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = recv_for_header_test(0);
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled = FxHashSet::default();
        let mut inflight_sids = FxHashMap::default();
        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));

        let mut rejected = vec![0, 0, 0, 1, 16];
        rejected.extend_from_slice(&[0x40, 1, b'x', 1, b'y']);
        let outcome = process_frame(
            FrameHeader {
                length: rejected.len() as u32,
                kind: kind::HEADERS,
                flags: flags::PRIORITY | flags::END_HEADERS,
                stream_id: 1,
            },
            &rejected,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        assert!(matches!(outcome, FrameOutcome::ResetStream(1)));
        assert_eq!(
            recv.last_client_stream, 1,
            "a rejected new stream id must still be marked seen"
        );

        let same_stream = [0x82, 0x87, 0x84];
        let outcome = process_frame(
            FrameHeader {
                length: same_stream.len() as u32,
                kind: kind::HEADERS,
                flags: flags::END_HEADERS | flags::END_STREAM,
                stream_id: 1,
            },
            &same_stream,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        // (#242) The reused-closed-id rejection now surfaces as ResetStream (with
        // outbound teardown) instead of a bare Continue — still no connection error.
        assert!(matches!(outcome, FrameOutcome::ResetStream(1)));
        assert_eq!(inflight.len(), 0, "the reset id cannot be reopened");

        let next = request_block_referencing_first_dynamic_entry();
        let outcome = process_frame(
            FrameHeader {
                length: next.len() as u32,
                kind: kind::HEADERS,
                flags: flags::END_HEADERS | flags::END_STREAM,
                stream_id: 3,
            },
            &next,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        assert!(matches!(outcome, FrameOutcome::Continue));
        assert_eq!(inflight.len(), 1, "the later dynamic reference must decode");
    }

    #[tokio::test]
    async fn self_priority_on_idle_even_stream_is_a_connection_error() {
        use super::recv::process_frame;
        use crate::frame::{flags, kind};

        let mut streams = FxHashMap::default();
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = recv_for_header_test(0);
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled = FxHashSet::default();
        let mut inflight_sids = FxHashMap::default();
        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));
        let mut block = vec![0, 0, 0, 2, 16];
        block.extend_from_slice(&[0x82, 0x87, 0x84]);

        let outcome = process_frame(
            FrameHeader {
                length: block.len() as u32,
                kind: kind::HEADERS,
                flags: flags::PRIORITY | flags::END_HEADERS | flags::END_STREAM,
                stream_id: 2,
            },
            &block,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        assert!(matches!(outcome, FrameOutcome::StopReading));
        assert_eq!(recv.last_client_stream, 0);
    }

    #[tokio::test]
    async fn unterminated_trailers_decode_continuation_before_reset() {
        use super::recv::process_frame;
        use crate::frame::{flags, kind};

        let mut streams = FxHashMap::default();
        streams.insert(
            1,
            StreamState {
                headers_done: true,
                recv_window: 65535,
                ..Default::default()
            },
        );
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = recv_for_header_test(1);
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled = FxHashSet::default();
        let mut inflight_sids = FxHashMap::default();
        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));

        let first = [0x40, 1, b'x'];
        let outcome = process_frame(
            FrameHeader {
                length: first.len() as u32,
                kind: kind::HEADERS,
                flags: 0,
                stream_id: 1,
            },
            &first,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        assert!(matches!(outcome, FrameOutcome::Continue));
        assert!(recv.discarding_header_block);

        let rest = [1, b'y'];
        let outcome = process_frame(
            FrameHeader {
                length: rest.len() as u32,
                kind: kind::CONTINUATION,
                flags: flags::END_HEADERS,
                stream_id: 1,
            },
            &rest,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        // (#242) The self-priority stream error now returns ResetStream so the
        // session tears down outbound state — still a STREAM reset, not GOAWAY.
        assert!(matches!(outcome, FrameOutcome::ResetStream(1)));

        let next = request_block_referencing_first_dynamic_entry();
        let outcome = process_frame(
            FrameHeader {
                length: next.len() as u32,
                kind: kind::HEADERS,
                flags: flags::END_HEADERS | flags::END_STREAM,
                stream_id: 3,
            },
            &next,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        assert!(matches!(outcome, FrameOutcome::Continue));
        assert_eq!(inflight.len(), 1, "the later dynamic reference must decode");
    }

    /// (audit-2026-07-01) A malformed trailer section (here a `:method` pseudo-header, illegal in
    /// trailers per RFC 9113 §8.1) arriving AFTER the request body was buffered must un-account the
    /// stream's buffered bytes from `Recv::total_buffered`. The old Decoded::Malformed arm removed
    /// the stream but leaked the budget, so a repeated malformed-trailer-after-body would inflate
    /// `total_buffered` until a later legitimate DATA byte tripped a spurious GOAWAY(ENHANCE_YOUR_CALM).
    #[test]
    fn malformed_trailer_after_body_unaccounts_buffered_bytes() {
        use super::recv::process_frame;
        use crate::frame::{flags, kind};

        let body_len = 100usize;
        let mut streams: FxHashMap<u32, StreamState> = FxHashMap::default();
        streams.insert(
            1,
            StreamState {
                headers_done: true,
                body: vec![0u8; body_len],
                recv_window: 65535,
                ..Default::default()
            },
        );
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = Recv {
            seen_settings: true,
            last_client_stream: 1,
            goaway_last: None,
            open_header_block: None,
            discarding_header_block: false,
            discard_header_block: Vec::new(),
            discard_rst_code: error_code::STREAM_CLOSED,
            reset_ids: Default::default(),
            sent_reset_ids: Default::default(),
            max_concurrent: 100,
            conn_recv_window: 65535,
            our_initial_window: 65535,
            header_count_hint: 0,
            reset_debt_until: None,
            total_buffered: body_len,
            max_request_body: 1 << 20,
            per_conn_request_body: 4 << 20,
            pending_header_bytes: 0,
            pending_header_mem: 4 << 20,
            body_budget: None,
            no_progress_frames: 0,
            early_reject: None,
        };
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled: FxHashSet<u32> = FxHashSet::default();
        let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();
        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));

        // HPACK indexed field, static-table index 2 = `:method: GET` — a pseudo-header, malformed
        // in a trailer section.
        let block = [0x82u8];
        let hdr = FrameHeader {
            length: block.len() as u32,
            kind: kind::HEADERS,
            flags: flags::END_HEADERS | flags::END_STREAM,
            stream_id: 1,
        };
        let outcome = process_frame(
            hdr,
            &block,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        assert!(
            matches!(outcome, FrameOutcome::ResetStream(1)),
            "a malformed trailer resets the stream (#242: with outbound teardown), not the connection"
        );
        assert!(
            !streams.contains_key(&1),
            "the malformed-trailer stream is removed"
        );
        assert_eq!(
            recv.total_buffered, 0,
            "the buffered request body must be un-accounted (it was leaking)"
        );
    }

    /// Regression (#581): a server RST_STREAM (here via a zero WINDOW_UPDATE)
    /// must tear down the receiving stream — a later DATA...END_STREAM must
    /// not complete and dispatch the already-reset request.
    #[test]
    fn server_rst_tears_down_receiving_stream() {
        use super::recv::process_frame;
        use crate::frame::{flags, kind};

        let mut streams: FxHashMap<u32, StreamState> = FxHashMap::default();
        streams.insert(
            1,
            StreamState {
                headers_done: true,
                body: vec![0u8; 10],
                recv_window: 65535,
                ..Default::default()
            },
        );
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = Recv {
            seen_settings: true,
            last_client_stream: 1,
            goaway_last: None,
            open_header_block: None,
            discarding_header_block: false,
            discard_header_block: Vec::new(),
            discard_rst_code: error_code::STREAM_CLOSED,
            reset_ids: Default::default(),
            sent_reset_ids: Default::default(),
            max_concurrent: 100,
            conn_recv_window: 65535,
            our_initial_window: 65535,
            header_count_hint: 0,
            reset_debt_until: None,
            total_buffered: 10,
            max_request_body: 1 << 20,
            per_conn_request_body: 4 << 20,
            pending_header_bytes: 0,
            pending_header_mem: 4 << 20,
            body_budget: None,
            no_progress_frames: 0,
            early_reject: None,
        };
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled: FxHashSet<u32> = FxHashSet::default();
        let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();
        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));

        // Zero-increment WINDOW_UPDATE on the body-pending stream -> RST.
        let outcome = process_frame(
            FrameHeader {
                length: 4,
                kind: kind::WINDOW_UPDATE,
                flags: 0,
                stream_id: 1,
            },
            &[0, 0, 0, 0],
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        assert!(matches!(outcome, FrameOutcome::ResetStream(1)));
        assert!(!streams.contains_key(&1), "receiving stream torn down");
        assert_eq!(recv.total_buffered, 0, "buffered body un-accounted");

        // A later DATA...END_STREAM on the reset stream must not dispatch.
        let outcome = process_frame(
            FrameHeader {
                length: 3,
                kind: kind::DATA,
                flags: flags::END_STREAM,
                stream_id: 1,
            },
            b"abc",
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        // §5.1: ignored, not re-reset (#877).
        assert!(matches!(outcome, FrameOutcome::Continue));
        assert_eq!(inflight.len(), 0, "reset request must never dispatch");
    }

    #[test]
    fn recent_ids_keep_the_newest_entries() {
        let mut ids = super::state::RecentIds::default();
        for sid in [1, 3, 5, 3] {
            ids.insert(sid, 3);
        }
        assert!(ids.contains(1) && ids.contains(3) && ids.contains(5));
        ids.insert(7, 3);
        assert!(!ids.contains(1), "the oldest id is evicted at the cap");
        assert!(ids.contains(3) && ids.contains(5) && ids.contains(7));
        let mut none = super::state::RecentIds::default();
        none.insert(1, 0);
        assert!(!none.contains(1));
    }

    /// Regression (#976): on a long-lived connection, resets past the cap used to go
    /// unrecorded, so late frames racing our newest RST_STREAMs were misjudged — DATA
    /// drew an RST instead of being ignored (#877) and trailers escalated to GOAWAY.
    /// The most recent resets are remembered; only evicted old ids fail closed.
    #[test]
    fn late_frames_after_many_resets_still_track_the_newest_resets() {
        use super::recv::process_frame;
        use crate::frame::{flags, kind};

        const RESETS: u32 = 600;
        let mut streams: FxHashMap<u32, StreamState> = FxHashMap::default();
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = Recv {
            seen_settings: true,
            last_client_stream: 2 * RESETS - 1,
            goaway_last: None,
            open_header_block: None,
            discarding_header_block: false,
            discard_header_block: Vec::new(),
            discard_rst_code: error_code::STREAM_CLOSED,
            reset_ids: Default::default(),
            sent_reset_ids: Default::default(),
            max_concurrent: 256,
            conn_recv_window: 65535,
            our_initial_window: 65535,
            header_count_hint: 0,
            reset_debt_until: None,
            total_buffered: 0,
            max_request_body: 1 << 20,
            per_conn_request_body: 4 << 20,
            pending_header_bytes: 0,
            pending_header_mem: 4 << 20,
            body_budget: None,
            no_progress_frames: 0,
            early_reject: None,
        };
        for sid in (1..2 * RESETS).step_by(2) {
            recv.teardown_receiving(&mut streams, sid);
        }
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled: FxHashSet<u32> = FxHashSet::default();
        let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();
        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));
        let mut trailers = Vec::new();
        Encoder::new().encode_header(&mut trailers, "x-trailer", "1");
        let newest = 2 * RESETS - 1;
        let late = [
            (kind::DATA, flags::END_STREAM, newest, &b"abc"[..]),
            (
                kind::HEADERS,
                flags::END_HEADERS | flags::END_STREAM,
                newest - 2,
                &trailers[..],
            ),
            (kind::DATA, flags::END_STREAM, 1, &b"abc"[..]),
            (
                kind::HEADERS,
                flags::END_HEADERS | flags::END_STREAM,
                3,
                &trailers[..],
            ),
        ];
        let mut outcomes = Vec::new();
        for (kind, flags, stream_id, payload) in late {
            outcomes.push(process_frame(
                FrameHeader {
                    length: payload.len() as u32,
                    kind,
                    flags,
                    stream_id,
                },
                payload,
                &mut streams,
                &mut dec,
                &mut enc,
                &mut out,
                &mut peer,
                &mut recv,
                0,
                true,
                &service,
                &mut inflight,
                &mut cancelled,
                &mut inflight_sids,
            ));
        }
        assert!(
            matches!(outcomes[0], FrameOutcome::Continue),
            "late DATA on our newest reset is ignored (#877)"
        );
        assert!(
            matches!(outcomes[1], FrameOutcome::ResetStream(sid) if sid == newest - 2),
            "racing trailers on a recent reset stay stream-scoped"
        );
        assert!(
            matches!(outcomes[2], FrameOutcome::ResetStream(1)),
            "an evicted id gets the RST answer"
        );
        assert!(
            matches!(outcomes[3], FrameOutcome::StopReading),
            "HEADERS on an evicted id fails closed to GOAWAY"
        );
        assert_eq!(inflight.len(), 0);
    }

    #[test]
    fn data_frame_respects_server_wide_body_budget() {
        // (#236 residual) The per-stream and per-connection caps leave the SERVER-WIDE
        // aggregate unbounded; the shared budget must refuse a reservation once exhausted
        // and release exactly what was buffered when a stream is torn down, so the
        // H1/H2/H3/LSAPI layers share one honest ledger.
        let budget = std::sync::Arc::new(hj_core::budget::BodyBufferBudget::new(16));
        let mut body_lease = hj_core::budget::BodyBufferLease::new(budget.clone());
        assert!(body_lease.reserve(8));
        use super::recv::process_frame;
        use crate::frame::kind;
        let mut streams: FxHashMap<u32, StreamState> = FxHashMap::default();
        streams.insert(
            1,
            StreamState {
                headers_done: true,
                body: vec![0u8; 8],
                body_lease: Some(body_lease),
                recv_window: 65535,
                ..Default::default()
            },
        );
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = Recv {
            seen_settings: true,
            last_client_stream: 1,
            goaway_last: None,
            open_header_block: None,
            discarding_header_block: false,
            discard_header_block: Vec::new(),
            discard_rst_code: error_code::STREAM_CLOSED,
            reset_ids: Default::default(),
            sent_reset_ids: Default::default(),
            max_concurrent: 100,
            conn_recv_window: 65535,
            our_initial_window: 65535,
            header_count_hint: 0,
            reset_debt_until: None,
            total_buffered: 8,
            max_request_body: 1 << 20,
            per_conn_request_body: 4 << 20,
            pending_header_bytes: 0,
            pending_header_mem: 4 << 20,
            body_budget: Some(budget.clone()),
            no_progress_frames: 0,
            early_reject: None,
        };
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled: FxHashSet<u32> = FxHashSet::default();
        let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();
        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));
        // A DATA frame that fits every per-stream/per-conn cap but exhausts the global one.
        let data = [0u8; 32];
        let hdr = FrameHeader {
            length: data.len() as u32,
            kind: kind::DATA,
            flags: 0,
            stream_id: 1,
        };
        let outcome = process_frame(
            hdr,
            &data,
            &mut streams,
            &mut dec,
            &mut enc,
            &mut out,
            &mut peer,
            &mut recv,
            0,
            true,
            &service,
            &mut inflight,
            &mut cancelled,
            &mut inflight_sids,
        );
        // (#597) The budget is server-wide, so its exhaustion refuses this stream
        // (retry-safe) instead of tearing down a connection that may carry others.
        assert!(
            matches!(outcome, FrameOutcome::ResetStream(1)),
            "exhausting the server-wide budget must refuse the stream, not GOAWAY"
        );
        assert!(!streams.contains_key(&1), "the refused stream is torn down");
        assert_eq!(
            recv.total_buffered, 0,
            "its buffered bytes are un-accounted"
        );
        assert_eq!(
            budget.in_flight(),
            0,
            "dropping the refused stream releases its lease; the failed reservation never landed"
        );
    }

    fn body_budget_request_block() -> Vec<u8> {
        let mut block = Vec::new();
        let mut encoder = Encoder::new();
        for (name, value) in [
            (":method", "POST"),
            (":path", "/upload"),
            (":scheme", "https"),
            (":authority", "example.com"),
            ("content-length", "8"),
        ] {
            encoder.encode_header(&mut block, name, value);
        }
        block
    }

    /// The server-wide reservation the body-pending request's decoded headers hold.
    fn body_budget_header_charge() -> u64 {
        u64::from(super::recv::pending_header_charge_of(
            &body_budget_request_block(),
        ))
    }

    fn body_budget_request_wire(end_stream: bool) -> Vec<u8> {
        let mut wire = crate::conn::PREFACE.to_vec();
        frame::write_settings(&mut wire, &[]);
        frame::write_frame(
            &mut wire,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS,
            1,
            &body_budget_request_block(),
        );
        frame::write_frame(
            &mut wire,
            frame::kind::DATA,
            if end_stream {
                frame::flags::END_STREAM
            } else {
                0
            },
            1,
            b"12345678",
        );
        wire
    }

    async fn wait_for_body_budget(budget: &hj_core::budget::BodyBufferBudget, bytes: u64) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while budget.in_flight() != bytes {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("body budget did not reach the expected allocation charge");
    }

    #[tokio::test]
    async fn incomplete_request_budget_is_released_on_connection_teardown() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Both transport drivers use the same receive state/leases. Exercise actual
        // connection exits through the in-memory tokio conformance driver, without
        // binding sockets or sending malformed requests to a running server.
        for exit in [
            "eof",
            "cancel",
            "stream_reset",
            "goaway",
            "protocol_error",
            "idle_timeout",
        ] {
            let headers = body_budget_header_charge();
            let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(16 + headers));
            let (mut client, server) = tokio::io::duplex(16 * 1024);
            let config = Config {
                body_budget: Some(budget.clone()),
                conn_idle_timeout: (exit == "idle_timeout").then_some(Duration::from_millis(20)),
                ..Config::default()
            };
            let task = tokio::spawn(async move {
                serve(
                    server,
                    |_req| async { Response::new(hj_core::Body::Empty) },
                    config,
                    None,
                )
                .await
            });
            client
                .write_all(&body_budget_request_wire(false))
                .await
                .unwrap();
            wait_for_body_budget(&budget, headers + 8).await;

            match exit {
                "eof" => drop(client),
                "goaway" => {
                    // A peer GOAWAY lets the admitted upload finish (#695); the peer
                    // then going away is what tears the connection down.
                    let mut wire = Vec::new();
                    frame::write_goaway(&mut wire, 1, frame::error_code::NO_ERROR);
                    client.write_all(&wire).await.unwrap();
                    drop(client);
                }
                "cancel" => {
                    task.abort();
                    drop(client);
                }
                "stream_reset" => {
                    let mut wire = Vec::new();
                    frame::write_rst_stream(&mut wire, 1, frame::error_code::CANCEL);
                    client.write_all(&wire).await.unwrap();
                    wait_for_body_budget(&budget, 0).await;
                    drop(client);
                }
                _ => {
                    let mut wire = Vec::new();
                    if exit == "protocol_error" {
                        // PING payload must be exactly eight bytes.
                        frame::write_frame(&mut wire, frame::kind::PING, 0, 0, &[0]);
                    }
                    client.write_all(&wire).await.unwrap();
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        client.read_to_end(&mut Vec::new()),
                    )
                    .await
                    .expect("connection teardown must finish")
                    .unwrap();
                    drop(client);
                }
            }
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("connection task must terminate");
            if exit != "cancel" {
                result.unwrap().unwrap();
            }
            assert_eq!(budget.in_flight(), 0, "{exit} leaked a reservation");
            assert!(
                budget.try_acquire(budget.capacity()),
                "an unrelated upload must still fit after {exit}"
            );
            budget.release(budget.capacity());
        }
    }

    #[tokio::test]
    async fn dispatched_body_budget_follows_retained_frames_beyond_connection() {
        use http_body_util::BodyExt;
        use tokio::io::AsyncWriteExt;

        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(
            16 + body_budget_header_charge(),
        ));
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let config = Config {
            body_budget: Some(budget.clone()),
            ..Config::default()
        };
        let task = tokio::spawn(async move {
            serve(
                server,
                move |req| {
                    sender.send(req).unwrap();
                    std::future::ready(Response::new(hj_core::Body::Empty))
                },
                config,
                None,
            )
            .await
        });
        client
            .write_all(&body_budget_request_wire(true))
            .await
            .unwrap();
        let req = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            budget.in_flight(),
            8,
            "dispatch returns the header charge; END_STREAM must not release retained bytes"
        );
        assert!(
            !budget.try_acquire(budget.capacity() - 7),
            "retained handler bodies count against admission"
        );
        task.abort();
        let _ = task.await;
        drop(client);
        assert_eq!(
            budget.in_flight(),
            8,
            "connection drop cannot release a transferred body"
        );

        let bytes = req.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"12345678");
        let tail = bytes.slice(4..);
        drop(bytes);
        assert_eq!(
            budget.in_flight(),
            8,
            "slices retain the complete body allocation"
        );
        drop(tail);
        assert_eq!(budget.in_flight(), 0);
    }

    /// Bytes the transport consumed before routing here become the inbound buffer: a
    /// partial preface is completed from the socket, and bytes past the preface are
    /// framed exactly as if they had arrived on the connection.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_prefix_seeds_the_preface_whole_or_split() {
        use std::io::Write;

        let mut wire = crate::conn::PREFACE.to_vec();
        frame::write_settings(&mut wire, &[]);
        get_headers(&mut Encoder::new(), 1, "/body", &mut wire);
        let preface = crate::conn::PREFACE.len();
        for split in [0, 10, preface, preface + 9, wire.len()] {
            let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = std_listener.local_addr().unwrap();
            std_listener.set_nonblocking(true).unwrap();
            let (prefix, rest) = wire.split_at(split);
            let (prefix, rest) = (prefix.to_vec(), rest.to_vec());
            let client = std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(address).unwrap();
                stream.write_all(&rest).unwrap();
                let mut seen = Vec::new();
                read_frames_until(&mut stream, &mut seen, Duration::from_secs(3), |f| {
                    f.iter().any(|&(kind, flags, sid, _)| {
                        kind == frame::kind::DATA
                            && sid == 1
                            && flags & frame::flags::END_STREAM != 0
                    })
                })
            });
            let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                .enable_timer()
                .build()
                .unwrap();
            let _ = runtime.block_on(async move {
                let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                serve_local_with_prefix(
                    stream,
                    prefix,
                    |_| {
                        std::future::ready(hj_core::text_response(
                            http::StatusCode::OK,
                            "0123456789",
                        ))
                    },
                    Config {
                        conn_idle_timeout: Some(Duration::from_millis(500)),
                        ..Config::default()
                    },
                    None,
                    None,
                )
                .await
            });
            let frames = client.join().unwrap();
            let body: Vec<u8> = frames
                .iter()
                .filter(|&&(kind, _, sid, _)| kind == frame::kind::DATA && sid == 1)
                .flat_map(|(.., payload)| payload.iter().copied())
                .collect();
            assert_eq!(body, b"0123456789", "split at {split}");
        }
    }

    /// Raw frames the server wrote, as `(kind, flags, stream_id, payload)`.
    #[cfg(feature = "monoio")]
    fn read_frames_until(
        stream: &mut std::net::TcpStream,
        seen: &mut Vec<u8>,
        limit: Duration,
        mut done: impl FnMut(&[(u8, u8, u32, Vec<u8>)]) -> bool,
    ) -> Vec<(u8, u8, u32, Vec<u8>)> {
        use std::io::Read;
        stream
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let started = std::time::Instant::now();
        let mut frames = Vec::new();
        let mut buf = [0u8; 16384];
        while started.elapsed() < limit {
            while seen.len() >= 9 {
                let len = (usize::from(seen[0]) << 16)
                    | (usize::from(seen[1]) << 8)
                    | usize::from(seen[2]);
                if seen.len() < 9 + len {
                    break;
                }
                let sid = u32::from_be_bytes([seen[5], seen[6], seen[7], seen[8]]) & 0x7fff_ffff;
                frames.push((seen[3], seen[4], sid, seen[9..9 + len].to_vec()));
                seen.drain(..9 + len);
            }
            if done(&frames) {
                return frames;
            }
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => seen.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        frames
    }

    #[cfg(feature = "monoio")]
    fn get_headers(encoder: &mut Encoder, sid: u32, path: &str, out: &mut Vec<u8>) {
        let mut block = Vec::new();
        for (name, value) in [
            (":method", "GET"),
            (":path", path),
            (":scheme", "https"),
            (":authority", "example.com"),
        ] {
            encoder.encode_header(&mut block, name, value);
        }
        frame::write_frame(
            out,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS | frame::flags::END_STREAM,
            sid,
            &block,
        );
    }

    #[cfg(feature = "monoio")]
    fn serve_one_monoio_connection(std_listener: std::net::TcpListener, config: Config) {
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        let _ = runtime.block_on(async move {
            let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            serve_local_with_prefix(
                stream,
                Vec::new(),
                |req: Request| {
                    use futures_util::future::Either;
                    let body = match req.uri().path() {
                        "/slow" => return Either::Right(std::future::pending()),
                        "/body" => "0123456789",
                        _ => "",
                    };
                    Either::Left(std::future::ready(hj_core::text_response(
                        http::StatusCode::OK,
                        body,
                    )))
                },
                config,
                None,
                None,
            )
            .await
        });
    }

    fn trailer_block_split_wire() -> (Vec<u8>, Vec<u8>) {
        let mut block = Vec::new();
        Encoder::new().encode_header(&mut block, "x-trailer", "split-across-continuation");
        let (first, rest) = block.split_at(block.len() / 2);
        let mut headers = Vec::new();
        frame::write_frame(
            &mut headers,
            frame::kind::HEADERS,
            frame::flags::END_STREAM,
            1,
            first,
        );
        let mut continuation = Vec::new();
        frame::write_frame(
            &mut continuation,
            frame::kind::CONTINUATION,
            frame::flags::END_HEADERS,
            1,
            rest,
        );
        (headers, continuation)
    }

    fn parse_frames(wire: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut rest = wire;
        while let Some(head) = rest.get(..9) {
            let len =
                (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
            let Some(payload) = rest.get(9..9 + len) else {
                break;
            };
            let sid = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            frames.push((head[3], head[4], sid, payload.to_vec()));
            rest = &rest[9 + len..];
        }
        frames
    }

    fn assert_trailer_continuation_survived(frames: &[(u8, u8, u32, Vec<u8>)]) {
        assert!(
            !frames.iter().any(|&(kind, ..)| kind == frame::kind::GOAWAY),
            "a CONTINUATION completing trailers on an expired stream must not tear down the connection"
        );
        assert!(
            frames
                .iter()
                .any(|(kind, _, sid, payload)| *kind == frame::kind::RST_STREAM
                    && *sid == 1
                    && payload.as_slice() == frame::error_code::CANCEL.to_be_bytes()),
            "the expired stream is still reset with CANCEL"
        );
        assert!(
            frames
                .iter()
                .any(|&(kind, _, sid, _)| kind == frame::kind::HEADERS && sid == 3),
            "the next request on the same connection must still be answered"
        );
    }

    /// Regression: the body deadline expiring while a trailer block is open left
    /// the block open on a removed stream, so its CONTINUATION was a connection error.
    #[tokio::test]
    async fn trailer_continuation_after_body_deadline_keeps_the_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let config = Config {
            request_body_timeout: Some(Duration::from_millis(300)),
            ..Config::default()
        };
        let task = tokio::spawn(async move {
            serve(
                server,
                |_req| async { hj_core::text_response(http::StatusCode::OK, "") },
                config,
                None,
            )
            .await
        });
        let (trailer_headers, continuation) = trailer_block_split_wire();
        client
            .write_all(&body_budget_request_wire(false))
            .await
            .unwrap();
        // The deadline arms once the headers are processed, before the trailers.
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.write_all(&trailer_headers).await.unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;

        let mut wire = continuation;
        let mut block = Vec::new();
        let mut encoder = Encoder::new();
        for (name, value) in [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            (":authority", "example.com"),
        ] {
            encoder.encode_header(&mut block, name, value);
        }
        frame::write_frame(
            &mut wire,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS | frame::flags::END_STREAM,
            3,
            &block,
        );
        client.write_all(&wire).await.unwrap();

        let mut seen = Vec::new();
        let mut buf = [0u8; 16384];
        let frames = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let frames = parse_frames(&seen);
                if frames.iter().any(|&(kind, _, sid, _)| {
                    kind == frame::kind::GOAWAY || (kind == frame::kind::HEADERS && sid == 3)
                }) {
                    return frames;
                }
                let n = client.read(&mut buf).await.unwrap();
                if n == 0 {
                    return frames;
                }
                seen.extend_from_slice(&buf[..n]);
            }
        })
        .await
        .expect("server must answer stream 3 or close");
        assert_trailer_continuation_survived(&frames);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_trailer_continuation_after_body_deadline_keeps_the_connection() {
        use std::io::Write;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();

        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            let (trailer_headers, continuation) = trailer_block_split_wire();
            stream.write_all(&body_budget_request_wire(false)).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            stream.write_all(&trailer_headers).unwrap();
            std::thread::sleep(Duration::from_millis(600));
            let mut wire = continuation;
            get_headers(&mut Encoder::new(), 3, "/", &mut wire);
            stream.write_all(&wire).unwrap();
            let mut seen = Vec::new();
            read_frames_until(&mut stream, &mut seen, Duration::from_secs(3), |f| {
                f.iter().any(|&(kind, _, sid, _)| {
                    kind == frame::kind::GOAWAY || (kind == frame::kind::HEADERS && sid == 3)
                })
            })
        });

        serve_one_monoio_connection(
            std_listener,
            Config {
                conn_idle_timeout: Some(Duration::from_secs(2)),
                request_body_timeout: Some(Duration::from_millis(300)),
                ..Config::default()
            },
        );
        assert_trailer_continuation_survived(&client.join().unwrap());
    }

    /// Regression: the monoio loop closed with the peer's in-flight WINDOW_UPDATEs
    /// unread, so the kernel answered the close with a RST that discarded the
    /// unsent tail of the final response.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_close_drains_unread_input_before_dropping_socket() {
        use std::io::{Read, Write};

        const BODY: usize = 16 * 1024 * 1024;
        const WINDOW: u32 = 8 * 1024 * 1024;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let socket = rustix::net::socket(
                rustix::net::AddressFamily::INET,
                rustix::net::SocketType::STREAM,
                None,
            )
            .unwrap();
            rustix::net::sockopt::set_socket_recv_buffer_size(&socket, 64 * 1024).unwrap();
            rustix::net::connect(&socket, &address).unwrap();
            let mut stream = std::net::TcpStream::from(socket);
            let mut wire = crate::conn::PREFACE.to_vec();
            frame::write_settings(&mut wire, &[(frame::settings::INITIAL_WINDOW_SIZE, WINDOW)]);
            frame::write_window_update(&mut wire, 0, WINDOW - 65_535);
            get_headers(&mut Encoder::new(), 1, "/big", &mut wire);
            frame::write_goaway(&mut wire, 0, frame::error_code::NO_ERROR);
            stream.write_all(&wire).unwrap();

            let mut seen = Vec::new();
            let mut buf = vec![0u8; 64 * 1024];
            let (mut cursor, mut unacked, mut data, mut end_stream) =
                (0usize, 0usize, 0usize, false);
            let outcome = loop {
                std::thread::sleep(Duration::from_micros(300));
                match stream.read(&mut buf) {
                    Ok(0) => break "eof".to_string(),
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                    Err(e) => break e.to_string(),
                }
                for (kind, flags, _, payload) in parse_frames(&seen[cursor..]) {
                    cursor += 9 + payload.len();
                    if kind == frame::kind::DATA {
                        data += payload.len();
                        unacked += payload.len();
                        end_stream |= flags & frame::flags::END_STREAM != 0;
                    }
                }
                if unacked >= 1 << 20 && !end_stream {
                    let mut wire = Vec::new();
                    frame::write_window_update(&mut wire, 0, unacked as u32);
                    frame::write_window_update(&mut wire, 1, unacked as u32);
                    unacked = 0;
                    let _ = stream.write_all(&wire);
                }
            };
            (data, end_stream, outcome)
        });

        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        let _ = runtime.block_on(async move {
            let (stream, _) = std_listener.accept().unwrap();
            rustix::net::sockopt::set_socket_send_buffer_size(&stream, 256 * 1024).unwrap();
            stream.set_nonblocking(true).unwrap();
            let stream = monoio::net::TcpStream::from_std(stream).unwrap();
            let body = Bytes::from(vec![b'a'; BODY]);
            serve_local(
                stream,
                move |_req: Request| {
                    std::future::ready(Response::new(hj_core::Body::Full(body.clone())))
                },
                Config::default(),
            )
            .await
        });
        // Keep the ring alive so the deferred close is actually submitted.
        runtime.block_on(async { monoio::time::sleep(Duration::from_millis(300)).await });
        let (data, end_stream, outcome) = client.join().unwrap();
        assert_eq!(
            (data, end_stream, outcome.as_str()),
            (BODY, true, "eof"),
            "the final response must arrive whole and end in an orderly close"
        );
    }

    /// Regression: a stream the body deadline reset must be recorded like every other
    /// server RST. Otherwise the client's trailers racing our RST_STREAM look like
    /// §5.1.1 stream-id reuse and GOAWAY every stream on the connection.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_trailers_after_body_deadline_reset_keep_the_connection() {
        use std::io::Write;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();

        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream.write_all(&body_budget_request_wire(false)).unwrap();
            let mut seen = Vec::new();
            let frames = read_frames_until(&mut stream, &mut seen, Duration::from_secs(3), |f| {
                f.iter()
                    .any(|&(kind, _, sid, _)| kind == frame::kind::RST_STREAM && sid == 1)
            });
            assert!(
                frames
                    .iter()
                    .any(|&(kind, _, sid, _)| kind == frame::kind::RST_STREAM && sid == 1),
                "the body deadline must reset stream 1"
            );

            // Trailers for the reset stream, then a fresh request on stream 3.
            let mut wire = Vec::new();
            let mut trailer_block = Vec::new();
            let mut trailer_encoder = Encoder::new();
            trailer_encoder.encode_header(&mut trailer_block, "x-trailer", "1");
            frame::write_frame(
                &mut wire,
                frame::kind::HEADERS,
                frame::flags::END_HEADERS | frame::flags::END_STREAM,
                1,
                &trailer_block,
            );
            let mut encoder = Encoder::new();
            get_headers(&mut encoder, 3, "/", &mut wire);
            stream.write_all(&wire).unwrap();
            let frames = read_frames_until(&mut stream, &mut seen, Duration::from_secs(3), |f| {
                f.iter().any(|&(kind, _, sid, _)| {
                    kind == frame::kind::GOAWAY || (kind == frame::kind::HEADERS && sid == 3)
                })
            });
            frames
        });

        serve_one_monoio_connection(
            std_listener,
            Config {
                conn_idle_timeout: Some(Duration::from_secs(2)),
                request_body_timeout: Some(Duration::from_millis(100)),
                ..Config::default()
            },
        );

        let frames = client.join().unwrap();
        assert!(
            !frames.iter().any(|&(kind, ..)| kind == frame::kind::GOAWAY),
            "late trailers on a stream we reset must not tear down the connection"
        );
        assert!(
            frames
                .iter()
                .any(|&(kind, _, sid, _)| kind == frame::kind::HEADERS && sid == 3),
            "the next request on the same connection must still be answered"
        );
    }

    /// The production loop: one cheap completed request per cancelled dispatched one must
    /// not keep paying the rapid-reset budget back.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_cheap_completions_do_not_refund_the_rapid_reset_budget() {
        use std::io::Write;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();

        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            let mut wire = crate::conn::PREFACE.to_vec();
            frame::write_settings(&mut wire, &[]);
            stream.write_all(&wire).unwrap();
            let mut encoder = Encoder::new();
            let mut seen = Vec::new();
            for pair in 0..1000u32 {
                let (fast, slow) = (1 + 4 * pair, 3 + 4 * pair);
                let mut wire = Vec::new();
                get_headers(&mut encoder, fast, "/", &mut wire);
                get_headers(&mut encoder, slow, "/slow", &mut wire);
                frame::write_rst_stream(&mut wire, slow, error_code::CANCEL);
                stream.write_all(&wire).unwrap();
                let frames =
                    read_frames_until(&mut stream, &mut seen, Duration::from_secs(3), |f| {
                        f.iter().any(|&(kind, _, sid, _)| {
                            kind == frame::kind::GOAWAY
                                || (kind == frame::kind::HEADERS && sid == fast)
                        })
                    });
                if let Some((.., payload)) = frames
                    .iter()
                    .find(|&&(kind, ..)| kind == frame::kind::GOAWAY)
                {
                    let code = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                    return Some((pair, code));
                }
                assert!(
                    frames
                        .iter()
                        .any(|&(kind, _, sid, _)| kind == frame::kind::HEADERS && sid == fast),
                    "pair {pair}: the cheap request must be answered"
                );
            }
            None
        });

        let goaways_before = rapid_reset_goaways();
        serve_one_monoio_connection(std_listener, Config::default());

        let (pairs, code) = client
            .join()
            .unwrap()
            .expect("1:1 cancel:complete pairs never exhausted the reset budget");
        assert_eq!(code, error_code::ENHANCE_YOUR_CALM);
        assert!(rapid_reset_goaways() > goaways_before);
        assert!(
            (190..=300).contains(&pairs),
            "cut off after {pairs} pairs; the burst is 200 plus slow refill"
        );
    }

    /// Regression: WINDOW_UPDATEs for streams whose responses already finished used to be
    /// parked as "pre-response credit" forever. Once 4096 had accumulated on a long-lived
    /// connection, real pre-response credit was dropped and a response that needed it
    /// stalled. The peer here advertises a zero initial window, so the final response body
    /// can only flow on the credit granted before the response begins.
    #[cfg(feature = "monoio")]
    #[test]
    fn monoio_finished_stream_credit_does_not_starve_new_streams() {
        use std::io::Write;

        const BATCH: u32 = 128;
        const WARMUP_STREAMS: u32 = 4096;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();

        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            let mut encoder = Encoder::new();
            let mut wire = crate::conn::PREFACE.to_vec();
            frame::write_settings(&mut wire, &[(frame::settings::INITIAL_WINDOW_SIZE, 0)]);
            stream.write_all(&wire).unwrap();

            let mut seen = Vec::new();
            let mut next_sid = 1u32;
            let mut finished = 0u32;
            while finished < WARMUP_STREAMS {
                let first = next_sid;
                let mut wire = Vec::new();
                for _ in 0..BATCH {
                    get_headers(&mut encoder, next_sid, "/", &mut wire);
                    next_sid += 2;
                }
                stream.write_all(&wire).unwrap();
                let last = next_sid - 2;
                let frames =
                    read_frames_until(&mut stream, &mut seen, Duration::from_secs(10), |f| {
                        f.iter().any(|&(kind, flags, sid, _)| {
                            kind == frame::kind::HEADERS
                                && sid == last
                                && flags & frame::flags::END_STREAM != 0
                        })
                    });
                assert!(
                    !frames.iter().any(|&(kind, ..)| kind == frame::kind::GOAWAY),
                    "warm-up must not trip a connection error"
                );
                // Credit for every stream that just finished — the grants that leaked.
                let mut wire = Vec::new();
                let mut sid = first;
                while sid <= last {
                    frame::write_window_update(&mut wire, sid, 1);
                    sid += 2;
                }
                stream.write_all(&wire).unwrap();
                finished += BATCH;
            }

            let body_sid = next_sid;
            let mut wire = Vec::new();
            get_headers(&mut encoder, body_sid, "/body", &mut wire);
            frame::write_window_update(&mut wire, body_sid, 10);
            stream.write_all(&wire).unwrap();
            let frames = read_frames_until(&mut stream, &mut seen, Duration::from_secs(3), |f| {
                f.iter().any(|&(kind, flags, sid, _)| {
                    kind == frame::kind::DATA
                        && sid == body_sid
                        && flags & frame::flags::END_STREAM != 0
                })
            });
            (frames, body_sid)
        });

        serve_one_monoio_connection(
            std_listener,
            Config {
                conn_idle_timeout: Some(Duration::from_secs(5)),
                ..Config::default()
            },
        );

        let (frames, body_sid) = client.join().unwrap();
        let body: Vec<u8> = frames
            .iter()
            .filter(|&&(kind, _, sid, _)| kind == frame::kind::DATA && sid == body_sid)
            .flat_map(|(_, _, _, payload)| payload.iter().copied())
            .collect();
        assert_eq!(
            body, b"0123456789",
            "pre-response credit must reach the new stream despite earlier late grants"
        );
    }
}

#[cfg(test)]
mod pacer_tests {
    use super::*;

    #[test]
    fn out_queue_total_bytes_covers_inline_and_body_segments() {
        let mut q = OutQueue::default();
        q.frames(|f| f.extend_from_slice(b"1234"));
        q.body(bytes::Bytes::from_static(b"abcdef"));
        assert_eq!(q.total_bytes(), 10, "inline + body segment lengths");
        assert!(!q.is_empty());
        assert_eq!(OutQueue::default().total_bytes(), 0);
    }

    #[test]
    fn h2_config_pacing_defaults_off() {
        assert_eq!(Config::default().bandwidth_limit, 0);
    }
}

#[cfg(all(test, feature = "monoio"))]
mod peer_goaway_monoio_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    const BODY_LEN: usize = 100_000;

    fn get(enc: &mut Encoder, wire: &mut Vec<u8>, sid: u32) {
        let mut block = Vec::new();
        enc.encode_header(&mut block, ":method", "GET");
        enc.encode_header(&mut block, ":path", "/");
        enc.encode_header(&mut block, ":scheme", "https");
        enc.encode_header(&mut block, ":authority", "example.com");
        frame::write_frame(
            wire,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS | frame::flags::END_STREAM,
            sid,
            &block,
        );
    }

    /// Returns (body bytes on stream 1, END_STREAM seen, streams refused, server closed).
    fn run(credit_with_goaway: bool, extra_stream: bool) -> (usize, bool, Vec<u32>, bool) {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                .enable_timer()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                serve_local_with_prefix(
                    stream,
                    Vec::new(),
                    |_| {
                        std::future::ready(Response::new(hj_core::Body::Full(Bytes::from(
                            vec![b'x'; BODY_LEN],
                        ))))
                    },
                    Config::default(),
                    None,
                    None,
                )
                .await
            })
        });

        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut enc = Encoder::new();
        let mut wire = crate::conn::PREFACE.to_vec();
        frame::write_settings(&mut wire, &[(settings::INITIAL_WINDOW_SIZE, 16384)]);
        get(&mut enc, &mut wire, 1);
        frame::write_goaway(&mut wire, 0, error_code::NO_ERROR);
        if credit_with_goaway {
            frame::write_window_update(&mut wire, 1, 1_000_000);
            frame::write_window_update(&mut wire, 0, 1_000_000);
        }
        if extra_stream {
            get(&mut enc, &mut wire, 3);
        }
        stream.write_all(&wire).unwrap();

        let (mut seen, mut at) = (Vec::new(), 0usize);
        let (mut body, mut ended, mut refused, mut closed) = (0usize, false, Vec::new(), false);
        let mut granted = credit_with_goaway;
        let started = Instant::now();
        let mut buf = [0u8; 16384];
        while started.elapsed() < Duration::from_secs(3) {
            match stream.read(&mut buf) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => seen.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
            while let Some(h) = seen.get(at..at + 9) {
                let hdr = FrameHeader::parse(h).unwrap();
                let Some(p) = seen.get(at + 9..at + 9 + hdr.length as usize) else {
                    break;
                };
                match hdr.kind {
                    frame::kind::DATA if hdr.stream_id == 1 => {
                        body += p.len();
                        ended |= hdr.flags & frame::flags::END_STREAM != 0;
                    }
                    frame::kind::RST_STREAM
                        if u32::from_be_bytes(p[..4].try_into().unwrap())
                            == error_code::REFUSED_STREAM =>
                    {
                        refused.push(hdr.stream_id);
                    }
                    _ => {}
                }
                at += 9 + hdr.length as usize;
            }
            if !granted && body >= 16384 {
                granted = true;
                let mut w = Vec::new();
                frame::write_window_update(&mut w, 1, 1_000_000);
                frame::write_window_update(&mut w, 0, 1_000_000);
                stream.write_all(&w).unwrap();
            }
        }
        drop(stream);
        server.join().unwrap().unwrap();
        (body, ended, refused, closed)
    }

    #[test]
    fn monoio_peer_goaway_keeps_reading_window_updates() {
        let (body, ended, _, closed) = run(false, false);
        assert!(ended && body == BODY_LEN, "truncated: {body}/{BODY_LEN}");
        assert!(closed, "server closes once the drained response completes");
    }

    #[test]
    fn monoio_peer_goaway_with_window_update_in_same_write() {
        let (body, ended, _, closed) = run(true, false);
        assert!(ended && body == BODY_LEN, "truncated: {body}/{BODY_LEN}");
        assert!(closed);
    }

    #[test]
    fn monoio_peer_goaway_refuses_later_streams() {
        let (body, ended, refused, closed) = run(false, true);
        assert!(ended && body == BODY_LEN, "truncated: {body}/{BODY_LEN}");
        assert_eq!(refused, vec![3]);
        assert!(closed);
    }
}
