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

pub use send::set_io_handle;

use std::collections::VecDeque;
use std::future::Future;
// FxHashMap/FxHashSet (rustc-hash): the per-connection stream maps are keyed by u32 stream IDs,
// where SipHash's DoS resistance is pure overhead. Internal/trusted keys only.
use rustc_hash::{FxHashMap, FxHashSet};

use crate::hpack::{Decoder, Encoder};
use bytes::Bytes;
use futures_util::future::{AbortHandle, Abortable};
use hj_core::{Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::frame::{self, FrameHeader, error_code, settings};
use recv::{FrameOutcome, process_frame};
use send::{Pulls, apply_pull, begin_response, cancel_outstream, pump_streams};
use state::{OutStream, PeerSettings, Recv, StreamState};

use std::sync::atomic::{AtomicUsize, Ordering};

/// Number of HTTP/2 connections currently being served in this process (one h2 server per
/// process). Maintained by [`ConnGuard`] around each [`serve`] call; read by [`spare_cores`].
static ACTIVE_H2_CONNS: AtomicUsize = AtomicUsize::new(0);

const H2_INBUF_IDLE: usize = 8 * 1024;
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
    /// buffers the whole request body before dispatch, so an over-cap stream is RST'd
    /// (REFUSED_STREAM). The per-connection aggregate is bounded at `4 ×` this value.
    pub max_request_body: usize,
    /// Server-wide buffered-body budget shared with the other transports (#236 residual).
    /// `None` (default) skips global accounting — per-stream/per-connection caps still apply.
    pub body_budget: Option<std::sync::Arc<hj_core::budget::BodyBufferBudget>>,
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
            conn_idle_timeout: Some(std::time::Duration::from_secs(60)),
            preface_timeout: None,
        }
    }
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
    /// only add a cross-thread hop).
    Inline(F),
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
        // SAFETY: structural pin projection. `self` is never moved out of; the `Inline`
        // future is re-pinned in place, and the `Spawned` handle is `Unpin`. This enum has
        // no Drop impl, so no destructor observes a moved pinned field.
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            TaggedInner::Inline(f) => unsafe { std::pin::Pin::new_unchecked(f) }
                .poll(cx)
                .map(|resp| resp),
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
    match config.preface_timeout.or(config.conn_idle_timeout) {
        Some(d) => match tokio::time::timeout(d, read_preface(&mut reader)).await {
            Ok(r) => r?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP/2 connection preface not received before idle timeout",
                ));
            }
        },
        None => read_preface(&mut reader).await?,
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
        last_client_stream: 0,
        open_header_block: None,
        discarding_header_block: false,
        discard_header_block: Vec::new(),
        discard_rst_code: error_code::STREAM_CLOSED,
        max_concurrent: config.max_concurrent_streams as usize,
        // The connection receive window we advertise = the level grown to above (the §6.9.2
        // default 65535, raised to initial_window_size via the stream-0 WINDOW_UPDATE sent above).
        conn_recv_window: (config.initial_window_size.max(65535)) as i64,
        our_initial_window: config.initial_window_size as i64,
        rst_unanswered: 0,
        total_buffered: 0,
        max_request_body: config.max_request_body,
        per_conn_request_body: config.max_request_body.saturating_mul(4),
        body_budget: config.body_budget.clone(),
        no_progress_frames: 0,
    };
    // Pre-size the per-stream maps to the multiplex degree we advertise (capped, so a large
    // MAX_CONCURRENT_STREAMS can't pre-allocate an oversized table) — avoids the handful of
    // table-growth reallocations as the first streams of a busy CF connection arrive. Bounded
    // by max_concurrent_streams either way, so this only moves the growth earlier, never higher.
    let stream_cap = (config.max_concurrent_streams as usize).min(32);
    let mut streams: FxHashMap<u32, StreamState> =
        FxHashMap::with_capacity_and_hasher(stream_cap, Default::default());
    let mut inflight: Inflight<F> = Inflight::new();
    // Outgoing response bodies still being written, plus their async chunk pulls and the
    // connection-level send window (RFC 7540 §6.9, default 65535 until the peer grows it).
    let mut outstreams: FxHashMap<u32, OutStream> =
        FxHashMap::with_capacity_and_hasher(stream_cap, Default::default());
    let mut send_schedule = VecDeque::with_capacity(stream_cap);
    let mut pulls: Pulls = Pulls::new();
    let mut send_conn: i64 = 65535;
    // Per-stream send-window credit that arrived (WINDOW_UPDATE) before the response was
    // generated — clients optimistically grant window right after HEADERS, well before a
    // slow handler (LSAPI render) produces the body. Held here and folded into the stream's
    // window when `begin_response` creates it; without this a streamed body stalls at the
    // 65535 initial window. Consumed/cleared in `begin_response` and on RST.
    let mut pending_window: FxHashMap<u32, i64> =
        FxHashMap::with_capacity_and_hasher(stream_cap, Default::default());
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
    let cap = config.max_frame_size.min(1 << 24);

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
        while inbuf.len() - cursor >= FrameHeader::LEN {
            // The loop guard guarantees 9 bytes, so parse always succeeds; fail closed with
            // a GOAWAY rather than panicking the connection task if that ever breaks.
            let Some(hdr) = FrameHeader::parse(&inbuf[cursor..]) else {
                out.frames(|b| frame::write_goaway(b, 0, error_code::PROTOCOL_ERROR));
                reading = false;
                accepting = false;
                draining = false;
                break;
            };
            if hdr.length > cap {
                out.frames(|b| frame::write_goaway(b, 0, error_code::FRAME_SIZE_ERROR));
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
            match process_frame(
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
            ) {
                FrameOutcome::Continue => {}
                FrameOutcome::StopReading => {
                    reading = false;
                    accepting = false;
                    draining = false;
                    break;
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
                        out.frames(|b| frame::write_goaway(b, 0, error_code::FLOW_CONTROL_ERROR));
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
                        if pending_window.len() < 4096 || pending_window.contains_key(&stream_id) {
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
                                // The server just reset this stream, so stop any backend work
                                // immediately. `Abortable` yields no response when it drains.
                                if let Some(abort) = inflight_sids.remove(&stream_id) {
                                    abort.abort();
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
                        out.frames(|b| frame::write_goaway(b, 0, error_code::FLOW_CONTROL_ERROR));
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
            recv.rst_unanswered = recv.rst_unanswered.saturating_sub(1); // a stream completed → earn back reset budget
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
        ) {
            break;
        }

        tokio::select! {
            biased;
            // A handler completed: begin its response (the rest batch at the next loop top),
            // unless the peer reset the stream while the handler was still running.
            Some((sid, is_head, resp)) = inflight.next(), if !inflight.is_empty() => {
                inflight_sids.remove(&sid);
                if let Some(resp) = resp && !cancelled.remove(&sid) {
                    recv.rst_unanswered = recv.rst_unanswered.saturating_sub(1); // a stream completed → earn back reset budget
                    begin_response(sid, is_head, resp, &mut enc, &mut out, &mut outstreams, &mut send_schedule, &mut pending_window, &peer, &mut block_scratch);
                } else {
                    cancelled.remove(&sid);
                }
            }
            // A streaming body produced a chunk (or ended): buffer it for the next pump.
            Some((sid, body, res)) = pulls.next(), if !pulls.is_empty() => {
                apply_pull(sid, body, res, &mut outstreams, &mut out);
            }
            // (OPS2) Graceful drain: on the shutdown signal, send GOAWAY and stop accepting
            // new streams. Keep reading frames so existing response bodies can receive flow
            // control credit and finish instead of being truncated at the initial window.
            _ = async {
                match &shutdown {
                    Some(t) => t.cancelled().await,
                    None => std::future::pending::<()>().await,
                }
            }, if reading && accepting => {
                out.frames(|b| frame::write_goaway(b, recv.last_client_stream, error_code::NO_ERROR));
                accepting = false;
                draining = true;
                drain.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_secs(12));
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
            // (HTTP/2-Bomb hardening) The connection went idle — no frame for `conn_idle_timeout`.
            // GOAWAY gracefully and stop reading; the loop then drains any in-flight work and
            // closes, freeing streams a silent peer held open. Lowest-priority (biased) so real
            // work always preempts it; gated on a configured timeout and `if reading` so it fires
            // at most once.
            _ = &mut idle, if reading && idle_timeout.is_some() => {
                out.frames(|b| frame::write_goaway(b, recv.last_client_stream, error_code::NO_ERROR));
                reading = false;
                accepting = false;
                draining = false;
            }
            _ = &mut drain, if reading && draining => {
                reading = false;
                accepting = false;
                draining = false;
            }
        }
    }

    flush(&mut writer, &mut out).await?;
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
) -> bool {
    if !reading && inflight_empty && pulls_empty {
        return true;
    }
    if draining && inflight_empty && pulls_empty && outstreams_empty {
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
}

impl OutQueue {
    #[inline]
    fn is_empty(&self) -> bool {
        self.segs.is_empty()
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
#[cfg(feature = "monoio")]
async fn monoio_flush<IO: monoio::io::AsyncWriteRent>(
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
    IO: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Split + 'static,
    S: Fn(Request) -> F,
    F: Future<Output = Response> + Send + 'static,
{
    serve_local_with_prefix(stream, Vec::new(), service, config, None, None).await
}

#[cfg(feature = "monoio")]
fn monoio_read_once<IO>(
    mut reader: monoio::io::OwnedReadHalf<IO>,
    buffer: Vec<u8>,
) -> impl Future<
    Output = (
        std::io::Result<usize>,
        Vec<u8>,
        monoio::io::OwnedReadHalf<IO>,
    ),
>
where
    IO: monoio::io::AsyncReadRent,
{
    use monoio::io::AsyncReadRent;
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
    IO: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Split + 'static,
    S: Fn(Request) -> F,
    F: Future<Output = Response> + Send + 'static,
{
    use futures_util::stream::StreamExt;
    use monoio::io::{AsyncReadRent, AsyncWriteRent, Splitable};

    let _conn_guard = ConnGuard::new();

    // Split into owned read/write halves so the step-5 read future can persist
    // ACROSS select! iterations (a handler completing must NOT cancel an in-flight
    // read — some monoio stream wrappers, e.g. monoio-rustls's SafeRead, lose their
    // buffer when a read future is dropped mid-flight). The write half flushes
    // independently, so there is no &mut aliasing between the persistent read and
    // the flush. Both monoio TcpStream and the monoio-rustls TLS stream are `Split`.
    let (mut rh, mut wh) = stream.into_split();

    // Client connection preface (24 bytes). Seeded with any pre-read prefix.
    let mut inbuf: Vec<u8> = Vec::with_capacity(H2_INBUF_IDLE.max(prefix.len()));
    inbuf.extend_from_slice(&prefix);
    // Bound the preface read so a peer that completes the TCP/TLS handshake then stalls
    // cannot pin this connection task forever (the monoio path otherwise had no deadline,
    // unlike the tokio `serve`). On timeout we close, so cancelling the in-flight read is
    // harmless (the stream is never reused).
    let preface_deadline = config
        .preface_timeout
        .or(config.conn_idle_timeout)
        .map(|duration| monoio::time::Instant::now() + duration);
    let mut preface_buffer = vec![0u8; 4096];
    while inbuf.len() < crate::conn::PREFACE.len() {
        let (res, b) = match preface_deadline {
            Some(deadline) => monoio::select! {
                rb = rh.read(preface_buffer) => rb,
                _ = monoio::time::sleep_until(deadline) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "h2 preface timeout"));
                }
            },
            None => rh.read(preface_buffer).await,
        };
        let n = res?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        inbuf.extend_from_slice(&b[..n]);
        preface_buffer = b;
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
    monoio_flush(&mut wh, &mut out, ktls_fd).await?;

    let mut dec = Decoder::new(
        config.header_table_size as usize,
        config.header_list_size as usize,
    );
    let mut enc = Encoder::new();
    let mut peer = PeerSettings::default();
    let mut recv = Recv {
        last_client_stream: 0,
        open_header_block: None,
        discarding_header_block: false,
        discard_header_block: Vec::new(),
        discard_rst_code: error_code::STREAM_CLOSED,
        max_concurrent: config.max_concurrent_streams as usize,
        conn_recv_window: (config.initial_window_size.max(65535)) as i64,
        our_initial_window: config.initial_window_size as i64,
        rst_unanswered: 0,
        total_buffered: 0,
        max_request_body: config.max_request_body,
        per_conn_request_body: config.max_request_body.saturating_mul(4),
        body_budget: config.body_budget.clone(),
        no_progress_frames: 0,
    };
    let stream_cap = (config.max_concurrent_streams as usize).min(32);
    let mut streams: FxHashMap<u32, StreamState> =
        FxHashMap::with_capacity_and_hasher(stream_cap, Default::default());
    let mut inflight: Inflight<F> = Inflight::new();
    let mut outstreams: FxHashMap<u32, OutStream> =
        FxHashMap::with_capacity_and_hasher(stream_cap, Default::default());
    let mut send_schedule = VecDeque::with_capacity(stream_cap);
    let mut pulls: Pulls = Pulls::new();
    let mut send_conn: i64 = 65535;
    let mut pending_window: FxHashMap<u32, i64> =
        FxHashMap::with_capacity_and_hasher(stream_cap, Default::default());
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
    let cap = config.max_frame_size.min(1 << 24);

    // The read future stays pinned across select iterations because cancelling a monoio-rustls
    // read can lose its owned buffer. The box is allocated once; after a completed read,
    // `Pin::set` replaces the future in place with the same concrete future type and hands its
    // returned Vec straight into the next read.
    let mut read_fut = Box::pin(monoio_read_once(rh, vec![0u8; H2_READ_CHUNK]));

    loop {
        // 1) Process every complete buffered frame (mirrors serve()).
        while inbuf.len() - cursor >= FrameHeader::LEN {
            let Some(hdr) = FrameHeader::parse(&inbuf[cursor..]) else {
                out.frames(|b| frame::write_goaway(b, 0, error_code::PROTOCOL_ERROR));
                reading = false;
                accepting = false;
                break;
            };
            if hdr.length > cap {
                out.frames(|b| frame::write_goaway(b, 0, error_code::FRAME_SIZE_ERROR));
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
            match process_frame(
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
            ) {
                FrameOutcome::Continue => {}
                FrameOutcome::StopReading => {
                    reading = false;
                    accepting = false;
                    break;
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
                        out.frames(|b| frame::write_goaway(b, 0, error_code::FLOW_CONTROL_ERROR));
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
                    } else if pending_window.len() < 4096 || pending_window.contains_key(&stream_id)
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
                            if let Some(abort) = inflight_sids.remove(&stream_id) {
                                abort.abort();
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
                        out.frames(|b| frame::write_goaway(b, 0, error_code::FLOW_CONTROL_ERROR));
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
            recv.rst_unanswered = recv.rst_unanswered.saturating_sub(1); // a stream completed → earn back reset budget
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

        // 3) Flush queued output.
        monoio_flush(&mut wh, &mut out, ktls_fd).await?;

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
        let mut read_done: Option<(
            std::io::Result<usize>,
            Vec<u8>,
            monoio::io::OwnedReadHalf<IO>,
        )> = None;
        monoio::select! {
            biased;
            rb = read_fut.as_mut(), if reading => { read_done = Some(rb); }
            Some((sid, is_head, resp)) = inflight.next(), if !inflight.is_empty() => {
                inflight_sids.remove(&sid);
                if let Some(resp) = resp && !cancelled.remove(&sid) {
                    recv.rst_unanswered = recv.rst_unanswered.saturating_sub(1); // a stream completed → earn back reset budget
                    begin_response(sid, is_head, resp, &mut enc, &mut out, &mut outstreams, &mut send_schedule, &mut pending_window, &peer, &mut block_scratch);
                } else {
                    cancelled.remove(&sid);
                }
            }
            Some((sid, body, res)) = pulls.next(), if !pulls.is_empty() => {
                apply_pull(sid, body, res, &mut outstreams, &mut out);
            }
            _ = async { match &shutdown { Some(t) => t.cancelled().await, None => std::future::pending::<()>().await } }, if reading && accepting => {
                out.frames(|b| frame::write_goaway(b, recv.last_client_stream, error_code::NO_ERROR));
                accepting = false;
                draining = true;
            }
            // Idle bound: no inbound frame within `conn_idle_timeout`. The sleep is
            // recreated each iteration, so it measures time since the last event. First
            // fire GOAWAY + drain (let in-flight responses finish); a second idle while
            // already draining forces the close — bounds a post-handshake slowloris that
            // the monoio path otherwise never timed out (the tokio `serve` does this).
            _ = async { match config.conn_idle_timeout { Some(d) => monoio::time::sleep(d).await, None => std::future::pending::<()>().await } }, if reading => {
                if accepting {
                    out.frames(|b| frame::write_goaway(b, recv.last_client_stream, error_code::NO_ERROR));
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
                    reading = false;
                    accepting = false;
                }
                Ok(n) => inbuf.extend_from_slice(&b[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    reading = false;
                    accepting = false;
                }
                Err(e) => return Err(e),
            }
            if reading {
                read_fut.as_mut().set(monoio_read_once(reader, b));
            }
        }
    }

    monoio_flush(&mut wh, &mut out, ktls_fd).await?;
    let _ = AsyncWriteRent::shutdown(&mut wh).await;
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

    /// Regression for the monoio-loop in-flight abandonment bug: once reads stop, the loop
    /// must keep running while `inflight` or `pulls` is non-empty so a slow handler's
    /// response is still delivered to a client that half-closed / GOAWAYed mid-request.
    /// The old monoio path had an unconditional `if !reading { break }` that closed first.
    #[test]
    fn should_close_drains_inflight_after_reads_stop() {
        // reading stopped, a handler still running -> must NOT close (the bug).
        assert!(!should_close(
            false, false, /*inflight*/ false, /*pulls*/ true, true
        ));
        // reading stopped, a streaming body still producing -> must NOT close.
        assert!(!should_close(
            false, false, true, /*pulls*/ false, true
        ));
        // reading stopped, nothing left to produce -> close (window-blocked outstreams
        // can't advance without reads, so they are intentionally ignored).
        assert!(should_close(
            false, false, true, true, /*outstreams*/ false
        ));
        assert!(should_close(false, false, true, true, true));
        // still reading -> never close here (the select drives the next read).
        assert!(!should_close(true, false, true, true, true));
        // graceful drain keeps reading, so it only closes once EVERYTHING (incl.
        // outstreams) has drained.
        assert!(!should_close(
            true, true, true, true, /*outstreams*/ false
        ));
        assert!(should_close(true, true, true, true, true));
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
            last_client_stream,
            open_header_block: None,
            discarding_header_block: false,
            discard_header_block: Vec::new(),
            discard_rst_code: error_code::STREAM_CLOSED,
            max_concurrent: 100,
            conn_recv_window: 65535,
            our_initial_window: 65535,
            rst_unanswered: 0,
            total_buffered: 0,
            max_request_body: 1 << 20,
            per_conn_request_body: 4 << 20,
            body_budget: None,
            no_progress_frames: 0,
        }
    }

    fn request_block_referencing_first_dynamic_entry() -> Vec<u8> {
        vec![0x82, 0x87, 0x84, 0xbe]
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
            last_client_stream: 1,
            open_header_block: None,
            discarding_header_block: false,
            discard_header_block: Vec::new(),
            discard_rst_code: error_code::STREAM_CLOSED,
            max_concurrent: 100,
            conn_recv_window: 65535,
            our_initial_window: 65535,
            rst_unanswered: 0,
            total_buffered: body_len,
            max_request_body: 1 << 20,
            per_conn_request_body: 4 << 20,
            body_budget: None,
            no_progress_frames: 0,
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

    #[test]
    fn data_frame_respects_server_wide_body_budget() {
        // (#236 residual) The per-stream and per-connection caps leave the SERVER-WIDE
        // aggregate unbounded; the shared budget must refuse a reservation once exhausted
        // (GOAWAY ENHANCE_YOUR_CALM) and release exactly what was buffered when a stream
        // un-buffers, so the H1/H2/H3/LSAPI layers share one honest ledger.
        let budget = std::sync::Arc::new(hj_core::budget::BodyBufferBudget::new(16));
        use super::recv::process_frame;
        use crate::frame::{flags, kind};
        let mut streams: FxHashMap<u32, StreamState> = FxHashMap::default();
        streams.insert(
            1,
            StreamState {
                headers_done: true,
                body: vec![0u8; 8],
                recv_window: 65535,
                ..Default::default()
            },
        );
        let mut dec = Decoder::new(4096, 8192);
        let mut enc = Encoder::new();
        let mut out = OutQueue::default();
        let mut peer = PeerSettings::default();
        let mut recv = Recv {
            last_client_stream: 1,
            open_header_block: None,
            discarding_header_block: false,
            discard_header_block: Vec::new(),
            discard_rst_code: error_code::STREAM_CLOSED,
            max_concurrent: 100,
            conn_recv_window: 65535,
            our_initial_window: 65535,
            rst_unanswered: 0,
            total_buffered: 8,
            max_request_body: 1 << 20,
            per_conn_request_body: 4 << 20,
            body_budget: Some(budget.clone()),
            no_progress_frames: 0,
        };
        let mut inflight: Inflight<std::future::Ready<Response>> = Inflight::new();
        let mut cancelled: FxHashSet<u32> = FxHashSet::default();
        let mut inflight_sids: FxHashMap<u32, AbortHandle> = FxHashMap::default();
        let service = |_req: Request| std::future::ready(Response::new(hj_core::Body::Empty));
        // The stream's already-buffered 8 bytes were reserved before the test (as the
        // connection would have); reflect that on the ledger.
        assert!(budget.try_acquire(8));

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
        assert!(
            matches!(outcome, FrameOutcome::StopReading),
            "exhausting the server-wide budget must GOAWAY the connection"
        );
        assert_eq!(
            budget.in_flight(),
            8,
            "the refused reservation must not have mutated the ledger"
        );

        // Un-buffering releases exactly what was reserved.
        recv.buffer_sub(8);
        assert_eq!(budget.in_flight(), 0, "buffer_sub must release the budget");
    }
}
