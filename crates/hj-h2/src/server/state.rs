//! Per-connection and per-stream HTTP/2 server state.
//!
//! The receive-side bookkeeping ([`Recv`], [`StreamState`]), the peer's negotiated
//! settings ([`PeerSettings`]), and the send-side outgoing-body record ([`OutStream`]).
//! These are pure state structs shared by the connection loop in [`super`] and the
//! receive/send halves; their fields are `pub(super)` so all three can read/write them.

use std::collections::VecDeque;

use bytes::Bytes;
use rustc_hash::FxHashSet;

/// Peer (client) SETTINGS we act on, with protocol defaults (RFC 7540 §6.5.2).
#[derive(Debug, Clone, Copy)]
pub(super) struct PeerSettings {
    pub(super) max_frame_size: u32,
    /// Per-stream send window the peer grants us initially (SETTINGS_INITIAL_WINDOW_SIZE).
    pub(super) initial_window: i64,
    /// The peer's first SETTINGS frame has been recorded in the process-wide
    /// `httpjet_h2_peer_settings_total` buckets (once per connection).
    pub(super) first_settings_recorded: bool,
}

impl Default for PeerSettings {
    fn default() -> Self {
        PeerSettings {
            max_frame_size: 16384,
            initial_window: 65535,
            first_settings_recorded: false,
        }
    }
}

/// Receive-side connection state used for RFC 7540 conformance checks: stream-id
/// ordering/parity, the open header-block (CONTINUATION continuity), and the concurrent
/// stream cap we advertise.
pub(super) struct Recv {
    /// RFC 9113 §3.4: the client preface is magic + a (non-ACK) SETTINGS frame;
    /// anything else first is a PROTOCOL_ERROR connection error (#625).
    pub(super) seen_settings: bool,
    /// Highest client-initiated (odd) stream id opened so far (§5.1.1 ordering).
    pub(super) last_client_stream: u32,
    /// Last-stream-id of the first GOAWAY we sent. RFC 9113 §6.8: a later GOAWAY must not
    /// raise it, although refused racing streams still advance `last_client_stream`.
    pub(super) goaway_last: Option<u32>,
    /// While a header block is open (HEADERS/CONTINUATION without END_HEADERS), the id of
    /// the stream it belongs to — only a CONTINUATION on that stream may follow (§6.10).
    pub(super) open_header_block: Option<u32>,
    /// True when `open_header_block` belongs to an already-closed stream whose
    /// HEADERS/CONTINUATION bytes are being decoded only to keep HPACK in sync.
    pub(super) discarding_header_block: bool,
    pub(super) discard_header_block: Vec<u8>,
    /// Stream error to emit once a decode-and-discard header block reaches END_HEADERS.
    /// Even rejected blocks must be decoded because HPACK state is connection-wide.
    pub(super) discard_rst_code: u32,
    /// (#357) Client stream ids torn down by a RST_STREAM — ours (every `rst!` site) or
    /// the peer's. A later frame on one of these is the §5.1 close race and stays a
    /// per-stream STREAM_CLOSED; a reused id NOT recorded here was closed cleanly or
    /// never opened, which is the §5.1.1 connection error. Unlike `cancelled` (which is
    /// consumed as aborted handlers drain), entries leave only by age. Bounded like
    /// `cancelled` (cap = max_concurrent * 2) to the most recent resets, the ones a late
    /// frame can still be racing; an evicted id fails closed — a later race on it
    /// degrades to GOAWAY rather than the set growing unbounded.
    pub(super) reset_ids: RecentIds,
    /// The subset of `reset_ids` WE reset: §5.1 says frames on those are ignored
    /// (#877), while a frame after the PEER's own RST_STREAM is still STREAM_CLOSED.
    /// Bounded like `reset_ids`; an evicted id just gets the RST answer.
    pub(super) sent_reset_ids: RecentIds,
    /// Our advertised SETTINGS_MAX_CONCURRENT_STREAMS (§5.1.2).
    pub(super) max_concurrent: usize,
    /// Connection-level RECEIVE flow-control window (§6.9): credit we have granted the peer for
    /// DATA across all streams. Decremented as DATA arrives, replenished as we buffer it.
    pub(super) conn_recv_window: i64,
    /// The per-stream receive window we grant on a new stream = our advertised
    /// SETTINGS_INITIAL_WINDOW_SIZE (§6.9.2). Stamped into each `StreamState` at open.
    pub(super) our_initial_window: i64,
    /// (CVE-2023-44487 rapid-reset) Running imbalance: streams the peer RST'd *while their
    /// handler was still in flight* minus streams that completed a response. An open→reset
    /// flood (each reset triggers a full backend render that is then discarded) drives this
    /// up monotonically; a healthy client that cancels some requests while completing others
    /// keeps it near zero. Over `RAPID_RESET_BUDGET` ⇒ GOAWAY(ENHANCE_YOUR_CALM) + close.
    pub(super) rst_unanswered: u32,
    /// (per-connection request-body bound) Running sum of buffered request-body bytes across
    /// all streams. The per-stream 64 MiB cap alone permits max_concurrent x 64 MiB (~16 GiB)
    /// resident on one connection; this bounds the aggregate. Incremented as DATA buffers,
    /// decremented when a stream's body is dispatched (complete) or its stream is removed.
    pub(super) total_buffered: usize,
    /// Per-stream buffered-request-body cap (LiteSpeed `maxReqBodySize`, from `Config`). An
    /// over-cap stream is answered 413 (#1014).
    pub(super) max_request_body: usize,
    /// Per-connection SUM cap = `4 × max_request_body`; over it ⇒ GOAWAY(ENHANCE_YOUR_CALM).
    pub(super) per_conn_request_body: usize,
    /// Server-wide buffered-body budget shared with the H1/H3 transports (#236 residual).
    /// Each stream owns its reservation and transfers it with the body at dispatch.
    /// Unlike `total_buffered`, global accounting lasts until the body allocation dies.
    pub(super) body_budget: Option<std::sync::Arc<hj_core::budget::BodyBufferBudget>>,
    /// (CVE-2019-9512/9515/9518 class) Count of frames processed since the last forward
    /// progress on this connection. Bounds a "no-progress" frame flood — empty DATA / non-ACK
    /// PING / non-ACK SETTINGS / PRIORITY churn that resets the idle timer and forces parse+ACK
    /// work without ever advancing a request. Reset to 0 on any progress (a dispatched request,
    /// a non-empty DATA byte, a window grant); over `NO_PROGRESS_BUDGET` ⇒ GOAWAY.
    pub(super) no_progress_frames: u32,
}

impl Recv {
    /// The last-stream-id for a GOAWAY being sent now, never above an earlier one.
    pub(super) fn goaway_last_stream_id(&mut self) -> u32 {
        let id = self.goaway_last.map_or(self.last_client_stream, |prev| {
            prev.min(self.last_client_stream)
        });
        self.goaway_last = Some(id);
        id
    }

    /// Remember a reset stream so a late HEADERS on it (trailers racing the
    /// RST_STREAM) is the tolerated §5.1 close race rather than §5.1.1 id reuse.
    /// Only the most recent resets are kept; an evicted id fails closed into a
    /// connection error.
    pub(super) fn note_reset(&mut self, sid: u32) {
        self.reset_ids
            .insert(sid, self.max_concurrent.saturating_mul(2));
    }

    /// Stop counting `n` bytes against the connection's unfinished-body limit.
    /// The stream/body's owned lease independently retains global accounting until
    /// its bytes are freed, including after dispatch and on connection teardown.
    pub(super) fn buffer_sub(&mut self, n: usize) {
        self.total_buffered = self.total_buffered.saturating_sub(n);
    }

    /// Receive-side teardown after WE reset `sid`: drop any half-received request
    /// (returning its buffered-body accounting) and record the reset id, so a later
    /// DATA...END_STREAM cannot complete and dispatch it (#581, #598).
    pub(super) fn teardown_receiving(
        &mut self,
        streams: &mut rustc_hash::FxHashMap<u32, StreamState>,
        sid: u32,
    ) {
        if let Some(s) = streams.remove(&sid) {
            self.buffer_sub(s.body.len());
        }
        self.note_reset(sid);
        self.sent_reset_ids
            .insert(sid, self.max_concurrent.saturating_mul(2));
    }

    /// Body-deadline teardown of `sid`. Returns whether to emit RST_STREAM now.
    /// A trailer block still open on `sid` must keep being decoded to stay in
    /// HPACK sync, and its CONTINUATIONs must not read as a connection error,
    /// so the block switches to discard mode and resets at END_HEADERS.
    pub(super) fn expire_receiving(
        &mut self,
        streams: &mut rustc_hash::FxHashMap<u32, StreamState>,
        sid: u32,
    ) -> bool {
        let open_block = self.open_header_block == Some(sid) && !self.discarding_header_block;
        if open_block && let Some(st) = streams.get_mut(&sid) {
            self.discard_header_block = std::mem::take(&mut st.header_block);
            self.discarding_header_block = true;
            self.discard_rst_code = crate::frame::error_code::CANCEL;
        }
        self.teardown_receiving(streams, sid);
        !open_block
    }
}

/// A bounded set of the most recently recorded stream ids: at the cap the oldest
/// entry is evicted, so a long-lived connection keeps tracking its newest resets.
#[derive(Default)]
pub(super) struct RecentIds {
    ids: FxHashSet<u32>,
    order: VecDeque<u32>,
}

impl RecentIds {
    pub(super) fn contains(&self, sid: u32) -> bool {
        self.ids.contains(&sid)
    }

    pub(super) fn insert(&mut self, sid: u32, cap: usize) {
        if cap == 0 || self.ids.contains(&sid) {
            return;
        }
        while self.order.len() >= cap {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.ids.remove(&oldest);
        }
        self.ids.insert(sid);
        self.order.push_back(sid);
    }
}

/// Per-stream accumulation until the request is complete. Request headers are decoded
/// straight into an `http::HeaderMap` (and the pseudo-headers captured) so there is no
/// intermediate `Vec<(String, String)>` and the map moves into the Request unchanged.
#[derive(Default)]
pub(super) struct StreamState {
    pub(super) header_block: Vec<u8>,
    // Pseudo-headers are parsed into their typed forms AT DECODE TIME (while the value is
    // still borrowed from the HPACK buffer) rather than stored as an intermediate `Box<str>`
    // and re-parsed in `build_request` — that round-trip cost one extra heap alloc per
    // pseudo-header (3/request on the connection task's hot path). Standard methods are static
    // (no alloc); the Uri/HeaderValue own the alloc `build_request` would have made anyway.
    pub(super) method: Option<http::Method>,
    pub(super) path: Option<http::Uri>,
    pub(super) authority: Option<http::HeaderValue>,
    pub(super) headers: http::HeaderMap,
    pub(super) headers_done: bool,
    pub(super) end_stream: bool,
    /// Refused for exceeding SETTINGS_MAX_CONCURRENT_STREAMS. The header block is STILL decoded
    /// (so the connection-wide HPACK dynamic table stays in sync) and CONTINUATIONs still find
    /// this stream; the RST_STREAM(REFUSED_STREAM) is deferred to the END_HEADERS decode-complete
    /// site (`refuse_if_marked` in recv.rs) instead of firing when the HEADERS frame first arrives.
    pub(super) refused: bool,
    pub(super) body: Vec<u8>,
    /// Own the global reservation while buffering; move it into the body Bytes at
    /// dispatch so every clone/slice keeps the allocation charged until final drop.
    pub(super) body_lease: Option<hj_core::budget::BodyBufferLease>,
    /// Declared `content-length`, if any — validated against the actual body at completion
    /// (§8.1.2.6). `Some(None)` would be a parse error; we store the parsed value or flag
    /// malformed at decode time.
    pub(super) content_length: Option<u64>,
    /// Deadline for completing the request body after the initial header block. Only
    /// this stream's own DATA extends it (`advance_body_deadlines`, #1035); other active
    /// streams and control frames must not.
    pub(super) body_deadline: Option<tokio::time::Instant>,
    /// Per-stream RECEIVE flow-control window (§6.9): credit granted to the peer for DATA on this
    /// stream. Initialized to our SETTINGS_INITIAL_WINDOW_SIZE when the stream opens (default 0
    /// from `Default` is overwritten at creation), decremented on DATA, replenished as we buffer.
    pub(super) recv_window: i64,
}

/// A response body being written out incrementally under HTTP/2 send flow control.
/// In-memory bodies (`Full` / `File`) seed `pending` and finish in one pass; streaming
/// bodies (`Stream` — LSAPI / proxy / SSE) pull chunks asynchronously into `pending`.
pub(super) struct OutStream {
    pub(super) completion: Option<hj_core::ResponseCompletion>,
    /// Bytes pulled but not yet sent (the window-blocked remainder of the current chunk).
    pub(super) pending: Bytes,
    /// The streaming source while it is "at home" (not currently being pulled). `None`
    /// for in-memory bodies and while a pull future holds it.
    pub(super) body: Option<hj_core::StreamBody>,
    /// A pull future for this stream is in flight.
    pub(super) pulling: bool,
    /// The body is exhausted; the final DATA frame carries END_STREAM.
    pub(super) eof: bool,
    /// END_STREAM has been written (or the stream was reset) — the entry can be dropped.
    pub(super) done: bool,
    /// Per-stream send window (RFC 7540 §6.9): bytes the peer will accept right now.
    pub(super) window: i64,
    /// Cancels an in-flight body pull when the peer resets this stream. Created by the
    /// first pull, so in-memory bodies (which never pull) never allocate one.
    pub(super) cancel: Option<tokio_util::sync::CancellationToken>,
    /// Send-stall clock while this response has bytes waiting on flow-control credit.
    pub(super) stall: Option<SendStall>,
    /// Already counted as flow-control blocked; cleared by the next DATA frame it sends.
    pub(super) send_blocked: bool,
}

/// One response's send-stall clock: when its current window started and how many DATA
/// bytes it has delivered since.
#[derive(Debug, Clone, Copy)]
pub(super) struct SendStall {
    pub(super) since: std::time::Instant,
    pub(super) progressed: u64,
}

impl Drop for OutStream {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
    }
}
