//! Per-connection and per-stream HTTP/2 server state.
//!
//! The receive-side bookkeeping ([`Recv`], [`StreamState`]), the peer's negotiated
//! settings ([`PeerSettings`]), and the send-side outgoing-body record ([`OutStream`]).
//! These are pure state structs shared by the connection loop in [`super`] and the
//! receive/send halves; their fields are `pub(super)` so all three can read/write them.

use bytes::Bytes;

/// Peer (client) SETTINGS we act on, with protocol defaults (RFC 7540 §6.5.2).
#[derive(Debug, Clone, Copy)]
pub(super) struct PeerSettings {
    pub(super) max_frame_size: u32,
    /// Per-stream send window the peer grants us initially (SETTINGS_INITIAL_WINDOW_SIZE).
    pub(super) initial_window: i64,
}

impl Default for PeerSettings {
    fn default() -> Self {
        PeerSettings {
            max_frame_size: 16384,
            initial_window: 65535,
        }
    }
}

/// Receive-side connection state used for RFC 7540 conformance checks: stream-id
/// ordering/parity, the open header-block (CONTINUATION continuity), and the concurrent
/// stream cap we advertise.
pub(super) struct Recv {
    /// Highest client-initiated (odd) stream id opened so far (§5.1.1 ordering).
    pub(super) last_client_stream: u32,
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
    /// over-cap stream is RST'd (REFUSED_STREAM).
    pub(super) max_request_body: usize,
    /// Per-connection SUM cap = `4 × max_request_body`; over it ⇒ GOAWAY(ENHANCE_YOUR_CALM).
    pub(super) per_conn_request_body: usize,
    /// (CVE-2019-9512/9515/9518 class) Count of frames processed since the last forward
    /// progress on this connection. Bounds a "no-progress" frame flood — empty DATA / non-ACK
    /// PING / non-ACK SETTINGS / PRIORITY churn that resets the idle timer and forces parse+ACK
    /// work without ever advancing a request. Reset to 0 on any progress (a dispatched request,
    /// a non-empty DATA byte, a window grant); over `NO_PROGRESS_BUDGET` ⇒ GOAWAY.
    pub(super) no_progress_frames: u32,
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
    /// Declared `content-length`, if any — validated against the actual body at completion
    /// (§8.1.2.6). `Some(None)` would be a parse error; we store the parsed value or flag
    /// malformed at decode time.
    pub(super) content_length: Option<u64>,
    /// Per-stream RECEIVE flow-control window (§6.9): credit granted to the peer for DATA on this
    /// stream. Initialized to our SETTINGS_INITIAL_WINDOW_SIZE when the stream opens (default 0
    /// from `Default` is overwritten at creation), decremented on DATA, replenished as we buffer.
    pub(super) recv_window: i64,
}

/// A response body being written out incrementally under HTTP/2 send flow control.
/// In-memory bodies (`Full` / `File`) seed `pending` and finish in one pass; streaming
/// bodies (`Stream` — LSAPI / proxy / SSE) pull chunks asynchronously into `pending`.
pub(super) struct OutStream {
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
    /// Cancels an in-flight body pull when the peer resets this stream.
    pub(super) cancel: tokio_util::sync::CancellationToken,
}

impl Drop for OutStream {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
