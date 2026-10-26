//! Inbound HTTP/2 frame processing.
//!
//! Decodes one frame at a time ([`process_frame`]): assembles request HEADERS (+CONTINUATION)
//! and DATA into a complete request, enforces RFC 7540 stream association/state, frame sizes,
//! header-block continuity, receive-side flow control, and §8.1.2 request-header validation.
//! Control frames (SETTINGS / PING / WINDOW_UPDATE / GOAWAY / RST_STREAM) queue responses or
//! surface a [`FrameOutcome`] to the connection loop in [`super`].

use futures_util::future::AbortHandle;
use rustc_hash::{FxHashMap, FxHashSet};
use std::future::Future;

use crate::hpack::{Decoder, Encoder};
use bytes::Bytes;
use hj_core::{IncomingBody, Request, Response};
use http_body_util::BodyExt;

use super::state::{PeerSettings, Recv, StreamState};
use super::{Inflight, OutQueue};
use crate::frame::{self, FrameHeader, error_code, flags, kind, settings};

/// Hard cap on per-stream buffering of an untrusted HEADERS+CONTINUATION block, bounding a
/// memory-DoS from a peer that opens up to `max_concurrent_streams` streams and floods them.
/// An over-cap header block fails the connection (COMPRESSION error — the HPACK state is
/// shared). The per-stream + per-connection request-BODY caps are config-driven (LiteSpeed
/// `maxReqBodySize`) and live on [`Recv`] (`max_request_body` / `per_conn_request_body`).
const MAX_HEADER_BLOCK: usize = 64 * 1024; // assembled HEADERS + CONTINUATION, per stream
/// (CVE-2023-44487) Resets of dispatched streams a connection may make at once before it
/// is treated as a rapid-reset flood and GOAWAYed: a browser navigating away cancels a
/// burst of dozens, never hundreds.
const RAPID_RESET_BURST: u32 = 200;
/// One reset credit returns per interval (10/s), and only time returns it: a completed
/// request must not pay for a cancelled one, or alternating the two never trips.
const RAPID_RESET_REFILL: std::time::Duration = std::time::Duration::from_millis(100);
/// (CVE-2019-9512/9515/9518 class) Max frames processed since the last forward progress before
/// we treat the connection as a no-progress flood and GOAWAY. Generous: real traffic resets
/// this to 0 on any progress (a dispatched request, a non-empty DATA byte, or a window grant),
/// so a legitimate client never approaches it; pure empty-DATA / PING / SETTINGS / PRIORITY
/// churn hits it in a fraction of a second.
const NO_PROGRESS_BUDGET: u32 = 10_000;
/// Heap a decoded request field holds beyond its name and value bytes: its `HeaderMap`
/// bucket, index slot and growth slack (measured 131-176 B for distinct short names).
const DECODED_FIELD_OVERHEAD: usize = 192;
/// Bound on the header-map pre-size carried between requests, so one request with many
/// headers does not make every later stream on the connection pre-allocate for them.
const HEADER_COUNT_HINT_MAX: usize = 64;

/// What a stream's decoded headers cost while they wait for the request body: every
/// field plus the pseudo-headers, the stream entry and the map's minimum allocation.
fn pending_header_charge(st: &StreamState) -> u32 {
    let fields = st.headers.iter().fold(0usize, |sum, (name, value)| {
        sum.saturating_add(name.as_str().len() + value.len() + DECODED_FIELD_OVERHEAD)
    });
    let path = st
        .path
        .as_ref()
        .and_then(http::Uri::path_and_query)
        .map_or(0, |pq| pq.as_str().len());
    let authority = st.authority.as_ref().map_or(0, http::HeaderValue::len);
    let charge = fields
        .saturating_add(path + authority + 4 * DECODED_FIELD_OVERHEAD)
        .saturating_add(std::mem::size_of::<StreamState>());
    u32::try_from(charge).unwrap_or(u32::MAX)
}

impl Recv {
    /// Charge one reset of a stream whose handler was still in flight against the
    /// rapid-reset budget, whichever side sent the RST_STREAM. True once exceeded.
    pub(super) fn charge_inflight_reset(&mut self) -> bool {
        let exhausted = self.charge_inflight_reset_at(tokio::time::Instant::now());
        if exhausted {
            super::RAPID_RESET_GOAWAYS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        exhausted
    }

    /// Each reset pushes the debt one refill interval further out, starting from `now`
    /// once earlier debt has been repaid; more than a burst of intervals ahead of `now`
    /// is exhausted.
    pub(super) fn charge_inflight_reset_at(&mut self, now: tokio::time::Instant) -> bool {
        let from = self.reset_debt_until.filter(|&t| t > now).unwrap_or(now);
        let until = from + RAPID_RESET_REFILL;
        self.reset_debt_until = Some(until);
        until - now > RAPID_RESET_REFILL * RAPID_RESET_BURST
    }
}

/// Strip PADDED/PRIORITY framing from a HEADERS payload, yielding the header block.
fn headers_block(flags_byte: u8, payload: &[u8]) -> Option<&[u8]> {
    let mut p = payload;
    let mut pad = 0usize;
    if flags_byte & flags::PADDED != 0 {
        pad = *p.first()? as usize;
        p = &p[1..];
    }
    if flags_byte & flags::PRIORITY != 0 {
        if p.len() < 5 {
            return None;
        }
        p = &p[5..]; // 4-byte stream dependency + 1-byte weight
    }
    if pad > p.len() {
        return None;
    }
    Some(&p[..p.len() - pad])
}

/// Strip PADDED framing from a DATA payload.
fn data_block(flags_byte: u8, payload: &[u8]) -> Option<&[u8]> {
    let mut p = payload;
    let mut pad = 0usize;
    if flags_byte & flags::PADDED != 0 {
        pad = *p.first()? as usize;
        p = &p[1..];
    }
    if pad > p.len() {
        return None;
    }
    Some(&p[..p.len() - pad])
}

/// The stream dependency carried in a priority field — the 5-byte block at the start of a
/// PRIORITY frame, or after the pad-length byte of a HEADERS frame that sets PRIORITY. Used
/// to reject a stream that depends on itself (§5.3.1). Returns `None` if no priority field.
fn priority_dependency(flags_byte: u8, payload: &[u8], is_headers: bool) -> Option<u32> {
    let mut p = payload;
    if is_headers {
        if flags_byte & flags::PRIORITY == 0 {
            return None;
        }
        if flags_byte & flags::PADDED != 0 {
            p = p.get(1..)?; // skip the pad-length octet
        }
    }
    let dep = u32::from_be_bytes(p.get(0..4)?.try_into().ok()?);
    Some(dep & 0x7fff_ffff) // mask off the exclusive (E) bit
}

/// Outcome of handling one frame.
pub(super) enum FrameOutcome {
    Continue,
    /// Stop reading further frames (a connection error already queued).
    StopReading,
    /// Peer sent GOAWAY (§6.8): refuse new streams but keep reading so in-flight
    /// responses still receive WINDOW_UPDATE / RST_STREAM and can finish.
    PeerGoaway,
    /// Peer granted send-window credit (WINDOW_UPDATE). `stream_id == 0` = connection-level.
    /// The send state lives in `serve`, so window changes surface here.
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    /// A stream was reset — received RST_STREAM, or WE emitted one (#242): drop
    /// its in-flight outgoing body so no further frames are sent on the dead id.
    ResetStream(u32),
    /// Peer changed SETTINGS_INITIAL_WINDOW_SIZE (§6.9.2): every active stream's send
    /// window must shift by this (signed) delta. Applied to `outstreams` in `serve`.
    InitialWindowDelta(i64),
}

/// Handle one decoded frame: control frames queue responses into `wbuf`; a completed
/// request pushes its `service(req)` future into `inflight` (NOT awaited here, so other
/// streams keep flowing).
#[allow(clippy::too_many_arguments)]
pub(super) fn process_frame<S, F>(
    hdr: FrameHeader,
    payload: &[u8],
    streams: &mut FxHashMap<u32, StreamState>,
    dec: &mut Decoder,
    enc: &mut Encoder,
    out: &mut OutQueue,
    peer: &mut PeerSettings,
    recv: &mut Recv,
    outstreams_len: usize,
    accept_new_streams: bool,
    service: &S,
    inflight: &mut Inflight<F>,
    cancelled: &mut FxHashSet<u32>,
    inflight_sids: &mut FxHashMap<u32, AbortHandle>,
) -> FrameOutcome
where
    S: Fn(Request) -> F,
    F: Future<Output = Response> + Send + 'static,
{
    macro_rules! goaway {
        ($code:expr_2021) => {{
            // §6.8: GOAWAY carries the highest client stream we processed so the peer knows
            // which streams may be retried, not a hardcoded 0 (which claims nothing was handled).
            let last = recv.goaway_last_stream_id();
            out.frames(|b| frame::write_goaway(b, last, $code));
            return FrameOutcome::StopReading;
        }};
    }
    // Stream-level error: reset the stream, keep the connection.
    macro_rules! rst {
        ($sid:expr_2021, $code:expr_2021) => {{
            out.frames(|b| frame::write_rst_stream(b, $sid, $code));
            // (#581) Tear down the RECEIVING side too: drop any half-received
            // request and return its buffered-body accounting, or a later
            // DATA...END_STREAM would still complete and dispatch a request
            // we already reset. Idempotent for arms that removed it first.
            // (#357) The reset id is recorded too (never consumed; skipped at the
            // cap — failing closed into a connection error on a later reuse) so a
            // subsequent HEADERS on it is the tolerated §5.1 close race, not reuse.
            recv.teardown_receiving(streams, $sid);
            // (#242) After WE emit RST_STREAM for a stream, RFC 9113 §5.1 forbids
            // sending ANY further frames on it. Tear down the outbound side (a
            // half-written response body would otherwise keep streaming past the
            // RST) and, when a request handler is still in flight, abort it and
            // record the sid so its late completion cannot `begin_response` fresh
            // frames on the dead id. Mirrors the peer-RST arm below.
            if let Some(abort) = inflight_sids.remove(&$sid) {
                abort.abort();
                if cancelled.len() < recv.max_concurrent.saturating_mul(2) {
                    cancelled.insert($sid);
                }
                // (#905, MadeYouReset / CVE-2025-8671) A reset the peer PROVOKED
                // (WINDOW_UPDATE 0, self-dependent PRIORITY, DATA on a half-closed
                // stream) discards backend work exactly like a peer RST_STREAM, so
                // it draws on the same rapid-reset budget. Resets of streams with no
                // live handler cost nothing and are not counted.
                if recv.charge_inflight_reset() {
                    goaway!(error_code::ENHANCE_YOUR_CALM);
                }
            }
            return FrameOutcome::ResetStream($sid);
        }};
    }
    // (#1014) A request too large to accept gets a complete, bodiless response with the
    // status H1 sends (413/431) — not REFUSED_STREAM, which tells the client the request
    // was never processed and is safe to resend whole (§8.7). If the client is still
    // sending, RST_STREAM(NO_ERROR) follows the response so it stops without error (§8.1);
    // the rest of its body is then ignored unbuffered (§5.1).
    macro_rules! reject_too_large {
        ($sid:expr_2021, $status:literal, $client_open:expr_2021) => {{
            let client_open = $client_open;
            let mut block = Vec::with_capacity(8);
            enc.encode_header(&mut block, ":status", $status);
            enc.encode_header(&mut block, "content-length", "0");
            out.frames(|b| {
                frame::write_frame(
                    b,
                    kind::HEADERS,
                    flags::END_HEADERS | flags::END_STREAM,
                    $sid,
                    &block,
                )
            });
            if client_open {
                rst!($sid, error_code::NO_ERROR);
            }
            recv.drop_receiving(streams, $sid);
            // Both sides have ended the stream: nothing is reset, but its pre-response
            // window credit must still be dropped.
            return FrameOutcome::ResetStream($sid);
        }};
    }
    // A body-carrying request that `Config::early_reject` refuses from its head gets that
    // bodiless response before any DATA is accepted or 100 Continue is sent, then
    // RST_STREAM(NO_ERROR) so the client stops sending without error (§8.1); its remaining
    // DATA is ignored unbuffered while still crediting the connection window (§5.1).
    macro_rules! reject_early {
        ($sid:expr_2021) => {{
            if recv.early_reject.is_some()
                && let Some((status, mut headers)) = streams
                    .get(&$sid)
                    .filter(|st| !st.end_stream)
                    .and_then(|st| early_reject_response(recv, st))
            {
                hj_core::strip_hop_by_hop_response(&mut headers);
                headers.remove(http::header::CONTENT_LENGTH);
                let mut block = Vec::with_capacity(128);
                enc.encode_header(&mut block, ":status", status.as_str());
                for (name, value) in &headers {
                    enc.encode_header(&mut block, name.as_str(), value.as_bytes());
                }
                enc.encode_header(&mut block, "content-length", "0");
                let max_frame = peer.max_frame_size as usize;
                out.frames(|b| {
                    super::send::write_field_block(b, $sid, flags::END_STREAM, &block, max_frame)
                });
                rst!($sid, error_code::NO_ERROR);
            }
        }};
    }
    // A stream marked `refused` (over the concurrency cap) is reset only AFTER its header block
    // has been fully assembled and decoded — keeping the connection-wide HPACK dynamic table in
    // sync and letting any CONTINUATION find its stream — so the refusal is applied at each
    // END_HEADERS decode-complete site rather than when the HEADERS frame first arrives.
    macro_rules! refuse_if_marked {
        ($sid:expr_2021) => {{
            if streams.get(&$sid).is_some_and(|s| s.refused) {
                streams.remove(&$sid);
                rst!($sid, error_code::REFUSED_STREAM);
            }
        }};
    }
    // A stream whose request headers completed without END_STREAM holds its decoded map
    // until the body arrives. Charge it against the connection's decoded-header cap and
    // the server-wide budget, or refuse it (retry-safe, §8.7) once either is exhausted.
    // Its block was already decoded in full, so HPACK stays in sync.
    macro_rules! admit_or_refuse {
        ($sid:expr_2021, $st:expr_2021) => {{
            let charge = pending_header_charge($st);
            if !recv.admit_pending_headers($st, charge) {
                rst!($sid, error_code::REFUSED_STREAM);
            }
        }};
    }
    // Build the request for a completed stream and push its handler future.
    macro_rules! complete {
        ($sid:expr_2021) => {{
            if let Some(st) = streams.remove(&$sid) {
                recv.no_progress_frames = 0; // a dispatched request is forward progress
                recv.release_stream(&st);
                if st.content_length.is_some_and(|cl| cl != st.body.len() as u64) {
                    // §8.1.2.6: declared content-length must equal the DATA bytes received.
                    // `rst!` also drops the stream's early WINDOW_UPDATE credit.
                    rst!($sid, error_code::PROTOCOL_ERROR);
                } else {
                    // §8.3.1: a HEAD response carries the GET's headers but never a body — captured
                    // here so the writer sends headers-only regardless of what the handler returns.
                    let is_head = st.method.as_ref() == Some(&http::Method::HEAD);
                    recv.header_count_hint =
                        (st.headers.len() + usize::from(st.authority.is_some())).min(HEADER_COUNT_HINT_MAX);
                    match build_request(st) {
                        Some(req) => {
                            let fut = service(req);
                            let sid = $sid;
                            // Every stream's handler future on this connection is polled by the ONE
                            // connection task, so a single h2 connection is confined to ~one CPU core
                            // no matter how many streams it multiplexes — a CPU-bound rewrite or
                            // backend-bound PHP burst over one (or a few) connections then pins ~1
                            // core while the rest of the box sits idle. When there are fewer active
                            // h2 connections than worker threads, connection-level parallelism alone
                            // can't fill the cores, so spawn the handler (work-stolen onto an idle
                            // worker); the single multiplexed connection then fans out across cores.
                            //
                            // At/above the worker count, inline is optimal — spawning only adds a
                            // cross-thread handoff per request and measurably *cuts* throughput
                            // (the common case: the loopback bench and real CF→origin traffic both
                            // arrive over many connections). `super::spare_cores()` reads a global
                            // active-connection counter, so the decision tracks live load. A single
                            // CPU-bound connection's backlog hides in the kernel socket buffer — it
                            // never shows up in `streams`/`inflight` — so a per-connection depth
                            // check can't detect this; only the global connection count can.
                            let fut = hj_core::Recycled::new(fut);
                            let inner = if super::spare_cores() {
                                super::TaggedInner::Spawned(super::AbortOnDrop(tokio::spawn(fut)))
                            } else {
                                super::TaggedInner::Inline(fut)
                            };
                            let (tagged, abort) = super::Tagged::cancellable(sid, is_head, inner);
                            inflight.push(tagged);
                            // Retain the stream's cancellation handle until its future drains.
                            // RST_STREAM removes and fires it immediately, dropping inline work
                            // and aborting spawned work instead of merely discarding a late response.
                            inflight_sids.insert(sid, abort);
                        }
                        None => rst!($sid, error_code::PROTOCOL_ERROR),
                    }
                }
            }
        }};
    }

    let sid = hdr.stream_id;

    // (CVE-2019-9512/9515/9518 class) Bound per-connection frames that make NO forward progress.
    // Every frame increments this; any genuine progress (a dispatched request via `complete!`, a
    // non-empty DATA byte, a positive window grant) resets it to 0 below. A pure flood of empty
    // DATA / non-ACK PING / non-ACK SETTINGS / PRIORITY frames — which the existing body/rapid-
    // reset caps don't catch and which resets the idle timer every loop — never resets it, so it
    // GOAWAYs(ENHANCE_YOUR_CALM) once the generous budget is exceeded instead of pinning ~1 core.
    // #625 (RFC 9113 §3.4): first frame must be non-ACK SETTINGS.
    if !recv.seen_settings {
        if hdr.kind != kind::SETTINGS || hdr.flags & flags::ACK != 0 {
            goaway!(error_code::PROTOCOL_ERROR);
        }
        recv.seen_settings = true;
    }
    recv.no_progress_frames = recv.no_progress_frames.saturating_add(1);
    if recv.no_progress_frames > NO_PROGRESS_BUDGET {
        goaway!(error_code::ENHANCE_YOUR_CALM);
    }

    // §6.10: while a header block is open, the only legal frame is a CONTINUATION on the
    // same stream (guards the CONTINUATION-flood / interleaving class).
    if let Some(open) = recv.open_header_block {
        if hdr.kind != kind::CONTINUATION || sid != open {
            goaway!(error_code::PROTOCOL_ERROR);
        }
    } else if hdr.kind == kind::CONTINUATION {
        // The converse half: a CONTINUATION is legal only after a HEADERS/CONTINUATION that did
        // NOT set END_HEADERS. A discard-in-progress block always carries `open_header_block`,
        // so it takes the arm above and is unaffected. Without this, a bare CONTINUATION on a
        // body-pending stream is absorbed as a phantom trailer section, letting every stream
        // hold a 64 KiB header block at once — outside both the body cap and the body budget.
        goaway!(error_code::PROTOCOL_ERROR);
    }

    // §6: stream association. Some frames MUST carry a stream id; others MUST be on 0.
    match hdr.kind {
        kind::DATA | kind::HEADERS | kind::PRIORITY | kind::RST_STREAM | kind::CONTINUATION => {
            if sid == 0 {
                goaway!(error_code::PROTOCOL_ERROR);
            }
        }
        kind::SETTINGS | kind::PING | kind::GOAWAY => {
            if sid != 0 {
                goaway!(error_code::PROTOCOL_ERROR);
            }
        }
        kind::PUSH_PROMISE => goaway!(error_code::PROTOCOL_ERROR), // a server never receives one
        _ => {}
    }

    // §6: fixed-size frames must carry exactly their defined length.
    let bad_len = match hdr.kind {
        kind::RST_STREAM | kind::WINDOW_UPDATE => hdr.length != 4,
        kind::PRIORITY => hdr.length != 5,
        kind::PING => hdr.length != 8,
        _ => false,
    };
    if bad_len {
        goaway!(error_code::FRAME_SIZE_ERROR);
    }

    match hdr.kind {
        kind::SETTINGS => {
            if hdr.flags & flags::ACK != 0 {
                if hdr.length != 0 {
                    goaway!(error_code::FRAME_SIZE_ERROR); // §6.5: ACK carries no payload
                }
            } else if !hdr.length.is_multiple_of(6) {
                goaway!(error_code::FRAME_SIZE_ERROR);
            } else {
                match frame::parse_settings(payload) {
                    Some(params) => {
                        let mut iw_delta: i64 = 0;
                        let mut header_table_size = None;
                        for (id, value) in params {
                            match id {
                                settings::ENABLE_PUSH => {
                                    if value > 1 {
                                        goaway!(error_code::PROTOCOL_ERROR);
                                    }
                                }
                                settings::HEADER_TABLE_SIZE => {
                                    // §6.5.2: the peer's decoder dynamic-table cap. Bound our
                                    // HPACK encoder to it; a change emits a size update (§6.3)
                                    // at the start of the next response header block.
                                    enc.set_peer_max_size(value as usize);
                                    header_table_size = Some(value);
                                }
                                settings::MAX_FRAME_SIZE => {
                                    if !(16384..=(1 << 24) - 1).contains(&value) {
                                        goaway!(error_code::PROTOCOL_ERROR);
                                    }
                                    peer.max_frame_size = value;
                                }
                                settings::INITIAL_WINDOW_SIZE => {
                                    if value > i32::MAX as u32 {
                                        goaway!(error_code::FLOW_CONTROL_ERROR);
                                        // §6.5.2
                                    }
                                    // §6.9.2: shift every active stream's send window by the
                                    // change in the initial window size.
                                    iw_delta += value as i64 - peer.initial_window;
                                    peer.initial_window = value as i64;
                                }
                                _ => {}
                            }
                        }
                        if !peer.first_settings_recorded {
                            peer.first_settings_recorded = true;
                            super::record_peer_settings(
                                peer.initial_window as u64,
                                header_table_size.unwrap_or(4096) as u64,
                                peer.max_frame_size as u64,
                            );
                        }
                        out.frames(frame::write_settings_ack);
                        if iw_delta != 0 {
                            return FrameOutcome::InitialWindowDelta(iw_delta);
                        }
                    }
                    None => goaway!(error_code::FRAME_SIZE_ERROR),
                }
            }
        }
        kind::PING => {
            if hdr.flags & flags::ACK == 0 {
                let mut opaque = [0u8; 8];
                opaque.copy_from_slice(payload);
                out.frames(|b| frame::write_ping_ack(b, opaque));
            }
        }
        kind::WINDOW_UPDATE
            if sid != 0 && (sid.is_multiple_of(2) || sid > recv.last_client_stream) =>
        {
            // §5.1.1: an even (server-initiated) id the client may not open, or an idle
            // (never-opened) stream — a connection error, not a tolerant stream RST.
            goaway!(error_code::PROTOCOL_ERROR);
        }
        kind::WINDOW_UPDATE => match frame::parse_window_update(payload) {
            Some(0) => {
                // §6.9: a 0 increment is an error — connection-level on stream 0, else stream.
                if sid == 0 {
                    goaway!(error_code::PROTOCOL_ERROR);
                }
                rst!(sid, error_code::PROTOCOL_ERROR);
            }
            Some(increment) => {
                // (#241) A stream-level grant is NOT automatically forward progress:
                // whether it actually unblocks a window-blocked response body is only
                // known where send windows are applied (the session loop in mod.rs),
                // which clears `no_progress_frames` when a blocked window genuinely
                // crosses back above 0. Resetting here for ANY sid != 0 let an
                // attacker alternate stream-level WINDOW_UPDATEs on idle/closed
                // streams to defer the flood GOAWAY forever (CVE-2019-9518 class).
                return FrameOutcome::WindowUpdate {
                    stream_id: sid,
                    increment,
                };
            }
            None => goaway!(error_code::FRAME_SIZE_ERROR),
        },
        kind::GOAWAY => {
            if payload.len() < 8 {
                goaway!(error_code::FRAME_SIZE_ERROR);
            }
            return FrameOutcome::PeerGoaway;
        }
        kind::HEADERS => {
            let opens_new_stream = !streams.contains_key(&sid);
            if opens_new_stream && sid.is_multiple_of(2) {
                goaway!(error_code::PROTOCOL_ERROR);
            }
            if opens_new_stream && sid <= recv.last_client_stream {
                if !recv.reset_ids.contains(sid) {
                    // §5.1.1: client stream ids are never reused — HEADERS on a lower id
                    // that no RST_STREAM (ours or the peer's) ever closed was either
                    // ended cleanly or skipped entirely, a connection error. Only reset
                    // ids get the tolerant per-stream STREAM_CLOSED below (§5.1's
                    // limited-period race). GOAWAY without decoding the block: the
                    // connection is being torn down, so HPACK sync only matters for
                    // frames we still intend to honor — same as every goaway! site (#357).
                    goaway!(error_code::PROTOCOL_ERROR);
                }
                let block = match headers_block(hdr.flags, payload) {
                    Some(b) => b,
                    None => goaway!(error_code::PROTOCOL_ERROR),
                };
                if block.len() > MAX_HEADER_BLOCK {
                    goaway!(error_code::COMPRESSION_ERROR);
                }
                if hdr.flags & flags::END_HEADERS != 0 {
                    if !decode_discard_header_block(dec, block) {
                        goaway!(error_code::COMPRESSION_ERROR);
                    }
                    rst!(sid, error_code::STREAM_CLOSED);
                }
                recv.discard_header_block.clear();
                recv.discard_header_block.extend_from_slice(block);
                recv.discarding_header_block = true;
                recv.discard_rst_code = error_code::STREAM_CLOSED;
                recv.open_header_block = Some(sid);
                return FrameOutcome::Continue;
            }
            if opens_new_stream {
                // Mark an odd, monotonically increasing id seen before any stream-local
                // decode/discard error so the same id can never be reopened later.
                recv.last_client_stream = sid;
            }
            let self_priority = priority_dependency(hdr.flags, payload, true) == Some(sid);
            let unterminated_trailers = streams.get(&sid).is_some_and(|s| s.headers_done)
                && hdr.flags & flags::END_STREAM == 0;
            if self_priority || unterminated_trailers {
                let block = match headers_block(hdr.flags, payload) {
                    Some(b) => b,
                    None => goaway!(error_code::PROTOCOL_ERROR),
                };
                if block.len() > MAX_HEADER_BLOCK {
                    goaway!(error_code::COMPRESSION_ERROR);
                }
                recv.drop_receiving(streams, sid);
                if hdr.flags & flags::END_HEADERS != 0 {
                    if !decode_discard_header_block(dec, block) {
                        goaway!(error_code::COMPRESSION_ERROR);
                    }
                    rst!(sid, error_code::PROTOCOL_ERROR);
                }
                recv.discard_header_block.clear();
                recv.discard_header_block.extend_from_slice(block);
                recv.discarding_header_block = true;
                recv.discard_rst_code = error_code::PROTOCOL_ERROR;
                recv.open_header_block = Some(sid);
                return FrameOutcome::Continue;
            }
            // §5.1.1 ordering/parity + §5.1.2 concurrency, checked when a stream first opens.
            let mut refuse_new_stream = false;
            if opens_new_stream {
                // §5.1.2: count streams in every active state — being assembled (`streams`),
                // running a handler (`inflight`), or sending a response (`outstreams`). Over the
                // cap → MARK for refusal but don't reset here: the header block must still be
                // decoded (HPACK stays in sync) and CONTINUATIONs must still find the stream. The
                // RST is emitted once the block is assembled (`refuse_if_marked` at END_HEADERS).
                refuse_new_stream = !accept_new_streams
                    || streams.len() + inflight.len() + outstreams_len >= recv.max_concurrent;
            }
            let block = match headers_block(hdr.flags, payload) {
                Some(b) => b,
                None => goaway!(error_code::PROTOCOL_ERROR),
            };
            // New streams open with the per-stream receive window we advertise (§6.9.2).
            let iw = recv.our_initial_window;
            let hint = recv.header_count_hint;
            let st = streams.entry(sid).or_insert_with(|| StreamState {
                recv_window: iw,
                headers: http::HeaderMap::with_capacity(hint),
                ..Default::default()
            });
            if refuse_new_stream {
                st.refused = true;
            }
            if st.header_block.len() + block.len() > MAX_HEADER_BLOCK {
                goaway!(error_code::COMPRESSION_ERROR); // header block too large (anti-DoS)
            }
            if hdr.flags & flags::END_STREAM != 0 {
                st.end_stream = true;
            }
            if hdr.flags & flags::END_HEADERS != 0 {
                recv.open_header_block = None;
                // Single-frame HEADERS (the common case): END_HEADERS is set and nothing was
                // buffered from a prior CONTINUATION, so decode straight from the inbuf payload
                // slice — no `extend_from_slice` copy into st.header_block. The decoder reads
                // `block` (borrowing inbuf) while the emit closure writes `st`; they don't alias.
                let decoded = if st.header_block.is_empty() {
                    decode_block_from(dec, st, block)
                } else {
                    st.header_block.extend_from_slice(block);
                    decode_block(dec, st)
                };
                match decoded {
                    Decoded::Ok => {
                        refuse_if_marked!(sid);
                        if declared_body_too_large(streams.get(&sid), recv.max_request_body) {
                            reject_too_large!(sid, "413", true);
                        }
                        reject_early!(sid);
                        if let Some(st) = streams.get_mut(&sid)
                            && !st.end_stream
                        {
                            admit_or_refuse!(sid, st);
                            maybe_send_100_continue(st, sid, out, enc);
                        }
                        if streams.get(&sid).is_some_and(|s| s.end_stream) {
                            complete!(sid);
                        }
                    }
                    Decoded::Compression => goaway!(error_code::COMPRESSION_ERROR),
                    Decoded::TooLarge => {
                        refuse_if_marked!(sid);
                        let client_open = streams.get(&sid).is_some_and(|s| !s.end_stream);
                        reject_too_large!(sid, "431", client_open);
                    }
                    Decoded::Malformed => {
                        // A malformed trailer arrives AFTER the body was buffered, so un-account it
                        // (mirror the other removal sites) — else `total_buffered` leaks by the body
                        // length for the connection's life, eventually tripping a spurious
                        // GOAWAY(ENHANCE_YOUR_CALM) on a later legitimate DATA byte.
                        recv.drop_receiving(streams, sid);
                        rst!(sid, error_code::PROTOCOL_ERROR);
                    }
                }
            } else {
                st.header_block.extend_from_slice(block); // accumulate; CONTINUATION must follow
                recv.open_header_block = Some(sid);
            }
        }
        kind::CONTINUATION => {
            if recv.discarding_header_block {
                if recv.discard_header_block.len() + payload.len() > MAX_HEADER_BLOCK {
                    goaway!(error_code::COMPRESSION_ERROR);
                }
                recv.discard_header_block.extend_from_slice(payload);
                if hdr.flags & flags::END_HEADERS != 0 {
                    recv.open_header_block = None;
                    recv.discarding_header_block = false;
                    let block = std::mem::take(&mut recv.discard_header_block);
                    if !decode_discard_header_block(dec, &block) {
                        goaway!(error_code::COMPRESSION_ERROR);
                    }
                    let code = recv.discard_rst_code;
                    recv.discard_rst_code = error_code::STREAM_CLOSED;
                    rst!(sid, code);
                }
                return FrameOutcome::Continue;
            }
            let Some(st) = streams.get_mut(&sid) else {
                goaway!(error_code::PROTOCOL_ERROR);
            };
            if st.header_block.len() + payload.len() > MAX_HEADER_BLOCK {
                goaway!(error_code::COMPRESSION_ERROR); // header block too large (anti-DoS)
            }
            st.header_block.extend_from_slice(payload);
            if hdr.flags & flags::END_HEADERS != 0 {
                recv.open_header_block = None;
                match decode_block(dec, st) {
                    Decoded::Ok => {
                        refuse_if_marked!(sid);
                        if declared_body_too_large(streams.get(&sid), recv.max_request_body) {
                            reject_too_large!(sid, "413", true);
                        }
                        reject_early!(sid);
                        if let Some(st) = streams.get_mut(&sid)
                            && !st.end_stream
                        {
                            admit_or_refuse!(sid, st);
                            maybe_send_100_continue(st, sid, out, enc);
                        }
                        if streams.get(&sid).is_some_and(|s| s.end_stream) {
                            complete!(sid);
                        }
                    }
                    Decoded::Compression => goaway!(error_code::COMPRESSION_ERROR),
                    Decoded::TooLarge => {
                        refuse_if_marked!(sid);
                        let client_open = streams.get(&sid).is_some_and(|s| !s.end_stream);
                        reject_too_large!(sid, "431", client_open);
                    }
                    Decoded::Malformed => {
                        // Same as the HEADERS arm: un-account any buffered body before dropping the
                        // stream so a CONTINUATION-spanning malformed trailer can't leak the budget.
                        recv.drop_receiving(streams, sid);
                        rst!(sid, error_code::PROTOCOL_ERROR);
                    }
                }
            }
        }
        kind::DATA => {
            // §6.9.1: the ENTIRE DATA frame payload (incl. Pad Length + Padding) is flow-controlled.
            let flow = payload.len() as i64;
            let data = match data_block(hdr.flags, payload) {
                Some(d) => d,
                None => goaway!(error_code::PROTOCOL_ERROR),
            };
            // §6.9 receive-side CONNECTION accounting runs for EVERY DATA frame — including one on
            // a closed/reset stream whose body we discard — because we buffer eagerly and must
            // replenish the connection window unconditionally. Skipping it on a stream-level early
            // return (or a closed-stream drop) permanently shrinks `conn_recv_window` by `flow`
            // with no WINDOW_UPDATE sent, draining the budget into a spurious connection-wide
            // GOAWAY FLOW_CONTROL_ERROR. A connection-level overrun is itself a GOAWAY.
            recv.conn_recv_window -= flow;
            if recv.conn_recv_window < 0 {
                goaway!(error_code::FLOW_CONTROL_ERROR);
            }
            // Replenish in batches (as nghttp2 and nginx do): once half the advertised window
            // is consumed, ONE WINDOW_UPDATE restores it, instead of one per DATA frame.
            let conn_target = recv.our_initial_window.max(65535);
            if recv.conn_recv_window <= conn_target / 2 {
                let credit = conn_target - recv.conn_recv_window;
                recv.conn_recv_window = conn_target;
                out.frames(|b| frame::write_window_update(b, 0, credit as u32));
            }
            // §5.1/§6.1: DATA on an IDLE stream (never opened, `sid > last_client_stream`) is a
            // connection error; DATA on a CLOSED stream (already completed/reset and removed from
            // the map) is a STREAM error — RST just that stream, do NOT GOAWAY every multiplexed
            // stream over one raced late frame (e.g. the handler responded END_STREAM before the
            // client finished its body). Mirrors the idle-vs-closed split the RST_STREAM and
            // WINDOW_UPDATE arms make via `last_client_stream`. (Connection window settled above.)
            let Some(st) = streams.get_mut(&sid) else {
                // §5.1.1: an even (server-initiated) id can never be client-opened, and an
                // idle (`> last_client_stream`) stream was never opened — both connection
                // errors. A genuinely closed odd stream stays a tolerant RST.
                if sid.is_multiple_of(2) || sid > recv.last_client_stream {
                    goaway!(error_code::PROTOCOL_ERROR);
                }
                // §5.1: frames on a stream WE reset are ignored, not re-reset (#877).
                if recv.sent_reset_ids.contains(sid) {
                    return FrameOutcome::Continue;
                }
                rst!(sid, error_code::STREAM_CLOSED);
            };
            st.recv_window -= flow;
            if st.recv_window < 0 {
                recv.drop_receiving(streams, sid);
                rst!(sid, error_code::FLOW_CONTROL_ERROR);
            }
            let body_len = st.body.len() + data.len();
            if st.content_length.is_some_and(|cl| body_len as u64 > cl) {
                // §8.1.1: DATA past the declared content-length is malformed; reset on the
                // first overrunning frame instead of buffering the excess until END_STREAM.
                rst!(sid, error_code::PROTOCOL_ERROR);
            }
            if body_len > recv.max_request_body {
                // Over the per-stream cap (LiteSpeed maxReqBodySize) with no declared length
                // to reject up front. Dispatch waits for the whole body, so no response has
                // started and the 413 can still be sent.
                reject_too_large!(sid, "413", hdr.flags & flags::END_STREAM == 0);
            }
            // (per-CONNECTION cap) bound the SUM of buffered bodies across streams, not just
            // per-stream — else max_concurrent x max_request_body is reachable on one conn.
            if recv.total_buffered.saturating_add(data.len()) > recv.per_conn_request_body {
                goaway!(error_code::ENHANCE_YOUR_CALM);
            }
            if !data.is_empty() {
                recv.no_progress_frames = 0; // a non-empty DATA byte is forward progress
            }
            // (#236 residual) Server-wide cap shared with the H1/H3 transports and LSAPI:
            // reserve BEFORE extending/accounting so aggregate buffered bodies stay bounded
            // even when every connection is individually under its per-stream/per-conn caps.
            if let Some(b) = &recv.body_budget {
                let lease = st
                    .body_lease
                    .get_or_insert_with(|| hj_core::budget::BodyBufferLease::new(b.clone()));
                if !lease.reserve(data.len() as u64) {
                    // The budget is server-wide: other connections exhausted it, so refuse
                    // this stream (retry-safe, §8.7) rather than this whole connection (#597).
                    rst!(sid, error_code::REFUSED_STREAM);
                }
            }
            recv.total_buffered = recv.total_buffered.saturating_add(data.len());
            st.body.extend_from_slice(data);
            // Refresh the PER-STREAM window (§5.2.2) so a single upload can exceed
            // SETTINGS_INITIAL_WINDOW_SIZE without stalling — batched like the connection
            // window above. Skip it once the stream has ended (no further DATA will arrive).
            if hdr.flags & flags::END_STREAM == 0 && st.recv_window <= recv.our_initial_window / 2 {
                let credit = recv.our_initial_window - st.recv_window;
                st.recv_window = recv.our_initial_window;
                out.frames(|b| frame::write_window_update(b, sid, credit as u32));
            }
            if hdr.flags & flags::END_STREAM != 0
                && streams.get(&sid).is_some_and(|s| s.headers_done)
            {
                complete!(sid);
            }
        }
        kind::RST_STREAM => {
            // §5.1.1: RST_STREAM on an idle (never-opened) stream, or on an even
            // (server-initiated) id the client may not use, is a connection error.
            if sid.is_multiple_of(2) || sid > recv.last_client_stream {
                goaway!(error_code::PROTOCOL_ERROR);
            }
            recv.drop_receiving(streams, sid);
            // (#357) Record the peer's reset UNCONDITIONALLY — even on an id already
            // cleanly closed or fully drained. §5.1 makes ANY later frame on an id that
            // saw a RST_STREAM a stream error (STREAM_CLOSED), so the HEADERS-reuse
            // guard must find it here; reuse-after-self-RST buys a peer nothing (the
            // churn never resets `no_progress_frames`, so a flood still GOAWAYs).
            // Unlike the `cancelled` insert below, this must NOT be gated on a live
            // handler — `cancelled` is consumed on drain, this set is not.
            recv.note_reset(sid);
            // If the handler future is still running in `inflight`, cancel it and mark the stream
            // so the aborted completion is discarded. ONLY record sids with a live future:
            // a RST arriving AFTER the handler already resolved+drained has nothing to cancel,
            // and recording it would leak a permanent `cancelled` entry (no future will ever
            // drain it) that — once enough accumulate on a long-lived connection — fills the
            // cap and silently disables reset-suppression for subsequent resets. The
            // `inflight_sids` handle removal makes the insert precise. The flood cap remains
            // a redundant backstop while the aborted completion waits to drain.
            if let Some(abort) = inflight_sids.remove(&sid) {
                abort.abort();
                if cancelled.len() < recv.max_concurrent.saturating_mul(2) {
                    cancelled.insert(sid);
                }
                // (CVE-2023-44487) The peer reset a stream whose handler is still doing
                // (now-discarded) backend work — the rapid-reset signal. Track the imbalance
                // vs completed responses; a sustained open→reset flood trips the budget below.
                if recv.charge_inflight_reset() {
                    goaway!(error_code::ENHANCE_YOUR_CALM);
                }
            }
            return FrameOutcome::ResetStream(sid);
        }
        // §5.3.1: a stream that depends on itself is a stream error. (We otherwise
        // ignore priority; length/association were validated above.)
        kind::PRIORITY if priority_dependency(hdr.flags, payload, false) == Some(sid) => {
            rst!(sid, error_code::PROTOCOL_ERROR);
        }
        _ => {} // unknown frame types: ignore (§4.1)
    }
    FrameOutcome::Continue
}

/// The request headers just completed and declare a body over `max_request_body` that is
/// still to come. With END_STREAM already set the declared length cannot match the empty
/// body, which is malformed (§8.1.1) and left to `complete!`'s PROTOCOL_ERROR.
fn declared_body_too_large(st: Option<&StreamState>, max_request_body: usize) -> bool {
    st.is_some_and(|st| {
        !st.end_stream
            && st
                .content_length
                .is_some_and(|cl| cl > max_request_body as u64)
    })
}

/// Ask `Config::early_reject` about a stream whose request headers are complete and
/// whose body is still to come.
fn early_reject_response(
    recv: &Recv,
    st: &StreamState,
) -> Option<(http::StatusCode, http::HeaderMap)> {
    let hook = recv.early_reject.as_ref()?;
    let head = super::RequestHead {
        method: st.method.as_ref()?,
        uri: st.path.as_ref()?,
        authority: st.authority.as_ref(),
        headers: &st.headers,
    };
    (hook.0)(&head)
}

/// What a body-pending stream opened with the request header `block` is charged.
#[cfg(test)]
pub(super) fn pending_header_charge_of(block: &[u8]) -> u32 {
    let mut st = StreamState::default();
    let mut dec = Decoder::new(4096, usize::MAX);
    assert!(matches!(
        decode_block_from(&mut dec, &mut st, block),
        Decoded::Ok
    ));
    pending_header_charge(&st)
}

/// Outcome of decoding a header block.
enum Decoded {
    /// Valid request headers, captured into `st`.
    Ok,
    /// HPACK decode failure — connection-fatal COMPRESSION_ERROR (§4.3).
    Compression,
    /// The decoded list exceeded SETTINGS_MAX_HEADER_LIST_SIZE. The block was fully
    /// decoded (HPACK state intact), so only this stream is answered (431): one oversized
    /// request must not tear down a pooled connection carrying other clients' streams (#595).
    TooLarge,
    /// A malformed request per §8.1.2 (bad pseudo-headers, uppercase names,
    /// connection-specific headers, …) — a stream error (RST_STREAM PROTOCOL_ERROR).
    Malformed,
}

/// Decode the accumulated header block into `st` (pseudo-headers + HeaderMap), validating
/// it against RFC 7540 §8.1.2: pseudo-headers precede regular fields and are the known
/// request set without duplicates (`:method`/`:scheme`/`:path` required); field names are
/// lowercase; connection-specific headers are rejected and `TE` may only be `trailers`.
fn decode_block(dec: &mut Decoder, st: &mut StreamState) -> Decoded {
    // Multi-frame (CONTINUATION) path: move the accumulated block out so the decode
    // callback can borrow `st` mutably. A single-frame HEADERS decodes in place via
    // `decode_block_from` (zero-copy from the read buffer), skipping this take.
    let block = std::mem::take(&mut st.header_block);
    decode_block_from(dec, st, &block)
}

fn decode_discard_header_block(dec: &mut Decoder, block: &[u8]) -> bool {
    // An over-cap list was still decoded to the end, so the table is in sync and the
    // block is consumed; only a real decode error desyncs the connection.
    matches!(
        dec.decode_octets(block, |_, _| {}),
        Ok(()) | Err(crate::hpack::Error::HeaderListTooLarge)
    )
}

/// Decode a complete HPACK header block into `st`. `block` may borrow the connection
/// read buffer directly (single-frame HEADERS, zero-copy) or an owned accumulation
/// buffer (multi-frame CONTINUATION); it MUST NOT alias `st`, since the emit closure
/// borrows `st` mutably while the decoder reads `block`.
fn decode_block_from(dec: &mut Decoder, st: &mut StreamState, block: &[u8]) -> Decoded {
    // A header block that arrives after the request headers are already complete is a
    // trailer section (§8.1): it carries no pseudo-headers and requires none.
    let is_trailers = st.headers_done;
    let mut seen_regular = false;
    let mut malformed = false;
    // (security #264) Track the regular `host` field: a second line is malformed
    // (mirrors the H1 dup-Host reject) and a host disagreeing with :authority is
    // malformed per RFC 9113 §8.3.1 — build_request REPLACES Host with :authority,
    // so forwarding both verbatim would inject a second HTTP_HOST value downstream.
    let mut host_value: Option<http::HeaderValue> = None;
    let mut scheme_is_http = false;
    let mut path_is_asterisk = false;
    let mut seen = [false; 4]; // :method, :scheme, :path, :authority
    let result = dec.decode_octets(block, |name, value| {
        if malformed {
            return;
        }
        if name.first() == Some(&b':') {
            if is_trailers || seen_regular {
                malformed = true; // pseudo-header in trailers, or after a regular field
                return;
            }
            // Pseudo-header values are URI components / a method token: non-UTF-8 octets
            // are malformed at stream scope, never an HPACK (connection) error.
            let (Ok(name), Ok(value)) = (std::str::from_utf8(name), std::str::from_utf8(value))
            else {
                malformed = true;
                return;
            };
            let idx = match name {
                ":method" => 0,
                ":scheme" => 1,
                ":path" => 2,
                ":authority" => 3,
                _ => {
                    malformed = true; // unknown or response (:status) pseudo-header
                    return;
                }
            };
            if seen[idx] {
                malformed = true; // duplicate pseudo-header
                return;
            }
            seen[idx] = true;
            match name {
                // Parse to the typed form now (value is still borrowed from the HPACK
                // buffer). A conversion failure is a §8.1.2 malformed request → RST, exactly
                // as the old `build_request` rejection (builder error → None → PROTOCOL_ERROR).
                ":method" => match http::Method::from_bytes(value.as_bytes()) {
                    Ok(m) => st.method = Some(m),
                    Err(_) => {
                        malformed = true;
                        return;
                    }
                },
                // RFC 9113 §8.3.1: :path MUST be origin-form (path-absolute, begins with
                // "/") or "*" for OPTIONS — NEVER absolute-form. An absolute-form :path
                // carrying its own scheme/authority is malformed AND dangerous: it lets
                // uri().host() disagree with the routed :authority/Host downstream (the
                // foreign-host CDN-cache-protection bypass). Reject anything with a scheme
                // or authority.
                ":path" => {
                    // Check the raw value before `http::Uri` parsing: that parser accepts a
                    // fragment and silently drops `#...`, but fragments are not request-target
                    // data and are outside the HTTP/2 :path grammar.
                    if value.contains('#') || (value != "*" && !value.starts_with('/')) {
                        malformed = true;
                        return;
                    }
                    match http::Uri::try_from(value) {
                        Ok(u) if u.scheme().is_none() && u.authority().is_none() => {
                            path_is_asterisk = value == "*";
                            st.path = Some(u)
                        }
                        _ => {
                            malformed = true;
                            return;
                        }
                    }
                }
                ":authority" => {
                    match (
                        hj_core::valid_uri_authority(value),
                        http::HeaderValue::from_str(value),
                    ) {
                        (true, Ok(v)) => st.authority = Some(v),
                        _ => {
                            malformed = true;
                            return;
                        }
                    }
                }
                ":scheme" => {
                    if !hj_core::valid_uri_scheme(value) {
                        malformed = true;
                        return;
                    }
                    // Routing continues to use the listener scheme, as before. This flag is
                    // only for RFC 9113's http/https-specific userinfo restriction.
                    scheme_is_http =
                        value.eq_ignore_ascii_case("http") || value.eq_ignore_ascii_case("https");
                }
                _ => unreachable!("known pseudo-header matched above"),
            }
        } else {
            seen_regular = true;
            let Ok(name) = std::str::from_utf8(name) else {
                malformed = true; // not a token
                return;
            };
            if name.bytes().any(|b| b.is_ascii_uppercase()) {
                malformed = true; // §8.1.2: field names must be lowercase
                return;
            }
            if hj_core::is_connection_specific_request_header(name) {
                malformed = true; // §8.1.2.2: connection-specific header (shared h2/h3 list)
                return;
            }
            if name == "te" && !value.eq_ignore_ascii_case(b"trailers") {
                malformed = true; // §8.1.2.2: TE may only be "trailers"
                return;
            }
            // §8.2.1 (RFC 9113): a field name/value that fails validation makes the message
            // malformed — it is NOT silently dropped — because an unvalidated field can enable
            // request smuggling once forwarded to a backend over HTTP/1.x (httpjet is an
            // intermediary; cf. §10.3). `HeaderName::from_bytes` rejects control/non-token bytes
            // and a bare colon; `HeaderValue::from_bytes` rejects NUL/CR/LF but, like H1 and H3,
            // admits obs-text; we add the §8.2.1 rule that a value MUST NOT start or end with
            // SP/HTAB.
            let vb = value;
            let edge_ws =
                matches!(vb.first(), Some(b' ' | b'\t')) || matches!(vb.last(), Some(b' ' | b'\t'));
            match (
                http::HeaderName::from_bytes(name.as_bytes()),
                http::HeaderValue::from_bytes(value),
            ) {
                (Ok(n), Ok(v)) if !edge_ws => {
                    if is_trailers {
                        // Trailer fields obey the same field syntax and connection-header
                        // rules, but valid trailers are discarded after HPACK decoding. This
                        // keeps the dynamic table synchronized without forwarding trailers as
                        // ordinary request headers.
                        return;
                    }
                    if name == "content-length" {
                        // (security #264) Digit-only, mirroring hj-core/H1's #232 strict
                        // resolver: Rust's unsigned parse() accepts a leading '+', which
                        // H1/H3 reject for the same bytes — a per-protocol divergence.
                        if value.is_empty() || !value.iter().all(|b| b.is_ascii_digit()) {
                            malformed = true;
                            return;
                        }
                        // Overflow (not encoding) is the only parse failure left.
                        match std::str::from_utf8(value).unwrap_or("").parse::<u64>() {
                            // A second, conflicting content-length is malformed (§8.1.2.6).
                            Ok(cl) if st.content_length.is_none_or(|prev| prev == cl) => {
                                st.content_length = Some(cl)
                            }
                            _ => {
                                malformed = true;
                                return;
                            }
                        }
                    }
                    if n == http::header::HOST {
                        if host_value.is_some() {
                            malformed = true; // duplicate Host line
                            return;
                        }
                        host_value = Some(v.clone());
                    }
                    st.headers.append(n, v);
                }
                _ => malformed = true,
            }
        }
    });
    match result {
        Ok(()) => {}
        Err(crate::hpack::Error::HeaderListTooLarge) => return Decoded::TooLarge,
        Err(_) => return Decoded::Compression,
    }
    if malformed {
        return Decoded::Malformed; // a §8.1.2 violation
    }
    if !is_trailers {
        // Required request pseudo-headers (§8.1.2.3).
        if !seen[0] || !seen[1] || !seen[2] {
            return Decoded::Malformed;
        }
        // (#1015) RFC 9113 §8.5: a CONNECT omits :scheme/:path (so a proper one already
        // failed above) and extended CONNECT is never advertised, so one that carries them
        // is malformed — the same verdict the H3 transport reaches. There is no tunnel to
        // offer, and it must not reach the pipeline (PHP, hj-proxy) as an ordinary method.
        if st.method.as_ref() == Some(&http::Method::CONNECT) {
            return Decoded::Malformed;
        }
        // RFC 9112 §3.2.4: asterisk-form is only a server-wide OPTIONS request.
        if path_is_asterisk && st.method.as_ref() != Some(&http::Method::OPTIONS) {
            return Decoded::Malformed;
        }
        // RFC 3986 permits userinfo and an empty reg-name for a generic
        // :authority, while RFC 9113 forbids both for HTTP(S).
        if let Some(authority) = st.authority.as_ref() {
            let Ok(text) = authority.to_str() else {
                return Decoded::Malformed;
            };
            if !hj_core::valid_uri_authority(text)
                || (scheme_is_http && !hj_core::valid_http_authority(text))
            {
                return Decoded::Malformed;
            }
        }
        // The regular Host field always uses HTTP host[:port] syntax, including
        // when it supplies the effective authority for a non-HTTP URI scheme.
        if let Some(host) = host_value.as_ref() {
            let Ok(text) = host.to_str() else {
                return Decoded::Malformed;
            };
            if !hj_core::valid_http_authority(text) {
                return Decoded::Malformed;
            }
        }
        // (security #264) :authority + Host must agree when both are present
        // (RFC 9113 §8.3.1); build_request replaces Host with :authority, so a
        // disagreeing pair would smuggle two different hosts downstream.
        if let (Some(a), Some(h)) = (&st.authority, &host_value) {
            if a.as_bytes() != h.as_bytes() {
                return Decoded::Malformed;
            }
        }
        st.headers_done = true;
    }
    Decoded::Ok
}

#[cfg(test)]
mod pseudo_header_tests {
    use super::*;
    use crate::hpack::Encoder;

    fn decode(headers: &[(&str, &str)]) -> Decoded {
        let mut encoder = Encoder::new();
        let mut block = Vec::new();
        for (name, value) in headers {
            encoder.encode_header(&mut block, name, value);
        }
        let mut decoder = Decoder::new(4096, 8192);
        let mut state = StreamState::default();
        decode_block_from(&mut decoder, &mut state, &block)
    }

    #[test]
    fn rejects_invalid_scheme_authority_and_fragment_path_syntax() {
        for scheme in ["", "1http", "http space", "http:"] {
            assert!(matches!(
                decode(&[(":method", "GET"), (":scheme", scheme), (":path", "/")]),
                Decoded::Malformed
            ));
        }
        for authority in [
            "bad host",
            "host/path",
            "[::1",
            "example.com:abc",
            "user@@example.com",
        ] {
            assert!(matches!(
                decode(&[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":path", "/"),
                    (":authority", authority),
                ]),
                Decoded::Malformed
            ));
        }
        assert!(matches!(
            decode(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/safe#ignored"),
            ]),
            Decoded::Malformed
        ));
        for authority in [":443", "user@example.com"] {
            assert!(matches!(
                decode(&[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":path", "/"),
                    (":authority", authority),
                ]),
                Decoded::Malformed
            ));
        }
        for host in ["bad host", "user@example.com", "example.com:abc", ":443"] {
            assert!(matches!(
                decode(&[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":path", "/"),
                    ("host", host),
                ]),
                Decoded::Malformed
            ));
        }
        assert!(matches!(
            decode(&[
                (":method", "GET"),
                (":scheme", "web+custom"),
                (":path", "/"),
                ("host", "user@example.com"),
            ]),
            Decoded::Malformed
        ));
    }

    #[test]
    fn connect_is_malformed_with_or_without_scheme_and_path() {
        assert!(matches!(
            decode(&[
                (":method", "CONNECT"),
                (":scheme", "https"),
                (":path", "/"),
                (":authority", "example.com:443"),
            ]),
            Decoded::Malformed
        ));
        assert!(matches!(
            decode(&[(":method", "CONNECT"), (":authority", "example.com:443")]),
            Decoded::Malformed
        ));
        assert!(matches!(
            decode(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/"),
                (":authority", "example.com:443"),
            ]),
            Decoded::Ok
        ));
    }

    #[test]
    fn asterisk_path_is_valid_only_for_options() {
        assert!(matches!(
            decode(&[(":method", "GET"), (":scheme", "https"), (":path", "*")]),
            Decoded::Malformed
        ));
        assert!(matches!(
            decode(&[(":method", "OPTIONS"), (":scheme", "https"), (":path", "*"),]),
            Decoded::Ok
        ));
    }

    #[test]
    fn accepts_non_http_scheme_arbitrary_pseudo_order_and_ipv6_authority() {
        assert!(matches!(
            decode(&[
                (":path", "/resource?x=1"),
                (":authority", "[2001:db8::1]:8443"),
                (":method", "GET"),
                (":scheme", "web+custom"),
            ]),
            Decoded::Ok
        ));
        assert!(matches!(
            decode(&[
                (":method", "GET"),
                (":scheme", "web+custom"),
                (":authority", "[v1.a-b]:443"),
                (":path", "/"),
            ]),
            Decoded::Ok
        ));
    }

    #[test]
    fn rejects_userinfo_only_for_http_and_https_authorities() {
        assert!(matches!(
            decode(&[
                (":authority", "user@example.com:443"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ]),
            Decoded::Malformed
        ));
        assert!(matches!(
            decode(&[
                (":authority", "user@example.com"),
                (":path", "/"),
                (":scheme", "web+custom"),
                (":method", "GET"),
            ]),
            Decoded::Ok
        ));
        // RFC 3986's generic `reg-name` permits zero characters, so a custom
        // scheme can carry an explicitly empty authority. HTTP(S) cannot.
        assert!(matches!(
            decode(&[
                (":authority", ""),
                (":path", "/"),
                (":scheme", "web+custom"),
                (":method", "GET"),
            ]),
            Decoded::Ok
        ));
        assert!(matches!(
            decode(&[
                (":authority", ""),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ]),
            Decoded::Malformed
        ));
    }
}

/// Translate the captured pseudo-headers, decoded HeaderMap, and buffered body into a
/// Request — moving the HeaderMap in without re-copying its entries.
fn build_request(mut st: StreamState) -> Option<Request> {
    let method = st.method.take()?;
    let uri = st.path.take()?;

    // h2 carries the host in :authority; surface it as a Host header for the pipeline.
    if let Some(v) = st.authority.take() {
        st.headers.insert(http::header::HOST, v);
    }

    let body: IncomingBody = if st.body.is_empty() {
        hj_core::empty_incoming()
    } else {
        let bytes = match st.body_lease.take() {
            Some(mut lease) => {
                // The decoded headers move into the request here; only the body stays charged.
                lease.release(u64::from(st.header_charge));
                lease.into_bytes(st.body)
            }
            None => Bytes::from(st.body),
        };
        http_body_util::Full::new(bytes)
            .map_err(|e| Box::new(e) as hj_core::BoxError)
            .boxed()
    };
    // Construct the Request directly so the pre-parsed Method/Uri MOVE in (no builder TryFrom
    // re-conversion, no per-request alloc); version stays the builder's HTTP/1.1 default.
    //
    // The protocol is delivered to `pipeline::handle` as a call argument (the service closure in
    // httpjet/src/server.rs) and `ctx.protocol` is set from it — nothing in the request pipeline
    // reads a `Proto` request extension. Inserting one here would only force the lazy
    // `http::Extensions` backing Box to allocate on every request (the hot HIT path inserts no
    // other request extension), so we deliberately omit it.
    let mut req = Request::new(body);
    *req.method_mut() = method;
    *req.uri_mut() = uri;
    *req.headers_mut() = std::mem::take(&mut st.headers);
    // §8.2.3: rejoin split `cookie` field lines with "; " so PHP/cache/rewrite see
    // the standard single-line form (the generic ", " join corrupts sessions).
    hj_core::coalesce_cookie_crumbs(req.headers_mut());
    Some(req)
}

/// §8.1: if a request carries `Expect: 100-continue` and a body is still to come, send an interim
/// `100 Continue` so a client that withholds its body pending a go-ahead doesn't stall on its own
/// timeout.
/// Interim 1xx HEADERS carry END_HEADERS but never END_STREAM (an END_STREAM 1xx is malformed).
fn maybe_send_100_continue(st: &StreamState, sid: u32, out: &mut OutQueue, enc: &mut Encoder) {
    if st.end_stream {
        return; // no request body is coming → nothing to continue
    }
    let wants = st
        .headers
        .get(http::header::EXPECT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
    if wants {
        // Through the shared encoder: a pending SETTINGS_HEADER_TABLE_SIZE change must
        // lead the first block after it (RFC 7541 §4.2), and this may be that block (#681).
        let mut block = Vec::with_capacity(8);
        enc.encode_header(&mut block, ":status", "100");
        out.frames(|b| frame::write_frame(b, kind::HEADERS, flags::END_HEADERS, sid, &block));
    }
}
