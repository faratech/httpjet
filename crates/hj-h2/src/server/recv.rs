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
/// (CVE-2023-44487) Max net "reset-while-in-flight minus completed" imbalance before we
/// treat the connection as a rapid-reset flood and GOAWAY. Generous so a client that
/// cancels a burst of requests (e.g. a browser navigating away) while completing others
/// never trips it; an attacker doing only open→reset churn hits it fast.
const RAPID_RESET_BUDGET: u32 = 200;
/// (CVE-2019-9512/9515/9518 class) Max frames processed since the last forward progress before
/// we treat the connection as a no-progress flood and GOAWAY. Generous: real traffic resets
/// this to 0 on any progress (a dispatched request, a non-empty DATA byte, or a window grant),
/// so a legitimate client never approaches it; pure empty-DATA / PING / SETTINGS / PRIORITY
/// churn hits it in a fraction of a second.
const NO_PROGRESS_BUDGET: u32 = 10_000;

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
    /// Stop reading further frames (peer GOAWAY, or a connection error already queued).
    StopReading,
    /// Peer granted send-window credit (WINDOW_UPDATE). `stream_id == 0` = connection-level.
    /// The send state lives in `serve`, so window changes surface here.
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    /// Peer reset a stream (RST_STREAM): drop any in-flight outgoing body for it.
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
            out.frames(|b| frame::write_goaway(b, recv.last_client_stream, $code));
            return FrameOutcome::StopReading;
        }};
    }
    // Stream-level error: reset the stream, keep the connection.
    macro_rules! rst {
        ($sid:expr_2021, $code:expr_2021) => {{
            out.frames(|b| frame::write_rst_stream(b, $sid, $code));
            return FrameOutcome::Continue;
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
    // Build the request for a completed stream and push its handler future.
    macro_rules! complete {
        ($sid:expr_2021) => {{
            if let Some(st) = streams.remove(&$sid) {
                recv.no_progress_frames = 0; // a dispatched request is forward progress
                recv.total_buffered = recv.total_buffered.saturating_sub(st.body.len());
                if st.content_length.is_some_and(|cl| cl != st.body.len() as u64) {
                    // §8.1.2.6: declared content-length must equal the DATA bytes received.
                    out.frames(|b| frame::write_rst_stream(b, $sid, error_code::PROTOCOL_ERROR));
                } else {
                    // §8.3.1: a HEAD response carries the GET's headers but never a body — captured
                    // here so the writer sends headers-only regardless of what the handler returns.
                    let is_head = st.method.as_ref() == Some(&http::Method::HEAD);
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
                        None => out.frames(|b| frame::write_rst_stream(b, $sid, error_code::PROTOCOL_ERROR)),
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
                // Only a STREAM-level grant (sid != 0) can unblock a blocked response body =
                // real forward progress. A connection-level WINDOW_UPDATE (sid == 0) flood
                // (CVE-2019-9512 class) must NOT reset the no-progress counter, or an attacker
                // sending endless +1 conn-window updates indefinitely defers the idle-abuse GOAWAY.
                if sid != 0 {
                    recv.no_progress_frames = 0;
                }
                return FrameOutcome::WindowUpdate {
                    stream_id: sid,
                    increment,
                };
            }
            None => goaway!(error_code::FRAME_SIZE_ERROR),
        },
        kind::GOAWAY => return FrameOutcome::StopReading,
        kind::HEADERS => {
            let opens_new_stream = !streams.contains_key(&sid);
            if opens_new_stream && sid.is_multiple_of(2) {
                goaway!(error_code::PROTOCOL_ERROR);
            }
            if opens_new_stream && sid <= recv.last_client_stream {
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
                if let Some(s) = streams.remove(&sid) {
                    recv.total_buffered = recv.total_buffered.saturating_sub(s.body.len());
                }
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
            let st = streams.entry(sid).or_insert_with(|| StreamState {
                recv_window: iw,
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
                        if let Some(st) = streams.get(&sid) {
                            maybe_send_100_continue(st, sid, out);
                        }
                        if streams.get(&sid).is_some_and(|s| s.end_stream) {
                            complete!(sid);
                        }
                    }
                    Decoded::Compression => goaway!(error_code::COMPRESSION_ERROR),
                    Decoded::Malformed => {
                        // A malformed trailer arrives AFTER the body was buffered, so un-account it
                        // (mirror the other removal sites) — else `total_buffered` leaks by the body
                        // length for the connection's life, eventually tripping a spurious
                        // GOAWAY(ENHANCE_YOUR_CALM) on a later legitimate DATA byte.
                        if let Some(s) = streams.remove(&sid) {
                            recv.total_buffered = recv.total_buffered.saturating_sub(s.body.len());
                        }
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
                        if let Some(st) = streams.get(&sid) {
                            maybe_send_100_continue(st, sid, out);
                        }
                        if streams.get(&sid).is_some_and(|s| s.end_stream) {
                            complete!(sid);
                        }
                    }
                    Decoded::Compression => goaway!(error_code::COMPRESSION_ERROR),
                    Decoded::Malformed => {
                        // Same as the HEADERS arm: un-account any buffered body before dropping the
                        // stream so a CONTINUATION-spanning malformed trailer can't leak the budget.
                        if let Some(s) = streams.remove(&sid) {
                            recv.total_buffered = recv.total_buffered.saturating_sub(s.body.len());
                        }
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
            if flow > 0 {
                recv.conn_recv_window += flow;
                out.frames(|b| frame::write_window_update(b, 0, flow as u32));
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
                rst!(sid, error_code::STREAM_CLOSED);
            };
            st.recv_window -= flow;
            if st.recv_window < 0 {
                if let Some(s) = streams.remove(&sid) {
                    recv.total_buffered = recv.total_buffered.saturating_sub(s.body.len());
                }
                rst!(sid, error_code::FLOW_CONTROL_ERROR);
            }
            if st.body.len() + data.len() > recv.max_request_body {
                // Buffered request body exceeds the per-stream cap (LiteSpeed maxReqBodySize) —
                // the custom stack buffers the body before dispatch, so cap it and reset.
                if let Some(s) = streams.remove(&sid) {
                    recv.total_buffered = recv.total_buffered.saturating_sub(s.body.len());
                }
                rst!(sid, error_code::REFUSED_STREAM);
            }
            // (per-CONNECTION cap) bound the SUM of buffered bodies across streams, not just
            // per-stream — else max_concurrent x max_request_body is reachable on one conn.
            if recv.total_buffered.saturating_add(data.len()) > recv.per_conn_request_body {
                goaway!(error_code::ENHANCE_YOUR_CALM);
            }
            if !data.is_empty() {
                recv.no_progress_frames = 0; // a non-empty DATA byte is forward progress
            }
            recv.total_buffered = recv.total_buffered.saturating_add(data.len());
            st.body.extend_from_slice(data);
            // Refresh the PER-STREAM window on receipt (§5.2.2) — which was previously never
            // sent — so a single upload can exceed SETTINGS_INITIAL_WINDOW_SIZE without
            // stalling. Skip it once the stream has ended (no further DATA will arrive).
            if flow > 0 && hdr.flags & flags::END_STREAM == 0 {
                st.recv_window += flow;
                out.frames(|b| frame::write_window_update(b, sid, flow as u32));
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
            if let Some(s) = streams.remove(&sid) {
                recv.total_buffered = recv.total_buffered.saturating_sub(s.body.len());
            }
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
                recv.rst_unanswered = recv.rst_unanswered.saturating_add(1);
                if recv.rst_unanswered > RAPID_RESET_BUDGET {
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

/// Outcome of decoding a header block.
enum Decoded {
    /// Valid request headers, captured into `st`.
    Ok,
    /// HPACK decode failure — connection-fatal COMPRESSION_ERROR (§4.3).
    Compression,
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
    dec.decode(block, |_, _| {}).is_ok()
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
    let mut seen = [false; 4]; // :method, :scheme, :path, :authority
    let ok = dec
        .decode(block, |name, value| {
            if malformed {
                return;
            }
            if name.starts_with(':') {
                if is_trailers || seen_regular {
                    malformed = true; // pseudo-header in trailers, or after a regular field
                    return;
                }
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
                    // or authority. (CONNECT — which omits :path/:scheme — is already rejected
                    // by the required-pseudo-header set check.)
                    ":path" => match http::Uri::try_from(value) {
                        Ok(u) if u.scheme().is_none() && u.authority().is_none() => {
                            st.path = Some(u)
                        }
                        _ => {
                            malformed = true;
                            return;
                        }
                    },
                    // An un-representable authority is dropped (no Host header), mirroring the
                    // old `HeaderValue::from_str(a).ok()` skip — it does not reject the request.
                    ":authority" => {
                        if let Ok(v) = http::HeaderValue::from_str(value) {
                            st.authority = Some(v);
                        }
                    }
                    _ => {} // :scheme validated; the actual scheme is implied by the listener
                }
            } else {
                seen_regular = true;
                if is_trailers {
                    // RFC 9113 §8.1: a trailer section is decoded only to keep the connection
                    // HPACK dynamic table in sync — its fields are DISCARDED, never appended to
                    // the request header map handed to the backend. A trailer field must not
                    // masquerade as a request header (a smuggling/confusion surface once forwarded
                    // over HTTP/1.x); this matches the h3 path, which drops request trailers.
                    return;
                }
                if name.bytes().any(|b| b.is_ascii_uppercase()) {
                    malformed = true; // §8.1.2: field names must be lowercase
                    return;
                }
                if hj_core::is_connection_specific_request_header(name) {
                    malformed = true; // §8.1.2.2: connection-specific header (shared h2/h3 list)
                    return;
                }
                match name {
                    "te" if !value.eq_ignore_ascii_case("trailers") => {
                        malformed = true; // §8.1.2.2: TE may only be "trailers"
                        return;
                    }
                    "content-length" => match value.parse::<u64>() {
                        // A second, conflicting content-length is malformed (§8.1.2.6).
                        Ok(cl) if st.content_length.is_none_or(|prev| prev == cl) => {
                            st.content_length = Some(cl)
                        }
                        _ => {
                            malformed = true;
                            return;
                        }
                    },
                    _ => {}
                }
                // §8.2.1 (RFC 9113): a field name/value that fails validation makes the message
                // malformed — it is NOT silently dropped — because an unvalidated field can enable
                // request smuggling once forwarded to a backend over HTTP/1.x (httpjet is an
                // intermediary; cf. §10.3). `HeaderName::from_bytes` rejects control/non-token bytes
                // and a bare colon; `HeaderValue::from_str` rejects NUL/CR/LF; we add the §8.2.1 rule
                // that a value MUST NOT start or end with SP/HTAB.
                let vb = value.as_bytes();
                let edge_ws = matches!(vb.first(), Some(b' ' | b'\t'))
                    || matches!(vb.last(), Some(b' ' | b'\t'));
                match (
                    http::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(value),
                ) {
                    (Ok(n), Ok(v)) if !edge_ws => {
                        st.headers.append(n, v);
                    }
                    _ => malformed = true,
                }
            }
        })
        .is_ok();
    if !ok {
        return Decoded::Compression;
    }
    if malformed {
        return Decoded::Malformed; // a §8.1.2 violation
    }
    if !is_trailers {
        // Required request pseudo-headers (§8.1.2.3).
        if !seen[0] || !seen[1] || !seen[2] {
            return Decoded::Malformed;
        }
        st.headers_done = true;
    }
    Decoded::Ok
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
        http_body_util::Full::new(Bytes::from(st.body))
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
/// timeout. `:status: 100` is encoded by hand as an HPACK literal-without-indexing on static name
/// index 8 (`:status`) with the literal value `100` — it does not mutate the dynamic table, so the
/// connection's HPACK encoder/decoder stay in sync without routing through the shared `Encoder`.
/// Interim 1xx HEADERS carry END_HEADERS but never END_STREAM (an END_STREAM 1xx is malformed).
fn maybe_send_100_continue(st: &StreamState, sid: u32, out: &mut OutQueue) {
    if st.end_stream {
        return; // no request body is coming → nothing to continue
    }
    let wants = st
        .headers
        .get(http::header::EXPECT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
    if wants {
        out.frames(|b| {
            frame::write_frame(
                b,
                kind::HEADERS,
                flags::END_HEADERS,
                sid,
                &[0x08, 0x03, b'1', b'0', b'0'],
            )
        });
    }
}
