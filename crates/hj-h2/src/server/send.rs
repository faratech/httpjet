//! Outbound HTTP/2 response writing.
//!
//! Encodes the response head (HPACK) and writes the body under send flow control:
//! [`begin_response`] registers each response, [`pump_streams`]/[`pump_one_frame`] write
//! DATA frames as the connection + per-stream windows allow, and streaming bodies (LSAPI /
//! proxy / SSE) and async-streamed files are pulled chunk-by-chunk ([`pull_next`] /
//! [`file_stream_body`]) into their stream buffers ([`apply_pull`]).

use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::future::Future;

use crate::hpack::Encoder;
use bytes::Bytes;
use hj_core::{Body, Response};

use super::OutQueue;
use super::state::{OutStream, PeerSettings};
use crate::frame::{self, FrameHeader, error_code, flags, kind};

/// Result of pulling one frame from a streaming body: the body handed back (so the next
/// chunk can be pulled), and either a data chunk, an error, or EOF (`None`).
pub(super) type PullResult = (
    u32,
    hj_core::StreamBody,
    Option<Result<Bytes, hj_core::BoxError>>,
);

/// In-flight next-chunk pulls for active streaming bodies, multiplexed on the connection
/// task alongside the request reads and handler futures.
pub(super) type Pulls = futures_util::stream::FuturesUnordered<
    std::pin::Pin<Box<dyn Future<Output = PullResult> + Send>>,
>;

/// Pull the next DATA chunk from a streaming body (skipping trailer frames — trailers are
/// not yet forwarded), returning the body so the caller can pull again.
async fn pull_next(
    sid: u32,
    mut body: hj_core::StreamBody,
    cancel: tokio_util::sync::CancellationToken,
) -> PullResult {
    use http_body_util::BodyExt;
    loop {
        let frame = tokio::select! {
            biased;
            _ = cancel.cancelled() => return (sid, body, None),
            frame = body.frame() => frame,
        };
        match frame {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => return (sid, body, Some(Ok(data))),
                Err(_non_data) => continue, // trailers/metadata: skip
            },
            Some(Err(e)) => return (sid, body, Some(Err(e))),
            None => return (sid, body, None),
        }
    }
}

/// A `Link` header value worth sending as a 103 Early Hint — i.e. a `rel=preload` or
/// `rel=preconnect` resource hint (quoted or bare, case-insensitive). Other relations
/// (canonical, alternate, …) are not actionable preloads and stay out of the 103.
/// Scans the raw value bytes in place — the old `to_str` + `to_ascii_lowercase` did a
/// validation pass plus a heap copy of every Link value on every response. Every match
/// site of the four old substring needles starts with `rel=`, so anchoring there and
/// prefix-testing the (optionally quoted) relation is needle-for-needle equivalent.
pub fn is_early_hint_link(v: &http::HeaderValue) -> bool {
    fn rel_at(rest: &[u8]) -> bool {
        for rel in [&b"preload"[..], b"preconnect"] {
            // Bare form: the old needle `rel=preload` matched as a substring, i.e. a
            // prefix here with no terminator required.
            if rest.len() >= rel.len() && rest[..rel.len()].eq_ignore_ascii_case(rel) {
                return true;
            }
            // Quoted form: the old needle `rel="preload"` included the closing quote.
            if rest.first() == Some(&b'"')
                && rest.len() > rel.len() + 1
                && rest[1..=rel.len()].eq_ignore_ascii_case(rel)
                && rest[rel.len() + 1] == b'"'
            {
                return true;
            }
        }
        false
    }
    let b = v.as_bytes();
    b.windows(4)
        .enumerate()
        .any(|(i, w)| w.eq_ignore_ascii_case(b"rel=") && rel_at(&b[i + 4..]))
}

/// Write a field block as a HEADERS frame plus any CONTINUATION frames, never exceeding the
/// peer's SETTINGS_MAX_FRAME_SIZE (§4.2: an endpoint MUST NOT send a frame larger than that;
/// §4.3: a field block too large for one frame is continued in CONTINUATION frames). The
/// leading HEADERS frame carries `lead_flags` (e.g. END_STREAM); END_HEADERS rides the last
/// frame of the run. The common single-frame case keeps the original one-write fast path.
fn write_field_block(
    b: &mut Vec<u8>,
    stream_id: u32,
    lead_flags: u8,
    block: &[u8],
    max_frame: usize,
) {
    let max = max_frame.max(1);
    if block.len() <= max {
        frame::write_frame(
            b,
            kind::HEADERS,
            lead_flags | flags::END_HEADERS,
            stream_id,
            block,
        );
        return;
    }
    let (first, mut rest) = block.split_at(max);
    frame::write_frame(b, kind::HEADERS, lead_flags, stream_id, first);
    while rest.len() > max {
        let (chunk, tail) = rest.split_at(max);
        frame::write_frame(b, kind::CONTINUATION, 0, stream_id, chunk);
        rest = tail;
    }
    frame::write_frame(b, kind::CONTINUATION, flags::END_HEADERS, stream_id, rest);
}

/// Encode the response head (HPACK) and register its body for incremental, flow-controlled
/// writing. Empty bodies finish immediately (END_STREAM on HEADERS); in-memory bodies are
/// queued whole; streaming bodies are registered for async chunk pulls. [`pump_streams`]
/// does the actual DATA writing.
#[allow(clippy::too_many_arguments)]
pub(super) fn begin_response(
    stream_id: u32,
    is_head: bool,
    response: Response,
    enc: &mut Encoder,
    out: &mut OutQueue,
    outstreams: &mut FxHashMap<u32, OutStream>,
    send_schedule: &mut VecDeque<u32>,
    pending_window: &mut FxHashMap<u32, i64>,
    peer: &PeerSettings,
    block_scratch: &mut Vec<u8>,
) {
    let (mut head, body) = response.into_parts();
    // §8.2.2: connection-specific ("hop-by-hop") fields are illegal on an h2 response — strip
    // them before encoding so a backend that emits e.g. `Connection`/`Transfer-Encoding`
    // (PHP over LSAPI, a proxied upstream) can't produce a malformed frame stream.
    hj_core::strip_hop_by_hop_response(&mut head.headers);
    let streaming_unknown_len = matches!(body, Body::Stream(_));
    let body_forbidden = hj_core::response_body_forbidden(is_head, head.status);
    hj_core::sanitize_h2_h3_body_headers(
        &mut head.headers,
        is_head,
        head.status,
        streaming_unknown_len,
    );
    // §4.2: every frame we emit for this response (HEADERS/CONTINUATION/DATA) is bounded by the
    // peer's advertised max frame size.
    let mf = (peer.max_frame_size as usize).max(1);

    // 103 Early Hints (RFC 8297): if the response declares preload/preconnect `Link` hints,
    // send them as an interim 103 over this stream BEFORE the final response, so the client —
    // and Cloudflare, which forwards origin 103s to browsers — can start fetching critical
    // assets while the (often large/slow) body is still in flight. The hints stay on the
    // final response too. Same connection HPACK encoder; END_HEADERS but NOT END_STREAM
    // (§8.1 allows one or more interim 1xx HEADERS before the final response HEADERS).
    if head.status.is_success() {
        // One scan decides hint-ness per Link value (bit i ⇒ value i is a hint), so the
        // emit loop below doesn't re-scan ~2.5 KB of Link values a second time per
        // response. >64 Link values (never seen in practice) fall back to a re-check.
        let mut hints: u64 = 0;
        for (i, v) in head
            .headers
            .get_all(http::header::LINK)
            .iter()
            .take(64)
            .enumerate()
        {
            if is_early_hint_link(v) {
                hints |= 1 << i;
            }
        }
        let any_hint = hints != 0
            || head
                .headers
                .get_all(http::header::LINK)
                .iter()
                .skip(64)
                .any(is_early_hint_link);
        if any_hint {
            // Encode the interim 103 block into the per-connection scratch (reused; write_field_block
            // copies it into OutQueue.inline before we touch the scratch again for the final block).
            block_scratch.clear();
            enc.encode_header(block_scratch, ":status", "103");
            for (i, v) in head.headers.get_all(http::header::LINK).iter().enumerate() {
                if (i < 64 && hints & (1 << i) != 0) || (i >= 64 && is_early_hint_link(v)) {
                    enc.encode_header(block_scratch, "link", v.as_bytes());
                }
            }
            out.frames(|b| write_field_block(b, stream_id, 0, block_scratch, mf));
        }
    }

    // Encode the HPACK header block into the per-connection scratch buffer (reused
    // across responses — capacity stays warm) rather than a fresh Vec per response.
    // It is fully copied into OutQueue.inline by write_field_block before the next
    // response touches the scratch, so reuse is safe.
    block_scratch.clear();
    enc.encode_header(block_scratch, ":status", head.status.as_str());
    for (name, value) in head.headers.iter() {
        // Raw octets, no `to_str`: HPACK strings are byte strings and `HeaderValue`
        // already forbids NUL/CR/LF (the only octets illegal in an h2 field value), so
        // the per-byte text validation was pure overhead — the hottest single loop in
        // the HIT-path CPU profile. Side effect: obs-text (0x80–0xFF) values are now
        // forwarded instead of silently dropped, matching LSWS/nginx behavior.
        enc.encode_header(block_scratch, name.as_str(), value.as_bytes());
    }
    let block: &[u8] = block_scratch;
    // Initial send window = the peer's INITIAL_WINDOW_SIZE plus any WINDOW_UPDATE credit
    // that arrived for this stream before we got here (always consume it, even for bodies
    // that need no stream, so the map stays bounded to in-flight streams).
    let credit = pending_window.remove(&stream_id).unwrap_or(0);
    let window = (peer.initial_window + credit).min(i32::MAX as i64);

    let headers_only = |out: &mut OutQueue| {
        out.frames(|b| write_field_block(b, stream_id, flags::END_STREAM, block, mf));
    };
    let headers_open = |out: &mut OutQueue| {
        out.frames(|b| write_field_block(b, stream_id, 0, block, mf));
    };
    let register = |outstreams: &mut FxHashMap<u32, OutStream>,
                    send_schedule: &mut VecDeque<u32>,
                    pending,
                    body,
                    eof| {
        outstreams.insert(
            stream_id,
            OutStream {
                pending,
                body,
                pulling: false,
                eof,
                done: false,
                window,
                cancel: tokio_util::sync::CancellationToken::new(),
            },
        );
        send_schedule.push_back(stream_id);
    };

    // HEAD and body-forbidden statuses send the header block only. HEAD keeps the
    // representation headers a GET would have; body-forbidden statuses are sanitized above.
    if body_forbidden {
        headers_only(out);
        return;
    }

    match body {
        Body::Empty => headers_only(out),
        Body::Stream(s) => {
            headers_open(out);
            register(outstreams, send_schedule, Bytes::new(), Some(s), false);
        }
        // Uncached file: stream it asynchronously (64 KiB chunks off tokio's blocking
        // pool) so a large file never blocks the connection task or its other streams.
        Body::File(f) if f.cached.is_none() => {
            if f.len == 0 {
                headers_only(out);
            } else {
                headers_open(out);
                register(
                    outstreams,
                    send_schedule,
                    Bytes::new(),
                    Some(file_stream_body(f.path, f.file, f.range, f.len)),
                    false,
                );
            }
        }
        other => {
            let bytes = body_to_bytes(other); // Body::Full or a cached file — already in memory
            if bytes.is_empty() {
                headers_only(out);
            } else {
                headers_open(out);
                register(outstreams, send_schedule, bytes, None, true);
            }
        }
    }
}

/// Tokio runtime handle for file-body blocking reads. The h2 send loop also runs on the
/// io_uring (monoio) transport threads, where `tokio::runtime::Handle::current()` would
/// panic (and `panic = "abort"` takes the whole process down — the 2026-07-11 crash-loop
/// incident). The binary plants its ambient tokio runtime here at startup so file chunks
/// are read off that runtime's blocking pool regardless of which thread polls the body.
static IO_HANDLE: std::sync::OnceLock<tokio::runtime::Handle> = std::sync::OnceLock::new();

/// Plant the tokio runtime used for file-body blocking reads. Idempotent; call before
/// serving connections on non-tokio (monoio) threads.
pub fn set_io_handle(handle: tokio::runtime::Handle) {
    let _ = IO_HANDLE.set(handle);
}

/// Ambient runtime first (a live runtime always beats the planted one, and a test that
/// planted a since-dropped runtime must not poison every later caller), planted second
/// (the monoio serve path, where there is no ambient runtime).
fn io_handle() -> Option<tokio::runtime::Handle> {
    tokio::runtime::Handle::try_current()
        .ok()
        .or_else(|| IO_HANDLE.get().cloned())
}

/// Run a blocking file operation on the planted tokio blocking pool, or inline on the
/// polling thread when no runtime is available. Both arms are correct on any thread;
/// the inline fallback trades a short stall for never panicking off-runtime.
async fn run_blocking<T: Send + 'static>(
    op: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> std::io::Result<T> {
    match io_handle() {
        Some(h) => h
            .spawn_blocking(op)
            .await
            .unwrap_or_else(|join| Err(std::io::Error::other(join))),
        None => op(),
    }
}

/// Stream an uncached file body asynchronously, in 64 KiB chunks read off the planted
/// tokio blocking pool, so a large file never blocks the connection task (or the other
/// streams multiplexed on it). Honors an optional inclusive byte range. A read error ends
/// the stream with an error frame, which [`apply_pull`] turns into RST_STREAM.
fn file_stream_body(
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
    range: Option<(u64, u64)>,
    len: u64,
) -> hj_core::StreamBody {
    use http_body::Frame;
    use http_body_util::{BodyExt, StreamBody};
    use std::sync::Arc;

    const CHUNK: usize = 64 * 1024;
    // Large transfers (above the file-cache in-mem tier, so every request streams)
    // read in 1 MiB chunks: 16× fewer read syscalls + blocking-pool hops for a big
    // download, while small/ranged serves keep the lean 64 KiB buffer.
    const LARGE: u64 = 4 * 1024 * 1024;
    const LARGE_CHUNK: usize = 1024 * 1024;
    let (start, total) = match range {
        Some((s, e)) => {
            let s = s.min(len);
            (s, e.saturating_add(1).min(len).saturating_sub(s))
        }
        None => (0, len),
    };
    let chunk = if total > LARGE { LARGE_CHUNK } else { CHUNK };
    let file = file.map(Arc::new);
    // State: (the open file once we have it, current offset, bytes still to send).
    // Positional reads (pread) never touch the descriptor's cursor, so a pinned
    // `FileBody.file` fd shared with other in-flight responses stays undisturbed.
    let stream =
        futures_util::stream::unfold((file, start, total), move |(file, off, remaining)| {
            let path = path.clone();
            async move {
                if remaining == 0 {
                    return None;
                }
                let read = async {
                    let f = match file {
                        Some(f) => f,
                        None => Arc::new(
                            run_blocking(move || {
                                let f = std::fs::File::open(&path)?;
                                if total > LARGE {
                                    // Kernel readahead for the sequential scan; advisory, errors ignored.
                                    let _ = rustix::fs::fadvise(
                                        &f,
                                        0,
                                        None,
                                        rustix::fs::Advice::Sequential,
                                    );
                                }
                                Ok(f)
                            })
                            .await?,
                        ),
                    };
                    let want = (remaining as usize).min(chunk);
                    let reader = f.clone();
                    let buf = run_blocking(move || {
                        // Read into uninitialized spare capacity (no per-chunk 64 KiB
                        // pre-zeroing); `spare_capacity` sets the Vec length to exactly
                        // the bytes pread initialized. EINTR retries instead of
                        // resetting the stream (parity with the bridge read loop) —
                        // it can surface on the inline-fallback arm, where a signal
                        // delivered to the polling thread interrupts the syscall.
                        let mut buf = Vec::with_capacity(want);
                        loop {
                            match rustix::io::pread(
                                &*reader,
                                rustix::buffer::spare_capacity(&mut buf),
                                off,
                            ) {
                                Ok(_) => break,
                                Err(rustix::io::Errno::INTR) => continue,
                                Err(e) => return Err(std::io::Error::from(e)),
                            }
                        }
                        // Vec::with_capacity is exact, but keep the range math immune
                        // to any allocator over-allocation.
                        buf.truncate(want);
                        Ok(buf)
                    })
                    .await?;
                    Ok::<_, std::io::Error>((f, Bytes::from(buf)))
                }
                .await;
                match read {
                    Ok((_, chunk)) if chunk.is_empty() => {
                        let err = std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "file shortened while streaming response",
                        );
                        let item: Result<Frame<Bytes>, hj_core::BoxError> = Err(Box::new(err));
                        Some((item, (None, off, 0)))
                    }
                    Ok((f, chunk)) => {
                        let n = chunk.len() as u64;
                        let item: Result<Frame<Bytes>, hj_core::BoxError> = Ok(Frame::data(chunk));
                        Some((item, (Some(f), off + n, remaining - n)))
                    }
                    Err(e) => {
                        let item: Result<Frame<Bytes>, hj_core::BoxError> = Err(Box::new(e));
                        Some((item, (None, off, 0))) // yield the error, then end next poll
                    }
                }
            }
        });
    StreamBody::new(stream).boxed()
}

/// Write at most one DATA frame for `st`. The caller rotates the stream to the back of the
/// connection schedule before granting another frame, so a large response cannot consume the
/// whole connection window ahead of its peers.
fn pump_one_frame(
    stream_id: u32,
    st: &mut OutStream,
    out: &mut OutQueue,
    send_conn: &mut i64,
    max_frame: usize,
) -> bool {
    if !st.pending.is_empty() {
        let allow = (*send_conn).min(st.window).min(max_frame as i64);
        if allow <= 0 {
            return false;
        }
        let n = (allow as usize).min(st.pending.len());
        let chunk = st.pending.slice(..n);
        st.pending = st.pending.slice(n..);
        let last = st.eof && st.pending.is_empty();
        let dflags = if last { flags::END_STREAM } else { 0 };
        out.frames(|b| {
            FrameHeader {
                length: n as u32,
                kind: kind::DATA,
                flags: dflags,
                stream_id,
            }
            .write(b)
        });
        out.body(chunk);
        *send_conn -= n as i64;
        st.window -= n as i64;
        if last {
            st.done = true;
        }
        return true;
    }
    // Drained and the body is exhausted but END_STREAM was never sent (a zero-length body,
    // or EOF discovered after the last chunk flushed): emit a final empty DATA.
    if st.eof && !st.done {
        out.frames(|b| {
            FrameHeader {
                length: 0,
                kind: kind::DATA,
                flags: flags::END_STREAM,
                stream_id,
            }
            .write(b)
        });
        st.done = true;
        return true;
    }
    false
}

/// Drive every active outgoing body: send what the windows allow, queue a chunk pull for
/// any stream that has drained its buffer and has more to come, and drop finished streams.
pub(super) fn pump_streams(
    outstreams: &mut FxHashMap<u32, OutStream>,
    send_schedule: &mut VecDeque<u32>,
    out: &mut OutQueue,
    send_conn: &mut i64,
    pulls: &mut Pulls,
    peer: &PeerSettings,
) {
    let max_frame = (peer.max_frame_size as usize).max(1);
    let mut visits_without_output = send_schedule.len();
    while visits_without_output > 0 {
        let Some(sid) = send_schedule.pop_front() else {
            break;
        };
        let mut keep = false;
        let mut wrote = false;
        if let Some(st) = outstreams.get_mut(&sid) {
            if !st.done {
                wrote = pump_one_frame(sid, st, out, send_conn, max_frame);
                if !st.done && st.pending.is_empty() && !st.eof && !st.pulling {
                    if let Some(body) = st.body.take() {
                        st.pulling = true;
                        pulls.push(Box::pin(pull_next(sid, body, st.cancel.clone())));
                    }
                }
                keep = !st.done;
            }
        }
        if keep {
            send_schedule.push_back(sid);
        } else {
            outstreams.remove(&sid);
        }
        if wrote {
            visits_without_output = send_schedule.len();
        } else {
            visits_without_output -= 1;
        }
    }
}

pub(super) fn cancel_outstream(outstreams: &mut FxHashMap<u32, OutStream>, sid: u32) {
    if let Some(st) = outstreams.remove(&sid) {
        st.cancel.cancel();
    }
}

/// Apply a completed chunk pull to its stream: re-home the body and buffer the chunk, mark
/// EOF, or reset the stream on a body error.
pub(super) fn apply_pull(
    sid: u32,
    body: hj_core::StreamBody,
    res: Option<Result<Bytes, hj_core::BoxError>>,
    outstreams: &mut FxHashMap<u32, OutStream>,
    out: &mut OutQueue,
) {
    let Some(st) = outstreams.get_mut(&sid) else {
        return; // stream was reset/dropped while the pull was in flight
    };
    st.pulling = false;
    match res {
        Some(Ok(data)) => {
            st.body = Some(body);
            // We only pull when `pending` is empty, so this just sets the next chunk.
            if st.pending.is_empty() {
                st.pending = data;
            } else {
                // Rare coalesce (we normally only pull with `pending` empty). This Vec is NOT a
                // poolable scratch: it becomes `st.pending` and is written to the wire by
                // `pump_streams` (zero-copy `Bytes`), so it escapes the request — it must own.
                let mut v = Vec::with_capacity(st.pending.len() + data.len());
                v.extend_from_slice(&st.pending);
                v.extend_from_slice(&data);
                st.pending = Bytes::from(v);
            }
        }
        None => st.eof = true,
        Some(Err(_e)) => {
            out.frames(|b| frame::write_rst_stream(b, sid, error_code::INTERNAL_ERROR));
            st.done = true; // dropped by the next pump_streams pass
        }
    }
}

/// Materialize an already-in-memory response [`Body`] to bytes: `Body::Full` and *cached*
/// files (zero-copy slices). `Body::Stream` and *uncached* files are handled by the async
/// streaming path (`begin_response` → `file_stream_body` / `pull_next`) and never reach
/// this function — their arms below are defensive fallbacks only (never a blocking read).
fn body_to_bytes(body: Body) -> Bytes {
    match body {
        Body::Empty => Bytes::new(),
        Body::Full(b) => b,
        // `cached` holds the WHOLE file; apply the range via the single-sourced, bounds-clamped
        // hj-core helper so this native-H2 path and the io_uring bridge slice cached identically.
        Body::File(f) => f.cached_ranged().unwrap_or_default(),
        Body::Stream(_) => Bytes::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_hint_link_matcher_semantics() {
        // Byte-for-byte the same accept/reject set as the old lowercase+contains version
        // over the four needles (bare = prefix after `rel=`; quoted = closing quote required).
        let hv = |s: &str| http::HeaderValue::from_str(s).unwrap();
        for yes in [
            "</a.css>; rel=preload; as=style",
            "</a.css>; rel=\"preload\"; as=style",
            "<https://x>; rel=preconnect",
            "<https://x>; rel=\"preconnect\"",
            "</a.css>; REL=PRELOAD",
            "</a.css>; Rel=\"Preconnect\"",
            "</a.css>; rel=preloadextra", // old contains("rel=preload") matched this too
        ] {
            assert!(is_early_hint_link(&hv(yes)), "should hint: {yes}");
        }
        for no in [
            "</p>; rel=canonical",
            "</p>; rel=alternate",
            "</p>; rel=prefetch",
            "</p>; rel=\"preload", // unterminated quote — old needle required the close
            "</p>; rel= preload",  // space after = — old needles had none
            "</p>; preload",       // no rel=
            "",
        ] {
            assert!(!is_early_hint_link(&hv(no)), "should NOT hint: {no}");
        }
    }

    #[test]
    fn write_field_block_fragments_to_max_frame_size() {
        // §4.2/§4.3: a block larger than max_frame splits into HEADERS + CONTINUATION(s);
        // lead_flags ride only the first frame, END_HEADERS only the last, payload reassembles.
        let block: Vec<u8> = (0..25u8).collect();
        let mut out = Vec::new();
        write_field_block(&mut out, 1, flags::END_STREAM, &block, 10);
        let mut frames = Vec::new();
        let mut p = 0;
        while p < out.len() {
            let h = FrameHeader::parse(&out[p..]).unwrap();
            let start = p + FrameHeader::LEN;
            frames.push((h, out[start..start + h.length as usize].to_vec()));
            p = start + h.length as usize;
        }
        assert_eq!(frames.len(), 3); // 10 + 10 + 5
        assert_eq!(frames[0].0.kind, kind::HEADERS);
        assert_eq!(frames[0].0.flags & flags::END_STREAM, flags::END_STREAM);
        assert_eq!(
            frames[0].0.flags & flags::END_HEADERS,
            0,
            "END_HEADERS must NOT be on the first frame"
        );
        assert_eq!(frames[1].0.kind, kind::CONTINUATION);
        assert_eq!(frames[1].0.flags, 0);
        assert_eq!(frames[2].0.kind, kind::CONTINUATION);
        assert_eq!(frames[2].0.flags & flags::END_HEADERS, flags::END_HEADERS);
        assert!(frames.iter().all(|(h, _)| h.stream_id == 1));
        let reassembled: Vec<u8> = frames.iter().flat_map(|(_, pl)| pl.clone()).collect();
        assert_eq!(reassembled, block);
        assert!(
            frames.iter().all(|(h, _)| h.length as usize <= 10),
            "no frame exceeds max_frame"
        );

        // Single-frame fast path: block ≤ max → one HEADERS with END_HEADERS.
        let mut out2 = Vec::new();
        write_field_block(&mut out2, 3, 0, &[1, 2, 3], 10);
        let h = FrameHeader::parse(&out2).unwrap();
        assert_eq!((h.kind, h.length), (kind::HEADERS, 3));
        assert_eq!(h.flags & flags::END_HEADERS, flags::END_HEADERS);
        assert_eq!(out2.len(), FrameHeader::LEN + 3, "one frame only");
    }

    #[test]
    fn send_flow_control_rotates_before_reusing_connection_credit() {
        fn stream(body: &'static [u8]) -> OutStream {
            OutStream {
                pending: Bytes::from_static(body),
                body: None,
                pulling: false,
                eof: true,
                done: false,
                window: 64,
                cancel: tokio_util::sync::CancellationToken::new(),
            }
        }
        fn data_stream_ids(out: &OutQueue) -> Vec<u32> {
            out.segs
                .iter()
                .filter_map(|seg| match seg {
                    super::super::Seg::Inline(offset, len) if *len == FrameHeader::LEN => {
                        FrameHeader::parse(&out.inline[*offset..*offset + *len])
                            .filter(|header| header.kind == kind::DATA)
                            .map(|header| header.stream_id)
                    }
                    _ => None,
                })
                .collect()
        }

        let mut streams = FxHashMap::default();
        streams.insert(1, stream(b"aaaaaaaa"));
        streams.insert(3, stream(b"bbbbbbbb"));
        let mut schedule = VecDeque::from([1, 3]);
        let mut out = OutQueue::default();
        let mut pulls = Pulls::new();
        let peer = PeerSettings {
            max_frame_size: 4,
            initial_window: 64,
        };

        let mut connection_window = 4;
        pump_streams(
            &mut streams,
            &mut schedule,
            &mut out,
            &mut connection_window,
            &mut pulls,
            &peer,
        );
        assert_eq!(data_stream_ids(&out), [1]);

        out.clear();
        connection_window += 4;
        pump_streams(
            &mut streams,
            &mut schedule,
            &mut out,
            &mut connection_window,
            &mut pulls,
            &peer,
        );
        assert_eq!(
            data_stream_ids(&out),
            [3],
            "new connection credit must go to the stream skipped in the prior round"
        );
    }

    #[tokio::test]
    async fn file_stream_body_honors_an_inclusive_range_across_chunks() {
        // Validates the ranged async file streamer (used for uncached Body::File): it must
        // seek to `start`, deliver exactly `end-start+1` bytes, and stop dead on the range
        // end — including the final partial chunk where `want < CHUNK`, which is the case
        // the `.limit(want)` read bound exists to keep from over-reading.
        use http_body_util::BodyExt;
        use std::io::Write;
        let path = std::env::temp_dir().join(format!("hj-h2-range-{}.bin", std::process::id()));
        let content: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&content)
            .unwrap();
        let len = content.len() as u64;

        // start mid-file; end spans two full 64 KiB chunks + a short remainder.
        let (start, end) = (100usize, 150_000usize);
        let collected = file_stream_body(path.clone(), None, Some((start as u64, end as u64)), len)
            .collect()
            .await
            .expect("ranged stream must not error")
            .to_bytes();
        assert_eq!(
            &collected[..],
            &content[start..=end],
            "ranged stream must return exactly the inclusive range, no over-read"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn short_file_stream_yields_error_instead_of_clean_eof() {
        use http_body_util::BodyExt;
        use std::io::Write;

        let path =
            std::env::temp_dir().join(format!("hj-h2-short-file-{}.bin", std::process::id()));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"short")
            .unwrap();

        let mut body = file_stream_body(path.clone(), None, None, 10);
        let first = body
            .frame()
            .await
            .expect("first frame")
            .expect("first read")
            .into_data()
            .expect("data frame");
        assert_eq!(&first[..], b"short");
        let err = body
            .frame()
            .await
            .expect("short read must yield an error frame")
            .expect_err("short read must not become clean EOF");
        assert!(err.to_string().contains("shortened"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn pinned_file_stream_survives_path_unlink() {
        use http_body_util::BodyExt;

        let path = std::env::temp_dir().join(format!(
            "hj-h2-pinned-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let payload = b"selected-cache-version";
        std::fs::write(&path, payload).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        let collected = file_stream_body(path, Some(file), None, payload.len() as u64)
            .collect()
            .await
            .expect("open descriptor remains readable after unlink")
            .to_bytes();
        assert_eq!(&collected[..], payload);
    }

    #[tokio::test]
    async fn cancelling_outstream_drops_body_without_disturbing_other_pulls() {
        use futures_util::StreamExt;
        use http_body_util::BodyExt;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll};

        struct QuietBody(Arc<AtomicBool>);
        impl Drop for QuietBody {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        impl http_body::Body for QuietBody {
            type Data = Bytes;
            type Error = hj_core::BoxError;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
                Poll::Pending
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let cancelled_body = BodyExt::boxed(QuietBody(dropped.clone()));
        let cancelled_token = tokio_util::sync::CancellationToken::new();
        let other_source = futures_util::stream::iter([Ok::<_, hj_core::BoxError>(
            http_body::Frame::data(Bytes::from_static(b"other-stream")),
        )]);
        let other_body = BodyExt::boxed(http_body_util::StreamBody::new(other_source));
        let other_token = tokio_util::sync::CancellationToken::new();
        let mut pulls = Pulls::new();
        pulls.push(Box::pin(pull_next(
            1,
            cancelled_body,
            cancelled_token.clone(),
        )));
        pulls.push(Box::pin(pull_next(3, other_body, other_token.clone())));

        let mut outstreams = FxHashMap::default();
        for (sid, cancel) in [(1, cancelled_token), (3, other_token)] {
            outstreams.insert(
                sid,
                OutStream {
                    pending: Bytes::new(),
                    body: None,
                    pulling: true,
                    eof: false,
                    done: false,
                    window: 0,
                    cancel,
                },
            );
        }
        cancel_outstream(&mut outstreams, 1);

        let mut out = OutQueue::default();
        let mut saw_cancelled = false;
        let mut saw_other = false;
        for _ in 0..2 {
            let (sid, body, result) =
                tokio::time::timeout(std::time::Duration::from_millis(100), pulls.next())
                    .await
                    .expect("reset and unrelated pull must both complete")
                    .expect("pull result");
            apply_pull(sid, body, result, &mut outstreams, &mut out);
            match sid {
                1 => {
                    saw_cancelled = true;
                    assert!(!outstreams.contains_key(&1));
                    assert!(
                        dropped.load(Ordering::Acquire),
                        "cancelled quiet body must be dropped when its pull result is discarded"
                    );
                }
                3 => {
                    saw_other = true;
                    let stream = outstreams.get(&3).expect("unrelated stream remains live");
                    assert_eq!(&stream.pending[..], b"other-stream");
                    assert!(stream.body.is_some(), "unrelated body is re-homed");
                }
                _ => unreachable!(),
            }
        }
        assert!(saw_cancelled && saw_other);
        assert!(
            !outstreams.contains_key(&1),
            "late pull cannot resurrect reset stream"
        );
    }
}
