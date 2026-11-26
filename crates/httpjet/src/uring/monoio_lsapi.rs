//! On-core `monoio::net::UnixStream` LSAPI fast path for bodyless GET/HEAD PHP
//! requests.
//!
//! Runs directly on the monoio worker thread — no Tokio channel hop, no
//! `tokio::spawn`, no `UnixStream::into_split`, and no Tokio timer-wheel
//! insert/remove (`write_watch::Deadline` provides lazy per-core timeouts).
//! Keeps a small thread-local LIFO pool of idle UDS connections keyed by
//! `(socket_path, pool_generation)` and falls back (`None`) to the full Tokio
//! bridge on any unsupported case (unbuffered streaming, oversized body,
//! non-inline error, or socket failure).

use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use hj_core::{Body, ReqCtx, Request, Response};
use hj_lsapi::handler::{
    MONOIO_INLINE_BODY_CAP, finalize_inline_body, log_lsapi_stderr, parse_inline_response_head,
};
use hj_lsapi::{LsapiScript, MonoioPoolTarget, PACKET_HEADER_LEN, PacketType, parse_resp_header};
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::UnixStream;

use super::write_watch::Deadline;

/// Largest BEGIN_REQUEST buffer retained in the thread-local scratch slot.
const BEGIN_BUF_KEEP_CAP: usize = 16 * 1024;
/// Read buffer size per LSAPI response read.
const READ_BUF_SIZE: usize = 64 * 1024;
/// Maximum response body size collected inline on-core (256 KiB).
const MAX_BODY_CAP: usize = MONOIO_INLINE_BODY_CAP;

const VERSION_B0: u8 = b'L';
const VERSION_B1: u8 = b'S';
const ENDIAN_BIT: u8 = 1;
#[cfg(target_endian = "little")]
const HOST_LSAPI_ENDIAN: u8 = 0;
#[cfg(target_endian = "big")]
const HOST_LSAPI_ENDIAN: u8 = 1;

#[derive(Default)]
struct WorkerLsapiState {
    begin_buf: BytesMut,
    read_buf: Option<Vec<u8>>,
}

thread_local! {
    static WORKER_LSAPI: RefCell<WorkerLsapiState> = RefCell::new(WorkerLsapiState::default());
}

fn take_begin_buf() -> BytesMut {
    WORKER_LSAPI.with(|s| {
        let mut buf = std::mem::take(&mut s.borrow_mut().begin_buf);
        buf.clear();
        buf
    })
}

fn return_begin_buf(mut buf: BytesMut) {
    if buf.capacity() <= BEGIN_BUF_KEEP_CAP {
        buf.clear();
        WORKER_LSAPI.with(|s| {
            s.borrow_mut().begin_buf = buf;
        });
    }
}

fn take_read_buf() -> Vec<u8> {
    WORKER_LSAPI.with(|s| {
        s.borrow_mut()
            .read_buf
            .take()
            .unwrap_or_else(|| Vec::with_capacity(READ_BUF_SIZE))
    })
}

fn return_read_buf(mut buf: Vec<u8>) {
    if buf.capacity() <= READ_BUF_SIZE * 2 {
        buf.clear();
        WORKER_LSAPI.with(|s| {
            let mut st = s.borrow_mut();
            if st.read_buf.is_none() {
                st.read_buf = Some(buf);
            }
        });
    }
}

async fn with_deadline<T, F: Future<Output = T>>(at: Instant, fut: F) -> Result<T, ()> {
    let mut fut = pin!(fut);
    let mut watch = Deadline::new(at);
    std::future::poll_fn(|cx| {
        if watch.expired() {
            return Poll::Ready(Err(()));
        }
        match fut.as_mut().poll(cx) {
            Poll::Ready(val) => Poll::Ready(Ok(val)),
            Poll::Pending => {
                watch.arm(cx.waker());
                Poll::Pending
            }
        }
    })
    .await
}

/// Try to parse one complete LSAPI packet from `buf[pos..]`.
/// Returns:
/// - `Ok(Some((packet_type, little_endian, body_start, next_pos)))` when a full packet is buffered
/// - `Ok(None)` when more bytes are needed
/// - `Err(())` on framing corruption
fn try_parse_packet(
    buf: &[u8],
    pos: usize,
) -> Result<Option<(PacketType, bool, usize, usize)>, ()> {
    let rem = buf.get(pos..).unwrap_or_default();
    if rem.len() < PACKET_HEADER_LEN {
        return Ok(None);
    }
    let Some(hdr) = rem.get(..PACKET_HEADER_LEN) else {
        return Ok(None);
    };
    if hdr.first().copied() != Some(VERSION_B0) || hdr.get(1).copied() != Some(VERSION_B1) {
        return Err(());
    }
    let Some(ptype) = hdr.get(2).copied().and_then(PacketType::from_u8) else {
        return Err(());
    };
    let sender_endian = hdr.get(3).copied().unwrap_or(0) & ENDIAN_BIT;
    let little_endian = sender_endian == 0;
    let len_bytes: [u8; 4] = hdr.get(4..8).and_then(|s| s.try_into().ok()).ok_or(())?;
    let raw_len = if sender_endian == HOST_LSAPI_ENDIAN {
        i32::from_ne_bytes(len_bytes)
    } else {
        i32::from_ne_bytes(len_bytes).swap_bytes()
    };
    if raw_len < PACKET_HEADER_LEN as i32 {
        return Err(());
    }
    let total_len = raw_len as usize;
    if rem.len() < total_len {
        return Ok(None);
    }
    let body_start = pos + PACKET_HEADER_LEN;
    let next_pos = pos + total_len;
    Ok(Some((ptype, little_endian, body_start, next_pos)))
}

enum AttemptResult {
    Response(Response),
    /// Clean pre-header EOF/reset on a reused idle socket: safe to retry once on a fresh dial.
    RetryFresh,
    /// Fall back to the full Tokio pipeline (no error response synthesized here).
    Fallback,
}

/// Execute a bodyless GET/HEAD PHP request directly on the current monoio core.
/// Returns `Some(Response)` on clean inline completion, or `None` to fall back
/// to the full Tokio LSAPI pipeline.
pub(crate) async fn dispatch_bodyless(
    target: &MonoioPoolTarget,
    req: &Request,
    ctx: &ReqCtx,
    script: &LsapiScript,
) -> Option<Response> {
    let mut begin = take_begin_buf();
    if target
        .handler
        .encode_bodyless_begin_request(req, ctx, script, &mut begin)
        .is_err()
    {
        return_begin_buf(begin);
        return None;
    }
    let mut begin_bytes = begin.freeze();

    let is_head = req.method() == http::Method::HEAD;
    let read_timeout = target.handler.read_timeout_duration();
    let max_process_time = target.handler.max_process_time_duration();
    let generation = target.pool.generation();

    // Acquire a global `max_conns` permit shared with the Tokio pool so total
    // concurrent + idle sockets never exceed `--php-children` (#896).
    let acq_start = Instant::now();
    let _permit = match with_deadline(
        acq_start + read_timeout.min(Duration::from_secs(5)),
        target.pool.acquire_monoio_permit(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        _ => {
            if let Ok(mut b) = begin_bytes.try_into_mut() {
                b.clear();
                return_begin_buf(b);
            }
            return None;
        }
    };

    for attempt in 0..2u8 {
        let (stream, reused) = if attempt == 0 {
            if let Some(std_s) = target.pool.pop_monoio_idle(generation)
                && let Ok(s) = UnixStream::from_std(std_s)
            {
                (s, true)
            } else {
                match UnixStream::connect(&target.socket_path).await {
                    Ok(s) => (s, false),
                    Err(_) => {
                        if let Ok(mut b) = begin_bytes.try_into_mut() {
                            b.clear();
                            return_begin_buf(b);
                        }
                        return None;
                    }
                }
            }
        } else {
            match UnixStream::connect(&target.socket_path).await {
                Ok(s) => (s, false),
                Err(_) => {
                    if let Ok(mut b) = begin_bytes.try_into_mut() {
                        b.clear();
                        return_begin_buf(b);
                    }
                    return None;
                }
            }
        };
        let acquire = acq_start.elapsed();

        let (result, returned_bytes) = run_once(
            stream,
            reused,
            begin_bytes,
            is_head,
            acquire,
            read_timeout,
            max_process_time,
            target,
            generation,
        )
        .await;
        begin_bytes = returned_bytes;
        match result {
            AttemptResult::Response(resp) => {
                if let Ok(mut b) = begin_bytes.try_into_mut() {
                    b.clear();
                    return_begin_buf(b);
                }
                return Some(resp);
            }
            AttemptResult::RetryFresh if reused && attempt == 0 => continue,
            AttemptResult::RetryFresh | AttemptResult::Fallback => {
                if let Ok(mut b) = begin_bytes.try_into_mut() {
                    b.clear();
                    return_begin_buf(b);
                }
                return None;
            }
        }
    }
    if let Ok(mut b) = begin_bytes.try_into_mut() {
        b.clear();
        return_begin_buf(b);
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn run_once(
    mut stream: UnixStream,
    reused: bool,
    begin_bytes: Bytes,
    is_head: bool,
    acquire: Duration,
    read_timeout: Duration,
    max_process_time: Option<Duration>,
    target: &MonoioPoolTarget,
    generation: u64,
) -> (AttemptResult, Bytes) {
    let sent_at = Instant::now();
    let abs_deadline = max_process_time.map(|d| sent_at + d);
    let next_deadline = || {
        let idle = Instant::now() + read_timeout;
        match abs_deadline {
            Some(abs) => idle.min(abs),
            None => idle,
        }
    };

    // Write BEGIN_REQUEST.
    let begin_bytes = match with_deadline(next_deadline(), stream.write_all(begin_bytes)).await {
        Ok((Ok(_), buf)) => buf,
        Ok((Err(e), buf)) => {
            if reused
                && matches!(
                    e.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::UnexpectedEof
                )
            {
                return (AttemptResult::RetryFresh, buf);
            }
            return (AttemptResult::Fallback, buf);
        }
        Err(()) => return (AttemptResult::Fallback, Bytes::new()),
    };

    let mut acc = take_read_buf();
    acc.clear();
    let mut pos: usize = 0;
    let mut saw_packet = false;

    // Helper: read more bytes into `acc` without allocating a fresh 64 KiB
    // Vec on the common first read (when `acc` is empty).
    async fn read_more(
        stream: &mut UnixStream,
        acc: &mut Vec<u8>,
        pos: &mut usize,
        deadline: Instant,
    ) -> Result<io::Result<usize>, ()> {
        if *pos >= acc.len() {
            acc.clear();
            *pos = 0;
            let buf = std::mem::take(acc);
            let res = with_deadline(deadline, stream.read(buf)).await;
            match res {
                Ok((r, buf)) => {
                    *acc = buf;
                    Ok(r)
                }
                Err(()) => Err(()),
            }
        } else {
            if *pos > 0 {
                acc.copy_within(*pos.., 0);
                acc.truncate(acc.len() - *pos);
                *pos = 0;
            }
            let chunk = Vec::with_capacity(READ_BUF_SIZE);
            match with_deadline(deadline, stream.read(chunk)).await {
                Ok((Ok(n), buf)) => {
                    acc.extend_from_slice(buf.get(..n).unwrap_or_default());
                    Ok(Ok(n))
                }
                Ok((Err(e), _)) => Ok(Err(e)),
                Err(()) => Err(()),
            }
        }
    }

    // 1. Read until RESP_HEADER.
    let resp_header = loop {
        match try_parse_packet(&acc, pos) {
            Ok(Some((ptype, little_endian, body_start, next_pos))) => {
                saw_packet = true;
                let body_slice = acc.get(body_start..next_pos).unwrap_or_default();
                match ptype {
                    PacketType::RespHeader => {
                        let parsed = parse_resp_header(body_slice, little_endian);
                        pos = next_pos;
                        match parsed {
                            Ok(h) => break h,
                            Err(_) => {
                                return_read_buf(acc);
                                return (AttemptResult::Fallback, begin_bytes);
                            }
                        }
                    }
                    PacketType::StderrStream => {
                        log_lsapi_stderr(body_slice);
                        pos = next_pos;
                    }
                    PacketType::ReqReceived => {
                        pos = next_pos;
                    }
                    PacketType::InternalError | PacketType::ConnClose | PacketType::RespEnd => {
                        return_read_buf(acc);
                        return (AttemptResult::Fallback, begin_bytes);
                    }
                    _ => {
                        pos = next_pos;
                    }
                }
            }
            Ok(None) => match read_more(&mut stream, &mut acc, &mut pos, next_deadline()).await {
                Ok(Ok(0)) => {
                    let empty = acc.is_empty();
                    return_read_buf(acc);
                    if !saw_packet && empty && reused {
                        return (AttemptResult::RetryFresh, begin_bytes);
                    }
                    return (AttemptResult::Fallback, begin_bytes);
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    let empty = acc.is_empty();
                    return_read_buf(acc);
                    if !saw_packet && empty && reused && e.kind() == io::ErrorKind::ConnectionReset
                    {
                        return (AttemptResult::RetryFresh, begin_bytes);
                    }
                    return (AttemptResult::Fallback, begin_bytes);
                }
                Err(()) => {
                    return_read_buf(acc);
                    return (AttemptResult::Fallback, begin_bytes);
                }
            },
            Err(()) => {
                return_read_buf(acc);
                return (AttemptResult::Fallback, begin_bytes);
            }
        }
    };

    let ttfb = sent_at.elapsed();
    let Ok((mut response, enforced_len, unbuffered)) =
        parse_inline_response_head(resp_header, is_head, acquire, ttfb)
    else {
        return_read_buf(acc);
        return (AttemptResult::Fallback, begin_bytes);
    };
    if unbuffered || enforced_len.is_some_and(|l| l > MAX_BODY_CAP as u64) {
        // Rare unbuffered/large response: close socket and fall back.
        return_read_buf(acc);
        return (AttemptResult::Fallback, begin_bytes);
    }

    // 2. Read RESP_STREAM chunks until RESP_END. Fast-path the common 1-chunk
    // inline PHP response without allocating a `Vec<Bytes>`.
    let mut first_chunk: Option<Bytes> = None;
    let mut extra_chunks: Vec<Bytes> = Vec::new();
    let mut body_len: usize = 0;
    let clean_end = loop {
        match try_parse_packet(&acc, pos) {
            Ok(Some((ptype, _, body_start, next_pos))) => {
                let body_slice = acc.get(body_start..next_pos).unwrap_or_default();
                match ptype {
                    PacketType::RespStream => {
                        if !body_slice.is_empty() {
                            body_len += body_slice.len();
                            if body_len > MAX_BODY_CAP {
                                return_read_buf(acc);
                                return (AttemptResult::Fallback, begin_bytes);
                            }
                            let chunk = Bytes::copy_from_slice(body_slice);
                            if first_chunk.is_none() {
                                first_chunk = Some(chunk);
                            } else {
                                extra_chunks.push(chunk);
                            }
                        }
                        pos = next_pos;
                    }
                    PacketType::StderrStream => {
                        log_lsapi_stderr(body_slice);
                        pos = next_pos;
                    }
                    PacketType::ReqReceived => {
                        pos = next_pos;
                    }
                    PacketType::RespEnd => {
                        pos = next_pos;
                        break true;
                    }
                    PacketType::ConnClose => {
                        pos = next_pos;
                        break false;
                    }
                    PacketType::InternalError => {
                        return_read_buf(acc);
                        return (AttemptResult::Fallback, begin_bytes);
                    }
                    _ => {
                        pos = next_pos;
                    }
                }
            }
            Ok(None) => match read_more(&mut stream, &mut acc, &mut pos, next_deadline()).await {
                Ok(Ok(0)) => break false,
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(()) => {
                    return_read_buf(acc);
                    return (AttemptResult::Fallback, begin_bytes);
                }
            },
            Err(()) => {
                return_read_buf(acc);
                return (AttemptResult::Fallback, begin_bytes);
            }
        }
    };

    let trailing = pos < acc.len();
    return_read_buf(acc);

    if !clean_end && enforced_len.is_none() {
        return (AttemptResult::Fallback, begin_bytes);
    }
    if let Some(len) = enforced_len
        && (body_len as u64) < len
    {
        return (AttemptResult::Fallback, begin_bytes);
    }
    let over_delivered = enforced_len.is_some_and(|len| body_len as u64 > len);
    let final_len = enforced_len.map_or(body_len, |len| len as usize);
    let body = if extra_chunks.is_empty() {
        match first_chunk {
            Some(mut b) => {
                b.truncate(final_len);
                b
            }
            None => Bytes::new(),
        }
    } else {
        let mut all = Vec::with_capacity(1 + extra_chunks.len());
        if let Some(first) = first_chunk {
            all.push(first);
        }
        all.extend(extra_chunks);
        finalize_inline_body(all, final_len)
    };

    // Return the clean UDS socket to the shared idle pool if generation is unchanged.
    if clean_end && !over_delivered && !trailing && target.pool.generation() == generation {
        let raw_fd = stream.into_raw_fd();
        // SAFETY: `into_raw_fd` transfers unique ownership of the open UDS fd.
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(raw_fd) };
        target.pool.push_monoio_idle(std_stream, generation);
    }

    *response.body_mut() = Body::Full(body);
    (AttemptResult::Response(response), begin_bytes)
}
