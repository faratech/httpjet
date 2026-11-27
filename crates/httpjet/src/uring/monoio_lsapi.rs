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
use hj_lsapi::handler::{MONOIO_INLINE_BODY_CAP, log_lsapi_stderr, parse_inline_response_head_raw};
use hj_lsapi::proto::HOST_LSAPI_ENDIAN;
use hj_lsapi::{LsapiScript, MonoioPoolTarget, PACKET_HEADER_LEN, PacketType};
use monoio::buf::IoBufMut;
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::UnixStream;

use super::write_watch::Slot;

/// `IoBufMut` wrapper that appends incoming bytes to `Vec<u8>` at `self.0.len()`
/// instead of monoio's default `Vec<u8>` impl (which writes from offset 0 and
/// overwrites any retained partial-packet prefix, #1303).
struct AppendVecBuf(Vec<u8>);

// SAFETY: `write_ptr` points to the initialized-end / spare-capacity boundary of
// `self.0`, `bytes_total` reports the exact spare capacity, and `set_init(pos)`
// advances `len` by `pos` within `capacity`.
unsafe impl IoBufMut for AppendVecBuf {
    fn write_ptr(&mut self) -> *mut u8 {
        // SAFETY: `self.0.len() <= self.0.capacity()`.
        unsafe { self.0.as_mut_ptr().add(self.0.len()) }
    }

    fn bytes_total(&mut self) -> usize {
        self.0.capacity().saturating_sub(self.0.len())
    }

    unsafe fn set_init(&mut self, pos: usize) {
        let new_len = self.0.len() + pos;
        debug_assert!(new_len <= self.0.capacity());
        // SAFETY: the kernel initialized `pos` bytes starting at `self.0.len()`.
        unsafe {
            self.0.set_len(new_len);
        }
    }
}

/// Largest BEGIN_REQUEST buffer retained in the thread-local scratch pool.
const BEGIN_BUF_KEEP_CAP: usize = 16 * 1024;
/// Read buffer size per LSAPI response read.
const READ_BUF_SIZE: usize = 64 * 1024;
/// Maximum number of buffers/slots pooled per worker thread.
const POOL_CAP: usize = 16;
/// Maximum response body size collected inline on-core (256 KiB).
const MAX_BODY_CAP: usize = MONOIO_INLINE_BODY_CAP;

const VERSION_B0: u8 = b'L';
const VERSION_B1: u8 = b'S';
const ENDIAN_BIT: u8 = 1;

#[derive(Default)]
struct WorkerLsapiState {
    begin_bufs: Vec<BytesMut>,
    read_bufs: Vec<Vec<u8>>,
    slots: Vec<Slot>,
}

thread_local! {
    static WORKER_LSAPI: RefCell<WorkerLsapiState> = RefCell::new(WorkerLsapiState::default());
}

fn take_begin_buf() -> BytesMut {
    WORKER_LSAPI.with(|s| {
        let mut buf = s.borrow_mut().begin_bufs.pop().unwrap_or_default();
        buf.clear();
        buf
    })
}

fn return_begin_buf(mut buf: BytesMut) {
    if buf.capacity() <= BEGIN_BUF_KEEP_CAP {
        buf.clear();
        WORKER_LSAPI.with(|s| {
            let mut st = s.borrow_mut();
            if st.begin_bufs.len() < POOL_CAP {
                st.begin_bufs.push(buf);
            }
        });
    }
}

fn take_read_buf() -> Vec<u8> {
    WORKER_LSAPI.with(|s| {
        s.borrow_mut()
            .read_bufs
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(READ_BUF_SIZE))
    })
}

fn return_read_buf(mut buf: Vec<u8>) {
    if buf.capacity() <= READ_BUF_SIZE * 2 {
        buf.clear();
        WORKER_LSAPI.with(|s| {
            let mut st = s.borrow_mut();
            if st.read_bufs.len() < POOL_CAP {
                st.read_bufs.push(buf);
            }
        });
    }
}

fn take_slot() -> Slot {
    WORKER_LSAPI.with(|s| s.borrow_mut().slots.pop().unwrap_or_default())
}

fn return_slot(mut slot: Slot) {
    slot.disarm();
    WORKER_LSAPI.with(|s| {
        let mut st = s.borrow_mut();
        if st.slots.len() < POOL_CAP {
            st.slots.push(slot);
        }
    });
}

struct PooledSlot(Option<Slot>);

impl PooledSlot {
    fn new() -> Self {
        Self(Some(take_slot()))
    }

    fn as_mut(&mut self) -> &mut Slot {
        self.0.get_or_insert_with(Slot::default)
    }
}

impl Drop for PooledSlot {
    fn drop(&mut self) {
        if let Some(slot) = self.0.take() {
            return_slot(slot);
        }
    }
}

struct DisarmGuard<'a> {
    slot: &'a mut Slot,
    armed: bool,
}

impl Drop for DisarmGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.slot.disarm();
        }
    }
}

async fn with_slot<T, F: Future<Output = T>>(
    slot: &mut Slot,
    at: Instant,
    fut: F,
) -> Result<T, ()> {
    let mut fut = pin!(fut);
    let mut guard = DisarmGuard { slot, armed: false };
    std::future::poll_fn(|cx| {
        if guard.armed && guard.slot.expired() {
            return Poll::Ready(Err(()));
        }
        match fut.as_mut().poll(cx) {
            Poll::Ready(val) => Poll::Ready(Ok(val)),
            Poll::Pending => {
                guard.slot.arm(at, cx.waker());
                guard.armed = true;
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
    // Match `RespHeader::parse_flagged`: lsphp writes body fields host-native LE
    // and stamps `HOST_LSAPI_ENDIAN` (which is 1 on aarch64, #1304).
    let little_endian = sender_endian == HOST_LSAPI_ENDIAN;
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

    let is_head = req.method() == http::Method::HEAD;
    let read_timeout = target.handler.read_timeout_duration();
    let max_process_time = target.handler.max_process_time_duration();
    let generation = target.pool.generation();

    // Acquire a global `max_conns` permit shared with the Tokio pool so total
    // concurrent + idle sockets never exceed `--php-children` (#896).
    let mut pooled_slot = PooledSlot::new();
    let acq_start = super::write_watch::coarse_now();
    let _permit = match with_slot(
        pooled_slot.as_mut(),
        acq_start + read_timeout.min(Duration::from_secs(5)),
        target.pool.acquire_monoio_permit(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        _ => {
            return_begin_buf(begin);
            return None;
        }
    };

    let now = super::write_watch::coarse_now();
    for attempt in 0..2u8 {
        let (stream, reused) = if attempt == 0 {
            if let Some(std_s) = target.pool.pop_monoio_idle(generation, now)
                && let Ok(s) = UnixStream::from_std(std_s)
            {
                (s, true)
            } else {
                match UnixStream::connect(&target.socket_path).await {
                    Ok(s) => (s, false),
                    Err(_) => {
                        return_begin_buf(begin);
                        return None;
                    }
                }
            }
        } else {
            match UnixStream::connect(&target.socket_path).await {
                Ok(s) => (s, false),
                Err(_) => {
                    return_begin_buf(begin);
                    return None;
                }
            }
        };
        let (result, returned_buf) = run_once(
            stream,
            reused,
            begin,
            is_head,
            now,
            read_timeout,
            max_process_time,
            target,
            generation,
            pooled_slot.as_mut(),
        )
        .await;
        begin = returned_buf;
        match result {
            AttemptResult::Response(resp) => {
                return_begin_buf(begin);
                return Some(resp);
            }
            AttemptResult::RetryFresh if reused && attempt == 0 && !begin.is_empty() => continue,
            AttemptResult::RetryFresh | AttemptResult::Fallback => {
                return_begin_buf(begin);
                return None;
            }
        }
    }
    return_begin_buf(begin);
    None
}

#[allow(clippy::too_many_arguments)]
async fn run_once(
    mut stream: UnixStream,
    reused: bool,
    begin_buf: BytesMut,
    is_head: bool,
    sent_at: Instant,
    read_timeout: Duration,
    max_process_time: Option<Duration>,
    target: &MonoioPoolTarget,
    generation: u64,
    slot: &mut Slot,
) -> (AttemptResult, BytesMut) {
    let abs_deadline = max_process_time.map(|d| sent_at + d);
    let next_deadline = || {
        let idle = super::write_watch::coarse_now() + read_timeout;
        match abs_deadline {
            Some(abs) => idle.min(abs),
            None => idle,
        }
    };

    // Write BEGIN_REQUEST: try a direct nonblocking `send(2)` directly from
    // `BytesMut` (zero `freeze`/`try_into_mut` refcount churn). Only freeze on
    // the rare `EAGAIN` or partial-write io_uring fallback.
    let begin_buf = {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let len = begin_buf.len();
        // SAFETY: `fd` is an open nonblocking UDS owned by `stream`, and
        // `begin_buf` is a valid initialized byte slice of length `len`.
        let rc = unsafe {
            libc::send(
                fd,
                begin_buf.as_ptr().cast(),
                len,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if rc >= 0 && (rc as usize) == len {
            begin_buf
        } else if rc > 0 {
            let written = rc as usize;
            let begin_buf = begin_buf.freeze();
            let tail = begin_buf.slice(written..);
            match with_slot(slot, next_deadline(), stream.write_all(tail)).await {
                Ok((Ok(_), tail)) => {
                    drop(tail);
                    begin_buf.try_into_mut().unwrap_or_default()
                }
                Ok((Err(e), tail)) => {
                    drop(tail);
                    let ret = begin_buf.try_into_mut().unwrap_or_default();
                    if reused
                        && matches!(
                            e.kind(),
                            io::ErrorKind::BrokenPipe
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::UnexpectedEof
                        )
                    {
                        return (AttemptResult::RetryFresh, ret);
                    }
                    return (AttemptResult::Fallback, ret);
                }
                Err(()) => return (AttemptResult::Fallback, BytesMut::new()),
            }
        } else {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::Interrupted {
                let begin_buf = begin_buf.freeze();
                match with_slot(slot, next_deadline(), stream.write_all(begin_buf)).await {
                    Ok((Ok(_), buf)) => buf.try_into_mut().unwrap_or_default(),
                    Ok((Err(e), buf)) => {
                        let ret = buf.try_into_mut().unwrap_or_default();
                        if reused
                            && matches!(
                                e.kind(),
                                io::ErrorKind::BrokenPipe
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::UnexpectedEof
                            )
                        {
                            return (AttemptResult::RetryFresh, ret);
                        }
                        return (AttemptResult::Fallback, ret);
                    }
                    Err(()) => return (AttemptResult::Fallback, BytesMut::new()),
                }
            } else if reused
                && matches!(
                    err.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::UnexpectedEof
                )
            {
                return (AttemptResult::RetryFresh, begin_buf);
            } else {
                return (AttemptResult::Fallback, begin_buf);
            }
        }
    };

    let mut acc = take_read_buf();
    acc.clear();
    let mut pos: usize = 0;
    let mut saw_packet = false;

    // Helper: read more bytes directly into `acc`'s spare capacity without
    // allocating a fresh 64 KiB `Vec` on partial packet reads.
    async fn read_more(
        stream: &mut UnixStream,
        acc: &mut Vec<u8>,
        pos: &mut usize,
        deadline: Instant,
        slot: &mut Slot,
    ) -> Result<io::Result<usize>, ()> {
        if *pos >= acc.len() {
            acc.clear();
            *pos = 0;
        } else if *pos > 0 {
            acc.copy_within(*pos.., 0);
            acc.truncate(acc.len() - *pos);
            *pos = 0;
        }
        if acc.capacity().saturating_sub(acc.len()) < 4096 {
            acc.reserve(READ_BUF_SIZE);
        }
        let buf = AppendVecBuf(std::mem::take(acc));
        let res = with_slot(slot, deadline, stream.read(buf)).await;
        match res {
            Ok((r, AppendVecBuf(buf))) => {
                *acc = buf;
                Ok(r)
            }
            Err(()) => Err(()),
        }
    }

    // 1. Read until RESP_HEADER and parse straight into `http::Response` head.
    let (mut response, enforced_len, unbuffered) = loop {
        match try_parse_packet(&acc, pos) {
            Ok(Some((ptype, little_endian, body_start, next_pos))) => {
                saw_packet = true;
                let body_slice = acc.get(body_start..next_pos).unwrap_or_default();
                match ptype {
                    PacketType::RespHeader => {
                        let parsed = parse_inline_response_head_raw(
                            body_slice,
                            little_endian,
                            is_head,
                            None,
                        );
                        pos = next_pos;
                        match parsed {
                            Ok(h) => break h,
                            Err(_) => {
                                return_read_buf(acc);
                                return (AttemptResult::Fallback, begin_buf);
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
                        return (AttemptResult::Fallback, begin_buf);
                    }
                    _ => {
                        pos = next_pos;
                    }
                }
            }
            Ok(None) => match read_more(&mut stream, &mut acc, &mut pos, next_deadline(), slot)
                .await
            {
                Ok(Ok(0)) => {
                    let empty = acc.is_empty();
                    return_read_buf(acc);
                    if !saw_packet && empty && reused {
                        return (AttemptResult::RetryFresh, begin_buf);
                    }
                    return (AttemptResult::Fallback, begin_buf);
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    let empty = acc.is_empty();
                    return_read_buf(acc);
                    if !saw_packet && empty && reused && e.kind() == io::ErrorKind::ConnectionReset
                    {
                        return (AttemptResult::RetryFresh, begin_buf);
                    }
                    return (AttemptResult::Fallback, begin_buf);
                }
                Err(()) => {
                    return_read_buf(acc);
                    return (AttemptResult::Fallback, begin_buf);
                }
            },
            Err(()) => {
                return_read_buf(acc);
                return (AttemptResult::Fallback, begin_buf);
            }
        }
    };
    if unbuffered || enforced_len.is_some_and(|l| l > MAX_BODY_CAP as u64) {
        // Rare unbuffered/large response: close socket and fall back.
        return_read_buf(acc);
        return (AttemptResult::Fallback, begin_buf);
    }

    // 2. Read RESP_STREAM chunks until RESP_END. Single-pass assembly: 1-chunk
    // responses stay zero-Vec (`One(Bytes)`), and multi-chunk responses (>8 KiB)
    // append directly into a single `BytesMut` instead of copying twice.
    enum BodyAcc {
        Empty,
        One(Bytes),
        Multi(BytesMut),
    }
    let mut body_acc = BodyAcc::Empty;
    let mut body_len: usize = 0;
    let clean_end = loop {
        match try_parse_packet(&acc, pos) {
            Ok(Some((ptype, _, body_start, next_pos))) => {
                let body_slice = acc.get(body_start..next_pos).unwrap_or_default();
                match ptype {
                    PacketType::RespStream => {
                        if !is_head && !body_slice.is_empty() {
                            body_len += body_slice.len();
                            if body_len > MAX_BODY_CAP {
                                return_read_buf(acc);
                                return (AttemptResult::Fallback, begin_buf);
                            }
                            match &mut body_acc {
                                BodyAcc::Empty => {
                                    if let Some(len) = enforced_len
                                        && (len as usize) > body_slice.len()
                                        && (len as usize) <= MAX_BODY_CAP
                                    {
                                        let mut buf = BytesMut::with_capacity(len as usize);
                                        buf.extend_from_slice(body_slice);
                                        body_acc = BodyAcc::Multi(buf);
                                    } else {
                                        body_acc = BodyAcc::One(Bytes::copy_from_slice(body_slice));
                                    }
                                }
                                BodyAcc::One(first) => {
                                    let cap = enforced_len
                                        .map(|l| (l as usize).min(MAX_BODY_CAP))
                                        .unwrap_or(0)
                                        .max(first.len() + body_slice.len());
                                    let mut buf = BytesMut::with_capacity(cap);
                                    buf.extend_from_slice(first);
                                    buf.extend_from_slice(body_slice);
                                    body_acc = BodyAcc::Multi(buf);
                                }
                                BodyAcc::Multi(buf) => {
                                    buf.extend_from_slice(body_slice);
                                }
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
                        return (AttemptResult::Fallback, begin_buf);
                    }
                    _ => {
                        pos = next_pos;
                    }
                }
            }
            Ok(None) => {
                match read_more(&mut stream, &mut acc, &mut pos, next_deadline(), slot).await {
                    Ok(Ok(0)) => break false,
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(()) => {
                        return_read_buf(acc);
                        return (AttemptResult::Fallback, begin_buf);
                    }
                }
            }
            Err(()) => {
                return_read_buf(acc);
                return (AttemptResult::Fallback, begin_buf);
            }
        }
    };

    let trailing = pos < acc.len();
    return_read_buf(acc);

    if !clean_end && enforced_len.is_none() {
        return (AttemptResult::Fallback, begin_buf);
    }
    if let Some(len) = enforced_len
        && (body_len as u64) < len
    {
        return (AttemptResult::Fallback, begin_buf);
    }
    let over_delivered = enforced_len.is_some_and(|len| body_len as u64 > len);
    let final_len = enforced_len.map_or(body_len, |len| len as usize);
    let body = match body_acc {
        BodyAcc::Empty => Bytes::new(),
        BodyAcc::One(mut b) => {
            b.truncate(final_len);
            b
        }
        BodyAcc::Multi(mut buf) => {
            buf.truncate(final_len);
            buf.freeze()
        }
    };

    // Return the clean UDS socket to the shared idle pool if generation is unchanged
    // so every monoio worker and Tokio share all lsphp children symmetrically (#896).
    if clean_end && !over_delivered && !trailing && target.pool.generation() == generation {
        let raw_fd = stream.into_raw_fd();
        // SAFETY: `into_raw_fd` transfers unique ownership of the open UDS fd.
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(raw_fd) };
        target
            .pool
            .push_monoio_idle(std_stream, generation, super::write_watch::coarse_now());
    }

    *response.body_mut() = if is_head {
        Body::Empty
    } else {
        Body::Full(body)
    };
    (AttemptResult::Response(response), begin_buf)
}
