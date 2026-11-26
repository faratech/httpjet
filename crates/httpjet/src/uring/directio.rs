//! `DirectWriteSocket`: a monoio `TcpStream` wrapper with direct nonblocking
//! TCP writes and an io_uring fallback on `EAGAIN`. Reads stay on io_uring.
//!
//! Why: on loopback bulk transfer io_uring's write is *slower* than a plain `write(2)`
//! — io_uring's edge is hiding *blocking* I/O, but a loopback socket write never blocks,
//! so the submit→reap round-trip is pure overhead. tokio uses a plain `write` syscall and
//! wins large-body egress for exactly this reason. Wrapping the socket UNDER
//! `monoio_rustls::ServerTlsStream` (which is generic over its IO) means rustls/aws-lc-rs
//! still does the AEAD — only the socket write of the already-encrypted bytes switches to a
//! syscall, matching tokio's write path and closing the userspace-TLS large-body gap.

use std::future::Future;
use std::os::fd::{AsRawFd, RawFd};

use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};
use monoio::io::{AsyncReadRent, AsyncWriteRent, Split};
use monoio::net::TcpStream;

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum MediumTlsWrite {
    Direct,
    Ring,
    Adaptive,
}

#[cfg(any(target_arch = "aarch64", test))]
#[derive(Clone, Copy)]
struct MediumWriteBurst {
    start: std::time::Instant,
    last: std::time::Instant,
    writes: u8,
    carried: bool,
}

#[cfg(any(target_arch = "aarch64", test))]
impl MediumWriteBurst {
    fn new(now: std::time::Instant) -> Self {
        Self {
            start: now,
            last: now,
            writes: 0,
            carried: false,
        }
    }

    fn record(&mut self, now: std::time::Instant) -> bool {
        use std::time::Duration;
        const BUSY_WRITES: u8 = 12;
        // At low offered rates an isolated write takes the direct path.
        // Reuse a busy window only while writes keep arriving.
        if now.duration_since(self.last) >= Duration::from_micros(200) {
            *self = Self::new(now);
        } else if now.duration_since(self.start) >= Duration::from_millis(1) {
            self.carried = self.writes >= BUSY_WRITES;
            self.start = now;
            self.writes = 0;
        }
        self.last = now;
        self.writes = self.writes.saturating_add(1);
        self.carried || self.writes >= BUSY_WRITES
    }
}

#[cfg(target_arch = "aarch64")]
fn medium_write_burst() -> bool {
    thread_local! {
        static BURST: std::cell::Cell<Option<MediumWriteBurst>> = const { std::cell::Cell::new(None) };
    }
    BURST.with(|slot| {
        let now = std::time::Instant::now();
        let mut burst = slot.get().unwrap_or_else(|| MediumWriteBurst::new(now));
        let batching = burst.record(now);
        slot.set(Some(burst));
        batching
    })
}

pub(crate) struct DirectWriteSocket {
    inner: TcpStream,
    fd: RawFd,
    /// (#335) H1-over-TLS only: small ciphertext writes ride the io_uring ring
    /// so many keep-alive sockets' responses batch into shared enters
    /// (+7% h1/empty/c50, 5/5 pairs). H2 stays direct-always — its tiny
    /// control-frame writes are latency-sensitive and measured -3..-5% when
    /// ringed. Bulk writes take the direct syscall (the loopback bulk
    /// case this module exists for).
    ring_small: bool,
    #[cfg(target_arch = "aarch64")]
    medium_tls: MediumTlsWrite,
}

impl DirectWriteSocket {
    pub(crate) fn new_for(inner: TcpStream, ring_small: bool) -> Self {
        let mut s = Self::new(inner);
        s.ring_small = ring_small;
        #[cfg(target_arch = "aarch64")]
        if ring_small {
            static MODE: std::sync::OnceLock<MediumTlsWrite> = std::sync::OnceLock::new();
            s.medium_tls =
                *MODE.get_or_init(|| match std::env::var("HJ_H1_RING_MEDIUM_TLS").as_deref() {
                    Ok("1") => MediumTlsWrite::Ring,
                    Ok("adaptive") => MediumTlsWrite::Adaptive,
                    _ => MediumTlsWrite::Direct,
                });
        }
        s
    }

    pub(crate) fn new(inner: TcpStream) -> Self {
        let fd = inner.as_raw_fd();
        // O_NONBLOCK so a full socket buffer returns EAGAIN (→ io_uring fallback) instead of
        // blocking the core. io_uring ops are unaffected (they wait via the ring).
        // SAFETY: plain fcntl on our owned socket fd.
        unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            if fl >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
        Self {
            inner,
            fd,
            ring_small: false,
            #[cfg(target_arch = "aarch64")]
            medium_tls: MediumTlsWrite::Direct,
        }
    }
}

impl AsyncReadRent for DirectWriteSocket {
    fn read<T: IoBufMut>(&mut self, buf: T) -> impl Future<Output = BufResult<usize, T>> {
        self.inner.read(buf)
    }
    fn readv<T: IoVecBufMut>(&mut self, buf: T) -> impl Future<Output = BufResult<usize, T>> {
        self.inner.readv(buf)
    }
}

/// (#335) Writes up to this many bytes go through the io_uring ring instead
/// of the direct write(2): under a high rate of SMALL responses the ring
/// batches many sockets' writes into the enters the reads already pay
/// (measured +9-22% on h1/empty/c50, all interleaved pairs), while LARGE
/// egress keeps the direct syscall this module was built for (ring
/// submit->reap is pure overhead when the copy dominates and the write
/// never blocks).
const RING_WRITE_MAX: usize = 16 * 1024;

impl AsyncWriteRent for DirectWriteSocket {
    fn write<T: IoBuf>(&mut self, buf: T) -> impl Future<Output = BufResult<usize, T>> {
        async move {
            let len = buf.bytes_init();
            if len == 0 {
                return (Ok(0), buf);
            }
            if self.ring_small && len <= RING_WRITE_MAX {
                return self.inner.write(buf).await;
            }
            // SAFETY: `buf` owns `len` initialized bytes at `read_ptr()` for this call.
            let n = unsafe { libc::write(self.fd, buf.read_ptr() as *const libc::c_void, len) };
            if n >= 0 {
                return (Ok(n as usize), buf);
            }
            let e = std::io::Error::last_os_error();
            let os_error = e.raw_os_error();
            if os_error == Some(libc::EAGAIN) || os_error == Some(libc::EWOULDBLOCK) {
                self.inner.write(buf).await
            } else {
                (Err(e), buf)
            }
        }
    }
    fn writev<T: IoVecBuf>(&mut self, buf_vec: T) -> impl Future<Output = BufResult<usize, T>> {
        async move {
            let count = buf_vec.read_iovec_len().min(64);
            if count == 0 {
                return (Ok(0), buf_vec);
            }
            #[cfg(target_arch = "aarch64")]
            if self.medium_tls != MediumTlsWrite::Direct && (1..=3).contains(&count) {
                // SAFETY: IoVecBuf owns these initialized descriptors for the rental.
                let segments =
                    unsafe { std::slice::from_raw_parts(buf_vec.read_iovec_ptr(), count) };
                let bytes = segments.iter().fold(0usize, |total, segment| {
                    total.saturating_add(segment.iov_len)
                });
                if (16 * 1024..=32 * 1024 + 512).contains(&bytes)
                    && (self.medium_tls == MediumTlsWrite::Ring || medium_write_burst())
                {
                    return self.inner.writev(buf_vec).await;
                }
            }
            // SAFETY: an all-zero msghdr is an empty C message header. Set
            // only the iovecs so both libc layouts retain zeroed padding.
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = buf_vec.read_iovec_ptr().cast_mut();
            message.msg_iovlen = count as _; // bounded to 64 on all targets
            loop {
                // SAFETY: the IoVecBuf owns count readable descriptors and
                // their payloads for this synchronous, nonblocking call.
                let sent = unsafe {
                    libc::sendmsg(self.fd, &message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
                };
                if sent >= 0 {
                    return (Ok(sent as usize), buf_vec);
                }
                let error = std::io::Error::last_os_error();
                match error.kind() {
                    std::io::ErrorKind::Interrupted => {}
                    std::io::ErrorKind::WouldBlock => return self.inner.writev(buf_vec).await,
                    _ => return (Err(error), buf_vec),
                }
            }
        }
    }
    fn flush(&mut self) -> impl Future<Output = std::io::Result<()>> {
        self.inner.flush()
    }
    fn shutdown(&mut self) -> impl Future<Output = std::io::Result<()>> {
        self.inner.shutdown()
    }
}

// SAFETY: read and write touch disjoint socket state (read side vs write side); the inner
// TcpStream is itself `Split`. Mirrors monoio's model for split read/write halves.
unsafe impl Split for DirectWriteSocket {}

impl AsRawFd for DirectWriteSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(test)]
#[test]
fn medium_write_burst_requires_current_demand() {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let mut burst = MediumWriteBurst::new(start);
    let at = |us| start + Duration::from_micros(us);
    for n in 0..11 {
        assert!(!burst.record(at(n * 50)));
    }
    for n in 11..=20 {
        assert!(burst.record(at(n * 50)));
    }
    assert!(!burst.record(at(1250)));
    assert!(!burst.record(at(2250)));
}
