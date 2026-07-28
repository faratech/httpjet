//! `DirectWriteSocket`: a monoio `TcpStream` wrapper whose WRITES use a direct
//! `write(2)` syscall (with an io_uring fallback on `EAGAIN`) instead of an io_uring
//! write op. Reads stay on io_uring.
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

pub(crate) struct DirectWriteSocket {
    inner: TcpStream,
    fd: RawFd,
}

impl DirectWriteSocket {
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
        Self { inner, fd }
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

impl AsyncWriteRent for DirectWriteSocket {
    fn write<T: IoBuf>(&mut self, buf: T) -> impl Future<Output = BufResult<usize, T>> {
        async move {
            let len = buf.bytes_init();
            if len == 0 {
                return (Ok(0), buf);
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
        // monoio-rustls's write path uses scalar write_all (not writev), so this delegates.
        self.inner.writev(buf_vec)
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
