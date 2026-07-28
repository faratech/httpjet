use std::{
    io::{self, Read, Write},
    ops::{Deref, DerefMut},
};

use monoio::{
    buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut, RawBuf},
    io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Split},
    BufResult,
};
use monoio_io_wrapper::ReadBuffer;
use rustls::{ClientConnection, ConnectionCommon, ServerConnection, SideData};

const TLS_WRITE_BUFFER_IDLE: usize = 64 * 1024;
const TLS_WRITE_BUFFER_BURST: usize = 512 * 1024;

#[derive(Debug)]
pub struct Stream<IO, C> {
    pub(crate) io: IO,
    pub(crate) session: C,
    r_buffer: ReadBuffer,
    w_buffer: WriteBuffer,
}

impl<IO> Stream<IO, ServerConnection> {
    #[inline]
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.session.alpn_protocol().map(|s| s.to_vec())
    }
}

impl<IO> Stream<IO, ClientConnection> {
    #[inline]
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.session.alpn_protocol().map(|s| s.to_vec())
    }
}

unsafe impl<IO: Split, C> Split for Stream<IO, C> {}

impl<IO, C> Stream<IO, C> {
    pub fn new(io: IO, session: C) -> Self {
        Self {
            io,
            session,
            r_buffer: Default::default(),
            // httpjet fork: adaptive TLS write buffer. Idle Cloudflare origin connections
            // are numerous, so keep the resident baseline small; large writes still grow to
            // the old 512 KiB batching ceiling for throughput, then shrink after the flush.
            w_buffer: WriteBuffer::new(TLS_WRITE_BUFFER_IDLE),
        }
    }

    /// Enable unsafe-io.
    /// # Safety
    /// Users must make sure the buffer ptr and len is valid until io finished.
    /// So the Future cannot be dropped directly. Consider using CancellableIO.
    #[cfg(feature = "unsafe_io")]
    pub unsafe fn new_unsafe(io: IO, session: C) -> Self {
        Self {
            io,
            session,
            r_buffer: ReadBuffer::new_unsafe(),
            w_buffer: WriteBuffer::new_unsafe(),
        }
    }

    pub fn into_parts(self) -> (IO, C) {
        (self.io, self.session)
    }

    pub(crate) fn map_conn<C2, F: FnOnce(C) -> C2>(self, f: F) -> Stream<IO, C2> {
        Stream {
            io: self.io,
            session: f(self.session),
            r_buffer: self.r_buffer,
            w_buffer: self.w_buffer,
        }
    }
}

#[derive(Debug)]
enum WriteBuffer {
    Safe(SafeWriteBuffer),
    #[cfg(feature = "unsafe_io")]
    Unsafe(monoio_io_wrapper::WriteBuffer),
}

impl WriteBuffer {
    fn new(buffer_size: usize) -> Self {
        Self::Safe(SafeWriteBuffer::new(buffer_size))
    }

    #[cfg(feature = "unsafe_io")]
    pub const unsafe fn new_unsafe() -> Self {
        Self::Unsafe(monoio_io_wrapper::WriteBuffer::new_unsafe())
    }

    async fn do_io<IO: AsyncWriteRent>(&mut self, mut io: IO) -> io::Result<usize> {
        match self {
            Self::Safe(buf) => buf.do_io(&mut io).await,
            #[cfg(feature = "unsafe_io")]
            Self::Unsafe(buf) => buf.do_io(&mut io).await,
        }
    }

    #[cfg(feature = "unsafe_io")]
    fn is_safe(&self) -> bool {
        match self {
            Self::Safe(_) => true,
            Self::Unsafe(buf) => buf.is_safe(),
        }
    }

    #[cfg(not(feature = "unsafe_io"))]
    const fn is_safe(&self) -> bool {
        true
    }

    fn shrink_to_idle(&mut self) {
        match self {
            Self::Safe(buf) => buf.shrink_to(TLS_WRITE_BUFFER_IDLE),
            #[cfg(feature = "unsafe_io")]
            Self::Unsafe(_) => {}
        }
    }
}

impl io::Write for WriteBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Safe(b) => b.write(buf),
            #[cfg(feature = "unsafe_io")]
            Self::Unsafe(b) => b.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Safe(b) => b.flush(),
            #[cfg(feature = "unsafe_io")]
            Self::Unsafe(b) => b.flush(),
        }
    }
}

#[derive(Debug)]
struct SafeWriteBuffer {
    buffer: Option<Buffer>,
    status: WriteStatus,
}

#[derive(Debug)]
enum WriteStatus {
    Err(io::Error),
    Ok,
}

impl SafeWriteBuffer {
    fn new(buffer_size: usize) -> Self {
        Self {
            buffer: Some(Buffer::new(buffer_size)),
            status: WriteStatus::Ok,
        }
    }

    async fn do_io<IO: AsyncWriteRent>(&mut self, mut io: IO) -> io::Result<usize> {
        let buffer = self.buffer.as_ref().expect("buffer ref expected");
        if buffer.is_empty() {
            return Ok(0);
        }

        let buffer = self.buffer.take().expect("buffer present");
        let (result, mut buffer) = io.write_all(buffer).await;
        match result {
            Ok(written_len) => {
                buffer.advance(written_len);
                self.buffer = Some(buffer);
                Ok(written_len)
            }
            Err(e) => {
                let rerr = e.kind().into();
                self.status = WriteStatus::Err(e);
                self.buffer = Some(buffer);
                Err(rerr)
            }
        }
    }

    fn shrink_to(&mut self, target: usize) {
        let Some(buffer) = self.buffer.as_mut() else {
            return;
        };
        if buffer.is_empty() && buffer.capacity() > target {
            *buffer = Buffer::new(target);
        }
    }
}

impl io::Write for SafeWriteBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let buffer = self.buffer.as_mut().expect("buffer mut expected");
        match std::mem::replace(&mut self.status, WriteStatus::Ok) {
            WriteStatus::Err(e) => return Err(e),
            WriteStatus::Ok => {}
        }

        if !buf.is_empty()
            && buffer.available() < buf.len()
            && buffer.capacity() < TLS_WRITE_BUFFER_BURST
        {
            let needed = buffer.len().saturating_add(buf.len());
            let grown = buffer
                .capacity()
                .saturating_mul(2)
                .max(needed)
                .min(TLS_WRITE_BUFFER_BURST);
            buffer.grow_to(grown);
        }

        if buffer.is_full() {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        Ok(buffer.copy_from(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        let buffer = self.buffer.as_mut().expect("buffer mut expected");
        match std::mem::replace(&mut self.status, WriteStatus::Ok) {
            WriteStatus::Err(e) => Err(e),
            WriteStatus::Ok if !buffer.is_empty() => Err(io::ErrorKind::WouldBlock.into()),
            WriteStatus::Ok => Ok(()),
        }
    }
}

#[derive(Debug)]
struct Buffer {
    read: usize,
    write: usize,
    buf: Box<[u8]>,
}

impl Buffer {
    fn new(size: usize) -> Self {
        Self {
            read: 0,
            write: 0,
            buf: vec![0; size].into_boxed_slice(),
        }
    }

    fn capacity(&self) -> usize {
        self.buf.len()
    }

    fn len(&self) -> usize {
        self.write - self.read
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn available(&self) -> usize {
        self.buf.len() - self.write
    }

    fn is_full(&self) -> bool {
        self.available() == 0
    }

    fn advance(&mut self, n: usize) {
        assert!(self.read + n <= self.write);
        self.read += n;
        if self.read == self.write {
            self.read = 0;
            self.write = 0;
        }
    }

    fn grow_to(&mut self, new_cap: usize) {
        if new_cap <= self.buf.len() {
            return;
        }
        if self.read > 0 {
            self.buf.copy_within(self.read..self.write, 0);
            self.write -= self.read;
            self.read = 0;
        }
        let len = self.write;
        let mut next = vec![0; new_cap].into_boxed_slice();
        next[..len].copy_from_slice(&self.buf[..len]);
        self.buf = next;
    }

    fn copy_from(&mut self, src: &[u8]) -> usize {
        let to_copy = src.len().min(self.available());
        self.buf[self.write..self.write + to_copy].copy_from_slice(&src[..to_copy]);
        self.write += to_copy;
        to_copy
    }
}

// SAFETY: `read_ptr` points at initialized bytes in `buf[read..write]`, and
// `bytes_init` returns exactly that initialized length.
unsafe impl IoBuf for Buffer {
    fn read_ptr(&self) -> *const u8 {
        self.buf[self.read..].as_ptr()
    }

    fn bytes_init(&self) -> usize {
        self.write - self.read
    }
}

// SAFETY: `write_ptr` points at spare capacity in `buf[write..]`; `set_init`
// advances `write` by the number of bytes the I/O operation initialized.
unsafe impl monoio::buf::IoBufMut for Buffer {
    fn write_ptr(&mut self) -> *mut u8 {
        self.buf[self.write..].as_mut_ptr()
    }

    fn bytes_total(&mut self) -> usize {
        self.buf.len() - self.write
    }

    unsafe fn set_init(&mut self, pos: usize) {
        self.write += pos;
    }
}

impl<IO: AsyncReadRent + AsyncWriteRent, C, SD: SideData> Stream<IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    pub(crate) async fn read_io(&mut self, splitted: bool) -> io::Result<usize> {
        let n = loop {
            match self.session.read_tls(&mut self.r_buffer) {
                Ok(n) => {
                    break n;
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    #[allow(unused_unsafe)]
                    unsafe {
                        self.r_buffer.do_io(&mut self.io).await?
                    };
                    continue;
                }
                Err(err) => return Err(err),
            }
        };

        let state = match self.session.process_new_packets() {
            Ok(state) => state,
            Err(err) => {
                // When to write_io? If we do this in read call, the UnsafeWrite may crash
                // when we impl split in an UnsafeCell way.
                // Here we choose not to do write when read.
                // User should manually shutdown it on error.
                if !splitted {
                    let _ = self.write_io().await;
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };

        if state.peer_has_closed() && self.session.is_handshaking() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tls handshake alert",
            ));
        }

        Ok(n)
    }

    pub(crate) async fn write_io(&mut self) -> io::Result<usize> {
        let n = loop {
            match self.session.write_tls(&mut self.w_buffer) {
                Ok(n) => {
                    if self.w_buffer.is_safe() {
                        self.w_buffer.do_io(&mut self.io).await?;
                    }
                    break n;
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    // here we don't have to check WouldBlock since we already captured the
                    // mem block info under unsafe-io.
                    #[allow(unused_unsafe)]
                    unsafe {
                        self.w_buffer.do_io(&mut self.io).await?
                    };
                    continue;
                }
                Err(err) => return Err(err),
            }
        };

        Ok(n)
    }

    pub(crate) async fn handshake(&mut self) -> io::Result<(usize, usize)> {
        let mut wrlen = 0;
        let mut rdlen = 0;
        let mut eof = false;

        loop {
            while self.session.wants_write() && self.session.is_handshaking() {
                wrlen += self.write_io().await?;
            }
            while !eof && self.session.wants_read() && self.session.is_handshaking() {
                let n = self.read_io(false).await?;
                rdlen += n;
                if n == 0 {
                    eof = true;
                }
            }

            match (eof, self.session.is_handshaking()) {
                (true, true) => {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
                    return Err(err);
                }
                (false, true) => (),
                (_, false) => {
                    break;
                }
            };
        }

        // flush buffer
        while self.session.wants_write() {
            wrlen += self.write_io().await?;
        }
        self.w_buffer.shrink_to_idle();

        Ok((rdlen, wrlen))
    }

    pub(crate) async fn read_inner<T: monoio::buf::IoBufMut>(
        &mut self,
        mut buf: T,
        splitted: bool,
    ) -> BufResult<usize, T> {
        let slice = unsafe { std::slice::from_raw_parts_mut(buf.write_ptr(), buf.bytes_total()) };
        loop {
            // read from rustls to buffer
            match self.session.reader().read(slice) {
                Ok(n) => {
                    unsafe { buf.set_init(n) };
                    return (Ok(n), buf);
                }
                // we need more data, read something.
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => (),
                Err(e) => {
                    return (Err(e), buf);
                }
            }

            // now we need data, read something into rustls
            if let Err(e) = self.read_io(splitted).await {
                return (Err(e), buf);
            }
        }
    }
}

impl<IO: AsyncReadRent + AsyncWriteRent, C, SD: SideData + 'static> AsyncReadRent for Stream<IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    async fn read<T: IoBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        self.read_inner(buf, false).await
    }

    async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let n = match unsafe { RawBuf::new_from_iovec_mut(&mut buf) } {
            Some(raw_buf) => self.read(raw_buf).await.0,
            None => Ok(0),
        };
        if let Ok(n) = n {
            unsafe { buf.set_init(n) };
        }
        (n, buf)
    }
}

impl<IO: AsyncReadRent + AsyncWriteRent, C, SD: SideData + 'static> AsyncWriteRent for Stream<IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        // construct slice
        let slice = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };

        // flush rustls inner write buffer to make sure there is space for new data
        if self.session.wants_write() {
            if let Err(e) = self.write_io().await {
                return (Err(e), buf);
            }
        }

        // write slice to rustls
        let n = match self.session.writer().write(slice) {
            Ok(n) => n,
            Err(e) => return (Err(e), buf),
        };

        // write from rustls to connection
        while self.session.wants_write() {
            match self.write_io().await {
                Ok(0) => {
                    break;
                }
                Ok(_) => (),
                Err(e) => return (Err(e), buf),
            }
        }
        self.w_buffer.shrink_to_idle();
        (Ok(n), buf)
    }

    // Real vectored write (httpjet fork): queue EVERY iovec into the rustls plaintext
    // writer, then flush the encrypted bytes — matching tokio's `write_vectored`-into-rustls
    // path (one buffered copy). Upstream 0.4.0 only wrote the FIRST iovec.
    async fn writev<T: IoVecBuf>(&mut self, buf_vec: T) -> BufResult<usize, T> {
        // Flush any pending rustls output first so there is room for new plaintext.
        if self.session.wants_write() {
            if let Err(e) = self.write_io().await {
                return (Err(e), buf_vec);
            }
        }
        let ptr = buf_vec.read_iovec_ptr();
        let cnt = buf_vec.read_iovec_len();
        // Gather all iovecs into ONE rustls `write_vectored` (rustls overrides it to copy
        // every slice into its plaintext buffer in a single call) — matching tokio-rustls.
        // SAFETY: the IoVecBuf contract guarantees `cnt` valid iovecs at `ptr`, each over
        // initialized bytes valid for this call; IoSlice is repr-compatible.
        let slices: Vec<std::io::IoSlice> = (0..cnt)
            .map(|i| unsafe {
                let iov = &*ptr.add(i);
                std::io::IoSlice::new(std::slice::from_raw_parts(
                    iov.iov_base as *const u8,
                    iov.iov_len,
                ))
            })
            .collect();
        let total = match self.session.writer().write_vectored(&slices) {
            Ok(n) => n,
            Err(e) => return (Err(e), buf_vec),
        };
        while self.session.wants_write() {
            match self.write_io().await {
                Ok(0) => break,
                Ok(_) => (),
                Err(e) => return (Err(e), buf_vec),
            }
        }
        self.w_buffer.shrink_to_idle();
        (Ok(total), buf_vec)
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.session.writer().flush()?;
        while self.session.wants_write() {
            self.write_io().await?;
        }
        let result = self.io.flush().await;
        if result.is_ok() {
            self.w_buffer.shrink_to_idle();
        }
        result
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.session.send_close_notify();

        while self.session.wants_write() {
            self.write_io().await?;
        }
        self.w_buffer.shrink_to_idle();
        self.io.shutdown().await
    }
}
