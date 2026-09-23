use std::{
    cell::RefCell,
    io::{self, Read, Write},
    ops::{Deref, DerefMut},
    rc::Rc,
};

use monoio::{
    buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut, RawBuf},
    io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Splitable},
    BufResult,
};
use monoio_io_wrapper::ReadBuffer;
use rustls::{ClientConnection, ConnectionCommon, ServerConnection, SideData};

const TLS_WRITE_BUFFER_IDLE: usize = 64 * 1024;
const TLS_WRITE_BUFFER_BURST: usize = 512 * 1024;
/// Idle-size write buffers kept warm per thread (see [`take_idle_box`]).
const IDLE_BUFFER_POOL_CAP: usize = 32;

thread_local! {
    static IDLE_BUFFERS: RefCell<Vec<Box<[u8]>>> = const { RefCell::new(Vec::new()) };
}

/// httpjet fork: a connection holds a write buffer only while it has ciphertext to send.
/// Idle origin connections are numerous (thousands of Cloudflare connections held open
/// between requests) and each used to keep a 64 KiB buffer; a flushed buffer now returns
/// to this thread's pool and the next write takes a warm one, so there is no allocation
/// or page fault per response.
fn take_idle_box() -> Box<[u8]> {
    IDLE_BUFFERS
        .try_with(|pool| pool.borrow_mut().pop())
        .ok()
        .flatten()
        .unwrap_or_else(|| uninit_box(TLS_WRITE_BUFFER_IDLE))
}

fn put_idle_box(buf: Box<[u8]>) {
    let _ = IDLE_BUFFERS.try_with(move |pool| {
        let mut pool = pool.borrow_mut();
        if pool.len() < IDLE_BUFFER_POOL_CAP {
            pool.push(buf);
        }
    });
}

#[derive(Debug)]
pub struct Stream<IO, C> {
    pub(crate) io: IO,
    pub(crate) session: C,
    r_buffer: ReadBuffer,
    w_buffer: WriteBuffer,
}

/// Read half of a TLS stream. Only the raw transport is split: the rustls
/// connection remains a single value behind a checked, single-threaded cell.
/// Every borrow of that connection is released before an I/O await.
pub struct ReadHalf<IO, C> {
    io: IO,
    session: Rc<RefCell<C>>,
    r_buffer: ReadBuffer,
}

/// Write half of a TLS stream. The write adapter buffer belongs exclusively
/// to this half; rustls state is shared with [`ReadHalf`] through `RefCell`.
pub struct WriteHalf<IO, C> {
    io: IO,
    session: Rc<RefCell<C>>,
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

impl<IO: Splitable, C> Splitable for Stream<IO, C> {
    type OwnedRead = ReadHalf<IO::OwnedRead, C>;
    type OwnedWrite = WriteHalf<IO::OwnedWrite, C>;

    fn into_split(self) -> (Self::OwnedRead, Self::OwnedWrite) {
        let (read_io, write_io) = self.io.into_split();
        let session = Rc::new(RefCell::new(self.session));
        (
            ReadHalf {
                io: read_io,
                session: Rc::clone(&session),
                r_buffer: self.r_buffer,
            },
            WriteHalf {
                io: write_io,
                session,
                w_buffer: self.w_buffer,
            },
        )
    }
}

impl<IO, C> Stream<IO, C> {
    pub fn new(io: IO, session: C) -> Self {
        Self {
            io,
            session,
            r_buffer: Default::default(),
            // httpjet fork: adaptive TLS write buffer. Nothing is held while idle; a write
            // takes a pooled 64 KiB buffer, large writes still grow to the old 512 KiB
            // batching ceiling for throughput, and the flush releases it again.
            w_buffer: WriteBuffer::idle(),
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

    /// Borrow the rustls connection without detaching it from the transport
    /// adapter's read-ahead and pending-write buffers.
    #[inline]
    pub fn session(&self) -> &C {
        &self.session
    }

    /// Mutably borrow the rustls connection without detaching it from the
    /// transport adapter's read-ahead and pending-write buffers.
    #[inline]
    pub fn session_mut(&mut self) -> &mut C {
        &mut self.session
    }

    /// Replace only the underlying I/O object, retaining the rustls connection
    /// and both adapter buffers exactly as they stood before the mapping.
    ///
    /// This is the lossless way to wrap an accepted stream after its handshake:
    /// [`Stream::into_parts`] intentionally returns only the public I/O/session
    /// pair and therefore cannot preserve ciphertext already read ahead by the
    /// adapter.
    #[inline]
    pub fn map_io<IO2, F>(self, map: F) -> Stream<IO2, C>
    where
        F: FnOnce(IO) -> IO2,
    {
        Stream {
            io: map(self.io),
            session: self.session,
            r_buffer: self.r_buffer,
            w_buffer: self.w_buffer,
        }
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

#[cfg(test)]
mod transition_tests {
    use std::future::Future;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    use monoio::buf::IoBuf;

    use super::{Stream, WriteBuffer};

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("in-memory I/O unexpectedly yielded"),
        }
    }

    /// An in-memory transport that records what the write buffer flushed.
    #[derive(Default)]
    struct Sink(Vec<u8>);

    impl monoio::io::AsyncWriteRent for Sink {
        async fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
            // SAFETY: an IoBuf guarantees `bytes_init` initialized bytes at `read_ptr`.
            let bytes = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
            self.0.extend_from_slice(bytes);
            (Ok(bytes.len()), buf)
        }
        async fn writev<T: monoio::buf::IoVecBuf>(
            &mut self,
            _buf: T,
        ) -> monoio::BufResult<usize, T> {
            unreachable!("the write buffer flushes with write_all")
        }
        async fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn shutdown(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capacity(buffer: &WriteBuffer) -> usize {
        match buffer {
            WriteBuffer::Safe(b) => b.buffer.as_ref().expect("not in flight").capacity(),
            #[cfg(feature = "unsafe_io")]
            WriteBuffer::Unsafe(_) => unreachable!(),
        }
    }

    fn storage(buffer: &WriteBuffer) -> *const u8 {
        match buffer {
            WriteBuffer::Safe(b) => b.buffer.as_ref().expect("not in flight").buf.as_ptr(),
            #[cfg(feature = "unsafe_io")]
            WriteBuffer::Unsafe(_) => unreachable!(),
        }
    }

    /// Idle holds nothing; a write takes a pooled buffer, and the flushed buffer goes back
    /// to the pool for the next connection instead of being freed and re-faulted.
    #[test]
    fn idle_write_buffer_is_released_to_a_warm_pool() {
        super::IDLE_BUFFERS.with(|pool| pool.borrow_mut().clear());
        let mut a = WriteBuffer::idle();
        assert_eq!(capacity(&a), 0, "a fresh connection holds no write buffer");
        assert_eq!(a.write(b"").unwrap(), 0);
        assert_eq!(capacity(&a), 0, "an empty write takes nothing");

        a.write_all(b"record one").unwrap();
        assert_eq!(capacity(&a), super::TLS_WRITE_BUFFER_IDLE);
        let first = storage(&a);
        a.shrink_to_idle();
        assert_eq!(
            capacity(&a),
            super::TLS_WRITE_BUFFER_IDLE,
            "unflushed data is kept"
        );

        let mut sink = Sink::default();
        ready(a.do_io(&mut sink)).unwrap();
        assert_eq!(sink.0, b"record one");
        a.shrink_to_idle();
        assert_eq!(capacity(&a), 0, "a drained buffer is released");

        let mut b = WriteBuffer::idle();
        b.write_all(b"record two").unwrap();
        assert_eq!(
            storage(&b),
            first,
            "the next writer reuses the pooled buffer"
        );
        ready(b.do_io(&mut sink)).unwrap();
        assert_eq!(sink.0, b"record onerecord two");
    }

    /// A buffer grown past the idle size for a burst is freed, never pooled.
    #[test]
    fn grown_write_buffer_is_not_pooled() {
        super::IDLE_BUFFERS.with(|pool| pool.borrow_mut().clear());
        let mut a = WriteBuffer::idle();
        let burst = vec![7u8; super::TLS_WRITE_BUFFER_IDLE + 1];
        a.write_all(&burst).unwrap();
        assert!(capacity(&a) > super::TLS_WRITE_BUFFER_IDLE);
        let mut sink = Sink::default();
        ready(a.do_io(&mut sink)).unwrap();
        assert_eq!(sink.0, burst);
        a.shrink_to_idle();
        assert_eq!(capacity(&a), 0);
        assert!(super::IDLE_BUFFERS.with(|pool| pool.borrow().is_empty()));
    }

    #[test]
    fn map_io_preserves_session_and_adapter_buffers() {
        let session = Arc::new("session-marker");
        let mut stream = Stream::new("original-io", session.clone());

        let mut read_ahead: &[u8] = b"ciphertext-read-ahead";
        assert_eq!(
            ready(stream.r_buffer.do_io(&mut read_ahead)).unwrap(),
            b"ciphertext-read-ahead".len()
        );
        stream.w_buffer.write_all(b"pending-ciphertext").unwrap();

        let mut mapped = stream.map_io(|io| {
            assert_eq!(io, "original-io");
            "wrapped-io"
        });
        assert_eq!(mapped.io, "wrapped-io");
        assert!(Arc::ptr_eq(mapped.session(), &session));

        let mut received = [0u8; 21];
        mapped.r_buffer.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"ciphertext-read-ahead");
        match &mapped.w_buffer {
            WriteBuffer::Safe(buffer) => assert_eq!(
                buffer.buffer.as_ref().expect("write buffer").len(),
                b"pending-ciphertext".len()
            ),
            #[cfg(feature = "unsafe_io")]
            WriteBuffer::Unsafe(_) => panic!("safe constructor selected unsafe buffer"),
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
    fn idle() -> Self {
        Self::Safe(SafeWriteBuffer::idle())
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
            Self::Safe(buf) => buf.release_idle(),
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
    fn idle() -> Self {
        Self {
            buffer: Some(Buffer::empty()),
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

    /// Give a drained buffer back. `None` means an io_uring write owns it right now.
    fn release_idle(&mut self) {
        let Some(buffer) = self.buffer.as_mut() else {
            return;
        };
        if !buffer.is_empty() || buffer.capacity() == 0 {
            return;
        }
        let released = std::mem::replace(buffer, Buffer::empty());
        // A buffer grown for a burst is freed rather than pooled.
        if released.capacity() == TLS_WRITE_BUFFER_IDLE {
            put_idle_box(released.buf);
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
        if buf.is_empty() {
            return Ok(0);
        }
        if buffer.capacity() == 0 {
            *buffer = Buffer::pooled();
        }

        if buffer.available() < buf.len() && buffer.capacity() < TLS_WRITE_BUFFER_BURST {
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

/// httpjet patch (#349): allocate the ciphertext buffer without the zero fill.
/// Every byte below `write` is explicitly written (`copy_from` / `IoBufMut`
/// completion / `grow_to`'s prefix copy) before any read exposes it
/// (`read_ptr`/`bytes_init` are bounded by `write`), so the 64 KiB-per-accept
/// (512 KiB on burst growth) memset was pure cost on the handshake path.
fn uninit_box(size: usize) -> Box<[u8]> {
    // SAFETY: u8 has no invalid bit patterns and the Buffer invariant above
    // guarantees no uninitialized byte is ever read.
    unsafe { Box::new_uninit_slice(size).assume_init() }
}

impl Buffer {
    /// No storage: what an idle connection holds.
    fn empty() -> Self {
        Self {
            read: 0,
            write: 0,
            buf: Box::default(),
        }
    }

    /// An idle-size buffer from this thread's pool. Its old bytes are never read: everything
    /// below `write` (0 here) is written first, as with a fresh uninitialized allocation.
    fn pooled() -> Self {
        Self {
            read: 0,
            write: 0,
            buf: take_idle_box(),
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
        let mut next = uninit_box(new_cap);
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

        // Post-handshake messages such as KeyUpdate can queue TLS output without
        // yielding plaintext. An unsplit stream can flush it directly here.
        if !splitted && state.plaintext_bytes_to_read() == 0 {
            while self.session.wants_write() {
                if self.write_io().await? == 0 {
                    break;
                }
            }
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

impl<IO: AsyncReadRent, C, SD: SideData> ReadHalf<IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    async fn read_io(&mut self) -> io::Result<usize> {
        let n = loop {
            let result = {
                let mut session = self.session.borrow_mut();
                session.read_tls(&mut self.r_buffer)
            };
            match result {
                Ok(n) => break n,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    #[allow(unused_unsafe)]
                    unsafe {
                        self.r_buffer.do_io(&mut self.io).await?
                    };
                }
                Err(err) => return Err(err),
            }
        };

        let state = {
            let mut session = self.session.borrow_mut();
            session.process_new_packets()
        };
        let state = match state {
            Ok(state) => state,
            Err(err) => {
                // A split reader cannot write the alert queued by rustls. This
                // matches the pre-fix split behavior: return the protocol error
                // and let the connection owner close the transport.
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };
        if state.peer_has_closed() && self.session.borrow().is_handshaking() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tls handshake alert",
            ));
        }
        Ok(n)
    }

    async fn read_inner<T: IoBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let slice = unsafe { std::slice::from_raw_parts_mut(buf.write_ptr(), buf.bytes_total()) };
        loop {
            let result = {
                let mut session = self.session.borrow_mut();
                session.reader().read(slice)
            };
            match result {
                Ok(n) => {
                    unsafe { buf.set_init(n) };
                    return (Ok(n), buf);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return (Err(err), buf),
            }
            if let Err(err) = self.read_io().await {
                return (Err(err), buf);
            }
        }
    }
}

impl<IO: AsyncReadRent, C, SD: SideData + 'static> AsyncReadRent for ReadHalf<IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    async fn read<T: IoBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        self.read_inner(buf).await
    }

    async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let result = match unsafe { RawBuf::new_from_iovec_mut(&mut buf) } {
            Some(raw) => self.read(raw).await.0,
            None => Ok(0),
        };
        if let Ok(n) = result {
            unsafe { buf.set_init(n) };
        }
        (result, buf)
    }
}

impl<IO: AsyncWriteRent, C, SD: SideData> WriteHalf<IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    async fn write_io(&mut self) -> io::Result<usize> {
        let n = loop {
            let result = {
                let mut session = self.session.borrow_mut();
                session.write_tls(&mut self.w_buffer)
            };
            match result {
                Ok(n) => {
                    if self.w_buffer.is_safe() {
                        self.w_buffer.do_io(&mut self.io).await?;
                    }
                    break n;
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    #[allow(unused_unsafe)]
                    unsafe {
                        self.w_buffer.do_io(&mut self.io).await?
                    };
                }
                Err(err) => return Err(err),
            }
        };
        Ok(n)
    }

    fn wants_write(&self) -> bool {
        self.session.borrow().wants_write()
    }

    async fn flush_pending(&mut self) -> io::Result<()> {
        while self.wants_write() {
            if self.write_io().await? == 0 {
                break;
            }
        }
        Ok(())
    }
}

impl<IO: AsyncWriteRent, C, SD: SideData + 'static> AsyncWriteRent for WriteHalf<IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        if self.wants_write() {
            if let Err(err) = self.write_io().await {
                return (Err(err), buf);
            }
        }
        let slice = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
        let written = {
            let mut session = self.session.borrow_mut();
            session.writer().write(slice)
        };
        let written = match written {
            Ok(n) => n,
            Err(err) => return (Err(err), buf),
        };
        if let Err(err) = self.flush_pending().await {
            return (Err(err), buf);
        }
        self.w_buffer.shrink_to_idle();
        (Ok(written), buf)
    }

    async fn writev<T: IoVecBuf>(&mut self, buf_vec: T) -> BufResult<usize, T> {
        if self.wants_write() {
            if let Err(err) = self.write_io().await {
                return (Err(err), buf_vec);
            }
        }
        let ptr = buf_vec.read_iovec_ptr();
        let count = buf_vec.read_iovec_len();
        let total = if count <= 8 {
            let mut slices = [std::io::IoSlice::new(&[]); 8];
            for (index, slot) in slices.iter_mut().enumerate().take(count) {
                *slot = std::io::IoSlice::new(unsafe {
                    let iov = &*ptr.add(index);
                    std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len)
                });
            }
            let result = {
                let mut session = self.session.borrow_mut();
                session.writer().write_vectored(&slices[..count])
            };
            match result {
                Ok(n) => n,
                Err(err) => return (Err(err), buf_vec),
            }
        } else {
            let slices: Vec<std::io::IoSlice<'_>> = (0..count)
                .map(|index| unsafe {
                    let iov = &*ptr.add(index);
                    std::io::IoSlice::new(std::slice::from_raw_parts(
                        iov.iov_base as *const u8,
                        iov.iov_len,
                    ))
                })
                .collect();
            let result = {
                let mut session = self.session.borrow_mut();
                session.writer().write_vectored(&slices)
            };
            match result {
                Ok(n) => n,
                Err(err) => return (Err(err), buf_vec),
            }
        };
        if let Err(err) = self.flush_pending().await {
            return (Err(err), buf_vec);
        }
        self.w_buffer.shrink_to_idle();
        (Ok(total), buf_vec)
    }

    async fn flush(&mut self) -> io::Result<()> {
        {
            let mut session = self.session.borrow_mut();
            session.writer().flush()?;
        }
        self.flush_pending().await?;
        let result = self.io.flush().await;
        if result.is_ok() {
            self.w_buffer.shrink_to_idle();
        }
        result
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.session.borrow_mut().send_close_notify();
        self.flush_pending().await?;
        self.w_buffer.shrink_to_idle();
        self.io.shutdown().await
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
        // (#322) Typical H1/H2 flushes carry <=4 iovecs; keep those on the stack and
        // only heap-allocate for pathological counts.
        if cnt <= 8 {
            let mut slices = [
                std::io::IoSlice::new(&[]),
                std::io::IoSlice::new(&[]),
                std::io::IoSlice::new(&[]),
                std::io::IoSlice::new(&[]),
                std::io::IoSlice::new(&[]),
                std::io::IoSlice::new(&[]),
                std::io::IoSlice::new(&[]),
                std::io::IoSlice::new(&[]),
            ];
            for (i, slot) in slices.iter_mut().enumerate().take(cnt) {
                // SAFETY: same IoVecBuf contract as above — cnt valid iovecs at ptr.
                *slot = std::io::IoSlice::new(unsafe {
                    let iov = &*ptr.add(i);
                    std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len)
                });
            }
            let total = match self.session.writer().write_vectored(&slices[..cnt]) {
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
            return (Ok(total), buf_vec);
        }
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
