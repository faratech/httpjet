//! Connection-local H1 scratch, transferred into every submitted write.

use std::io;

use bytes::Bytes;

// Retain ordinary response heads without pinning a large backend header block
// for the remaining keep-alive lifetime. The iovec allocation is exactly two.
const RETAIN_HEAD_CAPACITY: usize = 4096;

#[derive(Default)]
pub(super) struct ResponseBuffers {
    head: Vec<u8>,
    iovecs: Option<Box<[libc::iovec; 2]>>,
}

impl ResponseBuffers {
    pub(super) fn take_head(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.head)
    }

    pub(super) fn recycle_head(&mut self, mut head: Vec<u8>) {
        if head.capacity() <= RETAIN_HEAD_CAPACITY {
            head.clear();
            self.head = head;
        }
    }

    pub(super) fn full(&mut self, head: Vec<u8>, body: Bytes) -> io::Result<FullResponse> {
        let remaining = head.len().checked_add(body.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "H1 vectored payload too large")
        })?;
        let mut iovecs = self.iovecs.take().unwrap_or_else(|| {
            Box::new(
                [libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                }; 2],
            )
        });
        *iovecs = [
            libc::iovec {
                iov_base: head.as_ptr().cast_mut().cast(),
                iov_len: head.len(),
            },
            libc::iovec {
                iov_base: body.as_ptr().cast_mut().cast(),
                iov_len: body.len(),
            },
        ];
        Ok(FullResponse {
            head,
            body,
            iovecs,
            first: 0,
            remaining,
        })
    }

    /// Only a successfully completed write returns this value to the connection.
    pub(super) fn recycle_full(&mut self, mut returned: FullResponse) {
        debug_assert_eq!(returned.remaining, 0);
        returned.iovecs.fill(libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        });
        self.iovecs = Some(returned.iovecs);
        self.recycle_head(returned.head);
        // The body is intentionally released instead of entering scratch storage.
        drop(returned.body);
    }
}

/// Owns the head, body, and heap-stable iovec array until io_uring gives them back.
/// Cancellation never returns these allocations to `ResponseBuffers`.
pub(super) struct FullResponse {
    head: Vec<u8>,
    body: Bytes,
    iovecs: Box<[libc::iovec; 2]>,
    first: usize,
    remaining: usize,
}

impl FullResponse {
    pub(super) fn remaining(&self) -> usize {
        self.remaining
    }

    pub(super) fn consume(&mut self, mut written: usize) -> io::Result<()> {
        if written > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "H1 vectored write exceeded queued bytes",
            ));
        }
        self.remaining -= written;
        while written > 0 {
            let iovec = self
                .iovecs
                .get_mut(self.first)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing H1 iovec"))?;
            let consumed = written.min(iovec.iov_len);
            // SAFETY: the descriptor starts within its owned head/body allocation.
            // Advancing by at most iov_len stays within or one past that allocation.
            iovec.iov_base = unsafe { (iovec.iov_base as *mut u8).add(consumed) }.cast();
            iovec.iov_len -= consumed;
            written -= consumed;
            if iovec.iov_len == 0 {
                self.first += 1;
            }
        }
        Ok(())
    }
}

// SAFETY: both descriptors are in a Box, so moving FullResponse cannot move the
// kernel-visible metadata. The head Vec and body Bytes own stable allocations.
// No descriptor, head, or body is mutated while a submitted write owns this
// value. consume/recycle_full run only after the write returns it. Dropping a
// submitted future lets Monoio retain this entire value until CQ completion.
unsafe impl monoio::buf::IoVecBuf for FullResponse {
    fn read_iovec_ptr(&self) -> *const libc::iovec {
        // SAFETY: first advances at most to two, where this is one-past the array.
        unsafe { self.iovecs.as_ptr().add(self.first) }
    }

    fn read_iovec_len(&self) -> usize {
        self.iovecs.len() - self.first
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monoio::buf::{IoBuf, IoVecBuf};
    use monoio::io::AsyncWriteRent;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    fn bytes(buffer: &impl IoVecBuf) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..buffer.read_iovec_len() {
            // SAFETY: the live IoVecBuf owns this metadata and initialized data.
            unsafe {
                let part = &*buffer.read_iovec_ptr().add(i);
                out.extend_from_slice(std::slice::from_raw_parts(
                    part.iov_base.cast::<u8>(),
                    part.iov_len,
                ));
            }
        }
        out
    }

    #[test]
    fn partial_completion_keeps_exact_suffix_and_stable_metadata() {
        let mut cache = ResponseBuffers::default();
        let mut owned = cache
            .full(b"head".to_vec(), Bytes::from_static(b"body"))
            .unwrap();
        let metadata = owned.read_iovec_ptr();
        owned.consume(3).unwrap();
        assert_eq!(bytes(&owned), b"dbody");
        let mut moved = Box::new(owned);
        assert_eq!(moved.read_iovec_ptr(), metadata);
        moved.consume(3).unwrap();
        assert_eq!(bytes(&*moved), b"dy");
        moved.consume(2).unwrap();
        assert_eq!(moved.remaining(), 0);
        assert!(moved.consume(1).is_err());
        assert_eq!(moved.remaining(), 0);
    }

    #[test]
    fn oversized_heads_are_not_retained() {
        let mut cache = ResponseBuffers::default();
        let mut head = Vec::with_capacity(RETAIN_HEAD_CAPACITY + 1);
        head.extend_from_slice(b"head");
        let mut owned = cache.full(head, Bytes::from_static(b"body")).unwrap();
        owned.consume(owned.remaining()).unwrap();
        cache.recycle_full(owned);
        assert_eq!(cache.head.capacity(), 0);
        assert!(cache.iovecs.is_some());
    }

    #[derive(Default)]
    struct PartialWriter {
        wire: Vec<u8>,
        interrupt: bool,
        fail: bool,
    }

    impl AsyncWriteRent for PartialWriter {
        async fn write<T: IoBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
            if self.fail {
                return (Err(io::ErrorKind::BrokenPipe.into()), buf);
            }
            let n = buf.bytes_init().min(5);
            // SAFETY: the owned IoBuf guarantees n initialized bytes.
            self.wire
                .extend_from_slice(unsafe { std::slice::from_raw_parts(buf.read_ptr(), n) });
            (Ok(n), buf)
        }

        async fn writev<T: IoVecBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
            if self.fail {
                return (Err(io::ErrorKind::BrokenPipe.into()), buf);
            }
            if std::mem::take(&mut self.interrupt) {
                return (Err(io::ErrorKind::Interrupted.into()), buf);
            }
            let all = bytes(&buf);
            let n = all.len().min(5);
            self.wire.extend_from_slice(&all[..n]);
            (Ok(n), buf)
        }

        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn response(
        body: &'static [u8],
        status: http::StatusCode,
        value: &'static str,
        events: Arc<Mutex<Vec<hj_core::ResponseEnd>>>,
    ) -> super::super::bridge::BridgeResp {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static(value));
        super::super::bridge::BridgeResp {
            completion: Some(hj_core::ResponseCompletion::new(move |end| {
                events.lock().unwrap().push(end)
            })),
            status,
            headers,
            body: super::super::bridge::BridgeBody::Full(Bytes::from_static(body)),
            bw_rate: None,
        }
    }

    #[test]
    fn partial_and_interrupted_writes_reuse_head_and_metadata() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = super::super::build_core_runtime().unwrap();
        runtime.block_on(async {
            let mut cache = ResponseBuffers::default();
            let mut writer = PartialWriter { interrupt: true, ..Default::default() };
            let mut throttle = None;
            let shutdown = tokio_util::sync::CancellationToken::new();
            let first = super::super::write_h1_response_reusing(
                &mut writer, response(b"body", http::StatusCode::OK, "one", events.clone()),
                false, true, false, &mut throttle, None, None, &shutdown, &mut cache,
            ).await;
            assert!(!first.failed && !first.close);
            assert_eq!(writer.wire, b"HTTP/1.1 200 OK\r\nx-test: one\r\ncontent-length: 4\r\nconnection: keep-alive\r\n\r\nbody");
            let head = cache.head.as_ptr();
            let metadata = cache.iovecs.as_ref().unwrap().as_ptr();
            writer.wire.clear();
            let second = super::super::write_h1_response_reusing(
                &mut writer, response(b"updated", http::StatusCode::NOT_FOUND, "two", events.clone()),
                false, true, false, &mut throttle, None, None, &shutdown, &mut cache,
            ).await;
            assert!(!second.failed && !second.close);
            assert_eq!(writer.wire, b"HTTP/1.1 404 Not Found\r\nx-test: two\r\ncontent-length: 7\r\nconnection: keep-alive\r\n\r\nupdated");
            assert_eq!(cache.head.as_ptr(), head);
            assert_eq!(cache.iovecs.as_ref().unwrap().as_ptr(), metadata);
        });
        assert_eq!(*events.lock().unwrap(), [hj_core::ResponseEnd::Complete; 2]);
    }

    #[test]
    fn write_error_does_not_recycle_buffers_or_complete_successfully() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = super::super::build_core_runtime().unwrap();
        runtime.block_on(async {
            let mut cache = ResponseBuffers::default();
            let mut writer = PartialWriter {
                fail: true,
                ..Default::default()
            };
            let outcome = super::super::write_h1_response_reusing(
                &mut writer,
                response(b"body", http::StatusCode::OK, "one", events.clone()),
                false,
                true,
                false,
                &mut None,
                None,
                None,
                &tokio_util::sync::CancellationToken::new(),
                &mut cache,
            )
            .await;
            assert!(outcome.failed && outcome.close);
            assert_eq!(cache.head.capacity(), 0);
            assert!(cache.iovecs.is_none());
        });
        assert_eq!(*events.lock().unwrap(), [hj_core::ResponseEnd::Error]);
    }

    struct PendingWriter;
    impl AsyncWriteRent for PendingWriter {
        async fn write<T: IoBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
            let result = std::future::pending::<io::Result<usize>>().await;
            (result, buf)
        }
        async fn writev<T: IoVecBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
            let result = std::future::pending::<io::Result<usize>>().await;
            (result, buf)
        }
        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn cancelling_response_notifies_once_and_recycles_nothing() {
        use std::future::Future;
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut cache = ResponseBuffers::default();
        let mut writer = PendingWriter;
        let mut throttle = None;
        let shutdown = tokio_util::sync::CancellationToken::new();
        let mut future = Box::pin(super::super::write_h1_response_reusing(
            &mut writer,
            response(b"body", http::StatusCode::OK, "one", events.clone()),
            false,
            true,
            false,
            &mut throttle,
            None,
            None,
            &shutdown,
            &mut cache,
        ));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        drop(future);
        assert_eq!(cache.head.capacity(), 0);
        assert!(cache.iovecs.is_none());
        assert_eq!(*events.lock().unwrap(), [hj_core::ResponseEnd::Cancelled]);
    }

    #[test]
    fn timed_out_write_does_not_recycle_buffers() {
        // write_watch is deliberately one-runtime-per-thread; use an owned
        // thread so its sweeper cannot carry over to another test's runtime.
        std::thread::spawn(|| {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut runtime = super::super::build_core_runtime().unwrap();
            runtime.block_on(async {
                let mut cache = ResponseBuffers::default();
                let outcome = super::super::write_h1_response_reusing(
                    &mut PendingWriter,
                    response(b"body", http::StatusCode::OK, "one", events.clone()),
                    false,
                    true,
                    false,
                    &mut None,
                    None,
                    Some(std::time::Duration::from_millis(1)),
                    &tokio_util::sync::CancellationToken::new(),
                    &mut cache,
                )
                .await;
                assert!(outcome.failed && outcome.close);
                assert_eq!(cache.head.capacity(), 0);
                assert!(cache.iovecs.is_none());
            });
            assert_eq!(*events.lock().unwrap(), [hj_core::ResponseEnd::Error]);
        })
        .join()
        .unwrap();
    }

    struct Payload {
        data: Vec<u8>,
        dropped: Arc<AtomicBool>,
    }
    impl AsRef<[u8]> for Payload {
        fn as_ref(&self) -> &[u8] {
            &self.data
        }
    }
    impl Drop for Payload {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[test]
    fn cancelled_submitted_write_keeps_all_owned_storage_until_reaped() {
        let dropped = Arc::new(AtomicBool::new(false));
        let observed = dropped.clone();
        let mut runtime = super::super::build_core_runtime().unwrap();
        runtime.block_on(async move {
            let (mut writer, _reader) = monoio::net::UnixStream::pair().unwrap();
            let fill = [0u8; 16 * 1024];
            loop {
                // SAFETY: this live socket and initialized buffer belong to the test.
                let n = unsafe {
                    libc::send(
                        writer.as_raw_fd(),
                        fill.as_ptr().cast(),
                        fill.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if n < 0 {
                    assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                    break;
                }
            }
            let mut cache = ResponseBuffers::default();
            let body = Bytes::from_owner(Payload {
                data: vec![7; 4096],
                dropped: dropped.clone(),
            });
            let owned = cache.full(b"head".to_vec(), body).unwrap();
            let write = writer.writev(owned);
            drop(write);
            assert!(!dropped.load(Ordering::Acquire));
            assert!(
                cache.iovecs.is_none(),
                "cancelled I/O must not return metadata to the cache"
            );
            assert_eq!(cache.head.capacity(), 0);
        });
        drop(runtime);
        assert!(observed.load(Ordering::Acquire));
    }
}
