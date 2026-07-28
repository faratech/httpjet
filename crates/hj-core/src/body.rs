//! Protocol-agnostic body type. Handlers produce a [`Body`]; the transport
//! layer (the io_uring H1/H2/H3 paths) is responsible for writing it out,
//! choosing a zero-copy path for [`Body::File`] where the transport allows.

use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;

/// Boxed error used across body streams.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// An incoming (request) body, type-erased across protocols.
pub type IncomingBody = BoxBody<Bytes, BoxError>;

/// Build an empty [`IncomingBody`] (used for internal subrequests such as a PHP
/// `ErrorDocument` re-dispatch that carries no request body).
pub fn empty_incoming() -> IncomingBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

/// A streaming response body.
pub type StreamBody = BoxBody<Bytes, BoxError>;

/// The response body a handler returns.
pub enum Body {
    /// No body.
    Empty,
    /// A fully-buffered body already in memory (small files, generated content).
    Full(Bytes),
    /// A streamed body (proxy/LSAPI responses, chunked output).
    Stream(StreamBody),
    /// A file to be sent, resolved to the optimal send path by the transport.
    File(FileBody),
}

/// Describes a file response without reading it into userspace eagerly.
pub struct FileBody {
    pub path: PathBuf,
    /// An already-open descriptor for `path`. When present, transports must read
    /// from this descriptor instead of reopening the pathname. This pins the
    /// underlying inode across a concurrent cache eviction/version swap: Unix
    /// unlink remains synchronous while an in-flight response can still finish
    /// reading the exact version it selected.
    pub file: Option<std::fs::File>,
    /// Total file length in bytes.
    pub len: u64,
    /// Optional byte range `[start, end_inclusive]` for `Range` requests.
    pub range: Option<(u64, u64)>,
    /// If the file is already in the in-memory cache, its bytes (fast path).
    /// Holds the WHOLE file; `range` (if any) is applied by the transport via
    /// [`FileBody::cached_ranged`] — never pre-sliced here.
    pub cached: Option<Bytes>,
}

impl FileBody {
    /// The in-memory cached body sliced to `range`, bounds-CLAMPED to the cached length (so a
    /// stale/oversized range can never panic), or `None` when not cached. SINGLE-SOURCES the
    /// "`cached` holds the whole file; the transport applies the range" contract so every transport
    /// — the native hj-h2 send path AND the io_uring bridge — slices `cached` identically. If the
    /// two ever disagreed, one would serve the whole file and the other the slice under the same
    /// 206 / Content-Range (the H1↔H2 range divergence this consolidates).
    pub fn cached_ranged(&self) -> Option<Bytes> {
        self.cached.as_ref().map(|c| match self.range {
            Some((s, e)) => {
                let s = (s as usize).min(c.len());
                let e = (e as usize).saturating_add(1).min(c.len());
                c.slice(s..e.max(s))
            }
            None => c.clone(),
        })
    }
}

impl Body {
    pub fn empty() -> Self {
        Body::Empty
    }

    /// Number of bytes if known up front (used to set `Content-Length`).
    pub fn content_length(&self) -> Option<u64> {
        match self {
            Body::Empty => Some(0),
            Body::Full(b) => Some(b.len() as u64),
            Body::Stream(_) => None,
            Body::File(f) => Some(match f.range {
                Some((s, e)) => e.saturating_sub(s) + 1,
                None => f.len,
            }),
        }
    }
}

/// Wraps a streaming body so the total number of data bytes that flow through it
/// is reported to `on_done` exactly once — when the stream ends, errors, or is
/// dropped (e.g. the client disconnects mid-stream).
///
/// This is how the access log records the REAL bytes sent (`%B`/`%O`) for a
/// response whose length is not known up front. A streamed LSAPI/proxy body
/// carries no `Content-Length`, so reading the header at header-emit time logs `0`
/// even though bytes are still written; counting at the wire is the only faithful
/// source. Because the count is known only after the body drains, the callback —
/// not the caller — is what finally emits the log line (so a streamed response is
/// logged at completion, matching Apache/LiteSpeed).
pub struct CountingBody {
    inner: StreamBody,
    count: u64,
    on_done: Option<Box<dyn FnOnce(u64) + Send + Sync>>,
}

impl CountingBody {
    pub fn new(inner: StreamBody, on_done: impl FnOnce(u64) + Send + Sync + 'static) -> Self {
        CountingBody {
            inner,
            count: 0,
            on_done: Some(Box::new(on_done)),
        }
    }

    /// Wrap `inner` and re-box it as a [`Body::Stream`], ready to return from a
    /// handler/transform. `on_done` receives the total bytes when the stream is done.
    pub fn wrap(inner: StreamBody, on_done: impl FnOnce(u64) + Send + Sync + 'static) -> Body {
        Body::Stream(CountingBody::new(inner, on_done).boxed())
    }

    fn fire(&mut self) {
        if let Some(cb) = self.on_done.take() {
            cb(self.count);
        }
    }
}

impl HttpBody for CountingBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // CountingBody is Unpin (StreamBody is a BoxBody, which is Unpin; the other
        // fields are trivially Unpin), so this projection needs no unsafe.
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.count += data.len() as u64;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.fire();
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.fire();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CountingBody {
    fn drop(&mut self) {
        // EOS already fired and cleared `on_done`; this only fires on an early drop
        // (client disconnect / aborted stream), recording the partial byte count.
        self.fire();
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Self {
        Body::Full(b)
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Body::Full(Bytes::from(v))
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Self {
        Body::Full(Bytes::from_static(s.as_bytes()))
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Body::Full(Bytes::from(s.into_bytes()))
    }
}

#[cfg(test)]
mod filebody_tests {
    use super::*;

    fn fb(len: usize, range: Option<(u64, u64)>) -> FileBody {
        FileBody {
            path: PathBuf::from("/x"),
            file: None,
            len: len as u64,
            range,
            cached: Some(Bytes::from((0..len).map(|i| i as u8).collect::<Vec<_>>())),
        }
    }

    #[test]
    fn cached_ranged_applies_inclusive_range() {
        let served = fb(1000, Some((10, 19))).cached_ranged().unwrap();
        assert_eq!(served.len(), 10);
        assert_eq!(&served[..], &(10u8..20).collect::<Vec<_>>()[..]);
    }

    #[test]
    fn cached_ranged_no_range_is_whole() {
        assert_eq!(fb(50, None).cached_ranged().unwrap().len(), 50);
    }

    #[test]
    fn cached_ranged_clamps_oversized_range_without_panic() {
        // A range past the cached length (e.g. the file shrank between resolve and read) must clamp,
        // never panic. This is what makes the "transport applies range" contract crash-safe.
        let served = fb(100, Some((50, 999))).cached_ranged().unwrap();
        assert_eq!(served.len(), 50); // 50..=99
        let empty = fb(100, Some((500, 600))).cached_ranged().unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn cached_ranged_none_when_uncached() {
        let f = FileBody {
            path: PathBuf::from("/x"),
            file: None,
            len: 10,
            range: Some((0, 4)),
            cached: None,
        };
        assert!(f.cached_ranged().is_none());
    }
}

#[cfg(test)]
mod counting_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Wake, Waker};

    /// A synchronous multi-chunk test body (never returns `Pending`).
    struct VecBody(VecDeque<Bytes>);
    impl HttpBody for VecBody {
        type Data = Bytes;
        type Error = BoxError;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            match self.0.pop_front() {
                Some(b) => Poll::Ready(Some(Ok(Frame::data(b)))),
                None => Poll::Ready(None),
            }
        }
    }

    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn stream_of(chunks: &[&'static [u8]]) -> StreamBody {
        let q: VecDeque<Bytes> = chunks.iter().map(|c| Bytes::from_static(c)).collect();
        VecBody(q).boxed()
    }

    #[test]
    fn counts_total_bytes_and_fires_once_on_eos() {
        let counted = Arc::new(AtomicU64::new(u64::MAX));
        let sink = counted.clone();
        let mut body = CountingBody::new(stream_of(&[b"hello", b" world", b"!"]), move |n| {
            sink.store(n, Ordering::SeqCst)
        });
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        loop {
            match Pin::new(&mut body).poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(None) => break,
                other => panic!("unexpected poll: {}", matches!(other, Poll::Pending)),
            }
        }
        // "hello"(5) + " world"(6) + "!"(1)
        assert_eq!(counted.load(Ordering::SeqCst), 12);
        // Dropping after EOS must NOT fire the callback a second time.
        drop(body);
        assert_eq!(counted.load(Ordering::SeqCst), 12);
    }

    #[test]
    fn fires_partial_count_when_dropped_mid_stream() {
        let counted = Arc::new(AtomicU64::new(u64::MAX));
        let sink = counted.clone();
        let mut body = CountingBody::new(stream_of(&[b"hello", b" world"]), move |n| {
            sink.store(n, Ordering::SeqCst)
        });
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        // Pull only the first chunk ("hello" = 5), then drop the body — a client
        // disconnect mid-stream must still log the partial byte count.
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Ready(Some(Ok(_)))
        ));
        assert_eq!(
            counted.load(Ordering::SeqCst),
            u64::MAX,
            "must not fire before drop/EOS"
        );
        drop(body);
        assert_eq!(counted.load(Ordering::SeqCst), 5);
    }
}
