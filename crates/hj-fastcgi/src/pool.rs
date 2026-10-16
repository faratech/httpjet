use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Tcp(SocketAddr),
    TcpHost(String),
    Unix(PathBuf),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PoolError {
    #[error("FastCGI connection acquisition timed out")]
    Timeout,
    #[error("FastCGI connection failed")]
    Connect,
}

enum Stream {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

impl Stream {
    /// #629: an idle pooled socket whose peer already closed reads EOF (or
    /// errors / has unexpected bytes); a live one reports WouldBlock.
    fn is_healthy(&self) -> bool {
        let mut probe = [0u8; 1];
        let result = match self {
            Self::Tcp(s) => s.try_read(&mut probe),
            Self::Unix(s) => s.try_read(&mut probe),
        };
        matches!(result, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    }
}

/// #627: releases the reserved `open` slot if the connect future is dropped
/// (acquire timeout / caller cancellation) before a PooledConnection exists.
struct SlotGuard {
    inner: Arc<Inner>,
    armed: bool,
}
impl Drop for SlotGuard {
    fn drop(&mut self) {
        if self.armed {
            self.inner.release_open();
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

struct Idle {
    stream: Stream,
    since: Instant,
}

struct State {
    open: usize,
    idle: VecDeque<Idle>,
}

struct Inner {
    endpoint: Endpoint,
    max_open: usize,
    acquire_timeout: Duration,
    idle_timeout: Duration,
    state: Mutex<State>,
    changed: tokio::sync::Notify,
}

#[derive(Clone)]
pub struct FastCgiPool(Arc<Inner>);

impl FastCgiPool {
    pub fn new(
        endpoint: Endpoint,
        max_open: usize,
        acquire_timeout: Duration,
        idle_timeout: Duration,
    ) -> Result<Self, PoolError> {
        if max_open == 0 {
            return Err(PoolError::Connect);
        }
        Ok(Self(Arc::new(Inner {
            endpoint,
            max_open,
            acquire_timeout,
            idle_timeout,
            state: Mutex::new(State {
                open: 0,
                idle: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
        })))
    }

    pub async fn acquire(&self) -> Result<PooledConnection, PoolError> {
        tokio::time::timeout(self.0.acquire_timeout, self.acquire_inner())
            .await
            .map_err(|_| PoolError::Timeout)?
    }

    async fn acquire_inner(&self) -> Result<PooledConnection, PoolError> {
        loop {
            let notified = self.0.changed.notified();
            let reserve = {
                let mut state = self.0.state.lock().expect("FastCGI pool lock poisoned");
                let now = Instant::now();
                while state
                    .idle
                    .front()
                    .is_some_and(|idle| now.duration_since(idle.since) >= self.0.idle_timeout)
                {
                    state.idle.pop_front();
                    state.open -= 1;
                }
                while let Some(idle) = state.idle.pop_back() {
                    if idle.stream.is_healthy() {
                        return Ok(PooledConnection {
                            inner: self.0.clone(),
                            stream: Some(idle.stream),
                            reusable: false,
                        });
                    }
                    // #629: peer closed while idle — discard and keep looking
                    // (falls through to a fresh dial when no idle survives).
                    state.open -= 1;
                }
                if state.open < self.0.max_open {
                    state.open += 1;
                    true
                } else {
                    false
                }
            };
            if reserve {
                let mut guard = SlotGuard {
                    inner: self.0.clone(),
                    armed: true,
                };
                let stream = match &self.0.endpoint {
                    Endpoint::Tcp(address) => tokio::net::TcpStream::connect(address)
                        .await
                        .map(Stream::Tcp),
                    Endpoint::TcpHost(address) => tokio::net::TcpStream::connect(address)
                        .await
                        .map(Stream::Tcp),
                    Endpoint::Unix(path) => tokio::net::UnixStream::connect(path)
                        .await
                        .map(Stream::Unix),
                };
                return match stream {
                    Ok(stream) => {
                        guard.armed = false;
                        Ok(PooledConnection {
                            inner: self.0.clone(),
                            stream: Some(stream),
                            reusable: false,
                        })
                    }
                    Err(_) => Err(PoolError::Connect),
                };
            }
            notified.await;
        }
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        let state = self.0.state.lock().unwrap();
        (state.open, state.idle.len())
    }
}

impl Inner {
    fn release_open(&self) {
        let mut state = self.state.lock().expect("FastCGI pool lock poisoned");
        state.open -= 1;
        drop(state);
        self.changed.notify_one();
    }
}

pub struct PooledConnection {
    inner: Arc<Inner>,
    stream: Option<Stream>,
    reusable: bool,
}

impl PooledConnection {
    /// Mark this connection reusable only after a matching clean END_REQUEST.
    pub(crate) fn mark_reusable(&mut self) {
        self.reusable = true;
    }
}

impl AsyncRead for PooledConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.stream.as_mut().expect("connection stream missing")).poll_read(cx, buf)
    }
}

impl AsyncWrite for PooledConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(self.stream.as_mut().expect("connection stream missing")).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(self.stream.as_mut().expect("connection stream missing")).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(self.stream.as_mut().expect("connection stream missing")).poll_shutdown(cx)
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        let stream = self.stream.take().expect("connection stream missing");
        if self.reusable {
            let mut state = self.inner.state.lock().expect("FastCGI pool lock poisoned");
            state.idle.push_back(Idle {
                stream,
                since: Instant::now(),
            });
            drop(state);
            self.inner.changed.notify_one();
        } else {
            drop(stream);
            self.inner.release_open();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn total_open_cap_includes_idle_and_clean_connections_reuse() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = accepted.clone();
        let server = tokio::spawn(async move {
            // Hold accepted streams open: dropping each at loop end would make
            // the pooled socket dead on reuse (#629 probe would redial).
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                held.push(stream);
            }
        });
        let pool = FastCgiPool::new(
            Endpoint::Tcp(address),
            1,
            Duration::from_millis(30),
            Duration::from_secs(30),
        )
        .unwrap();
        let first = pool.acquire().await.unwrap();
        assert!(matches!(pool.acquire().await, Err(PoolError::Timeout)));
        let mut first = first;
        first.mark_reusable();
        drop(first);
        assert_eq!(pool.counts(), (1, 1));
        let second = pool.acquire().await.unwrap();
        assert_eq!(pool.counts(), (1, 0));
        drop(second);
        assert_eq!(pool.counts(), (0, 0));
        tokio::task::yield_now().await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn slot_guard_releases_reservation_on_drop() {
        // #627: a cancelled mid-connect acquire drops the guard, freeing open.
        let pool = FastCgiPool::new(
            Endpoint::Tcp("127.0.0.1:1".parse().unwrap()),
            1,
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .unwrap();
        pool.0.state.lock().unwrap().open = 1;
        let guard = SlotGuard {
            inner: pool.0.clone(),
            armed: true,
        };
        drop(guard);
        assert_eq!(pool.counts(), (0, 0));
    }

    #[tokio::test]
    async fn dead_idle_connection_is_discarded_for_fresh_dial() {
        // #629: server closes the first conn while it sits idle; the next
        // acquire must not hand out the dead socket.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            drop(first);
            let (_second, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let pool = FastCgiPool::new(
            Endpoint::Tcp(address),
            1,
            Duration::from_secs(2),
            Duration::from_secs(30),
        )
        .unwrap();
        let mut first = pool.acquire().await.unwrap();
        first.mark_reusable();
        drop(first);
        // Let the server-side close reach the pooled socket.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = pool.acquire().await.unwrap();
        assert_eq!(pool.counts(), (1, 0));
        drop(second);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn poisoned_connection_releases_capacity_for_a_fresh_dial() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _first = listener.accept().await.unwrap();
            let _second = listener.accept().await.unwrap();
        });
        let pool = FastCgiPool::new(
            Endpoint::Tcp(address),
            1,
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .unwrap();
        drop(pool.acquire().await.unwrap());
        drop(pool.acquire().await.unwrap());
        server.await.unwrap();
        assert_eq!(pool.counts(), (0, 0));
    }
}
