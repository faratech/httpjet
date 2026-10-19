//! (#1034) The shutdown drain on the monoio path: a response idle on its backend (SSE,
//! long-poll) is reset after `shutdown_idle_stream_timeout` instead of holding the drain
//! to the transport's bound; a response still producing and a handler yet to answer keep
//! running; a connection still waiting for the client preface closes at once.
#![cfg(feature = "monoio")]

use std::io::{Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hj_core::{Body, Request, Response};
use hj_h2::frame::{self, FrameHeader};
use hj_h2::hpack::Encoder;
use hj_h2::server::Config;
use tokio_util::sync::CancellationToken;

const GRACE: Duration = Duration::from_millis(300);

/// One chunk, then nothing ever again (an SSE stream between events). Records its drop.
struct Endless {
    first: Option<Bytes>,
    dropped: Arc<AtomicBool>,
}

impl Drop for Endless {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

impl http_body::Body for Endless {
    type Data = Bytes;
    type Error = hj_core::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        match self.first.take() {
            Some(chunk) => Poll::Ready(Some(Ok(http_body::Frame::data(chunk)))),
            None => Poll::Pending,
        }
    }
}

/// A body fed from a channel, so the test controls when each chunk arrives.
struct Fed(tokio::sync::mpsc::Receiver<Bytes>);

impl http_body::Body for Fed {
    type Data = Bytes;
    type Error = hj_core::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.0
            .poll_recv(cx)
            .map(|chunk| chunk.map(|data| Ok(http_body::Frame::data(data))))
    }
}

fn stream_response(
    body: impl http_body::Body<Data = Bytes, Error = hj_core::BoxError> + Send + Sync + 'static,
) -> Response {
    http::Response::builder()
        .header(http::header::CONTENT_TYPE, "text/event-stream")
        .body(Body::Stream(http_body_util::BodyExt::boxed(body)))
        .unwrap()
}

#[derive(Default, Debug)]
struct Seen {
    body: Vec<u8>,
    ended: bool,
    reset: Option<(u32, Instant)>,
    goaway: Option<u32>,
    closed: Option<Instant>,
}

/// A blocking h2 client on a std socket: preface + SETTINGS + one GET on stream 1.
struct Client {
    stream: std::net::TcpStream,
    raw: Vec<u8>,
    at: usize,
}

impl Client {
    fn connect(address: std::net::SocketAddr) -> Self {
        let stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        Self {
            stream,
            raw: Vec::new(),
            at: 0,
        }
    }

    fn get(&mut self) {
        let mut wire = hj_h2::conn::PREFACE.to_vec();
        frame::write_settings(&mut wire, &[]);
        let mut enc = Encoder::new();
        let mut block = Vec::new();
        for (name, value) in [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            (":authority", "example.com"),
        ] {
            enc.encode_header(&mut block, name, value);
        }
        frame::write_frame(
            &mut wire,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS | frame::flags::END_STREAM,
            1,
            &block,
        );
        self.stream.write_all(&wire).unwrap();
    }

    /// Read until `done(seen)` or the connection closes; panics past `limit`.
    fn read_until(&mut self, seen: &mut Seen, limit: Duration, done: impl Fn(&Seen) -> bool) {
        let started = Instant::now();
        let mut buf = [0u8; 16384];
        while !done(seen) && seen.closed.is_none() {
            assert!(started.elapsed() < limit, "timed out: {seen:?}");
            match self.stream.read(&mut buf) {
                Ok(0) => seen.closed = Some(Instant::now()),
                Ok(n) => self.raw.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => seen.closed = Some(Instant::now()),
            }
            while let Some(h) = self.raw.get(self.at..self.at + FrameHeader::LEN) {
                let hdr = FrameHeader::parse(h).unwrap();
                let start = self.at + FrameHeader::LEN;
                let Some(p) = self.raw.get(start..start + hdr.length as usize) else {
                    break;
                };
                match hdr.kind {
                    frame::kind::DATA if hdr.stream_id == 1 => {
                        seen.body.extend_from_slice(p);
                        seen.ended |= hdr.flags & frame::flags::END_STREAM != 0;
                    }
                    frame::kind::RST_STREAM if hdr.stream_id == 1 => {
                        let code = u32::from_be_bytes(p[..4].try_into().unwrap());
                        seen.reset = Some((code, Instant::now()));
                    }
                    frame::kind::GOAWAY => {
                        seen.goaway = Some(u32::from_be_bytes(p[4..8].try_into().unwrap()));
                    }
                    _ => {}
                }
                self.at = start + hdr.length as usize;
            }
        }
    }
}

/// Serve one monoio h2 connection with `service` under `config` and a shutdown token.
fn serve_one<S, F>(
    service: S,
    config: Config,
    shutdown: CancellationToken,
) -> (
    std::net::SocketAddr,
    std::sync::mpsc::Receiver<(std::io::Result<()>, Instant)>,
)
where
    S: Fn(Request) -> F + Send + 'static,
    F: std::future::Future<Output = Response> + Send + 'static,
{
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = std_listener.local_addr().unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let result = hj_h2::server::serve_local_with_prefix(
                stream,
                Vec::new(),
                service,
                config,
                Some(shutdown),
                None,
            )
            .await;
            let _ = done.send((result, Instant::now()));
        })
    });
    (address, finished)
}

/// The server's result and finish time; fails rather than hangs on a stuck drain.
fn finished(
    server: &std::sync::mpsc::Receiver<(std::io::Result<()>, Instant)>,
) -> (std::io::Result<()>, Instant) {
    server
        .recv_timeout(Duration::from_secs(10))
        .expect("the server connection must finish")
}

fn config() -> Config {
    Config {
        shutdown_idle_stream_timeout: Some(GRACE),
        ..Config::default()
    }
}

#[test]
fn shutdown_resets_a_backend_idle_stream_after_the_grace() {
    let dropped = Arc::new(AtomicBool::new(false));
    let body_dropped = dropped.clone();
    let shutdown = CancellationToken::new();
    let (address, server) = serve_one(
        move |_req: Request| {
            let body = Endless {
                first: Some(Bytes::from_static(b"data: 1\n\n")),
                dropped: body_dropped.clone(),
            };
            async move { stream_response(body) }
        },
        config(),
        shutdown.clone(),
    );
    let mut client = Client::connect(address);
    client.get();
    let mut seen = Seen::default();
    client.read_until(&mut seen, Duration::from_secs(5), |s| !s.body.is_empty());
    assert_eq!(seen.body, b"data: 1\n\n");

    let signalled = Instant::now();
    shutdown.cancel();
    client.read_until(&mut seen, GRACE + Duration::from_secs(3), |s| {
        s.reset.is_some() && s.closed.is_some()
    });
    let (code, reset_at) = seen.reset.expect("idle stream must be reset");
    assert_eq!(code, frame::error_code::CANCEL, "{seen:?}");
    assert!(
        !seen.ended,
        "a truncated stream must not end cleanly: {seen:?}"
    );
    assert_eq!(seen.goaway, Some(frame::error_code::NO_ERROR), "{seen:?}");
    let waited = reset_at - signalled;
    assert!(
        waited >= GRACE - Duration::from_millis(20),
        "reset before the grace: {waited:?}"
    );
    assert!(
        waited < GRACE + Duration::from_secs(1),
        "reset long after the grace: {waited:?}"
    );
    drop(client);
    let (result, finished_at) = finished(&server);
    result.unwrap();
    assert!(
        finished_at - signalled < GRACE + Duration::from_secs(2),
        "the connection must not outlive the idle grace: {:?}",
        finished_at - signalled
    );
    assert!(
        dropped.load(Ordering::Acquire),
        "backend body must be dropped"
    );
}

#[test]
fn shutdown_keeps_a_producing_stream_until_it_ends() {
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    let rx = std::sync::Mutex::new(Some(rx));
    let shutdown = CancellationToken::new();
    let (address, server) = serve_one(
        move |_req: Request| {
            let body = Fed(rx.lock().unwrap().take().unwrap());
            async move { stream_response(body) }
        },
        config(),
        shutdown.clone(),
    );
    let mut client = Client::connect(address);
    client.get();
    tx.blocking_send(Bytes::from_static(b"0")).unwrap();
    let mut seen = Seen::default();
    client.read_until(&mut seen, Duration::from_secs(5), |s| !s.body.is_empty());
    shutdown.cancel();
    // Ten more chunks over ~4x the grace: each gap stays under it, so the stream lives on.
    let producer = std::thread::spawn(move || {
        for digit in b"123456789X" {
            std::thread::sleep(GRACE / 3);
            tx.blocking_send(Bytes::copy_from_slice(&[*digit])).unwrap();
        }
    });
    client.read_until(&mut seen, Duration::from_secs(10), |s| s.ended);
    producer.join().unwrap();
    assert_eq!(seen.body, b"0123456789X", "{seen:?}");
    assert!(seen.ended && seen.reset.is_none(), "{seen:?}");
    assert_eq!(seen.goaway, Some(frame::error_code::NO_ERROR), "{seen:?}");
    client.read_until(&mut seen, Duration::from_secs(3), |s| s.closed.is_some());
    drop(client);
    finished(&server).0.unwrap();
}

#[test]
fn shutdown_still_delivers_a_handler_slower_than_the_grace() {
    let shutdown = CancellationToken::new();
    let (address, server) = serve_one(
        move |_req: Request| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                std::thread::sleep(GRACE * 3);
                let _ = tx.send(());
            });
            async move {
                let _ = rx.await;
                http::Response::new(Body::Full(Bytes::from_static(b"finished")))
            }
        },
        config(),
        shutdown.clone(),
    );
    let mut client = Client::connect(address);
    client.get();
    std::thread::sleep(Duration::from_millis(50));
    shutdown.cancel();
    let mut seen = Seen::default();
    client.read_until(&mut seen, Duration::from_secs(5), |s| s.ended);
    assert_eq!(seen.body, b"finished", "{seen:?}");
    assert!(seen.reset.is_none(), "{seen:?}");
    drop(client);
    finished(&server).0.unwrap();
}

#[test]
fn shutdown_closes_a_connection_still_waiting_for_the_preface() {
    let shutdown = CancellationToken::new();
    let (address, server) = serve_one(
        |_req: Request| async { http::Response::new(Body::Empty) },
        Config {
            preface_timeout: Some(Duration::from_secs(60)),
            ..config()
        },
        shutdown.clone(),
    );
    let mut silent = std::net::TcpStream::connect(address).unwrap();
    // Half a preface: the peer is mid-preface when the signal arrives.
    silent.write_all(&hj_h2::conn::PREFACE[..10]).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let signalled = Instant::now();
    shutdown.cancel();
    let (result, finished_at) = finished(&server);
    result.unwrap();
    assert!(
        finished_at - signalled < Duration::from_millis(500),
        "a pre-preface connection must close promptly: {:?}",
        finished_at - signalled
    );
    silent
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut rest = Vec::new();
    let _ = silent.read_to_end(&mut rest);
    assert!(rest.is_empty(), "nothing is written before the preface");
}
