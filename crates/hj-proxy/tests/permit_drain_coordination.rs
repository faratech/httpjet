//! Item 28 regression: the maxConns permit and the connection-drain task must be
//! coordinated so a mid-stream client disconnect can't transiently over-count
//! upstream connections up to 2x max_conns.
//!
//! With the permit MOVED INTO the drain task, the slot is freed only after the
//! drain completes (or its keep_alive_window cap fires), so the semaphore counts
//! running + draining connections. We assert the concurrent live-connection count
//! to the upstream never exceeds max_conns while a drain task is outstanding.
//!
//! Binds a loopback port, so `#[ignore]`
//! (`cargo test -p hj-proxy --test permit_drain_coordination -- --ignored`).

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame};
use http_body_util::{BodyExt, Empty};
use hyper::service::service_fn;
use hyper::{Request as HyperReq, Response as HyperResp};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use hj_core::config::{ServerConfig, VHostConfig};
use hj_core::{Body, BoxError, IncomingBody, Proto, ReqCtx};
use hj_proxy::{Proxy, ProxyTarget};

fn ctx() -> ReqCtx {
    let server = ServerConfig {
        server_root: Default::default(),
        server_name: String::new(),
        user: String::new(),
        group: String::new(),
        index_files: vec![],
        tuning: Default::default(),
        quic_enable: false,
        use_ip_in_proxy_header: 0,
        expires: Default::default(),
        cache: Default::default(),
        security: Default::default(),
        suexec: Default::default(),
        ext_processors: vec![],
        php_config: None,
        listeners: vec![],
        vhosts: Default::default(),
        vhost_order: vec![],
        mime: Default::default(),
    };
    ReqCtx {
        server: Arc::new(server),
        vhost_name: "t".into(),
        vhost: Arc::new(VHostConfig::default()),
        peer_ip: "127.0.0.1".parse().unwrap(),
        client_ip: "203.0.113.42".parse().unwrap(),
        is_tls: false,
        protocol: Proto::Http1,
        trusted_proxy: false,
        env: vec![],
        local_addr: "127.0.0.1:8080".parse().unwrap(),
        peer_port: 0,
        peer_unix: false,
        request_time: std::time::SystemTime::now(),
        request_id: Default::default(),
        tls: None,
        redirect_guard: None,
    }
}

fn empty_body() -> IncomingBody {
    Empty::<Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

/// A slow, long response body: emits up to `remaining` chunks, sleeping `gap` between each.
struct SlowBody {
    remaining: usize,
    gap: Duration,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl HttpBody for SlowBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        if self.sleep.is_none() {
            let gap = self.gap;
            self.sleep = Some(Box::pin(tokio::time::sleep(gap)));
        }
        let ready = self.sleep.as_mut().unwrap().as_mut().poll(cx).is_ready();
        if ready {
            self.sleep = None;
            self.remaining -= 1;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"chunk")))));
        }
        Poll::Pending
    }
}

/// Upstream that streams a slow, long response body and tracks the high-water mark of
/// concurrently-open TCP connections (incremented on accept, decremented on close).
async fn spawn_slow_stream(live: Arc<AtomicUsize>, high_water: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let n = live.fetch_add(1, Ordering::SeqCst) + 1;
            high_water.fetch_max(n, Ordering::SeqCst);
            let live = live.clone();
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(|_req: HyperReq<hyper::body::Incoming>| async move {
                    let body = SlowBody {
                        remaining: 600,
                        gap: Duration::from_millis(100),
                        sleep: None,
                    };
                    Ok::<_, Infallible>(HyperResp::new(body))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binds a loopback port; run with --ignored"]
async fn disconnect_mid_stream_never_over_counts_connections() {
    let live = Arc::new(AtomicUsize::new(0));
    let high_water = Arc::new(AtomicUsize::new(0));
    let addr = spawn_slow_stream(live.clone(), high_water.clone()).await;

    const MAX: u32 = 2;
    let proxy = Proxy::with_limits(MAX, Duration::from_secs(60), Duration::from_secs(5));
    let target = ProxyTarget::parse_url(&format!("http://{addr}/")).unwrap();

    // Repeatedly: open a forward, read one chunk, then drop the response (simulating a
    // mid-stream client disconnect). With the permit owned by the drain task, a fresh
    // forward must wait for a draining slot rather than dialing a 2nd connection.
    for _ in 0..12 {
        let req = http::Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "h")
            .body(empty_body())
            .unwrap();
        if let Ok(resp) = proxy.forward(&ctx(), req, &target, None).await {
            if let Body::Stream(mut s) = resp.into_body() {
                // Pull a single frame, then drop the stream (mid-stream disconnect).
                let _ = s.frame().await;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // Give any outstanding drain tasks a moment to settle.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let peak = high_water.load(Ordering::SeqCst);
    assert!(
        peak <= MAX as usize,
        "upstream saw {peak} concurrent connections, exceeding max_conns={MAX}"
    );
}
