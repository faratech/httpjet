//! Item 14 regression: a slow / never-terminating chunked request body must not
//! pin a proxy task and its maxConns permit forever.
//!
//! A body-bearing forward intentionally skips the fixed response-head timeout
//! (it would measure the legitimately slow upload), but an inactivity timeout on
//! the upload itself must still bound a stalled/trickling body so the permit is
//! released — a follow-up request to the same upstream is then NOT 503'd even
//! though the upstream only ever answers once it has read the full body.
//!
//! These bind a loopback port + drive a real h1 client, so they are `#[ignore]`
//! (run with `cargo test -p hj-proxy --test slow_body_timeout -- --ignored`).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
use hyper::{Request as HyperReq, Response as HyperResp};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use hj_core::config::{ServerConfig, VHostConfig};
use hj_core::{BoxError, IncomingBody, Proto, ReqCtx};
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
        request_time: std::time::SystemTime::now(),
        request_id: Default::default(),
        tls: None,
        redirect_guard: None,
    }
}

/// Upstream that only answers once it has read the ENTIRE request body (so a stalled
/// upload never produces a response head — the proxy must bound it from the upload side).
async fn spawn_read_full_then_reply() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(|req: HyperReq<hyper::body::Incoming>| async move {
                    // Drain the whole body first; only then reply.
                    let _ = req.into_body().collect().await;
                    Ok::<_, Infallible>(HyperResp::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

/// A request body that yields one chunk and then stalls forever (never sends the
/// terminal chunk) — the trickling/never-terminating chunked-upload case.
struct StallingBody {
    first: Option<Bytes>,
}

impl HttpBody for StallingBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(b) = self.first.take() {
            return Poll::Ready(Some(Ok(Frame::data(b))));
        }
        Poll::Pending
    }
    fn size_hint(&self) -> SizeHint {
        // Unknown length, body present — mirrors a chunked upload.
        SizeHint::default()
    }
}

fn empty_body() -> IncomingBody {
    Empty::<Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binds a loopback port; run with --ignored"]
async fn stalled_upload_releases_permit_before_followup() {
    let addr = spawn_read_full_then_reply().await;
    // max_conns = 1: if the stalled upload kept its permit, the follow-up would 503.
    let proxy = Proxy::with_limits(1, Duration::from_secs(60), Duration::from_secs(5));
    let target = ProxyTarget::parse_url(&format!("http://{addr}/")).unwrap();

    // First request: a chunked body that delivers one chunk then stalls. The upstream
    // waits for the full body, so the proxy must drop it on the upload inactivity timeout.
    let stalling: IncomingBody = StallingBody {
        first: Some(Bytes::from_static(b"partial")),
    }
    .boxed();
    // POST (not the builder's default GET): hyper's h1 client only frames a body for
    // methods that carry one — for GET/HEAD/CONNECT with an unknown length it emits a
    // bodyless request (role.rs `Encoder::length(0)`), so the inactivity guard would never
    // be exercised. POST is the realistic upload-stall vector this test must cover.
    let req = http::Request::builder()
        .method(hyper::Method::POST)
        .uri("/")
        .header(hyper::header::HOST, "h")
        .header(hyper::header::TRANSFER_ENCODING, "chunked")
        .body(stalling)
        .unwrap();

    // The forward must resolve (with a gateway timeout) within the inactivity window
    // (30s) — well under a no-timeout hang. Allow margin for CI slowness.
    let first =
        tokio::time::timeout(Duration::from_secs(45), proxy.forward(&ctx(), req, &target)).await;
    assert!(
        first.is_ok(),
        "stalled body must not hang the proxy task forever"
    );
    assert!(
        first.unwrap().is_err(),
        "a stalled upload surfaces a gateway error, not a hang"
    );

    // The permit must now be free: a normal follow-up to the SAME upstream must NOT 503.
    let req2 = http::Request::builder()
        .uri("/")
        .header(hyper::header::HOST, "h")
        .body(empty_body())
        .unwrap();
    let second = proxy.forward(&ctx(), req2, &target).await;
    match second {
        Ok(resp) => assert_ne!(
            resp.status(),
            http::StatusCode::SERVICE_UNAVAILABLE,
            "the stalled upload must have released its maxConns permit"
        ),
        Err(e) => assert_ne!(
            e.status(),
            http::StatusCode::SERVICE_UNAVAILABLE,
            "follow-up must not be 503'd by a leaked permit"
        ),
    }
}
