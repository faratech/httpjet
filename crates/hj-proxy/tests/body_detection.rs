//! Item 33 regression: body-bearing detection must come from the ACTUAL body, not
//! just request headers.
//!
//! hj-h2/h3 reject Transfer-Encoding and a legal h2/h3 POST conveys its length in
//! DATA frames with NO Content-Length header. A header-only test mis-flags such a
//! request as bodyless and then applies the response-head timeout where it must be
//! skipped (the head doesn't arrive until the upstream has read the whole upload),
//! which would become a spurious-504 DoS once h2/h3 dispatch is made streaming.
//!
//! The pure detection cases (no-CL Full body -> body-bearing; empty GET -> not;
//! `Transfer-Encoding: identity` with no body -> not; chunked/CL>0 -> yes) are unit
//! tested inline in `lib.rs` (`body_present_*`). This file pins the end-to-end
//! consequence: a request with a non-empty body but NO Content-Length forwards its
//! bytes upstream (i.e. it is handled on the body-bearing path). It binds a loopback
//! port, so `#[ignore]`:
//! `cargo test -p hj-proxy --test body_detection -- --ignored`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
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
        request_time: std::time::SystemTime::now(),
        request_id: Default::default(),
        upstream_id: None,
        tls: None,
    }
}

/// Upstream that echoes the received request-body length back in its response body.
async fn spawn_body_echo() -> SocketAddr {
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
                    let collected = req.into_body().collect().await.map(|b| b.to_bytes());
                    let n = collected.map(|b| b.len()).unwrap_or(0);
                    Ok::<_, Infallible>(HyperResp::new(Full::new(Bytes::from(format!("len={n}")))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

async fn collect(resp: hj_core::Response) -> String {
    match resp.into_body() {
        Body::Stream(s) => {
            String::from_utf8(s.collect().await.unwrap().to_bytes().to_vec()).unwrap()
        }
        Body::Full(b) => String::from_utf8(b.to_vec()).unwrap(),
        _ => String::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binds a loopback port; run with --ignored"]
async fn non_empty_body_without_content_length_is_forwarded() {
    let addr = spawn_body_echo().await;
    let proxy = Proxy::new();
    let target = ProxyTarget::parse_url(&format!("http://{addr}/")).unwrap();

    // A non-empty body, NO Content-Length header (the h2/h3 DATA-frame shape).
    let body: IncomingBody = Full::new(Bytes::from_static(b"hello-world"))
        .map_err(|e| Box::new(e) as BoxError)
        .boxed();
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header(hyper::header::HOST, "h")
        .body(body)
        .unwrap();

    // The whole forward must finish well under the 60s response-head timeout — if the
    // request were mis-detected as bodyless, the fast upstream still answers, so the
    // discriminating fact here is that the body BYTES reached the upstream.
    let resp = tokio::time::timeout(Duration::from_secs(10), proxy.forward(&ctx(), req, &target))
        .await
        .expect("forward must not hang")
        .expect("forward ok");
    let text = collect(resp).await;
    assert_eq!(
        text, "len=11",
        "the no-Content-Length body must be forwarded upstream: {text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binds a loopback port; run with --ignored"]
async fn empty_get_has_no_body() {
    let addr = spawn_body_echo().await;
    let proxy = Proxy::new();
    let target = ProxyTarget::parse_url(&format!("http://{addr}/")).unwrap();

    let body: IncomingBody = Empty::<Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed();
    let req = http::Request::builder()
        .uri("/")
        .header(hyper::header::HOST, "h")
        .body(body)
        .unwrap();
    let resp = proxy
        .forward(&ctx(), req, &target)
        .await
        .expect("forward ok");
    let text = collect(resp).await;
    assert_eq!(text, "len=0", "an empty GET forwards no body: {text}");
}
