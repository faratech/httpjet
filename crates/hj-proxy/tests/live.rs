//! Live integration tests for hj-proxy.
//!
//! These are all `#[ignore]` by default: they either spawn a local server on a
//! high alt port or hit the real backends on this host. Run explicitly with:
//!
//! ```bash
//! cargo test -p hj-proxy -- --ignored
//! # or a single one:
//! cargo test -p hj-proxy --test live forward_to_local_echo -- --ignored --nocapture
//! ```

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
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
        vhost_name: "live".into(),
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

fn empty_body() -> IncomingBody {
    Empty::<Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

/// Spawn a tiny HTTP/1.1 server that echoes selected request headers and the
/// request path back in the body. Returns the bound address.
async fn spawn_echo() -> SocketAddr {
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
                    let xff = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let host = req
                        .headers()
                        .get(hyper::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let path = req.uri().path().to_string();
                    let body = format!("path={path};host={host};xff={xff}");
                    Ok::<_, Infallible>(HyperResp::new(Full::new(Bytes::from(body))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
#[ignore = "spawns a local server; run with --ignored"]
async fn forward_to_local_echo() {
    let addr = spawn_echo().await;
    let proxy = Proxy::new();
    let target = ProxyTarget::parse_url(&format!("http://{addr}/proxied/path")).unwrap();

    let req = http::Request::builder()
        .uri("/orig?q=1")
        .header(hyper::header::HOST, "client.example")
        .body(empty_body())
        .unwrap();

    let resp = proxy
        .forward(&ctx(), req, &target)
        .await
        .expect("forward ok");
    assert_eq!(resp.status(), http::StatusCode::OK);

    // Drain the streamed body.
    let bytes = match resp.into_body() {
        hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        other => panic!("expected streaming body, got {:?}", body_kind(&other)),
    };
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("path=/proxied/path"), "got: {text}");
    assert!(
        text.contains("host=client.example"),
        "host preserved: {text}"
    );
    assert!(text.contains("xff=203.0.113.42"), "xff appended: {text}");
}

#[tokio::test]
#[ignore = "second request must reuse the pooled keep-alive connection"]
async fn keep_alive_reuses_connection() {
    let addr = spawn_echo().await;
    let proxy = Proxy::new();
    let target = ProxyTarget::parse_url(&format!("http://{addr}/x")).unwrap();

    for _ in 0..3 {
        let req = http::Request::builder()
            .uri("/x")
            .header(hyper::header::HOST, "h")
            .body(empty_body())
            .unwrap();
        let resp = proxy.forward(&ctx(), req, &target).await.unwrap();
        let _ = match resp.into_body() {
            hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
            _ => panic!("expected stream"),
        };
        // Let the connection return to the pool.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // One authority => one pool.
    assert_eq!(proxy.pool().len(), 1);
}

#[tokio::test]
#[ignore = "connects to nothing; expects a fast 502/504"]
async fn connect_failure_is_gateway_error() {
    let proxy = Proxy::with_limits(
        8,
        std::time::Duration::from_secs(30),
        std::time::Duration::from_millis(300),
    );
    // Port 1 is reserved/unbindable; connect should fail quickly.
    let target = ProxyTarget::parse_url("http://127.0.0.1:1/x").unwrap();
    let req = http::Request::builder()
        .uri("/x")
        .header(hyper::header::HOST, "h")
        .body(empty_body())
        .unwrap();
    let err = proxy
        .forward(&ctx(), req, &target)
        .await
        .err()
        .expect("should fail");
    let status = err.status();
    assert!(
        status == http::StatusCode::BAD_GATEWAY || status == http::StatusCode::GATEWAY_TIMEOUT,
        "got {status}"
    );
}

#[tokio::test]
#[ignore = "hits the real FastAPI backend on 127.0.0.1:8000"]
async fn live_fastapi_backend() {
    let proxy = Proxy::new();
    let target = ProxyTarget::parse_url("http://127.0.0.1:8000/").unwrap();
    let req = http::Request::builder()
        .uri("/")
        .header(hyper::header::HOST, "forum.example")
        .body(empty_body())
        .unwrap();
    match proxy.forward(&ctx(), req, &target).await {
        Ok(resp) => eprintln!("fastapi status: {}", resp.status()),
        Err(e) => eprintln!("fastapi unreachable: {e}"),
    }
}

#[tokio::test]
#[ignore = "hits the real MCP backend on 127.0.0.1:8002"]
async fn live_mcp_backend() {
    let proxy = Proxy::new();
    let target = ProxyTarget::parse_url("http://127.0.0.1:8002/health").unwrap();
    let req = http::Request::builder()
        .uri("/health")
        .header(hyper::header::HOST, "mcp.forum.example")
        .body(empty_body())
        .unwrap();
    match proxy.forward(&ctx(), req, &target).await {
        Ok(resp) => eprintln!("mcp /health status: {}", resp.status()),
        Err(e) => eprintln!("mcp unreachable: {e}"),
    }
}

fn body_kind(b: &hj_core::Body) -> &'static str {
    match b {
        hj_core::Body::Empty => "empty",
        hj_core::Body::Full(_) => "full",
        hj_core::Body::Stream(_) => "stream",
        hj_core::Body::File(_) => "file",
    }
}
