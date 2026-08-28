//! The one bodyless-idempotent retry must replay the CLIENT's head, not an empty one.
//!
//! When a pooled keep-alive connection dies between `checkout`'s `is_ready()` gate and
//! `send_request`, `forward` retries once. Rebuilding that request from method+URI alone left
//! `ensure_host` to substitute the upstream authority for the client `Host` (and
//! `X-Forwarded-Host` to inherit it), and dropped `Cookie` / `Authorization` / `Accept`.
//!
//! Binds a loopback port, so `#[ignore]`
//! (`cargo test -p hj-proxy --test retry_head_replay -- --ignored`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        tls: None,
        redirect_guard: None,
    }
}

fn empty_body() -> IncomingBody {
    Empty::<Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

/// A raw HTTP/1.1 listener that reproduces the check-to-send race deterministically.
///
/// Connection #1 answers the first request with a keep-alive 200 (so the sender is POOLED and
/// still passes `is_ready()`), then reads the SECOND request and closes without replying — so
/// `send_request` fails after the request was written, which is the arm that retries.
/// Connection #2 is the retry's fresh dial; its request head is reported over `tx`.
async fn spawn_scripted(tx: mpsc::Sender<String>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut conn = 0u32;
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            conn += 1;
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut seen = 0u32;
                loop {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(n) = stream.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        head.extend_from_slice(&buf[..n]);
                        if head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    seen += 1;
                    if conn == 1 && seen == 2 {
                        return; // drop mid-request => send_request fails => retry
                    }
                    if conn == 2 {
                        let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
                    }
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                        .await;
                    let _ = stream.flush().await;
                }
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binds a loopback port; run with --ignored"]
async fn retry_replays_the_client_head_not_an_empty_one() {
    let (tx, rx) = mpsc::channel();
    let addr = spawn_scripted(tx).await;
    let proxy = Proxy::with_limits(8, Duration::from_secs(60), Duration::from_secs(5));
    let target = ProxyTarget::parse_url(&format!("http://{addr}/")).unwrap();

    // Request 1: populates the idle pool, then the upstream closes that connection.
    let req = http::Request::builder()
        .uri("/tools.json")
        .header(hyper::header::HOST, "mcp.windowsforum.com")
        .body(empty_body())
        .unwrap();
    let resp = proxy.forward(&ctx(), req, &target).await.expect("first ok");
    if let Body::Stream(s) = resp.into_body() {
        let _ = s.collect().await;
    }
    // Let the drain task return the sender to the idle pool. It is still OPEN, so it passes
    // `is_ready()` — the upstream only closes once request 2 has been written to it.
    tokio::time::sleep(Duration::from_millis(120)).await;

    // Request 2: goes out on the pooled sender, the upstream closes without replying, and the
    // retry fires on a freshly dialed connection.
    let req = http::Request::builder()
        .uri("/tools.json")
        .header(hyper::header::HOST, "mcp.windowsforum.com")
        .header(hyper::header::COOKIE, "xf_session=abc")
        .header(hyper::header::ACCEPT, "text/event-stream")
        .header(hyper::header::AUTHORIZATION, "Bearer t0ken")
        .body(empty_body())
        .unwrap();
    let resp = proxy
        .forward(&ctx(), req, &target)
        .await
        .expect("retried request must succeed");
    assert_eq!(resp.status(), http::StatusCode::OK);
    if let Body::Stream(s) = resp.into_body() {
        let _ = s.collect().await;
    }

    let head = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("upstream never received a retried request");
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains("host: mcp.windowsforum.com"),
        "retry must carry the CLIENT Host, not the upstream authority; got:\n{head}"
    );
    assert!(
        lower.contains("x-forwarded-host: mcp.windowsforum.com"),
        "x-forwarded-host must derive from the client Host; got:\n{head}"
    );
    assert!(
        lower.contains("cookie: xf_session=abc"),
        "retry dropped Cookie; got:\n{head}"
    );
    assert!(
        lower.contains("authorization: bearer t0ken"),
        "retry dropped Authorization; got:\n{head}"
    );
    assert!(
        lower.contains("accept: text/event-stream"),
        "retry dropped Accept (the header the mcp vhost routes SSE on); got:\n{head}"
    );
}
