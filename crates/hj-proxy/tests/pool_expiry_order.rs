//! Item 27 regression: idle-pool expiry must prune stale connections from ALL
//! positions, not just the newest (back) end.
//!
//! `release` pushes fresh connections to the back, so the oldest live entries sit
//! at the front. The previous expiry loop popped only the back, leaving expired
//! front entries to linger (inflating idle_count + causing is_ready()-false
//! rejects and extra dials under a burst). The fix prunes the whole Vec in one
//! `retain` pass.
//!
//! The deterministic front-vs-back unit test lives inline in `pool.rs`
//! (`checkout_prunes_expired_from_front_not_just_back`, which sets `idle_since`
//! directly). This file exercises the same property through the public API and so
//! binds a loopback port (`#[ignore]`):
//! `cargo test -p hj-proxy --test pool_expiry_order -- --ignored`.

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
                let svc = service_fn(|_req: HyperReq<hyper::body::Incoming>| async move {
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

async fn drain(proxy: &Proxy, target: &ProxyTarget) {
    let req = http::Request::builder()
        .uri("/")
        .header(hyper::header::HOST, "h")
        .body(empty_body())
        .unwrap();
    let resp = proxy
        .forward(&ctx(), req, target, None)
        .await
        .expect("forward ok");
    if let Body::Stream(s) = resp.into_body() {
        let _ = s.collect().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binds a loopback port; run with --ignored"]
async fn expired_idle_entries_are_pruned_from_all_positions() {
    let addr = spawn_echo().await;
    // Short keep_alive so the connections from the first wave expire before the second.
    let proxy = Arc::new(Proxy::with_limits(
        8,
        Duration::from_millis(150),
        Duration::from_secs(5),
    ));
    let target = ProxyTarget::parse_url(&format!("http://{addr}/")).unwrap();

    // First wave (CONCURRENT) populates several idle connections (the "front", oldest).
    let mut handles = Vec::new();
    for _ in 0..4 {
        let p = proxy.clone();
        let t = target.clone();
        handles.push(tokio::spawn(async move { drain(&p, &t).await }));
    }
    for h in handles {
        h.await.unwrap();
    }
    // Let the connections settle into the idle pool.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_first = proxy.pool_idle(&target);
    assert!(
        after_first >= 1,
        "first wave should pool at least one connection (got {after_first})"
    );

    // Wait until the first wave is past keep_alive (now stale at the front of the Vec).
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A single checkout must prune ALL the stale front entries in one pass (retain),
    // then dial/reuse exactly one connection — not leave the stale ones lingering.
    drain(&proxy, &target).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let after_expiry = proxy.pool_idle(&target);
    assert!(
        after_expiry <= 1,
        "stale front entries must be pruned; idle_count reflects only live ones (got {after_expiry})"
    );
}

trait PoolIdle {
    fn pool_idle(&self, target: &ProxyTarget) -> usize;
}

impl PoolIdle for Proxy {
    fn pool_idle(&self, target: &ProxyTarget) -> usize {
        // The pool exposes per-authority upstreams lazily; re-creating with the same key
        // returns the existing Arc, whose idle_count() we read.
        self.pool()
            .get_or_create(
                target,
                8,
                Duration::from_millis(150),
                Duration::from_secs(5),
            )
            .idle_count()
    }
}
