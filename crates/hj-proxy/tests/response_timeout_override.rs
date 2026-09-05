//! A per-context response timeout must govern bodyless forwards too. Before the
//! regression fix only body-bearing requests consumed the override; a GET kept the
//! pool's 60-second default.

use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
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
        vhost_name: "test".into(),
        vhost: Arc::new(VHostConfig::default()),
        peer_ip: "127.0.0.1".parse().unwrap(),
        client_ip: "127.0.0.1".parse().unwrap(),
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
    Empty::<bytes::Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bodyless_get_uses_response_timeout_override() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(|_req| async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                bytes::Bytes::from_static(b"late"),
            )))
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let target = ProxyTarget::parse_url(&format!("http://{addr}/")).unwrap();
    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header(http::header::HOST, "public.example")
        .body(empty_body())
        .unwrap();
    let started = Instant::now();
    let err = match Proxy::new().forward(&ctx(), req, &target, Some(1)).await {
        Ok(_) => panic!("one-second override must expire before the upstream head"),
        Err(err) => err,
    };
    assert_eq!(err.status(), http::StatusCode::GATEWAY_TIMEOUT);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "bodyless request ignored its one-second timeout override"
    );

    server.abort();
    let _ = server.await;
}
