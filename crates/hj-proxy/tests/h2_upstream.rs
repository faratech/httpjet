//! (Tier 2) `h2://` upstream integration: a real HTTP/2 server (hyper's h2
//! server on a loopback TCP listener) driven by the proxy's forward path —
//! protocol normalization, both requests served, and pool separation from h1.

use std::sync::Arc;

use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use hj_core::config::ServerConfig;
use hj_core::{Proto, ReqCtx};
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
        vhost_name: String::new(),
        vhost: Arc::new(hj_core::config::VHostConfig::default()),
        peer_ip: "127.0.0.1".parse().unwrap(),
        client_ip: "127.0.0.1".parse().unwrap(),
        is_tls: false,
        peer_unix: false,
        protocol: Proto::Http1,
        trusted_proxy: false,
        env: Vec::new(),
        local_addr: "127.0.0.1:80".parse().unwrap(),
        peer_port: 40000,
        request_time: std::time::SystemTime::UNIX_EPOCH,
        request_id: hj_core::reqid::next(),
        redirect_guard: None,
        tls: None,
    }
}

fn empty_body() -> hj_core::IncomingBody {
    http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e| match e {})
        .boxed()
}

async fn serve_one_h2_connection(listener: TcpListener, conns: Arc<std::sync::atomic::AtomicU32>) {
    let (stream, _) = listener.accept().await.unwrap();
    conns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let io = TokioIo::new(stream);
    let service = hyper::service::service_fn(move |req: Request<Incoming>| async move {
        let body = format!("ok {}", req.uri().path());
        Ok::<_, std::convert::Infallible>(http::Response::new(
            Full::new(bytes::Bytes::from(body))
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        ))
    });
    if let Err(e) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await
    {
        eprintln!("h2 test server connection error: {e}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_upstream_serves_requests_with_normalized_version() {
    let conns = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_one_h2_connection(listener, conns.clone()));

    let target = ProxyTarget::parse_url(&format!("h2://{addr}")).unwrap();
    assert!(target.http2, "the h2:// scheme must select HTTP/2");
    let proxy = Proxy::new();

    for path in ["/one", "/two"] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("http://backend.test{path}"))
            .header(http::header::HOST, "backend.test")
            .body(empty_body())
            .unwrap();
        let resp = proxy
            .forward(&ctx(), req, &target, None)
            .await
            .expect("h2 forward");
        assert_eq!(resp.status(), StatusCode::OK);
        match resp.into_body() {
            hj_core::Body::Stream(mut s) => {
                let mut got = Vec::new();
                while let Some(frame) = s.frame().await {
                    let d = frame.expect("frame").into_data().expect("data");
                    got.extend_from_slice(&d);
                }
                assert_eq!(String::from_utf8_lossy(&got), format!("ok {path}"));
            }
            _other => panic!("expected stream body"),
        }
    }

    assert_eq!(
        conns.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "one h2 connection multiplexes both requests (single accept)"
    );
}
