//! (Tier 2) `h2://` upstream integration: a real HTTP/2 server (hyper's h2
//! server on a loopback TCP listener) driven by the proxy's forward path —
//! protocol normalization, both requests served, and pool separation from h1.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use http::{Request, StatusCode};
use http_body::{Body as HttpBody, Frame};
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
        let authority = req
            .uri()
            .authority()
            .map(|a| a.as_str())
            .unwrap_or("<missing>");
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<missing>");
        assert_eq!(
            authority, host,
            "RFC 9113 requires Host and :authority to agree"
        );
        assert_eq!(host, "backend.test", "preserve the client virtual host");
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

struct HeldBody {
    first: bool,
    release: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl HttpBody for HeldBody {
    type Data = bytes::Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.first {
            self.first = false;
            return Poll::Ready(Some(Ok(Frame::data(bytes::Bytes::from_static(b"held")))));
        }
        let Some(release) = self.release.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(release).poll(cx) {
            Poll::Ready(_) => {
                self.release = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn h2_upstream_serves_requests_with_normalized_version() {
    let conns = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_one_h2_connection(listener, conns.clone()));

    let target = ProxyTarget::parse_url(&format!("h2://{addr}")).unwrap();
    assert!(target.http2, "the h2:// scheme must select HTTP/2");
    let keep_alive = Duration::from_secs(60);
    let connect_timeout = Duration::from_secs(1);
    let proxy = Proxy::with_limits(100, keep_alive, connect_timeout);

    for path in ["/one", "/two"] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("http://backend.test{path}"))
            .header(http::header::HOST, "backend.test")
            .body(empty_body())
            .unwrap();
        let resp = tokio::time::timeout(
            Duration::from_secs(2),
            proxy.forward(&ctx(), req, &target, Some(1)),
        )
        .await
        .expect("h2 forward must not wait on an unnecessary second connection")
        .expect("h2 forward");
        let upstream = proxy
            .pool()
            .get_or_create(&target, 100, keep_alive, connect_timeout);
        assert_eq!(
            upstream.idle_count(),
            1,
            "the reusable h2 sender must be back in the pool before forward returns"
        );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_max_conns_counts_an_open_response_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let request_count = Arc::new(AtomicU32::new(0));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
    let server_count = request_count.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = hyper::service::service_fn(move |_req: Request<Incoming>| {
            let sequence = server_count.fetch_add(1, Ordering::SeqCst);
            let release = if sequence == 0 {
                release_rx.lock().unwrap().take()
            } else {
                None
            };
            async move {
                Ok::<_, Infallible>(http::Response::new(HeldBody {
                    first: true,
                    release,
                }))
            }
        });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let proxy = Arc::new(Proxy::with_limits(
        1,
        Duration::from_secs(60),
        Duration::from_secs(2),
    ));
    let target = ProxyTarget::parse_url(&format!("h2://{addr}")).unwrap();
    let first = proxy
        .forward(
            &ctx(),
            Request::builder()
                .uri("http://backend.test/first")
                .header(http::header::HOST, "backend.test")
                .body(empty_body())
                .unwrap(),
            &target,
            None,
        )
        .await
        .expect("first h2 forward");

    let second_proxy = proxy.clone();
    let second_target = target.clone();
    let second = tokio::spawn(async move {
        second_proxy
            .forward(
                &ctx(),
                Request::builder()
                    .uri("http://backend.test/second")
                    .header(http::header::HOST, "backend.test")
                    .body(empty_body())
                    .unwrap(),
                &second_target,
                None,
            )
            .await
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        request_count.load(Ordering::SeqCst),
        1,
        "maxConns=1 must keep the second h2 request queued while the first response is open"
    );

    let _ = release_tx.send(());
    drop(first);
    let second_resp = tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("second h2 forward should enter after first response drops")
        .expect("second task")
        .expect("second h2 forward");
    drop(second_resp);
    assert_eq!(request_count.load(Ordering::SeqCst), 2);

    server.abort();
    let _ = server.await;
}
