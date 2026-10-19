//! A backend that reads the request head and then stops reading the body leaves
//! hyper parked on a full socket, so the body-inactivity timer is never polled and
//! the response-head timer never starts. The forward must still end with a 504.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::io::AsyncReadExt;
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
        forwarding_trusted: false,
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

async fn spawn_reads_head_then_stops() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut head = [0u8; 1024];
            let _ = stream.read(&mut head).await;
            held.push(stream);
        }
    });
    addr
}

/// An always-ready upload far larger than the loopback socket buffers.
struct EndlessBody {
    remaining: usize,
}

impl HttpBody for EndlessBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let n = self.remaining.min(64 * 1024);
        self.remaining -= n;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'x'; n])))))
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[tokio::test(start_paused = true)]
async fn backend_that_stops_reading_upload_times_out() {
    let addr = spawn_reads_head_then_stops().await;
    let target = ProxyTarget::parse_url(&format!("http://{addr}/")).unwrap();
    let body: IncomingBody = EndlessBody {
        remaining: 256 * 1024 * 1024,
    }
    .boxed();
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri("/upload")
        .header(http::header::HOST, "h")
        .header(http::header::TRANSFER_ENCODING, "chunked")
        .body(body)
        .unwrap();

    let started = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(300),
        Proxy::new().forward(&ctx(), req, &target, Some(2)),
    )
    .await
    .expect("a backend that stops reading must not hang the forward");
    let err = match outcome {
        Ok(resp) => panic!("expected a gateway timeout, got {}", resp.status()),
        Err(err) => err,
    };
    assert_eq!(err.status(), http::StatusCode::GATEWAY_TIMEOUT);
    assert!(started.elapsed() < Duration::from_secs(60));
}
