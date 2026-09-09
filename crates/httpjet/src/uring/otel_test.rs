use super::*;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
use std::sync::Mutex;

#[path = "otel_quic_test.rs"]
mod quic;

#[derive(Clone, Debug, Default)]
struct Capture(Arc<Mutex<Vec<SpanData>>>);
impl SpanExporter for Capture {
    async fn export(&self, spans: Vec<SpanData>) -> opentelemetry_sdk::error::OTelSdkResult {
        self.0.lock().unwrap().extend(spans);
        Ok(())
    }
}

#[test]
fn traced_fast_and_bridged_requests() {
    // Isolate global SDK/runtime enablement from concurrently running unit tests.
    if std::env::var_os("HTTPJET_OTEL_TRANSPORT_TEST_CHILD").is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "uring::otel_test::traced_fast_and_bridged_requests",
                "--nocapture",
            ])
            .env("HTTPJET_OTEL_TRANSPORT_TEST_CHILD", "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("transport fixture timed out");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    let capture = Capture::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(capture.clone())
        .build();
    opentelemetry::global::set_tracer_provider(provider.clone());
    crate::otel::enable_for_isolated_test();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let root = std::env::temp_dir().join(format!("hj-otel-transport-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("index.html"), b"synthetic telemetry response").unwrap();
    let (core, server_root) = runtime.block_on(async {
        let state = crate::pipeline::e2e::build_state(root.clone());
        let server_root = state.server.server_root.clone();
        let holder = Arc::new(arc_swap::ArcSwap::from(state));
        let listener_name: Arc<str> = "http".into();
        let bridge = build_pipeline_bridge(
            holder.clone(),
            listener_name.clone(),
            bridge::BridgeAdmission::dynamic(|| 16),
        );
        (
            CoreHandler {
                bridge,
                holder: ServingView::new(holder),
                listener_name,
            },
            server_root,
        )
    });
    let ctx = BridgeCtx {
        peer: "127.0.0.1:12345".parse().unwrap(),
        local: "127.0.0.1:8080".parse().unwrap(),
        proto: hj_core::Proto::Http2,
        is_tls: false,
        direct_file_egress: false,
        peer_unix: false,
        mtls_required: false,
        sni: None,
        tls: None,
        request_generation: None,
    };
    // Drive the same H2 service dispatcher with both on-core and bridged requests.
    runtime.block_on(async {
        let cache_state = crate::pipeline::e2e::build_state_full(
            root.clone(),
            Vec::new(),
            Vec::new(),
            Some(Arc::new(hj_pagecache::PageStore::new(Default::default()))),
            None,
        );
        let cache_server_root = cache_state.server.server_root.clone();
        let cache_core = CoreHandler {
            bridge: build_pipeline_bridge(
                Arc::new(arc_swap::ArcSwap::from(cache_state.clone())),
                "http".into(),
                bridge::BridgeAdmission::dynamic(|| 16),
            ),
            holder: ServingView::new(Arc::new(arc_swap::ArcSwap::from(cache_state))),
            listener_name: "http".into(),
        };
        let req = http::Request::builder()
            .uri("/index.html")
            .header("host", "canon.test")
            .body(hj_core::empty_incoming())
            .unwrap();
        let response = cache_core.dispatch_h2(ctx.clone(), req).await;
        assert_eq!(response.status(), 200);
        let _ = bridge::buffer_body(response.into_body()).await;
        drop(cache_core);
        std::fs::remove_dir_all(cache_server_root).unwrap();
        for method in ["GET", "POST"] {
            let req = http::Request::builder()
                .method(method)
                .uri("/index.html")
                .header("host", "canon.test")
                .header("baggage", "secret=value")
                .body(hj_core::empty_incoming())
                .unwrap();
            let response = core.dispatch_h2(ctx.clone(), req).await;
            let _ = bridge::buffer_body(response.into_body()).await;
        }
        let mut h3_ctx = ctx.clone();
        h3_ctx.proto = hj_core::Proto::Http3;
        h3_ctx.is_tls = true;
        let req = http::Request::builder()
            .uri("/index.html")
            .header("host", "canon.test")
            .body(hj_core::empty_incoming())
            .unwrap();
        let before = capture
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.name == "httpjet.request")
            .count();
        let mut response = core.bridge.dispatch(req, h3_ctx.clone()).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            capture
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.name == "httpjet.request")
                .count(),
            before,
            "H3 bridge production must not finish the root span"
        );
        response
            .completion
            .take()
            .unwrap()
            .finish(hj_core::ResponseEnd::Complete);

        // A failure while buffering must preserve lifetime and report the actual
        // outgoing 502, not the original successful backend response head.
        let failing = bridge::spawn_bridge(1, |_, _| async {
            crate::otel::request_with_completion(opentelemetry::Context::new(), async {
                http::Response::new(hj_core::Body::File(hj_core::FileBody {
                    path: "/nonexistent-httpjet-test/path".into(),
                    file: None,
                    len: 4,
                    range: None,
                    cached: None,
                }))
            })
            .await
        })
        .unwrap();
        let req = http::Request::new(hj_core::empty_incoming());
        let mut response = failing.dispatch(req, h3_ctx).await.unwrap();
        assert_eq!(response.status, 502);
        response
            .completion
            .take()
            .unwrap()
            .finish(hj_core::ResponseEnd::Complete);
    });
    // Drive the actual io_uring H1 reader/dispatcher/writer over loopback.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream
            .write_all(b"GET /index.html HTTP/1.1\r\nHost: canon.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut wire = Vec::new();
        stream.read_to_end(&mut wire).unwrap();
        assert!(wire.starts_with(b"HTTP/1.1 200"));
        assert!(wire.ends_with(b"synthetic telemetry response"));
    });
    let mut monoio = build_core_runtime().unwrap();
    monoio.block_on(async {
        let listener = monoio::net::TcpListener::from_std(listener).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut ctx = ctx.clone();
        ctx.proto = hj_core::Proto::Http1;
        handle_h1_bridged(
            stream,
            Vec::new(),
            ctx,
            core.clone(),
            CancellationToken::new(),
            None,
        )
        .await;
    });
    client.join().unwrap();
    let websocket_headers = runtime.block_on(crate::pipeline::e2e::traced_websocket_handshakes(
        &core.holder.load_full(),
    ));
    websocket_roundtrip(&runtime, &mut monoio, &root, &ctx, &capture);
    let spans = capture.0.lock().unwrap().clone();
    let requests: Vec<_> = spans
        .iter()
        .filter(|s| s.name == "httpjet.request")
        .collect();
    assert_eq!(
        requests.len(),
        9,
        "one root per request, no duplicate bridge roots"
    );
    assert!(
        requests
            .iter()
            .all(|s| s.parent_span_id == opentelemetry::trace::SpanId::INVALID)
    );
    for path in ["on-core", "bridge"] {
        assert!(requests.iter().any(|s| {
            s.attributes
                .iter()
                .any(|a| a.key.as_str() == "httpjet.execution.path" && a.value.as_str() == path)
        }));
    }
    assert!(requests.iter().any(|s| {
        s.attributes
            .iter()
            .any(|a| a.key.as_str() == "httpjet.body.outcome" && a.value.as_str() == "complete")
    }));
    for backend in spans.iter().filter(|s| s.name == "httpjet.static") {
        assert!(
            requests
                .iter()
                .any(|r| r.span_context.span_id() == backend.parent_span_id)
        );
    }
    assert!(spans.iter().any(|s| s.name == "httpjet.static"));
    let websocket_spans: Vec<_> = spans
        .iter()
        .filter(|s| s.name == "httpjet.websocket")
        .collect();
    assert_eq!(websocket_spans.len(), 3);
    for span in &websocket_spans {
        assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Client);
        assert!(
            requests
                .iter()
                .any(|r| r.span_context.span_id() == span.parent_span_id)
        );
    }
    let named = websocket_spans[0];
    assert_eq!(
        websocket_headers[0].as_deref(),
        Some(
            format!(
                "00-{}-{}-01",
                named.span_context.trace_id(),
                named.span_context.span_id()
            )
            .as_str()
        )
    );
    assert!(
        websocket_headers[1].is_none(),
        "ad-hoc target must not receive generated context"
    );
    for name in [
        "httpjet.rewrite",
        "httpjet.cache.lookup",
        "httpjet.cache.store",
    ] {
        let stages: Vec<_> = spans.iter().filter(|s| s.name == name).collect();
        assert!(!stages.is_empty(), "missing {name} stage");
        for stage in stages {
            assert!(
                stage.attributes.is_empty(),
                "stage must not export request metadata"
            );
            assert!(
                requests
                    .iter()
                    .any(|r| r.span_context.span_id() == stage.parent_span_id)
            );
        }
    }
    assert!(requests.iter().any(|s| {
        s.attributes
            .iter()
            .any(|a| a.key.as_str() == "http.response.status_code" && a.value.as_str() == "502")
    }));
    provider.shutdown().unwrap();
    drop(core);
    drop(runtime);
    drop(monoio);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(server_root).unwrap();
}

fn websocket_roundtrip(
    runtime: &tokio::runtime::Runtime,
    monoio: &mut monoio::Runtime<monoio::time::TimeDriver<monoio::IoUringDriver>>,
    root: &std::path::Path,
    ctx: &BridgeCtx,
    capture: &Capture,
) {
    use std::io::{Read, Write};
    const CLIENT_FRAME: &[u8] = &[0x81, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2];
    const SERVER_FRAME: &[u8] = &[0x81, 2, b'o', b'k'];
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let backend = std::thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 8192);
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").unwrap();
        let mut frame = [0; 8];
        stream.read_exact(&mut frame).unwrap();
        assert_eq!(frame, CLIENT_FRAME);
        stream.write_all(SERVER_FRAME).unwrap();
        String::from_utf8(head).unwrap()
    });
    let (core, server_root) = runtime.block_on(async {
        let state =
            crate::pipeline::e2e::build_state_websocket(root.into(), upstream_addr.to_string());
        let server_root = state.server.server_root.clone();
        let holder = Arc::new(arc_swap::ArcSwap::from(state));
        let listener_name: Arc<str> = "http".into();
        let bridge = build_pipeline_bridge(
            holder.clone(),
            listener_name.clone(),
            bridge::BridgeAdmission::dynamic(|| 16),
        );
        (
            CoreHandler {
                bridge,
                holder: ServingView::new(holder),
                listener_name,
            },
            server_root,
        )
    });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let observed = capture.clone();
    let client = std::thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream.write_all(b"GET /socket HTTP/1.1\r\nHost: canon.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nBaggage: secret=value\r\n\r\n").unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 8192);
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 101"));
        // The root ends at the 101 handoff, not at eventual relay EOF.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let done = observed.0.lock().unwrap().iter().any(|s| {
                s.name == "httpjet.request"
                    && s.attributes.iter().any(|a| {
                        a.key.as_str() == "httpjet.body.outcome" && a.value.as_str() == "upgraded"
                    })
            });
            if done {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "101 root did not end before relay"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        stream.write_all(CLIENT_FRAME).unwrap();
        let mut frame = [0; 4];
        stream.read_exact(&mut frame).unwrap();
        assert_eq!(frame, SERVER_FRAME);
    });
    monoio.block_on(async {
        let listener = monoio::net::TcpListener::from_std(listener).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut ctx = ctx.clone();
        ctx.proto = hj_core::Proto::Http1;
        handle_h1_bridged(
            stream,
            Vec::new(),
            ctx,
            core,
            CancellationToken::new(),
            None,
        )
        .await;
    });
    client.join().unwrap();
    let head = backend.join().unwrap();
    let spans = capture.0.lock().unwrap();
    let span = spans
        .iter()
        .rev()
        .find(|s| s.name == "httpjet.websocket")
        .unwrap();
    let parent = format!(
        "traceparent: 00-{}-{}-01",
        span.span_context.trace_id(),
        span.span_context.span_id()
    );
    assert!(head.to_ascii_lowercase().contains(&parent));
    assert!(!head.to_ascii_lowercase().contains("baggage:"));
    std::fs::remove_dir_all(server_root).unwrap();
}
