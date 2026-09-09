use super::*;

#[test]
#[ignore = "requires python3 with aioquic; synthetic loopback QUIC only"]
fn traced_quic_roundtrip() {
    if std::env::var_os("HTTPJET_OTEL_QUIC_TEST_CHILD").is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "uring::otel_test::quic::traced_quic_roundtrip",
                "--nocapture",
            ])
            .env("HTTPJET_OTEL_QUIC_TEST_CHILD", "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("QUIC fixture timed out");
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
    let root = std::env::temp_dir().join(format!("hj-otel-quic-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("index.html"), b"synthetic QUIC response").unwrap();
    std::fs::write(root.join("large.txt"), vec![b'x'; 2 * 1024 * 1024]).unwrap();
    let (bridge, server_root, view) = runtime.block_on(async {
        let state = crate::pipeline::e2e::build_state(root.clone());
        let server_root = state.server.server_root.clone();
        let holder = Arc::new(arc_swap::ArcSwap::from(state));
        let view = ServingView::new(holder.clone());
        let bridge = build_pipeline_bridge(
            holder,
            "http".into(),
            bridge::BridgeAdmission::dynamic(|| 16),
        );
        (bridge, server_root, view)
    });
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let (workers, _policy) = h3::serve_h3_pipeline(
        addr,
        1,
        h3::self_signed_config().unwrap(),
        bridge,
        false,
        h3::H3RuntimeConfig::new(
            || (h3::H3RequestLimits::new(16_384, 1024 * 1024), 8),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            Arc::new(hj_core::budget::BodyBufferBudget::new(8 * 1024 * 1024)),
        )
        .with_serving_view(view),
        Some(vec![socket]),
        shutdown.clone(),
    )
    .unwrap();
    workers.activate();
    let mut client = std::process::Command::new("python3")
        .arg("-B")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/otel_h3_client.py"
        ))
        .arg(addr.port().to_string())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let status = loop {
        if let Some(status) = client.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = client.kill();
            let _ = client.wait();
            shutdown.cancel();
            panic!("aioquic client timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    shutdown.cancel();
    assert!(status.success());
    let spans = capture.0.lock().unwrap().clone();
    let roots: Vec<_> = spans
        .iter()
        .filter(|s| s.name == "httpjet.request")
        .collect();
    assert_eq!(roots.len(), 2, "one completed root per actual QUIC request");
    for root in &roots {
        assert_eq!(root.parent_span_id, opentelemetry::trace::SpanId::INVALID);
        for (key, value) in [
            ("http.response.status_code", "200"),
            ("httpjet.body.outcome", "complete"),
        ] {
            assert!(
                root.attributes
                    .iter()
                    .any(|a| a.key.as_str() == key && a.value.as_str() == value)
            );
        }
    }
    let backends: Vec<_> = spans
        .iter()
        .filter(|s| s.name == "httpjet.static")
        .collect();
    assert_eq!(backends.len(), 2);
    assert!(backends.iter().all(|s| {
        roots
            .iter()
            .any(|r| r.span_context.span_id() == s.parent_span_id)
    }));
    provider.shutdown().unwrap();
    drop(runtime);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(server_root).unwrap();
}
