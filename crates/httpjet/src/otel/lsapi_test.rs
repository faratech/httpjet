//! Synthetic LSAPI peer: no PHP process or production socket is used.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture(std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("lsapi.sock"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

pub(super) async fn roundtrip() -> (hj_core::Response, String) {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!(
        "hj-otel-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let fixture = Fixture(dir);
    let socket = fixture.0.join("lsapi.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let peer = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0; 8];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..2], b"LS");
            assert_eq!(head[2], hj_lsapi::PacketType::BeginRequest as u8);
            assert_eq!(head[3] & 1, 0, "fixture expects little-endian framing");
            let size = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
            assert!((44..65536).contains(&size));
            let mut body = vec![0; size - 8];
            stream.read_exact(&mut body).await.unwrap();
            let rd = |at: usize| u32::from_le_bytes(body[at..at + 4].try_into().unwrap()) as usize;
            // Skip the special and CGI env tables, then align to the index.
            let mut at = 36;
            for _ in 0..2 {
                loop {
                    let k = u16::from_be_bytes(body[at..at + 2].try_into().unwrap()) as usize;
                    let v = u16::from_be_bytes(body[at + 2..at + 4].try_into().unwrap()) as usize;
                    at += 4;
                    if k == 0 && v == 0 {
                        break;
                    }
                    at += k + v;
                }
            }
            at += (8 - ((8 + at) % 8)) % 8;
            let unknown_at = at + hj_lsapi::HEADER_INDEX_LEN;
            let count = rd(24);
            let raw_at = unknown_at + count * 16;
            let raw = &body[raw_at..raw_at + rd(0)];
            let mut trace = None;
            for i in 0..count {
                let slot = unknown_at + i * 16;
                let name = &raw[rd(slot)..rd(slot) + rd(slot + 4)];
                let value = &raw[rd(slot + 8)..rd(slot + 8) + rd(slot + 12)];
                assert_ne!(name, b"baggage");
                assert_ne!(name, b"tracestate");
                if name == b"traceparent" {
                    assert!(trace.is_none(), "exactly one propagated parent");
                    trace = Some(String::from_utf8(value.to_vec()).unwrap());
                }
            }
            // Empty 200 response, with an explicit RESP_END.
            let mut out = vec![b'L', b'S', hj_lsapi::PacketType::RespHeader as u8, 0];
            out.extend_from_slice(&16u32.to_le_bytes());
            out.extend_from_slice(&0i32.to_le_bytes());
            out.extend_from_slice(&200i32.to_le_bytes());
            out.extend_from_slice(&[b'L', b'S', hj_lsapi::PacketType::RespEnd as u8, 0]);
            out.extend_from_slice(&8u32.to_le_bytes());
            stream.write_all(&out).await.unwrap();
            trace.expect("LSAPI unknown-header table must carry traceparent")
        })
        .await
        .expect("synthetic LSAPI exchange timed out")
    });
    let pool = std::sync::Arc::new(hj_lsapi::LsapiPool::new(&socket, 1, Duration::from_secs(1)));
    let handler = hj_lsapi::Lsapi::new(pool).read_timeout(Duration::from_secs(1));
    let mut ctx = hj_core::ReqCtx {
        server: std::sync::Arc::new(Default::default()),
        vhost_name: "synthetic".into(),
        vhost: std::sync::Arc::new(hj_core::config::VHostConfig {
            doc_root: fixture.0.clone(),
            ..Default::default()
        }),
        peer_ip: "127.0.0.1".parse().unwrap(),
        client_ip: "127.0.0.1".parse().unwrap(),
        is_tls: false,
        protocol: hj_core::Proto::Http1,
        trusted_proxy: false,
        env: vec![],
        local_addr: "127.0.0.1:8080".parse().unwrap(),
        peer_port: 12345,
        peer_unix: false,
        request_time: std::time::SystemTime::now(),
        request_id: Default::default(),
        tls: None,
        redirect_guard: None,
    };
    use http_body_util::BodyExt;
    let mut req = http::Request::builder()
        .uri("/index.php")
        .header("host", "synthetic")
        .header("traceparent", "public-input")
        .header("baggage", "secret=value")
        .body(
            http_body_util::Empty::<bytes::Bytes>::new()
                .map_err(|e| -> hj_core::BoxError { match e {} })
                .boxed(),
        )
        .unwrap();
    // Apply the same public-input boundary as the common pipeline, then the
    // actual terminal instrumentation used by run_handler.
    extract_parent(req.headers_mut(), false);
    let response = crate::pipeline::instrumented_handler(&handler, &mut ctx, req)
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    (response, peer.await.unwrap())
}
