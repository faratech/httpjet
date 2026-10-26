//! End-to-end dispatch tests for the [`Lsapi`] handler.
//!
//! `mock_lsphp_roundtrip` runs a hand-rolled fake lsphp that speaks the LSAPI
//! wire format over a temp UDS — no external binary, runs in CI.
//!
//! `live_phpinfo` spawns the REAL `/usr/local/lsws/lsphp8/bin/lsphp` against a
//! SEPARATE temp socket and runs `phpinfo()`. It is `#[ignore]` so it never runs
//! by default and never touches the production server.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use http_body_util::channel::Channel;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use hj_core::config::{ServerConfig, Tuning, VHostConfig};
use hj_core::{Handler, HandlerError, Proto, ReqCtx};
use hj_lsapi::{
    ExternalGenerationWriter, HEADER_INDEX_LEN, KNOWN_HEADER_COUNT, Lsapi, LsapiPool,
    LsphpSupervisor, Monitor, MonitorConfig, PACKET_HEADER_LEN, PacketType, SupervisorConfig,
    WorkerState,
};

fn tmp_sock(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("hj-lsapi-it-{}-{}.sock", std::process::id(), name));
    let _ = std::fs::remove_file(&p);
    p
}

fn empty_incoming() -> hj_core::IncomingBody {
    BoxBody::new(Empty::<Bytes>::new().map_err(|e| {
        let e: hj_core::BoxError = Box::new(e);
        e
    }))
}

fn full_incoming(bytes: &'static [u8]) -> hj_core::IncomingBody {
    BoxBody::new(Full::new(Bytes::from_static(bytes)).map_err(|e| match e {}))
}

fn server() -> Arc<ServerConfig> {
    Arc::new(ServerConfig {
        server_root: PathBuf::from("/usr/local/lsws"),
        server_name: "it".into(),
        user: "nobody".into(),
        group: "nobody".into(),
        index_files: vec!["index.php".into()],
        tuning: Tuning::default(),
        quic_enable: false,
        use_ip_in_proxy_header: 0,
        expires: Default::default(),
        cache: Default::default(),
        security: Default::default(),
        suexec: Default::default(),
        ext_processors: vec![],
        php_config: None,
        listeners: vec![],
        vhosts: BTreeMap::new(),
        vhost_order: vec![],
        mime: Default::default(),
    })
}

fn ctx(doc_root: &str) -> ReqCtx {
    let vh = VHostConfig {
        doc_root: PathBuf::from(doc_root),
        ..Default::default()
    };
    ReqCtx {
        server: server(),
        vhost_name: "test".into(),
        vhost: Arc::new(vh),
        peer_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
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

/// Read one LSAPI packet from a stream (returns type + body).
async fn read_packet<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<(u8, Bytes)> {
    let mut hdr = [0u8; PACKET_HEADER_LEN];
    r.read_exact(&mut hdr).await?;
    assert_eq!(&hdr[..2], b"LS");
    let total = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    let mut body = vec![0u8; total - PACKET_HEADER_LEN];
    r.read_exact(&mut body).await?;
    Ok((hdr[2], Bytes::from(body)))
}

fn put_packet(buf: &mut BytesMut, ptype: PacketType, body: &[u8]) {
    let total = PACKET_HEADER_LEN + body.len();
    buf.put_u8(b'L');
    buf.put_u8(b'S');
    buf.put_u8(ptype as u8);
    // lsphp flags its little-endian packets with its LSAPI_ENDIAN, which is BIG on aarch64.
    buf.put_u8(hj_lsapi::proto::HOST_LSAPI_ENDIAN);
    buf.put_u32_le(total as u32);
    buf.extend_from_slice(body);
}

/// Build a RESP_HEADER body (little-endian) the way lsphp would.
fn resp_header_body(status: i32, headers: &[(&str, &str)]) -> BytesMut {
    let mut body = BytesMut::new();
    body.put_i32_le(headers.len() as i32);
    body.put_i32_le(status);
    let lines: Vec<String> = headers.iter().map(|(n, v)| format!("{n}: {v}")).collect();
    for l in &lines {
        body.put_u16_le((l.len() + 1) as u16); // include NUL
    }
    for l in &lines {
        body.extend_from_slice(l.as_bytes());
        body.put_u8(0);
    }
    body
}

async fn buffered_mock_response(
    tag: &str,
    method: &str,
    status: i32,
    headers: &[(&str, &str)],
    chunks: &[&[u8]],
) -> (Result<hj_core::Response, HandlerError>, Arc<LsapiPool>) {
    let path = tmp_sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let mut out = BytesMut::new();
    put_packet(
        &mut out,
        PacketType::RespHeader,
        &resp_header_body(status, headers),
    );
    for chunk in chunks {
        put_packet(&mut out, PacketType::RespStream, chunk);
    }
    put_packet(&mut out, PacketType::RespEnd, b"");

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (ptype, _) = read_packet(&mut stream).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        stream.write_all(&out).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(1));
    let request = http::Request::builder()
        .method(method)
        .uri("/index.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let result = handler.handle(&mut ctx("/web/test"), request).await;
    server_task.await.unwrap();
    tokio::task::yield_now().await;
    let _ = std::fs::remove_file(path);
    (result, pool)
}

async fn streamed_mock_response(
    tag: &str,
    method: &str,
    status: i32,
    declared: &str,
    body: &[u8],
) -> (Result<Bytes, hj_core::BoxError>, Arc<LsapiPool>) {
    let path = tmp_sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let header = {
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(status, &[("Content-Length", declared)]),
        );
        out
    };
    let body = body.to_vec();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (ptype, _) = read_packet(&mut stream).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        stream.write_all(&header).await.unwrap();
        stream.flush().await.unwrap();
        release_rx.await.unwrap();

        let mut out = BytesMut::new();
        put_packet(&mut out, PacketType::RespStream, &body);
        put_packet(&mut out, PacketType::RespEnd, b"");
        stream.write_all(&out).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(1));
    let request = http::Request::builder()
        .method(method)
        .uri("/index.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let response = handler
        .handle(&mut ctx("/web/test"), request)
        .await
        .expect("valid response head");
    release_tx.send(()).unwrap();
    let result = match response.into_body() {
        hj_core::Body::Stream(stream) => stream.collect().await.map(|body| body.to_bytes()),
        other => panic!(
            "barrier must force streaming, got {:?}",
            std::mem::discriminant(&other)
        ),
    };
    server_task.await.unwrap();
    tokio::task::yield_now().await;
    let _ = std::fs::remove_file(path);
    (result, pool)
}

fn read_i32_le(body: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(body[at..at + 4].try_into().unwrap())
}

fn skip_len_table(body: &[u8], mut p: usize) -> usize {
    loop {
        let klen = u16::from_be_bytes(body[p..p + 2].try_into().unwrap()) as usize;
        let vlen = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if klen == 0 && vlen == 0 {
            break;
        }
        p += klen + vlen;
    }
    p
}

fn parse_begin_env(body: &[u8]) -> (BTreeMap<String, String>, usize) {
    let mut env = BTreeMap::new();
    let mut p = skip_len_table(body, 36); // skip special-env table first.
    loop {
        let klen = u16::from_be_bytes(body[p..p + 2].try_into().unwrap()) as usize;
        let vlen = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if klen == 0 && vlen == 0 {
            break;
        }
        let key = std::str::from_utf8(&body[p..p + klen - 1])
            .unwrap()
            .to_string();
        p += klen;
        let val = std::str::from_utf8(&body[p..p + vlen - 1])
            .unwrap()
            .to_string();
        p += vlen;
        env.insert(key, val);
    }
    (env, p)
}

fn known_header_value(body: &[u8], env_end: usize, slot: usize) -> Option<String> {
    let unknown = read_i32_le(body, 24) as usize;
    let header_len = read_i32_le(body, 0) as usize;
    let pad = (8 - ((PACKET_HEADER_LEN + env_end) % 8)) % 8;
    let index_at = env_end + pad;
    let len_at = index_at + slot * 2;
    let len = u16::from_le_bytes(body[len_at..len_at + 2].try_into().unwrap()) as usize;
    if len == 0 {
        return None;
    }
    let off_at = index_at + KNOWN_HEADER_COUNT * 2 + 2 + slot * 4;
    let off = read_i32_le(body, off_at) as usize;
    let raw_at = index_at + HEADER_INDEX_LEN + unknown * 16;
    let raw = &body[raw_at..raw_at + header_len];
    Some(
        std::str::from_utf8(&raw[off..off + len])
            .unwrap()
            .to_string(),
    )
}

#[tokio::test]
async fn mock_lsphp_roundtrip() {
    let path = tmp_sock("mock");
    let listener = UnixListener::bind(&path).unwrap();

    // Fake lsphp: accept, read BEGIN_REQUEST, verify env, send RESP_*.
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, body) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);

        // Sanity: the env table should contain REQUEST_METHOD=GET. Find "GET\0".
        // (We just confirm the begin-request carried a non-trivial env body.)
        assert!(body.len() > 44, "begin request body should carry env");

        // Respond: header + two stream chunks + end.
        let mut out = BytesMut::new();
        let rh = resp_header_body(200, &[("Content-Type", "text/plain"), ("X-Test", "yes")]);
        put_packet(&mut out, PacketType::RespHeader, &rh);
        put_packet(&mut out, PacketType::RespStream, b"Hello, ");
        put_packet(&mut out, PacketType::RespStream, b"world!");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();
        // keep the conn briefly so the client can drain
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(100), s.read(&mut sink)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(2));

    let req = http::Request::builder()
        .method("GET")
        .uri("/index.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let mut c = ctx("/web/test");

    let resp = handler.handle(&mut c, req).await.expect("handle ok");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");
    assert_eq!(resp.headers().get("x-test").unwrap(), "yes");

    let (_p, body) = resp.into_parts();
    let bytes = match body {
        hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        // Small responses now take the inline fast path -> Body::Full.
        hj_core::Body::Full(b) => b,
        other => panic!(
            "unexpected body variant {:?}",
            std::mem::discriminant(&other)
        ),
    };
    assert_eq!(&bytes[..], b"Hello, world!");

    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn response_content_length_duplicates_are_normalized() {
    let (response, _) = buffered_mock_response(
        "response-cl-duplicates",
        "GET",
        200,
        &[("Content-Length", "3"), ("content-length", "3")],
        &[b"abc"],
    )
    .await;
    let response = response.expect("identical duplicate lengths are unambiguous");
    assert_eq!(
        response.headers().get_all("content-length").iter().count(),
        1
    );
    assert_eq!(response.headers()["content-length"], "3");
    let bytes = match response.into_body() {
        hj_core::Body::Full(bytes) => bytes,
        hj_core::Body::Stream(stream) => stream.collect().await.unwrap().to_bytes(),
        other => panic!("unexpected body: {:?}", std::mem::discriminant(&other)),
    };
    assert_eq!(&bytes[..], b"abc");
}

#[tokio::test]
async fn response_content_length_conflicts_and_malformed_values_are_rejected() {
    for (tag, headers) in [
        (
            "response-cl-conflict",
            vec![("Content-Length", "3"), ("Content-Length", "6")],
        ),
        ("response-cl-malformed", vec![("Content-Length", "+3")]),
        (
            "response-cl-comma-conflict",
            vec![("Content-Length", "3, 6")],
        ),
    ] {
        let (result, pool) = buffered_mock_response(tag, "GET", 200, &headers, &[b"abc"]).await;
        match result {
            Err(HandlerError::BadGateway(message)) => {
                assert!(message.contains("Content-Length"), "{message}")
            }
            Err(other) => panic!("unexpected handler error: {other}"),
            Ok(_) => panic!("invalid Content-Length should be rejected with 502"),
        }
        assert_eq!(
            pool.idle_count(),
            0,
            "invalid response must poison the socket"
        );
    }
}

#[tokio::test]
async fn body_forbidden_responses_do_not_enforce_representation_content_length() {
    for (tag, method, status) in [
        ("response-cl-head", "HEAD", 200),
        ("response-cl-not-modified", "GET", 304),
    ] {
        let (result, pool) =
            buffered_mock_response(tag, method, status, &[("Content-Length", "123")], &[]).await;
        let response = result.expect("body-forbidden response is not truncated");
        assert_eq!(response.status().as_u16(), status as u16);
        assert_eq!(response.headers()["content-length"], "123");
        let body = match response.into_body() {
            hj_core::Body::Full(bytes) => bytes,
            hj_core::Body::Stream(stream) => stream.collect().await.unwrap().to_bytes(),
            other => panic!("unexpected body: {:?}", std::mem::discriminant(&other)),
        };
        assert!(body.is_empty());
        assert_eq!(pool.idle_count(), 1, "clean LSAPI socket must be reusable");
    }
}

#[tokio::test]
async fn streamed_head_response_does_not_abort_on_representation_content_length() {
    let (body, pool) =
        streamed_mock_response("response-cl-head-stream", "HEAD", 200, "123", b"").await;
    assert!(body.expect("HEAD stream is not truncated").is_empty());
    assert_eq!(pool.idle_count(), 1, "clean LSAPI socket must be reusable");
}

#[tokio::test]
async fn buffered_response_content_length_caps_overflow_and_rejects_truncation() {
    let (over, pool) = buffered_mock_response(
        "response-cl-inline-over",
        "GET",
        200,
        &[("Content-Length", "3")],
        &[b"abcdef"],
    )
    .await;
    let response = over.expect("declared bytes remain a usable response");
    let bytes = match response.into_body() {
        hj_core::Body::Full(bytes) => bytes,
        other => panic!(
            "expected inline body, got {:?}",
            std::mem::discriminant(&other)
        ),
    };
    assert_eq!(&bytes[..], b"abc");
    assert_eq!(pool.idle_count(), 0, "over-delivery must poison the socket");

    let (under, pool) = buffered_mock_response(
        "response-cl-inline-under",
        "GET",
        200,
        &[("Content-Length", "6")],
        &[b"abc"],
    )
    .await;
    match under {
        Err(HandlerError::BadGateway(message)) => assert!(message.contains("truncated")),
        Err(other) => panic!("unexpected handler error: {other}"),
        Ok(_) => panic!("short inline response should be rejected with 502"),
    }
    assert_eq!(pool.idle_count(), 0);
}

#[tokio::test]
async fn streamed_response_content_length_caps_overflow_and_aborts_truncation() {
    let (over, pool) =
        streamed_mock_response("response-cl-stream-over", "GET", 200, "3", b"abcdef").await;
    assert_eq!(&over.expect("declared bytes should complete")[..], b"abc");
    assert_eq!(pool.idle_count(), 0, "over-delivery must poison the socket");

    let (under, pool) =
        streamed_mock_response("response-cl-stream-under", "GET", 200, "6", b"abc").await;
    assert!(
        under.is_err(),
        "short stream must surface a truncated-body error"
    );
    assert_eq!(pool.idle_count(), 0);
}

async fn assert_pre_header_terminator_is_bad_gateway(ptype: PacketType, tag: &str) {
    let path = tmp_sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (begin_type, _) = read_packet(&mut s).await.unwrap();
        assert_eq!(begin_type, PacketType::BeginRequest as u8);
        let mut out = BytesMut::new();
        put_packet(&mut out, ptype, b"");
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2));
    let req = http::Request::builder()
        .method("GET")
        .uri("/index.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let mut c = ctx("/web/test");

    let result = tokio::time::timeout(Duration::from_millis(250), handler.handle(&mut c, req))
        .await
        .expect("pre-header terminator must fail immediately");
    match result {
        Err(HandlerError::BadGateway(message)) => {
            assert!(message.contains("ended before headers"));
        }
        Err(other) => panic!("expected BadGateway, got {other:?}"),
        Ok(_) => panic!("pre-header terminator must not fabricate a response"),
    }
    assert_eq!(pool.idle_count(), 0, "failed connection must not re-pool");

    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn resp_end_before_headers_is_bad_gateway() {
    assert_pre_header_terminator_is_bad_gateway(PacketType::RespEnd, "early-end").await;
}

#[tokio::test]
async fn conn_close_before_headers_is_bad_gateway() {
    assert_pre_header_terminator_is_bad_gateway(PacketType::ConnClose, "early-close").await;
}

#[tokio::test]
async fn chunked_upload_synthesizes_content_length_for_env_and_header_index() {
    let path = tmp_sock("chunked-cl");
    let listener = UnixListener::bind(&path).unwrap();

    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, body) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        assert_eq!(
            read_i32_le(&body, 4),
            7,
            "m_reqBodyLen must be concrete for buffered uploads"
        );
        let (env, env_end) = parse_begin_env(&body);
        assert_eq!(env.get("CONTENT_LENGTH").map(String::as_str), Some("7"));
        assert_eq!(known_header_value(&body, env_end, 7).as_deref(), Some("7"));
        let mut uploaded = [0u8; 7];
        s.read_exact(&mut uploaded).await.unwrap();
        assert_eq!(&uploaded, b"abcdefg");

        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[("Content-Type", "text/plain")]),
        );
        put_packet(&mut out, PacketType::RespStream, b"ok");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(2));
    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .body(full_incoming(b"abcdefg"))
        .unwrap();
    let mut c = ctx("/web/test");
    let resp = handler
        .handle(&mut c, req)
        .await
        .expect("chunked-style upload ok");
    assert_eq!(resp.status(), 200);
    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn bodyless_get_without_content_length_gets_no_synthetic_length() {
    let path = tmp_sock("get-no-cl");
    let listener = UnixListener::bind(&path).unwrap();

    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, body) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        assert_eq!(read_i32_le(&body, 4), 0);
        let (env, env_end) = parse_begin_env(&body);
        assert!(!env.contains_key("CONTENT_LENGTH"), "{env:?}");
        assert!(!env.contains_key("HTTP_CONTENT_LENGTH"), "{env:?}");
        assert_eq!(known_header_value(&body, env_end, 7), None);

        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[("Content-Type", "text/plain")]),
        );
        put_packet(&mut out, PacketType::RespStream, b"ok");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(2));
    let req = http::Request::builder()
        .method("GET")
        .uri("/t.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let mut c = ctx("/web/test");
    let resp = handler.handle(&mut c, req).await.expect("get ok");
    assert_eq!(resp.status(), 200);
    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

/// PR-2 STALE-REUSE RETRY: a REUSED keep-alive socket that lsphp resets *before
/// any response byte* must, for an idempotent (GET) request, be retried once on a
/// fresh dial — not surfaced as a 502. The mock serves request #1 fully (pooling
/// the socket), then on request #2 reads BEGIN_REQUEST on the SAME socket and dies
/// without responding; the fresh dial (#2) then answers successfully.
#[tokio::test]
async fn stale_reused_socket_reset_retries_idempotent_get() {
    let path = tmp_sock("stale-retry");
    let listener = UnixListener::bind(&path).unwrap();

    let server_task = tokio::spawn(async move {
        // Connection #1: serve req #1, then on req #2 die before responding.
        let (mut s1, _) = listener.accept().await.unwrap();
        let (p1, _b1) = read_packet(&mut s1).await.unwrap();
        assert_eq!(p1, PacketType::BeginRequest as u8);
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[("X-Try", "1")]),
        );
        put_packet(&mut out, PacketType::RespStream, b"ok1");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s1.write_all(&out).await.unwrap();
        s1.flush().await.unwrap();
        // req #2 reuses the pooled socket: read BEGIN_REQUEST then DROP without
        // responding (the TOCTOU the pool probe cannot catch).
        let (p2, _b2) = read_packet(&mut s1).await.unwrap();
        assert_eq!(p2, PacketType::BeginRequest as u8);
        drop(s1);
        // Connection #2: the retry's fresh dial — answer successfully.
        let (mut s2, _) = listener.accept().await.unwrap();
        let (p3, _b3) = read_packet(&mut s2).await.unwrap();
        assert_eq!(p3, PacketType::BeginRequest as u8);
        let mut out2 = BytesMut::new();
        put_packet(
            &mut out2,
            PacketType::RespHeader,
            &resp_header_body(200, &[("X-Try", "2")]),
        );
        put_packet(&mut out2, PacketType::RespStream, b"ok2");
        put_packet(&mut out2, PacketType::RespEnd, b"");
        s2.write_all(&out2).await.unwrap();
        s2.flush().await.unwrap();
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(100), s2.read(&mut sink)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2));
    let mut c = ctx("/web/test");

    // Request #1 (GET): pools the keep-alive socket.
    let req1 = http::Request::builder()
        .method("GET")
        .uri("/a.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let resp1 = handler.handle(&mut c, req1).await.expect("req1 ok");
    let body1 = match resp1.into_parts().1 {
        hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        hj_core::Body::Full(b) => b,
        _ => panic!("stream or full"),
    };
    assert_eq!(&body1[..], b"ok1");

    // Wait for conn #1 to be re-pooled as idle so request #2 REUSES it.
    for _ in 0..200 {
        if pool.idle_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        pool.idle_count(),
        1,
        "conn #1 must be pooled before the retry"
    );

    // Request #2 (GET): reuses conn #1 (which resets pre-response) → must RETRY on a
    // fresh dial and return the fresh worker's "ok2", not a 502.
    let req2 = http::Request::builder()
        .method("GET")
        .uri("/b.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let resp2 = handler
        .handle(&mut c, req2)
        .await
        .expect("req2 must SUCCEED via stale-reuse retry");
    assert_eq!(resp2.status(), 200);
    assert_eq!(resp2.headers().get("x-try").unwrap(), "2");
    let body2 = match resp2.into_parts().1 {
        hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        hj_core::Body::Full(b) => b,
        _ => panic!("stream or full"),
    };
    assert_eq!(
        &body2[..],
        b"ok2",
        "retry must serve the fresh worker's response"
    );

    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

/// RECYCLE-BURST: when the FIRST retry's fresh dial ALSO resets pre-response (the
/// pool still mid-respawn), the handler must retry a SECOND time on another fresh
/// dial before giving up — surviving a burst, not just a single stale socket.
#[tokio::test]
async fn idempotent_reset_retries_twice_then_third_dial_succeeds() {
    let path = tmp_sock("burst-retry");
    let listener = UnixListener::bind(&path).unwrap();

    let server_task = tokio::spawn(async move {
        // conn#1: serve req#1 fully (pools the socket), then reset on req#2.
        let (mut s1, _) = listener.accept().await.unwrap();
        let _ = read_packet(&mut s1).await.unwrap();
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[]),
        );
        put_packet(&mut out, PacketType::RespStream, b"ok1");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s1.write_all(&out).await.unwrap();
        s1.flush().await.unwrap();
        let _ = read_packet(&mut s1).await.unwrap(); // req#2 BEGIN_REQUEST (reused)
        drop(s1); // reset #1
        // retry #1 → conn#2 (fresh dial): read BEGIN_REQUEST then reset.
        let (mut s2, _) = listener.accept().await.unwrap();
        let _ = read_packet(&mut s2).await.unwrap();
        drop(s2); // reset #2
        // retry #2 → conn#3 (fresh dial): succeed.
        let (mut s3, _) = listener.accept().await.unwrap();
        let _ = read_packet(&mut s3).await.unwrap();
        let mut out3 = BytesMut::new();
        put_packet(
            &mut out3,
            PacketType::RespHeader,
            &resp_header_body(200, &[("X-Try", "3")]),
        );
        put_packet(&mut out3, PacketType::RespStream, b"ok3");
        put_packet(&mut out3, PacketType::RespEnd, b"");
        s3.write_all(&out3).await.unwrap();
        s3.flush().await.unwrap();
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(100), s3.read(&mut sink)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2));
    let mut c = ctx("/web/test");

    let req1 = http::Request::builder()
        .method("GET")
        .uri("/a.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let r1 = handler.handle(&mut c, req1).await.expect("req1 ok");
    if let hj_core::Body::Stream(s) = r1.into_parts().1 {
        let _ = s.collect().await;
    }
    for _ in 0..200 {
        if pool.idle_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(pool.idle_count(), 1, "conn#1 pooled before the burst test");

    // req#2: reuse resets (conn#1) → retry#1 resets (conn#2) → retry#2 succeeds (conn#3).
    let req2 = http::Request::builder()
        .method("GET")
        .uri("/b.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let resp2 = handler
        .handle(&mut c, req2)
        .await
        .expect("req2 must SUCCEED after TWO retries");
    assert_eq!(resp2.status(), 200);
    assert_eq!(resp2.headers().get("x-try").unwrap(), "3");
    let body2 = match resp2.into_parts().1 {
        hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        hj_core::Body::Full(b) => b,
        _ => panic!("stream or full"),
    };
    assert_eq!(
        &body2[..],
        b"ok3",
        "the second retry's fresh worker response"
    );

    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

/// PR-2 NON-IDEMPOTENT: a POST whose REUSED socket resets pre-response must NOT be
/// retried (the backend may have begun processing it) — it surfaces an error and
/// the handler does NOT dial a second connection.
#[tokio::test]
async fn non_idempotent_reused_reset_does_not_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let path = tmp_sock("stale-post");
    let listener = UnixListener::bind(&path).unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts2 = accepts.clone();

    let server_task = tokio::spawn(async move {
        // Connection #1: serve a GET to pool the socket, then reset on the POST.
        let (mut s1, _) = listener.accept().await.unwrap();
        accepts2.fetch_add(1, Ordering::SeqCst);
        let _ = read_packet(&mut s1).await.unwrap();
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[]),
        );
        put_packet(&mut out, PacketType::RespStream, b"ok1");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s1.write_all(&out).await.unwrap();
        s1.flush().await.unwrap();
        // req #2 (POST, empty body → buffered path): read BEGIN_REQUEST then die.
        let _ = read_packet(&mut s1).await.unwrap();
        drop(s1);
        // A retry would dial a SECOND connection — detect it (and must NOT happen).
        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await
        {
            accepts2.fetch_add(1, Ordering::SeqCst);
        }
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2));
    let mut c = ctx("/web/test");

    // Request #1 (GET): pools the socket.
    let req1 = http::Request::builder()
        .method("GET")
        .uri("/a.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let r1 = handler.handle(&mut c, req1).await.expect("req1 ok");
    if let hj_core::Body::Stream(s) = r1.into_parts().1 {
        let _ = s.collect().await;
    }
    for _ in 0..200 {
        if pool.idle_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        pool.idle_count(),
        1,
        "conn #1 must be pooled before the POST"
    );

    // Request #2 (POST): reuses conn #1, which resets — must NOT retry → error.
    let req2 = http::Request::builder()
        .method("POST")
        .uri("/b.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    match handler.handle(&mut c, req2).await {
        Err(_) => {}
        Ok(_) => panic!("non-idempotent POST must not retry to success"),
    }
    let _ = server_task.await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "a non-idempotent request must NOT dial a second (retry) connection"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn get_with_body_reused_reset_does_not_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let path = tmp_sock("stale-get-body");
    let listener = UnixListener::bind(&path).unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts2 = accepts.clone();

    let server_task = tokio::spawn(async move {
        let (mut s1, _) = listener.accept().await.unwrap();
        accepts2.fetch_add(1, Ordering::SeqCst);
        let _ = read_packet(&mut s1).await.unwrap();
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[]),
        );
        put_packet(&mut out, PacketType::RespStream, b"ok1");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s1.write_all(&out).await.unwrap();
        s1.flush().await.unwrap();

        let (_ptype, body) = read_packet(&mut s1).await.unwrap();
        let body_len = read_i32_le(&body, 4) as usize;
        assert_eq!(body_len, 4);
        let mut uploaded = [0u8; 4];
        s1.read_exact(&mut uploaded).await.unwrap();
        assert_eq!(&uploaded, b"body");
        drop(s1);
        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await
        {
            accepts2.fetch_add(1, Ordering::SeqCst);
        }
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2));
    let mut c = ctx("/web/test");

    let req1 = http::Request::builder()
        .method("GET")
        .uri("/a.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let r1 = handler.handle(&mut c, req1).await.expect("req1 ok");
    if let hj_core::Body::Stream(s) = r1.into_parts().1 {
        let _ = s.collect().await;
    }
    for _ in 0..200 {
        if pool.idle_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        pool.idle_count(),
        1,
        "conn #1 must be pooled before the GET body request"
    );

    let req2 = http::Request::builder()
        .method("GET")
        .uri("/b.php")
        .header("Host", "test")
        .body(full_incoming(b"body"))
        .unwrap();
    assert!(
        handler.handle(&mut c, req2).await.is_err(),
        "GET with a body must not retry to success after a reset"
    );
    let _ = server_task.await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "GET with a body must NOT dial a second replay connection"
    );
    let _ = std::fs::remove_file(&path);
}

/// A supervisor in the `Bad` (backoff) state must make the handler fail FAST
/// with 503 (ServiceUnavailable) rather than dialing a worker that just failed.
///
/// We reach `Bad` deterministically: `restart_debounced()` against a NON-EXISTENT
/// command fails the spawn, and its failure path sets the worker `Bad`.
#[tokio::test]
async fn bad_supervisor_returns_503_fast() {
    let sock = tmp_sock("bad-sup");
    let cfg = SupervisorConfig {
        command: PathBuf::from("/nonexistent/lsphp-does-not-exist-xyz"),
        socket_path: sock.clone(),
        children: 1,
        max_requests: 0,
        env: vec![],
        backlog: 8,
        user: String::new(),
        group: String::new(),
        start_timeout: Duration::from_millis(50),
        limits: Default::default(),
        // Long window (but under the fresh-supervisor 1h last_restart offset, so
        // the FIRST restart still proceeds) so the monitor's recovery attempt is
        // a debounce no-op and the worker stays Bad for the lifetime of the test.
        min_restart_interval: Duration::from_secs(1800),
        max_restart_backoff: Duration::from_secs(30),
        jail: Default::default(),
        socket_source: Default::default(),
        retry_timeout: Duration::ZERO,
    };
    let sup = Arc::new(LsphpSupervisor::new(cfg));
    // restart_debounced sets Starting, drains (no child), then start() — whose
    // spawn fails for the missing binary — and its Err path sets Bad.
    let _ = sup.restart_debounced().await;
    assert_eq!(
        sup.state(),
        WorkerState::Bad,
        "missing command must leave Bad"
    );

    // Bad supervisor: the handler must 503 BEFORE touching the pool.
    let pool = Arc::new(LsapiPool::new(&sock, 2, Duration::from_millis(50)));
    let mon_cfg = MonitorConfig::new(sup.clone(), pool.clone());
    let (monitor, ticker) = Monitor::spawn(mon_cfg);
    let token = monitor.cancel_token();
    let handler = Lsapi::new(pool).monitor(monitor);

    let req = http::Request::builder()
        .uri("/index.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let mut c = ctx("/web/test");
    match handler.handle(&mut c, req).await {
        Err(HandlerError::ServiceUnavailable) => {}
        Err(other) => panic!("expected ServiceUnavailable (503), got {other:?}"),
        Ok(_) => panic!("expected 503, got a response"),
    }

    token.cancel();
    let _ = ticker.await;
    let _ = sup.drain().await;
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test]
async fn queued_request_is_not_counted_in_flight() {
    // #47 (part 1): the Tier-2 in-flight clock must start when the request is COMMITTED to
    // lsphp (after pool.acquire), NOT at handler entry. A request blocked in pool.acquire()
    // (no free slot) is merely queued — not being processed by a worker — and must NOT be
    // counted, else a pool-acquire backlog could make the monitor SIGKILL a healthy worker.
    // We hold the pool's only permit, fire a request (which then blocks in acquire), and assert
    // inflight().len()==0 while it is queued. Pre-fix the guard was begun at handler entry, so
    // len() would be 1 here.
    let path = tmp_sock("inflight-queue");
    let p2 = path.clone();
    let server = tokio::spawn(async move {
        let listener = UnixListener::bind(&p2).unwrap();
        // Accept the connection backing the manually-held permit; just hold it open.
        let (_held, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    // A fresh (NotStarted, never-started) supervisor is NOT Bad, so the handler proceeds to
    // acquire instead of fast-failing 503. Cancel the ticker immediately so on_tick never tries
    // to start the dummy command (which would flip the supervisor to Bad). Current-thread test
    // runtime => the ticker is not polled until our next await, by which point it is cancelled.
    let sup = Arc::new(LsphpSupervisor::new(SupervisorConfig {
        command: PathBuf::from("/nonexistent/lsphp-xyz"),
        socket_path: path.clone(),
        children: 1,
        max_requests: 0,
        env: vec![],
        backlog: 8,
        user: String::new(),
        group: String::new(),
        start_timeout: Duration::from_millis(50),
        limits: Default::default(),
        min_restart_interval: Duration::from_secs(1800),
        max_restart_backoff: Duration::from_secs(30),
        jail: Default::default(),
        socket_source: Default::default(),
        retry_timeout: Duration::ZERO,
    }));
    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(5)));
    let (monitor, ticker) = Monitor::spawn(MonitorConfig::new(sup.clone(), pool.clone()));
    let token = monitor.cancel_token();
    token.cancel();
    let inflight = monitor.inflight();
    let handler = Arc::new(
        Lsapi::new(pool.clone())
            .monitor(monitor)
            .read_timeout(Duration::from_secs(5)),
    );

    // Hold the only permit; with max_conns=1 the request below blocks in acquire().
    let held = pool.acquire().await.expect("hold the only permit");
    assert_eq!(inflight.len(), 0, "nothing committed to lsphp yet");

    let h = handler.clone();
    let req_task = tokio::spawn(async move {
        let req = http::Request::builder()
            .method("GET")
            .uri("/index.php")
            .header("Host", "test")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx("/web/test");
        h.handle(&mut c, req).await
    });

    // Let the request reach (and block in) pool.acquire().
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(
        inflight.len(),
        0,
        "#47p1: a request queued for a pool slot must NOT be counted in-flight"
    );

    // The invariant is verified; cancel the queued request and release the permit.
    req_task.abort();
    let _ = req_task.await;
    drop(held);
    let _ = ticker.await;
    let _ = server.await;
    let _ = sup.drain().await;
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn mock_lsphp_status_header_overrides_status() {
    let path = tmp_sock("status");
    let listener = UnixListener::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ = read_packet(&mut s).await.unwrap();
        let mut out = BytesMut::new();
        // PHP emits its status via a "Status:" header; resp_info status is 200.
        let rh = resp_header_body(
            200,
            &[("Status", "404 Not Found"), ("Content-Type", "text/html")],
        );
        put_packet(&mut out, PacketType::RespHeader, &rh);
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        let mut sink = [0u8; 8];
        let _ = tokio::time::timeout(Duration::from_millis(100), s.read(&mut sink)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 2, Duration::from_secs(2)));
    let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(2));
    let req = http::Request::builder()
        .uri("/missing.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let mut c = ctx("/web/test");
    let resp = handler.handle(&mut c, req).await.expect("handle ok");
    assert_eq!(resp.status(), 404);
    assert!(
        resp.headers().get("status").is_none(),
        "Status header must be consumed"
    );
    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

/// Regression (#668): a 1xx can never be the final response.
#[tokio::test]
async fn mock_lsphp_informational_final_status_is_bad_gateway() {
    for (resp_status, headers) in [(102, &[][..]), (200, &[("Status", "100 Continue")][..])] {
        let path = tmp_sock("info-status");
        let listener = UnixListener::bind(&path).unwrap();
        let server_task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_packet(&mut s).await.unwrap();
            let mut out = BytesMut::new();
            put_packet(
                &mut out,
                PacketType::RespHeader,
                &resp_header_body(resp_status, headers),
            );
            put_packet(&mut out, PacketType::RespStream, b"body");
            put_packet(&mut out, PacketType::RespEnd, b"");
            s.write_all(&out).await.unwrap();
            let mut sink = [0u8; 8];
            let _ = tokio::time::timeout(Duration::from_millis(100), s.read(&mut sink)).await;
        });
        let pool = Arc::new(LsapiPool::new(&path, 2, Duration::from_secs(2)));
        let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(2));
        let req = http::Request::builder()
            .uri("/early.php")
            .header("Host", "test")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx("/web/test");
        match handler.handle(&mut c, req).await {
            Err(HandlerError::BadGateway(_)) => {}
            Err(other) => panic!("expected BadGateway, got {other:?}"),
            Ok(resp) => panic!("expected BadGateway, got {}", resp.status()),
        }
        server_task.await.unwrap();
        let _ = std::fs::remove_file(&path);
    }
}

/// Read the concrete `m_reqBodyLen` (field[1], LE i32) out of a BEGIN_REQUEST
/// packet body. This is the exact count of raw body bytes lsphp will read off the
/// socket after the packet, so the mock uses it to drain exactly the body.
fn req_body_len_from_begin(body: &[u8]) -> i32 {
    // body offset 0 == m_httpHeaderLen, offset 4 == m_reqBodyLen.
    i32::from_le_bytes([body[4], body[5], body[6], body[7]])
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetainedHeadMarker(&'static str);

async fn retained_head_roundtrip(tag: &str, declare_content_length: bool) {
    let path = tmp_sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (ptype, begin) = read_packet(&mut stream).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let body_len = req_body_len_from_begin(&begin);
        assert_eq!(body_len, 3, "lsphp must receive a concrete body length");
        let mut body = vec![0; body_len as usize];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, b"abc");

        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(204, &[]),
        );
        put_packet(&mut out, PacketType::RespEnd, b"");
        stream.write_all(&out).await.unwrap();
        stream.flush().await.unwrap();
    });

    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(2)));
    let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(2));
    let mut request = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("X-Retained", "original")
        .body(full_incoming(b"abc"))
        .unwrap();
    if declare_content_length {
        request.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("3"),
        );
    }
    request
        .extensions_mut()
        .insert(RetainedHeadMarker("original"));

    let (result, parts) = handler
        .handle_retaining_head(&mut ctx("/web/test"), request)
        .await;
    assert_eq!(result.expect("dispatch succeeds").status(), 204);
    assert_eq!(parts.method, http::Method::POST);
    assert_eq!(parts.uri.path(), "/upload.php");
    assert_eq!(parts.headers.get("x-retained").unwrap(), "original");
    assert_eq!(
        parts.extensions.get::<RetainedHeadMarker>(),
        Some(&RetainedHeadMarker("original"))
    );
    assert_eq!(
        parts.headers.contains_key(http::header::CONTENT_LENGTH),
        declare_content_length,
        "buffering may synthesize Content-Length on the LSAPI wire but must not mutate the retained head"
    );

    server_task.await.unwrap();
    let _ = std::fs::remove_file(path);
}

/// The known-length path moves the original body into the socket pump while
/// returning the untouched request head for post-dispatch policy.
#[tokio::test]
async fn streaming_dispatch_returns_original_request_head() {
    retained_head_roundtrip("retain-stream-head", true).await;
}

/// The unknown-length path buffers to learn LSAPI's concrete length but still
/// returns the original head rather than the synthesized wire view.
#[tokio::test]
async fn buffered_dispatch_returns_original_request_head() {
    retained_head_roundtrip("retain-buffered-head", false).await;
}

/// FNV-1a 64-bit, used to fingerprint the received body so the assertions don't
/// depend on echoing megabytes back.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Build a genuinely multi-frame streaming request body (NOT a single `Bytes`):
/// a `Channel` body fed `chunk_count` chunks of `chunk` from a spawned task.
/// Returns the body plus the full bytes it will yield (for the expected hash).
fn streaming_body(chunk: &[u8], chunk_count: usize) -> (hj_core::IncomingBody, Vec<u8>) {
    let (mut tx, channel) = Channel::<Bytes, hj_core::BoxError>::new(64 * 1024);
    let chunk = Bytes::copy_from_slice(chunk);
    let mut full = Vec::with_capacity(chunk.len() * chunk_count);
    for _ in 0..chunk_count {
        full.extend_from_slice(&chunk);
    }
    tokio::spawn(async move {
        for _ in 0..chunk_count {
            if tx.send_data(chunk.clone()).await.is_err() {
                return;
            }
        }
        // Dropping tx ends the body cleanly.
    });
    (BoxBody::new(channel), full)
}

/// STREAMING PATH: POST a multi-megabyte body delivered as a streaming `Body`.
/// The mock reads BEGIN_REQUEST, drains EXACTLY `m_reqBodyLen` raw body bytes off
/// the socket, then echoes the observed length + FNV hash back in the response.
#[tokio::test]
async fn mock_lsphp_streams_multimegabyte_body() {
    let path = tmp_sock("stream-big");
    let listener = UnixListener::bind(&path).unwrap();

    // 4 MiB body, delivered as 4096 separate 1 KiB frames.
    let chunk = vec![0xABu8; 1024];
    let chunk_count = 4096;
    let (body, full) = streaming_body(&chunk, chunk_count);
    let expected_len = full.len();
    let expected_hash = fnv1a(&full);

    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, begin) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let body_len = req_body_len_from_begin(&begin);
        assert!(body_len >= 0, "concrete length expected, got {body_len}");

        // Drain EXACTLY body_len raw body bytes that follow the packet.
        let mut got = vec![0u8; body_len as usize];
        s.read_exact(&mut got).await.unwrap();
        let got_hash = fnv1a(&got);

        // Echo length + hash back so the client can assert the full byte count.
        let mut out = BytesMut::new();
        let rh = resp_header_body(200, &[("Content-Type", "text/plain")]);
        put_packet(&mut out, PacketType::RespHeader, &rh);
        let report = format!("len={};hash={:016x}", got.len(), got_hash);
        put_packet(&mut out, PacketType::RespStream, report.as_bytes());
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(200), s.read(&mut sink)).await;
        (body_len, got_hash)
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(5)));
    let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(5));

    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", expected_len.to_string())
        .body(body)
        .unwrap();
    let mut c = ctx("/web/test");

    let resp = handler.handle(&mut c, req).await.expect("handle ok");
    assert_eq!(resp.status(), 200);

    let (_p, rbody) = resp.into_parts();
    let bytes = match rbody {
        hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        // Small responses now take the inline fast path -> Body::Full.
        hj_core::Body::Full(b) => b,
        other => panic!(
            "unexpected body variant {:?}",
            std::mem::discriminant(&other)
        ),
    };
    let report = String::from_utf8_lossy(&bytes);
    assert_eq!(
        report,
        format!("len={};hash={:016x}", expected_len, expected_hash),
        "mock must observe the full streamed byte count + matching hash"
    );

    let (observed_len, observed_hash) = server_task.await.unwrap();
    assert_eq!(observed_len as usize, expected_len);
    assert_eq!(observed_hash, expected_hash);
    let _ = std::fs::remove_file(&path);
}

/// Regression (#806): a BUFFERED (no Content-Length) upload larger than the socket
/// buffers, sent to a script that writes a large response before reading its input,
/// must not deadlock. The mock writes its output first, then drains the body.
/// Before the fix the handler wrote the whole body before reading any response and
/// both sides blocked until the read timeout (a 502). The body exceeds even a large
/// host `net.core.wmem_default` (30 MiB on the build box), and the mock's own send
/// buffer is shrunk so its output write blocks too.
#[tokio::test]
async fn buffered_large_body_with_large_output_is_full_duplex() {
    let path = tmp_sock("buffered-duplex");
    let listener = UnixListener::bind(&path).unwrap();
    let chunk = vec![0x5Au8; 1024];
    let (body, full) = streaming_body(&chunk, 40 * 1024);
    let expected_len = full.len();
    drop(full);
    let output = vec![b'o'; 2 * 1024 * 1024];
    let output_len = output.len();

    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        rustix::net::sockopt::set_socket_send_buffer_size(&s, 64 * 1024).unwrap();
        let (ptype, begin) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let body_len = req_body_len_from_begin(&begin);
        assert_eq!(
            body_len as usize, expected_len,
            "buffered length is concrete"
        );

        let mut out = BytesMut::new();
        let rh = resp_header_body(200, &[("Content-Type", "text/plain")]);
        put_packet(&mut out, PacketType::RespHeader, &rh);
        for piece in output.chunks(32 * 1024) {
            put_packet(&mut out, PacketType::RespStream, piece);
        }
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();

        let mut got = vec![0u8; body_len as usize];
        s.read_exact(&mut got).await.unwrap();
        assert!(got.iter().all(|&b| b == 0x5A), "body bytes arrive intact");
        let mut end = BytesMut::new();
        put_packet(&mut end, PacketType::RespEnd, b"");
        s.write_all(&end).await.unwrap();
        s.flush().await.unwrap();
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(200), s.read(&mut sink)).await;
        got.len()
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(5)));
    let handler = Lsapi::new(pool)
        .read_timeout(Duration::from_secs(5))
        .max_body(64 * 1024 * 1024);
    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .unwrap();
    let mut c = ctx("/web/test");

    let started = std::time::Instant::now();
    let bytes = tokio::time::timeout(Duration::from_secs(4), async {
        let resp = handler.handle(&mut c, req).await.expect("handle ok");
        assert_eq!(resp.status(), 200);
        match resp.into_body() {
            hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
            hj_core::Body::Full(b) => b,
            other => panic!(
                "unexpected body variant {:?}",
                std::mem::discriminant(&other)
            ),
        }
    })
    .await
    .expect("buffered upload + large response must not deadlock");
    assert_eq!(bytes.len(), output_len);
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(server_task.await.unwrap(), expected_len);
    let _ = std::fs::remove_file(&path);
}

/// EARLY 413: a declared Content-Length over the cap must be rejected BEFORE any
/// pool acquire (the listener never sees a connection).
#[tokio::test]
async fn declared_content_length_over_cap_is_early_413() {
    let path = tmp_sock("early413");
    let listener = UnixListener::bind(&path).unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let accepted2 = accepted.clone();
    let server_task = tokio::spawn(async move {
        // If the handler ever acquires a connection, we flip the flag.
        if tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_ok()
        {
            accepted2.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    // Cap the handler at 1 MiB; declare 8 MiB.
    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool)
        .max_body(1024 * 1024)
        .read_timeout(Duration::from_secs(2));

    // Use a streaming body that would block forever if read — proving the handler
    // returns before reading or connecting. Keep `_tx` alive so the channel body
    // simply stalls rather than ending.
    let (_tx, channel) = Channel::<Bytes, hj_core::BoxError>::new(8);
    let body: hj_core::IncomingBody = BoxBody::new(channel);
    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Length", (8 * 1024 * 1024).to_string())
        .body(body)
        .unwrap();
    let mut c = ctx("/web/test");

    match handler.handle(&mut c, req).await {
        Err(HandlerError::PayloadTooLarge) => {}
        Err(other) => panic!("expected PayloadTooLarge, got {other:?}"),
        Ok(_) => panic!("expected PayloadTooLarge, got a response"),
    }

    // Give the listener its full window to (not) accept.
    let _ = server_task.await;
    assert!(
        !accepted.load(std::sync::atomic::Ordering::SeqCst),
        "early 413 must NOT acquire a pooled connection"
    );
    let _ = std::fs::remove_file(&path);
}

/// MID-STREAM OVER-DELIVERY: a streaming body that sends MORE than the declared
/// Content-Length must be capped at the declared length and the connection
/// abandoned — the writer shuts the write half down (so lsphp's raw body read
/// returns short) and poisons the conn so it is NEVER re-pooled. Critically, the
/// mock must NOT receive any surplus bytes beyond the declared length, and must
/// NOT see an ABORT_REQUEST control frame spliced into the raw body (lsphp would
/// read such a frame as body content and has no ABORT consumer — see
/// vendor/lsapilib.c).
#[tokio::test]
async fn streaming_body_over_delivery_caps_and_does_not_repool() {
    let path = tmp_sock("midcap");
    let listener = UnixListener::bind(&path).unwrap();

    // The mock reads BEGIN_REQUEST (which declares the concrete m_reqBodyLen),
    // then reads RAW body bytes until the socket's write direction closes (EOF).
    // It records how many body bytes it saw and whether any LSAPI control-frame
    // magic ("LS" + type 1/2/...) appeared in the raw body stream.
    let observed = Arc::new(std::sync::Mutex::new((0usize, 0i32, false)));
    let observed2 = observed.clone();
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, begin) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let declared = req_body_len_from_begin(&begin);
        let mut acc = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_secs(3), s.read(&mut tmp)).await {
                Ok(Ok(0)) | Err(_) => break, // write half shut down (EOF) -> done
                Ok(Ok(n)) => acc.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
            }
        }
        // Any LSAPI packet header in the RAW body stream would be protocol
        // corruption (these bytes are read by PHP as body content, not frames).
        let has_lsapi_frame = acc
            .windows(3)
            .any(|w| w[0] == b'L' && w[1] == b'S' && (1..=9).contains(&w[2]));
        *observed2.lock().unwrap() = (acc.len(), declared, has_lsapi_frame);
    });

    // Cap at 64 KiB; declare 32 KiB; the body over-delivers ~256 KiB.
    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(3)));
    let handler = Lsapi::new(pool)
        .max_body(64 * 1024)
        .read_timeout(Duration::from_secs(3));

    let chunk = vec![0x5Au8; 16 * 1024];
    let chunk_count = 16; // 256 KiB actual
    let (body, _full) = streaming_body(&chunk, chunk_count);
    let declared_len = 32 * 1024usize;
    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Length", declared_len.to_string())
        .body(body)
        .unwrap();
    let mut c = ctx("/web/test");

    // The mock never sends RESP_HEADER, so the response reader sees EOF/close
    // after the writer shuts down + poisons -> an error. That is expected; the
    // KEY assertions are on the mock's observations and that the conn is dropped.
    let result = handler.handle(&mut c, req).await;
    match result {
        Ok(resp) => {
            let (_p, rbody) = resp.into_parts();
            if let hj_core::Body::Stream(s) = rbody {
                let _ = s.collect().await;
            }
        }
        Err(_e) => { /* expected: upstream closed before headers */ }
    }

    let _ = server_task.await;
    let (body_bytes_seen, declared, has_lsapi_frame) = *observed.lock().unwrap();
    assert_eq!(
        declared, declared_len as i32,
        "BEGIN_REQUEST declares the concrete length"
    );
    assert!(
        body_bytes_seen <= declared_len,
        "writer must NOT over-deliver past the declared length (saw {body_bytes_seen}, declared {declared_len})"
    );
    assert!(
        !has_lsapi_frame,
        "no LSAPI control frame (e.g. ABORT_REQUEST) may be spliced into the raw body stream"
    );
    let _ = std::fs::remove_file(&path);
}

/// UNDER-DELIVERY: a client that declares Content-Length: N but streams fewer
/// than N bytes and then ends the stream must NOT leave a re-poolable socket.
/// The writer detects the short body, shuts the write half down, and poisons.
#[tokio::test]
async fn streaming_body_under_delivery_does_not_repool() {
    let path = tmp_sock("under");
    let listener = UnixListener::bind(&path).unwrap();

    let observed = Arc::new(std::sync::Mutex::new((0usize, 0i32)));
    let observed2 = observed.clone();
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, begin) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let declared = req_body_len_from_begin(&begin);
        // Read the (short) body until the write half is shut down (EOF).
        let mut acc = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_secs(3), s.read(&mut tmp)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => acc.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
            }
        }
        *observed2.lock().unwrap() = (acc.len(), declared);
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(3)));
    let pool_probe = pool.clone();
    let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(2));

    // Declare 64 KiB but only deliver 16 KiB, then end the stream.
    let chunk = vec![0x33u8; 16 * 1024];
    let (body, full) = streaming_body(&chunk, 1); // 16 KiB actual
    let declared_len = 64 * 1024usize;
    assert!(full.len() < declared_len);
    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Length", declared_len.to_string())
        .body(body)
        .unwrap();
    let mut c = ctx("/web/test");

    // No RESP_HEADER from the mock -> the response reader errors after EOF.
    let _ = handler.handle(&mut c, req).await;

    let _ = server_task.await;
    let (seen, declared) = *observed.lock().unwrap();
    assert_eq!(declared, declared_len as i32);
    assert!(
        seen <= declared_len,
        "short body should write at most the declared length"
    );
    // The desynced socket must NOT be returned to the idle pool.
    assert_eq!(
        pool_probe.idle_count(),
        0,
        "an under-delivered (short) body must poison the connection, not re-pool it"
    );
    let _ = std::fs::remove_file(&path);
}

/// LIVE test: spawn the real lsphp and run phpinfo(). Ignored by default.
///
/// Run explicitly with:
///   cargo test -p hj-lsapi --test dispatch -- --ignored live_phpinfo --nocapture
///
/// Uses a temp doc root + temp socket; never touches the production server.
#[tokio::test]
#[ignore = "spawns the real lsphp; run manually on an R&D box"]
async fn live_phpinfo() {
    use hj_lsapi::{LsphpSupervisor, SupervisorConfig};

    let lsphp = PathBuf::from("/usr/local/lsws/lsphp8/bin/lsphp");
    if !lsphp.exists() {
        eprintln!("lsphp not found at {lsphp:?}; skipping");
        return;
    }

    // Temp doc root with a phpinfo script.
    let dir = std::env::temp_dir().join(format!("hj-lsapi-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("info.php");
    std::fs::write(
        &script,
        b"<?php header('X-Probe: ok'); echo 'PHPSTART'; phpinfo(); echo 'PHPEND';\n",
    )
    .unwrap();

    let sock = std::env::temp_dir().join(format!("php8-httpjet-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);

    let php = hj_core::config::PhpConfig {
        handler_id: "lsphp".into(),
        command: lsphp.clone(),
        suffixes: vec!["php".into()],
        env: vec![("PHP_LSAPI_CHILDREN".into(), "1".into())],
        max_conns: 4,
        init_timeout: Duration::from_secs(10),
        retry_timeout: Duration::from_secs(0),
        pc_keep_alive_timeout: Duration::from_secs(0),
        backlog: 1024,
        run_on_startup: 1,
        mem_soft_limit: None,
        mem_hard_limit: None,
        detached_mode: false,
        max_process_time: None,
        cpu_limit_secs: None,
        proc_soft_limit: None,
        proc_hard_limit: None,
        max_idle_time: None,
        min_restart_interval: Duration::from_secs(10),
        max_restart_backoff: Duration::from_secs(30),
    };

    // Run as current user (don't drop privileges in a test): pass empty user.
    let cfg = SupervisorConfig::from_php_config(&php, &sock, "", "");
    let sup = LsphpSupervisor::new(cfg);
    sup.start().await.expect("lsphp should start");

    let pool = Arc::new(LsapiPool::new(&sock, 4, Duration::from_secs(10)));
    let handler = Lsapi::new(pool)
        .script_root(&dir)
        .read_timeout(Duration::from_secs(10));

    let req = http::Request::builder()
        .method("GET")
        .uri("/info.php")
        .header("Host", "localhost")
        .body(empty_incoming())
        .unwrap();
    let mut c = ctx(dir.to_str().unwrap());

    let resp = handler.handle(&mut c, req).await.expect("phpinfo dispatch");
    assert_eq!(resp.status(), 200, "phpinfo should return 200");
    assert_eq!(
        resp.headers().get("x-probe").map(|v| v.to_str().unwrap()),
        Some("ok")
    );

    let (_p, body) = resp.into_parts();
    let bytes = match body {
        hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        hj_core::Body::Full(b) => b,
        _ => panic!("expected stream or full body"),
    };
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("PHPSTART"), "missing leading echo");
    assert!(
        text.contains("phpinfo()") || text.contains("PHP Version"),
        "missing phpinfo output"
    );
    assert!(text.contains("PHPEND"), "missing trailing echo");

    sup.drain().await.unwrap();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// (D1) A declared Content-Length ends the CONSUMER's body as soon as that many
/// bytes have streamed — the pump must not make the client wait for RESP_END
/// (lsphp holds the stream open through the app's post-flush deferred work,
/// ~100ms on real XenForo pages). Deterministic barrier: the mock lsphp sends
/// header + full body but does NOT send RESP_END until the client has already
/// collected the complete body.
#[tokio::test]
async fn declared_content_length_completes_body_before_resp_end() {
    let path = tmp_sock("clearly");
    let listener = UnixListener::bind(&path).unwrap();

    let body_len = 100_000usize;
    let payload: Vec<u8> = (0..body_len).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    let (end_tx, end_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, _) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);

        let mut out = BytesMut::new();
        let rh = resp_header_body(
            200,
            &[("Content-Type", "text/html"), ("Content-Length", "100000")],
        );
        put_packet(&mut out, PacketType::RespHeader, &rh);
        for chunk in payload.chunks(8192) {
            put_packet(&mut out, PacketType::RespStream, chunk);
        }
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();

        // BARRIER: RESP_END is withheld until the client proves it collected the
        // whole body. Without the declared-length early completion this deadlocks
        // (bounded below by the test timeout).
        end_rx.await.unwrap();
        let mut out = BytesMut::new();
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(200), s.read(&mut sink)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(5));

    let req = http::Request::builder()
        .method("GET")
        .uri("/index.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let mut c = ctx("/web/test");

    let resp = handler.handle(&mut c, req).await.expect("handle ok");
    assert_eq!(resp.status(), 200);
    let (_p, body) = resp.into_parts();
    // (#987) The whole body is queued behind the header, so it now returns inline;
    // a body that still has to arrive would stream. Either way it must complete
    // without RESP_END.
    let bytes = match body {
        hj_core::Body::Full(b) => b,
        hj_core::Body::Stream(s) => tokio::time::timeout(Duration::from_secs(5), s.collect())
            .await
            .expect("body must complete WITHOUT waiting for RESP_END")
            .unwrap()
            .to_bytes(),
        other => panic!("unexpected body {:?}", std::mem::discriminant(&other)),
    };
    assert_eq!(bytes.len(), expected.len());
    assert_eq!(&bytes[..], &expected[..]);
    assert_eq!(pool.idle_count(), 0, "RESP_END has not arrived yet");

    // Release the barrier so the drain can see RESP_END and re-pool the socket.
    end_tx.send(()).unwrap();
    wait_for_idle(&pool, 1).await;
    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

async fn wait_for_idle(pool: &LsapiPool, want: usize) {
    for _ in 0..400 {
        if pool.idle_count() == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("idle_count stayed {} (wanted {want})", pool.idle_count());
}

fn declared_head(len: usize) -> BytesMut {
    let mut out = BytesMut::new();
    put_packet(
        &mut out,
        PacketType::RespHeader,
        &resp_header_body(
            200,
            &[
                ("Content-Type", "text/html"),
                ("Content-Length", &len.to_string()),
            ],
        ),
    );
    out
}

/// Accepts connections until none arrives for 500 ms; `serve(i, stream)` answers
/// connection `i`. Returns how many connections were accepted.
fn mock_lsphp<F, Fut>(listener: UnixListener, serve: F) -> tokio::task::JoinHandle<usize>
where
    F: Fn(usize, tokio::net::UnixStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut accepted = 0;
        let mut served = Vec::new();
        while let Ok(Ok((stream, _))) =
            tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
        {
            served.push(tokio::spawn(serve(accepted, stream)));
            accepted += 1;
        }
        for task in served {
            task.await.unwrap();
        }
        accepted
    })
}

/// (#987) A declared Content-Length body already in hand returns as `Body::Full`
/// BEFORE lsphp sends RESP_END; RESP_END then re-pools the socket, which the next
/// request reuses.
#[tokio::test]
async fn declared_length_body_returns_full_before_resp_end_then_repools() {
    let path = tmp_sock("cl-full-tail");
    let listener = UnixListener::bind(&path).unwrap();
    let (end_tx, end_rx) = tokio::sync::oneshot::channel::<()>();
    let end_rx = Arc::new(tokio::sync::Mutex::new(Some(end_rx)));
    let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    let body = payload.clone();
    let server = mock_lsphp(listener, move |_, mut s| {
        let end_rx = end_rx.clone();
        let body = body.clone();
        async move {
            let (ptype, _) = read_packet(&mut s).await.unwrap();
            assert_eq!(ptype, PacketType::BeginRequest as u8);
            let mut out = declared_head(body.len());
            put_packet(&mut out, PacketType::RespStream, &body);
            s.write_all(&out).await.unwrap();
            let rx = end_rx.lock().await.take().unwrap();
            rx.await.unwrap();
            let mut out = BytesMut::new();
            put_packet(&mut out, PacketType::RespEnd, b"");
            s.write_all(&out).await.unwrap();

            let (ptype, _) = read_packet(&mut s).await.unwrap();
            assert_eq!(ptype, PacketType::BeginRequest as u8);
            let mut out = declared_head(3);
            put_packet(&mut out, PacketType::RespStream, b"two");
            put_packet(&mut out, PacketType::RespEnd, b"");
            s.write_all(&out).await.unwrap();
            let mut sink = [0u8; 64];
            let _ = tokio::time::timeout(Duration::from_millis(100), s.read(&mut sink)).await;
        }
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(5));
    let resp = get(&handler, "/a.php").await.expect("first response");
    let hj_core::Body::Full(bytes) = resp.into_body() else {
        panic!("a fully buffered declared-length body must return inline");
    };
    assert_eq!(&bytes[..], &payload[..]);
    assert_eq!(pool.idle_count(), 0, "RESP_END has not arrived yet");
    assert_eq!(pool.stats().inline_tail_drains, 1);

    end_tx.send(()).unwrap();
    wait_for_idle(&pool, 1).await;

    let resp = get(&handler, "/b.php").await.expect("second response");
    assert_eq!(&body_bytes(resp).await[..], b"two");
    assert_eq!(
        server.await.unwrap(),
        1,
        "the second request reused the socket"
    );
    let stats = pool.stats();
    assert_eq!((stats.inline_bodies, stats.streamed_bodies), (2, 0));
    let _ = std::fs::remove_file(&path);
}

/// (#987) Bytes past the declared length make the inline tail drop the socket at
/// RESP_END, as the streaming pump does, whether they were already buffered or
/// arrive while the tail drains. The client gets exactly the declared bytes.
#[tokio::test]
async fn bytes_past_declared_length_before_resp_end_are_cut_and_not_repooled() {
    for (tag, early, late) in [
        ("cl-tail-over-buffered", &b"abcdef"[..], &b""[..]),
        ("cl-tail-over-late", &b"abc"[..], &b"xyz"[..]),
    ] {
        let path = tmp_sock(tag);
        let listener = UnixListener::bind(&path).unwrap();
        let (end_tx, end_rx) = tokio::sync::oneshot::channel::<()>();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<bool>();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let (ptype, _) = read_packet(&mut s).await.unwrap();
            assert_eq!(ptype, PacketType::BeginRequest as u8);
            let mut out = declared_head(3);
            put_packet(&mut out, PacketType::RespStream, early);
            s.write_all(&out).await.unwrap();
            end_rx.await.unwrap();
            let mut out = BytesMut::new();
            if !late.is_empty() {
                put_packet(&mut out, PacketType::RespStream, late);
            }
            put_packet(&mut out, PacketType::RespEnd, b"");
            s.write_all(&out).await.unwrap();
            let mut sink = [0u8; 64];
            let eof = matches!(
                tokio::time::timeout(Duration::from_secs(2), s.read(&mut sink)).await,
                Ok(Ok(0))
            );
            closed_tx.send(eof).unwrap();
        });

        let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
        let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(5));
        let resp = get(&handler, "/a.php").await.expect("response head");
        let hj_core::Body::Full(bytes) = resp.into_body() else {
            panic!("{tag}: the declared bytes are in hand and must return inline");
        };
        assert_eq!(&bytes[..], b"abc", "{tag}");
        end_tx.send(()).unwrap();
        assert!(closed_rx.await.unwrap(), "{tag}: the socket must be closed");
        assert_eq!(pool.idle_count(), 0, "{tag}");
        server.await.unwrap();
        let _ = std::fs::remove_file(&path);
    }
}

/// (#987) A declared-length body the socket already holds past the first read
/// buffer (64 KiB) is taken in with non-blocking reads and returned inline.
#[tokio::test]
async fn queued_declared_body_past_first_read_is_inlined() {
    let path = tmp_sock("cl-queued-150k");
    let listener = UnixListener::bind(&path).unwrap();
    let payload: Vec<u8> = (0..150 * 1024).map(|i| (i % 249) as u8).collect();
    let body = payload.clone();
    let (end_tx, end_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, _) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let mut out = declared_head(body.len());
        for chunk in body.chunks(16 * 1024) {
            put_packet(&mut out, PacketType::RespStream, chunk);
        }
        s.write_all(&out).await.unwrap();
        end_rx.await.unwrap();
        let mut out = BytesMut::new();
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(200), s.read(&mut sink)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(5));
    let resp = get(&handler, "/a.php").await.expect("response head");
    let hj_core::Body::Full(bytes) = resp.into_body() else {
        panic!("a queued 150 KiB declared body must return inline");
    };
    assert_eq!(bytes.len(), payload.len());
    assert!(bytes[..] == payload[..]);
    end_tx.send(()).unwrap();
    wait_for_idle(&pool, 1).await;
    server.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

/// (#987) The inline path never waits for body bytes the socket does not hold
/// yet: a partially delivered declared-length body streams.
#[tokio::test]
async fn partially_delivered_declared_body_streams() {
    let path = tmp_sock("cl-partial");
    let listener = UnixListener::bind(&path).unwrap();
    let payload: Vec<u8> = (0..10_000).map(|i| (i % 253) as u8).collect();
    let body = payload.clone();
    let (rest_tx, rest_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, _) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let (first, rest) = body.split_at(4000);
        let mut out = declared_head(body.len());
        put_packet(&mut out, PacketType::RespStream, first);
        s.write_all(&out).await.unwrap();
        rest_rx.await.unwrap();
        let mut out = BytesMut::new();
        put_packet(&mut out, PacketType::RespStream, rest);
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(200), s.read(&mut sink)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(5));
    let resp = get(&handler, "/a.php").await.expect("response head");
    let hj_core::Body::Stream(stream) = resp.into_body() else {
        panic!("a body still in flight must stream");
    };
    assert_eq!(pool.stats().streamed_bodies, 1);
    rest_tx.send(()).unwrap();
    let bytes = stream.collect().await.unwrap().to_bytes();
    assert!(bytes[..] == payload[..]);
    wait_for_idle(&pool, 1).await;
    server.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

/// (#989) A small inline body is its own allocation, not a slice pinning the
/// recycled LSAPI read buffer.
#[tokio::test]
async fn small_inline_body_does_not_share_the_read_buffer() {
    for (tag, headers) in [
        ("inline-unique-cl", vec![("Content-Length", "5")]),
        ("inline-unique-end", vec![]),
    ] {
        let (result, _) = buffered_mock_response(tag, "GET", 200, &headers, &[b"Hello"]).await;
        let hj_core::Body::Full(bytes) = result.expect("response").into_body() else {
            panic!("{tag}: a buffered response must return inline");
        };
        assert_eq!(&bytes[..], b"Hello");
        assert!(
            bytes.is_unique(),
            "{tag}: body still shares the read buffer"
        );
    }
}

/// A buffered body joined from several frames lives in a pooled buffer, which
/// `Bytes::is_unique` cannot recognize as fresh; the response's mark vouches for it so
/// the transport still charges it to the response budget.
#[tokio::test]
async fn a_joined_inline_body_carries_its_fresh_mark() {
    let first = vec![b'a'; 12 * 1024];
    let second = vec![b'b'; 12 * 1024];
    let (result, _) =
        buffered_mock_response("inline-fresh-mark", "GET", 200, &[], &[&first, &second]).await;
    let response = result.expect("response");
    let mark = *response
        .extensions()
        .get::<hj_core::FreshBody>()
        .expect("marked");
    let hj_core::Body::Full(bytes) = response.into_body() else {
        panic!("a buffered response must return inline");
    };
    assert_eq!(bytes.len(), first.len() + second.len());
    assert!(mark.names(&bytes));
}

/// (#990) Building the head by moving the parsed fields keeps their order and
/// duplicates: repeated Set-Cookie and custom X-LiteSpeed-* names reach the
/// response exactly as lsphp sent them, `Status:` is consumed, Content-Length is
/// normalized last.
#[tokio::test]
async fn response_head_keeps_header_order_and_duplicates() {
    let (result, _) = buffered_mock_response(
        "head-order",
        "GET",
        200,
        &[
            ("Set-Cookie", "a=1"),
            ("X-LiteSpeed-Cache-Control", "public,max-age=60"),
            ("Content-Type", "text/html"),
            ("set-cookie", "b=2"),
            ("X-Custom-Thing", "v"),
            ("Status", "201 Created"),
            ("Content-Length", "2"),
            ("Set-Cookie", "c=3"),
            ("x-litespeed-tag", "T1,T2"),
        ],
        &[b"ok"],
    )
    .await;
    let resp = result.expect("response");
    assert_eq!(resp.status(), 201);
    let seen: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap().to_owned()))
        .collect();
    let want = [
        ("set-cookie", "a=1"),
        ("set-cookie", "b=2"),
        ("set-cookie", "c=3"),
        ("x-litespeed-cache-control", "public,max-age=60"),
        ("content-type", "text/html"),
        ("x-custom-thing", "v"),
        ("x-litespeed-tag", "T1,T2"),
        ("content-length", "2"),
    ];
    let want: Vec<(String, String)> = want
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    assert_eq!(seen, want);
}

/// How the mock lsphp ends a response whose declared body already left inline,
/// i.e. while the inline tail drains toward RESP_END (#987).
#[derive(Clone, Copy, Debug)]
enum TailEnd {
    RespEnd,
    ConnClose,
    Eof,
    /// Nothing more: only the idle read timeout can end the tail.
    Silent,
    /// REQ_RECEIVED every 50 ms: reads keep succeeding, so only the processing
    /// deadline can end the tail.
    Trickle,
}

fn pid_frame(pid: u32) -> Vec<u8> {
    let mut frame = b"\0PID".to_vec();
    frame.extend_from_slice(&(pid as i32).to_ne_bytes());
    frame
}

/// Whether httpjet closed `s` before `done` fired. Read first, so a close that
/// already happened always wins.
async fn closed_before(
    s: &mut tokio::net::UnixStream,
    done: tokio::sync::oneshot::Receiver<()>,
) -> bool {
    let mut sink = [0u8; 64];
    tokio::select! {
        biased;
        read = s.read(&mut sink) => matches!(read, Ok(0) | Err(_)),
        _ = done => false,
    }
}

async fn trickle_until_closed(s: &mut tokio::net::UnixStream) -> bool {
    let mut packet = BytesMut::new();
    put_packet(&mut packet, PacketType::ReqReceived, b"");
    let mut sink = [0u8; 64];
    for _ in 0..200 {
        tokio::select! {
            read = s.read(&mut sink) => return matches!(read, Ok(0) | Err(_)),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if s.write_all(&packet).await.is_err() {
                    return true;
                }
            }
        }
    }
    false
}

/// One GET whose declared-length body is queued behind its head, so the handler
/// returns it inline before RESP_END. A PID frame names this test process: a
/// generation-aware pool then fails worker attribution on the hint (not an
/// lsphp) instead of scanning /proc. After `go` the response ends per `end`;
/// resolves to whether httpjet closed the socket.
fn tail_mock(
    listener: UnixListener,
    body: Vec<u8>,
    end: TailEnd,
    go: tokio::sync::oneshot::Receiver<()>,
    done: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, _) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::StderrStream,
            &pid_frame(std::process::id()),
        );
        out.extend_from_slice(&declared_head(body.len()));
        put_packet(&mut out, PacketType::RespStream, &body);
        s.write_all(&out).await.unwrap();
        go.await.unwrap();
        let mut last = BytesMut::new();
        match end {
            TailEnd::RespEnd => put_packet(&mut last, PacketType::RespEnd, b""),
            TailEnd::ConnClose => put_packet(&mut last, PacketType::ConnClose, b""),
            TailEnd::Eof => return true,
            TailEnd::Silent => {}
            TailEnd::Trickle => return trickle_until_closed(&mut s).await,
        }
        s.write_all(&last).await.unwrap();
        closed_before(&mut s, done).await
    })
}

/// The tail released its permit, so its guard is gone and any re-pool already
/// happened.
async fn wait_for_settled(pool: &LsapiPool, tag: &str) {
    for _ in 0..2000 {
        if pool.inflight() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("{tag}: the inline tail never released the socket");
}

struct TailRun {
    pool: Arc<LsapiPool>,
    closed: bool,
    /// From the request's start until the tail released the socket.
    settled: Duration,
}

async fn run_inline_tail(
    tag: &str,
    end: TailEnd,
    pool: impl FnOnce(&std::path::Path) -> LsapiPool,
    handler: impl FnOnce(Lsapi) -> Lsapi,
    during_tail: impl FnOnce(),
) -> TailRun {
    let path = tmp_sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let payload: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
    let (go_tx, go_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let server = tail_mock(listener, payload.clone(), end, go_rx, done_rx);
    let pool = Arc::new(pool(&path));
    let handler = handler(Lsapi::new(pool.clone()));
    let started = std::time::Instant::now();
    let resp = get(&handler, "/a.php").await.expect("response head");
    let hj_core::Body::Full(bytes) = resp.into_body() else {
        panic!("{tag}: a queued declared-length body must return inline");
    };
    assert_eq!(&bytes[..], &payload[..], "{tag}");
    assert_eq!(pool.stats().inline_tail_drains, 1, "{tag}");
    assert_eq!(pool.inflight(), 1, "{tag}: the tail holds the socket");
    during_tail();
    go_tx.send(()).unwrap();
    wait_for_settled(&pool, tag).await;
    let settled = started.elapsed();
    let _ = done_tx.send(());
    let closed = server.await.unwrap();
    let _ = std::fs::remove_file(&path);
    TailRun {
        pool,
        closed,
        settled,
    }
}

fn plain_pool(path: &std::path::Path) -> LsapiPool {
    LsapiPool::new(path, 4, Duration::from_secs(2))
}

/// A 0700 directory: the generation file refuses a group/other-writable parent.
fn private_dir(tag: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("hj-lsapi-it-{}-{tag}.d", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// (#987) After the body left inline, the tail settles the socket like the
/// streaming pump: only RESP_END re-pools; CONN_CLOSE or EOF before it closes it.
#[tokio::test]
async fn inline_tail_repools_only_after_resp_end() {
    for (tag, end, pooled) in [
        ("tail-resp-end", TailEnd::RespEnd, 1),
        ("tail-conn-close", TailEnd::ConnClose, 0),
        ("tail-eof", TailEnd::Eof, 0),
    ] {
        let run = run_inline_tail(
            tag,
            end,
            plain_pool,
            |h| h.read_timeout(Duration::from_secs(5)),
            || {},
        )
        .await;
        assert_eq!(run.pool.idle_count(), pooled, "{tag}");
        assert_eq!(run.closed, pooled == 0, "{tag}");
        assert!(
            run.settled < Duration::from_secs(4),
            "{tag}: settled by {end:?}, not a timeout: {:?}",
            run.settled
        );
    }
}

/// (#987) A tail that never sees RESP_END is cut by the idle read timeout and its
/// socket closed.
#[tokio::test]
async fn inline_tail_idle_timeout_closes_the_socket() {
    let read_timeout = Duration::from_millis(300);
    let run = run_inline_tail(
        "tail-idle",
        TailEnd::Silent,
        plain_pool,
        |h| h.read_timeout(read_timeout),
        || {},
    )
    .await;
    assert!(run.closed);
    assert_eq!(run.pool.idle_count(), 0);
    assert!(run.settled >= read_timeout, "{:?}", run.settled);
}

/// (#987) A tail kept busy past the processing deadline is cut by the deadline
/// (the idle timeout never fires while lsphp keeps writing) and its socket closed.
#[tokio::test]
async fn inline_tail_processing_deadline_closes_a_busy_socket() {
    let deadline = Duration::from_millis(700);
    let run = run_inline_tail(
        "tail-deadline",
        TailEnd::Trickle,
        plain_pool,
        |h| {
            h.read_timeout(Duration::from_secs(30))
                .max_process_time(Some(deadline))
        },
        || {},
    )
    .await;
    assert!(run.closed, "closed while lsphp was still writing");
    assert_eq!(run.pool.idle_count(), 0);
    assert!(run.settled >= deadline, "{:?}", run.settled);
}

/// (#987) RESP_END after an external generation advance does not re-pool: the
/// socket spans a worker-family replacement.
#[tokio::test]
async fn inline_tail_spanning_a_generation_advance_is_not_repooled() {
    for advance in [false, true] {
        let tag = if advance {
            "tail-gen-advanced"
        } else {
            "tail-gen-steady"
        };
        let dir = private_dir(tag);
        let generation = dir.join("lsphp.generation");
        let writer = ExternalGenerationWriter::open_or_create(&generation).unwrap();
        writer.advance_with_marker(1, "family-a");
        let run = run_inline_tail(
            tag,
            TailEnd::RespEnd,
            |path| {
                LsapiPool::new(path, 4, Duration::from_secs(2))
                    .external_generation_file(&generation)
                    .unwrap()
            },
            |h| h.read_timeout(Duration::from_secs(5)),
            || {
                if advance {
                    writer.advance_with_marker(1, "family-b");
                }
            },
        )
        .await;
        let stats = run.pool.stats();
        assert_eq!(run.pool.idle_count(), usize::from(!advance), "{tag}");
        assert_eq!(stats.stale_checked_out_drops, u64::from(advance), "{tag}");
        assert_eq!(run.closed, advance, "{tag}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// POST /upload.php declaring a 10-byte body of `content_type`; the body is whatever
/// `body` delivers.
fn upload_request(body: hj_core::IncomingBody, content_type: Option<&str>) -> hj_core::Request {
    let mut req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Length", "10");
    if let Some(content_type) = content_type {
        req = req.header("Content-Type", content_type);
    }
    req.body(body).unwrap()
}

/// (#987) lsphp may answer before the upload finishes, so the inline tail can run
/// while the request-body pump still waits on the client. RESP_END cancels that
/// upload (not its idle timer) and the half-uploaded socket is closed. (A body PHP
/// does not pre-read: one it pre-reads is collected before dispatch.)
#[tokio::test]
async fn inline_tail_cancels_a_stalled_upload_and_closes_the_socket() {
    let path = tmp_sock("tail-upload-stalled");
    let listener = UnixListener::bind(&path).unwrap();
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, begin) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        assert_eq!(req_body_len_from_begin(&begin), 100);
        let mut first = [0u8; 2];
        s.read_exact(&mut first).await.unwrap();
        let mut out = declared_head(5);
        put_packet(&mut out, PacketType::RespStream, b"hello");
        s.write_all(&out).await.unwrap();
        go_rx.await.unwrap();
        let mut end = BytesMut::new();
        put_packet(&mut end, PacketType::RespEnd, b"");
        s.write_all(&end).await.unwrap();
        let mut rest = Vec::new();
        let ended = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest))
            .await
            .is_ok_and(|read| read.is_ok());
        (first, ended, rest)
    });

    // The client sends 50 of the 100 declared bytes and then holds the body open. The
    // body has no Content-Type, so PHP does not pre-read it and it streams; its
    // embedded-request scan holds back only a short tail.
    let (mut upload, body) = Channel::<Bytes, hj_core::BoxError>::new(1);
    upload
        .send_data(Bytes::from_static(&[b'a'; 50]))
        .await
        .unwrap();
    let pool = Arc::new(plain_pool(&path));
    let read_timeout = Duration::from_secs(20);
    let handler = Lsapi::new(pool.clone()).read_timeout(read_timeout);
    let started = std::time::Instant::now();
    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Length", "100")
        .body(BoxBody::new(body))
        .unwrap();
    let resp = handler
        .handle(&mut ctx("/web/test"), req)
        .await
        .expect("response head");
    let hj_core::Body::Full(bytes) = resp.into_body() else {
        panic!("the declared body is in hand and must return inline");
    };
    assert_eq!(&bytes[..], b"hello");
    assert_eq!(pool.stats().inline_tail_drains, 1);
    go_tx.send(()).unwrap();
    wait_for_settled(&pool, "stalled upload").await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "RESP_END must cancel the upload, not wait out its {read_timeout:?} idle timer"
    );
    assert_eq!(pool.idle_count(), 0);
    let (first, ended, rest) = server.await.unwrap();
    assert_eq!(&first, b"aa");
    assert!(ended, "the cancelled upload must shut its write half down");
    assert!(
        rest.len() <= 48 && rest.iter().all(|&b| b == b'a'),
        "only the sent upload bytes may follow: {rest:?}"
    );
    drop(upload);
    let _ = std::fs::remove_file(&path);
}

/// A form POST PHP reads whole before its script runs is collected before dispatch, so
/// a retiring worker's unread reset can replay it: the worker sees BEGIN_REQUEST only
/// once the upload is complete, gets the body whole, and the socket re-pools.
#[tokio::test]
async fn preread_post_reaches_the_worker_once_its_upload_completes() {
    let path = tmp_sock("preread-upload-complete");
    let listener = UnixListener::bind(&path).unwrap();
    let (begun_tx, mut begun_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, begin) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        assert_eq!(req_body_len_from_begin(&begin), 10);
        let _ = begun_tx.send(());
        let mut body = [0u8; 10];
        s.read_exact(&mut body).await.unwrap();
        let mut out = declared_head(5);
        put_packet(&mut out, PacketType::RespStream, b"hello");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        (body, closed_before(&mut s, done_rx).await)
    });

    let (mut upload, body) = Channel::<Bytes, hj_core::BoxError>::new(1);
    upload.send_data(Bytes::from_static(b"ab")).await.unwrap();
    let pool = Arc::new(plain_pool(&path));
    let handler = Arc::new(Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(5)));
    let dispatch = {
        let handler = handler.clone();
        tokio::spawn(async move {
            handler
                .handle(
                    &mut ctx("/web/test"),
                    upload_request(
                        BoxBody::new(body),
                        Some("application/x-www-form-urlencoded"),
                    ),
                )
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        begun_rx.try_recv().is_err(),
        "BEGIN_REQUEST went out before the pre-read body was complete"
    );
    upload
        .send_data(Bytes::from_static(b"cdefghij"))
        .await
        .unwrap();
    drop(upload);
    let resp = dispatch.await.unwrap().expect("response head");
    assert_eq!(&collect_body(resp).await[..], b"hello");
    wait_for_settled(&pool, "completed upload").await;
    let _ = done_tx.send(());
    let (received, closed) = server.await.unwrap();
    assert_eq!(&received, b"abcdefghij");
    assert!(!closed, "a clean socket must stay open in the pool");
    assert_eq!(pool.idle_count(), 1);
    let stats = pool.stats();
    assert_eq!((stats.body_conn_closes, stats.unread_body_drops), (0, 0));
    let _ = std::fs::remove_file(&path);
}

/// A minimal lsphp stand-in: answers one request with argv's pre-built packets,
/// announcing its PID first like lsphp, and sends RESP_END on a stdin line. argv[4]
/// is the packet flag, this host's LSAPI_ENDIAN.
const FAKE_LSPHP: &str = r#"
import os, socket, struct, sys
path, head, end = sys.argv[1], bytes.fromhex(sys.argv[2]), bytes.fromhex(sys.argv[3])
flag = bytes([int(sys.argv[4])])
listener = socket.socket(socket.AF_UNIX)
listener.bind(path)
listener.listen(16)
conn, _ = listener.accept()
def recv_exact(n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            sys.exit(2)
        data += chunk
    return data
total = struct.unpack("<I", recv_exact(8)[4:8])[0]
recv_exact(total - 8)
pid = b"\0PID" + struct.pack("=i", os.getpid())
conn.sendall(b"LS\x06" + flag + struct.pack("<I", 8 + len(pid)) + pid + head)
sys.stdin.readline()
conn.sendall(end)
while conn.recv(4096):
    pass
"#;

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// (#987) A worker whose family is superseded while the inline tail drains is
/// retired through its pidfd once RESP_END completes the response, and its socket
/// is not re-pooled. The worker is python copied as `lsphp` and carrying the
/// generation marker, as in the pool's own retirement test.
#[tokio::test]
async fn inline_tail_retires_a_worker_superseded_mid_tail() {
    use std::io::Write as _;
    use std::os::unix::process::ExitStatusExt;

    let Ok(python) = std::fs::canonicalize("/usr/bin/python3") else {
        return;
    };
    let dir = private_dir("tail-retire");
    let fake = dir.join("lsphp");
    std::fs::copy(&python, &fake).unwrap();
    let socket = dir.join("php.sock");
    let generation = dir.join("lsphp.generation");
    let writer = ExternalGenerationWriter::open_or_create(&generation).unwrap();
    writer.advance_with_marker(1, "family-a");
    let payload = b"rendered before RESP_END";
    let mut head = declared_head(payload.len());
    put_packet(&mut head, PacketType::RespStream, payload);
    let mut end = BytesMut::new();
    put_packet(&mut end, PacketType::RespEnd, b"");
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut worker = KillOnDrop(
        std::process::Command::new(&fake)
            .arg("-c")
            .arg(FAKE_LSPHP)
            .arg(&socket)
            .arg(hex(&head))
            .arg(hex(&end))
            .arg(hj_lsapi::proto::HOST_LSAPI_ENDIAN.to_string())
            .env("LSAPI_Z_HTTPJET_GENERATION_MARKER", "family-a")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    for _ in 0..500 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let pool = Arc::new(
        LsapiPool::new(&socket, 4, Duration::from_secs(2))
            .external_generation_file(&generation)
            .unwrap(),
    );
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(5));
    let resp = get(&handler, "/a.php").await.expect("response head");
    let hj_core::Body::Full(bytes) = resp.into_body() else {
        panic!("a queued declared-length body must return inline");
    };
    assert_eq!(&bytes[..], payload);
    assert_eq!(pool.stats().inline_tail_drains, 1);

    writer.advance_with_marker(1, "family-b");
    worker.0.stdin.take().unwrap().write_all(b"\n").unwrap();
    wait_for_settled(&pool, "superseded worker").await;
    let mut status = None;
    for _ in 0..500 {
        status = worker.0.try_wait().unwrap();
        if status.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stats = pool.stats();
    assert_eq!(pool.idle_count(), 0, "a superseded worker must not re-pool");
    assert_eq!(stats.worker_attribution_failures, 0, "{stats:?}");
    assert_eq!(stats.stale_checked_out_drops, 1, "{stats:?}");
    assert_eq!(stats.stale_worker_retire_signals, 1, "{stats:?}");
    assert_eq!(
        status.and_then(|s| s.signal()),
        Some(libc::SIGUSR1),
        "the worker must be retired"
    );
    drop(worker);
    let _ = std::fs::remove_dir_all(&dir);
}

fn raw_header_block(body: &[u8], env_end: usize) -> &[u8] {
    let unknown = read_i32_le(body, 24) as usize;
    let header_len = read_i32_le(body, 0) as usize;
    let pad = (8 - ((PACKET_HEADER_LEN + env_end) % 8)) % 8;
    let raw_at = env_end + pad + HEADER_INDEX_LEN + unknown * 16;
    &body[raw_at..raw_at + header_len]
}

async fn begin_request_for(trusted: bool) -> (BTreeMap<String, String>, String) {
    let path = tmp_sock(if trusted {
        "fwd-trusted"
    } else {
        "fwd-untrusted"
    });
    let listener = UnixListener::bind(&path).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, body) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[]),
        );
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();
        let _ = tx.send(body);
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(2)));
    // Every HTTP_* copy, so the env table's own forwarding filter is exercised too.
    let handler = Lsapi::new(pool)
        .read_timeout(Duration::from_secs(2))
        .full_header_env(true);
    let req = http::Request::builder()
        .method("GET")
        .uri("/index.php")
        .header("Host", "test")
        .header("User-Agent", "curl/8")
        .header("X_Real_Ip", "127.0.0.1")
        .header("CF-Connecting-IP", "198.51.100.9")
        .body(empty_incoming())
        .unwrap();
    let mut c = ctx("/web/test");
    c.trusted_proxy = trusted;
    c.forwarding_trusted = trusted;
    handler.handle(&mut c, req).await.expect("handle ok");
    let body = rx.await.unwrap();
    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
    let (env, env_end) = parse_begin_env(&body);
    let raw = String::from_utf8_lossy(raw_header_block(&body, env_end)).to_ascii_lowercase();
    (env, raw)
}

#[tokio::test]
async fn wire_header_block_omits_underscore_and_untrusted_forwarding_names() {
    let (env, raw) = begin_request_for(false).await;
    assert!(raw.contains("user-agent: curl/8"), "{raw}");
    assert!(
        !raw.contains("x_real_ip"),
        "underscore names never reach lsphp: {raw}"
    );
    assert!(
        !raw.contains("cf-connecting-ip"),
        "untrusted forwarding header: {raw}"
    );
    assert!(!env.contains_key("HTTP_CF_CONNECTING_IP"));
    assert!(!env.contains_key("HTTP_X_REAL_IP"));

    let (env, raw) = begin_request_for(true).await;
    assert!(raw.contains("cf-connecting-ip: 198.51.100.9"), "{raw}");
    assert!(!raw.contains("x_real_ip"), "{raw}");
    assert_eq!(
        env.get("HTTP_CF_CONNECTING_IP").map(String::as_str),
        Some("198.51.100.9")
    );
}

/// LIVE: what the real lsphp exposes in `$_SERVER` for forwarding headers.
///   cargo test -p hj-lsapi --test dispatch -- --ignored live_forwarding_headers
#[tokio::test]
#[ignore = "spawns the real lsphp; run manually on an R&D box"]
async fn live_forwarding_headers_follow_peer_trust() {
    use hj_lsapi::{LsphpSupervisor, SupervisorConfig};

    let lsphp = PathBuf::from("/usr/local/lsws/lsphp8/bin/lsphp");
    if !lsphp.exists() {
        eprintln!("lsphp not found at {lsphp:?}; skipping");
        return;
    }
    let dir = std::env::temp_dir().join(format!("hj-lsapi-fwd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("env.php"),
        b"<?php foreach (['HTTP_CF_CONNECTING_IP','HTTP_X_REAL_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR','HTTP_USER_AGENT'] as $k) { echo $k, '=', $_SERVER[$k] ?? '-', \"\\n\"; }\n",
    )
    .unwrap();
    let sock = std::env::temp_dir().join(format!("php8-httpjet-fwd-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);
    let php = hj_core::config::PhpConfig {
        handler_id: "lsphp".into(),
        command: lsphp.clone(),
        suffixes: vec!["php".into()],
        env: vec![("PHP_LSAPI_CHILDREN".into(), "1".into())],
        max_conns: 4,
        init_timeout: Duration::from_secs(10),
        retry_timeout: Duration::from_secs(0),
        pc_keep_alive_timeout: Duration::from_secs(0),
        backlog: 1024,
        run_on_startup: 1,
        mem_soft_limit: None,
        mem_hard_limit: None,
        detached_mode: false,
        max_process_time: None,
        cpu_limit_secs: None,
        proc_soft_limit: None,
        proc_hard_limit: None,
        max_idle_time: None,
        min_restart_interval: Duration::from_secs(10),
        max_restart_backoff: Duration::from_secs(30),
    };
    let sup = LsphpSupervisor::new(SupervisorConfig::from_php_config(&php, &sock, "", ""));
    sup.start().await.expect("lsphp should start");
    let pool = Arc::new(LsapiPool::new(&sock, 4, Duration::from_secs(10)));
    let handler = Lsapi::new(pool)
        .script_root(&dir)
        .read_timeout(Duration::from_secs(10));

    let render = async |trusted: bool| -> String {
        let req = http::Request::builder()
            .method("GET")
            .uri("/env.php")
            .header("Host", "localhost")
            .header("User-Agent", "curl/8")
            .header("CF-Connecting-IP", "198.51.100.9")
            .header("X_Real_Ip", "127.0.0.1")
            .header("X_Forwarded_For", "127.0.0.2")
            .body(empty_incoming())
            .unwrap();
        let mut c = ctx(dir.to_str().unwrap());
        c.trusted_proxy = trusted;
        c.forwarding_trusted = trusted;
        let resp = handler.handle(&mut c, req).await.expect("dispatch");
        let (_p, body) = resp.into_parts();
        let bytes = match body {
            hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
            hj_core::Body::Full(b) => b,
            _ => panic!("unexpected body"),
        };
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let untrusted = render(false).await;
    let trusted = render(true).await;
    sup.drain().await.unwrap();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("untrusted:\n{untrusted}\ntrusted:\n{trusted}");

    assert!(
        untrusted.contains("HTTP_CF_CONNECTING_IP=-\n"),
        "{untrusted}"
    );
    assert!(untrusted.contains("HTTP_X_REAL_IP=-\n"), "{untrusted}");
    assert!(
        untrusted.contains("HTTP_X_FORWARDED_FOR=-\n"),
        "{untrusted}"
    );
    assert!(
        untrusted.contains("HTTP_USER_AGENT=curl/8\n"),
        "{untrusted}"
    );
    assert!(
        trusted.contains("HTTP_CF_CONNECTING_IP=198.51.100.9\n"),
        "{trusted}"
    );
    assert!(
        trusted.contains("HTTP_X_REAL_IP=-\n"),
        "underscore spoof: {trusted}"
    );
    assert!(
        trusted.contains("HTTP_X_FORWARDED_FOR=-\n"),
        "underscore spoof: {trusted}"
    );
}

/// Fake lsphp that answers a POST either after consuming the whole request body
/// (`drain`) or after reading only BEGIN_REQUEST, leaving the body in the socket
/// as a script that partially reads `php://input` would. Returns the pool so the
/// caller can see whether the connection was re-pooled.
async fn post_with_body_drain(tag: &str, drain: bool, declare_length: bool) -> Arc<LsapiPool> {
    request_with_body_drain("POST", Some("text/plain"), tag, drain, declare_length).await
}

async fn request_with_body_drain(
    method: &str,
    content_type: Option<&str>,
    tag: &str,
    drain: bool,
    declare_length: bool,
) -> Arc<LsapiPool> {
    const BODY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
    let path = tmp_sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (ptype, _) = read_packet(&mut stream).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        if drain {
            let mut body = [0u8; 32];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, BODY);
        }
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[("Content-Length", "2")]),
        );
        put_packet(&mut out, PacketType::RespStream, b"ok");
        put_packet(&mut out, PacketType::RespEnd, b"");
        stream.write_all(&out).await.unwrap();
        stream.flush().await.unwrap();
        // Keep the socket open until the client side has decided whether to
        // re-pool, so a closed peer cannot be what refuses reuse.
        let _ = done_rx.await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(1));
    let mut builder = http::Request::builder()
        .method(method)
        .uri("/index.php")
        .header("Host", "test");
    if declare_length {
        builder = builder.header("Content-Length", "32");
    }
    if let Some(ct) = content_type {
        builder = builder.header("Content-Type", ct);
    }
    let request = builder.body(full_incoming(BODY)).unwrap();
    let response = handler
        .handle(&mut ctx("/web/test"), request)
        .await
        .expect("response");
    let body = match response.into_body() {
        hj_core::Body::Full(bytes) => bytes,
        hj_core::Body::Stream(stream) => stream.collect().await.unwrap().to_bytes(),
        other => panic!("unexpected body: {:?}", std::mem::discriminant(&other)),
    };
    assert_eq!(&body[..], b"ok");
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if pool.idle_count() > 0 || pool.stats().body_conn_closes > 0 {
            break;
        }
    }
    let _ = done_tx.send(());
    server_task.await.unwrap();
    let _ = std::fs::remove_file(path);
    pool
}

/// Regression (#596): keep-alive must not depend on PHP draining php://input.
/// Unread request-body bytes would be parsed by lsphp as the next request.
#[tokio::test]
async fn unread_request_body_prevents_repool() {
    for (tag, declare_length) in [
        ("unread-body-stream", true),
        ("unread-body-buffered", false),
    ] {
        let pool = post_with_body_drain(tag, false, declare_length).await;
        assert_eq!(
            pool.idle_count(),
            0,
            "{tag}: undrained socket was re-pooled"
        );
        assert_eq!(pool.stats().unread_body_drops, 1, "{tag}");
    }
}

/// #833: a fully dequeued body is no proof of safety (lsphp's next `readReq`
/// dequeues a smuggled tail too), so a connection whose body PHP may not have
/// read (anything but a small POST) is never re-pooled. A small POST, which PHP
/// reads in full before the script runs, is re-pooled once fully dequeued.
#[tokio::test]
async fn drained_request_body_closes_unless_php_preread_it() {
    for (tag, declare_length) in [
        ("drained-body-stream", true),
        ("drained-body-buffered", false),
    ] {
        let pool =
            request_with_body_drain("PUT", Some("text/plain"), tag, true, declare_length).await;
        assert_eq!(
            pool.idle_count(),
            0,
            "{tag}: a PUT socket that carried a body must not be re-pooled"
        );
        assert_eq!(pool.stats().unread_body_drops, 0, "{tag}");
        assert_eq!(pool.stats().body_conn_closes, 1, "{tag}");

        let post_tag = format!("{tag}-post");
        let pool = post_with_body_drain(&post_tag, true, declare_length).await;
        assert_eq!(
            pool.idle_count(),
            1,
            "{post_tag}: a drained small POST is re-pooled"
        );
        assert_eq!(pool.stats().body_conn_closes, 0, "{post_tag}");

        // PHP pre-reads a POST only when it carries a Content-Type.
        let bare_tag = format!("{tag}-post-no-ct");
        let pool = request_with_body_drain("POST", None, &bare_tag, true, declare_length).await;
        assert_eq!(pool.idle_count(), 0, "{bare_tag}");
        assert_eq!(pool.stats().body_conn_closes, 1, "{bare_tag}");
    }
}

fn owned_incoming(bytes: Bytes) -> hj_core::IncomingBody {
    BoxBody::new(Full::new(bytes).map_err(|e| match e {}))
}

async fn collect_body(response: hj_core::Response) -> Bytes {
    match response.into_body() {
        hj_core::Body::Full(bytes) => bytes,
        hj_core::Body::Stream(stream) => stream.collect().await.unwrap().to_bytes(),
        hj_core::Body::Empty => Bytes::new(),
        other => panic!("unexpected body: {:?}", std::mem::discriminant(&other)),
    }
}

/// Regression (#833): lsphp parses an unread body tail as a new request right
/// after RESP_END and writes its response on the same socket. The fake lsphp
/// drains the body (so the unsent-bytes check reads 0, as with the real one)
/// and then emits that smuggled response; the next GET must never receive it.
/// PUT: PHP never pre-reads it, so a script may leave a tail.
#[tokio::test]
async fn smuggled_response_after_resp_end_never_reaches_next_request() {
    for (tag, body_len) in [
        ("smuggle-inline", 32_usize),
        ("smuggle-streamed", 96 * 1024),
    ] {
        for declare_length in [true, false] {
            let tag = format!("{tag}-{declare_length}");
            let path = tmp_sock(&tag);
            let listener = UnixListener::bind(&path).unwrap();
            let server_task = tokio::spawn(async move {
                let mut connections = 0_usize;
                let mut held = Vec::new();
                while let Ok(Ok((mut stream, _))) =
                    tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
                {
                    connections += 1;
                    let first = connections == 1;
                    held.push(tokio::spawn(async move {
                        while let Ok((ptype, begin)) = read_packet(&mut stream).await {
                            assert_eq!(ptype, PacketType::BeginRequest as u8);
                            let declared = read_i32_le(&begin, 4) as usize;
                            let mut body = vec![0u8; declared];
                            stream.read_exact(&mut body).await.unwrap();
                            let reply: &[u8] = if declared > 0 { b"post" } else { b"good" };
                            let mut out = BytesMut::new();
                            put_packet(
                                &mut out,
                                PacketType::RespHeader,
                                &resp_header_body(200, &[("Content-Length", "4")]),
                            );
                            put_packet(&mut out, PacketType::RespStream, reply);
                            put_packet(&mut out, PacketType::RespEnd, b"");
                            if stream.write_all(&out).await.is_err() {
                                return;
                            }
                            if first && declared > 0 {
                                // After the response is consumed, as lsphp's next
                                // readReq + script run would produce it.
                                tokio::time::sleep(Duration::from_millis(20)).await;
                                let mut evil = BytesMut::new();
                                put_packet(
                                    &mut evil,
                                    PacketType::RespHeader,
                                    &resp_header_body(200, &[("Content-Length", "4")]),
                                );
                                put_packet(&mut evil, PacketType::RespStream, b"EVIL");
                                put_packet(&mut evil, PacketType::RespEnd, b"");
                                if stream.write_all(&evil).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }));
                }
                for task in held {
                    task.abort();
                }
                connections
            });

            let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
            let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2));
            let mut builder = http::Request::builder()
                .method("PUT")
                .uri("/upload.php")
                .header("Host", "test");
            if declare_length {
                builder = builder.header("Content-Length", body_len.to_string());
            }
            let post = builder
                .body(owned_incoming(Bytes::from(vec![b'x'; body_len])))
                .unwrap();
            let response = handler.handle(&mut ctx("/web/test"), post).await.unwrap();
            assert_eq!(&collect_body(response).await[..], b"post", "{tag}");
            for _ in 0..100 {
                if pool.stats().body_conn_closes > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(pool.stats().body_conn_closes, 1, "{tag}");
            assert_eq!(pool.idle_count(), 0, "{tag}");

            for _ in 0..2 {
                let get = http::Request::builder()
                    .method("GET")
                    .uri("/index.php")
                    .header("Host", "test")
                    .body(empty_incoming())
                    .unwrap();
                let response = handler
                    .handle(&mut ctx("/web/test"), get)
                    .await
                    .unwrap_or_else(|e| panic!("{tag}: GET failed: {e:?}"));
                assert_eq!(
                    &collect_body(response).await[..],
                    b"good",
                    "{tag}: a GET received the smuggled response"
                );
            }
            // The two GETs share one re-pooled socket; the POST had its own.
            assert_eq!(server_task.await.unwrap(), 2, "{tag}");
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A BEGIN_REQUEST forged into a request body, as lsphp would run it.
fn forged_begin_request() -> Bytes {
    let env = [
        ("SCRIPT_FILENAME", "/web/test/evil.php"),
        ("SCRIPT_NAME", "/evil.php"),
        ("REQUEST_METHOD", "GET"),
        ("QUERY_STRING", ""),
        ("REMOTE_ADDR", "127.0.0.1"),
    ];
    hj_lsapi::build_begin_request_framed::<_, _, (&str, &str)>(&env, &[], &[("Host", "x")], 0)
}

/// A request body fed as separate frames, split at `cuts`.
fn framed_body(body: &[u8], cuts: &[usize]) -> hj_core::IncomingBody {
    let (mut tx, channel) = Channel::<Bytes, hj_core::BoxError>::new(1);
    let mut chunks = Vec::new();
    let mut at = 0;
    for &cut in cuts.iter().chain([&body.len()]) {
        if cut > at {
            chunks.push(Bytes::copy_from_slice(&body[at..cut]));
            at = cut;
        }
    }
    tokio::spawn(async move {
        for chunk in chunks {
            if tx.send_data(chunk).await.is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
    });
    BoxBody::new(channel)
}

/// A fake lsphp that records the body bytes it receives (up to the declared
/// length or EOF), then tries to answer. Returns the bytes, or `None` if no
/// connection arrived.
async fn recording_lsphp(listener: UnixListener) -> Option<Vec<u8>> {
    let (mut stream, _) = tokio::time::timeout(Duration::from_millis(500), listener.accept())
        .await
        .ok()?
        .unwrap();
    let (ptype, begin) = read_packet(&mut stream).await.unwrap();
    assert_eq!(ptype, PacketType::BeginRequest as u8);
    let declared = read_i32_le(&begin, 4) as usize;
    let mut received = vec![0u8; declared];
    let mut filled = 0;
    while filled < declared {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut received[filled..]))
            .await
            .expect("httpjet must deliver or end the body")
            .unwrap();
        if n == 0 {
            break;
        }
        filled += n;
    }
    received.truncate(filled);
    let mut out = BytesMut::new();
    put_packet(
        &mut out,
        PacketType::RespHeader,
        &resp_header_body(200, &[("Content-Length", "2")]),
    );
    put_packet(&mut out, PacketType::RespStream, b"ok");
    put_packet(&mut out, PacketType::RespEnd, b"");
    let _ = stream.write_all(&out).await;
    Some(received)
}

/// Regression (#1117): a forged BEGIN_REQUEST in a body PHP may leave unread is
/// never delivered to lsphp, whether the body is buffered (refused before
/// dispatch) or streamed (the upload stops short of the frame), including a frame
/// split across body frames.
#[tokio::test]
async fn embedded_begin_request_never_reaches_lsphp() {
    let frame = forged_begin_request();
    struct Case {
        tag: &'static str,
        method: &'static str,
        content_type: Option<&'static str>,
        frame_at: usize,
        declare_length: bool,
        cuts: Vec<usize>,
    }
    let cases = [
        Case {
            tag: "buffered-inline",
            method: "PUT",
            content_type: None,
            frame_at: 8192,
            declare_length: false,
            cuts: vec![],
        },
        Case {
            tag: "buffered-large",
            method: "PATCH",
            content_type: None,
            frame_at: 100 * 1024,
            declare_length: false,
            cuts: vec![4096],
        },
        Case {
            tag: "streamed",
            method: "PUT",
            content_type: Some("application/octet-stream"),
            frame_at: 8192,
            declare_length: true,
            cuts: vec![],
        },
        Case {
            tag: "streamed-straddle",
            method: "PUT",
            content_type: None,
            frame_at: 24576,
            declare_length: true,
            cuts: vec![16384, 24576 + 20],
        },
        Case {
            tag: "streamed-drip",
            method: "DELETE",
            content_type: None,
            frame_at: 3072,
            declare_length: true,
            cuts: (3000..3200).collect(),
        },
        Case {
            tag: "streamed-multipart-post",
            method: "POST",
            content_type: Some("multipart/form-data; boundary=x"),
            frame_at: 8192,
            declare_length: true,
            cuts: vec![8192 + 43],
        },
    ];
    for case in cases {
        let tag = case.tag;
        let mut body = vec![b'A'; case.frame_at];
        body.extend_from_slice(&frame);
        body.extend_from_slice(&[b'z'; 512]);
        let path = tmp_sock(tag);
        let listener = UnixListener::bind(&path).unwrap();
        let server_task = tokio::spawn(recording_lsphp(listener));
        let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
        let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(5));
        let mut builder = http::Request::builder()
            .method(case.method)
            .uri("/upload.php")
            .header("Host", "test");
        if case.declare_length {
            builder = builder.header("Content-Length", body.len().to_string());
        }
        if let Some(content_type) = case.content_type {
            builder = builder.header("Content-Type", content_type);
        }
        let request = builder.body(framed_body(&body, &case.cuts)).unwrap();
        let result = handler.handle(&mut ctx("/web/test"), request).await;
        assert!(
            matches!(result, Err(HandlerError::BadRequest)),
            "{tag}: {:?}",
            result.map(|r| r.status())
        );
        let received = server_task.await.unwrap();
        if !case.declare_length {
            assert!(received.is_none(), "{tag}: a buffered body was dispatched");
        }
        let received = received.unwrap_or_default();
        assert!(
            received.len() < case.frame_at + 44,
            "{tag}: lsphp got {} body bytes, frame at {}",
            received.len(),
            case.frame_at
        );
        assert_eq!(&received[..], &body[..received.len()], "{tag}");
        assert_eq!(pool.stats().embedded_begin_rejects, 1, "{tag}");
        assert_eq!(pool.idle_count(), 0, "{tag}");
        let _ = std::fs::remove_file(path);
    }
}

/// The scan is skipped for a POST PHP reads whole before the script runs, and a
/// clean PUT body reaches lsphp byte for byte.
#[tokio::test]
async fn preread_post_and_clean_put_bodies_are_delivered_whole() {
    let frame = forged_begin_request();
    let mut with_frame = vec![b'A'; 1000];
    with_frame.extend_from_slice(&frame);
    let mut clean = Vec::with_capacity(200_000);
    for i in 0..200_000_u32 {
        clean.push((i.wrapping_mul(2_654_435_761) >> 13) as u8);
    }
    for (tag, method, content_type, body, cuts) in [
        (
            "preread-post",
            "POST",
            "application/x-www-form-urlencoded",
            with_frame.clone(),
            vec![1010],
        ),
        (
            "clean-put",
            "PUT",
            "application/octet-stream",
            clean.clone(),
            (0..clean.len()).step_by(7919).collect::<Vec<_>>(),
        ),
    ] {
        let path = tmp_sock(tag);
        let listener = UnixListener::bind(&path).unwrap();
        let server_task = tokio::spawn(recording_lsphp(listener));
        let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
        let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(5));
        let request = http::Request::builder()
            .method(method)
            .uri("/upload.php")
            .header("Host", "test")
            .header("Content-Type", content_type)
            .header("Content-Length", body.len().to_string())
            .body(framed_body(&body, &cuts))
            .unwrap();
        let response = handler
            .handle(&mut ctx("/web/test"), request)
            .await
            .unwrap_or_else(|e| panic!("{tag}: {e:?}"));
        assert_eq!(&collect_body(response).await[..], b"ok", "{tag}");
        let received = server_task.await.unwrap().expect("dispatched");
        assert_eq!(received, body, "{tag}");
        assert_eq!(pool.stats().embedded_begin_rejects, 0, "{tag}");
        let _ = std::fs::remove_file(path);
    }
}

fn live_php_config(
    lsphp: &std::path::Path,
    children: &str,
    max_conns: u32,
) -> hj_core::config::PhpConfig {
    hj_core::config::PhpConfig {
        handler_id: "lsphp".into(),
        command: lsphp.to_path_buf(),
        suffixes: vec!["php".into()],
        env: vec![("PHP_LSAPI_CHILDREN".into(), children.into())],
        max_conns,
        init_timeout: Duration::from_secs(10),
        retry_timeout: Duration::from_secs(0),
        pc_keep_alive_timeout: Duration::from_secs(0),
        backlog: 1024,
        run_on_startup: 1,
        mem_soft_limit: None,
        mem_hard_limit: None,
        detached_mode: false,
        max_process_time: None,
        cpu_limit_secs: None,
        proc_soft_limit: None,
        proc_hard_limit: None,
        max_idle_time: None,
        min_restart_interval: Duration::from_secs(10),
        max_restart_backoff: Duration::from_secs(30),
    }
}

/// Runs `script` under the real lsphp with a request whose body carries a
/// forged BEGIN_REQUEST for `evil.php` at `frame_at`, then three GETs. Returns
/// each request's outcome and whether `evil.php` ran.
async fn live_smuggle_probe(
    tag: &str,
    method: &str,
    content_type: Option<&str>,
    script: &str,
    frame_at: usize,
    rounds: usize,
) -> (
    Vec<Result<String, HandlerError>>,
    Vec<String>,
    bool,
    hj_lsapi::PoolStats,
) {
    use hj_lsapi::{LsphpSupervisor, SupervisorConfig, build_begin_request_framed};

    let lsphp = PathBuf::from("/usr/local/lsws/lsphp8/bin/lsphp");
    assert!(lsphp.exists(), "lsphp not found at {lsphp:?}");
    let dir = std::env::temp_dir().join(format!("hj-lsapi-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("partial.php"), script).unwrap();
    std::fs::write(dir.join("hello.php"), b"<?php echo 'hello';\n").unwrap();
    std::fs::write(
        dir.join("evil.php"),
        b"<?php file_put_contents(__DIR__ . '/evil-ran', '1'); echo 'EVIL-RESPONSE';\n",
    )
    .unwrap();
    let sock = std::env::temp_dir().join(format!("php8-httpjet-{tag}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);
    let php = live_php_config(&lsphp, "1", 1);
    let sup = LsphpSupervisor::new(SupervisorConfig::from_php_config(&php, &sock, "", ""));
    sup.start().await.expect("lsphp should start");
    let pool = Arc::new(LsapiPool::new(&sock, 1, Duration::from_secs(10)));
    let handler = Lsapi::new(pool.clone())
        .script_root(&dir)
        .read_timeout(Duration::from_secs(10));

    let evil = dir.join("evil.php").to_string_lossy().into_owned();
    let env: Vec<(&str, String)> = vec![
        ("SCRIPT_FILENAME", evil),
        ("SCRIPT_NAME", "/evil.php".into()),
        ("REQUEST_URI", "/evil.php".into()),
        ("REQUEST_METHOD", "GET".into()),
        ("QUERY_STRING", String::new()),
        ("SERVER_PROTOCOL", "HTTP/1.1".into()),
        ("DOCUMENT_ROOT", dir.to_string_lossy().into_owned()),
    ];
    let forged = build_begin_request_framed(&env, &[], &[("Host", "localhost")], 0);
    let mut body = vec![b'A'; frame_at];
    body.extend_from_slice(&forged);

    let mut outcomes = Vec::new();
    let mut gets = Vec::new();
    for _ in 0..rounds {
        let mut builder = http::Request::builder()
            .method(method)
            .uri("/partial.php")
            .header("Host", "localhost")
            .header("Content-Length", body.len().to_string());
        if let Some(content_type) = content_type {
            builder = builder.header("Content-Type", content_type);
        }
        let request = builder
            .body(owned_incoming(Bytes::from(body.clone())))
            .unwrap();
        let outcome = match handler
            .handle(&mut ctx(dir.to_str().unwrap()), request)
            .await
        {
            Ok(response) => Ok(String::from_utf8_lossy(&collect_body(response).await).into_owned()),
            Err(e) => Err(e),
        };
        outcomes.push(outcome);
        for _ in 0..3 {
            let get = http::Request::builder()
                .method("GET")
                .uri("/hello.php")
                .header("Host", "localhost")
                .body(empty_incoming())
                .unwrap();
            let response = handler.handle(&mut ctx(dir.to_str().unwrap()), get).await;
            gets.push(
                String::from_utf8_lossy(&collect_body(response.expect("GET")).await).into_owned(),
            );
        }
    }
    // lsphp runs a smuggled request right after RESP_END; give it time to land.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stats = pool.stats();
    let evil_ran = dir.join("evil-ran").exists();
    sup.drain().await.unwrap();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!(
        "{tag}: outcomes={outcomes:?} evil_ran={evil_ran} embedded_begin_rejects={} \
         body_conn_closes={} unread_body_drops={}",
        stats.embedded_begin_rejects, stats.body_conn_closes, stats.unread_body_drops
    );
    (outcomes, gets, evil_ran, stats)
}

/// Asserts a live smuggle probe was refused before lsphp could run the forged
/// request.
fn assert_smuggle_refused(
    tag: &str,
    rounds: usize,
    (outcomes, gets, evil_ran, stats): (
        Vec<Result<String, HandlerError>>,
        Vec<String>,
        bool,
        hj_lsapi::PoolStats,
    ),
) {
    for outcome in &outcomes {
        assert!(
            matches!(outcome, Err(HandlerError::BadRequest)),
            "{tag}: {outcome:?}"
        );
    }
    assert!(!evil_ran, "{tag}: lsphp ran the forged request");
    assert_eq!(stats.embedded_begin_rejects, rounds as u64, "{tag}");
    for get in &gets {
        assert_eq!(get, "hello", "{tag}: a GET received the smuggled response");
    }
}

/// LIVE (#833, #1117): a script that reads `php://input` partially leaves a body
/// tail that the real lsphp parses as a new request and runs. httpjet now refuses
/// the body before the forged request reaches lsphp.
///   TMPDIR=/var/tmp/... cargo test -p hj-lsapi --test dispatch -- --ignored live_smuggled --nocapture
#[tokio::test]
#[ignore = "spawns the real lsphp; run manually on an R&D box"]
async fn live_smuggled_request_response_never_reaches_next_get() {
    // One php://input chunk: the script dequeues exactly this much. PUT, because
    // PHP swallows a POST body whose Content-Type has no handler at startup.
    let probe = live_smuggle_probe(
        "smuggle-fread",
        "PUT",
        None,
        "<?php $f = fopen('php://input', 'r'); $x = fread($f, 8192); echo 'partial:', strlen($x);\n",
        8192,
        1,
    )
    .await;
    assert_smuggle_refused("smuggle-fread", 1, probe);
}

/// LIVE (#1117): a bounded `file_get_contents` read consumes whole 8 KiB chunks,
/// so a 3072-byte read leaves a tail at 8192.
#[tokio::test]
#[ignore = "spawns the real lsphp; run manually on an R&D box"]
async fn live_smuggled_request_after_bounded_file_get_contents_is_refused() {
    let probe = live_smuggle_probe(
        "smuggle-fgc",
        "PUT",
        None,
        "<?php $x = file_get_contents('php://input', false, null, 0, 3072); echo 'partial:', strlen($x);\n",
        8192,
        1,
    )
    .await;
    assert_smuggle_refused("smuggle-fgc", 1, probe);
}

/// LIVE (#1117): `stream_get_contents($s, 16385)` leaves a tail at the next 8 KiB
/// boundary past the read, 24576.
#[tokio::test]
#[ignore = "spawns the real lsphp; run manually on an R&D box"]
async fn live_smuggled_request_after_stream_get_contents_is_refused() {
    let probe = live_smuggle_probe(
        "smuggle-sgc",
        "PUT",
        None,
        "<?php $s = fopen('php://input', 'r'); $x = stream_get_contents($s, 16385); echo 'partial:', strlen($x);\n",
        24576,
        1,
    )
    .await;
    assert_smuggle_refused("smuggle-sgc", 1, probe);
}

/// LIVE (#835, #1117): a small multipart POST without a boundary is NOT pre-read
/// by PHP (rfc1867 exits early), so its body is scanned like a PUT's and the
/// forged request is refused every round; no GET ever sees a smuggled response.
///   cargo test -p hj-lsapi --test dispatch -- --ignored live_multipart --nocapture
#[tokio::test]
#[ignore = "spawns the real lsphp; run manually on an R&D box"]
async fn live_multipart_without_boundary_never_leaks_a_smuggled_response() {
    let rounds = 40;
    let probe = live_smuggle_probe(
        "smuggle-multipart",
        "POST",
        Some("multipart/form-data"),
        "<?php $f = fopen('php://input', 'r'); $x = fread($f, 8192); echo 'partial:', strlen($x);\n",
        8192,
        rounds,
    )
    .await;
    assert_smuggle_refused("smuggle-multipart", rounds, probe);
}

/// LIVE perf probe (#833): POST cost now that every bodied connection is closed
/// after its response. Run with `--release`:
///   cargo test --release -p hj-lsapi --test dispatch -- --ignored live_post_reconnect_cost --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "spawns the real lsphp; benchmark, run manually on an R&D box"]
async fn live_post_reconnect_cost() {
    use hj_lsapi::{LsphpSupervisor, SupervisorConfig};

    let lsphp = PathBuf::from("/usr/local/lsws/lsphp8/bin/lsphp");
    if !lsphp.exists() {
        eprintln!("lsphp not found at {lsphp:?}; skipping");
        return;
    }
    let n: usize = std::env::var("HJ_BENCH_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let dir = std::env::temp_dir().join(format!("hj-lsapi-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("post.php"), b"<?php echo count($_POST);\n").unwrap();
    std::fs::write(dir.join("hello.php"), b"<?php echo 'hello';\n").unwrap();
    let sock = std::env::temp_dir().join(format!("php8-httpjet-bench-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);
    let php = live_php_config(&lsphp, "4", 4);
    let sup = LsphpSupervisor::new(SupervisorConfig::from_php_config(&php, &sock, "", ""));
    sup.start().await.expect("lsphp should start");
    let pool = Arc::new(LsapiPool::new(&sock, 4, Duration::from_secs(10)));
    let handler = Arc::new(
        Lsapi::new(pool.clone())
            .script_root(&dir)
            .read_timeout(Duration::from_secs(10)),
    );
    const FORM: &[u8] = b"_xfToken=1700000000%2Cabcdef0123456789abcdef0123456789&_xfResponseType=json&_xfWithData=1&_xfRequestUri=%2Fthreads%2Fexample.123%2F&visible=1&url=https%3A%2F%2Fexample.test%2F";
    let doc_root = dir.to_string_lossy().into_owned();
    let one = {
        let handler = handler.clone();
        let doc_root = doc_root.clone();
        move |post: bool| {
            let handler = handler.clone();
            let doc_root = doc_root.clone();
            async move {
                let builder = http::Request::builder().header("Host", "localhost");
                let req = if post {
                    builder
                        .method("POST")
                        .uri("/post.php")
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("Content-Length", FORM.len().to_string())
                        .body(full_incoming(FORM))
                        .unwrap()
                } else {
                    builder
                        .method("GET")
                        .uri("/hello.php")
                        .body(empty_incoming())
                        .unwrap()
                };
                let started = std::time::Instant::now();
                let response = handler.handle(&mut ctx(&doc_root), req).await.unwrap();
                let body = collect_body(response).await;
                assert!(!body.is_empty());
                started.elapsed()
            }
        }
    };
    let report = |label: &str, mut samples: Vec<Duration>, wall: Duration| {
        samples.sort();
        let mean = samples.iter().sum::<Duration>() / samples.len() as u32;
        let pct = |p: f64| samples[((samples.len() as f64 * p) as usize).min(samples.len() - 1)];
        eprintln!(
            "{label:<16} n={} mean={:>7.1}us p50={:>7.1}us p99={:>7.1}us rps={:>8.0}",
            samples.len(),
            mean.as_secs_f64() * 1e6,
            pct(0.50).as_secs_f64() * 1e6,
            pct(0.99).as_secs_f64() * 1e6,
            samples.len() as f64 / wall.as_secs_f64()
        );
    };
    for _ in 0..200 {
        one(true).await;
        one(false).await;
    }
    for post in [false, true] {
        let label = if post { "POST seq" } else { "GET seq" };
        let started = std::time::Instant::now();
        let mut samples = Vec::with_capacity(n);
        for _ in 0..n {
            samples.push(one(post).await);
        }
        report(label, samples, started.elapsed());

        let label = if post { "POST conc=4" } else { "GET conc=4" };
        let started = std::time::Instant::now();
        let tasks: Vec<_> = (0..4)
            .map(|_| {
                let one = one.clone();
                tokio::spawn(async move {
                    let mut samples = Vec::with_capacity(n / 4);
                    for _ in 0..n / 4 {
                        samples.push(one(post).await);
                    }
                    samples
                })
            })
            .collect();
        let mut samples = Vec::with_capacity(n);
        for task in tasks {
            samples.extend(task.await.unwrap());
        }
        report(label, samples, started.elapsed());
    }
    // Isolates the reconnect itself: a bodyless GET on a fresh dial every time.
    let last_pid = || {
        std::fs::read_to_string("/proc/sys/kernel/ns_last_pid")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    let pid_before = last_pid();
    let started = std::time::Instant::now();
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        pool.clear();
        samples.push(one(false).await);
    }
    report("GET fresh-dial", samples, started.elapsed());
    eprintln!(
        "pids allocated during fresh-dial loop: {}",
        last_pid().saturating_sub(pid_before)
    );
    eprintln!("stats={:?}", pool.stats());
    sup.drain().await.unwrap();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// How a fake lsphp ends a response that carries no Content-Length.
#[derive(Clone, Copy)]
enum UnframedEnd {
    RespEnd,
    ConnClose,
    Eof,
}

/// Fake lsphp: RESP_HEADER without Content-Length, then `chunk`, then `end`.
/// `stream` forces the streaming path by holding the first chunk back until
/// the handler has returned the response head.
async fn unframed_response(
    tag: &str,
    end: UnframedEnd,
    stream: bool,
) -> (Result<Bytes, String>, Arc<LsapiPool>) {
    let path = tmp_sock(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, _) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let mut head = BytesMut::new();
        put_packet(
            &mut head,
            PacketType::RespHeader,
            &resp_header_body(200, &[("Content-Type", "text/html")]),
        );
        let mut tail = BytesMut::new();
        put_packet(&mut tail, PacketType::RespStream, b"abc");
        match end {
            UnframedEnd::RespEnd => put_packet(&mut tail, PacketType::RespEnd, b""),
            UnframedEnd::ConnClose => put_packet(&mut tail, PacketType::ConnClose, b""),
            UnframedEnd::Eof => {}
        }
        if stream {
            s.write_all(&head).await.unwrap();
            s.flush().await.unwrap();
            release_rx.await.unwrap();
            s.write_all(&tail).await.unwrap();
        } else {
            head.extend_from_slice(&tail);
            s.write_all(&head).await.unwrap();
        }
        s.flush().await.unwrap();
        if matches!(end, UnframedEnd::Eof) {
            drop(s);
            let _ = done_rx.await;
        } else {
            let _ = done_rx.await;
        }
    });

    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(1));
    let request = http::Request::builder()
        .uri("/index.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let result = match handler.handle(&mut ctx("/web/test"), request).await {
        Err(e) => {
            let _ = release_tx.send(());
            Err(e.to_string())
        }
        Ok(response) => {
            let _ = release_tx.send(());
            match response.into_body() {
                hj_core::Body::Full(bytes) => Ok(bytes),
                hj_core::Body::Stream(body) => body
                    .collect()
                    .await
                    .map(|b| b.to_bytes())
                    .map_err(|e| e.to_string()),
                other => panic!("unexpected body: {:?}", std::mem::discriminant(&other)),
            }
        }
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    let _ = done_tx.send(());
    server_task.await.unwrap();
    let _ = std::fs::remove_file(path);
    (result, pool)
}

/// Regression (#594): without a Content-Length, RESP_END is the only completion
/// signal. A worker that dies mid-response (EOF) or sends CONN_CLOSE first must
/// surface as an error, never as a clean, cacheable short body.
#[tokio::test]
async fn unframed_response_ending_before_resp_end_is_an_error() {
    for stream in [true, false] {
        for (end, name) in [
            (UnframedEnd::ConnClose, "connclose"),
            (UnframedEnd::Eof, "eof"),
        ] {
            let tag = format!(
                "unframed-{name}-{}",
                if stream { "stream" } else { "inline" }
            );
            let (result, pool) = unframed_response(&tag, end, stream).await;
            let err = result.expect_err(&format!("{tag}: truncated body ended cleanly"));
            assert!(err.contains("RESP_END"), "{tag}: {err}");
            assert_eq!(pool.idle_count(), 0, "{tag}: socket must not be re-pooled");
        }
        let tag = format!(
            "unframed-respend-{}",
            if stream { "stream" } else { "inline" }
        );
        let (result, pool) = unframed_response(&tag, UnframedEnd::RespEnd, stream).await;
        assert_eq!(&result.expect("clean RESP_END")[..], b"abc", "{tag}");
        assert_eq!(pool.idle_count(), 1, "{tag}: clean socket must be reusable");
    }
}

/// Streams `chunks` one byte-chunk at a time, `gap` apart, then (if `stall`)
/// holds the body open without ending it.
fn dripping_body(chunks: usize, gap: Duration, stall: bool) -> hj_core::IncomingBody {
    let (mut tx, channel) = Channel::<Bytes, hj_core::BoxError>::new(1);
    tokio::spawn(async move {
        for i in 0..chunks {
            tokio::time::sleep(gap).await;
            if tx
                .send_data(Bytes::from(vec![b'a' + i as u8]))
                .await
                .is_err()
            {
                return;
            }
        }
        if stall {
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
        drop(tx);
    });
    BoxBody::new(channel)
}

/// #660: an upload that keeps making progress for longer than `read_timeout`
/// (and `max_process_time`) must not 504 — the response clocks start once the
/// body has been delivered, as LSWS's extapp timeout does.
#[tokio::test]
async fn slow_progressing_upload_outlives_response_read_timeout() {
    let path = tmp_sock("slow-upload");
    let listener = UnixListener::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (ptype, begin) = read_packet(&mut stream).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let mut body = vec![0; req_body_len_from_begin(&begin) as usize];
        stream.read_exact(&mut body).await.unwrap();
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[("Content-Length", "2")]),
        );
        put_packet(&mut out, PacketType::RespStream, b"ok");
        put_packet(&mut out, PacketType::RespEnd, b"");
        stream.write_all(&out).await.unwrap();
        stream.flush().await.unwrap();
        body
    });

    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
    let handler = Lsapi::new(pool)
        .read_timeout(Duration::from_millis(500))
        .max_process_time(Some(Duration::from_millis(800)));
    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Length", "10")
        .body(dripping_body(10, Duration::from_millis(150), false))
        .unwrap();
    let resp = handler
        .handle(&mut ctx("/web/test"), req)
        .await
        .expect("a progressing upload must not time out");
    assert_eq!(resp.status(), 200);
    let body = match resp.into_body() {
        hj_core::Body::Full(b) => b,
        hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        other => panic!("unexpected body {:?}", std::mem::discriminant(&other)),
    };
    assert_eq!(&body[..], b"ok");
    assert_eq!(server_task.await.unwrap(), b"abcdefghij");
    let _ = std::fs::remove_file(path);
}

/// #660 companion: a genuinely stalled upload is still bounded — the pump's idle
/// timer aborts it, which arms the response timer, so a worker that never
/// answers yields a 504 instead of hanging.
#[tokio::test]
async fn stalled_upload_still_times_out() {
    let path = tmp_sock("stalled-upload");
    let listener = UnixListener::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (ptype, begin) = read_packet(&mut stream).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let mut body = vec![0; req_body_len_from_begin(&begin) as usize];
        let short = stream.read_exact(&mut body).await.is_err();
        // Hold the socket without answering, like a wedged worker.
        tokio::time::sleep(Duration::from_secs(5)).await;
        short
    });

    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
    let handler = Lsapi::new(pool).read_timeout(Duration::from_millis(500));
    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Length", "10")
        .body(dripping_body(2, Duration::from_millis(50), true))
        .unwrap();
    let started = std::time::Instant::now();
    let result = handler.handle(&mut ctx("/web/test"), req).await;
    let elapsed = started.elapsed();
    assert!(
        matches!(result, Err(HandlerError::GatewayTimeout)),
        "stalled upload must 504, got {:?}",
        result.map(|r| r.status())
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "stalled upload must be bounded, took {elapsed:?}"
    );
    assert!(
        server_task.await.unwrap(),
        "lsphp must see the truncated body"
    );
    let _ = std::fs::remove_file(path);
}

/// #660 follow-up: the Tier-2 in-flight clock starts when the upload finishes, so a
/// slow but progressing upload cannot age into the hung-worker kill.
#[tokio::test]
async fn progressing_upload_is_not_counted_in_flight() {
    let path = tmp_sock("inflight-upload");
    let listener = UnixListener::bind(&path).unwrap();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (_, begin) = read_packet(&mut stream).await.unwrap();
        seen_tx.send(()).unwrap();
        let mut body = vec![0; req_body_len_from_begin(&begin) as usize];
        stream.read_exact(&mut body).await.unwrap();
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[("Content-Length", "2")]),
        );
        put_packet(&mut out, PacketType::RespStream, b"ok");
        put_packet(&mut out, PacketType::RespEnd, b"");
        stream.write_all(&out).await.unwrap();
    });
    let sup = Arc::new(LsphpSupervisor::new(SupervisorConfig {
        command: PathBuf::from("/nonexistent/lsphp-inflight-upload"),
        socket_path: path.clone(),
        children: 1,
        max_requests: 0,
        env: vec![],
        backlog: 8,
        user: String::new(),
        group: String::new(),
        start_timeout: Duration::from_millis(50),
        limits: Default::default(),
        min_restart_interval: Duration::from_secs(1800),
        max_restart_backoff: Duration::from_secs(30),
        jail: Default::default(),
        socket_source: Default::default(),
        retry_timeout: Duration::ZERO,
    }));
    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
    let (monitor, ticker) = Monitor::spawn(MonitorConfig::new(sup.clone(), pool.clone()));
    let token = monitor.cancel_token();
    token.cancel();
    let _ = ticker.await;
    let inflight = monitor.inflight();
    let handler = Lsapi::new(pool).monitor(monitor);
    let req = http::Request::builder()
        .method("POST")
        .uri("/upload.php")
        .header("Host", "test")
        .header("Content-Length", "6")
        .body(dripping_body(6, Duration::from_millis(50), false))
        .unwrap();
    let request = tokio::spawn(async move { handler.handle(&mut ctx("/web/test"), req).await });
    seen_rx.await.unwrap();
    assert!(
        inflight.oldest_age().is_none(),
        "upload time counted toward the Tier-2 hung-worker clock"
    );
    assert_eq!(request.await.unwrap().expect("ok").status(), 200);
    server_task.await.unwrap();
    let _ = std::fs::remove_file(path);
}

async fn get(handler: &Lsapi, uri: &str) -> Result<hj_core::Response, HandlerError> {
    let req = http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    handler.handle(&mut ctx("/web/test"), req).await
}

async fn body_bytes(resp: hj_core::Response) -> Bytes {
    match resp.into_parts().1 {
        hj_core::Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        hj_core::Body::Full(b) => b,
        _ => panic!("stream or full"),
    }
}

/// `litespeed_finish_request()` (LSAPI_End_Response_r) writes RESP_END and
/// CONN_CLOSE together and closes the socket. That socket must not be pooled:
/// the next bodiless GET reuses pooled sockets unprobed and would hit EPIPE.
#[tokio::test]
async fn finish_request_conn_close_is_not_repooled() {
    for streamed in [false, true] {
        let path = tmp_sock(if streamed {
            "finish-streamed"
        } else {
            "finish-inline"
        });
        let listener = UnixListener::bind(&path).unwrap();
        let server_task = tokio::spawn(async move {
            for i in 0..2u8 {
                let (mut s, _) = listener.accept().await.unwrap();
                let (p, _) = read_packet(&mut s).await.unwrap();
                assert_eq!(p, PacketType::BeginRequest as u8);
                let mut head = BytesMut::new();
                put_packet(
                    &mut head,
                    PacketType::RespHeader,
                    &resp_header_body(200, &[("X-Conn", &i.to_string())]),
                );
                let mut tail = BytesMut::new();
                put_packet(&mut tail, PacketType::RespStream, b"done");
                put_packet(&mut tail, PacketType::RespEnd, b"");
                put_packet(&mut tail, PacketType::ConnClose, b"");
                if streamed {
                    s.write_all(&head).await.unwrap();
                    s.flush().await.unwrap();
                    tokio::time::sleep(Duration::from_millis(30)).await;
                } else {
                    head.extend_from_slice(&tail);
                    tail = head;
                }
                s.write_all(&tail).await.unwrap();
                s.flush().await.unwrap();
                drop(s);
            }
        });

        let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
        let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2));
        let resp1 = get(&handler, "/a.php").await.expect("req1 ok");
        assert_eq!(&body_bytes(resp1).await[..], b"done");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            pool.idle_count(),
            0,
            "streamed={streamed}: a CONN_CLOSE'd socket must not be pooled"
        );

        let resp2 = get(&handler, "/b.php")
            .await
            .expect("req2 ok on a fresh dial");
        assert_eq!(resp2.headers().get("x-conn").unwrap(), "1");
        assert!(
            resp2
                .extensions()
                .get::<hj_lsapi::LsapiRetryInfo>()
                .is_none(),
            "streamed={streamed}: req2 must not need a retry"
        );
        server_task.await.unwrap();
        let _ = std::fs::remove_file(&path);
    }
}

/// lsphp closed a pooled keep-alive (LSAPI_MAX_IDLE / max-requests exit) with
/// no CONN_CLOSE. The unprobed reuse fails BEGIN_REQUEST with EPIPE; that must
/// retry on a fresh dial (even with no monitor/breaker), not 502 or restart.
#[tokio::test]
async fn closed_idle_socket_reuse_retries_as_stale_reuse() {
    let path = tmp_sock("stale-epipe");
    let listener = UnixListener::bind(&path).unwrap();
    let closed = Arc::new(tokio::sync::Notify::new());
    let closed_srv = closed.clone();
    let server_task = tokio::spawn(async move {
        let (mut s1, _) = listener.accept().await.unwrap();
        let (p, _) = read_packet(&mut s1).await.unwrap();
        assert_eq!(p, PacketType::BeginRequest as u8);
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[("X-Conn", "0")]),
        );
        put_packet(&mut out, PacketType::RespStream, b"one");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s1.write_all(&out).await.unwrap();
        s1.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(s1);
        closed_srv.notify_one();

        let (mut s2, _) = listener.accept().await.unwrap();
        let (p, _) = read_packet(&mut s2).await.unwrap();
        assert_eq!(p, PacketType::BeginRequest as u8);
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[("X-Conn", "1")]),
        );
        put_packet(&mut out, PacketType::RespStream, b"two");
        put_packet(&mut out, PacketType::RespEnd, b"");
        s2.write_all(&out).await.unwrap();
        s2.flush().await.unwrap();
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(100), s2.read(&mut sink)).await;
    });

    let pool = Arc::new(LsapiPool::new(&path, 4, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2));
    let resp1 = get(&handler, "/a.php").await.expect("req1 ok");
    assert_eq!(&body_bytes(resp1).await[..], b"one");
    assert_eq!(pool.idle_count(), 1, "clean keep-alive is pooled");
    closed.notified().await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let resp2 = get(&handler, "/b.php")
        .await
        .expect("req2 must succeed via a fresh dial");
    assert_eq!(resp2.headers().get("x-conn").unwrap(), "1");
    assert_eq!(
        resp2
            .extensions()
            .get::<hj_lsapi::LsapiRetryInfo>()
            .map(|r| r.kind),
        Some("stale_reuse")
    );
    assert_eq!(&body_bytes(resp2).await[..], b"two");
    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

async fn stale_get(handler: &Lsapi, uri: &str) -> Result<hj_core::Response, HandlerError> {
    let req = http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    handler.handle(&mut ctx("/web/test"), req).await
}

/// Regression (#740 follow-up): a whole lsphp family dies (master crash / hard restart) while N>=3 keep-alive
/// sockets sit idle in the pool. The next GET should still succeed on a fresh dial.
#[tokio::test]
async fn many_stale_idle_sockets_do_not_fail_the_next_get() {
    let path = tmp_sock("xv-many-stale");
    let listener = UnixListener::bind(&path).unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let dead = Arc::new(tokio::sync::Notify::new());
    let dead_srv = dead.clone();
    let b2 = barrier.clone();
    let server_task = tokio::spawn(async move {
        let mut socks = Vec::new();
        for i in 0..3u8 {
            let (s, _) = listener.accept().await.unwrap();
            socks.push((i, s));
        }
        // Answer all three after all three are accepted (forces 3 distinct conns).
        for (i, s) in socks.iter_mut() {
            let (p, _) = read_packet(s).await.unwrap();
            assert_eq!(p, PacketType::BeginRequest as u8);
            let mut out = BytesMut::new();
            put_packet(
                &mut out,
                PacketType::RespHeader,
                &resp_header_body(200, &[("X-Conn", &i.to_string())]),
            );
            put_packet(&mut out, PacketType::RespStream, b"ok");
            put_packet(&mut out, PacketType::RespEnd, b"");
            s.write_all(&out).await.unwrap();
            s.flush().await.unwrap();
        }
        b2.wait().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(socks); // family dies
        dead_srv.notify_one();
        // New family: answer on fresh dials.
        loop {
            let Ok(Ok((mut s, _))) =
                tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
            else {
                break;
            };
            let (p, _) = read_packet(&mut s).await.unwrap();
            assert_eq!(p, PacketType::BeginRequest as u8);
            let mut out = BytesMut::new();
            put_packet(
                &mut out,
                PacketType::RespHeader,
                &resp_header_body(200, &[("X-Conn", "fresh")]),
            );
            put_packet(&mut out, PacketType::RespStream, b"ok");
            put_packet(&mut out, PacketType::RespEnd, b"");
            s.write_all(&out).await.unwrap();
            s.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let pool = Arc::new(LsapiPool::new(&path, 8, Duration::from_secs(2)).with_circuit_breaker());
    let handler = Arc::new(Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2)));
    let mut js = Vec::new();
    for i in 0..3 {
        let h = handler.clone();
        js.push(tokio::spawn(async move {
            let r = stale_get(&h, &format!("/p{i}.php")).await.expect("warm ok");
            let _ = r.into_parts().1;
        }));
    }
    for j in js {
        j.await.unwrap();
    }
    barrier.wait().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    dead.notified().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    let resp = stale_get(&handler, "/after.php")
        .await
        .expect("a stale pool must not turn a GET into a 502");
    assert_eq!(resp.status(), 200);
    drop(resp);
    assert!(stale_get(&handler, "/after2.php").await.is_ok());
    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

/// Regression (#950): lsphp reports a non-indexed header by the name text in the
/// header block, so it must carry the conventional Title-Case, not the `http`
/// crate's lower-case (webhook code reads `getallheaders()['X-Hub-Signature-256']`).
#[tokio::test]
async fn unknown_header_names_reach_lsphp_title_cased() {
    let path = tmp_sock("titlecase");
    let listener = UnixListener::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (ptype, body) = read_packet(&mut s).await.unwrap();
        assert_eq!(ptype, PacketType::BeginRequest as u8);
        let (env, env_end) = parse_begin_env(&body);
        let unknown = read_i32_le(&body, 24) as usize;
        let header_len = read_i32_le(&body, 0) as usize;
        let pad = (8 - ((PACKET_HEADER_LEN + env_end) % 8)) % 8;
        let unknown_at = env_end + pad + HEADER_INDEX_LEN;
        let raw_at = unknown_at + unknown * 16;
        let raw = &body[raw_at..raw_at + header_len];
        let mut names = Vec::new();
        for i in 0..unknown {
            let slot = unknown_at + i * 16;
            let off = read_i32_le(&body, slot) as usize;
            let len = read_i32_le(&body, slot + 4) as usize;
            names.push(String::from_utf8(raw[off..off + len].to_vec()).unwrap());
        }
        let mut out = BytesMut::new();
        put_packet(
            &mut out,
            PacketType::RespHeader,
            &resp_header_body(200, &[("Content-Type", "text/plain")]),
        );
        put_packet(&mut out, PacketType::RespEnd, b"");
        s.write_all(&out).await.unwrap();
        s.flush().await.unwrap();
        let mut sink = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(100), s.read(&mut sink)).await;
        (env, names)
    });

    let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(2)));
    // Every HTTP_* copy, so the env names are checked alongside the block's.
    let handler = Lsapi::new(pool)
        .read_timeout(Duration::from_secs(2))
        .full_header_env(true);
    let req = http::Request::builder()
        .uri("/index.php")
        .header("Host", "test")
        .header("x-hub-signature-256", "sha256=abc")
        .header("X-GitHub-Event", "push")
        .header("dnt", "1")
        .header("user-agent", "ua")
        .body(empty_incoming())
        .unwrap();
    let resp = handler.handle(&mut ctx("/web/test"), req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let (env, names) = server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(
        names.contains(&"X-Hub-Signature-256".to_string()),
        "{names:?}"
    );
    assert!(names.contains(&"X-Github-Event".to_string()), "{names:?}");
    assert!(names.contains(&"Dnt".to_string()), "{names:?}");
    // Well-known headers ride the index table, never the unknown one.
    assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("user-agent")));
    assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("host")));
    // HTTP_* names are case-independent and unchanged.
    assert_eq!(env["HTTP_X_HUB_SIGNATURE_256"], "sha256=abc");
    assert_eq!(env["HTTP_X_GITHUB_EVENT"], "push");
}

/// Regression (#949): a streamed script response sent with `X-Accel-Buffering: no`
/// carries the unbuffered-feed marker the transport bridge streams on; an ordinary
/// streamed render does not, so it keeps the buffered path.
#[tokio::test]
async fn accel_buffering_off_stream_is_marked_unbuffered() {
    for (tag, accel, marked) in [
        ("accel-no", Some("no"), true),
        ("accel-yes", Some("yes"), false),
        ("accel-none", None, false),
    ] {
        let path = tmp_sock(tag);
        let listener = UnixListener::bind(&path).unwrap();
        let mut headers = vec![("Content-Type", "application/x-ndjson")];
        if let Some(v) = accel {
            headers.push(("X-Accel-Buffering", v));
        }
        let header = {
            let mut out = BytesMut::new();
            put_packet(
                &mut out,
                PacketType::RespHeader,
                &resp_header_body(200, &headers),
            );
            out
        };
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (ptype, _) = read_packet(&mut stream).await.unwrap();
            assert_eq!(ptype, PacketType::BeginRequest as u8);
            stream.write_all(&header).await.unwrap();
            stream.flush().await.unwrap();
            release_rx.await.unwrap();
            let mut out = BytesMut::new();
            put_packet(&mut out, PacketType::RespStream, b"{}\n");
            put_packet(&mut out, PacketType::RespEnd, b"");
            stream.write_all(&out).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let pool = Arc::new(LsapiPool::new(&path, 1, Duration::from_secs(1)));
        let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(1));
        let request = http::Request::builder()
            .uri("/index.php")
            .header("Host", "test")
            .body(empty_incoming())
            .unwrap();
        let response = handler
            .handle(&mut ctx("/web/test"), request)
            .await
            .expect("valid response head");
        assert_eq!(
            response
                .extensions()
                .get::<hj_core::ProxiedBody>()
                .is_some(),
            marked,
            "{tag}"
        );
        release_tx.send(()).unwrap();
        let hj_core::Body::Stream(stream) = response.into_body() else {
            panic!("{tag}: the held body must stream");
        };
        assert_eq!(&stream.collect().await.unwrap().to_bytes()[..], b"{}\n");
        server_task.await.unwrap();
        let _ = std::fs::remove_file(path);
    }
}

/// LIVE parity gate for leaving header copies out of the env table: the same
/// requests through a handler that sends every `HTTP_*` copy and one that leaves
/// out what lsphp registers from the header block must produce byte-identical
/// `$_SERVER` (keys, values and order), `$_ENV`, `getallheaders()`, `getenv()` and body.
///
///   cargo test -p hj-lsapi --test dispatch -- --ignored live_server_vars_match_without_block_registered_env_copies --nocapture
#[tokio::test]
#[ignore = "spawns the real lsphp; run manually on an R&D box"]
async fn live_server_vars_match_without_block_registered_env_copies() {
    use hj_lsapi::{LsphpSupervisor, SupervisorConfig};

    let lsphp = PathBuf::from(
        std::env::var("HJ_TEST_LSPHP")
            .unwrap_or_else(|_| "/usr/local/lsws/lsphp8/bin/lsphp".into()),
    );
    if !lsphp.exists() {
        eprintln!("lsphp not found at {lsphp:?}; skipping");
        return;
    }
    let dir = std::env::temp_dir().join(format!("hj-lsapi-parity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dump.php"),
        br#"<?php
$s = $_SERVER;
unset($s['REQUEST_TIME'], $s['REQUEST_TIME_FLOAT']);
// A fresh worker's first request still sees lsphp's own LSAPI_* process env.
foreach (array_keys($s) as $k) {
    if (strncmp($k, 'LSAPI_', 6) === 0) unset($s[$k]);
}
$g = [];
foreach (['HTTP_USER_AGENT', 'HTTP_HOST', 'HTTP_ACCEPT', 'HTTP_X_DUP', 'HTTP_COOKIE',
          'HTTP_CONTENT_TYPE', 'CONTENT_TYPE', 'HTTP_TRANSFER_ENCODING', 'HTTP_X_FROM_REWRITE'] as $k) {
    $g[$k] = getenv($k);
}
$e = $_ENV;
foreach (array_keys($e) as $k) {
    if (strncmp($k, 'LSAPI_', 6) === 0) unset($e[$k]);
}
echo json_encode(['server' => $s, 'env' => $e, 'headers' => getallheaders(), 'getenv' => $g,
                  'input' => file_get_contents('php://input')],
                 JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
"#,
    )
    .unwrap();

    let sock =
        std::env::temp_dir().join(format!("php8-httpjet-parity-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);
    let php = hj_core::config::PhpConfig {
        handler_id: "lsphp".into(),
        command: lsphp.clone(),
        suffixes: vec!["php".into()],
        env: vec![("PHP_LSAPI_CHILDREN".into(), "2".into())],
        max_conns: 4,
        init_timeout: Duration::from_secs(10),
        retry_timeout: Duration::from_secs(0),
        pc_keep_alive_timeout: Duration::from_secs(0),
        backlog: 1024,
        run_on_startup: 1,
        mem_soft_limit: None,
        mem_hard_limit: None,
        detached_mode: false,
        max_process_time: None,
        cpu_limit_secs: None,
        proc_soft_limit: None,
        proc_hard_limit: None,
        max_idle_time: None,
        min_restart_interval: Duration::from_secs(10),
        max_restart_backoff: Duration::from_secs(30),
    };
    let sup = LsphpSupervisor::new(SupervisorConfig::from_php_config(&php, &sock, "", ""));
    sup.start().await.expect("lsphp should start");
    let pool = Arc::new(LsapiPool::new(&sock, 4, Duration::from_secs(10)));
    let full = Lsapi::new(pool.clone())
        .script_root(&dir)
        .read_timeout(Duration::from_secs(10))
        .full_header_env(true);
    let lean = Lsapi::new(pool)
        .script_root(&dir)
        .read_timeout(Duration::from_secs(10))
        .full_header_env(false);

    let long_name = format!("x-{}", "a".repeat(258));
    let cf: Vec<(&str, &[u8])> = vec![
        (
            "user-agent",
            b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
        ),
        ("accept", b"text/html,application/xhtml+xml,*/*;q=0.8"),
        ("accept-language", b"en-US,en;q=0.9"),
        ("accept-encoding", b"gzip, br, zstd"),
        ("cookie", b"xf_csrf=Qm3pX9aL; xf_session=4a1f0c9b"),
        ("referer", b"https://www.google.com/"),
        ("cf-ray", b"8d6f2e9a1b3c4d5e-ORD"),
        ("cf-connecting-ip", b"203.0.113.42"),
        ("x-forwarded-for", b"203.0.113.42"),
        ("x-forwarded-proto", b"https"),
        ("cf-ipcountry", b"US"),
        ("cf-visitor", b"{\"scheme\":\"https\"}"),
        ("cdn-loop", b"cloudflare; loops=1"),
        (
            "sec-ch-ua",
            b"\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        ),
        ("sec-ch-ua-mobile", b"?0"),
        ("sec-fetch-site", b"same-origin"),
        ("if-none-match", b"W/\"abc\""),
        ("priority", b"u=0, i"),
    ];
    struct Case<'a> {
        label: &'a str,
        method: &'a str,
        uri: &'a str,
        headers: Vec<(&'a str, &'a [u8])>,
        body: &'static [u8],
        tls: bool,
        trusted: bool,
        env: Vec<(&'a str, &'a str)>,
    }
    let case = |label, method, uri, headers, body, tls, trusted| Case {
        label,
        method,
        uri,
        headers,
        body,
        tls,
        trusted,
        env: vec![],
    };
    let mut cases = vec![
        case(
            "CF h2 GET",
            "GET",
            "https://forum.example/dump.php?a=1",
            cf.clone(),
            b"",
            true,
            true,
        ),
        case(
            "CF h2 GET, untrusted peer",
            "GET",
            "https://forum.example/dump.php",
            cf.clone(),
            b"",
            true,
            false,
        ),
        case(
            "h1 Host with default port",
            "GET",
            "/dump.php",
            vec![
                ("host", b"www.forum.example:443"),
                ("user-agent", b"curl/8"),
            ],
            b"",
            true,
            true,
        ),
        case(
            "h1 Host with a non-default port",
            "GET",
            "/dump.php?x=%20y",
            vec![("host", b"forum.example:8443"), ("accept", b"*/*")],
            b"",
            true,
            true,
        ),
        case(
            "repeated headers",
            "GET",
            "/dump.php",
            vec![
                ("host", b"forum.example"),
                ("accept", b"text/html"),
                ("accept", b"*/*"),
                ("x-dup", b"one"),
                ("x-dup", b"two"),
                ("cookie", b"a=1"),
                ("cookie", b"b=2"),
                ("via", b"1.1 a"),
                ("via", b"1.1 b"),
            ],
            b"",
            false,
            true,
        ),
        case(
            "form POST",
            "POST",
            "/dump.php",
            vec![
                ("host", b"forum.example"),
                ("content-type", b"application/x-www-form-urlencoded"),
                ("content-length", b"7"),
                ("x-requested-with", b"XMLHttpRequest"),
                ("origin", b"https://forum.example"),
            ],
            b"a=1&b=2",
            true,
            true,
        ),
        case(
            "chunked POST (buffered, synthesized length)",
            "POST",
            "/dump.php",
            vec![
                ("host", b"forum.example"),
                ("content-type", b"text/plain"),
                ("transfer-encoding", b"chunked"),
            ],
            b"abc",
            true,
            true,
        ),
        case(
            "dropped, long, non-UTF-8, empty and every well-known header",
            "GET",
            "/dump.php",
            vec![
                ("host", b"forum.example"),
                ("proxy", b"http://evil/"),
                ("x_under", b"v"),
                (long_name.as_str(), b"long"),
                ("x-latin1", b"caf\xe9"),
                ("x-empty", b""),
                ("accept-charset", b"utf-8"),
                ("authorization", b"Basic YWxhZGRpbjpvcGVuc2VzYW1l"),
                ("connection", b"keep-alive"),
                ("cookie2", b"$Version=1"),
                ("pragma", b"no-cache"),
                ("cache-control", b"no-cache"),
                ("if-modified-since", b"Sun, 25 Oct 2026 00:00:00 GMT"),
                ("if-match", b"\"x\""),
                ("if-range", b"\"x\""),
                ("if-unmodified-since", b"Sun, 25 Oct 2026 00:00:00 GMT"),
                ("keep-alive", b"300"),
                ("range", b"bytes=0-1"),
                ("x-forwarded-for", b"198.51.100.1, 203.0.113.42"),
                ("via", b"1.1 cf"),
                ("x-1-digit-lead", b"1"),
            ],
            b"",
            false,
            true,
        ),
        case(
            "speculation prefetch",
            "GET",
            "https://forum.example/dump.php",
            vec![
                ("sec-purpose", b"prefetch;prerender"),
                ("user-agent", b"Chrome"),
            ],
            b"",
            true,
            true,
        ),
    ];
    let mut rewritten = case(
        "rewrite env over header copies",
        "GET",
        "https://forum.example/dump.php",
        cf.clone(),
        b"",
        true,
        true,
    );
    rewritten.env = vec![
        ("HTTP_USER_AGENT", "rewritten-ua"),
        ("HTTP_X_FROM_REWRITE", "rw"),
        ("HTTP_ACCEPT_ENCODING", "br"),
    ];
    cases.push(rewritten);

    for c in &cases {
        let mut outputs = Vec::new();
        for handler in [&full, &lean] {
            let mut builder = http::Request::builder().method(c.method).uri(c.uri);
            for (name, value) in &c.headers {
                builder = builder.header(*name, http::HeaderValue::from_bytes(value).unwrap());
            }
            let req = builder.body(full_incoming(c.body)).unwrap();
            let mut cx = ctx(dir.to_str().unwrap());
            cx.is_tls = c.tls;
            cx.forwarding_trusted = c.trusted;
            cx.trusted_proxy = c.trusted;
            cx.env = c
                .env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let resp = handler.handle(&mut cx, req).await.expect(c.label);
            assert_eq!(resp.status(), 200, "{}", c.label);
            let text = String::from_utf8(collect_body(resp).await.to_vec()).unwrap();
            assert!(text.starts_with("{\"server\":"), "{}: {text}", c.label);
            outputs.push(text);
        }
        assert_eq!(outputs[0], outputs[1], "{}: $_SERVER differs", c.label);
        eprintln!("{}: identical ({} bytes)", c.label, outputs[0].len());
    }

    sup.drain().await.unwrap();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// lsphp's master retires excess idle workers by marking them (`m_iKillSent`) without a
/// signal. A marked worker is alive and its socket passes the pool probe, but when its
/// next request arrives it exits without reading it, so the request resets before any
/// response byte. The master marks every excess idle worker at once, so the pooled
/// sockets a retry would reuse are likely marked too: an idempotent retry must take a
/// fresh dial (a new worker), or three marked sockets in a row turn into a 502.
#[tokio::test]
async fn get_retries_on_a_fresh_dial_past_marked_idle_workers() {
    let path = tmp_sock("marked-idle");
    let listener = UnixListener::bind(&path).unwrap();
    const WARM: usize = 3;
    let warm_ready = Arc::new(tokio::sync::Barrier::new(WARM));
    let fresh_served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let served = fresh_served.clone();
    let server_task = tokio::spawn(async move {
        let mut accepted = 0usize;
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            accepted += 1;
            let warm = accepted <= WARM;
            let ready = warm_ready.clone();
            let served = served.clone();
            tokio::spawn(async move {
                let respond = |tag: &str| {
                    let mut out = BytesMut::new();
                    put_packet(
                        &mut out,
                        PacketType::RespHeader,
                        &resp_header_body(200, &[("X-Worker", tag)]),
                    );
                    put_packet(&mut out, PacketType::RespStream, tag.as_bytes());
                    put_packet(&mut out, PacketType::RespEnd, b"");
                    out
                };
                if warm {
                    // Serve one request once all warm connections exist, then act
                    // like a marked worker: drop the next request unread.
                    let _ = read_packet(&mut s).await.unwrap();
                    ready.wait().await;
                    s.write_all(&respond("warm")).await.unwrap();
                    s.flush().await.unwrap();
                    // Block until the next request's first byte arrives, then close
                    // with the rest of it unread (readiness alone can be stale).
                    let mut first = [0u8; 1];
                    let _ = s.read(&mut first).await;
                    drop(s);
                    return;
                }
                while read_packet(&mut s).await.is_ok() {
                    served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if s.write_all(&respond("fresh")).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let pool = Arc::new(LsapiPool::new(&path, 8, Duration::from_secs(2)));
    let handler = Arc::new(Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2)));
    let get = |uri: &str| {
        http::Request::builder()
            .method("GET")
            .uri(uri)
            .header("Host", "test")
            .body(empty_incoming())
            .unwrap()
    };
    let mut warmups = Vec::new();
    for i in 0..WARM {
        let handler = handler.clone();
        let req = get(&format!("/warm{i}.php"));
        warmups.push(tokio::spawn(async move {
            let resp = handler
                .handle(&mut ctx("/web/test"), req)
                .await
                .expect("warm-up GET");
            collect_body(resp).await
        }));
    }
    for w in warmups {
        assert_eq!(&w.await.unwrap()[..], b"warm");
    }
    for _ in 0..200 {
        if pool.idle_count() == WARM {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(pool.idle_count(), WARM, "every warm connection is pooled");

    let resp = handler
        .handle(&mut ctx("/web/test"), get("/next.php"))
        .await
        .expect("a GET must survive marked idle workers");
    assert_eq!(
        resp.extensions()
            .get::<hj_lsapi::LsapiRetryInfo>()
            .map(|r| r.kind),
        Some("idempotent_reset")
    );
    assert_eq!(resp.headers().get("x-worker").unwrap(), "fresh");
    assert_eq!(&collect_body(resp).await[..], b"fresh");
    assert_eq!(fresh_served.load(std::sync::atomic::Ordering::SeqCst), 1);
    let stats = pool.stats();
    assert_eq!(
        (stats.reset_replays, stats.reset_replay_exhaustions),
        (1, 0)
    );

    server_task.abort();
    let _ = std::fs::remove_file(&path);
}

/// How the pooled (warm) worker treats the request after the one it served.
#[derive(Clone, Copy, PartialEq)]
enum WarmNext {
    /// A worker its master marked to retire: exits on the first byte, the rest unread.
    DropUnread,
    /// Reads the whole request, then dies before answering.
    ReadThenDie,
}

/// One warm pooled worker that served a GET, then `next` for the request under test;
/// every later connection is a fresh worker that reads `body_len` body bytes and
/// answers. Returns the result, how many fresh workers answered, and the body the
/// first of them received.
async fn dispatch_past_warm_worker(
    name: &str,
    next: WarmNext,
    req: hj_core::Request,
    body_len: usize,
) -> (
    Result<hj_core::Response, hj_core::HandlerError>,
    usize,
    Vec<u8>,
    hj_lsapi::PoolStats,
) {
    let path = tmp_sock(name);
    let listener = UnixListener::bind(&path).unwrap();
    let fresh_served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let fresh_body = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (served, seen) = (fresh_served.clone(), fresh_body.clone());
    let server_task = tokio::spawn(async move {
        let mut accepted = 0usize;
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            accepted += 1;
            let warm = accepted == 1;
            let (served, seen) = (served.clone(), seen.clone());
            tokio::spawn(async move {
                let respond = |tag: &str| {
                    let mut out = BytesMut::new();
                    put_packet(
                        &mut out,
                        PacketType::RespHeader,
                        &resp_header_body(200, &[("X-Worker", tag)]),
                    );
                    put_packet(&mut out, PacketType::RespStream, tag.as_bytes());
                    put_packet(&mut out, PacketType::RespEnd, b"");
                    out
                };
                if warm {
                    let _ = read_packet(&mut s).await.unwrap();
                    s.write_all(&respond("warm")).await.unwrap();
                    s.flush().await.unwrap();
                    match next {
                        WarmNext::DropUnread => {
                            let mut first = [0u8; 1];
                            let _ = s.read(&mut first).await;
                        }
                        WarmNext::ReadThenDie => {
                            let _ = read_packet(&mut s).await.unwrap();
                            let mut body = vec![0u8; body_len];
                            s.read_exact(&mut body).await.unwrap();
                        }
                    }
                    drop(s);
                    return;
                }
                if read_packet(&mut s).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; body_len];
                if s.read_exact(&mut body).await.is_err() {
                    return;
                }
                if served.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    *seen.lock().unwrap() = body;
                }
                let _ = s.write_all(&respond("fresh")).await;
                let _ = s.flush().await;
            });
        }
    });

    let pool = Arc::new(LsapiPool::new(&path, 8, Duration::from_secs(2)));
    let handler = Lsapi::new(pool.clone()).read_timeout(Duration::from_secs(2));
    let warm_get = http::Request::builder()
        .method("GET")
        .uri("/warm.php")
        .header("Host", "test")
        .body(empty_incoming())
        .unwrap();
    let resp = handler
        .handle(&mut ctx("/web/test"), warm_get)
        .await
        .expect("warm-up GET");
    assert_eq!(&collect_body(resp).await[..], b"warm");
    for _ in 0..200 {
        if pool.idle_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(pool.idle_count(), 1, "the warm connection is pooled");

    let result = handler.handle(&mut ctx("/web/test"), req).await;
    let stats = pool.stats();
    server_task.abort();
    let _ = std::fs::remove_file(&path);
    let served = fresh_served.load(std::sync::atomic::Ordering::SeqCst);
    let body = fresh_body.lock().unwrap().clone();
    (result, served, body, stats)
}

fn post(content_type: Option<&str>, body: &'static [u8]) -> hj_core::Request {
    let mut req = http::Request::builder()
        .method("POST")
        .uri("/sx.php")
        .header("Host", "test")
        .header("Content-Length", body.len());
    if let Some(ct) = content_type {
        req = req.header("Content-Type", ct);
    }
    req.body(full_incoming(body)).unwrap()
}

/// A POST that a retiring worker dropped unread never reached PHP, so it is replayed on
/// a fresh dial with its (small, PHP-preread) body, like OLS `ExtConn::connError`.
#[tokio::test]
async fn post_dropped_unread_by_a_retiring_worker_is_replayed() {
    let body: &'static [u8] = b"t=pv&u=%2Fthreads%2Fexample.1%2F";
    let (result, served, seen, stats) = dispatch_past_warm_worker(
        "unread-post",
        WarmNext::DropUnread,
        post(Some("application/x-www-form-urlencoded"), body),
        body.len(),
    )
    .await;
    let resp = result.expect("an unread POST must be replayed");
    assert_eq!(
        resp.extensions()
            .get::<hj_lsapi::LsapiRetryInfo>()
            .map(|r| r.kind),
        Some("unread_reset")
    );
    assert_eq!(resp.headers().get("x-worker").unwrap(), "fresh");
    assert_eq!((served, &seen[..]), (1, body));
    assert_eq!(
        (stats.reset_replays, stats.reset_replay_exhaustions),
        (1, 0)
    );
}

#[tokio::test]
async fn bodyless_post_dropped_unread_is_replayed() {
    let (result, served, _, _) =
        dispatch_past_warm_worker("unread-bodyless", WarmNext::DropUnread, post(None, b""), 0)
            .await;
    let resp = result.expect("an unread bodyless POST must be replayed");
    assert_eq!(resp.headers().get("x-worker").unwrap(), "fresh");
    assert_eq!(served, 1);
}

/// A body PHP may read only in part (multipart) is never replayed: an unread tail does
/// not prove the script never ran.
#[tokio::test]
async fn multipart_post_reset_is_not_replayed() {
    let body: &'static [u8] =
        b"--zz\r\nContent-Disposition: form-data; name=a\r\n\r\n1\r\n--zz--\r\n";
    let (result, served, _, _) = dispatch_past_warm_worker(
        "unread-multipart",
        WarmNext::DropUnread,
        post(Some("multipart/form-data; boundary=zz"), body),
        body.len(),
    )
    .await;
    assert!(
        matches!(result, Err(hj_core::HandlerError::BadGateway(_))),
        "multipart must not be replayed"
    );
    assert_eq!(served, 0);
}

/// A worker that took the whole request and then died may have run the script: EOF is
/// not an unread reset, so a POST stays a 502.
#[tokio::test]
async fn post_read_in_full_before_the_worker_died_is_not_replayed() {
    let body: &'static [u8] = b"a=1&b=2";
    let (result, served, _, _) = dispatch_past_warm_worker(
        "read-then-die",
        WarmNext::ReadThenDie,
        post(Some("application/x-www-form-urlencoded"), body),
        body.len(),
    )
    .await;
    assert!(
        matches!(result, Err(hj_core::HandlerError::BadGateway(_))),
        "a POST the worker read must not be replayed"
    );
    assert_eq!(served, 0);
}
