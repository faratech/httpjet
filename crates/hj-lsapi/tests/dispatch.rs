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
    HEADER_INDEX_LEN, KNOWN_HEADER_COUNT, Lsapi, LsapiPool, LsphpSupervisor, Monitor,
    MonitorConfig, PACKET_HEADER_LEN, PacketType, SupervisorConfig, WorkerState,
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
    buf.put_u8(0); // little-endian flag
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
    let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(5));

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
    let bytes = match body {
        hj_core::Body::Stream(s) => tokio::time::timeout(Duration::from_secs(5), s.collect())
            .await
            .expect("body must complete WITHOUT waiting for RESP_END")
            .unwrap()
            .to_bytes(),
        other => panic!(
            "expected streamed body, got {:?}",
            std::mem::discriminant(&other)
        ),
    };
    assert_eq!(bytes.len(), expected.len());
    assert_eq!(&bytes[..], &expected[..]);

    // Release the barrier so the pump can drain RESP_END and the mock can exit.
    end_tx.send(()).unwrap();
    server_task.await.unwrap();
    let _ = std::fs::remove_file(&path);
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
    let handler = Lsapi::new(pool).read_timeout(Duration::from_secs(2));
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
        .method("POST")
        .uri("/index.php")
        .header("Host", "test");
    if declare_length {
        builder = builder.header("Content-Length", "32");
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
        if pool.idle_count() > 0 || pool.stats().unread_body_drops > 0 {
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

#[tokio::test]
async fn drained_request_body_repools() {
    for (tag, declare_length) in [
        ("drained-body-stream", true),
        ("drained-body-buffered", false),
    ] {
        let pool = post_with_body_drain(tag, true, declare_length).await;
        assert_eq!(
            pool.idle_count(),
            1,
            "{tag}: drained socket must be reusable"
        );
        assert_eq!(pool.stats().unread_body_drops, 0, "{tag}");
    }
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
