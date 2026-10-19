//! End-to-end HTTP/2 server conformance tests, driving the public [`hj_h2::server::serve`]
//! entry over an in-memory duplex with a hand-rolled HPACK client. These exercise only the
//! crate's public API (the service closure, `Config`, the frame codec, the HPACK codec);
//! tests that reach into private internals (the field-block fragmenter, the file streamer)
//! stay in `src/server/send.rs`.

use bytes::Bytes;
use hj_core::{Body, Request, Response};
use hj_h2::frame::{self, FrameHeader};
use hj_h2::hpack::{Decoder, Encoder};
use hj_h2::server::{Config, serve};
use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn noop_service(_req: Request) -> Response {
    hj_core::text_response(http::StatusCode::OK, "")
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> (FrameHeader, Vec<u8>) {
    let mut h = [0u8; FrameHeader::LEN];
    r.read_exact(&mut h).await.unwrap();
    let hdr = FrameHeader::parse(&h).unwrap();
    let mut p = vec![0u8; hdr.length as usize];
    r.read_exact(&mut p).await.unwrap();
    (hdr, p)
}

#[tokio::test]
async fn handshake_then_ping_ack() {
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();

    let (hdr, _) = read_frame(&mut client).await; // server SETTINGS
    assert_eq!(hdr.kind, frame::kind::SETTINGS);
    let (hdr, payload) = read_frame(&mut client).await; // connection-window WINDOW_UPDATE
    assert_eq!((hdr.kind, hdr.stream_id), (frame::kind::WINDOW_UPDATE, 0));
    let inc = u32::from_be_bytes(payload[..4].try_into().unwrap());
    assert_eq!(inc, Config::default().initial_window_size - 65535);
    let (hdr, _) = read_frame(&mut client).await; // SETTINGS ACK
    assert_eq!(
        (hdr.kind, hdr.flags),
        (frame::kind::SETTINGS, frame::flags::ACK)
    );

    let mut ping = Vec::new();
    frame::write_frame(
        &mut ping,
        frame::kind::PING,
        0,
        0,
        &[1, 2, 3, 4, 5, 6, 7, 8],
    );
    client.write_all(&ping).await.unwrap();
    client.flush().await.unwrap();
    let (hdr, payload) = read_frame(&mut client).await;
    assert_eq!(
        (hdr.kind, hdr.flags),
        (frame::kind::PING, frame::flags::ACK)
    );
    assert_eq!(payload, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    drop(client);
    srv.await.unwrap().unwrap();
}

#[tokio::test]
async fn client_goaway_with_trailing_frame_closes_cleanly() {
    // Regression: a client GOAWAY followed by a trailing frame the server never
    // answers (a PING here) must be drained, not left unread — an unread receive
    // buffer at close makes the OS RST instead of FIN. serve() must half-close its
    // write side (client sees EOF) and return Ok without hanging or erroring.
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();
    let _ = read_frame(&mut client).await; // server SETTINGS
    let _ = read_frame(&mut client).await; // SETTINGS ACK

    // GOAWAY, then a trailing PING (unread inbound the teardown must drain).
    let mut g = Vec::new();
    frame::write_goaway(&mut g, 0, frame::error_code::NO_ERROR);
    client.write_all(&g).await.unwrap();
    let mut ping = Vec::new();
    frame::write_frame(&mut ping, frame::kind::PING, 0, 0, &[9u8; 8]);
    client.write_all(&ping).await.unwrap();
    client.flush().await.unwrap();

    // The server half-closes its write side, so the client reaches EOF promptly
    // (a hang here = teardown regression). Closing the client then lets the server's
    // bounded drain see EOF and return Ok immediately.
    let mut sink = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut sink),
    )
    .await
    .expect("server did not close after GOAWAY (drain/half-close regression)")
    .unwrap();
    drop(client);
    srv.await
        .unwrap()
        .expect("serve() must return Ok on a graceful client-GOAWAY close");
}

#[tokio::test]
async fn early_hints_103_precedes_final_response() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    // A response that declares a preload Link hint must yield an interim 103 first.
    let service = |_req: Request| async move {
        let mut resp = hj_core::text_response(http::StatusCode::OK, "page");
        resp.headers_mut().insert(
            http::header::LINK,
            http::HeaderValue::from_static("</app.css>; rel=preload; as=style"),
        );
        resp
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "GET");
    enc.encode_header(&mut block, ":path", "/");
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    let mut hframe = Vec::new();
    frame::write_frame(
        &mut hframe,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &block,
    );
    client.write_all(&hframe).await.unwrap();
    client.flush().await.unwrap();

    // Decode the HEADERS frames in order (shared HPACK state): expect 103 then 200.
    let mut dec = Decoder::new(4096, 1 << 20);
    let mut statuses = Vec::new();
    let mut early_link = None;
    while statuses.len() < 2 {
        let (hdr, payload) = read_frame(&mut client).await;
        if hdr.kind != frame::kind::HEADERS {
            continue;
        }
        let (mut st, mut link) = (None, None);
        dec.decode(&payload, |n, v| {
            if n == ":status" {
                st = Some(v.to_string());
            }
            if n == "link" {
                link = Some(v.to_string());
            }
        })
        .unwrap();
        if let Some(s) = st {
            if s == "103" {
                early_link = link;
            }
            statuses.push(s);
        }
    }
    assert_eq!(
        statuses[0], "103",
        "interim 103 Early Hints must precede the final response"
    );
    assert_eq!(statuses[1], "200", "final response follows the 103");
    assert_eq!(
        early_link.as_deref(),
        Some("</app.css>; rel=preload; as=style")
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn expect_100_continue_yields_interim_100() {
    // §8.1: a request with `Expect: 100-continue` and a body still to come must get an interim
    // 100 (no END_STREAM) before the client sends the body.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "POST");
    enc.encode_header(&mut block, ":path", "/upload");
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    enc.encode_header(&mut block, "expect", "100-continue");
    let mut hframe = Vec::new();
    // END_HEADERS but NOT END_STREAM: a request body is still to come.
    frame::write_frame(
        &mut hframe,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &block,
    );
    client.write_all(&hframe).await.unwrap();
    client.flush().await.unwrap();

    let mut dec = Decoder::new(4096, 1 << 20);
    let (status, end_stream) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind != frame::kind::HEADERS {
                continue;
            }
            let mut st = None;
            dec.decode(&payload, |n, v| {
                if n == ":status" {
                    st = Some(v.to_string());
                }
            })
            .unwrap();
            if let Some(s) = st {
                return (s, hdr.flags & frame::flags::END_STREAM != 0);
            }
        }
    })
    .await
    .expect("server must send an interim 100");
    assert_eq!(status, "100");
    assert!(
        !end_stream,
        "an interim 1xx must not carry END_STREAM (§8.1)"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn serves_a_get_request_end_to_end() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    // Service echoes a fixed body + a custom header, asserting it saw the request.
    let service = |req: Request| async move {
        assert_eq!(req.method(), http::Method::GET);
        assert_eq!(req.uri().path(), "/hello");
        let mut resp = hj_core::text_response(http::StatusCode::OK, "hi there");
        resp.headers_mut()
            .insert("x-served-by", http::HeaderValue::from_static("hj-h2"));
        resp
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    // Client handshake.
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();

    // Encode a GET request header block with our own HPACK encoder.
    let mut enc = Encoder::new();
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "GET");
    enc.encode_header(&mut block, ":path", "/hello");
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    let mut hframe = Vec::new();
    frame::write_frame(
        &mut hframe,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &block,
    );
    client.write_all(&hframe).await.unwrap();
    client.flush().await.unwrap();

    // Drain server SETTINGS + SETTINGS ACK, then read the response HEADERS + DATA.
    let mut dec = Decoder::new(4096, 1 << 20);
    let mut status = None;
    let mut served_by = None;
    let mut body = Vec::new();
    loop {
        let (hdr, payload) = read_frame(&mut client).await;
        match hdr.kind {
            frame::kind::HEADERS => {
                dec.decode(&payload, |n, v| {
                    if n == ":status" {
                        status = Some(v.to_owned());
                    }
                    if n == "x-served-by" {
                        served_by = Some(v.to_owned());
                    }
                })
                .unwrap();
                if hdr.flags & frame::flags::END_STREAM != 0 {
                    break;
                }
            }
            frame::kind::DATA => {
                body.extend_from_slice(&payload);
                if hdr.flags & frame::flags::END_STREAM != 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    assert_eq!(status.as_deref(), Some("200"));
    assert_eq!(served_by.as_deref(), Some("hj-h2"));
    assert_eq!(body, b"hi there");
    drop(client);
    let _ = srv.await;
}

fn encode_get(enc: &mut Encoder, path: &str) -> Vec<u8> {
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "GET");
    enc.encode_header(&mut block, ":path", path);
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    block
}

/// A GET block with extra regular fields appended after the pseudo-headers. An indexable
/// extra field (value <= 256 bytes) is added to the encoder's dynamic table, so encoding the
/// same field again on a later stream emits a single indexed reference — which the server can
/// only resolve if its decoder processed every intervening block (incl. refused ones).
fn encode_get_with(enc: &mut Encoder, path: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "GET");
    enc.encode_header(&mut block, ":path", path);
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    for (n, v) in extra {
        enc.encode_header(&mut block, n, v);
    }
    block
}

/// Read frames until an RST_STREAM for `sid` (asserting REFUSED_STREAM); panic on GOAWAY. Every
/// response HEADERS block seen along the way is decoded so the client `dec` stays in sync.
async fn expect_refused<R: AsyncReadExt + Unpin>(r: &mut R, dec: &mut Decoder, sid: u32) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(r).await;
            match hdr.kind {
                frame::kind::GOAWAY => {
                    panic!("connection GOAWAYed instead of refusing stream {sid}")
                }
                frame::kind::HEADERS => {
                    dec.decode(&payload, |_, _| {}).unwrap();
                }
                frame::kind::RST_STREAM if hdr.stream_id == sid => {
                    let code = u32::from_be_bytes(payload[..4].try_into().unwrap());
                    assert_eq!(
                        code,
                        frame::error_code::REFUSED_STREAM,
                        "over-cap stream → REFUSED_STREAM"
                    );
                    return;
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for RST_STREAM on stream {sid}"));
}

/// Read frames until the response HEADERS for `sid`; return (:status, x-echo). Panic on GOAWAY.
/// Decodes every HEADERS block in wire order to keep the client response decoder in sync.
async fn read_response<R: AsyncReadExt + Unpin>(
    r: &mut R,
    dec: &mut Decoder,
    sid: u32,
) -> (Option<String>, Option<String>) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(r).await;
            match hdr.kind {
                frame::kind::GOAWAY => {
                    panic!("connection GOAWAYed while awaiting stream {sid} response")
                }
                frame::kind::HEADERS => {
                    let mut status = None;
                    let mut echo = None;
                    dec.decode(&payload, |n, v| match n {
                        ":status" => status = Some(v.to_owned()),
                        "x-echo" => echo = Some(v.to_owned()),
                        _ => {}
                    })
                    .unwrap();
                    if hdr.stream_id == sid {
                        return (status, echo);
                    }
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for stream {sid} response"))
}

#[tokio::test]
async fn multiplexes_streams_slow_does_not_block_fast() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    // /slow sleeps; /fast is immediate. With true multiplexing the fast stream's
    // response must come back FIRST even though it was sent second; a sequential
    // server would block it behind the slow one.
    let service = |req: Request| async move {
        if req.uri().path() == "/slow" {
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        }
        hj_core::text_response(http::StatusCode::OK, "")
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();

    // Stream 1 = /slow (sent first), stream 3 = /fast (sent second).
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/slow"),
    );
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        3,
        &encode_get(&mut enc, "/fast"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    // Record the order in which response HEADERS frames arrive by stream id.
    let mut order = Vec::new();
    while order.len() < 2 {
        let (hdr, _) = read_frame(&mut client).await;
        if hdr.kind == frame::kind::HEADERS {
            order.push(hdr.stream_id);
        }
    }
    assert_eq!(
        order,
        vec![3, 1],
        "fast stream 3 must complete before slow stream 1"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn streams_a_chunked_body_end_to_end() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    // A multi-chunk streaming body — the LSAPI / proxy / SSE response shape that the
    // old buffered path served as an empty body.
    let service = |_req: Request| async move {
        use http_body::Frame;
        use http_body_util::{BodyExt, StreamBody};
        let chunks: Vec<Result<Frame<Bytes>, hj_core::BoxError>> = vec![
            Ok(Frame::data(Bytes::from_static(b"alpha"))),
            Ok(Frame::data(Bytes::from_static(b"-beta"))),
            Ok(Frame::data(Bytes::from_static(b"-gamma"))),
        ];
        let body = StreamBody::new(futures_util::stream::iter(chunks)).boxed();
        http::Response::builder()
            .status(200)
            .body(Body::Stream(body))
            .unwrap()
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/stream"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let mut body = Vec::new();
    let mut got_headers = false;
    loop {
        let (hdr, payload) = read_frame(&mut client).await;
        match hdr.kind {
            frame::kind::HEADERS => got_headers = true,
            frame::kind::DATA => {
                body.extend_from_slice(&payload);
                if hdr.flags & frame::flags::END_STREAM != 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    assert!(got_headers, "response HEADERS must arrive");
    assert_eq!(
        body, b"alpha-beta-gamma",
        "all streamed chunks must be delivered in order"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn streams_large_body_with_windowing() {
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    // 200 KB streaming body in 8 KB chunks — exceeds the 65535 default window ~3×, so
    // it only completes if the server resumes correctly after each WINDOW_UPDATE.
    let service = |_req: Request| async move {
        use http_body::Frame;
        use http_body_util::{BodyExt, StreamBody};
        // Yield `Pending` between chunks (a timer) — this models a real LSAPI/proxy body
        // whose data arrives off a socket, exercising the connection task's waker path
        // (a synchronous `stream::iter` would mask any now_or_never waker-loss bug).
        let stream = futures_util::stream::unfold(0u32, |i| async move {
            if i >= 25 {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            let frame: Result<Frame<Bytes>, hj_core::BoxError> =
                Ok(Frame::data(Bytes::from(vec![b'x'; 8192])));
            Some((frame, i + 1))
        });
        let body = StreamBody::new(stream).boxed();
        http::Response::builder()
            .status(200)
            .body(Body::Stream(body))
            .unwrap()
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]); // default per-stream window 65535
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/big"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    // Read all frames, replenishing the window as we consume (like curl/nghttp).
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut got = 0usize;
        let mut consumed = 0u32;
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::DATA {
                got += payload.len();
                consumed += payload.len() as u32;
                if consumed >= 16384 {
                    let mut wu = Vec::new();
                    frame::write_window_update(&mut wu, 0, consumed);
                    frame::write_window_update(&mut wu, 1, consumed);
                    client.write_all(&wu).await.unwrap();
                    client.flush().await.unwrap();
                    consumed = 0;
                }
                if hdr.flags & frame::flags::END_STREAM != 0 {
                    break;
                }
            }
        }
        got
    })
    .await
    .expect("large streaming body must complete, not deadlock on the send window");
    assert_eq!(got, 25 * 8192);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn early_window_update_before_response_is_honored() {
    // Regression: a client grants a large stream window right after HEADERS, before a
    // slow handler (LSAPI render) produces the body. That credit must be remembered and
    // applied when the response begins — otherwise the body stalls at the 65535 initial
    // window (the real XenForo-index-over-curl stall).
    let (mut client, server) = tokio::io::duplex(512 * 1024);
    let service = |_req: Request| async move {
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        http::Response::builder()
            .status(200)
            .body(Body::Full(Bytes::from(vec![b'y'; 200 * 1024])))
            .unwrap()
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/slow-big"),
    );
    // Grant a large window for the stream AND the connection NOW — before the response.
    frame::write_window_update(&mut req, 1, 1_000_000);
    frame::write_window_update(&mut req, 0, 1_000_000);
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    // Read the full 200 KB WITHOUT any further WINDOW_UPDATE — only the early credit can
    // carry it past the 65535 initial window.
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut got = 0usize;
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::DATA {
                got += payload.len();
                if hdr.flags & frame::flags::END_STREAM != 0 {
                    break;
                }
            }
        }
        got
    })
    .await
    .expect("early WINDOW_UPDATE credit must carry the body past the initial window");
    assert_eq!(got, 200 * 1024);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn refused_stream_window_update_does_not_goaway() {
    // Regression: at the concurrency cap a new stream is refused with RST_STREAM(REFUSED_STREAM).
    // A client that then optimistically sends WINDOW_UPDATE (or RST_STREAM) for that just-refused
    // stream — racing the server's in-flight RST (RFC 7540 §5.1 says ignore those) — must be a
    // closed-stream no-op, NOT an idle-stream PROTOCOL_ERROR that GOAWAYs the whole connection and
    // every multiplexed stream. The bug: the refused stream id was never recorded in
    // last_client_stream, so the WINDOW_UPDATE looked like it targeted an idle stream.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let mut cfg = Config::default();
    cfg.max_concurrent_streams = 1;
    let srv = tokio::spawn(async move { serve(server, noop_service, cfg, None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();
    // Drain the server handshake (SETTINGS, connection WINDOW_UPDATE, SETTINGS ACK).
    for _ in 0..3 {
        let _ = read_frame(&mut client).await;
    }

    let mut enc = Encoder::new();
    // Stream 1: END_HEADERS but NOT END_STREAM, so it stays half-open and holds the single slot.
    let mut s1 = Vec::new();
    frame::write_frame(
        &mut s1,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get(&mut enc, "/hold"),
    );
    client.write_all(&s1).await.unwrap();
    // Stream 3: a new stream over the cap → refused; immediately followed by an optimistic
    // WINDOW_UPDATE for it (the race that used to trigger a connection-wide GOAWAY).
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut s3 = Vec::new();
    frame::write_frame(
        &mut s3,
        frame::kind::HEADERS,
        end,
        3,
        &encode_get(&mut enc, "/refused"),
    );
    frame::write_window_update(&mut s3, 3, 1_000_000);
    client.write_all(&s3).await.unwrap();
    // PING last: its ACK proves the connection is still alive (no GOAWAY teardown).
    let mut ping = Vec::new();
    frame::write_frame(&mut ping, frame::kind::PING, 0, 0, &[7u8; 8]);
    client.write_all(&ping).await.unwrap();
    client.flush().await.unwrap();

    let mut saw_refused = false;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::GOAWAY => {
                    panic!("connection GOAWAYed on a refused-stream WINDOW_UPDATE (the bug)")
                }
                frame::kind::RST_STREAM => {
                    assert_eq!(hdr.stream_id, 3, "RST must target the refused stream");
                    let code = u32::from_be_bytes(payload[..4].try_into().unwrap());
                    assert_eq!(
                        code,
                        frame::error_code::REFUSED_STREAM,
                        "over-cap stream → REFUSED_STREAM"
                    );
                    saw_refused = true;
                }
                frame::kind::PING if hdr.flags & frame::flags::ACK != 0 => break, // still alive
                _ => {}
            }
        }
    })
    .await
    .expect(
        "server must answer PING (connection alive), not GOAWAY the refused-stream WINDOW_UPDATE",
    );
    assert!(
        saw_refused,
        "the over-cap stream must have been refused with RST_STREAM"
    );
    drop(client);
    let _ = srv.await;
}

/// What the server sent on `sid` before acknowledging a PING the test wrote after its
/// frames: each response HEADERS as (`:status`, END_STREAM) and each RST_STREAM code.
/// Panics on GOAWAY; decodes every HEADERS block to keep `dec` in sync.
#[derive(Debug, Default, PartialEq)]
struct StreamEvents {
    responses: Vec<(String, bool)>,
    resets: Vec<u32>,
}

async fn stream_events_until_ping_ack<R: AsyncReadExt + Unpin>(
    r: &mut R,
    dec: &mut Decoder,
    sid: u32,
) -> StreamEvents {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut events = StreamEvents::default();
        loop {
            let (hdr, payload) = read_frame(r).await;
            match hdr.kind {
                frame::kind::GOAWAY => panic!("connection GOAWAYed; stream {sid}: {events:?}"),
                frame::kind::HEADERS => {
                    let mut status = String::new();
                    dec.decode(&payload, |n, v| {
                        if n == ":status" {
                            status = v.to_owned();
                        }
                    })
                    .unwrap();
                    if hdr.stream_id == sid {
                        let end = hdr.flags & frame::flags::END_STREAM != 0;
                        events.responses.push((status, end));
                    }
                }
                frame::kind::RST_STREAM if hdr.stream_id == sid => {
                    events
                        .resets
                        .push(u32::from_be_bytes(payload[..4].try_into().unwrap()));
                }
                frame::kind::PING if hdr.flags & frame::flags::ACK != 0 => return events,
                _ => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for the PING ACK after stream {sid}"))
}

fn write_ping(buf: &mut Vec<u8>) {
    frame::write_frame(buf, frame::kind::PING, 0, 0, &[7u8; 8]);
}

fn small_body_cap_config() -> Config {
    Config {
        max_request_body: 8,
        initial_window_size: 1 << 16,
        ..Config::default()
    }
}

/// A 413 and nothing else, then RST_STREAM(NO_ERROR) iff the client was still sending.
fn too_large(status: &str, client_open: bool) -> StreamEvents {
    StreamEvents {
        responses: vec![(status.to_owned(), true)],
        resets: if client_open {
            vec![frame::error_code::NO_ERROR]
        } else {
            Vec::new()
        },
    }
}

#[tokio::test]
async fn request_body_over_config_max_is_answered_413() {
    // Regression (#84): the per-stream request-body cap is driven by Config.max_request_body
    // (LiteSpeed maxReqBodySize), NOT a hardcoded 64 MiB: with a tiny cap a 16-byte body is
    // over it. The window is sized well above the body so the BODY cap is what trips.
    // (#1014) With no declared length to reject up front, the overflowing DATA frame is
    // answered 413 + RST_STREAM(NO_ERROR) — not the retry-safe REFUSED_STREAM — and the rest
    // of the upload is ignored rather than reset again.
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mut client, srv) = open_client(small_body_cap_config(), calls.clone()).await;
    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get(&mut enc, "/upload"),
    );
    frame::write_frame(&mut buf, frame::kind::DATA, 0, 1, &[b'x'; 16]); // 16 > 8-byte body cap
    write_ping(&mut buf);
    client.write_all(&buf).await.unwrap();
    assert_eq!(
        stream_events_until_ping_ack(&mut client, &mut dec, 1).await,
        too_large("413", true)
    );

    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::DATA,
        frame::flags::END_STREAM,
        1,
        &[b'x'; 16],
    );
    write_ping(&mut buf);
    client.write_all(&buf).await.unwrap();
    assert_eq!(
        stream_events_until_ping_ack(&mut client, &mut dec, 1).await,
        StreamEvents::default(),
        "DATA after our RST_STREAM is ignored (§5.1)"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn over_cap_final_data_frame_is_answered_413_without_a_reset() {
    // (#1014) The client already ended the stream, so the 413 closes it; a RST_STREAM on a
    // closed stream would be a protocol violation (§5.1).
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mut client, srv) = open_client(small_body_cap_config(), calls.clone()).await;
    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get(&mut enc, "/upload"),
    );
    frame::write_frame(
        &mut buf,
        frame::kind::DATA,
        frame::flags::END_STREAM,
        1,
        &[b'x'; 16],
    );
    write_ping(&mut buf);
    client.write_all(&buf).await.unwrap();
    assert_eq!(
        stream_events_until_ping_ack(&mut client, &mut dec, 1).await,
        too_large("413", false)
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn declared_content_length_over_cap_is_answered_413_before_the_body() {
    // (#1014) H1 parity: a declared length over the cap is rejected when the headers
    // complete, without waiting for (or buffering) a single body byte.
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mut client, srv) = open_client(small_body_cap_config(), calls.clone()).await;
    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get_with(&mut enc, "/upload", &[("content-length", "9")]),
    );
    write_ping(&mut buf);
    client.write_all(&buf).await.unwrap();
    assert_eq!(
        stream_events_until_ping_ack(&mut client, &mut dec, 1).await,
        too_large("413", true)
    );

    // The connection, and the HPACK state the 413 updated, still serve the next request.
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        3,
        &encode_get(&mut enc, "/after"),
    );
    client.write_all(&buf).await.unwrap();
    let (status, _) = read_response(&mut client, &mut dec, 3).await;
    assert_eq!(status.as_deref(), Some("200"));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn data_past_declared_content_length_resets_on_the_first_overrunning_frame() {
    // (#1014) §8.1.1: DATA beyond the declared content-length is malformed. The stream is
    // reset on the overrunning frame itself — no END_STREAM is ever sent here, so the old
    // completion-time check would have buffered until the body deadline.
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mut client, srv) = open_client(Config::default(), calls.clone()).await;
    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get_with(&mut enc, "/upload", &[("content-length", "10")]),
    );
    frame::write_frame(&mut buf, frame::kind::DATA, 0, 1, &[b'x'; 6]);
    frame::write_frame(&mut buf, frame::kind::DATA, 0, 1, &[b'x'; 6]);
    write_ping(&mut buf);
    client.write_all(&buf).await.unwrap();
    assert_eq!(
        stream_events_until_ping_ack(&mut client, &mut dec, 1).await,
        StreamEvents {
            responses: Vec::new(),
            resets: vec![frame::error_code::PROTOCOL_ERROR],
        }
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn no_progress_frame_flood_goaways_enhance_your_calm() {
    // Regression (#87): a flood of frames that make NO forward progress — here empty DATA on an
    // open stream (same class as non-ACK PING / SETTINGS / PRIORITY) — must trip
    // GOAWAY(ENHANCE_YOUR_CALM), not pin the connection forever. Empty DATA produces no server
    // output, so it never resets the progress counter. Split the stream so the flood writer can't
    // deadlock against the GOAWAY read.
    let (client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    let (mut rd, mut wr) = tokio::io::split(client);

    wr.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    wr.write_all(&f).await.unwrap();
    // Open stream 1 WITHOUT END_STREAM, so empty DATA is legal and never completes a request.
    let mut enc = Encoder::new();
    let mut hb = Vec::new();
    frame::write_frame(
        &mut hb,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get(&mut enc, "/hold"),
    );
    wr.write_all(&hb).await.unwrap();
    wr.flush().await.unwrap();

    let writer = tokio::spawn(async move {
        let mut data = Vec::new();
        frame::write_frame(&mut data, frame::kind::DATA, 0, 1, b""); // empty DATA, no END_STREAM
        // Well past NO_PROGRESS_BUDGET (10k); stop early once the server closes the connection.
        for _ in 0..15_000u32 {
            if wr.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    let code = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let (hdr, payload) = read_frame(&mut rd).await;
            if hdr.kind == frame::kind::GOAWAY {
                return u32::from_be_bytes(payload[4..8].try_into().unwrap());
            }
        }
    })
    .await
    .expect("a no-progress frame flood must GOAWAY, not hang");
    assert_eq!(
        code,
        frame::error_code::ENHANCE_YOUR_CALM,
        "no-progress flood → GOAWAY(ENHANCE_YOUR_CALM)"
    );
    let _ = writer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn stream_window_update_flood_still_goaways() {
    // Regression (#241): a stream-level WINDOW_UPDATE used to reset the no-progress
    // counter UNCONDITIONALLY, so alternating +1 grants on an idle/never-blocked
    // stream deferred the flood GOAWAY forever (CVE-2019-9518 class). Only a grant
    // that genuinely unblocks a window-blocked response may clear it — a grant on a
    // stream with no blocked outbound data must count toward the budget like any
    // other no-progress frame.
    let (client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    let (mut rd, mut wr) = tokio::io::split(client);

    wr.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    wr.write_all(&f).await.unwrap();
    // Open stream 1 and hold the request open (no response body in flight, so no
    // stream send-window is ever blocked).
    let mut enc = Encoder::new();
    let mut hb = Vec::new();
    frame::write_frame(
        &mut hb,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get(&mut enc, "/hold"),
    );
    wr.write_all(&hb).await.unwrap();
    wr.flush().await.unwrap();

    let writer = tokio::spawn(async move {
        let mut wu = Vec::new();
        frame::write_frame(&mut wu, frame::kind::WINDOW_UPDATE, 0, 1, &[0, 0, 0, 1]);
        for _ in 0..15_000u32 {
            if wr.write_all(&wu).await.is_err() {
                break;
            }
        }
    });

    let code = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let (hdr, payload) = read_frame(&mut rd).await;
            if hdr.kind == frame::kind::GOAWAY {
                return u32::from_be_bytes(payload[4..8].try_into().unwrap());
            }
        }
    })
    .await
    .expect("a stream WINDOW_UPDATE flood must still GOAWAY, not hang");
    assert_eq!(
        code,
        frame::error_code::ENHANCE_YOUR_CALM,
        "unblocked-stream WINDOW_UPDATE flood → GOAWAY(ENHANCE_YOUR_CALM)"
    );
    let _ = writer.await;
    let _ = srv.await;
}

#[tokio::test]
async fn refused_stream_keeps_hpack_decoder_in_sync() {
    // Regression (#1): a stream refused for exceeding MAX_CONCURRENT_STREAMS must STILL have its
    // HPACK header block decoded, so the connection-wide decoder dynamic table stays in sync with
    // the client's encoder. Otherwise an incremental-indexing field the client added on the
    // refused stream is missing from the server's table, and a LATER stream that references it by
    // index decodes the wrong value (or a COMPRESSION_ERROR that GOAWAYs every multiplexed stream).
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let mut cfg = Config::default();
    cfg.max_concurrent_streams = 1;
    let service = |req: Request| async move {
        let echoed = req.headers().get("x-dyn").cloned();
        let mut resp = hj_core::text_response(http::StatusCode::OK, "");
        if let Some(v) = echoed {
            resp.headers_mut().insert("x-echo", v);
        }
        resp
    };
    let srv = tokio::spawn(async move { serve(server, service, cfg, None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();
    for _ in 0..3 {
        let _ = read_frame(&mut client).await; // handshake (SETTINGS, WINDOW_UPDATE, SETTINGS ACK)
    }

    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;

    // Stream 1: END_HEADERS but NOT END_STREAM → half-open, holds the single slot.
    // Stream 3: over the cap → refused; its block adds `x-dyn: v1` via incremental indexing.
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get(&mut enc, "/hold"),
    );
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        end,
        3,
        &encode_get_with(&mut enc, "/refused", &[("x-dyn", "v1")]),
    );
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();
    expect_refused(&mut client, &mut dec, 3).await;

    // Free the slot: end stream 1 with an empty END_STREAM DATA frame, then drain its 200.
    let mut d = Vec::new();
    frame::write_frame(&mut d, frame::kind::DATA, frame::flags::END_STREAM, 1, &[]);
    client.write_all(&d).await.unwrap();
    client.flush().await.unwrap();
    let (s1_status, _) = read_response(&mut client, &mut dec, 1).await;
    assert_eq!(
        s1_status.as_deref(),
        Some("200"),
        "stream 1 should complete normally"
    );

    // Stream 5: references `x-dyn: v1` again → the client emits a single indexed reference into
    // its dynamic table. The server resolves it ONLY if it decoded the refused block (the fix).
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        end,
        5,
        &encode_get_with(&mut enc, "/after", &[("x-dyn", "v1")]),
    );
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();
    let (s5_status, echo) = read_response(&mut client, &mut dec, 5).await;
    assert_eq!(
        s5_status.as_deref(),
        Some("200"),
        "stream 5 must decode + dispatch (no HPACK desync)"
    );
    assert_eq!(
        echo.as_deref(),
        Some("v1"),
        "server must resolve the dynamic-table reference to the correct value"
    );

    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn refused_split_header_block_does_not_goaway() {
    // Regression (#6): refusing a header block that is SPLIT across HEADERS + CONTINUATION must not
    // tear down the connection. The refusal is deferred to END_HEADERS, so the stream stays known
    // and its racing CONTINUATION finds it (instead of hitting the no-stream GOAWAY path).
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let mut cfg = Config::default();
    cfg.max_concurrent_streams = 1;
    let srv = tokio::spawn(async move { serve(server, noop_service, cfg, None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();
    for _ in 0..3 {
        let _ = read_frame(&mut client).await;
    }

    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);

    // Stream 1: half-open, holds the single slot.
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get(&mut enc, "/hold"),
    );
    // Stream 3 over the cap, block SPLIT: HEADERS (no END_HEADERS) + CONTINUATION (END_HEADERS).
    let block = encode_get_with(&mut enc, "/refused", &[("x-dyn2", "v2")]);
    let (head, tail) = block.split_at(block.len() / 2);
    frame::write_frame(&mut buf, frame::kind::HEADERS, 0, 3, head); // no END_HEADERS
    frame::write_frame(
        &mut buf,
        frame::kind::CONTINUATION,
        frame::flags::END_HEADERS,
        3,
        tail,
    );
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();

    // The refused split-block stream resets cleanly; the connection survives (no GOAWAY).
    expect_refused(&mut client, &mut dec, 3).await;

    // PING ACK proves the connection is still alive.
    let mut ping = Vec::new();
    frame::write_frame(&mut ping, frame::kind::PING, 0, 0, &[5u8; 8]);
    client.write_all(&ping).await.unwrap();
    client.flush().await.unwrap();
    let alive = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, _) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::GOAWAY => return false,
                frame::kind::PING if hdr.flags & frame::flags::ACK != 0 => return true,
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for PING ACK");
    assert!(
        alive,
        "connection must survive a refused split header block (no GOAWAY)"
    );

    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn request_trailers_are_not_forwarded() {
    // Regression (#7): a request trailer section is decoded (to keep HPACK in sync) but its fields
    // must NOT be appended to the request header map handed to the backend.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let service = |req: Request| async move {
        let leaked = req.headers().get("x-trailer").cloned();
        let mut resp = hj_core::text_response(http::StatusCode::OK, "");
        if let Some(v) = leaked {
            resp.headers_mut().insert("x-echo", v); // x-echo is set ONLY if the trailer leaked through
        }
        resp
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();
    for _ in 0..3 {
        let _ = read_frame(&mut client).await;
    }

    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);

    // POST with a body, then a trailer section (END_STREAM) carrying a regular field.
    let mut hdr_block = Vec::new();
    enc.encode_header(&mut hdr_block, ":method", "POST");
    enc.encode_header(&mut hdr_block, ":path", "/upload");
    enc.encode_header(&mut hdr_block, ":scheme", "https");
    enc.encode_header(&mut hdr_block, ":authority", "example.com");
    let mut trailer_block = Vec::new();
    enc.encode_header(&mut trailer_block, "x-trailer", "leaked");

    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &hdr_block,
    );
    frame::write_frame(&mut buf, frame::kind::DATA, 0, 1, b"payload"); // body, no END_STREAM
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    frame::write_frame(&mut buf, frame::kind::HEADERS, end, 1, &trailer_block); // trailer section
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();

    let (status, leaked) = read_response(&mut client, &mut dec, 1).await;
    assert_eq!(
        status.as_deref(),
        Some("200"),
        "request with trailers must complete normally"
    );
    assert_eq!(
        leaked, None,
        "a request trailer field must NOT reach the backend as a request header"
    );

    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn malformed_request_trailers_reset_stream_and_keep_connection_usable() {
    // Trailer fields obey the ordinary field-name/value rules. The decoder must
    // consume malformed HPACK blocks, reset only their streams, and retain its
    // connection-scoped dynamic-table state.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut setup = Vec::new();
    frame::write_settings(&mut setup, &[]);
    client.write_all(&setup).await.unwrap();
    client.flush().await.unwrap();
    for _ in 0..3 {
        let _ = read_frame(&mut client).await;
    }

    let mut enc = Encoder::new();
    for (stream_id, split_trailer, trailer_name, trailer_value) in [
        (1, true, "X-Bad", "value"),
        (3, false, "connection", "close"),
        (5, false, "bad name", "value"),
    ] {
        let mut request_head = Vec::new();
        enc.encode_header(&mut request_head, ":method", "POST");
        enc.encode_header(&mut request_head, ":path", "/upload");
        enc.encode_header(&mut request_head, ":scheme", "https");
        enc.encode_header(&mut request_head, ":authority", "example.com");
        let mut trailer = Vec::new();
        enc.encode_header(&mut trailer, trailer_name, trailer_value);

        let mut wire = Vec::new();
        frame::write_frame(
            &mut wire,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS,
            stream_id,
            &request_head,
        );
        frame::write_frame(&mut wire, frame::kind::DATA, 0, stream_id, b"payload");
        if split_trailer {
            let split = trailer.len().div_ceil(2);
            frame::write_frame(
                &mut wire,
                frame::kind::HEADERS,
                frame::flags::END_STREAM,
                stream_id,
                &trailer[..split],
            );
            frame::write_frame(
                &mut wire,
                frame::kind::CONTINUATION,
                frame::flags::END_HEADERS,
                stream_id,
                &trailer[split..],
            );
        } else {
            frame::write_frame(
                &mut wire,
                frame::kind::HEADERS,
                frame::flags::END_HEADERS | frame::flags::END_STREAM,
                stream_id,
                &trailer,
            );
        }
        client.write_all(&wire).await.unwrap();
        client.flush().await.unwrap();

        let code = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let (hdr, payload) = read_frame(&mut client).await;
                match hdr.kind {
                    frame::kind::RST_STREAM if hdr.stream_id == stream_id => {
                        return u32::from_be_bytes(payload[..4].try_into().unwrap());
                    }
                    frame::kind::GOAWAY => panic!("malformed trailer killed the connection"),
                    _ => {}
                }
            }
        })
        .await
        .expect("malformed trailer must reset its stream");
        assert_eq!(code, frame::error_code::PROTOCOL_ERROR);
    }

    // A valid request after the resets proves HPACK state remained synchronized.
    let mut valid = Vec::new();
    enc.encode_header(&mut valid, ":method", "GET");
    enc.encode_header(&mut valid, ":path", "/after-trailers");
    enc.encode_header(&mut valid, ":scheme", "https");
    enc.encode_header(&mut valid, ":authority", "example.com");
    let mut wire = Vec::new();
    frame::write_frame(
        &mut wire,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        7,
        &valid,
    );
    client.write_all(&wire).await.unwrap();
    client.flush().await.unwrap();

    let mut dec = Decoder::new(4096, 1 << 20);
    let (status, _) = read_response(&mut client, &mut dec, 7).await;
    assert_eq!(status.as_deref(), Some("200"));

    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn respects_send_flow_control() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    // 30-byte in-memory body; the client grants only a 10-byte initial per-stream window.
    let service = |_req: Request| async move {
        hj_core::text_response(http::StatusCode::OK, "0123456789abcdefghijklmnopqrst")
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[(frame::settings::INITIAL_WINDOW_SIZE, 10)]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/fc"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    // The server must cap DATA at the 10-byte window and withhold END_STREAM.
    let mut body = Vec::new();
    let mut ended = false;
    loop {
        let (hdr, payload) = read_frame(&mut client).await;
        if hdr.kind == frame::kind::DATA {
            body.extend_from_slice(&payload);
            if hdr.flags & frame::flags::END_STREAM != 0 {
                ended = true;
            }
        }
        if body.len() >= 10 {
            break;
        }
    }
    assert_eq!(
        body.len(),
        10,
        "DATA must be capped at the 10-byte send window"
    );
    assert!(
        !ended,
        "END_STREAM must not arrive before the window is extended"
    );

    // Extend the window; the remaining 20 bytes + END_STREAM must follow.
    let mut wu = Vec::new();
    frame::write_window_update(&mut wu, 1, 100);
    client.write_all(&wu).await.unwrap();
    client.flush().await.unwrap();
    while !ended {
        let (hdr, payload) = read_frame(&mut client).await;
        if hdr.kind == frame::kind::DATA {
            body.extend_from_slice(&payload);
            if hdr.flags & frame::flags::END_STREAM != 0 {
                ended = true;
            }
        }
    }
    assert_eq!(
        body, b"0123456789abcdefghijklmnopqrst",
        "full body delivered after window extension"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn streams_an_uncached_file_over_h2() {
    use std::io::Write;
    // A 150 KB *uncached* file (Body::File, cached=None): must be streamed
    // asynchronously (never a blocking read) and cross the 65535 send window.
    let path = std::env::temp_dir().join(format!("hj-h2-uncached-{}.bin", std::process::id()));
    let content: Vec<u8> = (0..150 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&content)
        .unwrap();
    let len = content.len() as u64;

    let (mut client, server) = tokio::io::duplex(256 * 1024);
    let p = path.clone();
    let service = move |_req: Request| {
        let p = p.clone();
        async move {
            let body = Body::File(hj_core::FileBody {
                path: p,
                file: None,
                len,
                range: None,
                cached: None,
            });
            http::Response::builder().status(200).body(body).unwrap()
        }
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/file"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let body = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut body = Vec::new();
        let mut consumed = 0u32;
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::DATA {
                body.extend_from_slice(&payload);
                consumed += payload.len() as u32;
                if consumed >= 16384 {
                    let mut wu = Vec::new();
                    frame::write_window_update(&mut wu, 0, consumed);
                    frame::write_window_update(&mut wu, 1, consumed);
                    client.write_all(&wu).await.unwrap();
                    client.flush().await.unwrap();
                    consumed = 0;
                }
                if hdr.flags & frame::flags::END_STREAM != 0 {
                    break;
                }
            }
        }
        body
    })
    .await
    .expect("uncached file must stream to completion without blocking");
    assert_eq!(
        body, content,
        "streamed file body must match the file byte-for-byte"
    );
    drop(client);
    let _ = srv.await;
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn malformed_request_is_reset_not_goaway() {
    // A duplicated :method pseudo-header is malformed (§8.1.2) — it must reset the
    // stream, not kill the connection.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();

    let mut enc = Encoder::new();
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "GET");
    enc.encode_header(&mut block, ":method", "POST"); // duplicate -> malformed
    enc.encode_header(&mut block, ":path", "/");
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &block,
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let rst = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, _) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::RST_STREAM if hdr.stream_id == 1 => return true,
                frame::kind::GOAWAY => return false,
                _ => {}
            }
        }
    })
    .await
    .expect("server must respond");
    assert!(rst, "a malformed request must be RST_STREAM'd, not GOAWAY");
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn malformed_path_pseudo_header_is_reset() {
    // A `:path` that is not a valid URI (here: an embedded space) is rejected when the
    // pseudo-header is parsed into `http::Uri` AT DECODE TIME — it must RST the stream, not
    // kill the connection. Guards the alloc-saving change that moved typed pseudo-header
    // construction out of `build_request` into the decode callback.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();

    let mut enc = Encoder::new();
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "GET");
    enc.encode_header(&mut block, ":path", "/ bad path"); // space -> invalid URI -> malformed
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &block,
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let rst = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, _) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::RST_STREAM if hdr.stream_id == 1 => return true,
                frame::kind::GOAWAY => return false,
                _ => {}
            }
        }
    })
    .await
    .expect("server must respond");
    assert!(rst, "an invalid :path must be RST_STREAM'd, not GOAWAY");
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn absolute_form_path_pseudo_header_is_reset() {
    // Regression (#85): RFC 9113 §8.3.1 — :path MUST be origin-form. An absolute-form :path
    // (its own scheme + authority) is malformed and dangerous: downstream `uri().host()` would
    // disagree with the routed :authority/Host (foreign-host cache-protection bypass). It must
    // RST the stream, not be accepted or GOAWAY the connection.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();

    let mut enc = Encoder::new();
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "GET");
    enc.encode_header(&mut block, ":path", "https://evil.example/foo"); // absolute-form -> malformed
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "good.example");
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &block,
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let rst = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, _) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::RST_STREAM if hdr.stream_id == 1 => return true,
                frame::kind::GOAWAY => return false,
                _ => {}
            }
        }
    })
    .await
    .expect("server must respond");
    assert!(
        rst,
        "an absolute-form :path must be RST_STREAM'd, not accepted or GOAWAY"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn malformed_host_fallback_is_reset_on_the_wire() {
    // When :authority is omitted, Host supplies the effective authority. Exercise
    // the full HPACK/frame receive path so malformed Host values cannot bypass the
    // stricter HTTP(S) authority checks at the pseudo-header seam.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();

    let mut enc = Encoder::new();
    for (index, host) in ["bad host", "user@example.com", "example.com:abc", ":443"]
        .into_iter()
        .enumerate()
    {
        let stream_id = 1 + (index as u32 * 2);
        let mut block = Vec::new();
        enc.encode_header(&mut block, ":method", "GET");
        enc.encode_header(&mut block, ":scheme", "https");
        enc.encode_header(&mut block, ":path", "/");
        enc.encode_header(&mut block, "host", host);
        let mut req = Vec::new();
        frame::write_frame(
            &mut req,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS | frame::flags::END_STREAM,
            stream_id,
            &block,
        );
        client.write_all(&req).await.unwrap();
        client.flush().await.unwrap();

        let rst = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let (hdr, _) = read_frame(&mut client).await;
                match hdr.kind {
                    frame::kind::RST_STREAM if hdr.stream_id == stream_id => return true,
                    frame::kind::GOAWAY => return false,
                    _ => {}
                }
            }
        })
        .await
        .expect("server must respond");
        assert!(rst, "malformed Host {host:?} must reset its stream");
    }

    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn connect_request_is_reset_as_malformed() {
    // (#1015) RFC 9113 §8.5: CONNECT carrying :scheme/:path is malformed and must never be
    // dispatched as an ordinary method (H3 rejects it the same way); the connection lives on.
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mut client, srv) = open_client(Config::default(), calls.clone()).await;
    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let mut block = Vec::new();
    for (n, v) in [
        (":method", "CONNECT"),
        (":path", "/"),
        (":scheme", "https"),
        (":authority", "example.com:443"),
    ] {
        enc.encode_header(&mut block, n, v);
    }
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &block,
    );
    write_ping(&mut buf);
    client.write_all(&buf).await.unwrap();
    assert_eq!(
        stream_events_until_ping_ack(&mut client, &mut dec, 1).await,
        StreamEvents {
            responses: Vec::new(),
            resets: vec![frame::error_code::PROTOCOL_ERROR],
        }
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(client);
    let _ = srv.await;
}

/// Echo `x-dyn` back as `x-echo`; count every dispatched request.
fn echo_counting_service(
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> impl Fn(Request) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> + Clone
{
    move |req: Request| {
        let calls = calls.clone();
        Box::pin(async move {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let echoed = req.headers().get("x-dyn").cloned();
            let mut resp = hj_core::text_response(http::StatusCode::OK, "");
            if let Some(v) = echoed {
                resp.headers_mut().insert("x-echo", v);
            }
            resp
        })
    }
}

async fn open_client(
    config: Config,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    let service = echo_counting_service(calls);
    let srv = tokio::spawn(async move {
        let _ = serve(server, service, config, None).await;
    });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();
    for _ in 0..3 {
        let _ = read_frame(&mut client).await; // SETTINGS, WINDOW_UPDATE, SETTINGS ACK
    }
    (client, srv)
}

/// Read frames until an RST_STREAM for `sid` and return its error code; panic on GOAWAY
/// or on response HEADERS for `sid`. Decodes every HEADERS block to keep `dec` in sync.
async fn expect_reset<R: AsyncReadExt + Unpin>(r: &mut R, dec: &mut Decoder, sid: u32) -> u32 {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(r).await;
            match hdr.kind {
                frame::kind::GOAWAY => panic!("connection GOAWAYed instead of resetting {sid}"),
                frame::kind::HEADERS => {
                    assert_ne!(hdr.stream_id, sid, "response written on reset stream {sid}");
                    dec.decode(&payload, |_, _| {}).unwrap();
                }
                frame::kind::RST_STREAM if hdr.stream_id == sid => {
                    return u32::from_be_bytes(payload[..4].try_into().unwrap());
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for RST_STREAM on stream {sid}"))
}

#[tokio::test]
async fn header_bomb_is_a_stream_reset_not_connection_fatal() {
    // The "HTTP/2 Bomb": single-byte indexed references to static index 32 (`cookie: ""`)
    // each append a full field, so the 64 KiB wire cap never fires; the decoded-list cap
    // must. Regression (#595): that used to GOAWAY the whole connection, so one oversized
    // request relayed by Cloudflare tore down a pooled origin connection carrying other
    // users' streams. Now the block is still decoded to the end (keeping the HPACK table in
    // sync — here it inserts `x-dyn: v1` before the bomb) and only its stream is answered,
    // with H1's 431 rather than the retry-safe REFUSED_STREAM (#1014).
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = Config {
        header_list_size: 1024,
        ..Config::default()
    };
    let (mut client, srv) = open_client(config, calls.clone()).await;
    let mut dec = Decoder::new(4096, 1 << 20);
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    // Pseudo-headers as static-table references and a non-indexing literal, so the
    // only dynamic-table insert on the connection is the one after the bomb.
    let mut get = vec![0x82, 0x84, 0x87, 0x01, 0x0b];
    get.extend_from_slice(b"example.com");

    // Stream 1: the bomb crosses the cap, THEN inserts `x-dyn: v1`. A decoder that
    // stopped at the cap would never make that insert.
    let mut block = get.clone();
    block.extend(std::iter::repeat_n(0xA0u8, 1024));
    block.extend_from_slice(&[0x40, 0x05]);
    block.extend_from_slice(b"x-dyn");
    block.push(0x02);
    block.extend_from_slice(b"v1");
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, frame::kind::HEADERS, end, 1, &block);
    write_ping(&mut buf);
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(
        stream_events_until_ping_ack(&mut client, &mut dec, 1).await,
        too_large("431", false)
    );

    // Stream 3 references dynamic index 62: it resolves to `x-dyn: v1` only if the
    // server consumed the whole over-cap block.
    let mut block = get.clone();
    block.push(0x80 | 62);
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, frame::kind::HEADERS, end, 3, &block);
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();
    let (status, echo) = read_response(&mut client, &mut dec, 3).await;
    assert_eq!(
        status.as_deref(),
        Some("200"),
        "connection must survive the bomb"
    );
    assert_eq!(echo.as_deref(), Some("v1"), "HPACK table must stay in sync");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "bomb never dispatched"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn oversized_headers_with_a_body_pending_get_431_then_a_no_error_reset() {
    // (#1014) The client has not ended the stream, so the 431 is followed by
    // RST_STREAM(NO_ERROR) asking it to stop sending (§8.1).
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = Config {
        header_list_size: 1024,
        ..Config::default()
    };
    let (mut client, srv) = open_client(config, calls.clone()).await;
    let mut dec = Decoder::new(4096, 1 << 20);
    let mut block = vec![0x82, 0x84, 0x87, 0x01, 0x0b];
    block.extend_from_slice(b"example.com");
    block.extend(std::iter::repeat_n(0xA0u8, 1024));
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &block,
    );
    write_ping(&mut buf);
    client.write_all(&buf).await.unwrap();
    assert_eq!(
        stream_events_until_ping_ack(&mut client, &mut dec, 1).await,
        too_large("431", true)
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn exhausted_body_budget_refuses_the_stream_not_the_connection() {
    // Regression (#597): the request-body budget is server-wide, so exhaustion caused by
    // OTHER connections must refuse this stream, not GOAWAY a pooled connection.
    let budget = std::sync::Arc::new(hj_core::budget::BodyBufferBudget::new(1024));
    let mut hog = hj_core::budget::BodyBufferLease::new(budget.clone());
    assert!(hog.reserve(1024));
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = Config {
        body_budget: Some(budget.clone()),
        ..Config::default()
    };
    let (mut client, srv) = open_client(config, calls.clone()).await;
    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);

    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get_with(&mut enc, "/upload", &[("content-length", "1")]),
    );
    frame::write_frame(
        &mut buf,
        frame::kind::DATA,
        frame::flags::END_STREAM,
        1,
        b"x",
    );
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(
        expect_reset(&mut client, &mut dec, 1).await,
        frame::error_code::REFUSED_STREAM
    );

    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        3,
        &encode_get(&mut enc, "/after"),
    );
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();
    let (status, _) = read_response(&mut client, &mut dec, 3).await;
    assert_eq!(status.as_deref(), Some("200"));
    assert_eq!(
        budget.in_flight(),
        1024,
        "the refused stream holds no budget"
    );
    drop(hog);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn pre_response_window_overflow_reset_tears_down_the_receiving_stream() {
    // Regression (#598, residual of #581): a WINDOW_UPDATE that overflows the parked
    // pre-response credit makes the server RST the stream from the connection loop (not
    // through rst!). A later DATA...END_STREAM must not then dispatch the request and
    // write a response on the stream the server already reset.
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mut client, srv) = open_client(Config::default(), calls.clone()).await;
    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);

    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get_with(&mut enc, "/one", &[("content-length", "5")]),
    );
    let mut wu = Vec::new();
    wu.extend_from_slice(&0x7fff_ffffu32.to_be_bytes());
    frame::write_frame(&mut buf, frame::kind::WINDOW_UPDATE, 0, 1, &wu);
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(
        expect_reset(&mut client, &mut dec, 1).await,
        frame::error_code::FLOW_CONTROL_ERROR
    );

    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::DATA,
        frame::flags::END_STREAM,
        1,
        b"hello",
    );
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        3,
        &encode_get(&mut enc, "/sync"),
    );
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();
    // read_response panics on a GOAWAY; expect_reset above already asserted that no
    // response HEADERS for stream 1 preceded the reset. Any HEADERS for 1 now would be
    // decoded here before stream 3's and is caught by the call count.
    let (status, _) = read_response(&mut client, &mut dec, 3).await;
    assert_eq!(status.as_deref(), Some("200"));
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the reset stream 1 must never be dispatched"
    );
    drop(client);
    let _ = srv.await;
}

/// Regression (#599), tokio loop: a response waiting on credit the reader withholds
/// (while it keeps the connection alive with PINGs) is reset by the send-stall deadline.
#[tokio::test]
async fn send_stall_deadline_resets_a_credit_starved_response() {
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    let config = Config {
        conn_idle_timeout: Some(std::time::Duration::from_secs(10)),
        send_stall_timeout: Some(std::time::Duration::from_millis(300)),
        ..Config::default()
    };
    let service =
        |_req: Request| async { Response::new(Body::Full(Bytes::from(vec![b'x'; 64 * 1024]))) };
    let srv = tokio::spawn(async move { serve(server, service, config, None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[(frame::settings::INITIAL_WINDOW_SIZE, 0)]);
    let mut enc = Encoder::new();
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &encode_get(&mut enc, "/big"),
    );
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();

    let started = std::time::Instant::now();
    let code = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            tokio::select! {
                (hdr, payload) = read_frame(&mut client) => {
                    assert_ne!(hdr.kind, frame::kind::DATA, "no credit, no DATA");
                    assert_ne!(hdr.kind, frame::kind::GOAWAY, "only the response is reset");
                    if hdr.kind == frame::kind::RST_STREAM && hdr.stream_id == 1 {
                        return u32::from_be_bytes(payload[..4].try_into().unwrap());
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    let mut ping = Vec::new();
                    frame::write_frame(&mut ping, frame::kind::PING, 0, 0, &[0u8; 8]);
                    client.write_all(&ping).await.unwrap();
                }
            }
        }
    })
    .await
    .expect("the starved response must be reset");
    assert_eq!(code, frame::error_code::CANCEL);
    assert!(started.elapsed() < std::time::Duration::from_millis(1500));
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn advertises_max_header_list_size() {
    // The opening SETTINGS must carry SETTINGS_MAX_HEADER_LIST_SIZE so a well-behaved peer
    // (Cloudflare) self-limits — the advertised half of the bomb mitigation (RFC 7540 §6.5.2).
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let config = Config {
        header_list_size: 12345,
        ..Config::default()
    };
    let srv = tokio::spawn(async move { serve(server, noop_service, config, None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();

    let (hdr, payload) = read_frame(&mut client).await; // server SETTINGS
    assert_eq!(hdr.kind, frame::kind::SETTINGS);
    // SETTINGS payload is repeated (u16 id, u32 value); locate id 0x6.
    let mut advertised = None;
    for entry in payload.chunks_exact(6) {
        let id = u16::from_be_bytes(entry[..2].try_into().unwrap());
        if id == frame::settings::MAX_HEADER_LIST_SIZE {
            advertised = Some(u32::from_be_bytes(entry[2..6].try_into().unwrap()));
        }
    }
    assert_eq!(
        advertised,
        Some(12345),
        "opening SETTINGS must advertise MAX_HEADER_LIST_SIZE"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn idle_connection_is_goaway_after_timeout() {
    // FIX 2 (defense-in-depth): a connection that completes the handshake then goes silent
    // must be GOAWAY'd (NO_ERROR) once `conn_idle_timeout` elapses — freeing anything a
    // stalled peer holds open (e.g. a HEADERS block left open without END_STREAM). hj-h2
    // previously had no per-connection read deadline, so such a hold lived forever.
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let config = Config {
        conn_idle_timeout: Some(std::time::Duration::from_millis(150)),
        ..Config::default()
    };
    let srv = tokio::spawn(async move { serve(server, noop_service, config, None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();

    // Stay silent after the handshake; the idle timer must fire and produce a graceful GOAWAY.
    let code = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::GOAWAY {
                return u32::from_be_bytes(payload[4..8].try_into().unwrap());
            }
        }
    })
    .await
    .expect("an idle connection must be GOAWAY'd after the timeout");
    assert_eq!(code, frame::error_code::NO_ERROR);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn partial_frame_has_an_absolute_deadline() {
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let config = Config {
        conn_idle_timeout: Some(std::time::Duration::from_secs(2)),
        frame_read_timeout: Some(std::time::Duration::from_millis(100)),
        ..Config::default()
    };
    let srv = tokio::spawn(async move { serve(server, noop_service, config, None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut settings = Vec::new();
    frame::write_settings(&mut settings, &[]);
    client.write_all(&settings).await.unwrap();

    // Announce a frame payload but provide only one byte. The connection idle
    // timer is deliberately much longer than the frame deadline.
    let mut partial = Vec::new();
    frame::write_frame(&mut partial, frame::kind::DATA, 0, 1, &[0; 32]);
    client
        .write_all(&partial[..FrameHeader::LEN + 1])
        .await
        .unwrap();
    client.flush().await.unwrap();

    let code = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::GOAWAY {
                return u32::from_be_bytes(payload[4..8].try_into().unwrap());
            }
        }
    })
    .await
    .expect("partial frame must expire independently of connection idleness");
    assert_eq!(code, frame::error_code::PROTOCOL_ERROR);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn unfinished_header_block_has_an_absolute_deadline() {
    // Regression (#1012): complete, empty CONTINUATION frames neither leave a partial frame
    // nor let the idle timer fire, so the open header block needs its own deadline.
    let (client, server) = tokio::io::duplex(16 * 1024);
    let config = Config {
        conn_idle_timeout: Some(std::time::Duration::from_secs(2)),
        frame_read_timeout: Some(std::time::Duration::from_millis(100)),
        ..Config::default()
    };
    let srv = tokio::spawn(async move { serve(server, noop_service, config, None).await });
    let (mut reader, mut writer) = tokio::io::split(client);
    let mut wire = hj_h2::conn::PREFACE.to_vec();
    frame::write_settings(&mut wire, &[]);
    let block = encode_get(&mut Encoder::new(), "/");
    frame::write_frame(
        &mut wire,
        frame::kind::HEADERS,
        frame::flags::END_STREAM,
        1,
        &block,
    );
    writer.write_all(&wire).await.unwrap();
    let trickle = tokio::spawn(async move {
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            let mut empty = Vec::new();
            frame::write_frame(&mut empty, frame::kind::CONTINUATION, 0, 1, &[]);
            if writer.write_all(&empty).await.is_err() {
                break;
            }
        }
    });

    let code = tokio::time::timeout(std::time::Duration::from_millis(700), async {
        loop {
            let (hdr, payload) = read_frame(&mut reader).await;
            assert_ne!(
                hdr.kind,
                frame::kind::HEADERS,
                "unfinished block dispatched"
            );
            if hdr.kind == frame::kind::GOAWAY {
                return u32::from_be_bytes(payload[4..8].try_into().unwrap());
            }
        }
    })
    .await
    .expect("CONTINUATION frames must not extend the header-block deadline");
    assert_eq!(code, frame::error_code::PROTOCOL_ERROR);
    trickle.abort();
    drop(reader);
    let _ = srv.await;
}

#[tokio::test]
async fn unfinished_request_body_expires_while_other_frames_arrive() {
    let (mut client, server) = tokio::io::duplex(32 * 1024);
    let config = Config {
        conn_idle_timeout: Some(std::time::Duration::from_secs(2)),
        request_body_timeout: Some(std::time::Duration::from_millis(120)),
        ..Config::default()
    };
    let srv = tokio::spawn(async move { serve(server, noop_service, config, None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut settings = Vec::new();
    frame::write_settings(&mut settings, &[]);
    client.write_all(&settings).await.unwrap();

    let mut enc = Encoder::new();
    let mut block = Vec::new();
    for (name, value) in [
        (":method", "POST"),
        (":scheme", "https"),
        (":path", "/upload"),
        ("content-length", "10"),
    ] {
        enc.encode_header(&mut block, name, value);
    }
    let mut headers = Vec::new();
    frame::write_frame(
        &mut headers,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &block,
    );
    client.write_all(&headers).await.unwrap();
    client.flush().await.unwrap();

    // Keep the connection active with control traffic; this must not extend
    // stream 1's request-body deadline.
    for nonce in 0..5u8 {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let mut ping = Vec::new();
        frame::write_frame(&mut ping, frame::kind::PING, 0, 0, &[nonce; 8]);
        client.write_all(&ping).await.unwrap();
        client.flush().await.unwrap();
    }

    let code = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::RST_STREAM && hdr.stream_id == 1 {
                return u32::from_be_bytes(payload[..4].try_into().unwrap());
            }
        }
    })
    .await
    .expect("unfinished body must expire despite connection activity");
    assert_eq!(code, frame::error_code::CANCEL);
    drop(client);
    let _ = srv.await;
}

/// (#1035) Each 16 KiB of a stream's own DATA restarts its body window, so a steady upload
/// outlasting the timeout is answered, while the ceiling still resets it. Paused clock:
/// `chunks` DATA frames of 16 KiB, one every 400 ms, against a 1 s body timeout.
async fn paced_upload_end(
    ceiling: std::time::Duration,
    chunks: usize,
) -> (Result<Vec<u8>, u32>, std::time::Duration) {
    let (client, server) = tokio::io::duplex(1 << 20);
    let config = Config {
        conn_idle_timeout: None,
        request_body_timeout: Some(std::time::Duration::from_secs(1)),
        request_body_ceiling: ceiling,
        ..Config::default()
    };
    let service = |req: Request| async move {
        let body = req.into_body().collect().await.unwrap().to_bytes();
        hj_core::text_response(http::StatusCode::OK, body.len().to_string())
    };
    let srv = tokio::spawn(async move { serve(server, service, config, None).await });
    let (mut reader, mut writer) = tokio::io::split(client);
    let mut wire = hj_h2::conn::PREFACE.to_vec();
    frame::write_settings(&mut wire, &[]);
    let mut enc = Encoder::new();
    let mut block = Vec::new();
    let length = (chunks * 16 * 1024).to_string();
    for (name, value) in [
        (":method", "POST"),
        (":scheme", "https"),
        (":path", "/upload"),
        ("content-length", length.as_str()),
    ] {
        enc.encode_header(&mut block, name, value);
    }
    frame::write_frame(
        &mut wire,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &block,
    );
    writer.write_all(&wire).await.unwrap();
    let started = tokio::time::Instant::now();
    let upload = tokio::spawn(async move {
        for index in 0..chunks {
            let flags = if index + 1 == chunks {
                frame::flags::END_STREAM
            } else {
                0
            };
            let mut data = Vec::new();
            frame::write_frame(&mut data, frame::kind::DATA, flags, 1, &[b'x'; 16 * 1024]);
            writer.write_all(&data).await.unwrap();
            if index + 1 < chunks {
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
        }
        writer
    });
    let mut body = Vec::new();
    let end = loop {
        let (hdr, payload) = read_frame(&mut reader).await;
        if hdr.stream_id != 1 {
            continue;
        }
        if hdr.kind == frame::kind::RST_STREAM {
            break Err(u32::from_be_bytes(payload[..4].try_into().unwrap()));
        }
        if hdr.kind == frame::kind::DATA {
            body.extend_from_slice(&payload);
            if hdr.flags & frame::flags::END_STREAM != 0 {
                break Ok(body);
            }
        }
    };
    let took = started.elapsed();
    drop(upload.await.unwrap());
    drop(reader);
    let _ = srv.await;
    (end, took)
}

#[tokio::test(start_paused = true)]
async fn steady_request_body_outlasting_the_timeout_is_answered() {
    let (end, took) = paced_upload_end(hj_core::body_deadline::BODY_DEADLINE_CEILING, 7).await;
    assert_eq!(end, Ok(b"114688".to_vec()));
    assert!(took >= std::time::Duration::from_millis(2400), "{took:?}");
}

#[tokio::test(start_paused = true)]
async fn steady_request_body_is_reset_at_the_ceiling() {
    let ceiling = std::time::Duration::from_millis(1500);
    let (end, took) = paced_upload_end(ceiling, 10).await;
    assert_eq!(end, Err(frame::error_code::CANCEL));
    assert!(
        took >= ceiling && took < ceiling + std::time::Duration::from_millis(10),
        "{took:?}"
    );
}

#[tokio::test]
async fn rejects_data_on_stream_zero() {
    // DATA on stream 0 is a connection error (§6.1) -> GOAWAY.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut bad = Vec::new();
    frame::write_frame(&mut bad, frame::kind::DATA, 0, 0, b"x");
    client.write_all(&bad).await.unwrap();
    client.flush().await.unwrap();

    let goaway = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, _) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::GOAWAY {
                return true;
            }
        }
    })
    .await
    .expect("server must respond");
    assert!(goaway, "DATA on stream 0 must trigger GOAWAY");
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn graceful_shutdown_drains_inflight() {
    // (OPS2) On the shutdown signal the server must GOAWAY *and* still finish the
    // in-flight request, not cut the connection.
    use tokio_util::sync::CancellationToken;
    let token = CancellationToken::new();
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let service = |_req: Request| async move {
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        hj_core::text_response(http::StatusCode::OK, "drained")
    };
    let tok = token.clone();
    let srv =
        tokio::spawn(async move { serve(server, service, Config::default(), Some(tok)).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/x"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    // Let the request reach the (slow) handler, then signal shutdown.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    token.cancel();

    let (goaway, body) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut goaway = false;
        let mut body = Vec::new();
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::GOAWAY => goaway = true,
                frame::kind::DATA if hdr.stream_id == 1 => body.extend_from_slice(&payload),
                _ => {}
            }
            if goaway && body == b"drained" {
                return (goaway, body);
            }
        }
    })
    .await
    .expect("server must GOAWAY and drain the in-flight response");
    assert!(goaway, "shutdown must send GOAWAY");
    assert_eq!(
        body, b"drained",
        "in-flight request must finish during graceful drain"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn graceful_shutdown_drains_window_blocked_body() {
    // Shutdown after the response starts but before the peer grants more send-window
    // credit must still read WINDOW_UPDATE and finish the body.
    use tokio_util::sync::CancellationToken;
    let token = CancellationToken::new();
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let service = |_req: Request| async move {
        hj_core::text_response(http::StatusCode::OK, "0123456789abcdefghijklmnopqrst")
    };
    let tok = token.clone();
    let srv =
        tokio::spawn(async move { serve(server, service, Config::default(), Some(tok)).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[(frame::settings::INITIAL_WINDOW_SIZE, 10)]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/drain-window"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let mut body = Vec::new();
    let mut ended = false;
    while body.len() < 10 {
        let (hdr, payload) = read_frame(&mut client).await;
        if hdr.kind == frame::kind::DATA && hdr.stream_id == 1 {
            body.extend_from_slice(&payload);
            ended |= hdr.flags & frame::flags::END_STREAM != 0;
        }
    }
    assert_eq!(body.len(), 10);
    assert!(
        !ended,
        "body must be blocked by the peer's small initial window"
    );

    token.cancel();
    let mut wu = Vec::new();
    frame::write_window_update(&mut wu, 1, 100);
    client.write_all(&wu).await.unwrap();
    client.flush().await.unwrap();

    let (saw_goaway, body, ended) =
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut saw_goaway = false;
            while !saw_goaway || !ended {
                let (hdr, payload) = read_frame(&mut client).await;
                match hdr.kind {
                    frame::kind::GOAWAY => saw_goaway = true,
                    frame::kind::DATA if hdr.stream_id == 1 => {
                        body.extend_from_slice(&payload);
                        ended |= hdr.flags & frame::flags::END_STREAM != 0;
                    }
                    _ => {}
                }
            }
            (saw_goaway, body, ended)
        })
        .await
        .expect("shutdown must drain a window-blocked response after WINDOW_UPDATE");
    assert!(saw_goaway);
    assert!(ended);
    assert_eq!(body, b"0123456789abcdefghijklmnopqrst");
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn rejects_content_length_mismatch() {
    // §8.1.2.6: a content-length that doesn't match the DATA bytes is malformed -> RST.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();

    let mut enc = Encoder::new();
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "POST");
    enc.encode_header(&mut block, ":path", "/");
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    enc.encode_header(&mut block, "content-length", "5");
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &block,
    );
    frame::write_frame(
        &mut req,
        frame::kind::DATA,
        frame::flags::END_STREAM,
        1,
        b"abc",
    ); // 3 != 5
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let rst = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, _) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::RST_STREAM if hdr.stream_id == 1 => return true,
                frame::kind::GOAWAY => return false,
                _ => {}
            }
        }
    })
    .await
    .expect("server must respond");
    assert!(rst, "content-length mismatch must reset the stream");
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn head_request_sends_headers_with_content_length_but_no_body() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    // A backend (PHP over LSAPI) may return a body for a HEAD; the server must drop it
    // while keeping the headers (incl. Content-Length) — never emitting DATA frames.
    let service = |_req: Request| async move {
        let mut resp = hj_core::text_response(http::StatusCode::OK, "BODY-THAT-MUST-NOT-SHIP");
        resp.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("23"),
        );
        resp
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "HEAD");
    enc.encode_header(&mut block, ":path", "/");
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    let mut hframe = Vec::new();
    frame::write_frame(
        &mut hframe,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &block,
    );
    client.write_all(&hframe).await.unwrap();
    client.flush().await.unwrap();

    let mut dec = Decoder::new(4096, 1 << 20);
    let mut content_length = None;
    let mut headers_end_stream = false;
    let mut saw_data = false;
    let res = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::HEADERS => {
                    dec.decode(&payload, |n, v| {
                        if n == "content-length" {
                            content_length = Some(v.to_string());
                        }
                    })
                    .unwrap();
                    if hdr.flags & frame::flags::END_STREAM != 0 {
                        headers_end_stream = true;
                        return;
                    }
                }
                frame::kind::DATA if hdr.stream_id == 1 => {
                    saw_data = true;
                    return;
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(res.is_ok(), "server did not respond to HEAD");
    assert!(
        headers_end_stream,
        "HEAD response HEADERS must carry END_STREAM"
    );
    assert!(!saw_data, "HEAD response must not send a DATA frame");
    assert_eq!(
        content_length.as_deref(),
        Some("23"),
        "Content-Length must be preserved on HEAD"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn no_content_status_sends_headers_only_and_strips_content_length() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let service = |_req: Request| async move {
        let mut resp = hj_core::text_response(http::StatusCode::NO_CONTENT, "MUST-NOT-SHIP");
        resp.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("13"),
        );
        resp
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/no-content"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let mut dec = Decoder::new(4096, 1 << 20);
    let mut status = None;
    let mut content_length = None;
    let mut headers_end_stream = false;
    let mut saw_data = false;
    let res = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::HEADERS => {
                    dec.decode(&payload, |n, v| {
                        if n == ":status" {
                            status = Some(v.to_string());
                        } else if n == "content-length" {
                            content_length = Some(v.to_string());
                        }
                    })
                    .unwrap();
                    if hdr.flags & frame::flags::END_STREAM != 0 {
                        headers_end_stream = true;
                        return;
                    }
                }
                frame::kind::DATA if hdr.stream_id == 1 => {
                    saw_data = true;
                    return;
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(res.is_ok(), "server did not respond to 204");
    assert_eq!(status.as_deref(), Some("204"));
    assert!(
        headers_end_stream,
        "204 response HEADERS must carry END_STREAM"
    );
    assert!(!saw_data, "204 response must not send DATA");
    assert!(
        content_length.is_none(),
        "204 response must strip Content-Length"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn streaming_response_strips_stale_content_length() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let service = |_req: Request| async move {
        let stream = http_body_util::Full::new(Bytes::from_static(b"stream-body"))
            .map_err(|e| match e {})
            .boxed();
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_LENGTH, "999")
            .body(Body::Stream(stream))
            .unwrap()
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/stream-cl"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let mut dec = Decoder::new(4096, 1 << 20);
    let mut status = None;
    let mut content_length = None;
    let mut body = Vec::new();
    let res = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::HEADERS => {
                    dec.decode(&payload, |n, v| {
                        if n == ":status" {
                            status = Some(v.to_string());
                        } else if n == "content-length" {
                            content_length = Some(v.to_string());
                        }
                    })
                    .unwrap();
                }
                frame::kind::DATA if hdr.stream_id == 1 => {
                    body.extend_from_slice(&payload);
                    if hdr.flags & frame::flags::END_STREAM != 0 {
                        return;
                    }
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(res.is_ok(), "server did not finish streaming response");
    assert_eq!(status.as_deref(), Some("200"));
    assert!(
        content_length.is_none(),
        "streaming h2 response must strip stale Content-Length"
    );
    assert_eq!(body, b"stream-body");
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn rst_stream_suppresses_in_flight_handler_response() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    // /slow sleeps so we can RST it mid-flight; /fast answers at once. The reset stream's
    // (eventual) response must never reach the wire; the other stream is unaffected.
    let service = |req: Request| async move {
        if req.uri().path() == "/slow" {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        hj_core::text_response(http::StatusCode::OK, "ok")
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/slow"),
    );
    frame::write_rst_stream(&mut req, 1, frame::error_code::CANCEL);
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        3,
        &encode_get(&mut enc, "/fast"),
    );
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    // Collect every HEADERS stream id until the read idles out (well past the 150 ms slow
    // sleep, so a non-suppressed stream-1 response would have arrived).
    let mut headers_sids = std::collections::HashSet::new();
    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        loop {
            let (hdr, _payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::HEADERS {
                headers_sids.insert(hdr.stream_id);
            }
        }
    })
    .await;
    assert!(
        headers_sids.contains(&3),
        "non-reset stream 3 must still respond"
    );
    assert!(
        !headers_sids.contains(&1),
        "reset stream 1 must not produce a response"
    );
    drop(client);
    let _ = srv.await;
}

// Issue A5: a RST_STREAM that arrives AFTER a stream's handler already resolved must NOT record a
// `cancelled` entry — the future is gone, there is nothing to suppress. The old code inserted one
// unconditionally, so a run of late RSTs filled the bounded `cancelled` set and then SILENTLY
// disabled reset-suppression for a *subsequent*, genuinely in-flight reset. With a tiny
// max_concurrent_streams the cap (= max_concurrent * 2 = 4) exhausts after a handful of late RSTs
// on the old code; the fix keeps `cancelled` empty so the later in-flight reset still suppresses.
#[tokio::test]
async fn late_rst_does_not_exhaust_cancelled_set() {
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    let service = |req: Request| async move {
        if req.uri().path() == "/slow" {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        hj_core::text_response(http::StatusCode::OK, "ok")
    };
    let mut config = Config::default();
    config.max_concurrent_streams = 2; // cancelled cap = 4
    let srv = tokio::spawn(async move { serve(server, service, config, None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;

    // 5 sequential fast streams; each is read to its END_STREAM (so its handler future has fully
    // drained — deterministic, no sleeps) BEFORE we send a LATE RST for it. On the old code these
    // 5 late RSTs fill+exhaust the cap-4 `cancelled` set.
    for sid in [1u32, 3, 5, 7, 9] {
        let mut h = Vec::new();
        frame::write_frame(
            &mut h,
            frame::kind::HEADERS,
            end,
            sid,
            &encode_get(&mut enc, "/fast"),
        );
        client.write_all(&h).await.unwrap();
        client.flush().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let (hdr, _p) = read_frame(&mut client).await;
                if hdr.stream_id == sid && (hdr.flags & frame::flags::END_STREAM) != 0 {
                    return;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("fast stream {sid} must complete"));
        let mut r = Vec::new();
        frame::write_rst_stream(&mut r, sid, frame::error_code::CANCEL);
        client.write_all(&r).await.unwrap();
        client.flush().await.unwrap();
    }

    // A genuinely in-flight reset: open /slow on 11 and RST it before its 150 ms resolve. Its
    // response MUST be suppressed — which fails on the old code because `cancelled` is already
    // full of the stale late-RST ids. Fresh /fast stream 13 proves suppression stays selective.
    let mut h = Vec::new();
    frame::write_frame(
        &mut h,
        frame::kind::HEADERS,
        end,
        11,
        &encode_get(&mut enc, "/slow"),
    );
    frame::write_rst_stream(&mut h, 11, frame::error_code::CANCEL);
    frame::write_frame(
        &mut h,
        frame::kind::HEADERS,
        end,
        13,
        &encode_get(&mut enc, "/fast"),
    );
    client.write_all(&h).await.unwrap();
    client.flush().await.unwrap();

    let mut seen = std::collections::HashSet::new();
    let _ = tokio::time::timeout(std::time::Duration::from_millis(600), async {
        loop {
            let (hdr, _p) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::HEADERS {
                seen.insert(hdr.stream_id);
            }
        }
    })
    .await;
    assert!(seen.contains(&13), "fresh stream 13 must still respond");
    assert!(
        !seen.contains(&11),
        "in-flight reset stream 11 must stay suppressed — late RSTs must not exhaust `cancelled`"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn strips_hop_by_hop_response_headers() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let service = |_req: Request| async move {
        let mut resp = hj_core::text_response(http::StatusCode::OK, "ok");
        resp.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("keep-alive"),
        );
        resp.headers_mut().insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        resp.headers_mut()
            .insert("x-keep", http::HeaderValue::from_static("yes"));
        resp
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let mut hframe = Vec::new();
    frame::write_frame(
        &mut hframe,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &encode_get(&mut enc, "/"),
    );
    client.write_all(&hframe).await.unwrap();
    client.flush().await.unwrap();

    let mut dec = Decoder::new(4096, 1 << 20);
    let mut names = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::HEADERS {
                dec.decode(&payload, |n, _v| names.push(n.to_string()))
                    .unwrap();
                return;
            }
        }
    })
    .await
    .expect("server must respond");
    assert!(
        !names.iter().any(|n| n == "connection"),
        "Connection must be stripped on h2"
    );
    assert!(
        !names.iter().any(|n| n == "transfer-encoding"),
        "Transfer-Encoding must be stripped on h2"
    );
    assert!(
        names.iter().any(|n| n == "x-keep"),
        "end-to-end headers must survive"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn honors_peer_header_table_size_zero() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    // Advertise SETTINGS_HEADER_TABLE_SIZE = 0 (disable the encoder's dynamic table).
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[(frame::settings::HEADER_TABLE_SIZE, 0)]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let mut hframe = Vec::new();
    frame::write_frame(
        &mut hframe,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &encode_get(&mut enc, "/"),
    );
    client.write_all(&hframe).await.unwrap();
    client.flush().await.unwrap();

    // The first response header block must lead with a §6.3 size-update-to-0 instruction
    // (0b001 prefix, value 0 = 0x20), proving the encoder honored the peer's setting, and
    // it must decode under a table-size-0 decoder.
    let mut dec = Decoder::new(0, 1 << 20);
    let mut status = None;
    let first = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::HEADERS {
                let lead = payload[0];
                dec.decode(&payload, |n, v| {
                    if n == ":status" {
                        status = Some(v.to_string());
                    }
                })
                .unwrap();
                return lead;
            }
        }
    })
    .await
    .expect("server must respond");
    assert_eq!(
        first, 0x20,
        "response block must lead with a dynamic-table size update to 0"
    );
    assert_eq!(status.as_deref(), Some("200"));
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn stream_rst_replenishes_connection_window() {
    // FIX 3: a per-stream RST (flow-control overrun or body-cap) MUST still replenish the
    // CONNECTION-level receive window and emit WINDOW_UPDATE(stream 0). Otherwise every such
    // RST permanently shrinks the server's connection-window accounting, eventually driving
    // it negative on the next DATA frame and GOAWAY'ing every multiplexed stream.
    //
    // initial_window_size=4 gives each stream a 4-byte receive window while the connection
    // window stays at the §6.9.1 floor of 65535 (no opening WINDOW_UPDATE, since 4 < 65535).
    // Each stream sends 5 DATA bytes (1 past the 4-byte stream window) to force the stream RST.
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    let config = Config {
        initial_window_size: 4,
        ..Config::default()
    };
    let srv = tokio::spawn(async move { serve(server, noop_service, config, None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();

    let n_streams: u32 = 64;
    let mut enc = Encoder::new();
    let mut buf = Vec::new();
    for i in 0..n_streams {
        let sid = 1 + i * 2; // client streams are odd
        // HEADERS without END_STREAM (a body follows), then a 5-byte DATA (>4-byte window).
        frame::write_frame(
            &mut buf,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS,
            sid,
            &encode_get(&mut enc, "/u"),
        );
        frame::write_frame(&mut buf, frame::kind::DATA, 0, sid, b"12345");
    }
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();

    // Every over-window stream is RST'd. The connection window is replenished in batches
    // (one WINDOW_UPDATE(0) per half-window consumed — see
    // `conn_window_update_precedes_stream_rst` for the credit accounting); a leak would
    // surface as a GOAWAY FLOW_CONTROL_ERROR, which must NOT appear.
    let rsts = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut rsts = 0u32;
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::RST_STREAM => {
                    assert_eq!(
                        u32::from_be_bytes(payload[..4].try_into().unwrap()),
                        frame::error_code::FLOW_CONTROL_ERROR
                    );
                    rsts += 1;
                }
                frame::kind::GOAWAY => panic!(
                    "connection-window leak regressed: a stream RST drove the conn window to a GOAWAY"
                ),
                _ => {}
            }
            if rsts >= n_streams {
                break;
            }
        }
        rsts
    })
    .await
    .expect("server must reset each over-window stream");
    assert_eq!(rsts, n_streams, "every over-window stream must be RST'd");

    // A fresh stream with a within-window (4-byte) body must still be served normally — proof
    // the connection window survived the RST storm (no spurious FLOW_CONTROL_ERROR GOAWAY).
    let fresh = 1 + n_streams * 2;
    let mut ok = Vec::new();
    frame::write_frame(
        &mut ok,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        fresh,
        &encode_get(&mut enc, "/ok"),
    );
    frame::write_frame(
        &mut ok,
        frame::kind::DATA,
        frame::flags::END_STREAM,
        fresh,
        b"4444",
    );
    client.write_all(&ok).await.unwrap();
    client.flush().await.unwrap();

    let served = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut dec = Decoder::new(4096, 1 << 20);
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::HEADERS if hdr.stream_id == fresh => {
                    let mut status = None;
                    dec.decode(&payload, |n, v| {
                        if n == ":status" {
                            status = Some(v.to_string());
                        }
                    })
                    .unwrap();
                    if let Some(s) = status {
                        return s;
                    }
                }
                frame::kind::GOAWAY => {
                    panic!("a valid request after the RST storm must not GOAWAY")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("a valid within-window request on a fresh stream must be served after the RST storm");
    assert_eq!(
        served, "200",
        "fresh stream after RST storm must get a normal response"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn upload_window_updates_are_batched() {
    // A 1.6 MB upload in 100 DATA frames used to draw 100 connection + 100 stream
    // WINDOW_UPDATEs. Replenishment is now batched at half the advertised window (2 MiB by
    // default), so this upload crosses the threshold exactly once on each level.
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut buf = Vec::new();
    frame::write_settings(&mut buf, &[]);
    let mut enc = Encoder::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get(&mut enc, "/upload"),
    );
    let chunk = vec![b'x'; 16_000];
    for i in 0..100 {
        let flags = if i == 99 { frame::flags::END_STREAM } else { 0 };
        frame::write_frame(&mut buf, frame::kind::DATA, flags, 1, &chunk);
    }
    let writer = tokio::spawn(async move {
        client.write_all(&buf).await.unwrap();
        client.flush().await.unwrap();
        client
    });
    let mut client = writer.await.unwrap();

    let (conn_updates, stream_updates) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (mut conn_updates, mut stream_updates) = (0u32, 0u32);
            loop {
                let (hdr, _) = read_frame(&mut client).await;
                match hdr.kind {
                    frame::kind::WINDOW_UPDATE if hdr.stream_id == 0 => conn_updates += 1,
                    frame::kind::WINDOW_UPDATE if hdr.stream_id == 1 => stream_updates += 1,
                    frame::kind::HEADERS if hdr.stream_id == 1 => break,
                    frame::kind::GOAWAY => panic!("the upload must not GOAWAY"),
                    _ => {}
                }
            }
            (conn_updates, stream_updates)
        })
        .await
        .expect("the upload must be answered");
    // The opening connection WINDOW_UPDATE (65535 -> 2 MiB) plus one refill.
    assert_eq!(conn_updates, 2, "connection window updates must be batched");
    assert_eq!(stream_updates, 1, "stream window updates must be batched");
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn conn_window_update_precedes_stream_rst() {
    // FIX 3 (parallel-path guarantee): the connection-window accounting sits ABOVE both
    // stream-level early returns (the §6.9 FLOW_CONTROL_ERROR rst! AND the MAX_REQUEST_BODY
    // REFUSED_STREAM rst!) and the closed-stream drop, so NONE can skip it. Replenishment is
    // batched (once half the 65535 connection window is consumed), so the flood here is three
    // 16000-byte frames: the first overruns stream 1's 4-byte window (RST), the next two land
    // on the now-closed stream. The single WINDOW_UPDATE(0) must credit all 48000 bytes.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let config = Config {
        initial_window_size: 4,
        ..Config::default()
    };
    let srv = tokio::spawn(async move { serve(server, noop_service, config, None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let mut buf = Vec::new();
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &encode_get(&mut enc, "/u"),
    );
    let chunk = vec![b'x'; 16_000];
    for _ in 0..3 {
        frame::write_frame(&mut buf, frame::kind::DATA, 0, 1, &chunk); // first: > 4-byte window
    }
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();

    let (saw_conn_update, saw_rst) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut saw_conn_update = false;
            let mut saw_rst = false;
            loop {
                let (hdr, payload) = read_frame(&mut client).await;
                match hdr.kind {
                    frame::kind::WINDOW_UPDATE if hdr.stream_id == 0 => {
                        // The replenish must cover every flow-controlled byte, including the
                        // frames on the reset stream.
                        assert_eq!(u32::from_be_bytes(payload[..4].try_into().unwrap()), 48_000);
                        saw_conn_update = true;
                    }
                    frame::kind::RST_STREAM if hdr.stream_id == 1 => saw_rst = true,
                    frame::kind::GOAWAY => panic!("must not GOAWAY"),
                    _ => {}
                }
                if saw_conn_update && saw_rst {
                    break;
                }
            }
            (saw_conn_update, saw_rst)
        })
        .await
        .expect("server must replenish the conn window and RST the stream");
    assert!(
        saw_conn_update,
        "connection WINDOW_UPDATE(0) must precede/accompany the stream RST"
    );
    assert!(saw_rst, "the over-window stream must be reset");
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn pending_window_overflow_suppresses_inflight_response() {
    // FIX 12: when accumulated WINDOW_UPDATE credit for a stream whose handler is still
    // running overflows i32::MAX, the server RST_STREAMs it AND must mark it cancelled, so
    // the slow handler's late HEADERS/DATA are dropped (RFC 7540 §5.1: the peer considers the
    // stream closed). Without the cancelled-insert the response races onto a reset stream.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    // A deliberately slow handler so its future is still in `inflight` when the overflow
    // WINDOW_UPDATE arrives, and a marker body so a leaked response would be detectable.
    let service = |_req: Request| async move {
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        hj_core::text_response(http::StatusCode::OK, "LEAKED-AFTER-RST")
    };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/slow"),
    );
    // Two near-max WINDOW_UPDATEs so peer.initial_window + accumulated credit exceeds
    // i32::MAX while the handler is still sleeping in `inflight` (the overflow RST path).
    frame::write_window_update(&mut req, 1, 0x7fff_ffff);
    frame::write_window_update(&mut req, 1, 0x7fff_ffff);
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    // Expect the FLOW_CONTROL_ERROR RST for stream 1, then — even after the handler resolves
    // — NO HEADERS/DATA for stream 1. Read until a quiet window passes after the RST.
    let mut saw_rst = false;
    let mut leaked = false;
    let _ = tokio::time::timeout(std::time::Duration::from_millis(400), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::RST_STREAM if hdr.stream_id == 1 => {
                    assert_eq!(
                        u32::from_be_bytes(payload[..4].try_into().unwrap()),
                        frame::error_code::FLOW_CONTROL_ERROR
                    );
                    saw_rst = true;
                }
                frame::kind::HEADERS | frame::kind::DATA if hdr.stream_id == 1 => {
                    leaked = true; // a response frame for the reset stream — the bug
                }
                _ => {}
            }
        }
    })
    .await; // times out (no clean close) — we only care WHAT arrived before then
    assert!(
        saw_rst,
        "the pending-window overflow must RST_STREAM the stream"
    );
    assert!(
        !leaked,
        "no HEADERS/DATA may be emitted for a stream RST by the overflow path"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn error_goaway_carries_last_client_stream() {
    // FIX 32: an error-path GOAWAY must carry the highest client stream the server processed
    // (recv.last_client_stream), not a hardcoded 0 — so the peer knows which streams may be
    // safely retried (§6.8). Open stream 1 (valid), then send DATA on stream 0 to trigger a
    // connection-error GOAWAY; its last-stream-id field must be 1, not 0.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    let mut req = Vec::new();
    frame::write_frame(
        &mut req,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/"),
    );
    // DATA on stream 0 is a connection error (§6.1) -> error-path GOAWAY.
    frame::write_frame(&mut req, frame::kind::DATA, 0, 0, b"x");
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let last_stream = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::GOAWAY {
                return u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff;
            }
        }
    })
    .await
    .expect("server must GOAWAY on DATA-on-stream-0");
    assert_eq!(
        last_stream, 1,
        "error-path GOAWAY must carry last_client_stream (1), not 0"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn data_on_closed_stream_rsts_that_stream_not_the_connection() {
    // A DATA frame racing the completion of its OWN stream (the handler responded END_STREAM
    // before the client's trailing DATA arrives) is a STREAM error (STREAM_CLOSED), not a
    // connection error — it must RST just that stream, never GOAWAY every multiplexed stream.
    // (An idle stream `sid > last_client_stream` still GOAWAYs, per §5.1 — covered elsewhere.)
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();

    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;

    // Stream 1: a complete GET (END_STREAM) — the server completes + removes it.
    let mut h1 = Vec::new();
    frame::write_frame(
        &mut h1,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/done"),
    );
    client.write_all(&h1).await.unwrap();
    client.flush().await.unwrap();
    let (status, _) = read_response(&mut client, &mut dec, 1).await;
    assert_eq!(
        status.as_deref(),
        Some("200"),
        "stream 1 must serve before we close it"
    );

    // Now send DATA on the now-closed stream 1.
    let mut d = Vec::new();
    frame::write_frame(&mut d, frame::kind::DATA, 0, 1, b"late-body");
    client.write_all(&d).await.unwrap();
    client.flush().await.unwrap();

    // Expect RST_STREAM(STREAM_CLOSED) on stream 1, NOT a connection GOAWAY.
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::GOAWAY => panic!("DATA on a closed stream GOAWAYed the connection"),
                frame::kind::HEADERS => {
                    dec.decode(&payload, |_, _| {}).unwrap();
                }
                frame::kind::RST_STREAM if hdr.stream_id == 1 => {
                    let code = u32::from_be_bytes(payload[..4].try_into().unwrap());
                    assert_eq!(
                        code,
                        frame::error_code::STREAM_CLOSED,
                        "DATA on a closed stream → RST_STREAM(STREAM_CLOSED)"
                    );
                    return;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("timed out: server GOAWAYed or hung instead of RST-ing the closed stream");

    // The connection must still be usable: stream 3 serves normally.
    let mut h3 = Vec::new();
    frame::write_frame(
        &mut h3,
        frame::kind::HEADERS,
        end,
        3,
        &encode_get(&mut enc, "/again"),
    );
    client.write_all(&h3).await.unwrap();
    client.flush().await.unwrap();
    let (status3, _) = read_response(&mut client, &mut dec, 3).await;
    assert_eq!(
        status3.as_deref(),
        Some("200"),
        "connection must survive the closed-stream DATA"
    );

    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn headers_reusing_a_cleanly_closed_stream_id_is_a_connection_error() {
    // RFC 9113 §5.1.1: client stream ids are never reused. Reopening an id that closed
    // cleanly (END_STREAM, no RST_STREAM in either direction) is a connection error —
    // GOAWAY(PROTOCOL_ERROR) carrying last_client_stream — NOT the per-stream
    // STREAM_CLOSED reserved for ids racing a RST_STREAM (#357; h2spec 5.1.1).
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();

    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;

    let mut h1 = Vec::new();
    frame::write_frame(
        &mut h1,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/done"),
    );
    client.write_all(&h1).await.unwrap();
    client.flush().await.unwrap();
    let (status, _) = read_response(&mut client, &mut dec, 1).await;
    assert_eq!(status.as_deref(), Some("200"));

    let mut late = Vec::new();
    frame::write_frame(
        &mut late,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/late"),
    );
    client.write_all(&late).await.unwrap();
    client.flush().await.unwrap();

    let (last_stream, code) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::GOAWAY {
                return (
                    u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff,
                    u32::from_be_bytes(payload[4..8].try_into().unwrap()),
                );
            }
        }
    })
    .await
    .expect("reusing a cleanly closed stream id must GOAWAY");
    assert_eq!(
        code,
        frame::error_code::PROTOCOL_ERROR,
        "clean-close reuse -> connection PROTOCOL_ERROR (§5.1.1)"
    );
    assert_eq!(
        last_stream, 1,
        "error-path GOAWAY must carry last_client_stream (§6.8)"
    );
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn headers_reusing_a_reset_stream_id_rsts_that_stream_not_the_connection() {
    // RFC 9113 §5.1: any frame on a stream that saw a RST_STREAM (either direction) is a
    // STREAM error (STREAM_CLOSED), never a connection error — a GOAWAY here would tear
    // down every multiplexed stream over one raced late frame (#357).
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    client.write_all(&f).await.unwrap();
    client.flush().await.unwrap();

    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;

    let mut h1 = Vec::new();
    frame::write_frame(
        &mut h1,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/done"),
    );
    client.write_all(&h1).await.unwrap();
    client.flush().await.unwrap();
    let (status, _) = read_response(&mut client, &mut dec, 1).await;
    assert_eq!(status.as_deref(), Some("200"));

    // The client resets the stream, then reuses its id — tolerated per-stream.
    let mut buf = Vec::new();
    frame::write_rst_stream(&mut buf, 1, frame::error_code::CANCEL);
    frame::write_frame(
        &mut buf,
        frame::kind::HEADERS,
        end,
        1,
        &encode_get(&mut enc, "/late"),
    );
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::GOAWAY => {
                    panic!("HEADERS on a reset stream GOAWAYed the connection")
                }
                frame::kind::HEADERS => {
                    dec.decode(&payload, |_, _| {}).unwrap();
                }
                frame::kind::RST_STREAM if hdr.stream_id == 1 => {
                    let code = u32::from_be_bytes(payload[..4].try_into().unwrap());
                    assert_eq!(code, frame::error_code::STREAM_CLOSED);
                    return;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for the reset-stream HEADERS reset");

    // The connection must still be usable: stream 3 serves normally.
    let mut h3 = Vec::new();
    frame::write_frame(
        &mut h3,
        frame::kind::HEADERS,
        end,
        3,
        &encode_get(&mut enc, "/again"),
    );
    client.write_all(&h3).await.unwrap();
    client.flush().await.unwrap();
    let (status3, _) = read_response(&mut client, &mut dec, 3).await;
    assert_eq!(
        status3.as_deref(),
        Some("200"),
        "connection must survive the reset-stream reuse"
    );

    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn headers_on_a_never_opened_lower_stream_id_is_a_connection_error() {
    // RFC 9113 §5.1.1: a new client stream id must be numerically greater than every id
    // the client has opened. HEADERS on never-opened 3 after opening 5 is a connection
    // error (h2spec 5.1.1/2) — no RST_STREAM was ever exchanged on 3, so the §5.1
    // closed-stream tolerance does not apply (#357).
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut frames = Vec::new();
    frame::write_settings(&mut frames, &[]);
    let mut enc = Encoder::new();
    let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
    frame::write_frame(
        &mut frames,
        frame::kind::HEADERS,
        end,
        5,
        &encode_get(&mut enc, "/first"),
    );
    frame::write_frame(
        &mut frames,
        frame::kind::HEADERS,
        end,
        3,
        &encode_get(&mut enc, "/lower"),
    );
    client.write_all(&frames).await.unwrap();
    client.flush().await.unwrap();

    let (last_stream, code) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            if hdr.kind == frame::kind::GOAWAY {
                return (
                    u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff,
                    u32::from_be_bytes(payload[4..8].try_into().unwrap()),
                );
            }
        }
    })
    .await
    .expect("HEADERS on a never-opened lower stream id must GOAWAY");
    assert_eq!(code, frame::error_code::PROTOCOL_ERROR);
    assert_eq!(
        last_stream, 5,
        "error-path GOAWAY must carry last_client_stream (§6.8)"
    );
    drop(client);
    let _ = srv.await;
}

/// Read frames until a GOAWAY and return its error code (`payload[4..8]`).
async fn read_until_goaway<R: AsyncReadExt + Unpin>(r: &mut R) -> u32 {
    loop {
        let (hdr, payload) = read_frame(r).await;
        if hdr.kind == frame::kind::GOAWAY {
            return u32::from_be_bytes(payload[4..8].try_into().unwrap());
        }
    }
}

#[tokio::test]
async fn zero_window_update_increment_uses_the_rfc_error_scope() {
    // RFC 9113 §6.9: zero connection credit is a connection PROTOCOL_ERROR.
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut frames = Vec::new();
    frame::write_settings(&mut frames, &[]);
    frame::write_frame(
        &mut frames,
        frame::kind::WINDOW_UPDATE,
        0,
        0,
        &0u32.to_be_bytes(),
    );
    client.write_all(&frames).await.unwrap();
    client.flush().await.unwrap();
    let code = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_until_goaway(&mut client),
    )
    .await
    .expect("zero connection WINDOW_UPDATE must GOAWAY");
    assert_eq!(code, frame::error_code::PROTOCOL_ERROR);
    drop(client);
    let _ = srv.await;

    // The same invalid increment on a stream is a stream PROTOCOL_ERROR.
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut frames = Vec::new();
    frame::write_settings(&mut frames, &[]);
    let mut enc = Encoder::new();
    frame::write_frame(
        &mut frames,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &encode_get(&mut enc, "/"),
    );
    frame::write_frame(
        &mut frames,
        frame::kind::WINDOW_UPDATE,
        0,
        1,
        &0u32.to_be_bytes(),
    );
    client.write_all(&frames).await.unwrap();
    client.flush().await.unwrap();
    let reset_code = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (header, payload) = read_frame(&mut client).await;
            if header.kind == frame::kind::GOAWAY {
                panic!("stream-scoped zero WINDOW_UPDATE must not close the connection");
            }
            if header.kind == frame::kind::RST_STREAM && header.stream_id == 1 {
                return u32::from_be_bytes(payload[..4].try_into().unwrap());
            }
        }
    })
    .await
    .expect("zero stream WINDOW_UPDATE must reset its stream");
    assert_eq!(reset_code, frame::error_code::PROTOCOL_ERROR);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn control_frame_on_even_stream_id_is_a_connection_error() {
    // §5.1.1: even stream ids are reserved for server-initiated streams, of which this
    // server has none. A client WINDOW_UPDATE on a low even id (<= last_client_stream)
    // must be a connection error (PROTOCOL_ERROR GOAWAY), not the tolerant
    // closed-stream no-op the same code applies to a low ODD id.
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut s = Vec::new();
    frame::write_settings(&mut s, &[]);
    client.write_all(&s).await.unwrap();
    // Open odd stream 1 so last_client_stream = 1 (the even id 2 is then NOT "idle"
    // via `> last_client_stream` — only the even-parity guard can reject it).
    let mut enc = Encoder::new();
    let mut h1 = Vec::new();
    frame::write_frame(
        &mut h1,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &encode_get(&mut enc, "/"),
    );
    client.write_all(&h1).await.unwrap();
    // WINDOW_UPDATE on even stream id 2.
    let mut wu = Vec::new();
    frame::write_frame(
        &mut wu,
        frame::kind::WINDOW_UPDATE,
        0,
        2,
        &100u32.to_be_bytes(),
    );
    client.write_all(&wu).await.unwrap();
    client.flush().await.unwrap();

    let code = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_until_goaway(&mut client),
    )
    .await
    .expect("a WINDOW_UPDATE on an even stream id must GOAWAY");
    assert_eq!(
        code,
        frame::error_code::PROTOCOL_ERROR,
        "even-id control frame → PROTOCOL_ERROR"
    );
    drop(client);
    let _ = srv.await;
}

/// A handler that never completes, so a reset stream stays in-flight (the rapid-reset shape).
async fn never_service(_req: Request) -> Response {
    std::future::pending::<()>().await;
    unreachable!()
}

#[tokio::test]
async fn rapid_reset_flood_is_rejected_with_enhance_your_calm() {
    // (CVE-2023-44487) Open a stream then immediately RST it, repeatedly. The handler stays
    // in-flight (never_service), so each reset is a rapid-reset; past the budget the server
    // must stop the flood with GOAWAY(ENHANCE_YOUR_CALM) instead of churning backend work.
    let (mut client, server) = tokio::io::duplex(512 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, never_service, Config::default(), None).await });

    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut s = Vec::new();
    frame::write_settings(&mut s, &[]);
    client.write_all(&s).await.unwrap();

    let mut enc = Encoder::new();
    let mut buf = Vec::new();
    let mut sid = 1u32;
    for _ in 0..230 {
        frame::write_frame(
            &mut buf,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS | frame::flags::END_STREAM,
            sid,
            &encode_get(&mut enc, "/"),
        );
        frame::write_rst_stream(&mut buf, sid, frame::error_code::CANCEL);
        sid += 2;
    }
    client.write_all(&buf).await.unwrap();
    client.flush().await.unwrap();

    let code = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_until_goaway(&mut client),
    )
    .await
    .expect("a rapid-reset flood must trigger a GOAWAY");
    assert_eq!(
        code,
        frame::error_code::ENHANCE_YOUR_CALM,
        "rapid-reset flood → ENHANCE_YOUR_CALM"
    );
    drop(client);
    // After the flood GOAWAY the server STOPS READING but keeps the reset-but-in-flight
    // handlers in `inflight` until they resolve (real lsphp/proxy handlers DO complete and
    // their responses are dropped via `cancelled`; aborting them is the deferred
    // nice-to-have). `never_service` is pending forever, so the connection task never
    // returns here — abort it rather than awaiting (this is a test-only shape).
    srv.abort();
}

#[tokio::test]
async fn bare_continuation_without_open_header_block_is_a_connection_error() {
    // RFC 9113 §6.10: a CONTINUATION MUST follow a HEADERS/CONTINUATION that did not set
    // END_HEADERS. A GET without END_STREAM leaves the stream open with its header block
    // already closed, so a following CONTINUATION has no block to continue. Absorbing it as a
    // phantom trailer section lets every stream pin a 64 KiB block at once.
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut frames = Vec::new();
    frame::write_settings(&mut frames, &[]);
    let mut enc = Encoder::new();
    let block = encode_get(&mut enc, "/");
    // END_HEADERS but NOT END_STREAM: the stream stays open awaiting a body.
    frame::write_frame(
        &mut frames,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &block,
    );
    // A regular field, deliberately not a pseudo-header: a pseudo-header decodes as malformed
    // and already yields a stream RST today, which would make this pass for the wrong reason.
    let mut orphan = Vec::new();
    enc.encode_header(&mut orphan, "x-bare", "continuation");
    frame::write_frame(
        &mut frames,
        frame::kind::CONTINUATION,
        frame::flags::END_HEADERS,
        1,
        &orphan,
    );
    client.write_all(&frames).await.unwrap();

    let code = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_until_goaway(&mut client),
    )
    .await
    .expect("server accepted a bare CONTINUATION instead of failing the connection");
    assert_eq!(code, frame::error_code::PROTOCOL_ERROR);

    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn header_table_size_lowered_then_restored_signals_min_size_update() {
    // RFC 7541 §4.2: SETTINGS_HEADER_TABLE_SIZE 0 then 4096 in one interval — our decoder
    // flushed its table at 0, so the next response block must lead with update(0).
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    let mut enc = Encoder::new();
    let b = encode_get(&mut enc, "/");
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &b,
    );
    client.write_all(&f).await.unwrap();
    loop {
        let (hdr, _) = read_frame(&mut client).await;
        if hdr.stream_id == 1 && hdr.flags & frame::flags::END_STREAM != 0 {
            break;
        }
    }
    let mut f = Vec::new();
    frame::write_settings(
        &mut f,
        &[
            (frame::settings::HEADER_TABLE_SIZE, 0),
            (frame::settings::HEADER_TABLE_SIZE, 4096),
        ],
    );
    let b = encode_get(&mut enc, "/");
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        3,
        &b,
    );
    client.write_all(&f).await.unwrap();
    let block = loop {
        let (hdr, p) = read_frame(&mut client).await;
        if hdr.kind == frame::kind::HEADERS && hdr.stream_id == 3 {
            break p;
        }
    };
    drop(client);
    let _ = srv.await;
    assert_eq!(block[0], 0x20, "update(0) must lead the block");
    assert_eq!(block[1] & 0xe0, 0x20, "then the final size update");
}

#[tokio::test]
async fn continue_interim_leads_with_pending_table_size_update() {
    // #681: the 100-continue block may be the first block after a peer lowered
    // SETTINGS_HEADER_TABLE_SIZE, so it must carry the required size update.
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let srv =
        tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[(frame::settings::HEADER_TABLE_SIZE, 0)]);
    let mut enc = Encoder::new();
    let mut b = Vec::new();
    for (n, v) in [
        (":method", "POST"),
        (":scheme", "https"),
        (":path", "/upload"),
        (":authority", "example.test"),
        ("expect", "100-continue"),
    ] {
        enc.encode_header(&mut b, n, v);
    }
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &b,
    );
    client.write_all(&f).await.unwrap();
    let block = loop {
        let (hdr, p) = read_frame(&mut client).await;
        if hdr.kind == frame::kind::HEADERS && hdr.stream_id == 1 {
            break p;
        }
    };
    drop(client);
    let _ = srv.await;
    assert_eq!(block[0], 0x20, "update(0) must lead the 100-continue block");
}

/// A streamed body whose exact size hint confirms its Content-Length (a bridged
/// file) keeps the header; a stream of unknown length loses a declared one.
#[tokio::test]
async fn known_length_stream_keeps_content_length() {
    for (exact, want) in [(true, Some("16")), (false, None)] {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let service = move |_req: Request| async move {
            use http_body_util::{BodyExt, Full, StreamBody};
            let body = if exact {
                Full::new(Bytes::from_static(b"alpha-beta-gamma"))
                    .map_err(|n| match n {})
                    .boxed()
            } else {
                let chunks: Vec<Result<http_body::Frame<Bytes>, hj_core::BoxError>> = vec![Ok(
                    http_body::Frame::data(Bytes::from_static(b"alpha-beta-gamma")),
                )];
                StreamBody::new(futures_util::stream::iter(chunks)).boxed()
            };
            http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_LENGTH, "16")
                .body(Body::Stream(body))
                .unwrap()
        };
        let srv =
            tokio::spawn(async move { serve(server, service, Config::default(), None).await });
        client.write_all(hj_h2::conn::PREFACE).await.unwrap();
        let mut f = Vec::new();
        frame::write_settings(&mut f, &[]);
        client.write_all(&f).await.unwrap();
        let mut enc = Encoder::new();
        let mut req = Vec::new();
        frame::write_frame(
            &mut req,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS | frame::flags::END_STREAM,
            1,
            &encode_get(&mut enc, "/file"),
        );
        client.write_all(&req).await.unwrap();
        client.flush().await.unwrap();

        let mut dec = Decoder::new(4096, 1 << 20);
        let mut content_length = None;
        let mut body = Vec::new();
        loop {
            let (hdr, payload) = read_frame(&mut client).await;
            match hdr.kind {
                frame::kind::HEADERS => dec
                    .decode(&payload, |n, v| {
                        if n == "content-length" {
                            content_length = Some(v.to_string());
                        }
                    })
                    .unwrap(),
                frame::kind::DATA => {
                    body.extend_from_slice(&payload);
                    if hdr.flags & frame::flags::END_STREAM != 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        assert_eq!(content_length.as_deref(), want, "exact={exact}");
        assert_eq!(body, b"alpha-beta-gamma");
        drop(client);
        let _ = srv.await;
    }
}

#[tokio::test]
async fn frame_size_and_window_overflow_goaways_carry_last_client_stream() {
    // #876: the loop-level connection errors (oversized frame, connection
    // WINDOW_UPDATE overflow) must report stream 1 as processed, not last=0.
    for trigger in ["oversized", "window"] {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let srv =
            tokio::spawn(async move { serve(server, noop_service, Config::default(), None).await });
        client.write_all(hj_h2::conn::PREFACE).await.unwrap();
        let mut f = Vec::new();
        frame::write_settings(&mut f, &[]);
        client.write_all(&f).await.unwrap();
        let mut enc = Encoder::new();
        let end = frame::flags::END_HEADERS | frame::flags::END_STREAM;
        let mut req = Vec::new();
        frame::write_frame(
            &mut req,
            frame::kind::HEADERS,
            end,
            1,
            &encode_get(&mut enc, "/"),
        );
        match trigger {
            "oversized" => frame::write_frame(&mut req, frame::kind::PING, 0, 0, &[0u8; 20000]),
            _ => frame::write_frame(
                &mut req,
                frame::kind::WINDOW_UPDATE,
                0,
                0,
                &0x7fff_ffffu32.to_be_bytes(),
            ),
        }
        client.write_all(&req).await.unwrap();
        client.flush().await.unwrap();
        let last_stream = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let (hdr, payload) = read_frame(&mut client).await;
                if hdr.kind == frame::kind::GOAWAY {
                    return u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff;
                }
            }
        })
        .await
        .expect("connection error must GOAWAY");
        assert_eq!(
            last_stream, 1,
            "{trigger}: GOAWAY must report stream 1 as processed"
        );
        drop(client);
        let _ = srv.await;
    }
}
