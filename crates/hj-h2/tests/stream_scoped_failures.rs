//! Failures that must stay scoped to one stream (or never regress connection-level
//! signalling): obs-text request headers, GOAWAY last-stream-id monotonicity, and the
//! early-WINDOW_UPDATE bookkeeping of streams reset for a Content-Length mismatch.

use hj_core::Request;
use hj_h2::frame::{self, FrameHeader};
use hj_h2::hpack::Encoder;
use hj_h2::server::{Config, serve};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Option<(FrameHeader, Vec<u8>)> {
    let mut h = [0u8; FrameHeader::LEN];
    r.read_exact(&mut h).await.ok()?;
    let hdr = FrameHeader::parse(&h).unwrap();
    let mut p = vec![0u8; hdr.length as usize];
    r.read_exact(&mut p).await.ok()?;
    Some((hdr, p))
}

async fn collect_frames<R: AsyncReadExt + Unpin>(r: &mut R) -> Vec<(FrameHeader, Vec<u8>)> {
    let mut seen = Vec::new();
    while let Ok(Some(f)) = tokio::time::timeout(Duration::from_secs(2), read_frame(r)).await {
        seen.push(f);
    }
    seen
}

fn req_block(enc: &mut Encoder, method: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    enc.encode_header(&mut b, ":method", method.as_bytes());
    enc.encode_header(&mut b, ":scheme", b"https");
    enc.encode_header(&mut b, ":path", b"/");
    enc.encode_header(&mut b, ":authority", b"example.com");
    for (n, v) in extra {
        enc.encode_header(&mut b, n, v);
    }
    b
}

fn goaway_ids(frames: &[(FrameHeader, Vec<u8>)]) -> Vec<u32> {
    frames
        .iter()
        .filter(|(h, _)| h.kind == frame::kind::GOAWAY)
        .map(|(_, p)| u32::from_be_bytes(p[..4].try_into().unwrap()))
        .collect()
}

#[tokio::test]
async fn obs_text_header_value_is_served_and_keeps_other_streams() {
    let service = |req: Request| async move {
        let ua = req.headers().get(http::header::USER_AGENT).cloned();
        let mut resp = hj_core::text_response(http::StatusCode::OK, "ok");
        if let Some(ua) = ua {
            resp.headers_mut().insert("x-echo-ua", ua);
        }
        resp
    };
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    let mut enc = Encoder::new();
    // Stream 1 is still uploading its body when stream 3 arrives.
    let b1 = req_block(&mut enc, "POST", &[]);
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &b1,
    );
    frame::write_frame(&mut f, frame::kind::DATA, 0, 1, b"partial");
    // RFC 9113 §8.2.1 permits field-value octets 0x80-0xFF (Latin-1 here, not UTF-8).
    // The default encoder indexes user-agent, so stream 5 references it from the table.
    let b3 = req_block(&mut enc, "GET", &[("user-agent", b"Mozilla caf\xe9")]);
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        3,
        &b3,
    );
    let b5 = req_block(&mut enc, "GET", &[("user-agent", b"Mozilla caf\xe9")]);
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        5,
        &b5,
    );
    frame::write_frame(&mut f, frame::kind::DATA, frame::flags::END_STREAM, 1, b"!");
    client.write_all(&f).await.unwrap();

    let frames = collect_frames(&mut client).await;
    drop(client);
    let _ = srv.await;
    assert!(
        goaway_ids(&frames).is_empty(),
        "connection torn down: {frames:?}"
    );
    let mut dec = hj_h2::hpack::Decoder::new(4096, 1 << 20);
    let mut statuses = Vec::new();
    for (h, p) in &frames {
        if h.kind != frame::kind::HEADERS {
            continue;
        }
        let mut status = None;
        let mut echo = None;
        dec.decode_octets(p, |n, v| match n {
            b":status" => status = Some(v.to_vec()),
            b"x-echo-ua" => echo = Some(v.to_vec()),
            _ => {}
        })
        .unwrap();
        statuses.push((h.stream_id, status.unwrap(), echo));
    }
    statuses.sort();
    assert_eq!(
        statuses,
        vec![
            (1, b"200".to_vec(), None),
            (3, b"200".to_vec(), Some(b"Mozilla caf\xe9".to_vec())),
            (5, b"200".to_vec(), Some(b"Mozilla caf\xe9".to_vec())),
        ]
    );
}

#[tokio::test]
async fn non_token_header_name_is_a_stream_error() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let service = |_req: Request| async move { hj_core::text_response(http::StatusCode::OK, "ok") };
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    let mut enc = Encoder::new();
    // Literal without indexing, raw (non-Huffman) name `x-caf\xe9` (Latin-1), value `v`.
    let mut b1 = req_block(&mut enc, "GET", &[]);
    b1.extend_from_slice(&[0x00, 6, b'x', b'-', b'c', b'a', b'f', 0xe9, 1, b'v']);
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &b1,
    );
    let b3 = req_block(&mut enc, "GET", &[]);
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        3,
        &b3,
    );
    client.write_all(&f).await.unwrap();
    let frames = collect_frames(&mut client).await;
    drop(client);
    let _ = srv.await;
    assert!(
        goaway_ids(&frames).is_empty(),
        "connection torn down: {frames:?}"
    );
    assert!(frames.iter().any(|(h, p)| h.kind == frame::kind::RST_STREAM
        && h.stream_id == 1
        && u32::from_be_bytes(p[..4].try_into().unwrap()) == frame::error_code::PROTOCOL_ERROR));
    assert!(
        frames
            .iter()
            .any(|(h, _)| h.kind == frame::kind::HEADERS && h.stream_id == 3)
    );
}

#[tokio::test]
async fn goaway_last_stream_id_never_increases_after_graceful_goaway() {
    let service = |_req: Request| async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        hj_core::text_response(http::StatusCode::OK, "ok")
    };
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let tok = tokio_util::sync::CancellationToken::new();
    let t2 = tok.clone();
    let srv =
        tokio::spawn(async move { serve(server, service, Config::default(), Some(t2)).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut f = Vec::new();
    frame::write_settings(&mut f, &[]);
    let mut enc = Encoder::new();
    let b = req_block(&mut enc, "GET", &[]);
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        1,
        &b,
    );
    client.write_all(&f).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    tok.cancel();
    tokio::time::sleep(Duration::from_millis(10)).await;
    // Stream 3 races the graceful GOAWAY(1); then a connection error (bad PING length).
    let mut f = Vec::new();
    let b = req_block(&mut enc, "GET", &[]);
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        3,
        &b,
    );
    frame::write_frame(&mut f, frame::kind::PING, 0, 0, &[0; 7]);
    client.write_all(&f).await.unwrap();
    let frames = collect_frames(&mut client).await;
    drop(client);
    let _ = srv.await;
    let ids = goaway_ids(&frames);
    assert!(ids.len() >= 2, "expected graceful + error GOAWAY: {ids:?}");
    assert!(
        ids.windows(2).all(|w| w[1] <= w[0]),
        "last-stream-id increased: {ids:?}"
    );
}

#[tokio::test]
async fn content_length_mismatch_reset_does_not_leak_early_window_credit() {
    let service = |_req: Request| async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        hj_core::text_response(http::StatusCode::OK, "hello world body")
    };
    let (client, server) = tokio::io::duplex(1 << 20);
    let srv = tokio::spawn(async move { serve(server, service, Config::default(), None).await });
    let mut f = Vec::new();
    f.extend_from_slice(hj_h2::conn::PREFACE);
    frame::write_settings(&mut f, &[(frame::settings::INITIAL_WINDOW_SIZE, 0)]);
    let mut enc = Encoder::new();
    let mut sid = 1u32;
    // More than the server's 4096-entry cap of streams holding pre-response credit.
    for _ in 0..4200 {
        let b = req_block(&mut enc, "POST", &[("content-length", b"5")]);
        frame::write_frame(
            &mut f,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS,
            sid,
            &b,
        );
        frame::write_window_update(&mut f, sid, 1000);
        frame::write_frame(
            &mut f,
            frame::kind::DATA,
            frame::flags::END_STREAM,
            sid,
            b"x",
        );
        sid += 2;
    }
    let b = req_block(&mut enc, "POST", &[]);
    frame::write_frame(
        &mut f,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        sid,
        &b,
    );
    frame::write_window_update(&mut f, sid, 100_000);
    let target = sid;
    let (mut rd, mut wr) = tokio::io::split(client);
    let w = tokio::spawn(async move {
        wr.write_all(&f).await.unwrap();
        wr
    });
    let frames = collect_frames(&mut rd).await;
    let _wr = w.await.unwrap();
    drop(srv);
    assert!(goaway_ids(&frames).is_empty());
    assert!(
        frames
            .iter()
            .any(|(h, _)| h.kind == frame::kind::DATA && h.stream_id == target),
        "pre-response WINDOW_UPDATE credit was dropped"
    );
}
