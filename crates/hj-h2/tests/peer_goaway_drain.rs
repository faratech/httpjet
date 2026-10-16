//! A peer's graceful GOAWAY (RFC 9113 §6.8) must not truncate responses already in
//! flight: the server keeps reading WINDOW_UPDATE / RST_STREAM so window-blocked bodies
//! finish, refuses streams opened after the GOAWAY, and closes once the work drains.

use std::time::Duration;

use bytes::Bytes;
use hj_core::{Body, Request, Response};
use hj_h2::frame::{self, FrameHeader};
use hj_h2::hpack::Encoder;
use hj_h2::server::{Config, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const BODY_LEN: usize = 100_000;

async fn read_frame(r: &mut DuplexStream) -> Option<(FrameHeader, Vec<u8>)> {
    let mut h = [0u8; FrameHeader::LEN];
    r.read_exact(&mut h).await.ok()?;
    let hdr = FrameHeader::parse(&h).unwrap();
    let mut p = vec![0u8; hdr.length as usize];
    r.read_exact(&mut p).await.ok()?;
    Some((hdr, p))
}

fn get(enc: &mut Encoder, wire: &mut Vec<u8>, sid: u32) {
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "GET");
    enc.encode_header(&mut block, ":path", "/");
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    frame::write_frame(
        wire,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS | frame::flags::END_STREAM,
        sid,
        &block,
    );
}

async fn slow_big(_req: Request) -> Response {
    tokio::time::sleep(Duration::from_millis(50)).await;
    http::Response::new(Body::Full(Bytes::from(vec![b'x'; BODY_LEN])))
}

#[derive(Default)]
struct Outcome {
    body: usize,
    ended: bool,
    refused: Vec<u32>,
    server_goaway: bool,
}

/// Opens stream 1 with a 16 KiB stream window, sends GOAWAY(NO_ERROR) right behind it
/// (plus `trailer` in the same write), then grants credit once the window is exhausted
/// when `grant_late`. Returns what the client observed and asserts the server returns.
async fn run(trailer: impl FnOnce(&mut Encoder, &mut Vec<u8>), grant_late: bool) -> Outcome {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let srv = tokio::spawn(async move { serve(server, slow_big, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut wire = Vec::new();
    frame::write_settings(&mut wire, &[(frame::settings::INITIAL_WINDOW_SIZE, 16384)]);
    let mut enc = Encoder::new();
    get(&mut enc, &mut wire, 1);
    frame::write_goaway(&mut wire, 0, frame::error_code::NO_ERROR);
    trailer(&mut enc, &mut wire);
    client.write_all(&wire).await.unwrap();

    let mut out = Outcome::default();
    let mut granted = false;
    while let Ok(Some((hdr, p))) =
        tokio::time::timeout(Duration::from_secs(3), read_frame(&mut client)).await
    {
        match hdr.kind {
            frame::kind::DATA if hdr.stream_id == 1 => {
                out.body += p.len();
                if hdr.flags & frame::flags::END_STREAM != 0 {
                    out.ended = true;
                    break;
                }
                if grant_late && !granted && out.body >= 16384 {
                    granted = true;
                    let mut w = Vec::new();
                    frame::write_window_update(&mut w, 1, 1_000_000);
                    frame::write_window_update(&mut w, 0, 1_000_000);
                    client.write_all(&w).await.unwrap();
                }
            }
            frame::kind::RST_STREAM => {
                assert_eq!(
                    u32::from_be_bytes(p[..4].try_into().unwrap()),
                    frame::error_code::REFUSED_STREAM
                );
                out.refused.push(hdr.stream_id);
            }
            frame::kind::GOAWAY => out.server_goaway = true,
            _ => {}
        }
    }
    // Once the drained response completes the server closes on its own (no EOF needed).
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut rest))
        .await
        .expect("server must close once the post-GOAWAY drain completes")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), srv)
        .await
        .expect("serve() must return after the drain")
        .unwrap()
        .unwrap();
    out
}

#[tokio::test]
async fn peer_goaway_keeps_reading_window_updates_for_blocked_response() {
    let out = run(|_, _| {}, true).await;
    assert!(
        out.ended && out.body == BODY_LEN,
        "response truncated after client GOAWAY: {}/{BODY_LEN}",
        out.body
    );
    assert!(!out.server_goaway, "a graceful peer GOAWAY is not an error");
}

#[tokio::test]
async fn peer_goaway_with_window_update_in_same_write_completes_response() {
    let out = run(
        |_, w| {
            frame::write_window_update(w, 1, 1_000_000);
            frame::write_window_update(w, 0, 1_000_000);
        },
        false,
    )
    .await;
    assert!(
        out.ended && out.body == BODY_LEN,
        "credit sent with the GOAWAY was dropped: {}/{BODY_LEN}",
        out.body
    );
}

#[tokio::test]
async fn peer_goaway_refuses_streams_opened_after_it() {
    let out = run(|enc, w| get(enc, w, 3), true).await;
    assert!(out.ended && out.body == BODY_LEN, "{}/{BODY_LEN}", out.body);
    assert_eq!(
        out.refused,
        vec![3],
        "a stream opened after GOAWAY is refused"
    );
}

async fn echo_len(req: Request) -> Response {
    use http_body_util::BodyExt;
    let body = req.into_body().collect().await.unwrap().to_bytes();
    http::Response::new(Body::Full(Bytes::from(body.len().to_string())))
}

#[tokio::test]
async fn peer_goaway_lets_an_in_progress_upload_finish() {
    // #695: a request still uploading has no handler yet; the drain must wait for it.
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let srv = tokio::spawn(async move { serve(server, echo_len, Config::default(), None).await });
    client.write_all(hj_h2::conn::PREFACE).await.unwrap();
    let mut wire = Vec::new();
    frame::write_settings(&mut wire, &[]);
    let mut enc = Encoder::new();
    let mut block = Vec::new();
    for (n, v) in [
        (":method", "POST"),
        (":path", "/"),
        (":scheme", "https"),
        (":authority", "example.com"),
    ] {
        enc.encode_header(&mut block, n, v);
    }
    frame::write_frame(
        &mut wire,
        frame::kind::HEADERS,
        frame::flags::END_HEADERS,
        1,
        &block,
    );
    frame::write_frame(&mut wire, frame::kind::DATA, 0, 1, b"abc");
    frame::write_goaway(&mut wire, 0, frame::error_code::NO_ERROR);
    client.write_all(&wire).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut rest = Vec::new();
    frame::write_frame(
        &mut rest,
        frame::kind::DATA,
        frame::flags::END_STREAM,
        1,
        b"def",
    );
    client.write_all(&rest).await.unwrap();
    let body = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (hdr, p) = read_frame(&mut client)
                .await
                .expect("connection closed early");
            if hdr.kind == frame::kind::DATA && hdr.stream_id == 1 {
                break p;
            }
        }
    })
    .await
    .expect("upload response never arrived");
    assert_eq!(body, b"6");
    drop(client);
    let _ = srv.await;
}
