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

#[derive(Default, Debug)]
struct Seen {
    body: usize,
    ended: bool,
    cancelled: bool,
    goaway: Option<u32>,
}

impl Seen {
    /// Records one server frame on the #906 connection.
    fn note(&mut self, hdr: &FrameHeader, p: &[u8]) {
        match hdr.kind {
            frame::kind::DATA if hdr.stream_id == 1 => {
                self.body += p.len();
                self.ended |= hdr.flags & frame::flags::END_STREAM != 0;
            }
            frame::kind::RST_STREAM if hdr.stream_id == 1 => {
                assert_eq!(
                    u32::from_be_bytes(p[..4].try_into().unwrap()),
                    frame::error_code::CANCEL
                );
                self.cancelled = true;
            }
            frame::kind::GOAWAY => {
                self.goaway = Some(u32::from_be_bytes(p[4..8].try_into().unwrap()));
            }
            _ => {}
        }
    }
}

fn drain_request() -> Vec<u8> {
    let mut wire = hj_h2::conn::PREFACE.to_vec();
    frame::write_settings(&mut wire, &[(frame::settings::INITIAL_WINDOW_SIZE, 16384)]);
    let mut enc = Encoder::new();
    get(&mut enc, &mut wire, 1);
    frame::write_goaway(&mut wire, 0, frame::error_code::NO_ERROR);
    wire
}

fn credit() -> Vec<u8> {
    let mut w = Vec::new();
    frame::write_window_update(&mut w, 1, 1_000_000);
    frame::write_window_update(&mut w, 0, 1_000_000);
    w
}

/// #906: GET with a 16 KiB stream window + GOAWAY(NO_ERROR), handler `delay`, 100 KB
/// body; credit is granted once the window is exhausted when `grant`. Runs on paused
/// time, so multi-second delays cost nothing.
async fn drain_case(delay: Duration, grant: bool, config: Config) -> Seen {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let svc = move |_req: Request| async move {
        tokio::time::sleep(delay).await;
        http::Response::new(Body::Full(Bytes::from(vec![b'x'; BODY_LEN])))
    };
    let srv = tokio::spawn(async move { serve(server, svc, config, None).await });
    client.write_all(&drain_request()).await.unwrap();

    let mut seen = Seen::default();
    let mut granted = false;
    let read_all = async {
        while let Some((hdr, p)) = read_frame(&mut client).await {
            seen.note(&hdr, &p);
            if grant && !granted && seen.body >= 16384 {
                granted = true;
                client.write_all(&credit()).await.unwrap();
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(600), read_all)
        .await
        .expect("server never closed the drained connection");
    tokio::time::timeout(Duration::from_secs(10), srv)
        .await
        .expect("serve() must return after the drain")
        .unwrap()
        .unwrap();
    seen
}

#[tokio::test(start_paused = true)]
async fn peer_goaway_handler_past_twelve_seconds_is_fully_delivered() {
    let seen = drain_case(Duration::from_secs(13), true, Config::default()).await;
    assert!(
        seen.ended && seen.body == BODY_LEN && !seen.cancelled,
        "slow post-GOAWAY response truncated: {seen:?}"
    );
    assert_eq!(
        seen.goaway, None,
        "a completed drain needs no server GOAWAY"
    );
}

#[tokio::test(start_paused = true)]
async fn drain_bound_resets_a_window_blocked_response_explicitly() {
    let config = Config {
        goaway_drain_timeout: Duration::from_secs(2),
        send_stall_timeout: None,
        ..Config::default()
    };
    let seen = drain_case(Duration::ZERO, false, config).await;
    assert_eq!(seen.body, 16384, "{seen:?}");
    assert!(!seen.ended && seen.cancelled, "silent truncation: {seen:?}");
    assert_eq!(seen.goaway, Some(frame::error_code::NO_ERROR), "{seen:?}");
}

#[tokio::test(start_paused = true)]
async fn drain_bound_resets_an_inflight_handler_explicitly() {
    let config = Config {
        goaway_drain_timeout: Duration::from_secs(2),
        ..Config::default()
    };
    let seen = drain_case(Duration::from_secs(30), true, config).await;
    assert_eq!(seen.body, 0, "{seen:?}");
    assert!(seen.cancelled, "silent truncation: {seen:?}");
    assert_eq!(seen.goaway, Some(frame::error_code::NO_ERROR), "{seen:?}");
}

#[cfg(feature = "monoio")]
mod monoio_path {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Instant;

    /// The monoio twin of `drain_case`, on real time. The handler waits on a std
    /// thread (monoio shares no timer with tokio) and resumes over a
    /// runtime-agnostic oneshot.
    fn monoio_drain_case(delay: Duration, grant: bool, config: Config) -> Seen {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                .enable_timer()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                hj_h2::server::serve_local_with_prefix(
                    stream,
                    Vec::new(),
                    move |_req: Request| {
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        std::thread::spawn(move || {
                            std::thread::sleep(delay);
                            let _ = tx.send(());
                        });
                        async move {
                            let _ = rx.await;
                            http::Response::new(Body::Full(Bytes::from(vec![b'x'; BODY_LEN])))
                        }
                    },
                    config,
                    None,
                    None,
                )
                .await
            })
        });

        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        stream.write_all(&drain_request()).unwrap();

        let (mut buf, mut at, mut raw) = ([0u8; 16384], 0usize, Vec::new());
        let mut seen = Seen::default();
        let mut granted = false;
        let started = Instant::now();
        loop {
            assert!(
                started.elapsed() < delay + Duration::from_secs(10),
                "server never closed: {seen:?}"
            );
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
            while let Some(h) = raw.get(at..at + FrameHeader::LEN) {
                let hdr = FrameHeader::parse(h).unwrap();
                let start = at + FrameHeader::LEN;
                let Some(p) = raw.get(start..start + hdr.length as usize) else {
                    break;
                };
                seen.note(&hdr, p);
                at = start + hdr.length as usize;
            }
            if grant && !granted && seen.body >= 16384 {
                granted = true;
                stream.write_all(&credit()).unwrap();
            }
        }
        drop(stream);
        server.join().unwrap().unwrap();
        seen
    }

    #[test]
    fn monoio_peer_goaway_handler_past_twelve_seconds_is_fully_delivered() {
        let seen = monoio_drain_case(Duration::from_secs(13), true, Config::default());
        assert!(
            seen.ended && seen.body == BODY_LEN && !seen.cancelled,
            "slow post-GOAWAY response truncated: {seen:?}"
        );
        assert_eq!(seen.goaway, None);
    }

    #[test]
    fn monoio_drain_bound_resets_a_window_blocked_response_explicitly() {
        let config = Config {
            goaway_drain_timeout: Duration::from_millis(500),
            send_stall_timeout: None,
            ..Config::default()
        };
        let seen = monoio_drain_case(Duration::ZERO, false, config);
        assert_eq!(seen.body, 16384, "{seen:?}");
        assert!(!seen.ended && seen.cancelled, "silent truncation: {seen:?}");
        assert_eq!(seen.goaway, Some(frame::error_code::NO_ERROR), "{seen:?}");
    }

    #[test]
    fn monoio_drain_bound_resets_an_inflight_handler_explicitly() {
        let config = Config {
            goaway_drain_timeout: Duration::from_millis(500),
            ..Config::default()
        };
        let seen = monoio_drain_case(Duration::from_secs(3), true, config);
        assert_eq!(seen.body, 0, "{seen:?}");
        assert!(seen.cancelled, "silent truncation: {seen:?}");
        assert_eq!(seen.goaway, Some(frame::error_code::NO_ERROR), "{seen:?}");
    }
}
