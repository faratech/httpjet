//! (#905, MadeYouReset / CVE-2025-8671) A reset the server sends because the peer
//! provoked it (WINDOW_UPDATE increment 0, self-dependent PRIORITY, DATA on a
//! half-closed stream, a pre-response WINDOW_UPDATE overflowing the stream window)
//! aborts the in-flight handler exactly like a peer RST_STREAM, so
//! it must draw on the same rapid-reset budget and end in GOAWAY(ENHANCE_YOUR_CALM).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hj_core::{Body, Request, Response};
use hj_h2::frame::{self, FrameHeader};
use hj_h2::hpack::Encoder;
use hj_h2::server::{Config, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ROUNDS: u32 = 300;

#[derive(Clone, Copy, Debug)]
enum Provoke {
    ZeroWindowUpdate,
    SelfPriority,
    DataOnHalfClosed,
    WindowOverflow,
}

const ALL: [Provoke; 4] = [
    Provoke::ZeroWindowUpdate,
    Provoke::SelfPriority,
    Provoke::DataOnHalfClosed,
    Provoke::WindowOverflow,
];

fn get_block(enc: &mut Encoder) -> Vec<u8> {
    let mut block = Vec::new();
    enc.encode_header(&mut block, ":method", "GET");
    enc.encode_header(&mut block, ":path", "/");
    enc.encode_header(&mut block, ":scheme", "https");
    enc.encode_header(&mut block, ":authority", "example.com");
    block
}

fn provoke(wire: &mut Vec<u8>, how: Provoke, sid: u32) {
    match how {
        Provoke::ZeroWindowUpdate => frame::write_frame(
            wire,
            frame::kind::WINDOW_UPDATE,
            0,
            sid,
            &0u32.to_be_bytes(),
        ),
        Provoke::SelfPriority => {
            let mut p = sid.to_be_bytes().to_vec();
            p.push(15);
            frame::write_frame(wire, frame::kind::PRIORITY, 0, sid, &p);
        }
        Provoke::DataOnHalfClosed => frame::write_frame(wire, frame::kind::DATA, 0, sid, b"x"),
        Provoke::WindowOverflow => frame::write_window_update(wire, sid, 0x7fff_ffff),
    }
}

/// HEADERS(END_STREAM) then the provoking frame on the same stream, `ROUNDS` times, in
/// one write so every handler is still in flight when its stream is reset.
fn flood(how: Provoke) -> Vec<u8> {
    let mut wire = hj_h2::conn::PREFACE.to_vec();
    frame::write_settings(&mut wire, &[]);
    let mut enc = Encoder::new();
    let mut sid = 1u32;
    for _ in 0..ROUNDS {
        let block = get_block(&mut enc);
        frame::write_frame(
            &mut wire,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS | frame::flags::END_STREAM,
            sid,
            &block,
        );
        provoke(&mut wire, how, sid);
        sid += 2;
    }
    wire
}

/// Scans a server byte stream for a GOAWAY; returns its error code.
fn find_goaway(seen: &[u8]) -> Option<u32> {
    let mut at = 0;
    while let Some(h) = seen.get(at..at + FrameHeader::LEN) {
        let hdr = FrameHeader::parse(h).unwrap();
        let p = seen.get(at + FrameHeader::LEN..at + FrameHeader::LEN + hdr.length as usize)?;
        if hdr.kind == frame::kind::GOAWAY {
            return Some(u32::from_be_bytes(p[4..8].try_into().unwrap()));
        }
        at += FrameHeader::LEN + hdr.length as usize;
    }
    None
}

/// Consumes complete frames from `seen`, calling `f` on each; returns true once `f` does.
fn scan(seen: &mut Vec<u8>, mut f: impl FnMut(&FrameHeader) -> bool) -> bool {
    let mut at = 0;
    let mut hit = false;
    while let Some(h) = seen.get(at..at + FrameHeader::LEN) {
        let hdr = FrameHeader::parse(h).unwrap();
        let end = at + FrameHeader::LEN + hdr.length as usize;
        if end > seen.len() {
            break;
        }
        hit |= f(&hdr);
        at = end;
    }
    seen.drain(..at);
    hit
}

fn counting_never(starts: Arc<AtomicUsize>) -> impl Fn(Request) -> std::future::Pending<Response> {
    move |_req| {
        starts.fetch_add(1, Ordering::Relaxed);
        std::future::pending()
    }
}

async fn tokio_flood(how: Provoke) {
    let starts = Arc::new(AtomicUsize::new(0));
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let svc = counting_never(starts.clone());
    let srv = tokio::spawn(async move { serve(server, svc, Config::default(), None).await });
    client.write_all(&flood(how)).await.unwrap();
    let mut seen = Vec::new();
    let code = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 16384];
        loop {
            if let Some(code) = find_goaway(&seen) {
                return code;
            }
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0, "server closed without a GOAWAY ({how:?})");
            seen.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("provoked-reset flood ({how:?}) never drew a GOAWAY"));
    assert_eq!(code, frame::error_code::ENHANCE_YOUR_CALM, "{how:?}");
    let started = starts.load(Ordering::Relaxed);
    assert!(
        started <= 202,
        "{how:?}: {started} handlers started past the reset budget"
    );
    srv.abort();
}

#[tokio::test]
async fn zero_window_update_on_inflight_streams_trips_reset_budget() {
    tokio_flood(Provoke::ZeroWindowUpdate).await;
}

#[tokio::test]
async fn self_dependent_priority_on_inflight_streams_trips_reset_budget() {
    tokio_flood(Provoke::SelfPriority).await;
}

#[tokio::test]
async fn data_on_half_closed_inflight_streams_trips_reset_budget() {
    tokio_flood(Provoke::DataOnHalfClosed).await;
}

/// The other side of the budget: answering frames on streams whose response already
/// finished (no handler in flight) costs no backend work and must not trip it.
#[tokio::test]
async fn resets_of_finished_streams_are_not_charged() {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let srv = tokio::spawn(async move {
        serve(
            server,
            |_req: Request| async { Response::new(Body::Full(Bytes::from_static(b"ok"))) },
            Config::default(),
            None,
        )
        .await
    });
    let mut wire = hj_h2::conn::PREFACE.to_vec();
    frame::write_settings(&mut wire, &[]);
    client.write_all(&wire).await.unwrap();
    let mut enc = Encoder::new();
    let mut sid = 1u32;
    let mut buf = [0u8; 16384];
    let mut seen: Vec<u8> = Vec::new();
    for round in 0..ROUNDS {
        let mut w = Vec::new();
        let block = get_block(&mut enc);
        frame::write_frame(
            &mut w,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS | frame::flags::END_STREAM,
            sid,
            &block,
        );
        client.write_all(&w).await.unwrap();
        // Wait for this stream's END_STREAM before provoking the reset.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let done = scan(&mut seen, |hdr| {
                    assert_ne!(hdr.kind, frame::kind::GOAWAY, "round {round}: GOAWAY");
                    hdr.stream_id == sid && hdr.flags & frame::flags::END_STREAM != 0
                });
                if done {
                    return;
                }
                let n = client.read(&mut buf).await.unwrap();
                assert!(n > 0, "server closed at round {round}");
                seen.extend_from_slice(&buf[..n]);
            }
        })
        .await
        .expect("response never finished");
        let mut w = Vec::new();
        provoke(&mut w, ALL[round as usize % ALL.len()], sid);
        client.write_all(&w).await.unwrap();
        sid += 2;
    }
    // A final PING round-trip proves the connection is still healthy.
    let mut w = Vec::new();
    frame::write_frame(&mut w, frame::kind::PING, 0, 0, &[7u8; 8]);
    client.write_all(&w).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let acked = scan(&mut seen, |hdr| {
                assert_ne!(
                    hdr.kind,
                    frame::kind::GOAWAY,
                    "finished-stream resets tripped"
                );
                hdr.kind == frame::kind::PING && hdr.flags & frame::flags::ACK != 0
            });
            if acked {
                return;
            }
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0, "server closed");
            seen.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("PING never acknowledged");
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn pre_response_window_overflow_on_inflight_streams_trips_reset_budget() {
    tokio_flood(Provoke::WindowOverflow).await;
}

#[cfg(feature = "monoio")]
mod monoio_path {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Instant;

    fn monoio_flood(how: Provoke) {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let starts = Arc::new(AtomicUsize::new(0));
        let svc = counting_never(starts.clone());
        // The never-completing handlers keep the connection task alive after the
        // GOAWAY; the server thread is left to the process exit.
        std::thread::spawn(move || {
            let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                .enable_timer()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let _ = hj_h2::server::serve_local_with_prefix(
                    stream,
                    Vec::new(),
                    svc,
                    Config::default(),
                    None,
                    None,
                )
                .await;
            })
        });
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        stream.write_all(&flood(how)).unwrap();
        let started = Instant::now();
        let mut seen = Vec::new();
        let mut buf = [0u8; 16384];
        let code = loop {
            if let Some(code) = find_goaway(&seen) {
                break code;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "monoio: provoked-reset flood ({how:?}) never drew a GOAWAY"
            );
            match stream.read(&mut buf) {
                Ok(0) => panic!("monoio: closed without GOAWAY ({how:?})"),
                Ok(n) => seen.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => panic!("{e}"),
            }
        };
        assert_eq!(code, frame::error_code::ENHANCE_YOUR_CALM, "{how:?}");
        let n = starts.load(Ordering::Relaxed);
        assert!(n <= 202, "monoio {how:?}: {n} handlers started");
    }

    #[test]
    fn monoio_zero_window_update_trips_reset_budget() {
        monoio_flood(Provoke::ZeroWindowUpdate);
    }

    #[test]
    fn monoio_self_dependent_priority_trips_reset_budget() {
        monoio_flood(Provoke::SelfPriority);
    }

    #[test]
    fn monoio_data_on_half_closed_trips_reset_budget() {
        monoio_flood(Provoke::DataOnHalfClosed);
    }

    #[test]
    fn monoio_pre_response_window_overflow_trips_reset_budget() {
        monoio_flood(Provoke::WindowOverflow);
    }
}
