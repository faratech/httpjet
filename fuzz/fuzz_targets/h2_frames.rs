//! Fuzz the HTTP/2 server's frame handling end to end: arbitrary bytes after the
//! client preface go through `hj_h2::server::serve` over an in-memory pipe. Besides
//! "no panic, no hang", what the server writes back must be whole frames, on client
//! streams only, with nothing sent on a stream the server already ended.
#![no_main]

use std::collections::HashSet;
use std::time::Duration;

use hj_h2::frame::{FrameHeader, flags, kind};
use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

thread_local! {
    // Paused clock: the server's timers fire as soon as nothing else can run, so a
    // connection that only waits never costs wall time.
    static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("runtime");
}

async fn exchange(wire: &[u8]) -> Vec<u8> {
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let serve = hj_h2::server::serve(
        server,
        |_request| async {
            hj_core::Response::new(hj_core::Body::Full(bytes::Bytes::from_static(b"ok")))
        },
        hj_h2::server::Config::default(),
        None,
    );
    let drive = async {
        let (mut read, mut write) = tokio::io::split(&mut client);
        let send = async {
            let _ = write.write_all(PREFACE).await;
            let _ = write.write_all(wire).await;
            let _ = write.shutdown().await;
        };
        let receive = async {
            let mut out = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = read.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&chunk[..n]);
                assert!(out.len() < 16 << 20, "unbounded output for a 4 KiB input");
            }
            out
        };
        tokio::join!(send, receive).1
    };
    let (_, out) = tokio::time::timeout(Duration::from_secs(3600), async {
        tokio::join!(serve, drive)
    })
    .await
    .expect("the connection did not end after the peer closed");
    out
}

fn check_output(mut rest: &[u8]) {
    let mut ended: HashSet<u32> = HashSet::new();
    let mut continuing: Option<u32> = None;
    while let Some(header) = FrameHeader::parse(rest) {
        let total = FrameHeader::LEN + header.length as usize;
        assert!(rest.len() >= total, "the server wrote a truncated frame");
        let id = header.stream_id;
        if let Some(open) = continuing {
            assert!(
                header.kind == kind::CONTINUATION && id == open,
                "a header block was interrupted"
            );
        }
        match header.kind {
            kind::HEADERS | kind::DATA => {
                assert!(id % 2 == 1, "response frame on stream {id}");
                assert!(!ended.contains(&id), "frame on stream {id} after it ended");
                if header.kind == kind::HEADERS && header.flags & flags::END_HEADERS == 0 {
                    continuing = Some(id);
                }
                if header.flags & flags::END_STREAM != 0 {
                    ended.insert(id);
                }
            }
            kind::CONTINUATION => {
                assert_eq!(continuing, Some(id), "CONTINUATION without a header block");
                if header.flags & flags::END_HEADERS != 0 {
                    continuing = None;
                }
            }
            kind::RST_STREAM => {
                assert!(id != 0, "RST_STREAM on stream 0");
                ended.insert(id);
            }
            kind::SETTINGS | kind::PING | kind::GOAWAY => {
                assert_eq!(id, 0, "connection frame on stream {id}");
            }
            kind::WINDOW_UPDATE => {}
            other => panic!("the server sent frame type {other}"),
        }
        rest = &rest[total..];
    }
    assert!(rest.is_empty(), "trailing bytes after the last frame");
}

fuzz_target!(|data: &[u8]| {
    let out = RUNTIME.with(|runtime| runtime.block_on(exchange(data)));
    check_output(&out);
});
