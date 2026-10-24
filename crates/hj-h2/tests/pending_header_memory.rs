//! Body-pending request streams keep a fully decoded header map until their body
//! arrives. The per-connection decoded-header budget must bound that in real heap
//! terms, not only in the server's own accounting: this binary counts every live
//! allocation (its only test, so nothing else allocates concurrently).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use hj_core::{Request, Response};
use hj_h2::frame::{self, FrameHeader};
use hj_h2::server::{Config, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call forwards to `System` unchanged; only a byte counter is updated.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(
            new_size as isize - layout.size() as isize,
            Ordering::Relaxed,
        );
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

async fn ok_service(_req: Request) -> Response {
    hj_core::text_response(http::StatusCode::OK, "")
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R, p: &mut Vec<u8>) -> FrameHeader {
    let mut h = [0u8; FrameHeader::LEN];
    r.read_exact(&mut h).await.unwrap();
    let hdr = FrameHeader::parse(&h).unwrap();
    p.resize(hdr.length as usize, 0);
    r.read_exact(p).await.unwrap();
    hdr
}

#[tokio::test(flavor = "current_thread")]
async fn body_pending_header_maps_hold_bounded_heap() {
    const LIST: usize = 16380; // prod maxReqHeaderSize
    const STREAMS: u32 = 256; // SETTINGS_MAX_CONCURRENT_STREAMS
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let config = Config {
        header_list_size: LIST as u32,
        ..Config::default()
    };
    let srv = tokio::spawn(async move { serve(server, ok_service, config, None).await });

    // Distinct two-letter names with empty values: the most decoded heap per listed byte.
    let mut block = vec![0x83, 0x84, 0x87, 0x01, 0x0b];
    block.extend_from_slice(b"example.com");
    let mut listed = 178;
    'names: for a in b'a'..=b'z' {
        for b in b'a'..=b'z' {
            if [a, b] == *b"te" {
                continue;
            }
            if listed + 34 > LIST {
                break 'names;
            }
            listed += 34;
            block.extend_from_slice(&[0x00, 0x02, a, b, 0x00]);
        }
    }
    let mut wire = Vec::new();
    for i in 0..STREAMS {
        frame::write_frame(
            &mut wire,
            frame::kind::HEADERS,
            frame::flags::END_HEADERS,
            1 + 2 * i,
            &block,
        );
    }
    frame::write_frame(&mut wire, frame::kind::PING, 0, 0, &[7u8; 8]);

    let mut hello = hj_h2::conn::PREFACE.to_vec();
    frame::write_settings(&mut hello, &[]);
    client.write_all(&hello).await.unwrap();
    let mut payload = Vec::with_capacity(64 * 1024);
    for _ in 0..3 {
        read_frame(&mut client, &mut payload).await; // SETTINGS, WINDOW_UPDATE, SETTINGS ACK
    }

    let before = LIVE.load(Ordering::Relaxed);
    client.write_all(&wire).await.unwrap();
    let mut refused = 0u32;
    loop {
        let hdr = read_frame(&mut client, &mut payload).await;
        match hdr.kind {
            frame::kind::GOAWAY => panic!("connection GOAWAYed"),
            frame::kind::RST_STREAM => refused += 1,
            frame::kind::PING if hdr.flags & frame::flags::ACK != 0 => break,
            _ => {}
        }
    }
    let grown = LIVE.load(Ordering::Relaxed) - before;
    assert!(
        grown < 8 << 20,
        "{} body-pending streams pinned {grown} bytes of heap",
        STREAMS - refused
    );
    assert!(
        refused > 0,
        "no stream refused past the decoded-header budget"
    );
    drop(client);
    let _ = srv.await;
}
