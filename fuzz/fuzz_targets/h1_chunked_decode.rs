//! Fuzz the HTTP/1.1 chunked-body decoder — the exact code that desynced in the
//! historical request-smuggling bug. Two invariants on arbitrary bytes:
//!   1. never panic;
//!   2. a `Done(end)` offset is within the buffer (never reads past it);
//!   3. byte-at-a-time (resumable) decoding agrees with one-shot decoding on the
//!      decoded body whenever both complete.
#![no_main]

// Same source file the server compiles as `uring::codec` — no `httpjet` dep, so the
// ASan fuzz build stays free of monoio/quinn/TLS. Fuzzed code == served code.
#[path = "../../crates/httpjet/src/uring/codec.rs"]
#[allow(dead_code)] // each target uses a subset of the shared codec module
mod codec;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // One-shot.
    let mut one = codec::ChunkedDecoder::new(0);
    let one_body = match one.advance(data) {
        codec::ChunkStep::Done(end) => {
            assert!(
                end <= data.len(),
                "chunked Done offset {end} past buffer len {}",
                data.len()
            );
            Some(std::mem::take(&mut one.body))
        }
        _ => None,
    };

    // Incremental: feed one byte at a time into a growing buffer (the resumable
    // contract). Must agree with one-shot on the decoded body when both complete.
    let mut inc = codec::ChunkedDecoder::new(0);
    let mut buf = Vec::with_capacity(data.len());
    let mut inc_body = None;
    for &b in data {
        buf.push(b);
        match inc.advance(&buf) {
            codec::ChunkStep::Done(_) => {
                inc_body = Some(std::mem::take(&mut inc.body));
                break;
            }
            codec::ChunkStep::Bad => break,
            codec::ChunkStep::NeedMore => {}
        }
    }

    if let (Some(o), Some(i)) = (one_body, inc_body) {
        assert_eq!(o, i, "one-shot vs incremental chunked body mismatch");
    }
});
