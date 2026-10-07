//! Fuzz the HTTP/3 request header decoder (static table + literals + Huffman) for
//! panics and for its size accounting: a decode under a limit never reports more
//! than the limit, the reported size is the RFC 9204 §4.5 sum, and tightening the
//! limit below the decoded size refuses the section.
#![no_main]

#[path = "../../crates/httpjet/src/uring/qpack.rs"]
#[allow(dead_code)]
mod qpack;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limit = data.first().map_or(0, |b| *b as usize * 64);
    let field = data.get(1..).unwrap_or_default();
    if let Some((headers, size)) = qpack::qpack_decode_limited(field, limit) {
        assert!(size <= limit);
        let sum: usize = headers.iter().map(|(n, v)| n.len() + v.len() + 32).sum();
        assert_eq!(size, sum);
        if size > 0 {
            assert!(qpack::qpack_decode_limited(field, size - 1).is_none());
        }
    }
    for cut in 0..field.len().min(64) {
        let _ = qpack::qpack_decode_limited(&field[..cut], usize::MAX);
    }
});
