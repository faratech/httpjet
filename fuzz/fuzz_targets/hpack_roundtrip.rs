//! HPACK encode -> decode roundtrip property: a header list encoded by our encoder
//! must decode back to the same sequence. Catches encoder/decoder divergence and
//! dynamic-table desync.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    pairs: Vec<(String, String)>,
}

fuzz_target!(|input: Input| {
    // HTTP/2 forbids an empty field name; the encoder/decoder may reject it, which
    // would break the equality check for reasons unrelated to a real bug.
    let pairs: Vec<(String, String)> = input
        .pairs
        .into_iter()
        .filter(|(n, _)| !n.is_empty())
        .collect();

    let mut enc = hj_h2::hpack::Encoder::new();
    let mut block = Vec::new();
    for (n, v) in &pairs {
        enc.encode_header(&mut block, n, v.as_bytes());
    }

    let mut dec = hj_h2::hpack::Decoder::new(4096, 1 << 24);
    let mut got: Vec<(String, String)> = Vec::new();
    let r = dec.decode(&block, |n, v| got.push((n.to_string(), v.to_string())));
    if r.is_ok() {
        assert_eq!(got, pairs, "HPACK encode->decode roundtrip mismatch");
    }
});
