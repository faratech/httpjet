//! Fuzz the PROXY protocol v1/v2 header parsers. Whatever they accept must consume
//! no more than the input, never claim a loopback or unspecified source (those
//! addresses are the origin's own local-trust boundary), and re-parse identically
//! from exactly the consumed bytes.
#![no_main]

#[path = "../../crates/httpjet/src/uring/proxy_protocol_wire.rs"]
#[allow(dead_code)]
mod wire;

use libfuzzer_sys::fuzz_target;

fn check(header: Option<wire::ProxyHeader>, data: &[u8], parse: fn(&[u8]) -> Option<wire::ProxyHeader>) {
    let Some(header) = header else { return };
    assert!(header.consumed <= data.len());
    if let Some(src) = header.src {
        let ip = src.ip().to_canonical();
        assert!(!ip.is_loopback() && !ip.is_unspecified(), "claimed {src}");
    }
    let again = parse(&data[..header.consumed]).expect("consumed bytes re-parse");
    assert_eq!(again.consumed, header.consumed);
    assert_eq!(again.src, header.src);
}

fuzz_target!(|data: &[u8]| {
    check(wire::parse_v2(data), data, wire::parse_v2);
    check(wire::parse_v1(data), data, wire::parse_v1);
});
