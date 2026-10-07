//! Fuzz the page-cache control-header parsers the PHP application drives
//! (X-LiteSpeed-Cache-Control / -Tag / -Vary / -Purge and standard Cache-Control)
//! for panics on arbitrary header text.
#![no_main]

#[path = "../../crates/hj-pagecache/src/proto.rs"]
#[allow(dead_code)]
mod proto;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = proto::parse_lscache_control(text);
    let _ = proto::parse_std_cache_control(text);
    let _ = proto::parse_tags(text);
    let _ = proto::parse_vary(text);
    let _ = proto::parse_purge(text);
});
