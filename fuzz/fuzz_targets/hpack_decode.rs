//! Fuzz the native HPACK decoder on arbitrary bytes: it must only ever return
//! `Ok`/`Err`, never panic (a panic on attacker-controlled header bytes under
//! `panic=abort` would abort the whole node).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut dec = hj_h2::hpack::Decoder::new(4096, 1 << 20);
    let _ = dec.decode(data, |_name, _value| {});
});
