//! Fuzz the native HPACK decoder on arbitrary bytes: it must only ever return
//! `Ok`/`Err`, never panic (a panic on attacker-controlled header bytes under
//! `panic=abort` would abort the whole node).
//!
//! It also checks that an over-cap header list is consumed exactly like an
//! uncapped decode (#595): a decoder that returned `HeaderListTooLarge` must keep
//! its dynamic table identical, so a follow-up block resolves the same fields
//! (the capped decoder emits a prefix of them, all of them when under its cap).
#![no_main]

use hj_h2::hpack::{Decoder, Error};
use libfuzzer_sys::fuzz_target;

fn fields(dec: &mut Decoder, block: &[u8]) -> (Vec<(String, String)>, Result<(), Error>) {
    let mut out = Vec::new();
    let result = dec.decode(block, |n, v| out.push((n.to_owned(), v.to_owned())));
    (out, result)
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let (block, follow_up) = rest.split_at((first as usize).min(rest.len()));

    let mut uncapped = Decoder::new(4096, 1 << 20);
    let mut capped = Decoder::new(4096, 64);
    let full = uncapped.decode(block, |_, _| {});
    let cut = capped.decode(block, |_, _| {});
    if full.is_ok() && cut == Err(Error::HeaderListTooLarge) {
        let (all, all_result) = fields(&mut uncapped, follow_up);
        let (some, some_result) = fields(&mut capped, follow_up);
        if all_result.is_ok() {
            assert!(all.starts_with(&some), "capped decoder resolved different fields");
            match some_result {
                Ok(()) => assert_eq!(all, some),
                Err(e) => assert_eq!(e, Error::HeaderListTooLarge),
            }
        }
    }
});
