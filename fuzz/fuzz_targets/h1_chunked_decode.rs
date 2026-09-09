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

#[path = "../h1_properties.rs"]
#[allow(dead_code)]
mod properties;

fuzz_target!(|data: &[u8]| properties::h1_chunked_decode(data));
