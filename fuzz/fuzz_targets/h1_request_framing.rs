//! Fuzz the request-head boundary and framing decisions
//! (`request_head_progress` + `classify_framing` + `resolve_content_length`)
//! for the RFC 7230 §3.3.3 smuggling invariant: a request that is accepted as
//! `Length(n)` or `Chunked` must have unambiguous, conflict-free framing — anything
//! ambiguous (CL+TE, a compound/other TE, a bad/conflicting Content-Length) MUST
//! become `Reject`. This is the property that, had it existed, would have caught the
//! historical chunked-smuggling bug automatically.
#![no_main]

#[path = "../../crates/httpjet/src/uring/codec.rs"]
#[allow(dead_code)] // each target uses a subset of the shared codec module
mod codec;

use libfuzzer_sys::fuzz_target;

#[path = "../h1_properties.rs"]
#[allow(dead_code)]
mod properties;

fuzz_target!(|data: &[u8]| properties::h1_request_framing(data));
