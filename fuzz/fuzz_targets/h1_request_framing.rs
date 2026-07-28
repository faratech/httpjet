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

fuzz_target!(|data: &[u8]| {
    fn parse_head(buf: &[u8], max_head: usize) -> codec::RequestHeadProgress {
        let mut headers = [httparse::EMPTY_HEADER; codec::MAX_REQUEST_HEADERS];
        let mut request = httparse::Request::new(&mut headers);
        codec::request_head_progress(request.parse(buf), buf.len(), max_head)
    }

    fn equivalent(a: codec::RequestHeadProgress, b: codec::RequestHeadProgress) -> bool {
        use codec::RequestHeadProgress::*;
        match (a, b) {
            (Complete(x), Complete(y)) => x == y,
            (Partial, Partial) => true,
            (TooLarge | Bad, TooLarge | Bad) => true,
            _ => false,
        }
    }

    // Exercise the exact byte cap under both a one-read parse and a split read.
    // Bad and TooLarge are both terminal rejection; the on-wire status can differ
    // when malformed bytes and the size boundary arrive in different reads, but a
    // request must never move between accepted/partial/rejected classifications.
    let max_head = data.first().copied().map(|n| n as usize + 1).unwrap_or(1);
    let wire = data.get(2..).unwrap_or_default();
    let split = data
        .get(1)
        .copied()
        .map(|n| (n as usize).min(wire.len()))
        .unwrap_or(0);
    let one_read = parse_head(wire, max_head);
    let first = parse_head(&wire[..split], max_head);
    let split_read = if first == codec::RequestHeadProgress::Partial {
        parse_head(wire, max_head)
    } else {
        first
    };
    assert!(equivalent(one_read, split_read));
    if let codec::RequestHeadProgress::Complete(head_len) = one_read {
        assert!(head_len <= max_head);
    }

    // Derive pseudo-headers: first byte = TE flags, remaining bytes split on NUL
    // into Content-Length header values.
    let (flags, rest) = data.split_first().unwrap_or((&0, &[]));
    let chunked = flags & 1 != 0;
    let te_other = flags & 2 != 0;
    let cl_values: Vec<&[u8]> = rest.split(|&b| b == 0).collect();

    let framing = codec::classify_framing(cl_values.iter().copied(), chunked, te_other);
    let cl = codec::resolve_content_length(cl_values.iter().copied());

    match framing {
        // A Length decision implies: no other TE, not chunked, and a valid CL.
        codec::BodyFraming::Length(_) => {
            assert!(
                !te_other,
                "Length chosen with a non-chunked/compound TE present"
            );
            assert!(
                !chunked,
                "Length chosen with chunked TE present (CL+TE smuggling)"
            );
            assert!(
                cl.is_ok(),
                "Length chosen with a malformed/conflicting Content-Length"
            );
        }
        // Chunked implies: chunked TE, no other TE, and NO Content-Length present.
        codec::BodyFraming::Chunked => {
            assert!(
                chunked && !te_other,
                "Chunked chosen with conflicting TE state"
            );
            assert!(
                matches!(cl, Ok(None)),
                "Chunked chosen with a Content-Length present (CL+TE)"
            );
        }
        codec::BodyFraming::Reject => {}
    }
});
