//! Shared deterministic replay and libFuzzer invariants; uses the served codec.
use crate::codec;

pub fn h1_chunked_decode(data: &[u8]) {
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
}

pub fn h1_request_framing(data: &[u8]) {
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
    let cl_values: Vec<&[u8]> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(|&b| b == 0).collect()
    };

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
}
