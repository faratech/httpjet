//! Fuzz the HTTP/3 request-stream parser (`H3FrameCounter`), which validates every
//! request frame as it arrives and keeps the field sections and the body for dispatch.
//! What it reports must not depend on how the bytes were split across reads, what it
//! buffers must stay within its limits, and a stream it accepts must hold the frames
//! an independent walk of the same bytes finds.
#![no_main]

// The same source files the server compiles as `uring::{codec, h3_wire, qpack}`.
#[path = "../../crates/httpjet/src/uring/codec.rs"]
#[allow(dead_code)]
mod codec;
#[path = "../../crates/httpjet/src/uring/h3_wire.rs"]
#[allow(dead_code)]
mod h3_wire;
#[path = "../../crates/httpjet/src/uring/qpack.rs"]
#[allow(dead_code)]
mod qpack;

use h3_wire::{
    DecodedFieldSection, H3FrameCounter, H3RequestHead, H3RequestLimits, RequestFrameError,
};
use libfuzzer_sys::fuzz_target;

const HEADER_LIMITS: [usize; 4] = [16, 256, 4096, 64 * 1024];
const BODY_LIMITS: [usize; 4] = [0, 16, 1024, 1024 * 1024];

#[derive(Debug, PartialEq)]
enum Head {
    Pending,
    Undecodable,
    Decoded(DecodedFieldSection, Option<usize>),
}

/// Everything the receive path and dispatch can observe of one request stream.
#[derive(Debug, PartialEq)]
struct Received {
    result: Result<(), RequestFrameError>,
    header_bytes: usize,
    body_bytes: usize,
    head_footprint: usize,
    malformed: bool,
    field: Option<Vec<u8>>,
    trailers: Option<Vec<u8>>,
    body: Vec<u8>,
    head: Head,
    /// The request handed to dispatch at FIN: field section, body, trailers, decoded head.
    request: Option<(
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<DecodedFieldSection>,
    )>,
}

fn check_bounds(frames: &H3FrameCounter, body: &[u8], limits: H3RequestLimits) {
    let held =
        frames.field.as_ref().map_or(0, Vec::len) + frames.trailers.as_ref().map_or(0, Vec::len);
    assert!(
        held <= frames.header_bytes,
        "more header bytes than declared"
    );
    assert!(
        frames.header_bytes <= limits.max_header_bytes,
        "header limit"
    );
    assert!(body.len() <= frames.body_bytes, "more body than declared");
    assert!(frames.body_bytes <= limits.max_body_bytes, "body limit");
    if let H3RequestHead::Decoded {
        fields,
        content_length,
    } = &frames.head
    {
        assert!(fields.1 <= limits.max_header_bytes, "decoded head limit");
        if let Some(declared) = content_length {
            assert!(body.len() <= *declared, "body past its content-length");
        }
    }
}

/// Deliver `wire` in `step`-byte reads, stopping at the first error as the server does.
fn receive(wire: &[u8], step: usize, limits: H3RequestLimits) -> Received {
    let mut frames = H3FrameCounter::default();
    let mut body = Vec::new();
    let mut result = Ok(());
    for piece in wire.chunks(step) {
        result = frames.consume(piece, &mut body, limits);
        check_bounds(&frames, &body, limits);
        if result.is_err() {
            break;
        }
    }
    let head = match &frames.head {
        H3RequestHead::Pending => Head::Pending,
        H3RequestHead::Undecodable => Head::Undecodable,
        H3RequestHead::Decoded {
            fields,
            content_length,
        } => Head::Decoded(fields.clone(), *content_length),
    };
    let mut received = Received {
        result,
        header_bytes: frames.header_bytes,
        body_bytes: frames.body_bytes,
        head_footprint: frames.head_footprint,
        malformed: frames.malformed,
        field: frames.field.clone(),
        trailers: frames.trailers.clone(),
        body: body.clone(),
        head,
        request: None,
    };
    if result.is_ok() {
        received.request = frames
            .finish(body, None)
            .map(|(parsed, head)| (parsed.field, parsed.body.to_vec(), parsed.trailers, head));
    }
    received
}

/// One RFC 9000 §16 variable-length integer at `*pos`; `None` if it is cut short.
fn varint(wire: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *wire.get(*pos)?;
    let bytes = wire.get(*pos..*pos + (1usize << (first >> 6)))?;
    *pos += bytes.len();
    Some(
        bytes
            .iter()
            .skip(1)
            .fold(u64::from(first & 0x3f), |value, byte| {
                (value << 8) | u64::from(*byte)
            }),
    )
}

/// Check a stream the parser took without an error against a plain walk of its
/// frames (RFC 9114 §4.1: HEADERS, then DATA frames, then optional trailers).
fn check_against_walk(received: &Received, wire: &[u8], limits: H3RequestLimits) {
    let (mut field, mut trailers, mut body) = (None, None, Vec::new());
    let (mut header_bytes, mut body_bytes) = (0usize, 0usize);
    let (mut malformed, mut cut, mut body_frames) = (false, false, 0usize);
    let mut pos = 0;
    while pos < wire.len() {
        let (Some(kind), Some(length)) = (varint(wire, &mut pos), varint(wire, &mut pos)) else {
            cut = true;
            break;
        };
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        let end = pos.saturating_add(length).min(wire.len());
        let payload = &wire[pos..end];
        cut = payload.len() < length;
        pos = end;
        match kind {
            0x01 => {
                header_bytes = header_bytes.saturating_add(length);
                if field.is_none() {
                    field = Some(payload.to_vec());
                } else if trailers.is_none() {
                    trailers = Some(payload.to_vec());
                } else {
                    malformed = true;
                }
            }
            0x00 => {
                body_bytes = body_bytes.saturating_add(length);
                malformed |= field.is_none() || trailers.is_some();
                if !malformed {
                    body.extend_from_slice(payload);
                    body_frames += 1;
                }
            }
            _ => assert!(
                !matches!(kind, 0x02..=0x09 | 0x0d),
                "a frame that is not allowed on a request stream was accepted"
            ),
        }
    }
    assert_eq!(received.field, field, "request field section");
    assert_eq!(received.trailers, trailers, "trailer field section");
    assert_eq!(received.body, body, "body bytes");
    assert_eq!(received.header_bytes, header_bytes, "declared header bytes");
    assert_eq!(received.body_bytes, body_bytes, "declared body bytes");
    assert_eq!(received.malformed, malformed, "frame sequence verdict");

    let request = match field {
        Some(field) if !malformed && !cut => {
            // Dispatch reuses the head decoded when the first DATA frame arrived.
            let head = if body_frames > 0 {
                qpack::qpack_decode_limited(&field, limits.max_header_bytes)
            } else {
                None
            };
            Some((field, body, trailers, head))
        }
        _ => None,
    };
    assert_eq!(received.request, request, "the request handed to dispatch");
}

fuzz_target!(|data: &[u8]| {
    let [split, select, wire @ ..] = data else {
        return;
    };
    let limits = H3RequestLimits::new(
        HEADER_LIMITS[usize::from(select & 3)],
        BODY_LIMITS[usize::from((select >> 2) & 3)],
    );
    let whole = receive(wire, wire.len().max(1), limits);
    let pieces = receive(wire, usize::from(split % 32) + 1, limits);
    assert_eq!(
        whole, pieces,
        "the request depends on how the bytes arrived"
    );
    if whole.result.is_ok() {
        check_against_walk(&whole, wire, limits);
    }
});
