//! Pure HTTP/1.1 request-framing primitives for the io_uring transport.
//!
//! Extracted from `uring/mod.rs` so they have NO async / monoio dependency and can
//! be (a) unit-tested in isolation and (b) reached by the `fuzz/` harnesses (the
//! crate's `lib.rs` re-exports this module via `#[path]`). Everything here is pure
//! `&[u8]` logic — the request smuggling / chunked-desync bug class
//! (RFC 7230 §3.3.3) lives entirely in these functions, so this is the surface the
//! fuzzers target. The live parser in `uring/mod.rs` calls into here, so the
//! fuzzed code and the served code can never diverge.

/// Matches the historical hyper request-header slot count. Exceeding it is
/// reported as a 431 by the H1 transport.
pub const MAX_REQUEST_HEADERS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestHeadProgress {
    Complete(usize),
    Partial,
    TooLarge,
    Bad,
}

/// Apply the configured request-head byte limit to one incremental `httparse`
/// result. A complete head is checked by its exact terminator offset; a partial
/// head is rejected only after the buffered bytes cross the limit. Keeping this
/// transition in one pure helper makes one-read and arbitrarily split reads obey
/// the same exact-boundary rule.
pub fn request_head_progress(
    parsed: Result<httparse::Status<usize>, httparse::Error>,
    buffered: usize,
    max_head: usize,
) -> RequestHeadProgress {
    match parsed {
        Ok(httparse::Status::Complete(head_len)) if head_len > max_head => {
            RequestHeadProgress::TooLarge
        }
        Ok(httparse::Status::Complete(head_len)) => RequestHeadProgress::Complete(head_len),
        Ok(httparse::Status::Partial) if buffered > max_head => RequestHeadProgress::TooLarge,
        Ok(httparse::Status::Partial) => RequestHeadProgress::Partial,
        Err(httparse::Error::TooManyHeaders) => RequestHeadProgress::TooLarge,
        Err(_) => RequestHeadProgress::Bad,
    }
}

/// How the request body is framed on the wire (decided from the request head).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// `Content-Length: n` (n may be 0).
    Length(usize),
    /// `Transfer-Encoding: chunked` — body is chunk-framed; decode it.
    Chunked,
    /// Unframable / smuggling-prone (CL+TE together, or a non-chunked TE) — 400.
    Reject,
}

/// Defensive cap on a decoded chunked request body (chunked carries no declared
/// length, so without this a malicious endless stream would grow unbounded). Far
/// above any legitimate upload; an over-cap body is rejected (400 + close).
const MAX_BRIDGED_CHUNKED_BODY: usize = 256 * 1024 * 1024;
/// Cap on the RAW chunked bytes (framing + data) accumulated for one request body,
/// independent of the decoded size. Bounds the read buffer against tiny-chunk
/// amplification (~5x raw:body) and an endless trailer section, which would otherwise
/// grow memory far past the decoded-body cap. = body cap + 1 MiB framing headroom.
const MAX_CHUNKED_RAW: usize = MAX_BRIDGED_CHUNKED_BODY + (1 << 20);
/// Cap on a single chunk-size / trailer line before we declare the framing bad
/// (guards a slowloris that never sends a CRLF).
pub const MAX_CHUNK_LINE: usize = 8 * 1024;

/// True iff a `Transfer-Encoding` header value is exactly `chunked`. A compound or
/// non-final coding (`gzip, chunked`, `gzip`) is intentionally NOT treated as
/// chunked here — we cannot safely length-frame it, so the caller rejects it.
pub fn te_is_chunked(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .map(|v| v.trim().eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
}

/// Strictly resolve the request Content-Length from its (possibly repeated) header
/// values. `Ok(None)` = absent; `Ok(Some(n))` = a single value (or identical duplicates
/// collapsed); `Err(())` = a non-numeric / overflowing value, or two values that disagree
/// (RFC 7230 §3.3.3). The caller rejects `Err` with 400 + close: silently coercing a
/// malformed/conflicting CL to a length would frame the body short and smuggle the
/// trailing bytes into the next pipelined request.
pub fn resolve_content_length<'a>(
    values: impl Iterator<Item = &'a [u8]>,
) -> Result<Option<usize>, ()> {
    let mut out: Option<usize> = None;
    for v in values {
        // (#232) Digit-only: Rust's unsigned FromStr accepts a leading '+'
        // ("+5" → 5), but RFC 9110 §8.6 defines field-length as 1*DIGIT and
        // hyper/LiteSpeed reject the signed form — admitting it here diverges
        // from every conformant stack framing the same bytes.
        let parsed = std::str::from_utf8(v)
            .ok()
            // (#232 residual) Trim ASCII OWS ONLY: str::trim is Unicode-aware, so
            // obs-text padding bytes (httparse passes 0x80..=0xFF header values)
            // would be stripped here and a non-conformant length like "\xc2\xa05"
            // would frame as 5 where hyper/LiteSpeed return 400.
            .map(|s| s.trim_matches([' ', '\t']))
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(())?;
        if out.is_some_and(|prev| prev != parsed) {
            return Err(());
        }
        out = Some(parsed);
    }
    Ok(out)
}

/// Decide body framing from the request's Content-Length / Transfer-Encoding state,
/// rejecting the RFC 7230 §3.3.3 smuggling shapes (CL+TE together, a non-chunked or
/// compound TE, a bad/conflicting CL). `cl_values` = every `Content-Length` value seen;
/// `chunked` = a lone `chunked` TE was seen; `te_other` = some other/compound TE was seen.
///
/// The live parser in `uring/mod.rs` calls this so the served framing decision and the
/// fuzzed one are the same code.
pub fn classify_framing<'a>(
    cl_values: impl Iterator<Item = &'a [u8]>,
    chunked: bool,
    te_other: bool,
) -> BodyFraming {
    match resolve_content_length(cl_values) {
        // A malformed/conflicting CL is unframable — reject (never coerce to a length).
        Err(()) => BodyFraming::Reject,
        Ok(cl) => {
            let saw_cl = cl.is_some();
            if te_other || (chunked && saw_cl) {
                BodyFraming::Reject
            } else if chunked {
                BodyFraming::Chunked
            } else {
                BodyFraming::Length(cl.unwrap_or(0))
            }
        }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Parse a chunk-size line (hex size, optional `;ext`). Returns None on garbage.
pub fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let hex = line.split(|&b| b == b';').next().unwrap_or(line);
    // (#232 class) Validate 1*HEXDIG ourselves after trimming ASCII OWS:
    // `usize::from_str_radix` accepts a leading '+' ("+2" → 2), which RFC 9112
    // §7.1 forbids and conformant stacks reject.
    let start = hex.iter().position(|b| *b != b' ' && *b != b'\t')?;
    let end = hex.iter().rposition(|b| *b != b' ' && *b != b'\t')?;
    let trimmed = &hex[start..=end];
    if trimmed.is_empty() || !trimmed.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    usize::from_str_radix(std::str::from_utf8(trimmed).ok()?, 16).ok()
}

/// Heap a chunked upload has committed: the decoded payload plus the raw chunk
/// stream still buffered in the keep-alive accumulator (both live until the
/// final drain). The server-wide body budget must see their sum — charging only
/// the decoded copy under-counts each uploading connection by ~1x its body.
pub fn chunked_accounted_bytes(decoded: usize, acc_len: usize, head_len: usize) -> u64 {
    (decoded + acc_len.saturating_sub(head_len)) as u64
}

pub enum ChunkStep {
    /// Body fully decoded; the value is the absolute end offset in the buffer (one
    /// past the terminating CRLF) — drain up to here to leave any pipelined bytes.
    Done(usize),
    /// Need more bytes appended to the buffer, then call `advance` again.
    NeedMore,
    /// Malformed framing (or body over `MAX_BRIDGED_CHUNKED_BODY`).
    Bad,
}

/// Resumable, allocation-light HTTP/1.1 chunked-body decoder over a growing buffer.
/// `advance` parses every byte exactly once across calls (the `pos` cursor and the
/// trailer phase persist), so a body delivered across many reads stays O(n).
pub struct ChunkedDecoder {
    pub body: Vec<u8>,
    pos: usize,
    in_trailers: bool,
    /// Buffer offset where the chunked body begins (after the request head).
    start: usize,
    /// Decoded-body budget (LiteSpeed `maxReqBodySize`; the production caller overrides the
    /// `MAX_BRIDGED_CHUNKED_BODY` default from config).
    pub max_body: usize,
    /// Raw-bytes budget from `start` (overridable in tests / by the config caller).
    pub max_raw: usize,
}

impl ChunkedDecoder {
    pub fn new(start: usize) -> Self {
        ChunkedDecoder {
            body: Vec::new(),
            pos: start,
            in_trailers: false,
            start,
            max_body: MAX_BRIDGED_CHUNKED_BODY,
            max_raw: MAX_CHUNKED_RAW,
        }
    }

    pub fn advance(&mut self, buf: &[u8]) -> ChunkStep {
        // Bound the RAW bytes accumulated for this body (framing + data + trailers),
        // independent of the decoded size — otherwise tiny-chunk amplification or an
        // endless trailer section grows the read buffer unbounded while the body cap is
        // still far away.
        if buf.len().saturating_sub(self.start) > self.max_raw {
            return ChunkStep::Bad;
        }
        loop {
            if self.in_trailers {
                // Consume optional trailer lines until the terminating empty line.
                let rest = &buf[self.pos.min(buf.len())..];
                let Some(rel) = find_crlf(rest) else {
                    return if rest.len() > MAX_CHUNK_LINE {
                        ChunkStep::Bad
                    } else {
                        ChunkStep::NeedMore
                    };
                };
                if rel == 0 {
                    return ChunkStep::Done(self.pos + 2);
                }
                self.pos += rel + 2;
                continue;
            }
            let rest = &buf[self.pos.min(buf.len())..];
            let Some(rel) = find_crlf(rest) else {
                return if rest.len() > MAX_CHUNK_LINE {
                    ChunkStep::Bad
                } else {
                    ChunkStep::NeedMore
                };
            };
            let line_end = self.pos + rel;
            let Some(size) = parse_chunk_size(&buf[self.pos..line_end]) else {
                return ChunkStep::Bad;
            };
            let data_start = line_end + 2;
            if size == 0 {
                self.pos = data_start;
                self.in_trailers = true;
                continue;
            }
            if self.body.len().saturating_add(size) > self.max_body {
                return ChunkStep::Bad;
            }
            let need = data_start.saturating_add(size).saturating_add(2);
            if buf.len() < need {
                return ChunkStep::NeedMore;
            }
            if &buf[data_start + size..data_start + size + 2] != b"\r\n" {
                return ChunkStep::Bad;
            }
            self.body
                .extend_from_slice(&buf[data_start..data_start + size]);
            self.pos = need;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_accounting_covers_raw_and_decoded_heap() {
        let head = 32usize;
        // Before any body arrives the accumulator is just the head: nothing charged.
        assert_eq!(chunked_accounted_bytes(0, head, head), 0);
        // Mid-upload: raw framing in the accumulator + decoded payload, both live.
        assert_eq!(chunked_accounted_bytes(5_000, head + 12_345, head), 17_345);
        // Raw extent fully drained after `Done`: only the decoded copy remains.
        assert_eq!(chunked_accounted_bytes(17_345, head, head), 17_345);
        // A head_len past the accumulator (defensive) clamps, never wraps.
        assert_eq!(chunked_accounted_bytes(4, 2, 8), 4);
    }

    #[test]
    fn classify_framing_rejects_smuggling_shapes() {
        // CL + TE together -> reject.
        assert!(matches!(
            classify_framing([b"5".as_slice()].into_iter(), true, false),
            BodyFraming::Reject
        ));
        // Compound / non-chunked TE -> reject.
        assert!(matches!(
            classify_framing(std::iter::empty(), false, true),
            BodyFraming::Reject
        ));
        // Conflicting duplicate CL -> reject.
        assert!(matches!(
            classify_framing([b"5".as_slice(), b"6".as_slice()].into_iter(), false, false),
            BodyFraming::Reject
        ));
        // Bad CL -> reject.
        assert!(matches!(
            classify_framing([b"notanumber".as_slice()].into_iter(), false, false),
            BodyFraming::Reject
        ));
        // Lone chunked -> Chunked.
        assert!(matches!(
            classify_framing(std::iter::empty(), true, false),
            BodyFraming::Chunked
        ));
        // Plain CL -> Length(n); identical duplicates collapse.
        assert!(matches!(
            classify_framing([b"7".as_slice(), b"7".as_slice()].into_iter(), false, false),
            BodyFraming::Length(7)
        ));
        // No framing headers -> Length(0).
        assert!(matches!(
            classify_framing(std::iter::empty(), false, false),
            BodyFraming::Length(0)
        ));
    }
}
