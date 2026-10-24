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
/// Cap on the RAW chunked bytes (framing + data) belonging to one request body,
/// independent of the decoded size. Bytes after its terminating trailer line belong to
/// a pipelined successor and do not count. Bounds the read buffer against tiny-chunk
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
    // ASCII OWS only (as in resolve_content_length): str::trim would strip obs-text
    // padding such as "\xc2\xa0chunked" that hyper/LiteSpeed never frame as chunked.
    let start = leading_ows(value);
    let end = value.len() - trailing_ows(value);
    value
        .get(start..end)
        .is_some_and(|v| v.eq_ignore_ascii_case(b"chunked"))
}

fn leading_ows(v: &[u8]) -> usize {
    v.iter().take_while(|&&b| b == b' ' || b == b'\t').count()
}

fn trailing_ows(v: &[u8]) -> usize {
    v.iter()
        .rev()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count()
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

/// Absolute offset of the first CRLF in `buf` at or after `from`.
fn find_crlf_from(buf: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    loop {
        let cr = at + buf.get(at..)?.iter().position(|&b| b == b'\r')?;
        if buf.get(cr + 1) == Some(&b'\n') {
            return Some(cr);
        }
        at = cr + 1;
    }
}

/// A framing line (chunk-size + extension, or trailer field) must be free of
/// bare CR/LF and other controls (HTAB aside): `find_crlf_from` only locates the first
/// CRLF, so `0\r\n\nGET /x` would otherwise be swallowed as one "line" here while
/// an LF-lenient intermediary sees a second request (#684).
fn framing_line_clean(line: &[u8]) -> bool {
    line.iter().all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// RFC 9112 §7.1.2 trailer field line: `token ":" value`.
fn trailer_line_valid(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let name = line.get(..colon).unwrap_or_default();
    !name.is_empty()
        && name
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        && framing_line_clean(line)
}

/// Parse a chunk-size line (hex size, optional `;ext`). Returns None on garbage.
pub fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    if !framing_line_clean(line) {
        return None;
    }
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
    /// Malformed framing, or a body over its cap (see [`ChunkedDecoder::too_large`]).
    Bad,
}

/// Resumable, allocation-light HTTP/1.1 chunked-body decoder over a growing buffer.
/// `advance` parses every byte exactly once across calls (the `pos` cursor, the
/// line-scan resume point, the parsed pending chunk and the trailer phase all
/// persist), so a body delivered across many reads stays O(n).
pub struct ChunkedDecoder {
    pub body: Vec<u8>,
    pos: usize,
    /// Where the CRLF search for the line starting at `pos` resumes: no CRLF
    /// begins in `pos..scan`. Only meaningful while `scan > pos`.
    scan: usize,
    /// `(data_start, size)` of a chunk whose size line is parsed but whose data
    /// has not fully arrived, so a slow chunk never re-parses its size line.
    pending: Option<(usize, usize)>,
    in_trailers: bool,
    /// Buffer offset where the chunked body begins (after the request head).
    start: usize,
    /// Decoded-body budget (LiteSpeed `maxReqBodySize`; the production caller overrides the
    /// `MAX_BRIDGED_CHUNKED_BODY` default from config).
    pub max_body: usize,
    /// Raw-bytes budget from `start` (overridable in tests / by the config caller).
    pub max_raw: usize,
    /// Set when `Bad` was the decoded body exceeding `max_body`: the caller answers 413
    /// like an oversized Content-Length, not 400.
    pub too_large: bool,
}

impl ChunkedDecoder {
    pub fn new(start: usize) -> Self {
        ChunkedDecoder {
            body: Vec::new(),
            pos: start,
            scan: start,
            pending: None,
            in_trailers: false,
            start,
            max_body: MAX_BRIDGED_CHUNKED_BODY,
            max_raw: MAX_CHUNKED_RAW,
            too_large: false,
        }
    }

    /// Find the CRLF ending the line at `pos`, resuming where the previous call's
    /// search stopped. On a miss, remember the last byte (it may be a CR whose LF
    /// is still in flight) and report the line's buffered length.
    fn next_line_end(&mut self, buf: &[u8]) -> Result<usize, usize> {
        match find_crlf_from(buf, self.scan.max(self.pos)) {
            Some(cr) => Ok(cr),
            None => {
                self.scan = buf.len().saturating_sub(1).max(self.pos);
                Err(buf.len().saturating_sub(self.pos))
            }
        }
    }

    /// `NeedMore` for an unterminated line unless it already broke the line or
    /// whole-body raw bound.
    fn unterminated(&self, buf: &[u8], line_len: usize) -> ChunkStep {
        if line_len > MAX_CHUNK_LINE || buf.len().saturating_sub(self.start) > self.max_raw {
            ChunkStep::Bad
        } else {
            ChunkStep::NeedMore
        }
    }

    pub fn advance(&mut self, buf: &[u8]) -> ChunkStep {
        loop {
            if let Some((data_start, size)) = self.pending {
                let need = data_start.saturating_add(size).saturating_add(2);
                if buf.len() < need {
                    return ChunkStep::NeedMore;
                }
                if &buf[data_start + size..need] != b"\r\n" {
                    return ChunkStep::Bad;
                }
                self.body
                    .extend_from_slice(&buf[data_start..data_start + size]);
                self.pending = None;
                self.pos = need;
                continue;
            }
            if self.in_trailers {
                // Consume optional trailer lines until the terminating empty line.
                // With no terminating CRLF, every buffered byte is still part of
                // this request. Enforce both the line and whole-body raw bounds.
                let line_end = match self.next_line_end(buf) {
                    Ok(line_end) => line_end,
                    Err(line_len) => return self.unterminated(buf, line_len),
                };
                let next = line_end + 2;
                if next.saturating_sub(self.start) > self.max_raw {
                    return ChunkStep::Bad;
                }
                if line_end == self.pos {
                    return ChunkStep::Done(next);
                }
                if !trailer_line_valid(&buf[self.pos..line_end]) {
                    return ChunkStep::Bad;
                }
                self.pos = next;
                continue;
            }
            let line_end = match self.next_line_end(buf) {
                Ok(line_end) => line_end,
                Err(line_len) => return self.unterminated(buf, line_len),
            };
            let data_start = line_end + 2;
            if data_start.saturating_sub(self.start) > self.max_raw {
                return ChunkStep::Bad;
            }
            let Some(size) = parse_chunk_size(&buf[self.pos..line_end]) else {
                return ChunkStep::Bad;
            };
            if size == 0 {
                self.pos = data_start;
                self.in_trailers = true;
                continue;
            }
            if self.body.len().saturating_add(size) > self.max_body {
                self.too_large = true;
                return ChunkStep::Bad;
            }
            let need = data_start.saturating_add(size).saturating_add(2);
            if need.saturating_sub(self.start) > self.max_raw {
                return ChunkStep::Bad;
            }
            self.pending = Some((data_start, size));
        }
    }
}

/// A request head that ends a line with LF alone. httparse tolerates it, but the chunked
/// decoder and the h2/h3 parsers do not; a head one parser frames differently from
/// another is a desync seam against lenient upstreams, so such a head is refused.
pub fn head_has_bare_lf(head: &[u8]) -> bool {
    head.iter()
        .enumerate()
        .any(|(i, &b)| b == b'\n' && (i == 0 || head[i - 1] != b'\r'))
}

#[cfg(test)]
mod tests {

    #[test]
    fn head_with_bare_lf_is_rejected() {
        assert!(!head_has_bare_lf(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(head_has_bare_lf(b"GET / HTTP/1.1\nHost: x\n\n"));
        assert!(head_has_bare_lf(b"GET / HTTP/1.1\r\nHost: x\n\r\n"));
        assert!(head_has_bare_lf(b"\nGET / HTTP/1.1\r\n\r\n"));
        let mut headers = [httparse::EMPTY_HEADER; 4];
        let mut req = httparse::Request::new(&mut headers);
        assert!(
            matches!(
                req.parse(b"GET / HTTP/1.1\nHost: x\n\n"),
                Ok(httparse::Status::Complete(_))
            ),
            "httparse alone accepts a bare-LF head, so the explicit check is needed"
        );
    }

    use super::*;

    #[test]
    fn chunked_framing_lines_reject_bare_lf_cr_and_bad_trailers() {
        // #684: smuggling seams an LF-lenient intermediary would frame differently.
        let decode = |wire: &[u8]| ChunkedDecoder::new(0).advance(wire);
        for wire in [
            &b"5\r\nhello\r\n0\r\n\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            b"5;a\n0\n\nGET /admin\r\nhello\r\n0\r\n\r\n",
            b"5;a\rb\r\nhello\r\n0\r\n\r\n",
            b"5\r\nhello\r\n0\r\nno-colon\r\n\r\n",
            b"5\r\nhello\r\n0\r\n: empty-name\r\n\r\n",
        ] {
            assert!(
                matches!(decode(wire), ChunkStep::Bad),
                "{:?}",
                String::from_utf8_lossy(wire)
            );
        }
        for wire in [
            &b"5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n"[..],
            b"5;name=v\r\nhello\r\n0\r\n\r\n",
            b"5\r\nhello\r\n0\r\nX-T:\tv\r\n\r\n",
        ] {
            assert!(matches!(decode(wire), ChunkStep::Done(n) if n == wire.len()));
        }
    }

    #[test]
    fn byte_at_a_time_lines_resume_their_scan_instead_of_restarting() {
        let mut size_line = b"1;".to_vec();
        size_line.resize(MAX_CHUNK_LINE - 1, b'a');
        let mut trailer = b"X-Pad: ".to_vec();
        trailer.resize(MAX_CHUNK_LINE - 1, b'b');
        let mut wire = size_line.clone();
        wire.extend_from_slice(b"\r\nx\r\n0\r\n");
        wire.extend_from_slice(&trailer);
        wire.extend_from_slice(b"\r\n\r\n");

        let mut dec = ChunkedDecoder::new(0);
        let mut buf = Vec::new();
        let mut done = None;
        for &byte in &wire {
            buf.push(byte);
            match dec.advance(&buf) {
                ChunkStep::Done(end) => {
                    done = Some(end);
                    break;
                }
                ChunkStep::Bad => panic!("valid wire rejected at {}", buf.len()),
                ChunkStep::NeedMore if dec.pending.is_none() => assert!(
                    dec.scan.max(dec.pos) >= buf.len() - 1,
                    "an unterminated line must resume at its last byte ({}), not at {}",
                    buf.len() - 1,
                    dec.scan.max(dec.pos)
                ),
                ChunkStep::NeedMore => {}
            }
        }
        assert_eq!(done, Some(wire.len()));
        assert_eq!(dec.body, b"x");
    }

    #[test]
    fn crlf_split_across_reads_and_slow_chunk_data_decode_once() {
        let mut dec = ChunkedDecoder::new(0);
        let mut buf = b"5\r".to_vec();
        assert!(matches!(dec.advance(&buf), ChunkStep::NeedMore));
        buf.extend_from_slice(b"\nhe");
        assert!(matches!(dec.advance(&buf), ChunkStep::NeedMore));
        assert_eq!(dec.pending, Some((3, 5)), "size line parsed once");
        buf.extend_from_slice(b"llo\r");
        assert!(matches!(dec.advance(&buf), ChunkStep::NeedMore));
        buf.extend_from_slice(b"\n0\r\n\r");
        assert!(matches!(dec.advance(&buf), ChunkStep::NeedMore));
        buf.extend_from_slice(b"\nNEXT");
        assert!(matches!(dec.advance(&buf), ChunkStep::Done(end) if end == buf.len() - 4));
        assert_eq!(dec.body, b"hello");

        let mut dec = ChunkedDecoder::new(0);
        let mut buf = b"2\r\nab\r".to_vec();
        assert!(matches!(dec.advance(&buf), ChunkStep::NeedMore));
        buf.push(b'X');
        assert!(
            matches!(dec.advance(&buf), ChunkStep::Bad),
            "a pending chunk still requires its CRLF"
        );
    }

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
    fn chunked_raw_cap_excludes_a_pipelined_successor() {
        let head = b"HEAD";
        let body = b"1\r\na\r\n0\r\nX-T: ok\r\n\r\n";
        let next = b"GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut wire = Vec::new();
        wire.extend_from_slice(head);
        wire.extend_from_slice(body);
        wire.extend_from_slice(next);

        let mut decoder = ChunkedDecoder::new(head.len());
        decoder.max_raw = body.len();
        assert!(matches!(
            decoder.advance(&wire),
            ChunkStep::Done(end) if end == head.len() + body.len()
        ));
        assert_eq!(decoder.body, b"a");
    }

    #[test]
    fn chunked_raw_cap_still_rejects_an_incomplete_or_overlong_body() {
        let mut oversized_chunk = ChunkedDecoder::new(0);
        oversized_chunk.max_raw = 8;
        assert!(matches!(
            oversized_chunk.advance(b"8\r\n12345678"),
            ChunkStep::Bad
        ));

        let mut endless_trailers = ChunkedDecoder::new(0);
        endless_trailers.max_raw = 10;
        assert!(matches!(
            endless_trailers.advance(b"0\r\nX: a\r\nY: b\r\n"),
            ChunkStep::Bad
        ));
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
