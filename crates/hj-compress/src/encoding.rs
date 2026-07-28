//! Content-coding negotiation and the per-codec byte helpers.
//!
//! This crate can produce three response content-codings, preferred in this
//! order by [`DEFAULT_PRIORITY`]: **zstd** (RFC 8878) > **brotli** (RFC 7932) >
//! **gzip** (RFC 1952). [`negotiate_with`] picks the first coding in a server
//! priority list that the client also accepts (q>0), honoring per-coding
//! q-values, the `*` wildcard, and explicit `q=0` refusals.

/// A response content-coding this crate can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// zstd (RFC 8878).
    Zstd,
    /// brotli (RFC 7932).
    Brotli,
    /// gzip (RFC 1952).
    Gzip,
}

impl Encoding {
    /// The token used in the `Content-Encoding` / `Accept-Encoding` headers.
    pub fn token(self) -> &'static str {
        match self {
            Encoding::Zstd => "zstd",
            Encoding::Brotli => "br",
            Encoding::Gzip => "gzip",
        }
    }

    /// Parse a single `Content-Encoding` token (e.g. from a backend response).
    /// Returns `None` for `identity`, an empty/unknown token, or a multi-value
    /// list (which the caller should treat as "can't canonicalize").
    pub fn from_token(token: &str) -> Option<Encoding> {
        match token.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Encoding::Gzip),
            "br" => Some(Encoding::Brotli),
            "zstd" => Some(Encoding::Zstd),
            _ => None,
        }
    }
}

/// Server codec preference, best first. Single source of truth for ordering:
/// [`negotiate_with`] returns the first entry the client also accepts. To
/// reorder globally, change this slice; to disable a codec at runtime,
/// `Compress` filters it out of its per-instance priority list.
pub const DEFAULT_PRIORITY: &[Encoding] = &[Encoding::Zstd, Encoding::Brotli, Encoding::Gzip];

/// Per-codec compression levels carried by the transform.
#[derive(Debug, Clone, Copy)]
pub struct Levels {
    /// gzip level (flate2, 0-9).
    pub gzip: u32,
    /// zstd level (1-22; zstd's own default is 3).
    pub zstd: i32,
    /// brotli quality (0-11).
    pub brotli_q: u32,
    /// brotli window log (10-24). httpjet defaults to 19 (512 KiB): dynamic
    /// pages are 20-80 KB, so a larger window only inflates per-stream encoder
    /// state without improving the ratio (matches Pingora's lgwin=19).
    pub brotli_lgwin: u32,
}

impl Default for Levels {
    fn default() -> Self {
        // gzip 6 matches `DEFAULT_LEVEL`; zstd 3 / brotli q5 are throughput-
        // friendly defaults for on-the-fly compression on a busy origin.
        Levels {
            gzip: 6,
            zstd: 3,
            brotli_q: 5,
            brotli_lgwin: 19,
        }
    }
}

/// Parse an `Accept-Encoding` header value and return the first coding in
/// `priority` that the client accepts (effective q>0), honoring q-values per
/// RFC 9110 §12.5.3.
///
/// A coding is acceptable when its explicit q (if listed) — or otherwise the
/// `*` wildcard q — is greater than zero. An explicit listing always overrides
/// the wildcard, so `gzip;q=0, *` refuses gzip but still admits other codings
/// via the wildcard. A missing/empty header yields `None` (send identity).
///
/// Selection is by **server priority**, not client q ordering: among all
/// codings the client accepts, the highest-priority one wins (mirrors
/// OpenLiteSpeed preferring brotli over gzip, and pingora's first-acceptable
/// pick). Codings absent from `priority` (e.g. one disabled by config) are
/// never selected.
pub fn negotiate_with(accept_encoding: &str, priority: &[Encoding]) -> Option<Encoding> {
    // q for each coding if named explicitly; q for "*" if a wildcard appears.
    let mut zstd_q: Option<f32> = None;
    let mut br_q: Option<f32> = None;
    let mut gzip_q: Option<f32> = None;
    let mut star_q: Option<f32> = None;

    let trimmed = accept_encoding.trim();
    if trimmed.is_empty() {
        // No preference expressed: do not compress (safe default).
        return None;
    }

    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (coding, q) = parse_coding(part);
        let coding = coding.trim();
        // Keep the most permissive q if a coding is duplicated (rare/malformed).
        if coding.eq_ignore_ascii_case("zstd") {
            zstd_q = Some(zstd_q.map_or(q, |prev| prev.max(q)));
        } else if coding.eq_ignore_ascii_case("br") {
            br_q = Some(br_q.map_or(q, |prev| prev.max(q)));
        } else if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
            gzip_q = Some(gzip_q.map_or(q, |prev| prev.max(q)));
        } else if coding == "*" {
            star_q = Some(star_q.map_or(q, |prev| prev.max(q)));
        }
    }

    // A coding is acceptable iff its effective q (explicit, else wildcard) > 0.
    let acceptable =
        |explicit: Option<f32>| -> bool { matches!(explicit.or(star_q), Some(q) if q > 0.0) };

    for &enc in priority {
        let ok = match enc {
            Encoding::Zstd => acceptable(zstd_q),
            Encoding::Brotli => acceptable(br_q),
            Encoding::Gzip => acceptable(gzip_q),
        };
        if ok {
            return Some(enc);
        }
    }
    None
}

/// Split a single `Accept-Encoding` element into `(coding, q)`. A missing
/// `q=` parameter defaults to `1.0`; an unparseable q defaults to `1.0` as
/// well (be lenient on input, strict only on `q=0`).
fn parse_coding(part: &str) -> (&str, f32) {
    let mut iter = part.split(';');
    let coding = iter.next().unwrap_or("").trim();
    let mut q = 1.0_f32;
    for param in iter {
        let param = param.trim();
        if let Some(rest) = param
            .strip_prefix("q=")
            .or_else(|| param.strip_prefix("Q="))
        {
            q = rest.trim().parse::<f32>().unwrap_or(1.0).clamp(0.0, 1.0);
        }
    }
    (coding, q)
}

/// One-shot compress `input` with `enc` at the configured `levels`.
///
/// Returns `None` only if a codec genuinely fails (in practice only on
/// allocation failure for zstd), so the caller can leave the body uncompressed
/// instead of emitting a `Content-Encoding` that doesn't match the bytes.
pub fn encode_bytes(enc: Encoding, input: &[u8], levels: &Levels) -> Option<Vec<u8>> {
    match enc {
        Encoding::Gzip => Some(gzip_bytes_level(input, levels.gzip)),
        Encoding::Zstd => zstd_bytes_level(input, levels.zstd),
        Encoding::Brotli => Some(brotli_bytes(input, levels.brotli_q, levels.brotli_lgwin)),
    }
}

/// Maximum bytes decode_bytes will expand a compressed body to.
///
/// Set well above a realistic max cacheable object so normal content never
/// hits the cap, but a decompression bomb (gzip of zeros, etc.) from a
/// misbehaving upstream is stopped before it can exhaust both nodes' RAM.
/// The page-cache max_obj_bytes default is 512 KiB; 16 MiB gives ample
/// headroom for any legitimate object while keeping the worst-case allocation
/// bounded.
pub const MAX_DECODE: u64 = 16 * 1024 * 1024; // 16 MiB

/// Decompress a buffer encoded with `enc` back to identity bytes. Returns `None`
/// on malformed input or when the decompressed size would exceed [`MAX_DECODE`]
/// (so the caller can fall back to caching/serving the original encoded body
/// rather than allocating unbounded memory from a hostile upstream).
pub fn decode_bytes(enc: Encoding, input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let cap = MAX_DECODE;
    let initial = input.len().saturating_mul(3).max(64).min(cap as usize);
    let mut out = Vec::with_capacity(initial);
    match enc {
        Encoding::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(input).take(cap);
            decoder.read_to_end(&mut out).ok()?;
            // If we hit the cap, a full read_to_end can succeed but the body
            // is truncated. Re-check by attempting one more byte.
            if (out.len() as u64) == cap {
                return None;
            }
            Some(out)
        }
        Encoding::Brotli => {
            let mut decoder = brotli::Decompressor::new(input, 4096).take(cap);
            decoder.read_to_end(&mut out).ok()?;
            if (out.len() as u64) == cap {
                return None;
            }
            Some(out)
        }
        Encoding::Zstd => {
            // zstd::stream::read::Decoder implements Read; wrap with take() so
            // the decompressor never writes more than MAX_DECODE bytes.
            let mut reader = zstd::stream::read::Decoder::new(input).ok()?;
            // (L5) Cap the back-reference window the decoder will pre-allocate at 16 MiB
            // (2^24). Every caller feeds httpjet's OWN encoder output (trusted) and zstd's
            // default cap (2^27 = 128 MiB) already bounds it, so this is defense-in-depth
            // against a malformed frame declaring an outsized window.
            reader.window_log_max(24).ok()?;
            let mut decoder = reader.take(cap);
            decoder.read_to_end(&mut out).ok()?;
            if (out.len() as u64) == cap {
                return None;
            }
            Some(out)
        }
    }
}

/// Compress a buffer with gzip at the given compression level, returning the
/// gzip stream. Thin wrapper over `flate2` used by the buffered (`Body::Full`)
/// path and tests.
pub(crate) fn gzip_bytes_level(input: &[u8], level: u32) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut enc = GzEncoder::new(
        Vec::with_capacity(input.len() / 2 + 32),
        Compression::new(level),
    );
    // Writing to a Vec is infallible.
    let _ = enc.write_all(input);
    enc.finish().unwrap_or_default()
}

thread_local! {
    /// Per-thread reused zstd compression context. zstd's `bulk::Compressor`
    /// "re-uses the zstd context between jobs to avoid re-allocations", so the
    /// CCtx workspace (tens-to-hundreds of KiB at level 3) is allocated ONCE per
    /// worker thread instead of once per response. This is what removes the
    /// per-request allocation churn on the force-zstd egress path (the heavy-vhost
    /// concurrent-miss allocator contention). `compress()` is one-shot per call
    /// (zstd `compress2`, which resets the session), so the output is byte-identical
    /// to a fresh `zstd::bulk::compress` at the same level — verified by the
    /// `zstd_bytes_pooled_matches_oneshot` test. The level is (re)set per call
    /// because the pooled context outlives any single `Levels`.
    static ZSTD_CCTX: std::cell::RefCell<Option<zstd::bulk::Compressor<'static>>> =
        std::cell::RefCell::new(None);
}

/// Compress a buffer with zstd at the given level (1-22), reusing a per-thread
/// compression context (see [`ZSTD_CCTX`]) instead of allocating one per call.
/// Returns `None` if the compressor fails (allocation only, in practice).
pub(crate) fn zstd_bytes_level(input: &[u8], level: i32) -> Option<Vec<u8>> {
    ZSTD_CCTX.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(zstd::bulk::Compressor::new(level).ok()?);
        }
        let comp = slot.as_mut().expect("just initialized above");
        comp.set_compression_level(level).ok()?;
        comp.compress(input).ok()
    })
}

/// Compress a buffer with brotli at the given quality (0-11) and window log.
/// `CompressorWriter::into_inner` performs the brotli FINISH operation, so the
/// returned buffer is a complete, self-contained brotli stream.
pub(crate) fn brotli_bytes(input: &[u8], quality: u32, lgwin: u32) -> Vec<u8> {
    use brotli::CompressorWriter;
    use std::io::Write;

    let mut w = CompressorWriter::new(
        Vec::with_capacity(input.len() / 2 + 64),
        4096,
        quality,
        lgwin,
    );
    // Writing to a Vec sink is infallible.
    let _ = w.write_all(input);
    w.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    #[test]
    fn zstd_bytes_pooled_matches_oneshot() {
        // Stage-2 safety: the per-thread pooled Compressor must produce BYTE-IDENTICAL
        // output to a fresh `zstd::bulk::compress` (the old path) at the same level —
        // across sizes, levels, and repeated calls (which exercise context reuse) — and
        // round-trip back to identity. Wire-identical ⇒ this is a pure allocation win.
        let inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"User-agent: *\nDisallow:\n".to_vec(),
            vec![b'a'; 446],
            (0..5000u32).flat_map(|i| i.to_le_bytes()).collect(),
            b"the quick brown fox jumps over the lazy dog ".repeat(64),
        ];
        for level in [3i32, 9, 19] {
            for inp in &inputs {
                let pooled = zstd_bytes_level(inp, level).expect("pooled compress");
                let oneshot = zstd::bulk::compress(inp, level).expect("oneshot compress");
                assert_eq!(
                    pooled,
                    oneshot,
                    "pooled != oneshot (len {}, level {level})",
                    inp.len()
                );
                assert_eq!(
                    &decode_bytes(Encoding::Zstd, &pooled).expect("decode"),
                    inp,
                    "round-trip (len {}, level {level})",
                    inp.len()
                );
            }
        }
        // Many repeats on the same thread (context reuse) stay correct.
        for _ in 0..200 {
            let p = zstd_bytes_level(b"context-reuse-check", 3).unwrap();
            assert_eq!(
                decode_bytes(Encoding::Zstd, &p).unwrap(),
                b"context-reuse-check"
            );
        }
    }

    #[test]
    fn decode_bytes_round_trips_each_codec() {
        let data = b"identity payload that the page cache must recover ".repeat(40);
        let levels = Levels::default();
        for enc in [Encoding::Gzip, Encoding::Brotli, Encoding::Zstd] {
            let encoded = encode_bytes(enc, &data, &levels).expect("encode");
            let decoded = decode_bytes(enc, &encoded).expect("decode");
            assert_eq!(decoded, data, "{:?} round-trip", enc);
        }
        // Malformed input → None, not a panic.
        assert!(decode_bytes(Encoding::Gzip, b"not gzip").is_none());
        // Token parsing.
        assert_eq!(Encoding::from_token("gzip"), Some(Encoding::Gzip));
        assert_eq!(Encoding::from_token("br"), Some(Encoding::Brotli));
        assert_eq!(Encoding::from_token(" ZSTD "), Some(Encoding::Zstd));
        assert_eq!(Encoding::from_token("identity"), None);
        assert_eq!(Encoding::from_token("gzip, br"), None);
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut d = GzDecoder::new(data);
        let mut out = Vec::new();
        d.read_to_end(&mut out).unwrap();
        out
    }

    fn unzstd(data: &[u8]) -> Vec<u8> {
        zstd::decode_all(data).unwrap()
    }

    fn unbrotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        brotli::Decompressor::new(data, 4096)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn token_strings() {
        assert_eq!(Encoding::Zstd.token(), "zstd");
        assert_eq!(Encoding::Brotli.token(), "br");
        assert_eq!(Encoding::Gzip.token(), "gzip");
    }

    #[test]
    fn gzip_round_trips() {
        let original = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let comp = gzip_bytes_level(&original, 6);
        assert!(
            comp.len() < original.len(),
            "expected compression to shrink data"
        );
        assert_eq!(gunzip(&comp), original);
    }

    #[test]
    fn zstd_round_trips() {
        let original = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let comp = zstd_bytes_level(&original, 3).expect("zstd compress");
        assert!(
            comp.len() < original.len(),
            "expected compression to shrink data"
        );
        assert_eq!(unzstd(&comp), original);
    }

    #[test]
    fn brotli_round_trips() {
        let original = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let comp = brotli_bytes(&original, 5, 22);
        assert!(
            comp.len() < original.len(),
            "expected compression to shrink data"
        );
        assert_eq!(unbrotli(&comp), original);
    }

    #[test]
    fn brotli_lgwin_default_is_19() {
        // 512 KiB window: enough for 20-80 KB dynamic pages, avoids oversized
        // per-stream encoder state (matches Pingora). See CMP2.
        assert_eq!(Levels::default().brotli_lgwin, 19);
    }

    #[test]
    fn encode_bytes_dispatches_each_codec() {
        let original = b"abcabcabc repeated content for compression".repeat(10);
        let lv = Levels::default();
        assert_eq!(
            unzstd(&encode_bytes(Encoding::Zstd, &original, &lv).unwrap()),
            original
        );
        assert_eq!(
            unbrotli(&encode_bytes(Encoding::Brotli, &original, &lv).unwrap()),
            original
        );
        assert_eq!(
            gunzip(&encode_bytes(Encoding::Gzip, &original, &lv).unwrap()),
            original
        );
    }

    // --- negotiation -------------------------------------------------------

    #[test]
    fn negotiate_respects_custom_priority() {
        // gzip-first priority forces gzip even when zstd/br are offered.
        assert_eq!(
            negotiate_with("gzip, br, zstd", &[Encoding::Gzip]),
            Some(Encoding::Gzip)
        );
        assert_eq!(
            negotiate_with("gzip, zstd", &[Encoding::Gzip, Encoding::Zstd]),
            Some(Encoding::Gzip)
        );
        // A priority list that omits the only offered coding -> None.
        assert_eq!(
            negotiate_with("gzip", &[Encoding::Zstd, Encoding::Brotli]),
            None
        );
    }
}
