//! hj-compress — response compression for httpjet.
//!
//! Implements multi-codec response compression as a [`hj_core::ResponseTransform`].
//! Supported codings, preferred in order: zstd (RFC 8878) > brotli (RFC 7932) >
//! gzip (RFC 1952). The negotiator picks the highest-priority coding the client
//! advertises; codecs are individually enable-able via server tuning.
//!
//! The transform is applied by the pipeline *after* the terminal handler has
//! produced a [`Response`]. It decides whether to compress based on:
//!
//! 1. The client `Accept-Encoding` (q-values honored, `identity;q=0` etc.).
//! 2. The response `Content-Type` being in a configurable *compressible set*.
//!    The default set is LiteSpeed/OLS's `compressibleTypes=default` list
//!    verbatim (`text/*`, `application/x-javascript`, `application/javascript`,
//!    `application/xml`, `image/svg+xml`, `application/rss+xml`,
//!    `application/json`, the `application/x-font*` and `font/*` families,
//!    `image/x-icon`, `image/vnd.microsoft.icon`, `application/xhtml+xml`).
//! 3. The body being above a minimum size — default 201 bytes, matching OLS's
//!    `getContentLen() > 200` gate.
//! 4. The response not already carrying a `Content-Encoding`.
//! 5. The response not being an SSE stream (`text/event-stream`).
//! 6. The response not being a `Range` / `206 Partial Content` response.
//!
//! When all gates pass it:
//! - compresses [`Body::Full`] in one shot via [`encode_bytes`];
//! - wraps [`Body::Stream`] with an incremental [`stream::CompressStream`];
//! - for [`Body::File`], an in-memory (`cached`) file body is buffered-compressed,
//!   while a non-cached, non-ranged file is left to the zero-copy / sendfile
//!   static path (a precompressed sibling already carrying a `Content-Encoding`
//!   is left untouched by the no-double-encode gate);
//! - always adds `Vary: Accept-Encoding`, sets `Content-Encoding` to the chosen
//!   coding, tags the strong-ETag variant slot (`;gz`/`;br`/`;zs`), and for
//!   streamed output removes `Content-Length` (length becomes unknown).
//!
//! ## Usage by the orchestrator
//!
//! ```text
//! use hj_compress::Compress;
//! // From server tuning (respects `enable_gzip` / `enable_dyn_gzip`):
//! let compress = Compress::from_tuning(&server.tuning);
//! ```
//!
//! Because [`ResponseTransform::transform`] only receives `&ReqCtx` (not the
//! request), the orchestrator must surface the client's `Accept-Encoding` to
//! the transform. By convention it is placed in the request env under
//! [`ACCEPT_ENCODING_ENV`] (`"HTTP_ACCEPT_ENCODING"`, the CGI-style name). The
//! transform reads it via [`ReqCtx::get_env`].

pub mod dict;
mod encoding;
pub mod expires;
mod stream;

use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use http::header::{
    ACCEPT_ENCODING, ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    ETAG, HeaderValue, TRANSFER_ENCODING, VARY,
};

use hj_core::config::Tuning;
use hj_core::{Body, ReqCtx, Response, ResponseTransform};

pub use dict::{DEFAULT_DICT_LEVEL, PageDict, PageDictRegistry};
pub use encoding::{
    AcceptEncoding, DEFAULT_PRIORITY, Encoding, Levels, MAX_DECODE, decode_bytes, encode_bytes,
    negotiate_with,
};
pub use expires::{ExpiresBase, ExpiresHeaders, ExpiresRule, ExpiresRules};
pub(crate) use stream::CompressStream;

/// The request-env key under which the pipeline stores the client's
/// `Accept-Encoding` header so this transform (which only sees `&ReqCtx`) can
/// negotiate. CGI-style name to match how other env values are carried.
pub const ACCEPT_ENCODING_ENV: &str = "HTTP_ACCEPT_ENCODING";

/// Default minimum body size (bytes) at or above which compression is applied.
///
/// Ground truth: OLS gates dynamic gzip on `m_response.getContentLen() > 200`
/// (src/http/httpsession.cpp:5842) — i.e. the body must be strictly larger than
/// 200 bytes, so the smallest compressed body is 201 bytes. httpjet's gate is
/// `len >= DEFAULT_MIN_SIZE`, so 201 reproduces OLS's `> 200` exactly.
pub const DEFAULT_MIN_SIZE: u64 = 201;

/// Default gzip compression level (flate2 0-9). 6 is zlib's default and a good
/// size/CPU tradeoff for on-the-fly compression.
pub(crate) const DEFAULT_LEVEL: u32 = 6;

/// Response compression transform.
///
/// Holds only configuration, so it is cheap to share behind an `Arc` from the
/// orchestrator.
pub struct Compress {
    /// Compressible content-type matchers (exact types and `type/*` prefixes).
    compressible: CompressibleSet,
    /// Minimum body length to bother compressing.
    min_size: u64,
    /// gzip level 0-9.
    level: u32,
    /// zstd level 1-22.
    zstd_level: i32,
    /// brotli quality 0-11.
    brotli_q: u32,
    /// brotli window log.
    brotli_lgwin: u32,
    /// Master switch (true when at least one codec is enabled).
    enabled: bool,
    /// Whether to compress dynamic (streamed/file) gzip bodies (mirrors
    /// `enable_dyn_gzip`).
    enable_stream: bool,
    /// Whether to compress dynamic bodies with zstd (mirrors `enable_dyn_zstd`).
    enable_dyn_zstd: bool,
    /// Whether to compress dynamic bodies with brotli (mirrors `enable_dyn_brotli`).
    enable_dyn_brotli: bool,
    /// Server codec preference, best first, filtered to the enabled codecs.
    priority: Vec<Encoding>,
    /// (CF_SEND_ZSTD) When true, responses to a **trusted proxy** peer (Cloudflare —
    /// the only way real traffic reaches the origin) are compressed as **zstd**
    /// regardless of the forwarded `Accept-Encoding`. CF requests `br,gzip` from the
    /// origin but decodes an origin `Content-Encoding: zstd` and re-encodes per client
    /// at its edge — so this hands CF the cheapest-to-produce form (zstd compresses far
    /// faster than brotli) without affecting what browsers receive. Officially
    /// unsupported CF↔origin; opt-in + default off. Never fires for untrusted (direct)
    /// clients, so a non-CF browser can't be handed an unrequested zstd body.
    cf_send_zstd: bool,
}

impl Default for Compress {
    fn default() -> Self {
        let lv = Levels::default();
        Compress {
            compressible: CompressibleSet::default(),
            min_size: DEFAULT_MIN_SIZE,
            level: DEFAULT_LEVEL,
            zstd_level: lv.zstd,
            brotli_q: lv.brotli_q,
            brotli_lgwin: lv.brotli_lgwin,
            enabled: true,
            enable_stream: true,
            enable_dyn_zstd: true,
            enable_dyn_brotli: true,
            priority: DEFAULT_PRIORITY.to_vec(),
            cf_send_zstd: false,
        }
    }
}

impl Compress {
    /// Build with the default compressible set and tuning.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from server [`Tuning`]. The per-codec `enable_*` flags select which
    /// codings are offered (and in what residual priority); the `enable_dyn_*`
    /// flags control whether streamed/dynamic bodies are compressed per codec;
    /// `zstd_level` / `brotli_quality` set the levels.
    pub fn from_tuning(tuning: &Tuning) -> Self {
        let priority: Vec<Encoding> = DEFAULT_PRIORITY
            .iter()
            .copied()
            .filter(|e| match e {
                Encoding::Zstd => tuning.enable_zstd,
                Encoding::Brotli => tuning.enable_brotli,
                Encoding::Gzip => tuning.enable_gzip,
            })
            .collect();
        Compress {
            enabled: !priority.is_empty(),
            enable_stream: tuning.enable_dyn_gzip,
            enable_dyn_zstd: tuning.enable_dyn_zstd,
            enable_dyn_brotli: tuning.enable_dyn_brotli,
            zstd_level: tuning.zstd_level as i32,
            brotli_q: tuning.brotli_quality,
            priority,
            ..Self::default()
        }
    }

    /// The per-codec levels this transform was configured with.
    fn levels(&self) -> Levels {
        Levels {
            gzip: self.level,
            zstd: self.zstd_level,
            brotli_q: self.brotli_q,
            brotli_lgwin: self.brotli_lgwin,
        }
    }

    /// (CF_SEND_ZSTD) Enable forcing zstd egress to trusted-proxy (Cloudflare) peers.
    pub fn with_cf_send_zstd(mut self, on: bool) -> Self {
        self.cf_send_zstd = on;
        self
    }

    /// Whether CF_SEND_ZSTD is enabled (consulted by the page cache so its stored
    /// variant + served encoding agree with the transform for CF peers).
    pub fn cf_send_zstd(&self) -> bool {
        self.cf_send_zstd
    }

    /// Whether a given content-type is considered compressible.
    pub fn is_compressible_type(&self, content_type: &str) -> bool {
        self.compressible.matches(content_type)
    }

    /// Decide whether `resp` should be gzip-compressed given the client's
    /// `accept_encoding`. Returns the chosen [`Encoding`] when it should be,
    /// `None` to leave the response as-is. Pure / no mutation, so it is unit
    /// testable in isolation.
    pub fn should_compress(&self, resp: &Response, accept_encoding: &str) -> Option<Encoding> {
        if !self.enabled {
            return None;
        }

        // Never double-encode. Checked BEFORE negotiation so a precompressed page-cache
        // hit (Content-Encoding already present — the prod-dominant shape) never pays an
        // Accept-Encoding parse just to no-op.
        if resp.headers().contains_key(CONTENT_ENCODING) {
            return None;
        }

        // Partial responses / range responses must not be transformed.
        if resp.status() == StatusCode::PARTIAL_CONTENT {
            return None;
        }
        // No body to compress.
        if matches!(
            resp.status(),
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        ) {
            return None;
        }
        if resp.headers().contains_key(http::header::CONTENT_RANGE) {
            return None;
        }

        // Content-Type gating (defaults compress text-ish types only).
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Explicitly never compress server-sent events.
        if ct_base(ct).eq_ignore_ascii_case("text/event-stream") {
            return None;
        }
        if !self.compressible.matches(ct) {
            return None;
        }

        // Client negotiation (server priority, bounded by what the client accepts) LAST:
        // the most expensive gate, reached only for compressible uncached bodies.
        let enc = negotiate_with(accept_encoding, &self.priority)?;

        // Honor `Cache-Control: no-transform` (RFC 9111 §5.2.2.6).
        // Scan ALL Cache-Control header lines (a proxied upstream may split
        // directives across multiple lines; get() only sees the first).
        if resp.headers().get_all(CACHE_CONTROL).iter().any(|v| {
            v.to_str().map_or(false, |s| {
                s.split(',')
                    .any(|d| d.trim().eq_ignore_ascii_case("no-transform"))
            })
        }) {
            return None;
        }

        // Per-codec gate for dynamic (streamed / cached-file) bodies. Note: the
        // codec is chosen by priority first, then this gate is applied — so
        // disabling a high-priority codec's dynamic path does not silently fall
        // back to a lower one for streamed bodies.
        let dyn_ok = match enc {
            Encoding::Gzip => self.enable_stream,
            Encoding::Zstd => self.enable_dyn_zstd,
            Encoding::Brotli => self.enable_dyn_brotli,
        };

        // Size + body-kind gating.
        match resp.body() {
            Body::Empty => None,
            Body::Full(b) => ((b.len() as u64) >= self.min_size).then_some(enc),
            Body::Stream(_) => dyn_ok.then_some(enc),
            Body::File(f) => {
                if !dyn_ok {
                    return None;
                }
                if f.content_len() < self.min_size {
                    return None;
                }
                // Ranged files would break with whole-stream compression; and
                // we only act on cached (in-memory) bytes — a non-cached file
                // is left to the zero-copy/sendfile static path.
                if f.range.is_some() {
                    return None;
                }
                f.cached.is_some().then_some(enc)
            }
        }
    }

    /// Apply compression to `resp` in place with the chosen `enc`. Assumes
    /// [`Self::should_compress`] already approved it. Sets headers and rewrites
    /// the body. If a codec genuinely fails (zstd allocation only, in practice),
    /// the body is restored and no headers are changed.
    fn apply(&self, resp: &mut Response, enc: Encoding) {
        let levels = self.levels();

        // Swap the body out so we can transform it.
        let body = std::mem::replace(resp.body_mut(), Body::Empty);

        let new_body = match body {
            Body::Full(b) => match encode_bytes(enc, &b, &levels) {
                Some(c) => Body::Full(Bytes::from(c)),
                None => {
                    *resp.body_mut() = Body::Full(b);
                    return;
                }
            },
            Body::Stream(s) => {
                resp.headers_mut().remove(CONTENT_LENGTH);
                Body::Stream(CompressStream::new(s, enc, &levels).boxed_stream())
            }
            Body::File(f) => match &f.cached {
                // Only reached when cached bytes exist (see should_compress).
                Some(bytes) => match encode_bytes(enc, bytes.as_ref(), &levels) {
                    Some(c) => Body::Full(Bytes::from(c)),
                    None => {
                        *resp.body_mut() = Body::File(f);
                        return;
                    }
                },
                None => Body::File(f),
            },
            other => other,
        };

        let streamed = matches!(new_body, Body::Stream(_));
        *resp.body_mut() = new_body;

        // Set Content-Encoding to the negotiated coding.
        resp.headers_mut()
            .insert(CONTENT_ENCODING, HeaderValue::from_static(enc.token()));

        // Distinguish this representation in the (strong) ETag variant slot.
        tag_etag_variant(resp, enc);

        // Fix up Content-Length for buffered output; drop it for streamed.
        if streamed {
            resp.headers_mut().remove(CONTENT_LENGTH);
        } else if let Some(len) = resp.body().content_length() {
            match HeaderValue::from_str(&len.to_string()) {
                Ok(hv) => {
                    resp.headers_mut().insert(CONTENT_LENGTH, hv);
                }
                Err(_) => {
                    resp.headers_mut().remove(CONTENT_LENGTH);
                }
            }
        }

        // A transformed body invalidates any chunked TE header from upstream;
        // let the transport re-derive framing.
        resp.headers_mut().remove(TRANSFER_ENCODING);

        // RFC 9110 §14.3: byte ranges address the *selected representation*. Once
        // we change the Content-Encoding the on-disk byte offsets no longer match
        // what the client received, so a subsequent `Range` request (which the
        // static handler would serve from the *uncompressed* file) yields a corrupt
        // resume. hj-static stamps `Accept-Ranges: bytes` on every 200; drop it on
        // the compressed representation so clients don't attempt range resumption.
        resp.headers_mut().remove(ACCEPT_RANGES);

        add_vary_accept_encoding(resp);
    }

    /// Read the client `Accept-Encoding` from the request env (CGI-style key),
    /// falling back to lower-case / canonical header-name keys the pipeline may
    /// have used.
    fn accept_encoding<'a>(&self, ctx: &'a ReqCtx) -> &'a str {
        ctx.get_env(ACCEPT_ENCODING_ENV)
            .or_else(|| ctx.get_env("accept-encoding"))
            .or_else(|| ctx.get_env(ACCEPT_ENCODING.as_str()))
            .unwrap_or("")
    }
}

#[async_trait]
impl ResponseTransform for Compress {
    async fn transform(&self, ctx: &ReqCtx, resp: &mut Response) {
        // (CF_SEND_ZSTD) For a trusted-proxy peer, ignore the forwarded Accept-Encoding and
        // negotiate as if the client sent `zstd` — CF decodes our zstd and re-encodes per
        // browser at its edge, and zstd is the cheapest form for us to produce. Untrusted
        // (direct) clients are never affected, so no browser is handed an unrequested encoding.
        //
        // PRECONDITION (operator contract): enabling `cf_send_zstd` asserts that EVERY trusted
        // proxy (`<accessControl>` `T`-tagged CIDR) speaks zstd — there is no CF-specific signal
        // at this layer, only `ctx.trusted_proxy`. Today Cloudflare is the sole trusted proxy, so
        // this holds; if a non-zstd trusted proxy is ever added to the trust list while this flag
        // is on, it too would receive zstd. Gate that case by NOT setting CF_SEND_ZSTD (or by
        // introducing a separate CF-range list) rather than relying on this transform.
        let accept = if self.cf_send_zstd && ctx.trusted_proxy {
            "zstd"
        } else {
            self.accept_encoding(ctx)
        };
        if let Some(enc) = self.should_compress(resp, accept) {
            self.apply(resp, enc);
            tracing::trace!(vhost = %ctx.vhost_name, codec = enc.token(), "compressed response");
        }
        // NOTE on Vary: OLS adds `Vary: Accept-Encoding` *only* when it actually
        // gzip-encodes the body — it is bundled into `addGzipEncodingHeader`,
        // which emits the pair `Content-Encoding: gzip\r\nVary: Accept-Encoding`
        // (src/http/httprespheaders.cpp:56,197). OLS does NOT add a speculative
        // `Vary: Accept-Encoding` on uncompressed-but-compressible responses, so
        // neither do we — the Vary is added inside `apply()` along with the
        // Content-Encoding, matching the production server exactly.
    }
}

/// Insert `Vary: Accept-Encoding`, merging with any existing `Vary` value
/// rather than clobbering it (e.g. stacking on a vhost's `Vary: Cookie`).
fn add_vary_accept_encoding(resp: &mut Response) {
    let headers = resp.headers_mut();
    // Already present (case-insensitive token search across all Vary values)?
    let already = headers.get_all(VARY).iter().any(|v| {
        v.to_str()
            .map(|s| {
                s.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("accept-encoding"))
            })
            .unwrap_or(false)
    });
    if already {
        return;
    }
    // (#12) Merge into a single line ONLY when there is exactly one existing Vary
    // line — `insert` REPLACES all values, so the old "get(VARY) first value +
    // insert" path silently dropped any further Vary lines (e.g. `Vary: User-Agent`
    // after `Vary: Cookie`). With 0 or 2+ existing lines, append a fresh line
    // instead (multiple Vary lines are valid and combine per RFC 9110).
    if headers.get_all(VARY).iter().count() == 1 {
        if let Some(existing) = headers.get(VARY).and_then(|v| v.to_str().ok()) {
            let merged = format!("{existing}, Accept-Encoding");
            if let Ok(hv) = HeaderValue::from_str(&merged) {
                headers.insert(VARY, hv);
                return;
            }
        }
    }
    headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
}

/// Mark the content-coding in the strong ETag's reserved variant slot, mirroring
/// OpenLiteSpeed: a base ETag ends with three reserved `;` slots before the
/// closing quote (`"<core>;;;"`), and the two chars before the quote are
/// overwritten with the codec marker — `;gz` (gzip), `;br` (brotli), or `;zs`
/// (zstd, an httpjet extension; LiteSpeed has no zstd). This keeps compressed and
/// uncompressed representations from sharing a strong validator (RFC 9110), while
/// preserving ETag *strength* (so `If-Range` resume still works). Only an ETag in
/// the exact `...;;;"` shape we generate is touched; foreign strong ETags are
/// dropped because the compressed representation cannot share their validator.
fn tag_etag_variant(resp: &mut Response, enc: Encoding) {
    let marker: &[u8] = match enc {
        Encoding::Gzip => b"gz",
        Encoding::Brotli => b"br",
        Encoding::Zstd => b"zs",
    };
    let Some(etag) = resp.headers().get(ETAG) else {
        return;
    };
    let bytes = etag.as_bytes();
    let n = bytes.len();
    // Require the reserved `;;;"` suffix; otherwise remove foreign STRONG ETags
    // so identity and compressed representations never share one validator.
    if n < 4
        || bytes[n - 1] != b'"'
        || bytes[n - 2] != b';'
        || bytes[n - 3] != b';'
        || bytes[n - 4] != b';'
    {
        if !(n >= 2 && bytes[0].eq_ignore_ascii_case(&b'w') && bytes[1] == b'/') {
            resp.headers_mut().remove(ETAG);
        }
        return;
    }
    // `"<core>;;;"` -> `"<core>;<marker>"` (keeps the first slot, fills the rest).
    let mut new = Vec::with_capacity(n);
    new.extend_from_slice(&bytes[..n - 3]);
    new.extend_from_slice(marker);
    new.push(b'"');
    if let Ok(hv) = HeaderValue::from_bytes(&new) {
        resp.headers_mut().insert(ETAG, hv);
    }
}

/// Strip any `;`-delimited parameter and surrounding whitespace from a
/// content-type (callers compare case-insensitively).
fn ct_base(ct: &str) -> &str {
    ct.split(';').next().unwrap_or("").trim()
}

/// Convenience for [`hj_core::FileBody`]: effective served length.
trait FileLenExt {
    fn content_len(&self) -> u64;
}
impl FileLenExt for hj_core::FileBody {
    fn content_len(&self) -> u64 {
        match self.range {
            Some((s, e)) => e.saturating_sub(s) + 1,
            None => self.len,
        }
    }
}

/// The set of content-types eligible for compression.
#[derive(Debug, Clone)]
struct CompressibleSet {
    /// Exact `type/subtype` entries (lowercased).
    exact: Vec<String>,
    /// `type/*` prefixes stored as `type/` (lowercased).
    prefixes: Vec<String>,
    /// `*` matches everything.
    any: bool,
}

impl Default for CompressibleSet {
    fn default() -> Self {
        // The EXACT `compressibleTypes=default` set used by LiteSpeed / OLS.
        //
        // Ground truth: OLS `HttpMime::setDefaultCompressibleType`
        // (src/http/httpmime.cpp:949-962). This list is reproduced verbatim
        // (it is an uncopyrightable set of MIME-type facts) so httpjet gzips
        // exactly the types the production server does — no more, no less.
        // Notably this means `font/woff`/`font/woff2` are NOT compressed (they
        // are already compressed) and structured types OLS omits — e.g.
        // `application/atom+xml`, `application/ld+json`,
        // `application/manifest+json`, `application/wasm` — are NOT in the
        // default set either.
        //
        // text/css and text/event-stream fall under `text/*`; event-stream is
        // explicitly excluded at the gating call site (see `should_compress`).
        CompressibleSet::from_types([
            "text/*",
            "application/x-javascript",
            "application/javascript",
            "application/xml",
            "image/svg+xml",
            "application/rss+xml",
            "application/json",
            "application/vnd.ms-fontobject",
            "application/x-font",
            "application/x-font-opentype",
            "application/x-font-truetype",
            "application/x-font-ttf",
            "font/eot",
            "font/opentype",
            "font/otf",
            "font/ttf",
            "image/x-icon",
            "image/vnd.microsoft.icon",
            "application/xhtml+xml",
        ])
    }
}

impl CompressibleSet {
    fn from_types<I, S>(types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut exact = Vec::new();
        let mut prefixes = Vec::new();
        let mut any = false;
        for t in types {
            let t = t.into().trim().to_ascii_lowercase();
            if t.is_empty() {
                continue;
            }
            if t == "*" || t == "*/*" {
                any = true;
            } else if let Some(prefix) = t.strip_suffix("/*") {
                prefixes.push(format!("{prefix}/"));
            } else {
                exact.push(t);
            }
        }
        CompressibleSet {
            exact,
            prefixes,
            any,
        }
    }

    /// Does `content_type` (possibly with parameters) match the set?
    fn matches(&self, content_type: &str) -> bool {
        if self.any {
            return true;
        }
        // Allocation-free: set entries are lowercased at construction, so compare the
        // borrowed (possibly mixed-case) base with ascii-case-insensitive equality.
        let base = ct_base(content_type);
        if base.is_empty() {
            return false;
        }
        if self.exact.iter().any(|t| t.eq_ignore_ascii_case(base)) {
            return true;
        }
        self.prefixes.iter().any(|p| {
            base.len() >= p.len()
                && p.as_bytes()
                    .eq_ignore_ascii_case(&base.as_bytes()[..p.len()])
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

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

    fn resp_with(ct: &str, body: Vec<u8>) -> Response {
        let mut r = http::Response::new(Body::Full(Bytes::from(body)));
        r.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
        r
    }

    #[test]
    fn add_vary_preserves_multiple_existing_lines() {
        // (#12) Two distinct Vary lines must BOTH survive when Accept-Encoding is
        // added (the old get+insert path dropped all but the first).
        let mut r = resp_with("text/html", b"x".to_vec());
        r.headers_mut()
            .append(VARY, HeaderValue::from_static("Cookie"));
        r.headers_mut()
            .append(VARY, HeaderValue::from_static("User-Agent"));
        add_vary_accept_encoding(&mut r);
        let toks: Vec<String> = r
            .headers()
            .get_all(VARY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(',').map(|t| t.trim().to_ascii_lowercase()))
            .collect();
        assert!(
            toks.contains(&"cookie".to_string()),
            "Cookie dropped: {toks:?}"
        );
        assert!(
            toks.contains(&"user-agent".to_string()),
            "User-Agent dropped: {toks:?}"
        );
        assert!(
            toks.contains(&"accept-encoding".to_string()),
            "Accept-Encoding missing: {toks:?}"
        );
    }

    #[test]
    fn add_vary_single_line_still_merges() {
        // The common single-Vary case still merges into one line (unchanged).
        let mut r = resp_with("text/html", b"x".to_vec());
        r.headers_mut()
            .append(VARY, HeaderValue::from_static("Cookie"));
        add_vary_accept_encoding(&mut r);
        assert_eq!(r.headers().get_all(VARY).iter().count(), 1);
        assert_eq!(r.headers().get(VARY).unwrap(), "Cookie, Accept-Encoding");
    }

    #[test]
    fn type_gating_compress_text_html() {
        let c = Compress::new();
        let r = resp_with("text/html; charset=utf-8", b"x".repeat(1000));
        assert_eq!(c.should_compress(&r, "gzip"), Some(Encoding::Gzip));
    }

    #[test]
    fn type_gating_skip_image_png() {
        let c = Compress::new();
        let r = resp_with("image/png", b"x".repeat(1000));
        assert_eq!(c.should_compress(&r, "gzip"), None);
    }

    #[test]
    fn type_gating_skip_event_stream() {
        let c = Compress::new();
        let r = resp_with("text/event-stream", b"data: hi\n\n".repeat(100));
        assert_eq!(c.should_compress(&r, "gzip"), None);
    }

    #[test]
    fn skips_small_bodies() {
        let c = Compress::new();
        let r = resp_with("text/plain", b"tiny".to_vec());
        assert_eq!(c.should_compress(&r, "gzip"), None);
    }

    #[test]
    fn min_size_threshold_matches_ols() {
        // OLS gates on `getContentLen() > 200`: 200 bytes is NOT compressed,
        // 201 bytes IS. DEFAULT_MIN_SIZE == 201 reproduces this with `>=`.
        let c = Compress::new();
        assert_eq!(DEFAULT_MIN_SIZE, 201);

        let r200 = resp_with("text/html", vec![b'x'; 200]);
        assert_eq!(c.should_compress(&r200, "gzip"), None, "200 bytes: skip");

        let r201 = resp_with("text/html", vec![b'x'; 201]);
        assert_eq!(
            c.should_compress(&r201, "gzip"),
            Some(Encoding::Gzip),
            "201 bytes: compress"
        );
    }

    #[test]
    fn skips_when_no_codec_accepted() {
        let c = Compress::new();
        let r = resp_with("text/html", b"x".repeat(1000));
        // No supported coding advertised.
        assert_eq!(c.should_compress(&r, "deflate"), None);
        assert_eq!(c.should_compress(&r, "identity"), None);
        // Every supported coding explicitly refused.
        assert_eq!(c.should_compress(&r, "gzip;q=0, br;q=0, zstd;q=0"), None);
        assert_eq!(c.should_compress(&r, "gzip;q=0"), None);
    }

    #[test]
    fn skips_already_encoded() {
        let c = Compress::new();
        let mut r = resp_with("text/html", b"x".repeat(1000));
        r.headers_mut()
            .insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
        assert_eq!(c.should_compress(&r, "gzip"), None);
    }

    #[test]
    fn skips_partial_content() {
        let c = Compress::new();
        let mut r = resp_with("text/html", b"x".repeat(1000));
        *r.status_mut() = StatusCode::PARTIAL_CONTENT;
        assert_eq!(c.should_compress(&r, "gzip"), None);
    }

    #[test]
    fn skips_content_range() {
        let c = Compress::new();
        let mut r = resp_with("text/html", b"x".repeat(1000));
        r.headers_mut().insert(
            http::header::CONTENT_RANGE,
            HeaderValue::from_static("bytes 0-999/5000"),
        );
        assert_eq!(c.should_compress(&r, "gzip"), None);
    }

    #[test]
    fn skips_no_transform() {
        let c = Compress::new();
        let mut r = resp_with("text/html", b"x".repeat(1000));
        r.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_static("private, no-transform"),
        );
        assert_eq!(c.should_compress(&r, "gzip"), None);
    }

    #[test]
    fn disabled_by_tuning() {
        let tuning = Tuning {
            enable_gzip: false,
            ..Tuning::default()
        };
        let c = Compress::from_tuning(&tuning);
        let r = resp_with("text/html", b"x".repeat(1000));
        assert_eq!(c.should_compress(&r, "gzip"), None);
    }

    #[test]
    fn dyn_gzip_off_still_compresses_full() {
        let tuning = Tuning {
            enable_dyn_gzip: false,
            ..Tuning::default()
        };
        let c = Compress::from_tuning(&tuning);
        let r = resp_with("text/html", b"x".repeat(1000));
        // Full (already-buffered) bodies still compress.
        assert_eq!(c.should_compress(&r, "gzip"), Some(Encoding::Gzip));
    }

    #[test]
    fn apply_sets_headers_and_compresses() {
        let c = Compress::new();
        let original = b"hello ".repeat(200);
        let mut r = resp_with("text/html", original.clone());
        let enc = c.should_compress(&r, "gzip").unwrap();
        assert_eq!(enc, Encoding::Gzip);
        c.apply(&mut r, enc);

        assert_eq!(
            r.headers().get(CONTENT_ENCODING).unwrap(),
            HeaderValue::from_static("gzip")
        );
        assert!(r.headers().get_all(VARY).iter().any(|v| {
            v.to_str()
                .unwrap()
                .to_ascii_lowercase()
                .contains("accept-encoding")
        }));
        match r.body() {
            Body::Full(b) => {
                let cl: u64 = r
                    .headers()
                    .get(CONTENT_LENGTH)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(cl, b.len() as u64);
                assert_eq!(gunzip(b), original);
            }
            _ => panic!("expected Full body"),
        }
    }

    #[test]
    fn vary_merges_with_existing() {
        let mut r = resp_with("text/html", b"x".repeat(1000));
        r.headers_mut()
            .insert(VARY, HeaderValue::from_static("Cookie"));
        add_vary_accept_encoding(&mut r);
        let merged = r.headers().get(VARY).unwrap().to_str().unwrap();
        assert!(merged.to_ascii_lowercase().contains("cookie"));
        assert!(merged.to_ascii_lowercase().contains("accept-encoding"));
        // Idempotent.
        add_vary_accept_encoding(&mut r);
        let count = r
            .headers()
            .get_all(VARY)
            .iter()
            .filter(|v| {
                v.to_str()
                    .unwrap()
                    .to_ascii_lowercase()
                    .contains("accept-encoding")
            })
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn compressible_set_defaults() {
        let s = CompressibleSet::default();
        // text/* prefix (covers html, css, plain, javascript, xml, ...).
        assert!(s.matches("text/html"));
        assert!(s.matches("text/css"));
        assert!(s.matches("text/plain; charset=utf-8"));
        assert!(s.matches("text/javascript"));
        // Exact application types in the OLS default set.
        assert!(s.matches("application/json"));
        assert!(s.matches("application/javascript"));
        assert!(s.matches("application/x-javascript"));
        assert!(s.matches("application/xml"));
        assert!(s.matches("application/xhtml+xml"));
        assert!(s.matches("application/rss+xml"));
        assert!(s.matches("application/vnd.ms-fontobject"));
        // Font types in the OLS default set.
        assert!(s.matches("application/x-font"));
        assert!(s.matches("application/x-font-opentype"));
        assert!(s.matches("application/x-font-truetype"));
        assert!(s.matches("application/x-font-ttf"));
        assert!(s.matches("font/eot"));
        assert!(s.matches("font/opentype"));
        assert!(s.matches("font/otf"));
        assert!(s.matches("font/ttf"));
        // Image types in the OLS default set.
        assert!(s.matches("image/svg+xml"));
        assert!(s.matches("image/x-icon"));
        assert!(s.matches("image/vnd.microsoft.icon"));

        // NOT in the OLS default set — must be left uncompressed.
        assert!(!s.matches("font/woff")); // already compressed
        assert!(!s.matches("font/woff2")); // already compressed
        assert!(!s.matches("image/png"));
        assert!(!s.matches("image/jpeg"));
        assert!(!s.matches("application/octet-stream"));
        // OLS deliberately omits these structured/binary types from `default`.
        assert!(!s.matches("application/atom+xml"));
        assert!(!s.matches("application/ld+json"));
        assert!(!s.matches("application/manifest+json"));
        assert!(!s.matches("application/wasm"));
        assert!(!s.matches(""));
    }

    /// Lock in the EXACT OLS `compressibleTypes=default` membership, type by
    /// type, against the ground-truth list from httpmime.cpp:952-960.
    #[test]
    fn compressible_set_matches_ols_default_exactly() {
        let c = Compress::new();
        // The full OLS default set — every entry must be compressible.
        let ols_default = [
            "text/html",
            "text/css",
            "text/plain",
            "application/x-javascript",
            "application/javascript",
            "application/xml",
            "image/svg+xml",
            "application/rss+xml",
            "application/json",
            "application/vnd.ms-fontobject",
            "application/x-font",
            "application/x-font-opentype",
            "application/x-font-truetype",
            "application/x-font-ttf",
            "font/eot",
            "font/opentype",
            "font/otf",
            "font/ttf",
            "image/x-icon",
            "image/vnd.microsoft.icon",
            "application/xhtml+xml",
        ];
        for ct in ols_default {
            assert!(
                c.is_compressible_type(ct),
                "OLS default set should compress {ct}"
            );
        }
        // Case-insensitivity and charset-parameter tolerance.
        assert!(c.is_compressible_type("Application/JSON"));
        assert!(c.is_compressible_type("application/json; charset=utf-8"));
    }

    #[test]
    fn should_compress_negotiates_by_priority() {
        let c = Compress::new();
        let r = resp_with("text/html", b"x".repeat(1000));
        assert_eq!(
            c.should_compress(&r, "gzip, deflate, br, zstd"),
            Some(Encoding::Zstd)
        );
        // What Cloudflare forwards to the origin: only gzip + br -> brotli.
        assert_eq!(c.should_compress(&r, "gzip, br"), Some(Encoding::Brotli));
        assert_eq!(c.should_compress(&r, "gzip"), Some(Encoding::Gzip));
    }

    #[test]
    fn apply_zstd_sets_headers_and_compresses() {
        let c = Compress::new();
        let original = b"hello ".repeat(200);
        let mut r = resp_with("text/html", original.clone());
        let enc = c.should_compress(&r, "zstd, gzip").unwrap();
        assert_eq!(enc, Encoding::Zstd);
        c.apply(&mut r, enc);
        assert_eq!(
            r.headers().get(CONTENT_ENCODING).unwrap(),
            HeaderValue::from_static("zstd")
        );
        match r.body() {
            Body::Full(b) => {
                let cl: u64 = r
                    .headers()
                    .get(CONTENT_LENGTH)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(cl, b.len() as u64);
                assert_eq!(unzstd(b), original);
            }
            _ => panic!("expected Full body"),
        }
    }

    #[test]
    fn apply_brotli_sets_headers_and_compresses() {
        let c = Compress::new();
        let original = b"hello ".repeat(200);
        let mut r = resp_with("text/html", original.clone());
        let enc = c.should_compress(&r, "gzip, br").unwrap();
        assert_eq!(enc, Encoding::Brotli);
        c.apply(&mut r, enc);
        assert_eq!(
            r.headers().get(CONTENT_ENCODING).unwrap(),
            HeaderValue::from_static("br")
        );
        match r.body() {
            Body::Full(b) => assert_eq!(unbrotli(b), original),
            _ => panic!("expected Full body"),
        }
    }

    #[test]
    fn apply_removes_accept_ranges_full_and_stream() {
        let c = Compress::new();
        // Full body: Accept-Ranges must be stripped once Content-Encoding is set.
        let mut r = resp_with("text/html", b"hello ".repeat(200));
        r.headers_mut()
            .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        let enc = c.should_compress(&r, "gzip").unwrap();
        c.apply(&mut r, enc);
        assert!(r.headers().contains_key(CONTENT_ENCODING));
        assert!(
            r.headers().get(ACCEPT_RANGES).is_none(),
            "Accept-Ranges must be removed on a compressed full body"
        );

        // Stream body: same guarantee.
        use hj_core::{BoxError, StreamBody};
        use http_body_util::{BodyExt, Full as FullBody};
        let inner: StreamBody = FullBody::new(Bytes::from(vec![b'x'; 1000]))
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let mut sr = http::Response::new(Body::Stream(inner));
        sr.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        sr.headers_mut()
            .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        let enc = c.should_compress(&sr, "gzip").unwrap();
        c.apply(&mut sr, enc);
        assert!(
            sr.headers().get(ACCEPT_RANGES).is_none(),
            "Accept-Ranges must be removed on a compressed stream body"
        );
    }

    #[test]
    fn enable_flags_filter_priority() {
        let r = resp_with("text/html", b"x".repeat(1000));
        // zstd disabled -> brotli wins.
        let c = Compress::from_tuning(&Tuning {
            enable_zstd: false,
            ..Tuning::default()
        });
        assert_eq!(
            c.should_compress(&r, "zstd, br, gzip"),
            Some(Encoding::Brotli)
        );
        // zstd + brotli disabled -> gzip.
        let c2 = Compress::from_tuning(&Tuning {
            enable_zstd: false,
            enable_brotli: false,
            ..Tuning::default()
        });
        assert_eq!(
            c2.should_compress(&r, "zstd, br, gzip"),
            Some(Encoding::Gzip)
        );
        // All disabled -> master switch off.
        let c3 = Compress::from_tuning(&Tuning {
            enable_zstd: false,
            enable_brotli: false,
            enable_gzip: false,
            ..Tuning::default()
        });
        assert_eq!(c3.should_compress(&r, "zstd, br, gzip"), None);
    }

    #[test]
    fn dyn_zstd_off_gates_zstd_stream() {
        use hj_core::{BoxError, StreamBody};
        use http_body_util::{BodyExt, Full as FullBody};

        let c = Compress::from_tuning(&Tuning {
            enable_dyn_zstd: false,
            ..Tuning::default()
        });

        let inner: StreamBody = FullBody::new(Bytes::from(vec![b'x'; 500]))
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let mut sr = http::Response::new(Body::Stream(inner));
        sr.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        // zstd is top priority + accepted, but its dynamic gate is off -> skip.
        assert_eq!(c.should_compress(&sr, "zstd"), None);

        // A buffered (Full) body still compresses with zstd (gate is dynamic-only).
        let full = resp_with("text/html", b"x".repeat(500));
        assert_eq!(c.should_compress(&full, "zstd"), Some(Encoding::Zstd));
    }

    #[test]
    fn etag_variant_tagged_per_codec() {
        let c = Compress::new();
        for (accept, enc, want) in [
            ("gzip", Encoding::Gzip, "\"abc;gz\""),
            ("gzip, br", Encoding::Brotli, "\"abc;br\""),
            ("zstd", Encoding::Zstd, "\"abc;zs\""),
        ] {
            let mut r = resp_with("text/html", b"x".repeat(500));
            r.headers_mut()
                .insert(ETAG, HeaderValue::from_static("\"abc;;;\""));
            let got = c.should_compress(&r, accept).unwrap();
            assert_eq!(got, enc);
            c.apply(&mut r, got);
            assert_eq!(r.headers().get(ETAG).unwrap().to_str().unwrap(), want);
        }
    }

    #[test]
    fn foreign_strong_etag_is_removed_after_compression() {
        let c = Compress::new();
        let mut r = resp_with("text/html", b"x".repeat(500));
        r.headers_mut()
            .insert(ETAG, HeaderValue::from_static("\"plain-etag\""));
        c.apply(&mut r, Encoding::Gzip);
        assert!(!r.headers().contains_key(ETAG));
    }

    #[test]
    fn weak_foreign_etag_survives_compression() {
        let c = Compress::new();
        let mut r = resp_with("text/html", b"x".repeat(500));
        r.headers_mut()
            .insert(ETAG, HeaderValue::from_static("W/\"plain-etag\""));
        c.apply(&mut r, Encoding::Gzip);
        assert_eq!(
            r.headers().get(ETAG).unwrap().to_str().unwrap(),
            "W/\"plain-etag\""
        );
    }

    fn make_ctx(accept: &str) -> ReqCtx {
        use hj_core::Proto;
        use hj_core::config::{ServerConfig, VHostConfig};
        use std::net::Ipv4Addr;
        use std::sync::Arc;

        let server = ServerConfig {
            server_root: Default::default(),
            server_name: String::new(),
            user: String::new(),
            group: String::new(),
            index_files: vec![],
            tuning: Default::default(),
            quic_enable: false,
            use_ip_in_proxy_header: 0,
            expires: Default::default(),
            cache: Default::default(),
            security: Default::default(),
            suexec: Default::default(),
            ext_processors: vec![],
            php_config: None,
            listeners: vec![],
            vhosts: Default::default(),
            vhost_order: vec![],
            mime: Default::default(),
        };
        let mut ctx = ReqCtx {
            server: Arc::new(server),
            vhost_name: "test".into(),
            vhost: Arc::new(VHostConfig::default()),
            peer_ip: Ipv4Addr::LOCALHOST.into(),
            client_ip: Ipv4Addr::LOCALHOST.into(),
            is_tls: false,
            protocol: Proto::Http1,
            trusted_proxy: false,
            env: Vec::new(),
            local_addr: "127.0.0.1:8080".parse().unwrap(),
            peer_port: 0,
            peer_unix: false,
            request_time: std::time::SystemTime::now(),
            request_id: Default::default(),
            tls: None,
            redirect_guard: None,
        };
        ctx.set_env(ACCEPT_ENCODING_ENV, accept);
        ctx
    }

    #[tokio::test]
    async fn transform_via_reqctx_env() {
        let ctx = make_ctx("gzip, deflate");
        let c = Compress::new();
        let original = b"hello ".repeat(200);
        let mut r = resp_with("text/html", original.clone());
        c.transform(&ctx, &mut r).await;

        assert_eq!(
            r.headers().get(CONTENT_ENCODING).unwrap(),
            HeaderValue::from_static("gzip")
        );
        match r.body() {
            Body::Full(b) => assert_eq!(gunzip(b), original),
            _ => panic!("expected Full body"),
        }
    }

    #[tokio::test]
    async fn cf_send_zstd_forces_zstd_only_for_trusted_proxy() {
        let body = b"x".repeat(1000);
        // CF forwards `br, gzip` (no zstd). With the flag on, a trusted-proxy (CF) peer
        // is served zstd anyway — CF decodes it and re-encodes per browser at its edge.
        let on = Compress::new().with_cf_send_zstd(true);
        let mut cf = make_ctx("br, gzip");
        cf.trusted_proxy = true;
        let mut r = resp_with("text/html", body.clone());
        on.transform(&cf, &mut r).await;
        assert_eq!(r.headers().get(CONTENT_ENCODING).unwrap(), "zstd");
        assert!(r.headers().get(VARY).is_some());

        // Same flag, but an UNTRUSTED (direct) client is never forced — normal br.
        let direct = make_ctx("br, gzip"); // trusted_proxy = false
        let mut r2 = resp_with("text/html", body.clone());
        on.transform(&direct, &mut r2).await;
        assert_eq!(r2.headers().get(CONTENT_ENCODING).unwrap(), "br");

        // Flag OFF: a trusted-proxy peer still negotiates normally (br) — no behavior change.
        let off = Compress::new();
        let mut cf3 = make_ctx("br, gzip");
        cf3.trusted_proxy = true;
        let mut r3 = resp_with("text/html", body);
        off.transform(&cf3, &mut r3).await;
        assert_eq!(r3.headers().get(CONTENT_ENCODING).unwrap(), "br");
    }

    #[tokio::test]
    async fn transform_no_accept_no_vary() {
        // OLS only emits Vary: Accept-Encoding when it actually gzip-encodes the
        // body. With no acceptable encoding, the response is left untouched —
        // no Content-Encoding AND no speculative Vary.
        let ctx = make_ctx(""); // no gzip
        let c = Compress::new();
        let mut r = resp_with("text/html", b"x".repeat(1000));
        c.transform(&ctx, &mut r).await;
        assert!(r.headers().get(CONTENT_ENCODING).is_none());
        assert!(
            r.headers().get_all(VARY).iter().next().is_none(),
            "OLS does not add a speculative Vary on uncompressed responses"
        );
    }

    #[tokio::test]
    async fn transform_compress_adds_vary() {
        // When gzip IS applied, Vary: Accept-Encoding must be present (OLS
        // bundles it with Content-Encoding: gzip).
        let ctx = make_ctx("gzip");
        let c = Compress::new();
        let mut r = resp_with("text/html", b"x".repeat(1000));
        c.transform(&ctx, &mut r).await;
        assert_eq!(
            r.headers().get(CONTENT_ENCODING).unwrap(),
            HeaderValue::from_static("gzip")
        );
        assert!(r.headers().get_all(VARY).iter().any(|v| {
            v.to_str()
                .unwrap()
                .to_ascii_lowercase()
                .contains("accept-encoding")
        }));
    }

    #[tokio::test]
    async fn transform_cloudflare_prefers_brotli() {
        // Cloudflare forwards `gzip, br` to the origin; brotli should win.
        let ctx = make_ctx("gzip, br");
        let c = Compress::new();
        let original = b"hello ".repeat(200);
        let mut r = resp_with("text/html", original.clone());
        c.transform(&ctx, &mut r).await;
        assert_eq!(
            r.headers().get(CONTENT_ENCODING).unwrap(),
            HeaderValue::from_static("br")
        );
        match r.body() {
            Body::Full(b) => assert_eq!(unbrotli(b), original),
            _ => panic!("expected Full body"),
        }
    }

    #[tokio::test]
    async fn transform_streams_gzip() {
        use hj_core::{BoxError, StreamBody};
        use http_body_util::{BodyExt, Full as FullBody};

        let ctx = make_ctx("gzip");
        let c = Compress::new();

        let payload = b"streamed content ".repeat(100);
        let inner: StreamBody = FullBody::new(Bytes::from(payload.clone()))
            .map_err(|e| Box::new(e) as BoxError)
            .boxed();
        let mut r = http::Response::new(Body::Stream(inner));
        r.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        r.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&payload.len().to_string()).unwrap(),
        );

        c.transform(&ctx, &mut r).await;

        assert_eq!(
            r.headers().get(CONTENT_ENCODING).unwrap(),
            HeaderValue::from_static("gzip")
        );
        // Content-Length removed for streamed output.
        assert!(r.headers().get(CONTENT_LENGTH).is_none());

        let (parts, body) = r.into_parts();
        let _ = parts;
        let collected = body_collect(body).await;
        assert_eq!(gunzip(&collected), payload);
    }

    /// Drain a `Body` into bytes for tests (handles Full + Stream).
    async fn body_collect(body: Body) -> Vec<u8> {
        use http_body_util::BodyExt;
        match body {
            Body::Full(b) => b.to_vec(),
            Body::Stream(s) => s.collect().await.unwrap().to_bytes().to_vec(),
            Body::Empty => Vec::new(),
            Body::File(_) => panic!("unexpected file body"),
        }
    }
}
