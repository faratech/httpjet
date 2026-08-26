//! Cache-hit response construction for the origin page cache: pick a
//! precompressed variant, build the `200`/`304` response from a stored entry,
//! and the precompress/ETag helpers the store path uses to fill an entry.

use std::time::Instant;

use bytes::Bytes;
use http::header::{
    AGE, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, VARY,
};
use http::{HeaderMap, HeaderValue, StatusCode};

use hj_compress::{
    AcceptEncoding, DEFAULT_MIN_SIZE, DEFAULT_PRIORITY, Encoding, Levels, MAX_DECODE, PageDict,
    decode_bytes, encode_bytes,
};
use hj_core::{Body, FileBody, Response};
use hj_pagecache::CachedResponse;

use crate::state::ServerState;

use super::HDR_CACHE_STATUS;

/// (PC1) Pick a precompressed variant the client accepts, in the server's canonical
/// priority `DEFAULT_PRIORITY` (zstd > brotli > gzip — the SAME order the on-serve
/// compress path negotiates, so a hit serves what a miss would). Returns the
/// (Content-Encoding token, body) or `None` to serve the identity body (and let the
/// per-serve compress transform run, as before). Only ever returns a variant that BOTH
/// exists in the entry AND the client's `Accept-Encoding` accepts, so it's never mislabeled.
fn pick_variant<'e>(
    entry: &'e CachedResponse,
    accept_encoding: AcceptEncoding,
) -> Option<(&'e str, Bytes)> {
    if entry.variants.is_empty() {
        return None;
    }
    DEFAULT_PRIORITY.iter().copied().find_map(|enc| {
        accept_encoding.accepts(enc).then_some(())?;
        entry
            .variants
            .iter()
            .find(|(tok, _)| tok == enc.token())
            .map(|(tok, b)| (tok.as_str(), b.clone()))
    })
}

enum HitBody {
    Bytes(Bytes),
    File(FileBody),
}

impl HitBody {
    fn len(&self) -> usize {
        match self {
            HitBody::Bytes(b) => b.len(),
            HitBody::File(f) => usize::try_from(file_body_len(f)).unwrap_or(usize::MAX),
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn into_body(self) -> Body {
        match self {
            HitBody::Bytes(b) => Body::Full(b),
            HitBody::File(f) => Body::File(f),
        }
    }
}

fn file_body_len(f: &FileBody) -> u64 {
    match f.range {
        Some((s, e)) => e.saturating_sub(s) + 1,
        None => f.len,
    }
}

/// Reconstruct an HTTP response from a cached entry, serving a precompressed
/// variant (PC1) when the client accepts one. For a HEAD request the same
/// representation a GET would get is selected (so Content-Length / Content-Encoding
/// match), but the body is empty (RFC 9110 §9.3.2).
///
/// **Fail closed:** returns `None` (so the caller degrades the lookup to a MISS and re-renders)
/// rather than ever serving an empty-bodied success response. That happens when a dict-compressed
/// body can't be decoded (`identity_body` → `None`) or when the resulting body is empty for a
/// status that must carry one (a 200 — an empty one would blank the page, and Cloudflare would
/// cache the blank). Redirects / 204 / 304 legitimately have no body and are returned as `Some`.
pub(super) fn build_hit_response(
    entry: &CachedResponse,
    now: Instant,
    accept_encoding: AcceptEncoding,
    is_head: bool,
    dict: Option<&PageDict>,
    store: Option<&hj_pagecache::PageStore>,
    stored: impl FnOnce() -> Option<Bytes>,
    stored_file: impl FnOnce() -> Option<FileBody>,
) -> Option<Response> {
    // The stored-body resolvers are only invoked when no precompressed variant
    // matches. Plain file-tier identity hits prefer `stored_file` so the
    // transport can stream the immutable HJPC payload range from tmpfs without
    // allocating the body on the heap; dict/derived/fallback paths use `stored`
    // bytes and still fail closed on a missing/corrupt file.
    let (body, encoding) = match pick_variant(entry, accept_encoding) {
        Some((tok, b)) => (HitBody::Bytes(b), Some(tok)),
        None => (
            resolve_identity(entry, dict, store, stored, stored_file)?,
            None,
        ),
    };
    if body.is_empty() && body_required(entry.status) {
        tracing::error!(
            status = entry.status,
            "page-cache: empty body on hit for a body-required status — failing closed (miss)"
        );
        return None;
    }
    let content_len = body.len();
    // A stored status outside the valid HTTP range can only come from a corrupt persisted/scanned
    // entry; fail CLOSED (degrade to a miss) like every other guard in this function — NOT serve a
    // blank 200 (the discarded real body) that Cloudflare would then pin at its edge. Construct the
    // Response directly (not via the builder) so the header map can be pre-sized — the builder
    // offers no `with_capacity`, so appending ~40 stored headers otherwise reallocates the map
    // several times per hit (the dominant prod path).
    let status = match StatusCode::from_u16(entry.status) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let out_body = if is_head {
        Body::Empty
    } else {
        body.into_body()
    };
    let mut resp = Response::new(out_body);
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    // entry.headers + CONTENT_LENGTH/HDR_CACHE_STATUS/AGE (+ optional CONTENT_ENCODING/VARY).
    h.reserve(entry.headers.len() + 5);
    for (k, v) in &entry.headers {
        h.append(k.clone(), v.clone());
    }
    h.insert(CONTENT_LENGTH, HeaderValue::from(content_len));
    h.insert(HDR_CACHE_STATUS, HeaderValue::from_static("hit"));
    h.insert(AGE, HeaderValue::from(entry.age_secs(now)));
    // For a precompressed hit, label the encoding and Vary so the downstream
    // compress transform skips it (it no-ops when Content-Encoding is set) and
    // CF/clients key their own cache per encoding. MERGE into any backend `Vary`
    // (e.g. `Vary: Cookie`) rather than replacing it.
    if let Some(tok) = encoding {
        // The stored tokens are the fixed negotiation set, so the common case needs no
        // per-hit allocation or revalidation.
        let v = match tok {
            "zstd" => Some(HeaderValue::from_static("zstd")),
            "br" => Some(HeaderValue::from_static("br")),
            "gzip" => Some(HeaderValue::from_static("gzip")),
            other => HeaderValue::from_str(other).ok(),
        };
        if let Some(v) = v {
            h.insert(CONTENT_ENCODING, v);
        }
        merge_vary_accept_encoding(h);
    }
    Some(resp)
}

/// Whether a cached response of this status MUST carry a non-empty body. A 200 must (an empty one
/// would blank the page — either a dict-decode failure or a mis-stored empty render); redirects
/// (3xx) and the bodyless 204 / 205 / 304 legitimately have none. Drives the fail-closed guard so
/// we never serve an empty 200, and the store-path guard so we never cache one.
pub(super) fn body_required(status: u16) -> bool {
    !(status == 204 || status == 205 || status == 304 || (300..=399).contains(&status))
}

/// (dedup) The entry's IDENTITY bytes — decoding the dict-compressed body when `dict_gen != 0`.
/// Returns `None` when a dict-compressed body cannot be decoded (a changed/absent dict, or a
/// corrupt body): the caller then FAILS CLOSED (degrades to a miss) rather than serving the empty
/// bytes as a 200. cache_lookup's generation guard normally catches a gen mismatch first, so this
/// is the belt-and-suspenders layer that guarantees dict-compressed bytes are never served raw.
/// The entry's IDENTITY bytes for an AE-mismatch serve (no stored variant the client
/// accepts). A variant-primary entry ([`CachedResponse::is_derived`]) has NO stored
/// identity — reconstruct it by decoding a stored variant (a standard codec, decodable
/// without the page dict). Otherwise resolve the stored-form body and dict-decode it.
/// `None` ⇒ fail closed (degrade to a miss), never serve empty.
fn resolve_identity(
    entry: &CachedResponse,
    dict: Option<&PageDict>,
    store: Option<&hj_pagecache::PageStore>,
    stored: impl FnOnce() -> Option<Bytes>,
    stored_file: impl FnOnce() -> Option<FileBody>,
) -> Option<HitBody> {
    if entry.is_derived() {
        return entry
            .variants
            .iter()
            .find_map(|(tok, b)| Encoding::from_token(tok).and_then(|e| decode_bytes(e, b)))
            .map(Bytes::from)
            .map(HitBody::Bytes);
    }
    if entry.dict_gen == 0 {
        if let Some(file) = stored_file() {
            return Some(HitBody::File(file));
        }
    }
    identity_body(entry, stored()?, dict, store).map(HitBody::Bytes)
}

fn identity_body(
    entry: &CachedResponse,
    stored: Bytes,
    dict: Option<&PageDict>,
    store: Option<&hj_pagecache::PageStore>,
) -> Option<Bytes> {
    if entry.dict_gen == 0 {
        return Some(stored);
    }
    // (#311) Decode ONCE per body generation into the tagged hot tier: without this,
    // every AE-mismatch identity serve ran a full-page zstd-dict decode (~50-150us
    // for a large page) on the serving thread.
    let body_id = match &entry.body {
        hj_pagecache::PageBody::File { body_id, .. } => Some(*body_id),
        _ => None,
    };
    if let (Some(id), Some(store)) = (body_id, store) {
        if let Some(warm) = store.hot_identity_get(id) {
            return Some(warm);
        }
    }
    match dict.and_then(|d| d.decode(stored.as_ref(), MAX_DECODE as usize)) {
        Some(v) => {
            if let (Some(id), Some(store)) = (body_id, store) {
                store.hot_identity_put(id, Bytes::from(v.clone()));
            }
            Some(Bytes::from(v))
        }
        None => {
            tracing::error!(
                dict_gen = entry.dict_gen,
                "page-cache: dict decode failed on serve — failing closed (degrade to miss)"
            );
            None
        }
    }
}

/// Add `Accept-Encoding` to the response `Vary`, merging with any existing value rather than
/// clobbering it — mirrors the compress transform so a backend `Vary: Cookie` survives a
/// precompressed cache hit (replacing it would let a shared cache serve the wrong variant).
fn merge_vary_accept_encoding(headers: &mut HeaderMap) {
    // Single pass over the (typically 0–2) Vary lines: detect Accept-Encoding presence and
    // count the lines at once, rather than two separate `get_all().iter()` traversals.
    let mut already = false;
    let mut count = 0usize;
    for v in headers.get_all(VARY).iter() {
        count += 1;
        if v.to_str()
            .map(|s| {
                s.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("accept-encoding"))
            })
            .unwrap_or(false)
        {
            already = true;
        }
    }
    if already {
        return;
    }
    // One existing line → fold into it; 0 or 2+ → append a fresh line (multiple `Vary` lines
    // are valid and combine per RFC 9110), since `insert` would drop the others.
    if count == 1 {
        if let Some(existing) = headers.get(VARY).and_then(|v| v.to_str().ok()) {
            const SUFFIX: &str = ", Accept-Encoding";
            let mut merged = String::with_capacity(existing.len() + SUFFIX.len());
            merged.push_str(existing);
            merged.push_str(SUFFIX);
            if let Ok(hv) = HeaderValue::from_str(&merged) {
                headers.insert(VARY, hv);
                return;
            }
        }
    }
    headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
}

/// The stored validator (ETag) for a cached entry, if any.
pub(super) fn entry_etag(entry: &CachedResponse) -> Option<&str> {
    entry
        .headers
        .iter()
        .find(|(k, _)| k == ETAG)
        .and_then(|(_, v)| v.to_str().ok())
}

/// RFC 7232 §3.2 `If-None-Match` (`*`, or a weak-compared entity-tag list). Our
/// page ETags are weak anyway (one page is served in several encodings —
/// semantically-equivalent representations). Delegates to the single-sourced
/// [`hj_core::if_none_match_matches`] so the cache and the static handler agree.
pub(super) fn if_none_match_matches(if_none_match: &str, etag: &str) -> bool {
    hj_core::if_none_match_matches(if_none_match, etag)
}

/// Build a `304 Not Modified` from a cache hit: the validators + caching directives so CF
/// refreshes its freshness window, an `Age`, and NO body. Deliberately carries only
/// cache-relevant headers (RFC 7232 §4.1) — not entity headers like Content-Type/Length.
pub(super) fn not_modified(entry: &CachedResponse, etag: &str, now: Instant) -> Response {
    let mut builder = http::Response::builder().status(StatusCode::NOT_MODIFIED);
    if let Some(h) = builder.headers_mut() {
        for (k, v) in &entry.headers {
            if k == CACHE_CONTROL
                || k == VARY
                || k == ETAG
                || k.as_str() == "cloudflare-cdn-cache-control"
            {
                h.append(k.clone(), v.clone());
            }
        }
        if !h.contains_key(ETAG) {
            if let Ok(v) = HeaderValue::from_str(etag) {
                h.insert(ETAG, v);
            }
        }
        h.insert(AGE, HeaderValue::from(entry.age_secs(now)));
        h.insert(HDR_CACHE_STATUS, HeaderValue::from_static("hit"));
    }
    builder
        .body(Body::Empty)
        .unwrap_or_else(|_| Response::new(Body::Empty))
}

/// A WEAK ETag derived from the identity body (FNV-1a 64). Weak (`W/`) because the same
/// page is served in multiple encodings (identity / br / gzip), which are
/// semantically-equivalent representations under RFC 7232. Fast + deterministic + changes
/// with content; computed once per cache fill, never per hit.
pub(super) fn weak_etag(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("W/\"pc{h:016x}\"")
}

/// (PC2) Precompute the variant(s) a hit will serve (see [`fill_encodings`]),
/// so cache hits skip recompression. Only for
/// compressible content types above the compress min size, and kept only if it is
/// actually smaller than the identity body.
///
/// Previously this compressed BOTH brotli AND gzip on every store. Because a hit
/// serves the single variant the requester accepts (brotli first), the other
/// encoding was computed-but-rarely-served — pure wasted CPU + RAM, which a CPU
/// flamegraph showed dominating on a store-heavy (stores ≫ hits) workload. Compute
/// only the one that will be served; a client whose `Accept-Encoding` doesn't match
/// the stored variant still gets correct output via the per-serve compress fallback
/// on the identity body. An empty AE (e.g. an internal SWR refresh that dropped the
/// header) defaults to brotli — accepted by Cloudflare and all modern browsers.
/// The single encoding to precompress+store for a request's `Accept-Encoding`:
/// the server's top priority among what the client accepts, in `DEFAULT_PRIORITY`
/// order (zstd > brotli > gzip). zstd is preferred where accepted — it compresses far
/// faster than brotli at comparable ratio, so it directly cuts the store-path CPU that
/// dominated the flamegraph, and matches what the on-serve path already negotiates.
/// An absent AE (an internal SWR refresh that dropped the header) defaults to brotli:
/// every modern client that accepts zstd also accepts br, so a brotli refresh entry
/// serves the widest set of hit clients without a per-serve fallback. `None` ⇒ the
/// client accepts none of zstd/br/gzip ⇒ store no variant (serve identity).
fn store_encoding(accept_encoding: AcceptEncoding) -> Option<Encoding> {
    // (#275) An absent/blank header takes the brotli default (the pre-#275
    // check was on the RAW string, so a whitespace-only AE — a shape no real
    // client sends — now also lands here instead of storing nothing; the
    // variant is still only ever SERVED to a client whose AE accepts it).
    if accept_encoding.is_empty() {
        return Some(Encoding::Brotli);
    }
    accept_encoding.negotiate(DEFAULT_PRIORITY)
}

/// The encodings a variant fill should compute: the first hitter's preferred
/// coding plus — when zstd egress to Cloudflare is forced — zstd. Without the
/// union, a non-zstd first hitter (a deploy-gate curl, a gzip-only monitor)
/// pins the entry's single variant to its own coding, and every subsequent CF
/// hit pays a dict-decode + full recompress for the entry's whole TTL.
fn add_encoding_once(encs: &mut Vec<Encoding>, enc: Encoding) {
    if !encs.contains(&enc) {
        encs.push(enc);
    }
}

fn fill_encodings(
    cf_zstd_egress: bool,
    accept_encoding: AcceptEncoding,
    capsule_shell: bool,
) -> Vec<Encoding> {
    let mut encs = Vec::with_capacity(if capsule_shell { 3 } else { 2 });
    if let Some(e) = store_encoding(accept_encoding) {
        add_encoding_once(&mut encs, e);
    }
    if cf_zstd_egress && !encs.contains(&Encoding::Zstd) {
        encs.push(Encoding::Zstd);
    }
    if capsule_shell {
        add_encoding_once(&mut encs, Encoding::Gzip);
    }
    encs
}

/// Levels for the once-per-entry variant fill: a variant is compressed ONCE off
/// the client path and served for the entry's whole TTL, so spend more CPU per
/// byte than the on-the-fly defaults (the same compress-once principle as the
/// level-19 dict storage, bounded well below it so a fill burst can't
/// monopolize the capped fill pool).
const FILL_LEVELS: Levels = Levels {
    gzip: 9,
    zstd: 9,
    brotli_q: 9,
    brotli_lgwin: 19,
};

/// (PC2-lazy) Cheap predicate — could this body plausibly yield a useful precompressed variant
/// for `accept_encoding`? Mirrors [`precompress_variants`]'s early-outs WITHOUT compressing, so
/// the on-first-hit variant fill is spawned only when a variant could actually help (never for a
/// too-small, incompressible-type, already-encoded, or non-compressing-AE request). The body may
/// still turn out not to shrink under compression — the fill marks the entry filled either way,
/// so it runs at most once. Single-sources the gate `precompress_variants` applies.
pub(super) fn eligible_for_variants(
    state: &ServerState,
    headers: &[(http::HeaderName, HeaderValue)],
    body_len: usize,
    accept_encoding: AcceptEncoding,
    capsule_shell: bool,
) -> bool {
    if (body_len as u64) < DEFAULT_MIN_SIZE {
        return false;
    }
    // (#C) Belt-and-suspenders: never precompress a body that still carries a Content-Encoding
    // (cache_store strips it, so a stored body is identity) — compressing an already-compressed
    // body produces gzip-of-gzip junk.
    if headers.iter().any(|(k, _)| k == CONTENT_ENCODING) {
        return false;
    }
    let content_type = headers
        .iter()
        .find(|(k, _)| k == CONTENT_TYPE)
        .and_then(|(_, v)| v.to_str().ok())
        .unwrap_or("");
    if !state.compress.is_compressible_type(content_type) {
        return false;
    }
    !fill_encodings(
        state.compress.cf_send_zstd(),
        accept_encoding,
        capsule_shell,
    )
    .is_empty()
}

pub(super) fn precompress_variants(
    state: &ServerState,
    headers: &[(http::HeaderName, HeaderValue)],
    body: &Bytes,
    accept_encoding: AcceptEncoding,
    capsule_shell: bool,
) -> Vec<(String, Bytes)> {
    if !eligible_for_variants(state, headers, body.len(), accept_encoding, capsule_shell) {
        return Vec::new();
    }
    fill_encodings(
        state.compress.cf_send_zstd(),
        accept_encoding,
        capsule_shell,
    )
    .into_iter()
    .filter_map(|enc| match encode_bytes(enc, body, &FILL_LEVELS) {
        Some(mut encoded) if encoded.len() < body.len() => {
            // Stored for the entry's whole TTL: exact-size it, or the encoder's
            // growth/compress-bound capacity pins an identity-scale block per variant
            // (the dict.rs::encode shrink note — same cold-block swap mechanism).
            encoded.shrink_to_fit();
            Some((enc.token().to_string(), Bytes::from(encoded)))
        }
        _ => None,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hj_pagecache::{PageBody, PageScope};
    use std::time::Duration;

    // F16: the single-pass rewrite must keep the original fold/append semantics — never clobber
    // an existing Vary, and combine multiple Vary lines per RFC 9110.
    #[test]
    fn merge_vary_accept_encoding_semantics() {
        // No Vary → appends a fresh Accept-Encoding line.
        let mut h = HeaderMap::new();
        merge_vary_accept_encoding(&mut h);
        let vals: Vec<_> = h.get_all(VARY).iter().collect();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0].to_str().unwrap(), "Accept-Encoding");

        // One existing line → fold into it (Cookie survives).
        let mut h = HeaderMap::new();
        h.insert(VARY, HeaderValue::from_static("Cookie"));
        merge_vary_accept_encoding(&mut h);
        let vals: Vec<_> = h.get_all(VARY).iter().collect();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0].to_str().unwrap(), "Cookie, Accept-Encoding");

        // Already present (case-insensitive) → no change, no duplicate.
        let mut h = HeaderMap::new();
        h.insert(VARY, HeaderValue::from_static("cookie, accept-encoding"));
        merge_vary_accept_encoding(&mut h);
        assert_eq!(h.get_all(VARY).iter().count(), 1);

        // 2+ existing lines, AE absent → append a new line, keep the others.
        let mut h = HeaderMap::new();
        h.append(VARY, HeaderValue::from_static("Cookie"));
        h.append(VARY, HeaderValue::from_static("User-Agent"));
        merge_vary_accept_encoding(&mut h);
        let vals: Vec<String> = h
            .get_all(VARY)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(vals, vec!["Cookie", "User-Agent", "Accept-Encoding"]);
    }

    fn entry_with_variants(body: &[u8], variants: &[(&str, &[u8])]) -> CachedResponse {
        CachedResponse {
            status: 200,
            identity: "id".into(),
            headers: vec![(CONTENT_TYPE, HeaderValue::from_static("text/html"))],
            body: PageBody::InMem(Bytes::copy_from_slice(body)),
            variants: variants
                .iter()
                .map(|(t, b)| (t.to_string(), Bytes::copy_from_slice(b)))
                .collect(),
            variants_filled: !variants.is_empty(),
            dict_gen: 0,
            tags: vec![],
            vary_cookie_name: String::new(),
            vary_value: String::new(),
            scope: PageScope::Public,
            stored_at: Instant::now(),
            ttl: Duration::from_secs(60),
            swr: Duration::ZERO,
            sie: Duration::ZERO,
        }
    }

    #[test]
    fn pick_variant_honours_server_priority_and_client_accept() {
        let e = entry_with_variants(b"identity-body", &[("br", b"BR"), ("gzip", b"GZ")]);
        assert_eq!(
            pick_variant(&e, AcceptEncoding::parse("br, gzip"))
                .unwrap()
                .0,
            "br"
        ); // brotli preferred
        assert_eq!(
            pick_variant(&e, AcceptEncoding::parse("gzip")).unwrap().0,
            "gzip"
        ); // only gzip accepted
        assert!(pick_variant(&e, AcceptEncoding::parse("")).is_none()); // identity request
        assert!(pick_variant(&e, AcceptEncoding::parse("identity")).is_none());
        // No variants stored ⇒ always identity.
        assert!(
            pick_variant(
                &entry_with_variants(b"x", &[]),
                AcceptEncoding::parse("br, gzip")
            )
            .is_none()
        );
    }

    #[test]
    fn fill_encodings_unions_first_hitter_with_cf_zstd() {
        // A gzip-only first hitter must not pin the entry's only variant to gzip
        // when zstd egress to CF is forced — later CF hits would recompress every
        // serve for the whole TTL.
        assert_eq!(
            fill_encodings(true, AcceptEncoding::parse("gzip"), false),
            vec![Encoding::Gzip, Encoding::Zstd]
        );
        // Already-zstd hitter: no duplicate.
        assert_eq!(
            fill_encodings(true, AcceptEncoding::parse("zstd, br, gzip"), false),
            vec![Encoding::Zstd]
        );
        // Empty AE (internal refresh) defaults to brotli, plus zstd under CF egress.
        assert_eq!(
            fill_encodings(true, AcceptEncoding::parse(""), false),
            vec![Encoding::Brotli, Encoding::Zstd]
        );
        // identity-only client alone yields nothing — but CF egress still fills zstd.
        assert_eq!(
            fill_encodings(true, AcceptEncoding::parse("identity"), false),
            vec![Encoding::Zstd]
        );
        // Without CF zstd egress: first hitter's coding only, as before.
        assert_eq!(
            fill_encodings(false, AcceptEncoding::parse("gzip"), false),
            vec![Encoding::Gzip]
        );
        assert_eq!(
            fill_encodings(false, AcceptEncoding::parse("identity"), false),
            Vec::<Encoding>::new()
        );
    }

    #[test]
    fn fill_encodings_adds_gzip_for_capsule_shells() {
        assert_eq!(
            fill_encodings(true, AcceptEncoding::parse("zstd, br, gzip"), true),
            vec![Encoding::Zstd, Encoding::Gzip]
        );
        assert_eq!(
            fill_encodings(false, AcceptEncoding::parse("br, gzip"), true),
            vec![Encoding::Brotli, Encoding::Gzip]
        );
        assert_eq!(
            fill_encodings(false, AcceptEncoding::parse("identity"), true),
            vec![Encoding::Gzip]
        );
    }

    #[test]
    fn store_encoding_picks_one_by_server_priority() {
        // zstd wins when accepted (top server priority, regardless of client order) —
        // cheapest to compress, so it cuts the store-path CPU the most.
        assert_eq!(
            store_encoding(AcceptEncoding::parse("zstd, br, gzip")),
            Some(Encoding::Zstd)
        );
        assert_eq!(
            store_encoding(AcceptEncoding::parse("gzip, br, zstd")),
            Some(Encoding::Zstd)
        );
        assert_eq!(
            store_encoding(AcceptEncoding::parse("zstd")),
            Some(Encoding::Zstd)
        );
        // No zstd: brotli preferred over gzip (server priority, not client order).
        assert_eq!(
            store_encoding(AcceptEncoding::parse("br, gzip")),
            Some(Encoding::Brotli)
        );
        assert_eq!(
            store_encoding(AcceptEncoding::parse("gzip, br")),
            Some(Encoding::Brotli)
        );
        assert_eq!(
            store_encoding(AcceptEncoding::parse("gzip, deflate, br")),
            Some(Encoding::Brotli)
        );
        // gzip-only client -> gzip (the one variant that will actually be served).
        assert_eq!(
            store_encoding(AcceptEncoding::parse("gzip")),
            Some(Encoding::Gzip)
        );
        assert_eq!(
            store_encoding(AcceptEncoding::parse("gzip, deflate")),
            Some(Encoding::Gzip)
        );
        // Empty AE (SWR refresh dropped the header) -> brotli (widest modern coverage).
        assert_eq!(
            store_encoding(AcceptEncoding::parse("")),
            Some(Encoding::Brotli)
        );
        // Accepts none of zstd/br/gzip -> no variant (serve identity).
        assert_eq!(store_encoding(AcceptEncoding::parse("identity")), None);
        assert_eq!(store_encoding(AcceptEncoding::parse("deflate")), None);
    }

    #[test]
    fn pick_variant_never_invents_a_missing_encoding() {
        // Only gzip stored: a br-only client must NOT be handed br — it falls back.
        let e = entry_with_variants(b"identity-body", &[("gzip", b"GZ")]);
        assert!(
            pick_variant(&e, AcceptEncoding::parse("br")).is_none(),
            "must not serve a non-existent br variant"
        );
        assert_eq!(
            pick_variant(&e, AcceptEncoding::parse("br, gzip"))
                .unwrap()
                .0,
            "gzip"
        );
    }

    #[test]
    fn build_hit_labels_variant_and_falls_back_to_identity() {
        let e = entry_with_variants(b"identity-body", &[("br", b"BR-bytes")]);
        let now = Instant::now();
        // Brotli client: serve the br variant, labeled, with Vary.
        let r = build_hit_response(
            &e,
            now,
            AcceptEncoding::parse("br"),
            false,
            None,
            None,
            || e.body.in_mem(),
            || None,
        )
        .unwrap();
        assert_eq!(r.headers().get(CONTENT_ENCODING).unwrap(), "br");
        assert!(r.headers().get(VARY).is_some());
        assert_eq!(r.headers().get(CONTENT_LENGTH).unwrap(), "8"); // "BR-bytes"
        // Identity client: no encoding, identity body length.
        let r2 = build_hit_response(
            &e,
            now,
            AcceptEncoding::parse(""),
            false,
            None,
            None,
            || e.body.in_mem(),
            || None,
        )
        .unwrap();
        assert!(r2.headers().get(CONTENT_ENCODING).is_none());
        assert_eq!(r2.headers().get(CONTENT_LENGTH).unwrap(), "13"); // "identity-body"
    }

    #[test]
    fn derived_entry_reconstructs_identity_losslessly_from_variant() {
        // VARIANT-PRIMARY: an entry whose identity body was dropped serves the stored
        // variant directly when the client accepts it, and reconstructs the EXACT identity
        // from that variant for an AE-mismatch client — never consulting a stored-form body
        // (the closure returns None, as it would for a real derived entry).
        let identity: &[u8] =
            b"<html><body>variant-primary lossless body; repeated repeated repeated repeated</body></html>";
        let zstd = encode_bytes(Encoding::Zstd, identity, &Levels::default()).expect("zstd encode");
        let mut e = entry_with_variants(identity, &[("zstd", zstd.as_slice())]);
        e.body = PageBody::Derived {
            identity_len: identity.len() as u32,
        };
        e.dict_gen = 0;
        assert!(e.is_derived());
        let now = Instant::now();

        // (a) zstd client: the stored variant is served directly (no reconstruction).
        let r = build_hit_response(
            &e,
            now,
            AcceptEncoding::parse("zstd"),
            false,
            None,
            None,
            || None,
            || None,
        )
        .expect("zstd hit");
        assert_eq!(r.headers().get(CONTENT_ENCODING).unwrap(), "zstd");
        match r.body() {
            Body::Full(b) => assert_eq!(
                b.as_ref(),
                zstd.as_slice(),
                "serves the stored zstd variant"
            ),
            _ => panic!("expected a full body"),
        }

        // (b) gzip client, only a zstd variant stored: reconstruct the identity from the
        // zstd variant — byte-for-byte, no Content-Encoding.
        let r2 = build_hit_response(
            &e,
            now,
            AcceptEncoding::parse("gzip"),
            false,
            None,
            None,
            || None,
            || None,
        )
        .expect("identity hit");
        assert!(r2.headers().get(CONTENT_ENCODING).is_none());
        assert_eq!(
            r2.headers().get(CONTENT_LENGTH).unwrap(),
            identity.len().to_string().as_str()
        );
        match r2.body() {
            Body::Full(b) => assert_eq!(b.as_ref(), identity, "identity reconstructed losslessly"),
            _ => panic!("expected a full body"),
        }
    }

    #[test]
    fn build_hit_head_keeps_length_but_empties_body() {
        let e = entry_with_variants(b"identity-body", &[("br", b"BR-bytes")]);
        let now = Instant::now();
        // HEAD selects the same (br) representation a GET would — Content-Length / encoding
        // match — but the body is empty.
        let r = build_hit_response(
            &e,
            now,
            AcceptEncoding::parse("br"),
            true,
            None,
            None,
            || e.body.in_mem(),
            || None,
        )
        .unwrap();
        assert_eq!(r.headers().get(CONTENT_ENCODING).unwrap(), "br");
        assert_eq!(r.headers().get(CONTENT_LENGTH).unwrap(), "8");
        assert!(
            matches!(r.body(), Body::Empty),
            "HEAD hit must have an empty body"
        );
        // Identity HEAD: identity length, empty body.
        let r2 = build_hit_response(
            &e,
            now,
            AcceptEncoding::parse(""),
            true,
            None,
            None,
            || e.body.in_mem(),
            || None,
        )
        .unwrap();
        assert_eq!(r2.headers().get(CONTENT_LENGTH).unwrap(), "13");
        assert!(matches!(r2.body(), Body::Empty));
    }

    #[test]
    fn identity_hit_can_use_file_body_without_materializing_bytes() {
        let e = entry_with_variants(b"identity-body", &[]);
        let r = build_hit_response(
            &e,
            Instant::now(),
            AcceptEncoding::parse(""),
            false,
            None,
            None,
            || -> Option<Bytes> { panic!("identity bytes should not be materialized") },
            || {
                Some(FileBody {
                    path: "/tmp/hjpc-test.pc".into(),
                    file: None,
                    len: 4096,
                    range: Some((128, 140)),
                    cached: None,
                })
            },
        )
        .unwrap();

        assert_eq!(r.headers().get(CONTENT_LENGTH).unwrap(), "13");
        match r.body() {
            Body::File(f) => {
                assert_eq!(f.path, std::path::PathBuf::from("/tmp/hjpc-test.pc"));
                assert_eq!(f.len, 4096);
                assert_eq!(f.range, Some((128, 140)));
                assert!(f.cached.is_none());
            }
            _ => panic!("identity hit should stay file-backed"),
        }
    }

    #[test]
    fn precompressed_hit_merges_into_backend_vary() {
        // The stored entry carries a backend `Vary: Cookie`; a precompressed hit must KEEP it
        // and add Accept-Encoding, not clobber it (clobbering would let a shared cache serve
        // the wrong cookie variant).
        let mut e = entry_with_variants(b"identity-body", &[("br", b"BR-bytes")]);
        e.headers.push((VARY, HeaderValue::from_static("Cookie")));
        let r = build_hit_response(
            &e,
            Instant::now(),
            AcceptEncoding::parse("br"),
            false,
            None,
            None,
            || e.body.in_mem(),
            || None,
        )
        .unwrap();
        let varies: Vec<String> = r
            .headers()
            .get_all(VARY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(',').map(|t| t.trim().to_ascii_lowercase()))
            .collect();
        assert!(
            varies.iter().any(|t| t == "cookie"),
            "backend Vary: Cookie must survive"
        );
        assert!(
            varies.iter().any(|t| t == "accept-encoding"),
            "Accept-Encoding must be added"
        );
    }

    #[test]
    fn invalid_stored_status_fails_closed() {
        // Regression (#5): a stored status outside the valid HTTP range (only reachable via a
        // corrupt persisted/scanned entry) must degrade to a MISS, not serve a blank 200 with the
        // real body discarded — which Cloudflare would then pin at its edge for the TTL.
        let mut e = entry_with_variants(b"real-body-bytes", &[]);
        e.status = 1000; // StatusCode::from_u16 rejects values > 999
        let got = build_hit_response(
            &e,
            Instant::now(),
            AcceptEncoding::parse(""),
            false,
            None,
            None,
            || e.body.in_mem(),
            || None,
        );
        assert!(
            got.is_none(),
            "an unparseable stored status must fail closed (miss), not an empty 200"
        );
    }

    #[test]
    fn build_hit_fails_closed_on_dict_decode_failure() {
        // A dict-compressed entry whose dict can't decode it (here: no dict supplied) must NOT
        // serve empty bytes as a 200 — build_hit_response returns None so the caller re-renders.
        let mut e = entry_with_variants(b"unused-raw-dict-bytes", &[]);
        e.dict_gen = 42; // tagged dict-compressed
        assert!(
            build_hit_response(
                &e,
                Instant::now(),
                AcceptEncoding::parse(""),
                false,
                None,
                None,
                || e.body.in_mem(),
                || None,
            )
            .is_none(),
            "dict decode failure must fail closed (None), never serve an empty 200"
        );
    }

    #[test]
    fn build_hit_fails_closed_on_empty_200() {
        // An empty-bodied 200 (a mis-stored render) must never be served — it would blank the page.
        let e = entry_with_variants(b"", &[]);
        assert!(
            build_hit_response(
                &e,
                Instant::now(),
                AcceptEncoding::parse(""),
                false,
                None,
                None,
                || e.body.in_mem(),
                || None,
            )
            .is_none(),
            "empty 200 must fail closed"
        );
    }

    #[test]
    fn build_hit_allows_empty_redirect_body() {
        // A 301 legitimately has no body — it must still be served (Location carries the redirect).
        let mut e = entry_with_variants(b"", &[]);
        e.status = 301;
        e.headers = vec![(
            http::header::LOCATION,
            HeaderValue::from_static("https://x/"),
        )];
        let r = build_hit_response(
            &e,
            Instant::now(),
            AcceptEncoding::parse(""),
            false,
            None,
            None,
            || e.body.in_mem(),
            || None,
        );
        assert!(
            r.is_some(),
            "an empty-bodied 301 is legitimate and must be served"
        );
        assert_eq!(r.unwrap().status(), 301);
    }

    #[test]
    fn body_required_only_for_content_statuses() {
        assert!(body_required(200));
        assert!(!body_required(301));
        assert!(!body_required(304));
        assert!(!body_required(204));
        assert!(!body_required(205)); // Reset Content — bodyless per RFC 9110 §15.3.6
    }

    #[test]
    fn weak_etag_is_deterministic_and_content_sensitive() {
        assert_eq!(weak_etag(b"hello world"), weak_etag(b"hello world"));
        assert_ne!(weak_etag(b"hello world"), weak_etag(b"hello worle"));
        assert!(weak_etag(b"x").starts_with("W/\"pc"));
    }

    #[test]
    fn if_none_match_weak_compare_and_list_and_star() {
        let tag = "W/\"pcdeadbeef\"";
        assert!(if_none_match_matches(tag, tag)); // exact
        assert!(if_none_match_matches("\"pcdeadbeef\"", tag)); // weak vs strong-form compare
        assert!(if_none_match_matches(" W/\"a\" , W/\"pcdeadbeef\" ", tag)); // list member
        assert!(if_none_match_matches("*", tag)); // star matches any
        assert!(!if_none_match_matches("W/\"other\"", tag)); // non-match
    }

    #[test]
    fn not_modified_carries_validators_not_body() {
        let mut e = entry_with_variants(b"<html>...</html>", &[]);
        e.headers = vec![
            (ETAG, HeaderValue::from_static("W/\"pcabc\"")),
            (
                CACHE_CONTROL,
                HeaderValue::from_static("public, s-maxage=600"),
            ),
            (CONTENT_TYPE, HeaderValue::from_static("text/html")),
        ];
        let r = not_modified(&e, "W/\"pcabc\"", Instant::now());
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
        assert!(matches!(r.body(), Body::Empty)); // 304 has no body
        assert_eq!(r.headers().get(ETAG).unwrap(), "W/\"pcabc\"");
        assert!(r.headers().contains_key(CACHE_CONTROL)); // freshness directive retained
        assert!(!r.headers().contains_key(CONTENT_TYPE)); // entity headers omitted (RFC 7232 §4.1)
    }
}
