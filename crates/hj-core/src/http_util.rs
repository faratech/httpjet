//! Shared HTTP message-hygiene helpers used by the native HTTP/2 ([`hj-h2`]) and
//! HTTP/3 ([`hj-http`]) transports.
//!
//! [`hj-h2`]: ../../hj_h2/index.html
//! [`hj-http`]: ../../hj_http/index.html

use std::borrow::Cow;
use std::cell::RefCell;
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{
    CONNECTION, CONTENT_LENGTH, COOKIE, HeaderName, TE, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderValue, StatusCode};

/// Strip connection-specific ("hop-by-hop") fields from a response header map
/// before it is encoded onto a multiplexed transport.
///
/// `Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`,
/// `Upgrade`, and `TE` are illegal or meaningless on HTTP/2 (RFC 9113 §8.2.2)
/// and HTTP/3 (RFC 9114 §4.2) — a response carrying them is malformed. Per
/// RFC 9110 §7.6.1 the fields *named by* a `Connection` token are themselves
/// hop-by-hop and are removed too.
///
/// HTTP/1.1 (hyper) manages these itself, so this is applied ONLY by the native
/// h2/h3 encoders: a backend (PHP over LSAPI, or a proxied upstream) that emits
/// `Connection: keep-alive` or `Transfer-Encoding: chunked` would otherwise
/// produce a malformed h2/h3 frame stream.
pub fn strip_hop_by_hop_response(headers: &mut HeaderMap) {
    // Resolve the field names called out by any `Connection` token first, then
    // drop them — once `Connection` is removed those names are no longer derivable.
    let mut named: Vec<HeaderName> = Vec::new();
    for value in headers.get_all(CONNECTION).iter() {
        if let Ok(s) = value.to_str() {
            for tok in s.split(',') {
                let tok = tok.trim();
                if tok.is_empty() {
                    continue;
                }
                if let Ok(name) = HeaderName::from_bytes(tok.as_bytes()) {
                    named.push(name);
                }
            }
        }
    }
    for name in named {
        headers.remove(name);
    }
    headers.remove(CONNECTION);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
    headers.remove(TE);
    // No `http::header` constants exist for these two.
    headers.remove(HeaderName::from_static("keep-alive"));
    headers.remove(HeaderName::from_static("proxy-connection"));
}

/// Status codes whose responses cannot carry a message body.
pub fn body_forbidden_status(status: StatusCode) -> bool {
    status.is_informational()
        || matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        )
}

/// Whether the transport must end the response at the header block.
pub fn response_body_forbidden(is_head: bool, status: StatusCode) -> bool {
    is_head || body_forbidden_status(status)
}

/// Normalize headers before emitting a response over h2/h3.
pub fn sanitize_h2_h3_body_headers(
    headers: &mut HeaderMap,
    is_head: bool,
    status: StatusCode,
    streaming_unknown_len: bool,
) {
    if body_forbidden_status(status) || (!is_head && streaming_unknown_len) {
        headers.remove(CONTENT_LENGTH);
    }
}

/// Connection-specific REQUEST header field names that are illegal over HTTP/2 (RFC 9113 §8.2.2)
/// and HTTP/3 (RFC 9114 §4.2). A request carrying any of these is malformed. (`te` is *separately*
/// illegal unless its value is exactly `trailers`, so it is handled at the call site, not here.)
///
/// Single-sourced so the native h2 decoder (`hj-h2` `decode_block_from`) and the h3 request
/// validation (`hj-http` `h3.rs`) cannot drift apart on which names they reject.
pub const CONNECTION_SPECIFIC_REQUEST_HEADERS: [&str; 5] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Whether a lowercase request header `name` is connection-specific and thus illegal over h2/h3.
/// See [`CONNECTION_SPECIFIC_REQUEST_HEADERS`].
pub fn is_connection_specific_request_header(name: &str) -> bool {
    CONNECTION_SPECIFIC_REQUEST_HEADERS.contains(&name)
}

/// RFC 3986 percent-decoding of `input`. Returns the raw decoded bytes, or
/// `None` on a malformed escape (`%` not followed by two hex digits). Does NOT
/// validate UTF-8 or reject NUL — callers apply their own post-conditions (the
/// static file layer rejects NUL + requires UTF-8; a byte consumer keeps the raw
/// bytes). Idempotent for inputs containing no `%`. Single-sourced so the static
/// handler and the rewrite path-decode stage cannot drift.
pub fn percent_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = hex_val(bytes[i + 1])?;
                let lo = hex_val(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

/// (#319) Path-context decode: BORROWS the input when it contains no `%` at all
/// (the overwhelming case) instead of copying byte-for-byte, else decodes. Post-
/// conditions for path use are folded in: `None` on a bad escape, embedded NUL,
/// or non-UTF-8 result. Single-sourced with [`percent_decode`].
pub fn percent_decode_cow(input: &str) -> Option<Cow<'_, str>> {
    if !input.as_bytes().contains(&b'%') {
        return Some(Cow::Borrowed(input));
    }
    let bytes = percent_decode(input)?;
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok().map(Cow::Owned)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The current wall time as an RFC 1123 `Date` header value (`Sun, 06 Nov 1994
/// 08:49:37 GMT`), memoized to one second per worker thread.
///
/// RFC 9110 §6.6.1: an origin server with a clock SHOULD send `Date` on every
/// response. hyper adds it on the HTTP/1.1 path, but the native h2/h3 encoders
/// do not — so the transports stamp this (insert-if-absent) at the per-request
/// boundary. Formatting an HTTP-date every request would be wasteful on the hot
/// serve path, so the value is rebuilt only when the wall-clock second changes
/// (the same coarse-memo trick the `expiresByType` transform uses); within a
/// second every caller clones a cached `HeaderValue`.
pub fn http_date_now() -> HeaderValue {
    thread_local! {
        static DATE_MEMO: RefCell<(u64, HeaderValue)> =
            RefCell::new((0, HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT")));
    }
    let now = SystemTime::now();
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    DATE_MEMO.with(|m| {
        let mut m = m.borrow_mut();
        if m.0 != secs {
            // fmt_http_date is infallible-ASCII, so from_str cannot fail; keep the
            // last good value on the impossible error rather than panic.
            if let Ok(v) = HeaderValue::from_str(&httpdate::fmt_http_date(now)) {
                *m = (secs, v);
            }
        }
        m.1.clone()
    })
}

/// Insert a `Date` header (RFC 9110 §6.6.1) if the response has none, returning the
/// response. Insert-if-absent: a backend- or hyper-supplied `Date` is preserved, never
/// doubled. hyper adds `Date` on its tokio HTTP/1.1 path, but the native h2/h3 encoders
/// and the io_uring H1 writer do NOT — so every non-hyper serve boundary (the tokio
/// h2/h3 service boundary AND the io_uring bridge / fast path) must stamp it here. Shared
/// so the tokio and io_uring transports can't drift on whether `Date` is present.
#[inline]
pub fn stamp_date<B>(mut resp: http::Response<B>) -> http::Response<B> {
    if !resp.headers().contains_key(http::header::DATE) {
        resp.headers_mut()
            .insert(http::header::DATE, http_date_now());
    }
    resp
}

/// The request-header value as text, decoded the way lsphp/CGI sees it: a
/// visible-ASCII value borrows (zero-alloc, the overwhelmingly common case); a
/// value carrying obs-text / UTF-8 bytes (which H1, H2 and H3 all admit) is
/// `from_utf8_lossy`-decoded instead of being treated as ABSENT. Every server-side
/// consumer of a security-relevant header (Cookie classification for the page
/// cache, `%{HTTP_*}` rewrite variables, `SetEnvIf`) must use this so that it
/// classifies the SAME string PHP receives — a `filter_map(to_str().ok())` let a
/// single non-ASCII cookie crumb hide `xf_user`/`xf_style_id` from the cache tier
/// while PHP still honored them (#360).
pub fn header_value_lossy(v: &HeaderValue) -> Cow<'_, str> {
    match v.to_str() {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => String::from_utf8_lossy(v.as_bytes()),
    }
}

/// Reassemble HTTP/2 / HTTP/3 `cookie` crumbs into the single standard line.
///
/// RFC 9113 §8.2.3 and RFC 9114 §4.2.1: clients MAY split the Cookie header into
/// multiple field lines (one per cookie — Chrome does, for HPACK/QPACK indexing),
/// and a server forwarding or consuming them must rejoin with `"; "` — NOT the
/// generic `", "` comma join used for other repeated headers, which corrupts
/// `$_SERVER['HTTP_COOKIE']` (mangled PHP sessions for any multi-cookie client
/// speaking h2/h3 directly to the origin). Called once at request build time in
/// the h2/h3 transports so every downstream consumer — the CGI env, the page
/// cache's vary/private-session routing (which reads ONE cookie line), rewrite
/// conditions — sees the canonical single-line form. A single (or absent) cookie
/// line is untouched and allocation-free.
pub fn coalesce_cookie_crumbs(headers: &mut HeaderMap) {
    let mut crumbs = headers.get_all(COOKIE).iter();
    let Some(first) = crumbs.next() else { return };
    if crumbs.next().is_none() {
        return;
    }
    let total: usize = headers.get_all(COOKIE).iter().map(|v| v.len() + 2).sum();
    let mut joined = Vec::with_capacity(total);
    joined.extend_from_slice(first.as_bytes());
    for v in headers.get_all(COOKIE).iter().skip(1) {
        joined.extend_from_slice(b"; ");
        joined.extend_from_slice(v.as_bytes());
    }
    // Each crumb was a valid HeaderValue and "; " is valid, so this cannot fail;
    // if it somehow does, leave the map unchanged (the prior behavior).
    if let Ok(v) = http::HeaderValue::from_maybe_shared(bytes::Bytes::from(joined)) {
        headers.insert(COOKIE, v);
    }
}

/// RFC 7232 §3.2 `If-None-Match` evaluation: returns `true` (precondition means
/// "not modified") when `if_none_match` is `*`, or is a comma list of entity-tags
/// one of which matches `etag` under the WEAK comparison function (the `W/`
/// prefix is ignored on both sides). Single-sourced so the static handler and the
/// page cache cannot drift on validator semantics.
pub fn if_none_match_matches(if_none_match: &str, etag: &str) -> bool {
    fn norm(s: &str) -> &str {
        s.trim().trim_start_matches("W/").trim()
    }
    let inm = if_none_match.trim();
    if inm == "*" {
        return true;
    }
    let want = norm(etag);
    // A LiteSpeed `fileETag=28` ETag ends in `;;;"`; the compress transform rewrites the SERVED
    // copy's variant slot to `;gz"` / `;br"` / `;zs"`, and that tagged value is what the client
    // caches and returns in If-None-Match. Accept a same-length `;<codec>"` slot as matching the
    // base `;;;"` (compare the core, ignoring the trailing 4-char slot) so a conditional GET on a
    // COMPRESSED static asset still revalidates to 304 instead of a full retransmit — mirroring
    // OpenLiteSpeed's `testMod` (`len -= 3`). Gated on the unambiguous `;;;"` shape, so weak
    // page-cache validators (`W/"pc…"`) and arbitrary app ETags only ever match exactly.
    let want_is_ls = want.as_bytes().ends_with(b";;;\"");
    let want_core = if want_is_ls {
        &want[..want.len() - 4]
    } else {
        want
    };
    inm.split(',').any(|tok| {
        let t = norm(tok);
        if t == want {
            return true;
        }
        if want_is_ls && t.len() == want.len() {
            let tb = t.as_bytes();
            // candidate carries a `;XX"` variant slot (`;` + 2 chars + close-quote) of equal length
            if tb.len() >= 4 && tb[tb.len() - 1] == b'"' && tb[tb.len() - 4] == b';' {
                return t[..t.len() - 4] == *want_core;
            }
        }
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn http_date_now_is_rfc1123_and_memoized() {
        let a = http_date_now();
        let s = a.to_str().unwrap();
        // RFC 1123 / IMF-fixdate shape: "Sun, 06 Nov 1994 08:49:37 GMT".
        assert!(s.ends_with(" GMT"), "must be a GMT HTTP-date: {s}");
        assert_eq!(s.len(), 29, "IMF-fixdate is exactly 29 chars: {s}");
        assert!(
            httpdate::parse_http_date(s).is_ok(),
            "must round-trip through httpdate: {s}"
        );
        // Two calls within the same second return the identical memoized value.
        assert_eq!(http_date_now(), a);
    }

    #[test]
    fn stamp_date_adds_when_absent_and_preserves_when_present() {
        // Absent → a valid Date is inserted.
        let r = stamp_date(http::Response::new(()));
        let d = r
            .headers()
            .get(http::header::DATE)
            .expect("Date inserted when absent");
        assert!(httpdate::parse_http_date(d.to_str().unwrap()).is_ok());
        // Present → preserved, never doubled (a backend/hyper Date wins).
        let mut pre = http::Response::new(());
        pre.headers_mut().insert(
            http::header::DATE,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        let r = stamp_date(pre);
        assert_eq!(
            r.headers().get_all(http::header::DATE).iter().count(),
            1,
            "no double Date"
        );
        assert_eq!(
            r.headers().get(http::header::DATE).unwrap(),
            "Wed, 21 Oct 2015 07:28:00 GMT"
        );
    }

    #[test]
    fn cookie_crumbs_rejoin_with_semicolons() {
        // 0 lines / 1 line: untouched.
        let mut h = HeaderMap::new();
        coalesce_cookie_crumbs(&mut h);
        assert!(h.get(COOKIE).is_none());
        h.insert(COOKIE, HeaderValue::from_static("a=1; b=2"));
        coalesce_cookie_crumbs(&mut h);
        assert_eq!(h.get(COOKIE).unwrap(), "a=1; b=2");
        assert_eq!(h.get_all(COOKIE).iter().count(), 1);

        // h2/h3 crumbs (one cookie per field line, Chrome-style) rejoin with "; ",
        // never the generic ", " — and collapse to ONE line so downstream
        // single-line readers (cache vary/private routing) see every cookie.
        let mut h = HeaderMap::new();
        h.append(COOKIE, HeaderValue::from_static("xf_user=1%2Ctok"));
        h.append(COOKIE, HeaderValue::from_static("xf_session=abc"));
        h.append(COOKIE, HeaderValue::from_static("xf_style_id=3"));
        coalesce_cookie_crumbs(&mut h);
        assert_eq!(h.get_all(COOKIE).iter().count(), 1);
        assert_eq!(
            h.get(COOKIE).unwrap(),
            "xf_user=1%2Ctok; xf_session=abc; xf_style_id=3"
        );
    }

    #[test]
    fn removes_standard_hop_by_hop() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        h.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        h.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        h.insert("content-type", HeaderValue::from_static("text/html"));
        strip_hop_by_hop_response(&mut h);
        assert!(!h.contains_key(CONNECTION));
        assert!(!h.contains_key(TRANSFER_ENCODING));
        assert!(!h.contains_key("keep-alive"));
        assert_eq!(h.get("content-type").unwrap(), "text/html");
    }

    #[test]
    fn removes_fields_named_by_connection_token() {
        let mut h = HeaderMap::new();
        h.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, X-Hop-Custom"),
        );
        h.insert("x-hop-custom", HeaderValue::from_static("secret"));
        h.insert("x-keep", HeaderValue::from_static("ok"));
        strip_hop_by_hop_response(&mut h);
        assert!(!h.contains_key(CONNECTION));
        assert!(!h.contains_key("x-hop-custom"));
        assert_eq!(h.get("x-keep").unwrap(), "ok");
    }

    #[test]
    fn leaves_end_to_end_headers_intact() {
        let mut h = HeaderMap::new();
        h.insert("content-length", HeaderValue::from_static("42"));
        h.insert("etag", HeaderValue::from_static("\"abc\""));
        h.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=60"),
        );
        strip_hop_by_hop_response(&mut h);
        assert_eq!(h.get("content-length").unwrap(), "42");
        assert_eq!(h.get("etag").unwrap(), "\"abc\"");
        assert_eq!(h.get("cache-control").unwrap(), "public, max-age=60");
    }

    #[test]
    fn h2_h3_body_sanitizer_preserves_head_content_length() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        sanitize_h2_h3_body_headers(&mut h, true, StatusCode::OK, true);
        assert_eq!(h.get(CONTENT_LENGTH).unwrap(), "42");
        assert!(response_body_forbidden(true, StatusCode::OK));
    }

    #[test]
    fn h2_h3_body_sanitizer_strips_for_body_forbidden_status() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        sanitize_h2_h3_body_headers(&mut h, false, StatusCode::NO_CONTENT, false);
        assert!(!h.contains_key(CONTENT_LENGTH));
        assert!(response_body_forbidden(false, StatusCode::NO_CONTENT));
    }

    #[test]
    fn h2_h3_body_sanitizer_strips_forbidden_status_on_head() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        sanitize_h2_h3_body_headers(&mut h, true, StatusCode::NO_CONTENT, false);
        assert!(!h.contains_key(CONTENT_LENGTH));
    }

    #[test]
    fn h2_h3_body_sanitizer_strips_unknown_stream_length() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        sanitize_h2_h3_body_headers(&mut h, false, StatusCode::OK, true);
        assert!(!h.contains_key(CONTENT_LENGTH));
    }

    #[test]
    fn percent_decode_basic_and_malformed() {
        assert_eq!(percent_decode("/a%2Fb").unwrap(), b"/a/b");
        assert_eq!(percent_decode("plain").unwrap(), b"plain");
        assert_eq!(percent_decode("%41%42").unwrap(), b"AB");
        assert!(percent_decode("%2").is_none()); // truncated escape
        assert!(percent_decode("%zz").is_none()); // non-hex digits
        assert_eq!(percent_decode("").unwrap(), b"");
    }

    #[test]
    fn if_none_match_weak_star_list() {
        assert!(if_none_match_matches("*", "\"abc\""));
        assert!(if_none_match_matches("\"abc\"", "\"abc\"")); // exact strong
        assert!(if_none_match_matches("W/\"abc\"", "\"abc\"")); // weak token vs strong
        assert!(if_none_match_matches("\"x\", \"abc\"", "\"abc\"")); // list member
        assert!(if_none_match_matches("W/\"x\" , W/\"abc\" ", "W/\"abc\"")); // weak both sides
        assert!(!if_none_match_matches("\"other\"", "\"abc\""));
    }

    #[test]
    fn if_none_match_compressed_variant_slot_matches_base() {
        // The compress transform tags the served ETag; the client caches `;gz`/`;br`/`;zs` and
        // revalidates against the freshly re-derived base `;;;` — all must match (→ 304).
        let base = "\"400-6a1ce183-3e6b8b;;;\"";
        assert!(if_none_match_matches("\"400-6a1ce183-3e6b8b;gz\"", base));
        assert!(if_none_match_matches("\"400-6a1ce183-3e6b8b;br\"", base));
        assert!(if_none_match_matches("\"400-6a1ce183-3e6b8b;zs\"", base));
        assert!(if_none_match_matches(base, base)); // identity still matches
        assert!(if_none_match_matches(
            "W/\"x\", \"400-6a1ce183-3e6b8b;gz\"",
            base
        )); // list member
    }

    #[test]
    fn if_none_match_variant_normalization_does_not_overmatch() {
        let base = "\"400-6a1ce183-3e6b8b;;;\"";
        // Different core never matches, even with a variant slot.
        assert!(!if_none_match_matches("\"999-deadbeef-0000;gz\"", base));
        // A non-LiteSpeed (no `;;;`) stored ETag — incl. weak page-cache validators — matches ONLY
        // exactly; the variant-slot equivalence must not fuzzy-match different slots.
        assert!(if_none_match_matches(
            "W/\"pcdeadbeef\"",
            "W/\"pcdeadbeef\""
        ));
        assert!(!if_none_match_matches(
            "W/\"pcdeadbe00\"",
            "W/\"pcdeadbeef\""
        ));
        assert!(!if_none_match_matches("\"v1;fr\"", "\"v1;en\""));
    }
}
