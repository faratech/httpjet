//! The page-cache key and its query-normalization / vary helpers.
//!
//! The full key is compared for equality on every served hit (the store keys by a
//! 64-bit hash of this struct but then verifies the decoded full key + the request
//! identity, so a hash collision degrades to a miss, never the wrong page). The key
//! must therefore contain **every input that can change the response**: vhost, the request
//! scheme (HTTP vs HTTPS), host, path, the normalized query, the vary
//! discriminant, and (for private entries) the owner.
//!
//! Scheme is in the key because the backend can produce a *scheme-conditional*
//! response: a plain-HTTP request makes XenForo see `REQUEST_SCHEME=http` and
//! emit a canonical `301 → https://…`, which the app marks publicly cacheable.
//! Without `secure` in the key that HTTP-origin 301 would be replayed to HTTPS
//! clients — telling them to redirect to the URL they are already on, an
//! infinite loop ("Too Many Redirects"). The `:80` and `:443` listeners share
//! one store, so the scheme MUST distinguish their entries.
//!
//! Unified key: `UnifiedKeyId` wraps a 64-bit compact key that discriminates
//! between page entries (bit 63 = 0) and static files (bit 63 = 1). Both route
//! to the same `ShardedCache` with unified eviction and disk backing.

/// One query-string modifier derived from a `CacheKeyModify` directive.
///
/// LiteSpeed's `CacheKeyModify -qs:NAME` drops a named query parameter from the
/// cache key (so `?x=1&utm_source=ad` and `?x=1` share one entry); the `NAME*`
/// form drops every parameter whose name starts with the prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QsStrip {
    /// `-qs:NAME` — drop a query param by exact name.
    Exact(String),
    /// `-qs:NAME*` — drop every query param whose name starts with this prefix.
    Prefix(String),
}

/// The full cache key for a stored response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PageCacheKey {
    /// Owning vhost (two vhosts may serve different content at the same path).
    pub vhost_id: u32,
    /// Request scheme: `true` = HTTPS (`:443`), `false` = plain HTTP (`:80`).
    /// Part of the key so a scheme-conditional response (e.g. an HTTP→HTTPS
    /// canonical `301`) is never served across schemes — see the module docs.
    pub secure: bool,
    /// Lowercased request host (port stripped).
    pub host: String,
    /// Percent-decoded, normalized request path (what the pipeline resolved).
    pub path: String,
    /// Query with `CacheKeyModify`-stripped params removed in their original order.
    pub normalized_query: String,
    /// Vary discriminant (e.g. guest vs member). Empty = no vary. Part of the
    /// key so a member variant can never be served for a guest request.
    pub vary_value: String,
    /// Private-cache owner (keyed hash of the session cookie value). `0` =
    /// public. Part of the key so one user's private page can't match another's.
    pub private_owner: u64,
}

impl PageCacheKey {
    /// Build a public key (no vary, no private owner).
    pub fn public(
        vhost_id: u32,
        secure: bool,
        host: impl Into<String>,
        path: impl Into<String>,
        normalized_query: impl Into<String>,
    ) -> Self {
        PageCacheKey {
            vhost_id,
            secure,
            host: host.into(),
            path: path.into(),
            normalized_query: normalized_query.into(),
            vary_value: String::new(),
            private_owner: 0,
        }
    }
}

/// Normalize a raw query string against the effective `CacheKeyModify` rules.
///
/// 1. Split into `name[=value]` pairs.
/// 2. Drop any pair matched by a [`QsStrip`] rule (case-sensitive, matching
///    LiteSpeed).
/// 3. Re-join the survivors in their original order with `&`.
///
/// Presence of `=` is preserved: a bare param `a` and an empty-value param `a=`
/// are distinct in the output (`a` vs `a=`), so they never collide on one cache
/// key. The value is carried as `Option<&str>` — `None` = no `=` in the raw
/// token, `Some(v)` = had `=` (even `Some("")` for `a=`) — and `=` is emitted
/// whenever the value is `Some`. The path-only identity guard cannot catch such
/// a collision, so the distinction must live in the key itself.
pub fn normalize_query(raw_query: &str, modifiers: &[QsStrip]) -> String {
    if raw_query.is_empty() {
        return String::new();
    }
    let pairs: Vec<(&str, Option<&str>)> = raw_query
        .split('&')
        .map(|kv| match kv.split_once('=') {
            Some((name, val)) => (name, Some(val)),
            None => (kv, None),
        })
        .filter(|(name, _)| !should_strip(name, modifiers))
        .collect();
    let mut out = String::with_capacity(raw_query.len());
    for (i, (name, val)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(name);
        if let Some(v) = val {
            out.push('=');
            out.push_str(v);
        }
    }
    out
}

fn should_strip(name: &str, modifiers: &[QsStrip]) -> bool {
    modifiers.iter().any(|m| match m {
        QsStrip::Exact(n) => name == n,
        QsStrip::Prefix(p) => name.starts_with(p.as_str()),
    })
}

/// Compute the public **vary discriminant** for a request from a set of vary
/// cookie names (e.g. `xf_style_variation`, `xf_style_id`, `xf_language_id`).
///
/// Only cookies that are *present* in the request contribute, sorted by name
/// and joined `name=value`. So a guest with none of them yields `""` (one
/// shared cache entry — the common case), while a dark-mode visitor yields
/// `xf_style_variation=dark` (its own entry). Identical on the lookup and store
/// paths, so the keys agree. Each value is bounded to 64 bytes for key sanity.
/// Bound a vary-cookie value's contribution to the cache key. A short value is used
/// verbatim; a long one is replaced by a deterministic hash of the FULL value rather
/// than a 64-byte prefix — truncation would alias two long cookies sharing that prefix
/// onto a single variant (wrong-variant serve). `DefaultHasher::new()` is fixed-seed, so
/// the digest is stable across calls/processes (lookup and store keys still agree).
fn bounded_vary_value(v: &str) -> String {
    if v.len() <= 64 {
        return v.to_string();
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    v.hash(&mut h);
    format!("#h{:016x}", h.finish())
}

pub fn compute_vary_value(cookie_header: Option<&str>, vary_cookies: &[String]) -> String {
    let Some(cookies) = cookie_header else {
        return String::new();
    };
    if vary_cookies.is_empty() {
        return String::new();
    }
    // Matched pairs stay borrowed from the header and render once into a single
    // output String — the matched case used to allocate two Strings per pair plus
    // a format!/Vec<String>/join chain. The no-match guest case allocates nothing.
    let mut found: Vec<(&str, String)> = Vec::new();
    for configured_name in vary_cookies {
        let value = cookies.split(';').find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name.trim() == configured_name).then_some(value.trim())
        });
        if let Some(value) = value {
            found.push((configured_name.as_str(), bounded_vary_value(value)));
        }
    }
    if found.is_empty() {
        return String::new();
    }
    found.sort_by(|a, b| a.0.cmp(b.0));
    let cap = found.iter().map(|(n, v)| n.len() + v.len() + 2).sum();
    let mut out = String::with_capacity(cap);
    for (i, (n, v)) in found.iter().enumerate() {
        if i > 0 {
            out.push(';');
        }
        out.push_str(n);
        out.push('=');
        out.push_str(v);
    }
    out
}

/// Build a public key carrying a vary discriminant.
pub fn public_with_vary(
    vhost_id: u32,
    secure: bool,
    host: impl Into<String>,
    path: impl Into<String>,
    normalized_query: impl Into<String>,
    vary_value: impl Into<String>,
) -> PageCacheKey {
    PageCacheKey {
        vhost_id,
        secure,
        host: host.into(),
        path: path.into(),
        normalized_query: normalized_query.into(),
        vary_value: vary_value.into(),
        private_owner: 0,
    }
}

/// Extract the value of `vary_cookie_name` from a request `Cookie` header.
/// Returns `""` if absent. Single-cookie convenience (see
/// [`compute_vary_value`] for the multi-cookie public-vary path).
pub fn vary_value_from_request(cookie_header: Option<&str>, vary_cookie_name: &str) -> String {
    let Some(cookies) = cookie_header else {
        return String::new();
    };
    if vary_cookie_name.is_empty() {
        return String::new();
    }
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if let Some((name, val)) = pair.split_once('=') {
            if name.trim() == vary_cookie_name {
                return bounded_vary_value(val.trim());
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_list() -> Vec<QsStrip> {
        // Mirrors a production-style CacheKeyModify config.
        vec![
            QsStrip::Prefix("utm".to_string()),
            QsStrip::Exact("gclid".to_string()),
            QsStrip::Exact("fbclid".to_string()),
            QsStrip::Exact("ref".to_string()),
            QsStrip::Exact("source".to_string()),
        ]
    }

    #[test]
    fn empty_query_normalizes_to_empty() {
        assert_eq!(normalize_query("", &strip_list()), "");
    }

    #[test]
    fn utm_params_stripped_by_wildcard() {
        // utm_source / utm_medium / utm_campaign all start with "utm".
        let q = "a=1&utm_source=news&utm_medium=email&b=2";
        assert_eq!(normalize_query(q, &strip_list()), "a=1&b=2");
    }

    #[test]
    fn exact_strips_and_preserves_survivor_order() {
        let q = "z=9&gclid=xyz&fbclid=abc&a=1&ref=home&source=cf";
        assert_eq!(normalize_query(q, &strip_list()), "z=9&a=1");
    }

    #[test]
    fn distinct_param_order_stays_distinct() {
        let s = strip_list();
        assert_ne!(
            normalize_query("b=2&a=1", &s),
            normalize_query("a=1&b=2", &s)
        );
    }

    #[test]
    fn bare_param_kept() {
        assert_eq!(normalize_query("a&b=2", &[]), "a&b=2");
    }

    #[test]
    fn duplicate_same_name_params_preserve_relative_order() {
        // Order-distinct duplicates must NOT collide on one key: a backend treats
        // `a=1&a=2` (last-wins → 2) differently from `a=2&a=1` (→ 1), so the cache
        // must key them apart. A name-only STABLE sort keeps each input's own order.
        assert_eq!(normalize_query("a=1&a=2", &[]), "a=1&a=2");
        assert_eq!(normalize_query("a=2&a=1", &[]), "a=2&a=1");
        assert_ne!(
            normalize_query("a=1&a=2", &[]),
            normalize_query("a=2&a=1", &[])
        );
        // Interleaved duplicates keep their exact position relative to other names.
        assert_eq!(normalize_query("b=1&a=2&a=1", &[]), "b=1&a=2&a=1");
    }

    #[test]
    fn no_modifiers_preserves_order() {
        assert_eq!(normalize_query("utm_source=x&a=1", &[]), "utm_source=x&a=1");
    }

    #[test]
    fn key_with_and_without_utm_match() {
        let s = strip_list();
        let k1 = PageCacheKey::public(1, true, "h", "/p", normalize_query("a=1&utm_source=ad", &s));
        let k2 = PageCacheKey::public(1, true, "h", "/p", normalize_query("a=1", &s));
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_vhosts_differ() {
        let k1 = PageCacheKey::public(1, true, "h", "/p", "");
        let k2 = PageCacheKey::public(2, true, "h", "/p", "");
        assert_ne!(k1, k2);
    }

    #[test]
    fn vary_cookie_extracted() {
        let c = Some("xf_csrf=abc; xf_user=42,deadbeef; foo=bar");
        assert_eq!(vary_value_from_request(c, "xf_user"), "42,deadbeef");
        assert_eq!(vary_value_from_request(c, "missing"), "");
        assert_eq!(vary_value_from_request(None, "xf_user"), "");
    }

    fn style_cookies() -> Vec<String> {
        vec![
            "xf_style_variation".to_string(),
            "xf_style_id".to_string(),
            "xf_language_id".to_string(),
        ]
    }

    #[test]
    fn vary_value_guest_no_style_is_empty() {
        // The common case: a guest with only csrf/analytics cookies shares one
        // public entry (empty vary).
        let c = Some("xf_csrf=abc; _ga=GA1.2.3");
        assert_eq!(compute_vary_value(c, &style_cookies()), "");
        assert_eq!(compute_vary_value(None, &style_cookies()), "");
    }

    #[test]
    fn vary_value_dark_mode_distinct() {
        let guest = compute_vary_value(Some("xf_csrf=abc"), &style_cookies());
        let dark = compute_vary_value(
            Some("xf_csrf=abc; xf_style_variation=dark"),
            &style_cookies(),
        );
        assert_eq!(guest, "");
        assert_eq!(dark, "xf_style_variation=dark");
        assert_ne!(
            guest, dark,
            "dark-mode visitor must key to a distinct entry"
        );
    }

    #[test]
    fn long_vary_values_sharing_a_64b_prefix_do_not_collide() {
        // (C-vary) Two values that agree on the first 64 bytes must NOT alias onto one
        // variant — a prefix truncation would, the full-value hash must not.
        let pfx = "a".repeat(64);
        let a = compute_vary_value(
            Some(&format!("xf_style_variation={pfx}X")),
            &style_cookies(),
        );
        let b = compute_vary_value(
            Some(&format!("xf_style_variation={pfx}Y")),
            &style_cookies(),
        );
        assert_ne!(
            a, b,
            "long values sharing a 64-byte prefix must key distinctly"
        );
        // A short value is still used verbatim (stable, readable key).
        assert_eq!(
            compute_vary_value(Some("xf_style_variation=dark"), &style_cookies()),
            "xf_style_variation=dark"
        );
    }

    #[test]
    fn vary_value_cookie_name_is_case_sensitive_like_php() {
        let canon = compute_vary_value(
            Some("xf_csrf=abc; xf_style_variation=dark"),
            &style_cookies(),
        );
        let upper = compute_vary_value(
            Some("xf_csrf=abc; XF_Style_Variation=dark"),
            &style_cookies(),
        );
        assert_eq!(canon, "xf_style_variation=dark");
        assert_eq!(upper, "");
        assert_ne!(canon, upper);
    }

    #[test]
    fn vary_value_uses_first_exact_duplicate_like_php() {
        assert_eq!(
            compute_vary_value(
                Some("xf_style_id=4; xf_style_id=7; XF_STYLE_ID=9"),
                &style_cookies(),
            ),
            "xf_style_id=4"
        );
    }

    #[test]
    fn empty_query_components_are_preserved() {
        assert_eq!(normalize_query("a=1&&b=2", &[]), "a=1&&b=2");
        assert_eq!(normalize_query("&", &[]), "&");
        assert_eq!(normalize_query("&a=1&", &[]), "&a=1&");
        assert_eq!(normalize_query("&&", &[]), "&&");
    }

    #[test]
    fn stripping_named_params_does_not_drop_unrelated_empty_components() {
        assert_eq!(
            normalize_query("a=1&&utm_source=x&&b=2", &strip_list()),
            "a=1&&&b=2"
        );
    }

    #[test]
    fn vary_value_is_order_stable() {
        // Same cookies, different header order => same vary value.
        let a = compute_vary_value(
            Some("xf_style_id=5; xf_language_id=2; foo=x"),
            &style_cookies(),
        );
        let b = compute_vary_value(
            Some("xf_language_id=2; foo=x; xf_style_id=5"),
            &style_cookies(),
        );
        assert_eq!(a, b);
        assert_eq!(a, "xf_language_id=2;xf_style_id=5");
    }

    #[test]
    fn public_with_vary_distinguishes() {
        let g = public_with_vary(0, true, "h", "/t", "", "");
        let d = public_with_vary(0, true, "h", "/t", "", "xf_style_variation=dark");
        assert_ne!(g, d);
    }

    #[test]
    fn public_with_vary_distinguishes_scheme() {
        // Same vhost/host/path/query/vary, differing ONLY in scheme, must key to
        // distinct entries — otherwise an HTTP-origin canonical 301 would be
        // served to HTTPS clients (the "Too Many Redirects" loop).
        let https = public_with_vary(0, true, "forum.example", "/threads/1234", "", "");
        let http = public_with_vary(0, false, "forum.example", "/threads/1234", "", "");
        assert_ne!(https, http, "HTTP and HTTPS must not share a cache entry");
    }
}

/// Unified 64-bit cache key that discriminates between page and static entries.
///
/// Bit 63 is a type discriminant:
///   0 → page entry (bits 0-62 = hash of PageCacheKey)
///   1 → static file (bits 0-62 = hash of vhost_id ++ path)
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct UnifiedKeyId(pub u64);

impl UnifiedKeyId {
    /// Build a page-cache key from an existing PageCacheKey hash.
    pub fn for_page(raw: u64) -> Self {
        Self(raw & !(1u64 << 63))
    }

    /// Build a static-file key from vhost_id and path.
    pub fn for_static(vhost_id: u32, path: &str) -> Self {
        let h = hash_static_key(vhost_id, path);
        Self(h | (1u64 << 63))
    }

    /// Check if this is a static file entry (bit 63 set).
    pub fn is_static(self) -> bool {
        self.0 >> 63 == 1
    }

    /// Get the 0-62 bits (without the type discriminant).
    pub fn inner(self) -> u64 {
        self.0 & !(1u64 << 63)
    }
}

// For backwards compatibility, CacheKeyId is an alias to UnifiedKeyId
pub type CacheKeyId = UnifiedKeyId;

/// Hash a static file key from vhost_id and path.
/// Uses the same FNV-like algorithm as page keys to ensure uniform distribution.
pub fn hash_static_key(vhost_id: u32, path: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        h ^= 0xFF;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    };
    eat(&vhost_id.to_le_bytes());
    eat(path.as_bytes());
    // Ensure bit 63 is clear (will be set by for_static)
    h & !(1u64 << 63)
}
