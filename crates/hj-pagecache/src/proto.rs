//! Parsers for the LiteSpeed cache control header protocol.
//!
//! The application (e.g. the XenForo LSCache add-on) drives caching with these
//! response headers, which httpjet consumes and then **strips** before the
//! response reaches the client / Cloudflare:
//! - `X-LiteSpeed-Cache-Control: public,max-age=N | private,max-age=N | no-cache`
//! - `X-LiteSpeed-Tag: tag1,tag2` — purge tags for the entry.
//! - `X-LiteSpeed-Vary: <value>` — vary discriminant.
//! - `X-LiteSpeed-Purge: tag1,tag2 | *` — invalidate tagged entries / everything.

/// Parsed `X-LiteSpeed-Cache-Control`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsCacheControl {
    /// Cacheable as a shared/public entry. `ttl_secs == 0` ⇒ use the configured
    /// default public TTL. `stale_secs`/`stale_if_error_secs` are the RFC 5861
    /// `stale-while-revalidate`/`stale-if-error` windows (0 ⇒ absent); the app
    /// usually carries them on the *standard* `Cache-Control` (see
    /// [`parse_std_cache_control`]) rather than here, but honor either source.
    Public {
        ttl_secs: u32,
        stale_secs: u32,
        stale_if_error_secs: u32,
    },
    /// Cacheable per-session (private). `ttl_secs == 0` ⇒ default private TTL.
    Private { ttl_secs: u32 },
    /// Explicitly not cacheable for this response.
    NoCache,
    /// Explicitly must-not-store.
    NoStore,
    /// Header absent or unrecognized ⇒ not opted in (do not cache).
    Absent,
}

/// Parse a `name=seconds` cache directive token, tolerant of optional whitespace
/// around `=` and optional quotes (RFC 7234 allows `max-age="600"`).
fn dir_secs(tok: &str, name: &str) -> Option<u32> {
    let (k, v) = tok.split_once('=')?;
    if k.trim() != name {
        return None;
    }
    let v = v.trim().trim_matches('"');
    Some(v.parse().unwrap_or(0))
}

/// Split a Cache-Control field at commas outside quoted strings. Backslash
/// escapes are significant inside a quoted string. An unterminated quote is
/// rejected so callers can fail closed instead of interpreting its contents as
/// independent directives.
fn cache_directives(v: &str) -> Result<Vec<&str>, ()> {
    let bytes = v.as_bytes();
    let mut directives = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (i, &byte) in bytes.iter().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == b',' {
            directives.push(&v[start..i]);
            start = i + 1;
        }
    }
    if quoted || escaped {
        return Err(());
    }
    directives.push(&v[start..]);
    Ok(directives)
}

/// Parse an `X-LiteSpeed-Cache-Control` header value.
pub fn parse_lscache_control(v: &str) -> LsCacheControl {
    let lower = v.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return LsCacheControl::Absent;
    }
    let directives = match cache_directives(&lower) {
        Ok(directives) => directives,
        Err(()) => return LsCacheControl::NoCache,
    };
    // Explicit non-cache wins regardless of any accompanying scope token.
    if directives.iter().any(|t| t.trim() == "no-cache") {
        return LsCacheControl::NoCache;
    }
    if directives.iter().any(|t| t.trim() == "no-store") {
        return LsCacheControl::NoStore;
    }

    let mut ttl_secs: u32 = 0;
    let mut stale_secs: u32 = 0;
    let mut stale_if_error_secs: u32 = 0;
    let mut is_private = false;
    let mut is_public = false;
    for tok in directives {
        let tok = tok.trim();
        if tok == "private" {
            is_private = true;
        } else if tok == "public" {
            is_public = true;
        } else if let Some(age) = dir_secs(tok, "stale-while-revalidate") {
            stale_secs = stale_secs.max(age);
        } else if let Some(age) = dir_secs(tok, "stale-if-error") {
            stale_if_error_secs = age;
        } else if let Some(age) = dir_secs(tok, "max-stale") {
            // OpenLiteSpeed's stale-serve window (`CacheCtrl::m_iMaxStale`): an LSCache
            // app may declare it on `X-LiteSpeed-Cache-Control` instead of RFC 5861
            // `stale-while-revalidate`. Honor either (largest wins) for OLS parity.
            stale_secs = stale_secs.max(age);
        } else if let Some((k, val)) = tok.split_once('=') {
            if k.trim() == "max-age" {
                // An EXPLICIT max-age must be distinguished from an absent one (both used
                // to collapse to ttl_secs=0 → the 900s default, so a page meant to be
                // uncacheable was cached fresh for 15 min). `max-age=0` means "immediately
                // stale", and a malformed/overflowing value we cannot trust → fail CLOSED
                // (do not cache) rather than silently default-cache. Absent max-age (a bare
                // `public`/`private`) still leaves ttl_secs=0 ⇒ the configured default.
                match val.trim().trim_matches('"').parse::<u32>() {
                    Ok(0) | Err(_) => return LsCacheControl::NoCache,
                    Ok(n) => ttl_secs = n,
                }
            }
        }
    }
    if is_private {
        LsCacheControl::Private { ttl_secs }
    } else if is_public {
        LsCacheControl::Public {
            ttl_secs,
            stale_secs,
            stale_if_error_secs,
        }
    } else {
        LsCacheControl::Absent
    }
}

/// Parsed *standard* HTTP `Cache-Control` (RFC 7234 + RFC 5861). The app drives
/// httpjet primarily via `X-LiteSpeed-Cache-Control`, but a non-LiteSpeed app
/// (e.g. moontimenow) opts in with the standard header only, and even the
/// LiteSpeed-aware app carries the `stale-*` windows here. Parsed by exact
/// directive token (NOT substring) so `no-stale-cache` never trips `no-cache`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StdCacheControl {
    pub public: bool,
    pub private: bool,
    pub no_store: bool,
    pub no_cache: bool,
    /// `must-revalidate`, `proxy-revalidate`, or `s-maxage` (RFC 9111
    /// §5.2.2.2/§5.2.2.8/§5.2.2.10): once stale, the entry MUST be revalidated,
    /// not served stale. We never inject our configured DEFAULT stale windows over
    /// this (an explicit app-declared SWR/SIE still wins — that combination is the
    /// app's own choice).
    pub must_revalidate: bool,
    /// `max-age` (browser TTL).
    pub max_age: Option<u32>,
    /// `s-maxage` (shared-cache TTL — what an origin cache should honor).
    pub s_maxage: Option<u32>,
    pub stale_while_revalidate: Option<u32>,
    pub stale_if_error: Option<u32>,
}

impl StdCacheControl {
    /// The TTL an origin cache should use: `s-maxage` (shared) preferred, else
    /// `max-age`. `None` ⇒ no positive freshness directive.
    pub fn shared_ttl(&self) -> Option<u32> {
        self.s_maxage.or(self.max_age)
    }
    /// True if any directive forbids shared caching.
    pub fn forbids_cache(&self) -> bool {
        self.no_store || self.no_cache || self.private
    }
}

/// Parse a standard `Cache-Control` value by exact directive token.
pub fn parse_std_cache_control(v: &str) -> StdCacheControl {
    let mut cc = StdCacheControl::default();
    let directives = match cache_directives(v) {
        Ok(directives) => directives,
        Err(()) => {
            cc.no_store = true;
            return cc;
        }
    };
    for tok in directives {
        let tok = tok.trim();
        let low = tok.to_ascii_lowercase();
        match low.as_str() {
            "public" => cc.public = true,
            "private" => cc.private = true,
            "no-store" => cc.no_store = true,
            "no-cache" => cc.no_cache = true,
            "must-revalidate" | "proxy-revalidate" => cc.must_revalidate = true,
            _ => {
                let name = low.split_once('=').map(|(name, _)| name.trim());
                if name == Some("private") {
                    cc.private = true;
                } else if name == Some("no-cache") {
                    cc.no_cache = true;
                } else if let Some(n) = dir_secs(&low, "s-maxage") {
                    cc.s_maxage.get_or_insert(n);
                    cc.must_revalidate = true;
                } else if let Some(n) = dir_secs(&low, "max-age") {
                    cc.max_age.get_or_insert(n);
                } else if let Some(n) = dir_secs(&low, "stale-while-revalidate") {
                    cc.stale_while_revalidate.get_or_insert(n);
                } else if let Some(n) = dir_secs(&low, "stale-if-error") {
                    cc.stale_if_error.get_or_insert(n);
                }
            }
        }
    }
    cc
}

/// Parse a comma-separated tag list (`X-LiteSpeed-Tag`).
pub fn parse_tags(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse an `X-LiteSpeed-Vary` value into its `cookie=NAME` vary names plus a
/// flag indicating whether *every* token was a cookie vary.
///
/// `X-LiteSpeed-Vary: cookie=xf_style_variation, cookie=xf_style_id` →
/// `(["xf_style_variation", "xf_style_id"], true)`. A non-cookie dimension
/// (e.g. `ismobile`) sets the flag to `false` so the caller can bypass caching
/// rather than under-vary a response it can't key correctly.
pub fn parse_vary(v: &str) -> (Vec<String>, bool) {
    let mut names = Vec::new();
    let mut all_cookie = true;
    for tok in v.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if let Some(name) = tok.strip_prefix("cookie=") {
            let name = name.trim();
            if !name.is_empty() {
                names.push(name.to_string());
            }
        } else {
            all_cookie = false;
        }
    }
    (names, all_cookie)
}

/// A purge instruction from `X-LiteSpeed-Purge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purge {
    /// Purge everything (`*`).
    All,
    /// Purge entries carrying any of these tags.
    Tags(Vec<String>),
}

/// Parse an `X-LiteSpeed-Purge` header value into a purge instruction.
///
/// LiteSpeed syntax: `*` purges everything; `tag=NAME` selects a tag; bare
/// scope qualifiers (`public`/`private`/`stale`) are skipped — NOT treated as
/// tags (otherwise `public, tag=T1`, which the app emits, would purge every
/// public entry instead of just thread T1). A bare non-scope token is accepted
/// as a tag for robustness.
pub fn parse_purge(v: &str) -> Purge {
    let v = v.trim();
    let mut tags = Vec::new();
    for tok in v.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let name = tok.strip_prefix("tag=").unwrap_or(tok).trim();
        // A bare `*` or `tag=*` is purge-everything (LiteSpeed compat), not a
        // literal tag named `*` (which would match nothing).
        if name == "*" {
            return Purge::All;
        }
        if name.eq_ignore_ascii_case("public")
            || name.eq_ignore_ascii_case("private")
            || name.eq_ignore_ascii_case("stale")
            || name.is_empty()
        {
            continue;
        }
        tags.push(name.to_string());
    }
    Purge::Tags(tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_public_with_age() {
        assert_eq!(
            parse_lscache_control("public,max-age=120"),
            LsCacheControl::Public {
                ttl_secs: 120,
                stale_secs: 0,
                stale_if_error_secs: 0
            }
        );
    }

    #[test]
    fn parse_public_default_ttl() {
        assert_eq!(
            parse_lscache_control("public"),
            LsCacheControl::Public {
                ttl_secs: 0,
                stale_secs: 0,
                stale_if_error_secs: 0
            }
        );
    }

    #[test]
    fn explicit_max_age_zero_is_not_cacheable() {
        // (C-exp) An EXPLICIT max-age=0 means "immediately stale" — it must NOT be cached
        // for the 900s default. A bare `public` (absent max-age) still defaults (above).
        assert_eq!(
            parse_lscache_control("public, max-age=0"),
            LsCacheControl::NoCache
        );
        assert_eq!(
            parse_lscache_control("private, max-age=0"),
            LsCacheControl::NoCache
        );
        assert_eq!(
            parse_lscache_control("public, max-age = 0"),
            LsCacheControl::NoCache
        );
    }

    #[test]
    fn malformed_or_overflowing_max_age_fails_closed() {
        // A value we cannot trust must fail CLOSED (no-cache), not silently default to 900s.
        assert_eq!(
            parse_lscache_control("public, max-age=banana"),
            LsCacheControl::NoCache
        );
        assert_eq!(
            parse_lscache_control("public, max-age=99999999999999"),
            LsCacheControl::NoCache
        );
        // A valid value still works.
        assert_eq!(
            parse_lscache_control("public, max-age=600"),
            LsCacheControl::Public {
                ttl_secs: 600,
                stale_secs: 0,
                stale_if_error_secs: 0
            }
        );
    }

    #[test]
    fn parse_lscache_stale_windows() {
        // If the app ever puts the stale windows on X-LiteSpeed-Cache-Control, honor them.
        assert_eq!(
            parse_lscache_control(
                "public, max-age=300, stale-while-revalidate=600, stale-if-error=3600"
            ),
            LsCacheControl::Public {
                ttl_secs: 300,
                stale_secs: 600,
                stale_if_error_secs: 3600
            }
        );
    }

    #[test]
    fn cache_control_seconds_tolerates_ows_around_equals() {
        assert_eq!(
            parse_lscache_control(
                "public, max-age = 300, stale-while-revalidate = \"600\", stale-if-error = 3600"
            ),
            LsCacheControl::Public {
                ttl_secs: 300,
                stale_secs: 600,
                stale_if_error_secs: 3600
            }
        );
        let cc = parse_std_cache_control(
            "public, s-maxage = \"600\", max-age = 300, stale-if-error = 3600",
        );
        assert_eq!(cc.s_maxage, Some(600));
        assert_eq!(cc.max_age, Some(300));
        assert_eq!(cc.stale_if_error, Some(3600));
        assert_eq!(cc.shared_ttl(), Some(600));
    }

    #[test]
    fn std_cc_full_directive_parse() {
        let cc = parse_std_cache_control(
            "public, max-age=300, s-maxage=600, stale-while-revalidate=900, stale-if-error=3600",
        );
        assert!(cc.public && !cc.forbids_cache());
        assert_eq!(cc.max_age, Some(300));
        assert_eq!(cc.s_maxage, Some(600));
        assert_eq!(cc.stale_while_revalidate, Some(900));
        assert_eq!(cc.stale_if_error, Some(3600));
        // shared_ttl prefers s-maxage.
        assert_eq!(cc.shared_ttl(), Some(600));
    }

    #[test]
    fn std_cc_max_age_only_opt_in() {
        // moontimenow style: standard public + max-age, no s-maxage.
        let cc = parse_std_cache_control("public, max-age=3600, stale-while-revalidate=3600");
        assert!(cc.public && !cc.forbids_cache());
        assert_eq!(cc.shared_ttl(), Some(3600));
        assert_eq!(cc.stale_while_revalidate, Some(3600));
    }

    #[test]
    fn std_cc_exact_token_not_substring() {
        // A garbage token containing "no-cache"/"private" as a substring must NOT trip.
        let cc = parse_std_cache_control("public, max-age=60, x-no-cache-foo, no-stale-cache");
        assert!(cc.public);
        assert!(
            !cc.no_cache,
            "substring 'no-cache' inside another token must not forbid"
        );
        assert!(!cc.private);
        assert!(!cc.forbids_cache());
        // The real forbidding tokens still work as exact tokens.
        assert!(parse_std_cache_control("private, no-store").forbids_cache());
        assert!(parse_std_cache_control("no-cache").forbids_cache());
    }

    #[test]
    fn std_cc_quoted_seconds() {
        let cc = parse_std_cache_control("max-age=\"600\"");
        assert_eq!(cc.max_age, Some(600));
    }

    #[test]
    fn std_cc_duplicate_numeric_directives_keep_the_first_value() {
        let cc = parse_std_cache_control(
            "public, max-age=0, max-age=300, s-maxage=0, s-maxage=600, \
             stale-if-error=0, stale-if-error=90",
        );
        assert_eq!(cc.max_age, Some(0));
        assert_eq!(cc.s_maxage, Some(0));
        assert_eq!(cc.stale_if_error, Some(0));

        let reversed = parse_std_cache_control("max-age=300, max-age=0");
        assert_eq!(reversed.max_age, Some(300));
    }

    #[test]
    fn std_cc_qualified_restrictions_forbid_shared_storage() {
        let private = parse_std_cache_control("public, max-age=60, private=\"x-user\"");
        assert!(private.private);
        assert!(private.forbids_cache());

        let no_cache = parse_std_cache_control("public, max-age=60, no-cache=\"set-cookie\"");
        assert!(no_cache.no_cache);
        assert!(no_cache.forbids_cache());
    }

    #[test]
    fn std_cc_s_maxage_implies_shared_revalidation() {
        let cc = parse_std_cache_control("public, s-maxage=60");
        assert!(cc.must_revalidate);
        assert_eq!(cc.shared_ttl(), Some(60));
    }

    #[test]
    fn cache_control_quoted_commas_are_opaque_and_malformed_quotes_fail_closed() {
        let hidden = parse_std_cache_control(
            "extension=\"ignore, public, max-age=300, no-cache\", another=1",
        );
        assert!(!hidden.public);
        assert_eq!(hidden.max_age, None);
        assert!(!hidden.no_cache);

        assert_eq!(
            parse_lscache_control("extension=\"ignore, public, max-age=300, no-cache\""),
            LsCacheControl::Absent
        );
        assert_eq!(
            parse_lscache_control(
                "extension=\"ignore\\\", public, max-age=300\", public, max-age=60"
            ),
            LsCacheControl::Public {
                ttl_secs: 60,
                stale_secs: 0,
                stale_if_error_secs: 0,
            }
        );

        assert!(
            parse_std_cache_control("public, extension=\"unterminated").forbids_cache(),
            "a malformed standard field must fail closed"
        );
        assert_eq!(
            parse_lscache_control("public, extension=\"unterminated"),
            LsCacheControl::NoCache
        );

        let ordinary = parse_std_cache_control("public, max-age=60, stale-if-error=30");
        assert!(ordinary.public);
        assert_eq!(ordinary.max_age, Some(60));
        assert_eq!(ordinary.stale_if_error, Some(30));
    }

    #[test]
    fn parse_private() {
        assert_eq!(
            parse_lscache_control("private,max-age=300"),
            LsCacheControl::Private { ttl_secs: 300 }
        );
    }

    #[test]
    fn no_cache_wins_over_scope() {
        assert_eq!(
            parse_lscache_control("public,no-cache"),
            LsCacheControl::NoCache
        );
        assert_eq!(parse_lscache_control("no-cache"), LsCacheControl::NoCache);
    }

    #[test]
    fn absent_and_unknown() {
        assert_eq!(parse_lscache_control(""), LsCacheControl::Absent);
        assert_eq!(parse_lscache_control("max-age=60"), LsCacheControl::Absent);
    }

    #[test]
    fn tags_split_and_trim() {
        assert_eq!(
            parse_tags("thread_1, post_2 ,,forum_3"),
            vec!["thread_1", "post_2", "forum_3"]
        );
    }

    #[test]
    fn purge_wildcard_and_tags() {
        assert_eq!(parse_purge(" * "), Purge::All);
        assert_eq!(
            parse_purge("a,b"),
            Purge::Tags(vec!["a".into(), "b".into()])
        );
    }

    #[test]
    fn purge_litespeed_tag_syntax() {
        // The real app emits "public, tag=T401039, tag=T401040": the scope word
        // must NOT become a tag (else every public entry would be purged).
        assert_eq!(
            parse_purge("public, tag=T401039, tag=T401040"),
            Purge::Tags(vec!["T401039".into(), "T401040".into()])
        );
        // bare "public" alone purges nothing (scope-only).
        assert_eq!(parse_purge("public"), Purge::Tags(vec![]));
        // tag= with wildcard anywhere => all.
        assert_eq!(parse_purge("public, *"), Purge::All);
        // `tag=*` is purge-everything too (not a literal tag named "*").
        assert_eq!(parse_purge("tag=*"), Purge::All);
        assert_eq!(parse_purge("public, tag=*"), Purge::All);
    }

    #[test]
    fn vary_all_cookies() {
        let (names, all) =
            parse_vary("cookie=xf_style_variation, cookie=xf_style_id, cookie=xf_language_id");
        assert_eq!(
            names,
            vec!["xf_style_variation", "xf_style_id", "xf_language_id"]
        );
        assert!(all);
    }

    #[test]
    fn vary_with_non_cookie_token() {
        let (names, all) = parse_vary("cookie=xf_style_id, ismobile");
        assert_eq!(names, vec!["xf_style_id"]);
        assert!(
            !all,
            "a non-cookie vary dimension must clear the all-cookie flag"
        );
    }
}
