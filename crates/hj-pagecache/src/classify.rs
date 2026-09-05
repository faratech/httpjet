//! The single cacheability decision point.
//!
//! `classify_response` is the one place where every "must not cache" signal
//! converges, so the rules can't drift between the store path and any future
//! callers. Phase 1 only ever returns [`Disposition::StorePublic`] —
//! private/vary responses are conservatively **bypassed** (never mis-served)
//! until Phase 2 implements per-session keying.

use http::{HeaderMap, Method};

use crate::proto::{LsCacheControl, parse_lscache_control, parse_std_cache_control};
use crate::store::StoreConfig;

/// What to do with a response after the backend produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Store as a shared/public entry with this resolved TTL plus the
    /// `stale-while-revalidate` / `stale-if-error` windows (seconds; 0 ⇒ none).
    StorePublic {
        ttl_secs: u32,
        stale_secs: u32,
        stale_if_error_secs: u32,
    },
    /// Store as a per-session PRIVATE entry (keyed by the session-cookie owner;
    /// the glue supplies the owner — a response without one is never stored).
    /// Only produced when [`StoreConfig::private_enabled`]; short TTL, no
    /// stale-while-revalidate (a private page is re-rendered, never served stale).
    StorePrivate { ttl_secs: u32 },
    /// Do not store; the `&'static str` is a stable reason code for logging.
    Bypass(&'static str),
}

/// Hard ceiling on a private entry's TTL regardless of what the app declares —
/// a logged-in page going stale must cost at most this many seconds.
pub const PRIVATE_TTL_CAP_SECS: u32 = 300;

/// Decide whether `response` (status/headers) for `method` may be PUBLIC-cached.
///
/// `no_cache_env` is true when the rewrite engine set `E=no-cache:1` (or
/// `E=Cache-Control:no-cache`) for this request — the `.htaccess` marks
/// AJAX/login/logged-in/5xx/api paths that way.
/// `honor_standard_cc` is resolved per-vhost by the caller (the vhost's canonical name
/// is in [`StoreConfig::standard_cc_vhosts`]): when true, a standard `Cache-Control:
/// public` opts in even without `X-LiteSpeed-Cache-Control`. Keeping it a parameter (not
/// a global flag) bounds the standards-mode behavior to the allowlisted vhosts.
pub fn classify_response(
    method: &Method,
    status: u16,
    headers: &HeaderMap,
    no_cache_env: bool,
    cfg: &StoreConfig,
    honor_standard_cc: bool,
) -> Disposition {
    // Method gate: only idempotent reads (POST only if explicitly enabled).
    let method_ok = method == Method::GET
        || method == Method::HEAD
        || (cfg.cache_post && method == Method::POST);
    if !method_ok {
        return Disposition::Bypass("method");
    }

    // Per-request no-cache from the rewrite env (logged-in / AJAX / api / 5xx).
    if no_cache_env {
        return Disposition::Bypass("env-no-cache");
    }

    // Status gate (LiteSpeed default: 200, 301).
    if !cfg.cacheable_status.contains(&status) {
        return Disposition::Bypass("status");
    }

    // Application opt-in: LSCache is opt-IN. A backend may emit MORE THAN ONE
    // `X-LiteSpeed-Cache-Control`; read every value and let any explicit non-cache
    // signal win (conservative — never cache when any value says not to). With
    // multiple public TTLs the smallest is used; stale windows take the largest.
    let mut forbid: Option<&'static str> = None;
    let mut ls_public_ttl: Option<u32> = None;
    let mut ls_private_ttl: Option<u32> = None;
    let mut decl_stale: u32 = 0;
    let mut decl_sie: u32 = 0;
    for v in headers
        .get_all("x-litespeed-cache-control")
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        match parse_lscache_control(v) {
            LsCacheControl::NoStore => forbid = forbid.or(Some("no-store")),
            LsCacheControl::NoCache => forbid = forbid.or(Some("no-cache")),
            // Per-session private caching is opt-in via the flag; without it the
            // pre-tier behavior stands: bypass rather than risk serving one
            // user's page to another. With multiple private TTLs the smallest
            // wins (conservative, mirrors the public arm).
            LsCacheControl::Private { ttl_secs } => {
                if cfg.private_enabled {
                    let ttl = if ttl_secs == 0 {
                        cfg.default_private_ttl.as_secs() as u32
                    } else {
                        ttl_secs
                    };
                    ls_private_ttl = Some(ls_private_ttl.map_or(ttl, |p: u32| p.min(ttl)));
                } else {
                    forbid = forbid.or(Some("private-deferred"));
                }
            }
            LsCacheControl::Public {
                ttl_secs,
                stale_secs,
                stale_if_error_secs,
            } => {
                let ttl = if ttl_secs == 0 {
                    cfg.default_public_ttl.as_secs() as u32
                } else {
                    ttl_secs
                };
                ls_public_ttl = Some(ls_public_ttl.map_or(ttl, |p| p.min(ttl)));
                decl_stale = decl_stale.max(stale_secs);
                decl_sie = decl_sie.max(stale_if_error_secs);
            }
            LsCacheControl::Absent => {}
        }
    }

    if let Some(reason) = forbid {
        return Disposition::Bypass(reason);
    }

    // Parse the STANDARD `Cache-Control` once (folding repeated lines): it is the
    // backstop AND the `stale-*` source AND — for a non-LiteSpeed app — the opt-in.
    let mut std = crate::proto::StdCacheControl::default();
    for cc in headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        let one = parse_std_cache_control(cc);
        std.public |= one.public;
        std.private |= one.private;
        std.no_store |= one.no_store;
        std.no_cache |= one.no_cache;
        std.must_revalidate |= one.must_revalidate;
        std.max_age = std.max_age.or(one.max_age);
        std.s_maxage = std.s_maxage.or(one.s_maxage);
        std.stale_while_revalidate = std.stale_while_revalidate.or(one.stale_while_revalidate);
        std.stale_if_error = std.stale_if_error.or(one.stale_if_error);
    }
    decl_stale = decl_stale.max(std.stale_while_revalidate.unwrap_or(0));
    decl_sie = decl_sie.max(std.stale_if_error.unwrap_or(0));

    // Standard HTTP backstop: an explicit no-store/no-cache/private on ANY standard
    // `Cache-Control` vetoes caching even if `X-LiteSpeed-Cache-Control` said public.
    // Parsed by exact directive token (not substring), so `no-stale-cache` is safe.
    // ONE carve-out: a standard `private` does NOT veto an EXPLICIT (and enabled)
    // `X-LiteSpeed-Cache-Control: private` opt-in — the app marking a page private
    // for browsers/CDNs while opting into the origin's per-session tier is exactly
    // the LSWS private-cache contract (X-LiteSpeed always wins). no-store/no-cache
    // still veto everything.
    if std.no_store || std.no_cache || (std.private && ls_private_ttl.is_none()) {
        return Disposition::Bypass("cache-control");
    }

    // Private wins over public if the app declared both (more restrictive scope).
    if let Some(t) = ls_private_ttl {
        return Disposition::StorePrivate {
            ttl_secs: t.clamp(1, PRIVATE_TTL_CAP_SECS),
        };
    }

    // Resolve the opt-in + TTL. `X-LiteSpeed-Cache-Control` wins; otherwise — and
    // only when configured — a standard `Cache-Control: public` opts in (so a
    // non-LiteSpeed app gets cached like any standards-compliant shared cache).
    let ttl = if let Some(t) = ls_public_ttl {
        t
    } else if honor_standard_cc && std.public {
        match std.shared_ttl() {
            // No max-age/s-maxage at all ⇒ "public" with our default TTL.
            None => cfg.default_public_ttl.as_secs() as u32,
            // `public, max-age=0` / `s-maxage=0` is "publicly cacheable but immediately
            // stale" — caching it for the DEFAULT TTL would over-serve a page the app
            // marked must-revalidate. Bypass (NOT the X-LiteSpeed convention where
            // max-age=0 means "use the default"). This only affects the standard-CC path.
            Some(0) => return Disposition::Bypass("cc-max-age-zero"),
            Some(t) => t,
        }
    } else {
        return Disposition::Bypass("not-opted-in");
    };

    // NOTE: `X-LiteSpeed-Vary` and `Set-Cookie` are NOT bypassed here. The glue keys the
    // entry by the declared public-vary cookies and strips `Set-Cookie` from the stored copy
    // (with a session-cookie guard) — bypassing here would make the app uncacheable.

    // Resolve the stale windows: app-declared (capped) or the configured default.
    // A response marked `must-revalidate` / `proxy-revalidate` MUST NOT be served
    // stale once expired (RFC 9111 §5.2.2.2), so our configured DEFAULT windows are
    // suppressed for it — an EXPLICIT app-declared SWR/SIE still applies (that
    // combination is the app's own call). (no-cache already bypassed above.)
    let default_stale = if std.must_revalidate {
        0
    } else {
        cfg.default_stale_secs
    };
    let default_sie = if std.must_revalidate {
        0
    } else {
        cfg.default_sie_secs
    };
    let stale = if decl_stale > 0 {
        decl_stale
    } else {
        default_stale
    };
    let stale_secs = stale.min(cfg.max_stale_secs);
    let sie = if decl_sie > 0 { decl_sie } else { default_sie };
    let stale_if_error_secs = sie.min(cfg.max_stale_if_error_secs);

    Disposition::StorePublic {
        ttl_secs: ttl,
        stale_secs,
        stale_if_error_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderName, HeaderValue, Method};

    fn cfg() -> StoreConfig {
        StoreConfig::default()
    }

    fn hdrs(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_static(k),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    /// A public store with no stale windows (the common X-LiteSpeed-only case).
    fn sp(ttl: u32) -> Disposition {
        Disposition::StorePublic {
            ttl_secs: ttl,
            stale_secs: 0,
            stale_if_error_secs: 0,
        }
    }

    #[test]
    fn public_opt_in_is_stored() {
        let h = hdrs(&[("x-litespeed-cache-control", "public,max-age=120")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            sp(120)
        );
    }

    #[test]
    fn default_sie_window_applies_when_app_declares_none() {
        // The app never emits stale-if-error (XenForo doesn't), so the configured
        // default is what arms the backend-5xx fallback at all.
        let mut c = cfg();
        c.default_sie_secs = 3600;
        let h = hdrs(&[("x-litespeed-cache-control", "public,max-age=120")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &c, false),
            Disposition::StorePublic {
                ttl_secs: 120,
                stale_secs: 0,
                stale_if_error_secs: 3600
            }
        );
        // An app-declared window still wins over the default…
        let h = hdrs(&[(
            "x-litespeed-cache-control",
            "public,max-age=120,stale-if-error=60",
        )]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &c, false),
            Disposition::StorePublic {
                ttl_secs: 120,
                stale_secs: 0,
                stale_if_error_secs: 60
            }
        );
        // …and the hard cap bounds both sources.
        c.default_sie_secs = 1_000_000;
        let h = hdrs(&[("x-litespeed-cache-control", "public,max-age=120")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &c, false),
            Disposition::StorePublic {
                ttl_secs: 120,
                stale_secs: 0,
                stale_if_error_secs: c.max_stale_if_error_secs,
            }
        );
    }

    #[test]
    fn must_revalidate_suppresses_default_stale_windows() {
        // The app opts a page in via X-LiteSpeed but ALSO sends a standard
        // `Cache-Control: must-revalidate` — our configured default SWR/SIE must NOT
        // be injected (RFC 9111 §5.2.2.2: no serving stale once expired).
        let mut c = cfg();
        c.default_stale_secs = 30;
        c.default_sie_secs = 3600;
        let h = hdrs(&[
            ("x-litespeed-cache-control", "public,max-age=120"),
            ("cache-control", "must-revalidate"),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &c, false),
            Disposition::StorePublic {
                ttl_secs: 120,
                stale_secs: 0,
                stale_if_error_secs: 0
            }
        );
        // proxy-revalidate behaves the same.
        let h = hdrs(&[
            ("x-litespeed-cache-control", "public,max-age=120"),
            ("cache-control", "proxy-revalidate"),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &c, false),
            Disposition::StorePublic {
                ttl_secs: 120,
                stale_secs: 0,
                stale_if_error_secs: 0
            }
        );
        // But an EXPLICIT app-declared window still applies even with must-revalidate
        // (the app combining them owns that choice).
        let h = hdrs(&[
            (
                "x-litespeed-cache-control",
                "public,max-age=120,stale-if-error=45",
            ),
            ("cache-control", "must-revalidate"),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &c, false),
            Disposition::StorePublic {
                ttl_secs: 120,
                stale_secs: 0,
                stale_if_error_secs: 45
            }
        );
    }

    #[test]
    fn public_default_ttl_resolved() {
        let h = hdrs(&[("x-litespeed-cache-control", "public")]);
        let d = classify_response(&Method::GET, 200, &h, false, &cfg(), false);
        assert_eq!(d, sp(900));
    }

    #[test]
    fn no_control_header_bypasses() {
        let d = classify_response(&Method::GET, 200, &HeaderMap::new(), false, &cfg(), false);
        assert_eq!(d, Disposition::Bypass("not-opted-in"));
    }

    #[test]
    fn post_bypasses_by_default() {
        let h = hdrs(&[("x-litespeed-cache-control", "public,max-age=120")]);
        assert_eq!(
            classify_response(&Method::POST, 200, &h, false, &cfg(), false),
            Disposition::Bypass("method")
        );
    }

    #[test]
    fn no_cache_env_bypasses() {
        let h = hdrs(&[("x-litespeed-cache-control", "public,max-age=120")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, true, &cfg(), false),
            Disposition::Bypass("env-no-cache")
        );
    }

    #[test]
    fn non_cacheable_status_bypasses() {
        let h = hdrs(&[("x-litespeed-cache-control", "public,max-age=120")]);
        assert_eq!(
            classify_response(&Method::GET, 500, &h, false, &cfg(), false),
            Disposition::Bypass("status")
        );
    }

    #[test]
    fn private_deferred_when_tier_disabled() {
        let h = hdrs(&[("x-litespeed-cache-control", "private,max-age=120")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            Disposition::Bypass("private-deferred")
        );
    }

    fn private_cfg() -> StoreConfig {
        StoreConfig {
            private_enabled: true,
            default_private_ttl: std::time::Duration::from_secs(60),
            ..StoreConfig::default()
        }
    }

    #[test]
    fn private_stores_when_tier_enabled() {
        let h = hdrs(&[("x-litespeed-cache-control", "private,max-age=120")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &private_cfg(), false),
            Disposition::StorePrivate { ttl_secs: 120 }
        );
        // No max-age ⇒ the configured default private TTL.
        let h = hdrs(&[("x-litespeed-cache-control", "private")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &private_cfg(), false),
            Disposition::StorePrivate { ttl_secs: 60 }
        );
        // The hard cap bounds whatever the app declares.
        let h = hdrs(&[("x-litespeed-cache-control", "private,max-age=86400")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &private_cfg(), false),
            Disposition::StorePrivate {
                ttl_secs: PRIVATE_TTL_CAP_SECS
            }
        );
    }

    #[test]
    fn private_optin_outranks_std_private_but_not_no_store() {
        // The app marks the page `private` for browsers while opting into the
        // origin's per-session tier — the LSWS contract (X-LiteSpeed wins).
        let h = hdrs(&[
            ("x-litespeed-cache-control", "private,max-age=60"),
            ("cache-control", "private, max-age=0"),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &private_cfg(), false),
            Disposition::StorePrivate { ttl_secs: 60 }
        );
        // no-store / no-cache still veto everything.
        let h = hdrs(&[
            ("x-litespeed-cache-control", "private,max-age=60"),
            ("cache-control", "private, no-store"),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &private_cfg(), false),
            Disposition::Bypass("cache-control")
        );
        // [E=no-cache] (AJAX/api/sensitive) hard-bypasses the private tier too.
        let h = hdrs(&[("x-litespeed-cache-control", "private,max-age=60")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, true, &private_cfg(), false),
            Disposition::Bypass("env-no-cache")
        );
    }

    #[test]
    fn vary_is_storable_glue_keys_it() {
        // classify no longer bypasses on vary; the glue keys by the vary cookies.
        let h = hdrs(&[
            ("x-litespeed-cache-control", "public,max-age=120"),
            ("x-litespeed-vary", "cookie=xf_style_variation"),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            sp(120)
        );
    }

    #[test]
    fn set_cookie_is_storable_glue_strips_it() {
        // classify no longer bypasses on Set-Cookie; the glue strips it from the
        // stored copy (and guards against session cookies).
        let h = hdrs(&[
            ("x-litespeed-cache-control", "public,max-age=120"),
            ("set-cookie", "xf_csrf=abc; Path=/"),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            sp(120)
        );
    }

    #[test]
    fn cache_control_no_store_backstop() {
        let h = hdrs(&[
            ("x-litespeed-cache-control", "public,max-age=120"),
            ("cache-control", "no-store, private"),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            Disposition::Bypass("cache-control")
        );
    }

    #[test]
    fn head_is_allowed() {
        let h = hdrs(&[("x-litespeed-cache-control", "public,max-age=60")]);
        assert_eq!(
            classify_response(&Method::HEAD, 200, &h, false, &cfg(), false),
            sp(60)
        );
    }

    #[test]
    fn repeated_control_any_no_cache_wins() {
        // Two X-LiteSpeed-Cache-Control values; the no-cache one must force a bypass even
        // though a public one is also present.
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-litespeed-cache-control"),
            HeaderValue::from_static("public,max-age=120"),
        );
        h.append(
            HeaderName::from_static("x-litespeed-cache-control"),
            HeaderValue::from_static("no-cache"),
        );
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            Disposition::Bypass("no-cache")
        );
    }

    #[test]
    fn repeated_public_uses_smallest_ttl() {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-litespeed-cache-control"),
            HeaderValue::from_static("public,max-age=300"),
        );
        h.append(
            HeaderName::from_static("x-litespeed-cache-control"),
            HeaderValue::from_static("public,max-age=60"),
        );
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            sp(60)
        );
    }

    #[test]
    fn repeated_cache_control_backstop_on_any_value() {
        // A second standard Cache-Control line carrying no-store must veto a public LSCache.
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-litespeed-cache-control"),
            HeaderValue::from_static("public,max-age=120"),
        );
        h.append(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=120"),
        );
        h.append(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            Disposition::Bypass("cache-control")
        );
    }

    #[test]
    fn standard_cc_public_opts_in_only_when_enabled() {
        // moontimenow style: standard public + max-age, NO X-LiteSpeed header.
        let h = hdrs(&[(
            "cache-control",
            "public, max-age=3600, stale-while-revalidate=3600",
        )]);
        // Default cfg (honor_standard_cc=false): not opted in.
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            Disposition::Bypass("not-opted-in")
        );
        // With the flag: opt in via standard CC, ttl=3600, swr=3600 (under cap).
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), true),
            Disposition::StorePublic {
                ttl_secs: 3600,
                stale_secs: 3600,
                stale_if_error_secs: 0
            }
        );
    }

    #[test]
    fn standard_cc_max_age_zero_bypasses_not_default_ttl() {
        // `public, max-age=0` is "cacheable but immediately stale" — must NOT be stored for
        // the default 900s (that was the bug). The X-LiteSpeed convention (0 = default) does
        // not apply to the standard-CC path.
        let h = hdrs(&[("cache-control", "public, max-age=0")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), true),
            Disposition::Bypass("cc-max-age-zero")
        );
        // s-maxage=0 (shared TTL zero) likewise bypasses.
        let h2 = hdrs(&[("cache-control", "public, max-age=60, s-maxage=0")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h2, false, &cfg(), true),
            Disposition::Bypass("cc-max-age-zero")
        );
    }

    #[test]
    fn standard_cc_s_maxage_preferred_for_ttl() {
        // Shared-cache TTL (s-maxage) is what an origin cache should use.
        let h = hdrs(&[("cache-control", "public, max-age=60, s-maxage=600")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), true),
            sp(600)
        );
    }

    #[test]
    fn standard_cc_no_store_vetoes_even_with_flag() {
        let h = hdrs(&[("cache-control", "public, max-age=60, no-store")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), true),
            Disposition::Bypass("cache-control")
        );
    }

    #[test]
    fn stale_windows_threaded_from_standard_cc_on_litespeed_app() {
        // Forum style: X-LiteSpeed public(ttl) + standard CC carries swr/sie.
        let h = hdrs(&[
            ("x-litespeed-cache-control", "public, max-age=300"),
            (
                "cache-control",
                "public, max-age=300, s-maxage=300, stale-while-revalidate=600, stale-if-error=3600",
            ),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &cfg(), false),
            Disposition::StorePublic {
                ttl_secs: 300,
                stale_secs: 600,
                stale_if_error_secs: 3600
            }
        );
    }

    #[test]
    fn stale_windows_capped() {
        let mut c = cfg();
        c.max_stale_secs = 600;
        c.max_stale_if_error_secs = 1800;
        let h = hdrs(&[
            ("x-litespeed-cache-control", "public, max-age=300"),
            (
                "cache-control",
                "stale-while-revalidate=86400, stale-if-error=86400",
            ),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &c, false),
            Disposition::StorePublic {
                ttl_secs: 300,
                stale_secs: 600,
                stale_if_error_secs: 1800
            }
        );
    }

    #[test]
    fn default_stale_applied_when_app_declares_none() {
        let mut c = cfg();
        c.default_stale_secs = 120;
        let h = hdrs(&[("x-litespeed-cache-control", "public, max-age=300")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &c, false),
            Disposition::StorePublic {
                ttl_secs: 300,
                stale_secs: 120,
                stale_if_error_secs: 0
            }
        );
    }

    #[test]
    fn duplicate_standard_freshness_keeps_first_value_across_and_within_fields() {
        let within = hdrs(&[("cache-control", "public, max-age=0, max-age=300")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &within, false, &cfg(), true),
            Disposition::Bypass("cc-max-age-zero")
        );

        let mut repeated = HeaderMap::new();
        repeated.append(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=0"),
        );
        repeated.append(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=300"),
        );
        assert_eq!(
            classify_response(&Method::GET, 200, &repeated, false, &cfg(), true),
            Disposition::Bypass("cc-max-age-zero")
        );
    }

    #[test]
    fn qualified_standard_restrictions_bypass_all_public_opt_ins() {
        let standard = hdrs(&[("cache-control", "public, max-age=60, private=\"x-user\"")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &standard, false, &cfg(), true),
            Disposition::Bypass("cache-control")
        );

        let mut litespeed = hdrs(&[("x-litespeed-cache-control", "public, max-age=60")]);
        litespeed.append(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=60"),
        );
        litespeed.append(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache=\"set-cookie\""),
        );
        assert_eq!(
            classify_response(&Method::GET, 200, &litespeed, false, &cfg(), false),
            Disposition::Bypass("cache-control")
        );
    }

    #[test]
    fn s_maxage_suppresses_configured_default_stale_windows() {
        let mut c = cfg();
        c.default_stale_secs = 30;
        c.default_sie_secs = 600;
        let h = hdrs(&[("cache-control", "public, s-maxage=60")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &h, false, &c, true),
            Disposition::StorePublic {
                ttl_secs: 60,
                stale_secs: 0,
                stale_if_error_secs: 0,
            }
        );

        let explicit = hdrs(&[("cache-control", "public, s-maxage=60, stale-if-error=45")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &explicit, false, &c, true),
            Disposition::StorePublic {
                ttl_secs: 60,
                stale_secs: 0,
                stale_if_error_secs: 45,
            }
        );
    }

    #[test]
    fn quoted_extension_contents_cannot_opt_in_or_veto_caching() {
        let hidden_public = hdrs(&[("cache-control", "extension=\"ignore, public, max-age=300\"")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &hidden_public, false, &cfg(), true),
            Disposition::Bypass("not-opted-in")
        );

        let hidden_ls_public = hdrs(&[(
            "x-litespeed-cache-control",
            "extension=\"ignore, public, max-age=300\"",
        )]);
        assert_eq!(
            classify_response(&Method::GET, 200, &hidden_ls_public, false, &cfg(), false),
            Disposition::Bypass("not-opted-in")
        );

        let opaque_no_cache = hdrs(&[
            ("x-litespeed-cache-control", "public, max-age=60"),
            ("cache-control", "extension=\"ignore, no-cache\""),
        ]);
        assert_eq!(
            classify_response(&Method::GET, 200, &opaque_no_cache, false, &cfg(), false),
            sp(60)
        );

        let malformed = hdrs(&[("cache-control", "public, extension=\"unterminated")]);
        assert_eq!(
            classify_response(&Method::GET, 200, &malformed, false, &cfg(), true),
            Disposition::Bypass("cache-control")
        );
    }
}
