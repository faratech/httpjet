//! Pipeline glue for the origin full-page cache ([`hj_pagecache`]).
//!
//! Two entry points, called from `dispatch()`:
//! - [`cache_lookup`] — runs after the rewrite/ACL stage but **before** any
//!   backend (LSAPI/proxy/static). On a hit it returns a ready [`Response`];
//!   the caller short-circuits dispatch.
//! - [`cache_store`] — runs after a terminal handler produced a response. It
//!   honors `X-LiteSpeed-Purge`, decides cacheability, buffers + stores the
//!   (uncompressed) body when eligible, and **strips** the internal
//!   `X-LiteSpeed-*` control headers so they never reach the client / Cloudflare.
//!
//! Public GET responses (plus opted-in 404/410/303 and the per-session private tier). The body is
//! canonicalized to identity at store time, then shrunk in place by the background dictionary
//! recompress (`spawn_dict_recompress`); a hit serves a precompressed variant when one has been
//! filled (`hit.rs`), else decodes and compresses per serve.

use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http::header::{
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, DATE, ETAG, LOCATION, SET_COOKIE,
    TRANSFER_ENCODING,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use http_body_util::BodyExt;

use std::borrow::Cow;

use hj_compress::{ACCEPT_ENCODING_ENV, AcceptEncoding, Encoding, decode_bytes};
use hj_core::{Body, FileBody, ReqCtx, Request, Response};
use hj_pagecache::{
    CachedResponse, Disposition, PageBody, PageScope, Purge, QsStrip, classify_response,
    compute_vary_value_with_defaults, normalize_query, parse_purge, parse_std_cache_control,
    parse_tags, parse_vary, public_with_vary,
};
use hj_rewrite::{CacheKeyModifier, Htaccess, chain_cacheable_for_default};

use crate::state::{DictSkip, ServerState, XfCapsuleSafeGetMode};

mod hit;
mod singleflight;

pub use singleflight::{Enter, InflightLeader, InflightRegistry, RefreshRegistry, RefreshStart};

const HDR_CACHE_CONTROL: &str = "x-litespeed-cache-control";
const HDR_TAG: &str = "x-litespeed-tag";
const HDR_VARY: &str = "x-litespeed-vary";
const HDR_PURGE: &str = "x-litespeed-purge";
const HDR_XF_CAPSULE: &str = "x-wf-capsule";
const HDR_XF_CAPSULE_TAGS: &str = "x-wf-capsule-tags";
const CAPSULE_HYDRATE_TOKEN: &str = "account-nav-v1";
const CAPSULE_KEY_PREFIX: &str = "/__hj_xf_capsule/account-nav-v1";
const CAPSULE_MEMBER_COOKIE: &str = "xf_wf_capsule_member";
const CAPSULE_BYPASS_COOKIE: &str = "xf_wf_capsule_bypass";
const CAPSULE_TAG: &str = "xf_capsule";
const CAPSULE_SHELL_TAG: &str = "xf_capsule_shell";
pub(super) const HDR_CACHE_STATUS: HeaderName = HeaderName::from_static("x-litespeed-cache");
const HDR_XF_CAPSULE_STATUS: HeaderName = HeaderName::from_static("x-wf-capsule");
const HDR_XF_HOT_PATH: HeaderName = HeaderName::from_static("x-wf-hot-path");
const HDR_XF_SHELL_AGE: HeaderName = HeaderName::from_static("x-wf-shell-age");

/// Lowercased request host (port stripped), falling back to the resolved vhost
/// name. Used as the host component of the cache key / identity guard.
///
/// Uses the IPv6-aware [`hj_core::host_without_port`] — a naive `split(':')` would
/// mangle a `[::1]:443` Host header to `[` (or empty) and feed that to the
/// self-redirect cache guard.
pub fn request_host(req: &Request, ctx: &ReqCtx) -> String {
    // SAME precedence as pipeline::dispatch's `route_key` (Host header first, then the URI
    // authority): the two MUST agree, else a request whose Host and absolute-form authority
    // disagree (h2 `:authority` vs an absolute-form `:path`, or h1 absolute-form) routes by one
    // host but computes `host_foreign` by the other — skipping the foreign-host CDN-cache
    // protection. Keying by the routed Host also keeps the identity guard consistent with
    // routing. (RFC 9110 §7.4: the Host/authority is authoritative for the target.)
    let raw: &str = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().host())
        .unwrap_or(&ctx.vhost_name);
    let h = hj_core::host_without_port(raw);
    // A port-only or empty authority (e.g. a bare ":443" Host) normalizes to "" — fall back
    // to the resolved vhost name so the self-redirect guard + the identity guard never run
    // against an empty host (which would make a self-redirect look like a different host).
    if h.is_empty() {
        ctx.vhost_name.to_ascii_lowercase()
    } else {
        h
    }
}

/// The raw value of a named cookie in the request `Cookie` header (first exact-name
/// match, value trimmed). `None` when absent. Cookie names are case-sensitive in PHP.
fn cookie_value<'a>(cookie: Option<&'a str>, name: &str) -> Option<&'a str> {
    if name.is_empty() {
        return None;
    }
    // #616/#656: PHP's `$_COOKIE` view, so a mangled xf.session/xf[user counts as the
    // private cookie here too.
    hj_pagecache::php_cookie_lookup(cookie?, name).map(|(_, _, v)| v)
}

/// FNV-1a 64 with a caller-chosen basis — the private tier derives TWO
/// independent hashes of the session value (different bases) so the effective
/// owner discriminant in the exact-Eq cache key is 128 bits wide: a cross-session
/// collision would need both to collide at once. No raw session token is stored.
fn fnv64(bytes: &[u8], basis: u64) -> u64 {
    let mut h = basis;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
const OWNER_BASIS_A: u64 = 0xcbf2_9ce4_8422_2325; // standard FNV-1a offset basis
const OWNER_BASIS_B: u64 = 0x6c62_272e_07bb_0142; // FNV-0 of "chongo <Landon ..." tail — independent start

/// How the private tier routes a request.
pub(crate) enum PrivateRoute {
    /// Not a private-tier request (tier off / no logged-in marker), or a logged-in
    /// request for an allowlisted visitor-invariant endpoint
    /// (`--page-cache-shared-paths`, canary-admitted): public path.
    Public,
    /// Logged-in with the tier ON, but unkeyable (no session value) or the vhost
    /// forbids private caching — NEVER serve or store cache for this request.
    /// (A logged-in request must never touch PUBLIC entries: the rendered page
    /// differs per login state, so falling back to public would serve the guest
    /// page to a member the moment the `.htaccess` no-cache marker narrows.)
    Bypass,
    /// Private path: `owner` keys the entry; `owner2` is the second independent
    /// hash carried in the key's vary slot (see [`fnv64`]).
    Private { owner: u64, owner2: String },
}

fn entry_scope_matches_route(entry: &CachedResponse, route: &PrivateRoute) -> bool {
    match route {
        PrivateRoute::Private { owner, .. } => {
            entry.scope == (PageScope::Private { owner_hash: *owner })
        }
        PrivateRoute::Public => matches!(entry.scope, PageScope::Public),
        PrivateRoute::Bypass => false,
    }
}

fn private_route(
    state: &ServerState,
    ctx: &ReqCtx,
    store: &hj_pagecache::PageStore,
    cc: &CacheCtx<'_>,
    count_shared_metrics: bool,
) -> PrivateRoute {
    let cfg = store.config();
    let cookie = cc.cookie;
    if !cfg.private_enabled {
        return PrivateRoute::Public;
    }
    // (2026-10-04) EITHER logged-in marker makes this a logged-in request. XenForo sets
    // `xf_user` only for "stay logged in"; a session-only login carries just `xf_session`,
    // and that visitor is a member too. Keying on `xf_user` alone routed those requests
    // PUBLIC and served them the cached GUEST page with `public, max-age=604800` (verified
    // with a minted member session, 22:30 UTC). pagecache.php already treats either cookie
    // as non-guest; this makes httpjet agree. Guests that happen to carry `xf_session`
    // (post-logout, after a POST) now render through PHP, where XF's own page cache serves
    // them — a short detour, never a wrong page.
    let session = cookie_value(cookie, &cfg.private_session_cookie).filter(|s| !s.is_empty());
    if cookie_value(cookie, &cfg.private_user_cookie).is_none() && session.is_none() {
        return PrivateRoute::Public;
    }
    // (shared-paths) Logged-in, but the request targets an allowlisted visitor-invariant
    // endpoint (`--page-cache-shared-paths`) and the sticky canary admits it: route PUBLIC
    // so members share the one public entry — for BOTH lookup and store (the two calls
    // are deterministic on the same inputs, so they can never disagree). Everything the
    // public path already enforces still applies downstream: `vhost_allows_public`,
    // `no_cache_env`, `chain_cacheable_for_default`, the per-entry identity guard in
    // `PageStore::get_entry`, and the store-side Set-Cookie strip + `sets_private_cookie`
    // refusal + vary guards in `cache_store`.
    if shared_path_public_allows(state, store, cc, count_shared_metrics) {
        return PrivateRoute::Public;
    }
    // Logged-in from here on. The vhost must explicitly allow private caching.
    let vhost_private = match ctx.vhost.cache_policy.as_ref() {
        Some(p) => p.enable_cache && p.enable_private,
        None => false,
    };
    // (#249) A context-level `<cachePolicy>` disabling PRIVATE caching denies it
    // for requests under its URI prefix, same as the public pair.
    if !vhost_private || context_denies_cache(ctx, cc.req_path, true) {
        return PrivateRoute::Bypass;
    }
    match session {
        Some(sess) => PrivateRoute::Private {
            owner: fnv64(sess.as_bytes(), OWNER_BASIS_A),
            owner2: format!("s={:016x}", fnv64(sess.as_bytes(), OWNER_BASIS_B)),
        },
        None => PrivateRoute::Bypass,
    }
}

/// (shared-paths) True when this request matches a `--page-cache-shared-paths`
/// matcher AND the sticky member canary admits it. Matching endpoints are
/// visitor-invariant by operator assertion (HMAC-gated image proxies), so a
/// member request routing PUBLIC shares one entry across guests and every
/// member session instead of duplicating bytes per session and re-rendering
/// each member's first view through PHP. `count` gates the metrics so only the
/// once-per-request lookup site bumps them — the store/peer-fill re-derivations
/// of the same routing decision stay uncounted.
fn shared_path_public_allows(
    state: &ServerState,
    store: &hj_pagecache::PageStore,
    cc: &CacheCtx<'_>,
    count: bool,
) -> bool {
    let cfg = store.config();
    if cfg.shared_public_paths.is_empty() {
        return false;
    }
    if !cfg
        .shared_public_paths
        .iter()
        .any(|m| m.matches(cc.req_path, cc.req_query))
    {
        return false;
    }
    if !shared_path_canary_allows(cc, store) {
        if count {
            state
                .metrics
                .page_cache_shared_path_canary_skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return false;
    }
    if count {
        state
            .metrics
            .page_cache_shared_path_public_routes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    true
}

/// (shared-paths) Deterministic member canary — the exact
/// [`capsule_member_canary_allows`] pattern: bucket by a hash of the stable
/// user/session cookie value only, never `cc.identity` (which includes the
/// request path), so a member is admitted or excluded consistently across
/// every allowlisted URL within one session.
fn shared_path_canary_allows(cc: &CacheCtx<'_>, store: &hj_pagecache::PageStore) -> bool {
    let pct = store.config().shared_paths_canary_percent;
    if pct >= 100 {
        return true;
    }
    if pct == 0 {
        return false;
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    if let Some(user_cookie) = cookie_value(cc.cookie, &store.config().private_user_cookie) {
        user_cookie.hash(&mut h);
    } else if let Some(session_cookie) =
        cookie_value(cc.cookie, &store.config().private_session_cookie)
    {
        session_cookie.hash(&mut h);
    }
    h.finish() % 100 < pct as u64
}

/// True when the rewrite engine marked this request not-cacheable
/// (`E=no-cache:1` or `E=Cache-Control:no-cache`, set by `.htaccess` for
/// logged-in / AJAX / api / 5xx paths).
fn no_cache_env(ctx: &ReqCtx) -> bool {
    ctx.get_env("no-cache").is_some()
        || ctx
            .get_env("Cache-Control")
            .is_some_and(|v| v.to_ascii_lowercase().contains("no-cache"))
}

/// Whether this vhost may serve/store PUBLIC cache entries. An explicit per-vhost
/// `<cache>` block always decides; a vhost that declares NO block inherits the
/// "default cache policy" (the server cache module's default — OLS's inherited
/// behavior) only when `default_vhost_public` is configured. This is the gate-1
/// that lets a blockless vhost (e.g. moontimenow) cache at all.
/// (#249) A CONTEXT-level `<cachePolicy>` that disables public caching forbids
/// entries under its URI prefix on top of the vhost decision (the live search/ai
/// proxy contexts declare all six flags 0).
fn vhost_allows_public(ctx: &ReqCtx, store: &hj_pagecache::PageStore, path: &str) -> bool {
    let vhost_ok = match ctx.vhost.cache_policy.as_ref() {
        Some(p) => p.enable_cache && p.enable_public,
        None => store.config().is_standards_vhost(&ctx.vhost_name),
    };
    vhost_ok && !context_denies_cache(ctx, path, false)
}

/// (#249) True when a `<context>` whose `<cachePolicy>` disables caching matches
/// `path` (segment-boundary match, same matcher as routing). `private=true`
/// checks the private pair; false the public pair.
fn context_denies_cache(ctx: &ReqCtx, path: &str, private: bool) -> bool {
    ctx.vhost.contexts.iter().any(|c| {
        // (Tier 2) A sub_filter context bypasses the cache entirely: the cache
        // hot path must never serve entries whose filtering depends on the
        // transform vec running on a path it may not see.
        if c.enabled
            && c.sub_filter.as_ref().is_some_and(|s| s.is_active())
            && crate::pipeline::context_uri_matches(path, &c.uri)
        {
            return true;
        }
        let Some(p) = c.cache_policy else {
            return false;
        };
        let disabled = if private {
            !p.enable_private_cache || !p.check_private_cache
        } else {
            !p.enable_cache || !p.check_public_cache
        };
        disabled && crate::pipeline::context_uri_matches(path, &c.uri)
    })
}

/// Collect the chain's `CacheKeyModify` ops into the page-cache key's qs-strip set, in a single
/// pass over the chain — without folding the whole [`hj_rewrite::CacheDirectives`] (its
/// `disabled_paths` Vec + the duplicate `key_modifiers` clone) just to read the modifiers.
fn chain_qs_strip(chain: &[Arc<Htaccess>]) -> Vec<QsStrip> {
    let mut out = Vec::new();
    for h in chain {
        for m in &h.cache_key_modifiers {
            out.push(match m {
                CacheKeyModifier::StripQs(n) => QsStrip::Exact(n.clone()),
                CacheKeyModifier::StripQsPrefix(p) => QsStrip::Prefix(p.clone()),
            });
        }
    }
    out
}

/// The normalized-query key component, single-sourced so the lookup and store keys always agree.
/// A query-less request needs no qs-strip set at all (`normalize_query` returns `""` for an empty
/// query), so we skip building it — the common forum hit allocates nothing for the cache key here.
fn normalized_query_for<'q>(chain: &[Arc<Htaccess>], req_query: &'q str) -> Cow<'q, str> {
    if req_query.is_empty() {
        Cow::Borrowed("")
    } else {
        normalize_query(req_query, &chain_qs_strip(chain))
    }
}

fn is_control_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        HDR_CACHE_CONTROL | HDR_TAG | HDR_VARY | HDR_PURGE | HDR_XF_CAPSULE | HDR_XF_CAPSULE_TAGS
    )
}

/// Whether `headers` carries any internal control header (see [`is_control_header`]).
pub(crate) fn has_control_header(headers: &HeaderMap) -> bool {
    [
        HDR_CACHE_CONTROL,
        HDR_TAG,
        HDR_VARY,
        HDR_PURGE,
        HDR_XF_CAPSULE,
        HDR_XF_CAPSULE_TAGS,
    ]
    .iter()
    .any(|h| headers.contains_key(*h))
}

/// Execute every `X-LiteSpeed-Purge` directive in `headers` against `store`.
fn execute_purges(store: &hj_pagecache::PageStore, headers: &HeaderMap) {
    for p in headers
        .get_all(HDR_PURGE)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        match parse_purge(p) {
            Purge::All => store.purge_all(),
            Purge::Tags(tags) => {
                let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
                store.purge_tags(&refs);
            }
        }
    }
}

/// Terminal-response funnel for paths that never reach [`cache_store`] (generated
/// error pages, redirects, extension responses): execute the purges a backend or a
/// `Header always set` emitted, then strip every internal control header. Strip
/// happens with or without a page cache; it is idempotent, and a response that went
/// through `cache_store` carries nothing left to act on.
/// Whether `headers` carry an `X-LiteSpeed-Purge` directive.
pub(crate) fn has_purge_header(headers: &HeaderMap) -> bool {
    headers.contains_key(HDR_PURGE)
}

/// Strip the control headers from an on-core static response that carries no purge.
pub(crate) fn strip_static_control_headers(headers: &mut HeaderMap) {
    strip_control_headers(headers);
}

pub(crate) fn settle_control_headers(state: &ServerState, headers: &mut HeaderMap) {
    if !has_control_header(headers) {
        return;
    }
    if let Some(store) = state.page_cache.as_ref() {
        execute_purges(store, headers);
    }
    // The capsule status marker shares the control header's name: a capsule hit's
    // `hit…` stamp is egress (the deploy capsule gate reads it), not a directive (#932).
    let status = headers
        .get(HDR_XF_CAPSULE_STATUS)
        .filter(|v| is_capsule_status_marker(v.as_bytes()))
        .cloned();
    strip_control_headers(headers);
    if let Some(status) = status {
        headers.insert(HDR_XF_CAPSULE_STATUS, status);
    }
}

/// A value `mark_capsule` stamps: `hit` or `hit,<qualifier>`.
fn is_capsule_status_marker(value: &[u8]) -> bool {
    value == b"hit" || value.starts_with(b"hit,")
}

/// Remove the internal `X-LiteSpeed-*` control headers so they never reach the
/// client / Cloudflare. (`Cache-Control` / `CDN-Cache-Control` are NOT touched —
/// Cloudflare needs them.)
fn strip_control_headers(headers: &mut HeaderMap) {
    headers.remove(HDR_CACHE_CONTROL);
    headers.remove(HDR_TAG);
    headers.remove(HDR_VARY);
    headers.remove(HDR_PURGE);
    headers.remove(HDR_XF_CAPSULE);
    headers.remove(HDR_XF_CAPSULE_TAGS);
}

/// The request-invariant cache inputs shared by [`cache_lookup`] + [`cache_store`].
///
/// Built once in `dispatch()` (after rewrite/ACL resolve the path, identity, and
/// htaccess chain, while `req` is still owned) and threaded unchanged to the one
/// lookup + three store sites — so the lookup key, the store key, and the
/// collision-guard identity can never drift apart. All fields are `Copy`
/// references into `dispatch` locals; the struct lives only for the cache-relevant
/// tail of dispatch. `host` is a key input for the store but only feeds the
/// identity guard on lookup (the key is by canonical vhost name — see `cache_lookup`).
#[derive(Clone, Copy)]
pub struct CacheCtx<'a> {
    /// Whether this request is allowed to participate in the page cache at all.
    /// This single route gate applies to both lookup and store so a request that
    /// is excluded before dispatch cannot accidentally populate an empty key.
    pub enabled: bool,
    pub method: &'a Method,
    pub host: &'a str,
    pub cookie: Option<&'a str>,
    pub identity: &'a str,
    pub req_path: &'a str,
    pub req_query: &'a str,
    pub chain: &'a [Arc<Htaccess>],
    pub render_epoch: u64,
    pub has_range: bool,
    /// (#275) The PUBLIC vary discriminant (`compute_vary_value` over the
    /// configured vary cookies), computed ONCE where the CacheCtx is built —
    /// `build_cache_key` + `capsule_key` used to re-split the whole Cookie
    /// header per call (2-3× per request). `None` ⇒ compute lazily from
    /// `cookie` (identical semantics; the memo is an optimization, never a
    /// correctness dependency).
    pub vary_value: Option<&'a str>,
    /// The request Host only matched the listener's `*` catch-all (not an exact vhostMap
    /// domain) and isn't the default vhost's own name — so it is FOREIGN to the resolved
    /// vhost. The cache keys by the resolved vhost, so a foreign host would otherwise be
    /// served (or would populate) the default vhost's cached entry, masking the backend's
    /// canonical redirect and leaking one brand's page under another's hostname. When set,
    /// the lookup degrades to a miss and the store is skipped — mirroring LiteSpeed LSCache,
    /// whose key embeds the request Host so a foreign host simply misses.
    pub host_foreign: bool,
    /// The raw first `Origin` header value (lossy-decoded, `None` = absent,
    /// `Some("")` = present-but-empty). Only consulted when the applied chain
    /// reads `Origin` — see [`request_vary_suffix`].
    pub origin: Option<&'a str>,
    /// The User-Agent CLASS key fragment when the applied chain reads User-Agent and
    /// the request matched at least one UA condition (see
    /// `rewrite_glue::page_cache_ua_class`); `None` keeps the historic key.
    pub ua_class: Option<&'a str>,
    /// (#617/#618) Fold of every other chain-read request header (Accept,
    /// Referer, X-*, plus Origin from inline/pre-rewrite sources), computed by
    /// `rewrite_glue::page_cache_header_vary`; `None` keeps the historic key.
    pub header_vary: Option<&'a str>,
    /// A rewrite `[E=Cache-Vary:…]` / `[E=Cache-Control:vary=…]` ran for this request
    /// ([`is_cache_vary_env`], recorded where the env was merged). Only then is `ctx.env`
    /// scanned for per-URL vary names.
    pub env_vary: bool,
}

/// Try to look the request up in the page cache. `Some(resp)` ⇒ serve the hit
/// and short-circuit dispatch; `None` ⇒ proceed to the backend.
///
/// `method` and `host` are captured by the caller once (before the request is
/// consumed by a handler) and passed identically to [`cache_store`], so the
/// lookup and store keys always agree.
///
/// CRITICAL: `req_path`/`req_query` MUST be the **original** request URI
/// (pre-rewrite), exactly as LiteSpeed LSCache keys by `REQUEST_URI` — NOT the
/// rewrite-resolved path. A front controller (XenForo: `RewriteRule ^.*$
/// index.php`) collapses every page to `/index.php`, so keying by the rewritten
/// path would give all pages ONE cache entry and serve the wrong page.
///
/// `force_miss` is set for a background stale-while-revalidate refresh: the request
/// is re-issued internally to RENDER + store a fresh entry, so it must pass the
/// bypass gates + compute the key exactly as a real request but never serve the
/// (still-stale) stored entry — it returns `Miss` so the render path runs.
/// The Accept-Encoding the COMPRESSION layers (page-cache variant store/serve + the
/// on-serve Compress transform) should negotiate against for this response — NOT what
/// lsphp/XenForo sees (cgi.rs always hands PHP `HTTP_ACCEPT_ENCODING=identity`). With `--cf-send-zstd`
/// on, a trusted-proxy (Cloudflare) peer is forced to `zstd` regardless of its forwarded
/// AE, keeping the stored variant + served encoding in lockstep with the transform. CF
/// decodes the zstd and re-encodes per browser at its edge; untrusted (direct) clients
/// always use their real AE, so none is ever handed an unrequested encoding.
/// (#237) A private body must never be storable by a SHARED cache. Cloudflare
/// gives `Cloudflare-CDN-Cache-Control` (then `CDN-Cache-Control`) priority over
/// `Cache-Control`, so a backend that sent e.g.
/// `Cloudflare-CDN-Cache-Control: max-age=86400` alongside the app's own
/// Cache-Control would have that directive replayed from the stored headers on
/// every private hit — letting CF pin one member's page at the shared edge even
/// though we force `private, no-store` on Cache-Control itself. Strip the
/// CDN-priority variants wherever we force the private guarantee.
fn strip_shared_cdn_cache_directives(headers: &mut http::HeaderMap) {
    headers.remove("cloudflare-cdn-cache-control");
    headers.remove("cdn-cache-control");
}

fn egress_ae<'a>(state: &ServerState, ctx: &'a ReqCtx) -> &'a str {
    // A non-empty AE that accepts no coding (an empty one takes the brotli fill
    // default): a `no-gzip` hit is served identity, never a stored variant.
    if hj_compress::no_gzip(ctx) {
        "identity"
    } else if state.compress.cf_send_zstd() && ctx.trusted_proxy {
        "zstd"
    } else {
        ctx.get_env(ACCEPT_ENCODING_ENV).unwrap_or("")
    }
}

/// Who is looking up. A request that misses on the on-core fast path falls through to
/// `dispatch`, which looks up again — so only one of the two may record the admission
/// sighting and the hit/miss counters, or a single request counts twice and the
/// "seen twice" admission bar passes on first sight.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LookupMode {
    /// The full pipeline: records the sighting and the counters on every lookup.
    Full,
    /// The on-core fast path: records only a hit it serves; a miss or a stale entry is
    /// left, unbuilt and uncounted, to the full lookup that follows.
    FastPath,
}

pub fn cache_lookup(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    if_none_match: Option<&str>,
    force_miss: bool,
    gates: Option<&SharedCacheGates>,
) -> CacheOutcome {
    lookup(
        state,
        ctx,
        cc,
        if_none_match,
        force_miss,
        gates,
        LookupMode::Full,
    )
}

/// The on-core fast path's probe: returns [`CacheOutcome::Hit`] for a fresh servable entry
/// and [`CacheOutcome::Miss`] (or `Bypass`) for everything else, which the caller hands to
/// `dispatch` for the counted lookup.
pub fn cache_lookup_fast_path(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    if_none_match: Option<&str>,
) -> CacheOutcome {
    lookup(
        state,
        ctx,
        cc,
        if_none_match,
        false,
        None,
        LookupMode::FastPath,
    )
}

fn lookup(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    if_none_match: Option<&str>,
    force_miss: bool,
    gates: Option<&SharedCacheGates>,
    mode: LookupMode,
) -> CacheOutcome {
    if !cc.enabled {
        return CacheOutcome::Bypass;
    }
    #[cfg(feature = "otel")]
    let _trace_stage = crate::otel::stage(crate::otel::StageKind::CacheLookup);
    // (#5) The raw request host is no longer a key input (it now keys by the canonical
    // vhost name); it survives inside the caller-built `identity` guard and the serve-time
    // self-redirect re-check below.
    let &CacheCtx {
        method,
        host,
        req_path,
        req_query,
        chain,
        host_foreign,
        ..
    } = cc;
    // A Host foreign to the resolved vhost (only matched the `*` catch-all) must never be
    // served the default vhost's cached page — that is the cross-host content leak. Degrade
    // to a miss so the backend runs and issues its own host-canonical response.
    if host_foreign {
        return CacheOutcome::Bypass;
    }
    let Some(store) = state.page_cache.as_ref() else {
        return CacheOutcome::Bypass;
    };

    // Only idempotent reads are ever served from cache.
    if method != Method::GET && method != Method::HEAD {
        return CacheOutcome::Bypass;
    }
    // A Range request bypasses the page cache: a cached full 200 served to a Range client ignores
    // the range (range-aware cache hits aren't implemented), so the backend must produce the 206.
    // The main pipeline gates this before calling, but the on-core fast path does not — enforce the
    // invariant centrally so a cookieless Range request can never be answered a full 200 from cache.
    if cc.has_range {
        return CacheOutcome::Bypass;
    }
    // (capsule key-space guard, #95) A path under the synthetic capsule prefix would key-collide
    // with a dedicated capsule entry's slot — never serve/store it on the public path.
    if is_capsule_reserved_path(req_path) {
        return CacheOutcome::Bypass;
    }
    // Private-tier routing decides which key space (if any) this request may
    // touch; a logged-in request can NEVER read public entries (route Bypass
    // when it can't be safely keyed) — EXCEPT the explicit
    // `--page-cache-shared-paths` allowlist of visitor-invariant endpoints,
    // which routes Public. Inert (always Public) with the flag off.
    let route = private_route(state, ctx, store, cc, true);
    if matches!(route, PrivateRoute::Bypass) {
        return CacheOutcome::Bypass;
    }
    // Vhost must opt into (public) caching; the private path carries its own
    // per-vhost `enable_private` gate inside `private_route`.
    if matches!(route, PrivateRoute::Public)
        && !gates
            .map(|g| g.vhost_allows_public)
            .unwrap_or_else(|| vhost_allows_public(ctx, store, req_path))
    {
        return CacheOutcome::Bypass;
    }
    // Per-request no-cache marker (logged-in / AJAX): always hit the backend.
    // (#320) Shared verdicts from the pipeline when provided.
    let no_cache = gates
        .map(|g| g.no_cache_env)
        .unwrap_or_else(|| no_cache_env(ctx));
    if no_cache {
        return CacheOutcome::Bypass;
    }
    // Per-directory `.htaccess` cacheability (CacheLookup on, no CacheDisable). In the
    // default-cache-policy mode, an unspecified CacheLookup defaults to on (a non-LiteSpeed
    // app never writes it) — an explicit CacheLookup off / CacheDisable still wins.
    let chain_ok = gates.map(|g| g.chain_cacheable).unwrap_or_else(|| {
        chain_cacheable_for_default(
            chain,
            req_path,
            store.config().is_standards_vhost(&ctx.vhost_name),
        )
    });
    if !chain_ok {
        return CacheOutcome::Bypass;
    }

    // The historic key path; only a URL that may vary (lock-free pre-filter) is extended.
    let key = configuration_key(state, build_cache_key(ctx, cc, store, &route));
    let key_hash = hash_key(&key);
    let resolved_identity: Cow<'_, str>;
    let (key, key_hash, identity, varied_base) = if !url_vary_may_apply(cc, store, key_hash) {
        (key, key_hash, cc.identity, None)
    } else {
        let Some(r) = resolve_url_vary(ctx, cc, store, &route, key, key_hash) else {
            return CacheOutcome::Bypass;
        };
        resolved_identity = r.identity;
        (r.key, r.key_hash, &*resolved_identity, r.varied_base)
    };
    // (W-TinyLFU) Record this cacheable lookup in the admission sketch — true access frequency
    // (hit OR miss), so the store-admission gate can reject one-hit-wonders. Cheap atomic bumps.
    // The fast path records only the hits it serves (see `LookupMode`).
    if mode == LookupMode::Full {
        state.page_cache_admission.record(key_hash);
    }
    // A background refresh re-runs the request only to RENDER + store: it has passed the
    // same bypass gates and computed the same key as a real request, but must not serve the
    // stale entry (that would loop). Returning Miss drives the single-flight render + store.
    if force_miss {
        return CacheOutcome::Miss(key_hash);
    }
    let now = Instant::now();
    let probed = match mode {
        LookupMode::Full => store.get_entry_hashed(key_hash, &key, identity, now),
        LookupMode::FastPath => store.get_entry_hashed_uncounted(key_hash, &key, identity, now),
    };
    if let (
        Some(base_hash),
        hj_pagecache::EntryState::Fresh(_) | hj_pagecache::EntryState::Stale(_),
    ) = (varied_base, &probed)
    {
        store.url_vary_touch(base_hash, key_hash);
    }
    let mut entry = match probed {
        hj_pagecache::EntryState::Fresh(e) => e,
        // Dispatch serves the stale body and spawns the refresh; don't build it twice.
        hj_pagecache::EntryState::Stale(_) if mode == LookupMode::FastPath => {
            return CacheOutcome::Miss(key_hash);
        }
        hj_pagecache::EntryState::Stale(mut e) => {
            // (dedup) A dict-compressed body is undecodable under a changed/absent dict → miss.
            if e.dict_gen != 0 && matching_dict(state, e.dict_gen).is_none() {
                return CacheOutcome::Miss(key_hash);
            }
            // (serve-time safety net) A stale self-redirect is still refused — degrade to a
            // miss so the backend re-renders instead of replaying a redirect loop.
            if entry_is_self_redirect(&e, ctx.is_tls, host, req_path, req_query) {
                return CacheOutcome::Miss(key_hash);
            }
            // A private page is re-rendered, never served stale: the stale egress
            // below is public (#1016).
            if !matches!(route, PrivateRoute::Public) || !entry_scope_matches_route(&e, &route) {
                return CacheOutcome::Miss(key_hash);
            }
            // Serve the stale body immediately; the caller spawns ONE background refresh
            // keyed by `key_hash`. Do NOT 304 here even on a conditional GET: a 304 would
            // tell CF "still fresh" and re-pin the stale copy — serve the body + a short/
            // no-store egress so CF re-asks and picks up the refreshed entry.
            let accept_encoding = AcceptEncoding::parse(egress_ae(state, ctx));
            let Some(mut resp) = build_hit_response_with_successor_retry(
                state,
                store,
                &key,
                identity,
                &mut e,
                now,
                accept_encoding,
                method == Method::HEAD,
                |candidate| {
                    (candidate.dict_gen == 0 || matching_dict(state, candidate.dict_gen).is_some())
                        && !entry_is_self_redirect(candidate, ctx.is_tls, host, req_path, req_query)
                        && entry_scope_matches_route(candidate, &route)
                },
            ) else {
                // (fail-closed) The stale entry couldn't be rendered (dict-decode failure / empty
                // body / a dead body file) — degrade to a miss so the backend re-renders instead
                // of serving a blank. The helper removed it only if this exact version stayed live.
                return CacheOutcome::Miss(key_hash);
            };
            note_variant_serve(state, &resp);
            apply_stale_cf_egress(resp.headers_mut());
            return CacheOutcome::StaleHit(resp, key_hash);
        }
        // Past the SWR window (error-only fallback) or absent/collision: render the backend.
        // stale-if-error (serving the retained entry on a 5xx render) is a planned follow-up;
        // the entry stays retained for its `sie` window so it can be used then.
        hj_pagecache::EntryState::ErrorOnly(_) | hj_pagecache::EntryState::Miss => {
            return CacheOutcome::Miss(key_hash);
        }
    };
    // ---- Fresh hit ----
    // (dedup) A dict-compressed body is only serveable if the loaded dictionary can decode it;
    // a changed/absent dict ⇒ degrade to a miss (never serve undecodable bytes).
    if entry.dict_gen != 0 && matching_dict(state, entry.dict_gen).is_none() {
        return CacheOutcome::Miss(key_hash);
    }
    // (serve-time safety net) Never REPLAY a stored self-redirect: an entry whose `Location`
    // is the request's own URL is an infinite loop. The store guard refuses to cache these,
    // but a pre-guard / transiently-stored entry can survive for its TTL (the homepage
    // self-redirect incident). Re-checking here degrades it to a MISS.
    if entry_is_self_redirect(&entry, ctx.is_tls, host, req_path, req_query) {
        return CacheOutcome::Miss(key_hash);
    }
    if !entry_scope_matches_route(&entry, &route) {
        return CacheOutcome::Miss(key_hash);
    }
    // Conditional revalidation: when CF's edge copy goes stale-but-revalidatable it sends
    // a conditional GET (If-None-Match) to the origin. If it matches our stored validator,
    // answer 304 (validators only) instead of re-shipping the full 50–200 KB HTML body
    // across the CF→origin hop. The store path synthesizes a weak ETag when the backend
    // gives none (XenForo pages usually don't), so this is what makes CF revalidation cheap.
    // RFC 9110 §13.2.1: preconditions are ignored when the response would not be 2xx.
    if let (Some(inm), Some(etag), true) = (
        if_none_match,
        hit::entry_etag(&entry),
        (200..300).contains(&entry.status),
    ) {
        if hit::if_none_match_matches(inm, etag) {
            let mut resp = hit::not_modified(
                &entry,
                etag,
                now,
                inm,
                AcceptEncoding::parse(egress_ae(state, ctx)),
                &state.compress,
            );
            // Apply the SAME private-tier guarantees as the 200 hit below: a private-routed
            // 304 must match its owner (else degrade to a miss, never cross-serve), and must
            // NEVER advertise a shared-cacheable Cache-Control — force `private, no-store` so
            // a 304's validators/freshness can't be stored/replayed by Cloudflare cross-user.
            if let PrivateRoute::Private { owner, .. } = &route {
                if entry.scope != (hj_pagecache::PageScope::Private { owner_hash: *owner }) {
                    return CacheOutcome::Miss(key_hash);
                }
                force_cache_control(resp.headers_mut(), "private, no-store");
                strip_shared_cdn_cache_directives(resp.headers_mut());
            }
            maybe_spawn_finalize(state, ctx, &key, key_hash, &entry);
            record_fast_path_hit(state, store, mode, key_hash);
            return CacheOutcome::Hit(resp);
        }
    }
    // (PC1) The client's Accept-Encoding (or forced zstd for a CF peer) selects a variant.
    let accept_encoding = AcceptEncoding::parse(egress_ae(state, ctx));
    // (PC2-lazy) The admitting store wrote this entry identity-only so compression CPU + variant
    // RAM is spent only on entries that prove hot by being SERVED. On the first hit of such an
    // entry, kick off ONE bounded background task to compute + re-insert the variant (preserving
    // the original stored_at/TTL); later hits serve it. Fires at most once per entry (the
    // re-insert sets `variants_filled`) and only when a variant could actually help.
    let capsule_shell = capsule_entry_shell_capable(&entry);
    if !entry.variants_filled
        && !hj_compress::no_gzip(ctx)
        && hit::eligible_for_variants(
            state,
            &entry.headers,
            variant_eligibility_len(&entry),
            accept_encoding,
            capsule_shell,
        )
    {
        spawn_variant_fill(
            state,
            key.clone(),
            key_hash,
            entry.clone(),
            accept_encoding,
            capsule_shell,
        );
    }
    match build_hit_response_with_successor_retry(
        state,
        store,
        &key,
        identity,
        &mut entry,
        now,
        accept_encoding,
        method == Method::HEAD,
        |candidate| {
            (candidate.dict_gen == 0 || matching_dict(state, candidate.dict_gen).is_some())
                && !entry_is_self_redirect(candidate, ctx.is_tls, host, req_path, req_query)
                && entry_scope_matches_route(candidate, &route)
        },
    ) {
        Some(mut resp) => {
            note_variant_serve(state, &resp);
            // Belt + suspenders on the cardinal rule: a private-routed lookup must
            // only ever surface a Private entry whose owner matches the key (the
            // exact-Eq key already guarantees this; a scope mismatch means a logic
            // bug somewhere — degrade to a miss, never serve).
            if let PrivateRoute::Private { owner, .. } = &route {
                if entry.scope != (hj_pagecache::PageScope::Private { owner_hash: *owner }) {
                    return CacheOutcome::Miss(key_hash);
                }
                resp.headers_mut()
                    .insert(HDR_CACHE_STATUS, HeaderValue::from_static("hit,private"));
                // A private (logged-in) body must NEVER be storable by a SHARED cache
                // (Cloudflare): force `private, no-store` on egress regardless of the app's
                // stored Cache-Control, so a missing/`public` header on a private page can't
                // leak one member's rendered HTML cross-user. httpjet's own origin private
                // tier is driven by X-LiteSpeed-Cache-Control, independent of this header.
                force_cache_control(resp.headers_mut(), "private, no-store");
                strip_shared_cdn_cache_directives(resp.headers_mut());
            }
            // Pin/open the selected stored body before a background recompress can
            // replace and unlink its pathname. The response keeps that inode alive.
            maybe_spawn_finalize(state, ctx, &key, key_hash, &entry);
            record_fast_path_hit(state, store, mode, key_hash);
            CacheOutcome::Hit(resp)
        }
        // (fail-closed) A fresh entry that can't be rendered (dict-decode failure / empty body /
        // a dead body file) is dropped and degrades to a miss so the backend re-renders — never
        // serve a blank 200, never keep retrying a dead file.
        None => CacheOutcome::Miss(key_hash),
    }
}

/// A fast-path hit ends the request, so it is the one lookup that counts: record the
/// sighting and the hit the full lookup would have recorded.
fn record_fast_path_hit(
    state: &ServerState,
    store: &hj_pagecache::PageStore,
    mode: LookupMode,
    key_hash: u64,
) {
    if mode == LookupMode::FastPath {
        store.record_hit();
        state.page_cache_admission.record(key_hash);
    }
}

/// (dedup) Whichever loaded dictionary (any vhost's) can decode an entry tagged with `dict_gen`.
/// `dict_gen == 0` (plain identity) needs no dictionary → `None`, and the body is used as-is. A
/// non-zero `dict_gen` with no loaded dict of that generation ⇒ `None`, which the callers treat as
/// "undecodable" (the lookup degrades the entry to a miss). Vhost-agnostic by design: an entry's
/// `dict_gen` alone identifies which dictionary compressed it, regardless of which vhost's entry
/// it is — see `hj_compress::PageDictRegistry`.
fn matching_dict(state: &ServerState, dict_gen: u32) -> Option<&hj_compress::PageDict> {
    state
        .page_cache_dicts
        .by_generation(dict_gen)
        .map(|d| d.as_ref())
}

fn stored_file_body(
    store: &hj_pagecache::PageStore,
    entry: &CachedResponse,
    deferred: Option<&hj_pagecache::BodyReadFailures>,
) -> Option<FileBody> {
    let f = match deferred {
        Some(failures) => store.body_file_deferred(entry, failures)?,
        None => store.body_file(entry)?,
    };
    if f.body_len == 0 {
        return None;
    }
    Some(FileBody {
        path: f.path,
        file: Some(f.file),
        len: f.file_len,
        range: Some((f.body_start, f.body_start + f.body_len as u64 - 1)),
        cached: None,
    })
}

/// Build one hit response, retrying once when a concurrent in-place enrichment
/// replaced the exact serve snapshot between lookup and body resolution. File
/// recompression preserves `stored_at` and identity but publishes a new immutable
/// file, so the old pathname may already be unlinked. Conditional invalidation
/// prevents that stale request from deleting the successor; the uncounted retry
/// then serves the successor without turning a valid cache hit into a backend miss.
/// Callers validate the lookup snapshot before entering; `valid` applies only to
/// a successor fetched after the first body-resolution attempt fails.
fn build_hit_response_with_successor_retry(
    state: &ServerState,
    store: &hj_pagecache::PageStore,
    key: &hj_pagecache::PageCacheKey,
    identity: &str,
    entry: &mut Arc<CachedResponse>,
    now: Instant,
    accept_encoding: AcceptEncoding,
    is_head: bool,
    valid: impl Fn(&CachedResponse) -> bool,
) -> Option<Response> {
    // The caller already validated its lookup snapshot. Borrow it directly: an
    // Arc bump and a second dict/redirect/scope pass on every hit buy nothing.
    let candidate = entry.as_ref();
    // A swap that retired this snapshot's file reads as a missing body here; only
    // the successor outcome below tells it apart from a genuinely lost body.
    let snapshot_failures = hj_pagecache::BodyReadFailures::default();
    if let Some(response) = hit::build_hit_response(
        candidate,
        now,
        accept_encoding,
        &state.compress,
        is_head,
        matching_dict(state, candidate.dict_gen),
        Some(store),
        || store.body_bytes_deferred(candidate, &snapshot_failures),
        || stored_file_body(store, candidate, Some(&snapshot_failures)),
    ) {
        store.settle_body_read_failures(snapshot_failures, false);
        return Some(response);
    }

    // Remove a genuinely broken current version, but never a replacement
    // published after this request obtained its snapshot.
    if store.invalidate_entry_if_current(key, entry) {
        store.settle_body_read_failures(snapshot_failures, false);
        return None;
    }
    let successor = match store.get_entry_uncounted(key, identity, now) {
        hj_pagecache::EntryState::Fresh(next)
        | hj_pagecache::EntryState::Stale(next)
        | hj_pagecache::EntryState::ErrorOnly(next) => next,
        hj_pagecache::EntryState::Miss => {
            store.settle_body_read_failures(snapshot_failures, false);
            return None;
        }
    };
    // A recompress/variant enrichment preserves the logical version. Do not
    // silently switch this request to an unrelated re-render of the same key.
    if Arc::ptr_eq(entry, &successor)
        || successor.stored_at != entry.stored_at
        || !valid(&successor)
    {
        store.settle_body_read_failures(snapshot_failures, false);
        return None;
    }
    *entry = successor;

    let candidate = entry.as_ref();
    let response = hit::build_hit_response(
        candidate,
        now,
        accept_encoding,
        &state.compress,
        is_head,
        matching_dict(state, candidate.dict_gen),
        Some(store),
        || store.body_bytes(candidate),
        || stored_file_body(store, candidate, None),
    );
    store.settle_body_read_failures(snapshot_failures, response.is_some());
    if response.is_none() {
        // The successor itself failed to resolve. Retire it only if this exact
        // snapshot is still current; another enrichment remains untouched.
        store.invalidate_entry_if_current(key, entry);
    }
    response
}

fn variant_eligibility_len(entry: &CachedResponse) -> usize {
    if entry.dict_gen == 0 {
        entry.body.len()
    } else {
        // A dict-compressed body's stored length is not the identity length. Let the
        // one-shot fill task decode it and apply the real `body.len()` gate there.
        usize::MAX
    }
}

/// (PC2-lazy) Compute and re-insert the precompressed variant for a freshly-hit, identity-only
/// entry, off the client path. Spawned at most once per key (the variant-fill [`RefreshRegistry`]
/// CAS) and globally concurrency-capped, SEPARATELY from the SWR refresh pool so a burst of fills
/// can't starve revalidations. The re-inserted entry copies EVERY field of the original verbatim
/// except the new `variants` + `variants_filled = true` — crucially keeping the original
/// `stored_at`/`ttl`/`swr`/`sie`, so the freshness window is unchanged and the identity/tag/scheme
/// guards still hold. The re-insert updates store eviction order, but serving is governed by the
/// preserved `stored_at`, so a hit near end-of-life can never resurrect the entry.
/// `variants_filled` is set even when the body yields no useful variant, so it runs once.
/// Spawn a background cache-enrichment task gated by `registry`'s per-key single-flight
/// CAS + its global concurrency cap, with the slot/permit freed when the task completes
/// (the guard moves into it). The fill pools are SEPARATE registries on purpose — a burst
/// of one class must not starve another — so the caller names the pool the task belongs
/// to. A saturated/duplicate key is silently dropped (the next hit re-spawns).
/// Handle to the tokio runtime that owns `ServerState` + the pipeline. The io_uring
/// on-core fast path (`uring::CoreHandler::fast` → `fast_serve` → `cache_lookup`)
/// runs on a **monoio** thread with NO ambient tokio reactor, so the background
/// variant-fill / SWR-refresh `tokio::spawn` panics ("there is no reactor running")
/// and `panic=abort` takes the whole process down. We capture the pipeline runtime's
/// `Handle` once at bridge setup and spawn those maintenance tasks onto it explicitly
/// (a `Handle` spawns from any thread). Unset on the pure-tokio serve path (no
/// bridge), where the ambient-runtime `tokio::spawn` fallback is correct.
static PIPELINE_RT: OnceLock<tokio::runtime::Handle> = OnceLock::new();

/// Record the tokio runtime that drives the cache/pipeline. Called once from the
/// io_uring bridge setup (inside that runtime). Idempotent.
pub(crate) fn set_pipeline_runtime(handle: tokio::runtime::Handle) {
    let _ = PIPELINE_RT.set(handle);
}

/// The ambient runtime when on one (tokio serve path / tests — also immune to a test
/// having planted, then dropped, a private runtime in `PIPELINE_RT`), else the planted
/// pipeline runtime (the monoio fast path). `None` only off-runtime before bridge setup.
pub(crate) fn pipeline_handle() -> Option<tokio::runtime::Handle> {
    tokio::runtime::Handle::try_current()
        .ok()
        .or_else(|| PIPELINE_RT.get().cloned())
}

fn spawn_guarded(
    registry: &Arc<RefreshRegistry>,
    key_hash: u64,
    fut: impl std::future::Future<Output = ()> + Send + 'static,
) -> RefreshStart {
    // Resolve the runtime BEFORE claiming the slot, so an unspawnable task can't burn the per-key
    // CAS. `pipeline_handle` prefers the AMBIENT runtime and only falls back to the planted one:
    // on the io_uring fast path there is no ambient reactor (a monoio thread), so it resolves to
    // the pipeline runtime; on the bridged/tokio path the ambient runtime IS the pipeline runtime.
    // Equivalent in prod either way, but it keeps a test from spawning onto a private runtime that
    // some other test planted in the `PIPELINE_RT` OnceLock and then dropped.
    let Some(handle) = pipeline_handle() else {
        return RefreshStart::Unavailable;
    };
    let (guard, result) = registry.try_begin_detailed(key_hash);
    let Some(guard) = guard else {
        return result;
    };
    handle.spawn(async move {
        let _guard = guard; // frees the per-key slot + the global permit on completion
        fut.await;
    });
    RefreshStart::Started
}

fn spawn_variant_fill(
    state: &Arc<ServerState>,
    key: hj_pagecache::PageCacheKey,
    key_hash: u64,
    entry: Arc<CachedResponse>,
    accept_encoding: AcceptEncoding,
    capsule_shell: bool,
) {
    let registry = state.page_cache_variant_fill.clone();
    let state = state.clone();
    spawn_guarded(&registry, key_hash, async move {
        let Some(store) = state.page_cache.as_ref() else {
            return;
        };
        // (dedup) Recover the IDENTITY to compress the variant from: resolve the stored-form
        // body without promoting it into the hot heap tier. This is a background compression
        // job, not a serve, so populating hot memory here pins bodies that may never be served
        // in identity form. A dead file just skips the fill.
        let Some(stored) = store.body_bytes_cold(&entry) else {
            return;
        };
        let body = if entry.dict_gen == 0 {
            stored
        } else {
            match matching_dict(&state, entry.dict_gen)
                .and_then(|d| d.decode(stored.as_ref(), hj_compress::MAX_DECODE as usize))
            {
                Some(v) => Bytes::from(v),
                None => return,
            }
        };
        // The same single-variant precompression the store path used to do eagerly, now deferred
        // to a proven hit. block_in_place caps concurrent compressions at --workers (no
        // spawn_blocking thread-pool oversubscription on a CPU-bound box).
        let variants = tokio::task::block_in_place(|| {
            hit::precompress_variants(
                &state,
                &entry.headers,
                &body,
                accept_encoding,
                capsule_shell,
            )
        });
        // Enrich IN PLACE only if K still holds this exact entry (identity + stored_at). If a
        // purge or an SWR refresh landed during the compression window, the fill is a NO-OP — so
        // it can never resurrect a purged entry nor clobber a fresher one. `variants_filled` is
        // set even when `variants` is empty, so the fill is attempted at most once per entry.
        // VARIANT-PRIMARY: authorize dropping the redundant identity body iff a stored
        // variant losslessly round-trips back to it. Verify the EXACT variant
        // resolve_identity would pick (the first decodable one) reproduces the identity
        // byte-for-byte — defense against any codec edge case before discarding the only
        // other copy. `derive_len` carries the identity length for the store's accounting.
        for (token, _) in &variants {
            if let Some(index) = variant_codec_index(token) {
                state.metrics.pagecache_variant_fills[index]
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        // The store only uses this for an InMem body (a file-tier body keeps its tmpfs
        // identity), so skip the verify decode everywhere else.
        let derive_len = matches!(entry.body, hj_pagecache::PageBody::InMem(_))
            .then(|| {
                variants
                    .iter()
                    .find_map(|(tok, b)| Encoding::from_token(tok).and_then(|e| decode_bytes(e, b)))
                    .filter(|id| id.as_slice() == body.as_ref())
                    .and(u32::try_from(body.len()).ok())
            })
            .flatten();
        store.fill_variants(&key, &entry.identity, entry.stored_at, variants, derive_len);
    });
}

/// Codecs a stored precompressed variant can carry, indexing the per-codec variant counters.
const VARIANT_CODECS: [&str; 3] = ["zstd", "br", "gzip"];

fn variant_codec_index(token: &str) -> Option<usize> {
    VARIANT_CODECS.iter().position(|codec| *codec == token)
}

/// Count a hit served from a stored variant. A hit response only carries Content-Encoding when
/// it came from one; identity hits are compressed later by the per-serve transform.
fn note_variant_serve(state: &ServerState, resp: &Response) {
    if let Some(index) = resp
        .headers()
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .and_then(variant_codec_index)
    {
        state.metrics.pagecache_variant_serves[index]
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Where the finalize task gets the identity bytes to compress.
enum FinalizeBody {
    /// The store path already holds the identity body — hand it straight to the task, no re-read.
    Ready(Bytes),
    /// The hit path only has the resident entry; resolve its stored body INSIDE the task, off the
    /// client path (a cold body costs a tmpfs read).
    Resident(Arc<CachedResponse>),
}

/// One stored version a finalize job may shrink, named by the store's own
/// `(key, identity, stored_at)` guard.
struct FinalizeTarget {
    key: hj_pagecache::PageCacheKey,
    key_hash: u64,
    identity: String,
    stored_at: Instant,
}

/// Dict-compress stored identity entries on the bounded background pool. Every target holds
/// the SAME body (a capsule render is stored under its dedicated key and its public mirror),
/// so the body is encoded once and swapped into each target that is still current. An
/// unsuccessful attempt leaves a resident marker, while a saturated worker pool leaves the
/// targets unmarked so a later hit can retry. Every guard is keyed on `(key, identity,
/// stored_at)`, so a purge, an SWR refresh, or a fresher re-store landing during the
/// compression window makes that target a no-op — it can neither resurrect a purged entry
/// nor clobber a newer one.
fn spawn_finalize(
    state: &Arc<ServerState>,
    targets: Vec<FinalizeTarget>,
    body: FinalizeBody,
    content_type: &str,
    vhost: String,
    dict: Arc<hj_compress::PageDict>,
) {
    let Some(guard_id) = targets.first().map(|t| t.key_hash) else {
        return;
    };
    let Some(store) = state.page_cache.clone() else {
        return;
    };
    let metrics = state
        .page_cache_dict_metrics
        .entry(vhost.clone())
        .or_insert_with(|| Arc::new(crate::state::DictRecompressMetrics::default()))
        .clone();
    // Bodies that can't clear the savings gate — an image or archive, or a tiny body such as
    // a cached redirect's empty one — skip the encode (and the pool slot) outright, marked so
    // the hit-path retry doesn't queue them again.
    let body_len = match &body {
        FinalizeBody::Ready(bytes) => bytes.len(),
        FinalizeBody::Resident(entry) => entry.body.len(),
    };
    let ineligible = if (body_len as u64) < hj_compress::DEFAULT_MIN_SIZE {
        Some(DictSkip::TooSmall)
    } else if !state.compress.is_compressible_type(content_type) {
        Some(DictSkip::ContentType)
    } else {
        None
    };
    if let Some(why) = ineligible {
        let marked = targets
            .iter()
            .filter(|t| store.mark_dict_compression_attempted(&t.key, &t.identity, t.stored_at))
            .count();
        metrics.skip(why, marked as u64);
        return;
    }
    let registry = state.page_cache_dict_fill.clone();
    let warn_vhost = vhost;
    let task_metrics = metrics.clone();
    let start = spawn_guarded(&registry, guard_id, async move {
        let claimed = targets.len();
        let targets: Vec<FinalizeTarget> = targets
            .into_iter()
            .filter(|t| store.mark_dict_compression_attempted(&t.key, &t.identity, t.stored_at))
            .collect();
        task_metrics.skip(DictSkip::Claimed, (claimed - targets.len()) as u64);
        if targets.is_empty() {
            return;
        }
        task_metrics
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bytes = match body {
            FinalizeBody::Ready(bytes) => Some(bytes),
            FinalizeBody::Resident(entry) => store.body_bytes_cold(&entry),
        };
        let Some(bytes) = bytes else {
            task_metrics.skip(DictSkip::BodyMissing, targets.len() as u64);
            return;
        };
        task_metrics
            .input_bytes
            .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
        // block_in_place caps concurrent compressions at --workers (no spawn_blocking pool
        // oversubscription on a CPU-bound box), same as the variant fill.
        // Savings gate: a dict-stored body costs a decode on every AE-mismatch hit and on
        // every variant fill, so the swap must buy real RAM. An incompressible body (already-
        // minified JSON blobs, binary-ish payloads) that shrinks <12.5% stays the identity file.
        let compressed = match tokio::task::block_in_place(|| dict.encode(&bytes)) {
            Some(c) if c.len() <= bytes.len().saturating_sub(bytes.len() / 8) => Bytes::from(c),
            _ => {
                task_metrics.skip(DictSkip::Savings, targets.len() as u64);
                return;
            }
        };
        let compressed_len = compressed.len() as u64;
        for target in targets {
            if store.fill_recompress_disk(
                &target.key,
                &target.identity,
                target.stored_at,
                compressed.clone(),
                dict.generation(),
            ) {
                task_metrics
                    .completed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                task_metrics
                    .output_bytes
                    .fetch_add(compressed_len, std::sync::atomic::Ordering::Relaxed);
                task_metrics.saved_bytes.fetch_add(
                    (bytes.len() as u64).saturating_sub(compressed_len),
                    std::sync::atomic::Ordering::Relaxed,
                );
            } else {
                task_metrics.skip(DictSkip::LostRace, 1);
            }
        }
    });
    match start {
        RefreshStart::Started => {
            metrics
                .queued
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result => {
            metrics
                .dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if result == RefreshStart::Saturated
                && rate_limit_dict_saturation_warning(
                    &metrics.last_saturation_warn_epoch_secs,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |elapsed| elapsed.as_secs()),
                )
            {
                tracing::warn!(
                    target: "hj_pagecache",
                    vhost = %warn_vhost,
                    in_flight = registry.inflight_count(),
                    "dictionary recompress pool saturated; storing identity body"
                );
            }
        }
    }
}

const DICT_SATURATION_WARN_INTERVAL_SECS: u64 = 60;

fn rate_limit_dict_saturation_warning(last: &std::sync::atomic::AtomicU64, now: u64) -> bool {
    last.try_update(
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Relaxed,
        |previous| {
            (now.saturating_sub(previous) >= DICT_SATURATION_WARN_INTERVAL_SECS).then_some(now)
        },
    )
    .is_ok()
}

/// (hit path, RETRY net) Compress an entry that reached a hit still uncompressed — it was stored
/// while the dict pool was saturated, was restored by the boot scan from an identity file written
/// before this change, or predates a dictionary being configured for its vhost. The common case is
/// already compressed at store time by [`spawn_store_finalize`], so this normally finds nothing to
/// do.
fn maybe_spawn_finalize(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    key: &hj_pagecache::PageCacheKey,
    key_hash: u64,
    entry: &Arc<CachedResponse>,
) {
    if entry.dict_gen != 0 || entry.dict_compression_attempted() {
        return;
    }
    let vhost = ctx.vhost_name.to_ascii_lowercase();
    let Some(dict) = state.page_cache_dicts.for_vhost(&vhost).cloned() else {
        return;
    };
    spawn_finalize(
        state,
        vec![FinalizeTarget {
            key: key.clone(),
            key_hash,
            identity: entry.identity.clone(),
            stored_at: entry.stored_at,
        }],
        FinalizeBody::Resident(entry.clone()),
        stored_content_type(&entry.headers),
        vhost,
        dict,
    );
}

/// The `Content-Type` of a stored entry's headers ("" when absent).
fn stored_content_type(headers: &[(HeaderName, HeaderValue)]) -> &str {
    headers
        .iter()
        .find(|(name, _)| name == CONTENT_TYPE)
        .and_then(|(_, value)| value.to_str().ok())
        .unwrap_or("")
}

/// (store path) Dict-compress a just-stored entry immediately, off the client path.
///
/// Compression is NOT deferred to the entry's first hit. The file tier is the binding capacity
/// constraint (it runs at its `--page-cache-disk-mem` cap and evicts continuously), and an entry
/// that is never hit still occupies the tier for its whole TTL — so hit-gating meant the tail that
/// fills the tier was exactly the part that never got compressed, and the identity body (~9-17x
/// larger) evicted entries that would otherwise have survived. Paying the zstd CPU on a store the
/// cache may never serve is the cheaper side of that trade: the pool is bounded and the encode is
/// ~100x cheaper than the PHP render that produced the body.
///
/// The encode stays on the background pool rather than running inline before the store: at the
/// configured dictionary level (default 12; production windowsforum=6, moontimenow=3) it costs
/// milliseconds to tens of ms on a real page, which would land directly on the TTFB of every
/// cacheable miss. The entry is therefore stored as identity and shrunk moments later, in place.
fn spawn_store_finalize(
    state: &Arc<ServerState>,
    vhost_name: &str,
    targets: Vec<FinalizeTarget>,
    body: &Bytes,
    content_type: &str,
) {
    if targets.is_empty() {
        return;
    }
    let vhost = vhost_name.to_ascii_lowercase();
    let Some(dict) = state.page_cache_dicts.for_vhost(&vhost).cloned() else {
        return;
    };
    spawn_finalize(
        state,
        targets,
        FinalizeBody::Ready(body.clone()),
        content_type,
        vhost,
        dict,
    );
}

/// Stable hash of a page-cache key → the single-flight / refresh coordination id.
/// (Also the admission-sketch id — the boot warm scan pre-records each loaded key.)
/// This is the SAME FNV-1a pass `hj_pagecache` uses as the storage id
/// (`CacheKeyId`), computed once per key here and reused by the store layer — a
/// former std SipHash pass over the same fields ran alongside it on every lookup
/// and store. Only a coordination/locator id either way: exact-key Eq + identity
/// guard decide serving on any collision.
pub(crate) fn hash_key(key: &hj_pagecache::PageCacheKey) -> u64 {
    hj_pagecache::key_hash(key)
}

/// Size-weighted W-TinyLFU admission bar: the minimum frequency estimate for a response to be
/// worth storing. `base` (tunable via `--page-cache-admit-threshold`) + 1 per 256 KiB, so a large
/// object must prove more reuse than a small one. `base=2` = "store on the 2nd sighting"
/// (miss-miss-hit, rejects one-hit-wonders); `base=1` = "store on the 1st sighting" (miss-hit,
/// cache everything — viable now that dedup makes a stored body ~9× cheaper, leaving
/// dict-compress CPU as the only added cost).
fn admission_threshold(base: u8, body_len: u64) -> u8 {
    const LARGE_OBJ_UNIT: u64 = 256 * 1024;
    (base as u64 + body_len / LARGE_OBJ_UNIT).min(u8::MAX as u64) as u8
}

/// True if a cached 3xx entry redirects to the request's own URL (a loop).
fn entry_is_self_redirect(
    entry: &CachedResponse,
    is_tls: bool,
    host: &str,
    req_path: &str,
    req_query: &str,
) -> bool {
    if !(300..400).contains(&entry.status) {
        return false;
    }
    entry
        .headers
        .iter()
        .find(|(k, _)| k == LOCATION)
        .and_then(|(_, v)| v.to_str().ok())
        .is_some_and(|loc| location_is_self(loc, is_tls, host, req_path, req_query))
}

/// Rewrite a STALE serve's egress so Cloudflare (or any shared cache) does NOT retain the
/// stale body for the backend's original `max-age`/`s-maxage`. A short public TTL (not
/// no-store: that defeated CF serve-stale/request-coalescing AND disqualified the page from
/// the browser bfcache) lets the edge absorb the burst while the background refresh
/// converges; the *next* fetch after 30s lands on the refreshed entry. Without the CDN
/// header strip a stale serve would pin stale content at the CF edge for up to the 7-day
/// s-maxage — the exact CF-poison class the origin cache must never create. The egress
/// strip beats the internal key for CF (see the cross-scheme-redirect-cf-cache-loop memory).
/// Replace a hit's Cache-Control with `value`, keeping a stored `no-transform`:
/// the compress transform reads it from the egress headers, so dropping it would
/// encode a page the app forbade transforming (#811).
fn force_cache_control(headers: &mut HeaderMap, value: &'static str) {
    let no_transform = headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|d| d.trim().eq_ignore_ascii_case("no-transform"));
    let v = if no_transform {
        HeaderValue::from_str(&format!("{value}, no-transform"))
            .unwrap_or_else(|_| HeaderValue::from_static(value))
    } else {
        HeaderValue::from_static(value)
    };
    headers.insert(http::header::CACHE_CONTROL, v);
}

fn apply_stale_cf_egress(headers: &mut HeaderMap) {
    force_cache_control(headers, "public, max-age=30, must-revalidate");
    // Reset Age to 0. `build_hit_response` stamped `Age: <entry age>`, which on a STALE
    // entry is >= the app TTL (300s..7200s). A conforming cache (RFC 9111 §4.2.3, and CF)
    // seeds current_age from Age, so `max-age=30` minus a 7200s Age arrives ALREADY EXPIRED
    // — the 30s coalescing window never engages and every request revalidates. The 30s must
    // be measured from THIS stale serve, so neutralize Age (#131).
    headers.insert(http::header::AGE, HeaderValue::from_static("0"));
    // CDN-Cache-Control overrides Cache-Control at the CF edge — drop it so our short public
    // TTL wins.
    headers.remove(HeaderName::from_static("cloudflare-cdn-cache-control"));
    headers.remove(HeaderName::from_static("cdn-cache-control"));
    // A surviving far-future `Expires` would pin the stale body on any HTTP/1.0 proxy or
    // secondary CDN that honors Expires independently of Cache-Control — drop it too (the
    // same neutralization `deny_foreign_host_cdn_caching` applies).
    headers.remove(http::header::EXPIRES);
    headers.insert(HDR_CACHE_STATUS, HeaderValue::from_static("stale"));
}

/// Build THE page-cache key for a request — the single definition shared by [`cache_lookup`],
/// [`cache_store`], and [`stale_if_error_fallback`], which MUST agree byte-for-byte: a lookup/store
/// key divergence is the cache-poisoning failure class, so every key-component change happens HERE.
/// (This is the BASE key; per-URL cookie vary extends it only in [`resolved_cache_key`] (readers)
/// and `store_cache_key` (writers), which share one suffix builder.)
///
/// Components and why:
/// - Scheme (`ctx.is_tls`): XenForo emits a scheme-conditional canonical 301 (HTTP→HTTPS) marked
///   publicly cacheable; without the scheme an HTTP-origin 301 replays to HTTPS clients — the
///   cross-scheme redirect loop.
/// - (#5) The RESOLVED vhost's canonical name, NOT the raw request Host: the router maps unknown
///   Hosts to the wildcard/default vhost, so keying by the raw value would let an attacker cycling
///   O(N) Hosts store O(N) entries and evict the legitimate set (cache-memory-exhaustion DoS). The
///   raw host still feeds the per-request identity guard. (#20) `vhost_id` is the FNV hash of the
///   canonical name so two listeners routing one hostname to different vhosts never collide.
/// - Vary slot: a PRIVATE route carries the second session-owner hash (the session subsumes
///   style/language prefs) plus the first in `private_owner`; a public route carries the
///   style/language cookie discriminant and owner 0.
/// A request whose ORIGINAL path literally begins with the synthetic capsule key prefix must
/// never be cached on the PUBLIC path: `build_cache_key` would produce a key byte-identical to a
/// dedicated capsule entry's key (`capsule_key` = prefix + `<path>`), so the two would share one
/// store slot. The per-entry identity guard already degrades that collision to a miss, but a
/// member-facing key space should not depend on a single guard — refuse the reserved prefix
/// outright (no legitimate content lives under this synthetic path). See issue #95.
fn is_capsule_reserved_path(path: &str) -> bool {
    path.starts_with(CAPSULE_KEY_PREFIX)
}

/// (#938) The request host when it is an EXACT vhostMap alias of the resolved vhost (not the
/// vhost's own name, not wildcard-routed): the backend renders the raw Host into og:url /
/// canonical links, so each alias needs its own entry — OLS LSCache hashes the Host. The alias
/// set is bounded by the configuration (a wildcard-routed host is foreign and never cached), so
/// this cannot reopen the #5 Host-cycling eviction. `None` for the canonical host, whose key and
/// identity bytes must not change (persisted file-tier entries stay valid across a deploy).
pub(crate) fn cache_alias_host<'a>(
    vhost_name: &str,
    host: &'a str,
    host_foreign: bool,
) -> Option<&'a str> {
    (!host_foreign && !host.is_empty() && !host.eq_ignore_ascii_case(vhost_name)).then_some(host)
}

fn key_host(ctx: &ReqCtx, cc: &CacheCtx<'_>) -> String {
    cache_alias_host(&ctx.vhost_name, cc.host, cc.host_foreign)
        .unwrap_or(&ctx.vhost_name)
        .to_ascii_lowercase()
}

pub(crate) fn build_cache_key(
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
    route: &PrivateRoute,
) -> hj_pagecache::PageCacheKey {
    let mut vary_value = match route {
        PrivateRoute::Private { owner2, .. } => owner2.clone(),
        _ => public_vary_value(cc, store),
    };
    vary_value.push_str(&request_vary_suffix(cc));
    let mut key = public_with_vary(
        vhost_id_hash(&ctx.vhost_name),
        ctx.is_tls,
        key_host(ctx, cc),
        cc.req_path,
        normalized_query_for(cc.chain, cc.req_query),
        vary_value,
    );
    if let PrivateRoute::Private { owner, .. } = route {
        key.private_owner = *owner;
    }
    key
}

/// (CORS) An `.htaccess` chain that reads the request `Origin` (`SetEnvIf
/// Origin`, `RewriteCond %{HTTP:Origin}`) produces origin-CONDITIONAL
/// responses — typically a reflected `Access-Control-Allow-Origin` — but a
/// stored entry replays whatever headers the FIRST storer's render produced,
/// so every later visitor would receive that request's CORS verdict. When the
/// chain reads `Origin`, fold a bounded hash of the value into the vary
/// discriminant (applied identically at lookup, store, stale-if-error, and
/// the capsule keys — they all thread this `CacheCtx`). Absent/empty Origin
/// keeps the historic base key, so caches populated before this fold stay
/// hit-able for the (dominant) no-Origin traffic.
///
/// User-Agent works the same way (#603): a chain whose rewrite conditions read the
/// UA (`RewriteCond %{HTTP_USER_AGENT} ... [E=KNOWN_CRAWLER:1]` driving
/// `Header set ... env=KNOWN_CRAWLER`) yields UA-conditional responses, so the
/// UA *class* (which conditions matched) is folded in. A request that matched none
/// keeps the historic key, so ordinary browsers keep their entries.
fn request_vary_suffix(cc: &CacheCtx<'_>) -> String {
    let reads_origin = cc
        .chain
        .iter()
        .any(|h| h.memo.vary_headers.iter().any(|v| v == "origin"));
    let mut suffix = match cc.origin {
        Some(o) if reads_origin && !o.is_empty() => {
            format!("\0origin:{:016x}", fnv64(o.as_bytes(), OWNER_BASIS_A))
        }
        _ => String::new(),
    };
    if let Some(class) = cc.ua_class {
        suffix.push_str("\0ua:");
        suffix.push_str(class);
    }
    if let Some(hdr) = cc.header_vary {
        suffix.push_str("\0hdr:");
        suffix.push_str(hdr);
    }
    suffix
}

/// Cookie names the rewrite env asks this request to vary on, as OpenLiteSpeed's cache
/// module reads them: `[E=Cache-Vary:a,b]` (env `cache-vary`, any case) and
/// `[E=Cache-Control:vary=a,b]`. Each item may carry a `cookie=` prefix.
fn env_vary_names<'c>(ctx: &'c ReqCtx, cc: &CacheCtx<'_>) -> Vec<&'c str> {
    let mut out = Vec::new();
    if !cc.env_vary {
        return out;
    }
    for (k, v) in &ctx.env {
        let Some(list) = env_vary_list(k, v) else {
            continue;
        };
        for item in list.split(',') {
            let item = item.trim();
            let item = strip_ascii_prefix(item, "cookie=").unwrap_or(item).trim();
            if !item.is_empty() {
                out.push(item);
            }
        }
    }
    out
}

/// The cookie list of an env assignment that requests a per-URL cache vary.
fn env_vary_list<'v>(key: &str, value: &'v str) -> Option<&'v str> {
    if key.eq_ignore_ascii_case("cache-vary") {
        Some(value)
    } else if key.eq_ignore_ascii_case("cache-control") || key.eq_ignore_ascii_case("cache-ctrl") {
        strip_ascii_prefix(value, "vary=")
    } else {
        None
    }
}

/// Whether an env assignment requests a per-URL cache vary (OLS `cache-vary`, or
/// `cache-control: vary=`). The pipeline records it into [`CacheCtx::env_vary`].
pub(crate) fn is_cache_vary_env(key: &str, value: &str) -> bool {
    env_vary_list(key, value).is_some()
}

/// A key extended by per-URL cookie vary, with the identity guard extended to match.
pub(crate) struct ResolvedKey<'a> {
    pub key: hj_pagecache::PageCacheKey,
    /// `hash_key(&key)`.
    pub key_hash: u64,
    pub identity: Cow<'a, str>,
    /// `Some(base hash)` when `key` is a per-URL variant of that base key.
    pub varied_base: Option<u64>,
}

impl<'a> ResolvedKey<'a> {
    fn unvaried(key: hj_pagecache::PageCacheKey, key_hash: u64, identity: &'a str) -> Self {
        ResolvedKey {
            key,
            key_hash,
            identity: Cow::Borrowed(identity),
            varied_base: None,
        }
    }
}

/// `base` (hashed `base_hash`) extended by the request's values of `names`.
fn extend_resolved<'a>(
    base: hj_pagecache::PageCacheKey,
    base_hash: u64,
    identity: &'a str,
    cookie: Option<&str>,
    names: &[String],
) -> Option<ResolvedKey<'a>> {
    if names.is_empty() {
        return Some(ResolvedKey::unvaried(base, base_hash, identity));
    }
    let suffix = hj_pagecache::urlvary::suffix(cookie, names)?;
    let key = hj_pagecache::urlvary::extend(&base, &suffix);
    Some(ResolvedKey {
        key_hash: hash_key(&key),
        key,
        identity: Cow::Owned(format!("{identity}{suffix}")),
        varied_base: Some(base_hash),
    })
}

/// THE lookup key: the base key ([`build_cache_key`] under the configuration generation),
/// extended by the cookies this URL varies on — the spec a cacheable response recorded
/// (`X-LiteSpeed-Vary: cookie=…` outside the global set) plus the rewrite env's
/// `Cache-Vary`. Every reader (dispatch, the on-core fast path, single-flight followers,
/// stale-while-revalidate, stale-if-error) goes through here, so they all agree. A URL with
/// no per-URL vary gets the base key and identity unchanged. `None` ⇒ the request cannot be
/// keyed (a vary cookie value too long, or a private route asked to vary): bypass.
///
/// The private tier and the capsule tier never hold per-URL variants: a private store of a
/// response declaring extra cookie vary is refused, so a private lookup ignores the spec.
pub(crate) fn resolved_cache_key<'a>(
    state: &ServerState,
    ctx: &ReqCtx,
    cc: &CacheCtx<'a>,
    store: &hj_pagecache::PageStore,
    route: &PrivateRoute,
) -> Option<ResolvedKey<'a>> {
    let base = configuration_key(state, build_cache_key(ctx, cc, store, route));
    let base_hash = hash_key(&base);
    resolve_url_vary(ctx, cc, store, route, base, base_hash)
}

/// [`resolved_cache_key`] given the already-built base key: the lookup builds the base key
/// exactly as before and calls this only when [`url_vary_may_apply`] says it may vary.
#[cold]
fn resolve_url_vary<'a>(
    ctx: &ReqCtx,
    cc: &CacheCtx<'a>,
    store: &hj_pagecache::PageStore,
    route: &PrivateRoute,
    base: hj_pagecache::PageCacheKey,
    base_hash: u64,
) -> Option<ResolvedKey<'a>> {
    let env = env_vary_names(ctx, cc);
    let spec = match route {
        PrivateRoute::Public => store.url_vary_names(&base, base_hash),
        _ => None,
    };
    if spec.is_none() && env.is_empty() {
        return Some(ResolvedKey::unvaried(base, base_hash, cc.identity));
    }
    let names = hj_pagecache::urlvary::normalize_names(
        spec.iter()
            .flat_map(|s| s.iter().map(String::as_str))
            .chain(env.iter().copied()),
        &store.config().vary_cookies,
    )?;
    if !names.is_empty() && !matches!(route, PrivateRoute::Public) {
        return None;
    }
    extend_resolved(base, base_hash, cc.identity, cc.cookie, &names)
}

/// Lock-free: `false` ⇒ the base key `base_hash` is final (no spec can exist for it and no
/// rewrite env asked to vary), so the caller keeps the historic key path.
#[inline]
fn url_vary_may_apply(cc: &CacheCtx<'_>, store: &hj_pagecache::PageStore, base_hash: u64) -> bool {
    cc.env_vary || store.url_vary_may_have(base_hash)
}

/// Whether this request's URL varies per-URL (a recorded spec for its public base key, or
/// the rewrite env's `Cache-Vary`). Only the capsule tier asks: it holds no variants.
fn url_vary_applies(
    state: &ServerState,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
) -> bool {
    if cc.env_vary
        && !hj_pagecache::urlvary::normalize_names(
            env_vary_names(ctx, cc),
            &store.config().vary_cookies,
        )
        .is_some_and(|n| n.is_empty())
    {
        return true;
    }
    if !store.url_vary_active() {
        return false;
    }
    // Every key family below carries this vhost id + path: one atomic load answers the
    // common case without building a key.
    if !store.url_vary_may_vary_path(vhost_id_hash(&ctx.vhost_name), cc.req_path) {
        return false;
    }
    [
        build_cache_key(ctx, cc, store, &PrivateRoute::Public),
        capsule_public_fallback_key(ctx, cc, store),
    ]
    .into_iter()
    .map(|k| configuration_key(state, k))
    .any(|base| store.url_vary_names(&base, hash_key(&base)).is_some())
}

/// The cookie vary a response (plus the rewrite env) declares for a store.
enum DeclaredVary {
    /// Every dimension is a cookie we can key; the per-URL names outside the global set
    /// (sorted; empty = only global cookies, the historic case).
    Names(Vec<String>),
    /// A non-cookie dimension, a malformed name, or too many names: never store publicly.
    /// `extra_cookie` = a cookie outside the global set was named.
    Unsupported { extra_cookie: bool },
}

impl DeclaredVary {
    fn global_only(&self) -> bool {
        matches!(self, DeclaredVary::Names(n) if n.is_empty())
    }
}

/// Every `X-LiteSpeed-Vary` line must be all cookie-vary (a backend may emit several; any
/// other dimension would under-key the entry). `env` = [`env_vary_names`].
fn declared_vary(env: Vec<&str>, headers: &HeaderMap, global: &[String]) -> DeclaredVary {
    let mut lines = headers.get_all(HDR_VARY).iter().peekable();
    if env.is_empty() && lines.peek().is_none() {
        return DeclaredVary::Names(Vec::new());
    }
    let mut all_cookie = true;
    let mut names: Vec<String> = env.iter().map(|s| s.to_string()).collect();
    for line in lines {
        // A non-UTF-8 line was skipped by the historic gate too (`filter_map(to_str)`).
        let Ok(v) = line.to_str() else { continue };
        let (n, cookie_only) = parse_vary(v);
        all_cookie &= cookie_only;
        names.extend(n);
    }
    let extra_cookie = names.iter().any(|n| !global.iter().any(|g| g == n));
    if !all_cookie {
        return DeclaredVary::Unsupported { extra_cookie };
    }
    match hj_pagecache::urlvary::normalize_names(names.iter().map(String::as_str), global) {
        Some(n) => DeclaredVary::Names(n),
        None => DeclaredVary::Unsupported { extra_cookie },
    }
}

/// The per-URL vary bookkeeping a public store commits with its entry.
struct UrlVaryCommit {
    base: hj_pagecache::PageCacheKey,
    base_hash: u64,
    names: Vec<String>,
}

struct StoreKey {
    key: hj_pagecache::PageCacheKey,
    key_hash: u64,
    identity: String,
    url_vary: Option<UrlVaryCommit>,
}

/// THE store key for a response that declared `names` (see [`declared_vary`]); `None` ⇒ the
/// request's vary cookie value cannot be keyed exactly, so nothing is stored.
fn store_cache_key(
    state: &ServerState,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
    route: &PrivateRoute,
    names: &[String],
) -> Option<StoreKey> {
    let base = configuration_key(state, build_cache_key(ctx, cc, store, route));
    let base_hash = hash_key(&base);
    if !matches!(route, PrivateRoute::Public)
        || (names.is_empty() && !store.url_vary_may_have(base_hash))
    {
        return Some(StoreKey {
            key: base,
            key_hash: base_hash,
            identity: cc.identity.to_string(),
            url_vary: None,
        });
    }
    let resolved = extend_resolved(base.clone(), base_hash, cc.identity, cc.cookie, names)?;
    let key_hash = resolved.key_hash;
    if !names.is_empty() {
        // The request that discovers (or changes) a URL's vary looked up a different key;
        // carry its admission sighting over so the variant is admitted on the same schedule
        // as any other URL rather than one render later.
        let looked_up = resolved_cache_key(state, ctx, cc, store, route).map(|r| r.key_hash);
        if looked_up != Some(key_hash) {
            state.page_cache_admission.record(key_hash);
        }
    }
    Some(StoreKey {
        identity: resolved.identity.into_owned(),
        key: resolved.key,
        key_hash,
        url_vary: Some(UrlVaryCommit {
            base,
            base_hash,
            names: names.to_vec(),
        }),
    })
}

fn configuration_key(
    state: &ServerState,
    mut key: hj_pagecache::PageCacheKey,
) -> hj_pagecache::PageCacheKey {
    if let Some(epoch) = &state.response_cache_epoch {
        key.vary_value = format!(
            "\0httpjet-config:{epoch}:{}\0{}",
            state.generation, key.vary_value
        );
    }
    key
}

#[cfg(test)]
thread_local! {
    /// Dedicated capsule keys `capsule_key` built on this thread.
    static CAPSULE_KEY_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn capsule_key(
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
) -> hj_pagecache::PageCacheKey {
    #[cfg(test)]
    CAPSULE_KEY_BUILDS.with(|n| n.set(n.get() + 1));
    let path = if cc.req_path == "/" {
        format!("{CAPSULE_KEY_PREFIX}/")
    } else {
        format!("{CAPSULE_KEY_PREFIX}{}", cc.req_path)
    };
    public_with_vary(
        vhost_id_hash(&ctx.vhost_name),
        ctx.is_tls,
        key_host(ctx, cc),
        path,
        normalized_query_for(cc.chain, cc.req_query),
        format!(
            "{}{}",
            public_vary_value(cc, store),
            request_vary_suffix(cc)
        ),
    )
}

/// (#275) The public vary discriminant for this request: the value memoized at
/// CacheCtx construction, else computed from the Cookie header exactly as
/// before (the memo is byte-identical by construction — both run
/// `compute_vary_value` over the same cookie + configured names).
fn public_vary_value(cc: &CacheCtx<'_>, store: &hj_pagecache::PageStore) -> String {
    match cc.vary_value {
        Some(v) => v.to_string(),
        None => {
            let cfg = store.config();
            compute_vary_value_with_defaults(cc.cookie, &cfg.vary_cookies, &cfg.vary_defaults)
        }
    }
}

fn capsule_public_fallback_key(
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
) -> hj_pagecache::PageCacheKey {
    public_with_vary(
        vhost_id_hash(&ctx.vhost_name),
        ctx.is_tls,
        key_host(ctx, cc),
        cc.req_path,
        normalized_query_for(cc.chain, cc.req_query),
        format!(
            "{}{}",
            capsule_public_vary_value(cc.cookie, store),
            request_vary_suffix(cc)
        ),
    )
}

fn capsule_public_vary_value(cookie: Option<&str>, store: &hj_pagecache::PageStore) -> String {
    let cfg = store.config();
    // (#320) Borrow the configured names instead of cloning every String per call;
    // compute_vary_value only reads them.
    let vary_cookies: Vec<&str> = cfg
        .vary_cookies
        .iter()
        .map(|name| name.as_str())
        .filter(|name| {
            *name != cfg.private_user_cookie.as_str()
                && *name != cfg.private_session_cookie.as_str()
                && *name != CAPSULE_MEMBER_COOKIE
                && *name != CAPSULE_BYPASS_COOKIE
                && *name != "xf_admin"
                && *name != "xf_api_key"
        })
        .collect();
    compute_vary_value_with_defaults(cookie, &vary_cookies, &cfg.vary_defaults)
}

fn capsule_vhost_allowed(state: &ServerState, ctx: &ReqCtx) -> bool {
    // (#239) CLOSED by default: the capsule tier is XenForo-specific, so an empty
    // --xf-capsule-vhosts list must DISABLE it, not silently enable it on every
    // vhost (including apps that have never heard of X-Acapsule headers). Deployed
    // configs pass an explicit list.
    state
        .xf_capsule
        .vhosts
        .contains(&ctx.vhost_name.to_ascii_lowercase())
}

fn capsule_path_allowed(state: &ServerState, path: &str, query: &str) -> bool {
    match state.xf_capsule.safe_get_mode {
        XfCapsuleSafeGetMode::Prefixes => state.xf_capsule.path_prefixes.iter().any(|prefix| {
            if prefix == "/" {
                path == "/"
            } else {
                path.starts_with(prefix)
            }
        }),
        XfCapsuleSafeGetMode::AllGetClassified => capsule_safe_get_candidate(path, query),
    }
}

fn capsule_safe_get_candidate(path: &str, query: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let trimmed = path.trim_end_matches('/');
    if path.ends_with(".php") && path != "/index.php" {
        return false;
    }
    if trimmed.ends_with("/add")
        || trimmed.ends_with("/edit")
        || trimmed.ends_with("/delete")
        || trimmed.ends_with("/approve")
        || trimmed.ends_with("/unapprove")
        || trimmed.ends_with("/report")
        || trimmed.ends_with("/watch")
        || trimmed.ends_with("/unwatch")
        || trimmed.ends_with("/mark-read")
    {
        return false;
    }

    const UNSAFE_PREFIXES: &[&str] = &[
        "/admin",
        "/api",
        "/account",
        "/login",
        "/logout",
        "/register",
        "/lost-password",
        "/two-step",
        "/conversations",
        "/direct-messages",
        "/attachments",
        "/inline-mod",
        "/approval-queue",
        "/moderation-queue",
        "/reports",
        "/payment",
        "/purchase",
        "/misc",
        "/editor",
        "/install",
    ];
    // Match a prefix only at a route boundary: the prefix is the whole path, or the byte
    // right after it is a non-alphanumeric separator (`/`, `.`, `-`, `?`, `&`, `;`, …). The
    // old `{prefix}/`-only test let hyphen/dot siblings slip through (`/admin-home`,
    // `/login-page`); a bare `starts_with` would instead over-match a longer route that merely
    // begins with the same letters (e.g. it would also swallow `/admins`). This is a strict
    // SUPERSET of the old match — it can only ever exclude MORE paths from the capsule, never
    // admit a new one. (`.php` is already rejected wholesale at the top of this fn, so the
    // former `*.php` entries here were redundant.)
    if UNSAFE_PREFIXES.iter().any(|prefix| {
        path == *prefix
            || (path.starts_with(prefix) && !path.as_bytes()[prefix.len()].is_ascii_alphanumeric())
    }) {
        return false;
    }

    let query = query.to_ascii_lowercase();
    !query.contains("_xftoken")
        && !query.contains("_xf")
        && !query.contains("token=")
        && !query.contains("logout")
        && !query.contains("login")
        && !query.contains("delete")
        && !query.contains("approve")
}

fn capsule_cookie_safe(cookie: Option<&str>) -> bool {
    cookie_value(cookie, "xf_admin").is_none()
        && cookie_value(cookie, "xf_api_key").is_none()
        && cookie_value(cookie, CAPSULE_BYPASS_COOKIE).is_none()
}

fn capsule_canary_allows(
    state: &ServerState,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
) -> bool {
    let pct = state.xf_capsule.canary_percent;
    if pct >= 100 {
        return true;
    }
    if pct == 0 {
        return false;
    }
    // Bucket by the stable per-user token so canary admission is sticky per user
    // across all paths (a member must not flicker in/out of the tier as they browse).
    // cc.identity contains the request path, so hashing it would make admission a
    // function of (user, path); only fall back to it for anonymous guests that have
    // no stable token, where per-path bucketing is the only consistent option.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    if let Some(user_cookie) = cookie_value(cc.cookie, &store.config().private_user_cookie) {
        user_cookie.hash(&mut h);
    } else if let Some(session_cookie) =
        cookie_value(cc.cookie, &store.config().private_session_cookie)
    {
        session_cookie.hash(&mut h);
    } else {
        cc.identity.hash(&mut h);
    }
    h.finish() % 100 < pct as u64
}

/// Broader than `private_route` on purpose: an empty session cookie still counts here, so
/// the capsule guards (never store a shell from, or serve a non-public entry to, a possible
/// member) err on the member side. `private_route` may route that same request public
/// because it only ever serves the guest page there.
fn capsule_member_candidate(cookie: Option<&str>, store: &hj_pagecache::PageStore) -> bool {
    cookie_value(cookie, &store.config().private_user_cookie).is_some()
        || cookie_value(cookie, &store.config().private_session_cookie).is_some()
}

fn capsule_member_canary_allows(
    state: &ServerState,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
) -> bool {
    let pct = state.xf_capsule.member_canary_percent;
    if pct >= 100 {
        return true;
    }
    if pct == 0 {
        return false;
    }

    // Sticky per-member bucketing: hash only the stable user/session token, never
    // cc.identity (which includes the request path) — otherwise the same member is
    // admitted on some URLs and excluded on others within one session.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    if let Some(user_cookie) = cookie_value(cc.cookie, &store.config().private_user_cookie) {
        user_cookie.hash(&mut h);
    } else if let Some(session_cookie) =
        cookie_value(cc.cookie, &store.config().private_session_cookie)
    {
        session_cookie.hash(&mut h);
    }
    h.finish() % 100 < pct as u64
}

fn capsule_member_lookup_allowed(
    state: &ServerState,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
    member: bool,
) -> bool {
    if !member {
        return true;
    }

    let opted_in = state.xf_capsule.allow_members
        && cookie_value(cc.cookie, CAPSULE_MEMBER_COOKIE) == Some("1");
    if !opted_in {
        return false;
    }
    if !capsule_member_canary_allows(state, cc, store) {
        // The member opted in but their deterministic bucket is outside the ramp: count it so
        // the canary denominator is visible (distinct from other bypass_not_allowed reasons).
        state
            .metrics
            .xf_capsule_canary_filtered
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return false;
    }
    true
}

fn capsule_public_fallback_allowed(
    state: &ServerState,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
) -> bool {
    capsule_member_candidate(cc.cookie, store)
        && state.xf_capsule.allow_members
        && cookie_value(cc.cookie, CAPSULE_MEMBER_COOKIE) == Some("1")
        && capsule_member_canary_allows(state, cc, store)
}

fn capsule_lookup_allowed(
    state: &ServerState,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
    gates: Option<&SharedCacheGates>,
    member: bool,
) -> bool {
    state.xf_capsule.enabled
        && !is_capsule_reserved_path(cc.req_path)
        && !cc.host_foreign
        && !cc.has_range
        && (cc.method == Method::GET || cc.method == Method::HEAD)
        // (#239) The capsule tier stores PUBLIC shells, so it must respect the same
        // per-request `.htaccess` no-cache marker and the per-vhost cache-policy gate
        // the plain public tier obeys — a vhost (or request) that opted out of public
        // caching must not be cached through the side door.
        // (#320) The three shared gates come from the pipeline's single evaluation
        // when provided; semantics identical (same fns, same args).
        && !gates.map(|g| g.no_cache_env).unwrap_or_else(|| no_cache_env(ctx))
        && gates
            .map(|g| g.vhost_allows_public)
            .unwrap_or_else(|| vhost_allows_public(ctx, store, cc.req_path))
        && capsule_vhost_allowed(state, ctx)
        && capsule_path_allowed(state, cc.req_path, cc.req_query)
        && capsule_cookie_safe(cc.cookie)
        && capsule_member_lookup_allowed(state, cc, store, member)
        && gates
            .map(|g| g.chain_cacheable)
            .unwrap_or_else(|| {
                chain_cacheable_for_default(
                    cc.chain,
                    cc.req_path,
                    store.config().is_standards_vhost(&ctx.vhost_name),
                )
            })
        && capsule_canary_allows(state, cc, store)
}

fn capsule_store_allowed(
    state: &ServerState,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
    status: u16,
) -> bool {
    state.xf_capsule.enabled
        // (#101) Don't store a shell that can NEVER be served. `capsule_canary_allows`
        // (guest canary) ANDs into EVERY capsule lookup — guest and member alike — so at
        // canary_percent==0 nothing is ever served from the capsule tier, and an eager
        // dedicated store would be pure store-LRU pressure that evicts live public entries during
        // a 0% ramp. canary>0 keys one shell per URL (amortized across all serves),
        // so it stays justified there; the #99 admission-exemption only covers canary>0.
        && state.xf_capsule.canary_percent > 0
        && !cc.host_foreign
        && !cc.has_range
        && *cc.method == Method::GET
        && status == 200
        // (#239) Same gates as lookup: no `.htaccess` no-cache marker on the
        // request that produced this response, and the vhost must allow public
        // caching — a capsule shell is a public entry.
        && !no_cache_env(ctx)
        && vhost_allows_public(ctx, store, cc.req_path)
        && capsule_vhost_allowed(state, ctx)
        && capsule_path_allowed(state, cc.req_path, cc.req_query)
        && capsule_cookie_safe(cc.cookie)
        && !capsule_member_candidate(cc.cookie, store)
        && chain_cacheable_for_default(
            cc.chain,
            cc.req_path,
            store.config().is_standards_vhost(&ctx.vhost_name),
        )
}

#[derive(Debug, Clone, Copy)]
struct CapsuleControl {
    ttl_secs: u32,
}

/// (#238) True when the stored response's Cache-Control explicitly forbids
/// stale-with-revalidation serving (`must-revalidate`, `proxy-revalidate`) or
/// storage/staleness outright (`no-store`, `no-cache`). The capsule shell's
/// forced SWR window is entry-level and would override these directives for the
/// plain public entry too — so it must not be injected when they are present.
fn stored_cc_forbids_stale(headers: &HeaderMap) -> bool {
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(parse_std_cache_control)
        .any(|cc| cc.must_revalidate || cc.no_store || cc.no_cache || cc.private)
}

fn parse_capsule_control(headers: &HeaderMap, fallback_ttl_secs: u32) -> Option<CapsuleControl> {
    let mut public_shell = false;
    let mut hydrate_ok = false;
    let mut ttl_secs = None;
    for v in headers
        .get_all(HDR_XF_CAPSULE)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        for token in v.split([',', ';']).map(str::trim).filter(|t| !t.is_empty()) {
            if token.eq_ignore_ascii_case("public-shell") || token.eq_ignore_ascii_case("public") {
                public_shell = true;
            } else if let Some((name, value)) = token.split_once('=') {
                if name.trim().eq_ignore_ascii_case("max-age") {
                    ttl_secs = value.trim().parse::<u32>().ok();
                } else if name.trim().eq_ignore_ascii_case("hydrate")
                    && value.trim().eq_ignore_ascii_case(CAPSULE_HYDRATE_TOKEN)
                {
                    hydrate_ok = true;
                }
            }
        }
    }
    (public_shell && hydrate_ok).then_some(CapsuleControl {
        ttl_secs: ttl_secs.unwrap_or(fallback_ttl_secs).max(1),
    })
}

fn add_tag_once(tags: &mut Vec<Arc<str>>, tag: &'static str) {
    if !tags.iter().any(|existing| existing.as_ref() == tag) {
        tags.push(Arc::from(tag));
    }
}

fn capsule_tags(headers: &HeaderMap, base_tags: &[Arc<str>]) -> Vec<Arc<str>> {
    let mut tags = Vec::with_capacity(base_tags.len() + 2);
    tags.extend(base_tags.iter().cloned());
    for tag in headers
        .get_all(HDR_XF_CAPSULE_TAGS)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(parse_tags)
    {
        let tag = Arc::<str>::from(tag.as_str());
        if !tags
            .iter()
            .any(|existing| existing.as_ref() == tag.as_ref())
        {
            tags.push(tag);
        }
    }
    add_tag_once(&mut tags, CAPSULE_TAG);
    add_tag_once(&mut tags, CAPSULE_SHELL_TAG);
    tags
}

fn capsule_entry_shell_capable(entry: &CachedResponse) -> bool {
    matches!(entry.scope, PageScope::Public)
        && entry
            .tags
            .iter()
            .any(|tag| tag.as_ref() == CAPSULE_SHELL_TAG)
}

fn stored_headers_from(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    let mut stored_headers = Vec::with_capacity(headers.len());
    for (k, v) in headers.iter() {
        if is_control_header(k)
            || k == CONTENT_LENGTH
            || k == TRANSFER_ENCODING
            || k == CONTENT_ENCODING
            || k == SET_COOKIE
            || k == DATE
        {
            continue;
        }
        stored_headers.push((k.clone(), v.clone()));
    }
    stored_headers
}

#[cfg(test)]
thread_local! {
    /// Body hashes `ensure_stored_etag` computed on this thread.
    static STORED_ETAG_HASHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Only a 2xx gets a synthesized validator: a body hash says nothing about a redirect's
/// Location, so every empty-body 301 would share one ETag (#658).
fn ensure_stored_etag(status: u16, headers: &mut Vec<(HeaderName, HeaderValue)>, bytes: &Bytes) {
    if (200..300).contains(&status) && !headers.iter().any(|(k, _)| k == ETAG) {
        #[cfg(test)]
        STORED_ETAG_HASHES.with(|n| n.set(n.get() + 1));
        if let Ok(v) = HeaderValue::from_str(&hit::weak_etag(bytes)) {
            headers.push((ETAG, v));
        }
    }
}

/// The stored copy of a buffered miss's headers with its validator, and that validator.
fn stored_headers_with_etag(
    status: u16,
    headers: &HeaderMap,
    bytes: &Bytes,
) -> (Vec<(HeaderName, HeaderValue)>, Option<HeaderValue>) {
    let mut stored = stored_headers_from(headers);
    ensure_stored_etag(status, &mut stored, bytes);
    let etag = stored
        .iter()
        .find(|(name, _)| name == ETAG)
        .map(|(_, value)| value.clone());
    (stored, etag)
}

fn apply_capsule_member_egress(headers: &mut HeaderMap) {
    force_cache_control(headers, "private, no-store");
    headers.remove(HeaderName::from_static("cloudflare-cdn-cache-control"));
    headers.remove(HeaderName::from_static("cdn-cache-control"));
    headers.remove(http::header::EXPIRES);
}

fn mark_capsule(headers: &mut HeaderMap, value: &'static str) {
    headers.insert(HDR_XF_CAPSULE_STATUS, HeaderValue::from_static(value));
}

fn mark_hot_path(headers: &mut HeaderMap, value: &'static str) {
    headers.insert(HDR_XF_HOT_PATH, HeaderValue::from_static(value));
}

/// Stamp the X-WF-Shell-Age header and return the computed age in seconds (so the caller can
/// fold the same value into the shell-age summary metric without recomputing `now - stored_at`).
fn mark_shell_age(headers: &mut HeaderMap, entry: &CachedResponse, now: Instant) -> u64 {
    let age_secs = now.duration_since(entry.stored_at).as_secs();
    if let Ok(v) = HeaderValue::from_str(&age_secs.to_string()) {
        headers.insert(HDR_XF_SHELL_AGE, v);
    }
    age_secs
}

fn record_capsule_hit(state: &ServerState, source: &'static str, member: bool, age_secs: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    match source {
        "dedicated" => state
            .metrics
            .xf_capsule_hits_dedicated
            .fetch_add(1, Relaxed),
        "dedicated_stale" => state
            .metrics
            .xf_capsule_stale_hits_dedicated
            .fetch_add(1, Relaxed),
        "public_fallback" => state
            .metrics
            .xf_capsule_hits_public_fallback
            .fetch_add(1, Relaxed),
        "public_fallback_stale" => state
            .metrics
            .xf_capsule_stale_hits_public_fallback
            .fetch_add(1, Relaxed),
        _ => return,
    };
    if member {
        state.metrics.xf_capsule_hits_member.fetch_add(1, Relaxed);
    } else {
        state.metrics.xf_capsule_hits_guest.fetch_add(1, Relaxed);
    }
    state
        .metrics
        .xf_capsule_shell_age_secs_sum
        .fetch_add(age_secs, Relaxed);
    state
        .metrics
        .xf_capsule_shell_age_secs_count
        .fetch_add(1, Relaxed);
}

pub(crate) fn capsule_public_refresh_cookie(
    cookie: Option<&str>,
    store: &hj_pagecache::PageStore,
) -> Option<HeaderValue> {
    let cfg = store.config();
    let mut pairs = Vec::new();
    for pair in cookie?.split(';') {
        let pair = pair.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        // Array-form cookies key their own slot (#656); re-emitting them as a
        // scalar would refresh a different one.
        let Some(hj_pagecache::PhpCookieName::Scalar(parsed)) =
            hj_pagecache::php_cookie_name(raw_name)
        else {
            continue;
        };
        let Some(name) = cfg.vary_cookies.iter().find(|name| **name == *parsed) else {
            continue;
        };
        if name == &cfg.private_user_cookie
            || name == &cfg.private_session_cookie
            || name == CAPSULE_MEMBER_COOKIE
            || name == CAPSULE_BYPASS_COOKIE
            || name == "xf_admin"
            || name == "xf_api_key"
        {
            continue;
        }
        // Preserve every matching pair, including explicit empty values and duplicates:
        // `compute_vary_value` keys both, so collapsing either would refresh a different slot.
        pairs.push(format!("{name}={}", raw_value));
    }
    if pairs.is_empty() {
        None
    } else {
        HeaderValue::from_str(&pairs.join("; ")).ok()
    }
}

fn record_capsule_miss(state: &ServerState, reason: &'static str) {
    use std::sync::atomic::Ordering::Relaxed;
    match reason {
        "dedicated_miss" => state
            .metrics
            .xf_capsule_misses_dedicated
            .fetch_add(1, Relaxed),
        "public_fallback_miss" => state
            .metrics
            .xf_capsule_misses_public_fallback
            .fetch_add(1, Relaxed),
        "not_allowed" => state
            .metrics
            .xf_capsule_bypass_not_allowed
            .fetch_add(1, Relaxed),
        _ => return,
    };
}

fn capsule_public_fallback_lookup(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
    now: Instant,
    dedicated_key_hash: u64,
    if_none_match: Option<&str>,
) -> CacheOutcome {
    if !capsule_public_fallback_allowed(state, cc, store) {
        return CacheOutcome::Miss(dedicated_key_hash);
    }

    let key = configuration_key(state, capsule_public_fallback_key(ctx, cc, store));
    let key_hash = hash_key(&key);
    let (mut entry, stale) = match store.get_entry_uncounted(&key, cc.identity, now) {
        hj_pagecache::EntryState::Fresh(e) => (e, false),
        hj_pagecache::EntryState::Stale(e) => (e, true),
        hj_pagecache::EntryState::ErrorOnly(_) | hj_pagecache::EntryState::Miss => {
            record_capsule_miss(state, "public_fallback_miss");
            return CacheOutcome::Miss(dedicated_key_hash);
        }
    };

    if !capsule_entry_shell_capable(&entry)
        || (entry.dict_gen != 0 && matching_dict(state, entry.dict_gen).is_none())
        || entry_is_self_redirect(&entry, ctx.is_tls, cc.host, cc.req_path, cc.req_query)
        || !matches!(entry.scope, PageScope::Public)
    {
        record_capsule_miss(state, "public_fallback_miss");
        return CacheOutcome::Miss(dedicated_key_hash);
    }

    // RFC 9110 §13.2.1: preconditions are ignored when the response would not be 2xx.
    if let (Some(inm), Some(etag), true) = (
        if_none_match,
        hit::entry_etag(&entry),
        (200..300).contains(&entry.status),
    ) {
        if hit::if_none_match_matches(inm, etag) {
            let mut resp = hit::not_modified(
                &entry,
                etag,
                now,
                inm,
                AcceptEncoding::parse(egress_ae(state, ctx)),
                &state.compress,
            );
            mark_capsule(
                resp.headers_mut(),
                if stale {
                    "hit,stale-public-fallback"
                } else {
                    "hit,public-fallback"
                },
            );
            mark_hot_path(
                resp.headers_mut(),
                if stale { "l2-stale" } else { "l1-fresh" },
            );
            let age_secs = mark_shell_age(resp.headers_mut(), &entry, now);
            if stale {
                apply_stale_cf_egress(resp.headers_mut());
            }
            apply_capsule_member_egress(resp.headers_mut());
            if !stale {
                maybe_spawn_finalize(state, ctx, &key, key_hash, &entry);
            }
            // The public-fallback path is reachable only by a member candidate
            // (capsule_public_fallback_allowed gates on capsule_member_candidate).
            record_capsule_hit(
                state,
                if stale {
                    "public_fallback_stale"
                } else {
                    "public_fallback"
                },
                true,
                age_secs,
            );
            return if stale {
                CacheOutcome::CapsuleStaleHit(resp, key_hash)
            } else {
                CacheOutcome::Hit(resp)
            };
        }
    }

    let accept_encoding = AcceptEncoding::parse(egress_ae(state, ctx));
    // Skip the precompress on a STALE hit: a background refresh is already in flight and will
    // re-store a fresh entry with variants, so filling the soon-to-be-superseded stale body is
    // wasted CPU (the fill's `stored_at` guard would no-op it anyway). Mirrors `cache_lookup`,
    // which only fills on the Fresh arm.
    if !stale
        && !entry.variants_filled
        && !hj_compress::no_gzip(ctx)
        && hit::eligible_for_variants(
            state,
            &entry.headers,
            variant_eligibility_len(&entry),
            accept_encoding,
            true,
        )
    {
        spawn_variant_fill(
            state,
            key.clone(),
            hash_key(&key),
            entry.clone(),
            accept_encoding,
            true,
        );
    }

    match build_hit_response_with_successor_retry(
        state,
        store,
        &key,
        cc.identity,
        &mut entry,
        now,
        accept_encoding,
        cc.method == Method::HEAD,
        |candidate| {
            capsule_entry_shell_capable(candidate)
                && (candidate.dict_gen == 0 || matching_dict(state, candidate.dict_gen).is_some())
                && !entry_is_self_redirect(
                    candidate,
                    ctx.is_tls,
                    cc.host,
                    cc.req_path,
                    cc.req_query,
                )
                && matches!(candidate.scope, PageScope::Public)
        },
    ) {
        Some(mut resp) => {
            note_variant_serve(state, &resp);
            mark_capsule(
                resp.headers_mut(),
                if stale {
                    "hit,stale-public-fallback"
                } else {
                    "hit,public-fallback"
                },
            );
            mark_hot_path(
                resp.headers_mut(),
                if stale { "l2-stale" } else { "l1-fresh" },
            );
            let age_secs = mark_shell_age(resp.headers_mut(), &entry, now);
            if stale {
                apply_stale_cf_egress(resp.headers_mut());
            }
            apply_capsule_member_egress(resp.headers_mut());
            if !stale {
                // Build/pin the response before recompress may retire the identity file.
                maybe_spawn_finalize(state, ctx, &key, key_hash, &entry);
            }
            // Public-fallback path is member-only (see above).
            record_capsule_hit(
                state,
                if stale {
                    "public_fallback_stale"
                } else {
                    "public_fallback"
                },
                true,
                age_secs,
            );
            if stale {
                CacheOutcome::CapsuleStaleHit(resp, key_hash)
            } else {
                CacheOutcome::Hit(resp)
            }
        }
        None => {
            record_capsule_miss(state, "public_fallback_miss");
            CacheOutcome::Miss(dedicated_key_hash)
        }
    }
}

/// (#320) Gate verdicts shared between the sequential capsule and plain lookups of
/// ONE dispatch: the pipeline computes them once and passes them to both, so the
/// capsule-enabled hot path stops re-evaluating `no_cache_env` (two linear env
/// scans), `vhost_allows_public` (context scan) and `chain_cacheable_for_default`.
/// `None` = compute internally (cold paths / non-capsule callers).
#[derive(Clone, Copy)]
pub struct SharedCacheGates {
    pub no_cache_env: bool,
    pub vhost_allows_public: bool,
    pub chain_cacheable: bool,
}

pub(crate) fn compute_shared_gates(
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
) -> SharedCacheGates {
    SharedCacheGates {
        no_cache_env: no_cache_env(ctx),
        vhost_allows_public: vhost_allows_public(ctx, store, cc.req_path),
        chain_cacheable: chain_cacheable_for_default(
            cc.chain,
            cc.req_path,
            store.config().is_standards_vhost(&ctx.vhost_name),
        ),
    }
}

pub fn capsule_lookup(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    if_none_match: Option<&str>,
    gates: Option<&SharedCacheGates>,
) -> CacheOutcome {
    if !cc.enabled {
        return CacheOutcome::Bypass;
    }
    let Some(store) = state.page_cache.as_ref() else {
        return CacheOutcome::Bypass;
    };
    let member = capsule_member_candidate(cc.cookie, store);
    if !capsule_lookup_allowed(state, ctx, cc, store, gates, member) {
        if member || cookie_value(cc.cookie, CAPSULE_MEMBER_COOKIE) == Some("1") {
            record_capsule_miss(state, "not_allowed");
        }
        return CacheOutcome::Bypass;
    }

    // The capsule tier never holds per-URL variants (a response varying on a cookie outside
    // the global set is not capsule-stored), so a URL that varies is served by `cache_lookup`.
    if url_vary_applies(state, ctx, cc, store) {
        return CacheOutcome::Bypass;
    }
    // (2026-10-04) Guests never probe the dedicated key: their page is the PUBLIC entry that
    // `cache_lookup` serves next, so the extra probe (39k "dedicated misses" per 2.5 h) bought
    // nothing. Members fall straight through to the shell-capable public entry unless dedicated
    // stores are enabled (`--xf-capsule-dedicated-store`).
    if !member {
        return CacheOutcome::Bypass;
    }
    let now = Instant::now();
    if !state.xf_capsule.dedicated_store {
        // No dedicated key exists to report; dispatch ignores a capsule miss's hash (#984).
        return capsule_public_fallback_lookup(state, ctx, cc, store, now, 0, if_none_match);
    }
    let key = configuration_key(state, capsule_key(ctx, cc, store));
    let key_hash = hash_key(&key);
    let mut entry = match store.get_entry_uncounted(&key, cc.identity, now) {
        hj_pagecache::EntryState::Fresh(e) => e,
        hj_pagecache::EntryState::Stale(mut e) => {
            if e.dict_gen != 0 && matching_dict(state, e.dict_gen).is_none() {
                record_capsule_miss(state, "dedicated_miss");
                return capsule_public_fallback_lookup(
                    state,
                    ctx,
                    cc,
                    store,
                    now,
                    key_hash,
                    if_none_match,
                );
            }
            if entry_is_self_redirect(&e, ctx.is_tls, cc.host, cc.req_path, cc.req_query) {
                record_capsule_miss(state, "dedicated_miss");
                return capsule_public_fallback_lookup(
                    state,
                    ctx,
                    cc,
                    store,
                    now,
                    key_hash,
                    if_none_match,
                );
            }
            // (defense-in-depth) Never hand a member a non-Public dedicated entry. The dedicated
            // key is namespaced (capsule_key = prefix+path) and stored Public-scoped, so this can
            // only fire on a slot collision/corruption — degrade to the public-fallback miss path.
            if member && !matches!(e.scope, PageScope::Public) {
                record_capsule_miss(state, "dedicated_miss");
                return capsule_public_fallback_lookup(
                    state,
                    ctx,
                    cc,
                    store,
                    now,
                    key_hash,
                    if_none_match,
                );
            }
            let Some(mut resp) = build_hit_response_with_successor_retry(
                state,
                store,
                &key,
                cc.identity,
                &mut e,
                now,
                AcceptEncoding::parse(egress_ae(state, ctx)),
                cc.method == Method::HEAD,
                |candidate| {
                    (candidate.dict_gen == 0 || matching_dict(state, candidate.dict_gen).is_some())
                        && !entry_is_self_redirect(
                            candidate,
                            ctx.is_tls,
                            cc.host,
                            cc.req_path,
                            cc.req_query,
                        )
                        && (!member || matches!(candidate.scope, PageScope::Public))
                },
            ) else {
                record_capsule_miss(state, "dedicated_miss");
                return capsule_public_fallback_lookup(
                    state,
                    ctx,
                    cc,
                    store,
                    now,
                    key_hash,
                    if_none_match,
                );
            };
            note_variant_serve(state, &resp);
            apply_stale_cf_egress(resp.headers_mut());
            mark_capsule(resp.headers_mut(), "hit,stale");
            mark_hot_path(resp.headers_mut(), "l2-stale");
            let age_secs = mark_shell_age(resp.headers_mut(), &e, now);
            if member {
                apply_capsule_member_egress(resp.headers_mut());
            }
            record_capsule_hit(state, "dedicated_stale", member, age_secs);
            return CacheOutcome::CapsuleStaleHit(resp, key_hash);
        }
        hj_pagecache::EntryState::ErrorOnly(_) | hj_pagecache::EntryState::Miss => {
            record_capsule_miss(state, "dedicated_miss");
            return capsule_public_fallback_lookup(
                state,
                ctx,
                cc,
                store,
                now,
                key_hash,
                if_none_match,
            );
        }
    };

    if entry.dict_gen != 0 && matching_dict(state, entry.dict_gen).is_none() {
        record_capsule_miss(state, "dedicated_miss");
        return capsule_public_fallback_lookup(state, ctx, cc, store, now, key_hash, if_none_match);
    }
    if entry_is_self_redirect(&entry, ctx.is_tls, cc.host, cc.req_path, cc.req_query) {
        record_capsule_miss(state, "dedicated_miss");
        return capsule_public_fallback_lookup(state, ctx, cc, store, now, key_hash, if_none_match);
    }
    // (defense-in-depth) A member must never be handed a non-Public dedicated entry (see the
    // Stale arm above) — degrade to the public-fallback miss path if scope is ever not Public.
    if member && !matches!(entry.scope, PageScope::Public) {
        record_capsule_miss(state, "dedicated_miss");
        return capsule_public_fallback_lookup(state, ctx, cc, store, now, key_hash, if_none_match);
    }
    // RFC 9110 §13.2.1: preconditions are ignored when the response would not be 2xx.
    if let (Some(inm), Some(etag), true) = (
        if_none_match,
        hit::entry_etag(&entry),
        (200..300).contains(&entry.status),
    ) {
        if hit::if_none_match_matches(inm, etag) {
            let mut resp = hit::not_modified(
                &entry,
                etag,
                now,
                inm,
                AcceptEncoding::parse(egress_ae(state, ctx)),
                &state.compress,
            );
            mark_capsule(resp.headers_mut(), "hit");
            mark_hot_path(resp.headers_mut(), "l1-fresh");
            let age_secs = mark_shell_age(resp.headers_mut(), &entry, now);
            if member {
                apply_capsule_member_egress(resp.headers_mut());
            }
            maybe_spawn_finalize(state, ctx, &key, key_hash, &entry);
            record_capsule_hit(state, "dedicated", member, age_secs);
            return CacheOutcome::Hit(resp);
        }
    }
    let accept_encoding = AcceptEncoding::parse(egress_ae(state, ctx));
    let capsule_shell = capsule_entry_shell_capable(&entry);
    if !entry.variants_filled
        && !hj_compress::no_gzip(ctx)
        && hit::eligible_for_variants(
            state,
            &entry.headers,
            variant_eligibility_len(&entry),
            accept_encoding,
            capsule_shell,
        )
    {
        spawn_variant_fill(
            state,
            key.clone(),
            key_hash,
            entry.clone(),
            accept_encoding,
            capsule_shell,
        );
    }
    match build_hit_response_with_successor_retry(
        state,
        store,
        &key,
        cc.identity,
        &mut entry,
        now,
        accept_encoding,
        cc.method == Method::HEAD,
        |candidate| {
            (candidate.dict_gen == 0 || matching_dict(state, candidate.dict_gen).is_some())
                && !entry_is_self_redirect(
                    candidate,
                    ctx.is_tls,
                    cc.host,
                    cc.req_path,
                    cc.req_query,
                )
                && (!member || matches!(candidate.scope, PageScope::Public))
        },
    ) {
        Some(mut resp) => {
            note_variant_serve(state, &resp);
            mark_capsule(resp.headers_mut(), "hit");
            mark_hot_path(resp.headers_mut(), "l1-fresh");
            let age_secs = mark_shell_age(resp.headers_mut(), &entry, now);
            if member {
                apply_capsule_member_egress(resp.headers_mut());
            }
            // Build/pin the response before recompress may retire the identity file.
            maybe_spawn_finalize(state, ctx, &key, key_hash, &entry);
            record_capsule_hit(state, "dedicated", member, age_secs);
            CacheOutcome::Hit(resp)
        }
        None => {
            record_capsule_miss(state, "dedicated_miss");
            capsule_public_fallback_lookup(state, ctx, cc, store, now, key_hash, if_none_match)
        }
    }
}

/// (SIE) A backend 5xx on a cacheable public GET/HEAD: serve the retained entry for this
/// request instead of the error, RFC 5861 stale-if-error semantics. Runs ONLY on the rare
/// 5xx path (gated on status before any key work), re-deriving the key exactly as
/// lookup/store do. Accepts Fresh/Stale (a concurrent request may have stored a good entry
/// while this render failed) as well as ErrorOnly (the dedicated post-SWR grace window).
/// Every guard fails open to the original error response; private routes never fall back
/// (a private page is re-rendered, never served stale — it has no SIE window by design).
fn stale_if_error_fallback(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
    route: &PrivateRoute,
    status: u16,
) -> Option<Response> {
    if !matches!(status, 500 | 502 | 503 | 504) {
        return None;
    }
    let &CacheCtx {
        method,
        host,
        req_path,
        req_query,
        chain,
        host_foreign,
        has_range,
        ..
    } = cc;
    if host_foreign
        || has_range
        || (method != Method::GET && method != Method::HEAD)
        || !matches!(route, PrivateRoute::Public)
        || no_cache_env(ctx)
        || !vhost_allows_public(ctx, store, req_path)
        || !chain_cacheable_for_default(
            chain,
            req_path,
            store.config().is_standards_vhost(&ctx.vhost_name),
        )
    {
        return None;
    }
    let ResolvedKey { key, identity, .. } = resolved_cache_key(state, ctx, cc, store, route)?;
    let identity: &str = &identity;
    let now = Instant::now();
    let mut entry = match store.get_entry(&key, identity, now) {
        hj_pagecache::EntryState::Fresh(e)
        | hj_pagecache::EntryState::Stale(e)
        | hj_pagecache::EntryState::ErrorOnly(e) => e,
        hj_pagecache::EntryState::Miss => return None,
    };
    // A fresh opt-in 404/410 stored while this render failed must never stand in
    // for the 5xx (#783).
    if entry.status >= 400 {
        return None;
    }
    if entry.dict_gen != 0 && matching_dict(state, entry.dict_gen).is_none() {
        return None;
    }
    if entry_is_self_redirect(&entry, ctx.is_tls, host, req_path, req_query) {
        return None;
    }
    let mut resp = build_hit_response_with_successor_retry(
        state,
        store,
        &key,
        identity,
        &mut entry,
        now,
        AcceptEncoding::parse(egress_ae(state, ctx)),
        method == Method::HEAD,
        |candidate| {
            (candidate.dict_gen == 0 || matching_dict(state, candidate.dict_gen).is_some())
                && !entry_is_self_redirect(candidate, ctx.is_tls, host, req_path, req_query)
        },
    )?;
    note_variant_serve(state, &resp);
    // Short-public egress (with Age reset + CDN/Expires strip) so CF never pins the
    // stale body past 30s, then label the serve for operators (apply_stale_cf_egress
    // sets the generic "stale" marker first).
    apply_stale_cf_egress(resp.headers_mut());
    resp.headers_mut().insert(
        HDR_CACHE_STATUS,
        HeaderValue::from_static("hit,stale-if-error"),
    );
    state
        .telemetry
        .shard()
        .cache_sie_serves
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::warn!(
        path = %req_path,
        status,
        age_secs = entry.age_secs(now),
        "page-cache: backend 5xx — served stale-if-error fallback"
    );
    Some(resp)
}

/// Outcome of a [`cache_lookup`]. `Miss`/`StaleHit` carry the page-cache key hash so the
/// pipeline can single-flight concurrent misses and key the background refresh; `Bypass`
/// means this request is never cached (no single-flight — render directly).
pub enum CacheOutcome {
    Hit(Response),
    /// Serve this stale (CF-poison-guarded) response now AND spawn ONE background refresh
    /// for the carried key hash.
    StaleHit(Response, u64),
    /// Stale XenForo capsule shell. The pipeline refreshes it as a public-shell render
    /// with auth/session cookies stripped, not as the triggering member request.
    CapsuleStaleHit(Response, u64),
    Miss(u64),
    Bypass,
}

/// (#20) FNV-1a 32 hash of the resolved vhost name → the `vhost_id` key component, so two
/// listeners routing the same hostname to DIFFERENT vhosts (sharing one cache) never collide.
/// The `PageCacheKey.vhost_id` type stays `u32` (frozen hj-pagecache contract); we just stop
/// passing a hardcoded 0. Computed identically on lookup + store so the keys agree.
pub(crate) fn vhost_id_hash(vhost_name: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in vhost_name.as_bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Post-handler hook: handle purge, store an eligible response, and strip the
/// internal control headers. Consumes and returns the response (the body may be
/// buffered from a stream into memory when stored).
///
/// `req_path`/`req_query` MUST be the **original** request URI (see
/// [`cache_lookup`]) so the stored key matches the lookup key.
/// True when a 3xx response redirects to the request's own URL **in the same scheme** — a
/// self-redirect that, if cached and replayed, is an infinite loop. Resolves the `Location`
/// (absolute or root-relative) to `host/path[?query]`, drops any `#fragment`, lowercases the
/// host, and compares exactly. A *cross-scheme* http→https `Location` is a LEGITIMATE upgrade
/// (handled by the scheme cache key dd2054b + the CDN-header strip dffb39c), not a loop, so
/// it is NOT flagged here. A trailing-slash difference is likewise a different URL (a
/// legitimate canonical redirect).
pub(crate) fn is_self_redirect(
    status: u16,
    headers: &HeaderMap,
    is_tls: bool,
    host: &str,
    req_path: &str,
    req_query: &str,
) -> bool {
    if !(300..400).contains(&status) {
        return false;
    }
    let Some(loc) = headers.get(LOCATION).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    location_is_self(loc, is_tls, host, req_path, req_query)
}

/// [`is_self_redirect`] with a RAW (un-normalized) path+query compare, fed the
/// request's RAW URI. A response that is self only after percent-normalization
/// (raw request `/a%5Fb`, Location `/a_b`) is a slug-canonicalization redirect:
/// refusing to cache it stays right (a percent-normalizing shared cache like
/// Cloudflare replays it as a loop), but RE-RENDERING it is futile — the
/// backend deterministically emits the same redirect again. The pipeline's
/// re-render retry keys off this raw form.
pub(crate) fn is_self_redirect_raw(
    status: u16,
    headers: &HeaderMap,
    is_tls: bool,
    host: &str,
    raw_req_path: &str,
    raw_req_query: &str,
) -> bool {
    if !(300..400).contains(&status) {
        return false;
    }
    let Some(loc) = headers.get(LOCATION).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    location_is_self_impl(loc, is_tls, host, raw_req_path, raw_req_query, false)
}

/// Split a `host[:port]/path?query` (no scheme) into its host and `/path?query` parts,
/// defaulting an absent/empty path to `/`.
fn split_host_pathq(host_and_rest: &str) -> (String, String) {
    match host_and_rest.split_once('/') {
        Some((h, rest)) => (h.to_string(), format!("/{rest}")),
        None => (host_and_rest.to_string(), "/".to_string()),
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_upper(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'A' + (n - 10),
        _ => b'0',
    }
}

fn is_unreserved_uri_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

pub(crate) fn normalize_self_redirect_pq(pq: &str) -> String {
    let bytes = pq.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                let decoded = (hi << 4) | lo;
                if is_unreserved_uri_byte(decoded) {
                    out.push(decoded);
                } else {
                    out.push(b'%');
                    out.push(hex_upper(hi));
                    out.push(hex_upper(lo));
                }
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_canonical_path_literal(b: u8) -> bool {
    is_unreserved_uri_byte(b)
        || matches!(
            b,
            b'/' | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn escaped_byte_at(raw: &[u8], i: usize) -> Option<u8> {
    match raw.get(i..i + 3)? {
        [b'%', hi, lo] => Some((hex_val(*hi)? << 4) | hex_val(*lo)?),
        _ => None,
    }
}

/// Entries are keyed by the normalized host (no port, no trailing dot, lowercase), but
/// the backend renders with the RAW Host (`HTTP_HOST`/`SERVER_NAME`, XenForo's og:url),
/// so only the canonical spelling — optionally with the scheme's default port — may
/// read or populate an entry; `x.com:1234` or `X.COM.` would poison `x.com` (#840).
pub(crate) fn raw_host_is_cache_canonical(req: &Request, is_tls: bool) -> bool {
    let raw = match req.headers().get(http::header::HOST) {
        Some(v) => match v.to_str() {
            Ok(s) => s,
            Err(_) => return false,
        },
        None => match req.uri().authority() {
            Some(a) => a.as_str(),
            None => return true,
        },
    };
    let canonical = hj_core::host_without_port(raw);
    let default_port = if is_tls { ":443" } else { ":80" };
    raw.strip_prefix(canonical.as_str())
        .is_some_and(|rest| rest.is_empty() || rest == default_port)
}

/// Entries are keyed and identified by the decoded, dot-normalized path, but the backend
/// routes the RAW `REQUEST_URI`. Only the one raw spelling that canonically encodes that path
/// (modulo hex case) may read or populate an entry. Any other
/// spelling — `/./`, `/x/../`, `//`, `%2F`, an escaped sub-delim — shares the key yet can
/// render different content (XenForo 404s `/./`), which would poison the canonical URL.
pub(crate) fn raw_path_is_cache_canonical(raw: &str, normalized: &str) -> bool {
    let raw = raw.as_bytes();
    let mut i = 0;
    for &b in normalized.as_bytes() {
        let Some(&r) = raw.get(i) else {
            return false;
        };
        if is_canonical_path_literal(b) && r == b {
            i += 1;
        // An unreserved byte must appear literally: XenForo strips the SCRIPT_NAME
        // prefix from the RAW REQUEST_URI before decoding, so `/index%2Ephp/x/`
        // routes differently from `/index.php/x/` (#705 follow-up).
        } else if !is_canonical_path_literal(b) && escaped_byte_at(raw, i) == Some(b) {
            i += 3;
        } else {
            return false;
        }
    }
    i == raw.len()
}

/// The decoded, dot-segment-collapsed form of a `Location` path, comparable to the request's
/// canonical `orig_path` (a trailing slash is kept, and an escaped `/` is not a separator:
/// both name a different URL).
fn canonical_location_path(path: &str) -> Option<String> {
    if path.contains("%2F") || path.contains("%2f") {
        return None;
    }
    let decoded = hj_core::percent_decode_cow(path)?;
    let mut segs: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut out = String::with_capacity(decoded.len() + 1);
    for s in &segs {
        out.push('/');
        out.push_str(s);
    }
    if out.is_empty() || (decoded.ends_with('/') && !out.ends_with('/')) {
        out.push('/');
    }
    Some(out)
}

/// Core of [`is_self_redirect`], split out so the serve-time guard in [`cache_lookup`]
/// can re-check a stored entry's `Location` directly. Resolves `loc` to host + `/path
/// [?query]`, dropping any `#fragment`, and compares it to the request. Both hosts are
/// normalized through [`hj_core::host_without_port`] so an h2 `HTTP_HOST` that carries
/// `:443` still matches a port-less `Location` host (the homepage self-redirect cache-loop
/// incident). An empty path is normalized to `/`; a trailing-slash difference is a DIFFERENT
/// url (a legitimate canonical redirect) and is preserved. A cross-scheme absolute `Location`
/// (http⇄https) is an upgrade, not a loop, and returns false.
fn location_is_self(loc: &str, is_tls: bool, host: &str, req_path: &str, req_query: &str) -> bool {
    location_is_self_impl(loc, is_tls, host, req_path, req_query, true)
}

/// `normalize`: `true` = percent-normalized compare (the caching guards — a
/// percent-normalizing shared cache replays a normalized-equal redirect as a
/// loop); `false` = raw byte compare ([`is_self_redirect_raw`], the re-render
/// futility test).
fn location_is_self_impl(
    loc: &str,
    is_tls: bool,
    host: &str,
    req_path: &str,
    req_query: &str,
    normalize: bool,
) -> bool {
    let loc = loc.split('#').next().unwrap_or(loc).trim();
    let (loc_host, loc_pq) = if let Some(rest) = strip_ascii_prefix(loc, "https://") {
        if !is_tls {
            return false;
        }
        split_host_pathq(rest)
    } else if let Some(rest) = strip_ascii_prefix(loc, "http://") {
        if is_tls {
            return false;
        }
        split_host_pathq(rest)
    } else if let Some(rest) = loc.strip_prefix("//") {
        // Protocol-relative `//host/path` resolves against the request's OWN scheme, so
        // it is same-scheme by construction — split host from path like an absolute URL.
        // (Must precede the `starts_with('/')` arm: `//host` also starts with `/`, and
        // falling through to root-relative kept the `//host` prefix in the path so the
        // self-compare never matched — the loop was then cached and CF-pinned.)
        split_host_pathq(rest)
    } else if loc.starts_with('/') {
        (host.to_string(), loc.to_string()) // root-relative: same host + scheme
    } else {
        return false; // a relative-without-leading-slash Location is unusual; don't guess
    };
    if hj_core::host_without_port(&loc_host) != hj_core::host_without_port(host) {
        return false;
    }
    let loc_pq = if loc_pq.is_empty() {
        "/".to_string()
    } else {
        loc_pq
    };
    let req_pq = if req_query.is_empty() {
        if req_path.is_empty() {
            "/".to_string()
        } else {
            req_path.to_string()
        }
    } else {
        format!("{req_path}?{req_query}")
    };
    if normalize {
        if normalize_self_redirect_pq(&loc_pq) == normalize_self_redirect_pq(&req_pq) {
            return true;
        }
        // `req_path` is the fully decoded canonical path: `Location: /a%20b` from `/a b`
        // (or `/caf%C3%A9/` from `/café/`) is a loop the unreserved-only compare misses.
        let (loc_path, loc_query) = match loc_pq.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (loc_pq.as_str(), None),
        };
        let req_path = if req_path.is_empty() { "/" } else { req_path };
        canonical_location_path(loc_path).is_some_and(|p| p == req_path)
            && loc_query.map(normalize_self_redirect_pq)
                == (!req_query.is_empty()).then(|| normalize_self_redirect_pq(req_query))
    } else {
        loc_pq == req_pq
    }
}

pub(crate) fn strip_ascii_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len()
        && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

pub async fn cache_store(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    resp: Response,
) -> Response {
    cache_store_leading(state, ctx, cc, resp, &mut None).await
}

/// [`cache_store`] for the single-flight leader of this key. A miss stored while it streams
/// (`--page-cache-stream-fill-vhosts`) takes `leader` along, so followers wake only once the
/// entry exists; otherwise `leader` is left for the caller to drop.
pub async fn cache_store_leading(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    resp: Response,
    leader: &mut Option<InflightLeader>,
) -> Response {
    #[cfg(feature = "otel")]
    let _trace_stage = crate::otel::stage(crate::otel::StageKind::CacheStore);
    let &CacheCtx {
        method,
        host,
        identity,
        req_path,
        req_query,
        chain,
        render_epoch,
        host_foreign,
        ..
    } = cc;
    let Some(store) = state.page_cache.as_ref() else {
        let mut resp = resp;
        strip_control_headers(resp.headers_mut());
        return resp;
    };

    let (mut parts, body) = resp.into_parts();

    // 1. Purge (acted on regardless of this response's own cacheability — a
    //    write request returns a purge directive for the content it changed).
    //    A backend may emit MORE THAN ONE `X-LiteSpeed-Purge`; execute every one
    //    so no invalidation is dropped.
    execute_purges(store, &parts.headers);

    // Keep the request-side route decision authoritative on the store side too.
    // Purges above remain response side-effects even when this response itself
    // is outside the cache route; all other internal control headers stay local.
    if !cc.enabled {
        strip_control_headers(&mut parts.headers);
        return Response::from_parts(parts, body);
    }

    // 2. Cacheability decision (response-level), plus the glue's vary/cookie
    //    gates that classify deliberately leaves to us.
    let status = parts.status.as_u16();
    let cfg = store.config();
    let disposition = classify_response(
        method,
        status,
        &parts.headers,
        no_cache_env(ctx),
        cfg,
        cfg.is_standards_vhost(&ctx.vhost_name),
    );
    // (telemetry) Count the response-level disposition so :9090 shows the
    // cacheable-vs-why-bypassed mix (decides the private-cache go/no-go).
    state.telemetry.record_cache_disposition(&disposition);
    let is_sse = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_event_stream);

    // (#1) Store ONLY for GET. A HEAD reaches the same key+identity (method is not
    // in the key) but lsphp returns an EMPTY body for HEAD, so storing it would
    // serve a blank page to every subsequent GET — cache poisoning that Cloudflare
    // then amplifies at its edge. HEAD lookups still hit a GET entry; HEAD just
    // never populates one.
    // (#11) Honor the per-vhost cache policy on the STORE path too, mirroring
    // cache_lookup — otherwise a caching-disabled vhost fills the shared store with
    // dead entries that evict another vhost's live ones.
    let vhost_caches = vhost_allows_public(ctx, store, req_path);
    // Only a GET stores and only a GET/HEAD falls back to a stale entry; any other method
    // needs no route (#983).
    let route = if *method == Method::GET || *method == Method::HEAD {
        private_route(state, ctx, store, cc, false)
    } else {
        PrivateRoute::Bypass
    };
    // Conditions EVERY stored entry must meet, public or private:
    let base_eligible =
        // Never store a Partial Content (206) / ranged response as if it were the full body —
        // a later non-range request would be served a partial. (collect_body also reads the
        // whole file ignoring FileBody.range, so a stored 206 would be doubly wrong.) Range
        // requests bypass the cache lookup too, so a 206 only reaches here via a backend that
        // marked a partial cacheable — refuse it.
        status != 206
        // Never STORE under a foreign catch-all Host: the entry is keyed by the resolved
        // (default) vhost, so storing a foreign host's response would poison that vhost's
        // own page for legitimate visitors. The control headers are still stripped below.
        && !host_foreign
        && *method == Method::GET
        && chain_cacheable_for_default(chain, req_path, cfg.is_standards_vhost(&ctx.vhost_name))
        && !is_sse
        // Never cache a self-redirect: a 3xx whose Location is the request's own URL is an
        // infinite loop if replayed. Caching one (a transient backend mis-render) is what
        // amplifies it into a persistent edge-cached "Too Many Redirects" — the incident
        // class. Compares host+path+query ignoring scheme, so it also catches the
        // cross-scheme variant. The origin still serves THIS one response; it just is not
        // stored or replayed.
        && !is_self_redirect(status, &parts.headers, ctx.is_tls, host, req_path, req_query)
        // An opted-in 303 is stored only under an allowlisted prefix: redirects elsewhere
        // (thread `latest`, attachments) rely on CDN purges the origin can't mirror.
        && (status != 303
            || cfg
                .opt_in_303_prefixes
                .iter()
                .any(|p| hj_pagecache::path_has_segment_prefix(req_path, p)))
        // A standard HTTP `Vary` response header lists request dimensions the content
        // depends on. We key on cookies + the negotiated encoding variant, so the only
        // token we can honor is `Accept-Encoding`; any other (`Accept-Language`,
        // `User-Agent`, `Cookie`, `*`, …) means the entry would be UNDER-KEYED and we'd
        // serve one variant to every client — refuse to store. (X-LiteSpeed-Vary cookie
        // dimensions are checked separately by `vary_supported` on the public path.)
        && standard_vary_supported(&parts.headers)
        // (capsule key-space guard, #95) Never store under the synthetic capsule prefix path;
        // its public key would collide with a dedicated capsule entry's slot (see cache_lookup).
        && !is_capsule_reserved_path(req_path);
    // `X-LiteSpeed-Vary` cookies outside the global set (and the rewrite env's
    // `Cache-Vary`) make this URL vary on them: the public entry is stored under the
    // extended key (see `store_cache_key`). Any other vary dimension still refuses.
    let declared = declared_vary(env_vary_names(ctx, cc), &parts.headers, &cfg.vary_cookies);
    let eligible = base_eligible
        // A private-routed (logged-in) request must never POPULATE the public
        // tier either — even if the app marked the render public, a logged-in
        // page may embed user state. Conservative by construction.
        && matches!(route, PrivateRoute::Public)
        && vhost_caches
        && matches!(declared, DeclaredVary::Names(_))
        && !sets_private_cookie(&parts.headers, &cfg.private_cookies);
    // The private tier keys by session and never holds per-URL variants: a response
    // varying on a cookie outside the global set is not stored privately.
    let private_vary_ok = match &declared {
        DeclaredVary::Names(n) => n.is_empty(),
        DeclaredVary::Unsupported { extra_cookie } => !extra_cookie,
    };
    let url_vary_names: &[String] = match &declared {
        DeclaredVary::Names(n) if eligible => n,
        _ => &[],
    };

    let (ttl_secs, mut stale_secs, sie_secs, scope) = match (&disposition, &route) {
        (
            Disposition::StorePublic {
                ttl_secs,
                stale_secs,
                stale_if_error_secs,
            },
            _,
        ) if eligible => (
            *ttl_secs,
            *stale_secs,
            *stale_if_error_secs,
            PageScope::Public,
        ),
        // A private store needs the private ROUTE (logged-in + session-keyed +
        // vhost allows private): the response opting in alone is not enough.
        // Set-Cookie is stripped from the stored copy below like any entry;
        // X-LiteSpeed-Vary/style-vary is subsumed by the per-session owner key.
        // No SWR/SIE windows: a private page is re-rendered, never served stale.
        (Disposition::StorePrivate { ttl_secs }, PrivateRoute::Private { owner, .. })
            if base_eligible && private_vary_ok =>
        {
            (*ttl_secs, 0, 0, PageScope::Private { owner_hash: *owner })
        }
        _ => {
            // (SIE) A 5xx render on a cacheable route may have a retained stale
            // entry to serve instead of the error (gated on status first — this
            // arm is also the every-POST/bypass path).
            if status >= 500 {
                if let Some(stale) = stale_if_error_fallback(state, ctx, cc, store, &route, status)
                {
                    return stale;
                }
            }
            // Not eligible: strip control headers, keep the original body as-is.
            strip_control_headers(&mut parts.headers);
            return Response::from_parts(parts, body);
        }
    };
    // The filling miss of a private entry gets the same shared-cache lockout as
    // its hits, or the first render reaches the CDN with the app's public
    // Cache-Control (#883).
    if matches!(scope, PageScope::Private { .. }) {
        force_cache_control(&mut parts.headers, "private, no-store");
        strip_shared_cdn_cache_directives(&mut parts.headers);
    }

    // 3. Extract tags BEFORE stripping, then buffer the (uncompressed) body. Union the tags
    //    across EVERY `X-LiteSpeed-Tag` line (a backend may split them across headers).
    let mut tags: Vec<Arc<str>> = parts
        .headers
        .get_all(HDR_TAG)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(parse_tags)
        .map(|t| Arc::from(t.as_str()))
        .collect();
    let capsule_control = if base_eligible
        && capsule_store_allowed(state, ctx, cc, store, status)
        && declared.global_only()
        && !sets_private_cookie(&parts.headers, &cfg.private_cookies)
    {
        let fallback_ttl_secs = match &disposition {
            Disposition::StorePublic { ttl_secs, .. } => *ttl_secs,
            _ => cfg.default_public_ttl.as_secs().min(u32::MAX as u64) as u32,
        };
        parse_capsule_control(&parts.headers, fallback_ttl_secs)
    } else {
        None
    };
    if capsule_control.is_some()
        // (#238) The forced SWR window is entry-level, so it applies to the PLAIN
        // public entry as well as the capsule shell. An app that explicitly demands
        // revalidation (must-revalidate / proxy-revalidate) or forbids staleness
        // (no-store / no-cache) must not get a 3600s stale window bolted on over
        // its objection — only raise the window when the stored CC permits stale
        // serving at all.
        && !stored_cc_forbids_stale(&parts.headers)
    {
        stale_secs = stale_secs
            .max(state.xf_capsule.stale_secs)
            .min(cfg.max_stale_secs);
    }

    // (cap) Enforce the per-object size cap BEFORE buffering the whole body into RAM. A File
    // over the cap is never read (don't slurp a large cacheable static file into memory just
    // to reject it, turning a zero-copy file serve into an in-RAM one); a Stream that DECLARES
    // a Content-Length over the cap is forwarded untouched. Both are served uncached with
    // control headers stripped. (A chunked stream with no Content-Length still buffers below,
    // where the post-collect size check skips the store — same as before, no worse.)
    let known_len: Option<u64> = match &body {
        Body::File(f) => Some(f.range.map_or(f.len, |(s, e)| e.saturating_sub(s) + 1)),
        Body::Full(b) => Some(b.len() as u64),
        _ => parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok()),
    };
    if matches!(body, Body::File(_) | Body::Stream(_))
        && known_len.is_some_and(|n| n > cfg.max_obj_bytes)
    {
        strip_control_headers(&mut parts.headers);
        return Response::from_parts(parts, body);
    }
    // (#949) A feed the backend asked not to buffer (`X-Accel-Buffering: no`) reaches
    // the client as it is produced; collecting it here to store it would hold every
    // byte until the backend finishes. Serve it through, uncached.
    if matches!(body, Body::Stream(_)) && accel_buffering_off(&parts.headers) {
        strip_control_headers(&mut parts.headers);
        return Response::from_parts(parts, body);
    }

    // Progressive template output (no Content-Length) reaches the client as the backend
    // writes it; the body is stored when the backend finishes. Framed (Content-Length) PHP
    // output arrives in one burst, so buffering it below costs nothing.
    if capsule_control.is_none()
        && status == 200
        && matches!(scope, PageScope::Public)
        && known_len.is_none()
        && matches!(body, Body::Stream(_))
        && cfg.streams_fill(&ctx.vhost_name)
        && parts
            .headers
            .get(CONTENT_ENCODING)
            .is_none_or(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        let Body::Stream(inner) = body else {
            unreachable!("matched a stream body above");
        };
        let Some(StoreKey {
            key,
            key_hash,
            identity,
            url_vary,
        }) = store_cache_key(state, ctx, cc, store, &route, url_vary_names)
        else {
            strip_control_headers(&mut parts.headers);
            return Response::from_parts(parts, Body::Stream(inner));
        };
        parts.headers.remove(CONTENT_ENCODING);
        let commit = FillCommit {
            state: state.clone(),
            entry: PendingEntry {
                key_hash,
                key,
                identity,
                url_vary,
                status,
                tags,
                scope,
                ttl: Duration::from_secs(ttl_secs as u64),
                swr: Duration::from_secs(stale_secs as u64),
                sie: Duration::from_secs(sie_secs as u64),
                render_epoch,
            },
            headers: stored_headers_from(&parts.headers),
            content_type: parts
                .headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string(),
            vhost_name: ctx.vhost_name.to_string(),
            leader: leader.take(),
            _render: store.begin_render(render_epoch),
        };
        strip_control_headers(&mut parts.headers);
        parts.headers.remove(TRANSFER_ENCODING);
        parts
            .headers
            .insert(HDR_CACHE_STATUS, HeaderValue::from_static("miss"));
        parts.extensions.insert(hj_compress::ProgressiveBody);
        state
            .metrics
            .pagecache_stream_fills
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let body = StreamFill {
            inner,
            buf: BytesMut::with_capacity(COLLECT_DEFAULT_CAPACITY),
            max_bytes: cfg.max_obj_bytes,
            commit: Some(commit),
        };
        return Response::from_parts(parts, Body::Stream(body.boxed()));
    }

    // (#9) A `Body::File` CAN be eligible (an `.htaccess` `Header set
    // X-LiteSpeed-Cache-Control: public` on a static file, applied by
    // `apply_response_headers` BEFORE this store runs). `collect_body` reads it into
    // memory; if THAT exact read fails, `collect_body` returns the original File response
    // with its selected descriptor/cache lease intact. A valid file must never become a 502,
    // and fallback must never reopen a replacement pathname under stale validators.
    // (sampled) How long a streamed body takes to collect before the miss can be served —
    // split by framing, since progressive no-Content-Length output is what this hides.
    let collect_timer = (matches!(body, Body::Stream(_))
        && state
            .telemetry
            .sample_phase(crate::telemetry::PHASE_SAMPLE_RATE))
    .then(|| (Instant::now(), parts.headers.contains_key(CONTENT_LENGTH)));
    // A doubling BytesMut would pass through 16/32/64/128/256 KiB for a typical 170 KB page.
    let capacity_hint = known_len.map_or(COLLECT_DEFAULT_CAPACITY, |n| {
        n.min(COLLECT_PRESIZE_CAP).min(cfg.max_obj_bytes) as usize
    });
    let mut bytes = match collect_body(body, cfg.max_obj_bytes, capacity_hint).await {
        Collected::Buffered(b) => b,
        Collected::Passthrough(passthrough) => {
            // An unknown-length (chunked) stream exceeded the cap mid-buffer: serve it through,
            // or a selected File could not be read to its advertised length. Preserve the exact
            // body/descriptor/cache lease and serve uncached with control headers stripped.
            strip_control_headers(&mut parts.headers);
            return Response::from_parts(parts, passthrough);
        }
        Collected::Error => {
            strip_control_headers(&mut parts.headers);
            // A genuine backend STREAM error mid-flight; the body is unrecoverable.
            tracing::warn!(path = %req_path, "page-cache: backend stream error while buffering");
            if let Some(stale) = stale_if_error_fallback(state, ctx, cc, store, &route, 502) {
                return stale;
            }
            return error_502();
        }
    };
    if let Some((started, declared_len)) = collect_timer {
        let shard = state.telemetry.shard();
        let hist = if declared_len {
            &shard.phase_collect_cl
        } else {
            &shard.phase_collect_nocl
        };
        hist.record(started.elapsed());
    }

    // (#A/#B) CANONICALIZE TO IDENTITY before caching. The store, PC1 variants, and
    // per-serve compression all assume an identity body; the cache key is NOT
    // encoding-aware, so storing an already-compressed backend response (a backend that
    // ignores the identity Accept-Encoding cgi.rs hands it and sends `Content-Encoding`
    // anyway) would replay that body to EVERY client — binary junk to clients that did not
    // ask for it, and PC1 would re-compress it (gzip-of-gzip). Decode a known single codec back to identity
    // and drop the header; if it can't be canonicalized (unknown / multi-value
    // encoding, or a decode error) DON'T cache it — fall through to the miss return
    // below, which serves the backend's response verbatim (valid for THIS client).
    let mut store_ok = true;
    if let Some(ce) = parts
        .headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
    {
        let ce = ce.to_string();
        if ce.eq_ignore_ascii_case("identity") {
            parts.headers.remove(CONTENT_ENCODING);
        } else if let Some(enc) = Encoding::from_token(&ce) {
            let raw = bytes.clone();
            match tokio::task::block_in_place(|| decode_bytes(enc, &raw)) {
                Some(identity) => {
                    bytes = Bytes::from(identity);
                    parts.headers.remove(CONTENT_ENCODING);
                }
                None => {
                    tracing::warn!(path = %req_path, encoding = %ce, "page-cache: decode failed; not caching");
                    store_ok = false;
                }
            }
        } else {
            // Unknown or multi-value Content-Encoding — can't canonicalize.
            store_ok = false;
        }
    }

    // (error/empty guard) Never CACHE an empty-bodied success response or a XenForo soft-error
    // page (HTTP 200 carrying the `error` content template). Caching either would pin a broken /
    // blank page at the origin AND at Cloudflare's edge for the full TTL — the cache-poisoning
    // class. The response is still SERVED to THIS client below (an error page is valid to show
    // the requester); it just must never populate the shared cache.
    // Only meaningful when the body is the canonical identity (`store_ok`): a failed
    // Content-Encoding decode leaves `bytes` compressed, so scanning it for the marker would be
    // garbage — and `store_ok == false` already blocks the store below regardless.
    let uncacheable_body = store_ok
        && ((bytes.is_empty() && hit::body_required(status))
            || is_xf_error_page(status, &parts.headers, &bytes));
    if uncacheable_body {
        tracing::warn!(
            path = %req_path,
            status,
            empty = bytes.is_empty(),
            "page-cache: refusing to store empty/error response body"
        );
    }

    // 4. Store if within the per-object size cap. The stored copy drops the
    //    internal control headers, recomputable length/encoding, AND Set-Cookie
    //    (a shared cache entry must never replay one client's cookie — the same
    //    strip CDNs/LiteSpeed apply; the fill response below still carries it to
    //    the originating client).
    // The validator a committed store carries, so the fill response that Cloudflare caches has
    // the same ETag every later hit and 304 will use (it is a hash of these exact bytes).
    let mut fill_etag: Option<HeaderValue> = None;
    if store_ok && !uncacheable_body && bytes.len() as u64 <= cfg.max_obj_bytes {
        let store_timer = state
            .telemetry
            .sample_phase(crate::telemetry::PHASE_SAMPLE_RATE)
            .then(Instant::now);
        // Synthesize a weak validator when the backend gave none (XenForo pages usually
        // don't), so CF can revalidate a stale-but-cacheable page with a conditional GET and
        // get a 304 (headers only) instead of re-pulling the whole body. Served on every hit.
        // Built only for an entry that is actually stored: eagerly for the unadmitted
        // dedicated capsule entry, else once the public entry passes admission (#985).
        let mut stored_etag: Option<HeaderValue> = None;
        let mut eager_headers: Option<Vec<(HeaderName, HeaderValue)>> = None;
        let mut finalize_targets = Vec::with_capacity(2);
        if let (Some(control), true) = (capsule_control, state.xf_capsule.dedicated_store) {
            // (#99) The dedicated capsule entry is stored WITHOUT the W-TinyLFU `admitted` gate
            // that governs the public mirror below — intentionally. The admission sketch frequency
            // is recorded only in `cache_lookup` (the public key), driven by GUEST traffic; capsule
            // member serves go through `capsule_lookup`/`capsule_public_fallback_lookup` and never
            // record it, and the dedicated (prefixed) key accumulates no frequency of its own. So
            // gating the shell store on that guest-only frequency would defeat the capsule exactly
            // for guest-rare-but-member-popular URLs. Eager storage is bounded (the `x-wf-capsule`
            // header is backend-controlled) and capped by the page store.
            let (stored_headers, etag) = stored_headers_with_etag(status, &parts.headers, &bytes);
            stored_etag = etag;
            let key = configuration_key(state, capsule_key(ctx, cc, store));
            let stored_at = Instant::now();
            let stored_identity = identity.to_string();
            let sie_secs = match &disposition {
                Disposition::StorePublic {
                    stale_if_error_secs,
                    ..
                } => *stale_if_error_secs,
                _ => cfg.default_sie_secs,
            };
            let stored = store.store_if_not_purged_since(
                key.clone(),
                CachedResponse {
                    status,
                    identity: stored_identity.clone(),
                    headers: stored_headers.clone(),
                    body: PageBody::InMem(bytes.clone()),
                    variants: Vec::new(),
                    variants_filled: false,
                    dict_gen: 0,
                    tags: capsule_tags(&parts.headers, &tags),
                    vary_cookie_name: String::new(),
                    vary_value: String::new(),
                    scope: PageScope::Public,
                    stored_at,
                    ttl: Duration::from_secs(control.ttl_secs as u64),
                    swr: Duration::from_secs(stale_secs as u64),
                    sie: Duration::from_secs(sie_secs as u64),
                },
                render_epoch,
            );
            if stored {
                state
                    .metrics
                    .xf_capsule_dedicated_stores
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                finalize_targets.push(FinalizeTarget {
                    key_hash: hash_key(&key),
                    key,
                    identity: stored_identity,
                    stored_at,
                });
            }
            eager_headers = Some(stored_headers);
        }
        if capsule_control.is_some() {
            // (#94) Tag the public-shell entry with BOTH capsule tags, matching the dedicated
            // entry (`capsule_tags`), so a coarse `tag=xf_capsule` purge clears both key spaces —
            // otherwise the member-served public-fallback shell survives a "clear all capsules".
            add_tag_once(&mut tags, CAPSULE_TAG);
            add_tag_once(&mut tags, CAPSULE_SHELL_TAG);
        }
        // Scheme must match cache_lookup: keep `ctx.is_tls` as the second key
        // component so a 301 stored for one scheme is never replayed to the other.
        // (#5/#20) Key host = canonical vhost name (not the raw `host` arg), vhost_id =
        // FNV hash of it — identical to cache_lookup so the lookup/store keys agree, and
        // bounded to the finite set of configured vhosts (no Host-header key inflation).
        // The PageScope owner equals the route owner by construction (the eligibility
        // match binds them from the same PrivateRoute), so the shared builder covers it.
        let entry = store_cache_key(state, ctx, cc, store, &route, url_vary_names).map(
            |StoreKey {
                 key,
                 key_hash,
                 identity,
                 url_vary,
             }| PendingEntry {
                key_hash,
                key,
                identity,
                url_vary,
                status,
                tags,
                scope,
                ttl: Duration::from_secs(ttl_secs as u64),
                swr: Duration::from_secs(stale_secs as u64),
                sie: Duration::from_secs(sie_secs as u64),
                render_epoch,
            },
        );
        if let Some(entry) = entry {
            finalize_targets.extend(store_admitted(state, store, entry, &bytes, || {
                eager_headers.unwrap_or_else(|| {
                    let (headers, etag) = stored_headers_with_etag(status, &parts.headers, &bytes);
                    stored_etag = etag;
                    headers
                })
            }));
        }
        if let Some(started) = store_timer {
            state
                .telemetry
                .shard()
                .phase_store
                .record(started.elapsed());
        }
        if !finalize_targets.is_empty() {
            fill_etag = stored_etag;
        }
        // One encode covers the capsule entry and its public mirror (same bytes).
        spawn_store_finalize(
            state,
            &ctx.vhost_name,
            finalize_targets,
            &bytes,
            parts
                .headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        );
    }

    // 5. Serve the buffered body; strip control headers, mark the fill as a miss.
    if let Some(etag) = fill_etag
        && !parts.headers.contains_key(ETAG)
    {
        parts.headers.insert(ETAG, etag);
    }
    strip_control_headers(&mut parts.headers);
    parts.headers.remove(TRANSFER_ENCODING);
    parts
        .headers
        .insert(CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    parts
        .headers
        .insert(HDR_CACHE_STATUS, HeaderValue::from_static("miss"));
    Response::from_parts(parts, Body::Full(bytes))
}

/// A XenForo soft-error page served as HTTP 200. XenForo renders its error reply through the
/// `error` content template (`\XF\Mvc\Renderer\Html::renderErrors` → `public:error`), and the
/// page container emits `data-template="<contentTemplate>"` in the opening `<html>` tag — so an
/// error page carries the exact marker `data-template="error"` near the top of the body. Such a
/// page must never be cached: caching it would pin an error at the origin AND Cloudflare's edge
/// for the full TTL. Only scans 200 `text/html`, and only the head of the body (the marker lives
/// in the `<html>` tag), so it's cheap and low-false-positive (`error` is XF's reserved template
/// name — a normal page reads e.g. `data-template="forum_list"`/`"thread_view"`).
fn is_xf_error_page(status: u16, headers: &HeaderMap, body: &[u8]) -> bool {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    is_xf_error_body(status, content_type, body)
}

fn is_xf_error_body(status: u16, content_type: &str, body: &[u8]) -> bool {
    if status != 200 {
        return false; // non-200 errors are excluded by the cacheable-status gate already
    }
    if !content_type.contains("text/html") {
        return false;
    }
    const SCAN: usize = 8192;
    const MARKER: &[u8] = b"data-template=\"error\"";
    let head = body.get(..SCAN).unwrap_or(body);
    memchr::memmem::find(head, MARKER).is_some()
}

/// A fully received miss, keyed and classified, ready for the admission check and store.
struct PendingEntry {
    key: hj_pagecache::PageCacheKey,
    key_hash: u64,
    identity: String,
    url_vary: Option<UrlVaryCommit>,
    status: u16,
    tags: Vec<Arc<str>>,
    scope: PageScope,
    ttl: Duration,
    swr: Duration,
    sie: Duration,
    render_epoch: u64,
}

/// Admit and store `entry` with `bytes` as its body and `headers()` as its stored headers
/// (built only once the entry is admitted); the finalize target when it was stored.
fn store_admitted(
    state: &Arc<ServerState>,
    store: &hj_pagecache::PageStore,
    entry: PendingEntry,
    bytes: &Bytes,
    headers: impl FnOnce() -> Vec<(HeaderName, HeaderValue)>,
) -> Option<FinalizeTarget> {
    // (W-TinyLFU admission) Spend RAM (store) + CPU (precompress) only on keys that show
    // REUSE. The frequency sketch is recorded on every cacheable lookup; admit when the
    // estimate meets a SIZE-WEIGHTED bar (a one-hit-wonder is rejected; a larger object needs
    // more proven reuse) so the long tail behind Cloudflare can't churn out the hot working
    // set. A rejected response is still served (just neither precompressed nor stored).
    // Private entries skip the W-TinyLFU frequency bar: per-session keys are
    // near-unique so the sketch never accumulates reuse for them, and the
    // whole point is serving the SAME session's next request.
    // (per-URL vary) The vary decision acts BEFORE admission where it only retires: a
    // response that stopped varying drops the spec and its variants, and one that varies on
    // a non-global cookie retires the un-varied base entry it supersedes — whatever happens
    // to this variant below. The spec itself is recorded only for an admitted variant, so
    // one-hit renders (cache-buster queries) cannot grow the spec map.
    if let Some(uv) = &entry.url_vary {
        if uv.names.is_empty() {
            store.url_vary_drop(&uv.base, uv.base_hash);
        } else {
            store.invalidate_key(&uv.base);
        }
    }
    let is_private = matches!(entry.scope, PageScope::Private { .. });
    let admitted = is_private
        || state.page_cache_admission.estimate(entry.key_hash)
            >= admission_threshold(state.page_cache_admit_base, bytes.len() as u64);
    state.telemetry.record_cache_admission(admitted);
    if !admitted {
        return None;
    }
    if let Some(uv) = &entry.url_vary
        && !uv.names.is_empty()
        && !store.url_vary_prepare(&uv.base, uv.base_hash, &uv.names, entry.key_hash)
    {
        state
            .metrics
            .pagecache_url_vary_refused
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    let headers = headers();
    // (PC2-lazy) Store the entry IDENTITY-ONLY (no precompressed serve variant) — variant
    // precompression is deferred to the first cache HIT (`spawn_variant_fill`), so that CPU
    // is spent only on entries proven hot by being SERVED. Dictionary compression is NOT
    // deferred that way: it shrinks the entry's footprint in the capacity-bound file tier,
    // which it occupies whether or not it is ever served (see `spawn_store_finalize`).
    let stored_at = Instant::now();
    let stored = store.store_if_not_purged_since_hashed(
        entry.key_hash,
        entry.key.clone(),
        CachedResponse {
            status: entry.status,
            identity: entry.identity.clone(),
            headers,
            body: PageBody::InMem(bytes.clone()),
            variants: Vec::new(),
            // Private entries never get the lazy variant fill: per-session
            // reuse is too low to pay the precompress CPU/RAM.
            variants_filled: is_private,
            dict_gen: 0,
            tags: entry.tags,
            vary_cookie_name: String::new(),
            vary_value: String::new(),
            scope: entry.scope,
            stored_at,
            ttl: entry.ttl,
            swr: entry.swr,
            sie: entry.sie,
        },
        entry.render_epoch,
    );
    if stored
        && let Some(uv) = &entry.url_vary
        && !store.url_vary_confirm(&uv.base, uv.base_hash, &uv.names, entry.key_hash)
    {
        store.invalidate_key(&entry.key);
        return None;
    }
    stored.then(|| FinalizeTarget {
        key: entry.key,
        key_hash: entry.key_hash,
        identity: entry.identity,
        stored_at,
    })
}

/// What a streamed miss needs to store itself once the backend has finished.
struct FillCommit {
    state: Arc<ServerState>,
    entry: PendingEntry,
    /// The stored headers, snapshotted before the head went to the client; the validator
    /// is added only if the finished body is admitted.
    headers: Vec<(HeaderName, HeaderValue)>,
    content_type: String,
    vhost_name: String,
    /// Held until the store is done, so single-flight followers wake to a hit.
    leader: Option<InflightLeader>,
    /// dispatch()'s render guard drops when the head is returned, but the store
    /// still vetoes on `render_epoch`: maintenance must keep every tag-purge
    /// stamp newer than it until the streamed body is stored or abandoned.
    _render: hj_pagecache::store::RenderEpochGuard,
}

impl FillCommit {
    /// Store off the response's task: the client's end-of-stream never waits for the
    /// tmpfs write.
    fn finish(self, bytes: Bytes) {
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn(async move { self.store(bytes) });
            }
            Err(_) => self.store(bytes),
        }
    }

    fn store(self, bytes: Bytes) {
        let FillCommit {
            state,
            entry,
            headers,
            content_type,
            vhost_name,
            leader,
            _render,
        } = self;
        if let Some(store) = state.page_cache.as_ref() {
            if (bytes.is_empty() && hit::body_required(entry.status))
                || is_xf_error_body(entry.status, &content_type, &bytes)
            {
                tracing::warn!(
                    status = entry.status,
                    empty = bytes.is_empty(),
                    "page-cache: refusing to store empty/error streamed body"
                );
            } else {
                let status = entry.status;
                if let Some(target) = store_admitted(&state, store, entry, &bytes, || {
                    let mut headers = headers;
                    ensure_stored_etag(status, &mut headers, &bytes);
                    headers
                }) {
                    state
                        .metrics
                        .pagecache_stream_fill_stores
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    spawn_store_finalize(&state, &vhost_name, vec![target], &bytes, &content_type);
                }
            }
        }
        drop(leader);
    }
}

/// A page-cache miss served while the backend is still writing it. Each frame is forwarded
/// as it arrives and copied aside; the copy is stored once the backend finishes cleanly. A
/// backend error, an early drop (client gone) or a body past the object cap stores nothing,
/// so a partial body can never become an entry.
struct StreamFill {
    inner: hj_core::StreamBody,
    buf: BytesMut,
    max_bytes: u64,
    commit: Option<FillCommit>,
}

impl StreamFill {
    fn abandon(&mut self) {
        self.commit = None;
        self.buf = BytesMut::new();
    }
}

impl http_body::Body for StreamFill {
    type Data = Bytes;
    type Error = hj_core::BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        let polled = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && this.commit.is_some()
                {
                    if (this.buf.len() + data.len()) as u64 > this.max_bytes {
                        this.abandon();
                    } else {
                        this.buf.extend_from_slice(data);
                    }
                }
            }
            Poll::Ready(Some(Err(_))) => this.abandon(),
            Poll::Ready(None) => {
                if let Some(commit) = this.commit.take() {
                    commit.finish(std::mem::take(&mut this.buf).freeze());
                }
            }
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        // Not before the end-of-stream poll that commits the store.
        self.commit.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

fn accel_buffering_off(headers: &HeaderMap) -> bool {
    headers
        .get_all("x-accel-buffering")
        .iter()
        .any(|v| v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"no"))
}

fn is_event_stream(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|base| base.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// A standard HTTP `Vary` response header is honored only if its sole dimension is
/// `Accept-Encoding` (handled by the per-encoding variant system). Any other token —
/// `Accept-Language`, `User-Agent`, `Cookie`, `*`, … — is a request dimension we do NOT
/// fold into the cache key, so storing would under-key the entry and serve one variant to
/// all clients; such a response is refused. Absent / encoding-only `Vary` ⇒ supported.
fn standard_vary_supported(headers: &HeaderMap) -> bool {
    headers
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .all(|v| {
            v.split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .all(|t| t.eq_ignore_ascii_case("accept-encoding"))
        })
}

/// Defense-in-depth: a public response must not be cached if it sets a cookie
/// the operator marked private/session-bearing (the app should mark such pages
/// no-cache; this guards against a misconfiguration leaking a session).
fn sets_private_cookie(headers: &HeaderMap, private_cookies: &[String]) -> bool {
    if private_cookies.is_empty() {
        return false;
    }
    headers.get_all(SET_COOKIE).iter().any(|v| {
        let Ok(s) = v.to_str() else { return false };
        let name = s.split('=').next().unwrap_or("").trim();
        private_cookies
            .iter()
            .any(|p| hj_pagecache::php_cookie_name_eq(name, p))
    })
}

/// Fully buffer a response body into `Bytes`. Returns `None` only if a stream
/// errors or a File body can't be read. (Only called for cache-eligible — i.e.
/// opted-in, bounded — bodies.)
///
/// (#9) A `Body::File` CAN reach this path: `finalize_response` runs
/// `apply_response_headers` BEFORE `cache_store`, so an `.htaccess`
/// `Header set X-LiteSpeed-Cache-Control: public` on a STATIC file makes the
/// still-File response eligible (the File→Full promotion in `maybe_cache_static`
/// only happens AFTER dispatch returns, too late for the store). Read the file
/// into memory off the runtime so a valid file is cached/served, never dropped as
/// a 502.
/// A body that emits a buffered `prefix` as its first data frame, then delegates to `rest`.
/// Used to serve an over-cap (un-cacheable) unknown-length stream that `collect_body` partially
/// read before deciding not to cache it — without ever holding the whole body in RAM. Both
/// fields are `Unpin` (`Bytes` + a `BoxBody`), so the projection needs no `unsafe`.
struct PrefixedBody {
    prefix: Option<bytes::Bytes>,
    rest: hj_core::StreamBody,
}

impl http_body::Body for PrefixedBody {
    type Data = bytes::Bytes;
    type Error = hj_core::BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(p) = this.prefix.take() {
            if !p.is_empty() {
                return std::task::Poll::Ready(Some(Ok(http_body::Frame::data(p))));
            }
        }
        std::pin::Pin::new(&mut this.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.is_none() && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        // Total length is unknown (that is why we are streaming it through) — defer to the inner.
        self.rest.size_hint()
    }
}

/// Outcome of buffering a response body for the page cache.
enum Collected {
    /// Fully buffered within `max_obj_bytes` — eligible to cache.
    Buffered(Bytes),
    /// The body must be served uncached: either an unknown-length stream exceeded
    /// `max_obj_bytes` (with its consumed prefix reattached), or an exact File read failed
    /// (with the original descriptor/cache lease retained).
    Passthrough(Body),
    /// Stream read error mid-buffer, or a blocking worker failure (unrecoverable here).
    Error,
}

/// Buffer a response body for caching, BOUNDED at `max_obj_bytes`. `Full`/`Empty`/`File` are
/// already size-bounded by the caller's known-length pre-check (a declared-length File/Stream
/// over the cap never reaches here), so they buffer directly. An unknown-length `Stream`
/// (chunked, no Content-Length) is collected frame-by-frame and stops the MOMENT it crosses the
/// cap — so a large or adversarial chunked response marked cacheable can't be slurped unboundedly
/// into RAM (an OOM/DoS vector the old `s.collect()` had). On overflow it is handed back as
/// `Passthrough` to serve through, uncached.
/// Start a streamed-body collect at the declared length, but never pre-reserve more than this:
/// Content-Length is backend-controlled.
const COLLECT_PRESIZE_CAP: u64 = 1 << 20;
/// Starting capacity when no length is declared.
const COLLECT_DEFAULT_CAPACITY: usize = 64 * 1024;

async fn collect_body(body: Body, max_obj_bytes: u64, capacity_hint: usize) -> Collected {
    match body {
        Body::Full(b) => Collected::Buffered(b),
        Body::Empty => Collected::Buffered(Bytes::new()),
        Body::File(mut f) => {
            let (start, len) = match f.range {
                Some((start, end)) => (start, end.saturating_sub(start) + 1),
                None => (0, f.len),
            };
            // `cached` always holds the whole file; apply the inclusive range through
            // FileBody's single-sourced helper, then require the exact advertised size.
            if let Some(bytes) = f.cached_ranged() {
                return if bytes.len() as u64 == len {
                    Collected::Buffered(bytes)
                } else {
                    Collected::Passthrough(Body::File(f))
                };
            }
            match tokio::task::spawn_blocking(move || {
                if f.file.is_none() {
                    match std::fs::File::open(&f.path) {
                        Ok(file) => f.file = Some(file),
                        Err(_) => return (None, f),
                    }
                }
                let bytes = usize::try_from(len).ok().and_then(|len| {
                    let mut bytes = vec![0; len];
                    use std::os::unix::fs::FileExt;
                    f.file.as_ref()?.read_exact_at(&mut bytes, start).ok()?;
                    Some(Bytes::from(bytes))
                });
                (bytes, f)
            })
            .await
            {
                Ok((Some(bytes), _)) => Collected::Buffered(bytes),
                Ok((None, f)) => Collected::Passthrough(Body::File(f)),
                Err(_) => Collected::Error,
            }
        }
        Body::Stream(mut s) => {
            let mut buf = BytesMut::with_capacity(capacity_hint);
            loop {
                match s.frame().await {
                    Some(Ok(frame)) => {
                        // Trailers (non-data frames) are not part of the cached body — skip them,
                        // mirroring the old `Collected::to_bytes()` which dropped them too.
                        if let Ok(data) = frame.into_data() {
                            buf.extend_from_slice(&data);
                            if buf.len() as u64 > max_obj_bytes {
                                // Over cap: re-attach what we've read ahead of the unread
                                // remainder and serve it through, uncached — never materializing
                                // the whole body in RAM. (Over-shoots by at most one frame.)
                                let passthrough = PrefixedBody {
                                    prefix: Some(buf.freeze()),
                                    rest: s,
                                };
                                return Collected::Passthrough(Body::Stream(passthrough.boxed()));
                            }
                        }
                    }
                    Some(Err(_)) => return Collected::Error,
                    None => return Collected::Buffered(buf.freeze()),
                }
            }
        }
    }
}

fn error_502() -> Response {
    http::Response::builder()
        .status(http::StatusCode::BAD_GATEWAY)
        .body(Body::Empty)
        .unwrap_or_else(|_| Response::new(Body::Empty))
}

#[cfg(test)]
mod tests {
    use super::*;

    // (CORS vary) A chain that reads `Origin` (SetEnvIf Origin — the forum's
    // reflected-ACAO rule) must key origin-conditional renders per origin, or
    // the first storer's `Access-Control-Allow-Origin` is replayed to every
    // later visitor. A chain that does not read Origin keeps the historic base
    // key, and an absent Origin keeps it too (pre-fold entries stay hit-able).
    #[tokio::test]
    async fn origin_reading_chain_varies_the_cache_key() {
        let (_state, ctx, store) = cache_test_ctx();
        let reads_origin: Vec<Arc<hj_rewrite::Htaccess>> = vec![Arc::new(
            hj_rewrite::Htaccess::parse("SetEnvIf Origin ^https://a\\.example$ CORS=1\n")
                .expect("parse"),
        )];
        let silent_chain: Vec<Arc<hj_rewrite::Htaccess>> = vec![];
        let origin_a = "https://a.example".to_string();
        let origin_b = "https://b.example".to_string();

        let key_for =
            |chain: &Vec<Arc<hj_rewrite::Htaccess>>, origin: Option<&String>, identity: &str| {
                let cc = CacheCtx {
                    enabled: true,
                    method: &Method::GET,
                    host: "forum.example",
                    cookie: None,
                    identity,
                    req_path: "/config",
                    req_query: "",
                    chain,
                    render_epoch: store.purge_epoch(),
                    has_range: false,
                    vary_value: None,
                    host_foreign: false,
                    origin: origin.map(|s| s.as_str()),
                    ua_class: None,
                    header_vary: None,
                    env_vary: false,
                };
                build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public)
            };

        assert_ne!(
            key_for(&reads_origin, Some(&origin_a), "i"),
            key_for(&reads_origin, Some(&origin_b), "i"),
            "each origin gets its own entry when the chain reflects Origin"
        );
        assert_eq!(
            key_for(&reads_origin, None, "i"),
            key_for(&silent_chain, None, "i"),
            "an absent Origin keeps the historic base key"
        );
        assert_eq!(
            key_for(&silent_chain, Some(&origin_a), "i"),
            key_for(&silent_chain, Some(&origin_b), "i"),
            "a chain that does not read Origin ignores Origin entirely"
        );
    }

    // Regression (#617/#618): a chain reading a non-Origin/UA header (Accept
    // here, via both SetEnvIf and %{HTTP:Accept}) must key per header value.
    #[tokio::test]
    async fn accept_reading_chain_varies_the_cache_key_by_header_vary() {
        let (state, ctx, _store) = cache_test_ctx();
        let ran: Vec<(std::path::PathBuf, Arc<hj_rewrite::Htaccess>)> = vec![(
            std::path::PathBuf::from("/"),
            Arc::new(
                hj_rewrite::Htaccess::parse(
                    "RewriteEngine On\nRewriteCond %{HTTP:Accept} text/event-stream\nRewriteCond %{HTTP:X-Partner} ^yes\nRewriteRule .* - [E=SSE:1]\nSetEnvIf Referer ^https://ref\\.example REF=1\nSetEnvIf User_Agent Googlebot BOT=1\nSetEnvIf Cookie ab_test=b AB=B\n",
                )
                .expect("parse"),
            ),
        )];
        let vary = |accept: Option<&str>, referer: Option<&str>| {
            let mut h = http::HeaderMap::new();
            if let Some(a) = accept {
                h.insert(http::header::ACCEPT, a.parse().unwrap());
            }
            if let Some(r) = referer {
                h.insert(http::header::REFERER, r.parse().unwrap());
            }
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &h)
        };
        assert!(
            vary(None, None).is_none(),
            "absent headers keep historic key"
        );
        assert_ne!(
            vary(Some("text/event-stream"), None),
            vary(Some("text/html"), None)
        );
        assert_eq!(vary(Some("text/html"), None), vary(Some("text/html"), None));
        assert_ne!(vary(None, Some("https://ref.example/x")), vary(None, None));

        let vary_named = |name: &'static str, value: &str| {
            let mut h = http::HeaderMap::new();
            h.insert(name, value.parse().unwrap());
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &h)
        };
        assert_ne!(
            vary_named("x-partner", "yes"),
            vary_named("x-partner", "no")
        );
        assert_ne!(vary_named("user-agent", "Googlebot"), vary(None, None));
        assert_ne!(
            vary_named("cookie", "ab_test=b"),
            vary_named("cookie", "ab_test=a")
        );
    }

    #[tokio::test]
    async fn setenvif_empty_origin_distinguishes_absent_from_present_empty() {
        let (state, ctx, _) = cache_test_ctx();
        let ran = vec![(
            std::path::PathBuf::from("/"),
            Arc::new(hj_rewrite::Htaccess::parse("SetEnvIf Origin ^$ EMPTY=1\n").unwrap()),
        )];
        let absent = http::HeaderMap::new();
        let mut empty = http::HeaderMap::new();
        empty.insert(http::header::ORIGIN, http::HeaderValue::from_static(""));
        assert_ne!(
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &absent),
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &empty)
        );
    }

    #[tokio::test]
    async fn cookie_setenv_vary_tracks_assignments_and_shares_unrelated_cookies() {
        let (state, ctx, _) = cache_test_ctx();
        let ran = vec![(
            std::path::PathBuf::from("/"),
            Arc::new(
                hj_rewrite::Htaccess::parse(concat!(
                    "SetEnvIfNoCase Cookie admin=1 ADMIN=1\n",
                    "SetEnvIf Cookie ab_test=([ab]) AB=$1\n",
                ))
                .unwrap(),
            ),
        )];
        let vary = |cookie: Option<&str>| {
            let mut headers = http::HeaderMap::new();
            if let Some(value) = cookie {
                headers.insert(http::header::COOKIE, value.parse().unwrap());
            }
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &headers)
        };
        assert_eq!(vary(None), vary(Some("xf_csrf=guest-one")));
        assert_eq!(
            vary(None),
            vary(Some("xf_user=1; xf_csrf=member-two")),
            "an ordinary member can find the visitor-invariant capsule shell"
        );
        assert_eq!(
            vary(Some("ab_test=b; xf_csrf=one")),
            vary(Some("ab_test=b; xf_csrf=two"))
        );
        assert_ne!(
            vary(Some("ab_test=a")),
            vary(Some("ab_test=b")),
            "captures must discriminate"
        );
        assert_ne!(vary(Some("admin=1")), vary(None));
        assert_eq!(vary(Some("ADMIN=1")), vary(Some("admin=1")));
    }

    #[tokio::test]
    async fn cookie_rewrite_reads_keep_raw_vary_despite_equal_setenv_results() {
        let (state, ctx, _) = cache_test_ctx();
        let ran = vec![(
            std::path::PathBuf::from("/"),
            Arc::new(
                hj_rewrite::Htaccess::parse(concat!(
                    "SetEnvIf Cookie admin=1 ADMIN=1\n",
                    "RewriteEngine On\nRewriteCond %{HTTP:Cookie} token=one\n",
                    "RewriteRule .* - [E=TOKEN:1]\n",
                ))
                .unwrap(),
            ),
        )];
        let vary = |cookie: &str| {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::COOKIE, cookie.parse().unwrap());
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &headers)
        };
        assert_ne!(vary("token=one"), vary("token=two"));
        assert!(vary("token=one").unwrap().starts_with("cookie:"));
    }

    #[tokio::test]
    async fn cookie_setenv_vary_cannot_alias_a_real_header_dimension() {
        let (state, ctx, _) = cache_test_ctx();
        let ran = vec![(
            std::path::PathBuf::from("/"),
            Arc::new(
                hj_rewrite::Htaccess::parse(concat!(
                    "SetEnvIf Cookie ab_test=b AB=b\n",
                    "RewriteEngine On\nRewriteCond %{HTTP:Cookie-Env} .\n",
                    "RewriteRule .* - [E=HEADER:1]\n",
                ))
                .unwrap(),
            ),
        )];
        let mut cookie = http::HeaderMap::new();
        cookie.insert(http::header::COOKIE, "ab_test=b".parse().unwrap());
        let mut header = http::HeaderMap::new();
        header.insert("cookie-env", "2:AB1:b".parse().unwrap());
        assert_ne!(
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &cookie),
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &header)
        );
    }

    #[tokio::test]
    async fn setenvif_host_aliases_distinguish_the_canonical_vhost_key() {
        let (state, ctx, _) = cache_test_ctx();
        let ran = vec![(
            std::path::PathBuf::from("/"),
            Arc::new(hj_rewrite::Htaccess::parse("SetEnvIf Host ^alias ALIAS=1\n").unwrap()),
        )];
        let mut canonical = http::HeaderMap::new();
        canonical.insert(
            http::header::HOST,
            http::HeaderValue::from_static("forum.example"),
        );
        let mut alias = http::HeaderMap::new();
        alias.insert(
            http::header::HOST,
            http::HeaderValue::from_static("alias.example"),
        );
        assert_ne!(
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &canonical),
            crate::pipeline::page_cache_header_vary(&state, &ctx, &ran, &alias)
        );
    }

    // Regression (#603): a chain whose rewrite conditions read User-Agent produces
    // UA-conditional headers (`Header set X-Crawler-Detected ... env=KNOWN_CRAWLER`), so
    // a crawler's render must not land in (or be served from) the browsers' entry. The
    // UA *class* is folded in; a request matching no UA condition keeps the historic key.
    #[tokio::test]
    async fn user_agent_reading_chain_varies_the_cache_key_by_ua_class() {
        let classified = crate::state::RewriteTuning {
            ua_classify: true,
            ..Default::default()
        };
        let (state, ctx, store) = cache_test_ctx_with_rewrite(
            crate::state::XfCapsuleConfig::disabled(),
            |_| {},
            classified,
        );
        let chain: Vec<Arc<hj_rewrite::Htaccess>> = vec![Arc::new(
            hj_rewrite::Htaccess::parse(
                "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot)\nRewriteRule .* - [E=KNOWN_CRAWLER:1]\n",
            )
            .expect("parse"),
        )];
        let silent_chain: Vec<Arc<hj_rewrite::Htaccess>> = vec![];
        let ran: Vec<(std::path::PathBuf, Arc<hj_rewrite::Htaccess>)> = chain
            .iter()
            .map(|h| (std::path::PathBuf::from("/"), h.clone()))
            .collect();
        let class = |state: &ServerState, ua: &str| {
            let mut h = http::HeaderMap::new();
            h.insert(http::header::USER_AGENT, ua.parse().unwrap());
            crate::pipeline::page_cache_ua_class(state, &ctx, &ran, &h)
        };
        let browser = class(&state, "Mozilla/5.0 (X11; Linux) Chrome/140");
        let googlebot = class(&state, "Mozilla/5.0 (compatible; Googlebot/2.1)");
        let bingbot = class(&state, "Mozilla/5.0 (compatible; Bingbot/2.0)");
        assert!(browser.is_none(), "a browser matches no UA condition");
        assert!(googlebot.is_some());
        assert_eq!(googlebot, bingbot, "both crawlers share one class");

        let key_for = |chain: &Vec<Arc<hj_rewrite::Htaccess>>, ua_class: Option<&String>| {
            let cc = CacheCtx {
                enabled: true,
                method: &Method::GET,
                host: "forum.example",
                cookie: None,
                identity: "i",
                req_path: "/threads/x.1/",
                req_query: "",
                chain,
                render_epoch: store.purge_epoch(),
                has_range: false,
                vary_value: None,
                host_foreign: false,
                origin: None,
                ua_class: ua_class.map(|s| s.as_str()),
                header_vary: None,
                env_vary: false,
            };
            build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public)
        };
        assert_ne!(
            key_for(&chain, googlebot.as_ref()),
            key_for(&chain, browser.as_ref()),
            "a crawler's render gets its own entry"
        );
        assert_eq!(
            key_for(&chain, browser.as_ref()),
            key_for(&silent_chain, None),
            "browsers keep the historic key"
        );

        let (unclassified, _, _) =
            cache_test_ctx_with(crate::state::XfCapsuleConfig::disabled(), |_| {});
        assert!(
            class(&unclassified, "Googlebot/2.1").is_none(),
            "without --rewrite-ua-classify the raw UA is never folded (check warns instead)"
        );

        // A UA cond in a ruleset that is NOT path-cacheable (here: it also reads a
        // cookie) still classifies — the page cache must not depend on that (#603).
        let mixed: Vec<(std::path::PathBuf, Arc<hj_rewrite::Htaccess>)> = vec![(
            std::path::PathBuf::from("/"),
            Arc::new(
                hj_rewrite::Htaccess::parse(
                    "RewriteEngine On\nRewriteCond %{HTTP_REFERER} !^$\nRewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot)\nRewriteRule .* - [E=KNOWN_CRAWLER:1]\n",
                )
                .expect("parse"),
            ),
        )];
        assert!(!mixed[0].1.rules.path_cacheable);
        let mut h = http::HeaderMap::new();
        h.insert(http::header::USER_AGENT, "Googlebot/2.1".parse().unwrap());
        assert_eq!(
            crate::pipeline::page_cache_ua_class(&state, &ctx, &mixed, &h),
            googlebot,
            "same UA conds, same restart-stable class"
        );
    }

    // Regression (#237): private-hit egress forces `private, no-store` onto
    // Cache-Control, but Cloudflare gives `Cloudflare-CDN-Cache-Control` /
    // `CDN-Cache-Control` priority — if the backend's directive survived in the
    // stored headers it would be replayed on every private hit and CF could pin a
    // member page at the shared edge. Both variants must be stripped.
    #[test]
    fn strip_shared_cdn_cache_directives_removes_priority_variants() {
        let mut h = http::HeaderMap::new();
        h.insert(
            "cloudflare-cdn-cache-control",
            http::HeaderValue::from_static("max-age=86400"),
        );
        h.insert(
            "cdn-cache-control",
            http::HeaderValue::from_static("max-age=3600"),
        );
        h.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("private, must-revalidate"),
        );
        strip_shared_cdn_cache_directives(&mut h);
        assert!(h.get("cloudflare-cdn-cache-control").is_none());
        assert!(h.get("cdn-cache-control").is_none());
        assert_eq!(h[http::header::CACHE_CONTROL], "private, must-revalidate");
    }

    // Regression (#239): the xf-capsule vhost allowlist is CLOSED by default — an
    // empty list must disable the capsule tier everywhere, not enable it on all
    // vhosts (the old fail-open default).
    #[tokio::test]
    async fn capsule_vhost_allowlist_is_closed_by_default() {
        let mk_state = |vhosts: std::collections::HashSet<String>| {
            let server = Arc::new(hj_core::config::ServerConfig::default());
            ServerState::new(
                server,
                None,
                None,
                None,
                Arc::new(hj_compress::PageDictRegistry::empty()),
                1,
                {
                    let mut xf = crate::state::XfCapsuleConfig::disabled();
                    xf.enabled = true;
                    xf.vhosts = vhosts;
                    xf
                },
                None,
                false,
                None,
                false,
                crate::state::RewriteTuning::default(),
            )
            .unwrap()
        };
        let server2 = Arc::new(hj_core::config::ServerConfig::default());
        let vhost = Arc::new(hj_core::config::VHostConfig {
            cache_policy: Some(hj_core::config::VhostCachePolicy {
                enable_cache: true,
                enable_public: true,
                enable_private: false,
            }),
            ..Default::default()
        });
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let ctx = ReqCtx {
            vhost_name: "forum.example".into(),
            vhost,
            peer_ip: loopback,
            client_ip: loopback,
            is_tls: true,
            protocol: hj_core::Proto::Http2,
            trusted_proxy: false,
            forwarding_trusted: false,
            env: Vec::new(),
            local_addr: "127.0.0.1:443".parse().unwrap(),
            peer_port: 12345,
            peer_unix: false,
            request_time: std::time::SystemTime::UNIX_EPOCH,
            request_id: Default::default(),
            tls: None,
            redirect_guard: None,
            server: server2,
        };
        assert!(!capsule_vhost_allowed(&mk_state(Default::default()), &ctx));
        let mut listed = std::collections::HashSet::new();
        listed.insert("forum.example".to_string());
        assert!(capsule_vhost_allowed(&mk_state(listed), &ctx));
    }

    // Regression (F15): the capsule safe-GET classifier must match an UNSAFE_PREFIXES entry at
    // a route boundary, not only on a trailing `/`. The old `{prefix}/`-only test let hyphen/dot
    // siblings (`/admin-home`, `/account.json`) be classified safe. The new boundary check is a
    // strict superset, so real capsuled public pages stay safe while siblings of an unsafe
    // prefix are excluded.
    #[test]
    fn capsule_safe_get_prefix_boundary() {
        // Real public pages the capsule serves — must remain SAFE.
        for p in [
            "/",
            "/threads/example.1/",
            "/forums/general.5/",
            "/whats-new/",
            "/help/",
            "/tags/windows/",
            "/members/jane.42/",
            "/index.php",
        ] {
            assert!(capsule_safe_get_candidate(p, ""), "should be safe: {p}");
        }
        // Exact + slash-boundary unsafe routes — unchanged behavior.
        for p in [
            "/admin",
            "/admin/",
            "/account/upgrades",
            "/misc/contact",
            "/login/",
        ] {
            assert!(!capsule_safe_get_candidate(p, ""), "should be unsafe: {p}");
        }
        // Hyphen/dot/query siblings of an unsafe prefix — newly caught by the boundary check.
        for p in [
            "/admin-home",
            "/login-page",
            "/account-x",
            "/api.json",
            "/reports-archive",
            "/misc-tools",
        ] {
            assert!(
                !capsule_safe_get_candidate(p, ""),
                "sibling should be unsafe: {p}"
            );
        }
        // A longer DISTINCT route that merely begins with the same letters must NOT be
        // over-matched (the next byte is alphanumeric, so it is a different token).
        assert!(
            capsule_safe_get_candidate("/admins", ""),
            "/admins is a distinct route"
        );
        assert!(
            capsule_safe_get_candidate("/apidocs", ""),
            "/apidocs is a distinct route"
        );
    }

    // Regression: the io_uring on-core fast path (`uring::CoreHandler::fast` →
    // `cache_lookup`) calls `spawn_guarded` from a monoio thread with NO ambient tokio
    // reactor. A bare `tokio::spawn` there panics ("no reactor running") and, under
    // panic=abort, SIGABRTs the whole process — a live prod crash loop (2026-06-20).
    // With the pipeline runtime captured in PIPELINE_RT, the task must run there even
    // when spawned from a thread that is not inside any tokio runtime.
    #[test]
    fn spawn_guarded_runs_from_non_tokio_thread() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let _ = PIPELINE_RT.set(rt.handle().clone());

        let registry = RefreshRegistry::new(2);
        let (tx, rx) = std::sync::mpsc::channel();
        // Spawn from a plain OS thread: no ambient tokio runtime in scope, exactly like
        // the monoio io_uring core. Pre-fix this panicked; post-fix it must enqueue.
        std::thread::spawn(move || {
            spawn_guarded(&registry, 0xC0FFEE, async move {
                let _ = tx.send(());
            });
        })
        .join()
        .unwrap();

        rx.recv_timeout(Duration::from_secs(5))
            .expect("guarded task ran on the captured pipeline runtime");
    }

    #[test]
    fn dict_saturation_warning_is_rate_limited_per_vhost() {
        let last = std::sync::atomic::AtomicU64::new(0);
        assert!(rate_limit_dict_saturation_warning(&last, 1_000));
        assert!(!rate_limit_dict_saturation_warning(&last, 1_059));
        assert!(rate_limit_dict_saturation_warning(&last, 1_060));
    }

    fn hdrs(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_static(k),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn capsule_control_requires_public_shell_and_parses_ttl() {
        assert!(parse_capsule_control(&hdrs(&[]), 600).is_none());
        assert!(parse_capsule_control(&hdrs(&[("x-wf-capsule", "hit")]), 600).is_none());
        assert!(
            parse_capsule_control(&hdrs(&[("x-wf-capsule", "public-shell, max-age=42")]), 600)
                .is_none()
        );
        let c = parse_capsule_control(
            &hdrs(&[(
                "x-wf-capsule",
                "public-shell, hydrate=account-nav-v1, max-age=42",
            )]),
            600,
        )
        .unwrap();
        assert_eq!(c.ttl_secs, 42);
        let c = parse_capsule_control(
            &hdrs(&[("x-wf-capsule", "hydrate=account-nav-v1, public-shell")]),
            600,
        )
        .unwrap();
        assert_eq!(c.ttl_secs, 600);
    }

    #[test]
    fn capsule_control_headers_are_not_replayed_from_store() {
        let h = hdrs(&[
            ("content-type", "text/html"),
            ("content-length", "12"),
            ("set-cookie", "xf_session=abc"),
            ("x-wf-capsule", "public-shell, max-age=60"),
            ("x-wf-capsule-tags", "public, T1"),
            ("x-litespeed-cache-control", "public,max-age=60"),
        ]);
        let stored = stored_headers_from(&h);
        assert!(stored.iter().any(|(k, _)| k == CONTENT_TYPE));
        assert!(!stored.iter().any(|(k, _)| k == CONTENT_LENGTH));
        assert!(!stored.iter().any(|(k, _)| k == SET_COOKIE));
        assert!(!stored.iter().any(|(k, _)| k.as_str() == HDR_XF_CAPSULE));
        assert!(
            !stored
                .iter()
                .any(|(k, _)| k.as_str() == HDR_XF_CAPSULE_TAGS)
        );
        assert!(!stored.iter().any(|(k, _)| k.as_str() == HDR_CACHE_CONTROL));
    }

    #[test]
    fn capsule_tags_merge_litespeed_and_capsule_tags() {
        let base: Vec<Arc<str>> = vec![Arc::from("public"), Arc::from("T1")];
        let tags = capsule_tags(&hdrs(&[("x-wf-capsule-tags", "T1, F2")]), &base);
        let tags: Vec<&str> = tags.iter().map(|t| t.as_ref()).collect();
        assert_eq!(
            tags,
            vec!["public", "T1", "F2", "xf_capsule", "xf_capsule_shell"]
        );
    }

    #[test]
    fn capsule_reserved_path_guard() {
        // (#95) Any path under the synthetic capsule prefix is refused on the public path so its
        // key can never collide with a dedicated capsule entry's slot. A normal page is unaffected.
        assert!(is_capsule_reserved_path(CAPSULE_KEY_PREFIX));
        assert!(is_capsule_reserved_path(&format!(
            "{CAPSULE_KEY_PREFIX}/threads/1"
        )));
        assert!(!is_capsule_reserved_path("/threads/1"));
        assert!(!is_capsule_reserved_path("/"));
        // The prefix is distinctive enough that no real forum path collides with it.
        assert!(!is_capsule_reserved_path("/account-nav-v1"));
    }

    #[test]
    fn standard_vary_refuses_under_keying_dimensions() {
        // (G-vary) Only Accept-Encoding is keyable (variant system); anything else would
        // under-key and serve one variant to all clients → must not be stored.
        assert!(
            standard_vary_supported(&hdrs(&[])),
            "absent Vary is storable"
        );
        assert!(standard_vary_supported(&hdrs(&[(
            "vary",
            "Accept-Encoding"
        )])));
        assert!(standard_vary_supported(&hdrs(&[(
            "vary",
            "accept-encoding"
        )])));
        assert!(
            !standard_vary_supported(&hdrs(&[("vary", "Accept-Language")])),
            "language under-keys"
        );
        assert!(!standard_vary_supported(&hdrs(&[(
            "vary",
            "Accept-Encoding, User-Agent"
        )])));
        assert!(
            !standard_vary_supported(&hdrs(&[("vary", "*")])),
            "Vary:* is never cacheable"
        );
    }

    fn style_set() -> Vec<String> {
        vec![
            "xf_style_variation".into(),
            "xf_style_id".into(),
            "xf_language_id".into(),
        ]
    }

    fn declared(h: &HeaderMap) -> DeclaredVary {
        declared_vary(Vec::new(), h, &style_set())
    }

    fn names(d: DeclaredVary) -> Option<Vec<String>> {
        match d {
            DeclaredVary::Names(n) => Some(n),
            DeclaredVary::Unsupported { .. } => None,
        }
    }

    #[test]
    fn declared_vary_unions_all_repeated_lines() {
        // Two X-LiteSpeed-Vary lines, both in the global set -> the historic global-only case.
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-litespeed-vary"),
            HeaderValue::from_static("cookie=xf_style_id"),
        );
        h.append(
            HeaderName::from_static("x-litespeed-vary"),
            HeaderValue::from_static("cookie=xf_language_id"),
        );
        assert!(declared(&h).global_only());
        // A third line naming a cookie outside the set makes the URL vary on it.
        h.append(
            HeaderName::from_static("x-litespeed-vary"),
            HeaderValue::from_static("cookie=xf_user"),
        );
        assert_eq!(names(declared(&h)), Some(vec!["xf_user".to_string()]));
    }

    #[test]
    fn vary_absent_is_global_only() {
        assert!(declared(&HeaderMap::new()).global_only());
    }

    #[test]
    fn vary_cookie_subset_is_global_only() {
        let h = hdrs(&[(
            "x-litespeed-vary",
            "cookie=xf_style_variation, cookie=xf_style_id, cookie=xf_language_id",
        )]);
        assert!(declared(&h).global_only());
    }

    #[test]
    fn vary_unknown_cookie_is_a_per_url_dimension() {
        let h = hdrs(&[("x-litespeed-vary", "cookie=tz_date,cookie=xf_style_id")]);
        assert_eq!(names(declared(&h)), Some(vec!["tz_date".to_string()]));
        // The rewrite env's Cache-Vary joins the response's names.
        assert_eq!(
            names(declared_vary(vec!["a_b", "tz_date"], &h, &style_set())),
            Some(vec!["a_b".to_string(), "tz_date".to_string()])
        );
    }

    #[test]
    fn vary_non_cookie_or_malformed_is_unsupported() {
        for v in [
            "cookie=xf_style_id, ismobile",
            "cookie=bad name",
            "cookie=a,cookie=b,cookie=c,cookie=d,cookie=e",
        ] {
            let h = hdrs(&[("x-litespeed-vary", v)]);
            assert!(names(declared(&h)).is_none(), "{v}");
        }
        assert!(matches!(
            declared(&hdrs(&[(
                "x-litespeed-vary",
                "cookie=xf_style_id, ismobile"
            )])),
            DeclaredVary::Unsupported {
                extra_cookie: false
            }
        ));
        assert!(matches!(
            declared(&hdrs(&[("x-litespeed-vary", "cookie=tz_date, ismobile")])),
            DeclaredVary::Unsupported { extra_cookie: true }
        ));
    }

    #[test]
    fn xf_error_page_detected_only_for_the_error_template() {
        let html = hdrs(&[("content-type", "text/html; charset=utf-8")]);
        // A XenForo error page: data-template="error" in the <html> tag → never cache.
        let err = br#"<!DOCTYPE html><html id="XF" data-template="error" lang="en"><head>"#;
        assert!(is_xf_error_page(200, &html, err));
        // A normal page carries a different content template → cacheable.
        let ok = br#"<!DOCTYPE html><html id="XF" data-template="thread_view" lang="en"><head>"#;
        assert!(!is_xf_error_page(200, &html, ok));
        let home = br#"<html data-template="forum_list">"#;
        assert!(!is_xf_error_page(200, &html, home));
        // Must not false-positive on a longer template name that merely starts with "error".
        let close = br#"<html data-template="error_report_form">"#;
        assert!(!is_xf_error_page(200, &html, close));
    }

    #[test]
    fn xf_error_page_only_for_200_html() {
        let html = hdrs(&[("content-type", "text/html")]);
        let err = br#"<html data-template="error">"#;
        // Non-200 is excluded by the cacheable-status gate already.
        assert!(!is_xf_error_page(301, &html, err));
        // Non-HTML (e.g. an API/JSON 200) is never scanned.
        let json = hdrs(&[("content-type", "application/json")]);
        assert!(!is_xf_error_page(200, &json, err));
    }

    #[test]
    fn event_stream_content_type_is_case_insensitive() {
        assert!(is_event_stream("text/event-stream"));
        assert!(is_event_stream("Text/Event-Stream; charset=utf-8"));
        assert!(!is_event_stream("text/plain; note=text/event-stream"));
    }

    #[test]
    fn variant_gate_ignores_dict_compressed_stored_len() {
        let mut entry = CachedResponse {
            status: 200,
            identity: "id".into(),
            headers: Vec::new(),
            body: PageBody::InMem(Bytes::from_static(b"tiny")),
            variants: Vec::new(),
            variants_filled: false,
            dict_gen: 0,
            tags: Vec::new(),
            vary_cookie_name: String::new(),
            vary_value: String::new(),
            scope: PageScope::Public,
            stored_at: Instant::now(),
            ttl: Duration::from_secs(60),
            swr: Duration::ZERO,
            sie: Duration::ZERO,
        };
        assert_eq!(variant_eligibility_len(&entry), 4);
        entry.dict_gen = 42;
        assert_eq!(variant_eligibility_len(&entry), usize::MAX);
    }

    #[test]
    fn xf_error_marker_past_scan_window_is_ignored() {
        // The marker lives in the <html> tag near the top; a stray occurrence deep in a large
        // body (e.g. a forum post quoting the attribute) must not block caching a normal page.
        let html = hdrs(&[("content-type", "text/html")]);
        let mut body = vec![b' '; 9000];
        body.extend_from_slice(br#"data-template="error""#);
        assert!(!is_xf_error_page(200, &html, &body));
    }

    /// #985: the substring search answers exactly what the former `windows` scan did,
    /// including a marker that ends on, or straddles, the 8 KiB scan boundary.
    #[test]
    fn xf_error_marker_scan_matches_the_window_scan_at_the_boundary() {
        const MARKER: &[u8] = br#"data-template="error""#;
        fn window_scan(body: &[u8]) -> bool {
            let head = &body[..body.len().min(8192)];
            head.windows(MARKER.len()).any(|w| w == MARKER)
        }
        let check = |body: &[u8]| {
            assert_eq!(
                is_xf_error_body(200, "text/html", body),
                window_scan(body),
                "len {}",
                body.len()
            );
        };
        check(b"");
        check(&MARKER[..MARKER.len() - 1]);
        check(MARKER);
        for at in (8192 - MARKER.len() - 3)..=8192 {
            for tail in [0usize, 1, 64] {
                let mut body = vec![b' '; at];
                body.extend_from_slice(MARKER);
                body.extend(std::iter::repeat_n(b' ', tail));
                check(&body);
            }
        }
        let mut ends_on_boundary = vec![b' '; 8192 - MARKER.len()];
        ends_on_boundary.extend_from_slice(MARKER);
        assert!(is_xf_error_body(200, "text/html", &ends_on_boundary));
        let mut straddles = vec![b' '; 8192 - MARKER.len() + 1];
        straddles.extend_from_slice(MARKER);
        assert!(!is_xf_error_body(200, "text/html", &straddles));
    }

    #[test]
    fn private_cookie_guard() {
        let priv_set = vec!["xf_session".to_string(), "xf_user".to_string()];
        // csrf/analytics cookies are fine (cached + stripped).
        assert!(!sets_private_cookie(
            &hdrs(&[("set-cookie", "xf_csrf=abc; path=/")]),
            &priv_set
        ));
        // a session cookie forbids public caching.
        assert!(sets_private_cookie(
            &hdrs(&[("set-cookie", "xf_session=secret; path=/")]),
            &priv_set
        ));
        for name in ["xf.session", "xf session", "xf.user", "xf user"] {
            let mut headers = hdrs(&[("set-cookie", "analytics=x")]);
            headers.append(
                SET_COOKIE,
                format!("{name}=secret; path=/").parse().unwrap(),
            );
            assert!(sets_private_cookie(&headers, &priv_set), "{name}");
        }
        assert!(!sets_private_cookie(
            &hdrs(&[("set-cookie", "xf.session_extra=x")]),
            &priv_set
        ));
        // empty guard list => never blocks.
        assert!(!sets_private_cookie(
            &hdrs(&[("set-cookie", "xf_session=x")]),
            &[]
        ));
    }

    #[test]
    fn strip_removes_control_headers_only() {
        let mut h = hdrs(&[
            ("x-litespeed-cache-control", "public,max-age=60"),
            ("x-litespeed-tag", "public, T1"),
            ("x-litespeed-vary", "cookie=xf_style_id"),
            ("x-litespeed-purge", "T1"),
            ("cache-control", "public, max-age=60"),
            ("cloudflare-cdn-cache-control", "max-age=600"),
        ]);
        strip_control_headers(&mut h);
        assert!(!h.contains_key("x-litespeed-cache-control"));
        assert!(!h.contains_key("x-litespeed-tag"));
        assert!(!h.contains_key("x-litespeed-vary"));
        assert!(!h.contains_key("x-litespeed-purge"));
        // CF-facing cache headers must survive.
        assert!(h.contains_key("cache-control"));
        assert!(h.contains_key("cloudflare-cdn-cache-control"));
    }

    #[test]
    fn vhost_id_hash_is_stable_and_distinguishes_vhosts() {
        // (#20) Deterministic, and distinct vhost names get distinct ids so two
        // listeners routing one hostname to different vhosts never collide on the key.
        assert_eq!(
            vhost_id_hash("forum.example"),
            vhost_id_hash("forum.example")
        );
        assert_ne!(
            vhost_id_hash("forum.example"),
            vhost_id_hash("news.forum.example")
        );
        assert_ne!(vhost_id_hash("a"), vhost_id_hash("b"));
    }

    /// Mirror the exact key construction `cache_lookup`/`cache_store` now use (canonical
    /// vhost name as host + FNV vhost_id), so we can assert the keying property without a
    /// full ServerState/ReqCtx.
    fn key_for(vhost_name: &str, path: &str) -> hj_pagecache::PageCacheKey {
        public_with_vary(
            vhost_id_hash(vhost_name),
            true,
            vhost_name.to_ascii_lowercase(),
            path,
            String::new(),
            String::new(),
        )
    }

    #[test]
    fn cache_key_collapses_host_variants_to_canonical_vhost() {
        // (#5) Three distinct attacker-supplied Host values all routing to ONE wildcard
        // vhost must collapse to a SINGLE cache key — keyed by the canonical vhost name,
        // not the raw Host header — so an attacker can't multiply entries by varying Host
        // and evict the legitimate ones (cache-memory-exhaustion DoS). The raw Host is no
        // longer a key input; the resolved vhost name is.
        let k1 = key_for("default_wildcard", "/");
        let k2 = key_for("default_wildcard", "/");
        let k3 = key_for("default_wildcard", "/");
        assert_eq!(k1, k2);
        assert_eq!(k2, k3);
        let mut set = std::collections::HashSet::new();
        set.insert(k1);
        set.insert(k2);
        set.insert(k3);
        assert_eq!(
            set.len(),
            1,
            "all Host variants on one vhost must share one key"
        );
    }

    #[test]
    fn cache_key_isolates_distinct_vhosts() {
        // (#20) Same path, different resolved vhost → different key (different vhost_id
        // AND different canonical host), so cross-vhost content can never collide.
        assert_ne!(
            key_for("forum.example", "/p"),
            key_for("news.forum.example", "/p")
        );
    }

    /// Every key family (public, private, capsule, capsule fallback) for one request.
    fn all_keys_for(
        ctx: &ReqCtx,
        store: &hj_pagecache::PageStore,
        host: &str,
        host_foreign: bool,
        ua_class: Option<&str>,
    ) -> Vec<hj_pagecache::PageCacheKey> {
        let cc = CacheCtx {
            enabled: true,
            method: &Method::GET,
            host,
            cookie: Some("xf_style_id=3"),
            identity: "i",
            req_path: "/threads/a.1/",
            req_query: "page=2",
            chain: &[],
            render_epoch: store.purge_epoch(),
            has_range: false,
            vary_value: None,
            host_foreign,
            origin: None,
            ua_class,
            header_vary: None,
            env_vary: false,
        };
        vec![
            build_cache_key(ctx, &cc, store, &PrivateRoute::Public),
            build_cache_key(
                ctx,
                &cc,
                store,
                &PrivateRoute::Private {
                    owner: 0x1234_5678_9abc_def0,
                    owner2: "o2".into(),
                },
            ),
            capsule_key(ctx, &cc, store),
            capsule_public_fallback_key(ctx, &cc, store),
        ]
    }

    fn render_keys(keys: &[hj_pagecache::PageCacheKey]) -> String {
        keys.iter()
            .map(|k| format!("{:016x}:{k:?}", hash_key(k)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// (#938) Exact-alias hosts get their own key, but a request whose normalized Host IS the
    /// canonical vhost name (and a foreign wildcard-routed host) must keep the pre-#938 key
    /// byte-for-byte, so persisted file-tier, capsule and private entries stay valid across
    /// the deploy. The golden values were captured from the code BEFORE the alias fold.
    #[tokio::test]
    async fn canonical_host_cache_keys_are_byte_stable_across_the_alias_fold() {
        let (_state, ctx, store) = cache_test_ctx();
        assert_eq!(ctx.vhost_name, "forum.example");
        const PLAIN: &str = concat!(
            "5cbdff93fdbff4ab:PageCacheKey { vhost_id: 3328770662, secure: true, host: \"forum.example\", path: \"/threads/a.1/\", normalized_query: \"page=2\", vary_value: \"\", private_owner: 0 }\n",
            "fdcf0b5044494e02:PageCacheKey { vhost_id: 3328770662, secure: true, host: \"forum.example\", path: \"/threads/a.1/\", normalized_query: \"page=2\", vary_value: \"o2\", private_owner: 1311768467463790320 }\n",
            "fe8f818eed53c4e3:PageCacheKey { vhost_id: 3328770662, secure: true, host: \"forum.example\", path: \"/__hj_xf_capsule/account-nav-v1/threads/a.1/\", normalized_query: \"page=2\", vary_value: \"\", private_owner: 0 }\n",
            "5cbdff93fdbff4ab:PageCacheKey { vhost_id: 3328770662, secure: true, host: \"forum.example\", path: \"/threads/a.1/\", normalized_query: \"page=2\", vary_value: \"\", private_owner: 0 }",
        );
        const UA: &str = concat!(
            "af6a556163fd350c:PageCacheKey { vhost_id: 3328770662, secure: true, host: \"forum.example\", path: \"/threads/a.1/\", normalized_query: \"page=2\", vary_value: \"\\0ua:bot\", private_owner: 0 }\n",
            "7f7b01fd90c26d57:PageCacheKey { vhost_id: 3328770662, secure: true, host: \"forum.example\", path: \"/threads/a.1/\", normalized_query: \"page=2\", vary_value: \"o2\\0ua:bot\", private_owner: 1311768467463790320 }\n",
            "9a619d26d838d654:PageCacheKey { vhost_id: 3328770662, secure: true, host: \"forum.example\", path: \"/__hj_xf_capsule/account-nav-v1/threads/a.1/\", normalized_query: \"page=2\", vary_value: \"\\0ua:bot\", private_owner: 0 }\n",
            "af6a556163fd350c:PageCacheKey { vhost_id: 3328770662, secure: true, host: \"forum.example\", path: \"/threads/a.1/\", normalized_query: \"page=2\", vary_value: \"\\0ua:bot\", private_owner: 0 }",
        );
        for host in ["forum.example", "Forum.Example"] {
            assert_eq!(
                render_keys(&all_keys_for(&ctx, &store, host, false, None)),
                PLAIN
            );
            assert_eq!(
                render_keys(&all_keys_for(&ctx, &store, host, false, Some("bot"))),
                UA
            );
        }
        // A foreign (wildcard-routed) host never reads or writes, but its key must not move.
        assert_eq!(
            render_keys(&all_keys_for(&ctx, &store, "www.forum.example", true, None)),
            PLAIN
        );
        // An exact alias gets its own key in every family: same vhost id, alias host.
        let alias = all_keys_for(&ctx, &store, "alias.example", false, None);
        let canonical = all_keys_for(&ctx, &store, "forum.example", false, None);
        for (a, c) in alias.iter().zip(&canonical) {
            assert_ne!(a, c);
            assert_ne!(hash_key(a), hash_key(c));
            assert_eq!(a.vhost_id, c.vhost_id);
            assert_eq!(a.host, "alias.example");
            assert_eq!((&a.path, &a.vary_value), (&c.path, &c.vary_value));
        }
    }

    fn cache_test_ctx() -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        cache_test_ctx_with_capsule(crate::state::XfCapsuleConfig::disabled())
    }

    /// #492: with the opt-in configured, an app-opted 404 and a `/whats-new/` 303 are stored and
    /// then hit; a 303 elsewhere, a self-redirecting 303, and a 404 that sets a private cookie
    /// are not.
    #[tokio::test]
    async fn opted_in_404_and_allowlisted_303_are_cached_but_nothing_else() {
        let (state, ctx, store) =
            cache_test_ctx_with(crate::state::XfCapsuleConfig::disabled(), |cfg| {
                cfg.opt_in_status = vec![404, 410, 303];
                cfg.opt_in_303_prefixes = vec!["/whats-new/".into()];
                cfg.private_cookies = vec!["xf_session".into()];
            });
        let run = |path: &'static str, status: u16, extra: Vec<(&'static str, &'static str)>| {
            let state = state.clone();
            let ctx = ctx.clone();
            let store = store.clone();
            async move {
                let method = Method::GET;
                let identity = format!("https\nforum.example\n{path}");
                let cc = CacheCtx {
                    enabled: true,
                    method: &method,
                    host: "forum.example",
                    cookie: None,
                    identity: &identity,
                    req_path: path,
                    req_query: "",
                    chain: &[],
                    render_epoch: store.purge_epoch(),
                    has_range: false,
                    vary_value: None,
                    host_foreign: false,
                    origin: None,
                    ua_class: None,
                    header_vary: None,
                    env_vary: false,
                };
                let _ = cache_lookup(&state, &ctx, &cc, None, false, None);
                let mut resp = http::Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, "text/html")
                    .header(HDR_CACHE_CONTROL, "public,max-age=86400");
                for (k, v) in extra {
                    resp = resp.header(k, v);
                }
                let body = if status == 404 {
                    &b"<p>gone</p>"[..]
                } else {
                    &b""[..]
                };
                let _ = cache_store(
                    &state,
                    &ctx,
                    &cc,
                    resp.body(Body::Full(Bytes::from_static(body))).unwrap(),
                )
                .await;
                matches!(
                    cache_lookup(&state, &ctx, &cc, None, false, None),
                    CacheOutcome::Hit(_)
                )
            }
        };
        assert!(
            run("/missing-page/", 404, vec![]).await,
            "an opted-in 404 is cached"
        );
        assert!(
            run(
                "/whats-new/posts/",
                303,
                vec![("location", "https://forum.example/whats-new/posts/42/")]
            )
            .await,
            "an allowlisted 303 is cached"
        );
        assert!(
            !run(
                "/threads/slug.1/latest",
                303,
                vec![("location", "https://forum.example/threads/slug.1/page-9")]
            )
            .await,
            "a 303 outside the allowlist is not"
        );
        assert!(
            !run(
                "/whats-new/",
                303,
                vec![("location", "https://forum.example/whats-new/")]
            )
            .await,
            "a self-redirect is never cached"
        );
        assert!(
            !run(
                "/cookie-404/",
                404,
                vec![("set-cookie", "xf_session=abc; path=/")]
            )
            .await,
            "a 404 setting a private cookie is not"
        );
        for (path, name) in [
            ("/cookie-dot-404/", "xf.session=abc; path=/"),
            ("/cookie-space-404/", "xf session=abc; path=/"),
        ] {
            assert!(!run(path, 404, vec![("set-cookie", name)]).await);
        }
    }

    /// #490: the fill response Cloudflare caches must carry the same synthesized validator as
    /// every later hit, and a response that was not stored must carry none.
    #[tokio::test]
    async fn fill_response_carries_the_stored_etag() {
        let (state, ctx, store) = cache_test_ctx();
        let method = Method::GET;
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity: "https\nforum.example\n/etag",
            req_path: "/etag",
            req_query: "",
            chain: &[],
            render_epoch: store.purge_epoch(),
            has_range: false,
            vary_value: None,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
        };
        // The lookup that precedes a real render records the admission sighting.
        assert!(matches!(
            cache_lookup(&state, &ctx, &cc, None, false, None),
            CacheOutcome::Miss(_)
        ));
        let fill = cache_store(
            &state,
            &ctx,
            &cc,
            http::Response::builder()
                .status(200)
                .header(CONTENT_TYPE, "text/html")
                .header(HDR_CACHE_CONTROL, "public,max-age=600")
                .body(Body::Full(Bytes::from_static(b"<p>page</p>")))
                .unwrap(),
        )
        .await;
        let fill_etag = fill.headers().get(ETAG).cloned().expect("fill has an ETag");
        assert!(fill_etag.to_str().unwrap().starts_with("W/\"pc"));
        let CacheOutcome::Hit(hit) = cache_lookup(&state, &ctx, &cc, None, false, None) else {
            panic!("second request must hit");
        };
        assert_eq!(hit.headers().get(ETAG), Some(&fill_etag));

        let not_stored = cache_store(
            &state,
            &ctx,
            &CacheCtx {
                enabled: true,
                identity: "https\nforum.example\n/etag-private",
                req_path: "/etag-private",
                ..cc
            },
            http::Response::builder()
                .status(200)
                .header(CONTENT_TYPE, "text/html")
                .header(HDR_CACHE_CONTROL, "no-cache")
                .body(Body::Full(Bytes::from_static(b"<p>page</p>")))
                .unwrap(),
        )
        .await;
        assert!(not_stored.headers().get(ETAG).is_none());
    }

    fn stored_etag_hashes() -> usize {
        STORED_ETAG_HASHES.with(|n| n.get())
    }

    fn opted_in_page(body: &'static [u8]) -> Response {
        http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html")
            .header(HDR_CACHE_CONTROL, "public,max-age=600")
            .body(Body::Full(Bytes::from_static(body)))
            .unwrap()
    }

    /// #985: a buffered miss the admission sketch rejects hashes no validator and carries
    /// none; once admitted it hashes once, and the fill, the hit and the body hash agree.
    #[tokio::test]
    async fn buffered_store_hashes_the_validator_only_when_admitted() {
        let (state, ctx, store) = cache_test_ctx();
        let method = Method::GET;
        let identity = "https\nforum.example\n/admit";
        let cc = page_cc(&method, "/admit", identity, store.purge_epoch());

        let before = stored_etag_hashes();
        let rejected = cache_store(&state, &ctx, &cc, opted_in_page(b"<p>page</p>")).await;
        assert_eq!(
            stored_etag_hashes(),
            before,
            "a rejected miss hashes nothing"
        );
        assert!(rejected.headers().get(ETAG).is_none());
        assert_eq!(rejected.headers().get(HDR_CACHE_STATUS).unwrap(), "miss");
        assert_eq!(store.entry_count(), 0);

        assert!(matches!(
            cache_lookup(&state, &ctx, &cc, None, false, None),
            CacheOutcome::Miss(_)
        ));
        let fill = cache_store(&state, &ctx, &cc, opted_in_page(b"<p>page</p>")).await;
        assert_eq!(stored_etag_hashes(), before + 1);
        let fill_etag = fill
            .headers()
            .get(ETAG)
            .cloned()
            .expect("admitted fill ETag");
        assert_eq!(fill_etag, hit::weak_etag(b"<p>page</p>").as_str());
        let CacheOutcome::Hit(hit) = cache_lookup(&state, &ctx, &cc, None, false, None) else {
            panic!("the admitted miss was stored");
        };
        assert_eq!(hit.headers().get(ETAG), Some(&fill_etag));
    }

    /// #983: a member POST takes no private route on the store side, yet its purge still
    /// drops the member's private entry and its response is otherwise passed through.
    #[tokio::test]
    async fn member_post_store_purges_without_a_private_route() {
        let (state, mut ctx, store) =
            cache_test_ctx_with(crate::state::XfCapsuleConfig::disabled(), |cfg| {
                cfg.private_enabled = true;
            });
        ctx.vhost = Arc::new(hj_core::config::VHostConfig {
            cache_policy: Some(hj_core::config::VhostCachePolicy {
                enable_cache: true,
                enable_public: true,
                enable_private: true,
            }),
            ..Default::default()
        });
        let member = Some("xf_user=1; xf_session=sessAAAA");
        let identity = "https\nforum.example\n/threads/p.1/";
        let get = Method::GET;
        let get_cc = CacheCtx {
            cookie: member,
            ..page_cc(&get, "/threads/p.1/", identity, store.purge_epoch())
        };
        assert!(matches!(
            cache_lookup(&state, &ctx, &get_cc, None, false, None),
            CacheOutcome::Miss(_)
        ));
        let fill = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html")
            .header(HDR_CACHE_CONTROL, "private,max-age=60")
            .header(HDR_TAG, "T1")
            .body(Body::Full(Bytes::from_static(b"<p>member</p>")))
            .unwrap();
        let _ = cache_store(&state, &ctx, &get_cc, fill).await;
        assert!(matches!(
            cache_lookup(&state, &ctx, &get_cc, None, false, None),
            CacheOutcome::Hit(_)
        ));

        let post = Method::POST;
        let post_cc = CacheCtx {
            method: &post,
            ..get_cc
        };
        let resp = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html")
            .header(http::header::CACHE_CONTROL, "public, max-age=60")
            .header(HDR_CACHE_CONTROL, "private,max-age=60")
            .header(HDR_PURGE, "tag=T1")
            .body(Body::Full(Bytes::from_static(b"<p>saved</p>")))
            .unwrap();
        let resp = cache_store(&state, &ctx, &post_cc, resp).await;
        assert_eq!(
            resp.headers().get(http::header::CACHE_CONTROL).unwrap(),
            "public, max-age=60"
        );
        for name in [HDR_CACHE_CONTROL, HDR_PURGE, "x-litespeed-cache"] {
            assert!(!resp.headers().contains_key(name), "{name}");
        }
        assert!(matches!(resp.into_body(), Body::Full(b) if &b[..] == b"<p>saved</p>"));
        assert_eq!(
            store.entry_count(),
            0,
            "the purge dropped the private entry"
        );
    }

    /// #985: the streamed store adds its validator only after admission too, and the
    /// admitted entry's ETag is still the hash of the whole streamed body.
    #[tokio::test]
    async fn streamed_store_hashes_the_validator_only_when_admitted() {
        let (state, ctx, store) = stream_fill_ctx();
        let method = Method::GET;
        let identity = "https\nforum.example\n/stream-admit".to_string();
        let cc = page_cc(&method, "/stream-admit", &identity, store.purge_epoch());
        let before = stored_etag_hashes();

        for admitted in [false, true] {
            // The uncounted probe leaves the sketch empty, so the first fill is rejected.
            let probe = if admitted {
                cache_lookup(&state, &ctx, &cc, None, false, None)
            } else {
                cache_lookup_fast_path(&state, &ctx, &cc, None)
            };
            let CacheOutcome::Miss(key_hash) = probe else {
                panic!("admitted={admitted}: misses");
            };
            let Enter::Leader(guard) = state.page_cache_inflight.enter(key_hash) else {
                panic!("admitted={admitted}: leads");
            };
            let (feed, resp) = fed_page(None);
            let resp = cache_store_leading(&state, &ctx, &cc, resp, &mut Some(guard)).await;
            let Body::Stream(mut body) = resp.into_body() else {
                panic!("admitted={admitted}: streams");
            };
            let Enter::Follower(follower) = state.page_cache_inflight.enter(key_hash) else {
                panic!("admitted={admitted}: still in flight");
            };
            feed.send(Ok(Bytes::from_static(b"<head>"))).unwrap();
            feed.send(Ok(Bytes::from_static(b"<body>"))).unwrap();
            drop(feed);
            assert_eq!(next_data(&mut body).await.unwrap(), "<head>");
            assert_eq!(next_data(&mut body).await.unwrap(), "<body>");
            assert!(next_data(&mut body).await.is_none());
            tokio::time::timeout(Duration::from_secs(5), follower.wait())
                .await
                .expect("the store attempt releases the leader");
            assert_eq!(stored_etag_hashes(), before + usize::from(admitted));
        }
        let CacheOutcome::Hit(hit) = cache_lookup(&state, &ctx, &cc, None, false, None) else {
            panic!("the admitted stream was stored");
        };
        assert_eq!(
            hit.headers().get(ETAG).unwrap(),
            hit::weak_etag(b"<head><body>").as_str()
        );
    }

    /// #985: a dedicated capsule shell is stored without the admission gate, so its validator
    /// is still hashed eagerly; the fill carries it although the public mirror was rejected.
    #[tokio::test]
    async fn dedicated_capsule_store_keeps_its_eager_validator() {
        let mut capsule = capsule_member_config();
        capsule.dedicated_store = true;
        let (state, ctx, store) = cache_test_ctx_with_capsule(capsule);
        let method = Method::GET;
        let identity = "https\nforum.example\n/threads/eager.1/";
        let cc = page_cc(&method, "/threads/eager.1/", identity, store.purge_epoch());
        let before = stored_etag_hashes();
        let mut resp = opted_in_page(b"<p>shell</p>");
        resp.headers_mut().insert(
            HDR_XF_CAPSULE,
            HeaderValue::from_static("public-shell, hydrate=account-nav-v1, max-age=60"),
        );
        let fill = cache_store(&state, &ctx, &cc, resp).await;
        assert_eq!(stored_etag_hashes(), before + 1);
        assert_eq!(
            state
                .metrics
                .xf_capsule_dedicated_stores
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(store.entry_count(), 1, "only the dedicated shell is stored");
        assert_eq!(
            fill.headers().get(ETAG).unwrap(),
            hit::weak_etag(b"<p>shell</p>").as_str()
        );
    }

    /// A backend body the test feeds frame by frame.
    struct FedBody(tokio::sync::mpsc::UnboundedReceiver<Result<Bytes, hj_core::BoxError>>);

    impl http_body::Body for FedBody {
        type Data = Bytes;
        type Error = hj_core::BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            self.0
                .poll_recv(cx)
                .map(|item| item.map(|r| r.map(http_body::Frame::data)))
        }
    }

    type Feed = tokio::sync::mpsc::UnboundedSender<Result<Bytes, hj_core::BoxError>>;

    fn fed_page(content_length: Option<usize>) -> (Feed, Response) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut b = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html")
            .header(HDR_CACHE_CONTROL, "public,max-age=600");
        if let Some(n) = content_length {
            b = b.header(CONTENT_LENGTH, n);
        }
        (tx, b.body(Body::Stream(FedBody(rx).boxed())).unwrap())
    }

    fn stream_fill_ctx() -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        cache_test_ctx_with(crate::state::XfCapsuleConfig::disabled(), |cfg| {
            cfg.stream_fill_vhosts = vec!["forum.example".into()];
            cfg.max_obj_bytes = 64;
        })
    }

    fn page_cc<'a>(
        method: &'a Method,
        path: &'a str,
        identity: &'a str,
        epoch: u64,
    ) -> CacheCtx<'a> {
        CacheCtx {
            enabled: true,
            method,
            host: "forum.example",
            cookie: None,
            identity,
            req_path: path,
            req_query: "",
            chain: &[],
            render_epoch: epoch,
            has_range: false,
            vary_value: None,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
        }
    }

    async fn next_data(body: &mut hj_core::StreamBody) -> Option<Bytes> {
        loop {
            match body.frame().await? {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        return Some(data);
                    }
                }
                Err(_) => return None,
            }
        }
    }

    /// A miss on a stream-fill vhost reaches the client frame by frame while the backend is
    /// still writing, and is stored once the backend finishes. Single-flight followers keep
    /// waiting until the entry exists.
    #[tokio::test]
    async fn streamed_miss_is_forwarded_early_and_stored_at_the_end() {
        let (state, ctx, store) = stream_fill_ctx();
        let method = Method::GET;
        let identity = "https\nforum.example\n/moon".to_string();
        let cc = page_cc(&method, "/moon", &identity, store.purge_epoch());
        let CacheOutcome::Miss(key_hash) = cache_lookup(&state, &ctx, &cc, None, false, None)
        else {
            panic!("first request misses");
        };
        let Enter::Leader(guard) = state.page_cache_inflight.enter(key_hash) else {
            panic!("first misser leads");
        };
        let mut leader = Some(guard);
        let (feed, resp) = fed_page(None);
        let resp = cache_store_leading(&state, &ctx, &cc, resp, &mut leader).await;
        assert!(leader.is_none(), "the streamed miss owns the leader");
        assert!(resp.headers().get(CONTENT_LENGTH).is_none());
        assert_eq!(resp.headers().get(HDR_CACHE_STATUS).unwrap(), "miss");
        assert!(
            resp.extensions()
                .get::<hj_compress::ProgressiveBody>()
                .is_some()
        );
        let Body::Stream(mut body) = resp.into_body() else {
            panic!("a no-Content-Length miss streams");
        };

        feed.send(Ok(Bytes::from_static(b"<head>"))).unwrap();
        assert_eq!(next_data(&mut body).await.unwrap(), "<head>");
        let Enter::Follower(follower) = state.page_cache_inflight.enter(key_hash) else {
            panic!("the render is still in flight");
        };
        feed.send(Ok(Bytes::from_static(b"<body>"))).unwrap();
        drop(feed);
        assert_eq!(next_data(&mut body).await.unwrap(), "<body>");
        assert!(next_data(&mut body).await.is_none());

        tokio::time::timeout(Duration::from_secs(5), follower.wait())
            .await
            .expect("the leader is released after the store");
        let CacheOutcome::Hit(hit) = cache_lookup(&state, &ctx, &cc, None, false, None) else {
            panic!("the finished stream was stored before followers woke");
        };
        match hit.into_body() {
            Body::Full(b) => assert_eq!(&b[..], b"<head><body>"),
            _ => panic!("an in-RAM hit is Full"),
        }
        let m = &state.metrics;
        assert_eq!(
            m.pagecache_stream_fills
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            m.pagecache_stream_fill_stores
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// Regression (#949): a cacheable streamed response sent with `X-Accel-Buffering: no`
    /// is a live feed. The store must not collect it (that held every byte until the
    /// backend finished): it passes through frame by frame and is never stored.
    #[tokio::test]
    async fn accel_buffering_off_stream_passes_through_uncached() {
        let (state, ctx, store) =
            cache_test_ctx_with(crate::state::XfCapsuleConfig::disabled(), |_| {});
        let method = Method::GET;
        let identity = "https\nforum.example\n/feed".to_string();
        let cc = page_cc(&method, "/feed", &identity, store.purge_epoch());
        let (feed, mut resp) = fed_page(None);
        resp.headers_mut()
            .insert("x-accel-buffering", HeaderValue::from_static("no"));
        let resp = cache_store(&state, &ctx, &cc, resp).await;
        assert!(resp.headers().get(HDR_CACHE_CONTROL).is_none());
        let Body::Stream(mut body) = resp.into_body() else {
            panic!("an unbuffered feed stays a stream");
        };
        feed.send(Ok(Bytes::from_static(b"line1\n"))).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), next_data(&mut body))
                .await
                .expect("the first frame arrives before the backend finishes")
                .unwrap(),
            "line1\n"
        );
        drop(feed);
        assert!(next_data(&mut body).await.is_none());
        assert!(matches!(
            cache_lookup(&state, &ctx, &cc, None, false, None),
            CacheOutcome::Miss(_)
        ));
    }

    /// A streamed miss that errors, is dropped by the client, or outgrows the object cap is
    /// never stored, and its leader is released so followers render for themselves.
    #[tokio::test]
    async fn cut_short_or_oversized_streamed_miss_stores_nothing() {
        let (state, ctx, store) = stream_fill_ctx();
        let method = Method::GET;
        for (path, case) in [("/err", 0), ("/drop", 1), ("/big", 2)] {
            let identity = format!("https\nforum.example\n{path}");
            let cc = page_cc(&method, path, &identity, store.purge_epoch());
            let CacheOutcome::Miss(key_hash) = cache_lookup(&state, &ctx, &cc, None, false, None)
            else {
                panic!("{path}: first request misses");
            };
            let Enter::Leader(guard) = state.page_cache_inflight.enter(key_hash) else {
                panic!("{path}: first misser leads");
            };
            let (feed, resp) = fed_page(None);
            let resp = cache_store_leading(&state, &ctx, &cc, resp, &mut Some(guard)).await;
            let Body::Stream(mut body) = resp.into_body() else {
                panic!("{path}: streams");
            };
            feed.send(Ok(Bytes::from_static(b"<head>"))).unwrap();
            assert_eq!(next_data(&mut body).await.unwrap(), "<head>");
            match case {
                0 => {
                    feed.send(Err("backend died".into())).unwrap();
                    assert!(matches!(body.frame().await, Some(Err(_))));
                }
                1 => drop(body),
                _ => {
                    let big = Bytes::from(vec![b'x'; 100]);
                    feed.send(Ok(big.clone())).unwrap();
                    drop(feed);
                    assert_eq!(next_data(&mut body).await.unwrap(), big, "still served");
                    assert!(next_data(&mut body).await.is_none());
                }
            }
            tokio::task::yield_now().await;
            assert!(
                matches!(state.page_cache_inflight.enter(key_hash), Enter::Leader(_)),
                "{path}: leader released"
            );
            assert!(
                matches!(
                    cache_lookup(&state, &ctx, &cc, None, false, None),
                    CacheOutcome::Miss(_)
                ),
                "{path}: nothing stored"
            );
        }
        assert_eq!(
            state
                .metrics
                .pagecache_stream_fill_stores
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// A tag purge that lands while a streamed miss is still being written vetoes its
    /// store even after maintenance has pruned the purge stamp: the fill keeps its
    /// render epoch active although dispatch()'s own guard is gone.
    #[tokio::test]
    async fn streamed_miss_purged_mid_stream_is_not_stored_after_maintenance() {
        let (state, ctx, store) = stream_fill_ctx();
        let method = Method::GET;
        let identity = "https\nforum.example\n/purged".to_string();
        let cc = page_cc(&method, "/purged", &identity, store.purge_epoch());
        let CacheOutcome::Miss(key_hash) = cache_lookup(&state, &ctx, &cc, None, false, None)
        else {
            panic!("first request misses");
        };
        let Enter::Leader(guard) = state.page_cache_inflight.enter(key_hash) else {
            panic!("first misser leads");
        };
        let (feed, mut resp) = fed_page(None);
        resp.headers_mut()
            .insert(HDR_TAG, HeaderValue::from_static("T1"));
        let resp = cache_store_leading(&state, &ctx, &cc, resp, &mut Some(guard)).await;
        let Body::Stream(mut body) = resp.into_body() else {
            panic!("a no-Content-Length miss streams");
        };
        feed.send(Ok(Bytes::from_static(b"<pre-purge>"))).unwrap();
        assert_eq!(next_data(&mut body).await.unwrap(), "<pre-purge>");
        let Enter::Follower(follower) = state.page_cache_inflight.enter(key_hash) else {
            panic!("the render is still in flight");
        };

        store.purge_tags(&["T1"]);
        store.maintenance(Duration::from_secs(90));
        store.maintenance(Duration::from_secs(90));

        drop(feed);
        assert!(next_data(&mut body).await.is_none());
        tokio::time::timeout(Duration::from_secs(5), follower.wait())
            .await
            .expect("the leader is released after the store attempt");
        assert!(
            matches!(
                cache_lookup(&state, &ctx, &cc, None, false, None),
                CacheOutcome::Miss(_)
            ),
            "a body rendered before the purge must not be stored"
        );
    }

    /// Framed (Content-Length) bodies and vhosts without the opt-in keep the buffered miss.
    #[tokio::test]
    async fn framed_or_unlisted_misses_are_still_buffered() {
        for (listed, content_length) in [(true, Some(6)), (false, None)] {
            let (state, ctx, store) =
                cache_test_ctx_with(crate::state::XfCapsuleConfig::disabled(), |cfg| {
                    if listed {
                        cfg.stream_fill_vhosts = vec!["forum.example".into()];
                    }
                });
            let method = Method::GET;
            let identity = "https\nforum.example\n/framed".to_string();
            let cc = page_cc(&method, "/framed", &identity, store.purge_epoch());
            let _ = cache_lookup(&state, &ctx, &cc, None, false, None);
            let (feed, resp) = fed_page(content_length);
            feed.send(Ok(Bytes::from_static(b"<page>"))).unwrap();
            drop(feed);
            let resp = cache_store(&state, &ctx, &cc, resp).await;
            assert!(
                resp.extensions()
                    .get::<hj_compress::ProgressiveBody>()
                    .is_none()
            );
            assert!(
                matches!(resp.into_body(), Body::Full(b) if &b[..] == b"<page>"),
                "listed={listed}: buffered"
            );
            assert!(matches!(
                cache_lookup(&state, &ctx, &cc, None, false, None),
                CacheOutcome::Hit(_)
            ));
        }
    }

    /// Regression (#594): a buffered (non-stream-fill) miss whose backend body ends
    /// in an error (LSAPI now surfaces a worker that died before RESP_END this way)
    /// must store nothing, so a truncated page can never become a hit.
    #[tokio::test]
    async fn buffered_miss_with_errored_body_stores_nothing() {
        let (state, ctx, store) =
            cache_test_ctx_with(crate::state::XfCapsuleConfig::disabled(), |_| {});
        let method = Method::GET;
        let identity = "https\nforum.example\n/cut".to_string();
        let cc = page_cc(&method, "/cut", &identity, store.purge_epoch());
        let _ = cache_lookup(&state, &ctx, &cc, None, false, None);
        let (feed, resp) = fed_page(None);
        feed.send(Ok(Bytes::from_static(b"<page>"))).unwrap();
        feed.send(Err("lsapi response EOF before RESP_END".into()))
            .unwrap();
        drop(feed);
        let _ = cache_store(&state, &ctx, &cc, resp).await;
        assert!(
            matches!(
                cache_lookup(&state, &ctx, &cc, None, false, None),
                CacheOutcome::Miss(_)
            ),
            "a truncated body must not be stored"
        );
    }

    /// Regression (30b7fda): a cookieless request probes on the fast path and, on a miss,
    /// looks up again in dispatch. Both used to record the admission sighting and the miss,
    /// so the "seen twice" bar passed on first sight and the miss count doubled.
    #[tokio::test]
    async fn fast_path_probe_counts_only_the_hits_it_serves() {
        let (state, ctx, store) = cache_test_ctx();
        let method = Method::GET;
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity: "https\nforum.example\n/fast",
            req_path: "/fast",
            req_query: "",
            chain: &[],
            render_epoch: store.purge_epoch(),
            has_range: false,
            vary_value: None,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
        };
        let key = configuration_key(
            &state,
            build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public),
        );
        let key_hash = hash_key(&key);

        // First request: fast-path miss, then dispatch's lookup — ONE sighting, ONE miss.
        assert!(matches!(
            cache_lookup_fast_path(&state, &ctx, &cc, None),
            CacheOutcome::Miss(_)
        ));
        assert_eq!(state.page_cache_admission.estimate(key_hash), 0);
        assert_eq!(store.stats().misses, 0);
        assert!(matches!(
            cache_lookup(&state, &ctx, &cc, None, false, None),
            CacheOutcome::Miss(_)
        ));
        assert_eq!(state.page_cache_admission.estimate(key_hash), 1);
        assert_eq!(store.stats().misses, 1);
        // (The fixture admits on one sighting.) A fast-path hit ends the request, so it is
        // the lookup that records the sighting and the hit.
        let response = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/plain")
            .header(HDR_CACHE_CONTROL, "public,max-age=600")
            .body(Body::Full(Bytes::from_static(b"page")))
            .unwrap();
        let _ = cache_store(&state, &ctx, &cc, response).await;
        let hits_before = store.stats().hits;
        assert!(matches!(
            cache_lookup_fast_path(&state, &ctx, &cc, None),
            CacheOutcome::Hit(_)
        ));
        assert_eq!(store.stats().hits, hits_before + 1);
        assert_eq!(store.stats().misses, 1);
        assert_eq!(state.page_cache_admission.estimate(key_hash), 2);
    }

    #[tokio::test]
    async fn configuration_generations_isolate_late_cache_writers() {
        let (old, ctx, store) = cache_test_ctx();
        let mut next = ServerState::reload(&old, old.server.clone()).unwrap();
        Arc::get_mut(&mut next).unwrap().response_cache_epoch =
            Some(Arc::from("test-incarnation-1"));
        let later = ServerState::reload(&next, next.server.clone()).unwrap();
        let method = Method::GET;
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity: "https\nforum.example\n/config",
            req_path: "/config",
            req_query: "",
            chain: &[],
            render_epoch: store.purge_epoch(),
            has_range: false,
            vary_value: None,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
        };
        let base = build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public);
        let old_key = configuration_key(&old, base.clone());
        let next_key = configuration_key(&next, base.clone());
        let later_key = configuration_key(&later, base.clone());
        assert_eq!(old_key, base);
        assert_ne!(old_key, next_key);
        assert_ne!(next_key, later_key);
        for (state, key, text) in [(&next, &next_key, "new"), (&old, &old_key, "late old")] {
            state.page_cache_admission.record(hash_key(key));
            let response = http::Response::builder()
                .status(200)
                .header(CONTENT_TYPE, "text/plain")
                .header(HDR_CACHE_CONTROL, "public,max-age=600")
                .body(Body::Full(Bytes::from_static(text.as_bytes())))
                .unwrap();
            let _ = cache_store(state, &ctx, &cc, response).await;
        }
        let hj_pagecache::EntryState::Fresh(entry) =
            store.get_entry(&next_key, cc.identity, Instant::now())
        else {
            panic!("new generation entry missing");
        };
        assert!(matches!(&entry.body, PageBody::InMem(bytes) if bytes.as_ref() == b"new"));
        let CacheOutcome::Hit(response) = cache_lookup(&next, &ctx, &cc, None, false, None) else {
            panic!("new generation lookup did not hit");
        };
        assert!(matches!(response.into_body(), Body::Full(bytes) if bytes.as_ref() == b"new"));
        assert!(matches!(
            store.get_entry(&later_key, cc.identity, Instant::now()),
            hj_pagecache::EntryState::Miss
        ));
        for key in [
            capsule_key(&ctx, &cc, &store),
            capsule_public_fallback_key(&ctx, &cc, &store),
        ] {
            assert_ne!(
                configuration_key(&old, key.clone()),
                configuration_key(&next, key)
            );
        }
    }

    #[test]
    fn capsule_refresh_cookie_preserves_empty_and_duplicate_vary_key_pairs() {
        let mut cfg = hj_pagecache::StoreConfig::default();
        cfg.vary_cookies = vec![
            "xf_style_id".into(),
            "xf_language_id".into(),
            "xf_user".into(),
            "xf_session".into(),
        ];
        cfg.private_user_cookie = "xf_user".into();
        cfg.private_session_cookie = "xf_session".into();
        let store = hj_pagecache::PageStore::new(cfg);
        let original = "XF_STYLE_ID=; xf_style_id=4; xf_language_id=2; \
                        xf_user=secret; xf_session=session; unrelated=x";
        let rebuilt = capsule_public_refresh_cookie(Some(original), &store)
            .expect("public vary pairs remain");
        assert_eq!(rebuilt, "xf_style_id=4; xf_language_id=2");

        let public_vary: Vec<String> = vec!["xf_style_id".into(), "xf_language_id".into()];
        let before = hj_pagecache::compute_vary_value(Some(original), &public_vary);
        let after = hj_pagecache::compute_vary_value(rebuilt.to_str().ok(), &public_vary);
        assert_eq!(
            after, before,
            "rebuilt Cookie must target the exact stale key"
        );
    }

    #[test]
    fn cookie_lookup_is_case_sensitive_and_first_exact_match_wins() {
        let header = Some("XF_USER=wrong; xf_user=first; xf_user=second");
        assert_eq!(cookie_value(header, "xf_user"), Some("first"));
        assert_eq!(cookie_value(Some("xf[user=m"), "xf_user"), Some("m"));
        assert_eq!(cookie_value(Some("xf_user =m"), "xf_user"), None);
        assert_eq!(cookie_value(header, "XF_USER"), Some("wrong"));
        assert_eq!(cookie_value(header, "Xf_User"), None);
    }

    /// Fixture for the `--page-cache-shared-paths` routing tests: private tier ON,
    /// vhost allows private + public, shared paths parsed from `spec` at `canary`%.
    fn shared_paths_ctx(
        spec: &str,
        canary: u8,
    ) -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        let mut cfg = hj_pagecache::StoreConfig::default();
        cfg.private_enabled = true;
        cfg.private_user_cookie = "xf_user".into();
        cfg.private_session_cookie = "xf_session".into();
        cfg.shared_public_paths = hj_pagecache::parse_shared_paths(spec).unwrap();
        cfg.shared_paths_canary_percent = canary;
        let store = Arc::new(hj_pagecache::PageStore::new(cfg));
        let mut server = hj_core::config::ServerConfig::default();
        server.server_root = std::env::temp_dir().join(format!(
            "httpjet_sharedpaths_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let server = Arc::new(server);
        let vhost = Arc::new(hj_core::config::VHostConfig {
            cache_policy: Some(hj_core::config::VhostCachePolicy {
                enable_cache: true,
                enable_public: true,
                enable_private: true,
            }),
            ..Default::default()
        });
        let state = ServerState::new(
            server.clone(),
            None,
            None,
            Some(store.clone()),
            Arc::new(hj_compress::PageDictRegistry::empty()),
            1,
            crate::state::XfCapsuleConfig::disabled(),
            None,
            false,
            None,
            false,
            crate::state::RewriteTuning::default(),
        )
        .unwrap();
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let ctx = ReqCtx {
            server,
            vhost_name: "forum.example".into(),
            vhost,
            peer_ip: loopback,
            client_ip: loopback,
            is_tls: true,
            protocol: hj_core::Proto::Http2,
            trusted_proxy: false,
            forwarding_trusted: false,
            env: Vec::new(),
            local_addr: "127.0.0.1:443".parse().unwrap(),
            peer_port: 12345,
            peer_unix: false,
            request_time: std::time::SystemTime::UNIX_EPOCH,
            request_id: Default::default(),
            tls: None,
            redirect_guard: None,
        };
        (state, ctx, store)
    }

    fn shared_paths_route(
        state: &ServerState,
        ctx: &ReqCtx,
        store: &hj_pagecache::PageStore,
        cookie: Option<&'static str>,
        path: &'static str,
        query: &'static str,
        count: bool,
    ) -> PrivateRoute {
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie,
            identity: "https\nforum.example\ntest",
            req_path: path,
            req_query: query,
            chain: &chain,
            render_epoch: 0,
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        private_route(state, ctx, store, &cc, count)
    }

    const MEMBER: Option<&str> = Some("xf_user=1%2Ctok; xf_session=sessAAAAAAAA");
    const SHARED_SPEC: &str = "proxy.php?image,/wf-unfurl/image";

    #[tokio::test]
    async fn shared_path_member_routes_public_and_counts() {
        let (state, ctx, store) = shared_paths_ctx(SHARED_SPEC, 100);
        // Matching exact-with-param and prefix forms both route PUBLIC for a member.
        for (p, q) in [
            ("/proxy.php", "image=https%3A%2F%2Fx&hash=abc"),
            ("/wf-unfurl/image/abc.webp", ""),
        ] {
            assert!(
                matches!(
                    shared_paths_route(&state, &ctx, &store, MEMBER, p, q, true),
                    PrivateRoute::Public
                ),
                "{p}?{q} must route public"
            );
        }
        assert_eq!(
            state
                .metrics
                .page_cache_shared_path_public_routes
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        // The store-side re-derivation (count=false) must not double-count.
        let _ = shared_paths_route(&state, &ctx, &store, MEMBER, "/proxy.php", "image=x", false);
        assert_eq!(
            state
                .metrics
                .page_cache_shared_path_public_routes
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    /// (2026-10-04) A session-only login (`xf_session` without the `xf_user` remember cookie)
    /// is a member too. Routing it PUBLIC served the cached GUEST page with `public,
    /// max-age=604800` to a logged-in visitor; now either logged-in marker leaves the public
    /// tier. Guests (no marker, or an empty session value) still route public, and the
    /// visitor-invariant shared paths stay public for everyone.
    #[tokio::test]
    async fn session_only_cookie_never_routes_public() {
        let (state, ctx, store) = shared_paths_ctx(SHARED_SPEC, 100);
        let session_only = Some("xf_csrf=abc; xf_session=sessOnlyAAAA");
        assert!(
            !matches!(
                shared_paths_route(
                    &state,
                    &ctx,
                    &store,
                    session_only,
                    "/threads/x.1/",
                    "",
                    true
                ),
                PrivateRoute::Public
            ),
            "a session-only login must never read or store the public tier"
        );
        assert!(matches!(
            shared_paths_route(
                &state,
                &ctx,
                &store,
                Some("xf_csrf=abc"),
                "/threads/x.1/",
                "",
                true
            ),
            PrivateRoute::Public
        ));
        assert!(matches!(
            shared_paths_route(
                &state,
                &ctx,
                &store,
                Some("xf_session="),
                "/threads/x.1/",
                "",
                true
            ),
            PrivateRoute::Public
        ));
        assert!(matches!(
            shared_paths_route(
                &state,
                &ctx,
                &store,
                session_only,
                "/wf-unfurl/image/abc.webp",
                "",
                true
            ),
            PrivateRoute::Public
        ));
    }

    #[tokio::test]
    async fn shared_path_non_matching_member_stays_private() {
        let (state, ctx, store) = shared_paths_ctx(SHARED_SPEC, 100);
        // A page URL, the link-proxy form (no image=), and a prefix near-miss all
        // keep the private-tier routing.
        for (p, q) in [
            ("/help/", ""),
            ("/proxy.php", "link=https%3A%2F%2Fx&hash=abc"),
            ("/wf-unfurl", ""),
        ] {
            assert!(
                matches!(
                    shared_paths_route(&state, &ctx, &store, MEMBER, p, q, true),
                    PrivateRoute::Private { .. }
                ),
                "{p}?{q} must stay private"
            );
        }
        assert_eq!(
            state
                .metrics
                .page_cache_shared_path_public_routes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn shared_path_canary_zero_stays_private_and_counts_skip() {
        let (state, ctx, store) = shared_paths_ctx(SHARED_SPEC, 0);
        assert!(matches!(
            shared_paths_route(
                &state,
                &ctx,
                &store,
                MEMBER,
                "/proxy.php",
                "image=x&hash=y",
                true
            ),
            PrivateRoute::Private { .. }
        ));
        assert_eq!(
            state
                .metrics
                .page_cache_shared_path_canary_skipped
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            state
                .metrics
                .page_cache_shared_path_public_routes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn shared_path_empty_spec_is_inert() {
        let (state, ctx, store) = shared_paths_ctx("", 100);
        assert!(matches!(
            shared_paths_route(
                &state,
                &ctx,
                &store,
                MEMBER,
                "/proxy.php",
                "image=x&hash=y",
                true
            ),
            PrivateRoute::Private { .. }
        ));
    }

    #[tokio::test]
    async fn shared_path_guest_and_sessionless_member_route_as_expected() {
        let (state, ctx, store) = shared_paths_ctx(SHARED_SPEC, 100);
        // Guests are public regardless of the allowlist (unchanged behavior).
        assert!(matches!(
            shared_paths_route(&state, &ctx, &store, None, "/help/", "", true),
            PrivateRoute::Public
        ));
        // A member WITHOUT a session cookie is unkeyable for the private tier
        // (Bypass today) — but an allowlisted visitor-invariant endpoint may
        // still route public, while a page keeps the Bypass.
        let userless = Some("xf_user=1%2Ctok");
        assert!(matches!(
            shared_paths_route(
                &state,
                &ctx,
                &store,
                userless,
                "/proxy.php",
                "image=x",
                true
            ),
            PrivateRoute::Public
        ));
        assert!(matches!(
            shared_paths_route(&state, &ctx, &store, userless, "/help/", "", true),
            PrivateRoute::Bypass
        ));
    }

    /// A store must dict-compress on the STORE itself, with no cache hit ever occurring. Hit-gating
    /// this left the never-hit tail — which is most of what fills the capacity-bound file tier —
    /// stored as full-size identity, so those bodies evicted entries that would otherwise have
    /// survived.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn store_dict_compresses_without_any_hit() {
        let (state, ctx, store) = cache_test_ctx_with_dict();
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/dict.1/";
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity,
            req_path: "/threads/dict.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let key = build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public);
        // Clear the W-TinyLFU bar the way a real second sighting would, so the entry is admitted.
        state.page_cache_admission.record(hash_key(&key));

        // A body the dictionary can actually shrink past the 12.5% savings gate.
        let body = DICT_CORPUS.repeat(8);
        let resp = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(HDR_CACHE_CONTROL, "public,max-age=600")
            .body(Body::Full(Bytes::from(body.clone())))
            .unwrap();
        let _ = cache_store(&state, &ctx, &cc, resp).await;

        // The compression runs on the bounded background pool, so poll for it. NOTHING here ever
        // performs a lookup — the entry must shrink on the strength of the store alone.
        let mut compressed = None;
        for _ in 0..200 {
            if let hj_pagecache::EntryState::Fresh(e) =
                store.get_entry_uncounted(&key, identity, std::time::Instant::now())
                && e.dict_gen != 0
            {
                compressed = Some(e);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let entry = compressed.expect("a stored entry must be dict-compressed without any hit");
        assert!(
            entry.body.len() < body.len(),
            "the stored body must be smaller than the identity it replaced ({} vs {})",
            entry.body.len(),
            body.len()
        );
        // Still losslessly serveable: the stored form decodes back to the exact identity bytes.
        let dict = state
            .page_cache_dicts
            .by_generation(entry.dict_gen)
            .expect("the entry's dict_gen must resolve to a loaded dictionary");
        let stored = store.body_bytes_cold(&entry).expect("stored body");
        assert_eq!(
            dict.decode(stored.as_ref(), hj_compress::MAX_DECODE as usize)
                .expect("stored body must decode"),
            body,
            "dict-compressed storage must round-trip to the identity body"
        );
    }

    /// An image never clears the 12.5% savings gate, so it must not cost an L15 encode (or a
    /// pool slot): the entry is marked attempted at store time and left as its identity body.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn store_skips_the_dict_encode_for_incompressible_types() {
        let (state, ctx, store) = cache_test_ctx_with_dict();
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/proxy.php";
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity,
            req_path: "/proxy.php",
            req_query: "image=x",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let key = build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public);
        state.page_cache_admission.record(hash_key(&key));
        let resp = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "image/png")
            .header(HDR_CACHE_CONTROL, "public,max-age=600")
            .body(Body::Full(Bytes::from(DICT_CORPUS.repeat(8))))
            .unwrap();
        let _ = cache_store(&state, &ctx, &cc, resp).await;

        let hj_pagecache::EntryState::Fresh(entry) =
            store.get_entry_uncounted(&key, identity, std::time::Instant::now())
        else {
            panic!("the image must still be cached");
        };
        assert_eq!(entry.dict_gen, 0);
        assert!(
            entry.dict_compression_attempted(),
            "marked so the hit-path retry never queues it"
        );
        let metrics = state
            .page_cache_dict_metrics
            .get("forum.example")
            .expect("dict metrics for the vhost")
            .clone();
        let load = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(load(&metrics.queued), 0);
        assert_eq!(load(&metrics.attempts), 0);
        assert_eq!(
            load(&metrics.skipped_by_reason[DictSkip::ContentType as usize]),
            1
        );
    }

    /// A cached canonical redirect has an empty body: an encode of it can never clear the
    /// savings gate, so it must not be queued (it was the bulk of the post-L12 `savings` skips).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn store_skips_the_dict_encode_for_tiny_bodies() {
        let (state, ctx, store) = cache_test_ctx_with_dict();
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/378554/";
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity,
            req_path: "/threads/378554/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let key = build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public);
        state.page_cache_admission.record(hash_key(&key));
        let resp = http::Response::builder()
            .status(301)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(
                http::header::LOCATION,
                "https://forum.example/threads/slug.378554/",
            )
            .header(HDR_CACHE_CONTROL, "public,max-age=600")
            .body(Body::Full(Bytes::new()))
            .unwrap();
        let _ = cache_store(&state, &ctx, &cc, resp).await;

        let hj_pagecache::EntryState::Fresh(entry) =
            store.get_entry_uncounted(&key, identity, std::time::Instant::now())
        else {
            panic!("the redirect must still be cached");
        };
        assert!(entry.dict_compression_attempted());
        let metrics = state
            .page_cache_dict_metrics
            .get("forum.example")
            .expect("dict metrics for the vhost")
            .clone();
        let load = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(load(&metrics.queued), 0);
        assert_eq!(
            load(&metrics.skipped_by_reason[DictSkip::TooSmall as usize]),
            1
        );
    }

    /// Enough repeated page boilerplate to train a usable dictionary on.
    const DICT_CORPUS: &[u8] =
        b"<html><head><title>example forum</title></head><body><div class=\"p-nav\">thread</div></body></html>";

    /// A capsule render is stored twice (dedicated capsule entry + public mirror) with the SAME
    /// bytes. Both must end up dict-compressed from ONE encode: two back-to-back jobs used to
    /// fill the 2-slot recompress pool and push other stores out as identity bodies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capsule_render_is_dict_encoded_once_for_both_entries() {
        let capsule = crate::state::XfCapsuleConfig {
            enabled: true,
            vhosts: std::collections::HashSet::from(["forum.example".to_string()]),
            path_prefixes: vec!["/threads/".into()],
            safe_get_mode: crate::state::XfCapsuleSafeGetMode::Prefixes,
            stale_secs: 86_400,
            canary_percent: 100,
            allow_members: true,
            member_canary_percent: 100,
            dedicated_store: true,
        };
        let (state, ctx, store) = cache_test_ctx_with_dict_and_capsule(capsule);
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/dict-capsule.1/";
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity,
            req_path: "/threads/dict-capsule.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let public_key = build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public);
        let capsule_key = configuration_key(&state, capsule_key(&ctx, &cc, &store));
        state.page_cache_admission.record(hash_key(&public_key));

        let body = DICT_CORPUS.repeat(8);
        let resp = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(HDR_CACHE_CONTROL, "public,max-age=60")
            .header(HDR_TAG, "public, T1")
            .header(
                HDR_XF_CAPSULE,
                "public-shell, hydrate=account-nav-v1, max-age=60",
            )
            .header(HDR_XF_CAPSULE_TAGS, "public, T1")
            .body(Body::Full(Bytes::from(body.clone())))
            .unwrap();
        let _ = cache_store(&state, &ctx, &cc, resp).await;

        let compressed = |key: &hj_pagecache::PageCacheKey| {
            matches!(
                store.get_entry_uncounted(key, identity, std::time::Instant::now()),
                hj_pagecache::EntryState::Fresh(e) if e.dict_gen != 0
            )
        };
        for _ in 0..200 {
            if compressed(&public_key) && compressed(&capsule_key) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            compressed(&capsule_key),
            "the capsule entry must be dict-compressed"
        );
        assert!(
            compressed(&public_key),
            "the public mirror must be dict-compressed"
        );
        let metrics = state
            .page_cache_dict_metrics
            .get("forum.example")
            .expect("dict metrics for the vhost")
            .clone();
        let load = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(load(&metrics.queued), 1, "one job per render");
        assert_eq!(load(&metrics.attempts), 1, "one encode per render");
        assert_eq!(load(&metrics.completed), 2, "both entries shrink");
        assert_eq!(load(&metrics.dropped), 0);
    }

    fn cache_test_ctx_with_dict() -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        cache_test_ctx_with_dict_and_capsule(crate::state::XfCapsuleConfig::disabled())
    }

    fn cache_test_ctx_with_dict_and_capsule(
        xf_capsule: crate::state::XfCapsuleConfig,
    ) -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        let (state, ctx, store) = cache_test_ctx();
        let dict = Arc::new(
            hj_compress::PageDict::new(DICT_CORPUS.to_vec(), hj_compress::DEFAULT_DICT_LEVEL)
                .expect("non-empty dict"),
        );
        let registry = hj_compress::PageDictRegistry::new(
            std::collections::HashMap::from([("forum.example".to_string(), dict)]),
            None,
        );
        let state = ServerState::new(
            state.server.clone(),
            None,
            None,
            Some(store.clone()),
            Arc::new(registry),
            1,
            xf_capsule,
            None,
            false,
            None,
            false,
            crate::state::RewriteTuning::default(),
        )
        .unwrap();
        (state, ctx, store)
    }

    fn cache_test_ctx_with_capsule(
        xf_capsule: crate::state::XfCapsuleConfig,
    ) -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        cache_test_ctx_with(xf_capsule, |_| {})
    }

    fn cache_test_ctx_with(
        xf_capsule: crate::state::XfCapsuleConfig,
        tweak: impl FnOnce(&mut hj_pagecache::StoreConfig),
    ) -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        cache_test_ctx_with_rewrite(xf_capsule, tweak, crate::state::RewriteTuning::default())
    }

    fn cache_test_ctx_with_rewrite(
        xf_capsule: crate::state::XfCapsuleConfig,
        tweak: impl FnOnce(&mut hj_pagecache::StoreConfig),
        rewrite_tuning: crate::state::RewriteTuning,
    ) -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        let mut cfg = hj_pagecache::StoreConfig::default();
        cfg.standard_cc_vhosts.push("forum.example".into());
        cfg.private_user_cookie = "xf_user".into();
        cfg.private_session_cookie = "xf_session".into();
        tweak(&mut cfg);
        let store = Arc::new(hj_pagecache::PageStore::new(cfg));
        let mut server = hj_core::config::ServerConfig::default();
        let root = std::env::temp_dir().join(format!(
            "httpjet_lscache_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        server.server_root = root;
        let server = Arc::new(server);
        let vhost = Arc::new(hj_core::config::VHostConfig {
            cache_policy: Some(hj_core::config::VhostCachePolicy {
                enable_cache: true,
                enable_public: true,
                enable_private: false,
            }),
            ..Default::default()
        });
        let state = ServerState::new(
            server.clone(),
            None,
            None,
            Some(store.clone()),
            Arc::new(hj_compress::PageDictRegistry::empty()),
            1,
            {
                // (#239) The capsule allowlist is CLOSED by default now; tests here
                // exercise capsule MECHANICS against vhost forum.example, so an
                // explicitly-empty list is scoped to that vhost.
                let mut xf = xf_capsule;
                if xf.vhosts.is_empty() {
                    xf.vhosts.insert("forum.example".into());
                }
                xf
            },
            None,
            false,
            None,
            false,
            rewrite_tuning,
        )
        .unwrap();
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let ctx = ReqCtx {
            server,
            vhost_name: "forum.example".into(),
            vhost,
            peer_ip: loopback,
            client_ip: loopback,
            is_tls: true,
            protocol: hj_core::Proto::Http2,
            trusted_proxy: false,
            forwarding_trusted: false,
            env: Vec::new(),
            local_addr: "127.0.0.1:443".parse().unwrap(),
            peer_port: 12345,
            peer_unix: false,
            request_time: std::time::SystemTime::UNIX_EPOCH,
            request_id: Default::default(),
            tls: None,
            redirect_guard: None,
        };
        (state, ctx, store)
    }

    #[tokio::test]
    async fn capsule_store_then_marked_member_cookie_lookup_hits_public_shell() {
        let (state, ctx, store) = cache_test_ctx_with_capsule(crate::state::XfCapsuleConfig {
            enabled: true,
            vhosts: std::collections::HashSet::new(),
            path_prefixes: vec!["/threads/".into()],
            safe_get_mode: crate::state::XfCapsuleSafeGetMode::Prefixes,
            stale_secs: 86_400,
            canary_percent: 100,
            allow_members: true,
            member_canary_percent: 100,
            dedicated_store: false,
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/example.1/";
        let guest_cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity,
            req_path: "/threads/example.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let resp = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(HDR_CACHE_CONTROL, "public,max-age=60")
            .header(HDR_TAG, "public, T1")
            .header(
                HDR_XF_CAPSULE,
                "public-shell, hydrate=account-nav-v1, max-age=60",
            )
            .header(HDR_XF_CAPSULE_TAGS, "public, T1")
            .body(Body::Full(Bytes::from_static(b"<html>capsule</html>")))
            .unwrap();
        // (2026-10-04) Members are served from the PUBLIC entry (dedicated capsule stores are
        // off), and the public store is admission-gated: record the sighting the guest
        // `cache_lookup` would have recorded before the render.
        state.page_cache_admission.record(hash_key(&build_cache_key(
            &ctx,
            &guest_cc,
            &store,
            &PrivateRoute::Public,
        )));
        let _ = cache_store(&state, &ctx, &guest_cc, resp).await;

        let member_cookie = "xf_user=1; xf_session=abc; xf_wf_capsule_member=1";
        let member_cc = CacheCtx {
            enabled: true,
            cookie: Some(member_cookie),
            ..guest_cc
        };
        let mut hit = match capsule_lookup(&state, &ctx, &member_cc, None, None) {
            CacheOutcome::Hit(hit) => hit,
            _ => panic!("expected capsule hit for member cookie"),
        };
        // #932: the terminal control-header settle in `handle()` keeps the status marker.
        settle_control_headers(&state, hit.headers_mut());
        // (2026-10-04) Served from the shell-capable PUBLIC entry (dedicated stores off).
        assert_eq!(
            hit.headers().get(HDR_XF_CAPSULE_STATUS).unwrap(),
            "hit,public-fallback"
        );
        assert_eq!(
            hit.headers().get(http::header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        match hit.into_body() {
            Body::Full(b) => assert_eq!(&b[..], b"<html>capsule</html>"),
            _ => panic!("expected full capsule body"),
        }
    }

    #[tokio::test]
    async fn capsule_zero_canary_stores_no_shell() {
        // (#101) With the capsule tier enabled but canary_percent==0, nothing is ever SERVED
        // from the capsule tier (capsule_canary_allows gates every lookup), so a shell must
        // never be STORED — else a 0% ramp accumulates unreadable dedicated entries that evict
        // live public entries. (member_canary 100 proves the guest canary is the master gate.)
        let (state, ctx, store) = cache_test_ctx_with_capsule(crate::state::XfCapsuleConfig {
            enabled: true,
            vhosts: std::collections::HashSet::new(),
            path_prefixes: vec!["/threads/".into()],
            safe_get_mode: crate::state::XfCapsuleSafeGetMode::Prefixes,
            stale_secs: 86_400,
            canary_percent: 0,
            allow_members: true,
            member_canary_percent: 100,
            dedicated_store: false,
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/zero.1/";
        let guest_cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity,
            req_path: "/threads/zero.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let resp = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(HDR_CACHE_CONTROL, "public,max-age=60")
            .header(
                HDR_XF_CAPSULE,
                "public-shell, hydrate=account-nav-v1, max-age=60",
            )
            .body(Body::Full(Bytes::from_static(b"<html>capsule</html>")))
            .unwrap();
        let _ = cache_store(&state, &ctx, &guest_cc, resp).await;

        // No dedicated capsule entry may have been stored.
        let dedicated = capsule_key(&ctx, &guest_cc, &store);
        assert!(
            matches!(
                store.get_entry(&dedicated, identity, std::time::Instant::now()),
                hj_pagecache::EntryState::Miss
            ),
            "no dedicated capsule entry must be stored at canary_percent==0"
        );
    }

    #[tokio::test]
    async fn capsule_marked_member_cookie_falls_back_to_tagged_public_shell() {
        let (state, ctx, store) = cache_test_ctx_with_capsule(crate::state::XfCapsuleConfig {
            enabled: true,
            vhosts: std::collections::HashSet::new(),
            path_prefixes: vec!["/threads/".into()],
            safe_get_mode: crate::state::XfCapsuleSafeGetMode::Prefixes,
            stale_secs: 86_400,
            canary_percent: 100,
            allow_members: true,
            member_canary_percent: 100,
            dedicated_store: false,
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/fallback.1/";
        let member_cookie = "xf_user=1; xf_session=abc; xf_wf_capsule_member=1";
        let member_cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: Some(member_cookie),
            identity,
            req_path: "/threads/fallback.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let key = capsule_public_fallback_key(&ctx, &member_cc, &store);
        assert!(store.store(
            key,
            CachedResponse {
                status: 200,
                identity: identity.into(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8")
                )],
                body: PageBody::InMem(Bytes::from_static(b"<html>public shell</html>")),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: vec![Arc::from(CAPSULE_SHELL_TAG)],
                vary_cookie_name: String::new(),
                vary_value: capsule_public_vary_value(Some(member_cookie), &store),
                scope: PageScope::Public,
                stored_at: Instant::now(),
                ttl: Duration::from_secs(60),
                swr: Duration::ZERO,
                sie: Duration::ZERO,
            }
        ));

        let hit = match capsule_lookup(&state, &ctx, &member_cc, None, None) {
            CacheOutcome::Hit(hit) => hit,
            _ => panic!("expected public fallback capsule hit"),
        };
        assert_eq!(
            hit.headers().get(HDR_XF_CAPSULE_STATUS).unwrap(),
            "hit,public-fallback"
        );
        assert_eq!(
            hit.headers().get(http::header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        match hit.into_body() {
            Body::Full(b) => assert_eq!(&b[..], b"<html>public shell</html>"),
            _ => panic!("expected full capsule body"),
        }
    }

    #[tokio::test]
    async fn capsule_marked_member_cookie_serves_stale_public_shell() {
        let (state, ctx, store) = cache_test_ctx_with_capsule(crate::state::XfCapsuleConfig {
            enabled: true,
            vhosts: std::collections::HashSet::new(),
            path_prefixes: vec!["/threads/".into()],
            safe_get_mode: crate::state::XfCapsuleSafeGetMode::Prefixes,
            stale_secs: 86_400,
            canary_percent: 100,
            allow_members: true,
            member_canary_percent: 100,
            dedicated_store: false,
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/stale-fallback.1/";
        let member_cookie = "xf_user=1; xf_session=abc; xf_wf_capsule_member=1";
        let member_cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: Some(member_cookie),
            identity,
            req_path: "/threads/stale-fallback.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let key = capsule_public_fallback_key(&ctx, &member_cc, &store);
        assert!(store.store(
            key,
            CachedResponse {
                status: 200,
                identity: identity.into(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8")
                )],
                body: PageBody::InMem(Bytes::from_static(b"<html>stale public shell</html>")),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: vec![Arc::from(CAPSULE_SHELL_TAG)],
                vary_cookie_name: String::new(),
                vary_value: capsule_public_vary_value(Some(member_cookie), &store),
                scope: PageScope::Public,
                stored_at: Instant::now(),
                ttl: Duration::ZERO,
                swr: Duration::from_secs(60),
                sie: Duration::ZERO,
            }
        ));

        let hit = match capsule_lookup(&state, &ctx, &member_cc, None, None) {
            CacheOutcome::CapsuleStaleHit(hit, _) => hit,
            _ => panic!("expected stale public fallback capsule hit"),
        };
        assert_eq!(
            hit.headers().get(HDR_XF_CAPSULE_STATUS).unwrap(),
            "hit,stale-public-fallback"
        );
        assert_eq!(hit.headers().get(HDR_XF_HOT_PATH).unwrap(), "l2-stale");
        assert_eq!(
            hit.headers().get(http::header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        match hit.into_body() {
            Body::Full(b) => assert_eq!(&b[..], b"<html>stale public shell</html>"),
            _ => panic!("expected full capsule body"),
        }
    }

    #[tokio::test]
    async fn capsule_public_fallback_rejects_untagged_public_entries() {
        let (state, ctx, store) = cache_test_ctx_with_capsule(crate::state::XfCapsuleConfig {
            enabled: true,
            vhosts: std::collections::HashSet::new(),
            path_prefixes: vec!["/threads/".into()],
            safe_get_mode: crate::state::XfCapsuleSafeGetMode::Prefixes,
            stale_secs: 86_400,
            canary_percent: 100,
            allow_members: true,
            member_canary_percent: 100,
            dedicated_store: false,
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/untagged.1/";
        let member_cookie = "xf_user=1; xf_session=abc; xf_wf_capsule_member=1";
        let member_cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: Some(member_cookie),
            identity,
            req_path: "/threads/untagged.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let key = capsule_public_fallback_key(&ctx, &member_cc, &store);
        assert!(store.store(
            key,
            CachedResponse {
                status: 200,
                identity: identity.into(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8")
                )],
                body: PageBody::InMem(Bytes::from_static(b"<html>ordinary public</html>")),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: vec![Arc::from("public")],
                vary_cookie_name: String::new(),
                vary_value: capsule_public_vary_value(Some(member_cookie), &store),
                scope: PageScope::Public,
                stored_at: Instant::now(),
                ttl: Duration::from_secs(60),
                swr: Duration::ZERO,
                sie: Duration::ZERO,
            }
        ));

        assert!(matches!(
            capsule_lookup(&state, &ctx, &member_cc, None, None),
            CacheOutcome::Miss(_)
        ));
    }

    fn capsule_member_config() -> crate::state::XfCapsuleConfig {
        crate::state::XfCapsuleConfig {
            enabled: true,
            vhosts: std::collections::HashSet::new(),
            path_prefixes: vec!["/threads/".into()],
            safe_get_mode: crate::state::XfCapsuleSafeGetMode::Prefixes,
            stale_secs: 86_400,
            canary_percent: 100,
            allow_members: true,
            member_canary_percent: 100,
            dedicated_store: false,
        }
    }

    #[tokio::test]
    async fn private_cookie_aliases_block_public_and_dedicated_capsule_stores() {
        let mut capsule = capsule_member_config();
        capsule.dedicated_store = true;
        let (state, ctx, store) = cache_test_ctx_with(capsule, |cfg| {
            cfg.private_cookies = vec!["xf_session".into()];
        });
        for (number, cookie, stored) in [
            (0, "xf.session=secret", false),
            (1, "xf session=secret", false),
            (2, "analytics=ok", true),
        ] {
            let path = format!("/threads/cookie.{number}/");
            let identity = format!("https\nforum.example\n{path}");
            let cc = CacheCtx {
                enabled: true,
                method: &Method::GET,
                host: "forum.example",
                cookie: None,
                identity: &identity,
                req_path: &path,
                req_query: "",
                chain: &[],
                render_epoch: store.purge_epoch(),
                has_range: false,
                host_foreign: false,
                origin: None,
                ua_class: None,
                header_vary: None,
                env_vary: false,
                vary_value: None,
            };
            let public = build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public);
            let dedicated = configuration_key(&state, capsule_key(&ctx, &cc, &store));
            state.page_cache_admission.record(hash_key(&public));
            let response = http::Response::builder()
                .status(200)
                .header(CONTENT_TYPE, "text/html")
                .header(HDR_CACHE_CONTROL, "public,max-age=60")
                .header(
                    HDR_XF_CAPSULE,
                    "public-shell, hydrate=account-nav-v1, max-age=60",
                )
                .header(SET_COOKIE, cookie)
                .body(Body::Full(Bytes::from_static(b"<html>shell</html>")))
                .unwrap();
            let _ = cache_store(&state, &ctx, &cc, response).await;
            for key in [&public, &dedicated] {
                assert_eq!(
                    matches!(
                        store.get_entry_uncounted(key, &identity, Instant::now()),
                        hj_pagecache::EntryState::Fresh(_)
                    ),
                    stored,
                    "cookie={cookie} key={key:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn capsule_member_serve_refuses_non_public_dedicated_entry() {
        // (A.4 defense-in-depth) A non-Public entry occupying the dedicated capsule slot must
        // NEVER be handed to a member — the scope guard degrades it to a miss. (The slot is
        // namespaced + stored Public-scoped in prod, so this only triggers on collision/corruption.)
        let (state, ctx, store) = cache_test_ctx_with_capsule(capsule_member_config());
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/scope.1/";
        let member_cookie = "xf_user=1; xf_session=abc; xf_wf_capsule_member=1";
        let member_cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: Some(member_cookie),
            identity,
            req_path: "/threads/scope.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        // Plant a PRIVATE entry directly at the dedicated capsule key, shell-tagged so the only
        // thing standing between a member and these bytes is the Public-scope guard.
        let key = capsule_key(&ctx, &member_cc, &store);
        assert!(store.store(
            key,
            CachedResponse {
                status: 200,
                identity: identity.into(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8")
                )],
                body: PageBody::InMem(Bytes::from_static(b"<html>PRIVATE leak</html>")),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: vec![Arc::from(CAPSULE_SHELL_TAG)],
                vary_cookie_name: String::new(),
                vary_value: String::new(),
                scope: PageScope::Private { owner_hash: 0xDEAD },
                stored_at: Instant::now(),
                ttl: Duration::from_secs(60),
                swr: Duration::ZERO,
                sie: Duration::ZERO,
            }
        ));

        // No public-fallback entry exists, so the guard's degrade-to-fallback ends in a miss —
        // the private bytes are never served.
        assert!(
            matches!(
                capsule_lookup(&state, &ctx, &member_cc, None, None),
                CacheOutcome::Miss(_)
            ),
            "a member must not be served a non-Public dedicated entry"
        );
    }

    #[tokio::test]
    async fn capsule_hit_class_counters_split_member_and_guest() {
        // (A.1) A guest hit bumps the guest series + a member hit bumps the member series; the
        // shell-age summary count tracks total hits. Guests serve from the public path
        // (cache_lookup), members from the dedicated capsule path (capsule_lookup) — both feed
        // record_capsule_hit, so verify the dimension at the capsule serve sites.
        use std::sync::atomic::Ordering::Relaxed;
        let (state, ctx, store) = cache_test_ctx_with_capsule(capsule_member_config());
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/classcount.1/";
        let guest_cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity,
            req_path: "/threads/classcount.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let resp = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(HDR_CACHE_CONTROL, "public,max-age=60")
            .header(HDR_TAG, "public, T1")
            .header(
                HDR_XF_CAPSULE,
                "public-shell, hydrate=account-nav-v1, max-age=60",
            )
            .header(HDR_XF_CAPSULE_TAGS, "public, T1")
            .body(Body::Full(Bytes::from_static(b"<html>capsule</html>")))
            .unwrap();
        // (2026-10-04) Members are served from the PUBLIC entry (dedicated capsule stores are
        // off), and the public store is admission-gated: record the sighting the guest
        // `cache_lookup` would have recorded before the render.
        state.page_cache_admission.record(hash_key(&build_cache_key(
            &ctx,
            &guest_cc,
            &store,
            &PrivateRoute::Public,
        )));
        let _ = cache_store(&state, &ctx, &guest_cc, resp).await;

        // (2026-10-04) Guests never probe the capsule tier: their page is the public entry
        // `cache_lookup` serves next, so capsule_lookup is a Bypass and the guest class is
        // never counted here.
        assert!(matches!(
            capsule_lookup(&state, &ctx, &guest_cc, None, None),
            CacheOutcome::Bypass
        ));
        assert_eq!(state.metrics.xf_capsule_hits_guest.load(Relaxed), 0);
        assert_eq!(state.metrics.xf_capsule_hits_member.load(Relaxed), 0);

        // A member serve of the same dedicated shell.
        let member_cc = CacheCtx {
            enabled: true,
            cookie: Some("xf_user=1; xf_session=abc; xf_wf_capsule_member=1"),
            ..guest_cc
        };
        assert!(matches!(
            capsule_lookup(&state, &ctx, &member_cc, None, None),
            CacheOutcome::Hit(_)
        ));
        assert_eq!(state.metrics.xf_capsule_hits_guest.load(Relaxed), 0);
        assert_eq!(state.metrics.xf_capsule_hits_member.load(Relaxed), 1);
        // One member hit => one shell-age observation.
        assert_eq!(
            state.metrics.xf_capsule_shell_age_secs_count.load(Relaxed),
            1
        );
    }

    /// #984: the dedicated capsule key is built only when dedicated stores are on; with them
    /// off a member miss still falls back to the public shell and still counts as a miss.
    #[tokio::test]
    async fn capsule_member_miss_builds_the_dedicated_key_only_for_dedicated_stores() {
        use std::sync::atomic::Ordering::Relaxed;
        for dedicated_store in [false, true] {
            let mut capsule = capsule_member_config();
            capsule.dedicated_store = dedicated_store;
            let (state, ctx, store) = cache_test_ctx_with_capsule(capsule);
            let method = Method::GET;
            let identity = "https\nforum.example\n/threads/none.1/";
            let member_cc = CacheCtx {
                cookie: Some("xf_user=1; xf_session=abc; xf_wf_capsule_member=1"),
                ..page_cc(&method, "/threads/none.1/", identity, store.purge_epoch())
            };
            let before = CAPSULE_KEY_BUILDS.with(|n| n.get());
            assert!(matches!(
                capsule_lookup(&state, &ctx, &member_cc, None, None),
                CacheOutcome::Miss(_)
            ));
            assert_eq!(
                CAPSULE_KEY_BUILDS.with(|n| n.get()) - before,
                usize::from(dedicated_store),
                "dedicated_store={dedicated_store}"
            );
            let m = &state.metrics;
            assert_eq!(
                m.xf_capsule_misses_dedicated.load(Relaxed),
                u64::from(dedicated_store)
            );
            assert_eq!(m.xf_capsule_misses_public_fallback.load(Relaxed), 1);
            assert_eq!(m.xf_capsule_bypass_not_allowed.load(Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn capsule_member_cookie_bypasses_without_member_opt_in() {
        let (state, ctx, store) = cache_test_ctx_with_capsule(crate::state::XfCapsuleConfig {
            enabled: true,
            vhosts: std::collections::HashSet::new(),
            path_prefixes: vec!["/threads/".into()],
            safe_get_mode: crate::state::XfCapsuleSafeGetMode::Prefixes,
            stale_secs: 86_400,
            canary_percent: 100,
            allow_members: false,
            member_canary_percent: 0,
            dedicated_store: false,
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/example.1/";
        let guest_cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity,
            req_path: "/threads/example.1/",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let resp = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(HDR_CACHE_CONTROL, "public,max-age=60")
            .header(HDR_TAG, "public, T1")
            .header(
                HDR_XF_CAPSULE,
                "public-shell, hydrate=account-nav-v1, max-age=60",
            )
            .header(HDR_XF_CAPSULE_TAGS, "public, T1")
            .body(Body::Full(Bytes::from_static(b"<html>capsule</html>")))
            .unwrap();
        let _ = cache_store(&state, &ctx, &guest_cc, resp).await;

        let member_cc = CacheCtx {
            enabled: true,
            cookie: Some("xf_user=1; xf_session=abc; xf_wf_capsule_member=1"),
            ..guest_cc
        };
        assert!(matches!(
            capsule_lookup(&state, &ctx, &member_cc, None, None),
            CacheOutcome::Bypass
        ));
    }

    #[tokio::test]
    async fn stale_if_error_fallback_skips_range_requests() {
        let (state, ctx, store) = cache_test_ctx();
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity: "forum.example\n/range",
            req_path: "/range",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let route = PrivateRoute::Public;
        let key = build_cache_key(&ctx, &cc, &store, &route);
        assert!(store.store(
            key,
            CachedResponse {
                status: 200,
                identity: cc.identity.to_string(),
                headers: vec![(CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
                body: PageBody::InMem(Bytes::from_static(b"stale-body")),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: Vec::new(),
                vary_cookie_name: String::new(),
                vary_value: String::new(),
                scope: PageScope::Public,
                stored_at: Instant::now() - Duration::from_secs(5),
                ttl: Duration::from_secs(1),
                swr: Duration::ZERO,
                sie: Duration::from_secs(60),
            }
        ));
        assert!(
            stale_if_error_fallback(&state, &ctx, &cc, &store, &route, 503).is_some(),
            "plain GET may use stale-if-error"
        );
        let ranged = CacheCtx {
            enabled: true,
            has_range: true,
            ..cc
        };
        assert!(
            stale_if_error_fallback(&state, &ctx, &ranged, &store, &route, 503).is_none(),
            "Range requests must not receive a full stale-if-error body"
        );
    }

    #[tokio::test]
    async fn stale_if_error_fallback_never_serves_a_fresh_error_entry() {
        let (state, ctx, store) = cache_test_ctx();
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let cc = CacheCtx {
            enabled: true,
            method: &method,
            host: "forum.example",
            cookie: None,
            identity: "forum.example\n/gone",
            req_path: "/gone",
            req_query: "",
            chain: &chain,
            render_epoch: store.purge_epoch(),
            has_range: false,
            host_foreign: false,
            origin: None,
            ua_class: None,
            header_vary: None,
            env_vary: false,
            vary_value: None,
        };
        let route = PrivateRoute::Public;
        let key = build_cache_key(&ctx, &cc, &store, &route);
        assert!(store.store(
            key,
            CachedResponse {
                status: 404,
                identity: cc.identity.to_string(),
                headers: vec![(CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
                body: PageBody::InMem(Bytes::from_static(b"not found")),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: Vec::new(),
                vary_cookie_name: String::new(),
                vary_value: String::new(),
                scope: PageScope::Public,
                stored_at: Instant::now(),
                ttl: Duration::from_secs(300),
                swr: Duration::ZERO,
                sie: Duration::ZERO,
            }
        ));
        assert!(
            stale_if_error_fallback(&state, &ctx, &cc, &store, &route, 503).is_none(),
            "a cached 404 must not replace a backend 5xx"
        );
    }

    fn retained_entry(identity: &str, scope: PageScope, swr: Duration) -> CachedResponse {
        CachedResponse {
            status: 200,
            identity: identity.to_string(),
            headers: vec![(CONTENT_TYPE, HeaderValue::from_static("text/html"))],
            body: PageBody::InMem(Bytes::from_static(b"stale-body")),
            variants: Vec::new(),
            variants_filled: false,
            dict_gen: 0,
            tags: Vec::new(),
            vary_cookie_name: String::new(),
            vary_value: String::new(),
            scope,
            stored_at: Instant::now() - Duration::from_secs(5),
            ttl: Duration::from_secs(1),
            swr,
            sie: Duration::from_secs(60),
        }
    }

    /// Regression (#1016): a backend stream that fails while a cacheable miss is
    /// buffered falls back to the retained stale public entry, like a 5xx render;
    /// with nothing retained it is still a bare 502.
    #[tokio::test]
    async fn backend_stream_error_on_a_cacheable_miss_serves_stale_if_error() {
        let (state, ctx, store) = cache_test_ctx();
        let method = Method::GET;
        for (path, retained) in [("/sie-stream", true), ("/no-stale", false)] {
            let identity = format!("https\nforum.example\n{path}");
            let cc = page_cc(&method, path, &identity, store.purge_epoch());
            if retained {
                let key = build_cache_key(&ctx, &cc, &store, &PrivateRoute::Public);
                let entry = retained_entry(&identity, PageScope::Public, Duration::ZERO);
                assert!(store.store(key, entry));
            }
            let (feed, resp) = fed_page(None);
            feed.send(Ok(Bytes::from_static(b"<p>partial"))).unwrap();
            feed.send(Err("backend reset".into())).unwrap();
            drop(feed);
            let resp = cache_store(&state, &ctx, &cc, resp).await;
            if retained {
                assert_eq!(resp.status(), http::StatusCode::OK);
                assert_eq!(
                    resp.headers().get(HDR_CACHE_STATUS).unwrap(),
                    "hit,stale-if-error"
                );
                assert!(matches!(resp.into_body(), Body::Full(b) if &b[..] == b"stale-body"));
            } else {
                assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
            }
        }
    }

    /// Regression (#1016): a stale PRIVATE entry is never served stale (that serve uses
    /// the public stale egress); the member's lookup misses and re-renders. A stale
    /// public entry still serves stale to a guest.
    #[tokio::test]
    async fn stale_private_entry_is_a_miss_not_a_stale_hit() {
        let (state, mut ctx, store) =
            cache_test_ctx_with(crate::state::XfCapsuleConfig::disabled(), |cfg| {
                cfg.private_enabled = true;
            });
        ctx.vhost = Arc::new(hj_core::config::VHostConfig {
            cache_policy: Some(hj_core::config::VhostCachePolicy {
                enable_cache: true,
                enable_public: true,
                enable_private: true,
            }),
            ..Default::default()
        });
        let method = Method::GET;
        let identity = "https\nforum.example\n/threads/stale.1/";
        let guest = page_cc(&method, "/threads/stale.1/", identity, store.purge_epoch());
        let member = CacheCtx {
            cookie: Some("xf_user=1; xf_session=sessSTALE"),
            ..guest
        };
        let route = private_route(&state, &ctx, &store, &member, false);
        let PrivateRoute::Private { owner, .. } = route else {
            panic!("a member request takes the private route");
        };
        let key = build_cache_key(&ctx, &member, &store, &route);
        let scope = PageScope::Private { owner_hash: owner };
        let entry = retained_entry(identity, scope, Duration::from_secs(60));
        assert!(store.store(key.clone(), entry));
        assert!(matches!(
            store.get_entry_uncounted(&key, identity, Instant::now()),
            hj_pagecache::EntryState::Stale(_)
        ));
        assert!(matches!(
            cache_lookup(&state, &ctx, &member, None, false, None),
            CacheOutcome::Miss(_)
        ));

        let public_key = build_cache_key(&ctx, &guest, &store, &PrivateRoute::Public);
        let entry = retained_entry(identity, PageScope::Public, Duration::from_secs(60));
        assert!(store.store(public_key, entry));
        assert!(matches!(
            cache_lookup(&state, &ctx, &guest, None, false, None),
            CacheOutcome::StaleHit(..)
        ));
    }

    #[tokio::test]
    async fn collect_body_reads_file_into_bytes() {
        // (#9) A Body::File reaching the eligible store path must buffer to its real
        // bytes (so it can be cached + served), NOT yield None (which 502'd the client).
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("httpjet_collect_file_{n}"));
        std::fs::write(&path, b"static-file-body").unwrap();
        let fb = Body::File(hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: 16,
            range: None,
            cached: None,
        });
        match collect_body(fb, 1024, 0).await {
            Collected::Buffered(b) => assert_eq!(b.as_ref(), b"static-file-body"),
            _ => panic!("file body must buffer to its bytes"),
        }
        // A missing file is returned unchanged for uncached pass-through, not a 502.
        let _ = std::fs::remove_file(&path);
        let missing = Body::File(hj_core::FileBody {
            path,
            file: None,
            len: 0,
            range: None,
            cached: None,
        });
        assert!(matches!(
            collect_body(missing, 1024, 0).await,
            Collected::Passthrough(Body::File(_))
        ));
    }

    #[tokio::test]
    async fn collect_file_requires_exact_advertised_length() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("httpjet_collect_short_{n}"));
        std::fs::write(&path, b"short").unwrap();
        let body = Body::File(hj_core::FileBody {
            path: path.clone(),
            file: None,
            len: 8,
            range: None,
            cached: None,
        });
        match collect_body(body, 1024, 0).await {
            Collected::Passthrough(Body::File(f)) => {
                assert!(
                    f.file.is_some(),
                    "the opened fallback descriptor stays pinned"
                );
                assert_eq!(f.len, 8);
            }
            _ => panic!("a short EOF must never become cacheable buffered bytes"),
        }
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn collect_file_reads_the_pinned_version_after_atomic_replacement() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("httpjet_collect_replace_{n}"));
        let replacement = path.with_extension("new");
        std::fs::write(&path, b"OLD-BODY").unwrap();
        let pinned = std::fs::File::open(&path).unwrap();
        std::fs::write(&replacement, b"NEW-BODY").unwrap();
        std::fs::rename(&replacement, &path).unwrap();

        let body = Body::File(hj_core::FileBody {
            path: path.clone(),
            file: Some(pinned),
            len: 8,
            range: None,
            cached: None,
        });
        match collect_body(body, 1024, 0).await {
            Collected::Buffered(bytes) => assert_eq!(bytes.as_ref(), b"OLD-BODY"),
            _ => panic!("the selected descriptor is exact and must buffer"),
        }
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn collect_file_failure_preserves_selected_descriptor_identity() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("httpjet_collect_fallback_{n}"));
        let replacement = path.with_extension("new");
        std::fs::write(&path, b"OLD").unwrap();
        let pinned = std::fs::File::open(&path).unwrap();
        std::fs::write(&replacement, b"NEW-BODY").unwrap();
        std::fs::rename(&replacement, &path).unwrap();

        let body = Body::File(hj_core::FileBody {
            path: path.clone(),
            file: Some(pinned),
            len: 8,
            range: None,
            cached: None,
        });
        let fallback = match collect_body(body, 1024, 0).await {
            Collected::Passthrough(Body::File(f)) => f,
            _ => panic!("short selected inode must pass through uncached"),
        };
        let (served, truncated) = crate::uring::bridge::buffer_body(Body::File(fallback)).await;
        assert!(
            truncated,
            "the selected inode is shorter than its old metadata"
        );
        assert_eq!(served.as_ref(), b"OLD", "fallback must not reopen NEW-BODY");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn collect_file_cached_bytes_apply_the_inclusive_range_once() {
        let body = Body::File(hj_core::FileBody {
            path: std::path::PathBuf::from("unused-cached-path"),
            file: None,
            len: 8,
            range: Some((2, 5)),
            cached: Some(Bytes::from_static(b"01234567")),
        });
        match collect_body(body, 1024, 0).await {
            Collected::Buffered(bytes) => assert_eq!(bytes.as_ref(), b"2345"),
            _ => panic!("a complete cached range must buffer without reopening"),
        }
    }

    #[tokio::test]
    async fn recompress_keeps_an_already_built_file_body_readable() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("httpjet_recompress_file_lease_{n}"));
        let mut cfg = hj_pagecache::StoreConfig::default();
        cfg.store_path = Some(root.clone());
        cfg.max_mem_bytes = 8 * 1024 * 1024;
        cfg.max_disk_bytes = 8 * 1024 * 1024;
        cfg.max_obj_bytes = 1024 * 1024;
        let store = hj_pagecache::PageStore::new(cfg);
        store.load_from_disk(|_| {});

        let key = hj_pagecache::PageCacheKey::public(1, true, "example.com", "/lease", "");
        let identity = "https\nexample.com\n/lease";
        let body = Bytes::from(vec![b'x'; 32 * 1024]);
        let stored_at = Instant::now();
        assert!(store.store(
            key.clone(),
            CachedResponse {
                status: 200,
                identity: identity.to_owned(),
                headers: vec![(CONTENT_TYPE, HeaderValue::from_static("text/html"))],
                body: PageBody::InMem(body.clone()),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: Vec::new(),
                vary_cookie_name: String::new(),
                vary_value: String::new(),
                scope: PageScope::Public,
                stored_at,
                ttl: Duration::from_secs(60),
                swr: Duration::ZERO,
                sie: Duration::ZERO,
            }
        ));
        let hit = store.lookup(&key, identity, Instant::now()).unwrap();
        let file_body = stored_file_body(&store, &hit, None).expect("file-tier hit");
        let retired_path = file_body.path.clone();

        assert!(store.fill_recompress_disk(
            &key,
            identity,
            stored_at,
            Bytes::from_static(b"dict-compressed"),
            7,
        ));
        assert!(
            !retired_path.exists(),
            "the cache index still unlinks a retired pathname synchronously"
        );

        let (served, truncated) = crate::uring::bridge::buffer_body(Body::File(file_body)).await;
        assert!(
            !truncated,
            "the pinned descriptor must outlive pathname unlink"
        );
        assert_eq!(served, body, "the in-flight hit reads its selected version");

        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn stale_file_snapshot_retries_the_recompressed_successor() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("httpjet_recompress_retry_{n}"));
        let mut cfg = hj_pagecache::StoreConfig::default();
        cfg.store_path = Some(root.clone());
        cfg.max_mem_bytes = 8 * 1024 * 1024;
        cfg.max_disk_bytes = 8 * 1024 * 1024;
        cfg.max_obj_bytes = 1024 * 1024;
        let store = Arc::new(hj_pagecache::PageStore::new(cfg));
        store.load_from_disk(|_| {});

        let (base_state, _, _) = cache_test_ctx();
        let dict = Arc::new(
            hj_compress::PageDict::new(DICT_CORPUS.to_vec(), hj_compress::DEFAULT_DICT_LEVEL)
                .expect("test dictionary"),
        );
        let state = ServerState::new(
            base_state.server.clone(),
            None,
            None,
            Some(store.clone()),
            Arc::new(hj_compress::PageDictRegistry::new(
                std::collections::HashMap::from([("forum.example".to_string(), dict.clone())]),
                None,
            )),
            1,
            crate::state::XfCapsuleConfig::disabled(),
            None,
            false,
            None,
            false,
            crate::state::RewriteTuning::default(),
        )
        .unwrap();

        let key = hj_pagecache::PageCacheKey::public(1, true, "example.com", "/retry", "");
        let identity = "https\nexample.com\n/retry";
        let body = Bytes::from(DICT_CORPUS.repeat(16));
        let stored_at = Instant::now();
        assert!(store.store(
            key.clone(),
            CachedResponse {
                status: 200,
                identity: identity.to_owned(),
                headers: vec![(CONTENT_TYPE, HeaderValue::from_static("text/html"))],
                body: PageBody::InMem(body.clone()),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: Vec::new(),
                vary_cookie_name: String::new(),
                vary_value: String::new(),
                scope: PageScope::Public,
                stored_at,
                ttl: Duration::from_secs(60),
                swr: Duration::ZERO,
                sie: Duration::ZERO,
            }
        ));

        // A normal hit snapshot has already passed its caller's dict/redirect/scope
        // checks. The helper must build it without invoking the successor validator.
        let mut current = store.lookup(&key, identity, Instant::now()).unwrap();
        let current_validations = std::cell::Cell::new(0usize);
        let response = build_hit_response_with_successor_retry(
            &state,
            &store,
            &key,
            identity,
            &mut current,
            Instant::now(),
            AcceptEncoding::parse(""),
            false,
            |candidate| {
                current_validations.set(current_validations.get() + 1);
                candidate.dict_gen == 0 || matching_dict(&state, candidate.dict_gen).is_some()
            },
        )
        .expect("the validated current snapshot must build directly");
        assert_eq!(current_validations.get(), 0);
        drop(response);

        let mut stale = store.lookup(&key, identity, Instant::now()).unwrap();
        let retired_path = match &stale.body {
            PageBody::File { path, .. } => path.clone(),
            _ => panic!("file tier should offload the identity"),
        };
        let compressed = Bytes::from(dict.encode(&body).expect("dictionary compression"));
        assert!(store.fill_recompress_disk(
            &key,
            identity,
            stored_at,
            compressed,
            dict.generation(),
        ));
        assert!(!retired_path.exists(), "old snapshot path was retired");

        let before = store.stats();
        let successor_validations = std::cell::Cell::new(0usize);
        let response = build_hit_response_with_successor_retry(
            &state,
            &store,
            &key,
            identity,
            &mut stale,
            Instant::now(),
            AcceptEncoding::parse(""),
            false,
            |candidate| {
                successor_validations.set(successor_validations.get() + 1);
                candidate.dict_gen == 0 || matching_dict(&state, candidate.dict_gen).is_some()
            },
        )
        .expect("the successor must satisfy the stale snapshot hit");
        assert_eq!(
            successor_validations.get(),
            1,
            "only the fetched successor needs validation"
        );
        let after = store.stats();
        assert_eq!(
            after.disk_read_errors, before.disk_read_errors,
            "a swap the successor recovered is not a read error (#997)"
        );
        assert_eq!(
            after.disk_read_swap_retries,
            before.disk_read_swap_retries + 1
        );
        let (served, truncated) = crate::uring::bridge::buffer_body(response.into_body()).await;
        assert!(!truncated);
        assert_eq!(served, body);
        assert_eq!(stale.dict_gen, dict.generation());
        assert!(matches!(
            store.get_entry_uncounted(&key, identity, Instant::now()),
            hj_pagecache::EntryState::Fresh(_)
        ));

        drop(state);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn lost_file_body_without_successor_counts_a_read_error_and_misses() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("httpjet_lost_body_{n}"));
        let mut cfg = hj_pagecache::StoreConfig::default();
        cfg.store_path = Some(root.clone());
        cfg.max_mem_bytes = 8 * 1024 * 1024;
        cfg.max_disk_bytes = 8 * 1024 * 1024;
        cfg.max_obj_bytes = 1024 * 1024;
        let store = Arc::new(hj_pagecache::PageStore::new(cfg));
        store.load_from_disk(|_| {});
        let (base_state, _, _) = cache_test_ctx();
        let state = ServerState::new(
            base_state.server.clone(),
            None,
            None,
            Some(store.clone()),
            Arc::new(hj_compress::PageDictRegistry::new(
                std::collections::HashMap::new(),
                None,
            )),
            1,
            crate::state::XfCapsuleConfig::disabled(),
            None,
            false,
            None,
            false,
            crate::state::RewriteTuning::default(),
        )
        .unwrap();

        let key = hj_pagecache::PageCacheKey::public(1, true, "example.com", "/lost", "");
        let identity = "https\nexample.com\n/lost";
        assert!(store.store(
            key.clone(),
            CachedResponse {
                status: 200,
                identity: identity.to_owned(),
                headers: vec![(CONTENT_TYPE, HeaderValue::from_static("text/html"))],
                body: PageBody::InMem(Bytes::from(DICT_CORPUS.repeat(4))),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: Vec::new(),
                vary_cookie_name: String::new(),
                vary_value: String::new(),
                scope: PageScope::Public,
                stored_at: Instant::now(),
                ttl: Duration::from_secs(60),
                swr: Duration::ZERO,
                sie: Duration::ZERO,
            }
        ));
        let mut current = store.lookup(&key, identity, Instant::now()).unwrap();
        match &current.body {
            PageBody::File { path, .. } => std::fs::remove_file(path.as_ref()).unwrap(),
            _ => panic!("file tier should offload the identity"),
        }

        let before = store.stats();
        let response = build_hit_response_with_successor_retry(
            &state,
            &store,
            &key,
            identity,
            &mut current,
            Instant::now(),
            AcceptEncoding::parse("gzip"),
            false,
            |_| true,
        );
        assert!(response.is_none(), "a lost body fails closed to a miss");
        let after = store.stats();
        assert_eq!(after.disk_read_errors, before.disk_read_errors + 1);
        assert_eq!(after.disk_read_swap_retries, before.disk_read_swap_retries);
        assert!(matches!(
            store.get_entry_uncounted(&key, identity, Instant::now()),
            hj_pagecache::EntryState::Miss
        ));

        drop(state);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Build a multi-frame `Body::Stream` — one data frame per chunk — by nesting `PrefixedBody`
    /// over an `Empty` tail. Each `PrefixedBody` emits its prefix as one frame then delegates, so
    /// wrapping the chunks in reverse yields them in order. Exercises frame-by-frame accumulation
    /// + a preserved unread remainder.
    fn stream_of(chunks: &[&[u8]]) -> Body {
        let mut body: hj_core::StreamBody = http_body_util::Empty::<Bytes>::new()
            .map_err(|e| Box::new(e) as hj_core::BoxError)
            .boxed();
        for c in chunks.iter().rev() {
            body = PrefixedBody {
                prefix: Some(Bytes::copy_from_slice(c)),
                rest: body,
            }
            .boxed();
        }
        Body::Stream(body)
    }

    #[tokio::test]
    async fn collect_stream_under_and_at_cap_buffers() {
        // Under the cap: fully buffered.
        match collect_body(stream_of(&[b"ab", b"cd", b"ef"]), 1024, 0).await {
            Collected::Buffered(b) => assert_eq!(b.as_ref(), b"abcdef"),
            _ => panic!("under-cap stream must buffer"),
        }
        // Exactly at the cap (6 bytes, cap 6): buffered (the store guard is `<= max_obj_bytes`).
        match collect_body(stream_of(&[b"abc", b"def"]), 6, 0).await {
            Collected::Buffered(b) => assert_eq!(b.as_ref(), b"abcdef"),
            _ => panic!("at-cap stream must buffer"),
        }
    }

    #[tokio::test]
    async fn collect_stream_over_cap_serves_through_uncached() {
        // 10 bytes over a 4-byte cap: Passthrough, and the body must reproduce the
        // FULL original bytes (prefix read so far + the unread remainder), never truncated.
        match collect_body(stream_of(&[b"abcd", b"efgh", b"ij"]), 4, 0).await {
            Collected::Passthrough(Body::Stream(s)) => {
                let bytes = s.collect().await.expect("pass-through collects").to_bytes();
                assert_eq!(
                    bytes.as_ref(),
                    b"abcdefghij",
                    "over-cap pass-through must be complete"
                );
            }
            _ => panic!("over-cap stream must be Passthrough(Stream), not buffered"),
        }
    }

    #[test]
    fn capsule_stale_guard_uses_parsed_cache_control_directives() {
        let s_maxage = hdrs(&[("cache-control", "public, s-maxage=60")]);
        assert!(stored_cc_forbids_stale(&s_maxage));

        let quoted = hdrs(&[(
            "cache-control",
            "public, extension=\"ignore, no-cache, private\"",
        )]);
        assert!(!stored_cc_forbids_stale(&quoted));

        let malformed = hdrs(&[("cache-control", "public, extension=\"unterminated")]);
        assert!(stored_cc_forbids_stale(&malformed));
    }

    #[test]
    fn stale_egress_forces_edge_revalidate() {
        // A stale serve must neutralize the backend's long edge freshness so Cloudflare
        // re-fetches within seconds (and lands on the background-refreshed entry) instead
        // of pinning the stale body for the 7-day s-maxage — the CF-poison class. A short
        // public TTL (not no-store) keeps CF request-coalescing and browser bfcache alive.
        let mut h = hdrs(&[
            (
                "cache-control",
                "public, max-age=300, s-maxage=604800, stale-while-revalidate=600",
            ),
            ("cloudflare-cdn-cache-control", "max-age=604800"),
            ("cdn-cache-control", "max-age=604800"),
            ("expires", "Wed, 21 Oct 2099 07:28:00 GMT"),
            // build_hit_response stamps this on every hit; on a STALE entry it exceeds the
            // TTL, so it must be neutralized or the 30s window is expired-on-arrival (#131).
            ("age", "7200"),
            ("content-type", "text/html"),
        ]);
        apply_stale_cf_egress(&mut h);
        let cc = h.get("cache-control").unwrap().to_str().unwrap();
        assert_eq!(
            cc, "public, max-age=30, must-revalidate",
            "stale serve must emit a short public TTL, got `{cc}`"
        );
        assert!(
            !cc.contains("no-store"),
            "no-store on the stale main resource defeats CF coalescing and bfcache"
        );
        assert_eq!(
            h.get(http::header::AGE).unwrap(),
            "0",
            "Age must be reset to 0 so the 30s window starts at this stale serve, not \
             `max-age=30` minus a 7200s Age (which arrives already expired) (#131)"
        );
        assert!(
            !h.contains_key("cloudflare-cdn-cache-control"),
            "CDN-Cache-Control overrides Cache-Control at the CF edge — must be dropped"
        );
        assert!(!h.contains_key("cdn-cache-control"));
        assert!(
            !h.contains_key(http::header::EXPIRES),
            "a far-future Expires would pin the stale body on an Expires-honoring intermediary"
        );
        assert_eq!(
            h.get(HDR_CACHE_STATUS).unwrap(),
            "stale",
            "observability marker"
        );
        // Unrelated headers (the body's content-type) survive.
        assert_eq!(h.get(CONTENT_TYPE).unwrap(), "text/html");
    }

    #[test]
    fn self_redirect_detection() {
        let host = "forum.example";
        let p = "/threads/x.422156/";
        let loc = |l: &str| hdrs(&[("location", l)]);
        // Same-scheme self-redirect (https request → https Location, same URL) → caught.
        assert!(is_self_redirect(
            301,
            &loc("https://forum.example/threads/x.422156/"),
            true,
            host,
            p,
            ""
        ));
        assert!(is_self_redirect(
            301,
            &loc("HTTPS://forum.example/threads/x.422156/"),
            true,
            host,
            p,
            ""
        ));
        // Same-scheme http self-redirect (http request → http Location, same URL) → caught.
        assert!(is_self_redirect(
            301,
            &loc("http://forum.example/threads/x.422156/"),
            false,
            host,
            p,
            ""
        ));
        // #fragment is stripped; root-relative resolves to the request scheme; query matters.
        assert!(is_self_redirect(
            301,
            &loc("https://forum.example/threads/x.422156/#post-1"),
            true,
            host,
            p,
            ""
        ));
        assert!(is_self_redirect(
            302,
            &loc("/threads/x.422156/"),
            true,
            host,
            p,
            ""
        ));
        assert!(is_self_redirect(
            301,
            &loc("https://forum.example/threads/x.422156/?page=2"),
            true,
            host,
            p,
            "page=2"
        ));
        // Percent-encoded unreserved bytes and hex case normalize before comparison.
        assert!(is_self_redirect(
            301,
            &loc("https://forum.example/threads/%78.422156/"),
            true,
            host,
            p,
            ""
        ));
        assert!(is_self_redirect(
            301,
            &loc("https://forum.example/threads/x.422156/?q=%7etest"),
            true,
            host,
            p,
            "q=~test"
        ));
        assert!(is_self_redirect(
            301,
            &loc("https://forum.example/threads/x.422156/?q=%2f"),
            true,
            host,
            p,
            "q=%2F"
        ));
        // (incident) h2 HTTP_HOST carries :443 while the Location is port-less — the host
        // compare must normalize both, else the homepage self-redirect loop gets cached.
        assert!(is_self_redirect(
            301,
            &loc("https://forum.example/"),
            true,
            "forum.example:443",
            "/",
            ""
        ));
        // ...and the reverse: a port-bearing Location vs a port-less request host.
        assert!(is_self_redirect(
            301,
            &loc("https://forum.example:443/threads/x.422156/"),
            true,
            host,
            p,
            ""
        ));
        // An empty-path absolute Location (no trailing slash) == a request path of "/".
        assert!(is_self_redirect(
            301,
            &loc("https://forum.example"),
            true,
            host,
            "/",
            ""
        ));
        // A PROTOCOL-RELATIVE `//host/path` resolves to the request's own scheme, so a
        // same-host, same-path one is a self-redirect loop (must not fall into the
        // root-relative arm and keep the `//host` prefix).
        assert!(is_self_redirect(
            301,
            &loc("//forum.example/threads/x.422156/"),
            true,
            host,
            p,
            ""
        ));
        assert!(is_self_redirect(
            301,
            &loc("//forum.example:443/threads/x.422156/"),
            true,
            host,
            p,
            ""
        ));

        // NOT self-redirects:
        // a protocol-relative Location to a DIFFERENT host is not a self-loop.
        assert!(!is_self_redirect(
            301,
            &loc("//other.example/threads/x.422156/"),
            true,
            host,
            p,
            ""
        ));
        // cross-scheme http→https is a LEGITIMATE upgrade, not a loop.
        assert!(!is_self_redirect(
            301,
            &loc("https://forum.example/threads/x.422156/"),
            false,
            host,
            p,
            ""
        ));
        assert!(!is_self_redirect(
            301,
            &loc("http://forum.example/threads/x.422156/"),
            true,
            host,
            p,
            ""
        ));
        // different path / trailing-slash canonical / query mismatch / non-3xx.
        assert!(!is_self_redirect(
            301,
            &loc("https://forum.example/threads/y.999/"),
            true,
            host,
            p,
            ""
        ));
        assert!(!is_self_redirect(
            301,
            &loc("https://forum.example/threads/x.422156/"),
            true,
            host,
            "/threads/x.422156",
            ""
        ));
        assert!(!is_self_redirect(
            301,
            &loc("https://forum.example/threads/x.422156/?page=2"),
            true,
            host,
            p,
            ""
        ));
        assert!(!is_self_redirect(
            301,
            &loc("https://forum.example/threads%2Fx.422156/"),
            true,
            host,
            p,
            ""
        ));
        assert!(!is_self_redirect(
            200,
            &loc("https://forum.example/threads/x.422156/"),
            true,
            host,
            p,
            ""
        ));
    }

    #[test]
    fn raw_self_redirect_distinguishes_canonicalization_from_mis_render() {
        let host = "forum.example";
        let loc = |l: &str| {
            let mut h = HeaderMap::new();
            h.insert(LOCATION, http::HeaderValue::from_str(l).unwrap());
            h
        };
        // Encoded-slug canonical 301 (raw request /a%5Fb, Location /a_b): SELF
        // for the caching guards (normalized), NOT self for the re-render
        // futility test (raw) — the backend would emit it again identically.
        let l = loc("/threads/erlang-ssh_sftpd.405371/");
        let raw_path = "/threads/erlang-ssh%5Fsftpd.405371/";
        assert!(is_self_redirect(301, &l, true, host, raw_path, ""));
        assert!(!is_self_redirect_raw(301, &l, true, host, raw_path, ""));
        // A byte-exact self-redirect (the /whats-new/posts/N shape) is raw-self.
        let l = loc("https://forum.example/whats-new/posts/1/");
        assert!(is_self_redirect_raw(
            303,
            &l,
            true,
            host,
            "/whats-new/posts/1/",
            ""
        ));
        // Raw compare still respects scheme (an upgrade is not a loop) ...
        assert!(!is_self_redirect_raw(
            301,
            &loc("https://forum.example/x"),
            false,
            host,
            "/x",
            ""
        ));
        // ... and host.
        assert!(!is_self_redirect_raw(
            301,
            &loc("https://other.example/x"),
            true,
            host,
            "/x",
            ""
        ));
    }

    #[test]
    fn raw_path_cache_canonical_admits_only_the_canonical_spelling() {
        for (raw, norm) in [
            ("/", "/"),
            ("/threads/x.422156/", "/threads/x.422156/"),
            ("/a%20b", "/a b"),
            ("/caf%C3%A9/", "/café/"),
            ("/caf%c3%a9/", "/café/"),
            ("/tag/r&d", "/tag/r&d"),
            ("/a%5D", "/a]"),
        ] {
            assert!(raw_path_is_cache_canonical(raw, norm), "{raw} -> {norm}");
        }
        for (raw, norm) in [
            ("/./", "/"),
            ("/index%2Ephp", "/index.php"),
            ("/a%5fb", "/a_b"),
            ("/zzz/..", "/"),
            ("/zzz/%2e%2e/target/", "/target/"),
            ("//target/", "/target/"),
            ("/a//b", "/a/b"),
            ("/a%2Fb", "/a/b"),
            ("/tag/r%26d", "/tag/r&d"),
            ("/a]", "/a]"),
            ("/a%2", "/a%2"),
            ("/a", "/a/"),
        ] {
            assert!(!raw_path_is_cache_canonical(raw, norm), "{raw} -> {norm}");
        }
    }

    #[test]
    fn self_redirect_detection_decodes_reserved_and_non_ascii_location() {
        let host = "forum.example";
        let loc = |l: &str| hdrs(&[("location", l)]);
        for (l, path, query) in [
            ("/self%20x/", "/self x/", ""),
            ("/self%C3%A9/", "/selfé/", ""),
            ("https://forum.example/a%2Bb?p=1", "/a+b", "p=1"),
            ("/a/./b", "/a/b", ""),
        ] {
            assert!(
                is_self_redirect(301, &loc(l), true, host, path, query),
                "{l} from {path}"
            );
        }
        for (l, path, query) in [
            ("/self%20x", "/self x/", ""),
            ("/self%20y/", "/self x/", ""),
            ("/a%20b?p=2", "/a b", "p=1"),
            ("/a%20b?", "/a b", ""),
        ] {
            assert!(
                !is_self_redirect(301, &loc(l), true, host, path, query),
                "{l} from {path}"
            );
        }
    }

    #[test]
    fn forced_cache_control_keeps_no_transform() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, No-Transform, max-age=60"),
        );
        apply_stale_cf_egress(&mut h);
        assert_eq!(
            h[http::header::CACHE_CONTROL],
            "public, max-age=30, must-revalidate, no-transform"
        );
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("public"),
        );
        apply_capsule_member_egress(&mut h);
        assert_eq!(h[http::header::CACHE_CONTROL], "private, no-store");
    }

    #[test]
    fn only_the_canonical_host_spelling_may_use_the_cache() {
        let req = |host: &str| {
            http::Request::builder()
                .uri("/")
                .header(http::header::HOST, host)
                .body(hj_core::empty_incoming())
                .unwrap()
        };
        for (host, tls) in [("x.test", true), ("x.test:443", true), ("x.test:80", false)] {
            assert!(raw_host_is_cache_canonical(&req(host), tls), "{host}");
        }
        for (host, tls) in [
            ("x.test:1234", true),
            ("x.test:99999999", true),
            ("X.TEST", true),
            ("x.test.", true),
            ("x.test.:443", true),
            ("x.test:80", true),
            ("x.test:443", false),
        ] {
            assert!(!raw_host_is_cache_canonical(&req(host), tls), "{host}");
        }
    }

    // ---- per-URL (response-declared) cookie vary ----------------------------------------

    fn uv_cc<'a>(
        store: &hj_pagecache::PageStore,
        path: &'a str,
        identity: &'a str,
        cookie: Option<&'a str>,
    ) -> CacheCtx<'a> {
        CacheCtx {
            cookie,
            ..page_cc(&Method::GET, path, identity, store.purge_epoch())
        }
    }

    /// As the pipeline records it when merging the rewrite env.
    fn uv_env_flag(ctx: &ReqCtx) -> bool {
        ctx.env.iter().any(|(k, v)| is_cache_vary_env(k, v))
    }

    fn uv_identity(path: &str) -> String {
        format!("https\nforum.example\n{path}")
    }

    /// Look `path` up with `cookie`; the served body on a hit.
    async fn uv_get(
        state: &Arc<ServerState>,
        ctx: &ReqCtx,
        path: &str,
        cookie: Option<&str>,
    ) -> Option<Bytes> {
        let store = state.page_cache.clone().unwrap();
        let identity = uv_identity(path);
        let cc = CacheCtx {
            env_vary: uv_env_flag(ctx),
            ..uv_cc(&store, path, &identity, cookie)
        };
        match cache_lookup(state, ctx, &cc, None, false, None) {
            CacheOutcome::Hit(resp) => {
                assert_eq!(resp.headers()[HDR_CACHE_STATUS], "hit");
                assert!(!resp.headers().contains_key(HDR_VARY));
                Some(crate::uring::bridge::buffer_body(resp.into_body()).await.0)
            }
            _ => None,
        }
    }

    /// A miss for `path` + `cookie` rendered as `body`, declaring `vary` / `tag`.
    async fn uv_fill(
        state: &Arc<ServerState>,
        ctx: &ReqCtx,
        path: &str,
        cookie: Option<&str>,
        vary: Option<&str>,
        tag: Option<&str>,
        body: &str,
    ) {
        let store = state.page_cache.clone().unwrap();
        let identity = uv_identity(path);
        let cc = CacheCtx {
            env_vary: uv_env_flag(ctx),
            ..uv_cc(&store, path, &identity, cookie)
        };
        let _ = cache_lookup(state, ctx, &cc, None, false, None);
        let mut resp = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html")
            .header(HDR_CACHE_CONTROL, "public,max-age=600");
        if let Some(v) = vary {
            resp = resp.header(HDR_VARY, v);
        }
        if let Some(t) = tag {
            resp = resp.header(HDR_TAG, t);
        }
        let resp = resp
            .body(Body::Full(Bytes::from(body.to_string())))
            .unwrap();
        let out = cache_store(state, ctx, &cc, resp).await;
        assert!(
            !out.headers().contains_key(HDR_VARY),
            "control header leaked"
        );
    }

    const TZ: Option<&str> = Some("cookie=tz_date");

    #[tokio::test]
    async fn per_url_vary_keeps_each_cookie_value_on_its_own_entry() {
        let (state, ctx, store) = cache_test_ctx();
        let d17 = Some("xf_csrf=a; tz_date=10-17");
        let d18 = Some("tz_date=10-18");
        uv_fill(&state, &ctx, "/", d17, TZ, None, "day 10-17").await;
        assert_eq!(store.url_vary_spec_count(), 1);
        assert_eq!(uv_get(&state, &ctx, "/", d17).await.unwrap(), "day 10-17");
        assert_eq!(uv_get(&state, &ctx, "/", d18).await, None);
        assert_eq!(uv_get(&state, &ctx, "/", None).await, None);
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=")).await, None);
        uv_fill(&state, &ctx, "/", d18, TZ, None, "day 10-18").await;
        uv_fill(&state, &ctx, "/", None, TZ, None, "no date").await;
        for _ in 0..2 {
            assert_eq!(uv_get(&state, &ctx, "/", d17).await.unwrap(), "day 10-17");
            assert_eq!(uv_get(&state, &ctx, "/", d18).await.unwrap(), "day 10-18");
            assert_eq!(uv_get(&state, &ctx, "/", None).await.unwrap(), "no date");
            // Unrelated cookies do not split the absent-date entry.
            assert_eq!(
                uv_get(&state, &ctx, "/", Some("other=1")).await.unwrap(),
                "no date"
            );
        }
        // The cookieless on-core fast path resolves the same (absent-date) variant.
        let identity = uv_identity("/");
        let cc = uv_cc(&store, "/", &identity, None);
        let CacheOutcome::Hit(hit) = cache_lookup_fast_path(&state, &ctx, &cc, None) else {
            panic!("fast path missed the absent-date variant");
        };
        assert_eq!(
            crate::uring::bridge::buffer_body(hit.into_body()).await.0,
            "no date"
        );
        // A URL that never declares the extra vary shares one entry across tz_date values.
        uv_fill(&state, &ctx, "/help/", d17, None, None, "help").await;
        assert_eq!(uv_get(&state, &ctx, "/help/", d18).await.unwrap(), "help");
        assert_eq!(uv_get(&state, &ctx, "/help/", None).await.unwrap(), "help");
        assert_eq!(store.url_vary_spec_count(), 1);
    }

    /// The hard constraint: while other URLs carry per-URL specs, a URL that never declares
    /// one keys, identifies and stores exactly as before (the golden key of
    /// `canonical_host_cache_keys_are_byte_stable_across_the_alias_fold`).
    #[tokio::test]
    async fn non_varying_urls_keep_their_historic_key_and_identity_bytes() {
        let (state, ctx, store) = cache_test_ctx();
        const PLAIN: &str = "5cbdff93fdbff4ab:PageCacheKey { vhost_id: 3328770662, secure: true, host: \"forum.example\", path: \"/threads/a.1/\", normalized_query: \"page=2\", vary_value: \"\", private_owner: 0 }";
        let cc = CacheCtx {
            cookie: Some("xf_style_id=3; tz_date=10-17"),
            req_query: "page=2",
            ..page_cc(&Method::GET, "/threads/a.1/", "i", store.purge_epoch())
        };
        let check = |label: &str| {
            let r = resolved_cache_key(&state, &ctx, &cc, &store, &PrivateRoute::Public).unwrap();
            assert_eq!(render_keys(std::slice::from_ref(&r.key)), PLAIN, "{label}");
            assert!(matches!(r.identity, Cow::Borrowed("i")), "{label}");
            let sk =
                store_cache_key(&state, &ctx, &cc, &store, &PrivateRoute::Public, &[]).unwrap();
            assert_eq!(render_keys(std::slice::from_ref(&sk.key)), PLAIN, "{label}");
            assert_eq!(sk.key_hash, hash_key(&sk.key));
            assert_eq!(sk.identity, "i", "{label}");
        };
        check("no spec anywhere");
        uv_fill(&state, &ctx, "/", Some("tz_date=10-17"), TZ, None, "d").await;
        assert!(store.url_vary_active());
        check("another URL carries a spec");
        // The spec's own variant key is the base key plus the self-describing suffix.
        let identity = uv_identity("/");
        let vcc = uv_cc(&store, "/", &identity, Some("tz_date=10-17"));
        let r = resolved_cache_key(&state, &ctx, &vcc, &store, &PrivateRoute::Public).unwrap();
        assert_eq!(r.key.vary_value, "\0lsvary:tz_date=v:10-17");
        assert_eq!(r.identity, format!("{identity}\0lsvary:tz_date=v:10-17"));
    }

    #[tokio::test]
    async fn per_url_vary_variants_follow_tag_purge_and_purge_all() {
        let (state, ctx, store) = cache_test_ctx();
        for d in ["10-17", "10-18"] {
            let c = format!("tz_date={d}");
            uv_fill(&state, &ctx, "/", Some(&c), TZ, Some("home"), d).await;
        }
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=10-17"))
                .await
                .unwrap(),
            "10-17"
        );
        store.purge_tags(&["home"]);
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=10-17")).await, None);
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=10-18")).await, None);
        // The spec survives a tag purge: the re-render is varied again.
        uv_fill(
            &state,
            &ctx,
            "/",
            Some("tz_date=10-17"),
            TZ,
            Some("home"),
            "again",
        )
        .await;
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=10-18")).await, None);
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=10-17"))
                .await
                .unwrap(),
            "again"
        );
        store.purge_all();
        assert_eq!(store.url_vary_spec_count(), 0);
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=10-17")).await, None);
        assert_eq!(store.entry_count(), 0);
    }

    #[tokio::test]
    async fn per_url_vary_cap_evicts_the_least_recently_used_variant() {
        let (state, ctx, store) = cache_test_ctx();
        let max = hj_pagecache::urlvary::MAX_VARIANTS;
        for i in 0..max {
            let c = format!("tz_date=v{i}");
            uv_fill(&state, &ctx, "/", Some(&c), TZ, None, &format!("b{i}")).await;
        }
        assert_eq!(store.entry_count(), max as u64);
        // Every variant but v0 is served after the fills, so v0 is least recently used.
        // (A hit rewrites the last-use stamp at most once a second.)
        tokio::time::sleep(Duration::from_millis(1100)).await;
        for i in 1..max {
            let c = format!("tz_date=v{i}");
            assert!(uv_get(&state, &ctx, "/", Some(&c)).await.is_some());
        }
        uv_fill(&state, &ctx, "/", Some("tz_date=flood"), TZ, None, "x").await;
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=flood"))
                .await
                .unwrap(),
            "x"
        );
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=v0")).await, None);
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=v3")).await.unwrap(),
            "b3"
        );
        assert_eq!(store.entry_count(), max as u64);
        // A value too long to key is never stored.
        let long = format!("tz_date={}", "z".repeat(200));
        uv_fill(&state, &ctx, "/", Some(&long), TZ, None, "long").await;
        assert_eq!(uv_get(&state, &ctx, "/", Some(&long)).await, None);
        assert_eq!(store.entry_count(), max as u64);
    }

    /// A varying render the admission bar rejects records no spec (so one-hit cache-buster
    /// renders cannot grow the spec map) but still retires the shared base entry it
    /// supersedes; the next render is admitted as for any other URL.
    #[tokio::test]
    async fn rejected_variant_creates_no_spec_but_retires_the_base() {
        let (state, ctx, store) = cache_test_ctx();
        uv_fill(&state, &ctx, "/", None, None, None, "shared").await;
        assert_eq!(uv_get(&state, &ctx, "/", None).await.unwrap(), "shared");
        // > 256 KiB raises the admission bar to two sightings.
        let big = "d".repeat(300 * 1024);
        uv_fill(&state, &ctx, "/", Some("tz_date=10-17"), TZ, None, &big).await;
        assert_eq!(
            store.url_vary_spec_count(),
            0,
            "no spec without an admitted variant"
        );
        assert_eq!(store.url_vary_bytes(), 0);
        assert_eq!(uv_get(&state, &ctx, "/", None).await, None, "base retired");
        assert_eq!(store.entry_count(), 0);
        uv_fill(&state, &ctx, "/", Some("tz_date=10-17"), TZ, None, &big).await;
        assert_eq!(store.url_vary_spec_count(), 1);
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=10-17"))
                .await
                .unwrap(),
            big.as_str()
        );
        assert_eq!(uv_get(&state, &ctx, "/", None).await, None);
    }

    /// With the spec map at its bound, a newly varying URL evicts the least recently touched
    /// spec rather than being refused, and its shared base entry is retired either way.
    #[tokio::test]
    async fn full_spec_map_still_retires_the_base_and_admits_the_new_url() {
        let (state, ctx, store) = cache_test_ctx();
        uv_fill(&state, &ctx, "/", None, None, None, "shared").await;
        let names = vec!["tz_date".to_string()];
        for i in 0..hj_pagecache::urlvary::MAX_SPECS as u64 {
            let b = hj_pagecache::PageCacheKey::public(1, true, "junk", format!("/j{i}"), "");
            assert!(store.url_vary_prepare(&b, hash_key(&b), &names, i));
        }
        assert_eq!(
            store.url_vary_spec_count(),
            hj_pagecache::urlvary::MAX_SPECS
        );
        assert!(store.url_vary_bytes() <= hj_pagecache::urlvary::MAX_SPEC_BYTES);
        uv_fill(&state, &ctx, "/", Some("tz_date=10-17"), TZ, None, "d17").await;
        assert_eq!(uv_get(&state, &ctx, "/", None).await, None, "base retired");
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=10-17"))
                .await
                .unwrap(),
            "d17"
        );
        assert_eq!(
            store.url_vary_spec_count(),
            hj_pagecache::urlvary::MAX_SPECS
        );
    }

    #[tokio::test]
    async fn a_later_response_without_vary_drops_the_spec_and_its_variants() {
        let (state, ctx, store) = cache_test_ctx();
        uv_fill(&state, &ctx, "/", Some("tz_date=10-17"), TZ, None, "d17").await;
        uv_fill(&state, &ctx, "/", Some("tz_date=10-18"), TZ, None, "d18").await;
        // The app stops varying: the next render declares no vary.
        uv_fill(&state, &ctx, "/", Some("tz_date=10-19"), None, None, "same").await;
        assert_eq!(store.url_vary_spec_count(), 0);
        for c in [Some("tz_date=10-17"), Some("tz_date=10-18"), None] {
            assert_eq!(uv_get(&state, &ctx, "/", c).await.unwrap(), "same", "{c:?}");
        }
        assert_eq!(store.entry_count(), 1);
        // And back: declaring the vary again retires the shared entry.
        uv_fill(&state, &ctx, "/", Some("tz_date=10-17"), TZ, None, "d17").await;
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=10-18")).await, None);
        assert_eq!(store.entry_count(), 1);
        // A changed vary set retires the old variants.
        uv_fill(
            &state,
            &ctx,
            "/",
            Some("tz_date=10-17; lang=fr"),
            Some("cookie=lang"),
            None,
            "fr",
        )
        .await;
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=10-17")).await, None);
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=10-18; lang=fr"))
                .await
                .unwrap(),
            "fr"
        );
    }

    #[tokio::test]
    async fn rewrite_env_cache_vary_keys_the_request_like_a_declared_vary() {
        for (k, v) in [
            ("Cache-Vary", "cookie=tz_date"),
            ("cache-control", "vary=tz_date"),
        ] {
            let (state, mut ctx, _store) = cache_test_ctx();
            ctx.env.push((k.into(), v.into()));
            uv_fill(
                &state,
                &ctx,
                "/env/",
                Some("tz_date=10-17"),
                None,
                None,
                "e17",
            )
            .await;
            assert_eq!(
                uv_get(&state, &ctx, "/env/", Some("tz_date=10-18")).await,
                None,
                "{k}"
            );
            uv_fill(
                &state,
                &ctx,
                "/env/",
                Some("tz_date=10-18"),
                None,
                None,
                "e18",
            )
            .await;
            assert_eq!(
                uv_get(&state, &ctx, "/env/", Some("tz_date=10-17"))
                    .await
                    .unwrap(),
                "e17"
            );
            assert_eq!(
                uv_get(&state, &ctx, "/env/", Some("tz_date=10-18"))
                    .await
                    .unwrap(),
                "e18"
            );
        }
    }

    fn uv_file_root(tag: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("hj-urlvary-{tag}-{}-{n}", std::process::id()))
    }

    fn uv_file_boot(
        root: &std::path::Path,
    ) -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        let root = root.to_path_buf();
        let (state, ctx, store) =
            cache_test_ctx_with(crate::state::XfCapsuleConfig::disabled(), move |cfg| {
                cfg.store_path = Some(root);
                cfg.max_mem_bytes = 8 * 1024 * 1024;
                cfg.max_disk_bytes = 8 * 1024 * 1024;
            });
        store.load_from_disk(|_| {});
        (state, ctx, store)
    }

    /// Persisted variants are self-describing: after a restart the boot scan rebuilds the
    /// spec, every variant serves only its own cookie value, and the un-varied key stays empty.
    #[tokio::test]
    async fn per_url_vary_variants_restore_from_the_file_tier() {
        let root = uv_file_root("restore");
        {
            let (state, ctx, store) = uv_file_boot(&root);
            uv_fill(&state, &ctx, "/", Some("tz_date=10-17"), TZ, None, "d17").await;
            uv_fill(&state, &ctx, "/", Some("tz_date=10-18"), TZ, None, "d18").await;
            uv_fill(&state, &ctx, "/", None, TZ, None, "none").await;
            uv_fill(&state, &ctx, "/help/", None, None, None, "help").await;
            assert_eq!(store.entry_count(), 4);
        }
        let (state, ctx, store) = uv_file_boot(&root);
        assert_eq!(store.scan_loaded(), 4);
        assert_eq!(store.url_vary_spec_count(), 1);
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=10-17"))
                .await
                .unwrap(),
            "d17"
        );
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=10-18"))
                .await
                .unwrap(),
            "d18"
        );
        assert_eq!(uv_get(&state, &ctx, "/", None).await.unwrap(), "none");
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=10-19")).await, None);
        assert_eq!(
            uv_get(&state, &ctx, "/help/", Some("tz_date=10-19"))
                .await
                .unwrap(),
            "help"
        );
        drop((state, store));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A restored un-varied entry older than the URL's variants is never served: the boot scan
    /// keeps the newest vary decision for the base key.
    #[tokio::test]
    async fn boot_scan_prefers_the_newest_vary_decision() {
        let root = uv_file_root("newest");
        {
            let (state, ctx, store) = uv_file_boot(&root);
            uv_fill(
                &state,
                &ctx,
                "/",
                Some("tz_date=10-17"),
                None,
                None,
                "old shared",
            )
            .await;
            let identity = uv_identity("/");
            let cc = uv_cc(&store, "/", &identity, None);
            let base = resolved_cache_key(&state, &ctx, &cc, &store, &PrivateRoute::Public)
                .unwrap()
                .key;
            let old = store.lookup(&base, &identity, Instant::now()).unwrap();
            uv_fill(&state, &ctx, "/", Some("tz_date=10-17"), TZ, None, "d17").await;
            assert!(store.lookup(&base, &identity, Instant::now()).is_none());
            // Plant a stale un-varied base entry beside the newer variant, as a crash between
            // the two decisions could leave behind (`store` skips the per-URL bookkeeping).
            let mut replant = (*old).clone();
            replant.body = PageBody::InMem(Bytes::from_static(b"old shared"));
            replant.stored_at = Instant::now() - Duration::from_secs(1);
            assert!(store.store(base, replant));
        }
        let (state, ctx, store) = uv_file_boot(&root);
        assert_eq!(store.url_vary_spec_count(), 1);
        assert_eq!(uv_get(&state, &ctx, "/", Some("tz_date=10-18")).await, None);
        assert_eq!(uv_get(&state, &ctx, "/", None).await, None);
        assert_eq!(
            uv_get(&state, &ctx, "/", Some("tz_date=10-17"))
                .await
                .unwrap(),
            "d17"
        );
        // The losing base entry was retired, not merely shadowed.
        assert_eq!(store.entry_count(), 1);
        drop((state, store));
        let _ = std::fs::remove_dir_all(&root);
    }
}
