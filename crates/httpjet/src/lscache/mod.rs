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
//! Phase 1 caches **public GET** responses only. The store deliberately holds
//! the *uncompressed* canonical body — compression happens per-serve in the
//! `handle()` transform chain (which skips bodies that already carry a
//! `Content-Encoding`), so a cache hit negotiates `gzip`/`br`/`zstd` exactly
//! like a miss and there is no per-codec variant explosion.

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

use hj_compress::{ACCEPT_ENCODING_ENV, Encoding, decode_bytes};
use hj_core::{Body, FileBody, ReqCtx, Request, Response};
use hj_pagecache::{
    CachedResponse, Disposition, PageBody, PageScope, Purge, QsStrip, classify_response,
    compute_vary_value, normalize_query, parse_purge, parse_tags, parse_vary, public_with_vary,
};
use hj_rewrite::{CacheKeyModifier, Htaccess, chain_cacheable_for_default};

use crate::state::{ServerState, XfCapsuleSafeGetMode};

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
    for pair in cookie?.split(';') {
        if let Some((n, v)) = pair.trim().split_once('=') {
            if n.trim() == name {
                return Some(v.trim());
            }
        }
    }
    None
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
enum PrivateRoute {
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
    if cookie_value(cookie, &cfg.private_user_cookie).is_none() {
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
    if !vhost_private {
        return PrivateRoute::Bypass;
    }
    match cookie_value(cookie, &cfg.private_session_cookie) {
        Some(sess) if !sess.is_empty() => PrivateRoute::Private {
            owner: fnv64(sess.as_bytes(), OWNER_BASIS_A),
            owner2: format!("s={:016x}", fnv64(sess.as_bytes(), OWNER_BASIS_B)),
        },
        _ => PrivateRoute::Bypass,
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
fn vhost_allows_public(ctx: &ReqCtx, store: &hj_pagecache::PageStore) -> bool {
    match ctx.vhost.cache_policy.as_ref() {
        Some(p) => p.enable_cache && p.enable_public,
        None => store.config().is_standards_vhost(&ctx.vhost_name),
    }
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
fn normalized_query_for(chain: &[Arc<Htaccess>], req_query: &str) -> String {
    if req_query.is_empty() {
        String::new()
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
    pub method: &'a Method,
    pub host: &'a str,
    pub cookie: Option<&'a str>,
    pub identity: &'a str,
    pub req_path: &'a str,
    pub req_query: &'a str,
    pub chain: &'a [Arc<Htaccess>],
    pub render_epoch: u64,
    pub has_range: bool,
    /// The request Host only matched the listener's `*` catch-all (not an exact vhostMap
    /// domain) and isn't the default vhost's own name — so it is FOREIGN to the resolved
    /// vhost. The cache keys by the resolved vhost, so a foreign host would otherwise be
    /// served (or would populate) the default vhost's cached entry, masking the backend's
    /// canonical redirect and leaking one brand's page under another's hostname. When set,
    /// the lookup degrades to a miss and the store is skipped — mirroring LiteSpeed LSCache,
    /// whose key embeds the request Host so a foreign host simply misses.
    pub host_foreign: bool,
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
/// lsphp/XenForo sees (that stays the real `HTTP_ACCEPT_ENCODING`). With `--cf-send-zstd`
/// on, a trusted-proxy (Cloudflare) peer is forced to `zstd` regardless of its forwarded
/// AE, keeping the stored variant + served encoding in lockstep with the transform. CF
/// decodes the zstd and re-encodes per browser at its edge; untrusted (direct) clients
/// always use their real AE, so none is ever handed an unrequested encoding.
fn egress_ae<'a>(state: &ServerState, ctx: &'a ReqCtx) -> &'a str {
    if state.compress.cf_send_zstd() && ctx.trusted_proxy {
        "zstd"
    } else {
        ctx.get_env(ACCEPT_ENCODING_ENV).unwrap_or("")
    }
}

/// (peer-fetch) On a genuine local MISS, try to fill the entry from the `--cache-peer`
/// instead of rendering: re-derive the (public) key, ask the peer for its HJPC bytes,
/// adopt them into the local store, then re-run the lookup so the entry is served
/// through the normal hit path. Returns `None` (→ render locally) when fill is off, the
/// request isn't publicly cacheable, no peer has it, or the peer is down. Inert unless
/// `--cache-peer-fill` is set; a slow/down peer is bounded by the fetch timeout +
/// circuit breaker, so it never delays the render.
pub async fn try_peer_fill(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
) -> Option<Response> {
    let pf = state.peer_purge.as_ref()?;
    if !pf.fill_enabled() {
        return None;
    }
    let store = state.page_cache.as_ref()?;
    // Re-derive the key exactly as cache_lookup did. Only PUBLIC entries cross nodes
    // (a private per-session entry would never match the peer's request).
    let route = private_route(state, ctx, store, cc, false);
    if !matches!(route, PrivateRoute::Public) {
        return None;
    }
    let key = build_cache_key(ctx, cc, store, &route);
    let key_hash = hash_key(&key);
    // Capture the purge epoch BEFORE the fetch: a purge landing while the peer round-trip is in
    // flight must veto the adoption, or the fill resurrects just-purged content (the two-node
    // cross-fill resurrection loop — see PageStore::adopt_entry).
    let fetch_epoch = store.purge_epoch();
    let blob = crate::peer_purge::serialize_fetch_key(&key, cc.identity);
    let bytes = pf.fetch(key_hash, &blob, state).await?;
    if !store.adopt_entry(key_hash, &bytes, fetch_epoch) {
        return None;
    }
    // The entry is now local → serve it through the standard hit path (build_hit_response,
    // egress, etc.). force_miss=false, no INM (serve the body, not a 304).
    match cache_lookup(state, ctx, cc, None, false) {
        CacheOutcome::Hit(h) => Some(h),
        _ => None,
    }
}

pub fn cache_lookup(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    if_none_match: Option<&str>,
    force_miss: bool,
) -> CacheOutcome {
    // (#5) The raw request host is no longer a key input (it now keys by the canonical
    // vhost name); it survives inside the caller-built `identity` guard and the serve-time
    // self-redirect re-check below.
    let &CacheCtx {
        method,
        host,
        identity,
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
    if matches!(route, PrivateRoute::Public) && !vhost_allows_public(ctx, store) {
        return CacheOutcome::Bypass;
    }
    // Per-request no-cache marker (logged-in / AJAX): always hit the backend.
    if no_cache_env(ctx) {
        return CacheOutcome::Bypass;
    }
    // Per-directory `.htaccess` cacheability (CacheLookup on, no CacheDisable). In the
    // default-cache-policy mode, an unspecified CacheLookup defaults to on (a non-LiteSpeed
    // app never writes it) — an explicit CacheLookup off / CacheDisable still wins.
    if !chain_cacheable_for_default(
        chain,
        req_path,
        store.config().is_standards_vhost(&ctx.vhost_name),
    ) {
        return CacheOutcome::Bypass;
    }

    let key = build_cache_key(ctx, cc, store, &route);
    let key_hash = hash_key(&key);
    // (W-TinyLFU) Record this cacheable lookup in the admission sketch — true access frequency
    // (hit OR miss), so the store-admission gate can reject one-hit-wonders. Cheap atomic bumps.
    state.page_cache_admission.record(key_hash);
    // A background refresh re-runs the request only to RENDER + store: it has passed the
    // same bypass gates and computed the same key as a real request, but must not serve the
    // stale entry (that would loop). Returning Miss drives the single-flight render + store.
    if force_miss {
        return CacheOutcome::Miss(key_hash);
    }
    let now = Instant::now();
    let entry = match store.get_entry(&key, identity, now) {
        hj_pagecache::EntryState::Fresh(e) => e,
        hj_pagecache::EntryState::Stale(e) => {
            // (dedup) A dict-compressed body is undecodable under a changed/absent dict → miss.
            if e.dict_gen != 0 && matching_dict(state, e.dict_gen).is_none() {
                return CacheOutcome::Miss(key_hash);
            }
            // (serve-time safety net) A stale self-redirect is still refused — degrade to a
            // miss so the backend re-renders instead of replaying a redirect loop.
            if entry_is_self_redirect(&e, ctx.is_tls, host, req_path, req_query) {
                return CacheOutcome::Miss(key_hash);
            }
            // Serve the stale body immediately; the caller spawns ONE background refresh
            // keyed by `key_hash`. Do NOT 304 here even on a conditional GET: a 304 would
            // tell CF "still fresh" and re-pin the stale copy — serve the body + a short/
            // no-store egress so CF re-asks and picks up the refreshed entry.
            let accept_encoding = egress_ae(state, ctx);
            let Some(mut resp) = hit::build_hit_response(
                &e,
                now,
                accept_encoding,
                method == Method::HEAD,
                matching_dict(state, e.dict_gen),
                || store.body_bytes(&e),
                || stored_file_body(store, &e),
            ) else {
                // (fail-closed) The stale entry couldn't be rendered (dict-decode failure / empty
                // body / a dead body file) — drop it and degrade to a miss so the backend
                // re-renders instead of serving a blank or retrying a dead file.
                store.invalidate_key(&key);
                return CacheOutcome::Miss(key_hash);
            };
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
    maybe_spawn_finalize(state, ctx, &key, key_hash, &entry);
    // Conditional revalidation: when CF's edge copy goes stale-but-revalidatable it sends
    // a conditional GET (If-None-Match) to the origin. If it matches our stored validator,
    // answer 304 (validators only) instead of re-shipping the full 50–200 KB HTML body
    // across the CF→origin hop. The store path synthesizes a weak ETag when the backend
    // gives none (XenForo pages usually don't), so this is what makes CF revalidation cheap.
    if let (Some(inm), Some(etag)) = (if_none_match, hit::entry_etag(&entry)) {
        if hit::if_none_match_matches(inm, etag) {
            let mut resp = hit::not_modified(&entry, etag, now);
            // Apply the SAME private-tier guarantees as the 200 hit below: a private-routed
            // 304 must match its owner (else degrade to a miss, never cross-serve), and must
            // NEVER advertise a shared-cacheable Cache-Control — force `private, no-store` so
            // a 304's validators/freshness can't be stored/replayed by Cloudflare cross-user.
            if let PrivateRoute::Private { owner, .. } = &route {
                if entry.scope != (hj_pagecache::PageScope::Private { owner_hash: *owner }) {
                    return CacheOutcome::Miss(key_hash);
                }
                resp.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    HeaderValue::from_static("private, no-store"),
                );
            }
            return CacheOutcome::Hit(resp);
        }
    }
    // (PC1) The client's Accept-Encoding (or forced zstd for a CF peer) selects a variant.
    let accept_encoding = egress_ae(state, ctx);
    // (PC2-lazy) The admitting store wrote this entry identity-only so compression CPU + variant
    // RAM is spent only on entries that prove hot by being SERVED. On the first hit of such an
    // entry, kick off ONE bounded background task to compute + re-insert the variant (preserving
    // the original stored_at/TTL); later hits serve it. Fires at most once per entry (the
    // re-insert sets `variants_filled`) and only when a variant could actually help.
    let capsule_shell = capsule_entry_shell_capable(&entry);
    if !entry.variants_filled
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
            accept_encoding.to_string(),
            capsule_shell,
        );
    }
    match hit::build_hit_response(
        &entry,
        now,
        accept_encoding,
        method == Method::HEAD,
        matching_dict(state, entry.dict_gen),
        || store.body_bytes(&entry),
        || stored_file_body(store, &entry),
    ) {
        Some(mut resp) => {
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
                resp.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    HeaderValue::from_static("private, no-store"),
                );
            }
            CacheOutcome::Hit(resp)
        }
        // (fail-closed) A fresh entry that can't be rendered (dict-decode failure / empty body /
        // a dead body file) is dropped and degrades to a miss so the backend re-renders — never
        // serve a blank 200, never keep retrying a dead file.
        None => {
            store.invalidate_key(&key);
            CacheOutcome::Miss(key_hash)
        }
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

fn stored_file_body(store: &hj_pagecache::PageStore, entry: &CachedResponse) -> Option<FileBody> {
    let f = store.body_file(entry)?;
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
    accept_encoding: String,
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
                &accept_encoding,
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
        let derive_len = variants
            .iter()
            .find_map(|(tok, b)| Encoding::from_token(tok).and_then(|e| decode_bytes(e, b)))
            .filter(|id| id.as_slice() == body.as_ref())
            .and(u32::try_from(body.len()).ok());
        store.fill_variants(&key, &entry.identity, entry.stored_at, variants, derive_len);
    });
}

/// Where the finalize task gets the identity bytes to compress.
enum FinalizeBody {
    /// The store path already holds the identity body — hand it straight to the task, no re-read.
    Ready(Bytes),
    /// The hit path only has the resident entry; resolve its stored body INSIDE the task, off the
    /// client path (a cold body costs a tmpfs read).
    Resident(Arc<CachedResponse>),
}

/// Dict-compress a stored identity entry on the bounded background pool. An unsuccessful attempt
/// leaves a resident marker, while a saturated worker pool leaves it unmarked so a later hit can
/// retry. Every guard is keyed on `(key, identity, stored_at)`, so a purge, an SWR refresh, or a
/// fresher re-store landing during the compression window makes the task a no-op — it can neither
/// resurrect a purged entry nor clobber a newer one.
fn spawn_finalize(
    state: &Arc<ServerState>,
    key: hj_pagecache::PageCacheKey,
    key_hash: u64,
    identity: String,
    stored_at: Instant,
    body: FinalizeBody,
    vhost: String,
    dict: Arc<hj_compress::PageDict>,
) {
    let registry = state.page_cache_dict_fill.clone();
    let warn_vhost = vhost.clone();
    let metrics = state
        .page_cache_dict_metrics
        .entry(vhost)
        .or_insert_with(|| Arc::new(crate::state::DictRecompressMetrics::default()))
        .clone();
    let task_metrics = metrics.clone();
    let state = state.clone();
    let start = spawn_guarded(&registry, key_hash, async move {
        let Some(store) = state.page_cache.as_ref() else {
            task_metrics
                .skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        if !store.mark_dict_compression_attempted(&key, &identity, stored_at) {
            task_metrics
                .skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            task_metrics
                .skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            Some(c) if c.len() <= bytes.len().saturating_sub(bytes.len() / 8) => c,
            _ => {
                task_metrics
                    .skipped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        };
        let compressed_len = compressed.len() as u64;
        if store.fill_recompress_disk(
            &key,
            &identity,
            stored_at,
            Bytes::from(compressed),
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
            task_metrics
                .skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
    last.fetch_update(
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
        key.clone(),
        key_hash,
        entry.identity.clone(),
        entry.stored_at,
        FinalizeBody::Resident(entry.clone()),
        vhost,
        dict,
    );
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
/// The encode stays on the background pool rather than running inline before the store: at level 15
/// it costs tens of ms on a real page, which would land directly on the TTFB of every cacheable
/// miss. The entry is therefore stored as identity and shrunk moments later, in place.
fn spawn_store_finalize(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    key: &hj_pagecache::PageCacheKey,
    key_hash: u64,
    identity: &str,
    stored_at: Instant,
    body: &Bytes,
) {
    let vhost = ctx.vhost_name.to_ascii_lowercase();
    let Some(dict) = state.page_cache_dicts.for_vhost(&vhost).cloned() else {
        return;
    };
    spawn_finalize(
        state,
        key.clone(),
        key_hash,
        identity.to_owned(),
        stored_at,
        FinalizeBody::Ready(body.clone()),
        vhost,
        dict,
    );
}

/// Stable hash of a page-cache key → the single-flight / refresh coordination id.
/// (Also the admission-sketch id — the boot warm scan pre-records each loaded key.)
pub(crate) fn hash_key(key: &hj_pagecache::PageCacheKey) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(key, &mut hasher);
    std::hash::Hasher::finish(&hasher)
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
fn apply_stale_cf_egress(headers: &mut HeaderMap) {
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=30, must-revalidate"),
    );
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

fn build_cache_key(
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
    route: &PrivateRoute,
) -> hj_pagecache::PageCacheKey {
    let vary_value = match route {
        PrivateRoute::Private { owner2, .. } => owner2.clone(),
        _ => compute_vary_value(cc.cookie, &store.config().vary_cookies),
    };
    let mut key = public_with_vary(
        vhost_id_hash(&ctx.vhost_name),
        ctx.is_tls,
        ctx.vhost_name.to_ascii_lowercase(),
        cc.req_path,
        normalized_query_for(cc.chain, cc.req_query),
        vary_value,
    );
    if let PrivateRoute::Private { owner, .. } = route {
        key.private_owner = *owner;
    }
    key
}

fn capsule_key(
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
) -> hj_pagecache::PageCacheKey {
    let path = if cc.req_path == "/" {
        format!("{CAPSULE_KEY_PREFIX}/")
    } else {
        format!("{CAPSULE_KEY_PREFIX}{}", cc.req_path)
    };
    public_with_vary(
        vhost_id_hash(&ctx.vhost_name),
        ctx.is_tls,
        ctx.vhost_name.to_ascii_lowercase(),
        path,
        normalized_query_for(cc.chain, cc.req_query),
        compute_vary_value(cc.cookie, &store.config().vary_cookies),
    )
}

fn capsule_public_fallback_key(
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    store: &hj_pagecache::PageStore,
) -> hj_pagecache::PageCacheKey {
    public_with_vary(
        vhost_id_hash(&ctx.vhost_name),
        ctx.is_tls,
        ctx.vhost_name.to_ascii_lowercase(),
        cc.req_path,
        normalized_query_for(cc.chain, cc.req_query),
        capsule_public_vary_value(cc.cookie, store),
    )
}

fn capsule_public_vary_value(cookie: Option<&str>, store: &hj_pagecache::PageStore) -> String {
    let cfg = store.config();
    let vary_cookies: Vec<String> = cfg
        .vary_cookies
        .iter()
        .filter(|name| {
            *name != &cfg.private_user_cookie
                && *name != &cfg.private_session_cookie
                && name.as_str() != CAPSULE_MEMBER_COOKIE
                && name.as_str() != CAPSULE_BYPASS_COOKIE
                && name.as_str() != "xf_admin"
                && name.as_str() != "xf_api_key"
        })
        .cloned()
        .collect();
    compute_vary_value(cookie, &vary_cookies)
}

fn capsule_vhost_allowed(state: &ServerState, ctx: &ReqCtx) -> bool {
    state.xf_capsule.vhosts.is_empty()
        || state
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
) -> bool {
    if !capsule_member_candidate(cc.cookie, store) {
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
) -> bool {
    state.xf_capsule.enabled
        && !is_capsule_reserved_path(cc.req_path)
        && !cc.host_foreign
        && !cc.has_range
        && (cc.method == Method::GET || cc.method == Method::HEAD)
        && capsule_vhost_allowed(state, ctx)
        && capsule_path_allowed(state, cc.req_path, cc.req_query)
        && capsule_cookie_safe(cc.cookie)
        && capsule_member_lookup_allowed(state, cc, store)
        && chain_cacheable_for_default(
            cc.chain,
            cc.req_path,
            store.config().is_standards_vhost(&ctx.vhost_name),
        )
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

fn ensure_stored_etag(headers: &mut Vec<(HeaderName, HeaderValue)>, bytes: &Bytes) {
    if !headers.iter().any(|(k, _)| k == ETAG) {
        if let Ok(v) = HeaderValue::from_str(&hit::weak_etag(bytes)) {
            headers.push((ETAG, v));
        }
    }
}

fn apply_capsule_member_egress(headers: &mut HeaderMap) {
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
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
        let Some((raw_name, raw_value)) = pair.trim().split_once('=') else {
            continue;
        };
        let Some(name) = cfg
            .vary_cookies
            .iter()
            .find(|name| name.as_str() == raw_name.trim())
        else {
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
        pairs.push(format!("{name}={}", raw_value.trim()));
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

    let key = capsule_public_fallback_key(ctx, cc, store);
    let key_hash = hash_key(&key);
    let (entry, stale) = match store.get_entry_uncounted(&key, cc.identity, now) {
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
    {
        record_capsule_miss(state, "public_fallback_miss");
        return CacheOutcome::Miss(dedicated_key_hash);
    }

    if !stale {
        maybe_spawn_finalize(state, ctx, &key, key_hash, &entry);
    }

    if let (Some(inm), Some(etag)) = (if_none_match, hit::entry_etag(&entry)) {
        if hit::if_none_match_matches(inm, etag) {
            let mut resp = hit::not_modified(&entry, etag, now);
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

    let accept_encoding = egress_ae(state, ctx);
    // Skip the precompress on a STALE hit: a background refresh is already in flight and will
    // re-store a fresh entry with variants, so filling the soon-to-be-superseded stale body is
    // wasted CPU (the fill's `stored_at` guard would no-op it anyway). Mirrors `cache_lookup`,
    // which only fills on the Fresh arm.
    if !stale
        && !entry.variants_filled
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
            accept_encoding.to_string(),
            true,
        );
    }

    match hit::build_hit_response(
        &entry,
        now,
        accept_encoding,
        cc.method == Method::HEAD,
        matching_dict(state, entry.dict_gen),
        || store.body_bytes(&entry),
        || stored_file_body(store, &entry),
    ) {
        Some(mut resp) => {
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
            store.invalidate_key(&key);
            record_capsule_miss(state, "public_fallback_miss");
            CacheOutcome::Miss(dedicated_key_hash)
        }
    }
}

pub fn capsule_lookup(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    cc: &CacheCtx<'_>,
    if_none_match: Option<&str>,
) -> CacheOutcome {
    let Some(store) = state.page_cache.as_ref() else {
        return CacheOutcome::Bypass;
    };
    if !capsule_lookup_allowed(state, ctx, cc, store) {
        if capsule_member_candidate(cc.cookie, store)
            || cookie_value(cc.cookie, CAPSULE_MEMBER_COOKIE) == Some("1")
        {
            record_capsule_miss(state, "not_allowed");
        }
        return CacheOutcome::Bypass;
    }

    let key = capsule_key(ctx, cc, store);
    let key_hash = hash_key(&key);
    let now = Instant::now();
    let entry = match store.get_entry_uncounted(&key, cc.identity, now) {
        hj_pagecache::EntryState::Fresh(e) => e,
        hj_pagecache::EntryState::Stale(e) => {
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
            if capsule_member_candidate(cc.cookie, store) && !matches!(e.scope, PageScope::Public) {
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
            let Some(mut resp) = hit::build_hit_response(
                &e,
                now,
                egress_ae(state, ctx),
                cc.method == Method::HEAD,
                matching_dict(state, e.dict_gen),
                || store.body_bytes(&e),
                || stored_file_body(store, &e),
            ) else {
                store.invalidate_key(&key);
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
            apply_stale_cf_egress(resp.headers_mut());
            mark_capsule(resp.headers_mut(), "hit,stale");
            mark_hot_path(resp.headers_mut(), "l2-stale");
            let age_secs = mark_shell_age(resp.headers_mut(), &e, now);
            let member = capsule_member_candidate(cc.cookie, store);
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
    if capsule_member_candidate(cc.cookie, store) && !matches!(entry.scope, PageScope::Public) {
        record_capsule_miss(state, "dedicated_miss");
        return capsule_public_fallback_lookup(state, ctx, cc, store, now, key_hash, if_none_match);
    }
    maybe_spawn_finalize(state, ctx, &key, key_hash, &entry);
    if let (Some(inm), Some(etag)) = (if_none_match, hit::entry_etag(&entry)) {
        if hit::if_none_match_matches(inm, etag) {
            let mut resp = hit::not_modified(&entry, etag, now);
            mark_capsule(resp.headers_mut(), "hit");
            mark_hot_path(resp.headers_mut(), "l1-fresh");
            let age_secs = mark_shell_age(resp.headers_mut(), &entry, now);
            let member = capsule_member_candidate(cc.cookie, store);
            if member {
                apply_capsule_member_egress(resp.headers_mut());
            }
            record_capsule_hit(state, "dedicated", member, age_secs);
            return CacheOutcome::Hit(resp);
        }
    }
    let accept_encoding = egress_ae(state, ctx);
    let capsule_shell = capsule_entry_shell_capable(&entry);
    if !entry.variants_filled
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
            accept_encoding.to_string(),
            capsule_shell,
        );
    }
    match hit::build_hit_response(
        &entry,
        now,
        accept_encoding,
        cc.method == Method::HEAD,
        matching_dict(state, entry.dict_gen),
        || store.body_bytes(&entry),
        || stored_file_body(store, &entry),
    ) {
        Some(mut resp) => {
            mark_capsule(resp.headers_mut(), "hit");
            mark_hot_path(resp.headers_mut(), "l1-fresh");
            let age_secs = mark_shell_age(resp.headers_mut(), &entry, now);
            let member = capsule_member_candidate(cc.cookie, store);
            if member {
                apply_capsule_member_egress(resp.headers_mut());
            }
            record_capsule_hit(state, "dedicated", member, age_secs);
            CacheOutcome::Hit(resp)
        }
        None => {
            store.invalidate_key(&key);
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
        identity,
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
        || !vhost_allows_public(ctx, store)
        || !chain_cacheable_for_default(
            chain,
            req_path,
            store.config().is_standards_vhost(&ctx.vhost_name),
        )
    {
        return None;
    }
    let key = build_cache_key(ctx, cc, store, route);
    let now = Instant::now();
    let entry = match store.get_entry(&key, identity, now) {
        hj_pagecache::EntryState::Fresh(e)
        | hj_pagecache::EntryState::Stale(e)
        | hj_pagecache::EntryState::ErrorOnly(e) => e,
        hj_pagecache::EntryState::Miss => return None,
    };
    if entry.dict_gen != 0 && matching_dict(state, entry.dict_gen).is_none() {
        return None;
    }
    if entry_is_self_redirect(&entry, ctx.is_tls, host, req_path, req_query) {
        return None;
    }
    let mut resp = hit::build_hit_response(
        &entry,
        now,
        egress_ae(state, ctx),
        method == Method::HEAD,
        matching_dict(state, entry.dict_gen),
        || store.body_bytes(&entry),
        || stored_file_body(store, &entry),
    )?;
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
        normalize_self_redirect_pq(&loc_pq) == normalize_self_redirect_pq(&req_pq)
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
        return resp;
    };

    let (mut parts, body) = resp.into_parts();

    // 1. Purge (acted on regardless of this response's own cacheability — a
    //    write request returns a purge directive for the content it changed).
    //    A backend may emit MORE THAN ONE `X-LiteSpeed-Purge`; execute and forward
    //    every one so no invalidation is dropped.
    for p in parts
        .headers
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
        // (OPS3) Propagate to the peer node(s) so the active-active pair stays
        // coherent — without this a purge only invalidates the node Cloudflare
        // routed the write to. Best-effort + off the response path; a received
        // purge arrives via the listener (not here), so this never loops.
        if let Some(pp) = state.peer_purge.as_ref() {
            pp.forward(p, state);
        }
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
    let vhost_caches = vhost_allows_public(ctx, store);
    let route = private_route(state, ctx, store, cc, false);
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
    let eligible = base_eligible
        // A private-routed (logged-in) request must never POPULATE the public
        // tier either — even if the app marked the render public, a logged-in
        // page may embed user state. Conservative by construction.
        && matches!(route, PrivateRoute::Public)
        && vhost_caches
        && vary_supported(&parts.headers, &cfg.vary_cookies)
        && !sets_private_cookie(&parts.headers, &cfg.private_cookies);

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
            if base_eligible =>
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
        && vary_supported(&parts.headers, &cfg.vary_cookies)
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
    if capsule_control.is_some() {
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

    // (#9) A `Body::File` CAN be eligible (an `.htaccess` `Header set
    // X-LiteSpeed-Cache-Control: public` on a static file, applied by
    // `apply_response_headers` BEFORE this store runs). `collect_body` reads it into
    // memory; only if THAT read fails do we recover the original File response below —
    // a valid file must never be replaced by a 502. Capture the descriptor first since
    // `collect_body` consumes the body.
    let file_recover: Option<(std::path::PathBuf, u64, Option<(u64, u64)>)> = match &body {
        Body::File(f) => Some((f.path.clone(), f.len, f.range)),
        _ => None,
    };
    let mut bytes = match collect_body(body, cfg.max_obj_bytes).await {
        Collected::Buffered(b) => b,
        Collected::OverCap(passthrough) => {
            // An unknown-length (chunked) stream exceeded the cap mid-buffer: serve it through,
            // uncached, control headers stripped — never buffering the whole body. (A File or a
            // Stream that DECLARED a length over the cap was already rejected before buffering.)
            strip_control_headers(&mut parts.headers);
            return Response::from_parts(parts, passthrough);
        }
        Collected::Error => {
            strip_control_headers(&mut parts.headers);
            if let Some((path, len, range)) = file_recover {
                // (#9) File read failed: serve the ORIGINAL file response (control
                // headers stripped), never a 502. The transport re-opens the file.
                tracing::warn!(path = %req_path, "page-cache: file body unreadable for cache; serving file uncached");
                let fb = Body::File(hj_core::FileBody {
                    path,
                    file: None,
                    len,
                    range,
                    cached: None,
                });
                return Response::from_parts(parts, fb);
            }
            // A genuine backend STREAM error mid-flight; the body is unrecoverable.
            tracing::warn!(path = %req_path, "page-cache: backend stream error while buffering");
            return error_502();
        }
    };

    // (#A/#B) CANONICALIZE TO IDENTITY before caching. The store, PC1 variants, and
    // per-serve compression all assume an identity body; the cache key is NOT
    // encoding-aware, so storing an already-compressed backend response (PHP/XF
    // `Content-Encoding: gzip` for gzip clients like Cloudflare) would replay a gzip
    // body to EVERY client — binary junk to non-gzip clients, and PC1 would
    // re-compress it (gzip-of-gzip). Decode a known single codec back to identity
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
    if store_ok && !uncacheable_body && bytes.len() as u64 <= cfg.max_obj_bytes {
        let mut stored_headers = stored_headers_from(&parts.headers);
        // Synthesize a weak validator when the backend gave none (XenForo pages usually
        // don't), so CF can revalidate a stale-but-cacheable page with a conditional GET and
        // get a 304 (headers only) instead of re-pulling the whole body. Served on every hit.
        ensure_stored_etag(&mut stored_headers, &bytes);
        if let Some(control) = capsule_control {
            // (#99) The dedicated capsule entry is stored WITHOUT the W-TinyLFU `admitted` gate
            // that governs the public mirror below — intentionally. The admission sketch frequency
            // is recorded only in `cache_lookup` (the public key), driven by GUEST traffic; capsule
            // member serves go through `capsule_lookup`/`capsule_public_fallback_lookup` and never
            // record it, and the dedicated (prefixed) key accumulates no frequency of its own. So
            // gating the shell store on that guest-only frequency would defeat the capsule exactly
            // for guest-rare-but-member-popular URLs. Eager storage is bounded (the `x-wf-capsule`
            // header is backend-controlled) and capped by the page store.
            let key = capsule_key(ctx, cc, store);
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
                spawn_store_finalize(
                    state,
                    ctx,
                    &key,
                    hash_key(&key),
                    &stored_identity,
                    stored_at,
                    &bytes,
                );
            }
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
        let key = build_cache_key(ctx, cc, store, &route);
        // (W-TinyLFU admission) Spend RAM (store) + CPU (precompress) only on keys that show
        // REUSE. The frequency sketch is recorded on every cacheable lookup; admit when the
        // estimate meets a SIZE-WEIGHTED bar (a one-hit-wonder is rejected; a larger object needs
        // more proven reuse) so the long tail behind Cloudflare can't churn out the hot working
        // set. A rejected response is still served below (just neither precompressed nor stored).
        let key_hash = hash_key(&key);
        // Private entries skip the W-TinyLFU frequency bar: per-session keys are
        // near-unique so the sketch never accumulates reuse for them, and the
        // whole point is serving the SAME session's next request.
        let is_private = matches!(scope, PageScope::Private { .. });
        let admitted = is_private
            || state.page_cache_admission.estimate(key_hash)
                >= admission_threshold(state.page_cache_admit_base, bytes.len() as u64);
        state.telemetry.record_cache_admission(admitted);
        if admitted {
            // (PC2-lazy) Store the entry IDENTITY-ONLY (no precompressed serve variant) — variant
            // precompression is deferred to the first cache HIT (`spawn_variant_fill`), so that CPU
            // is spent only on entries proven hot by being SERVED. Dictionary compression is NOT
            // deferred that way: it shrinks the entry's footprint in the capacity-bound file tier,
            // which it occupies whether or not it is ever served (see `spawn_store_finalize`).
            let stored_at = Instant::now();
            let stored_identity = identity.to_string();
            let stored = store.store_if_not_purged_since(
                key.clone(),
                CachedResponse {
                    status,
                    identity: stored_identity.clone(),
                    headers: stored_headers,
                    body: PageBody::InMem(bytes.clone()),
                    variants: Vec::new(),
                    // Private entries never get the lazy variant fill: per-session
                    // reuse is too low to pay the precompress CPU/RAM.
                    variants_filled: is_private,
                    dict_gen: 0,
                    tags,
                    vary_cookie_name: String::new(),
                    vary_value: String::new(),
                    scope,
                    stored_at,
                    ttl: Duration::from_secs(ttl_secs as u64),
                    swr: Duration::from_secs(stale_secs as u64),
                    sie: Duration::from_secs(sie_secs as u64),
                },
                render_epoch,
            );
            if stored {
                spawn_store_finalize(
                    state,
                    ctx,
                    &key,
                    key_hash,
                    &stored_identity,
                    stored_at,
                    &bytes,
                );
            }
        }
    }

    // 5. Serve the buffered body; strip control headers, mark the fill as a miss.
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
    if status != 200 {
        return false; // non-200 errors are excluded by the cacheable-status gate already
    }
    let is_html = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("text/html"));
    if !is_html {
        return false;
    }
    const SCAN: usize = 8192;
    const MARKER: &[u8] = b"data-template=\"error\"";
    let head = &body[..body.len().min(SCAN)];
    head.windows(MARKER.len()).any(|w| w == MARKER)
}

fn is_event_stream(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|base| base.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// A public response is storable only if EVERY declared `X-LiteSpeed-Vary` line is all
/// cookie-vary and every named cookie is in the supported (configured) set. A backend may
/// emit more than one `X-LiteSpeed-Vary`; all must be supported, since any unsupported vary
/// dimension means we'd under-key the entry and risk serving the wrong variant. Absent vary
/// ⇒ supported (no vary).
fn vary_supported(headers: &HeaderMap, allowed: &[String]) -> bool {
    headers
        .get_all(HDR_VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .all(|v| {
            let (names, all_cookie) = parse_vary(v);
            all_cookie && names.iter().all(|n| allowed.iter().any(|a| a == n))
        })
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
        private_cookies.iter().any(|p| p == name)
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
    /// An unknown-length stream exceeded `max_obj_bytes` while buffering: NOT cacheable. Carries
    /// a pass-through `Body` — the bytes read so far re-attached AHEAD of the unread remainder —
    /// so the response is served in full WITHOUT ever holding it all in RAM.
    OverCap(Body),
    /// Stream/file read error mid-buffer (unrecoverable here).
    Error,
}

/// Buffer a response body for caching, BOUNDED at `max_obj_bytes`. `Full`/`Empty`/`File` are
/// already size-bounded by the caller's known-length pre-check (a declared-length File/Stream
/// over the cap never reaches here), so they buffer directly. An unknown-length `Stream`
/// (chunked, no Content-Length) is collected frame-by-frame and stops the MOMENT it crosses the
/// cap — so a large or adversarial chunked response marked cacheable can't be slurped unboundedly
/// into RAM (an OOM/DoS vector the old `s.collect()` had). On overflow it is handed back as
/// `OverCap` to serve through, uncached.
async fn collect_body(body: Body, max_obj_bytes: u64) -> Collected {
    match body {
        Body::Full(b) => Collected::Buffered(b),
        Body::Empty => Collected::Buffered(Bytes::new()),
        Body::File(mut f) => {
            match tokio::task::spawn_blocking(move || {
                use std::io::{Read, Seek};

                let mut file = match f.file.take() {
                    Some(file) => file,
                    None => std::fs::File::open(&f.path)?,
                };
                let (start, len) = match f.range {
                    Some((start, end)) => (start, end.saturating_sub(start) + 1),
                    None => (0, f.len),
                };
                file.seek(std::io::SeekFrom::Start(start))?;
                let mut bytes = Vec::with_capacity(len.min(usize::MAX as u64) as usize);
                file.take(len).read_to_end(&mut bytes)?;
                Ok::<_, std::io::Error>(bytes)
            })
            .await
            {
                Ok(Ok(v)) => Collected::Buffered(Bytes::from(v)),
                _ => Collected::Error,
            }
        }
        Body::Stream(mut s) => {
            let mut buf = BytesMut::new();
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
                                return Collected::OverCap(Body::Stream(passthrough.boxed()));
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

    #[test]
    fn vary_supported_requires_all_repeated_lines() {
        // Two X-LiteSpeed-Vary lines, both supported -> storable.
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-litespeed-vary"),
            HeaderValue::from_static("cookie=xf_style_id"),
        );
        h.append(
            HeaderName::from_static("x-litespeed-vary"),
            HeaderValue::from_static("cookie=xf_language_id"),
        );
        assert!(vary_supported(&h, &style_set()));
        // Add a third, unsupported line -> NOT storable (would under-key the entry).
        h.append(
            HeaderName::from_static("x-litespeed-vary"),
            HeaderValue::from_static("cookie=xf_user"),
        );
        assert!(!vary_supported(&h, &style_set()));
    }

    #[test]
    fn vary_absent_is_supported() {
        assert!(vary_supported(&HeaderMap::new(), &style_set()));
    }

    #[test]
    fn vary_cookie_subset_supported() {
        let h = hdrs(&[(
            "x-litespeed-vary",
            "cookie=xf_style_variation, cookie=xf_style_id, cookie=xf_language_id",
        )]);
        assert!(vary_supported(&h, &style_set()));
    }

    #[test]
    fn vary_unknown_cookie_unsupported() {
        let h = hdrs(&[("x-litespeed-vary", "cookie=xf_user")]);
        assert!(!vary_supported(&h, &style_set()));
    }

    #[test]
    fn vary_non_cookie_unsupported() {
        let h = hdrs(&[("x-litespeed-vary", "cookie=xf_style_id, ismobile")]);
        assert!(!vary_supported(&h, &style_set()));
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

    fn cache_test_ctx() -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        cache_test_ctx_with_capsule(crate::state::XfCapsuleConfig::disabled())
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

        let public_vary = vec!["xf_style_id".into(), "xf_language_id".into()];
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
        );
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
            env: Vec::new(),
            local_addr: "127.0.0.1:443".parse().unwrap(),
            peer_port: 12345,
            request_time: std::time::SystemTime::UNIX_EPOCH,
            request_id: Default::default(),
            upstream_id: None,
            tls: None,
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
                store.get_entry(&key, identity, std::time::Instant::now())
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

    /// Enough repeated page boilerplate to train a usable dictionary on.
    const DICT_CORPUS: &[u8] =
        b"<html><head><title>example forum</title></head><body><div class=\"p-nav\">thread</div></body></html>";

    fn cache_test_ctx_with_dict() -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
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
            crate::state::XfCapsuleConfig::disabled(),
            None,
            false,
            None,
            false,
            crate::state::RewriteTuning::default(),
        );
        (state, ctx, store)
    }

    fn cache_test_ctx_with_capsule(
        xf_capsule: crate::state::XfCapsuleConfig,
    ) -> (Arc<ServerState>, ReqCtx, Arc<hj_pagecache::PageStore>) {
        let mut cfg = hj_pagecache::StoreConfig::default();
        cfg.standard_cc_vhosts.push("forum.example".into());
        cfg.private_user_cookie = "xf_user".into();
        cfg.private_session_cookie = "xf_session".into();
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
            xf_capsule,
            None,
            false,
            None,
            false,
            crate::state::RewriteTuning::default(),
        );
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
            env: Vec::new(),
            local_addr: "127.0.0.1:443".parse().unwrap(),
            peer_port: 12345,
            request_time: std::time::SystemTime::UNIX_EPOCH,
            request_id: Default::default(),
            upstream_id: None,
            tls: None,
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
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/example.1/";
        let guest_cc = CacheCtx {
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

        let member_cookie = "xf_user=1; xf_session=abc; xf_wf_capsule_member=1";
        let member_cc = CacheCtx {
            cookie: Some(member_cookie),
            ..guest_cc
        };
        let hit = match capsule_lookup(&state, &ctx, &member_cc, None) {
            CacheOutcome::Hit(hit) => hit,
            _ => panic!("expected capsule hit for member cookie"),
        };
        assert_eq!(hit.headers().get(HDR_XF_CAPSULE_STATUS).unwrap(), "hit");
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
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/zero.1/";
        let guest_cc = CacheCtx {
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
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/fallback.1/";
        let member_cookie = "xf_user=1; xf_session=abc; xf_wf_capsule_member=1";
        let member_cc = CacheCtx {
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

        let hit = match capsule_lookup(&state, &ctx, &member_cc, None) {
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
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/stale-fallback.1/";
        let member_cookie = "xf_user=1; xf_session=abc; xf_wf_capsule_member=1";
        let member_cc = CacheCtx {
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

        let hit = match capsule_lookup(&state, &ctx, &member_cc, None) {
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
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/untagged.1/";
        let member_cookie = "xf_user=1; xf_session=abc; xf_wf_capsule_member=1";
        let member_cc = CacheCtx {
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
            capsule_lookup(&state, &ctx, &member_cc, None),
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
                capsule_lookup(&state, &ctx, &member_cc, None),
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

        // A guest serve from the dedicated capsule entry (guest passes the lookup gate too).
        assert!(matches!(
            capsule_lookup(&state, &ctx, &guest_cc, None),
            CacheOutcome::Hit(_)
        ));
        assert_eq!(state.metrics.xf_capsule_hits_guest.load(Relaxed), 1);
        assert_eq!(state.metrics.xf_capsule_hits_member.load(Relaxed), 0);

        // A member serve of the same dedicated shell.
        let member_cc = CacheCtx {
            cookie: Some("xf_user=1; xf_session=abc; xf_wf_capsule_member=1"),
            ..guest_cc
        };
        assert!(matches!(
            capsule_lookup(&state, &ctx, &member_cc, None),
            CacheOutcome::Hit(_)
        ));
        assert_eq!(state.metrics.xf_capsule_hits_guest.load(Relaxed), 1);
        assert_eq!(state.metrics.xf_capsule_hits_member.load(Relaxed), 1);
        // Two hits => two shell-age observations.
        assert_eq!(
            state.metrics.xf_capsule_shell_age_secs_count.load(Relaxed),
            2
        );
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
        });
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let identity = "https\nforum.example\n/threads/example.1/";
        let guest_cc = CacheCtx {
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
            cookie: Some("xf_user=1; xf_session=abc; xf_wf_capsule_member=1"),
            ..guest_cc
        };
        assert!(matches!(
            capsule_lookup(&state, &ctx, &member_cc, None),
            CacheOutcome::Bypass
        ));
    }

    #[tokio::test]
    async fn stale_if_error_fallback_skips_range_requests() {
        let (state, ctx, store) = cache_test_ctx();
        let method = Method::GET;
        let chain: Vec<Arc<Htaccess>> = Vec::new();
        let cc = CacheCtx {
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
            has_range: true,
            ..cc
        };
        assert!(
            stale_if_error_fallback(&state, &ctx, &ranged, &store, &route, 503).is_none(),
            "Range requests must not receive a full stale-if-error body"
        );
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
        match collect_body(fb, 1024).await {
            Collected::Buffered(b) => assert_eq!(b.as_ref(), b"static-file-body"),
            _ => panic!("file body must buffer to its bytes"),
        }
        // A missing file is an Error (caller serves the original file, not 502).
        let _ = std::fs::remove_file(&path);
        let missing = Body::File(hj_core::FileBody {
            path,
            file: None,
            len: 0,
            range: None,
            cached: None,
        });
        assert!(matches!(
            collect_body(missing, 1024).await,
            Collected::Error
        ));
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
        let file_body = stored_file_body(&store, &hit).expect("file-tier hit");
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
        match collect_body(stream_of(&[b"ab", b"cd", b"ef"]), 1024).await {
            Collected::Buffered(b) => assert_eq!(b.as_ref(), b"abcdef"),
            _ => panic!("under-cap stream must buffer"),
        }
        // Exactly at the cap (6 bytes, cap 6): buffered (the store guard is `<= max_obj_bytes`).
        match collect_body(stream_of(&[b"abc", b"def"]), 6).await {
            Collected::Buffered(b) => assert_eq!(b.as_ref(), b"abcdef"),
            _ => panic!("at-cap stream must buffer"),
        }
    }

    #[tokio::test]
    async fn collect_stream_over_cap_serves_through_uncached() {
        // 10 bytes over a 4-byte cap: OverCap, and the pass-through body must reproduce the
        // FULL original bytes (prefix read so far + the unread remainder), never truncated.
        match collect_body(stream_of(&[b"abcd", b"efgh", b"ij"]), 4).await {
            Collected::OverCap(Body::Stream(s)) => {
                let bytes = s.collect().await.expect("pass-through collects").to_bytes();
                assert_eq!(
                    bytes.as_ref(),
                    b"abcdefghij",
                    "over-cap pass-through must be complete"
                );
            }
            _ => panic!("over-cap stream must be OverCap(Stream), not buffered"),
        }
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
}
