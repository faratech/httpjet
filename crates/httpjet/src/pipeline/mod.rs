//! The request pipeline: resolve the vhost, apply OLS-derived rewrite/access
//! rules, optionally short-circuit through the LSCache-equivalent page cache, then
//! dispatch to the terminal handler (proxy / LSAPI / static).
//!
//! Order (per the OLS dispatch algorithm):
//! 1. vhost resolution + `ReqCtx`.
//! 2. `.htaccess` load, server env, SetEnvIf, and pre-rewrite access checks.
//! 3. rewrite: inline `<rewrite>` rules then `.htaccess` chain. `[P]` is deferred
//!    so proxied responses can participate in page-cache store; `[R]` redirects;
//!    `[F]`/`[G]` forbid/gone; a rewrite updates the path.
//! 4. post-rewrite access checks, PATH_INFO script deny, and page-cache lookup.
//! 5. WebSocket upgrade → proxy via the vhost `websocketList`.
//! 6. proxy `<context>` (enabled) → reverse proxy to the named ext processor.
//! 7. suffix routing: `php`/`html` → LSAPI, else static files.

use std::borrow::Cow;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hj_compress::ExpiresHeaders;
use hj_core::{Body, Handler, Proto, ReqCtx, Request, Response, ResponseTransform};
use hj_lsapi::{JailConfig, LsapiScript, SpecialEnvType};
use hj_proxy::{ProxyTarget, is_websocket_upgrade};
use hj_rewrite::Htaccess;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, ETAG, LAST_MODIFIED};
use http::{HeaderValue, StatusCode};

use crate::lscache;
use crate::state::ServerState;

#[cfg(test)]
mod e2e;
pub(crate) mod fast_memo;
mod htaccess_apply;
mod proxy_glue;
mod response_util;
#[cfg(test)]
mod rewrite_differential;
mod rewrite_glue;
mod suffix_routing;

pub(crate) use rewrite_glue::{DEFAULT_REWRITE_OUTCOME_TTL, RewriteOutcomeCache, UaClassifyCache};

use htaccess_apply::{
    access_denied, access_deny_dir, apply_response_headers_for_request, apply_set_env,
    seed_server_env,
};
use proxy_glue::{ProxyHandler, matching_proxy_context, proxy_websocket, resolve_proxy_target};
use response_util::{
    apply_error_document, apply_static_context_headers, cache_identity_for, error_doc_or_page,
    matching_static_context, redirect, status_response,
};
use rewrite_glue::{
    RwResult, build_uri, decode_request_path, needs_encoding, normalized_request_path,
    percent_encode_path, resolved_rel_path, run_rewrite, url_parent_dir,
};
use suffix_routing::split_script_path;

/// Whether a `<context>` / WebSocket mount `uri` matches request `path`, with a
/// SEGMENT boundary: `/extended` matches `/extended` and `/extended/foo` but NOT
/// `/extendedness`. OLS resolves contexts segment-by-segment through its context
/// tree (`ContextNode::match`), so a raw `path.starts_with(uri)` over-matches any
/// shared prefix — a parity gap and a latent mis-route. The longest matching mount
/// still wins (callers keep their `max_by_key(uri.len())`); this only tightens the
/// per-candidate test.
pub(super) fn context_uri_matches(path: &str, uri: &str) -> bool {
    if uri == "/" {
        return true; // the root context matches every path
    }
    match path.strip_prefix(uri) {
        // Exact match, a `/`-delimited child, or a mount URI already ending in `/`.
        Some(rest) => rest.is_empty() || rest.starts_with('/') || uri.ends_with('/'),
        None => false,
    }
}

fn base_index_files<'a>(state: &'a ServerState, ctx: &'a ReqCtx) -> &'a [String] {
    if ctx.vhost.index_files.is_empty() {
        &state.server.index_files
    } else {
        &ctx.vhost.index_files
    }
}

fn htaccess_index_files(chain: &[Arc<Htaccess>]) -> Option<&[String]> {
    chain
        .iter()
        .rev()
        .find(|ht| !ht.directory_index.is_empty())
        .map(|ht| ht.directory_index.as_slice())
}

fn effective_index_files<'a>(
    state: &'a ServerState,
    ctx: &'a ReqCtx,
    chain: &'a [Arc<Htaccess>],
) -> &'a [String] {
    htaccess_index_files(chain).unwrap_or_else(|| base_index_files(state, ctx))
}

/// (OPS2) RAII ±1 around the lifetime of one `handle()` call so graceful shutdown
/// can wait for in-flight requests to finish. Decrements on every exit path
/// (early returns, the cache-hit short-circuit, panics) via `Drop`.
struct RequestGuard<'a>(&'a std::sync::atomic::AtomicU64);

impl<'a> RequestGuard<'a> {
    fn new(counter: &'a std::sync::atomic::AtomicU64) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        RequestGuard(counter)
    }
}

impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Sync-prefix cache-hit fast path for the io_uring transport. Resolves the vhost,
/// builds the SAME `ReqCtx` + `CacheCtx` `handle()` builds, and calls the SAME
/// `lscache::cache_lookup` — on a public/private HIT it applies the response
/// transforms and returns the response WITHOUT crossing the tokio bridge. Returns
/// `None` for anything that needs the backend (miss / stale-refresh / dynamic / no
/// cache / ACL deny), which the caller then bridges to the full pipeline.
///
/// Correctness: this reuses `cache_lookup` verbatim against the SAME mtime-cached
/// `.htaccess` chain `dispatch()` would load, AFTER running the sync prefix
/// (`seed_server_env`/`apply_set_env` + the per-dir/accessDenyDir gates) AND the
/// rewrite engine with dispatch()'s post-rewrite gates (#358), so request-side
/// state cannot diverge from the tokio path: a `CacheDisable`, `CacheLookup off`,
/// `CacheKeyModify -qs:` strip or `[E=no-cache]` SetEnvIf/rewrite mark applies here
/// exactly as it does at store time / slow-path lookup, a `RewriteCond`-gated
/// `[F]`/`[G]`/`[R]` or a directory denied AFTER an entry was stored bridges to the
/// 403/410/3xx instead of serving the stale hit, and the query-normalized key
/// matches the store-side key byte-for-byte. The chain load costs only cached
/// per-dir stats on the hot hit path; the rewrite is outcome-cached. The cache key
/// embeds `is_tls`, so a cross-scheme request just misses. Net: the fast path can
/// only ever serve a byte-correct hit or fall through.
const X_REQUEST_ID: http::HeaderName = http::HeaderName::from_static("x-request-id");

/// Echo the correlation id as `X-Request-Id` when `--request-id-header` is set, so a
/// client/CDN can join a response to the server-side logs. Called at the served-response
/// funnels (covers cache hits, redirects, proxy, LSAPI, static) — narrower and earlier
/// than a `ResponseTransform` (which never sees the id). Off by default ⇒ zero cost.
fn apply_request_id_header(state: &ServerState, ctx: &ReqCtx, resp: &mut Response) {
    if !state.request_id_header {
        return;
    }
    if let Ok(v) = http::HeaderValue::from_str(&ctx.request_id.to_string()) {
        resp.headers_mut().insert(X_REQUEST_ID, v);
    }
}

/// (#343 Step 1) Cookie-census classes for the on-core fast path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FastCookieClass {
    None,
    MemberSession,
    BenignOnly,
}

/// True when the Cookie header's NAMES include a membership marker (the configured
/// private user/session cookies). Names only — cookie values are never read here.
fn has_member_session_cookie(cookie: &str, session: &str, user: &str) -> bool {
    cookie.split(';').any(|kv| {
        let name = kv.split('=').next().unwrap_or("").trim();
        (!session.is_empty() && name.eq_ignore_ascii_case(session.trim()))
            || (!user.is_empty() && name.eq_ignore_ascii_case(user.trim()))
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fast_serve(
    state: &Arc<ServerState>,
    listener: &str,
    peer_ip: IpAddr,
    local_addr: std::net::SocketAddr,
    peer_port: u16,
    is_tls: bool,
    peer_unix: bool,
    proto: Proto,
    tls: Option<hj_core::TlsParams>,
    req: &Request,
) -> Option<Response> {
    let req_start = std::time::Instant::now();
    // Reserved cache endpoints (`/__hj_cache_purge|_get|_ready`) are intercepted
    // before vhost routing on BOTH entry points: `handle()` checks them below the
    // bridge, but this on-core fast path runs FIRST — without the same gate here,
    // any GET/HEAD probe could be answered by vhost content instead of the
    // endpoint contract (`classify()` accepts every method by design).
    if let Some(pp) = state.peer_purge.as_ref() {
        if let Some(resp) = pp.handle_inbound(req, peer_ip, state) {
            return Some(resp);
        }
    }
    let method = req.method().clone();
    if method != http::Method::GET && method != http::Method::HEAD {
        return None;
    }
    // (SEC1) request-target length cap — bridge the 414 to the full pipeline.
    let target_len = req.uri().path().len() + req.uri().query().map_or(0, |q| q.len() + 1);
    if target_len > state.serve_config.max_req_url_len {
        return None;
    }
    let (route_key, host_src): (Option<String>, fast_memo::HostSource) = match req
        .headers()
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        Some(h) => (Some(h.to_owned()), fast_memo::HostSource::Header),
        None => match req.uri().authority().map(|a| a.host().to_string()) {
            Some(a) => (Some(a), fast_memo::HostSource::Authority),
            None => (None, fast_memo::HostSource::None),
        },
    };
    let resolved = state.router.resolve(listener, route_key.as_deref())?;
    if !state.acl.check_peer(peer_ip).is_allowed() {
        return None; // let the bridge render the 403 with the full pipeline
    }
    let trusted_proxy = state.acl.is_trusted(peer_ip);
    let effective_https = effective_request_https(is_tls, trusted_proxy, req.headers());
    // (SEC) mTLS trust-boundary parity with `handle()`: a plaintext request to an
    // mTLS-required vhost from a non-internal peer must be 301'd to HTTPS *before* any
    // content is served. The on-core fast path cannot issue that redirect itself, so
    // decline and let the full pipeline enforce the gate — otherwise a direct-to-:80
    // client would be served public cache/static content over cleartext that policy
    // says must be HTTPS.
    if mtls_gate_redirects(
        effective_https,
        state.mtls_required_vhosts.contains(&resolved.name),
        peer_ip,
    ) {
        return None;
    }
    let mut ctx = ReqCtx {
        server: state.server.clone(),
        vhost_name: resolved.name,
        vhost: resolved.config,
        peer_ip,
        client_ip: peer_ip,
        is_tls: effective_https,
        peer_unix,
        protocol: proto,
        trusted_proxy,
        env: Vec::with_capacity(8),
        local_addr,
        peer_port,
        tls,
        request_time: std::time::SystemTime::now(),
        request_id: hj_core::reqid::next(),
        redirect_guard: None,
    };
    // (#349) Finished-response memo (default-on; `--no-fast-memo` / HJ_FAST_MEMO=0
    // kill switch). The request gates here are HALF the correctness contract;
    // the other half is the chain/inline eligibility enforced at the store site
    // below — see the `fast_memo` module doc. A hit replays a response the FULL
    // fast path built for this exact key + vary-set within the last second,
    // resolves the real client IP for the access log, and goes through the same
    // observability funnel as every other serve. Every conditional header the
    // static handler answers with 304/412/206 is excluded, not just the two
    // common ones — a replayed 200 would silently override that verdict.
    let memo_eligible_req = fast_memo::enabled()
        && method == http::Method::GET
        && !req.headers().contains_key(http::header::COOKIE)
        && !req.headers().contains_key(http::header::RANGE)
        && !req.headers().contains_key(http::header::IF_NONE_MATCH)
        && !req.headers().contains_key(http::header::IF_MODIFIED_SINCE)
        && !req.headers().contains_key(http::header::IF_MATCH)
        && !req.headers().contains_key(http::header::IF_RANGE)
        && !req
            .headers()
            .contains_key(http::header::IF_UNMODIFIED_SINCE)
        && !req.headers().contains_key(http::header::AUTHORIZATION);
    // A `path_cacheable: false` inline set means stores are impossible; skip
    // the probe entirely. Its keyable vars become vary items at the store site.
    let memo_inline = state.inline_rules.get(&ctx.vhost_name);
    let memo_inline_ok = memo_inline.is_none_or(|rs| rs.path_cacheable);
    if memo_eligible_req && memo_inline_ok {
        let mk = fast_memo::MemoKey {
            listener,
            https: effective_https,
            trusted_proxy,
            vhost: &ctx.vhost_name,
            host_src,
            host: route_key.as_deref().unwrap_or("").as_bytes(),
            path: req.uri().path(),
            query: req.uri().query().unwrap_or(""),
            ae: req
                .headers()
                .get(http::header::ACCEPT_ENCODING)
                .map(|v| v.as_bytes())
                .unwrap_or(b""),
        };
        if let Some(resp) = fast_memo::probe(&mk, req, &state.ua_classify, req_start) {
            state
                .metrics
                .fast_memo_hits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mtls_ok = if state.mtls_required_vhosts.contains(&ctx.vhost_name) {
                ctx.tls
                    .as_ref()
                    .map(|t| t.client_cert.is_some())
                    .unwrap_or(false)
            } else {
                is_tls
            };
            ctx.client_ip = state.acl.resolve_client_ip(
                peer_ip,
                req.headers(),
                state.server.use_ip_in_proxy_header,
                mtls_ok,
            );
            if !state.geo.allows(ctx.client_ip) {
                return None; // the full pipeline renders the identical geo 403
            }
            if !state.client_throttle.allow(peer_ip) {
                return None; // over the per-IP rate: dispatch() renders the 429
            }
            return Some(record_fast_serve(state, &ctx, proto, req, req_start, resp));
        }
    }
    if let Some(ae) = req
        .headers()
        .get(http::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
    {
        ctx.set_env("HTTP_ACCEPT_ENCODING", ae.to_string());
    }
    let req_host = lscache::request_host(req, &ctx);
    let host_foreign = !req_host.eq_ignore_ascii_case(&ctx.vhost_name)
        && !state.router.host_is_exact(listener, &req_host);
    set_redirect_guard(&mut ctx, req.uri(), &req_host);
    let orig_path = match decode_request_path(req.uri().path()) {
        Some(p) => normalized_request_path(&p),
        None => return None, // malformed path → let the bridge render the error
    };
    let orig_query = req.uri().query().unwrap_or("").to_string();

    // ---- SYNC PREFIX (shared by both branches): reproduce dispatch()'s pre-backend
    // state with the SAME helpers in the SAME order — per-dir `.htaccess` chain
    // (mtime-cached), REAL client IP, server env + SetEnvIf (`[E=no-cache]` included),
    // then the per-dir deny + accessDenyDir gates — so neither on-core branch can serve
    // content the tokio path would refuse. A deny declines (None) and dispatch() renders.
    let htaccess_enabled = ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess);
    let chain_with_dirs: Vec<(std::path::PathBuf, std::sync::Arc<Htaccess>)> = if htaccess_enabled {
        state.rewrite_cache.load_chain_with_dirs(
            &ctx.vhost.doc_root,
            &orig_path,
            ctx.vhost.access_file_name_or_default(),
        )
    } else {
        Vec::new()
    };
    let chain: Vec<std::sync::Arc<Htaccess>> =
        chain_with_dirs.iter().map(|(_, h)| h.clone()).collect();
    // (Tier 1.3) An auth-protected tree never serves on-core: dispatch() enforces
    // the 401 challenge / credential verification before anything else.
    if chain.iter().any(|h| h.auth.is_some()) {
        return None;
    }
    // (#349) Memo store eligibility — the response must be a pure function of
    // the memo key plus the entry's vary-set. Each chain file's verdict is
    // parse-time (`MemoClass`, fail-closed): SetEnvIf on client/server address
    // or protocol, IP/env access rules, and any rewrite input outside the key +
    // keyable vars withdraw it; header reads become vary dimensions. The vhost
    // inline ruleset must be `path_cacheable`. `Header`/`extraHeaders`
    // conditionality is URI/env-modelled in this engine, so under these gates
    // it is key-deterministic too. A directory change that adds any such
    // directive is visible within the memo's 1 s TTL.
    let memo_chain_ok = memo_inline_ok
        && chain_with_dirs
            .iter()
            .all(|(_, ht)| ht.memo.eligible && ht.rules.path_cacheable);
    // (Tier 2) sub_filter paths are memo-ineligible: the memo stores
    // POST-transform bytes and a memo hit re-runs the transforms, which would
    // substitute twice whenever a replacement contains its own search string.
    let memo_store_ok = memo_eligible_req && memo_chain_ok && !sub_filter_matches(&ctx, &orig_path);
    // (B5) Resolve the REAL client IP before any IP-sensitive access decision (a
    // `SetEnvIf Remote_Addr …` feeding a `Require`, or an `accessDenyDir`) so the on-core
    // path judges the SAME identity the tokio `handle()` path does — not the raw socket
    // peer (the Cloudflare edge IP). Mirrors `record_fast_serve` / `handle()`; honors
    // the mtls-ok-vs-real-IP invariant (no client cert required under a non-mTLS vhost).
    let mtls_ok = if state.mtls_required_vhosts.contains(&ctx.vhost_name) {
        ctx.tls
            .as_ref()
            .map(|t| t.client_cert.is_some())
            .unwrap_or(false)
    } else {
        is_tls
    };
    ctx.client_ip = state.acl.resolve_client_ip(
        peer_ip,
        req.headers(),
        state.server.use_ip_in_proxy_header,
        mtls_ok,
    );
    if !state.geo.allows(ctx.client_ip) {
        // (Tier 2) Decline so the bridge renders the identical geo 403 the full
        // pipeline would (fast_serve cannot produce an error page itself).
        return None;
    }
    seed_server_env(&mut ctx);
    apply_set_env(&mut ctx, &chain, req, &orig_path, &orig_query);
    let orig_rel = resolved_rel_path(&orig_path);
    if access_denied(&chain, &orig_rel, method.as_str(), &ctx)
        || access_deny_dir(&state.acl, &ctx.vhost.doc_root, &orig_rel)
    {
        return None;
    }

    // ---- REWRITE (shared by both branches): dispatch() runs the engine BEFORE its
    // cache lookup (step 3 → step 4c), as LSWS/OLS hook the cache at URI_MAP after
    // `processContextRewrite`. Serving a hit first let a `RewriteCond
    // %{REMOTE_ADDR}|%{HTTP_USER_AGENT}|…` + `[F]`/`[G]`/`[E=no-cache]` — inputs
    // outside the cache key — be skipped for a warm cookieless URL (#358). Redirect/
    // status/forbidden/gone outcomes bridge so dispatch() renders them; `[P]` merges
    // its env and keeps the original path exactly as dispatch() defers it; a
    // rewritten target carries dispatch()'s post-rewrite gates below.
    let rw = run_rewrite(state, &ctx, req, &chain_with_dirs, &orig_path, &orig_query);
    let (cache_path, cache_rel, rewrite_unchanged): (Cow<'_, str>, Cow<'_, str>, bool) = match rw {
        RwResult::Unchanged { env } => {
            merge_rewrite_env(&mut ctx, env);
            (Cow::Borrowed(&orig_path), Cow::Borrowed(&orig_rel), true)
        }
        RwResult::Proxy { env, .. } => {
            merge_rewrite_env(&mut ctx, env);
            (Cow::Borrowed(&orig_path), Cow::Borrowed(&orig_rel), false)
        }
        RwResult::Rewritten { path, env, .. } => {
            merge_rewrite_env(&mut ctx, env);
            // A rewrite INTO a non-ancestor directory makes dispatch() reload the
            // destination chain (#8); the on-core path bridges instead of guessing.
            if !url_parent_dir(&orig_path).starts_with(url_parent_dir(&path)) {
                return None;
            }
            let rel = resolved_rel_path(&path);
            (Cow::Owned(path), Cow::Owned(rel), false)
        }
        RwResult::Redirect { .. }
        | RwResult::Status { .. }
        | RwResult::Forbidden
        | RwResult::Gone => {
            return None;
        }
    };

    // ---- Branch 1: GUEST cookieless page-cache HIT (B1) ----
    // Any Cookie may carry membership (`xf_user`) or a vary dimension; bridge cookied
    // requests so the full pipeline decides (the cache_private gate catches a leak
    // without this). The lookup sees the SAME loaded chain `dispatch()` uses, so
    // request-side cache policy cannot diverge from the store/slow-path decisions.
    // (#343 Step 1) Cookie census on every fast-path GET/HEAD: names only, values never
    // read — the benign-only share among cookied requests decides whether extending the
    // fast path past literally-cookieless guests is worth building.
    if let Some(store) = state.page_cache.as_ref() {
        let cfg = store.config();
        let class = match req
            .headers()
            .get(http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
        {
            None => FastCookieClass::None,
            Some(c)
                if has_member_session_cookie(
                    c,
                    &cfg.private_session_cookie,
                    &cfg.private_user_cookie,
                ) =>
            {
                FastCookieClass::MemberSession
            }
            Some(_) => FastCookieClass::BenignOnly,
        };
        let counter = match class {
            FastCookieClass::None => &state.metrics.fast_cookie_none,
            FastCookieClass::MemberSession => &state.metrics.fast_cookie_member_session,
            FastCookieClass::BenignOnly => &state.metrics.fast_cookie_benign_only,
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    if state.page_cache.is_some() && !req.headers().contains_key(http::header::COOKIE) {
        if fast_post_rewrite_bridges(
            state,
            &ctx,
            &chain,
            &cache_path,
            &cache_rel,
            method.as_str(),
        ) {
            return None;
        }
        let identity = cache_identity_for(ctx.is_tls, &ctx.vhost_name, &orig_path);
        let render_epoch = state
            .page_cache
            .as_ref()
            .map(|pc| pc.purge_epoch())
            .unwrap_or(0);
        let _render_guard = state
            .page_cache
            .as_ref()
            .map(|pc| pc.begin_render(render_epoch));
        let cc = lscache::CacheCtx {
            method: &method,
            host: &req_host,
            cookie: None,
            identity: &identity,
            req_path: &orig_path,
            req_query: &orig_query,
            chain: &chain,
            render_epoch,
            has_range: req.headers().contains_key(http::header::RANGE),
            host_foreign,
            // Cookieless by branch precondition ⇒ the public vary value is "".
            vary_value: Some(""),
        };
        let inm = req
            .headers()
            .get(http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());
        if let lscache::CacheOutcome::Hit(mut resp) =
            lscache::cache_lookup(state, &ctx, &cc, inm, false, None)
        {
            for t in &state.transforms {
                t.transform(&ctx, &mut resp).await;
            }
            state.telemetry.record_cache_hit(peer_ip.is_loopback());
            if !state.client_throttle.allow(peer_ip) {
                return None; // over the per-IP rate: dispatch() renders the 429
            }
            return Some(record_fast_serve(state, &ctx, proto, req, req_start, resp));
        }
    }

    // ---- Branch 2: STATIC file served on-core (cookie-independent) ----
    // Faithfully reproduce dispatch()'s SYNC prefix with the SAME helpers in the SAME
    // order (path canonicalization, per-dir deny, accessDenyDir, PHP-suffix source
    // protection), then serve via the static handler. CONSERVATIVE: bridge (None) on
    // ANY non-trivial outcome — foreign host, a rewrite that changes the path,
    // proxy/static <context>, a PHP/script suffix, an access deny, or a non-success
    // status (so a `.htaccess` ErrorDocument, possibly a .php subrequest, renders on
    // the tokio path). dispatch() itself is untouched (this is an additive uring path).
    if host_foreign {
        return None;
    }
    // Only an unchanged (no-op) rewrite stays on-core; any rewrite/redirect/status/
    // forbidden/gone/proxy outcome bridges.
    if !rewrite_unchanged {
        return None;
    }
    if access_denied(&chain, &orig_rel, method.as_str(), &ctx) {
        return None;
    }
    if matching_proxy_context(&ctx, &orig_path).is_some() {
        return None;
    }
    // (#349) A matching static <context> no longer forces the bridge: mirror
    // dispatch's handling (DocRootOverride when the location differs from the
    // docroot, extraHeaders after the handler, default charset) so
    // context-bearing vhosts — e.g. the mcp hybrid docroot, whose `/` static
    // context used to push EVERY static request through the tokio pipeline —
    // serve on-core. The post-handler `resolved_static_target_denied` net
    // still fail-closes an override root against accessDenyDir, exactly as on
    // the bridged path.
    let (static_extra_headers, static_location, static_charset): (
        Option<Vec<(String, String)>>,
        Option<std::path::PathBuf>,
        Option<String>,
    ) = match matching_static_context(&ctx, &orig_path) {
        Some(c) => (
            Some(c.extra_headers.clone()),
            c.location.clone(),
            effective_static_charset(c),
        ),
        None => (None, None, None),
    };
    // A path that resolves to a script handler must NEVER be served by the static
    // handler (source disclosure) — bridge it. `&chain` lets an `.htaccess`
    // `SetHandler`/`AddHandler`/`AddType` force a non-PHP-suffixed file to script
    // here too, so the on-core static fast path never serves its source.
    let index_files = effective_index_files(state, &ctx, &chain);
    if split_script_path(state, &ctx, &orig_path, index_files, &chain).is_some() {
        return None;
    }
    // Static. Serve via the shared static handler on a bodyless GET/HEAD clone (the
    // caller keeps the original request to bridge if we decline).
    let mut sreq: Request = http::Request::new(hj_core::empty_incoming());
    *sreq.method_mut() = method.clone();
    *sreq.uri_mut() = req.uri().clone();
    *sreq.headers_mut() = req.headers().clone();
    if let Some(idx) = htaccess_index_files(&chain) {
        sreq.extensions_mut()
            .insert(hj_static::IndexFilesOverride(idx.to_vec()));
    }
    if let Some(loc) = static_location {
        if loc != ctx.vhost.doc_root {
            sreq.extensions_mut()
                .insert(hj_static::DocRootOverride(loc));
        }
    }
    if let Some(charset) = static_charset {
        sreq.extensions_mut()
            .insert(hj_static::DefaultCharsetOverride(charset));
    }
    let mut resp = run_handler(&state.static_handler, &mut ctx, sreq).await;
    if resolved_static_target_denied(&state.acl, &resp) {
        return None;
    }
    if !matches!(resp.status().as_u16(), 200 | 206 | 304) {
        return None; // 404/403/416 → bridge so the ErrorDocument renders on tokio
    }
    if let Some(extra) = &static_extra_headers {
        apply_static_context_headers(extra, &mut resp);
    }
    // Promote the file body to in-memory ON-CORE (sync read; large/ranged → bridge),
    // BEFORE the transforms — the monoio writers have no on-core file streamer yet, and
    // CacheStaticTransform's own promotion uses tokio block_in_place (panics off a tokio
    // runtime). Small static files become Body::Full and serve on-core.
    let mut resp = buffer_static_file(state, lscache::vhost_id_hash(&ctx.vhost_name), resp)?;
    finalize_response(
        state, &mut ctx, &chain, &orig_rel, &orig_path, &orig_path, &mut resp,
    )
    .await;
    // (Tier 2) Stamp BEFORE the transform loop so SubFilterTransform sees the plan.
    stamp_sub_filter(&ctx, &orig_path, &mut resp);
    // Header transforms (expires / Alt-Svc / compress) — they see an in-memory body now,
    // so CacheStaticTransform is a no-op (no block_in_place) and Compress negotiates per AE.
    for t in &state.transforms {
        t.transform(&ctx, &mut resp).await;
    }
    if resp.status() == StatusCode::OK && !resp.headers().contains_key(http::header::SET_COOKIE) {
        if memo_store_ok {
            if let Some(vary) = memo_vary_set(state, &ctx, req, memo_inline, &chain_with_dirs) {
                fast_memo::store(
                    &fast_memo::MemoKey {
                        listener,
                        https: effective_https,
                        trusted_proxy,
                        vhost: &ctx.vhost_name,
                        host_src,
                        host: route_key.as_deref().unwrap_or("").as_bytes(),
                        path: req.uri().path(),
                        query: req.uri().query().unwrap_or(""),
                        ae: req
                            .headers()
                            .get(http::header::ACCEPT_ENCODING)
                            .map(|v| v.as_bytes())
                            .unwrap_or(b""),
                    },
                    vary,
                    &resp,
                    req_start,
                );
                state
                    .metrics
                    .fast_memo_stores
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        } else if memo_eligible_req {
            state
                .metrics
                .fast_memo_ineligible
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    if !state.client_throttle.allow(peer_ip) {
        return None; // over the per-IP rate: dispatch() renders the 429
    }
    stamp_bandwidth(
        &ctx,
        &orig_path,
        state.serve_config.bandwidth_limit,
        &mut resp,
    );
    Some(record_fast_serve(state, &ctx, proto, req, req_start, resp))
}

/// (#349) The vary-set a memo entry for this request must carry: the raw value
/// of every request header the chain's `SetEnvIf`/`RewriteCond` read, and a
/// UA-cond bitmap per User-Agent-reading ruleset (raw `User-Agent` when the
/// ruleset is not classify-eligible or classification is tuned off — the same
/// choice `run_rewrite` makes for its outcome key). `None` refuses the store:
/// an `%{ENV:}` name the rewrite classifier assumed constant-empty is actually
/// seeded on this request (mirrors `run_rewrite`'s `assumed_env_absent`).
fn memo_vary_set(
    state: &ServerState,
    ctx: &ReqCtx,
    req: &Request,
    inline: Option<&Arc<hj_rewrite::RuleSet>>,
    chain: &[(PathBuf, Arc<Htaccess>)],
) -> Option<Vec<fast_memo::VaryItem>> {
    let seeded = |rs: &hj_rewrite::RuleSet| {
        rs.assumed_empty_env
            .iter()
            .any(|name| ctx.get_env(name).is_some())
    };
    if inline.is_some_and(|rs| seeded(rs)) || chain.iter().any(|(_, ht)| seeded(&ht.rules)) {
        return None;
    }
    let mut vary: Vec<fast_memo::VaryItem> = Vec::new();
    let push_header = |vary: &mut Vec<fast_memo::VaryItem>, name: &str| -> bool {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            return false;
        };
        if !vary
            .iter()
            .any(|v| matches!(v, fast_memo::VaryItem::Header { name: n, .. } if *n == name))
        {
            vary.push(fast_memo::vary_header(req, name));
        }
        true
    };
    let push_rules = |vary: &mut Vec<fast_memo::VaryItem>,
                      rs: &hj_rewrite::RuleSet,
                      pin: fast_memo::UaRules|
     -> bool {
        for v in &rs.cache_key_vars {
            let ok = match v {
                hj_rewrite::CacheKeyVar::Origin => push_header(vary, "origin"),
                hj_rewrite::CacheKeyVar::Accept => push_header(vary, "accept"),
                hj_rewrite::CacheKeyVar::UserAgent => {
                    if state.rewrite_ua_classify && rs.ua_classify_eligible() {
                        let bits = state
                            .ua_classify
                            .get_or_compute(rs, &fast_memo::ua_for_classify(req));
                        vary.push(fast_memo::VaryItem::UaClass { rules: pin, bits });
                        return true;
                    }
                    push_header(vary, "user-agent")
                }
            };
            if !ok {
                return false;
            }
        }
        true
    };
    if let Some(rs) = inline
        && !push_rules(&mut vary, rs, fast_memo::UaRules::Inline(rs.clone()))
    {
        return None;
    }
    for (_, ht) in chain {
        for name in &ht.memo.vary_headers {
            if !push_header(&mut vary, name) {
                return None;
            }
        }
        if !push_rules(&mut vary, &ht.rules, fast_memo::UaRules::Chain(ht.clone())) {
            return None;
        }
    }
    Some(vary)
}

/// The request's Cookie header as ONE string for cache classification.
/// (security #267) Every Cookie line is joined with ", " — exactly how PHP/lsphp
/// reassembles multi-line Cookie headers; reading only the first line let a request
/// present as guest to the cache tier while PHP saw the logged-in cookie on a second
/// line (tier desync). (#319) The overwhelmingly common single-line case borrows the
/// header value instead of building a Vec + joined String. (#360) A line carrying a
/// non-ASCII byte is decoded lossily — the same view lsphp gets — never skipped:
/// skipping it presented the request as cookieless (public route, default vary)
/// while PHP still honored its `xf_*` crumbs.
pub(crate) fn cookie_header_joined(headers: &http::HeaderMap) -> Option<String> {
    let mut lines = headers
        .get_all(http::header::COOKIE)
        .iter()
        .map(hj_core::header_value_lossy);
    match (lines.next(), lines.next()) {
        (Some(first), None) => (!first.is_empty()).then(|| first.into_owned()),
        (None, _) => None,
        (Some(first), Some(second)) => {
            let mut joined = String::with_capacity(first.len() + second.len() + 16);
            joined.push_str(&first);
            joined.push_str(", ");
            joined.push_str(&second);
            for line in lines {
                joined.push_str(", ");
                joined.push_str(&line);
            }
            Some(joined)
        }
    }
}

/// dispatch()'s post-rewrite gates (step 4) for the on-core cache-hit branch: the
/// post-rewrite `.htaccess` access decision (now seeing any `[E=]` env), `accessDenyDir`,
/// and the resolved-script re-deny (PATH_INFO / DirectoryIndex, `<Files>` scoped to the
/// file the request MAPS TO). `true` = dispatch() would 403 → the caller bridges so the
/// tokio path renders it instead of a stale hit.
fn fast_post_rewrite_bridges(
    state: &ServerState,
    ctx: &ReqCtx,
    chain: &[Arc<Htaccess>],
    cur_path: &str,
    cur_rel: &str,
    method: &str,
) -> bool {
    if access_denied(chain, cur_rel, method, ctx)
        || access_deny_dir(&state.acl, &ctx.vhost.doc_root, cur_rel)
    {
        return true;
    }
    let index_files = effective_index_files(state, ctx, chain);
    if let Some((script_abs, _, _)) = split_script_path(state, ctx, cur_path, index_files, chain) {
        if allowed_script_target(&state.acl, &script_abs).is_none() {
            return true;
        }
        if let Ok(rel) = script_abs.strip_prefix(&ctx.vhost.doc_root) {
            let script_rel = format!("/{}", rel.to_string_lossy());
            if script_rel != cur_rel
                && (access_denied(chain, &script_rel, method, ctx)
                    || access_deny_dir(&state.acl, &ctx.vhost.doc_root, &script_rel))
            {
                return true;
            }
        }
    }
    false
}

/// Mirror `handle()`'s served-request observability funnel on the on-core fast path so a
/// guest cache HIT / static serve is counted (`requests_total` + telemetry) and
/// access-logged like every other response — they were previously invisible to ops. The
/// callers resolve the real client IP into `ctx.client_ip` (XFF / CF-Connecting-IP for a
/// trusted+mTLS peer) before calling, so the fast path does not log the Cloudflare edge
/// IP for every guest.
fn record_fast_serve(
    state: &Arc<ServerState>,
    ctx: &ReqCtx,
    proto: Proto,
    req: &Request,
    req_start: std::time::Instant,
    mut resp: Response,
) -> Response {
    apply_request_id_header(state, ctx, &mut resp);
    state
        .metrics
        .requests_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let status = resp.status().as_u16();
    state.telemetry.record_request(
        proto,
        status,
        req_start.elapsed(),
        state.telemetry.vhost_idx(&ctx.vhost_name),
    );
    let Some(log) = state.access_logger_for(&ctx.vhost_name) else {
        return resp;
    };
    let vhost_log_headers = state
        .vhost_access_logs
        .get(&ctx.vhost_name)
        .map(|v| v.log_headers)
        .unwrap_or(0);
    // (#349) Common fast-path case (no logHeaders continuation, known body
    // length): render the line on-core from borrowed request data into this
    // thread's chunk — no per-line Strings, no per-line channel send. The
    // chunk path measured ~11% throughput hidden in per-request logging.
    if vhost_log_headers == 0 {
        if let Some(body_bytes) = resp.body().content_length() {
            let referer = req
                .headers()
                .get(http::header::REFERER)
                .and_then(|v| v.to_str().ok());
            let user_agent = req
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok());
            chunk_access_line(log, |buf, format| {
                hj_log::render_access_line_into(
                    buf,
                    format,
                    ctx.client_ip,
                    ctx.request_time,
                    req.method().as_str(),
                    req.uri().path(),
                    req.uri().query(),
                    proto.as_str(),
                    status,
                    body_bytes,
                    referer,
                    user_agent,
                    Some(&ctx.request_id as &dyn std::fmt::Display),
                    ctx.peer_unix,
                );
            });
            return resp;
        }
    }
    // (#283) fast_serve already resolved the real client IP into ctx; re-resolving
    // here repeated the trusted-peer scan (incl. per-XFF-entry CIDR checks) for the
    // log record only.
    let client_ip = ctx.client_ip;
    let log_uri = match req.uri().query() {
        Some(q) => format!("{}?{}", req.uri().path(), q),
        None => req.uri().path().to_string(),
    };
    let record = hj_log::AccessRecord {
        client_ip,
        ts: ctx.request_time,
        method: method_static(req.method()),
        uri: log_uri,
        protocol: proto.as_str(),
        status,
        bytes: 0,
        referer: header_str(req, http::header::REFERER),
        user_agent: header_str(req, http::header::USER_AGENT),
        host: header_str(req, http::header::HOST),
        remote_user: None,
        request_id: Some(ctx.request_id.to_string()),
        peer_unix: ctx.peer_unix,
    };
    // (#248 + #261) LSWS `logHeaders`: a vhost that opts in gets its request headers
    // as a redacted continuation line carried in the SAME channel message as the
    // record (can never mis-align), with credential-class values hashed.
    let headers_extra = (vhost_log_headers != 0).then(|| render_request_headers(req));
    log_access(log, resp, record, headers_extra)
}

/// Request headers whose VALUES are credentials — captured only as a salted-length +
/// short hash so correlation survives but a reader of the log file never sees a live
/// session token (security #261: the vhost log is readable by the same uid PHP runs as).
fn header_value_is_credential(name: &str) -> bool {
    matches!(
        name,
        "cookie" | "authorization" | "proxy-authorization" | "x-wf-capsule"
    )
}

/// (#248) Render the request's headers for the per-vhost `logHeaders` line: one
/// line, CRLF/NUL-escaped (the access file is line-oriented — raw CR/LF would let
/// a client forge extra "records"), capped at 4 KiB. Credential-class values are
/// replaced by `<len>:<sha256[:12]>` (see [`header_value_is_credential`]).
fn render_request_headers(req: &hj_core::Request) -> String {
    use std::fmt::Write as _;
    const CAP: usize = 4 * 1024;
    let mut line = String::with_capacity(256);
    line.push_str("+headers ");
    for (n, v) in req.headers() {
        if line.len() >= CAP {
            break;
        }
        let ok_name = n
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ok_name {
            continue;
        }
        if line.len() + n.as_str().len() + v.len() + 2 > CAP {
            break;
        }
        line.push_str(n.as_str());
        line.push('=');
        if header_value_is_credential(n.as_str()) {
            // <len>:<first 12 hex of sha256> — enough to correlate identical
            // tokens across lines, useless for replay.
            let digest = <sha2::Sha256 as sha2::Digest>::digest(v.as_bytes());
            let mut hex = String::with_capacity(24);
            for b in &digest[..6] {
                let _ = write!(hex, "{b:02x}");
            }
            let _ = write!(line, "{}:{hex}", v.len());
        } else {
            for &b in v.as_bytes() {
                match b {
                    b'\r' => line.push_str("%0D"),
                    b'\n' => line.push_str("%0A"),
                    0..=0x1F | 0x7F => {}
                    _ => line.push(b as char),
                }
            }
        }
        line.push(';');
    }
    line
}

/// Turn a static `Body::File` response into an in-memory `Body::Full` on the calling
/// (monoio) core. Files too large for the static cache, ranged `File` bodies, a cache
/// size-mismatch, or any `Stream` return `None` so the caller bridges them.
/// `Full`/`Empty` pass through.
fn buffer_static_file(
    state: &Arc<ServerState>,
    vhost_id: u32,
    mut resp: Response,
) -> Option<Response> {
    let (path, len, cached) = match resp.body() {
        Body::Full(_) | Body::Empty => return Some(resp),
        Body::File(f) if f.range.is_none() => (f.path.clone(), f.len, f.cached.clone()),
        _ => return None,
    };
    if len > state.static_cache.config().max_static_obj_bytes {
        return None; // larger than the static cache → bridge (streams from disk on tokio)
    }
    if let Some(bytes) = cached {
        if bytes.len() as u64 == len {
            *resp.body_mut() = Body::Full(bytes);
            return Some(resp);
        }
        return None;
    }
    let ct = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let etag = header_value_string(resp.headers(), http::header::ETAG);
    let last_modified = header_value_string(resp.headers(), http::header::LAST_MODIFIED);
    match static_cached_bytes(
        &state.static_cache,
        vhost_id,
        &path,
        len,
        ct,
        etag,
        last_modified,
        StaticReadMode::Direct,
    ) {
        Some(bytes) => {
            *resp.body_mut() = Body::Full(bytes);
            Some(resp)
        }
        None => None,
    }
}

#[allow(clippy::too_many_arguments)]
/// Rewrite a request URI carrying a **trailing empty query** ("/x?") to the query-less form
/// ("/x"), preserving scheme + authority; returns `None` (leave the URI untouched) for a URI
/// with no query or a non-empty query.
///
/// A bare "?" is RFC-3986-equivalent to no query, and the page-cache key already collapses it
/// (`normalize_query` returns "" for an empty query — same as OpenLiteSpeed's `if (len > 0)`
/// cache-key drop in `cache.cpp`). Left intact, a bare "?" reaches the backend, which
/// 301-canonicalizes to the query-less URL; the self-redirect guard then (correctly) refuses
/// to cache that loop and burns a re-render — the bulk of the "backend self-redirect
/// persisted" churn (Amazonbot's bare-"?" thread crawl). Dropping it before dispatch lets the
/// backend render the canonical page (200) directly, so it caches with no redirect.
fn strip_empty_query(uri: &http::Uri) -> Option<http::Uri> {
    if uri.query() != Some("") {
        return None;
    }
    let path = uri.path().to_owned();
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(http::uri::PathAndQuery::try_from(path.as_str()).ok()?);
    http::Uri::from_parts(parts).ok()
}

pub async fn handle(
    state: Arc<ServerState>,
    listener: &str,
    peer_ip: IpAddr,
    local_addr: std::net::SocketAddr,
    peer_port: u16,
    is_tls: bool,
    peer_unix: bool,
    mtls_required: bool,
    tls: Option<hj_core::TlsParams>,
    proto: Proto,
    sni: Option<&str>,
    mut req: Request,
) -> Response {
    // (OPS2) Count this request as in-flight for the duration of handle().
    let _req_guard = RequestGuard::new(&state.metrics.active_requests);
    // (telemetry) Total wall time, recorded at the single response funnel below.
    let req_start = std::time::Instant::now();

    // Normalize a trailing empty query ("/x?" -> "/x") before anything reads the URI. See
    // strip_empty_query for the rationale (it prevents the backend-canonicalization redirect
    // that the self-redirect guard would otherwise burn a re-render on and refuse to cache).
    if let Some(uri) = strip_empty_query(req.uri()) {
        *req.uri_mut() = uri;
    }

    // (OPS3) Cross-node page-cache purge, intercepted on the EXISTING listener
    // (no extra port): a reserved path plus a raw-peer-IP allowlist, checked
    // before vhost routing / the mTLS gate. For all normal traffic this is a
    // single path comparison; anything not from loopback or a configured peer
    // (incl. CF-sourced probes) falls through to normal handling.
    if let Some(pp) = state.peer_purge.as_ref() {
        if let Some(resp) = pp.handle_inbound(&req, peer_ip, &state) {
            return resp;
        }
    }

    // Routing key precedence: the request's own authority is authoritative (RFC 9110 §7.4 /
    // RFC 9113 §8.3.1) — the Host header first, then the URI authority (h2/h3 `:authority`,
    // which hj-h2/h3 already surface as a Host header), with the TLS SNI only as a fallback
    // for a request that carries no host at all. For CF-fronted traffic SNI and Host are
    // identical; this just makes Host authoritative for routing, as HTTP requires (and stops
    // an SNI/Host mismatch from resolving the wrong vhost).
    let route_key: Option<String> = req
        .headers()
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .or_else(|| req.uri().authority().map(|a| a.host().to_string()))
        .or_else(|| sni.map(|s| s.to_string()));

    let resolved = match state.router.resolve(listener, route_key.as_deref()) {
        Some(r) => r,
        None => {
            // A host that resolves to a real vhost whose per-vhost config file failed to load is an
            // operator misconfiguration, not a missing host — surface a loud 503 (not a silent 404
            // that's easy to misattribute to "no such host"). check --strict + the SIGHUP guard
            // should keep this from ever reaching prod, but if it does it must be diagnosable.
            if state
                .router
                .host_known_but_unloaded(listener, route_key.as_deref())
            {
                tracing::error!(
                    host = route_key.as_deref().unwrap_or("<none>"),
                    listener,
                    "vhost is mapped but its config file did not load — serving 503 (misconfigured), not 404"
                );
                return error_page(StatusCode::SERVICE_UNAVAILABLE);
            }
            return error_page(StatusCode::NOT_FOUND);
        }
    };

    // ---- mTLS trust-boundary enforcement (#2) ----------------------------
    // The production origin only trusts traffic that arrived through Cloudflare,
    // which presents a client cert to the `clientVerify>=2` :443 listener
    // (fail-closed at the TLS handshake). The SAME vhosts are also mapped on the
    // plain :80 listener, where no client cert is presented and `is_tls=false`.
    // Without a gate here, a direct connection to the origin's port 80 would reach
    // the DB-backed PHP apps / proxy backends with the mTLS check simply never on
    // the code path. So: if this request is NOT on TLS and its resolved vhost is
    // one that a secure listener requires a client cert for, force it to HTTPS
    // BEFORE the rewrite engine / access checks / handlers run (so the
    // unauthenticated backend is never touched).
    //
    // Exemptions (peers already inside the trust boundary, mirroring the :443
    // app-layer client-cert exemption in `hj-tls`): loopback / private-LAN peers
    // (`is_trusted_internal_peer`) reach plaintext :80 directly — on-box and
    // internal callers (health checks, the peer node, services that hit the vhost
    // over `/etc/hosts`→127.0.0.1) must not be bounced to HTTPS. The other
    // plaintext exception is the ACME http-01 challenge (handled in
    // `mtls_https_redirect_target`), which must stay reachable for cert issuance.
    // Effective request scheme. The CDN→origin hop may be cleartext (`:80`) while the
    // real client is on HTTPS — honor the proxy's `X-Forwarded-Proto`/`CF-Visitor`, but
    // ONLY when `peer_ip` is a trusted proxy, so an untrusted `:80` client cannot spoof
    // `https` to slip past the mTLS gate below (or be treated as secure by the backend).
    // `tls.is_some()` stays the test for a *physical* TLS handshake (client cert / SSL_*
    // env / Alt-Svc). With the current CF→origin-over-HTTPS topology this is identical to
    // `is_tls` for live traffic; it only engages if CF is switched to "Flexible" SSL.
    let trusted_proxy = state.acl.is_trusted(peer_ip);
    let effective_https = effective_request_https(is_tls, trusted_proxy, req.headers());

    if mtls_gate_redirects(
        effective_https,
        state.mtls_required_vhosts.contains(&resolved.name),
        peer_ip,
    ) {
        let host = route_key
            .as_deref()
            .map(hj_core::host_without_port)
            .unwrap_or_else(|| resolved.name.clone());
        if let Some(target) = mtls_https_redirect_target(&host, req.uri().path(), req.uri().query())
        {
            // (#13) Route the mTLS 301 through the common funnel instead of a bare
            // early return: a cleartext proxy / ISP transparent cache between the
            // client and origin could otherwise cache this HTTP→HTTPS 301 (it carries
            // no Cache-Control), and :80 probe traffic would be invisible. Apply
            // deny_redirect_cdn_caching (private, no-store), count it in requests_total,
            // and access-log it. client_ip is unresolved here (the request is bounced
            // before trust resolution), so log peer_ip — the literal source of the
            // probe, which is what an operator wants to see for these.
            let mut resp = redirect(301, &target);
            deny_redirect_cdn_caching(&mut resp);
            state
                .metrics
                .requests_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(log) = &state.access_log {
                let log_uri = match req.uri().query() {
                    Some(q) => format!("{}?{}", req.uri().path(), q),
                    None => req.uri().path().to_string(),
                };
                let record = hj_log::AccessRecord {
                    client_ip: peer_ip,
                    ts: std::time::SystemTime::now(),
                    method: method_static(req.method()),
                    uri: log_uri,
                    protocol: proto.as_str(),
                    status: resp.status().as_u16(),
                    bytes: 0, // filled with the REAL bytes by log_access
                    referer: header_str(&req, http::header::REFERER),
                    user_agent: header_str(&req, http::header::USER_AGENT),
                    host: header_str(&req, http::header::HOST),
                    remote_user: None,
                    // No `ctx` yet (bounced before trust resolution): mint a fresh id so
                    // even a :80 mTLS-bounce probe is joinable across the logs.
                    request_id: Some(hj_core::reqid::next().to_string()),
                    peer_unix: false,
                };
                resp = log_access(log, resp, record, None);
            }
            // Mirror the main response funnel (see below): record this 301 in the
            // per-protocol/status/latency telemetry too, not just `requests_total`
            // — otherwise the :80 mTLS-bounce probes are invisible to the metrics
            // endpoint despite being counted and access-logged.
            state.telemetry.record_request(
                proto,
                resp.status().as_u16(),
                req_start.elapsed(),
                state.telemetry.vhost_idx(&resolved.name),
            );
            return resp;
        }
    }

    // ---- Access control + trusted-proxy client IP ------------------------
    // (#16, corrected) Whether to treat this connection as mTLS-trusted for honoring forwarded
    // client-IP headers (resolve_client_ip mode 2 honors them only when is_trusted(peer) && mtls_ok).
    // When the listener REQUESTS client certs (`clientVerify >= 1`), require an actually-PRESENTED
    // cert: a cert-less internal/loopback TLS peer must not be trusted should a private-LAN CIDR ever
    // join trusted_nets. When the listener requests NO client cert (`--no-mtls` / `clientVerify=0`,
    // now reserved for local testing or an explicit operator rollback), trust is established by the
    // network boundary, so any completed TLS connection counts (the pre-#16 behavior).
    // Requiring a cert UNCONDITIONALLY made mtls_ok false for 100% of --no-mtls traffic, silently
    // disabling CF-Connecting-IP real-IP resolution (every visitor resolved to the CF edge IP).
    let mtls_ok = if mtls_required {
        tls.as_ref()
            .map(|t| t.client_cert.is_some())
            .unwrap_or(false)
    } else {
        is_tls
    };
    let client_ip = state.acl.resolve_client_ip(
        peer_ip,
        req.headers(),
        state.server.use_ip_in_proxy_header,
        mtls_ok,
    );

    // Capture log fields before the request body is consumed downstream.
    let log_method = method_static(req.method());
    let log_uri = match req.uri().query() {
        Some(q) => format!("{}?{}", req.uri().path(), q),
        None => req.uri().path().to_string(),
    };
    let referer = header_str(&req, http::header::REFERER);
    let user_agent = header_str(&req, http::header::USER_AGENT);
    let host_hdr = header_str(&req, http::header::HOST);

    let mut ctx = ReqCtx {
        server: state.server.clone(),
        vhost_name: resolved.name,
        vhost: resolved.config,
        peer_ip,
        client_ip,
        is_tls: effective_https,
        peer_unix,
        protocol: proto,
        trusted_proxy,
        // Pre-size past the first growth doublings: the PHP path pushes ~8-24 entries
        // (HTTPS seed + SetEnvIf + SCRIPT_NAME/QUERY_STRING/REDIRECT_URL + [E=] sets).
        env: Vec::with_capacity(8),
        local_addr,
        peer_port,
        tls,
        request_time: std::time::SystemTime::now(),
        request_id: hj_core::reqid::next(),
        redirect_guard: None,
    };

    // A Host is FOREIGN to its resolved vhost when it reached the vhost only via the `*`
    // wildcard or an iterative subdomain fallback (not an exact `<vhostMap>` domain) and is
    // not the vhost's own canonical name — e.g. an unconfigured `www.publisher.example` landing
    // on the `forum.example` default. Such a host must never serve, populate, or let
    // Cloudflare edge-cache the vhost's content. Computed once here (independent of
    // `--page-cache`): it gates BOTH the page-cache bypass (passed to `dispatch`) and the
    // CF de-cache below. Uses the SAME `request_host` the cache keys by, so the two agree.
    // Computed ONCE here (B4) and moved into `dispatch`, which reuses it as `cache_host` instead
    // of recomputing the identical value — the comment below already requires the two to agree.
    let req_host = lscache::request_host(&req, &ctx);
    let host_foreign = !req_host.eq_ignore_ascii_case(&ctx.vhost_name)
        && !state.router.host_is_exact(listener, &req_host);

    // (Tier 2) Captured only when a context declares a bandwidthLimit — the per-request
    // path allocation stays off the hot path otherwise (the connection-wide tuning rate
    // needs no stamp; the transport already carries it).
    let bw_path = (has_bandwidth_context(&ctx.vhost) || sub_filter_matches(&ctx, req.uri().path()))
        .then(|| req.uri().path().to_owned());

    let mut resp = if !state.acl.check_peer(peer_ip).is_allowed() {
        error_page(StatusCode::FORBIDDEN)
    } else if !state.client_throttle.allow(peer_ip) {
        error_page(StatusCode::TOO_MANY_REQUESTS)
    } else if !state.geo.allows(client_ip) {
        // (Tier 2) GeoIP/ASN ACL: judged by the resolved client IP, so a
        // CF-fronted visitor is evaluated by their real address.
        error_page(StatusCode::FORBIDDEN)
    } else {
        // Expose Accept-Encoding to the compression transform (which only sees ctx).
        if let Some(ae) = req
            .headers()
            .get(http::header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
        {
            ctx.set_env("HTTP_ACCEPT_ENCODING", ae.to_string());
        }
        set_redirect_guard(&mut ctx, req.uri(), &req_host);
        dispatch(&state, host_foreign, req_host, &mut ctx, req).await
    };

    if let Some(p) = &bw_path {
        stamp_bandwidth(&ctx, p, state.serve_config.bandwidth_limit, &mut resp);
        stamp_sub_filter(&ctx, p, &mut resp);
    }

    // ---- Response-transform pipeline (the post-handler stage) --------------
    // Runs ServerState::transforms in order: cache-small-static (so gzip can compress it)
    // -> expires -> compress -> deny-CDN-cache-on-redirects (the "Too Many Redirects" loop
    // class, on the single funnel so it covers backend AND page-cache 301s) -> advertise-h3
    // on TLS. A new transform plugs into the Vec without editing handle(). The requests_total
    // counter + access log below stay OUTSIDE the loop (they are not response transforms).
    let _ct = state
        .telemetry
        .sample_phase(crate::telemetry::PHASE_SAMPLE_RATE)
        .then(std::time::Instant::now);
    for t in &state.transforms {
        t.transform(&ctx, &mut resp).await;
    }
    if let Some(t) = _ct {
        state.telemetry.shard().phase_compress.record(t.elapsed());
    }

    // A foreign Host must never get an edge-cacheable response: Cloudflare caches per
    // hostname, so a `public`/`s-maxage` body under a non-canonical host gets stored under
    // that brand's zone (the foreign-host regression, which the page-cache bypass alone does
    // NOT stop — the origin still SENDS the response). Runs AFTER the transform loop so a
    // foreign-host static asset can't keep the `public` header `apply_expires` added, and
    // covers EVERY status (the existing redirect-decache only covers 3xx). Inert for
    // canonical hosts. Independent of `--page-cache`.
    if host_foreign {
        deny_foreign_host_cdn_caching(&mut resp);
    }
    apply_request_id_header(&state, &ctx, &mut resp);

    // (OPS1) Count every served request here — the single response funnel — so the
    // counter is independent of whether access logging is enabled.
    state
        .metrics
        .requests_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // (telemetry) Total wall time + protocol + status class, on the single funnel.
    state.telemetry.record_request(
        proto,
        resp.status().as_u16(),
        req_start.elapsed(),
        state.telemetry.vhost_idx(&ctx.vhost_name),
    );

    // ---- Access log ------------------------------------------------------
    // (#248) A vhost declaring its own `<logging><accessLog>` records there;
    // everyone else rides the unified log.
    if let Some(log) = state.access_logger_for(&ctx.vhost_name) {
        // (#248) Mirror 5xx responses into the vhost's own error file when it
        // declares one — the closest per-vhost analogue of LSWS's error log
        // (httpjet has no per-vhost stderr stream to route). Built before the
        // record consumes `log_uri`.
        let err_line = match (
            resp.status().is_server_error(),
            state.vhost_error_logger(&ctx.vhost_name),
        ) {
            (true, Some(errlog)) => Some((
                errlog,
                format!(
                    "[{}] error status={} uri={} request_id={}",
                    hj_log::clf_time(ctx.request_time),
                    resp.status().as_u16(),
                    log_uri,
                    ctx.request_id
                ),
            )),
            _ => None,
        };
        let record = hj_log::AccessRecord {
            client_ip,
            // CLF `%t` is the time the request was RECEIVED — reuse the arrival stamp
            // (also one fewer clock read per request than re-reading at log time).
            ts: ctx.request_time,
            method: log_method,
            uri: log_uri,
            protocol: proto.as_str(),
            status: resp.status().as_u16(),
            bytes: 0, // filled with the REAL bytes by log_access (see below)
            referer,
            user_agent,
            host: host_hdr,
            remote_user: None,
            request_id: Some(ctx.request_id.to_string()),
            peer_unix: ctx.peer_unix,
        };
        // (#248) Mirror 5xx responses into the vhost's own error file when it
        // declares one.
        if let Some((errlog, line)) = err_line {
            errlog.log_line(line);
        }
        resp = log_access(log, resp, record, None);
    }

    resp
}

/// Emit an access-log record with the correct bytes-sent figure (Apache `%B`/`%O`
/// semantics — bytes actually written, not the declared `Content-Length`).
///
/// A known-length body (`Full`/`File`/`Empty` — cache hits, static files,
/// redirects, error pages) is logged immediately from its content length. A
/// streamed body (`Body::Stream` — LSAPI/PHP output and proxy pass-through) carries
/// no `Content-Length`, so reading the header logged `0` even though bytes flow;
/// instead we wrap it to tally the bytes written at the wire and emit the line when
/// the stream ends or is dropped (a client disconnect logs the partial count). The
/// trade-off is that a streamed response is logged at completion rather than at
/// header time — which is how Apache/LiteSpeed already behave. Returns the response
/// (body rewrapped in the streaming case).
const ACCESS_CHUNK_FLUSH_BYTES: usize = 16 * 1024;
const ACCESS_CHUNK_MAX_AGE: std::time::Duration = std::time::Duration::from_millis(250);

struct PendingChunk {
    logger: Arc<hj_log::AccessLogger>,
    buf: Vec<u8>,
    lines: u32,
    first: std::time::Instant,
}

thread_local! {
    /// (#349) Per-serving-thread access-line chunks, keyed by logger identity.
    /// Fast-path serves render their line on-core (borrowed data, no Strings)
    /// and ship one channel message per chunk instead of one per line. Flushed
    /// by size/age here and by the per-worker ticker in `uring`.
    static ACCESS_CHUNKS: std::cell::RefCell<rustc_hash::FxHashMap<usize, PendingChunk>> =
        std::cell::RefCell::new(rustc_hash::FxHashMap::default());
}

fn chunk_access_line(
    log: &Arc<hj_log::AccessLogger>,
    render: impl FnOnce(&mut Vec<u8>, hj_log::LogFormat),
) {
    let key = Arc::as_ptr(log) as usize;
    ACCESS_CHUNKS.with(|chunks| {
        let mut chunks = chunks.borrow_mut();
        let entry = chunks.entry(key).or_insert_with(|| PendingChunk {
            logger: log.clone(),
            buf: Vec::with_capacity(ACCESS_CHUNK_FLUSH_BYTES + 512),
            lines: 0,
            first: std::time::Instant::now(),
        });
        if entry.lines == 0 {
            entry.first = std::time::Instant::now();
        }
        render(&mut entry.buf, log.format());
        entry.lines += 1;
        if entry.buf.len() >= ACCESS_CHUNK_FLUSH_BYTES
            || entry.first.elapsed() >= ACCESS_CHUNK_MAX_AGE
        {
            let buf = std::mem::take(&mut entry.buf);
            let lines = std::mem::replace(&mut entry.lines, 0);
            entry.logger.log_chunk(buf, lines);
        }
    });
}

/// (#349) Flush this thread's pending access-line chunks (per-worker ticker +
/// worker drain call this; size/age flushes happen inline on append).
pub(crate) fn flush_access_chunks() {
    ACCESS_CHUNKS.with(|chunks| {
        let mut chunks = chunks.borrow_mut();
        for entry in chunks.values_mut() {
            if entry.lines > 0 {
                let buf = std::mem::take(&mut entry.buf);
                let lines = std::mem::replace(&mut entry.lines, 0);
                entry.logger.log_chunk(buf, lines);
            }
        }
    });
}

fn log_access(
    log: &Arc<hj_log::AccessLogger>,
    resp: Response,
    mut record: hj_log::AccessRecord,
    extra: Option<String>,
) -> Response {
    if let Some(len) = resp.body().content_length() {
        record.bytes = len;
        log.log_with_extra(record, extra);
        return resp;
    }
    let log = log.clone();
    let (parts, body) = resp.into_parts();
    let body = match body {
        Body::Stream(inner) => hj_core::CountingBody::wrap(inner, move |n| {
            record.bytes = n;
            // `extra` moves with the record: the +headers continuation stays glued to
            // its line even when logging is deferred to stream end.
            log.log_with_extra(record, extra);
        }),
        // content_length() is None only for Body::Stream; this arm can't run today
        // but keeps a future Body variant from silently logging a wrong size.
        other => {
            log.log_with_extra(record, extra);
            other
        }
    };
    Response::from_parts(parts, body)
}

/// Dispatch a resolved request: rewrite → websocket → proxy context → suffix.
/// How long a single-flight follower waits for the leader to fill the cache before giving
/// up and rendering itself. The leader wakes followers the instant it stores (typically far
/// sooner), so this only bounds the degenerate case of a leader that hangs or produces an
/// uncacheable response — generous so a legitimately slow render never trips it early.
const SINGLEFLIGHT_WAIT: Duration = Duration::from_secs(10);

/// Request-extension marker set on a stale-while-revalidate background refresh, so the
/// re-entered [`dispatch`] forces a cache MISS (renders + stores) instead of re-serving the
/// stale entry that triggered it.
#[derive(Clone, Copy)]
struct RefreshMode;

/// (Tier 2) Response-extension carrying the per-connection egress rate (bytes/sec) the
/// transport should pace this response with — set when the matched `<context>` declares a
/// `bandwidthLimit`. Absent ⇒ the transport's connection-wide default applies.
#[derive(Clone, Copy)]
pub(crate) struct PerConnBandwidth(pub u64);

/// (Tier 2) Response extension carrying the resolved sub_filter plan — set when
/// the matched `<context>` declares rules, read by [`SubFilterTransform`]. The
/// plan is resolved against the ORIGINAL request path (same deliberate
/// deviation the page cache documents: contexts are matched pre-rewrite).
#[derive(Clone)]
pub(crate) struct SubFilterPlan(pub Arc<hj_core::config::SubFilterConfig>);

/// The innermost (longest matching URI prefix) enabled context that declares
/// active sub_filter rules for `path`.
fn resolve_sub_filter<'a>(
    ctx: &'a ReqCtx,
    path: &str,
) -> Option<&'a hj_core::config::SubFilterConfig> {
    ctx.vhost
        .contexts
        .iter()
        .filter(|c| {
            c.enabled
                && c.sub_filter.as_ref().is_some_and(|s| s.is_active())
                && context_uri_matches(path, &c.uri)
        })
        .max_by_key(|c| c.uri.len())
        .and_then(|c| c.sub_filter.as_deref())
}

/// Stamp the sub_filter plan onto a terminal response (mirror of
/// [`stamp_bandwidth`]); skipped when no context declares rules.
fn stamp_sub_filter(ctx: &ReqCtx, path: &str, resp: &mut Response) {
    if let Some(cfg) = resolve_sub_filter(ctx, path) {
        resp.extensions_mut()
            .insert(SubFilterPlan(Arc::new(cfg.clone())));
    }
}

/// Does ANY enabled context with active sub_filter rules match this path?
/// Gates the fast-memo store and the page cache: the memo stores POST-transform
/// bytes that a memo hit would re-filter (non-idempotent when a replacement
/// contains its search string), and the page-cache hot path must not serve
/// entries the transform vec would have to filter inconsistently.
fn sub_filter_matches(ctx: &ReqCtx, path: &str) -> bool {
    ctx.vhost.contexts.iter().any(|c| {
        c.enabled
            && c.sub_filter.as_ref().is_some_and(|s| s.is_active())
            && context_uri_matches(path, &c.uri)
    })
}

/// (Tier 2) Literal search/replace over an eligible response body. Runs between
/// expires and compress so the filtered body is compressed by the ordinary
/// transform, and every serve funnel re-applies it to unfiltered bytes.
pub(crate) struct SubFilterTransform;

impl SubFilterTransform {
    /// 200 only; never filter already-encoded bytes; Content-Type must match.
    fn eligible(plan: &hj_core::config::SubFilterConfig, resp: &Response) -> bool {
        resp.status() == StatusCode::OK
            && !resp.headers().contains_key(CONTENT_ENCODING)
            && resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| plan.matches_type(ct))
    }
}

#[async_trait]
impl hj_core::ResponseTransform for SubFilterTransform {
    async fn transform(&self, _ctx: &ReqCtx, resp: &mut Response) {
        let Some(plan) = resp.extensions().get::<SubFilterPlan>().cloned() else {
            return;
        };
        let plan = plan.0;
        if !Self::eligible(&plan, resp) {
            return;
        }
        let body = std::mem::replace(resp.body_mut(), Body::Empty);
        match body {
            Body::Full(bytes) => {
                let filtered = apply_sub_filter(&plan, bytes);
                finalize_filtered(resp, &plan, filtered.len());
                *resp.body_mut() = Body::Full(filtered);
            }
            Body::File(f) if f.range.is_none() && f.len <= plan.max_body => {
                // Small files are already promoted to Full by CacheStaticTransform;
                // this File is uncached but small enough to buffer.
                match std::fs::read(&f.path) {
                    Ok(bytes) => {
                        let filtered = apply_sub_filter(&plan, bytes.into());
                        finalize_filtered(resp, &plan, filtered.len());
                        *resp.body_mut() = Body::Full(filtered);
                    }
                    Err(_) => *resp.body_mut() = Body::File(f),
                }
            }
            Body::Stream(mut s) => {
                // Buffer with a cap: a stream that completes within it is filtered;
                // one that overflows passes through RAW (prefix + remainder chained)
                // — never a half-filtered entity.
                use http_body_util::BodyExt;
                let mut buf = bytes::BytesMut::new();
                let mut overflow = false;
                loop {
                    match s.frame().await {
                        Some(Ok(frame)) => {
                            if let Some(d) = frame.data_ref() {
                                buf.extend_from_slice(d);
                                if buf.len() as u64 > plan.max_body {
                                    overflow = true;
                                    break;
                                }
                            }
                        }
                        Some(Err(_)) | None => break,
                    }
                }
                if overflow {
                    use http_body_util::BodyExt;
                    *resp.body_mut() = Body::Stream(
                        PrefixBody {
                            prefix: Some(buf.freeze()),
                            inner: s,
                        }
                        .boxed(),
                    );
                } else {
                    let filtered = apply_sub_filter(&plan, buf.freeze());
                    finalize_filtered(resp, &plan, filtered.len());
                    *resp.body_mut() = Body::Full(filtered);
                }
            }
            other => *resp.body_mut() = other,
        }
    }
}

/// A body that yields one buffered prefix frame before forwarding the inner
/// stream — the raw-passthrough path when a stream overflows the sub_filter
/// buffering cap (the entity must pass through whole, never half-filtered).
struct PrefixBody {
    prefix: Option<bytes::Bytes>,
    inner: hj_core::StreamBody,
}

impl http_body::Body for PrefixBody {
    type Data = bytes::Bytes;
    type Error = hj_core::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(chunk) = self.prefix.take() {
            return std::task::Poll::Ready(Some(Ok(http_body::Frame::data(chunk))));
        }
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        // The prefix is known; the inner stream is not — lower bound only.
        let mut hint = http_body::SizeHint::default();
        hint.set_lower(self.prefix.as_ref().map_or(0, |b| b.len() as u64));
        hint
    }
}

/// Apply the rules in order (all occurrences, or the first only under `once`).
fn apply_sub_filter(plan: &hj_core::config::SubFilterConfig, body: bytes::Bytes) -> bytes::Bytes {
    if plan.rules.is_empty() {
        return body;
    }
    let mut text = String::from_utf8_lossy(&body).into_owned();
    for (search, replace) in &plan.rules {
        if search.is_empty() {
            continue;
        }
        if plan.once {
            if let Some(pos) = text.find(search.as_str()) {
                text.replace_range(pos..pos + search.len(), replace);
            }
        } else {
            text = text.replace(search.as_str(), replace);
        }
    }
    text.into_bytes().into()
}

/// Recompute Content-Length and drop the entity validators: the bytes changed,
/// so the strong ETag is wrong by construction, and Last-Modified defaults off
/// (nginx sub_filter_last_modified).
fn finalize_filtered(resp: &mut Response, plan: &hj_core::config::SubFilterConfig, len: usize) {
    let h = resp.headers_mut();
    h.remove(CONTENT_LENGTH);
    h.remove(ETAG);
    if !plan.keep_last_modified {
        h.remove(LAST_MODIFIED);
    }
    if let Ok(v) = http::HeaderValue::from_str(&len.to_string()) {
        h.insert(CONTENT_LENGTH, v);
    }
}

enum RefreshCookie {
    Preserve,
    Replace(Option<HeaderValue>),
}

fn build_revalidation_request(req: &Request, cookie: RefreshCookie) -> Request {
    let mut sub: Request = Request::new(hj_core::empty_incoming());
    *sub.method_mut() = http::Method::GET;
    *sub.uri_mut() = req.uri().clone();
    *sub.version_mut() = req.version();
    *sub.headers_mut() = req.headers().clone();
    for name in [
        http::header::IF_MATCH,
        http::header::IF_NONE_MATCH,
        http::header::IF_MODIFIED_SINCE,
        http::header::IF_UNMODIFIED_SINCE,
        http::header::IF_RANGE,
        http::header::RANGE,
        http::header::CONTENT_LENGTH,
        http::header::TRANSFER_ENCODING,
        http::header::EXPECT,
    ] {
        sub.headers_mut().remove(name);
    }
    if let RefreshCookie::Replace(cookie) = cookie {
        sub.headers_mut().remove(COOKIE);
        if let Some(cookie) = cookie {
            sub.headers_mut().insert(COOKIE, cookie);
        }
    }
    sub.extensions_mut().insert(RefreshMode);
    sub
}

/// Stale-while-revalidate: kick off (at most) ONE detached background re-render for `key_hash`,
/// so the client that received the stale body never waits and the next request lands on a
/// fresh entry. Reuses the FULL [`dispatch`] path (identical rewrite → classify → key → store
/// + every correctness guard) by re-issuing the request internally with a [`RefreshMode`]
/// marker; the rendered response is discarded — only the `cache_store` side effect matters.
///
/// Safe by construction: the [`RefreshRegistry`](crate::lscache::RefreshRegistry) CAS makes it
/// idempotent per key (no refresh-storms, no refresh-spawns-refresh loop) and globally caps
/// concurrent refreshes; if the slot/permit can't be taken the refresh is simply skipped and
/// the stale entry is retried on the next hit. Only cacheable GET/HEAD reach a stale hit.

/// (Tier 2) Find the tightest per-context body limit matching `path`, or the
/// server-wide default. A `<context>` with `<maxReqBodySize>` overrides the
/// server limit for requests under its URI prefix.
fn effective_max_body(ctx: &ReqCtx, path: &str, server_default: u64) -> u64 {
    let mut best = server_default;
    for c in &ctx.vhost.contexts {
        if !c.enabled || c.max_body_override.is_none() {
            continue;
        }
        if context_uri_matches(path, &c.uri) {
            let v = c.max_body_override.unwrap();
            if v < best {
                best = v;
            }
        }
    }
    best
}

/// (Tier 2) The strictest `bandwidthLimit` among the matching contexts that declare one;
/// the server-wide `<tuning>` rate when none matches. A declared context rate is an
/// OVERRIDE (it may raise as well as lower) — an operator scoping a limit to a subtree
/// is not served by a min-against-server-default rule that can never raise.
fn effective_bandwidth(ctx: &ReqCtx, path: &str, server_default: u64) -> u64 {
    let mut best: Option<u64> = None;
    for c in &ctx.vhost.contexts {
        if !c.enabled || c.bandwidth_limit == 0 {
            continue;
        }
        if context_uri_matches(path, &c.uri) {
            best = Some(best.map_or(c.bandwidth_limit, |b| b.min(c.bandwidth_limit)));
        }
    }
    best.unwrap_or(server_default)
}

/// Any enabled context on this vhost declares a `bandwidthLimit` (the cheap pre-check
/// that keeps the per-request path capture off the hot path when none does).
fn has_bandwidth_context(vhost: &hj_core::config::VHostConfig) -> bool {
    vhost
        .contexts
        .iter()
        .any(|c| c.enabled && c.bandwidth_limit > 0)
}

/// Stamp the transport-facing egress rate onto a terminal response. Skipped entirely when
/// no context declares a rate — the connection-wide tuning default then applies.
fn stamp_bandwidth(ctx: &ReqCtx, path: &str, server_default: u64, resp: &mut Response) {
    if !has_bandwidth_context(&ctx.vhost) {
        return;
    }
    let rate = effective_bandwidth(ctx, path, server_default);
    if rate > 0 {
        resp.extensions_mut().insert(PerConnBandwidth(rate));
    }
}

fn spawn_revalidate(
    state: &Arc<ServerState>,
    host_foreign: bool,
    ctx: &ReqCtx,
    req: &Request,
    key_hash: u64,
) {
    let Some(guard) = state.page_cache_refresh.try_begin(key_hash) else {
        return; // already refreshing this key, or the global concurrency cap is saturated
    };
    // Preserve the inputs that feed vary/identity, but force a full unconditional render.
    // Replaying HEAD or validators can only produce an unstorable HEAD/304 response.
    let sub = build_revalidation_request(req, RefreshCookie::Preserve);
    let state = state.clone();
    let mut ctx = ctx.clone();
    // Re-run rewrite from a clean slate: the captured ctx already holds the triggering
    // request's post-rewrite env, and dispatch re-runs rewrite — clear it so env isn't
    // double-applied (a fresh request starts with no rewrite env).
    ctx.env.clear();
    tokio::spawn(async move {
        let _guard = guard; // frees the per-key slot + the global permit on completion
        // `sub` carries the original request's host header, so this equals the triggering
        // request's host; recomputed here (off the hot path — revalidation only).
        let sub_host = lscache::request_host(&sub, &ctx);
        let _ = dispatch(&state, host_foreign, sub_host, &mut ctx, sub).await;
    });
}

fn spawn_capsule_revalidate(
    state: &Arc<ServerState>,
    host_foreign: bool,
    ctx: &ReqCtx,
    req: &Request,
    key_hash: u64,
) {
    let Some(guard) = state.page_cache_refresh.try_begin(key_hash) else {
        return;
    };
    let public_cookie: Option<HeaderValue> = state.page_cache.as_ref().and_then(|store| {
        let raw = req.headers().get(COOKIE).and_then(|v| v.to_str().ok());
        lscache::capsule_public_refresh_cookie(raw, store)
    });
    let sub = build_revalidation_request(req, RefreshCookie::Replace(public_cookie));
    let state = state.clone();
    let mut ctx = ctx.clone();
    ctx.env.clear();
    tokio::spawn(async move {
        let _guard = guard;
        let sub_host = lscache::request_host(&sub, &ctx);
        let _ = dispatch(&state, host_foreign, sub_host, &mut ctx, sub).await;
    });
}

async fn dispatch(
    state: &Arc<ServerState>,
    host_foreign: bool,
    req_host: String,
    ctx: &mut ReqCtx,
    mut req: Request,
) -> Response {
    // (SEC1) Enforce LiteSpeed `maxReqURLLen` (default 8192): reject an over-long
    // request-target (path + `?query`) with 414 before doing any work. The header
    // size limit is enforced at the transport layer (hyper `max_buf_size` /
    // `max_header_list_size`); this guards the URL the rewrite/stat path handles.
    let target_len = req.uri().path().len() + req.uri().query().map_or(0, |q| q.len() + 1);
    if target_len > state.serve_config.max_req_url_len {
        return error_page(StatusCode::URI_TOO_LONG);
    }

    // (#1 security) Hyper does NOT percent-decode the URI path, but the terminal
    // handlers (static via `clean_request_path`, LSAPI/script resolution) decode
    // it before touching the filesystem. If access control / header scoping ran
    // on the raw, still-encoded request-target while the handler opened the
    // DECODED file, a denied file could be reached via `%72`/`%2E`/`%2F` tricks.
    // Decode once, up front, so every consumer — the rewrite engine (whose `uri`
    // contract is "percent-decoded"), the access check, header/error scoping, and
    // the filesystem handlers — sees the exact same canonical path. A path that
    // cannot be decoded (bad escape), contains a NUL, or is not valid UTF-8 is
    // rejected outright (400), matching `clean_request_path`'s fail-closed stance.
    // `req.uri().path()` is already `&str` and `decode_request_path` returns an owned String, so
    // pass it directly — no intermediate `raw_path` allocation (the borrow ends at the call).
    let decoded_path = match decode_request_path(req.uri().path()) {
        Some(p) => p,
        None => return error_page(StatusCode::BAD_REQUEST),
    };
    // (M1 security) Canonicalize the decoded path *before* anything consumes it:
    // collapse `.`/`..`/empty segments while keeping the leading `/`. Apache
    // normalizes `..` up front, so a missing intermediate directory cannot be
    // used to defeat a per-directory deny. Previously `orig_path` still carried
    // raw `..` segments, so `load_chain_with_dirs` joined them literally — a
    // request like `/zz/../internal_data/config.php` (with `zz` absent) made the
    // chain loader stat `<docroot>/zz/../internal_data/.htaccess`, which ENOENTs
    // on the missing `zz` and silently SKIPS the protected `internal_data` deny,
    // even though the access check (which uses `resolved_rel_path`) DID collapse
    // to `/internal_data/config.php`. Collapsing here makes the chain load, the
    // rewrite engine, and the access check all operate on the same canonical
    // path. The front controller / existing rewrites already saw a leading-`/`
    // path, and a no-`.`/`..` path is unchanged by the collapse, so they are
    // unaffected.
    //
    // CRITICAL: preserve a TRAILING slash. `resolved_rel_path` collapses *every*
    // empty segment, including the one a trailing `/` produces, so it would turn
    // `/community/` into `/community`. That slash is load-bearing for directory
    // routing: `resolve_script`'s dir-index fallback gates on
    // `path.ends_with('/')`, so stripping it makes a request to a real
    // subdirectory whose only index is `index.php` resolve to `None` at the
    // LSAPI stage and fall through to the STATIC handler — which reads the
    // un-collapsed `req.uri()` (still `/community/`), resolves the directory, and
    // serves `community/index.php` as raw source (PHP source disclosure, the bug
    // class commit 0960ce0 fixed). Use the slash-preserving normalizer so the
    // canonical path the rewrite engine + dir-index routing see still ends in `/`
    // exactly as `req.uri()` does, while the access/header scoping helpers
    // continue to call `resolved_rel_path` (slash irrelevant there).
    let orig_path = normalized_request_path(&decoded_path);
    let orig_query = req.uri().query().unwrap_or("").to_string();
    // Borrow the original path/query; only the `Rewritten` arm below promotes them to Owned, so
    // the common unchanged case (e.g. a static `.bin` whose rewrite is a no-op) clones neither.
    let mut cur_path: Cow<str> = Cow::Borrowed(&orig_path);
    let mut cur_query: Cow<str> = Cow::Borrowed(&orig_query);
    let mut rewritten = false;

    // ---- 1. .htaccess chain (gated by allowOverride / autoLoadHtaccess) ----
    // (#10) Load the per-directory access-file chain when the vhost enables
    // `.htaccess` via EITHER signal: `<htAccess><allowOverride>` != 0 OR the
    // inline rewrite block's `autoLoadHtaccess`. The two are independent in the
    // common imported configs set `allowOverride=31` with no
    // `<rewrite>` block, while mcp sets `autoLoadHtaccess=1` with no
    // `<htAccess>` — so an `AND` would disable `.htaccess` for every vhost.
    // Vhosts that set neither policy get an
    // empty chain and run inline rules only, exactly as before. Each entry
    // carries its source directory so we can derive the per-directory prefix (#6).
    // An EXPLICIT `<allowOverride>0` still forbids the chain outright (overrides_enabled).
    let htaccess_enabled = ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess);
    let chain_with_dirs: Vec<(PathBuf, Arc<Htaccess>)> = if htaccess_enabled {
        state.rewrite_cache.load_chain_with_dirs(
            &ctx.vhost.doc_root,
            &orig_path,
            ctx.vhost.access_file_name_or_default(),
        )
    } else {
        Vec::new()
    };
    // A flat view for the access / header / error-doc helpers (order preserved).
    let chain: Vec<Arc<Htaccess>> = chain_with_dirs.iter().map(|(_, h)| h.clone()).collect();

    // ---- 2. Seed server env (HTTPS=on for TLS), then SetEnvIf (#8b): merge into
    // ctx.env BEFORE the rewrite so later RewriteConds and Header env= guards see
    // the variables. HTTPS must be seeded first so `Header ... env=HTTPS` (HSTS)
    // and `%{ENV:HTTPS}` observe it, exactly as Apache/OLS set it. ----------------
    seed_server_env(ctx);
    apply_set_env(ctx, &chain, &req, &orig_path, &orig_query);

    // ---- 2b. Access control on the ORIGINAL request path, BEFORE rewrite ---
    // Apache/LiteSpeed evaluate <Files>/<FilesMatch>/Require + accessDenyDir
    // against the REQUESTED path; a rewrite (front controller, `[P]` proxy, ...)
    // must NOT bypass a deny. Without this, a denied-but-absent path (e.g.
    // `/.htpasswd`, `/secret.md`) would be front-controller-rewritten to
    // index.php and escape the deny (403 only happens for existing files), and a
    // `[P]` rule could proxy a denied path. The post-rewrite checks below still
    // catch a rewrite INTO a denied path; this adds the pre-rewrite guarantee.
    let orig_rel = resolved_rel_path(&orig_path);
    if access_denied(&chain, &orig_rel, req.method().as_str(), ctx)
        || access_deny_dir(&state.acl, &ctx.vhost.doc_root, &orig_rel)
    {
        return error_doc_or_page(state, ctx, &chain, &orig_path, StatusCode::FORBIDDEN).await;
    }

    // ---- 3. Rewrite -------------------------------------------------------
    let _rt = state
        .telemetry
        .sample_phase(crate::telemetry::PHASE_SAMPLE_RATE)
        .then(std::time::Instant::now);
    let rw_result = run_rewrite(state, ctx, &req, &chain_with_dirs, &cur_path, &cur_query);
    if let Some(t) = _rt {
        state.telemetry.shard().phase_rewrite.record(t.elapsed());
    }
    // A terminal `[P]` proxy target is DEFERRED to the dispatch site after the cache context
    // (cc) is built (below) so a cacheable proxied response can participate in the origin page
    // cache, like the proxy-<context>/LSAPI/static paths; `None` for every other outcome.
    let mut proxy_target: Option<String> = None;
    match rw_result {
        RwResult::Proxy { target_url, env } => {
            // Merge the rewrite chain's env (incl. preceding `[E=]` rulesets) into ctx.env so
            // env-gated `Header ... env=` directives fire on the proxied response, and so
            // `[E=no-cache]` is visible to the page-cache lookup at the deferred dispatch below.
            merge_rewrite_env(ctx, env);
            proxy_target = Some(target_url);
        }
        RwResult::Redirect {
            code,
            location,
            env,
        } => {
            merge_rewrite_env(ctx, env);
            // (#11) `Header always set` applies to a rewrite-generated 3xx too (Apache
            // scopes `always` to redirects — directives.rs), matching the Status arm.
            let mut resp = redirect(code, &location);
            let rel = resolved_rel_path(&cur_path);
            apply_response_headers_for_request(ctx, &chain, &rel, &orig_path, &mut resp);
            return resp;
        }
        RwResult::Status { code, env } => {
            // (#8) [R=NNN] with a non-3xx status: respond with that bare status,
            // applying any [E=...] / Header set directives, and NO Location or
            // "moved" body. The CORS preflight rule is the live example.
            merge_rewrite_env(ctx, env);
            let rel = resolved_rel_path(&cur_path);
            let mut resp = status_response(code);
            apply_response_headers_for_request(ctx, &chain, &rel, &orig_path, &mut resp);
            return resp;
        }
        RwResult::Forbidden => {
            return error_doc_or_page(state, ctx, &chain, &cur_path, StatusCode::FORBIDDEN).await;
        }
        RwResult::Gone => {
            return error_doc_or_page(state, ctx, &chain, &cur_path, StatusCode::GONE).await;
        }
        RwResult::Rewritten { path, query, env } => {
            cur_path = Cow::Owned(path);
            // `None` = the rewrite left no query (e.g. `[QSD]`) → empty, not the original.
            cur_query = Cow::Owned(query.unwrap_or_default());
            rewritten = true;
            merge_rewrite_env(ctx, env);
        }
        RwResult::Unchanged { env } => {
            merge_rewrite_env(ctx, env);
        }
    }

    // (#8) A rewrite that routes into a directory whose .htaccess was NOT already loaded must
    // consult the DESTINATION directory's chain for the post-rewrite access checks — otherwise a
    // <Files>/<FilesMatch>/Require deny living in the dir the request was rewritten INTO is never
    // seen (the chain was built for orig_path's ancestor dirs). The original chain already covers
    // every ANCESTOR of orig_path, so a reload is only needed when the destination directory is NOT
    // an ancestor-or-equal of the original's — i.e. the rewrite went sideways or DEEPER. This keeps
    // the hot front-controller rewrite (/whats-new/ -> /index.php: root "/" IS an ancestor of
    // "/whats-new/") paying nothing, while a rewrite into "/protected/x" reloads. Mirrors Apache's
    // internal-redirect re-evaluation. Not triggered by the live config (its directory-crossing
    // rules are all external [R] redirects), so this closes a latent gap with zero hot-path or
    // live-behavior change.
    let chain: Vec<Arc<Htaccess>> = if rewritten
        && htaccess_enabled
        && !url_parent_dir(&orig_path).starts_with(url_parent_dir(&cur_path))
    {
        state
            .rewrite_cache
            .load_chain_with_dirs(
                &ctx.vhost.doc_root,
                &cur_path,
                ctx.vhost.access_file_name_or_default(),
            )
            .into_iter()
            .map(|(_, h)| h)
            .collect()
    } else {
        chain
    };

    // The docroot-relative, normalized path used for access / header scoping. When the rewrite
    // left the path unchanged (the common case), this equals `orig_rel` already computed for the
    // pre-rewrite access check — reuse it (a move, no second normalization alloc).
    let rel_path = if rewritten {
        resolved_rel_path(&cur_path)
    } else {
        orig_rel
    };

    // ---- 4. ACCESS enforcement (#1): a denied path is a 403 BEFORE any
    // terminal handler (proxy / LSAPI / static). Fail-safe: any matching
    // `denied` section anywhere in the chain wins. -------------------------
    if access_denied(&chain, &rel_path, req.method().as_str(), ctx) {
        return error_doc_or_page(state, ctx, &chain, &cur_path, StatusCode::FORBIDDEN).await;
    }
    // (M4 security) `accessDenyDir` enforcement: the resolved docroot-relative
    // path is mapped to its absolute on-disk path and tested against the
    // compiled deny globs (`security.access_deny_dir` PLUS the built-in `.ht*`
    // default). `deny_dir_match` was previously DEAD CODE — built but never
    // called — so configured deny dirs (and the `.htaccess`/`.htpasswd`
    // protection every vhost is supposed to have, LiteSpeed/Apache parity) were
    // not enforced. We gate ALL terminal handlers (proxy / LSAPI / static) here,
    // alongside the chain access check above, so e.g. a request for any
    // `.htaccess` is a 403 regardless of which handler would otherwise serve it.
    if access_deny_dir(&state.acl, &ctx.vhost.doc_root, &rel_path) {
        return error_doc_or_page(state, ctx, &chain, &cur_path, StatusCode::FORBIDDEN).await;
    }
    // (#1, PATH_INFO deny bypass) `<Files>`/`<FilesMatch>` are scoped by Apache to
    // the file the request MAPS TO — i.e. the resolved script — not the trailing
    // PATH_INFO segment. When `split_script_path` would route `/config.php/x` to
    // script `/config.php` (PATH_INFO `/x`), the access check above only saw
    // basename `x` and missed a `<FilesMatch "config\.php$"> Require all denied`.
    // Re-run the access decision against the SCRIPT's docroot-relative path so a
    // denied script cannot be executed by appending a PATH_INFO segment. We only
    // do the extra check when the resolved script path differs from `rel_path`
    // (i.e. there IS a PATH_INFO tail), so the common no-PATH_INFO case is
    // unaffected. Both the literal (`/install.php/x`) and the encoded
    // (`/install.php%2Fx`, already decoded upstream) forms hit this.
    // Resolve the script split ONCE (B5): `cur_path` is final after rewrite (line ~614) and is
    // not mutated below, so both this PATH_INFO-deny re-check and the suffix routing in step 7
    // need the identical split. Computed here so the MISS path doesn't scan + stat-lookup twice;
    // a cache HIT / WS / proxy returns before step 7 and simply drops it (one call, as before).
    let index_files = effective_index_files(state, ctx, &chain);
    let script_split = split_script_path(state, ctx, &cur_path, index_files, &chain);
    let mut pinned_script_target = None;
    if let Some((script_abs, _script_name, _path_info)) = &script_split {
        // `accessDenyDir` is a filesystem-target policy. The lexical request-path check above
        // cannot see a PHP symlink whose target is inside a denied tree, so resolve through an
        // opened descriptor and retain that exact target as lsphp's SCRIPT_FILENAME.
        let Some(target) = allowed_script_target(&state.acl, script_abs) else {
            return error_doc_or_page(state, ctx, &chain, &cur_path, StatusCode::FORBIDDEN).await;
        };
        pinned_script_target = Some(target);
        // Re-run the access decision against the RESOLVED script whenever it differs from the
        // request path — covering BOTH the PATH_INFO tail (`/config.php/x` → script `/config.php`)
        // AND a DirectoryIndex resolution (`/dir/` → `/dir/index.php`). `<Files>`/`<FilesMatch>`
        // are scoped to the file the request MAPS TO, so the earlier check on the request path
        // (basename `x`, or the directory `dir`) misses a deny on the script's basename.
        //
        // Derive the rel path from the RESOLVED script's absolute path (strip the docroot), NOT
        // `script_name`: for a DirectoryIndex `resolve_script` returns `script_name` = the request
        // directory (`/protected/`), so keying off it leaves `script_rel == rel_path` and the
        // re-check is skipped — letting a `<Files "index.php"> Require all denied` be bypassed by
        // requesting the directory. `script_abs` is the actual index file, so it does not.
        if let Ok(rel) = script_abs.strip_prefix(&ctx.vhost.doc_root) {
            // Re-canonicalize to the LEADING-SLASH form `resolved_rel_path` produces and that the
            // htaccess access matchers expect: path-anchored rules (`<DirectoryMatch>`, `<If
            // "%{REQUEST_URI} =~ m#^/...#">`) regex-match the full rel_path, so the bare
            // `strip_prefix` output (no leading slash) would silently miss every path-anchored deny.
            // `access_deny_dir` trims the leading slash itself, so the slash form is correct there too.
            let script_rel = format!("/{}", rel.to_string_lossy());
            // Re-run BOTH deny mechanisms (the `.htaccess` `<Files>`/`Require` chain AND the
            // `accessDenyDir` glob set) against the resolved script, mirroring the request-path check.
            if script_rel != rel_path
                && (access_denied(&chain, &script_rel, req.method().as_str(), ctx)
                    || access_deny_dir(&state.acl, &ctx.vhost.doc_root, &script_rel))
            {
                return error_doc_or_page(state, ctx, &chain, &cur_path, StatusCode::FORBIDDEN)
                    .await;
            }
        }
    }

    // ---- 4c. Origin full-page cache lookup (LSCache equivalent) ----------
    // Runs AFTER rewrite/ACL merged the `[E=no-cache]` env (so logged-in/AJAX
    // bypass is visible) but keys by the ORIGINAL request URI `orig_path`/
    // `orig_query`, NOT the rewrite-resolved `cur_path`. The XenForo front
    // controller rewrites every page to `/index.php`, so keying by `cur_path`
    // would collapse all pages to one entry and serve the wrong page (this was
    // a real cache-poisoning bug). LSCache likewise keys by `REQUEST_URI`.
    // Inert unless `--page-cache` is set. `method`/`host`/`cookie` are captured
    // here while `req` is still owned, and reused identically by the store seams
    // below so the lookup and store keys always agree.
    let cache_on = state.page_cache.is_some();
    let cache_method = req.method().clone();
    // Reuse the host already computed in `handle()` (B4) instead of recomputing the identical
    // value; dropped unused when the cache is off (cache_host stays empty as before).
    let cache_host = if cache_on { req_host } else { String::new() };
    let cache_cookie = if cache_on {
        cookie_header_joined(req.headers())
    } else {
        None
    };
    // Collision guard identity: scheme + canonical vhost + the canonical request path.
    // A cached entry is only ever served when this matches, so a key bug can never serve
    // the wrong page — it degrades to a miss. Scheme is included for the same reason it is
    // in the cache key: an HTTP-origin canonical 301 must never match an HTTPS request
    // (cross-scheme redirect loop). Reused by the store seams below.
    //
    // (#6) Use the CANONICAL `orig_path` (percent-decoded + dot-normalized), the SAME
    // path that feeds the cache key — NOT the raw `req.uri().path()`. Two
    // encoding-variants of one URL (`/index.php` vs `/index%2Ephp`) share a key but,
    // with the raw path, produced DIFFERENT identities — so every lookup failed the
    // guard, re-rendered, and overwrote: an endless overwrite cycle that nullified the
    // cache for any URL with a valid percent-encoded variant CF doesn't normalize. The
    // guard still distinguishes genuinely-different `orig_path`s (its collision-detection
    // purpose); it just no longer fires on encoding-equal URLs.
    // (#5/#20) Identify by the canonical vhost name, NOT the raw `cache_host`. The key
    // already collapses every Host value routed to a vhost onto one entry (#5); embedding
    // the raw Host here would instead make each distinct attacker-chosen Host MISS the
    // shared entry, re-render, and overwrite (a Host cache-buster + a flood of false
    // collision-guard warnings). The vhost name still refuses a genuine cross-vhost key
    // collision (same path routed to a different vhost on a shared cache).
    let cache_identity = if cache_on {
        cache_identity_for(ctx.is_tls, &ctx.vhost_name, &orig_path)
    } else {
        String::new()
    };
    // A Host that reached this vhost ONLY via the listener's `*` wildcard (it is neither an
    // exact vhostMap domain nor the default vhost's own name) is foreign to the resolved
    // vhost — e.g. an unconfigured `www.publisher.example` falling through to the
    // `forum.example` default. Since the cache keys by the resolved vhost, serving it the
    // default vhost's cached page would mask the backend's canonical 301 and leak one brand's
    // content under another's hostname (the foreign-host regression). When set, the lookup
    // bypasses and the store is skipped — LiteSpeed LSCache embeds the Host in its key, so a
    // foreign host misses there by construction. `host_foreign` is computed once in `handle()`
    // (the same `request_host` the cache keys by) and gates BOTH this and the CF de-cache, so
    // an explicitly-configured alias (a `www.` listed in a vhostMap, like `www.tenant.example`)
    // stays cacheable while an unconfigured `www.` does not.
    let cache_host_foreign = cache_on && host_foreign;
    let cache_has_range = cache_on && req.headers().contains_key(http::header::RANGE);
    let cache_render_epoch = state
        .page_cache
        .as_ref()
        .map(|pc| pc.purge_epoch())
        .unwrap_or(0);
    let _cache_render_guard = state
        .page_cache
        .as_ref()
        .map(|pc| pc.begin_render(cache_render_epoch));
    // (#275) The public vary discriminant, computed ONCE for the lookup + all
    // store sites (build_cache_key/capsule_key otherwise re-split the Cookie
    // header per call).
    let cache_vary = if cache_on {
        state
            .page_cache
            .as_ref()
            .map(|pc| {
                hj_pagecache::compute_vary_value(cache_cookie.as_deref(), &pc.config().vary_cookies)
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    // Built once, threaded unchanged to the lookup + all three store sites so their
    // keys + identity guard can never drift apart (see lscache::CacheCtx).
    let cc = lscache::CacheCtx {
        method: &cache_method,
        host: &cache_host,
        cookie: cache_cookie.as_deref(),
        identity: &cache_identity,
        req_path: &orig_path,
        req_query: &orig_query,
        chain: &chain,
        render_epoch: cache_render_epoch,
        has_range: cache_has_range,
        host_foreign: cache_host_foreign,
        vary_value: (cache_on && state.page_cache.is_some()).then_some(cache_vary.as_str()),
    };

    // (Tier 1.3) Basic auth: the deepest `.htaccess` realm in the chain governs
    // this tree. Missing/invalid credentials → 401 + WWW-Authenticate BEFORE any
    // cache lookup or backend runs; valid credentials set REMOTE_USER for the app.
    if let Some(realm) = chain.iter().rev().find_map(|h| h.auth.as_ref()) {
        // A relative AuthUserFile resolves against the vhost docroot.
        let user_file = if realm.user_file.is_absolute() {
            realm.user_file.clone()
        } else {
            ctx.vhost.doc_root.join(&realm.user_file)
        };
        let creds = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(hj_rewrite::auth::decode_basic_credentials);
        let authorized = match &creds {
            Some((user, pass)) => {
                let uf = user_file;
                let (u, p) = (user.clone(), pass.clone());
                let ok = tokio::task::spawn_blocking(move || {
                    hj_rewrite::auth::verify_credentials(&uf, &u, &p)
                })
                .await
                .unwrap_or(false);
                ok && realm.user_satisfies(user)
            }
            None => false,
        };
        if !authorized {
            let mut resp = error_page(StatusCode::UNAUTHORIZED);
            if let Ok(v) = http::HeaderValue::from_str(&realm.challenge()) {
                resp.headers_mut().insert(http::header::WWW_AUTHENTICATE, v);
            }
            return resp;
        }
        if let Some((user, _)) = &creds {
            ctx.set_env("REMOTE_USER", user.clone());
        }
    }

    // ---- 4d. Deferred terminal `[P]` proxy, with page-cache participation ------------
    // Mirrors the proxy-<context> arm (lookup -> render -> store) but for a rewrite `[P]`
    // target. Keyed by the original request URI (cc); respects the `[E=no-cache]` env merged
    // in the rewrite arm above. Range/refresh bypass the lookup; cache_store is identity- /
    // 206- / self-redirect-guarded and no-ops for a non-cacheable response (today's Monit
    // `[P]` is non-cacheable, so this is inert for it). No single-flight: the `[P]` path is
    // low-volume; add it if a high-traffic cacheable `[P]` ever appears.
    if let Some(target_url) = proxy_target {
        // (Tier 2) Per-context body limit: reject before the body is consumed if the
        // matching context declares a tighter limit than the server-wide default.
        {
            let eff_max = effective_max_body(
                ctx,
                req.uri().path(),
                state.serve_config.max_req_body_size as u64,
            );
            if let Some(cl) = req
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
            {
                if cl > eff_max {
                    return error_page(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }
        }
        let is_refresh_p = req.extensions().get::<RefreshMode>().is_some();
        if cache_on && !cache_has_range && !is_refresh_p {
            let inm = req
                .headers()
                .get(http::header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok());
            if let lscache::CacheOutcome::Hit(hit) =
                lscache::cache_lookup(state, ctx, &cc, inm, false, None)
            {
                state.telemetry.record_cache_hit(ctx.peer_ip.is_loopback());
                return hit;
            }
        }
        // (#11) `.htaccess` `Header always set` (HSTS/CSP/CORS/...) applies to a [P] response.
        let rel = resolved_rel_path(&cur_path);
        let mut resp = match ProxyTarget::parse_url(&target_url) {
            Ok(target) => {
                let h = ProxyHandler {
                    proxy: state.proxy.clone(),
                    telemetry: state.telemetry.clone(),
                    target,
                    response_timeout_override: ctx
                        .vhost
                        .contexts
                        .iter()
                        .find(|c| context_uri_matches(cur_path.as_ref(), c.uri.as_str()))
                        .and_then(|c| c.timeout_override),
                };
                state
                    .telemetry
                    .shard()
                    .served_proxy
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                run_handler(&h, ctx, req).await
            }
            Err(e) => {
                // Config/rewrite bug -> always a 502; low volume -> warn.
                tracing::warn!(request_id = %ctx.request_id, target = %target_url, error = %e, "bad [P] rewrite target -> 502");
                error_page(StatusCode::BAD_GATEWAY)
            }
        };
        apply_response_headers_for_request(ctx, &chain, &rel, &orig_path, &mut resp);
        return if cache_on {
            lscache::cache_store(state, ctx, &cc, resp).await
        } else {
            resp
        };
    }

    // Single-flight: collapse concurrent MISSES of the same cacheable key into ONE backend
    // render so a hot page's TTL expiry doesn't stampede the (PHP) backend with N identical
    // renders. The leader holds `_sf_leader` — a local that drops at any dispatch return
    // (after cache_store on the cacheable paths), waking followers; followers wait for that,
    // then serve from the cache the leader filled. `Bypass` (logged-in / non-GET / disabled)
    // never single-flights. Inert when --page-cache is off (`cache_on` false).
    let mut _sf_leader: Option<lscache::InflightLeader> = None;
    // (range) A Range request bypasses the page cache: serving a full cached 200 to a Range
    // client ignores the range, and range-aware cache hits aren't implemented — let it reach
    // the backend (static/LSAPI), which produces a proper 206. The store-side guard
    // (status != 206) keeps that partial out of the cache.
    if cache_on && !cache_has_range {
        // A background stale-while-revalidate refresh re-enters dispatch with this marker:
        // it must RENDER + store a fresh entry (force a cache miss), never re-serve the stale
        // copy that triggered it.
        let is_refresh = req.extensions().get::<RefreshMode>().is_some();
        if is_refresh {
            // Signal the app's `auto_prepend` page cache (`pagecache.php`) to BYPASS its own
            // pre-bootstrap hit and render fresh. A stale-while-revalidate refresh MUST reach a
            // genuine origin render — if the app cache replays its own (aging) copy, the entry
            // can never converge back to fresh (the homepage perpetual-stale loop). Rides to
            // lsphp as `$_SERVER['HJ_CACHE_REFRESH']`; unforgeable since a client header would
            // arrive as `HTTP_*` (see `hj_lsapi::cgi`).
            ctx.env
                .push(("HJ_CACHE_REFRESH".to_string(), "1".to_string()));
        }
        let inm = req
            .headers()
            .get(http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());
        let _lt = state
            .telemetry
            .sample_phase(crate::telemetry::PHASE_SAMPLE_RATE)
            .then(std::time::Instant::now);
        // (#320) Evaluate the shared cache gates ONCE for both sequential lookups.
        let shared_gates = state
            .page_cache
            .as_ref()
            .map(|store| lscache::compute_shared_gates(ctx, &cc, store));
        if !is_refresh {
            match lscache::capsule_lookup(state, ctx, &cc, inm, shared_gates.as_ref()) {
                lscache::CacheOutcome::Hit(hit) => {
                    state.telemetry.record_cache_hit(ctx.peer_ip.is_loopback());
                    return hit;
                }
                lscache::CacheOutcome::StaleHit(stale, key_hash) => {
                    let lb = ctx.peer_ip.is_loopback();
                    state.telemetry.record_cache_hit(lb);
                    state.telemetry.record_cache_stale_serve(lb);
                    spawn_revalidate(state, host_foreign, ctx, &req, key_hash);
                    return stale;
                }
                lscache::CacheOutcome::CapsuleStaleHit(stale, key_hash) => {
                    let lb = ctx.peer_ip.is_loopback();
                    state.telemetry.record_cache_hit(lb);
                    state.telemetry.record_cache_stale_serve(lb);
                    spawn_capsule_revalidate(state, host_foreign, ctx, &req, key_hash);
                    return stale;
                }
                lscache::CacheOutcome::Miss(_) | lscache::CacheOutcome::Bypass => {}
            }
        }
        let cache_outcome =
            lscache::cache_lookup(state, ctx, &cc, inm, is_refresh, shared_gates.as_ref());
        if let Some(t) = _lt {
            state
                .telemetry
                .shard()
                .phase_cache_lookup
                .record(t.elapsed());
        }
        match cache_outcome {
            lscache::CacheOutcome::Hit(hit) => {
                state.telemetry.record_cache_hit(ctx.peer_ip.is_loopback());
                return hit;
            }
            lscache::CacheOutcome::StaleHit(stale, key_hash) => {
                // Serve the stale (CF-poison-guarded) body NOW and kick off exactly one
                // background refresh — the client never waits on the re-render. Counts as a
                // hit (it avoided the backend). A refresh request never reaches here (its
                // initial lookup is force-missed), so this only fires for real traffic.
                let lb = ctx.peer_ip.is_loopback();
                state.telemetry.record_cache_hit(lb);
                state.telemetry.record_cache_stale_serve(lb);
                spawn_revalidate(state, host_foreign, ctx, &req, key_hash);
                return stale;
            }
            lscache::CacheOutcome::CapsuleStaleHit(stale, key_hash) => {
                let lb = ctx.peer_ip.is_loopback();
                state.telemetry.record_cache_hit(lb);
                state.telemetry.record_cache_stale_serve(lb);
                spawn_capsule_revalidate(state, host_foreign, ctx, &req, key_hash);
                return stale;
            }
            lscache::CacheOutcome::Bypass => {
                state
                    .telemetry
                    .record_cache_bypass(ctx.peer_ip.is_loopback());
            }
            lscache::CacheOutcome::Miss(key_hash) => {
                match state.page_cache_inflight.enter(key_hash) {
                    lscache::Enter::Leader(guard) => {
                        // Genuine miss: this request renders (and maybe stores).
                        state.telemetry.record_cache_miss(ctx.peer_ip.is_loopback());
                        _sf_leader = Some(guard);
                    }
                    lscache::Enter::Follower(notify) => {
                        // Another request is rendering this key. It may have already stored;
                        // otherwise wait (bounded) for it to wake us, then serve from cache.
                        // (force_miss=false here: a follower WANTS the leader's fresh entry.)
                        //
                        // CRITICAL: REGISTER on the leader's Notify (`enable()`) BEFORE the
                        // pre-wait cache_lookup. A tokio `Notified` future is not a registered
                        // waiter until first polled or enabled. If we ran the lookup first —
                        // which on the heavy vhost loads the whole `.htaccess` chain and builds
                        // the key, far longer than a fast leader's render — and the leader
                        // dropped during it, the leader's `notify_waiters()` would wake nobody
                        // (we are not parked yet) and its `notify_one()` stores only ONE permit.
                        // With N concurrent followers racing in this window, exactly one consumes
                        // the permit and the other N-1 lose the wakeup and block the full
                        // SINGLEFLIGHT_WAIT (10s) — the heavy-vhost concurrency collapse (a
                        // cacheable-candidate-but-uncacheable response, e.g. robots.txt, where
                        // the leader stores nothing, serializes every concurrent miss to ~1 at a
                        // time with 10s tails). Enabling first makes us a registered waiter so
                        // `notify_waiters()` releases us regardless of lookup duration.
                        let notified = notify.notified();
                        tokio::pin!(notified);
                        notified.as_mut().enable();
                        if let lscache::CacheOutcome::Hit(hit) =
                            lscache::cache_lookup(state, ctx, &cc, inm, false, None)
                        {
                            // Follower served the leader's freshly-stored entry: a HIT, not a miss.
                            state.telemetry.record_cache_hit(ctx.peer_ip.is_loopback());
                            return hit;
                        }
                        let _ = tokio::time::timeout(SINGLEFLIGHT_WAIT, notified).await;
                        if let lscache::CacheOutcome::Hit(hit) =
                            lscache::cache_lookup(state, ctx, &cc, inm, false, None)
                        {
                            // Follower served the leader's freshly-stored entry: a HIT, not a miss.
                            state.telemetry.record_cache_hit(ctx.peer_ip.is_loopback());
                            return hit;
                        }
                        // Leader stored nothing cacheable (or hung past the wait): fall through
                        // and render ourselves. We stay a non-leader (no guard) — a real miss.
                        state.telemetry.record_cache_miss(ctx.peer_ip.is_loopback());
                    }
                }
            }
        }
    }

    // ---- 5. WebSocket upgrade --------------------------------------------
    let ws_upgrade = is_websocket_upgrade(req.headers());
    if ws_upgrade {
        if let Some(ws) = ctx
            .vhost
            .websockets
            .iter()
            .find(|w| context_uri_matches(&cur_path, &w.uri))
        {
            let target = ProxyTarget::from_websocket_map(ws);
            return proxy_websocket(state, ctx, req, target).await;
        }
    }

    // ---- 6. Proxy context -------------------------------------------------
    if let Some(handler) = matching_proxy_context(ctx, &cur_path) {
        // A WebSocket-upgrade request that reached here matched no `websockets` map, so
        // it is being routed to an ORDINARY reverse-proxy context that has no upgrade
        // relay. Forwarding the handshake would produce a non-conformant 101 the client
        // can never use (and pin a pool slot) — refuse cleanly with 426 instead.
        if ws_upgrade {
            return error_page(StatusCode::UPGRADE_REQUIRED);
        }
        // (#3) Per-vhost <extProcessorList> takes precedence over the global map
        // so e.g. status.forum.example's `stats_api` resolves locally.
        if let Some(target) = resolve_proxy_target(state, ctx, &handler) {
            let h = ProxyHandler {
                proxy: state.proxy.clone(),
                telemetry: state.telemetry.clone(),
                target,
                response_timeout_override: ctx
                    .vhost
                    .contexts
                    .iter()
                    .find(|c| context_uri_matches(cur_path.as_ref(), c.uri.as_str()))
                    .and_then(|c| c.timeout_override),
            };
            state
                .telemetry
                .shard()
                .served_proxy
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut resp = run_handler(&h, ctx, req).await;
            // (#2/#7) `.htaccess` Header directives still apply to a proxied
            // response, but NOT error documents — the body is upstream's.
            apply_response_headers_for_request(ctx, &chain, &rel_path, &orig_path, &mut resp);
            return lscache::cache_store(state, ctx, &cc, resp).await;
        }
        tracing::debug!(handler, "proxy context references unknown ext processor");
    }

    // ---- 7. Suffix routing: LSAPI (php/html) or static -------------------
    // Reuse the split resolved once above (B5) — `cur_path` is unchanged since.
    if let Some((script_abs, script_name, path_info)) = script_split {
        if let Some(registry) = state.lsapi.clone() {
            // Resolve this vhost's jail (config-gated + root-gated inside
            // JailConfig::resolve). With suEXEC off / non-root / no per-vhost
            // isolation this is the all-None jail -> the default "php" pool, so
            // Phase-1 single-pool behavior is preserved byte-for-byte. An Err
            // means the jail is configured but unsafe (e.g. root uid, below the
            // floor, bad chroot) -> we MUST disable PHP for this vhost (503),
            // never run as root and never fall back unjailed.
            let jail = match resolve_vhost_jail(state, ctx) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!(request_id = %ctx.request_id, vhost = %ctx.vhost_name, error = %e, "suexec jail resolve failed; disabling PHP for vhost");
                    // Through cache_store so a retained entry can serve as the
                    // stale-if-error fallback instead of the 503 (lsphp outage class).
                    return lscache::cache_store(
                        state,
                        ctx,
                        &cc,
                        error_page(StatusCode::SERVICE_UNAVAILABLE),
                    )
                    .await;
                }
            };
            let lsapi = match registry.handler_for(&ctx.vhost_name, &jail).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!(request_id = %ctx.request_id, vhost = %ctx.vhost_name, error = %e, "lsphp pool unavailable for vhost");
                    return lscache::cache_store(
                        state,
                        ctx,
                        &cc,
                        error_page(StatusCode::SERVICE_UNAVAILABLE),
                    )
                    .await;
                }
            };
            // `.htaccess` php_value/php_admin_value/php_flag/php_admin_flag — resolved
            // across the docroot→deepest chain (admin LOCKS a name) — ride to lsphp in
            // the LSAPI special-env section. This is what makes the site's
            // `php_value auto_prepend_file "…/pagecache.php"` fast-path fire, exactly as
            // under LiteSpeed. Empty (the common case) ⇒ zero-cost identical wire bytes.
            // `script_name`/`script_basename` honor each directive's enclosing
            // `<Files*>` scope: the basename is the RESOLVED script (e.g. `index.php`
            // for a DirectoryIndex hit), so a `<Files "crontab.html">` override does
            // not leak onto sibling scripts and 500 them via `require 'none'`.
            let script_basename = script_abs
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            let special_env: Vec<(SpecialEnvType, String, String)> =
                hj_rewrite::php_directives(&chain, &script_name, script_basename)
                    .into_iter()
                    .map(|d| {
                        let ty = if d.admin {
                            SpecialEnvType::Admin
                        } else {
                            SpecialEnvType::User
                        };
                        (ty, d.name, d.value)
                    })
                    .collect();
            let lsapi_script = LsapiScript {
                script: pinned_script_target.unwrap_or_else(|| {
                    panic!("script split reached LSAPI without a pinned filesystem target")
                }),
                script_name: Some(script_name.clone()),
                path_info: if path_info.is_empty() {
                    None
                } else {
                    Some(path_info)
                },
                special_env,
            };
            // Never SERVE a self-redirect loop. A backend 3xx whose Location is the request's
            // own URL is a guaranteed loop; it is a transient mis-render (the normal render is
            // the page), so for an idempotent GET/HEAD keep what's needed to re-render ONCE and
            // use the retry if it comes back clean. This is the cache-MISS path (hits
            // short-circuit before dispatch reaches here), so the clone is off the hot serve
            // path. Pairs with the store-side guard (a self-redirect is never cached either).
            let sr_retry =
                matches!(*req.method(), http::Method::GET | http::Method::HEAD).then(|| {
                    let host = if cache_host.is_empty() {
                        lscache::request_host(&req, ctx)
                    } else {
                        cache_host.clone()
                    };
                    (
                        req.method().clone(),
                        req.uri().clone(),
                        req.headers().clone(),
                        lsapi_script.clone(),
                        host,
                    )
                });
            req.extensions_mut().insert(lsapi_script);
            if rewritten {
                // Keep the original REQUEST_URI (req.uri untouched); override the
                // script-relative env that the rewrite changed, and expose the
                // pre-rewrite request path as REDIRECT_URL (Apache/LiteSpeed).
                ctx.set_env("SCRIPT_NAME", script_name);
                ctx.set_env("QUERY_STRING", cur_query.clone());
                ctx.set_env("REDIRECT_URL", orig_path.clone());
            }
            // (attribution) Pre-capture the request identity for the PHP slow/sample
            // log before dispatch consumes `req` — whether the line is written is
            // only known after the render (the decision needs the TTFB).
            let slow_pre = state.php_slow.as_ref().map(|sl| {
                let host = if cache_host.is_empty() {
                    lscache::request_host(&req, ctx)
                } else {
                    cache_host.clone()
                };
                (
                    sl.clone(),
                    crate::phpslow::PreCapture::from_request(
                        &req,
                        host,
                        ctx.request_id.to_string(),
                    ),
                )
            });
            // (telemetry) The PHP/LSAPI backend call — served counter + dispatch
            // latency (always-on on this minority cache-miss path; the histogram
            // that fingers the spawn/channel overhead the optimization targets).
            state
                .telemetry
                .shard()
                .served_php
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let lsapi_start = std::time::Instant::now();
            let mut resp = run_handler(lsapi.as_ref(), ctx, req).await;
            let lsapi_elapsed = lsapi_start.elapsed();
            state.telemetry.shard().lsapi_dispatch.record(lsapi_elapsed);
            // Split: pool-acquire (httpjet contention) vs TTFB (lsphp worker pickup
            // + render start) — distinguishes "needs more workers" from "slow PHP".
            let lsapi_timing = resp
                .extensions()
                .get::<hj_lsapi::LsapiTiming>()
                .map(|t| (t.acquire, t.ttfb));
            if let Some((acquire, ttfb)) = lsapi_timing {
                state.telemetry.shard().lsapi_acquire.record(acquire);
                state.telemetry.shard().lsapi_ttfb.record(ttfb);
            }
            // Retry attribution for the php-slow log (#133): the handler stamps this
            // only when the dispatch succeeded after a retry.
            let retry_kind = resp
                .extensions()
                .get::<hj_lsapi::LsapiRetryInfo>()
                .map(|r| r.kind)
                .unwrap_or("-");
            if let Some((method, uri, headers, script, host)) = sr_retry {
                let is_tls = ctx.is_tls;
                let is_self = |r: &Response| {
                    lscache::is_self_redirect(
                        r.status().as_u16(),
                        r.headers(),
                        is_tls,
                        &host,
                        &orig_path,
                        &orig_query,
                    )
                };
                if is_self(&resp) {
                    // Self only after percent-normalization (raw request `/a%5Fb`,
                    // Location `/a_b`) = a slug-canonicalization redirect, not a
                    // mis-render: the backend deterministically emits the same
                    // redirect again, so a re-render buys nothing — skip the
                    // second render. The store guards keep it uncached either way.
                    let raw_self = lscache::is_self_redirect_raw(
                        resp.status().as_u16(),
                        resp.headers(),
                        is_tls,
                        &host,
                        uri.path(),
                        uri.query().unwrap_or(""),
                    );
                    if !raw_self {
                        tracing::debug!(request_id = %ctx.request_id, path = %orig_path, "self-redirect by percent-normalization only; serving uncached without re-render");
                    } else {
                        let mut req2: Request = Request::new(hj_core::empty_incoming());
                        *req2.method_mut() = method;
                        *req2.uri_mut() = uri;
                        *req2.headers_mut() = headers;
                        req2.extensions_mut().insert(script);
                        let resp2 = run_handler(lsapi.as_ref(), ctx, req2).await;
                        if is_self(&resp2) {
                            tracing::warn!(request_id = %ctx.request_id, path = %orig_path, "backend self-redirect persisted on re-render; serving (not cached)");
                        } else {
                            tracing::warn!(request_id = %ctx.request_id, path = %orig_path, "backend self-redirect re-rendered cleanly on retry");
                            resp = resp2;
                        }
                    }
                }
            }
            // (attribution) Emit the slow/sample line now that the final status is
            // known. First-attempt timing — same numbers the histograms recorded.
            if let Some((sl, pre)) = slow_pre {
                let bytes = resp
                    .headers()
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                sl.record(
                    pre,
                    lsapi_timing,
                    lsapi_elapsed,
                    resp.status().as_u16(),
                    bytes,
                    ctx.peer_ip.is_loopback(),
                    retry_kind,
                );
            }
            finalize_response(
                state, ctx, &chain, &rel_path, &orig_path, &cur_path, &mut resp,
            )
            .await;
            return lscache::cache_store(state, ctx, &cc, resp).await;
        }
        // The path resolved to a script handler (php/html), but no lsphp pool is
        // available (PHP disabled, or lsphp failed to start). NEVER fall through
        // to the static handler — that would serve the script's SOURCE CODE
        // (a source-disclosure). Apache/LiteSpeed return an error here, so do we.
        let _ = (script_name, path_info);
        tracing::error!(
            vhost = %ctx.vhost_name,
            script = %script_abs.display(),
            "script handler resolved but PHP pool unavailable; refusing to serve as static"
        );
        // Through cache_store: a retained entry serves as the stale-if-error
        // fallback instead of the 503 (the PHP-disabled / lsphp-down class).
        return lscache::cache_store(state, ctx, &cc, error_page(StatusCode::SERVICE_UNAVAILABLE))
            .await;
    }

    // ---- 8. Static -------------------------------------------------------
    // (#9b) Honor a matching static <context> location override + extraHeaders
    // (the mcp.forum.example hybrid docroot). Capture both as owned data BEFORE
    // the `&mut ctx` borrow needed to serve the file (the context borrows ctx).
    let (static_extra_headers, static_location, static_charset): (
        Option<Vec<(String, String)>>,
        Option<PathBuf>,
        Option<String>,
    ) = match matching_static_context(ctx, &cur_path) {
        Some(c) => (
            Some(c.extra_headers.clone()),
            c.location.clone(),
            effective_static_charset(c),
        ),
        None => (None, None, None),
    };
    // The location override only takes effect when it actually differs from the
    // vhost docroot; pinned via the DocRootOverride extension the static handler reads.
    if let Some(loc) = static_location {
        if loc != ctx.vhost.doc_root {
            req.extensions_mut().insert(hj_static::DocRootOverride(loc));
        }
    }
    if let Some(charset) = static_charset {
        req.extensions_mut()
            .insert(hj_static::DefaultCharsetOverride(charset));
    }
    if let Some(index_files) = htaccess_index_files(&chain) {
        req.extensions_mut()
            .insert(hj_static::IndexFilesOverride(index_files.to_vec()));
    }

    // Static: if a rewrite changed the path, serve the rewritten file. The
    // terminal handlers percent-DECODE `req.uri()`, while `cur_path` is already
    // decoded (the rewrite engine operates on the decoded path), so re-encode it
    // before injecting — otherwise a path containing a literal `%` (or `?`/`#`)
    // would be double-decoded by the handler. A single decode then recovers the
    // exact `cur_path` the access check and rewrite engine already saw (#1).
    if rewritten && cur_path.as_ref() != orig_path.as_str() {
        let encoded;
        let target = if needs_encoding(cur_path.as_ref()) {
            encoded = percent_encode_path(cur_path.as_ref());
            encoded.as_str()
        } else {
            cur_path.as_ref()
        };
        match build_uri(target, &cur_query) {
            Some(uri) => *req.uri_mut() = uri,
            // Fail closed: an unparsable rewritten target must not silently
            // keep the PRE-rewrite URI in `req` — the static handler would
            // then serve a file other than the one whose access checks just
            // passed. Render 400 like any other rejected request target.
            None => {
                return error_doc_or_page(state, ctx, &chain, &orig_path, StatusCode::BAD_REQUEST)
                    .await;
            }
        }
    }
    state
        .telemetry
        .shard()
        .served_static
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut resp = run_handler(&state.static_handler, ctx, req).await;
    if resolved_static_target_denied(&state.acl, &resp) {
        return error_doc_or_page(state, ctx, &chain, &cur_path, StatusCode::FORBIDDEN).await;
    }
    // Apply the static context's extra headers (Vary / Cache-Control) first,
    // then the .htaccess response-header ops + error documents.
    if let Some(extra) = static_extra_headers {
        apply_static_context_headers(&extra, &mut resp);
    }
    finalize_response(
        state, ctx, &chain, &rel_path, &orig_path, &cur_path, &mut resp,
    )
    .await;
    lscache::cache_store(state, ctx, &cc, resp).await
}

fn resolved_static_target_denied(acl: &hj_acl::AccessControl, resp: &Response) -> bool {
    resp.extensions()
        .get::<hj_static::ResolvedTargetPath>()
        .is_some_and(|target| acl.deny_dir_match(&target.0))
}

fn allowed_script_target(acl: &hj_acl::AccessControl, script: &Path) -> Option<PathBuf> {
    let target = opened_target_path(script).ok()?;
    (!acl.deny_dir_match(&target)).then_some(target)
}

fn opened_target_path(path: &Path) -> std::io::Result<PathBuf> {
    // (security #266) NONBLOCK + regular-file check: `path` is attacker-nameable
    // (.htaccess-derived script target), so a planted FIFO must fail fast here
    // instead of parking the executor thread inside open(2) — same treatment as
    // hj-static's open_beneath.
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let meta = rustix::fs::fstat(&file).map_err(std::io::Error::from)?;
    // S_IFMT type bits: 0100000 = regular file (Linux).
    const S_IFREG: u32 = 0o100000;
    if meta.st_mode & 0o170000 != S_IFREG {
        return Err(std::io::Error::from(rustix::io::Errno::NXIO));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        if let Ok(target) = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())) {
            return Ok(target);
        }
    }
    drop(file);
    path.canonicalize()
}

fn effective_static_charset(context: &hj_core::config::Context) -> Option<String> {
    context.add_default_charset.then(|| {
        context
            .charset
            .clone()
            .unwrap_or_else(|| "UTF-8".to_string())
    })
}

/// Post-dispatch transforms shared by the terminal handlers: apply the
/// `.htaccess` response-header ops (#2/#7) and, for an httpjet-generated 4xx/5xx,
/// swap in an `ErrorDocument` body (#8a).
///
/// Async because an `ErrorDocument` whose target is a `.php` file is an internal
/// LSAPI subrequest that RUNS the script (#3) — Apache/LiteSpeed parity — rather
/// than reading and disclosing its raw source.
async fn finalize_response(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
    chain: &[Arc<Htaccess>],
    rel_path: &str,
    request_path: &str,
    cur_path: &str,
    resp: &mut Response,
) {
    apply_response_headers_for_request(ctx, chain, rel_path, request_path, resp);
    apply_error_document(state, ctx, chain, cur_path, resp).await;
}

/// (#9a) Build the effective PHP suffix set for a vhost. Per-suffix override,
/// mirroring OpenLiteSpeed (`HttpMime::mergeHandlerList`): a per-vhost
/// `<scriptHandler>` whose `<type>` is `lsapi` ADDS its suffix to the global set;
/// any other (non-LSAPI, e.g. `static`) handler REMOVES its suffix. This lets a
/// vhost run `.php` through lsphp while serving `.html` statically even when the
/// global `phpConfig` maps both. Returns a borrowed reference to the global set
/// (no allocation) when the vhost changes nothing.
pub(super) fn effective_php_suffixes<'s>(
    state: &'s ServerState,
    ctx: &ReqCtx,
) -> std::borrow::Cow<'s, std::collections::HashSet<String>> {
    compute_php_suffixes(&state.php_suffixes, &ctx.vhost.script_handlers)
}

/// Pure core of [`effective_php_suffixes`]: `global` ∪ (lsapi suffixes) \ (non-lsapi
/// suffixes). Independent of `ServerState`/`ReqCtx` so it can be unit-tested.
fn compute_php_suffixes<'a>(
    global: &'a std::collections::HashSet<String>,
    handlers: &[hj_core::config::ScriptHandler],
) -> std::borrow::Cow<'a, std::collections::HashSet<String>> {
    use hj_core::config::ContextKind;
    use std::borrow::Cow;

    let mut adds: Vec<String> = Vec::new();
    let mut removes: Vec<String> = Vec::new();
    for sh in handlers {
        let suffix = sh.suffix.to_ascii_lowercase();
        if sh.kind == ContextKind::Lsapi {
            if !global.contains(&suffix) {
                adds.push(suffix);
            }
        } else if global.contains(&suffix) {
            removes.push(suffix);
        }
    }
    if adds.is_empty() && removes.is_empty() {
        return Cow::Borrowed(global);
    }
    let mut set = global.clone();
    set.extend(adds);
    for r in &removes {
        set.remove(r);
    }
    Cow::Owned(set)
}

/// Resolve the per-vhost lsphp [`JailConfig`] for the current request.
///
/// Feeds the vhost's parsed isolation intent (`ctx.vhost.isolation`), its
/// `doc_root`, the declared `vh_root` (from the server's vhost declaration), the
/// server-wide `suexec` policy, and `getuid()==0` into [`JailConfig::resolve`],
/// which applies all the dev-safety gates and fail-closed checks. With suEXEC off
/// / non-root / no per-vhost isolation this yields the all-None jail (the default
/// `"php"` pool, today's behavior).
pub(super) fn resolve_vhost_jail(state: &ServerState, ctx: &ReqCtx) -> std::io::Result<JailConfig> {
    let vh_root: PathBuf = state
        .server
        .vhosts
        .get(&ctx.vhost_name)
        .map(|d| d.vh_root.clone())
        .unwrap_or_else(|| ctx.vhost.doc_root.clone());
    let is_root = rustix::process::getuid().is_root();
    JailConfig::resolve(
        ctx.vhost.isolation.as_ref(),
        &ctx.vhost.doc_root,
        &vh_root,
        &state.server.suexec,
        is_root,
    )
}

pub(super) async fn run_handler<H: Handler>(h: &H, ctx: &mut ReqCtx, req: Request) -> Response {
    // Capture before `handle` consumes `req`, for the 5xx-with-cause log below.
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    match h.handle(ctx, req).await {
        Ok(resp) => resp,
        Err(err) => {
            let status = err.status();
            if status.is_server_error() {
                // (item 4) One structured line per genuine 5xx so the access-log
                // status code is greppable to its cause in the error log.
                tracing::warn!(
                    request_id = %ctx.request_id, vhost = %ctx.vhost_name, method = %method,
                    path = %path, status = status.as_u16(), cause = %err, "5xx serving error"
                );
            } else {
                // Expected 4xx (403/404/410/…): quiet.
                tracing::debug!(vhost = %ctx.vhost_name, error = %err, "handler error");
            }
            error_page(status)
        }
    }
}

/// (#2) Decide the HTTPS redirect target for a plaintext request to an
/// mTLS-required vhost. Returns `None` for the ACME http-01 challenge path (which
/// must stay reachable over plaintext for certificate issuance), otherwise the
/// `https://host/path[?query]` location to 301-redirect to. Pure for testing.
fn mtls_https_redirect_target(host: &str, path: &str, query: Option<&str>) -> Option<String> {
    // (security #259) The ACME http-01 exemption applies ONLY when the path, AFTER the
    // same dot-segment normalization dispatch() performs, is exactly
    // /.well-known/acme-challenge/<token> with a single RFC 8555 token segment. The old
    // RAW-prefix check combined with dispatch's later normalization let
    // /acme-challenge/x/../../../threads serve backend content over plaintext :80,
    // bypassing the mTLS trust boundary (and every Cloudflare control) for all vhosts.
    if acme_challenge_token(path).is_some() {
        return None;
    }
    Some(match query {
        Some(q) if !q.is_empty() => format!("https://{host}{path}?{q}"),
        _ => format!("https://{host}{path}"),
    })
}

/// The ACME challenge token iff `path` normalizes to exactly one token under
/// /.well-known/acme-challenge/ — else None (the caller must redirect).
fn acme_challenge_token(path: &str) -> Option<String> {
    let rest = normalized_request_path(path)
        .strip_prefix("/.well-known/acme-challenge/")?
        .to_string();
    if rest.is_empty()
        || rest.contains('/')
        || rest.starts_with('.')
        || !rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(rest)
}

/// (#2) Whether the mTLS trust-boundary gate should force a plaintext request to
/// HTTPS. True only when the request is NOT already on TLS, its vhost is one a
/// secure listener requires a client cert for, AND the peer is not an exempt
/// loopback / private-LAN internal caller. Internal peers (on-box services, the
/// active-active peer node, health checks — same exemption as the `:443`
/// app-layer client-cert check in `hj-tls`) reach plaintext `:80` directly.
/// Pure for testing.
fn mtls_gate_redirects(is_tls: bool, vhost_requires_mtls: bool, peer_ip: IpAddr) -> bool {
    !is_tls && vhost_requires_mtls && !hj_core::is_trusted_internal_peer(peer_ip)
}

/// Effective request scheme: the client is on HTTPS if the connection is physically TLS,
/// or a **trusted proxy** asserts https via a forwarded header. The `trusted_proxy` gate
/// is the security boundary — without it, a direct `:80` client could spoof
/// `X-Forwarded-Proto: https` and walk past the mTLS gate / be served as secure.
fn effective_request_https(
    physical_tls: bool,
    trusted_proxy: bool,
    headers: &http::HeaderMap,
) -> bool {
    physical_tls || (trusted_proxy && forwarded_scheme_is_https(headers))
}

/// Whether a trusted proxy has asserted the client's request is HTTPS — via either
/// `CF-Visitor: {"scheme":"https"}` (Cloudflare) or `X-Forwarded-Proto: https` (generic
/// reverse proxies). The caller MUST have already confirmed the peer is a trusted proxy:
/// these headers are client-controlled, so honoring them from an untrusted peer would let
/// a direct `:80` client spoof `https` and bypass the mTLS trust-boundary gate.
fn forwarded_scheme_is_https(headers: &http::HeaderMap) -> bool {
    if let Some(v) = headers.get("cf-visitor").and_then(|v| v.to_str().ok()) {
        // A small JSON object, e.g. `{"scheme":"https"}` (interior spacing varies).
        if v.split_whitespace()
            .collect::<String>()
            .contains("\"scheme\":\"https\"")
        {
            return true;
        }
    }
    if let Some(v) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        // A proxy chain may comma-join; the left-most is the original client scheme.
        if v.split(',')
            .next()
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("https"))
        {
            return true;
        }
    }
    false
}

/// Stop origin-issued redirects from being cached by a shared cache (Cloudflare) and
/// replayed under a normalized key — the "Too Many Redirects" loop class.
///
/// A redirect that a shared cache stores can be replayed under a cache key that no longer
/// captures what determined the redirect's target, and then it loops. Two real variants:
/// - **Cross-scheme:** a plain-HTTP (`:80`) request makes XenForo emit `301 → https://<same
///   url>`; cached scheme-blind, it is replayed to HTTPS clients → redirect-to-self loop.
/// - **Slug canonicalization:** a non-canonical thread slug makes XenForo emit `301 →
///   <canonical slug>` that its LSCache add-on marks publicly cacheable for 7 days (incl.
///   `cloudflare-cdn-cache-control`, the header Cloudflare honors above `Cache-Control`).
///   Cloudflare keys thread URLs slug-blind (by id), so that 301 becomes the cache entry for
///   the *canonical* slug too — the canonical URL then redirects to itself → the loop. This
///   one is same-scheme over HTTPS, which the earlier cross-scheme-only guard missed.
///
/// httpjet's own page cache keys correctly (scheme + original URI, commit dd2054b) so it
/// never mis-replays; but a per-process key cannot constrain Cloudflare's edge. The default
/// origin-side defense is to make redirects uncacheable by shared caches: drop the CDN-cache
/// directives and downgrade `Cache-Control` to `private, no-store`. A small allow-list lets
/// XenForo explicitly opt vetted, cookie-free redirects back into shared caching after the
/// app has confirmed the target is stable and non-user-specific. Only responses that actually
/// carry a `Location` are touched, so a `304 Not Modified` (also 3xx, but no `Location`) keeps
/// its cacheability.
fn deny_redirect_cdn_caching(resp: &mut Response) {
    if !resp.status().is_redirection() || !resp.headers().contains_key(http::header::LOCATION) {
        return;
    }
    if explicit_cacheable_redirect(resp) {
        return;
    }
    let h = resp.headers_mut();
    h.remove("cloudflare-cdn-cache-control");
    h.remove("cdn-cache-control");
    h.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("private, no-store"),
    );
}

fn explicit_cacheable_redirect(resp: &Response) -> bool {
    if resp.headers().contains_key(http::header::SET_COOKIE) {
        return false;
    }
    let Some(label) = resp
        .headers()
        .get("x-cache-optimizer")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    if !cache_optimizer_allows_redirect_cdn_cache(label) {
        return false;
    }
    response_has_public_cache_control(resp)
}

fn cache_optimizer_allows_redirect_cdn_cache(label: &str) -> bool {
    matches!(
        label,
        "redirect-temp-302"
            | "redirect-temp-303"
            | "unfurl-image-redirect"
            // Generic permanent redirects (slug canonicalization, tag/member/
            // forum trailing-slash forms the edge rule can't know). The origin
            // labels these ONLY after its isSelfRedirect guard has excluded
            // loop shapes, and the labeled-self-redirect hard-deny in
            // DenyRedirectCdnTransform backstops that guard at this layer.
            | "redirect-301"
            | "redirect-308"
            // Guest attachment-page 303s to the public R2 custom domain
            // (stable Location; the origin guards host + non-presigned form).
            | "redirect-attach-303"
    ) || label
        .strip_prefix("redirect-thread-post-")
        .is_some_and(|code| matches!(code, "301" | "308"))
}

/// Merge rewrite-chain `[E=…]` sets into `ctx.env`. Names under the internal
/// `HJ_` prefix are reserved for request-identity plumbing (e.g.
/// `HJ_CACHE_REFRESH`) that a config rule must never be able to overwrite.
/// Reserved keys are skipped with a warning instead of poisoning the
/// pipeline's view of the request.
fn merge_rewrite_env(ctx: &mut ReqCtx, env: Vec<(String, String)>) {
    for (k, v) in env {
        if !htaccess_apply::env_key_allowed(&k) {
            tracing::warn!(
                request_id = %ctx.request_id,
                key = %k,
                "rewrite [E=] targets the reserved HJ_ env prefix; ignored"
            );
            continue;
        }
        ctx.set_env(k, v);
    }
}

/// Stash the request identity the redirect-decache transform needs (it only
/// sees `ctx`): the ORIGINAL raw path+query (Bytes-backed, rendered lazily on
/// 3xx) and the request host (already lowercased + port-stripped by
/// `lscache::request_host`). Called on BOTH entry paths — `handle` and
/// `fast_serve` — the labeled-self-redirect hard-deny is inert without it.
fn set_redirect_guard(ctx: &mut ReqCtx, uri: &http::Uri, req_host: &str) {
    ctx.redirect_guard = Some(hj_core::RedirectGuard::new(
        req_host.to_string(),
        uri.path_and_query().cloned(),
    ));
}

/// True when an absolute redirect target's host matches NEITHER the serving
/// vhost's canonical name NOR the request's own Host (modulo case, port, and a
/// bare `www.`). The request host matters because a vhost can carry exact
/// alias hostnames: a backend that reflects the alias into an absolute
/// self-Location must not slip past the self-redirect deny as "cross-host".
/// `req_host` is the pre-normalized `HJ_REQUEST_HOST` value.
fn location_host_is_foreign(loc_host: &str, vhost_name: &str, req_host: Option<&str>) -> bool {
    let strip_www = |h: &str| h.strip_prefix("www.").unwrap_or(h).to_string();
    let l = strip_www(loc_host);
    if l == strip_www(&vhost_name.to_ascii_lowercase()) {
        return false;
    }
    !req_host.is_some_and(|h| l == strip_www(h))
}

/// Hard-deny a SELF-redirect even when it carries an allow-listed label — the
/// belt-and-braces layer for the "Too Many Redirects" incident class now that
/// generic `redirect-301`/`redirect-308` are allow-listed. The origin's
/// isSelfRedirect guard normally prevents a labeled self-loop from ever being
/// emitted; this catches a regression there before Cloudflare can pin a loop.
/// Deliberately SCHEME-BLIND: the http->https upgrade for the same path+query
/// is the exact shape a scheme-blind shared cache replays into a loop (the
/// cache_scheme_test contract), so it is denied too — the origin may label it
/// cacheable, but only the terminal (different-path) hop may keep CDN headers.
/// Returns true when it de-cached the response (caller should stop).
fn deny_labeled_self_redirect(req_path_query: &str, resp: &mut Response) -> bool {
    if !resp.status().is_redirection() || req_path_query.is_empty() {
        return false;
    }
    let Some(loc) = resp
        .headers()
        .get(http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(loc_pq) = redirect_target_path_query(loc) else {
        return false;
    };
    // Percent-normalized compare (unreserved bytes only): Cloudflare normalizes
    // its cache key the same way, so `/a%5Fb` and `/a_b` share ONE edge entry —
    // a labeled redirect between them replays as a loop even though the raw
    // strings differ. Same rule as lscache::normalize_self_redirect_pq.
    if lscache::normalize_self_redirect_pq(&loc_pq)
        != lscache::normalize_self_redirect_pq(req_path_query)
    {
        return false;
    }
    let h = resp.headers_mut();
    h.remove("cloudflare-cdn-cache-control");
    h.remove("cdn-cache-control");
    h.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("private, no-store"),
    );
    true
}

/// Path+query of a redirect target, fragment stripped: `/a/b?c=d` for the
/// relative, absolute http(s) (scheme case-insensitive), and protocol-relative
/// forms. A bare-authority target (`https://host`, `https://host?q`) is an
/// implicit root (`/`, `/?q`). `None` only for non-http schemes and
/// relative-without-leading-slash forms (don't guess).
fn redirect_target_path_query(loc: &str) -> Option<String> {
    let loc = loc.split('#').next().unwrap_or(loc);
    let rest = if let Some(rest) = lscache::strip_ascii_prefix(loc, "https://")
        .or_else(|| lscache::strip_ascii_prefix(loc, "http://"))
        .or_else(|| loc.strip_prefix("//").filter(|r| !r.starts_with('/')))
    {
        rest
    } else if loc.starts_with('/') && !loc.starts_with("//") {
        return Some(loc.to_string());
    } else {
        return None;
    };
    match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => Some(rest[i..].to_string()),
        Some(i) => Some(format!("/{}", &rest[i..])),
        None => Some("/".to_string()),
    }
}

fn response_has_public_cache_control(resp: &Response) -> bool {
    let mut public = false;
    for value in resp.headers().get_all(http::header::CACHE_CONTROL).iter() {
        let Ok(value) = value.to_str() else {
            return false;
        };
        if cache_control_blocks_shared_cache(value) {
            return false;
        }
        if cache_control_has_public(value) {
            public = true;
        }
    }
    for name in ["cloudflare-cdn-cache-control", "cdn-cache-control"] {
        for value in resp.headers().get_all(name).iter() {
            let Ok(value) = value.to_str() else {
                return false;
            };
            if cache_control_blocks_shared_cache(value) {
                return false;
            }
        }
    }
    public
}

fn cache_control_has_public(value: &str) -> bool {
    value
        .split(',')
        .any(|directive| directive.trim().eq_ignore_ascii_case("public"))
}

fn cache_control_blocks_shared_cache(value: &str) -> bool {
    value.split(',').any(|directive| {
        let name = directive
            .trim()
            .split_once('=')
            .map_or(directive.trim(), |(name, _)| name.trim());
        name.eq_ignore_ascii_case("private")
            || name.eq_ignore_ascii_case("no-store")
            || name.eq_ignore_ascii_case("no-cache")
    })
}

/// Make EVERY response under a FOREIGN Host uncacheable by a shared cache (Cloudflare) — for
/// any status, not just redirects (which [`deny_redirect_cdn_caching`] already covers).
///
/// A Host that reached its vhost only via the `*` wildcard or a subdomain fallback (see
/// `handle`'s `host_foreign`) is non-canonical. Cloudflare edge-caches PER HOSTNAME, so a
/// `public`/`s-maxage` response under such a host gets stored under *that brand's* zone — one
/// brand's body served at another brand's URL (the foreign-host regression). The page cache
/// already bypasses foreign hosts, but the origin still SENDS the response; this strips its
/// shared-cacheability so the edge can never store it. The response still works — the foreign
/// host just isn't edge-cached (it should be getting the backend's canonical redirect anyway).
///
/// Overwriting `Cache-Control` wholesale subsumes any `public`/`s-maxage`/`max-age` the
/// backend set (no token surgery); `Expires` is dropped too, since it is an independent
/// shared-cache freshness signal that could otherwise keep a `no-store` response cacheable.
fn deny_foreign_host_cdn_caching(resp: &mut Response) {
    let h = resp.headers_mut();
    h.remove("cloudflare-cdn-cache-control");
    h.remove("cdn-cache-control");
    h.remove(http::header::EXPIRES);
    h.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("private, no-store"),
    );
}

/// Load a static file into memory via the unified cache and replace the response
/// body with `Body::Full`. This serves hot files from RAM/tmpfs and lets the gzip
/// transform compress them (it can only compress in-memory bodies). Large files
/// are left as `Body::File` to stream from disk.
pub(super) fn maybe_cache_static(
    static_cache: &hj_pagecache::PageStore,
    vhost_id: u32,
    resp: &mut Response,
) {
    if resp.headers().contains_key("x-litespeed-cache") {
        return;
    }
    // A ranged (206) response keeps its Body::File but gets the cache's bytes
    // ATTACHED via the FileBody.cached seam — every transport already slices
    // cached bytes by the range, so a range over a hot cached file serves with
    // zero syscalls instead of an open+seek+read per request. Full 200 bodies
    // are promoted to Body::Full below (unchanged).
    let ranged = resp.status() == StatusCode::PARTIAL_CONTENT;
    if !ranged && resp.status() != StatusCode::OK {
        return;
    }
    let (path, len) = match resp.body() {
        Body::File(f) if f.range.is_some() == ranged && f.cached.is_none() => {
            (f.path.clone(), f.len)
        }
        _ => return,
    };
    if len > static_cache.config().max_static_obj_bytes {
        return;
    }
    let ct = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let etag = header_value_string(resp.headers(), http::header::ETAG);
    let last_modified = header_value_string(resp.headers(), http::header::LAST_MODIFIED);
    if let Some(bytes) = static_cached_bytes(
        static_cache,
        vhost_id,
        &path,
        len,
        ct,
        etag,
        last_modified,
        StaticReadMode::TokioBlocking,
    ) {
        if ranged {
            if let Body::File(f) = resp.body_mut() {
                f.cached = Some(bytes);
            }
        } else {
            *resp.body_mut() = Body::Full(bytes);
        }
    }
}

#[derive(Clone, Copy)]
enum StaticReadMode {
    Direct,
    TokioBlocking,
}

#[allow(clippy::too_many_arguments)]
fn static_cached_bytes(
    cache: &hj_pagecache::PageStore,
    vhost_id: u32,
    path: &std::path::Path,
    len: u64,
    content_type: String,
    etag: String,
    last_modified: String,
    read_mode: StaticReadMode,
) -> Option<bytes::Bytes> {
    if len > cache.config().max_static_obj_bytes {
        return None;
    }
    let fresh_id = match hj_pagecache::FileId::stat(path) {
        Ok(id) => id,
        Err(_) => {
            cache.invalidate_static(vhost_id, path);
            return None;
        }
    };
    if fresh_id.size != len {
        cache.invalidate_static(vhost_id, path);
        return None;
    }
    if let Some(entry) = cache.get_static(vhost_id, path, &fresh_id, std::time::Instant::now()) {
        match cache.static_body_bytes(&entry) {
            Some(bytes) if bytes.len() as u64 == len => return Some(bytes),
            _ => {
                cache.invalidate_static(vhost_id, path);
                return None;
            }
        }
    }
    let read = || std::fs::read(path);
    let bytes = match read_mode {
        StaticReadMode::Direct => read().ok()?,
        StaticReadMode::TokioBlocking => tokio::task::block_in_place(read).ok()?,
    };
    if bytes.len() as u64 != len {
        return None;
    }
    let bytes = bytes::Bytes::from(bytes);
    let _ = cache.store_static(
        vhost_id,
        path,
        fresh_id,
        bytes.clone(),
        Arc::<str>::from(content_type),
        etag,
        last_modified,
    );
    Some(bytes)
}

fn header_value_string(headers: &http::HeaderMap, name: http::header::HeaderName) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn header_str(req: &Request, name: http::header::HeaderName) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// The request method as a `&'static str` for the access log, with no allocation for the
/// standard verbs (all CF-fronted traffic). A non-standard/custom method (rare) is owned.
fn method_static(m: &http::Method) -> Cow<'static, str> {
    match *m {
        http::Method::GET => Cow::Borrowed("GET"),
        http::Method::POST => Cow::Borrowed("POST"),
        http::Method::HEAD => Cow::Borrowed("HEAD"),
        http::Method::PUT => Cow::Borrowed("PUT"),
        http::Method::DELETE => Cow::Borrowed("DELETE"),
        http::Method::OPTIONS => Cow::Borrowed("OPTIONS"),
        http::Method::PATCH => Cow::Borrowed("PATCH"),
        http::Method::TRACE => Cow::Borrowed("TRACE"),
        http::Method::CONNECT => Cow::Borrowed("CONNECT"),
        ref other => Cow::Owned(other.as_str().to_string()),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Apply `expiresByType` Cache-Control/Expires headers to cacheable static
/// responses (200/206 with a content-type, no existing Cache-Control).
pub(super) fn apply_expires(expires: &hj_compress::ExpiresRules, now: i64, resp: &mut Response) {
    if expires.is_empty() {
        return;
    }
    let status = resp.status();
    if status != StatusCode::OK && status != StatusCode::PARTIAL_CONTENT {
        return;
    }
    if resp.headers().contains_key(http::header::CACHE_CONTROL) {
        return;
    }
    let rule = match resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|ct| expires.lookup(ct))
    {
        Some(r) => r,
        None => return,
    };
    let last_mod = resp
        .headers()
        .get(http::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| httpdate::parse_http_date(s).ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(now);
    let h = ExpiresHeaders::compute(rule, now, last_mod);
    if let Ok(v) = http::HeaderValue::from_str(&h.cache_control) {
        resp.headers_mut().insert(http::header::CACHE_CONTROL, v);
    }
    // Same-second responses under one rule share an expiry instant, so memo the last
    // rendered `Expires` value per thread instead of re-formatting the HTTP date for
    // every static response (this transform never runs on page-cache hits — they
    // carry Cache-Control — so the memo serves the static fan-out).
    std::thread_local! {
        static EXPIRES_MEMO: std::cell::RefCell<(i64, http::HeaderValue)> =
            std::cell::RefCell::new((i64::MIN, http::HeaderValue::from_static("0")));
    }
    let key = h.expire_unix.max(0);
    let memo = EXPIRES_MEMO.with(|m| {
        let mut m = m.borrow_mut();
        if m.0 != key {
            let s = httpdate::fmt_http_date(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(key as u64),
            );
            match http::HeaderValue::from_str(&s) {
                Ok(hv) => *m = (key, hv),
                Err(_) => return None,
            }
        }
        Some(m.1.clone())
    });
    if let Some(v) = memo {
        resp.headers_mut().insert(http::header::EXPIRES, v);
    }
}

// ---- Response-transform pipeline (the post-handler stage) ------------------
// Each transform mutates the outgoing response in order; a future transform plugs into
// `ServerState::transforms` without touching handle(). The Vec order reproduces the
// historical sequence exactly: cache-small-static (so gzip can compress it) -> expires ->
// compress -> deny-CDN-cache-on-redirects -> advertise-h3. Built once per ServerState.

/// Promote a small static `Body::File` to an in-memory `Body::Full` (lets gzip run).
pub(crate) struct CacheStaticTransform {
    pub static_cache: std::sync::Arc<hj_pagecache::PageStore>,
}
#[async_trait]
impl ResponseTransform for CacheStaticTransform {
    async fn transform(&self, ctx: &ReqCtx, resp: &mut Response) {
        maybe_cache_static(
            &self.static_cache,
            crate::lscache::vhost_id_hash(&ctx.vhost_name),
            resp,
        );
    }
}

/// Apply `expiresByType` Cache-Control/Expires to cacheable static responses.
pub(crate) struct ExpiresTransform {
    pub expires: std::sync::Arc<hj_compress::ExpiresRules>,
    /// Per-vhost `<expires>` overrides (audit): a vhost with its own enabled block
    /// replaces the server-wide rules for its requests; everyone else falls back.
    pub vhost_expires: std::collections::HashMap<String, std::sync::Arc<hj_compress::ExpiresRules>>,
}
#[async_trait]
impl ResponseTransform for ExpiresTransform {
    async fn transform(&self, ctx: &ReqCtx, resp: &mut Response) {
        // Expiry is relative to the request's arrival stamp — one clock read per
        // request (taken at ReqCtx build) instead of another here.
        let now = ctx
            .request_time
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_else(|_| unix_now());
        let rules = self
            .vhost_expires
            .get(&ctx.vhost_name)
            .unwrap_or(&self.expires);
        apply_expires(rules, now, resp);
    }
}

/// Make any origin redirect non-shared-cacheable (the CF "Too Many Redirects" class) —
/// EXCEPT cross-host redirects. Every loop variant the guard exists for (scheme-blind
/// replay, slug canonicalization) requires the Location to land back on the SAME host;
/// a redirect whose absolute target host differs from the serving vhost (modulo a bare
/// `www.`) cannot be cached into a loop, and denying it would defeat deliberate offload
/// redirects (the news img-proxy 301s to the CF-bound R2 attachments domain, which this
/// origin does not serve at all).
pub(crate) struct DenyRedirectCdnTransform;
#[async_trait]
impl ResponseTransform for DenyRedirectCdnTransform {
    async fn transform(&self, ctx: &ReqCtx, resp: &mut Response) {
        deny_redirect_cdn_headers(ctx, resp);
        // The label is internal metadata (origin CacheOptimizer -> this
        // transform). The page-cache stored copy KEEPS it — a hit re-runs this
        // transform and needs it (cache_store runs before egress transforms) —
        // but it must not leak to Cloudflare/clients, so strip after the
        // evaluation above, on every exit path.
        resp.headers_mut().remove("x-cache-optimizer");
    }
}

fn deny_redirect_cdn_headers(ctx: &ReqCtx, resp: &mut Response) {
    if resp.status().is_redirection() {
        if let Some(host) = resp
            .headers()
            .get(http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .and_then(redirect_target_host)
        {
            let req_host = ctx.redirect_guard.as_ref().map(|g| g.host.as_str());
            if location_host_is_foreign(&host, &ctx.vhost_name, req_host) {
                return;
            }
        }
        // Same-host from here down. A labeled self-redirect is de-cached
        // unconditionally (see deny_labeled_self_redirect) — the label
        // allow-list below must never be able to re-cache a loop.
        if let Some(req_pq) = ctx.redirect_guard.as_ref().and_then(|g| g.path_query()) {
            if deny_labeled_self_redirect(req_pq, resp) {
                return;
            }
        }
    }
    deny_redirect_cdn_caching(resp);
}

/// Host of an absolute http(s) (scheme case-insensitive) or protocol-relative
/// (`//host/…`, same-scheme by construction) redirect target, lowercased,
/// port/userinfo stripped. `None` for relative Locations (same-host by
/// definition) or non-http schemes.
fn redirect_target_host(loc: &str) -> Option<String> {
    let rest = lscache::strip_ascii_prefix(loc, "https://")
        .or_else(|| lscache::strip_ascii_prefix(loc, "http://"))
        .or_else(|| loc.strip_prefix("//").filter(|r| !r.starts_with('/')))?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..end];
    let host = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    // IPv6-aware port strip: a naive `rsplit_once(':')` splits inside a `[::1]`
    // literal and mangles the host. Reuse the shared normalizer the rest of the
    // pipeline / page-cache host key already use (it also lowercases).
    let host = hj_core::host_without_port(host);
    (!host.is_empty()).then_some(host)
}

/// Advertise HTTP/3 to TLS clients via `Alt-Svc` (cheap pre-parsed HeaderValue clone).
pub(crate) struct AltSvcTransform {
    pub alt_svc: Option<http::HeaderValue>,
}
#[async_trait]
impl ResponseTransform for AltSvcTransform {
    async fn transform(&self, ctx: &ReqCtx, resp: &mut Response) {
        if ctx.tls.is_some() && ctx.protocol != Proto::Http3 {
            if let Some(alt) = &self.alt_svc {
                if !resp.headers().contains_key(http::header::ALT_SVC) {
                    resp.headers_mut()
                        .insert(http::header::ALT_SVC, alt.clone());
                }
            }
        }
    }
}

/// Marker on a response that httpjet itself synthesized as an error page (every
/// `error_page()` output). The `.htaccess` `ErrorDocument` body-swap (#8a) keys on
/// this — NOT on the body variant — because a small buffered backend (LSAPI/proxy)
/// error takes the fast path and is delivered as a `Body::Full`, the same variant
/// as a built-in error page. Without this tag, an app's own 4xx/5xx body (e.g.
/// chat.php's `{captcha_required:true}` JSON 403) would be clobbered by the custom
/// error page. See `is_generated_error_body`.
#[derive(Clone, Copy)]
pub(super) struct GeneratedErrorPage;

fn error_page(status: StatusCode) -> Response {
    let reason = status.canonical_reason().unwrap_or("Error");
    let body = format!(
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>{code} {reason}</title>\n</head><body>\n<h1>{reason}</h1>\n</body></html>\n",
        code = status.as_u16()
    );
    let mut resp = Response::new(Body::Full(bytes::Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/html"),
    );
    resp.extensions_mut().insert(GeneratedErrorPage);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_session_cookie_classification() {
        // Member marker present (either name, any case, any position).
        assert!(has_member_session_cookie(
            "xf_style_variation=dark; xf_user=42",
            "xf_session",
            "xf_user"
        ));
        assert!(has_member_session_cookie(
            "XF_SESSION=abc; theme=x",
            "xf_session",
            "xf_user"
        ));
        assert!(has_member_session_cookie(
            "consent=1; xf_session=abc",
            "xf_session",
            "xf_user"
        ));
        // Benign-only: vary/analytics-style names without markers.
        assert!(!has_member_session_cookie(
            "xf_style_variation=dark; xf_style_id=3; consent=1",
            "xf_session",
            "xf_user"
        ));
        assert!(!has_member_session_cookie(
            "cf_bm=abc",
            "xf_session",
            "xf_user"
        ));
        // A marker PREFIX must not match (name equality, not prefix).
        assert!(!has_member_session_cookie(
            "xf_username=evil",
            "xf_session",
            "xf_user"
        ));
        // Values containing the marker name don't count (names before '=' only).
        assert!(!has_member_session_cookie(
            "theme=xf_user",
            "xf_session",
            "xf_user"
        ));
        // Empty configured names never match.
        assert!(!has_member_session_cookie("xf_session=abc", "", "xf_user"));
    }

    #[test]
    fn revalidation_request_is_an_unconditional_get_with_vary_inputs() {
        let req = http::Request::builder()
            .method(http::Method::HEAD)
            .uri("/threads/example.1/?page=2")
            .version(http::Version::HTTP_3)
            .header(http::header::HOST, "example.com")
            .header(COOKIE, "style=4; language=2")
            .header(http::header::ACCEPT_ENCODING, "br, gzip")
            .header(http::header::IF_MATCH, "\"old\"")
            .header(http::header::IF_NONE_MATCH, "\"old\"")
            .header(
                http::header::IF_MODIFIED_SINCE,
                "Wed, 21 Oct 2015 07:28:00 GMT",
            )
            .header(
                http::header::IF_UNMODIFIED_SINCE,
                "Wed, 21 Oct 2015 07:28:00 GMT",
            )
            .header(http::header::IF_RANGE, "\"old\"")
            .header(http::header::RANGE, "bytes=0-99")
            .header(http::header::CONTENT_LENGTH, "123")
            .header(http::header::TRANSFER_ENCODING, "chunked")
            .header(http::header::EXPECT, "100-continue")
            .body(hj_core::empty_incoming())
            .unwrap();

        let sub = build_revalidation_request(&req, RefreshCookie::Preserve);
        assert_eq!(sub.method(), http::Method::GET);
        assert_eq!(sub.uri(), req.uri());
        assert_eq!(sub.version(), http::Version::HTTP_3);
        assert_eq!(
            sub.headers().get(http::header::HOST).unwrap(),
            "example.com"
        );
        assert_eq!(sub.headers().get(COOKIE).unwrap(), "style=4; language=2");
        assert_eq!(
            sub.headers().get(http::header::ACCEPT_ENCODING).unwrap(),
            "br, gzip"
        );
        for name in [
            http::header::IF_MATCH,
            http::header::IF_NONE_MATCH,
            http::header::IF_MODIFIED_SINCE,
            http::header::IF_UNMODIFIED_SINCE,
            http::header::IF_RANGE,
            http::header::RANGE,
            http::header::CONTENT_LENGTH,
            http::header::TRANSFER_ENCODING,
            http::header::EXPECT,
        ] {
            assert!(!sub.headers().contains_key(name));
        }
        assert!(sub.extensions().get::<RefreshMode>().is_some());
    }

    #[test]
    fn capsule_revalidation_replaces_private_cookie_with_public_vary_cookie() {
        let req = http::Request::builder()
            .uri("/help/")
            .header(COOKIE, "xf_session=secret; style=4")
            .body(hj_core::empty_incoming())
            .unwrap();

        let sub = build_revalidation_request(
            &req,
            RefreshCookie::Replace(Some(HeaderValue::from_static("style=4"))),
        );
        assert_eq!(sub.headers().get(COOKIE).unwrap(), "style=4");

        let without_public_cookie = build_revalidation_request(&req, RefreshCookie::Replace(None));
        assert!(!without_public_cookie.headers().contains_key(COOKIE));
    }

    #[test]
    fn strip_empty_query_only_touches_bare_question_mark() {
        // Bare "?" (empty query) is dropped, path preserved, query becomes None.
        let u: http::Uri = "/threads/x.1/?".parse().unwrap();
        assert_eq!(u.query(), Some(""));
        let n = strip_empty_query(&u).expect("bare ? should be rewritten");
        assert_eq!(n.path(), "/threads/x.1/");
        assert_eq!(n.query(), None);

        // Root "/?" -> "/".
        let root: http::Uri = "/?".parse().unwrap();
        assert_eq!(strip_empty_query(&root).unwrap().to_string(), "/");

        // No query -> untouched (None so the caller keeps the original).
        assert!(strip_empty_query(&"/threads/x.1/".parse::<http::Uri>().unwrap()).is_none());

        // Non-empty query -> untouched (these are handled/cached normally).
        assert!(strip_empty_query(&"/threads/x.1/?amp=1".parse::<http::Uri>().unwrap()).is_none());
        assert!(strip_empty_query(&"/threads/x.1/?amp".parse::<http::Uri>().unwrap()).is_none());

        // Scheme + authority are preserved when present (absolute-form URI).
        let abs: http::Uri = "https://forum.example/threads/x.1/?".parse().unwrap();
        let n = strip_empty_query(&abs).unwrap();
        assert_eq!(n.scheme_str(), Some("https"));
        assert_eq!(n.authority().map(|a| a.as_str()), Some("forum.example"));
        assert_eq!(n.path(), "/threads/x.1/");
        assert_eq!(n.query(), None);
    }

    #[test]
    fn context_uri_matches_respects_segment_boundary() {
        // Exact + child paths match.
        assert!(context_uri_matches("/ws", "/ws"));
        assert!(context_uri_matches("/ws/", "/ws"));
        assert!(context_uri_matches("/ws/socket", "/ws"));
        assert!(context_uri_matches("/extended/x", "/extended"));
        // Shared-prefix siblings must NOT match (the parity bug).
        assert!(!context_uri_matches("/ws2", "/ws"));
        assert!(!context_uri_matches("/extendedness", "/extended"));
        assert!(!context_uri_matches("/active-clients-x", "/active-clients"));
        // A non-prefix never matches.
        assert!(!context_uri_matches("/other", "/ws"));
        // A mount URI that already ends in '/' keeps prefix semantics on the child.
        assert!(context_uri_matches("/api/v1/x", "/api/v1/"));
        assert!(!context_uri_matches("/api/v1x", "/api/v1/"));
        // The root context matches everything.
        assert!(context_uri_matches("/anything/at/all", "/"));
    }

    #[test]
    fn resolved_static_target_is_checked_against_access_deny_dir() {
        let mut security = hj_core::config::Security::default();
        security.access_deny_dir = vec!["/srv/denied/*".to_string()];
        let acl = hj_acl::AccessControl::from_security(&security).unwrap();
        let mut resp = Response::new(Body::Empty);
        resp.extensions_mut()
            .insert(hj_static::ResolvedTargetPath("/srv/denied/file.txt".into()));
        assert!(resolved_static_target_denied(&acl, &resp));

        let mut allowed = Response::new(Body::Empty);
        allowed
            .extensions_mut()
            .insert(hj_static::ResolvedTargetPath("/srv/public/file.txt".into()));
        assert!(!resolved_static_target_denied(&acl, &allowed));
    }

    #[cfg(unix)]
    #[test]
    fn script_target_is_resolved_once_denied_and_pinned_for_lsapi() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "httpjet-script-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let public = root.join("public");
        let denied = root.join("denied");
        std::fs::create_dir_all(&public).unwrap();
        std::fs::create_dir_all(&denied).unwrap();
        let target = denied.join("index.php");
        std::fs::write(&target, b"<?php echo 1;").unwrap();
        let script = public.join("index.php");
        symlink(&target, &script).unwrap();

        let mut security = hj_core::config::Security::default();
        security.access_deny_dir = vec![format!("{}/*", denied.display())];
        let acl = hj_acl::AccessControl::from_security(&security).unwrap();
        assert!(allowed_script_target(&acl, &script).is_none());

        let allowed = public.join("allowed.php");
        std::fs::write(&allowed, b"<?php echo 2;").unwrap();
        assert_eq!(
            allowed_script_target(&acl, &allowed).unwrap(),
            std::fs::canonicalize(&allowed).unwrap()
        );

        let first = public.join("first.php");
        let second = public.join("second.php");
        let switch = public.join("switch.php");
        std::fs::write(&first, b"first-script").unwrap();
        std::fs::write(&second, b"second-script").unwrap();
        symlink(&first, &switch).unwrap();
        let pinned = allowed_script_target(&acl, &switch).unwrap();
        std::fs::remove_file(&switch).unwrap();
        symlink(&second, &switch).unwrap();
        assert_eq!(std::fs::read(&pinned).unwrap(), b"first-script");
        assert_eq!(
            allowed_script_target(&acl, &switch).unwrap(),
            std::fs::canonicalize(&second).unwrap()
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn static_context_charset_defaults_and_customizes() {
        use hj_core::config::{Context, ContextKind};
        let mut context = Context {
            cache_policy: None,
            max_body_override: None,
            bandwidth_limit: 0,
            timeout_override: None,
            sub_filter: None,
            kind: ContextKind::Static,
            uri: "/assets".into(),
            location: None,
            handler: None,
            enabled: true,
            extra_headers: vec![],
            add_default_charset: false,
            charset: None,
        };
        assert_eq!(effective_static_charset(&context), None);
        context.add_default_charset = true;
        assert_eq!(effective_static_charset(&context).as_deref(), Some("UTF-8"));
        context.charset = Some("ISO-8859-1".into());
        assert_eq!(
            effective_static_charset(&context).as_deref(),
            Some("ISO-8859-1")
        );
    }

    #[test]
    fn php_suffixes_per_vhost_override() {
        use hj_core::config::{ContextKind, ScriptHandler};
        use std::collections::HashSet;

        let global: HashSet<String> = ["php".to_string(), "html".to_string()]
            .into_iter()
            .collect();
        let sh = |suffix: &str, kind| ScriptHandler {
            suffix: suffix.to_string(),
            kind,
            handler: String::new(),
        };

        // No per-vhost handlers -> borrow the global set unchanged (fast path).
        let none = compute_php_suffixes(&global, &[]);
        assert!(matches!(none, std::borrow::Cow::Borrowed(_)));
        assert_eq!(none.len(), 2);

        // An lsapi handler for a suffix already global -> no change (still borrowed).
        let same = compute_php_suffixes(&global, &[sh("php", ContextKind::Lsapi)]);
        assert!(matches!(same, std::borrow::Cow::Borrowed(_)));

        // A `static` override removes html; php (from global) stays -> only php scripts.
        let only_php = compute_php_suffixes(
            &global,
            &[
                sh("php", ContextKind::Lsapi),
                sh("html", ContextKind::Static),
            ],
        );
        assert!(only_php.contains("php"));
        assert!(!only_php.contains("html"));

        // An lsapi handler for a NEW suffix adds it (additive union still works).
        let added = compute_php_suffixes(&global, &[sh("phtml", ContextKind::Lsapi)]);
        assert!(added.contains("phtml") && added.contains("php") && added.contains("html"));
    }

    #[test]
    fn request_guard_tracks_inflight_and_decrements_on_drop() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let c = AtomicU64::new(0);
        {
            let _g = RequestGuard::new(&c);
            assert_eq!(c.load(Ordering::Relaxed), 1);
            let _g2 = RequestGuard::new(&c);
            assert_eq!(c.load(Ordering::Relaxed), 2);
        }
        // Both guards dropped (every handle() exit path) → back to zero.
        assert_eq!(c.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn mtls_redirect_forces_https_except_acme() {
        // (#2) A plaintext request to an mTLS-required vhost is 301'd to HTTPS,
        // preserving path + query.
        assert_eq!(
            mtls_https_redirect_target("forum.example", "/index.php", None).as_deref(),
            Some("https://forum.example/index.php")
        );
        assert_eq!(
            mtls_https_redirect_target("forum.example", "/search", Some("q=x")).as_deref(),
            Some("https://forum.example/search?q=x")
        );
        // Empty query string does not produce a dangling `?`.
        assert_eq!(
            mtls_https_redirect_target("tenant.example", "/a", Some("")).as_deref(),
            Some("https://tenant.example/a")
        );
        // The ACME http-01 challenge must stay plaintext-reachable (None = serve).
        assert_eq!(
            mtls_https_redirect_target(
                "forum.example",
                "/.well-known/acme-challenge/tokenXYZ",
                None
            ),
            None
        );
    }

    #[test]
    fn mtls_acme_exemption_confined_to_normalized_single_token() {
        // (security #259) The exemption is decided on the NORMALIZED path with a strict
        // single-token shape: traversal that would escape the prefix after dispatch's
        // dot-segment collapse must REDIRECT (Some), never serve over plaintext.
        for escape in [
            "/.well-known/acme-challenge/x/../../../threads",
            "/.well-known/acme-challenge/../index.php",
            "/.well-known/acme-challenge/%2e%2e%2findex.php",
            "/.well-known/acme-challenge/a/b",
            "/.well-known/acme-challenge/.hidden",
            "/.well-known/acme-challenge/",
            "/.well-known/acme-challenge/token/../../admin",
        ] {
            assert!(
                mtls_https_redirect_target("forum.example", escape, None).is_some(),
                "traversal shape {escape} must not be exempt from the mTLS gate"
            );
        }
        // Legit tokens still exempt.
        assert!(acme_challenge_token("/.well-known/acme-challenge/t0kEn-_9").is_some());
    }

    #[test]
    fn logheaders_redacts_credential_values() {
        // (security #261) Credential-class header VALUES must never reach the log
        // file verbatim — only <len>:<sha256[:12]>. Ordinary headers stay intact.
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("cookie", "xf_session=SECRETTOKEN123; xf_user=7")
            .header("authorization", "Bearer sk-supersecret")
            .header("user-agent", "TestAgent/1.0")
            .body(hj_core::empty_incoming())
            .unwrap();
        let line = render_request_headers(&req);
        assert!(
            !line.contains("SECRETTOKEN123"),
            "raw cookie leaked: {line}"
        );
        assert!(!line.contains("sk-supersecret"), "raw authorization leaked");
        assert!(line.contains("user-agent=TestAgent/1.0"), "{line}");
        let cookie_val = "xf_session=SECRETTOKEN123; xf_user=7";
        assert!(
            line.contains(&format!("cookie={}:", cookie_val.len())),
            "cookie value must be replaced by len:hash, got {line}"
        );
        let authz = line.split("authorization=").nth(1).unwrap_or("");
        let hex = authz.split(';').next().unwrap_or("").split(':').nth(1);
        assert_eq!(
            hex.map(|h| h.len()),
            Some(12),
            "hash truncated to 12 hex chars"
        );
    }

    #[test]
    fn mtls_gate_exempts_only_loopback_when_no_peers_installed() {
        use std::net::IpAddr;
        let ext: IpAddr = "203.0.113.7".parse().unwrap(); // public client
        let cdn: IpAddr = "192.0.2.229".parse().unwrap(); // documentation CDN peer
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let lan: IpAddr = "10.0.0.3".parse().unwrap(); // a LAN host (NOT an installed peer here)
        let lan2: IpAddr = "192.168.1.5".parse().unwrap();

        // Plaintext :80 to an mTLS-required vhost: external/CDN peers are
        // bounced to HTTPS so an unauthenticated direct hit never reaches backends.
        assert!(mtls_gate_redirects(false, true, ext));
        assert!(mtls_gate_redirects(false, true, cdn));
        // Loopback always reaches :80 directly (on-box `/etc/hosts` fetches).
        assert!(!mtls_gate_redirects(false, true, lo));
        // (audit-2026-06-19 narrowing) With no `--cache-peer` allow-list installed in
        // this test process, an arbitrary RFC1918/LAN host is NO LONGER exempt — it is
        // bounced to HTTPS like any other non-loopback peer. Only loopback + the
        // explicitly-installed sibling node are exempt (covered in hj-core::net tests).
        assert!(mtls_gate_redirects(false, true, lan));
        assert!(mtls_gate_redirects(false, true, lan2));
        // Already on TLS, or a vhost that doesn't require mTLS: never redirect.
        assert!(!mtls_gate_redirects(true, true, ext));
        assert!(!mtls_gate_redirects(false, false, ext));
    }

    #[test]
    fn forwarded_scheme_https_parses_cf_visitor_and_xfp() {
        use http::header::HeaderName;
        let hm = |pairs: &[(&str, &str)]| {
            let mut m = http::HeaderMap::new();
            for (k, v) in pairs {
                m.insert(
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                );
            }
            m
        };
        // CF-Visitor (Cloudflare), spacing-tolerant.
        assert!(forwarded_scheme_is_https(&hm(&[(
            "cf-visitor",
            r#"{"scheme":"https"}"#
        )])));
        assert!(forwarded_scheme_is_https(&hm(&[(
            "cf-visitor",
            r#"{ "scheme": "https" }"#
        )])));
        assert!(!forwarded_scheme_is_https(&hm(&[(
            "cf-visitor",
            r#"{"scheme":"http"}"#
        )])));
        // X-Forwarded-Proto, incl. a proxy chain (left-most is the client scheme).
        assert!(forwarded_scheme_is_https(&hm(&[(
            "x-forwarded-proto",
            "https"
        )])));
        assert!(forwarded_scheme_is_https(&hm(&[(
            "x-forwarded-proto",
            "HTTPS"
        )])));
        assert!(forwarded_scheme_is_https(&hm(&[(
            "x-forwarded-proto",
            "https, http"
        )])));
        assert!(!forwarded_scheme_is_https(&hm(&[(
            "x-forwarded-proto",
            "http"
        )])));
        // Absent → false (the caller then keeps the connection's physical scheme).
        assert!(!forwarded_scheme_is_https(&hm(&[])));
        // NOTE: this parser is only ever consulted after the peer is confirmed a trusted
        // proxy (see `handle`), so an untrusted client setting these cannot spoof https.
    }

    #[test]
    fn effective_https_gates_forwarded_scheme_on_trusted_proxy() {
        use http::header::HeaderName;
        let xfp_https = {
            let mut m = http::HeaderMap::new();
            m.insert(
                HeaderName::from_static("x-forwarded-proto"),
                "https".parse().unwrap(),
            );
            m
        };
        let none = http::HeaderMap::new();
        // Physical TLS is always https, regardless of trust/headers.
        assert!(effective_request_https(true, false, &none));
        // Cleartext + a TRUSTED proxy asserting https → https (the CF "Flexible" case).
        assert!(effective_request_https(false, true, &xfp_https));
        // Cleartext + UNTRUSTED peer asserting https → still http (spoof rejected). This
        // is the security-critical case: a direct :80 client cannot forge the scheme.
        assert!(!effective_request_https(false, false, &xfp_https));
        // Cleartext + trusted proxy but no header → http.
        assert!(!effective_request_https(false, true, &none));
    }

    #[test]
    fn redirect_cdn_caching_is_denied_for_generic_redirects() {
        use http::header::{CACHE_CONTROL, LOCATION};
        // Both loop variants must be de-cached: cross-scheme (http→https) AND same-scheme
        // HTTPS slug-canonicalization (the variant the old cross-scheme-only guard missed,
        // which Cloudflare cached slug-blind and replayed on the canonical URL = self-loop).
        for loc in [
            "https://forum.example/forums/x.302/", // cross-scheme upgrade
            "https://forum.example/threads/canonical-slug.422335/", // same-scheme canonicalization
            "/threads/canonical-slug.422335/",     // relative canonicalization
        ] {
            let mut resp: Response = Response::new(Body::Empty);
            *resp.status_mut() = http::StatusCode::MOVED_PERMANENTLY;
            let h = resp.headers_mut();
            h.insert(LOCATION, http::HeaderValue::from_str(loc).unwrap());
            h.insert(
                CACHE_CONTROL,
                http::HeaderValue::from_static("public, max-age=86400, s-maxage=604800"),
            );
            h.insert(
                http::HeaderName::from_static("cloudflare-cdn-cache-control"),
                http::HeaderValue::from_static("max-age=604800"),
            );
            deny_redirect_cdn_caching(&mut resp);
            assert!(
                !resp.headers().contains_key("cloudflare-cdn-cache-control"),
                "loc={loc}"
            );
            assert_eq!(
                resp.headers().get(CACHE_CONTROL).unwrap(),
                "private, no-store",
                "loc={loc}"
            );
        }
    }

    #[test]
    fn explicit_cacheable_redirects_keep_cdn_cache_headers() {
        use http::header::{CACHE_CONTROL, LOCATION};
        let cf_cc = http::HeaderName::from_static("cloudflare-cdn-cache-control");
        let xco = http::HeaderName::from_static("x-cache-optimizer");
        for (status, loc, label) in [
            (
                http::StatusCode::SEE_OTHER,
                "/threads/canonical-slug.422335/#post-988619",
                "redirect-temp-303",
            ),
            (
                http::StatusCode::MOVED_PERMANENTLY,
                "/threads/canonical-slug.422335/#post-90362",
                "redirect-thread-post-301",
            ),
            (
                http::StatusCode::SEE_OTHER,
                "/proxy.php?image=https%3A%2F%2Fexample.test%2Fx.png&hash=abc",
                "unfurl-image-redirect",
            ),
            (
                http::StatusCode::MOVED_PERMANENTLY,
                "/tags/windows-11/",
                "redirect-301",
            ),
            (
                http::StatusCode::PERMANENT_REDIRECT,
                "/forums/windows-help-and-support.302/",
                "redirect-308",
            ),
            (
                http::StatusCode::SEE_OTHER,
                "https://attachments.forum.example/attachments/137/137096-abc.data?token=x",
                "redirect-attach-303",
            ),
        ] {
            let mut resp: Response = Response::new(Body::Empty);
            *resp.status_mut() = status;
            let h = resp.headers_mut();
            h.insert(LOCATION, http::HeaderValue::from_str(loc).unwrap());
            h.insert(
                CACHE_CONTROL,
                http::HeaderValue::from_static("public, max-age=300, s-maxage=1800"),
            );
            h.insert(
                cf_cc.clone(),
                http::HeaderValue::from_static("max-age=1800"),
            );
            h.insert(xco.clone(), http::HeaderValue::from_static(label));

            deny_redirect_cdn_caching(&mut resp);
            assert_eq!(
                resp.headers().get(CACHE_CONTROL).unwrap(),
                "public, max-age=300, s-maxage=1800",
                "label={label}"
            );
            assert_eq!(
                resp.headers().get(&cf_cc).unwrap(),
                "max-age=1800",
                "label={label}"
            );
        }
    }

    #[test]
    fn explicit_cacheable_redirect_with_set_cookie_is_denied() {
        use http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
        let mut resp: Response = Response::new(Body::Empty);
        *resp.status_mut() = http::StatusCode::SEE_OTHER;
        let h = resp.headers_mut();
        h.insert(
            LOCATION,
            http::HeaderValue::from_static("/threads/canonical-slug.422335/#post-988619"),
        );
        h.insert(
            CACHE_CONTROL,
            http::HeaderValue::from_static("public, max-age=300, s-maxage=1800"),
        );
        h.insert(
            http::HeaderName::from_static("cloudflare-cdn-cache-control"),
            http::HeaderValue::from_static("max-age=1800"),
        );
        h.insert(
            http::HeaderName::from_static("x-cache-optimizer"),
            http::HeaderValue::from_static("redirect-temp-303"),
        );
        h.insert(
            SET_COOKIE,
            http::HeaderValue::from_static("xf_session=abc; Path=/; HttpOnly"),
        );

        deny_redirect_cdn_caching(&mut resp);
        assert!(!resp.headers().contains_key("cloudflare-cdn-cache-control"));
        assert_eq!(
            resp.headers().get(CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
    }

    #[test]
    fn labeled_self_redirect_is_hard_denied() {
        use http::header::{CACHE_CONTROL, LOCATION};
        // A response that carries an allow-listed label AND public cache
        // headers must STILL be de-cached when its Location points back at
        // the request's own path+query — the loop shape the allow-list must
        // never re-enable. Covers relative and absolute same-host forms.
        for loc in [
            "/tags/windows-11",
            "/tags/windows-11#frag",
            "https://forum.example/tags/windows-11",
            // Uppercase scheme and protocol-relative must not evade the deny.
            "HTTPS://forum.example/tags/windows-11",
            "//forum.example/tags/windows-11",
            // Percent-encoding of an unreserved byte (%2D = '-'): CF normalizes
            // its cache key, so this is the SAME edge entry as the request URL.
            "/tags/windows%2D11",
        ] {
            let mut resp: Response = Response::new(Body::Empty);
            *resp.status_mut() = http::StatusCode::MOVED_PERMANENTLY;
            let h = resp.headers_mut();
            h.insert(LOCATION, http::HeaderValue::from_str(loc).unwrap());
            h.insert(
                CACHE_CONTROL,
                http::HeaderValue::from_static("public, max-age=86400, s-maxage=604800"),
            );
            h.insert(
                http::HeaderName::from_static("cloudflare-cdn-cache-control"),
                http::HeaderValue::from_static("max-age=604800"),
            );
            h.insert(
                http::HeaderName::from_static("x-cache-optimizer"),
                http::HeaderValue::from_static("redirect-301"),
            );
            assert!(
                deny_labeled_self_redirect("/tags/windows-11", &mut resp),
                "loc={loc}"
            );
            assert_eq!(
                resp.headers().get(CACHE_CONTROL).unwrap(),
                "private, no-store",
                "loc={loc}"
            );
            assert!(!resp.headers().contains_key("cloudflare-cdn-cache-control"));
        }

        // NOT self: different path (the slash-append canonicalization) — untouched.
        let mut resp: Response = Response::new(Body::Empty);
        *resp.status_mut() = http::StatusCode::MOVED_PERMANENTLY;
        resp.headers_mut().insert(
            LOCATION,
            http::HeaderValue::from_static("/tags/windows-11/"),
        );
        resp.headers_mut().insert(
            CACHE_CONTROL,
            http::HeaderValue::from_static("public, max-age=86400"),
        );
        assert!(!deny_labeled_self_redirect("/tags/windows-11", &mut resp));
        assert_eq!(
            resp.headers().get(CACHE_CONTROL).unwrap(),
            "public, max-age=86400"
        );

        // Scheme-BLIND on purpose: the http->https upgrade to the SAME
        // path+query is exactly what a scheme-blind shared cache replays
        // into a loop (cache_scheme_test contract) — denied even though
        // the origin labels upgrades cacheable.
        let mut up: Response = Response::new(Body::Empty);
        *up.status_mut() = http::StatusCode::MOVED_PERMANENTLY;
        up.headers_mut().insert(
            LOCATION,
            http::HeaderValue::from_static("https://forum.example/tags/windows-11"),
        );
        up.headers_mut().insert(
            CACHE_CONTROL,
            http::HeaderValue::from_static("public, max-age=86400"),
        );
        assert!(deny_labeled_self_redirect("/tags/windows-11", &mut up));
        assert_eq!(
            up.headers().get(CACHE_CONTROL).unwrap(),
            "private, no-store"
        );

        // The normalized compare also works with the ENCODED form on the
        // request side (crawlers hit `%5F` URLs; the origin 301s to the
        // decoded canonical slug — one CF cache-key entry, i.e. a loop).
        let mut enc: Response = Response::new(Body::Empty);
        *enc.status_mut() = http::StatusCode::MOVED_PERMANENTLY;
        enc.headers_mut().insert(
            LOCATION,
            http::HeaderValue::from_static("/threads/erlang-ssh_sftpd.405371/"),
        );
        enc.headers_mut().insert(
            CACHE_CONTROL,
            http::HeaderValue::from_static("public, max-age=86400"),
        );
        assert!(deny_labeled_self_redirect(
            "/threads/erlang-ssh%5Fsftpd.405371/",
            &mut enc
        ));
    }

    #[test]
    fn location_host_foreignness_covers_vhost_name_and_request_host() {
        // Canonical vhost name matches (case/www-insensitive) — not foreign.
        assert!(!location_host_is_foreign(
            "forum.example",
            "forum.example",
            None
        ));
        assert!(!location_host_is_foreign(
            "www.forum.example",
            "Forum.Example",
            None
        ));
        // An exact ALIAS host (resolves to the vhost but differs from its
        // canonical name) must count as same-host via the request host —
        // otherwise a backend reflecting the alias into an absolute
        // self-Location slips past the deny as "cross-host".
        assert!(!location_host_is_foreign(
            "alias.example",
            "forum.example",
            Some("alias.example")
        ));
        // Genuinely foreign target (the R2 offload shape) stays exempt even
        // when the request host is present.
        assert!(location_host_is_foreign(
            "attachments.forum.example",
            "forum.example",
            Some("forum.example")
        ));
    }

    #[test]
    fn rewrite_env_merge_reserves_the_hj_prefix() {
        let mut ctx = bare_ctx_for_headers();
        ctx.set_env("HJ_REQUEST_PATH_QUERY", "/real".to_string());
        merge_rewrite_env(
            &mut ctx,
            vec![
                ("no-cache".into(), "1".into()),
                ("HJ_REQUEST_PATH_QUERY".into(), "/poisoned".into()),
                ("HJ_ANYTHING".into(), "x".into()),
            ],
        );
        assert_eq!(ctx.get_env("no-cache"), Some("1"));
        assert_eq!(ctx.get_env("HJ_REQUEST_PATH_QUERY"), Some("/real"));
        assert_eq!(ctx.get_env("HJ_ANYTHING"), None);
    }

    #[test]
    fn redirect_guard_set_on_ctx() {
        let mut ctx = bare_ctx_for_headers();
        let uri: http::Uri = "https://forum.example/tags/x?a=b".parse().unwrap();
        set_redirect_guard(&mut ctx, &uri, "alias.example");
        let guard = ctx.redirect_guard.as_ref().unwrap();
        assert_eq!(guard.path_query(), Some("/tags/x?a=b"));
        assert_eq!(guard.host, "alias.example");

        // An empty query is dropped — parity with strip_empty_query on the
        // path that doesn't normalize the URI (fast_serve).
        let mut ctx = bare_ctx_for_headers();
        let uri: http::Uri = "/tags/x?".parse().unwrap();
        set_redirect_guard(&mut ctx, &uri, "forum.example");
        let guard = ctx.redirect_guard.as_ref().unwrap();
        assert_eq!(guard.path_query(), Some("/tags/x"));
    }

    #[tokio::test]
    async fn deny_redirect_transform_needs_the_guard() {
        use http::header::{CACHE_CONTROL, LOCATION};
        let labeled_self = || {
            let mut resp: Response = Response::new(Body::Empty);
            *resp.status_mut() = http::StatusCode::MOVED_PERMANENTLY;
            let h = resp.headers_mut();
            h.insert(LOCATION, http::HeaderValue::from_static("/tags/x"));
            h.insert(
                CACHE_CONTROL,
                http::HeaderValue::from_static("public, max-age=86400"),
            );
            h.insert(
                http::HeaderName::from_static("x-cache-optimizer"),
                http::HeaderValue::from_static("redirect-301"),
            );
            resp
        };

        // With the guard (both entry paths set it): the labeled
        // self-redirect is hard-denied at egress.
        let mut ctx = bare_ctx_for_headers();
        set_redirect_guard(
            &mut ctx,
            &"/tags/x".parse::<http::Uri>().unwrap(),
            "forum.example",
        );
        let mut resp = labeled_self();
        DenyRedirectCdnTransform.transform(&ctx, &mut resp).await;
        assert_eq!(
            resp.headers().get(CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        assert!(
            !resp.headers().contains_key("x-cache-optimizer"),
            "the internal label must not egress"
        );

        // Without it the allow-listed label keeps CDN headers — the transform
        // is BLIND to self-loops, which is why every serve path (handle AND
        // fast_serve) must call set_redirect_guard.
        let ctx = bare_ctx_for_headers();
        let mut resp = labeled_self();
        DenyRedirectCdnTransform.transform(&ctx, &mut resp).await;
        assert_eq!(
            resp.headers().get(CACHE_CONTROL).unwrap(),
            "public, max-age=86400"
        );
        assert!(!resp.headers().contains_key("x-cache-optimizer"));
    }

    #[test]
    fn redirect_target_path_query_parses_forms() {
        assert_eq!(
            redirect_target_path_query("/threads/x.1/?a=b#frag").as_deref(),
            Some("/threads/x.1/?a=b")
        );
        assert_eq!(
            redirect_target_path_query("https://forum.example/tags/x?q=1").as_deref(),
            Some("/tags/x?q=1")
        );
        // Scheme matching is case-INsensitive (parity with lscache's
        // location_is_self — an uppercase-scheme self-loop must not evade).
        assert_eq!(
            redirect_target_path_query("HTTPS://forum.example/tags/x").as_deref(),
            Some("/tags/x")
        );
        // A bare authority is an implicit root — the homepage self-redirect
        // shape (`/` -> `https://host`) must compare equal to `/`.
        assert_eq!(
            redirect_target_path_query("https://forum.example").as_deref(),
            Some("/")
        );
        assert_eq!(
            redirect_target_path_query("https://forum.example?a=b").as_deref(),
            Some("/?a=b")
        );
        // Protocol-relative is parsed (same-scheme by construction); host
        // gating is the transform's job via redirect_target_host.
        assert_eq!(
            redirect_target_path_query("//forum.example/path").as_deref(),
            Some("/path")
        );
        assert_eq!(redirect_target_path_query("///x"), None);
        assert_eq!(redirect_target_path_query("mailto:a@b"), None);
        assert_eq!(redirect_target_path_query("threads/x"), None);
    }

    #[test]
    fn redirect_cdn_caching_leaves_304_and_non_redirects_untouched() {
        use http::header::CACHE_CONTROL;
        let cc = "public, s-maxage=600";
        // (1) 304 Not Modified is 3xx but carries no Location — its cacheability is preserved
        // (conditional-request revalidation depends on it).
        let mut not_modified: Response = Response::new(Body::Empty);
        *not_modified.status_mut() = http::StatusCode::NOT_MODIFIED;
        not_modified
            .headers_mut()
            .insert(CACHE_CONTROL, http::HeaderValue::from_static(cc));
        deny_redirect_cdn_caching(&mut not_modified);
        assert_eq!(not_modified.headers().get(CACHE_CONTROL).unwrap(), cc);

        // (2) A 200 (not a redirect): untouched.
        let mut ok: Response = Response::new(Body::Empty);
        ok.headers_mut()
            .insert(CACHE_CONTROL, http::HeaderValue::from_static(cc));
        deny_redirect_cdn_caching(&mut ok);
        assert_eq!(ok.headers().get(CACHE_CONTROL).unwrap(), cc);

        // (3) A redirect WITHOUT a Location (degenerate) is also left alone.
        let mut bare: Response = Response::new(Body::Empty);
        *bare.status_mut() = http::StatusCode::MOVED_PERMANENTLY;
        bare.headers_mut()
            .insert(CACHE_CONTROL, http::HeaderValue::from_static(cc));
        deny_redirect_cdn_caching(&mut bare);
        assert_eq!(bare.headers().get(CACHE_CONTROL).unwrap(), cc);
    }

    #[test]
    fn redirect_target_host_parses_absolute_http_urls_only() {
        // The cross-host redirect exemption hinges on this parse: absolute
        // http(s) or protocol-relative target -> Some(host); anything else
        // (relative = same-host, exotic schemes, empty authority) -> None ->
        // the strict deny applies.
        assert_eq!(
            redirect_target_host("HTTPS://Example.COM/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            redirect_target_host("//cdn.example/x").as_deref(),
            Some("cdn.example")
        );
        assert_eq!(redirect_target_host("///x"), None);
        assert_eq!(
            redirect_target_host("https://attachments.forum.example/processed-images/a/b.jpg")
                .as_deref(),
            Some("attachments.forum.example")
        );
        assert_eq!(
            redirect_target_host("http://Example.COM:8080/p?q#f").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            redirect_target_host("https://u:p@host.tld/x").as_deref(),
            Some("host.tld")
        );
        // IPv6 literal authority must not be mangled by the port strip.
        assert_eq!(
            redirect_target_host("https://[::1]:8443/x").as_deref(),
            Some("::1")
        );
        assert_eq!(
            redirect_target_host("https://[2001:db8::1]/x").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(redirect_target_host("/threads/some-slug.123/"), None);
        assert_eq!(redirect_target_host("ftp://h/x"), None);
        assert_eq!(redirect_target_host("https:///nohost"), None);
    }

    #[test]
    fn foreign_host_decache_forces_private_nostore_for_every_status() {
        use http::header::{CACHE_CONTROL, EXPIRES};
        // Unlike the redirect guard, this covers ALL statuses — a foreign-Host 200 (the
        // homepage-poison shape), a 301, a 304, a 500 — because Cloudflare edge-caches per
        // hostname regardless of status, and the page-cache bypass does NOT stop the origin
        // from SENDING a `public` response.
        for status in [
            http::StatusCode::OK,
            http::StatusCode::MOVED_PERMANENTLY,
            http::StatusCode::NOT_MODIFIED,
            http::StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let mut resp: Response = Response::new(Body::Empty);
            *resp.status_mut() = status;
            let h = resp.headers_mut();
            h.insert(
                CACHE_CONTROL,
                http::HeaderValue::from_static("public, max-age=300, s-maxage=300"),
            );
            h.insert(
                http::HeaderName::from_static("cloudflare-cdn-cache-control"),
                http::HeaderValue::from_static("max-age=600"),
            );
            h.insert(
                http::HeaderName::from_static("cdn-cache-control"),
                http::HeaderValue::from_static("max-age=600"),
            );
            h.insert(
                EXPIRES,
                http::HeaderValue::from_static("Wed, 21 Oct 2099 07:28:00 GMT"),
            );
            deny_foreign_host_cdn_caching(&mut resp);
            let cc = resp.headers().get(CACHE_CONTROL).unwrap().to_str().unwrap();
            assert_eq!(cc, "private, no-store", "status={status}");
            // No shared-cache directive of any kind survives.
            assert!(
                !cc.contains("public") && !cc.contains("s-maxage"),
                "status={status}"
            );
            assert!(
                !resp.headers().contains_key("cloudflare-cdn-cache-control"),
                "status={status}"
            );
            assert!(
                !resp.headers().contains_key("cdn-cache-control"),
                "status={status}"
            );
            assert!(!resp.headers().contains_key(EXPIRES), "status={status}");
        }
    }

    /// Build a minimal `ReqCtx` whose `env` is empty (enough for `apply_response_headers`,
    /// which only reads `ctx.env`). Avoids spinning up a full ServerState.
    pub(super) fn bare_ctx_for_headers() -> ReqCtx {
        use hj_core::config::{MimeMap, ServerConfig, VHostConfig};
        use std::collections::BTreeMap;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let server = ServerConfig {
            server_root: std::path::PathBuf::from("/tmp"),
            server_name: "test".into(),
            user: "nobody".into(),
            group: "nobody".into(),
            index_files: vec!["index.html".into()],
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
            vhosts: BTreeMap::new(),
            vhost_order: vec![],
            mime: MimeMap::default(),
        };
        ReqCtx {
            server: Arc::new(server),
            vhost_name: "v".into(),
            vhost: Arc::new(VHostConfig::default()),
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            is_tls: true,
            protocol: Proto::Http1,
            trusted_proxy: false,
            env: Vec::new(),
            local_addr: SocketAddr::from(([127, 0, 0, 1], 443)),
            peer_port: 12345,
            peer_unix: false,
            tls: None,
            redirect_guard: None,
            request_time: std::time::SystemTime::now(),
            request_id: Default::default(),
        }
    }

    #[test]
    fn rewrite_redirect_and_proxy_get_header_always_set() {
        // (#11) `.htaccess` `Header always set` must land on a rewrite-generated 3xx and on
        // a `[P]`-proxied response, exactly as it does on the Status arm — Apache/LiteSpeed
        // scope `always` to redirects and proxied responses. This exercises the same
        // apply_response_headers call the Redirect/Proxy early-return arms now make.
        let ht = Arc::new(Htaccess::parse("Header always set X-Test foo").unwrap());
        let chain = [ht];
        let ctx = bare_ctx_for_headers();

        // Redirect-shaped response (what the Redirect arm builds via `redirect`).
        let mut redir = redirect(301, "https://forum.example/canonical/");
        apply_response_headers_for_request(&ctx, &chain, "/old", "/old", &mut redir);
        assert_eq!(
            redir.headers().get("x-test").unwrap(),
            "foo",
            "redirect must carry always-set header"
        );

        // Proxy-shaped response (status 200, opaque upstream body).
        let mut proxied: Response = Response::new(Body::Empty);
        *proxied.status_mut() = StatusCode::OK;
        apply_response_headers_for_request(&ctx, &chain, "/api", "/api", &mut proxied);
        assert_eq!(
            proxied.headers().get("x-test").unwrap(),
            "foo",
            "proxied must carry always-set header"
        );
    }

    #[test]
    fn mtls_ok_depends_on_whether_the_listener_requests_client_auth() {
        // (#16, corrected) mtls_ok gates whether forwarded client-IP headers are honored.
        // - When the listener REQUESTS client certs (clientVerify>=1, `mtls_required=true`):
        //   require an ACTUAL presented cert (a cert-less internal TLS peer must not be trusted).
        // - When it does NOT (--no-mtls / clientVerify=0, the prod topology, `mtls_required=false`):
        //   trust the network boundary — any completed TLS connection counts (pre-#16 behavior).
        // The unconditional cert requirement broke 100% of --no-mtls real-IP resolution.
        // Mirror the exact expression handle() uses.
        let mtls_ok = |mtls_required: bool, is_tls: bool, tls: &Option<hj_core::TlsParams>| {
            if mtls_required {
                tls.as_ref()
                    .map(|t| t.client_cert.is_some())
                    .unwrap_or(false)
            } else {
                is_tls
            }
        };
        let tls_no_cert = Some(hj_core::TlsParams::new(
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384".into(),
            None,
        ));
        let tls_cert = Some(hj_core::TlsParams::new(
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384".into(),
            Some(hj_core::ClientCert {
                subject_dn: "CN=origin".into(),
                issuer_dn: "CN=CF".into(),
                serial_hex: "01".into(),
                verified: true,
                not_before: "".into(),
                not_after: "".into(),
            }),
        ));

        // Listener requires client auth (clientVerify>=1): cert presence is decisive.
        assert!(!mtls_ok(true, false, &None)); // plaintext: never ok
        assert!(!mtls_ok(true, true, &tls_no_cert)); // TLS, no cert: NOT ok (hardening)
        assert!(mtls_ok(true, true, &tls_cert)); // TLS + presented cert: ok

        // --no-mtls / clientVerify=0 (local-test or explicit rollback mode): no cert is ever
        // requested, so trust the network boundary — any TLS connection is ok, plaintext is not.
        // THIS is the case the unconditional cert check broke (was false for every CF :443 request).
        assert!(mtls_ok(false, true, &None)); // TLS, no cert, no client-auth: ok (the fix)
        assert!(mtls_ok(false, true, &tls_no_cert)); // ditto
        assert!(!mtls_ok(false, false, &None)); // plaintext :80: not ok
    }

    #[test]
    fn mtls_redirect_is_uncacheable_by_shared_caches() {
        // (#13) The mTLS HTTP->HTTPS 301 now runs through the funnel: deny_redirect_cdn_caching
        // marks it `private, no-store` so a cleartext proxy / ISP transparent cache cannot
        // cache+replay it. (requests_total/access-log wiring is exercised by handle() in prod;
        // here we lock the observable header behavior the funnel adds to the early-return 301.)
        let mut resp = redirect(301, "https://forum.example/index.php");
        deny_redirect_cdn_caching(&mut resp);
        assert_eq!(
            resp.headers().get(http::header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
    }
}
