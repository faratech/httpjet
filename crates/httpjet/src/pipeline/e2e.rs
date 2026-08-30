//! Full-pipeline (`handle()`) black-box tests.
//!
//! Every other test in the tree exercises ONE layer (a rewrite rule, a cache
//! helper, a static-handler call) and the existing `pipeline::tests` module
//! deliberately uses `bare_ctx_for_headers()` to AVOID building a real
//! `ServerState`. So the assembly itself — `handle()` wiring vhost resolution →
//! `dispatch()` → the static handler → the `finalize`/transform pipeline →
//! foreign-host de-caching — was untested end to end. These tests build a
//! minimal real `ServerState` over a temp docroot and drive `handle()` exactly
//! as the connection layer does. (httpjet is a binary-only crate, so this lives
//! in `src` rather than `tests/` — there is no lib target to link against.)

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use hj_core::config::{
    Context, ContextKind, Listener, MimeMap, ScriptHandler, ServerConfig, Tuning, VHostConfig,
    VHostDecl, VhostMap,
};
use hj_core::{Body, Proto, Request, Response};
use http::header;

use crate::pipeline::{fast_serve, handle};
use crate::state::ServerState;

const LISTENER: &str = "http";
const VHOST: &str = "testvh";
const CANON_HOST: &str = "canon.test";

fn temp_root(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("hj-e2e-{}-{}-{}", tag, std::process::id(), nanos));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn mime() -> MimeMap {
    let mut by_suffix = BTreeMap::new();
    by_suffix.insert("html".to_string(), "text/html".to_string());
    by_suffix.insert("txt".to_string(), "text/plain".to_string());
    MimeMap { by_suffix }
}

/// A minimal real `ServerState`: one plaintext listener `http` mapping the exact
/// host `canon.test` (plus a `*` catch-all, so any OTHER host resolves to the
/// same vhost but counts as foreign) to a single vhost rooted at `doc_root`.
fn build_state(doc_root: PathBuf) -> Arc<ServerState> {
    build_state_with(doc_root, Vec::new(), Vec::new())
}

fn build_state_with(
    doc_root: PathBuf,
    contexts: Vec<Context>,
    access_deny_dir: Vec<String>,
) -> Arc<ServerState> {
    build_state_full(doc_root, contexts, access_deny_dir, None, None)
}

/// [`build_state_with`] with an origin page-cache attached (the `--page-cache`
/// mode); the vhost gets a cache-enabled policy so store-side eligibility holds.
fn build_state_full(
    doc_root: PathBuf,
    contexts: Vec<Context>,
    access_deny_dir: Vec<String>,
    page_cache: Option<Arc<hj_pagecache::PageStore>>,
    peer_purge: Option<crate::peer_purge::PurgeForwarder>,
) -> Arc<ServerState> {
    let htaccess = page_cache.is_some();
    build_state_inner(
        doc_root,
        contexts,
        access_deny_dir,
        htaccess,
        page_cache,
        peer_purge,
    )
}

/// A `.htaccess`-loading vhost WITHOUT a page cache: the fast_memo tests need
/// the per-dir chain but not the Branch-1 lookup in front of the static serve.
fn build_state_htaccess(doc_root: PathBuf) -> Arc<ServerState> {
    build_state_inner(doc_root, Vec::new(), Vec::new(), true, None, None)
}

fn build_state_inner(
    doc_root: PathBuf,
    contexts: Vec<Context>,
    access_deny_dir: Vec<String>,
    htaccess: bool,
    page_cache: Option<Arc<hj_pagecache::PageStore>>,
    peer_purge: Option<crate::peer_purge::PurgeForwarder>,
) -> Arc<ServerState> {
    // AccessLogger writes under server_root/logs; give it a real writable dir.
    let server_root = temp_root("srv");
    std::fs::create_dir_all(server_root.join("logs")).unwrap();

    let mut vhost_cfg = VHostConfig {
        doc_root: doc_root.clone(),
        index_files: vec!["index.html".into()],
        allow_symbol_link: true,
        contexts,
        script_handlers: vec![ScriptHandler {
            suffix: "php".into(),
            kind: ContextKind::Lsapi,
            handler: "php".into(),
        }],
        ..VHostConfig::default()
    };
    if page_cache.is_some() {
        vhost_cfg.cache_policy = Some(hj_core::config::VhostCachePolicy {
            enable_cache: true,
            enable_public: true,
            enable_private: false,
        });
    }
    if htaccess {
        // The cache-parity + memo tests write per-dir `.htaccess` files (CacheDisable /
        // Require / SetEnvIf); the vhost must load them like a prod standards vhost does.
        vhost_cfg.allow_override = 1;
    }
    let decl = VHostDecl {
        name: VHOST.into(),
        vh_root: doc_root.clone(),
        config_file: PathBuf::new(),
        allow_symbol_link: Some(true),
        restrained: false,
        enable_script: true,
        config: Some(Arc::new(vhost_cfg)),
    };
    let mut vhosts = BTreeMap::new();
    vhosts.insert(VHOST.to_string(), decl);

    let listener = Listener {
        name: LISTENER.into(),
        address: "127.0.0.1:0".into(),
        secure: false,
        vhost_map: vec![VhostMap {
            vhost: VHOST.into(),
            domains: vec![CANON_HOST.into(), "*".into()],
        }],
        tls: None,
    };

    let mut security = hj_core::config::Security::default();
    security.access_deny_dir = access_deny_dir;
    let server = ServerConfig {
        server_root,
        server_name: "e2e".into(),
        user: "nobody".into(),
        group: "nobody".into(),
        index_files: vec!["index.html".into()],
        tuning: Tuning::default(),
        quic_enable: false,
        use_ip_in_proxy_header: 0,
        expires: Default::default(),
        cache: Default::default(),
        security,
        suexec: Default::default(),
        ext_processors: vec![],
        php_config: None,
        listeners: vec![listener],
        vhosts,
        vhost_order: vec![VHOST.into()],
        mime: mime(),
    };

    ServerState::new(
        Arc::new(server),
        None, // lsapi
        None, // alt_svc
        page_cache,
        Arc::new(hj_compress::PageDictRegistry::empty()), // page_cache_dicts
        1,                                                // admit base
        crate::state::XfCapsuleConfig::disabled(),
        peer_purge,
        false, // cf_send_zstd
        None,  // php_slow
        false, // request_id_header
        crate::state::RewriteTuning::default(),
    )
    .unwrap()
}

fn get(host: &str, path: &str, inm: Option<&str>) -> Request {
    let mut b = http::Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, host);
    if let Some(v) = inm {
        b = b.header(header::IF_NONE_MATCH, v);
    }
    b.body(hj_core::empty_incoming()).unwrap()
}

/// Pull the served bytes out of a response `Body` — the cache-small-static
/// transform turns a small static file into `Full`; otherwise read the file.
fn body_bytes(body: Body) -> bytes::Bytes {
    match body {
        Body::Full(b) => b,
        Body::File(f) => f
            .cached
            .unwrap_or_else(|| bytes::Bytes::from(std::fs::read(&f.path).unwrap())),
        Body::Empty => bytes::Bytes::new(),
        Body::Stream(_) => panic!("unexpected streamed body for a small static file"),
    }
}

async fn run(state: &Arc<ServerState>, req: Request) -> Response {
    handle(
        state.clone(),
        LISTENER,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from(([127, 0, 0, 1], 80)),
        40000,
        false, // is_tls
        false, // mtls_required
        None,  // tls
        Proto::Http1,
        None, // sni
        req,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_get_serves_litespeed_etag_and_revalidates_to_304() {
    let root = temp_root("static");
    let path = root.join("hello.txt");
    std::fs::write(&path, b"hello\n").unwrap();
    let state = build_state(root);

    // First GET: 200, the body, and a LiteSpeed-shaped ETag "<size>-<mtime>-<inode>;;;".
    let resp = run(&state, get(CANON_HOST, "/hello.txt", None)).await;
    assert_eq!(resp.status(), 200);
    let etag = resp
        .headers()
        .get(header::ETAG)
        .expect("static 200 must carry an ETag (fileETag=28)")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        etag.starts_with('"') && etag.ends_with(";;;\""),
        "unexpected ETag shape: {etag}"
    );
    assert_eq!(
        etag.matches('-').count(),
        2,
        "ETag must be size-mtime-inode: {etag}"
    );
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"hello\n");

    // A second GET is served through the static body cache. Mutating the source
    // file must invalidate that cached body through the unified PageStore path.
    let resp = run(&state, get(CANON_HOST, "/hello.txt", None)).await;
    assert_eq!(resp.status(), 200);
    assert!(matches!(resp.body(), Body::Full(_)));
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"hello\n");

    // Conditional revalidation with that exact ETag → 304 Not Modified, no body.
    let resp = run(&state, get(CANON_HOST, "/hello.txt", Some(&etag))).await;
    assert_eq!(resp.status(), 304);

    std::fs::write(&path, b"hello after edit\n").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let resp = run(&state, get(CANON_HOST, "/hello.txt", None)).await;
    assert_eq!(resp.status(), 200);
    assert!(matches!(resp.body(), Body::Full(_)));
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"hello after edit\n");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_symlink_into_access_deny_dir_is_forbidden() {
    use std::os::unix::fs::symlink;

    let root = temp_root("deny-symlink-docroot");
    let denied = temp_root("deny-symlink-target");
    std::fs::write(denied.join("secret.txt"), b"must not be served").unwrap();
    symlink(&denied, root.join("alias")).unwrap();
    let state = build_state_with(root, Vec::new(), vec![format!("{}/*", denied.display())]);

    let resp = run(&state, get(CANON_HOST, "/alias/secret.txt", None)).await;
    assert_eq!(resp.status(), 403);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lsapi_script_symlink_into_access_deny_dir_is_forbidden_before_dispatch() {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::Ordering;

    let root = temp_root("deny-script-docroot");
    let denied = temp_root("deny-script-target");
    let target = denied.join("index.php");
    std::fs::write(&target, b"<?php echo 'secret';").unwrap();
    symlink(&target, root.join("index.php")).unwrap();
    let state = build_state_with(root, Vec::new(), vec![format!("{}/*", denied.display())]);

    let resp = run(&state, get(CANON_HOST, "/index.php", None)).await;
    assert_eq!(resp.status(), 403);
    assert_eq!(
        state
            .telemetry
            .shard()
            .served_static
            .load(Ordering::Relaxed),
        0,
        "the denied PHP target must be rejected before static fallback"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_context_resolved_location_in_access_deny_dir_is_forbidden() {
    let doc_root = temp_root("deny-context-docroot");
    let context_root = temp_root("deny-context-target");
    let target_dir = context_root.join("assets");
    std::fs::create_dir_all(&target_dir).unwrap();
    std::fs::write(target_dir.join("secret.txt"), b"must not be served").unwrap();
    let context = Context {
        cache_policy: None,
        kind: ContextKind::Static,
        uri: "/assets".into(),
        location: Some(context_root),
        handler: None,
        enabled: true,
        extra_headers: Vec::new(),
        add_default_charset: false,
        charset: None,
    };
    let state = build_state_with(
        doc_root,
        vec![context],
        vec![format!("{}/*", target_dir.display())],
    );

    let resp = run(&state, get(CANON_HOST, "/assets/secret.txt", None)).await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_context_default_charset_applies_without_other_overrides() {
    let doc_root = temp_root("context-charset");
    std::fs::create_dir_all(doc_root.join("assets")).unwrap();
    std::fs::write(doc_root.join("assets/readme.txt"), b"hello").unwrap();
    let context = Context {
        kind: ContextKind::Static,
        uri: "/assets".into(),
        location: None,
        handler: None,
        enabled: true,
        extra_headers: Vec::new(),
        add_default_charset: true,
        charset: Some("ISO-8859-1".into()),
        cache_policy: None,
    };
    let state = build_state_with(doc_root, vec![context], Vec::new());

    let resp = run(&state, get(CANON_HOST, "/assets/readme.txt", None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()[header::CONTENT_TYPE],
        "text/plain; charset=ISO-8859-1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_host_response_is_decached_end_to_end() {
    // A Host that is NOT the exact map domain resolves to the vhost via the `*`
    // catch-all, so it is foreign: the response must be forced uncacheable by any
    // shared/CDN cache (the publisher.example cross-zone poisoning class), even for a
    // plain static 200 — asserted through the full funnel, not just the helper.
    let root = temp_root("foreign");
    std::fs::write(root.join("hello.txt"), b"hello\n").unwrap();
    let state = build_state(root);

    let resp = run(&state, get("evil.example", "/hello.txt", None)).await;
    assert_eq!(resp.status(), 200);
    let cc = resp
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(cc, "private, no-store", "foreign host must be de-cached");

    // The canonical host, same asset, must NOT be force-decached.
    let resp = run(&state, get(CANON_HOST, "/hello.txt", None)).await;
    assert_eq!(resp.status(), 200);
    let cc = resp
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok());
    assert!(
        cc != Some("private, no-store"),
        "canonical host must not be force-decached"
    );
}

// ─── fast_serve parity: request-side `.htaccess` state gates on-core hits ───
// Regression for the empty-chain Branch-1 lookup: a stored entry kept being
// served on-core to cookieless guests after an operator added `CacheDisable`
// or a directory deny, because only dispatch() saw the chain. Both must bridge.

async fn fast_serve_get(state: &Arc<ServerState>, path: &str) -> Option<Response> {
    let req = get(CANON_HOST, path, None);
    fast_serve(
        state,
        LISTENER,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from(([127, 0, 0, 1], 80)),
        40000,
        false,
        Proto::Http1,
        None,
        &req,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_bridges_stale_hit_when_htaccess_disables_cache_or_denies() {
    let doc_root = temp_root("fastserve");
    std::fs::create_dir_all(doc_root.join("admin")).unwrap();
    std::fs::write(doc_root.join("admin/index.html"), "<h1>admin</h1>\n").unwrap();

    let mut cfg = hj_pagecache::StoreConfig::default();
    // Standards-mode default-cache policy for this vhost (the prod posture):
    // unspecified CacheLookup defaults ON, explicit off/CacheDisable still wins.
    cfg.standard_cc_vhosts.push(VHOST.into());
    let store = Arc::new(hj_pagecache::PageStore::new(cfg));
    let state = build_state_full(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        Some(store.clone()),
        None,
    );

    // Populate exactly as a store-side render would (no .htaccess yet ⇒ empty chain).
    let method = http::Method::GET;
    let identity = format!("http\n{VHOST}\n/admin/index.html");
    let chain: Vec<std::sync::Arc<hj_rewrite::Htaccess>> = Vec::new();
    let resolved = state.router.resolve(LISTENER, Some(CANON_HOST)).unwrap();
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let rctx = hj_core::ReqCtx {
        server: state.server.clone(),
        vhost_name: resolved.name.clone(),
        vhost: resolved.config,
        peer_ip: loopback,
        client_ip: loopback,
        is_tls: false,
        protocol: Proto::Http1,
        trusted_proxy: false,
        env: Vec::new(),
        local_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
        peer_port: 40000,
        tls: None,
        redirect_guard: None,
        request_time: std::time::SystemTime::UNIX_EPOCH,
        request_id: Default::default(),
    };
    let cc = crate::lscache::CacheCtx {
        method: &method,
        host: CANON_HOST,
        cookie: None,
        identity: &identity,
        req_path: "/admin/index.html",
        req_query: "",
        chain: &chain,
        render_epoch: store.purge_epoch(),
        has_range: false,
        host_foreign: false,
        vary_value: None,
    };
    let key =
        crate::lscache::build_cache_key(&rctx, &cc, &store, &crate::lscache::PrivateRoute::Public);
    state
        .page_cache_admission
        .record(crate::lscache::hash_key(&key));
    let resp = http::Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/html")
        .header(header::CACHE_CONTROL, "public,max-age=600")
        .body(Body::Full(bytes::Bytes::from_static(b"<h1>admin</h1>\n")))
        .unwrap();
    crate::lscache::cache_store(&state, &rctx, &cc, resp).await;

    // Baseline: the cookieless GET is served ON-CORE from the stored entry.
    let hit = fast_serve_get(&state, "/admin/index.html")
        .await
        .expect("baseline cookieless request must serve from the page cache");
    assert_eq!(
        hit.headers()
            .get("x-litespeed-cache")
            .map(|v| v.to_str().unwrap()),
        Some("hit"),
        "expected a Branch-1 cache hit"
    );

    // An .htaccess added AFTER storing must gate the on-core hit: the lookup
    // bypasses (no `x-litespeed-cache: hit`); this static fixture then serves
    // fresh from disk on-core, while a PHP-rendered entry would bridge to
    // dispatch() at the script-suffix check. Either way: no stale cached serve.
    std::fs::write(
        doc_root.join("admin/.htaccess"),
        "CacheDisable public /admin\n",
    )
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await; // outlast the 1s HtaccessCache revalidate window
    let served = fast_serve_get(&state, "/admin/index.html").await;
    assert_ne!(
        served
            .as_ref()
            .and_then(|r| r.headers().get("x-litespeed-cache"))
            .map(|v| v.to_str().unwrap()),
        Some("hit"),
        "CacheDisable public must stop the stale entry being served on-core"
    );

    // A directory ACL deny must likewise never serve the stale hit on-core.
    std::fs::write(doc_root.join("admin/.htaccess"), "Require all denied\n").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await; // outlast the 1s HtaccessCache revalidate window
    assert!(
        fast_serve_get(&state, "/admin/index.html").await.is_none(),
        "Require all denied must bridge instead of serving the stale entry"
    );

    let _ = std::fs::remove_dir_all(doc_root);
}

// ─── #358: the on-core cache hit must run the rewrite engine FIRST, like
// dispatch() (and LSWS's URI_MAP cache hook). A `RewriteCond`-gated `[F]` or
// `[E=Cache-Control:no-cache]` — inputs outside the cache key — must never be
// skipped for a warm cookieless URL.
fn get_with_ua(path: &str, ua: &str) -> Request {
    http::Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, CANON_HOST)
        .header(header::USER_AGENT, ua)
        .body(hj_core::empty_incoming())
        .unwrap()
}

async fn fast_serve_req(state: &Arc<ServerState>, req: &Request) -> Option<Response> {
    fast_serve(
        state,
        LISTENER,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from(([127, 0, 0, 1], 80)),
        40000,
        false,
        Proto::Http1,
        None,
        req,
    )
    .await
}

async fn seed_public_entry(
    state: &Arc<ServerState>,
    store: &Arc<hj_pagecache::PageStore>,
    path: &str,
    body: &'static [u8],
) {
    let method = http::Method::GET;
    let identity = format!("http\n{VHOST}\n{path}");
    let chain: Vec<std::sync::Arc<hj_rewrite::Htaccess>> = Vec::new();
    let resolved = state.router.resolve(LISTENER, Some(CANON_HOST)).unwrap();
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let rctx = hj_core::ReqCtx {
        server: state.server.clone(),
        vhost_name: resolved.name.clone(),
        vhost: resolved.config,
        peer_ip: loopback,
        client_ip: loopback,
        is_tls: false,
        protocol: Proto::Http1,
        trusted_proxy: false,
        env: Vec::new(),
        local_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
        peer_port: 40000,
        tls: None,
        redirect_guard: None,
        request_time: std::time::SystemTime::UNIX_EPOCH,
        request_id: Default::default(),
    };
    let cc = crate::lscache::CacheCtx {
        method: &method,
        host: CANON_HOST,
        cookie: None,
        identity: &identity,
        req_path: path,
        req_query: "",
        chain: &chain,
        render_epoch: store.purge_epoch(),
        has_range: false,
        host_foreign: false,
        vary_value: None,
    };
    let key =
        crate::lscache::build_cache_key(&rctx, &cc, store, &crate::lscache::PrivateRoute::Public);
    state
        .page_cache_admission
        .record(crate::lscache::hash_key(&key));
    let resp = http::Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/html")
        .header(header::CACHE_CONTROL, "public,max-age=600")
        .body(Body::Full(bytes::Bytes::from_static(body)))
        .unwrap();
    crate::lscache::cache_store(state, &rctx, &cc, resp).await;
}

fn is_cache_hit(resp: Option<&Response>) -> bool {
    resp.and_then(|r| r.headers().get("x-litespeed-cache"))
        .map(|v| v.to_str().unwrap())
        == Some("hit")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_runs_rewrite_before_serving_a_cache_hit() {
    let doc_root = temp_root("fastserve_rw");
    std::fs::create_dir_all(doc_root.join("pages")).unwrap();
    std::fs::write(doc_root.join("pages/index.html"), "<h1>page</h1>\n").unwrap();
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\n\
         RewriteCond %{HTTP_USER_AGENT} BadBot\n\
         RewriteRule .* - [F]\n\
         RewriteCond %{HTTP_USER_AGENT} NoCache\n\
         RewriteRule .* - [E=Cache-Control:no-cache]\n",
    )
    .unwrap();

    let mut cfg = hj_pagecache::StoreConfig::default();
    cfg.standard_cc_vhosts.push(VHOST.into());
    let store = Arc::new(hj_pagecache::PageStore::new(cfg));
    let state = build_state_full(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        Some(store.clone()),
        None,
    );
    seed_public_entry(&state, &store, "/pages/index.html", b"<h1>page</h1>\n").await;

    // Baseline: an unbanned UA is served on-core from the entry.
    let ok = fast_serve_req(&state, &get_with_ua("/pages/index.html", "Mozilla/5.0")).await;
    assert!(is_cache_hit(ok.as_ref()), "baseline must be a Branch-1 hit");

    // The RewriteCond-gated [F] must bridge (dispatch renders the 403), never serve the hit.
    let banned = get_with_ua("/pages/index.html", "BadBot/1.0");
    assert!(
        fast_serve_req(&state, &banned).await.is_none(),
        "a rewrite [F] must bridge instead of serving the warm entry"
    );
    let full = run(&state, banned).await;
    assert_eq!(
        full.status(),
        403,
        "dispatch() parity: the banned UA is forbidden"
    );

    // A rewrite-set `[E=Cache-Control:no-cache]` must reach the lookup (bypass), like
    // dispatch()'s merge_rewrite_env → cache_lookup ordering.
    let bypass = fast_serve_req(&state, &get_with_ua("/pages/index.html", "NoCache/1.0")).await;
    assert!(
        !is_cache_hit(bypass.as_ref()),
        "a rewrite-set no-cache env must bypass the on-core hit"
    );

    let _ = std::fs::remove_dir_all(doc_root);
}

// ─── #360: a Cookie line carrying a non-ASCII byte is decoded the way lsphp
// decodes it (lossily), never treated as ABSENT — otherwise the cache tier and
// the rewrite engine classify a request as cookieless while PHP honors its
// `xf_*` crumbs.
#[test]
fn cookie_header_with_non_ascii_byte_is_still_classified() {
    let mut h = http::HeaderMap::new();
    h.append(
        header::COOKIE,
        http::HeaderValue::from_bytes(b"xf_user=7; x=\xc3\xa9").unwrap(),
    );
    let joined = crate::pipeline::cookie_header_joined(&h).expect("cookie must not vanish");
    assert!(joined.starts_with("xf_user=7; x="), "{joined:?}");
    // Multi-line: the non-ASCII line is joined, not dropped.
    h.append(
        header::COOKIE,
        http::HeaderValue::from_bytes(b"xf_style_id=9").unwrap(),
    );
    let joined = crate::pipeline::cookie_header_joined(&h).unwrap();
    assert!(
        joined.contains("xf_user=7") && joined.contains("xf_style_id=9"),
        "{joined:?}"
    );
    // Raw obs-text (invalid UTF-8) is replaced, and the crumb before it survives.
    let mut h = http::HeaderMap::new();
    h.append(
        header::COOKIE,
        http::HeaderValue::from_bytes(b"xf_session=abc; y=\x80").unwrap(),
    );
    assert!(
        crate::pipeline::cookie_header_joined(&h)
            .unwrap()
            .starts_with("xf_session=abc; y=")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_cond_on_cookie_sees_a_non_ascii_cookie_line() {
    let doc_root = temp_root("cookie_rw");
    std::fs::write(doc_root.join("index.html"), "<h1>home</h1>\n").unwrap();
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteCond %{HTTP_COOKIE} xf_user=\nRewriteRule .* - [F]\n",
    )
    .unwrap();
    let mut cfg = hj_pagecache::StoreConfig::default();
    cfg.standard_cc_vhosts.push(VHOST.into());
    let store = Arc::new(hj_pagecache::PageStore::new(cfg));
    let state = build_state_full(doc_root.clone(), Vec::new(), Vec::new(), Some(store), None);

    let req = http::Request::builder()
        .method("GET")
        .uri("/index.html")
        .header(header::HOST, CANON_HOST)
        .header(
            header::COOKIE,
            http::HeaderValue::from_bytes(b"xf_user=7; x=\xc3\xa9").unwrap(),
        )
        .body(hj_core::empty_incoming())
        .unwrap();
    let resp = run(&state, req).await;
    assert_eq!(
        resp.status(),
        403,
        "a non-ASCII crumb must not hide the cookie from %{{HTTP_COOKIE}}"
    );
    let _ = std::fs::remove_dir_all(doc_root);
}

// ─── R5: an unparsable REWRITTEN target must fail closed, not serve the
// pre-rewrite file. `[NE]` skips substitution escaping so a decoded capture's
// literal space reaches the static terminal's Uri construction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewritten_static_target_with_unparsable_query_fails_closed() {
    let doc_root = temp_root("failclosed400");
    std::fs::create_dir_all(doc_root.join("files")).unwrap();
    std::fs::write(doc_root.join("files").join("a b.txt"), b"target body\n").unwrap();
    // allow_override comes with the page-cache variant; the store itself stays idle here.
    let mut cfg = hj_pagecache::StoreConfig::default();
    cfg.standard_cc_vhosts.push(VHOST.into());
    let store = Arc::new(hj_pagecache::PageStore::new(cfg));
    let state = build_state_full(doc_root.clone(), Vec::new(), Vec::new(), Some(store), None);

    // [NE]: noescape keeps the raw space → build_uri fails → 400 (never the
    // original /q/... file or a silent fall-through).
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^q/(.*)$ /files/$1.txt?v=$1 [L,NE]\n",
    )
    .unwrap();

    let resp = run(&state, get(CANON_HOST, "/q/a%20b", None)).await;
    assert_eq!(
        resp.status(),
        400,
        "an unparsable rewritten target must fail closed"
    );

    // Without [NE] the same rule encodes cleanly and serves the target file.
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^q/(.*)$ /files/$1.txt?v=$1 [L]\n",
    )
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let resp = run(&state, get(CANON_HOST, "/q/a%20b", None)).await;
    let status = resp.status();
    let body = body_bytes(resp.into_body());
    assert_eq!(
        (status, body.as_ref()),
        (http::StatusCode::OK, b"target body\n".as_ref()),
        "unexpected response"
    );

    let _ = std::fs::remove_dir_all(doc_root);
}

// ─── R6: reserved cache endpoints are intercepted BEFORE the on-core fast path.
// A docroot file sitting at the reserved name must not answer a GET probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_paths_are_intercepted_before_the_fast_path() {
    let doc_root = temp_root("reserved");
    std::fs::write(doc_root.join("__hj_cache_ready"), b"vhost imposter\n").unwrap();
    let forwarder = crate::peer_purge::PurgeForwarder::new();
    let state = build_state_full(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        None,
        Some(forwarder),
    );

    // GET (the method the fast path serves) at the reserved name must return
    // the endpoint contract, not the docroot file. With no persisted store the
    // boot warm-scan is trivially complete -> 200 + ready:1.
    let resp = fast_serve_get(&state, "/__hj_cache_ready")
        .await
        .expect("reserved path intercepted on-core");
    assert_eq!(
        resp.status(),
        200,
        "endpoint contract, never the imposter file"
    );
    assert_eq!(
        resp.headers()
            .get("x-hj-cache-ready")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    assert_ne!(
        body_bytes(resp.into_body()).as_ref(),
        b"vhost imposter\n".as_ref(),
        "the docroot file at the reserved name must not be served"
    );

    let _ = std::fs::remove_dir_all(doc_root);
}

// ─── (#349) fast_memo under a `.htaccess`-heavy chain: the vary-set contract ───
// The production forum docroot file reads Origin (SetEnvIf → ACAO echo), the
// User-Agent (crawler class → X-Robots-Tag), Cookie (SetEnvIfNoCase) and
// `%{ENV:REDIRECT_STATUS}`, and carries scoped `Require`s and a `<FilesMatch>`
// canonical block. Every test below drives `fast_serve` on ONE thread (the
// memo is per-thread) and judges it by the :9090 counters plus byte identity.
mod fast_memo_e2e {
    use super::*;
    use std::sync::atomic::Ordering;

    const FORUM_HTACCESS: &str = r##"RewriteEngine On
<FilesMatch "\.(secret)$">
  Require all denied
</FilesMatch>
<Files "robots.txt">
  Require all granted
</Files>
Header set X-Static-Chain 1
Header unset ETag
SetEnvIf Query_String "(^|&)amp=1(&|$)" AMP_PAGE
SetEnvIf Origin "^https://(a\.test|b\.test)$" ORIGIN_ALLOWED=$0
Header set Access-Control-Allow-Origin "%{ORIGIN_ALLOWED}e" env=ORIGIN_ALLOWED
SetEnvIfNoCase Cookie xf_session_admin Cache-Control=no-cache
RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot)
RewriteRule .* - [E=KNOWN_CRAWLER:1]
Header set X-Robots-Tag "index, follow" env=KNOWN_CRAWLER
RewriteCond %{ENV:REDIRECT_STATUS} ^(403|5)
RewriteRule .* - [E=no-cache:1]
<FilesMatch "\.(css|js)$">
  RewriteCond %{HTTPS} !=on
  RewriteRule .* - [E=CANONICAL:http://%{HTTP_HOST}%{REQUEST_URI},NE]
  Header set Link "<%{CANONICAL}e>; rel=\"canonical\""
</FilesMatch>
RewriteCond %{REQUEST_FILENAME} -f
RewriteRule ^.*$ - [NC,L]
RewriteRule ^.*$ index.php [NC,L]
"##;

    fn setup(tag: &str, htaccess: &str) -> (PathBuf, Arc<ServerState>) {
        let doc_root = temp_root(tag);
        std::fs::write(doc_root.join("a.css"), "body{margin:0}\n").unwrap();
        std::fs::write(doc_root.join("robots.txt"), "User-agent: *\n").unwrap();
        std::fs::write(doc_root.join("x.secret"), "hidden\n").unwrap();
        std::fs::write(doc_root.join(".htaccess"), htaccess).unwrap();
        let state = build_state_htaccess(doc_root.clone());
        (doc_root, state)
    }

    fn req(path: &str, headers: &[(&str, &str)]) -> Request {
        let mut b = http::Request::builder()
            .method("GET")
            .uri(path)
            .header(header::HOST, CANON_HOST);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(hj_core::empty_incoming()).unwrap()
    }

    fn stores(state: &ServerState) -> u64 {
        state.metrics.fast_memo_stores.load(Ordering::Relaxed)
    }
    fn hits(state: &ServerState) -> u64 {
        state.metrics.fast_memo_hits.load(Ordering::Relaxed)
    }
    fn ineligible(state: &ServerState) -> u64 {
        state.metrics.fast_memo_ineligible.load(Ordering::Relaxed)
    }

    fn hdr<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
        r.headers().get(name).and_then(|v| v.to_str().ok())
    }

    async fn serve(state: &Arc<ServerState>, r: Request) -> Response {
        fast_serve_req(state, &r)
            .await
            .expect("static GET must be served on-core, not bridged")
    }

    #[tokio::test]
    async fn stores_then_replays_byte_identically_under_the_forum_chain() {
        let (root, state) = setup("memo_basic", FORUM_HTACCESS);
        let ua = ("user-agent", "Mozilla/5.0 Chrome/120");
        let first = serve(&state, req("/a.css", &[ua])).await;
        assert_eq!((stores(&state), hits(&state)), (1, 0), "first sight stores");
        assert_eq!(hdr(&first, "x-static-chain"), Some("1"));
        assert_eq!(
            hdr(&first, "link"),
            Some("<http://canon.test/a.css>; rel=\"canonical\""),
            "the FilesMatch canonical block ran for the store"
        );
        assert!(hdr(&first, "x-robots-tag").is_none());
        assert!(hdr(&first, "access-control-allow-origin").is_none());

        let second = serve(&state, req("/a.css", &[ua])).await;
        assert_eq!((stores(&state), hits(&state)), (1, 1), "repeat key replays");
        assert_eq!(second.status(), first.status());
        assert_eq!(
            second.headers(),
            first.headers(),
            "replayed headers are identical"
        );
        let (a, b) = (
            body_bytes(first.into_body()),
            body_bytes(second.into_body()),
        );
        assert_eq!(a, b);
        assert_eq!(&a[..], b"body{margin:0}\n");
        assert_eq!(ineligible(&state), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn varies_on_origin_exactly_like_the_setenvif_echo() {
        let (root, state) = setup("memo_origin", FORUM_HTACCESS);
        let none = serve(&state, req("/a.css", &[])).await;
        assert!(hdr(&none, "access-control-allow-origin").is_none());
        let a = serve(&state, req("/a.css", &[("origin", "https://a.test")])).await;
        assert_eq!(
            hdr(&a, "access-control-allow-origin"),
            Some("https://a.test")
        );
        let evil = serve(&state, req("/a.css", &[("origin", "https://evil.test")])).await;
        assert!(hdr(&evil, "access-control-allow-origin").is_none());
        assert_eq!(
            (stores(&state), hits(&state)),
            (3, 0),
            "three distinct vary values"
        );

        // Replays land on their OWN variant — never a sibling's ACAO.
        let a2 = serve(&state, req("/a.css", &[("origin", "https://a.test")])).await;
        assert_eq!(
            hdr(&a2, "access-control-allow-origin"),
            Some("https://a.test")
        );
        let none2 = serve(&state, req("/a.css", &[])).await;
        assert!(hdr(&none2, "access-control-allow-origin").is_none());
        let b = serve(&state, req("/a.css", &[("origin", "https://b.test")])).await;
        assert_eq!(
            hdr(&b, "access-control-allow-origin"),
            Some("https://b.test")
        );
        assert_eq!((stores(&state), hits(&state)), (4, 2));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn keys_the_user_agent_by_crawler_class_not_string() {
        let (root, state) = setup("memo_ua", FORUM_HTACCESS);
        // Classification is the deploy-time `--rewrite-ua-classify` tuning
        // (ON in prod); without it the memo varies on the raw UA (still correct).
        let mut tuned = build_state_htaccess(root.clone());
        Arc::get_mut(&mut tuned).unwrap().rewrite_ua_classify = true;
        drop(state);
        let state = tuned;
        let bot = serve(&state, req("/a.css", &[("user-agent", "Googlebot/2.1")])).await;
        assert_eq!(hdr(&bot, "x-robots-tag"), Some("index, follow"));
        let chrome = serve(&state, req("/a.css", &[("user-agent", "Chrome/120")])).await;
        assert!(hdr(&chrome, "x-robots-tag").is_none());
        assert_eq!((stores(&state), hits(&state)), (2, 0));

        let bing = serve(&state, req("/a.css", &[("user-agent", "Bingbot/2.0")])).await;
        assert_eq!(hdr(&bing, "x-robots-tag"), Some("index, follow"));
        let firefox = serve(&state, req("/a.css", &[("user-agent", "Firefox/130")])).await;
        assert!(hdr(&firefox, "x-robots-tag").is_none());
        assert_eq!(
            (stores(&state), hits(&state)),
            (2, 2),
            "a new UA string in a known class replays that class's entry"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn cookied_requests_never_store_or_replay() {
        let (root, state) = setup("memo_cookie", FORUM_HTACCESS);
        let c = ("cookie", "xf_session_admin=1");
        let _ = serve(&state, req("/a.css", &[c])).await;
        let _ = serve(&state, req("/a.css", &[c])).await;
        assert_eq!(
            (stores(&state), hits(&state), ineligible(&state)),
            (0, 0, 0)
        );
        // And a cookieless entry is never handed to a cookied request.
        let _ = serve(&state, req("/a.css", &[])).await;
        let _ = serve(&state, req("/a.css", &[c])).await;
        assert_eq!((stores(&state), hits(&state)), (1, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn address_dependent_chains_never_store_and_are_counted() {
        for (tag, extra) in [
            ("memo_remote_addr", "SetEnvIf Remote_Addr ^127\\. LOCAL=1\n"),
            (
                "memo_deny_net",
                "Order allow,deny\nAllow from 10.0.0.0/8\nAllow from 127.0.0.1\n",
            ),
            (
                "memo_cookie_cond",
                "RewriteCond %{HTTP_COOKIE} xf_user\nRewriteRule .* - [E=X:1]\n",
            ),
        ] {
            let (root, state) = setup(tag, &format!("{FORUM_HTACCESS}{extra}"));
            let _ = serve(&state, req("/a.css", &[])).await;
            let _ = serve(&state, req("/a.css", &[])).await;
            assert_eq!(
                (stores(&state), hits(&state), ineligible(&state)),
                (0, 0, 2),
                "{tag}"
            );
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn conditional_request_headers_bypass_the_memo() {
        let (root, state) = setup("memo_conditional", FORUM_HTACCESS);
        let _ = serve(&state, req("/a.css", &[])).await;
        assert_eq!(stores(&state), 1);
        // 412-class preconditions bridge (the static handler's verdict, not a
        // replayed 200) …
        for h in [
            ("if-match", "\"nope\""),
            ("if-unmodified-since", "Thu, 01 Jan 1970 00:00:00 GMT"),
        ] {
            assert!(
                fast_serve_req(&state, &req("/a.css", &[h])).await.is_none(),
                "{h:?} must not be answered from the memo"
            );
        }
        // … and a served-but-conditional request neither hits nor stores.
        let r = serve(&state, req("/a.css", &[("if-range", "\"nope\"")])).await;
        assert_eq!(r.status(), 200);
        assert_eq!((stores(&state), hits(&state)), (1, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn scoped_deny_and_canonical_link_follow_the_path() {
        let (root, state) = setup("memo_scopes", FORUM_HTACCESS);
        assert!(
            fast_serve_req(&state, &req("/x.secret", &[]))
                .await
                .is_none()
        );
        assert!(
            fast_serve_req(&state, &req("/x.secret", &[]))
                .await
                .is_none()
        );
        assert_eq!(
            (stores(&state), hits(&state)),
            (0, 0),
            "a denied path never memoizes"
        );
        let robots = serve(&state, req("/robots.txt", &[])).await;
        assert!(
            hdr(&robots, "link").is_none(),
            "canonical Link is FilesMatch-scoped"
        );
        let robots2 = serve(&state, req("/robots.txt", &[])).await;
        assert!(hdr(&robots2, "link").is_none());
        assert_eq!((stores(&state), hits(&state)), (1, 1));
        let _ = std::fs::remove_dir_all(root);
    }
}
