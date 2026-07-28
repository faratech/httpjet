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

use crate::pipeline::handle;
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
    // AccessLogger writes under server_root/logs; give it a real writable dir.
    let server_root = temp_root("srv");
    std::fs::create_dir_all(server_root.join("logs")).unwrap();

    let vhost_cfg = VHostConfig {
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
    let decl = VHostDecl {
        name: VHOST.into(),
        vh_root: doc_root.clone(),
        config_file: PathBuf::new(),
        allow_symbol_link: true,
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
        None,                                             // lsapi
        None,                                             // alt_svc
        None,                                             // page_cache
        Arc::new(hj_compress::PageDictRegistry::empty()), // page_cache_dicts
        1,                                                // admit base
        crate::state::XfCapsuleConfig::disabled(),
        None,  // peer_purge
        false, // cf_send_zstd
        None,  // php_slow
        false, // request_id_header
        crate::state::RewriteTuning::default(),
    )
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
