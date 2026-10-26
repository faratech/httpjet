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

#[path = "security_regressions.rs"]
mod security_regressions;

#[path = "scoped_auth_tests.rs"]
mod scoped_auth_tests;

#[path = "private_miss_egress_tests.rs"]
mod private_miss_egress_tests;

#[path = "php_env_tests.rs"]
mod php_env_tests;

const LISTENER: &str = "http";
const VHOST: &str = "testvh";
const CANON_HOST: &str = "canon.test";

/// Test temp roots live in `$TMPDIR`, often a RAM-backed tmpfs, and many tests
/// (every `build_state` server root) never remove theirs. Once per test process,
/// delete this suite's leftovers older than an hour: any concurrent run's are newer.
pub(super) fn sweep_stale_test_dirs() {
    static SWEEP: std::sync::Once = std::sync::Once::new();
    SWEEP.call_once(|| {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        let cutoff = std::time::Duration::from_secs(3600);
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !(name.starts_with("hj-e2e-") || name.starts_with("hj-rwdiff-")) {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > cutoff);
            if stale {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    });
}

fn temp_root(tag: &str) -> PathBuf {
    sweep_stale_test_dirs();
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
    MimeMap {
        by_suffix,
        default_type: None,
    }
}

/// A minimal real `ServerState`: one plaintext listener `http` mapping the exact
/// host `canon.test` (plus a `*` catch-all, so any OTHER host resolves to the
/// same vhost but counts as foreign) to a single vhost rooted at `doc_root`.
pub(crate) fn build_state(doc_root: PathBuf) -> Arc<ServerState> {
    build_state_with(doc_root, Vec::new(), Vec::new())
}

#[cfg(feature = "otel")]
pub(crate) fn build_state_websocket(doc_root: PathBuf, address: String) -> Arc<ServerState> {
    build_state_inner(
        doc_root,
        Vec::new(),
        Vec::new(),
        false,
        None,
        None,
        |config| {
            let vhost = config
                .vhosts
                .get_mut(VHOST)
                .unwrap()
                .config
                .as_mut()
                .unwrap();
            Arc::make_mut(vhost)
                .websockets
                .push(hj_core::config::WebSocketMap {
                    uri: "/socket".into(),
                    address,
                });
        },
    )
}

/// Synthetic handshake fixture; called only by the isolated telemetry process.
#[cfg(feature = "otel")]
pub(crate) async fn traced_websocket_handshakes(state: &ServerState) -> Vec<Option<String>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut observed = Vec::new();
    for named in [true, false] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(3), async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    assert!(head.len() < 8192);
                    head.push(stream.read_u8().await.unwrap());
                }
                stream
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                let head = String::from_utf8(head).unwrap();
                assert!(!head.to_ascii_lowercase().contains("baggage:"));
                assert!(!head.to_ascii_lowercase().contains("tracestate:"));
                head.lines().find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("traceparent")
                        .then(|| value.trim().to_owned())
                })
            })
            .await
            .unwrap()
        });
        let mut target = hj_proxy::ProxyTarget::parse_url(&format!("ws://{addr}/socket")).unwrap();
        target.name = named.then(|| "synthetic-websocket".to_owned());
        let mut req = http::Request::builder()
            .uri("/socket")
            .header("host", "canon.test")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("baggage", "secret=value")
            .header("tracestate", "secret=value")
            .body(hj_core::empty_incoming())
            .unwrap();
        let parent = crate::otel::inbound_parent(req.headers_mut(), addr.ip(), true);
        let ctx = super::tests::bare_ctx_for_headers();
        let response = crate::otel::request_with_parent(
            parent,
            super::proxy_glue::proxy_websocket(state, &ctx, req, target),
        )
        .await;
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
        drop(response);
        observed.push(upstream.await.unwrap());
    }
    observed
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
pub(crate) fn build_state_full(
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
        |_| {},
    )
}

/// A `.htaccess`-loading vhost WITHOUT a page cache: the fast_memo tests need
/// the per-dir chain but not the Branch-1 lookup in front of the static serve.
fn build_state_htaccess(doc_root: PathBuf) -> Arc<ServerState> {
    build_state_inner(doc_root, Vec::new(), Vec::new(), true, None, None, |_| {})
}

fn build_state_inner(
    doc_root: PathBuf,
    contexts: Vec<Context>,
    access_deny_dir: Vec<String>,
    htaccess: bool,
    page_cache: Option<Arc<hj_pagecache::PageStore>>,
    peer_purge: Option<crate::peer_purge::PurgeForwarder>,
    config_tweak: impl FnOnce(&mut ServerConfig),
) -> Arc<ServerState> {
    build_state_tuned(
        doc_root,
        contexts,
        access_deny_dir,
        htaccess,
        page_cache,
        peer_purge,
        config_tweak,
        crate::state::RewriteTuning::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_state_tuned(
    doc_root: PathBuf,
    contexts: Vec<Context>,
    access_deny_dir: Vec<String>,
    htaccess: bool,
    page_cache: Option<Arc<hj_pagecache::PageStore>>,
    peer_purge: Option<crate::peer_purge::PurgeForwarder>,
    config_tweak: impl FnOnce(&mut ServerConfig),
    rewrite_tuning: crate::state::RewriteTuning,
) -> Arc<ServerState> {
    build_state_with_lsapi(
        doc_root,
        contexts,
        access_deny_dir,
        htaccess,
        page_cache,
        peer_purge,
        config_tweak,
        rewrite_tuning,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_state_with_lsapi(
    doc_root: PathBuf,
    contexts: Vec<Context>,
    access_deny_dir: Vec<String>,
    htaccess: bool,
    page_cache: Option<Arc<hj_pagecache::PageStore>>,
    peer_purge: Option<crate::peer_purge::PurgeForwarder>,
    config_tweak: impl FnOnce(&mut ServerConfig),
    rewrite_tuning: crate::state::RewriteTuning,
    lsapi: Option<Arc<hj_lsapi::LsapiRegistry>>,
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
        proxy_protocol: false,
        proxy_protocol_peers: vec![],
        uds_path: None,
        vhost_map: vec![VhostMap {
            vhost: VHOST.into(),
            domains: vec![CANON_HOST.into(), "*".into()],
        }],
        tls: None,
    };

    let mut security = hj_core::config::Security::default();
    security.access_deny_dir = access_deny_dir;
    let mut server = ServerConfig {
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

    config_tweak(&mut server);
    ServerState::new(
        Arc::new(server),
        lsapi,
        None, // alt_svc
        page_cache,
        Arc::new(hj_compress::PageDictRegistry::empty()), // page_cache_dicts
        1,                                                // admit base
        crate::state::XfCapsuleConfig::disabled(),
        peer_purge,
        false, // cf_send_zstd
        None,  // php_slow
        false, // request_id_header
        rewrite_tuning,
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

fn run(
    state: &Arc<ServerState>,
    req: Request,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
    Box::pin(handle(
        state.clone(),
        LISTENER,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from(([127, 0, 0, 1], 80)),
        40000,
        false, // is_tls
        false, // peer_unix
        false, // client_auth_requested
        None,  // tls
        Proto::Http1,
        None, // sni
        req,
    ))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cgi_route_summary_reloads_and_missing_processor_fails_closed() {
    let root = temp_root("cgi-route-summary");
    const SOURCE: &[u8] = b"<?php echo 'must never be served';";
    std::fs::write(root.join("app.fcgi"), SOURCE).unwrap();

    let initial = build_state(root);
    assert!(!initial.has_cgi_script_routes);
    assert!(initial.fastcgi.is_empty());

    // A declared CGI suffix is security-significant even when its named
    // processor is absent: the script must resolve as executable and return
    // 503, never fall through to static source serving. The summary is rebuilt
    // from config on reload rather than inferred from the handler map.
    let mut with_route = (*initial.server).clone();
    let vhost = with_route
        .vhosts
        .get_mut(VHOST)
        .unwrap()
        .config
        .as_mut()
        .unwrap();
    Arc::make_mut(vhost).script_handlers.push(ScriptHandler {
        suffix: "fcgi".into(),
        kind: ContextKind::Cgi,
        handler: "missing-fastcgi".into(),
    });
    let routed = ServerState::reload(&initial, Arc::new(with_route)).unwrap();
    assert!(routed.has_cgi_script_routes);
    assert!(routed.fastcgi.is_empty());

    let response = run(&routed, get(CANON_HOST, "/app.fcgi", None)).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(body_bytes(response.into_body()).as_ref(), SOURCE);

    let mut without_route = (*routed.server).clone();
    let vhost = without_route
        .vhosts
        .get_mut(VHOST)
        .unwrap()
        .config
        .as_mut()
        .unwrap();
    Arc::make_mut(vhost)
        .script_handlers
        .retain(|handler| handler.kind != ContextKind::Cgi);
    let restored = ServerState::reload(&routed, Arc::new(without_route)).unwrap();
    assert!(!restored.has_cgi_script_routes);
}

/// #928: a suffix mapped only by the SERVER-level `<scriptHandlerList>` is an
/// executable route in every vhost; it must never be served as static source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_level_script_handler_is_executable_not_source() {
    let root = temp_root("server-script-handler");
    const SOURCE: &[u8] = b"<?php echo 'server-level handler source';";
    std::fs::write(root.join("app.php74"), SOURCE).unwrap();

    let server_xml = format!(
        "<httpServerConfig><scriptHandlerList><scriptHandler><suffix>php74</suffix>\
         <type>lsapi</type><handler>lsphp74</handler></scriptHandler></scriptHandlerList>\
         <virtualHostList><virtualHost><name>{VHOST}</name><vhRoot>{}</vhRoot>\
         <configFile>v.xml</configFile></virtualHost></virtualHostList></httpServerConfig>",
        root.display()
    );
    let vhost_xml = format!(
        "<virtualHostConfig><docRoot>{}</docRoot></virtualHostConfig>",
        root.display()
    );
    let documents = std::collections::BTreeMap::from([(VHOST.to_string(), vhost_xml)]);
    let parsed = hj_config::parse_bundle(&root, &server_xml, &documents, "").unwrap();
    let merged = parsed.vhosts[VHOST]
        .config
        .as_ref()
        .unwrap()
        .script_handlers
        .clone();
    assert!(
        merged
            .iter()
            .any(|h| h.suffix == "php74" && h.kind == ContextKind::Lsapi && h.handler == "lsphp74"),
        "{merged:?}"
    );

    let initial = build_state(root);
    let mut next = (*initial.server).clone();
    let vhost = next.vhosts.get_mut(VHOST).unwrap().config.as_mut().unwrap();
    Arc::make_mut(vhost).script_handlers.extend(merged);
    let state = ServerState::reload(&initial, Arc::new(next)).unwrap();

    let response = run(&state, get(CANON_HOST, "/app.php74", None)).await;
    assert_ne!(response.status(), http::StatusCode::OK);
    assert_ne!(body_bytes(response.into_body()).as_ref(), SOURCE);
}

/// #1027: LSWS treats a `<phpHandler>` id as a handled suffix, so the live
/// config's `<id>php8</id>` routes `*.php8` to PHP (here: no pool, 503) instead
/// of publishing the source, while `.php` keeps its route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn php_handler_id_is_an_executable_suffix_not_source() {
    let root = temp_root("php-handler-id");
    const SOURCE: &[u8] = b"<?php echo 'php8 handler source';";
    std::fs::write(root.join("app.php8"), SOURCE).unwrap();
    std::fs::write(root.join("app.php"), SOURCE).unwrap();

    let server_xml = format!(
        "<httpServerConfig><phpConfig><phpHandler><id>php8</id>\
         <command>/usr/local/lsws/lsphp8/bin/lsphp</command><suffixes>php, html</suffixes>\
         </phpHandler></phpConfig>\
         <virtualHostList><virtualHost><name>{VHOST}</name><vhRoot>{}</vhRoot>\
         <configFile>v.xml</configFile></virtualHost></virtualHostList></httpServerConfig>",
        root.display()
    );
    let vhost_xml = format!(
        "<virtualHostConfig><docRoot>{}</docRoot></virtualHostConfig>",
        root.display()
    );
    let documents = std::collections::BTreeMap::from([(VHOST.to_string(), vhost_xml)]);
    let parsed = hj_config::parse_bundle(&root, &server_xml, &documents, "").unwrap();
    let php = parsed.php_config.clone().unwrap();
    assert_eq!(php.suffixes, ["php", "html", "php8"]);

    let state = build_state_inner(root, Vec::new(), Vec::new(), false, None, None, |server| {
        server.php_config = Some(php);
    });
    for path in ["/app.php8", "/app.php"] {
        let response = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(
            response.status(),
            http::StatusCode::SERVICE_UNAVAILABLE,
            "{path}"
        );
        assert_ne!(body_bytes(response.into_body()).as_ref(), SOURCE, "{path}");
    }
}

fn assert_builtin_404_without(resp: Response, forbidden: &[u8]) {
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    let body = body_bytes(resp.into_body());
    assert!(
        !body
            .as_ref()
            .windows(forbidden.len())
            .any(|window| window == forbidden),
        "ErrorDocument target bytes must not be exposed"
    );
    assert!(
        String::from_utf8_lossy(&body).contains("<title>404 Not Found</title>"),
        "failed ErrorDocument substitution must preserve the built-in 404 body"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errordocument_script_source_is_not_served_when_php_is_unavailable_or_disabled() {
    const SOURCE: &[u8] = b"<?php echo 'error document secret';";
    for enabled in [true, false] {
        let root = temp_root(if enabled {
            "errordoc-no-php"
        } else {
            "errordoc-script-disabled"
        });
        std::fs::create_dir(root.join("errors")).unwrap();
        std::fs::write(root.join("errors/404.php"), SOURCE).unwrap();
        std::fs::write(
            root.join(".htaccess"),
            "ErrorDocument 404 /errors/404.php\n",
        )
        .unwrap();
        let state = build_state_inner(
            root,
            Vec::new(),
            Vec::new(),
            true,
            None,
            None,
            move |server| {
                server.vhosts.get_mut(VHOST).unwrap().enable_script = enabled;
            },
        );

        assert_builtin_404_without(run(&state, get(CANON_HOST, "/missing", None)).await, SOURCE);
        let direct = run(&state, get(CANON_HOST, "/errors/404.php", None)).await;
        assert_eq!(direct.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(body_bytes(direct.into_body()).as_ref(), SOURCE);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_scripts_preserve_static_directory_index_selection() {
    const STATIC_INDEX: &[u8] = b"static index remains available";
    let root = temp_root("disabled-script-static-index");
    std::fs::write(root.join("index.html"), STATIC_INDEX).unwrap();
    let state = build_state_inner(root, Vec::new(), Vec::new(), true, None, None, |server| {
        let declaration = server.vhosts.get_mut(VHOST).unwrap();
        declaration.enable_script = false;
        Arc::make_mut(declaration.config.as_mut().unwrap()).index_files =
            vec!["index.php".into(), "index.html".into()];
    });

    let response = run(&state, get(CANON_HOST, "/", None)).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(body_bytes(response.into_body()).as_ref(), STATIC_INDEX);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_scripts_allow_static_children_of_dotted_directories() {
    const STATIC_FILE: &[u8] = b"ordinary static child";
    let root = temp_root("disabled-script-dotted-directory");
    std::fs::create_dir(root.join("assets.php")).unwrap();
    std::fs::write(root.join("assets.php/logo.png"), STATIC_FILE).unwrap();
    let state = build_state_inner(root, Vec::new(), Vec::new(), true, None, None, |server| {
        server.vhosts.get_mut(VHOST).unwrap().enable_script = false;
    });

    let response = run(&state, get(CANON_HOST, "/assets.php/logo.png", None)).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(body_bytes(response.into_body()).as_ref(), STATIC_FILE);

    let response = run(&state, get(CANON_HOST, "/assets.php", None)).await;
    assert_eq!(response.status(), http::StatusCode::MOVED_PERMANENTLY);
    assert_eq!(response.headers()[http::header::LOCATION], "/assets.php/");

    let response = run(&state, get(CANON_HOST, "/missing.php", None)).await;
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_header_guard_cannot_populate_public_page_cache() {
    for (expression, supported) in [
        ("%{HTTP_COOKIE} == ''", false),
        ("%{REQUEST_URI} =~ m#^/# && %{REQUEST_STATUS} == 200", false),
        ("%{REQUEST_URI} =~ m#^/public#", true),
    ] {
        let root = temp_root("header-cache-guard");
        std::fs::write(root.join("public.txt"), b"ordinary public response").unwrap();
        std::fs::write(root.join(".htaccess"), format!(
            "CacheLookup public on\nHeader set X-LiteSpeed-Cache-Control public,max-age=60 \"expr={expression}\"\n"
        )).unwrap();
        let mut config = hj_pagecache::StoreConfig::default();
        config.max_static_obj_bytes = 0;
        let store = Arc::new(hj_pagecache::PageStore::new(config));
        let state = build_state_inner(
            root.clone(),
            Vec::new(),
            Vec::new(),
            true,
            Some(store.clone()),
            None,
            |_| {},
        );
        for _ in 0..3 {
            let response = run(&state, get(CANON_HOST, "/public.txt", None)).await;
            assert_eq!(
                response.status(),
                if supported {
                    http::StatusCode::OK
                } else {
                    http::StatusCode::FORBIDDEN
                }
            );
            if !supported {
                assert!(!response.headers().contains_key("x-litespeed-cache-control"));
            }
        }
        assert_eq!(store.stats().entries, u64::from(supported));
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// Regression (#1000): a disabled/suspended vhost answers 403 to every request (OLS
/// `processNewReqData`). Its page-cache entries are neither served nor refreshed, nothing
/// new is stored, and the on-core fast path bridges instead of replaying the entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_vhost_answers_403_without_touching_the_page_cache() {
    let root = temp_root("disabled-vhost");
    std::fs::write(root.join("page.txt"), b"cached public body").unwrap();
    std::fs::write(root.join("fresh.txt"), b"never cached body").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "CacheLookup public on\nHeader set X-LiteSpeed-Cache-Control public,max-age=60\n",
    )
    .unwrap();
    let mut config = hj_pagecache::StoreConfig::default();
    config.max_static_obj_bytes = 0;
    let store = Arc::new(hj_pagecache::PageStore::new(config));
    let state_for = |disabled: bool| {
        build_state_inner(
            root.clone(),
            Vec::new(),
            Vec::new(),
            true,
            Some(store.clone()),
            None,
            move |server| {
                let vhost = server.vhosts.get_mut(VHOST).unwrap();
                Arc::make_mut(vhost.config.as_mut().unwrap()).disabled = disabled;
            },
        )
    };

    let enabled = state_for(false);
    for _ in 0..2 {
        let response = run(&enabled, get(CANON_HOST, "/page.txt", None)).await;
        assert_eq!(response.status(), http::StatusCode::OK);
    }
    assert_eq!(store.stats().entries, 1);
    assert!(
        fast_serve_get(&enabled, "/page.txt").await.is_some(),
        "the stored entry serves on-core while the vhost is enabled"
    );

    let disabled = state_for(true);
    let before = store.stats();
    for path in ["/page.txt", "/fresh.txt", "/fresh.txt", "/missing", "/"] {
        let response = run(&disabled, get(CANON_HOST, path, None)).await;
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN, "{path}");
        assert!(
            !response.headers().contains_key("x-litespeed-cache"),
            "{path}"
        );
        let body = body_bytes(response.into_body());
        assert!(!body.as_ref().ends_with(b" body"), "{path}: {body:?}");
    }
    let foreign = run(&disabled, get("other.test", "/page.txt", None)).await;
    assert_eq!(foreign.status(), http::StatusCode::FORBIDDEN);
    assert!(fast_serve_get(&disabled, "/page.txt").await.is_none());
    let reasons: std::collections::HashMap<_, _> =
        disabled.metrics.fast_bridge.snapshot().collect();
    assert_eq!(reasons["vhost_disabled"], 1);
    let after = store.stats();
    assert_eq!(
        (after.entries, after.hits, after.misses, after.stores),
        (before.entries, before.hits, before.misses, before.stores),
        "a disabled vhost never looks up or stores page-cache entries"
    );
    std::fs::remove_dir_all(root).unwrap();
}

/// Write a server root whose `http` listener maps `good.test` to a vhost serving
/// `page.txt` and `stub.test` to a vhost whose file is `stub_xml`.
pub(crate) fn write_stub_vhost_root(tag: &str, stub_xml: &str) -> PathBuf {
    let root = temp_root(tag);
    let doc_root = root.join("good-html");
    std::fs::create_dir_all(root.join("conf/vhosts")).unwrap();
    std::fs::create_dir_all(root.join("logs")).unwrap();
    std::fs::create_dir_all(&doc_root).unwrap();
    std::fs::write(doc_root.join("page.txt"), b"good vhost body").unwrap();
    let decl = |name: &str| {
        format!(
            "<virtualHost><name>{name}</name><vhRoot>{}/</vhRoot>\
             <configFile>$SERVER_ROOT/conf/vhosts/{name}.xml</configFile></virtualHost>",
            root.display()
        )
    };
    std::fs::write(
        root.join("conf/httpd_config.xml"),
        format!(
            "<httpServerConfig><serverName>e2e</serverName><listenerList><listener>\
             <name>{LISTENER}</name><address>127.0.0.1:0</address><secure>0</secure>\
             <vhostMapList><vhostMap><vhost>good</vhost><domain>good.test</domain></vhostMap>\
             <vhostMap><vhost>stub</vhost><domain>stub.test</domain></vhostMap></vhostMapList>\
             </listener></listenerList><virtualHostList>{}{}</virtualHostList></httpServerConfig>",
            decl("good"),
            decl("stub")
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("conf/vhosts/good.xml"),
        format!(
            "<virtualHostConfig><docRoot>{}</docRoot></virtualHostConfig>",
            doc_root.display()
        ),
    )
    .unwrap();
    std::fs::write(root.join("conf/vhosts/stub.xml"), stub_xml).unwrap();
    root
}

/// Regression (#1010): a declared vhost whose file has no `<docRoot>` (LSWS's stub
/// `default.xml`) is skipped as OLS skips it. The server still starts, the other
/// vhost serves, and the stub's mapped host answers 503.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vhost_without_doc_root_is_skipped_and_its_host_answers_503() {
    let root = write_stub_vhost_root("stub-vhost", "<virtualHostConfig></virtualHostConfig>");
    let cfg = hj_config::load(&root).expect("a stub vhost must not fail the whole load");
    assert!(cfg.vhosts["stub"].config.is_none());
    let state = ServerState::new(
        Arc::new(cfg),
        None,
        None,
        None,
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

    let good = run(&state, get("good.test", "/page.txt", None)).await;
    assert_eq!(good.status(), http::StatusCode::OK);
    assert_eq!(&body_bytes(good.into_body())[..], b"good vhost body");
    for path in ["/page.txt", "/"] {
        let stub = run(&state, get("stub.test", path, None)).await;
        assert_eq!(
            stub.status(),
            http::StatusCode::SERVICE_UNAVAILABLE,
            "{path}"
        );
    }
    let unknown = run(&state, get("other.test", "/page.txt", None)).await;
    assert_eq!(unknown.status(), http::StatusCode::NOT_FOUND);
    std::fs::remove_dir_all(root).unwrap();
}

/// Regression (#603): `.htaccess` headers set only for crawlers (KNOWN_CRAWLER via a
/// User-Agent RewriteCond, as on the live forum) must not be replayed to browsers from a
/// crawler-primed public entry, and browsers must not hand crawlers their entry either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crawler_conditional_headers_are_not_served_across_ua_classes() {
    let root = temp_root("ua-class-cache");
    std::fs::write(root.join("page.txt"), b"same body for every client").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "CacheLookup public on\n\
         RewriteEngine On\n\
         RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot)\n\
         RewriteRule .* - [E=KNOWN_CRAWLER:1]\n\
         Header set X-LiteSpeed-Cache-Control \"public,max-age=60\"\n\
         Header set X-Crawler-Detected \"true\" env=KNOWN_CRAWLER\n",
    )
    .unwrap();
    let mut config = hj_pagecache::StoreConfig::default();
    config.max_static_obj_bytes = 0;
    let store = Arc::new(hj_pagecache::PageStore::new(config));
    let state = build_state_tuned(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |_| {},
        crate::state::RewriteTuning {
            ua_classify: true,
            ..Default::default()
        },
    );
    let as_ua = |ua: &str| {
        let mut req = get(CANON_HOST, "/page.txt", None);
        req.headers_mut()
            .insert(header::USER_AGENT, ua.parse().unwrap());
        req
    };
    let crawler_header = |resp: &Response| resp.headers().contains_key("x-crawler-detected");
    let googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1)";
    let chrome = "Mozilla/5.0 (X11; Linux) Chrome/140";
    for _ in 0..3 {
        let resp = run(&state, as_ua(googlebot)).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(crawler_header(&resp), "a crawler gets the crawler headers");
    }
    assert_eq!(store.stats().entries, 1, "the crawler render was stored");
    for _ in 0..3 {
        let resp = run(&state, as_ua(chrome)).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(
            !crawler_header(&resp),
            "a browser never gets the crawler's headers"
        );
    }
    assert_eq!(store.stats().entries, 2, "browsers got their own entry");
    let resp = run(&state, as_ua("Mozilla/5.0 (compatible; Bingbot/2.0)")).await;
    assert!(
        crawler_header(&resp),
        "another crawler shares the crawler class"
    );

    // The on-core fast path (the first lookup for cookieless traffic in prod) must
    // key by the same class: each UA gets its own entry's headers from a hit.
    for (ua, crawler) in [(chrome, false), (googlebot, true)] {
        let req = as_ua(ua);
        let resp = fast_serve(
            &state,
            LISTENER,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::from(([127, 0, 0, 1], 80)),
            40000,
            false,
            false,
            false,
            Proto::Http1,
            None,
            &req,
        )
        .await
        .expect("a cookieless warm entry is served on-core");
        assert_eq!(crawler_header(&resp), crawler, "{ua}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_script_directory_candidate_cannot_populate_page_cache() {
    const STATIC_INDEX: &[u8] = b"cacheable static fallback";
    let root = temp_root("disabled-script-page-cache");
    std::fs::write(root.join("index.html"), STATIC_INDEX).unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "CacheLookup public on\n\
         Header set X-LiteSpeed-Cache-Control \"public,max-age=60\"\n",
    )
    .unwrap();

    let new_store = || {
        let mut cfg = hj_pagecache::StoreConfig::default();
        // Keep the count specific to origin-page entries; the unified static
        // body cache is unrelated to the route gate exercised here.
        cfg.max_static_obj_bytes = 0;
        Arc::new(hj_pagecache::PageStore::new(cfg))
    };

    // Positive control: the same cacheable static fallback populates normally
    // when script execution is allowed and the missing index.php is skipped.
    let enabled_store = new_store();
    let enabled_state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(enabled_store.clone()),
        None,
        |server| {
            Arc::make_mut(
                server
                    .vhosts
                    .get_mut(VHOST)
                    .unwrap()
                    .config
                    .as_mut()
                    .unwrap(),
            )
            .index_files = vec!["index.php".into(), "index.html".into()];
        },
    );
    let response = run(&enabled_state, get(CANON_HOST, "/", None)).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(body_bytes(response.into_body()).as_ref(), STATIC_INDEX);
    assert_eq!(
        enabled_store.entry_count(),
        1,
        "positive control must store"
    );

    let disabled_store = new_store();
    let disabled_state = build_state_inner(
        root,
        Vec::new(),
        Vec::new(),
        true,
        Some(disabled_store.clone()),
        None,
        |server| {
            let declaration = server.vhosts.get_mut(VHOST).unwrap();
            declaration.enable_script = false;
            Arc::make_mut(declaration.config.as_mut().unwrap()).index_files =
                vec!["index.php".into(), "index.html".into()];
        },
    );
    let response = run(&disabled_state, get(CANON_HOST, "/", None)).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(body_bytes(response.into_body()).as_ref(), STATIC_INDEX);
    assert_eq!(
        disabled_store.entry_count(),
        0,
        "the disabled route must not populate an origin-page entry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_scripts_reject_precompressed_directory_index_source() {
    const SOURCE: &[u8] = b"<?php echo 'logical script source';";
    const COMPRESSED_SOURCE: &[u8] = b"precompressed-script-source";
    let root = temp_root("disabled-script-precompressed-index");
    std::fs::write(root.join("index.php"), SOURCE).unwrap();
    std::fs::write(root.join("index.php.br"), COMPRESSED_SOURCE).unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |server| {
            let declaration = server.vhosts.get_mut(VHOST).unwrap();
            declaration.enable_script = false;
            Arc::make_mut(declaration.config.as_mut().unwrap()).index_files =
                vec!["index.php".into()];
        },
    );
    let mut request = get(CANON_HOST, "/", None);
    request.headers_mut().insert(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static("br"),
    );

    let response = run(&state, request).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    let body = body_bytes(response.into_body());
    assert_ne!(body.as_ref(), SOURCE);
    assert_ne!(body.as_ref(), COMPRESSED_SOURCE);

    // The conditional static path used to omit Content-Encoding on its 304,
    // which hid the logical `.php` suffix from the resolved-target backstop.
    // `If-None-Match: *` exercises that path without first exposing a 200.
    let mut conditional = get(CANON_HOST, "/", Some("*"));
    conditional.headers_mut().insert(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static("br"),
    );
    let response = run(&state, conditional).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(response.status(), http::StatusCode::NOT_MODIFIED);

    // A direct representation request has no Content-Encoding metadata, but
    // the `.br` wrapper must not hide the executable suffix.
    let response = run(&state, get(CANON_HOST, "/index.php.br", None)).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(body_bytes(response.into_body()).as_ref(), COMPRESSED_SOURCE);

    // Script routing being enabled does not make compressed PHP source an
    // executable request; the static fallback must reject it just the same.
    let enabled = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );
    let response = run(&enabled, get(CANON_HOST, "/index.php.br", None)).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(body_bytes(response.into_body()).as_ref(), COMPRESSED_SOURCE);

    // A file-tier entry can survive a deploy. Seed the vulnerable URL exactly
    // as an older binary could have stored it, then prove both the on-core and
    // full lookup paths bypass the hit before exact static-target validation.
    let mut cache_cfg = hj_pagecache::StoreConfig::default();
    cache_cfg.standard_cc_vhosts.push(VHOST.into());
    let store = Arc::new(hj_pagecache::PageStore::new(cache_cfg));
    let cached = build_state_full(
        root.clone(),
        Vec::new(),
        Vec::new(),
        Some(store.clone()),
        None,
    );
    seed_public_entry(&cached, &store, "/index.php.br", COMPRESSED_SOURCE).await;
    assert_eq!(store.entry_count(), 1, "precondition: stale entry stored");
    assert!(
        fast_serve_get(&cached, "/index.php.br").await.is_none(),
        "on-core lookup replayed the persisted source entry"
    );
    let response = run(&cached, get(CANON_HOST, "/index.php.br", None)).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(
        response
            .headers()
            .get("x-litespeed-cache")
            .and_then(|value| value.to_str().ok()),
        Some("hit")
    );
    assert_ne!(body_bytes(response.into_body()).as_ref(), COMPRESSED_SOURCE);

    let mut dir_cache_cfg = hj_pagecache::StoreConfig::default();
    dir_cache_cfg.standard_cc_vhosts.push(VHOST.into());
    let dir_store = Arc::new(hj_pagecache::PageStore::new(dir_cache_cfg));
    let cached_directory = build_state_inner(
        root,
        Vec::new(),
        Vec::new(),
        true,
        Some(dir_store.clone()),
        None,
        |server| {
            Arc::make_mut(
                server
                    .vhosts
                    .get_mut(VHOST)
                    .unwrap()
                    .config
                    .as_mut()
                    .unwrap(),
            )
            .index_files = vec!["index.php.br".into()];
        },
    );
    seed_public_entry(&cached_directory, &dir_store, "/", COMPRESSED_SOURCE).await;
    assert_eq!(
        dir_store.entry_count(),
        1,
        "precondition: stale directory entry stored"
    );
    assert!(
        fast_serve_get(&cached_directory, "/").await.is_none(),
        "on-core lookup replayed a wrapped DirectoryIndex entry"
    );
    let response = run(&cached_directory, get(CANON_HOST, "/", None)).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(
        response
            .headers()
            .get("x-litespeed-cache")
            .and_then(|value| value.to_str().ok()),
        Some("hit")
    );
    assert_ne!(body_bytes(response.into_body()).as_ref(), COMPRESSED_SOURCE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_script_rewrite_proxy_strips_untrusted_cache_control_headers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut buf = [0_u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buf).await.unwrap();
            assert_ne!(read, 0);
            head.extend_from_slice(&buf[..read]);
            assert!(head.len() < 8192);
        }
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Length: 2\r\n\
                  X-LiteSpeed-Purge: *\r\n\
                  X-LiteSpeed-Cache-Control: public,max-age=60\r\n\
                  X-LiteSpeed-Tag: T1\r\n\
                  X-WF-Capsule: max-age=60\r\n\
                  X-WF-Capsule-Tags: T1\r\n\
                  Connection: close\r\n\r\nOK",
            )
            .await
            .unwrap();
    });

    let root = temp_root("disabled-script-rewrite-proxy-cache-control");
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "RewriteEngine On\n\
             RewriteRule ^/route\\.php$ http://{address}/upstream [P,L]\n\
             Header set X-LiteSpeed-Purge \"*\"\n\
             Header set X-LiteSpeed-Cache-Control \"public,max-age=60\"\n\
             Header set X-LiteSpeed-Tag \"T-local\"\n\
             Header set X-LiteSpeed-Vary \"cookie=xf_style_id\"\n"
        ),
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let state = build_state_inner(
        root,
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |server| {
            server.vhosts.get_mut(VHOST).unwrap().enable_script = false;
            server.ext_processors.push(hj_core::config::ExtProcessor {
                name: "rewrite-upstream".into(),
                kind: hj_core::config::ExtKind::Proxy,
                address: hj_core::config::ExtAddress::Tcp(address),
                extra_addresses: Vec::new(),
                load_balance: Default::default(),
                client_cert_file: None,
                client_key_file: None,
                max_conns: 2,
                init_timeout: std::time::Duration::from_secs(1),
                retry_timeout: std::time::Duration::ZERO,
                pc_keep_alive_timeout: std::time::Duration::from_secs(1),
                resp_buffer: false,
                env: Vec::new(),
                auto_start: 0,
                path: None,
                backlog: 0,
                instances: 0,
                run_on_startup: 0,
            });
        },
    );
    let before = store.purge_epoch();
    let response = run(&state, get(CANON_HOST, "/route.php", None)).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    for name in [
        "x-litespeed-purge",
        "x-litespeed-cache-control",
        "x-litespeed-tag",
        "x-litespeed-vary",
        "x-wf-capsule",
        "x-wf-capsule-tags",
    ] {
        assert!(
            !response.headers().contains_key(name),
            "internal cache header leaked: {name}"
        );
    }
    assert!(
        store.purge_epoch() > before,
        "trusted local purge directive was ignored"
    );
    assert_eq!(store.entry_count(), 0, "disabled route must not be stored");
    drop(response);
    upstream.await.unwrap();
}

/// Registers `address` as a proxy ext-processor so a rewrite `[P]` to it passes the SSRF screen.
fn register_upstream(server: &mut ServerConfig, address: SocketAddr) {
    server.ext_processors.push(hj_core::config::ExtProcessor {
        name: "test-upstream".into(),
        kind: hj_core::config::ExtKind::Proxy,
        address: hj_core::config::ExtAddress::Tcp(address),
        extra_addresses: Vec::new(),
        load_balance: Default::default(),
        client_cert_file: None,
        client_key_file: None,
        max_conns: 4,
        init_timeout: std::time::Duration::from_secs(1),
        retry_timeout: std::time::Duration::ZERO,
        pc_keep_alive_timeout: std::time::Duration::from_secs(1),
        resp_buffer: false,
        env: Vec::new(),
        auto_start: 0,
        path: None,
        backlog: 0,
        instances: 0,
        run_on_startup: 0,
    });
}

/// A `[P]` whose upstream host the request chose (a substitution in the authority)
/// never receives the visitor's Cookie or Authorization; a literal upstream does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn substituted_proxy_authority_withholds_credentials() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0_u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            let echo = String::from_utf8_lossy(&head).to_ascii_lowercase();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{echo}",
                echo.len()
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });

    let root = temp_root("p-substituted-authority");
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "RewriteEngine On\n\
             RewriteRule ^lit$ http://{address}/lit [P,L]\n\
             RewriteCond %{{HTTP:X-Up}} (.+)\n\
             RewriteRule ^dyn$ http://%1/dyn [P,L]\n"
        ),
    )
    .unwrap();
    let state = build_state_inner(root, Vec::new(), Vec::new(), true, None, None, |server| {
        register_upstream(server, address)
    });
    let upstream_host = address.to_string();
    for (path, forwarded) in [("/lit", true), ("/dyn", false)] {
        let request = get_with(
            CANON_HOST,
            path,
            &[
                ("Cookie", "sid=secret"),
                ("Authorization", "Basic dXNlcjpwYXNz"),
                ("Proxy-Authorization", "Basic dXNlcjpwYXNz"),
                ("X-Up", &upstream_host),
            ],
        );
        let response = run(&state, request).await;
        assert_eq!(response.status(), http::StatusCode::OK, "{path}");
        let echo = response_text(response).await;
        assert!(echo.starts_with(&format!("get {path} ")), "{echo}");
        assert_eq!(echo.contains("sid=secret"), forwarded, "{path}: {echo}");
        assert_eq!(
            echo.contains("\r\nauthorization:"),
            forwarded,
            "{path}: {echo}"
        );
        assert!(!echo.contains("proxy-authorization"), "{path}: {echo}");
    }
    upstream.abort();
}

/// Regression (#658): a cached redirect is never answered 304 (RFC 9110 §13.2.1), and an
/// empty-body redirect gets no synthesized body-hash ETag that every redirect would share.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_redirect_ignores_if_none_match() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0_u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            let etag = if head.windows(8).any(|w| w == b"/tagged ") {
                "ETag: \"r1\"\r\n"
            } else {
                ""
            };
            let reply = format!(
                "HTTP/1.1 301 Moved Permanently\r\n\
                 Location: /new\r\n\
                 {etag}Content-Length: 0\r\n\
                 X-LiteSpeed-Cache-Control: public,max-age=60\r\n\
                 Connection: close\r\n\r\n"
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });

    let root = temp_root("redirect-inm");
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "CacheLookup public on\n\
             RewriteEngine On\n\
             RewriteRule ^/(plain|tagged)$ http://{address}/$1 [P,L]\n\
             Header set X-LiteSpeed-Cache-Control public,max-age=60\n"
        ),
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let state = build_state_inner(
        root,
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |server| register_upstream(server, address),
    );
    for _ in 0..3 {
        let response = run(&state, get(CANON_HOST, "/plain", None)).await;
        assert_eq!(response.status(), http::StatusCode::MOVED_PERMANENTLY);
        assert!(!response.headers().contains_key(header::ETAG));
        run(&state, get(CANON_HOST, "/tagged", None)).await;
    }
    assert!(store.entry_count() >= 2, "redirects were not cached");
    let response = run(&state, get(CANON_HOST, "/tagged", Some("\"r1\""))).await;
    assert_eq!(response.headers().get("x-litespeed-cache").unwrap(), "hit");
    assert_eq!(response.status(), http::StatusCode::MOVED_PERMANENTLY);
    let response = run(&state, get(CANON_HOST, "/plain", Some("*"))).await;
    assert_eq!(response.status(), http::StatusCode::MOVED_PERMANENTLY);
    upstream.abort();
}

/// An Origin whose vary digest collides with a legitimate one must render its own entry: under
/// the former unkeyed FNV-1a-64 fold the victim Origin was a HIT on the attacker's render and
/// received the attacker's reflected `Access-Control-Allow-Origin`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn colliding_origins_never_share_a_page_cache_entry() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0_u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let origin = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("origin")
                        .then(|| value.trim().to_owned())
                })
                .unwrap_or_default();
            let body = format!("render for {origin}");
            let reply = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    let root = temp_root("pc-origin-collision");
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "CacheLookup public on\n\
             SetEnvIf Origin \"^https://(windowsforum\\.com|.*\\.windowsforum\\.com|www\\.google\\.com)$\" ORIGIN_ALLOWED=$0\n\
             Header set Access-Control-Allow-Origin \"%{{ORIGIN_ALLOWED}}e\" env=ORIGIN_ALLOWED\n\
             RewriteEngine On\n\
             RewriteRule ^/?(.*)$ http://{address}/$1 [P,L]\n\
             Header set X-LiteSpeed-Cache-Control public,max-age=60\n"
        ),
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |server| register_upstream(server, address),
    );
    let fetch = |path: &'static str, origin: &'static str| {
        let state = state.clone();
        async move {
            let response = run(&state, get_with(CANON_HOST, path, &[("origin", origin)])).await;
            assert_eq!(response.status(), http::StatusCode::OK, "{origin}");
            let header = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            let (cache, acao) = (
                header("x-litespeed-cache"),
                header("access-control-allow-origin"),
            );
            let body = String::from_utf8(hop_body(response.into_body()).await).unwrap();
            (cache, acao, body)
        }
    };
    for (path, (attacker, victim)) in ["/a", "/b"]
        .into_iter()
        .zip(crate::lscache::FNV_COLLIDING_ORIGINS)
    {
        for _ in 0..2 {
            let (_, acao, body) = fetch(path, attacker).await;
            assert_eq!(acao.as_deref(), Some(attacker));
            assert_eq!(body, format!("render for {attacker}"));
        }
        let (cache, _, _) = fetch(path, attacker).await;
        assert_eq!(
            cache.as_deref(),
            Some("hit"),
            "the attacker render is stored"
        );
        let (cache, acao, body) = fetch(path, victim).await;
        assert_ne!(
            cache.as_deref(),
            Some("hit"),
            "{victim} hit {attacker}'s entry"
        );
        assert_eq!(acao.as_deref(), Some(victim));
        assert_eq!(body, format!("render for {victim}"));
    }
    upstream.abort();
    std::fs::remove_dir_all(root).ok();
}

/// Regression (#938): two exact vhostMap aliases of one vhost whose backend renders the request
/// Host into the canonical link must each get their own entry — a `www.` render served as a
/// HIT to the apex is the cross-served canonical. Tag purges still reach every alias entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_aliases_get_their_own_page_cache_entries() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const APEX: &str = "alias.test";
    const WWW: &str = "www.alias.test";

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let renders = Arc::new(AtomicUsize::new(0));
    let upstream_renders = renders.clone();
    let upstream = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0_u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            upstream_renders.fetch_add(1, Ordering::SeqCst);
            let head = String::from_utf8_lossy(&head).into_owned();
            let host = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("host")
                        .then(|| value.trim().to_owned())
                })
                .unwrap_or_default();
            let body = format!("<link rel=\"canonical\" href=\"https://{host}/page\">");
            let reply = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 Content-Length: {}\r\n\
                 X-LiteSpeed-Cache-Control: public,max-age=60\r\n\
                 X-LiteSpeed-Tag: T1\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });

    let root = temp_root("exact-alias-cache");
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "CacheLookup public on\n\
             RewriteEngine On\n\
             RewriteRule ^/page$ http://{address}/page [P,L]\n\
             Header set X-LiteSpeed-Cache-Control public,max-age=60\n\
             Header set X-LiteSpeed-Tag T1\n"
        ),
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let state = build_state_inner(
        root,
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |server| {
            register_upstream(server, address);
            // The vhost is NAMED after its apex; www. is an exact alias.
            let mut decl = server.vhosts.remove(VHOST).unwrap();
            decl.name = APEX.into();
            server.vhosts.insert(APEX.into(), decl);
            server.vhost_order = vec![APEX.into()];
            server.listeners[0].vhost_map = vec![VhostMap {
                vhost: APEX.into(),
                domains: vec![APEX.into(), WWW.into(), "*".into()],
            }];
        },
    );
    let fetch = |host: &'static str| {
        let state = state.clone();
        async move {
            let response = run(&state, get(host, "/page", None)).await;
            assert_eq!(response.status(), http::StatusCode::OK, "{host}");
            let status = response
                .headers()
                .get("x-litespeed-cache")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let body = String::from_utf8(hop_body(response.into_body()).await).unwrap();
            (status, body)
        }
    };
    let canonical = |host: &str| format!("<link rel=\"canonical\" href=\"https://{host}/page\">");

    // The www. render is stored first; the apex must render its own, never hit the www. copy.
    let (_, body) = fetch(WWW).await;
    assert_eq!(body, canonical(WWW));
    let (status, body) = fetch(APEX).await;
    assert_ne!(status.as_deref(), Some("hit"), "apex served the www. entry");
    assert_eq!(body, canonical(APEX));
    assert_eq!(renders.load(Ordering::SeqCst), 2);
    // Both now hit, each with its own Host's canonical link.
    for host in [WWW, APEX, WWW, APEX] {
        let (status, body) = fetch(host).await;
        assert_eq!(status.as_deref(), Some("hit"), "{host}");
        assert_eq!(body, canonical(host));
    }
    assert_eq!(renders.load(Ordering::SeqCst), 2);
    assert_eq!(store.entry_count(), 2);

    // A tag purge invalidates the alias entry as well as the canonical one.
    store.purge_tags(&["T1"]);
    for host in [WWW, APEX] {
        let (status, body) = fetch(host).await;
        assert_ne!(
            status.as_deref(),
            Some("hit"),
            "{host} survived the tag purge"
        );
        assert_eq!(body, canonical(host));
    }
    assert_eq!(renders.load(Ordering::SeqCst), 4);
    upstream.abort();
}

/// Regression (#657): a HEAD miss can never store, so it must not become the single-flight
/// leader that concurrent GETs of the same page park behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn head_miss_does_not_lead_page_cache_single_flight() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut buf = [0_u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buf).await.unwrap();
            assert_ne!(read, 0);
            head.extend_from_slice(&buf[..read]);
        }
        seen_tx.send(()).unwrap();
        release_rx.await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Length: 2\r\n\
                  X-LiteSpeed-Cache-Control: public,max-age=60\r\n\
                  Connection: close\r\n\r\nOK",
            )
            .await
            .unwrap();
    });

    let root = temp_root("head-single-flight");
    std::fs::write(
        root.join(".htaccess"),
        "CacheLookup public on\nHeader set X-LiteSpeed-Cache-Control public,max-age=60\n",
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let context = Context {
        kind: ContextKind::Proxy,
        uri: "/page".into(),
        location: None,
        handler: Some("test-upstream".into()),
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: None,
        charset: None,
        cache_policy: None,
        max_body_override: None,
        bandwidth_limit: 0,
        timeout_override: None,
        sub_filter: None,
    };
    let state = build_state_inner(
        root,
        vec![context],
        Vec::new(),
        true,
        Some(store),
        None,
        |server| register_upstream(server, address),
    );
    let head_state = state.clone();
    let head = tokio::spawn(async move {
        let mut req = get(CANON_HOST, "/page", None);
        *req.method_mut() = http::Method::HEAD;
        run(&head_state, req).await
    });
    let mut head = head;
    tokio::select! {
        seen = seen_rx => seen.unwrap(),
        done = &mut head => panic!("HEAD finished without reaching upstream: {:?}", done.unwrap().status()),
    }
    assert_eq!(
        state.page_cache_inflight.len(),
        0,
        "HEAD miss registered as single-flight leader"
    );
    release_tx.send(()).unwrap();
    assert_eq!(head.await.unwrap().status(), http::StatusCode::OK);
    upstream.await.unwrap();
}

/// Regression (#983): a cookied POST computes none of the page-cache key inputs (it can
/// never look up or store an entry), yet its `X-LiteSpeed-Purge` still purges, its control
/// headers are still stripped, and a member POST is not counted as a capsule
/// `not_allowed` miss. GET and HEAD stay keyed: HEAD hits the GET-stored entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookied_post_skips_cache_key_inputs_but_still_purges() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let renders = Arc::new(AtomicUsize::new(0));
    let upstream_renders = renders.clone();
    let upstream = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0_u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                assert_ne!(read, 0);
                head.extend_from_slice(&buf[..read]);
            }
            upstream_renders.fetch_add(1, Ordering::SeqCst);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
        }
    });

    let root = temp_root("cookied-post-unkeyed");
    std::fs::write(
        root.join(".htaccess"),
        "CacheLookup public on\n\
         SetEnvIf Cookie \"xf_style_id=(\\d+)\" STYLE=$1\n\
         Header set X-LiteSpeed-Cache-Control \"public,max-age=60\"\n\
         Header set X-LiteSpeed-Tag \"T1\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("act")).unwrap();
    std::fs::write(
        root.join("act/.htaccess"),
        "Header set X-LiteSpeed-Purge \"tag=T1\"\n",
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(hj_pagecache::StoreConfig {
        vary_cookies: vec!["xf_style_id".into()],
        private_user_cookie: "xf_user".into(),
        private_session_cookie: "xf_session".into(),
        ..hj_pagecache::StoreConfig::default()
    }));
    let context = Context {
        kind: ContextKind::Proxy,
        uri: "/".into(),
        location: None,
        handler: Some("test-upstream".into()),
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: None,
        charset: None,
        cache_policy: None,
        max_body_override: None,
        bandwidth_limit: 0,
        timeout_override: None,
        sub_filter: None,
    };
    let state = build_state_inner(
        root,
        vec![context],
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |server| register_upstream(server, address),
    );
    let request = |method: http::Method, path: &str, cookie: &str| {
        let mut req = get(CANON_HOST, path, None);
        *req.method_mut() = method;
        req.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        req
    };
    let header_vary_calls = || super::rewrite_glue::HEADER_VARY_CALLS.with(|calls| calls.get());
    let cache_status = |resp: &Response| {
        resp.headers()
            .get("x-litespeed-cache")
            .map(|v| v.to_str().unwrap().to_string())
    };

    let before = header_vary_calls();
    let fill = run(&state, request(http::Method::GET, "/page", "xf_style_id=2")).await;
    assert_eq!(fill.status(), http::StatusCode::OK);
    assert_eq!(cache_status(&fill).as_deref(), Some("miss"));
    assert_eq!(header_vary_calls() - before, 1, "a GET is keyed once");
    assert_eq!(store.entry_count(), 1);

    let before = header_vary_calls();
    let head = run(
        &state,
        request(http::Method::HEAD, "/page", "xf_style_id=2"),
    )
    .await;
    assert_eq!(cache_status(&head).as_deref(), Some("hit"));
    assert_eq!(header_vary_calls() - before, 1, "a HEAD is keyed");
    assert_eq!(
        renders.load(Ordering::SeqCst),
        1,
        "the HEAD was served from cache"
    );

    let not_allowed = || {
        state
            .metrics
            .xf_capsule_bypass_not_allowed
            .load(Ordering::Relaxed)
    };
    let not_allowed_before = not_allowed();
    let before = header_vary_calls();
    let post = run(
        &state,
        request(
            http::Method::POST,
            "/act/save",
            "xf_style_id=2; xf_user=1; xf_session=abc",
        ),
    )
    .await;
    assert_eq!(
        not_allowed(),
        not_allowed_before,
        "no capsule miss for a POST"
    );
    assert_eq!(
        header_vary_calls() - before,
        0,
        "a POST computes no key inputs"
    );
    assert_eq!(post.status(), http::StatusCode::OK);
    assert_eq!(renders.load(Ordering::SeqCst), 2);
    for name in [
        "x-litespeed-purge",
        "x-litespeed-cache-control",
        "x-litespeed-tag",
        "x-litespeed-cache",
    ] {
        assert!(!post.headers().contains_key(name), "{name} on the POST");
    }
    let post_body = match post.into_body() {
        Body::Full(b) => b.to_vec(),
        Body::Stream(mut s) => {
            use http_body_util::BodyExt;
            let mut out = Vec::new();
            while let Some(frame) = s.frame().await {
                if let Ok(data) = frame.expect("frame").into_data() {
                    out.extend_from_slice(&data);
                }
            }
            out
        }
        _ => panic!("unexpected POST body variant"),
    };
    assert_eq!(post_body, b"OK");
    assert_eq!(
        store.entry_count(),
        0,
        "the POST's purge dropped the T1 entry"
    );

    let refill = run(&state, request(http::Method::GET, "/page", "xf_style_id=2")).await;
    assert_eq!(cache_status(&refill).as_deref(), Some("miss"));
    assert_eq!(renders.load(Ordering::SeqCst), 3);
    upstream.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errordocument_handler_overrides_are_classified_before_static_serving() {
    const SOURCE: &[u8] = b"<?php echo 'handler-forced secret';";
    for (tag, directive) in [
        ("sethandler", "SetHandler application/x-httpd-php\n"),
        ("addhandler", "AddHandler application/x-httpd-php .html\n"),
        ("addtype", "AddType application/x-httpd-php .html\n"),
        ("forcetype", "ForceType application/x-httpd-php\n"),
        ("quoted", "SetHandler \"application/x-httpd-php\"\n"),
    ] {
        let root = temp_root(tag);
        std::fs::create_dir(root.join("errors")).unwrap();
        std::fs::write(root.join("errors/404.html"), SOURCE).unwrap();
        std::fs::write(root.join("errors/.htaccess"), directive).unwrap();
        std::fs::write(
            root.join(".htaccess"),
            "ErrorDocument 404 /errors/404.html\n",
        )
        .unwrap();
        let state = build_state_htaccess(root);

        assert_builtin_404_without(run(&state, get(CANON_HOST, "/missing", None)).await, SOURCE);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errordocument_declared_cgi_with_missing_processor_never_serves_source() {
    const SOURCE: &[u8] = b"#!/bin/sh\necho 'cgi error document secret'\n";
    let root = temp_root("errordoc-missing-fastcgi");
    std::fs::create_dir(root.join("errors")).unwrap();
    std::fs::write(root.join("errors/404.fcgi"), SOURCE).unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "ErrorDocument 404 /errors/404.fcgi\n",
    )
    .unwrap();
    let initial = build_state_htaccess(root);
    let mut with_route = (*initial.server).clone();
    let vhost = with_route
        .vhosts
        .get_mut(VHOST)
        .unwrap()
        .config
        .as_mut()
        .unwrap();
    Arc::make_mut(vhost).script_handlers.push(ScriptHandler {
        suffix: "fcgi".into(),
        kind: ContextKind::Cgi,
        handler: "missing-fastcgi".into(),
    });
    let state = ServerState::reload(&initial, Arc::new(with_route)).unwrap();

    assert_builtin_404_without(run(&state, get(CANON_HOST, "/missing", None)).await, SOURCE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errordocument_target_directory_deny_preserves_original_error() {
    const PRIVATE: &[u8] = b"private error document";
    let root = temp_root("errordoc-target-deny");
    std::fs::create_dir(root.join("private")).unwrap();
    std::fs::write(root.join("private/404.html"), PRIVATE).unwrap();
    std::fs::write(root.join("private/.htaccess"), "Require all denied\n").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "ErrorDocument 404 /private/404.html\n",
    )
    .unwrap();
    let state = build_state_htaccess(root);

    assert_builtin_404_without(
        run(&state, get(CANON_HOST, "/missing", None)).await,
        PRIVATE,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errordocument_target_directory_rewrite_forbidden_preserves_original_error() {
    const PRIVATE: &[u8] = b"rewrite-protected error document";
    let root = temp_root("errordoc-target-rewrite-forbidden");
    std::fs::create_dir(root.join("private")).unwrap();
    std::fs::write(root.join("private/404.html"), PRIVATE).unwrap();
    std::fs::write(
        root.join("private/.htaccess"),
        "RewriteEngine On\nRewriteRule ^404\\.html$ - [F]\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "ErrorDocument 404 /private/404.html\n",
    )
    .unwrap();
    let state = build_state_htaccess(root);

    assert_builtin_404_without(
        run(&state, get(CANON_HOST, "/missing", None)).await,
        PRIVATE,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errordocument_target_does_not_inherit_source_setenvif() {
    const PRIVATE: &[u8] = b"env-protected error document";
    let root = temp_root("errordoc-target-env-isolation");
    std::fs::create_dir(root.join("private")).unwrap();
    std::fs::write(root.join("private/404.html"), PRIVATE).unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "SetEnvIf Request_URI ^/missing$ SOURCE_PATH=1\n\
         ErrorDocument 404 /private/404.html\n",
    )
    .unwrap();
    std::fs::write(
        root.join("private/.htaccess"),
        "Order deny,allow\nDeny from all\nAllow from env=SOURCE_PATH\n",
    )
    .unwrap();
    let state = build_state_htaccess(root);

    assert_builtin_404_without(
        run(&state, get(CANON_HOST, "/missing", None)).await,
        PRIVATE,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errordocument_public_static_target_keeps_original_status() {
    const CUSTOM: &[u8] = b"custom public 404";
    let root = temp_root("errordoc-static-control");
    std::fs::create_dir(root.join("errors")).unwrap();
    std::fs::write(root.join("errors/404.html"), CUSTOM).unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "ErrorDocument 404 /errors/404.html\n",
    )
    .unwrap();
    let state = build_state_htaccess(root);

    let response = run(&state, get(CANON_HOST, "/missing", None)).await;
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    assert_eq!(body_bytes(response.into_body()).as_ref(), CUSTOM);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_normalized_script_handler_fails_closed() {
    let root = temp_root("unsupported-script-handler");
    const SOURCE: &[u8] = b"<?php echo 'must never be served';";
    std::fs::create_dir(root.join("errors")).unwrap();
    std::fs::write(root.join("app.tmpl"), SOURCE).unwrap();
    std::fs::write(root.join("errors/404.tmpl"), SOURCE).unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "ErrorDocument 404 /errors/404.tmpl\n",
    )
    .unwrap();

    // Parser-built configurations reject this kind. Construct the normalized
    // model directly to exercise the runtime defense independently.
    let initial = build_state_htaccess(root);
    let mut next = (*initial.server).clone();
    let vhost = next.vhosts.get_mut(VHOST).unwrap().config.as_mut().unwrap();
    Arc::make_mut(vhost).script_handlers.push(ScriptHandler {
        suffix: "tmpl".into(),
        kind: ContextKind::Other,
        handler: "misspelled-type".into(),
    });
    let routed = ServerState::reload(&initial, Arc::new(next)).unwrap();

    let response = run(&routed, get(CANON_HOST, "/app.tmpl", None)).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(body_bytes(response.into_body()).as_ref(), SOURCE);

    let mut disabled = (*routed.server).clone();
    disabled.vhosts.get_mut(VHOST).unwrap().enable_script = false;
    let disabled = ServerState::reload(&routed, Arc::new(disabled)).unwrap();
    let response = run(&disabled, get(CANON_HOST, "/app.tmpl", None)).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(body_bytes(response.into_body()).as_ref(), SOURCE);

    assert_builtin_404_without(
        run(&disabled, get(CANON_HOST, "/missing", None)).await,
        SOURCE,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waf_runs_before_static_cache_and_can_block_a_previously_allowed_path() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let sidecar = tokio::spawn(async move {
        for status in ["204 No Content", "403 Forbidden"] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            let header_end = loop {
                let read = stream.read(&mut buf).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buf[..read]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let head = std::str::from_utf8(&request[..header_end]).unwrap();
            let length: usize = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|value| value.trim().parse().unwrap())
                })
                .unwrap();
            while request.len() < header_end + length {
                let read = stream.read(&mut buf).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buf[..read]);
            }
            let payload: serde_json::Value =
                serde_json::from_slice(&request[header_end..header_end + length]).unwrap();
            assert_eq!(payload["path"], "/cached.txt");
            stream
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
        }
    });

    let root = temp_root("waf-before-cache");
    std::fs::write(root.join("cached.txt"), b"allowed once").unwrap();
    let mut state = build_state(root);
    Arc::get_mut(&mut state).unwrap().waf = Some(Arc::new(
        crate::waf::Sidecar::new(
            address,
            None,
            "/inspect".into(),
            std::time::Duration::from_secs(1),
            1024,
            2,
            crate::waf::FailurePolicy::Closed,
        )
        .unwrap(),
    ));
    let allowed = run(&state, get(CANON_HOST, "/cached.txt", None)).await;
    assert_eq!(allowed.status(), 200);
    assert_eq!(body_bytes(allowed.into_body()), "allowed once");
    assert!(
        fast_serve_get(&state, "/cached.txt").await.is_none(),
        "WAF must disable the on-core cache path that bypasses dispatch"
    );
    let blocked = run(&state, get(CANON_HOST, "/cached.txt", None)).await;
    assert_eq!(blocked.status(), 403);
    sidecar.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waf_sidecar_failure_policy_is_closed_unless_explicitly_opened() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable = listener.local_addr().unwrap();
    drop(listener);
    let root = temp_root("waf-failure-policy");
    std::fs::write(root.join("visible.txt"), b"visible").unwrap();

    for (policy, expected) in [
        (crate::waf::FailurePolicy::Closed, 503),
        (crate::waf::FailurePolicy::Open, 200),
    ] {
        let mut state = build_state(root.clone());
        Arc::get_mut(&mut state).unwrap().waf = Some(Arc::new(
            crate::waf::Sidecar::new(
                unavailable,
                None,
                "/inspect".into(),
                std::time::Duration::from_millis(100),
                1024,
                1,
                policy,
            )
            .unwrap(),
        ));
        let response = run(&state, get(CANON_HOST, "/visible.txt", None)).await;
        assert_eq!(response.status(), expected);
    }
}

struct BlockingExtension;

#[async_trait::async_trait]
impl hj_extension::PreHandler for BlockingExtension {
    async fn handle(
        &self,
        ctx: &hj_core::ReqCtx,
        request: hj_extension::RequestView<'_>,
    ) -> Result<hj_extension::PreHandlerDecision, hj_core::HandlerError> {
        assert_eq!(ctx.client_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(request.uri().path(), "/blocked.txt");
        assert_eq!(request.method(), http::Method::GET);
        Ok(hj_extension::PreHandlerDecision::Respond(
            hj_core::text_response(http::StatusCode::IM_A_TEAPOT, "extension blocked"),
        ))
    }
}

struct ExtensionHeader;

#[async_trait::async_trait]
impl hj_core::ResponseTransform for ExtensionHeader {
    async fn transform(&self, _ctx: &hj_core::ReqCtx, response: &mut Response) {
        response
            .headers_mut()
            .insert("x-compile-extension", http::HeaderValue::from_static("ran"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compile_time_pre_handler_short_circuits_before_static_and_forces_the_full_funnel() {
    let root = temp_root("extension-pre-handler");
    std::fs::write(root.join("blocked.txt"), b"must not be served").unwrap();
    let mut state = build_state(root);
    let mut registry = hj_extension::ExtensionRegistry::new();
    registry
        .register_pre_handler("test.block", Arc::new(BlockingExtension))
        .unwrap();
    Arc::get_mut(&mut state).unwrap().extensions = Arc::new(registry);

    let request = get(CANON_HOST, "/blocked.txt", None);
    assert!(
        fast_serve_req(&state, &request).await.is_none(),
        "a pre-handler must prevent the on-core path from bypassing it"
    );
    let response = run(&state, request).await;
    assert_eq!(response.status(), http::StatusCode::IM_A_TEAPOT);
    assert_eq!(body_bytes(response.into_body()), "extension blocked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compile_time_response_transform_runs_on_full_and_on_core_funnels() {
    let root = temp_root("extension-response");
    std::fs::write(root.join("visible.txt"), b"visible").unwrap();
    let mut state = build_state(root);
    let mut registry = hj_extension::ExtensionRegistry::new();
    registry
        .register_response_transform("test.header", Arc::new(ExtensionHeader))
        .unwrap();
    Arc::get_mut(&mut state).unwrap().extensions = Arc::new(registry);

    let full = run(&state, get(CANON_HOST, "/visible.txt", None)).await;
    assert_eq!(full.headers()["x-compile-extension"], "ran");

    let fast = fast_serve_get(&state, "/visible.txt")
        .await
        .expect("a response-only extension leaves the on-core path available");
    assert_eq!(fast.headers()["x-compile-extension"], "ran");
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
    // `/assets/x` maps to `<location>/x` (OLS translate(), #673).
    let target_dir = context_root.join("files");
    std::fs::create_dir_all(&target_dir).unwrap();
    std::fs::write(target_dir.join("secret.txt"), b"must not be served").unwrap();
    let context = Context {
        cache_policy: None,
        bandwidth_limit: 0,
        max_body_override: None,
        timeout_override: None,
        sub_filter: None,
        kind: ContextKind::Static,
        uri: "/assets".into(),
        location: Some(context_root.join("files")),
        handler: None,
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: None,
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

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_context_alternate_root_never_serves_or_replays_script_source() {
    use std::os::unix::fs::symlink;

    const SOURCE: &[u8] = b"<?php echo 'alternate-root secret';";
    let doc_root = temp_root("alternate-script-docroot");
    let context_root = temp_root("alternate-script-context");
    std::fs::write(
        doc_root.join(".htaccess"),
        "DirectoryIndex index.php\n\
         <Files \"forced.html\">\n\
         SetHandler application/x-httpd-php\n\
         </Files>\n",
    )
    .unwrap();
    std::fs::write(context_root.join("secret.php"), SOURCE).unwrap();
    std::fs::write(context_root.join("public.txt"), b"public").unwrap();
    std::fs::write(context_root.join("payload.txt"), SOURCE).unwrap();
    symlink("payload.txt", context_root.join("linked.php")).unwrap();
    symlink("payload.txt", context_root.join("forced.html")).unwrap();
    std::fs::create_dir_all(context_root.join("dir")).unwrap();
    std::fs::write(context_root.join("dir/payload.txt"), SOURCE).unwrap();
    symlink("payload.txt", context_root.join("dir/index.php")).unwrap();
    let context = Context {
        cache_policy: None,
        bandwidth_limit: 0,
        max_body_override: None,
        timeout_override: None,
        sub_filter: None,
        kind: ContextKind::Static,
        uri: "/assets".into(),
        location: Some(context_root),
        handler: None,
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: None,
        charset: None,
    };
    let mut cache_cfg = hj_pagecache::StoreConfig::default();
    cache_cfg.standard_cc_vhosts.push(VHOST.into());
    cache_cfg.max_static_obj_bytes = 0;
    let store = Arc::new(hj_pagecache::PageStore::new(cache_cfg));
    let state = build_state_full(
        doc_root.clone(),
        vec![context],
        // A nonmatching rule forces canonical target collection and covers the
        // exact policy shape that previously lost the declared symlink name.
        vec![format!("{}/*", doc_root.join("unrelated-deny").display())],
        Some(store.clone()),
        None,
    );

    let public = run(&state, get(CANON_HOST, "/assets/public.txt", None)).await;
    assert_eq!(public.status(), http::StatusCode::OK);
    assert_eq!(body_bytes(public.into_body()), "public");

    for path in [
        "/assets/secret.php",
        "/assets/linked.php",
        "/assets/forced.html",
        "/assets/dir/",
    ] {
        let entries_before = store.entry_count();
        seed_public_entry(&state, &store, path, SOURCE).await;
        assert_eq!(
            store.entry_count(),
            entries_before + 1,
            "precondition: seeded cache entry missing for {path}"
        );
        assert!(
            fast_serve_get(&state, path).await.is_none(),
            "on-core lookup replayed alternate-root script source for {path}"
        );
        let response = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(
            response.status(),
            http::StatusCode::SERVICE_UNAVAILABLE,
            "static fallback was not denied for {path}"
        );
        assert_ne!(
            response
                .headers()
                .get("x-litespeed-cache")
                .and_then(|value| value.to_str().ok()),
            Some("hit"),
            "stale script source was replayed for {path}"
        );
        assert_ne!(body_bytes(response.into_body()).as_ref(), SOURCE, "{path}");
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn symlink_alias_to_script_never_serves_any_static_response_shape() {
    use std::os::unix::fs::symlink;

    const SOURCE: &[u8] = b"<?php echo 'symlink secret';";
    let root = temp_root("symlink-script-target");
    std::fs::write(root.join("real.php"), SOURCE).unwrap();
    symlink("real.php", root.join("alias.txt")).unwrap();
    let state = build_state_with(root, Vec::new(), Vec::new());

    assert!(
        fast_serve_get(&state, "/alias.txt").await.is_none(),
        "on-core static path served a symlinked script target"
    );

    let ordinary = run(&state, get(CANON_HOST, "/alias.txt", None)).await;
    assert_eq!(ordinary.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(body_bytes(ordinary.into_body()).as_ref(), SOURCE);

    let conditional = run(&state, get(CANON_HOST, "/alias.txt", Some("*"))).await;
    assert_eq!(
        conditional.status(),
        http::StatusCode::SERVICE_UNAVAILABLE,
        "the 304 branch bypassed script-target classification"
    );

    let ranged = http::Request::builder()
        .method("GET")
        .uri("/alias.txt")
        .header(header::HOST, CANON_HOST)
        .header(header::RANGE, "bytes=0-3")
        .body(hj_core::empty_incoming())
        .unwrap();
    let ranged = run(&state, ranged).await;
    assert_eq!(
        ranged.status(),
        http::StatusCode::SERVICE_UNAVAILABLE,
        "the 206 branch bypassed script-target classification"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn symlink_resolve_memo_refreshes_canonical_policy_target() {
    use std::os::unix::fs::symlink;

    const SOURCE: &[u8] = b"<?php echo 'same-inode secret';";
    let root = temp_root("symlink-script-memo");
    let public = root.join("public.txt");
    let script = root.join("secret.php");
    let alias = root.join("alias.txt");
    std::fs::write(&public, SOURCE).unwrap();
    std::fs::hard_link(&public, &script).unwrap();
    symlink("public.txt", &alias).unwrap();
    let state = build_state_with(root, Vec::new(), Vec::new());

    let first = run(&state, get(CANON_HOST, "/alias.txt", None)).await;
    assert_eq!(first.status(), http::StatusCode::OK);
    assert_eq!(body_bytes(first.into_body()).as_ref(), SOURCE);

    std::fs::remove_file(&alias).unwrap();
    symlink("secret.php", &alias).unwrap();
    let second = run(&state, get(CANON_HOST, "/alias.txt", None)).await;
    assert_eq!(
        second.status(),
        http::StatusCode::SERVICE_UNAVAILABLE,
        "same-inode memo replay retained the old safe-looking target name"
    );
    assert_ne!(body_bytes(second.into_body()).as_ref(), SOURCE);
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
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: Some(true),
        charset: Some("ISO-8859-1".into()),
        cache_policy: None,
        bandwidth_limit: 0,
        max_body_override: None,
        timeout_override: None,
        sub_filter: None,
    };
    let state = build_state_with(doc_root, vec![context], Vec::new());

    let resp = run(&state, get(CANON_HOST, "/assets/readme.txt", None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()[header::CONTENT_TYPE],
        "text/plain; charset=ISO-8859-1"
    );
}

fn static_ctx(
    uri: &str,
    location: Option<PathBuf>,
    add_default_charset: Option<bool>,
    charset: Option<&str>,
) -> Context {
    Context {
        kind: ContextKind::Static,
        uri: uri.into(),
        location,
        handler: None,
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset,
        charset: charset.map(str::to_owned),
        cache_policy: None,
        bandwidth_limit: 0,
        max_body_override: None,
        timeout_override: None,
        sub_filter: None,
    }
}

/// #828: a plain nested static context inherits its parent's addDefaultCharset
/// on the dispatch, fast_serve and ErrorDocument paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_static_context_inherits_parent_default_charset() {
    let doc_root = temp_root("context-charset-nested");
    std::fs::create_dir_all(doc_root.join("assets/img/errors")).unwrap();
    std::fs::write(doc_root.join("assets/img/readme.txt"), b"hello").unwrap();
    std::fs::write(doc_root.join("assets/img/errors/404.txt"), b"nope").unwrap();
    std::fs::write(
        doc_root.join(".htaccess"),
        "ErrorDocument 404 /assets/img/errors/404.txt\n",
    )
    .unwrap();
    let contexts = vec![
        static_ctx("/assets/", None, Some(true), Some("ISO-8859-1")),
        static_ctx("/assets/img/", None, None, None),
        static_ctx("/assets/img/errors/", None, Some(false), None),
    ];
    let state = build_state_inner(doc_root, contexts, Vec::new(), true, None, None, |_| {});

    let resp = run(&state, get(CANON_HOST, "/assets/img/readme.txt", None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()[header::CONTENT_TYPE],
        "text/plain; charset=ISO-8859-1"
    );
    let resp = fast_serve_get(&state, "/assets/img/readme.txt")
        .await
        .expect("plain static serves on-core");
    assert_eq!(
        resp.headers()[header::CONTENT_TYPE],
        "text/plain; charset=ISO-8859-1"
    );
    // An explicit `off` in the innermost context beats the inherited charset,
    // including for the ErrorDocument static subrequest.
    let resp = run(&state, get(CANON_HOST, "/assets/img/missing.txt", None)).await;
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/plain");
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"nope");
}

/// #828: the ErrorDocument subrequest maps its own path's inherited charset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_document_static_subrequest_inherits_context_charset() {
    let doc_root = temp_root("context-charset-errordoc");
    std::fs::create_dir_all(doc_root.join("assets/errors")).unwrap();
    std::fs::write(doc_root.join("assets/errors/404.txt"), b"nope").unwrap();
    std::fs::write(
        doc_root.join(".htaccess"),
        "ErrorDocument 404 /assets/errors/404.txt\n",
    )
    .unwrap();
    let contexts = vec![
        static_ctx("/assets/", None, Some(true), Some("ISO-8859-1")),
        static_ctx("/assets/errors/", None, None, None),
    ];
    let state = build_state_inner(doc_root, contexts, Vec::new(), true, None, None, |_| {});
    let resp = run(&state, get(CANON_HOST, "/missing.txt", None)).await;
    assert_eq!(resp.status(), 404);
    assert_eq!(
        resp.headers()[header::CONTENT_TYPE],
        "text/plain; charset=ISO-8859-1"
    );
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"nope");
}

/// #829: a static context located AT the docroot still strips its URI (OLS
/// translate), on dispatch and fast_serve alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn docroot_located_static_context_strips_its_uri() {
    let doc_root = temp_root("context-docroot-strip");
    std::fs::create_dir_all(doc_root.join("assets")).unwrap();
    std::fs::write(doc_root.join("x.css"), b"stripped").unwrap();
    std::fs::write(doc_root.join("assets/x.css"), b"unstripped").unwrap();
    let contexts = vec![static_ctx("/assets/", Some(doc_root.clone()), None, None)];
    let state = build_state_with(doc_root, contexts, Vec::new());

    let resp = run(&state, get(CANON_HOST, "/assets/x.css", None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"stripped");
    let resp = fast_serve_get(&state, "/assets/x.css")
        .await
        .expect("plain static serves on-core");
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"stripped");
}

/// #830: a slashless request for a trailing-slash context URI is OLS's
/// `redirectDir` 301 (query kept, CDN-uncacheable) for static AND proxy contexts;
/// fast_serve bridges it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slashless_trailing_slash_context_uri_redirects() {
    let doc_root = temp_root("context-slash-redirect");
    std::fs::create_dir_all(doc_root.join("docs-root")).unwrap();
    std::fs::write(doc_root.join("docs-root/index.html"), b"docs").unwrap();
    let mut proxy = static_ctx("/app/", None, None, None);
    proxy.kind = ContextKind::Proxy;
    proxy.handler = Some("test-upstream".into());
    let contexts = vec![
        static_ctx("/docs/", Some(doc_root.join("docs-root")), None, None),
        proxy,
    ];
    // Never dialed: the redirect is answered before proxy routing.
    let unused: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let state = build_state_inner(
        doc_root,
        contexts,
        Vec::new(),
        false,
        None,
        None,
        |server| register_upstream(server, unused),
    );

    for (path, location) in [
        ("/docs?x=1&y", "/docs/?x=1&y"),
        ("/docs", "/docs/"),
        ("/app", "/app/"),
    ] {
        let resp = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(resp.status(), 301, "{path}");
        assert_eq!(resp.headers()[header::LOCATION], location, "{path}");
        assert_eq!(
            resp.headers()[header::CACHE_CONTROL],
            "private, no-store",
            "{path}: redirects stay out of the CDN"
        );
        assert!(
            fast_serve_get(&state, path).await.is_none(),
            "{path}: fast_serve bridges the redirect"
        );
    }
    let resp = run(&state, get(CANON_HOST, "/docs/", None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"docs");
    let resp = run(&state, get(CANON_HOST, "/docsx", None)).await;
    assert_eq!(resp.status(), 404, "a sibling name is not the context");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_bandwidth_limit_stamps_per_conn_rate_extension() {
    let doc_root = temp_root("bw-context");
    std::fs::create_dir_all(doc_root.join("dl")).unwrap();
    std::fs::write(doc_root.join("dl/big.txt"), vec![b'x'; 4096]).unwrap();
    std::fs::write(doc_root.join("index.html"), b"<html>ok</html>").unwrap();
    let throttled = Context {
        kind: ContextKind::Static,
        uri: "/dl".into(),
        location: None,
        handler: None,
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: None,
        charset: None,
        cache_policy: None,
        bandwidth_limit: 250_000,
        max_body_override: None,
        timeout_override: None,
        sub_filter: None,
    };
    let state = build_state_with(doc_root, vec![throttled], Vec::new());

    let resp = run(&state, get(CANON_HOST, "/dl/big.txt", None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.extensions()
            .get::<super::PerConnBandwidth>()
            .map(|b| b.0),
        Some(250_000),
        "the matched context's bandwidthLimit must reach the transport extension"
    );

    let unthrottled = run(&state, get(CANON_HOST, "/index.html", None)).await;
    assert_eq!(unthrottled.status(), 200);
    assert!(
        unthrottled
            .extensions()
            .get::<super::PerConnBandwidth>()
            .is_none(),
        "paths outside the throttled context must not carry a rate stamp"
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
        false,
        false,
        Proto::Http1,
        None,
        &req,
    )
    .await
}

/// A request with neither Host nor an absolute-form authority is routed by the full
/// pipeline (which falls back to the TLS SNI); the on-core path must not resolve it to
/// the default vhost on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_bridges_a_request_without_host() {
    let doc_root = temp_root("fastserve-no-host");
    std::fs::write(doc_root.join("robots.txt"), b"default vhost").unwrap();
    let state = build_state_inner(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        false,
        None,
        None,
        |_| {},
    );
    let mut req = get(CANON_HOST, "/robots.txt", None);
    assert!(
        fast_serve(
            &state,
            LISTENER,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::from(([127, 0, 0, 1], 443)),
            40000,
            true,
            false,
            false,
            Proto::Http1,
            None,
            &req,
        )
        .await
        .is_some(),
        "control: with a Host the on-core path serves"
    );
    req.headers_mut().remove(header::HOST);
    assert!(
        fast_serve(
            &state,
            LISTENER,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::from(([127, 0, 0, 1], 443)),
            40000,
            true,
            false,
            false,
            Proto::Http1,
            None,
            &req,
        )
        .await
        .is_none(),
        "a Host-less request must be bridged to the SNI-aware pipeline"
    );
    let reasons: std::collections::HashMap<_, _> = state.metrics.fast_bridge.snapshot().collect();
    assert_eq!(
        reasons["no_host"], 1,
        "the bridge is counted under its gate"
    );
    assert_eq!(
        reasons.values().sum::<u64>(),
        1,
        "the served request counts no bridge"
    );
    std::fs::remove_dir_all(doc_root).unwrap();
}

async fn fast_serve_cookied(state: &Arc<ServerState>, path: &str) -> Option<Response> {
    let mut req = get(CANON_HOST, path, None);
    req.headers_mut().insert(
        header::COOKIE,
        http::HeaderValue::from_static("xf_style_id=50"),
    );
    fast_serve(
        state,
        LISTENER,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from(([127, 0, 0, 1], 80)),
        40000,
        false,
        false,
        false,
        Proto::Http1,
        None,
        &req,
    )
    .await
}

/// A cookied request can only be served on-core from a file at its unrewritten path; a
/// front-controller URL names none, so it bridges before the prefix runs (the rewrite
/// engine is never consulted) while a cookied static file still serves on-core.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookied_request_for_a_missing_path_bridges_before_the_prefix() {
    let doc_root = temp_root("fastserve-cookied");
    std::fs::write(doc_root.join("real.txt"), b"real").unwrap();
    std::fs::write(doc_root.join("index.php"), b"<?php").unwrap();
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ index.php [L]\n",
    )
    .unwrap();
    let state = build_state_inner(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );
    let rewrites = |state: &ServerState| {
        let m = &state.metrics;
        m.rewrite_outcome_hits
            .load(std::sync::atomic::Ordering::Relaxed)
            + m.rewrite_outcome_misses
                .load(std::sync::atomic::Ordering::Relaxed)
            + m.rewrite_outcome_uncacheable
                .load(std::sync::atomic::Ordering::Relaxed)
    };
    assert!(
        fast_serve_cookied(&state, "/real.txt").await.is_some(),
        "cookied static stays on-core"
    );
    let before = rewrites(&state);
    assert!(
        fast_serve_cookied(&state, "/threads/a-thread.123/")
            .await
            .is_none()
    );
    assert!(
        fast_serve_cookied(&state, "/real.txt/extra")
            .await
            .is_none(),
        "file as a directory"
    );
    assert_eq!(
        rewrites(&state),
        before,
        "the prefix (rewrite) never ran for them"
    );
    // An extension-bearing path is never pre-judged: it takes the normal prefix.
    assert!(fast_serve_cookied(&state, "/missing.css").await.is_none());
    assert!(
        rewrites(&state) > before,
        "the extension-bearing miss ran the prefix"
    );
    let reasons: std::collections::HashMap<_, _> = state.metrics.fast_bridge.snapshot().collect();
    assert_eq!(reasons["cookied_no_target"], 2);
    // Cookieless, the same URL still runs the prefix (it may be a page-cache hit).
    assert!(
        fast_serve_get(&state, "/threads/a-thread.123/")
            .await
            .is_none()
    );
    let reasons: std::collections::HashMap<_, _> = state.metrics.fast_bridge.snapshot().collect();
    assert_eq!(reasons["cookied_no_target"], 2);
    // `/missing.css` (cookied) and the cookieless route both left via the rewrite.
    assert_eq!(reasons["rewritten"], 2);
    std::fs::remove_dir_all(doc_root).unwrap();
}

/// (--fast-early-bridge) A cookieless front-controller URL the page cache holds nothing for
/// bridges before the prefix; the same URL with an entry resident, an extension-bearing path,
/// and a real file all keep the on-core path. Off is exactly today's behavior.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookieless_route_the_cache_cannot_hold_bridges_before_the_prefix() {
    let doc_root = temp_root("fastserve-early");
    std::fs::write(doc_root.join("real.txt"), b"real").unwrap();
    std::fs::write(doc_root.join("index.php"), b"<?php").unwrap();
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ index.php [L]\n",
    )
    .unwrap();
    let mut config = hj_pagecache::StoreConfig::default();
    config.path_presence = true;
    config.standard_cc_vhosts = vec![VHOST.to_string()];
    let store = Arc::new(hj_pagecache::PageStore::new(config));
    let state = build_state_inner(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |_| {},
    );
    let rewrites = |state: &ServerState| {
        let m = &state.metrics;
        m.rewrite_outcome_hits
            .load(std::sync::atomic::Ordering::Relaxed)
            + m.rewrite_outcome_misses
                .load(std::sync::atomic::Ordering::Relaxed)
            + m.rewrite_outcome_uncacheable
                .load(std::sync::atomic::Ordering::Relaxed)
    };
    let reasons = |state: &ServerState| -> std::collections::HashMap<&'static str, u64> {
        state.metrics.fast_bridge.snapshot().collect()
    };

    // Off: the route runs the prefix and bridges as a rewrite.
    let before = rewrites(&state);
    assert!(fast_serve_get(&state, "/threads/a.1/").await.is_none());
    assert!(rewrites(&state) > before, "off runs the prefix");
    assert_eq!(reasons(&state)["early_cache_absent"], 0);

    // Shadow: same path, the decision is only counted.
    state
        .early_bridge
        .set_mode(crate::pipeline::early_bridge::Mode::Shadow);
    let before = rewrites(&state);
    assert!(fast_serve_get(&state, "/threads/a.2/").await.is_none());
    assert!(rewrites(&state) > before, "shadow still runs the prefix");
    assert_eq!(state.early_bridge.predicted_snapshot()[1].1, 1);
    assert_eq!(reasons(&state)["early_cache_absent"], 0);

    // On: nothing on-core can serve it, so it bridges without running the prefix.
    state
        .early_bridge
        .set_mode(crate::pipeline::early_bridge::Mode::On);
    let before = rewrites(&state);
    assert!(fast_serve_get(&state, "/threads/a.3/").await.is_none());
    assert_eq!(rewrites(&state), before, "the prefix never ran");
    assert_eq!(reasons(&state)["early_cache_absent"], 1);

    // An entry that may be resident for the path keeps the prefix (it may be an on-core hit).
    let key = hj_pagecache::PageCacheKey::public(
        crate::lscache::vhost_id_hash(VHOST),
        false,
        CANON_HOST,
        "/threads/a.4/",
        "",
    );
    assert!(store.store(
        key,
        hj_pagecache::CachedResponse {
            status: 200,
            identity: "unrelated".into(),
            headers: Vec::new(),
            body: hj_pagecache::PageBody::InMem(bytes::Bytes::from_static(b"x")),
            variants: Vec::new(),
            variants_filled: true,
            dict_gen: 0,
            tags: Vec::new(),
            vary_cookie_name: String::new(),
            vary_value: String::new(),
            scope: hj_pagecache::PageScope::Public,
            stored_at: std::time::Instant::now(),
            ttl: std::time::Duration::from_secs(60),
            swr: std::time::Duration::ZERO,
            sie: std::time::Duration::ZERO,
        }
    ));
    let before = rewrites(&state);
    assert!(fast_serve_get(&state, "/threads/a.4/").await.is_none());
    assert!(
        rewrites(&state) > before,
        "a possibly cached path runs the prefix"
    );
    assert_eq!(reasons(&state)["early_cache_absent"], 1);

    // Paths the static branch could serve are never pre-judged.
    assert!(
        fast_serve_get(&state, "/real.txt").await.is_some(),
        "file serves on-core"
    );
    let before = rewrites(&state);
    assert!(fast_serve_get(&state, "/missing.css").await.is_none());
    assert!(
        rewrites(&state) > before,
        "an extension-bearing path runs the prefix"
    );
    assert_eq!(reasons(&state)["early_cache_absent"], 1);
    std::fs::remove_dir_all(doc_root).unwrap();
}

/// A cookied request for a script path can never serve on-core (no page-cache branch for
/// cookies, and scripts never serve static), so it bridges before the prefix runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookied_script_request_bridges_before_the_prefix() {
    let doc_root = temp_root("fastserve-cookied-script");
    std::fs::write(doc_root.join("index.php"), b"<?php").unwrap();
    std::fs::write(doc_root.join("real.txt"), b"real").unwrap();
    std::fs::write(doc_root.join(".htaccess"), "RewriteEngine On\n").unwrap();
    let state = build_state_inner(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );
    let rewrites = |state: &ServerState| {
        let m = &state.metrics;
        m.rewrite_outcome_hits
            .load(std::sync::atomic::Ordering::Relaxed)
            + m.rewrite_outcome_misses
                .load(std::sync::atomic::Ordering::Relaxed)
            + m.rewrite_outcome_uncacheable
                .load(std::sync::atomic::Ordering::Relaxed)
    };
    let before = rewrites(&state);
    assert!(fast_serve_cookied(&state, "/index.php").await.is_none());
    assert_eq!(rewrites(&state), before, "the prefix (rewrite) never ran");
    let reasons: std::collections::HashMap<_, _> = state.metrics.fast_bridge.snapshot().collect();
    assert_eq!(reasons["cookied_script"], 1);
    assert!(
        fast_serve_cookied(&state, "/real.txt").await.is_some(),
        "a cookied non-script file still serves on-core"
    );
    std::fs::remove_dir_all(doc_root).unwrap();
}

/// (#986) Without the page-cache branch only the static branch can serve, so its own
/// bridges are decided before the target policy is paid for: a directory index whose
/// script is symlinked into an auth-protected tree bridges as `script` (it used to
/// open and judge the target first, as `auth`), and dispatch() still challenges.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_branch_bridges_precede_the_target_policy_without_a_page_cache() {
    let root = temp_root("fastserve-bridge-order");
    std::fs::create_dir_all(root.join("private")).unwrap();
    std::fs::create_dir_all(root.join("d")).unwrap();
    std::fs::write(
        root.join("users"),
        "Admin:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
    )
    .unwrap();
    std::fs::write(
        root.join("private/.htaccess"),
        "AuthType Basic\nAuthUserFile users\nRequire user Admin\n",
    )
    .unwrap();
    std::fs::write(root.join("private/real.php"), b"<?php echo 'private';").unwrap();
    std::os::unix::fs::symlink(root.join("private/real.php"), root.join("d/index.php")).unwrap();
    std::fs::write(root.join(".htaccess"), "DirectoryIndex index.php\n").unwrap();
    let state = build_state_htaccess(root.clone());
    assert!(fast_serve_get(&state, "/d/").await.is_none());
    let reasons: std::collections::HashMap<_, _> = state.metrics.fast_bridge.snapshot().collect();
    assert_eq!(reasons["script"], 1);
    assert_eq!(reasons["auth"], 0);
    assert_eq!(
        run(&state, get(CANON_HOST, "/d/", None)).await.status(),
        401
    );
    std::fs::remove_dir_all(root).ok();
}

/// A front-controller rewrite (XenForo's `^.*$ index.php`) leaves the static branch: the
/// request bridges under `rewritten`, which is why cookied forum pages never memoize.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_counts_a_rewritten_path_as_its_bridge_reason() {
    let doc_root = temp_root("fastserve-rewritten");
    std::fs::write(doc_root.join("real.txt"), b"real").unwrap();
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^alias\\.txt$ real.txt [L]\n",
    )
    .unwrap();
    let state = build_state_inner(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );
    assert!(
        fast_serve_get(&state, "/real.txt").await.is_some(),
        "control: on-core"
    );
    assert!(fast_serve_get(&state, "/alias.txt").await.is_none());
    let reasons: std::collections::HashMap<_, _> = state.metrics.fast_bridge.snapshot().collect();
    assert_eq!(reasons["rewritten"], 1);
    assert_eq!(reasons.values().sum::<u64>(), 1);
    std::fs::remove_dir_all(doc_root).unwrap();
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
    let identity = seeded_identity("/admin/index.html");
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
        forwarding_trusted: false,
        env: Vec::new(),
        local_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
        peer_port: 40000,
        peer_unix: false,
        tls: None,
        redirect_guard: None,
        request_time: std::time::SystemTime::UNIX_EPOCH,
        request_id: Default::default(),
    };
    let cc = crate::lscache::CacheCtx {
        enabled: true,
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
        origin: None,
        ua_class: None,
        header_vary: None,
        env_vary: false,
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
        false,
        false,
        Proto::Http1,
        None,
        req,
    )
    .await
}

/// The identity a plaintext `CANON_HOST` request carries. The fixture vhost is named
/// `VHOST`, so `CANON_HOST` is an exact alias and its identity carries the alias (#938).
fn seeded_identity(path: &str) -> String {
    super::cache_identity_for(
        false,
        VHOST,
        crate::lscache::cache_alias_host(VHOST, CANON_HOST, false),
        path,
    )
}

async fn seed_public_entry(
    state: &Arc<ServerState>,
    store: &Arc<hj_pagecache::PageStore>,
    path: &str,
    body: &'static [u8],
) {
    seed_public_entry_for_headers(state, store, path, body, &http::HeaderMap::new()).await;
}

async fn seed_public_entry_for_headers(
    state: &Arc<ServerState>,
    store: &Arc<hj_pagecache::PageStore>,
    path: &str,
    body: &'static [u8],
    headers: &http::HeaderMap,
) {
    let method = http::Method::GET;
    let identity = seeded_identity(path);
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
        forwarding_trusted: false,
        env: Vec::new(),
        local_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
        peer_port: 40000,
        peer_unix: false,
        tls: None,
        redirect_guard: None,
        request_time: std::time::SystemTime::UNIX_EPOCH,
        request_id: Default::default(),
    };
    let ran = state.rewrite_cache.load_chain_with_dirs(
        &rctx.vhost.doc_root,
        path,
        rctx.vhost.access_file_name_or_default(),
    );
    let header_vary = super::rewrite_glue::page_cache_header_vary(state, &rctx, &ran, headers);
    let ua_class = super::rewrite_glue::page_cache_ua_class(state, &rctx, &ran, headers);
    let cc = crate::lscache::CacheCtx {
        enabled: true,
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
        origin: None,
        ua_class: ua_class.as_deref(),
        header_vary: header_vary.as_deref(),
        env_vary: false,
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
    seed_public_entry_for_headers(
        &state,
        &store,
        "/pages/index.html",
        b"<h1>page</h1>\n",
        get_with_ua("/pages/index.html", "Mozilla/5.0").headers(),
    )
    .await;

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
    // #671: the joined view must expose the second line's crumbs to the vary key.
    assert_eq!(
        hj_pagecache::compute_vary_value(Some(&joined), &["xf_style_id"]),
        "xf_style_id=v:9"
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn purge_endpoint_rejects_non_post_on_both_entry_paths() {
    use crate::peer_purge::{PURGE_PATH, READY_PATH};
    let doc_root = temp_root("purge-method");
    let state = build_state_full(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        None,
        Some(crate::peer_purge::PurgeForwarder::new()),
    );
    let on_core = fast_serve_get(&state, PURGE_PATH)
        .await
        .expect("reserved path intercepted on-core");
    assert_eq!(on_core.status(), 405);
    assert_eq!(on_core.headers().get(header::ALLOW).unwrap(), "POST");
    let full = run(&state, get(CANON_HOST, PURGE_PATH, None)).await;
    assert_eq!(full.status(), 405);

    let post = |path: &str| {
        http::Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, CANON_HOST)
            .header("x-litespeed-purge", "*")
            .body(hj_core::empty_incoming())
            .unwrap()
    };
    assert_eq!(run(&state, post(PURGE_PATH)).await.status(), 204);
    let ready = run(&state, post(READY_PATH)).await;
    assert_eq!(ready.status(), 405);
    assert_eq!(ready.headers().get(header::ALLOW).unwrap(), "GET, HEAD");
    let _ = std::fs::remove_dir_all(doc_root);
}

/// Poll the unified access log (written asynchronously by its writer task)
/// until a line containing `needle` appears; returns that line.
pub(crate) async fn unified_access_line(state: &Arc<ServerState>, needle: &str) -> String {
    let path =
        crate::state::redirect_log_path(&state.server.server_root.join("logs/httpjet_access.log"));
    for _ in 0..200 {
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Some(line) = text.lines().find(|l| l.contains(needle))
        {
            return line.to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!(
        "no access-log line containing {needle:?} in {}",
        path.display()
    );
}

// #914: a non-ASCII User-Agent / Referer is logged escaped, not as "-".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_ascii_request_headers_are_logged_escaped() {
    let doc_root = temp_root("nonascii-log");
    std::fs::write(doc_root.join("n914.txt"), b"x").unwrap();
    let state = build_state(doc_root.clone());
    let mut req = get(CANON_HOST, "/n914.txt", None);
    req.headers_mut().insert(
        header::USER_AGENT,
        http::HeaderValue::from_bytes(b"caf\xc3\xa9/\xff").unwrap(),
    );
    req.headers_mut().insert(
        header::REFERER,
        http::HeaderValue::from_bytes(b"https://r.test/\xe9").unwrap(),
    );
    assert_eq!(run(&state, req).await.status(), 200);
    let line = unified_access_line(&state, "/n914.txt").await;
    if line.starts_with('{') {
        assert!(line.contains(r#""user_agent":"café/\\xff""#), "{line}");
        assert!(
            line.contains(r#""referer":"https://r.test/\\xe9""#),
            "{line}"
        );
    } else {
        assert!(
            line.contains(r#" "https://r.test/\xe9" "caf\xc3\xa9/\xff""#),
            "{line}"
        );
    }
    let _ = std::fs::remove_dir_all(doc_root);
}

// #916: a request no vhost routes (404), and the loopback purge/ready
// endpoints on both entry paths, are counted and access-logged on the unified
// log; the responses themselves are unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrouted_and_reserved_endpoint_requests_are_counted_and_logged() {
    use crate::peer_purge::READY_PATH;
    use std::sync::atomic::Ordering;
    let doc_root = temp_root("unrouted-log");
    let state = build_state_full(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        None,
        Some(crate::peer_purge::PurgeForwarder::new()),
    );
    let before = state.metrics.requests_total.load(Ordering::Relaxed);
    let unrouted = handle(
        state.clone(),
        "no-such-listener",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from(([127, 0, 0, 1], 80)),
        40000,
        false,
        false,
        false,
        None,
        Proto::Http1,
        None,
        get("stray.test", "/unrouted-916?q=1", None),
    )
    .await;
    assert_eq!(unrouted.status(), 404);
    let line = unified_access_line(&state, "/unrouted-916?q=1").await;
    assert!(line.contains("404") && line.contains("reqid="), "{line}");

    let ready = run(&state, get(CANON_HOST, &format!("{READY_PATH}?full"), None)).await;
    assert_eq!(ready.status(), 200);
    unified_access_line(&state, &format!("{READY_PATH}?full")).await;
    let on_core = fast_serve_get(&state, &format!("{READY_PATH}?core"))
        .await
        .expect("reserved path intercepted on-core");
    assert_eq!(on_core.status(), 200);
    unified_access_line(&state, &format!("{READY_PATH}?core")).await;
    assert_eq!(
        state.metrics.requests_total.load(Ordering::Relaxed) - before,
        3,
        "unrouted 404 + both ready probes are counted"
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

    /// Full-pipeline dispatch for auth tests: auth-protected trees decline the
    /// on-core path by design, so the 401/200 verdict comes from dispatch().
    async fn dispatch_get(
        state: &Arc<ServerState>,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Response {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let r = req(path, headers);
        let req_host = CANON_HOST.to_string();
        let resolved = state.router.resolve(LISTENER, Some(CANON_HOST)).unwrap();
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut ctx = hj_core::ReqCtx {
            server: state.server.clone(),
            vhost_name: resolved.name.clone(),
            vhost: resolved.config,
            peer_ip: loopback,
            client_ip: loopback,
            is_tls: false,
            protocol: Proto::Http1,
            trusted_proxy: false,
            forwarding_trusted: false,
            env: Vec::new(),
            local_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
            peer_port: 40000,
            peer_unix: false,
            redirect_guard: None,
            request_time: std::time::SystemTime::UNIX_EPOCH,
            request_id: Default::default(),
            tls: None,
        };
        crate::pipeline::dispatch(state, false, req_host, &mut ctx, r).await
    }

    // (Tier 1.3) Basic auth end-to-end through dispatch: challenge, wrong-password
    // rejection, and the served file on valid credentials.
    #[tokio::test]
    async fn basic_auth_challenges_then_accepts_valid_credentials() {
        // htpasswd -s user:password
        let ht = "AuthType Basic\n\
                 AuthName \"Restricted\"\n\
                 AuthUserFile htpasswd\n\
                 Require valid-user\n";
        let (root, state) = setup("auth_basic", ht);
        std::fs::write(
            root.join("htpasswd"),
            "user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
        )
        .unwrap();

        // No credentials → 401 with the Basic challenge.
        let resp = dispatch_get(&state, "/x.secret", &[]).await;
        assert_eq!(resp.status(), 401);
        assert_eq!(
            hdr(&resp, "www-authenticate"),
            Some("Basic realm=\"Restricted\"")
        );

        // Wrong password → still 401.
        let bad = dispatch_get(
            &state,
            "/x.secret",
            &[("authorization", "Basic dXNlcjpwYXNz")],
        )
        .await;
        assert_eq!(bad.status(), 401);

        // Correct credentials (user:password) → the file is served.
        let ok = dispatch_get(
            &state,
            "/x.secret",
            &[("authorization", "Basic dXNlcjpwYXNzd29yZA==")],
        )
        .await;
        assert_eq!(ok.status(), 200);
        assert_eq!(&body_bytes(ok.into_body())[..], b"hidden\n");
        let _ = std::fs::remove_dir_all(root);
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
        // fast_serve's caller stamps Date on the original; a replay carries its own.
        let mut first_headers = first.headers().clone();
        first_headers.remove(http::header::DATE);
        let mut second_headers = second.headers().clone();
        assert_eq!(
            second_headers.remove(http::header::DATE),
            Some(hj_core::http_date_now()),
            "a replay carries a fresh Date"
        );
        assert_eq!(
            second_headers, first_headers,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_range_request_serves_framed_multipart_byteranges() {
    // (Tier 2) The full funnel: a comma-separated Range over a static file leaves
    // the pipeline as a framed multipart/byteranges 206 with an exact Content-Length
    // (the transports then carry the buffered body untouched).
    let doc_root = temp_root("multipart-e2e");
    let data: Vec<u8> = (0u32..1000).map(|i| (i % 251) as u8).collect();
    std::fs::write(doc_root.join("blob.bin"), &data).unwrap();
    let state = build_state(doc_root);

    let req = http::Request::builder()
        .method("GET")
        .uri("/blob.bin")
        .header(header::HOST, CANON_HOST)
        .header(header::RANGE, "bytes=0-9,100-109")
        .body(hj_core::empty_incoming())
        .unwrap();
    let resp = run(&state, req).await;
    assert_eq!(resp.status(), http::StatusCode::PARTIAL_CONTENT);
    let ct = resp.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .to_owned();
    let boundary = ct
        .strip_prefix("multipart/byteranges; boundary=")
        .expect("multipart content type")
        .to_owned();
    let mut expect = Vec::new();
    for (s, e) in [(0usize, 9usize), (100usize, 109usize)] {
        expect.extend_from_slice(
            format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes {s}-{e}/1000\r\n\r\n")
                .as_bytes(),
        );
        expect.extend_from_slice(&data[s..=e]);
    }
    expect.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    match resp.into_body() {
        Body::Full(bytes) => {
            assert_eq!(
                bytes.len(),
                expect.len(),
                "Content-Length covers the whole framed entity"
            );
            assert_eq!(&bytes[..], &expect[..]);
        }
        _ => panic!("multipart must be a buffered full body"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn geo_acl_denies_by_resolved_client_ip() {
    // (Tier 2) A country-labelled CIDR list + `geoDeny` must 403 a request whose
    // RESOLVED client IP (CF-Connecting-IP from a trusted peer) falls in the
    // denied range — while the same request without the header (client_ip ==
    // loopback peer) passes. This is the real-IP trust boundary the geo gate
    // depends on.
    let doc_root = temp_root("geo-e2e");
    std::fs::write(doc_root.join("page.html"), b"<html>ok</html>").unwrap();
    let db = doc_root.join("geo.db");
    std::fs::write(
        &db,
        "country US 203.0.113.0/24\ncountry DE 198.51.100.0/24\n",
    )
    .unwrap();
    let state = build_state_inner(doc_root, Vec::new(), Vec::new(), false, None, None, |cfg| {
        cfg.security.geo_db_file = Some(db);
        cfg.security.geo_deny = vec!["US".into()];
        // Mode 2 + a trusted loopback rule: CF-Connecting-IP is honored from
        // the (loopback) peer, exactly like the production CF path.
        cfg.use_ip_in_proxy_header = 2;
        cfg.security.access_control = vec![hj_core::config::AccessRule {
            spec: "127.0.0.0/8".into(),
            trusted: true,
            allow: true,
        }];
    });

    // Mode-2 real-IP resolution only honors forwarded headers on the TLS path
    // (run_tls sets is_tls=true, client_auth_requested=false — the CF-over-TLS shape).
    let denied = get_with(
        CANON_HOST,
        "/page.html",
        &[("CF-Connecting-IP", "203.0.113.9")],
    );
    let resp = run_tls(&state, denied).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::FORBIDDEN,
        "a denied-country visitor must be rejected"
    );

    let allowed = get_with(CANON_HOST, "/page.html", &[("CF-Connecting-IP", "8.8.8.8")]);
    let resp = run_tls(&state, allowed).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "other countries pass");

    let no_header = get(CANON_HOST, "/page.html", None);
    let resp = run_tls(&state, no_header).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::OK,
        "loopback (the peer) is not in any denied range"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_throttle_uses_resolved_forwarded_identity() {
    let doc_root = temp_root("client-throttle-e2e");
    std::fs::write(doc_root.join("page.html"), b"<html>ok</html>").unwrap();
    let state = build_state_inner(doc_root, Vec::new(), Vec::new(), false, None, None, |cfg| {
        cfg.tuning.per_ip_rate = 1;
        cfg.tuning.per_ip_rate_window = std::time::Duration::from_secs(60);
        cfg.use_ip_in_proxy_header = 2;
        cfg.security.access_control = vec![hj_core::config::AccessRule {
            spec: "127.0.0.0/8".into(),
            trusted: true,
            allow: true,
        }];
    });

    let first = get_with(
        CANON_HOST,
        "/page.html",
        &[("CF-Connecting-IP", "203.0.113.10")],
    );
    assert_eq!(run_tls(&state, first).await.status(), http::StatusCode::OK);

    let repeated = get_with(
        CANON_HOST,
        "/page.html",
        &[("CF-Connecting-IP", "203.0.113.10")],
    );
    assert_eq!(
        run_tls(&state, repeated).await.status(),
        http::StatusCode::TOO_MANY_REQUESTS
    );

    let independent = get_with(
        CANON_HOST,
        "/page.html",
        &[("CF-Connecting-IP", "203.0.113.11")],
    );
    assert_eq!(
        run_tls(&state, independent).await.status(),
        http::StatusCode::OK,
        "clients behind one trusted proxy must have independent rate windows"
    );
}

pub(crate) fn forwarded_deny_state(tag: &str) -> (PathBuf, Arc<ServerState>) {
    let doc_root = temp_root(tag);
    std::fs::write(doc_root.join("page.html"), b"<html>ok</html>").unwrap();
    std::fs::write(doc_root.join("other.html"), b"<html>other</html>").unwrap();
    let state = build_state_inner(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        false,
        None,
        None,
        |cfg| {
            cfg.use_ip_in_proxy_header = 2;
            cfg.security.access_control = vec![
                hj_core::config::AccessRule {
                    spec: "ALL".into(),
                    trusted: false,
                    allow: true,
                },
                hj_core::config::AccessRule {
                    spec: "127.0.0.0/8".into(),
                    trusted: true,
                    allow: true,
                },
                hj_core::config::AccessRule {
                    spec: "203.0.113.0/24".into(),
                    trusted: false,
                    allow: false,
                },
            ];
        },
    );
    (doc_root, state)
}

/// #776: the server allow/deny list judges the resolved forwarded client, not
/// only the trusted proxy peer (OLS `updateClientInfoFromProxyHeader` → `checkAccess`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_acl_denies_by_resolved_forwarded_client_ip() {
    let (doc_root, state) = forwarded_deny_state("acl-forwarded-e2e");

    let denied = get_with(
        CANON_HOST,
        "/page.html",
        &[("CF-Connecting-IP", "203.0.113.9")],
    );
    assert_eq!(
        run_tls(&state, denied).await.status(),
        http::StatusCode::FORBIDDEN,
        "a denied forwarded client must be rejected behind an allowed proxy"
    );

    let allowed = get_with(CANON_HOST, "/page.html", &[("CF-Connecting-IP", "8.8.8.8")]);
    assert_eq!(
        run_tls(&state, allowed).await.status(),
        http::StatusCode::OK
    );

    let direct = get(CANON_HOST, "/page.html", None);
    assert_eq!(
        run_tls(&state, direct).await.status(),
        http::StatusCode::OK,
        "the allowed proxy itself is still served"
    );
    std::fs::remove_dir_all(doc_root).ok();
}

/// The production shape (`ALL` + trusted Cloudflare ranges, allow-only) keeps
/// serving every forwarded visitor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_acl_allow_only_trusted_ranges_keep_forwarded_clients_allowed() {
    let doc_root = temp_root("acl-forwarded-prod-shape");
    std::fs::write(doc_root.join("page.html"), b"<html>ok</html>").unwrap();
    let state = build_state_inner(
        doc_root.clone(),
        Vec::new(),
        Vec::new(),
        false,
        None,
        None,
        |cfg| {
            cfg.use_ip_in_proxy_header = 2;
            cfg.security.access_control = vec![
                hj_core::config::AccessRule {
                    spec: "ALL".into(),
                    trusted: false,
                    allow: true,
                },
                hj_core::config::AccessRule {
                    spec: "127.0.0.0/8".into(),
                    trusted: true,
                    allow: true,
                },
                hj_core::config::AccessRule {
                    spec: "173.245.48.0/20".into(),
                    trusted: true,
                    allow: true,
                },
            ];
        },
    );
    for client in ["203.0.113.9", "173.245.48.5", "2001:db8::1"] {
        let req = get_with(CANON_HOST, "/page.html", &[("CF-Connecting-IP", client)]);
        assert_eq!(
            run_tls(&state, req).await.status(),
            http::StatusCode::OK,
            "{client}"
        );
    }
    std::fs::remove_dir_all(doc_root).ok();
}

async fn fast_serve_tls(state: &Arc<ServerState>, req: &Request) -> Option<Response> {
    fast_serve(
        state,
        LISTENER,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from(([127, 0, 0, 1], 443)),
        40000,
        true,
        false,
        false,
        Proto::Http1,
        None,
        req,
    )
    .await
}

/// #776 on-core parity: both the memo-hit path and the main fast path must bridge
/// a denied forwarded client so the full pipeline renders the identical 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_bridges_a_denied_forwarded_client() {
    let (doc_root, state) = forwarded_deny_state("acl-forwarded-fast");
    let denied_hdr = [("CF-Connecting-IP", "203.0.113.9")];

    // Main path: a URL never served before (no memo entry).
    let req = get_with(CANON_HOST, "/other.html", &denied_hdr);
    assert!(
        fast_serve_tls(&state, &req).await.is_none(),
        "main fast path served a denied forwarded client"
    );

    // Memo path: warm the finished-response memo with an allowed request.
    let warm = get(CANON_HOST, "/page.html", None);
    for _ in 0..2 {
        let served = fast_serve_tls(&state, &warm).await;
        assert_eq!(served.map(|r| r.status()), Some(http::StatusCode::OK));
    }
    let hits_before = state
        .metrics
        .fast_memo_hits
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(hits_before > 0, "the memo was not exercised");
    let req = get_with(CANON_HOST, "/page.html", &denied_hdr);
    assert!(
        fast_serve_tls(&state, &req).await.is_none(),
        "memo hit replayed to a denied forwarded client"
    );
    // The warmed entry shares this request's memo key (CF-Connecting-IP is not a
    // vary), so the probe hit and was refused; a refused probe is not counted as a
    // memo hit (#824).
    assert_eq!(
        state
            .metrics
            .fast_memo_hits
            .load(std::sync::atomic::Ordering::Relaxed),
        hits_before,
        "a refused memo probe must not count as a hit"
    );
    let req = get_with(CANON_HOST, "/page.html", &[("CF-Connecting-IP", "8.8.8.8")]);
    assert_eq!(
        fast_serve_tls(&state, &req).await.map(|r| r.status()),
        Some(http::StatusCode::OK)
    );
    let full = run_tls(&state, get_with(CANON_HOST, "/page.html", &denied_hdr)).await;
    assert_eq!(full.status(), http::StatusCode::FORBIDDEN);
    std::fs::remove_dir_all(doc_root).ok();
}

/// [`run`] over a TLS-shaped connection (`is_tls=true`, no client-cert
/// requirement): forwarded client-IP headers are honored from a trusted peer.
async fn run_tls(state: &Arc<ServerState>, req: Request) -> Response {
    handle(
        state.clone(),
        LISTENER,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::from(([127, 0, 0, 1], 443)),
        40000,
        true,  // is_tls
        false, // peer_unix
        false, // client_auth_requested
        None,  // tls
        Proto::Http1,
        None, // sni
        req,
    )
    .await
}

fn get_with(host: &str, path: &str, headers: &[(&str, &str)]) -> Request {
    let mut b = http::Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, host);
    for (name, value) in headers {
        b = b.header(*name, *value);
    }
    b.body(hj_core::empty_incoming()).unwrap()
}

// ─── (Tier 2) sub_filter: literal response-body substitution ───

fn sub_filter_context(uri: &str, rules: &[(&str, &str)], once: bool) -> Context {
    Context {
        kind: ContextKind::Static,
        uri: uri.into(),
        location: None,
        handler: None,
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: None,
        charset: None,
        cache_policy: None,
        bandwidth_limit: 0,
        max_body_override: None,
        timeout_override: None,
        sub_filter: Some(Box::new(hj_core::config::SubFilterConfig {
            rules: rules
                .iter()
                .map(|(s, r)| (s.to_string(), r.to_string()))
                .collect(),
            once,
            ..hj_core::config::SubFilterConfig::default()
        })),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sub_filter_rewrites_matching_type_and_recomputes_headers() {
    let doc_root = temp_root("subfilter");
    std::fs::write(
        doc_root.join("page.html"),
        b"<html>hello world hello</html>",
    )
    .unwrap();
    std::fs::write(doc_root.join("data.txt"), b"hello world").unwrap();
    let state = build_state_with(
        doc_root,
        vec![sub_filter_context("/", &[("hello", "goodbye")], false)],
        Vec::new(),
    );

    let resp = run(&state, get(CANON_HOST, "/page.html", None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        body_bytes(resp.into_body()),
        "<html>goodbye world goodbye</html>"
    );
    let resp = run(&state, get(CANON_HOST, "/page.html", None)).await;
    assert!(
        resp.headers().get(header::ETAG).is_none(),
        "the entity changed: ETag must drop"
    );
    assert!(
        resp.headers().get(header::LAST_MODIFIED).is_none(),
        "Last-Modified defaults off (nginx sub_filter_last_modified)"
    );
    assert_eq!(resp.headers()[header::CONTENT_LENGTH], "34");

    // Non-matching Content-Type is untouched.
    let resp = run(&state, get(CANON_HOST, "/data.txt", None)).await;
    assert_eq!(body_bytes(resp.into_body()), "hello world");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sub_filter_once_replaces_first_occurrence_only() {
    let doc_root = temp_root("subfilter-once");
    std::fs::write(doc_root.join("page.html"), b"<html>aaa and aaa</html>").unwrap();
    let state = build_state_with(
        doc_root,
        vec![sub_filter_context("/", &[("aaa", "bbb")], true)],
        Vec::new(),
    );
    let resp = run(&state, get(CANON_HOST, "/page.html", None)).await;
    assert_eq!(body_bytes(resp.into_body()), "<html>bbb and aaa</html>");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sub_filter_paths_memoize_final_bytes_without_double_substitution() {
    // The memo stores the final response and replays it without transforms. A
    // non-idempotent replacement proves a hit cannot apply the filter twice.
    let doc_root = temp_root("subfilter-memo");
    std::fs::create_dir_all(doc_root.join("sub")).unwrap();
    std::fs::write(doc_root.join("sub/index.html"), b"a b a").unwrap();
    let state = build_state_inner(
        doc_root,
        vec![sub_filter_context("/sub", &[("a", "ab")], false)],
        Vec::new(),
        true, // htaccess-loading vhost: the memo path is live
        None,
        None,
        |_| {},
    );

    let stores = || {
        state
            .metrics
            .fast_memo_stores
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    let hits = || {
        state
            .metrics
            .fast_memo_hits
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    let stores_before = stores();
    let hits_before = hits();
    let first = fast_serve_get(&state, "/sub/").await;
    let first = first.expect("first serve");
    assert_eq!(body_bytes(first.into_body()), "ab b ab");
    assert!(
        stores() > stores_before,
        "filtered response was not memoized"
    );
    let second = fast_serve_get(&state, "/sub/").await;
    let second = second.expect("second serve");
    assert_eq!(
        body_bytes(second.into_body()),
        "ab b ab",
        "memo hit must replay final bytes without filtering twice"
    );
    assert!(hits() > hits_before, "second serve did not hit fast memo");
}

#[test]
fn apply_sub_filter_rules_are_ordered_and_literal() {
    use super::apply_sub_filter;
    let plan = |rules: &[(&str, &str)], once: bool| hj_core::config::SubFilterConfig {
        rules: rules
            .iter()
            .map(|(s, r)| (s.to_string(), r.to_string()))
            .collect(),
        once,
        ..hj_core::config::SubFilterConfig::default()
    };
    // Rules apply in order; each sees the PREVIOUS rule's output.
    let out = apply_sub_filter(
        &plan(&[("aaa", "aba"), ("aba", "XYZ")], false),
        "aaa".into(),
    )
    .unwrap();
    assert_eq!(&out[..], b"XYZ");

    // once replaces only the first occurrence.
    let out = apply_sub_filter(&plan(&[("a", "b")], true), "aa".into()).unwrap();
    assert_eq!(&out[..], b"ba");

    // An empty search string would insert everywhere — skipped by design.
    let out = apply_sub_filter(&plan(&[("", "x")], false), "ab".into()).unwrap();
    assert_eq!(&out[..], b"ab");

    // Matches never overlap.
    let out = apply_sub_filter(&plan(&[("aa", "b")], false), "aaaaa".into()).unwrap();
    assert_eq!(&out[..], b"bba");

    // A non-idempotent shape proves memo hits must replay finalized bytes without
    // rerunning transforms: a replacement containing its search grows if reapplied.
    let plan = plan(&[("a", "ab")], false);
    let once = apply_sub_filter(&plan, "a".into()).unwrap();
    let twice = apply_sub_filter(&plan, once.clone()).unwrap();
    assert_ne!(&once[..], &twice[..]);
}

/// Regression (#1141): every rule's output is sized before it is built, so an
/// expanding rule (or rules compounding) past `max_body` yields `None` and the
/// entity is served unfiltered instead of growing without bound.
#[test]
fn apply_sub_filter_refuses_output_past_the_cap() {
    use super::apply_sub_filter;
    let plan = |rules: &[(&str, &str)], max_body: u64| hj_core::config::SubFilterConfig {
        rules: rules
            .iter()
            .map(|(s, r)| (s.to_string(), r.to_string()))
            .collect(),
        max_body,
        ..hj_core::config::SubFilterConfig::default()
    };
    let expand = plan(&[("a", "aaaa")], 16);
    assert_eq!(
        &apply_sub_filter(&expand, "aaaa".into()).unwrap()[..],
        b"aaaaaaaaaaaaaaaa"
    );
    assert!(apply_sub_filter(&expand, "aaaaa".into()).is_none());
    // Each rule fits on its own; together they would pass the cap.
    let compound = plan(&[("a", "aa"), ("a", "aa")], 10);
    assert!(apply_sub_filter(&compound, "aaa".into()).is_none());
    assert_eq!(
        &apply_sub_filter(&compound, "aa".into()).unwrap()[..],
        b"aaaaaaaa"
    );
    // A shrinking rule is never refused.
    let shrink = plan(&[("aaaa", "")], 4);
    assert_eq!(
        &apply_sub_filter(&shrink, "aaaab".into()).unwrap()[..],
        b"b"
    );
}

/// Regression (#1141): a Full body over `max_body`, or one whose filtered output
/// would pass it, is served unfiltered with its headers untouched.
#[tokio::test]
async fn sub_filter_full_body_past_the_cap_is_served_raw() {
    use hj_core::ResponseTransform;
    for (body, max_body, expect) in [
        (&b"SEND"[..], 8, &b"RECEIVED"[..]),
        (&b"SEND SEND"[..], 8, &b"SEND SEND"[..]),
        (&b"SEND"[..], 7, &b"SEND"[..]),
        (&b"xxxxxxxxxxSEND"[..], 8, &b"xxxxxxxxxxSEND"[..]),
    ] {
        let mut resp = http::Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "text/html")
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .header(header::ETAG, "\"e\"")
            .body(hj_core::Body::Full(bytes::Bytes::copy_from_slice(body)))
            .unwrap();
        resp.extensions_mut().insert(html_plan(max_body));
        crate::pipeline::SubFilterTransform
            .transform(&ctx_for_transform(), &mut resp)
            .await;
        let filtered = expect != body;
        assert_eq!(
            resp.headers().contains_key(header::ETAG),
            !filtered,
            "{body:?}"
        );
        assert_eq!(
            resp.headers()[header::CONTENT_LENGTH],
            expect.len().to_string()
        );
        assert_eq!(
            frames_of(resp.into_body()),
            expect,
            "{body:?} cap {max_body}"
        );
    }
}

/// Regression (#1141): a stream buffered within the cap whose filtered output
/// would pass it replays unfiltered.
#[tokio::test]
async fn sub_filter_stream_expanding_past_the_cap_is_served_raw() {
    use hj_core::ResponseTransform;
    use http_body_util::BodyExt;
    let mut resp = stream_response(hj_core::StreamBody::boxed(
        http_body_util::Full::new(bytes::Bytes::from_static(b"SEND SEND"))
            .map_err(|e: std::convert::Infallible| match e {})
            .boxed(),
    ));
    resp.extensions_mut().insert(html_plan(12));
    crate::pipeline::SubFilterTransform
        .transform(&ctx_for_transform(), &mut resp)
        .await;
    assert_eq!(frames_of(resp.into_body()), b"SEND SEND");
}

// ─── (Tier 2) SubFilterTransform stream handling: filter-within-cap, raw past it ───

/// A tiny replayable stream body for transform tests.
struct VecBody {
    frames: std::collections::VecDeque<bytes::Bytes>,
}

impl http_body::Body for VecBody {
    type Data = bytes::Bytes;
    type Error = hj_core::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.frames.pop_front() {
            Some(b) => std::task::Poll::Ready(Some(Ok(http_body::Frame::data(b)))),
            None => std::task::Poll::Ready(None),
        }
    }
}

fn stream_response(body: hj_core::StreamBody) -> Response {
    http::Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/html")
        .body(hj_core::Body::Stream(body))
        .unwrap()
}

fn html_plan(max_body: u64) -> super::SubFilterPlan {
    super::SubFilterPlan(Arc::new(hj_core::config::SubFilterConfig {
        rules: vec![("SEND".to_string(), "RECEIVED".to_string())],
        max_body,
        ..hj_core::config::SubFilterConfig::default()
    }))
}

fn ctx_for_transform() -> hj_core::ReqCtx {
    let server = ServerConfig {
        server_root: Default::default(),
        server_name: String::new(),
        user: String::new(),
        group: String::new(),
        index_files: vec![],
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
        vhosts: Default::default(),
        vhost_order: vec![],
        mime: Default::default(),
    };
    hj_core::ReqCtx {
        server: Arc::new(server),
        vhost_name: String::new(),
        vhost: Arc::new(hj_core::config::VHostConfig::default()),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        is_tls: false,
        peer_unix: false,
        protocol: Proto::Http1,
        trusted_proxy: false,
        forwarding_trusted: false,
        env: Vec::new(),
        local_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
        peer_port: 40000,
        request_time: std::time::SystemTime::UNIX_EPOCH,
        request_id: Default::default(),
        redirect_guard: None,
        tls: None,
    }
}

fn frames_of(body: Body) -> Vec<u8> {
    match body {
        Body::Full(b) => b.to_vec(),
        Body::Stream(mut s) => {
            use http_body_util::BodyExt;
            let mut out = Vec::new();
            futures_executor_block(async {
                while let Some(frame) = s.frame().await {
                    out.extend_from_slice(
                        frame.expect("frame").into_data().expect("data").as_ref(),
                    );
                }
            });
            out
        }
        _other => panic!("unexpected body variant"),
    }
}

// The pipeline is tokio-native; block inline so the unit test stays sync.
fn futures_executor_block<F: std::future::Future<Output = ()>>(fut: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut);
}

#[tokio::test]
async fn sub_filter_stream_within_cap_is_buffered_and_filtered() {
    use http_body_util::BodyExt;
    let mut resp = stream_response(hj_core::StreamBody::boxed(
        http_body_util::Full::new(bytes::Bytes::from_static(b"<p>SEND a</p>SEND"))
            .map_err(|e: std::convert::Infallible| match e {})
            .boxed(),
    ));
    resp.extensions_mut().insert(html_plan(1024));
    let ctx = ctx_for_transform();
    use hj_core::ResponseTransform;
    crate::pipeline::SubFilterTransform
        .transform(&ctx, &mut resp)
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(frames_of(resp.into_body()), b"<p>RECEIVED a</p>RECEIVED");
}

#[tokio::test]
async fn sub_filter_stream_over_cap_passes_through_raw_untouched() {
    use http_body_util::BodyExt;
    // Two frames totaling > the 8-byte cap; the SEARCH token appears in the
    // buffered prefix — the response must still pass through UNFILTERED.
    let frames = vec![
        bytes::Bytes::from_static(b"SEND a"),
        bytes::Bytes::from_static(b"SEND b"),
    ];
    let mut resp = stream_response(hj_core::StreamBody::boxed(
        VecBody {
            frames: frames.clone().into(),
        }
        .boxed(),
    ));
    resp.extensions_mut().insert(html_plan(8));
    let ctx = ctx_for_transform();
    use hj_core::ResponseTransform;
    crate::pipeline::SubFilterTransform
        .transform(&ctx, &mut resp)
        .await;

    let body = match resp.into_body() {
        Body::Stream(s) => s,
        _ => panic!("over-cap stream must stay a stream"),
    };
    let mut got = Vec::new();
    let mut s = body;
    while let Some(frame) = s.frame().await {
        got.extend_from_slice(frame.expect("frame").into_data().expect("data").as_ref());
    }
    assert_eq!(
        got, b"SEND aSEND b",
        "raw passthrough: prefix + remainder, unfiltered"
    );
}

#[test]
fn sub_filter_no_extension_is_a_no_op() {
    // The transform must leave responses WITHOUT a plan untouched (every serve
    // path runs it; only stamped responses may change).
    let mut resp = http::Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/html")
        .body(Body::Full(bytes::Bytes::from_static(b"SEND")))
        .unwrap();
    let ctx = ctx_for_transform();
    use hj_core::ResponseTransform;
    futures_executor_block(async {
        crate::pipeline::SubFilterTransform
            .transform(&ctx, &mut resp)
            .await;
    });
    assert_eq!(frames_of(resp.into_body()), b"SEND");
}

/// A deterministic body that can replay data, trailers, and errors in order.
struct ScriptedBody {
    frames: std::collections::VecDeque<Result<http_body::Frame<bytes::Bytes>, hj_core::BoxError>>,
}

impl http_body::Body for ScriptedBody {
    type Data = bytes::Bytes;
    type Error = hj_core::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(self.frames.pop_front())
    }
}

#[tokio::test]
async fn sub_filter_stream_error_preserves_raw_prefix_and_error() {
    use hj_core::ResponseTransform;
    use http_body_util::BodyExt;

    let scripted = ScriptedBody {
        frames: vec![
            Ok(http_body::Frame::data(bytes::Bytes::from_static(
                b"prefix ",
            ))),
            Ok(http_body::Frame::data(bytes::Bytes::from_static(b"SEND"))),
            Err(Box::new(std::io::Error::other("scripted stream failure")) as hj_core::BoxError),
        ]
        .into(),
    };
    let mut resp = stream_response(scripted.boxed());
    resp.extensions_mut().insert(html_plan(1024));
    crate::pipeline::SubFilterTransform
        .transform(&ctx_for_transform(), &mut resp)
        .await;

    let Body::Stream(mut body) = resp.into_body() else {
        panic!("a failed source stream must remain a stream");
    };
    let prefix = body
        .frame()
        .await
        .expect("prefix frame")
        .expect("prefix remains successful")
        .into_data()
        .expect("prefix data");
    assert_eq!(prefix, "prefix SEND", "partial data stays unfiltered");
    let err = body
        .frame()
        .await
        .expect("error frame")
        .expect_err("the original stream failure must reach the transport");
    assert_eq!(err.to_string(), "scripted stream failure");
}

#[tokio::test]
async fn sub_filter_stream_preserves_trailers_after_filtering() {
    use hj_core::ResponseTransform;
    use http_body_util::BodyExt;

    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        http::HeaderName::from_static("x-body-checksum"),
        http::HeaderValue::from_static("present"),
    );
    let scripted = ScriptedBody {
        frames: vec![
            Ok(http_body::Frame::data(bytes::Bytes::from_static(b"SEND"))),
            Ok(http_body::Frame::trailers(trailers)),
        ]
        .into(),
    };
    let mut resp = stream_response(scripted.boxed());
    resp.extensions_mut().insert(html_plan(1024));
    crate::pipeline::SubFilterTransform
        .transform(&ctx_for_transform(), &mut resp)
        .await;

    assert!(
        resp.headers().get(header::CONTENT_LENGTH).is_none(),
        "HTTP/1 trailers require streamed framing"
    );
    let Body::Stream(mut body) = resp.into_body() else {
        panic!("trailers require the filtered response to remain a stream");
    };
    let data = body
        .frame()
        .await
        .expect("data frame")
        .expect("successful data")
        .into_data()
        .expect("filtered data");
    assert_eq!(data, "RECEIVED");
    let trailers = body
        .frame()
        .await
        .expect("trailer frame")
        .expect("successful trailers")
        .into_trailers()
        .expect("trailers preserved");
    assert_eq!(trailers["x-body-checksum"], "present");
}

#[tokio::test]
async fn sub_filter_file_uses_selected_pinned_or_cached_bytes() {
    use hj_core::ResponseTransform;

    fn file_response(file: hj_core::FileBody) -> Response {
        http::Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::File(file))
            .unwrap()
    }

    let root = temp_root("subfilter-file-version");
    let selected = root.join("page.html");
    let archived = root.join("selected-version.html");
    std::fs::write(&selected, b"PINNED SEND").unwrap();
    let pinned = std::fs::File::open(&selected).unwrap();
    std::fs::rename(&selected, &archived).unwrap();
    std::fs::write(&selected, b"REPLACEMENT SEND").unwrap();

    let mut pinned_resp = file_response(hj_core::FileBody {
        path: selected.clone(),
        file: Some(pinned),
        len: 11,
        range: None,
        cached: None,
    });
    pinned_resp.extensions_mut().insert(html_plan(1024));
    crate::pipeline::SubFilterTransform
        .transform(&ctx_for_transform(), &mut pinned_resp)
        .await;
    assert_eq!(frames_of(pinned_resp.into_body()), b"PINNED RECEIVED");

    std::fs::write(&selected, b"DISK SEND").unwrap();
    let mut cached_resp = file_response(hj_core::FileBody {
        path: selected,
        file: None,
        len: 11,
        range: None,
        cached: Some(bytes::Bytes::from_static(b"CACHED SEND")),
    });
    cached_resp.extensions_mut().insert(html_plan(1024));
    crate::pipeline::SubFilterTransform
        .transform(&ctx_for_transform(), &mut cached_resp)
        .await;
    assert_eq!(frames_of(cached_resp.into_body()), b"CACHED RECEIVED");

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn apply_sub_filter_preserves_non_utf8_bytes() {
    use super::apply_sub_filter;

    let plan = hj_core::config::SubFilterConfig {
        rules: vec![("SEND".to_string(), "RECEIVED".to_string())],
        ..hj_core::config::SubFilterConfig::default()
    };
    let out = apply_sub_filter(
        &plan,
        bytes::Bytes::from_static(b"\xff prefix SEND suffix \xfe"),
    )
    .unwrap();
    assert_eq!(&out[..], b"\xff prefix RECEIVED suffix \xfe");

    let untouched = bytes::Bytes::from_static(b"\xff no match \xfe");
    assert_eq!(apply_sub_filter(&plan, untouched.clone()), Some(untouched));
}

fn body_limit_context(uri: &str, max_body: u64) -> Context {
    Context {
        kind: ContextKind::Static,
        uri: uri.into(),
        location: None,
        handler: None,
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: None,
        charset: None,
        cache_policy: None,
        max_body_override: Some(max_body),
        bandwidth_limit: 0,
        timeout_override: None,
        sub_filter: None,
    }
}

fn get_with_body(path: &str, body: &'static [u8]) -> Request {
    use http_body_util::BodyExt;
    let body = http_body_util::Full::new(bytes::Bytes::from_static(body))
        .map_err(|never: std::convert::Infallible| -> hj_core::BoxError { match never {} })
        .boxed();
    http::Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, CANON_HOST)
        .body(body)
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_body_limit_enforces_original_and_rewritten_paths_without_content_length() {
    let doc_root = temp_root("context-body-limit");
    std::fs::write(doc_root.join("upload.txt"), b"upload target\n").unwrap();
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^front$ /upload.txt [L]\n",
    )
    .unwrap();
    let state = build_state_inner(
        doc_root.clone(),
        vec![body_limit_context("/upload.txt", 4)],
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );

    let direct = get_with_body("/upload.txt", b"12345");
    assert!(!direct.headers().contains_key(header::CONTENT_LENGTH));
    assert_eq!(run(&state, direct).await.status(), 413);

    let rewritten = get_with_body("/front", b"12345");
    assert!(!rewritten.headers().contains_key(header::CONTENT_LENGTH));
    assert_eq!(
        run(&state, rewritten).await.status(),
        413,
        "the final rewritten context must enforce its body cap"
    );

    let allowed = run(&state, get_with_body("/front", b"1234")).await;
    assert_eq!(allowed.status(), 200);
    assert_eq!(body_bytes(allowed.into_body()), "upload target\n");
    std::fs::remove_dir_all(doc_root).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_bridges_nonempty_and_unknown_request_bodies_before_memo_or_static() {
    use http_body_util::BodyExt;

    let doc_root = temp_root("fast-body-bridge");
    std::fs::write(doc_root.join("hello.txt"), b"hello\n").unwrap();
    let state = build_state(doc_root.clone());

    let nonempty = get_with_body("/hello.txt", b"x");
    assert!(fast_serve_req(&state, &nonempty).await.is_none());

    let unknown = http::Request::builder()
        .method("GET")
        .uri("/hello.txt")
        .header(header::HOST, CANON_HOST)
        .body(
            ScriptedBody {
                frames: vec![Ok(http_body::Frame::data(bytes::Bytes::from_static(b"x")))].into(),
            }
            .boxed(),
        )
        .unwrap();
    assert!(fast_serve_req(&state, &unknown).await.is_none());

    assert!(
        fast_serve_get(&state, "/hello.txt").await.is_some(),
        "an actually empty request remains eligible"
    );
    std::fs::remove_dir_all(doc_root).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_cache_promotion_reads_the_selected_descriptor_for_full_range_and_fast_paths() {
    fn file_response(
        path: PathBuf,
        file: std::fs::File,
        len: u64,
        range: Option<(u64, u64)>,
    ) -> Response {
        http::Response::builder()
            .status(if range.is_some() { 206 } else { 200 })
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::ETAG, "\"selected-version\"")
            .header(header::LAST_MODIFIED, "Thu, 01 Jan 1970 00:00:00 GMT")
            .body(Body::File(hj_core::FileBody {
                path,
                file: Some(file),
                len,
                range,
                cached: None,
            }))
            .unwrap()
    }

    let root = temp_root("static-selected-fd");
    let state = build_state(root.clone());

    let ordinary_path = root.join("ordinary.txt");
    let selected = b"OLD-FULL";
    std::fs::write(&ordinary_path, selected).unwrap();
    let ordinary_fd = std::fs::File::open(&ordinary_path).unwrap();
    let range_fd = ordinary_fd.try_clone().unwrap();
    let replacement = root.join("ordinary-replacement.txt");
    std::fs::write(&replacement, b"NEW-FULL").unwrap();
    std::fs::rename(replacement, &ordinary_path).unwrap();

    let mut full = file_response(
        ordinary_path.clone(),
        ordinary_fd,
        selected.len() as u64,
        None,
    );
    super::maybe_cache_static(&state.static_cache, 7, &mut full);
    assert_eq!(
        body_bytes(full.into_body()),
        bytes::Bytes::from_static(selected),
        "ordinary promotion must not mix replacement bytes with selected-file validators"
    );

    let mut ranged = file_response(ordinary_path, range_fd, selected.len() as u64, Some((1, 3)));
    super::maybe_cache_static(&state.static_cache, 7, &mut ranged);
    let Body::File(ranged) = ranged.into_body() else {
        panic!("a ranged response stays a file body");
    };
    assert!(
        ranged.file.is_some(),
        "the selected descriptor remains pinned"
    );
    assert_eq!(
        ranged.cached_ranged().unwrap(),
        bytes::Bytes::from_static(b"LD-"),
        "range promotion must attach the selected file's whole cached body"
    );

    let fast_path = root.join("fast.txt");
    std::fs::write(&fast_path, b"OLD-FAST").unwrap();
    let fast_fd = std::fs::File::open(&fast_path).unwrap();
    let fast_replacement = root.join("fast-replacement.txt");
    std::fs::write(&fast_replacement, b"NEW-FAST").unwrap();
    std::fs::rename(fast_replacement, &fast_path).unwrap();
    let fast = file_response(fast_path, fast_fd, 8, None);
    let fast = super::buffer_static_file(&state, 8, fast).expect("small file buffers in fast path");
    assert_eq!(
        body_bytes(fast.into_body()),
        bytes::Bytes::from_static(b"OLD-FAST"),
        "fast promotion must read the same selected descriptor as the ordinary funnel"
    );

    std::fs::remove_dir_all(root).ok();
}

async fn response_text(resp: Response) -> String {
    use http_body_util::BodyExt;
    let bytes = match resp.into_body() {
        Body::Stream(s) => s.collect().await.unwrap().to_bytes(),
        other => body_bytes(other),
    };
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Upstream that renders the RAW request-target it received, cacheable for 60 s — the shape of
/// a front controller that routes `REQUEST_URI` (XenForo 404s `/./` while `/` is the homepage).
async fn spawn_raw_echo_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0_u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            let line = String::from_utf8_lossy(&head);
            let target = line.split(' ').nth(1).unwrap_or("").to_string();
            let body = format!("raw={target}");
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    (address, task)
}

fn raw_echo_proxy_state(tag: &str, address: SocketAddr) -> Arc<ServerState> {
    let root = temp_root(tag);
    std::fs::write(
        root.join(".htaccess"),
        "CacheLookup public on\nHeader set X-LiteSpeed-Cache-Control public,max-age=60\n",
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let context = Context {
        kind: ContextKind::Proxy,
        uri: "/".into(),
        location: None,
        handler: Some("test-upstream".into()),
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: None,
        charset: None,
        cache_policy: None,
        max_body_override: None,
        bandwidth_limit: 0,
        timeout_override: None,
        sub_filter: None,
    };
    build_state_inner(
        root,
        vec![context],
        Vec::new(),
        true,
        Some(store),
        None,
        |server| register_upstream(server, address),
    )
}

/// The page cache keys by the decoded, dot-normalized path but the backend routes the raw
/// URI: a non-canonical spelling (`/./`, `/x/../`, `//`, `%2F`) must neither populate nor read
/// the canonical URL's entry, or one request poisons the homepage for every visitor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_segment_spelling_cannot_poison_or_read_the_canonical_page_cache_entry() {
    let (address, upstream) = spawn_raw_echo_upstream().await;
    let state = raw_echo_proxy_state("dot-poison", address);

    for (attack, victim) in [
        ("/./", "/"),
        ("/zzz/..", "/"),
        ("/zzz/%2e%2e/target/", "/target/"),
        ("//target/", "/target/"),
        ("/a%2Fb", "/a/b"),
    ] {
        for _ in 0..3 {
            let resp = run(&state, get(CANON_HOST, attack, None)).await;
            assert_ne!(
                resp.headers()
                    .get("x-litespeed-cache")
                    .map(|v| v.as_bytes()),
                Some(&b"hit"[..]),
                "{attack} must bypass the page cache"
            );
            assert_eq!(response_text(resp).await, format!("raw={attack}"));
        }
        let resp = run(&state, get(CANON_HOST, victim, None)).await;
        assert_eq!(
            response_text(resp).await,
            format!("raw={victim}"),
            "{attack} poisoned the entry for {victim}"
        );
    }

    // The canonical spelling still caches; any other spelling, including an escaped
    // unreserved byte (XenForo strips SCRIPT_NAME from the RAW URI, so `/index%2Ephp/x`
    // routes differently), never reads it — neither on the full pipeline nor on-core.
    for _ in 0..3 {
        run(&state, get(CANON_HOST, "/target/", None)).await;
    }
    let hit = run(&state, get(CANON_HOST, "/target/", None)).await;
    assert_eq!(hit.headers().get("x-litespeed-cache").unwrap(), "hit");
    let escaped = run(&state, get(CANON_HOST, "/t%61rget/", None)).await;
    assert_ne!(
        escaped
            .headers()
            .get("x-litespeed-cache")
            .map(|v| v.as_bytes()),
        Some(&b"hit"[..]),
        "an escaped unreserved byte must not read the canonical entry"
    );
    assert!(is_cache_hit(
        fast_serve_req(&state, &get(CANON_HOST, "/target/", None))
            .await
            .as_ref()
    ));
    for spelling in ["/./target/", "//target/", "/x/../target/"] {
        assert!(
            !is_cache_hit(
                fast_serve_req(&state, &get(CANON_HOST, spelling, None))
                    .await
                    .as_ref()
            ),
            "{spelling} read the canonical entry on-core"
        );
        let resp = run(&state, get(CANON_HOST, spelling, None)).await;
        assert_eq!(response_text(resp).await, format!("raw={spelling}"));
    }
    upstream.abort();
}

fn plain_context(kind: ContextKind, uri: &str) -> Context {
    Context {
        kind,
        uri: uri.into(),
        location: None,
        handler: None,
        enabled: true,
        allow_browse: true,
        extra_headers: Vec::new(),
        inherit_extra_headers: true,
        add_default_charset: None,
        charset: None,
        cache_policy: None,
        bandwidth_limit: 0,
        max_body_override: None,
        timeout_override: None,
        sub_filter: None,
    }
}

fn websocket_get(path: &str) -> Request {
    http::Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, CANON_HOST)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(hj_core::empty_incoming())
        .unwrap()
}

async fn spawn_fixed_upstream(head: &'static str, body: &'static str) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut buf = [0_u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    req.extend_from_slice(&buf[..n]);
                }
                let reply = format!(
                    "{head}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    address
}

/// The on-core cache hit must authenticate a REWRITTEN target like dispatch() does: an
/// auth-free original chain says nothing about a symlink into an auth-protected directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_path_cache_hit_bridges_when_rewritten_target_requires_auth() {
    let root = temp_root("auth-rewritten-target");
    std::fs::create_dir_all(root.join("private")).unwrap();
    std::fs::write(root.join("private/secret.txt"), b"secret").unwrap();
    std::fs::write(
        root.join("users"),
        "Admin:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
    )
    .unwrap();
    std::fs::write(
        root.join("private/.htaccess"),
        format!(
            "AuthType Basic\nAuthName \"p\"\nAuthUserFile {}/users\nRequire valid-user\n",
            root.display()
        ),
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("private/secret.txt"), root.join("alias.txt")).unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^app/ /alias.txt [L]\n\
         Header set Cache-Control \"public, max-age=600\"\n",
    )
    .unwrap();
    let mut cfg = hj_pagecache::StoreConfig::default();
    cfg.standard_cc_vhosts.push(VHOST.into());
    let store = Arc::new(hj_pagecache::PageStore::new(cfg));
    let state = build_state_full(root.clone(), Vec::new(), Vec::new(), Some(store), None);

    assert_eq!(
        run(&state, get(CANON_HOST, "/app/x", None)).await.status(),
        401
    );
    let mut stored = false;
    for _ in 0..3 {
        let mut authed = get(CANON_HOST, "/app/x", None);
        authed.headers_mut().insert(
            header::AUTHORIZATION,
            "Basic QWRtaW46cGFzc3dvcmQ=".parse().unwrap(),
        );
        let resp = run(&state, authed).await;
        assert_eq!(resp.status(), 200);
        stored |= resp
            .headers()
            .get("x-litespeed-cache")
            .map(|v| v.as_bytes())
            == Some(b"hit");
    }
    assert!(
        stored,
        "precondition: the authenticated render is publicly cached"
    );
    let fast = fast_serve_get(&state, "/app/x").await;
    assert!(
        fast.is_none(),
        "on-core path served an auth-protected target without credentials: {:?}",
        fast.map(|r| r.status())
    );
    assert_eq!(
        run(&state, get(CANON_HOST, "/app/x", None)).await.status(),
        401
    );
    std::fs::remove_dir_all(root).ok();
}

/// OLS resolves the single most specific context of any kind, so a static context nested
/// under a proxy root serves the local file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_context_nested_under_proxy_root_serves_locally() {
    let address = spawn_fixed_upstream("HTTP/1.1 200 OK", "UPSTREAM").await;
    let root = temp_root("nested-static-under-proxy");
    std::fs::create_dir_all(root.join("assets")).unwrap();
    std::fs::write(root.join("assets/app.txt"), b"LOCAL").unwrap();
    std::fs::write(root.join("other.txt"), b"LOCAL-OTHER").unwrap();
    let mut proxy = plain_context(ContextKind::Proxy, "/");
    proxy.handler = Some("test-upstream".into());
    let mut assets = plain_context(ContextKind::Static, "/assets/");
    assets.location = Some(root.join("assets"));
    let state = build_state_inner(
        root.clone(),
        vec![proxy, assets],
        Vec::new(),
        false,
        None,
        None,
        |server| register_upstream(server, address),
    );
    let resp = run(&state, get(CANON_HOST, "/assets/app.txt", None)).await;
    assert_eq!(response_text(resp).await, "LOCAL");
    let resp = run(&state, get(CANON_HOST, "/other.txt", None)).await;
    assert_eq!(response_text(resp).await, "UPSTREAM");
    std::fs::remove_dir_all(root).ok();
}

/// #815/#816: a plain static context nested under a location-override context
/// serves `$DOC_ROOT + uri` (not the parent's location) on dispatch AND the
/// on-core fast path, and inherits the parent's extraHeaders before its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_plain_static_context_keeps_docroot_and_inherits_headers() {
    let root = temp_root("nested-static-docroot");
    let alt = temp_root("nested-static-alt");
    std::fs::create_dir_all(root.join("docs/sub")).unwrap();
    std::fs::write(root.join("docs/sub/a.txt"), b"DOCROOT").unwrap();
    std::fs::create_dir_all(alt.join("sub")).unwrap();
    std::fs::write(alt.join("sub/a.txt"), b"ALT-SUB").unwrap();
    std::fs::write(alt.join("b.txt"), b"ALT").unwrap();
    let mut parent = plain_context(ContextKind::Static, "/docs/");
    parent.location = Some(alt.clone());
    parent.extra_headers = vec![
        ("X-Parent".into(), "p".into()),
        ("Cache-Control".into(), "public, max-age=60".into()),
    ];
    let mut child = plain_context(ContextKind::Static, "/docs/sub/");
    child.extra_headers = vec![("X-Child".into(), "c".into())];
    let state = build_state_with(root.clone(), vec![parent, child], Vec::new());

    let resp = run(&state, get(CANON_HOST, "/docs/sub/a.txt", None)).await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    assert_eq!(resp.headers()["x-parent"], "p");
    assert_eq!(resp.headers()["x-child"], "c");
    assert_eq!(resp.headers()["cache-control"], "public, max-age=60");
    assert_eq!(response_text(resp).await, "DOCROOT");

    {
        let resp = fast_serve_get(&state, "/docs/sub/a.txt")
            .await
            .expect("on-core");
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(resp.headers()["x-parent"], "p");
        assert_eq!(resp.headers()["x-child"], "c");
        assert_eq!(response_text(resp).await, "DOCROOT");
    }

    let resp = run(&state, get(CANON_HOST, "/docs/b.txt", None)).await;
    assert_eq!(resp.headers()["x-parent"], "p");
    assert!(resp.headers().get("x-child").is_none());
    assert_eq!(response_text(resp).await, "ALT");
    std::fs::remove_dir_all(root).ok();
    std::fs::remove_dir_all(alt).ok();
}

/// #815: a static ErrorDocument under a location-override context renders from
/// that context's root, exactly as a direct request for the page would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_errordocument_under_location_context_uses_its_root() {
    let root = temp_root("errordoc-context-docroot");
    let alt = temp_root("errordoc-context-alt");
    std::fs::create_dir_all(root.join("errors")).unwrap();
    std::fs::write(root.join("errors/404.html"), b"DOCROOT-404").unwrap();
    std::fs::write(alt.join("404.html"), b"ALT-404").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "ErrorDocument 404 /errors/404.html\n",
    )
    .unwrap();
    let mut errors = plain_context(ContextKind::Static, "/errors/");
    errors.location = Some(alt.clone());
    let state = build_state_inner(
        root.clone(),
        vec![errors],
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );
    let direct = run(&state, get(CANON_HOST, "/errors/404.html", None)).await;
    assert_eq!(response_text(direct).await, "ALT-404");
    let resp = run(&state, get(CANON_HOST, "/missing", None)).await;
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    assert_eq!(response_text(resp).await, "ALT-404");
    std::fs::remove_dir_all(root).ok();
    std::fs::remove_dir_all(alt).ok();
}

/// A WebSocket handshake is routed to the upgrade relay, never answered from the page cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_upgrade_is_never_served_from_page_cache() {
    let root = temp_root("ws-page-cache");
    let mut cfg = hj_pagecache::StoreConfig::default();
    cfg.standard_cc_vhosts.push(VHOST.into());
    let store = Arc::new(hj_pagecache::PageStore::new(cfg));
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |config| {
            let vhost = config
                .vhosts
                .get_mut(VHOST)
                .unwrap()
                .config
                .as_mut()
                .unwrap();
            Arc::make_mut(vhost)
                .websockets
                .push(hj_core::config::WebSocketMap {
                    uri: "/ws".into(),
                    address: "127.0.0.1:1".into(),
                });
        },
    );
    seed_public_entry(&state, &store, "/ws", b"<h1>cached page</h1>").await;
    let plain = run(&state, get(CANON_HOST, "/ws", None)).await;
    assert_eq!(plain.headers().get("x-litespeed-cache").unwrap(), "hit");
    let resp = run(&state, websocket_get("/ws")).await;
    assert_ne!(
        resp.headers()
            .get("x-litespeed-cache")
            .map(|v| v.as_bytes()),
        Some(&b"hit"[..]),
        "a WebSocket handshake was answered from the page cache"
    );
    std::fs::remove_dir_all(root).ok();
}

/// The most specific `websocketList` map wins, as with OLS `bestMatch`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_map_selection_prefers_the_longest_uri() {
    let a = spawn_fixed_upstream("HTTP/1.1 403 Forbidden\r\nX-Backend: root", "").await;
    let b = spawn_fixed_upstream("HTTP/1.1 403 Forbidden\r\nX-Backend: chat", "").await;
    let root = temp_root("ws-longest");
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        false,
        None,
        None,
        |config| {
            let vhost = config
                .vhosts
                .get_mut(VHOST)
                .unwrap()
                .config
                .as_mut()
                .unwrap();
            let v = Arc::make_mut(vhost);
            for (uri, address) in [("/", a), ("/chat", b)] {
                v.websockets.push(hj_core::config::WebSocketMap {
                    uri: uri.into(),
                    address: address.to_string(),
                });
            }
        },
    );
    for (path, backend) in [("/chat/room", "chat"), ("/lobby", "root")] {
        let resp = run(&state, websocket_get(path)).await;
        assert_eq!(
            resp.headers().get("x-backend").map(|v| v.as_bytes()),
            Some(backend.as_bytes()),
            "{path}"
        );
    }
    std::fs::remove_dir_all(root).ok();
}

/// sub_filter and the context egress rate match the same decoded, dot-normalized path as
/// every other context matcher on the bridged pipeline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sub_filter_and_bandwidth_match_the_normalized_request_path() {
    let root = temp_root("subfilter-normalized");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/page.html"), b"<html>hello</html>").unwrap();
    let mut context = sub_filter_context("/sub", &[("hello", "goodbye")], false);
    context.bandwidth_limit = 1000;
    let state = build_state_with(root.clone(), vec![context], Vec::new());
    for path in [
        "/sub/page.html",
        "/%73ub/page.html",
        "/x/../sub/page.html",
        "//sub/page.html",
    ] {
        let resp = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(
            resp.extensions()
                .get::<super::PerConnBandwidth>()
                .map(|b| b.0),
            Some(1000),
            "{path}"
        );
        assert_eq!(
            body_bytes(resp.into_body()).as_ref(),
            b"<html>goodbye</html>",
            "{path}"
        );
    }
    std::fs::remove_dir_all(root).ok();
}

/// On-core memo hits and page-cache hits carry the context egress rate like every other
/// serve funnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_path_memo_and_cache_hits_keep_the_bandwidth_stamp() {
    let root = temp_root("bw-fast-hits");
    std::fs::create_dir_all(root.join("dl")).unwrap();
    std::fs::write(root.join("dl/big.txt"), vec![b'x'; 4096]).unwrap();
    let mut throttled = plain_context(ContextKind::Static, "/dl");
    throttled.bandwidth_limit = 250_000;
    let rate = |r: &Option<Response>| {
        r.as_ref()
            .and_then(|r| r.extensions().get::<super::PerConnBandwidth>().map(|b| b.0))
    };
    let state = build_state_with(root.clone(), vec![throttled.clone()], Vec::new());
    for i in 0..3 {
        let resp = fast_serve_get(&state, "/dl/big.txt").await;
        assert!(resp.is_some(), "iteration {i} served on-core");
        assert_eq!(rate(&resp), Some(250_000), "iteration {i}");
    }
    let mut cfg = hj_pagecache::StoreConfig::default();
    cfg.standard_cc_vhosts.push(VHOST.into());
    let store = Arc::new(hj_pagecache::PageStore::new(cfg));
    let state = build_state_full(
        root.clone(),
        vec![throttled],
        Vec::new(),
        Some(store.clone()),
        None,
    );
    seed_public_entry(&state, &store, "/dl/page", b"<h1>cached</h1>").await;
    let fast = fast_serve_get(&state, "/dl/page").await;
    assert!(is_cache_hit(fast.as_ref()));
    assert_eq!(rate(&fast), Some(250_000));
    std::fs::remove_dir_all(root).ok();
}

/// A 4xx/5xx `[R=]` renders the ErrorDocument (Apache `ap_die`); a 2xx stays bare.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_error_status_applies_error_document() {
    let root = temp_root("rewrite-status-errordoc");
    std::fs::write(
        root.join(".htaccess"),
        "ErrorDocument 404 \"custom404\"\nErrorDocument 503 \"custom503\"\n\
         RewriteEngine On\nRewriteRule ^gone$ - [R=404,L]\nRewriteRule ^busy$ - [R=503,L]\n\
         RewriteRule ^ok$ - [R=204,L]\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    for (path, status, body) in [
        ("/gone", 404, &b"custom404"[..]),
        ("/busy", 503, &b"custom503"[..]),
        ("/ok", 204, &b""[..]),
    ] {
        let resp = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(resp.status(), status, "{path}");
        assert_eq!(body_bytes(resp.into_body()).as_ref(), body, "{path}");
    }
    std::fs::remove_dir_all(root).ok();
}

async fn fast_serve_from(
    state: &Arc<ServerState>,
    peer: IpAddr,
    req: &Request,
) -> Option<Response> {
    fast_serve(
        state,
        LISTENER,
        peer,
        SocketAddr::from(([127, 0, 0, 1], 80)),
        40000,
        false,
        false,
        false,
        Proto::Http1,
        None,
        req,
    )
    .await
}

/// A symlinked target's own `.htaccess` denies by an env var the request
/// chain's SetEnvIf sets: the on-core path must judge it with that env, exactly
/// as dispatch() does, not before SetEnvIf has run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_judges_symlink_target_chain_after_set_env() {
    let root = temp_root("fast-target-env-deny");
    std::fs::create_dir(root.join("restricted")).unwrap();
    std::fs::create_dir(root.join("pub")).unwrap();
    std::fs::write(root.join("restricted/file.txt"), b"restricted bytes").unwrap();
    std::fs::write(
        root.join("restricted/.htaccess"),
        "Order Allow,Deny\nAllow from all\nDeny from env=bad_bot\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("restricted/file.txt"), root.join("pub/file.txt"))
        .unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "SetEnvIf User-Agent BadBot bad_bot\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let bad = get_with(CANON_HOST, "/pub/file.txt", &[("user-agent", "BadBot/1.0")]);
    let full = run(
        &state,
        get_with(CANON_HOST, "/pub/file.txt", &[("user-agent", "BadBot/1.0")]),
    )
    .await;
    assert_eq!(full.status(), http::StatusCode::FORBIDDEN);
    let fast = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &bad).await;
    assert!(fast.is_none(), "on-core path served what dispatch denies");
    let good = get_with(
        CANON_HOST,
        "/pub/file.txt",
        &[("user-agent", "Mozilla/5.0")],
    );
    let fast = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &good).await;
    assert_eq!(fast.map(|r| r.status()), Some(http::StatusCode::OK));
    std::fs::remove_dir_all(root).ok();
}

/// A target chain that denies by client IP is not a pure function of the memo
/// key: a response served to one client must not be replayed to a denied one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_memo_never_replays_a_target_chain_ip_deny() {
    let root = temp_root("fast-target-ip-deny");
    std::fs::create_dir(root.join("restricted")).unwrap();
    std::fs::create_dir(root.join("pub")).unwrap();
    std::fs::write(root.join("restricted/file.txt"), b"restricted bytes").unwrap();
    std::fs::write(
        root.join("restricted/.htaccess"),
        "Order Allow,Deny\nAllow from all\nDeny from 203.0.113.7\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("restricted/file.txt"), root.join("pub/file.txt"))
        .unwrap();
    std::fs::write(root.join(".htaccess"), "# root\n").unwrap();
    let state = build_state_htaccess(root.clone());
    let req = get(CANON_HOST, "/pub/file.txt", None);
    for _ in 0..2 {
        let served = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &req).await;
        assert_eq!(served.map(|r| r.status()), Some(http::StatusCode::OK));
    }
    let denied_peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    assert!(
        fast_serve_from(&state, denied_peer, &req).await.is_none(),
        "a memoized allow was replayed to a client the target chain denies"
    );
    std::fs::remove_dir_all(root).ok();
}

/// (#1023) A precompressed sibling the static handler substitutes may be a
/// symlink into a directory with its own `.htaccess`. That chain's revalidation
/// deadline bounds the memo entry exactly like the request chain's (#557): a
/// deny added there is honored once that chain is due for its recheck, not up
/// to a full memo TTL after the request chain was rechecked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_memo_expires_with_a_substituted_sibling_target_chain() {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    // The HtaccessCache revalidation window and the memo TTL.
    const WINDOW: Duration = Duration::from_secs(1);
    let identity = b"body{}".repeat(50);
    // Each attempt needs the serve to land inside a timing window; a loaded box
    // that misses it retries instead of failing.
    for _ in 0..3 {
        let root = temp_root("fast-sibling-target-deadline");
        std::fs::create_dir(root.join("restricted")).unwrap();
        std::fs::create_dir(root.join("pub")).unwrap();
        std::fs::write(root.join("pub/app.css"), &identity).unwrap();
        std::fs::write(root.join("restricted/app.css.br"), b"BRSIBLING").unwrap();
        std::fs::write(root.join("restricted/.htaccess"), "# restricted\n").unwrap();
        std::os::unix::fs::symlink(
            root.join("restricted/app.css.br"),
            root.join("pub/app.css.br"),
        )
        .unwrap();
        std::fs::write(root.join(".htaccess"), "# root\n").unwrap();
        let state = build_state_htaccess(root.clone());
        let req = || get_with(CANON_HOST, "/pub/app.css", &[("accept-encoding", "br")]);
        // Check the request chain first and the sibling's directory later, so the
        // serve below rechecks the request chain while the sibling's is still fresh.
        let (_, request_chain_until) = state.rewrite_cache.load_chain_with_dirs_and_deadline(
            &root,
            "/pub/app.css",
            ".htaccess",
        );
        tokio::time::sleep(Duration::from_millis(450)).await;
        let sibling_checked = Instant::now();
        state.rewrite_cache.load_chain_with_dirs_and_deadline(
            &root,
            "/restricted/app.css.br",
            ".htaccess",
        );
        let sibling_until = Instant::now() + WINDOW;
        tokio::time::sleep_until((request_chain_until + Duration::from_millis(20)).into()).await;
        let served_at = Instant::now();
        let served = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &req()).await;
        if Instant::now() >= sibling_checked + WINDOW {
            std::fs::remove_dir_all(&root).ok();
            continue;
        }
        let served = served.expect("the allowed sibling serves on-core");
        assert_eq!(
            served
                .headers()
                .get(header::CONTENT_ENCODING)
                .map(|v| v.as_bytes()),
            Some(&b"br"[..])
        );
        assert_eq!(body_bytes(served.into_body()).as_ref(), b"BRSIBLING");
        assert_eq!(state.metrics.fast_memo_stores.load(Ordering::Relaxed), 1);
        std::fs::write(root.join("restricted/.htaccess"), "Require all denied\n").unwrap();
        tokio::time::sleep_until((sibling_until + Duration::from_millis(50)).into()).await;
        let probed_at = Instant::now();
        let fresh = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &req())
            .await
            .expect("the identity primary serves on-core");
        let full = run(&state, req()).await;
        for resp in [fresh, full] {
            assert_eq!(resp.status(), 200);
            assert_ne!(
                resp.headers()
                    .get(header::CONTENT_ENCODING)
                    .map(|v| v.as_bytes()),
                Some(&b"br"[..]),
                "a memoized sibling outlived its own chain's revalidation deadline"
            );
            assert_eq!(identity_bytes(resp), identity);
        }
        std::fs::remove_dir_all(&root).ok();
        // Only a probe the request chain's deadline alone would still have
        // replayed past tells the two deadlines apart.
        if probed_at < served_at + WINDOW {
            return;
        }
    }
}

const CONTROL_HEADERS: [&str; 6] = [
    "x-litespeed-purge",
    "x-litespeed-cache-control",
    "x-litespeed-tag",
    "x-litespeed-vary",
    "x-wf-capsule",
    "x-wf-capsule-tags",
];

fn assert_no_control_headers(resp: &Response, what: &str) {
    for name in CONTROL_HEADERS {
        assert!(
            !resp.headers().contains_key(name),
            "{what}: internal cache header leaked: {name}"
        );
    }
}

/// (#897) `.htaccess` `Header set X-LiteSpeed-*` on a static file: the on-core
/// path must bridge (never serve or memoize the control headers), and the full
/// pipeline strips them and executes the purge, with or without a page cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_static_control_headers_bridge_and_full_pipeline_strips() {
    let root = temp_root("fast-static-control-headers");
    std::fs::write(root.join("sitemap.xml"), b"<urlset/>").unwrap();
    std::fs::write(root.join("plain.txt"), b"plain").unwrap();
    std::fs::write(root.join("tagged.txt"), b"tagged").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "<Files sitemap.xml>\n\
         Header set X-LiteSpeed-Cache-Control \"no-cache\"\n\
         Header set X-LiteSpeed-Tag \"sitemap\"\n\
         Header set X-LiteSpeed-Vary \"cookie=xf_style_id\"\n\
         Header set X-LiteSpeed-Purge \"*\"\n\
         </Files>\n\
         <Files tagged.txt>\n\
         Header set X-LiteSpeed-Cache-Control \"public, max-age=3600\"\n\
         </Files>\n",
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let cached = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |_| {},
    );
    let uncached = build_state_htaccess(root.clone());
    for state in [&cached, &uncached] {
        let req = get(CANON_HOST, "/sitemap.xml", None);
        for _ in 0..3 {
            assert!(
                fast_serve_from(state, IpAddr::V4(Ipv4Addr::LOCALHOST), &req)
                    .await
                    .is_none(),
                "on-core path served a response carrying control headers"
            );
        }
        let before = store.purge_epoch();
        let full = run(state, get(CANON_HOST, "/sitemap.xml", None)).await;
        assert_eq!(full.status(), http::StatusCode::OK);
        assert_no_control_headers(&full, "full pipeline static");
        assert_eq!(body_bytes(full.into_body()).as_ref(), b"<urlset/>");
        if Arc::ptr_eq(state, &cached) {
            assert!(
                store.purge_epoch() > before,
                "static Header set purge dropped"
            );
        }
        // Cache directives without a purge are stripped on-core (no bridge).
        let tagged = fast_serve_from(
            state,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &get(CANON_HOST, "/tagged.txt", None),
        )
        .await
        .expect("a tagged static file without a purge stays on-core");
        assert_eq!(tagged.status(), http::StatusCode::OK);
        assert_no_control_headers(&tagged, "on-core tagged static");
        // An unrelated file in the same tree stays on-core.
        let plain = fast_serve_from(
            state,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &get(CANON_HOST, "/plain.txt", None),
        )
        .await;
        assert_eq!(plain.map(|r| r.status()), Some(http::StatusCode::OK));
    }
    std::fs::remove_dir_all(root).ok();
}

/// (#898) A rewrite `[F]` 403 with `Header always set X-LiteSpeed-*` never
/// reaches `cache_store`: the generated error page must still execute the purge
/// and must never egress the control headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_error_page_executes_purge_and_strips_control_headers() {
    let root = temp_root("forbidden-control-headers");
    std::fs::write(
        root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^blocked$ - [F,L]\n\
         Header always set X-LiteSpeed-Purge \"*\"\n\
         Header always set X-LiteSpeed-Cache-Control \"public,max-age=60\"\n\
         Header always set X-LiteSpeed-Tag \"t1\"\n\
         Header always set X-WF-Capsule \"max-age=60\"\n",
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |_| {},
    );
    let before = store.purge_epoch();
    let resp = run(&state, get(CANON_HOST, "/blocked", None)).await;
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    assert_no_control_headers(&resp, "[F] 403");
    assert!(store.purge_epoch() > before, "[F] 403 purge dropped");

    let uncached = build_state_htaccess(root.clone());
    let resp = run(&uncached, get(CANON_HOST, "/blocked", None)).await;
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    assert_no_control_headers(&resp, "[F] 403 without page cache");
    std::fs::remove_dir_all(root).ok();
}

/// `[F]`/`[G]` keep the `[E=]` env set up to them, from their own rule and from
/// earlier rulesets: the error response's `Header always ... env=` sees it (OLS
/// expands env before the action).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_and_gone_keep_their_rewrite_env_for_header_ops() {
    let root = temp_root("forbidden-env-headers");
    std::fs::write(
        root.join(".htaccess"),
        "RewriteEngine On
         RewriteRule ^blocked$ - [F,E=BLOCKED:1]
         RewriteRule ^old$ - [G,E=RETIRED:1]
         Header always set X-Blocked yes env=BLOCKED
         Header always set X-Retired yes env=RETIRED
",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let resp = run(&state, get(CANON_HOST, "/blocked", None)).await;
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(resp.headers().get("x-blocked").unwrap(), "yes");
    let resp = run(&state, get(CANON_HOST, "/old", None)).await;
    assert_eq!(resp.status(), http::StatusCode::GONE);
    assert_eq!(resp.headers().get("x-retired").unwrap(), "yes");
    assert!(resp.headers().get("x-blocked").is_none());
    std::fs::remove_dir_all(root).ok();
}

/// The static handler may substitute a precompressed sibling the prediction
/// never judged; when that sibling is a symlink into a denied tree the on-core
/// path must bridge like dispatch()'s opened-target backstop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_checks_a_symlinked_precompressed_sibling() {
    let root = temp_root("fast-precomp-symlink");
    std::fs::create_dir(root.join("restricted")).unwrap();
    std::fs::create_dir(root.join("pub")).unwrap();
    std::fs::write(root.join("restricted/secret.txt.gz"), b"SECRET-GZ-BYTES").unwrap();
    std::fs::write(root.join("restricted/.htaccess"), "Require all denied\n").unwrap();
    std::fs::write(root.join("pub/file.txt"), b"public bytes").unwrap();
    std::os::unix::fs::symlink(
        root.join("restricted/secret.txt.gz"),
        root.join("pub/file.txt.gz"),
    )
    .unwrap();
    std::fs::write(root.join(".htaccess"), "# root\n").unwrap();
    let state = build_state_htaccess(root.clone());
    // (#941) Both paths refuse the sibling and fall back to the identity file.
    let gz = || get_with(CANON_HOST, "/pub/file.txt", &[("accept-encoding", "gzip")]);
    let slow = run(&state, gz()).await;
    let req = gz();
    let fast = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &req)
        .await
        .expect("identity primary serves on-core");
    for resp in [slow, fast] {
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(identity_bytes(resp), b"public bytes");
    }
    // The identity representation is still served on-core.
    let plain = fast_serve_get(&state, "/pub/file.txt").await;
    assert_eq!(plain.map(|r| r.status()), Some(http::StatusCode::OK));
    std::fs::remove_dir_all(root).ok();
}

/// `Header always` ops reach ErrorDocument replacements and every generated
/// 403/410, once each; `onsuccess` ops never do, even when an external
/// ErrorDocument turns the error into a 302 (Apache `ap_send_error_response`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_always_survives_error_documents_and_generated_errors() {
    let root = temp_root("header-always-errors");
    std::fs::create_dir(root.join("errors")).unwrap();
    std::fs::write(root.join("errors/404.html"), b"custom 404").unwrap();
    std::fs::write(root.join("ok.txt"), b"ok").unwrap();
    std::fs::write(root.join("secret.txt"), b"s").unwrap();
    std::fs::write(root.join("deny.txt"), b"d").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "Header always set X-Frame-Options DENY\n\
         Header always add X-Trial one\n\
         Header set X-Onsuccess yes\n\
         ErrorDocument 404 /errors/404.html\n\
         ErrorDocument 410 \"gone page\"\n\
         ErrorDocument 403 https://errors.example/denied\n\
         RewriteEngine On\n\
         RewriteRule ^secret - [F]\n\
         RewriteRule ^old - [G]\n\
         <Files \"deny.txt\">\nRequire all denied\n</Files>\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let trial_count = |r: &Response| r.headers().get_all("x-trial").iter().count();

    let ok = run(&state, get(CANON_HOST, "/ok.txt", None)).await;
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.headers()["x-frame-options"], "DENY");
    assert_eq!(ok.headers()["x-onsuccess"], "yes");
    assert_eq!(trial_count(&ok), 1);

    let missing = run(&state, get(CANON_HOST, "/missing", None)).await;
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.headers()["x-frame-options"], "DENY");
    assert_eq!(trial_count(&missing), 1);
    assert!(missing.headers().get("x-onsuccess").is_none());
    assert_eq!(body_bytes(missing.into_body()).as_ref(), b"custom 404");

    let gone = run(&state, get(CANON_HOST, "/old", None)).await;
    assert_eq!(gone.status(), 410);
    assert_eq!(gone.headers()["x-frame-options"], "DENY");
    assert_eq!(trial_count(&gone), 1);

    for path in ["/secret.txt", "/deny.txt"] {
        let denied = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(denied.status(), 302, "{path}");
        assert_eq!(
            denied.headers()[header::LOCATION],
            "https://errors.example/denied"
        );
        assert_eq!(denied.headers()["x-frame-options"], "DENY", "{path}");
        assert_eq!(trial_count(&denied), 1, "{path}");
        assert!(denied.headers().get("x-onsuccess").is_none(), "{path}");
    }
    std::fs::remove_dir_all(root).ok();
}

/// HEAD on a sub_filter path advertises the filtered GET's length and no
/// validator the GET representation does not carry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sub_filter_head_matches_get_framing() {
    let doc_root = temp_root("subfilter-head");
    std::fs::write(
        doc_root.join("page.html"),
        b"<html>hello world hello</html>",
    )
    .unwrap();
    let state = build_state_with(
        doc_root.clone(),
        vec![sub_filter_context("/", &[("hello", "goodbye")], false)],
        Vec::new(),
    );
    let g = run(&state, get(CANON_HOST, "/page.html", None)).await;
    let mut h = get(CANON_HOST, "/page.html", None);
    *h.method_mut() = http::Method::HEAD;
    let h = run(&state, h).await;
    assert_eq!(h.status(), 200);
    assert_eq!(
        g.headers().get(header::CONTENT_LENGTH),
        h.headers().get(header::CONTENT_LENGTH)
    );
    assert_eq!(g.headers()[header::CONTENT_LENGTH], "34");
    assert!(h.headers().get(header::ETAG).is_none());
    assert!(g.headers().get(header::ETAG).is_none());
    std::fs::remove_dir_all(doc_root).ok();
}

fn mtls_required_state(root: PathBuf) -> Arc<ServerState> {
    build_state_inner(root, Vec::new(), Vec::new(), true, None, None, |server| {
        server.listeners.push(Listener {
            name: "mtls".into(),
            address: "127.0.0.1:0".into(),
            secure: true,
            proxy_protocol: false,
            proxy_protocol_peers: vec![],
            uds_path: None,
            vhost_map: vec![VhostMap {
                vhost: VHOST.into(),
                domains: vec![CANON_HOST.into()],
            }],
            tls: Some(hj_core::config::ListenerTls {
                key_file: PathBuf::new(),
                cert_file: PathBuf::new(),
                cert_chain: false,
                ca_cert_file: None,
                client_verify: 2,
                verify_depth: 1,
                enable_stapling: false,
                crl_file: None,
            }),
        });
    })
}

/// A direct (non-internal) cleartext :80 request.
async fn run_direct_plaintext(state: &Arc<ServerState>, path: &str) -> Response {
    handle(
        state.clone(),
        LISTENER,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        SocketAddr::from(([127, 0, 0, 1], 80)),
        40000,
        false,
        false,
        false,
        None,
        Proto::Http1,
        None,
        get(CANON_HOST, path, None),
    )
    .await
}

/// The cleartext ACME http-01 exemption on an mTLS-required vhost serves only a
/// static token file: a missing token never reaches the front controller, the
/// path's own deny still applies, and every other path is still redirected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acme_plaintext_exemption_serves_only_static_token_files() {
    const TOKEN: &str = "/.well-known/acme-challenge/tok-123_A";
    let setup = |tag: &str, deny: bool| {
        let root = temp_root(tag);
        std::fs::create_dir_all(root.join(".well-known/acme-challenge")).unwrap();
        std::fs::write(root.join(TOKEN.trim_start_matches('/')), b"token-bytes").unwrap();
        std::fs::write(root.join("index.html"), b"front controller").unwrap();
        std::fs::write(
            root.join(".htaccess"),
            "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ index.html [L]\n",
        )
        .unwrap();
        if deny {
            std::fs::write(root.join(".well-known/.htaccess"), "Require all denied\n").unwrap();
        }
        root
    };
    let root = setup("acme-plaintext", false);
    let state = mtls_required_state(root.clone());
    assert!(state.mtls_required_vhosts.contains(VHOST));
    let token = run_direct_plaintext(&state, TOKEN).await;
    assert_eq!(token.status(), 200);
    assert_eq!(body_bytes(token.into_body()).as_ref(), b"token-bytes");
    let missing = run_direct_plaintext(&state, "/.well-known/acme-challenge/absent").await;
    assert_eq!(missing.status(), 404, "a missing token reached the rewrite");
    let other = run_direct_plaintext(&state, "/index.html").await;
    assert_eq!(other.status(), 301);
    std::fs::remove_dir_all(root).ok();

    let root = setup("acme-plaintext-deny", true);
    let state = mtls_required_state(root.clone());
    let denied = run_direct_plaintext(&state, TOKEN).await;
    assert_eq!(denied.status(), 403, "the exemption must not bypass a deny");
    std::fs::remove_dir_all(root).ok();
}

/// #747 follow-up: the target chain must also see the rewrite's `[E=]` env.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_judges_symlink_target_chain_after_rewrite_env() {
    let root = temp_root("fast-target-rewrite-env-deny");
    std::fs::create_dir(root.join("restricted")).unwrap();
    std::fs::create_dir(root.join("pub")).unwrap();
    std::fs::write(root.join("restricted/file.txt"), b"restricted bytes").unwrap();
    std::fs::write(
        root.join("restricted/.htaccess"),
        "Order Allow,Deny\nAllow from all\nDeny from env=bad_bot\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("restricted/file.txt"), root.join("pub/file.txt"))
        .unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^pub/ - [E=bad_bot:1]\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let full = run(&state, get(CANON_HOST, "/pub/file.txt", None)).await;
    assert_eq!(full.status(), http::StatusCode::FORBIDDEN);
    let fast = fast_serve_from(
        &state,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &get(CANON_HOST, "/pub/file.txt", None),
    )
    .await;
    assert!(fast.is_none(), "on-core path served what dispatch denies");
    std::fs::remove_dir_all(root).ok();
}

fn head_with(path: &str, headers: &[(&str, &str)]) -> Request {
    let mut req = get_with(CANON_HOST, path, headers);
    *req.method_mut() = http::Method::HEAD;
    req
}

fn encoding_headers(resp: &Response) -> [Option<String>; 5] {
    [
        header::CONTENT_ENCODING,
        header::ETAG,
        header::VARY,
        header::ACCEPT_RANGES,
        header::CONTENT_LENGTH,
    ]
    .map(|name| {
        resp.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    })
}

/// (#774) A conditional GET that matched a dynamically gzipped file's `;gz`
/// tag answers 304 with that tag and the 200's `Vary`, on both serve paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compressed_static_304_echoes_variant_etag_and_vary() {
    let root = temp_root("gz-304");
    std::fs::write(root.join("a.txt"), b"x".repeat(6000)).unwrap();
    let state = build_state(root.clone());
    let ae = ("accept-encoding", "gzip");
    let ok = run(&state, get_with(CANON_HOST, "/a.txt", &[ae])).await;
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.headers()[header::CONTENT_ENCODING], "gzip");
    let tag = ok.headers()[header::ETAG].to_str().unwrap().to_string();
    assert!(tag.ends_with(";gz\""), "{tag}");

    let cond = || get_with(CANON_HOST, "/a.txt", &[ae, ("if-none-match", tag.as_str())]);
    let bridged = run(&state, cond()).await;
    let req = cond();
    let fast = fast_serve_req(&state, &req).await.expect("on-core 304");
    for resp in [&bridged, &fast] {
        assert_eq!(resp.status(), 304);
        assert_eq!(resp.headers()[header::ETAG], tag.as_str());
        assert_eq!(resp.headers()[header::VARY], "Accept-Encoding");
    }

    // A client holding the identity copy keeps its own validator and no Vary.
    let base = format!("{};;;\"", tag.strip_suffix(";gz\"").unwrap());
    let plain = run(
        &state,
        get_with(CANON_HOST, "/a.txt", &[("if-none-match", base.as_str())]),
    )
    .await;
    assert_eq!(plain.status(), 304);
    assert_eq!(plain.headers()[header::ETAG], base.as_str());
    assert!(plain.headers().get(header::VARY).is_none());
    std::fs::remove_dir_all(root).ok();
}

/// (#775) HEAD on a compressible static file advertises the encoded GET's
/// headers (no identity length, no Accept-Ranges), identically on both paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compressible_static_head_matches_get_headers() {
    let root = temp_root("gz-head");
    std::fs::write(root.join("a.txt"), b"x".repeat(6000)).unwrap();
    std::fs::write(root.join("small.txt"), b"tiny").unwrap();
    let state = build_state(root.clone());
    let ae = ("accept-encoding", "gzip");
    let get = run(&state, get_with(CANON_HOST, "/a.txt", &[ae])).await;
    let head = run(&state, head_with("/a.txt", &[ae])).await;
    let req = head_with("/a.txt", &[ae]);
    let fast = fast_serve_req(&state, &req).await.expect("on-core HEAD");
    assert_eq!(head.status(), 200);
    assert!(matches!(head.body(), Body::Empty));
    let [ce, etag, vary, ranges, len] = encoding_headers(&head);
    assert_eq!(ce.as_deref(), Some("gzip"));
    assert_eq!(
        etag,
        get.headers()
            .get(header::ETAG)
            .map(|v| v.to_str().unwrap().to_string())
    );
    assert_eq!(vary.as_deref(), Some("Accept-Encoding"));
    assert_eq!(ranges, None);
    assert_eq!(len, None);
    assert_eq!(encoding_headers(&fast), encoding_headers(&head));

    // No shared codec, or below the minimum size: identity headers, like GET.
    for (path, headers) in [("/a.txt", &[][..]), ("/small.txt", &[ae][..])] {
        let get = run(&state, get_with(CANON_HOST, path, headers)).await;
        let head = run(&state, head_with(path, headers)).await;
        assert!(head.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(encoding_headers(&head), encoding_headers(&get), "{path}");
    }
    std::fs::remove_dir_all(root).ok();
}

/// Regression (#1020): OLS/LSWS honour the `no-gzip` env (`[E=no-gzip:1]`,
/// `SetEnvIf… no-gzip`; `0` or `!no-gzip` re-enables): the GET, its HEAD and
/// 304, and a precompressed sibling all stay identity, on both serve paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_gzip_env_serves_identity() {
    let root = temp_root("no-gzip");
    let body = b"x".repeat(6000);
    for name in [
        "page.txt", "nogz.txt", "zero.txt", "keep.txt", "data.csv", "sib.txt",
    ] {
        std::fs::write(root.join(name), &body).unwrap();
    }
    std::fs::write(root.join("sib.txt.gz"), b"\x1f\x8b-precompressed-sibling").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "SetEnvIfNoCase Request_URI \\.CSV$ no-gzip\n\
         SetEnvIf Request_URI ^/keep\\.txt$ no-gzip\n\
         RewriteEngine On\n\
         RewriteRule ^/?(nogz|sib)\\.txt$ - [E=no-gzip:1]\n\
         RewriteRule ^/?zero\\.txt$ - [E=no-gzip:0]\n\
         RewriteRule ^/?keep\\.txt$ - [E=!no-gzip]\n",
    )
    .unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |server| {
            server
                .mime
                .by_suffix
                .insert("csv".to_string(), "text/csv".to_string());
        },
    );
    let ae = ("accept-encoding", "gzip");
    for (path, encoded) in [
        ("/page.txt", true),
        ("/nogz.txt", false),
        ("/data.csv", false),
        ("/sib.txt", false),
        ("/zero.txt", true),
        ("/keep.txt", true),
    ] {
        let slow = run(&state, get_with(CANON_HOST, path, &[ae])).await;
        let req = get_with(CANON_HOST, path, &[ae]);
        let fast = fast_serve_req(&state, &req).await.expect("served on-core");
        for resp in [slow, fast] {
            assert_eq!(resp.status(), 200, "{path}");
            assert_eq!(
                resp.headers().contains_key(header::CONTENT_ENCODING),
                encoded,
                "{path}"
            );
            if !encoded {
                assert!(resp.headers().get(header::VARY).is_none(), "{path}");
                assert_eq!(body_bytes(resp.into_body()), body, "{path}");
            }
        }
    }

    let head = run(&state, head_with("/nogz.txt", &[ae])).await;
    let [ce, etag, vary, _, len] = encoding_headers(&head);
    assert_eq!((ce, vary), (None, None));
    assert_eq!(len.as_deref(), Some("6000"));
    let req = head_with("/nogz.txt", &[ae]);
    let fast = fast_serve_req(&state, &req).await.expect("on-core HEAD");
    assert_eq!(encoding_headers(&fast), encoding_headers(&head));

    let etag = etag.expect("identity ETag");
    let cond = || {
        get_with(
            CANON_HOST,
            "/nogz.txt",
            &[ae, ("if-none-match", etag.as_str())],
        )
    };
    let slow = run(&state, cond()).await;
    let req = cond();
    let fast = fast_serve_req(&state, &req).await.expect("on-core 304");
    for resp in [slow, fast] {
        assert_eq!(resp.status(), 304);
        assert!(resp.headers().get(header::VARY).is_none());
    }
    std::fs::remove_dir_all(root).ok();
}

/// (#784) A Range on a sub_filter path is served as the full filtered 200:
/// the raw source bytes the filter replaces never leave as a 206, and the
/// filtered entity advertises no byte ranges.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sub_filter_range_serves_full_filtered_entity() {
    let doc_root = temp_root("subfilter-range");
    std::fs::write(
        doc_root.join("page.html"),
        b"<html>SECRET-TOKEN world</html>",
    )
    .unwrap();
    let state = build_state_with(
        doc_root.clone(),
        vec![sub_filter_context(
            "/",
            &[("SECRET-TOKEN", "redacted")],
            false,
        )],
        Vec::new(),
    );
    for headers in [
        &[("range", "bytes=6-17")][..],
        &[("range", "bytes=6-17"), ("if-range", "\"anything\"")][..],
        &[][..],
    ] {
        let resp = run(&state, get_with(CANON_HOST, "/page.html", headers)).await;
        assert_eq!(resp.status(), 200, "{headers:?}");
        assert!(resp.headers().get(header::CONTENT_RANGE).is_none());
        assert!(resp.headers().get(header::ACCEPT_RANGES).is_none());
        assert_eq!(
            body_bytes(resp.into_body()).as_ref(),
            b"<html>redacted world</html>"
        );
    }
    std::fs::remove_dir_all(doc_root).ok();
}

/// (#784) A precompressed sibling would bypass sub_filter; filtered paths
/// always select the identity file (then compress the filtered body).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sub_filter_ignores_precompressed_sibling() {
    let doc_root = temp_root("subfilter-sibling");
    let page = format!("<html>SECRET-TOKEN {}</html>", "a".repeat(400));
    std::fs::write(doc_root.join("page.html"), page.as_bytes()).unwrap();
    std::fs::write(
        doc_root.join("page.html.gz"),
        hj_compress::encode_bytes(
            hj_compress::Encoding::Gzip,
            page.as_bytes(),
            &hj_compress::Levels::default(),
        )
        .unwrap(),
    )
    .unwrap();
    let state = build_state_with(
        doc_root.clone(),
        vec![sub_filter_context(
            "/",
            &[("SECRET-TOKEN", "redacted")],
            false,
        )],
        Vec::new(),
    );
    let gz = || get_with(CANON_HOST, "/page.html", &[("accept-encoding", "gzip")]);
    let bridged = run(&state, gz()).await;
    let req = gz();
    let fast = fast_serve_req(&state, &req).await;
    for resp in std::iter::once(bridged).chain(fast) {
        assert_eq!(resp.status(), 200);
        let encoded = resp.headers().get(header::CONTENT_ENCODING).cloned();
        let body = body_bytes(resp.into_body());
        let plain = match encoded {
            Some(_) => hj_compress::decode_bytes(hj_compress::Encoding::Gzip, &body).unwrap(),
            None => body.to_vec(),
        };
        let plain = String::from_utf8(plain).unwrap();
        assert!(plain.contains("redacted"), "{plain}");
        assert!(!plain.contains("SECRET-TOKEN"));
    }
    std::fs::remove_dir_all(doc_root).ok();
}

/// (#785) A Basic-auth 401 gets `Header always` ops once and the local
/// ErrorDocument body, keeping the challenge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_refusals_get_header_always_and_error_document() {
    let root = temp_root("auth-always");
    std::fs::create_dir_all(root.join("private")).unwrap();
    std::fs::write(root.join("private/secret.txt"), b"secret").unwrap();
    std::fs::create_dir(root.join("errors")).unwrap();
    std::fs::write(root.join("errors/401.html"), b"custom 401").unwrap();
    std::fs::write(
        root.join("users"),
        "Admin:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "Header always add X-Trial one\nHeader set X-Onsuccess yes\n\
         ErrorDocument 401 /errors/401.html\n",
    )
    .unwrap();
    std::fs::write(
        root.join("private/.htaccess"),
        format!(
            "AuthType Basic\nAuthName \"p\"\nAuthUserFile {}/users\nRequire valid-user\n",
            root.display()
        ),
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let resp = run(&state, get(CANON_HOST, "/private/secret.txt", None)).await;
    assert_eq!(resp.status(), 401);
    assert_eq!(resp.headers().get_all("x-trial").iter().count(), 1);
    assert!(resp.headers().get("x-onsuccess").is_none());
    assert!(
        resp.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .starts_with("Basic ")
    );
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"custom 401");
    std::fs::remove_dir_all(root).ok();
}

/// (#785) An external ErrorDocument cannot carry a challenge, so a 401 stays
/// a 401 (Apache ignores a URL there) while still getting `Header always`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_challenge_ignores_external_error_document() {
    let root = temp_root("auth-external");
    std::fs::create_dir_all(root.join("private")).unwrap();
    std::fs::write(root.join("private/secret.txt"), b"secret").unwrap();
    std::fs::write(
        root.join("users"),
        "Admin:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "Header always add X-Trial one\nErrorDocument 401 https://errors.example/login\n",
    )
    .unwrap();
    std::fs::write(
        root.join("private/.htaccess"),
        format!(
            "AuthType Basic\nAuthName \"p\"\nAuthUserFile {}/users\nRequire valid-user\n",
            root.display()
        ),
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let resp = run(&state, get(CANON_HOST, "/private/secret.txt", None)).await;
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().get(header::LOCATION).is_none());
    assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_some());
    assert_eq!(resp.headers().get_all("x-trial").iter().count(), 1);
    std::fs::remove_dir_all(root).ok();
}

/// (#789) HEAD ignores Range, so it still describes the GET's precompressed sibling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn head_with_range_still_describes_the_precompressed_sibling() {
    let root = temp_root("head-range-sibling");
    std::fs::write(root.join("a.txt"), b"x".repeat(6000)).unwrap();
    std::fs::write(
        root.join("a.txt.gz"),
        b"\x1f\x8b-not-really-gzip-but-a-sibling",
    )
    .unwrap();
    let state = build_state(root.clone());
    let ae = ("accept-encoding", "gzip");
    let get = run(&state, get_with(CANON_HOST, "/a.txt", &[ae])).await;
    let head = run(&state, head_with("/a.txt", &[ae, ("range", "bytes=0-9")])).await;
    assert_eq!(head.status(), 200);
    assert_eq!(encoding_headers(&head), encoding_headers(&get));
    std::fs::remove_dir_all(root).ok();
}

/// (#788) A sub_filter GET above the static cap is still buffered (and so
/// compressed) by the filter; its HEAD must advertise the same encoding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sub_filter_head_above_static_cap_matches_get_encoding() {
    let root = temp_root("subfilter-head-cap");
    let mut page = b"<html>SECRET ".to_vec();
    page.extend(std::iter::repeat_n(b'x', 5 * 1024 * 1024));
    page.extend_from_slice(b"</html>");
    std::fs::write(root.join("page.html"), &page).unwrap();
    let mut ctx = sub_filter_context("/", &[("SECRET", "public")], false);
    if let Some(sf) = ctx.sub_filter.as_mut() {
        sf.max_body = 8 * 1024 * 1024;
    }
    let state = build_state_with(root.clone(), vec![ctx], Vec::new());
    assert!(
        (page.len() as u64) > state.static_cache.config().max_static_obj_bytes,
        "fixture must exceed the static object cap"
    );
    let ae = ("accept-encoding", "gzip");
    let get = run(&state, get_with(CANON_HOST, "/page.html", &[ae])).await;
    let head = run(&state, head_with("/page.html", &[ae])).await;
    assert_eq!(
        get.headers()
            .get(header::CONTENT_ENCODING)
            .map(|v| v.as_bytes()),
        Some(&b"gzip"[..])
    );
    let [ce, _, vary, ranges, _] = encoding_headers(&head);
    let [gce, _, gvary, granges, _] = encoding_headers(&get);
    assert_eq!((ce, vary, ranges), (gce, gvary, granges));
    std::fs::remove_dir_all(root).ok();
}

fn no_symlinks(cfg: &mut ServerConfig) {
    let decl = cfg.vhosts.get_mut(VHOST).unwrap();
    decl.allow_symbol_link = Some(false);
    if let Some(vhost) = decl.config.as_mut() {
        Arc::make_mut(vhost).allow_symbol_link = false;
    }
}

/// (#795) Without symlinks the on-core path still judges the file it opens:
/// a DirectoryIndex or a precompressed sibling denied by its own `<Files>`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_judges_index_and_sibling_without_symlinks() {
    let root = temp_root("fast-nosym-target");
    std::fs::create_dir(root.join("dir")).unwrap();
    std::fs::write(root.join("dir/index.html"), b"SECRET INDEX").unwrap();
    std::fs::write(
        root.join("dir/.htaccess"),
        "<Files \"index.html\">\nRequire all denied\n</Files>\n",
    )
    .unwrap();
    std::fs::write(root.join("page.txt"), b"x".repeat(100)).unwrap();
    std::fs::write(root.join("page.txt.gz"), b"GZSECRET").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "<FilesMatch \"\\.gz$\">\nRequire all denied\n</FilesMatch>\n",
    )
    .unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        no_symlinks,
    );
    assert_eq!(
        run(&state, get_with(CANON_HOST, "/dir/", &[]))
            .await
            .status(),
        403
    );
    assert!(
        fast_serve_get(&state, "/dir/").await.is_none(),
        "index served on-core"
    );
    // (#941) The denied sibling never reaches the client; the allowed primary is
    // served instead, identically on both paths.
    let gz = get_with(CANON_HOST, "/page.txt", &[("accept-encoding", "gzip")]);
    let slow = run(&state, gz).await;
    let gz = get_with(CANON_HOST, "/page.txt", &[("accept-encoding", "gzip")]);
    let fast = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &gz)
        .await
        .expect("allowed primary serves on-core");
    for resp in [slow, fast] {
        assert_eq!(resp.status(), 200);
        assert_eq!(identity_bytes(resp), b"x".repeat(100));
    }
    let plain = fast_serve_get(&state, "/page.txt").await;
    assert_eq!(plain.map(|r| r.status()), Some(http::StatusCode::OK));
    std::fs::remove_dir_all(root).ok();
}

/// (#986) A cookieless directory-index cache hit judges the index script the target
/// policy already opened: one symlinked into an accessDenyDir tree still bridges
/// (dispatch renders the 403), while an allowed one serves the hit on-core.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_dir_index_hit_judges_the_opened_index_script() {
    use std::os::unix::fs::symlink;
    for denied in [true, false] {
        let root = temp_root("fast-index-script");
        let elsewhere = temp_root("fast-index-script-target");
        std::fs::write(elsewhere.join("index.php"), b"<?php echo 'x';").unwrap();
        symlink(elsewhere.join("index.php"), root.join("index.php")).unwrap();
        std::fs::write(root.join(".htaccess"), "DirectoryIndex index.php\n").unwrap();
        let deny = if denied {
            vec![format!("{}/*", elsewhere.display())]
        } else {
            Vec::new()
        };
        let mut cfg = hj_pagecache::StoreConfig::default();
        cfg.standard_cc_vhosts.push(VHOST.into());
        let store = Arc::new(hj_pagecache::PageStore::new(cfg));
        let state = build_state_full(root.clone(), Vec::new(), deny, Some(store.clone()), None);
        seed_public_entry(&state, &store, "/", b"cached index").await;
        let fast = fast_serve_get(&state, "/").await;
        if denied {
            assert!(fast.is_none(), "a denied index script must bridge");
            assert_eq!(run(&state, get(CANON_HOST, "/", None)).await.status(), 403);
        } else {
            assert!(is_cache_hit(fast.as_ref()), "the allowed index hit serves");
        }
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(elsewhere).ok();
    }
}

/// The served entity with any dynamic gzip undone.
fn identity_bytes(resp: Response) -> Vec<u8> {
    let gzip = resp
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v == "gzip");
    let bytes = body_bytes(resp.into_body());
    if !gzip {
        return bytes.to_vec();
    }
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&bytes[..]), &mut out).unwrap();
    out
}

/// (#941) A sibling denied by its own `<FilesMatch>` (br and gzip) falls back to the
/// identity primary on both paths, while a denied PRIMARY still refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_precompressed_sibling_falls_back_to_identity() {
    let root = temp_root("sibling-fallback");
    std::fs::write(root.join("style.css"), b"body{}".repeat(50)).unwrap();
    std::fs::write(root.join("style.css.gz"), b"GZSECRET").unwrap();
    std::fs::write(root.join("style.css.br"), b"BRSECRET").unwrap();
    std::fs::write(root.join("secret.css"), b"PRIMARY SECRET").unwrap();
    std::fs::write(root.join("secret.css.gz"), b"GZSECRET").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "<FilesMatch \"\\.(gz|br|sql)$\">\nRequire all denied\n</FilesMatch>\n\
         <Files \"secret.css\">\nRequire all denied\n</Files>\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    for ae in ["gzip", "br", "br, gzip"] {
        let req = || get_with(CANON_HOST, "/style.css", &[("accept-encoding", ae)]);
        let slow = run(&state, req()).await;
        let fast = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &req())
            .await
            .expect("allowed primary serves on-core");
        for resp in [slow, fast] {
            assert_eq!(resp.status(), 200, "AE {ae}");
            assert_ne!(
                resp.headers()
                    .get(header::CONTENT_ENCODING)
                    .map(|v| v.as_bytes()),
                Some(&b"br"[..]),
                "AE {ae}: the denied .br sibling was served"
            );
            assert_eq!(identity_bytes(resp), b"body{}".repeat(50), "AE {ae}");
        }
    }
    let req = || get_with(CANON_HOST, "/secret.css", &[("accept-encoding", "gzip")]);
    assert_eq!(run(&state, req()).await.status(), 403);
    assert!(
        fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &req())
            .await
            .is_none_or(|r| r.status() == 403)
    );
    std::fs::remove_dir_all(root).ok();
}

// ─── #796 / #797: page-cache hits negotiate exactly like the compress transform ───

const PC_BODY_REPEAT: usize = 400;

/// An upstream answering every request with a cacheable `text/html` page. `/nt*`
/// adds `Cache-Control: no-transform`; `/tagged*` carries a LiteSpeed-shape strong ETag.
async fn cacheable_html_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0_u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            let line = String::from_utf8_lossy(&head);
            let path = line.split(' ').nth(1).unwrap_or("/").to_string();
            let mut extra = String::new();
            if path.starts_with("/nt") {
                extra.push_str("Cache-Control: public, no-transform\r\n");
            }
            if path.starts_with("/tagged") {
                extra.push_str("ETag: \"1-2-3;;;\"\r\n");
            }
            let body = "<p>cacheable page body</p>".repeat(PC_BODY_REPEAT);
            let reply = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 {extra}Content-Length: {}\r\n\
                 X-LiteSpeed-Cache-Control: public,max-age=60\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    (address, task)
}

fn page_cache_proxy_state(
    tag: &str,
    address: SocketAddr,
    tweak: impl FnOnce(&mut ServerConfig),
) -> (Arc<ServerState>, PathBuf) {
    let root = temp_root(tag);
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "CacheLookup public on\n\
             RewriteEngine On\n\
             RewriteRule ^/?(.*)$ http://{address}/$1 [P,L]\n\
             Header set X-LiteSpeed-Cache-Control public,max-age=60\n"
        ),
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(store),
        None,
        |server| {
            register_upstream(server, address);
            tweak(server);
        },
    );
    (state, root)
}

fn variant_serves(state: &ServerState) -> u64 {
    state
        .metrics
        .pagecache_variant_serves
        .iter()
        .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        .sum()
}

/// GET `path` until a hit is served from a stored variant (the first hit only
/// spawns the background fill), returning every response seen on the way.
async fn get_until_variant_hit(
    state: &Arc<ServerState>,
    path: &str,
    headers: &[(&str, &str)],
) -> Vec<Response> {
    let mut seen = Vec::new();
    for _ in 0..200 {
        let before = variant_serves(state);
        let resp = run(state, get_with(CANON_HOST, path, headers)).await;
        let hit = resp
            .headers()
            .get("x-litespeed-cache")
            .is_some_and(|v| v == "hit");
        seen.push(resp);
        if hit && variant_serves(state) > before {
            return seen;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no variant hit for {path}");
}

/// #796: with brotli disabled a `br, gzip` client is never handed br from a cache
/// hit (the variant fill stores gzip, the transform's choice), and a
/// `no-transform` page is identity on every hit and never gets a variant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_cache_hits_honor_disabled_codecs_and_no_transform() {
    let (address, upstream) = cacheable_html_upstream().await;
    let (state, root) = page_cache_proxy_state("pc-no-br", address, |server| {
        server.tuning.enable_brotli = false;
    });
    let ae = [("accept-encoding", "br, gzip")];
    let seen = get_until_variant_hit(&state, "/page", &ae).await;
    for resp in &seen {
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "gzip");
    }
    for _ in 0..3 {
        let resp = run(&state, get_with(CANON_HOST, "/page", &ae)).await;
        assert_eq!(resp.headers()["x-litespeed-cache"], "hit");
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "gzip");
    }

    let before = variant_serves(&state);
    for _ in 0..6 {
        let resp = run(&state, get_with(CANON_HOST, "/nt", &ae)).await;
        assert_eq!(resp.status(), 200);
        assert!(
            resp.headers().get(header::CONTENT_ENCODING).is_none(),
            "no-transform page was encoded"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let resp = run(&state, get_with(CANON_HOST, "/nt", &ae)).await;
    assert_eq!(resp.headers()["x-litespeed-cache"], "hit");
    assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
    assert_eq!(variant_serves(&state), before, "no-transform got a variant");
    upstream.abort();
    std::fs::remove_dir_all(root).ok();
}

/// #796: compression switched off entirely ⇒ hits are identity and no fill runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_cache_hits_stay_identity_when_compression_is_disabled() {
    let (address, upstream) = cacheable_html_upstream().await;
    let (state, root) = page_cache_proxy_state("pc-no-compress", address, |server| {
        server.tuning.enable_brotli = false;
        server.tuning.enable_gzip = false;
        server.tuning.enable_zstd = false;
    });
    let ae = [("accept-encoding", "zstd, br, gzip")];
    for _ in 0..6 {
        let resp = run(&state, get_with(CANON_HOST, "/page", &ae)).await;
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(variant_serves(&state), 0);
    upstream.abort();
    std::fs::remove_dir_all(root).ok();
}

/// Regression (#1020): a `no-gzip` request is served identity from a cache hit,
/// even when the entry holds a variant its Accept-Encoding takes, and its HEAD
/// and 304 follow; it never spawns a variant fill of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_cache_hits_honor_no_gzip_env() {
    let (address, upstream) = cacheable_html_upstream().await;
    let (mut state, root) = page_cache_proxy_state("pc-no-gzip", address, |_| {});
    // Prod's zstd egress: every fill also computes zstd, whatever the hitter accepts.
    let compress = hj_compress::Compress::from_tuning(&state.server.tuning).with_cf_send_zstd(true);
    Arc::get_mut(&mut state).expect("sole owner").compress = Arc::new(compress);
    let gz = [("accept-encoding", "gzip")];
    let seen = get_until_variant_hit(&state, "/page", &gz).await;
    assert_eq!(
        seen.last().unwrap().headers()[header::CONTENT_ENCODING],
        "gzip"
    );

    // The rule lands while the variant entry is cached; SetEnvIf is not a key input.
    let htaccess = root.join(".htaccess");
    let rules = std::fs::read_to_string(&htaccess).unwrap();
    std::fs::write(
        &htaccess,
        format!("SetEnvIfNoCase Request_URI ^/(page|fresh)$ no-gzip\n{rules}"),
    )
    .unwrap();
    let mut honored = None;
    for _ in 0..300 {
        let resp = run(&state, get_with(CANON_HOST, "/page", &gz)).await;
        if resp.headers().get(header::CONTENT_ENCODING).is_none() {
            honored = Some(resp);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let resp = honored.expect("the no-gzip rule took effect");
    assert_eq!(resp.headers()["x-litespeed-cache"], "hit");
    assert!(resp.headers().get(header::VARY).is_none());
    let identity = "<p>cacheable page body</p>".repeat(PC_BODY_REPEAT);
    assert_eq!(body_bytes(resp.into_body()), identity.as_bytes());

    let before = variant_serves(&state);
    let head = run(&state, head_req("/page", &gz)).await;
    assert_eq!(head.headers()["x-litespeed-cache"], "hit");
    assert!(head.headers().get(header::CONTENT_ENCODING).is_none());
    assert_eq!(
        head.headers().get(header::CONTENT_LENGTH).unwrap(),
        identity.len().to_string().as_str()
    );
    let tag = head.headers()[header::ETAG].to_str().unwrap().to_string();
    let cond = run(
        &state,
        get_with(
            CANON_HOST,
            "/page",
            &[gz[0], ("if-none-match", tag.as_str())],
        ),
    )
    .await;
    assert_eq!(cond.status(), 304);
    assert!(cond.headers().get(header::VARY).is_none());

    let fills = || -> u64 {
        state
            .metrics
            .pagecache_variant_fills
            .iter()
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            .sum()
    };
    let fills_before = fills();
    for _ in 0..6 {
        let resp = run(&state, get_with(CANON_HOST, "/fresh", &gz)).await;
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let resp = run(&state, get_with(CANON_HOST, "/fresh", &gz)).await;
    assert_eq!(resp.headers()["x-litespeed-cache"], "hit");
    assert_eq!(
        variant_serves(&state),
        before,
        "a no-gzip request got a variant"
    );
    assert_eq!(fills(), fills_before, "a no-gzip hit filled a variant");
    upstream.abort();
    std::fs::remove_dir_all(root).ok();
}

fn head_req(path: &str, headers: &[(&str, &str)]) -> Request {
    let mut req = get_with(CANON_HOST, path, headers);
    *req.method_mut() = http::Method::HEAD;
    req
}

fn pc_encoding_headers(resp: &Response) -> [Option<String>; 4] {
    [
        header::CONTENT_ENCODING,
        header::ETAG,
        header::VARY,
        header::ACCEPT_RANGES,
    ]
    .map(|name| {
        resp.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    })
}

/// #797: a HEAD hit carries the GET hit's encoding headers, both when the GET is
/// encoded per-serve (no stored variant for this client) and when it is served
/// from a stored variant; and an identity-only HEAD stays identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_cache_head_hit_matches_get_headers() {
    let (address, upstream) = cacheable_html_upstream().await;
    let (state, root) = page_cache_proxy_state("pc-head", address, |_| {});
    for path in ["/page", "/tagged"] {
        // The fill stores only the gzip variant (cf_send_zstd off).
        get_until_variant_hit(&state, path, &[("accept-encoding", "gzip")]).await;

        // Per-serve: no br variant is stored, so the GET identity hit is br-encoded.
        let br = [("accept-encoding", "br")];
        let get = run(&state, get_with(CANON_HOST, path, &br)).await;
        let head = run(&state, head_req(path, &br)).await;
        assert_eq!(get.headers()["x-litespeed-cache"], "hit");
        assert_eq!(head.headers()["x-litespeed-cache"], "hit");
        assert_eq!(get.headers()[header::CONTENT_ENCODING], "br");
        assert_eq!(
            pc_encoding_headers(&head),
            pc_encoding_headers(&get),
            "{path}"
        );
        assert!(matches!(head.body(), Body::Empty));
        assert!(head.headers().get(header::CONTENT_LENGTH).is_none());

        // Variant: both are served from the stored gzip copy.
        let gz = [("accept-encoding", "gzip")];
        let get = run(&state, get_with(CANON_HOST, path, &gz)).await;
        let head = run(&state, head_req(path, &gz)).await;
        assert_eq!(get.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(pc_encoding_headers(&head), pc_encoding_headers(&get));
        assert_eq!(
            head.headers().get(header::CONTENT_LENGTH),
            get.headers().get(header::CONTENT_LENGTH)
        );

        // Identity client: neither is encoded.
        let get = run(&state, get_with(CANON_HOST, path, &[])).await;
        let head = run(&state, head_req(path, &[])).await;
        assert!(get.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(pc_encoding_headers(&head), pc_encoding_headers(&get));
        assert_eq!(
            head.headers().get(header::CONTENT_LENGTH),
            get.headers().get(header::CONTENT_LENGTH)
        );
    }
    let get = run(
        &state,
        get_with(CANON_HOST, "/tagged", &[("accept-encoding", "br")]),
    )
    .await;
    assert_eq!(get.headers()[header::ETAG], "\"1-2-3;br\"");
    upstream.abort();
    std::fs::remove_dir_all(root).ok();
}

/// #797: a page-cache 304 carries the `Vary` its encoded 200 carries and echoes
/// the encoded ETag variant the client revalidates; an identity client's 304
/// keeps the base validator and no `Vary`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_cache_304_carries_vary_and_variant_etag() {
    let (address, upstream) = cacheable_html_upstream().await;
    let (state, root) = page_cache_proxy_state("pc-304", address, |_| {});
    let gz = ("accept-encoding", "gzip");
    let seen = get_until_variant_hit(&state, "/tagged", &[gz]).await;
    let ok = seen.last().unwrap();
    assert_eq!(ok.headers()[header::CONTENT_ENCODING], "gzip");
    assert_eq!(ok.headers()[header::ETAG], "\"1-2-3;gz\"");
    let vary = ok.headers()[header::VARY].to_str().unwrap().to_string();

    let cond = run(
        &state,
        get_with(
            CANON_HOST,
            "/tagged",
            &[gz, ("if-none-match", "\"1-2-3;gz\"")],
        ),
    )
    .await;
    assert_eq!(cond.status(), 304);
    assert_eq!(cond.headers()["x-litespeed-cache"], "hit");
    assert_eq!(cond.headers()[header::ETAG], "\"1-2-3;gz\"");
    assert_eq!(cond.headers()[header::VARY], vary.as_str());

    // Per-serve encoded 200 (no br variant): the 304 still varies.
    let cond = run(
        &state,
        get_with(
            CANON_HOST,
            "/tagged",
            &[("accept-encoding", "br"), ("if-none-match", "\"1-2-3;br\"")],
        ),
    )
    .await;
    assert_eq!(cond.status(), 304);
    assert_eq!(cond.headers()[header::ETAG], "\"1-2-3;br\"");
    assert_eq!(cond.headers()[header::VARY], "Accept-Encoding");

    // Synthesized weak validator: same tag, Vary present for an encoding client.
    let page = get_until_variant_hit(&state, "/page", &[gz]).await;
    let weak = page.last().unwrap().headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_string();
    assert!(weak.starts_with("W/\"pc"), "{weak}");
    let cond = run(
        &state,
        get_with(CANON_HOST, "/page", &[gz, ("if-none-match", weak.as_str())]),
    )
    .await;
    assert_eq!(cond.status(), 304);
    assert_eq!(cond.headers()[header::ETAG], weak.as_str());
    assert_eq!(cond.headers()[header::VARY], "Accept-Encoding");

    // Identity client holding the base validator: base tag, no Vary.
    let cond = run(
        &state,
        get_with(CANON_HOST, "/tagged", &[("if-none-match", "\"1-2-3;;;\"")]),
    )
    .await;
    assert_eq!(cond.status(), 304);
    assert_eq!(cond.headers()[header::ETAG], "\"1-2-3;;;\"");
    assert!(cond.headers().get(header::VARY).is_none());
    upstream.abort();
    std::fs::remove_dir_all(root).ok();
}

/// #803: OLS answers every request resolved to a static context with
/// `<allowBrowse>0</allowBrowse>` with a 403, on both serving paths and for a
/// rewrite into the context; a more specific context below it is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_context_allow_browse_off_is_forbidden_on_every_path() {
    let root = temp_root("allow-browse-off");
    std::fs::create_dir_all(root.join("private/open")).unwrap();
    std::fs::write(root.join("private/secret.txt"), b"SECRET").unwrap();
    std::fs::write(root.join("private/open/ok.txt"), b"NESTED").unwrap();
    std::fs::write(root.join("public.txt"), b"PUBLIC").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^alias$ /private/secret.txt [L]\n",
    )
    .unwrap();
    let mut private = plain_context(ContextKind::Static, "/private/");
    private.allow_browse = false;
    let open = plain_context(ContextKind::Static, "/private/open/");
    let state = build_state_inner(
        root.clone(),
        vec![private, open],
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );

    for path in [
        "/private/secret.txt",
        "/private/",
        "/private/missing",
        "/alias",
    ] {
        assert!(
            fast_serve_req(&state, &get(CANON_HOST, path, None))
                .await
                .is_none(),
            "{path}: the on-core path must bridge so dispatch renders the 403"
        );
        let resp = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(resp.status(), 403, "{path}");
        assert_ne!(response_text(resp).await, "SECRET", "{path}");
    }
    let resp = run(&state, get(CANON_HOST, "/private/open/ok.txt", None)).await;
    assert_eq!(response_text(resp).await, "NESTED");
    let fast = fast_serve_req(&state, &get(CANON_HOST, "/public.txt", None))
        .await
        .expect("an unrelated path still serves on-core");
    assert_eq!(response_text(fast).await, "PUBLIC");
    std::fs::remove_dir_all(root).ok();
}

/// #802: a context kind httpjet does not route never falls through to static
/// serving (the parser rejects it; this is the runtime backstop).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrouted_context_kind_never_serves_static() {
    let root = temp_root("unrouted-context-kind");
    std::fs::create_dir_all(root.join("app")).unwrap();
    std::fs::write(root.join("app/run.py"), b"SOURCE").unwrap();
    let state = build_state_inner(
        root.clone(),
        vec![plain_context(ContextKind::Other, "/app/")],
        Vec::new(),
        false,
        None,
        None,
        |_| {},
    );
    assert!(
        fast_serve_req(&state, &get(CANON_HOST, "/app/run.py", None))
            .await
            .is_none()
    );
    let resp = run(&state, get(CANON_HOST, "/app/run.py", None)).await;
    assert_eq!(resp.status(), 503);
    assert_ne!(response_text(resp).await, "SOURCE");
    std::fs::remove_dir_all(root).ok();
}

/// (#814) An ErrorDocument inside an `allowBrowse 0` context is refused like
/// any other request there; the built-in page is used instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_document_never_serves_from_an_allow_browse_off_context() {
    let root = temp_root("errdoc-allow-browse");
    std::fs::create_dir_all(root.join("private")).unwrap();
    std::fs::write(root.join("private/secret.html"), b"SECRET").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "ErrorDocument 404 /private/secret.html\nErrorDocument 403 /private/secret.html\n",
    )
    .unwrap();
    let mut private = plain_context(ContextKind::Static, "/private/");
    private.allow_browse = false;
    let state = build_state_inner(
        root.clone(),
        vec![private],
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );
    for (path, status) in [("/missing", 404), ("/private/secret.html", 403)] {
        let resp = run(&state, get_with(CANON_HOST, path, &[])).await;
        assert_eq!(resp.status(), status, "{path}");
        let body = body_bytes(resp.into_body());
        assert!(
            !body.windows(6).any(|w| w == b"SECRET"),
            "{path} leaked the denied page"
        );
    }
    std::fs::remove_dir_all(root).ok();
}

// ─── #826: a rewrite into another directory runs that directory's rules ───

fn dest_rewrite_root(tag: &str, root_rules: &str, end: bool) -> PathBuf {
    let doc_root = temp_root(tag);
    let flag = if end { "END" } else { "L" };
    std::fs::write(
        doc_root.join(".htaccess"),
        format!("RewriteEngine On\nRewriteRule ^blog/(.*)$ /wp/$1 [{flag}]\n{root_rules}"),
    )
    .unwrap();
    std::fs::create_dir_all(doc_root.join("wp")).unwrap();
    std::fs::write(
        doc_root.join("wp/.htaccess"),
        "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /wp/front.html [L]\n",
    )
    .unwrap();
    std::fs::write(doc_root.join("wp/front.html"), b"wp front controller").unwrap();
    doc_root
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_directory_rewrite_runs_the_destination_front_controller() {
    let doc_root = dest_rewrite_root("dest-rewrite-fc", "", false);
    let state = build_state_htaccess(doc_root.clone());
    for path in ["/wp/post", "/blog/post"] {
        let resp = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(resp.status(), http::StatusCode::OK, "{path}");
        assert_eq!(
            &body_bytes(resp.into_body())[..],
            b"wp front controller",
            "{path}"
        );
    }
    // The on-core path cannot key on the wp chain it did not load: it bridges.
    assert!(fast_serve_get(&state, "/blog/post").await.is_none());
    std::fs::remove_dir_all(doc_root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_rewrite_skips_the_destination_front_controller() {
    let doc_root = dest_rewrite_root("dest-rewrite-end", "", true);
    let state = build_state_htaccess(doc_root.clone());
    let resp = run(&state, get(CANON_HOST, "/blog/post", None)).await;
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    std::fs::remove_dir_all(doc_root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inline_rewrite_runs_the_docroot_front_controller() {
    let doc_root = temp_root("dest-rewrite-inline");
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ /front.html [L]\n",
    )
    .unwrap();
    std::fs::write(doc_root.join("front.html"), b"docroot front controller").unwrap();
    let mut state = build_state_htaccess(doc_root.clone());
    Arc::get_mut(&mut state).unwrap().inline_rules.insert(
        VHOST.into(),
        Arc::new(
            hj_rewrite::RuleSet::parse("RewriteEngine On\nRewriteRule ^/old/(.*)$ /new/$1 [L]\n")
                .unwrap(),
        ),
    );
    let resp = run(&state, get(CANON_HOST, "/old/x", None)).await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    assert_eq!(
        &body_bytes(resp.into_body())[..],
        b"docroot front controller"
    );
    std::fs::remove_dir_all(doc_root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_directory_rewrite_loop_is_a_500() {
    let doc_root = temp_root("dest-rewrite-loop");
    for (dir, to) in [("a", "b"), ("b", "a")] {
        std::fs::create_dir_all(doc_root.join(dir)).unwrap();
        std::fs::write(
            doc_root.join(dir).join(".htaccess"),
            format!("RewriteEngine On\nRewriteRule ^(.*)$ /{to}/$1 [L]\n"),
        )
        .unwrap();
    }
    let state = build_state_htaccess(doc_root.clone());
    let resp = run(&state, get(CANON_HOST, "/a/x", None)).await;
    assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(fast_serve_get(&state, "/a/x").await.is_none());
    std::fs::remove_dir_all(doc_root).unwrap();
}

// ─── #836: a hop into another chain passes that chain's access phase ───

/// An upstream that answers every request `200 BACKEND`.
async fn backend_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0_u8; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    let Ok(read) = stream.read(&mut buf).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&buf[..read]);
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nBACKEND",
                    )
                    .await;
            });
        }
    });
    (address, task)
}

async fn hop_body(body: Body) -> Vec<u8> {
    use http_body_util::BodyExt;
    match body {
        Body::Stream(stream) => stream
            .collect()
            .await
            .map(|c| c.to_bytes().to_vec())
            .unwrap_or_default(),
        other => body_bytes(other).to_vec(),
    }
}

fn hop_proxy_state(doc_root: PathBuf, address: SocketAddr) -> Arc<ServerState> {
    build_state_inner(
        doc_root,
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |server| register_upstream(server, address),
    )
}

fn write_priv_proxy(doc_root: &std::path::Path, access: &str, address: SocketAddr) {
    std::fs::create_dir_all(doc_root.join("priv")).unwrap();
    std::fs::write(
        doc_root.join("priv/.htaccess"),
        format!("{access}RewriteEngine On\nRewriteRule ^(.*)$ http://{address}/$1 [P,L]\n"),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hop_proxy_into_denied_directory_is_forbidden() {
    let (address, upstream) = backend_upstream().await;
    let doc_root = temp_root("hop-deny-proxy");
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^pub/(.*)$ /priv/$1 [L]\n",
    )
    .unwrap();
    write_priv_proxy(
        &doc_root,
        "<Files \"secret\">\nRequire all denied\n</Files>\n",
        address,
    );
    let state = hop_proxy_state(doc_root.clone(), address);
    // Control: an allowed hop reaches the backend.
    let resp = run(&state, get(CANON_HOST, "/pub/open", None)).await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    assert_eq!(hop_body(resp.into_body()).await, b"BACKEND");
    for path in ["/priv/secret", "/pub/secret"] {
        let resp = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN, "{path}");
        assert!(
            !hop_body(resp.into_body())
                .await
                .windows(7)
                .any(|w| w == b"BACKEND"),
            "{path} reached the backend"
        );
    }
    assert!(fast_serve_get(&state, "/pub/secret").await.is_none());
    upstream.abort();
    std::fs::remove_dir_all(doc_root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hop_proxy_into_auth_directory_challenges() {
    let (address, upstream) = backend_upstream().await;
    let doc_root = temp_root("hop-auth-proxy");
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^pub/(.*)$ /priv/$1 [L]\n",
    )
    .unwrap();
    std::fs::write(
        doc_root.join("users"),
        "Admin:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
    )
    .unwrap();
    write_priv_proxy(
        &doc_root,
        &format!(
            "AuthType Basic\nAuthName \"p\"\nAuthUserFile {}/users\nRequire valid-user\n",
            doc_root.display()
        ),
        address,
    );
    let state = hop_proxy_state(doc_root.clone(), address);
    let resp = run(&state, get(CANON_HOST, "/pub/x", None)).await;
    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
    let mut authed = get(CANON_HOST, "/pub/x", None);
    authed.headers_mut().insert(
        header::AUTHORIZATION,
        "Basic QWRtaW46cGFzc3dvcmQ=".parse().unwrap(),
    );
    let resp = run(&state, authed).await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    assert_eq!(hop_body(resp.into_body()).await, b"BACKEND");
    upstream.abort();
    std::fs::remove_dir_all(doc_root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intermediate_hop_deny_is_enforced() {
    let doc_root = temp_root("hop-deny-intermediate");
    std::fs::write(doc_root.join("index.html"), b"front").unwrap();
    std::fs::create_dir_all(doc_root.join("a")).unwrap();
    std::fs::write(
        doc_root.join("a/.htaccess"),
        "RewriteEngine On\nRewriteRule ^(.*)$ /b/$1 [L]\n",
    )
    .unwrap();
    std::fs::create_dir_all(doc_root.join("b")).unwrap();
    std::fs::write(
        doc_root.join("b/.htaccess"),
        "Require all denied\nRewriteEngine On\nRewriteRule ^(.*)$ /index.html [L]\n",
    )
    .unwrap();
    let state = build_state_htaccess(doc_root.clone());
    let resp = run(&state, get(CANON_HOST, "/a/x", None)).await;
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    assert!(fast_serve_get(&state, "/a/x").await.is_none());
    std::fs::remove_dir_all(doc_root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hop_redirect_carries_the_hop_chain_headers() {
    let doc_root = temp_root("hop-redirect-headers");
    std::fs::write(
        doc_root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^r/(.*)$ /hdr/$1 [L]\nHeader always set X-Root root\n",
    )
    .unwrap();
    std::fs::create_dir_all(doc_root.join("hdr")).unwrap();
    std::fs::write(
        doc_root.join("hdr/.htaccess"),
        "RewriteEngine On\nRewriteRule ^(.*)$ /elsewhere/$1 [R=302,L]\n\
         Header always set X-Hop hdr\n",
    )
    .unwrap();
    let state = build_state_htaccess(doc_root.clone());
    let resp = run(&state, get(CANON_HOST, "/r/x", None)).await;
    assert_eq!(resp.status(), http::StatusCode::FOUND);
    assert_eq!(resp.headers().get("x-hop").unwrap(), "hdr");
    assert_eq!(resp.headers().get("x-root").unwrap(), "root");
    std::fs::remove_dir_all(doc_root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inline_rewrite_into_denied_proxy_directory_is_forbidden() {
    let (address, upstream) = backend_upstream().await;
    let doc_root = temp_root("hop-inline-deny-proxy");
    write_priv_proxy(&doc_root, "Require all denied\n", address);
    let mut state = hop_proxy_state(doc_root.clone(), address);
    Arc::get_mut(&mut state).unwrap().inline_rules.insert(
        VHOST.into(),
        Arc::new(
            hj_rewrite::RuleSet::parse("RewriteEngine On\nRewriteRule ^/pub/(.*)$ /priv/$1 [L]\n")
                .unwrap(),
        ),
    );
    let resp = run(&state, get(CANON_HOST, "/pub/x", None)).await;
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    upstream.abort();
    std::fs::remove_dir_all(doc_root).unwrap();
}

// ─── #850-#853/#856: `.htaccess` handler + DirectoryIndex routing ───────────

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Dispatch must route `path` to the (absent) PHP pool and the on-core fast path
/// must bridge it: neither may return the file's source.
async fn assert_routed_to_php(state: &Arc<ServerState>, path: &str, source: &[u8]) {
    let resp = run(state, get(CANON_HOST, path, None)).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::SERVICE_UNAVAILABLE,
        "dispatch did not route {path} to PHP"
    );
    assert!(!contains_bytes(&body_bytes(resp.into_body()), source));
    assert!(
        fast_serve_get(state, path).await.is_none(),
        "on-core fast path served {path} instead of bridging it to PHP"
    );
}

async fn assert_served_static(state: &Arc<ServerState>, path: &str, body: &[u8]) {
    let resp = run(state, get(CANON_HOST, path, None)).await;
    assert_eq!(resp.status(), http::StatusCode::OK, "dispatch {path}");
    assert_eq!(
        body_bytes(resp.into_body()).as_ref(),
        body,
        "dispatch {path}"
    );
    let fast = fast_serve_get(state, path)
        .await
        .unwrap_or_else(|| panic!("on-core fast path bridged static {path}"));
    assert_eq!(fast.status(), http::StatusCode::OK, "fast_serve {path}");
    assert_eq!(
        body_bytes(fast.into_body()).as_ref(),
        body,
        "fast_serve {path}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn force_type_php_routes_extensionless_file_to_php() {
    // #850.
    const SOURCE: &[u8] = b"<?php echo 'forcetype secret';";
    let root = temp_root("forcetype-php");
    std::fs::write(root.join("api"), SOURCE).unwrap();
    std::fs::write(root.join("other"), b"plain other").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "<Files api>\nForceType application/x-httpd-php\n</Files>\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    assert_routed_to_php(&state, "/api", SOURCE).await;
    assert_routed_to_php(&state, "/api/extra/path", SOURCE).await;
    assert_served_static(&state, "/other", b"plain other").await;
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quoted_set_handler_routes_to_php() {
    // #851.
    const SOURCE: &[u8] = b"<?php echo 'quoted handler secret';";
    let root = temp_root("quoted-sethandler");
    std::fs::create_dir(root.join("app")).unwrap();
    std::fs::write(root.join("app/page.html"), SOURCE).unwrap();
    std::fs::write(
        root.join("app/.htaccess"),
        "SetHandler \"application/x-httpd-php\"\n",
    )
    .unwrap();
    std::fs::write(root.join("public.html"), b"public page").unwrap();
    let state = build_state_htaccess(root.clone());
    assert_routed_to_php(&state, "/app/page.html", SOURCE).await;
    assert_served_static(&state, "/public.html", b"public page").await;
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_inside_unevaluable_if_fails_closed() {
    // #852: `SetHandler none` under a host test we cannot evaluate must not
    // disable the directory's PHP mapping for every host.
    const SOURCE: &[u8] = b"<?php echo 'if-guarded secret';";
    let root = temp_root("unevaluable-if-handler");
    std::fs::write(root.join("page.html"), SOURCE).unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "AddHandler application/x-httpd-php .html\n\
         <If \"%{HTTP_HOST} == 'static.example'\">\nSetHandler none\n</If>\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let resp = run(&state, get(CANON_HOST, "/page.html", None)).await;
    assert!(
        !resp.status().is_success(),
        "malformed handler scope must fail closed, got {}",
        resp.status()
    );
    assert!(!contains_bytes(&body_bytes(resp.into_body()), SOURCE));
    if let Some(fast) = fast_serve_get(&state, "/page.html").await {
        assert!(!fast.status().is_success());
        assert!(!contains_bytes(&body_bytes(fast.into_body()), SOURCE));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_handler_undoes_an_inherited_php_mapping() {
    // #853: uploads/ opts out of the docroot's `.html` PHP mapping.
    const SOURCE: &[u8] = b"<?php echo 'docroot html script';";
    const UPLOAD: &[u8] = b"<?php echo 'uploaded html';";
    for (root_directive, child_directive) in [
        (
            "AddHandler application/x-httpd-php .html\n",
            "RemoveHandler .html\n",
        ),
        (
            "AddType application/x-httpd-php .html\n",
            "RemoveType .html\n",
        ),
        (
            "AddType application/x-httpd-php .html\n",
            "AddType text/html .html\n",
        ),
    ] {
        let root = temp_root("removehandler");
        std::fs::create_dir(root.join("uploads")).unwrap();
        std::fs::write(root.join("page.html"), SOURCE).unwrap();
        std::fs::write(root.join("uploads/evil.html"), UPLOAD).unwrap();
        std::fs::write(root.join(".htaccess"), root_directive).unwrap();
        std::fs::write(root.join("uploads/.htaccess"), child_directive).unwrap();
        let state = build_state_htaccess(root.clone());
        assert_routed_to_php(&state, "/page.html", SOURCE).await;
        assert_served_static(&state, "/uploads/evil.html", UPLOAD).await;
        // A configured script suffix is never stripped by `.htaccess`.
        std::fs::write(root.join("uploads/x.php"), SOURCE).unwrap();
        std::fs::write(
            root.join("uploads/.htaccess"),
            format!("{child_directive}RemoveHandler .php\nRemoveType .php\n"),
        )
        .unwrap();
        let state = build_state_htaccess(root.clone());
        assert_routed_to_php(&state, "/uploads/x.php", SOURCE).await;
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_index_disabled_stops_the_index_search() {
    // #856: neither the parent's list nor the vhost's `index.html` applies.
    let root = temp_root("dirindex-disabled");
    for dir in ["off", "on", "nested", "nested/off"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
        std::fs::write(root.join(dir).join("index.html"), b"index page").unwrap();
        std::fs::write(root.join(dir).join("home.html"), b"home page").unwrap();
    }
    std::fs::write(root.join("off/.htaccess"), "DirectoryIndex disabled\n").unwrap();
    std::fs::write(root.join("nested/.htaccess"), "DirectoryIndex home.html\n").unwrap();
    std::fs::write(
        root.join("nested/off/.htaccess"),
        "DirectoryIndex disabled\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());

    for path in ["/off/", "/nested/off/"] {
        let resp = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(
            resp.status(),
            http::StatusCode::NOT_FOUND,
            "dispatch {path}"
        );
        if let Some(fast) = fast_serve_get(&state, path).await {
            assert_eq!(
                fast.status(),
                http::StatusCode::NOT_FOUND,
                "fast_serve {path}"
            );
        }
    }
    // Files in a disabled directory are still served, and siblings keep theirs.
    assert_served_static(&state, "/off/index.html", b"index page").await;
    assert_served_static(&state, "/on/", b"index page").await;
    assert_served_static(&state, "/nested/", b"home page").await;
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_index_disabled_never_selects_a_script_index() {
    // #856 on the script side: a parent `DirectoryIndex index.php` must not
    // route the disabled child directory to its index.php either.
    const SOURCE: &[u8] = b"<?php echo 'child index';";
    let root = temp_root("dirindex-disabled-script");
    std::fs::create_dir(root.join("child")).unwrap();
    std::fs::write(root.join("child/index.php"), SOURCE).unwrap();
    std::fs::write(root.join(".htaccess"), "DirectoryIndex index.php\n").unwrap();
    std::fs::write(root.join("child/.htaccess"), "DirectoryIndex disabled\n").unwrap();
    let state = build_state_htaccess(root.clone());
    let resp = run(&state, get(CANON_HOST, "/child/", None)).await;
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    assert!(!contains_bytes(&body_bytes(resp.into_body()), SOURCE));
    if let Some(fast) = fast_serve_get(&state, "/child/").await {
        assert_eq!(fast.status(), http::StatusCode::NOT_FOUND);
    }
    std::fs::remove_dir_all(root).unwrap();
}

// ─── #857: chains whose response depends on unkeyed request inputs ───

async fn run_from(state: &Arc<ServerState>, peer: Ipv4Addr, req: Request) -> Response {
    handle(
        state.clone(),
        LISTENER,
        IpAddr::V4(peer),
        SocketAddr::from(([127, 0, 0, 1], 80)),
        40000,
        false,
        false,
        false,
        None,
        Proto::Http1,
        None,
        req,
    )
    .await
}

/// A cacheable upstream that names the path it was asked for in `x-upstream-path`.
async fn spawn_path_echo_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0_u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            let line = String::from_utf8_lossy(&head);
            let path = line.split(' ').nth(1).unwrap_or("").to_string();
            let reply = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 X-Upstream-Path: {path}\r\n\
                 X-LiteSpeed-Cache-Control: public,max-age=60\r\n\
                 Content-Length: 2\r\n\
                 Connection: close\r\n\r\nOK"
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    (address, task)
}

fn upstream_path(resp: &Response) -> Option<&str> {
    resp.headers()
        .get("x-upstream-path")
        .and_then(|v| v.to_str().ok())
}

/// Regression (#857): an admin-IP rewrite plus a `SetEnvIf Remote_Addr` feeding
/// `Header … env=` were stored by the page cache and replayed to every later
/// client. The client address is not in the key, so such a chain must neither
/// populate nor serve the cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_cache_bypasses_chains_reading_the_client_address() {
    const ADMIN: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const VISITOR: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
    let (address, upstream) = spawn_path_echo_upstream().await;
    for (tag, htaccess) in [
        (
            "rewrite",
            format!(
                "CacheLookup public on\nHeader set X-LiteSpeed-Cache-Control public,max-age=60\n\
                 RewriteEngine On\n\
                 RewriteCond %{{REMOTE_ADDR}} ^203\\.0\\.113\\.7$\n\
                 RewriteRule ^/page$ http://{address}/admin [P,L]\n\
                 RewriteRule ^/page$ http://{address}/public [P,L]\n"
            ),
        ),
        (
            "setenvif",
            format!(
                "CacheLookup public on\nHeader set X-LiteSpeed-Cache-Control public,max-age=60\n\
                 SetEnvIf Remote_Addr ^203\\.0\\.113\\.7$ IS_ADMIN=1\n\
                 Header set X-Admin yes env=IS_ADMIN\n\
                 RewriteEngine On\n\
                 RewriteRule ^/page$ http://{address}/public [P,L]\n"
            ),
        ),
    ] {
        let root = temp_root(&format!("pc-unkeyed-{tag}"));
        std::fs::write(root.join(".htaccess"), htaccess).unwrap();
        let store = Arc::new(hj_pagecache::PageStore::new(
            hj_pagecache::StoreConfig::default(),
        ));
        let state = build_state_inner(
            root.clone(),
            Vec::new(),
            Vec::new(),
            true,
            Some(store.clone()),
            None,
            |server| register_upstream(server, address),
        );
        for _ in 0..2 {
            let admin = run_from(&state, ADMIN, get(CANON_HOST, "/page", None)).await;
            assert_eq!(admin.status(), http::StatusCode::OK, "{tag}");
            if tag == "rewrite" {
                assert_eq!(upstream_path(&admin), Some("/admin"), "{tag}");
            } else {
                assert_eq!(admin.headers().get("x-admin").unwrap(), "yes", "{tag}");
            }
            let visitor = run_from(&state, VISITOR, get(CANON_HOST, "/page", None)).await;
            assert_eq!(visitor.status(), http::StatusCode::OK, "{tag}");
            assert_eq!(upstream_path(&visitor), Some("/public"), "{tag}");
            assert!(
                !visitor.headers().contains_key("x-admin"),
                "{tag}: the admin's header was replayed to another client"
            );
            assert_ne!(
                visitor
                    .headers()
                    .get("x-litespeed-cache")
                    .and_then(|v| v.to_str().ok()),
                Some("hit"),
                "{tag}"
            );
        }
        assert_eq!(store.entry_count(), 0, "{tag}: an unkeyed chain was stored");
        std::fs::remove_dir_all(root).unwrap();
    }

    // Control: the same proxied page under a chain with only keyed inputs caches.
    let root = temp_root("pc-unkeyed-control");
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "CacheLookup public on\nHeader set X-LiteSpeed-Cache-Control public,max-age=60\n\
             SetEnvIf Request_URI ^/page$ IS_PAGE=1\n\
             Header set X-Page yes env=IS_PAGE\n\
             Order allow,deny\nAllow from all\n\
             RewriteEngine On\n\
             RewriteCond %{{HTTP_USER_AGENT}} !bot\n\
             RewriteRule ^/page$ http://{address}/public [P,L]\n"
        ),
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |server| register_upstream(server, address),
    );
    let first = run_from(&state, ADMIN, get(CANON_HOST, "/page", None)).await;
    assert_eq!(first.headers().get("x-litespeed-cache").unwrap(), "miss");
    let visitor = run_from(&state, VISITOR, get(CANON_HOST, "/page", None)).await;
    assert_eq!(
        visitor.headers().get("x-litespeed-cache").unwrap(),
        "hit",
        "a keyed chain must stay cacheable"
    );
    upstream.abort();
    std::fs::remove_dir_all(root).unwrap();
}

/// (#857) The on-core Branch-1 lookup must refuse a stored entry once the chain
/// reads an unkeyed input, as dispatch() does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_serve_does_not_serve_page_cache_under_unkeyed_chain() {
    let doc_root = temp_root("fastserve-unkeyed");
    std::fs::write(doc_root.join("page.html"), "<h1>public</h1>\n").unwrap();
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
    let method = http::Method::GET;
    let identity = seeded_identity("/page.html");
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
        forwarding_trusted: false,
        env: Vec::new(),
        local_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
        peer_port: 40000,
        peer_unix: false,
        tls: None,
        redirect_guard: None,
        request_time: std::time::SystemTime::UNIX_EPOCH,
        request_id: Default::default(),
    };
    let cc = crate::lscache::CacheCtx {
        enabled: true,
        method: &method,
        host: CANON_HOST,
        cookie: None,
        identity: &identity,
        req_path: "/page.html",
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
    let key =
        crate::lscache::build_cache_key(&rctx, &cc, &store, &crate::lscache::PrivateRoute::Public);
    state
        .page_cache_admission
        .record(crate::lscache::hash_key(&key));
    let resp = http::Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/html")
        .header(header::CACHE_CONTROL, "public,max-age=600")
        .header("x-admin", "yes")
        .body(Body::Full(bytes::Bytes::from_static(b"<h1>admin</h1>\n")))
        .unwrap();
    crate::lscache::cache_store(&state, &rctx, &cc, resp).await;
    let is_hit = |r: &Option<Response>| {
        r.as_ref()
            .and_then(|r| r.headers().get("x-litespeed-cache"))
            .is_some_and(|v| v == "hit")
    };
    assert!(
        is_hit(&fast_serve_get(&state, "/page.html").await),
        "baseline: the stored entry serves on-core"
    );

    // A keyed-only .htaccess keeps the hit.
    std::fs::write(
        doc_root.join(".htaccess"),
        "SetEnvIf Request_URI ^/page IS_PAGE=1\nHeader set X-Page yes env=IS_PAGE\n",
    )
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(
        is_hit(&fast_serve_get(&state, "/page.html").await),
        "a keyed chain keeps the on-core hit"
    );

    for htaccess in [
        "SetEnvIf Remote_Addr ^203\\.0\\.113\\.7$ IS_ADMIN=1\nHeader set X-Admin yes env=IS_ADMIN\n",
        "RewriteEngine On\nRewriteCond %{REMOTE_ADDR} ^203\\.0\\.113\\.7$\nRewriteRule ^ - [E=IS_ADMIN:1]\n",
    ] {
        std::fs::write(doc_root.join(".htaccess"), htaccess).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(
            !is_hit(&fast_serve_get(&state, "/page.html").await),
            "an unkeyed chain must not serve the shared entry on-core: {htaccess}"
        );
    }
    std::fs::remove_dir_all(doc_root).unwrap();
}

/// Upstream that answers every request with `status_line` and the received request
/// head (request line + headers) as the body.
async fn spawn_head_echo_upstream(status_line: &'static str) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0_u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&buf[..n]);
                }
                let body = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let reply = format!(
                    "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    address
}

fn request_line(echo: &str) -> &str {
    echo.lines().next().unwrap_or("")
}

/// #867: an internal rewrite into a proxy context forwards the REWRITTEN path and
/// query (OLS `encodeReqLine`); an unrewritten request keeps its raw target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_into_proxy_context_forwards_the_rewritten_uri() {
    let address = spawn_head_echo_upstream("HTTP/1.1 200 OK").await;
    let root = temp_root("rewrite-into-proxy-context");
    std::fs::write(
        root.join(".htaccess"),
        "RewriteEngine On\n\
         RewriteRule ^old/(.*)$ /api/$1?x=2 [L]\n\
         RewriteRule ^keep/(.*)$ /api/$1 [L]\n",
    )
    .unwrap();
    let mut proxy = plain_context(ContextKind::Proxy, "/api/");
    proxy.handler = Some("test-upstream".into());
    let state = build_state_inner(
        root.clone(),
        vec![proxy],
        Vec::new(),
        true,
        None,
        None,
        |server| register_upstream(server, address),
    );
    let echo = response_text(run(&state, get(CANON_HOST, "/old/echo?q=1", None)).await).await;
    assert_eq!(request_line(&echo), "get /api/echo?x=2 http/1.1", "{echo}");
    let echo = response_text(run(&state, get(CANON_HOST, "/keep/a%20b?q=1", None)).await).await;
    assert_eq!(request_line(&echo), "get /api/a%20b?q=1 http/1.1", "{echo}");
    let echo = response_text(run(&state, get(CANON_HOST, "/api/a%7Eb?q=1", None)).await).await;
    assert_eq!(
        request_line(&echo),
        "get /api/a%7eb?q=1 http/1.1",
        "an unrewritten request keeps its raw target: {echo}"
    );
    std::fs::remove_dir_all(root).ok();
}

/// #867: the websocket-map arm forwards the rewritten URI too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_into_websocket_map_forwards_the_rewritten_uri() {
    let address = spawn_head_echo_upstream("HTTP/1.1 403 Forbidden").await;
    let root = temp_root("rewrite-into-ws-map");
    std::fs::write(
        root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^legacy/(.*)$ /ws/$1 [L]\n",
    )
    .unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |config| {
            let vhost = config
                .vhosts
                .get_mut(VHOST)
                .unwrap()
                .config
                .as_mut()
                .unwrap();
            Arc::make_mut(vhost)
                .websockets
                .push(hj_core::config::WebSocketMap {
                    uri: "/ws/".into(),
                    address: address.to_string(),
                });
        },
    );
    let echo = response_text(run(&state, websocket_get("/legacy/room")).await).await;
    assert_eq!(request_line(&echo), "get /ws/room http/1.1", "{echo}");
    std::fs::remove_dir_all(root).ok();
}

/// #868: `[P]` to a `ws://` target on an upgrade request goes to the WebSocket relay
/// (the upgrade reaches the upstream) with the screened target; a plain request to the
/// same rule stays an ordinary forward with Upgrade stripped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_proxy_to_ws_target_relays_the_upgrade() {
    let address = spawn_head_echo_upstream("HTTP/1.1 403 Forbidden").await;
    let root = temp_root("rewrite-proxy-ws");
    std::fs::write(
        root.join(".htaccess"),
        format!("RewriteEngine On\nRewriteRule ^chat/(.*)$ ws://{address}/socket/$1 [P,L]\n"),
    )
    .unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |server| register_upstream(server, address),
    );
    let echo = response_text(run(&state, websocket_get("/chat/r1")).await).await;
    assert_eq!(request_line(&echo), "get /socket/r1 http/1.1", "{echo}");
    assert!(echo.contains("\r\nupgrade: websocket\r\n"), "{echo}");
    assert!(echo.contains("sec-websocket-key:"), "{echo}");
    let echo = response_text(run(&state, get(CANON_HOST, "/chat/r1", None)).await).await;
    assert!(!echo.contains("upgrade:"), "{echo}");
    std::fs::remove_dir_all(root).ok();
}

/// #868: the SSRF screen still guards a ws `[P]` upgrade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_proxy_ws_upgrade_keeps_the_ssrf_screen() {
    let root = temp_root("rewrite-proxy-ws-screen");
    std::fs::write(
        root.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^chat/(.*)$ ws://127.0.0.1:9/$1 [P,L]\n",
    )
    .unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );
    let resp = run(&state, websocket_get("/chat/r1")).await;
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    std::fs::remove_dir_all(root).ok();
}

/// #870: `[P,E=Proxy-Host:value]` replaces the upstream Host (OLS `setNewHost`);
/// X-Forwarded-Host keeps the client's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_proxy_host_overrides_the_upstream_host() {
    let address = spawn_head_echo_upstream("HTTP/1.1 200 OK").await;
    let root = temp_root("rewrite-proxy-host");
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "RewriteEngine On\n\
             RewriteRule ^preview/([^/]*)/(.*)$ http://{address}/$2 [P,E=Proxy-Host:$1,L]\n\
             RewriteRule ^plain/(.*)$ http://{address}/$1 [P,L]\n"
        ),
    )
    .unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |server| register_upstream(server, address),
    );
    let echo =
        response_text(run(&state, get(CANON_HOST, "/preview/app.example/x", None)).await).await;
    assert_eq!(request_line(&echo), "get /x http/1.1", "{echo}");
    assert!(echo.contains("\r\nhost: app.example\r\n"), "{echo}");
    assert!(
        echo.contains(&format!("\r\nx-forwarded-host: {CANON_HOST}\r\n")),
        "{echo}"
    );
    let echo = response_text(run(&state, get(CANON_HOST, "/plain/x", None)).await).await;
    assert!(
        echo.contains(&format!("\r\nhost: {CANON_HOST}\r\n")),
        "{echo}"
    );
    let resp = run(&state, get(CANON_HOST, "/preview/bad%20host/x", None)).await;
    assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
    std::fs::remove_dir_all(root).ok();
}

/// #871: an upstream 101 to an ordinary (non-upgrade) forward is a 502, never a
/// 101 the downstream (notably H2/H3) cannot frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_101_on_a_non_upgrade_forward_is_bad_gateway() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0_u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&buf[..n]);
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                    )
                    .await;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            });
        }
    });
    let root = temp_root("upstream-101-non-upgrade");
    let mut proxy = plain_context(ContextKind::Proxy, "/");
    proxy.handler = Some("test-upstream".into());
    let state = build_state_inner(
        root.clone(),
        vec![proxy],
        Vec::new(),
        false,
        None,
        None,
        |server| register_upstream(server, address),
    );
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        run(&state, get(CANON_HOST, "/x", None)),
    )
    .await
    .expect("a 101 to a plain forward is answered promptly");
    assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
    std::fs::remove_dir_all(root).ok();
}

/// #866: hj-proxy marks an unsized (chunked) or `X-Accel-Buffering: no` upstream
/// body so the transport bridge streams it; a sized body stays unmarked (buffered).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxied_response_marker_follows_the_upstream_framing() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chunked = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0_u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&buf[..n]);
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\
                          Connection: close\r\n\r\n4\r\nOGG!\r\n0\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    let sized = spawn_fixed_upstream("HTTP/1.1 200 OK", "UPSTREAM").await;
    let accel = spawn_fixed_upstream("HTTP/1.1 200 OK\r\nX-Accel-Buffering: no", "UPSTREAM").await;
    for (address, marked) in [(chunked, true), (sized, false), (accel, true)] {
        let root = temp_root("proxied-body-marker");
        let mut proxy = plain_context(ContextKind::Proxy, "/");
        proxy.handler = Some("test-upstream".into());
        let state = build_state_inner(
            root.clone(),
            vec![proxy],
            Vec::new(),
            false,
            None,
            None,
            |server| register_upstream(server, address),
        );
        let resp = run(&state, get(CANON_HOST, "/x", None)).await;
        assert_eq!(
            resp.extensions().get::<hj_core::ProxiedBody>().is_some(),
            marked,
            "{address}"
        );
        assert!(!response_text(resp).await.is_empty());
        std::fs::remove_dir_all(root).ok();
    }
}

/// (#890) `Allow/Deny from env=` read the env table ASCII-case-insensitively
/// like Apache's `apr_table_get`, on both the full pipeline and fast_serve.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_env_operand_matches_env_name_case_insensitively() {
    let root = temp_root("access-env-nocase");
    std::fs::create_dir(root.join("deny")).unwrap();
    std::fs::write(root.join("deny/page.txt"), b"page").unwrap();
    std::fs::write(
        root.join("deny/.htaccess"),
        "SetEnvIfNoCase User-Agent evilbot BadBot\n\
         Order Allow,Deny\nAllow from all\nDeny from env=badbot\n",
    )
    .unwrap();
    std::fs::create_dir(root.join("allow")).unwrap();
    std::fs::write(root.join("allow/page.txt"), b"page").unwrap();
    std::fs::write(
        root.join("allow/.htaccess"),
        "SetEnvIfNoCase User-Agent evilbot BadBot\n\
         Order Deny,Allow\nDeny from all\nAllow from env=!badbot\n",
    )
    .unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    for path in ["/deny/page.txt", "/allow/page.txt"] {
        let bad = || get_with(CANON_HOST, path, &[("user-agent", "EvilBot/1.0")]);
        assert_eq!(run(&state, bad()).await.status(), 403, "{path}");
        assert!(
            fast_serve_from(&state, loopback, &bad()).await.is_none(),
            "{path} served on-core"
        );
        let good = || get_with(CANON_HOST, path, &[("user-agent", "Mozilla/5.0")]);
        assert_eq!(run(&state, good()).await.status(), 200, "{path}");
        let fast = fast_serve_from(&state, loopback, &good()).await;
        assert_eq!(
            fast.map(|r| r.status()),
            Some(http::StatusCode::OK),
            "{path}"
        );
    }
    std::fs::remove_dir_all(root).ok();
}

/// (#891) `<If "%{REQUEST_URI} …">` access rules see the trailing `/` of the
/// request path, on both the full pipeline and fast_serve.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_if_request_uri_sees_trailing_slash() {
    let root = temp_root("access-if-slash");
    std::fs::create_dir(root.join("admin")).unwrap();
    std::fs::write(root.join("admin/index.html"), b"ADMIN").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "<If \"%{REQUEST_URI} =~ m#^/admin/$#\">\nRequire all denied\n</If>\n",
    )
    .unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |_| {},
    );
    assert_eq!(
        run(&state, get_with(CANON_HOST, "/admin/", &[]))
            .await
            .status(),
        403
    );
    assert!(
        fast_serve_get(&state, "/admin/").await.is_none(),
        "/admin/ served on-core"
    );
    // Control: a URI the expression does not match is still served.
    assert_eq!(
        run(&state, get_with(CANON_HOST, "/admin/index.html", &[]))
            .await
            .status(),
        200
    );
    let fast = fast_serve_get(&state, "/admin/index.html").await;
    assert_eq!(fast.map(|r| r.status()), Some(http::StatusCode::OK));
    std::fs::remove_dir_all(root).ok();
}

/// (#979) A `SetEnvIf`/`SetEnv` inside `<If "%{REQUEST_URI} …">` sees the
/// trailing `/` of the request path, on both the full pipeline and fast_serve:
/// the `Deny from env=` fed by it no longer fails open for `/private/`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn if_scoped_set_env_sees_trailing_slash() {
    let root = temp_root("if-setenvif-slash");
    for dir in ["private", "sealed"] {
        std::fs::create_dir(root.join(dir)).unwrap();
        std::fs::write(root.join(dir).join("index.html"), b"INDEX").unwrap();
    }
    std::fs::write(
        root.join(".htaccess"),
        "<If \"%{REQUEST_URI} =~ m#^/private/$#\">\n  SetEnvIf Request_URI . BLOCK\n</If>\n\
         <If \"%{REQUEST_URI} =~ m#^/sealed/$#\">\n  SetEnv BLOCK 1\n</If>\n\
         Order Allow,Deny\nAllow from all\nDeny from env=BLOCK\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    for dir in ["/private/", "/sealed/"] {
        assert_eq!(
            run(&state, get(CANON_HOST, dir, None)).await.status(),
            403,
            "{dir}"
        );
        assert!(
            fast_serve_get(&state, dir).await.is_none(),
            "{dir} served on-core"
        );
        // The expression does not match the index file itself.
        let file = format!("{dir}index.html");
        assert_eq!(
            run(&state, get(CANON_HOST, &file, None)).await.status(),
            200,
            "{file}"
        );
    }
    std::fs::remove_dir_all(root).ok();
}

/// (#978) `SetEnvIf` reads `\<` as a literal `<`, as PCRE does, so the
/// `Deny from env=` it feeds denies a `<?php` User-Agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_env_if_pcre_literal_bracket_feeds_deny() {
    let root = temp_root("setenvif-pcre-lt");
    std::fs::write(root.join("page.txt"), b"page").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "SetEnvIf User-Agent \"^\\<\\?php\" bad\n\
         Order Allow,Deny\nAllow from all\nDeny from env=bad\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let bad = || {
        get_with(
            CANON_HOST,
            "/page.txt",
            &[("user-agent", "<?php echo 1; ?>")],
        )
    };
    assert_eq!(run(&state, bad()).await.status(), 403);
    assert!(fast_serve_from(&state, loopback, &bad()).await.is_none());
    let good = get_with(CANON_HOST, "/page.txt", &[("user-agent", "Mozilla/5.0")]);
    assert_eq!(run(&state, good).await.status(), 200);
    std::fs::remove_dir_all(root).ok();
}

// ─── r14: .htaccess Header/ErrorDocument/env/MIME parity (#907-#911) ───

fn header_str<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

/// #907: `<Files*>`-scoped `Header` and `SetEnvIf` match the DirectoryIndex
/// file served for a directory request, on both the full and on-core paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r14_files_scoped_header_and_setenvif_apply_to_directory_index() {
    let root = temp_root("r14-index-scope");
    std::fs::create_dir(root.join("docs")).unwrap();
    std::fs::write(root.join("index.html"), "<h1>home</h1>\n").unwrap();
    std::fs::write(root.join("docs/index.html"), "<h1>docs</h1>\n").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "<FilesMatch \"\\.html$\">\n  Header set X-Html yes\n</FilesMatch>\n\
         <Files \"index.html\">\n  SetEnvIf Request_URI . IDX=1\n</Files>\n\
         Header set X-Idx yes env=IDX\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    for path in ["/", "/docs/", "/index.html"] {
        let full = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(full.status(), 200, "{path}");
        assert_eq!(header_str(&full, "x-html"), Some("yes"), "full {path}");
        assert_eq!(header_str(&full, "x-idx"), Some("yes"), "full {path}");
        let fast = fast_serve_get(&state, path).await.expect("served on-core");
        assert_eq!(header_str(&fast, "x-html"), Some("yes"), "fast {path}");
        assert_eq!(header_str(&fast, "x-idx"), Some("yes"), "fast {path}");
    }
    std::fs::remove_dir_all(root).ok();
}

/// #908: a quoted ErrorDocument path renders the file, a quoted URL redirects,
/// and a deeper `default` restores the built-in page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r14_quoted_error_document_targets_are_classified_after_unquoting() {
    let root = temp_root("r14-errordoc");
    std::fs::create_dir_all(root.join("errors")).unwrap();
    std::fs::create_dir_all(root.join("plain")).unwrap();
    std::fs::create_dir_all(root.join("away")).unwrap();
    std::fs::write(root.join("errors/404.html"), "custom not found\n").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "ErrorDocument 404 \"/errors/404.html\"\n",
    )
    .unwrap();
    std::fs::write(root.join("plain/.htaccess"), "ErrorDocument 404 default\n").unwrap();
    std::fs::write(
        root.join("away/.htaccess"),
        "ErrorDocument 404 'https://errors.example/404'\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());

    let resp = run(&state, get(CANON_HOST, "/missing", None)).await;
    assert_eq!(resp.status(), 404);
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"custom not found\n");

    let resp = run(&state, get(CANON_HOST, "/plain/missing", None)).await;
    assert_eq!(resp.status(), 404);
    let body = body_bytes(resp.into_body());
    assert!(
        !body.starts_with(b"custom not found") && !body.starts_with(b"/errors"),
        "{body:?}"
    );

    let resp = run(&state, get(CANON_HOST, "/away/missing", None)).await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        header_str(&resp, "location"),
        Some("https://errors.example/404")
    );
    std::fs::remove_dir_all(root).ok();
}

/// #909/#910: Header ops fold in Apache merge order and `env=` matches env
/// names case-insensitively, on the full and on-core paths alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r14_header_merge_order_and_case_insensitive_env_guards() {
    let root = temp_root("r14-merge");
    std::fs::write(root.join("a.txt"), "a\n").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "<Files a.txt>\n  Header set X-Order files\n</Files>\n\
         Header set X-Order dir\n\
         SetEnvIf Request_URI . Lower=1\n\
         Header set X-Env on env=LOWER\n\
         Header set X-Val \"%{LOWER}e\"\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let full = run(&state, get(CANON_HOST, "/a.txt", None)).await;
    let fast = fast_serve_get(&state, "/a.txt")
        .await
        .expect("served on-core");
    for resp in [&full, &fast] {
        assert_eq!(header_str(resp, "x-order"), Some("files"));
        assert_eq!(header_str(resp, "x-env"), Some("on"));
        assert_eq!(header_str(resp, "x-val"), Some("1"));
    }
    std::fs::remove_dir_all(root).ok();
}

/// #911: SetEnv reaches `%{VAR}e`/`env=`; AddType/ForceType set the served
/// static Content-Type; AddDefaultCharset completes text/html / text/plain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r14_setenv_addtype_forcetype_and_default_charset_apply() {
    let root = temp_root("r14-mod-mime-env");
    std::fs::create_dir_all(root.join("media")).unwrap();
    std::fs::create_dir_all(root.join("feed")).unwrap();
    std::fs::write(root.join("site.webmanifest"), "{}\n").unwrap();
    std::fs::write(root.join("media/clip.webm"), "webm\n").unwrap();
    std::fs::write(root.join("page.html"), "<p>x</p>\n").unwrap();
    std::fs::write(root.join("notes.txt"), "n\n").unwrap();
    std::fs::write(root.join("feed/index.html"), "<rss/>\n").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "SetEnv FOO bar\n\
         SetEnv DROPPED 1\n\
         UnsetEnv DROPPED\n\
         Header set X-Foo \"%{FOO}e\" env=foo\n\
         Header set X-Dropped 1 env=DROPPED\n\
         <IfModule mod_mime.c>\n  AddType application/manifest+json .webmanifest\n</IfModule>\n\
         AddDefaultCharset UTF-8\n",
    )
    .unwrap();
    std::fs::write(root.join("media/.htaccess"), "AddType video/webm .webm\n").unwrap();
    std::fs::write(
        root.join("feed/.htaccess"),
        "<Files index.html>\n  ForceType application/rss+xml\n</Files>\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let cases = [
        ("/site.webmanifest", "application/manifest+json"),
        ("/media/clip.webm", "video/webm"),
        ("/page.html", "text/html; charset=UTF-8"),
        ("/notes.txt", "text/plain; charset=UTF-8"),
        ("/feed/", "application/rss+xml"),
    ];
    for (path, want) in cases {
        let full = run(&state, get(CANON_HOST, path, None)).await;
        assert_eq!(full.status(), 200, "{path}");
        let fast = fast_serve_get(&state, path).await.expect("served on-core");
        for resp in [&full, &fast] {
            assert_eq!(header_str(resp, "content-type"), Some(want), "{path}");
            assert_eq!(header_str(resp, "x-foo"), Some("bar"), "{path}");
            assert_eq!(header_str(resp, "x-dropped"), None, "{path}");
        }
    }
    // A 304 revalidation describes the same representation.
    let full = run(&state, get(CANON_HOST, "/site.webmanifest", None)).await;
    let etag = header_str(&full, "etag").expect("etag").to_owned();
    let revalidated = run(&state, get(CANON_HOST, "/site.webmanifest", Some(&etag))).await;
    assert_eq!(revalidated.status(), 304);
    assert_eq!(
        header_str(&revalidated, "content-type"),
        Some("application/manifest+json")
    );
    std::fs::remove_dir_all(root).ok();
}

/// #911: SetEnv is visible to `%{ENV:}` rewrite conditions; the reserved `HJ_`
/// namespace stays out of config reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r14_setenv_is_visible_to_rewrite_env_conditions() {
    let root = temp_root("r14-setenv-rewrite");
    std::fs::write(root.join("on.txt"), "on\n").unwrap();
    std::fs::write(root.join("off.txt"), "off\n").unwrap();
    std::fs::write(
        root.join(".htaccess"),
        "SetEnv SWITCH on\n\
         SetEnv HJ_PROBE 1\n\
         Header set X-Probe 1 env=HJ_PROBE\n\
         RewriteEngine On\n\
         RewriteCond %{ENV:SWITCH} =on\n\
         RewriteRule ^off\\.txt$ /on.txt [L]\n",
    )
    .unwrap();
    let state = build_state_htaccess(root.clone());
    let resp = run(&state, get(CANON_HOST, "/off.txt", None)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header_str(&resp, "x-probe"), None);
    assert_eq!(body_bytes(resp.into_body()).as_ref(), b"on\n");
    std::fs::remove_dir_all(root).ok();
}

/// (#943) A static 304 carries the expiresByType Cache-Control/Expires its 200
/// does, on dispatch() and on the on-core path alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_304_keeps_expires_by_type_headers() {
    let root = temp_root("expires-304");
    std::fs::write(root.join("a.txt"), b"expiring body").unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        false,
        None,
        None,
        |cfg| {
            cfg.expires = hj_core::config::ExpiresConfig {
                enabled: true,
                enable_declared: true,
                by_type: vec![("text/plain".into(), "A3600".into())],
            };
        },
    );
    let full = run(&state, get(CANON_HOST, "/a.txt", None)).await;
    assert_eq!(full.status(), 200);
    let cc = full.headers()[header::CACHE_CONTROL].clone();
    assert_eq!(cc, "public, max-age=3600");
    assert!(full.headers().contains_key(header::EXPIRES));
    let etag = full.headers()[header::ETAG].to_str().unwrap().to_owned();
    let lm = full.headers()[header::LAST_MODIFIED]
        .to_str()
        .unwrap()
        .to_owned();
    let revalidations = [
        get(CANON_HOST, "/a.txt", Some(&etag)),
        get_with(CANON_HOST, "/a.txt", &[("if-modified-since", &lm)]),
    ];
    for req in revalidations {
        let fast = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &req).await;
        let slow = run(&state, req).await;
        for resp in std::iter::once(slow).chain(fast) {
            assert_eq!(resp.status(), 304);
            assert_eq!(resp.headers()[header::CACHE_CONTROL], cc);
            assert!(resp.headers().contains_key(header::EXPIRES));
        }
    }
    std::fs::remove_dir_all(root).ok();
}

fn assert_expiry_headers(response: &Response, status: u16, cache_control: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CACHE_CONTROL], cache_control);
    assert!(response.headers().contains_key(header::EXPIRES));
}

async fn assert_htaccess_expiring_responses(state: Arc<ServerState>) {
    {
        let response = run(&state, get(CANON_HOST, "/robots.txt", None)).await;
        assert_expiry_headers(&response, 200, "public, max-age=172800");
    }
    {
        let response = run(&state, get(CANON_HOST, "/default.webmanifest", None)).await;
        assert_expiry_headers(&response, 200, "public, max-age=172800");
    }
    {
        let response = run(
            &state,
            get_with(
                CANON_HOST,
                "/default.webmanifest",
                &[("range", "bytes=0-1")],
            ),
        )
        .await;
        assert_expiry_headers(&response, 206, "public, max-age=172800");
    }

    let etag = {
        let response = run(&state, get(CANON_HOST, "/logo.png", None)).await;
        assert_expiry_headers(&response, 200, "public, max-age=31536000");
        response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned()
    };
    {
        let response = run(&state, get(CANON_HOST, "/logo.png", Some(&etag))).await;
        assert_expiry_headers(&response, 304, "public, max-age=31536000");
    }
    {
        let request = get(CANON_HOST, "/logo.png", Some(&etag));
        let response = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &request)
            .await
            .expect("static 304 serves on-core");
        assert_expiry_headers(&response, 304, "public, max-age=31536000");
    }
    {
        let response = run(&state, get(CANON_HOST, "/pinned.txt", None)).await;
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=7"
        );
        assert!(!response.headers().contains_key(header::EXPIRES));
    }
    {
        let response = run(
            &state,
            get_with(
                CANON_HOST,
                "/robots.txt",
                &[("authorization", "Basic eA==")],
            ),
        )
        .await;
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert!(!response.headers().contains_key(header::EXPIRES));
    }
    {
        let response = run(
            &state,
            get_with(CANON_HOST, "/robots.txt", &[("range", "bytes=0-1")]),
        )
        .await;
        assert_expiry_headers(&response, 206, "public, max-age=172800");
    }
    {
        let response = run(
            &state,
            get_with(CANON_HOST, "/logo.png", &[("range", "bytes=0-1")]),
        )
        .await;
        assert_expiry_headers(&response, 206, "public, max-age=31536000");
    }
}

async fn assert_htaccess_off_responses_and_memo(state: Arc<ServerState>) {
    for path in ["/admin/tokens/app.txt", "/builds/bg.webp"] {
        {
            let response = run(&state, get(CANON_HOST, path, None)).await;
            assert_eq!(response.status(), 200, "{path}");
            assert!(
                !response.headers().contains_key(header::CACHE_CONTROL),
                "{path}"
            );
            assert!(!response.headers().contains_key(header::EXPIRES), "{path}");
        }
        {
            let response = run(
                &state,
                get_with(CANON_HOST, path, &[("range", "bytes=0-1")]),
            )
            .await;
            assert_eq!(response.status(), 206, "{path}");
            assert!(
                !response.headers().contains_key(header::CACHE_CONTROL),
                "{path}"
            );
            assert!(!response.headers().contains_key(header::EXPIRES), "{path}");
        }
    }

    let hits_before = state
        .metrics
        .fast_memo_hits
        .load(std::sync::atomic::Ordering::Relaxed);
    for _ in 0..2 {
        let response = fast_serve_get(&state, "/admin/tokens/app.txt")
            .await
            .expect("static child serves on-core");
        assert!(!response.headers().contains_key(header::CACHE_CONTROL));
        assert!(!response.headers().contains_key(header::EXPIRES));
    }
    assert!(
        state
            .metrics
            .fast_memo_hits
            .load(std::sync::atomic::Ordering::Relaxed)
            > hits_before,
        "the ExpiresActive Off response was not replayed through fast memo"
    );
}

fn htaccess_expires_fixture() -> (PathBuf, Arc<ServerState>) {
    let root = temp_root("htaccess-expires");
    std::fs::create_dir_all(root.join("admin/tokens")).unwrap();
    std::fs::create_dir_all(root.join("builds")).unwrap();
    for (path, body) in [
        ("robots.txt", b"robots".as_slice()),
        ("logo.png", b"png"),
        ("pinned.txt", b"pinned"),
        ("default.webmanifest", b"manifest"),
        ("admin/tokens/app.txt", b"private"),
        ("builds/bg.webp", b"background"),
    ] {
        std::fs::write(root.join(path), body).unwrap();
    }
    std::fs::write(
        root.join(".htaccess"),
        r#"
<IfModule mod_expires.c>
ExpiresActive On
ExpiresByType image/png "access 1 year"
ExpiresByType text/plain "access 2 days"
ExpiresDefault "access 2 days"
</IfModule>
<LocationMatch "^/builds/">
ExpiresActive Off
</LocationMatch>
<Files "pinned.txt">
Header set Cache-Control "public, max-age=7"
</Files>
"#,
    )
    .unwrap();
    std::fs::write(root.join("admin/tokens/.htaccess"), "ExpiresActive Off\n").unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |config| {
            config.expires = hj_core::config::ExpiresConfig {
                enabled: true,
                enable_declared: true,
                by_type: vec![("text/plain".into(), "A60".into())],
            };
            config
                .mime
                .by_suffix
                .insert("png".into(), "image/png".into());
            config
                .mime
                .by_suffix
                .insert("webp".into(), "image/webp".into());
            config
                .mime
                .by_suffix
                .insert("webmanifest".into(), "application/manifest+json".into());
        },
    );

    (root, state)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn htaccess_expires_is_static_scoped_and_survives_fast_memo() {
    let (root, state) = htaccess_expires_fixture();
    tokio::spawn(assert_htaccess_off_responses_and_memo(state))
        .await
        .unwrap();
    std::fs::remove_dir_all(root).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn htaccess_expires_applies_default_type_status_and_precedence() {
    let (root, state) = htaccess_expires_fixture();
    tokio::spawn(assert_htaccess_expiring_responses(state))
        .await
        .unwrap();
    std::fs::remove_dir_all(root).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn htaccess_expires_rule_inherits_native_activation() {
    // Native exact and wildcard entries are both ExpiresByType MIME settings,
    // so each outranks the lower-level context's ExpiresDefault in OLS.
    for (server_enabled, vhost_enabled, native_glob, expected_age) in [
        (true, None, None, Some(172800)),
        (true, None, Some("text/plain"), Some(60)),
        (true, None, Some("*/*"), Some(60)),
        (false, None, None, None),
        (false, Some(true), None, Some(172800)),
    ] {
        let root = temp_root("htaccess-expires-native-parent");
        std::fs::create_dir_all(root.join("child")).unwrap();
        std::fs::write(root.join("child/a.txt"), b"body").unwrap();
        std::fs::write(root.join(".htaccess"), "# parent\n").unwrap();
        std::fs::write(
            root.join("child/.htaccess"),
            "ExpiresDefault \"access 2 days\"\n",
        )
        .unwrap();
        let state = build_state_inner(
            root.clone(),
            Vec::new(),
            Vec::new(),
            true,
            None,
            None,
            |config| {
                config.expires = hj_core::config::ExpiresConfig {
                    enabled: server_enabled,
                    enable_declared: true,
                    by_type: native_glob
                        .map(|glob| (glob.to_string(), "A60".into()))
                        .into_iter()
                        .collect(),
                };
                if let Some(enabled) = vhost_enabled {
                    let vhost = config
                        .vhosts
                        .get_mut(VHOST)
                        .unwrap()
                        .config
                        .as_mut()
                        .unwrap();
                    Arc::make_mut(vhost).expires = Some(hj_core::config::ExpiresConfig {
                        enabled,
                        enable_declared: true,
                        by_type: Vec::new(),
                    });
                }
            },
        );
        let response = run(&state, get(CANON_HOST, "/child/a.txt", None)).await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            expected_age
                .map(|age| format!("public, max-age={age}"))
                .as_deref(),
            "server_enabled={server_enabled} vhost_enabled={vhost_enabled:?} native_glob={native_glob:?}"
        );
        assert_eq!(
            response.headers().contains_key(header::EXPIRES),
            expected_age.is_some()
        );
        std::fs::remove_dir_all(root).ok();
    }

    let root = temp_root("htaccess-expires-turns-native-on");
    std::fs::create_dir_all(root.join("child")).unwrap();
    std::fs::write(root.join("child/a.txt"), b"body").unwrap();
    std::fs::write(root.join(".htaccess"), "# parent\n").unwrap();
    std::fs::write(root.join("child/.htaccess"), "ExpiresActive On\n").unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        None,
        None,
        |config| {
            config.expires = hj_core::config::ExpiresConfig {
                enabled: false,
                enable_declared: true,
                by_type: vec![("text/plain".into(), "A60".into())],
            };
        },
    );
    let response = run(&state, get(CANON_HOST, "/child/a.txt", None)).await;
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "public, max-age=60"
    );
    std::fs::remove_dir_all(root).ok();
}

/// (#944) The mime map's `default` type reaches served responses for a file
/// with no (or an unmapped) suffix, on both paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mime_default_type_serves_unknown_suffixes() {
    let root = temp_root("mime-default");
    std::fs::write(root.join("LICENSE"), b"license text").unwrap();
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        false,
        None,
        None,
        |cfg| cfg.mime.default_type = Some("text/plain".into()),
    );
    let slow = run(&state, get(CANON_HOST, "/LICENSE", None)).await;
    let fast = fast_serve_get(&state, "/LICENSE").await;
    for resp in std::iter::once(slow).chain(fast) {
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/plain");
    }
    std::fs::remove_dir_all(root).ok();
}

/// (#942) A future mtime never yields a Last-Modified past the request time,
/// and the old future date cannot pin a 304, on both paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn future_mtime_is_clamped_on_both_paths() {
    let root = temp_root("future-mtime");
    let path = root.join("f.txt");
    std::fs::write(&path, b"from the future").unwrap();
    let future = std::time::SystemTime::now() + std::time::Duration::from_secs(10 * 365 * 86_400);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(future)
        .unwrap();
    let state = build_state(root.clone());
    let before = std::time::SystemTime::now() - std::time::Duration::from_secs(1);
    let slow = run(&state, get(CANON_HOST, "/f.txt", None)).await;
    let fast = fast_serve_get(&state, "/f.txt").await;
    for resp in std::iter::once(slow).chain(fast) {
        assert_eq!(resp.status(), 200);
        let lm = httpdate::parse_http_date(resp.headers()[header::LAST_MODIFIED].to_str().unwrap())
            .unwrap();
        assert!(lm >= before && lm <= std::time::SystemTime::now(), "{lm:?}");
    }
    let ims = httpdate::fmt_http_date(future);
    let req = || get_with(CANON_HOST, "/f.txt", &[("if-modified-since", &ims)]);
    let fast = fast_serve_from(&state, IpAddr::V4(Ipv4Addr::LOCALHOST), &req()).await;
    let slow = run(&state, req()).await;
    for resp in std::iter::once(slow).chain(fast) {
        assert_eq!(resp.status(), 200);
    }
    std::fs::remove_dir_all(root).ok();
}

/// LSWS per-URL cookie vary through the full pipeline: `/` declares `X-LiteSpeed-Vary:
/// cookie=tz_date`, so each tz_date value (and its absence) gets its own entry and body;
/// `/plain` declares nothing and is shared across tz_date values; `/env` varies through the
/// rewrite env (`[E=Cache-Vary:tz_date]`). The on-core fast path agrees with dispatch, and
/// tag / global purges clear the variants.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_url_cookie_vary_keeps_variants_apart_end_to_end() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let renders = Arc::new(AtomicUsize::new(0));
    let upstream_renders = renders.clone();
    let upstream = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0_u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            upstream_renders.fetch_add(1, Ordering::SeqCst);
            let head = String::from_utf8_lossy(&head).into_owned();
            let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
            let date = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
                .flat_map(|(_, value)| value.split(';'))
                .find_map(|pair| pair.trim().strip_prefix("tz_date="))
                .unwrap_or("none")
                .to_owned();
            let body = format!("{path} date={date}");
            let reply = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });

    let root = temp_root("per-url-vary");
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "CacheLookup public on\n\
             RewriteEngine On\n\
             RewriteRule ^/$ http://{address}/home [P,L,E=VARY_HOME:1]\n\
             RewriteRule ^/plain$ http://{address}/plain [P,L]\n\
             RewriteRule ^/env$ http://{address}/env [P,L,E=Cache-Vary:tz_date]\n\
             Header set X-LiteSpeed-Cache-Control public,max-age=60\n\
             Header set X-LiteSpeed-Tag home\n\
             Header set X-LiteSpeed-Vary cookie=tz_date env=VARY_HOME\n"
        ),
    )
    .unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(
        hj_pagecache::StoreConfig::default(),
    ));
    let state = build_state_inner(
        root.clone(),
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |server| register_upstream(server, address),
    );
    let request = |path: &str, date: Option<&str>| {
        let mut req = get(CANON_HOST, path, None);
        if let Some(d) = date {
            req.headers_mut().insert(
                header::COOKIE,
                format!("xf_csrf=x; tz_date={d}").parse().unwrap(),
            );
        }
        req
    };
    let fetch = |path: &'static str, date: Option<&'static str>| {
        let state = state.clone();
        async move {
            let response = run(&state, request(path, date)).await;
            assert_eq!(response.status(), http::StatusCode::OK);
            assert!(!response.headers().contains_key("x-litespeed-vary"));
            let status = response
                .headers()
                .get("x-litespeed-cache")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let body = String::from_utf8(hop_body(response.into_body()).await).unwrap();
            (status, body)
        }
    };

    let dates = [Some("10-17"), Some("10-18"), None];
    for date in dates {
        let (status, body) = fetch("/", date).await;
        assert_ne!(
            status.as_deref(),
            Some("hit"),
            "{date:?} served another's entry"
        );
        assert_eq!(body, format!("/home date={}", date.unwrap_or("none")));
    }
    assert_eq!(renders.load(Ordering::SeqCst), 3);
    assert_eq!(store.url_vary_spec_count(), 1);
    for _ in 0..2 {
        for date in dates {
            let (status, body) = fetch("/", date).await;
            assert_eq!(status.as_deref(), Some("hit"), "{date:?}");
            assert_eq!(body, format!("/home date={}", date.unwrap_or("none")));
        }
    }
    assert_eq!(renders.load(Ordering::SeqCst), 3);

    // The on-core fast path (cookieless) serves the absent-date variant, as dispatch does.
    let fast = fast_serve_req(&state, &request("/", None))
        .await
        .expect("cookieless warm variant is served on-core");
    assert_eq!(
        String::from_utf8(hop_body(fast.into_body()).await).unwrap(),
        "/home date=none"
    );

    // A URL that never declares the vary keeps one shared entry.
    let (_, body) = fetch("/plain", Some("10-17")).await;
    assert_eq!(body, "/plain date=10-17");
    let (status, body) = fetch("/plain", Some("10-18")).await;
    assert_eq!(status.as_deref(), Some("hit"));
    assert_eq!(body, "/plain date=10-17");
    let (status, _) = fetch("/plain", None).await;
    assert_eq!(status.as_deref(), Some("hit"));

    // The rewrite env route varies the same way.
    for date in [Some("10-17"), Some("10-18")] {
        let (status, body) = fetch("/env", date).await;
        assert_ne!(status.as_deref(), Some("hit"));
        assert_eq!(body, format!("/env date={}", date.unwrap()));
    }
    for date in [Some("10-17"), Some("10-18")] {
        let (status, body) = fetch("/env", date).await;
        assert_eq!(status.as_deref(), Some("hit"));
        assert_eq!(body, format!("/env date={}", date.unwrap()));
    }

    // A tag purge clears every variant; purge-all clears the specs too.
    store.purge_tags(&["home"]);
    let before = renders.load(Ordering::SeqCst);
    let (status, body) = fetch("/", Some("10-18")).await;
    assert_ne!(status.as_deref(), Some("hit"));
    assert_eq!(body, "/home date=10-18");
    assert_eq!(renders.load(Ordering::SeqCst), before + 1);
    store.purge_all();
    assert_eq!(store.url_vary_spec_count(), 0);
    let (status, _) = fetch("/", Some("10-18")).await;
    assert_ne!(status.as_deref(), Some("hit"));
    let (status, body) = fetch("/", Some("10-17")).await;
    assert_ne!(status.as_deref(), Some("hit"));
    assert_eq!(body, "/home date=10-17");

    upstream.abort();
    std::fs::remove_dir_all(root).ok();
}
