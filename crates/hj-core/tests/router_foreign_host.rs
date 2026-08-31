//! Regression test for the publisher.example cross-host page-cache leak.
//!
//! `www.publisher.example` is in no `<vhostMap>`, so it falls through the `*` catch-all to
//! the `forum.example` default vhost. The page cache keys by the resolved vhost, so
//! without a foreign-host guard a `www.publisher.example` request was served (and populated)
//! the forum.example homepage cache entry — masking XenForo's canonical 301 and leaking
//! one brand's page under another's hostname. `Router::host_is_exact` is the discriminator
//! that lets the cache tell a configured hostname from a foreign catch-all Host.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use hj_core::Router;
use hj_core::config::{Listener, MimeMap, ServerConfig, Tuning, VHostConfig, VHostDecl, VhostMap};

fn make_server(listeners: Vec<Listener>, vhosts: BTreeMap<String, VHostDecl>) -> Arc<ServerConfig> {
    Arc::new(ServerConfig {
        server_root: PathBuf::from("/tmp"),
        server_name: "test".into(),
        user: "nobody".into(),
        group: "nobody".into(),
        index_files: vec!["index.html".into()],
        tuning: Tuning::default(),
        quic_enable: false,
        use_ip_in_proxy_header: 0,
        expires: Default::default(),
        cache: Default::default(),
        security: Default::default(),
        suexec: Default::default(),
        ext_processors: vec![],
        php_config: None,
        listeners,
        vhosts,
        vhost_order: vec![],
        mime: MimeMap {
            by_suffix: BTreeMap::new(),
        },
    })
}

fn make_vhost_decl(name: &str) -> VHostDecl {
    VHostDecl {
        name: name.into(),
        vh_root: PathBuf::from("/tmp"),
        config_file: PathBuf::from("/tmp/vhost.xml"),
        allow_symbol_link: None,
        restrained: false,
        enable_script: false,
        config: Some(Arc::new(VHostConfig::default())),
    }
}

/// Representative listener: an exact-mapped `publisher.example` (+ its `news.` alias) and
/// a `*` catch-all → `forum.example`, plus an explicitly-configured `www.tenant.example` alias.
fn build_router() -> Router {
    let listener = Listener {
        name: "tls".into(),
        address: "0.0.0.0:443".into(),
        secure: true,
        proxy_protocol: false,
        uds_path: None,
        vhost_map: vec![
            VhostMap {
                vhost: "publisher.example".into(),
                domains: vec!["publisher.example".into(), "news.forum.example".into()],
            },
            VhostMap {
                vhost: "tenant.example".into(),
                domains: vec!["tenant.example".into(), "www.tenant.example".into()],
            },
            VhostMap {
                vhost: "forum.example".into(),
                domains: vec!["*".into()],
            },
        ],
        tls: None,
    };
    let mut vhosts = BTreeMap::new();
    vhosts.insert(
        "publisher.example".into(),
        make_vhost_decl("publisher.example"),
    );
    vhosts.insert("tenant.example".into(), make_vhost_decl("tenant.example"));
    vhosts.insert("forum.example".into(), make_vhost_decl("forum.example"));
    Router::build(make_server(vec![listener], vhosts))
}

#[test]
fn configured_domains_are_exact() {
    let r = build_router();
    // Every explicitly-listed vhostMap domain is an exact match — cacheable as itself.
    assert!(r.host_is_exact("tls", "publisher.example"));
    assert!(r.host_is_exact("tls", "news.forum.example"));
    assert!(r.host_is_exact("tls", "tenant.example"));
    // A `www.` that is explicitly listed (www.tenant.example) stays exact → still cacheable.
    assert!(r.host_is_exact("tls", "www.tenant.example"));
}

#[test]
fn foreign_catchall_host_is_not_exact() {
    let r = build_router();
    // The leak: www.publisher.example is in NO vhostMap, so it is NOT an exact match — it only
    // reaches a vhost via fallback/wildcard. This is what flags it for cache bypass + CF
    // de-cache (the pipeline treats `!host_is_exact && != vhost_name` as foreign).
    assert!(!r.host_is_exact("tls", "www.publisher.example"));
}

#[test]
fn www_subdomain_falls_back_to_parent_vhost_not_the_global_wildcard() {
    let r = build_router();
    // The fix: www.publisher.example is unmapped, but its parent publisher.example IS mapped, so it
    // routes to the publisher.example vhost (whose app then 301s www→non-www to its OWN root) —
    // NOT to the forum.example `*` catch-all (the regression). Still non-canonical (not
    // exact), so the cache/CF layers treat it as foreign.
    assert_eq!(
        r.resolve("tls", Some("www.publisher.example"))
            .unwrap()
            .name,
        "publisher.example"
    );
    assert!(!r.host_is_exact("tls", "www.publisher.example"));
}

#[test]
fn deep_subdomain_falls_back_iteratively_to_nearest_mapped_parent() {
    let r = build_router();
    // Iterative fallback: a.b.publisher.example → b.publisher.example (unmapped) → publisher.example
    // (mapped) wins. Only an explicitly-configured parent can be matched.
    assert_eq!(
        r.resolve("tls", Some("a.b.publisher.example"))
            .unwrap()
            .name,
        "publisher.example"
    );
}

#[test]
fn subdomain_of_a_wildcard_only_apex_still_falls_to_the_wildcard() {
    let r = build_router();
    // forum.example is mapped only via `*` (not an exact domain), so www.forum.example
    // has no exact parent to fall back to and correctly lands on the `*` default — where the
    // backend canonical-redirects it. No surprise routing.
    assert_eq!(
        r.resolve("tls", Some("www.forum.example")).unwrap().name,
        "forum.example"
    );
}

#[test]
fn unrelated_host_with_no_mapped_parent_uses_the_wildcard_default() {
    let r = build_router();
    // foo.bar.baz has no configured parent anywhere → `*` default. And the one-label-with-a-dot
    // guard means a bare registry suffix is never looked up: x.com → parent "com" (no dot) →
    // default, never a "com" vhost (there is none, but this proves the guard).
    assert_eq!(
        r.resolve("tls", Some("foo.bar.baz")).unwrap().name,
        "forum.example"
    );
    assert_eq!(
        r.resolve("tls", Some("anything.com")).unwrap().name,
        "forum.example"
    );
}

#[test]
fn explicit_www_alias_and_apex_resolve_exactly_no_fallback() {
    let r = build_router();
    // www.tenant.example is explicitly mapped → exact (cacheable), not a fallback.
    assert_eq!(
        r.resolve("tls", Some("www.tenant.example")).unwrap().name,
        "tenant.example"
    );
    assert!(r.host_is_exact("tls", "www.tenant.example"));
    // Bare exact domains and the configured alias resolve directly.
    assert_eq!(
        r.resolve("tls", Some("publisher.example")).unwrap().name,
        "publisher.example"
    );
    assert_eq!(
        r.resolve("tls", Some("news.forum.example")).unwrap().name,
        "publisher.example"
    );
}

#[test]
fn default_vhost_canonical_name_is_not_exact_but_resolves_to_itself() {
    let r = build_router();
    // forum.example is mapped only via `*`, so it is not an "exact" domain. The pipeline
    // pairs `host_is_exact` with a `host == vhost_name` check so the default vhost's OWN
    // homepage stays cacheable; this asserts the routing half of that pairing.
    assert!(!r.host_is_exact("tls", "forum.example"));
    assert_eq!(
        r.resolve("tls", Some("forum.example")).unwrap().name,
        "forum.example"
    );
}

#[test]
fn host_is_exact_is_case_insensitive_and_listener_scoped() {
    let r = build_router();
    assert!(r.host_is_exact("tls", "Publisher.Example"));
    // Unknown listener name never matches.
    assert!(!r.host_is_exact("does-not-exist", "publisher.example"));
}

fn make_unloaded_vhost_decl(name: &str) -> VHostDecl {
    VHostDecl {
        config: None,
        ..make_vhost_decl(name)
    }
}

#[test]
fn mapped_vhost_with_unloaded_config_is_known_but_unloaded() {
    // Regression (#4): a vhost that is mapped but whose per-vhost file failed to load (config==None)
    // must be distinguishable from an unknown host. resolve() returns None for it (it does NOT fall
    // back to the `*` default once the name matched), but host_known_but_unloaded() is true — so the
    // pipeline serves a loud 503 (misconfigured) instead of a silent, misattributed 404.
    let listener = Listener {
        name: "tls".into(),
        address: "0.0.0.0:443".into(),
        secure: true,
        proxy_protocol: false,
        uds_path: None,
        vhost_map: vec![
            VhostMap {
                vhost: "broken.example.com".into(),
                domains: vec!["broken.example.com".into()],
            },
            VhostMap {
                vhost: "forum.example".into(),
                domains: vec!["*".into()],
            },
        ],
        tls: None,
    };
    let mut vhosts = BTreeMap::new();
    vhosts.insert(
        "broken.example.com".into(),
        make_unloaded_vhost_decl("broken.example.com"),
    );
    vhosts.insert("forum.example".into(), make_vhost_decl("forum.example"));
    let r = Router::build(make_server(vec![listener], vhosts));

    // Mapped-but-broken host: resolve fails AND it is flagged known-but-unloaded (→ 503).
    assert!(r.resolve("tls", Some("broken.example.com")).is_none());
    assert!(r.host_known_but_unloaded("tls", Some("broken.example.com")));
    // A healthy host (the loaded `*` default) is NOT flagged — it resolves and serves normally.
    assert!(
        r.resolve("tls", Some("anything-else.example.org"))
            .is_some()
    );
    assert!(!r.host_known_but_unloaded("tls", Some("anything-else.example.org")));
    // An unknown listener is never "known but unloaded".
    assert!(!r.host_known_but_unloaded("nope", Some("broken.example.com")));
}
