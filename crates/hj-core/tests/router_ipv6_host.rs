//! Regression test: Router::resolve must correctly route IPv6-literal Host
//! headers ([::1]:443, [2606:4700::1111]:443) to the matching vhost instead of
//! silently falling through to the wildcard default. The old split(':').next()
//! path truncated "[::1]:443" to "[", which never matched any vhost entry.

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
        allow_symbol_link: false,
        enable_script: false,
        config: Some(Arc::new(VHostConfig::default())),
    }
}

/// Build a router with one listener named "default" that maps:
///   - `::1`   -> "ipv6loopback" vhost
///   - `*`     -> "wildcard"     vhost
fn build_router() -> Router {
    let listener = Listener {
        name: "default".into(),
        address: "0.0.0.0:443".into(),
        secure: true,
        vhost_map: vec![
            VhostMap {
                vhost: "ipv6loopback".into(),
                domains: vec!["::1".into()],
            },
            VhostMap {
                vhost: "wildcard".into(),
                domains: vec!["*".into()],
            },
        ],
        tls: None,
    };

    let mut vhosts = BTreeMap::new();
    vhosts.insert("ipv6loopback".into(), make_vhost_decl("ipv6loopback"));
    vhosts.insert("wildcard".into(), make_vhost_decl("wildcard"));

    let server = make_server(vec![listener], vhosts);
    Router::build(server)
}

#[test]
fn ipv6_bracketed_with_port_routes_to_correct_vhost() {
    let router = build_router();
    // [::1]:443 must match the "::1" entry, not fall to wildcard.
    let resolved = router.resolve("default", Some("[::1]:443"));
    assert!(resolved.is_some(), "should resolve, not return None");
    assert_eq!(
        resolved.unwrap().name,
        "ipv6loopback",
        "[::1]:443 must route to ipv6loopback, not wildcard"
    );
}

#[test]
fn ipv6_bracketed_no_port_routes_to_correct_vhost() {
    let router = build_router();
    // [::1] with no port must also match the "::1" entry.
    let resolved = router.resolve("default", Some("[::1]"));
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().name, "ipv6loopback");
}

#[test]
fn ipv6_with_port_does_not_fall_to_wildcard() {
    let router = build_router();
    // A host not in the map should fall back to wildcard (sanity check that
    // the fallback itself still works after the fix).
    let resolved = router.resolve("default", Some("unknown.example.com:443"));
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().name, "wildcard");
}

#[test]
fn hostname_with_port_still_routes_correctly() {
    // Plain hostname:port normalisation must still work after the refactor.
    let listener = Listener {
        name: "http".into(),
        address: "0.0.0.0:80".into(),
        secure: false,
        vhost_map: vec![
            VhostMap {
                vhost: "forum".into(),
                domains: vec!["forum.example".into()],
            },
            VhostMap {
                vhost: "wildcard".into(),
                domains: vec!["*".into()],
            },
        ],
        tls: None,
    };
    let mut vhosts = BTreeMap::new();
    vhosts.insert("forum".into(), make_vhost_decl("forum"));
    vhosts.insert("wildcard".into(), make_vhost_decl("wildcard"));
    let server = make_server(vec![listener], vhosts);
    let router = Router::build(server);

    // With explicit :80 port in the Host header.
    let r = router.resolve("http", Some("forum.example:80"));
    assert!(r.is_some());
    assert_eq!(r.unwrap().name, "forum");

    // Without port.
    let r2 = router.resolve("http", Some("forum.example"));
    assert!(r2.is_some());
    assert_eq!(r2.unwrap().name, "forum");
}

#[test]
fn host_without_port_ipv6_cases() {
    // Direct unit-level checks on the helper used by Router::resolve.
    use hj_core::net::host_without_port;

    assert_eq!(host_without_port("[::1]:443"), "::1");
    assert_eq!(host_without_port("[::1]"), "::1");
    assert_eq!(
        host_without_port("[2606:4700::1111]:443"),
        "2606:4700::1111"
    );
    // Plain hostname with port.
    assert_eq!(host_without_port("example.com:8080"), "example.com");
    // Trailing-dot stripping.
    assert_eq!(host_without_port("example.com."), "example.com");
    // Uppercase is lowercased.
    assert_eq!(host_without_port("Example.COM:443"), "example.com");
}
