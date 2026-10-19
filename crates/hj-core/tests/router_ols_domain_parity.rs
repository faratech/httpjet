//! Regression (#940): vhostMap domains follow OLS `mapDomainList` — a configured `www.` is
//! stripped for the lookup key (so the bare apex routes too), a `:port` is ignored, and a
//! domain mapped twice keeps its FIRST vhost.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use hj_core::Router;
use hj_core::config::{Listener, MimeMap, ServerConfig, Tuning, VHostConfig, VHostDecl, VhostMap};

fn router(maps: &[(&str, &[&str])]) -> Router {
    let listener = Listener {
        name: "l".into(),
        address: "*:80".into(),
        secure: false,
        proxy_protocol: false,
        proxy_protocol_peers: vec![],
        uds_path: None,
        vhost_map: maps
            .iter()
            .map(|(vhost, domains)| VhostMap {
                vhost: (*vhost).into(),
                domains: domains.iter().map(|d| (*d).to_string()).collect(),
            })
            .collect(),
        tls: None,
    };
    let mut vhosts = BTreeMap::new();
    for (vhost, _) in maps {
        vhosts.insert(
            (*vhost).to_string(),
            VHostDecl {
                name: (*vhost).into(),
                vh_root: PathBuf::from("/tmp"),
                config_file: PathBuf::from("/tmp/vhost.xml"),
                allow_symbol_link: None,
                restrained: false,
                enable_script: false,
                config: Some(Arc::new(VHostConfig::default())),
            },
        );
    }
    Router::build(Arc::new(ServerConfig {
        server_root: PathBuf::from("/tmp"),
        server_name: "test".into(),
        user: "nobody".into(),
        group: "nobody".into(),
        index_files: vec![],
        tuning: Tuning::default(),
        quic_enable: false,
        use_ip_in_proxy_header: 0,
        expires: Default::default(),
        cache: Default::default(),
        security: Default::default(),
        suexec: Default::default(),
        ext_processors: vec![],
        php_config: None,
        listeners: vec![listener],
        vhosts,
        vhost_order: vec![],
        mime: MimeMap {
            by_suffix: BTreeMap::new(),
            default_type: None,
        },
    }))
}

fn resolved(r: &Router, host: &str) -> String {
    r.resolve("l", Some(host)).unwrap().name
}

#[test]
fn configured_www_also_maps_the_bare_domain() {
    let r = router(&[("b", &["www.b.test"]), ("d", &["*"])]);
    assert_eq!(resolved(&r, "b.test"), "b");
    assert_eq!(resolved(&r, "www.b.test"), "b");
    // Both spellings are configured mappings, not catch-all fallbacks.
    assert!(r.host_is_exact("l", "b.test"));
    assert!(r.host_is_exact("l", "www.b.test"));
    assert!(r.host_maps_to_vhost("b.test", "b"));
}

#[test]
fn unconfigured_www_of_a_mapped_apex_stays_a_fallback() {
    let r = router(&[("a", &["a.test"]), ("d", &["*"])]);
    assert_eq!(resolved(&r, "www.a.test"), "a");
    assert!(!r.host_is_exact("l", "www.a.test"));
}

#[test]
fn configured_port_is_ignored() {
    let r = router(&[("c", &["csite.test:8080"]), ("d", &["*"])]);
    assert_eq!(resolved(&r, "csite.test"), "c");
    assert_eq!(resolved(&r, "csite.test:8080"), "c");
    assert!(r.host_is_exact("l", "csite.test"));
}

#[test]
fn duplicate_exact_domain_keeps_the_first_mapping() {
    let r = router(&[
        ("first", &["dup.test"]),
        ("second", &["dup.test"]),
        ("third", &["www.dup.test"]),
        ("d", &["*"]),
    ]);
    assert_eq!(resolved(&r, "dup.test"), "first");
    assert_eq!(resolved(&r, "www.dup.test"), "first");
    assert!(!r.host_maps_to_vhost("www.dup.test", "third"));
}
