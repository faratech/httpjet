//! httpjet configuration: object model + parser for LiteSpeed's XML config.
//!
//! Entry point: [`parse::load`] reads `conf/httpd_config.xml` under a server
//! root and every referenced vhost file, returning a normalized
//! [`model::ServerConfig`].

pub mod error;
pub mod model;
pub(crate) mod parse;
pub(crate) mod subst;
pub mod units;

pub use error::{ConfigError, Result};
pub use model::*;
pub use parse::load;

/// Whether a vhostMap `<domain>` token is a wildcard PATTERN httpjet does not support: it contains
/// a glob char (`*`/`?`) but is not the bare `*` catch-all (the only supported wildcard). Such a
/// pattern is stored as a literal exact key the router never matches, so those hosts fall to the
/// `*` default vhost — callers warn so it isn't a silent misconfiguration (OLS has a glob matcher;
/// httpjet deliberately does not — see hj_core's router).
pub fn is_unsupported_wildcard_domain(domain: &str) -> bool {
    domain != "*" && domain.bytes().any(|b| b == b'*' || b == b'?')
}

#[cfg(test)]
mod wildcard_domain_tests {
    use super::is_unsupported_wildcard_domain;
    #[test]
    fn classifies_wildcard_domains() {
        assert!(!is_unsupported_wildcard_domain("*")); // the supported catch-all
        assert!(!is_unsupported_wildcard_domain("example.com")); // plain exact domain
        assert!(!is_unsupported_wildcard_domain("news.forum.example"));
        assert!(is_unsupported_wildcard_domain("*.example.com")); // subdomain wildcard — unsupported
        assert!(is_unsupported_wildcard_domain("a?b.example.com")); // single-char glob — unsupported
        assert!(is_unsupported_wildcard_domain("foo*.example.com"));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    const LSWS_ROOT: &str = "/usr/local/lsws";

    fn live_config_available() -> bool {
        std::path::Path::new(LSWS_ROOT)
            .join("conf/httpd_config.xml")
            .exists()
    }

    #[test]
    fn parses_live_server_config() {
        if !live_config_available() {
            eprintln!("skipping: live LSWS config not present");
            return;
        }
        let cfg = load(LSWS_ROOT).expect("load live config");

        // Listeners: Default (:80) and TLS (:443, mTLS).
        assert!(
            cfg.listeners
                .iter()
                .any(|l| l.address.ends_with(":80") && !l.secure)
        );
        let tls = cfg
            .listeners
            .iter()
            .find(|l| l.secure)
            .expect("TLS listener present");
        let tls_cfg = tls.tls.as_ref().expect("TLS listener has tls config");
        // clientVerify=2 (mandatory mTLS) + Cloudflare CA.
        assert_eq!(tls_cfg.client_verify, 2, "mandatory mTLS expected");
        assert!(
            tls_cfg
                .ca_cert_file
                .as_ref()
                .map(|p| p.to_string_lossy().contains("cloudflare"))
                .unwrap_or(false),
            "Cloudflare origin-pull CA expected as client verifier"
        );

        // A wildcard default vhost is present.
        let default_map = tls
            .vhost_map
            .iter()
            .find(|m| m.domains.iter().any(|d| d == "*"));
        assert!(default_map.is_some(), "wildcard default vhost map expected");

        // php8 lsapi ext processor over UDS, plus proxy backends.
        let php = cfg
            .ext_processors
            .iter()
            .find(|e| e.kind == ExtKind::Lsapi)
            .expect("lsapi ext processor");
        assert!(matches!(php.address, ExtAddress::Uds(_)), "php8 over UDS");
        assert!(
            cfg.ext_processors.iter().any(|e| e.kind == ExtKind::Proxy
                && matches!(&e.address, ExtAddress::Tcp(sa) if sa.port() == 8002)),
            "mcp-api proxy backend on :8002 expected"
        );

        // PHP handler maps both php AND html (the static-server trap).
        let php_cfg = cfg.php_config.as_ref().expect("phpConfig present");
        // The backlog must track whatever the live XML's <phpConfig> declares
        // (default 1024 when absent) WITHOUT pinning the operator-tunable value
        // into the test suite. Scope the scan to the <phpConfig> block: the
        // config carries unrelated <backlog> elements (extProcessor, rails).
        let raw_config =
            std::fs::read_to_string(std::path::Path::new(LSWS_ROOT).join("conf/httpd_config.xml"))
                .expect("read live config XML");
        let expected_backlog = raw_config
            .split_once("<phpConfig>")
            .and_then(|(_, rest)| rest.split_once("</phpConfig>"))
            .and_then(|(block, _)| block.split_once("<backlog>"))
            .and_then(|(_, rest)| rest.split_once("</backlog>"))
            .and_then(|(value, _)| value.trim().parse::<u32>().ok())
            .unwrap_or(1024);
        assert_eq!(
            php_cfg.backlog, expected_backlog,
            "PHP backlog must flow from the live XML's <phpConfig> (or default to 1024)"
        );
        assert!(
            php_cfg.suffixes.iter().any(|s| s == "html"),
            ".html handled as PHP"
        );

        // Tuning sanity.
        assert_eq!(cfg.tuning.max_connections, 65000);
        assert!(cfg.quic_enable, "QUIC enabled server-wide");

        // Access control should include Cloudflare trusted ranges.
        assert!(
            cfg.security.access_control.iter().any(|r| r.trusted),
            "trusted (T) Cloudflare CIDRs expected"
        );
    }

    #[test]
    fn loads_vhost_files_with_subst() {
        if !live_config_available() {
            eprintln!("skipping: live LSWS config not present");
            return;
        }
        let cfg = load(LSWS_ROOT).expect("load");
        // A websocket vhost: docRoot != vhRoot, with inline rewrite rules.
        if let Some(decl) = cfg.vhosts.values().find(|decl| {
            decl.config
                .as_ref()
                .is_some_and(|vc| vc.websockets.iter().any(|w| w.uri == "/ws"))
        }) {
            let vc = decl.config.as_ref().expect("mcp vhost loaded");
            assert_eq!(vc.doc_root.to_string_lossy(), "/web/mcp-static");
            assert!(vc.rewrite.enable, "mcp inline rewrite enabled");
            assert!(!vc.rewrite.rules.is_empty(), "mcp has rewrite rules text");
            assert!(
                vc.rewrite.auto_load_htaccess,
                "mcp autoLoadHtaccess enables .htaccess (allowOverride unset)"
            );
            assert!(
                vc.websockets.iter().any(|w| w.uri == "/ws"),
                "mcp /ws websocket map expected"
            );
            // mcp static <context> with location override + extraHeaders.
            let c = vc
                .contexts
                .iter()
                .find(|c| c.uri == "/")
                .expect("mcp / static context");
            assert!(c.extra_headers.iter().any(|(k, _)| k == "Vary"));
            assert!(c.location.is_some(), "mcp static location override");
        }
        // Every vhost that enables .htaccess resolves its configured access-file name.
        for vc in cfg
            .vhosts
            .values()
            .filter_map(|decl| decl.config.as_ref())
            .filter(|vc| vc.htaccess_allowed())
        {
            assert_eq!(vc.access_file_name_or_default(), ".htaccess");
        }
        // A per-vhost scriptHandlerList maps php -> php8 (lsapi).
        if let Some(decl) = cfg.vhosts.values().find(|decl| {
            decl.config.as_ref().is_some_and(|vc| {
                vc.script_handlers
                    .iter()
                    .any(|sh| sh.suffix == "php" && sh.handler == "php8")
            })
        }) {
            let vc = decl.config.as_ref().expect("script-handler vhost loaded");
            assert!(
                vc.script_handlers
                    .iter()
                    .any(|sh| sh.suffix == "php" && sh.handler == "php8"),
                "vhost php->php8 scriptHandler expected"
            );
        }
        // A per-vhost extProcessorList exposes `stats_api` for proxy contexts.
        if let Some(decl) = cfg.vhosts.values().find(|decl| {
            decl.config.as_ref().is_some_and(|vc| {
                vc.extra_ext_processors
                    .iter()
                    .any(|processor| processor.name == "stats_api")
            })
        }) {
            let vc = decl.config.as_ref().expect("status vhost loaded");
            assert!(
                vc.extra_ext_processors
                    .iter()
                    .any(|e| e.name == "stats_api"),
                "status stats_api ext processor expected"
            );
        }
        // At least one vhost config should have loaded successfully.
        let loaded = cfg.vhosts.values().filter(|d| d.config.is_some()).count();
        assert!(loaded >= 1, "expected at least one vhost file to load");
    }

    #[test]
    fn empty_vhost_config_is_tolerated() {
        use crate::subst::SubstCtx;
        let ctx = SubstCtx {
            server_root: "/usr/local/lsws".into(),
            ..Default::default()
        };
        let vc = parse::parse_vhost_config("<virtualHostConfig/>", &ctx)
            .expect("empty vhost config parses");
        assert!(vc.doc_root.as_os_str().is_empty());
        assert!(!vc.rewrite.enable);
    }
}
