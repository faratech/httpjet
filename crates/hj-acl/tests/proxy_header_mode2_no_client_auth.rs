//! Regression (post-#16): under `useIpInProxyHeader=2`, a trusted Cloudflare peer's
//! `CF-Connecting-IP` MUST be honored whenever the connection is mTLS-trusted
//! (`mtls_ok=true`). Production runs `--no-mtls` (clientVerify=0, no client cert ever
//! presented), and the corrected pipeline passes `mtls_ok=true` for those TLS
//! connections (trust = network boundary). A prior fix made `mtls_ok` require a
//! presented cert unconditionally, so `mtls_ok` was false for 100% of `:443` traffic
//! and every visitor resolved to the Cloudflare edge IP. This pins the contract that
//! `resolve_client_ip` mode 2 honors the header exactly when `mtls_ok` is true.

use hj_acl::AccessControl;
use hj_core::config::{AccessRule, Security};
use http::HeaderMap;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// allow-ALL + a trusted CF range (173.245.48.0/20).
fn acl_with_cf_trusted() -> AccessControl {
    let rules = vec![
        AccessRule {
            spec: "ALL".into(),
            trusted: false,
            allow: true,
        },
        AccessRule {
            spec: "173.245.48.0/20".into(),
            trusted: true,
            allow: true,
        },
    ];
    AccessControl::from_security(&Security {
        follow_symlink: false,
        access_deny_dir: vec![],
        access_control: rules,
        cgi_cpu_limit_secs: None,
        ..Default::default()
    })
    .unwrap()
}

/// Mode 2, trusted CF peer, mtls_ok=true (the --no-mtls / network-boundary-trust case):
/// the authoritative CF-Connecting-IP is honored — the visitor's real IP, not the CF edge IP.
#[test]
fn mode2_trusted_peer_with_mtls_ok_honors_cf_connecting_ip() {
    let acl = acl_with_cf_trusted();
    let cf_peer = ip("173.245.48.10"); // inside the trusted CF range

    let mut h = HeaderMap::new();
    h.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap()); // the real visitor

    let resolved = acl.resolve_client_ip(cf_peer, &h, 2, /* mtls_ok */ true);
    assert_eq!(
        resolved,
        ip("203.0.113.7"),
        "mode 2 + trusted peer + mtls_ok must resolve to CF-Connecting-IP, not the CF edge peer"
    );
}

/// Mode 2, trusted CF peer, mtls_ok=FALSE (clientVerify=2 listener, no cert presented):
/// the header is NOT honored — this is the #16 hardening (a cert-less peer is untrusted).
#[test]
fn mode2_without_mtls_ok_falls_back_to_peer() {
    let acl = acl_with_cf_trusted();
    let cf_peer = ip("173.245.48.10");

    let mut h = HeaderMap::new();
    h.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());

    let resolved = acl.resolve_client_ip(cf_peer, &h, 2, /* mtls_ok */ false);
    assert_eq!(
        resolved, cf_peer,
        "mode 2 without mtls_ok must NOT honor the forwarded header (cert-less peer is untrusted)"
    );
}

/// Mode 2, mtls_ok=true, but the peer is NOT trusted: still falls back to peer
/// (both is_trusted(peer) AND mtls_ok are required).
#[test]
fn mode2_untrusted_peer_falls_back_even_with_mtls_ok() {
    let acl = acl_with_cf_trusted();
    let untrusted = ip("8.8.8.8");

    let mut h = HeaderMap::new();
    h.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());

    let resolved = acl.resolve_client_ip(untrusted, &h, 2, true);
    assert_eq!(
        resolved, untrusted,
        "an untrusted peer's forwarded header is never honored"
    );
}
