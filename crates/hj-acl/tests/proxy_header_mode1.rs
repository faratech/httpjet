//! Regression: mode 1 (use_ip_in_proxy_header=1) must NOT honor CF-Connecting-IP
//! from untrusted peers — only leftmost-untrusted XFF semantics, matching OLS mode 1.
//! Mode 2 still requires is_trusted && mtls_ok before consulting any header.

use hj_acl::AccessControl;
use hj_core::config::{AccessRule, Security};
use http::HeaderMap;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Security with allow-ALL and a trusted CF range (173.245.48.0/20).
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
    })
}

/// Mode 1 with CF-Connecting-IP set by an untrusted peer: the header must be
/// ignored; only XFF is consulted (OLS mode-1 parity — CF-header is modes 2/3).
#[test]
fn mode1_cf_connecting_ip_from_untrusted_peer_is_ignored() {
    let acl = acl_with_cf_trusted();
    let untrusted_peer = ip("8.8.8.8");

    let mut h = HeaderMap::new();
    // Attacker tries to spoof client_ip via CF-Connecting-IP.
    h.insert("cf-connecting-ip", "1.2.3.4".parse().unwrap());
    // XFF carries a different value.
    h.insert("x-forwarded-for", "5.6.7.8".parse().unwrap());

    let resolved = acl.resolve_client_ip(untrusted_peer, &h, 1, false);
    // CF-Connecting-IP must NOT be used; XFF leftmost-untrusted is used instead.
    assert_ne!(
        resolved,
        ip("1.2.3.4"),
        "CF-Connecting-IP must not be honored in mode 1"
    );
    assert_eq!(
        resolved,
        ip("5.6.7.8"),
        "mode 1 should use leftmost-untrusted XFF"
    );
}

/// Mode 1 with only CF-Connecting-IP (no XFF): falls back to peer since
/// CF-Connecting-IP is not consulted and there is no XFF to read.
#[test]
fn mode1_cf_connecting_ip_only_falls_back_to_peer() {
    let acl = acl_with_cf_trusted();
    let untrusted_peer = ip("8.8.8.8");

    let mut h = HeaderMap::new();
    h.insert("cf-connecting-ip", "1.2.3.4".parse().unwrap());
    // No XFF header at all.

    let resolved = acl.resolve_client_ip(untrusted_peer, &h, 1, false);
    assert_eq!(
        resolved, untrusted_peer,
        "mode 1 with no XFF should fall back to peer"
    );
}

/// Mode 1 with XFF from an untrusted peer: leftmost untrusted entry is used.
#[test]
fn mode1_xff_leftmost_untrusted_used() {
    let acl = acl_with_cf_trusted();
    let untrusted_peer = ip("8.8.8.8");

    // Left side is real client; right is a non-trusted hop that appended itself.
    let mut h = HeaderMap::new();
    h.insert(
        "x-forwarded-for",
        "203.0.113.42, 192.0.2.1".parse().unwrap(),
    );

    let resolved = acl.resolve_client_ip(untrusted_peer, &h, 1, false);
    assert_eq!(resolved, ip("203.0.113.42"));
}

/// Mode 2 still requires is_trusted && mtls_ok; an untrusted peer is ignored.
#[test]
fn mode2_untrusted_peer_ignores_all_headers() {
    let acl = acl_with_cf_trusted();
    let untrusted_peer = ip("8.8.8.8");

    let mut h = HeaderMap::new();
    h.insert("cf-connecting-ip", "1.2.3.4".parse().unwrap());
    h.insert("x-forwarded-for", "5.6.7.8".parse().unwrap());

    let resolved = acl.resolve_client_ip(untrusted_peer, &h, 2, true);
    assert_eq!(
        resolved, untrusted_peer,
        "mode 2 with untrusted peer must return peer"
    );
}

/// Mode 2 with a trusted peer + mTLS: CF-Connecting-IP is honored.
#[test]
fn mode2_trusted_peer_mtls_ok_honors_cf_connecting_ip() {
    let acl = acl_with_cf_trusted();
    let trusted_peer = ip("173.245.48.5");

    let mut h = HeaderMap::new();
    h.insert("cf-connecting-ip", "198.51.100.42".parse().unwrap());
    h.insert("x-forwarded-for", "5.6.7.8".parse().unwrap());

    let resolved = acl.resolve_client_ip(trusted_peer, &h, 2, true);
    assert_eq!(
        resolved,
        ip("198.51.100.42"),
        "mode 2 trusted+mtls must honor CF-Connecting-IP"
    );
}

/// Mode 2 with a trusted peer but mTLS failed: no headers honored.
#[test]
fn mode2_trusted_peer_mtls_fail_returns_peer() {
    let acl = acl_with_cf_trusted();
    let trusted_peer = ip("173.245.48.5");

    let mut h = HeaderMap::new();
    h.insert("cf-connecting-ip", "198.51.100.42".parse().unwrap());

    let resolved = acl.resolve_client_ip(trusted_peer, &h, 2, false);
    assert_eq!(
        resolved, trusted_peer,
        "mode 2 trusted but mTLS fail must return peer"
    );
}
