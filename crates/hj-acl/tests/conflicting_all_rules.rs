//! Regression: two conflicting ALL rules — deny wins regardless of order
//! (#808). OLS adds the allow list, then the deny list, and a later entry for
//! the same network overwrites the earlier one, so an equal-network tie denies.

use hj_acl::{AccessControl, AclDecision};
use hj_core::config::{AccessRule, Security};
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn acl_from_rules(rules: Vec<AccessRule>) -> AccessControl {
    AccessControl::from_security(&Security {
        follow_symlink: false,
        access_deny_dir: vec![],
        access_control: rules,
        cgi_cpu_limit_secs: None,
        ..Default::default()
    })
    .unwrap()
}

/// Two ALL rules: first says allow, second says deny. Deny wins.
#[test]
fn all_deny_wins_over_earlier_all_allow() {
    let acl = acl_from_rules(vec![
        AccessRule {
            spec: "ALL".into(),
            trusted: false,
            allow: true,
        },
        AccessRule {
            spec: "ALL".into(),
            trusted: false,
            allow: false,
        },
    ]);
    assert_eq!(acl.check_peer(ip("8.8.8.8")), AclDecision::Deny);
    assert_eq!(acl.check_peer(ip("203.0.113.1")), AclDecision::Deny);
}

/// Two ALL rules in deny-first order: deny still wins.
#[test]
fn first_all_deny_wins_over_second_allow() {
    let acl = acl_from_rules(vec![
        AccessRule {
            spec: "ALL".into(),
            trusted: false,
            allow: false,
        },
        AccessRule {
            spec: "ALL".into(),
            trusted: false,
            allow: true,
        },
    ]);
    assert_eq!(acl.check_peer(ip("8.8.8.8")), AclDecision::Deny);
    assert_eq!(acl.check_peer(ip("203.0.113.1")), AclDecision::Deny);
}

/// No rules at all: open default (LiteSpeed behavior when no ACL configured).
#[test]
fn no_rules_defaults_open() {
    let acl = acl_from_rules(vec![]);
    assert_eq!(acl.check_peer(ip("8.8.8.8")), AclDecision::Allow);
}

/// A specific CIDR overrides the ALL default regardless of which ALL variant
/// comes first, confirming most-specific-first ordering still applies.
#[test]
fn specific_cidr_beats_all_rule() {
    let acl = acl_from_rules(vec![
        AccessRule {
            spec: "ALL".into(),
            trusted: false,
            allow: true,
        },
        AccessRule {
            spec: "10.0.0.0/24".into(),
            trusted: false,
            allow: false,
        },
    ]);
    assert_eq!(acl.check_peer(ip("10.0.0.1")), AclDecision::Deny);
    assert_eq!(acl.check_peer(ip("10.0.1.1")), AclDecision::Allow);
}
