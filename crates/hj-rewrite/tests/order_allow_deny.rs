//! Legacy mod_access (`Order` / `Allow from` / `Deny from`) must RESTRICT, not
//! silently vanish (#359): every non-`all` operand form used to be dropped, so
//! an `Order allow,deny` + `Allow from <cidr>` lockdown served to the world.

use std::net::IpAddr;

use hj_rewrite::{AccessDecision, AccessSubject, Htaccess};

fn subject(ip: &str) -> AccessSubject<'static> {
    AccessSubject {
        client_ip: Some(ip.parse::<IpAddr>().unwrap()),
        env_set: None,
    }
}

#[test]
fn order_allow_deny_with_cidr_allow_denies_everyone_else() {
    let h = Htaccess::parse("Order allow,deny\nAllow from 203.0.113.0/24\n").unwrap();
    assert_eq!(
        h.access_decision_for("/admin/", "GET", &subject("203.0.113.9")),
        AccessDecision::Granted
    );
    assert_eq!(
        h.access_decision_for("/admin/", "GET", &subject("198.51.100.1")),
        AccessDecision::Denied
    );
    // The subject-less API (no client IP) fails closed.
    assert_eq!(h.access_decision("/admin/", "GET"), AccessDecision::Denied);
    assert!(h.is_forbidden("/admin/index.php", "index.php"));
}

#[test]
fn order_deny_allow_with_ip_deny_bans_only_that_ip() {
    let h = Htaccess::parse("Order deny,allow\nDeny from 198.51.100.7 10.0\n").unwrap();
    assert_eq!(
        h.access_decision_for("/x", "GET", &subject("198.51.100.7")),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision_for("/x", "GET", &subject("10.0.44.5")),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision_for("/x", "GET", &subject("192.0.2.1")),
        AccessDecision::Granted
    );
}

#[test]
fn bad_bot_env_idiom_denies_when_setenvif_marked() {
    let h = Htaccess::parse(
        "SetEnvIfNoCase User-Agent \"badbot\" bad_bot\nOrder allow,deny\nAllow from all\nDeny from env=bad_bot\n",
    )
    .unwrap();
    let marked = |n: &str| n == "bad_bot";
    let clean = |_: &str| false;
    assert_eq!(
        h.access_decision_for(
            "/x",
            "GET",
            &AccessSubject {
                client_ip: Some("192.0.2.1".parse().unwrap()),
                env_set: Some(&marked),
            }
        ),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision_for(
            "/x",
            "GET",
            &AccessSubject {
                client_ip: Some("192.0.2.1".parse().unwrap()),
                env_set: Some(&clean),
            }
        ),
        AccessDecision::Granted
    );
}

#[test]
fn hostname_operands_fail_closed() {
    let allow = Htaccess::parse("Order allow,deny\nAllow from .corp.example\n").unwrap();
    assert_eq!(
        allow.access_decision_for("/x", "GET", &subject("192.0.2.1")),
        AccessDecision::Denied
    );
    let deny = Htaccess::parse("Order deny,allow\nDeny from evil.example\n").unwrap();
    assert_eq!(
        deny.access_decision_for("/x", "GET", &subject("192.0.2.1")),
        AccessDecision::Denied
    );
}

#[test]
fn scoped_blocks_keep_their_own_order() {
    // The /web/mfara idiom: a per-file `Order allow,deny` + `Allow from all`
    // grant next to a per-file `Deny from all`.
    let h = Htaccess::parse(
        "<Files \"maintenance-config.json\">\nOrder allow,deny\nAllow from all\n</Files>\n\
         <FilesMatch \"\\.(env|lock)$\">\nOrder allow,deny\nDeny from all\n</FilesMatch>\n",
    )
    .unwrap();
    let s = subject("192.0.2.1");
    assert_eq!(
        h.access_decision_for("/maintenance-config.json", "GET", &s),
        AccessDecision::Granted
    );
    assert_eq!(
        h.access_decision_for("/.env", "GET", &s),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision_for("/other.txt", "GET", &s),
        AccessDecision::NoOpinion
    );
}

#[test]
fn order_allow_deny_with_no_allow_denies_all_and_deny_beats_allow() {
    let bare = Htaccess::parse("Order allow,deny\n").unwrap();
    assert_eq!(
        bare.access_decision_for("/x", "GET", &subject("192.0.2.1")),
        AccessDecision::Denied
    );
    let both = Htaccess::parse("Order allow,deny\nDeny from all\nAllow from all\n").unwrap();
    assert_eq!(
        both.access_decision_for("/x", "GET", &subject("192.0.2.1")),
        AccessDecision::Denied
    );
}

#[test]
fn legacy_from_all_forms_are_unchanged() {
    let deny = Htaccess::parse("Order deny,allow\nDeny from all\n").unwrap();
    assert_eq!(
        deny.access_decision("/anything", "GET"),
        AccessDecision::Denied
    );
    let allow = Htaccess::parse("Allow from all\n").unwrap();
    assert_eq!(allow.access_decision("/x", "GET"), AccessDecision::Granted);
    let top_deny_file_allow =
        Htaccess::parse("Deny from all\n<Files \"pub.txt\">\nAllow from all\n</Files>\n").unwrap();
    assert_eq!(
        top_deny_file_allow.access_decision("/pub.txt", "GET"),
        AccessDecision::Granted
    );
    assert_eq!(
        top_deny_file_allow.access_decision("/secret.txt", "GET"),
        AccessDecision::Denied
    );
}

#[test]
fn ipv6_and_mapped_peers() {
    let h = Htaccess::parse("Order allow,deny\nAllow from 2001:db8::/32 203.0.113.5\n").unwrap();
    assert_eq!(
        h.access_decision_for("/x", "GET", &subject("2001:db8:1::7")),
        AccessDecision::Granted
    );
    assert_eq!(
        h.access_decision_for("/x", "GET", &subject("::ffff:203.0.113.5")),
        AccessDecision::Granted
    );
    assert_eq!(
        h.access_decision_for("/x", "GET", &subject("2001:db9::1")),
        AccessDecision::Denied
    );
}
