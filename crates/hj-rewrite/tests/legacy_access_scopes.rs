//! Legacy `Order`/`Allow`/`Deny` across `<IfModule>` and `<Limit>`: Apache keeps
//! one `mod_access_compat` config per section, so neither container may start a
//! fresh (default-open) block that overrides the enclosing `Deny from all`
//! (#778).

use hj_rewrite::{AccessDecision, AccessSubject, Htaccess};

fn ip(addr: &str) -> AccessSubject<'static> {
    AccessSubject {
        client_ip: Some(addr.parse().unwrap()),
        env_set: None,
    }
}

fn decide(ht: &Htaccess, method: &str, addr: &str) -> AccessDecision {
    ht.access_decision_for("/x", method, &ip(addr))
}

#[test]
fn ifmodule_is_transparent_to_the_enclosing_legacy_block() {
    let ht = Htaccess::parse(
        "Order Deny,Allow\nDeny from all\n<IfModule mod_authz_host.c>\n  Allow from 10.0.0.0/8\n</IfModule>\n",
    )
    .unwrap();
    assert_eq!(decide(&ht, "GET", "10.1.2.3"), AccessDecision::Granted);
    assert_eq!(decide(&ht, "GET", "198.51.100.1"), AccessDecision::Denied);
}

#[test]
fn ifmodule_wrapping_the_whole_block_still_counts() {
    let ht = Htaccess::parse(
        "<IfModule mod_access_compat.c>\n  Order allow,deny\n</IfModule>\nAllow from 10.0.0.0/8\n",
    )
    .unwrap();
    assert_eq!(decide(&ht, "GET", "10.1.2.3"), AccessDecision::Granted);
    assert_eq!(decide(&ht, "GET", "198.51.100.1"), AccessDecision::Denied);
}

#[test]
fn limit_method_tags_lines_inside_the_same_block() {
    let ht = Htaccess::parse(
        "Order Deny,Allow\nDeny from all\n<Limit GET>\n  Allow from 10.0.0.0/8\n</Limit>\n",
    )
    .unwrap();
    assert_eq!(decide(&ht, "GET", "10.1.2.3"), AccessDecision::Granted);
    assert_eq!(decide(&ht, "HEAD", "10.1.2.3"), AccessDecision::Granted);
    assert_eq!(decide(&ht, "GET", "198.51.100.1"), AccessDecision::Denied);
    // The Allow is GET-only; POST keeps the directory-wide Deny.
    assert_eq!(decide(&ht, "POST", "10.1.2.3"), AccessDecision::Denied);
}

#[test]
fn limit_except_inverts_the_method_mask() {
    let ht = Htaccess::parse(
        "Order Allow,Deny\nAllow from all\n<LimitExcept GET POST>\n  Deny from all\n</LimitExcept>\n",
    )
    .unwrap();
    assert_eq!(decide(&ht, "GET", "198.51.100.1"), AccessDecision::Granted);
    assert_eq!(decide(&ht, "PUT", "198.51.100.1"), AccessDecision::Denied);
}

#[test]
fn limit_scoped_order_applies_only_to_its_methods() {
    let ht = Htaccess::parse("Allow from 10.0.0.0/8\n<Limit POST>\n  Order Allow,Deny\n</Limit>\n")
        .unwrap();
    // GET keeps the default deny,allow: open to everyone.
    assert_eq!(decide(&ht, "GET", "198.51.100.1"), AccessDecision::Granted);
    // POST is allow,deny: only the listed network.
    assert_eq!(decide(&ht, "POST", "198.51.100.1"), AccessDecision::Denied);
    assert_eq!(decide(&ht, "POST", "10.1.2.3"), AccessDecision::Granted);
}

#[test]
fn later_unlimited_order_supersedes_a_limit_order() {
    let ht = Htaccess::parse(
        "<Limit POST>\n  Order Deny,Allow\n</Limit>\nOrder Allow,Deny\nAllow from 10.0.0.0/8\n",
    )
    .unwrap();
    assert_eq!(decide(&ht, "POST", "198.51.100.1"), AccessDecision::Denied);
    assert_eq!(decide(&ht, "POST", "10.1.2.3"), AccessDecision::Granted);
}

#[test]
fn limit_only_block_has_no_opinion_on_other_methods() {
    let ht =
        Htaccess::parse("<Limit POST>\n  Order Deny,Allow\n  Deny from all\n</Limit>\n").unwrap();
    assert_eq!(decide(&ht, "POST", "10.1.2.3"), AccessDecision::Denied);
    assert_eq!(decide(&ht, "GET", "10.1.2.3"), AccessDecision::NoOpinion);
}

#[test]
fn limit_inside_files_joins_that_files_block() {
    let ht = Htaccess::parse(
        "<Files admin.php>\n  Order Deny,Allow\n  Deny from all\n  <Limit GET>\n    Allow from 10.0.0.0/8\n  </Limit>\n</Files>\n",
    )
    .unwrap();
    let at = |path: &str, addr: &str| ht.access_decision_for(path, "GET", &ip(addr));
    assert_eq!(at("/admin.php", "10.1.2.3"), AccessDecision::Granted);
    assert_eq!(at("/admin.php", "198.51.100.1"), AccessDecision::Denied);
    assert_eq!(at("/index.php", "198.51.100.1"), AccessDecision::NoOpinion);
}
