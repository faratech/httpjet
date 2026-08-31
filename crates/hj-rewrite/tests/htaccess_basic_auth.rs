//! (Tier 1.3) A complete `AuthType Basic` + `AuthName` + `AuthUserFile` block
//! resolves into a Basic-auth realm: `Require valid-user`/`Require user …` feed
//! the realm (enforced by the pipeline as a 401 challenge) instead of the
//! historical fail-closed deny collapse. An INCOMPLETE block (no AuthUserFile,
//! or non-Basic AuthType) keeps the deny collapse.

use hj_rewrite::Htaccess;

#[test]
fn complete_basic_auth_block_builds_a_realm() {
    let ht = Htaccess::parse(
        "AuthType Basic\n\
         AuthName \"Restricted area\"\n\
         AuthUserFile /etc/httpd/htpasswd\n\
         Require valid-user\n",
    )
    .expect("parse");
    let auth = ht
        .auth
        .clone()
        .expect("a complete Basic-auth block yields a realm");
    assert_eq!(auth.realm, "Restricted area");
    assert_eq!(
        auth.user_file,
        std::path::PathBuf::from("/etc/httpd/htpasswd")
    );
    assert!(auth.require_valid_user);

    // The Require line must NOT also collapse to a blanket deny.
    assert!(
        !ht.is_forbidden("/admin/tool.php", "tool.php"),
        "auth is enforced as a 401 challenge, not a deny"
    );
}

#[test]
fn require_user_lists_feed_the_realm() {
    let ht = Htaccess::parse(
        "AuthType Basic\n\
         AuthName \"Private\"\n\
         AuthUserFile /etc/httpd/htpasswd\n\
         Require user alice bob\n",
    )
    .expect("parse");
    let auth = ht.auth.clone().expect("realm");
    assert!(auth.user_satisfies("alice"));
    assert!(auth.user_satisfies("bob"));
    assert!(!auth.user_satisfies("eve"));
}

#[test]
fn incomplete_auth_block_keeps_the_deny_collapse() {
    // AuthType without AuthUserFile: `Require valid-user` cannot be honored, so
    // the historical fail-closed deny must stand.
    let ht = Htaccess::parse("AuthType Basic\nRequire valid-user\n").expect("parse");
    assert!(ht.auth.is_none(), "no realm without an AuthUserFile");
    assert!(
        ht.is_forbidden("/admin/tool.php", "tool.php"),
        "incomplete auth keeps the fail-closed deny"
    );
}
