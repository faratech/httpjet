//! Regression (#822): `[E=]` output is visible to later `%{ENV:}` reads (in this
//! ruleset and in later rulesets of the chain), so a ruleset that writes a name the
//! classifier treats as constant-empty (`REDIRECT_STATUS`), or a name only known at
//! eval time, must not be outcome-cacheable / memo-eligible.

use hj_rewrite::RuleSet;

fn cacheable(rules: &str) -> bool {
    RuleSet::parse(rules).expect("parse").path_cacheable
}

#[test]
fn redirect_status_writer_is_uncacheable() {
    assert!(!cacheable(
        "RewriteEngine On\nRewriteRule ^p$ - [E=REDIRECT_STATUS:403]\n"
    ));
    assert!(!cacheable(
        "RewriteEngine On\nRewriteRule ^p$ - [E=!REDIRECT_STATUS]\n"
    ));
}

#[test]
fn dynamic_env_name_is_uncacheable() {
    assert!(!cacheable(
        "RewriteEngine On\nRewriteRule ^(\\w+)$ - [E=$1:1]\n"
    ));
}

#[test]
fn ordinary_env_writer_stays_cacheable() {
    assert!(cacheable(
        "RewriteEngine On\nRewriteRule ^p$ - [E=no-cache:1]\nRewriteRule ^q$ - [E=!esi]\n"
    ));
}
