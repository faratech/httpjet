//! Regression coverage for the cond pre-screen optimization (apply_rule evaluates
//! `$N`-free conds before the rule pattern `captures()` and skips the regex when a
//! cond fails). These cases pin the semantics the optimization must preserve: a
//! method/header-gated generic rule must match exactly the requests it matched
//! before, and `%N` cond backrefs (which gate pre-screen eligibility but not the
//! per-rule reset) must still see only captures from the current rule.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

/// The mcp vhost shape: a generic `^/(.*)$` proxy rule gated by a method cond. The
/// pattern matches every URI, so before the pre-screen this captured on every GET
/// only to fail the method cond. Behavior must be: GET → Unchanged, POST → Proxy.
const METHOD_GATED: &str = r#"
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(POST|DELETE)$
RewriteRule ^/(.*)$ http://127.0.0.1:8002/$1 [P,L]
"#;

fn eval(rules: &str, method: &str, uri: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).expect("parse");
    let input = RewriteInput::new(uri.to_string(), "/tmp/doc")
        .method(method)
        .host("mcp.test");
    evaluate(&rs, &input)
}

#[test]
fn method_gated_get_is_unchanged() {
    // GET fails the method cond → the rule does not apply → URI unchanged. This is
    // the hot path the pre-screen optimizes (captures() must be skipped, outcome
    // identical to the pre-optimization behavior).
    match eval(METHOD_GATED, "GET", "/anything/here") {
        RewriteOutcome::Unchanged { .. } => {}
        other => panic!("GET should be Unchanged, got {other:?}"),
    }
}

#[test]
fn method_gated_post_proxies() {
    // POST passes the method cond → the rule applies → proxy with $1 substituted.
    // Confirms the pre-screen pass-through path still captures and substitutes.
    match eval(METHOD_GATED, "POST", "/anything/here") {
        RewriteOutcome::Proxy { target_url, .. } => {
            assert_eq!(target_url, "http://127.0.0.1:8002/anything/here");
        }
        other => panic!("POST should Proxy, got {other:?}"),
    }
}

#[test]
fn method_gated_delete_proxies() {
    match eval(METHOD_GATED, "DELETE", "/x") {
        RewriteOutcome::Proxy { target_url, .. } => {
            assert_eq!(target_url, "http://127.0.0.1:8002/x");
        }
        other => panic!("DELETE should Proxy, got {other:?}"),
    }
}

/// A header-gated rule (`%{HTTP:Accept}`) — also `$N`-free in its cond, so it is
/// pre-screen eligible. The screen must reject when the header is absent/mismatched
/// and pass when it matches.
const ACCEPT_GATED: &str = r#"
RewriteEngine On
RewriteCond %{HTTP:Accept} text/event-stream
RewriteRule ^/$ http://127.0.0.1:8002/ [P,L]
"#;

#[test]
fn accept_gated_without_header_is_unchanged() {
    match eval(ACCEPT_GATED, "GET", "/") {
        RewriteOutcome::Unchanged { .. } => {}
        other => panic!("missing Accept should be Unchanged, got {other:?}"),
    }
}

#[test]
fn accept_gated_with_header_proxies() {
    let rs = RuleSet::parse(ACCEPT_GATED).expect("parse");
    let input = RewriteInput::new("/".to_string(), "/tmp/doc")
        .method("GET")
        .host("mcp.test")
        .header("Accept", "text/event-stream");
    match evaluate(&rs, &input) {
        RewriteOutcome::Proxy { target_url, .. } => {
            assert_eq!(target_url, "http://127.0.0.1:8002/");
        }
        other => panic!("Accept SSE should Proxy, got {other:?}"),
    }
}

/// A rule whose cond chains `%N` (the second cond references `%1` from the first).
/// Both conds are `$N`-free, so the rule is pre-screen eligible — the per-rule
/// `%N` reset in the pre-screen must hold, so `%1` resolves to the first cond's
/// capture (the subdomain), not a stale value. www.* is excluded; other.* rewrites.
const COND_BACKREF: &str = r#"
RewriteEngine On
RewriteCond %{HTTP_HOST} ^(.+)\.example\.com$
RewriteCond %1 !^www$
RewriteRule ^/(.*)$ /sub/%1/$1 [L]
"#;

#[test]
fn cond_n_backref_matches_non_www() {
    let rs = RuleSet::parse(COND_BACKREF).expect("parse");
    let input = RewriteInput::new("/page".to_string(), "/tmp/doc")
        .method("GET")
        .host("shop.example.com");
    match evaluate(&rs, &input) {
        RewriteOutcome::Rewritten { new_uri, .. } => {
            assert!(new_uri.ends_with("/sub/shop/page"), "new_uri was {new_uri}");
        }
        other => panic!("non-www should rewrite, got {other:?}"),
    }
}

#[test]
fn cond_n_backref_excludes_www() {
    let rs = RuleSet::parse(COND_BACKREF).expect("parse");
    let input = RewriteInput::new("/page".to_string(), "/tmp/doc")
        .method("GET")
        .host("www.example.com");
    match evaluate(&rs, &input) {
        RewriteOutcome::Unchanged { .. } => {}
        other => panic!("www should be excluded (Unchanged), got {other:?}"),
    }
}
