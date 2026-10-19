//! A `$N`/`%N` backreference is literal text in the substitution (OLS `appendSubst`
//! never decodes it). The rule matches the DECODED request path, so a `%` in a
//! capture came from a `%25` in the request; the pipeline decodes the rewritten
//! target exactly once, so the path part must carry that `%` as `%25` or a
//! `%252e%252e` request is decoded twice into `..` (#1033).

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

fn run(rules: &str, uri: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).unwrap();
    let mut input = RewriteInput::new(uri, "/nonexistent");
    input.per_directory_prefix = Some(String::new());
    evaluate(&rs, &input)
}

fn rewritten(out: RewriteOutcome) -> (String, Option<String>) {
    match out {
        RewriteOutcome::Rewritten {
            new_uri, new_query, ..
        } => (new_uri, new_query),
        other => panic!("expected Rewritten, got {other:?}"),
    }
}

fn location(out: RewriteOutcome) -> String {
    match out {
        RewriteOutcome::Redirect { location, .. } => location,
        other => panic!("expected Redirect, got {other:?}"),
    }
}

fn proxy_target(out: RewriteOutcome) -> String {
    match out {
        RewriteOutcome::Proxy { target_url, .. } => target_url,
        other => panic!("expected Proxy, got {other:?}"),
    }
}

const FORUM_ASSETS: &str =
    "RewriteEngine On\nRewriteRule ^threads/assets/(.+)$ /wf-statement/assets/$1 [L]\n";

#[test]
fn forum_asset_rule_without_a_percent_is_unchanged() {
    for (uri, target) in [
        (
            "/threads/assets/css/app.min.css",
            "/wf-statement/assets/css/app.min.css",
        ),
        (
            "/threads/assets/img/logo-2x.png",
            "/wf-statement/assets/img/logo-2x.png",
        ),
        ("/threads/assets/a b.png", "/wf-statement/assets/a%20b.png"),
        ("/threads/assets/x?.js", "/wf-statement/assets/x%3F.js"),
        (
            "/threads/assets/caf\u{e9}.svg",
            "/wf-statement/assets/caf%C3%A9.svg",
        ),
    ] {
        assert_eq!(
            rewritten(run(FORUM_ASSETS, uri)),
            (target.to_string(), None),
            "{uri}"
        );
    }
}

#[test]
fn forum_asset_rule_keeps_a_decoded_escape_literal() {
    let (uri, query) = rewritten(run(
        FORUM_ASSETS,
        "/threads/assets/%2e%2e/%2e%2e/%2emypy_cache/3.14/cache.0.db",
    ));
    assert_eq!(
        uri,
        "/wf-statement/assets/%252e%252e/%252e%252e/%252emypy_cache/3.14/cache.0.db"
    );
    assert_eq!(query, None);
}

#[test]
fn cond_backref_percent_is_literal() {
    let out = run(
        "RewriteEngine On\nRewriteCond %{REQUEST_URI} ^/c/(.*)$\nRewriteRule ^c/ /d/%1 [L]\n",
        "/c/%41",
    );
    assert_eq!(rewritten(out).0, "/d/%2541");
}

#[test]
fn query_part_backref_is_unchanged() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^q/(.*)$ /s.php?v=$1 [L]\n",
        "/q/a%41",
    );
    assert_eq!(
        rewritten(out),
        ("/s.php".to_string(), Some("v=a%41".to_string()))
    );
}

#[test]
fn unsafe_allow_3f_splits_with_the_path_half_literal() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^f/(.*)$ /g/$1 [L,UnsafeAllow3F]\n",
        "/f/%41?x=%41",
    );
    assert_eq!(
        rewritten(out),
        ("/g/%2541".to_string(), Some("x=%41".to_string()))
    );
}

#[test]
fn redirect_location_keeps_the_literal_percent() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^r/(.*)$ /t/$1 [R=302,L]\n",
        "/r/%41",
    );
    assert_eq!(location(out), "/t/%2541");
}

#[test]
fn proxy_target_keeps_the_literal_percent() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^p/(.*)$ http://127.0.0.1:9/$1 [P]\n",
        "/p/%41",
    );
    assert_eq!(proxy_target(out), "http://127.0.0.1:9/%2541");
}

/// OLS `[NE]` leaves only an external URL unescaped (`setRewriteLocation`,
/// `internalRedirectURI`); the capture reaches it verbatim.
#[test]
fn ne_leaves_an_external_url_verbatim() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^r/(.*)$ /t/$1 [R=302,NE,L]\n",
        "/r/%41",
    );
    assert_eq!(location(out), "/t/%41");
    let out = run(
        "RewriteEngine On\nRewriteRule ^p/(.*)$ http://127.0.0.1:9/$1 [P,NE]\n",
        "/p/%41",
    );
    assert_eq!(proxy_target(out), "http://127.0.0.1:9/%41");
    let out = run(
        "RewriteEngine On\nRewriteRule ^g/(.*)$ http://other.test/$1 [NE,L]\n",
        "/g/%41",
    );
    assert_eq!(location(out), "http://other.test/%41");
}

/// OLS builds an internal target the same way with or without `[NE]`, so `[NE]`
/// does not reopen the double decode.
#[test]
fn ne_internal_rewrite_keeps_the_percent_literal() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^n/(.*)$ /m/$1 [NE,L]\n",
        "/n/%2e%2e/x",
    );
    assert_eq!(rewritten(out).0, "/m/%252e%252e/x");
    let out = run(
        "RewriteEngine On\nRewriteRule ^n/(.*)$ /m/$1 [NE,L]\n",
        "/n/a b",
    );
    assert_eq!(rewritten(out).0, "/m/a b");
}

/// A later rule captures from the substituted (already escaped) URI, whose `%`
/// is an escape: it must not be escaped a second time.
#[test]
fn capture_from_a_substituted_uri_is_not_escaped_again() {
    let rules = "RewriteEngine On\nRewriteRule ^a/(.*)$ /b/$1\nRewriteRule ^b/(.*)$ /c/$1 [L]\n";
    assert_eq!(rewritten(run(rules, "/a/100%")).0, "/c/100%25");
    assert_eq!(rewritten(run(rules, "/a/x y")).0, "/c/x%20y");
    assert_eq!(rewritten(run(rules, "/a/%41")).0, "/c/%2541");
    let restart =
        "RewriteEngine On\nRewriteRule ^b/(.*)$ /c/$1 [L]\nRewriteRule ^a/(.*)$ /b/$1 [N]\n";
    assert_eq!(rewritten(run(restart, "/a/%41")).0, "/c/%2541");
}

#[test]
fn b_flag_percent_is_escaped_once() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^b/(.*)$ /x/$1 [B,L]\n",
        "/b/%41",
    );
    assert_eq!(rewritten(out).0, "/x/%2541");
    let out = run(
        "RewriteEngine On\nRewriteRule ^b/(.*)$ /x/$1 [B=&,L]\n",
        "/b/%41&",
    );
    assert_eq!(rewritten(out).0, "/x/%2541%26");
}

/// An absolute target naming the current URL is a loop (OLS detectLoopRedirect
/// compares the unescaped target with the decoded request path).
#[test]
fn absolute_target_naming_the_current_url_is_detected_as_a_loop() {
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^(.*)$ http://h.test/$1 [L]\n").unwrap();
    let mut input = RewriteInput::new("/a%41", "/nonexistent").host("h.test");
    input.per_directory_prefix = Some(String::new());
    assert!(
        matches!(evaluate(&rs, &input), RewriteOutcome::Unchanged { .. }),
        "the target is the request URL itself"
    );
}
