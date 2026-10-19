//! A `%{VAR}` expanded into the path part of a substitution is literal text, as in
//! OLS `appendSubst` (it decodes only the substitution's own text and
//! `%{REQUEST_URI}`, whose source there is the raw request target; ours is the
//! decoded path already). The pipeline decodes the target once, so a `%` the value
//! carries must reach it as `%25` or a `%252e` request becomes `.` (#1038). After a
//! substitution, the working URI and everything taken from it is escaped already;
//! a `%N` keeps the provenance of the bytes it captured.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

fn eval(rules: &str, input: RewriteInput<'_>) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).unwrap();
    let mut input = input;
    input.per_directory_prefix = Some(String::new());
    evaluate(&rs, &input)
}

fn req(uri: &str) -> RewriteInput<'static> {
    RewriteInput::new(uri.to_string(), "/nonexistent")
}

fn rewritten(out: RewriteOutcome) -> (String, Option<String>) {
    match out {
        RewriteOutcome::Rewritten {
            new_uri, new_query, ..
        } => (new_uri, new_query),
        other => panic!("expected Rewritten, got {other:?}"),
    }
}

fn path(out: RewriteOutcome) -> String {
    rewritten(out).0
}

#[test]
fn request_uri_is_literal() {
    let rules = "RewriteEngine On\nRewriteRule ^go/ /x%{REQUEST_URI} [L]\n";
    assert_eq!(path(eval(rules, req("/go/%2e%2e/s"))), "/x/go/%252e%252e/s");
    assert_eq!(path(eval(rules, req("/go/plain.css"))), "/x/go/plain.css");
    assert_eq!(path(eval(rules, req("/go/a b"))), "/x/go/a%20b");
}

#[test]
fn http_header_is_literal() {
    let rules = "RewriteEngine On\nRewriteRule ^h$ /files/%{HTTP:X-Path} [L]\n";
    let with = |v: &str| path(eval(rules, req("/h").header("X-Path", v)));
    assert_eq!(with("%2e%2e/secret"), "/files/%252e%252e/secret");
    assert_eq!(with("a/b.txt"), "/files/a/b.txt");
    let named = "RewriteEngine On\nRewriteRule ^h$ /files/%{HTTP_REFERER} [L]\n";
    let out = eval(named, req("/h").header("Referer", "%2e%2e"));
    assert_eq!(path(out), "/files/%252e%252e");
}

#[test]
fn query_string_is_literal() {
    let rules = "RewriteEngine On\nRewriteRule ^q$ /files/%{QUERY_STRING} [L]\n";
    assert_eq!(
        rewritten(eval(rules, req("/q").query("%2e%2e/x"))),
        (
            "/files/%252e%252e/x".to_string(),
            Some("%2e%2e/x".to_string())
        )
    );
    assert_eq!(path(eval(rules, req("/q").query("a.txt"))), "/files/a.txt");
}

#[test]
fn env_is_literal() {
    let rules = "RewriteEngine On\nRewriteRule ^ - [E=P:%{QUERY_STRING}]\nRewriteRule ^e$ /files/%{ENV:P} [L]\n";
    assert_eq!(
        path(eval(rules, req("/e").query("%2e%2e/x"))),
        "/files/%252e%252e/x"
    );
    assert_eq!(path(eval(rules, req("/e").query("a.txt"))), "/files/a.txt");
    let mut seeded = req("/e");
    seeded.env.insert("SEED".into(), "%2e%2e".into());
    let out = eval(
        "RewriteEngine On\nRewriteRule ^e$ /files/%{ENV:SEED} [L]\n",
        seeded,
    );
    assert_eq!(path(out), "/files/%252e%252e");
}

#[test]
fn a_question_mark_in_a_variable_starts_the_query() {
    let rules = "RewriteEngine On\nRewriteRule ^w$ /files/%{HTTP:X-Path} [L]\n";
    assert_eq!(
        rewritten(eval(rules, req("/w").header("X-Path", "a%41?b=%41"))),
        ("/files/a%2541".to_string(), Some("b=%41".to_string()))
    );
}

#[test]
fn variable_in_the_query_part_is_unchanged() {
    let rules = "RewriteEngine On\nRewriteRule ^v$ /s.php?q=%{HTTP:X-Q} [L]\n";
    assert_eq!(
        rewritten(eval(rules, req("/v").header("X-Q", "%41"))),
        ("/s.php".to_string(), Some("q=%41".to_string()))
    );
}

#[test]
fn ne_leaves_a_variable_verbatim_in_an_external_url() {
    let rules = |flags: &str| {
        format!("RewriteEngine On\nRewriteRule ^n$ /t/%{{HTTP:X-Path}} [R=302,{flags}L]\n")
    };
    let location = |rules: &str| match eval(rules, req("/n").header("X-Path", "%2e%2e")) {
        RewriteOutcome::Redirect { location, .. } => location,
        other => panic!("expected Redirect, got {other:?}"),
    };
    assert_eq!(location(&rules("")), "/t/%252e%252e");
    assert_eq!(location(&rules("NE,")), "/t/%2e%2e");
}

#[test]
fn host_in_a_redirect_authority_is_unchanged() {
    let rules = "RewriteEngine On\nRewriteRule ^r$ https://%{HTTP_HOST}/x [R=301,L]\n";
    match eval(rules, req("/r").host("example.test")) {
        RewriteOutcome::Redirect { location, .. } => {
            assert_eq!(location, "https://example.test/x")
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
}

/// After a substitution the working URI is escaped: a value read from it is not
/// escaped a second time.
#[test]
fn working_uri_after_a_substitution_is_not_escaped_again() {
    let base = "RewriteEngine On\nRewriteRule ^a/(.*)$ /b/$1\n";
    let var = format!("{base}RewriteRule ^b/ /c%{{REQUEST_URI}} [L]\n");
    assert_eq!(path(eval(&var, req("/a/x y"))), "/c/b/x%20y");
    assert_eq!(path(eval(&var, req("/a/%41"))), "/c/b/%2541");
    let cond = format!("{base}RewriteCond %{{REQUEST_URI}} ^/b/(.*)$\nRewriteRule ^b/ /d/%1 [L]\n");
    assert_eq!(path(eval(&cond, req("/a/x y"))), "/d/x%20y");
    assert_eq!(path(eval(&cond, req("/a/%41"))), "/d/%2541");
    let nested = format!(
        "{base}RewriteCond %{{REQUEST_URI}} ^/b/(.*)$\nRewriteCond %1 ^(.*)$\nRewriteRule ^b/ /d/%1 [L]\n"
    );
    assert_eq!(path(eval(&nested, req("/a/x y"))), "/d/x%20y");
}

/// A `%N` from a literal source after a substitution is still literal.
#[test]
fn literal_cond_capture_after_a_substitution_is_escaped() {
    let base = "RewriteEngine On\nRewriteRule ^t/(.*)$ /u/$1\n";
    let the_request = format!(
        "{base}RewriteCond %{{THE_REQUEST}} \\s/t/(\\S+)\\s\nRewriteRule ^u/ /files/%1 [L]\n"
    );
    // `GET /t/q/%2e%2e/x` normalizes to `/t/x`; THE_REQUEST keeps the raw target.
    let out = eval(
        &the_request,
        req("/t/x").raw_request_target("/t/q/%2e%2e/x"),
    );
    assert_eq!(path(out), "/files/q/%252e%252e/x");
    let out = eval(&the_request, req("/t/a.txt").raw_request_target("/t/a.txt"));
    assert_eq!(path(out), "/files/a.txt");

    let query =
        format!("{base}RewriteCond %{{QUERY_STRING}} ^p=(.*)$\nRewriteRule ^u/ /files/%1 [L]\n");
    assert_eq!(
        path(eval(&query, req("/t/z").query("p=%2e%2e"))),
        "/files/%252e%252e"
    );
    let header =
        format!("{base}RewriteCond %{{HTTP:X-Path}} ^(.+)$\nRewriteRule ^u/ /files/%1 [L]\n");
    assert_eq!(
        path(eval(&header, req("/t/z").header("X-Path", "%2e%2e"))),
        "/files/%252e%252e"
    );
}

/// A capture spanning a literal source and the escaped working URI escapes only
/// the literal bytes.
#[test]
fn mixed_cond_capture_escapes_only_its_literal_bytes() {
    let rules = "RewriteEngine On\nRewriteRule ^a/(.*)$ /b/$1\nRewriteCond %{QUERY_STRING}|%{REQUEST_URI} ^(.*)$\nRewriteRule ^b/ /files/%1 [L]\n";
    assert_eq!(
        path(eval(rules, req("/a/x y").query("p=%41"))),
        "/files/p=%2541%7C/b/x%20y"
    );
}
