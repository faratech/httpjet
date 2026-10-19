//! Regression (#821): a per-directory ruleset re-ran on a URI it had rewritten
//! OUTSIDE its own directory, matching its rules against the unstripped path.
//! `/old/.htaccess` `^(.*)$ /new/$1` nested `/new/new/.../foo`, and a `sub/`
//! front controller `^(.*)$ /index.php?path=$1` clobbered its own query to
//! `path=index.php`. Apache/OLS hand the new URI to the destination directory.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

fn eval_in(prefix: Option<&str>, rules: &str, uri: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).expect("parse");
    let mut input = RewriteInput::new(uri.to_string(), "/web/docroot")
        .method("GET")
        .host("h.test");
    input.per_directory_prefix = prefix.map(str::to_string);
    evaluate(&rs, &input)
}

fn rewritten(outcome: RewriteOutcome) -> (String, Option<String>) {
    match outcome {
        RewriteOutcome::Rewritten {
            new_uri, new_query, ..
        } => (new_uri, new_query),
        other => panic!("expected a rewrite, got {other:?}"),
    }
}

#[test]
fn rewrite_out_of_directory_does_not_reapply_ruleset() {
    let (uri, _) = rewritten(eval_in(
        Some("old/"),
        "RewriteEngine On\nRewriteRule ^(.*)$ /new/$1 [L]\n",
        "/old/foo",
    ));
    assert_eq!(uri, "/new/foo");
}

#[test]
fn front_controller_outside_directory_keeps_captured_query() {
    let (uri, query) = rewritten(eval_in(
        Some("sub/"),
        "RewriteEngine On\nRewriteRule ^(.*)$ /index.php?path=$1 [L]\n",
        "/sub/page",
    ));
    assert_eq!(uri, "/index.php");
    assert_eq!(query.as_deref(), Some("path=page"));
}

#[test]
fn sibling_with_shared_name_prefix_is_outside() {
    // /sub2/ is not inside sub/: no restart, so the second rule never fires.
    let (uri, _) = rewritten(eval_in(
        Some("sub/"),
        "RewriteEngine On\nRewriteRule ^a$ /sub2/a [L]\nRewriteRule ^(.*)$ /never/$1\n",
        "/sub/a",
    ));
    assert_eq!(uri, "/sub2/a");
}

#[test]
fn rewrite_within_directory_is_final() {
    // OLS keeps the context for a target still under sub/: the ruleset does not
    // re-run on it (#880).
    let (uri, _) = rewritten(eval_in(
        Some("sub/"),
        "RewriteEngine On\nRewriteRule ^a$ b [L]\nRewriteRule ^b$ c [L]\n",
        "/sub/a",
    ));
    assert_eq!(uri, "/sub/b");
}

#[test]
fn docroot_ruleset_runs_once() {
    let (uri, _) = rewritten(eval_in(
        None,
        "RewriteEngine On\nRewriteRule ^a$ /b [L]\nRewriteRule ^b$ /c [L]\n",
        "/a",
    ));
    assert_eq!(uri, "/b");
}
