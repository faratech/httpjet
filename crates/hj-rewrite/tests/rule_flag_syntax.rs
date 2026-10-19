//! RewriteRule/RewriteCond argument and flag syntax that used to be silently
//! dropped or mis-tokenized: spaced flag lists, `\ `-escaped and single-quoted
//! arguments, the long cond flag names, forced type/handler flags and
//! `RewriteCond expr` (both unsupported, so they fail closed).

use hj_rewrite::{RewriteError, RewriteInput, RewriteOutcome, RuleSet, evaluate};

fn run(rules: &str, uri: &str, ua: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(&format!("RewriteEngine On\n{rules}")).unwrap();
    let mut input = RewriteInput::new(uri, "/nonexistent").header("User-Agent", ua);
    input.per_directory_prefix = Some(String::new());
    evaluate(&rs, &input)
}

fn is_forbidden(out: &RewriteOutcome) -> bool {
    matches!(out, RewriteOutcome::Forbidden { .. })
}

#[test]
fn whitespace_inside_the_flag_list_keeps_every_flag() {
    assert!(is_forbidden(&run(
        "RewriteRule ^secret - [NC, F]\n",
        "/SECRET",
        ""
    )));
    assert!(is_forbidden(&run(
        "RewriteRule ^secret - [ F ]\n",
        "/secret",
        ""
    )));
    assert!(is_forbidden(&run(
        "RewriteRule ^secret - [F, NC]\n",
        "/SECRET",
        ""
    )));
    match run("RewriteRule ^a$ /b [L, R=301]\n", "/a", "") {
        RewriteOutcome::Redirect { code: 301, .. } => {}
        other => panic!("expected a 301, got {other:?}"),
    }
    let or_rules = "RewriteCond %{HTTP_USER_AGENT} ^a [NC, OR]\nRewriteCond %{HTTP_USER_AGENT} ^b\nRewriteRule ^ - [F]\n";
    assert!(is_forbidden(&run(or_rules, "/x", "A")));
}

#[test]
fn backslash_escaped_space_is_part_of_the_argument() {
    let rs =
        "RewriteRule ^a\\ b$ /c [L]\nRewriteCond %{REQUEST_URI} ^/d\\ e$\nRewriteRule ^ - [F]\n";
    match run(rs, "/a b", "") {
        RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/c"),
        other => panic!("expected Rewritten, got {other:?}"),
    }
    assert!(is_forbidden(&run(rs, "/d e", "")));
}

#[test]
fn single_quoted_argument_is_one_token() {
    match run("RewriteRule '^a b$' /c [L]\n", "/a b", "") {
        RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/c"),
        other => panic!("expected Rewritten, got {other:?}"),
    }
}

#[test]
fn cond_long_flag_names() {
    let ornext = "RewriteCond %{HTTP_USER_AGENT} ^A [ornext]\nRewriteCond %{HTTP_USER_AGENT} ^B\nRewriteRule ^ - [F]\n";
    assert!(is_forbidden(&run(ornext, "/x", "A")));
    let nocase = "RewriteCond %{HTTP_USER_AGENT} ^a [nocase]\nRewriteRule ^ - [F]\n";
    assert!(is_forbidden(&run(nocase, "/x", "A")));
}

#[test]
fn forced_type_and_handler_flags_fail_closed() {
    for flag in [
        "T=application/x-httpd-php",
        "H=application/x-httpd-php",
        "type=text/plain",
        "handler=php-script",
        "L,T=text/plain",
    ] {
        let err = RuleSet::parse(&format!("RewriteRule \\.html$ - [{flag}]\n"));
        assert!(
            matches!(err, Err(RewriteError::Malformed { .. })),
            "[{flag}] must not parse: {err:?}"
        );
    }
}

#[test]
fn rewrite_cond_expr_fails_closed() {
    for src in [
        "RewriteCond expr \"%{HTTP_REFERER} =~ /evil/\"\nRewriteRule ^images - [F]\n",
        "RewriteCond EXPR \"! %{HTTP_REFERER} -strmatch '*://%{HTTP_HOST}/*'\"\nRewriteRule ^images - [F]\n",
    ] {
        assert!(matches!(
            RuleSet::parse(src),
            Err(RewriteError::Malformed { .. })
        ));
    }
}
