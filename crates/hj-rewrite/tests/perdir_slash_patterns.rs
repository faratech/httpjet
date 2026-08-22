//! Regression: in a per-directory context, `^/...`-anchored patterns used to be
//! matched against the FULL request URI (`select_match_target` checked the
//! pattern's shape before the per-directory strip), so a nested `.htaccess`'s
//! slash-anchored rules were inert against their own directory and `$1`
//! captures spanned the whole URI. Apache strips the prefix AND the leading
//! slash for every pattern in per-directory context; we now do the same. The
//! slashed shape remains honored for vhost-level rulesets (no prefix), where
//! the LiteSpeed inline rules are written `^/tools\.json$`.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

fn eval_in_forum(rules: &str, uri: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).expect("parse");
    let mut input = RewriteInput::new(uri.to_string(), "/web/docroot")
        .method("GET")
        .host("h.test");
    // /forum/.htaccess applies with the "forum/" per-directory prefix.
    input.per_directory_prefix = Some("forum/".to_string());
    evaluate(&rs, &input)
}

#[test]
fn nested_slash_anchored_patterns_stop_matching_the_full_uri() {
    // Pre-fix, `^/(.*)$` was tested against the FULL "/forum/..." URI and its
    // `$1` captured the whole thing; post-fix the per-dir strip happens first,
    // so the slashed spelling simply does not match (Apache behavior) while
    // the unslashed spelling matches and captures dir-relative.
    let slashed = eval_in_forum(
        "RewriteEngine On\nRewriteRule ^/(.*)$ /index.php [L]\n",
        "/forum/threads/x.1/",
    );
    assert!(
        matches!(slashed, RewriteOutcome::Unchanged { .. }),
        "`^/...` in a per-dir file must not match the full URI"
    );

    let unslashed = eval_in_forum(
        "RewriteEngine On\nRewriteRule ^threads/(.*)$ /i/$1 [L]\n",
        "/forum/threads/x.1/",
    );
    match unslashed {
        RewriteOutcome::Rewritten { new_uri, .. } => {
            assert_eq!(new_uri, "/i/x.1/", "$1 captures the DIR-RELATIVE path");
        }
        other => panic!("expected a rewrite, got {other:?}"),
    }
}

#[test]
fn nested_slash_anchored_deny_matches_its_own_directory() {
    // Author intent: deny config.php IN THIS DIRECTORY. With the per-dir strip
    // applied first, `^config.php$` (the Apache spelling) fires; the slashed
    // spelling `^/config\.php$` is inert exactly as it would be under Apache.
    let fires = eval_in_forum(
        "RewriteEngine On\nRewriteRule ^config\\.php$ - [F]\n",
        "/forum/config.php",
    );
    assert!(
        matches!(fires, RewriteOutcome::Forbidden { .. }),
        "plain per-dir deny must fire on its own directory"
    );

    let slashed = eval_in_forum(
        "RewriteEngine On\nRewriteRule ^/config\\.php$ - [F]\n",
        "/forum/config.php",
    );
    assert!(
        !matches!(slashed, RewriteOutcome::Forbidden { .. }),
        "`^/...` in a per-dir file must not match the FULL uri (Apache strips it)"
    );
}

#[test]
fn vhost_level_slashed_rules_keep_matching_the_full_uri() {
    // No prefix (inline vhost ruleset): the LiteSpeed-style anchored form works.
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^/tools\\.json$ - [F]\n").unwrap();
    let input = RewriteInput::new("/tools.json".to_string(), "/web/docroot")
        .method("GET")
        .host("h.test");
    assert!(matches!(
        evaluate(&rs, &input),
        RewriteOutcome::Forbidden { .. }
    ));
}
