//! Regression (audit M5): a RELATIVE substitution in a nested `.htaccess` used to
//! resolve against the DOCROOT (`resolve_subst_path` ignored the RewriteInput and
//! fell back to `/`) instead of the rule set's own directory. Apache resolves a
//! relative substitution against the per-directory prefix when no `RewriteBase`
//! is set — the front-controller idiom
//! `RewriteRule (.*) index.php/$1 [L]` in `<docroot>/admin/.htaccess` must land on
//! `/admin/index.php/...`, never `/index.php/...`.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

fn eval_in_admin(rules: &str, uri: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).expect("parse");
    let mut input = RewriteInput::new(uri.to_string(), "/web/docroot")
        .method("GET")
        .host("h.test");
    // /web/docroot/admin/.htaccess applies with the "admin/" per-directory prefix.
    input.per_directory_prefix = Some("admin/".to_string());
    evaluate(&rs, &input)
}

#[test]
fn relative_substitution_resolves_against_ruleset_directory() {
    // Pattern shaped so the rewritten result cannot rematch (`^monit/$` vs the
    // resolved `/admin/index.php`) — isolating ONE substitution resolution.
    let outcome = eval_in_admin(
        "RewriteEngine On\nRewriteRule ^monit/$ index.php [L]\n",
        "/admin/monit/",
    );
    match outcome {
        RewriteOutcome::Rewritten { new_uri, .. } => {
            assert_eq!(
                new_uri, "/admin/index.php",
                "relative subst must resolve against the .htaccess's own directory"
            );
        }
        other => panic!("expected a rewrite, got {other:?}"),
    }
}

#[test]
fn explicit_rewrite_base_still_wins_over_the_directory() {
    let outcome = eval_in_admin(
        "RewriteEngine On\nRewriteBase /app/\nRewriteRule ^x$ target [L]\n",
        "/admin/x",
    );
    match outcome {
        RewriteOutcome::Rewritten { new_uri, .. } => {
            assert_eq!(
                new_uri, "/app/target",
                "RewriteBase overrides the directory"
            );
        }
        other => panic!("expected a rewrite, got {other:?}"),
    }
}

#[test]
fn root_level_relative_subst_keeps_docroot_behavior() {
    // No per-directory prefix (vhost-level ruleset): unchanged "/" fallback.
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^x$ target [L]\n").expect("parse");
    let input = RewriteInput::new("/x".to_string(), "/web/docroot").method("GET");
    match evaluate(&rs, &input) {
        RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/target"),
        other => panic!("expected a rewrite, got {other:?}"),
    }
}
