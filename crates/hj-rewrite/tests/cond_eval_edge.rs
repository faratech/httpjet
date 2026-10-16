//! RewriteCond evaluation edge cases: match-time regex failure under negation
//! and `[OR]`, saturating numeric comparison, `%0` across a foldable `[OR]`
//! group, and per-directory `RewriteEngine` inheritance.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate, evaluate_with_engine};

// A backtracking-heavy pattern that exceeds fancy_regex's backtrack limit.
const EXPLOSIVE: &str = r"^(?:(a)\1?)*c";

#[test]
fn negated_cond_regex_failure_is_fail_closed() {
    let rs = RuleSet::parse(&format!(
        "RewriteEngine On\nRewriteCond %{{QUERY_STRING}} !{EXPLOSIVE}\nRewriteRule ^admin - [L]\nRewriteRule ^admin - [F]\n"
    ))
    .unwrap();
    let q = "a".repeat(40);
    let input = RewriteInput::new("/admin", "/tmp").query(q.as_str());
    assert!(matches!(
        evaluate(&rs, &input),
        RewriteOutcome::Failed { .. }
    ));
}

#[test]
fn or_group_regex_failure_is_fail_closed() {
    let rs = RuleSet::parse(&format!(
        "RewriteEngine On\nRewriteCond %{{QUERY_STRING}} {EXPLOSIVE} [OR]\nRewriteCond %{{REQUEST_URI}} ^/admin\nRewriteRule ^admin - [E=X:1]\n"
    ))
    .unwrap();
    let q = "a".repeat(40);
    let input = RewriteInput::new("/admin", "/tmp").query(q.as_str());
    assert!(matches!(
        evaluate(&rs, &input),
        RewriteOutcome::Failed { .. }
    ));
}

#[test]
fn numeric_compare_saturates_on_overflow() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{QUERY_STRING} page=(\\d+)\nRewriteCond %1 -gt 1000\nRewriteRule ^ - [F]\n",
    )
    .unwrap();
    for q in ["page=5000", "page=99999999999999999999"] {
        let input = RewriteInput::new("/x", "/tmp").query(q);
        assert!(
            matches!(evaluate(&rs, &input), RewriteOutcome::Forbidden { .. }),
            "{q}"
        );
    }
}

#[test]
fn percent_zero_is_the_first_passing_or_member() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{QUERY_STRING} zzz [OR]\nRewriteCond %{QUERY_STRING} aaa\nRewriteRule ^ - [E=M:%0]\n",
    )
    .unwrap();
    let input = RewriteInput::new("/x", "/tmp").query("aaazzz");
    match evaluate(&rs, &input) {
        RewriteOutcome::Unchanged { env, .. } => {
            assert_eq!(env, vec![("M".to_string(), "zzz".to_string())]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn engine_state_is_inherited_when_unset() {
    let child = RuleSet::parse("RewriteRule ^private - [F]\n").unwrap();
    assert_eq!(child.engine_state(), None);
    assert!(!child.is_noop());
    let input = RewriteInput::new("private", "/tmp");
    assert!(matches!(
        evaluate_with_engine(&child, &input, true),
        RewriteOutcome::Forbidden { .. }
    ));
    assert!(matches!(
        evaluate(&child, &input),
        RewriteOutcome::Unchanged { .. }
    ));
    let off = RuleSet::parse("RewriteEngine Off\nRewriteRule ^private - [F]\n").unwrap();
    assert_eq!(off.engine_state(), Some(false));
    assert!(off.is_noop());
}
