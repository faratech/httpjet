//! Regression for the `[N]`/`[next]` loop guard. The restart counter used to be a
//! `run_pass`-local that reset on every `[N]` jump, so its `> MAX_ITERATIONS` check
//! was dead code (it never saw more than one restart). The counter now lives in the
//! eval state and accumulates across restarts, so an always-matching `[N]` rule is
//! bounded and `evaluate` terminates instead of looping. These tests pin both the
//! bound (termination) and that ordinary `[N]` semantics (restart-from-top) survive.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

/// `^` matches every URI and `-` makes no substitution, so this rule fires `[N]`
/// on every pass and never changes the URI: a textbook `[N]` loop. The guard must
/// bound the restarts and let `evaluate` return (a hang here = a regressed guard).
const INFINITE_N: &str = r#"
RewriteEngine On
RewriteRule ^ - [N]
"#;

#[test]
fn always_matching_next_terminates() {
    let rs = RuleSet::parse(INFINITE_N).expect("parse");
    let input = RewriteInput::new("/loop".to_string(), "/tmp/doc")
        .method("GET")
        .host("h.test");
    // The URI never changes, so once the `[N]` guard bails the outcome is Unchanged.
    // The assertion that matters is that this call RETURNS at all.
    match evaluate(&rs, &input) {
        RewriteOutcome::Unchanged { .. } => {}
        other => panic!("infinite [N] should bail to Unchanged, got {other:?}"),
    }
}

/// A `[N]` rule that genuinely changes the URI each time it fires, but only while a
/// condition holds, must also terminate (the guard bounds it even though the URI
/// keeps changing). Pattern strips one leading `x`; after enough passes it stops.
const PROGRESSING_N: &str = r#"
RewriteEngine On
RewriteRule ^x(.*)$ /$1 [N]
"#;

#[test]
fn progressing_next_terminates_and_strips() {
    let rs = RuleSet::parse(PROGRESSING_N).expect("parse");
    // Three leading 'x's: each `[N]` pass strips one. Fewer than MAX_ITERATIONS, so
    // it converges to a stable URI before the guard bails.
    let input = RewriteInput::new("/xxxpage".to_string(), "/tmp/doc")
        .method("GET")
        .host("h.test");
    match evaluate(&rs, &input) {
        RewriteOutcome::Rewritten { new_uri, .. } => {
            assert_eq!(new_uri, "/page", "each [N] pass should strip one leading x");
        }
        other => panic!("progressing [N] should rewrite to /page, got {other:?}"),
    }
}

/// `[N]` that keeps matching AND keeps changing the URI (prepends a char) must not
/// hang: the `[N]` guard, not URI convergence, is what stops it. We only assert
/// termination (the exact bailed-out URI is an implementation detail of the bound).
const GROWING_N: &str = r#"
RewriteEngine On
RewriteRule ^/(.*)$ /a$1 [N]
"#;

#[test]
fn growing_next_is_bounded_not_infinite() {
    let rs = RuleSet::parse(GROWING_N).expect("parse");
    let input = RewriteInput::new("/seed".to_string(), "/tmp/doc")
        .method("GET")
        .host("h.test");
    // Returns (does not hang) because the [N] restart count is bounded.
    let out = evaluate(&rs, &input);
    match out {
        RewriteOutcome::Rewritten { .. } | RewriteOutcome::Unchanged { .. } => {}
        other => panic!("growing [N] must terminate to a rewrite/unchanged, got {other:?}"),
    }
}
