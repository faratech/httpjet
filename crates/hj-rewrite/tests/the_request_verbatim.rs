//! Regression (audit): `%{THE_REQUEST}` used to resolve from the DECODED canonical
//! path (`/a%2Eb` -> `/a.b`), so verbatim request-line conds — like the live
//! `RewriteCond %{THE_REQUEST} ^[A-Z]+\ /rss/index%2Ephp...` shape — never matched.
//! When the pipeline attaches `raw_request_target`, the var resolves from the
//! exact bytes the client sent; without it, the decoded fallback applies.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

const RULES: &str = "RewriteEngine On\n\
     RewriteCond %{THE_REQUEST} /rss/index%2Ephp\\?x=1\n\
     RewriteRule ^ - [F,L]\n";

#[test]
fn the_request_matches_the_verbatim_encoded_target() {
    let rs = RuleSet::parse(RULES).expect("parse");
    let mut input = RewriteInput::new("/rss/index.php".to_string(), "/tmp/doc").method("GET");
    input.raw_request_target = Some("/rss/index%2Ephp?x=1".to_string());
    assert!(
        matches!(evaluate(&rs, &input), RewriteOutcome::Forbidden { .. }),
        "the verbatim %2E form must match when the raw target is attached"
    );
}

#[test]
fn decoded_fallback_applies_without_an_attached_raw_target() {
    let rs = RuleSet::parse(RULES).expect("parse");
    let input = RewriteInput::new("/rss/index.php".to_string(), "/tmp/doc")
        .method("GET")
        .query("x=1");
    assert!(
        matches!(evaluate(&rs, &input), RewriteOutcome::Unchanged { .. }),
        "the decoded path must not satisfy an encoded literal"
    );
}

#[test]
fn uses_the_request_flag_gates_the_attachment_cost() {
    let rs = RuleSet::parse(RULES).expect("parse");
    assert!(rs.uses_the_request, "reading THE_REQUEST sets the flag");
    let plain = RuleSet::parse("RewriteEngine On\nRewriteRule ^/a$ /b [L]\n").expect("parse");
    assert!(!plain.uses_the_request, "unrelated rulesets keep it false");
}
