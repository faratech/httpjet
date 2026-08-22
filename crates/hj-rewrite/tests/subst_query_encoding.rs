//! Regression: `$N` captures expand from the DECODED request path, so a capture
//! carrying a literal space (from `%20`) used to reach the substitution's query
//! tail raw — an unparsable URI that made the static terminal silently serve the
//! PRE-rewrite target instead of the authorized one. The query tail is now
//! percent-encoded (path portion already was); `&`/`=` and existing `%XX`
//! escapes survive so QSA-style rules behave unchanged.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

fn eval(rules: &str, path: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).expect("parse");
    let input = RewriteInput::new(path.to_string(), "/tmp/doc")
        .method("GET")
        .host("h.test");
    evaluate(&rs, &input)
}

#[test]
fn capture_with_decoded_space_is_encoded_in_query_tail() {
    let outcome = eval(
        "RewriteEngine On\nRewriteRule ^dl/(.*)$ /files/$1.txt?v=$1 [L]\n",
        "/dl/a%20b",
    );
    match outcome {
        RewriteOutcome::Rewritten {
            new_uri, new_query, ..
        } => {
            assert_eq!(new_uri, "/files/a%20b.txt");
            assert_eq!(
                new_query.as_deref(),
                Some("v=a%20b"),
                "space from the decoded capture must be %20 in BOTH parts"
            );
        }
        other => panic!("expected a rewrite, got {other:?}"),
    }
}

#[test]
fn query_structure_and_existing_escapes_survive() {
    // NOTE: `%<digit>` cannot appear literally in a substitution (it is a
    // cond-backreference, per Apache semantics), so the pre-encoded-escape
    // check uses `%FA`.
    let outcome = eval(
        "RewriteEngine On\nRewriteRule ^x/(.*)$ /y%FAz?keep=%FA&a=$1 [L]\n",
        "/x/z%20q",
    );
    match outcome {
        RewriteOutcome::Rewritten {
            new_uri, new_query, ..
        } => {
            assert_eq!(new_uri, "/y%FAz", "existing %XX escapes stay verbatim");
            assert_eq!(
                new_query.as_deref(),
                Some("keep=%FA&a=z%20q"),
                "`&`/`=`/existing escapes survive; the raw space is encoded"
            );
        }
        other => panic!("expected a rewrite, got {other:?}"),
    }
}
