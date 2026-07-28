//! Repro: a docroot `.htaccess` with an [R=301] redirect followed by a
//! front-controller fallback. Verifies [R] yields an external redirect (not an
//! internal rewrite) and the fallback rewrites unknown paths to index.php.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

const HT: &str = r#"
RewriteEngine On
RewriteRule ^redirect-me$ /landed [R=301,L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php [L]
"#;

fn eval(uri: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(HT).expect("parse");
    // No filesystem -> every -f/-d test is false, so !-f / !-d are true.
    let input = RewriteInput::new(uri.to_string(), "/tmp/doc")
        .method("GET")
        .host("php.test");
    evaluate(&rs, &input)
}

#[test]
fn r301_is_external_redirect() {
    match eval("/redirect-me") {
        RewriteOutcome::Redirect { code, location, .. } => {
            assert_eq!(code, 301, "expected 301");
            assert!(location.ends_with("/landed"), "location was {location}");
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
}

#[test]
fn front_controller_rewrites_unknown_path() {
    match eval("/some/spa/route") {
        RewriteOutcome::Rewritten { new_uri, .. } => {
            assert!(new_uri.ends_with("index.php"), "new_uri was {new_uri}");
        }
        other => panic!("expected Rewritten to index.php, got {other:?}"),
    }
}
