//! Regressions for per-directory re-entry and server-variable parity with OLS:
//! REDIRECT_STATUS on the restart pass (#880), REQUEST_FILENAME stopping at an
//! existing script with PATH_INFO split off (#881), and `%{REMOTE_HOST}` /
//! single-word `%{HTTP_<NAME>}` reads (#882).

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, StatSource, evaluate};

const SYMFONY: &str = "RewriteEngine On
RewriteCond %{REQUEST_URI}::$0 ^(/.+)/(.*)::\\2$
RewriteRule .* - [E=BASE:%1]
RewriteCond %{ENV:REDIRECT_STATUS} =\"\"
RewriteRule ^index\\.php(?:/(.*)|$) %{ENV:BASE}/$1 [R=301,L]
RewriteCond %{REQUEST_FILENAME} -f
RewriteRule ^ - [L]
RewriteRule ^ %{ENV:BASE}/index.php [L]
";

fn eval_with(rules: &str, input: RewriteInput) -> RewriteOutcome {
    evaluate(&RuleSet::parse(rules).expect("parse"), &input)
}

fn rewritten_uri(outcome: RewriteOutcome) -> String {
    match outcome {
        RewriteOutcome::Rewritten { new_uri, .. } => new_uri,
        other => panic!("expected a rewrite, got {other:?}"),
    }
}

#[test]
fn symfony_front_controller_does_not_redirect_its_own_target() {
    for uri in ["/foo", "/"] {
        let mut input = RewriteInput::new(uri.to_string(), "/web/docroot").host("h.test");
        input.per_directory_prefix = Some(String::new());
        assert_eq!(
            rewritten_uri(eval_with(SYMFONY, input)),
            "/index.php",
            "{uri}"
        );
    }
}

#[test]
fn symfony_direct_index_php_still_redirects() {
    let mut input = RewriteInput::new("/index.php/foo", "/web/docroot").host("h.test");
    input.per_directory_prefix = Some(String::new());
    assert!(matches!(
        eval_with(SYMFONY, input),
        RewriteOutcome::Redirect { .. }
    ));
}

#[test]
fn request_filename_splits_path_info_at_existing_script() {
    let dir = std::env::temp_dir().join(format!("hj-rw-pathinfo-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.php"), "<?php").unwrap();
    let stat = |p: &std::path::Path| std::fs::metadata(p).ok();
    let rules = "RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^([\\s\\S]*)$ index.php/$1 [L,NC,QSA]
";
    for (uri, want) in [
        ("/welcome", Some("/index.php/welcome")),
        ("/index.php/welcome", None),
        ("/index.php/", None),
        ("/index.php//", None),
    ] {
        let mut input = RewriteInput::new(uri.to_string(), dir.clone()).host("h.test");
        input.per_directory_prefix = Some(String::new());
        input.stat = StatSource::Live(&stat);
        match (eval_with(rules, input), want) {
            (RewriteOutcome::Rewritten { new_uri, .. }, Some(w)) => assert_eq!(new_uri, w),
            (RewriteOutcome::Unchanged { .. }, None) => {}
            (other, w) => panic!("{uri}: got {other:?}, want {w:?}"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remote_host_and_single_word_headers_are_enforced() {
    let deny_host =
        "RewriteEngine On\nRewriteCond %{REMOTE_HOST} ^203\\.0\\.113\\.\nRewriteRule ^ - [F]\n";
    let input = RewriteInput::new("/x", "/web/docroot").remote_addr("203.0.113.9");
    assert!(matches!(
        eval_with(deny_host, input),
        RewriteOutcome::Forbidden { .. }
    ));

    let deny_auth =
        "RewriteEngine On\nRewriteCond %{HTTP_AUTHORIZATION} ^Bearer\nRewriteRule ^ - [F]\n";
    let input = RewriteInput::new("/x", "/web/docroot").header("Authorization", "Bearer t");
    assert!(matches!(
        eval_with(deny_auth, input),
        RewriteOutcome::Forbidden { .. }
    ));
    let rs = RuleSet::parse(deny_auth).unwrap();
    assert!(rs.header_reads.iter().any(|h| h == "authorization"));
}
