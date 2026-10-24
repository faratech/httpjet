//! Backreference escaping in RewriteRule substitutions: a `?` that `$N`/`%N`
//! carries into the path part (from a decoded `%3F`) must not split the target
//! (OLS `escape_unsafe_3f`, CVE-2024-38474), and the `[B]` family escapes the
//! backreference itself (OLS `escape_uri`).

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

fn run(rules: &str, uri: &str, query: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).unwrap();
    let mut input = RewriteInput::new(uri, "/nonexistent").query(query);
    input.per_directory_prefix = Some(String::new());
    evaluate(&rs, &input)
}

fn rewritten(out: RewriteOutcome) -> (String, Option<String>) {
    match out {
        RewriteOutcome::Rewritten {
            new_uri, new_query, ..
        } => (new_uri, new_query),
        other => panic!("expected Rewritten, got {other:?}"),
    }
}

#[test]
fn decoded_question_mark_in_rule_backref_keeps_the_forced_suffix() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^files/(.*)$ /store/$1.pdf [L]\n",
        "/files/secret.txt?",
        "",
    );
    assert_eq!(
        rewritten(out),
        ("/store/secret.txt%3F.pdf".to_string(), None)
    );
}

#[test]
fn decoded_question_mark_in_cond_backref_is_escaped_in_the_path_part() {
    let out = run(
        "RewriteEngine On\nRewriteCond %{REQUEST_URI} ^/c/(.*)$\nRewriteRule ^c/ /d/%1.html [L]\n",
        "/c/a?b",
        "",
    );
    assert_eq!(rewritten(out).0, "/d/a%3Fb.html");
}

#[test]
fn backref_in_the_query_part_is_unchanged() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^q/(.*)$ /s.php?v=$1 [L]\n",
        "/q/a?b",
        "",
    );
    assert_eq!(
        rewritten(out),
        ("/s.php".to_string(), Some("v=a?b".to_string()))
    );
}

#[test]
fn unsafe_allow_3f_restores_the_split() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^files/(.*)$ /store/$1.pdf [L,UnsafeAllow3F]\n",
        "/files/secret.txt?",
        "",
    );
    assert_eq!(
        rewritten(out),
        ("/store/secret.txt".to_string(), Some(".pdf".to_string()))
    );
}

#[test]
fn b_flag_escapes_ampersand_injection_in_the_query() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^search/(.*)$ /s.php?q=$1&safe=1 [B,L]\n",
        "/search/a&admin=1",
        "",
    );
    assert_eq!(
        rewritten(out),
        (
            "/s.php".to_string(),
            Some("q=a%26admin%3D1&safe=1".to_string())
        )
    );
}

#[test]
fn b_flag_variants() {
    let rules =
        |flags: &str| format!("RewriteEngine On\nRewriteRule ^s/(.*)$ /s.php?q=$1 [{flags},L]\n");
    let q = |flags: &str| rewritten(run(&rules(flags), "/s/a b&c", "")).1.unwrap();
    assert_eq!(q("B"), "q=a+b%26c");
    assert_eq!(q("BNP"), "q=a%20b%26c");
    assert_eq!(q("B,BNE=&"), "q=a+b&c");
    assert_eq!(q("B=&"), "q=a%20b%26c");
}

#[test]
fn proxy_target_keeps_an_encoded_question_mark_in_the_path() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^monit/(.*)$ http://localhost:2812/$1 [P,L]\n",
        "/monit/x?admin=1",
        "",
    );
    match out {
        RewriteOutcome::Proxy { target_url, .. } => {
            assert_eq!(target_url, "http://localhost:2812/x%3Fadmin=1")
        }
        other => panic!("expected Proxy, got {other:?}"),
    }
}

#[test]
fn b_family_flags_that_keep_question_mark_literal_still_escape_it() {
    // OLS escapes `?` after the [B] family's escape_uri, so these never split (#753).
    for flags in ["BCTLS,L", "B=&,L", "B,BNE=?,L"] {
        let out = run(
            &format!("RewriteEngine On\nRewriteRule ^files/(.*)$ /store/$1.pdf [{flags}]\n"),
            "/files/secret?",
            "",
        );
        let (uri, query) = rewritten(out);
        assert!(uri.ends_with("%3F.pdf"), "{flags}: {uri}");
        assert_eq!(query, None, "{flags}");
    }
}

fn proxy(out: RewriteOutcome) -> (String, Option<String>, Vec<(String, String)>) {
    match out {
        RewriteOutcome::Proxy {
            target_url,
            proxy_host,
            env,
            ..
        } => (target_url, proxy_host, env),
        other => panic!("expected Proxy, got {other:?}"),
    }
}

/// #869: the authority of an absolute substitution is not path-escaped, so an
/// IPv6 literal's brackets survive into the `[P]` target.
#[test]
fn proxy_target_keeps_an_ipv6_literal_authority() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^api/(.*)$ http://[::1]:8080/v1/$1 [P,L]\n",
        "/api/a b",
        "",
    );
    assert_eq!(proxy(out).0, "http://[::1]:8080/v1/a%20b");
}

/// #869: the same holds for an `[R]` Location.
#[test]
fn redirect_location_keeps_an_ipv6_literal_authority() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^go/(.*)$ http://[2001:db8::5]:8443/$1 [R=302,L]\n",
        "/go/x y",
        "",
    );
    match out {
        RewriteOutcome::Redirect { location, .. } => {
            assert_eq!(location, "http://[2001:db8::5]:8443/x%20y")
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
}

/// #869: bytes the authority grammar forbids are still escaped there.
#[test]
fn proxy_target_escapes_forbidden_authority_bytes() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^h/([^/]+)/(.*)$ http://$1/$2 [P,L]\n",
        "/h/a b/c",
        "",
    );
    assert_eq!(proxy(out).0, "http://a%20b/c");
}

/// #870: `[P,E=Proxy-Host:value]` is the upstream Host override (OLS
/// `setNewHost`), not an env var.
#[test]
fn proxy_host_flag_is_carried_on_the_proxy_outcome() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^preview/([^/]*)/(.*)$ http://127.0.0.1:9/$2 [P,E=Proxy-Host:$1,E=keep:1]\n",
        "/preview/app.example/x",
        "",
    );
    let (target, host, env) = proxy(out);
    assert_eq!(target, "http://127.0.0.1:9/x");
    assert_eq!(host.as_deref(), Some("app.example"));
    assert!(env.iter().any(|(k, v)| k == "keep" && v == "1"));
    assert!(
        !env.iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Proxy-Host"))
    );
}

/// #870: on a non-`[P]` rule `E=Proxy-Host` stays an ordinary env var (OLS).
#[test]
fn proxy_host_on_a_non_proxy_rule_is_an_env_var() {
    let out = run(
        "RewriteEngine On\nRewriteRule ^a$ /b [E=Proxy-Host:h,L]\n",
        "/a",
        "",
    );
    match out {
        RewriteOutcome::Rewritten { env, .. } => {
            assert!(env.iter().any(|(k, v)| k == "Proxy-Host" && v == "h"))
        }
        other => panic!("expected Rewritten, got {other:?}"),
    }
}
