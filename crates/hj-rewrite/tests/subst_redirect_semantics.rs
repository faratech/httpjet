//! Substitution-shape semantics that decide redirect vs internal rewrite,
//! mirroring OLS rewriteengine.cpp's end-of-ruleset target handling.

use hj_rewrite::{RewriteInput, RewriteOutcome, RuleSet, evaluate};

fn eval(rules: &str, input: RewriteInput) -> RewriteOutcome {
    evaluate(&RuleSet::parse(rules).expect("parse"), &input)
}

fn redirect(outcome: RewriteOutcome) -> (u16, String) {
    match outcome {
        RewriteOutcome::Redirect { code, location, .. } => (code, location),
        other => panic!("expected Redirect, got {other:?}"),
    }
}

#[test]
fn absolute_url_without_r_flag_is_a_302() {
    let out = eval(
        "RewriteEngine On\nRewriteRule ^old$ http://other.com/new [L]",
        RewriteInput::new("/old", "/d").host("me.com"),
    );
    assert_eq!(redirect(out), (302, "http://other.com/new".to_string()));
}

#[test]
fn absolute_url_without_r_flag_keeps_the_query() {
    let out = eval(
        "RewriteEngine On\nRewriteRule ^old$ HTTPS://other.com/new",
        RewriteInput::new("/old", "/d").host("me.com").query("a=1"),
    );
    assert_eq!(
        redirect(out),
        (302, "HTTPS://other.com/new?a=1".to_string())
    );
}

#[test]
fn relative_redirect_target_gets_rewrite_base() {
    let out = eval(
        "RewriteEngine On\nRewriteBase /other/\nRewriteRule ^a/b$ new [R=301,L]",
        RewriteInput::new("/a/b", "/d").host("me.com"),
    );
    assert_eq!(redirect(out), (301, "http://me.com/other/new".to_string()));
}

#[test]
fn relative_redirect_target_gets_per_directory_prefix() {
    let mut input = RewriteInput::new("/sub/a/b", "/d").host("me.com");
    input.per_directory_prefix = Some("sub/".into());
    let out = eval(
        "RewriteEngine On\nRewriteRule ^a/b$ new?x=1 [R=301,L]",
        input,
    );
    assert_eq!(
        redirect(out),
        (301, "http://me.com/sub/new?x=1".to_string())
    );
}

#[test]
fn optional_multibyte_char_is_not_part_of_the_literal_prefix() {
    let rules = "RewriteEngine On\nRewriteRule ^caf\u{e9}?x$ - [F]";
    for uri in ["/cafx", "/caf\u{e9}x"] {
        match eval(rules, RewriteInput::new(uri, "/d")) {
            RewriteOutcome::Forbidden { .. } => {}
            other => panic!("{uri}: expected Forbidden, got {other:?}"),
        }
    }
    match eval(rules, RewriteInput::new("/cabx", "/d")) {
        RewriteOutcome::Unchanged { .. } => {}
        other => panic!("expected Unchanged, got {other:?}"),
    }
}

#[test]
fn absolute_url_promotion_waits_for_later_rules() {
    // OLS promotes to 302 only after the rule loop: a later [F] still applies.
    let out = eval(
        "RewriteEngine On\nRewriteRule ^old$ http://other.com/new\nRewriteRule ^ - [F]",
        RewriteInput::new("/old", "/d").host("me.com"),
    );
    assert!(matches!(out, RewriteOutcome::Forbidden { .. }), "{out:?}");
}

#[test]
fn absolute_url_naming_the_current_url_is_not_a_redirect_loop() {
    let out = eval(
        "RewriteEngine On\nRewriteRule ^(.*)$ http://me.com/$1",
        RewriteInput::new("/x", "/d").host("me.com"),
    );
    assert!(matches!(out, RewriteOutcome::Unchanged { .. }), "{out:?}");
    let out = eval(
        "RewriteEngine On\nRewriteRule ^(.*)$ http://other.com/$1",
        RewriteInput::new("/x", "/d").host("me.com"),
    );
    assert_eq!(redirect(out), (302, "http://other.com/x".to_string()));
}

#[test]
fn informational_r_code_is_never_a_final_status() {
    let out = eval(
        "RewriteEngine On\nRewriteRule ^a$ /b [R=103,L]",
        RewriteInput::new("/a", "/d").host("me.com"),
    );
    assert!(
        matches!(out, RewriteOutcome::Redirect { code: 302, .. }),
        "{out:?}"
    );
}

#[test]
fn self_target_guard_compares_decoded_paths_and_ports() {
    let rules = "RewriteEngine On\nRewriteRule ^(.*)$ http://me.com/$1";
    for path in ["/a b", "/caf\u{e9}"] {
        let out = eval(rules, RewriteInput::new(path, "/d").host("me.com"));
        assert!(
            matches!(out, RewriteOutcome::Unchanged { .. }),
            "{path}: {out:?}"
        );
    }
    let alt = || {
        let mut i = RewriteInput::new("/x", "/d")
            .host("me.com")
            .server_port(8080);
        i.host_port = Some(8080);
        i
    };
    assert_eq!(
        redirect(eval(rules, alt())),
        (302, "http://me.com/x".to_string())
    );
    let out = eval(
        "RewriteEngine On\nRewriteRule ^(.*)$ http://me.com:8080/$1",
        alt(),
    );
    assert!(matches!(out, RewriteOutcome::Unchanged { .. }), "{out:?}");
    let out = eval(
        "RewriteEngine On\nRewriteRule ^(.*)$ https://me.com:443/$1",
        RewriteInput::new("/x", "/d")
            .host("me.com")
            .https(true)
            .server_port(443),
    );
    assert!(matches!(out, RewriteOutcome::Unchanged { .. }), "{out:?}");
}

#[test]
fn self_target_guard_uses_the_host_port_and_v6_literals() {
    // #703: behind PROXY protocol the socket port (8443) differs from the port the
    // client used (443, implicit); the guard follows the Host header.
    let rules = "RewriteEngine On\nRewriteRule ^/?(.*)$ https://example.com/$1";
    let behind_lb = RewriteInput::new("/x", "/d")
        .host("example.com")
        .https(true)
        .server_port(8443);
    let out = eval(rules, behind_lb);
    assert!(matches!(out, RewriteOutcome::Unchanged { .. }), "{out:?}");
    for (target, host_port) in [
        ("http://[::1]/$1", None),
        ("http://[::1]:8080/$1", Some(8080)),
    ] {
        let mut i = RewriteInput::new("/x", "/d").host("::1");
        i.host_port = host_port;
        let out = eval(
            &format!("RewriteEngine On\nRewriteRule ^/?(.*)$ {target} [NE]"),
            i,
        );
        assert!(
            matches!(out, RewriteOutcome::Unchanged { .. }),
            "{target}: {out:?}"
        );
    }
}
