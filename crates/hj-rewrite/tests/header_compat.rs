//! Executable inventory for the current `Header`/`RequestHeader` compatibility
//! boundary. These tests deliberately pin gaps; changing an assertion requires
//! updating `docs/header-directive-compatibility.md` in the same review.

use hj_rewrite::{HeaderOp, Htaccess};

const SUPPORTED: &str = include_str!("fixtures/header_compat/supported.htaccess");
const IGNORED: &str = include_str!("fixtures/header_compat/ignored-actions.htaccess");
const SEMANTIC_GAPS: &str = include_str!("fixtures/header_compat/semantic-gaps.htaccess");

#[test]
fn implemented_response_actions_are_emitted_in_source_order() {
    let ht = Htaccess::parse(SUPPORTED).unwrap();
    let env = vec![("FEATURE".to_string(), "enabled".to_string())];
    assert_eq!(
        ht.response_headers("/index.html", 200, &env),
        vec![
            HeaderOp::Set {
                name: "X-Set".into(),
                value: "replacement".into(),
            },
            HeaderOp::Add {
                name: "Set-Cookie".into(),
                value: "a=1".into(),
            },
            HeaderOp::Append {
                name: "Vary".into(),
                value: "Accept-Encoding".into(),
            },
            HeaderOp::Merge {
                name: "Cache-Control".into(),
                value: "no-store".into(),
            },
            HeaderOp::Unset {
                name: "X-Remove".into(),
            },
            HeaderOp::Set {
                name: "X-Always".into(),
                value: "present".into(),
            },
            HeaderOp::Set {
                name: "X-Env".into(),
                value: "enabled".into(),
            },
        ]
    );
}

#[test]
fn onsuccess_is_status_gated_while_always_survives_an_error() {
    let ht = Htaccess::parse(SUPPORTED).unwrap();
    assert_eq!(
        ht.response_headers("/index.html", 500, &[]),
        vec![HeaderOp::Set {
            name: "X-Always".into(),
            value: "present".into(),
        }]
    );
}

#[test]
fn request_header_and_unimplemented_response_actions_are_ignored() {
    let ht = Htaccess::parse(IGNORED).unwrap();
    assert!(!ht.has_resp_op);
    assert!(ht.response_headers("/index.html", 200, &[]).is_empty());
}

#[test]
fn parsed_semantic_gaps_remain_explicit() {
    let ht = Htaccess::parse(SEMANTIC_GAPS).unwrap();

    let success = ht.response_headers("/index.html", 200, &[]);
    assert!(success.contains(&HeaderOp::Merge {
        name: "Cache-Control".into(),
        value: "no-cache".into(),
    }));
    assert!(
        !success.iter().any(|op| op.name().starts_with("^X-Request")),
        "Header echo is parsed but intentionally emits no operation"
    );
    assert!(success.contains(&HeaderOp::Set {
        name: "X-Early".into(),
        value: "late-only".into(),
    }));
    assert!(success.contains(&HeaderOp::Set {
        name: "X-Colon:".into(),
        value: "value".into(),
    }));
}

#[test]
fn unsupported_header_guards_reject_the_access_file() {
    for guard in [
        "%{HTTP_COOKIE} == ''",
        "%{REQUEST_STATUS} == 200",
        "",
        "%{REQUEST_URI} =~ m#^/# && %{HTTP_COOKIE} == ''",
        "%{REQUEST_URI} =~ m#^/# || %{HTTP_COOKIE} == ''",
        "(%{HTTP_COOKIE} == '')",
    ] {
        let text = format!("Header set X-LiteSpeed-Cache-Control public \"expr={guard}\"\n");
        assert!(Htaccess::parse(&text).is_err(), "{guard}");
    }
}

#[test]
fn supported_header_guards_preserve_conjunctions_and_regex_operators() {
    let ht = Htaccess::parse(r##"Header set Cache-Control public "expr=%{REQUEST_URI} =~ m#^/public/# && %{REQUEST_URI} !~ m#private#""##).unwrap();
    assert_eq!(ht.response_headers("/public/file", 200, &[]).len(), 1);
    assert!(ht.response_headers("/public/private", 200, &[]).is_empty());
    assert!(ht.response_headers("/other", 200, &[]).is_empty());
}

#[test]
fn unsupported_enclosing_expression_cannot_mutate_headers() {
    assert!(
        Htaccess::parse("<If \"%{HTTP_COOKIE} == ''\">\nHeader set Cache-Control public\n</If>\n")
            .is_err()
    );
    assert!(Htaccess::parse("Header set Cache-Control public env=A env=B").is_err());
}

#[test]
fn either_quote_style_and_malformed_guards_fail_closed() {
    for text in [
        "Header set X-Review guarded 'expr=%{REQUEST_STATUS} == 200'",
        "Header set X-Review guarded \"expr=%{REQUEST_STATUS} == 200",
        "Header set X-Review guarded 'expr=%{REQUEST_URI} =~ m#^/# && %{HTTP_COOKIE} == 1'",
        "Header set X-Review guarded Expr=%{REQUEST_STATUS}",
    ] {
        assert!(Htaccess::parse(text).is_err(), "{text}");
    }
    let ht = Htaccess::parse("Header set X-Review guarded 'expr=%{REQUEST_URI} =~ m#^/public/#'")
        .unwrap();
    assert_eq!(ht.response_headers("/public/file", 200, &[]).len(), 1);
    assert!(ht.response_headers("/other", 200, &[]).is_empty());
}
