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
            // Current gap: Merge is represented as Append and does not
            // de-duplicate an existing comma-delimited value.
            HeaderOp::Append {
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
    assert!(success.contains(&HeaderOp::Append {
        name: "Cache-Control".into(),
        value: "no-cache".into(),
    }));
    assert!(
        !success.iter().any(|op| op.name().starts_with("^X-Request")),
        "Header echo is parsed but intentionally emits no operation"
    );
    assert!(success.contains(&HeaderOp::Set {
        name: "X-Expr-Value".into(),
        value: String::new(),
    }));
    assert!(success.contains(&HeaderOp::Set {
        name: "X-Early".into(),
        value: "late-only".into(),
    }));
    assert!(success.contains(&HeaderOp::Set {
        name: "X-Colon:".into(),
        value: "value".into(),
    }));

    let error = ht.response_headers("/index.html", 500, &[]);
    assert!(
        error.contains(&HeaderOp::Set {
            name: "X-Expr-Guard".into(),
            value: "guarded".into(),
        }),
        "an unsupported expression currently collapses to no guard"
    );
}
