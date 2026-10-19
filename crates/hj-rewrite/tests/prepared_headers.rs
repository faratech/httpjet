//! `chain_prepared_headers` is `chain_response_headers` with names and static values
//! built at parse time (#982): the same ops in the same order, minus invalid names.

use hj_rewrite::{
    HeaderOp, HeaderOpKind, Htaccess, chain_prepared_headers, chain_response_headers,
};

const FORUM: &str = include_str!("fixtures/header_compat/forum-headers.htaccess");
const SUPPORTED: &str = include_str!("fixtures/header_compat/supported.htaccess");
const SEMANTIC_GAPS: &str = include_str!("fixtures/header_compat/semantic-gaps.htaccess");
const INVALID: &str = "Header set X-Colon: value\n\
                       Header set X-Bad \"a\u{7f}b\"\n\
                       Header add X-Dyn \"%{V}e\"\n\
                       Header append Vary Origin\n\
                       Header merge Cache-Control \"\"\n";

fn parts(op: &HeaderOp) -> (HeaderOpKind, &str, &str) {
    match op {
        HeaderOp::Set { name, value } => (HeaderOpKind::Set, name, value),
        HeaderOp::Add { name, value } => (HeaderOpKind::Add, name, value),
        HeaderOp::Append { name, value } | HeaderOp::Edit { name, value } => {
            (HeaderOpKind::Append, name, value)
        }
        HeaderOp::Merge { name, value } => (HeaderOpKind::Merge, name, value),
        HeaderOp::Unset { name } => (HeaderOpKind::Unset, name, ""),
    }
}

#[test]
fn prepared_ops_mirror_string_ops() {
    let envs: [&[(String, String)]; 3] = [
        &[],
        &[
            ("HTTPS".into(), "on".into()),
            ("ORIGIN_ALLOWED".into(), "https://windowsforum.com".into()),
            ("WF_BETA_CONTROL".into(), "1".into()),
            ("V".into(), "x".into()),
        ],
        &[
            ("v".into(), "bad\u{1}".into()),
            ("FEATURE".into(), "on".into()),
            ("CANONICAL".into(), "https://h/a.css".into()),
        ],
    ];
    let mut seen_static = 0;
    for text in [FORUM, SUPPORTED, SEMANTIC_GAPS, INVALID] {
        let ht = Htaccess::parse(text).unwrap();
        for env in envs {
            for path in ["/", "/index.php", "/a.css", "/service_worker.js", "/x.md"] {
                for status in [200, 404] {
                    let chain = || std::iter::once(&ht);
                    let strings = chain_response_headers(chain(), path, None, path, status, env);
                    let prepared = chain_prepared_headers(chain(), path, None, path, status, env);
                    let expected: Vec<_> = strings
                        .iter()
                        .map(parts)
                        .filter(|(_, name, _)| {
                            http::HeaderName::from_bytes(name.as_bytes()).is_ok()
                        })
                        .collect();
                    assert_eq!(prepared.len(), expected.len(), "{path} {status} {env:?}");
                    for (op, (kind, name, value)) in prepared.iter().zip(expected) {
                        assert_eq!(op.kind, kind);
                        assert_eq!(
                            *op.name,
                            http::HeaderName::from_bytes(name.as_bytes()).unwrap()
                        );
                        assert_eq!(op.value, value);
                        if let Some(v) = op.field_value {
                            seen_static += 1;
                            assert_ne!(kind, HeaderOpKind::Unset);
                            assert_eq!(*v, http::HeaderValue::from_str(value).unwrap());
                        }
                    }
                }
            }
        }
    }
    assert!(seen_static > 0);
}

#[test]
fn only_valid_static_values_are_prebuilt() {
    let ht = Htaccess::parse(INVALID).unwrap();
    let env = [("V".to_string(), "x".to_string())];
    let ops = chain_prepared_headers(std::iter::once(&ht), "/", None, "/", 200, &env);
    let by_name: Vec<_> = ops
        .iter()
        .map(|op| (op.name.as_str(), op.field_value.is_some()))
        .collect();
    assert_eq!(
        by_name,
        [
            ("x-bad", false),
            ("x-dyn", false),
            ("vary", true),
            ("cache-control", true)
        ]
    );
}
