use hj_compress::ExpiresBase;
use hj_rewrite::{ExpiresDecision, Htaccess, expires_decision};

fn decide(chain: &[Htaccess], path: &str, content_type: &str) -> ExpiresDecision {
    let basename = path.rsplit('/').next().unwrap_or("");
    expires_decision(chain.iter(), path, path, basename, content_type)
}

fn rule(decision: ExpiresDecision) -> hj_compress::ExpiresRule {
    match decision {
        ExpiresDecision::Rule { rule, .. } => rule,
        other => panic!("expected expiry rule, got {other:?}"),
    }
}

#[test]
fn root_child_inheritance_and_type_over_default() {
    let root = Htaccess::parse(
        r#"
<IfModule mod_expires.c>
ExpiresActive On
ExpiresByType image/* "access 1 year"
ExpiresDefault "access 2 days"
</IfModule>
"#,
    )
    .unwrap();
    let child = Htaccess::parse(
        r#"
ExpiresByType text/css "access 1 month"
ExpiresDefault "access 3 days"
"#,
    )
    .unwrap();
    let chain = [root, child];

    let image = rule(decide(&chain, "/child/logo.png", "image/png"));
    assert_eq!(image.base, ExpiresBase::Access);
    assert_eq!(image.age_secs, 365 * 86_400);
    assert_eq!(
        rule(decide(&chain, "/child/site.css", "text/css")).age_secs,
        30 * 86_400
    );
    assert_eq!(
        rule(decide(&chain, "/child/readme.txt", "text/plain")).age_secs,
        3 * 86_400
    );
}

#[test]
fn active_off_is_scoped_and_child_overrides_parent() {
    let root = Htaccess::parse(
        r#"
ExpiresActive On
ExpiresDefault "access 2 days"
<LocationMatch "^/builds/">
ExpiresActive Off
</LocationMatch>
<FilesMatch "\.private$">
ExpiresActive Off
</FilesMatch>
"#,
    )
    .unwrap();
    assert_eq!(
        decide(
            std::slice::from_ref(&root),
            "/builds/logo.webp",
            "image/webp"
        ),
        ExpiresDecision::Off
    );
    assert!(matches!(
        decide(
            std::slice::from_ref(&root),
            "/styles/logo.webp",
            "image/webp"
        ),
        ExpiresDecision::Rule { .. }
    ));
    assert_eq!(
        decide(std::slice::from_ref(&root), "/x/a.private", "text/plain"),
        ExpiresDecision::Off
    );

    let child = Htaccess::parse("ExpiresActive Off\n").unwrap();
    assert_eq!(
        decide(
            &[root, child],
            "/admin/tokens/app.js",
            "application/javascript"
        ),
        ExpiresDecision::Off
    );
}

#[test]
fn absent_malformed_and_unmodelled_declarations_fail_closed() {
    let no_active = Htaccess::parse("ExpiresDefault \"access 2 days\"\n").unwrap();
    assert!(matches!(
        decide(&[no_active], "/a.txt", "text/plain"),
        ExpiresDecision::Rule {
            kind: hj_rewrite::ExpiresRuleKind::Default,
            inherit_active: true,
            ..
        }
    ));
    let on_only = Htaccess::parse("ExpiresActive On\n").unwrap();
    assert_eq!(
        decide(&[on_only], "/a.txt", "text/plain"),
        ExpiresDecision::On
    );

    for text in [
        "ExpiresActive maybe\n",
        "ExpiresActive On\nExpiresDefault nonsense\n",
        "ExpiresActive On\nExpiresByType bad-type \"access 1 day\"\n",
        "ExpiresActive On\n<Unknown condition>\nExpiresDefault \"access 1 day\"\n</Unknown>\n",
        "ExpiresActive On\n<LocationMatch \"[\">\nExpiresActive Off\n</LocationMatch>\n",
    ] {
        let parsed = Htaccess::parse(text).unwrap();
        assert_eq!(
            decide(&[parsed], "/a.txt", "text/plain"),
            ExpiresDecision::Off,
            "{text:?}"
        );
    }
}
