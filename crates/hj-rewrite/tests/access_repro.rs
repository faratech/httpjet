use hj_rewrite::{AccessDecision, Htaccess};

#[test]
fn filesmatch_require_denied_blocks_dotfiles() {
    let src = r#"RewriteEngine On
<FilesMatch "^(\.env|config\.php|\.htaccess|composer\.(json|lock)|.*\.md)$">
    Require all denied
</FilesMatch>
<FilesMatch "\.log$">
    Require all denied
</FilesMatch>
<Files "robots.txt">
    Require all granted
</Files>
"#;
    let h = Htaccess::parse(src).expect("parse ok");
    eprintln!("access_rules.len() = {}", h.access_rules.len());
    for r in &h.access_rules {
        eprintln!("  rule denied={} matchers={}", r.denied, r.matchers.len());
    }
    assert_eq!(
        h.access_decision("/.env", "GET"),
        AccessDecision::Denied,
        ".env"
    );
    assert_eq!(
        h.access_decision("/config.php", "GET"),
        AccessDecision::Denied,
        "config.php"
    );
    assert_eq!(
        h.access_decision("/README.md", "GET"),
        AccessDecision::Denied,
        "README.md"
    );
    assert_eq!(
        h.access_decision("/x.log", "GET"),
        AccessDecision::Denied,
        "x.log"
    );
    assert_eq!(
        h.access_decision("/index.php", "GET"),
        AccessDecision::NoOpinion,
        "index.php allowed"
    );
}

#[test]
fn path_info_basename_does_not_match_files_deny_but_script_path_does() {
    // (#1 PATH_INFO deny bypass) `<FilesMatch>` is basename-scoped, so the FULL
    // request path `/install.php/x` (basename `x`) does NOT match the deny — yet
    // the request maps to script `/install.php`. The pipeline must therefore
    // re-run the access decision against the SCRIPT path, which DOES match.
    // This test pins both halves of that contract.
    let src = r#"RewriteEngine On
<FilesMatch "(config\.php|wp-config\.php|install\.php|xmlrpc\.php|adminer\.php)$">
    Require all denied
</FilesMatch>
"#;
    let h = Htaccess::parse(src).expect("parse ok");
    // Direct invocation is correctly denied.
    assert_eq!(
        h.access_decision("/install.php", "GET"),
        AccessDecision::Denied,
        "install.php denied"
    );
    // With a PATH_INFO segment, the basename is `x` -> the deny does NOT match the
    // full path (this is the divergence the pipeline fix compensates for).
    assert_eq!(
        h.access_decision("/install.php/x", "GET"),
        AccessDecision::NoOpinion,
        "full path basename is `x`, deny does not match"
    );
    // ...but the resolved SCRIPT path still matches the deny (what the pipeline
    // now also checks before executing the script).
    assert_eq!(
        h.access_decision("/install.php", "GET"),
        AccessDecision::Denied,
        "script path is denied"
    );
}

#[test]
fn unmodellable_if_grant_does_not_fail_open() {
    // An `<If>` whose condition we cannot model (a `%{HTTP_HOST}` test, not the
    // `%{REQUEST_URI}` form the engine understands) must NOT let an enclosed
    // `Require all granted` widen to a directory-wide grant that overrides a sibling
    // deny. The unverifiable grant is dropped (fail-closed).
    let src = r#"RewriteEngine On
<FilesMatch "\.log$">
    Require all denied
</FilesMatch>
<If "%{HTTP_HOST} == 'evil.example'">
    Require all granted
</If>
"#;
    let h = Htaccess::parse(src).expect("parse ok");
    // The unverifiable grant must not override the .log deny...
    assert_eq!(
        h.access_decision("/secret.log", "GET"),
        AccessDecision::Denied,
        ".log stays denied"
    );
    // ...nor grant an opinion on arbitrary paths.
    assert_eq!(
        h.access_decision("/index.php", "GET"),
        AccessDecision::NoOpinion,
        "no directory-wide grant"
    );
}

#[test]
fn unmodellable_if_deny_still_applies() {
    // A DENY under an unmodellable `<If>` is fail-safe: we cannot verify the
    // condition, so we keep the restriction (it applies broadly).
    let src = r#"RewriteEngine On
<If "%{HTTP_HOST} == 'evil.example'">
    Require all denied
</If>
"#;
    let h = Htaccess::parse(src).expect("parse ok");
    assert_eq!(
        h.access_decision("/anything", "GET"),
        AccessDecision::Denied,
        "deny applies broadly"
    );
}

#[test]
fn partially_unmodellable_if_grant_does_not_drop_unknown_conjunct() {
    let src = r#"Require all denied
<If "%{REQUEST_URI} =~ m#^/admin# && %{HTTP_HOST} == 'trusted.example'">
    Require all granted
</If>
"#;
    let h = Htaccess::parse(src).expect("parse ok");
    assert_eq!(
        h.access_decision("/admin", "GET"),
        AccessDecision::Denied,
        "an unsupported conjunct must withhold the conditional grant"
    );
}

#[test]
fn if_uri_or_expression_evaluates_every_branch() {
    let src = r#"<If "%{REQUEST_URI} =~ m#^/private-a# || %{REQUEST_URI} =~ m#^/private-b#">
    Require all denied
</If>
"#;
    let h = Htaccess::parse(src).expect("parse ok");
    assert_eq!(
        h.access_decision("/private-a", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/private-b", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/public", "GET"),
        AccessDecision::NoOpinion
    );
}

#[test]
fn if_uri_parentheses_preserve_boolean_grouping() {
    let src = r#"<If "(%{REQUEST_URI} =~ m#^/private-a# || %{REQUEST_URI} =~ m#^/private-b#) && %{REQUEST_URI} !~ m#/public$#">
    Require all denied
</If>
"#;
    let h = Htaccess::parse(src).expect("parse ok");
    assert_eq!(
        h.access_decision("/private-a/secret", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/private-b/secret", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/private-a/public", "GET"),
        AccessDecision::NoOpinion
    );
    assert_eq!(
        h.access_decision("/other/secret", "GET"),
        AccessDecision::NoOpinion
    );
}

#[test]
fn directorymatch_denies_files_inside_the_directory() {
    // `<DirectoryMatch>` must deny everything BENEATH the matched directory, not
    // just a path that itself matches the dir regex (XenForo internal_data, .git).
    let src = r#"RewriteEngine On
<DirectoryMatch "^.*/(\.git|\.svn|internal_data|node_modules)$">
    Require all denied
</DirectoryMatch>
"#;
    let h = Htaccess::parse(src).expect("parse ok");
    assert_eq!(
        h.access_decision("/internal_data", "GET"),
        AccessDecision::Denied,
        "the dir itself"
    );
    assert_eq!(
        h.access_decision("/internal_data/config.php", "GET"),
        AccessDecision::Denied,
        "file in dir"
    );
    assert_eq!(
        h.access_decision("/internal_data/deep/sub/x", "GET"),
        AccessDecision::Denied,
        "deep file"
    );
    assert_eq!(
        h.access_decision("/.git/config", "GET"),
        AccessDecision::Denied,
        ".git/config"
    );
    assert_eq!(
        h.access_decision("/styles/public/x.css", "GET"),
        AccessDecision::NoOpinion,
        "unrelated allowed"
    );
}
