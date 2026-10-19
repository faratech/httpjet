//! Access-section containers that are not plain scopes: `<Limit>`/`<LimitExcept>`
//! (method filters), `<Else>`/`<ElseIf>` (negated `<If>` chains) and
//! `<RequireAll>`/`<RequireAny>`/`<RequireNone>` (combined verdicts), plus
//! Apache's section merge order, slash-delimited `<If>` regexes, a leading BOM,
//! malformed sections and whitespace inside `Require all granted`.

use hj_rewrite::{AccessDecision, AccessSubject, Htaccess};

fn subject() -> AccessSubject<'static> {
    AccessSubject {
        client_ip: Some("203.0.113.9".parse().unwrap()),
        env_set: None,
    }
}

fn decide(src: &str, path: &str, method: &str) -> AccessDecision {
    Htaccess::parse(src)
        .unwrap()
        .access_decision_for(path, method, &subject())
}

#[test]
fn else_branch_is_the_negation_of_its_if() {
    let src = "<If \"%{REQUEST_URI} =~ m#^/admin#\">\nRequire all denied\n</If>\n<Else>\nRequire all granted\n</Else>\n";
    assert_eq!(decide(src, "/admin/x", "GET"), AccessDecision::Denied);
    assert_eq!(decide(src, "/public", "GET"), AccessDecision::Granted);
}

#[test]
fn elseif_requires_its_own_condition_and_no_earlier_match() {
    let src = "<If \"%{REQUEST_URI} =~ m#^/a#\">\nRequire all granted\n</If>\n\
               <ElseIf \"%{REQUEST_URI} =~ m#^/b#\">\nRequire all denied\n</ElseIf>\n\
               <Else>\nRequire all granted\n</Else>\n";
    assert_eq!(decide(src, "/a/b", "GET"), AccessDecision::Granted);
    assert_eq!(decide(src, "/b/x", "GET"), AccessDecision::Denied);
    assert_eq!(decide(src, "/c", "GET"), AccessDecision::Granted);
}

#[test]
fn else_after_an_unmodellable_if_keeps_denies_and_drops_grants() {
    let deny = "<If \"%{HTTP_HOST} == 'x'\">\nRequire all granted\n</If>\n<Else>\nRequire all denied\n</Else>\n";
    assert_eq!(decide(deny, "/x", "GET"), AccessDecision::Denied);
    let grant = "Require all denied\n<If \"%{HTTP_HOST} == 'x'\">\nRequire all denied\n</If>\n<Else>\nRequire all granted\n</Else>\n";
    assert_eq!(decide(grant, "/x", "GET"), AccessDecision::Denied);
}

#[test]
fn limit_grant_for_other_methods_does_not_open_a_files_deny() {
    let src = "<Files secret.php>\nRequire all denied\n</Files>\n<Limit OPTIONS>\nRequire all granted\n</Limit>\n";
    assert_eq!(decide(src, "/secret.php", "GET"), AccessDecision::Denied);
}

#[test]
fn wordpress_files_deny_survives_a_later_cpanel_limit_allow() {
    let src = "<Files wp-config.php>\norder allow,deny\ndeny from all\n</Files>\n\
               <Limit GET POST>\norder allow,deny\nallow from all\n</Limit>\n";
    assert_eq!(decide(src, "/wp-config.php", "GET"), AccessDecision::Denied);
    assert_eq!(decide(src, "/index.php", "GET"), AccessDecision::Granted);
}

#[test]
fn cpanel_limit_pair_denies_only_the_listed_methods() {
    let src = "<Limit GET POST>\norder allow,deny\nallow from all\n</Limit>\n\
               <Limit PUT DELETE>\norder deny,allow\ndeny from all\n</Limit>\n";
    assert_eq!(decide(src, "/index.html", "GET"), AccessDecision::Granted);
    assert_eq!(decide(src, "/index.html", "HEAD"), AccessDecision::Granted);
    assert_eq!(decide(src, "/index.html", "PUT"), AccessDecision::Denied);
    assert_eq!(decide(src, "/index.html", "DELETE"), AccessDecision::Denied);
    assert!(!Htaccess::parse(src).unwrap().memo.eligible);
}

#[test]
fn limit_except_applies_to_unlisted_methods_only() {
    let src = "<LimitExcept GET POST>\nRequire all denied\n</LimitExcept>\n";
    assert_eq!(decide(src, "/x", "GET"), AccessDecision::NoOpinion);
    assert_eq!(decide(src, "/x", "HEAD"), AccessDecision::NoOpinion);
    assert_eq!(decide(src, "/x", "PUT"), AccessDecision::Denied);
}

#[test]
fn limit_without_methods_is_malformed() {
    assert!(Htaccess::parse("<Limit>\nRequire all denied\n</Limit>\n").is_err());
}

#[test]
fn require_containers_combine_their_members() {
    let any = "<RequireAny>\nRequire ip 10.0.0.1\nRequire all granted\n</RequireAny>\n";
    assert_eq!(decide(any, "/x", "GET"), AccessDecision::Granted);
    let all = "<RequireAll>\nRequire all granted\nRequire all denied\n</RequireAll>\n";
    assert_eq!(decide(all, "/x", "GET"), AccessDecision::Denied);
    let none = "<RequireNone>\nRequire all denied\n</RequireNone>\n";
    assert_eq!(decide(none, "/x", "GET"), AccessDecision::Denied);
    let nested = "<Files a.php>\n<RequireAll>\nRequire all granted\n<RequireAny>\nRequire all denied\nRequire ip 10.0.0.1\n</RequireAny>\n</RequireAll>\n</Files>\n";
    assert_eq!(decide(nested, "/a.php", "GET"), AccessDecision::Denied);
    assert_eq!(decide(nested, "/b.php", "GET"), AccessDecision::NoOpinion);
}

#[test]
fn require_container_scoping_and_misuse() {
    // A grant inside a container no longer leaks past an enclosing Files deny.
    let src = "<Files secret.php>\nRequire all denied\n</Files>\n<RequireAny>\nRequire all granted\n</RequireAny>\n";
    assert_eq!(decide(src, "/secret.php", "GET"), AccessDecision::Denied);
    assert!(Htaccess::parse("<RequireAll>\n</RequireAll>\n").is_err());
    assert!(Htaccess::parse("<RequireAny>\nDeny from all\n</RequireAny>\n").is_err());
}

#[test]
fn files_section_overrides_a_later_directory_level_grant() {
    let src = "<Files secret.php>\nRequire all denied\n</Files>\nRequire all granted\n";
    assert_eq!(decide(src, "/secret.php", "GET"), AccessDecision::Denied);
    assert_eq!(decide(src, "/other.php", "GET"), AccessDecision::Granted);
}

#[test]
fn slash_delimited_if_regex_is_modelled() {
    let src = "<If \"%{REQUEST_URI} =~ /^\\/admin/\">\nRequire all denied\n</If>\n";
    assert_eq!(decide(src, "/admin/x", "GET"), AccessDecision::Denied);
    assert_eq!(decide(src, "/public", "GET"), AccessDecision::NoOpinion);
    let nocase = "<If \"%{REQUEST_URI} =~ m#^/ADMIN#i\">\nRequire all denied\n</If>\n";
    assert_eq!(decide(nocase, "/admin/x", "GET"), AccessDecision::Denied);
    let h =
        Htaccess::parse("<If \"%{REQUEST_URI} =~ /^\\/docs/\">\nHeader set X-Docs yes\n</If>\n")
            .unwrap();
    assert_eq!(h.response_headers("/docs/a", 200, &[]).len(), 1);
    assert!(h.response_headers("/other", 200, &[]).is_empty());
}

#[test]
fn bare_token_if_regex_is_unmodellable() {
    // Not an ap_expr regex literal: the deny still applies everywhere, a grant does not.
    let deny = "<If \"%{REQUEST_URI} =~ ^/admin\">\nRequire all denied\n</If>\n";
    assert_eq!(decide(deny, "/public", "GET"), AccessDecision::Denied);
    let grant = "<If \"%{REQUEST_URI} =~ ^/admin\">\nRequire all granted\n</If>\n";
    assert_eq!(decide(grant, "/admin", "GET"), AccessDecision::NoOpinion);
}

#[test]
fn leading_bom_does_not_hide_the_first_directive() {
    assert_eq!(
        decide("\u{FEFF}Require all denied\n", "/x", "GET"),
        AccessDecision::Denied
    );
    let h = Htaccess::parse("\u{FEFF}RewriteEngine On\nRewriteRule ^secret - [F]\n").unwrap();
    assert_eq!(h.rules.engine_state(), Some(true));
    let rs = hj_rewrite::RuleSet::parse("\u{FEFF}RewriteEngine On\n").unwrap();
    assert_eq!(rs.engine_state(), Some(true));
}

#[test]
fn malformed_sections_fail_the_parse() {
    assert!(
        Htaccess::parse(
            "<Files \"a.txt\">\nRequire all denied\n</FilesMatch>\nRequire all denied\n"
        )
        .is_err()
    );
    assert!(Htaccess::parse("<FilesMatch \"\\.php$\">\nRequire all denied\n").is_err());
    assert!(Htaccess::parse("</Files>\nRequire all denied\n").is_err());
}

#[test]
fn require_all_granted_tolerates_extra_whitespace() {
    assert_eq!(
        decide("Require all   granted\n", "/x", "GET"),
        AccessDecision::Granted
    );
    assert_eq!(
        decide("Require\tall\tgranted\n", "/x", "GET"),
        AccessDecision::Granted
    );
    assert_eq!(
        decide("Require all granted extra\n", "/x", "GET"),
        AccessDecision::Denied
    );
}

#[test]
fn files_grant_never_opens_a_directory_deny() {
    // The live forum shape: a `<Files auth.md>` grant earlier in the file must not
    // override the later recursive `<DirectoryMatch>` deny of sensitive trees.
    let src = "<FilesMatch \"\\.md$\">\nRequire all denied\n</FilesMatch>\n\
               <Files \"auth.md\">\nRequire all granted\n</Files>\n\
               <DirectoryMatch \"^.*/backups$\">\nRequire all denied\n</DirectoryMatch>\n";
    assert_eq!(decide(src, "/auth.md", "GET"), AccessDecision::Granted);
    assert_eq!(
        decide(src, "/backups/auth.md", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(decide(src, "/backups/x.md", "GET"), AccessDecision::Denied);
    assert_eq!(decide(src, "/x.md", "GET"), AccessDecision::Denied);
}

#[test]
fn grant_inside_an_unmodelled_container_does_not_widen() {
    for src in [
        "Require all denied\n<IfDefine FOO>\nRequire all granted\n</IfDefine>\n",
        "Require all denied\n<LocationMatch \"^/public/\">\nRequire all granted\n</LocationMatch>\n",
        "<Files *.php>\nRequire all denied\n</Files>\n<LocationMatch \"^/x\">\n<Files *.php>\nRequire all granted\n</Files>\n</LocationMatch>\n",
    ] {
        assert_eq!(
            decide(src, "/secret/x.php", "GET"),
            AccessDecision::Denied,
            "{src}"
        );
    }
}

#[test]
fn deny_inside_an_unmodelled_container_still_applies() {
    let src = "<IfDefine FOO>\nRequire all denied\n</IfDefine>\n";
    assert_eq!(decide(src, "/x", "GET"), AccessDecision::Denied);
}

#[test]
fn legacy_access_inside_an_unmodelled_container_fails_closed() {
    let src = "Order deny,allow\nDeny from all\n<IfDefine FOO>\nAllow from all\n</IfDefine>\n";
    assert!(Htaccess::parse(src).is_err());
}

#[test]
fn ifmodule_stays_transparent_for_grants() {
    let src = "Require all denied\n<IfModule mod_authz_core.c>\nRequire all granted\n</IfModule>\n";
    assert_eq!(decide(src, "/x", "GET"), AccessDecision::Granted);
}
