use hj_rewrite::{Htaccess, resolve_auth};

#[test]
fn sibling_require_groups_never_union_and_case_is_preserved() {
    let ht = Htaccess::parse(
        r#"
AuthType Basic
AuthName "Shared metadata"
AuthUserFile users
<Files "public.txt">
 Require valid-user
</Files>
<Files "admin.txt">
 Require user Admin
</Files>
"#,
    )
    .unwrap();
    assert!(resolve_auth([&ht], "/open.txt").unwrap().is_none());
    let public = resolve_auth([&ht], "/public.txt").unwrap().unwrap();
    assert!(public.user_satisfies("visitor"));
    let admin = resolve_auth([&ht], "/admin.txt").unwrap().unwrap();
    assert!(admin.user_satisfies("Admin"));
    assert!(!admin.user_satisfies("admin"));
    assert!(!admin.user_satisfies("visitor"));
}

#[test]
fn parent_child_metadata_inheritance_and_explicit_require_override() {
    let parent =
        Htaccess::parse("AuthType Basic\nAuthName Parent\nAuthUserFile users\nRequire valid-user")
            .unwrap();
    let child = Htaccess::parse(
        "<Files secret.txt>\nRequire user Alice\nRequire user Bob\n</Files>\nAuthName Child",
    )
    .unwrap();
    let realm = resolve_auth([&parent, &child], "/sub/secret.txt")
        .unwrap()
        .unwrap();
    assert_eq!(realm.realm, "Child");
    assert_eq!(realm.user_file, std::path::PathBuf::from("users"));
    assert!(realm.user_satisfies("Alice"));
    assert!(realm.user_satisfies("Bob"));
    assert!(!realm.user_satisfies("visitor"));
    assert!(
        resolve_auth([&parent, &child], "/sub/open.txt")
            .unwrap()
            .unwrap()
            .user_satisfies("visitor")
    );
    assert!(resolve_auth([&child], "/sub/secret.txt").is_err());
    let public_child = Htaccess::parse("Require all granted").unwrap();
    assert!(
        resolve_auth([&parent, &public_child], "/sub/open.txt")
            .unwrap()
            .is_none()
    );
}

#[test]
fn matching_siblings_replace_require_and_inherit_metadata_in_config_order() {
    let ht = Htaccess::parse(
        r#"
<FilesMatch "\.txt$">
 AuthType Basic
 AuthUserFile users
 Require valid-user
</FilesMatch>
<Files secret.txt>
 Require user Admin
</Files>
"#,
    )
    .unwrap();
    let secret = resolve_auth([&ht], "/secret.txt").unwrap().unwrap();
    assert!(secret.user_satisfies("Admin"));
    assert!(!secret.user_satisfies("visitor"));
    assert!(
        resolve_auth([&ht], "/open.txt")
            .unwrap()
            .unwrap()
            .user_satisfies("visitor")
    );
}

#[test]
fn metadata_only_matching_sibling_cannot_clear_a_requirement() {
    let ht = Htaccess::parse(
        r#"
AuthType Basic
AuthUserFile users
<Files secret.txt>
 Require user Admin
</Files>
<Files secret.txt>
 AuthName Second
</Files>
"#,
    )
    .unwrap();
    let realm = resolve_auth([&ht], "/secret.txt").unwrap().unwrap();
    assert_eq!(realm.realm, "Second");
    assert!(realm.user_satisfies("Admin"));
    assert!(!realm.user_satisfies("Visitor"));
}

#[test]
fn directory_files_and_if_scopes_are_conjunctive() {
    let ht = Htaccess::parse(
        r##"
AuthType Basic
AuthUserFile users
<DirectoryMatch "^/private(?:/|$)">
 <If "%{REQUEST_URI} !~ m#^/private/open/#">
  <FilesMatch "\.txt$">
   Require user Admin
  </FilesMatch>
 </If>
</DirectoryMatch>
"##,
    )
    .unwrap();
    assert!(resolve_auth([&ht], "/private/x.txt").unwrap().is_some());
    for path in ["/private/open/x.txt", "/public/x.txt", "/private/x.png"] {
        assert!(resolve_auth([&ht], path).unwrap().is_none(), "{path}");
    }
}

#[test]
fn incomplete_unsupported_and_malformed_auth_fail_closed() {
    for config in [
        "# AuthType Basic\nAuthUserFile users\nRequire valid-user",
        "AuthType Digest\nAuthUserFile users\nRequire valid-user",
        "AuthType Basic\nAuthUserFile users\nRequire user",
        "AuthType Basic\nAuthUserFile users\nAuthBasicProvider ldap\nRequire valid-user",
        "AuthType Basic\nAuthUserFile users\nAuthMerging And\nRequire valid-user",
        "AuthType Basic\nAuthUserFile \"users\nRequire valid-user",
        "AuthType Basic\nAuthUserFile users\n<RequireAny>\nRequire valid-user\n</RequireAny>",
        "AuthType Basic\nAuthUserFile users\n<If \"%{HTTP_HOST} == 'x'\">\nRequire valid-user\n</If>",
        "AuthType Basic\nAuthUserFile users\n<FilesMatch \"[\">\nRequire valid-user\n</FilesMatch>",
    ] {
        let ht = Htaccess::parse(config).unwrap();
        assert!(resolve_auth([&ht], "/x.txt").is_err(), "{config}");
    }
    for config in [
        "AuthType Basic\n<Files x.txt>\nRequire valid-user",
        "AuthType Basic\n<Files x.txt>\nRequire valid-user\n</If>",
        "AuthType Basic\n<Files x.txt\nRequire valid-user\n</Files>",
    ] {
        assert!(Htaccess::parse(config).is_err(), "{config}");
    }
}

#[test]
fn directive_case_whitespace_and_transparent_ifmodule_are_supported() {
    let ht = Htaccess::parse("<IfModule mod_auth_basic.c>\n\tReQuIrE\tuser\tAlice Bob\nAuThTyPe\tBaSiC\nAuthUserFile\tusers\n</IfModule>").unwrap();
    let realm = resolve_auth([&ht], "/x").unwrap().unwrap();
    assert!(realm.user_satisfies("Alice"));
    assert!(!realm.user_satisfies("alice"));
    assert!(ht.auth_warnings().is_empty());
}

#[test]
fn single_quoted_auth_values_and_file_scopes_keep_their_meaning() {
    let ht = Htaccess::parse("AuthType 'Basic'\nAuthName 'Private area'\nAuthUserFile 'users'\n<Files 'private.txt'>\nRequire user 'Admin'\n</Files>").unwrap();
    let realm = resolve_auth([&ht], "/private.txt").unwrap().unwrap();
    assert_eq!(realm.realm, "Private area");
    assert!(realm.user_satisfies("Admin"));
    assert!(resolve_auth([&ht], "/public.txt").unwrap().is_none());
}
