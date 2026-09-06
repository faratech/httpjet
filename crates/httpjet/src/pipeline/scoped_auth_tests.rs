use super::*;

const ADMIN: &str = "Basic QWRtaW46cGFzc3dvcmQ=";
const VISITOR: &str = "Basic VmlzaXRvcjpwYXNzd29yZA==";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filesystem_absolute_directory_patterns_protect_direct_and_aliased_resources() {
    for tag in ["Directory", "DirectoryMatch"] {
        let root = fixture("auth_absolute_directory", "");
        std::fs::create_dir(root.join("private")).unwrap();
        std::fs::create_dir(root.join("privateish")).unwrap();
        std::fs::write(root.join("private/x.txt"), b"protected").unwrap();
        std::fs::write(root.join("privateish/x.txt"), b"public").unwrap();
        std::os::unix::fs::symlink(root.join("private/x.txt"), root.join("alias.txt")).unwrap();
        let directory = root.join("private");
        let pattern = if tag == "Directory" {
            directory.to_string_lossy().into_owned()
        } else {
            format!("^{}(?:/|$)", directory.display())
        };
        std::fs::write(root.join(".htaccess"), format!(
            "AuthType Basic\nAuthUserFile users\n<{tag} \"{pattern}\">\nRequire user Admin\n</{tag}>\n"
        )).unwrap();
        let state = build_state_htaccess(root);
        for path in ["/private/x.txt", "/alias.txt"] {
            assert_eq!(status(&state, path, None).await, 401, "{tag}: {path}");
            assert_eq!(status(&state, path, Some(VISITOR)).await, 401);
            assert_eq!(status(&state, path, Some(ADMIN)).await, 200);
            assert!(fast_serve_req(&state, &request(path, None)).await.is_none());
        }
        assert_eq!(status(&state, "/privateish/x.txt", None).await, 200);
    }
}

fn fixture(tag: &str, config: &str) -> PathBuf {
    let root = temp_root(tag);
    std::fs::write(root.join(".htaccess"), config).unwrap();
    std::fs::write(root.join("users"), "Admin:password\nVisitor:password\n").unwrap();
    root
}

fn request(path: &str, credentials: Option<&str>) -> Request {
    let mut req = get(CANON_HOST, path, None);
    if let Some(value) = credentials {
        req.headers_mut()
            .insert(header::AUTHORIZATION, value.parse().unwrap());
    }
    req
}

async fn status(state: &Arc<ServerState>, path: &str, credentials: Option<&str>) -> u16 {
    run(state, request(path, credentials))
        .await
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sibling_valid_user_never_authorizes_the_admin_file() {
    let root = fixture(
        "auth_siblings",
        r#"
AuthType Basic
AuthUserFile users
<Files public.txt>
 Require valid-user
</Files>
<Files admin.txt>
 Require user Admin
</Files>
"#,
    );
    for path in ["public.txt", "admin.txt", "open.txt"] {
        std::fs::write(root.join(path), path).unwrap();
    }
    let state = build_state_htaccess(root);
    assert_eq!(status(&state, "/open.txt", None).await, 200);
    assert_eq!(status(&state, "/public.txt", Some(VISITOR)).await, 200);
    assert_eq!(status(&state, "/admin.txt", Some(VISITOR)).await, 401);
    assert_eq!(status(&state, "/%61dmin.txt", Some(VISITOR)).await, 401);
    assert_eq!(status(&state, "/admin.txt", Some(ADMIN)).await, 200);
    assert_eq!(status(&state, "/admin.txt", None).await, 401);
    assert!(
        fast_serve_req(&state, &request("/admin.txt", None))
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn child_require_inherits_metadata_but_replaces_parent_valid_user() {
    let root = fixture(
        "auth_inherited",
        "AuthType Basic\nAuthName Parent\nAuthUserFile users\nRequire valid-user",
    );
    std::fs::create_dir(root.join("child")).unwrap();
    std::fs::write(
        root.join("child/.htaccess"),
        "AuthName Child\nRequire user Admin",
    )
    .unwrap();
    std::fs::write(root.join("child/x.txt"), b"private").unwrap();
    std::fs::write(root.join("parent.txt"), b"parent").unwrap();
    let state = build_state_htaccess(root);
    assert_eq!(status(&state, "/parent.txt", Some(VISITOR)).await, 200);
    let rejected = run(&state, request("/child/x.txt", Some(VISITOR))).await;
    assert_eq!(rejected.status(), 401);
    assert_eq!(
        rejected.headers()[header::WWW_AUTHENTICATE],
        "Basic realm=\"Child\""
    );
    assert_eq!(status(&state, "/child/x.txt", Some(ADMIN)).await, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_only_matching_sibling_does_not_clear_auth() {
    let root = fixture(
        "auth_metadata_sibling",
        "AuthType Basic\nAuthUserFile users\n<Files secret.txt>\nRequire user Admin\n</Files>\n<Files secret.txt>\nAuthName Second\n</Files>",
    );
    std::fs::write(root.join("secret.txt"), b"secret").unwrap();
    let state = build_state_htaccess(root);
    assert_eq!(status(&state, "/secret.txt", None).await, 401);
    assert_eq!(status(&state, "/secret.txt", Some(VISITOR)).await, 401);
    assert_eq!(status(&state, "/secret.txt", Some(ADMIN)).await, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_scopes_and_invalid_auth_are_enforced_through_pipeline() {
    let root = fixture(
        "auth_nested",
        r##"
AuthType Basic
AuthUserFile users
<Directory "/private">
 <If "%{REQUEST_URI} !~ m#^/private/open/#">
  <FilesMatch "\.txt$">
   Require user Admin
  </FilesMatch>
 </If>
</Directory>
"##,
    );
    std::fs::create_dir_all(root.join("private/open")).unwrap();
    std::fs::create_dir(root.join("privateish")).unwrap();
    for path in ["private/x.txt", "private/open/x.txt", "privateish/x.txt"] {
        std::fs::write(root.join(path), b"text").unwrap();
    }
    let state = build_state_htaccess(root);
    assert_eq!(status(&state, "/private/x.txt", Some(VISITOR)).await, 401);
    assert_eq!(status(&state, "/private/open/x.txt", None).await, 200);
    assert_eq!(status(&state, "/privateish/x.txt", None).await, 200);

    for config in [
        "# AuthType Basic\nAuthUserFile users\nRequire valid-user",
        "AuthType Digest\nAuthUserFile users\nRequire valid-user",
        "AuthType Basic\nAuthUserFile users\n<RequireAny>\nRequire valid-user\n</RequireAny>",
        "AuthType Basic\nAuthUserFile users\n<Files x.txt>\nRequire valid-user",
        "AuthType Basic\nAuthUserFile \"users\nRequire valid-user",
    ] {
        let root = fixture("auth_invalid", config);
        std::fs::write(root.join("x.txt"), b"must not serve").unwrap();
        let state = build_state_htaccess(root);
        assert_eq!(status(&state, "/x.txt", Some(ADMIN)).await, 403, "{config}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewriting_out_of_or_into_a_protected_resource_keeps_both_checks() {
    let root = fixture(
        "auth_rewrites",
        "RewriteEngine On\nRewriteRule ^entry.txt$ private/target.txt [L]\n",
    );
    std::fs::create_dir(root.join("private")).unwrap();
    std::fs::write(root.join("private/.htaccess"), "AuthType Basic\nAuthUserFile users\nRequire user Admin\nRewriteEngine On\nRewriteRule ^source.txt$ /public.txt [L]\n").unwrap();
    std::fs::write(root.join("private/target.txt"), b"private").unwrap();
    std::fs::write(root.join("public.txt"), b"public").unwrap();
    let state = build_state_htaccess(root);
    for path in ["/entry.txt", "/private/source.txt"] {
        assert_eq!(status(&state, path, None).await, 401, "{path}");
        assert_eq!(status(&state, path, Some(VISITOR)).await, 401, "{path}");
        assert_eq!(status(&state, path, Some(ADMIN)).await, 200, "{path}");
    }
    assert_eq!(status(&state, "/public.txt", None).await, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_path_info_and_both_directory_indexes_require_the_mapped_files_user() {
    let root = fixture(
        "auth_mapped_files",
        r#"
AuthType Basic
AuthUserFile users
<FilesMatch "^(script\.php|index\.php|index\.html)$">
 Require user Admin
</FilesMatch>
"#,
    );
    std::fs::create_dir(root.join("html")).unwrap();
    std::fs::create_dir(root.join("php")).unwrap();
    std::fs::write(root.join("html/index.html"), b"html index").unwrap();
    std::fs::write(root.join("php/index.php"), b"<?php echo 'private';").unwrap();
    std::fs::write(root.join("php/.htaccess"), "DirectoryIndex index.php").unwrap();
    std::fs::write(root.join("script.php"), b"<?php echo 'private';").unwrap();
    let state = build_state_htaccess(root);
    for path in ["/script.php/tail", "/script.php%2Ftail", "/php/", "/html/"] {
        assert_eq!(status(&state, path, None).await, 401, "{path}");
        assert_eq!(status(&state, path, Some(VISITOR)).await, 401, "{path}");
        assert_eq!(
            status(&state, path, Some(ADMIN)).await,
            if path == "/html/" { 200 } else { 503 },
            "{path}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_info_rewrite_cannot_discard_the_original_scripts_file_scope() {
    let root = fixture(
        "auth_original_script",
        "AuthType Basic\nAuthUserFile users\n<Files script.php>\nRequire user Admin\n</Files>\nRewriteEngine On\nRewriteRule ^script.php/.*$ public.txt [L]",
    );
    std::fs::write(root.join("script.php"), b"<?php echo 'private';").unwrap();
    std::fs::write(root.join("public.txt"), b"public").unwrap();
    let state = build_state_htaccess(root);
    assert_eq!(status(&state, "/script.php/tail", None).await, 401);
    assert_eq!(status(&state, "/script.php/tail", Some(VISITOR)).await, 401);
    assert_eq!(status(&state, "/script.php/tail", Some(ADMIN)).await, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn if_uri_and_files_scope_use_original_uri_and_resolved_filename() {
    let root = fixture(
        "auth_if_index",
        r##"
AuthType Basic
AuthUserFile users
<If "%{REQUEST_URI} =~ m#^/html/$#">
 <Files index.html>
  Require user Admin
 </Files>
</If>
<If "%{REQUEST_URI} =~ m#^/script\.php/#">
 <Files script.php>
  Require user Admin
 </Files>
</If>
"##,
    );
    std::fs::create_dir(root.join("html")).unwrap();
    std::fs::write(root.join("html/index.html"), b"index").unwrap();
    std::fs::write(root.join("script.php"), b"<?php echo 'private';").unwrap();
    let state = build_state_htaccess(root);
    for path in ["/html/", "/script.php/tail"] {
        assert_eq!(status(&state, path, None).await, 401);
        assert_eq!(status(&state, path, Some(VISITOR)).await, 401);
        assert_eq!(
            status(&state, path, Some(ADMIN)).await,
            if path == "/html/" { 200 } else { 503 }
        );
    }
    assert_eq!(
        status(&state, "/html/index.html", None).await,
        200,
        "If URI false control"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_symlink_into_protected_directory_checks_auth_before_cached_body() {
    let root = fixture("auth_alias", "");
    std::fs::create_dir(root.join("private")).unwrap();
    std::fs::write(
        root.join("private/.htaccess"),
        "AuthType Basic\nAuthUserFile users\nRequire user Admin",
    )
    .unwrap();
    std::fs::write(root.join("private/secret.txt"), b"secret body").unwrap();
    std::os::unix::fs::symlink(root.join("private/secret.txt"), root.join("alias.txt")).unwrap();
    let store = Arc::new(hj_pagecache::PageStore::new(hj_pagecache::StoreConfig {
        max_mem_bytes: 8 * 1024 * 1024,
        standard_cc_vhosts: vec![VHOST.into()],
        ..Default::default()
    }));
    let state = build_state_full(root, vec![], vec![], Some(store.clone()), None);
    seed_public_entry(&state, &store, "/alias.txt", b"stale cached secret").await;
    assert_eq!(
        store.stats().entries,
        1,
        "the bypass test must contain a real cache entry"
    );
    assert!(
        fast_serve_req(&state, &request("/alias.txt", None))
            .await
            .is_none()
    );
    assert_eq!(status(&state, "/alias.txt", None).await, 401);
    assert_eq!(status(&state, "/alias.txt", Some(VISITOR)).await, 401);
    let allowed = run(&state, request("/alias.txt", Some(ADMIN))).await;
    assert_eq!(allowed.status(), 200);
    assert!(is_cache_hit(Some(&allowed)));
    assert_eq!(
        body_bytes(allowed.into_body()),
        b"stale cached secret".as_slice()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_context_location_resolves_its_own_auth_chain() {
    let root = fixture("auth_context", "");
    std::fs::create_dir_all(root.join("private/assets")).unwrap();
    std::fs::write(
        root.join("private/.htaccess"),
        "AuthType Basic\nAuthUserFile users\nRequire user Admin",
    )
    .unwrap();
    std::fs::write(root.join("private/assets/secret.txt"), b"secret").unwrap();
    let context = Context {
        cache_policy: None,
        bandwidth_limit: 0,
        max_body_override: None,
        timeout_override: None,
        sub_filter: None,
        kind: ContextKind::Static,
        uri: "/assets".into(),
        location: Some(root.join("private")),
        handler: None,
        enabled: true,
        extra_headers: vec![],
        add_default_charset: false,
        charset: None,
    };
    let state = build_state_inner(root, vec![context], vec![], true, None, None, |_| {});
    assert!(
        fast_serve_req(&state, &request("/assets/secret.txt", None))
            .await
            .is_none()
    );
    assert_eq!(status(&state, "/assets/secret.txt", None).await, 401);
    assert_eq!(
        status(&state, "/assets/secret.txt", Some(VISITOR)).await,
        401
    );
    assert_eq!(status(&state, "/assets/secret.txt", Some(ADMIN)).await, 200);
}
