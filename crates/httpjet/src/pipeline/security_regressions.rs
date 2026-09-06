use super::*;
use std::sync::atomic::Ordering;

fn asset_request(path: &str, authorized: bool) -> Request {
    let mut req = get(CANON_HOST, path, None);
    if authorized {
        req.headers_mut().insert(
            header::AUTHORIZATION,
            "Basic dXNlcjpwYXNzd29yZA==".parse().unwrap(),
        );
    }
    req
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_static_expiry_is_private_through_full_handle() {
    let root = temp_root("auth_expiry");
    std::fs::create_dir(root.join("protected")).unwrap();
    std::fs::write(
        root.join("protected/.htaccess"),
        "AuthType Basic\nAuthUserFile htpasswd\nRequire valid-user\n",
    )
    .unwrap();
    std::fs::write(
        root.join("htpasswd"),
        "user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
    )
    .unwrap();
    std::fs::write(root.join("protected/asset.png"), b"protected image bytes").unwrap();
    std::fs::write(root.join("public.png"), b"public image bytes").unwrap();
    let state = build_state_inner(root.clone(), vec![], vec![], true, None, None, |cfg| {
        cfg.expires.enabled = true;
        cfg.expires.by_type = vec![("image/*".into(), "A604800".into())];
        cfg.mime.by_suffix.insert("png".into(), "image/png".into());
    });

    for (method, range, expected) in [
        ("GET", false, 200),
        ("HEAD", false, 200),
        ("GET", true, 206),
    ] {
        let mut req = asset_request("/protected/asset.png", true);
        *req.method_mut() = method.parse().unwrap();
        if range {
            req.headers_mut()
                .insert(header::RANGE, "bytes=0-2".parse().unwrap());
        }
        assert!(fast_serve_req(&state, &req).await.is_none());
        let resp = run(&state, req).await;
        assert_eq!(resp.status(), expected);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "private, no-store");
        assert!(!resp.headers().contains_key(header::EXPIRES));
        // A shared cache respecting the response policy has nothing to reuse.
        assert!(
            !resp.headers()[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .split(',')
                .any(|d| d.trim() == "public")
        );
        let anonymous = run(&state, asset_request("/protected/asset.png", false)).await;
        assert_eq!(anonymous.status(), 401);
    }
    for authorized in [false, true] {
        let req = asset_request("/public.png", authorized);
        let fast = fast_serve_req(&state, &req).await.unwrap();
        let full = run(&state, req).await;
        let expected = if authorized {
            "private, no-store"
        } else {
            "public, max-age=604800"
        };
        assert_eq!(fast.headers()[header::CACHE_CONTROL], expected);
        assert_eq!(full.headers()[header::CACHE_CONTROL], expected);
        assert_eq!(body_bytes(fast.into_body()), body_bytes(full.into_body()));
    }
}

#[tokio::test]
async fn inline_memo_keeps_every_header_dependency_after_user_agent() {
    for classify in [false, true] {
        for ua_first in [false, true] {
            let root = temp_root("inline_memo_dependencies");
            std::fs::write(root.join("asset.txt"), b"public asset").unwrap();
            let ua = "RewriteCond %{HTTP_USER_AGENT} ^Allowed\nRewriteRule ^ - [E=UA_OK:1]\n";
            let others = "RewriteCond %{HTTP:Origin} !^https://good\\.test$\nRewriteRule ^ - [F]\nRewriteCond %{HTTP:Accept} !^text/plain$\nRewriteRule ^ - [F]\n";
            let rules = if ua_first {
                format!("RewriteEngine On\n{ua}{others}")
            } else {
                format!("RewriteEngine On\n{others}{ua}")
            };
            let mut state = build_state_htaccess(root);
            let s = Arc::get_mut(&mut state).unwrap();
            s.rewrite_ua_classify = classify;
            s.inline_rules.insert(
                VHOST.into(),
                Arc::new(hj_rewrite::RuleSet::parse(&rules).unwrap()),
            );
            let req = |origin: Option<&str>, accept: Option<&str>| {
                let mut req = get_with_ua("/asset.txt", "Allowed");
                if let Some(origin) = origin {
                    req.headers_mut()
                        .insert(header::ORIGIN, origin.parse().unwrap());
                }
                if let Some(accept) = accept {
                    req.headers_mut()
                        .insert(header::ACCEPT, accept.parse().unwrap());
                }
                req
            };
            let good = || req(Some("https://good.test"), Some("text/plain"));
            let warm = fast_serve_req(&state, &good()).await.unwrap();
            assert_eq!(warm.status(), 200);
            let hits = state.metrics.fast_memo_hits.load(Ordering::Relaxed);
            let replay = fast_serve_req(&state, &good()).await.unwrap();
            assert_eq!(
                state.metrics.fast_memo_hits.load(Ordering::Relaxed),
                hits + 1
            );
            assert_eq!(warm.headers(), replay.headers());
            assert_eq!(body_bytes(warm.into_body()), body_bytes(replay.into_body()));
            for (origin, accept) in [
                (Some("https://bad.test"), Some("text/plain")),
                (Some("https://good.test"), Some("text/html")),
                (None, Some("text/plain")),
                (Some("https://good.test"), None),
            ] {
                let request = req(origin, accept);
                assert!(
                    fast_serve_req(&state, &request).await.is_none(),
                    "must miss: classify={classify} ua_first={ua_first} origin={origin:?} accept={accept:?}"
                );
                assert_eq!(run(&state, request).await.status(), 403);
            }
        }
    }
}
