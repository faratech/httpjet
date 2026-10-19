//! Regression (#883): a private-tier fill must leave with the same shared-cache
//! lockout as its hits, not the app's public Cache-Control / CDN directives.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn member_get(path: &str) -> Request {
    http::Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, CANON_HOST)
        .header("cookie", "xf_session=abc; xf_user=1")
        .body(hj_core::empty_incoming())
        .unwrap()
}

async fn upstream_private(listener: tokio::net::TcpListener) {
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut head = Vec::new();
            let mut buf = [0_u8; 4096];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                head.extend_from_slice(&buf[..n]);
            }
            let body = "<html>".to_string() + &"member page ".repeat(300) + "</html>";
            let reply = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html; charset=utf-8\r\n\
                 Cache-Control: public, max-age=600\r\n\
                 Cloudflare-CDN-Cache-Control: max-age=600\r\n\
                 Vary: Accept-Encoding\r\n\
                 Content-Length: {}\r\n\
                 X-LiteSpeed-Cache-Control: private,max-age=60\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_miss_and_hit_share_shared_cache_lockout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let up = tokio::spawn(upstream_private(listener));
    let root = temp_root("private-miss-egress");
    std::fs::write(
        root.join(".htaccess"),
        format!(
            "CacheLookup public on\nRewriteEngine On\nRewriteRule ^/?(m.*)$ http://{address}/$1 [P,L]\nHeader set X-LiteSpeed-Cache-Control private,max-age=60\n"
        ),
    )
    .unwrap();
    let cfg = hj_pagecache::StoreConfig {
        private_enabled: true,
        private_session_cookie: "xf_session".into(),
        private_user_cookie: "xf_user".into(),
        ..Default::default()
    };
    let store = Arc::new(hj_pagecache::PageStore::new(cfg));
    let state = build_state_inner(
        root,
        Vec::new(),
        Vec::new(),
        true,
        Some(store.clone()),
        None,
        |s| {
            register_upstream(s, address);
            for decl in s.vhosts.values_mut() {
                if let Some(c) = decl.config.as_mut() {
                    let mut v = (**c).clone();
                    v.cache_policy = Some(hj_core::config::VhostCachePolicy {
                        enable_cache: true,
                        enable_public: true,
                        enable_private: true,
                    });
                    *c = Arc::new(v);
                }
            }
        },
    );
    for label in ["miss", "hit,private"] {
        let r = run(&state, member_get("/m1")).await;
        let h = r.headers();
        assert_eq!(h.get("x-litespeed-cache").unwrap(), label);
        assert_eq!(
            h.get("cache-control").unwrap(),
            "private, no-store",
            "{label}"
        );
        assert!(h.get("cloudflare-cdn-cache-control").is_none(), "{label}");
    }
    up.abort();
}
