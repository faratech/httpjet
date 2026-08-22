//! `.htaccess` directive consumption (#1, #2, #7, #8b): merge `SetEnvIf` into
//! `ctx.env` before the rewrite, evaluate the access decision across the chain,
//! and fold the chain's `Header` directives into a finished response.

use std::path::Path;
use std::sync::Arc;

use hj_core::{ReqCtx, Request, Response};
use hj_rewrite::{AccessDecision, HeaderLookup, HeaderOp, Htaccess, ReqAttrs};

use super::rewrite_glue::ip_to_string;

/// Seed the server-provided env vars Apache/OLS set automatically and that
/// `.htaccess` directives depend on. Currently `HTTPS=on` for TLS requests —
/// `Header set ... env=HTTPS` guards (e.g. the HSTS header) and `%{ENV:HTTPS}`
/// conds rely on it (mod_ssl sets it). The `env=` guard is **presence-based**, so
/// `HTTPS` must be ABSENT on plaintext (setting it to "off" would make `env=HTTPS`
/// pass on HTTP too); set it only when the request is effectively HTTPS.
/// `ctx.is_tls` already reflects the XFF-aware effective scheme (so it is correct
/// behind a trusted proxy doing TLS termination / Cloudflare Flexible SSL).
pub(super) fn seed_server_env(ctx: &mut ReqCtx) {
    if ctx.is_tls {
        ctx.set_env("HTTPS", "on");
    }
}

/// (#8b) Evaluate the chain's `SetEnvIf`/`SetEnvIfNoCase` and merge the results
/// into `ctx.env` (later entries win) BEFORE the rewrite runs, so RewriteConds
/// (`%{ENV:NAME}`) and `Header ... env=` guards observe them.
/// Reserved env namespace shared by every config-driven env writer: names under
/// `HJ_` are request-identity plumbing (e.g. `HJ_REQUEST_PATH_QUERY` feeding the
/// redirect-decache transform, seeded by `set_redirect_guard_env` BEFORE config
/// evaluation runs) that a vhost/.htaccess rule must never be able to overwrite
/// — doing so would spoof what `deny_labeled_self_redirect` compares against.
pub(super) fn env_key_allowed(k: &str) -> bool {
    !k.starts_with("HJ_")
}

pub(super) fn apply_set_env(
    ctx: &mut ReqCtx,
    chain: &[Arc<Htaccess>],
    req: &Request,
    path: &str,
    query: &str,
) {
    if chain.is_empty() {
        return;
    }
    // Skip the per-request header materialization (+ ReqAttrs build) entirely when no dir in
    // the chain declares any SetEnvIf — the common case even when an .htaccess chain exists.
    // Only when at least one SetEnvIf is present do we pay to snapshot the request headers.
    if chain.iter().all(|ht| ht.set_env_if.is_empty()) {
        return;
    }
    // Lazy header source: SetEnvIf only reads the specific names its rules reference, so resolve
    // them on demand from `req.headers()` instead of cloning the WHOLE header set into a Vec per
    // request. Case-insensitive (HeaderMap::get_all); first decodable value wins (matching the old
    // find-first); `_`/`-` folding is applied by ReqAttrs::lookup_header before this is called.
    let header_lookup = |name: &str| -> Option<String> {
        req.headers()
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .next()
            .map(|s| s.to_string())
    };
    // `as_str()` already yields a borrow good for the rest of this fn (method borrows `req`,
    // protocol is `&'static`), so feed ReqAttrs the borrows directly — no per-request String.
    let method = req.method().as_str();
    let protocol = ctx.protocol.as_str();
    let remote_addr = ip_to_string(ctx.client_ip);
    let server_addr = ip_to_string(ctx.local_addr.ip());
    // IPv6-aware host (a naive `split(':')` mangles a bracketed `[::1]:443` to `[`);
    // matches the router / rewrite-host normalization so SetEnvIf/RewriteCond see the
    // same host the vhost was resolved by.
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(hj_core::host_without_port)
        .unwrap_or_else(|| ctx.vhost_name.to_string());

    let attrs = ReqAttrs {
        request_uri: path,
        method,
        protocol,
        query_string: query,
        remote_addr: &remote_addr,
        server_addr: &server_addr,
        host: &host,
        header_lookup: Some(HeaderLookup(&header_lookup)),
    };
    for ht in chain {
        for (k, v) in ht.eval_set_env(&attrs) {
            if !env_key_allowed(&k) {
                tracing::warn!(
                    request_id = %ctx.request_id,
                    key = %k,
                    "SetEnvIf targets the reserved HJ_ env prefix; ignored"
                );
                continue;
            }
            ctx.set_env(k, v);
        }
    }
}

/// (#1) Fail-safe access decision across the whole chain: any `denied` section
/// (in any `.htaccess`) that matches `rel_path` -> deny. `rel_path` must already
/// be normalized (see [`resolved_rel_path`](super::rewrite_glue::resolved_rel_path)).
pub(super) fn access_denied(chain: &[Arc<Htaccess>], rel_path: &str, method: &str) -> bool {
    chain
        .iter()
        .any(|ht| ht.access_decision(rel_path, method) == AccessDecision::Denied)
}

/// (M4) Resolve the docroot-relative request path to its absolute on-disk path
/// and test it against the [`AccessControl`](hj_acl::AccessControl) deny-dir
/// globs (`security.access_deny_dir` plus the built-in `.ht*` default). `true`
/// means the path must NOT be served (-> 403). `rel_path` must already be
/// normalized (see [`resolved_rel_path`](super::rewrite_glue::resolved_rel_path));
/// its leading `/` is stripped before joining so the result stays inside `docroot`.
pub(super) fn access_deny_dir(acl: &hj_acl::AccessControl, docroot: &Path, rel_path: &str) -> bool {
    let abs = docroot.join(rel_path.trim_start_matches('/'));
    acl.deny_dir_match(&abs)
}

/// (#2/#7) Apply the chain's `Header` directives to a finished response: set /
/// add / append / unset, honoring `always`/`onsuccess`, `env=` guards, and
/// FilesMatch/`<If>` scoping. `%{VAR}e` values resolve from `ctx.env`.
pub(super) fn apply_response_headers_for_request(
    ctx: &ReqCtx,
    chain: &[Arc<Htaccess>],
    rel_path: &str,
    request_path: &str,
    resp: &mut Response,
) {
    if chain.is_empty() {
        return;
    }
    let status = resp.status().as_u16();
    for ht in chain {
        // Skip only THIS chain entry when it carries no `Header` directives (a
        // subdirectory `.htaccess` with only rewrite/access rules) — avoids the
        // `response_headers` call + its `Vec` alloc. A later entry that DOES have
        // headers still runs (the loop continues).
        if !ht.has_resp_op {
            continue;
        }
        for op in ht.response_headers_for_request(rel_path, request_path, status, &ctx.env) {
            apply_header_op(resp, &op);
        }
    }
}

/// Fold one [`HeaderOp`] into a response's header map.
fn apply_header_op(resp: &mut Response, op: &HeaderOp) {
    use http::header::{HeaderName, HeaderValue};
    let name = match HeaderName::from_bytes(op.name().as_bytes()) {
        Ok(n) => n,
        Err(_) => return, // skip malformed header names rather than panic.
    };
    let headers = resp.headers_mut();
    match op {
        HeaderOp::Unset { .. } => {
            headers.remove(&name);
        }
        HeaderOp::Set { value, .. } => {
            if let Ok(v) = HeaderValue::from_str(value) {
                headers.remove(&name);
                headers.insert(&name, v);
            }
        }
        HeaderOp::Add { value, .. } => {
            if let Ok(v) = HeaderValue::from_str(value) {
                headers.append(&name, v);
            }
        }
        // Append: concatenate ", value" onto the existing (last) value, else Set.
        HeaderOp::Append { value, .. } | HeaderOp::Edit { value, .. } => {
            let existing = headers
                .get(&name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let merged = match existing {
                Some(prev) if !prev.is_empty() => format!("{prev}, {value}"),
                _ => value.clone(),
            };
            if let Ok(v) = HeaderValue::from_str(&merged) {
                headers.remove(&name);
                headers.insert(&name, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::rewrite_glue::resolved_rel_path;
    use super::*;

    #[test]
    fn set_env_if_cannot_overwrite_reserved_hj_env() {
        let ht = hj_rewrite::Htaccess::parse(
            "SetEnvIf Request_URI ^.*$ HJ_REQUEST_PATH_QUERY=/spoofed\n\
             SetEnvIf Request_URI ^.*$ PLAIN_OK=yes\n",
        )
        .unwrap();
        let chain = vec![Arc::new(ht)];
        let req = http::Request::builder()
            .uri("/x")
            .body(hj_core::empty_incoming())
            .unwrap();

        let server = Arc::new(hj_core::config::ServerConfig::default());
        let vhost = Arc::new(hj_core::config::VHostConfig::default());
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut ctx = ReqCtx {
            server,
            vhost_name: "test.example".into(),
            vhost,
            peer_ip: loopback,
            client_ip: loopback,
            is_tls: false,
            protocol: hj_core::Proto::Http1,
            trusted_proxy: false,
            env: Vec::new(),
            local_addr: "127.0.0.1:80".parse().unwrap(),
            peer_port: 40000,
            tls: None,
            request_time: std::time::SystemTime::UNIX_EPOCH,
            request_id: Default::default(),
            upstream_id: None,
        };
        ctx.set_env("HJ_REQUEST_PATH_QUERY", "/original");

        apply_set_env(&mut ctx, &chain, &req, "/x", "");

        assert_eq!(
            ctx.get_env("HJ_REQUEST_PATH_QUERY"),
            Some("/original"),
            "SetEnvIf must not overwrite the reserved request-identity env"
        );
        assert_eq!(
            ctx.get_env("PLAIN_OK"),
            Some("yes"),
            "non-reserved SetEnvIf vars still apply"
        );
    }

    #[test]
    fn dotdot_through_missing_dir_loads_protected_htaccess_and_denies() {
        // (M1 security) `/zz/../internal_data/config.php` with `zz` ABSENT must
        // load `internal_data/.htaccess` (which denies) and 403 — the `..` is
        // collapsed up front (mirroring `dispatch`) so the chain loader walks the
        // canonical directory list, not the raw `<docroot>/zz/../internal_data`
        // (which ENOENTs on the missing `zz` and skips the deny).
        use hj_rewrite::HtaccessCache;

        // Build a temp docroot with a protected subdir but NO `zz` directory.
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("httpjet_m1_{n}"));
        let protected = root.join("internal_data");
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::write(
            protected.join(".htaccess"),
            b"<Files \"*\">\nRequire all denied\n</Files>\n",
        )
        .unwrap();
        std::fs::write(protected.join("config.php"), b"<?php\n").unwrap();

        let cache = HtaccessCache::new();
        let decoded = "/zz/../internal_data/config.php";

        // --- The vulnerability (pre-fix): loading the chain with the RAW path
        // walks `<docroot>/zz/../internal_data`; `zz` is missing so the protected
        // `.htaccess` is never read -> the chain is empty -> NOT denied. ---------
        let raw_chain: Vec<_> = cache
            .load_chain_with_dirs(&root, decoded, ".htaccess")
            .into_iter()
            .map(|(_, h)| h)
            .collect();
        let raw_rel = resolved_rel_path(decoded); // access check already collapsed
        assert!(
            !access_denied(&raw_chain, &raw_rel, "GET"),
            "pre-fix: raw `..` path skips the protected .htaccess (the bypass)"
        );

        // --- The fix: canonicalize the path BEFORE loading the chain (exactly
        // what `dispatch` now does). The chain loads `internal_data/.htaccess`
        // and the access check denies -> 403. ----------------------------------
        let canonical = resolved_rel_path(decoded);
        assert_eq!(canonical, "/internal_data/config.php");
        let fixed_chain: Vec<_> = cache
            .load_chain_with_dirs(&root, &canonical, ".htaccess")
            .into_iter()
            .map(|(_, h)| h)
            .collect();
        assert!(
            !fixed_chain.is_empty(),
            "canonical path must load the protected internal_data/.htaccess"
        );
        let rel = resolved_rel_path(&canonical);
        assert!(
            access_denied(&fixed_chain, &rel, "GET"),
            "canonical path loads the deny and 403s (#M1 fixed)"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn access_deny_dir_blocks_ht_and_configured_paths() {
        // (M4) The pipeline helper maps a docroot-relative path to its on-disk
        // path and consults the ACL deny globs. `.htaccess` is denied by the
        // built-in default; an ordinary file is not.
        use hj_acl::AccessControl;
        use hj_core::config::Security;

        let docroot = Path::new("/web/public_html");
        let acl = AccessControl::from_security(&Security::default());
        assert!(access_deny_dir(&acl, docroot, "/.htaccess"));
        assert!(access_deny_dir(&acl, docroot, "/sub/.htpasswd"));
        assert!(!access_deny_dir(&acl, docroot, "/index.php"));
        assert!(!access_deny_dir(&acl, docroot, "/assets/app.js"));
    }

    #[test]
    fn seed_server_env_gates_hsts_on_tls_only() {
        // The live .htaccess: `Header set Strict-Transport-Security ... env=HTTPS`.
        // The env= guard is presence-based, so HSTS must appear on TLS (HTTPS seeded)
        // and NOT on plaintext (HTTPS absent). Regression for the origin-HSTS gap.
        use hj_rewrite::Htaccess;
        let ht = Arc::new(
            Htaccess::parse(
                "Header set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" env=HTTPS",
            )
            .unwrap(),
        );
        let chain = [ht];

        // TLS request: HTTPS seeded -> HSTS present.
        let mut ctx = super::super::tests::bare_ctx_for_headers();
        assert!(ctx.is_tls);
        seed_server_env(&mut ctx);
        assert_eq!(ctx.get_env("HTTPS"), Some("on"));
        let mut resp: Response = Response::new(hj_core::Body::Empty);
        apply_response_headers_for_request(&ctx, &chain, "/", "/", &mut resp);
        assert!(
            resp.headers().contains_key("strict-transport-security"),
            "HSTS must be emitted on a TLS request"
        );

        // Plaintext request: HTTPS absent -> no HSTS (env=HTTPS guard fails).
        let mut ctx2 = super::super::tests::bare_ctx_for_headers();
        ctx2.is_tls = false;
        seed_server_env(&mut ctx2);
        assert_eq!(ctx2.get_env("HTTPS"), None);
        let mut resp2: Response = Response::new(hj_core::Body::Empty);
        apply_response_headers_for_request(&ctx2, &chain, "/", "/", &mut resp2);
        assert!(
            !resp2.headers().contains_key("strict-transport-security"),
            "HSTS must NOT be emitted on a plaintext request"
        );
    }

    #[test]
    fn has_resp_op_skip_does_not_suppress_later_chain_entry() {
        // (Stage 3, Mandatory change 4) A chain entry with no Header directives
        // (has_resp_op=false) is skipped, but a LATER entry that DOES carry
        // headers must still apply — the `continue` skips only the current `ht`.
        use hj_rewrite::Htaccess;
        let no_headers = Arc::new(
            Htaccess::parse("RewriteEngine On\nRewriteRule ^(.*)$ index.php [L]").unwrap(),
        );
        assert!(!no_headers.has_resp_op);
        let with_headers = Arc::new(Htaccess::parse("Header always set X-Sec nosniff").unwrap());
        assert!(with_headers.has_resp_op);

        let chain = vec![no_headers, with_headers];
        let ctx = super::super::tests::bare_ctx_for_headers();
        let mut resp: Response = Response::new(hj_core::Body::Empty);
        apply_response_headers_for_request(&ctx, &chain, "/index.php", "/index.php", &mut resp);
        assert_eq!(
            resp.headers().get("x-sec").map(|v| v.to_str().unwrap()),
            Some("nosniff"),
            "the second chain entry's header must apply despite the first being skipped"
        );
    }

    #[test]
    fn header_op_set_add_append_unset_fold() {
        use http::header::HeaderName;
        let mut resp: Response = Response::new(hj_core::Body::Empty);
        resp.headers_mut().insert(
            HeaderName::from_static("vary"),
            http::HeaderValue::from_static("Accept"),
        );

        // Append concatenates onto the existing value.
        apply_header_op(
            &mut resp,
            &HeaderOp::Append {
                name: "Vary".into(),
                value: "Accept-Encoding".into(),
            },
        );
        assert_eq!(
            resp.headers().get("vary").unwrap(),
            "Accept, Accept-Encoding"
        );

        // Set replaces.
        apply_header_op(
            &mut resp,
            &HeaderOp::Set {
                name: "X-Cache".into(),
                value: "HIT".into(),
            },
        );
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");

        // Add appends a new line (multi-valued).
        apply_header_op(
            &mut resp,
            &HeaderOp::Add {
                name: "Set-Cookie".into(),
                value: "a=1".into(),
            },
        );
        apply_header_op(
            &mut resp,
            &HeaderOp::Add {
                name: "Set-Cookie".into(),
                value: "b=2".into(),
            },
        );
        assert_eq!(resp.headers().get_all("set-cookie").iter().count(), 2);

        // Unset removes.
        apply_header_op(
            &mut resp,
            &HeaderOp::Unset {
                name: "X-Cache".into(),
            },
        );
        assert!(!resp.headers().contains_key("x-cache"));
    }
}
