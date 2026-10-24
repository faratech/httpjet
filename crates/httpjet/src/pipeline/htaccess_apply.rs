//! `.htaccess` directive consumption (#1, #2, #7, #8b): merge `SetEnvIf` into
//! `ctx.env` before the rewrite, evaluate the access decision across the chain,
//! and fold the chain's `Header` directives into a finished response.

use std::path::Path;
use std::sync::Arc;

use hj_core::{ReqCtx, Request, Response};
use hj_rewrite::{AccessDecision, EnvAssignment, HeaderLookup, HeaderOpKind, Htaccess, ReqAttrs};

use super::rewrite_glue::{ip_to_string, resolved_rel_path};

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
/// `HJ_` are internal pipeline plumbing (e.g. `HJ_CACHE_REFRESH`) that a
/// vhost/.htaccess rule must never be able to overwrite. (The redirect-decache
/// request identity moved off env onto the dedicated `ReqCtx.redirect_guard`
/// field (#318), out of config reach by construction; the prefix stays reserved
/// for the remaining and any future internal keys.)
pub(super) fn env_key_allowed(k: &str) -> bool {
    !k.starts_with("HJ_")
}

/// Merge one `SetEnvIf` / rewrite `[E=]` assignment into `ctx.env`. A `!VAR`
/// key UNSETS `VAR` (#780). Both forms honor the reserved `HJ_` namespace, so
/// config can neither overwrite nor remove internal plumbing.
pub(super) fn apply_env_assignment(
    ctx: &mut ReqCtx,
    key: String,
    value: String,
    source: &'static str,
) {
    let assignment = EnvAssignment::classify(&key, &value);
    let name = assignment.name();
    if !env_key_allowed(name) {
        tracing::warn!(
            request_id = %ctx.request_id,
            key = %name,
            source,
            "env assignment targets the reserved HJ_ env prefix; ignored"
        );
        return;
    }
    match assignment {
        EnvAssignment::Unset { name } => {
            if !name.is_empty() {
                ctx.unset_env(name);
            }
        }
        EnvAssignment::Set { .. } => ctx.set_env(key, value),
    }
}

#[cfg(test)]
pub(super) fn apply_set_env(
    ctx: &mut ReqCtx,
    chain: &[Arc<Htaccess>],
    req: &Request,
    path: &str,
    query: &str,
) -> Result<(), &'static str> {
    apply_set_env_scoped(ctx, chain, req, path, query, None)
}

/// [`apply_set_env`] with the basename `<Files*>`-scoped `SetEnv`/`SetEnvIf`
/// match: the file `path` maps to (its `DirectoryIndex` file or script), see
/// [`set_env_scope_basename`](super::set_env_scope_basename).
pub(super) fn apply_set_env_scoped(
    ctx: &mut ReqCtx,
    chain: &[Arc<Htaccess>],
    req: &Request,
    path: &str,
    query: &str,
    scope_basename: Option<&str>,
) -> Result<(), &'static str> {
    apply_set_env_iter_with_headers(
        ctx,
        chain.iter().map(AsRef::as_ref),
        req.method().as_str(),
        req.headers(),
        path,
        query,
        scope_basename,
    )
}

/// Merge the chain's `SetEnv`/`UnsetEnv` (mod_env) and then its `SetEnvIf`
/// output into `ctx.env`, so `SetEnvIf` env-attribute tests, the rewrite's
/// `%{ENV:}`, `Header env=` and the backend env all observe both.
pub(super) fn apply_set_env_iter_with_headers<'a, I>(
    ctx: &mut ReqCtx,
    chain: I,
    method: &str,
    headers: &http::HeaderMap,
    path: &str,
    query: &str,
    scope_basename: Option<&str>,
) -> Result<(), &'static str>
where
    I: Clone + Iterator<Item = &'a Htaccess>,
{
    if chain.clone().any(Htaccess::has_set_env) {
        let rel = resolved_rel_path(path);
        // An unscoped SetEnv never reads it: no second path otherwise.
        let if_path = if chain.clone().any(|ht| ht.has_scoped_set_env) {
            if_scope_path(path, &rel)
        } else {
            std::borrow::Cow::Borrowed(rel.as_str())
        };
        let basename = scope_basename.unwrap_or_else(|| rel.rsplit('/').next().unwrap_or(""));
        for (k, v) in hj_rewrite::set_env_assignments(chain.clone(), &rel, &if_path, basename) {
            apply_env_assignment(ctx, k, v, "SetEnv");
        }
    }
    // Skip the per-request header materialization (+ ReqAttrs build) entirely when no dir in
    // the chain declares any SetEnvIf — the common case even when an .htaccess chain exists.
    // Only when at least one SetEnvIf is present do we pay to snapshot the request headers.
    if chain.clone().all(|ht| ht.set_env_if.is_empty()) {
        return Ok(());
    }
    // Lazy header source: SetEnvIf only reads the specific names its rules reference, so resolve
    // them on demand from `req.headers()` instead of cloning the WHOLE header set into a Vec per
    // request. Case-insensitive (HeaderMap::get_all); the first value wins (matching the old
    // find-first) and a non-ASCII value is decoded lossily, never skipped, so SetEnvIf judges
    // the same string lsphp receives (#360); `_`/`-` folding is applied by
    // ReqAttrs::lookup_header before this is called.
    let header_lookup = |name: &str| -> Option<String> {
        headers
            .get_all(name)
            .iter()
            .next()
            .map(|v| hj_core::header_value_lossy(v).into_owned())
    };
    // `as_str()` already yields a borrow good for the rest of this fn (method borrows `req`,
    // protocol is `&'static`), so feed ReqAttrs the borrows directly — no per-request String.
    let protocol = ctx.protocol.as_str();
    // Formatted only when some SetEnvIf reads them; otherwise ReqAttrs never does.
    let (remote_addr, server_addr, host) =
        if chain.clone().any(Htaccess::set_env_if_reads_connection) {
            // IPv6-aware host (a naive `split(':')` mangles a bracketed `[::1]:443` to `[`);
            // matches the router / rewrite-host normalization so SetEnvIf/RewriteCond see the
            // same host the vhost was resolved by.
            let host = headers
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(hj_core::host_without_port)
                .unwrap_or_else(|| ctx.vhost_name.to_string());
            (
                ip_to_string(ctx.client_ip),
                ip_to_string(ctx.local_addr.ip()),
                host,
            )
        } else {
            (String::new(), String::new(), String::new())
        };
    // Scoped SetEnvIf matches the normalized path like Header/access scopes do;
    // computed only when some file in the chain actually has one (#781). `<If>`
    // sees it with the request's trailing `/` (#979).
    let scope_path = chain
        .clone()
        .any(|ht| ht.has_scoped_set_env)
        .then(|| resolved_rel_path(path));
    let if_path = scope_path.as_deref().map(|rel| if_scope_path(path, rel));

    let attrs = ReqAttrs {
        request_uri: path,
        method,
        protocol,
        query_string: query,
        remote_addr: &remote_addr,
        server_addr: &server_addr,
        host: &host,
        scope_path: scope_path.as_deref().unwrap_or(""),
        if_path: if_path.as_deref().unwrap_or(""),
        scope_basename,
        header_lookup: Some(HeaderLookup(&header_lookup)),
        env_lookup: None,
    };
    for ht in chain {
        // An attribute that is no header falls back to the env (mod_setenvif's
        // subprocess_env step), so each file sees the server variables and the
        // assignments of the files before it (#794).
        let assignments = {
            let env = &ctx.env;
            let env_lookup = |name: &str| setenvif_env_value(env, name);
            let attrs = ReqAttrs {
                env_lookup: Some(HeaderLookup(&env_lookup)),
                ..attrs
            };
            ht.eval_set_env(&attrs)?
        };
        for (k, v) in assignments {
            apply_env_assignment(ctx, k, v, "SetEnvIf");
        }
    }
    Ok(())
}

/// Whether `chain`'s own env phase can change its access verdict: some file writes
/// env (`SetEnv`/`UnsetEnv`/`SetEnvIf`) and some `Allow/Deny from env=` reads it.
pub(super) fn chain_env_feeds_access(chain: &[Arc<Htaccess>]) -> bool {
    chain.iter().any(|ht| ht.access_reads_env())
        && chain
            .iter()
            .any(|ht| ht.has_set_env() || !ht.set_env_if.is_empty())
}

/// The `<If "%{REQUEST_URI} …">` subject for `path` whose collapsed form is
/// `rel`: [`normalized_request_path`](super::rewrite_glue::normalized_request_path)
/// without collapsing twice, keeping the trailing `/` that `rel` drops (#979).
fn if_scope_path<'r>(path: &str, rel: &'r str) -> std::borrow::Cow<'r, str> {
    if path.ends_with('/') && !rel.ends_with('/') {
        std::borrow::Cow::Owned(format!("{rel}/"))
    } else {
        std::borrow::Cow::Borrowed(rel)
    }
}

/// The env value a `SetEnvIf` attribute falls back to: ASCII-case-insensitive
/// like Apache's tables, with an exact-case entry preferred. Internal plumbing
/// is hidden: `HJ_*` is pipeline-reserved, and `HTTP_ACCEPT_ENCODING` is only
/// pre-seeded for the compression transform (Apache adds `HTTP_*` vars at
/// handler time, after mod_setenvif), so a rule could otherwise read the raw
/// Accept-Encoding, which no cache key carries.
fn setenvif_env_value(env: &[(String, String)], name: &str) -> Option<String> {
    let hidden = |k: &str| {
        k.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("HJ_"))
            || k.eq_ignore_ascii_case("HTTP_ACCEPT_ENCODING")
    };
    if hidden(name) {
        return None;
    }
    env.iter()
        .find(|(k, _)| k == name)
        .or_else(|| env.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)))
        .map(|(_, v)| v.clone())
}

/// Whether an `Allow/Deny from env=NAME` variable is set: ASCII-case-insensitive
/// like Apache's `apr_table_get`, with an exact-case entry preferred; a
/// case-folded match never reaches the pipeline-reserved `HJ_*` names.
fn access_env_set(env: &[(String, String)], name: &str) -> bool {
    let hidden = |k: &str| k.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("HJ_"));
    env.iter().any(|(k, _)| k == name)
        || env
            .iter()
            .any(|(k, _)| !hidden(k) && k.eq_ignore_ascii_case(name))
}

/// (#1) Fail-safe access decision across the whole chain: any `denied` section
/// (in any `.htaccess`) that matches `path` -> deny. `path` must already be
/// normalized, either as [`resolved_rel_path`](super::rewrite_glue::resolved_rel_path)
/// or slash-preserving as
/// [`normalized_request_path`](super::rewrite_glue::normalized_request_path): the
/// `<If "%{REQUEST_URI} …">` matchers see the trailing `/`, the
/// `<Files*>`/`<Directory*>` matchers see the path without it.
/// Judged against the RESOLVED client IP and the post-SetEnvIf env in `ctx`, which
/// the legacy `Order`/`Allow from`/`Deny from` rules read (#359) — so it must run
/// after `apply_set_env`, as every call site does.
pub(super) fn access_denied(
    chain: &[Arc<Htaccess>],
    path: &str,
    method: &str,
    ctx: &ReqCtx,
) -> bool {
    access_denied_iter(chain.iter().map(AsRef::as_ref), path, method, ctx)
}

pub(super) fn access_denied_iter<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    path: &str,
    method: &str,
    ctx: &ReqCtx,
) -> bool {
    let rel_path = match path.strip_suffix('/') {
        Some(p) if !p.is_empty() => p,
        _ => path,
    };
    let env_set = |name: &str| access_env_set(&ctx.env, name);
    let subject = hj_rewrite::AccessSubject {
        client_ip: Some(ctx.client_ip),
        env_set: Some(&env_set),
    };
    chain.into_iter().any(|ht| {
        ht.access_decision_for_request(rel_path, path, method, &subject) == AccessDecision::Denied
    })
}

#[cfg(test)]
pub(super) fn access_denied_for(
    chain: &[Arc<Htaccess>],
    rel_path: &str,
    method: &str,
    subject: &hj_rewrite::AccessSubject<'_>,
) -> bool {
    chain
        .iter()
        .any(|ht| ht.access_decision_for(rel_path, method, subject) == AccessDecision::Denied)
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
    apply_response_headers_for_target(ctx, chain, rel_path, None, request_path, resp);
}

/// [`apply_response_headers_for_request`] whose `<Files*>` sections match
/// `target_basename`, the file the request maps to (the `DirectoryIndex` file
/// served, or the script before `PATH_INFO`), as Apache's internal redirect /
/// file walk does. Then `AddDefaultCharset` completes a charset-less
/// `text/html` / `text/plain` `Content-Type`.
pub(super) fn apply_response_headers_for_target(
    ctx: &ReqCtx,
    chain: &[Arc<Htaccess>],
    rel_path: &str,
    target_basename: Option<&str>,
    request_path: &str,
    resp: &mut Response,
) {
    let has_headers = chain.iter().any(|ht| ht.has_resp_op);
    let has_charset = chain.iter().any(|ht| ht.has_default_charset());
    if !has_headers && !has_charset {
        return;
    }
    if has_headers {
        let status = resp.status().as_u16();
        let ops = hj_rewrite::chain_prepared_headers(
            chain.iter().map(AsRef::as_ref),
            rel_path,
            target_basename,
            request_path,
            status,
            &ctx.env,
        );
        for op in &ops {
            apply_header(resp, op.kind, op.name, &op.value, op.field_value);
        }
    }
    if has_charset {
        let basename = target_basename.unwrap_or_else(|| rel_path.rsplit('/').next().unwrap_or(""));
        if let Some(charset) =
            hj_rewrite::default_charset(chain.iter().map(AsRef::as_ref), rel_path, basename)
        {
            apply_default_charset(resp, &charset);
        }
    }
}

/// Attach the effective `.htaccess` expiry decision to a static 200/206/304. The
/// response transform consumes it after authorization sensitivity is known.
pub(super) fn attach_expires_decision(
    chain: &[Arc<Htaccess>],
    rel_path: &str,
    target_basename: Option<&str>,
    request_path: &str,
    resp: &mut Response,
) {
    if !matches!(
        resp.status(),
        http::StatusCode::OK | http::StatusCode::PARTIAL_CONTENT | http::StatusCode::NOT_MODIFIED
    ) || resp
        .extensions()
        .get::<hj_static::ResolvedTargetPath>()
        .is_none()
    {
        return;
    }
    let Some(content_type) = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let basename = target_basename.unwrap_or_else(|| rel_path.rsplit('/').next().unwrap_or(""));
    let decision = hj_rewrite::expires_decision(
        chain.iter().map(AsRef::as_ref),
        rel_path,
        request_path,
        basename,
        content_type,
    );
    if decision != hj_rewrite::ExpiresDecision::Inherit {
        resp.extensions_mut().insert(decision);
    }
}

/// Apache `AddDefaultCharset`: append `; charset=<cs>` to a `text/html` or
/// `text/plain` `Content-Type` that carries no charset parameter.
fn apply_default_charset(resp: &mut Response, charset: &str) {
    let Some(ct) = resp.headers().get(http::header::CONTENT_TYPE) else {
        return;
    };
    let Ok(ct) = ct.to_str() else {
        return;
    };
    let media = ct.split(';').next().unwrap_or("").trim();
    let eligible =
        media.eq_ignore_ascii_case("text/html") || media.eq_ignore_ascii_case("text/plain");
    if !eligible || ct.to_ascii_lowercase().contains("charset=") {
        return;
    }
    if let Ok(value) = http::HeaderValue::from_str(&format!("{ct}; charset={charset}")) {
        resp.headers_mut().insert(http::header::CONTENT_TYPE, value);
    }
}

/// Fold one `Header` op into a response's header map. `field_value` is `value`
/// already built as a field value (a static directive value); otherwise `value`
/// is validated here, and an invalid one leaves the response untouched.
fn apply_header(
    resp: &mut Response,
    kind: HeaderOpKind,
    name: &http::HeaderName,
    value: &str,
    field_value: Option<&http::HeaderValue>,
) {
    use http::header::HeaderValue;
    let built = || match field_value {
        Some(v) => Ok(v.clone()),
        None => HeaderValue::from_str(value),
    };
    let headers = resp.headers_mut();
    match kind {
        HeaderOpKind::Unset => {
            headers.remove(name);
        }
        HeaderOpKind::Set => {
            if let Ok(v) = built() {
                headers.remove(name);
                headers.insert(name, v);
            }
        }
        HeaderOpKind::Add => {
            if let Ok(v) = built() {
                headers.append(name, v);
            }
        }
        // Fold list fields across every line; Set-Cookie remains non-combinable.
        HeaderOpKind::Append | HeaderOpKind::Merge => {
            if kind == HeaderOpKind::Merge
                && headers.get_all(name).iter().any(|v| {
                    v.as_bytes()
                        .split(|&b| b == b',')
                        .any(|tok| tok.trim_ascii() == value.trim().as_bytes())
                })
            {
                return;
            }
            if *name == http::header::SET_COOKIE {
                if let Ok(value) = built() {
                    headers.append(name, value);
                }
                return;
            }
            let existing = {
                let values: Vec<&[u8]> =
                    headers.get_all(name).iter().map(|v| v.as_bytes()).collect();
                (!values.is_empty()).then(|| values.join(&b", "[..]))
            };
            let merged = match existing {
                Some(mut prev) if !prev.is_empty() => {
                    prev.extend_from_slice(b", ");
                    prev.extend_from_slice(value.as_bytes());
                    prev
                }
                _ => value.as_bytes().to_vec(),
            };
            if let Ok(v) = HeaderValue::from_bytes(&merged) {
                headers.remove(name);
                headers.insert(name, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::rewrite_glue::resolved_rel_path;
    use super::*;
    use hj_rewrite::HeaderOp;

    #[test]
    fn expires_decision_attaches_only_to_static_cacheable_statuses() {
        let chain = vec![Arc::new(
            Htaccess::parse("ExpiresActive On\nExpiresDefault \"access 2 days\"\n").unwrap(),
        )];
        let response = || {
            let mut response = Response::new(hj_core::Body::Full(bytes::Bytes::from_static(b"x")));
            response
                .headers_mut()
                .insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
            response
        };

        let mut dynamic = response();
        attach_expires_decision(&chain, "/x.txt", None, "/x.txt", &mut dynamic);
        assert!(
            dynamic
                .extensions()
                .get::<hj_rewrite::ExpiresDecision>()
                .is_none()
        );

        for status in [
            http::StatusCode::OK,
            http::StatusCode::PARTIAL_CONTENT,
            http::StatusCode::NOT_MODIFIED,
        ] {
            let mut static_response = response();
            *static_response.status_mut() = status;
            static_response
                .extensions_mut()
                .insert(hj_static::ResolvedTargetPath("/tmp/x.txt".into()));
            attach_expires_decision(&chain, "/x.txt", None, "/x.txt", &mut static_response);
            assert!(matches!(
                static_response
                    .extensions()
                    .get::<hj_rewrite::ExpiresDecision>(),
                Some(hj_rewrite::ExpiresDecision::Rule { .. })
            ));
        }
    }

    /// Fold a string [`HeaderOp`] through [`apply_header`], parsing its name here.
    fn apply_header_op(resp: &mut Response, op: &HeaderOp) {
        let Ok(name) = http::HeaderName::from_bytes(op.name().as_bytes()) else {
            return;
        };
        let (kind, value) = match op {
            HeaderOp::Set { value, .. } => (HeaderOpKind::Set, value.as_str()),
            HeaderOp::Add { value, .. } => (HeaderOpKind::Add, value.as_str()),
            HeaderOp::Append { value, .. } | HeaderOp::Edit { value, .. } => {
                (HeaderOpKind::Append, value.as_str())
            }
            HeaderOp::Merge { value, .. } => (HeaderOpKind::Merge, value.as_str()),
            HeaderOp::Unset { .. } => (HeaderOpKind::Unset, ""),
        };
        apply_header(resp, kind, &name, value, None);
    }

    #[test]
    fn append_preserves_cookie_lines_and_non_ascii_list_values() {
        let mut response = http::Response::new(hj_core::Body::Empty);
        response
            .headers_mut()
            .append(http::header::SET_COOKIE, "first=a".parse().unwrap());
        response
            .headers_mut()
            .append(http::header::SET_COOKIE, "second=b".parse().unwrap());
        apply_header_op(
            &mut response,
            &HeaderOp::Append {
                name: "Set-Cookie".into(),
                value: "third=c".into(),
            },
        );
        let cookies: Vec<_> = response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| v.as_bytes())
            .collect();
        assert_eq!(
            cookies,
            vec![b"first=a".as_slice(), b"second=b", b"third=c"]
        );
        response
            .headers_mut()
            .append("x-list", http::HeaderValue::from_bytes(b"\xff").unwrap());
        response
            .headers_mut()
            .append("x-list", "second".parse().unwrap());
        apply_header_op(
            &mut response,
            &HeaderOp::Edit {
                name: "X-List".into(),
                value: "third".into(),
            },
        );
        assert_eq!(
            response.headers()["x-list"].as_bytes(),
            b"\xff, second, third"
        );
    }

    #[test]
    fn merge_skips_a_value_already_in_the_list() {
        let mut response = http::Response::new(hj_core::Body::Empty);
        response.headers_mut().append(
            http::header::VARY,
            "Origin, Accept-Encoding".parse().unwrap(),
        );
        let merge = |value: &str| HeaderOp::Merge {
            name: "Vary".into(),
            value: value.into(),
        };
        apply_header_op(&mut response, &merge("Accept-Encoding"));
        assert_eq!(response.headers()["vary"], "Origin, Accept-Encoding");
        apply_header_op(&mut response, &merge("Cookie"));
        assert_eq!(
            response.headers()["vary"],
            "Origin, Accept-Encoding, Cookie"
        );
        let mut empty = http::Response::new(hj_core::Body::Empty);
        apply_header_op(&mut empty, &merge("Accept-Encoding"));
        assert_eq!(empty.headers()["vary"], "Accept-Encoding");
    }

    fn get_req(uri: &str) -> Request {
        http::Request::builder()
            .uri(uri)
            .body(hj_core::empty_incoming())
            .unwrap()
    }

    #[test]
    fn set_env_if_bang_unsets_and_cannot_remove_reserved_env() {
        let ht = hj_rewrite::Htaccess::parse(
            "SetEnvIf Request_URI ^/pub/secret !ok !HJ_REQUEST_PATH_QUERY\n",
        )
        .unwrap();
        let chain = vec![Arc::new(ht)];
        let mut ctx = test_ctx();
        ctx.set_env("ok", "1");
        ctx.set_env("HJ_REQUEST_PATH_QUERY", "/original");
        apply_set_env(
            &mut ctx,
            &chain,
            &get_req("/pub/secret/x"),
            "/pub/secret/x",
            "",
        )
        .unwrap();
        assert_eq!(ctx.get_env("ok"), None);
        assert_eq!(ctx.get_env("!ok"), None);
        assert_eq!(ctx.get_env("HJ_REQUEST_PATH_QUERY"), Some("/original"));
    }

    #[test]
    fn set_env_if_env_attribute_sees_server_env_and_earlier_chain_files() {
        let parent = hj_rewrite::Htaccess::parse("SetEnvIf Request_URI ^/app/ in_app\n").unwrap();
        let child = hj_rewrite::Htaccess::parse(
            "SetEnvIf in_app ^1$ chained\nSetEnvIf HTTPS ^on$ tls\n\
             SetEnvIf HJ_REQUEST_PATH_QUERY . leaked_hj\n\
             SetEnvIf HTTP_ACCEPT_ENCODING . leaked_ae\n",
        )
        .unwrap();
        let chain = vec![Arc::new(parent), Arc::new(child)];
        let mut ctx = test_ctx();
        ctx.is_tls = true;
        seed_server_env(&mut ctx);
        ctx.set_env("HJ_REQUEST_PATH_QUERY", "/original");
        ctx.set_env("HTTP_ACCEPT_ENCODING", "gzip");
        apply_set_env(&mut ctx, &chain, &get_req("/app/x"), "/app/x", "").unwrap();
        assert_eq!(ctx.get_env("chained"), Some("1"));
        assert_eq!(ctx.get_env("tls"), Some("1"));
        assert_eq!(ctx.get_env("leaked_hj"), None);
        assert_eq!(ctx.get_env("leaked_ae"), None);
    }

    #[test]
    fn scoped_set_env_if_matches_the_normalized_path() {
        let ht = hj_rewrite::Htaccess::parse(
            "<Files \"public.html\">\n  SetEnvIf Request_URI . open_it\n</Files>\n",
        )
        .unwrap();
        let chain = vec![Arc::new(ht)];
        let mut ctx = test_ctx();
        apply_set_env(&mut ctx, &chain, &get_req("/secret.txt"), "/secret.txt", "").unwrap();
        assert_eq!(ctx.get_env("open_it"), None);
        let mut ctx = test_ctx();
        let path = "/sub/../public.html";
        apply_set_env(&mut ctx, &chain, &get_req(path), path, "").unwrap();
        assert_eq!(ctx.get_env("open_it"), Some("1"));
        let mut ctx = test_ctx();
        apply_set_env(
            &mut ctx,
            &chain,
            &get_req("/public.html"),
            "/public.html",
            "",
        )
        .unwrap();
        assert_eq!(ctx.get_env("open_it"), Some("1"));
    }

    fn test_ctx() -> ReqCtx {
        let server = Arc::new(hj_core::config::ServerConfig::default());
        let vhost = Arc::new(hj_core::config::VHostConfig::default());
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        ReqCtx {
            server,
            vhost_name: "test.example".into(),
            vhost,
            peer_ip: loopback,
            client_ip: loopback,
            is_tls: false,
            protocol: hj_core::Proto::Http1,
            trusted_proxy: false,
            forwarding_trusted: false,
            env: Vec::new(),
            local_addr: "127.0.0.1:80".parse().unwrap(),
            peer_port: 40000,
            peer_unix: false,
            tls: None,
            redirect_guard: None,
            request_time: std::time::SystemTime::UNIX_EPOCH,
            request_id: Default::default(),
        }
    }

    #[test]
    fn set_env_if_cannot_overwrite_reserved_hj_env() {
        let ht = hj_rewrite::Htaccess::parse(
            "SetEnvIf Request_URI ^.*$ HJ_REQUEST_PATH_QUERY=/spoofed\n\
             SetEnvIf Request_URI ^.*$ PLAIN_OK=yes\n",
        )
        .unwrap();
        let chain = vec![Arc::new(ht)];
        let req = get_req("/x");
        let mut ctx = test_ctx();
        ctx.set_env("HJ_REQUEST_PATH_QUERY", "/original");

        apply_set_env(&mut ctx, &chain, &req, "/x", "").unwrap();

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
            !access_denied_for(&raw_chain, &raw_rel, "GET", &Default::default()),
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
            access_denied_for(&fixed_chain, &rel, "GET", &Default::default()),
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
        let acl = AccessControl::from_security(&Security::default()).unwrap();
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
        resp.headers_mut().append(
            HeaderName::from_static("vary"),
            http::HeaderValue::from_static("Origin"),
        );

        // Append concatenates onto every existing value.
        apply_header_op(
            &mut resp,
            &HeaderOp::Append {
                name: "Vary".into(),
                value: "Accept-Encoding".into(),
            },
        );
        assert_eq!(
            resp.headers().get("vary").unwrap(),
            "Accept, Origin, Accept-Encoding"
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

    #[test]
    fn compatibility_fixture_pins_final_response_semantic_gaps() {
        const FIXTURE: &str =
            include_str!("../../../hj-rewrite/tests/fixtures/header_compat/semantic-gaps.htaccess");
        let chain = vec![Arc::new(Htaccess::parse(FIXTURE).unwrap())];
        let ctx = super::super::tests::bare_ctx_for_headers();
        let mut resp: Response = Response::new(hj_core::Body::Empty);
        resp.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-cache"),
        );

        apply_response_headers_for_request(&ctx, &chain, "/index.html", "/index.html", &mut resp);

        assert_eq!(
            resp.headers().get(http::header::CACHE_CONTROL).unwrap(),
            "no-cache",
            "Merge de-duplicates an existing list value"
        );
        assert!(
            !resp.headers().contains_key("x-colon"),
            "Apache's optional trailing colon is currently rejected as an invalid field name"
        );
        assert!(!resp.headers().contains_key("x-expr-value"));
        assert_eq!(resp.headers().get("x-early").unwrap(), "late-only");
    }

    /// The fold before #982, verbatim: every op's name and value parsed from strings.
    fn legacy_apply_header_op(resp: &mut Response, op: &HeaderOp) {
        use http::header::{HeaderName, HeaderValue};
        let name = match HeaderName::from_bytes(op.name().as_bytes()) {
            Ok(n) => n,
            Err(_) => return,
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
            HeaderOp::Append { value, .. }
            | HeaderOp::Edit { value, .. }
            | HeaderOp::Merge { value, .. } => {
                if matches!(op, HeaderOp::Merge { .. })
                    && headers.get_all(&name).iter().any(|v| {
                        v.as_bytes()
                            .split(|&b| b == b',')
                            .any(|tok| tok.trim_ascii() == value.trim().as_bytes())
                    })
                {
                    return;
                }
                if name == http::header::SET_COOKIE {
                    if let Ok(value) = HeaderValue::from_str(value) {
                        headers.append(name, value);
                    }
                    return;
                }
                let existing = {
                    let values: Vec<&[u8]> = headers
                        .get_all(&name)
                        .iter()
                        .map(|v| v.as_bytes())
                        .collect();
                    (!values.is_empty()).then(|| values.join(&b", "[..]))
                };
                let merged = match existing {
                    Some(mut prev) if !prev.is_empty() => {
                        prev.extend_from_slice(b", ");
                        prev.extend_from_slice(value.as_bytes());
                        prev
                    }
                    _ => value.as_bytes().to_vec(),
                };
                if let Ok(v) = HeaderValue::from_bytes(&merged) {
                    headers.remove(&name);
                    headers.insert(&name, v);
                }
            }
        }
    }

    fn backend_response(status: u16) -> Response {
        let mut resp: Response = Response::new(hj_core::Body::Empty);
        *resp.status_mut() = http::StatusCode::from_u16(status).unwrap();
        for (name, value) in [
            ("content-type", "text/html; charset=utf-8"),
            ("server", "httpjet"),
            ("link", "</styles/a.css>; rel=preload; as=style"),
            ("set-cookie", "xf_csrf=a; path=/"),
            ("set-cookie", "xf_session=b; path=/"),
            ("cache-control", "no-cache, max-age=0"),
            ("vary", "Accept-Encoding"),
            ("etag", "\"1-2-3;;;\""),
            ("x-frame-options", "DENY"),
            ("access-control-allow-origin", "*"),
            ("x-list", "a, b"),
        ] {
            resp.headers_mut().append(name, value.parse().unwrap());
        }
        resp
    }

    fn header_lines(resp: &Response) -> Vec<(String, Vec<u8>)> {
        resp.headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect()
    }

    /// The prepared fold (the pipeline's path) must leave the response header map
    /// identical, line for line and in order, to the legacy string fold.
    fn assert_prepared_fold_matches_legacy(
        text: &str,
        envs: &[Vec<(&str, &str)>],
        paths: &[(&str, Option<&str>)],
    ) -> usize {
        let chain = vec![Arc::new(Htaccess::parse(text).unwrap())];
        let mut changed = 0;
        for env in envs {
            let mut ctx = super::super::tests::bare_ctx_for_headers();
            ctx.env = env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            for &(request_path, target) in paths {
                let rel_path = request_path
                    .strip_suffix('/')
                    .filter(|p| !p.is_empty())
                    .unwrap_or(request_path);
                for status in [200, 301, 404, 500] {
                    let mut legacy = backend_response(status);
                    for op in hj_rewrite::chain_response_headers(
                        chain.iter().map(AsRef::as_ref),
                        rel_path,
                        target,
                        request_path,
                        status,
                        &ctx.env,
                    ) {
                        legacy_apply_header_op(&mut legacy, &op);
                    }
                    let mut prepared = backend_response(status);
                    apply_response_headers_for_target(
                        &ctx,
                        &chain,
                        rel_path,
                        target,
                        request_path,
                        &mut prepared,
                    );
                    assert_eq!(
                        header_lines(&prepared),
                        header_lines(&legacy),
                        "{request_path} target={target:?} status={status} env={env:?}"
                    );
                    if header_lines(&prepared) != header_lines(&backend_response(status)) {
                        changed += 1;
                    }
                }
            }
        }
        changed
    }

    #[test]
    fn prepared_header_fold_matches_legacy_on_the_forum_fixture() {
        const FORUM: &str =
            include_str!("../../../hj-rewrite/tests/fixtures/header_compat/forum-headers.htaccess");
        let envs: Vec<Vec<(&str, &str)>> = vec![
            vec![],
            vec![("HTTPS", "on")],
            vec![
                ("HTTPS", "on"),
                ("ORIGIN_ALLOWED", "https://windowsforum.com"),
                ("KNOWN_CRAWLER", "1"),
                ("AMP_PAGE", ""),
                ("CANONICAL", "https://windowsforum.com/styles/a.css"),
            ],
            vec![
                ("WF_CHAT_CORS_ENDPOINT", "1"),
                ("WF_CHAT_CORS_ORIGIN", "https://beta.windowsforum.com"),
                ("ORIGIN_ALLOWED", "https://beta.windowsforum.com"),
            ],
            vec![
                ("WF_BETA_CONTROL", "1"),
                ("no-cache", "1"),
                ("WF_NOINDEX_PATH", "1"),
            ],
            vec![
                ("no-cache-sso", "1"),
                ("no-cache-webmcp", "1"),
                ("proxy-img-cache", "1"),
                ("wf-unfurl-image", "1"),
                ("no-cache-vc", "1"),
                ("no-cache-api", "1"),
                ("no-cache-wp", "1"),
                ("cache-bypass-misc", "1"),
                ("NO_CACHE_BUILDS", "1"),
                ("no-cache-lsonly", "1"),
            ],
            // Case-folded names resolve, an exact-case entry wins, plumbing stays hidden.
            vec![
                ("https", "on"),
                ("origin_allowed", "https://folded.example"),
                ("ORIGIN_ALLOWED", "https://exact.example"),
                ("canonical", "https://windowsforum.com/x.png"),
                ("HTTP_ACCEPT_ENCODING", "gzip"),
                ("HJ_KNOWN_CRAWLER", "1"),
            ],
            // An interpolated value that is not a valid field value is skipped.
            vec![
                ("ORIGIN_ALLOWED", "https://a.example\r\nX-Injected: 1"),
                ("CANONICAL", "bad\u{7f}"),
            ],
        ];
        let paths = [
            ("/", None),
            ("/", Some("index.php")),
            ("/index.php", None),
            ("/threads/a-thread.123/", Some("index.php")),
            ("/styles/a.css", None),
            ("/data/x.png", None),
            ("/service_worker.js", None),
            ("/js/sx.min.js", None),
            ("/amp-onetap.html", None),
            ("/cf-challenge.html", None),
            ("/css.php", None),
            ("/proxy.php", None),
            ("/llms.txt", None),
            ("/auth.md", None),
            ("/.well-known/api-catalog", None),
            ("/.well-known/agent-skills/x.md", None),
            ("/docs/readme.md", None),
            ("/beta/", Some("index.php")),
        ];
        let changed = assert_prepared_fold_matches_legacy(FORUM, &envs, &paths);
        assert!(changed > 0, "the fixture must actually rewrite headers");
    }

    #[test]
    fn prepared_header_fold_matches_legacy_on_invalid_and_list_ops() {
        let text = "Header set X-Colon: value\n\
                    Header set X-Bad \"a\u{7f}b\"\n\
                    Header add X-Bad-Add \"tab\tok\u{1}\"\n\
                    Header set X-Ok \"caf\u{e9}\"\n\
                    Header append X-List c\n\
                    Header append X-List \"bad\u{1}\"\n\
                    Header merge X-List b\n\
                    Header merge Cache-Control no-cache\n\
                    Header merge Cache-Control private\n\
                    Header append Set-Cookie \"c=3\"\n\
                    Header append Set-Cookie \"d=\u{1}\"\n\
                    Header merge Vary Origin\n\
                    Header add Vary \"%{V}e\"\n\
                    Header set X-Dyn \"pre-%{V}e-post\" env=V\n\
                    Header unset X-Frame-Options env=!KEEP\n\
                    Header add X-Empty \"\"\n";
        let envs: Vec<Vec<(&str, &str)>> = vec![
            vec![],
            vec![("V", "Accept")],
            vec![("v", "folded"), ("KEEP", "1")],
            vec![("V", "bad\u{1}")],
        ];
        let paths = [("/", None), ("/a.php", None)];
        assert!(assert_prepared_fold_matches_legacy(text, &envs, &paths) > 0);
    }
}
