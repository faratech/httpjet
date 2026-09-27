//! Response construction + `.htaccess` error-document handling (#8a) and the
//! static-context header application (#9b), plus the small redirect/status
//! builders and the page-cache collision-guard identity helper.

use std::path::Path;
use std::sync::Arc;

use hj_core::{Body, ReqCtx, Request, Response};
use hj_fastcgi::FastCgiScript;
use hj_lsapi::LsapiScript;
use hj_rewrite::{ErrorDoc, Htaccess};
use http::StatusCode;

use crate::state::ServerState;

use super::htaccess_apply::{access_denied_iter, apply_set_env_iter_with_headers};
use super::rewrite_glue::{build_uri, normalized_request_path, percent_encode_path};
use super::{GeneratedErrorPage, error_page, resolve_vhost_jail, run_handler};

/// (#8a) If the response is an httpjet-generated 4xx/5xx, replace it with the
/// chain's `ErrorDocument` for that status: inline message, local file body, or
/// an external redirect. An upstream (proxy/LSAPI) error is left untouched —
/// detected by the presence of a non-empty body produced by the handler.
///
/// (#3) A `Path` declared executable by suffix or `.htaccess` handler override
/// is an internal LSAPI/FastCGI subrequest (Apache/LiteSpeed parity), NOT a raw
/// file read. Declaration is classified independently of backend availability or
/// the vhost execution toggle, so an unavailable script can never fall through
/// to static source serving. A non-script path uses the static handler.
pub(super) async fn apply_error_document(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
    request_headers: &http::HeaderMap,
    chain: &[Arc<Htaccess>],
    cur_path: &str,
    resp: &mut Response,
) {
    if chain.is_empty() {
        return;
    }
    let status = resp.status().as_u16();
    if !(400..600).contains(&status) {
        return;
    }
    // Only override httpjet's own error pages. A streamed/file/non-empty upstream
    // body means the terminal handler produced this response; leave it alone.
    if !is_generated_error_body(resp) {
        return;
    }
    // Innermost (leaf) .htaccess wins for the same status code. Clone so we no
    // longer borrow `chain` while we take `&mut ctx` for a PHP subrequest.
    let Some(doc) = chain
        .iter()
        .rev()
        .find_map(|ht| ht.error_document(status))
        .cloned()
    else {
        return;
    };
    match doc {
        ErrorDoc::External(url) => {
            *resp = redirect(302, &url);
        }
        ErrorDoc::Inline(msg) => {
            let keep = resp.status();
            *resp = Response::new(Body::Full(bytes::Bytes::from(msg)));
            *resp.status_mut() = keep;
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/html; charset=UTF-8"),
            );
        }
        ErrorDoc::Path(p) => {
            let rel = normalized_request_path(&p);
            // An ErrorDocument is a distinct internal request. Source-path rewrite and
            // SetEnvIf variables must not satisfy target-path `Allow from env=` rules.
            // Build the target context field-by-field so the source env and all of
            // its strings are not cloned just to be discarded. The remaining owned
            // fields preserve the same isolation as a full context clone.
            let mut target_ctx = isolated_error_document_context(ctx);
            // Recreate automatic server variables for the internal request while
            // excluding all source-path SetEnvIf/rewrite/auth state.
            super::seed_server_env(&mut target_ctx);
            let replacement = render_path_error_document(
                state,
                &mut target_ctx,
                request_headers,
                &rel,
                cur_path,
                status,
                resp.status(),
                resp.extensions().get::<super::PhpBackendFailed>().is_some(),
            )
            .await;
            if let Some(rendered) = replacement {
                *resp = rendered;
            }
        }
    }
}

/// Resolve, authorize, and render a local ErrorDocument as an isolated internal
/// request. The caller supplies a cloned context with target-local environment.
async fn render_path_error_document(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
    request_headers: &http::HeaderMap,
    rel: &str,
    orig_request_path: &str,
    status: u16,
    keep: StatusCode,
    php_backend_failed: bool,
) -> Option<Response> {
    // Resolve the target's own per-directory policy rather than reusing the
    // chain of the URL that failed. Keep a trailing slash for DirectoryIndex.
    let target_chain_with_dirs = if ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess)
    {
        state.rewrite_cache.load_chain_with_dirs(
            &ctx.vhost.doc_root,
            rel,
            ctx.vhost.access_file_name_or_default(),
        )
    } else {
        Vec::new()
    };
    let target_chain = || target_chain_with_dirs.iter().map(|(_, ht)| ht.as_ref());

    // Policy reads inbound headers through borrowed lookups. No owned request
    // (and no full HeaderMap clone) is needed until terminal dispatch.
    let has_set_env = target_chain().any(|ht| !ht.set_env_if.is_empty());
    let has_rewrite = state
        .inline_rules
        .get(&ctx.vhost_name)
        .is_some_and(|rules| !rules.is_noop())
        || target_chain_with_dirs
            .iter()
            .any(|(_, ht)| !ht.rules.is_noop());
    if has_set_env {
        apply_set_env_iter_with_headers(ctx, target_chain(), "GET", request_headers, rel, "")
            .ok()?;
    }

    if access_denied_iter(target_chain(), rel, "GET", ctx)
        || super::access_deny_dir(&state.acl, &ctx.vhost.doc_root, rel)
    {
        return None;
    }
    let mut authenticated = Vec::new();
    super::scoped_auth::enforce_chain_iter(
        ctx,
        request_headers,
        target_chain(),
        rel,
        rel,
        &mut authenticated,
    )
    .await
    .ok()?;

    // The ErrorDocument target is an internal request and must obey its own
    // rewrite policy. Replacement rendering is deliberately narrower than a
    // normal dispatch: only an unchanged target is safe here. Following a
    // rewrite/redirect/proxy/status outcome could expose a resource that the
    // target directory meant to deny or route elsewhere, while recursively
    // rendering forbidden/gone/failed outcomes could mask the original error.
    if has_rewrite {
        let raw_request_target = percent_encode_path(rel);
        match super::rewrite_glue::run_rewrite_with_headers(
            state,
            ctx,
            "GET",
            request_headers,
            &raw_request_target,
            &target_chain_with_dirs,
            rel,
            "",
        ) {
            super::rewrite_glue::RwResult::Unchanged { env } => {
                super::merge_rewrite_env(ctx, env);
            }
            _ => return None,
        }
    }

    // Re-check env-sensitive access rules after merging `[E=...]`, matching the
    // normal dispatch's pre/post-rewrite deny gates. The path itself cannot have
    // changed because every `Rewritten` result was rejected above.
    if access_denied_iter(target_chain(), rel, "GET", ctx) {
        return None;
    }

    let index_files = target_chain_with_dirs
        .iter()
        .rev()
        .find(|(_, ht)| !ht.directory_index.is_empty())
        .map(|(_, ht)| ht.directory_index.as_slice())
        .unwrap_or_else(|| super::base_index_files(state, ctx));
    if let Some((script_abs, script_name, path_info)) =
        super::suffix_routing::split_declared_script_path_with_dirs(
            state,
            ctx,
            rel,
            index_files,
            &target_chain_with_dirs,
        )
    {
        let configured_handler = super::configured_script_handler_for_script(ctx, &script_abs);
        if !super::suffix_routing::vhost_scripts_enabled(state, ctx)
            || configured_handler.is_some_and(super::script_handler_is_unusable)
        {
            return None;
        }
        let fastcgi_handler = state
            .has_cgi_script_routes
            .then(|| configured_handler.and_then(super::script_handler_fastcgi_name))
            .flatten()
            .map(str::to_owned);
        // Do not retry the same failed LSAPI pool. A separately configured
        // FastCGI target remains independent.
        if fastcgi_handler.is_none() && php_backend_failed {
            return None;
        }
        let target = super::allowed_script_target(&state.acl, &script_abs)?;
        // The lexical target chain was already authorized above. Reload target
        // policy only for a genuinely different opened resource (PATH_INFO,
        // DirectoryIndex, symlink/alias target); those cases remain fail-closed.
        if !target_matches_policy_path(&ctx.vhost.doc_root, rel, &target) {
            super::scoped_auth::enforce_target(
                state,
                ctx,
                request_headers,
                &target,
                rel,
                &mut authenticated,
            )
            .await
            .ok()?;
        }
        let subreq = internal_error_document_request(&script_name);
        return run_script_error_document(
            state,
            ctx,
            subreq,
            &target,
            &script_name,
            &path_info,
            fastcgi_handler.as_deref(),
            orig_request_path,
            status,
        )
        .await;
    }

    let mut subreq = internal_error_document_request(rel);
    if let Some(index_files) = target_chain_with_dirs
        .iter()
        .rev()
        .find(|(_, ht)| !ht.directory_index.is_empty())
        .map(|(_, ht)| ht.directory_index.as_slice())
    {
        subreq
            .extensions_mut()
            .insert(hj_static::IndexFilesOverride(index_files.to_vec()));
    }
    let mut served = run_handler(&state.static_handler, ctx, subreq).await;
    if !served.status().is_success() || super::resolved_static_target_denied(&state.acl, &served) {
        return None;
    }
    if let Some(target) = super::scoped_auth::served_target(&served) {
        if !target_matches_policy_path(&ctx.vhost.doc_root, rel, &target) {
            super::scoped_auth::enforce_target(
                state,
                ctx,
                request_headers,
                &target,
                rel,
                &mut authenticated,
            )
            .await
            .ok()?;
        }
    }
    if let Some(resolved) = served.extensions().get::<hj_static::ResolvedTargetPath>() {
        let selected = served
            .extensions()
            .get::<hj_static::LexicalTargetPath>()
            .map(|target| target.0.as_path())
            .unwrap_or(&resolved.0);
        if super::suffix_routing::target_is_declared_script(
            state,
            ctx,
            rel,
            selected,
            &resolved.0,
            target_chain(),
        ) {
            return None;
        }
    }
    *served.status_mut() = keep;
    Some(served)
}

/// (#3/#507) Run a declared script `ErrorDocument` through its configured
/// LSAPI/FastCGI backend and return the rendered response with the original error
/// `status` preserved. Returns `None` when execution is unavailable or unsafe;
/// the caller retains the original page and never falls back to static source.
///
/// The subrequest is a GET at the error-doc path with the standard Apache/CGI
/// error-handler env: `REDIRECT_STATUS` (the original code, e.g. `404`) and
/// `REDIRECT_URL` (the original request path) so the PHP page can detect it is
/// an error subrequest.
async fn run_script_error_document(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
    mut subreq: Request,
    script_abs: &Path,
    script_rel: &str,
    path_info: &str,
    fastcgi_handler: Option<&str>,
    orig_request_path: &str,
    status: u16,
) -> Option<Response> {
    // Apache error-handler CGI env, read by the LSAPI env builder so the PHP
    // page can tell it is an error subrequest. This runs in an isolated cloned
    // context, so none of these values leak back to the outer request.
    ctx.set_env("REDIRECT_STATUS", status.to_string());
    ctx.set_env("REDIRECT_URL", orig_request_path.to_string());

    let mut rendered = if let Some(handler_name) = fastcgi_handler {
        let Some(handler) = state
            .fastcgi_handler(&ctx.vhost_name, handler_name)
            .cloned()
        else {
            tracing::error!(request_id = %ctx.request_id, vhost = %ctx.vhost_name, handler = handler_name, "error-doc CGI handler is not an enabled FastCGI processor");
            return None;
        };
        let mut script = match FastCgiScript::new(script_abs.to_path_buf()) {
            Ok(script) => script.script_name(script_rel.to_string()),
            Err(error) => {
                tracing::error!(request_id = %ctx.request_id, %error, "invalid pinned error-doc FastCGI target");
                return None;
            }
        };
        if !path_info.is_empty() {
            script = script.path_info(path_info.to_string());
        }
        subreq.extensions_mut().insert(script);
        run_handler(handler.as_ref(), ctx, subreq).await
    } else {
        let registry = state.lsapi.clone()?;
        let jail = match resolve_vhost_jail(state, ctx) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(vhost = %ctx.vhost_name, error = %e, "error-doc PHP jail resolve failed");
                return None;
            }
        };
        let lsapi = match registry.handler_for(&ctx.vhost_name, &jail).await {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(vhost = %ctx.vhost_name, error = %e, "error-doc lsphp pool unavailable");
                return None;
            }
        };
        subreq.extensions_mut().insert(LsapiScript {
            script: script_abs.to_path_buf(),
            script_name: Some(script_rel.to_string()),
            path_info: (!path_info.is_empty()).then(|| path_info.to_string()),
            // Error-document subrequests carry no `.htaccess` php.ini overrides.
            special_env: Vec::new(),
        });
        run_handler(lsapi.as_ref(), ctx, subreq).await
    };
    // `run_handler` maps transport/pool/protocol failures to a tagged generated
    // error. That is a failed replacement, not ErrorDocument content: retain the
    // original response body/status instead of disguising this 5xx as the outer
    // status. An application's own response never carries this internal marker.
    if rendered.extensions().get::<GeneratedErrorPage>().is_some() {
        return None;
    }
    // Preserve the original error status (a PHP error page typically emits 200).
    if let Ok(keep) = StatusCode::from_u16(status) {
        *rendered.status_mut() = keep;
    }
    Some(rendered)
}

/// Clone the connection/request identity needed by an internal ErrorDocument,
/// while deliberately starting with no source-path environment. A derived
/// `ReqCtx::clone()` would duplicate every source env key/value before clearing
/// it, which is both wasted work and contrary to the isolation this fork needs.
fn isolated_error_document_context(ctx: &ReqCtx) -> ReqCtx {
    ReqCtx {
        server: Arc::clone(&ctx.server),
        vhost_name: ctx.vhost_name.clone(),
        vhost: Arc::clone(&ctx.vhost),
        peer_ip: ctx.peer_ip,
        client_ip: ctx.client_ip,
        is_tls: ctx.is_tls,
        protocol: ctx.protocol,
        trusted_proxy: ctx.trusted_proxy,
        env: Vec::new(),
        local_addr: ctx.local_addr,
        peer_port: ctx.peer_port,
        request_time: ctx.request_time,
        request_id: ctx.request_id,
        tls: ctx.tls.clone(),
        peer_unix: ctx.peer_unix,
        redirect_guard: ctx.redirect_guard.clone(),
    }
}

/// Headerless bodyless GET used for terminal ErrorDocument dispatch after
/// policy has evaluated directly against borrowed inbound headers.
fn internal_error_document_request(path: &str) -> Request {
    let mut request = Request::new(hj_core::empty_incoming());
    if let Some(uri) = build_uri(&percent_encode_path(path), "") {
        *request.uri_mut() = uri;
    }
    request
}

/// True only when target-chain authorization above covered the exact opened
/// resource. PATH_INFO, indexes, symlinks, aliases, and alternate roots compare
/// unequal and retain the final target-policy reload.
fn target_matches_policy_path(doc_root: &Path, policy_path: &str, target: &Path) -> bool {
    target
        .strip_prefix(doc_root)
        .is_ok_and(|relative| relative == Path::new(policy_path.trim_start_matches('/')))
}

/// Whether this response is httpjet's OWN synthesized error page — the only thing
/// an `ErrorDocument` may replace. Keyed on the [`GeneratedErrorPage`] tag set by
/// `error_page()`, NOT on the body variant: a small buffered backend (LSAPI/proxy)
/// error takes the fast path (`hj_lsapi` returns `Body::Full`), so a body-variant
/// check would misclassify an app's own 4xx/5xx JSON body as server-generated and
/// clobber it (e.g. chat.php's captcha-gate `403 {captcha_required:true}`). An
/// empty body carries nothing to preserve, so it stays replaceable.
fn is_generated_error_body(resp: &Response) -> bool {
    resp.extensions().get::<GeneratedErrorPage>().is_some() || matches!(resp.body(), Body::Empty)
}

/// Build a terminal response for a forbidden/gone outcome, preferring the
/// chain's `ErrorDocument` for that status (#8a) over the built-in page.
pub(super) async fn error_doc_or_page(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
    request_headers: &http::HeaderMap,
    chain: &[Arc<Htaccess>],
    cur_path: &str,
    status: StatusCode,
) -> Response {
    let mut resp = error_page(status);
    apply_error_document(state, ctx, request_headers, chain, cur_path, &mut resp).await;
    resp
}

/// A bare status response (no body) for a non-3xx `[R=NNN]` outcome (#8/A).
pub(super) fn status_response(code: u16) -> Response {
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
    let mut resp = Response::new(Body::Empty);
    *resp.status_mut() = status;
    resp
}

/// (#9b) The longest-matching enabled **static** `<context>` for `path` that
/// changes static serving: a location override, extra headers, or a default
/// charset. Returns the context so the caller can apply those settings.
pub(super) fn matching_static_context<'a>(
    ctx: &'a ReqCtx,
    path: &str,
) -> Option<&'a hj_core::config::Context> {
    use hj_core::config::ContextKind;
    ctx.vhost
        .contexts
        .iter()
        .filter(|c| {
            c.kind == ContextKind::Static && c.enabled && super::context_uri_matches(path, &c.uri)
        })
        .filter(|c| !c.extra_headers.is_empty() || c.location.is_some() || c.add_default_charset)
        .max_by_key(|c| c.uri.len())
}

/// Apply a static context's `<extraHeaders>` (e.g. mcp's `Vary`/`Cache-Control`)
/// to a 2xx static response, without clobbering headers the handler already set.
pub(super) fn apply_static_context_headers(extra: &[(String, String)], resp: &mut Response) {
    if !resp.status().is_success() {
        return;
    }
    for (name, value) in extra {
        if let (Ok(n), Ok(v)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }
}

/// Page-cache collision-guard identity: `scheme\nvhost\norig_path`. Built from the
/// canonical, operator-controlled vhost name and the decoded+normalized path — never the
/// raw Host header (which the key already collapses, #5) and never the raw request path
/// (encoding variants must share one identity, #6). A cached entry is served only when a
/// request reproduces this exact string, so a key collision degrades to a miss.
pub(super) fn cache_identity_for(is_tls: bool, vhost_name: &str, orig_path: &str) -> String {
    let scheme = if is_tls { "https" } else { "http" };
    format!("{}\n{}\n{}", scheme, vhost_name, orig_path)
}

pub(super) fn redirect(code: u16, location: &str) -> Response {
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND);
    let reason = status.canonical_reason().unwrap_or("Moved");
    // Apache/LiteSpeed-style text/html redirect body so clients/crawlers that
    // read the body — and conformance vs LiteSpeed — match.
    let esc = html_escape(location);
    let body = format!(
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>{code} {reason}</title>\n</head><body>\n<h1>{reason}</h1>\n<p>The document has moved <a href=\"{esc}\">here</a>.</p>\n</body></html>\n"
    );
    let mut resp = Response::new(Body::Full(bytes::Bytes::from(body)));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    if let Ok(v) = http::HeaderValue::from_str(location) {
        h.insert(http::header::LOCATION, v);
    }
    h.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/html"),
    );
    resp
}

/// Minimal HTML attribute escaping for the redirect-target link.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_policy_reuse_requires_the_exact_lexical_resource() {
        let root = Path::new("/srv/site");
        assert!(target_matches_policy_path(
            root,
            "/errors/404.html",
            Path::new("/srv/site/errors/404.html")
        ));
        assert!(!target_matches_policy_path(
            root,
            "/errors/",
            Path::new("/srv/site/errors/index.html")
        ));
        assert!(!target_matches_policy_path(
            root,
            "/errors/404.php/details",
            Path::new("/srv/site/errors/404.php")
        ));
        assert!(!target_matches_policy_path(
            root,
            "/errors/404.html",
            Path::new("/srv/shared/404.html")
        ));
    }

    #[test]
    fn status_response_has_no_body_or_location() {
        let resp = status_response(200);
        assert_eq!(resp.status().as_u16(), 200);
        assert!(matches!(resp.body(), Body::Empty));
        assert!(!resp.headers().contains_key(http::header::LOCATION));
        // A non-canonical code still maps (e.g. 299 -> falls back to 200 only on
        // an out-of-range value; 204 is a real status).
        assert_eq!(status_response(204).status().as_u16(), 204);
    }

    #[test]
    fn static_context_headers_only_on_success() {
        let extra = vec![
            ("Vary".to_string(), "Accept".to_string()),
            (
                "Cache-Control".to_string(),
                "public, max-age=300".to_string(),
            ),
        ];
        let mut ok: Response = Response::new(Body::Empty);
        *ok.status_mut() = StatusCode::OK;
        apply_static_context_headers(&extra, &mut ok);
        assert_eq!(ok.headers().get("vary").unwrap(), "Accept");
        assert_eq!(
            ok.headers().get("cache-control").unwrap(),
            "public, max-age=300"
        );

        // Not applied on a non-2xx response.
        let mut err: Response = Response::new(Body::Empty);
        *err.status_mut() = StatusCode::NOT_FOUND;
        apply_static_context_headers(&extra, &mut err);
        assert!(!err.headers().contains_key("vary"));
    }

    // Regression: a small buffered backend (LSAPI/proxy) error returns a non-empty
    // `Body::Full` — the SAME variant as httpjet's built-in error page. The
    // `ErrorDocument` body-swap must key on the generated-page tag, not the variant,
    // or it clobbers an app's own 4xx body (e.g. chat.php's captcha-gate 403 JSON).
    #[test]
    fn errordocument_guard_preserves_backend_body_but_replaces_generated() {
        // App-produced 403 with a real JSON body (the chat.php captcha case): an
        // untagged Body::Full. Must NOT be treated as a generated error page.
        let mut backend: Response = Response::new(Body::Full(bytes::Bytes::from_static(
            b"{\"captcha_required\":true}",
        )));
        *backend.status_mut() = StatusCode::FORBIDDEN;
        assert!(
            !is_generated_error_body(&backend),
            "a backend's own non-empty body must be preserved, not swapped for the ErrorDocument"
        );

        // httpjet's own built-in error page (also a non-empty Body::Full) IS tagged
        // and remains eligible for the ErrorDocument swap.
        let generated = error_page(StatusCode::FORBIDDEN);
        assert!(matches!(generated.body(), Body::Full(_)));
        assert!(is_generated_error_body(&generated));

        // An empty-bodied error carries nothing to preserve: still replaceable.
        let mut empty: Response = Response::new(Body::Empty);
        *empty.status_mut() = StatusCode::NOT_FOUND;
        assert!(is_generated_error_body(&empty));
    }

    #[test]
    fn cache_identity_uses_canonical_orig_path_for_encoding_variants() {
        // (#6) The page-cache identity guard is now built from the canonical `orig_path`
        // (decoded + normalized), the SAME path that feeds the cache key — not the raw
        // `req.uri().path()`. So two encoding-variants of one URL produce the SAME identity
        // (a HIT, no overwrite cycle), while genuinely different pages still differ.
        use super::super::rewrite_glue::{decode_request_path, normalized_request_path};
        let canon = |raw: &str| {
            let decoded = decode_request_path(raw).expect("decodable");
            normalized_request_path(&decoded)
        };
        let identity = |raw: &str| cache_identity_for(true, "v", &canon(raw));

        // /index.php vs /index%2Ephp -> same canonical path -> same identity.
        assert_eq!(identity("/index.php"), identity("/index%2Ephp"));
        // /foo bar vs /foo%20bar -> same identity (CF doesn't always normalize %20).
        assert_eq!(identity("/foo%20bar"), identity("/foo bar"));
        // A genuinely different page still yields a different identity (guard preserved).
        assert_ne!(identity("/index.php"), identity("/about.php"));
    }

    #[test]
    fn cache_identity_collapses_host_variants_and_excludes_raw_host() {
        // (#5/#20) The identity is keyed by the canonical vhost name + path, never the raw
        // Host header. Two requests to the same vhost with different Host values share ONE
        // identity (a HIT — no re-render thrash, no false collision-guard warnings), while
        // a different vhost, path, or scheme still differs (collision guard preserved).
        let base = cache_identity_for(true, "forum.example", "/threads/1");
        assert_eq!(
            base,
            cache_identity_for(true, "forum.example", "/threads/1")
        );
        // The raw Host never leaks into the identity (it isn't even an input here).
        assert!(!base.contains("evil.example"));
        // Distinct vhost / path / scheme each yield a distinct identity.
        assert_ne!(
            base,
            cache_identity_for(true, "news.forum.example", "/threads/1")
        );
        assert_ne!(
            base,
            cache_identity_for(true, "forum.example", "/threads/2")
        );
        assert_ne!(
            base,
            cache_identity_for(false, "forum.example", "/threads/1")
        );
    }
}
