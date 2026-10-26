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

use super::htaccess_apply::{
    access_denied_iter, apply_response_headers_for_target, apply_set_env_iter_with_headers,
};
use super::rewrite_glue::{
    build_uri, normalized_request_path, percent_encode_path, resolved_rel_path,
};
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
        // A deeper `ErrorDocument N default` restores the built-in page.
        ErrorDoc::Default => {}
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
    let has_set_env = target_chain().any(|ht| !ht.set_env_if.is_empty() || ht.has_set_env());
    let has_rewrite = state
        .inline_rules
        .get(&ctx.vhost_name)
        .is_some_and(|rules| !rules.is_noop())
        || target_chain_with_dirs
            .iter()
            .any(|(_, ht)| !ht.rules.is_noop());
    if has_set_env {
        apply_set_env_iter_with_headers(ctx, target_chain(), "GET", request_headers, rel, "", None)
            .ok()?;
    }

    // An `allowBrowse 0` context is not accessible to the error page either (#814).
    if access_denied_iter(target_chain(), rel, "GET", ctx)
        || super::access_deny_dir(&state.acl, &ctx.vhost.doc_root, rel)
        || context_refusal(&ctx.vhost.contexts, rel).is_some()
    {
        return None;
    }
    let mut authenticated = Vec::new();
    super::scoped_auth::enforce_chain_iter(
        state,
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
            &mut super::rewrite_glue::RewriteTrace::default(),
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
        .find_map(|(_, ht)| ht.directory_index_override())
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
                super::ResourceRequest {
                    method: "GET",
                    headers: request_headers,
                    query: "",
                },
                &target,
                rel,
                &mut authenticated,
            )
            .await
            .ok()?;
        }
        let (subreq, orig_query) =
            script_error_document_request(ctx, request_headers, &script_name);
        return run_script_error_document(
            state,
            ctx,
            subreq,
            &target,
            &script_name,
            &path_info,
            fastcgi_handler.as_deref(),
            orig_request_path,
            orig_query.as_deref(),
            status,
        )
        .await;
    }

    let mut subreq = internal_error_document_request(rel);
    // Map the target exactly as dispatch's static path would (#815): a location
    // override context serves the error page from its own root.
    apply_static_context_request(ctx, rel, &mut subreq);
    if let Some(index_files) = target_chain_with_dirs
        .iter()
        .rev()
        .find_map(|(_, ht)| ht.directory_index_override())
    {
        subreq
            .extensions_mut()
            .insert(hj_static::IndexFilesOverride(index_files.to_vec()));
    }
    if target_chain().any(|ht| ht.has_type_override) {
        let chain: Vec<Arc<Htaccess>> = target_chain_with_dirs
            .iter()
            .map(|(_, ht)| ht.clone())
            .collect();
        super::apply_content_type_override(&chain, rel, &mut subreq);
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
                super::ResourceRequest {
                    method: "GET",
                    headers: request_headers,
                    query: "",
                },
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
/// The subrequest is a bodyless GET carrying the original request headers and
/// `REQUEST_URI` (LSWS `getOrgReqURL`), with the standard Apache/CGI
/// error-handler env: `REDIRECT_STATUS` (the original code, e.g. `404`),
/// `REDIRECT_URL` (the original request path) and `REDIRECT_QUERY_STRING`, so
/// the PHP page can detect it is an error subrequest. `QUERY_STRING` is the
/// error document's own (empty).
async fn run_script_error_document(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
    mut subreq: Request,
    script_abs: &Path,
    script_rel: &str,
    path_info: &str,
    fastcgi_handler: Option<&str>,
    orig_request_path: &str,
    orig_query: Option<&str>,
    status: u16,
) -> Option<Response> {
    // Apache error-handler CGI env, read by the LSAPI env builder so the PHP
    // page can tell it is an error subrequest. This runs in an isolated cloned
    // context, so none of these values leak back to the outer request.
    ctx.set_env("REDIRECT_STATUS", status.to_string());
    ctx.set_env("REDIRECT_URL", orig_request_path.to_string());
    if let Some(query) = orig_query.filter(|q| !q.is_empty()) {
        ctx.set_env("REDIRECT_QUERY_STRING", query.to_string());
    }
    // The subrequest URI is the original request's (it is REQUEST_URI), so its
    // query would otherwise become the error document's QUERY_STRING.
    ctx.set_env("QUERY_STRING", String::new());

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
        forwarding_trusted: ctx.forwarding_trusted,
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

/// Request headers that describe the original request BODY. The error
/// subrequest never resends that body, so they must not reach the backend
/// (a stale `Content-Length` would have PHP wait for bytes that never come).
fn is_body_framing_header(name: &http::HeaderName) -> bool {
    matches!(
        *name,
        http::header::CONTENT_LENGTH
            | http::header::TRANSFER_ENCODING
            | http::header::CONTENT_TYPE
            | http::header::CONTENT_ENCODING
            | http::header::EXPECT
    )
}

/// The script ErrorDocument subrequest (#948). LSWS runs the error page as an
/// internal redirect of the SAME request: it keeps the inbound headers (Cookie,
/// User-Agent, Accept-Language, ...) and `REQUEST_URI` is the original request
/// URI. The method becomes a bodyless GET, so the body framing headers go.
/// Returns the request plus the original query for `REDIRECT_QUERY_STRING`.
fn script_error_document_request(
    ctx: &ReqCtx,
    request_headers: &http::HeaderMap,
    script_name: &str,
) -> (Request, Option<String>) {
    let original = ctx
        .redirect_guard
        .as_ref()
        .and_then(|guard| guard.path_query())
        .and_then(|pq| pq.parse::<http::Uri>().ok().map(|uri| (uri, pq)));
    let (mut request, query) = match original {
        Some((uri, pq)) => {
            let mut request = Request::new(hj_core::empty_incoming());
            *request.uri_mut() = uri;
            let query = pq.split_once('?').map(|(_, q)| q.to_string());
            (request, query)
        }
        None => (internal_error_document_request(script_name), None),
    };
    let headers = request.headers_mut();
    headers.reserve(request_headers.len());
    for (name, value) in request_headers {
        if !is_body_framing_header(name) {
            headers.append(name.clone(), value.clone());
        }
    }
    (request, query)
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
/// `request_path` is the original request path that `Header` URI tests read.
pub(super) async fn error_doc_or_page(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
    request_headers: &http::HeaderMap,
    chain: &[Arc<Htaccess>],
    cur_path: &str,
    request_path: &str,
    status: StatusCode,
) -> Response {
    let mut resp = error_page(status);
    apply_error_document(state, ctx, request_headers, chain, cur_path, &mut resp).await;
    let rel = resolved_rel_path(cur_path);
    apply_error_response_headers(ctx, chain, &rel, None, request_path, status, &mut resp);
    resp
}

/// Finish an auth refusal (`scoped_auth` 401/403/500/503) like any other
/// generated error: `ErrorDocument` replacement plus the `always` header ops.
/// The challenge (`WWW-Authenticate`) and `Retry-After` survive a local
/// replacement page; a 401 never follows an external ErrorDocument (Apache
/// ignores a URL there, since the browser would never see the challenge).
pub(super) async fn auth_refusal(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
    request_headers: &http::HeaderMap,
    chain: &[Arc<Htaccess>],
    cur_path: &str,
    request_path: &str,
    mut resp: Response,
) -> Response {
    let status = resp.status();
    let challenge = resp.headers().get(http::header::WWW_AUTHENTICATE).cloned();
    let retry_after = resp.headers().get(http::header::RETRY_AFTER).cloned();
    let skip_doc = status == StatusCode::UNAUTHORIZED
        && chain
            .iter()
            .rev()
            .find_map(|ht| ht.error_document(status.as_u16()))
            .is_some_and(|doc| matches!(doc, ErrorDoc::External(_)));
    if !skip_doc {
        apply_error_document(state, ctx, request_headers, chain, cur_path, &mut resp).await;
    }
    if resp.status() == status {
        let headers = resp.headers_mut();
        if let Some(v) = challenge {
            headers.insert(http::header::WWW_AUTHENTICATE, v);
        }
        if let Some(v) = retry_after {
            headers.insert(http::header::RETRY_AFTER, v);
        }
    }
    let rel = resolved_rel_path(cur_path);
    apply_error_response_headers(ctx, chain, &rel, None, request_path, status, &mut resp);
    resp
}

/// Apply the chain's `Header` ops as they apply to an error of `status`, even
/// when an external ErrorDocument turned the response into a 302: like Apache's
/// `ap_send_error_response`, only `always` (err_headers_out) ops survive there.
pub(super) fn apply_error_response_headers(
    ctx: &ReqCtx,
    chain: &[Arc<Htaccess>],
    rel_path: &str,
    target_basename: Option<&str>,
    request_path: &str,
    status: StatusCode,
    resp: &mut Response,
) {
    let served = std::mem::replace(resp.status_mut(), status);
    apply_response_headers_for_target(ctx, chain, rel_path, target_basename, request_path, resp);
    *resp.status_mut() = served;
}

/// A bare status response (no body) for a non-3xx `[R=NNN]` outcome (#8/A).
pub(super) fn status_response(code: u16) -> Response {
    let status = StatusCode::from_u16(code)
        .ok()
        .filter(|s| !s.is_informational())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = Response::new(Body::Empty);
    *resp.status_mut() = status;
    resp
}

/// (#9b) The single most-specific enabled **static** `<context>` for `path`.
/// Selection never looks at what the context configures (#815): like OLS, a
/// context without `<location>` serves `$DOC_ROOT + uri`, so a plain nested
/// context must NOT fall through to its parent's location. dispatch, fast_serve
/// and scoped_auth all resolve through this one selector (#673).
pub(super) fn matching_static_context<'a>(
    ctx: &'a ReqCtx,
    path: &str,
) -> Option<&'a hj_core::config::Context> {
    enclosing_static_contexts(&ctx.vhost.contexts, path)
        .last()
        .copied()
}

/// Every enabled static context enclosing `path`, outermost first.
fn enclosing_static_contexts<'a>(
    contexts: &'a [hj_core::config::Context],
    path: &str,
) -> Vec<&'a hj_core::config::Context> {
    use hj_core::config::ContextKind;
    let mut contexts: Vec<_> = contexts
        .iter()
        .filter(|c| {
            c.kind == ContextKind::Static && c.enabled && super::context_uri_matches(path, &c.uri)
        })
        .collect();
    contexts.sort_by_key(|c| c.uri.len());
    contexts
}

/// The `<extraHeaders>` that apply to `path`: every enclosing static context's,
/// outermost to innermost, as OLS `HttpContext::inherit` prepends the parent's
/// header ops to the child's (#816). Feed the result to
/// [`apply_static_context_headers`] in one call.
pub(super) fn static_context_extra_headers(ctx: &ReqCtx, path: &str) -> Vec<(String, String)> {
    inherited_extra_headers(enclosing_static_contexts(&ctx.vhost.contexts, path))
}

/// The enclosing contexts' extra headers, outermost first; a context set to
/// `NONE` drops what it would have inherited.
fn inherited_extra_headers<'a>(
    enclosing: impl IntoIterator<Item = &'a hj_core::config::Context>,
) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for c in enclosing {
        if !c.inherit_extra_headers {
            headers.clear();
        }
        headers.extend(c.extra_headers.iter().cloned());
    }
    headers
}

/// The effective `addDefaultCharset` for `path`: the innermost enclosing static
/// context that SETS it wins, and a context leaving it absent inherits its
/// parent's (OLS `HttpContext::inherit` copies the parent charset unless the
/// child configured its own, #828). `None` = off.
pub(super) fn static_context_charset(ctx: &ReqCtx, path: &str) -> Option<String> {
    enclosing_static_charset(&ctx.vhost.contexts, path)
}

fn enclosing_static_charset(contexts: &[hj_core::config::Context], path: &str) -> Option<String> {
    let context = enclosing_static_contexts(contexts, path)
        .into_iter()
        .rev()
        .find(|c| c.add_default_charset.is_some())?;
    (context.add_default_charset == Some(true)).then(|| {
        context
            .charset
            .clone()
            .unwrap_or_else(|| "UTF-8".to_string())
    })
}

/// The `<location>` mapping the static handler must apply for `path`: the
/// selected context's location and URI, whenever it moves the root OR strips a
/// non-root context URI (OLS `translate` maps `/assets/x.css` under a
/// `/assets/` context located at `$DOC_ROOT/` to `$DOC_ROOT/x.css`, #829).
/// dispatch, fast_serve, the ErrorDocument subrequest and scoped_auth share it.
pub(super) fn static_location_override<'a>(
    ctx: &'a ReqCtx,
    path: &str,
) -> Option<(&'a std::path::PathBuf, &'a str)> {
    vhost_static_location_override(&ctx.vhost, path)
}

fn vhost_static_location_override<'a>(
    vhost: &'a hj_core::config::VHostConfig,
    path: &str,
) -> Option<(&'a std::path::PathBuf, &'a str)> {
    let context = enclosing_static_contexts(&vhost.contexts, path)
        .last()
        .copied()?;
    let location = context.location.as_ref()?;
    (*location != vhost.doc_root || !context.uri.trim_matches('/').is_empty())
        .then_some((location, context.uri.as_str()))
}

/// Pin the static `<context>` mapping for `path` onto a static-handler request:
/// the location override and the inherited default charset.
pub(super) fn apply_static_context_request(ctx: &ReqCtx, path: &str, req: &mut Request) {
    if let Some((location, uri)) = static_location_override(ctx, path) {
        req.extensions_mut()
            .insert(hj_static::DocRootOverride(location.clone(), uri.to_owned()));
    }
    if let Some(charset) = static_context_charset(ctx, path) {
        req.extensions_mut()
            .insert(hj_static::DefaultCharsetOverride(charset));
    }
}

/// (#830) OLS `bestMatch` selects a `/docs/` context for the slashless `/docs`
/// (its tree matches by path component) and `redirectDir` answers 301 to
/// `/docs/`. True when `path` is exactly such a trailing-slash context URI
/// minus its slash.
pub(super) fn context_slash_redirect(contexts: &[hj_core::config::Context], path: &str) -> bool {
    // Every other context matching `path` is a strict ancestor of the slashed
    // URI unless one is configured as exactly `path`, which then wins.
    contexts
        .iter()
        .any(|c| c.enabled && c.uri.len() > 1 && c.uri.strip_suffix('/') == Some(path))
        && !contexts.iter().any(|c| c.enabled && c.uri == path)
}

/// OLS resolves ONE most-specific context and refuses the whole request when
/// that static context has `<allowBrowse>0</allowBrowse>` (`processURIEx`).
/// A context kind httpjet does not route (only a hand-built model can carry
/// one; the parser rejects them) fails closed instead of serving as static.
pub(super) fn context_refusal(
    contexts: &[hj_core::config::Context],
    path: &str,
) -> Option<StatusCode> {
    use hj_core::config::ContextKind;
    let context = contexts
        .iter()
        .filter(|c| c.enabled && super::context_uri_matches(path, &c.uri))
        .max_by_key(|c| c.uri.len())?;
    match context.kind {
        ContextKind::Static => (!context.allow_browse).then_some(StatusCode::FORBIDDEN),
        ContextKind::Proxy => None,
        _ => Some(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Apply a static context's `<extraHeaders>` (e.g. mcp's `Vary`/`Cache-Control`)
/// to a 2xx static response. `Vary` merges into the handler's own tokens (a
/// precompressed sibling's `Accept-Encoding` must survive, #801); a repeated
/// name appends, as OLS adds each line; otherwise the context value replaces.
pub(super) fn apply_static_context_headers(extra: &[(String, String)], resp: &mut Response) {
    // A 304 carries the Vary/Cache-Control its 200 would (RFC 9110 §15.4.5, #843).
    if !resp.status().is_success() && resp.status() != http::StatusCode::NOT_MODIFIED {
        return;
    }
    let mut seen: Vec<http::header::HeaderName> = Vec::new();
    for (name, value) in extra {
        let (Ok(n), Ok(v)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) else {
            continue;
        };
        let headers = resp.headers_mut();
        if n == http::header::VARY {
            merge_vary_tokens(headers, value);
        } else if seen.contains(&n) {
            headers.append(n, v);
        } else {
            headers.insert(n.clone(), v);
            seen.push(n);
        }
    }
}

fn merge_vary_tokens(headers: &mut http::HeaderMap, value: &str) {
    let existing: Vec<String> = headers
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    let mut tokens = existing.clone();
    for token in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if !tokens.iter().any(|t| t.eq_ignore_ascii_case(token)) {
            tokens.push(token.to_string());
        }
    }
    if tokens == existing && !existing.is_empty() {
        return;
    }
    if let Ok(v) = http::HeaderValue::from_str(&tokens.join(", ")) {
        headers.insert(http::header::VARY, v);
    }
}

/// Page-cache collision-guard identity: `scheme\nvhost\norig_path`. Built from the
/// canonical, operator-controlled vhost name and the decoded+normalized path — never a
/// wildcard-routed raw Host (which the key collapses, #5) and never the raw request path
/// (encoding variants must share one identity, #6). An exact vhostMap alias (#938, see
/// `lscache::cache_alias_host`) adds an `@alias` line before the path; the path always
/// starts with `/`, so an alias identity never equals a canonical one, and the canonical
/// form is unchanged. A cached entry is served only when a request reproduces this exact
/// string, so a key collision degrades to a miss.
pub(super) fn cache_identity_for(
    is_tls: bool,
    vhost_name: &str,
    alias_host: Option<&str>,
    orig_path: &str,
) -> String {
    let scheme = if is_tls { "https" } else { "http" };
    match alias_host {
        None => format!("{}\n{}\n{}", scheme, vhost_name, orig_path),
        Some(alias) => format!(
            "{}\n{}\n@{}\n{}",
            scheme,
            vhost_name,
            alias.to_ascii_lowercase(),
            orig_path
        ),
    }
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
    fn status_response_never_emits_an_informational_final() {
        assert_eq!(
            status_response(103).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(status_response(410).status(), StatusCode::GONE);
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
        let identity = |raw: &str| cache_identity_for(true, "v", None, &canon(raw));

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
        let base = cache_identity_for(true, "forum.example", None, "/threads/1");
        assert_eq!(
            base,
            cache_identity_for(true, "forum.example", None, "/threads/1")
        );
        // The raw Host never leaks into the identity (it isn't even an input here).
        assert!(!base.contains("evil.example"));
        // Distinct vhost / path / scheme each yield a distinct identity.
        assert_ne!(
            base,
            cache_identity_for(true, "news.forum.example", None, "/threads/1")
        );
        assert_ne!(
            base,
            cache_identity_for(true, "forum.example", None, "/threads/2")
        );
        assert_ne!(
            base,
            cache_identity_for(false, "forum.example", None, "/threads/1")
        );
    }

    /// (#938) The canonical identity bytes are the pre-#938 format, so persisted entries
    /// keep hitting; an exact alias gets a distinct identity that no path can reproduce.
    #[test]
    fn cache_identity_canonical_bytes_are_stable_and_aliases_differ() {
        assert_eq!(
            cache_identity_for(true, "forum.example", None, "/threads/1"),
            "https\nforum.example\n/threads/1"
        );
        assert_eq!(
            cache_identity_for(false, "forum.example", None, "/"),
            "http\nforum.example\n/"
        );
        let alias = cache_identity_for(true, "forum.example", Some("WWW.Forum.Example"), "/");
        assert_eq!(alias, "https\nforum.example\n@www.forum.example\n/");
        assert_ne!(
            alias,
            cache_identity_for(true, "forum.example", Some("alias.example"), "/")
        );
        assert_ne!(alias, cache_identity_for(true, "forum.example", None, "/"));
    }

    fn static_context(
        uri: &str,
        location: Option<&str>,
        extra: &[(&str, &str)],
    ) -> hj_core::config::Context {
        hj_core::config::Context {
            cache_policy: None,
            bandwidth_limit: 0,
            max_body_override: None,
            timeout_override: None,
            sub_filter: None,
            kind: hj_core::config::ContextKind::Static,
            uri: uri.into(),
            location: location.map(Into::into),
            handler: None,
            enabled: true,
            allow_browse: true,
            extra_headers: extra
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            inherit_extra_headers: true,
            add_default_charset: None,
            charset: None,
        }
    }

    #[test]
    fn plain_nested_static_context_is_selected_over_its_parent() {
        // #815: /docs/sub/ configures nothing, yet it is the most specific
        // context, so it must win (serving $DOC_ROOT + uri), not /docs/'s location.
        let contexts = vec![
            static_context("/docs/", Some("/alt"), &[("X-Parent", "p")]),
            static_context("/docs/sub/", None, &[]),
        ];
        let selected = enclosing_static_contexts(&contexts, "/docs/sub/a.txt");
        assert_eq!(selected.last().unwrap().uri, "/docs/sub/");
        assert!(selected.last().unwrap().location.is_none());
        let parent = enclosing_static_contexts(&contexts, "/docs/a.txt");
        assert_eq!(parent.last().unwrap().uri, "/docs/");
    }

    #[test]
    fn extra_headers_none_drops_the_inherited_headers() {
        let mut none = static_context("/docs/", None, &[]);
        none.inherit_extra_headers = false;
        let contexts = vec![
            static_context("/", None, &[("X-Root", "r")]),
            none,
            static_context("/docs/sub/", None, &[("X-Child", "c")]),
        ];
        let names = |path: &str| -> Vec<String> {
            inherited_extra_headers(enclosing_static_contexts(&contexts, path))
                .into_iter()
                .map(|(n, _)| n)
                .collect()
        };
        assert_eq!(names("/x"), ["X-Root"]);
        assert!(names("/docs/a").is_empty());
        assert_eq!(names("/docs/sub/a"), ["X-Child"]);
    }

    #[test]
    fn nested_static_context_headers_inherit_outermost_first() {
        // #816: the parent's header ops come first, then the child's.
        let contexts = vec![
            static_context("/docs/sub/", None, &[("X-Child", "c"), ("Vary", "Origin")]),
            static_context("/", None, &[("X-Root", "r")]),
            static_context("/docs/", None, &[("X-Parent", "p"), ("Vary", "Accept")]),
            static_context("/other/", None, &[("X-Other", "o")]),
        ];
        let extra: Vec<(String, String)> = enclosing_static_contexts(&contexts, "/docs/sub/a")
            .into_iter()
            .flat_map(|c| c.extra_headers.iter().cloned())
            .collect();
        let names: Vec<&str> = extra.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["X-Root", "X-Parent", "Vary", "X-Child", "Vary"]);
        let mut resp: Response = Response::new(Body::Empty);
        apply_static_context_headers(&extra, &mut resp);
        let h = resp.headers();
        assert_eq!(h["x-root"], "r");
        assert_eq!(h["x-parent"], "p");
        assert_eq!(h["x-child"], "c");
        assert_eq!(h[http::header::VARY], "Accept, Origin");
        assert!(!h.contains_key("x-other"));
    }

    /// Prod safety (#815/#816): the live config's static contexts are not nested,
    /// so selection and headers match the pre-fix selector exactly.
    #[test]
    fn live_config_static_context_selection_is_unchanged() {
        use hj_core::config::ContextKind;
        let root = std::path::Path::new("/usr/local/lsws");
        if !root.join("conf/httpd_config.xml").is_file() {
            return;
        }
        let cfg = hj_config::load(root).expect("the live config must load");
        let mut mcp_checked = false;
        for decl in cfg.vhosts.values() {
            let Some(vhost) = decl.config.as_ref() else {
                continue;
            };
            let probes = [
                "/",
                "/index.html",
                "/a/b/c.json",
                "/play",
                "/api/x",
                "/static/x.js",
            ];
            for path in probes {
                let legacy = vhost
                    .contexts
                    .iter()
                    .filter(|c| {
                        c.kind == ContextKind::Static
                            && c.enabled
                            && super::super::context_uri_matches(path, &c.uri)
                    })
                    .filter(|c| {
                        !c.extra_headers.is_empty()
                            || c.location.is_some()
                            || c.add_default_charset == Some(true)
                    })
                    .max_by_key(|c| c.uri.len());
                let enclosing = enclosing_static_contexts(&vhost.contexts, path);
                let selected = enclosing.last().copied();
                assert_eq!(
                    selected.map(|c| (&c.uri, &c.location)),
                    legacy.map(|c| (&c.uri, &c.location)),
                    "{} {path}",
                    decl.name
                );
                let extra: Vec<(String, String)> = enclosing
                    .iter()
                    .flat_map(|c| c.extra_headers.iter().cloned())
                    .collect();
                assert_eq!(
                    extra,
                    legacy.map(|c| c.extra_headers.clone()).unwrap_or_default(),
                    "{} {path}",
                    decl.name
                );
                // (#828) Inherited charset == the legacy single-context charset.
                let legacy_charset = legacy
                    .filter(|c| c.add_default_charset == Some(true))
                    .map(|c| c.charset.clone().unwrap_or_else(|| "UTF-8".to_string()));
                assert_eq!(
                    enclosing_static_charset(&vhost.contexts, path),
                    legacy_charset,
                    "{} {path}",
                    decl.name
                );
                // (#829) The location mapping == the legacy `loc != doc_root` rule.
                let legacy_location = legacy
                    .and_then(|c| c.location.as_ref().map(|loc| (loc, c.uri.as_str())))
                    .filter(|(loc, _)| **loc != vhost.doc_root);
                assert_eq!(
                    vhost_static_location_override(vhost, path),
                    legacy_location,
                    "{} {path}",
                    decl.name
                );
            }
            // (#830) No live context URI ends in `/` except the root, so no
            // live request is ever answered by the slash redirect.
            for c in &vhost.contexts {
                assert!(
                    c.uri == "/" || !c.uri.ends_with('/'),
                    "{} live context {} ends in a slash",
                    decl.name,
                    c.uri
                );
                for path in [c.uri.as_str(), c.uri.trim_end_matches('/')]
                    .into_iter()
                    .chain(probes)
                {
                    assert!(
                        !context_slash_redirect(&vhost.contexts, path),
                        "{} {path}",
                        decl.name
                    );
                }
            }
            if decl.name == "mcp.windowsforum.com" {
                let selected = enclosing_static_contexts(&vhost.contexts, "/a/b/c.json");
                let c = selected.last().expect("mcp static context");
                assert_eq!(c.uri, "/");
                assert_eq!(
                    c.location.as_deref(),
                    Some(std::path::Path::new("/web/mcp-static/"))
                );
                assert_eq!(
                    c.extra_headers,
                    vec![
                        ("Vary".to_string(), "Accept".to_string()),
                        (
                            "Cache-Control".to_string(),
                            "public, max-age=300".to_string()
                        ),
                    ]
                );
                mcp_checked = true;
            }
        }
        assert!(mcp_checked, "live config lost the mcp static context");
    }

    fn charset_context(
        uri: &str,
        location: Option<&str>,
        charset: Option<bool>,
        custom: Option<&str>,
    ) -> hj_core::config::Context {
        hj_core::config::Context {
            kind: hj_core::config::ContextKind::Static,
            uri: uri.into(),
            location: location.map(std::path::PathBuf::from),
            handler: None,
            enabled: true,
            allow_browse: true,
            extra_headers: vec![],
            inherit_extra_headers: true,
            add_default_charset: charset,
            charset: custom.map(str::to_owned),
            cache_policy: None,
            max_body_override: None,
            bandwidth_limit: 0,
            timeout_override: None,
            sub_filter: None,
        }
    }

    #[test]
    fn nested_static_context_inherits_the_innermost_set_charset() {
        // #828: OLS HttpContext::inherit copies the parent's charset unless the
        // child configures addDefaultCharset itself.
        let parent = charset_context("/assets/", None, Some(true), Some("ISO-8859-1"));
        let inherit = [
            parent.clone(),
            charset_context("/assets/img/", None, None, None),
        ];
        assert_eq!(
            enclosing_static_charset(&inherit, "/assets/img/x.png").as_deref(),
            Some("ISO-8859-1")
        );
        let off = [
            parent.clone(),
            charset_context("/assets/img/", None, Some(false), None),
        ];
        assert_eq!(enclosing_static_charset(&off, "/assets/img/x.png"), None);
        assert_eq!(
            enclosing_static_charset(&off, "/assets/x.css").as_deref(),
            Some("ISO-8859-1")
        );
        let own = [
            parent,
            charset_context("/assets/img/", None, Some(true), None),
        ];
        assert_eq!(
            enclosing_static_charset(&own, "/assets/img/x.png").as_deref(),
            Some("UTF-8")
        );
        let unset = [charset_context("/assets/", None, None, Some("ISO-8859-1"))];
        assert_eq!(enclosing_static_charset(&unset, "/assets/x.css"), None);
    }

    #[test]
    fn slashless_context_uri_redirect_selection() {
        let docs = charset_context("/docs/", None, None, None);
        let contexts = [charset_context("/", None, None, None), docs.clone()];
        assert!(context_slash_redirect(&contexts, "/docs"));
        assert!(!context_slash_redirect(&contexts, "/docs/"));
        assert!(!context_slash_redirect(&contexts, "/docs/x"));
        assert!(!context_slash_redirect(&contexts, "/doc"));
        assert!(!context_slash_redirect(&contexts, ""));
        let exact = [charset_context("/docs", None, None, None), docs.clone()];
        assert!(
            !context_slash_redirect(&exact, "/docs"),
            "an exact slashless context is selected instead"
        );
        let mut disabled = docs;
        disabled.enabled = false;
        assert!(!context_slash_redirect(&[disabled], "/docs"));
    }

    #[test]
    fn docroot_located_static_context_still_strips_its_uri() {
        // #829: OLS translate strips the context URI whenever the context has a
        // location, even one equal to $DOC_ROOT.
        let vhost = |contexts| hj_core::config::VHostConfig {
            doc_root: "/srv/www/".into(),
            contexts,
            ..Default::default()
        };
        let stripped = vhost(vec![charset_context(
            "/assets/",
            Some("/srv/www/"),
            None,
            None,
        )]);
        assert_eq!(
            vhost_static_location_override(&stripped, "/assets/x.css"),
            Some((&std::path::PathBuf::from("/srv/www/"), "/assets/"))
        );
        let root = vhost(vec![charset_context("/", Some("/srv/www/"), None, None)]);
        assert_eq!(vhost_static_location_override(&root, "/x.css"), None);
        let moved = vhost(vec![charset_context("/", Some("/srv/other/"), None, None)]);
        assert!(vhost_static_location_override(&moved, "/x.css").is_some());
        let plain = vhost(vec![charset_context("/assets/", None, None, None)]);
        assert_eq!(
            vhost_static_location_override(&plain, "/assets/x.css"),
            None
        );
        assert_eq!(
            hj_static::context_relative_path(std::path::Path::new("assets/x.css"), "/assets/"),
            std::path::Path::new("x.css")
        );
    }

    #[test]
    fn static_context_headers_merge_vary_and_append_repeats() {
        // #801: a precompressed sibling's Vary: Accept-Encoding must survive.
        let mut resp = http::Response::new(hj_core::Body::Empty);
        resp.headers_mut()
            .insert(http::header::VARY, "Accept-Encoding".parse().unwrap());
        resp.headers_mut()
            .insert(http::header::CACHE_CONTROL, "no-cache".parse().unwrap());
        let extra = vec![
            ("Vary".to_string(), "Accept".to_string()),
            (
                "Cache-Control".to_string(),
                "public, max-age=300".to_string(),
            ),
            ("Link".to_string(), "</a.css>; rel=preload".to_string()),
            ("Link".to_string(), "</b.js>; rel=preload".to_string()),
        ];
        super::apply_static_context_headers(&extra, &mut resp);
        let h = resp.headers();
        assert_eq!(h[http::header::VARY], "Accept-Encoding, Accept");
        assert_eq!(h[http::header::CACHE_CONTROL], "public, max-age=300");
        assert_eq!(h.get_all(http::header::LINK).iter().count(), 2);

        let mut bare = http::Response::new(hj_core::Body::Empty);
        super::apply_static_context_headers(&extra[..1], &mut bare);
        assert_eq!(bare.headers()[http::header::VARY], "Accept");
    }
}
