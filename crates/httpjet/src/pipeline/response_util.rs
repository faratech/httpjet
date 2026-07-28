//! Response construction + `.htaccess` error-document handling (#8a) and the
//! static-context header application (#9b), plus the small redirect/status
//! builders and the page-cache collision-guard identity helper.

use std::path::Path;
use std::sync::Arc;

use hj_core::{Body, ReqCtx, Request, Response};
use hj_lsapi::LsapiScript;
use hj_rewrite::{ErrorDoc, Htaccess};
use http::StatusCode;

use crate::state::ServerState;

use super::rewrite_glue::{build_uri, percent_encode_path, resolved_rel_path};
use super::{
    GeneratedErrorPage, effective_php_suffixes, error_page, resolve_vhost_jail, run_handler,
};

/// (#8a) If the response is an httpjet-generated 4xx/5xx, replace it with the
/// chain's `ErrorDocument` for that status: inline message, local file body, or
/// an external redirect. An upstream (proxy/LSAPI) error is left untouched —
/// detected by the presence of a non-empty body produced by the handler.
///
/// (#3) A `Path` whose suffix is a configured PHP suffix is an internal LSAPI
/// subrequest that RUNS the script (Apache/LiteSpeed parity), NOT a raw file
/// read — serving the unexecuted source would leak it (e.g. `/web/news/404.php`).
/// A non-PHP file is read off the async runtime via `spawn_blocking`.
pub(super) async fn apply_error_document(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
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
            let rel = resolved_rel_path(&p);
            let abs = ctx.vhost.doc_root.join(rel.trim_start_matches('/'));

            // (#3) A PHP-suffixed error document must be EXECUTED, never served
            // as source. Re-dispatch it as an internal LSAPI subrequest.
            if is_php_error_doc(state, ctx, &abs) {
                let Some(target) = super::allowed_script_target(&state.acl, &abs) else {
                    return;
                };
                if let Some(rendered) =
                    run_php_error_document(state, ctx, &target, &rel, cur_path, status).await
                {
                    *resp = rendered;
                }
                // On failure (PHP disabled / pool down / jail unsafe) keep the
                // built-in error page — we must NOT fall back to reading source.
                return;
            }

            // (#4) Non-PHP local file: serve it THROUGH the static handler — which
            // resolves it symlink-safe and confined beneath the docroot (open_beneath
            // / RESOLVE_BENEATH, plus its content-type detection) — rather than a raw
            // `std::fs::read` of a joined path that bypasses those guards. A GET
            // subrequest at the error-doc path; substitute only a successfully-served
            // body, with the original error status preserved. A missing/forbidden doc
            // (non-2xx) leaves the built-in error page in place.
            let keep = resp.status();
            let mut subreq: Request = Request::new(hj_core::empty_incoming());
            if let Some(uri) = build_uri(&percent_encode_path(&rel), "") {
                *subreq.uri_mut() = uri;
            }
            let mut served = run_handler(&state.static_handler, ctx, subreq).await;
            if served.status().is_success()
                && !super::resolved_static_target_denied(&state.acl, &served)
            {
                *served.status_mut() = keep;
                *resp = served;
            }
        }
    }
}

/// Whether `abs` (an `ErrorDocument` target) is a PHP script for this vhost: it
/// has a configured PHP suffix and LSAPI is enabled. Such an error document must
/// be executed, not read (#3).
fn is_php_error_doc(state: &ServerState, ctx: &ReqCtx, abs: &Path) -> bool {
    if state.lsapi.is_none() {
        return false;
    }
    let enable_script = state
        .server
        .vhosts
        .get(&ctx.vhost_name)
        .map(|d| d.enable_script)
        .unwrap_or(true);
    if !enable_script {
        return false;
    }
    match abs.extension().and_then(|e| e.to_str()) {
        Some(ext) => effective_php_suffixes(state, ctx).contains(&ext.to_ascii_lowercase()),
        None => false,
    }
}

/// (#3) Run a PHP `ErrorDocument` as an internal LSAPI subrequest and return the
/// rendered response with the original error `status` preserved. Returns `None`
/// if PHP is unavailable for the vhost (caller keeps the built-in error page;
/// it must never fall back to serving the raw `.php` source).
///
/// The subrequest is a GET at the error-doc path with the standard Apache/CGI
/// error-handler env: `REDIRECT_STATUS` (the original code, e.g. `404`) and
/// `REDIRECT_URL` (the original request path) so the PHP page can detect it is
/// an error subrequest.
async fn run_php_error_document(
    state: &Arc<ServerState>,
    ctx: &mut ReqCtx,
    script_abs: &Path,
    script_rel: &str,
    orig_request_path: &str,
    status: u16,
) -> Option<Response> {
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

    // Build the internal subrequest: GET <error-doc path>, no body.
    let mut subreq: Request = Request::new(hj_core::empty_incoming());
    if let Some(uri) = build_uri(&percent_encode_path(script_rel), "") {
        *subreq.uri_mut() = uri;
    }
    subreq.extensions_mut().insert(LsapiScript {
        script: script_abs.to_path_buf(),
        script_name: Some(script_rel.to_string()),
        path_info: None,
        // Error-document subrequests carry no `.htaccess` php.ini overrides.
        special_env: Vec::new(),
    });

    // Apache error-handler CGI env, read by the LSAPI env builder so the PHP
    // page can tell it is an error subrequest. `set_env` overwrites in place; this
    // is the terminal response path, so the mutation cannot affect a later stage.
    ctx.set_env("REDIRECT_STATUS", status.to_string());
    ctx.set_env("REDIRECT_URL", orig_request_path.to_string());

    let mut rendered = run_handler(lsapi.as_ref(), ctx, subreq).await;
    // Preserve the original error status (a PHP error page typically emits 200).
    if let Ok(keep) = StatusCode::from_u16(status) {
        *rendered.status_mut() = keep;
    }
    Some(rendered)
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
    chain: &[Arc<Htaccess>],
    cur_path: &str,
    status: StatusCode,
) -> Response {
    let mut resp = error_page(status);
    apply_error_document(state, ctx, chain, cur_path, &mut resp).await;
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
