//! One auth boundary shared by requested, rewritten, and filesystem resources.

use super::*;
use hj_rewrite::AuthRealm;

pub(super) async fn enforce_chain(
    ctx: &mut ReqCtx,
    headers: &http::HeaderMap,
    chain: &[Arc<Htaccess>],
    path: &str,
    request_path: &str,
    authenticated: &mut Vec<AuthRealm>,
) -> Result<(), Response> {
    if !chain.iter().any(|ht| ht.has_auth()) {
        return Ok(());
    }
    let filesystem_path = ctx.vhost.doc_root.join(path.trim_start_matches('/'));
    let realm = match hj_rewrite::resolve_auth_for_request(
        chain.iter().map(AsRef::as_ref),
        path,
        request_path,
        Some(filesystem_path.to_string_lossy().as_ref()),
    ) {
        Ok(None) => return Ok(()),
        Ok(Some(realm)) => realm,
        Err(_) => return Err(error_page(StatusCode::FORBIDDEN)),
    };
    if authenticated.contains(&realm) {
        return Ok(());
    }
    let credentials = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .and_then(|(_, value)| hj_rewrite::auth::decode_basic_credentials(value));
    if let Some((user, password)) = credentials {
        if realm.user_satisfies(&user) {
            let file = if realm.user_file.is_absolute() {
                realm.user_file.clone()
            } else {
                ctx.vhost.doc_root.join(&realm.user_file)
            };
            let checked_user = user.clone();
            let valid = tokio::task::spawn_blocking(move || {
                hj_rewrite::auth::verify_credentials(&file, &checked_user, &password)
            })
            .await
            .unwrap_or(false);
            if valid {
                ctx.set_env("REMOTE_USER", user);
                authenticated.push(realm);
                return Ok(());
            }
        }
    }
    let mut response = error_page(StatusCode::UNAUTHORIZED);
    if let Ok(value) = http::HeaderValue::from_str(&realm.challenge()) {
        response
            .headers_mut()
            .insert(http::header::WWW_AUTHENTICATE, value);
    }
    Err(response)
}

async fn enforce_resource(
    state: &ServerState,
    ctx: &mut ReqCtx,
    headers: &http::HeaderMap,
    path: &str,
    request_path: &str,
    authenticated: &mut Vec<AuthRealm>,
) -> Result<(), Response> {
    if !ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess)
    {
        return Ok(());
    }
    let chain: Vec<_> = state
        .rewrite_cache
        .load_chain_with_dirs(
            &ctx.vhost.doc_root,
            path,
            ctx.vhost.access_file_name_or_default(),
        )
        .into_iter()
        .map(|(_, ht)| ht)
        .collect();
    // Preserve the loader's deny-all sentinel when malformed auth could not
    // produce an AuthPolicy, as well as the resource's ordinary host ACLs.
    if access_denied(&chain, path, "GET", ctx) {
        return Err(error_page(StatusCode::FORBIDDEN));
    }
    enforce_chain(ctx, headers, &chain, path, request_path, authenticated).await
}

pub(super) async fn enforce_target(
    state: &ServerState,
    ctx: &mut ReqCtx,
    headers: &http::HeaderMap,
    target: &Path,
    request_path: &str,
    authenticated: &mut Vec<AuthRealm>,
) -> Result<(), Response> {
    if let Ok(relative) = target.strip_prefix(&ctx.vhost.doc_root) {
        let path = format!("/{}", relative.to_string_lossy());
        enforce_resource(state, ctx, headers, &path, request_path, authenticated).await?;
    }
    Ok(())
}

fn static_candidates(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    chain: &[Arc<Htaccess>],
) -> Vec<(String, PathBuf)> {
    let root = matching_static_context(ctx, path)
        .and_then(|c| c.location.as_ref())
        .unwrap_or(&ctx.vhost.doc_root);
    let lexical = root.join(path.trim_start_matches('/'));
    if path.ends_with('/') && lexical.is_dir() {
        for index in effective_index_files(state, ctx, chain) {
            let candidate = lexical.join(index);
            if hj_static::safe_index_name(index) && candidate.is_file() {
                return vec![(format!("{path}{index}"), candidate)];
            }
        }
        Vec::new()
    } else {
        vec![(path.to_owned(), lexical)]
    }
}

fn aliases_possible(ctx: &ReqCtx, path: &str) -> bool {
    ctx.vhost.allow_symbol_link
        || matching_static_context(ctx, path)
            .and_then(|c| c.location.as_ref())
            .is_some_and(|p| p != &ctx.vhost.doc_root)
}

/// On-core cache/static serving cannot authenticate. Discover a mapped target's
/// auth policy before either cache branch, then bridge to the shared enforcer.
/// Runs after the existing finished-memo probe (its normal one-second TTL).
pub(super) fn target_has_auth(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    chain: &[Arc<Htaccess>],
) -> bool {
    if !ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess)
        || !aliases_possible(ctx, path)
    {
        return false;
    }
    let indexes = effective_index_files(state, ctx, chain);
    let candidates =
        if let Some((script, _, _)) = split_script_path(state, ctx, path, indexes, chain) {
            vec![(path.to_owned(), script)]
        } else {
            static_candidates(state, ctx, path, chain)
        };
    candidates.into_iter().any(|(_, lexical)| {
        let Ok(target) = opened_target_path(&lexical) else {
            return false;
        };
        let Ok(rel) = target.strip_prefix(&ctx.vhost.doc_root) else {
            return false;
        };
        let resource = format!("/{}", rel.to_string_lossy());
        let chain: Vec<_> = state
            .rewrite_cache
            .load_chain_with_dirs(
                &ctx.vhost.doc_root,
                &resource,
                ctx.vhost.access_file_name_or_default(),
            )
            .into_iter()
            .map(|(_, ht)| ht)
            .collect();
        chain.iter().any(|ht| ht.has_auth()) || access_denied(&chain, &resource, "GET", ctx)
    })
}

/// Prefer the opened inode over a lexical target hint for the final backstop.
pub(super) fn served_target(response: &Response) -> Option<PathBuf> {
    if let Body::File(file) = response.body() {
        if let Some(opened) = &file.file {
            use std::os::fd::AsRawFd;
            if let Ok(path) = std::fs::read_link(format!("/proc/self/fd/{}", opened.as_raw_fd())) {
                return Some(path);
            }
        }
    }
    response
        .extensions()
        .get::<hj_static::ResolvedTargetPath>()
        .map(|p| p.0.canonicalize().unwrap_or_else(|_| p.0.clone()))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn enforce_mapped_resources(
    state: &ServerState,
    ctx: &mut ReqCtx,
    headers: &http::HeaderMap,
    original: &str,
    path: &str,
    chain: &[Arc<Htaccess>],
    script: Option<&Path>,
    pinned_script: Option<&Path>,
    authenticated: &mut Vec<AuthRealm>,
) -> Result<(), Response> {
    if !ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess)
    {
        return Ok(());
    }
    if path != original {
        // Always rebuild the target's auth chain: a rewrite to an ancestor must
        // not retain a child file's different credentials or narrower Require.
        enforce_resource(
            state,
            ctx,
            headers,
            &resolved_rel_path(path),
            original,
            authenticated,
        )
        .await?;
    }
    if let Some(script) = script {
        enforce_target(state, ctx, headers, script, original, authenticated).await?;
        if let Some(target) = pinned_script.filter(|target| *target != script) {
            enforce_target(state, ctx, headers, target, original, authenticated).await?;
        }
        return Ok(());
    }
    // Resolve directory-index authorization before a cache hit. The actual
    // static response's pinned target is checked again before it is returned.
    // An auth-free lexical chain says nothing about a symlink target's chain.
    if !chain.iter().any(|ht| ht.has_auth()) && !aliases_possible(ctx, path) {
        return Ok(());
    }
    for (resource, target) in static_candidates(state, ctx, path, chain) {
        enforce_resource(state, ctx, headers, &resource, original, authenticated).await?;
        if let Ok(resolved) = opened_target_path(&target) {
            enforce_target(state, ctx, headers, &resolved, original, authenticated).await?;
        }
    }
    Ok(())
}
