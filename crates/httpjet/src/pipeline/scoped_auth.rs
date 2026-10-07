//! One auth boundary shared by requested, rewritten, and filesystem resources.

use super::*;
use hj_rewrite::AuthRealm;

// Bound work before spawn_blocking. The owned permit stays in the closure even
// if the requesting future is cancelled, so queued/running verification counts.
const AUTH_CONCURRENCY: usize = 4;
/// Roots beyond the docroot where an `AuthUserFile` may live (`--auth-user-file-roots`),
/// set once at startup.
static EXTRA_AUTH_USER_FILE_ROOTS: std::sync::OnceLock<Vec<std::path::PathBuf>> =
    std::sync::OnceLock::new();

pub(crate) fn set_auth_user_file_roots(roots: Vec<std::path::PathBuf>) {
    let _ = EXTRA_AUTH_USER_FILE_ROOTS.set(roots);
}

fn auth_user_file_roots() -> Vec<std::path::PathBuf> {
    EXTRA_AUTH_USER_FILE_ROOTS
        .get()
        .cloned()
        .unwrap_or_default()
}
static AUTH_WORK: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(AUTH_CONCURRENCY)));
static AUTH_QUEUE: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(16)));
async fn auth_permit() -> Result<tokio::sync::OwnedSemaphorePermit, Response> {
    auth_permit_from(&AUTH_WORK, &AUTH_QUEUE).await
}
async fn auth_permit_from(
    work: &Arc<tokio::sync::Semaphore>,
    queue: &Arc<tokio::sync::Semaphore>,
) -> Result<tokio::sync::OwnedSemaphorePermit, Response> {
    let _queue = queue.clone().try_acquire_owned().map_err(|_| auth_busy())?;
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        work.clone().acquire_owned(),
    )
    .await
    .map_err(|_| auth_busy())?
    .map_err(|_| auth_busy())
}
static AUTH_RATE: std::sync::LazyLock<std::sync::Mutex<AuthRate>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(AuthRate::default()));

#[derive(Default)]
struct AuthRate {
    clients: std::collections::HashMap<std::net::IpAddr, (std::time::Instant, u32)>,
}
impl AuthRate {
    fn blocked(&mut self, ip: std::net::IpAddr, now: std::time::Instant) -> bool {
        let ip = ip.to_canonical();
        self.clients
            .retain(|_, (start, _)| now.duration_since(*start) < std::time::Duration::from_secs(1));
        self.clients
            .get(&ip)
            .map_or(self.clients.len() >= 1024, |(_, count)| *count >= 32)
    }
    fn allow(&mut self, ip: std::net::IpAddr, now: std::time::Instant) -> bool {
        let ip = ip.to_canonical();
        self.clients
            .retain(|_, (start, _)| now.duration_since(*start) < std::time::Duration::from_secs(1));
        if !self.clients.contains_key(&ip) && self.clients.len() >= 1024 {
            return false;
        }
        let (_, count) = self.clients.entry(ip).or_insert((now, 0));
        if *count >= 32 {
            return false;
        }
        *count += 1;
        true
    }
}
fn auth_busy() -> Response {
    let mut response = error_page(StatusCode::SERVICE_UNAVAILABLE);
    response.headers_mut().insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_static("1"),
    );
    response
}

pub(super) async fn enforce_chain(
    ctx: &mut ReqCtx,
    headers: &http::HeaderMap,
    chain: &[Arc<Htaccess>],
    path: &str,
    request_path: &str,
    authenticated: &mut Vec<AuthRealm>,
) -> Result<(), Response> {
    enforce_chain_iter(
        ctx,
        headers,
        chain.iter().map(AsRef::as_ref),
        path,
        request_path,
        authenticated,
    )
    .await
}

pub(super) async fn enforce_chain_iter<'a, I>(
    ctx: &mut ReqCtx,
    headers: &http::HeaderMap,
    chain: I,
    path: &str,
    request_path: &str,
    authenticated: &mut Vec<AuthRealm>,
) -> Result<(), Response>
where
    I: Clone + Iterator<Item = &'a Htaccess>,
{
    if !chain.clone().any(Htaccess::has_auth) {
        return Ok(());
    }
    let filesystem_path = ctx.vhost.doc_root.join(path.trim_start_matches('/'));
    let realm = match hj_rewrite::resolve_auth_for_request(
        chain,
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
            let user_file = realm.user_file.clone();
            let doc_root = ctx.vhost.doc_root.clone();
            let roots = auth_user_file_roots();
            let permit = auth_permit().await?;
            if AUTH_RATE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .blocked(ctx.client_ip, std::time::Instant::now())
            {
                return Err(auth_busy());
            }
            let checked_user = user.clone();
            let verdict = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let file = hj_rewrite::auth::open_user_file(&user_file, &doc_root, &roots)?;
                hj_rewrite::auth::verify_credentials(&user_file, file, &checked_user, &password)
            })
            .await
            .unwrap_or(Ok(false));
            let valid = match verdict {
                Ok(valid) => valid,
                Err(error) => {
                    tracing::error!(request_id = %ctx.request_id, %error, "Basic auth refused");
                    return Err(error_page(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };
            if valid {
                ctx.set_env(hj_lsapi::cgi::AUTH_USER_ENV, user);
                authenticated.push(realm);
                return Ok(());
            }
            AUTH_RATE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .allow(ctx.client_ip, std::time::Instant::now());
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
) -> (bool, Option<std::time::Instant>) {
    if !ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess)
        || !aliases_possible(ctx, path)
    {
        return (false, None);
    }
    let indexes = effective_index_files(state, ctx, chain);
    let script = split_script_path(state, ctx, path, indexes, chain);
    let candidates = if let Some((script, _, _)) = script {
        vec![(path.to_owned(), script)]
    } else {
        static_candidates(state, ctx, path, chain)
    };
    let mut deadline: Option<std::time::Instant> = None;
    for (_, lexical) in candidates {
        let Ok(target) = opened_target_path(&lexical) else {
            continue;
        };
        let Ok(rel) = target.strip_prefix(&ctx.vhost.doc_root) else {
            continue;
        };
        let resource = format!("/{}", rel.to_string_lossy());
        let (entries, checked_until) = state.rewrite_cache.load_chain_with_dirs_and_deadline(
            &ctx.vhost.doc_root,
            &resource,
            ctx.vhost.access_file_name_or_default(),
        );
        deadline = Some(deadline.map_or(checked_until, |old| old.min(checked_until)));
        let chain: Vec<_> = entries.into_iter().map(|(_, ht)| ht).collect();
        if chain.iter().any(|ht| ht.has_auth()) || access_denied(&chain, &resource, "GET", ctx) {
            return (true, deadline);
        }
    }
    (false, deadline)
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

#[cfg(test)]
mod admission_tests {
    use super::*;
    #[test]
    fn auth_rate_is_bounded_and_canonical() {
        let mut rate = AuthRate::default();
        let now = std::time::Instant::now();
        for _ in 0..32 {
            assert!(rate.allow("192.0.2.1".parse().unwrap(), now));
        }
        assert!(!rate.allow("::ffff:192.0.2.1".parse().unwrap(), now));
        assert!(rate.allow(
            "192.0.2.1".parse().unwrap(),
            now + std::time::Duration::from_secs(1)
        ));
        for n in 1..=1024u32 {
            let _ = rate.allow(
                std::net::IpAddr::V4(n.into()),
                now + std::time::Duration::from_secs(1),
            );
        }
        assert!(rate.clients.len() <= 1024);
        assert!(!rate.allow(
            "198.51.100.1".parse().unwrap(),
            now + std::time::Duration::from_secs(1)
        ));
    }
    #[tokio::test]
    async fn cancelled_verification_retains_its_work_reservation() {
        let work = Arc::new(tokio::sync::Semaphore::new(1));
        let queue = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = auth_permit_from(&work, &queue)
            .await
            .unwrap_or_else(|_| panic!("free work slot"));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let request = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                drop(permit);
                let _ = finished_tx.send(());
            })
            .await
        });
        started_rx.await.unwrap();
        request.abort();
        let busy = auth_permit_from(&work, &queue).await.unwrap_err();
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(busy.headers()[http::header::RETRY_AFTER], "1");
        let queued = queue.clone().try_acquire_owned().unwrap();
        assert_eq!(
            auth_permit_from(&work, &queue).await.unwrap_err().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(queued);
        release_tx.send(()).unwrap();
        finished_rx.await.unwrap();
        assert!(auth_permit_from(&work, &queue).await.is_ok());
    }
}
