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
const AUTH_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
/// Unverified attempts (failures plus those still in flight) one client may hold
/// per window.
const AUTH_RATE_ATTEMPTS: u32 = 32;
const AUTH_RATE_CLIENTS: usize = 1024;
/// A browser fetching a protected page's assets in parallel queues behind its own
/// slot rather than failing; beyond this many it is refused.
const AUTH_PENDING_PER_CLIENT: u32 = 16;
const AUTH_CLIENT_SLOT_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Per-client Basic-auth accounting. An attempt is charged when admitted, before
/// any work permit or hash, and refunded only when it authenticates. A client
/// verifies one credential at a time, so it never holds more than one of the
/// shared work permits.
#[derive(Default)]
pub(crate) struct AuthLimiter(std::sync::Mutex<AuthRate>);

#[derive(Default)]
struct AuthRate {
    clients: std::collections::HashMap<std::net::IpAddr, ClientAttempts>,
}

struct ClientAttempts {
    start: std::time::Instant,
    attempts: u32,
    pending: u32,
    slot: Arc<tokio::sync::Semaphore>,
}

impl AuthRate {
    /// Charge one attempt by `ip`; `None` refuses it. The returned slot admits one
    /// verification per client at a time.
    fn admit(
        &mut self,
        ip: std::net::IpAddr,
        now: std::time::Instant,
    ) -> Option<Arc<tokio::sync::Semaphore>> {
        let ip = ip.to_canonical();
        self.clients.retain(|_, client| {
            if now.duration_since(client.start) < AUTH_RATE_WINDOW {
                return true;
            }
            client.start = now;
            client.attempts = client.pending;
            client.pending > 0
        });
        if !self.clients.contains_key(&ip) && self.clients.len() >= AUTH_RATE_CLIENTS {
            // A full table evicts its stalest idle client instead of refusing every
            // client it has not seen yet.
            let idle = self
                .clients
                .iter()
                .filter(|(_, client)| client.pending == 0)
                .min_by_key(|(_, client)| client.start)
                .map(|(ip, _)| *ip)?;
            self.clients.remove(&idle);
        }
        let client = self.clients.entry(ip).or_insert_with(|| ClientAttempts {
            start: now,
            attempts: 0,
            pending: 0,
            slot: Arc::new(tokio::sync::Semaphore::new(1)),
        });
        if client.attempts >= AUTH_RATE_ATTEMPTS || client.pending >= AUTH_PENDING_PER_CLIENT {
            return None;
        }
        client.attempts += 1;
        client.pending += 1;
        Some(client.slot.clone())
    }

    fn finish(&mut self, ip: std::net::IpAddr, verified: bool) {
        if let Some(client) = self.clients.get_mut(&ip.to_canonical()) {
            client.pending = client.pending.saturating_sub(1);
            if verified {
                client.attempts = client.attempts.saturating_sub(1);
            }
        }
    }
}

/// One admitted attempt. However the request ends, dropping it settles the
/// charge: refunded if it authenticated, kept otherwise.
struct AuthAttempt {
    limiter: Arc<AuthLimiter>,
    ip: std::net::IpAddr,
    slot: Arc<tokio::sync::Semaphore>,
    verified: bool,
}

impl AuthAttempt {
    fn admit(limiter: &Arc<AuthLimiter>, ip: std::net::IpAddr) -> Option<Self> {
        let slot = limiter
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .admit(ip, std::time::Instant::now())?;
        Some(AuthAttempt {
            limiter: limiter.clone(),
            ip,
            slot,
            verified: false,
        })
    }

    fn authenticated(&mut self) {
        self.verified = true;
    }

    async fn client_slot(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Response> {
        tokio::time::timeout(AUTH_CLIENT_SLOT_WAIT, self.slot.clone().acquire_owned())
            .await
            .map_err(|_| auth_busy())?
            .map_err(|_| auth_busy())
    }
}

impl Drop for AuthAttempt {
    fn drop(&mut self) {
        self.limiter
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .finish(self.ip, self.verified);
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
    state: &ServerState,
    ctx: &mut ReqCtx,
    headers: &http::HeaderMap,
    chain: &[Arc<Htaccess>],
    path: &str,
    request_path: &str,
    authenticated: &mut Vec<AuthRealm>,
) -> Result<(), Response> {
    enforce_chain_iter(
        state,
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
    state: &ServerState,
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
    let lexical = ctx.vhost.doc_root.join(path.trim_start_matches('/'));
    let canonical = ctx
        .vhost
        .doc_root
        .canonicalize()
        .ok()
        .map(|root| root.join(path.trim_start_matches('/')));
    let names = [
        Some(lexical.to_string_lossy()),
        canonical.as_ref().map(|path| path.to_string_lossy()),
    ];
    let filesystem_paths: Vec<&str> = names.iter().filter_map(|name| name.as_deref()).collect();
    let realm = match hj_rewrite::resolve_auth_for_request_paths(
        chain,
        path,
        request_path,
        &filesystem_paths,
    ) {
        Ok(None) => return Ok(()),
        Ok(Some(realm)) => realm,
        Err(_) => return Err(error_page(StatusCode::FORBIDDEN)),
    };
    if authenticated.contains(&realm) {
        return Ok(());
    }
    // lsphp keeps the LAST Authorization (PHP_AUTH_USER) while this check reads
    // one value: a repeated header could verify one user and hand PHP another (#864).
    let mut authorizations = headers.get_all(http::header::AUTHORIZATION).iter();
    let first = authorizations.next();
    if authorizations.next().is_some() {
        return Err(error_page(StatusCode::BAD_REQUEST));
    }
    let credentials = first
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .and_then(|(_, value)| hj_rewrite::auth::decode_basic_credentials(value));
    if let Some((user, password)) = credentials {
        // Every named user pays the same hash and `Require user` applies after it,
        // so the response time does not reveal whom the realm admits.
        let member = realm.user_satisfies(&user);
        let Some(mut attempt) = AuthAttempt::admit(&state.auth_limiter, ctx.client_ip) else {
            return Err(auth_busy());
        };
        let slot = attempt.client_slot().await?;
        let permit = auth_permit().await?;
        let user_file = realm.user_file.clone();
        let doc_root = ctx.vhost.doc_root.clone();
        let roots = auth_user_file_roots();
        let checked_user = user.clone();
        let verdict = tokio::task::spawn_blocking(move || {
            let _permits = (permit, slot);
            let verdict =
                hj_rewrite::auth::open_user_file(&user_file, &doc_root, &roots).and_then(|file| {
                    hj_rewrite::auth::verify_credentials(&user_file, file, &checked_user, &password)
                });
            if member && matches!(verdict, Ok(true)) {
                attempt.authenticated();
            }
            verdict
        })
        .await
        .unwrap_or(Ok(false));
        let valid = match verdict {
            Ok(valid) => valid && member,
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
    request: ResourceRequest<'_>,
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
    let denied = match chain_access_ctx(state, ctx, &chain, request, path) {
        Ok(access_ctx) => access_denied(&chain, path, request.method, &access_ctx),
        Err(reason) => {
            tracing::error!(request_id = %ctx.request_id, reason, "target SetEnvIf evaluation failed closed");
            return Err(error_page(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };
    if denied {
        return Err(error_page(StatusCode::FORBIDDEN));
    }
    enforce_chain(
        state,
        ctx,
        request.headers,
        &chain,
        path,
        request_path,
        authenticated,
    )
    .await
}

/// The last resource [`enforce_mapped_resources`] passed, with the realm count it
/// left. Enforcement mutates `ctx` only when it authenticates a new realm, which
/// also grows `authenticated`, so an equal count means a repeat of that resource
/// would see identical inputs and pass again.
#[derive(Default)]
struct LastEnforced(Option<(String, usize)>);

impl LastEnforced {
    async fn resource(
        &mut self,
        state: &ServerState,
        ctx: &mut ReqCtx,
        request: ResourceRequest<'_>,
        path: &str,
        request_path: &str,
        authenticated: &mut Vec<AuthRealm>,
    ) -> Result<(), Response> {
        if self
            .0
            .as_ref()
            .is_some_and(|(last, realms)| last == path && *realms == authenticated.len())
        {
            return Ok(());
        }
        let realms = authenticated.len();
        enforce_resource(state, ctx, request, path, request_path, authenticated).await?;
        self.0 = (authenticated.len() == realms).then(|| (path.to_owned(), realms));
        Ok(())
    }

    async fn target(
        &mut self,
        state: &ServerState,
        ctx: &mut ReqCtx,
        request: ResourceRequest<'_>,
        target: &Path,
        request_path: &str,
        authenticated: &mut Vec<AuthRealm>,
    ) -> Result<(), Response> {
        if let Some(relative) = relative_to_doc_root(ctx, target) {
            let path = format!("/{}", relative.to_string_lossy());
            self.resource(state, ctx, request, &path, request_path, authenticated)
                .await?;
        }
        Ok(())
    }
}

fn relative_to_doc_root(ctx: &ReqCtx, target: &Path) -> Option<PathBuf> {
    if let Ok(relative) = target.strip_prefix(&ctx.vhost.doc_root) {
        return Some(relative.to_path_buf());
    }
    let canonical_root = ctx.vhost.doc_root.canonicalize().ok()?;
    target
        .strip_prefix(canonical_root)
        .ok()
        .map(Path::to_path_buf)
}

pub(super) async fn enforce_target(
    state: &ServerState,
    ctx: &mut ReqCtx,
    request: ResourceRequest<'_>,
    target: &Path,
    request_path: &str,
    authenticated: &mut Vec<AuthRealm>,
) -> Result<(), Response> {
    LastEnforced::default()
        .target(state, ctx, request, target, request_path, authenticated)
        .await
}

fn static_candidates(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    chain: &[Arc<Htaccess>],
) -> Vec<(String, PathBuf)> {
    // Same mapping as the static handler's DocRootOverride (#673).
    let rel = std::path::Path::new(path.trim_start_matches('/'));
    let (root, rel) = match static_location_override(ctx, path) {
        Some((loc, uri)) => (loc, hj_static::context_relative_path(rel, uri)),
        None => (&ctx.vhost.doc_root, rel),
    };
    let lexical = root.join(rel);
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
    ctx.vhost.allow_symbol_link || static_location_override(ctx, path).is_some()
}

/// What the on-core path learned about a request's mapped filesystem targets.
#[derive(Default)]
pub(super) struct TargetPolicy {
    /// Auth-protected or access-denied: bridge so dispatch() renders the outcome.
    pub protected: bool,
    /// Every checked target chain is memo-eligible (its access rules are a pure
    /// function of the memo key), so a finished response may be memoized.
    pub memo_ok: bool,
    pub deadline: Option<std::time::Instant>,
    pub targets: Vec<PathBuf>,
    /// The script the path maps to, when judged, with its opened target, so a
    /// later gate on the same script need not open it again.
    pub script: Option<OpenedScript>,
}

pub(super) struct OpenedScript {
    pub lexical: PathBuf,
    pub target: Option<PathBuf>,
}

/// On-core cache/static serving cannot authenticate. Discover a mapped target's
/// auth policy before either cache branch, then bridge to the shared enforcer.
/// Runs after the existing finished-memo probe (its normal one-second TTL).
pub(super) fn target_has_auth(
    state: &ServerState,
    ctx: &ReqCtx,
    request: ResourceRequest<'_>,
    path: &str,
    chain: &[Arc<Htaccess>],
) -> (bool, Option<std::time::Instant>) {
    let policy = target_policy(state, ctx, request, path, chain);
    (policy.protected, policy.deadline)
}

/// [`target_has_auth`] with the memo verdict and the resolved targets. The access
/// part reads `ctx.client_ip` and `ctx.env`, so call it after both are final.
pub(super) fn target_policy(
    state: &ServerState,
    ctx: &ReqCtx,
    request: ResourceRequest<'_>,
    path: &str,
    chain: &[Arc<Htaccess>],
) -> TargetPolicy {
    let mut policy = TargetPolicy {
        memo_ok: true,
        ..TargetPolicy::default()
    };
    if !ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess)
        || !aliases_possible(ctx, path)
    {
        return policy;
    }
    let indexes = effective_index_files(state, ctx, chain);
    let script = split_script_path(state, ctx, path, indexes, chain);
    let is_script = script.is_some();
    let candidates = if let Some((script, _, _)) = script {
        vec![(path.to_owned(), script)]
    } else {
        static_candidates(state, ctx, path, chain)
    };
    for (_, lexical) in candidates {
        let opened = opened_target_path(&lexical).ok();
        if is_script {
            policy.script = Some(OpenedScript {
                lexical,
                target: opened.clone(),
            });
        }
        let Some(target) = opened else {
            continue;
        };
        let Some(checked) = opened_target_policy(state, ctx, request, &target) else {
            continue;
        };
        policy.deadline = Some(
            policy
                .deadline
                .map_or(checked.until, |old| old.min(checked.until)),
        );
        policy.memo_ok &= checked.memo_ok;
        policy.targets.push(target);
        if checked.protected {
            policy.protected = true;
            return policy;
        }
    }
    policy
}

/// The opened inode of an on-core static response, when it is not one of the
/// targets [`target_policy`] already judged (a precompressed sibling the static
/// handler substituted, or a target that changed after the prediction).
/// `None` = nothing new to judge.
pub(super) fn served_target_policy(
    state: &ServerState,
    ctx: &ReqCtx,
    request: ResourceRequest<'_>,
    path: &str,
    predicted: &[PathBuf],
    response: &Response,
) -> Option<ServedTargetPolicy> {
    if !ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess)
    {
        return None;
    }
    let target = served_target(response)?;
    if predicted.contains(&target) {
        return None;
    }
    // Without aliases only the lexical request file was judged (by its own
    // chain); a DirectoryIndex or precompressed sibling still needs its check (#795).
    if !aliases_possible(ctx, path)
        && target
            == ctx
                .vhost
                .doc_root
                .join(resolved_rel_path(path).trim_start_matches('/'))
    {
        return None;
    }
    // A target outside the docroot has no .htaccess chain: dispatch()'s
    // enforce_target skips it the same way.
    let checked = opened_target_policy(state, ctx, request, &target)?;
    Some(ServedTargetPolicy {
        protected: checked.protected,
        denied: checked.denied,
        memo_ok: checked.memo_ok,
        until: checked.until,
    })
}

/// The verdict of [`served_target_policy`] on an opened target.
pub(super) struct ServedTargetPolicy {
    /// Auth-gated or denied: on-core serving must not return it.
    pub(super) protected: bool,
    /// Denied whatever the client's credentials (dispatch()'s 403 shape).
    pub(super) denied: bool,
    pub(super) memo_ok: bool,
    /// When the target's chain is next revalidated; a memoized response must
    /// not outlive it.
    pub(super) until: std::time::Instant,
}

struct CheckedTarget {
    protected: bool,
    denied: bool,
    memo_ok: bool,
    until: std::time::Instant,
}

fn opened_target_policy(
    state: &ServerState,
    ctx: &ReqCtx,
    request: ResourceRequest<'_>,
    target: &Path,
) -> Option<CheckedTarget> {
    let rel = relative_to_doc_root(ctx, target)?;
    let resource = format!("/{}", rel.to_string_lossy());
    let (entries, until) = state.rewrite_cache.load_chain_with_dirs_and_deadline(
        &ctx.vhost.doc_root,
        &resource,
        ctx.vhost.access_file_name_or_default(),
    );
    let chain: Vec<_> = entries.into_iter().map(|(_, ht)| ht).collect();
    // A failed env phase bridges: dispatch() renders its 500.
    let (denied, env_failed) = match chain_access_ctx(state, ctx, &chain, request, &resource) {
        Ok(access_ctx) => (
            access_denied(&chain, &resource, request.method, &access_ctx),
            false,
        ),
        Err(_) => (false, true),
    };
    Some(CheckedTarget {
        protected: denied || env_failed || chain.iter().any(|ht| ht.has_auth()),
        denied,
        memo_ok: chain.iter().all(|ht| ht.memo.eligible),
        until,
    })
}

/// [`target_has_auth`] for a script the caller already opened and resolved, so the
/// on-core path does not open it twice.
pub(super) fn resolved_target_has_auth(
    state: &ServerState,
    ctx: &ReqCtx,
    request: ResourceRequest<'_>,
    path: &str,
    target: &Path,
) -> bool {
    ctx.vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess)
        && aliases_possible(ctx, path)
        // An unaliased target's chain is a prefix of the request chain the caller
        // already auth-checked (a rewrite into a non-ancestor directory bridges
        // first), so only an aliased target needs its own chain load. This keeps the
        // load off every front-controller cache hit (`/threads/..` -> `/index.php`).
        && target != ctx.vhost.doc_root.join(path.trim_start_matches('/'))
        && opened_target_policy(state, ctx, request, target).is_some_and(|checked| checked.protected)
}

/// Prefer the opened inode over a lexical target hint for the final backstop.
pub(super) fn served_target(response: &Response) -> Option<PathBuf> {
    // hj-static resolves its target after precompressed selection, from the
    // opened descriptor whenever a symlink was followed: no readlink needed.
    if let Some(resolved) = response.extensions().get::<hj_static::ResolvedTargetPath>()
        && matches!(response.body(), Body::File(_))
    {
        return Some(resolved.0.clone());
    }
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
    request: ResourceRequest<'_>,
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
    let mut last = LastEnforced::default();
    if path != original {
        // Always rebuild the target's auth chain: a rewrite to an ancestor must
        // not retain a child file's different credentials or narrower Require.
        last.resource(
            state,
            ctx,
            request,
            &resolved_rel_path(path),
            original,
            authenticated,
        )
        .await?;
    }
    if let Some(script) = script {
        last.target(state, ctx, request, script, original, authenticated)
            .await?;
        if let Some(target) = pinned_script.filter(|target| *target != script) {
            last.target(state, ctx, request, target, original, authenticated)
                .await?;
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
        last.resource(state, ctx, request, &resource, original, authenticated)
            .await?;
        if let Ok(resolved) = opened_target_path(&target) {
            last.target(state, ctx, request, &resolved, original, authenticated)
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    fn ip(text: &str) -> std::net::IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn auth_attempts_are_charged_before_verification_and_refunded_on_success() {
        let mut rate = AuthRate::default();
        let now = std::time::Instant::now();
        let client = ip("192.0.2.1");
        for _ in 0..AUTH_PENDING_PER_CLIENT {
            assert!(rate.admit(client, now).is_some());
        }
        assert!(
            rate.admit(client, now).is_none(),
            "in-flight attempts count before any hash completes"
        );
        for _ in 0..AUTH_PENDING_PER_CLIENT {
            rate.finish(client, false);
        }
        // Failures stay charged, and the IPv4-mapped form is the same client.
        for _ in AUTH_PENDING_PER_CLIENT..AUTH_RATE_ATTEMPTS {
            assert!(rate.admit(ip("::ffff:192.0.2.1"), now).is_some());
            rate.finish(ip("::ffff:192.0.2.1"), false);
        }
        assert!(rate.admit(client, now).is_none());
        let user = ip("192.0.2.2");
        for _ in 0..4 * AUTH_RATE_ATTEMPTS {
            assert!(rate.admit(user, now).is_some(), "successes are refunded");
            rate.finish(user, true);
        }
        assert!(rate.admit(client, now + AUTH_RATE_WINDOW).is_some());
    }

    #[test]
    fn a_full_auth_table_does_not_lock_out_new_clients() {
        let mut rate = AuthRate::default();
        let now = std::time::Instant::now();
        for n in 1..=AUTH_RATE_CLIENTS as u32 {
            let client = std::net::IpAddr::V4(n.into());
            for _ in 0..AUTH_RATE_ATTEMPTS {
                assert!(rate.admit(client, now).is_some());
                rate.finish(client, false);
            }
        }
        assert_eq!(rate.clients.len(), AUTH_RATE_CLIENTS);
        assert!(rate.admit(ip("198.51.100.1"), now).is_some());
        assert!(rate.clients.len() <= AUTH_RATE_CLIENTS);
        let tracked = *rate
            .clients
            .keys()
            .find(|tracked| **tracked != ip("198.51.100.1"))
            .unwrap();
        assert!(
            rate.admit(tracked, now).is_none(),
            "a blocked client stays blocked"
        );
    }

    #[test]
    fn one_client_verifies_one_credential_at_a_time() {
        let mut rate = AuthRate::default();
        let now = std::time::Instant::now();
        let first = rate.admit(ip("192.0.2.1"), now).unwrap();
        let second = rate.admit(ip("::ffff:192.0.2.1"), now).unwrap();
        let other = rate.admit(ip("192.0.2.9"), now).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(first.available_permits(), 1);
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
