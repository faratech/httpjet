//! Per-vhost lsphp pool registry.
//!
//! [`LsapiRegistry`] owns a set of lsphp pools keyed by a [`PoolKey`] derived from
//! the worker's *jail identity* — `(command, uid, gid, chroot, namespaces)`. Two
//! vhosts that resolve to the same credentials + chroot share **one** pool (and
//! therefore one lsphp master + socket); a vhost with distinct credentials gets
//! its own. Each [`PoolEntry`] owns its own
//! `{ LsphpSupervisor, LsapiPool, Monitor, Lsapi }` quartet — the exact wiring
//! `main.rs` used to build by hand for the single global pool.
//!
//! # Dev-safety invariants (must hold)
//! The whole per-vhost-jail feature is **config-gated** ([`SuExecPolicy::enable`],
//! default `false`) **and** root-gated (only drops/chroots when `getuid()==0`).
//! Those gates live in [`JailConfig::resolve`](crate::JailConfig::resolve), which
//! returns an all-`None` jail whenever the feature is off, we are not root, or the
//! vhost declares no isolation. An all-`None` jail maps to the canonical
//! [`PoolKey::default`] (`"php"`), so:
//!
//! - With suEXEC **OFF** (the default) the registry holds **exactly one** entry,
//!   keyed `"php"`, behaving byte-for-byte like today's single pool: the existing
//!   separate socket, the server user/group, no chroot.
//! - Per-instance sockets only ever exist when suEXEC is **on + root + multiple
//!   distinct credentials**. Every generated socket path lives under `/tmp`
//!   (`/tmp/php-httpjet-<sanitized-key>.sock`); we **assert** no generated path is
//!   ever under `/usr/local/lsws` or `/web` (the production trees).
//!
//! # Concurrency
//! The map is a `RwLock<HashMap<…>>`. The hot path ([`LsapiRegistry::handler_for`])
//! takes the **read** lock and returns a cloned `Arc<Lsapi>` on a hit; only the
//! first request for a given key takes the **write** lock to start the pool
//! (double-checked so concurrent first-requests start it once). Starting an lsphp
//! master is async, so the write lock is *not* held across the `start().await` —
//! we reserve the slot with a `tokio::sync::OnceCell` per entry instead (see
//! [`PoolEntry`]).

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};

use crate::handler::{BodyBufferBudget, DEFAULT_BODY_BUFFER_MEM, Lsapi};
use crate::jail::{Credentials, JailConfig, NamespaceFlags};
use crate::monitor::{Monitor, MonitorConfig};
use crate::pool::{ExternalGeneration, LsapiPool, PoolStats};
use crate::supervisor::{LsphpSupervisor, PromotionHook, SupervisorConfig};
use tokio_util::sync::CancellationToken;

/// The canonical key for the default (un-jailed) pool. With suEXEC OFF every
/// vhost maps here, so the registry holds exactly one entry behaving like today.
const DEFAULT_KEY: &str = "php";

/// Production trees a generated socket path must NEVER touch (R&D safety).
const FORBIDDEN_SOCKET_PREFIXES: [&str; 2] = ["/usr/local/lsws", "/web"];

/// Identity of an lsphp pool: vhosts sharing this identity share one pool.
///
/// Derived from the worker command + the resolved jail. The all-`None` jail
/// (suEXEC off / non-root / no per-vhost isolation) collapses to
/// [`PoolKey::default`] so today's single-pool behavior is preserved exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    /// `None` for the canonical default pool; `Some` for a jailed instance.
    /// `(command, uid, gid, chroot, namespaces)`.
    inner: Option<JailedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct JailedKey {
    command: PathBuf,
    uid: u32,
    gid: u32,
    /// The chroot target as raw bytes (or empty when no chroot).
    chroot: Vec<u8>,
    /// Namespace isolation flags (Phase 5a). Pools that unshare different
    /// namespaces must NOT dedupe, so these participate in the key. `Copy` +
    /// `Hash` via [`NamespaceFlags`]. Empty for the un-jailed / no-namespace
    /// case (matching today's single-pool behavior).
    namespaces: NamespaceFlags,
}

impl Default for PoolKey {
    /// The canonical default pool key (`"php"`): the un-jailed, server
    /// user/group, no-chroot pool that every vhost uses when suEXEC is off.
    fn default() -> Self {
        PoolKey { inner: None }
    }
}

impl PoolKey {
    /// Derive the pool key for a resolved jail + the worker command.
    ///
    /// An all-`None` jail (suEXEC off / non-root / no isolation) yields the
    /// canonical default key, guaranteeing a single shared pool in that mode.
    pub fn from_jail(command: &Path, jail: &JailConfig) -> Self {
        // No credential drop AND no chroot AND no namespaces => indistinguishable
        // from the default pool. (A jail only carries chroot/namespaces alongside
        // a credential drop per JailConfig::resolve, but be defensive about all
        // three so a namespaces-only jail never collapses into the shared pool.)
        if jail.credentials.is_none() && jail.chroot.is_none() && jail.namespaces.is_empty() {
            return PoolKey::default();
        }
        let Credentials { uid, gid } = jail.credentials.unwrap_or(Credentials { uid: 0, gid: 0 });
        let chroot = jail
            .chroot
            .as_ref()
            .map(|c| c.to_bytes().to_vec())
            .unwrap_or_default();
        PoolKey {
            inner: Some(JailedKey {
                command: command.to_path_buf(),
                uid,
                gid,
                chroot,
                // Phase 5a: different namespace isolation => different pool.
                namespaces: jail.namespaces,
            }),
        }
    }

    /// True for the canonical default (un-jailed) pool.
    pub fn is_default(&self) -> bool {
        self.inner.is_none()
    }

    /// A filesystem-safe, collision-resistant token for this key, used to build
    /// the per-instance socket name. The default key returns `"php"`.
    fn sanitized(&self) -> String {
        match &self.inner {
            None => DEFAULT_KEY.to_string(),
            Some(j) => {
                // uid/gid + a hash of (command, chroot, ns) keeps the name short,
                // unique, and free of path separators.
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                use std::hash::{Hash, Hasher};
                j.command.hash(&mut hasher);
                j.chroot.hash(&mut hasher);
                j.namespaces.hash(&mut hasher);
                let h = hasher.finish();
                format!("u{}g{}-{:016x}", j.uid, j.gid, h)
            }
        }
    }
}

/// A single running pool quartet: supervisor + connection pool + monitor +
/// handler, all sharing one lsphp master on one socket. Mirrors the wiring
/// `main.rs` built for the global pool in Phase 3.
struct PoolEntry {
    handler: Arc<Lsapi>,
    pool: Arc<LsapiPool>,
    /// Present only for an EXTERNAL pool with a mapped generation file. It
    /// observes owner promotions even when the web tier is quiet, so old idle
    /// sockets release their workers during the supervisor's graceful window.
    external_generation_watcher: Option<ExternalGenerationWatcher>,
    /// Present for a pool THIS registry spawns + supervises; `None` for an
    /// EXTERNAL pool — a separate `httpjet lsphp` process owns the lsphp master
    /// (LS-Enterprise model), so the web process is a pure LSAPI client with
    /// nothing of its own to drain on shutdown.
    supervised: Option<Supervised>,
}

/// The supervision handles for a pool this registry spawned itself.
struct Supervised {
    supervisor: Arc<LsphpSupervisor>,
    /// Cancel BEFORE draining the supervisor (Phase-3 shutdown semantics).
    cancel: CancellationToken,
    /// The monitor ticker `JoinHandle`, taken + joined (bounded) before drain on
    /// shutdown. Behind a `Mutex<Option<…>>` because the entry is shared (held by
    /// the slot's `OnceCell` via `&PoolEntry`); `drain_all` `take()`s it to await.
    ticker: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

const EXTERNAL_GENERATION_WATCH_INTERVAL: Duration = Duration::from_millis(50);
const EXTERNAL_GENERATION_WATCH_STOP_TIMEOUT: Duration = Duration::from_secs(5);

struct ExternalGenerationWatcher {
    cancel: CancellationToken,
    task: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ExternalGenerationWatcher {
    fn spawn(pool: Arc<LsapiPool>) -> Self {
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(EXTERNAL_GENERATION_WATCH_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // `interval` ticks immediately. Construction already synchronized the
            // pool epoch, so wait for the first real polling interval.
            ticker.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = task_cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        // An epoch advance atomically drains the idle set and
                        // retires each attributed old-family worker. The mmap
                        // read is syscall-free when no promotion occurred.
                        pool.generation();
                    }
                }
            }
        });
        Self {
            cancel,
            task: parking_lot::Mutex::new(Some(task)),
        }
    }

    async fn stop(&self) -> std::io::Result<()> {
        self.cancel.cancel();
        let Some(mut task) = self.task.lock().take() else {
            return Ok(());
        };
        match tokio::time::timeout(EXTERNAL_GENERATION_WATCH_STOP_TIMEOUT, &mut task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(std::io::Error::other(format!(
                "external lsphp generation watcher failed: {error}"
            ))),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "external lsphp generation watcher did not stop within {EXTERNAL_GENERATION_WATCH_STOP_TIMEOUT:?}"
                    ),
                ))
            }
        }
    }
}

impl Drop for ExternalGenerationWatcher {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.get_mut().take() {
            task.abort();
        }
    }
}

/// Runtime knobs (sourced once from `PhpConfig`) needed to build each pool's
/// pool/monitor/handler. The per-key [`SupervisorConfig`] is cloned from a
/// template and re-jailed per entry.
#[derive(Clone)]
struct PoolParams {
    /// Idle TTL for pooled keep-alive sockets.
    idle_ttl: Duration,
    /// Tier-1/Tier-2 processing-time cap.
    max_process_time: Option<Duration>,
    /// Pool init/connect timeout.
    init_timeout: Duration,
    /// Refused/missing-socket dial retry budget (LiteSpeed `retryTimeout`); rides
    /// out an lsphp restart window instead of 502ing. 0 ⇒ pool's built-in floor.
    retry_timeout: Duration,
    /// Max pooled connections (≈ children * 2).
    max_conns: u32,
    /// Max request body fed to lsphp.
    max_body: u64,
    /// Server-wide budget shared by ALL pools' handlers bounding heap held by
    /// buffered (chunked) request bodies (#236).
    body_budget: Arc<BodyBufferBudget>,
    /// Extra env appended to every request (PHP_VALUE/ext env).
    base_env: Vec<(String, String)>,
}

/// A lazily-populated, jail-keyed set of lsphp pools.
pub struct LsapiRegistry {
    /// Template config for the default pool — cloned and re-jailed per entry.
    /// Carries command, env, children, limits, restart knobs, and the default
    /// pool's socket path (used verbatim for the `"php"` key).
    template: SupervisorConfig,
    params: PoolParams,
    entries: RwLock<HashMap<PoolKey, Arc<EntrySlot>>>,
    /// Set once shutdown begins (under the `entries` write lock). Once set,
    /// `handler_for` refuses to insert NEW slots so `drain_all` cannot be raced
    /// into orphaning a freshly-spawned lsphp master + its Monitor ticker. The
    /// flag is written and observed under the same write lock that inserts a
    /// slot, giving a happens-before relationship: any slot that exists when
    /// `drain_all` snapshots is guaranteed drained, and any later first-request
    /// is rejected before it can spawn a pool.
    draining: AtomicBool,
    /// EXTERNAL mode (`httpjet serve --lsphp-external`): the lsphp master is owned
    /// by a separate persistent process, so this registry NEVER spawns/supervises
    /// — it only builds client pools that dial `template.socket_path`. Lets the web
    /// process restart (zero-downtime deploy) without cold-starting PHP.
    external: bool,
    /// Shared epoch published by the standalone pool owner. Installed before
    /// `start_default`; external client pools clone the mapping so idle and
    /// checked-out connections spanning a promotion cannot be re-pooled.
    external_generation: RwLock<Option<Arc<ExternalGeneration>>>,
    /// Owner-side generation publisher installed before the default pool starts.
    /// Combined with the pool epoch in the supervisor's persistent promotion hook.
    default_promotion_hook: RwLock<Option<PromotionHook>>,
    /// An inherited (systemd socket-activated) listen fd for the DEFAULT pool, set
    /// by the standalone `httpjet lsphp` process via [`Self::set_listen_fd`] and
    /// `take`n once when the default supervisor is built — so the lsphp master
    /// adopts the persistent socket instead of binding (and the socket survives
    /// restarts). `None` (the common case) = self-bind as before.
    listen_fd: Mutex<Option<OwnedFd>>,
}

/// Per-key slot guarding lazy async start. The map's write lock inserts the slot
/// synchronously; the (async) supervisor start runs through the slot's
/// `OnceCell` so the map lock is never held across `.await` and concurrent
/// first-requests start the pool exactly once.
struct EntrySlot {
    key: PoolKey,
    socket_path: PathBuf,
    cell: tokio::sync::OnceCell<PoolEntry>,
}

impl LsapiRegistry {
    /// Build a registry from the default pool's [`SupervisorConfig`] plus the
    /// `PhpConfig`-derived runtime params. The `template` already carries the
    /// R&D overrides (children cap, the default `--php-socket` path); the default
    /// `"php"` entry reuses `template.socket_path` verbatim.
    pub fn new(
        template: SupervisorConfig,
        idle_ttl: Duration,
        max_process_time: Option<Duration>,
        max_body: u64,
    ) -> Arc<Self> {
        Self::new_inner(template, idle_ttl, max_process_time, max_body, false)
    }

    /// Build a registry in EXTERNAL mode: it dials `template.socket_path` as a
    /// pure LSAPI client and never spawns or supervises lsphp (a separate
    /// `httpjet lsphp` process owns the master). suEXEC jailing is not supported
    /// here — there is a single shared pool on the one external socket.
    pub fn new_external(
        template: SupervisorConfig,
        idle_ttl: Duration,
        max_process_time: Option<Duration>,
        max_body: u64,
    ) -> Arc<Self> {
        Self::new_inner(template, idle_ttl, max_process_time, max_body, true)
    }

    fn new_inner(
        template: SupervisorConfig,
        idle_ttl: Duration,
        max_process_time: Option<Duration>,
        max_body: u64,
        external: bool,
    ) -> Arc<Self> {
        let params = PoolParams {
            idle_ttl,
            max_process_time,
            init_timeout: template.start_timeout,
            retry_timeout: template.retry_timeout,
            max_conns: if external {
                template.children.max(1)
            } else {
                (template.children * 2).max(2)
            },
            max_body,
            body_budget: Arc::new(BodyBufferBudget::new(DEFAULT_BODY_BUFFER_MEM)),
            base_env: template.env.clone(),
        };
        Arc::new(LsapiRegistry {
            template,
            params,
            entries: RwLock::new(HashMap::new()),
            draining: AtomicBool::new(false),
            external,
            external_generation: RwLock::new(None),
            default_promotion_hook: RwLock::new(None),
            listen_fd: Mutex::new(None),
        })
    }

    /// Attach the process-independent epoch used by an EXTERNAL client pool.
    /// Call before [`Self::start_default`]. A missing or malformed file is
    /// deliberately non-fatal so the static/cache web tier can still start.
    pub fn set_external_generation_file(&self, path: impl AsRef<Path>) -> bool {
        let path = path.as_ref();
        if !self.external {
            tracing::warn!(
                path = %path.display(),
                "ignoring lsphp generation file on a supervised registry"
            );
            return false;
        }
        if self.default_pool_started() {
            tracing::warn!(
                path = %path.display(),
                "cannot replace lsphp generation file after the external client pool has started"
            );
            return false;
        }
        match ExternalGeneration::open(path) {
            Ok(source) => {
                *self.external_generation.write() = Some(Arc::new(source));
                tracing::info!(
                    path = %path.display(),
                    "external lsphp generation counter attached"
                );
                true
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "external lsphp generation counter unavailable; mapping was not attached"
                );
                false
            }
        }
    }

    /// Attach an already-open generation mapping. Call before
    /// [`Self::start_default`].
    pub fn set_external_generation(&self, source: Arc<ExternalGeneration>) -> bool {
        if !self.external {
            tracing::warn!("ignoring lsphp generation mapping on a supervised registry");
            return false;
        }
        if self.default_pool_started() {
            tracing::warn!(
                "cannot replace lsphp generation mapping after the external client pool has started"
            );
            return false;
        }
        *self.external_generation.write() = Some(source);
        true
    }

    fn default_pool_started(&self) -> bool {
        self.entries
            .read()
            .get(&PoolKey::default())
            .is_some_and(|slot| slot.cell.get().is_some())
    }

    /// Install the owner-side publisher used by every default-pool promotion,
    /// including autonomous monitor recovery. Call before `start_default`.
    pub fn set_default_promotion_hook(&self, hook: PromotionHook) -> bool {
        if self.external || self.default_pool_started() {
            return false;
        }
        *self.default_promotion_hook.write() = Some(hook);
        true
    }

    /// Install an inherited (systemd socket-activated) listen fd for the default
    /// pool. Call BEFORE [`Self::start_default`]; the fd is adopted by the default
    /// supervisor (which holds it across restarts) instead of self-binding the
    /// socket path. Only meaningful for the standalone `httpjet lsphp` (non-external)
    /// registry; ignored for jailed/non-default keys.
    pub fn set_listen_fd(&self, fd: OwnedFd) {
        *self.listen_fd.lock() = Some(fd);
    }

    /// Eagerly start the default (`"php"`) pool so the hot path is a pure map
    /// lookup. Equivalent to the single global pool `main.rs` started in Phase 3.
    pub async fn start_default(self: &Arc<Self>) -> std::io::Result<Arc<Lsapi>> {
        self.handler_for("<default>", &JailConfig::default()).await
    }

    /// Current generation of the started default supervised pool.
    pub fn default_generation(&self) -> Option<u64> {
        let slot = self.entries.read().get(&PoolKey::default()).cloned()?;
        let entry = slot.cell.get()?;
        entry
            .supervised
            .as_ref()
            .map(|supervised| supervised.supervisor.generation())
    }

    /// Forced old-family cleanups observed by the default supervisor.
    pub fn default_forced_cleanup_count(&self) -> Option<u64> {
        let slot = self.entries.read().get(&PoolKey::default()).cloned()?;
        let entry = slot.cell.get()?;
        entry
            .supervised
            .as_ref()
            .map(|supervised| supervised.supervisor.forced_cleanup_count())
    }

    /// Operational counters for the started default client pool.
    pub fn default_pool_stats(&self) -> Option<PoolStats> {
        let slot = self.entries.read().get(&PoolKey::default()).cloned()?;
        Some(slot.cell.get()?.pool.stats())
    }

    /// Candidate-first hot reload of the default socket-activated pool. `Ok(g)`
    /// means the candidate was promoted, the client-pool epoch advanced to `g`,
    /// and the complete old process family was drained or force-reaped.
    pub async fn hot_reload_default(self: &Arc<Self>) -> std::io::Result<u64> {
        self.hot_reload_default_with_promotion(|_| {}).await
    }

    /// As [`Self::hot_reload_default`], invoking `publish` at the promotion
    /// boundary. The candidate is installed and the old master receives SIGUSR1;
    /// then the external generation is published and the registry pool advances
    /// before the old family's bounded grace wait.
    pub async fn hot_reload_default_with_promotion<F>(
        self: &Arc<Self>,
        publish: F,
    ) -> std::io::Result<u64>
    where
        F: FnOnce(u64) + Send + 'static,
    {
        if self.external {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "external lsphp registries do not own the server lifecycle",
            ));
        }
        if self.draining.load(Ordering::Acquire) {
            return Err(std::io::Error::other(
                "lsphp registry is draining (server shutting down)",
            ));
        }
        let slot = self
            .entries
            .read()
            .get(&PoolKey::default())
            .cloned()
            .ok_or_else(|| std::io::Error::other("default lsphp pool is not started"))?;
        let entry = slot
            .cell
            .get()
            .ok_or_else(|| std::io::Error::other("default lsphp pool is still starting"))?;
        let supervised = entry
            .supervised
            .as_ref()
            .ok_or_else(|| std::io::Error::other("default lsphp pool is not supervised"))?;
        let supervisor = supervised.supervisor.clone();
        // The lifecycle transaction outlives a dropped control connection or a
        // shutdown handler's short wait budget. Dropping a JoinHandle detaches
        // the task; the supervisor lock then serializes the final shutdown drain
        // behind the in-progress promote/cleanup operation.
        tokio::spawn(async move { supervisor.hot_reload_with_promotion(publish).await })
            .await
            .map_err(|error| std::io::Error::other(format!("lsphp reload task failed: {error}")))?
    }

    /// Resolve (lazily starting on first use) the [`Lsapi`] handler for a vhost's
    /// resolved [`JailConfig`].
    ///
    /// Fast path: a **read** lock + a started `OnceCell` returns a cloned
    /// `Arc<Lsapi>` with no contention. First use of a key takes the **write**
    /// lock only to *insert the slot* (double-checked); the async supervisor
    /// start happens outside the map lock via the slot's `OnceCell`, so the map
    /// lock is never held across `.await`.
    ///
    /// On pool-create/start failure returns `Err` (the caller turns this into a
    /// 503 and disables PHP for the vhost — never runs as root, never falls back
    /// unjailed).
    pub async fn handler_for(
        self: &Arc<Self>,
        vhost_name: &str,
        jail: &JailConfig,
    ) -> std::io::Result<Arc<Lsapi>> {
        let key = PoolKey::from_jail(&self.template.command, jail);
        if self.external && !key.is_default() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "external lsphp mode has one shared socket and cannot honor a per-vhost jail",
            ));
        }

        // 1. Read fast-path: slot already present?
        let slot = {
            let guard = self.entries.read();
            guard.get(&key).cloned()
        };
        let slot = match slot {
            Some(slot) => slot,
            None => {
                // 2. Insert the slot under the write lock (double-checked). This
                //    is synchronous and cheap — no async work under the lock.
                let socket_path = self.socket_for(&key);
                let mut guard = self.entries.write();
                // Re-check presence under the write lock (a concurrent first-
                // request may have inserted it) before consulting `draining`.
                if let Some(existing) = guard.get(&key) {
                    existing.clone()
                } else {
                    // SHUTDOWN GUARD: if drain_all has begun, refuse to insert a
                    // NEW slot. Both this check and drain_all's `draining` store
                    // happen under this same write lock, so once drain_all has
                    // flipped the flag no later first-request can spawn a pool
                    // that drain_all would miss — closing the orphaned
                    // lsphp/Monitor race on shutdown.
                    if self.draining.load(Ordering::Acquire) {
                        return Err(std::io::Error::other(
                            "lsphp registry is draining (server shutting down)",
                        ));
                    }
                    let slot = Arc::new(EntrySlot {
                        key: key.clone(),
                        socket_path,
                        cell: tokio::sync::OnceCell::new(),
                    });
                    guard.insert(key.clone(), slot.clone());
                    slot
                }
            }
        };

        // 3. Start the pool once via the slot's OnceCell (no map lock held). A
        //    failed start leaves the cell un-initialized so a later request can
        //    retry; the error propagates so the caller returns 503.
        let entry = slot
            .cell
            .get_or_try_init(|| self.build_entry(vhost_name, &slot.key, jail, &slot.socket_path))
            .await?;
        Ok(entry.handler.clone())
    }

    /// Compute the socket path for a key. The default key reuses the template's
    /// socket verbatim (the `--php-socket` default); jailed keys get a unique
    /// `/tmp/php-httpjet-<sanitized>.sock`. ASSERTS the path is never under a
    /// production tree.
    fn socket_for(&self, key: &PoolKey) -> PathBuf {
        let path = if key.is_default() {
            self.template.socket_path.clone()
        } else {
            PathBuf::from(format!("/tmp/php-httpjet-{}.sock", key.sanitized()))
        };
        // DEV-SAFETY: a *generated* per-instance socket must never live under the
        // production trees. The default socket comes from the operator (--php-socket,
        // already a /tmp path in R&D) so we only assert the generated ones.
        if !key.is_default() {
            assert_socket_safe(&path);
        }
        path
    }

    /// Build + start one pool quartet for a key. Runs OUTSIDE the map lock.
    async fn build_entry(
        &self,
        vhost_name: &str,
        key: &PoolKey,
        jail: &JailConfig,
        socket_path: &Path,
    ) -> std::io::Result<PoolEntry> {
        // Clone the template and re-target it: the resolved jail (credentials +
        // chroot) and the per-key socket. The default key keeps the all-None jail
        // (today's behavior). For jailed keys, jail.credentials drives the drop and
        // jail.chroot drives the chroot+chdir (see SupervisorConfig::jail docs).
        // EXTERNAL mode: the lsphp master is a separate persistent process. Build a
        // client pool that dials the existing socket — no spawn, no supervisor, no
        // monitor. The mapped generation epoch invalidates idle and checked-out
        // connections at the standalone supervisor's promotion boundary. A small
        // watcher observes promotions even when no request touches the client pool.
        if self.external {
            let external_generation = self.external_generation.read().clone();
            let mut pool =
                LsapiPool::from_uds(socket_path, self.params.max_conns, self.params.init_timeout)
                    .idle_ttl(self.params.idle_ttl)
                    .retry_timeout(self.params.retry_timeout)
                    .with_circuit_breaker();
            if let Some(source) = external_generation.as_ref() {
                pool = pool.external_generation(source.clone());
            }
            let pool = Arc::new(pool);
            let external_generation_watcher = external_generation
                .is_some()
                .then(|| ExternalGenerationWatcher::spawn(pool.clone()));
            let handler = Arc::new(
                Lsapi::new(pool.clone())
                    .max_body(self.params.max_body)
                    .body_buffer_budget(self.params.body_budget.clone())
                    .base_env(self.params.base_env.clone())
                    // EXTERNAL mode has no Monitor to source the Tier-1 deadline from
                    // (supervised mode gets it via `.monitor(...)`), so apply the
                    // configured `maxProcessTime` directly — else an external pool
                    // enforces no per-request processing deadline at all.
                    .max_process_time(self.params.max_process_time),
            );
            tracing::info!(
                vhost = %vhost_name,
                socket = %socket_path.display(),
                "lsphp EXTERNAL pool wired (client-only; master owned by httpjet-lsphp)"
            );
            return Ok(PoolEntry {
                handler,
                pool,
                external_generation_watcher,
                supervised: None,
            });
        }

        let mut sup_cfg = self.template.clone();
        sup_cfg.socket_path = socket_path.to_path_buf();
        sup_cfg.jail = jail.clone();

        // One shutdown token shared by the supervisor's kill-loop wait and the
        // monitor's ticker (#29): cancelling it (cancel-before-drain, below) cuts a
        // hung kill_and_restart short instead of pinning the monitor for ~25s.
        let cancel = CancellationToken::new();
        let mut supervisor = LsphpSupervisor::new(sup_cfg);
        supervisor.set_cancel(cancel.clone());
        // Adopt the systemd socket-activated listen fd for the DEFAULT pool, if one was
        // installed (standalone `httpjet lsphp`). The supervisor then holds it across
        // restarts and never binds/unlinks the socket path. Jailed/non-default keys always
        // self-bind their own generated sockets.
        if key.is_default() {
            if let Some(fd) = self.listen_fd.lock().take() {
                supervisor = supervisor.with_listen_fd(fd);
            }
        }
        let pool = Arc::new(
            LsapiPool::from_uds(socket_path, self.params.max_conns, self.params.init_timeout)
                .idle_ttl(self.params.idle_ttl)
                .retry_timeout(self.params.retry_timeout),
        );
        let owner_hook = key
            .is_default()
            .then(|| self.default_promotion_hook.read().clone())
            .flatten();
        let promotion_pool = pool.clone();
        assert!(
            supervisor.set_promotion_hook(Arc::new(move |generation, marker| {
                if let Some(hook) = &owner_hook {
                    hook(generation, marker);
                }
                promotion_pool.bump_generation(generation);
            }))
        );
        let supervisor = Arc::new(supervisor);
        supervisor.start().await?;

        // Monitor: the single restart authority for THIS pool.
        let mut mon_cfg = MonitorConfig::new(supervisor.clone(), pool.clone());
        mon_cfg.idle_ttl = self.params.idle_ttl;
        mon_cfg.max_process_time = self.params.max_process_time;
        mon_cfg.cancel = Some(cancel.clone());
        let (monitor, ticker) = Monitor::spawn(mon_cfg);

        let handler = Arc::new(
            Lsapi::new(pool.clone())
                .max_body(self.params.max_body)
                .body_buffer_budget(self.params.body_budget.clone())
                .base_env(self.params.base_env.clone())
                .monitor(monitor),
        );

        tracing::info!(
            vhost = %vhost_name,
            socket = %socket_path.display(),
            default_pool = key.is_default(),
            "lsphp pool started (monitor up)"
        );

        Ok(PoolEntry {
            handler,
            pool: pool.clone(),
            external_generation_watcher: None,
            supervised: Some(Supervised {
                supervisor,
                cancel,
                ticker: parking_lot::Mutex::new(Some(ticker)),
            }),
        })
    }

    /// Drain every started pool for shutdown, preserving the Phase-3
    /// cancel-before-drain semantics per pool: cancel the monitor ticker, join it
    /// (bounded), then drain the supervisor. Slots that never started are skipped.
    ///
    /// # Shutdown-race safety
    /// A single snapshot is NOT enough. A concurrent first-request can be between
    /// inserting its `EntrySlot` (done under the write lock) and finishing
    /// `cell.get_or_try_init` (which spawns the lsphp master + Monitor ticker,
    /// done OUTSIDE the lock). Such a slot may be in the snapshot but with an
    /// un-initialized cell (so we'd skip it), then spawn its pool right after —
    /// orphaning the lsphp child + a forever-ticking Monitor.
    ///
    /// We close this two ways: (1) set `draining` under the write lock so NO new
    /// slot can be inserted once shutdown begins (`handler_for` rejects it); and
    /// (2) loop the snapshot+drain until a full pass starts no further pool. Each
    /// slot is drained at most once (tracked via the cancel token having been
    /// fired), and any in-flight `get_or_try_init` either completes (then the
    /// next pass drains it) or errors out. The loop terminates because the set of
    /// slots is fixed once `draining` is set (no new inserts) and is bounded.
    pub async fn drain_all(&self) -> std::io::Result<()> {
        // Flip the draining flag under the write lock. After this, handler_for
        // cannot insert a NEW slot (it checks `draining` under the same lock),
        // so the slot set is now frozen — only already-inserted slots remain,
        // each of which we WILL observe in the snapshot below.
        {
            let _guard = self.entries.write();
            self.draining.store(true, Ordering::Release);
        }

        // Track which keys we've already drained so a re-snapshot pass does not
        // double-drain (and double-fire the cancel token).
        let mut drained: std::collections::HashSet<PoolKey> = std::collections::HashSet::new();
        let mut first_error: Option<std::io::Error> = None;

        // Bound the wait for a slot that is mid-start. Normally an in-flight
        // get_or_try_init finishes within a poll or two; but if a start
        // *permanently failed* (Err leaves the cell un-initialized and the
        // caller does not retry under draining) the cell never populates. We
        // wait a few yields, then give up on it — the supervisor's own Drop is
        // the backstop for any child that did manage to spawn. This keeps the
        // loop bounded.
        let mut idle_passes: u32 = 0;
        const MAX_IDLE_PASSES: u32 = 1024;

        loop {
            // Snapshot the slots so we don't hold the map lock across awaits.
            let slots: Vec<Arc<EntrySlot>> = {
                let guard = self.entries.read();
                guard.values().cloned().collect()
            };

            let mut made_progress = false;
            let mut pending_start = false;

            for slot in slots {
                if drained.contains(&slot.key) {
                    continue;
                }
                // Only started slots have a PoolEntry. An un-started slot is
                // either (a) never going to start (handler_for already rejected
                // it, or its start failed and won't retry now that we're
                // draining) or (b) a first-request still inside
                // get_or_try_init that will finish imminently. We can't tell the
                // two apart from here, so we note that a start MIGHT still be
                // pending and re-snapshot after this pass. The `draining` flag
                // guarantees no NEW slot appears, so this loop is bounded.
                let Some(entry) = slot.cell.get() else {
                    pending_start = true;
                    continue;
                };
                drained.insert(slot.key.clone());
                made_progress = true;

                if let Some(watcher) = entry.external_generation_watcher.as_ref() {
                    if let Err(error) = watcher.stop().await {
                        tracing::warn!(%error, "external lsphp generation watcher failed to stop");
                        first_error.get_or_insert(error);
                    }
                }

                // External pools have no supervisor/monitor of ours to drain (the
                // separate httpjet-lsphp process owns the master + its lifecycle).
                let Some(sup) = entry.supervised.as_ref() else {
                    tracing::debug!(socket = %slot.socket_path.display(), "external lsphp pool: nothing to drain");
                    continue;
                };

                // 1. Cancel the ticker BEFORE draining so the monitor does not
                //    fight the intentional stop with a restart.
                sup.cancel.cancel();
                // 2. JOIN the ticker (bounded) so an in-flight do_restart/
                //    kill_and_restart cannot race drain() — which could otherwise
                //    orphan/double-spawn lsphp or clobber NotStarted. Cancellation
                //    is only observed at the ticker's select! point, so a restart
                //    already in flight runs to completion first. Bounded so a
                //    wedged restart cannot hang shutdown forever; the supervisor's
                //    own Drop is the final backstop for the child.
                // Take the JoinHandle out (dropping the guard immediately) so the
                // parking_lot guard is never held across the join `.await`.
                let ticker = sup.ticker.lock().take();
                if let Some(ticker) = ticker {
                    let join_budget = Duration::from_secs(30);
                    match tokio::time::timeout(join_budget, ticker).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::warn!(error = %e, "lsphp monitor ticker join error"),
                        Err(_) => {
                            let error = std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                format!("lsphp monitor did not quiesce within {join_budget:?}"),
                            );
                            tracing::warn!(%error, "draining supervisor anyway");
                            first_error.get_or_insert(error);
                        }
                    }
                }
                // 3. Drain the supervisor (graceful SIGUSR1 then reap). Use drain_graceful:
                //    the shutdown token was fired in step 1 to stop the ticker, so plain
                //    drain() would observe it and SIGKILL immediately, skipping the worker's
                //    grace for in-flight requests (#29 regression). The ticker is already
                //    joined here, so nothing races this final drain.
                match sup.supervisor.drain_graceful().await {
                    Ok(()) => tracing::info!(
                        socket = %slot.socket_path.display(),
                        default_pool = slot.key.is_default(),
                        "lsphp pool drained"
                    ),
                    Err(error) => {
                        tracing::error!(
                            socket = %slot.socket_path.display(),
                            default_pool = slot.key.is_default(),
                            %error,
                            "lsphp pool failed to drain completely"
                        );
                        first_error.get_or_insert(error);
                    }
                }
            }

            // Done when this pass drained nothing AND no slot is mid-start. If a
            // slot is still mid-start (cell not yet initialized) we must
            // re-snapshot so its freshly-spawned pool gets drained rather than
            // orphaned. Yield to let in-flight get_or_try_init make progress.
            if !pending_start {
                break;
            }
            if made_progress {
                // Real work happened this pass; reset the idle budget and
                // re-snapshot immediately.
                idle_passes = 0;
                continue;
            }
            // No progress and a start still pending: yield to let the in-flight
            // get_or_try_init advance, but bound the total idle waiting so a
            // permanently-failed (never-retried) start cannot wedge shutdown.
            idle_passes += 1;
            if idle_passes >= MAX_IDLE_PASSES {
                tracing::warn!(
                    "lsphp registry drain: a pool slot stayed mid-start after \
                     {MAX_IDLE_PASSES} passes; abandoning it (supervisor Drop is the backstop)"
                );
                first_error.get_or_insert_with(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "lsphp pool slot stayed mid-start during registry drain",
                    )
                });
                break;
            }
            tokio::task::yield_now().await;
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// Assert a generated socket path is not under a production tree. Panics in R&D
/// if the invariant is violated — a generated path must always be under `/tmp`.
fn assert_socket_safe(path: &Path) {
    for forbidden in FORBIDDEN_SOCKET_PREFIXES {
        assert!(
            !path.starts_with(forbidden),
            "BUG: generated lsphp socket {} must never live under {} (R&D safety)",
            path.display(),
            forbidden
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    fn cmd() -> PathBuf {
        PathBuf::from("/usr/local/lsws/lsphp8/bin/lsphp")
    }

    #[test]
    fn default_jail_maps_to_default_key() {
        // The all-None jail (suEXEC off / non-root / no isolation) collapses to
        // the canonical default key -> exactly one shared pool.
        let key = PoolKey::from_jail(&cmd(), &JailConfig::default());
        assert!(key.is_default());
        assert_eq!(key, PoolKey::default());
        assert_eq!(key.sanitized(), "php");
    }

    #[test]
    fn distinct_credentials_get_distinct_keys() {
        let a = JailConfig {
            credentials: Some(Credentials {
                uid: 1000,
                gid: 1000,
            }),
            ..Default::default()
        };
        let b = JailConfig {
            credentials: Some(Credentials {
                uid: 1001,
                gid: 1001,
            }),
            ..Default::default()
        };
        let ka = PoolKey::from_jail(&cmd(), &a);
        let kb = PoolKey::from_jail(&cmd(), &b);
        assert_ne!(ka, kb);
        assert!(!ka.is_default());
        assert!(!kb.is_default());
    }

    #[test]
    fn same_credentials_dedupe_to_one_key() {
        let a = JailConfig {
            credentials: Some(Credentials {
                uid: 1000,
                gid: 1000,
            }),
            ..Default::default()
        };
        let b = JailConfig {
            credentials: Some(Credentials {
                uid: 1000,
                gid: 1000,
            }),
            ..Default::default()
        };
        assert_eq!(
            PoolKey::from_jail(&cmd(), &a),
            PoolKey::from_jail(&cmd(), &b)
        );
    }

    #[test]
    fn chroot_differentiates_keys() {
        let base = Credentials {
            uid: 1000,
            gid: 1000,
        };
        let a = JailConfig {
            credentials: Some(base),
            chroot: Some(std::ffi::CString::new("/jail/a").unwrap()),
            ..Default::default()
        };
        let b = JailConfig {
            credentials: Some(base),
            chroot: Some(std::ffi::CString::new("/jail/b").unwrap()),
            ..Default::default()
        };
        assert_ne!(
            PoolKey::from_jail(&cmd(), &a),
            PoolKey::from_jail(&cmd(), &b)
        );
    }

    #[test]
    fn namespaces_differentiate_keys() {
        // Same creds + chroot but different namespace isolation => distinct pools
        // (must NOT dedupe).
        let base = Credentials {
            uid: 1000,
            gid: 1000,
        };
        let a = JailConfig {
            credentials: Some(base),
            namespaces: NamespaceFlags {
                net: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let b = JailConfig {
            credentials: Some(base),
            namespaces: NamespaceFlags {
                net: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_ne!(
            PoolKey::from_jail(&cmd(), &a),
            PoolKey::from_jail(&cmd(), &b)
        );
    }

    #[test]
    fn same_namespaces_and_creds_dedupe() {
        let base = Credentials {
            uid: 1000,
            gid: 1000,
        };
        let ns = NamespaceFlags {
            mount: true,
            pid: true,
            ..Default::default()
        };
        let a = JailConfig {
            credentials: Some(base),
            namespaces: ns,
            ..Default::default()
        };
        let b = JailConfig {
            credentials: Some(base),
            namespaces: ns,
            ..Default::default()
        };
        assert_eq!(
            PoolKey::from_jail(&cmd(), &a),
            PoolKey::from_jail(&cmd(), &b)
        );
    }

    #[test]
    fn namespaces_only_jail_is_not_default_key() {
        // Defensive: a jail with no creds/chroot but namespaces set must not
        // collapse into the shared default pool.
        let jail = JailConfig {
            namespaces: NamespaceFlags {
                uts: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let key = PoolKey::from_jail(&cmd(), &jail);
        assert!(!key.is_default());
        assert_ne!(key, PoolKey::default());
    }

    #[test]
    fn generated_socket_is_under_tmp_and_safe() {
        let jail = JailConfig {
            credentials: Some(Credentials {
                uid: 1000,
                gid: 1000,
            }),
            ..Default::default()
        };
        let key = PoolKey::from_jail(&cmd(), &jail);
        let sock = PathBuf::from(format!("/tmp/php-httpjet-{}.sock", key.sanitized()));
        assert!(sock.starts_with("/tmp"));
        // Must not panic — this is the production-tree guard.
        assert_socket_safe(&sock);
    }

    #[test]
    #[should_panic(expected = "R&D safety")]
    fn forbidden_socket_path_panics() {
        assert_socket_safe(Path::new("/usr/local/lsws/extapp-sock/php8.sock"));
    }

    #[test]
    #[should_panic(expected = "R&D safety")]
    fn forbidden_web_socket_path_panics() {
        assert_socket_safe(Path::new("/web/something.sock"));
    }

    /// Build a registry whose template points at a non-existent lsphp so any
    /// accidental `start()` would fail loudly (the draining-guard test relies on
    /// `start()` NEVER being reached).
    fn test_registry() -> Arc<LsapiRegistry> {
        let php = hj_core::config::PhpConfig {
            handler_id: "lsphp".into(),
            command: cmd(),
            suffixes: vec!["php".into()],
            env: vec![],
            max_conns: 2,
            init_timeout: Duration::from_secs(1),
            retry_timeout: Duration::from_secs(0),
            pc_keep_alive_timeout: Duration::from_secs(0),
            backlog: 1024,
            run_on_startup: 1,
            mem_soft_limit: None,
            mem_hard_limit: None,
            detached_mode: false,
            max_process_time: None,
            cpu_limit_secs: None,
            proc_soft_limit: None,
            proc_hard_limit: None,
            max_idle_time: None,
            min_restart_interval: Duration::from_secs(10),
            max_restart_backoff: Duration::from_secs(30),
        };
        let sup_cfg = SupervisorConfig::from_php_config(&php, "/tmp/php-httpjet-test.sock", "", "");
        LsapiRegistry::new(sup_cfg, Duration::from_secs(30), None, 1024)
    }

    /// Once drain has begun, `handler_for` for a NOT-yet-present (new) key must
    /// be rejected WITHOUT inserting a slot or spawning lsphp. This is the
    /// shutdown-race fix: a first-request arriving during shutdown can no longer
    /// orphan a freshly-spawned lsphp master + Monitor ticker.
    #[tokio::test]
    async fn handler_for_rejects_new_key_while_draining() {
        let reg = test_registry();
        // Simulate shutdown having started.
        reg.draining.store(true, Ordering::Release);

        let jail = JailConfig {
            credentials: Some(Credentials {
                uid: 4242,
                gid: 4242,
            }),
            ..Default::default()
        };
        let key = PoolKey::from_jail(&reg.template.command, &jail);
        assert!(!key.is_default());

        let err = match reg.handler_for("vh-during-shutdown", &jail).await {
            Ok(_) => panic!("must be rejected while draining, not started"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("draining"),
            "unexpected error: {err}"
        );
        // CRUCIAL: no slot was inserted, so there is nothing to orphan and
        // drain_all (already complete) cannot have missed a pool.
        assert!(
            !reg.entries.read().contains_key(&key),
            "draining handler_for must NOT insert a new slot"
        );
    }

    /// A key that already has a slot present is still served from the existing
    /// slot during draining (no new insert needed); the guard only blocks NEW
    /// keys. Here the cell is never started so we only assert the slot-presence
    /// path is taken (no `draining` rejection for an existing slot).
    #[tokio::test]
    async fn drain_all_sets_flag_and_is_idempotent_when_empty() {
        let reg = test_registry();
        assert!(!reg.draining.load(Ordering::Acquire));
        // Nothing started; drain_all must complete promptly and set the flag.
        reg.drain_all().await.unwrap();
        assert!(reg.draining.load(Ordering::Acquire));
        // Calling again is harmless.
        reg.drain_all().await.unwrap();
    }

    #[tokio::test]
    async fn external_registry_uses_only_its_single_unjailed_socket() {
        let owned = test_registry();
        let reg = LsapiRegistry::new_external(
            owned.template.clone(),
            owned.params.idle_ttl,
            owned.params.max_process_time,
            owned.params.max_body,
        );
        let generation_path = std::env::temp_dir().join(format!(
            "hj-lsapi-registry-generation-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&generation_path);
        assert!(
            !reg.set_external_generation_file(&generation_path),
            "a missing generation file must degrade non-fatally"
        );
        let publisher =
            crate::pool::ExternalGenerationWriter::open_or_create(&generation_path).unwrap();
        publisher.publish(1);
        assert!(reg.set_external_generation_file(&generation_path));
        reg.start_default()
            .await
            .expect("the shared external pool should be wired without dialing");
        assert_eq!(reg.default_pool_stats().unwrap().generation_advances, 1);
        assert!(
            !reg.set_external_generation_file(&generation_path),
            "a started pool must not silently ignore a replacement mapping"
        );

        let jail = JailConfig {
            credentials: Some(Credentials {
                uid: 4242,
                gid: 4242,
            }),
            ..Default::default()
        };
        let err = match reg.handler_for("jailed-vhost", &jail).await {
            Ok(_) => panic!("a single external socket cannot impersonate a jailed pool"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("cannot honor a per-vhost jail"));

        let entries = reg.entries.read();
        assert_eq!(entries.len(), 1);
        let default = entries.get(&PoolKey::default()).expect("default slot");
        assert_eq!(default.socket_path, reg.template.socket_path);
        let _ = std::fs::remove_file(generation_path);
    }

    #[tokio::test]
    async fn quiet_external_generation_advance_prunes_idle_without_acquire() {
        let owned = test_registry();
        let socket_path = std::env::temp_dir().join(format!(
            "hj-lsapi-registry-quiet-{}.sock",
            std::process::id()
        ));
        let generation_path = std::env::temp_dir().join(format!(
            "hj-lsapi-registry-quiet-generation-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&generation_path);

        let mut template = owned.template.clone();
        template.socket_path = socket_path.clone();
        let reg = LsapiRegistry::new_external(
            template,
            owned.params.idle_ttl,
            owned.params.max_process_time,
            owned.params.max_body,
        );
        let publisher =
            crate::pool::ExternalGenerationWriter::open_or_create(&generation_path).unwrap();
        publisher.publish(1);
        assert!(reg.set_external_generation_file(&generation_path));

        let listener = UnixListener::bind(&socket_path).unwrap();
        let peer_closed = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut sink = Vec::new();
            stream.read_to_end(&mut sink).await.unwrap();
        });
        reg.start_default().await.unwrap();
        let slot = reg
            .entries
            .read()
            .get(&PoolKey::default())
            .cloned()
            .unwrap();
        let entry = slot.cell.get().unwrap();
        let pool = entry.pool.clone();

        let conn = pool.acquire().await.unwrap();
        drop(conn);
        assert_eq!(pool.idle_count(), 1);
        let stats_before = pool.stats();

        publisher.advance(1);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let stats = pool.stats();
                if pool.idle_count() == 0
                    && stats.generation_advances == stats_before.generation_advances + 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("quiet generation watcher did not observe promotion");

        let stats = pool.stats();
        assert_eq!(stats.stale_idle_drops, stats_before.stale_idle_drops + 1);
        tokio::time::timeout(Duration::from_secs(1), peer_closed)
            .await
            .expect("generation watcher did not close the idle socket")
            .unwrap();

        reg.drain_all().await.unwrap();
        assert!(
            entry
                .external_generation_watcher
                .as_ref()
                .unwrap()
                .task
                .lock()
                .is_none(),
            "registry shutdown must join the external generation watcher"
        );

        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(generation_path);
    }
}
