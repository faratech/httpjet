//! lsphp process supervisor.
//!
//! Creates a Unix-domain listening socket, hands it to a spawned `lsphp` process
//! on file descriptor 0 (`LSAPI_SOCK_FILENO`, per `lsapilib.c`), sets the LSAPI
//! controlling env vars (`LSAPI_CHILDREN`, `LSAPI_MAX_REQS`, ...), and — when the
//! supervisor runs as root — drops to the configured user/group in the child
//! before `exec`.
//!
//! # Safety / production note
//! For R&D, ALWAYS point [`SupervisorConfig::socket_path`] at a SEPARATE path
//! (e.g. `/tmp/php8-httpjet.sock`), never the production
//! `/usr/local/lsws/extapp-sock/php8.sock`. This module never touches the live
//! LiteSpeed sockets.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use crate::jail::{Credentials, JailConfig, resolve_credentials};
use crate::limits::ResourceLimits;
use crate::proto::{MAX_PACKET_LEN, PACKET_HEADER_LEN, PacketType, build_begin_request_framed};

/// Infallible epoch publication invoked for every inherited-listener promotion
/// after the old prefork master receives SIGUSR1 and before its grace wait.
pub type PromotionHook = Arc<dyn Fn(u64, &str) + Send + Sync + 'static>;

/// Graceful-stop window for a worker on restart/kill, mirroring OLS
/// `GRACE_TIMEOUT` (localworker.cpp). After SIGUSR1 we wait this long for the
/// worker to drain in-flight requests and exit on its own; if it is still alive
/// (or a shutdown cancellation cuts the wait short) it then gets SIGKILL.
const GRACE_TIMEOUT: Duration = Duration::from_secs(20);
const FORCE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Outer bound on quiescing one generation (normally milliseconds: SIGSTOP
/// cannot be blocked and the stopped master cannot fork). Keeps a pathological
/// process state from pinning the lifecycle lock past systemd's stop timeout.
const QUIESCE_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_SUPERVISED_CHILDREN: u32 = 2;
const GENERATION_MARKER_ENV: &str = "LSAPI_Z_HTTPJET_GENERATION_MARKER";

/// One application-level readiness attempt. A connect alone only proves the
/// kernel listener/backlog exists (especially under socket activation); a real
/// worker must accept, parse BEGIN_REQUEST, and write an LSAPI packet back.
const READY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Explicit lifecycle state of a worker pool, modeled on OLS's worker
/// `ST_NOTSTARTED` / `ST_GOOD` / `ST_BAD` states (extworker.cpp).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    /// Never started, or fully stopped/reaped — no live child.
    NotStarted,
    /// A start/restart is in flight (the spawn + readiness wait).
    Starting,
    /// Running and believed healthy.
    Good,
    /// Last start failed; `restart_failures` is non-zero and backoff applies.
    Bad,
    /// Being gracefully drained (SIGUSR1 sent, awaiting exit).
    Draining,
}

/// Where the listening LSAPI socket comes from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SocketSource {
    /// Bind + listen on `socket_path` on every start (the default: R&D, tests,
    /// non-socket-activated runs). The socket file is unlinked + rebound on each
    /// (re)start — which is the window a client can see ECONNREFUSED.
    #[default]
    Bind,
    /// Adopt an inherited listen fd (systemd socket activation). The fd itself is
    /// HELD by [`LsphpSupervisor`] (an `OwnedFd` is not `Clone`, so it cannot live
    /// in this `Clone` config) and re-`dup`'d onto fd 0 of each child across
    /// restarts. In this mode the supervisor never binds or unlinks `socket_path`
    /// — systemd owns it, so the socket survives a restart and clients never see
    /// ECONNREFUSED.
    Inherited,
}

/// Configuration for spawning an lsphp worker pool behind one socket.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Path to the `lsphp` binary (from `PhpConfig::command`).
    pub command: PathBuf,
    /// Listening UDS path lsphp will accept on (handed to it on fd 0).
    pub socket_path: PathBuf,
    /// Number of LSAPI children (`LSAPI_CHILDREN` / `PHP_LSAPI_CHILDREN`).
    /// Persistent supervision requires at least two: LSAPI only creates its
    /// prefork manager when the configured count is greater than one.
    pub children: u32,
    /// Requests a child handles before recycling (`LSAPI_MAX_REQS`). 0 = leave default.
    pub max_requests: u32,
    /// Extra environment (from `PhpConfig::env` / `ExtProcessor::env`).
    pub env: Vec<(String, String)>,
    /// listen(2) backlog. The kernel silently caps this to `net.core.somaxconn`,
    /// so a generous value just defers to that ceiling under a connect burst (e.g.
    /// a worker-pool swap) instead of refusing queued dials at a low fixed cap.
    pub backlog: u32,
    /// User to drop to when running as root (empty = no drop).
    pub user: String,
    /// Group to drop to when running as root (empty = use user's primary group).
    pub group: String,
    /// How long [`LsphpSupervisor::start`] waits for a worker to answer an LSAPI probe.
    pub start_timeout: Duration,
    /// Resource limits (`setrlimit`) installed in the child before `exec`.
    /// Default (all-`None`) is today's behavior: inherit the parent's limits.
    pub limits: ResourceLimits,
    /// Minimum interval between debounced restarts (OLS `tryRestart`'s 10s
    /// window). Used by [`LsphpSupervisor::restart_debounced`].
    pub min_restart_interval: Duration,
    /// Upper bound on the exponential restart backoff after repeated failures.
    pub max_restart_backoff: Duration,
    /// Fully-resolved privilege/isolation jail (parent-side). Default is the
    /// all-`None` jail = today's behavior (server user/group, no chroot). When
    /// `jail.credentials` is `Some`, the child drops to those creds (overriding
    /// the legacy `user`/`group` path); when `jail.chroot` is `Some`, the child
    /// chroots + chdir("/"). See [`JailConfig`].
    pub jail: JailConfig,
    /// How the listen socket is provided (default [`SocketSource::Bind`]).
    pub socket_source: SocketSource,
    /// How long to keep retrying a refused/missing-socket FRESH dial before a 502
    /// — the LiteSpeed `retryTimeout` (from `PhpConfig`). 0 ⇒ a bounded built-in
    /// floor (see [`crate::pool::LsapiPool::acquire`]); lets a request issued
    /// during an lsphp restart ride out the gap instead of failing.
    pub retry_timeout: Duration,
}

impl SupervisorConfig {
    /// Enforce the process-model invariants required by the persistent pool.
    ///
    /// With one child, lsphp skips its prefork manager and the sole process
    /// exits after serving the readiness request. Normalize both the typed
    /// value and any inherited aliases so reporting and the spawn environment
    /// describe the same effective concurrency.
    pub fn normalize(&mut self) {
        if self.children < MIN_SUPERVISED_CHILDREN {
            tracing::warn!(
                configured_children = self.children,
                effective_children = MIN_SUPERVISED_CHILDREN,
                "lsphp persistent supervision requires at least two children"
            );
            self.children = MIN_SUPERVISED_CHILDREN;
        }
        let children = self.children.to_string();
        for (key, value) in &mut self.env {
            if key == "PHP_LSAPI_CHILDREN" || key == "LSAPI_CHILDREN" {
                *value = children.clone();
            }
        }
    }

    /// Build from a [`hj_core::config::PhpConfig`] plus an explicit (R&D) socket path.
    pub fn from_php_config(
        php: &hj_core::config::PhpConfig,
        socket_path: impl Into<PathBuf>,
        user: impl Into<String>,
        group: impl Into<String>,
    ) -> Self {
        // PHP_LSAPI_CHILDREN often comes through `env`; honor it if present.
        let children = php
            .env
            .iter()
            .find(|(k, _)| k == "PHP_LSAPI_CHILDREN" || k == "LSAPI_CHILDREN")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(php.max_conns.max(1));
        let max_requests = php
            .env
            .iter()
            .find(|(k, _)| k == "PHP_LSAPI_MAX_REQUESTS" || k == "LSAPI_MAX_REQS")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);
        let cpu = php.cpu_limit_secs.unwrap_or_default();
        let limits = ResourceLimits {
            mem_soft: php.mem_soft_limit,
            mem_hard: php.mem_hard_limit,
            cpu_soft_secs: cpu.soft,
            cpu_hard_secs: cpu.hard,
            nproc_soft: php.proc_soft_limit,
            nproc_hard: php.proc_hard_limit,
        };
        let mut config = SupervisorConfig {
            command: php.command.clone(),
            socket_path: socket_path.into(),
            children,
            max_requests,
            env: php.env.clone(),
            backlog: php.backlog,
            user: user.into(),
            group: group.into(),
            start_timeout: php.init_timeout.max(Duration::from_secs(1)),
            limits,
            min_restart_interval: php.min_restart_interval,
            max_restart_backoff: php.max_restart_backoff,
            // Default jail = today's behavior (no drop beyond the legacy
            // user/group path, no chroot). The registry stage (Phase 4) builds a
            // real jail via JailConfig::resolve and sets it here.
            jail: JailConfig::default(),
            socket_source: SocketSource::Bind,
            retry_timeout: php.retry_timeout,
        };
        config.normalize();
        config
    }
}

/// Mutable lifecycle inner state, guarded by a single mutex. The lock is never
/// held across an `.await`; async paths clone out what they need (pid, state,
/// generation) or drop the guard before awaiting.
struct Inner {
    child: Option<Child>,
    child_marker: Option<String>,
    /// Markers whose direct master died outside a controlled drain. Detached
    /// listener holders remain owned until the next lifecycle pass reaps them.
    retired_markers: Vec<String>,
    state: WorkerState,
    /// Monotonic counter bumped on every successful (re)start; lets callers
    /// detect that the worker behind the socket was replaced.
    generation: u64,
    /// When the last (re)start was attempted — basis for debounce + backoff.
    last_restart: Instant,
    /// Consecutive failed restarts; drives exponential backoff. Reset to 0 on
    /// a successful start.
    restart_failures: u32,
}

struct RetiredMarkerGuard<'a> {
    inner: &'a Mutex<Inner>,
    marker: Option<String>,
}

impl<'a> RetiredMarkerGuard<'a> {
    fn new(inner: &'a Mutex<Inner>, marker: String) -> Self {
        Self {
            inner,
            marker: Some(marker),
        }
    }

    fn marker(&self) -> &str {
        self.marker
            .as_deref()
            .expect("retired marker guard must remain armed")
    }

    fn take(&mut self) -> String {
        self.marker
            .take()
            .expect("retired marker guard must remain armed")
    }

    fn disarm(&mut self) {
        self.marker = None;
    }
}

impl Drop for RetiredMarkerGuard<'_> {
    fn drop(&mut self) {
        if let Some(marker) = self.marker.take() {
            let mut inner = self.inner.lock();
            if !inner.retired_markers.contains(&marker) {
                inner.retired_markers.push(marker);
            }
        }
    }
}

struct ReadyChild<'a> {
    child: Option<Child>,
    marker: RetiredMarkerGuard<'a>,
}

impl<'a> ReadyChild<'a> {
    fn new(inner: &'a Mutex<Inner>, child: Child, marker: String) -> Self {
        Self {
            child: Some(child),
            marker: RetiredMarkerGuard::new(inner, marker),
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("ready child must remain owned before promotion")
    }

    fn child_id(&self) -> Option<u32> {
        self.child.as_ref().and_then(Child::id)
    }

    fn marker(&self) -> &str {
        self.marker.marker()
    }

    fn into_parts(mut self) -> (Child, String) {
        let child = self
            .child
            .take()
            .expect("ready child must remain owned before promotion");
        let marker = self.marker.take();
        (child, marker)
    }
}

struct StateRollback<'a> {
    inner: &'a Mutex<Inner>,
    restore: WorkerState,
    armed: bool,
}

impl<'a> StateRollback<'a> {
    fn new(inner: &'a Mutex<Inner>, restore: WorkerState) -> Self {
        let restore = match restore {
            WorkerState::Starting | WorkerState::Draining => WorkerState::Bad,
            state => state,
        };
        Self {
            inner,
            restore,
            armed: true,
        }
    }

    fn set_restore(&mut self, restore: WorkerState) {
        self.restore = restore;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StateRollback<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.inner.lock().state = self.restore;
        }
    }
}

/// A running (or restartable) lsphp worker pool, modeled as an explicit
/// lifecycle state machine.
pub struct LsphpSupervisor {
    cfg: SupervisorConfig,
    inner: Mutex<Inner>,
    /// Serializes every async lifecycle transition. `Inner` protects snapshots;
    /// this lock protects whole spawn/readiness/promote/drain transactions.
    lifecycle: AsyncMutex<()>,
    /// Number of generations that could not complete graceful drain and
    /// required pidfd-targeted SIGKILL cleanup.
    forced_cleanup_count: AtomicU64,
    promotion_hook: Mutex<Option<PromotionHook>>,
    subreaper_ready: bool,
    /// Cancelled on shutdown so the long grace waits inside [`Self::drain`]
    /// (which can be entered via [`Self::kill_and_restart`]) abort promptly
    /// instead of blocking the monitor ticker for the full grace window. Default
    /// is a never-fired token, so until the owner wires shutdown to it the
    /// behavior is byte-for-byte today's (wait out the grace).
    cancel: CancellationToken,
    /// The inherited listen socket, held for the supervisor's WHOLE lifetime when
    /// `cfg.socket_source == Inherited` (systemd socket activation). It is re-`dup`'d
    /// onto fd 0 of EVERY child across restarts — there is no rebind. `None` in
    /// `Bind` mode. Behind a `Mutex` only so the `&self` `start()` can borrow it to
    /// `dup` (it is never mutated after [`Self::with_listen_fd`]); kept OUTSIDE
    /// `Inner` so `start()`'s pre_exec path never touches the async-state lock.
    listen_fd: Mutex<Option<OwnedFd>>,
}

impl LsphpSupervisor {
    pub fn new(mut cfg: SupervisorConfig) -> Self {
        cfg.normalize();
        let subreaper_ready = ensure_child_subreaper();
        LsphpSupervisor {
            cfg,
            inner: Mutex::new(Inner {
                child: None,
                child_marker: None,
                retired_markers: Vec::new(),
                state: WorkerState::NotStarted,
                generation: 0,
                // Far enough in the past that the first restart is never
                // debounced away.
                last_restart: Instant::now() - Duration::from_secs(3600),
                restart_failures: 0,
            }),
            lifecycle: AsyncMutex::new(()),
            forced_cleanup_count: AtomicU64::new(0),
            promotion_hook: Mutex::new(None),
            subreaper_ready,
            cancel: CancellationToken::new(),
            listen_fd: Mutex::new(None),
        }
    }

    /// Install an inherited listen fd (systemd socket activation) and switch this
    /// supervisor to [`SocketSource::Inherited`]. The fd is HELD for the
    /// supervisor's lifetime and re-`dup`'d onto fd 0 of every child across
    /// restarts; the socket file is never bound or unlinked (systemd owns it).
    pub fn with_listen_fd(mut self, fd: OwnedFd) -> Self {
        self.cfg.socket_source = SocketSource::Inherited;
        *self.listen_fd.lock() = Some(fd);
        self
    }

    /// Install the shutdown [`CancellationToken`] whose firing makes [`Self::drain`]
    /// abandon its grace wait early. The owner (the monitor/registry) shares its
    /// own token here so an intentional stop is observed without waiting out the
    /// full `GRACE_TIMEOUT`.
    pub fn set_cancel(&mut self, cancel: CancellationToken) {
        self.cancel = cancel;
    }

    /// A clone of the shutdown cancellation token (for tests / wiring).
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn config(&self) -> &SupervisorConfig {
        &self.cfg
    }

    /// Current lifecycle state.
    pub fn state(&self) -> WorkerState {
        self.inner.lock().state
    }

    /// Monotonic generation counter (bumped on each successful start/restart).
    pub fn generation(&self) -> u64 {
        self.inner.lock().generation
    }

    pub fn forced_cleanup_count(&self) -> u64 {
        self.forced_cleanup_count.load(Ordering::Relaxed)
    }

    /// Install the hook shared by control- and monitor-driven promotions. Call
    /// before the first generation starts.
    pub fn set_promotion_hook(&self, hook: PromotionHook) -> bool {
        if self.inner.lock().state != WorkerState::NotStarted {
            return false;
        }
        *self.promotion_hook.lock() = Some(hook);
        true
    }

    /// PID of the live worker, if any.
    pub fn worker_pid(&self) -> Option<u32> {
        self.inner.lock().child.as_ref().and_then(|c| c.id())
    }

    /// Poll the child without blocking: reaps it if it has exited and flips a
    /// `Good` worker to `NotStarted` on exit. Returns the resulting state.
    ///
    /// Mirrors OLS `detectDiedPid` (localworker.cpp): a worker found dead is
    /// removed from the live set so the next request triggers a restart.
    pub fn poll_liveness(&self) -> WorkerState {
        let Ok(_lifecycle) = self.lifecycle.try_lock() else {
            return self.inner.lock().state;
        };
        let protected_child = self.inner.lock().child.as_ref().and_then(Child::id);
        match reap_adopted_curl_zombies(protected_child) {
            Ok(0) => {}
            Ok(reaped) => {
                tracing::debug!(
                    target: "hj_lsapi",
                    reaped,
                    "reaped adopted request subprocess zombies"
                );
            }
            Err(error) => {
                tracing::warn!(
                    target: "hj_lsapi",
                    %error,
                    "could not reap adopted request subprocess zombies"
                );
            }
        }
        let mut g = self.inner.lock();
        if matches!(g.state, WorkerState::Starting | WorkerState::Draining) {
            return g.state;
        }
        let exited = match g.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(_status)) => true, // exited + reaped by try_wait
                Ok(None) => false,         // still running
                Err(e) => {
                    // (item 7) A transient `try_wait` error (e.g. an EINTR or a
                    // /proc hiccup) is NOT proof the worker died — treating it as
                    // dead caused a spurious restart loop. Keep the worker and warn
                    // so the real error is visible instead of silently swallowed.
                    tracing::warn!(target: "hj_lsapi", error = %e, "lsphp try_wait failed; NOT treating worker as dead");
                    false
                }
            },
            None => false,
        };
        if exited {
            g.child = None;
            if let Some(marker) = g.child_marker.take() {
                g.retired_markers.push(marker);
            }
            g.state = WorkerState::NotStarted;
        }
        g.state
    }

    /// Start the first generation. Lifecycle operations are serialized across
    /// their complete async transaction, not merely their state mutations.
    pub async fn start(&self) -> io::Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        self.start_locked().await
    }

    async fn start_locked(&self) -> io::Result<()> {
        if !self.subreaper_ready {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "lsphp supervision requires PR_SET_CHILD_SUBREAPER",
            ));
        }
        let previous_state = {
            let mut inner = self.inner.lock();
            if inner.child.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "lsphp supervisor already has a live generation",
                ));
            }
            let previous_state = inner.state;
            inner.state = WorkerState::Starting;
            previous_state
        };
        let mut state_rollback = StateRollback::new(&self.inner, previous_state);
        if let Err(error) = self.cleanup_retired_markers().await {
            self.inner.lock().state = WorkerState::Bad;
            state_rollback.disarm();
            return Err(error);
        }

        match self.spawn_ready_child().await {
            Ok(candidate) => {
                let (child, marker) = candidate.into_parts();
                let promoted_marker = marker.clone();
                let generation = {
                    let mut inner = self.inner.lock();
                    inner.child = Some(child);
                    inner.child_marker = Some(marker);
                    inner.state = WorkerState::Good;
                    inner.generation += 1;
                    inner.restart_failures = 0;
                    inner.generation
                };
                state_rollback.disarm();
                if let Some(hook) = self.promotion_hook.lock().clone() {
                    hook(generation, &promoted_marker);
                }
                Ok(())
            }
            Err(error) => {
                let mut inner = self.inner.lock();
                inner.state = WorkerState::Bad;
                state_rollback.disarm();
                Err(error)
            }
        }
    }

    /// Spawn one candidate master and prove that a worker belonging to that
    /// master can execute an LSAPI request. The candidate remains local until
    /// the caller explicitly promotes it into `Inner`.
    async fn spawn_ready_child(&self) -> io::Result<ReadyChild<'_>> {
        // Guard: the lsphp binary must not be setuid/setgid or have file capabilities,
        // as the kernel silently clears PR_SET_PDEATHSIG at exec() time for such binaries.
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&self.cfg.command)?;
        let mode = meta.mode();
        if (mode & 0o4000) != 0 || (mode & 0o2000) != 0 {
            tracing::warn!(
                binary = %self.cfg.command.display(),
                "lsphp binary has setuid or setgid bit set; PR_SET_PDEATHSIG will be cleared at exec()"
            );
        }

        // Obtain the listen fd for THIS child. The rest of start() (pre_exec dup2 → fd 0,
        // spawn, the trailing `drop(listen_fd)`) is identical in both modes — only how we
        // acquire this per-start OwnedFd differs.
        let listen_fd: OwnedFd = match self.cfg.socket_source {
            SocketSource::Bind => {
                // Bind a fresh listening socket (remove any stale socket file first).
                let _ = std::fs::remove_file(&self.cfg.socket_path);
                let listener = StdUnixListener::bind(&self.cfg.socket_path)?;
                rustix::net::listen(&listener, self.cfg.backlog as i32)
                    .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
                listener.into()
            }
            SocketSource::Inherited => {
                // Systemd owns the socket. Duplicate it with CLOEXEC so the pre_exec source
                // closes at exec; dup2 onto fd 0 creates the one descriptor lsphp keeps. The
                // held original stays open in the supervisor for the next restart. Never bind
                // or unlink: clients can queue in the persistent socket during a worker swap.
                let guard = self.listen_fd.lock();
                let held = guard.as_ref().ok_or_else(|| {
                    io::Error::other("socket activation: inherited listen fd missing")
                })?;
                // systemd applies Backlog only when it initially creates the
                // socket. A daemon-reload does not resize an already-active
                // listener, so repeat listen(2) here before every adoption. This
                // changes the live accept queue in place without replacing the
                // fd or its filesystem inode.
                rustix::net::listen(held, self.cfg.backlog as i32)
                    .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
                duplicate_listen_fd(held)?
            }
        };

        let mut cmd = Command::new(&self.cfg.command);
        cmd.stdin(Stdio::null()) // replaced by our dup2 in pre_exec
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            // (L1) Reap the child on Drop: the supervisor's `Drop` `start_kill()`s but never
            // waits, so without this a kill_on_drop'd tokio child would zombie until the tokio
            // reaper notices. `kill_on_drop` registers it with the runtime reaper so the SIGKILL
            // and the wait both happen when the `Child` handle drops.
            .kill_on_drop(true)
            .env_clear();

        // Dedicated-server worker policy: keep a WARM worker pool instead of
        // reaping idle workers and re-forking on demand. Without this, a request
        // landing on a freshly-forked (cold) worker pays fork + PHP init +
        // first-request bootstrap — the LSAPI TTFB the telemetry isolates. CHILDREN
        // stays the burst ceiling; cap the warm IDLE pool so it never pins that
        // much RAM (40 workers at the observed concurrency, not 250).
        cmd.env("LSAPI_AVOID_FORK", "1");
        cmd.env(
            "LSAPI_MAX_IDLE_CHILDREN",
            self.cfg.children.min(40).to_string(),
        );
        if self.cfg.max_requests > 0 {
            cmd.env("LSAPI_MAX_REQS", self.cfg.max_requests.to_string());
            cmd.env("PHP_LSAPI_MAX_REQUESTS", self.cfg.max_requests.to_string());
        }
        // Keep the listen socket; we want lsphp to accept on fd 0, not exit.
        cmd.env("LSAPI_KEEP_LISTEN", "1");
        for (k, v) in &self.cfg.env {
            cmd.env(k, v);
        }
        // The normalized count is authoritative over inherited aliases.
        cmd.env("LSAPI_CHILDREN", self.cfg.children.to_string());
        cmd.env("PHP_LSAPI_CHILDREN", self.cfg.children.to_string());
        let marker = next_generation_marker();
        // lsphp rewrites argv/process-title storage when a worker enters its
        // setsid accept loop. The first environment entry shares that storage
        // and can be partially clobbered, so keep the ownership token late in
        // the sorted LSAPI namespace. unset_lsapi_envs() removes only the
        // logical pointer before PHP dispatch; /proc/<pid>/environ retains the
        // original bytes used by the supervisor's family scan.
        cmd.env(GENERATION_MARKER_ENV, &marker);
        // Authoritative after the inherited env: readiness depends on an
        // already-warm worker ACKing immediately after accept(2), without a
        // synthetic PHP request. On-demand forks may instead send their PID frame;
        // either response is worker-originated and accepted by the probe below.
        cmd.env("LSAPI_ACCEPT_NOTIFY", "1");
        // A minimal PATH so PHP's exec()/proc_open() behave.
        cmd.env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );

        // Resolve the effective credentials in the PARENT.
        //
        // Precedence: a fully-resolved jail (from JailConfig::resolve, set by the
        // registry stage) wins. Its credentials already passed the
        // never-root + uid_min/gid_min invariants. Otherwise fall back to the
        // legacy user/group drop (only when we are root and a user is named) —
        // byte-for-byte today's behavior.
        let target: Option<Credentials> = if let Some(cred) = self.cfg.jail.credentials {
            Some(cred)
        } else if rustix::process::getuid().is_root() && !self.cfg.user.is_empty() {
            Some(resolve_credentials(&self.cfg.user, &self.cfg.group)?)
        } else {
            None
        };

        // Capture chroot/chdir as Copy/CString values (parent-resolved). The
        // child does NO path allocation — these are pre-encoded CStrings.
        let chroot: Option<CString> = self.cfg.jail.chroot.clone();
        let chdir: Option<CString> = self.cfg.jail.chdir.clone();

        let raw_listen_fd = listen_fd.as_raw_fd();
        let limits = self.cfg.limits;
        // Capture OUR pid (the child's parent) in the PARENT, before fork. The child
        // compares its post-prctl `getppid()` against this to detect a parent that
        // died anywhere in the fork()→prctl() window — baselining `getppid()` inside
        // the child (post-fork) instead would miss a death before the child's first
        // getppid(), since the child is already reparented and both reads return the
        // reaper's pid (#127).
        let parent_pid = rustix::process::getpid();
        // Namespace flags are `Copy` and resolved in the parent (before fork), so
        // the child only issues a single async-signal-safe `unshare_unsafe` call.
        // Empty (the default jail) => no unshare at all (today's behavior).
        let ns_flags = self.cfg.jail.namespaces;
        // SAFETY: the closure runs in the freshly-forked child before exec. It
        // only calls async-signal-safe-ish syscalls (dup2/unshare/setgroups/
        // setgid/chroot/chdir/setuid/setrlimit). No heap allocation, no locks, no
        // name resolution. The closure captures `raw_listen_fd` (a plain RawFd),
        // not the OwnedFd itself; `listen_fd` lives in this OUTER scope and stays
        // open across the spawn, only dropped at the explicit `drop(listen_fd)`
        // below — so the fd `raw_listen_fd` names is valid when the child dup2s
        // it. The CStrings were built in the parent and `ns_flags` is a Copy
        // value captured pre-fork.
        unsafe {
            cmd.pre_exec(move || {
                // --- Step 1: die when our parent (httpjet) dies, so lsphp
                // workers never orphan if httpjet is killed without a graceful
                // drain.
                let _ = rustix::process::set_parent_process_death_signal(Some(
                    rustix::process::Signal::TERM,
                ));
                // Post-prctl recheck against the parent's OWN pid captured before fork:
                // if httpjet died anywhere in the fork()→prctl() window the PDEATHSIG is
                // armed against a since-dead parent (never fires), so `getppid()` no longer
                // matches and we exit now rather than orphaning. `_exit` (async-signal-safe)
                // — NOT std::process::exit, which runs atexit handlers / flushes stdio /
                // touches the allocator lock, any of which can be held (inherited locked) in
                // this forked child of a multithreaded process and deadlock it (#126).
                if rustix::process::getppid() != Some(parent_pid) {
                    // SAFETY (within the enclosing pre_exec `unsafe`): `_exit` is
                    // async-signal-safe; no allocation, no locks, no atexit handlers —
                    // the only correct way to leave a forked child here.
                    libc::_exit(1);
                }
                // --- Step 2: hand the listen socket to lsphp on fd 0
                // (LSAPI_SOCK_FILENO). dup2 clears O_CLOEXEC, so it survives exec.
                let borrowed = std::os::fd::BorrowedFd::borrow_raw(raw_listen_fd);
                rustix::stdio::dup2_stdin(borrowed)
                    .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;

                // --- Step 2b (Phase 5a): unshare the configured Linux namespaces
                // here — AFTER dup2 (so the listen fd is already on fd 0) and
                // BEFORE the RLIMIT_NPROC / setuid drop (unshare needs
                // CAP_SYS_ADMIN, which we still hold as root). `ns_flags` is a
                // `Copy` value captured before the fork, so this is async-signal
                // safe (no allocation, no locks, no name lookups). The result is
                // CHECKED: a failed unshare aborts the child rather than running
                // the worker without the requested isolation.
                //
                // Notes:
                //  * NEWPID is deliberately NEVER part of `ns_flags` here:
                //    `to_unshare_flags`/`from_policy` strip it. The lsphp master
                //    would stay in the old PID namespace and the FIRST worker it
                //    forks would become PID 1 of the new one; that worker's
                //    routine recycling (LSAPI_MAX_REQS / idle pruning) would then
                //    SIGKILL the whole sibling pool. See `NamespaceFlags::pid`.
                //  * NEWNET yields a loopback-only namespace, breaking outbound
                //    PHP networking — hence the most opt-in flag.
                //  * No mount choreography in 5a: chroot already provides the
                //    worker's path view, so NEWNS here only detaches mount
                //    propagation (no remount/pivot_root).
                if !ns_flags.is_empty() {
                    // SAFETY: we pass only namespace flags (never UnshareFlags::
                    // FILES), and the child execs immediately afterwards, so the
                    // fd-table caveat on `unshare_unsafe` does not apply.
                    rustix::thread::unshare_unsafe(ns_flags.to_unshare_flags())
                        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
                }

                // --- Step 3: RLIMIT_NPROC before the setuid drop (binds for the
                // worker uid the instant it runs; matches OLS ordering).
                limits.apply_pre_setuid()?;

                if let Some(cred) = &target {
                    // --- Step 4: drop supplementary groups to just the target
                    // gid (must happen while still privileged).
                    rustix::thread::set_thread_groups(&[rustix::thread::Gid::from_raw(cred.gid)])
                        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
                    // --- Step 5: setgid (before losing root via setuid).
                    rustix::thread::set_thread_gid(rustix::thread::Gid::from_raw(cred.gid))
                        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
                    // --- Step 6: chroot + chdir, BETWEEN setgid and setuid (so
                    // chroot still has the privilege it needs; chdir into the new
                    // root immediately after).
                    if let Some(root) = &chroot {
                        rustix::process::chroot(root.as_c_str())
                            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
                        // After chroot we ALWAYS chdir (the resolved chdir is
                        // "/" — the new root).
                        if let Some(dir) = &chdir {
                            rustix::process::chdir(dir.as_c_str())
                                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
                        }
                    }
                    // --- Step 7: setuid LAST (point of no return for privilege).
                    rustix::thread::set_thread_uid(rustix::thread::Uid::from_raw(cred.uid))
                        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
                } else if let Some(dir) = &chdir {
                    // No credential drop but a chdir was requested (rare/no-op in
                    // the default jail, which only sets chdir alongside a chroot).
                    rustix::process::chdir(dir.as_c_str())
                        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
                }

                // --- Step 8: RLIMIT_AS / RLIMIT_CPU AFTER the drop (not
                // uid-relative; matches OLS, which sets RLIMIT_AS post uid/chroot).
                limits.apply_post_setuid()?;
                Ok(())
            });
        }

        let child = cmd.spawn()?;
        let mut candidate = ReadyChild::new(&self.inner, child, marker);
        // Drop our copy of the listen fd; the child has its dup on fd 0.
        drop(listen_fd);
        let master_pid = candidate
            .child_id()
            .ok_or_else(|| io::Error::other("spawned lsphp candidate has no pid"))?;

        if let Err(error) = self.wait_until_ready(master_pid).await {
            let marker = candidate.marker().to_string();
            if let Err(cleanup_error) = force_kill_generation(candidate.child_mut(), &marker).await
            {
                return Err(io::Error::other(format!(
                    "lsphp candidate readiness failed ({error}); generation cleanup also failed ({cleanup_error})"
                )));
            }
            candidate.marker.disarm();
            return Err(error);
        }
        Ok(candidate)
    }

    /// Probe until a worker attributable to `expected_master` executes a real
    /// LSAPI request (or, where a chroot makes the probe script unavailable,
    /// returns lsphp's worker PID frame) or the timeout elapses.
    async fn wait_until_ready(&self, expected_master: u32) -> io::Result<()> {
        let script = match ReadinessScript::create(&self.cfg, expected_master) {
            Ok(script) => Some(script),
            Err(error)
                if self.cfg.jail.chroot.is_some() && error.kind() == io::ErrorKind::Unsupported =>
            {
                None
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("could not create lsphp readiness script: {error}"),
                ));
            }
        };
        let deadline = tokio::time::Instant::now() + self.cfg.start_timeout;
        let mut last_error = io::Error::new(io::ErrorKind::NotConnected, "no readiness attempt");
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "lsphp worker did not accept LSAPI at {:?}: {last_error}",
                        self.cfg.socket_path
                    ),
                ));
            }
            let attempt_budget = READY_PROBE_TIMEOUT.min(deadline - now);
            match tokio::time::timeout(
                attempt_budget,
                probe_worker_ready_once(
                    &self.cfg.socket_path,
                    expected_master,
                    script.as_ref().map(|script| script.path.as_path()),
                ),
            )
            .await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => last_error = e,
                Err(_) => {
                    last_error = io::Error::new(
                        io::ErrorKind::TimedOut,
                        "connected socket produced no worker response",
                    )
                }
            }
            if tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }

    /// Is the child still alive? `Ok(true)` = running, `Ok(false)` = exited.
    pub fn is_alive(&self) -> io::Result<bool> {
        let mut guard = self.inner.lock();
        match guard.child.as_mut() {
            Some(child) => match child.try_wait()? {
                Some(_status) => Ok(false),
                None => Ok(true),
            },
            None => Ok(false),
        }
    }

    /// Gracefully drain: signal the child to terminate and reap it. lsphp exits
    /// its accept loop on SIGUSR1 after finishing in-flight requests.
    ///
    /// Cancel-safe: once the child leaves `Inner`, an ownership-marker guard
    /// retains the complete generation for a later forced cleanup and a state
    /// guard restores a stable state if the returned future is dropped.
    /// Graceful stop, ABORTABLE by the shutdown/abort token: SIGUSR1 the master, wait up
    /// to `GRACE_TIMEOUT` for it to exit OR until `self.cancel` fires, then SIGKILL + reap.
    /// Used by the respawn paths ([`Self::restart_debounced`], [`Self::kill_and_restart`])
    /// so a respawn/kill in flight when shutdown begins can't pin the monitor ticker.
    pub async fn drain(&self) -> io::Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        self.drain_inner_locked(true).await
    }

    /// Graceful stop that ALWAYS honors the full SIGUSR1-to-grace window, IGNORING the abort
    /// token. Used for the FINAL shutdown drain (registry `drain_all`): there the token is
    /// already fired (to stop the ticker), so [`Self::drain`] would skip the grace and
    /// SIGKILL the worker immediately — killing in-flight requests (#29 regression). This
    /// variant gives the worker its `GRACE_TIMEOUT` to finish them.
    pub async fn drain_graceful(&self) -> io::Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        self.drain_inner_locked(false).await
    }

    async fn drain_inner_locked(&self, abortable: bool) -> io::Result<()> {
        let previous_state = {
            let mut g = self.inner.lock();
            let previous_state = g.state;
            g.state = WorkerState::Draining;
            previous_state
        };
        let mut state_rollback = StateRollback::new(&self.inner, previous_state);
        if let Err(error) = self.cleanup_retired_markers().await {
            let mut g = self.inner.lock();
            g.state = if g.child.is_some() {
                WorkerState::Good
            } else {
                WorkerState::Bad
            };
            state_rollback.disarm();
            return Err(error);
        }
        let (mut child, marker) = {
            let mut g = self.inner.lock();
            (g.child.take(), g.child_marker.take())
        };
        state_rollback.set_restore(WorkerState::Bad);
        let mut marker = marker.map(|marker| RetiredMarkerGuard::new(&self.inner, marker));
        let drain_result = match (child.as_mut(), marker.as_mut()) {
            (Some(child), Some(marker)) => {
                drain_generation(
                    child,
                    marker.marker(),
                    &self.cfg.socket_path,
                    Some(&self.cancel),
                    abortable,
                    &self.forced_cleanup_count,
                )
                .await
            }
            (Some(_), None) => Err(io::Error::other(
                "live lsphp generation is missing its ownership marker",
            )),
            (None, Some(marker)) => force_cleanup_marker(marker.marker()).await,
            (None, None) => Ok(()),
        };
        if let Err(error) = drain_result {
            self.inner.lock().state = WorkerState::Bad;
            state_rollback.disarm();
            return Err(error);
        }
        if let Some(marker) = marker.as_mut() {
            marker.disarm();
        }
        // Only unlink a socket we bound ourselves. Under socket activation systemd owns the
        // socket file and must keep it across the drain so the next adopter (and any client
        // dialing during the swap) still finds it.
        if matches!(self.cfg.socket_source, SocketSource::Bind) {
            let _ = std::fs::remove_file(&self.cfg.socket_path);
        }
        {
            let mut g = self.inner.lock();
            // If nobody started a new child meanwhile, we are fully stopped.
            if g.child.is_none() {
                g.state = WorkerState::NotStarted;
            }
        }
        state_rollback.disarm();
        Ok(())
    }

    /// Restart: drain then start again. Prefer [`Self::restart_debounced`] for
    /// liveness-driven recovery; this is the unconditional variant.
    pub async fn restart(&self) -> io::Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        if self.can_hot_reload() {
            self.hot_reload_locked(|_| {}).await.map(|_| ())
        } else {
            self.drain_inner_locked(true).await?;
            self.start_locked().await
        }
    }

    /// Debounced restart, mirroring OLS `tryRestart`/`restart` (localworker.cpp):
    ///
    /// - If a (re)start is already in flight (`Starting`) or a drain is running
    ///   (`Draining`), do nothing and return `Ok` — another path owns the
    ///   transition.
    /// - If less than `min_restart_interval` has elapsed since the last attempt,
    ///   skip (return `Ok`) — this is the 10s `tryRestart` window that prevents
    ///   restart storms under a steady stream of 503s.
    /// - Otherwise: mark `Starting`, drain the old child, apply exponential
    ///   backoff (`min_restart_interval * 2^restart_failures`, capped at
    ///   `max_restart_backoff`) on the failure path, then `start()`.
    ///   On success: `Good`, generation bumped (by `start`), failures reset.
    ///   On failure: `Bad`, failures incremented.
    ///
    /// The lock is never held across an `.await`.
    pub async fn restart_debounced(&self) -> io::Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        let backoff = {
            let mut g = self.inner.lock();
            match g.state {
                WorkerState::Starting | WorkerState::Draining => return Ok(()),
                _ => {}
            }
            if g.last_restart.elapsed() < self.cfg.min_restart_interval {
                // Within the debounce window — skip.
                return Ok(());
            }
            g.last_restart = Instant::now();
            // Compute backoff from the *prior* failure count before we attempt.
            backoff_for(
                self.cfg.min_restart_interval,
                g.restart_failures,
                self.cfg.max_restart_backoff,
            )
        };

        // Drain the old child (drain() manages its own Draining state, but we
        // already hold logical ownership of this transition via Starting; reset
        // back to Starting after drain so the post-start logic is unambiguous).
        // Backoff only matters when we've already failed at least once.
        if !backoff.is_zero() {
            tokio::time::sleep(backoff).await;
        }

        let result = if self.can_hot_reload() {
            self.hot_reload_locked(|_| {}).await.map(|_| ())
        } else {
            self.drain_inner_locked(true).await?;
            self.inner.lock().state = WorkerState::Starting;
            self.start_locked().await
        };
        match result {
            Ok(()) => {
                // start() already set Good + bumped generation.
                self.inner.lock().restart_failures = 0;
                Ok(())
            }
            Err(e) => {
                let mut g = self.inner.lock();
                // Candidate-first failure leaves the old generation serving.
                // Only a no-child failure is a genuinely Bad pool.
                g.state = if g.child.is_some() {
                    WorkerState::Good
                } else {
                    WorkerState::Bad
                };
                g.restart_failures = g.restart_failures.saturating_add(1);
                Err(e)
            }
        }
    }

    /// Forceful restart: gracefully signal the wedged worker, reap it, and start a fresh
    /// one — UNCONDITIONALLY, bypassing the [`Self::restart_debounced`] window.
    /// Used when a worker is wedged (e.g. exceeded `maxProcessTime`) rather than
    /// merely dead. Mirrors OLS `killProcess` + `restart`.
    ///
    /// This delegates to [`Self::drain`] (which takes `g.child`, sets `Draining`,
    /// signals + waits + reaps) followed by [`Self::start`]. A Tier-2 kill is an
    /// explicit decision that the worker MUST be replaced *now*, so the
    /// `min_restart_interval` debounce — meant only to dampen crash-loops — would
    /// be wrong here: it could silently refuse to respawn (leaving PHP dead and
    /// the state stuck `Good` with an un-reaped child) when a recent restart had
    /// just bumped `last_restart`. The debounce is therefore kept solely for the
    /// ordinary crash-respawn path via [`Self::restart_debounced`].
    pub async fn kill_and_restart(&self) -> io::Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        if self.can_hot_reload() {
            self.hot_reload_locked(|_| {}).await.map(|_| ())
        } else {
            self.drain_inner_locked(true).await?;
            self.start_locked().await
        }
    }

    /// Candidate-first replacement for a socket-activated pool. The old
    /// generation keeps accepting until a candidate worker is proven to belong
    /// to the newly spawned master. A failed candidate is killed without
    /// touching the old generation or generation counter.
    pub async fn hot_reload(&self) -> io::Result<u64> {
        self.hot_reload_with_promotion(|_| {}).await
    }

    /// As [`Self::hot_reload`], with an infallible hook invoked at the promotion
    /// boundary after the old master has received SIGUSR1 but before its grace
    /// wait. This is where clients publish the new epoch and clear stale pools.
    pub async fn hot_reload_with_promotion<F>(&self, on_promoted: F) -> io::Result<u64>
    where
        F: FnOnce(u64) + Send,
    {
        let _lifecycle = self.lifecycle.lock().await;
        self.hot_reload_locked(on_promoted).await
    }

    fn can_hot_reload(&self) -> bool {
        matches!(self.cfg.socket_source, SocketSource::Inherited)
            && self.inner.lock().child.is_some()
    }

    async fn hot_reload_locked<F>(&self, on_promoted: F) -> io::Result<u64>
    where
        F: FnOnce(u64),
    {
        if !self.subreaper_ready {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "candidate-first reload requires PR_SET_CHILD_SUBREAPER",
            ));
        }
        if !matches!(self.cfg.socket_source, SocketSource::Inherited) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "candidate-first lsphp reload requires an inherited listener",
            ));
        }
        self.cleanup_retired_markers().await?;
        let (old_state, old_master, old_marker) = {
            let mut inner = self.inner.lock();
            let child = inner.child.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "cannot hot-reload an unstarted lsphp pool",
                )
            })?;
            let master = child
                .id()
                .ok_or_else(|| io::Error::other("old lsphp generation has no live master pid"))?;
            let marker = inner.child_marker.clone().ok_or_else(|| {
                io::Error::other("old lsphp generation is missing its ownership marker")
            })?;
            let state = inner.state;
            inner.state = WorkerState::Starting;
            (state, master, marker)
        };
        let mut state_rollback = StateRollback::new(&self.inner, old_state);

        let mut candidate = match self.spawn_ready_child().await {
            Ok(candidate) => candidate,
            Err(error) => return Err(error),
        };

        // Prepare while the old generation is still authoritative in Inner.
        // The guard resumes every stopped acceptor if this future is cancelled,
        // the quiesce bound elapses, or any pre-commit validation fails.
        let quiesced = match quiesce_generation_bounded(&old_marker, Some(old_master)).await {
            Ok(quiesced) => quiesced,
            Err(error) => {
                if let Err(cleanup_error) = self.discard_candidate(&mut candidate).await {
                    return Err(io::Error::other(format!(
                        "could not quiesce old lsphp generation ({error}); candidate cleanup also failed ({cleanup_error})"
                    )));
                }
                return Err(error);
            }
        };

        let candidate_error = match candidate.child_mut().try_wait() {
            Ok(None) => None,
            Ok(Some(status)) => Some(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("ready lsphp candidate exited before promotion: {status}"),
            )),
            Err(error) => Some(io::Error::new(
                error.kind(),
                format!("could not revalidate ready lsphp candidate: {error}"),
            )),
        };
        let old_changed = {
            let inner = self.inner.lock();
            inner.child.as_ref().and_then(Child::id) != Some(old_master)
                || inner.child_marker.as_deref() != Some(old_marker.as_str())
        };
        if candidate_error.is_some() || old_changed {
            drop(quiesced);
            let error = candidate_error.unwrap_or_else(|| {
                io::Error::other("old lsphp generation changed during reload preparation")
            });
            if let Err(cleanup_error) = self.discard_candidate(&mut candidate).await {
                return Err(io::Error::other(format!(
                    "{error}; candidate cleanup also failed ({cleanup_error})"
                )));
            }
            return Err(error);
        }

        // Confirm every pinned old acceptor is signalable before the atomic
        // commit. Signal 0 performs the permission/object check without changing
        // process state.
        if let Err(error) = quiesced.signal_lsapi(0) {
            drop(quiesced);
            if let Err(cleanup_error) = self.discard_candidate(&mut candidate).await {
                return Err(io::Error::other(format!(
                    "old lsphp generation cannot be signalled ({error}); candidate cleanup also failed ({cleanup_error})"
                )));
            }
            return Err(error);
        }

        let (candidate_child, candidate_marker) = candidate.into_parts();
        let promoted_marker = candidate_marker.clone();
        let (mut old, committed_old_marker, generation) = {
            let mut inner = self.inner.lock();
            let old = inner.child.replace(candidate_child).expect("checked above");
            let committed_old_marker = inner
                .child_marker
                .replace(candidate_marker)
                .expect("checked above");
            let generation = inner.generation + 1;
            inner.generation = generation;
            inner.restart_failures = 0;
            inner.last_restart = Instant::now();
            inner.state = WorkerState::Good;
            (old, committed_old_marker, generation)
        };
        state_rollback.disarm();
        let mut retired = RetiredMarkerGuard::new(&self.inner, committed_old_marker);

        // The old acceptors remain SIGSTOP-quiesced across publication. Signal
        // only the prefork master: SIGUSR1 terminates a worker immediately, but
        // makes the master stop accepting while busy workers finish. Publishing
        // the epoch then closes their checked-out connections after response.
        let mut first_error = None;
        if let Err(error) = quiesced.signal_master(libc::SIGUSR1) {
            record_first_error(
                &mut first_error,
                "could not gracefully signal the retired lsphp master",
                error,
            );
        }
        if let Err(error) = quiesced.signal_idle_workers(libc::SIGUSR1, &self.cfg.socket_path) {
            record_first_error(
                &mut first_error,
                "could not gracefully signal retired idle lsphp workers",
                error,
            );
        }
        if let Some(hook) = self.promotion_hook.lock().clone() {
            hook(generation, &promoted_marker);
        }
        on_promoted(generation);
        let (master, tracked, resume_error) = quiesced.into_resumed();
        if let Some(error) = resume_error {
            record_first_error(
                &mut first_error,
                "could not resume every quiesced lsphp process",
                error,
            );
        }
        let result = finish_generation_drain(
            &mut old,
            retired.marker(),
            master,
            tracked,
            &self.cfg.socket_path,
            None,
            false,
            first_error,
            &self.forced_cleanup_count,
        )
        .await;
        if result.is_ok() {
            retired.disarm();
        }
        result.map(|()| generation)
    }

    async fn discard_candidate(&self, candidate: &mut ReadyChild<'_>) -> io::Result<()> {
        let marker = candidate.marker().to_string();
        match force_kill_generation(candidate.child_mut(), &marker).await {
            Ok(()) => {
                candidate.marker.disarm();
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    async fn cleanup_retired_markers(&self) -> io::Result<()> {
        self.cleanup_retired_markers_with_timeout(FORCE_CLEANUP_TIMEOUT)
            .await
    }

    async fn cleanup_retired_markers_with_timeout(&self, timeout: Duration) -> io::Result<()> {
        loop {
            let marker = self.inner.lock().retired_markers.first().cloned();
            let Some(marker) = marker else {
                return Ok(());
            };
            force_cleanup_marker_with_timeout(&marker, timeout).await?;
            self.inner
                .lock()
                .retired_markers
                .retain(|pending| pending != &marker);
        }
    }
}

fn duplicate_listen_fd(fd: &impl AsFd) -> io::Result<OwnedFd> {
    rustix::io::fcntl_dupfd_cloexec(fd, 3)
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

fn next_generation_marker() -> String {
    static NEXT_MARKER: AtomicU64 = AtomicU64::new(1);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT_MARKER.fetch_add(1, Ordering::Relaxed)
    )
}

struct ReadinessScript {
    path: PathBuf,
}

impl ReadinessScript {
    fn create(cfg: &SupervisorConfig, master_pid: u32) -> io::Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        if cfg.jail.chroot.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "readiness script is not visible inside a chroot",
            ));
        }
        let path = std::env::temp_dir().join(format!(
            ".httpjet-lsapi-ready-{}-{master_pid}.php",
            std::process::id()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(&path)?;
        file.write_all(b"<?php echo getmypid();")?;
        file.sync_all()?;
        Ok(Self { path })
    }
}

impl Drop for ReadinessScript {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn probe_worker_ready_once(
    path: &Path,
    expected_master: u32,
    script: Option<&Path>,
) -> io::Result<()> {
    let mut stream = tokio::net::UnixStream::connect(path).await?;
    if let Some(script) = script {
        let script = script.to_string_lossy().into_owned();
        let env = vec![
            ("SCRIPT_FILENAME", script.clone()),
            ("SCRIPT_NAME", "/__httpjet_lsapi_ready.php".to_string()),
            ("REQUEST_METHOD", "GET".to_string()),
            ("QUERY_STRING", String::new()),
            ("REQUEST_URI", "/__httpjet_lsapi_ready.php".to_string()),
            ("SERVER_PROTOCOL", "HTTP/1.1".to_string()),
            ("SERVER_SOFTWARE", "httpjet-readiness".to_string()),
            ("SERVER_NAME", "localhost".to_string()),
            ("SERVER_ADDR", "127.0.0.1".to_string()),
            ("SERVER_PORT", "80".to_string()),
            ("REMOTE_ADDR", "127.0.0.1".to_string()),
            ("REMOTE_PORT", "0".to_string()),
            (
                "DOCUMENT_ROOT",
                script
                    .rsplit_once('/')
                    .map(|(parent, _)| parent)
                    .unwrap_or("/")
                    .to_string(),
            ),
        ];
        let request = build_begin_request_framed(
            &env,
            &[],
            &[("host", "localhost"), ("connection", "close")],
            0,
        );
        stream.write_all(&request).await?;
    }

    let mut attributed_pid = None;
    let mut response = Vec::new();
    let mut response_status = None;
    loop {
        let (packet_type, body) = read_lsapi_packet(&mut stream).await?;
        match packet_type {
            PacketType::ReqReceived => {}
            PacketType::RespHeader => {
                if body.len() < 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "readiness PHP response had a truncated header",
                    ));
                }
                let status = i32::from_ne_bytes(body[4..8].try_into().expect("four-byte status"));
                response_status = u16::try_from(status).ok();
            }
            PacketType::StderrStream if body.len() == 8 && &body[..4] == b"\0PID" => {
                let pid = i32::from_ne_bytes(body[4..8].try_into().expect("four-byte pid"));
                if pid > 0 && process_belongs_to(pid as u32, expected_master) {
                    attributed_pid = Some(pid as u32);
                    if script.is_none() {
                        return Ok(());
                    }
                }
            }
            PacketType::StderrStream => {}
            PacketType::RespStream => {
                if response.len() + body.len() <= 128 {
                    response.extend_from_slice(&body);
                }
            }
            PacketType::RespEnd => {
                if script.is_some() && !matches!(response_status, Some(200..=299)) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "readiness PHP request returned status {:?}",
                            response_status
                        ),
                    ));
                }
                let body_pid = std::str::from_utf8(&response)
                    .ok()
                    .map(str::trim)
                    .and_then(|value| value.parse::<u32>().ok());
                let pid = if script.is_some() {
                    body_pid
                } else {
                    attributed_pid
                }
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "readiness PHP response did not identify its worker pid",
                    )
                })?;
                if process_belongs_to(pid, expected_master) {
                    return Ok(());
                }
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "readiness request was served by old worker {pid}, not candidate master {expected_master}"
                    ),
                ));
            }
            PacketType::ConnClose | PacketType::InternalError => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "lsphp closed or rejected the readiness request",
                ));
            }
            PacketType::BeginRequest | PacketType::AbortRequest => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "readiness peer returned a request-side LSAPI packet",
                ));
            }
        }
    }
}

async fn read_lsapi_packet(
    stream: &mut tokio::net::UnixStream,
) -> io::Result<(PacketType, Vec<u8>)> {
    let mut header = [0u8; PACKET_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    if &header[..2] != b"LS" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "readiness peer returned invalid LSAPI magic",
        ));
    }
    let packet_type = PacketType::from_u8(header[2]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "readiness peer returned an unknown LSAPI packet type",
        )
    })?;
    // The probe and lsphp are co-located, so the native field representation is
    // authoritative even on the aarch64 LSAPI build whose flag predates modern
    // little-endian architectures.
    let length = u32::from_ne_bytes(header[4..8].try_into().expect("four-byte slice")) as usize;
    if !(PACKET_HEADER_LEN..=MAX_PACKET_LEN).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "readiness peer returned an invalid LSAPI packet length",
        ));
    }
    let mut body = vec![0; length - PACKET_HEADER_LEN];
    stream.read_exact(&mut body).await?;
    Ok((packet_type, body))
}

#[derive(Debug)]
struct TrackedPid {
    pid: u32,
    start_time: u64,
    marker: Arc<str>,
    pidfd: OwnedFd,
    is_lsapi: bool,
}

impl TrackedPid {
    fn signal(&self, signal: libc::c_int) -> io::Result<()> {
        // SAFETY: construction verifies marker + start time both before and
        // after pidfd_open. The held pidfd therefore pins that exact process and
        // its stored generation marker; it cannot be redirected by PID reuse or
        // made unsafe by a descendant mutating its live environment later.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            let error = io::Error::last_os_error();
            Err(io::Error::new(
                error.kind(),
                format!(
                    "pidfd signal failed for pid {} in lsphp generation {}: {error}",
                    self.pid, self.marker
                ),
            ))
        }
    }

    fn alive(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pollfd` is valid for the duration of the non-blocking poll.
        let ready = unsafe { libc::poll(&mut pollfd, 1, 0) };
        ready <= 0 || pollfd.revents & libc::POLLIN == 0
    }

    fn state(&self) -> Option<u8> {
        proc_details(self.pid)
            .filter(|details| details.start_time == self.start_time)
            .map(|details| details.state)
    }

    fn lsapi_worker_is_idle(&self) -> bool {
        if !self.is_lsapi || !proc_stat(self.pid).is_some_and(|(_, start)| start == self.start_time)
        {
            return false;
        }
        std::fs::read(format!("/proc/{}/cmdline", self.pid))
            .ok()
            .is_some_and(|cmdline| lsapi_cmdline_is_idle(&cmdline))
    }

    fn lsapi_worker_is_retirable(&self, connections: &[u64]) -> bool {
        self.lsapi_worker_is_idle()
            && !process_holds_socket_inode(self.pid, self.start_time, connections)
    }

    fn reap_if_adopted(&self) -> io::Result<()> {
        let Some((parent, start)) = proc_stat(self.pid) else {
            return Ok(());
        };
        if start != self.start_time || parent != std::process::id() {
            return Ok(());
        }
        // A zombie no longer exposes its environment, but the pidfd still pins
        // the exact process whose marker + start time were verified at capture.
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: Linux waitid(P_PIDFD) targets the process object pinned by the
        // pidfd, so it cannot steal a different Tokio child after numeric PID
        // reuse. WNOHANG makes this safe for live adopted descendants.
        let rc = unsafe {
            libc::waitid(
                3 as libc::idtype_t,
                self.pidfd.as_raw_fd() as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG,
            )
        };
        if rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

struct ResumeOnDrop<'a>(&'a TrackedPid);

impl Drop for ResumeOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.signal(libc::SIGCONT);
    }
}

fn lsapi_cmdline_is_idle(cmdline: &[u8]) -> bool {
    cmdline
        .split(|byte| *byte == 0)
        .next()
        .is_some_and(|title| title == b"lsphp")
}

fn lsapi_connection_inodes(socket_path: &Path) -> io::Result<Vec<u64>> {
    let expected = socket_path.to_string_lossy();
    let sockets = std::fs::read_to_string("/proc/net/unix")?;
    Ok(sockets
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            (fields.len() >= 8 && fields[5] != "01" && fields[7] == expected)
                .then(|| fields[6].parse::<u64>().ok())
                .flatten()
        })
        .collect())
}

fn process_holds_socket_inode(pid: u32, start_time: u64, inodes: &[u64]) -> bool {
    if inodes.is_empty() {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return true;
    };
    let holds = entries.flatten().any(|entry| {
        std::fs::read_link(entry.path())
            .ok()
            .and_then(|target| {
                let target = target.to_str()?;
                target
                    .strip_prefix("socket:[")?
                    .strip_suffix(']')?
                    .parse::<u64>()
                    .ok()
            })
            .is_some_and(|inode| inodes.contains(&inode))
    });
    holds || !proc_stat(pid).is_some_and(|(_, start)| start == start_time)
}

async fn retire_idle_lsapi_workers(
    tracked: &[TrackedPid],
    master: Option<u32>,
    socket_path: &Path,
) -> io::Result<()> {
    let connections = lsapi_connection_inodes(socket_path)?;
    for process in tracked.iter().filter(|process| {
        process.is_lsapi
            && Some(process.pid) != master
            && process.lsapi_worker_is_retirable(&connections)
    }) {
        process.signal(libc::SIGSTOP)?;
        let resume = ResumeOnDrop(process);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(25);
        loop {
            match process.state() {
                None | Some(b'Z') => break,
                Some(b'T' | b't') => {
                    let connections = lsapi_connection_inodes(socket_path)?;
                    if process.lsapi_worker_is_retirable(&connections) {
                        process.signal(libc::SIGUSR1)?;
                    }
                    break;
                }
                _ if tokio::time::Instant::now() >= deadline => break,
                _ => tokio::time::sleep(Duration::from_millis(1)).await,
            }
        }
        drop(resume);
    }
    Ok(())
}

fn open_pidfd(pid: u32) -> io::Result<Option<OwnedFd>> {
    // SAFETY: pidfd_open returns a new owned descriptor on success.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as libc::c_int;
    if fd >= 0 {
        Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
    } else {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(None)
        } else {
            Err(error)
        }
    }
}

/// Reap exited curl subprocesses orphaned into this process by child-subreaper
/// mode. PHP handlers deliberately use `exec("curl ... &")`; after their
/// intermediate shell exits, Linux reparents curl to the nearest subreaper. It
/// must be waited here when it later exits or it remains a zombie for the
/// lifetime of the persistent pool.
///
/// The caller holds the supervisor lifecycle lock, so candidates and draining
/// generations cannot race this scan. `protected_child` is the live master owned
/// by Tokio's [`Child`] handle; never consume its exit status here. Restricting
/// this to the proven curl caller also prevents one pool monitor from consuming
/// the exit status of a child owned by a different supervisor in the same
/// process.
fn reap_adopted_curl_zombies(protected_child: Option<u32>) -> io::Result<usize> {
    let self_pid = std::process::id();
    let mut reaped = 0;
    let mut children = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{self_pid}/task"))?.flatten() {
        let Ok(list) = std::fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        children.extend(
            list.split_ascii_whitespace()
                .filter_map(|pid| pid.parse::<u32>().ok()),
        );
    }
    for pid in children {
        if Some(pid) == protected_child {
            continue;
        }
        let Some(details) = proc_details(pid) else {
            continue;
        };
        if details.parent != self_pid || details.state != b'Z' {
            continue;
        }
        if !std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .is_ok_and(|comm| comm.trim() == "curl")
        {
            continue;
        }
        let Some(pidfd) = open_pidfd(pid)? else {
            continue;
        };
        // Revalidate after pidfd_open. A zombie cannot be numerically reused
        // before it is reaped, and the pidfd pins that exact process object.
        if !proc_details(pid)
            .is_some_and(|current| current.parent == self_pid && current.state == b'Z')
        {
            continue;
        }
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: P_PIDFD waits on the process pinned above; WNOHANG cannot
        // block the one-second monitor tick.
        let rc = unsafe {
            libc::waitid(
                3 as libc::idtype_t,
                pidfd.as_raw_fd() as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG,
            )
        };
        if rc == 0 {
            reaped += 1;
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ECHILD) {
                return Err(error);
            }
        }
    }
    Ok(reaped)
}

struct ProcDetails {
    state: u8,
    parent: u32,
    session: u32,
    start_time: u64,
}

fn proc_details(pid: u32) -> Option<ProcDetails> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = stat.rsplit_once(')')?.1.trim_start();
    let fields: Vec<&str> = tail.split_ascii_whitespace().collect();
    Some(ProcDetails {
        state: *fields.first()?.as_bytes().first()?,
        parent: fields.get(1)?.parse().ok()?,
        session: fields.get(3)?.parse().ok()?,
        start_time: fields.get(19)?.parse().ok()?,
    })
}

fn proc_stat(pid: u32) -> Option<(u32, u64)> {
    let details = proc_details(pid)?;
    Some((details.parent, details.start_time))
}

#[cfg(test)]
fn proc_state(pid: u32) -> Option<u8> {
    Some(proc_details(pid)?.state)
}

fn proc_session(pid: u32) -> Option<u32> {
    Some(proc_details(pid)?.session)
}

fn process_belongs_to(mut pid: u32, master: u32) -> bool {
    for _ in 0..64 {
        if pid == master {
            return true;
        }
        let Some((parent, _)) = proc_stat(pid) else {
            return false;
        };
        if parent <= 1 || parent == pid {
            return false;
        }
        pid = parent;
    }
    false
}

fn process_has_marker(pid: u32, marker: &str) -> io::Result<bool> {
    let expected = format!("{GENERATION_MARKER_ENV}={marker}");
    match std::fs::read(format!("/proc/{pid}/environ")) {
        Ok(environment) => Ok(environment
            .split(|byte| *byte == 0)
            .any(|entry| entry == expected.as_bytes())),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || matches!(error.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH)) =>
        {
            Ok(false)
        }
        Err(_) if proc_stat(pid).is_none() => Ok(false),
        Err(error) => Err(error),
    }
}

fn scan_generation(marker: &str, master: Option<u32>) -> io::Result<Vec<TrackedPid>> {
    let marker: Arc<str> = Arc::from(marker);
    let entries = std::fs::read_dir("/proc")?;
    let mut tracked = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Some((_, start_before)) = proc_stat(pid) else {
            continue;
        };
        if !process_has_marker(pid, &marker)? {
            continue;
        }
        let Some(pidfd) = open_pidfd(pid)? else {
            continue;
        };
        let Some((_, start_after)) = proc_stat(pid) else {
            continue;
        };
        if start_before != start_after || !process_has_marker(pid, &marker)? {
            continue;
        }
        let comm_is_lsapi = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .is_some_and(|comm| comm.trim().starts_with("lsphp"));
        let exe_is_lsapi = std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|path| path.file_name().map(|name| name.to_owned()))
            .is_some_and(|name| name.as_encoded_bytes().starts_with(b"lsphp"));
        if !proc_stat(pid).is_some_and(|(_, start)| start == start_before) {
            continue;
        }
        let is_lsapi = master == Some(pid)
            || ((comm_is_lsapi || exe_is_lsapi) && proc_session(pid).is_some_and(|sid| sid == pid));
        tracked.push(TrackedPid {
            pid,
            start_time: start_before,
            marker: marker.clone(),
            pidfd,
            is_lsapi,
        });
    }
    Ok(tracked)
}

fn record_first_error(
    first_error: &mut Option<io::Error>,
    context: &'static str,
    error: io::Error,
) {
    let error = io::Error::new(error.kind(), format!("{context}: {error}"));
    if first_error.is_none() {
        *first_error = Some(error);
    } else {
        tracing::warn!(%error, "additional lsphp generation cleanup failure");
    }
}

async fn drain_generation(
    child: &mut Child,
    marker: &str,
    socket_path: &Path,
    cancel: Option<&CancellationToken>,
    abortable: bool,
    forced_cleanup_count: &AtomicU64,
) -> io::Result<()> {
    let master = child.id();
    let quiesced = match quiesce_generation_bounded(marker, master).await {
        Ok(quiesced) => quiesced,
        Err(error) => {
            return finish_generation_drain(
                child,
                marker,
                master,
                Vec::new(),
                socket_path,
                cancel,
                abortable,
                Some(io::Error::new(
                    error.kind(),
                    format!("could not quiesce the draining lsphp generation: {error}"),
                )),
                forced_cleanup_count,
            )
            .await;
        }
    };
    let mut first_error = None;
    if let Err(error) = quiesced.signal_master(libc::SIGUSR1) {
        record_first_error(
            &mut first_error,
            "could not gracefully signal the draining lsphp master",
            error,
        );
    }
    if let Err(error) = quiesced.signal_idle_workers(libc::SIGUSR1, socket_path) {
        record_first_error(
            &mut first_error,
            "could not gracefully signal draining idle lsphp workers",
            error,
        );
    }
    let (master, tracked, resume_error) = quiesced.into_resumed();
    if let Some(error) = resume_error {
        record_first_error(
            &mut first_error,
            "could not resume every quiesced lsphp process",
            error,
        );
    }
    finish_generation_drain(
        child,
        marker,
        master,
        tracked,
        socket_path,
        cancel,
        abortable,
        first_error,
        forced_cleanup_count,
    )
    .await
}

#[derive(Debug)]
struct QuiescedGeneration {
    master: Option<u32>,
    tracked: Vec<TrackedPid>,
    resume_on_drop: bool,
}

impl QuiescedGeneration {
    fn signal_master(&self, signal: libc::c_int) -> io::Result<()> {
        let Some(master) = self.master else {
            return Ok(());
        };
        let process = self
            .tracked
            .iter()
            .find(|process| process.pid == master)
            .ok_or_else(|| io::Error::other("lsphp master missing from pinned generation"))?;
        process.signal(signal)
    }

    fn signal_lsapi(&self, signal: libc::c_int) -> io::Result<()> {
        for process in self.tracked.iter().filter(|process| process.is_lsapi) {
            process.signal(signal)?;
        }
        Ok(())
    }

    fn signal_idle_workers(&self, signal: libc::c_int, socket_path: &Path) -> io::Result<()> {
        let connections = lsapi_connection_inodes(socket_path)?;
        for process in self.tracked.iter().filter(|process| {
            process.is_lsapi
                && Some(process.pid) != self.master
                && process.lsapi_worker_is_retirable(&connections)
        }) {
            process.signal(signal)?;
        }
        Ok(())
    }

    fn signal_all(&self, signal: libc::c_int) -> io::Result<()> {
        for process in &self.tracked {
            process.signal(signal)?;
        }
        Ok(())
    }

    fn into_resumed(mut self) -> (Option<u32>, Vec<TrackedPid>, Option<io::Error>) {
        let mut first_error = None;
        for process in self.tracked.iter().filter(|process| process.is_lsapi) {
            if let Err(error) = process.signal(libc::SIGCONT) {
                record_first_error(
                    &mut first_error,
                    "could not resume a quiesced lsphp process",
                    error,
                );
            }
        }
        self.resume_on_drop = false;
        (self.master, std::mem::take(&mut self.tracked), first_error)
    }

    fn into_disarmed(mut self) -> (Option<u32>, Vec<TrackedPid>) {
        self.resume_on_drop = false;
        (self.master, std::mem::take(&mut self.tracked))
    }
}

impl Drop for QuiescedGeneration {
    fn drop(&mut self) {
        if self.resume_on_drop {
            for process in self.tracked.iter().filter(|process| process.is_lsapi) {
                let _ = process.signal(libc::SIGCONT);
            }
        }
    }
}

#[cfg(test)]
#[derive(Default)]
struct QuiesceTestPause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
static QUIESCE_TEST_PAUSES: OnceLock<
    Mutex<std::collections::HashMap<String, Arc<QuiesceTestPause>>>,
> = OnceLock::new();

#[cfg(test)]
fn install_quiesce_test_pause(marker: &str) -> Arc<QuiesceTestPause> {
    let pause = Arc::new(QuiesceTestPause::default());
    QUIESCE_TEST_PAUSES
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
        .insert(marker.to_string(), pause.clone());
    pause
}

#[cfg(test)]
async fn pause_quiesce_for_test(marker: &str) {
    let pause = QUIESCE_TEST_PAUSES
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
        .remove(marker);
    if let Some(pause) = pause {
        pause.entered.notify_one();
        pause.release.notified().await;
    }
}

/// [`quiesce_generation`] with the standard [`QUIESCE_TIMEOUT`] bound. The
/// hot-reload and drain paths use this; the force-kill paths carry their own
/// outer timeouts. On timeout the dropped inner future's partial
/// [`QuiescedGeneration`] guard resumes every already-stopped process.
async fn quiesce_generation_bounded(
    marker: &str,
    master: Option<u32>,
) -> io::Result<QuiescedGeneration> {
    quiesce_generation_within(QUIESCE_TIMEOUT, marker, master).await
}

async fn quiesce_generation_within(
    timeout: Duration,
    marker: &str,
    master: Option<u32>,
) -> io::Result<QuiescedGeneration> {
    match tokio::time::timeout(timeout, quiesce_generation(marker, master)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("lsphp generation quiesce did not converge within {timeout:?}"),
        )),
    }
}

async fn quiesce_generation(marker: &str, master: Option<u32>) -> io::Result<QuiescedGeneration> {
    let mut generation = QuiescedGeneration {
        master,
        tracked: Vec::new(),
        resume_on_drop: true,
    };
    let mut stable_scans = 0u8;
    loop {
        let current = scan_generation(marker, master)?;
        let mut found_new_lsapi = false;
        for process in current {
            if let Some(known) = generation
                .tracked
                .iter_mut()
                .find(|known| known.pid == process.pid && known.start_time == process.start_time)
            {
                if process.is_lsapi && !known.is_lsapi {
                    known.is_lsapi = true;
                    known.signal(libc::SIGSTOP)?;
                    found_new_lsapi = true;
                }
                continue;
            }
            if process.is_lsapi {
                process.signal(libc::SIGSTOP)?;
                found_new_lsapi = true;
            }
            generation.tracked.push(process);
        }

        #[cfg(test)]
        pause_quiesce_for_test(marker).await;

        let mut all_quiesced = true;
        for process in generation.tracked.iter().filter(|process| process.is_lsapi) {
            if !matches!(process.state(), None | Some(b'T' | b't' | b'D' | b'Z')) {
                all_quiesced = false;
                break;
            }
        }
        if all_quiesced && !found_new_lsapi {
            stable_scans += 1;
            if stable_scans >= 2 {
                return Ok(generation);
            }
        } else {
            stable_scans = 0;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn finish_generation_drain(
    child: &mut Child,
    marker: &str,
    master: Option<u32>,
    mut tracked: Vec<TrackedPid>,
    socket_path: &Path,
    cancel: Option<&CancellationToken>,
    abortable: bool,
    initial_error: Option<io::Error>,
    forced_cleanup_count: &AtomicU64,
) -> io::Result<()> {
    let mut first_error = initial_error;
    let mut stable_empty_scans = 0u8;
    if first_error.is_none() {
        let deadline = tokio::time::Instant::now() + GRACE_TIMEOUT;
        'grace: loop {
            let master_done = match child.try_wait() {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(error) => {
                    record_first_error(
                        &mut first_error,
                        "could not reap the lsphp master during graceful drain",
                        error,
                    );
                    break 'grace;
                }
            };
            let marker_members =
                match merge_marker_members(marker, master, &mut tracked, None, true) {
                    Ok(members) => members,
                    Err(error) => {
                        record_first_error(
                            &mut first_error,
                            "could not scan the lsphp generation during graceful drain",
                            error,
                        );
                        break 'grace;
                    }
                };
            if let Err(error) = retire_idle_lsapi_workers(&tracked, master, socket_path).await {
                record_first_error(
                    &mut first_error,
                    "could not retire an idle lsphp worker during graceful drain",
                    error,
                );
                break 'grace;
            }
            let family_done = tracked.iter().all(|process| !process.alive());
            for process in &tracked {
                if Some(process.pid) != master {
                    if let Err(error) = process.reap_if_adopted() {
                        record_first_error(
                            &mut first_error,
                            "could not reap an adopted lsphp process during graceful drain",
                            error,
                        );
                        break 'grace;
                    }
                }
            }
            if master_done && family_done && marker_members == 0 {
                stable_empty_scans += 1;
                if stable_empty_scans >= 2 {
                    return Ok(());
                }
            } else {
                stable_empty_scans = 0;
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            if abortable {
                if let Some(cancel) = cancel {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }

    forced_cleanup_count.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        generation_marker = marker,
        master_pid = ?master,
        grace_secs = GRACE_TIMEOUT.as_secs(),
        "lsphp generation did not complete graceful drain; forcing complete marked-family cleanup"
    );
    for process in &tracked {
        if let Err(error) = process.signal(libc::SIGKILL) {
            record_first_error(
                &mut first_error,
                "could not force-kill a tracked lsphp process",
                error,
            );
        }
    }
    let mut master_done = match child.try_wait() {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => {
            record_first_error(
                &mut first_error,
                "could not reap the lsphp master before forced cleanup",
                error,
            );
            false
        }
    };
    if !master_done {
        if let Err(error) = child.start_kill() {
            record_first_error(
                &mut first_error,
                "could not force-kill the lsphp master",
                error,
            );
        }
    }
    let forced_deadline = tokio::time::Instant::now() + FORCE_CLEANUP_TIMEOUT;
    stable_empty_scans = 0;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => master_done = true,
            Ok(None) => {}
            Err(error) => record_first_error(
                &mut first_error,
                "could not reap the lsphp master during forced cleanup",
                error,
            ),
        }
        let marker_members =
            match merge_marker_members(marker, master, &mut tracked, Some(libc::SIGKILL), false) {
                Ok(members) => Some(members),
                Err(error) => {
                    record_first_error(
                        &mut first_error,
                        "could not scan or signal the lsphp generation during forced cleanup",
                        error,
                    );
                    None
                }
            };
        for process in &tracked {
            if Some(process.pid) != master {
                if let Err(error) = process.reap_if_adopted() {
                    record_first_error(
                        &mut first_error,
                        "could not reap an adopted lsphp process during forced cleanup",
                        error,
                    );
                }
            }
        }
        if master_done
            && tracked.iter().all(|process| !process.alive())
            && marker_members == Some(0)
        {
            stable_empty_scans += 1;
            if stable_empty_scans >= 2 {
                return match first_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                };
            }
        } else {
            stable_empty_scans = 0;
        }
        if tokio::time::Instant::now() >= forced_deadline {
            let timeout = format!(
                "forced lsphp generation cleanup did not complete within {:?}",
                FORCE_CLEANUP_TIMEOUT
            );
            return match first_error {
                Some(error) => Err(io::Error::new(error.kind(), format!("{error}; {timeout}"))),
                None => Err(io::Error::new(io::ErrorKind::TimedOut, timeout)),
            };
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn force_kill_generation(child: &mut Child, marker: &str) -> io::Result<()> {
    force_kill_generation_with_timeout(child, marker, FORCE_CLEANUP_TIMEOUT).await
}

async fn force_kill_generation_with_timeout(
    child: &mut Child,
    marker: &str,
    timeout: Duration,
) -> io::Result<()> {
    let cleanup = async {
        let master = child.id();
        let generation = quiesce_generation(marker, master).await?;
        generation.signal_all(libc::SIGKILL)?;
        let (_, mut tracked) = generation.into_disarmed();
        let _ = child.start_kill();
        let _ = child.wait().await;
        let mut stable_empty_scans = 0u8;
        loop {
            let marker_members =
                merge_marker_members(marker, master, &mut tracked, Some(libc::SIGKILL), false)?;
            for process in &tracked {
                if Some(process.pid) != master {
                    process.reap_if_adopted()?;
                }
            }
            if tracked.iter().all(|process| !process.alive()) && marker_members == 0 {
                stable_empty_scans += 1;
                if stable_empty_scans >= 2 {
                    return Ok(());
                }
            } else {
                stable_empty_scans = 0;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    match tokio::time::timeout(timeout, cleanup).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("forced lsphp candidate cleanup did not complete within {timeout:?}"),
        )),
    }
}

async fn force_cleanup_marker(marker: &str) -> io::Result<()> {
    force_cleanup_marker_with_timeout(marker, FORCE_CLEANUP_TIMEOUT).await
}

async fn force_cleanup_marker_with_timeout(marker: &str, timeout: Duration) -> io::Result<()> {
    let cleanup = async {
        #[cfg(test)]
        pause_quiesce_for_test(marker).await;

        let mut tracked = Vec::new();
        let mut stable_empty_scans = 0u8;
        loop {
            let marker_members =
                merge_marker_members(marker, None, &mut tracked, Some(libc::SIGKILL), false)?;
            for process in &tracked {
                process.reap_if_adopted()?;
            }
            if tracked.iter().all(|process| !process.alive()) && marker_members == 0 {
                stable_empty_scans += 1;
                if stable_empty_scans >= 2 {
                    return Ok(());
                }
            } else {
                stable_empty_scans = 0;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    match tokio::time::timeout(timeout, cleanup).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("forced lsphp marker cleanup did not complete within {timeout:?}"),
        )),
    }
}

fn merge_marker_members(
    marker: &str,
    master: Option<u32>,
    tracked: &mut Vec<TrackedPid>,
    signal: Option<libc::c_int>,
    lsapi_only: bool,
) -> io::Result<usize> {
    let current = scan_generation(marker, master)?;
    let marker_members = current.len();
    for process in current {
        if let Some(known) = tracked
            .iter_mut()
            .find(|known| known.pid == process.pid && known.start_time == process.start_time)
        {
            if process.is_lsapi && !known.is_lsapi {
                known.is_lsapi = true;
                if let Some(signal) = signal {
                    known.signal(libc::SIGSTOP)?;
                    known.signal(signal)?;
                    known.signal(libc::SIGCONT)?;
                }
            }
            continue;
        }
        if let Some(signal) = signal {
            if lsapi_only {
                if process.is_lsapi {
                    process.signal(libc::SIGSTOP)?;
                    process.signal(signal)?;
                    process.signal(libc::SIGCONT)?;
                }
            } else {
                process.signal(signal)?;
            }
        }
        tracked.push(process);
    }
    Ok(marker_members)
}

fn ensure_child_subreaper() -> bool {
    static SUBREAPER: OnceLock<i32> = OnceLock::new();
    let errno = *SUBREAPER.get_or_init(|| {
        // SAFETY: PR_SET_CHILD_SUBREAPER is a process-scoped boolean setting.
        let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        if rc == 0 {
            0
        } else {
            io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        }
    });
    if errno != 0 {
        tracing::warn!(
            errno,
            "could not enable child-subreaper mode for lsphp cleanup"
        );
    }
    errno == 0
}

/// Exponential backoff: `base * 2^failures`, capped at `max`. Returns zero when
/// `failures == 0` (a fresh, non-retry restart waits not at all).
fn backoff_for(base: Duration, failures: u32, max: Duration) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    // Saturate the shift to avoid overflow on pathological failure counts.
    let shift = failures.min(16);
    let scaled = base.saturating_mul(1u32 << shift);
    scaled.min(max)
}

impl Drop for LsphpSupervisor {
    fn drop(&mut self) {
        // Best-effort cleanup of the complete marked generation on drop. Normal
        // shutdown goes through the async drain and retains pidfds until every
        // member is gone; this backstop prevents a detached listener holder from
        // surviving an owner that drops the supervisor without draining it.
        let mut g = self.inner.lock();
        let mut markers = std::mem::take(&mut g.retired_markers);
        if let Some(marker) = g.child_marker.take() {
            markers.push(marker);
        }
        if let Some(mut child) = g.child.take() {
            let _ = child.start_kill();
        }
        g.state = WorkerState::NotStarted;
        drop(g);
        for marker in markers {
            if let Ok(processes) = scan_generation(&marker, None) {
                for process in processes {
                    let _ = process.signal(libc::SIGKILL);
                }
            }
        }
        // Never unlink a systemd-owned (socket-activated) socket; only one we bound.
        if matches!(self.cfg.socket_source, SocketSource::Bind) {
            let _ = std::fs::remove_file(&self.cfg.socket_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32};

    fn write_fake_lsapi_master(tag: &str, fail_after_first: bool) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "hj-lsapi-{tag}-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let program = base.with_extension("py");
        let counter = base.with_extension("count");
        let gate = if fail_after_first {
            format!(
                r#"
with open({counter:?}, "a+") as count:
    count.write("x")
    count.flush()
with open({counter:?}, "r") as count:
    if len(count.read()) > 1:
        sys.exit(71)
"#,
                counter = counter
            )
        } else {
            String::new()
        };
        let source = format!(
            r#"#!/usr/bin/python3
import os
import signal
import socket
import struct
import sys

{gate}

os.setsid()

def stop(_signal, _frame):
    sys.exit(0)

signal.signal(signal.SIGUSR1, stop)
listener = socket.socket(fileno=0)

while True:
    stream, _ = listener.accept()
    try:
        pid = os.getpid()
        stream.sendall(b"LS\x06\x00" + struct.pack("=I", 16) + b"\x00PID" + struct.pack("=i", pid))
        header = b""
        while len(header) < 8:
            chunk = stream.recv(8 - len(header))
            if not chunk:
                break
            header += chunk
        if len(header) == 8:
            total = struct.unpack("=I", header[4:8])[0]
            remaining = total - 8
            while remaining:
                chunk = stream.recv(remaining)
                if not chunk:
                    break
                remaining -= len(chunk)
            body = str(pid).encode()
            response_header = struct.pack("=ii", 0, 200)
            stream.sendall(b"LS\x03\x00" + struct.pack("=I", 8 + len(response_header)) + response_header)
            stream.sendall(b"LS\x04\x00" + struct.pack("=I", 8 + len(body)) + body)
            stream.sendall(b"LS\x05\x00" + struct.pack("=I", 8))
    finally:
        stream.close()
"#
        );
        std::fs::write(&program, source).unwrap();
        let mut permissions = std::fs::metadata(&program).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&program, permissions).unwrap();
        (program, counter)
    }

    fn write_hanging_lsapi_master(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "hj-lsapi-{tag}-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let program = base.with_extension("py");
        let accepted = base.with_extension("accepted");
        let source = format!(
            r#"#!/usr/bin/python3
import os
import socket
import time

os.setsid()
listener = socket.socket(fileno=0)
stream, _ = listener.accept()
with open({accepted:?}, "w") as output:
    output.write(str(os.getpid()))
while True:
    time.sleep(1)
"#,
            accepted = accepted,
        );
        std::fs::write(&program, source).unwrap();
        let mut permissions = std::fs::metadata(&program).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&program, permissions).unwrap();
        (program, accepted)
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn fake_supervisor_config(command: PathBuf, socket: &Path) -> SupervisorConfig {
        let mut config = SupervisorConfig::from_php_config(&sample_php(), socket, "", "");
        config.command = command;
        config.children = 1;
        config.start_timeout = Duration::from_secs(2);
        config
    }

    #[test]
    fn inherited_listener_duplicate_is_close_on_exec() {
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let duplicate = duplicate_listen_fd(&stream).unwrap();

        assert!(
            rustix::io::fcntl_getfd(&duplicate)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
    }

    #[test]
    fn lsapi_process_title_distinguishes_idle_from_busy_workers() {
        assert!(lsapi_cmdline_is_idle(b"lsphp\0"));
        assert!(!lsapi_cmdline_is_idle(
            b"lsphp:/web/public_html/index.php\0"
        ));
        assert!(!lsapi_cmdline_is_idle(
            b"/usr/local/lsws/lsphp8/bin/lsphp\0"
        ));
        assert!(!lsapi_cmdline_is_idle(b""));
    }

    fn probe_socket(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hj-lsapi-ready-{}-{tag}.sock", std::process::id()))
    }

    #[tokio::test]
    async fn readiness_probe_rejects_a_backlog_without_an_accepting_worker() {
        let path = probe_socket("backlog-only");
        let _ = std::fs::remove_file(&path);
        let _listener = tokio::net::UnixListener::bind(&path).unwrap();

        let result = tokio::time::timeout(
            Duration::from_millis(75),
            probe_worker_ready_once(&path, std::process::id(), None),
        )
        .await;
        assert!(
            result.is_err(),
            "kernel connectability alone must not satisfy worker readiness"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn readiness_probe_requires_an_attributed_worker_pid() {
        let path = probe_socket("worker-reply");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let worker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut pid = [0u8; 16];
            pid[..2].copy_from_slice(b"LS");
            pid[2] = PacketType::StderrStream as u8;
            pid[4..8].copy_from_slice(&16u32.to_ne_bytes());
            pid[8..12].copy_from_slice(b"\0PID");
            pid[12..16].copy_from_slice(&(std::process::id() as i32).to_ne_bytes());
            stream.write_all(&pid).await.unwrap();
        });

        tokio::time::timeout(
            Duration::from_secs(1),
            probe_worker_ready_once(&path, std::process::id(), None),
        )
        .await
        .expect("probe should not time out")
        .expect("candidate-attributed pid frame should prove readiness");
        worker.await.unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn readiness_probe_rejects_an_old_worker_pid() {
        let path = probe_socket("old-worker");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let worker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut pid = [0u8; 16];
            pid[..2].copy_from_slice(b"LS");
            pid[2] = PacketType::StderrStream as u8;
            pid[4..8].copy_from_slice(&16u32.to_ne_bytes());
            pid[8..12].copy_from_slice(b"\0PID");
            pid[12..16].copy_from_slice(&(std::process::id() as i32).to_ne_bytes());
            stream.write_all(&pid).await.unwrap();
        });

        let error = probe_worker_ready_once(&path, u32::MAX - 1, None)
            .await
            .expect_err("an unrelated worker must not prove candidate readiness");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
        ));
        worker.await.unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn readiness_probe_does_not_accept_an_old_ack() {
        let path = probe_socket("old-ack");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let worker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut ack = [0u8; PACKET_HEADER_LEN];
            ack[..2].copy_from_slice(b"LS");
            ack[2] = PacketType::ReqReceived as u8;
            ack[4..8].copy_from_slice(&(PACKET_HEADER_LEN as u32).to_ne_bytes());
            stream.write_all(&ack).await.unwrap();
        });

        probe_worker_ready_once(&path, std::process::id(), None)
            .await
            .expect_err("an ACK has no candidate attribution and is not readiness");
        worker.await.unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn readiness_probe_requires_successful_php_execution() {
        let path = probe_socket("php-failure");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let worker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut pid = [0u8; 16];
            pid[..2].copy_from_slice(b"LS");
            pid[2] = PacketType::StderrStream as u8;
            pid[4..8].copy_from_slice(&16u32.to_ne_bytes());
            pid[8..12].copy_from_slice(b"\0PID");
            pid[12..16].copy_from_slice(&(std::process::id() as i32).to_ne_bytes());
            stream.write_all(&pid).await.unwrap();

            let mut request_header = [0u8; PACKET_HEADER_LEN];
            stream.read_exact(&mut request_header).await.unwrap();
            let request_len = u32::from_ne_bytes(request_header[4..8].try_into().unwrap()) as usize;
            let mut request_body = vec![0u8; request_len - PACKET_HEADER_LEN];
            stream.read_exact(&mut request_body).await.unwrap();

            let mut response_header = [0u8; 16];
            response_header[..2].copy_from_slice(b"LS");
            response_header[2] = PacketType::RespHeader as u8;
            response_header[4..8].copy_from_slice(&16u32.to_ne_bytes());
            response_header[12..16].copy_from_slice(&500i32.to_ne_bytes());
            stream.write_all(&response_header).await.unwrap();

            let mut response_end = [0u8; PACKET_HEADER_LEN];
            response_end[..2].copy_from_slice(b"LS");
            response_end[2] = PacketType::RespEnd as u8;
            response_end[4..8].copy_from_slice(&(PACKET_HEADER_LEN as u32).to_ne_bytes());
            stream.write_all(&response_end).await.unwrap();
        });

        let error = probe_worker_ready_once(
            &path,
            std::process::id(),
            Some(Path::new("/tmp/hj-readiness-expected-to-fail.php")),
        )
        .await
        .expect_err("a PID frame cannot mask a failed readiness script");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("500"));
        worker.await.unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn hot_reload_promotes_only_a_ready_candidate() {
        let (program, counter) = write_fake_lsapi_master("promote", false);
        let socket = probe_socket("promote");
        let _ = std::fs::remove_file(&socket);
        let listener = StdUnixListener::bind(&socket).unwrap();
        rustix::net::listen(&listener, 128).unwrap();
        let supervisor = LsphpSupervisor::new(fake_supervisor_config(program.clone(), &socket))
            .with_listen_fd(listener.into());
        let old_pid_for_hook = Arc::new(AtomicU32::new(0));
        let old_pid_seen = old_pid_for_hook.clone();
        let observed_frozen = Arc::new(AtomicBool::new(false));
        let frozen_seen = observed_frozen.clone();
        assert!(
            supervisor.set_promotion_hook(Arc::new(move |generation, marker| {
                assert!(!marker.is_empty());
                if generation == 1 {
                    return;
                }
                assert_eq!(generation, 2);
                let old_pid = old_pid_seen.load(Ordering::Acquire);
                assert_ne!(old_pid, 0);
                assert!(
                    matches!(proc_state(old_pid), None | Some(b'T' | b't' | b'D' | b'Z')),
                    "old acceptor must remain quiesced while the new epoch is published"
                );
                frozen_seen.store(true, Ordering::Release);
            }))
        );

        supervisor.start().await.expect("first fake generation");
        let old_pid = supervisor.worker_pid().unwrap();
        old_pid_for_hook.store(old_pid, Ordering::Release);
        assert_eq!(supervisor.generation(), 1);
        let generation = supervisor.hot_reload().await.expect("candidate reload");

        assert_eq!(generation, 2);
        assert_eq!(supervisor.generation(), 2);
        assert_eq!(supervisor.state(), WorkerState::Good);
        assert_ne!(supervisor.worker_pid(), Some(old_pid));
        assert!(proc_stat(old_pid).is_none(), "old master must be reaped");
        assert!(observed_frozen.load(Ordering::Acquire));

        supervisor.drain_graceful().await.unwrap();
        let _ = std::fs::remove_file(socket);
        let _ = std::fs::remove_file(program);
        let _ = std::fs::remove_file(counter);
    }

    #[tokio::test]
    async fn retired_marker_is_queued_if_cleanup_future_is_cancelled() {
        let supervisor = Arc::new(LsphpSupervisor::new(SupervisorConfig::from_php_config(
            &sample_php(),
            "/tmp/x.sock",
            "",
            "",
        )));
        let task_supervisor = supervisor.clone();
        let (armed, armed_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _retired =
                RetiredMarkerGuard::new(&task_supervisor.inner, "cancelled-old".to_string());
            let _ = armed.send(());
            std::future::pending::<()>().await;
        });

        armed_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            supervisor.inner.lock().retired_markers,
            vec!["cancelled-old".to_string()]
        );
    }

    #[tokio::test]
    async fn timed_out_candidate_cleanup_retains_marker_for_a_later_pass() {
        let supervisor = LsphpSupervisor::new(SupervisorConfig::from_php_config(
            &sample_php(),
            "/tmp/x.sock",
            "",
            "",
        ));
        let marker = format!("candidate-timeout-{}", rand_suffix());
        let mut command = Command::new("/bin/sleep");
        command
            .arg("30")
            .env(GENERATION_MARKER_ENV, &marker)
            .kill_on_drop(true);
        let child = command.spawn().unwrap();
        let mut candidate = ReadyChild::new(&supervisor.inner, child, marker.clone());
        let _pause = install_quiesce_test_pause(&marker);

        let error = force_kill_generation_with_timeout(
            candidate.child_mut(),
            &marker,
            Duration::from_millis(25),
        )
        .await
        .expect_err("paused candidate cleanup must hit its bound");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        drop(candidate);
        assert_eq!(
            supervisor.inner.lock().retired_markers,
            vec![marker.clone()],
            "the candidate marker remains owned after timeout"
        );
        supervisor
            .cleanup_retired_markers_with_timeout(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(supervisor.inner.lock().retired_markers.is_empty());
    }

    #[tokio::test]
    async fn timed_out_deferred_cleanup_keeps_marker_queued_for_retry() {
        let supervisor = LsphpSupervisor::new(SupervisorConfig::from_php_config(
            &sample_php(),
            "/tmp/x.sock",
            "",
            "",
        ));
        let marker = format!("retired-timeout-{}", rand_suffix());
        supervisor.inner.lock().retired_markers.push(marker.clone());
        let _pause = install_quiesce_test_pause(&marker);

        let error = supervisor
            .cleanup_retired_markers_with_timeout(Duration::from_millis(25))
            .await
            .expect_err("paused marker cleanup must hit its bound");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            supervisor.inner.lock().retired_markers,
            vec![marker.clone()],
            "a timeout must not relinquish the deferred ownership marker"
        );

        supervisor
            .cleanup_retired_markers_with_timeout(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(supervisor.inner.lock().retired_markers.is_empty());
    }

    #[tokio::test]
    async fn stalled_quiesce_hits_its_bound() {
        let marker = format!("quiesce-timeout-{}-{}", std::process::id(), rand_suffix());
        let mut command = Command::new("/bin/sleep");
        command
            .arg("30")
            .env(GENERATION_MARKER_ENV, &marker)
            .kill_on_drop(true);
        let mut child = command.spawn().unwrap();
        let _pause = install_quiesce_test_pause(&marker);

        let error = quiesce_generation_within(Duration::from_millis(25), &marker, None)
            .await
            .expect_err("a paused quiesce must hit its outer bound");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        child.start_kill().unwrap();
        let _ = child.wait().await;
    }

    #[tokio::test]
    async fn aborted_readiness_retains_candidate_marker_and_restores_state() {
        let (program, accepted) = write_hanging_lsapi_master("abort-readiness");
        let socket = probe_socket("abort-readiness");
        let _ = std::fs::remove_file(&socket);
        let mut config = fake_supervisor_config(program.clone(), &socket);
        config.start_timeout = Duration::from_secs(30);
        let supervisor = Arc::new(LsphpSupervisor::new(config));
        let task_supervisor = supervisor.clone();
        let task = tokio::spawn(async move { task_supervisor.start().await });

        tokio::time::timeout(Duration::from_secs(2), async {
            while !accepted.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("candidate must enter the readiness probe");
        assert_eq!(supervisor.state(), WorkerState::Starting);

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let marker = {
            let inner = supervisor.inner.lock();
            assert_eq!(inner.state, WorkerState::NotStarted);
            assert!(inner.child.is_none());
            assert!(inner.child_marker.is_none());
            assert_eq!(inner.retired_markers.len(), 1);
            inner.retired_markers[0].clone()
        };
        supervisor.cleanup_retired_markers().await.unwrap();
        assert!(scan_generation(&marker, None).unwrap().is_empty());

        let _ = std::fs::remove_file(socket);
        let _ = std::fs::remove_file(program);
        let _ = std::fs::remove_file(accepted);
    }

    #[tokio::test]
    async fn aborted_hot_reload_quiesce_keeps_old_generation_and_candidate_marker() {
        let (program, counter) = write_fake_lsapi_master("abort-reload-quiesce", false);
        let socket = probe_socket("abort-reload-quiesce");
        let _ = std::fs::remove_file(&socket);
        let listener = StdUnixListener::bind(&socket).unwrap();
        rustix::net::listen(&listener, 128).unwrap();
        let supervisor = Arc::new(
            LsphpSupervisor::new(fake_supervisor_config(program.clone(), &socket))
                .with_listen_fd(listener.into()),
        );
        supervisor.start().await.unwrap();
        let (old_pid, old_marker) = {
            let inner = supervisor.inner.lock();
            (
                inner.child.as_ref().and_then(Child::id).unwrap(),
                inner.child_marker.clone().unwrap(),
            )
        };
        let pause = install_quiesce_test_pause(&old_marker);
        let task_supervisor = supervisor.clone();
        let task = tokio::spawn(async move { task_supervisor.hot_reload().await });
        tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
            .await
            .expect("reload must reach old-generation quiesce");

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !matches!(proc_state(old_pid), Some(b'T' | b't')) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled quiesce must resume the old master");
        let candidate_marker = {
            let inner = supervisor.inner.lock();
            assert_eq!(inner.state, WorkerState::Good);
            assert_eq!(inner.child.as_ref().and_then(Child::id), Some(old_pid));
            assert_eq!(inner.child_marker.as_deref(), Some(old_marker.as_str()));
            assert_eq!(inner.retired_markers.len(), 1);
            assert_ne!(inner.retired_markers[0], old_marker);
            inner.retired_markers[0].clone()
        };
        supervisor.cleanup_retired_markers().await.unwrap();
        assert!(scan_generation(&candidate_marker, None).unwrap().is_empty());
        assert!(supervisor.is_alive().unwrap());

        supervisor.drain_graceful().await.unwrap();
        let _ = std::fs::remove_file(socket);
        let _ = std::fs::remove_file(program);
        let _ = std::fs::remove_file(counter);
    }

    #[tokio::test]
    async fn aborted_drain_retains_detached_generation_marker_and_stable_state() {
        let (program, counter) = write_fake_lsapi_master("abort-drain", false);
        let socket = probe_socket("abort-drain");
        let _ = std::fs::remove_file(&socket);
        let supervisor = Arc::new(LsphpSupervisor::new(fake_supervisor_config(
            program.clone(),
            &socket,
        )));
        supervisor.start().await.unwrap();
        let marker = supervisor
            .inner
            .lock()
            .child_marker
            .clone()
            .expect("live generation marker");
        let pause = install_quiesce_test_pause(&marker);
        let task_supervisor = supervisor.clone();
        let task = tokio::spawn(async move { task_supervisor.drain_graceful().await });
        tokio::time::timeout(Duration::from_secs(2), pause.entered.notified())
            .await
            .expect("drain must reach generation quiesce");

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        {
            let inner = supervisor.inner.lock();
            assert_eq!(inner.state, WorkerState::Bad);
            assert!(inner.child.is_none());
            assert!(inner.child_marker.is_none());
            assert_eq!(inner.retired_markers, vec![marker.clone()]);
        }
        supervisor.cleanup_retired_markers().await.unwrap();
        assert!(scan_generation(&marker, None).unwrap().is_empty());

        let _ = std::fs::remove_file(socket);
        let _ = std::fs::remove_file(program);
        let _ = std::fs::remove_file(counter);
    }

    #[tokio::test]
    async fn failed_candidate_keeps_the_old_generation_good() {
        let (program, counter) = write_fake_lsapi_master("candidate-fail", true);
        let socket = probe_socket("candidate-fail");
        let _ = std::fs::remove_file(&socket);
        let listener = StdUnixListener::bind(&socket).unwrap();
        rustix::net::listen(&listener, 128).unwrap();
        let mut config = fake_supervisor_config(program.clone(), &socket);
        config.start_timeout = Duration::from_millis(250);
        let supervisor = LsphpSupervisor::new(config).with_listen_fd(listener.into());

        supervisor.start().await.expect("first fake generation");
        let old_pid = supervisor.worker_pid().unwrap();
        let error = supervisor
            .hot_reload()
            .await
            .expect_err("second invocation exits before readiness");

        assert!(matches!(error.kind(), io::ErrorKind::TimedOut));
        assert_eq!(supervisor.state(), WorkerState::Good);
        assert_eq!(supervisor.generation(), 1);
        assert_eq!(supervisor.worker_pid(), Some(old_pid));
        assert!(supervisor.is_alive().unwrap());

        supervisor.drain_graceful().await.unwrap();
        let _ = std::fs::remove_file(socket);
        let _ = std::fs::remove_file(program);
        let _ = std::fs::remove_file(counter);
    }

    #[tokio::test]
    #[ignore = "spawns the real lsphp; run manually on an R&D box"]
    async fn real_lsphp_workers_retain_the_exact_generation_marker() {
        let lsphp = PathBuf::from("/usr/local/lsws/lsphp8/bin/lsphp");
        if !lsphp.exists() {
            eprintln!("lsphp not found at {lsphp:?}; skipping");
            return;
        }

        let socket = probe_socket("real-marker");
        let _ = std::fs::remove_file(&socket);
        let mut config =
            SupervisorConfig::from_php_config(&sample_php(), &socket, "nobody", "nobody");
        config.command = lsphp;
        config.children = 4;
        config.normalize();
        let supervisor = LsphpSupervisor::new(config);
        supervisor.start().await.expect("real lsphp generation");

        let (master, marker) = {
            let inner = supervisor.inner.lock();
            (
                inner
                    .child
                    .as_ref()
                    .and_then(Child::id)
                    .expect("master pid"),
                inner.child_marker.clone().expect("generation marker"),
            )
        };
        let workers = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let workers: Vec<_> = scan_generation(&marker, Some(master))
                    .expect("scan real lsphp generation")
                    .into_iter()
                    .filter(|process| process.pid != master && process.is_lsapi)
                    .collect();
                if !workers.is_empty() {
                    break workers;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("real lsphp setsid worker");

        for worker in workers {
            assert!(
                process_has_marker(worker.pid, &marker).expect("read worker environment"),
                "real lsphp worker {} must retain {GENERATION_MARKER_ENV} exactly",
                worker.pid
            );
        }

        supervisor.drain_graceful().await.unwrap();
        let _ = std::fs::remove_file(socket);
    }

    #[tokio::test]
    async fn full_generation_drain_kills_and_reaps_a_detached_worker() {
        assert!(ensure_child_subreaper());
        let base = std::env::temp_dir().join(format!(
            "hj-lsapi-detached-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let program = base.with_extension("py");
        let pid_file = base.with_extension("pid");
        let unexpected_signal_file = base.with_extension("usr1");
        let marker = format!("detached-test-{}-{}", std::process::id(), rand_suffix());
        let source = format!(
            r#"#!/usr/bin/python3
import ctypes
import os
import signal
import time

signal.signal(signal.SIGUSR1, signal.SIG_IGN)
child = os.fork()
if child == 0:
    os.setsid()
    ctypes.CDLL(None).prctl(15, b"lsphp", 0, 0, 0)
    def unexpected_usr1(_signal, _frame):
        with open({unexpected_signal_file:?}, "w") as output:
            output.write("signalled")
    signal.signal(signal.SIGUSR1, unexpected_usr1)
    with open({pid_file:?}, "w") as output:
        output.write(str(os.getpid()))
    while True:
        time.sleep(1)
while True:
    time.sleep(1)
"#,
            pid_file = pid_file,
            unexpected_signal_file = unexpected_signal_file,
        );
        std::fs::write(&program, source).unwrap();
        let mut permissions = std::fs::metadata(&program).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&program, permissions).unwrap();

        let mut child = Command::new(&program)
            .env(GENERATION_MARKER_ENV, &marker)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let worker_pid = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(value) = std::fs::read_to_string(&pid_file) {
                    if let Ok(pid) = value.parse::<u32>() {
                        break pid;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("detached worker pid");
        assert!(proc_stat(worker_pid).is_some());
        assert!(
            scan_generation(&marker, child.id())
                .unwrap()
                .iter()
                .any(|process| process.pid == worker_pid),
            "detached worker must be retained by generation marker"
        );

        let cancel = CancellationToken::new();
        cancel.cancel();
        let forced_cleanup_count = AtomicU64::new(0);
        drain_generation(
            &mut child,
            &marker,
            Path::new("/tmp/hj-lsapi-detached-no-socket"),
            Some(&cancel),
            true,
            &forced_cleanup_count,
        )
        .await
        .expect("complete family cleanup");
        assert_eq!(forced_cleanup_count.load(Ordering::Relaxed), 1);
        assert!(
            proc_stat(worker_pid).is_none(),
            "detached worker must be killed and reaped"
        );
        assert!(
            scan_generation(&marker, None).unwrap().is_empty(),
            "drain must not report success while a marked process survives"
        );
        assert!(
            !unexpected_signal_file.exists(),
            "request subprocesses must not receive lsphp's graceful signal"
        );

        let _ = std::fs::remove_file(program);
        let _ = std::fs::remove_file(pid_file);
        let _ = std::fs::remove_file(unexpected_signal_file);
    }

    #[tokio::test]
    async fn postcommit_error_still_forces_and_reaps_the_complete_generation() {
        assert!(ensure_child_subreaper());
        let base = std::env::temp_dir().join(format!(
            "hj-lsapi-postcommit-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let program = base.with_extension("py");
        let pid_file = base.with_extension("pid");
        let marker = format!("postcommit-test-{}-{}", std::process::id(), rand_suffix());
        let source = format!(
            r#"#!/usr/bin/python3
import ctypes
import os
import time

child = os.fork()
if child == 0:
    os.setsid()
    ctypes.CDLL(None).prctl(15, b"lsphp", 0, 0, 0)
    with open({pid_file:?}, "w") as output:
        output.write(str(os.getpid()))
    while True:
        time.sleep(1)
while True:
    time.sleep(1)
"#,
            pid_file = pid_file,
        );
        std::fs::write(&program, source).unwrap();
        let mut permissions = std::fs::metadata(&program).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&program, permissions).unwrap();

        let mut child = Command::new(&program)
            .env(GENERATION_MARKER_ENV, &marker)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let worker_pid = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(value) = std::fs::read_to_string(&pid_file) {
                    if let Ok(pid) = value.parse::<u32>() {
                        break pid;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("detached worker pid");
        let master = child.id();
        let forced_cleanup_count = AtomicU64::new(0);
        let error = finish_generation_drain(
            &mut child,
            &marker,
            master,
            Vec::new(),
            Path::new("/tmp/hj-lsapi-postcommit-no-socket"),
            None,
            false,
            Some(io::Error::other("injected post-commit signal failure")),
            &forced_cleanup_count,
        )
        .await
        .expect_err("the original post-commit failure must be returned");

        assert!(
            error
                .to_string()
                .contains("injected post-commit signal failure")
        );
        assert_eq!(forced_cleanup_count.load(Ordering::Relaxed), 1);
        assert!(proc_stat(worker_pid).is_none());
        assert!(scan_generation(&marker, None).unwrap().is_empty());
        assert!(child.try_wait().unwrap().is_some(), "master must be reaped");

        let _ = std::fs::remove_file(program);
        let _ = std::fs::remove_file(pid_file);
    }

    #[tokio::test]
    async fn generation_marker_survives_master_exit_and_reparenting() {
        assert!(ensure_child_subreaper());
        let base = std::env::temp_dir().join(format!(
            "hj-lsapi-reparent-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let program = base.with_extension("py");
        let pid_file = base.with_extension("pid");
        let marker = format!("reparent-test-{}-{}", std::process::id(), rand_suffix());
        let source = format!(
            r#"#!/usr/bin/python3
import os
import time

child = os.fork()
if child == 0:
    os.setsid()
    with open({pid_file:?}, "w") as output:
        output.write(str(os.getpid()))
    while True:
        time.sleep(1)
"#,
            pid_file = pid_file,
        );
        std::fs::write(&program, source).unwrap();
        let mut permissions = std::fs::metadata(&program).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&program, permissions).unwrap();

        let mut master = Command::new(&program)
            .env(GENERATION_MARKER_ENV, &marker)
            .spawn()
            .unwrap();
        master.wait().await.unwrap();
        let worker_pid = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(value) = std::fs::read_to_string(&pid_file) {
                    if let Ok(pid) = value.parse::<u32>() {
                        break pid;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reparented worker pid");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if scan_generation(&marker, None)
                    .unwrap()
                    .iter()
                    .any(|process| process.pid == worker_pid)
                    && proc_stat(worker_pid).is_some_and(|(parent, _)| parent == std::process::id())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("marker must retain the worker after its master exits");

        force_cleanup_marker(&marker).await.unwrap();
        assert!(proc_stat(worker_pid).is_none());
        assert!(scan_generation(&marker, None).unwrap().is_empty());
        let _ = std::fs::remove_file(program);
        let _ = std::fs::remove_file(pid_file);
    }

    #[tokio::test]
    async fn autonomous_crash_replacement_publishes_once() {
        let (program, counter) = write_fake_lsapi_master("crash-promotion", false);
        let socket = probe_socket("crash-promotion");
        let _ = std::fs::remove_file(&socket);
        let listener = StdUnixListener::bind(&socket).unwrap();
        rustix::net::listen(&listener, 128).unwrap();
        let supervisor = LsphpSupervisor::new(fake_supervisor_config(program.clone(), &socket))
            .with_listen_fd(listener.into());
        let publish_count = Arc::new(AtomicU64::new(0));
        let last_generation = Arc::new(AtomicU64::new(0));
        let count_seen = publish_count.clone();
        let generation_seen = last_generation.clone();
        assert!(
            supervisor.set_promotion_hook(Arc::new(move |generation, marker| {
                assert!(!marker.is_empty());
                count_seen.fetch_add(1, Ordering::AcqRel);
                generation_seen.store(generation, Ordering::Release);
            }))
        );

        supervisor.start().await.unwrap();
        assert_eq!(publish_count.load(Ordering::Acquire), 1);
        assert_eq!(last_generation.load(Ordering::Acquire), 1);
        let old_pid = supervisor.worker_pid().unwrap();
        unsafe {
            libc::kill(old_pid as libc::pid_t, libc::SIGKILL);
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if supervisor.poll_liveness() == WorkerState::NotStarted {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("dead master must be observed");

        supervisor.restart_debounced().await.unwrap();
        assert_eq!(supervisor.generation(), 2);
        assert_eq!(publish_count.load(Ordering::Acquire), 2);
        assert_eq!(last_generation.load(Ordering::Acquire), 2);
        assert!(
            supervisor.inner.lock().retired_markers.is_empty(),
            "autonomous replacement must eagerly clean the dead generation marker"
        );

        supervisor.drain_graceful().await.unwrap();
        let _ = std::fs::remove_file(socket);
        let _ = std::fs::remove_file(program);
        let _ = std::fs::remove_file(counter);
    }

    #[tokio::test]
    async fn poll_liveness_does_not_reap_a_transition_owned_child() {
        let socket = probe_socket("transition-liveness");
        let cfg = SupervisorConfig::from_php_config(&sample_php(), &socket, "", "");
        let supervisor = LsphpSupervisor::new(cfg);
        let child = Command::new("/bin/true").spawn().unwrap();
        {
            let mut inner = supervisor.inner.lock();
            inner.child = Some(child);
            inner.child_marker = Some("transition-test".to_string());
            inner.state = WorkerState::Starting;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(supervisor.poll_liveness(), WorkerState::Starting);
        let mut child = {
            let mut inner = supervisor.inner.lock();
            assert!(inner.child.is_some());
            inner.state = WorkerState::NotStarted;
            inner.child_marker = None;
            inner.child.take().unwrap()
        };
        child.wait().await.unwrap();
        let _ = std::fs::remove_file(socket);
    }

    #[test]
    fn systemd_stop_timeout_has_headroom_beyond_worker_grace() {
        let unit = include_str!("../../../packaging/systemd/httpjet-lsphp.service");
        let seconds = unit
            .lines()
            .find_map(|line| line.strip_prefix("TimeoutStopSec="))
            .and_then(|value| value.parse::<u64>().ok())
            .expect("httpjet-lsphp.service TimeoutStopSec");
        assert!(
            Duration::from_secs(seconds) >= GRACE_TIMEOUT + Duration::from_secs(10),
            "systemd must leave kill/reap headroom after the {GRACE_TIMEOUT:?} worker grace"
        );
    }

    /// A representative PhpConfig for SupervisorConfig tests.
    fn sample_php() -> hj_core::config::PhpConfig {
        hj_core::config::PhpConfig {
            handler_id: "lsphp".into(),
            command: PathBuf::from("/usr/local/lsws/lsphp8/bin/lsphp"),
            suffixes: vec!["php".into()],
            env: vec![
                ("PHP_LSAPI_CHILDREN".into(), "35".into()),
                ("PHP_LSAPI_MAX_REQUESTS".into(), "5000".into()),
            ],
            max_conns: 10,
            backlog: 1024,
            init_timeout: Duration::from_secs(3),
            retry_timeout: Duration::from_secs(0),
            pc_keep_alive_timeout: Duration::from_secs(0),
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
        }
    }

    #[test]
    fn from_php_config_reads_children_env() {
        let php = sample_php();
        let cfg =
            SupervisorConfig::from_php_config(&php, "/tmp/php8-httpjet.sock", "nobody", "nobody");
        assert_eq!(cfg.children, 35);
        assert_eq!(cfg.max_requests, 5000);
        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/php8-httpjet.sock"));
        // Restart knobs flow through from the config defaults.
        assert_eq!(cfg.min_restart_interval, Duration::from_secs(10));
        assert_eq!(cfg.max_restart_backoff, Duration::from_secs(30));
    }

    #[test]
    fn single_child_is_normalized_to_a_persistent_prefork_pool() {
        let mut php = sample_php();
        php.env
            .retain(|(key, _)| key != "PHP_LSAPI_CHILDREN" && key != "LSAPI_CHILDREN");
        php.env
            .push(("PHP_LSAPI_CHILDREN".to_string(), "1".to_string()));

        let cfg = SupervisorConfig::from_php_config(&php, "/tmp/x.sock", "", "");
        assert_eq!(cfg.children, MIN_SUPERVISED_CHILDREN);
        assert_eq!(
            cfg.env
                .iter()
                .find(|(key, _)| key == "PHP_LSAPI_CHILDREN")
                .map(|(_, value)| value.as_str()),
            Some("2")
        );

        let mut manually_overridden = cfg;
        manually_overridden.children = 1;
        manually_overridden
            .env
            .iter_mut()
            .find(|(key, _)| key == "PHP_LSAPI_CHILDREN")
            .unwrap()
            .1 = "1".to_string();
        let supervisor = LsphpSupervisor::new(manually_overridden);
        assert_eq!(supervisor.config().children, MIN_SUPERVISED_CHILDREN);
        assert_eq!(
            supervisor
                .config()
                .env
                .iter()
                .find(|(key, _)| key == "PHP_LSAPI_CHILDREN")
                .map(|(_, value)| value.as_str()),
            Some("2")
        );
    }

    #[test]
    fn from_php_config_populates_limits() {
        let mut php = sample_php();
        php.mem_soft_limit = Some(256 * 1024 * 1024);
        php.mem_hard_limit = Some(512 * 1024 * 1024);
        php.cpu_limit_secs = Some(hj_core::config::RlimitPair {
            soft: Some(30),
            hard: Some(60),
        });
        php.proc_soft_limit = Some(40);
        php.proc_hard_limit = Some(50);
        let cfg = SupervisorConfig::from_php_config(&php, "/tmp/php8-httpjet.sock", "", "");
        assert_eq!(cfg.limits.mem_soft, Some(256 * 1024 * 1024));
        assert_eq!(cfg.limits.mem_hard, Some(512 * 1024 * 1024));
        assert_eq!(cfg.limits.cpu_soft_secs, Some(30));
        assert_eq!(cfg.limits.cpu_hard_secs, Some(60));
        assert_eq!(cfg.limits.nproc_soft, Some(40));
        assert_eq!(cfg.limits.nproc_hard, Some(50));
    }

    #[test]
    fn from_php_config_preserves_nproc_soft_without_hard() {
        let mut php = sample_php();
        php.proc_soft_limit = Some(40);
        php.proc_hard_limit = None;
        let cfg = SupervisorConfig::from_php_config(&php, "/tmp/php8-httpjet.sock", "", "");
        assert_eq!(cfg.limits.nproc_soft, Some(40));
        assert_eq!(cfg.limits.nproc_hard, None);
    }

    #[test]
    fn from_php_config_default_limits_empty() {
        let cfg = SupervisorConfig::from_php_config(&sample_php(), "/tmp/x.sock", "", "");
        assert!(cfg.limits.is_empty());
    }

    #[test]
    fn fresh_supervisor_state_and_generation() {
        let cfg = SupervisorConfig::from_php_config(&sample_php(), "/tmp/x.sock", "", "");
        let sup = LsphpSupervisor::new(cfg);
        assert_eq!(sup.state(), WorkerState::NotStarted);
        assert_eq!(sup.generation(), 0);
        assert_eq!(sup.worker_pid(), None);
        // No child -> poll_liveness stays NotStarted, is_alive false.
        assert_eq!(sup.poll_liveness(), WorkerState::NotStarted);
        assert!(!sup.is_alive().unwrap());
    }

    #[test]
    fn restart_debounced_skips_within_window() {
        // A freshly-constructed supervisor has last_restart ~1h in the past, so
        // the first debounced restart is NOT skipped by the window; instead we
        // verify the window logic directly via a manual state poke.
        let cfg = SupervisorConfig::from_php_config(&sample_php(), "/tmp/x.sock", "", "");
        let sup = LsphpSupervisor::new(cfg);
        {
            let mut g = sup.inner.lock();
            g.last_restart = Instant::now(); // just restarted
            g.state = WorkerState::Good;
        }
        // Within min_restart_interval (10s) -> debounced restart should skip and
        // leave state unchanged (Good).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            sup.restart_debounced().await.unwrap();
        });
        assert_eq!(sup.state(), WorkerState::Good);
        assert_eq!(sup.generation(), 0); // no successful start happened
    }

    #[test]
    fn restart_debounced_noop_while_starting_or_draining() {
        let cfg = SupervisorConfig::from_php_config(&sample_php(), "/tmp/x.sock", "", "");
        let sup = LsphpSupervisor::new(cfg);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        for st in [WorkerState::Starting, WorkerState::Draining] {
            sup.inner.lock().state = st;
            rt.block_on(async { sup.restart_debounced().await.unwrap() });
            assert_eq!(sup.state(), st, "restart should be a no-op in {st:?}");
        }
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let base = Duration::from_secs(10);
        let max = Duration::from_secs(30);
        assert_eq!(backoff_for(base, 0, max), Duration::ZERO);
        assert_eq!(backoff_for(base, 1, max), Duration::from_secs(20));
        // 10 * 2^2 = 40 -> capped to 30.
        assert_eq!(backoff_for(base, 2, max), Duration::from_secs(30));
        // Large failure counts saturate, still capped.
        assert_eq!(backoff_for(base, 1000, max), Duration::from_secs(30));
    }
}
