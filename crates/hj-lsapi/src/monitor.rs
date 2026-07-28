//! Runtime resilience monitor: the single restart authority for an lsphp master.
//!
//! A [`Monitor`] owns the supervisor + the connection pool and runs a ~1s ticker
//! that:
//!
//! 1. **Liveness** — [`LsphpSupervisor::poll_liveness`]; if the worker is
//!    `NotStarted`/`Bad` it clears the pool, debounce-restarts the master, and on
//!    success advances the pool generation so stale sockets are discarded.
//! 2. **Idle pruning** — drops idle pooled sockets past the keep-alive TTL.
//! 3. **Hung-request (Tier 2)** — if the oldest in-flight request has exceeded
//!    `max_process_time + grace`, it SIGTERM→SIGKILLs and restarts the master
//!    (this aborts every in-flight request on that pool — see [`Monitor`] docs).
//!
//! The monitor is also nudged by the handler via [`Monitor::request_restart`]
//! (a [`tokio::sync::Notify`]): concurrent nudges coalesce because the actual
//! restart goes through [`LsphpSupervisor::restart_debounced`], which is itself
//! debounced. Handlers can briefly await recovery by subscribing to the
//! [`watch::Receiver<WorkerState>`] returned by [`Monitor::subscribe`].
//!
//! ## Hung-request tiers (verified against vendor/lsapilib.c)
//! lsphp has NO ABORT_REQUEST consumer, so we cannot signal a hung worker to stop
//! a single request. Hung handling is two-tier:
//!   - **Tier 1** (in the handler): a TOTAL processing-time deadline across the
//!     response read; on expiry the handler poisons the connection, closes our
//!     side, and returns 504. lsphp notices on its next socket write.
//!   - **Tier 2** (here): if a request runs past `max_process_time + grace`, the
//!     whole master is killed and restarted, aborting in-flight requests on the
//!     pool. This is the blunt backstop for a worker wedged in uninterruptible
//!     work that never writes again.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::pool::LsapiPool;
use crate::supervisor::{LsphpSupervisor, WorkerState};

/// How often the monitor ticks (liveness + prune + hung check).
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Extra slack added to `max_process_time` before Tier 2 kills the master, so the
/// Tier 1 (handler) deadline gets the first, gentler attempt at recovery.
const DEFAULT_HUNG_GRACE: Duration = Duration::from_secs(5);

/// Shared tracker of in-flight requests against one pool. The handler brackets a
/// request with [`InFlight::begin`] (returning an RAII [`InFlightGuard`]); the
/// monitor reads [`InFlight::oldest_age`] to detect a hung request.
///
/// Implementation: a small vector of start `Instant`s keyed by a monotonic id.
/// At the concurrency this pool runs (a few × `php_children`), linear scans are
/// trivially cheap and avoid a heap/ordering dependency.
#[derive(Default)]
pub struct InFlight {
    inner: Mutex<InFlightInner>,
}

#[derive(Default)]
struct InFlightInner {
    next_id: u64,
    /// (id, started_at) for each currently in-flight request.
    entries: Vec<(u64, Instant)>,
}

impl InFlight {
    pub fn new() -> Arc<Self> {
        Arc::new(InFlight::default())
    }

    /// Mark a request as started; the returned guard removes the entry on drop.
    pub fn begin(self: &Arc<Self>) -> InFlightGuard {
        let id = {
            let mut g = self.inner.lock();
            let id = g.next_id;
            g.next_id = g.next_id.wrapping_add(1);
            g.entries.push((id, Instant::now()));
            id
        };
        InFlightGuard {
            tracker: self.clone(),
            id,
        }
    }

    /// Age of the OLDEST in-flight request, or `None` if the pool is idle.
    pub fn oldest_age(&self) -> Option<Duration> {
        let now = Instant::now();
        self.inner
            .lock()
            .entries
            .iter()
            // `now` is snapshotted before the lock, so a concurrent begin() on
            // another core can stamp an entry with `*t > now`. Instant::
            // duration_since panics on that underflow; checked_duration_since
            // saturates a just-stamped (not-yet-hung) entry to zero instead.
            .map(|(_, t)| now.checked_duration_since(*t).unwrap_or(Duration::ZERO))
            .max()
    }

    /// Number of in-flight requests.
    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().entries.is_empty()
    }

    fn end(&self, id: u64) {
        let mut g = self.inner.lock();
        if let Some(pos) = g.entries.iter().position(|(eid, _)| *eid == id) {
            g.entries.swap_remove(pos);
        }
    }

    /// Drop all currently-tracked start stamps. Called after a Tier-2 hung kill so a
    /// still-parked handler's stale entry does not re-trigger the kill every tick (#47).
    /// Safe vs live `InFlightGuard`s: their later `end(id)` no-ops on a missing id, and
    /// `next_id` only advances, so no id is ever reused for a post-reset request.
    pub fn reset(&self) {
        self.inner.lock().entries.clear();
    }
}

/// RAII guard removing its in-flight entry when dropped (request completed or
/// errored). Held by the handler for the full request lifetime.
pub struct InFlightGuard {
    tracker: Arc<InFlight>,
    id: u64,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.tracker.end(self.id);
    }
}

/// Construction parameters for a [`Monitor`].
pub struct MonitorConfig {
    pub supervisor: Arc<LsphpSupervisor>,
    pub pool: Arc<LsapiPool>,
    /// Idle TTL for pruning pooled sockets (PhpConfig `pc_keep_alive_timeout`).
    pub idle_ttl: Duration,
    /// Tier 1 total processing deadline (PhpConfig `max_process_time`); `None`
    /// disables BOTH the handler deadline and the Tier 2 kill.
    pub max_process_time: Option<Duration>,
    /// Extra slack before Tier 2 fires (after the handler's Tier 1 504). Defaults
    /// to 5s if left at its `Default`.
    pub hung_grace: Duration,
    /// Shutdown token shared with the supervisor so one cancel stops BOTH the
    /// ticker and the supervisor's kill-loop wait (#29). `None` ⇒ the monitor
    /// mints its own (the ticker is then the only thing it stops).
    pub cancel: Option<CancellationToken>,
}

impl MonitorConfig {
    /// Defaults: 30s idle TTL, no processing-time cap, the standard hung grace.
    /// Callers normally override `idle_ttl` from `PhpConfig.pc_keep_alive_timeout`
    /// and `max_process_time` from `PhpConfig.max_process_time`.
    pub fn new(supervisor: Arc<LsphpSupervisor>, pool: Arc<LsapiPool>) -> Self {
        MonitorConfig {
            supervisor,
            pool,
            idle_ttl: Duration::from_secs(30),
            max_process_time: None,
            hung_grace: DEFAULT_HUNG_GRACE,
            cancel: None,
        }
    }
}

/// The resilience monitor. Construct via [`Monitor::spawn`], which returns the
/// shared handle plus the ticker's [`JoinHandle`]. Shut down by cancelling the
/// returned token (see [`Monitor::cancel_token`]).
pub struct Monitor {
    supervisor: Arc<LsphpSupervisor>,
    pool: Arc<LsapiPool>,
    idle_ttl: Duration,
    max_process_time: Option<Duration>,
    hung_grace: Duration,
    /// Nudged by handlers to request a restart; coalesced by the debounce.
    restart_req: Notify,
    /// Latest worker state, observable by handlers awaiting recovery.
    state_tx: watch::Sender<WorkerState>,
    /// Cancels the ticker (drive from the server's shutdown path).
    cancel: CancellationToken,
    /// In-flight request tracker shared with the handler.
    inflight: Arc<InFlight>,
}

impl Monitor {
    /// Build the monitor and spawn its ticker task. Returns the shared handle and
    /// the ticker `JoinHandle`. The ticker runs until [`Monitor::cancel_token`]
    /// is cancelled (or the handle is dropped and the token with it).
    pub fn spawn(cfg: MonitorConfig) -> (Arc<Monitor>, JoinHandle<()>) {
        let initial = cfg.supervisor.state();
        let (state_tx, _state_rx) = watch::channel(initial);
        let monitor = Arc::new(Monitor {
            supervisor: cfg.supervisor,
            pool: cfg.pool,
            idle_ttl: cfg.idle_ttl,
            max_process_time: cfg.max_process_time,
            hung_grace: cfg.hung_grace,
            restart_req: Notify::new(),
            state_tx,
            cancel: cfg.cancel.unwrap_or_else(CancellationToken::new),
            inflight: InFlight::new(),
        });
        let handle = tokio::spawn(monitor.clone().run());
        (monitor, handle)
    }

    /// The in-flight tracker the handler must bracket each request with.
    pub fn inflight(&self) -> Arc<InFlight> {
        self.inflight.clone()
    }

    /// The cancellation token; cancel it (BEFORE draining the supervisor) to stop
    /// the ticker so it does not fight an intentional shutdown.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Subscribe to worker-state changes (handlers await this to briefly wait for
    /// recovery after nudging a restart).
    pub fn subscribe(&self) -> watch::Receiver<WorkerState> {
        self.state_tx.subscribe()
    }

    /// Nudge the monitor to (debounce-)restart the worker. Safe to call from many
    /// handlers concurrently: the wakeups coalesce and the restart itself is
    /// debounced, so the monitor remains the single restart authority.
    pub fn request_restart(&self) {
        self.restart_req.notify_one();
    }

    /// Max processing time configured (Tier 1 deadline used by the handler).
    pub fn max_process_time(&self) -> Option<Duration> {
        self.max_process_time
    }

    /// The supervisor handle (for the handler's fast 503-on-Bad check).
    pub fn supervisor(&self) -> &Arc<LsphpSupervisor> {
        &self.supervisor
    }

    /// One restart cycle: clear the pool, debounce-restart, and on success bump
    /// the pool generation to the supervisor's new generation so stale sockets
    /// are discarded. The monitor is the ONLY caller of this, keeping it the
    /// single restart authority.
    async fn do_restart(&self) {
        // Drop stale idle sockets up front; they belong to the worker we are
        // about to replace (or are unusable after the connection trouble that
        // prompted the nudge). Healthy sockets simply re-dial.
        self.pool.clear();
        match self.supervisor.restart_debounced().await {
            Ok(()) => {
                // restart_debounced may be a debounce no-op (no real restart), in
                // which case the supervisor generation is unchanged and
                // bump_generation is a no-op (it only moves forward). When the
                // worker actually came back Good with a higher generation, the
                // bump advances the pool epoch so any in-flight re-pool that spans
                // the restart is refused.
                self.pool.bump_generation(self.supervisor.generation());
            }
            Err(e) => {
                tracing::error!(error = %e, "lsphp restart failed");
            }
        }
        self.publish_state();
    }

    /// Publish the current supervisor state to the watch channel (only sends on a
    /// change, since `watch::Sender::send_if_modified` dedupes).
    fn publish_state(&self) {
        let s = self.supervisor.state();
        self.state_tx.send_if_modified(|cur| {
            if *cur != s {
                *cur = s;
                true
            } else {
                false
            }
        });
    }

    /// The ticker loop. Consumes an `Arc<Self>` so it can be `tokio::spawn`ed.
    async fn run(self: Arc<Self>) {
        let mut tick = tokio::time::interval(TICK_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    tracing::debug!("lsphp monitor cancelled; stopping ticker");
                    break;
                }
                // Handler-driven restart nudge.
                _ = self.restart_req.notified() => {
                    self.do_restart().await;
                }
                _ = tick.tick() => {
                    self.on_tick().await;
                }
            }
        }
    }

    /// One periodic tick: liveness, prune, and the Tier 2 hung-request check.
    async fn on_tick(&self) {
        // (1) Liveness: a dead or bad worker triggers a clear + debounced restart.
        let state = self.supervisor.poll_liveness();
        self.publish_state();
        if matches!(state, WorkerState::NotStarted | WorkerState::Bad) {
            self.do_restart().await;
            // After a restart attempt, skip the rest of this tick: a fresh worker
            // has no idle sockets to prune and no in-flight to be hung.
            return;
        }

        // (2) Idle pruning of stale keep-alive sockets.
        self.pool.prune_idle(self.idle_ttl);

        // (3) Tier 2 hung-request kill: if the OLDEST in-flight request has run
        //     past max_process_time + grace, the worker is wedged in a way the
        //     Tier 1 (handler) 504 could not recover (no further socket write).
        //     SIGTERM->SIGKILL + restart the master. NOTE: this ABORTS every
        //     in-flight request on this pool, so it is gated behind the grace.
        if let Some(limit) = self.max_process_time {
            let kill_after = limit.saturating_add(self.hung_grace);
            if let Some(age) = self.inflight.oldest_age() {
                if age >= kill_after {
                    tracing::warn!(
                        oldest_age = ?age,
                        max_process_time = ?limit,
                        "lsphp request exceeded max_process_time + grace; killing master"
                    );
                    self.pool.clear();
                    if let Err(e) = self.supervisor.kill_and_restart().await {
                        tracing::error!(error = %e, "lsphp kill_and_restart failed");
                    } else if self.supervisor.state() == WorkerState::Good {
                        self.pool.bump_generation(self.supervisor.generation());
                    }
                    // One kill per hang: drop the stale start-stamps so a still-parked handler
                    // does not re-trigger the Tier-2 kill on the next tick. Live guards' later
                    // end() no-op on the now-missing id (#47). Reset unconditionally so a
                    // persistent hang + repeated kill-failure cannot spin every tick.
                    self.inflight.reset();
                    self.publish_state();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflight_tracks_oldest_age() {
        let t = InFlight::new();
        assert!(t.is_empty());
        assert_eq!(t.oldest_age(), None);
        let g1 = t.begin();
        assert_eq!(t.len(), 1);
        let _g2 = t.begin();
        assert_eq!(t.len(), 2);
        // Oldest age is non-None and monotonic-ish; we cannot assert ordering of
        // the two without sleeping, but both entries exist.
        assert!(t.oldest_age().is_some());
        drop(g1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn inflight_guard_removes_on_drop() {
        let t = InFlight::new();
        {
            let _g = t.begin();
            assert_eq!(t.len(), 1);
        }
        assert_eq!(t.len(), 0);
        assert!(t.oldest_age().is_none());
    }

    #[tokio::test]
    async fn inflight_oldest_age_grows() {
        let t = InFlight::new();
        let _g = t.begin();
        let a = t.oldest_age().unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let b = t.oldest_age().unwrap();
        assert!(b > a, "oldest age should grow over time");
    }

    // (#21) Regression: oldest_age() snapshots `now` BEFORE locking, so a
    // concurrent begin() on another core can stamp an entry with `*t > now`.
    // `Instant::duration_since` panics on that underflow ("supplied instant is
    // later than self"), which would kill the monitor task. Here we inject a
    // future-stamped entry directly to deterministically reproduce that ordering
    // and assert oldest_age() returns Duration::ZERO instead of panicking.
    #[test]
    fn oldest_age_no_panic_on_future_entry() {
        let t = InFlight::new();
        {
            let mut g = t.inner.lock();
            // An entry stamped well after any `now` oldest_age() will snapshot.
            let future = Instant::now() + Duration::from_secs(3600);
            let id = g.next_id;
            g.next_id = g.next_id.wrapping_add(1);
            g.entries.push((id, future));
        }
        // Must not panic; the not-yet-elapsed entry saturates to zero age.
        let age = t.oldest_age().expect("one entry present");
        assert_eq!(age, Duration::ZERO);
    }

    #[test]
    fn reset_clears_entries_and_stale_guard_drop_is_noop() {
        // #47: after a Tier-2 hung kill the monitor calls reset() so a still-parked handler's
        // stale start-stamp does not re-trigger the kill every tick. reset() must clear all
        // current entries; a new request after reset is still tracked; and dropping a guard
        // whose entry was cleared is a harmless no-op (it must not remove the live entry, since
        // next_id only advances so the cleared guard's id can never match a later one).
        let t = InFlight::new();
        let g1 = t.begin();
        let _g2 = t.begin();
        assert_eq!(t.len(), 2);
        t.reset();
        assert_eq!(t.len(), 0, "reset drops all current start-stamps");
        assert!(t.oldest_age().is_none());
        let _g3 = t.begin(); // a new request after the kill is tracked normally
        assert_eq!(t.len(), 1);
        drop(g1); // dropping a guard whose entry was cleared must not remove the live entry
        assert_eq!(
            t.len(),
            1,
            "stale guard drop after reset is a harmless no-op"
        );
    }
}
