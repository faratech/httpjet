//! Single-flight registry for the origin page cache: collapse concurrent cache
//! MISSES of the same key into one backend render (the leader), so a hot page's
//! TTL expiry doesn't stampede the (PHP) backend with N identical renders.
//!
//! Plus the [`RefreshRegistry`]: a SIBLING primitive for stale-while-revalidate.
//! Where single-flight makes followers BLOCK on a leader (a miss-collapse), a
//! background refresh must NOT block anyone — it fires at most once per key, off
//! the client path, bounded by a global concurrency cap so a wave of stale hits
//! can't spawn unbounded PHP renders.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct InflightState {
    completed: AtomicBool,
    notify: tokio::sync::Notify,
}

impl InflightState {
    fn new() -> Self {
        Self {
            completed: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }
}

/// Single-flight registry: collapses concurrent cache MISSES of the same key into a single
/// backend render. The first misser becomes the leader (renders + stores); concurrent
/// missers of the same key are followers that wait for the leader, then serve from the
/// freshly-filled cache instead of stampeding the (PHP) backend at a hot page's TTL expiry.
/// Keyed by the page-cache key hash, so different pages never serialize and a page never
/// blocks on itself (a render does not sub-request its own URL).
#[derive(Default)]
pub struct InflightRegistry {
    map: dashmap::DashMap<u64, Arc<InflightState>>,
}

/// What [`InflightRegistry::enter`] decided for a given key.
pub enum Enter {
    /// Sole renderer: hold this guard until the render+store finishes; dropping it wakes
    /// followers and removes the registry entry.
    Leader(InflightLeader),
    /// Another request is already rendering this key — await it, then re-check the cache.
    Follower(InflightFollower),
}

/// A follower's sticky view of the current leader's completion.
#[derive(Clone)]
pub struct InflightFollower {
    state: Arc<InflightState>,
}

impl InflightFollower {
    /// Wait until the leader finishes. The atomic completion bit closes both
    /// Notify races: completion before this future exists, and completion
    /// between the initial check and waiter registration.
    pub async fn wait(&self) {
        if self.state.completed.load(Ordering::Acquire) {
            return;
        }
        let notified = self.state.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.state.completed.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

/// RAII leader token. On drop (at any dispatch return, after `cache_store` on the cacheable
/// paths) it removes the registry entry and wakes followers so they re-read the cache.
pub struct InflightLeader {
    registry: Arc<InflightRegistry>,
    key_hash: u64,
    state: Arc<InflightState>,
}

impl InflightRegistry {
    /// Become the leader for `key_hash`, or get the leader's notify to wait on as a follower.
    pub fn enter(self: &Arc<Self>, key_hash: u64) -> Enter {
        use dashmap::mapref::entry::Entry;
        match self.map.entry(key_hash) {
            Entry::Occupied(e) => Enter::Follower(InflightFollower {
                state: e.get().clone(),
            }),
            Entry::Vacant(e) => {
                let state = Arc::new(InflightState::new());
                e.insert(state.clone());
                Enter::Leader(InflightLeader {
                    registry: self.clone(),
                    key_hash,
                    state,
                })
            }
        }
    }
}

impl Drop for InflightLeader {
    fn drop(&mut self) {
        // Remove BEFORE notifying: a woken follower's re-lookup then either hits the
        // now-stored entry or (if nothing was cacheable) starts a fresh leader, never
        // waiting on us again.
        self.registry.map.remove(&self.key_hash);
        // Completion is sticky for followers that have not started waiting yet;
        // notify_waiters releases every follower already registered on this state.
        self.state.completed.store(true, Ordering::Release);
        self.state.notify.notify_waiters();
    }
}

/// Coordinates stale-while-revalidate background refreshes. Two layers:
/// 1. a per-key CAS so AT MOST ONE background refresh runs for a given page at a
///    time (a wave of stale hits on one hot page ⇒ exactly one re-render);
/// 2. a global [`Semaphore`](tokio::sync::Semaphore) cap so the total number of
///    in-flight refreshes can't starve live traffic of PHP workers — when it is
///    saturated, a would-be refresh is simply skipped (the stale entry stays
///    servable and the next stale hit retries).
pub struct RefreshRegistry {
    inflight: dashmap::DashMap<u64, ()>,
    sem: Arc<tokio::sync::Semaphore>,
}

/// RAII token for an in-flight background refresh. On drop it frees the per-key
/// CAS slot AND releases the global concurrency permit, so the key can be
/// refreshed again later and another key may take the slot.
pub struct RefreshGuard {
    registry: Arc<RefreshRegistry>,
    key_hash: u64,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshStart {
    Started,
    Duplicate,
    Saturated,
    Unavailable,
}

impl RefreshRegistry {
    pub fn new(max_concurrent: usize) -> Arc<Self> {
        Arc::new(RefreshRegistry {
            inflight: dashmap::DashMap::new(),
            sem: Arc::new(tokio::sync::Semaphore::new(max_concurrent.max(1))),
        })
    }

    /// Try to become the sole background-refresher for `key_hash`. Returns a guard
    /// to hold for the duration of the refresh, or `None` if a refresh for this key
    /// is already in flight OR the global cap is saturated.
    pub fn try_begin(self: &Arc<Self>, key_hash: u64) -> Option<RefreshGuard> {
        self.try_begin_detailed(key_hash).0
    }

    /// As [`Self::try_begin`], but preserves why a task was refused so callers
    /// can distinguish harmless same-key coalescing from global pool saturation.
    pub fn try_begin_detailed(
        self: &Arc<Self>,
        key_hash: u64,
    ) -> (Option<RefreshGuard>, RefreshStart) {
        use dashmap::mapref::entry::Entry;
        // Take a global permit FIRST; if the cap is saturated, skip (the permit is
        // dropped on the `?`). Then CAS the per-key slot — if another refresh holds
        // it, drop the permit and skip.
        let Ok(permit) = self.sem.clone().try_acquire_owned() else {
            return (None, RefreshStart::Saturated);
        };
        match self.inflight.entry(key_hash) {
            Entry::Occupied(_) => (None, RefreshStart::Duplicate),
            Entry::Vacant(e) => {
                e.insert(());
                (
                    Some(RefreshGuard {
                        registry: self.clone(),
                        key_hash,
                        _permit: permit,
                    }),
                    RefreshStart::Started,
                )
            }
        }
    }

    /// In-flight refresh count (observability/tests).
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.registry.inflight.remove(&self.key_hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn refresh_registry_one_per_key_and_capped() {
        let reg = RefreshRegistry::new(2);
        // First refresh for key 1 wins.
        let g1 = reg.try_begin(1).expect("first refresh of a key wins");
        // A second concurrent refresh of the SAME key is refused.
        assert!(reg.try_begin(1).is_none(), "one background refresh per key");
        // A different key wins (still under the cap of 2).
        let g2 = reg.try_begin(2).expect("different key under cap wins");
        // The cap is now saturated (2 permits held): a third distinct key is skipped.
        assert!(
            reg.try_begin(3).is_none(),
            "global concurrency cap must bound refreshes"
        );
        assert_eq!(
            reg.try_begin_detailed(3).1,
            RefreshStart::Saturated,
            "the detailed result distinguishes saturation"
        );
        assert_eq!(reg.inflight_count(), 2);
        // Dropping a guard frees its key slot AND a permit.
        drop(g1);
        assert_eq!(reg.inflight_count(), 1);
        let g3 = reg
            .try_begin(3)
            .expect("a freed permit lets a new key refresh");
        drop(g2);
        drop(g3);
        assert_eq!(reg.inflight_count(), 0);
    }

    #[tokio::test]
    async fn inflight_leader_follower_and_reentry() {
        let reg = Arc::new(InflightRegistry::default());
        // First enter for a key → leader.
        let leader = match reg.enter(7) {
            Enter::Leader(g) => g,
            _ => panic!("first enter must be leader"),
        };
        // Concurrent enter, same key → follower with the leader's notify.
        let follower = match reg.enter(7) {
            Enter::Follower(n) => n,
            _ => panic!("second same-key enter must be follower"),
        };
        // A different key → its own leader (different pages never serialize).
        assert!(matches!(reg.enter(8), Enter::Leader(_)));

        // A waiter on the follower's notify is woken when the leader drops.
        let woken = follower.clone();
        let waiter = tokio::spawn(async move { woken.wait().await });
        tokio::task::yield_now().await; // let the waiter register
        drop(leader); // removes the slot and marks this generation complete
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("follower must be woken when the leader drops")
            .unwrap();

        // Slot is freed → a fresh enter for key 7 is a leader again.
        assert!(matches!(reg.enter(7), Enter::Leader(_)));
    }

    // Lost-wakeup regression: the leader completes before the follower starts waiting.
    #[tokio::test]
    async fn inflight_follower_wakeup_survives_drop_before_wait() {
        let reg = Arc::new(InflightRegistry::default());
        let leader = match reg.enter(42) {
            Enter::Leader(g) => g,
            _ => panic!("first enter must be leader"),
        };
        // Follower enters (mirrors the pre-wait lookup), no waiting yet.
        let follower = match reg.enter(42) {
            Enter::Follower(n) => n,
            _ => panic!("second same-key enter must be follower"),
        };
        // Leader finishes before the follower calls wait.
        drop(leader);
        // Sticky completion makes this resolve at once; a lost edge would hang to timeout.
        tokio::time::timeout(Duration::from_millis(500), follower.wait())
            .await
            .expect("a post-drop follower wait must observe completion");
    }

    #[tokio::test]
    async fn inflight_all_late_followers_observe_completion() {
        let reg = Arc::new(InflightRegistry::default());
        let leader = match reg.enter(43) {
            Enter::Leader(g) => g,
            _ => panic!("first enter must be leader"),
        };
        let first = match reg.enter(43) {
            Enter::Follower(n) => n,
            _ => panic!("same-key enter must be follower"),
        };
        let second = match reg.enter(43) {
            Enter::Follower(n) => n,
            _ => panic!("same-key enter must be follower"),
        };

        // Neither follower has created or polled a wait future when the leader
        // completes. Completion must remain observable to every follower, not
        // only the first one that consumes Notify's single stored permit.
        drop(leader);
        tokio::time::timeout(Duration::from_millis(100), first.wait())
            .await
            .expect("first late follower must observe completion");
        tokio::time::timeout(Duration::from_millis(100), second.wait())
            .await
            .expect("second late follower must also observe completion");
    }

    // N followers parked before the leader drops must all be released.
    #[tokio::test]
    async fn inflight_wakes_all_parked_followers_not_just_one() {
        let reg = Arc::new(InflightRegistry::default());
        let leader = match reg.enter(99) {
            Enter::Leader(g) => g,
            _ => panic!("first enter must be leader"),
        };
        let n = 5;
        let mut handles = Vec::new();
        for _ in 0..n {
            let notify = match reg.enter(99) {
                Enter::Follower(nf) => nf,
                _ => panic!("same-key enter must be follower"),
            };
            handles.push(tokio::spawn(async move { notify.wait().await }));
        }
        // Let every follower register before the drop.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(leader);
        // With notify_waiters() every parked follower wakes; with notify_one() only one would
        // and the rest would hang to this timeout.
        for h in handles {
            tokio::time::timeout(Duration::from_millis(500), h)
                .await
                .expect("every parked follower must wake (notify_waiters), not just one")
                .expect("follower task panicked");
        }
    }

    // Followers that do slow pre-wait work must still observe a leader that completes
    // during that work.
    #[tokio::test]
    async fn followers_waiting_after_slow_prework_observe_midwork_completion() {
        let reg = Arc::new(InflightRegistry::default());
        let leader = match reg.enter(123) {
            Enter::Leader(g) => g,
            _ => panic!("first enter must be leader"),
        };
        let n = 8;
        let mut handles = Vec::new();
        for _ in 0..n {
            let notify = match reg.enter(123) {
                Enter::Follower(nf) => nf,
                _ => panic!("same-key enter must be follower"),
            };
            handles.push(tokio::spawn(async move {
                // Do the slow synchronous pre-wait work (the .htaccess-loading
                // cache_lookup), during which the leader will drop...
                tokio::time::sleep(Duration::from_millis(20)).await;
                // ...and only now wait. Sticky completion makes this return at once.
                notify.wait().await;
            }));
        }
        // Drop the leader while every follower is still inside its pre-wait work window.
        tokio::time::sleep(Duration::from_millis(5)).await;
        drop(leader);
        for h in handles {
            tokio::time::timeout(Duration::from_millis(500), h)
                .await
                .expect("a follower must observe completion after its slow prework")
                .expect("follower task panicked");
        }
    }
}
