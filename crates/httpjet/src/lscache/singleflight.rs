//! Single-flight registry for the origin page cache: collapse concurrent cache
//! MISSES of the same key into one backend render (the leader), so a hot page's
//! TTL expiry doesn't stampede the (PHP) backend with N identical renders.
//!
//! Plus the [`RefreshRegistry`]: a SIBLING primitive for stale-while-revalidate.
//! Where single-flight makes followers BLOCK on a leader (a miss-collapse), a
//! background refresh must NOT block anyone — it fires at most once per key, off
//! the client path, bounded by a global concurrency cap so a wave of stale hits
//! can't spawn unbounded PHP renders.

use std::sync::Arc;

/// Single-flight registry: collapses concurrent cache MISSES of the same key into a single
/// backend render. The first misser becomes the leader (renders + stores); concurrent
/// missers of the same key are followers that wait for the leader, then serve from the
/// freshly-filled cache instead of stampeding the (PHP) backend at a hot page's TTL expiry.
/// Keyed by the page-cache key hash, so different pages never serialize and a page never
/// blocks on itself (a render does not sub-request its own URL).
#[derive(Default)]
pub struct InflightRegistry {
    map: dashmap::DashMap<u64, Arc<tokio::sync::Notify>>,
}

/// What [`InflightRegistry::enter`] decided for a given key.
pub enum Enter {
    /// Sole renderer: hold this guard until the render+store finishes; dropping it wakes
    /// followers and removes the registry entry.
    Leader(InflightLeader),
    /// Another request is already rendering this key — await it, then re-check the cache.
    Follower(Arc<tokio::sync::Notify>),
}

/// RAII leader token. On drop (at any dispatch return, after `cache_store` on the cacheable
/// paths) it removes the registry entry and wakes followers so they re-read the cache.
pub struct InflightLeader {
    registry: Arc<InflightRegistry>,
    key_hash: u64,
    notify: Arc<tokio::sync::Notify>,
}

impl InflightRegistry {
    /// Become the leader for `key_hash`, or get the leader's notify to wait on as a follower.
    pub fn enter(self: &Arc<Self>, key_hash: u64) -> Enter {
        use dashmap::mapref::entry::Entry;
        match self.map.entry(key_hash) {
            Entry::Occupied(e) => Enter::Follower(e.get().clone()),
            Entry::Vacant(e) => {
                let notify = Arc::new(tokio::sync::Notify::new());
                e.insert(notify.clone());
                Enter::Leader(InflightLeader {
                    registry: self.clone(),
                    key_hash,
                    notify,
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
        // Wake ALL followers, covering both races. The common case is N concurrent missers
        // parked on this shared Notify at a hot key's TTL expiry:
        // - notify_waiters() releases EVERY currently-parked follower at once. notify_one()
        //   alone would wake only ONE and leave the other N-1 to block the full
        //   SINGLEFLIGHT_WAIT (10s) and then each render the backend — the inverse of the
        //   stampede protection (the promised "wake the next in turn" chain was never built).
        // - notify_one() additionally stores ONE permit so a follower that finishes its
        //   synchronous pre-wait cache_lookup AFTER this drop but before its first notified()
        //   poll still wakes (notify_waiters stores no permit). Woken followers re-check the
        //   cache (hit) or one becomes the next leader.
        self.notify.notify_waiters();
        self.notify.notify_one();
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
        let notify = match reg.enter(7) {
            Enter::Follower(n) => n,
            _ => panic!("second same-key enter must be follower"),
        };
        // A different key → its own leader (different pages never serialize).
        assert!(matches!(reg.enter(8), Enter::Leader(_)));

        // A waiter on the follower's notify is woken when the leader drops.
        let woken = notify.clone();
        let waiter = tokio::spawn(async move { woken.notified().await });
        tokio::task::yield_now().await; // let the waiter register
        drop(leader); // removes the slot + notify_one()
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("follower must be woken when the leader drops")
            .unwrap();

        // Slot is freed → a fresh enter for key 7 is a leader again.
        assert!(matches!(reg.enter(7), Enter::Leader(_)));
    }

    // (#4) Lost-wakeup regression. Reproduces the EXACT production ordering: a follower
    // obtains the leader's notify (a synchronous pre-wait cache_lookup runs here in prod
    // with NO yield), the leader then completes + drops, and ONLY AFTER that does the
    // follower first poll `notified()`. notify_waiters() only wakes futures already parked,
    // so it would lose this edge and the follower would block the full SINGLEFLIGHT_WAIT
    // (10s). notify_one() stores a permit, so the first poll after the drop consumes it and
    // returns immediately — well under SINGLEFLIGHT_WAIT. (The existing
    // inflight_leader_follower_and_reentry test parks BEFORE the drop with a yield_now; this
    // one deliberately reverses that order, which is the bug.)
    #[tokio::test]
    async fn inflight_follower_wakeup_survives_drop_before_wait() {
        let reg = Arc::new(InflightRegistry::default());
        let leader = match reg.enter(42) {
            Enter::Leader(g) => g,
            _ => panic!("first enter must be leader"),
        };
        // Follower grabs the notify (mirrors the pre-wait lookup), no parking yet.
        let notify = match reg.enter(42) {
            Enter::Follower(n) => n,
            _ => panic!("second same-key enter must be follower"),
        };
        // Leader finishes + drops BEFORE the follower ever polls notified() — the race.
        drop(leader);
        // The stored permit makes this resolve at once; a lost edge would hang to timeout.
        tokio::time::timeout(Duration::from_millis(500), notify.notified())
            .await
            .expect("notify_one must store a permit so a post-drop notified() does not stall");
    }

    // (#4, corrected) N followers parked on the shared Notify BEFORE the leader drops must
    // ALL be released. notify_one() alone woke only ONE and left the other N-1 to block the
    // full SINGLEFLIGHT_WAIT (10s) then stampede the backend — the inverse of the protection.
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
            handles.push(tokio::spawn(async move { notify.notified().await }));
        }
        // Let every follower poll notified() and park (register as a waiter) before the drop.
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

    // (#5) The production heavy-vhost concurrency collapse. The pipeline follower does
    // SLOW pre-wait work (a cache_lookup that loads the whole `.htaccess` chain) before
    // it parks. If it registers on the notify only AFTER that work (`notified()` last),
    // a fast leader that renders an UNCACHEABLE response (stores nothing) and drops DURING
    // the work wakes nobody via notify_waiters() (no one parked yet) and leaves a single
    // notify_one() permit — so out of N racing followers exactly one proceeds and the rest
    // block the full SINGLEFLIGHT_WAIT (10s), serializing every concurrent miss. The fix
    // is for the follower to `enable()` the Notified future BEFORE the slow work, becoming
    // a registered waiter so notify_waiters() releases it regardless of work duration. This
    // test reproduces that exact ordering (register → slow work → leader drops mid-work →
    // park) and asserts ALL followers wake promptly.
    #[tokio::test]
    async fn followers_enabling_before_slow_prework_all_wake_when_leader_drops_midwork() {
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
                // The correct pipeline pattern: register as a waiter FIRST...
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                // ...THEN do the slow synchronous pre-wait work (the .htaccess-loading
                // cache_lookup), during which the leader will drop...
                tokio::time::sleep(Duration::from_millis(20)).await;
                // ...and only now actually park. enable() means the mid-work
                // notify_waiters() already marked us notified, so this returns at once.
                notified.await;
            }));
        }
        // Drop the leader while every follower is still inside its pre-wait work window
        // (all have enable()d, none has reached the final await). A buggy register-last
        // follower would lose this wakeup; an enable()-first follower must not.
        tokio::time::sleep(Duration::from_millis(5)).await;
        drop(leader);
        for h in handles {
            tokio::time::timeout(Duration::from_millis(500), h)
                .await
                .expect("a follower that enabled before its slow prework must wake on the leader drop, not block to SINGLEFLIGHT_WAIT")
                .expect("follower task panicked");
        }
    }
}
