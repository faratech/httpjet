//! Server-wide byte budget for request bodies that must be fully buffered into
//! heap before a handler runs.
//!
//! Without a shared cap, aggregate buffered-body memory is attacker-controlled:
//! N slow connections each streaming up to `maxReqBodySize` commit `N x
//! maxReqBodySize` of heap regardless of worker count. Reservation happens
//! incrementally AS BYTES ARRIVE, so small bodies always admit and only
//! genuinely large concurrent uploads contend.
//!
//! ONE instance lives on the server state and is shared by every layer that
//! commits body bytes: the io_uring H1/H2/H3 transport buffering paths and
//! hj-lsapi's `collect_to_cap`. Layers reserve independently (a body already
//! reserved by its transport is reserved again by LSAPI), which double-counts
//! by design — the bound errs tight, never loose.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Default server-wide budget for buffered bodies: generous against real
/// chunked-upload traffic, hard against memory-exhaustion floods.
pub const DEFAULT_BODY_BUFFER_MEM: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub struct BodyBufferBudget {
    max_bytes: u64,
    in_flight: AtomicU64,
    rejected: AtomicU64,
    waiters: AtomicUsize,
    /// One waiter at a time holds the turn and watches `released`; the rest queue
    /// here in arrival order, so a release wakes one task instead of every waiter.
    turn: tokio::sync::Semaphore,
    released: tokio::sync::Notify,
}

impl BodyBufferBudget {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            in_flight: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            waiters: AtomicUsize::new(0),
            turn: tokio::sync::Semaphore::new(1),
            released: tokio::sync::Notify::new(),
        }
    }

    /// Reserve `n` more bytes if the budget allows; false when exhausted.
    pub fn try_acquire(&self, n: u64) -> bool {
        if self.reserve(n) {
            return true;
        }
        self.rejected.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Reserve `n` bytes, waiting for other reservations to release instead of
    /// refusing. Waiting is back-pressure, not a refusal, so it never counts
    /// toward [`Self::rejected`]; only an `n` that can never fit is refused.
    /// Waiters are served first-come first-served: a newcomer queues behind any
    /// earlier waiter even when its own `n` would fit (non-waiting
    /// [`Self::try_acquire`] callers are unaffected).
    /// Cancel-safe: dropping the future reserves nothing and passes its turn on.
    pub async fn acquire_wait(&self, n: u64) -> bool {
        if self.max_bytes != 0 && n > self.max_bytes {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if self.waiters.load(Ordering::SeqCst) == 0 && self.reserve(n) {
            return true;
        }
        let _waiter = Waiter::register(&self.waiters);
        // The semaphore is never closed; were it, waiting without the turn is
        // still correct, merely unordered.
        let _turn = self.turn.acquire().await;
        loop {
            // Created before the re-check, so a release that the re-check misses
            // still wakes it (`notify_waiters` reaches every existing `Notified`).
            let released = self.released.notified();
            if self.reserve(n) {
                return true;
            }
            released.await;
        }
    }

    // SeqCst on `in_flight` and `waiters` on both sides: a waiter that registers
    // and then re-checks either sees the release or is counted by its notify.
    fn reserve(&self, n: u64) -> bool {
        if self.max_bytes == 0 {
            return true; // 0 = accounting disabled
        }
        let mut cur = self.in_flight.load(Ordering::SeqCst);
        loop {
            if cur.saturating_add(n) > self.max_bytes {
                return false;
            }
            match self.in_flight.compare_exchange_weak(
                cur,
                cur + n,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }

    pub fn release(&self, n: u64) {
        if self.max_bytes == 0 || n == 0 {
            return;
        }
        let prev = self.in_flight.fetch_sub(n, Ordering::SeqCst);
        debug_assert!(prev >= n, "body-budget underflow");
        if self.waiters.load(Ordering::SeqCst) != 0 {
            self.released.notify_waiters();
        }
    }

    /// Bytes currently reserved by live buffered bodies.
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn capacity(&self) -> u64 {
        self.max_bytes
    }

    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

/// RAII lease on bytes reserved from a [`BodyBufferBudget`]. Held alongside the
/// collected buffer for the rest of the request so the reservation tracks the
/// buffer's actual lifetime; released exactly once on drop (including error paths).
#[derive(Debug)]
pub struct BodyBufferLease {
    budget: Arc<BodyBufferBudget>,
    held: u64,
}

impl BodyBufferLease {
    pub fn new(budget: Arc<BodyBufferBudget>) -> Self {
        Self { budget, held: 0 }
    }

    /// Reserve `n` more bytes on this lease; false (no change) when exhausted.
    pub fn reserve(&mut self, n: u64) -> bool {
        if !self.budget.try_acquire(n) {
            return false;
        }
        self.held += n;
        true
    }

    /// [`BodyBufferBudget::acquire_wait`] onto this lease; false (no change)
    /// only when `n` exceeds the whole budget.
    pub async fn reserve_wait(&mut self, n: u64) -> bool {
        if !self.budget.acquire_wait(n).await {
            return false;
        }
        self.held += n;
        true
    }

    /// Bytes this lease currently holds.
    pub fn held(&self) -> u64 {
        self.held
    }

    /// Give back `n` bytes reserved on this lease (a transient raw copy that
    /// was drained, so the ledger tracks only the copy that lives on). Clamped
    /// to what is held so a bookkeeping bug cannot underflow the server-wide
    /// counter.
    pub fn release(&mut self, n: u64) {
        let n = n.min(self.held);
        if n == 0 {
            return;
        }
        self.budget.release(n);
        self.held -= n;
    }

    /// Keep the reservation until the last alias of this allocation is dropped,
    /// including DATA frames moved out of the request into an asynchronous writer.
    pub fn into_bytes(self, data: Vec<u8>) -> bytes::Bytes {
        struct OwnedBody {
            data: Vec<u8>,
            _lease: BodyBufferLease,
        }
        impl AsRef<[u8]> for OwnedBody {
            fn as_ref(&self) -> &[u8] {
                &self.data
            }
        }
        debug_assert!(self.held >= data.len() as u64);
        bytes::Bytes::from_owner(OwnedBody { data, _lease: self })
    }
}

impl Drop for BodyBufferLease {
    fn drop(&mut self) {
        self.budget.release(self.held);
    }
}

struct Waiter<'a>(&'a AtomicUsize);

impl<'a> Waiter<'a> {
    fn register(waiters: &'a AtomicUsize) -> Self {
        waiters.fetch_add(1, Ordering::SeqCst);
        Self(waiters)
    }
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_release_roundtrip() {
        let b = Arc::new(BodyBufferBudget::new(100));
        let mut l = BodyBufferLease::new(b.clone());
        assert!(l.reserve(60));
        assert!(!l.reserve(60), "exhaustion must refuse without mutating");
        assert!(l.reserve(40));
        assert_eq!(b.in_flight(), 100);
        drop(l);
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn release_returns_reserved_bytes() {
        let b = Arc::new(BodyBufferBudget::new(100));
        let mut l = BodyBufferLease::new(b.clone());
        assert!(l.reserve(80));
        l.release(30);
        assert_eq!(b.in_flight(), 50);
        assert!(l.reserve(50));
        assert_eq!(b.in_flight(), 100);
        l.release(1_000);
        assert_eq!(b.in_flight(), 0, "release clamps to what is held");
        drop(l);
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn zero_disables_accounting() {
        let b = BodyBufferBudget::new(0);
        assert!(b.try_acquire(u64::MAX));
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn owned_bytes_keep_reservation_through_clones_and_slices() {
        let budget = Arc::new(BodyBufferBudget::new(12));
        let mut lease = BodyBufferLease::new(budget.clone());
        assert!(lease.reserve(12));
        let bytes = lease.into_bytes(vec![1; 8]);
        let alias = bytes.slice(2..4);
        drop(bytes);
        assert_eq!(budget.in_flight(), 12);
        assert!(!budget.try_acquire(1));
        assert_eq!(budget.rejected(), 1);
        assert_eq!(budget.capacity(), 12);
        drop(alias);
        assert_eq!(budget.in_flight(), 0);
    }

    #[tokio::test]
    async fn waiting_reserve_wakes_on_release_without_counting_rejections() {
        let budget = Arc::new(BodyBufferBudget::new(10));
        let mut hog = BodyBufferLease::new(budget.clone());
        assert!(hog.reserve(10));
        let waiter = tokio::spawn({
            let budget = budget.clone();
            async move {
                let mut lease = BodyBufferLease::new(budget);
                assert!(lease.reserve_wait(4).await);
                lease
            }
        });
        while budget.waiters.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        assert!(!waiter.is_finished());
        hog.release(6);
        let lease = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("a release must wake the waiter")
            .unwrap();
        assert_eq!(budget.in_flight(), 8);
        assert_eq!(budget.rejected(), 0, "a wait is not a refusal");
        assert_eq!(budget.waiters.load(Ordering::SeqCst), 0);
        drop((hog, lease));
        assert_eq!(budget.in_flight(), 0);
    }

    #[tokio::test]
    async fn cancelled_wait_reserves_nothing_and_deregisters() {
        let budget = Arc::new(BodyBufferBudget::new(4));
        let mut hog = BodyBufferLease::new(budget.clone());
        assert!(hog.reserve(4));
        let mut lease = BodyBufferLease::new(budget.clone());
        let waited =
            tokio::time::timeout(std::time::Duration::from_millis(20), lease.reserve_wait(1)).await;
        assert!(waited.is_err());
        assert_eq!(budget.waiters.load(Ordering::SeqCst), 0);
        drop(hog);
        drop(lease);
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(budget.rejected(), 0);
    }

    #[tokio::test]
    async fn oversized_wait_is_refused_at_once() {
        let budget = Arc::new(BodyBufferBudget::new(4));
        let mut lease = BodyBufferLease::new(budget.clone());
        assert!(!lease.reserve_wait(5).await);
        assert_eq!(budget.rejected(), 1);
        assert!(lease.reserve_wait(4).await);
        assert_eq!(budget.in_flight(), 4);
        let unlimited = Arc::new(BodyBufferBudget::new(0));
        assert!(BodyBufferLease::new(unlimited).reserve_wait(u64::MAX).await);
    }

    async fn settle() {
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }

    fn spawn_wait(
        budget: &Arc<BodyBufferBudget>,
        n: u64,
        order: &Arc<std::sync::Mutex<Vec<u64>>>,
        id: u64,
    ) -> tokio::task::JoinHandle<BodyBufferLease> {
        let budget = budget.clone();
        let order = order.clone();
        tokio::spawn(async move {
            let mut lease = BodyBufferLease::new(budget);
            assert!(lease.reserve_wait(n).await);
            order.lock().unwrap().push(id);
            lease
        })
    }

    async fn wait_for_waiters(budget: &BodyBufferBudget, n: usize) {
        while budget.waiters.load(Ordering::SeqCst) != n {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn waiters_are_served_in_arrival_order() {
        let budget = Arc::new(BodyBufferBudget::new(10));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut hog = BodyBufferLease::new(budget.clone());
        assert!(hog.reserve(10));
        let first = spawn_wait(&budget, 6, &order, 1);
        wait_for_waiters(&budget, 1).await;
        let second = spawn_wait(&budget, 2, &order, 2);
        wait_for_waiters(&budget, 2).await;

        hog.release(4);
        settle().await;
        assert!(
            order.lock().unwrap().is_empty(),
            "a later waiter that fits must not overtake an earlier one"
        );
        hog.release(2);
        let first = first.await.unwrap();
        assert_eq!(*order.lock().unwrap(), [1]);
        assert!(!second.is_finished());
        hog.release(2);
        let second = second.await.unwrap();
        assert_eq!(*order.lock().unwrap(), [1, 2]);
        assert_eq!(budget.in_flight(), 10);
        assert_eq!(budget.rejected(), 0);
        drop((hog, first, second));
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(budget.waiters.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_waiting_reserve_does_not_overtake_but_try_acquire_still_admits() {
        let budget = Arc::new(BodyBufferBudget::new(10));
        let mut hog = BodyBufferLease::new(budget.clone());
        assert!(hog.reserve(8));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let head = spawn_wait(&budget, 4, &order, 1);
        wait_for_waiters(&budget, 1).await;
        let mut newcomer = BodyBufferLease::new(budget.clone());
        let queued = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            newcomer.reserve_wait(1),
        )
        .await;
        assert!(queued.is_err(), "a newcomer waits behind the queued head");
        assert_eq!(budget.waiters.load(Ordering::SeqCst), 1);
        assert!(
            budget.try_acquire(2),
            "a refusing reservation is not queued"
        );
        budget.release(2);
        drop(hog);
        let head = head.await.unwrap();
        drop((head, newcomer));
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(budget.rejected(), 0);
    }

    struct CountPolls<F> {
        inner: std::pin::Pin<Box<F>>,
        polls: Arc<AtomicUsize>,
    }

    impl<F: std::future::Future> std::future::Future for CountPolls<F> {
        type Output = F::Output;
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<F::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            self.inner.as_mut().poll(cx)
        }
    }

    #[tokio::test]
    async fn a_release_wakes_one_waiter_not_the_herd() {
        const WAITERS: u64 = 16;
        let budget = Arc::new(BodyBufferBudget::new(64));
        let mut hog = BodyBufferLease::new(budget.clone());
        assert!(hog.reserve(64));
        let polls = Arc::new(AtomicUsize::new(0));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for id in 0..WAITERS {
            let budget = budget.clone();
            let order = order.clone();
            tasks.push(tokio::spawn(CountPolls {
                inner: Box::pin(async move {
                    let mut lease = BodyBufferLease::new(budget);
                    assert!(lease.reserve_wait(4).await);
                    order.lock().unwrap().push(id);
                    lease
                }),
                polls: polls.clone(),
            }));
        }
        wait_for_waiters(&budget, WAITERS as usize).await;
        settle().await;
        let parked = polls.load(Ordering::SeqCst);
        for _ in 0..3 {
            hog.release(1);
            settle().await;
        }
        assert!(
            polls.load(Ordering::SeqCst) - parked <= 3,
            "releases too small for the head must wake only the head, not all {WAITERS} waiters"
        );
        hog.release(61);
        let mut leases = Vec::new();
        for task in tasks {
            leases.push(task.await.unwrap());
        }
        assert_eq!(*order.lock().unwrap(), (0..WAITERS).collect::<Vec<_>>());
        assert_eq!(budget.in_flight(), 64);
        drop(leases);
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(budget.waiters.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_cancelled_head_passes_its_wakeup_to_the_next_waiter() {
        let budget = Arc::new(BodyBufferBudget::new(10));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut hog = BodyBufferLease::new(budget.clone());
        assert!(hog.reserve(10));
        let head = spawn_wait(&budget, 6, &order, 1);
        wait_for_waiters(&budget, 1).await;
        let next = spawn_wait(&budget, 4, &order, 2);
        wait_for_waiters(&budget, 2).await;
        // The release wakes the head; it is cancelled before it can run.
        hog.release(6);
        head.abort();
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), next)
            .await
            .expect("the cancelled head's wakeup must reach the next waiter")
            .unwrap();
        assert!(head.await.unwrap_err().is_cancelled());
        assert_eq!(*order.lock().unwrap(), [2]);
        assert_eq!(budget.in_flight(), 8);
        assert_eq!(budget.waiters.load(Ordering::SeqCst), 0);
        drop((hog, next));
        assert_eq!(budget.in_flight(), 0);
    }

    #[tokio::test]
    async fn a_cancelled_queued_waiter_does_not_block_those_behind_it() {
        let budget = Arc::new(BodyBufferBudget::new(10));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut hog = BodyBufferLease::new(budget.clone());
        assert!(hog.reserve(10));
        let head = spawn_wait(&budget, 6, &order, 1);
        wait_for_waiters(&budget, 1).await;
        let cancelled = spawn_wait(&budget, 6, &order, 2);
        wait_for_waiters(&budget, 2).await;
        let tail = spawn_wait(&budget, 4, &order, 3);
        wait_for_waiters(&budget, 3).await;
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        wait_for_waiters(&budget, 2).await;
        hog.release(10);
        let head = head.await.unwrap();
        let tail = tokio::time::timeout(std::time::Duration::from_secs(5), tail)
            .await
            .expect("the turn skips a cancelled waiter")
            .unwrap();
        assert_eq!(*order.lock().unwrap(), [1, 3]);
        assert_eq!(budget.in_flight(), 10);
        drop((hog, head, tail));
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(budget.rejected(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn contended_waiters_never_lose_a_wakeup() {
        const TASKS: u64 = 32;
        const ROUNDS: u64 = 200;
        let budget = Arc::new(BodyBufferBudget::new(16));
        let mut tasks = Vec::new();
        for id in 0..TASKS {
            let budget = budget.clone();
            tasks.push(tokio::spawn(async move {
                for round in 0..ROUNDS {
                    let n = 1 + (id + round) % 16;
                    let mut lease = BodyBufferLease::new(budget.clone());
                    assert!(lease.reserve_wait(n).await);
                    if round % 3 == 0 {
                        tokio::task::yield_now().await;
                    }
                    drop(lease);
                }
            }));
        }
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            for task in tasks {
                task.await.unwrap();
            }
        })
        .await
        .expect("every waiter must eventually be woken");
        assert_eq!(budget.in_flight(), 0);
        assert_eq!(budget.waiters.load(Ordering::SeqCst), 0);
        assert_eq!(budget.rejected(), 0);
    }

    #[test]
    fn disabled_budget_allows_owned_bytes() {
        let budget = Arc::new(BodyBufferBudget::new(0));
        let mut lease = BodyBufferLease::new(budget.clone());
        assert!(lease.reserve(8));
        let bytes = lease.into_bytes(vec![0; 8]);
        assert_eq!(bytes.len(), 8);
        assert_eq!(budget.in_flight(), 0);
        drop(bytes);
        assert_eq!(budget.rejected(), 0);
    }
}

// ---- (Tier 2) Per-connection bandwidth throttle ----
// Lives in hj-core so both hj-http (the ServeConfig knob) and hj-h2 (the h2
// connection egress path) can share ONE implementation.

/// Token-bucket bandwidth limiter for response egress. Constructed per
/// connection with the configured bytes-per-second rate; `acquire(n)` blocks
/// until `n` bytes of budget are available. Disabled when rate is 0.
pub struct BandwidthThrottle {
    rate_bps: u64,
    // Signed so a write may consume future tokens (debt). i128 covers the
    // complete u64 rate/request domain plus the 2x burst cap without casts.
    available: i128,
    last: std::time::Instant,
}

impl BandwidthThrottle {
    pub fn new(rate_bps: u64) -> Option<Self> {
        if rate_bps == 0 {
            return None;
        }
        Some(Self {
            rate_bps,
            available: i128::from(rate_bps),
            last: std::time::Instant::now(),
        })
    }

    /// The configured bytes-per-second rate (lets a caller detect a rate change and
    /// rebuild the bucket instead of silently re-using the wrong pace).
    pub fn rate_bps(&self) -> u64 {
        self.rate_bps
    }

    /// Replenish tokens based on elapsed time and consume `n` for this write.
    /// Returns the MICROSECONDS the caller should wait before writing (0 = go now).
    pub fn acquire(&mut self, n: u64) -> u64 {
        let now = std::time::Instant::now();
        let elapsed_us = now.duration_since(self.last).as_micros();
        self.last = now;
        self.acquire_after(n, elapsed_us)
    }

    /// Deterministic arithmetic core for [`Self::acquire`]. `elapsed_us` is
    /// u128 because `Duration::as_micros` is u128; every conversion below is
    /// saturating so all legal u64 rates and write sizes remain defined.
    fn acquire_after(&mut self, n: u64, elapsed_us: u128) -> u64 {
        let refill = elapsed_us.saturating_mul(u128::from(self.rate_bps)) / 1_000_000;
        let refill = i128::try_from(refill).unwrap_or(i128::MAX);
        let cap = i128::from(self.rate_bps) * 2; // burst cap = 2× rate
        self.available = self
            .available
            .saturating_add(refill)
            .min(cap)
            .saturating_sub(i128::from(n));
        if self.available < 0 {
            // Over budget: caller should wait this many µs.
            let wait_us =
                self.available.unsigned_abs().saturating_mul(1_000_000) / u128::from(self.rate_bps);
            wait_us.min(u128::from(u64::MAX)) as u64
        } else {
            0
        }
    }
}

#[cfg(test)]
mod bandwidth_tests {
    use super::*;

    #[test]
    fn bandwidth_throttle_allows_burst_then_paces() {
        let mut t = BandwidthThrottle::new(1000).unwrap(); // 1 KB/s
        // First acquire is free (full burst budget).
        assert_eq!(t.acquire(500), 0);
        // Second acquire immediately after: budget already consumed, may need to wait.
        let _wait = t.acquire(500);
        // After a real sleep the budget refills and allows more.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(t.acquire(500), 0, "budget should have refilled after 1.1s");
    }

    #[test]
    fn bandwidth_throttle_disabled_at_zero() {
        assert!(BandwidthThrottle::new(0).is_none());
    }

    #[test]
    fn bandwidth_throttle_preserves_token_and_debt_math() {
        let mut t = BandwidthThrottle::new(1_000).expect("nonzero rate");
        assert_eq!(t.acquire_after(500, 0), 0);
        assert_eq!(t.available, 500);
        assert_eq!(t.acquire_after(1_000, 0), 500_000);
        assert_eq!(t.available, -500);
        assert_eq!(t.acquire_after(0, 500_000), 0);
        assert_eq!(t.available, 0);
    }

    #[test]
    fn bandwidth_throttle_accepts_maximum_u64_rate() {
        let mut t = BandwidthThrottle::new(u64::MAX).expect("nonzero rate");
        assert_eq!(t.rate_bps(), u64::MAX);
        assert_eq!(t.available, i128::from(u64::MAX));
        assert_eq!(
            t.acquire_after(u64::MAX, u128::MAX),
            0,
            "huge elapsed refill saturates at the 2x burst cap"
        );
        assert_eq!(t.available, i128::from(u64::MAX));
    }

    #[test]
    fn bandwidth_throttle_clamps_unrepresentable_wait() {
        let mut t = BandwidthThrottle::new(1).expect("nonzero rate");
        assert_eq!(
            t.acquire_after(u64::MAX, 0),
            u64::MAX,
            "a legal request can create more wait microseconds than u64 holds"
        );

        // Large elapsed arithmetic also stays defined and restores only the
        // configured 2x burst, rather than wrapping into excess credit.
        assert_eq!(t.acquire_after(2, u128::MAX), 0);
        assert_eq!(t.available, 0);
    }
}
