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
use std::sync::atomic::{AtomicU64, Ordering};

/// Default server-wide budget for buffered bodies: generous against real
/// chunked-upload traffic, hard against memory-exhaustion floods.
pub const DEFAULT_BODY_BUFFER_MEM: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub struct BodyBufferBudget {
    max_bytes: u64,
    in_flight: AtomicU64,
}

impl BodyBufferBudget {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            in_flight: AtomicU64::new(0),
        }
    }

    /// Reserve `n` more bytes if the budget allows; false when exhausted.
    pub fn try_acquire(&self, n: u64) -> bool {
        if self.max_bytes == 0 {
            return true; // 0 = accounting disabled
        }
        let mut cur = self.in_flight.load(Ordering::Relaxed);
        loop {
            if cur.saturating_add(n) > self.max_bytes {
                return false;
            }
            match self.in_flight.compare_exchange_weak(
                cur,
                cur + n,
                Ordering::AcqRel,
                Ordering::Relaxed,
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
        let prev = self.in_flight.fetch_sub(n, Ordering::AcqRel);
        debug_assert!(prev >= n, "body-budget underflow");
    }

    /// Bytes currently reserved by live buffered bodies.
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
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
}

impl Drop for BodyBufferLease {
    fn drop(&mut self) {
        self.budget.release(self.held);
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
}

// ---- (Tier 2) Per-connection bandwidth throttle ----
// Lives in hj-core so both hj-http (the ServeConfig knob) and hj-h2 (the h2
// connection egress path) can share ONE implementation.

/// Token-bucket bandwidth limiter for response egress. Constructed per
/// connection with the configured bytes-per-second rate; `acquire(n)` blocks
/// until `n` bytes of budget are available. Disabled when rate is 0.
pub struct BandwidthThrottle {
    rate_bps: u64,
    available: std::sync::atomic::AtomicI64,
    last: std::time::Instant,
}

impl BandwidthThrottle {
    pub fn new(rate_bps: u64) -> Option<Self> {
        if rate_bps == 0 {
            return None;
        }
        Some(Self {
            rate_bps,
            available: std::sync::atomic::AtomicI64::new(rate_bps as i64),
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
        let elapsed_us = now.duration_since(self.last).as_micros() as u64;
        self.last = now;
        let refill = elapsed_us * self.rate_bps / 1_000_000;
        let mut avail = self.available.load(std::sync::atomic::Ordering::Relaxed) + refill as i64;
        let cap = self.rate_bps as i64 * 2; // burst cap = 2× rate
        avail = avail.min(cap);
        avail -= n as i64;
        self.available
            .store(avail, std::sync::atomic::Ordering::Relaxed);
        if avail < 0 {
            // Over budget: caller should wait this many µs.
            let wait_us = (-avail) * 1_000_000 / self.rate_bps as i64;
            wait_us as u64
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
}
