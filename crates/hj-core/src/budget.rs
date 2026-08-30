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
