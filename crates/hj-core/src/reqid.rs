//! Per-request correlation id.
//!
//! A single [`ReqId`] is minted once per request at the transport boundary and
//! threaded through [`crate::ReqCtx`] into every log sink (access, error,
//! php-slow) so one request is joinable across all of them. Minting is a single
//! relaxed atomic increment finalized through a per-process seed — no syscall,
//! no lock, no RNG on the hot path (mirrors the lock-free per-thread counter
//! idiom the metrics shards use).

use std::cell::Cell;
use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Per-request correlation id. `Copy` so cloning a `ReqCtx` (e.g. a background
/// SWR-refresh subrequest) inherits the parent's id for free, and so adding it
/// to `ReqCtx` does not perturb the derived `Clone`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReqId(u64);

static COUNTER: AtomicU64 = AtomicU64::new(0);
static SEED: OnceLock<u64> = OnceLock::new();

const BATCH: u64 = 1024;

thread_local! {
    /// `(next_raw, end_raw, cached_seed)` claimed by this thread.
    static LOCAL_BATCH: Cell<(u64, u64, u64)> = const { Cell::new((0, 0, 0)) };
}

/// Per-process seed, minted once. Mixing it into every id keeps ids from
/// repeating across a restart and from being trivially enumerable, while
/// minting stays a single relaxed increment.
fn seed() -> u64 {
    *SEED.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        splitmix64(nanos ^ ((std::process::id() as u64) << 32) ^ 0x9E37_79B9_7F4A_7C15)
    })
}

/// Mint a fresh request id: claims [`BATCH`] sequential integers per thread from
/// the global counter and finalizes each through [`splitmix64`], eliminating
/// cross-core `LOCK XADD` cache-line contention on the global counter.
#[inline]
pub fn next() -> ReqId {
    LOCAL_BATCH.with(|cell| {
        let (cur, end, s) = cell.get();
        if cur < end {
            cell.set((cur + 1, end, s));
            return ReqId(splitmix64(s.wrapping_add(cur)));
        }
        let s = seed();
        let base = COUNTER.fetch_add(BATCH, Relaxed);
        cell.set((base + 1, base + BATCH, s));
        ReqId(splitmix64(s.wrapping_add(base)))
    })
}

/// Batch of pre-claimed sequential request IDs minted in one TLS access.
pub struct ReqIdBatch {
    cur: u64,
    seed: u64,
}

impl ReqIdBatch {
    /// Finalize and return the next 64-bit request id in this batch.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let cur = self.cur;
        self.cur = cur.wrapping_add(1);
        splitmix64(self.seed.wrapping_add(cur))
    }
}

/// Claim `count` sequential request IDs in a single TLS access (falling back to
/// one relaxed atomic `fetch_add` on the global counter when the thread-local
/// batch does not have `count` IDs remaining).
#[inline]
pub fn next_batch(count: u64) -> ReqIdBatch {
    if count == 0 {
        return ReqIdBatch { cur: 0, seed: 0 };
    }
    LOCAL_BATCH.with(|cell| {
        let (cur, end, s) = cell.get();
        if end.saturating_sub(cur) >= count {
            cell.set((cur + count, end, s));
            return ReqIdBatch { cur, seed: s };
        }
        let s = seed();
        let claim = BATCH.max(count);
        let base = COUNTER.fetch_add(claim, Relaxed);
        cell.set((base + count, base + claim, s));
        ReqIdBatch { cur: base, seed: s }
    })
}

/// SplitMix64 finalizer — turns the sequential counter into a well-distributed
/// 64-bit value so consecutive ids share no visible prefix.
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

impl ReqId {
    /// The raw 64-bit value (for hashing / numeric joins).
    #[inline]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// The `Default` is the all-zero sentinel (`0000000000000000`) — only for test
/// helpers and contexts that predate a real mint; production always mints via
/// [`next`] at the transport boundary.
impl Default for ReqId {
    fn default() -> Self {
        ReqId(0)
    }
}

impl fmt::Display for ReqId {
    /// Lower-hex, zero-padded to 16 chars, written straight through the
    /// formatter — no allocation. Callers that need an owned value use
    /// `.to_string()` (one small alloc, off the per-request fast path).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn next_batch_produces_unique_ids_across_refill_boundaries() {
        let mut seen = HashSet::new();
        // Mix single next() and small/large next_batch() calls across BATCH (1024).
        for _ in 0..16 {
            assert!(seen.insert(next().as_u64()));
        }
        let mut small = next_batch(64);
        for _ in 0..64 {
            assert!(seen.insert(small.next_u64()));
        }
        let mut large = next_batch(BATCH + 17);
        for _ in 0..(BATCH + 17) {
            assert!(seen.insert(large.next_u64()));
        }
        assert!(seen.insert(next().as_u64()));
    }
}
