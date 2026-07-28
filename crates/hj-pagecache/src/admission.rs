//! W-TinyLFU **store-admission** filter for the origin page cache.
//!
//! The store runs a byte-weighted LRU for EVICTION (which entry to drop when a shard is full);
//! what it does NOT decide is whether a response is worth storing in the first place.
//! Behind Cloudflare the origin cache is an L2 — it mostly sees CF misses plus a long tail of
//! unique URLs, so storing (and precompressing) every cacheable response churns the
//! genuinely-recurring pages out and wastes RAM + CPU on one-hit-wonders.
//!
//! This is the missing admission half: a small, FIXED-memory count-min sketch of per-key
//! request frequency, aged periodically so a once-hot key fades, consulted before `store()`
//! so only keys that show reuse are admitted. It estimates frequency only — the caller picks
//! the (size-weighted) admission threshold.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Count-min depth (probes per key). 4 is the classic TinyLFU choice.
const DEPTH: u64 = 4;
/// Odd 64-bit mixing constant for the second (stride) hash.
const MIX: u64 = 0x9E37_79B9_7F4A_7C15;

/// Counters halved per [`AdmissionFilter::age_step`] claim. Bounds the aging work any
/// single request can be charged to a few µs (a full pass at the 1 Mi-counter cap is
/// 256 steps), instead of one unlucky request sweeping the whole sketch inline.
const AGE_CHUNK: u64 = 4096;

/// A frequency sketch over 64-bit page-cache key hashes.
pub struct AdmissionFilter {
    counters: Box<[AtomicU8]>,
    mask: u64,   // counters.len() - 1 (len is a power of two)
    sample: u64, // age (halve every counter) after this many record() ops
    ops: AtomicU64,
    /// Counters still to halve in the in-flight aging pass (0 = no pass active).
    /// Claimed in [`AGE_CHUNK`] slices by subsequent `record()` calls.
    age_remaining: AtomicU64,
}

impl AdmissionFilter {
    /// Size a filter for a cache of `max_mem_bytes`: ~4 counters per estimated entry (assuming
    /// a ~16 KiB average entry), power-of-two width bounded to [4 Ki, 1 Mi] counters
    /// (4 KiB–1 MiB of fixed overhead). Aging halves the sketch every ~10× estimated-entries
    /// accesses so stale frequencies decay.
    pub fn new(max_mem_bytes: u64) -> Self {
        let est_entries = (max_mem_bytes / 16_384).max(1024);
        let width = (est_entries.saturating_mul(4))
            .clamp(4096, 1 << 20)
            .next_power_of_two() as usize;
        let counters = (0..width)
            .map(|_| AtomicU8::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        AdmissionFilter {
            counters,
            mask: width as u64 - 1,
            sample: est_entries.saturating_mul(10).max(10_000),
            ops: AtomicU64::new(0),
            age_remaining: AtomicU64::new(0),
        }
    }

    #[inline]
    fn probe(&self, key: u64, i: u64) -> usize {
        // Double-hashing: position_i = key + i*stride, stride odd & key-derived so distinct
        // keys spread differently across the row.
        let stride = (key ^ MIX).rotate_left(32).wrapping_mul(MIX) | 1;
        (key.wrapping_add(i.wrapping_mul(stride)) & self.mask) as usize
    }

    /// Record one access of `key` (call on every cacheable lookup). Saturating per counter;
    /// halves the whole sketch every `sample` ops so once-hot-now-cold keys decay.
    pub fn record(&self, key: u64) {
        for i in 0..DEPTH {
            let c = &self.counters[self.probe(key, i)];
            let mut cur = c.load(Ordering::Relaxed);
            while cur < u8::MAX {
                match c.compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(v) => cur = v,
                }
            }
        }
        // Approximate aging: the op that crosses `sample` wins a CAS to reset the counter and
        // ARMS an incremental halving pass; this and subsequent record() calls each claim one
        // AGE_CHUNK slice until the pass drains. Concurrent records during the halve are fine
        // (a sketch is an estimate); no lock, and no single request sweeps the whole sketch.
        let n = self.ops.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.sample
            && self
                .ops
                .compare_exchange(n, 0, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            // No-op if a previous pass is still draining: the sketch decays a touch later,
            // which the estimate tolerates; overlapping passes would double-halve instead.
            let _ = self.age_remaining.compare_exchange(
                0,
                self.counters.len() as u64,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        self.age_step();
    }

    /// Claim and halve one [`AGE_CHUNK`] slice of the in-flight aging pass, if any.
    /// Concurrent callers claim disjoint slices (the `age_remaining` CAS hands out
    /// ranges back-to-front), so the pass parallelizes safely.
    fn age_step(&self) {
        let mut rem = self.age_remaining.load(Ordering::Relaxed);
        loop {
            if rem == 0 {
                return;
            }
            let claim = rem.min(AGE_CHUNK);
            match self.age_remaining.compare_exchange_weak(
                rem,
                rem - claim,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let start = (self.counters.len() as u64 - rem) as usize;
                    for c in &self.counters[start..start + claim as usize] {
                        c.store(c.load(Ordering::Relaxed) >> 1, Ordering::Relaxed);
                    }
                    return;
                }
                Err(v) => rem = v,
            }
        }
    }

    /// Estimated access frequency of `key` — the min over the DEPTH probes (count-min).
    pub fn estimate(&self, key: u64) -> u8 {
        let mut m = u8::MAX;
        for i in 0..DEPTH {
            m = m.min(self.counters[self.probe(key, i)].load(Ordering::Relaxed));
            if m == 0 {
                break;
            }
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unseen_is_zero_then_increments() {
        let f = AdmissionFilter::new(128 * 1024 * 1024);
        assert_eq!(f.estimate(0xABCD_1234), 0, "unseen key estimates 0");
        f.record(0xABCD_1234);
        assert_eq!(f.estimate(0xABCD_1234), 1);
        f.record(0xABCD_1234);
        assert_eq!(
            f.estimate(0xABCD_1234),
            2,
            "a 2nd sighting is what crosses the default admit bar"
        );
    }

    #[test]
    fn distinct_keys_are_independent() {
        let f = AdmissionFilter::new(128 * 1024 * 1024);
        for _ in 0..5 {
            f.record(111);
        }
        assert!(f.estimate(111) >= 5);
        // A never-recorded key reads ~0 in a wide sketch (collisions improbable at this width).
        assert_eq!(f.estimate(987_654_321), 0);
    }

    #[test]
    fn saturates_at_u8_max() {
        let f = AdmissionFilter::new(128 * 1024 * 1024);
        for _ in 0..300 {
            f.record(42);
        }
        // Saturating increment caps a counter at u8::MAX; aging may pull it below, but it must
        // never wrap to a small value.
        assert!(f.estimate(42) >= 100, "hot key stays hot, no wrap");
    }

    #[test]
    fn aging_halves_counts() {
        let mut f = AdmissionFilter::new(128 * 1024 * 1024);
        f.sample = 8; // force an early aging pass
        for _ in 0..4 {
            f.record(7);
        }
        assert_eq!(f.estimate(7), 4);
        // 4 more ops on other keys -> the 8th record() crosses `sample` and arms the
        // (now incremental) halving pass; drain it and every counter must be halved.
        for k in 100..104u64 {
            f.record(k);
        }
        while f.age_remaining.load(Ordering::Relaxed) > 0 {
            f.age_step();
        }
        assert_eq!(f.estimate(7), 2, "aged: 4 >> 1 == 2");
    }

    #[test]
    fn aging_is_incremental_per_record() {
        let mut f = AdmissionFilter::new(128 * 1024 * 1024);
        f.sample = 1; // every record arms/advances an aging pass
        f.record(7);
        let width = f.counters.len() as u64;
        let rem = f.age_remaining.load(Ordering::Relaxed);
        // The arming record() also claimed the first chunk — but no more: the rest
        // of the pass is paid by later records, never one inline full sweep.
        assert_eq!(
            rem,
            width - AGE_CHUNK.min(width),
            "exactly one chunk claimed"
        );
    }
}
