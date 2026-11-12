//! W-TinyLFU **store-admission** filter for the origin page cache.
//!
//! The store runs a byte-weighted LRU for EVICTION (which entry to drop when a shard is full);
//! what it does NOT decide is whether a response is worth storing in the first place.
//! Behind Cloudflare the origin cache is an L2 — it mostly sees CF misses plus a long tail of
//! unique URLs, so storing (and precompressing) every cacheable response churns the
//! genuinely-recurring pages out and wastes RAM + CPU on one-hit-wonders.
//!
//! This is the missing admission half: a FIXED-memory count-min sketch of per-key
//! request frequency, aged periodically so a once-hot key fades, consulted before `store()`
//! so only keys that show reuse are admitted. It estimates frequency only — the caller picks
//! the (size-weighted) admission threshold.
//!
//! The caller compares the estimate with an ABSOLUTE threshold (there is no victim to
//! compare against), so collision noise must stay below one count: a never-requested key
//! has to read 0, or its first request is taken for its second and "admit on the second
//! sighting" turns into "admit everything". The table is therefore sized from the number
//! of records between two agings, not from the cache's byte budget (see [`AdmissionFilter::new`]).

use std::cell::Cell;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Counters probed per key. 4 is the classic TinyLFU choice.
const DEPTH: usize = 4;

/// Counters per block. A key's [`DEPTH`] counters share one block, and a block is one
/// cache line, so a record or an estimate costs one cache miss however large the table is.
const BLOCK: usize = 64;
/// Counters in each of the [`DEPTH`] quarters of a block.
const LANE: usize = BLOCK / DEPTH;

/// Counters per record of one aging period. At 16 the share of never-recorded keys that
/// already read 1 or more stays under 1% in steady state (distinct keys recorded once
/// each, the worst case); at 8 it is about 5%, at 4 about 30%.
const COUNTERS_PER_PERIOD_RECORD: u64 = 16;

/// Table size bounds, in counters (= bytes): 64 KiB to 64 MiB.
const MIN_COUNTERS: u64 = 1 << 16;
const MAX_COUNTERS: u64 = 1 << 26;

/// Smallest slice of blocks halved per [`AdmissionFilter::age_step`] claim (4096 counters).
/// Bounds the aging work any single request can be charged to a few µs instead of one
/// unlucky request sweeping the whole sketch inline.
const MIN_AGE_CHUNK_BLOCKS: u64 = 64;

/// Per-thread record() calls accumulated before one flush to the shared `ops` counter.
/// record() runs on EVERY cacheable lookup on every worker; without batching, the `ops`
/// RMW plus `age_remaining`'s probe line are the two hottest cross-core cache lines in
/// the process. Batching shifts aging-cadence accuracy by at most one batch per thread,
/// which the sketch's documented approximation tolerance covers.
const OPS_FLUSH_EVERY: u32 = 128;

/// Blocks read by [`AdmissionFilter::occupancy`].
const OCCUPANCY_SAMPLE_BLOCKS: usize = 1024;

thread_local! {
    /// Per-thread count of record() calls not yet flushed to the shared op counter.
    /// Cell — never leaves the thread, zero synchronization on the common path.
    static OPS_BATCH: Cell<u32> = const { Cell::new(0) };
}

/// One cache line, so hot atomics never share a line with a neighbor.
#[repr(align(64))]
struct Padded(AtomicU64);

/// One cache line of counters.
#[repr(align(64))]
struct Block([AtomicU8; BLOCK]);

impl Block {
    fn new() -> Self {
        Block([const { AtomicU8::new(0) }; BLOCK])
    }
}

/// A frequency sketch over 64-bit page-cache key hashes.
pub struct AdmissionFilter {
    blocks: Box<[Block]>,
    /// `64 - log2(blocks.len())`: the block index is the top bits of the mixed key.
    block_shift: u32,
    sample: u64, // age (halve every counter) after this many record() ops
    /// Blocks halved per flushing `record()` while an aging pass is draining; sized so a
    /// pass finishes within a quarter of the period.
    age_chunk: u64,
    ops: Padded,
    /// Blocks still to halve in the in-flight aging pass (0 = no pass active).
    /// Claimed in `age_chunk` slices by flushing `record()` calls.
    age_remaining: Padded,
    /// Aging passes started since this filter was created.
    agings: AtomicU64,
}

impl AdmissionFilter {
    /// Size a filter for a cache of `max_mem_bytes`.
    ///
    /// The aging period is ~10 accesses per estimated entry (assuming a ~16 KiB average
    /// entry): every counter is halved after that many records, so stale frequencies
    /// decay. The table holds [`COUNTERS_PER_PERIOD_RECORD`] counters per record of one
    /// period, rounded up to a power of two within 64 KiB..64 MiB (128 MiB of cache:
    /// 2 MiB; 3 GiB: 32 MiB). A cache too large for the cap gets a shorter period instead
    /// of a noisier table.
    pub fn new(max_mem_bytes: u64) -> Self {
        let est_entries = (max_mem_bytes / 16_384).max(1024);
        let period = est_entries.saturating_mul(10).max(10_000);
        let counters = period
            .saturating_mul(COUNTERS_PER_PERIOD_RECORD)
            .clamp(MIN_COUNTERS, MAX_COUNTERS)
            .next_power_of_two();
        let sample = period.min(counters / COUNTERS_PER_PERIOD_RECORD);
        let blocks = (counters as usize / BLOCK).max(1);
        let age_chunk = (blocks as u64)
            .saturating_mul(u64::from(OPS_FLUSH_EVERY) * 4)
            .div_ceil(sample)
            .max(MIN_AGE_CHUNK_BLOCKS);
        AdmissionFilter {
            blocks: (0..blocks).map(|_| Block::new()).collect(),
            block_shift: u64::BITS - blocks.trailing_zeros(),
            sample,
            age_chunk,
            ops: Padded(AtomicU64::new(0)),
            age_remaining: Padded(AtomicU64::new(0)),
            agings: AtomicU64::new(0),
        }
    }

    /// The block of `key` and its [`DEPTH`] distinct counters in it.
    #[inline]
    fn slots(&self, key: u64) -> (&Block, [usize; DEPTH]) {
        // The key is an FNV-1a hash, whose high bits mix poorly. Fold them down and
        // multiply: the block index is the top bits of the product, ready first so the
        // one cache line can be fetched while the slots are derived from a second fold.
        let h = (key ^ (key >> 32)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let block = &self.blocks[(h >> self.block_shift) as usize];
        let low = h ^ (h >> 29);
        // One counter in each quarter of the block. They are distinct by position, and
        // a block has 16^4 slot sets: a key that was never recorded rarely finds all
        // four of its counters raised by one other key. (A start and a step gave 1,024
        // sets and close to twice the false positives.)
        (
            block,
            std::array::from_fn(|i| i * LANE + ((low >> (20 + 4 * i)) as usize & (LANE - 1))),
        )
    }

    /// Record one access of `key` (call on every cacheable lookup). Saturating per counter;
    /// halves the whole sketch every `sample` ops so once-hot-now-cold keys decay.
    pub fn record(&self, key: u64) {
        let (block, slots) = self.slots(key);
        for slot in slots {
            let c = &block.0[slot];
            let mut cur = c.load(Ordering::Relaxed);
            while cur < u8::MAX {
                match c.compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(v) => cur = v,
                }
            }
        }
        // Approximate aging, batched per thread: only every OPS_FLUSH_EVERY-th record()
        // touches the shared `ops`/`age_remaining` lines (the counter CAS loops above stay
        // exact). The op that crosses `sample` wins a CAS to reset the counter and ARMS an
        // incremental halving pass; flushing callers each claim one `age_chunk` slice until
        // the pass drains. Concurrent records during the halve are fine (a sketch is an
        // estimate); no lock, and no single request sweeps the whole sketch.
        OPS_BATCH.with(|b| {
            let n = b.get() + 1;
            if n < OPS_FLUSH_EVERY {
                b.set(n);
                return;
            }
            b.set(0);
            self.flush_ops();
        });
    }

    /// Account OPS_FLUSH_EVERY batched records against the shared op counter and run the
    /// aging trigger/claim step once for the whole batch.
    fn flush_ops(&self) {
        let n = self
            .ops
            .0
            .fetch_add(OPS_FLUSH_EVERY as u64, Ordering::Relaxed)
            + OPS_FLUSH_EVERY as u64;
        if n >= self.sample
            && self
                .ops
                .0
                .compare_exchange(n, 0, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            // No-op if a previous pass is still draining: the sketch decays a touch later,
            // which the estimate tolerates; overlapping passes would double-halve instead.
            if self
                .age_remaining
                .0
                .compare_exchange(
                    0,
                    self.blocks.len() as u64,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.agings.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.age_step();
    }

    /// Claim and halve one `age_chunk` slice of the in-flight aging pass, if any.
    /// Concurrent flushing callers claim disjoint slices (the `age_remaining` CAS hands out
    /// ranges back-to-front), so the pass parallelizes safely.
    fn age_step(&self) {
        let mut rem = self.age_remaining.0.load(Ordering::Relaxed);
        loop {
            if rem == 0 {
                return;
            }
            let claim = rem.min(self.age_chunk);
            match self.age_remaining.0.compare_exchange_weak(
                rem,
                rem - claim,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let start = (self.blocks.len() as u64 - rem) as usize;
                    for block in &self.blocks[start..start + claim as usize] {
                        for c in &block.0 {
                            c.store(c.load(Ordering::Relaxed) >> 1, Ordering::Relaxed);
                        }
                    }
                    return;
                }
                Err(v) => rem = v,
            }
        }
    }

    /// Estimated access frequency of `key` — the min over its DEPTH counters (count-min).
    pub fn estimate(&self, key: u64) -> u8 {
        let (block, slots) = self.slots(key);
        let mut m = u8::MAX;
        for slot in slots {
            m = m.min(block.0[slot].load(Ordering::Relaxed));
            if m == 0 {
                break;
            }
        }
        m
    }

    /// Counters in the table (one byte each).
    pub fn counters(&self) -> u64 {
        (self.blocks.len() * BLOCK) as u64
    }

    /// Records between two agings.
    pub fn period_records(&self) -> u64 {
        self.sample
    }

    /// Aging passes started since this filter was created.
    pub fn aging_passes(&self) -> u64 {
        self.agings.load(Ordering::Relaxed)
    }

    /// Share of counters that are non-zero, from an evenly spaced sample of blocks.
    /// The chance that a never-recorded key already reads 1 or more is about this
    /// share to the power of [`DEPTH`]; it should stay well under one half.
    pub fn occupancy(&self) -> f64 {
        let stride = (self.blocks.len() / OCCUPANCY_SAMPLE_BLOCKS).max(1);
        let (mut seen, mut nonzero) = (0u64, 0u64);
        for block in self.blocks.iter().step_by(stride) {
            for c in &block.0 {
                seen += 1;
                nonzero += u64::from(c.load(Ordering::Relaxed) != 0);
            }
        }
        nonzero as f64 / seen as f64
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
        // Drive one ops FLUSH (records land thread-locally until the batch fills): the flush
        // crosses `sample` and arms the incremental halving pass. Extra records only pad the
        // batch — the trigger is >=, and key 7's counters stay untouched.
        for _ in 0..(2 * OPS_FLUSH_EVERY) {
            f.record(101);
        }
        while f.age_remaining.0.load(Ordering::Relaxed) > 0 {
            f.age_step();
        }
        assert_eq!(f.estimate(7), 2, "aged: 4 >> 1 == 2");
        assert!(f.aging_passes() >= 1);
    }

    #[test]
    fn aging_is_incremental_per_flush() {
        let mut f = AdmissionFilter::new(128 * 1024 * 1024);
        f.sample = 1; // any flush arms/advances an aging pass
        for _ in 0..OPS_FLUSH_EVERY {
            f.record(7); // exactly one flush fires (batch full)
        }
        let blocks = f.blocks.len() as u64;
        let rem = f.age_remaining.0.load(Ordering::Relaxed);
        // The arming flush also claimed the first chunk — but no more: the rest
        // of the pass is paid by later flushes, never one inline full sweep.
        assert_eq!(
            rem,
            blocks - f.age_chunk.min(blocks),
            "exactly one chunk claimed"
        );
    }

    #[test]
    fn a_key_uses_distinct_counters_of_one_block() {
        let f = AdmissionFilter::new(128 * 1024 * 1024);
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..10_000 {
            let (_, mut slots) = f.slots(splitmix(&mut state));
            slots.sort_unstable();
            assert!(slots.windows(2).all(|pair| pair[0] != pair[1]));
            assert!(slots.iter().all(|slot| *slot < BLOCK));
        }
    }

    #[test]
    fn an_aging_pass_ends_well_inside_its_period() {
        for mem in [16u64 << 20, 128 << 20, 1 << 30, 3 << 30, 64 << 30] {
            let f = AdmissionFilter::new(mem);
            let flushes = (f.blocks.len() as u64).div_ceil(f.age_chunk);
            assert!(
                flushes * u64::from(OPS_FLUSH_EVERY) <= f.sample / 2,
                "cache of {mem} bytes: a pass takes {flushes} flushes, period is {} records",
                f.sample
            );
            assert!(f.counters() >= f.sample * COUNTERS_PER_PERIOD_RECORD);
            assert!(f.counters() <= MAX_COUNTERS);
        }
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The share of never-recorded keys that read 0 after `periods` aging periods in
    /// which every record is a different key (nothing recurs: the worst case for noise).
    fn unseen_share_reading_zero(max_mem_bytes: u64, periods: u64) -> f64 {
        let f = AdmissionFilter::new(max_mem_bytes);
        let mut state = max_mem_bytes ^ 0x00C0_FFEE;
        // Stop three quarters into the period after the last aging, with that pass
        // drained: the records since are the noise a new key meets.
        for _ in 0..(f.period_records() * periods + f.period_records() * 3 / 4) {
            f.record(splitmix(&mut state));
        }
        let probes = 20_000u32;
        let zero = (0..probes)
            .filter(|_| f.estimate(splitmix(&mut state)) == 0)
            .count();
        zero as f64 / f64::from(probes)
    }

    /// (#1231) With the absolute admit bar, a key that was never requested must read 0,
    /// or its first request passes for its second. The old table (at most 1 Mi counters,
    /// sized from the byte budget) left no unseen key reading 0 at any of these sizes.
    #[test]
    fn a_never_requested_key_reads_zero_at_production_sizes() {
        for (budget, max_mem_bytes) in [
            ("128 MiB (the default)", 128u64 << 20),
            ("1 GiB", 1 << 30),
            ("3 GiB", 3 << 30),
        ] {
            let share = unseen_share_reading_zero(max_mem_bytes, 2);
            // One slot per quarter of the block reads 99.8% or better here; a start and
            // a step inside the block read 99.5% at the largest size.
            assert!(
                share >= 0.997,
                "cache budget {budget}: only {:.1}% of never-requested keys read 0",
                share * 100.0
            );
        }
    }

    /// The cache's key hash is FNV-1a over the key fields. URLs that differ only in a
    /// trailing number are its worst case; they must spread as well as random keys.
    #[test]
    fn sequential_urls_hashed_like_cache_keys_stay_below_the_noise_floor() {
        let fnv = |url: &str| {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for part in [
                &b"\x2a\0\0\0"[..],
                b"\x01",
                b"forum.example",
                url.as_bytes(),
                b"",
                b"",
            ] {
                for byte in part {
                    h = (h ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01B3);
                }
                h = (h ^ 0xFF).wrapping_mul(0x0000_0100_0000_01B3);
            }
            h
        };
        let f = AdmissionFilter::new(1 << 30);
        let recorded = f.period_records() * 3 / 4;
        for n in 0..recorded {
            f.record(fnv(&format!("/threads/topic.{n}/")));
        }
        let probes = 20_000u64;
        let zero = (0..probes)
            .filter(|n| f.estimate(fnv(&format!("/threads/topic.{}/", recorded + n))) == 0)
            .count();
        assert!(
            zero as f64 / probes as f64 >= 0.97,
            "only {zero} of {probes} unseen URLs read 0"
        );
        assert!((0..2000).all(|n| f.estimate(fnv(&format!("/threads/topic.{n}/"))) >= 1));
    }

    #[test]
    fn a_repeated_key_is_still_counted_among_many_others() {
        let f = AdmissionFilter::new(1 << 30);
        let mut state = 7u64;
        let repeated: Vec<u64> = (0..1000).map(|_| splitmix(&mut state)).collect();
        for key in &repeated {
            f.record(*key);
        }
        for _ in 0..f.period_records() / 2 {
            f.record(splitmix(&mut state));
        }
        for key in &repeated {
            f.record(*key);
        }
        assert!(repeated.iter().all(|key| f.estimate(*key) >= 2));
    }

    #[test]
    fn occupancy_tracks_the_recorded_share() {
        let f = AdmissionFilter::new(128 << 20);
        assert_eq!(f.occupancy(), 0.0);
        let mut state = 99u64;
        for _ in 0..f.period_records() / 2 {
            f.record(splitmix(&mut state));
        }
        let occupancy = f.occupancy();
        assert!(occupancy > 0.0 && occupancy < 0.25, "occupancy {occupancy}");
    }
}
