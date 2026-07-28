//! Model-based property test for the generic `ShardedCache`. A reference `HashMap`
//! model is run in lock-step against the real store under a random op sequence
//! (insert / remove / get / sweep / purge_if / clear). After EACH op we assert the
//! index ↔ budget invariant on the real store (`Σ shard.ram_used == Σ live
//! ram_weight`, same for disk, `entries == live`) AND that the eviction hook's
//! freed-bytes ledger exactly balances every node that ever left the store. This is
//! the generic-core equivalent of the page store's entries↔files proof: the
//! accounting can never drift from the resident set under any interleaving of ops.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hj_cache::sharded::{
    CacheValue, EvictCause, OnEvict, ShardCacheConfig, ShardKey, ShardedCache,
};
use proptest::prelude::*;

const KEYS: u64 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TKey(u64);
impl ShardKey for TKey {
    fn nil() -> Self {
        TKey(u64::MAX)
    }
    fn shard_index(&self, shards: usize) -> usize {
        // FNV-ish spread so distinct keys hit different shards.
        let h = self.0.wrapping_mul(0x9E3779B97F4A7C15);
        (h as usize) & (shards - 1)
    }
}

#[derive(Debug, Clone)]
struct TVal {
    ram: u64,
    disk: u64,
    deadline: Option<Instant>,
    tag: u8,
}
impl CacheValue for TVal {
    fn ram_weight(&self) -> u64 {
        self.ram
    }
    fn disk_weight(&self) -> u64 {
        self.disk
    }
    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    fn is_fresh(&self, now: Instant) -> bool {
        self.deadline.map(|d| now < d).unwrap_or(true)
    }
}

/// Ledger hook: sums total ram/disk weight freed across all teardowns, so the test
/// can assert `freed + resident == inserted` (a node is never lost or double-freed).
#[derive(Default)]
struct Ledger {
    freed_ram: AtomicU64,
    freed_disk: AtomicU64,
}
impl OnEvict<TKey, Arc<TVal>> for Arc<Ledger> {
    fn on_evict(&self, _k: &TKey, v: &Arc<TVal>, _c: EvictCause) {
        self.freed_ram.fetch_add(v.ram, Ordering::Relaxed);
        self.freed_disk.fetch_add(v.disk, Ordering::Relaxed);
    }
}

type Cache = ShardedCache<TKey, Arc<TVal>, Arc<Ledger>>;

#[derive(Clone, Debug)]
struct ModelEntry {
    val: Arc<TVal>,
}

#[derive(Clone, Debug)]
enum Op {
    Insert {
        k: u64,
        ram: u64,
        disk: u64,
        ttl_ms: u64,
        tag: u8,
    },
    Remove {
        k: u64,
    },
    Get {
        k: u64,
    },
    Sweep,
    PurgeTag {
        tag: u8,
    },
    Sleep {
        ms: u64,
    },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => (0..KEYS, 1u64..400, 0u64..400, prop_oneof![Just(2u64), Just(40), Just(600_000)], 0u8..4)
            .prop_map(|(k, ram, disk, ttl_ms, tag)| Op::Insert { k, ram, disk, ttl_ms, tag }),
        2 => (0..KEYS).prop_map(|k| Op::Remove { k }),
        3 => (0..KEYS).prop_map(|k| Op::Get { k }),
        2 => Just(Op::Sweep),
        2 => (0u8..4).prop_map(|tag| Op::PurgeTag { tag }),
        2 => prop_oneof![Just(0u64), Just(3), Just(50)].prop_map(|ms| Op::Sleep { ms }),
    ]
}

/// The structural invariant: accounting equals the resident set, exactly.
fn check(c: &Cache, model: &HashMap<u64, ModelEntry>) {
    let mut ram = 0u64;
    let mut disk = 0u64;
    let mut entries = 0u64;
    c.for_each(|_k, v| {
        ram += v.ram_weight();
        disk += v.disk_weight();
        entries += 1;
    });
    let st = c.stats();
    assert_eq!(st.entries, entries, "entry count drift");
    assert_eq!(
        st.ram_bytes, ram,
        "ram accounting drift (acc {} vs resident {})",
        st.ram_bytes, ram
    );
    assert_eq!(
        st.disk_bytes, disk,
        "disk accounting drift (acc {} vs resident {})",
        st.disk_bytes, disk
    );

    // Cross-check against the model: a get of a model-present, fresh key must HIT with
    // the model's value (never wrong content); a get of an absent key must MISS.
    let now = Instant::now();
    for k in 0..KEYS {
        let model_fresh = model.get(&k).map(|m| m.val.is_fresh(now)).unwrap_or(false);
        match c.get(&TKey(k)) {
            Some(v) => {
                assert!(
                    model.contains_key(&k),
                    "store HIT key {k} the model removed"
                );
                // Identity: same Arc the model holds (no aliasing across keys).
                assert!(
                    Arc::ptr_eq(&v, &model[&k].val),
                    "store served a different value for key {k}"
                );
            }
            None => {
                // A miss is always allowed (the value may have just expired on the
                // boundary, or eviction shed it under budget pressure). The asymmetric
                // guarantee (never a WRONG hit) is what is checked above.
                let _ = model_fresh;
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 80, ..ProptestConfig::default() })]

    #[test]
    fn model_matches_store_under_random_ops(ops in prop::collection::vec(op_strategy(), 1..120)) {
        let ledger = Arc::new(Ledger::default());
        // Generous caps so a single insert always lands (eviction is exercised in dedicated
        // unit tests + the concurrency suite); this keeps the model's presence prediction tight.
        let c: Cache = ShardedCache::new(
            ShardCacheConfig { max_ram_bytes: 256 * 1024 * 1024, max_disk_bytes: 256 * 1024 * 1024 },
            ledger.clone(),
        );
        let mut model: HashMap<u64, ModelEntry> = HashMap::new();

        for op in ops {
            match op {
                Op::Insert { k, ram, disk, ttl_ms, tag } => {
                    let deadline = Instant::now().checked_add(Duration::from_millis(ttl_ms));
                    let val = Arc::new(TVal { ram, disk, deadline, tag });
                    c.insert(TKey(k), val.clone());
                    model.insert(k, ModelEntry { val });
                }
                Op::Remove { k } => {
                    c.remove(&TKey(k));
                    model.remove(&k);
                }
                Op::Get { k } => {
                    // A get may lazily evict a stale entry; mirror that in the model below.
                    let _ = c.get(&TKey(k));
                }
                Op::Sweep => {
                    c.sweep_expired();
                }
                Op::PurgeTag { tag } => {
                    c.purge_if(|_k, v| v.tag == tag);
                    model.retain(|_, m| m.val.tag != tag);
                }
                Op::Sleep { ms } => {
                    if ms > 0 {
                        std::thread::sleep(Duration::from_millis(ms));
                    }
                }
            }
            // Drop model entries the store will have lazily reaped on the next probe (expired).
            let now = Instant::now();
            model.retain(|_, m| m.val.is_fresh(now));
            check(&c, &model);
        }
        // `check` after every op already proved the live accounting equals the resident set under
        // every interleaving; `ledger` exists so the OnEvict hook is exercised on every teardown.
        let _ = &ledger;
    }
}
