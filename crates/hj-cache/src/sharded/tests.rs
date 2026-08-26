//! Unit tests for the generic sharded-LRU core with concrete `TestKey`/`TestValue`
//! types, plus the index↔budget invariant on the generic primitive.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// A u64 test key (FNV-ish identity); NIL = u64::MAX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TestKey(pub u64);

impl ShardKey for TestKey {
    fn nil() -> Self {
        TestKey(u64::MAX)
    }
    fn shard_index(&self, shards: usize) -> usize {
        (self.0 as usize) & (shards - 1)
    }
}

/// A test value with explicit ram/disk weight + optional deadline.
#[derive(Debug, Clone)]
pub struct TestValue {
    pub ram: u64,
    pub disk: u64,
    pub deadline: Option<Instant>,
}

impl TestValue {
    fn ram(n: u64) -> Self {
        TestValue {
            ram: n,
            disk: 0,
            deadline: None,
        }
    }
    fn disk(ram: u64, disk: u64) -> Self {
        TestValue {
            ram,
            disk,
            deadline: None,
        }
    }
    fn expiring(ram: u64, deadline: Instant) -> Self {
        TestValue {
            ram,
            disk: 0,
            deadline: Some(deadline),
        }
    }
}

impl CacheValue for TestValue {
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

/// A counting eviction hook (records causes; sums freed disk bytes).
#[derive(Default)]
struct CountingEvict {
    evictions: AtomicU64,
    disk_evictions: AtomicU64,
    explicit: AtomicU64,
    expired: AtomicU64,
    after_unlock: AtomicU64,
}

impl OnEvict<TestKey, Arc<TestValue>> for Arc<CountingEvict> {
    fn on_evict(&self, _k: &TestKey, _v: &Arc<TestValue>, cause: EvictCause) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
        match cause {
            EvictCause::Disk => {
                self.disk_evictions.fetch_add(1, Ordering::Relaxed);
            }
            EvictCause::Explicit => {
                self.explicit.fetch_add(1, Ordering::Relaxed);
            }
            EvictCause::Expired => {
                self.expired.fetch_add(1, Ordering::Relaxed);
            }
            EvictCause::Size => {}
        }
    }

    fn after_unlock(&self) {
        self.after_unlock.fetch_add(1, Ordering::Relaxed);
    }
}

type Cache = ShardedCache<TestKey, Arc<TestValue>, Arc<CountingEvict>>;

fn cache(ram: u64, disk: u64) -> (Cache, Arc<CountingEvict>) {
    let hook = Arc::new(CountingEvict::default());
    let c = ShardedCache::new(
        ShardCacheConfig {
            max_ram_bytes: ram,
            max_disk_bytes: disk,
        },
        hook.clone(),
    );
    (c, hook)
}

/// Σ shard ram/disk must always equal the per-key recomputed weights (no drift).
fn assert_accounting(c: &Cache) {
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
    assert_eq!(st.ram_bytes, ram, "ram accounting drift");
    assert_eq!(st.disk_bytes, disk, "disk accounting drift");
    let global = c.global_budget.lock();
    assert_eq!(global.ram_used, ram, "global ram reservation drift");
    assert_eq!(global.disk_used, disk, "global disk reservation drift");
}

#[test]
fn insert_get_remove() {
    let (c, hook) = cache(1 << 20, 0);
    assert!(c.get(&TestKey(1)).is_none());
    c.insert(TestKey(1), Arc::new(TestValue::ram(100)));
    assert_eq!(c.get(&TestKey(1)).unwrap().ram, 100);
    assert_eq!(c.entry_count(), 1);
    c.remove(&TestKey(1));
    assert!(c.get(&TestKey(1)).is_none());
    assert_eq!(hook.explicit.load(Ordering::Relaxed), 1);
    assert_accounting(&c);
}

#[test]
fn replace_fires_hook_and_reconciles_accounting() {
    let (c, hook) = cache(1 << 20, 0);
    c.insert(TestKey(5), Arc::new(TestValue::ram(100)));
    c.insert(TestKey(5), Arc::new(TestValue::ram(250)));
    assert_eq!(c.entry_count(), 1);
    assert_eq!(c.ram_bytes(), 250, "weight reflects the replacement");
    assert!(
        hook.explicit.load(Ordering::Relaxed) >= 1,
        "predecessor torn down"
    );
    assert_accounting(&c);
}

#[derive(Debug)]
struct InteriorWeight {
    ram: AtomicU64,
}

impl CacheValue for InteriorWeight {
    fn ram_weight(&self) -> u64 {
        self.ram.load(Ordering::Relaxed)
    }
}

#[test]
fn reconcile_weights_updates_interior_weight_change() {
    let c: ShardedCache<TestKey, Arc<InteriorWeight>, NoEvict> = ShardedCache::new(
        ShardCacheConfig {
            max_ram_bytes: 1 << 20,
            max_disk_bytes: 0,
        },
        NoEvict,
    );
    let key = TestKey(42);
    let value = Arc::new(InteriorWeight {
        ram: AtomicU64::new(100),
    });
    c.insert(key, value.clone());
    assert_eq!(c.ram_bytes(), 100);

    value.ram.store(350, Ordering::Relaxed);
    c.with_shard(&key, |acc| {
        assert!(acc.reconcile_weights(&key, &key));
    });
    assert_eq!(c.ram_bytes(), 350);
}

#[test]
fn mutate_reservation_failure_reports_false_and_evicts_the_mutated_value() {
    let (c, hook) = cache(100, 0);
    let key = TestKey(7);
    c.insert(key, Arc::new(TestValue::ram(100)));

    let committed = c.with_shard(&key, |acc| {
        acc.mutate(&key, |value| {
            *value = Arc::new(TestValue::ram(200));
            true
        })
    });

    assert!(
        !committed,
        "an evicted mutation is not a committed resident value"
    );
    assert!(
        c.get(&key).is_none(),
        "oversized mutated value was torn down"
    );
    assert_eq!(hook.evictions.load(Ordering::Relaxed), 1);
    assert_accounting(&c);
}

#[test]
fn reconcile_on_lru_tail_still_enforces_budget() {
    // reconcile_weights(&tail, &tail) grows the LRU TAIL and protects it. The eviction
    // loop must skip the protected tail and evict its predecessors instead of bailing out
    // and leaving the shard transiently over budget (the old `break` did the latter).
    let c: ShardedCache<TestKey, Arc<InteriorWeight>, NoEvict> = ShardedCache::new(
        ShardCacheConfig {
            max_ram_bytes: 256 * 300, // per-shard budget = 300
            max_disk_bytes: 0,
        },
        NoEvict,
    );
    let mk = |n| {
        Arc::new(InteriorWeight {
            ram: AtomicU64::new(n),
        })
    };
    // All keys land on shard 0 (low byte 0); insert order 0,1,2 ⇒ LRU tail = key 0.
    let tail = TestKey(0);
    let v0 = mk(100);
    c.insert(tail, v0.clone());
    c.insert(TestKey(1 << 8), mk(100));
    c.insert(TestKey(2 << 8), mk(100)); // total 300, exactly at budget
    v0.ram.store(250, Ordering::Relaxed); // grow the protected tail past budget
    c.with_shard(&tail, |acc| {
        assert!(acc.reconcile_weights(&tail, &tail));
    });
    assert!(c.get(&tail).is_some(), "protected tail must survive");
    assert!(
        c.ram_bytes() <= 300,
        "budget must be enforced (no overshoot), got {}",
        c.ram_bytes()
    );
    assert_eq!(c.entry_count(), 1, "predecessors evicted to fit budget");
}

#[test]
fn ram_cap_evicts_coldest() {
    let (c, _hook) = cache(256 * 300, 0); // per-shard budget = 300
    // All keys land on shard 0 (low byte 0).
    for i in 0..10u64 {
        c.insert(TestKey(i << 8), Arc::new(TestValue::ram(100)));
    }
    // Shard 0 budget 300 ⇒ at most 3 of the 100B entries survive.
    let st = c.stats();
    assert!(st.ram_bytes <= 300, "ram bytes {} over cap", st.ram_bytes);
    assert!(c.entry_count() <= 3, "entries {} over cap", c.entry_count());
    assert_accounting(&c);
}

#[test]
fn serve_bumps_recency_then_eviction_spares_it() {
    let (c, _hook) = cache(256 * 300, 0); // per-shard 300
    // Three keys on shard 0; insert order 0,1,2 (2 is MRU).
    for i in 0..3u64 {
        c.insert(TestKey(i << 8), Arc::new(TestValue::ram(100)));
    }
    // Touch key 0 → it becomes MRU. Now insert key 3, evicting the LRU (key 1).
    let _ = c.get(&TestKey(0));
    c.insert(TestKey(3 << 8), Arc::new(TestValue::ram(100)));
    assert!(c.get(&TestKey(0)).is_some(), "recently-served key survived");
    assert!(c.get(&TestKey(1 << 8)).is_none(), "LRU key evicted");
    assert_accounting(&c);
}

#[test]
fn disk_cap_evicts_and_dual_budget_independence() {
    // Generous RAM, tight disk. A disk-weighted value's body is bounded by the disk cap;
    // its small ram weight by the (generous) ram cap. Offloading frees ram budget.
    let (c, hook) = cache(256 * 1_000_000, 256 * 300); // ram huge, disk per-shard 300
    for i in 0..10u64 {
        // ram 10 (metadata-only), disk 100 (body offloaded).
        c.insert(TestKey(i << 8), Arc::new(TestValue::disk(10, 100)));
    }
    let st = c.stats();
    assert!(
        st.disk_bytes <= 300,
        "disk bytes {} over cap",
        st.disk_bytes
    );
    assert!(
        hook.disk_evictions.load(Ordering::Relaxed) > 0,
        "disk cap forced disk evictions"
    );
    assert_accounting(&c);
}

#[test]
fn oversized_protected_inserts_cannot_multiply_the_global_caps_by_shard_count() {
    let (ram, _) = cache(256 * 64, 0);
    // One 1 KiB object is valid against the 16 KiB global cap even though it is
    // much larger than the 64-byte soft shard target.
    for shard in 0..16u64 {
        ram.insert(TestKey(shard), Arc::new(TestValue::ram(1024)));
    }
    assert!(ram.get(&TestKey(0)).is_some());
    assert_eq!(ram.ram_bytes(), 256 * 64);
    assert_eq!(ram.entry_count(), 16);
    ram.insert(TestKey(200), Arc::new(TestValue::ram(1024)));
    assert!(
        ram.get(&TestKey(200)).is_none(),
        "a full cache rejects admission into an empty owning shard"
    );
    assert!(
        ram.get(&TestKey(0)).is_some(),
        "rejection preserves other shards"
    );
    ram.insert(TestKey(256), Arc::new(TestValue::ram(1024)));
    assert!(
        ram.get(&TestKey(0)).is_none(),
        "full-cap insert rotates its shard LRU"
    );
    assert!(ram.get(&TestKey(256)).is_some());
    assert_eq!(ram.ram_bytes(), 256 * 64);
    assert_accounting(&ram);

    let (disk, hook) = cache(256 * 1024, 256 * 64);
    for shard in 0..16u64 {
        disk.insert(TestKey(shard), Arc::new(TestValue::disk(10, 1024)));
    }
    assert!(disk.get(&TestKey(0)).is_some());
    assert_eq!(disk.disk_bytes(), 256 * 64);
    assert_eq!(disk.entry_count(), 16);
    disk.insert(TestKey(200), Arc::new(TestValue::disk(10, 1024)));
    assert!(disk.get(&TestKey(200)).is_none());
    assert!(disk.get(&TestKey(0)).is_some());
    disk.insert(TestKey(256), Arc::new(TestValue::disk(10, 1024)));
    assert!(disk.get(&TestKey(0)).is_none());
    assert!(disk.get(&TestKey(256)).is_some());
    assert_eq!(disk.disk_bytes(), 256 * 64);
    assert_eq!(hook.disk_evictions.load(Ordering::Relaxed), 1);
    assert_accounting(&disk);
}

#[test]
fn not_fresh_get_evicts_through_funnel() {
    let (c, hook) = cache(1 << 20, 0);
    let past = Instant::now() - Duration::from_secs(1);
    c.insert(TestKey(9), Arc::new(TestValue::expiring(100, past)));
    assert!(c.get(&TestKey(9)).is_none(), "stale get is a miss");
    assert_eq!(c.entry_count(), 0, "stale entry torn down on get");
    assert_eq!(hook.expired.load(Ordering::Relaxed), 1);
    assert_accounting(&c);
}

#[test]
fn sweep_reclaims_past_deadline() {
    let (c, hook) = cache(1 << 20, 0);
    let past = Instant::now() - Duration::from_millis(1);
    let future = Instant::now() + Duration::from_secs(60);
    c.insert(TestKey(1), Arc::new(TestValue::expiring(100, past)));
    c.insert(TestKey(2), Arc::new(TestValue::expiring(100, future)));
    let swept = c.sweep_expired();
    assert_eq!(swept, 1, "one past-deadline entry reclaimed");
    assert!(c.get(&TestKey(2)).is_some(), "fresh entry survives sweep");
    assert_eq!(hook.expired.load(Ordering::Relaxed), 1);
    assert_accounting(&c);
}

#[test]
fn sweep_skips_superseded_heap_entry() {
    // A re-insert with a fresh deadline bumps the generation, orphaning the old heap
    // entry; the sweep must NOT tear down the fresh re-store.
    let (c, _hook) = cache(1 << 20, 0);
    let past = Instant::now() - Duration::from_millis(1);
    c.insert(TestKey(1), Arc::new(TestValue::expiring(100, past)));
    let future = Instant::now() + Duration::from_secs(60);
    c.insert(TestKey(1), Arc::new(TestValue::expiring(100, future)));
    let swept = c.sweep_expired();
    assert_eq!(
        swept, 0,
        "fresh re-store not reaped by the stale heap entry"
    );
    assert!(c.get(&TestKey(1)).is_some());
    assert_accounting(&c);
}

#[test]
fn clear_fires_hook_for_every_node() {
    let (c, hook) = cache(1 << 20, 256 * 1_000_000);
    for i in 0..20u64 {
        c.insert(TestKey(i), Arc::new(TestValue::disk(10, 50)));
    }
    let before = hook.evictions.load(Ordering::Relaxed);
    c.clear();
    assert_eq!(c.entry_count(), 0);
    assert_eq!(c.ram_bytes(), 0);
    assert_eq!(c.disk_bytes(), 0);
    assert_eq!(hook.evictions.load(Ordering::Relaxed), before + 20);
    assert_accounting(&c);
}

#[test]
fn purge_if_removes_matching_keys() {
    let (c, _hook) = cache(1 << 20, 0);
    for i in 0..10u64 {
        c.insert(TestKey(i), Arc::new(TestValue::ram(10)));
    }
    c.purge_if(|k, _v| k.0 % 2 == 0);
    assert_eq!(c.entry_count(), 5);
    for i in 0..10u64 {
        assert_eq!(c.get(&TestKey(i)).is_some(), i % 2 == 1);
    }
    assert_accounting(&c);
}

#[test]
fn with_shard_in_place_mutate() {
    let (c, _hook) = cache(1 << 20, 0);
    c.insert(TestKey(3), Arc::new(TestValue::ram(100)));
    let did = c.with_shard(&TestKey(3), |acc| {
        acc.mutate(&TestKey(3), |v| {
            *v = Arc::new(TestValue::ram(400));
            true
        })
    });
    assert!(did);
    assert_eq!(c.ram_bytes(), 400, "mutate reconciled the weight");
    assert_accounting(&c);
}

/// (#293) `after_unlock` fires exactly once per critical section that tore at
/// least one node down — never for eviction-free sections, and once (not once
/// per member) for a grouped multi-id sweep or an expiry sweep of one shard.
#[test]
fn after_unlock_fires_once_per_evicting_critical_section() {
    let (c, hook) = cache(1 << 20, 0);
    let drains = || hook.after_unlock.load(Ordering::Relaxed);

    // Eviction-free sections never call it.
    c.insert(TestKey(1), Arc::new(TestValue::ram(10)));
    let _ = c.get(&TestKey(1));
    let _ = c.get(&TestKey(999));
    assert_eq!(drains(), 0);

    // Explicit remove: one call.
    c.remove(&TestKey(1));
    assert_eq!(drains(), 1);

    // Same-key replace tears the old node down under one section: one call.
    c.insert(TestKey(2), Arc::new(TestValue::ram(10)));
    c.insert(TestKey(2), Arc::new(TestValue::ram(11)));
    assert_eq!(drains(), 2);

    // Grouped sweep: 4 ids in the SAME shard torn down under one lock hold
    // drain once, not four times.
    let ids: Vec<TestKey> = (0..4).map(|i| TestKey(3 + 256 * i)).collect();
    for id in &ids {
        c.insert(*id, Arc::new(TestValue::ram(5)));
    }
    let before = drains();
    let mut group_ids = ids.clone();
    c.with_shard_groups(&mut group_ids, |acc, group| {
        assert_eq!(group.len(), 4, "all four ids share shard 3");
        for id in group {
            acc.teardown(id, EvictCause::Explicit);
        }
    });
    assert_eq!(drains(), before + 1, "one drain per locked shard group");

    // Expiry sweep: several expired entries in one shard drain once.
    let past = Instant::now() - Duration::from_millis(10);
    for i in 0..3u64 {
        c.insert(TestKey(7 + 256 * i), Arc::new(TestValue::expiring(5, past)));
    }
    let before = drains();
    assert_eq!(c.sweep_expired(), 3);
    assert_eq!(drains(), before + 1, "one drain for the swept shard");
    assert_accounting(&c);
}
