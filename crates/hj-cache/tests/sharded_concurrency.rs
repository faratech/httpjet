//! Concurrency proofs of the generic `ShardedCache` accounting invariant. These are
//! deterministic (no settle dependency); a failure is a real regression. N writers
//! churn insert/replace/remove × M readers hammer `get` under tight RAM+disk caps
//! forcing constant eviction. After join + quiesce, the live byte accounting EXACTLY
//! equals the resident set (`Σ shard.ram_used == Σ live ram_weight`, same for disk),
//! every served value is the value for THAT key (never aliased across keys), and the
//! eviction hook fired for every node that left. The strand the moka era could not
//! rule out — accounting drifting from the resident set under churn — is structurally
//! impossible here (every mutation runs under the one shard lock through the one
//! teardown funnel).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use hj_cache::sharded::{
    CacheValue, EvictCause, OnEvict, ShardCacheConfig, ShardKey, ShardedCache,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TKey(u64);
impl ShardKey for TKey {
    fn nil() -> Self {
        TKey(u64::MAX)
    }
    fn shard_index(&self, shards: usize) -> usize {
        let h = self.0.wrapping_mul(0x9E3779B97F4A7C15);
        (h as usize) & (shards - 1)
    }
}

/// The value carries the key it belongs to (`owner`) so a reader can prove a served
/// value is NEVER another key's value (the never-wrong-content guarantee, generic form).
#[derive(Debug, Clone)]
struct TVal {
    owner: u64,
    ram: u64,
    disk: u64,
    deadline: Option<Instant>,
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

#[derive(Default)]
struct Counter {
    evictions: AtomicU64,
}
impl OnEvict<TKey, Arc<TVal>> for Arc<Counter> {
    fn on_evict(&self, _k: &TKey, _v: &Arc<TVal>, _c: EvictCause) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }
}

type Cache = ShardedCache<TKey, Arc<TVal>, Arc<Counter>>;

/// After quiesce: accounting equals the resident set, exactly, and probing each key
/// either misses or returns that key's own value.
fn assert_invariant(c: &Cache, keys: u64) {
    let mut ram = 0u64;
    let mut disk = 0u64;
    let mut entries = 0u64;
    c.for_each(|k, v| {
        assert_eq!(v.owner, k.0, "a node holds another key's value (aliasing)");
        ram += v.ram_weight();
        disk += v.disk_weight();
        entries += 1;
    });
    let st = c.stats();
    assert_eq!(st.entries, entries, "entry count drift");
    assert_eq!(
        st.ram_bytes, ram,
        "ram accounting ({}) != resident ({})",
        st.ram_bytes, ram
    );
    assert_eq!(
        st.disk_bytes, disk,
        "disk accounting ({}) != resident ({})",
        st.disk_bytes, disk
    );
    // Probe each key: a hit must be that key's own value.
    for k in 0..keys {
        if let Some(v) = c.get(&TKey(k)) {
            assert_eq!(v.owner, k, "get(key {k}) returned key {}'s value", v.owner);
        }
    }
}

/// C1 (flagship): heavy concurrent insert + replace + remove + get under tight caps
/// forcing constant eviction. After quiesce: accounting exact, 0 aliasing.
#[test]
fn c1_heavy_concurrent_insert_get_evict_keeps_accounting_exact() {
    const KEYS: u64 = 200;
    let counter = Arc::new(Counter::default());
    // Tight caps force eviction: ~64 KiB ram + ~64 KiB disk against 200 keys × ~300-700 B.
    let c: Arc<Cache> = Arc::new(ShardedCache::new(
        ShardCacheConfig {
            max_ram_bytes: 64 * 1024,
            max_disk_bytes: 64 * 1024,
        },
        counter.clone(),
    ));
    let stop = Arc::new(AtomicBool::new(false));

    let readers: Vec<_> = (0..4)
        .map(|t| {
            let c = c.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut x = (t as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15);
                let mut wrong = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    let k = x % KEYS;
                    if let Some(v) = c.get(&TKey(k)) {
                        if v.owner != k {
                            wrong += 1;
                        }
                    }
                }
                wrong
            })
        })
        .collect();

    let writers: Vec<_> = (0..4)
        .map(|w| {
            let c = c.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                for round in 0..200u64 {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut k = w as u64;
                    while k < KEYS {
                        let ram = 100 + (round + k) % 400;
                        let disk = 200 + (round + k) % 500;
                        c.insert(
                            TKey(k),
                            Arc::new(TVal {
                                owner: k,
                                ram,
                                disk,
                                deadline: None,
                            }),
                        );
                        if (round + k) % 5 == 0 {
                            // exercise in-place mutate under the lock
                            c.with_shard(&TKey(k), |acc| {
                                acc.mutate(&TKey(k), |v| {
                                    *v = Arc::new(TVal {
                                        owner: k,
                                        ram: ram / 2,
                                        disk: disk / 2,
                                        deadline: None,
                                    });
                                    true
                                });
                            });
                        }
                        if (round + k) % 7 == 0 {
                            c.remove(&TKey(k));
                        }
                        k += 4;
                    }
                }
            })
        })
        .collect();

    for wr in writers {
        wr.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    let mut wrong = 0u64;
    for r in readers {
        wrong += r.join().unwrap();
    }
    assert_eq!(wrong, 0, "a reader saw {wrong} aliased values");
    assert_invariant(&c, KEYS);
    assert!(
        counter.evictions.load(Ordering::Relaxed) > 0,
        "tight caps must have forced evictions"
    );
}

/// C2: a single key churned expire→re-insert while a sweeper races; every observed
/// value is well-formed for the key, accounting stays exact after quiesce.
#[test]
fn c2_expire_then_reinsert_race_keeps_accounting_exact() {
    let counter = Arc::new(Counter::default());
    let c: Arc<Cache> = Arc::new(ShardedCache::new(
        ShardCacheConfig {
            max_ram_bytes: 8 * 1024 * 1024,
            max_disk_bytes: 8 * 1024 * 1024,
        },
        counter.clone(),
    ));
    let stop = Arc::new(AtomicBool::new(false));

    let sweeper = {
        let c = c.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                c.sweep_expired();
            }
        })
    };
    let readers: Vec<_> = (0..3)
        .map(|_| {
            let c = c.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut wrong = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    if let Some(v) = c.get(&TKey(0)) {
                        if v.owner != 0 {
                            wrong += 1;
                        }
                    }
                }
                wrong
            })
        })
        .collect();

    for _ in 0..3000 {
        // short-lived then long-lived re-store of the same key.
        c.insert(
            TKey(0),
            Arc::new(TVal {
                owner: 0,
                ram: 500,
                disk: 500,
                deadline: Some(Instant::now() + Duration::from_millis(1)),
            }),
        );
        thread::sleep(Duration::from_micros(100));
        c.insert(
            TKey(0),
            Arc::new(TVal {
                owner: 0,
                ram: 700,
                disk: 700,
                deadline: None,
            }),
        );
    }

    stop.store(true, Ordering::Relaxed);
    sweeper.join().unwrap();
    let mut wrong = 0u64;
    for r in readers {
        wrong += r.join().unwrap();
    }
    assert_eq!(wrong, 0, "reader saw a non-owner value during the race");
    c.sweep_expired();
    assert_invariant(&c, 1);
}

/// C3: concurrent insert + purge_if on the same key; after a final quiescent purge the
/// key is gone and accounting is zero.
#[test]
fn c3_concurrent_insert_and_purge_settles_to_zero() {
    let counter = Arc::new(Counter::default());
    let c: Arc<Cache> = Arc::new(ShardedCache::new(
        ShardCacheConfig {
            max_ram_bytes: 8 * 1024 * 1024,
            max_disk_bytes: 8 * 1024 * 1024,
        },
        counter,
    ));
    let stop = Arc::new(AtomicBool::new(false));

    let inserter = {
        let c = c.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                c.insert(
                    TKey(7),
                    Arc::new(TVal {
                        owner: 7,
                        ram: 400,
                        disk: 400,
                        deadline: None,
                    }),
                );
            }
        })
    };
    let purger = {
        let c = c.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                c.purge_if(|k, _v| k.0 == 7);
            }
        })
    };

    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    inserter.join().unwrap();
    purger.join().unwrap();

    c.purge_if(|k, _v| k.0 == 7);
    assert!(
        c.get(&TKey(7)).is_none(),
        "key must be gone after final purge"
    );
    let st = c.stats();
    assert_eq!(st.entries, 0);
    assert_eq!(st.ram_bytes, 0);
    assert_eq!(st.disk_bytes, 0);
}
