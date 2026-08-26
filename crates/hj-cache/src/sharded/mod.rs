//! `hj-shardcache`: a shared, strongly-consistent, sharded byte-weighted LRU
//! used by [`hj-cache`](../hj_cache) (the static-file memory+mmap cache) and
//! shaped for page-cache-style stores that need synchronous teardown hooks.
//!
//! The store is `SHARDS` (256) `parking_lot::Mutex<Shard<K, V>>`, each a
//! `HashMap<K, Box<Node<V>>>` threaded by two intrusive LRU lists (a RAM-weight
//! list every node is on, and a disk-weight list only disk-weighted nodes are on)
//! plus two byte accumulators (`ram_used`/`disk_used`) and a per-shard deadline
//! min-heap with per-node generation guards. A shared reservation counter makes
//! the configured aggregate RAM/disk caps hard; per-shard budgets remain soft
//! LRU targets so one valid object can exceed its shard's fraction.
//!
//! Every removal — size eviction, deadline expiry, explicit invalidate, same-key
//! replace — runs through ONE synchronous teardown funnel **under the owning
//! shard lock on the calling thread**: it removes the node from the map + both
//! LRU lists + budgets, then fires the caller-supplied
//! [`OnEvict`] side-effect (e.g. the page cache's tmpfs unlink + hot-tier drop +
//! tag GC) before the node is dropped. That makes the index ↔ side-effect states
//! atomic by construction, so a node whose external resource was freed while the
//! index still references it is unrepresentable.
//!
//! ## Monomorphization (the hot-path contract)
//! [`ShardedCache`] is generic over the key `K`, value `V`, and eviction hook `E`
//! with NO trait objects on the get/insert path: the value weigher/freshness
//! ([`CacheValue`]) and the eviction hook ([`OnEvict`]) are concrete type
//! parameters, so the ~19k-RPS get-hit path is fully monomorphized (zero virtual
//! dispatch). The only indirection on a hit is one `HashMap` probe + a few O(1)
//! intrusive link writes under one of 256 uncontended shard locks.
//!
//! ## Lock-ordering rule
//! An operation acquires its owning shard before the internal global-budget mutex
//! and before any lock touched by [`OnEvict::on_evict`] (e.g. a tag reverse index).
//! No path may acquire the global-budget mutex and then a shard, or re-enter any
//! shard while an eviction hook's external lock is held.

use std::cmp::{Ordering as CmpOrdering, Reverse};
use std::collections::{BinaryHeap, HashMap};

use rustc_hash::FxBuildHasher;
use std::hash::Hash;
use std::time::Instant;

use parking_lot::Mutex;

/// Number of shards. Power of two so `shard = key.shard_index(SHARDS)` can mask.
pub const SHARDS: usize = 256;

/// A key usable in the sharded store: hashable + cloneable, with a `NIL` sentinel
/// that the intrusive LRU lists use as their terminator, and a shard selector.
///
/// `nil()` MUST return a value that is never a real key (it is the list-end marker;
/// a real key colliding with it would corrupt the LRU lists). Callers that hash an
/// untrusted input into the key are responsible for guarding the hash away from the
/// NIL bit pattern (the page cache does this in `key_hash`).
pub trait ShardKey: Eq + Hash + Clone {
    /// The intrusive-list terminator. Never equal to a real key.
    fn nil() -> Self;
    /// Which shard this key lives in (`0..shards`).
    fn shard_index(&self, shards: usize) -> usize;
}

/// The value stored in a [`ShardedCache`] entry: it supplies its own byte weights,
/// an optional deadline for the proactive expiry heap, and a freshness predicate.
///
/// All four are called under the shard lock, so they must be cheap and must not
/// re-enter the cache.
pub trait CacheValue {
    /// Bytes charged against the RAM budget (`max_mem_bytes`). Every node is on the
    /// RAM LRU list and contributes this to its shard's `ram_used`.
    fn ram_weight(&self) -> u64;
    /// Bytes charged against the disk budget (`max_disk_bytes`). A value with
    /// `disk_weight() > 0` is additionally threaded on the disk LRU list. Callers
    /// with a single budget return `0` here (and pass `max_disk_bytes = 0`).
    fn disk_weight(&self) -> u64 {
        0
    }
    /// The instant past which this value is logically dead. `None` ⇒ it is never
    /// reclaimed by the deadline heap (it lives until evicted by budget pressure or
    /// removed explicitly).
    fn deadline(&self) -> Option<Instant> {
        None
    }
    /// Whether this value is still usable at `now`. A `get` of a non-fresh value
    /// evicts it through the single teardown funnel and reports a miss (the value's
    /// external resources are freed atomically). The default keeps every value fresh
    /// (freshness is the caller's concern), which is what a stat-validated file cache
    /// wants.
    fn is_fresh(&self, _now: Instant) -> bool {
        true
    }
}

/// `Arc<V>` is itself a [`CacheValue`] (delegating to the inner value), so a cache
/// keyed on shared `Arc` handles — the static file cache stores `Arc<CacheEntry>` —
/// works without a wrapper.
impl<T: CacheValue> CacheValue for std::sync::Arc<T> {
    #[inline]
    fn ram_weight(&self) -> u64 {
        (**self).ram_weight()
    }
    #[inline]
    fn disk_weight(&self) -> u64 {
        (**self).disk_weight()
    }
    #[inline]
    fn deadline(&self) -> Option<Instant> {
        (**self).deadline()
    }
    #[inline]
    fn is_fresh(&self, now: Instant) -> bool {
        (**self).is_fresh(now)
    }
}

/// Why a node is being torn down. Passed to [`OnEvict::on_evict`] so the side-effect
/// can distinguish, e.g., a disk-budget eviction (which the page cache counts) from
/// an explicit invalidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictCause {
    /// Evicted because the shard's RAM budget was exceeded.
    Size,
    /// Evicted because the shard's disk budget was exceeded.
    Disk,
    /// Evicted because the value reported it was no longer fresh ([`CacheValue::is_fresh`])
    /// or its deadline passed.
    Expired,
    /// Removed explicitly (invalidate / same-key replace / purge).
    Explicit,
}

/// A synchronous side-effect fired under the shard lock as a node is torn down,
/// BEFORE the node value is dropped. Capture context (counters, an `Arc<HotTier>`,
/// a tag reverse-index) by value/Arc in the implementing type.
///
/// Monomorphized: `E` is a concrete type parameter on [`ShardedCache`], so this is
/// never a trait object on the teardown path.
///
/// LOCK-ORDERING: this runs with the shard mutex held. Do NOT acquire a shard mutex
/// of the same store from here.
pub trait OnEvict<K, V> {
    fn on_evict(&self, key: &K, value: &V, cause: EvictCause);

    /// (#293) Called on the SAME thread immediately after a shard mutex under
    /// which at least one [`Self::on_evict`] fired has been released. Lets a
    /// hook defer pure syscall side-effects (file unlink) out of the critical
    /// section while all bookkeeping stays synchronous under the lock. Every
    /// [`ShardedCache`] entry point that can tear nodes down calls this;
    /// sections that evict nothing never do.
    #[inline]
    fn after_unlock(&self) {}
}

/// A no-op eviction hook (the static file cache: the value's RAII drop — `Bytes` /
/// `Arc<Mmap>` — is the only side-effect needed).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoEvict;

impl<K, V> OnEvict<K, V> for NoEvict {
    #[inline]
    fn on_evict(&self, _key: &K, _value: &V, _cause: EvictCause) {}
}

/// Tunable budgets for a [`ShardedCache`].
#[derive(Debug, Clone, Copy)]
pub struct ShardCacheConfig {
    /// Total RAM-weight budget (bytes) across all shards before LRU eviction.
    pub max_ram_bytes: u64,
    /// Total disk-weight budget (bytes). `0` ⇒ fall back to `max_ram_bytes` for the
    /// disk list's per-shard budget (the page cache's "disk cap defaults to mem cap"
    /// rule); a single-budget caller leaves every value's `disk_weight()` at 0, so the
    /// disk list stays empty and this is irrelevant.
    pub max_disk_bytes: u64,
}

/// One deadline-heap element: `(deadline, gen, key)`. Ordering is by `(deadline,
/// gen)` ONLY so the key `K` need not be `Ord` (it is just a payload carried to the
/// pop site). A `Reverse<DeadlineEntry>` in the `BinaryHeap` makes it a min-heap by
/// deadline.
struct DeadlineEntry<K> {
    deadline: Instant,
    generation: u32,
    key: K,
}

impl<K> PartialEq for DeadlineEntry<K> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.generation == other.generation
    }
}
impl<K> Eq for DeadlineEntry<K> {}
impl<K> PartialOrd for DeadlineEntry<K> {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}
impl<K> Ord for DeadlineEntry<K> {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.deadline
            .cmp(&other.deadline)
            .then(self.generation.cmp(&other.generation))
    }
}

/// One node: the value plus its intrusive LRU links and cached weights/deadline.
struct Node<K, V> {
    value: V,
    ram_prev: K,
    ram_next: K,
    disk_prev: K,
    disk_next: K,
    ram_weight: u64,
    disk_weight: u64,
    generation: u32,
}

/// One shard: a key→node map threaded by two intrusive LRU lists (RAM + disk weight),
/// two byte accumulators, and a deadline min-heap with per-node generation guards (a
/// re-insert or mutation bumps `next_gen`, orphaning old heap entries so a stale heap
/// pop can never tear down a fresh node).
struct Shard<K, V> {
    // FxBuildHasher: K is an internal u64-ish key derived from our own hashing, never
    // raw client input (the ShardKey contract) — a multiply-xor hash beats SipHash for
    // the 5-7 probes a hit pays across probe + LRU touches.
    map: HashMap<K, Box<Node<K, V>>, FxBuildHasher>,
    ram_head: K,
    ram_tail: K,
    disk_head: K,
    disk_tail: K,
    ram_used: u64,
    disk_used: u64,
    expiry: BinaryHeap<Reverse<DeadlineEntry<K>>>,
    next_gen: u32,
}

impl<K: ShardKey, V: CacheValue> Shard<K, V> {
    fn new() -> Self {
        Shard {
            map: HashMap::with_hasher(FxBuildHasher),
            ram_head: K::nil(),
            ram_tail: K::nil(),
            disk_head: K::nil(),
            disk_tail: K::nil(),
            ram_used: 0,
            disk_used: 0,
            expiry: BinaryHeap::new(),
            next_gen: 0,
        }
    }

    fn is_nil(k: &K) -> bool {
        *k == K::nil()
    }

    // ---- RAM LRU list (every node is on it) ----

    fn ram_push_front(&mut self, id: &K) {
        let old_head = self.ram_head.clone();
        {
            let n = self.map.get_mut(id).expect("ram_push_front: id present");
            n.ram_prev = K::nil();
            n.ram_next = old_head.clone();
        }
        if !Self::is_nil(&old_head) {
            self.map
                .get_mut(&old_head)
                .expect("ram head present")
                .ram_prev = id.clone();
        } else {
            self.ram_tail = id.clone();
        }
        self.ram_head = id.clone();
    }

    fn ram_unlink(&mut self, id: &K) {
        let (prev, next) = {
            let n = self.map.get(id).expect("ram_unlink: id present");
            (n.ram_prev.clone(), n.ram_next.clone())
        };
        if !Self::is_nil(&prev) {
            self.map.get_mut(&prev).expect("ram prev present").ram_next = next.clone();
        } else {
            self.ram_head = next.clone();
        }
        if !Self::is_nil(&next) {
            self.map.get_mut(&next).expect("ram next present").ram_prev = prev.clone();
        } else {
            self.ram_tail = prev.clone();
        }
        let n = self.map.get_mut(id).expect("ram_unlink: id present");
        n.ram_prev = K::nil();
        n.ram_next = K::nil();
    }

    /// Splice `id` to the MRU end of the RAM list (recency bump on a hit). O(1).
    fn ram_touch(&mut self, id: &K) {
        if self.ram_head == *id {
            return;
        }
        self.ram_unlink(id);
        self.ram_push_front(id);
    }

    // ---- disk LRU list (disk-weighted nodes only) ----

    fn disk_push_front(&mut self, id: &K) {
        let old_head = self.disk_head.clone();
        {
            let n = self.map.get_mut(id).expect("disk_push_front: id present");
            n.disk_prev = K::nil();
            n.disk_next = old_head.clone();
        }
        if !Self::is_nil(&old_head) {
            self.map
                .get_mut(&old_head)
                .expect("disk head present")
                .disk_prev = id.clone();
        } else {
            self.disk_tail = id.clone();
        }
        self.disk_head = id.clone();
    }

    fn disk_unlink(&mut self, id: &K) {
        let (prev, next) = {
            let n = self.map.get(id).expect("disk_unlink: id present");
            (n.disk_prev.clone(), n.disk_next.clone())
        };
        if !Self::is_nil(&prev) {
            self.map
                .get_mut(&prev)
                .expect("disk prev present")
                .disk_next = next.clone();
        } else {
            self.disk_head = next.clone();
        }
        if !Self::is_nil(&next) {
            self.map
                .get_mut(&next)
                .expect("disk next present")
                .disk_prev = prev.clone();
        } else {
            self.disk_tail = prev.clone();
        }
        let n = self.map.get_mut(id).expect("disk_unlink: id present");
        n.disk_prev = K::nil();
        n.disk_next = K::nil();
    }

    fn disk_touch(&mut self, id: &K) {
        if self.disk_head == *id {
            return;
        }
        self.disk_unlink(id);
        self.disk_push_front(id);
    }

    /// Push a deadline-heap entry for `id` under generation `g` if `deadline` is set.
    fn push_deadline(&mut self, id: &K, deadline: Option<Instant>, g: u32) {
        if let Some(deadline) = deadline {
            self.expiry.push(Reverse(DeadlineEntry {
                deadline,
                generation: g,
                key: id.clone(),
            }));
        }
    }

    /// Bump and return a shard-unique generation for a node version.
    fn bump_gen(&mut self) -> u32 {
        self.next_gen = self.next_gen.wrapping_add(1);
        self.next_gen
    }
}

/// The generic sharded byte-weighted LRU. Construct one with [`ShardedCache::new`]
/// and share it via `Arc`. All methods take `&self`.
pub struct ShardedCache<K: ShardKey, V: CacheValue, E: OnEvict<K, V>> {
    shards: Box<[Mutex<Shard<K, V>>]>,
    on_evict: E,
    ram_budget_per_shard: u64,
    disk_budget_per_shard: u64,
    global_budget: Mutex<GlobalBudget>,
}

struct GlobalBudget {
    ram_used: u64,
    disk_used: u64,
    ram_max: u64,
    disk_max: u64,
}

impl GlobalBudget {
    fn try_replace(&mut self, old_ram: u64, old_disk: u64, new_ram: u64, new_disk: u64) -> bool {
        let Some(next_ram) = self.ram_used.saturating_sub(old_ram).checked_add(new_ram) else {
            return false;
        };
        let Some(next_disk) = self
            .disk_used
            .saturating_sub(old_disk)
            .checked_add(new_disk)
        else {
            return false;
        };
        if next_ram > self.ram_max || next_disk > self.disk_max {
            return false;
        }
        self.ram_used = next_ram;
        self.disk_used = next_disk;
        true
    }

    fn release(&mut self, ram: u64, disk: u64) {
        self.ram_used = self.ram_used.saturating_sub(ram);
        self.disk_used = self.disk_used.saturating_sub(disk);
    }

    fn replacement_pressure(
        &self,
        old_ram: u64,
        old_disk: u64,
        new_ram: u64,
        new_disk: u64,
    ) -> (bool, bool) {
        let ram_over = self
            .ram_used
            .saturating_sub(old_ram)
            .checked_add(new_ram)
            .is_none_or(|next| next > self.ram_max);
        let disk_over = self
            .disk_used
            .saturating_sub(old_disk)
            .checked_add(new_disk)
            .is_none_or(|next| next > self.disk_max);
        (ram_over, disk_over)
    }
}

/// A snapshot of a [`ShardedCache`]'s aggregate counters (loopback/debug use; O(shards)).
#[derive(Debug, Clone, Copy, Default)]
pub struct ShardCacheStats {
    /// Live entry count (Σ shard map lengths).
    pub entries: u64,
    /// Σ shard `ram_used`.
    pub ram_bytes: u64,
    /// Σ shard `disk_used`.
    pub disk_bytes: u64,
}

impl<K: ShardKey, V: CacheValue, E: OnEvict<K, V>> ShardedCache<K, V, E> {
    /// Build a store with the given budgets and eviction hook.
    pub fn new(config: ShardCacheConfig, on_evict: E) -> Self {
        let disk_total = if config.max_disk_bytes > 0 {
            config.max_disk_bytes
        } else {
            config.max_ram_bytes
        };
        let ram_budget_per_shard = (config.max_ram_bytes / SHARDS as u64).max(1);
        let disk_budget_per_shard = (disk_total / SHARDS as u64).max(1);
        let shards = (0..SHARDS)
            .map(|_| Mutex::new(Shard::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        ShardedCache {
            shards,
            on_evict,
            ram_budget_per_shard,
            disk_budget_per_shard,
            global_budget: Mutex::new(GlobalBudget {
                ram_used: 0,
                disk_used: 0,
                ram_max: config.max_ram_bytes,
                disk_max: disk_total,
            }),
        }
    }

    /// The configured eviction hook (so a wrapper can reach the captured context).
    #[inline]
    pub fn on_evict(&self) -> &E {
        &self.on_evict
    }

    #[inline]
    fn shard_for(&self, id: &K) -> &Mutex<Shard<K, V>> {
        &self.shards[id.shard_index(SHARDS)]
    }

    /// Run `f` with the owning shard of `id` locked, giving it a [`ShardAccess`]
    /// handle for in-place node access + the single teardown funnel + recency
    /// touches. This is the escape hatch a wrapper uses to do value-specific work
    /// (decode, identity check) atomically under the lock. The closure returns a
    /// value to the caller.
    pub fn with_shard<R>(&self, id: &K, f: impl FnOnce(&mut ShardAccess<'_, K, V, E>) -> R) -> R {
        let (r, evicted) = {
            let mut s = self.shard_for(id).lock();
            let mut acc = ShardAccess {
                shard: &mut s,
                on_evict: &self.on_evict,
                ram_budget_per_shard: self.ram_budget_per_shard,
                disk_budget_per_shard: self.disk_budget_per_shard,
                global_budget: &self.global_budget,
                evicted: false,
            };
            let r = f(&mut acc);
            (r, acc.evicted)
        };
        if evicted {
            self.on_evict.after_unlock();
        }
        r
    }

    /// Run `f` once per DISTINCT owning shard of `ids` (grouped in place; `ids`
    /// is reordered), with that shard locked, passing the subset of ids it
    /// owns. A multi-id sweep (tag purge) otherwise locks a shard once per
    /// member id (#293).
    pub fn with_shard_groups(
        &self,
        ids: &mut [K],
        mut f: impl FnMut(&mut ShardAccess<'_, K, V, E>, &[K]),
    ) {
        ids.sort_unstable_by_key(|id| id.shard_index(SHARDS));
        let mut start = 0;
        while start < ids.len() {
            let shard_idx = ids[start].shard_index(SHARDS);
            let mut end = start + 1;
            while end < ids.len() && ids[end].shard_index(SHARDS) == shard_idx {
                end += 1;
            }
            let evicted = {
                let mut s = self.shards[shard_idx].lock();
                let mut acc = ShardAccess {
                    shard: &mut s,
                    on_evict: &self.on_evict,
                    ram_budget_per_shard: self.ram_budget_per_shard,
                    disk_budget_per_shard: self.disk_budget_per_shard,
                    global_budget: &self.global_budget,
                    evicted: false,
                };
                f(&mut acc, &ids[start..end]);
                acc.evicted
            };
            if evicted {
                self.on_evict.after_unlock();
            }
            start = end;
        }
    }

    /// Get a clone of the value for `id` if present and fresh, bumping recency.
    /// A present-but-not-fresh value is torn down (through [`OnEvict`]) and `None`
    /// is returned. `V` must be `Clone` (typically `Arc<…>` so the clone is cheap).
    pub fn get(&self, id: &K) -> Option<V>
    where
        V: Clone,
    {
        let now = Instant::now();
        self.with_shard(id, |acc| {
            let (fresh, value, disk) = match acc.shard.map.get(id) {
                None => return None,
                Some(node) => (
                    node.value.is_fresh(now),
                    node.value.clone(),
                    node.disk_weight > 0,
                ),
            };
            if !fresh {
                acc.teardown(id, EvictCause::Expired);
                return None;
            }
            acc.shard.ram_touch(id);
            if disk {
                acc.shard.disk_touch(id);
            }
            Some(value)
        })
    }

    /// Insert `value` under `id`, replacing any existing node (its teardown fires the
    /// [`OnEvict`] hook), then enforce both per-shard LRU targets. A shared reservation
    /// keeps the configured aggregate byte caps hard even when one protected object is
    /// larger than its shard's target. At a full global cap, admission may evict an
    /// eligible LRU from the owning shard; if that shard has no victim, the insert is
    /// rejected rather than cross-locking another shard.
    pub fn insert(&self, id: K, value: V) {
        self.with_shard(&id.clone(), |acc| {
            if acc.insert_replacing(&id, value) {
                acc.enforce_budgets(&id);
            }
        });
    }

    /// Remove `id` if present, firing the [`OnEvict`] hook with [`EvictCause::Explicit`].
    pub fn remove(&self, id: &K) {
        self.with_shard(id, |acc| acc.teardown(id, EvictCause::Explicit));
    }

    /// Reclaim every node whose deadline has passed (and whose value is no longer
    /// fresh), draining each shard's deadline heap. Returns the count reclaimed.
    pub fn sweep_expired(&self) -> u64 {
        let now = Instant::now();
        let mut swept = 0u64;
        for sh in self.shards.iter() {
            let evicted = {
                let mut s = sh.lock();
                let mut acc = ShardAccess {
                    shard: &mut s,
                    on_evict: &self.on_evict,
                    ram_budget_per_shard: self.ram_budget_per_shard,
                    disk_budget_per_shard: self.disk_budget_per_shard,
                    global_budget: &self.global_budget,
                    evicted: false,
                };
                while let Some(Reverse(top)) = acc.shard.expiry.peek() {
                    if top.deadline > now {
                        break;
                    }
                    let (id, g) = (top.key.clone(), top.generation);
                    acc.shard.expiry.pop();
                    let due = acc
                        .shard
                        .map
                        .get(&id)
                        .is_some_and(|n| n.generation == g && !n.value.is_fresh(now));
                    if due {
                        acc.teardown(&id, EvictCause::Expired);
                        swept += 1;
                    }
                }
                acc.evicted
            };
            if evicted {
                self.on_evict.after_unlock();
            }
        }
        swept
    }

    /// Aggregate counters (Σ over shards under each lock). O(shards); off the hot path.
    pub fn stats(&self) -> ShardCacheStats {
        let mut st = ShardCacheStats::default();
        for sh in self.shards.iter() {
            let s = sh.lock();
            st.entries += s.map.len() as u64;
            st.ram_bytes += s.ram_used;
            st.disk_bytes += s.disk_used;
        }
        st
    }

    /// Exact live entry count.
    pub fn entry_count(&self) -> u64 {
        self.shards.iter().map(|s| s.lock().map.len() as u64).sum()
    }

    /// Σ shard `ram_used`.
    pub fn ram_bytes(&self) -> u64 {
        self.shards.iter().map(|s| s.lock().ram_used).sum()
    }

    /// Σ shard `disk_used`.
    pub fn disk_bytes(&self) -> u64 {
        self.shards.iter().map(|s| s.lock().disk_used).sum()
    }

    /// Visit every live `(key, value)` under each shard lock (loopback/debug; O(entries)).
    pub fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        for sh in self.shards.iter() {
            let s = sh.lock();
            for (k, n) in s.map.iter() {
                f(k, &n.value);
            }
        }
    }

    /// Copy a compact snapshot from one shard at a time, then process that batch after
    /// releasing the shard lock. Intended for O(entries) diagnostics whose decoding or
    /// aggregation work must not stall cache hits on the same shard.
    pub fn for_each_shard_snapshot<T>(
        &self,
        mut snapshot: impl FnMut(&K, &V) -> Option<T>,
        mut consume: impl FnMut(Vec<T>),
    ) {
        for sh in self.shards.iter() {
            let batch = {
                let s = sh.lock();
                let mut batch = Vec::with_capacity(s.map.len());
                for (key, node) in s.map.iter() {
                    if let Some(item) = snapshot(key, &node.value) {
                        batch.push(item);
                    }
                }
                batch
            };
            consume(batch);
        }
    }

    /// Remove every node whose key matches `predicate`. Lock-order-safe: each key is
    /// dispatched to its own shard and torn down through the funnel. (For a simple
    /// per-key predicate this is O(entries); callers with a reverse index should
    /// remove keys directly via [`Self::remove`] / [`Self::with_shard`].)
    pub fn purge_if(&self, mut predicate: impl FnMut(&K, &V) -> bool) {
        let mut to_remove: Vec<K> = Vec::new();
        for sh in self.shards.iter() {
            let s = sh.lock();
            for (k, n) in s.map.iter() {
                if predicate(k, &n.value) {
                    to_remove.push(k.clone());
                }
            }
        }
        for id in to_remove {
            self.remove(&id);
        }
    }

    /// Clear every shard, firing the [`OnEvict`] hook for each node (so external
    /// resources are released). Used by the page cache's `purge_all`.
    pub fn clear(&self) {
        for sh in self.shards.iter() {
            let evicted = {
                let mut s = sh.lock();
                // Drain the map first so a node is gone from the index before its hook
                // runs (the hook never re-enters this shard).
                let drained: Vec<(K, Box<Node<K, V>>)> = s.map.drain().collect();
                for (k, n) in &drained {
                    self.on_evict.on_evict(k, &n.value, EvictCause::Explicit);
                }
                let ram = s.ram_used;
                let disk = s.disk_used;
                s.ram_used = 0;
                s.disk_used = 0;
                s.expiry.clear();
                s.ram_head = K::nil();
                s.ram_tail = K::nil();
                s.disk_head = K::nil();
                s.disk_tail = K::nil();
                self.global_budget.lock().release(ram, disk);
                !drained.is_empty()
            };
            // Per shard (not once at the end) so a deferred-unlink hook's
            // pending list holds at most one shard's worth of paths.
            if evicted {
                self.on_evict.after_unlock();
            }
        }
    }
}

/// A handle to one locked shard, handed to the [`ShardedCache::with_shard`] closure.
/// Exposes in-place node access plus the single teardown funnel and budget
/// enforcement, so a wrapper can run value-specific logic atomically under the lock.
pub struct ShardAccess<'a, K: ShardKey, V: CacheValue, E: OnEvict<K, V>> {
    shard: &'a mut Shard<K, V>,
    on_evict: &'a E,
    ram_budget_per_shard: u64,
    disk_budget_per_shard: u64,
    global_budget: &'a Mutex<GlobalBudget>,
    /// True once any teardown fired [`OnEvict::on_evict`] in this critical
    /// section; the owning entry point calls [`OnEvict::after_unlock`] after
    /// releasing the shard mutex iff set (#293).
    evicted: bool,
}

impl<K: ShardKey, V: CacheValue, E: OnEvict<K, V>> ShardAccess<'_, K, V, E> {
    /// Borrow the value for `id` if present.
    pub fn get(&self, id: &K) -> Option<&V> {
        self.shard.map.get(id).map(|n| &n.value)
    }

    /// Is `id` present in this shard?
    pub fn contains(&self, id: &K) -> bool {
        self.shard.map.contains_key(id)
    }

    /// Splice `id` to the MRU end of the RAM (and, if disk-weighted, disk) recency list.
    pub fn touch(&mut self, id: &K) {
        if !self.shard.map.contains_key(id) {
            return;
        }
        self.shard.ram_touch(id);
        let disk = self
            .shard
            .map
            .get(id)
            .map(|n| n.disk_weight > 0)
            .unwrap_or(false);
        if disk {
            self.shard.disk_touch(id);
        }
    }

    /// Splice `id` to the MRU end of the RAM recency list ONLY, never the disk list.
    /// The page cache uses this on a hit it wants to keep RAM-hot while deciding the
    /// disk-recency bump separately (e.g. an error-only File hit bumps RAM recency but
    /// must NOT bump disk recency). No-op if `id` is absent.
    pub fn touch_ram(&mut self, id: &K) {
        if !self.shard.map.contains_key(id) {
            return;
        }
        self.shard.ram_touch(id);
    }

    /// Splice `id` to the MRU end of the disk recency list only (the page cache's
    /// "a served File hit bumps disk-LRU recency" step). No-op if not disk-weighted.
    pub fn touch_disk(&mut self, id: &K) {
        let disk = self
            .shard
            .map
            .get(id)
            .map(|n| n.disk_weight > 0)
            .unwrap_or(false);
        if disk {
            self.shard.disk_touch(id);
        }
    }

    /// The single synchronous teardown funnel: remove `id` from the map + both LRU
    /// lists + budgets, fire [`OnEvict`], then drop the node.
    /// No-op if `id` is absent.
    pub fn teardown(&mut self, id: &K, cause: EvictCause) {
        self.teardown_inner(id, cause, true);
    }

    fn teardown_inner(&mut self, id: &K, cause: EvictCause, release_global: bool) {
        if !self.shard.map.contains_key(id) {
            return;
        }
        let (ram_w, disk_w) = {
            let n = self.shard.map.get(id).expect("teardown: id present");
            (n.ram_weight, n.disk_weight)
        };
        self.shard.ram_unlink(id);
        if disk_w > 0 {
            self.shard.disk_unlink(id);
        }
        self.shard.ram_used = self.shard.ram_used.saturating_sub(ram_w);
        self.shard.disk_used = self.shard.disk_used.saturating_sub(disk_w);
        let node = self.shard.map.remove(id).expect("teardown: id present");
        if release_global {
            self.global_budget.lock().release(ram_w, disk_w);
        }
        self.evicted = true;
        self.on_evict.on_evict(id, &node.value, cause);
    }

    fn reserve_replacing(
        &mut self,
        id: &K,
        old_ram: u64,
        old_disk: u64,
        new_ram: u64,
        new_disk: u64,
    ) -> bool {
        loop {
            let (ram_over, disk_over, impossible) = {
                let mut global = self.global_budget.lock();
                if global.try_replace(old_ram, old_disk, new_ram, new_disk) {
                    return true;
                }
                let impossible = new_ram > global.ram_max || new_disk > global.disk_max;
                let (ram_over, disk_over) =
                    global.replacement_pressure(old_ram, old_disk, new_ram, new_disk);
                (ram_over, disk_over, impossible)
            };
            if impossible {
                return false;
            }

            let (mut victim, cause) = if disk_over {
                (self.shard.disk_tail.clone(), EvictCause::Disk)
            } else if ram_over {
                (self.shard.ram_tail.clone(), EvictCause::Size)
            } else {
                return false;
            };
            if victim == *id {
                victim = self
                    .shard
                    .map
                    .get(&victim)
                    .map(|node| {
                        if disk_over {
                            node.disk_prev.clone()
                        } else {
                            node.ram_prev.clone()
                        }
                    })
                    .unwrap_or_else(K::nil);
            }
            if Shard::<K, V>::is_nil(&victim) {
                return false;
            }
            self.teardown(&victim, cause);
        }
    }

    /// Insert `value` under `id`, tearing down any predecessor first (its [`OnEvict`]
    /// fires). Pushes the node onto the RAM (and disk, if weighted) MRU end, adds its
    /// weights, bumps the generation, and pushes a deadline-heap entry. Does NOT enforce
    /// budgets — call [`Self::enforce_budgets`] after (the wrapper may want to register
    /// tags etc. between insert and enforce).
    pub fn insert_replacing(&mut self, id: &K, value: V) -> bool {
        let ram_w = value.ram_weight();
        let disk_w = value.disk_weight();
        let (old_ram, old_disk) = self
            .shard
            .map
            .get(id)
            .map(|n| (n.ram_weight, n.disk_weight))
            .unwrap_or((0, 0));
        if !self.reserve_replacing(id, old_ram, old_disk, ram_w, disk_w) {
            return false;
        }
        if self.shard.map.contains_key(id) {
            self.teardown_inner(id, EvictCause::Explicit, false);
        }
        let g = self.shard.bump_gen();
        let node = Box::new(Node {
            value,
            ram_prev: K::nil(),
            ram_next: K::nil(),
            disk_prev: K::nil(),
            disk_next: K::nil(),
            ram_weight: ram_w,
            disk_weight: disk_w,
            generation: g,
        });
        self.shard.map.insert(id.clone(), node);
        self.shard.ram_push_front(id);
        if disk_w > 0 {
            self.shard.disk_push_front(id);
        }
        self.shard.ram_used += ram_w;
        self.shard.disk_used += disk_w;
        let deadline = self
            .shard
            .map
            .get(id)
            .expect("just inserted")
            .value
            .deadline();
        self.shard.push_deadline(id, deadline, g);
        true
    }

    /// Mutate the value for `id` in place via `f`, then reconcile its weights, disk-list
    /// membership, deadline-heap entry, and budgets against the pre-mutation snapshot.
    /// `f` returns `true` to commit (weights re-read from the value) or `false` to abort
    /// (no reconciliation). Returns true only when the committed value remains resident;
    /// a global-reservation failure evicts the already-mutated value and returns false.
    /// No-op (returns `false`) if `id` is absent.
    pub fn mutate(&mut self, id: &K, f: impl FnOnce(&mut V) -> bool) -> bool {
        if !self.shard.map.contains_key(id) {
            return false;
        }
        let (old_ram, old_disk) = {
            let n = self.shard.map.get(id).expect("present");
            (n.ram_weight, n.disk_weight)
        };
        let committed = {
            let n = self.shard.map.get_mut(id).expect("present");
            f(&mut n.value)
        };
        if !committed {
            return false;
        }
        let (new_ram, new_disk, deadline) = {
            let n = self.shard.map.get(id).expect("present");
            (
                n.value.ram_weight(),
                n.value.disk_weight(),
                n.value.deadline(),
            )
        };
        if !self.reserve_replacing(id, old_ram, old_disk, new_ram, new_disk) {
            // `f` already committed an in-place change and cannot be rolled back. Evict the
            // mutated value while its cached weights still carry the old global reservation;
            // report false because no committed value remains resident.
            self.teardown(id, EvictCause::Size);
            return false;
        }
        {
            let n = self.shard.map.get_mut(id).expect("present");
            n.ram_weight = new_ram;
            n.disk_weight = new_disk;
        }
        if old_disk > 0 && new_disk == 0 {
            self.shard.disk_unlink(id);
        } else if old_disk == 0 && new_disk > 0 {
            self.shard.disk_push_front(id);
        }
        self.shard.ram_used = self.shard.ram_used.saturating_sub(old_ram) + new_ram;
        self.shard.disk_used = self.shard.disk_used.saturating_sub(old_disk) + new_disk;
        let g = self.shard.bump_gen();
        if let Some(n) = self.shard.map.get_mut(id) {
            n.generation = g;
        }
        self.shard.push_deadline(id, deadline, g);
        self.enforce_budgets(id);
        true
    }

    /// Re-read a value's weights after interior state changed without a `&mut V`
    /// mutation, then enforce budgets. This is for values with internal one-time
    /// initialization such as `OnceLock`-backed decoded metadata.
    pub fn reconcile_weights(&mut self, id: &K, protect: &K) -> bool {
        if !self.shard.map.contains_key(id) {
            return false;
        }
        let (old_ram, old_disk) = {
            let n = self.shard.map.get(id).expect("present");
            (n.ram_weight, n.disk_weight)
        };
        let (new_ram, new_disk) = {
            let n = self.shard.map.get(id).expect("present");
            (n.value.ram_weight(), n.value.disk_weight())
        };
        if !self.reserve_replacing(id, old_ram, old_disk, new_ram, new_disk) {
            self.teardown(id, EvictCause::Size);
            return false;
        }
        {
            let n = self.shard.map.get_mut(id).expect("present");
            n.ram_weight = new_ram;
            n.disk_weight = new_disk;
        }
        if old_disk > 0 && new_disk == 0 {
            self.shard.disk_unlink(id);
        } else if old_disk == 0 && new_disk > 0 {
            self.shard.disk_push_front(id);
        }
        self.shard.ram_used = self.shard.ram_used.saturating_sub(old_ram) + new_ram;
        self.shard.disk_used = self.shard.disk_used.saturating_sub(old_disk) + new_disk;
        self.enforce_budgets(protect);
        true
    }

    /// Pop LRU tails until both per-shard targets are satisfied. `protect` is never
    /// self-evicted: the shared global reservation already guarantees the hard total cap,
    /// while allowing one valid object to exceed its shard's soft target.
    pub fn enforce_budgets(&mut self, protect: &K) {
        while self.shard.ram_used > self.ram_budget_per_shard {
            let mut t = self.shard.ram_tail.clone();
            // `protect` (the just-touched key) is never self-evicted. If it happens to be
            // the LRU tail, step toward the head to its predecessor and evict THAT instead
            // of breaking — otherwise a `reconcile_weights(&id,&id)` charge on the tail
            // would leave the shard transiently over budget until the next insert.
            if t == *protect {
                t = self
                    .shard
                    .map
                    .get(&t)
                    .map(|n| n.ram_prev.clone())
                    .unwrap_or_else(K::nil);
            }
            if Shard::<K, V>::is_nil(&t) {
                break;
            }
            self.teardown(&t, EvictCause::Size);
        }
        while self.shard.disk_used > self.disk_budget_per_shard {
            let mut t = self.shard.disk_tail.clone();
            if t == *protect {
                t = self
                    .shard
                    .map
                    .get(&t)
                    .map(|n| n.disk_prev.clone())
                    .unwrap_or_else(K::nil);
            }
            if Shard::<K, V>::is_nil(&t) {
                break;
            }
            self.teardown(&t, EvictCause::Disk);
        }
    }
}

#[cfg(test)]
mod tests;
