I have full grounding. Now I'll write the blueprint.

# FINAL IMPLEMENTATION BLUEPRINT — Bespoke strongly-consistent page-cache store (`hj-pagecache`)

## 1. CHOICE + rationale

**Adopt Design A (sharded `Mutex` + intrusive LRU + synchronous teardown), with one borrowed refinement from Design B and an explicit rejection of Design C's policy layer.**

The user's mandate is ordered: **bulletproof first, efficient second, simplest-that-is-bulletproof always.** Measured against that:

- **Design C (W-TinyLFU/segmented) is rejected as the core.** Its own risk section concedes it is "the *most* complex" and that the hit-ratio upside is "uncertain" and "not where the latency is" (the memories confirm: httpjet CPU is ~0.2% of latency; PHP/private-tier are the levers, not in-store eviction policy). Window+SLRU+CMS+read-buffer replay is more moving parts than the store needs, which directly violates "the existing complexity is the disease." The atomic teardown invariant — the actual mandate — is achieved identically by a plain sharded byte-LRU. **Admission stays where it already is: W-TinyLFU lives in the glue (`AdmissionFilter` in `lscache`), gating *entry into* the store. The store stays admission-agnostic.** This is unchanged and keeps the scan-resistance that matters, without segmenting the store internals.

- **Design B's CLOCK is rejected as the eviction algorithm but its `referenced`-bit idea is folded in as an *optional, off-by-default* read-path refinement.** Plain LRU's "splice to MRU on every hit" is a write-under-lock on the hot path. But at 256 shards / ~74 hits/sec/shard, that write is uncontended and trivially cheap; CLOCK's approximation only earns its keep under shard-lock contention that won't exist at this scale. We keep an intrusive LRU (exact recency, simplest to reason about) and note the CLOCK escape hatch in §5 if a soak ever shows shard-lock contention.

- **Design A is the winner because the invariant is *structural*, not policy-dependent.** Every removal — size eviction, TTL expiry, explicit invalidate, replace — removes the index node, unlinks its tmpfs file, drops its hot copy, GCs its tags, and adjusts both budgets **inside one shard-lock critical section on the calling thread.** That single fact deletes the entire scar-tissue catalog (reconcile, orphan grace, missing-file reclaimer, `disk_lru` second cache + echo, `expiry_track`+sweep, `Replaced`/live-key listener guards, both `OnceLock` forward-refs, all `run_pending` pumping). It is the smallest design that makes the four sub-states atomic.

**One concrete simplification over Design A as written:** use **`parking_lot::Mutex<Shard>`** (no poisoning, ~15-25 ns uncontended CAS) and a **`HashMap<CacheKeyId, Box<Node>>` with `CacheKeyId`-valued intrusive links** rather than a `slab::Slab`. The `slab` adds a generation-counter complication (Design A risk #5) purely to recycle indices; `Box<Node>` with the LRU lists threaded by `CacheKeyId` (a map lookup per link-hop, all O(1), all under the shard lock) sidesteps slab-index reuse entirely and is simpler to audit. The minor cost (LRU relink does 2-4 extra `HashMap::get`s vs a slab index deref) is irrelevant off the read path's critical section.

The read path holds **one shard lock across a `HashMap::get` + LRU touch + `Arc::clone`** (tens of ns), then classifies/decodes/serves outside the lock on the cloned `Arc` — the cloned `Arc` is the caller's snapshot. The 86k/s ceiling (memory `hardening-audit-2026-06-23`) was a single *global* writer-class lock on reads; this is a per-`CacheKeyId`-sharded lock and does not apply.

---

## 2. New module layout, structs, enums

Rewrite `crates/hj-pagecache/src/store.rs`. Use `parking_lot` (workspace). `dashmap` stays (tag epoch maps + render epochs). `key.rs`, `metablob.rs` (minus `file_path_from_body`/`cloned_file_path`), `admission.rs`, `classify.rs`, and `diskstore.rs` (minus `reconcile`/`ReconcileDecision`/`ReconcileSummary`) are unchanged.

```rust
use parking_lot::Mutex;
use std::collections::{BinaryHeap, HashMap};
use std::cmp::Reverse;

const SHARDS: usize = 256;                       // power of two; shard = id.0 & (SHARDS-1)
const PER_ENTRY_OVERHEAD: u64 = 256;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKeyId(u64);
impl CacheKeyId { fn new(k: &PageCacheKey) -> Self { CacheKeyId(stable_key_hash(k)) } }
```

### 2.1 The resident node

`ResidentEntry`'s payload is preserved verbatim (so `to_cached`, `weight`, `freshness`, `retention`, the `OnceLock<DecodedMeta>` decode-once, and the denormalized `tags` are all kept). It gains intrusive LRU links, cached weights, and a precomputed deadline.

```rust
const NIL: CacheKeyId = CacheKeyId(0xFFFF_FFFF_FFFF_FFFF); // sentinel; key_hash never yields this (guarded at hash time, see §2.5)

struct Node {
    // ---- payload (UNCHANGED from today's ResidentEntry) ----
    meta: MetaBlob,
    decoded: OnceLock<DecodedMeta>,        // decode-once; no longer behind an Arc (the Node is owned by one shard)
    tags: Vec<Arc<str>>,                   // denormalized for inline tag GC without decode
    body: PageBody,
    variants: Vec<(String, Bytes)>,
    variants_filled: bool,
    dict_gen: u32,
    stored_at: Instant,
    ttl: Duration, swr: Duration, sie: Duration,

    // ---- intrusive LRU links (keyed by CacheKeyId; NIL = end) ----
    ram_prev: CacheKeyId, ram_next: CacheKeyId,    // RAM-weight LRU (every node is on this list)
    disk_prev: CacheKeyId, disk_next: CacheKeyId,  // disk-weight LRU (only File bodies; else NIL/NIL)

    // ---- cached weights + deadline (computed once at insert/replace) ----
    ram_weight: u32,                       // = weight()  (File/Derived body component = 0)
    disk_weight: u32,                      // = File.len, else 0
    deadline: Instant,                     // = stored_at + retention()
}
```

`Node::freshness`, `Node::to_cached`, `Node::weight` are the existing methods (compute `ram_weight`/`disk_weight` from `weight()` + the body). A single helper `recompute_weights(&self) -> (u32, u32)` is the **sole** arithmetic source for both insert and replace (Design A risk #6).

### 2.2 The shard

```rust
struct Shard {
    map: HashMap<CacheKeyId, Box<Node>>,
    ram_head: CacheKeyId, ram_tail: CacheKeyId,   // MRU .. LRU
    disk_head: CacheKeyId, disk_tail: CacheKeyId, // MRU .. LRU (File bodies only)
    ram_used: u64,
    disk_used: u64,
    expiry: BinaryHeap<Reverse<(Instant, CacheKeyId, u32)>>, // (deadline, id, gen) min-heap; gen guards stale entries
    gen: HashMap<CacheKeyId, u32>,        // current generation per live key (bumped on every replace)
}
```

The `expiry` min-heap + per-key `gen` replaces `expiry_track` + `TtlExpiry`/`deadline_from`. A heap entry is honored only if `gen` matches the live node's current generation (a re-store bumps gen, orphaning the old heap entry — skipped, never tearing down the fresh entry). This is what makes proactive expiry safe by construction (Design A §6, B §5).

### 2.3 The store

```rust
pub struct PageStore {
    shards: Box<[Mutex<Shard>]>,           // length SHARDS, each padded via Box (heap-separated → no false-sharing)
    config: StoreConfig,
    disk: Option<Arc<DiskStore>>,          // tmpfs tier (UNCHANGED)
    hot: Option<HotTier>,                  // body_id -> Bytes; small sharded LRU (see §2.4)

    // per-shard budgets
    ram_budget_per_shard: u64,             // max_mem_bytes / SHARDS  (min 1)
    disk_budget_per_shard: u64,            // (max_disk_bytes||max_mem_bytes) / SHARDS

    // render-vs-purge veto (KEPT verbatim)
    purge_seq: AtomicU64,
    purge_all_epoch: AtomicU64,
    tag_purge_epoch: DashMap<Arc<str>, u64>,
    tag_epoch_prune_floor: AtomicU64,
    active_render_epochs: Arc<Mutex<BTreeMap<u64, usize>>>,

    // tag reverse-index (KEPT; DashMap, sharded internally). value carries the owning shard idx
    // so purge dispatches each key straight to its shard with no scan.
    tag_index: DashMap<Arc<str>, DashMap<CacheKeyId, u8>>,

    // boot readiness (KEPT — readiness signal ONLY, not a reaper interlock)
    scan_purge: Mutex<Option<ScanPurgeBuffer>>,
    scan_loaded: AtomicU64,

    body_id_seq: AtomicU64,
    disk_max_bytes: u64,                   // for stats

    // relaxed-atomic counters
    hits: AtomicU64, misses: AtomicU64, stores: AtomicU64, purges: AtomicU64,
    store_purge_rejections: AtomicU64,
    evictions: AtomicU64, disk_evictions: AtomicU64, swept_expired: AtomicU64,
    disk_read_errors: AtomicU64, disk_write_errors: AtomicU64, disk_full_errors: AtomicU64,
    meta_decode_errors: AtomicU64, key_id_collisions: AtomicU64,
}
```

### 2.4 The hot tier

A small independent sharded LRU of the same shape (key `u64` body_id, value `Bytes`, weight `len+64`, cap `hot_mem_bytes`, idle-evicted on its own clock). It is **pure derived cache** (losing one costs a tmpfs re-read, never correctness) and has **no teardown coupling** to files — so it can be the simplest possible thing. Concretely, a `Box<[Mutex<HotShard>]>` where `HotShard` is `{ map: HashMap<u64, (Bytes, Instant)>, lru: intrusive, bytes: u64 }`; `time_to_idle` enforced by an `Instant` stamp checked on the `maintenance` tick.

### 2.5 NIL-sentinel guard

`stable_key_hash` (= `diskstore::key_hash`) must never return `NIL`'s bit pattern. Add at the bottom of `key_hash`: `if h == u64::MAX { h = 0 }` (collapses one value into another bucket — harmless; collisions already degrade to miss via the identity guard). This keeps `NIL` usable as the list terminator. (Verify no persisted file currently has that hash; effectively impossible, and the identity guard makes a one-in-2⁶⁴ reassignment safe.)

---

## 3. Public method bodies (high level, external-cache-free)

All signatures from the PERF+API report are preserved byte-for-byte so `lscache/mod.rs` is untouched.

### 3.1 `get_entry` / `get_entry_uncounted` / `lookup` / `body_bytes` (read path)

```rust
fn get_entry_inner(&self, key: &PageCacheKey, identity: &str, now: Instant, count: bool) -> EntryState {
    let id = CacheKeyId::new(key);
    let outcome: Option<(Freshness, CachedResponse)> = {
        let mut s = self.shards[id.0 as usize & (SHARDS - 1)].lock();   // ONE shard lock
        match s.map.get(&id) {
            None => None,
            Some(node) => {
                let fresh = node.freshness(now);
                if fresh == Freshness::Gone {
                    self.teardown_locked(&mut s, id, EvictCause::Expired);  // SYNCHRONOUS, under the lock
                    None
                } else {
                    // decode-once + collision guard (UNCHANGED semantics)
                    match node.to_cached() {
                        Err(_) => { self.meta_decode_errors.fetch_add(1, Relaxed);
                                    self.teardown_locked(&mut s, id, EvictCause::Explicit); None }
                        Ok((stored_key, resp)) if stored_key != *key || resp.identity != identity => {
                            self.key_id_collisions.fetch_add(1, Relaxed); None      // NEVER serve wrong content
                        }
                        Ok((_, resp)) => {
                            s.lru_touch_ram(id);                                   // splice to MRU
                            if matches!(node.body, PageBody::File{..})
                               && matches!(fresh, Freshness::Fresh | Freshness::Stale) {
                                s.lru_touch_disk(id);                              // = old disk_lru.get() recency bump
                            }
                            Some((fresh, resp))
                        }
                    }
                }
            }
        }
    };  // lock released here
    match outcome {
        None => { if count { self.misses.fetch_add(1, Relaxed); } EntryState::Miss }
        Some((Freshness::Fresh, r)) => { if count { self.hits.fetch_add(1, Relaxed); } EntryState::Fresh(Arc::new(r)) }
        Some((Freshness::Stale, r)) => { if count { self.hits.fetch_add(1, Relaxed); } EntryState::Stale(Arc::new(r)) }
        Some((Freshness::ErrorOnly, r)) => { if count { self.misses.fetch_add(1, Relaxed); } EntryState::ErrorOnly(Arc::new(r)) }
        Some((Freshness::Gone, _)) => unreachable!(),
    }
}
```

`lookup` and `get_entry_uncounted` are the existing thin wrappers (`count=false` for uncounted). `body_bytes` is **unchanged** — it resolves `InMem`/hot/tmpfs outside any lock, returns `None` fail-closed on a missing/corrupt file (this is the residual-race fallback, §5). `invalidate_key` becomes: lock the owning shard, `teardown_locked(.., Explicit)` if present (drops `self.settle_pending()` — no queue to drain).

### 3.2 The single synchronous teardown funnel

```rust
enum EvictCause { Size, Disk, Expired, Explicit }

impl PageStore {
    // PRECONDITION: caller holds the shard lock for `id`. Removes the node from map + both LRU
    // lists + budgets + expiry gen, unlinks its tmpfs file, drops its hot copy, GCs its tags.
    fn teardown_locked(&self, s: &mut Shard, id: CacheKeyId, cause: EvictCause) {
        let Some(node) = s.map.remove(&id) else { return; };
        s.lru_unlink_ram(&node, id);
        if node.disk_weight > 0 { s.lru_unlink_disk(&node, id); }
        s.ram_used  -= node.ram_weight as u64;
        s.disk_used -= node.disk_weight as u64;
        s.gen.remove(&id);                                   // orphan any pending heap entry
        if let PageBody::File { path, body_id, .. } = &node.body {
            DiskStore::remove(path);                         // UNLINK tmpfs NOW (few µs), under the lock
            if let Some(h) = &self.hot { h.invalidate(*body_id); }
            if cause == EvictCause::Disk { self.disk_evictions.fetch_add(1, Relaxed); }
        }
        for tag in &node.tags {                              // inline tag GC from denormalized tags (no decode)
            if let Some(set) = self.tag_index.get(tag) {
                set.remove(&id);
                if set.is_empty() { drop(set); self.tag_index.remove_if(tag, |_, m| m.is_empty()); }
            }
        }
        self.evictions.fetch_add(1, Relaxed);
    }

    // Pop LRU tails until both per-shard budgets are satisfied. `protect` = the just-inserted key.
    fn enforce_budgets_locked(&self, s: &mut Shard, protect: CacheKeyId) {
        while s.ram_used > self.ram_budget_per_shard {
            let t = s.ram_tail;
            if t == NIL || t == protect { break; }
            self.teardown_locked(s, t, EvictCause::Size);
        }
        while s.disk_used > self.disk_budget_per_shard {
            let t = s.disk_tail;
            if t == NIL || t == protect { break; }
            self.teardown_locked(s, t, EvictCause::Disk);
        }
    }
}
```

**Note on the lock-ordering edge:** `teardown_locked` touches `tag_index` (a `DashMap`) while holding a *shard* mutex. `purge_tags` removes the tag's set from `tag_index` **before** locking any shard. The invariant (documented + debug-asserted): **a shard mutex is innermost; never acquire a shard mutex while holding a `tag_index` entry-set guard.** This is the one hand-maintained rule (Design A risk #4).

### 3.3 `store_if_not_purged_since`

```rust
pub fn store_if_not_purged_since(&self, key: PageCacheKey, mut entry: CachedResponse, render_epoch: u64) -> bool {
    if entry.body.len() as u64 > self.config.max_obj_bytes { return false; }   // >100 MiB / oversize bypass
    let id = CacheKeyId::new(&key);

    // (1) SLOW PART, OFF THE LOCK: offload body to tmpfs at birth (identity form). Same as today.
    if let (Some(disk), PageBody::InMem(bytes)) = (self.disk.as_ref(), &entry.body) {
        let bytes = bytes.clone();
        let stored_unix_ms = wall_ms_of(entry.stored_at);
        match disk.write_entry(&key, &entry, 0, &bytes, stored_unix_ms) {
            Ok(path) => {
                let body_id = self.body_id_seq.fetch_add(1, Relaxed);
                entry.body = PageBody::File { path: Arc::from(path), len: bytes.len() as u32, body_id };
                entry.dict_gen = 0;
            }
            Err(e) => { self.disk_write_errors.fetch_add(1, Relaxed);
                        if e.kind()==StorageFull { self.disk_full_errors.fetch_add(1, Relaxed); } }
        }
    }
    let tags = entry.tags.clone();
    let new_file = cloned_file_path(&entry.body);             // for cleanup on veto/collision
    let node = match Node::from_cached(&key, entry) {          // encodes MetaBlob; same as ResidentEntry::from_cached
        Ok(n) => n,
        Err(_) => { if let Some(p)=new_file { DiskStore::remove(&p); } return false; }
    };

    // (2) FAST PART, UNDER THE SHARD LOCK
    let mut s = self.shards[id.0 as usize & (SHARDS-1)].lock();
    if self.purged_after(&tags, render_epoch) {               // render-vs-purge veto (KEPT)
        self.store_purge_rejections.fetch_add(1, Relaxed);
        if let Some(p) = new_file { DiskStore::remove(&p); }
        return false;
    }
    // SAME-KEY REPLACE: synchronous, eager unlink of the predecessor's DIFFERENT file.
    if let Some(prev) = s.map.get(&id) {
        // collision: prev belongs to a different key → refuse (never overwrite a foreign entry)
        if let Ok((prev_key, prev_exp)) = prev.to_cached() {
            if prev_key != key { self.key_id_collisions.fetch_add(1, Relaxed);
                                 if let Some(p)=new_file { DiskStore::remove(&p);} return false; }
            // drop stale tag memberships this re-store no longer carries
            for old in prev_exp.tags.iter() { if !tags.contains(old) {
                if let Some(set)=self.tag_index.get(old){ set.remove(&id);} } }
        }
        let prev = s.map.get(&id).unwrap();
        let prev_file = cloned_file_path(&prev.body);
        let prev_body_id = if let PageBody::File{body_id,..} = &prev.body { Some(*body_id) } else { None };
        self.detach_for_replace(&mut s, id);                  // unlink lists + subtract weights, KEEP map slot pending swap
        if let Some(pf) = prev_file {
            if Some(pf.as_ref()) != new_file.as_deref() {     // distinct path ⇒ safe to unlink predecessor NOW
                DiskStore::remove(&pf);
            }
        }
        if let (Some(bid), Some(h)) = (prev_body_id, &self.hot) { h.invalidate(bid); }
    }
    // install: index slot + tags + budgets + expiry-heap, all under this one lock
    let g = { let e = s.gen.entry(id).or_insert(0); *e = e.wrapping_add(1); *e };
    s.expiry.push(Reverse((node.deadline, id, g)));
    for tag in &tags { self.tag_index.entry(tag.clone()).or_default().insert(id, (id.0 & (SHARDS-1)) as u8); }
    s.insert_node(id, node);                                  // map.insert + push MRU on ram/disk lists + add weights
    self.enforce_budgets_locked(&mut s, /*protect=*/ id);
    self.stores.fetch_add(1, Relaxed);
    true
}
```

`store(key, entry)` is the existing 2-liner: snapshot `purge_epoch()`, call `store_if_not_purged_since`.

### 3.4 `fill_variants` / `fill_dict_body` / `fill_recompress_disk`

All three keep their exact bodies, with three mechanical changes: `write_lock` → the owning shard lock; `self.inner.get` → `s.map.get`; `self.inner.insert` → an **in-place node mutation** (mutate `s.map.get_mut(&id)` fields + adjust `s.ram_used`/`s.disk_used` deltas + bump `s.gen[id]` + push a fresh expiry-heap entry). The `(identity, stored_at)` no-op race guard is **unchanged** (purged/replaced/already-filled → return). For `fill_recompress_disk`, the predecessor (identity) file is unlinked **synchronously under the shard lock** (it has a distinct path from the new compressed file), deleting the old "lingers as an orphan" branch — and `fill_dict_body`/`fill_variants` (RAM-only) just swap the in-RAM body. The pre-lock unlocked pre-check in `fill_recompress_disk` is dropped (the shard lock is cheap; one re-check suffices), and the slow `disk.write_entry` still happens before the lock.

### 3.5 `purge_tags` / `purge_all`

```rust
pub fn purge_tags(&self, tags: &[&str]) {
    let epoch = self.purge_seq.fetch_add(1, AcqRel) + 1;
    if self.disk.is_some() { /* buffer tags into scan_purge (KEPT, durability) */ }
    for &t in tags {
        let ta: Arc<str> = Arc::from(t);
        self.tag_purge_epoch.insert(ta.clone(), epoch);           // render-veto (KEPT)
        if let Some((_, set)) = self.tag_index.remove(&ta) {      // remove the set FIRST (lock-order rule)
            for e in set.iter() {
                let id = *e.key();
                let mut s = self.shards[id.0 as usize & (SHARDS-1)].lock();
                if let Some(node) = s.map.get(&id) {
                    if let Ok((full_key,_)) = node.to_cached() {
                        if let Some(disk) = &self.disk { disk.remove_key_versions(&full_key); } // durable, all versions
                    }
                }
                self.teardown_locked(&mut s, id, EvictCause::Explicit);  // unlink current file + GC remaining tags
            }
        }
    }
    self.purges.fetch_add(1, Relaxed);
}

pub fn purge_all(&self) {
    let epoch = self.purge_seq.fetch_add(1, AcqRel) + 1;
    self.purge_all_epoch.store(epoch, Release);
    self.tag_purge_epoch.clear();
    self.tag_index.clear();
    for sh in self.shards.iter() {                                // true atomic per-shard clear
        let mut s = sh.lock();
        for (_, node) in s.map.drain() {
            if let PageBody::File{path,body_id,..} = &node.body {
                DiskStore::remove(path);
                if let Some(h)=&self.hot { h.invalidate(*body_id); }
            }
        }
        s.ram_used=0; s.disk_used=0; s.gen.clear(); s.expiry.clear();
        s.ram_head=NIL; s.ram_tail=NIL; s.disk_head=NIL; s.disk_tail=NIL;
    }
    if let Some(h)=&self.hot { h.invalidate_all(); }
    if let Some(disk)=self.disk.clone() { /* write_purge_stamp + scan-purge buffer + bg tmpfs sweep — KEPT */ }
    self.purges.fetch_add(1, Relaxed);
}
```

### 3.6 `maintenance`

```rust
pub fn maintenance(&self, _orphan_grace: Duration) {   // signature kept (main.rs:933 unchanged); arg ignored
    let now = Instant::now();
    for sh in self.shards.iter() {
        let mut s = sh.lock();
        while let Some(Reverse((deadline, id, g))) = s.expiry.peek().copied() {
            if deadline > now { break; }                 // heap ordered by deadline → done for this shard
            s.expiry.pop();
            if s.gen.get(&id) == Some(&g) {              // live current version (else superseded heap entry — skip)
                if let Some(node) = s.map.get(&id) {
                    if node.deadline <= now { self.teardown_locked(&mut s, id, EvictCause::Expired); }
                }
            }
        }
    }
    if let Some(h) = &self.hot { h.evict_idle(now); }   // hot TTI
    self.prune_tag_purge_epoch();                        // KEPT (render-veto map bound)
}
```

### 3.7 `load_from_disk`

Unchanged scan logic (HJPC format, dict-gen reject, purge-stamp reject, per-entry clock for Age continuity). Each kept `ScannedEntry` is rebuilt into a `Node` with `PageBody::File`, then **inserted via the same locked install path** (`s.insert_node` + tag index + expiry heap + `enforce_budgets_locked`). The "newer boot duplicate supersedes" case becomes the §3.3 same-key replace: insert newest, **unlink the older duplicate synchronously under the shard lock** — no orphan handed to a reaper. `on_loaded(&key)` fires per kept key (pre-warms the glue admission sketch). At completion, set `scan_purge = None` and `scan_loaded = kept`. `is_warm()`/`scan_loaded()` unchanged (readiness signal only).

### 3.8 `stats` / `list_entries`

`stats()` sums per-shard `ram_used`/`disk_used`/`map.len()` (exact, not lagged) under each shard lock briefly; `disk_bytes = Σ disk_used`, `memory_bytes = Σ ram_used`, `hot_bytes = hot.bytes()`. `list_entries` iterates each shard's `map` under its lock. Both loopback-only, O(entries), off the request path — unchanged contract. **`CacheStats` keeps all fields** but `swept_expired`/`missing_file_invalidations`/`orphan_reclaimed`/`orphan_deferred` now always report `0` (or `swept_expired` reports `maintenance`'s expiry-pop count if desired). Keep the fields so `metrics.rs` + `cachehud.py` compile (see §8).

---

## 4. Code to DELETE (each subsumed by the invariant)

| Deleted | Subsumed by |
|---|---|
| `TtlExpiry` impl, `deadline_from`, `expire_after_create/update` | Per-shard `expiry` min-heap + `gen`; expiry evicts at `stored_at+retention()` synchronously (§2.2, §3.6) |
| `expiry_track` DashMap + `sweep_expired` standalone reaper + `swept_expired` plumbing | Same expiry heap; no "hidden-but-counted" ghost state exists |
| `inner: Cache`, `disk_lru: Cache`, `hot: Cache` (3 external caches) | One sharded `HashMap`+intrusive LRU; `disk_lru` → per-shard `disk_used` + `disk_*` LRU list; `hot` → bespoke `HotTier` |
| The main eviction listener + `Replaced`-skip + `inner.get` live-key guard + `inner_cell`/`inner_for_main` `OnceLock` | `teardown_locked` runs inline under the lock; the key is the authority, no async stale-cause callback exists |
| `disk_lru` listener + `Size`/`Replaced` skips + `disk_lru_cell` `OnceLock` + the main↔disk echo cascade | `enforce_budgets_locked`'s disk loop tears down the *same* node in the *same* shard — one path, no echo |
| `reconcile_orphans` + `DiskStore::reconcile` + `ReconcileDecision` + `ReconcileSummary` + `orphan_reclaimed`/`orphan_deferred` + `metablob::{file_path_from_body,cloned_file_path}` (the latter kept *only* if still used for veto cleanup — see note) | Supersession unlinks under the lock → orphans never exist |
| `invalidate_missing_file_entries` + `missing_file_invalidations` | A live node's `File.path` always names a current file (invariant) → fileless entry unrepresentable |
| `is_warm()` *as a reaper interlock* (the `!self.is_warm()` gate inside the deleted reapers) | Reapers deleted; `is_warm()` survives as the `/__hj_cache_ready` readiness probe only |
| `settle_pending` / `run_pending` / all `run_pending_tasks()` pumping | Synchronous store has no deferred queue; these become `{}` no-op shims (kept only to satisfy the public surface / tests) |
| The "lingers as an orphan, reclaimed by reconcile" deferral branches in `store`/`fill_recompress_disk`/`load_scanned` | Replaced by synchronous predecessor unlink under the shard lock |
| `write_lock: Mutex<()>` + `lock_loud` + `poisoned_locks` (poison handling) | Folded into the per-shard `parking_lot::Mutex` (no poisoning); `poisoned_locks` stat reports 0 |
| external cache dependency in `Cargo.toml` | — |

**Keep** `cloned_file_path` (it is load-bearing for veto/collision cleanup of the just-written file). Delete `file_path_from_body` (only fed the reconcile `referenced` set).

The `-<seq>` filename + hard-link-refuse publish in `diskstore.rs` is **kept as-is** (cheap crash-safety; orphans bounded to ~1 version/key now, but the publish is correct regardless). The nanosecond seed / `fetch_max` reseed can stay (harmless) — not in the critical-simplicity path.

---

## 5. Read-hit hot path (step by step) + cost

For a HIT on a `File`-bodied entry (the common prod case):

1. `id = CacheKeyId::new(key)` — one `stable_key_hash` (FNV-ish, already cheap; same as today).
2. `self.shards[id.0 & 255].lock()` — one `parking_lot::Mutex` acquire = **one uncontended CAS, ~15-25 ns**. At 19k RPS / 256 shards ≈ **74 acquisitions/sec/shard** → effectively zero contention; the contended cache line is one of 256 (each `Box`-separated), so coherence traffic is ~1/256 of a global lock.
3. `s.map.get(&id)` — one `HashMap` probe.
4. `node.freshness(now)` — arithmetic on the node's own `stored_at` (no global clock, no lock on time).
5. `node.to_cached()` — `OnceLock` read (populated → just a clone of `DecodedMeta` fields); the **decode runs once ever**, on the cold-promotion hit, under the lock. Long-tail entries that are never hit stay compressed-only (footprint preserved).
6. Collision guard: `stored_key == *key && resp.identity == identity` (full `PartialEq` — the structural anti-poisoning check).
7. `s.lru_touch_ram(id)` + (File+servable) `s.lru_touch_disk(id)` — O(1) intrusive splices (a few `HashMap::get` link-hops). This is the only *write* on a hit; it does **not** touch `ram_used`/`disk_used` (recency only), so no budget atomic is bumped.
8. Drop the lock. `Arc::new(resp)` is the caller's snapshot (same allocation the old get-clone path implied).
9. `self.hits.fetch_add(1, Relaxed)` outside the lock.
10. Glue calls `body_bytes` lazily (HEAD/304 skip it): `InMem` clone | hot-tier clone | one tmpfs `pread` (+ hot promote), all **outside any lock**.

**Total HIT cost:** 1 uncontended mutex CAS, 1 hashmap get, ~4 O(1) link writes, 1 `Arc`, 1 relaxed atomic. No syscall, no global atomic, no allocation beyond the `Arc`. **Escape hatch (Design B fold-in):** if a soak ever shows a single super-hot key's shard contending, swap step 7 for a `node.referenced.store(true, Relaxed)` bit + CLOCK-style relink-on-evict; the shard interface is unchanged. Not enabled by default (adds approximation for no measured gain at 256 shards).

---

## 6. Byte-budget + disk-budget enforcement; oversize handling

- **Per-shard, never global** (constraint D; keeps contention local). `ram_budget_per_shard = max_mem_bytes / SHARDS` (min 1); `disk_budget_per_shard = (max_disk_bytes>0 ? max_disk_bytes : max_mem_bytes) / SHARDS`. Each shard holds `ram_used`/`disk_used` `u64`s mutated only under its lock. No global weighted-size atomic → no writer serialization point.
- **Dual-cap charge model (KEPT):** `ram_weight` = `weight()` (InMem body + variants + `meta.compressed_len()` + 256; **File/Derived body component = 0**). `disk_weight` = `File.len` (else 0). The disk LRU is the *same intrusive list threaded through the same nodes* — so the entire `disk_lru` second cache + echo collapses to one `disk_used` accumulator + one LRU list per shard.
- **Enforcement** is `enforce_budgets_locked` (§3.2): after an over-budget insert, pop RAM-LRU tail until `ram_used ≤ cap`, then disk-LRU tail until `disk_used ≤ cap`, each via the single `teardown_locked` (which unlinks the file synchronously). The just-inserted key is `protect`ed from self-eviction.
- **Oversize / >100 MiB single object:** `store_if_not_purged_since` early-returns `false` when `entry.body.len() > config.max_obj_bytes` (unchanged; the glue also gates before constructing the entry). Such a response serves uncached. A single object larger than a *shard's* budget would, if admitted, immediately evict everything else in that shard then itself (protected → stays until next insert); but `max_obj_bytes` (≤100 MiB) is bounded well under `max_mem_bytes`, and admission (glue W-TinyLFU) rejects one-hit-wonders before they reach `store`. Per-shard skew from one large object is bounded to one object/shard (Design A risk #1) and accepted as the standard sharded-LRU tradeoff.

---

## 7. Restart persistence — why no boot-race gate is needed

The tmpfs HJPC files remain the source of truth; `load_from_disk` rebuilds the bespoke index by inserting each scanned `Node` through the **same locked install path** as a live store. The old boot-race gate (`is_warm()` interlocking the reapers) existed because reconcile/missing-file reasoned about "is this file referenced?" against a half-built index, and could delete a persisted file before the scan indexed it. **Those reapers are deleted**, so:

- There is **no file GC that runs against unindexed files** — the *only* unlink sites are `teardown_locked` (acts on a node already in the map) and the same-key replace (acts on a node being superseded under the lock). Neither walks the tmpfs directory; neither can touch a file the scan hasn't yet indexed.
- A request arriving mid-scan simply misses and re-renders (a re-store writes a *new* `-<seq>` file; the scan's later-loaded duplicate of that key triggers a synchronous same-key replace that unlinks the older — correct either way, no orphan).
- `scan_purge` (mid-scan purge buffer) is **kept** for durability: a purge landing during the scan buffers its tags/all-flag, and a scanned entry matching the buffer is rejected at load — so a purge during boot is never resurrected.

`is_warm()`/`scan_loaded()` survive **only** as the `/__hj_cache_ready` readiness signal that `cache_persist_test.sh` waits on (a probe mid-scan would still re-prime + unlink a persisted file via the same-key replace tie-break, so the readiness wait stays mandatory — that part is unchanged).

---

## 8. Migration plan

**Public API is held byte-for-byte stable**, so `crates/httpjet/src/lscache/*` is **untouched**. Concretely:

- **`store.rs`** rewritten (the `PageStore`/`Node`/teardown/maintenance core, ~1500 lines changed, ~600 deleted). `CachedResponse`, `PageBody`, `PageScope`, `EntryState`, `Freshness`, `StoreConfig`, `CacheStats`, `CacheListing`, `EntryInfo`, `RenderEpochGuard`, every `pub fn` signature — unchanged.
- **`diskstore.rs`**: delete `reconcile`, `ReconcileDecision`, `ReconcileSummary`. Keep `write_entry`, `read_body`, `scan`, `read_meta`, `remove_key_versions`, `write/read_purge_stamp`, `remove`, `key_hash` (+ the NIL guard, §2.5). `disk_lru` is **removed entirely** (it was a separate cache inside `store.rs`, not a `diskstore` concept).
- **`metablob.rs`**: delete `file_path_from_body`; keep `cloned_file_path`, `MetaBlob`, `DecodedMeta`, `MetaError`.
- **`Cargo.toml`**: use `parking_lot`.
- **`main.rs`** (only prod caller change): the 30 s tick calls `pc.maintenance(Duration::from_secs(90))` — **signature unchanged**, body now does expiry-heap drain + tag-epoch prune. Delete the comment block referencing `invalidate_missing_file_entries`/`reconcile_orphans`. `load_from_disk` call unchanged. No other `main.rs` change.
- **`metrics.rs`**: unchanged *if* `CacheStats` keeps all fields (it does; the deleted-counter fields report 0). If the `:9090` formatter or `cachehud.py` prints `swept_expired`/`orphan_*`/`missing_file_*`, leave them printing 0, or drop those lines in the same change. **Grep before deleting any field:** `grep -rn 'swept_expired\|orphan_\|missing_file' crates/httpjet/src/ scripts/cachehud.py`.
- **`pipeline/mod.rs`**: `purge_epoch`/`begin_render` unchanged (render-veto kept verbatim).
- **`peer_purge.rs`**: `is_warm`/`scan_loaded` unchanged.

`disk_lru` is removed entirely (folded into per-shard `disk_used` + the disk LRU list). The `--page-cache-disk-mem` flag and `max_disk_bytes` config are unchanged (now feed `disk_budget_per_shard`).

---

## 9. Test plan

**Survive unchanged (must pass byte-for-byte — the regression backstop that format/key/policy didn't drift):** all of `diskstore.rs`/`key.rs`/`classify.rs`/`proto.rs`/`admission.rs`/`metablob.rs` in-src tests (~80), `tests/store_purge_race.rs` (3), `tests/store_retag.rs` (1), `tests/query_empty_vs_bare.rs` (2), and the freshness/identity/private/vary/fill/eviction/cross-scheme in-src tests in `store.rs`. **All 5+ shell gates** (`cache_xurl`, `cache_scheme`, `cache_xhost`, `cache_private`, `cache_persist`, + `sie`/`stale_cf`/`private_live_check`) — implementation-agnostic CF-poisoning acceptance ring.

**Delete (external-cache mechanism artifacts, structurally impossible now):**
- `tests/reconcile.rs` — all 4 (no orphans, no reconcile).
- `tests/expiry_sweep.rs` — the 2 sweep-staging tests (`maintenance_does_not_sweep_*`, the sweep-staged-off assertion).
- In `store.rs`: hidden-invalidation upsert notification tests, `maintenance_batch_invalidates_missing_file_entries`, `reconcile_defers_when_current_file_cannot_be_verified`, the `tag_purge_epoch` map-length tests (rewrite to assert *behavior* — an active render keeps its veto).

**Rewrite from "orphan + reconcile" to "atomic, 1 file":**
- `restore_then_restore_again_replaces_file_version`, `purge_removes_orphan_versions_*`, `expired_and_wrong_dict_gen_files_are_unlinked_at_scan`, `recompress_shrinks_disk_and_unlinks_identity_file` → assert **1 `.pc` file/key immediately**, old file unlinked synchronously, no reconcile call.
- The concurrency tests in `expiry_sweep.rs`/`reconcile.rs` (`*_never_reaps_a_concurrent_restore`, `*_never_strands_live_entries_under_churn`) → fold into Group C below.

**New tests (the proof the invariant holds — `crates/hj-pagecache/tests/atomic_store.rs` + `concurrency.rs`):**

*Group A — atomic single-op consistency:* `store_is_immediately_consistent` (after `store()`, no settle: lookup hits, `entry_count==1`, `disk_bytes` equals the referenced file footprint, exactly 1 `.pc`); `expiry_atomically_unlinks_and_releases` (tiny TTL; first lookup-or-tick reclaims: entries==0, disk_bytes==0, **0 files**); `restore_replaces_file_with_one_file`; `recompress_swaps_to_one_smaller_file`; `purge_{tag,all}_unlinks_synchronously`.

*Group B — eviction:* `ram_cap_evicts_coldest`; `disk_cap_evicts_coldest_and_unlinks` (assert *which* — recently-served survive); `serve_bumps_recency_then_eviction_spares_it`; `dual_cap_independence` (offloaded body frees RAM budget).

*Group C — concurrency proofs (deterministic; no settle dependency; a failure is a real regression):*
- **C1 `heavy_concurrent_store_serve_evict_never_strands_a_referenced_file`** (flagship): N writers (store+recompress+re-store churning versions) × M readers (`lookup`+`body_bytes`) under tight RAM+disk caps forcing constant eviction, fixed iteration count. **After join, with all threads quiesced:** for every indexed entry `body_bytes` resolves (0 fileless) **AND** every `.pc` file on disk is referenced by some live entry (0 orphans) **AND** `Σ disk_used == Σ referenced File.disk_total`. This is the entries↔files↔accounting invariant proven *continuously* — folds `reconcile_never_strands_*` + `concurrent_sweep_*`.
- **C2 `expire_then_restore_race_never_loses_the_restore`** — one key churned expire→re-store while readers hammer; every observed state is the fresh re-store or a clean miss, never a half-evicted hit, `disk_read_errors==0` (the swept-then-restored interleave is structurally impossible: expiry and store hold the same shard lock).
- **C3 `concurrent_store_and_purge_never_serves_stale`** — port verbatim + assert `entries==0 && disk_bytes==0 && 0 files` after the final quiescent purge.
- **C4 `evict_during_serve_never_frees_a_body_in_use`** — a reader holding a resolved `Bytes`/`Arc` while another thread forces that key's eviction; the held body stays valid (it was cloned/hot before the unlink; a cold post-unlink `pread` fails closed to a miss, never wrong bytes).
- **C5 `concurrent_fill_vs_purge_vs_restore`** — a `fill_*` keyed by old `stored_at` racing purge/re-store is always a no-op against the new/absent entry.

*Group F — model-based property test (`tests/model_proptest.rs`, proptest):* a reference `HashMap<Key,(version,body,tags,deadline)>` vs the real store under a random op sequence (store/restore/expire/evict/purge-tag/purge-all/fill); after each op assert (a) every indexed entry resolves a body, (b) no `.pc` is unreferenced, (c) `disk_bytes == Σ referenced file footprints`, (d) lookup == model. This makes the invariant *exhaustively* checkable instead of timing-dependent. (Optional `loom` test on the store/purge + expire/restore interleavings if the `parking_lot` model is loom-compatible; defer if not.)

---

## 10. Risk + rollout

**Risks (with mitigations):**
1. **Per-shard budget skew** — uniform FNV over 256 shards bounds it; one >cap object bounded by `max_obj_bytes`. Accepted (= prior behavior). Optional per-shard slack `×1.0625`.
2. **Unlink-under-lock tail latency** — a tmpfs `unlink` is normally µs; only runs on store/purge/expiry-tick, **never on a pure HIT** (a HIT only lazily evicts a `Gone` entry it was about to miss on, and the backend render dwarfs the µs). Escape hatch: move *only* the `unlink` syscall (not the index removal) to a bounded background drain if a soak shows spikes — index removal stays synchronous so `entries==files` holds from the index's view.
3. **Lock-ordering discipline** (shard mutex innermost; `tag_index` set dropped before locking a shard) is now explicit — add a debug-only lock-order assertion + document the one rule.
4. **Residual cold-body race** (body evicted between `get_entry` and `body_bytes`) → fail-closed cold-miss → backend render, identical to a normal miss, **never wrong content** (the HJPC header re-validation in `read_body` rejects same-name foreign files; `-<seq>` makes names unique). Hot tier covers hot bodies. `Arc<FileGuard>` drop-unlink alternative deferred unless a soak shows measurable cold-miss rate.
5. **Replace-branch accounting drift** — single `recompute_weights` helper for insert+replace+fill; debug `assert(Σ node.ram_weight == shard.ram_used)` in `maintenance`.
6. **Read-path lock model** — `parking_lot::Mutex` per shard at 256 shards; if a future profile shows single-hot-key shard contention, the Design B `referenced`-bit/CLOCK fold-in or an `arc-swap` map swap is a localized change behind the shard interface (validate under real homepage concurrency in the soak).

**Rollout (per CLAUDE.md, one node at a time, cache outlives a rollback via CF edge TTL so gate hard):**
1. `cargo test -p hj-pagecache` (full new suite incl. Group C/F) green locally; `cargo test --workspace`.
2. **x86 PGO:** `scripts/build-pgo.sh` (verify `done ->` + ~16-18M binary; OOM auto-retry per the build-pgo memory).
3. **ARM PGO natively:** rsync sources, `setsid bash /usr/local/httpjet/scripts/build-pgo.sh` on `root@10.10.0.3`, wait for `done ->`.
4. **Deploy x86** (`scripts/deploy-lscache.sh` → `bin/` + `systemctl restart httpjet`), then **GATE on loopback before touching ARM**: `cache_xurl_test.sh`, `cache_scheme_test.sh`, `cache_xhost_test.sh`, `cache_private_test.sh`, `cache_persist_test.sh` (run ONCE — restart-budget), and the `__hj_cache_purge` 204 smoke. All MUST pass.
5. **Deploy ARM**, gate it identically.
6. **Rollback** = `deploy-lscache.sh` auto-revert (`bin/httpjet.prev` + restart). If a bad cache shipped, **also purge Cloudflare** (`purge_everything`, zone windowsforum.com) — a cache bug outlives the binary rollback.
7. **The storm is structurally gone:** `entries ≫ .pc files` + rising `disk_read_err` (the 2026-06-18 prod symptom that `invalidate_missing_file_entries` was added to cure) **cannot recur** — a fileless live entry is unrepresentable under the invariant. `find /dev/shm/jetcache -name '*.pc' | wc -l` **stops oscillating** (no recompress double-write orphan). Watch `:9090 /cache-entries` post-deploy: `entries ≈ files`, `disk_read_err` flat, `evictions`/`disk_evictions` advancing under pressure, `key_id_collisions` ~0. Update CLAUDE.md "file-tier correctness rules 3-4" and the `pagecache-sweep-disabled`/`jetcache-file-tier` memories to reflect that orphans/reconcile no longer exist.

---

**Net:** A plain sharded `parking_lot::Mutex<Shard>` + intrusive byte-weighted LRU + a per-shard deadline min-heap, where **one synchronous `teardown_locked` under the owning shard lock** removes the index node, unlinks the tmpfs file, drops the hot copy, GCs tags, and adjusts both byte budgets together. This makes the four sub-states atomic *by construction*, deleting the entire reconcile/sweep/missing-file/dual-listener/orphan apparatus and all `run_pending` pumping, while keeping a near-lock-free 19k-RPS read path (one of 256 uncontended shard locks for an `Arc::clone`), the dual byte-budget policy, the HJPC persistence + atomic publish, durable purge stamp + `remove_key_versions`, the freshness/SWR/SIE serve semantics, the render-epoch veto, decode-once amortization, the W-TinyLFU admission filter (in the glue, untouched), and the mandatory id+identity collision guard. The public API is held stable so `lscache/*` is untouched and only `main.rs`'s maintenance comment changes.

Key source anchors: read path `store.rs:1050`, store `store.rs:1158`, fills `store.rs:1309-1509`, eviction listener being replaced `store.rs:759-809`, disk-LRU cascade `store.rs:820-856`, purge `store.rs:1737-1825`, expiry/sweep/reconcile `store.rs:1852-2025`, key hash `diskstore.rs:484`, publish `diskstore.rs:143-217`, maintenance caller `main.rs:909-933`.
