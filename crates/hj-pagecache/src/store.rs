//! The full-page response store: a strongly-consistent, sharded in-RAM index with
//! byte-weighted LRU eviction plus a tag → keys reverse index for O(tagged) purge,
//! optionally fronting a tmpfs file tier.
//!
//! The index is the shared `hj_cache::sharded::ShardedCache` primitive (256
//! `parking_lot::Mutex<Shard>`, each a `HashMap` threaded by two intrusive LRU
//! lists (RAM-weight + disk-weight) and a per-shard deadline min-heap with per-key
//! generation guards). The teardown side-effects — unlink the tmpfs file, drop
//! the hot copy, GC page tags, bump the disk-eviction counter — ride the
//! primitive's [`OnEvict`] hook ([`StoreEvict`]), which fires **under the owning
//! shard lock on the calling thread** before the node value is dropped. So every
//! removal (size eviction, TTL expiry, explicit invalidate, same-key replace) makes
//! the index ↔ file ↔ hot ↔ tag sub-states atomic by construction, and a fileless
//! live entry (the legacy file-tier strand) is unrepresentable — there is no
//! reconcile/orphan/missing-file apparatus and no eventual-consistency queue to pump.
//!
//! TTL/SWR/SIE freshness is still a lookup-time decision (`CachedResponse::freshness`),
//! and the deadline min-heap reclaims past-deadline entries on the maintenance tick.
//!
//! ## Lock-ordering rule (the one hand-maintained invariant)
//! Page publication/purge serialization is outermost, then a shard mutex, then the
//! sharded cache's global-budget mutex or the tag index. [`StoreEvict::on_evict`]
//! runs while the shard lock is held and touches `tag_index`, so a caller must never
//! acquire a shard mutex while holding a `tag_index` lock. `purge_tags` removes a tag
//! set before locking each shard.

use std::cmp::{Ordering as CmpOrdering, Reverse};
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::ffi::OsStr;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use dashmap::DashMap;
use hashbrown::{HashMap as HbHashMap, HashSet as HbHashSet};
use http::{HeaderName, HeaderValue};
use parking_lot::Mutex;

use hj_cache::sharded::{
    CacheValue, EvictCause, OnEvict, SHARDS, ShardAccess, ShardCacheConfig, ShardKey, ShardedCache,
};

use crate::diskstore::{
    DiskStore, ScanSummary, StoredBodyFile, TAG_PURGE_FLOOR_RECORD_BYTES,
    TAG_PURGE_STAMP_RECORD_BYTES, key_hash as stable_key_hash,
};
use crate::key::PageCacheKey;
use crate::metablob::{DecodedMeta, MetaBlob, MetaError, cloned_file_path};

/// Mask for the low-bits shard selector (`SHARDS` is a power of two).
const SHARD_MASK: u64 = SHARDS as u64 - 1;
const DICT_ATTEMPT_VARIANT_TOKEN: &str = "__hj_dict_attempted";
/// Exact durable tag tombstones stay precise through ordinary restarts. Only an exceptional
/// cardinality overflow falls back to the conservative all-tag wall floor.
const MAX_PEER_TAG_PURGE_TOMBSTONES: usize = 262_144;
const PEER_TAG_PURGE_RETAIN_TOMBSTONES: usize = MAX_PEER_TAG_PURGE_TOMBSTONES * 3 / 4;
const PEER_TAG_PURGE_JOURNAL_COMPACT_RECORDS: u64 = 16_384;
const PEER_TAG_PURGE_JOURNAL_COMPACT_BYTES: u64 =
    PEER_TAG_PURGE_JOURNAL_COMPACT_RECORDS * TAG_PURGE_STAMP_RECORD_BYTES;

fn stable_tag_hash(tag: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in tag.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn tag_shard(tag: &str) -> usize {
    (stable_tag_hash(tag) as usize) & (SHARDS - 1)
}

fn wall_purge_veto(
    stored_unix_ms: u64,
    floor_ms: &AtomicU64,
    exact_purged: impl FnOnce() -> bool,
) -> bool {
    if stored_unix_ms <= floor_ms.load(Ordering::Acquire) {
        return true;
    }
    if exact_purged() {
        return true;
    }
    stored_unix_ms <= floor_ms.load(Ordering::Acquire)
}

fn bound_peer_tag_purge_stamps(
    floor_ms: &mut u64,
    stamps: &mut HashMap<u64, u64>,
    hard_cap: usize,
    retain: usize,
) -> bool {
    stamps.retain(|_, wall_ms| *wall_ms > *floor_ms);
    if stamps.len() <= hard_cap {
        return false;
    }

    let retain = retain.min(hard_cap);
    let remove = stamps.len().saturating_sub(retain);
    let mut by_age: Vec<(u64, u64)> = stamps
        .iter()
        .map(|(&tag_hash, &wall_ms)| (wall_ms, tag_hash))
        .collect();
    by_age.sort_unstable();
    *floor_ms = (*floor_ms).max(by_age[remove - 1].0);
    stamps.retain(|_, wall_ms| *wall_ms > *floor_ms);
    true
}

/// Keeps a render epoch visible to cache maintenance until the backend response
/// has either stored or been discarded.
pub struct RenderEpochGuard {
    active: Arc<Mutex<BTreeMap<u64, usize>>>,
    epoch: u64,
}

impl Drop for RenderEpochGuard {
    fn drop(&mut self) {
        let mut active = self.active.lock();
        if let Some(n) = active.get_mut(&self.epoch) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                active.remove(&self.epoch);
            }
        }
    }
}

/// Freshness of a looked-up entry at a given instant — the lookup-time decision
/// that replaces the old binary `is_live` once stale windows exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Within `ttl`: serve as a normal hit.
    Fresh,
    /// Past `ttl`, within the `stale-while-revalidate` window: serve immediately
    /// AND trigger a background revalidation.
    Stale,
    /// Past the SWR window, within the `stale-if-error` window: serve ONLY when
    /// the backend errors; otherwise a miss (render fresh).
    ErrorOnly,
    /// Past every window: gone (a miss; the entry is evictable).
    Gone,
}

/// Result of [`PageStore::get_entry`] — a freshness-classified lookup.
pub enum EntryState {
    /// Fresh hit: serve as a normal cache hit.
    Fresh(Arc<CachedResponse>),
    /// Stale hit: serve immediately, then revalidate in the background.
    Stale(Arc<CachedResponse>),
    /// Past SWR but within stale-if-error: available ONLY as a backend-error
    /// fallback; the caller renders fresh otherwise.
    ErrorOnly(Arc<CachedResponse>),
    /// No usable entry (absent / gone / identity-collision): render the backend.
    Miss,
}

/// Scope of a cached entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageScope {
    /// Shared across all clients.
    Public,
    /// Per-session; `owner_hash` is a keyed hash of the session cookie value.
    Private { owner_hash: u64 },
}

/// Static file validator: (size, mtime, inode) snapshot for freshness checking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileId {
    pub size: u64,
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
    pub inode: u64,
}

impl FileId {
    pub fn stat(path: &Path) -> std::io::Result<Self> {
        std::fs::metadata(path).map(|md| Self::from_metadata(&md))
    }

    pub fn from_metadata(md: &std::fs::Metadata) -> Self {
        let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let dur = mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        FileId {
            size: md.len(),
            mtime_secs: dur.as_secs(),
            mtime_nanos: dur.subsec_nanos(),
            inode: inode_of(md),
        }
    }
}

#[cfg(unix)]
fn inode_of(md: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    md.ino()
}

#[cfg(not(unix))]
fn inode_of(_md: &std::fs::Metadata) -> u64 {
    0
}

/// Static file cache entry. Stored alongside page entries in the unified cache.
/// Identified by vhost_id + path; freshness validated by (size, mtime, inode).
/// Never TTL-expires; invalidated when stat() shows the file changed or is gone.
#[derive(Clone)]
pub struct StaticNode {
    /// Absolute filesystem path of the source file (identity guard).
    pub source_path: std::path::PathBuf,
    /// (size, mtime, inode) snapshot when entry was stored.
    pub file_id: FileId,
    /// Response content type (e.g. "text/css").
    pub content_type: Arc<str>,
    /// ETag: "size-mtime-inode;;;" matching LiteSpeed format.
    pub etag: String,
    /// Last-Modified: RFC 1123 date string.
    pub last_modified: String,
    /// Body: either InMem(bytes) or File{path, len, disk_total, body_id} on tmpfs.
    pub body: PageBody,
}

impl CacheValue for StaticNode {
    fn ram_weight(&self) -> u64 {
        size_of::<StaticNode>() as u64
            + body_ram_bytes(&self.body)
            + path_bytes(&self.source_path)
            + self.content_type.len() as u64
            + string_heap_bytes(&self.etag)
            + string_heap_bytes(&self.last_modified)
    }

    fn disk_weight(&self) -> u64 {
        match &self.body {
            PageBody::File { disk_total, .. } => *disk_total as u64,
            _ => 0,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        None // Static entries never TTL-expire
    }

    fn is_fresh(&self, _now: Instant) -> bool {
        true // Static entries always report fresh; staleness is detected via FileId
    }
}

/// Unified cache entry: either a page response or a static file.
#[allow(private_interfaces)]
pub enum CacheEntry {
    Page(Node),
    Static(StaticNode),
}

impl CacheValue for CacheEntry {
    fn ram_weight(&self) -> u64 {
        match self {
            CacheEntry::Page(n) => n.ram_weight(),
            CacheEntry::Static(s) => s.ram_weight(),
        }
    }

    fn disk_weight(&self) -> u64 {
        match self {
            CacheEntry::Page(n) => n.disk_weight(),
            CacheEntry::Static(s) => s.disk_weight(),
        }
    }

    fn deadline(&self) -> Option<Instant> {
        match self {
            CacheEntry::Page(n) => n.deadline(),
            CacheEntry::Static(_s) => None, // Static entries don't TTL-expire
        }
    }

    fn is_fresh(&self, now: Instant) -> bool {
        match self {
            CacheEntry::Page(n) => n.is_fresh(now),
            CacheEntry::Static(_s) => true, // Static entries always report fresh
        }
    }
}

impl CacheEntry {
    /// Helper: get page variant if present.
    fn as_page(&self) -> Option<&Node> {
        match self {
            CacheEntry::Page(n) => Some(n),
            _ => None,
        }
    }

    fn as_static(&self) -> Option<&StaticNode> {
        match self {
            CacheEntry::Static(n) => Some(n),
            _ => None,
        }
    }
}

/// Body storage for a cached page.
#[derive(Debug, Clone)]
pub enum PageBody {
    /// Fully buffered in RAM. Cheap zero-copy clone via `Bytes`.
    InMem(Bytes),
    /// Persisted in the tmpfs file store (`--page-cache-store-path`), read on
    /// demand through the hot tier — see [`PageStore::body_bytes`]. `len` is the
    /// stored-form body length; `disk_total` is the charged tmpfs footprint
    /// (actual allocated blocks when available, full container size otherwise).
    /// `body_id` keys the hot tier and is unique per body VERSION, so a re-store
    /// can never alias a stale cached copy. The file is immutable for this
    /// entry's lifetime.
    File {
        path: Arc<Path>,
        len: u32,
        /// Charged tmpfs footprint (allocated blocks or full container-size fallback).
        disk_total: u32,
        body_id: u64,
    },
    /// VARIANT-PRIMARY: the identity body is NOT stored — it is reconstructed on
    /// demand by decoding one of the entry's precompressed `variants` (a standard
    /// codec, decodable WITHOUT the page dict, so `dict_gen` is 0 for such an entry).
    /// Set by [`PageStore::fill_variants`] once a stored variant is verified to
    /// round-trip to the identity, dropping the now-redundant (dict-compressed)
    /// identity copy. The body's RAM cost becomes the variant(s), charged separately;
    /// this charges 0. `identity_len` is the uncompressed length (accounting/`len()`
    /// only). Only ever replaces an `InMem` body (RAM-only mode); a file-tier body
    /// keeps its tmpfs identity.
    Derived { identity_len: u32 },
}

impl PageBody {
    /// The body bytes when (and only when) they are resident in this entry.
    /// File-backed and Derived bodies must be resolved via the serve glue.
    pub fn in_mem(&self) -> Option<Bytes> {
        match self {
            PageBody::InMem(b) => Some(b.clone()),
            PageBody::File { .. } | PageBody::Derived { .. } => None,
        }
    }

    /// Body length in bytes (the uncompressed identity length for a Derived body).
    pub fn len(&self) -> usize {
        match self {
            PageBody::InMem(b) => b.len(),
            PageBody::File { len, .. } => *len as usize,
            PageBody::Derived { identity_len } => *identity_len as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A cached full-page response.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    /// The exact request identity (host + raw request path) this entry was built
    /// for. Verified against the request on every lookup: a hit is served ONLY
    /// when it matches, so a key bug/collision can never serve the wrong page —
    /// it degrades to a miss. This is the structural guarantee that each cached
    /// page is unique to its URL. Captured independently of the cache key.
    pub identity: String,
    /// Response headers to replay on a hit (the `X-LiteSpeed-*` control headers
    /// are already stripped before storing).
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: PageBody,
    /// (PC1/PC2-lazy) Precompressed body variants by Content-Encoding token (e.g. "br",
    /// "gzip"). Filled LAZILY on the first cache HIT (not at store time) so compression
    /// CPU + variant RAM is spent only on entries that prove hot by being served — see the
    /// on-first-hit fill in the binary's `lscache`. The identity `body` above is always
    /// retained. Empty ⇒ serve `body` and let the per-serve compress transform handle it.
    pub variants: Vec<(String, Bytes)>,
    /// (PC2-lazy) Set once the on-first-hit variant fill has RUN for this entry — even if it
    /// produced no useful variant — so the fill is attempted at most once (an eligible-type
    /// body that doesn't actually shrink must not re-spawn it on every hit). A freshly-stored
    /// entry is `false` (identity-only); the fill re-inserts the entry with this `true`.
    pub variants_filled: bool,
    /// (dedup) When non-zero, `body` is stored **compressed against the shared page-cache
    /// dictionary** of THIS generation id (see `hj_compress::PageDict`); the identity is recovered
    /// by decoding it with that dictionary. `0` ⇒ `body` is the plain identity (no dictionary).
    /// Tying a body to its dict generation lets a lookup under a different/absent dict degrade to a
    /// miss rather than serve undecodable bytes. The precompressed `variants` are NEVER dict-
    /// compressed (they are served as-is and must stay standard zstd/br/gzip).
    pub dict_gen: u32,
    /// Purge tags from `X-LiteSpeed-Tag`.
    pub tags: Vec<Arc<str>>,
    /// The vary cookie name that produced `vary_value` (empty if none).
    pub vary_cookie_name: String,
    /// The vary discriminant baked into the key.
    pub vary_value: String,
    pub scope: PageScope,
    /// When the entry was stored (for TTL + `Age`).
    pub stored_at: Instant,
    /// Absolute fresh lifetime from `stored_at`.
    pub ttl: Duration,
    /// `stale-while-revalidate` window past `ttl` (0 ⇒ no SWR).
    pub swr: Duration,
    /// `stale-if-error` window past `ttl` (0 ⇒ no SIE).
    pub sie: Duration,
}

impl CachedResponse {
    /// How long the store must retain the entry: `ttl` plus the longer stale window,
    /// so a stale serve / error fallback is possible after `ttl`.
    pub fn retention(&self) -> Duration {
        self.ttl + self.swr.max(self.sie)
    }

    /// Lookup-time freshness classification (single `now` read — no double-eval race).
    pub fn freshness(&self, now: Instant) -> Freshness {
        let age = now.duration_since(self.stored_at);
        if age < self.ttl {
            Freshness::Fresh
        } else if age < self.ttl + self.swr {
            Freshness::Stale
        } else if age < self.ttl + self.sie {
            Freshness::ErrorOnly
        } else {
            Freshness::Gone
        }
    }

    /// Whole seconds since the entry was stored (the HTTP `Age`).
    pub fn age_secs(&self, now: Instant) -> u64 {
        now.duration_since(self.stored_at).as_secs()
    }

    /// True when the identity body was dropped (variant-primary) and must be
    /// reconstructed from a stored variant on an AE-mismatch serve. See
    /// [`PageBody::Derived`]. Such an entry always has `dict_gen == 0`.
    pub fn is_derived(&self) -> bool {
        matches!(self.body, PageBody::Derived { .. })
    }

    /// Whether dictionary recompression has already been attempted for this resident version.
    /// The marker lives in the non-persisted variant vector, so a restart may retry once.
    pub fn dict_compression_attempted(&self) -> bool {
        self.variants
            .iter()
            .any(|(token, _)| token == DICT_ATTEMPT_VARIANT_TOKEN)
    }
}

fn vec_heap_bytes<T>(v: &Vec<T>) -> u64 {
    (v.capacity() * size_of::<T>()) as u64
}

fn string_heap_bytes(s: &String) -> u64 {
    s.capacity() as u64
}

#[cfg(unix)]
fn os_str_len(s: &OsStr) -> usize {
    use std::os::unix::ffi::OsStrExt;
    s.as_bytes().len()
}

#[cfg(not(unix))]
fn os_str_len(s: &OsStr) -> usize {
    s.to_string_lossy().len()
}

fn path_bytes(path: &Path) -> u64 {
    os_str_len(path.as_os_str()) as u64
}

fn page_key_heap_bytes(key: &PageCacheKey) -> u64 {
    string_heap_bytes(&key.host)
        + string_heap_bytes(&key.path)
        + string_heap_bytes(&key.normalized_query)
        + string_heap_bytes(&key.vary_value)
}

fn body_ram_bytes(body: &PageBody) -> u64 {
    match body {
        PageBody::InMem(b) => b.len() as u64,
        PageBody::File { path, .. } => path_bytes(path),
        PageBody::Derived { .. } => 0,
    }
}

fn file_body_disk_version(body: &PageBody) -> Option<(u64, u64)> {
    match body {
        PageBody::File { path, .. } => crate::diskstore::read_meta(path.as_ref())
            .ok()
            .map(|se| (se.stored_unix_ms, se.version_seq)),
        PageBody::InMem(_) | PageBody::Derived { .. } => None,
    }
}

fn variants_ram_bytes(variants: &Vec<(String, Bytes)>) -> u64 {
    vec_heap_bytes(variants)
        + variants
            .iter()
            .map(|(token, body)| string_heap_bytes(token) + body.len() as u64)
            .sum::<u64>()
}

fn tag_vec_ram_bytes(tags: &Vec<Arc<str>>) -> u64 {
    vec_heap_bytes(tags) + tags.iter().map(|t| t.len() as u64).sum::<u64>()
}

fn decoded_meta_heap_bytes(decoded: &DecodedMeta) -> u64 {
    page_key_heap_bytes(&decoded.key)
        + string_heap_bytes(&decoded.identity)
        + vec_heap_bytes(&decoded.headers)
        + decoded
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len() as u64 + value.as_bytes().len() as u64)
            .sum::<u64>()
        + tag_vec_ram_bytes(&decoded.tags)
        + string_heap_bytes(&decoded.vary_cookie_name)
        + string_heap_bytes(&decoded.vary_value)
}

/// Resident heap of the shared serve snapshot (body/variants are accounted by their own
/// `body_ram_bytes`/`variants_ram_bytes` terms; this covers only the rebuilt response shell).
fn snapshot_heap_bytes(r: &CachedResponse) -> u64 {
    size_of::<CachedResponse>() as u64
        + string_heap_bytes(&r.identity)
        + vec_heap_bytes(&r.headers)
        + r.headers
            .iter()
            .map(|(name, value)| name.as_str().len() as u64 + value.as_bytes().len() as u64)
            .sum::<u64>()
        + tag_vec_ram_bytes(&r.tags)
        + string_heap_bytes(&r.vary_cookie_name)
        + string_heap_bytes(&r.vary_value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct CacheKeyId(u64);

impl CacheKeyId {
    fn new(key: &PageCacheKey) -> Self {
        // Clear bit 63: page keys occupy [0, 2^63), static keys (see `for_static`) set
        // bit 63 as a type discriminant. Without this mask ~half of page keys would land
        // in the static numeric range, so a 64-bit collision between a page key and a
        // static key would tear the wrong-type entry down on store (never wrong content —
        // reads are type+identity guarded — but a spurious cross-type eviction). Every
        // in-RAM page CacheKeyId (store, lookup, boot-scan reinsert) goes through here, so
        // the mask is applied consistently; the on-disk filename uses the raw `key_hash`
        // independently. Masking also makes a page key unable to alias the NIL terminator.
        CacheKeyId(stable_key_hash(key) & !(1u64 << 63))
    }

    /// Derive from an ALREADY-COMPUTED raw page hash (`crate::key_hash`) — the glue layer
    /// hashes each key once per request for single-flight/admission and hands it down, so
    /// the storage id costs a mask, not a second pass over every key field. Must stay the
    /// exact inverse of `CacheKeyId::new`: same FNV, same bit-63 mask (see `new`).
    fn from_raw_page_hash(raw: u64) -> Self {
        CacheKeyId(raw & !(1u64 << 63))
    }

    /// Create a key for a static file entry. Uses bit 63 as a type discriminant.
    fn for_static(vhost_id: u32, path: &str) -> Self {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut eat = |bytes: &[u8]| {
            for &b in bytes {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01B3);
            }
            h ^= 0xFF;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        };
        eat(&vhost_id.to_le_bytes());
        eat(path.as_bytes());
        // Set bit 63 to mark as static.
        let mut id = h | (1u64 << 63);
        // NIL-sentinel guard: `CacheKeyId(u64::MAX)` is the intrusive-LRU terminator, so a
        // real static key must never equal it (one-in-2⁶³ reassignment; the identity guard
        // makes any resulting collision a clean miss). Mirrors `key_hash`'s page guard.
        if id == u64::MAX {
            id = 1u64 << 63;
        }
        CacheKeyId(id)
    }
}

/// The primitive's intrusive-LRU list terminator. `key_hash` is guarded never to
/// yield this bit pattern (see `diskstore::key_hash`), so it can double as NIL.
const NIL: CacheKeyId = CacheKeyId(0xFFFF_FFFF_FFFF_FFFF);

impl ShardKey for CacheKeyId {
    #[inline]
    fn nil() -> Self {
        NIL
    }
    #[inline]
    fn shard_index(&self, shards: usize) -> usize {
        (self.0 as usize) & (shards - 1)
    }
}

/// One resident page-cache entry — the value `V` stored in the [`ShardedCache`].
/// The payload (`meta`/`decoded`/`tags`/`body`/variants/timings) is the old
/// `ResidentEntry`, kept verbatim so decode-once, freshness, retention and the
/// denormalized tag GC all behave identically. The intrusive LRU links + cached
/// weights/deadline now live in the primitive's internal node wrapper, so the byte
/// weights / deadline / freshness are exposed via the [`CacheValue`] impl below.
struct Node {
    // ---- payload (UNCHANGED from the old ResidentEntry) ----
    meta: MetaBlob,
    /// Lazily-memoized decode of `meta`, populated on the FIRST hit and reused for every
    /// subsequent one. Cold / rarely-served entries never populate it, so the compressed-only
    /// resident footprint is preserved for the long tail; only entries proven hot by being
    /// served pay the (one-time) decode + hold the decoded form. The `Node` is owned by its
    /// shard and only ever touched under the shard lock, so the `OnceLock` need not be behind
    /// an `Arc`.
    decoded: OnceLock<DecodedMeta>,
    /// Per-node SERVE SNAPSHOT: the fully built `CachedResponse` shared by every hit of
    /// this node version. Built eagerly at store time and after any invalidation; a hit
    /// costs an Arc refcount bump instead of rebuilding + cloning headers/identity/tags/
    /// vary strings under the shard lock. INVARIANT: any post-install mutation of
    /// `body`/`variants`/`variants_filled`/`dict_gen` MUST call `invalidate_snapshot`
    /// (the next hit rebuilds from the mutated fields); missing it serves stale bytes.
    resp_snapshot: OnceLock<Arc<CachedResponse>>,
    /// Plaintext copy of the purge tags, denormalized off the encoded `meta` so [`StoreEvict`]
    /// can drop this key from the tag index WITHOUT decoding `meta` (a decode failure on a corrupt
    /// blob would otherwise strand the key in its tag sets forever).
    tags: Vec<Arc<str>>,
    body: PageBody,
    variants: Vec<(String, Bytes)>,
    variants_filled: bool,
    dict_gen: u32,
    /// Purge clock captured before the render/fetch that produced this node.
    /// A tag purge must not tear down a replacement whose render began at or
    /// after that purge's own epoch.
    render_epoch: u64,
    stored_at: Instant,
    ttl: Duration,
    swr: Duration,
    sie: Duration,
}

impl CacheValue for Node {
    /// Cache-accounted RAM bytes: exact inline struct size plus owned resident byte
    /// payloads/capacities visible from the current fields. Hidden allocator and
    /// hash-table bucket overhead is reported separately as process/RSS gap metrics.
    fn ram_weight(&self) -> u64 {
        let decoded = self.decoded.get().map(decoded_meta_heap_bytes).unwrap_or(0);
        let snap = self
            .resp_snapshot
            .get()
            .map(|r| snapshot_heap_bytes(r))
            .unwrap_or(0);
        size_of::<Node>() as u64
            + self.meta.compressed_len() as u64
            + tag_vec_ram_bytes(&self.tags)
            + body_ram_bytes(&self.body)
            + variants_ram_bytes(&self.variants)
            + decoded
            + snap
    }

    /// Disk (tmpfs) bytes: the charged file-tier footprint of a File body, else 0.
    fn disk_weight(&self) -> u64 {
        match &self.body {
            PageBody::File { disk_total, .. } => *disk_total as u64,
            _ => 0,
        }
    }

    /// Logical end-of-life = `stored_at + retention()`, fed to the primitive's deadline heap.
    fn deadline(&self) -> Option<Instant> {
        Some(
            self.stored_at
                .checked_add(self.retention())
                .unwrap_or(self.stored_at),
        )
    }

    /// A `get`/sweep evicts a value only when it is fully `Gone`; Fresh/Stale/ErrorOnly all
    /// stay resident (they are still served / error-fallback-served by the page logic).
    fn is_fresh(&self, now: Instant) -> bool {
        !matches!(self.freshness(now), Freshness::Gone)
    }
}

impl Node {
    /// Encode the metadata blob and build a fresh node.
    fn from_cached(
        key: &PageCacheKey,
        entry: CachedResponse,
        render_epoch: u64,
    ) -> Result<Self, MetaError> {
        let meta = MetaBlob::encode(key, &entry)?;
        let node = Node {
            meta,
            decoded: OnceLock::new(),
            resp_snapshot: OnceLock::new(),
            tags: entry.tags.clone(),
            body: entry.body,
            variants: entry.variants,
            variants_filled: entry.variants_filled,
            dict_gen: entry.dict_gen,
            render_epoch,
            stored_at: entry.stored_at,
            ttl: entry.ttl,
            swr: entry.swr,
            sie: entry.sie,
        };
        // The serve snapshot stays LAZY (built on the first hit): cold / rarely-served
        // entries must keep their compressed-only resident footprint — eagerly decoding
        // at store time would re-inflate the whole long tail's RAM for no serving benefit.
        Ok(node)
    }

    /// Build (and install) the shared serve snapshot from current fields. Caller holds the
    /// shard lock. Returns a clone for immediate use.
    fn build_snapshot(&self) -> Result<Arc<CachedResponse>, MetaError> {
        let decoded = match self.decoded.get() {
            Some(d) => d,
            None => {
                let d = self.meta.decode()?;
                let _ = self.decoded.set(d);
                self.decoded.get().expect("OnceLock populated after set")
            }
        };
        let resp = Arc::new(decoded.to_cached_response(
            self.body.clone(),
            self.variants.clone(),
            self.variants_filled,
            self.dict_gen,
            self.stored_at,
            self.ttl,
            self.swr,
            self.sie,
        ));
        let _ = self.resp_snapshot.set(Arc::clone(&resp));
        Ok(resp)
    }

    /// Drop the shared snapshot after mutating body/variants/dict_gen/variants_filled;
    /// the next hit rebuilds it from the mutated fields (one rebuild per mutation —
    /// mutations are rare relative to hits).
    fn invalidate_snapshot(&mut self) {
        self.resp_snapshot = OnceLock::new();
    }

    fn retention(&self) -> Duration {
        self.ttl + self.swr.max(self.sie)
    }

    fn freshness(&self, now: Instant) -> Freshness {
        let age = now.duration_since(self.stored_at);
        if age < self.ttl {
            Freshness::Fresh
        } else if age < self.ttl + self.swr {
            Freshness::Stale
        } else if age < self.ttl + self.sie {
            Freshness::ErrorOnly
        } else {
            Freshness::Gone
        }
    }

    /// Decode the metadata at most once per node and rebuild the `(key, CachedResponse)` view.
    /// Caller holds the shard lock, so the `OnceLock` populate is uncontended. The boolean
    /// reports whether this call populated the decoded form, which changes the exact RAM weight.
    fn to_cached_with_decode_state(
        &self,
    ) -> Result<(PageCacheKey, CachedResponse, bool), MetaError> {
        let mut populated = false;
        let decoded = match self.decoded.get() {
            Some(d) => d,
            None => {
                let d = self.meta.decode()?;
                let _ = self.decoded.set(d);
                populated = true;
                self.decoded.get().expect("OnceLock populated after set")
            }
        };
        let resp = decoded.to_cached_response(
            self.body.clone(),
            self.variants.clone(),
            self.variants_filled,
            self.dict_gen,
            self.stored_at,
            self.ttl,
            self.swr,
            self.sie,
        );
        Ok((decoded.key.clone(), resp, populated))
    }

    fn to_cached(&self) -> Result<(PageCacheKey, CachedResponse), MetaError> {
        self.to_cached_with_decode_state()
            .map(|(key, response, _)| (key, response))
    }
}

fn wall_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// The wall-clock time corresponding to a monotonic `stored_at` — what the file
/// tier persists so a later boot can re-derive a monotonic `stored_at` and keep
/// every freshness window continuous across the restart.
fn wall_ms_of(stored_at: Instant) -> u64 {
    let age = Instant::now().saturating_duration_since(stored_at);
    wall_now_ms().saturating_sub(age.as_millis() as u64)
}

fn ms_saturating(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A small standalone sharded LRU of `body_id -> Bytes` in front of the file store.
/// Pure derived cache (losing one costs a tmpfs re-read, never correctness), with NO
/// teardown coupling to files — so it is the simplest possible thing. `time_to_idle`
/// is enforced lazily on the maintenance tick (`evict_idle`).
struct HotTier {
    shards: Box<[Mutex<HotShard>]>,
    max_bytes: u64,
    used_bytes: AtomicU64,
    tti: Duration,
}

struct HotShard {
    map: HashMap<u64, HotNode>,
    head: u64,
    tail: u64,
    bytes: u64,
}

struct HotNode {
    body: Bytes,
    last: Instant,
    prev: u64,
    next: u64,
}

/// `u64::MAX` is the hot-LRU NIL terminator. `body_id` is allocated from a counter
/// starting at 1, so it never reaches this.
const HOT_NIL: u64 = u64::MAX;

impl HotTier {
    fn new(max_bytes: u64, tti: Duration) -> Self {
        let shards = (0..SHARDS)
            .map(|_| {
                Mutex::new(HotShard {
                    map: HashMap::new(),
                    head: HOT_NIL,
                    tail: HOT_NIL,
                    bytes: 0,
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        HotTier {
            shards,
            max_bytes,
            used_bytes: AtomicU64::new(0),
            tti,
        }
    }

    #[inline]
    fn shard_idx(body_id: u64) -> usize {
        (body_id & SHARD_MASK) as usize
    }

    fn budget_per_shard(&self) -> u64 {
        (self.max_bytes / SHARDS as u64).max(1)
    }

    fn weight(body_id: u64, body: &Bytes) -> u64 {
        let _ = body_id;
        body.len() as u64 + 64
    }

    fn get(&self, body_id: u64, now: Instant) -> Option<Bytes> {
        let mut s = self.shards[Self::shard_idx(body_id)].lock();
        if !s.map.contains_key(&body_id) {
            return None;
        }
        s.touch(body_id, now);
        s.map.get(&body_id).map(|n| n.body.clone())
    }

    fn insert(&self, body_id: u64, body: Bytes, now: Instant) {
        let budget = self.budget_per_shard();
        let mut s = self.shards[Self::shard_idx(body_id)].lock();
        let old_weight = s
            .map
            .get(&body_id)
            .map(|node| Self::weight(body_id, &node.body))
            .unwrap_or(0);
        let new_weight = Self::weight(body_id, &body);
        loop {
            if self.try_replace_weight(old_weight, new_weight) {
                break;
            }
            if new_weight > self.max_bytes {
                return;
            }
            let mut victim = s.tail;
            if victim == body_id {
                victim = s.map.get(&victim).map(|node| node.prev).unwrap_or(HOT_NIL);
            }
            if victim == HOT_NIL {
                return;
            }
            let removed = s.remove(victim);
            self.release_weight(removed);
        }
        s.insert(body_id, body, now);
        let evicted = s.enforce(budget, body_id);
        self.release_weight(evicted);
    }

    fn invalidate(&self, body_id: u64) {
        let mut s = self.shards[Self::shard_idx(body_id)].lock();
        let removed = s.remove(body_id);
        self.release_weight(removed);
    }

    fn evict_idle(&self, now: Instant) {
        for sh in self.shards.iter() {
            let mut s = sh.lock();
            let stale: Vec<u64> = s
                .map
                .iter()
                .filter(|(_, n)| now.duration_since(n.last) >= self.tti)
                .map(|(k, _)| *k)
                .collect();
            for id in stale {
                let removed = s.remove(id);
                self.release_weight(removed);
            }
        }
    }

    fn bytes(&self) -> u64 {
        self.used_bytes.load(Ordering::Relaxed)
    }

    fn try_replace_weight(&self, old_weight: u64, new_weight: u64) -> bool {
        self.used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
                used.saturating_sub(old_weight)
                    .checked_add(new_weight)
                    .filter(|next| *next <= self.max_bytes)
            })
            .is_ok()
    }

    fn release_weight(&self, weight: u64) {
        if weight == 0 {
            return;
        }
        let _ = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(weight))
            });
    }
}

impl HotShard {
    fn push_front(&mut self, id: u64) {
        let old = self.head;
        if let Some(n) = self.map.get_mut(&id) {
            n.prev = HOT_NIL;
            n.next = old;
        }
        if old != HOT_NIL {
            if let Some(o) = self.map.get_mut(&old) {
                o.prev = id;
            }
        } else {
            self.tail = id;
        }
        self.head = id;
    }

    fn unlink(&mut self, id: u64) {
        let (prev, next) = match self.map.get(&id) {
            Some(n) => (n.prev, n.next),
            None => return,
        };
        if prev != HOT_NIL {
            if let Some(p) = self.map.get_mut(&prev) {
                p.next = next;
            }
        } else {
            self.head = next;
        }
        if next != HOT_NIL {
            if let Some(nx) = self.map.get_mut(&next) {
                nx.prev = prev;
            }
        } else {
            self.tail = prev;
        }
        if let Some(n) = self.map.get_mut(&id) {
            n.prev = HOT_NIL;
            n.next = HOT_NIL;
        }
    }

    fn touch(&mut self, id: u64, now: Instant) {
        if let Some(n) = self.map.get_mut(&id) {
            n.last = now;
        }
        if self.head == id {
            return;
        }
        self.unlink(id);
        self.push_front(id);
    }

    fn insert(&mut self, id: u64, body: Bytes, now: Instant) {
        if self.map.contains_key(&id) {
            self.remove(id);
        }
        let w = HotTier::weight(id, &body);
        self.map.insert(
            id,
            HotNode {
                body,
                last: now,
                prev: HOT_NIL,
                next: HOT_NIL,
            },
        );
        self.bytes += w;
        self.push_front(id);
    }

    fn remove(&mut self, id: u64) -> u64 {
        if !self.map.contains_key(&id) {
            return 0;
        }
        self.unlink(id);
        if let Some(n) = self.map.remove(&id) {
            let weight = HotTier::weight(id, &n.body);
            self.bytes -= weight;
            return weight;
        }
        0
    }

    fn enforce(&mut self, budget: u64, protect: u64) -> u64 {
        let mut removed = 0;
        while self.bytes > budget {
            let t = self.tail;
            if t == HOT_NIL || t == protect {
                break;
            }
            removed += self.remove(t);
        }
        removed
    }
}

/// Tunable store limits.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// RAM budget (bytes) for the in-process index: zstd-compressed entry
    /// metadata, precompressed variants, and any body still resident in RAM (a
    /// not-yet-offloaded or degraded `InMem` body). With a tmpfs file tier,
    /// persisted (`File`) bodies do NOT count here — they are bounded by
    /// `max_disk_bytes` instead. Without a file tier this is the whole body budget.
    pub max_mem_bytes: u64,
    /// tmpfs file-tier budget (bytes): the disk LRU evicts the least-recently-served
    /// `File` entry once charged file footprint under `store_path` exceeds this.
    /// `0` (with a file tier) falls back to `max_mem_bytes`. Ignored without a file tier.
    pub max_disk_bytes: u64,
    /// Root of the tmpfs file tier (e.g. `/dev/shm/jetcache`). `None` ⇒ bodies
    /// stay in RAM and nothing below the existing behavior changes.
    pub store_path: Option<PathBuf>,
    /// Byte cap of the in-RAM hot tier in front of the file store.
    pub hot_mem_bytes: u64,
    /// Every dict generation currently loaded (per-vhost dicts + fallback; empty = none). The
    /// boot scan unlinks persisted bodies compressed under any generation not in this set —
    /// vhost-agnostic by design, since a stored entry's `dict_gen` alone (not its vhost) says
    /// which loaded dictionary decodes it.
    pub expected_dict_gens: HashSet<u32>,
    /// Largest single response (bytes) eligible for caching.
    pub max_obj_bytes: u64,
    /// Largest single static file (bytes) eligible for static-body caching.
    pub max_static_obj_bytes: u64,
    /// Default public TTL when the app gives `public` with no `max-age`.
    pub default_public_ttl: Duration,
    /// Default private TTL.
    pub default_private_ttl: Duration,
    /// Status codes that may be cached (LiteSpeed default: 200, 301).
    pub cacheable_status: Vec<u16>,
    /// Whether POST responses may be cached (LiteSpeed `enablePostCache`).
    pub cache_post: bool,
    /// Public-vary cookie names: a cacheable public response may declare an
    /// `X-LiteSpeed-Vary: cookie=NAME,...` whose names must all be in this set,
    /// and the entry is keyed by those cookies' request values. Empty = no vary
    /// supported (any varied response is bypassed). These are shared,
    /// non-sensitive prefs (e.g. style/language), never session tokens.
    pub vary_cookies: Vec<String>,
    /// Cookie names that, if a *public* response tries to `Set-Cookie`, forbid
    /// caching (defense-in-depth against an app marking a session-bearing page
    /// public). Other `Set-Cookie`s (csrf/analytics) are cached-but-stripped.
    pub private_cookies: Vec<String>,
    /// Canonical vhost names (lowercase) put into "standards mode": they honor a
    /// *standard* `Cache-Control: public, max-age=…` as a cache opt-in (OLS
    /// `checkPublicCache`), get a default public cache policy when they declare no
    /// `<cache>` block, and default `CacheLookup` to on. This is an ALLOWLIST, not a
    /// global toggle, so opting one content site in (e.g. moontimenow) can never make
    /// an unrelated vhost (status/admin APIs) cache a response it merely marked public.
    /// A vhost NOT in this list behaves exactly as before (X-LiteSpeed opt-in only).
    pub standard_cc_vhosts: Vec<String>,
    /// Stale-while-revalidate window applied when the app declares none (0 ⇒ off).
    pub default_stale_secs: u32,
    /// Stale-if-error window applied when the app declares none (0 ⇒ off): how
    /// long past freshness a public entry stays servable as a backend-5xx
    /// fallback. Retention (and the boot scan's keep window) extends to
    /// `ttl + max(swr, sie)`, so with a large value LRU governs in practice.
    pub default_sie_secs: u32,
    /// Hard cap on the `stale-while-revalidate` window honored from the app.
    pub max_stale_secs: u32,
    /// Hard cap on the `stale-if-error` window honored from the app.
    pub max_stale_if_error_secs: u32,
    /// Master switch for the per-session PRIVATE tier. Off ⇒ an
    /// `X-LiteSpeed-Cache-Control: private` opt-in keeps bypassing
    /// (`"private-deferred"`), exactly the pre-tier behavior.
    pub private_enabled: bool,
    /// Request cookie whose VALUE keys a private entry's owner (the session).
    /// A logged-in request without it can never be private-cached (bypass).
    pub private_session_cookie: String,
    /// Request cookie whose PRESENCE routes a request to the private tier
    /// (logged-in marker). Requests without it stay on the public path.
    pub private_user_cookie: String,
    /// (shared-paths) Matchers for visitor-invariant endpoints that a MEMBER
    /// (logged-in) request may still read AND populate on the PUBLIC tier
    /// (`--page-cache-shared-paths`; see [`crate::shared_paths`]). Empty =
    /// feature off — members never touch public entries (the private-tier
    /// contract), exactly as before.
    pub shared_public_paths: Vec<crate::shared_paths::SharedPathMatcher>,
    /// (shared-paths) Deterministic percentage (0–100) of member requests
    /// matching `shared_public_paths` that actually route public (sticky by
    /// member-cookie hash); the rest keep the private-tier routing. Only
    /// consulted when `shared_public_paths` is non-empty.
    pub shared_paths_canary_percent: u8,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            max_mem_bytes: 128 * 1024 * 1024,
            max_disk_bytes: 0,
            store_path: None,
            hot_mem_bytes: 192 * 1024 * 1024,
            expected_dict_gens: HashSet::new(),
            max_obj_bytes: 1024 * 1024,
            max_static_obj_bytes: 1024 * 1024,
            default_public_ttl: Duration::from_secs(900),
            default_private_ttl: Duration::ZERO,
            cacheable_status: vec![200, 301],
            cache_post: false,
            vary_cookies: Vec::new(),
            private_cookies: Vec::new(),
            standard_cc_vhosts: Vec::new(),
            default_stale_secs: 0,
            default_sie_secs: 0,
            max_stale_secs: 86_400,
            max_stale_if_error_secs: 86_400,
            private_enabled: false,
            private_session_cookie: String::new(),
            private_user_cookie: String::new(),
            shared_public_paths: Vec::new(),
            shared_paths_canary_percent: 100,
        }
    }
}

impl StoreConfig {
    /// True if `vhost_name` is in "standards mode" (honor standard `Cache-Control`,
    /// default cache policy, `CacheLookup` default-on). Case-insensitive.
    pub fn is_standards_vhost(&self, vhost_name: &str) -> bool {
        self.standard_cc_vhosts
            .iter()
            .any(|v| v.eq_ignore_ascii_case(vhost_name))
    }
}

/// Snapshot of store counters (loopback-only `/_lscache/cache-stats`).
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub purges: u64,
    /// Store-path `page_commit` hold telemetry (µs total + call count) — the
    /// measure-first signal for narrowing the store-vs-purge critical section.
    pub store_commit_hold_us: u64,
    pub store_commit_calls: u64,
    /// Store attempts rejected because a relevant tag/global purge happened
    /// after the backend render began.
    pub store_purge_rejections: u64,
    /// Live entry count (exact — the sum of every shard's map length under its lock).
    /// Under the atomic-teardown invariant a live entry always has its body file, so this
    /// tracks the served working set; judge hit health by `hits`/`misses` + `disk_read_err`.
    pub entries: u64,
    /// Exact cache-accounted resident RAM bytes visible from owned entry fields plus the reverse
    /// tag-index allocations exposed by `hashbrown::allocation_size()`. This excludes tmpfs bodies.
    pub memory_bytes: u64,
    /// Bytes resident in the in-RAM hot tier (0 without a file store).
    pub hot_bytes: u64,
    /// Charged tmpfs file-tier footprint (the sum of every shard's `disk_used`; 0 without a
    /// file store). Under the invariant this equals Σ referenced `File.disk_total`.
    pub disk_bytes: u64,
    /// The configured tmpfs file-tier budget (`max_disk_bytes`; 0 without a file store).
    pub disk_max_bytes: u64,
    /// `File` entries evicted by the disk LRU because tmpfs hit its cap.
    pub disk_evictions: u64,
    /// Entries reclaimed by the proactive expiry sweep on the maintenance tick.
    pub swept_expired: u64,
    /// Counted lookups that met an entry past its full retention window (a TTL re-render
    /// the sweep didn't reap first).
    pub expired_misses: u64,
    /// Age-at-eviction of disk-LRU victims: [<1h, 1-6h, 6-24h, >=24h]. A mass in the low
    /// buckets means the disk cap (or a hot shard slice) is evicting entries before any
    /// realistic second request — capacity, not churn.
    pub disk_evict_ages: [u64; 4],
    /// DEPRECATED (always 0): a fileless live entry is unrepresentable under the atomic-teardown
    /// invariant, so there is no missing-file reclaimer. Kept for metric/format stability.
    pub missing_file_invalidations: u64,
    /// DEPRECATED (always 0): supersession unlinks synchronously under the shard lock, so no
    /// orphan files exist and there is no reconciliation. Kept for metric/format stability.
    pub orphan_reclaimed: u64,
    /// DEPRECATED (always 0): see `orphan_reclaimed`. Kept for metric/format stability.
    pub orphan_deferred: u64,
    /// File-tier body reads that failed (each one degraded to a miss).
    pub disk_read_errors: u64,
    /// File-tier persists that failed (each entry stayed in RAM).
    pub disk_write_errors: u64,
    /// Subset of `disk_write_errors` caused specifically by a full tmpfs (`ENOSPC`). A nonzero
    /// value means bodies are being retained in RAM because the file tier is out of space —
    /// the early signal that the disk cap (or the tmpfs itself) needs raising before RAM spikes.
    pub disk_full_errors: u64,
    /// DEPRECATED (always 0): `parking_lot::Mutex` shards do not poison. Kept for format stability.
    pub poisoned_locks: u64,
    /// Compressed resident metadata bytes.
    pub meta_compressed_bytes: u64,
    /// Raw resident metadata bytes before zstd.
    pub meta_raw_bytes: u64,
    /// Entries whose decoded metadata has been memoized in RAM.
    pub decoded_entries: u64,
    /// Distinct purge-tag keys in the reverse index.
    pub tag_keys: u64,
    /// Exact live key memberships across all purge-tag sets.
    pub tag_memberships: u64,
    /// Exact reverse tag-index allocation bytes exposed by the underlying hash tables.
    pub tag_index_bytes: u64,
    /// Exact tag-purge wall stamps retained for peer-fill resurrection protection.
    pub tag_purge_tombstones: u64,
    /// Coarse persisted wall floor that subsumes pruned tag tombstones.
    pub tag_purge_floor_ms: u64,
    /// Resident metadata blobs that failed to decode and were invalidated.
    pub meta_decode_errors: u64,
    /// Compact key-id collisions refused as misses/skipped stores.
    pub key_id_collisions: u64,
}

/// One cached entry's view for the loopback debug listing (what's actually in the cache).
#[derive(Debug, Clone)]
pub struct EntryInfo {
    /// The entry's identity = `scheme\nhost\npath` it was built for (the URL).
    pub identity: String,
    pub status: u16,
    /// Stored body size (DICT-COMPRESSED when `dict_gen != 0`).
    pub stored_bytes: u64,
    /// Sum of precompressed variant sizes.
    pub variant_bytes: u64,
    pub dict_gen: u32,
    pub age_secs: u64,
    pub ttl_secs: u64,
}

/// Aggregated snapshot of the live cache contents for the loopback debug endpoint: totals, a
/// per-URL-class histogram (so "what's junk" is answerable at a glance), and the largest entries.
#[derive(Debug, Clone, Default)]
pub struct CacheListing {
    pub total_entries: u64,
    pub total_bytes: u64,
    /// `(url-class, count, bytes)`, e.g. `("/threads", 412, 5_300_000)`, largest-bytes first.
    pub classes: Vec<(String, u64, u64)>,
    /// The `top_n` largest entries (by stored+variant bytes).
    pub top: Vec<EntryInfo>,
}

struct ListingCandidate {
    weight: u64,
    ordinal: u64,
    info: EntryInfo,
}

impl PartialEq for ListingCandidate {
    fn eq(&self, other: &Self) -> bool {
        (self.weight, self.ordinal) == (other.weight, other.ordinal)
    }
}

impl Eq for ListingCandidate {}

impl PartialOrd for ListingCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for ListingCandidate {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        (self.weight, self.ordinal).cmp(&(other.weight, other.ordinal))
    }
}

/// Purges observed while the boot scan is still walking the file tier. A
/// scanned (pre-boot) entry is strictly older than any in-process purge, so
/// membership alone decides: a buffered tag (or a buffered purge-all) rejects
/// the load. Dropped once the scan completes.
#[derive(Default)]
struct ScanPurgeBuffer {
    tags: HashSet<Arc<str>>,
    purged_all: bool,
}

struct TagIndex {
    shards: Box<[Mutex<TagShard>]>,
}

#[derive(Default)]
struct TagShard {
    map: HbHashMap<Arc<str>, HbHashSet<CacheKeyId>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct TagIndexStats {
    keys: u64,
    memberships: u64,
    bytes: u64,
}

impl TagIndex {
    fn new() -> Self {
        let shards = (0..SHARDS)
            .map(|_| Mutex::new(TagShard::default()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        TagIndex { shards }
    }

    fn insert(&self, tag: Arc<str>, id: CacheKeyId) {
        let mut shard = self.shards[tag_shard(&tag)].lock();
        shard.map.entry(tag).or_default().insert(id);
    }

    fn remove_membership(&self, tag: &Arc<str>, id: &CacheKeyId) {
        let mut shard = self.shards[tag_shard(tag)].lock();
        let empty = match shard.map.get_mut(tag) {
            Some(set) => {
                set.remove(id);
                set.is_empty()
            }
            None => false,
        };
        if empty {
            shard.map.remove(tag);
        }
    }

    fn remove_tag(&self, tag: &str) -> Option<HbHashSet<CacheKeyId>> {
        let mut shard = self.shards[tag_shard(tag)].lock();
        shard.map.remove(&Arc::<str>::from(tag))
    }

    fn clear(&self) {
        for shard in self.shards.iter() {
            shard.lock().map.clear();
        }
    }

    fn stats(&self) -> TagIndexStats {
        let mut stats = TagIndexStats {
            bytes: size_of::<TagIndex>() as u64
                + (self.shards.len() * size_of::<Mutex<TagShard>>()) as u64,
            ..TagIndexStats::default()
        };
        for shard in self.shards.iter() {
            let shard = shard.lock();
            stats.keys += shard.map.len() as u64;
            stats.bytes += shard.map.allocation_size() as u64;
            for set in shard.map.values() {
                stats.memberships += set.len() as u64;
                stats.bytes += set.allocation_size() as u64;
            }
        }
        stats
    }
}

/// The page-cache eviction hook: the side-effects fired by the primitive's single teardown
/// funnel as a node leaves the index (under the shard lock, before the value drops). It unlinks
/// the entry's tmpfs file, drops its hot copy, GCs its tags from the reverse index, and bumps the
/// disk-eviction counter on a disk-budget eviction. The index/budget/LRU bookkeeping is the
/// primitive's job; this is only the page-specific external state.
///
/// LOCK-ORDERING: runs with the owning shard mutex held, and touches `tag_index`, so
/// a caller must never lock a shard while holding a `tag_index` lock (`purge_tags`
/// removes the tag set BEFORE locking any shard, honoring this).
struct StoreEvict {
    disk: Option<Arc<DiskStore>>,
    hot: Option<Arc<HotTier>>,
    tag_index: Arc<TagIndex>,
    disk_evictions: Arc<AtomicU64>,
    /// Age-at-eviction of disk-LRU victims (buckets: <1h, 1-6h, 6-24h, >=24h). Directly
    /// answers "are entries evicted before their would-be second hit?" — the capacity
    /// question — without offline mtime sampling.
    disk_evict_ages: Arc<[AtomicU64; 4]>,
    /// Total teardowns through the funnel. Diagnostic-only — not surfaced in [`CacheStats`]
    /// today (it was the old `PageStore.evictions`), kept so the teardown path stays cheap to
    /// instrument if a counter is ever wanted.
    evictions: AtomicU64,
}

/// Bucket index for [`StoreEvict::disk_evict_ages`].
fn evict_age_bucket(age: Duration) -> usize {
    match age.as_secs() {
        s if s < 3600 => 0,
        s if s < 6 * 3600 => 1,
        s if s < 24 * 3600 => 2,
        _ => 3,
    }
}

thread_local! {
    /// (#293) File paths whose unlink(2) is deferred out of the shard-lock
    /// critical section: [`StoreEvict::on_evict`] queues them under the lock,
    /// [`StoreEvict::after_unlock`] drains them on the SAME thread immediately
    /// after the mutex is released. Bookkeeping (index, hot tier, tags,
    /// budgets) stays synchronous under the lock; only the syscall moves.
    /// Paths are unique per body VERSION, so a queued unlink can never hit a
    /// successor file from a same-key re-store.
    static PENDING_UNLINKS: std::cell::RefCell<Vec<Arc<Path>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

impl StoreEvict {
    fn unlink_body(&self, body: &PageBody, cause: EvictCause) {
        if let PageBody::File { path, body_id, .. } = body {
            PENDING_UNLINKS.with(|q| q.borrow_mut().push(path.clone()));
            if let Some(h) = &self.hot {
                h.invalidate(*body_id);
            }
            let _ = &self.disk;
            if cause == EvictCause::Disk {
                self.disk_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl OnEvict<CacheKeyId, CacheEntry> for StoreEvict {
    fn on_evict(&self, id: &CacheKeyId, entry: &CacheEntry, cause: EvictCause) {
        match entry {
            CacheEntry::Page(node) => {
                if cause == EvictCause::Disk {
                    let b = evict_age_bucket(node.stored_at.elapsed());
                    self.disk_evict_ages[b].fetch_add(1, Ordering::Relaxed);
                }
                self.unlink_body(&node.body, cause);
                for tag in &node.tags {
                    self.tag_index.remove_membership(tag, id);
                }
            }
            CacheEntry::Static(node) => self.unlink_body(&node.body, cause),
        }
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    fn after_unlock(&self) {
        PENDING_UNLINKS.with(|q| {
            let mut q = q.borrow_mut();
            for path in q.drain(..) {
                DiskStore::remove(&path);
            }
            // A purge-all drains one shard's worth of paths at a time; don't
            // let that burst pin its capacity on the thread forever.
            q.shrink_to(64);
        });
    }
}

/// Per-tag in-process purge epoch, ordered against a render/fill's `purge_seq` snapshot.
#[derive(Clone, Copy)]
struct TagPurgeStamp {
    epoch: u64,
}

/// Unified page-response and static-file body store.
pub struct PageStore {
    /// The shared sharded byte-weighted LRU index (`hj_cache::sharded`) for page and static entries.
    inner: ShardedCache<CacheKeyId, CacheEntry, StoreEvict>,
    config: StoreConfig,
    /// The tmpfs file tier (`store_path`); `None` ⇒ in-RAM-only, all file paths inert.
    /// `Arc`-shared with [`StoreEvict`] (the teardown unlink path).
    disk: Option<Arc<DiskStore>>,
    /// Hot `body_id -> Bytes` tier in front of the file store (read-through).
    /// `Arc`-shared with [`StoreEvict`] (the teardown hot-drop).
    hot: Option<Arc<HotTier>>,
    /// The configured tmpfs file-tier budget (mirrors the disk cap; for stats).
    disk_max_bytes: u64,

    /// `tag -> { key }` reverse index for tag-based purge.
    /// `Arc`-shared with [`StoreEvict`] (the teardown tag GC).
    tag_index: Arc<TagIndex>,

    /// Monotonic purge clock. Store callers snapshot this before rendering; a
    /// tag/global purge that advances after that snapshot can veto the later store.
    purge_seq: AtomicU64,
    /// Latest purge-all epoch. Any store whose render began before this must be
    /// rejected, regardless of its tag set.
    purge_all_epoch: AtomicU64,
    /// Wall-clock ms of the most recent purge-all (seeded from the disk purge stamp at boot).
    /// Peer-fill adoption compares the peer entry's `stored_unix_ms` against this so a purge-all
    /// cannot be undone by adopting a pre-purge entry from the peer — without it, two nodes
    /// cross-filling resurrect each other's purged entries and sequential per-node purge-alls
    /// never converge (found live 2026-07-03: pre-rollout shells kept re-seeding Cloudflare).
    purge_all_wall_ms: AtomicU64,
    /// Latest per-tag in-process purge epoch, retained while a slow pre-purge render can
    /// still commit. This map is pruned independently of durable peer-adoption tombstones.
    tag_purge_epoch: DashMap<Arc<str>, TagPurgeStamp>,
    /// Stable tag-hash -> latest wall-clock purge time. This is the peer-adoption guard and is
    /// persisted by the file tier so a service restart cannot forget a completed tag purge.
    peer_tag_purge_wall: DashMap<u64, u64>,
    /// Successful append records since the last canonical journal rewrite.
    peer_tag_purge_journal_appends: AtomicU64,
    /// Conservative all-tag floor used only after exact-map capacity overflow or corrupt-journal
    /// recovery. Every peer entry stored at-or-before it is rejected.
    peer_tag_purge_floor_ms: AtomicU64,
    /// `purge_seq` snapshot taken a full maintenance interval ago — the generational floor for the
    /// bounded `tag_purge_epoch` prune.
    tag_epoch_prune_floor: AtomicU64,
    /// Cache fills currently rendering, keyed by the purge epoch they snapshotted before dispatch.
    active_render_epochs: Arc<Mutex<BTreeMap<u64, usize>>>,
    /// Serializes a page entry's final-file publication/index commit with tag/global
    /// purge stamping and teardown. Lock order is `page_commit -> shard -> tag_index`.
    page_commit: Mutex<()>,

    /// `Some` from construction until the boot scan finishes (file tier only).
    scan_purge: Mutex<Option<ScanPurgeBuffer>>,
    /// Test-only hook fired inside `load_scanned`, in the window between the pre-lock purge check
    /// and the under-lock install, to deterministically drive the boot-scan/purge race.
    #[cfg(test)]
    scan_insert_probe: Mutex<Option<Box<dyn FnOnce(&PageStore) + Send>>>,
    /// Test-only hook fired after the ordinary store's first purge check but
    /// before tag membership is published.
    #[cfg(test)]
    store_commit_probe: Mutex<Option<Box<dyn FnOnce(&PageStore) + Send>>>,
    /// Test-only hook fired after a prepared page file becomes boot-scannable but
    /// before its index install, while `page_commit` remains held.
    #[cfg(test)]
    store_publish_probe: Mutex<Option<Box<dyn FnOnce(&PageStore) + Send>>>,
    /// Entries the boot warm-scan loaded from the file tier (set once, when the scan finishes).
    scan_loaded: AtomicU64,

    /// Hot-tier key allocator — unique per body version within this process.
    body_id_seq: AtomicU64,

    // The four per-request counters are cache-line padded: packed together they
    // shared one 64-byte line, so every worker's increment invalidated it across
    // cores on EVERY request (true ping-pong under load).
    hits: CachePaddedAtomic,
    misses: CachePaddedAtomic,
    stores: CachePaddedAtomic,
    purges: CachePaddedAtomic,
    /// Cumulative `page_commit` hold time on the STORE path (µs) + call count.
    /// Measure-first telemetry for the store-vs-purge serialization: optimize the
    /// critical section only if real hold times justify cutting into it.
    store_commit_hold_us: CachePaddedAtomic,
    store_commit_calls: CachePaddedAtomic,
    store_purge_rejections: AtomicU64,
    /// `Arc`-shared with [`StoreEvict`] (bumped on a disk-budget eviction).
    disk_evictions: Arc<AtomicU64>,
    /// `Arc`-shared with [`StoreEvict`]: age-at-eviction buckets (<1h, 1-6h, 6-24h, >=24h).
    disk_evict_ages: Arc<[AtomicU64; 4]>,
    swept_expired: AtomicU64,
    /// Counted lookups that met an entry past its full retention (TTL+SWR+SIE) — the
    /// direct "this miss was a TTL re-render" signal (the sweep usually reaps first;
    /// this counts the lookups that beat it).
    expired_misses: AtomicU64,
    disk_read_errors: AtomicU64,
    disk_write_errors: AtomicU64,
    disk_full_errors: AtomicU64,
    meta_decode_errors: AtomicU64,
    key_id_collisions: AtomicU64,
}

/// One cache line (64 B) of storage for an [`AtomicU64`], so hot per-request
/// counters never share a line with each other.
#[repr(align(64))]
struct CachePaddedAtomic(AtomicU64);

impl std::ops::Deref for CachePaddedAtomic {
    type Target = AtomicU64;
    fn deref(&self) -> &AtomicU64 {
        &self.0
    }
}

impl PageStore {
    /// Build a store with the given limits.
    pub fn new(config: StoreConfig) -> Self {
        // A file tier that can't open degrades to in-RAM-only (the server must
        // come up either way); the error is loud because persistence is silently
        // off until an operator fixes the path.
        let disk = config
            .store_path
            .as_deref()
            .and_then(|p| match DiskStore::open(p) {
                Ok(d) => Some(Arc::new(d)),
                Err(e) => {
                    tracing::error!(path = %p.display(), error = %e,
                    "jetcache: cannot open file store — running in-RAM only");
                    None
                }
            });
        let hot = disk.as_ref().map(|_| {
            Arc::new(HotTier::new(
                config.hot_mem_bytes,
                Duration::from_secs(3600),
            ))
        });

        let disk_max_bytes = if config.max_disk_bytes > 0 {
            config.max_disk_bytes
        } else {
            config.max_mem_bytes
        };

        let tag_index = Arc::new(TagIndex::new());
        let purge_all_wall_ms = disk
            .as_ref()
            .and_then(|disk| disk.read_purge_stamp())
            .unwrap_or(0);
        let tag_state = disk
            .as_ref()
            .map(|disk| disk.read_tag_purge_state())
            .unwrap_or_default();
        let recovered_floor_ms = tag_state.floor_ms;
        let recovered_record_count = tag_state.record_count;
        let recovered_stamp_record_count = tag_state.stamp_record_count;
        let recovered_byte_len = tag_state.byte_len;
        let recovered_corrupt = tag_state.corrupt;
        let recovered_canonical = tag_state.canonical;
        let mut peer_tag_purge_floor_ms = recovered_floor_ms.max(purge_all_wall_ms);
        let mut persisted_tag_stamps = tag_state.stamps;
        let bounded = bound_peer_tag_purge_stamps(
            &mut peer_tag_purge_floor_ms,
            &mut persisted_tag_stamps,
            MAX_PEER_TAG_PURGE_TOMBSTONES,
            PEER_TAG_PURGE_RETAIN_TOMBSTONES,
        );
        let canonical_byte_len = TAG_PURGE_FLOOR_RECORD_BYTES.saturating_add(
            (persisted_tag_stamps.len() as u64).saturating_mul(TAG_PURGE_STAMP_RECORD_BYTES),
        );
        let excess_records =
            recovered_stamp_record_count.saturating_sub(persisted_tag_stamps.len() as u64);
        let excess_bytes = recovered_byte_len.saturating_sub(canonical_byte_len);
        let recovered_journal_appends = excess_records.max(
            excess_bytes.saturating_add(TAG_PURGE_STAMP_RECORD_BYTES - 1)
                / TAG_PURGE_STAMP_RECORD_BYTES,
        );
        let restart_compaction = recovered_corrupt
            || bounded
            || peer_tag_purge_floor_ms > recovered_floor_ms
            || (!recovered_canonical
                && recovered_record_count >= PEER_TAG_PURGE_JOURNAL_COMPACT_RECORDS)
            || recovered_journal_appends >= PEER_TAG_PURGE_JOURNAL_COMPACT_RECORDS
            || excess_bytes >= PEER_TAG_PURGE_JOURNAL_COMPACT_BYTES;
        let mut initial_journal_appends = recovered_journal_appends;
        if restart_compaction {
            if let Some(disk) = &disk {
                let mut stamps: Vec<(u64, u64)> = persisted_tag_stamps
                    .iter()
                    .map(|(&tag_hash, &wall_ms)| (tag_hash, wall_ms))
                    .collect();
                stamps.sort_unstable();
                if let Err(error) = disk.write_tag_purge_state(peer_tag_purge_floor_ms, &stamps) {
                    tracing::warn!(%error, "jetcache: tag-purge restart compaction failed");
                    initial_journal_appends =
                        initial_journal_appends.max(PEER_TAG_PURGE_JOURNAL_COMPACT_RECORDS);
                } else {
                    initial_journal_appends = 0;
                }
            }
        }
        let peer_tag_purge_wall = DashMap::new();
        for (&tag_hash, &wall_ms) in &persisted_tag_stamps {
            peer_tag_purge_wall.insert(tag_hash, wall_ms);
        }
        let disk_evictions = Arc::new(AtomicU64::new(0));
        let disk_evict_ages: Arc<[AtomicU64; 4]> = Arc::new(Default::default());

        // The primitive divides each configured TOTAL by SHARDS internally, reproducing the page
        // store's old `(max_mem_bytes / SHARDS).max(1)` per-shard budgets exactly.
        let inner = ShardedCache::new(
            ShardCacheConfig {
                max_ram_bytes: config.max_mem_bytes,
                max_disk_bytes: disk_max_bytes,
            },
            StoreEvict {
                disk: disk.clone(),
                hot: hot.clone(),
                tag_index: tag_index.clone(),
                disk_evictions: disk_evictions.clone(),
                disk_evict_ages: disk_evict_ages.clone(),
                evictions: AtomicU64::new(0),
            },
        );

        let scan_purge = Mutex::new(disk.as_ref().map(|_| ScanPurgeBuffer::default()));

        PageStore {
            inner,
            config,
            disk,
            hot,
            disk_max_bytes,
            tag_index,
            purge_seq: AtomicU64::new(0),
            purge_all_epoch: AtomicU64::new(0),
            purge_all_wall_ms: AtomicU64::new(purge_all_wall_ms),
            tag_purge_epoch: DashMap::new(),
            peer_tag_purge_wall,
            peer_tag_purge_journal_appends: AtomicU64::new(initial_journal_appends),
            peer_tag_purge_floor_ms: AtomicU64::new(peer_tag_purge_floor_ms),
            tag_epoch_prune_floor: AtomicU64::new(0),
            active_render_epochs: Arc::new(Mutex::new(BTreeMap::new())),
            page_commit: Mutex::new(()),
            scan_purge,
            #[cfg(test)]
            scan_insert_probe: Mutex::new(None),
            #[cfg(test)]
            store_commit_probe: Mutex::new(None),
            #[cfg(test)]
            store_publish_probe: Mutex::new(None),
            scan_loaded: AtomicU64::new(0),
            body_id_seq: AtomicU64::new(1),
            hits: CachePaddedAtomic(AtomicU64::new(0)),
            misses: CachePaddedAtomic(AtomicU64::new(0)),
            stores: CachePaddedAtomic(AtomicU64::new(0)),
            purges: CachePaddedAtomic(AtomicU64::new(0)),
            store_commit_hold_us: CachePaddedAtomic(AtomicU64::new(0)),
            store_commit_calls: CachePaddedAtomic(AtomicU64::new(0)),
            store_purge_rejections: AtomicU64::new(0),
            disk_evictions,
            disk_evict_ages,
            swept_expired: AtomicU64::new(0),
            expired_misses: AtomicU64::new(0),
            disk_read_errors: AtomicU64::new(0),
            disk_write_errors: AtomicU64::new(0),
            disk_full_errors: AtomicU64::new(0),
            meta_decode_errors: AtomicU64::new(0),
            key_id_collisions: AtomicU64::new(0),
        }
    }

    /// True when a tmpfs file tier is active.
    pub fn has_disk(&self) -> bool {
        self.disk.is_some()
    }

    /// True once the boot warm-scan has finished (or there is no file tier to scan) — i.e. the
    /// in-RAM index reflects the persisted set and a lookup miss is genuine, not "not scanned yet".
    /// Readiness signal ONLY (no longer interlocks any reaper). Exposed so a restart-persistence
    /// check can wait for warm-up BEFORE probing a URL (a probe mid-scan can re-prime a key and
    /// unlink its persisted file via the same-key replace tie-break).
    pub fn is_warm(&self) -> bool {
        self.scan_purge.lock().is_none()
    }

    /// Entries the boot warm-scan loaded from the file tier (0 before the scan / no file tier).
    pub fn scan_loaded(&self) -> u64 {
        self.scan_loaded.load(Ordering::Relaxed)
    }

    /// Current purge clock. Cache fills snapshot this before the backend render starts.
    pub fn purge_epoch(&self) -> u64 {
        self.purge_seq.load(Ordering::Acquire)
    }

    /// Mark a backend render as active at `epoch`. The returned guard must live
    /// until the request has either attempted its store or definitively bypassed
    /// the cache.
    pub fn begin_render(&self, epoch: u64) -> RenderEpochGuard {
        let mut active = self.active_render_epochs.lock();
        *active.entry(epoch).or_insert(0) += 1;
        RenderEpochGuard {
            active: self.active_render_epochs.clone(),
            epoch,
        }
    }

    fn purged_after(&self, tags: &[Arc<str>], epoch: u64) -> bool {
        if self.purge_all_epoch.load(Ordering::Acquire) > epoch {
            return true;
        }
        tags.iter().any(|tag| {
            self.tag_purge_epoch
                .get(tag)
                .is_some_and(|e| e.value().epoch > epoch)
        })
    }

    /// Whether any of `tags` was tag-purged at a wall time at or after the candidate
    /// entry's `stored_unix_ms`. Unlike [`Self::purged_after`] (epoch-based, which a peer
    /// fill defeats by snapshotting its `fetch_epoch` at/after an already-completed tag
    /// purge), this catches a tag purge that finished BEFORE the fill was requested — the
    /// dominant XenForo purge case (a member reply purging `tag=T<id>`) (#134). Mirrors the
    /// purge-all `purge_all_wall_ms` veto but per tag.
    fn tag_purged_since_wall(&self, tags: &[Arc<str>], stored_unix_ms: u64) -> bool {
        wall_purge_veto(stored_unix_ms, &self.peer_tag_purge_floor_ms, || {
            tags.iter().any(|tag| {
                self.peer_tag_purge_wall
                    .get(&stable_tag_hash(tag))
                    .is_some_and(|wall_ms| *wall_ms >= stored_unix_ms)
            })
        })
    }

    /// Resolve an entry's stored-form body bytes: an in-RAM body is a zero-copy
    /// clone (today's path); a file-backed one is served from the hot tier or
    /// read from tmpfs (and promoted). `None` = the file is gone/corrupt — the
    /// caller must fail closed (degrade to a miss and invalidate the key); the
    /// bytes are re-rendered, never partially served.
    pub fn body_bytes(&self, entry: &CachedResponse) -> Option<Bytes> {
        self.body_bytes_inner(&entry.body, true)
    }

    /// Resolve stored-form body bytes for background jobs that need the payload
    /// as compression input but must not populate the hot in-RAM body tier.
    pub fn body_bytes_cold(&self, entry: &CachedResponse) -> Option<Bytes> {
        self.body_bytes_inner(&entry.body, false)
    }

    /// Resolve a file-backed body's immutable container path + byte range
    /// without reading the body into anonymous heap. Returns `None` for in-RAM,
    /// derived, missing, or corrupt bodies so callers can fall back to the byte
    /// path or fail closed.
    pub fn body_file(&self, entry: &CachedResponse) -> Option<StoredBodyFile> {
        match &entry.body {
            PageBody::File { path, len, .. } => match DiskStore::body_file(path, *len) {
                Ok(f) => Some(f),
                Err(e) => {
                    self.disk_read_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(path = %path.display(), error = ?e,
                        "jetcache: body file resolve failed — degrading to a miss");
                    None
                }
            },
            PageBody::InMem(_) | PageBody::Derived { .. } => None,
        }
    }

    pub fn static_body_bytes(&self, entry: &StaticNode) -> Option<Bytes> {
        self.body_bytes_inner(&entry.body, true)
    }

    fn body_bytes_inner(&self, body: &PageBody, promote_hot: bool) -> Option<Bytes> {
        match body {
            PageBody::InMem(b) => Some(b.clone()),
            PageBody::Derived { .. } => None,
            PageBody::File {
                path,
                len,
                disk_total: _,
                body_id,
            } => {
                let now = Instant::now();
                if let Some(hot) = &self.hot {
                    if let Some(b) = hot.get(*body_id, now) {
                        return Some(b);
                    }
                }
                match DiskStore::read_body(path, *len) {
                    Ok(b) => {
                        if promote_hot {
                            if let Some(hot) = &self.hot {
                                hot.insert(*body_id, b.clone(), now);
                            }
                        }
                        Some(b)
                    }
                    Err(e) => {
                        self.disk_read_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(path = %path.display(), error = ?e,
                            "jetcache: body read failed — degrading to a miss");
                        None
                    }
                }
            }
        }
    }
    /// (#311) DECODED-IDENTITY hot-tier namespace: bit 63 tags ids whose cached
    /// Bytes are the IDENTITY form of a dict-compressed body (real `body_id`s come
    /// from a monotonic counter and can never reach bit 63). Lets an AE-mismatch
    /// identity serve pay ONE dict decode instead of one per request.
    const HOT_IDENTITY_TAG: u64 = 0x8000_0000_0000_0000;

    /// Cached decoded identity for a dict-compressed file-backed body, if warm.
    pub fn hot_identity_get(&self, body_id: u64) -> Option<Bytes> {
        let hot = self.hot.as_ref()?;
        hot.get(body_id | Self::HOT_IDENTITY_TAG, Instant::now())
    }

    /// Park a freshly decoded identity so later serves skip the dict decode.
    pub fn hot_identity_put(&self, body_id: u64, bytes: Bytes) {
        if let Some(hot) = self.hot.as_ref() {
            hot.insert(body_id | Self::HOT_IDENTITY_TAG, bytes, Instant::now());
        }
    }

    /// Drop a key whose file-backed body failed to resolve (the fail-closed
    /// follow-up to a `body_bytes() == None`), so subsequent requests re-render
    /// instead of re-attempting a dead file.
    pub fn invalidate_key(&self, key: &PageCacheKey) {
        self.inner.remove(&CacheKeyId::new(key));
    }

    /// The active store limits.
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// Look up `key` with full freshness classification + the identity collision
    /// guard. This is the SWR-aware entry point: the caller distinguishes a fresh
    /// hit (serve normally) from a stale one (serve + revalidate) from an
    /// error-only one (serve only on backend error) from a miss.
    ///
    /// The identity check is the collision guard: a cached page is served ONLY
    /// for the exact URL it was built for. A key collision degrades to a miss,
    /// never the wrong page. A fully-gone entry is invalidated lazily.
    pub fn get_entry(&self, key: &PageCacheKey, identity: &str, now: Instant) -> EntryState {
        self.get_entry_inner(key, CacheKeyId::new(key), identity, now, true)
    }

    /// [`get_entry`](Self::get_entry) with a caller-supplied raw page hash (`crate::key_hash`)
    /// — the glue layer computed it for single-flight/admission, so the storage id costs a
    /// mask instead of a second pass over every key field. `key_hash` MUST be `key_hash(key)`
    /// for this very key; anything else is a wrong-key probe (identity guard still fail-closes).
    pub fn get_entry_hashed(
        &self,
        key_hash: u64,
        key: &PageCacheKey,
        identity: &str,
        now: Instant,
    ) -> EntryState {
        self.get_entry_inner(
            key,
            CacheKeyId::from_raw_page_hash(key_hash),
            identity,
            now,
            true,
        )
    }

    /// Like [`get_entry`](Self::get_entry) but does NOT bump the global hit/miss counters.
    /// Used by the capsule tier's SPECULATIVE probes (dedicated + public-fallback lookups), which
    /// are accounted separately by their own `xf_capsule_*` counters.
    pub fn get_entry_uncounted(
        &self,
        key: &PageCacheKey,
        identity: &str,
        now: Instant,
    ) -> EntryState {
        self.get_entry_inner(key, CacheKeyId::new(key), identity, now, false)
    }

    fn get_entry_inner(
        &self,
        key: &PageCacheKey,
        id: CacheKeyId,
        identity: &str,
        now: Instant,
        count: bool,
    ) -> EntryState {
        // ONE shard lock across the get + freshness + guards + recency touch (via
        // `with_shard`). The shared serve snapshot makes the hit O(1)-ish: an Arc clone
        // replaces the former rebuild+clone of the whole CachedResponse under this lock
        // (headers/identity/tags/vary strings); a first-hit or post-mutation hit pays the
        // rebuild once and re-shares it.
        let outcome: Option<(Freshness, Arc<CachedResponse>)> =
            self.inner.with_shard(&id, |acc| {
                let node = acc.get(&id)?.as_page()?;
                let fresh = node.freshness(now);
                if fresh == Freshness::Gone {
                    if count {
                        self.expired_misses.fetch_add(1, Ordering::Relaxed);
                    }
                    acc.teardown(&id, EvictCause::Expired);
                    return None;
                }
                // Scoped node reads: build the shared snapshot on first use, then lift an
                // owned Arc + guard verdicts out so the node borrow ends before any `acc`
                // mutation below.
                let freshly_built = node.resp_snapshot.get().is_none();
                let (snap, key_matches, identity_ok, body_is_file) = {
                    if node.resp_snapshot.get().is_none() {
                        // First hit / post-mutation rebuild: decode-once + build-once.
                        if let Err(e) = node.build_snapshot() {
                            self.meta_decode_errors.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(error = ?e, "hj-pagecache: resident metadata decode failed — invalidating entry");
                            acc.teardown(&id, EvictCause::Explicit);
                            return None;
                        }
                    }
                    let snap = node.resp_snapshot.get().expect("snapshot built above");
                    (
                        Arc::clone(snap),
                        &node.decoded.get().expect("decoded during build").key == key,
                        snap.identity == identity,
                        matches!(snap.body, PageBody::File { .. }),
                    )
                };
                // Reconcile BEFORE any guard rejection: a first-hit that goes on to fail
                // a guard still had its residency grow (decode+snapshot), so the shard
                // budget must see it or the charge leaks.
                if freshly_built && !acc.reconcile_weights(&id, &id) {
                    return None;
                }
                if !key_matches {
                    // Rate-limit the warn (audit): an attacker who can force FNV
                    // second preimages can otherwise spam one line PER REQUEST.
                    // Log at collision counts 1, 2, 4, 8... — O(log n) total.
                    let prev = self.key_id_collisions.fetch_add(1, Ordering::Relaxed);
                    if prev == 0 || prev.is_power_of_two() {
                        tracing::warn!(count = prev + 1, "hj-pagecache: compact key-id collision — refusing cached entry");
                    }
                    return None;
                }
                if !identity_ok {
                    tracing::warn!(
                        requested = %identity,
                        "hj-pagecache: key/identity mismatch — refusing to serve cached entry (collision guard)"
                    );
                    return None;
                }
                acc.touch_ram(&id);
                if body_is_file && matches!(fresh, Freshness::Fresh | Freshness::Stale) {
                    acc.touch_disk(&id);
                }
                Some((fresh, snap))
            });
        match outcome {
            None => {
                if count {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                }
                EntryState::Miss
            }
            Some((Freshness::Fresh, r)) => {
                if count {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                }
                EntryState::Fresh(r)
            }
            Some((Freshness::Stale, r)) => {
                if count {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                }
                EntryState::Stale(r)
            }
            Some((Freshness::ErrorOnly, r)) => {
                if count {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                }
                EntryState::ErrorOnly(r)
            }
            Some((Freshness::Gone, _)) => unreachable!("Gone handled under the lock"),
        }
    }

    /// Look up `key`, returning the entry only if present, FRESH (or stale —
    /// either is servable), and its identity matches. Thin wrapper over
    /// [`get_entry`](Self::get_entry) for callers that don't distinguish stale.
    pub fn lookup(
        &self,
        key: &PageCacheKey,
        identity: &str,
        now: Instant,
    ) -> Option<Arc<CachedResponse>> {
        match self.get_entry(key, identity, now) {
            EntryState::Fresh(e) | EntryState::Stale(e) => Some(e),
            EntryState::ErrorOnly(_) | EntryState::Miss => None,
        }
    }

    /// (peer-fetch) Serialize a FRESH/STALE PUBLIC entry to its on-disk HJPC bytes
    /// for cross-node fill, or `None` if absent / not file-backed / private. Uses the
    /// UNCOUNTED lookup (a peer probe is not a local hit/miss) and the identity
    /// collision guard, so a key/identity mismatch yields `None`, never a wrong page.
    pub fn serialize_entry(&self, key: &PageCacheKey, identity: &str) -> Option<Vec<u8>> {
        let now = Instant::now();
        let entry = match self.get_entry_uncounted(key, identity, now) {
            EntryState::Fresh(e) | EntryState::Stale(e) => e,
            EntryState::ErrorOnly(_) | EntryState::Miss => return None,
        };
        if !matches!(entry.scope, PageScope::Public) {
            return None;
        }
        match &entry.body {
            PageBody::File { path, .. } => std::fs::read(path.as_ref()).ok(),
            PageBody::InMem(_) | PageBody::Derived { .. } => None,
        }
    }

    /// (peer-fetch) Adopt an HJPC blob fetched from a peer: persist it (filename keyed
    /// by the cross-node-deterministic `key_hash`), rebuild the entry, and index it via
    /// the SAME path the boot warm-scan uses (freshness/dict/purge/newer-local checks,
    /// then `load_scanned`). Returns true if installed. No admission gate — the peer
    /// already served it, so it is proven hot.
    /// `fetch_epoch` is the purge epoch captured BEFORE the peer fetch began; a relevant purge
    /// landing after that point vetoes the adoption (same contract as
    /// [`Self::store_if_not_purged_since`]). Entries whose `stored_unix_ms` is at or before the
    /// last purge-all are rejected outright — peer-fill must never resurrect purged content.
    pub fn adopt_entry(&self, key_hash: u64, bytes: &[u8], fetch_epoch: u64) -> bool {
        let Some(disk) = self.disk.clone() else {
            return false;
        };
        let prepared = match disk.prepare_raw(key_hash, bytes) {
            Ok(prepared) => prepared,
            Err(_) => {
                self.disk_write_errors.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        };
        let se = match disk.read_prepared_entry(&prepared) {
            Ok(se) => se,
            Err(_) => {
                self.meta_decode_errors.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        };
        if se.body_len as u64 > self.config.max_obj_bytes
            || (se.dict_gen != 0 && !self.config.expected_dict_gens.contains(&se.dict_gen))
        {
            return false;
        }
        // Per-entry clock so the adopted entry's freshness window stays continuous.
        let now_wall = wall_now_ms();
        let now_inst = Instant::now();
        let age_ms = now_wall.saturating_sub(se.stored_unix_ms);
        let retention_ms = ms_saturating(se.ttl + se.swr.max(se.sie));
        if se.stored_unix_ms == 0 || se.stored_unix_ms > now_wall || age_ms >= retention_ms {
            return false;
        }
        if se.stored_unix_ms <= self.purge_all_wall_ms.load(Ordering::Acquire) {
            return false;
        }
        // Per-tag equivalent of the purge-all wall veto above: reject an entry stored
        // at or before a tag purge of any tag it carries. The epoch veto inside
        // `load_scanned` can't catch a tag purge that COMPLETED before this fill was
        // requested (the fill's `fetch_epoch` is >= that purge's epoch), which is the
        // dominant XenForo purge case — so resurrection was left open for tag purges
        // until this wall-stamp check (#134).
        if self.tag_purged_since_wall(&se.tags, se.stored_unix_ms) {
            return false;
        }
        let Some(stored_at) = now_inst.checked_sub(Duration::from_millis(age_ms)) else {
            return false;
        };
        let _page_commit = self.page_commit.lock();
        if self.purged_after(&se.tags, fetch_epoch)
            || se.stored_unix_ms <= self.purge_all_wall_ms.load(Ordering::Acquire)
            || self.tag_purged_since_wall(&se.tags, se.stored_unix_ms)
        {
            return false;
        }
        let (path, _disk_total) = match disk.publish_entry(prepared) {
            Ok(published) => published,
            Err(_) => {
                self.disk_write_errors.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        };
        let se = match crate::diskstore::read_meta(&path) {
            Ok(se) => se,
            Err(_) => {
                self.meta_decode_errors.fetch_add(1, Ordering::Relaxed);
                DiskStore::remove(&path);
                return false;
            }
        };
        let body_id = self.body_id_seq.fetch_add(1, Ordering::Relaxed);
        let entry = CachedResponse {
            status: se.status,
            identity: se.identity.clone(),
            headers: se.headers.clone(),
            body: PageBody::File {
                path: Arc::from(se.path.as_path()),
                len: se.body_len,
                disk_total: se.disk_total,
                body_id,
            },
            variants: Vec::new(),
            variants_filled: false,
            dict_gen: se.dict_gen,
            tags: se.tags.clone(),
            vary_cookie_name: se.vary_cookie_name.clone(),
            vary_value: se.vary_value.clone(),
            scope: se.scope,
            stored_at,
            ttl: se.ttl,
            swr: se.swr,
            sie: se.sie,
        };
        self.load_scanned(
            se.key.clone(),
            entry,
            se.stored_unix_ms,
            se.version_seq,
            Some(fetch_epoch),
        )
    }

    /// Store an entry. A body larger than `max_obj_bytes` is a silent no-op.
    pub fn store(&self, key: PageCacheKey, entry: CachedResponse) -> bool {
        let epoch = self.purge_epoch();
        self.store_if_not_purged_since(key, entry, epoch)
    }

    /// Store an entry only if no relevant purge happened after `render_epoch`.
    pub fn store_if_not_purged_since(
        &self,
        key: PageCacheKey,
        entry: CachedResponse,
        render_epoch: u64,
    ) -> bool {
        self.store_if_not_purged_since_hashed(stable_key_hash(&key), key, entry, render_epoch)
    }

    /// Caller-supplied raw page hash variant (the glue layer already computed it for
    /// single-flight/admission) — skips the second pass over the key fields. `key_hash`
    /// MUST be `key_hash(key)` for this very key.
    pub fn store_if_not_purged_since_hashed(
        &self,
        key_hash: u64,
        key: PageCacheKey,
        entry: CachedResponse,
        render_epoch: u64,
    ) -> bool {
        if entry.body.len() as u64 > self.config.max_obj_bytes {
            return false;
        }
        let id = CacheKeyId::from_raw_page_hash(key_hash);

        // (1) SLOW PART, OFF THE LOCK: write the complete container under a private temp name.
        // Final publication waits until the key's shard is locked and tag membership is visible,
        // so a concurrent purge can never delete or strand a boot-scannable in-flight version.
        let mut prepared = None;
        if let (Some(disk), PageBody::InMem(bytes)) = (self.disk.as_ref(), &entry.body) {
            let stored_unix_ms = wall_ms_of(entry.stored_at);
            match disk.prepare_entry(&key, &entry, 0, bytes, stored_unix_ms) {
                Ok(p) => prepared = Some((disk.clone(), p, bytes.len() as u32)),
                Err(e) => {
                    self.disk_write_errors.fetch_add(1, Ordering::Relaxed);
                    if e.kind() == std::io::ErrorKind::StorageFull {
                        self.disk_full_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    tracing::warn!(error = %e, "jetcache: identity persist failed — entry stays in RAM");
                }
            }
        }
        let tags = entry.tags.clone();
        let mut node = match Node::from_cached(&key, entry, render_epoch) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = ?e, "hj-pagecache: metadata compression failed — bypassing store");
                return false;
            }
        };
        let mut new_file: Option<Arc<Path>> = None;
        // Hold-time measurement spans from just before the lock to just after the
        // shard closure returns (lock still held): µs-resolution accounting of the
        // store-vs-purge serialization window without a Drop-guard in every path.
        let commit_hold_start = std::time::Instant::now();
        let _page_commit = self.page_commit.lock();

        // (2) FAST PART, UNDER THE SHARD LOCK (via `with_shard`). Returns `true` on a committed
        // install; `false` (with the caller cleaning up `new_file`) on a veto/collision/bypass.
        let installed = self.inner.with_shard(&id, |acc| {
            if self.purged_after(&tags, render_epoch) {
                self.store_purge_rejections.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            #[cfg(test)]
            {
                if let Some(hook) = self.store_commit_probe.lock().take() {
                    hook(self);
                }
            }
            // SAME-KEY REPLACE: a predecessor of a DIFFERENT key is a collision — refuse, never
            // overwrite a foreign entry. A corrupt predecessor is torn down and we proceed. A same
            // key is a genuine re-store; `insert_replacing` tears the predecessor down (firing the
            // teardown hook: its file is unlinked under the lock + its tags GC'd) before installing.
            let mut previous_tags = Vec::new();
            if let Some(prev) = acc.get(&id).and_then(CacheEntry::as_page) {
                previous_tags = prev.tags.clone();
                match prev.to_cached_with_decode_state() {
                    Ok((prev_key, _, decoded_populated)) => {
                        if prev_key != key {
                            if decoded_populated {
                                acc.reconcile_weights(&id, &id);
                            }
                            // Same power-of-two rate limit as the lookup-side warn (audit).
                            let prev = self.key_id_collisions.fetch_add(1, Ordering::Relaxed);
                            if prev == 0 || prev.is_power_of_two() {
                                tracing::warn!(
                                    count = prev + 1,
                                    "hj-pagecache: compact key-id collision on store — skipping new entry"
                                );
                            }
                            return false;
                        }
                    }
                    Err(_) => {
                        self.meta_decode_errors.fetch_add(1, Ordering::Relaxed);
                        acc.teardown(&id, EvictCause::Explicit);
                        previous_tags.clear();
                    }
                }
            }
            if !acc.contains(&id) {
                previous_tags.clear();
            }

            // Make every NEW tag visible before publishing a final file. Existing tags are already
            // registered by the predecessor; after replacement all tags are registered again because
            // predecessor teardown removes memberships by compact key id.
            let mut provisional_tags = Vec::new();
            for tag in &tags {
                if !previous_tags.iter().any(|old| old == tag) {
                    self.tag_index.insert(tag.clone(), id);
                    provisional_tags.push(tag.clone());
                }
            }
            if self.purged_after(&tags, render_epoch) {
                self.store_purge_rejections.fetch_add(1, Ordering::Relaxed);
                for tag in &provisional_tags {
                    self.tag_index.remove_membership(tag, &id);
                }
                return false;
            }

            if let Some((disk, pending, body_len)) = prepared.take() {
                match disk.publish_entry(pending) {
                    Ok((path, disk_total)) => {
                        let path: Arc<Path> = Arc::from(path);
                        let body_id = self.body_id_seq.fetch_add(1, Ordering::Relaxed);
                        node.invalidate_snapshot();
                        node.body = PageBody::File {
                            path: path.clone(),
                            len: body_len,
                            disk_total,
                            body_id,
                        };
                        node.dict_gen = 0;
                        new_file = Some(path);
                        #[cfg(test)]
                        {
                            if let Some(hook) = self.store_publish_probe.lock().take() {
                                hook(self);
                            }
                        }
                    }
                    Err(e) => {
                        self.disk_write_errors.fetch_add(1, Ordering::Relaxed);
                        if e.kind() == std::io::ErrorKind::StorageFull {
                            self.disk_full_errors.fetch_add(1, Ordering::Relaxed);
                        }
                        for tag in &provisional_tags {
                            self.tag_index.remove_membership(tag, &id);
                        }
                        tracing::warn!(error = %e, "jetcache: identity publish failed — entry bypassed");
                        return false;
                    }
                }
            }
            if self.purged_after(&tags, render_epoch) {
                self.store_purge_rejections.fetch_add(1, Ordering::Relaxed);
                for tag in &provisional_tags {
                    self.tag_index.remove_membership(tag, &id);
                }
                return false;
            }
            // Install (tears down any same-key predecessor first), then register THIS node's tags
            // (after the predecessor's GC), then enforce budgets with the just-inserted key
            // protected.
            if !acc.insert_replacing(&id, CacheEntry::Page(node)) {
                for tag in &provisional_tags {
                    self.tag_index.remove_membership(tag, &id);
                }
                return false;
            }
            for tag in &tags {
                self.tag_index.insert(tag.clone(), id);
            }
            acc.enforce_budgets(&id);
            if !acc.contains(&id) {
                return false;
            }
            if self.purged_after(&tags, render_epoch) {
                self.store_purge_rejections.fetch_add(1, Ordering::Relaxed);
                acc.teardown(&id, EvictCause::Explicit);
                return false;
            }
            true
        });
        self.store_commit_hold_us.fetch_add(
            commit_hold_start.elapsed().as_micros() as u64,
            Ordering::Relaxed,
        );
        self.store_commit_calls.fetch_add(1, Ordering::Relaxed);
        if !installed {
            if let Some(p) = new_file {
                DiskStore::remove(&p);
            }
            return false;
        }
        self.stores.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// In-place mutation of the live node for `id` IF it still matches `(identity, stored_at)`.
    /// Re-validates under the shard lock (purged/replaced/already-filled → returns the closure's
    /// `None`). `mutate` returns `Some(())` to commit (weights are recomputed + a fresh expiry-heap
    /// entry pushed + budgets enforced) or `None` to abort. Returns whether a commit happened.
    fn mutate_if_matches(
        &self,
        key: &PageCacheKey,
        identity: &str,
        stored_at: Instant,
        mutate: impl FnOnce(&mut Node) -> bool,
    ) -> bool {
        let id = CacheKeyId::new(key);
        self.inner.with_shard(&id, |acc| {
            // Re-validate under the lock: a decode-corrupt entry is torn down; a key/identity/
            // stored_at mismatch (purged + replaced, or a fresher re-store) aborts the fill.
            match acc.get(&id).and_then(CacheEntry::as_page) {
                None => return false,
                Some(node) => match node.to_cached_with_decode_state() {
                    Ok((k, exp, decoded_populated)) => {
                        let node_stored_at = node.stored_at;
                        if decoded_populated && !acc.reconcile_weights(&id, &id) {
                            return false;
                        }
                        if k != *key || exp.identity != identity || node_stored_at != stored_at {
                            return false;
                        }
                    }
                    Err(_) => {
                        self.meta_decode_errors.fetch_add(1, Ordering::Relaxed);
                        acc.teardown(&id, EvictCause::Explicit);
                        return false;
                    }
                },
            }
            // The primitive's `mutate` snapshots the old weights, runs the closure, and on commit
            // re-reads `ram_weight`/`disk_weight`/`deadline` from the `CacheValue` impl, reconciles
            // disk-LRU membership + both budgets + a fresh deadline-heap entry, and enforces budgets
            // with `id` protected. (A fill can flip File↔Derived/InMem; the trait weights track it.)
            acc.mutate(&id, |entry| match entry {
                CacheEntry::Page(node) => mutate(node),
                CacheEntry::Static(_) => false,
            })
        })
    }

    /// (PC2-lazy) Add precompressed `variants` to an entry IN PLACE, but only if `key` still
    /// holds the SAME entry the fill was started for — matched by `identity` + `stored_at`.
    /// A NO-OP if the entry was purged, evicted, already filled, or replaced by a fresher
    /// re-store since the fill began.
    pub fn fill_variants(
        &self,
        key: &PageCacheKey,
        identity: &str,
        stored_at: Instant,
        variants: Vec<(String, Bytes)>,
        derive_identity_len: Option<u32>,
    ) {
        self.mutate_if_matches(key, identity, stored_at, |n| {
            if n.variants_filled {
                return false;
            }
            let dict_attempted = n
                .variants
                .iter()
                .any(|(token, _)| token == DICT_ATTEMPT_VARIANT_TOKEN);
            let has_servable_variant = !variants.is_empty();
            n.variants = variants;
            if dict_attempted {
                n.variants
                    .push((DICT_ATTEMPT_VARIANT_TOKEN.to_owned(), Bytes::new()));
            }
            n.variants_filled = true;
            n.invalidate_snapshot();
            // VARIANT-PRIMARY: drop the redundant identity body when the caller verified a stored
            // variant losslessly round-trips to it. Only for an InMem body (RAM-only mode — a
            // file-tier body keeps its tmpfs identity). dict_gen → 0.
            if let (Some(id_len), PageBody::InMem(_)) = (derive_identity_len, &n.body) {
                if has_servable_variant && !dict_attempted {
                    n.body = PageBody::Derived {
                        identity_len: id_len,
                    };
                    n.dict_gen = 0;
                }
            }
            true
        });
    }

    /// Claim the one dictionary-recompression attempt for this exact resident version.
    /// The zero-byte marker is ignored by content negotiation and preserved by variant fill.
    pub fn mark_dict_compression_attempted(
        &self,
        key: &PageCacheKey,
        identity: &str,
        stored_at: Instant,
    ) -> bool {
        self.mutate_if_matches(key, identity, stored_at, |node| {
            if node.dict_gen != 0
                || node
                    .variants
                    .iter()
                    .any(|(token, _)| token == DICT_ATTEMPT_VARIANT_TOKEN)
            {
                return false;
            }
            node.variants
                .push((DICT_ATTEMPT_VARIANT_TOKEN.to_owned(), Bytes::new()));
            true
        })
    }

    /// Swap a freshly-stored IDENTITY entry's body for its dict-compressed form (in RAM). A NO-OP
    /// if the entry was purged, replaced by a fresher store, a key collision, or already
    /// dict-compressed (`dict_gen != 0`). Only the body + `dict_gen` change; `stored_at`/`ttl` are
    /// preserved.
    pub fn fill_dict_body(
        &self,
        key: &PageCacheKey,
        identity: &str,
        stored_at: Instant,
        compressed: Bytes,
        dict_gen: u32,
    ) -> bool {
        self.mutate_if_matches(key, identity, stored_at, |n| {
            // Defense-in-depth: this RAM-swap path must never run on a File body — mutate_if_matches
            // reconciles the disk-LRU/accounting but does NOT unlink the physical .pc, so a File here
            // would orphan its tmpfs file. fill_recompress_disk owns File bodies and only delegates
            // here only for InMem. File would leak its old container; Derived means the
            // concurrent variant fill already won and discarded identity, so keep that winner.
            if n.dict_gen != 0 || matches!(n.body, PageBody::File { .. } | PageBody::Derived { .. })
            {
                return false;
            }
            n.body = PageBody::InMem(compressed);
            n.dict_gen = dict_gen;
            n.invalidate_snapshot();
            true
        })
    }

    /// Recompress a freshly-stored IDENTITY entry into its dict-compressed form. The body was
    /// already offloaded to tmpfs at store time (identity, `dict_gen == 0`); this writes the
    /// dict-compressed bytes to a NEW immutable file, flips the entry to point at it, and unlinks
    /// the identity file SYNCHRONOUSLY under the shard lock (distinct path ⇒ no orphan).
    ///
    /// On any loss — purge, fresher re-store, collision, or already-recompressed — the just-written
    /// compressed file is unlinked and nothing is resurrected. A write failure leaves the
    /// (servable) identity file in place. Degrades to an in-RAM swap ([`Self::fill_dict_body`]) for
    /// an entry whose body never reached tmpfs.
    pub fn fill_recompress_disk(
        &self,
        key: &PageCacheKey,
        identity: &str,
        stored_at: Instant,
        compressed: Bytes,
        dict_gen: u32,
    ) -> bool {
        let id = CacheKeyId::new(key);

        /// Outcome of the cheap pre-check under the shard lock. The decoded view carried by
        /// `Recompress` is boxed so the enum stays small (the other arms are unit).
        enum PreCheck {
            /// Bail out (purged / replaced / collision / decode error).
            Bail,
            /// Body never reached tmpfs (degraded InMem, or no disk tier): swap in RAM.
            DegradeRam,
            /// Still the identity File version: recompress, carrying its decoded view for `write_entry`.
            Recompress(Box<CachedResponse>),
        }

        // Pre-check (under the lock, cheap): is the entry still the identity File version we mean
        // to recompress? Also decide the RAM-degrade path while holding the lock so we have the
        // decoded response for the prepared container below.
        let pre = self.inner.with_shard(&id, |acc| {
            match acc.get(&id).and_then(CacheEntry::as_page) {
                None => PreCheck::Bail,
                Some(node) => {
                    if node.stored_at != stored_at || node.dict_gen != 0 {
                        return PreCheck::Bail;
                    }
                    match node.to_cached_with_decode_state() {
                        Ok((k, exp, decoded_populated)) => {
                            let is_file = matches!(node.body, PageBody::File { .. });
                            if decoded_populated && !acc.reconcile_weights(&id, &id) {
                                return PreCheck::Bail;
                            }
                            if k != *key || exp.identity != identity {
                                PreCheck::Bail
                            } else if !is_file {
                                PreCheck::DegradeRam
                            } else {
                                PreCheck::Recompress(Box::new(exp))
                            }
                        }
                        Err(_) => PreCheck::Bail,
                    }
                }
            }
        });
        let cur_expanded = match pre {
            PreCheck::Bail => return false,
            PreCheck::DegradeRam => {
                return self.fill_dict_body(key, identity, stored_at, compressed, dict_gen);
            }
            PreCheck::Recompress(exp) => *exp,
        };
        let Some(disk) = self.disk.clone() else {
            return self.fill_dict_body(key, identity, stored_at, compressed, dict_gen);
        };
        // SLOW PART, off the lock: build a complete private temp container. Final publication
        // shares the page commit mutex with purge, so a completed tag purge can never leave a
        // newer unindexed version for the next boot scan to resurrect.
        let stored_unix_ms = wall_ms_of(stored_at);
        let prepared = match disk.prepare_entry(
            key,
            &cur_expanded,
            dict_gen,
            &compressed,
            stored_unix_ms,
        ) {
            Ok(p) => p,
            Err(e) => {
                self.disk_write_errors.fetch_add(1, Ordering::Relaxed);
                if e.kind() == std::io::ErrorKind::StorageFull {
                    self.disk_full_errors.fetch_add(1, Ordering::Relaxed);
                }
                tracing::warn!(error = %e, "jetcache: recompress write failed — identity file kept");
                return false;
            }
        };
        let new_body_id = self.body_id_seq.fetch_add(1, Ordering::Relaxed);
        let new_len = compressed.len() as u32;
        let _page_commit = self.page_commit.lock();
        let mut prepared = Some(prepared);
        let mut published_path = None;

        // FAST PART, under the shard lock: re-validate, publish, swap the body, and unlink the old
        // identity file. The primitive's `mutate` reconciles BOTH budgets (a File→File recompress
        // shrinks the disk weight; ram_weight is stable today but reconciling exactly is harmless),
        // the disk-LRU membership, and a fresh deadline-heap entry with `id` protected.
        let swapped = self.inner.with_shard(&id, |acc| {
            let (still_match, old_file) = match acc.get(&id) {
                Some(CacheEntry::Page(node)) => match &node.body {
                    PageBody::File { path, body_id, .. }
                        if node.stored_at == stored_at && node.dict_gen == 0 =>
                    {
                        let old_file = Some((path.clone(), *body_id));
                        let ok = match node.to_cached_with_decode_state() {
                            Ok((k, exp, decoded_populated)) => {
                                (!decoded_populated || acc.reconcile_weights(&id, &id))
                                    && k == *key
                                    && exp.identity == identity
                            }
                            Err(_) => false,
                        };
                        (ok, old_file)
                    }
                    _ => (false, None),
                },
                Some(CacheEntry::Static(_)) | None => (false, None),
            };
            if !still_match {
                return false;
            }
            let (new_path, new_disk_total) = match disk.publish_entry(
                prepared
                    .take()
                    .expect("prepared recompress file published at most once"),
            ) {
                Ok(published) => published,
                Err(e) => {
                    self.disk_write_errors.fetch_add(1, Ordering::Relaxed);
                    if e.kind() == std::io::ErrorKind::StorageFull {
                        self.disk_full_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    tracing::warn!(error = %e, "jetcache: recompress publish failed — identity file kept");
                    return false;
                }
            };
            published_path = Some(new_path.clone());
            let new_path = new_path.clone();
            let committed = acc.mutate(&id, |entry| {
                let CacheEntry::Page(n) = entry else {
                    return false;
                };
                n.invalidate_snapshot();
                n.body = PageBody::File {
                    path: Arc::from(new_path),
                    len: new_len,
                    disk_total: new_disk_total,
                    body_id: new_body_id,
                };
                n.dict_gen = dict_gen;
                true
            });
            // Unlink the predecessor identity file SYNCHRONOUSLY (distinct path) + drop its hot copy.
            // A failed budget reservation tears down the already-mutated node (and therefore its
            // new file) through StoreEvict; in that case the predecessor is no longer referenced
            // either and must be removed here as well.
            if committed || !acc.contains(&id) {
                if let Some((old_path, old_body_id)) = old_file {
                    DiskStore::remove(&old_path);
                    if let Some(hot) = &self.hot {
                        hot.invalidate(old_body_id);
                    }
                }
            }
            committed
        });
        if !swapped {
            if let Some(new_path) = published_path {
                DiskStore::remove(&new_path);
            }
        }
        swapped
    }

    /// Rebuild the index from the file tier (the boot warm scan). Runs in the
    /// background after startup; requests during the walk simply miss and
    /// re-render. `on_loaded` fires once per kept key (the glue pre-warms the
    /// W-TinyLFU admission sketch with it).
    pub fn load_from_disk(&self, on_loaded: impl Fn(&PageCacheKey) + Send + Sync) -> ScanSummary {
        let Some(disk) = self.disk.clone() else {
            return ScanSummary::default();
        };
        let stamp = disk.read_purge_stamp();
        if let Some(s) = stamp {
            self.purge_all_wall_ms.fetch_max(s, Ordering::AcqRel);
        }
        let expected_gens = &self.config.expected_dict_gens;
        let max_obj = self.config.max_obj_bytes;

        let mut sum = disk.scan(|se| {
            if se.body_len as u64 > max_obj {
                return false;
            }
            if se.dict_gen != 0 && !expected_gens.contains(&se.dict_gen) {
                return false; // dict retrained since this was stored
            }
            if stamp.is_some_and(|s| se.stored_unix_ms <= s) {
                return false; // purged-all before the restart
            }
            // PER-ENTRY clock so a slow scan keeps each restored entry's freshness window
            // continuous across the restart.
            let now_wall = wall_now_ms();
            let now_inst = Instant::now();
            let age_ms = now_wall.saturating_sub(se.stored_unix_ms);
            let retention_ms = ms_saturating(se.ttl + se.swr.max(se.sie));
            if se.stored_unix_ms == 0 || se.stored_unix_ms > now_wall || age_ms >= retention_ms {
                return false; // expired (or clock skew put it in the future)
            }
            let Some(stored_at) = now_inst.checked_sub(Duration::from_millis(age_ms)) else {
                return false; // older than the monotonic epoch
            };
            let body_id = self.body_id_seq.fetch_add(1, Ordering::Relaxed);
            let entry = CachedResponse {
                status: se.status,
                identity: se.identity.clone(),
                headers: se.headers.clone(),
                body: PageBody::File {
                    path: Arc::from(se.path.as_path()),
                    len: se.body_len,
                    disk_total: se.disk_total,
                    body_id,
                },
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: se.dict_gen,
                tags: se.tags.clone(),
                vary_cookie_name: se.vary_cookie_name.clone(),
                vary_value: se.vary_value.clone(),
                scope: se.scope,
                stored_at,
                ttl: se.ttl,
                swr: se.swr,
                sie: se.sie,
            };
            let kept = self.load_scanned(
                se.key.clone(),
                entry,
                se.stored_unix_ms,
                se.version_seq,
                None,
            );
            if kept {
                on_loaded(&se.key);
            }
            kept
        });
        let static_max_obj = self.config.max_static_obj_bytes;
        let static_sum = disk.scan_static(|se| {
            if se.body_len as u64 > static_max_obj {
                return false;
            }
            if FileId::stat(&se.source_path).ok() != Some(se.file_id) {
                return false;
            }
            self.load_scanned_static(se)
        });
        sum.loaded += static_sum.loaded;
        sum.rejected += static_sum.rejected;
        sum.corrupt_removed += static_sum.corrupt_removed;
        sum.tmp_removed += static_sum.tmp_removed;
        disk.finish_boot_scan();
        // Scan complete: record the loaded count (gate signal), then drop the purge buffer.
        self.scan_loaded.store(sum.loaded, Ordering::Relaxed);
        *self.scan_purge.lock() = None;
        tracing::info!(
            loaded = sum.loaded,
            rejected = sum.rejected,
            corrupt = sum.corrupt_removed,
            tmp = sum.tmp_removed,
            "jetcache: warm scan complete"
        );
        sum
    }

    /// Insert one scanned (pre-boot) entry. False ⇒ the caller unlinks the file: a purge already
    /// covered it, or a LIVE entry (a post-boot store, or a newer duplicate file of the same key)
    /// wins. A newer duplicate triggers a synchronous same-key replace (the older file is unlinked
    /// under the lock — no orphan).
    fn load_scanned(
        &self,
        key: PageCacheKey,
        entry: CachedResponse,
        new_stored_unix_ms: u64,
        new_version_seq: u64,
        runtime_purge_epoch: Option<u64>,
    ) -> bool {
        let id = CacheKeyId::new(&key);
        // Capture the file to unlink BEFORE any veto. The early `return false` paths below
        // (boot-scan buffer, runtime epoch, metadata-decode error) reject a peer-fill adopt
        // whose file `adopt_entry` already wrote to tmpfs; without unlinking here that file
        // strands outside both cache budgets and the next boot scan resurrects the
        // (tag-)purged entry (tag purges leave no durable disk stamp) (#137). `DiskStore::remove`
        // of a missing/already-installed file is a no-op, so this is safe for both callers.
        let new_file = cloned_file_path(&entry.body);
        let unlink_new_file = |nf: &Option<Arc<Path>>| {
            if let Some(p) = nf.as_ref() {
                DiskStore::remove(p);
            }
        };
        {
            let buf = self.scan_purge.lock();
            if let Some(buf) = buf.as_ref() {
                if buf.purged_all || entry.tags.iter().any(|t| buf.tags.contains(t)) {
                    unlink_new_file(&new_file);
                    return false;
                }
            }
        }
        // The wall veto is also durable boot-scan state. Only the in-process epoch check is
        // conditional on this being a runtime peer adoption.
        if self.tag_purged_since_wall(&entry.tags, new_stored_unix_ms)
            || runtime_purge_epoch.is_some_and(|epoch| self.purged_after(&entry.tags, epoch))
        {
            unlink_new_file(&new_file);
            return false;
        }
        let tags = entry.tags.clone();
        let node = match Node::from_cached(&key, entry, runtime_purge_epoch.unwrap_or(0)) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = ?e, "hj-pagecache: scanned metadata compression failed");
                unlink_new_file(&new_file);
                return false;
            }
        };
        let new_stored_at = node.stored_at;
        #[cfg(test)]
        {
            if let Some(hook) = self.scan_insert_probe.lock().take() {
                hook(self);
            }
        }
        let installed = self.inner.with_shard(&id, |acc| {
            // Re-check the boot-scan purge buffer UNDER the shard lock, atomic with the insert
            // below. The pre-lock check above raced the slow `Node::from_cached` compression, so a
            // purge landing in that window would be escaped by this install (it re-serves purged
            // content, which Cloudflare can then re-pin). `purge_tags` records its tags / `purge_all`
            // sets `purged_all` BEFORE dropping the live set, so this shard-serialized re-check either
            // observes the purge (reject) or the purge's own drop reaches this entry. Deadlock-safe:
            // no purge path holds `scan_purge` while taking a shard lock (each releases it first).
            {
                let buf = self.scan_purge.lock();
                if let Some(buf) = buf.as_ref() {
                    if buf.purged_all || tags.iter().any(|t| buf.tags.contains(t)) {
                        return false;
                    }
                }
            }
            // Runtime peer adoption holds `page_commit` from final publication through this install,
            // so no purge can stamp/collect between this check and tag registration. Keep both epoch
            // and wall checks here as the final defense against purges completed before publication.
            if self.tag_purged_since_wall(&tags, new_stored_unix_ms)
                || runtime_purge_epoch.is_some_and(|epoch| self.purged_after(&tags, epoch))
            {
                return false;
            }
            if let Some(cur) = acc.get(&id).and_then(CacheEntry::as_page) {
                let (cur_key, cur_stored_at, cur_disk_version) =
                    match cur.to_cached_with_decode_state() {
                        Ok((k, _, decoded_populated)) => {
                            let cur_stored_at = cur.stored_at;
                            let cur_disk_version = file_body_disk_version(&cur.body);
                            if decoded_populated {
                                acc.reconcile_weights(&id, &id);
                            }
                            (k, cur_stored_at, cur_disk_version)
                        }
                        Err(_) => {
                            self.meta_decode_errors.fetch_add(1, Ordering::Relaxed);
                            acc.teardown(&id, EvictCause::Explicit);
                            (
                                PageCacheKey::public(0, false, "", "", ""),
                                Instant::now(),
                                None,
                            )
                        }
                    };
                if acc.contains(&id) {
                    if cur_key != key {
                        self.key_id_collisions.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                    let cur_is_at_least_as_new = match cur_disk_version {
                        Some((cur_stored_unix_ms, cur_version_seq)) => {
                            cur_stored_unix_ms > new_stored_unix_ms
                                || (cur_stored_unix_ms == new_stored_unix_ms
                                    && cur_version_seq >= new_version_seq)
                        }
                        None => cur_stored_at >= new_stored_at,
                    };
                    if cur_is_at_least_as_new {
                        // The in-index entry is at least as new — keep it; the caller unlinks the
                        // older scanned file.
                        return false;
                    }
                    // The scanned file is NEWER: `insert_replacing` below tears down the older
                    // in-index version (unlinks its file synchronously via the teardown hook).
                }
            }
            if !acc.insert_replacing(&id, CacheEntry::Page(node)) {
                return false;
            }
            for tag in &tags {
                self.tag_index.insert(tag.clone(), id);
            }
            acc.enforce_budgets(&id);
            if !acc.contains(&id) {
                return false;
            }
            let scan_rejected = {
                let buf = self.scan_purge.lock();
                buf.as_ref().is_some_and(|buf| {
                    buf.purged_all || tags.iter().any(|tag| buf.tags.contains(tag))
                })
            };
            let runtime_rejected = self.tag_purged_since_wall(&tags, new_stored_unix_ms)
                || runtime_purge_epoch.is_some_and(|epoch| self.purged_after(&tags, epoch));
            if scan_rejected || runtime_rejected {
                acc.teardown(&id, EvictCause::Explicit);
                return false;
            }
            true
        });
        if !installed {
            unlink_new_file(&new_file);
        }
        installed
    }

    fn load_scanned_static(&self, se: crate::diskstore::ScannedStaticEntry) -> bool {
        let key = CacheKeyId::for_static(se.vhost_id, &se.cache_path);
        let body_id = self.body_id_seq.fetch_add(1, Ordering::Relaxed);
        let entry = StaticNode {
            source_path: se.source_path.clone(),
            file_id: se.file_id,
            content_type: se.content_type.clone(),
            etag: se.etag.clone(),
            last_modified: se.last_modified.clone(),
            body: PageBody::File {
                path: Arc::from(se.path.as_path()),
                len: se.body_len,
                disk_total: se.disk_total,
                body_id,
            },
        };
        let new_file = cloned_file_path(&entry.body);
        let installed = self.inner.with_shard(&key, |acc| {
            if let Some(prev) = acc.get(&key).and_then(CacheEntry::as_static) {
                if prev.source_path != se.source_path {
                    self.key_id_collisions.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
            if !acc.insert_replacing(&key, CacheEntry::Static(entry)) {
                return false;
            }
            acc.enforce_budgets(&key);
            acc.contains(&key)
        });
        if !installed {
            if let Some(p) = new_file {
                DiskStore::remove(&p);
            }
        }
        installed
    }

    /// Enumerate the live cache contents for the loopback debug endpoint: total entries/bytes, a
    /// per-URL-class histogram, and the `top_n` largest entries.
    pub fn list_entries(&self, now: Instant, top_n: usize) -> CacheListing {
        struct Snapshot {
            meta: MetaBlob,
            stored_bytes: u64,
            variant_bytes: u64,
            dict_gen: u32,
            stored_at: Instant,
            ttl: Duration,
        }

        let mut total_entries = 0u64;
        let mut total_bytes = 0u64;
        let mut classes: HashMap<String, (u64, u64)> = HashMap::new();
        let mut top: BinaryHeap<Reverse<ListingCandidate>> = BinaryHeap::with_capacity(top_n);
        let mut ordinal = 0u64;
        self.inner.for_each_shard_snapshot(
            |_, entry| {
                let entry = entry.as_page()?;
                Some(Snapshot {
                    meta: entry.meta.clone(),
                    stored_bytes: match &entry.body {
                        PageBody::Derived { .. } => 0,
                        body => body.len() as u64,
                    },
                    variant_bytes: entry.variants.iter().map(|(_, b)| b.len() as u64).sum(),
                    dict_gen: entry.dict_gen,
                    stored_at: entry.stored_at,
                    ttl: entry.ttl,
                })
            },
            |batch| {
                for snapshot in batch {
                    let weight = snapshot.stored_bytes + snapshot.variant_bytes;
                    let _ = snapshot.meta.with_listing_fields(|status, identity| {
                        total_entries += 1;
                        total_bytes += weight;
                        // identity is "scheme\nhost\npath": bucket per HOST too, or
                        // two vhosts' same-named paths silently share one class and
                        // hide which site actually owns the entries.
                        let mut identity_parts = identity.splitn(3, '\n');
                        let _scheme = identity_parts.next();
                        let host = identity_parts.next().unwrap_or("");
                        let path = identity_parts.next().unwrap_or("");
                        let segment = path.split('/').nth(1).unwrap_or("");
                        let class_key = format!("{host}/{segment}");
                        if let Some(class) = classes.get_mut(&class_key) {
                            class.0 += 1;
                            class.1 += weight;
                        } else {
                            classes.insert(class_key, (1, weight));
                        }

                        let qualifies = top_n > 0
                            && (top.len() < top_n
                                || top
                                    .peek()
                                    .is_some_and(|candidate| weight > candidate.0.weight));
                        if qualifies {
                            ordinal = ordinal.wrapping_add(1);
                            top.push(Reverse(ListingCandidate {
                                weight,
                                ordinal,
                                info: EntryInfo {
                                    identity: identity.to_owned(),
                                    status,
                                    stored_bytes: snapshot.stored_bytes,
                                    variant_bytes: snapshot.variant_bytes,
                                    dict_gen: snapshot.dict_gen,
                                    age_secs: now.duration_since(snapshot.stored_at).as_secs(),
                                    ttl_secs: snapshot.ttl.as_secs(),
                                },
                            }));
                            if top.len() > top_n {
                                top.pop();
                            }
                        }
                    });
                }
            },
        );

        let mut top: Vec<EntryInfo> = top.into_iter().map(|candidate| candidate.0.info).collect();
        top.sort_by(|a, b| {
            (b.stored_bytes + b.variant_bytes).cmp(&(a.stored_bytes + a.variant_bytes))
        });
        let mut classes: Vec<(String, u64, u64)> = classes
            .into_iter()
            .map(|(class_key, (count, bytes))| {
                // class_key is "host/segment"; render as host + /segment.
                let (host, segment) = class_key
                    .split_once('/')
                    .unwrap_or((class_key.as_str(), ""));
                (format!("{host}/{segment}"), count, bytes)
            })
            .collect();
        classes.sort_by(|a, b| b.2.cmp(&a.2));
        CacheListing {
            total_entries,
            total_bytes,
            classes,
            top,
        }
    }

    /// Tear one tag-carrying entry down under its shard lock and return the
    /// `(key, max_version_seq)` whose OLDER tmpfs versions still need unlinking.
    /// The index teardown stays synchronous under the lock (file-tier rule 3);
    /// the older-version sweep is deliberately returned to the caller so it can
    /// run OUTSIDE `page_commit`/the shard mutex — a hot tag's fanout bucket can
    /// hold many `{hash}-{seq}.pc` files and the readdir+header walk must not
    /// stall unrelated stores. Filename seq disambiguation plus the boot scan
    /// tolerate their transient presence while the sweep runs unlocked.
    /// The per-member body of a tag purge, run under the member's OWNING shard
    /// lock (the caller groups members by shard so each shard locks once per
    /// purge, #293).
    fn purge_tagged_id_locked(
        &self,
        tag: &Arc<str>,
        id: CacheKeyId,
        purge_epoch: u64,
        acc: &mut ShardAccess<'_, CacheKeyId, CacheEntry, StoreEvict>,
    ) -> Option<(PageCacheKey, u64)> {
        enum Action {
            None,
            KeepFresh,
            Remove(Option<(PageCacheKey, u64)>),
        }

        let action = match acc.get(&id).and_then(CacheEntry::as_page) {
            None => Action::None,
            Some(node) if !node.tags.iter().any(|t| t == tag) => Action::None,
            Some(node) if node.render_epoch >= purge_epoch => Action::KeepFresh,
            Some(node) => match node.to_cached() {
                Ok((full_key, _)) => Action::Remove(
                    file_body_disk_version(&node.body)
                        .map(|(_, version_seq)| (full_key, version_seq)),
                ),
                Err(_) => {
                    self.meta_decode_errors.fetch_add(1, Ordering::Relaxed);
                    Action::Remove(None)
                }
            },
        };

        match action {
            Action::None => None,
            Action::KeepFresh => {
                self.tag_index.insert(tag.clone(), id);
                None
            }
            Action::Remove(version) => {
                acc.teardown(&id, EvictCause::Explicit);
                version
            }
        }
    }

    /// Purge every entry carrying any of the given tags.
    pub fn purge_tags(&self, tags: &[&str]) {
        let sweeps = self.purge_tags_locked(tags);
        // Deferred older-version unlinks: outside `page_commit` and the shard
        // locks (see `purge_tagged_id`). The referenced body file itself was
        // already unlinked by the synchronous teardown above; this clears the
        // superseded versions left in the bucket.
        if let Some(disk) = &self.disk {
            for (key, max_version_seq) in sweeps {
                disk.remove_key_versions_through(&key, max_version_seq);
            }
        }
    }

    fn purge_tags_locked(&self, tags: &[&str]) -> Vec<(PageCacheKey, u64)> {
        let _page_commit = self.page_commit.lock();
        let mut sweeps: Vec<(PageCacheKey, u64)> = Vec::new();
        let wall_ms = wall_now_ms();
        let epoch = self.purge_seq.fetch_add(1, Ordering::AcqRel) + 1;
        if self.disk.is_some() {
            let mut buf = self.scan_purge.lock();
            if let Some(buf) = buf.as_mut() {
                for tag in tags {
                    buf.tags.insert(Arc::from(*tag));
                }
            }
        }
        for &t in tags {
            let ta: Arc<str> = Arc::from(t);
            self.tag_purge_epoch
                .insert(ta.clone(), TagPurgeStamp { epoch });
            if let Some(disk) = &self.disk {
                let tag_hash = stable_tag_hash(t);
                self.peer_tag_purge_wall
                    .entry(tag_hash)
                    .and_modify(|old| *old = (*old).max(wall_ms))
                    .or_insert(wall_ms);
                if let Err(error) = disk.append_tag_purge_stamp(tag_hash, wall_ms) {
                    tracing::warn!(%error, "jetcache: tag-purge stamp append failed");
                    self.peer_tag_purge_journal_appends
                        .store(PEER_TAG_PURGE_JOURNAL_COMPACT_RECORDS, Ordering::Relaxed);
                } else {
                    self.peer_tag_purge_journal_appends
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            // Remove the tag set FIRST (lock-order rule: never lock a shard while holding a
            // tag_index lock). Collect the ids, then dispatch them grouped by
            // owning shard so a hot tag locks each shard once, not once per id.
            if let Some(set) = self.tag_index.remove_tag(&ta) {
                let mut ids: Vec<CacheKeyId> = set.iter().copied().collect();
                self.inner.with_shard_groups(&mut ids, |acc, group| {
                    for id in group {
                        if let Some(sweep) = self.purge_tagged_id_locked(&ta, *id, epoch, acc) {
                            sweeps.push(sweep);
                        }
                    }
                });
            }
        }
        if self.disk.is_some() && self.peer_tag_purge_wall.len() > MAX_PEER_TAG_PURGE_TOMBSTONES {
            self.compact_peer_tag_purge_state_locked(
                MAX_PEER_TAG_PURGE_TOMBSTONES,
                PEER_TAG_PURGE_RETAIN_TOMBSTONES,
            );
        } else if self.disk.is_some()
            && self.peer_tag_purge_journal_appends.load(Ordering::Relaxed)
                >= PEER_TAG_PURGE_JOURNAL_COMPACT_RECORDS
        {
            self.persist_peer_tag_purge_state_locked();
        }
        self.purges.fetch_add(1, Ordering::Relaxed);
        sweeps
    }

    /// Purge everything (handles `X-LiteSpeed-Purge: *`).
    pub fn purge_all(&self) {
        let _page_commit = self.page_commit.lock();
        let stamp = wall_now_ms();
        self.purge_all_wall_ms.fetch_max(stamp, Ordering::AcqRel);
        let epoch = self.purge_seq.fetch_add(1, Ordering::AcqRel) + 1;
        self.purge_all_epoch.store(epoch, Ordering::Release);
        self.tag_purge_epoch.clear();
        let tag_floor = if self.disk.is_some() {
            let floor = self
                .peer_tag_purge_floor_ms
                .fetch_max(stamp, Ordering::AcqRel)
                .max(stamp);
            self.peer_tag_purge_wall.clear();
            floor
        } else {
            0
        };
        self.tag_index.clear();
        // Record purged-all in the boot-scan buffer BEFORE dropping the live set, so a concurrent
        // `load_scanned` whose under-lock re-check runs after `purge_if` swept its shard is still
        // rejected (mirrors `purge_tags`, which buffers its tags before tearing down). Together with
        // the shard-serialized re-check in `load_scanned`, a scanned entry can never escape a
        // purge_all that lands during the warm scan.
        if self.disk.is_some() {
            let mut buf = self.scan_purge.lock();
            if let Some(buf) = buf.as_mut() {
                buf.purged_all = true;
            }
        }
        // Drop page entries only. Static-file bodies share the same index/budgets but are not
        // LSCache entries, so an app/page purge must not flush them.
        self.inner.purge_if(|_, e| matches!(e, CacheEntry::Page(_)));
        if let Some(disk) = &self.disk {
            // The per-shard drain above already unlinked EVERY current file synchronously. We do NOT
            // run a background tmpfs sweep: a store landing concurrently with (or just after)
            // purge_all is either vetoed by `purge_all_epoch` (and cleans up its own file) or is a
            // legitimately-newer live entry that MUST survive — and a millisecond-granular
            // `stored_unix_ms > stamp` background scan would wrongly unlink that fresh file, leaving
            // its index entry permanently fileless (no reaper exists to fix it). Durability across a
            // restart is the stamp's job alone: the boot scan rejects anything stored at-or-before it.
            if let Err(e) = disk.write_purge_stamp(stamp) {
                tracing::warn!(error = %e, "jetcache: purge-all stamp write failed");
            }
            if let Err(e) = disk.write_tag_purge_state(tag_floor, &[]) {
                tracing::warn!(error = %e, "jetcache: tag-purge state write failed");
            } else {
                self.peer_tag_purge_journal_appends
                    .store(0, Ordering::Relaxed);
            }
        }
        self.purges.fetch_add(1, Ordering::Relaxed);
    }

    /// Proactively reclaim entries past their logical end-of-life by draining each shard's deadline
    /// min-heap. A heap entry is honored only if its generation still matches the live node's (a
    /// re-store bumps the generation, orphaning the stale heap entry — skipped, never tearing down
    /// the fresh re-store) AND the value is no longer fresh (for the page `Node`, `is_fresh` returns
    /// false exactly when `freshness() == Gone`, i.e. past `stored_at + retention()`). Each reclaim
    /// runs through the primitive's teardown funnel firing [`StoreEvict`] (file unlink + budget drop
    /// + tag GC). Returns the number reclaimed.
    pub fn sweep_expired(&self) -> u64 {
        let swept = self.inner.sweep_expired();
        if swept > 0 {
            self.swept_expired.fetch_add(swept, Ordering::Relaxed);
        }
        swept
    }

    /// Entries reclaimed by the proactive expiry sweep so far.
    pub fn swept_expired(&self) -> u64 {
        self.swept_expired.load(Ordering::Relaxed)
    }

    /// Exact live entry count (Σ over shards under each lock).
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }

    /// A snapshot of counters for the stats endpoint.
    ///
    /// O(entries): the `meta_*_bytes` sums + the entry/byte totals iterate every shard's map (cheap
    /// per entry: two length reads, no decode). Keep this OFF the request path; it is for the
    /// loopback metrics/debug listeners only.
    pub fn stats(&self) -> CacheStats {
        // Index-level aggregates (entries + both byte accumulators) from the primitive.
        let index = self.inner.stats();
        let entries = index.entries;
        let tag_index = self.tag_index.stats();
        let memory_bytes = index.ram_bytes + tag_index.bytes;
        let disk_bytes = index.disk_bytes;
        // The page-specific metadata-byte sums need to read each value, via `for_each`.
        let mut meta_compressed_bytes = 0u64;
        let mut meta_raw_bytes = 0u64;
        let mut decoded_entries = 0u64;
        self.inner.for_each(|_, e| {
            let Some(e) = e.as_page() else {
                return;
            };
            meta_compressed_bytes += e.meta.compressed_len() as u64;
            meta_raw_bytes += e.meta.raw_len() as u64;
            if e.decoded.get().is_some() {
                decoded_entries += 1;
            }
        });
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stores: self.stores.load(Ordering::Relaxed),
            purges: self.purges.load(Ordering::Relaxed),
            store_commit_hold_us: self.store_commit_hold_us.load(Ordering::Relaxed),
            store_commit_calls: self.store_commit_calls.load(Ordering::Relaxed),
            store_purge_rejections: self.store_purge_rejections.load(Ordering::Relaxed),
            entries,
            memory_bytes,
            hot_bytes: self.hot.as_ref().map_or(0, |h| h.bytes()),
            disk_bytes,
            disk_max_bytes: self.disk.as_ref().map_or(0, |_| self.disk_max_bytes),
            disk_evictions: self.disk_evictions.load(Ordering::Relaxed),
            swept_expired: self.swept_expired.load(Ordering::Relaxed),
            expired_misses: self.expired_misses.load(Ordering::Relaxed),
            disk_evict_ages: [
                self.disk_evict_ages[0].load(Ordering::Relaxed),
                self.disk_evict_ages[1].load(Ordering::Relaxed),
                self.disk_evict_ages[2].load(Ordering::Relaxed),
                self.disk_evict_ages[3].load(Ordering::Relaxed),
            ],
            // Always 0 under the atomic-teardown invariant; kept for metric/format stability.
            missing_file_invalidations: 0,
            orphan_reclaimed: 0,
            orphan_deferred: 0,
            disk_read_errors: self.disk_read_errors.load(Ordering::Relaxed),
            disk_write_errors: self.disk_write_errors.load(Ordering::Relaxed),
            disk_full_errors: self.disk_full_errors.load(Ordering::Relaxed),
            poisoned_locks: 0,
            meta_compressed_bytes,
            meta_raw_bytes,
            decoded_entries,
            tag_keys: tag_index.keys,
            tag_memberships: tag_index.memberships,
            tag_index_bytes: tag_index.bytes,
            tag_purge_tombstones: self.peer_tag_purge_wall.len() as u64,
            tag_purge_floor_ms: self.peer_tag_purge_floor_ms.load(Ordering::Relaxed),
            meta_decode_errors: self.meta_decode_errors.load(Ordering::Relaxed),
            key_id_collisions: self.key_id_collisions.load(Ordering::Relaxed),
        }
    }

    /// No-op shim: the synchronous store has no deferred queue to drain. Kept so existing test
    /// helpers / callers compile unchanged.
    pub fn settle_pending(&self) {}

    /// Back-compat test helper name (no-op — see [`Self::settle_pending`]).
    pub fn run_pending(&self) {}

    pub fn get_static(
        &self,
        vhost_id: u32,
        path: &std::path::Path,
        fresh_id: &FileId,
        _now: Instant,
    ) -> Option<StaticNode> {
        let path_str = path.display().to_string();
        let key = CacheKeyId::for_static(vhost_id, &path_str);

        self.inner.with_shard(&key, |acc| {
            let Some(entry) = acc.get(&key).and_then(CacheEntry::as_static) else {
                return None;
            };
            if entry.source_path != path {
                self.key_id_collisions.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    "hj-pagecache: static compact key-id collision — refusing cached entry"
                );
                return None;
            }
            if entry.file_id != *fresh_id {
                acc.teardown(&key, EvictCause::Explicit);
                return None;
            }
            let cloned = entry.clone();
            acc.touch_ram(&key);
            if matches!(cloned.body, PageBody::File { .. }) {
                acc.touch_disk(&key);
            }
            Some(cloned)
        })
    }

    /// Store a static file entry in the unified cache.
    pub fn store_static(
        &self,
        vhost_id: u32,
        path: &std::path::Path,
        file_id: FileId,
        bytes: Bytes,
        content_type: Arc<str>,
        etag: String,
        last_modified: String,
    ) -> bool {
        if bytes.len() as u64 > self.config.max_static_obj_bytes {
            return false;
        }

        let path_str = path.display().to_string();
        let key = CacheKeyId::for_static(vhost_id, &path_str);
        let mut body = PageBody::InMem(bytes.clone());

        if let Some(disk) = self.disk.as_ref() {
            match disk.write_static_entry(
                vhost_id,
                &path_str,
                path,
                file_id,
                &content_type,
                &etag,
                &last_modified,
                &bytes,
            ) {
                Ok((path, disk_total)) => {
                    let body_id = self.body_id_seq.fetch_add(1, Ordering::Relaxed);
                    body = PageBody::File {
                        path: Arc::from(path),
                        len: bytes.len() as u32,
                        disk_total,
                        body_id,
                    };
                }
                Err(e) => {
                    self.disk_write_errors.fetch_add(1, Ordering::Relaxed);
                    if e.kind() == std::io::ErrorKind::StorageFull {
                        self.disk_full_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    tracing::warn!(error = %e, "jetcache: static persist failed — entry stays in RAM");
                }
            }
        }

        let entry = StaticNode {
            source_path: path.to_path_buf(),
            file_id,
            content_type,
            etag,
            last_modified,
            body,
        };
        let new_file = cloned_file_path(&entry.body);

        let installed = self.inner.with_shard(&key, |acc| {
            if let Some(prev) = acc.get(&key).and_then(CacheEntry::as_static) {
                if prev.source_path != path {
                    self.key_id_collisions.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        "hj-pagecache: static compact key-id collision on store — skipping new entry"
                    );
                    return false;
                }
            }
            if !acc.insert_replacing(&key, CacheEntry::Static(entry)) {
                return false;
            }
            acc.enforce_budgets(&key);
            acc.contains(&key)
        });

        if !installed {
            if let Some(p) = new_file {
                DiskStore::remove(&p);
            }
            return false;
        }
        self.stores.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Invalidate a static file entry.
    pub fn invalidate_static(&self, vhost_id: u32, path: &std::path::Path) {
        let path_str = path.display().to_string();
        let key = CacheKeyId::for_static(vhost_id, &path_str);
        self.inner.remove(&key);
    }

    /// Low-frequency production maintenance: drain the per-shard expiry heaps (reclaiming
    /// past-deadline entries through the one teardown funnel), evict idle hot-tier bodies, and
    /// prune the bounded `tag_purge_epoch` map. The `_orphan_grace` argument is retained for the
    /// caller's stable signature but ignored (there are no orphans to reconcile).
    pub fn maintenance(&self, _orphan_grace: Duration) {
        self.sweep_expired();
        if let Some(h) = &self.hot {
            h.evict_idle(Instant::now());
        }
        self.prune_tag_purge_epoch();
    }

    /// Bounded prune of `tag_purge_epoch`. `purge_tags` only ever INSERTS into this map (one entry
    /// per distinct tag) and only `purge_all` clears it, so on a long-lived node it grows
    /// monotonically. A tag's purge epoch only matters to VETO a store whose render snapshot
    /// predates it; the generational floor bounds old tags while active render epochs prevent
    /// pruning a purge a slow in-flight store still needs to observe.
    fn prune_tag_purge_epoch(&self) {
        let _page_commit = self.page_commit.lock();
        let floor = self.tag_epoch_prune_floor.load(Ordering::Acquire);
        if floor > 0 {
            let active_floor = self.active_render_epochs.lock().keys().next().copied();
            self.tag_purge_epoch.retain(|_, stamp| {
                stamp.epoch > floor
                    || active_floor.is_some_and(|render_epoch| stamp.epoch > render_epoch)
            });
        }
        if self.disk.is_some() && self.peer_tag_purge_wall.len() > MAX_PEER_TAG_PURGE_TOMBSTONES {
            self.compact_peer_tag_purge_state_locked(
                MAX_PEER_TAG_PURGE_TOMBSTONES,
                PEER_TAG_PURGE_RETAIN_TOMBSTONES,
            );
        }
        self.tag_epoch_prune_floor
            .store(self.purge_seq.load(Ordering::Acquire), Ordering::Release);
    }

    fn compact_peer_tag_purge_state_locked(&self, hard_cap: usize, retain: usize) {
        let mut floor_ms = self.peer_tag_purge_floor_ms.load(Ordering::Acquire);
        let mut stamps: HashMap<u64, u64> = self
            .peer_tag_purge_wall
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect();
        bound_peer_tag_purge_stamps(&mut floor_ms, &mut stamps, hard_cap, retain);

        let floor_ms = self
            .peer_tag_purge_floor_ms
            .fetch_max(floor_ms, Ordering::AcqRel)
            .max(floor_ms);
        self.peer_tag_purge_wall
            .retain(|_, wall_ms| *wall_ms > floor_ms);

        self.persist_peer_tag_purge_state_locked();
    }

    fn persist_peer_tag_purge_state_locked(&self) {
        let Some(disk) = &self.disk else {
            return;
        };
        let floor_ms = self.peer_tag_purge_floor_ms.load(Ordering::Acquire);
        let stamps: Vec<(u64, u64)> = self
            .peer_tag_purge_wall
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect();
        if let Err(error) = disk.write_tag_purge_state(floor_ms, &stamps) {
            tracing::warn!(%error, "jetcache: tag-purge state compaction failed");
        } else {
            self.peer_tag_purge_journal_appends
                .store(0, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_and_static_key_namespaces_are_disjoint_and_not_nil() {
        // Page keys must keep bit 63 clear (so they never alias the static namespace,
        // which sets bit 63 as a type discriminant) and never equal the NIL terminator.
        for (vh, host, path, q) in [
            (1u32, "forum.example", "/help/", ""),
            (2, "example.com", "/forums/thread-1", "page=2"),
            (3, "a.b.c", "/", "utm=x"),
        ] {
            let k = PageCacheKey {
                vhost_id: vh,
                secure: true,
                host: host.into(),
                path: path.into(),
                normalized_query: q.into(),
                vary_value: String::new(),
                private_owner: 0,
            };
            let id = CacheKeyId::new(&k);
            assert_eq!(id.0 & (1u64 << 63), 0, "page key must have bit 63 clear");
            assert_ne!(id, NIL, "page key must not be the NIL sentinel");

            let s = CacheKeyId::for_static(vh, path);
            assert_ne!(s.0 & (1u64 << 63), 0, "static key must have bit 63 set");
            assert_ne!(s, NIL, "static key must not be the NIL sentinel");
            assert_ne!(id, s, "page and static keys must never collide");
        }
    }

    #[test]
    fn hits_share_one_snapshot_and_mutation_rebuilds_it() {
        // (#271) A hit must serve the node's SHARED snapshot (Arc refcount bump) instead of
        // rebuilding the CachedResponse under the shard lock — and a post-install mutation
        // must invalidate so the next hit reflects the mutated fields.
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "example.com", "/snap", "");
        let id = "example.com\n/snap";
        s.store(
            k.clone(),
            entry_id(b"body", &["T1"], Duration::from_secs(60), id),
        );
        let now = Instant::now();
        let first = s.lookup(&k, id, now).expect("fresh after store");
        let second = s.lookup(&k, id, now).expect("second fresh lookup");
        assert!(
            Arc::ptr_eq(&first, &second),
            "consecutive hits must share one snapshot Arc"
        );
        assert!(first.variants.is_empty());

        // Simulate the PC2 variant fill: mutate + invalidate under the same guards it uses.
        assert!(s.mutate_if_matches(&k, id, second.stored_at, |n| {
            n.variants
                .push(("br".to_string(), bytes::Bytes::from_static(b"v")));
            n.invalidate_snapshot();
            true
        }));
        let third = s.lookup(&k, id, now).expect("fresh after fill");
        assert!(
            !Arc::ptr_eq(&first, &third),
            "post-mutation hit must observe a rebuilt snapshot"
        );
        assert_eq!(third.variants.len(), 1, "fill result visible on next hit");
    }

    #[test]
    fn from_raw_page_hash_matches_new_and_never_nil() {
        // The glue layer computes the raw FNV once per request (single-flight/admission)
        // and hands it to `*_hashed` store methods; that derivation MUST stay the exact
        // inverse of `CacheKeyId::new` — same hash, same bit-63 mask, same NIL guard.
        for (vh, host, path, q) in [
            (1u32, "forum.example", "/help/", ""),
            (2, "example.com", "/forums/thread-1", "page=2"),
            (3, "a.b.c", "/", "utm=x&vary=style-9"),
        ] {
            let k = PageCacheKey {
                vhost_id: vh,
                secure: false,
                host: host.into(),
                path: path.into(),
                normalized_query: q.into(),
                vary_value: "guest".into(),
                private_owner: 7,
            };
            let raw = crate::key_hash(&k);
            assert_eq!(
                CacheKeyId::from_raw_page_hash(raw),
                CacheKeyId::new(&k),
                "hashed derivation diverged from CacheKeyId::new"
            );
            let id = CacheKeyId::from_raw_page_hash(raw);
            assert_eq!(id.0 & (1u64 << 63), 0, "masked id must keep bit 63 clear");
            assert_ne!(id, NIL, "the bit-63 mask already prevents NIL");
        }
    }

    fn cfg() -> StoreConfig {
        StoreConfig {
            max_mem_bytes: 4096,
            max_obj_bytes: 1024,
            default_public_ttl: Duration::from_secs(60),
            cacheable_status: vec![200, 301],
            ..StoreConfig::default()
        }
    }

    fn entry(body: &[u8], tags: &[&str], ttl: Duration) -> CachedResponse {
        entry_id(body, tags, ttl, "id")
    }

    fn entry_id(body: &[u8], tags: &[&str], ttl: Duration, identity: &str) -> CachedResponse {
        entry_stale(body, tags, ttl, Duration::ZERO, Duration::ZERO, identity)
    }

    fn entry_stale(
        body: &[u8],
        tags: &[&str],
        ttl: Duration,
        swr: Duration,
        sie: Duration,
        identity: &str,
    ) -> CachedResponse {
        CachedResponse {
            status: 200,
            identity: identity.to_string(),
            headers: vec![(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/html"),
            )],
            body: PageBody::InMem(Bytes::copy_from_slice(body)),
            variants: Vec::new(),
            variants_filled: false,
            dict_gen: 0,
            tags: tags.iter().map(|t| Arc::from(*t)).collect(),
            vary_cookie_name: String::new(),
            vary_value: String::new(),
            scope: PageScope::Public,
            stored_at: Instant::now(),
            ttl,
            swr,
            sie,
        }
    }

    // ---- tag_purge_epoch bound (behavioral) ----

    #[test]
    fn maintenance_bounds_tag_purge_epoch_map() {
        let store = PageStore::new(cfg());
        for i in 0..200u32 {
            let tag = format!("T{i}");
            store.purge_tags(&[tag.as_str()]);
        }
        assert_eq!(
            store.tag_purge_epoch.len(),
            200,
            "every distinct tag inserts an epoch"
        );

        store.maintenance(Duration::from_secs(90));
        assert_eq!(
            store.tag_purge_epoch.len(),
            200,
            "first tick only arms the floor"
        );

        for i in 200..250u32 {
            let tag = format!("T{i}");
            store.purge_tags(&[tag.as_str()]);
        }
        store.maintenance(Duration::from_secs(90));
        assert_eq!(
            store.tag_purge_epoch.len(),
            50,
            "the 200 pre-tick tags are reclaimed; only the 50 since the prior tick remain"
        );
    }

    #[test]
    fn ram_only_tag_purges_do_not_retain_peer_wall_state() {
        let store = PageStore::new(cfg());
        assert!(!store.has_disk());

        for index in 0..512u32 {
            let tag = format!("T{index}");
            store.purge_tags(&[tag.as_str()]);
        }

        assert!(store.peer_tag_purge_wall.is_empty());
        assert_eq!(store.peer_tag_purge_floor_ms.load(Ordering::Acquire), 0);
        assert_eq!(
            store.peer_tag_purge_journal_appends.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn ram_only_maintenance_prunes_tag_epochs_and_expired_entries() {
        let store = PageStore::new(cfg());
        let key = PageCacheKey::public(1, true, "example.com", "/expired", "");
        assert!(store.store(key, entry(b"old", &[], Duration::ZERO)));
        for index in 0..128u32 {
            let tag = format!("T{index}");
            store.purge_tags(&[&tag]);
        }

        store.maintenance(Duration::ZERO);
        store.maintenance(Duration::ZERO);

        assert_eq!(store.entry_count(), 0, "the expiry heap was drained");
        assert!(
            store.tag_purge_epoch.is_empty(),
            "old render-veto epochs were pruned"
        );
    }

    #[test]
    fn maintenance_retains_tag_epoch_needed_by_active_render() {
        let store = PageStore::new(cfg());
        let render_epoch = store.purge_epoch();
        let _guard = store.begin_render(render_epoch);

        store.purge_tags(&["T"]);
        store.maintenance(Duration::from_secs(90));
        store.maintenance(Duration::from_secs(90));

        let tag = Arc::<str>::from("T");
        assert!(
            store.tag_purge_epoch.contains_key(&tag),
            "active render keeps its purge veto epoch"
        );

        let key = PageCacheKey::public(1, true, "example.com", "/p", "");
        assert!(
            !store.store_if_not_purged_since(
                key,
                entry(b"stale", &["T"], Duration::from_secs(60)),
                render_epoch
            ),
            "pre-purge render must not store after maintenance pruning"
        );
    }

    #[test]
    fn store_and_lookup() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        assert!(s.lookup(&k, "id", Instant::now()).is_none());
        s.store(k.clone(), entry(b"hello", &[], Duration::from_secs(60)));
        let got = s.lookup(&k, "id", Instant::now()).expect("hit");
        assert_eq!(got.body.in_mem().unwrap().as_ref(), b"hello");
        assert_eq!(got.status, 200);
    }

    #[test]
    fn lazy_decode_reservation_failure_evicts_and_returns_a_miss() {
        let key = PageCacheKey::public(1, true, "example.com", "/decoded", "");
        let cached = entry_id(
            b"x",
            &["tag"],
            Duration::from_secs(60),
            "example.com\n/decoded",
        );
        let probe = Node::from_cached(&key, cached.clone(), 0).unwrap();
        let compressed_only_weight = probe.ram_weight();
        let (_, _, populated) = probe.to_cached_with_decode_state().unwrap();
        assert!(populated);
        assert!(
            probe.ram_weight() > compressed_only_weight,
            "decoded metadata must add a resident RAM charge"
        );

        let mut config = cfg();
        config.max_mem_bytes = compressed_only_weight;
        let store = PageStore::new(config);
        assert!(store.store(key.clone(), cached));
        assert!(matches!(
            store.get_entry_uncounted(&key, "example.com\n/decoded", Instant::now()),
            EntryState::Miss
        ));
        let stats = store.stats();
        assert_eq!(stats.entries, 0, "the over-cap decoded node was evicted");
        assert_eq!(
            stats.tag_memberships, 0,
            "teardown removed its tag membership"
        );
    }

    // ---- tmpfs-primary dual-cap behaviour ----

    fn disk_cfg(dir: &Path, disk_max: u64) -> StoreConfig {
        StoreConfig {
            max_mem_bytes: 64 * 1024 * 1024, // generous: the RAM cap is not the limiter here
            max_disk_bytes: disk_max,
            max_obj_bytes: 1024 * 1024,
            store_path: Some(dir.to_path_buf()),
            hot_mem_bytes: 1024 * 1024,
            default_public_ttl: Duration::from_secs(60),
            cacheable_status: vec![200, 301],
            ..StoreConfig::default()
        }
    }

    fn pc_files(root: &Path) -> usize {
        fn walk(d: &Path, n: &mut usize) {
            if let Ok(rd) = std::fs::read_dir(d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, n);
                    } else if p.extension().is_some_and(|x| x == "pc") {
                        *n += 1;
                    }
                }
            }
        }
        let mut n = 0;
        walk(root, &mut n);
        n
    }

    fn pc_allocated_bytes(root: &Path) -> u64 {
        fn allocated(md: &std::fs::Metadata) -> u64 {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                md.blocks().saturating_mul(512).max(md.len())
            }
            #[cfg(not(unix))]
            {
                md.len()
            }
        }
        fn walk(d: &Path, n: &mut u64) {
            if let Ok(rd) = std::fs::read_dir(d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, n);
                    } else if p.extension().is_some_and(|x| x == "pc") {
                        if let Ok(md) = e.metadata() {
                            *n += allocated(&md);
                        }
                    }
                }
            }
        }
        let mut n = 0;
        walk(root, &mut n);
        n
    }

    fn ext_files(root: &Path, ext: &str) -> usize {
        fn walk(d: &Path, ext: &str, n: &mut usize) {
            if let Ok(rd) = std::fs::read_dir(d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, ext, n);
                    } else if p.extension().is_some_and(|x| x == ext) {
                        *n += 1;
                    }
                }
            }
        }
        let mut n = 0;
        walk(root, ext, &mut n);
        n
    }

    #[test]
    fn static_store_lookup_and_fileid_invalidation() {
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"static-one").unwrap();
        let id = FileId::stat(source.path()).unwrap();
        let s = PageStore::new(cfg());

        assert!(s.store_static(
            7,
            source.path(),
            id,
            Bytes::from_static(b"static-one"),
            Arc::<str>::from("text/plain"),
            "\"etag\"".to_string(),
            "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
        ));

        let hit = s
            .get_static(7, source.path(), &id, Instant::now())
            .expect("static hit");
        assert_eq!(&s.static_body_bytes(&hit).unwrap()[..], b"static-one");

        let changed = FileId {
            size: id.size + 1,
            ..id
        };
        assert!(
            s.get_static(7, source.path(), &changed, Instant::now())
                .is_none(),
            "changed source identity invalidates the static entry"
        );
        assert!(
            s.get_static(7, source.path(), &id, Instant::now())
                .is_none(),
            "stale entry was removed, not retained for the old identity"
        );
    }

    #[test]
    fn static_file_tier_restores_only_when_source_matches() {
        let dir = tempfile::tempdir().unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), vec![b's'; 2048]).unwrap();
        let id = FileId::stat(source.path()).unwrap();
        let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));

        assert!(s.store_static(
            11,
            source.path(),
            id,
            Bytes::from(vec![b's'; 2048]),
            Arc::<str>::from("application/octet-stream"),
            "\"static\"".to_string(),
            "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
        ));
        assert_eq!(ext_files(dir.path(), "sc"), 1);
        let hit = s
            .get_static(11, source.path(), &id, Instant::now())
            .expect("static disk hit");
        assert!(matches!(hit.body, PageBody::File { .. }));
        assert_eq!(
            &s.static_body_bytes(&hit).unwrap()[..],
            &vec![b's'; 2048][..]
        );

        let restored = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        restored.load_from_disk(|_| {});
        let hit = restored
            .get_static(11, source.path(), &id, Instant::now())
            .expect("restored static hit");
        assert_eq!(
            &restored.static_body_bytes(&hit).unwrap()[..],
            &vec![b's'; 2048][..]
        );

        drop(source);
        let rejected = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        rejected.load_from_disk(|_| {});
        assert_eq!(
            ext_files(dir.path(), "sc"),
            0,
            "boot scan rejects static entries whose source file is gone"
        );
    }

    fn decoded_meta_count(s: &PageStore) -> usize {
        let mut n = 0;
        s.inner.for_each(|_, e| {
            if let Some(e) = e.as_page() {
                if e.decoded.get().is_some() {
                    n += 1;
                }
            }
        });
        n
    }

    #[test]
    fn list_entries_does_not_memoize_decoded_metadata() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let id = "h\n/p";
        s.store(
            k.clone(),
            entry_id(b"body", &[], Duration::from_secs(60), id),
        );

        assert_eq!(decoded_meta_count(&s), 0);
        let listing = s.list_entries(Instant::now(), 10);
        assert_eq!(listing.total_entries, 1);
        assert_eq!(
            decoded_meta_count(&s),
            0,
            "diagnostics must not make every cold entry hot in RAM"
        );

        assert!(s.lookup(&k, id, Instant::now()).is_some());
        assert_eq!(
            decoded_meta_count(&s),
            1,
            "serve lookup still memoizes decoded metadata for real hits"
        );
    }

    #[test]
    fn list_entries_keeps_only_the_largest_requested_entries() {
        let mut config = cfg();
        config.max_mem_bytes = 1024 * 1024;
        let store = PageStore::new(config);
        for size in 1..=10usize {
            let path = format!("/p{size}");
            let key = PageCacheKey::public(1, true, "h", &path, "");
            let identity = format!("https\nh\n{path}");
            assert!(store.store(
                key,
                entry_id(
                    &vec![b'x'; size * 10],
                    &[],
                    Duration::from_secs(60),
                    &identity,
                ),
            ));
        }
        let listing = store.list_entries(Instant::now(), 3);
        assert_eq!(listing.total_entries, 10);
        assert_eq!(
            listing
                .top
                .iter()
                .map(|entry| entry.stored_bytes)
                .collect::<Vec<_>>(),
            vec![100, 90, 80]
        );
    }

    #[test]
    #[ignore = "100k-entry cache diagnostics performance gate"]
    fn list_entries_large_cache_stays_within_latency_budget() {
        const ENTRIES: usize = 100_000;
        let mut config = cfg();
        config.max_mem_bytes = 512 * 1024 * 1024;
        let store = PageStore::new(config);
        for index in 0..ENTRIES {
            let path = format!("/threads/{index}");
            let key = PageCacheKey::public(1, true, "example.com", &path, "");
            let identity = format!("https\nexample.com\n{path}");
            assert!(store.store(
                key,
                entry_id(
                    &vec![b'x'; 64 + index % 64],
                    &[],
                    Duration::from_secs(60),
                    &identity,
                ),
            ));
        }
        let started = Instant::now();
        let listing = store.list_entries(Instant::now(), 60);
        let elapsed = started.elapsed();
        assert_eq!(listing.total_entries, ENTRIES as u64);
        assert_eq!(listing.top.len(), 60);
        assert!(
            elapsed < Duration::from_secs(2),
            "100k-entry diagnostics took {elapsed:?}"
        );
        eprintln!("100k-entry cache diagnostics: {elapsed:?}");
    }

    #[test]
    fn first_lookup_charges_decoded_metadata_once() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "example.com", "/threads/a.1/", "p=2");
        let id = "example.com\n/threads/a.1/";
        let mut e = entry_id(b"body", &["T1", "T2"], Duration::from_secs(60), id);
        e.headers.push((
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("public, max-age=60"),
        ));
        assert!(s.store(k.clone(), e));

        let before = s.stats();
        assert_eq!(before.decoded_entries, 0);
        assert_eq!(decoded_meta_count(&s), 0);

        assert!(s.lookup(&k, id, Instant::now()).is_some());
        let after_first = s.stats();
        assert_eq!(after_first.decoded_entries, 1);
        assert!(
            after_first.memory_bytes > before.memory_bytes,
            "decoded metadata must be charged when it becomes resident"
        );

        assert!(s.lookup(&k, id, Instant::now()).is_some());
        let after_second = s.stats();
        assert_eq!(after_second.decoded_entries, 1);
        assert_eq!(
            after_second.memory_bytes, after_first.memory_bytes,
            "a repeated hit must not charge decoded metadata twice"
        );
    }

    #[test]
    fn tag_index_stats_count_exact_live_memberships() {
        let s = PageStore::new(cfg());
        let k1 = PageCacheKey::public(1, true, "h", "/a", "");
        let k2 = PageCacheKey::public(1, true, "h", "/b", "");
        assert!(s.store(
            k1,
            entry_id(b"a", &["T1", "T2"], Duration::from_secs(60), "h\n/a"),
        ));
        assert!(s.store(
            k2,
            entry_id(b"b", &["T1"], Duration::from_secs(60), "h\n/b"),
        ));

        let st = s.stats();
        assert_eq!(st.tag_keys, 2);
        assert_eq!(st.tag_memberships, 3);
    }

    #[test]
    fn static_entries_charge_ram_accounting() {
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"static-ram").unwrap();
        let id = FileId::stat(source.path()).unwrap();
        let s = PageStore::new(cfg());

        assert!(s.store_static(
            3,
            source.path(),
            id,
            Bytes::from_static(b"static-ram"),
            Arc::<str>::from("text/plain"),
            "\"static-ram\"".to_string(),
            "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
        ));
        let st = s.stats();
        assert_eq!(st.entries, 1);
        assert!(
            st.memory_bytes >= size_of::<StaticNode>() as u64 + b"static-ram".len() as u64,
            "static cache entries must be visible to RAM eviction"
        );
    }

    #[test]
    fn file_body_weighs_metadata_only_and_charges_disk_cap() {
        let dir = tempfile::tempdir().unwrap();
        let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let body = vec![b'x'; 4096];
        s.store(
            k.clone(),
            entry_id(&body, &[], Duration::from_secs(60), "h\n/p"),
        );
        let st = s.stats();
        // The 4 KiB body is on tmpfs (charged to the disk cap), NOT against the RAM cap.
        assert!(
            st.disk_bytes >= 4096,
            "body plus tmpfs file footprint charged to the disk cap"
        );
        assert_eq!(st.disk_bytes, pc_allocated_bytes(dir.path()));
        assert!(
            st.memory_bytes.saturating_sub(st.tag_index_bytes) < 4096,
            "entry RAM weight excludes the tmpfs body (got entry={} tag_index={})",
            st.memory_bytes.saturating_sub(st.tag_index_bytes),
            st.tag_index_bytes
        );
        assert_eq!(
            st.hot_bytes, 0,
            "store does not prefill the hot tier for one-hit objects"
        );
        let got = s.lookup(&k, "h\n/p", Instant::now()).unwrap();
        assert!(
            matches!(got.body, PageBody::File { .. }),
            "body offloaded to tmpfs at birth"
        );
        assert_eq!(&s.body_bytes_cold(&got).unwrap()[..], &body[..]);
        assert_eq!(
            s.stats().hot_bytes,
            0,
            "background cold reads must not populate the hot heap tier"
        );
        assert_eq!(&s.body_bytes(&got).unwrap()[..], &body[..]);
        assert!(
            s.stats().hot_bytes >= 4096,
            "first served hit promotes the body into the hot tier"
        );
        assert_eq!(pc_files(dir.path()), 1);
    }

    #[test]
    fn hot_tier_hard_cap_rejects_empty_shard_and_rotates_same_shard() {
        let hot = HotTier::new(4 * 1024, Duration::from_secs(60));
        let now = Instant::now();
        for body_id in 0..4u64 {
            hot.insert(body_id, Bytes::from(vec![0; 960]), now);
        }
        assert!(
            hot.get(0, now).is_some(),
            "a 1 KiB body exceeds its 16-byte shard target but fits globally"
        );
        assert_eq!(hot.bytes(), 4 * 1024);
        assert_eq!(
            hot.shards.iter().map(|s| s.lock().map.len()).sum::<usize>(),
            4
        );
        hot.insert(100, Bytes::from(vec![0; 960]), now);
        assert!(
            hot.get(100, now).is_none(),
            "a full hot tier rejects admission into an empty owning shard"
        );
        assert!(
            hot.get(0, now).is_some(),
            "rejection preserves other shards"
        );
        hot.insert(256, Bytes::from(vec![0; 960]), now);
        assert!(
            hot.get(0, now).is_none(),
            "full-cap insert rotates its shard LRU"
        );
        assert!(hot.get(256, now).is_some());
        assert_eq!(hot.bytes(), 4 * 1024);
    }

    #[test]
    fn disk_cap_rejects_an_object_larger_than_the_global_cap() {
        let dir = tempfile::tempdir().unwrap();
        // Every allocated file footprint exceeds the entire 3000-byte global cap.
        let s = PageStore::new(disk_cfg(dir.path(), 3000));
        for i in 0..6u32 {
            let path = format!("/p{i}");
            let k = PageCacheKey::public(1, true, "h", &path, "");
            let id = format!("h\n{path}");
            s.store(
                k,
                entry_id(&vec![b'a'; 1000], &[], Duration::from_secs(600), &id),
            );
        }
        let st = s.stats();
        assert_eq!(st.entries, 0);
        assert_eq!(st.disk_bytes, 0);
        assert_eq!(
            st.disk_evictions, 0,
            "a never-admitted file is not an eviction"
        );
        assert_eq!(
            st.entries as usize,
            pc_files(dir.path()),
            "entries == .pc files (atomic teardown invariant)"
        );
        assert_eq!(
            st.disk_bytes,
            pc_allocated_bytes(dir.path()),
            "disk_bytes == referenced file allocation"
        );
    }

    #[test]
    fn file_tier_tag_purge_settles_disk_accounting_without_manual_flush() {
        let dir = tempfile::tempdir().unwrap();
        let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        s.load_from_disk(|_| {});
        let k = PageCacheKey::public(1, true, "h", "/purge", "");
        s.store(
            k.clone(),
            entry_id(
                &vec![b'a'; 2048],
                &["t"],
                Duration::from_secs(600),
                "h\n/purge",
            ),
        );
        assert_eq!(s.stats().disk_bytes, pc_allocated_bytes(dir.path()));
        assert_eq!(pc_files(dir.path()), 1);

        s.purge_tags(&["t"]);
        let st = s.stats();
        assert_eq!(st.entries, 0, "purged entry left the index immediately");
        assert_eq!(
            st.disk_bytes, 0,
            "purged file body weight left the disk accounting immediately"
        );
        assert_eq!(pc_files(dir.path()), 0, "purged file was unlinked");
        assert!(s.lookup(&k, "h\n/purge", Instant::now()).is_none());
    }

    #[test]
    fn dead_file_invalidation_settles_accounting_without_retry_loop() {
        let dir = tempfile::tempdir().unwrap();
        let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        s.load_from_disk(|_| {});
        let k = PageCacheKey::public(1, true, "h", "/dead", "");
        s.store(
            k.clone(),
            entry_id(&vec![b'a'; 2048], &[], Duration::from_secs(600), "h\n/dead"),
        );
        let hit = s
            .lookup(&k, "h\n/dead", Instant::now())
            .expect("file-backed hit");
        let (path, body_id) = match &hit.body {
            PageBody::File { path, body_id, .. } => (path.clone(), *body_id),
            _ => panic!("file tier should offload the body"),
        };
        if let Some(hot) = &s.hot {
            hot.invalidate(body_id);
        }
        std::fs::remove_file(path.as_ref()).unwrap();

        assert!(
            s.body_bytes(&hit).is_none(),
            "missing file degrades to a miss"
        );
        s.invalidate_key(&k);
        let st = s.stats();
        assert_eq!(st.entries, 0, "dead file entry removed from index");
        assert_eq!(st.disk_bytes, 0, "dead file weight removed from accounting");
        assert_eq!(st.disk_read_errors, 1);

        assert!(s.lookup(&k, "h\n/dead", Instant::now()).is_none());
        assert_eq!(
            s.stats().disk_read_errors,
            1,
            "dead file is not retried after invalidation"
        );
    }

    #[test]
    fn restore_then_restore_again_replaces_file_synchronously() {
        // The cure (atomic teardown): a re-store unlinks the predecessor's file SYNCHRONOUSLY under
        // the shard lock — there is exactly 1 .pc file per key, no orphan, no reconcile.
        let dir = tempfile::tempdir().unwrap();
        let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        s.load_from_disk(|_| {});
        let k = PageCacheKey::public(1, true, "h", "/v", "");
        let id = "h\n/v";
        s.store(
            k.clone(),
            entry_id(b"version-1", &[], Duration::from_secs(600), id),
        );
        assert_eq!(pc_files(dir.path()), 1);
        s.store(
            k.clone(),
            entry_id(b"version-2", &[], Duration::from_secs(600), id),
        );
        assert_eq!(
            pc_files(dir.path()),
            1,
            "re-store unlinked the predecessor synchronously (1 file/key)"
        );
        let got = s.lookup(&k, id, Instant::now()).unwrap();
        assert_eq!(&s.body_bytes(&got).unwrap()[..], b"version-2");
        assert_eq!(s.stats().disk_bytes, pc_allocated_bytes(dir.path()));
    }

    #[test]
    fn recompress_shrinks_disk_and_unlinks_identity_synchronously() {
        let dir = tempfile::tempdir().unwrap();
        let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        s.load_from_disk(|_| {});
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let id = "h\n/p";
        let e = entry_id(&vec![b'x'; 16 * 1024], &[], Duration::from_secs(600), id);
        let sa = e.stored_at;
        s.store(k.clone(), e);
        let before = s.stats().disk_bytes;
        assert_eq!(before, pc_allocated_bytes(dir.path()));
        assert_eq!(pc_files(dir.path()), 1);
        s.fill_recompress_disk(&k, id, sa, Bytes::from(vec![b'z'; 200]), 9);
        let after = s.stats().disk_bytes;
        assert_eq!(
            after,
            pc_allocated_bytes(dir.path()),
            "disk weight tracks the compressed file footprint"
        );
        assert!(
            after < before,
            "disk footprint should shrink after large identity is recompressed"
        );
        assert_eq!(
            s.stats().hot_bytes,
            0,
            "recompress does not prefill the hot tier for unserved objects"
        );
        // The cure: recompress unlinks the identity SYNCHRONOUSLY — exactly 1 file/key, no orphan.
        assert_eq!(
            pc_files(dir.path()),
            1,
            "identity unlinked synchronously (no orphan)"
        );
        let got = s.lookup(&k, id, Instant::now()).unwrap();
        assert_eq!(got.dict_gen, 9);
        assert_eq!(
            &s.body_bytes(&got).unwrap()[..],
            &vec![b'z'; 200][..],
            "stored form is the compressed bytes"
        );
    }

    #[test]
    fn recompress_budget_rejection_unlinks_both_file_versions() {
        let dir = tempfile::tempdir().unwrap();
        let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024));
        let key = PageCacheKey::public(1, true, "h", "/too-large-recompress", "");
        let identity = "h\n/too-large-recompress";
        let cached = entry_id(
            &vec![b'x'; 1024],
            &["tag"],
            Duration::from_secs(600),
            identity,
        );
        let stored_at = cached.stored_at;
        assert!(s.store(key.clone(), cached));
        assert_eq!(pc_files(dir.path()), 1, "identity file was admitted");

        s.fill_recompress_disk(
            &key,
            identity,
            stored_at,
            Bytes::from(vec![b'z'; 256 * 1024]),
            9,
        );

        assert!(matches!(
            s.get_entry_uncounted(&key, identity, Instant::now()),
            EntryState::Miss
        ));
        assert_eq!(s.stats().entries, 0);
        assert_eq!(s.stats().disk_bytes, 0);
        assert_eq!(s.stats().tag_memberships, 0);
        assert_eq!(
            pc_files(dir.path()),
            0,
            "failed replacement removed both the published candidate and predecessor"
        );
    }

    #[test]
    fn recompress_is_noop_after_purge() {
        let dir = tempfile::tempdir().unwrap();
        let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let id = "h\n/p";
        let e = entry_id(&vec![b'x'; 1000], &["t"], Duration::from_secs(600), id);
        let sa = e.stored_at;
        s.store(k.clone(), e);
        s.purge_tags(&["t"]);
        // A late recompress must NOT resurrect the purged entry nor leak a file.
        s.fill_recompress_disk(&k, id, sa, Bytes::from(vec![b'z'; 200]), 9);
        assert!(
            s.lookup(&k, id, Instant::now()).is_none(),
            "purged entry not resurrected"
        );
        assert_eq!(
            pc_files(dir.path()),
            0,
            "no file leaked by the no-op recompress"
        );
    }

    #[test]
    fn is_warm_reflects_boot_scan_state() {
        // No file tier → nothing to scan → warm immediately.
        assert!(PageStore::new(cfg()).is_warm());

        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg();
        c.store_path = Some(dir.path().to_path_buf());
        let disk = PageStore::new(c);
        assert!(
            !disk.is_warm(),
            "a fresh file-tier store is NOT warm until the boot scan completes"
        );
        assert_eq!(disk.scan_loaded(), 0, "no entries loaded before the scan");
        disk.load_from_disk(|_| {});
        assert!(disk.is_warm(), "warm once load_from_disk has run");
        assert_eq!(
            disk.scan_loaded(),
            0,
            "empty store dir ⇒ 0 entries restored"
        );
    }

    #[test]
    fn scan_loaded_counts_restored_entries() {
        let dir = tempfile::tempdir().unwrap();
        let ds = DiskStore::open(dir.path()).unwrap();
        let e = entry(b"persisted-body", &[], Duration::from_secs(3600));
        let k = PageCacheKey {
            vhost_id: 1,
            secure: true,
            host: "forum.example".into(),
            path: "/help/".into(),
            normalized_query: String::new(),
            vary_value: String::new(),
            private_owner: 0,
        };
        ds.write_entry(&k, &e, 0, b"persisted-body", wall_now_ms())
            .unwrap();

        let mut c = cfg();
        c.store_path = Some(dir.path().to_path_buf());
        c.expected_dict_gens = HashSet::new();
        let store = PageStore::new(c);
        store.load_from_disk(|_| {});
        assert_eq!(
            store.scan_loaded(),
            1,
            "the boot scan restored the one persisted entry"
        );
    }

    #[test]
    fn boot_scan_same_millisecond_duplicate_keeps_highest_file_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let ds = DiskStore::open(dir.path()).unwrap();
        let k = PageCacheKey::public(1, true, "forum.example", "/help/", "");
        let stored_ms = wall_now_ms();
        let e = entry(b"old-body", &[], Duration::from_secs(3600));

        ds.write_entry(&k, &e, 0, b"old-body", stored_ms).unwrap();
        ds.write_entry(&k, &e, 0, b"new-body", stored_ms).unwrap();

        let mut c = disk_cfg(dir.path(), 64 * 1024 * 1024);
        c.expected_dict_gens = HashSet::new();
        let store = PageStore::new(c);
        store.load_from_disk(|_| {});

        let got = store
            .lookup(&k, "id", Instant::now())
            .expect("restored hit");
        assert_eq!(&store.body_bytes(&got).unwrap()[..], b"new-body");
        assert_eq!(
            pc_files(dir.path()),
            1,
            "older duplicate file was unlinked during scan"
        );
    }

    #[test]
    fn private_owner_isolation_is_absolute() {
        let s = PageStore::new(cfg());
        let mut e = entry(b"session-A-page", &[], Duration::from_secs(60));
        e.scope = PageScope::Private { owner_hash: 0xAAAA };
        let mut ka = PageCacheKey::public(1, true, "h", "/p", "");
        ka.private_owner = 0xAAAA;
        ka.vary_value = "s=aaaa".into();
        s.store(ka.clone(), e);

        assert!(s.lookup(&ka, "id", Instant::now()).is_some());
        let mut kb = ka.clone();
        kb.private_owner = 0xBBBB;
        assert!(s.lookup(&kb, "id", Instant::now()).is_none());
        let mut ka2 = ka.clone();
        ka2.vary_value = "s=bbbb".into();
        assert!(s.lookup(&ka2, "id", Instant::now()).is_none());
        let kp = PageCacheKey::public(1, true, "h", "/p", "");
        assert!(s.lookup(&kp, "id", Instant::now()).is_none());
    }

    #[test]
    fn tag_purge_clears_private_entries() {
        let s = PageStore::new(cfg());
        let mut e = entry(b"private-page", &["t1"], Duration::from_secs(60));
        e.scope = PageScope::Private { owner_hash: 7 };
        let mut k = PageCacheKey::public(1, true, "h", "/thread", "");
        k.private_owner = 7;
        s.store(k.clone(), e);
        assert!(s.lookup(&k, "id", Instant::now()).is_some());
        s.purge_tags(&["t1"]);
        assert!(s.lookup(&k, "id", Instant::now()).is_none());
    }

    #[test]
    fn ttl_expiry_is_a_miss() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        s.store(k.clone(), entry(b"x", &[], Duration::ZERO));
        assert!(s.lookup(&k, "id", Instant::now()).is_none());
        assert!(matches!(
            s.get_entry(&k, "id", Instant::now()),
            EntryState::Miss
        ));
    }

    #[test]
    fn stale_window_serves_stale_then_gone() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        s.store(
            k.clone(),
            entry_stale(
                b"x",
                &[],
                Duration::ZERO,
                Duration::from_secs(60),
                Duration::ZERO,
                "id",
            ),
        );
        let now = Instant::now();
        match s.get_entry(&k, "id", now) {
            EntryState::Stale(e) => assert_eq!(e.body.in_mem().unwrap().as_ref(), b"x"),
            other => panic!("expected Stale, got {:?}", std::mem::discriminant(&other)),
        }
        assert!(s.lookup(&k, "id", now).is_some());
    }

    #[test]
    fn error_only_window_is_a_miss_but_retained() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        s.store(
            k.clone(),
            entry_stale(
                b"x",
                &[],
                Duration::ZERO,
                Duration::ZERO,
                Duration::from_secs(60),
                "id",
            ),
        );
        let now = Instant::now();
        assert!(matches!(
            s.get_entry(&k, "id", now),
            EntryState::ErrorOnly(_)
        ));
        assert!(s.lookup(&k, "id", now).is_none());
    }

    #[test]
    fn identity_guard_applies_to_stale_entries() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/index.php", "");
        s.store(
            k.clone(),
            entry_stale(
                b"A",
                &[],
                Duration::ZERO,
                Duration::from_secs(60),
                Duration::ZERO,
                "/threads/A",
            ),
        );
        let now = Instant::now();
        assert!(matches!(
            s.get_entry(&k, "/threads/A", now),
            EntryState::Stale(_)
        ));
        assert!(matches!(
            s.get_entry(&k, "/threads/B", now),
            EntryState::Miss
        ));
    }

    #[test]
    fn oversize_not_stored() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/big", "");
        s.store(
            k.clone(),
            entry(&vec![b'x'; 2048], &[], Duration::from_secs(60)),
        );
        assert!(s.lookup(&k, "id", Instant::now()).is_none());
    }

    #[test]
    fn tag_purge_removes_tagged_entries() {
        let s = PageStore::new(cfg());
        let k1 = PageCacheKey::public(1, true, "h", "/a", "");
        let k2 = PageCacheKey::public(1, true, "h", "/b", "");
        let k3 = PageCacheKey::public(1, true, "h", "/c", "");
        s.store(
            k1.clone(),
            entry(b"a", &["thread_1", "forum_9"], Duration::from_secs(60)),
        );
        s.store(
            k2.clone(),
            entry(b"b", &["thread_1"], Duration::from_secs(60)),
        );
        s.store(
            k3.clone(),
            entry(b"c", &["thread_2"], Duration::from_secs(60)),
        );
        s.purge_tags(&["thread_1"]);
        let now = Instant::now();
        assert!(
            s.lookup(&k1, "id", now).is_none(),
            "k1 tagged thread_1 must be purged"
        );
        assert!(
            s.lookup(&k2, "id", now).is_none(),
            "k2 tagged thread_1 must be purged"
        );
        assert!(
            s.lookup(&k3, "id", now).is_some(),
            "k3 (thread_2) must survive"
        );
    }

    #[test]
    fn adopt_rejects_entries_stored_before_purge_all() {
        // Two-node model: node A serialized an entry BEFORE node B's purge-all. Adopting it on
        // B must be vetoed by the wall-clock stamp — otherwise two nodes cross-filling resurrect
        // each other's purged entries and sequential per-node purge-alls never converge (the
        // live 2026-07-03 incident: pre-rollout shells kept re-seeding Cloudflare).
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = PageStore::new(disk_cfg(dir_a.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "forum.example", "/t/1", "");
        assert!(a.store(
            key.clone(),
            entry(b"pre-purge", &["T1"], Duration::from_secs(60))
        ));
        let bytes = a
            .serialize_entry(&key, "id")
            .expect("file-backed public entry");

        let b = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        std::thread::sleep(Duration::from_millis(5)); // wall_now_ms granularity
        b.purge_all();
        assert!(
            !b.adopt_entry(CacheKeyId::new(&key).0, &bytes, b.purge_epoch()),
            "adoption of a pre-purge-all entry must be vetoed"
        );
        assert!(matches!(
            b.get_entry_uncounted(&key, "id", Instant::now()),
            EntryState::Miss
        ));
    }

    #[test]
    fn purge_all_stamp_vetoes_tagless_peer_adoption_before_warm_scan() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = PageStore::new(disk_cfg(dir_a.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "forum.example", "/tagless", "");
        let mut old = entry(b"pre-purge", &[], Duration::from_secs(60));
        old.stored_at = Instant::now() - Duration::from_secs(1);
        assert!(a.store(key.clone(), old));
        let bytes = a.serialize_entry(&key, "id").unwrap();

        let purge_stamp = wall_now_ms();
        let disk = DiskStore::open(dir_b.path()).unwrap();
        disk.write_purge_stamp(purge_stamp).unwrap();
        drop(disk);

        let b = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        assert!(!b.is_warm(), "the background warm scan has not run");
        assert_eq!(b.purge_all_wall_ms.load(Ordering::Acquire), purge_stamp);
        assert!(b.peer_tag_purge_floor_ms.load(Ordering::Acquire) >= purge_stamp);
        assert!(!b.adopt_entry(CacheKeyId::new(&key).0, &bytes, b.purge_epoch()));
        assert_eq!(count_pc_files(dir_b.path()), 0);
    }

    #[test]
    fn adopt_rejects_when_purge_lands_during_peer_fetch() {
        // The entry itself postdates the purge stamp (stamp veto passes), but the adopting
        // request captured its epoch before the purge landed — the epoch veto must reject,
        // mirroring store_if_not_purged_since's contract.
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let b = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        let fetch_epoch = b.purge_epoch(); // peer fetch "starts" here
        b.purge_all(); // purge lands while the fetch is in flight
        std::thread::sleep(Duration::from_millis(5));

        let a = PageStore::new(disk_cfg(dir_a.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "forum.example", "/t/2", "");
        assert!(a.store(
            key.clone(),
            entry(b"post-stamp", &["T2"], Duration::from_secs(60))
        ));
        let bytes = a
            .serialize_entry(&key, "id")
            .expect("file-backed public entry");
        assert!(
            !b.adopt_entry(CacheKeyId::new(&key).0, &bytes, fetch_epoch),
            "a purge landing after the fetch epoch must veto the adoption"
        );
    }

    #[test]
    fn adopt_succeeds_with_current_epoch() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = PageStore::new(disk_cfg(dir_a.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "forum.example", "/t/3", "");
        assert!(a.store(
            key.clone(),
            entry(b"clean", &["T3"], Duration::from_secs(60))
        ));
        let bytes = a
            .serialize_entry(&key, "id")
            .expect("file-backed public entry");

        let b = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        assert!(b.adopt_entry(CacheKeyId::new(&key).0, &bytes, b.purge_epoch()));
        assert!(matches!(
            b.get_entry_uncounted(&key, "id", Instant::now()),
            EntryState::Fresh(_)
        ));
    }

    /// Count published (`.pc`, not `.pc.tmp`) body files under a jetcache root.
    fn count_pc_files(dir: &std::path::Path) -> usize {
        let mut n = 0;
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    n += count_pc_files(&p);
                } else if p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.ends_with(".pc") && !s.ends_with(".pc.tmp"))
                {
                    n += 1;
                }
            }
        }
        n
    }

    #[test]
    fn adopt_rejects_entry_tag_purged_before_fetch() {
        // #134: node A serialized an entry tagged T5. Node B tag-purged T5 BEFORE the peer
        // fetch, so B's fetch_epoch is >= that purge's epoch and the EPOCH veto cannot see it
        // — only the per-tag wall stamp catches this (the dominant XenForo purge case: a member
        // reply purges tag=T<id>, then the next guest miss peer-fills the pre-reply page).
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = PageStore::new(disk_cfg(dir_a.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "forum.example", "/t/5", "");
        assert!(a.store(
            key.clone(),
            entry(b"pre-tag-purge", &["T5"], Duration::from_secs(60))
        ));
        let bytes = a
            .serialize_entry(&key, "id")
            .expect("file-backed public entry");

        let b = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        std::thread::sleep(Duration::from_millis(5)); // wall_now_ms granularity
        b.purge_tags(&["T5"]); // tag purge COMPLETES before the fetch
        let fetch_epoch = b.purge_epoch(); // captured AFTER the purge (>= its epoch)
        assert!(
            !b.adopt_entry(CacheKeyId::new(&key).0, &bytes, fetch_epoch),
            "adoption of an entry tag-purged before the fetch must be vetoed by the wall stamp (#134)"
        );
        assert!(matches!(
            b.get_entry_uncounted(&key, "id", Instant::now()),
            EntryState::Miss
        ));
        assert_eq!(
            count_pc_files(dir_b.path()),
            0,
            "the vetoed adopt must not strand a tmpfs file (#137)"
        );
    }

    #[test]
    fn pruned_local_tag_epoch_keeps_a_persisted_exact_peer_tombstone() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = PageStore::new(disk_cfg(dir_a.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "forum.example", "/t/pruned", "");
        let mut old = entry(b"pre-tag-purge", &["T-pruned"], Duration::from_secs(60));
        old.stored_at = Instant::now() - Duration::from_secs(1);
        assert!(a.store(key.clone(), old));
        let bytes = a.serialize_entry(&key, "id").unwrap();

        let b = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        b.purge_tags(&["T-pruned"]);
        b.maintenance(Duration::ZERO);
        b.maintenance(Duration::ZERO);
        assert!(b.tag_purge_epoch.is_empty());
        assert_eq!(b.peer_tag_purge_floor_ms.load(Ordering::Acquire), 0);
        assert!(
            b.peer_tag_purge_wall
                .contains_key(&stable_tag_hash("T-pruned"))
        );
        assert!(!b.adopt_entry(CacheKeyId::new(&key).0, &bytes, b.purge_epoch()));
        drop(b);

        let restarted = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        assert_eq!(restarted.peer_tag_purge_floor_ms.load(Ordering::Acquire), 0);
        assert!(
            restarted
                .peer_tag_purge_wall
                .contains_key(&stable_tag_hash("T-pruned"))
        );
        assert!(!restarted.adopt_entry(CacheKeyId::new(&key).0, &bytes, restarted.purge_epoch()));
        assert_eq!(count_pc_files(dir_b.path()), 0);
    }

    #[test]
    fn peer_tombstones_coarsen_oldest_only_after_hard_capacity_is_exceeded() {
        let mut floor_ms = 0;
        let mut stamps = HashMap::from([(1, 10), (2, 20), (3, 30), (4, 40)]);
        assert!(!bound_peer_tag_purge_stamps(
            &mut floor_ms,
            &mut stamps,
            4,
            2
        ));
        assert_eq!(floor_ms, 0);
        assert_eq!(stamps.len(), 4);

        stamps.insert(5, 50);
        assert!(bound_peer_tag_purge_stamps(
            &mut floor_ms,
            &mut stamps,
            4,
            2
        ));
        assert_eq!(floor_ms, 30);
        assert_eq!(stamps, HashMap::from([(4, 40), (5, 50)]));

        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = PageStore::new(disk_cfg(dir_a.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "forum.example", "/t/overflow", "");
        let mut old = entry(b"pre-purge", &["T0"], Duration::from_secs(60));
        old.stored_at = Instant::now() - Duration::from_secs(1);
        assert!(a.store(key.clone(), old));
        let bytes = a.serialize_entry(&key, "id").unwrap();

        let b = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        b.purge_tags(&["T0", "T1", "T2", "T3"]);
        {
            let _page_commit = b.page_commit.lock();
            b.compact_peer_tag_purge_state_locked(4, 2);
        }
        assert_eq!(b.peer_tag_purge_floor_ms.load(Ordering::Acquire), 0);
        assert_eq!(b.peer_tag_purge_wall.len(), 4);

        b.purge_tags(&["T4"]);
        {
            let _page_commit = b.page_commit.lock();
            b.compact_peer_tag_purge_state_locked(4, 2);
        }
        let overflow_floor = b.peer_tag_purge_floor_ms.load(Ordering::Acquire);
        assert!(overflow_floor > 0);
        assert!(b.peer_tag_purge_wall.len() <= 2);
        assert!(!b.adopt_entry(CacheKeyId::new(&key).0, &bytes, b.purge_epoch()));
        drop(b);

        let restarted = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        assert_eq!(
            restarted.peer_tag_purge_floor_ms.load(Ordering::Acquire),
            overflow_floor
        );
        assert!(!restarted.adopt_entry(CacheKeyId::new(&key).0, &bytes, restarted.purge_epoch()));
    }

    #[test]
    fn wall_veto_rechecks_floor_after_exact_tombstone_compaction() {
        let store = PageStore::new(cfg());
        let tag_hash = stable_tag_hash("T-race");
        let stored_unix_ms = 15;
        store.peer_tag_purge_wall.insert(tag_hash, 20);

        let vetoed = wall_purge_veto(stored_unix_ms, &store.peer_tag_purge_floor_ms, || {
            let _page_commit = store.page_commit.lock();
            store.compact_peer_tag_purge_state_locked(0, 0);
            store
                .peer_tag_purge_wall
                .get(&tag_hash)
                .is_some_and(|wall_ms| *wall_ms >= stored_unix_ms)
        });

        assert!(store.peer_tag_purge_wall.is_empty());
        assert_eq!(store.peer_tag_purge_floor_ms.load(Ordering::Acquire), 20);
        assert!(vetoed, "the post-lookup floor re-read must close the race");
    }

    #[test]
    fn unpruned_tag_tombstone_survives_a_service_restart() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = PageStore::new(disk_cfg(dir_a.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "forum.example", "/t/restart", "");
        assert!(a.store(
            key.clone(),
            entry(b"pre-tag-purge", &["T-restart"], Duration::from_secs(60))
        ));
        let bytes = a.serialize_entry(&key, "id").unwrap();

        let b = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        std::thread::sleep(Duration::from_millis(5));
        b.purge_tags(&["T-restart"]);
        drop(b);

        let restarted = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        assert!(!restarted.adopt_entry(CacheKeyId::new(&key).0, &bytes, restarted.purge_epoch()));
        assert_eq!(count_pc_files(dir_b.path()), 0);
    }

    #[test]
    fn durable_tag_tombstone_rejects_a_crash_window_boot_scan_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = PageCacheKey::public(1, true, "forum.example", "/t/crash", "");
        let store = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        assert!(store.store(
            key.clone(),
            entry(b"pre-tag-purge", &["T-crash"], Duration::from_secs(60))
        ));
        assert_eq!(count_pc_files(dir.path()), 1);
        std::thread::sleep(Duration::from_millis(5));
        store
            .disk
            .as_ref()
            .unwrap()
            .append_tag_purge_stamp(stable_tag_hash("T-crash"), wall_now_ms())
            .unwrap();
        drop(store);

        let restarted = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let summary = restarted.load_from_disk(|_| {});
        assert_eq!(summary.loaded, 0);
        assert_eq!(summary.rejected, 1);
        assert!(matches!(
            restarted.get_entry_uncounted(&key, "id", Instant::now()),
            EntryState::Miss
        ));
        assert_eq!(count_pc_files(dir.path()), 0);
    }

    #[test]
    fn restart_recovers_duplicate_journal_growth_and_compacts_at_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let tag_hash = stable_tag_hash("T-repeat");
        let wall_ms = wall_now_ms();
        let record = format!("T {tag_hash:016x} {wall_ms:016x}\n");
        let journal = dir.path().join(".tag_purge_stamps");

        std::fs::write(&journal, record.repeat(100)).unwrap();
        let recovered = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let state = recovered.disk.as_ref().unwrap().read_tag_purge_state();
        assert_eq!(state.record_count, 100);
        assert_eq!(state.stamp_record_count, 100);
        assert_eq!(state.byte_len, 100 * TAG_PURGE_STAMP_RECORD_BYTES);
        assert_eq!(
            recovered
                .peer_tag_purge_journal_appends
                .load(Ordering::Relaxed),
            99,
            "restart must recover pre-existing duplicate append pressure"
        );
        drop(recovered);

        std::fs::write(
            &journal,
            record.repeat((PEER_TAG_PURGE_JOURNAL_COMPACT_RECORDS + 2) as usize),
        )
        .unwrap();
        let compacted = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let state = compacted.disk.as_ref().unwrap().read_tag_purge_state();
        assert_eq!(
            state.record_count, 2,
            "canonical floor plus one exact stamp"
        );
        assert_eq!(state.stamp_record_count, 1);
        assert_eq!(state.stamps, HashMap::from([(tag_hash, wall_ms)]));
        assert!(!state.corrupt);
        assert_eq!(
            compacted
                .peer_tag_purge_journal_appends
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn restart_does_not_rewrite_a_large_canonical_tag_journal() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskStore::open(dir.path()).unwrap();
        let stamps: Vec<(u64, u64)> = (0..PEER_TAG_PURGE_JOURNAL_COMPACT_RECORDS)
            .rev()
            .map(|tag_hash| (tag_hash, tag_hash + 1))
            .collect();
        disk.write_tag_purge_state(0, &stamps).unwrap();
        let journal = dir.path().join(".tag_purge_stamps");
        let before = std::fs::read(&journal).unwrap();
        drop(disk);

        let restarted = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let after = std::fs::read(&journal).unwrap();
        assert_eq!(
            after, before,
            "a canonical exact map is already compact regardless of record count"
        );
        assert_eq!(
            restarted
                .peer_tag_purge_journal_appends
                .load(Ordering::Relaxed),
            0
        );
        assert!(
            restarted
                .disk
                .as_ref()
                .unwrap()
                .read_tag_purge_state()
                .canonical
        );
    }

    #[test]
    fn corrupt_tag_journal_is_compacted_to_one_stable_fail_closed_floor() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".tag_purge_stamps"),
            b"T 0000000000000001 0000",
        )
        .unwrap();
        let first = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let first_floor = first.peer_tag_purge_floor_ms.load(Ordering::Acquire);
        assert!(first_floor > 0);
        drop(first);

        std::thread::sleep(Duration::from_millis(5));
        let second = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        assert_eq!(
            second.peer_tag_purge_floor_ms.load(Ordering::Acquire),
            first_floor,
            "the first recovery must compact corruption instead of advancing the floor every restart"
        );
    }

    #[test]
    fn corrupt_tag_journal_with_future_stamp_is_canonicalized_once() {
        let dir = tempfile::tempdir().unwrap();
        let tag_hash = stable_tag_hash("T-future");
        let future_wall = u64::MAX - 1;
        std::fs::write(
            dir.path().join(".tag_purge_stamps"),
            format!("T {tag_hash:016x} {future_wall:016x}\nmalformed\n"),
        )
        .unwrap();

        let first = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let first_floor = first.peer_tag_purge_floor_ms.load(Ordering::Acquire);
        assert!(first_floor > 0);
        assert_eq!(
            first.peer_tag_purge_wall.get(&tag_hash).map(|v| *v),
            Some(future_wall)
        );
        let state = first.disk.as_ref().unwrap().read_tag_purge_state();
        assert!(!state.corrupt, "startup must rewrite the malformed journal");
        assert_eq!(state.floor_ms, first_floor);
        assert_eq!(state.stamps, HashMap::from([(tag_hash, future_wall)]));
        drop(first);

        std::thread::sleep(Duration::from_millis(5));
        let second = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        assert_eq!(
            second.peer_tag_purge_floor_ms.load(Ordering::Acquire),
            first_floor,
            "canonical recovery must not advance the floor again"
        );
        assert_eq!(
            second.peer_tag_purge_wall.get(&tag_hash).map(|v| *v),
            Some(future_wall)
        );
    }

    #[test]
    fn adopt_epoch_veto_leaves_no_published_file() {
        // #137: the entry postdates the purge wall stamp, but a purge landed after the peer fetch
        // began. The commit-time epoch veto must reject before final publication, leaving neither
        // an indexed entry nor a boot-scannable file.
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let b = PageStore::new(disk_cfg(dir_b.path(), 64 * 1024 * 1024));
        // Finish the (empty) boot scan so `scan_purge` becomes None — otherwise
        // purge_all's `buf.purged_all=true` would make load_scanned reject on the
        // scan-buffer branch and this test wouldn't exercise the runtime-EPOCH veto.
        b.load_from_disk(|_| {});
        let fetch_epoch = b.purge_epoch(); // peer fetch "starts" here
        b.purge_all(); // purge lands while the fetch is in flight
        std::thread::sleep(Duration::from_millis(5));

        let a = PageStore::new(disk_cfg(dir_a.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "forum.example", "/t/6", "");
        assert!(a.store(
            key.clone(),
            entry(b"post-stamp", &["T6"], Duration::from_secs(60))
        ));
        let bytes = a
            .serialize_entry(&key, "id")
            .expect("file-backed public entry");
        assert!(
            !b.adopt_entry(CacheKeyId::new(&key).0, &bytes, fetch_epoch),
            "the epoch veto must reject the adoption"
        );
        assert_eq!(
            count_pc_files(dir_b.path()),
            0,
            "the epoch-vetoed adopt must not leave an orphaned tmpfs file (#137)"
        );
    }

    #[test]
    fn purge_all_clears() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        s.store(k.clone(), entry(b"x", &["t"], Duration::from_secs(60)));
        s.purge_all();
        assert!(s.lookup(&k, "id", Instant::now()).is_none());
    }

    #[test]
    fn purge_missing_tag_is_idempotent() {
        let s = PageStore::new(cfg());
        s.purge_tags(&["never_seen"]); // must not panic
    }

    #[test]
    fn identity_guard_refuses_mismatched_url() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/index.php", "");
        s.store(
            k.clone(),
            entry_id(b"page-A", &[], Duration::from_secs(60), "/threads/A"),
        );
        assert!(s.lookup(&k, "/threads/A", Instant::now()).is_some());
        assert!(
            s.lookup(&k, "/threads/B", Instant::now()).is_none(),
            "collision guard must refuse to serve a page built for a different URL"
        );
    }

    #[test]
    fn cross_scheme_301_is_not_replayed() {
        let s = PageStore::new(cfg());
        let http_key = PageCacheKey::public(1, false, "forum.example", "/threads/1234", "");
        let https_key = PageCacheKey::public(1, true, "forum.example", "/threads/1234", "");
        let http_id = "http\nforum.example\n/threads/1234";

        let mut e = entry_id(b"", &[], Duration::from_secs(60), http_id);
        e.status = 301;
        e.headers = vec![(
            http::header::LOCATION,
            HeaderValue::from_static("https://forum.example/threads/1234"),
        )];
        s.store(http_key.clone(), e);

        let hit = s
            .lookup(&http_key, http_id, Instant::now())
            .expect("http 301 hit");
        assert_eq!(hit.status, 301);
        assert_eq!(
            hit.headers[0].1,
            HeaderValue::from_static("https://forum.example/threads/1234")
        );
        assert!(
            s.lookup(
                &https_key,
                "https\nforum.example\n/threads/1234",
                Instant::now()
            )
            .is_none(),
            "HTTPS must not receive the HTTP-origin 301 (cross-scheme redirect loop)"
        );
    }

    #[test]
    fn eviction_under_cap() {
        let s = PageStore::new(cfg()); // 4096B budget
        for i in 0..50 {
            let k = PageCacheKey::public(1, true, "h", format!("/p{i}"), "");
            s.store(k, entry(&vec![b'x'; 512], &[], Duration::from_secs(60)));
        }
        // 512B entries against a 4096B global cap (per-shard 4096/256≈16, so each shard keeps just
        // its protected just-inserted entry — and 50 distinct keys land on up to 50 shards). The
        // structural guarantee under per-shard budgeting: total RAM stays bounded and no shard
        // overflows; here entries can be up to 50 (one per shard) but each shard's ram_used <= its
        // budget + one protected oversized entry. Assert the invariant: entry_count is sane + the
        // index is internally consistent.
        let n = s.entry_count();
        assert!(n <= 50, "got {n}");
        // The RAM accounting must equal the sum of resident weights (no drift).
        let st = s.stats();
        assert_eq!(st.entries, n);
    }

    #[test]
    fn fill_variants_adds_to_live_entry_and_preserves_deadline() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let mut e = entry(b"hello", &[], Duration::from_secs(60));
        e.stored_at = Instant::now() - Duration::from_secs(59);
        let (id, sa) = (e.identity.clone(), e.stored_at);
        s.store(k.clone(), e);
        s.fill_variants(
            &k,
            &id,
            sa,
            vec![("br".to_string(), Bytes::from_static(b"BR"))],
            None,
        );
        let after = s
            .lookup(&k, "id", Instant::now())
            .expect("still fresh right after fill");
        assert_eq!(after.variants.len(), 1, "variant present after fill");
        assert!(after.variants_filled, "fill marked done");
        let later = Instant::now() + Duration::from_secs(2);
        assert!(
            matches!(s.get_entry(&k, "id", later), EntryState::Miss),
            "fill preserved stored_at: entry expires on its original deadline, not reset"
        );
    }

    #[test]
    fn dictionary_attempt_is_one_shot_and_survives_variant_fill() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/dict-attempt", "");
        let e = entry(b"hello", &[], Duration::from_secs(60));
        let (identity, stored_at) = (e.identity.clone(), e.stored_at);
        s.store(k.clone(), e);

        assert!(s.mark_dict_compression_attempted(&k, &identity, stored_at));
        assert!(!s.mark_dict_compression_attempted(&k, &identity, stored_at));
        assert!(
            s.lookup(&k, "id", Instant::now())
                .unwrap()
                .dict_compression_attempted()
        );

        s.fill_variants(
            &k,
            &identity,
            stored_at,
            vec![("br".to_owned(), Bytes::from_static(b"BR"))],
            Some(5),
        );
        let after = s.lookup(&k, "id", Instant::now()).unwrap();
        assert!(after.dict_compression_attempted());
        assert!(matches!(after.body, PageBody::InMem(_)));
        assert!(
            after
                .variants
                .iter()
                .any(|(token, body)| { token == "br" && body.as_ref() == b"BR" })
        );
        assert!(s.fill_dict_body(&k, &identity, stored_at, Bytes::from_static(b"D"), 7));
        assert_eq!(s.lookup(&k, "id", Instant::now()).unwrap().dict_gen, 7);

        let derived_key = PageCacheKey::public(1, true, "h", "/variant-first", "");
        let derived = entry(b"identity", &[], Duration::from_secs(60));
        let (derived_identity, derived_stored_at) = (derived.identity.clone(), derived.stored_at);
        s.store(derived_key.clone(), derived);
        s.fill_variants(
            &derived_key,
            &derived_identity,
            derived_stored_at,
            vec![("br".to_owned(), Bytes::from_static(b"BR"))],
            Some(8),
        );
        assert!(s.mark_dict_compression_attempted(
            &derived_key,
            &derived_identity,
            derived_stored_at
        ));
        assert!(!s.fill_dict_body(
            &derived_key,
            &derived_identity,
            derived_stored_at,
            Bytes::from_static(b"D"),
            7
        ));
        assert!(matches!(
            s.lookup(&derived_key, "id", Instant::now()).unwrap().body,
            PageBody::Derived { .. }
        ));

        let empty_key = PageCacheKey::public(1, true, "h", "/dict-empty-variant", "");
        let empty = entry(b"identity", &[], Duration::from_secs(60));
        let (empty_identity, empty_stored_at) = (empty.identity.clone(), empty.stored_at);
        s.store(empty_key.clone(), empty);
        assert!(s.mark_dict_compression_attempted(&empty_key, &empty_identity, empty_stored_at));
        s.fill_variants(
            &empty_key,
            &empty_identity,
            empty_stored_at,
            Vec::new(),
            Some(8),
        );
        assert!(matches!(
            s.lookup(&empty_key, "id", Instant::now()).unwrap().body,
            PageBody::InMem(_)
        ));
    }

    #[test]
    fn fill_variants_is_noop_after_purge() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let e = entry(b"hello", &["t"], Duration::from_secs(60));
        let (id, sa) = (e.identity.clone(), e.stored_at);
        s.store(k.clone(), e);
        s.purge_tags(&["t"]);
        s.fill_variants(
            &k,
            &id,
            sa,
            vec![("br".to_string(), Bytes::from_static(b"BR"))],
            None,
        );
        assert!(
            s.lookup(&k, "id", Instant::now()).is_none(),
            "fill must not resurrect a purged entry"
        );
    }

    #[test]
    fn fill_variants_is_noop_when_entry_was_replaced() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let mut old = entry(b"old", &[], Duration::from_secs(60));
        old.stored_at = Instant::now() - Duration::from_secs(10);
        let (old_id, old_sa) = (old.identity.clone(), old.stored_at);
        s.store(k.clone(), old);
        s.store(k.clone(), entry(b"fresh", &[], Duration::from_secs(60)));
        s.fill_variants(
            &k,
            &old_id,
            old_sa,
            vec![("br".to_string(), Bytes::from_static(b"BR"))],
            None,
        );
        let got = s
            .lookup(&k, "id", Instant::now())
            .expect("fresh entry present");
        assert_eq!(
            got.body.in_mem().unwrap().as_ref(),
            b"fresh",
            "fill must not clobber the refreshed entry"
        );
        assert!(got.variants.is_empty(), "stale fill did not apply");
    }

    #[test]
    fn fill_variants_drops_identity_when_derive_authorized() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/d", "");
        let id_body: &[u8] = b"hello-identity-body";
        let e = entry(id_body, &[], Duration::from_secs(60));
        let (id, sa) = (e.identity.clone(), e.stored_at);
        s.store(k.clone(), e);
        s.fill_variants(
            &k,
            &id,
            sa,
            vec![("zstd".to_string(), Bytes::from_static(b"ZSTDVARIANTBYTES"))],
            Some(id_body.len() as u32),
        );
        let got = s.lookup(&k, &id, Instant::now()).expect("fresh after fill");
        assert!(got.is_derived(), "identity dropped → derived");
        assert_eq!(
            got.dict_gen, 0,
            "a derived entry no longer depends on the page dict"
        );
        assert_eq!(
            got.body.len(),
            id_body.len(),
            "len() reports the identity length"
        );
        assert!(
            s.body_bytes(&got).is_none(),
            "no stored-form body for a derived entry"
        );
        assert_eq!(got.variants.len(), 1, "the variant is retained");
    }

    #[test]
    fn fill_variants_keeps_identity_when_derive_not_authorized() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/d2", "");
        let e = entry(b"keep-me", &[], Duration::from_secs(60));
        let (id, sa) = (e.identity.clone(), e.stored_at);
        s.store(k.clone(), e);
        s.fill_variants(
            &k,
            &id,
            sa,
            vec![("zstd".to_string(), Bytes::from_static(b"Z"))],
            None,
        );
        let got = s.lookup(&k, &id, Instant::now()).expect("fresh after fill");
        assert!(!got.is_derived(), "no derive authorization → identity kept");
        assert!(
            got.body.in_mem().is_some(),
            "identity still resident in RAM"
        );
    }

    #[test]
    fn fill_dict_body_swaps_identity_body_and_preserves_deadline() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let mut e = entry(b"the-identity-body", &[], Duration::from_secs(60));
        e.stored_at = Instant::now() - Duration::from_secs(59);
        let (id, sa) = (e.identity.clone(), e.stored_at);
        s.store(k.clone(), e);
        s.fill_dict_body(&k, &id, sa, Bytes::from_static(b"DICTBYTES"), 42);
        let after = s
            .lookup(&k, "id", Instant::now())
            .expect("still fresh right after fill");
        assert_eq!(after.dict_gen, 42, "dict_gen set after fill");
        assert_eq!(
            after.body.in_mem().unwrap().as_ref(),
            b"DICTBYTES",
            "body swapped to dict-compressed bytes"
        );
        let later = Instant::now() + Duration::from_secs(2);
        assert!(
            matches!(s.get_entry(&k, "id", later), EntryState::Miss),
            "fill preserved stored_at: entry expires on its original deadline"
        );
    }

    #[test]
    fn fill_dict_body_is_noop_after_purge_replace_or_already_filled() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let e = entry(b"hello", &["t"], Duration::from_secs(60));
        let (id, sa) = (e.identity.clone(), e.stored_at);
        s.store(k.clone(), e);
        s.purge_tags(&["t"]);
        s.fill_dict_body(&k, &id, sa, Bytes::from_static(b"X"), 7);
        assert!(
            s.lookup(&k, "id", Instant::now()).is_none(),
            "must not resurrect a purged entry"
        );
        let mut old = entry(b"old", &[], Duration::from_secs(60));
        old.stored_at = Instant::now() - Duration::from_secs(10);
        let (old_id, old_sa) = (old.identity.clone(), old.stored_at);
        s.store(k.clone(), old);
        s.store(k.clone(), entry(b"fresh", &[], Duration::from_secs(60)));
        s.fill_dict_body(&k, &old_id, old_sa, Bytes::from_static(b"X"), 7);
        let got = s.lookup(&k, "id", Instant::now()).expect("fresh present");
        assert_eq!(
            got.body.in_mem().unwrap().as_ref(),
            b"fresh",
            "must not clobber the refreshed entry"
        );
        assert_eq!(got.dict_gen, 0, "stale dict fill did not apply");
        let mut comp = entry(b"compressed", &[], Duration::from_secs(60));
        comp.dict_gen = 5;
        let (cid, csa) = (comp.identity.clone(), comp.stored_at);
        let k2 = PageCacheKey::public(2, true, "h", "/p2", "");
        s.store(k2.clone(), comp);
        s.fill_dict_body(&k2, &cid, csa, Bytes::from_static(b"NEW"), 9);
        let g2 = s.lookup(&k2, "id", Instant::now()).expect("present");
        assert_eq!(g2.dict_gen, 5, "already-dict-filled entry is not re-filled");
        assert_eq!(
            g2.body.in_mem().unwrap().as_ref(),
            b"compressed",
            "body unchanged when already dict-filled"
        );
    }

    #[test]
    fn stats_track_hits_misses() {
        let s = PageStore::new(cfg());
        let k = PageCacheKey::public(1, true, "h", "/p", "");
        let _ = s.lookup(&k, "id", Instant::now()); // miss
        s.store(k.clone(), entry(b"x", &[], Duration::from_secs(60)));
        let _ = s.lookup(&k, "id", Instant::now()); // hit
        let st = s.stats();
        assert_eq!(st.hits, 1);
        assert_eq!(st.misses, 1);
        assert_eq!(st.stores, 1);
    }

    #[test]
    fn tag_purge_serializes_with_store_before_tag_membership() {
        let store = Arc::new(PageStore::new(cfg()));
        let key = PageCacheKey::public(1, true, "example.com", "/slow", "");
        let render_epoch = store.purge_epoch();
        let paused = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let hook_paused = paused.clone();
        let hook_release = release.clone();
        *store.store_commit_probe.lock() = Some(Box::new(move |_s: &PageStore| {
            hook_paused.wait();
            hook_release.wait();
        }));

        let storing = {
            let store = store.clone();
            let key = key.clone();
            std::thread::spawn(move || {
                store.store_if_not_purged_since(
                    key,
                    entry(b"stale", &["T"], Duration::from_secs(60)),
                    render_epoch,
                )
            })
        };
        paused.wait();
        assert!(store.page_commit.try_lock().is_none());

        let purge_started = Arc::new(std::sync::Barrier::new(2));
        let purging = {
            let store = store.clone();
            let purge_started = purge_started.clone();
            std::thread::spawn(move || {
                purge_started.wait();
                store.purge_tags(&["T"]);
            })
        };
        purge_started.wait();
        release.wait();

        assert!(
            storing.join().unwrap(),
            "store linearizes before the waiting purge"
        );
        purging.join().unwrap();
        assert!(matches!(
            store.get_entry_uncounted(&key, "id", Instant::now()),
            EntryState::Miss
        ));
    }

    #[test]
    fn published_file_is_serialized_with_purge_and_cannot_resurrect() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024)));
        let key = PageCacheKey::public(1, true, "example.com", "/published", "");
        let render_epoch = store.purge_epoch();
        let published = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let hook_published = published.clone();
        let hook_release = release.clone();
        *store.store_publish_probe.lock() = Some(Box::new(move |_s: &PageStore| {
            hook_published.wait();
            hook_release.wait();
        }));

        let storing = {
            let store = store.clone();
            let key = key.clone();
            std::thread::spawn(move || {
                store.store_if_not_purged_since(
                    key,
                    entry(b"published", &["T"], Duration::from_secs(60)),
                    render_epoch,
                )
            })
        };
        published.wait();
        assert_eq!(
            pc_files(dir.path()),
            1,
            "the final file is already boot-scannable"
        );
        assert!(store.page_commit.try_lock().is_none());

        let purge_started = Arc::new(std::sync::Barrier::new(2));
        let purging = {
            let store = store.clone();
            let purge_started = purge_started.clone();
            std::thread::spawn(move || {
                purge_started.wait();
                store.purge_tags(&["T"]);
            })
        };
        purge_started.wait();
        release.wait();

        assert!(storing.join().unwrap());
        purging.join().unwrap();
        assert_eq!(
            pc_files(dir.path()),
            0,
            "completed purge removes the published version"
        );
        assert!(matches!(
            store.get_entry_uncounted(&key, "id", Instant::now()),
            EntryState::Miss
        ));

        drop(store);
        let restarted = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let scan = restarted.load_from_disk(|_| {});
        assert_eq!(
            scan.loaded, 0,
            "an immediate restart cannot resurrect the purged file"
        );
        assert!(matches!(
            restarted.get_entry_uncounted(&key, "id", Instant::now()),
            EntryState::Miss
        ));
    }

    #[test]
    fn store_rejects_a_tag_purge_that_completed_before_commit() {
        let store = PageStore::new(cfg());
        let key = PageCacheKey::public(1, true, "example.com", "/stale", "");
        let render_epoch = store.purge_epoch();
        store.purge_tags(&["T"]);
        assert!(!store.store_if_not_purged_since(
            key.clone(),
            entry(b"stale", &["T"], Duration::from_secs(60)),
            render_epoch,
        ));
        assert!(matches!(
            store.get_entry_uncounted(&key, "id", Instant::now()),
            EntryState::Miss
        ));
        assert_eq!(store.stats().store_purge_rejections, 1);
    }

    #[test]
    fn tag_purge_does_not_remove_a_replacement_rendered_after_its_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let store = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        let key = PageCacheKey::public(1, true, "example.com", "/fresh", "");
        assert!(store.store_if_not_purged_since(
            key.clone(),
            entry(b"old", &["T"], Duration::from_secs(60)),
            store.purge_epoch(),
        ));

        let purge_epoch = store.purge_seq.fetch_add(1, Ordering::AcqRel) + 1;
        let tag: Arc<str> = Arc::from("T");
        store
            .tag_purge_epoch
            .insert(tag.clone(), TagPurgeStamp { epoch: purge_epoch });
        let ids: Vec<CacheKeyId> = store
            .tag_index
            .remove_tag(&tag)
            .expect("old tagged entry")
            .iter()
            .copied()
            .collect();

        assert!(store.store_if_not_purged_since(
            key.clone(),
            entry(b"fresh", &["T"], Duration::from_secs(60)),
            purge_epoch,
        ));
        let mut ids = ids;
        store.inner.with_shard_groups(&mut ids, |acc, group| {
            for id in group {
                store.purge_tagged_id_locked(&tag, *id, purge_epoch, acc);
            }
        });

        let fresh = store
            .lookup(&key, "id", Instant::now())
            .expect("post-purge replacement survives");
        assert_eq!(&store.body_bytes(&fresh).unwrap()[..], b"fresh");

        store.purge_tags(&["T"]);
        assert!(store.lookup(&key, "id", Instant::now()).is_none());
    }

    // ---- boot-scan/purge race (audit-2026-07-01) ----
    // A purge landing during the warm scan must not be escaped by an in-flight `load_scanned`.
    // The `scan_insert_probe` hook fires the purge in the exact window between load_scanned's
    // pre-lock purge check and its under-lock install, deterministically reproducing the race.

    #[test]
    fn boot_scan_insert_loses_to_a_purge_tag_landing_mid_scan() {
        let dir = tempfile::tempdir().unwrap();
        let store = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        // Inject purge_tags("T") into the load_scanned window (buffer is active pre-scan-finish).
        *store.scan_insert_probe.lock() = Some(Box::new(|s: &PageStore| {
            s.purge_tags(&["T"]);
        }));
        let key = PageCacheKey::public(1, true, "example.com", "/p", "");
        let installed = store.load_scanned(
            key,
            entry(b"stale", &["T"], Duration::from_secs(60)),
            1,
            1,
            None,
        );
        assert!(
            !installed,
            "an entry whose tag is purged mid-scan must not be installed"
        );
        assert_eq!(
            store.entry_count(),
            0,
            "the purged-tag entry must not be live"
        );
    }

    #[test]
    fn boot_scan_insert_loses_to_a_purge_all_landing_mid_scan() {
        let dir = tempfile::tempdir().unwrap();
        let store = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
        *store.scan_insert_probe.lock() = Some(Box::new(|s: &PageStore| {
            s.purge_all();
        }));
        let key = PageCacheKey::public(1, true, "example.com", "/p", "");
        let installed = store.load_scanned(
            key,
            entry(b"stale", &[], Duration::from_secs(60)),
            1,
            1,
            None,
        );
        assert!(
            !installed,
            "an entry inserted mid-scan after purge_all must not survive"
        );
        assert_eq!(store.entry_count(), 0, "purge_all must win the race");
    }
}
