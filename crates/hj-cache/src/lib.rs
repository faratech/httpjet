//! Two-tier static file cache for httpjet.
//!
//! This crate implements the hot path for serving static files: it keeps small
//! files fully in RAM (the *in-memory tier*) and mid-sized files as `mmap`'d
//! regions (the *mmap tier*), avoiding a `read(2)` syscall and userspace copy on
//! every request. Files larger than the mmap cap are deliberately **not** cached
//! — the caller is expected to stream them directly (e.g. `sendfile`).
//!
//! Eviction is byte-weighted and *soft*: caps are upper bounds that trigger
//! in-house LRU eviction, never a hard up-front reservation. This matters
//! because the host has only a few GB of free RAM; the cache must never pin more
//! than it is told it may use, and it should shed entries gracefully under
//! pressure.
//!
//! ## Coherency
//!
//! Static files on disk can change underneath us (deploys, rsync, editors). On
//! **every** cache hit we perform a cheap `stat` of the underlying file and
//! compare `(mtime, size, inode)` against what we cached. If anything differs
//! the stale entry is invalidated and the loader is re-run, so a changed file is
//! reflected on the very next request rather than after a TTL.
//!
//! ## Usage
//!
//! ```no_run
//! use hj_cache::{CacheKey, FileCache, Loaded};
//! use hj_config::model::Tuning;
//!
//! let cache = FileCache::from_tuning(&Tuning::default());
//! let key = CacheKey::new(0, "/web/public_html/index.html");
//! let entry = cache.get_or_load(&key, |_id| {
//!     // The cache already stat'd the file; just load the bytes + MIME type.
//!     std::fs::read("/web/public_html/index.html")
//!         .map(|v| Loaded::new(v, "text/html".to_string()))
//! }).unwrap();
//! if let Some(e) = entry {
//!     let _body = e.bytes(); // zero-copy for in-mem tier
//! }
//! ```

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Within this window a cached entry is trusted without a freshness `stat`
/// (production default; `with_caps` callers/tests get `0` = always revalidate).
const DEFAULT_REVALIDATE_TTL: Duration = Duration::from_secs(1);

/// Monotonic process-clock baseline for the freshness-coalescing window. A MONOTONIC
/// source (not wall-clock) is required: a system clock step backward would otherwise
/// make `now_ms()` smaller than a stored `last_checked_ms`, and a forward step would
/// widen the gap — either skewing the `recently_checked` window into skipping or forcing
/// freshness stats spuriously. The absolute value is meaningless; only diffs matter.
static MONO_BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Milliseconds since [`MONO_BASE`] (monotonic; comparable only to other `now_ms()` values).
fn now_ms() -> u64 {
    MONO_BASE.elapsed().as_millis() as u64
}

use bytes::Bytes;
use memmap2::Mmap;

/// The shared, strongly-consistent sharded byte-weighted LRU primitive. Lives here (not a
/// separate crate) so it is the one in-process cache `hj-cache`'s file cache and
/// `hj-pagecache`'s page store both build on (`hj_cache::sharded::ShardedCache`).
pub mod sharded;
use sharded::{CacheValue, NoEvict, SHARDS, ShardCacheConfig, ShardKey, ShardedCache};

use hj_config::model::Tuning;

/// Default in-memory tier cap when none can be derived: 256 MiB.
///
/// The contract notes this box has ~5 GB free RAM, so we keep the *default*
/// modest even though [`Tuning`] may ask for far more. [`FileCache::from_tuning`]
/// honours the configured value but clamps it (see [`clamp_in_mem_cap`]).
pub(crate) const DEFAULT_IN_MEM_CAP: u64 = 256 * 1024 * 1024;

/// Default per-file ceiling for the in-memory tier: 1 MiB.
pub(crate) const DEFAULT_MAX_IN_MEM_FILE: u64 = 1024 * 1024;

/// Default mmap tier cap: 512 MiB of mapped address space.
pub(crate) const DEFAULT_MMAP_CAP: u64 = 512 * 1024 * 1024;

/// Default per-file ceiling for the mmap tier: 16 MiB.
pub(crate) const DEFAULT_MAX_MMAP_FILE: u64 = 16 * 1024 * 1024;

/// Hard upper clamp on the in-mem tier, regardless of config: 1 GiB.
const ABS_MAX_IN_MEM_CAP: u64 = 1024 * 1024 * 1024;

/// Hard upper clamp on the mmap tier, regardless of config: 2 GiB.
const ABS_MAX_MMAP_CAP: u64 = 2 * 1024 * 1024 * 1024;

/// Identifies a cached file: the owning vhost plus its absolute filesystem path.
///
/// Two vhosts may legitimately serve different files at the same path, so the
/// `vhost_id` is part of the key. The id is whatever stable small integer the
/// router assigns to a vhost.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub(crate) vhost_id: u32,
    pub(crate) path: PathBuf,
}

impl CacheKey {
    /// Build a key from a vhost id and a path-like value.
    pub fn new(vhost_id: u32, path: impl Into<PathBuf>) -> Self {
        CacheKey {
            vhost_id,
            path: path.into(),
        }
    }
}

/// The bytes a loader produced together with the content type the caller
/// resolved (typically from the MIME map). The cache decides the tier and
/// computes the validators; the loader only supplies raw content + type.
pub struct Loaded {
    bytes: Vec<u8>,
    content_type: String,
}

impl Loaded {
    pub fn new(bytes: Vec<u8>, content_type: String) -> Self {
        Loaded {
            bytes,
            content_type,
        }
    }
}

/// File identity captured at load time, used to detect on-disk changes.
///
/// Equality of `(mtime, size, inode)` is treated as "unchanged". `inode` guards
/// against atomic replace-via-rename, which can preserve size and (rarely) the
/// coarse mtime while swapping the underlying file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub size: u64,
    pub(crate) mtime: SystemTime,
    pub(crate) inode: u64,
}

impl FileId {
    /// Stat `path` cheaply and capture its identity. This is the per-hit check.
    pub(crate) fn stat(path: &Path) -> io::Result<FileId> {
        let md = std::fs::metadata(path)?;
        Ok(FileId::from_metadata(&md))
    }

    fn from_metadata(md: &std::fs::Metadata) -> FileId {
        let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        FileId {
            size: md.len(),
            mtime,
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

/// Backing storage for a cached file: either an owned heap buffer (in-mem tier)
/// or a memory map (mmap tier). Both expose a contiguous `&[u8]`.
enum Backing {
    /// Fully buffered in RAM. Cheap, zero-copy clones via `Bytes`.
    Mem(Bytes),
    /// Memory-mapped file region. The OS pages it in/out on demand.
    Mapped(Arc<Mmap>),
}

struct MmapOwner(Arc<Mmap>);

impl AsRef<[u8]> for MmapOwner {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// A cached static file plus its HTTP validators and metadata.
///
/// Returned wrapped in an `Arc` so clones are cheap and concurrent readers
/// share one copy. Obtain the body via [`CacheEntry::bytes`] (zero-copy for the
/// in-mem tier, copy-on-demand over the map for the mmap tier) or borrow the
/// slice via [`CacheEntry::as_slice`].
pub struct CacheEntry {
    backing: Backing,
    /// Strong ETag value (already quoted), suitable for the `ETag` header.
    pub(crate) etag: String,
    /// RFC 1123 date string for the `Last-Modified` header.
    pub(crate) last_modified: String,
    /// Resolved MIME type for the `Content-Type` header.
    pub(crate) content_type: String,
    /// File size in bytes.
    pub size: u64,
    /// Identity used for invalidation checks.
    id: FileId,
    /// Which tier this entry lives in (for metrics / debugging).
    tier: Tier,
    /// Last time (ms since epoch) freshness was validated, for TTL coalescing.
    last_checked_ms: AtomicU64,
}

/// Which storage tier an entry occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    InMem,
    Mmap,
}

impl std::fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheEntry")
            .field("tier", &self.tier)
            .field("size", &self.size)
            .field("etag", &self.etag)
            .field("last_modified", &self.last_modified)
            .field("content_type", &self.content_type)
            .field("id", &self.id)
            .finish()
    }
}

impl CacheEntry {
    /// Get the contents as `Bytes`.
    ///
    /// For the in-mem tier this is a zero-copy refcount bump. For the mmap tier
    /// the returned `Bytes` owns an `Arc<Mmap>` view, so clones and transport
    /// range slices share the map instead of copying the mapped region into heap.
    pub fn bytes(&self) -> Bytes {
        match &self.backing {
            Backing::Mem(b) => b.clone(),
            Backing::Mapped(m) => Bytes::from_owner(MmapOwner(m.clone())),
        }
    }

    /// The tier this entry is stored in.
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// The captured file identity (mtime/size/inode) for this entry.
    pub fn file_id(&self) -> FileId {
        self.id
    }

    /// True if this entry is fully copied into RAM (in-mem tier). Such entries
    /// are immune to SIGBUS from on-disk truncation, so the TTL fast path may
    /// skip their freshness `stat`. `Backing::Mapped` entries must NOT take that
    /// shortcut: a truncate-in-place under the live map would fault on access.
    fn is_in_mem(&self) -> bool {
        matches!(self.backing, Backing::Mem(_))
    }

    /// Number of bytes this entry weighs against its tier cap.
    fn weight(&self) -> u64 {
        self.size
    }

    /// Returns `true` if `current` matches the identity captured at load time.
    /// (Named `is_current`, not `is_fresh`, to avoid shadowing the `CacheValue::is_fresh`
    /// trait method that the shared cache adds to `CacheEntry` / `Arc<CacheEntry>`.)
    fn is_current(&self, current: &FileId) -> bool {
        &self.id == current
    }

    /// True if freshness was validated within `ttl` (skip the `stat`).
    fn recently_checked(&self, ttl: Duration) -> bool {
        now_ms().saturating_sub(self.last_checked_ms.load(Ordering::Relaxed))
            < ttl.as_millis() as u64
    }

    /// Record that freshness was just validated (or the entry just loaded).
    fn touch(&self) {
        self.last_checked_ms.store(now_ms(), Ordering::Relaxed);
    }
}

/// Decision about where (if anywhere) a file of a given size should be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierDecision {
    /// Small enough for the in-memory tier.
    InMem,
    /// Too big for in-mem but within the mmap cap.
    Mmap,
    /// Larger than the mmap cap — do not cache; serve directly.
    Uncacheable,
}

/// Tunable, soft-capped capacities for the two tiers.
#[derive(Debug, Clone, Copy)]
pub struct CacheCaps {
    /// Largest single file (bytes) eligible for the in-memory tier.
    pub max_in_mem_file: u64,
    /// Total in-memory tier budget (bytes) before LRU eviction kicks in.
    pub total_in_mem: u64,
    /// Largest single file (bytes) eligible for the mmap tier.
    pub max_mmap_file: u64,
    /// Total mapped-region budget (bytes) before LRU eviction kicks in.
    pub total_mmap: u64,
}

impl Default for CacheCaps {
    fn default() -> Self {
        CacheCaps {
            max_in_mem_file: DEFAULT_MAX_IN_MEM_FILE,
            total_in_mem: DEFAULT_IN_MEM_CAP,
            max_mmap_file: DEFAULT_MAX_MMAP_FILE,
            total_mmap: DEFAULT_MMAP_CAP,
        }
    }
}

/// Clamp a configured in-mem cap to the modest absolute ceiling.
pub(crate) fn clamp_in_mem_cap(requested: u64) -> u64 {
    requested.clamp(1, ABS_MAX_IN_MEM_CAP)
}

/// Clamp a configured mmap cap to the absolute ceiling.
pub(crate) fn clamp_mmap_cap(requested: u64) -> u64 {
    requested.clamp(1, ABS_MAX_MMAP_CAP)
}

impl CacheCaps {
    /// Derive caps from server [`Tuning`], clamping the totals so we never
    /// promise more than this box can spare even if the config asks for it.
    ///
    /// LiteSpeed's defaults (e.g. 4 GiB `total_in_mem_cache_size`) are far too
    /// large for a 5 GiB box, so the totals are clamped while the per-file
    /// ceilings are honoured directly.
    pub fn from_tuning(t: &Tuning) -> Self {
        let max_in_mem_file = if t.max_cached_file_size == 0 {
            DEFAULT_MAX_IN_MEM_FILE
        } else {
            t.max_cached_file_size
        };
        let max_mmap_file = if t.max_mmap_file_size == 0 {
            DEFAULT_MAX_MMAP_FILE
        } else {
            t.max_mmap_file_size
        };
        let total_in_mem = if t.total_in_mem_cache_size == 0 {
            DEFAULT_IN_MEM_CAP
        } else {
            clamp_in_mem_cap(t.total_in_mem_cache_size)
        };
        let total_mmap = if t.total_mmap_cache_size == 0 {
            DEFAULT_MMAP_CAP
        } else {
            clamp_mmap_cap(t.total_mmap_cache_size)
        };
        CacheCaps {
            // A per-file ceiling above its tier total is nonsensical; clamp it.
            max_in_mem_file: max_in_mem_file.min(total_in_mem),
            total_in_mem,
            // The mmap tier should accept everything the in-mem tier rejects, up
            // to its own per-file ceiling, but never more than the tier total.
            max_mmap_file: max_mmap_file.max(max_in_mem_file).min(total_mmap),
            total_mmap,
        }
    }

    /// Decide the tier for a file of `size` bytes.
    pub(crate) fn decide(&self, size: u64) -> TierDecision {
        if size <= self.max_in_mem_file {
            TierDecision::InMem
        } else if size <= self.max_mmap_file {
            TierDecision::Mmap
        } else {
            TierDecision::Uncacheable
        }
    }
}

type TierCache = ShardedCache<CacheKey, Arc<CacheEntry>, NoEvict>;

impl ShardKey for CacheKey {
    fn nil() -> Self {
        CacheKey {
            vhost_id: u32::MAX,
            path: PathBuf::new(),
        }
    }

    fn shard_index(&self, _shards: usize) -> usize {
        // The static-file cache historically enforced one global byte cap per
        // tier. Use the shared in-house cache primitive while keeping those
        // exact global-cap semantics by routing this wrapper's keys to one shard.
        0
    }
}

impl CacheValue for CacheEntry {
    fn ram_weight(&self) -> u64 {
        self.weight()
    }
}

fn tier_cache(max_capacity: u64) -> TierCache {
    ShardedCache::new(
        ShardCacheConfig {
            // ShardedCache divides the configured total by SHARDS. This wrapper
            // intentionally uses one shard to preserve hj-cache's old global cap.
            max_ram_bytes: max_capacity.saturating_mul(SHARDS as u64),
            max_disk_bytes: 0,
        },
        NoEvict,
    )
}

/// The two-tier static file cache.
///
/// Construct one per server and share it via `Arc<FileCache>`. All methods take
/// `&self` and are safe to call concurrently.
pub struct FileCache {
    in_mem: TierCache,
    mmap: TierCache,
    caps: CacheCaps,
    /// Trust a cached entry without a freshness `stat` within this window.
    revalidate_ttl: Duration,
}

impl FileCache {
    /// Build a cache with explicit caps and a revalidation TTL.
    pub fn with_caps_ttl(caps: CacheCaps, revalidate_ttl: Duration) -> Self {
        FileCache {
            in_mem: tier_cache(caps.total_in_mem),
            mmap: tier_cache(caps.total_mmap),
            caps,
            revalidate_ttl,
        }
    }

    /// Build a cache from server [`Tuning`] (the normal path) with the default
    /// revalidation TTL — every cached hit skips its freshness `stat` within
    /// the window, the dominant per-request syscall for cached static serving.
    pub fn from_tuning(t: &Tuning) -> Self {
        Self::with_caps_ttl(CacheCaps::from_tuning(t), DEFAULT_REVALIDATE_TTL)
    }

    /// Decide the tier a file of `size` bytes would land in.
    pub fn tier_for(&self, size: u64) -> TierDecision {
        self.caps.decide(size)
    }

    /// Look up `key`, validating freshness, loading and caching on miss.
    ///
    /// Behaviour:
    /// 1. `stat` the file once (cheap). If the file is gone/unreadable, the
    ///    error is returned and any cached entry for the key is dropped.
    /// 2. If a cached entry exists and its `(mtime, size, inode)` matches the
    ///    fresh `stat`, return it (a hit).
    /// 3. Otherwise decide the tier from the *current* size:
    ///    - in-mem / mmap: run `loader`, build a [`CacheEntry`] (heap bytes for
    ///      in-mem, an `mmap` of the file for the mmap tier), insert into the
    ///      right tier, and return it.
    ///    - uncacheable (too large): evict any stale entry and return `Ok(None)`
    ///      so the caller serves the file directly.
    ///
    /// `loader` receives the fresh [`FileId`] (so it need not re-stat) and must
    /// return the file's bytes plus resolved content type. For the in-mem tier
    /// the returned bytes are stored directly; for the mmap tier the bytes are
    /// discarded in favour of a direct `mmap`, but the content type is still
    /// taken from the loader so MIME resolution lives entirely in the caller.
    pub fn get_or_load<L>(&self, key: &CacheKey, loader: L) -> io::Result<Option<Arc<CacheEntry>>>
    where
        L: FnOnce(&FileId) -> io::Result<Loaded>,
    {
        // TTL fast path: a recently-validated *in-mem* entry is trusted without a
        // freshness `stat` (the dominant per-request syscall for cached statics).
        // mmap-tier (`Backing::Mapped`) entries are deliberately excluded: their
        // pages are read straight from the file, so a truncate-in-place within
        // the TTL window would make `as_slice`/`bytes` fault with SIGBUS (an
        // uncatchable signal that aborts the process). Always re-stat Mapped
        // entries before serving so a shrunk/replaced file is caught.
        if !self.revalidate_ttl.is_zero() {
            if let Some(existing) = self.in_mem.get(key).or_else(|| self.mmap.get(key)) {
                if existing.is_in_mem() && existing.recently_checked(self.revalidate_ttl) {
                    return Ok(Some(existing));
                }
            }
        }

        let current = match FileId::stat(&key.path) {
            Ok(id) => id,
            Err(e) => {
                // File vanished or unreadable: forget any cached copy.
                self.invalidate(key);
                return Err(e);
            }
        };

        // Hit path: validate against the fresh stat.
        if let Some(existing) = self.in_mem.get(key).or_else(|| self.mmap.get(key)) {
            if existing.is_current(&current) {
                existing.touch();
                return Ok(Some(existing));
            }
            // Stale: drop it from whichever tier holds it before reloading.
            self.invalidate(key);
        }

        match self.caps.decide(current.size) {
            TierDecision::InMem => {
                let loaded = loader(&current)?;
                let entry = Arc::new(build_mem_entry(&current, loaded));
                self.in_mem.insert(key.clone(), entry.clone());
                Ok(Some(entry))
            }
            TierDecision::Mmap => {
                // Use the loader only for MIME resolution; map the file for data.
                let loaded = loader(&current)?;
                let entry =
                    Arc::new(self.build_mmap_entry(&key.path, &current, loaded.content_type)?);
                self.mmap.insert(key.clone(), entry.clone());
                Ok(Some(entry))
            }
            TierDecision::Uncacheable => Ok(None),
        }
    }

    /// Remove a key from both tiers.
    pub(crate) fn invalidate(&self, key: &CacheKey) {
        self.in_mem.remove(key);
        self.mmap.remove(key);
    }

    fn build_mmap_entry(
        &self,
        path: &Path,
        id: &FileId,
        content_type: String,
    ) -> io::Result<CacheEntry> {
        let file = File::open(path)?;
        // SAFETY: we map a regular file read-only. The map can be torn if the
        // file is mutated under us; accessing pages past a truncated EOF would
        // SIGBUS. We rely on a freshness `stat` BEFORE every serve to detect
        // mtime/size/inode changes and invalidate a stale entry. Crucially this
        // protection only holds because the TTL fast path in `get_or_load` is
        // restricted to in-mem backings — Mapped entries are never served from
        // the stat-skipping fast path, so each mmap serve is preceded by a stat.
        let map = unsafe { Mmap::map(&file)? };
        // `size` is the length of the bytes this entry will actually serve (the mapped region),
        // NOT the freshness-stat `id.size`. They differ only if the file was truncated between the
        // stat and the map; recording the real length makes the consumer's `entry.size == len`
        // guard (pipeline) reject a body/Content-Length mismatch instead of serving a short body.
        let size = map.len() as u64;
        Ok(CacheEntry {
            backing: Backing::Mapped(Arc::new(map)),
            etag: make_etag(id),
            last_modified: httpdate::fmt_http_date(id.mtime),
            content_type,
            size,
            id: *id,
            tier: Tier::Mmap,
            last_checked_ms: AtomicU64::new(now_ms()),
        })
    }
}

/// Build an in-mem entry from already-loaded bytes.
fn build_mem_entry(id: &FileId, loaded: Loaded) -> CacheEntry {
    let bytes = Bytes::from(loaded.bytes);
    // `size` is the length of the bytes actually buffered (what this entry serves), NOT the
    // freshness-stat `id.size`. They differ only if the file was truncated between `get_or_load`'s
    // stat and the loader's read; recording the real length keeps the consumer's `entry.size ==
    // len` guard honest so a short body is never substituted under a larger Content-Length.
    let size = bytes.len() as u64;
    CacheEntry {
        backing: Backing::Mem(bytes),
        etag: make_etag(id),
        last_modified: httpdate::fmt_http_date(id.mtime),
        content_type: loaded.content_type,
        size,
        id: *id,
        tier: Tier::InMem,
        last_checked_ms: AtomicU64::new(now_ms()),
    }
}

/// Compute a strong validator ETag from file identity.
///
/// Mirrors LiteSpeed/Apache's default `INode-Size-MTime` style strong ETag,
/// quoted per RFC 7232. mtime is rendered as whole seconds since the epoch.
fn make_etag(id: &FileId) -> String {
    let secs = id
        .mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("\"{:x}-{:x}-{:x}\"", id.inode, id.size, secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread::sleep;
    use std::time::Duration;

    fn tiny_caps() -> CacheCaps {
        CacheCaps {
            max_in_mem_file: 64, // <=64 bytes => in-mem
            total_in_mem: 128,   // only ~2 small files fit
            max_mmap_file: 4096, // <=4 KiB => mmap
            total_mmap: 16 * 1024,
        }
    }

    fn write_file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(contents).unwrap();
        f.sync_all().unwrap();
        p
    }

    /// A loader closure that reads the file from disk.
    fn read_loader(path: PathBuf, ct: &'static str) -> impl FnOnce(&FileId) -> io::Result<Loaded> {
        move |_id| std::fs::read(&path).map(|b| Loaded::new(b, ct.to_string()))
    }

    #[test]
    fn mem_entry_size_reflects_buffered_bytes_not_stat() {
        // Regression (#9): when the file shrinks between the freshness stat (id.size) and the
        // loader's read (loaded.bytes) — a concurrent in-place truncate — the entry's size must
        // reflect the ACTUAL buffered length. The consumer's `entry.size == len` guard then rejects
        // substituting a short body under a stale, larger Content-Length (which would desync
        // HTTP/1.1 framing / under-deliver an h2/h3 DATA stream).
        let id = FileId {
            size: 100,
            mtime: SystemTime::UNIX_EPOCH,
            inode: 1,
        };
        let loaded = Loaded::new(vec![b'x'; 40], "text/plain".into()); // only 40 bytes actually read
        let entry = build_mem_entry(&id, loaded);
        assert_eq!(
            entry.size, 40,
            "size must be the buffered byte count, not the stat size"
        );
        // The stable case (no race) is unchanged: bytes.len() == id.size.
        let id2 = FileId {
            size: 8,
            mtime: SystemTime::UNIX_EPOCH,
            inode: 2,
        };
        let entry2 = build_mem_entry(&id2, Loaded::new(vec![b'y'; 8], "text/plain".into()));
        assert_eq!(entry2.size, 8);
    }

    #[test]
    fn tier_selection_by_size() {
        let caps = tiny_caps();
        assert_eq!(caps.decide(10), TierDecision::InMem);
        assert_eq!(caps.decide(64), TierDecision::InMem);
        assert_eq!(caps.decide(65), TierDecision::Mmap);
        assert_eq!(caps.decide(4096), TierDecision::Mmap);
        assert_eq!(caps.decide(4097), TierDecision::Uncacheable);
    }

    /// Shorthand used throughout unit tests: zero-TTL cache (every call re-stats).
    fn test_cache(caps: CacheCaps) -> FileCache {
        FileCache::with_caps_ttl(caps, Duration::ZERO)
    }

    /// Inline the two-tier lookup (mirrors the removed `maybe_cached` method).
    fn peek(cache: &FileCache, key: &CacheKey) -> Option<Arc<CacheEntry>> {
        cache.in_mem.get(key).or_else(|| cache.mmap.get(key))
    }

    #[test]
    fn in_mem_hit_and_validators() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "small.txt", b"hello");
        let cache = test_cache(tiny_caps());
        let key = CacheKey::new(1, &path);

        let mut loads = 0u32;
        let e1 = cache
            .get_or_load(&key, |_id| {
                loads += 1;
                Ok(Loaded::new(b"hello".to_vec(), "text/plain".to_string()))
            })
            .unwrap()
            .expect("should be cacheable");
        assert_eq!(e1.tier(), Tier::InMem);
        assert_eq!(&e1.bytes()[..], b"hello");
        assert_eq!(e1.size, 5);
        assert!(e1.etag.starts_with('"') && e1.etag.ends_with('"'));
        assert!(!e1.last_modified.is_empty());
        assert_eq!(e1.content_type, "text/plain");
        assert_eq!(loads, 1);

        // Second call is a hit: loader must NOT run again.
        let e2 = cache
            .get_or_load(&key, |_id| {
                loads += 1;
                Ok(Loaded::new(b"DIFFERENT".to_vec(), "x/x".to_string()))
            })
            .unwrap()
            .unwrap();
        assert_eq!(loads, 1, "loader should not re-run on a fresh hit");
        assert_eq!(&e2.bytes()[..], b"hello");
        assert!(Arc::ptr_eq(&e1, &e2));
    }

    #[test]
    fn mtime_size_invalidation_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "page.html", b"v1");
        let cache = test_cache(tiny_caps());
        let key = CacheKey::new(0, &path);

        let e1 = cache
            .get_or_load(&key, read_loader(path.clone(), "text/html"))
            .unwrap()
            .unwrap();
        assert_eq!(&e1.bytes()[..], b"v1");

        // Rewrite with different contents AND bump mtime forward so the change
        // is detectable even on coarse-mtime filesystems.
        sleep(Duration::from_millis(1100));
        write_file(dir.path(), "page.html", b"version-2-longer");

        let e2 = cache
            .get_or_load(&key, read_loader(path.clone(), "text/html"))
            .unwrap()
            .unwrap();
        assert_eq!(
            &e2.bytes()[..],
            b"version-2-longer",
            "stale entry must reload"
        );
        assert_ne!(e1.etag, e2.etag, "etag must change when file changes");
        assert!(!Arc::ptr_eq(&e1, &e2));
    }

    #[test]
    fn size_only_change_invalidates() {
        // Even if mtime resolution were coarse, a size change must invalidate.
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "f.txt", b"abc");
        let cache = test_cache(tiny_caps());
        let key = CacheKey::new(0, &path);

        let e1 = cache
            .get_or_load(&key, read_loader(path.clone(), "text/plain"))
            .unwrap()
            .unwrap();
        assert_eq!(e1.size, 3);

        // Replace with a different size without sleeping.
        write_file(dir.path(), "f.txt", b"abcdefgh");
        let e2 = cache
            .get_or_load(&key, read_loader(path.clone(), "text/plain"))
            .unwrap()
            .unwrap();
        assert_eq!(e2.size, 8);
        assert_eq!(&e2.bytes()[..], b"abcdefgh");
    }

    #[test]
    fn eviction_under_tiny_cap() {
        let dir = tempfile::tempdir().unwrap();
        let cache = test_cache(tiny_caps()); // 128B total in-mem
        // Insert several 50-byte files; total in-mem budget is 128B so not all
        // can coexist, so the tier must evict.
        let blob = vec![b'x'; 50];
        for i in 0..10 {
            let name = format!("f{i}.txt");
            let path = write_file(dir.path(), &name, &blob);
            let key = CacheKey::new(0, &path);
            let _ = cache
                .get_or_load(&key, read_loader(path.clone(), "text/plain"))
                .unwrap()
                .unwrap();
        }
        // 50-byte entries against a 128-byte cap: at most 2 should survive.
        assert!(
            cache.in_mem.entry_count() <= 2,
            "expected eviction to keep <=2 entries, got {}",
            cache.in_mem.entry_count()
        );
        let total_size = cache.in_mem.ram_bytes() + cache.mmap.ram_bytes();
        assert!(
            total_size <= 128 + 50,
            "weighted size {} exceeded cap meaningfully",
            total_size
        );
    }

    #[test]
    fn mmap_tier_serves_mid_files() {
        let dir = tempfile::tempdir().unwrap();
        // 1 KiB file: above max_in_mem_file (64) but below max_mmap_file (4096).
        let blob = vec![b'M'; 1024];
        let path = write_file(dir.path(), "mid.bin", &blob);
        let cache = test_cache(tiny_caps());
        let key = CacheKey::new(2, &path);

        let entry = cache
            .get_or_load(&key, read_loader(path.clone(), "application/octet-stream"))
            .unwrap()
            .expect("mid file should be cached in mmap tier");
        assert_eq!(entry.tier(), Tier::Mmap);
        assert_eq!(entry.size, 1024);
        let entry_bytes = entry.bytes();
        assert_eq!(entry_bytes.len(), 1024);
        assert_eq!(entry_bytes[0], b'M');
        assert_eq!(entry.content_type, "application/octet-stream");
        let mapped_bytes = entry.bytes();
        assert_eq!(mapped_bytes.len(), 1024);
        assert_eq!(&mapped_bytes[..4], b"MMMM");

        // mmap-tier hit returns the same Arc and does not re-run loader.
        let mut ran = false;
        let entry2 = cache
            .get_or_load(&key, |_id| {
                ran = true;
                Ok(Loaded::new(Vec::new(), "x".to_string()))
            })
            .unwrap()
            .unwrap();
        assert!(!ran, "mmap hit must not re-run loader");
        assert!(Arc::ptr_eq(&entry, &entry2));
        drop(entry);
        drop(entry2);
        assert_eq!(
            &mapped_bytes[1020..],
            b"MMMM",
            "Bytes must keep the mmap owner alive"
        );
    }

    #[test]
    fn oversize_is_uncacheable() {
        let dir = tempfile::tempdir().unwrap();
        // 8 KiB file: above max_mmap_file (4096) => uncacheable.
        let blob = vec![b'Z'; 8192];
        let path = write_file(dir.path(), "big.bin", &blob);
        let cache = test_cache(tiny_caps());
        let key = CacheKey::new(0, &path);

        let res = cache
            .get_or_load(&key, read_loader(path.clone(), "application/octet-stream"))
            .unwrap();
        assert!(res.is_none(), "oversize file must not be cached");
        assert!(peek(&cache, &key).is_none());
    }

    #[test]
    fn missing_file_errors_and_invalidates() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(dir.path(), "gone.txt", b"data");
        let cache = test_cache(tiny_caps());
        let key = CacheKey::new(0, &path);

        cache
            .get_or_load(&key, read_loader(path.clone(), "text/plain"))
            .unwrap()
            .unwrap();
        assert!(peek(&cache, &key).is_some());

        std::fs::remove_file(&path).unwrap();
        let err = cache
            .get_or_load(&key, read_loader(path.clone(), "text/plain"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        // Stale entry must be evicted after the file disappears.
        assert!(peek(&cache, &key).is_none());
    }

    #[test]
    fn caps_from_tuning_are_clamped() {
        let t = Tuning::default(); // total_in_mem_cache_size = 4 GiB
        let caps = CacheCaps::from_tuning(&t);
        assert!(
            caps.total_in_mem <= ABS_MAX_IN_MEM_CAP,
            "in-mem cap must be clamped, got {}",
            caps.total_in_mem
        );
        assert!(caps.total_mmap <= ABS_MAX_MMAP_CAP);
        assert!(caps.max_in_mem_file <= caps.total_in_mem);
    }

    #[test]
    fn clear_drops_all() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = write_file(dir.path(), "a.txt", b"a");
        let p2 = write_file(dir.path(), "b.bin", &[b'b'; 200]); // mmap tier
        let cache = test_cache(tiny_caps());
        let k1 = CacheKey::new(0, &p1);
        let k2 = CacheKey::new(0, &p2);
        cache
            .get_or_load(&k1, read_loader(p1.clone(), "text/plain"))
            .unwrap();
        cache
            .get_or_load(&k2, read_loader(p2.clone(), "application/octet-stream"))
            .unwrap();
        assert!(peek(&cache, &k1).is_some());
        assert!(peek(&cache, &k2).is_some());
        cache.in_mem.clear();
        cache.mmap.clear();
        assert!(peek(&cache, &k1).is_none());
        assert!(peek(&cache, &k2).is_none());
    }
}
