//! [`HtaccessCache`]: per-directory `.htaccess` loading with mtime-based
//! invalidation, plus chain assembly for a request path.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use dashmap::DashMap;

use crate::htaccess::Htaccess;

/// Within this window we trust a cached entry without re-`stat`-ing the file.
/// Bounds `.htaccess`-change visibility latency (mirrors how LiteSpeed/OLS avoid
/// a stat per request) while removing the dominant per-request syscall.
const REVALIDATE_TTL: Duration = Duration::from_secs(1);

/// Soft cap on the number of cached directory entries. The map is keyed by the
/// per-directory access-file path, which is derived from the (attacker-controlled)
/// request path, so without a bound an htaccess-enabled vhost (`allowOverride`) lets
/// a flood of high-cardinality URLs grow the process-wide map without limit. Real
/// docroot depth is tiny, so a few tens of thousands of slots never evicts a live
/// directory; beyond the cap a new path still pays its stat but is not memoized
/// (mirrors `hj-static`'s `META_CACHE_CAP`).
const MAX_HTACCESS_ENTRIES: usize = 16_384;

/// A cache entry: the parsed `.htaccess`, the mtime it was parsed at, and when
/// we last validated it (for `REVALIDATE_TTL` coalescing).
struct Entry {
    /// `None` means "we checked and there is no `.htaccess` in this dir".
    parsed: Option<Arc<Htaccess>>,
    mtime: Option<SystemTime>,
    checked_at: Instant,
}

/// Thread-safe cache of parsed `.htaccess` files, keyed by absolute directory.
///
/// On each [`load_chain`](HtaccessCache::load_chain), every directory from the
/// docroot down to the request's directory is consulted; an entry is reparsed
/// whenever the file's mtime changes (or it appears/disappears).
pub struct HtaccessCache {
    /// Sharded concurrent map: every request reads this on the hot path, so a
    /// single `Mutex` here was the dominant lock-contention (futex) source under
    /// load. `DashMap` shards the locking across many sub-maps.
    inner: DashMap<PathBuf, Entry>,
    /// How long a validated entry is trusted before re-`stat`-ing. Production
    /// uses [`REVALIDATE_TTL`]; tests can set `0` to force per-call revalidation.
    revalidate_ttl: Duration,
    /// Approximate entry count for the cap gate — `DashMap::len()` sweeps every
    /// shard. Entries are never removed, so a counter bumped on new-key insert
    /// is exact up to insert races.
    count: AtomicUsize,
}

impl Default for HtaccessCache {
    fn default() -> Self {
        Self::new()
    }
}

impl HtaccessCache {
    /// Soft cap on cached directory entries (see [`MAX_HTACCESS_ENTRIES`]). Exposed
    /// so callers/tests can reason about the bound without duplicating the constant.
    pub const MAX_ENTRIES: usize = MAX_HTACCESS_ENTRIES;

    /// Create an empty cache with the default revalidation TTL.
    pub fn new() -> Self {
        Self::with_revalidate_ttl(REVALIDATE_TTL)
    }

    /// Create a cache with an explicit revalidation TTL (`0` = stat every call).
    pub fn with_revalidate_ttl(revalidate_ttl: Duration) -> Self {
        HtaccessCache {
            inner: DashMap::new(),
            revalidate_ttl,
            count: AtomicUsize::new(0),
        }
    }

    /// Load (and cache) the access-file chain that applies to `request_path`
    /// under `docroot`, from the docroot down to the request's directory, using
    /// the default `.htaccess` file name.
    ///
    /// `request_path` is the URL path (with leading `/`). The returned vector
    /// is ordered outermost-first (docroot's `.htaccess` first), matching
    /// Apache's merge order. Directories without a readable access file are
    /// skipped.
    pub fn load_chain(&self, docroot: &Path, request_path: &str) -> Vec<Arc<Htaccess>> {
        self.load_chain_named(docroot, request_path, ".htaccess")
    }

    /// Like [`load_chain`](Self::load_chain) but with an explicit per-directory
    /// access file name (LiteSpeed `<htAccess><accessFileName>`). The pipeline
    /// passes the vhost's configured name (defaulting to `.htaccess`).
    pub fn load_chain_named(
        &self,
        docroot: &Path,
        request_path: &str,
        access_file_name: &str,
    ) -> Vec<Arc<Htaccess>> {
        self.load_chain_with_dirs(docroot, request_path, access_file_name)
            .into_iter()
            .map(|(_, h)| h)
            .collect()
    }

    /// Like [`load_chain_named`](Self::load_chain_named) but pairs each parsed
    /// access file with the **absolute directory** it was loaded from. The
    /// pipeline uses the directory to derive Apache's per-directory rule prefix
    /// (`RewriteInput::per_directory_prefix`). Directories without an access
    /// file are omitted, so the directory is needed to recover the prefix
    /// (a positional chain index cannot, since gaps are skipped).
    pub fn load_chain_with_dirs(
        &self,
        docroot: &Path,
        request_path: &str,
        access_file_name: &str,
    ) -> Vec<(PathBuf, Arc<Htaccess>)> {
        let mut chain = Vec::new();

        // The directories to check, in order: docroot, docroot/seg1, ... up to the directory
        // containing the requested resource (the last path segment is the resource/file unless the
        // path ends in '/'). Walk them WITHOUT materializing a `segments` Vec or a full `dirs` Vec,
        // growing one cumulative `cur` PathBuf in place and cloning a directory into the chain only
        // when it actually has an access file. The SET and ORDER of directories stat'd is IDENTICAL
        // to the prior list-then-loop form — load-bearing: a per-directory deny depends on every
        // intermediate directory being checked (see the M1 note in pipeline::dispatch).
        let rel = request_path.trim_start_matches('/');
        let ends_with_slash = request_path.ends_with('/') || rel.is_empty();
        let seg_count = rel.split('/').filter(|s| !s.is_empty()).count();
        let dir_count = if ends_with_slash {
            seg_count
        } else {
            seg_count.saturating_sub(1)
        };

        let mut cur = docroot.to_path_buf();
        if let Some(h) = self.get_or_load_named(&cur, access_file_name) {
            chain.push((cur.clone(), h));
        }
        for seg in rel.split('/').filter(|s| !s.is_empty()).take(dir_count) {
            cur.push(seg);
            if let Some(h) = self.get_or_load_named(&cur, access_file_name) {
                chain.push((cur.clone(), h));
            }
        }
        chain
    }

    /// Load a single directory's `.htaccess`, reparsing on mtime change.
    /// Returns `None` if there is no `.htaccess` there.
    pub fn get_or_load(&self, dir: &Path) -> Option<Arc<Htaccess>> {
        self.get_or_load_named(dir, ".htaccess")
    }

    /// Load a single directory's access file (named `access_file_name`),
    /// reparsing on mtime change. Returns `None` if the file is absent.
    ///
    /// The cache is keyed by the full access-file path (`dir/access_file_name`),
    /// so two vhosts that share a directory but use different access file names
    /// do not collide.
    pub fn get_or_load_named(&self, dir: &Path, access_file_name: &str) -> Option<Arc<Htaccess>> {
        let file = dir.join(access_file_name);

        // Fast path: within the revalidation window, trust the cache — no stat.
        // (`get` takes only a shard read lock; the guard is dropped before any
        // insert below to avoid a same-shard deadlock.)
        if let Some(entry) = self.inner.get(&file) {
            if !self.revalidate_ttl.is_zero() && entry.checked_at.elapsed() < self.revalidate_ttl {
                return entry.parsed.clone();
            }
        }

        let cur_mtime = std::fs::metadata(&file).and_then(|m| m.modified()).ok();

        // Revalidate: if mtime is unchanged, refresh the check timestamp and reuse.
        {
            if let Some(mut entry) = self.inner.get_mut(&file) {
                if entry.mtime == cur_mtime {
                    entry.checked_at = Instant::now();
                    return entry.parsed.clone();
                }
            }
        }

        // Cache miss or stale: (re)parse (no map guard held during the read/parse).
        let parsed = match (cur_mtime, std::fs::read_to_string(&file)) {
            (Some(_), Ok(text)) => match Htaccess::parse(&text) {
                Ok(h) => Some(Arc::new(h)),
                Err(e) => {
                    tracing::warn!(path = %file.display(), error = %e, "failed to parse .htaccess");
                    None
                }
            },
            _ => None,
        };

        // Cap growth: only memoize when under the soft cap or refreshing a key
        // that is already present (a refresh replaces in place and never grows the
        // map). Past the cap an absent/new directory still resolves correctly — it
        // just isn't cached, so it re-stats on each request rather than poisoning
        // the bound. Keeps the existing `DashMap` API (no eviction machinery).
        if self.count.load(Ordering::Relaxed) < MAX_HTACCESS_ENTRIES
            || self.inner.contains_key(&file)
        {
            let prev = self.inner.insert(
                file,
                Entry {
                    parsed: parsed.clone(),
                    mtime: cur_mtime,
                    checked_at: Instant::now(),
                },
            );
            if prev.is_none() {
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }
        parsed
    }

    /// Number of cached directory entries (for diagnostics/tests).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Drop all cached entries (e.g. on a config reload). Resets the soft-cap
    /// counter too: forgetting this leaves `count` pinned at the cap while the
    /// map is empty, so the insert guard (`count < MAX || contains_key`) blocks
    /// ALL re-caching and every access file re-parses per request — recompiling
    /// its regex DFAs into a multi-core CPU storm (seen live 2026-06-13 after a
    /// SIGHUP config reload).
    pub fn clear(&self) {
        self.inner.clear();
        self.count.store(0, Ordering::Relaxed);
    }

    /// (test) Entries counted against the soft cap. Diverges from [`len`](Self::len)
    /// only when `clear` fails to reset the counter — the regression hook.
    #[cfg(test)]
    pub(crate) fn cap_count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}
