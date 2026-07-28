//! A tiny TTL-coalesced cache of filesystem `-f`/`-d`/`-l`/`-s` tests.
//!
//! Apache-style front-controller `.htaccess` rules (`RewriteCond %{REQUEST_FILENAME}
//! !-f` / `!-d`) `statx` the request path on *every* request. For a hot path that
//! result barely changes, so we cache the cheap [`FileTests`] booleans — a
//! `Metadata` is not storable — behind a short revalidation TTL: inside the
//! window we return the cached result and skip the syscall; after it we re-stat
//! and refresh. Both existence *and* non-existence are cached so a repeatedly
//! missing path (e.g. a SPA route falling through to the front controller) also
//! coalesces.
//!
//! Mirrors the same TTL-coalescing already used by `HtaccessCache`; this closes
//! the last redundant per-request `statx` on the rewrite hot path.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hj_rewrite::FileTests;

/// Re-`statx` a given path at most once per this window.
pub const DEFAULT_STAT_TTL: Duration = Duration::from_secs(1);

/// Soft cap on distinct cached paths, so a high-cardinality URL space can't grow
/// the map without bound. Refreshing an existing key is always allowed; only
/// inserting a brand-new key is gated once the cap is reached (cold paths then
/// just `statx` through, exactly as before).
const DEFAULT_CAP: usize = 32_768;

/// TTL-coalesced cache of `-f`/`-d`/`-l`/`-s` file tests, keyed by absolute path.
pub struct StatCache {
    map: DashMap<PathBuf, (Instant, Option<FileTests>)>,
    ttl: Duration,
    cap: usize,
    /// Approximate entry count for the cap gate: `DashMap::len()` sweeps (and
    /// briefly locks) every shard, and once the map is full that sweep ran on
    /// EVERY uncached request. Entries are never removed, so a saturating
    /// counter bumped on new-key insert is exact up to insert races.
    count: AtomicUsize,
}

impl StatCache {
    /// Create a cache that revalidates each path at most once per `ttl`.
    /// `ttl == 0` disables caching (every call `statx`es) — useful in tests.
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: DashMap::new(),
            ttl,
            cap: DEFAULT_CAP,
            count: AtomicUsize::new(0),
        }
    }

    /// File tests for `path`, re-`statx`-ing at most once per TTL.
    /// `None` means the path does not exist (cached as such within the window).
    pub fn tests(&self, path: &Path) -> Option<FileTests> {
        if self.ttl.is_zero() {
            return Self::stat(path);
        }
        let mut present = false;
        if let Some(e) = self.map.get(path) {
            if e.0.elapsed() < self.ttl {
                return e.1; // FileTests is Copy
            }
            present = true;
        } // read guard dropped here before we take the write lock below
        let tests = Self::stat(path);
        if present || self.count.load(Ordering::Relaxed) < self.cap {
            if self
                .map
                .insert(path.to_path_buf(), (Instant::now(), tests))
                .is_none()
            {
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }
        tests
    }

    fn stat(path: &Path) -> Option<FileTests> {
        std::fs::metadata(path)
            .ok()
            .map(|md| FileTests::from_metadata(&md))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_existence_and_nonexistence() {
        let dir = std::env::temp_dir().join("httpjet_statcache_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("present.txt");
        std::fs::write(&file, b"hi").unwrap();
        let missing = dir.join("missing.txt");

        let c = StatCache::new(Duration::from_secs(60));
        let t = c.tests(&file).expect("file exists");
        assert!(t.is_file && t.is_nonempty);
        assert!(c.tests(&missing).is_none());

        // Second lookups are served from cache (still correct).
        assert!(c.tests(&file).unwrap().is_file);
        assert!(c.tests(&missing).is_none());

        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn zero_ttl_always_stats() {
        let dir = std::env::temp_dir().join("httpjet_statcache_zero");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("toggle.txt");
        let _ = std::fs::remove_file(&file);

        let c = StatCache::new(Duration::ZERO);
        assert!(c.tests(&file).is_none());
        std::fs::write(&file, b"x").unwrap();
        // No TTL window → the very next call sees the new state.
        assert!(c.tests(&file).unwrap().is_file);
        let _ = std::fs::remove_file(&file);
    }
}
