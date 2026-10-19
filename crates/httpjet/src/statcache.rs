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

use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

/// Paths longer than this are never memoized: real hot paths are short, and an
/// attacker-chosen 8 KiB key would otherwise pin its bytes for the process life.
const MAX_KEY_BYTES: usize = 1024;

/// TTL-coalesced cache of `-f`/`-d`/`-l`/`-s` file tests, keyed by absolute path.
pub struct StatCache {
    /// Keyed by the raw path bytes: `PathBuf` equality ignores a trailing `/`, but
    /// `file/` fails with ENOTDIR where `file` exists, so they must not share an
    /// entry (#899).
    map: DashMap<OsString, (Instant, Option<FileTests>)>,
    ttl: Duration,
    cap: usize,
    /// Approximate entry count for the cap gate: `DashMap::len()` sweeps (and
    /// briefly locks) every shard, and once the map is full that sweep ran on
    /// EVERY uncached request. Bumped on new-key insert and lowered by
    /// `sweep_expired`, exact up to insert races.
    count: AtomicUsize,
    created: Instant,
    /// Milliseconds after `created` of the last expired-entry sweep (+1; 0 = never).
    last_sweep_ms: AtomicU64,
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
            created: Instant::now(),
            last_sweep_ms: AtomicU64::new(0),
        }
    }

    /// File tests for `path`, re-`statx`-ing at most once per TTL.
    /// `None` means the path does not exist (cached as such within the window).
    pub fn tests(&self, path: &Path) -> Option<FileTests> {
        if self.ttl.is_zero() {
            return Self::stat(path);
        }
        let mut present = false;
        if let Some(e) = self.map.get(path.as_os_str()) {
            if e.0.elapsed() < self.ttl {
                return e.1; // FileTests is Copy
            }
            present = true;
        } // read guard dropped here before we take the write lock below
        let tests = Self::stat(path);
        if present
            || (path.as_os_str().len() <= MAX_KEY_BYTES
                && (self.count.load(Ordering::Relaxed) < self.cap || self.sweep_expired()))
        {
            if self
                .map
                .insert(path.as_os_str().to_owned(), (Instant::now(), tests))
                .is_none()
            {
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }
        tests
    }

    /// Once the map is full, drop entries past their TTL (they would be re-stat'd
    /// on next use anyway), at most once per TTL. Returns whether room was made.
    fn sweep_expired(&self) -> bool {
        let now_ms = self.created.elapsed().as_millis() as u64 + 1;
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        if last != 0 && now_ms.saturating_sub(last) < self.ttl.as_millis() as u64 {
            return false;
        }
        if self
            .last_sweep_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        let mut removed = 0;
        self.map.retain(|_, e| {
            let keep = e.0.elapsed() < self.ttl;
            removed += usize::from(!keep);
            keep
        });
        let _ = self
            .count
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                Some(c.saturating_sub(removed))
            });
        self.count.load(Ordering::Relaxed) < self.cap
    }

    /// `-f`/`-d`/`-s` follow a symlink; `-l` must see the link itself (lstat), or it
    /// could never be true and a dangling link would read as absent.
    fn stat(path: &Path) -> Option<FileTests> {
        let lmd = std::fs::symlink_metadata(path).ok()?;
        if !lmd.file_type().is_symlink() {
            return Some(FileTests::from_metadata(&lmd));
        }
        let mut tests = std::fs::metadata(path)
            .map(|md| FileTests::from_metadata(&md))
            .unwrap_or_default();
        tests.is_link = true;
        Some(tests)
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
    fn symlinks_report_is_link_and_follow_for_other_tests() {
        let dir =
            std::env::temp_dir().join(format!("httpjet_statcache_link_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("target.txt"), b"hi").unwrap();
        std::os::unix::fs::symlink(dir.join("target.txt"), dir.join("link")).unwrap();
        std::os::unix::fs::symlink(dir.join("gone"), dir.join("dangling")).unwrap();

        let c = StatCache::new(Duration::ZERO);
        let t = c.tests(&dir.join("link")).expect("link exists");
        assert!(t.is_link && t.is_file && t.is_nonempty);
        let t = c
            .tests(&dir.join("dangling"))
            .expect("dangling link exists");
        assert!(t.is_link && !t.is_file && !t.is_dir);
        assert!(!c.tests(&dir.join("target.txt")).unwrap().is_link);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_map_reclaims_expired_entries_and_skips_long_keys() {
        let mut c = StatCache::new(Duration::from_millis(20));
        c.cap = 2;
        c.tests(Path::new("/nonexistent-statcache-a"));
        c.tests(Path::new("/nonexistent-statcache-b"));
        assert_eq!(c.map.len(), 2);
        std::thread::sleep(Duration::from_millis(40));
        c.tests(Path::new("/nonexistent-statcache-c"));
        assert!(
            c.map
                .contains_key(Path::new("/nonexistent-statcache-c").as_os_str())
        );
        assert_eq!(c.map.len(), 1);

        let long = std::path::PathBuf::from(format!("/{}", "x".repeat(2048)));
        assert!(c.tests(&long).is_none());
        assert!(!c.map.contains_key(long.as_os_str()));
    }

    /// Regression (#899): `file/` (ENOTDIR) must not poison the entry for `file`.
    #[test]
    fn trailing_slash_does_not_share_an_entry() {
        let dir =
            std::env::temp_dir().join(format!("httpjet_statcache_slash_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("robots.txt");
        std::fs::write(&file, b"x").unwrap();
        let c = StatCache::new(Duration::from_secs(60));
        let slashed = std::path::PathBuf::from(format!("{}/", file.display()));
        assert!(c.tests(&slashed).is_none());
        assert!(c.tests(&file).unwrap().is_file);
        let _ = std::fs::remove_dir_all(&dir);
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
