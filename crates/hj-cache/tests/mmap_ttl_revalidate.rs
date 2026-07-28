//! Regression (item 23): an mmap-tier entry must be re-`stat`ed before every
//! serve, even inside the freshness-TTL window, so a truncate-in-place of the
//! backing file is caught instead of faulting with SIGBUS.
//!
//! The bug: `get_or_load` took a TTL fast path that returned any
//! recently-checked entry without a fresh `stat`. For an `mmap`-backed entry
//! that means `as_slice()`/`bytes()` could read pages past the new EOF after an
//! in-place truncation, delivering SIGBUS — an uncatchable signal that aborts
//! the whole process. The fix restricts the TTL fast path to in-mem backings;
//! mmap entries always re-stat.
//!
//! This test is SIGBUS-safe: it never dereferences a possibly-stale mapping. It
//! truncates the file, then asserts the *metadata* the next `get_or_load`
//! returns reflects the new size — which can only be true if the stat ran (the
//! fast path would have returned the original, larger entry untouched).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::Duration;

use hj_cache::{CacheCaps, CacheKey, FileCache, Loaded, Tier};

/// Caps that force a ~1 KiB file into the mmap tier: in-mem ceiling 64 B,
/// mmap ceiling 64 KiB.
fn mmap_caps() -> CacheCaps {
    CacheCaps {
        max_in_mem_file: 64,
        total_in_mem: 4096,
        max_mmap_file: 64 * 1024,
        total_mmap: 1024 * 1024,
    }
}

fn read_loader(
    path: std::path::PathBuf,
    ct: &'static str,
) -> impl FnOnce(&hj_cache::FileId) -> std::io::Result<Loaded> {
    move |_id| std::fs::read(&path).map(|b| Loaded::new(b, ct.to_string()))
}

#[test]
fn mmap_entry_revalidated_within_ttl_after_truncate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mid.bin");
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(&vec![b'A'; 1024]).unwrap();
        f.sync_all().unwrap();
    }

    // Non-zero TTL: an in-mem entry would legitimately skip the stat inside this
    // window. The fix must NOT extend that shortcut to the mmap tier.
    let cache = FileCache::with_caps_ttl(mmap_caps(), Duration::from_secs(60));
    let key = CacheKey::new(0, &path);

    let e1 = cache
        .get_or_load(&key, read_loader(path.clone(), "application/octet-stream"))
        .unwrap()
        .expect("1 KiB file should be cached in the mmap tier");
    assert_eq!(e1.tier(), Tier::Mmap, "test must exercise the mmap tier");
    assert_eq!(e1.size, 1024);
    // The first load just `touch`ed the entry, so it is "recently checked" and
    // well within the 60s TTL window for the next call.

    // Truncate the backing file IN PLACE (the dangerous deploy pattern). Do NOT
    // touch the old mapping after this point — a stale-fast-path serve would
    // SIGBUS; we only inspect the metadata the cache returns.
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(16)
        .unwrap();

    // Second call is inside the TTL window. With the bug it would return the
    // original 1024-byte mmap entry without a stat; with the fix it re-stats,
    // sees the size change, invalidates, and reloads — so the returned entry's
    // size reflects the truncated file.
    let e2 = cache
        .get_or_load(&key, read_loader(path.clone(), "application/octet-stream"))
        .unwrap()
        .expect("truncated file is still cacheable");
    assert_eq!(
        e2.size, 16,
        "mmap entry must be re-stat'd within the TTL window after truncation, \
         not served stale (would SIGBUS on access)"
    );
    assert_ne!(
        e1.file_id().size,
        e2.file_id().size,
        "the reloaded entry must capture the new, smaller file identity"
    );
}
