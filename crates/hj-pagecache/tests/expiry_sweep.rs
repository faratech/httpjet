//! The proactive expiry sweep, now backed by the per-shard deadline min-heap with
//! per-key generation guards. `sweep_expired()` drains past-deadline heap entries and
//! tears each live one down through the one synchronous funnel (file unlink + budget
//! drop + tag GC) — so an expired entry's file is unlinked SYNCHRONOUSLY and the index
//! holds `entries == .pc files` at all times. A stale heap entry (a re-store bumped the
//! key's generation) is skipped, never tearing down the fresh re-store.

use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hj_pagecache::{CachedResponse, PageBody, PageCacheKey, PageScope, PageStore, StoreConfig};
use http::HeaderValue;

fn cfg(root: &Path) -> StoreConfig {
    StoreConfig {
        max_mem_bytes: 256 * 1024 * 1024,
        max_disk_bytes: 256 * 1024 * 1024,
        max_obj_bytes: 1024 * 1024,
        store_path: Some(root.to_path_buf()),
        hot_mem_bytes: 1, // tiny ⇒ a dangling File body can't be masked by an in-RAM copy
        default_public_ttl: Duration::from_secs(600),
        cacheable_status: vec![200, 301],
        ..StoreConfig::default()
    }
}

fn key(i: usize) -> PageCacheKey {
    PageCacheKey::public(1, true, "h", format!("/p{i}"), "")
}
fn identity(i: usize) -> String {
    format!("h\n/p{i}")
}
fn entry_ttl(i: usize, body: &[u8], ttl: Duration) -> CachedResponse {
    CachedResponse {
        status: 200,
        identity: identity(i),
        headers: vec![(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        )],
        body: PageBody::InMem(Bytes::copy_from_slice(body)),
        variants: Vec::new(),
        variants_filled: false,
        dict_gen: 0,
        tags: Vec::new(),
        vary_cookie_name: String::new(),
        vary_value: String::new(),
        scope: PageScope::Public,
        stored_at: Instant::now(),
        ttl,
        swr: Duration::ZERO,
        sie: Duration::ZERO,
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

/// The sweep reclaims every past-deadline entry, releases its disk weight, and unlinks its
/// (recompressed) file SYNCHRONOUSLY — no orphan lingers, no reconcile is needed.
#[test]
fn sweep_reclaims_expired_entries_files_and_disk_weight() {
    let td = tempfile::tempdir().unwrap();
    let s = PageStore::new(cfg(td.path()));
    s.load_from_disk(|_| {});

    const N: usize = 300;
    let body = vec![b'x'; 2000];
    let comp = vec![b'z'; 400];
    for i in 0..N {
        let e = entry_ttl(i, &body, Duration::from_millis(30));
        let sa = e.stored_at;
        s.store(key(i), e); // writes identity file at birth
        s.fill_recompress_disk(&key(i), &identity(i), sa, Bytes::from(comp.clone()), 7);
    }
    // recompress unlinks the identity synchronously ⇒ exactly 1 file/key.
    assert_eq!(pc_files(td.path()), N, "1 live recompressed file per key");

    // Let them all pass their 30 ms retention, then sweep ONCE.
    std::thread::sleep(Duration::from_millis(120));
    let swept = s.sweep_expired();
    let st = s.stats();
    assert_eq!(swept, N as u64, "sweep reclaimed every expired entry");
    assert_eq!(st.entries, 0, "index empty after sweep");
    assert_eq!(st.disk_bytes, 0, "disk weight back to 0 after sweep");
    assert_eq!(
        pc_files(td.path()),
        0,
        "every reclaimed entry's file unlinked synchronously"
    );
}

/// A re-store of an expired-deadline key BEFORE the sweep runs must not be reaped: the re-store
/// bumps the key's generation, orphaning the old heap entry, so the sweep's stale pop is skipped.
#[test]
fn sweep_skips_a_restored_key_via_generation_guard() {
    let td = tempfile::tempdir().unwrap();
    let s = PageStore::new(cfg(td.path()));
    s.load_from_disk(|_| {});

    // Store with a tiny ttl, let it cross its deadline (enters the heap as due).
    s.store(
        key(0),
        entry_ttl(0, &[b'a'; 1500], Duration::from_millis(2)),
    );
    std::thread::sleep(Duration::from_millis(5));
    // Re-store fresh BEFORE sweeping: a new generation, a fresh long deadline.
    s.store(
        key(0),
        entry_ttl(0, &[b'b'; 1500], Duration::from_secs(600)),
    );

    let swept = s.sweep_expired();
    assert_eq!(
        swept, 0,
        "the stale heap entry is skipped (generation guard)"
    );
    let got = s
        .lookup(&key(0), &identity(0), Instant::now())
        .expect("fresh re-store survives the sweep");
    assert_eq!(&s.body_bytes(&got).unwrap()[..], &[b'b'; 1500][..]);
    assert_eq!(s.stats().disk_read_errors, 0);
    assert_eq!(pc_files(td.path()), 1, "exactly the live file remains");
}

/// `maintenance()` drives the sweep on its tick: a past-deadline entry IS reclaimed (the old
/// "staged off the tick" behavior is gone — the heap-backed sweep is safe by construction).
#[test]
fn maintenance_sweeps_expired_entries() {
    let td = tempfile::tempdir().unwrap();
    let s = PageStore::new(cfg(td.path()));
    s.load_from_disk(|_| {});

    let e = entry_ttl(0, &[b'x'; 2000], Duration::from_millis(30));
    let sa = e.stored_at;
    s.store(key(0), e);
    s.fill_recompress_disk(&key(0), &identity(0), sa, Bytes::from(vec![b'z'; 400]), 7);
    assert_eq!(
        pc_files(td.path()),
        1,
        "1 file/key after synchronous recompress"
    );

    std::thread::sleep(Duration::from_millis(120));
    s.maintenance(Duration::ZERO);
    let st = s.stats();
    assert_eq!(
        st.swept_expired, 1,
        "maintenance swept the past-deadline entry"
    );
    assert_eq!(st.entries, 0, "expired entry reaped on the tick");
    assert_eq!(pc_files(td.path()), 0, "its file unlinked synchronously");
}
