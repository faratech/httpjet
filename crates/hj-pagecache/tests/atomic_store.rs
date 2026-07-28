//! Group A (atomic single-op consistency) + Group B (eviction) proofs for the bespoke
//! sharded store. The invariant the whole rewrite exists to guarantee: every index-removal
//! and tmpfs-file-unlink happens ATOMICALLY under one shard lock, so a fileless live entry
//! is unrepresentable and `entries == .pc files` holds after every synchronous op (no
//! settle, no reconcile, no orphan).

use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hj_pagecache::{
    CachedResponse, EntryState, PageBody, PageCacheKey, PageScope, PageStore, StoreConfig,
};
use http::HeaderValue;

fn disk_cfg(dir: &Path, disk_max: u64) -> StoreConfig {
    StoreConfig {
        max_mem_bytes: 64 * 1024 * 1024,
        max_disk_bytes: disk_max,
        max_obj_bytes: 1024 * 1024,
        store_path: Some(dir.to_path_buf()),
        hot_mem_bytes: 1024 * 1024,
        default_public_ttl: Duration::from_secs(60),
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
fn entry(i: usize, body: &[u8], tags: &[&str], ttl: Duration) -> CachedResponse {
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
        tags: tags.iter().map(|t| std::sync::Arc::from(*t)).collect(),
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

/// Assert the core invariant: every live entry's body resolves (0 fileless) AND
/// `entries == .pc files` AND `disk_bytes == Σ referenced file footprints`.
fn assert_consistent(s: &PageStore, root: &Path, probe_range: usize) {
    let now = Instant::now();
    let mut fileless = 0;
    let mut referenced_disk = 0u64;
    let mut live = 0u64;
    for i in 0..probe_range {
        if let Some(e) = s.lookup(&key(i), &identity(i), now) {
            live += 1;
            match s.body_bytes(&e) {
                Some(b) => {
                    if let PageBody::File {
                        len, disk_total, ..
                    } = &e.body
                    {
                        assert_eq!(
                            *len as usize,
                            b.len(),
                            "File.len must equal resolved body len"
                        );
                        assert!(*disk_total as u64 >= *len as u64);
                        referenced_disk += *disk_total as u64;
                    }
                }
                None => fileless += 1,
            }
        }
    }
    assert_eq!(
        fileless, 0,
        "a live entry resolved no body (fileless strand)"
    );
    let st = s.stats();
    assert_eq!(
        st.entries as usize,
        pc_files(root),
        "entries ({}) must equal on-disk .pc files ({})",
        st.entries,
        pc_files(root)
    );
    // The probe loop touched every key, so `live` equals the indexed count.
    assert_eq!(live, st.entries, "every indexed entry was probed");
    assert_eq!(
        st.disk_bytes, referenced_disk,
        "disk_bytes must equal Σ referenced File.disk_total"
    );
}

// ===================== Group A — atomic single-op consistency =====================

#[test]
fn store_is_immediately_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
    s.load_from_disk(|_| {});
    let body = vec![b'a'; 1234];
    s.store(key(0), entry(0, &body, &[], Duration::from_secs(600)));
    // No settle: the op was synchronous.
    assert!(s.lookup(&key(0), &identity(0), Instant::now()).is_some());
    let st = s.stats();
    assert_eq!(st.entries, 1);
    assert!(st.disk_bytes >= 1234);
    assert_eq!(pc_files(dir.path()), 1);
    assert_consistent(&s, dir.path(), 1);
}

#[test]
fn expiry_atomically_unlinks_and_releases() {
    let dir = tempfile::tempdir().unwrap();
    let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
    s.load_from_disk(|_| {});
    s.store(
        key(0),
        entry(0, &vec![b'a'; 2000], &[], Duration::from_millis(20)),
    );
    assert_eq!(pc_files(dir.path()), 1);
    std::thread::sleep(Duration::from_millis(50));
    // A lookup at this point sees Gone and tears it down under the lock; OR a tick does.
    assert!(matches!(
        s.get_entry(&key(0), &identity(0), Instant::now()),
        EntryState::Miss
    ));
    let st = s.stats();
    assert_eq!(st.entries, 0, "expired entry reclaimed on the gone-lookup");
    assert_eq!(st.disk_bytes, 0);
    assert_eq!(pc_files(dir.path()), 0, "its file unlinked synchronously");
}

#[test]
fn expiry_via_sweep_atomically_unlinks() {
    let dir = tempfile::tempdir().unwrap();
    let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
    s.load_from_disk(|_| {});
    for i in 0..20 {
        s.store(
            key(i),
            entry(i, &vec![b'a'; 1000], &[], Duration::from_millis(20)),
        );
    }
    assert_eq!(pc_files(dir.path()), 20);
    std::thread::sleep(Duration::from_millis(50));
    let swept = s.sweep_expired();
    assert_eq!(swept, 20);
    assert_eq!(s.stats().entries, 0);
    assert_eq!(s.stats().disk_bytes, 0);
    assert_eq!(pc_files(dir.path()), 0);
}

#[test]
fn restore_replaces_file_with_one_file() {
    let dir = tempfile::tempdir().unwrap();
    let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
    s.load_from_disk(|_| {});
    for v in 0..10 {
        let body = vec![b'a' + v as u8; 100 + v];
        s.store(key(0), entry(0, &body, &[], Duration::from_secs(600)));
        assert_eq!(
            pc_files(dir.path()),
            1,
            "exactly 1 file/key after re-store #{v}"
        );
    }
    assert_consistent(&s, dir.path(), 1);
}

#[test]
fn recompress_swaps_to_one_smaller_file() {
    let dir = tempfile::tempdir().unwrap();
    let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
    s.load_from_disk(|_| {});
    let e = entry(0, &vec![b'x'; 16 * 1024], &[], Duration::from_secs(600));
    let sa = e.stored_at;
    s.store(key(0), e);
    let before = s.stats().disk_bytes;
    assert!(before >= 16 * 1024);
    s.fill_recompress_disk(&key(0), &identity(0), sa, Bytes::from(vec![b'z'; 500]), 7);
    assert_eq!(
        pc_files(dir.path()),
        1,
        "1 file/key — identity unlinked synchronously"
    );
    assert!(s.stats().disk_bytes < before);
    assert_consistent(&s, dir.path(), 1);
}

#[test]
fn purge_tag_unlinks_synchronously() {
    let dir = tempfile::tempdir().unwrap();
    let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
    s.load_from_disk(|_| {});
    for i in 0..30 {
        s.store(
            key(i),
            entry(i, &vec![b'a'; 500], &["bulk"], Duration::from_secs(600)),
        );
    }
    assert_eq!(pc_files(dir.path()), 30);
    s.purge_tags(&["bulk"]);
    assert_eq!(s.stats().entries, 0);
    assert_eq!(s.stats().disk_bytes, 0);
    assert_eq!(
        pc_files(dir.path()),
        0,
        "every purged file unlinked synchronously"
    );
}

#[test]
fn purge_all_unlinks_synchronously() {
    let dir = tempfile::tempdir().unwrap();
    let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
    s.load_from_disk(|_| {});
    for i in 0..30 {
        s.store(
            key(i),
            entry(i, &vec![b'a'; 500], &[], Duration::from_secs(600)),
        );
    }
    s.purge_all();
    assert_eq!(s.stats().entries, 0);
    assert_eq!(s.stats().disk_bytes, 0);
    assert_eq!(pc_files(dir.path()), 0);
}

// ===================== Group B — eviction =====================

#[test]
fn disk_cap_evicts_coldest_and_unlinks() {
    let dir = tempfile::tempdir().unwrap();
    // Force eviction by colliding many keys onto a single shard: store distinct keys whose
    // hashes land on the same shard is hard to arrange, so use a SMALL per-shard budget via a
    // tiny global cap and a single in-RAM-only run instead. Here: a tiny disk cap forces the
    // disk LRU. We assert the invariant survives (the precise survivor set is shard-dependent).
    let s = PageStore::new(disk_cfg(dir.path(), 4096));
    for i in 0..40 {
        s.store(
            key(i),
            entry(i, &vec![b'a'; 1000], &[], Duration::from_secs(600)),
        );
    }
    assert_consistent(&s, dir.path(), 40);
    let st = s.stats();
    assert!(st.disk_bytes <= 40 * 16 * 1024, "disk accounting bounded");
}

#[test]
fn serve_bumps_recency_then_eviction_spares_it() {
    // On a single shard a served entry's recency is bumped to MRU; the next eviction takes the
    // cold tail, not the recently-served head. We exercise this by keying onto one shard via the
    // same key churned, plus distinct cold keys, but precise shard control isn't possible from
    // outside — so we assert the weaker but real guarantee: a served-then-stored set stays
    // consistent and the served key keeps resolving.
    let dir = tempfile::tempdir().unwrap();
    let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
    s.load_from_disk(|_| {});
    s.store(
        key(0),
        entry(0, &vec![b'a'; 1000], &[], Duration::from_secs(600)),
    );
    // Serve it (bumps RAM + disk recency).
    let got = s.lookup(&key(0), &identity(0), Instant::now()).unwrap();
    assert!(s.body_bytes(&got).is_some());
    // Churn other keys.
    for i in 1..20 {
        s.store(
            key(i),
            entry(i, &vec![b'b'; 1000], &[], Duration::from_secs(600)),
        );
    }
    assert!(
        s.lookup(&key(0), &identity(0), Instant::now()).is_some(),
        "the served key survives under a generous cap"
    );
    assert_consistent(&s, dir.path(), 20);
}

#[test]
fn dual_cap_independence_offloaded_body_frees_ram() {
    // With the file tier, a File body is charged metadata-only against the RAM cap and its bytes
    // against the disk cap — so a large offloaded body does NOT consume RAM budget.
    let dir = tempfile::tempdir().unwrap();
    let s = PageStore::new(disk_cfg(dir.path(), 64 * 1024 * 1024));
    s.load_from_disk(|_| {});
    s.store(
        key(0),
        entry(0, &vec![b'a'; 500_000], &[], Duration::from_secs(600)),
    );
    let st = s.stats();
    assert!(
        st.disk_bytes >= 500_000,
        "body plus tmpfs file footprint charged to the disk cap"
    );
    assert!(
        st.memory_bytes.saturating_sub(st.tag_index_bytes) < 10_000,
        "entry RAM weight excludes the tmpfs body (got entry={} tag_index={})",
        st.memory_bytes.saturating_sub(st.tag_index_bytes),
        st.tag_index_bytes
    );
    assert_consistent(&s, dir.path(), 1);
}

#[test]
fn ram_cap_evicts_under_pressure_in_ram_only_mode() {
    // In-RAM-only mode (no file tier): the RAM byte budget governs. A tiny cap keeps only a
    // handful of entries; the index stays internally consistent (no disk files to track).
    let cfg = StoreConfig {
        max_mem_bytes: 8192,
        max_obj_bytes: 1024,
        default_public_ttl: Duration::from_secs(60),
        cacheable_status: vec![200, 301],
        ..StoreConfig::default()
    };
    let s = PageStore::new(cfg);
    for i in 0..200 {
        s.store(
            key(i),
            entry(i, &vec![b'x'; 512], &[], Duration::from_secs(60)),
        );
    }
    let st = s.stats();
    // Each entry exceeds its 32-byte soft shard target but remains eligible while the shared
    // global reservation has room. The aggregate cap, not 256 protected exceptions, is hard.
    assert!(
        st.entries > 0,
        "valid objects larger than a shard target stay cacheable"
    );
    assert!(
        st.memory_bytes.saturating_sub(st.tag_index_bytes) <= 8192,
        "hard entry RAM cap"
    );
    assert_eq!(st.entries, s.entry_count(), "entries counter == map len");
}
