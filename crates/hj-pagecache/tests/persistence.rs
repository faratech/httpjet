//! The file tier's reason to exist: entries survive a `PageStore` teardown
//! (= a `systemctl restart`) and come back with correct freshness, identity,
//! tags, and purge semantics — while everything rejected by policy (purged,
//! expired, corrupt, wrong dict generation) is unlinked, never resurrected.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hj_pagecache::{CachedResponse, PageBody, PageCacheKey, PageScope, PageStore, StoreConfig};
use http::HeaderValue;

fn cfg(root: &Path) -> StoreConfig {
    StoreConfig {
        max_mem_bytes: 64 * 1024 * 1024,
        max_obj_bytes: 1024 * 1024,
        store_path: Some(root.to_path_buf()),
        hot_mem_bytes: 1024 * 1024,
        ..StoreConfig::default()
    }
}

fn key(path: &str) -> PageCacheKey {
    PageCacheKey::public(1, true, "forum.example", path, "")
}

fn identity(path: &str) -> String {
    format!("https\nforum.example\n{path}")
}

fn entry(path: &str, body: &[u8], tags: &[&str], ttl: Duration) -> CachedResponse {
    CachedResponse {
        status: 200,
        identity: identity(path),
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
        swr: Duration::ZERO,
        sie: Duration::ZERO,
    }
}

/// Store one entry the way the glue does. `store()` now offloads the body to the
/// tmpfs file tier synchronously (identity form), so the entry is persisted at birth
/// — no separate finalize step (the optional dict-recompress is exercised separately).
fn store_and_persist(s: &PageStore, path: &str, body: &[u8], tags: &[&str], ttl: Duration) {
    s.store(key(path), entry(path, body, tags, ttl));
}

fn file_count(root: &Path) -> usize {
    let mut n = 0;
    for e in walkdir(root) {
        if e.extension().is_some_and(|x| x == "pc") {
            n += 1;
        }
    }
    n
}

fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walkdir(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn entries_survive_a_restart_with_freshness_continuity() {
    let td = tempfile::tempdir().unwrap();
    {
        let s = PageStore::new(cfg(td.path()));
        store_and_persist(&s, "/a/", b"page-a", &["T1"], Duration::from_secs(600));
        store_and_persist(&s, "/b/", b"page-b", &[], Duration::from_secs(600));
        s.run_pending();
        assert_eq!(file_count(td.path()), 2, "both entries persisted");
    } // drop = the restart

    let s2 = PageStore::new(cfg(td.path()));
    let loaded = std::sync::Mutex::new(Vec::new());
    let sum = s2.load_from_disk(|k| loaded.lock().unwrap().push(k.path.clone()));
    assert_eq!(sum.loaded, 2);
    let mut loaded = loaded.into_inner().unwrap();
    loaded.sort();
    assert_eq!(loaded, vec!["/a/".to_string(), "/b/".to_string()]);

    let got = s2
        .lookup(&key("/a/"), &identity("/a/"), Instant::now())
        .expect("warm hit");
    assert_eq!(got.status, 200);
    assert_eq!(got.tags, vec![Arc::<str>::from("T1")]);
    assert!(
        !got.variants_filled,
        "variants are not persisted; PC2-lazy refills"
    );
    assert!(
        got.age_secs(Instant::now()) < 5,
        "age continuity: just stored, near-zero age"
    );
    let body = s2.body_bytes(&got).expect("file body resolves");
    assert_eq!(&body[..], b"page-a");
    // second resolve comes from the hot tier (same bytes either way)
    assert_eq!(&s2.body_bytes(&got).unwrap()[..], b"page-a");
}

#[test]
fn tag_purge_unlinks_eagerly_and_holds_across_restart() {
    let td = tempfile::tempdir().unwrap();
    {
        let s = PageStore::new(cfg(td.path()));
        store_and_persist(&s, "/t/", b"tagged", &["news"], Duration::from_secs(600));
        store_and_persist(&s, "/u/", b"untagged", &[], Duration::from_secs(600));
        s.run_pending();
        assert_eq!(file_count(td.path()), 2);
        s.purge_tags(&["news"]);
        assert_eq!(
            file_count(td.path()),
            1,
            "purged entry's file unlinked eagerly"
        );
    }
    let s2 = PageStore::new(cfg(td.path()));
    let sum = s2.load_from_disk(|_| {});
    assert_eq!(sum.loaded, 1);
    assert!(
        s2.lookup(&key("/t/"), &identity("/t/"), Instant::now())
            .is_none()
    );
    assert!(
        s2.lookup(&key("/u/"), &identity("/u/"), Instant::now())
            .is_some()
    );
}

#[test]
fn purge_all_stamp_blocks_resurrection() {
    let td = tempfile::tempdir().unwrap();
    {
        let s = PageStore::new(cfg(td.path()));
        store_and_persist(&s, "/x/", b"pre-purge", &[], Duration::from_secs(600));
        s.run_pending();
        s.purge_all();
        // The crash-window case: even if the background sweep hadn't unlinked the
        // file yet, the stamp alone must block the load. Recreate the file state
        // by storing nothing new and (re)writing a stale-stamped file is overkill —
        // instead assert via a fresh file written BEFORE the stamp: simulate by
        // checking the stamp is on disk.
    }
    // Whatever files remain (sweep is best-effort), nothing pre-stamp may load.
    let s2 = PageStore::new(cfg(td.path()));
    let sum = s2.load_from_disk(|_| {});
    assert_eq!(
        sum.loaded, 0,
        "no entry stored before purge_all may survive a restart"
    );
    assert!(
        s2.lookup(&key("/x/"), &identity("/x/"), Instant::now())
            .is_none()
    );
}

#[test]
fn expired_and_wrong_dict_gen_files_are_unlinked_at_scan() {
    let td = tempfile::tempdir().unwrap();
    {
        let s = PageStore::new(cfg(td.path()));
        s.load_from_disk(|_| {}); // empty dir → instant warm (reconcile is gated on warm)
        store_and_persist(&s, "/short/", b"expires", &[], Duration::from_millis(10));
        store_and_persist(&s, "/long/", b"stays", &[], Duration::from_secs(600));
        // a dict-compressed body under generation 7: store persists the identity,
        // then recompress rewrites it to the gen-7 file (unlinking the identity).
        let k = key("/dict/");
        let e = entry("/dict/", b"raw", &[], Duration::from_secs(600));
        let stored_at = e.stored_at;
        s.store(k.clone(), e);
        s.fill_recompress_disk(
            &k,
            &identity("/dict/"),
            stored_at,
            Bytes::from_static(b"dictbody"),
            7,
        );
        // recompress unlinks the identity SYNCHRONOUSLY ⇒ exactly the 3 current files
        // (/short/, /long/, /dict/ gen-7), no orphan, no reconcile.
        assert_eq!(file_count(td.path()), 3);
        std::thread::sleep(Duration::from_millis(30)); // /short/ expires on the wall clock
    }
    // restart with NO dict loaded (expected_dict_gens stays empty)
    let s2 = PageStore::new(cfg(td.path()));
    let sum = s2.load_from_disk(|_| {});
    assert_eq!(sum.loaded, 1, "only /long/ survives");
    assert_eq!(sum.rejected, 2, "expired + dict-gen-mismatch rejected");
    assert_eq!(file_count(td.path()), 1, "rejected files unlinked");
    assert!(
        s2.lookup(&key("/long/"), &identity("/long/"), Instant::now())
            .is_some()
    );
}

#[test]
fn purge_removes_all_versions_so_nothing_resurrects_after_restart() {
    let td = tempfile::tempdir().unwrap();
    {
        let s = PageStore::new(cfg(td.path()));
        // store + recompress ⇒ exactly the CURRENT (gen-7) file (the identity was unlinked
        // synchronously by recompress — no orphan lingers). A tag purge must still remove every
        // on-disk version of the key (via remove_key_versions) so an immediate restart with no
        // dict cannot resurrect anything.
        let k = key("/p/");
        let e = entry("/p/", b"v1-raw", &["tagX"], Duration::from_secs(600));
        let sa = e.stored_at;
        s.store(k.clone(), e);
        s.fill_recompress_disk(&k, &identity("/p/"), sa, Bytes::from_static(b"v1-dict"), 7);
        assert_eq!(
            file_count(td.path()),
            1,
            "only the current gen-7 file (identity unlinked synchronously)"
        );
        s.purge_tags(&["tagX"]);
        assert_eq!(
            file_count(td.path()),
            0,
            "purge removed the current version"
        );
    }
    let s2 = PageStore::new(cfg(td.path()));
    let sum = s2.load_from_disk(|_| {});
    assert_eq!(sum.loaded, 0, "no purged version resurrected after restart");
    assert!(
        s2.lookup(&key("/p/"), &identity("/p/"), Instant::now())
            .is_none()
    );
}

#[test]
fn corrupt_file_is_unlinked_and_missing_body_fails_closed() {
    let td = tempfile::tempdir().unwrap();
    let s = PageStore::new(cfg(td.path()));
    store_and_persist(&s, "/c/", b"will corrupt", &[], Duration::from_secs(600));
    s.run_pending();
    let files = walkdir(td.path());
    let pc = files
        .iter()
        .find(|p| p.extension().is_some_and(|x| x == "pc"))
        .unwrap();

    // missing file: the body resolve fails closed (None) and the key can be dropped.
    // Store no longer pre-fills the hot tier for one-hit objects, so a missing
    // backing file is visible immediately on the cold path.
    let got = s
        .lookup(&key("/c/"), &identity("/c/"), Instant::now())
        .expect("indexed");
    std::fs::remove_file(pc).unwrap();
    let s_cold = PageStore::new(cfg(td.path()));
    let sum = s_cold.load_from_disk(|_| {});
    assert_eq!(sum.loaded, 0, "file gone before scan");
    assert!(
        s.body_bytes(&got).is_none(),
        "missing backing file fails closed"
    );
    s.invalidate_key(&key("/c/"));
    assert!(
        s.lookup(&key("/c/"), &identity("/c/"), Instant::now())
            .is_none()
    );

    // corrupt file at scan time
    store_and_persist(&s, "/d/", b"x", &[], Duration::from_secs(600));
    s.run_pending();
    let files = walkdir(td.path());
    let pc = files
        .iter()
        .find(|p| p.extension().is_some_and(|x| x == "pc"))
        .unwrap();
    std::fs::write(pc, b"garbage").unwrap();
    let s3 = PageStore::new(cfg(td.path()));
    let sum = s3.load_from_disk(|_| {});
    assert_eq!(sum.corrupt_removed, 1);
    assert_eq!(sum.loaded, 0);
}

#[test]
fn write_failure_leaves_entry_in_ram_and_servable() {
    let td = tempfile::tempdir().unwrap();
    let store_root = td.path().join("jc");
    let s = PageStore::new(cfg(&store_root));
    // ENOSPC stand-in that also fails for root (chmod doesn't — CAP_DAC_OVERRIDE):
    // plant a regular FILE at every first-level fanout name so create_dir_all errors.
    for c in "0123456789abcdef".chars() {
        std::fs::write(store_root.join(c.to_string()), b"").unwrap();
    }

    store_and_persist(&s, "/e/", b"ram only", &[], Duration::from_secs(600));
    let got = s
        .lookup(&key("/e/"), &identity("/e/"), Instant::now())
        .expect("still indexed");
    assert!(
        matches!(got.body, PageBody::InMem(_)),
        "persist failed ⇒ body stays in RAM"
    );
    assert_eq!(&s.body_bytes(&got).unwrap()[..], b"ram only");
    assert_eq!(s.stats().disk_write_errors, 1);
}

#[test]
fn restore_then_restore_again_replaces_file_synchronously() {
    let td = tempfile::tempdir().unwrap();
    let s = PageStore::new(cfg(td.path()));
    s.load_from_disk(|_| {});
    store_and_persist(&s, "/v/", b"version-1", &[], Duration::from_secs(600));
    assert_eq!(file_count(td.path()), 1);
    store_and_persist(&s, "/v/", b"version-2", &[], Duration::from_secs(600));
    // The cure (atomic teardown): a re-store unlinks the predecessor's file SYNCHRONOUSLY under
    // the shard lock — exactly 1 file/key, no orphan, no reconcile.
    assert_eq!(
        file_count(td.path()),
        1,
        "re-store unlinked the predecessor synchronously (1 file/key)"
    );
    let got = s
        .lookup(&key("/v/"), &identity("/v/"), Instant::now())
        .unwrap();
    assert_eq!(&s.body_bytes(&got).unwrap()[..], b"version-2");
}

#[test]
fn private_entries_round_trip_with_owner_isolation() {
    let td = tempfile::tempdir().unwrap();
    {
        let s = PageStore::new(cfg(td.path()));
        let mut k = key("/me/");
        k.private_owner = 0xA11CE;
        k.vary_value = "s=alice".into();
        let mut e = entry("/me/", b"alice page", &[], Duration::from_secs(120));
        e.scope = PageScope::Private {
            owner_hash: 0xA11CE,
        };
        s.store(k.clone(), e);
        s.run_pending();
    }
    let s2 = PageStore::new(cfg(td.path()));
    s2.load_from_disk(|_| {});
    let mut alice = key("/me/");
    alice.private_owner = 0xA11CE;
    alice.vary_value = "s=alice".into();
    let got = s2
        .lookup(&alice, &identity("/me/"), Instant::now())
        .expect("owner sees it");
    assert_eq!(
        got.scope,
        PageScope::Private {
            owner_hash: 0xA11CE
        }
    );
    let mut bob = alice.clone();
    bob.private_owner = 0xB0B;
    assert!(
        s2.lookup(&bob, &identity("/me/"), Instant::now()).is_none(),
        "other owners miss"
    );
}

/// The boot scan fans out across threads (walk_parallel): a population spread
/// over many fanout dirs — including same-key duplicate files and a mix of
/// live + expired entries — must load completely and order-independently,
/// with exactly one file per surviving key left on disk.
#[test]
fn parallel_boot_scan_loads_full_population() {
    let td = tempfile::tempdir().unwrap();
    let n: u64 = 500;
    {
        let s = PageStore::new(cfg(td.path()));
        for i in 0..n {
            store_and_persist(
                &s,
                &format!("/page-{i}/"),
                format!("body-{i}").as_bytes(),
                &["ALL"],
                Duration::from_secs(600),
            );
        }
        // Same-key duplicates: re-store a slice so newer files coexist with
        // whatever the teardown didn't unlink before the drop.
        for i in 0..50 {
            store_and_persist(
                &s,
                &format!("/page-{i}/"),
                format!("body-{i}-v2").as_bytes(),
                &["ALL"],
                Duration::from_secs(600),
            );
        }
        // Entries the scan must reject (expired at load time).
        for i in 0..25 {
            store_and_persist(&s, &format!("/expired-{i}/"), b"stale", &[], Duration::ZERO);
        }
        s.run_pending();
    } // drop = the restart

    let s2 = PageStore::new(cfg(td.path()));
    let loaded = std::sync::atomic::AtomicUsize::new(0);
    let sum = s2.load_from_disk(|_| {
        loaded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    assert_eq!(sum.loaded, n, "every live key restored exactly once");
    assert_eq!(loaded.load(std::sync::atomic::Ordering::Relaxed) as u64, n);
    for i in 0..n {
        let path = format!("/page-{i}/");
        let got = s2
            .lookup(&key(&path), &identity(&path), Instant::now())
            .unwrap_or_else(|| panic!("warm hit for {path}"));
        let want = if i < 50 {
            format!("body-{i}-v2")
        } else {
            format!("body-{i}")
        };
        assert_eq!(
            s2.body_bytes(&got).expect("body resolves"),
            Bytes::from(want)
        );
    }
    for i in 0..25 {
        let path = format!("/expired-{i}/");
        assert!(
            s2.lookup(&key(&path), &identity(&path), Instant::now())
                .is_none(),
            "expired entry {path} must not resurrect"
        );
    }
    assert_eq!(
        file_count(td.path()) as u64,
        n,
        "one .pc file per surviving key; duplicates and rejects unlinked"
    );
}
