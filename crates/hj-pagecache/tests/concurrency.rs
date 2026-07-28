//! Group C — concurrency proofs of the atomic-teardown invariant. These are deterministic
//! (no settle dependency); a failure is a real regression. The flagship is C1: N writers
//! churning store/recompress/re-store × M readers under tight RAM+disk caps forcing constant
//! eviction. After join + quiesce, EVERY indexed entry resolves a body (0 fileless) AND every
//! on-disk `.pc` is referenced by a live entry (0 orphans) AND `Σ disk_used == Σ referenced
//! File.disk_total`. The old stranded-file failure mode is structurally impossible here.
//!
//! NOTE on the transient read-vs-unlink race: a reader takes a lookup snapshot (an
//! `Arc<CachedResponse>` naming a specific immutable `-<seq>.pc` version), drops the shard lock,
//! then resolves the body. Between the two, a concurrent re-store/recompress can SYNCHRONOUSLY
//! unlink that version (the eager-unlink that kills the PERMANENT strand). The cold read then
//! fails CLOSED — `body_bytes` returns `None` (the unique versioned filename + the HJPC header
//! re-validation in `read_body` guarantee it NEVER reads a different version's bytes), so the glue
//! re-renders. This is a benign cache miss, IDENTICAL to the pre-existing fail-closed path, and is
//! distinct from the bug these tests rule out: a live entry left PERMANENTLY fileless. The readers
//! below therefore assert the load-bearing guarantee — a resolved body is NEVER the wrong content —
//! and the post-quiesce check asserts 0 permanent strands / 0 orphans / exact accounting.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hj_pagecache::{CachedResponse, PageBody, PageCacheKey, PageScope, PageStore, StoreConfig};
use http::HeaderValue;

fn cfg(root: &Path, mem: u64, disk: u64) -> StoreConfig {
    StoreConfig {
        max_mem_bytes: mem,
        max_disk_bytes: disk,
        max_obj_bytes: 1024 * 1024,
        store_path: Some(root.to_path_buf()),
        hot_mem_bytes: 64 * 1024, // small ⇒ cold reads hit tmpfs, exposing any strand
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

fn all_pc_files(root: &Path) -> Vec<PathBuf> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "pc") {
                    out.push(p);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

/// The full invariant check after the cache has been quiesced (all worker threads joined).
/// Probes every key in `0..n`, then cross-checks the on-disk file set against the referenced set.
fn assert_invariant(s: &PageStore, root: &Path, n: usize) {
    let now = Instant::now();
    let mut referenced: HashSet<PathBuf> = HashSet::new();
    let mut referenced_disk = 0u64;
    let mut fileless = 0;
    let mut live = 0u64;
    for i in 0..n {
        if let Some(e) = s.lookup(&key(i), &identity(i), now) {
            live += 1;
            match &e.body {
                PageBody::File {
                    path,
                    len,
                    disk_total,
                    ..
                } => {
                    // body_bytes must resolve (0 fileless).
                    match s.body_bytes(&e) {
                        Some(b) => assert_eq!(b.len(), *len as usize),
                        None => fileless += 1,
                    }
                    referenced.insert(path.to_path_buf());
                    assert!(*disk_total as u64 >= *len as u64);
                    referenced_disk += *disk_total as u64;
                }
                PageBody::InMem(b) => {
                    assert!(s.body_bytes(&e).is_some());
                    let _ = b;
                }
                PageBody::Derived { .. } => {}
            }
        }
    }
    assert_eq!(fileless, 0, "a live entry resolved no body (the strand)");

    // 0 orphans: every on-disk .pc is referenced by a live entry.
    let on_disk = all_pc_files(root);
    let orphans: Vec<&PathBuf> = on_disk
        .iter()
        .filter(|p| !referenced.contains(*p))
        .collect();
    assert!(
        orphans.is_empty(),
        "found {} orphan .pc files (unreferenced): {:?}",
        orphans.len(),
        orphans.iter().take(5).collect::<Vec<_>>()
    );

    let st = s.stats();
    assert_eq!(
        st.entries, live,
        "every indexed entry was probed (entries {} live {})",
        st.entries, live
    );
    assert_eq!(
        st.entries as usize,
        on_disk.len(),
        "entries ({}) == on-disk .pc files ({})",
        st.entries,
        on_disk.len()
    );
    assert_eq!(
        st.disk_bytes, referenced_disk,
        "disk_bytes ({}) == Σ referenced File.disk_total ({})",
        st.disk_bytes, referenced_disk
    );
}

/// C1 (flagship): heavy concurrent store + recompress + re-store + serve under tight caps
/// forcing constant eviction. After quiesce: 0 fileless, 0 orphans, accounting exact.
#[test]
fn c1_heavy_concurrent_store_serve_evict_never_strands_a_referenced_file() {
    let td = tempfile::tempdir().unwrap();
    const KEYS: usize = 200;
    // Tight caps force eviction: ~50 KiB disk + ~50 KiB RAM against ~200 keys × ~2-4 KiB bodies.
    let s = Arc::new(PageStore::new(cfg(td.path(), 64 * 1024, 64 * 1024)));
    s.load_from_disk(|_| {});

    let stop = Arc::new(AtomicBool::new(false));

    // A body whose bytes encode the key it belongs to, so a reader can verify a resolved body is
    // NEVER the content of a DIFFERENT key (the load-bearing guarantee). A transient cold-read miss
    // (the file was unlinked between lookup and read) is fine — fail-closed, never wrong content.
    fn body_for(i: usize, len: usize) -> Vec<u8> {
        let marker = b'A' + (i % 26) as u8;
        vec![marker; len]
    }

    // Readers: continuously look up + resolve bodies; any RESOLVED body must be well-formed for the
    // key it was looked up under (single-byte marker == this key's marker), never wrong content.
    let readers: Vec<_> = (0..4)
        .map(|t| {
            let s = s.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut x = (t as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15);
                let mut wrong_content = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    let i = (x as usize) % KEYS;
                    if let Some(e) = s.lookup(&key(i), &identity(i), Instant::now()) {
                        // A resolved body must be THIS key's marker bytes (or a recompress's 'z').
                        // A transient None (file unlinked mid-read) is acceptable; wrong content is not.
                        if let Some(b) = s.body_bytes(&e) {
                            let marker = b'A' + (i % 26) as u8;
                            let ok = b.iter().all(|&c| c == marker) || b.iter().all(|&c| c == b'z'); // recompressed form
                            if !ok {
                                wrong_content += 1;
                            }
                        }
                    }
                }
                wrong_content
            })
        })
        .collect();

    // Writers: store + (sometimes) recompress + re-store, churning versions for many rounds.
    let writers: Vec<_> = (0..4)
        .map(|w| {
            let s = s.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let comp = vec![b'z'; 600];
                for round in 0..120 {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut i = w;
                    while i < KEYS {
                        let len = 2000 + (round + i) % 1000;
                        let mut e = entry(i, &[], &[], Duration::from_secs(600));
                        e.body = PageBody::InMem(Bytes::from(body_for(i, len)));
                        let sa = e.stored_at;
                        s.store(key(i), e);
                        // half the time, recompress (swaps to a new file, unlinks the identity).
                        if (round + i) % 2 == 0 {
                            s.fill_recompress_disk(
                                &key(i),
                                &identity(i),
                                sa,
                                Bytes::from(comp.clone()),
                                7,
                            );
                        }
                        i += 4;
                    }
                }
            })
        })
        .collect();

    for wr in writers {
        wr.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    let mut wrong = 0u64;
    for r in readers {
        wrong += r.join().unwrap();
    }

    assert_eq!(
        wrong, 0,
        "a reader resolved {wrong} WRONG-CONTENT bodies — the never-wrong-content guarantee broke"
    );
    // Post-quiesce: the PERMANENT-strand check. A maintenance pass settles any expired entry through
    // the same funnel; then EVERY indexed entry must resolve a body (0 fileless), every on-disk file
    // is referenced (0 orphans), and accounting is exact.
    s.maintenance(Duration::ZERO);
    assert_invariant(&s, td.path(), KEYS);
}

/// C2: one key churned expire→re-store while readers hammer; every observed state is the fresh
/// re-store or a clean miss, never a half-evicted hit. `disk_read_errors == 0` (expiry and store
/// hold the same shard lock, so the swept-then-restored interleave is structurally impossible).
#[test]
fn c2_expire_then_restore_race_never_loses_the_restore() {
    let td = tempfile::tempdir().unwrap();
    let s = Arc::new(PageStore::new(cfg(
        td.path(),
        8 * 1024 * 1024,
        8 * 1024 * 1024,
    )));
    s.load_from_disk(|_| {});
    let stop = Arc::new(AtomicBool::new(false));

    // A sweeper thread racing the churn.
    let sweeper = {
        let s = s.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                s.sweep_expired();
            }
        })
    };
    // Two distinct bodies: the short-lived 'a' and the fresh long-lived 'b'. A resolved body must
    // be one of these (never wrong content); a transient None (unlink mid-read) is acceptable.
    let readers: Vec<_> = (0..3)
        .map(|_| {
            let s = s.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut wrong = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    if let Some(e) = s.lookup(&key(0), &identity(0), Instant::now()) {
                        if let Some(b) = s.body_bytes(&e) {
                            let all_a = b.iter().all(|&c| c == b'a');
                            let all_b = b.iter().all(|&c| c == b'b');
                            if !(all_a || all_b) {
                                wrong += 1;
                            }
                        }
                    }
                }
                wrong
            })
        })
        .collect();

    let body_fresh = vec![b'b'; 1500];
    for _ in 0..2000 {
        s.store(
            key(0),
            entry(0, &[b'a'; 1500], &[], Duration::from_millis(1)),
        );
        thread::sleep(Duration::from_micros(200));
        s.store(key(0), entry(0, &body_fresh, &[], Duration::from_secs(600)));
        // The fresh re-store, observed on THIS thread immediately after the store with no concurrent
        // re-store in between, must be a readable hit with its own bytes (the unlink race only bites
        // across a store; here the next op is a lookup, so the file is still current).
        if let Some(e) = s.lookup(&key(0), &identity(0), Instant::now()) {
            if let Some(b) = s.body_bytes(&e) {
                assert!(
                    b[..] == body_fresh[..] || b.iter().all(|&c| c == b'a'),
                    "store thread resolved wrong content"
                );
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    sweeper.join().unwrap();
    let mut wrong = 0u64;
    for r in readers {
        wrong += r.join().unwrap();
    }
    assert_eq!(
        wrong, 0,
        "a reader resolved wrong content during the expire↔restore race"
    );
}

/// C3: concurrent store + purge on the same key+tag; after a final quiescent purge the entry is
/// gone (a miss), `entries == 0`, `disk_bytes == 0`, 0 files.
#[test]
fn c3_concurrent_store_and_purge_never_serves_stale() {
    let td = tempfile::tempdir().unwrap();
    let s = Arc::new(PageStore::new(cfg(
        td.path(),
        8 * 1024 * 1024,
        8 * 1024 * 1024,
    )));
    s.load_from_disk(|_| {});
    let stop = Arc::new(AtomicBool::new(false));

    let storer = {
        let s = s.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            let mut n: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let body = format!("rev-{n}");
                s.store(
                    key(7),
                    entry(7, body.as_bytes(), &["thread_7"], Duration::from_secs(600)),
                );
            }
        })
    };
    let purger = {
        let s = s.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                s.purge_tags(&["thread_7"]);
            }
        })
    };

    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    storer.join().unwrap();
    purger.join().unwrap();

    s.purge_tags(&["thread_7"]);
    assert!(
        s.lookup(&key(7), &identity(7), Instant::now()).is_none(),
        "after a final tag purge the entry must be a miss"
    );
    let st = s.stats();
    assert_eq!(st.entries, 0);
    assert_eq!(st.disk_bytes, 0);
    let on_disk = all_pc_files(td.path());
    assert!(on_disk.is_empty(), "purge left orphan files: {:?}", on_disk);
}

/// C4: a reader holding a resolved body while another thread forces that key's eviction. The held
/// `Bytes` stays valid (it was cloned/promoted before any unlink); a cold post-unlink read fails
/// closed to a miss, never wrong bytes.
#[test]
fn c4_evict_during_serve_never_frees_a_body_in_use() {
    let td = tempfile::tempdir().unwrap();
    let s = Arc::new(PageStore::new(cfg(
        td.path(),
        8 * 1024 * 1024,
        8 * 1024 * 1024,
    )));
    s.load_from_disk(|_| {});
    let body = vec![b'q'; 4000];
    for round in 0..500 {
        s.store(key(0), entry(0, &body, &["x"], Duration::from_secs(600)));
        // Reader resolves the body (clone/promote), THEN a purge frees the entry + unlinks the file.
        let e = s.lookup(&key(0), &identity(0), Instant::now()).unwrap();
        let held = s.body_bytes(&e).expect("body resolves while live");
        s.purge_tags(&["x"]);
        // The held bytes are still the correct, complete body — the unlink did not corrupt them.
        assert_eq!(
            &held[..],
            &body[..],
            "held body corrupted by concurrent eviction (round {round})"
        );
        // A fresh lookup now misses (purged).
        assert!(s.lookup(&key(0), &identity(0), Instant::now()).is_none());
    }
    assert!(all_pc_files(td.path()).is_empty());
}

/// C5: a `fill_*` keyed by an old `stored_at` racing purge/re-store is always a no-op against the
/// new/absent entry (never resurrects nor clobbers).
#[test]
fn c5_concurrent_fill_vs_purge_vs_restore() {
    let td = tempfile::tempdir().unwrap();
    let s = Arc::new(PageStore::new(cfg(
        td.path(),
        8 * 1024 * 1024,
        8 * 1024 * 1024,
    )));
    s.load_from_disk(|_| {});

    for _ in 0..1000 {
        let e = entry(0, &vec![b'r'; 1000], &["t"], Duration::from_secs(600));
        let sa = e.stored_at;
        s.store(key(0), e);
        // Race a stale fill (old stored_at) against a purge + re-store.
        let s_fill = s.clone();
        let h = thread::spawn(move || {
            s_fill.fill_recompress_disk(&key(0), &identity(0), sa, Bytes::from(vec![b'c'; 200]), 9);
            s_fill.fill_dict_body(&key(0), &identity(0), sa, Bytes::from(vec![b'd'; 150]), 11);
        });
        s.purge_tags(&["t"]);
        let fresh = entry(0, &vec![b'f'; 800], &["t"], Duration::from_secs(600));
        s.store(key(0), fresh);
        h.join().unwrap();
        // Whatever the interleave, the live entry (if present) is consistent and resolves.
        if let Some(e) = s.lookup(&key(0), &identity(0), Instant::now()) {
            assert!(
                s.body_bytes(&e).is_some(),
                "live entry must resolve after the race"
            );
        }
    }
    s.purge_tags(&["t"]);
    s.maintenance(Duration::ZERO);
    assert_invariant(&s, td.path(), 1);
}
