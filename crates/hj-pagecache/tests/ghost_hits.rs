//! (#1217) Ghost hits: a counted miss on a key the disk LRU evicted while its copy was
//! still fresh. The file tier can sit at its cap with a low hit ratio; this counter says
//! whether a larger cap would turn misses into hits or only keep bodies nobody reads.

use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hj_pagecache::{
    CachedResponse, EntryState, PageBody, PageCacheKey, PageScope, PageStore, StoreConfig,
};
use http::HeaderValue;

const KEYS: usize = 1500;
const TTL: Duration = Duration::from_secs(600);

/// A file tier whose per-shard budget holds one small body but not two, so most of
/// `KEYS` stores evict an earlier entry of the same shard.
fn tight_store(dir: &Path) -> PageStore {
    let store = PageStore::new(StoreConfig {
        max_mem_bytes: 64 * 1024 * 1024,
        max_disk_bytes: 256 * 6000,
        max_obj_bytes: 1024 * 1024,
        store_path: Some(dir.to_path_buf()),
        hot_mem_bytes: 1024 * 1024,
        ..StoreConfig::default()
    });
    store.load_from_disk(|_| {});
    store
}

fn key(i: usize) -> PageCacheKey {
    PageCacheKey::public(1, true, "h", format!("/p{i}"), "")
}

fn identity(i: usize) -> String {
    format!("h\n/p{i}")
}

fn fill(store: &PageStore) {
    for i in 0..KEYS {
        store.store(
            key(i),
            CachedResponse {
                status: 200,
                identity: identity(i),
                headers: vec![(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html"),
                )],
                body: PageBody::InMem(Bytes::from(vec![b'a'; 1000])),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: Vec::new(),
                vary_cookie_name: String::new(),
                vary_value: String::new(),
                scope: PageScope::Public,
                stored_at: Instant::now(),
                ttl: TTL,
                swr: Duration::ZERO,
                sie: Duration::ZERO,
            },
        );
    }
}

/// Counted lookups of every key at `now`; returns how many missed.
fn lookup_all(store: &PageStore, now: Instant) -> u64 {
    (0..KEYS)
        .filter(|i| {
            matches!(
                store.get_entry(&key(*i), &identity(*i), now),
                EntryState::Miss
            )
        })
        .count() as u64
}

#[test]
fn a_miss_on_a_still_fresh_evicted_key_is_a_ghost_hit_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = tight_store(dir.path());
    fill(&store);
    let evicted = store.stats().disk_evictions;
    assert!(evicted > 100, "the tight cap must evict: {evicted}");
    assert_eq!(store.stats().ghost_hits, 0, "nothing was looked up yet");

    let misses = lookup_all(&store, Instant::now());
    let ghosts = store.stats().ghost_hits;
    assert!(misses >= evicted, "{misses} misses for {evicted} evictions");
    assert!(
        ghosts <= evicted,
        "{ghosts} ghost hits for {evicted} evictions"
    );
    // The record of evictions is a direct-mapped sample: a few share a slot.
    assert!(
        ghosts * 10 >= evicted * 9,
        "{ghosts} ghost hits for {evicted} evictions"
    );

    // Each eviction is counted at most once.
    lookup_all(&store, Instant::now());
    assert_eq!(store.stats().ghost_hits, ghosts);
}

#[test]
fn an_evicted_key_past_its_ttl_is_not_a_ghost_hit() {
    let dir = tempfile::tempdir().unwrap();
    let store = tight_store(dir.path());
    fill(&store);
    assert!(store.stats().disk_evictions > 100);

    // The evicted copies would have expired by now: a larger cap would not have helped.
    lookup_all(&store, Instant::now() + TTL + Duration::from_secs(1));
    assert_eq!(store.stats().ghost_hits, 0);
}

#[test]
fn a_store_without_a_file_tier_records_no_ghosts() {
    let store = PageStore::new(StoreConfig {
        max_mem_bytes: 64 * 1024,
        ..StoreConfig::default()
    });
    fill(&store);
    lookup_all(&store, Instant::now());
    assert_eq!(store.stats().ghost_hits, 0);
}
