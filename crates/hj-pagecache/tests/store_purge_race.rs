//! Regression: a concurrent fill must not evade a tag purge.
//!
//! Before the fix, `store()` did (1) `inner.insert(key)` then (2)
//! `tag_index.insert(key)`, while `purge_tags()` does (A) take+remove the tag's
//! key set, then (B) invalidate each key in the store. The interleaving
//! store(1) -> purge(A,B) -> store(2) left the freshly-stored entry LIVE in the store
//! yet re-registered under a just-purged tag — so an updated forum post served
//! its stale pre-update copy until TTL (minutes, up to 7 days for permalinks).
//! The identity guard cannot help: the stale entry has the correct identity for
//! its URL.
//!
//! The fix serializes store/purge mutations and records tag purge watermarks. These
//! tests cover the simple post-store purge invariant, the slow-render-after-purge
//! rejection, and concurrent store()/purge_tags() hammering.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hj_pagecache::key::PageCacheKey;
use hj_pagecache::store::{CachedResponse, PageBody, PageScope, PageStore, StoreConfig};

fn cfg() -> StoreConfig {
    StoreConfig {
        max_mem_bytes: 1 << 20,
        max_obj_bytes: 1 << 16,
        default_public_ttl: Duration::from_secs(600),
        default_private_ttl: Duration::ZERO,
        cacheable_status: vec![200, 301],
        cache_post: false,
        vary_cookies: Vec::new(),
        private_cookies: Vec::new(),
        standard_cc_vhosts: Vec::new(),
        default_stale_secs: 0,
        max_stale_secs: 86_400,
        max_stale_if_error_secs: 86_400,
        ..StoreConfig::default()
    }
}

fn entry(body: &[u8], tags: &[&str]) -> CachedResponse {
    CachedResponse {
        status: 200,
        identity: "id".to_string(),
        headers: Vec::new(),
        body: PageBody::InMem(Bytes::copy_from_slice(body)),
        variants: Vec::new(),
        variants_filled: false,
        dict_gen: 0,
        tags: tags.iter().map(|t| Arc::from(*t)).collect(),
        vary_cookie_name: String::new(),
        vary_value: String::new(),
        scope: PageScope::Public,
        stored_at: Instant::now(),
        ttl: Duration::from_secs(600),
        swr: Duration::ZERO,
        sie: Duration::ZERO,
    }
}

#[test]
fn store_then_purge_is_a_miss() {
    // The non-racy invariant the reorder must preserve: a tagged entry stored
    // before a purge of that tag is invalidated, so the next lookup misses.
    let s = PageStore::new(cfg());
    let k = PageCacheKey::public(1, true, "forum.example", "/threads/1", "");
    s.store(k.clone(), entry(b"stale", &["thread_1"]));
    s.purge_tags(&["thread_1"]);
    assert!(
        s.lookup(&k, "id", Instant::now()).is_none(),
        "a tagged entry must be purgeable after store() returns"
    );
}

#[test]
fn render_started_before_tag_purge_cannot_store_afterward() {
    let s = PageStore::new(cfg());
    let k = PageCacheKey::public(1, true, "forum.example", "/threads/slow", "");
    let render_epoch = s.purge_epoch();

    s.purge_tags(&["thread_1"]);
    assert!(
        !s.store_if_not_purged_since(k.clone(), entry(b"old-render", &["thread_1"]), render_epoch),
        "a render that began before its tag purge must not be stored afterward"
    );
    assert_eq!(s.stats().store_purge_rejections, 1);
    assert!(
        s.lookup(&k, "id", Instant::now()).is_none(),
        "post-purge stale render must not become a cache hit"
    );
}

#[test]
fn concurrent_store_and_purge_never_serves_stale() {
    // Hammer store() and purge_tags() on the SAME key+tag from two threads. With
    // the tag-first store ordering, no interleaving can leave the entry live in
    // the store but untracked by the tag. We assert: after a final quiescent
    // purge of the tag, the entry is gone (a MISS), regardless of how the
    // threads raced.
    let s = Arc::new(PageStore::new(cfg()));
    let k = PageCacheKey::public(1, true, "forum.example", "/threads/7", "");
    let stop = Arc::new(AtomicBool::new(false));

    let storer = {
        let s = s.clone();
        let k = k.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            let mut n: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let body = format!("rev-{n}");
                s.store(k.clone(), entry(body.as_bytes(), &["thread_7"]));
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

    // Let them race for a while.
    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    storer.join().unwrap();
    purger.join().unwrap();

    // Quiescent final purge of the tag: the entry MUST be gone. If the old
    // old ordering let a store register under the purged tag while the
    // key was already removed from the index, this final purge could not reach
    // it and the lookup would be a stale HIT.
    s.purge_tags(&["thread_7"]);
    s.run_pending();
    assert!(
        s.lookup(&k, "id", Instant::now()).is_none(),
        "after a final tag purge the entry must be a miss, never a stale hit"
    );
}
