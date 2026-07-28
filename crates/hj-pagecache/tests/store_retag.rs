//! Regression (#7 follow-up): re-storing a key with a DIFFERENT tag set must drop it from
//! its old tags. The eviction listener skips `RemovalCause::Replaced` (so a same-tag
//! re-store keeps its live tags), but a tag-set change would otherwise leave the key
//! registered under its old tag — so a purge of the OLD tag would wrongly invalidate it
//! (over-purge) and the old tag's index entry leaks. `store()` cleans the old-only tags
//! under its write lock.

use std::sync::Arc;
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
fn restore_with_new_tag_set_drops_old_tag() {
    let s = PageStore::new(cfg());
    let k = PageCacheKey::public(1, true, "forum.example", "/threads/7", "");

    // Store under [thread_7], then re-store the SAME key under [thread_8] (e.g. a tag change).
    s.store(k.clone(), entry(b"v1", &["thread_7"]));
    s.run_pending();
    s.store(k.clone(), entry(b"v2", &["thread_8"]));
    s.run_pending();

    // Purging the OLD tag must NOT invalidate the entry — it no longer carries thread_7.
    s.purge_tags(&["thread_7"]);
    s.run_pending();
    assert!(
        s.lookup(&k, "id", Instant::now()).is_some(),
        "purging the old tag must not over-purge a re-tagged entry"
    );

    // Purging the NEW tag must invalidate it.
    s.purge_tags(&["thread_8"]);
    s.run_pending();
    assert!(
        s.lookup(&k, "id", Instant::now()).is_none(),
        "purging the current tag must invalidate the entry"
    );
}
