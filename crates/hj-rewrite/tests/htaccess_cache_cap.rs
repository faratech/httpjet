//! Regression for the unbounded `HtaccessCache` growth DoS: the map is keyed by
//! the (attacker-controlled) request directory, so a flood of distinct paths must
//! NOT grow it past the soft cap. We drive `get_or_load_named` with far more than
//! `HtaccessCache::MAX_ENTRIES` distinct synthetic directories and assert the map
//! never exceeds the cap, while lookups past the cap still return correct results.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use hj_rewrite::HtaccessCache;

/// Drive more distinct directories than the cap allows; the map must never exceed
/// `MAX_ENTRIES`. Use `revalidate_ttl = 0` so every call re-stats (no TTL coalescing
/// masks the insert path). The synthetic dirs do not exist on disk, so each load is
/// a clean miss (`parsed: None`) — exactly the absent-file insert the bug grew on.
#[test]
fn cap_bounds_distinct_path_flood() {
    let cache = HtaccessCache::with_revalidate_ttl(Duration::from_secs(0));
    let cap = HtaccessCache::MAX_ENTRIES;

    let base = PathBuf::from("/nonexistent-httpjet-cap-test-root");
    for i in 0..(cap + 5_000) {
        let dir = base.join(format!("seg-{i}"));
        // No `.htaccess` exists there, so this is a miss; pre-fix this inserted an
        // Entry { parsed: None } unconditionally and grew the map without bound.
        assert!(cache.get_or_load_named(&dir, ".htaccess").is_none());
        assert!(
            cache.len() <= cap,
            "cache grew past cap: len={} > cap={} at i={i}",
            cache.len(),
            cap
        );
    }
    assert!(
        cache.len() <= cap,
        "final len {} exceeds cap {cap}",
        cache.len()
    );
}

/// Past the cap, a directory that *does* hold a real `.htaccess` must still parse
/// correctly (the cap only blocks memoization, never correctness), and a still-absent
/// directory must still resolve to `None`.
#[test]
fn correctness_holds_past_cap() {
    let cache = HtaccessCache::with_revalidate_ttl(Duration::from_secs(0));
    let cap = HtaccessCache::MAX_ENTRIES;

    // Fill the cache to (at least) the cap with absent synthetic directories.
    let base = PathBuf::from("/nonexistent-httpjet-cap-test-root2");
    for i in 0..(cap + 100) {
        let dir = base.join(format!("seg-{i}"));
        let _ = cache.get_or_load_named(&dir, ".htaccess");
    }
    assert!(cache.len() <= cap);

    // A real `.htaccess` in a fresh temp dir must still parse and apply past the cap.
    let tmp = std::env::temp_dir().join(format!("hj-cap-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("mkdir tmp");
    fs::write(
        tmp.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^foo$ /bar [L]\n",
    )
    .expect("write .htaccess");

    let parsed = cache.get_or_load_named(&tmp, ".htaccess");
    assert!(
        parsed.is_some(),
        "real .htaccess must still parse past the cap"
    );

    // A still-absent directory past the cap resolves to None (no false hit).
    let absent = base.join("definitely-absent-after-cap");
    assert!(cache.get_or_load_named(&absent, ".htaccess").is_none());

    let _ = fs::remove_dir_all(&tmp);
}
