//! (#1209) Requests that miss the `.htaccess` cache together must share one parse.
//! After a restart or an edit every serving thread used to read and parse the same
//! file itself; for a long rule chain that stalled all of them for the whole parse.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::time::{Duration, SystemTime};

use hj_rewrite::HtaccessCache;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hj-singleflight-{}-{}-{}",
        tag,
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

const THREADS: usize = 16;

/// Load `dir`'s access file from `THREADS` threads released together.
fn load_together(cache: &Arc<HtaccessCache>, dir: &Path) -> Vec<Arc<hj_rewrite::Htaccess>> {
    let barrier = Arc::new(Barrier::new(THREADS));
    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let (cache, dir, barrier) = (cache.clone(), dir.to_path_buf(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                cache
                    .get_or_load_named(&dir, ".htaccess")
                    .expect("the access file exists")
            })
        })
        .collect();
    workers.into_iter().map(|w| w.join().unwrap()).collect()
}

#[test]
fn concurrent_misses_share_one_parse_and_an_edit_adds_exactly_one() {
    let dir = temp_dir("parse");
    let file = dir.join(".htaccess");
    fs::write(&file, "RewriteEngine On\nRewriteRule ^a$ /b [L]\n").unwrap();
    // TTL 0: every load re-stats, so the test controls when the file counts as changed.
    let cache = Arc::new(HtaccessCache::with_revalidate_ttl(Duration::ZERO));

    let first = load_together(&cache, &dir);
    assert_eq!(
        cache.parse_count(),
        1,
        "one parse for {THREADS} concurrent misses"
    );
    assert!(first.iter().all(|parsed| Arc::ptr_eq(parsed, &first[0])));

    // Unchanged file: revalidation only.
    let again = load_together(&cache, &dir);
    assert_eq!(cache.parse_count(), 1);
    assert!(again.iter().all(|parsed| Arc::ptr_eq(parsed, &first[0])));

    // An edit (new mtime) is parsed once, and every thread sees the new rules.
    fs::write(&file, "RewriteEngine On\nRewriteRule ^a$ /c [L]\n").unwrap();
    let later = SystemTime::now() + Duration::from_secs(5);
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(later)
        .unwrap();
    let edited = load_together(&cache, &dir);
    assert_eq!(cache.parse_count(), 2, "one more parse for the edit");
    assert!(edited.iter().all(|parsed| Arc::ptr_eq(parsed, &edited[0])));
    assert!(!Arc::ptr_eq(&edited[0], &first[0]));

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn concurrent_misses_on_an_unparseable_file_all_fail_closed() {
    let dir = temp_dir("broken");
    fs::write(
        dir.join(".htaccess"),
        "RewriteCond %{QUERY_STRING} (unbalanced\n",
    )
    .unwrap();
    let cache = Arc::new(HtaccessCache::with_revalidate_ttl(Duration::ZERO));

    let loaded = load_together(&cache, &dir);
    assert_eq!(cache.parse_count(), 1);
    assert!(
        loaded
            .iter()
            .all(|sentinel| sentinel.is_forbidden("/internal/config.php", "config.php")),
        "every waiter gets the deny-all sentinel, none an empty rule set"
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// The cache parses with the prefilter deferred and a background thread attaches it:
/// a cached file must not stay unfiltered for good.
#[test]
fn a_cached_file_gets_its_prefilter_in_the_background() {
    let dir = temp_dir("builder");
    fs::write(
        dir.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^old/(.*)$ /new/$1 [R=301,L]\n",
    )
    .unwrap();
    let cache = HtaccessCache::new();
    let parsed = cache.get_or_load_named(&dir, ".htaccess").unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while parsed.prefilter_pending() {
        assert!(
            std::time::Instant::now() < deadline,
            "the prefilter was never built"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_reload_starts_from_the_previous_parses_and_still_sees_edits() {
    let dir = temp_dir("seed");
    let file = dir.join(".htaccess");
    fs::write(&file, "RewriteEngine On\nRewriteRule ^a$ /b [L]\n").unwrap();
    let missing = dir.join("no-such-directory");

    let old = HtaccessCache::new();
    let parsed = old.get_or_load_named(&dir, ".htaccess").unwrap();
    assert!(old.get_or_load_named(&missing, ".htaccess").is_none());
    assert_eq!(old.parse_count(), 1);

    let next = HtaccessCache::seeded_from(&old);
    assert_eq!(next.len(), 1, "absent files are not carried over");
    let reused = next.get_or_load_named(&dir, ".htaccess").unwrap();
    assert!(Arc::ptr_eq(&reused, &parsed));
    assert_eq!(
        next.parse_count(),
        0,
        "an unchanged file is not parsed again"
    );

    // The file changed since the old generation parsed it: the seed is not trusted.
    fs::write(&file, "RewriteEngine On\nRewriteRule ^a$ /c [L]\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(5))
        .unwrap();
    let after_edit = HtaccessCache::seeded_from(&old);
    let fresh = after_edit.get_or_load_named(&dir, ".htaccess").unwrap();
    assert!(!Arc::ptr_eq(&fresh, &parsed));
    assert_eq!(after_edit.parse_count(), 1);

    fs::remove_dir_all(&dir).unwrap();
}
