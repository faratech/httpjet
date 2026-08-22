//! Regression: an unparseable access file must fail CLOSED, not degrade to
//! "no rules". `Htaccess::parse` is all-or-nothing, so a single bad regex in a
//! protected directory's `.htaccess` used to memoize as absent — silently
//! stripping that directory's `Deny from all` until the mtime changed (Apache
//! fails the request instead). The cache now substitutes a deny-all sentinel,
//! memoized like a real parse, which self-heals once the fixed file lands.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use hj_rewrite::{Htaccess, HtaccessCache};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hj-failclosed-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn unparseable_access_file_fails_closed_and_self_heals() {
    let dir = temp_dir("sentinel");
    let file = dir.join(".htaccess");
    // One unbalanced regex poisons the WHOLE file (RuleSet::parse is fatal).
    fs::write(&file, "RewriteCond %{QUERY_STRING} (unbalanced\n").unwrap();

    let cache = HtaccessCache::with_revalidate_ttl(Duration::from_secs(0));
    let sentinel = cache
        .get_or_load_named(&dir, ".htaccess")
        .expect("broken file yields the fail-closed sentinel");
    assert!(
        sentinel.is_forbidden("/internal_data/config.php", "config.php"),
        "a broken access file must deny its directory instead of serving it"
    );

    // Fixing the file (new mtime) restores the real rules immediately.
    std::thread::sleep(Duration::from_millis(10));
    fs::write(&file, "Require all granted\n").unwrap();
    let healed = cache
        .get_or_load_named(&dir, ".htaccess")
        .expect("fixed file parses");
    assert!(
        !healed.is_forbidden("/internal_data/config.php", "config.php"),
        "the fixed access file must take effect, not stay denied"
    );

    let _ = fs::remove_dir_all(dir);
}

/// The sentinel is indistinguishable from a hand-written `Require all denied`.
#[test]
fn deny_all_sentinel_matches_hand_written_semantics() {
    let manual = Htaccess::parse("Require all denied\n").unwrap();
    assert!(manual.is_forbidden("/p/x.txt", "x.txt"));
    assert!(
        Htaccess::parse("Require all granted\n")
            .unwrap()
            .is_forbidden("/p/x.txt", "x.txt")
            == false
    );
}
