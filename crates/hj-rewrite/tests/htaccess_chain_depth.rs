//! Regression (audit 2026-08-30): the per-directory chain walk stats one
//! directory per `/` segment of the request path, and `maxReqURLLen` (8192)
//! admits ~4096 segments — a single cold deep URL, or a flood of unique ones,
//! bought thousands of syscalls per request. An over-deep path must resolve to
//! the deny-all sentinel (fail CLOSED: truncating the walk would skip a deeper
//! ancestor's deny and serve), while depths under the cap keep loading the real
//! chain.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use hj_rewrite::HtaccessCache;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hj-chain-depth-{}-{}-{}",
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

fn deep_path(segments: usize) -> String {
    let mut p = String::new();
    for _ in 0..segments {
        p.push_str("/a");
    }
    p.push_str("/x.txt");
    p
}

#[test]
fn over_deep_path_fails_closed_to_deny_all() {
    let docroot = temp_dir("over");
    let cache = HtaccessCache::with_revalidate_ttl(Duration::from_secs(0));

    let chain = cache.load_chain(&docroot, &deep_path(4096));
    assert_eq!(chain.len(), 1, "sentinel-only chain, not a walked chain");
    assert!(
        chain[0].is_forbidden("/a/x.txt", "x.txt"),
        "an over-deep path must be denied, not served with a truncated chain"
    );

    let _ = fs::remove_dir_all(docroot);
}

#[test]
fn depth_cap_boundary_still_walks_normally() {
    let docroot = temp_dir("under");
    let sub = docroot.join("a").join("protected");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join(".htaccess"), b"Require all denied\n").unwrap();
    let cache = HtaccessCache::with_revalidate_ttl(Duration::from_secs(0));

    let path = deep_path(63).replace("/x.txt", "/protected/x.txt");
    let chain = cache.load_chain(&docroot, &path);
    assert!(
        chain
            .iter()
            .any(|h| h.is_forbidden("/a/protected/x.txt", "x.txt")),
        "a path under the cap must still consult every ancestor's access file"
    );

    let _ = fs::remove_dir_all(docroot);
}
