//! Stage-3 load-time `ScopeIndex` tests: the index is a *pure superset filter*,
//! so it must (a) classify each rule's scope into the right bucket and (b) never
//! change an access decision or a header outcome vs the old full linear scan.
//!
//! Behavioral coverage of the unchanged decisions also lives in the crate's
//! `directives.rs` / `tests.rs` / `access_repro.rs` suites (all of which now run
//! *through* the index); these tests pin the index structure + the tricky
//! later-wins / mixed-bucket / suffix-case / mtime-rebuild edges explicitly.

use hj_rewrite::{AccessDecision, Htaccess};

// ---------------------------------------------------------------------------
// Classification: each scope lands in exactly the right bucket.
// ---------------------------------------------------------------------------

#[test]
fn exact_literal_files_glob_is_exact_bucket() {
    let h = Htaccess::parse("<Files \"robots.txt\">\n Require all granted\n</Files>").unwrap();
    assert_eq!(h.access_index.exact.get("robots.txt"), Some(&vec![0]));
    assert!(h.access_index.suffix.is_empty());
    assert!(h.access_index.residual.is_empty());
    assert!(h.access_index.dir_wide.is_empty());
}

#[test]
fn single_and_multi_extension_filesmatch_are_suffix_bucket() {
    let h = Htaccess::parse(
        "<FilesMatch \"\\.log$\">\n Require all denied\n</FilesMatch>\n\
         <FilesMatch \"\\.(less|template)$\">\n Require all denied\n</FilesMatch>",
    )
    .unwrap();
    assert_eq!(h.access_index.suffix.get("log"), Some(&vec![0]));
    assert_eq!(h.access_index.suffix.get("less"), Some(&vec![1]));
    assert_eq!(h.access_index.suffix.get("template"), Some(&vec![1]));
    assert!(h.access_index.exact.is_empty());
    assert!(h.access_index.residual.is_empty());
}

#[test]
fn complex_regex_is_residual_and_still_denies() {
    // `.*` prefix arms => residual (must always be a candidate). The real
    // Forum-style dotfile/secret guard shape.
    let h = Htaccess::parse(
        "<FilesMatch \"^(\\.env|config\\.php|.*\\.md)$\">\n Require all denied\n</FilesMatch>",
    )
    .unwrap();
    assert_eq!(h.access_index.residual, vec![0]);
    assert!(h.access_index.exact.is_empty());
    assert!(h.access_index.suffix.is_empty());
    // Behavior unchanged: all three still denied; an unrelated file is not.
    assert_eq!(h.access_decision("/.env", "GET"), AccessDecision::Denied);
    assert_eq!(
        h.access_decision("/config.php", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/README.md", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/index.php", "GET"),
        AccessDecision::NoOpinion
    );
}

#[test]
fn addon_json_without_anchor_is_residual_not_suffix() {
    // `addon\.json$` (no leading ^) ends in .json but requires the literal stem
    // "addon" — it is NOT a pure extension suffix, so it must be residual, and
    // must keep matching anything ending in "addon.json" (not just *.json).
    let h = Htaccess::parse("<FilesMatch \"addon\\.json$\">\n Require all denied\n</FilesMatch>")
        .unwrap();
    assert_eq!(h.access_index.residual, vec![0]);
    assert_eq!(h.access_index.suffix.get("json"), None);
    assert_eq!(
        h.access_decision("/addon.json", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/myaddon.json", "GET"),
        AccessDecision::Denied
    );
    // A different .json file is untouched (the residual regex requires "addon").
    assert_eq!(
        h.access_decision("/other.json", "GET"),
        AccessDecision::NoOpinion
    );
    assert_eq!(
        h.access_decision("/addon.yaml", "GET"),
        AccessDecision::NoOpinion
    );
}

#[test]
fn directorymatch_is_dir_wide_and_denies_files_inside() {
    let h = Htaccess::parse(
        "<DirectoryMatch \"^.*/internal_data$\">\n Require all denied\n</DirectoryMatch>",
    )
    .unwrap();
    assert_eq!(h.access_index.dir_wide, vec![0]);
    // Ancestor walk: a file inside the denied directory is denied.
    assert_eq!(
        h.access_decision("/internal_data", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/internal_data/config.php", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/internal_data/deep/x", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        h.access_decision("/styles/app.css", "GET"),
        AccessDecision::NoOpinion
    );
}

// ---------------------------------------------------------------------------
// Superset filter must preserve "later wins" across buckets.
// ---------------------------------------------------------------------------

#[test]
fn later_grant_overrides_earlier_suffix_deny() {
    // suffix deny (idx 0) then an exact grant (idx 1) for the same file — the
    // grant must win because candidates arrive in ascending source order.
    let h = Htaccess::parse(
        "<FilesMatch \"\\.txt$\">\n Require all denied\n</FilesMatch>\n\
         <Files \"robots.txt\">\n Require all granted\n</Files>",
    )
    .unwrap();
    assert_eq!(
        h.access_decision("/robots.txt", "GET"),
        AccessDecision::Granted
    );
    assert_eq!(
        h.access_decision("/secret.txt", "GET"),
        AccessDecision::Denied
    );
}

#[test]
fn mixed_bucket_source_order_is_preserved() {
    // Three buckets at once: suffix(\.log$)=deny, dir-wide deny, exact grant.
    // /error.log must end Granted (exact idx 2 is the highest matching index).
    let h = Htaccess::parse(
        "<FilesMatch \"\\.log$\">\n Require all denied\n</FilesMatch>\n\
         Require all denied\n\
         <Files \"error.log\">\n Require all granted\n</Files>",
    )
    .unwrap();
    assert_eq!(h.access_index.suffix.get("log"), Some(&vec![0]));
    assert_eq!(h.access_index.dir_wide, vec![1]);
    assert_eq!(h.access_index.exact.get("error.log"), Some(&vec![2]));
    assert_eq!(
        h.access_decision("/error.log", "GET"),
        AccessDecision::Granted
    );
    // A different .log hits the suffix deny then the dir-wide deny (no later grant).
    assert_eq!(
        h.access_decision("/other.log", "GET"),
        AccessDecision::Denied
    );
    // A non-.log file is only caught by the dir-wide deny.
    assert_eq!(
        h.access_decision("/page.html", "GET"),
        AccessDecision::Denied
    );
}

// ---------------------------------------------------------------------------
// Headers: suffix-scoped + dir-wide both apply; case-insensitive ext lookup.
// ---------------------------------------------------------------------------

#[test]
fn css_gets_suffix_cache_control_and_global_header() {
    let h = Htaccess::parse(
        "Header set X-Content-Type-Options nosniff\n\
         <FilesMatch \"\\.(js|css|woff2)$\">\n  Header set Cache-Control \"public, max-age=31536000\"\n</FilesMatch>",
    )
    .unwrap();
    assert_eq!(h.header_index.dir_wide, vec![0]);
    assert_eq!(h.header_index.suffix.get("css"), Some(&vec![1]));
    let ops = h.response_headers("/assets/app.css", 200, &[]);
    assert!(ops.iter().any(|o| o.name() == "Cache-Control"));
    assert!(ops.iter().any(|o| o.name() == "X-Content-Type-Options"));
    // A .php asset: only the global header (suffix scope does not match).
    let php = h.response_headers("/index.php", 200, &[]);
    assert!(!php.iter().any(|o| o.name() == "Cache-Control"));
    assert!(php.iter().any(|o| o.name() == "X-Content-Type-Options"));
}

#[test]
fn uppercase_extension_is_a_candidate_but_case_sensitive_regex_still_decides() {
    // Lowercased ext lookup makes `.CSS` a candidate for the suffix bucket, but
    // the underlying regex is case-sensitive, so the (already-current) outcome is
    // that it does NOT apply — the index never changes that.
    let h = Htaccess::parse(
        "<FilesMatch \"\\.(js|css)$\">\n  Header set Cache-Control public\n</FilesMatch>",
    )
    .unwrap();
    assert!(
        h.response_headers("/a.css", 200, &[])
            .iter()
            .any(|o| o.name() == "Cache-Control")
    );
    assert!(h.response_headers("/a.CSS", 200, &[]).is_empty());
}

#[test]
fn nested_if_files_conjunction_is_residual_and_honors_both() {
    // A conjunction (`<If><FilesMatch>`) cannot be single-key indexed -> residual,
    // and must still require BOTH the URI and the basename.
    let h = Htaccess::parse(
        "<If \"%{REQUEST_URI} =~ m#^/api/#\">\n  \
         <FilesMatch \"\\.php$\">\n    Header set X-Api 1\n  </FilesMatch>\n</If>",
    )
    .unwrap();
    assert_eq!(h.header_index.residual, vec![0]);
    assert!(
        h.response_headers("/api/x.php", 200, &[])
            .iter()
            .any(|o| o.name() == "X-Api")
    );
    assert!(h.response_headers("/other/x.php", 200, &[]).is_empty());
    assert!(h.response_headers("/api/style.css", 200, &[]).is_empty());
}

// ---------------------------------------------------------------------------
// has_resp_op + mtime rebuild.
// ---------------------------------------------------------------------------

#[test]
fn has_resp_op_reflects_header_presence() {
    let none = Htaccess::parse("RewriteEngine On\nRewriteRule ^(.*)$ index.php [L]").unwrap();
    assert!(!none.has_resp_op);
    let some = Htaccess::parse("Header set X-Test 1").unwrap();
    assert!(some.has_resp_op);
}

#[test]
fn index_and_has_resp_op_rebuild_on_mtime_change() {
    use hj_rewrite::HtaccessCache;
    use std::time::Duration;

    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hj_scopeidx_{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(".htaccess");

    // ZERO revalidate TTL -> every load re-stats and reparses on mtime change.
    let cache = HtaccessCache::with_revalidate_ttl(Duration::ZERO);

    // v1: no headers.
    std::fs::write(&file, b"RewriteEngine On\n").unwrap();
    let v1 = cache.get_or_load(&dir).unwrap();
    assert!(!v1.has_resp_op);
    assert!(v1.header_index.dir_wide.is_empty());

    // A distinct mtime (ns granularity on tmpfs/ext4; the rest of the cache relies
    // on the same assumption).
    std::thread::sleep(Duration::from_millis(50));

    // v2: add a directory-wide Header.
    std::fs::write(&file, b"RewriteEngine On\nHeader set X-Test 1\n").unwrap();
    let v2 = cache.get_or_load(&dir).unwrap();
    assert!(v2.has_resp_op, "reparse must refresh has_resp_op");
    assert_eq!(
        v2.header_index.dir_wide,
        vec![0],
        "reparse must rebuild the index"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
