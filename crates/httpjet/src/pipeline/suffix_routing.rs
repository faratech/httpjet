//! Suffix routing: resolve a request path to the PHP script that should run,
//! splitting off any trailing `PATH_INFO` (OLS / Apache `AcceptPathInfo`-style),
//! with a directory-index fallback. Static files fall through (`None`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hj_core::ReqCtx;
use hj_rewrite::Htaccess;

use crate::state::ServerState;

use super::effective_php_suffixes;
use super::rewrite_glue::clean_rel;

/// Resolve `path` to the PHP script that should run, splitting off any trailing
/// `PATH_INFO`. Returns `(script_abs, script_name, path_info)` where `script_name`
/// is the URL prefix that maps to the script and `path_info` is the remainder
/// (`""` when none).
///
/// Routing (OLS / Apache `AcceptPathInfo`-style):
/// 1. Walk the URL path-segment boundaries from shortest to longest prefix; for
///    each prefix join the cleaned relative path onto the docroot and consult the
///    TTL stat cache. The LONGEST prefix that is a regular file whose extension is
///    a configured PHP suffix is the script; everything after it is `PATH_INFO`.
///    This is what lets `/index.php/foo/bar` route to `/index.php` with
///    `PATH_INFO=/foo/bar`.
/// 2. If no prefix is a PHP file, fall back to directory-index resolution: a
///    `dir_like` request (trailing slash or docroot) resolves to the first index
///    file that exists and carries a PHP suffix.
///
/// A non-`.php`-suffixed file can additionally be forced through PHP by an
/// `.htaccess` handler-override directive (`SetHandler application/x-httpd-php`,
/// `AddHandler`/`AddType`); the `chain` is consulted via
/// [`hj_rewrite::php_handler_forced`]. This is **additive** — it only ever turns a
/// non-PHP file into a PHP route, never the reverse.
///
/// Returns `None` when LSAPI/PHP is disabled, scripting is off for the vhost, or
/// the request does not resolve to a PHP script (static files fall through).
pub(super) fn split_script_path(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    index_files: &[String],
    chain: &[Arc<Htaccess>],
) -> Option<(PathBuf, String, String)> {
    // NOTE: do NOT short-circuit on `state.lsapi.is_none()`. A path that resolves
    // to a script handler must be IDENTIFIED as such even when the lsphp pool is
    // unavailable, so the suffix-routing block can return 503 instead of letting
    // the file fall through to the static handler and leak its SOURCE CODE.
    let enable_script = state
        .server
        .vhosts
        .get(&ctx.vhost_name)
        .map(|d| d.enable_script)
        .unwrap_or(true);
    if !enable_script {
        return None;
    }

    // (#9a) Effective PHP suffix set: the global `phpConfig` suffixes plus this
    // vhost's `<scriptHandlerList>` LSAPI suffixes (per-vhost wins by being a
    // superset; suffixes mapped to a non-LSAPI handler are ignored here).
    let php_suffixes = effective_php_suffixes(state, ctx);
    // Hot-path gate: only chains that actually carry a `SetHandler`/`AddHandler`/
    // `AddType` directive pay the per-prefix scope-match cost. Bool-field scan over
    // the (short) chain — no alloc/regex/syscall — so the common no-override case is
    // byte-identical to before (the `force_php` closure is never invoked).
    let force_active = chain.iter().any(|h| h.has_handler_override);
    if php_suffixes.is_empty() && !force_active {
        return None;
    }
    let force_php = |url: &str| {
        let base = url.rsplit('/').next().unwrap_or("");
        hj_rewrite::php_handler_forced(chain, url, base)
    };

    resolve_script(
        &ctx.vhost.doc_root,
        path,
        &php_suffixes,
        index_files,
        &|p| {
            state
                .stat_cache
                .tests(p)
                .map(|t| t.is_file)
                .unwrap_or(false)
        },
        force_active,
        &force_php,
    )
}

/// Pure core of [`split_script_path`]: independent of `ServerState`/`ReqCtx` so it
/// can be unit-tested. `is_file` reports whether an absolute path is a regular
/// file (production wires it to the TTL stat cache).
fn resolve_script(
    doc_root: &Path,
    path: &str,
    php_suffixes: &std::collections::HashSet<String>,
    index_files: &[String],
    is_file: &dyn Fn(&Path) -> bool,
    force_active: bool,
    force_php: &dyn Fn(&str) -> bool,
) -> Option<(PathBuf, String, String)> {
    let ext_is_php = |ext: &str| -> bool {
        // Suffixes are stored lowercase and real extensions almost always are — try the
        // extension as-is first; only allocate a lowercased copy if it actually has uppercase.
        php_suffixes.contains(ext)
            || (ext.bytes().any(|b| b.is_ascii_uppercase())
                && php_suffixes.contains(&ext.to_ascii_lowercase()))
    };
    let is_php = |abs: &Path| -> bool {
        abs.extension()
            .and_then(|e| e.to_str())
            .is_some_and(ext_is_php)
    };
    // Whether a URL prefix's FINAL segment could be a PHP script, checked WITHOUT allocating a
    // PathBuf or stat'ing — lets the longest-prefix scan skip the overwhelmingly common non-PHP
    // file. `None` = ambiguous final segment (empty/`.`/`..`, which clean_rel would collapse,
    // possibly exposing a different final segment): the caller must fall back to the precise
    // clean_rel-based check.
    let prefix_maybe_php = |prefix: &str| -> Option<bool> {
        let seg = prefix.rsplit('/').next().unwrap_or("");
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        Some(matches!(seg.rsplit_once('.'), Some((_, ext)) if !ext.is_empty() && ext_is_php(ext)))
    };

    // --- 1. Longest-PHP-prefix scan. ----------------------------------------
    // Cumulative segment boundaries: for "/a/b.php/c" the candidate prefixes are
    // "/a", "/a/b.php", "/a/b.php/c". The longest one that stats as a PHP file
    // wins; the URL tail after it becomes PATH_INFO.
    let mut best: Option<(PathBuf, usize)> = None; // (script_abs, byte offset of prefix end)
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Advance to the next '/'-delimited boundary (end of the next segment).
        // Skip a leading '/' so the first boundary is after segment 1.
        let start = if bytes[i] == b'/' { i + 1 } else { i };
        let rel_end = match path[start..].find('/') {
            Some(off) => start + off,
            None => path.len(),
        };
        i = rel_end;
        let prefix = &path[..rel_end];
        // An `.htaccess` `SetHandler`/`AddHandler`/`AddType` can force this prefix to
        // PHP even though its extension is not a configured suffix. Evaluated on the
        // prefix STRING (scope/extension match, no filesystem) and short-circuited by
        // `force_active`, so it costs nothing when no override directive is in scope.
        let could_force = force_active && force_php(prefix);
        // Skip the PathBuf build + stat for a prefix whose final segment definitively is not a
        // PHP script (the common static-asset case). Only a PHP-extension, an ambiguous
        // (`None`) prefix, or a force-handler prefix pays for clean_rel + join + is_file.
        if prefix_maybe_php(prefix) != Some(false) || could_force {
            if let Some(rel) = clean_rel(prefix) {
                if !rel.as_os_str().is_empty() {
                    let abs = doc_root.join(&rel);
                    if (is_php(&abs) || could_force) && is_file(&abs) {
                        best = Some((abs, rel_end));
                    }
                }
            }
        }
        if rel_end >= path.len() {
            break;
        }
    }
    if let Some((abs, end)) = best {
        let script_name = path[..end].to_string();
        let path_info = path[end..].to_string();
        return Some((abs, script_name, path_info));
    }

    // --- 2. Directory-index fallback. ---------------------------------------
    // Decide "directory-like" from the URL string first — ends in '/', or normalizes to empty
    // (only empty/`.` segments, equivalent to the old `rel.as_os_str().is_empty()`) — so a plain
    // file request returns without building a PathBuf or stat'ing an index file.
    let dir_like = path.ends_with('/') || path.split('/').all(|s| s.is_empty() || s == ".");
    if !dir_like {
        return None;
    }
    let rel = clean_rel(path)?;
    let abs = doc_root.join(&rel);
    for idx in index_files {
        // (#244) DirectoryIndex tokens come from .htaccess verbatim, NOT from the
        // lexically-cleaned request path; `abs.join` would happily escape the
        // docroot for "../x" (or replace it outright for an absolute "/x"). Same
        // guard hj-static applies to its own dir-index arm — fail closed by
        // skipping the candidate.
        if !hj_static::safe_index_name(idx) {
            continue;
        }
        let cand = abs.join(idx);
        if is_file(&cand) {
            // The index file may be PHP by extension OR forced via a handler-override
            // scoped to its basename (e.g. `<Files "index.html"> SetHandler …`). The
            // force URL is the per-candidate path (`path` ends in '/'), so `<Files>`
            // matches the index basename rather than the directory.
            if is_php(&cand) || (force_active && force_php(&format!("{path}{idx}"))) {
                // Dir index: SCRIPT_NAME stays the request path (matching prior
                // behavior), no PATH_INFO; SCRIPT_FILENAME points at the index.
                return Some((cand, path.to_string(), String::new()));
            }
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::rewrite_glue::{normalized_request_path, resolved_rel_path};
    use super::*;
    use std::collections::HashSet;

    /// Build a unique temp docroot with a real `index.php`, returning the dir and a
    /// teardown guard that removes it on drop.
    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir =
                std::env::temp_dir().join(format!("httpjet_split_{}_{:p}", n, &n as *const _));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("index.php"), b"<?php\n").unwrap();
            TempRoot(dir)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn php_suffixes() -> HashSet<String> {
        ["php".to_string()].into_iter().collect()
    }

    /// No handler-override force (the common case): keeps `resolve_script`
    /// byte-identical to its extension-only behavior.
    fn no_force(_: &str) -> bool {
        false
    }

    #[test]
    fn path_info_routes_to_longest_php_prefix() {
        let root = TempRoot::new();
        let sfx = php_suffixes();
        let index = vec!["index.php".to_string()];
        let is_file = |p: &Path| p.is_file();

        let (script, name, path_info) = resolve_script(
            &root.0,
            "/index.php/foo/bar",
            &sfx,
            &index,
            &is_file,
            false,
            &no_force,
        )
        .expect("should route to index.php with PATH_INFO");
        assert_eq!(script, root.0.join("index.php"));
        assert_eq!(name, "/index.php");
        assert_eq!(path_info, "/foo/bar");
    }

    #[test]
    fn plain_script_has_no_path_info() {
        let root = TempRoot::new();
        std::fs::write(root.0.join("a.php"), b"<?php\n").unwrap();
        let sfx = php_suffixes();
        let index = vec!["index.php".to_string()];
        let is_file = |p: &Path| p.is_file();

        let (script, name, path_info) =
            resolve_script(&root.0, "/a.php", &sfx, &index, &is_file, false, &no_force)
                .expect("should route to a.php");
        assert_eq!(script, root.0.join("a.php"));
        assert_eq!(name, "/a.php");
        assert_eq!(path_info, "");
    }

    #[test]
    fn missing_script_with_path_info_is_none() {
        let root = TempRoot::new();
        let sfx = php_suffixes();
        let index = vec!["index.php".to_string()];
        let is_file = |p: &Path| p.is_file();

        // missing.php does not exist on disk -> no PHP prefix matches, and the
        // request is not dir-like -> None (falls through to static).
        assert!(
            resolve_script(
                &root.0,
                "/missing.php/x",
                &sfx,
                &index,
                &is_file,
                false,
                &no_force
            )
            .is_none()
        );
    }

    #[test]
    fn dir_index_traversal_tokens_fail_closed() {
        // (#244 residual) `.htaccess` DirectoryIndex tokens reach the dir-index join
        // verbatim. A "../" escape or absolute token used to be joined straight onto
        // the docroot-relative dir (PathBuf::join even REPLACES the base for an
        // absolute token), so an attacker-writable .htaccess could route PHP execution
        // at files outside the served tree. Bad tokens must be skipped, and the first
        // SAFE candidate must still win.
        let root = TempRoot::new();
        let sub = root.0.join("community");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("index.php"), b"<?php // safe\n").unwrap();
        // The escape target exists and IS php-extensioned, so the unguarded join would
        // have selected it.
        std::fs::write(root.0.join("escaped.php"), b"<?php // outside\n").unwrap();
        let sfx = php_suffixes();
        let index = vec![
            "../escaped.php".to_string(),
            "/etc/passwd".to_string(),
            "..\\..\\escaped.php".to_string(),
            "index.php".to_string(),
        ];
        let is_file = |p: &Path| p.is_file();

        let (script, _name, _path_info) = resolve_script(
            &root.0,
            "/community/",
            &sfx,
            &index,
            &is_file,
            false,
            &no_force,
        )
        .expect("the safe trailing candidate must still route");
        assert_eq!(
            script,
            sub.join("index.php"),
            "traversal/absolute DirectoryIndex tokens must be skipped, never joined"
        );
    }

    #[test]
    fn dir_index_with_trailing_slash_routes_to_index_php() {
        // (M1 regression) A request to a real subdirectory whose only index is
        // `index.php` must route to that index via the dir-index fallback. This
        // ONLY fires when the canonical path retains its trailing slash
        // (`resolve_script` gates dir-like on `path.ends_with('/')`). If the
        // pipeline collapses `/community/` -> `/community` before this call, the
        // request loses PHP routing and the static handler serves the index PHP
        // source instead — a source-code disclosure. We feed the path through the
        // same `normalized_request_path` the pipeline uses to prove the slash —
        // and therefore the PHP routing — survives canonicalization.
        let root = TempRoot::new();
        let sub = root.0.join("community");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("index.php"), b"<?php // secret\n").unwrap();
        let sfx = php_suffixes();
        let index = vec!["index.php".to_string()];
        let is_file = |p: &Path| p.is_file();

        // The pipeline normalizes the decoded request path before routing.
        let canon = normalized_request_path("/community/");
        assert_eq!(
            canon, "/community/",
            "trailing slash must survive normalization"
        );

        let (script, name, path_info) =
            resolve_script(&root.0, &canon, &sfx, &index, &is_file, false, &no_force)
                .expect("dir-index must route /community/ to community/index.php");
        assert_eq!(script, sub.join("index.php"));
        assert_eq!(name, "/community/");
        assert_eq!(path_info, "");

        // And the collapsing variant (slash stripped) would have lost the route,
        // demonstrating exactly why `normalized_request_path` is required here.
        let stripped = resolved_rel_path("/community/");
        assert_eq!(stripped, "/community");
        assert!(
            resolve_script(&root.0, &stripped, &sfx, &index, &is_file, false, &no_force).is_none(),
            "slash-stripped path must NOT route to PHP (this was the M1 bug)"
        );
    }

    #[test]
    fn set_handler_forces_non_php_file_to_script() {
        // `<Files "crontab.html"> SetHandler application/x-httpd-php` — the html file
        // exists on disk but `.html` is NOT a PHP suffix here. With the force
        // predicate matching only crontab.html it must route to a script (so the
        // pipeline hands it to lsphp instead of serving the source).
        let root = TempRoot::new();
        std::fs::write(root.0.join("crontab.html"), b"<?php echo 1;\n").unwrap();
        std::fs::write(root.0.join("other.html"), b"<h1>static</h1>\n").unwrap();
        let sfx = php_suffixes(); // {"php"} — html intentionally absent
        let index = vec!["index.php".to_string()];
        let is_file = |p: &Path| p.is_file();
        let force = |url: &str| url.rsplit('/').next() == Some("crontab.html");

        let (script, name, path_info) = resolve_script(
            &root.0,
            "/crontab.html",
            &sfx,
            &index,
            &is_file,
            true,
            &force,
        )
        .expect("forced .html must resolve to a script");
        assert_eq!(script, root.0.join("crontab.html"));
        assert_eq!(name, "/crontab.html");
        assert_eq!(path_info, "");

        // A sibling .html NOT in the force scope still falls through to static.
        assert!(
            resolve_script(&root.0, "/other.html", &sfx, &index, &is_file, true, &force).is_none(),
            "unscoped sibling .html must NOT be forced to PHP"
        );
    }

    #[test]
    fn forced_file_keeps_path_info_split() {
        // AddHandler-style force on `.html`: `/page.html/extra` -> script /page.html,
        // PATH_INFO /extra (same longest-prefix scan as a real PHP suffix).
        let root = TempRoot::new();
        std::fs::write(root.0.join("page.html"), b"<?php\n").unwrap();
        let sfx = php_suffixes();
        let index = vec!["index.php".to_string()];
        let is_file = |p: &Path| p.is_file();
        let force = |url: &str| url.ends_with(".html");

        let (script, name, path_info) = resolve_script(
            &root.0,
            "/page.html/extra",
            &sfx,
            &index,
            &is_file,
            true,
            &force,
        )
        .expect("forced .html with PATH_INFO must resolve");
        assert_eq!(script, root.0.join("page.html"));
        assert_eq!(name, "/page.html");
        assert_eq!(path_info, "/extra");
    }

    #[test]
    fn forced_dir_index_html_routes_to_script() {
        // `<Files "index.html"> SetHandler …` on a trailing-slash dir request: the
        // index.html must route to a script, not serve static. The force URL is the
        // per-candidate path so the basename scope matches.
        let root = TempRoot::new();
        let sub = root.0.join("tools");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("index.html"), b"<?php\n").unwrap();
        let sfx = php_suffixes();
        let index = vec!["index.html".to_string(), "index.php".to_string()];
        let is_file = |p: &Path| p.is_file();
        let force = |url: &str| url.rsplit('/').next() == Some("index.html");

        let (script, name, path_info) =
            resolve_script(&root.0, "/tools/", &sfx, &index, &is_file, true, &force)
                .expect("forced index.html must resolve to a script");
        assert_eq!(script, sub.join("index.html"));
        assert_eq!(name, "/tools/");
        assert_eq!(path_info, "");
    }
}
