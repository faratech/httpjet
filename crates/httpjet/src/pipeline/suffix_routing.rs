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
/// Returns `None` when the request does not resolve to a declared script or when
/// execution is disabled. Disabled vhosts use the lexical/cache gate plus the
/// static resolver's actual-target backstop instead of duplicating filesystem
/// probes here. Runtime backend availability remains irrelevant to classification.
pub(super) fn split_script_path(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    index_files: &[String],
    chain: &[Arc<Htaccess>],
) -> Option<(PathBuf, String, String)> {
    split_declared_script_path(state, ctx, path, index_files, chain)
}

/// Whether this vhost permits script execution. Kept separate from declaration
/// classification so security-sensitive callers can recognize script source even
/// while execution is disabled or its runtime backend is unavailable.
pub(super) fn vhost_scripts_enabled(state: &ServerState, ctx: &ReqCtx) -> bool {
    state
        .server
        .vhosts
        .get(&ctx.vhost_name)
        .map(|d| d.enable_script)
        .unwrap_or(true)
}

fn extension_is_executable(
    php_suffixes: &std::collections::HashSet<String>,
    extension: &str,
) -> bool {
    php_suffixes.contains(extension)
        || (extension.bytes().any(|byte| byte.is_ascii_uppercase())
            && php_suffixes.contains(&extension.to_ascii_lowercase()))
}

pub(super) fn directory_like(path: &str) -> bool {
    path.ends_with('/')
        || path
            .split('/')
            .all(|segment| segment.is_empty() || segment == ".")
}

/// Cheap lexical gate before candidate construction or stat-cache probes. A
/// PATH_INFO request retains the executable extension in an earlier segment.
fn has_executable_segment(path: &str, php_suffixes: &std::collections::HashSet<String>) -> bool {
    path.split('/').any(|segment| {
        matches!(
            segment.rsplit_once('.'),
            Some((_, extension))
                if !extension.is_empty() && extension_is_executable(php_suffixes, extension)
        )
    })
}

/// Last-wins executable-suffix lookup that borrows configuration directly. This
/// is used only while script execution is disabled, where constructing the full
/// effective suffix set would be wasted: every possible script route fails
/// closed before a backend or filesystem target is consulted.
fn configured_extension_is_executable(state: &ServerState, ctx: &ReqCtx, extension: &str) -> bool {
    if let Some(handler) = ctx
        .vhost
        .script_handlers
        .iter()
        .rev()
        .find(|handler| handler.suffix.eq_ignore_ascii_case(extension))
    {
        return handler.kind != hj_core::config::ContextKind::Static;
    }
    state.php_suffixes.contains(extension)
        || (extension.bytes().any(|byte| byte.is_ascii_uppercase())
            && state
                .php_suffixes
                .iter()
                .any(|suffix| suffix.eq_ignore_ascii_case(extension)))
}

/// Whether configuration could map this URL to a script, without building a
/// suffix set, candidate PathBuf, or probing the filesystem. Disabled vhosts use
/// this to bypass page-cache/static fast paths. A directory is only *potential*:
/// the static resolver chooses the first existing index, and the actual-target
/// backstop below decides whether that selected file is executable.
pub(super) fn path_may_resolve_to_script(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    index_files: &[String],
    chain: &[Arc<Htaccess>],
) -> bool {
    let force_active = chain.iter().any(|ht| ht.has_handler_override);
    let force_php = |url: &str| {
        let basename = url.rsplit('/').next().unwrap_or("");
        hj_rewrite::php_handler_forced(chain, url, basename)
    };
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let start = if bytes[i] == b'/' { i + 1 } else { i };
        let rel_end = match path[start..].find('/') {
            Some(offset) => start + offset,
            None => path.len(),
        };
        i = rel_end;
        let prefix = &path[..rel_end];
        let basename = prefix.rsplit('/').next().unwrap_or("");
        let declared = basename.rsplit_once('.').is_some_and(|(_, extension)| {
            !extension.is_empty() && configured_extension_is_executable(state, ctx, extension)
        }) || (force_active && force_php(prefix));
        if declared {
            return true;
        }
        if rel_end >= path.len() {
            break;
        }
    }
    if !directory_like(path) {
        return false;
    }
    index_files.iter().any(|index| {
        if !hj_static::safe_index_name(index) {
            return false;
        }
        Path::new(index)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| configured_extension_is_executable(state, ctx, extension))
            || (force_active && force_php(&format!("{path}{index}")))
    })
}

/// Whether the request path ends in one or more known precompressed wrappers
/// around a configuration-declared script (for example `index.php.br`). This is
/// lexical by design: cache lookups run before static resolution, so a possible
/// wrapped script must bypass a persisted hit and reach the exact-target guard.
pub(super) fn path_may_resolve_to_precompressed_script(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    index_files: &[String],
    chain: &[Arc<Htaccess>],
) -> bool {
    let force_active = chain.iter().any(|ht| ht.has_handler_override);
    let candidate = |representation_basename: &str, prefix: &str| {
        let Some(basename) = logical_precompressed_basename(representation_basename) else {
            return false;
        };
        if Path::new(basename)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| configured_extension_is_executable(state, ctx, extension))
        {
            return true;
        }
        force_active
            && hj_rewrite::php_handler_forced(chain, &format!("{prefix}{basename}"), basename)
    };

    let representation_basename = path.rsplit('/').next().unwrap_or("");
    let prefix = path.strip_suffix(representation_basename).unwrap_or(path);
    if candidate(representation_basename, prefix) {
        return true;
    }

    if !directory_like(path) {
        return false;
    }
    index_files
        .iter()
        .any(|index| hj_static::safe_index_name(index) && candidate(index, path))
}

/// Strip one or more storage-representation suffixes, returning `None` when
/// the basename is not wrapped. Repeated wrappers remain fail-closed.
fn logical_precompressed_basename(mut basename: &str) -> Option<&str> {
    let original_len = basename.len();
    loop {
        let bytes = basename.as_bytes();
        if bytes.len() < 3
            || (!bytes[bytes.len() - 3..].eq_ignore_ascii_case(b".br")
                && !bytes[bytes.len() - 3..].eq_ignore_ascii_case(b".gz"))
        {
            break;
        }
        basename = &basename[..basename.len() - 3];
    }
    (basename.len() != original_len).then_some(basename)
}

/// Linux renders an unlinked-but-open proc-fd target as
/// `<original path> (deleted)`. Static responses serve the pinned descriptor, so
/// strip every such marker before suffix classification; otherwise an unlink
/// race can turn `secret.php` into the apparently safe extension
/// `php (deleted)` while the script bytes remain readable.
fn proc_fd_basename(mut basename: &str) -> &str {
    while let Some(stripped) = basename.strip_suffix(" (deleted)") {
        basename = stripped;
    }
    basename
}

/// Precisely resolve an existing script prefix for a disabled vhost without
/// constructing the full effective-suffix set.
///
/// The cheap lexical gate calls this only for script-shaped paths after proxy
/// precedence. Filesystem type still decides routing: `/assets.php/logo.png`
/// may name an ordinary directory plus a static child, `/assets.php` keeps its
/// DirectorySlash redirect, and a missing `/app.php` remains a normal 404.
/// DirectoryIndex is deliberately left to the static resolver so it can choose
/// the first existing index and the pinned-target guard can classify that exact
/// file before any bytes are served.
pub(super) fn disabled_path_resolves_to_script(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    chain: &[Arc<Htaccess>],
) -> bool {
    let force_active = chain.iter().any(|ht| ht.has_handler_override);
    let bytes = path.as_bytes();
    let mut i = 0;
    let mut best = None;
    while i < bytes.len() {
        let start = if bytes[i] == b'/' { i + 1 } else { i };
        let rel_end = match path[start..].find('/') {
            Some(offset) => start + offset,
            None => path.len(),
        };
        i = rel_end;
        let prefix = &path[..rel_end];
        let basename = prefix.rsplit('/').next().unwrap_or("");
        let declared = basename.rsplit_once('.').is_some_and(|(_, extension)| {
            !extension.is_empty() && configured_extension_is_executable(state, ctx, extension)
        }) || (force_active
            && hj_rewrite::php_handler_forced(chain, prefix, basename));
        if declared
            && let Some(rel) = clean_rel(prefix)
            && !rel.as_os_str().is_empty()
        {
            let candidate = ctx.vhost.doc_root.join(rel);
            if state
                .stat_cache
                .tests(&candidate)
                .is_some_and(|tests| tests.is_file)
            {
                best = Some(candidate);
            }
        }
        if rel_end >= path.len() {
            break;
        }
    }
    let Some(script) = best else { return false };
    if ctx.vhost.allow_symbol_link {
        return true;
    }
    let Some(doc_root) = std::fs::canonicalize(&ctx.vhost.doc_root).ok() else {
        return false;
    };
    std::fs::canonicalize(script)
        .ok()
        .is_some_and(|script| script.starts_with(doc_root))
}

/// Classify the actual file selected by the static resolver. This is the
/// DirectoryIndex-safe disabled-vhost backstop and the direct precompressed
/// representation guard for enabled vhosts. It reuses the resolver's pinned
/// target and performs no filesystem work of its own.
pub(super) fn target_is_declared_script<'a>(
    state: &ServerState,
    ctx: &ReqCtx,
    request_path: &str,
    selected_target: &Path,
    resolved_target: &Path,
    chain: impl IntoIterator<Item = &'a Htaccess>,
) -> bool {
    let executable_basename = |target: &Path| -> bool {
        let Some(representation) = target.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        let representation = proc_fd_basename(representation);
        let logical = logical_precompressed_basename(representation).unwrap_or(representation);
        Path::new(logical)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| configured_extension_is_executable(state, ctx, extension))
    };

    // The lexical selected target preserves the declared filename across a
    // permitted symlink (`index.php -> payload.txt`). The canonical fd target
    // remains a second fail-closed check for the inverse shape
    // (`public.txt -> payload.php`). Known precompressed wrappers never change
    // whether either target is a declared script.
    if executable_basename(selected_target)
        || (resolved_target != selected_target && executable_basename(resolved_target))
    {
        return true;
    }

    // Handler overrides are URL/name scoped. Evaluate them against the lexical
    // file selected for this request, never the canonical symlink destination.
    let Some(representation_basename) = selected_target.file_name().and_then(|name| name.to_str())
    else {
        return false;
    };
    let logical_basename = logical_precompressed_basename(representation_basename);
    let wrapped = logical_basename.is_some();
    let basename = logical_basename.unwrap_or(representation_basename);
    let scoped_path = if request_path.ends_with('/') {
        std::borrow::Cow::Owned(format!("{request_path}{basename}"))
    } else if wrapped {
        std::borrow::Cow::Owned(
            request_path
                .strip_suffix(representation_basename)
                .map(|prefix| format!("{prefix}{basename}"))
                .unwrap_or_else(|| request_path.to_owned()),
        )
    } else {
        std::borrow::Cow::Borrowed(request_path)
    };
    hj_rewrite::php_handler_forced_iter(chain, &scoped_path, basename)
}

/// Resolve every path that configuration declares executable while execution is
/// enabled, independent of runtime backend availability. Disabled vhosts defer
/// DirectoryIndex choice to the static resolver and reject its logical target
/// before bytes can be served.
pub(super) fn split_declared_script_path(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    index_files: &[String],
    chain: &[Arc<Htaccess>],
) -> Option<(PathBuf, String, String)> {
    split_declared_script_path_iter(
        state,
        ctx,
        path,
        index_files,
        chain.iter().map(AsRef::as_ref),
    )
}

/// Directory-bearing chain form for ErrorDocument policy. Keeping the parsed
/// entries borrowed avoids cloning every `Arc<Htaccess>` into a parallel vector.
pub(super) fn split_declared_script_path_with_dirs(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    index_files: &[String],
    chain: &[(PathBuf, Arc<Htaccess>)],
) -> Option<(PathBuf, String, String)> {
    split_declared_script_path_iter(
        state,
        ctx,
        path,
        index_files,
        chain.iter().map(|(_, ht)| ht.as_ref()),
    )
}

fn split_declared_script_path_iter<'a, I>(
    state: &ServerState,
    ctx: &ReqCtx,
    path: &str,
    index_files: &[String],
    chain: I,
) -> Option<(PathBuf, String, String)>
where
    I: Clone + Iterator<Item = &'a Htaccess>,
{
    // NOTE: do NOT short-circuit on `state.lsapi.is_none()`. A path that resolves
    // to a script handler must be IDENTIFIED as such even when the lsphp pool is
    // unavailable, so the caller can fail closed instead of letting the file fall
    // through to the static handler and leak its SOURCE CODE.
    if !vhost_scripts_enabled(state, ctx) {
        return None;
    }
    // Hot-path gate: only chains that actually carry a `SetHandler`/`AddHandler`/
    // `AddType` directive pay the per-prefix scope-match cost. Bool-field scan over
    // the (short) chain — no alloc/regex/syscall — so the common no-override case is
    // byte-identical to before (the `force_php` closure is never invoked).
    let force_active = chain.clone().any(|h| h.has_handler_override);
    let force_php = |url: &str| {
        let base = url.rsplit('/').next().unwrap_or("");
        hj_rewrite::php_handler_forced_iter(chain.clone(), url, base)
    };
    // (#9a/#505) Effective executable-suffix set: global `phpConfig` suffixes
    // plus per-vhost script handlers. Only an explicit `static` mapping removes
    // a suffix; unsupported normalized kinds remain classified as scripts so
    // dispatch can fail closed instead of serving source.
    let php_suffixes = effective_php_suffixes(state, ctx);
    if php_suffixes.is_empty() && !force_active {
        return None;
    }
    if !force_active && !directory_like(path) && !has_executable_segment(path, &php_suffixes) {
        return None;
    }
    let resolved = resolve_script(
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
    )?;
    // (security #266) The symlink policy must hold on the PHP routing path too, not
    // just hj-static's file serving: when this vhost does not follow symlinks, a
    // chosen script that resolves (through symlinks) outside the docroot is refused
    // — one canonicalize on the FINAL candidate only, so the hot path pays nothing
    // for allow_symlink vhosts or non-PHP requests.
    if !ctx.vhost.allow_symbol_link {
        let doc_canon = std::fs::canonicalize(&ctx.vhost.doc_root).ok()?;
        let script_canon = std::fs::canonicalize(&resolved.0).ok()?;
        if !script_canon.starts_with(&doc_canon) {
            tracing::debug!(
                script = %resolved.0.display(),
                "php dir-index/script candidate escapes docroot via symlink; refusing"
            );
            return None;
        }
    }
    Some(resolved)
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
    let ext_is_php = |ext: &str| extension_is_executable(php_suffixes, ext);
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
    if !directory_like(path) {
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
    fn proc_fd_deleted_markers_do_not_hide_script_or_wrapper_suffixes() {
        assert_eq!(proc_fd_basename("secret.php (deleted)"), "secret.php");
        assert_eq!(
            proc_fd_basename("secret.php.br (deleted) (deleted)"),
            "secret.php.br"
        );
        assert_eq!(
            logical_precompressed_basename(proc_fd_basename("secret.php.br (deleted) (deleted)")),
            Some("secret.php")
        );
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
