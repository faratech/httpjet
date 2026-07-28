//! Load-time **scope index** for the `.htaccess` access rules and `Header`
//! directives — httpjet's equivalent of OpenLiteSpeed's "index the context tree
//! once at load, do one cheap lookup per request" (OLS reimplemented cleanly, no
//! GPL code).
//!
//! A heavy forum `.htaccess` (14 access rules + ~51 header
//! directives) is otherwise scanned **in full on every request** — including
//! every static asset — by [`Htaccess::access_decision`] /
//! [`Htaccess::response_headers`]. Most rules cannot possibly match a given
//! request (a `<FilesMatch "\.log$">` deny is irrelevant to `/css/app.css`), so
//! this module classifies each rule's scope **once at parse time** into a bucket
//! keyed by exact basename or file extension, and at request time hands the
//! matcher only the rules that could plausibly apply.
//!
//! # Correctness — this is a *pure superset filter*
//!
//! The index NEVER decides anything. It only narrows the candidate list; the
//! existing [`AccessRule::matches`](crate::htaccess::AccessRule) /
//! [`scopes_match`](crate::directives) remain the sole arbiter, run on every
//! candidate. The classification is **conservative**: a scope is placed in the
//! basename/extension buckets only when its compiled regex is *provably* an
//! exact-literal or pure-extension-suffix match; anything else (`.*`, `?`, char
//! classes, alternations with a non-literal arm, lookahead, an un-anchored stem,
//! a path/`<If>`/`<Directory*>` scope, a conjunction of scopes, or a regex that
//! failed to compile) lands in `dir_wide`/`residual`, which are **always**
//! included in the candidate set. Thus the index can only ever drop a rule that
//! could not have matched — it can never flip an allow/deny or drop a header.
//!
//! Invariants (kept in lock-step with the parser):
//! * Every rule index lands in **exactly one** bucket (so the merged candidate
//!   set needs no dedup for correctness — but the merge dedups anyway, defence in
//!   depth, so an accidental double-bucket can never double-apply an `Append`/`Add`).
//! * `dir_wide` + `residual` are always candidates; the matcher still runs on
//!   them, so they are not assumed to match — a `regex == None` Files/FilesMatch
//!   scope is therefore `residual`, never `dir_wide` (it must reach the
//!   fail-closed `scopes_match`).
//! * Bucket Vecs are built by iterating `0..N`, so they are already ascending;
//!   the per-request merge yields **ascending source order**, preserving the
//!   later-wins semantics the linear scan relied on.
//! * The index is a field on [`Htaccess`](crate::htaccess::Htaccess), rebuilt on
//!   every reparse, so it shares the file's `Arc` identity + mtime TTL and can
//!   never be stale relative to the rules it indexes.

use std::collections::HashMap;

use super::{AccessMatcher, AccessRule, HeaderDirective, Scope, ScopeKind};

/// A per-`.htaccess` index over either the access rules or the header directives.
/// Each `usize` is the rule's 0-based source index into the owning Vec. The same
/// shape serves both (an access rule is keyed by its single `<Files*>` basename
/// matcher; a header by its single enclosing scope).
#[derive(Debug, Default, Clone)]
pub struct ScopeIndex {
    /// Exact-literal basename (`<Files "robots.txt">` → `^robots\.txt$`) → rules.
    pub exact: HashMap<String, Vec<usize>>,
    /// File extension, lowercased (`<FilesMatch "\.(js|css)$">` → `js`,`css`) → rules.
    pub suffix: HashMap<String, Vec<usize>>,
    /// Directory-wide / unconditional rules (no scope, or a `<Directory*>`/`<If>`
    /// path scope that cannot be basename-indexed). Always candidates.
    pub dir_wide: Vec<usize>,
    /// Everything not provably exact/suffix and not dir-wide (complex regexes,
    /// conjunctions, failed-compile scopes). Always candidates.
    pub residual: Vec<usize>,
}

/// Where a single scope/matcher belongs. `classify_regex_source` is total —
/// every input yields one of these — so a rule can never silently fall out of
/// the index.
enum BucketKind {
    Exact(String),
    Suffix(Vec<String>),
    DirWide,
    Residual,
}

impl ScopeIndex {
    fn insert(&mut self, idx: usize, bucket: BucketKind) {
        // Exhaustive on BucketKind (no `_`): adding a variant is a compile error,
        // so a new bucket can never be silently dropped from the index.
        match bucket {
            BucketKind::Exact(key) => self.exact.entry(key).or_default().push(idx),
            BucketKind::Suffix(arms) => {
                for a in arms {
                    self.suffix.entry(a).or_default().push(idx);
                }
            }
            BucketKind::DirWide => self.dir_wide.push(idx),
            BucketKind::Residual => self.residual.push(idx),
        }
    }

    /// The ascending, de-duplicated set of rule indices that could match a
    /// request whose basename is `basename` (case-sensitive) and whose lowercased
    /// extension is `ext`. Zero-allocation: a k-way merge over the four already
    /// sorted bucket slices.
    pub(crate) fn candidates<'a>(&'a self, basename: &str, ext: &str) -> Candidates<'a> {
        let e = self.exact.get(basename).map(Vec::as_slice).unwrap_or(&[]);
        let s = self.suffix.get(ext).map(Vec::as_slice).unwrap_or(&[]);
        Candidates {
            slices: [e, s, &self.dir_wide, &self.residual],
            pos: [0; 4],
        }
    }
}

/// Ascending, de-duplicating merge iterator over up to four sorted index slices.
/// Each `next()` emits the smallest unseen index and advances every slice whose
/// head equals it (so an index appearing in two slices is yielded once).
pub(crate) struct Candidates<'a> {
    slices: [&'a [usize]; 4],
    pos: [usize; 4],
}

impl Iterator for Candidates<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let mut min: Option<usize> = None;
        for i in 0..4 {
            if let Some(&v) = self.slices[i].get(self.pos[i]) {
                min = Some(min.map_or(v, |m| m.min(v)));
            }
        }
        let m = min?;
        for i in 0..4 {
            while self.slices[i].get(self.pos[i]) == Some(&m) {
                self.pos[i] += 1;
            }
        }
        Some(m)
    }
}

/// Build the access-rule index: classify each rule by its (single) enclosing
/// `<Files*>`/`<Directory*>`/`<If>` matcher. Multi-matcher conjunctions are not
/// indexable by a single key, so they go to `residual` (always a candidate).
pub(crate) fn build_access_index(rules: &[AccessRule]) -> ScopeIndex {
    let mut idx = ScopeIndex::default();
    for (i, rule) in rules.iter().enumerate() {
        idx.insert(i, classify_access_rule(rule));
    }
    idx
}

/// Build the header index: classify each directive by its (single) enclosing
/// scope. An empty scope list is directory-wide; a conjunction is `residual`.
pub(crate) fn build_header_index(headers: &[HeaderDirective]) -> ScopeIndex {
    let mut idx = ScopeIndex::default();
    for (i, h) in headers.iter().enumerate() {
        idx.insert(i, classify_header_scopes(&h.scopes));
    }
    idx
}

fn classify_access_rule(rule: &AccessRule) -> BucketKind {
    match rule.matchers.as_slice() {
        // Directory-wide rule (top-level `Deny from all`, a standalone `<If>`,
        // etc.) — matches every path.
        [] => BucketKind::DirWide,
        // A single `<Files*>` basename matcher: the only indexable shape. (A
        // failed-compile `<Files*>` never reaches here — `record_access_rule`
        // drops such a rule entirely.)
        [AccessMatcher::Basename(re)] => classify_regex_source(re.as_str()),
        // Path (`<Directory*>`) and `<If>` matchers run against the full path /
        // URI and cannot be keyed by basename — always candidates.
        [AccessMatcher::Path(_)]
        | [AccessMatcher::IfUri { .. }]
        | [AccessMatcher::IfUriExpr(_)] => BucketKind::DirWide,
        // Conjunction of several enclosing blocks — not single-key indexable.
        _ => BucketKind::Residual,
    }
}

fn classify_header_scopes(scopes: &[Scope]) -> BucketKind {
    match scopes {
        [] => BucketKind::DirWide,
        [s] => classify_single_scope(s),
        // Nested `<If><Files>` etc.: a conjunction — keep it always-candidate.
        _ => BucketKind::Residual,
    }
}

fn classify_single_scope(s: &Scope) -> BucketKind {
    match s.kind {
        ScopeKind::Files | ScopeKind::FilesMatch => match &s.regex {
            Some(re) => classify_regex_source(re.as_str()),
            // A failed-compile Files/FilesMatch scope is fail-closed in
            // `scope_matches` (it does NOT match). It must reach that check, so
            // it is `residual` (always a candidate), NEVER `dir_wide` — a future
            // dir-wide short-circuit must not be able to apply it unconditionally.
            None => BucketKind::Residual,
        },
        // Path / `<If>` scopes match against the full path and cannot be keyed by
        // basename; `scope_matches` runs on them as a candidate.
        ScopeKind::DirectoryMatch | ScopeKind::Directory | ScopeKind::If => BucketKind::DirWide,
    }
}

/// Classify a compiled regex's **source string** (never executed) into a bucket.
/// Total: returns `Exact`/`Suffix` only for the two provably-narrow shapes,
/// `Residual` for everything else.
///
/// * exact  — `^BODY$` where `BODY` is only `[A-Za-z0-9_-]` and `\.` (literal
///   dot). Matches exactly one basename. Key = `BODY` with `\.` → `.`.
/// * suffix — `(^)?\.(arm|arm|…)$` (or `(^)?\.arm$`) where every arm is
///   `[A-Za-z0-9]+`. Matches any basename ending in one of the extensions.
///   Keys = the arms, lowercased.
fn classify_regex_source(src: &str) -> BucketKind {
    // exact must be anchored at BOTH ends (so it pins one basename).
    if let Some(body) = src.strip_prefix('^').and_then(|s| s.strip_suffix('$')) {
        if let Some(lit) = exact_literal_body(body) {
            return BucketKind::Exact(lit);
        }
    }
    // suffix may omit the leading `^` (real `<FilesMatch "\.log$">` does), but a
    // trailing `$` is required so the extension is genuinely at the end.
    let unanchored = src.strip_prefix('^').unwrap_or(src);
    if let Some(arms) = suffix_arms(unanchored) {
        return BucketKind::Suffix(arms);
    }
    BucketKind::Residual
}

/// If `body` (the inside of `^…$`) is a pure literal basename — only
/// `[A-Za-z0-9_-]` and `\.` escapes — return it with `\.` resolved to `.`.
/// A bare `.` (regex "any char"), `*`, `(`, char classes, etc. → `None`.
fn exact_literal_body(body: &str) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            // The only allowed escape is `\.` (a literal dot).
            '\\' => match chars.next() {
                Some('.') => out.push('.'),
                _ => return None,
            },
            c if c.is_ascii_alphanumeric() || c == '_' || c == '-' => out.push(c),
            _ => return None,
        }
    }
    Some(out)
}

/// If `s` (with any leading `^` already stripped) is `\.(arm|arm|…)$` or `\.arm$`
/// with every arm `[A-Za-z0-9]+`, return the lowercased arms; else `None`.
fn suffix_arms(s: &str) -> Option<Vec<String>> {
    let body = s.strip_prefix("\\.")?.strip_suffix('$')?;
    // `(a|b|c)` group or a single bare `arm`.
    let inner = match body.strip_prefix('(').and_then(|b| b.strip_suffix(')')) {
        Some(group) => group,
        None => body,
    };
    if inner.is_empty() {
        return None;
    }
    let mut arms = Vec::new();
    for arm in inner.split('|') {
        if arm.is_empty() || !arm.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        arms.push(arm.to_ascii_lowercase());
    }
    Some(arms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_regex::Regex;

    fn bucket_of(src: &str) -> &'static str {
        match classify_regex_source(src) {
            BucketKind::Exact(_) => "exact",
            BucketKind::Suffix(_) => "suffix",
            BucketKind::DirWide => "dir_wide",
            BucketKind::Residual => "residual",
        }
    }

    #[test]
    fn classify_exact_suffix_residual() {
        // fnmatch of a metachar-free `<Files "robots.txt">`.
        assert_eq!(bucket_of(r"^robots\.txt$"), "exact");
        // Anchored single-extension is exact (matches only ".log").
        assert_eq!(bucket_of(r"^\.log$"), "exact");
        // Unanchored stem → pure suffix.
        assert_eq!(bucket_of(r"\.log$"), "suffix");
        assert_eq!(bucket_of(r"\.(less|template)$"), "suffix");
        assert_eq!(bucket_of(r"\.(js|css|woff2|avif)$"), "suffix");
        // `.*` prefix, char classes, alternation with non-literal arms, optional
        // groups, bare-dot regexes → residual.
        assert_eq!(bucket_of(r".*_generator\.log$"), "residual");
        assert_eq!(bucket_of(r"addon\.json$"), "residual");
        assert_eq!(bucket_of(r"^(\.env|config\.php|.*\.md)$"), "residual");
        assert_eq!(bucket_of(r"\.(ico|pdf|js|css)(\.gz)?(\?.*)?$"), "residual");
        assert_eq!(bucket_of(r"robots.txt"), "residual"); // bare dot, unanchored
    }

    #[test]
    fn exact_key_resolves_escaped_dot() {
        match classify_regex_source(r"^robots\.txt$") {
            BucketKind::Exact(k) => assert_eq!(k, "robots.txt"),
            _ => panic!("expected exact"),
        }
    }

    #[test]
    fn suffix_arms_are_lowercased() {
        match classify_regex_source(r"\.(JS|Css)$") {
            BucketKind::Suffix(arms) => assert_eq!(arms, vec!["js", "css"]),
            _ => panic!("expected suffix"),
        }
    }

    #[test]
    fn candidates_merge_is_sorted_and_deduped() {
        let mut idx = ScopeIndex::default();
        idx.dir_wide = vec![1, 4];
        idx.residual = vec![0, 4]; // 4 intentionally duplicated across buckets
        idx.exact.insert("x.css".into(), vec![2]);
        idx.suffix.insert("css".into(), vec![3]);
        let got: Vec<usize> = idx.candidates("x.css", "css").collect();
        assert_eq!(got, vec![0, 1, 2, 3, 4]); // ascending, 4 appears once
    }

    #[test]
    fn header_regex_none_scope_is_residual_not_dir_wide() {
        // A failed-compile <FilesMatch> scope must be residual (reaches the
        // fail-closed scopes_match), never dir_wide.
        let scope = Scope {
            kind: ScopeKind::FilesMatch,
            regex: None,
            negate: false,
            uri_expr: None,
        };
        let h = HeaderDirective {
            action: crate::htaccess::HeaderAction::Set,
            name: "X".into(),
            value: "1".into(),
            env: None,
            expr: Vec::new(),
            always: false,
            scopes: vec![scope],
        };
        let idx = build_header_index(std::slice::from_ref(&h));
        assert_eq!(idx.residual, vec![0]);
        assert!(idx.dir_wide.is_empty());
    }

    #[test]
    fn access_basename_indexed_path_and_if_are_dir_wide() {
        let files = AccessRule {
            matchers: vec![AccessMatcher::Basename(Regex::new(r"\.log$").unwrap())],
            denied: true,
        };
        let dir = AccessRule {
            matchers: vec![AccessMatcher::Path(
                Regex::new(r"^.*/internal_data$").unwrap(),
            )],
            denied: true,
        };
        let iff = AccessRule {
            matchers: vec![AccessMatcher::IfUri {
                regex: None,
                negate: false,
            }],
            denied: true,
        };
        let idx = build_access_index(&[files, dir, iff]);
        assert_eq!(idx.suffix.get("log"), Some(&vec![0]));
        assert_eq!(idx.dir_wide, vec![1, 2]);
    }
}
