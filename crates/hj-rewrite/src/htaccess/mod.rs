//! Per-directory `.htaccess` model. [`Htaccess`] is a parsed [`RuleSet`] plus
//! the *recognized* non-rewrite directives (header ops, access rules, SetEnvIf,
//! and the LSCache page-cache directives).
//!
//! Application of most non-rewrite directives is wired up later by the
//! pipeline; here we *parse and record* them faithfully so that information is
//! never lost. `RewriteRule` side-effects inside vendor blocks (e.g.
//! `<IfModule LiteSpeed>` LSCache directives) are preserved because their
//! `[E=...]` env sets still flow through the embedded [`RuleSet`].

mod cache;
mod mod_access;
mod parse;
mod php;
mod scope_index;

use std::collections::BTreeMap;

use fancy_regex::Regex;

use crate::rules::RuleSet;

pub use cache::{CacheDirectives, CacheKeyModifier, cache_directives, chain_cacheable_for_default};
pub use mod_access::{AccessOrder, AccessSubject, HostAccess, HostEntry};
pub use php::{ResolvedPhp, php_directives, php_handler_forced};
pub use scope_index::ScopeIndex;

pub(crate) use scope_index::{build_access_index, build_header_index};

/// A header op recorded from `Header set/add/append/unset/merge ...`, together
/// with the scope (enclosing `<Files*>`/`<DirectoryMatch>`/`<If>`) it was
/// written under, so the consumer can apply it only to matching paths.
///
/// Note: this is the *parsed record*. The per-request, value-interpolated view
/// the pipeline consumes is [`crate::HeaderOp`] (produced by
/// [`Htaccess::response_headers`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderDirective {
    pub(crate) action: HeaderAction,
    pub(crate) name: String,
    /// The value (already de-quoted). Empty for `unset`.
    pub(crate) value: String,
    /// Optional `env=NAME` guard (or `env=!NAME` for negation).
    pub(crate) env: Option<EnvGuard>,
    /// Optional `expr=%{REQUEST_URI} =~|!~ ...` guard.
    pub(crate) expr: Vec<UriCond>,
    /// `always` condition keyword (vs `onsuccess`).
    pub(crate) always: bool,
    /// The conjunction of every enclosing block's scope (`<Files*>`,
    /// `<DirectoryMatch>`/`<Directory>`, `<If>`), outermost first. The op applies
    /// only when ALL of them match. Empty = directory-wide. Mirrors how
    /// `record_access_rule` ANDs the open-section stack, so a nested
    /// `<If ...><Files ...>Header ...</Files></If>` honors the outer `<If>` too.
    pub(crate) scopes: Vec<Scope>,
}

/// The path-matching scope a directive inherits from its enclosing block.
#[derive(Debug, Clone)]
pub struct Scope {
    pub kind: ScopeKind,
    /// Compiled matcher for the scope (basename for `Files*`, path for
    /// `DirectoryMatch`/`If`). `None` if the block's argument could not be
    /// understood (then the consumer treats the scope leniently).
    pub regex: Option<Regex>,
    /// For `<If>`: whether the URI test was negated (`!~`). Ignored otherwise.
    pub negate: bool,
    /// For `<If>`: the modelled `%{REQUEST_URI} =~|!~ ...` boolean expression.
    /// `None` means the expression could not be modelled.
    pub uri_expr: Option<UriExpr>,
}

#[derive(Debug, Clone)]
pub struct UriCond {
    pub regex: Option<Regex>,
    pub negate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriExpr {
    Cond(UriCond),
    And(Vec<UriExpr>),
    Or(Vec<UriExpr>),
}

impl UriExpr {
    pub(crate) fn matches(&self, path: &str, on_err: bool) -> bool {
        match self {
            UriExpr::Cond(test) => match &test.regex {
                Some(re) => match re.is_match(path) {
                    Ok(m) => m != test.negate,
                    Err(_) => on_err,
                },
                None => on_err,
            },
            UriExpr::And(parts) => parts.iter().all(|part| part.matches(path, on_err)),
            UriExpr::Or(parts) => parts.iter().any(|part| part.matches(path, on_err)),
        }
    }

    pub(crate) fn first_cond(&self) -> &UriCond {
        match self {
            UriExpr::Cond(cond) => cond,
            UriExpr::And(parts) | UriExpr::Or(parts) => parts[0].first_cond(),
        }
    }
}

impl PartialEq for UriCond {
    fn eq(&self, other: &Self) -> bool {
        self.negate == other.negate
            && self.regex.as_ref().map(|r| r.as_str()) == other.regex.as_ref().map(|r| r.as_str())
    }
}
impl Eq for UriCond {}

impl PartialEq for Scope {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.negate == other.negate
            && self.regex.as_ref().map(|r| r.as_str()) == other.regex.as_ref().map(|r| r.as_str())
            && self.uri_expr == other.uri_expr
    }
}
impl Eq for Scope {}

/// The kind of block a [`Scope`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    Files,
    FilesMatch,
    DirectoryMatch,
    Directory,
    /// `<If "...">` — we only model the common `%{REQUEST_URI} (!)~ m#re#` form.
    If,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderAction {
    Set,
    Add,
    Append,
    Merge,
    Unset,
    Echo,
}

/// `env=NAME` / `env=!NAME` guard on a `Header` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvGuard {
    pub(crate) var: String,
    pub(crate) negate: bool,
}

/// A `SetEnvIf attr regex VAR[=val]` (or `SetEnvIfNoCase`).
#[derive(Debug, Clone)]
pub struct SetEnvIf {
    /// Attribute name (e.g. `Origin`, `Request_URI`, `Query_String`, or a
    /// header / `Remote_Addr`).
    pub(crate) attribute: String,
    pub(crate) regex: Regex,
    /// (#312) Literal prefix fast path: when the pattern is `^`-anchored and
    /// case-sensitive, the leading literal run (same extractor as RewriteRule's
    /// prefilter) lets evaluation skip the fancy_regex backtracker for subjects
    /// that cannot match. Empty = no fast path (fail open, always execute).
    pub(crate) literal_prefix: Box<[u8]>,
    /// Variable to set and its value template (`$0`, `$1` allowed).
    pub(crate) var: String,
    pub(crate) value: String,
}

/// Parse-time verdict on whether a finished STATIC response built under this
/// file may be replayed for a later request (the pipeline's `fast_memo`).
/// `eligible` holds iff every request-state input the file reads is either part
/// of the memo's base key (scheme, Host, path, query, GET-only method) or a
/// request header named in `vary_headers`, whose raw value the pipeline then
/// captures per memo entry (an HTTP `Vary`, in effect). Fail-closed: any
/// directive kind not proven key-determined marks the file ineligible and
/// records the offending line in `blockers`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoClass {
    pub eligible: bool,
    /// Lowercased, `_`→`-` folded request-header names whose raw first value
    /// must match between the memoized request and a replay (absent ≠ present).
    /// `User-Agent` reads by the REWRITE ruleset are deliberately not listed:
    /// the pipeline keys those on [`RuleSet::ua_cond_signature`] when
    /// [`RuleSet::ua_classify_eligible`] and on the raw header otherwise.
    pub vary_headers: Vec<String>,
    /// `(line, reason)` of the first few blocking directives; line 0 = the
    /// rewrite ruleset (which keeps no line numbers).
    pub blockers: Vec<(usize, &'static str)>,
}

impl MemoClass {
    const MAX_BLOCKERS: usize = 8;

    pub(crate) fn block(&mut self, line: usize, reason: &'static str) {
        self.eligible = false;
        if self.blockers.len() < Self::MAX_BLOCKERS {
            self.blockers.push((line, reason));
        }
    }

    pub(crate) fn vary(&mut self, folded_name: String) {
        if !self.vary_headers.contains(&folded_name) {
            self.vary_headers.push(folded_name);
        }
    }
}

/// `SetEnvIf`'s header-attribute spelling folded to the canonical header name
/// (`User_Agent` → `user-agent`), or `None` when it is not a valid token.
pub(crate) fn fold_header_name(attr: &str) -> Option<String> {
    let folded: String = attr
        .chars()
        .map(|c| {
            if c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    let tchar = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    (!folded.is_empty() && folded.bytes().all(tchar)).then_some(folded)
}

/// A `php_value` / `php_admin_value` / `php_flag` / `php_admin_flag` directive
/// from `.htaccess`. Flags are normalized to their value form at parse time
/// (`on`→`1`, `off`→`0`), so `value` is always the literal php.ini value.
/// Passed to lsphp via the LSAPI *special-env* section (see `hj_lsapi`), exactly
/// as LiteSpeed does — the regular CGI env is ignored by the lsphp SAPI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhpDirective {
    pub(crate) kind: PhpDirectiveKind,
    /// The php.ini setting name, e.g. `auto_prepend_file`.
    pub(crate) name: String,
    pub(crate) value: String,
    /// The conjunction of every enclosing block's scope, outermost first; the
    /// directive applies only when ALL of them match. Empty = directory-wide.
    /// Mirrors [`HeaderDirective::scopes`] and `record_access_rule`'s AND over
    /// the open-section stack: a `php_value` scoped to e.g.
    /// `<Files "crontab.html">` must apply ONLY to that file (else an
    /// `auto_prepend_file "none"` meant for one file leaks onto every PHP
    /// request in the directory and lsphp fatals on `require 'none'`), AND a
    /// `php_value` under `<If ...><Files ...>` must also honor the outer `<If>`.
    pub(crate) scopes: Vec<Scope>,
}

/// Which directive produced a [`PhpDirective`] — selects the permission level:
/// `php_admin_*` is applied as `PHP_INI_SYSTEM` (can set any ini), the plain
/// forms as `PHP_INI_PERDIR` (PHP itself refuses anything stronger).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhpDirectiveKind {
    Value,
    AdminValue,
    Flag,
    AdminFlag,
}

impl PhpDirectiveKind {
    /// True for the `php_admin_*` forms (PHP_INI_SYSTEM level).
    pub fn is_admin(self) -> bool {
        matches!(
            self,
            PhpDirectiveKind::AdminValue | PhpDirectiveKind::AdminFlag
        )
    }
}

/// A `SetHandler <handler>` directive. Apache/LiteSpeed: `SetHandler` forces the
/// named handler on every file in scope regardless of extension. We only model
/// whether the effective handler is PHP (`application/x-httpd-php`): `php == true`
/// forces PHP routing; `php == false` (`None`/`default-handler`/anything else)
/// records an explicit reset so a deeper `SetHandler none` can cancel a shallower
/// `SetHandler application/x-httpd-php` or an [`AddPhpExt`]. Consulted ONLY to
/// *add* PHP routing (never to strip extension-based PHP routing) — see
/// [`php_handler_forced`](super::php::php_handler_forced).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandlerDirective {
    pub(crate) php: bool,
    /// The conjunction of every enclosing block's scope, outermost first; applies
    /// only when ALL match. Empty = directory-wide. Mirrors [`PhpDirective::scopes`].
    pub(crate) scopes: Vec<Scope>,
}

/// An `AddHandler application/x-httpd-php <ext…>` / `AddType application/x-httpd-php
/// <ext…>` directive: the listed extensions (lowercased, leading dot stripped) are
/// mapped to PHP for this directory (and below, since the chain includes parent
/// `.htaccess` files). Only the PHP handler/type is recorded; non-PHP `AddType`
/// (e.g. `AddType text/html .shtml`) is ignored. Additive only (see
/// [`HandlerDirective`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddPhpExt {
    pub(crate) exts: Vec<String>,
    /// Enclosing-block scope conjunction (usually empty = directory-wide).
    pub(crate) scopes: Vec<Scope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionKind {
    Files,
    FilesMatch,
    DirectoryMatch,
    Directory,
}

/// One conjunctive matcher contributed by an enclosing access block. A rule's
/// matchers are **ANDed**: the rule applies only when every matcher matches.
#[derive(Debug, Clone)]
pub enum AccessMatcher {
    /// `<Files "glob">` / `<Files ~ re>` / `<FilesMatch re>` — match the basename.
    Basename(Regex),
    /// `<Directory>` / `<DirectoryMatch re>` — match the full request path.
    Path(Regex),
    /// `<If "%{REQUEST_URI} (=~|!~) m#re#">` — match (or, when `negate`, NOT
    /// match) the request path. `regex == None` means the `<If>` expression
    /// could not be modelled; such a matcher is treated as "always satisfied"
    /// so the rule still applies (fail-safe for a deny).
    IfUri { regex: Option<Regex>, negate: bool },
    /// Compound `<If>` expression preserving boolean grouping and precedence.
    IfUriExpr(UriExpr),
}

impl AccessMatcher {
    /// `on_err` is the result substituted when a `fancy_regex` match-time error occurs (e.g. a
    /// backtrack-limit hit). Callers pass the rule's `denied` flag so the outcome is fail-CLOSED
    /// in BOTH directions (issue A6): a DENY rule treats an un-evaluable matcher as MATCHED (the
    /// deny still applies), an ALLOW rule treats it as NOT matched (the grant is withheld).
    /// Previously every match error mapped unconditionally to `false`, which silently let a
    /// denied path through whenever its pattern errored.
    pub(crate) fn matches(&self, rel_path: &str, basename: &str, on_err: bool) -> bool {
        match self {
            AccessMatcher::Basename(re) => re.is_match(basename).unwrap_or(on_err),
            AccessMatcher::Path(re) => {
                // `<Directory>`/`<DirectoryMatch>` apply to the matched directory
                // AND everything beneath it (Apache). Match the request path and
                // every ancestor directory prefix, so a file *inside* a denied
                // directory (e.g. `/internal_data/x`, `/.git/config`) is denied
                // even though the file path itself does not match the dir regex.
                let hit = |s: &str| re.is_match(s).unwrap_or(on_err);
                if hit(rel_path) {
                    true
                } else {
                    let mut p = rel_path;
                    let mut found = false;
                    while let Some((parent, _)) = p.rsplit_once('/') {
                        let dir = if parent.is_empty() { "/" } else { parent };
                        if hit(dir) {
                            found = true;
                            break;
                        }
                        if parent.is_empty() {
                            break;
                        }
                        p = parent;
                    }
                    found
                }
            }
            AccessMatcher::IfUri { regex, negate } => match regex {
                Some(re) => match re.is_match(rel_path) {
                    Ok(m) => m != *negate,
                    Err(_) => on_err,
                },
                None => true,
            },
            AccessMatcher::IfUriExpr(expr) => expr.matches(rel_path, on_err),
        }
    }
}

/// A complete access decision recorded from an `allow`/`deny`/`Require` line,
/// scoped by the **conjunction** of its enclosing blocks (`<Files*>`,
/// `<Directory*>`, and `<If>`). An empty `matchers` list is a directory-wide
/// rule (matches every path) — e.g. a top-level `Deny from all` or a standalone
/// `<If> Require all denied`.
#[derive(Debug, Clone)]
pub struct AccessRule {
    /// ANDed matchers from the enclosing blocks (empty = directory-wide).
    pub matchers: Vec<AccessMatcher>,
    /// True = denied (403); false = explicitly granted. For a `host_access` rule
    /// this is always `true`: it is the fail-closed polarity of the scope
    /// matchers, and the verdict itself comes from [`HostAccess::permits`].
    pub denied: bool,
    /// The legacy `Order` + `Allow from` / `Deny from` block of this scope, whose
    /// verdict depends on the request subject (client IP / env) — see
    /// [`AccessRule::denies`].
    pub host_access: Option<HostAccess>,
}

impl AccessRule {
    /// The verdict for a request this rule's scope matches.
    pub fn denies(&self, subject: &AccessSubject<'_>) -> bool {
        match &self.host_access {
            Some(ha) => !ha.permits(subject),
            None => self.denied,
        }
    }

    pub(crate) fn matches(&self, rel_path: &str, basename: &str) -> bool {
        // Fail CLOSED toward this rule's polarity on a regex match-time error (issue A6): for a
        // deny rule an un-evaluable matcher counts as matched (deny applies); for an allow rule
        // it counts as not matched (grant withheld).
        self.matchers
            .iter()
            .all(|m| m.matches(rel_path, basename, self.denied))
    }
}

/// A parsed `.htaccess`: the rewrite engine plus recognized side directives.
#[derive(Debug, Default)]
pub struct Htaccess {
    /// The rewrite rules (RewriteEngine/Base/Cond/Rule), including those inside
    /// recognized vendor blocks.
    pub rules: RuleSet,
    /// `Header` ops in source order (each carries its enclosing scope).
    pub(crate) headers: Vec<HeaderDirective>,
    /// `ErrorDocument code target` classified into path / inline / external.
    /// Queried via [`Htaccess::error_document`].
    pub(crate) error_docs: BTreeMap<u16, crate::directives::ErrorDoc>,
    /// All access decisions in source order, each scoped by the conjunction of
    /// its enclosing blocks (Files/Directory/If). This is the authoritative
    /// model consulted by [`Htaccess::access_decision`] / [`Htaccess::is_forbidden`]:
    /// it captures top-level `Deny from all` (#4), `<If>`-nested `Require`
    /// (#5), and fail-closed unrecognized `Require` predicates (#2).
    pub access_rules: Vec<AccessRule>,
    /// (Tier 1.3) `AuthType Basic` + `AuthName` + `AuthUserFile` (+ `Require
    /// valid-user`/`user …`) resolved into a Basic-auth realm covering this
    /// directory tree. Enforcement (401 challenge + credential verification)
    /// happens in the pipeline; `None` = no auth directives (or an incomplete
    /// block, which keeps the historical fail-closed deny collapse).
    pub auth: Option<crate::auth::AuthRealm>,
    /// `SetEnvIf`/`SetEnvIfNoCase`.
    pub set_env_if: Vec<SetEnvIf>,
    /// `CacheLookup [public|private] on|off` — `Some(true/false)` if present in
    /// this directory's file (last one wins). Drives the origin page cache.
    pub(crate) cache_lookup: Option<bool>,
    /// `CacheEnable [public|private] [path]` path prefixes seen here.
    pub(crate) cache_enable: Vec<String>,
    /// `CacheDisable [public|private] [path]` path prefixes (empty = dir-wide).
    pub(crate) cache_disable: Vec<String>,
    /// `CacheKeyModify -qs:NAME[*]` operations (source order).
    pub cache_key_modifiers: Vec<CacheKeyModifier>,
    /// `php_value`/`php_admin_value`/`php_flag`/`php_admin_flag` directives in
    /// source order. Resolved across the chain by [`php_directives`](super::php::php_directives)
    /// and passed to lsphp via the LSAPI special-env section.
    pub(crate) php_directives: Vec<PhpDirective>,
    /// `DirectoryIndex` names in source order for this directory. Empty means no
    /// override; the caller falls back to vhost/server index files.
    pub directory_index: Vec<String>,
    /// `SetHandler <handler>` directives in source order (each carries its scope).
    /// Folded across the chain by [`php_handler_forced`](super::php::php_handler_forced)
    /// to decide whether a non-PHP-suffixed file is forced through lsphp.
    pub(crate) set_handlers: Vec<HandlerDirective>,
    /// `AddHandler`/`AddType application/x-httpd-php <ext…>` directives in source
    /// order. Adds the listed extensions to PHP routing for this directory subtree.
    pub(crate) add_php_exts: Vec<AddPhpExt>,
    /// True iff `headers` is non-empty. Lets [`apply_response_headers`] skip the
    /// per-request `response_headers` call (and its `Vec` alloc) for chain
    /// entries (subdirectory `.htaccess` files) that carry no `Header` ops.
    pub has_resp_op: bool,
    /// True iff `set_handlers`/`add_php_exts` is non-empty. The hot-path gate that
    /// keeps suffix routing byte-identical (and free of any scope-regex cost) for
    /// the overwhelmingly common case of no handler-override directive in the chain.
    pub has_handler_override: bool,
    /// Load-time index over `access_rules` (keyed by `<Files*>` basename/ext) so a
    /// request evaluates only the rules that could match, not all of them. Built
    /// at the tail of [`Htaccess::parse`]; rebuilt on every reparse so it is never
    /// stale vs the rules it indexes. A pure superset filter — see [`ScopeIndex`].
    pub access_index: ScopeIndex,
    /// Load-time index over `headers`, same contract as `access_index`.
    pub header_index: ScopeIndex,
    /// Parse-time `fast_memo` replay eligibility (see [`MemoClass`]).
    pub memo: MemoClass,
}
