//! Per-request *consumption* of the non-rewrite `.htaccess` directives that
//! [`crate::Htaccess`] already parses (access sections, `Header` ops,
//! `ErrorDocument`, `SetEnvIf`). The parser records this information faithfully
//! but exposes no usable query surface; this module is that surface.
//!
//! Everything here is **pure**: no I/O, no syscalls, no clock. Each function
//! takes an already-resolved request path (relative to the docroot, with a
//! leading `/`), the request method, and — where relevant — an environment map
//! and a bundle of request attributes. The pipeline computes those once and
//! threads them through the `.htaccess` chain.
//!
//! ## Apache parity notes
//!
//! * `<Files "glob">` uses **fnmatch glob** semantics against the final path
//!   *segment* (basename), NOT regex. `*.log` matches `x.log` but not `xlog`.
//! * `<Files ~ "regex">` and `<FilesMatch "regex">` use regex against the
//!   basename.
//! * `<DirectoryMatch "regex">` / `<Directory>` match against the directory
//!   path.
//! * Access merges in source order, later wins for the same target — but a
//!   matched `denied` is treated *fail-safe*: see [`Htaccess::access_decision`].
//! * `Header` honors `always` vs `onsuccess` (the latter only applies on a 2xx/
//!   3xx response), the `env=[!]NAME` guard, FilesMatch/`<If>` scoping, and
//!   `%{VAR}e` environment interpolation in the value.

use std::borrow::Cow;

use crate::htaccess::{AccessSubject, EnvGuard, HeaderAction, Htaccess, Scope, ScopeKind};
use crate::input::HeaderLookup;

// ===========================================================================
// 1. ACCESS
// ===========================================================================

/// The outcome of consulting one `.htaccess`'s access sections for a request.
///
/// A chain of `.htaccess` files yields a sequence of decisions; the pipeline
/// combines them outermost-first and a single [`AccessDecision::Denied`]
/// anywhere is final (fail-safe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// A matching section denies the request -> respond `403`.
    Denied,
    /// A matching section explicitly grants the request.
    Granted,
    /// No section in this `.htaccess` had anything to say about this path.
    NoOpinion,
}

impl Htaccess {
    /// Decide whether this `.htaccess` permits serving `rel_path` for `method`.
    ///
    /// `rel_path` is the request path relative to the docroot, with a leading
    /// `/` (e.g. `/config/db.php`); `method` is the upper-case HTTP method.
    ///
    /// Matching rules (Apache parity):
    /// * `<Files "glob">` -> fnmatch glob against the **basename** (last
    ///   segment). `*.log` denies `x.log`, not `xlog`.
    /// * `<Files ~ "re">` / `<FilesMatch "re">` -> regex against the basename.
    /// * `<DirectoryMatch "re">` / `<Directory>` -> regex against `rel_path`.
    ///
    /// Sections are evaluated in source order; a later same-scope section wins
    /// (matching Apache's `Require` merge). The result is **fail-safe**: the
    /// method is currently advisory (Apache `<Limit>` is not modelled here), so
    /// any matching `denied` section produces [`AccessDecision::Denied`].
    pub fn access_decision(&self, rel_path: &str, method: &str) -> AccessDecision {
        self.access_decision_for(rel_path, method, &AccessSubject::default())
    }

    /// [`Htaccess::access_decision`] evaluated against a concrete request subject
    /// (resolved client IP + env), which the legacy `Order`/`Allow from`/`Deny
    /// from` rules need. With an unknown subject those rules fail closed.
    pub fn access_decision_for(
        &self,
        rel_path: &str,
        method: &str,
        subject: &AccessSubject<'_>,
    ) -> AccessDecision {
        let _ = method; // reserved for future <Limit METHOD> support.
        let basename = basename(rel_path);
        let ext = ext_lower(basename);
        let mut decision = AccessDecision::NoOpinion;
        // The `access_rules` model is authoritative: it carries directory-wide
        // rules (top-level `Deny from all`, #4), `<If>`-scoped rules (#5), and
        // fail-closed unrecognized `Require` predicates (#2) — none of which the
        // flat `access` section list can represent. The `access_index` narrows the
        // scan to rules whose scope could match (a pure superset filter); the
        // matcher below is still the arbiter, and candidates arrive in ascending
        // source order so "later wins" is preserved.
        for i in self.access_index.candidates(basename, &ext) {
            let rule = &self.access_rules[i];
            if rule.matches(rel_path, basename) {
                decision = if rule.denies(subject) {
                    AccessDecision::Denied
                } else {
                    AccessDecision::Granted
                };
            }
        }
        decision
    }
}

// ===========================================================================
// 2. HEADERS  (requirements #2, #7)
// ===========================================================================

/// A response-header mutation to apply, with `%{VAR}e` already interpolated.
///
/// ## Merge semantics (apply in order against the outgoing header set)
/// * [`HeaderOp::Set`] — replace: remove every existing `name`, then set it to
///   `value` (a single line).
/// * [`HeaderOp::Add`] — append a **new** line: keep existing `name` lines and
///   add another `name: value` (used for multi-valued headers like `Set-Cookie`,
///   `Vary`).
/// * [`HeaderOp::Append`] — concatenate: if `name` already exists, append
///   `, value` to the existing (last) value; otherwise behave like `Set`.
/// * [`HeaderOp::Unset`] — remove every existing `name` (`value` is empty).
/// * [`HeaderOp::Edit`] — for completeness; carries the value verbatim. (Apache
///   `Header edit name regex repl` is rare in the live configs; the pipeline may
///   treat it as a no-op or implement the substitution.)
///
/// `Merge` from Apache collapses to [`HeaderOp::Append`] (Apache de-duplicates;
/// the caller may dedup if it wishes), and `echo`/`note` forms are dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderOp {
    Set { name: String, value: String },
    Add { name: String, value: String },
    Append { name: String, value: String },
    Unset { name: String },
    Edit { name: String, value: String },
}

impl HeaderOp {
    /// The header name this op targets (always present).
    pub fn name(&self) -> &str {
        match self {
            HeaderOp::Set { name, .. }
            | HeaderOp::Add { name, .. }
            | HeaderOp::Append { name, .. }
            | HeaderOp::Unset { name }
            | HeaderOp::Edit { name, .. } => name,
        }
    }
}

impl Htaccess {
    /// Compute the ordered list of response-header mutations that apply to a
    /// response for `rel_path` with final `status`, resolving `%{VAR}e`
    /// references against `env`.
    ///
    /// * `rel_path` — request path relative to docroot, leading `/`.
    /// * `status`   — the response status code chosen so far. `onsuccess`
    ///   (non-`always`) header ops only fire for 2xx/3xx; `always` ops always
    ///   fire.
    /// * `env`      — the request env (e.g. from [`Htaccess::eval_set_env`] and
    ///   any `[E=...]` rewrite sets); used for both the `env=[!]NAME` guard and
    ///   `%{NAME}e` value interpolation.
    ///
    /// Only headers whose enclosing `<Files*>` / `<DirectoryMatch>` (and any
    /// `<If "%{REQUEST_URI} ...">`) scope matches `rel_path` are emitted; an
    /// unscoped (directory-wide) `Header` always applies. The returned ops carry
    /// fully-interpolated values and are ordered as written in the file, so the
    /// caller can fold them left-to-right over the header map.
    pub fn response_headers(
        &self,
        rel_path: &str,
        status: u16,
        env: &[(String, String)],
    ) -> Vec<HeaderOp> {
        self.response_headers_for_request(rel_path, rel_path, status, env)
    }

    pub fn response_headers_for_request(
        &self,
        rel_path: &str,
        request_path: &str,
        status: u16,
        env: &[(String, String)],
    ) -> Vec<HeaderOp> {
        let basename = basename(rel_path);
        let ext = ext_lower(basename);
        let success = (200..400).contains(&status);
        let mut out = Vec::new();

        // `header_index` narrows the scan to directives whose scope could match
        // (superset filter); `scopes_match` below remains the arbiter, and
        // candidates arrive in ascending source order so the ops fold left-to-right
        // exactly as written.
        for i in self.header_index.candidates(basename, &ext) {
            let h = &self.headers[i];
            // always vs onsuccess.
            if !h.always && !success {
                continue;
            }
            // env=[!]NAME guard.
            if let Some(g) = &h.env {
                if !env_guard_passes(g, env) {
                    continue;
                }
            }
            if !h.expr.is_empty() && !uri_tests_match(&h.expr, request_path, false) {
                continue;
            }
            // FilesMatch / DirectoryMatch / If scoping (conjunction of all
            // enclosing blocks).
            if !scopes_match(&h.scopes, rel_path, basename) {
                continue;
            }

            let name = h.name.clone();
            match h.action {
                HeaderAction::Unset => out.push(HeaderOp::Unset { name }),
                HeaderAction::Set => out.push(HeaderOp::Set {
                    name,
                    value: interpolate_env(&h.value, env),
                }),
                HeaderAction::Add => out.push(HeaderOp::Add {
                    name,
                    value: interpolate_env(&h.value, env),
                }),
                HeaderAction::Append | HeaderAction::Merge => out.push(HeaderOp::Append {
                    name,
                    value: interpolate_env(&h.value, env),
                }),
                // `Header echo Foo` mirrors a *request* header into the response;
                // it has no static value, so we skip it (rare; not in live cfg).
                // (Apache `Header edit name re repl` is not emitted by the parser
                // today; [`HeaderOp::Edit`] exists for API completeness so the
                // integration layer can construct it directly if needed.)
                HeaderAction::Echo => {}
            }
        }
        out
    }
}

fn env_guard_passes(g: &EnvGuard, env: &[(String, String)]) -> bool {
    let present = env.iter().any(|(k, _)| k == &g.var);
    present != g.negate
}

fn uri_tests_match(tests: &[crate::htaccess::UriCond], path: &str, on_err: bool) -> bool {
    tests.iter().all(|test| match &test.regex {
        Some(re) => match re.is_match(path) {
            Ok(m) => m != test.negate,
            Err(_) => on_err,
        },
        None => true,
    })
}

/// Does the conjunction of enclosing scopes (`<Files*>`/`<DirectoryMatch>`/`<If>`)
/// match? An empty slice = directory-wide -> always matches; otherwise EVERY
/// scope must match (the AND that `record_access_rule` already applies to access
/// rules), so an outer `<If>`/`<Directory>` guard around an inner `<Files>` is
/// honored rather than silently dropped.
pub(crate) fn scopes_match(scopes: &[Scope], rel_path: &str, basename: &str) -> bool {
    scopes.iter().all(|s| scope_matches(s, rel_path, basename))
}

/// Does a single scope match? A `<Files*>`/`<Directory*>` block whose pattern did
/// not compile (`regex == None`) does NOT match (fail-closed — the directive does
/// not apply rather than widening to the whole directory); an unmodellable `<If>`
/// matches (lenient superset, as headers are not security-critical).
fn scope_matches(scope: &Scope, rel_path: &str, basename: &str) -> bool {
    match scope.kind {
        ScopeKind::Files | ScopeKind::FilesMatch => scope
            .regex
            .as_ref()
            .is_some_and(|re| re.is_match(basename).unwrap_or(false)),
        ScopeKind::DirectoryMatch | ScopeKind::Directory => scope
            .regex
            .as_ref()
            .is_some_and(|re| re.is_match(rel_path).unwrap_or(false)),
        // `<If "%{REQUEST_URI} =~ m#...#">` — evaluate the parsed boolean expression.
        // If we could not understand it, conservatively apply the header (headers are not
        // security-critical, so a superset is acceptable).
        ScopeKind::If => scope
            .uri_expr
            .as_ref()
            .map_or(true, |expr| expr.matches(rel_path, false)),
    }
}

/// Expand `%{NAME}e` references in `value` from `env`. Unknown names expand to
/// the empty string (Apache behavior). A literal `%` not part of `%{...}` is
/// passed through unchanged. Also accepts `%{NAME}` without the trailing `e`
/// (some configs omit it) — both forms resolve from the same env map.
fn interpolate_env(value: &str, env: &[(String, String)]) -> String {
    if !value.contains("%{") {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(close) = value[i + 2..].find('}') {
                let name = &value[i + 2..i + 2 + close];
                let mut after = i + 2 + close + 1;
                // Optional trailing `e` (environment) qualifier. Because we also accept
                // the bare `%{NAME}` form, a following `e` is ambiguous; only treat it as
                // the qualifier when it is NOT the first letter of a following word (i.e.
                // it is the last char or precedes a non-alphanumeric). This keeps the
                // canonical `%{VAR}e` / `%{VAR}e/path` stripping the qualifier while
                // `%{VAR}extra` no longer silently drops the leading `e` of `extra`.
                if after < bytes.len()
                    && bytes[after] == b'e'
                    && !bytes
                        .get(after + 1)
                        .is_some_and(|b| b.is_ascii_alphanumeric())
                {
                    after += 1;
                }
                let val = env
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                out.push_str(val);
                i = after;
                continue;
            }
        }
        // Not a recognized token; copy this codepoint (UTF-8 safe).
        let ch_len = utf8_len(bytes[i]);
        out.push_str(&value[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        b if b < 0x80 => 1,
        b if b >> 5 == 0b110 => 2,
        b if b >> 4 == 0b1110 => 3,
        _ => 4,
    }
}

// ===========================================================================
// 3. ERROR DOCUMENTS  (requirement #8a)
// ===========================================================================

/// A resolved `ErrorDocument code <target>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorDoc {
    /// `ErrorDocument 404 /404.php` — an internal path (served from docroot).
    Path(String),
    /// `ErrorDocument 404 "Sorry, not here"` — an inline message (Apache marks
    /// these with a leading quote that is stripped here).
    Inline(String),
    /// `ErrorDocument 404 https://...` — an external redirect target.
    External(String),
}

impl ErrorDoc {
    /// Classify a raw `ErrorDocument` target string the way Apache does:
    /// a leading `"` => inline message; an absolute `http(s)://` (or `//`)
    /// URL => external; otherwise a local path.
    pub fn classify(raw: &str) -> ErrorDoc {
        if let Some(rest) = raw.strip_prefix('"') {
            // Apache: a leading quote introduces a literal text message. The
            // trailing quote (if any) is not required; strip a matching one.
            let msg = rest.strip_suffix('"').unwrap_or(rest);
            return ErrorDoc::Inline(msg.to_string());
        }
        let lower = raw.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") || raw.starts_with("//") {
            ErrorDoc::External(raw.to_string())
        } else {
            ErrorDoc::Path(raw.to_string())
        }
    }
}

impl Htaccess {
    /// The `ErrorDocument` registered for `status`, if any.
    pub fn error_document(&self, status: u16) -> Option<&ErrorDoc> {
        self.error_docs.get(&status)
    }
}

// ===========================================================================
// 4. SETENVIF  (requirement #8b)
// ===========================================================================

/// The request attributes [`Htaccess::eval_set_env`] reads. Apache's `SetEnvIf`
/// first argument is an attribute name (a small set of specials) or a request
/// *header* name; this struct supplies the specials, and arbitrary headers come
/// from `headers`. All fields are borrowed so the pipeline pays nothing to
/// construct it per request.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReqAttrs<'a> {
    /// `Request_URI` — the path (no query), e.g. `/api/x.php`.
    pub request_uri: &'a str,
    /// `Request_Method` — upper-case method.
    pub method: &'a str,
    /// `Request_Protocol` — e.g. `HTTP/1.1`.
    pub protocol: &'a str,
    /// `Query_String` — query without leading `?`.
    pub query_string: &'a str,
    /// `Remote_Addr` — client IP.
    pub remote_addr: &'a str,
    /// `Server_Addr` — local bind address.
    pub server_addr: &'a str,
    /// `Host` (also matched by a literal `Host` attribute and `Server_Name`).
    pub host: &'a str,
    /// Lazy request-header source (e.g. `Origin`, `User-Agent`, `Referer`). A callback
    /// rather than a materialized map, so the caller pays nothing to snapshot the whole
    /// header set — `SetEnvIf` only ever looks up the specific names its rules reference.
    /// `lookup_header` folds `-`/`_` to equivalent (so `User_Agent` ~ `User-Agent`) and the
    /// callback itself matches names ASCII-case-insensitively. `None` ⇒ no headers (all
    /// header lookups miss); the specials above are always available.
    pub header_lookup: Option<HeaderLookup<'a>>,
}

impl<'a> ReqAttrs<'a> {
    /// Resolve `SetEnvIf`'s first argument to the string to test. Returns `None`
    /// for attributes we do not model (the directive is then skipped, matching
    /// Apache testing an empty/absent value: a regex that requires content
    /// simply won't match).
    fn resolve(&self, attribute: &str) -> Option<Cow<'a, str>> {
        // Compare case-insensitively against the modelled specials WITHOUT allocating a
        // lowercased copy per SetEnvIf rule per request (L4). `lookup_header` is itself
        // case-insensitive (and folds `_`→`-`), so the un-lowercased name resolves identically.
        let eq = |s: &str| attribute.eq_ignore_ascii_case(s);
        if eq("request_uri") {
            Some(Cow::Borrowed(self.request_uri))
        } else if eq("request_method") {
            Some(Cow::Borrowed(self.method))
        } else if eq("request_protocol") {
            Some(Cow::Borrowed(self.protocol))
        } else if eq("query_string") {
            Some(Cow::Borrowed(self.query_string))
        } else if eq("remote_addr") {
            Some(Cow::Borrowed(self.remote_addr))
        } else if eq("server_addr") {
            Some(Cow::Borrowed(self.server_addr))
        } else if eq("host") || eq("server_name") {
            Some(Cow::Borrowed(self.host))
        } else {
            self.lookup_header(attribute).map(Cow::Owned)
        }
    }

    fn lookup_header(&self, want: &str) -> Option<String> {
        let hl = self.header_lookup.as_ref()?;
        // SetEnvIf matches `_` and `-` equivalently; fold to dash form before the (case-
        // insensitive) callback so `User_Agent` resolves the `User-Agent` header. Only
        // allocate the folded copy when an underscore is actually present — without one
        // the fold is a no-op, so the borrowed name resolves identically (byte-for-byte).
        if want.contains('_') {
            let folded: String = want
                .chars()
                .map(|c| if c == '_' { '-' } else { c })
                .collect();
            (hl.0)(&folded)
        } else {
            (hl.0)(want)
        }
    }
}

impl Htaccess {
    /// Evaluate all `SetEnvIf` / `SetEnvIfNoCase` directives against `attrs`,
    /// returning the `(VAR, value)` pairs to merge into the request env.
    ///
    /// Per Apache: the directive's value template may reference `$0`..`$9`
    /// (whole-match / capture groups of the matching regex). `SetEnvIf Foo re
    /// VAR` with no `=value` sets `VAR=1`; `VAR=val` sets the literal (after
    /// backref expansion). `!VAR` (unset) is not modelled — it is rare and the
    /// pipeline merges, so we only emit sets.
    ///
    /// Directives are applied in source order; a later set for the same `VAR`
    /// overrides an earlier one (the caller should let later entries win, e.g.
    /// by inserting into a map in order).
    pub fn eval_set_env(&self, attrs: &ReqAttrs<'_>) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for s in &self.set_env_if {
            let Some(subject) = attrs.resolve(&s.attribute) else {
                continue;
            };
            // (#312) Literal-prefix prefilter (fail open): a ^-anchored pattern's
            // leading literal run must be a prefix of the subject.
            if !s.literal_prefix.is_empty()
                && !subject
                    .as_ref()
                    .as_bytes()
                    .starts_with(s.literal_prefix.as_ref())
            {
                continue;
            }
            if let Ok(Some(caps)) = s.regex.captures(subject.as_ref()) {
                let value = expand_backrefs(&s.value, &caps);
                out.push((s.var.clone(), value));
            }
        }
        out
    }
}

/// Expand `$0`..`$9` in a `SetEnvIf` value template from regex captures.
/// Unknown / absent groups expand to empty. `$$` is a literal `$`.
fn expand_backrefs(template: &str, caps: &fancy_regex::Captures<'_, str>) -> String {
    if !template.contains('$') {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            match chars.peek() {
                Some('$') => {
                    out.push('$');
                    chars.next();
                }
                Some(d) if d.is_ascii_digit() => {
                    let idx = (*d as u8 - b'0') as usize;
                    chars.next();
                    if let Some(m) = caps.get(idx) {
                        out.push_str(m.as_str());
                    }
                }
                _ => out.push('$'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ===========================================================================
// Small helpers
// ===========================================================================

/// Final path segment of `rel_path` (the basename). For `/` or a trailing
/// slash the basename is empty.
fn basename(rel_path: &str) -> &str {
    match rel_path.rsplit_once('/') {
        Some((_, last)) => last,
        None => rel_path,
    }
}

/// The lowercased file extension of `basename` (the text after the last `.`), for
/// the scope index's `suffix` lookup. Borrows when already lowercase (the common
/// case) so the hot path stays allocation-free. `""` when there is no dot.
/// Note: a dotfile like `.env` yields `env` — harmless, since the exact bucket
/// (keyed by the full basename) carries the authoritative match and the suffix
/// bucket is only ever a superset.
fn ext_lower(basename: &str) -> std::borrow::Cow<'_, str> {
    match basename.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() => {
            if ext.bytes().any(|b| b.is_ascii_uppercase()) {
                std::borrow::Cow::Owned(ext.to_ascii_lowercase())
            } else {
                std::borrow::Cow::Borrowed(ext)
            }
        }
        _ => std::borrow::Cow::Borrowed(""),
    }
}

#[cfg(test)]
mod directive_tests {
    use super::*;
    use crate::Htaccess;

    /// A case-insensitive header lookup closure over a `(name, value)` slice — the test analogue
    /// of the production `req.headers()` callback. Bind it to a `let` so the `&` lives long enough
    /// for `HeaderLookup`. (`lookup_header` folds `_`→`-` before calling this, mirroring prod.)
    fn lookup_from(headers: &[(String, String)]) -> impl Fn(&str) -> Option<String> + '_ {
        move |n: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.clone())
        }
    }

    #[test]
    fn access_files_glob_log_denies_dotlog_not_xlog() {
        // <Files "*.log"> must deny `x.log` but NOT `xlog` (fnmatch, not regex).
        let h = Htaccess::parse("<Files \"*.log\">\n  Require all denied\n</Files>").unwrap();
        assert_eq!(
            h.access_decision("/dir/x.log", "GET"),
            AccessDecision::Denied
        );
        assert_eq!(
            h.access_decision("/dir/error.log", "GET"),
            AccessDecision::Denied
        );
        // `xlog` is NOT `*.log` under fnmatch glob.
        assert_eq!(
            h.access_decision("/dir/xlog", "GET"),
            AccessDecision::NoOpinion
        );
    }

    #[test]
    fn access_files_literal_exact_match() {
        let h = Htaccess::parse("<Files \"robots.txt\">\n  Require all granted\n</Files>").unwrap();
        assert_eq!(
            h.access_decision("/robots.txt", "GET"),
            AccessDecision::Granted
        );
        // A different basename containing the literal is not matched.
        assert_eq!(
            h.access_decision("/x-robots.txt", "GET"),
            AccessDecision::NoOpinion
        );
    }

    #[test]
    fn access_filesmatch_regex() {
        // <FilesMatch> uses regex against the basename.
        let h =
            Htaccess::parse("<FilesMatch \"\\.(sql|bak)$\">\n  Require all denied\n</FilesMatch>")
                .unwrap();
        assert_eq!(
            h.access_decision("/db/dump.sql", "POST"),
            AccessDecision::Denied
        );
        assert_eq!(
            h.access_decision("/db/dump.bak", "GET"),
            AccessDecision::Denied
        );
        assert_eq!(
            h.access_decision("/db/dump.txt", "GET"),
            AccessDecision::NoOpinion
        );
    }

    #[test]
    fn access_require_all_granted_overrides_earlier_deny() {
        // Source order: a later granted section for the same target wins.
        let h = Htaccess::parse(
            "<FilesMatch \"\\.txt$\">\n  Require all denied\n</FilesMatch>\n\
             <Files \"robots.txt\">\n  Require all granted\n</Files>",
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
    fn access_directory_match_uses_path() {
        let h = Htaccess::parse(
            "<DirectoryMatch \"(^|/)(\\.git|node_modules)$\">\n  Require all denied\n</DirectoryMatch>",
        )
        .unwrap();
        assert_eq!(
            h.access_decision("/app/node_modules", "GET"),
            AccessDecision::Denied
        );
        assert_eq!(
            h.access_decision("/app/public", "GET"),
            AccessDecision::NoOpinion
        );
    }

    // --- #4: top-level (no enclosing section) Deny from all / Require all denied ---

    #[test]
    fn access_top_level_deny_from_all_blocks_everything() {
        // The XenForo library/internal_data idiom: a bare directory-wide deny.
        let h = Htaccess::parse("Order deny,allow\nDeny from all").unwrap();
        assert_eq!(
            h.access_decision("/anything", "GET"),
            AccessDecision::Denied
        );
        assert_eq!(
            h.access_decision("/sub/file.php", "POST"),
            AccessDecision::Denied
        );
        assert!(h.is_forbidden("/x/y/z", "z"));
    }

    #[test]
    fn access_top_level_require_all_denied_blocks_everything() {
        let h = Htaccess::parse("Require all denied").unwrap();
        assert_eq!(
            h.access_decision("/whatever.txt", "GET"),
            AccessDecision::Denied
        );
    }

    #[test]
    fn access_top_level_allow_from_all_grants() {
        let h = Htaccess::parse("Allow from all").unwrap();
        assert_eq!(h.access_decision("/x", "GET"), AccessDecision::Granted);
    }

    // --- #2: Require ip / valid-user / user / group are restrictions (fail-closed) ---

    #[test]
    fn access_require_ip_is_fail_closed_deny() {
        // `<Files "admin.php"> Require ip 192.168.0.0/16` must RESTRICT, not open.
        let h = Htaccess::parse("<Files \"admin.php\">\n  Require ip 192.168.0.0/16\n</Files>")
            .unwrap();
        assert_eq!(
            h.access_decision("/admin.php", "GET"),
            AccessDecision::Denied
        );
        // Unrelated files are untouched.
        assert_eq!(
            h.access_decision("/index.php", "GET"),
            AccessDecision::NoOpinion
        );
    }

    #[test]
    fn access_require_valid_user_user_group_fail_closed() {
        for predicate in [
            "valid-user",
            "user alice",
            "group admins",
            "host example.com",
        ] {
            let h = Htaccess::parse(&format!(
                "<FilesMatch \"\\.secret$\">\n  Require {predicate}\n</FilesMatch>"
            ))
            .unwrap();
            assert_eq!(
                h.access_decision("/data/x.secret", "GET"),
                AccessDecision::Denied,
                "Require {predicate} must fail closed"
            );
        }
    }

    #[test]
    fn access_require_all_granted_still_opens() {
        // An explicit grant must NOT be caught by the fail-closed default.
        let h = Htaccess::parse("<Files \"public.txt\">\n  Require all granted\n</Files>").unwrap();
        assert_eq!(
            h.access_decision("/public.txt", "GET"),
            AccessDecision::Granted
        );
    }

    // --- #5: Require all denied nested inside <If> (within Files*/Directory* or top-level) ---

    #[test]
    fn access_require_denied_inside_if_within_filesmatch() {
        // news dot-file guard: deny dot-files EXCEPT under /.well-known/.
        let h = Htaccess::parse(
            "<FilesMatch \"^\\..*\">\n  <If \"%{REQUEST_URI} !~ m#^/\\.well-known/#\">\n    Require all denied\n  </If>\n</FilesMatch>",
        )
        .unwrap();
        // A dot-file outside /.well-known/ -> denied (the !~ condition holds).
        assert_eq!(h.access_decision("/.env", "GET"), AccessDecision::Denied);
        // A dot-file UNDER /.well-known/ -> the negated condition fails -> allowed.
        assert_eq!(
            h.access_decision("/.well-known/acme-challenge/.x", "GET"),
            AccessDecision::NoOpinion
        );
        // A non-dot file -> the FilesMatch basename scope does not match.
        assert_eq!(
            h.access_decision("/index.php", "GET"),
            AccessDecision::NoOpinion
        );
    }

    #[test]
    fn access_require_denied_standalone_if() {
        // news standalone dot guard: `<If "%{REQUEST_URI} =~ m#(^|/)\.# && ...">`.
        let h = Htaccess::parse(
            "<If \"%{REQUEST_URI} =~ m#(^|/)\\.# && %{REQUEST_URI} !~ m#^/\\.well-known/#\">\n  Require all denied\n</If>",
        )
        .unwrap();
        assert_eq!(h.access_decision("/.env", "GET"), AccessDecision::Denied);
        assert_eq!(
            h.access_decision("/secret/.git", "GET"),
            AccessDecision::Denied
        );
        assert_eq!(
            h.access_decision("/.well-known/acme-challenge/.token", "GET"),
            AccessDecision::NoOpinion
        );
        // A normal path with no dot segment is untouched.
        assert_eq!(
            h.access_decision("/threads/123", "GET"),
            AccessDecision::NoOpinion
        );
    }

    #[test]
    fn access_uncompilable_section_pattern_does_not_deny_whole_directory() {
        // A <FilesMatch> whose regex fails to compile must NOT collapse into a
        // directory-wide deny (that would 403 every file). It is dropped.
        let h =
            Htaccess::parse("<FilesMatch \"[unterminated\">\n  Require all denied\n</FilesMatch>")
                .unwrap();
        assert_eq!(
            h.access_decision("/anything.txt", "GET"),
            AccessDecision::NoOpinion
        );
    }

    #[test]
    fn access_require_denied_inside_if_within_directorymatch() {
        let h = Htaccess::parse(
            "<DirectoryMatch \"(^|/)secret(/|$)\">\n  <If \"%{REQUEST_URI} =~ m#\\.git#\">\n    Require all denied\n  </If>\n</DirectoryMatch>",
        )
        .unwrap();
        // Both the DirectoryMatch path scope AND the If URI condition hold.
        assert_eq!(
            h.access_decision("/secret/.git/config", "GET"),
            AccessDecision::Denied
        );
        // DirectoryMatch matches but the If condition (.git) does not.
        assert_eq!(
            h.access_decision("/secret/readme.txt", "GET"),
            AccessDecision::NoOpinion
        );
    }

    // --- Headers ---

    #[test]
    fn header_set_with_env_interpolation() {
        // Header set with %{VAR}e interpolation from the env map.
        let h =
            Htaccess::parse("Header always set Access-Control-Allow-Origin \"%{ORIGIN_ALLOWED}e\"")
                .unwrap();
        let env = vec![(
            "ORIGIN_ALLOWED".to_string(),
            "https://forum.example".to_string(),
        )];
        let ops = h.response_headers("/api/x.php", 200, &env);
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            HeaderOp::Set {
                name: "Access-Control-Allow-Origin".to_string(),
                value: "https://forum.example".to_string(),
            }
        );
    }

    #[test]
    fn header_unknown_env_var_interpolates_empty() {
        let h = Htaccess::parse("Header set X-Test \"v=%{MISSING}e\"").unwrap();
        let ops = h.response_headers("/x", 200, &[]);
        assert_eq!(
            ops[0],
            HeaderOp::Set {
                name: "X-Test".into(),
                value: "v=".into()
            }
        );
    }

    #[test]
    fn header_onsuccess_skipped_on_error_status() {
        // Without `always`, the op only fires for 2xx/3xx.
        let h = Htaccess::parse("Header set X-Cache HIT").unwrap();
        assert!(h.response_headers("/x", 200, &[]).len() == 1);
        assert!(h.response_headers("/x", 500, &[]).is_empty());
        // `always` fires even on 500.
        let ha = Htaccess::parse("Header always set X-Always 1").unwrap();
        assert_eq!(ha.response_headers("/x", 500, &[]).len(), 1);
    }

    #[test]
    fn header_env_guard_present_and_negated() {
        let h = Htaccess::parse(
            "Header set Cache-Control no-cache env=NEWS_API_CC\n\
             Header set X-Off 1 env=!SOMEFLAG",
        )
        .unwrap();
        // NEWS_API_CC present -> first applies; SOMEFLAG absent -> second applies.
        let env = vec![("NEWS_API_CC".to_string(), "1".to_string())];
        let ops = h.response_headers("/api/x.php", 200, &env);
        assert!(ops.iter().any(|o| o.name() == "Cache-Control"));
        assert!(ops.iter().any(|o| o.name() == "X-Off"));
        // With SOMEFLAG present, the negated guard fails.
        let env2 = vec![("SOMEFLAG".to_string(), "1".to_string())];
        let ops2 = h.response_headers("/api/x.php", 200, &env2);
        assert!(!ops2.iter().any(|o| o.name() == "X-Off"));
        assert!(!ops2.iter().any(|o| o.name() == "Cache-Control"));
    }

    #[test]
    fn header_scoped_to_filesmatch() {
        // The Header inside <FilesMatch "\.php$"> applies only to .php paths.
        let h = Htaccess::parse(
            "<FilesMatch \"\\.php$\">\n  Header set X-PHP 1\n</FilesMatch>\n\
             Header set X-Global 1",
        )
        .unwrap();
        let php = h.response_headers("/index.php", 200, &[]);
        assert!(php.iter().any(|o| o.name() == "X-PHP"));
        assert!(php.iter().any(|o| o.name() == "X-Global"));
        let css = h.response_headers("/style.css", 200, &[]);
        assert!(!css.iter().any(|o| o.name() == "X-PHP"));
        assert!(css.iter().any(|o| o.name() == "X-Global"));
    }

    #[test]
    fn header_scoped_to_if_request_uri() {
        // <If "%{REQUEST_URI} =~ m#^/api/#"> Header ... applies only under /api/.
        let h =
            Htaccess::parse("<If \"%{REQUEST_URI} =~ m#^/api/#\">\n  Header set X-Api 1\n</If>")
                .unwrap();
        assert!(
            h.response_headers("/api/x.php", 200, &[])
                .iter()
                .any(|o| o.name() == "X-Api")
        );
        assert!(h.response_headers("/other/x.php", 200, &[]).is_empty());
    }

    #[test]
    fn header_scoped_to_if_uri_or_expression() {
        let h = Htaccess::parse(
            "<If \"%{REQUEST_URI} =~ m#^/api/# || %{REQUEST_URI} =~ m#^/feed/#\">\n  Header set X-Route 1\n</If>",
        )
        .unwrap();
        assert!(
            h.response_headers("/api/x", 200, &[])
                .iter()
                .any(|o| o.name() == "X-Route")
        );
        assert!(
            h.response_headers("/feed/x", 200, &[])
                .iter()
                .any(|o| o.name() == "X-Route")
        );
        assert!(h.response_headers("/other/x", 200, &[]).is_empty());
    }

    #[test]
    fn header_nested_if_files_scope_honors_both() {
        // A Header under `<If ^/api/><FilesMatch \.php$>` must require BOTH the
        // outer `<If>` (URI) AND the inner `<FilesMatch>` (basename) — the old
        // innermost-only scope dropped the `<If>` and leaked it to /other/x.php.
        let h = Htaccess::parse(
            "<If \"%{REQUEST_URI} =~ m#^/api/#\">\n  \
             <FilesMatch \"\\.php$\">\n    Header set X-Api 1\n  \
             </FilesMatch>\n</If>",
        )
        .unwrap();
        // under /api/ AND a .php basename -> applies.
        assert!(
            h.response_headers("/api/x.php", 200, &[])
                .iter()
                .any(|o| o.name() == "X-Api")
        );
        // .php basename but NOT under /api/ -> the outer `<If>` fails -> no header.
        assert!(h.response_headers("/other/x.php", 200, &[]).is_empty());
        // under /api/ but not a .php basename -> the inner `<FilesMatch>` fails.
        assert!(h.response_headers("/api/style.css", 200, &[]).is_empty());
    }

    #[test]
    fn header_expr_request_uri_guard_uses_request_path() {
        let h = Htaccess::parse("Header set X-Home 1 \"expr=%{REQUEST_URI} =~ m#^/$#\"").unwrap();
        assert!(
            h.response_headers_for_request("/index.php", "/", 200, &[])
                .iter()
                .any(|o| o.name() == "X-Home")
        );
        assert!(
            h.response_headers_for_request("/index.php", "/threads/123", 200, &[])
                .is_empty()
        );
    }

    #[test]
    fn directory_index_is_recorded() {
        let h = Htaccess::parse("DirectoryIndex feed.php index.php index.html").unwrap();
        assert_eq!(
            h.directory_index,
            vec![
                "feed.php".to_string(),
                "index.php".to_string(),
                "index.html".to_string()
            ]
        );
    }

    #[test]
    fn header_unset_and_append_actions() {
        let h = Htaccess::parse("Header unset Server\nHeader append Vary Accept-Encoding").unwrap();
        let ops = h.response_headers("/x", 200, &[]);
        assert!(ops.contains(&HeaderOp::Unset {
            name: "Server".into()
        }));
        assert!(ops.contains(&HeaderOp::Append {
            name: "Vary".into(),
            value: "Accept-Encoding".into(),
        }));
    }

    // --- ErrorDocument ---

    #[test]
    fn error_document_path_inline_external() {
        let h = Htaccess::parse(
            "ErrorDocument 404 /404.php\n\
             ErrorDocument 403 \"Forbidden, go away\"\n\
             ErrorDocument 500 https://errors.example.com/500",
        )
        .unwrap();
        assert_eq!(
            h.error_document(404),
            Some(&ErrorDoc::Path("/404.php".into()))
        );
        assert_eq!(
            h.error_document(403),
            Some(&ErrorDoc::Inline("Forbidden, go away".into()))
        );
        assert_eq!(
            h.error_document(500),
            Some(&ErrorDoc::External("https://errors.example.com/500".into()))
        );
        assert_eq!(h.error_document(418), None);
    }

    // --- SetEnvIf ---

    #[test]
    fn set_env_if_sets_var_with_backref() {
        // SetEnvIf Origin "^https://(forum\.example)$" ORIGIN_ALLOWED=$0
        let h = Htaccess::parse(
            "SetEnvIf Origin \"^https://(forum\\.example|news\\.forum\\.example)$\" ORIGIN_ALLOWED=$0",
        )
        .unwrap();
        let headers = vec![("Origin".to_string(), "https://forum.example".to_string())];
        let lk = lookup_from(&headers);
        let attrs = ReqAttrs {
            header_lookup: Some(HeaderLookup(&lk)),
            ..Default::default()
        };
        let env = h.eval_set_env(&attrs);
        assert_eq!(
            env,
            vec![(
                "ORIGIN_ALLOWED".to_string(),
                "https://forum.example".to_string()
            )]
        );
        // A disallowed origin sets nothing.
        let bad = vec![("Origin".to_string(), "https://evil.example.com".to_string())];
        let lk_bad = lookup_from(&bad);
        let attrs_bad = ReqAttrs {
            header_lookup: Some(HeaderLookup(&lk_bad)),
            ..Default::default()
        };
        assert!(h.eval_set_env(&attrs_bad).is_empty());
    }

    #[test]
    fn set_env_if_request_uri_defaults_value_to_one() {
        // SetEnvIf Request_URI "..." NEWS_API_CC=1  (and a no-value form -> "1")
        let h = Htaccess::parse(
            "SetEnvIf Request_URI \"^/(api|rss)/.*\\.php(\\?|$)\" NEWS_API_CC=1\n\
             SetEnvIf Query_String \"(^|&)amp=1(&|$)\" AMP_PAGE",
        )
        .unwrap();
        let attrs = ReqAttrs {
            request_uri: "/api/feed.php",
            query_string: "amp=1&x=2",
            ..Default::default()
        };
        let env = h.eval_set_env(&attrs);
        assert!(env.contains(&("NEWS_API_CC".to_string(), "1".to_string())));
        assert!(env.contains(&("AMP_PAGE".to_string(), "1".to_string())));
        // Non-matching URI -> NEWS_API_CC not set.
        let attrs2 = ReqAttrs {
            request_uri: "/page.html",
            ..Default::default()
        };
        assert!(
            !h.eval_set_env(&attrs2)
                .iter()
                .any(|(k, _)| k == "NEWS_API_CC")
        );
    }

    #[test]
    fn set_env_if_nocase_and_header_underscore_folding() {
        // SetEnvIfNoCase User-Agent ... matches case-insensitively; the attribute
        // `User_Agent` must resolve the `User-Agent` header (underscore folding).
        let h = Htaccess::parse("SetEnvIfNoCase User_Agent \"bot\" IS_BOT=1").unwrap();
        let headers = vec![(
            "User-Agent".to_string(),
            "Mozilla GoogleBOT/2.1".to_string(),
        )];
        let lk = lookup_from(&headers);
        let attrs = ReqAttrs {
            header_lookup: Some(HeaderLookup(&lk)),
            ..Default::default()
        };
        assert_eq!(
            h.eval_set_env(&attrs),
            vec![("IS_BOT".to_string(), "1".to_string())]
        );
    }

    // --- end-to-end: CORS shape (SetEnvIf -> Header %{VAR}e) ---

    #[test]
    fn cors_setenvif_then_header_interpolation() {
        let h = Htaccess::parse(
            "SetEnvIf Origin \"^https://(forum\\.example)$\" ORIGIN_ALLOWED=$0\n\
             Header always set Access-Control-Allow-Origin \"%{ORIGIN_ALLOWED}e\" env=ORIGIN_ALLOWED",
        )
        .unwrap();
        let headers = vec![("Origin".to_string(), "https://forum.example".to_string())];
        let lk = lookup_from(&headers);
        let attrs = ReqAttrs {
            header_lookup: Some(HeaderLookup(&lk)),
            ..Default::default()
        };
        let env = h.eval_set_env(&attrs);
        let ops = h.response_headers("/api/x.php", 200, &env);
        assert_eq!(
            ops[0],
            HeaderOp::Set {
                name: "Access-Control-Allow-Origin".to_string(),
                value: "https://forum.example".to_string(),
            }
        );
        // No allowed origin -> SetEnvIf sets nothing -> env guard fails -> no header.
        let bad = vec![("Origin".to_string(), "https://evil.com".to_string())];
        let lk_bad = lookup_from(&bad);
        let attrs_bad = ReqAttrs {
            header_lookup: Some(HeaderLookup(&lk_bad)),
            ..Default::default()
        };
        let env_bad = h.eval_set_env(&attrs_bad);
        assert!(h.response_headers("/api/x.php", 200, &env_bad).is_empty());
    }

    #[test]
    fn interpolate_env_e_qualifier_vs_literal_e() {
        let env = vec![("VAR".to_string(), "val".to_string())];
        // Canonical `%{VAR}e` qualifier at end of string -> stripped.
        assert_eq!(interpolate_env("%{VAR}e", &env), "val");
        // `e` qualifier before a non-alphanumeric -> stripped.
        assert_eq!(interpolate_env("%{VAR}e/path", &env), "val/path");
        // Bare `%{VAR}` (lenient form) -> resolved, nothing to strip.
        assert_eq!(interpolate_env("%{VAR}", &env), "val");
        // `%{VAR}` abutting a literal word starting with `e` must NOT lose the `e`.
        assert_eq!(interpolate_env("%{VAR}extra", &env), "valextra");
        // Unknown name -> empty (Apache behavior); literal text preserved.
        assert_eq!(interpolate_env("[%{MISSING}e]", &env), "[]");
        // A bare `%` not part of `%{...}` is passed through.
        assert_eq!(interpolate_env("100% %{VAR}", &env), "100% val");
    }
}
