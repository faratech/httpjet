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
//! * Access merges in Apache's section order, later wins within a phase: see
//!   [`Htaccess::access_decision`].
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
    /// Rules merge in Apache's order — directory-level (including `<Limit>`
    /// method filters), then `<Files*>`, then `<If>`/`<Else>` — and within a
    /// phase a later matching rule wins.
    pub fn access_decision(&self, rel_path: &str, method: &str) -> AccessDecision {
        // Standalone convenience check: incomplete auth cannot be satisfied.
        // The pipeline uses access_decision_for for host ACLs and separately
        // resolves auth across the full inherited chain before any handler.
        if self.has_auth()
            && crate::htaccess::resolve_auth(std::iter::once(self), rel_path).is_err()
        {
            return AccessDecision::Denied;
        }
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
        self.access_decision_for_request(rel_path, rel_path, method, subject)
    }

    /// [`Htaccess::access_decision_for`] with a separate `request_path` for the
    /// `<If "%{REQUEST_URI} …">` matchers: `REQUEST_URI` keeps its trailing `/`,
    /// which `rel_path` (the `<Files*>`/`<Directory*>` subject) drops.
    pub fn access_decision_for_request(
        &self,
        rel_path: &str,
        request_path: &str,
        method: &str,
        subject: &AccessSubject<'_>,
    ) -> AccessDecision {
        if self.access_rules.is_empty() {
            return AccessDecision::NoOpinion;
        }
        let basename = basename(rel_path);
        let ext = ext_lower(basename);
        let mut decision = AccessDecision::NoOpinion;
        let mut winner_phase = 0;
        // The `access_rules` model is authoritative: it carries directory-wide
        // rules (top-level `Deny from all`, #4), `<If>`-scoped rules (#5), and
        // fail-closed unrecognized `Require` predicates (#2) — none of which the
        // flat `access` section list can represent. The `access_index` narrows the
        // scan to rules whose scope could match (a pure superset filter); the
        // matcher below is still the arbiter, and candidates arrive in ascending
        // source order so "later wins" is preserved.
        // Source-order winner among directory-level (phase 0) rules, and whether it
        // is an httpjet `<Directory*>` deny.
        let mut directory_deny = false;
        let scan = || -> Vec<usize> {
            self.access_index
                .candidates(basename, &ext)
                .filter(|&i| {
                    self.access_rules
                        .get(i)
                        .is_some_and(|r| r.matches(rel_path, request_path, basename, method))
                })
                .collect()
        };
        let mut visit = |i: usize| {
            let Some(rule) = self.access_rules.get(i) else {
                return;
            };
            let phase = rule.merge_phase();
            let denies = rule.denies(subject, method);
            if phase == 0 {
                directory_deny = denies && rule.is_directory_scoped();
            }
            if phase >= winner_phase {
                winner_phase = phase;
                decision = if denies {
                    AccessDecision::Denied
                } else {
                    AccessDecision::Granted
                };
            }
        };
        // Which rules MATCH is a pure function of the paths and method, memoized per
        // parsed file; the subject-dependent verdict is still evaluated on every call.
        // Rules with nothing but `<Limit>` methods match in less than a memo probe.
        let memo = self
            .access_memo_useful
            .then(|| {
                self.access_memo.matched(
                    rel_path,
                    request_path,
                    method,
                    self.access_rules.len(),
                    || scan(),
                )
            })
            .flatten();
        match memo {
            Some(hit) => hit.iter().for_each(|&i| visit(usize::from(i))),
            None => scan().into_iter().for_each(visit),
        }
        // A `<Files>`/`<If>` grant must not open a sensitive directory denied by a
        // `<Directory*>` matcher (no Apache .htaccess analogue; the live forum file
        // relies on it, e.g. `<Files auth.md>` grant vs a later backups/ deny).
        if directory_deny && decision == AccessDecision::Granted && winner_phase > 0 {
            return AccessDecision::Denied;
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
/// * [`HeaderOp::Merge`] — like `Append`, but a no-op when `value` already is one
///   of the existing comma-separated values (Apache `Header merge`).
///
/// `echo`/`note` forms are dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderOp {
    Set { name: String, value: String },
    Add { name: String, value: String },
    Append { name: String, value: String },
    Merge { name: String, value: String },
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
            | HeaderOp::Merge { name, .. }
            | HeaderOp::Unset { name }
            | HeaderOp::Edit { name, .. } => name,
        }
    }
}

/// The action of a [`PreparedHeaderOp`], with [`HeaderOp`]'s merge semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderOpKind {
    Set,
    Add,
    Append,
    Merge,
    Unset,
}

/// A [`HeaderOp`] borrowing the field name and, for a value without `%{VAR}`, the
/// field value built once at parse time. An op whose name is not a valid field
/// name is never produced (applying it cannot change a response).
#[derive(Debug, Clone)]
pub struct PreparedHeaderOp<'a> {
    pub kind: HeaderOpKind,
    pub name: &'a http::HeaderName,
    /// The interpolated value (empty for [`HeaderOpKind::Unset`]).
    pub value: Cow<'a, str>,
    /// `value` as a field value, when it is static and valid.
    pub field_value: Option<&'a http::HeaderValue>,
}

impl HeaderAction {
    fn op_kind(self) -> Option<HeaderOpKind> {
        match self {
            HeaderAction::Set => Some(HeaderOpKind::Set),
            HeaderAction::Add => Some(HeaderOpKind::Add),
            HeaderAction::Append => Some(HeaderOpKind::Append),
            HeaderAction::Merge => Some(HeaderOpKind::Merge),
            HeaderAction::Unset => Some(HeaderOpKind::Unset),
            // `Header echo Foo` mirrors a *request* header into the response; it has
            // no static value, so it is skipped (rare; not in the live config).
            HeaderAction::Echo => None,
        }
    }
}

/// One staged op: merge phase, kind, the directive, its interpolated value.
type StagedHeader<'a> = (
    u8,
    HeaderOpKind,
    &'a crate::htaccess::HeaderDirective,
    Cow<'a, str>,
);

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
    /// fully-interpolated values in Apache merge order (see
    /// [`chain_response_headers`]), so the caller can fold them left-to-right
    /// over the header map.
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
        chain_response_headers(
            std::iter::once(self),
            rel_path,
            None,
            request_path,
            status,
            env,
        )
    }

    /// Stage this file's matching ops in source order.
    fn stage_response_headers<'a>(
        &'a self,
        rel_path: &str,
        basename: &str,
        request_path: &str,
        status: u16,
        env: &[(String, String)],
        out: &mut Vec<StagedHeader<'a>>,
    ) {
        let ext = ext_lower(basename);
        let success = (200..400).contains(&status);
        let env_lens = EnvLengths::of(env);

        // `header_index` narrows the scan to directives whose scope could match
        // (superset filter); `scopes_match` below remains the arbiter, and
        // candidates arrive in ascending source order.
        for i in self.header_index.candidates(basename, &ext) {
            let h = &self.headers[i];
            // always vs onsuccess.
            if !h.always && !success {
                continue;
            }
            // env=[!]NAME guard.
            if let Some(g) = &h.env {
                if !env_guard_passes(g, env, env_lens) {
                    continue;
                }
            }
            if !h.expr.is_empty() && !uri_tests_match(&h.expr, request_path, false) {
                continue;
            }
            // FilesMatch / DirectoryMatch / If scoping (conjunction of all
            // enclosing blocks). `<If>` tests `rel_path` too: Apache evaluates
            // it for the internally redirected request, so a front controller's
            // `<If>` sees the rewritten URI, not the original `request_path`.
            if !scopes_match(&h.scopes, rel_path, rel_path, basename) {
                continue;
            }

            // (Apache `Header edit name re repl` is not emitted by the parser today;
            // [`HeaderOp::Edit`] exists for API completeness.)
            let Some(kind) = h.action.op_kind() else {
                continue;
            };
            let value = match kind {
                HeaderOpKind::Unset => Cow::Borrowed(""),
                _ if h.interpolated => Cow::Owned(interpolate_env(&h.value, env)),
                _ => Cow::Borrowed(h.value.as_str()),
            };
            out.push((
                crate::htaccess::scope_merge_phase(&h.scopes),
                kind,
                h,
                value,
            ));
        }
    }
}

/// Stage a chain's matching ops in Apache merge order (see [`chain_response_headers`]).
fn stage_chain_headers<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    rel_path: &str,
    target_basename: Option<&str>,
    request_path: &str,
    status: u16,
    env: &[(String, String)],
) -> Vec<StagedHeader<'a>> {
    let basename = target_basename.unwrap_or_else(|| basename(rel_path));
    let mut staged = Vec::new();
    for ht in chain {
        if ht.has_resp_op {
            // Sized once for a typical security/CORS header set instead of regrowing
            // 4 -> 8 -> 16 on every response; a chain without header ops allocates nothing.
            if staged.capacity() == 0 {
                staged.reserve(16);
            }
            ht.stage_response_headers(rel_path, basename, request_path, status, env, &mut staged);
        }
    }
    staged.sort_by_key(|(phase, ..)| *phase);
    staged
}

/// The ordered `Header` mutations a `.htaccess` chain (document root → deepest)
/// applies to a response, folded left-to-right by the caller.
///
/// Apache merges per-directory configuration as directory-level directives of
/// every chain file first, then `<Files*>` sections, then `<If>` sections, so a
/// `<Files>` op outranks a later top-level op (and a deeper file's top-level
/// op) for the same header. Chain and source order are kept within a phase.
///
/// `<Files*>` sections match `target_basename` — the file the request maps to
/// (the `DirectoryIndex` file served, or the script before `PATH_INFO`) — or,
/// when `None`, the basename of `rel_path`. Other scopes see `rel_path`;
/// `expr=` guards see `request_path`.
pub fn chain_response_headers<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    rel_path: &str,
    target_basename: Option<&str>,
    request_path: &str,
    status: u16,
    env: &[(String, String)],
) -> Vec<HeaderOp> {
    stage_chain_headers(chain, rel_path, target_basename, request_path, status, env)
        .into_iter()
        .map(|(_, kind, h, value)| {
            let name = h.name.clone();
            let value = value.into_owned();
            match kind {
                HeaderOpKind::Set => HeaderOp::Set { name, value },
                HeaderOpKind::Add => HeaderOp::Add { name, value },
                HeaderOpKind::Append => HeaderOp::Append { name, value },
                HeaderOpKind::Merge => HeaderOp::Merge { name, value },
                HeaderOpKind::Unset => HeaderOp::Unset { name },
            }
        })
        .collect()
}

/// [`chain_response_headers`] as [`PreparedHeaderOp`]s: the same ops in the same
/// order, minus those whose name is not a valid field name, borrowing the names
/// and static values the chain built at parse time.
pub fn chain_prepared_headers<'a>(
    chain: impl IntoIterator<Item = &'a Htaccess>,
    rel_path: &str,
    target_basename: Option<&str>,
    request_path: &str,
    status: u16,
    env: &[(String, String)],
) -> Vec<PreparedHeaderOp<'a>> {
    let staged = stage_chain_headers(chain, rel_path, target_basename, request_path, status, env);
    let mut prepared = Vec::with_capacity(staged.len());
    prepared.extend(staged.into_iter().filter_map(|(_, kind, h, value)| {
        Some(PreparedHeaderOp {
            kind,
            name: h.field_name.as_ref()?,
            value,
            field_value: h.static_value.as_ref(),
        })
    }));
    prepared
}

/// Request-plumbing names the pipeline keeps in the env (the negotiated
/// Accept-Encoding, reserved `HJ_*`) are not part of the configured environment
/// `Header` sees: Apache/OLS have no such variables, and a cached response would
/// replay one client's value to every other (#842).
fn header_env_hidden(name: &str) -> bool {
    name.eq_ignore_ascii_case("HTTP_ACCEPT_ENCODING")
        || name.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("HJ_"))
}

/// The env value `Header` sees for `name`: ASCII-case-insensitive like Apache's
/// `subprocess_env` table, an exact-case entry preferred, plumbing hidden.
fn header_env_value<'e>(env: &'e [(String, String)], name: &str) -> Option<&'e str> {
    if header_env_hidden(name) {
        return None;
    }
    let mut folded = None;
    for (k, v) in env {
        if k == name {
            return Some(v);
        }
        if folded.is_none() && k.eq_ignore_ascii_case(name) && !header_env_hidden(k) {
            folded = Some(v.as_str());
        }
    }
    folded
}

/// The lengths of the env's names, folded into a 64-bit set. Both of
/// [`header_env_value`]'s comparisons need equal lengths, so a guard whose length is
/// absent from the set is absent from the env: the common case, as a ruleset's many
/// `env=` guards name variables most requests never set.
#[derive(Clone, Copy)]
struct EnvLengths(u64);

impl EnvLengths {
    fn of(env: &[(String, String)]) -> Self {
        EnvLengths(env.iter().fold(0, |set, (k, _)| set | Self::bit(k.len())))
    }

    fn bit(len: usize) -> u64 {
        1 << (len % 64)
    }

    fn may_hold(self, name: &str) -> bool {
        self.0 & Self::bit(name.len()) != 0
    }
}

fn env_guard_passes(g: &EnvGuard, env: &[(String, String)], lens: EnvLengths) -> bool {
    let set = lens.may_hold(&g.var) && header_env_value(env, &g.var).is_some();
    set != g.negate
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
///
/// `<If "%{REQUEST_URI} …">` tests `request_path`, which keeps the trailing `/`
/// that `rel_path` (the `<Directory*>` subject) drops (#979).
pub(crate) fn scopes_match(
    scopes: &[Scope],
    rel_path: &str,
    request_path: &str,
    basename: &str,
) -> bool {
    scopes
        .iter()
        .all(|s| scope_matches(s, rel_path, request_path, basename))
}

/// Does a single scope match? A `<Files*>`/`<Directory*>` block whose pattern did
/// not compile (`regex == None`) does NOT match (fail-closed — the directive does
/// not apply rather than widening to the whole directory); an unmodellable `<If>`
/// matches (lenient superset, as headers are not security-critical).
fn scope_matches(scope: &Scope, rel_path: &str, request_path: &str, basename: &str) -> bool {
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
            .map_or(true, |expr| expr.matches(request_path, false)),
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
                let val = header_env_value(env, name).unwrap_or("");
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
    /// `ErrorDocument 404 "Sorry, not here"` — an inline message (its quotes
    /// are stripped here).
    Inline(String),
    /// `ErrorDocument 404 https://...` — an external redirect target.
    External(String),
    /// `ErrorDocument 404 default` — the built-in page, overriding any
    /// inherited document for that status.
    Default,
}

impl ErrorDoc {
    /// Classify a raw `ErrorDocument` target the way Apache's `set_error_document`
    /// does, after its config tokenizer has unquoted the argument (`"…"` or
    /// `'…'`): whitespace => message; a leading `/` => local path; an absolute
    /// `scheme:` URL => external redirect; `default` => the built-in page;
    /// anything else => message.
    pub fn classify(raw: &str) -> ErrorDoc {
        let target = unquote_conf_word(raw);
        if target.contains(char::is_whitespace) {
            ErrorDoc::Inline(target)
        } else if target.starts_with('/') {
            ErrorDoc::Path(target)
        } else if is_url(&target) {
            ErrorDoc::External(target)
        } else if target.eq_ignore_ascii_case("default") {
            ErrorDoc::Default
        } else {
            ErrorDoc::Inline(target)
        }
    }
}

/// Apache `ap_getword_conf` for one argument: a leading `"` or `'` quotes up to
/// the matching unescaped quote (or the end of the text), and a backslash before
/// that quote character is dropped.
fn unquote_conf_word(raw: &str) -> String {
    let Some(quote) = raw.chars().next().filter(|c| matches!(c, '"' | '\'')) else {
        return raw.to_string();
    };
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw[1..].chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&quote) {
            out.push(quote);
            chars.next();
        } else if c == quote {
            break;
        } else {
            out.push(c);
        }
    }
    out
}

/// Apache `ap_is_url`: a non-empty `[A-Za-z0-9+.-]` scheme followed by `:`.
fn is_url(target: &str) -> bool {
    target.split_once(':').is_some_and(|(scheme, _)| {
        !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
    })
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
    /// `Remote_Addr` — client IP. This and `server_addr`/`host` are only read
    /// when [`Htaccess::set_env_if_reads_connection`].
    pub remote_addr: &'a str,
    /// `Server_Addr` — local bind address.
    pub server_addr: &'a str,
    /// `Host` (also matched by a literal `Host` attribute and `Server_Name`).
    pub host: &'a str,
    /// The normalized docroot-relative path (leading `/`) that a scoped
    /// `SetEnvIf`'s enclosing `<Files*>`/`<Directory*>` sections are matched
    /// against, exactly as `Header` scopes are. Empty = `request_uri`.
    /// Only read when [`Htaccess::has_scoped_set_env`].
    pub scope_path: &'a str,
    /// The slash-preserving normalized request path `<If "%{REQUEST_URI} …">`
    /// sections test: `/dir/` keeps the `/` that `scope_path` drops (#979).
    /// Empty = `scope_path`.
    pub if_path: &'a str,
    /// The basename `<Files*>` sections match: the file the request maps to
    /// (the `DirectoryIndex` file, or the script before `PATH_INFO`). `None` =
    /// the basename of the scope path.
    pub scope_basename: Option<&'a str>,
    /// Lazy request-header source (e.g. `Origin`, `User-Agent`, `Referer`). A callback
    /// rather than a materialized map, so the caller pays nothing to snapshot the whole
    /// header set — `SetEnvIf` only ever looks up the specific names its rules reference.
    /// `lookup_header` folds `-`/`_` to equivalent (so `User_Agent` ~ `User-Agent`) and the
    /// callback itself matches names ASCII-case-insensitively. `None` ⇒ no headers (all
    /// header lookups miss); the specials above are always available.
    pub header_lookup: Option<HeaderLookup<'a>>,
    /// The request env as it stands before this file's `SetEnvIf` run (server
    /// variables and earlier chain files' assignments), matched
    /// ASCII-case-insensitively like Apache's `subprocess_env` table. An
    /// attribute that is neither a special nor a present header falls back to
    /// it, after this file's own earlier assignments. `None` = empty env.
    pub env_lookup: Option<HeaderLookup<'a>>,
}

/// How a `SetEnvIf` attribute resolves, fixed when the directive is parsed:
/// one of mod_setenvif's specials, or a request header that falls back to the
/// env variable of that name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetEnvAttr {
    RequestUri,
    Method,
    Protocol,
    QueryString,
    /// `Remote_Addr`, and `Remote_Host`: the client's hostname, which without
    /// reverse DNS (Apache `HostnameLookups Off`) is its address — never a header.
    RemoteAddr,
    ServerAddr,
    /// `Host` and `Server_Name`.
    Host,
    Header,
}

impl SetEnvAttr {
    pub(crate) fn classify(attribute: &str) -> SetEnvAttr {
        let eq = |s: &str| attribute.eq_ignore_ascii_case(s);
        if eq("request_uri") {
            SetEnvAttr::RequestUri
        } else if eq("request_method") {
            SetEnvAttr::Method
        } else if eq("request_protocol") {
            SetEnvAttr::Protocol
        } else if eq("query_string") {
            SetEnvAttr::QueryString
        } else if eq("remote_addr") || eq("remote_host") {
            SetEnvAttr::RemoteAddr
        } else if eq("server_addr") {
            SetEnvAttr::ServerAddr
        } else if eq("host") || eq("server_name") {
            SetEnvAttr::Host
        } else {
            SetEnvAttr::Header
        }
    }

    /// Reads a value the caller formats from the connection per request.
    pub(crate) fn reads_connection(self) -> bool {
        matches!(
            self,
            SetEnvAttr::RemoteAddr | SetEnvAttr::ServerAddr | SetEnvAttr::Host
        )
    }
}

impl<'a> ReqAttrs<'a> {
    /// mod_setenvif `match_headers`' second step: an attribute that is neither a
    /// special nor a present header names an env variable. `pending` holds this
    /// file's earlier assignments (in order, `!VAR` = unset), which shadow the
    /// base env.
    fn resolve_env(&self, attribute: &str, pending: &[(String, String)]) -> Option<String> {
        for (key, value) in pending.iter().rev() {
            match EnvAssignment::classify(key, value) {
                EnvAssignment::Set { name, value } if name.eq_ignore_ascii_case(attribute) => {
                    return Some(value.to_string());
                }
                EnvAssignment::Unset { name } if name.eq_ignore_ascii_case(attribute) => {
                    return None;
                }
                _ => {}
            }
        }
        (self.env_lookup.as_ref()?.0)(attribute)
    }

    /// The value of a special attribute; `None` for a header attribute.
    fn special(&self, attr: SetEnvAttr) -> Option<&'a str> {
        Some(match attr {
            SetEnvAttr::RequestUri => self.request_uri,
            SetEnvAttr::Method => self.method,
            SetEnvAttr::Protocol => self.protocol,
            SetEnvAttr::QueryString => self.query_string,
            SetEnvAttr::RemoteAddr => self.remote_addr,
            SetEnvAttr::ServerAddr => self.server_addr,
            SetEnvAttr::Host => self.host,
            SetEnvAttr::Header => return None,
        })
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

/// Distinct header attributes one `eval_set_env` call remembers; more are
/// looked up per directive, as before.
const HEADER_CACHE_SLOTS: usize = 4;

type HeaderCache<'r> = [Option<(&'r str, Option<String>)>; HEADER_CACHE_SLOTS];

/// `attribute`'s request header, looked up once per evaluation: header values
/// do not depend on the assignments made so far, so a Cookie read by several
/// rules is copied once.
fn cached_header<'h, 'r>(
    cache: &'h mut HeaderCache<'r>,
    attrs: &ReqAttrs<'_>,
    attribute: &'r str,
) -> Option<Cow<'h, str>> {
    let slot = match cache
        .iter()
        .position(|slot| matches!(slot, Some((name, _)) if *name == attribute))
    {
        Some(i) => i,
        None => {
            let Some(free) = cache.iter().position(Option::is_none) else {
                return attrs.lookup_header(attribute).map(Cow::Owned);
            };
            if let Some(entry) = cache.get_mut(free) {
                *entry = Some((attribute, attrs.lookup_header(attribute)));
            }
            free
        }
    };
    cache
        .get(slot)
        .and_then(Option::as_ref)
        .and_then(|(_, value)| value.as_deref())
        .map(Cow::Borrowed)
}

impl Htaccess {
    /// Evaluate all `SetEnvIf` / `SetEnvIfNoCase` directives against `attrs`,
    /// returning the `(VAR, value)` pairs to merge into the request env.
    /// An attribute that is neither a special nor a present header is tested
    /// against the env variable of that name ([`ReqAttrs::env_lookup`] shadowed
    /// by this file's earlier assignments), as mod_setenvif does.
    ///
    /// Per Apache: the directive's value template may reference `$0`..`$9`
    /// (whole-match / capture groups of the matching regex). `SetEnvIf Foo re
    /// VAR` with no `=value` sets `VAR=1`; `VAR=val` sets the literal (after
    /// backref expansion). `!VAR` is emitted as `("!VAR", "")`, an UNSET of
    /// `VAR` — decode with [`EnvAssignment::classify`]. A directive inside
    /// `<Files*>`/`<Directory*>` runs only when its scopes match
    /// [`ReqAttrs::scope_path`], inside `<If>` when [`ReqAttrs::if_path`] does.
    ///
    /// Directives are applied in source order; a later set for the same `VAR`
    /// overrides an earlier one (the caller should let later entries win, e.g.
    /// by inserting into a map in order).
    pub fn eval_set_env(
        &self,
        attrs: &ReqAttrs<'_>,
    ) -> Result<Vec<(String, String)>, &'static str> {
        let mut out = Vec::new();
        let scope_path = if attrs.scope_path.is_empty() {
            attrs.request_uri
        } else {
            attrs.scope_path
        };
        let if_path = if attrs.if_path.is_empty() {
            scope_path
        } else {
            attrs.if_path
        };
        let scope_basename = attrs.scope_basename.unwrap_or_else(|| basename(scope_path));
        let mut headers: HeaderCache<'_> = Default::default();
        // The previous directive's match result, for a `reuse_prev` directive.
        let mut prev: Option<bool> = None;
        for s in &self.set_env_if {
            if !s.scopes.is_empty() && !scopes_match(&s.scopes, scope_path, if_path, scope_basename)
            {
                prev = None;
                continue;
            }
            let matched = match prev {
                Some(matched) if s.reuse_prev => {
                    if matched {
                        push_assignments(s, None, &mut out);
                    }
                    matched
                }
                _ => {
                    if let Some(subject) = attrs.special(s.attr) {
                        eval_set_env_subject(s, subject, &mut out)?
                    } else if let Some(subject) = cached_header(&mut headers, attrs, &s.attribute) {
                        eval_set_env_subject(s, &subject, &mut out)?
                    } else if let Some(subject) = attrs.resolve_env(&s.attribute, &out) {
                        eval_set_env_subject(s, &subject, &mut out)?
                    } else {
                        // mod_setenvif tests an absent field as "" so `^$` matches it.
                        eval_set_env_subject(s, "", &mut out)?
                    }
                }
            };
            prev = Some(matched);
        }
        Ok(out)
    }

    /// Whether some `SetEnvIf` here reads `Remote_Addr`/`Remote_Host`/
    /// `Server_Addr`/`Host`/`Server_Name`; otherwise those [`ReqAttrs`] fields
    /// are never read and a caller need not format them.
    pub fn set_env_if_reads_connection(&self) -> bool {
        self.set_env_if_reads_conn
    }

    /// Cookie-dependent assignments in the same order and with the same
    /// capture expansion as `eval_set_env`. Cache keys can distinguish their
    /// effects without fragmenting on unrelated cookies in the same header.
    /// Scoped rules are included regardless of path: a superset only adds key
    /// discrimination, never merges two different effective envs.
    pub fn eval_cookie_env(
        &self,
        cookie: Option<&str>,
    ) -> Result<Vec<(String, String)>, &'static str> {
        let mut out = Vec::new();
        // An absent Cookie is tested as "", exactly as `eval_set_env` does.
        let cookie = cookie.unwrap_or("");
        let mut prev: Option<bool> = None;
        for rule in &self.set_env_if {
            if !rule.attribute.eq_ignore_ascii_case("cookie") {
                prev = None;
                continue;
            }
            let matched = match prev {
                Some(matched) if rule.reuse_prev => {
                    if matched {
                        push_assignments(rule, None, &mut out);
                    }
                    matched
                }
                _ => eval_set_env_subject(rule, cookie, &mut out)?,
            };
            prev = Some(matched);
        }
        Ok(out)
    }

    /// [`Htaccess::eval_cookie_env`], borrowing the parse-time result when the
    /// request carries no Cookie.
    pub fn cookie_env(
        &self,
        cookie: Option<&str>,
    ) -> Result<Cow<'_, [(String, String)]>, &'static str> {
        match (cookie, &self.cookie_env_absent) {
            (None, Some(absent)) => absent.as_deref().map(Cow::Borrowed).map_err(|e| *e),
            _ => self.eval_cookie_env(cookie).map(Cow::Owned),
        }
    }
}

/// Test one directive against `subject`, appending its assignments on a match.
fn eval_set_env_subject(
    rule: &crate::htaccess::SetEnvIf,
    subject: &str,
    out: &mut Vec<(String, String)>,
) -> Result<bool, &'static str> {
    const FAILED: &str = "SetEnvIf regex failed at match time";
    // Keep the literal-prefix guard shared by normal evaluation and cache
    // discrimination, including the empty-prefix NoCase behavior.
    if !rule.literal_prefix.is_empty()
        && !subject.as_bytes().starts_with(rule.literal_prefix.as_ref())
    {
        return Ok(false);
    }
    if !rule.needs_caps {
        let matched = rule.regex.is_match_checked(subject).map_err(|()| FAILED)?;
        if matched {
            push_assignments(rule, None, out);
        }
        return Ok(matched);
    }
    match rule.regex.captures_checked(subject) {
        Ok(Some(caps)) => {
            push_assignments(rule, Some(&caps), out);
            Ok(true)
        }
        Ok(None) => Ok(false),
        Err(()) => Err(FAILED),
    }
}

/// Append a matched directive's assignments. Without `caps` the templates hold
/// no `$` (`SetEnvIf::needs_caps`), so they are literal.
fn push_assignments(
    rule: &crate::htaccess::SetEnvIf,
    caps: Option<&crate::rules::Caps<'_>>,
    out: &mut Vec<(String, String)>,
) {
    for (var, value) in &rule.assigns {
        let value = if var.starts_with('!') {
            String::new()
        } else if let Some(caps) = caps {
            expand_backrefs(value, caps)
        } else {
            value.clone()
        };
        out.push((var.clone(), value));
    }
}

/// One env mutation from `SetEnvIf` output or a rewrite outcome's `[E=]` list.
/// Both use Apache's spelling (mod_setenvif `!VAR`, mod_rewrite `[E=!VAR]`; OLS
/// `RequestVars::setEnv`): a key starting with `!` REMOVES the variable named by
/// the rest of the key. Every consumer that merges those `(key, value)` lists
/// into a request env must decode them through [`EnvAssignment::classify`]; a
/// literal `!VAR` key would leave `VAR` set (#780).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvAssignment<'a> {
    Set {
        name: &'a str,
        value: &'a str,
    },
    /// Remove `name` (a no-op when it is not set).
    Unset {
        name: &'a str,
    },
}

impl<'a> EnvAssignment<'a> {
    pub fn classify(key: &'a str, value: &'a str) -> EnvAssignment<'a> {
        match key.strip_prefix('!') {
            Some(name) => EnvAssignment::Unset { name },
            None => EnvAssignment::Set { name: key, value },
        }
    }

    /// The variable this assignment targets.
    pub fn name(&self) -> &'a str {
        match *self {
            EnvAssignment::Set { name, .. } | EnvAssignment::Unset { name } => name,
        }
    }
}

/// Expand `$0`..`$9` in a `SetEnvIf` value template from regex captures.
/// Unknown / absent groups expand to empty. `$$` is a literal `$`.
fn expand_backrefs(template: &str, caps: &crate::rules::Caps<'_>) -> String {
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
                        out.push_str(m);
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
mod set_env_tests;

#[cfg(test)]
mod directive_tests {
    use super::*;
    use crate::Htaccess;
    use crate::error::RewriteError;

    /// The length-set shortcut never changes a guard's verdict.
    #[test]
    fn env_length_shortcut_agrees_with_the_full_lookup() {
        let names = [
            "no-cache",
            "NO-CACHE",
            "BLOCKED",
            "blocked",
            "WF_BETA_CONTROL",
            "x",
            "HTTP_ACCEPT_ENCODING",
            "HJ_PLUMBING",
            "a-sixty-four-character-name-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "proxy-img-cache",
            "",
        ];
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for _ in 0..2000 {
            let mut env = Vec::new();
            for _ in 0..(x % 6) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                env.push((
                    names[(x % names.len() as u64) as usize].to_string(),
                    "1".to_string(),
                ));
            }
            let lens = EnvLengths::of(&env);
            for var in names {
                for negate in [false, true] {
                    let g = EnvGuard {
                        var: var.to_string(),
                        negate,
                    };
                    let full = header_env_value(&env, var).is_some() != negate;
                    assert_eq!(env_guard_passes(&g, &env, lens), full, "{var:?} {env:?}");
                }
            }
        }
    }

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

    /// Regression (#604): an access section whose regex does not compile is a parse
    /// error, so the file fails closed (deny-all sentinel), never a silent drop of
    /// the `Require`/`Deny` it encloses.
    #[test]
    fn uncompilable_regex_section_fails_the_file_closed() {
        for text in [
            "<FilesMatch \"[unterminated\">\n  Require all denied\n</FilesMatch>",
            "<Files ~ \"(\">\n  Require all denied\n</Files>",
            "<DirectoryMatch \"[\">\n  Deny from all\n</DirectoryMatch>",
        ] {
            assert!(
                matches!(
                    Htaccess::parse(text),
                    Err(RewriteError::BadRegex { line: 1, .. })
                ),
                "{text}"
            );
        }
    }

    /// A glob can always be translated: an unterminated `[` is literal (fnmatch),
    /// so `<Files "glob">` never trips the fail-closed path by accident.
    #[test]
    fn glob_section_with_unbalanced_bracket_matches_literally() {
        let h = Htaccess::parse("<Files \"[x\">\n  Require all denied\n</Files>").unwrap();
        assert_eq!(h.access_decision("/dir/[x", "GET"), AccessDecision::Denied);
        assert_eq!(
            h.access_decision("/dir/a.txt", "GET"),
            AccessDecision::NoOpinion
        );
        let h = Htaccess::parse("<Files \"*.[ch]\">\n  Require all denied\n</Files>").unwrap();
        assert_eq!(h.access_decision("/src/a.c", "GET"), AccessDecision::Denied);
        assert_eq!(
            h.access_decision("/src/a.o", "GET"),
            AccessDecision::NoOpinion
        );
        for glob in [
            "[", "]", "[!", "[]", "[]]", "[!]]", "a[\\\\]b", "[[x]", "[a-", "\\\\", "[!]", "[^]",
            "[^]]", "[z-a]*", "*.[z-a]",
        ] {
            let text = format!("<Files \"{glob}\">\n  Require all denied\n</Files>");
            assert!(
                Htaccess::parse(&text).is_ok(),
                "glob {glob:?} must always compile"
            );
        }
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
        let env = h.eval_set_env(&attrs).unwrap();
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
        assert!(h.eval_set_env(&attrs_bad).unwrap().is_empty());
    }

    #[test]
    fn set_env_if_match_error_is_not_treated_as_non_match() {
        // Both the plain match test and the capture path report the error (#977).
        for text in [
            "SetEnvIf Request_URI x SAFE=1",
            "SetEnvIf Request_URI x SAFE=$0",
        ] {
            let mut h = Htaccess::parse(text).unwrap();
            let mut builder = fancy_regex::RegexBuilder::new(r"^(a+)+\1$");
            builder.backtrack_limit(1);
            h.set_env_if[0].regex = crate::rules::CompiledRegex::Fancy(builder.build().unwrap());
            let attrs = ReqAttrs {
                request_uri: "aaaaaaaaaaaaaaaaX",
                ..Default::default()
            };
            assert!(h.eval_set_env(&attrs).is_err(), "{text}");
        }
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
        let env = h.eval_set_env(&attrs).unwrap();
        assert!(env.contains(&("NEWS_API_CC".to_string(), "1".to_string())));
        assert!(env.contains(&("AMP_PAGE".to_string(), "1".to_string())));
        // Non-matching URI -> NEWS_API_CC not set.
        let attrs2 = ReqAttrs {
            request_uri: "/page.html",
            ..Default::default()
        };
        assert!(
            !h.eval_set_env(&attrs2)
                .unwrap()
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
            h.eval_set_env(&attrs).unwrap(),
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
        let env = h.eval_set_env(&attrs).unwrap();
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
        let env_bad = h.eval_set_env(&attrs_bad).unwrap();
        assert!(h.response_headers("/api/x.php", 200, &env_bad).is_empty());
    }

    /// #907: `<Files*>` header scope matches the file the request maps to.
    #[test]
    fn files_scoped_header_matches_the_target_basename() {
        let h = Htaccess::parse(
            "<FilesMatch \"\\.html$\">\n  Header set X-Html 1\n</FilesMatch>\n\
             <Files \"index.php\">\n  Header set X-Index 1\n</Files>",
        )
        .unwrap();
        let names = |rel: &str, target: Option<&str>| -> Vec<String> {
            chain_response_headers([&h], rel, target, rel, 200, &[])
                .iter()
                .map(|o| o.name().to_string())
                .collect()
        };
        assert!(names("/", None).is_empty());
        assert_eq!(names("/", Some("index.html")), vec!["X-Html"]);
        assert_eq!(names("/docs", Some("index.html")), vec!["X-Html"]);
        // PATH_INFO: the script basename, not the trailing segment.
        assert!(names("/index.php/x", None).is_empty());
        assert_eq!(names("/index.php/x", Some("index.php")), vec!["X-Index"]);
    }

    /// #907: a `<Files>`-scoped SetEnvIf matches `scope_basename` when given.
    #[test]
    fn files_scoped_set_env_if_matches_the_scope_basename() {
        let h = Htaccess::parse("<Files \"index.html\">\n  SetEnvIf Request_URI . IDX=1\n</Files>")
            .unwrap();
        let attrs = ReqAttrs {
            request_uri: "/",
            scope_path: "/",
            ..Default::default()
        };
        assert!(h.eval_set_env(&attrs).unwrap().is_empty());
        let attrs = ReqAttrs {
            scope_basename: Some("index.html"),
            ..attrs
        };
        assert_eq!(
            h.eval_set_env(&attrs).unwrap(),
            vec![("IDX".to_string(), "1".to_string())]
        );
    }

    /// #908: Apache unquotes the target, then classifies it.
    #[test]
    fn error_document_classification_unquotes_first() {
        let cases = [
            (
                "\"/errors/404.html\"",
                ErrorDoc::Path("/errors/404.html".into()),
            ),
            (
                "'/errors/404.html'",
                ErrorDoc::Path("/errors/404.html".into()),
            ),
            (
                "/errors/404.html",
                ErrorDoc::Path("/errors/404.html".into()),
            ),
            (
                "\"https://e.example/404\"",
                ErrorDoc::External("https://e.example/404".into()),
            ),
            (
                "'https://e.example/404'",
                ErrorDoc::External("https://e.example/404".into()),
            ),
            (
                "http://e.example/x",
                ErrorDoc::External("http://e.example/x".into()),
            ),
            ("\"Not here\"", ErrorDoc::Inline("Not here".into())),
            ("'Not here'", ErrorDoc::Inline("Not here".into())),
            ("\"Sorry\"", ErrorDoc::Inline("Sorry".into())),
            ("Sorry", ErrorDoc::Inline("Sorry".into())),
            ("\"Sorry", ErrorDoc::Inline("Sorry".into())),
            (
                "\"say \\\"hi\\\" there\"",
                ErrorDoc::Inline("say \"hi\" there".into()),
            ),
            ("\"/a b.html\"", ErrorDoc::Inline("/a b.html".into())),
            ("default", ErrorDoc::Default),
            ("\"DEFAULT\"", ErrorDoc::Default),
        ];
        for (raw, want) in cases {
            assert_eq!(ErrorDoc::classify(raw), want, "{raw}");
        }
        let h = Htaccess::parse(
            "ErrorDocument 404 \"/errors/404.html\"\n\
             ErrorDocument 410 default\n\
             ErrorDocument 401 https://e.example/login",
        )
        .unwrap();
        assert_eq!(
            h.error_document(404),
            Some(&ErrorDoc::Path("/errors/404.html".into()))
        );
        assert_eq!(h.error_document(410), Some(&ErrorDoc::Default));
        // Apache ignores a URL for 401 (the challenge would be lost).
        assert_eq!(h.error_document(401), None);
    }

    /// #909: Apache merges directory-level ops, then `<Files*>`, then `<If>`.
    #[test]
    fn header_ops_apply_in_apache_merge_order() {
        let h = Htaccess::parse(
            "<If \"%{REQUEST_URI} =~ m#^/#\">\n  Header set X-Order if\n</If>\n\
             <Files a.txt>\n  Header set X-Order files\n</Files>\n\
             Header set X-Order dir\n\
             Header add X-Seq one\n\
             Header add X-Seq two",
        )
        .unwrap();
        let ops = h.response_headers("/a.txt", 200, &[]);
        let order: Vec<String> = ops
            .iter()
            .filter(|o| o.name() == "X-Order")
            .map(|o| match o {
                HeaderOp::Set { value, .. } => value.clone(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(order, vec!["dir", "files", "if"]);
        let seq: Vec<&HeaderOp> = ops.iter().filter(|o| o.name() == "X-Seq").collect();
        assert_eq!(
            seq,
            vec![
                &HeaderOp::Add {
                    name: "X-Seq".into(),
                    value: "one".into()
                },
                &HeaderOp::Add {
                    name: "X-Seq".into(),
                    value: "two".into()
                },
            ]
        );
        // Across the chain: a parent's `<Files>` op outranks a child's top level.
        let parent =
            Htaccess::parse("<Files a.txt>\n  Header set X-Order parent-files\n</Files>").unwrap();
        let child = Htaccess::parse("Header set X-Order child-dir").unwrap();
        let ops = chain_response_headers(
            [&parent, &child],
            "/sub/a.txt",
            None,
            "/sub/a.txt",
            200,
            &[],
        );
        assert_eq!(
            ops.last(),
            Some(&HeaderOp::Set {
                name: "X-Order".into(),
                value: "parent-files".into()
            })
        );
    }

    /// #910: `env=` guards and `%{VAR}e` match env names case-insensitively.
    #[test]
    fn header_env_names_match_case_insensitively() {
        let h = Htaccess::parse(
            "Header set X-Guard on env=LOWER\n\
             Header set X-Neg on env=!LOWER\n\
             Header set X-Val \"%{LOWER}e\"",
        )
        .unwrap();
        let env = vec![("Lower".to_string(), "1".to_string())];
        let ops = h.response_headers("/x", 200, &env);
        assert!(ops.iter().any(|o| o.name() == "X-Guard"));
        assert!(!ops.iter().any(|o| o.name() == "X-Neg"));
        assert!(ops.contains(&HeaderOp::Set {
            name: "X-Val".into(),
            value: "1".into()
        }));
        // Exact case wins over a case-folded sibling.
        let env = vec![
            ("lower".to_string(), "folded".to_string()),
            ("LOWER".to_string(), "exact".to_string()),
        ];
        assert_eq!(interpolate_env("%{LOWER}e", &env), "exact");
        // Plumbing stays hidden however it is spelled.
        let plumbing = vec![
            ("HTTP_ACCEPT_ENCODING".to_string(), "gzip".to_string()),
            ("HJ_X".to_string(), "1".to_string()),
        ];
        assert_eq!(
            interpolate_env("[%{http_accept_encoding}e]", &plumbing),
            "[]"
        );
        assert_eq!(interpolate_env("[%{hj_x}e]", &plumbing), "[]");
        let g = Htaccess::parse("Header set X-P 1 env=hj_x").unwrap();
        assert!(g.response_headers("/x", 200, &plumbing).is_empty());
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
        // Pipeline plumbing never reaches Header values (#842).
        let plumbing = vec![
            ("HTTP_ACCEPT_ENCODING".to_string(), "gzip".to_string()),
            ("HJ_X".to_string(), "1".to_string()),
        ];
        assert_eq!(
            interpolate_env("[%{HTTP_ACCEPT_ENCODING}e]", &plumbing),
            "[]"
        );
        assert_eq!(interpolate_env("[%{HJ_X}e]", &plumbing), "[]");
    }
}
