//! Rule-set evaluation internals: `%{VAR}` resolution, template expansion, the
//! per-pass loop driver ([`run_pass`]/`apply_rule`), and the substitution /
//! redirect / query-string machinery. The public [`super::evaluate`] entry
//! drives these.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ops::Range;

use regex_automata::PatternSet;

use crate::input::{FileTests, RewriteInput, StatSource};

use super::*;

// ===========================================================================
// Variable resolution
// ===========================================================================

/// Resolve a single `%{VAR}` against the input + current state.
///
/// Genuinely-unavailable variables resolve to the empty string (Apache also
/// yields `""` when it cannot compute them): the time family (`%{TIME}`,
/// `%{TIME_YEAR}`, `%{TIME_MON}`, ...) and the internal-map `%{...}` forms. They
/// fall through to the env lookup below, which returns `""` for unknown names.
/// (`%{LA-U:VAR}`/`%{LA-F:VAR}` were already reduced to `%{VAR}` at parse time.)
/// Look up `name` in the borrowed env seed (the pipeline's key-deduped `ctx.env`).
/// Exact-key match, equivalent to the former `BTreeMap::get` on the cloned seed.
fn seed_get<'s>(input: &'s RewriteInput, name: &str) -> Option<&'s String> {
    input
        .env_seed
        .and_then(|s| s.iter().find(|(k, _)| k == name).map(|(_, v)| v))
}

fn resolve_var_into(
    out: &mut String,
    name: &str,
    input: &RewriteInput,
    cur_uri: &str,
    cur_query: &str,
    env: &BTreeMap<String, String>,
) {
    use std::fmt::Write;
    // %{HTTP:Header-Name}
    if let Some(hdr) = name.strip_prefix("HTTP:") {
        if let Some(c) = input.get_header(hdr) {
            out.push_str(&c);
        }
        return;
    }
    // %{ENV:NAME} — check the [E=] overlay first, then the request seed (input.env).
    if let Some(var) = name.strip_prefix("ENV:") {
        if let Some(v) = env
            .get(var)
            .or_else(|| input.env.get(var))
            .or_else(|| seed_get(input, var))
        {
            out.push_str(v);
        }
        return;
    }
    match name {
        "REQUEST_URI" => out.push_str(cur_uri),
        "REQUEST_FILENAME" | "SCRIPT_FILENAME" => push_request_filename(out, input, cur_uri),
        "REQUEST_METHOD" => out.push_str(&input.method),
        "HTTP_HOST" => out.push_str(&input.host),
        "HTTP_USER_AGENT" => {
            if let Some(c) = input.get_header("User-Agent") {
                out.push_str(&c)
            }
        }
        "HTTP_COOKIE" => {
            if let Some(c) = input.get_header("Cookie") {
                out.push_str(&c)
            }
        }
        "HTTP_REFERER" => {
            if let Some(c) = input.get_header("Referer") {
                out.push_str(&c)
            }
        }
        "HTTP_ACCEPT" => {
            if let Some(c) = input.get_header("Accept") {
                out.push_str(&c)
            }
        }
        "QUERY_STRING" => out.push_str(cur_query),
        "HTTPS" => out.push_str(if input.https { "on" } else { "off" }),
        "SERVER_PORT" => match input.server_port {
            Some(p) => {
                let _ = write!(out, "{p}");
            }
            None => out.push_str(if input.https { "443" } else { "80" }),
        },
        "REQUEST_SCHEME" => out.push_str(if input.https { "https" } else { "http" }),
        // %{REMOTE_ADDR}/%{SERVER_ADDR}/%{SERVER_NAME}/%{REMOTE_PORT}: supplied by
        // the pipeline from ReqCtx (client_ip/peer_*/local_addr). Unset -> "".
        // OLS resolves REMOTE_HOST to the client address (no reverse DNS).
        "REMOTE_ADDR" | "REMOTE_HOST" => out.push_str(&input.remote_addr),
        "REMOTE_PORT" => {
            if let Some(p) = input.remote_port {
                let _ = write!(out, "{p}");
            }
        }
        "SERVER_ADDR" => out.push_str(&input.server_addr),
        // SERVER_NAME falls back to the Host header when no canonical name is set
        // (Apache's UseCanonicalName Off default behavior).
        "SERVER_NAME" => {
            if input.server_name.is_empty() {
                out.push_str(&input.host);
            } else {
                out.push_str(&input.server_name);
            }
        }
        "DOCUMENT_ROOT" => out.push_str(&input.docroot.to_string_lossy()),
        "SERVER_PROTOCOL" => out.push_str(&input.protocol),
        // %{THE_REQUEST} is the VERBATIM original request line — Apache documents it as NOT
        // modified by any rewriting. Use the FROZEN raw target when the pipeline attached
        // one (audit: the decoded canonical path turned `/a%2Eb` into `/a.b` and broke
        // verbatim-line rules like the live rss `.htaccess`), else the frozen
        // `input.uri`/`input.query` — never the evolving `cur_uri`/`cur_query`.
        "THE_REQUEST" => {
            out.push_str(&input.method);
            out.push(' ');
            match &input.raw_request_target {
                Some(raw) => out.push_str(raw),
                None => {
                    out.push_str(&input.uri);
                    if !input.query.is_empty() {
                        out.push('?');
                        out.push_str(&input.query);
                    }
                }
            }
            out.push(' ');
            out.push_str(&input.protocol);
        }
        _ if let Some(hdr) = super::parse::single_word_header_var(name) => {
            if let Some(c) = input.get_header(hdr) {
                out.push_str(&c);
            }
        }
        // Bare %{NAME} fallthrough — same overlay-then-seed lookup as %{ENV:NAME}.
        _ => {
            if let Some(v) = env
                .get(name)
                .or_else(|| input.env.get(name))
                .or_else(|| seed_get(input, name))
            {
                out.push_str(v)
            }
        }
    }
}

/// Push the on-disk path for `%{REQUEST_FILENAME}` (docroot joined with the
/// current path, leading `/` stripped) directly into `out`. Byte-identical to
/// `docroot.join(rel).to_string_lossy()` — `Path::join` collapses a trailing
/// docroot separator and always inserts exactly one before `rel` (even when
/// `rel` is empty, e.g. the `/` request) — but without the intermediate
/// `PathBuf` + `String` allocation.
///
/// When the full path does not exist but a proper prefix is a regular file, the
/// value stops at that file and the rest is PATH_INFO, as OLS `checkPathInfo`
/// and Apache's directory walk resolve it: `/index.php/welcome` is `-f`, so an
/// `index.php/$1` front controller does not re-wrap its own target (#881).
fn push_request_filename(out: &mut String, input: &RewriteInput, cur_uri: &str) {
    if !matches!(input.stat, StatSource::Live(_) | StatSource::LiveTests(_)) {
        resolve_request_filename(out, input, cur_uri);
        return;
    }
    let hit = FS_MEMO.with(|m| {
        let m = m.borrow();
        let hit = m.active && m.filename_valid && m.filename_uri == cur_uri;
        if hit {
            out.push_str(&m.filename);
        }
        hit
    });
    if hit {
        return;
    }
    let start = out.len();
    resolve_request_filename(out, input, cur_uri);
    FS_MEMO.with(|m| {
        let m = &mut *m.borrow_mut();
        if m.active {
            m.filename_uri.clear();
            m.filename_uri.push_str(cur_uri);
            m.filename.clear();
            m.filename.push_str(out.get(start..).unwrap_or_default());
            m.filename_valid = true;
        }
    });
}

fn resolve_request_filename(out: &mut String, input: &RewriteInput, cur_uri: &str) {
    let start = out.len();
    let rel = cur_uri.trim_start_matches('/');
    let dr = input.docroot.to_string_lossy();
    out.push_str(dr.trim_end_matches('/'));
    let base = out.len();
    out.push('/');
    out.push_str(rel);
    if !matches!(input.stat, StatSource::Live(_) | StatSource::LiveTests(_)) {
        return;
    }
    let path = &out[start..];
    let base = base - start;
    let mut end = path.trim_end_matches('/').len();
    if end <= base {
        return;
    }
    if let Some(is_file) = stat_is_file(input, &path[..end]) {
        // `/index.php/` names the script with an empty PATH_INFO (OLS strips the
        // trailing slashes before its stat), so `-f` holds.
        if is_file {
            out.truncate(start + end);
        }
        return;
    }
    if end < path.len() {
        // `X/` cannot exist where `X` does not: record that for the file tests on the
        // slashed path that follow (a front controller's `-f [OR] -l [OR] -d` on every
        // `/threads/slug.1/` route), which would otherwise stat it again (#899 keeps
        // the two spellings apart in the stat cache).
        FS_MEMO.with(|m| {
            let m = &mut *m.borrow_mut();
            if m.active {
                m.test_path.clear();
                m.test_path.push_str(path);
                m.test = None;
                m.test_valid = true;
            }
        });
    }
    // Bounded: a hostile URI of thousands of missing segments must not cost a
    // stat per segment.
    for _ in 0..MAX_PATH_INFO_WALK {
        let Some(cut) = path[..end].rfind('/') else {
            return;
        };
        end = path[..cut].trim_end_matches('/').len();
        if end <= base {
            return;
        }
        if let Some(is_file) = stat_is_file(input, &path[..end]) {
            if is_file {
                out.truncate(start + end);
            }
            return;
        }
    }
}

const MAX_PATH_INFO_WALK: usize = 32;

std::thread_local! {
    /// The last live `%{REQUEST_FILENAME}` expansion and file test of the
    /// evaluation running on this thread: a front controller's `-f [OR] -l [OR] -d`
    /// otherwise re-expands, re-walks PATH_INFO and re-stats one path per cond.
    /// Buffers keep their capacity across evaluations.
    static FS_MEMO: std::cell::RefCell<FsMemo> = std::cell::RefCell::new(FsMemo::default());
}

#[derive(Default)]
struct FsMemo {
    active: bool,
    filename_valid: bool,
    filename_uri: String,
    filename: String,
    test_valid: bool,
    test_path: String,
    test: Option<FileTests>,
}

impl FsMemo {
    fn reset(&mut self, active: bool) {
        self.active = active;
        self.filename_valid = false;
        self.test_valid = false;
    }
}

/// Confines [`FS_MEMO`] to one `evaluate` call: its docroot and stat source are
/// fixed for the call, and outside one the memo is bypassed.
pub(super) struct FsMemoScope(());

impl FsMemoScope {
    pub(super) fn enter() -> Self {
        FS_MEMO.with(|m| m.borrow_mut().reset(true));
        FsMemoScope(())
    }
}

impl Drop for FsMemoScope {
    fn drop(&mut self) {
        FS_MEMO.with(|m| m.borrow_mut().reset(false));
    }
}

/// `Some(is_regular_file)` when `path` exists under a live stat source.
fn stat_is_file(input: &RewriteInput, path: &str) -> Option<bool> {
    let path = std::path::Path::new(path);
    match &input.stat {
        StatSource::Live(f) => f(path).map(|md| md.is_file()),
        StatSource::LiveTests(f) => f(path).map(|t| t.is_file),
        StatSource::Precomputed(_) | StatSource::None => None,
    }
}

/// Expand `%{VAR}`, `$N` (rule backrefs), and `%N` (last-cond backrefs) inside a
/// string. `rule_caps`/`cond_caps` are indexed 0..=9.
/// Owned-result `expand` for the ESCAPING callers (the rewritten URI/query/env values that
/// outlive the rule). Transient callers (cond test strings) should use [`expand_into`] with a
/// reused buffer instead — see `eval_one_cond`.
fn expand(
    template: &str,
    input: &RewriteInput,
    cur_uri: &str,
    cur_query: &str,
    env: &BTreeMap<String, String>,
    rule_caps: &[Option<String>],
    cond_caps: &[Option<String>],
) -> String {
    let mut out = String::new();
    expand_into(
        &mut out, template, input, cur_uri, cur_query, env, rule_caps, cond_caps,
    );
    out
}

/// Per `%N` slot, the byte spans of the capture that came from the escaped working
/// URI (see [`EvalState::uri_escaped`]); every other byte is literal.
pub(super) type CondEscaped = Box<[Vec<Range<usize>>; 10]>;

/// How backreferences are escaped while expanding a RewriteRule substitution.
struct SubstEscape<'r> {
    backref: Option<&'r BackrefEscape>,
    allow_3f: bool,
    /// Emit a literal `%` that an expansion carries into the path part as `%25`.
    escape_pct: bool,
    /// `$N` and the `%{VAR}`s that read the working URI are escaped already.
    uri_escaped: bool,
    cond_escaped: Option<&'r CondEscaped>,
}

/// What an expansion is for: a substitution escapes what it inserts; a condition
/// test string expanded after a substitution records which bytes came from the
/// escaped working URI, so its `%N` captures keep that provenance.
enum Expansion<'a, 'r> {
    Plain,
    Subst(&'a SubstEscape<'r>),
    TestString {
        escaped: &'a mut Vec<Range<usize>>,
        cond_escaped: Option<&'a CondEscaped>,
    },
}

/// Where the bytes of an inserted value came from.
#[derive(Clone, Copy)]
enum Provenance<'a> {
    Literal,
    Escaped,
    /// Literal except these escaped spans.
    Spans(&'a [Range<usize>]),
}

impl Provenance<'_> {
    fn literal_at(self, i: usize) -> bool {
        match self {
            Provenance::Literal => true,
            Provenance::Escaped => false,
            Provenance::Spans(spans) => !spans.iter().any(|r| r.contains(&i)),
        }
    }
}

/// The variables whose value is the working URI: escaped once a substitution ran.
fn var_reads_working_uri(name: &str) -> bool {
    matches!(name, "REQUEST_URI" | "REQUEST_FILENAME" | "SCRIPT_FILENAME")
}

/// Expand a substitution. Like OLS `appendSubst`, a value it inserts is literal
/// text in the target, so in the path part a literal `%` becomes `%25`: the
/// pipeline decodes the target once, which must yield the inserted bytes rather
/// than decode a `%252e` request a second time into `.` (#1033). OLS decodes only
/// the substitution's own text (here `%XX` survives `escape_subst` and that one
/// decode) and `%{REQUEST_URI}`, whose source there is the raw request target;
/// ours is the decoded path already (OLS also re-decodes its decoded URI after an
/// internal redirect, the double decode this avoids). A `?` a `$N`/`%N` carries
/// into the path part becomes `%3F` (unless `[UnsafeAllow3F]`; a decoded `%3F`
/// must not split the target, CVE-2024-38474); one in a `%{VAR}` starts the
/// query, as in OLS.
fn expand_subst(
    rule: &Rule,
    input: &RewriteInput,
    state: &EvalState,
    rule_caps: &[Option<String>],
    escape_pct: bool,
) -> String {
    let mut out = String::new();
    let esc = SubstEscape {
        backref: rule.flags.backref_escape.as_ref(),
        allow_3f: rule.flags.allow_3f,
        escape_pct,
        uri_escaped: state.uri_escaped,
        cond_escaped: state.last_cond_escaped.as_ref(),
    };
    expand_with(
        &mut out,
        &rule.subst,
        input,
        &state.uri,
        &state.query,
        &state.env,
        rule_caps,
        &state.last_cond_caps,
        Expansion::Subst(&esc),
    );
    out
}

fn push_backref(out: &mut String, val: &str, e: &SubstEscape<'_>, from: Provenance<'_>) {
    let mut in_path = !out.contains('?');
    let escape_pct = e.escape_pct && !matches!(from, Provenance::Escaped);
    if e.backref.is_none()
        && (!in_path || !val.bytes().any(|b| b == b'?' || (escape_pct && b == b'%')))
    {
        out.push_str(val);
        return;
    }
    // OLS runs escape_unsafe_3f AFTER the [B] family's escape_uri, so a [B=chars],
    // [BCTLS] or [BNE=?] that leaves `?` literal must still not split the path (#753).
    for (i, c) in val.char_indices() {
        if let Some(b) = e.backref
            && backref_escapes(b, c)
        {
            push_backref_escaped(out, c, b);
            continue;
        }
        match c {
            '?' if in_path && !e.allow_3f => out.push_str("%3F"),
            '?' => {
                in_path = false;
                out.push('?');
            }
            '%' if in_path && escape_pct && from.literal_at(i) => out.push_str("%25"),
            _ => out.push(c),
        }
    }
}

/// Escape the literal `%`s of the `%{VAR}` value that `out` holds from `start`, up
/// to the end of the path part.
fn escape_var_value(out: &mut String, start: usize) {
    let Some(head) = out.get(..start) else {
        return;
    };
    if head.contains('?') {
        return;
    }
    let value = out.get(start..).unwrap_or_default();
    let path_len = value.find('?').unwrap_or(value.len());
    if !value.get(..path_len).unwrap_or_default().contains('%') {
        return;
    }
    let value = out.split_off(start);
    for (i, c) in value.char_indices() {
        if c == '%' && i < path_len {
            out.push_str("%25");
        } else {
            out.push(c);
        }
    }
}

/// OLS `escape_uri` for the `[B]` family: everything but alphanumerics and `_` is
/// percent-encoded, a space becoming `+` unless `[BNP]`.
fn backref_escapes(b: &BackrefEscape, c: char) -> bool {
    let escape = if let Some(only) = &b.only {
        only.contains(c)
    } else if b.ctls_only {
        c.is_control() || c == ' '
    } else {
        !(c.is_ascii_alphanumeric() || c == '_')
    };
    escape && !b.no_escape.contains(c)
}

fn push_backref_escaped(out: &mut String, c: char, b: &BackrefEscape) {
    if c == ' ' && !b.no_plus {
        out.push('+');
        return;
    }
    let mut buf = [0u8; 4];
    for byte in c.encode_utf8(&mut buf).bytes() {
        out.push('%');
        out.push(hex_upper(byte >> 4));
        out.push(hex_upper(byte & 0xf));
    }
}

/// `expand` into a caller-provided buffer (which the caller has cleared) — no allocation when the
/// buffer already has capacity. Lets the per-cond expansions in `eval_one_cond` reuse one
/// thread-local buffer across every cond + request instead of allocating a fresh `String` each time
/// (the #1 per-request allocation on a heavy-`.htaccess` vhost: `expand` per RewriteCond test).
fn expand_into(
    out: &mut String,
    template: &str,
    input: &RewriteInput,
    cur_uri: &str,
    cur_query: &str,
    env: &BTreeMap<String, String>,
    rule_caps: &[Option<String>],
    cond_caps: &[Option<String>],
) {
    expand_with(
        out,
        template,
        input,
        cur_uri,
        cur_query,
        env,
        rule_caps,
        cond_caps,
        Expansion::Plain,
    );
}

#[allow(clippy::too_many_arguments)]
fn expand_with(
    out: &mut String,
    template: &str,
    input: &RewriteInput,
    cur_uri: &str,
    cur_query: &str,
    env: &BTreeMap<String, String>,
    rule_caps: &[Option<String>],
    cond_caps: &[Option<String>],
    mut mode: Expansion<'_, '_>,
) {
    // Byte-scan the template directly (no `Vec<char>` allocation). All the special
    // markers (`%`, `{`, `}`, `$`, `\`, digits) are ASCII, so byte positions are
    // valid `str` boundaries and multibyte UTF-8 is copied intact in the run below.
    let b = template.as_bytes();
    let n = b.len();
    // Common case: no markers at all -> copy the template unchanged.
    if !b.iter().any(|&c| matches!(c, b'%' | b'$' | b'\\')) {
        out.push_str(template);
        return;
    }
    out.reserve(template.len());
    let mut i = 0;
    while i < n {
        match b[i] {
            b'%' if i + 1 < n && b[i + 1] == b'{' => {
                // %{VAR}
                if let Some(end) = find_byte(b, i + 2, b'}') {
                    let name = &template[i + 2..end];
                    let start = out.len();
                    resolve_var_into(out, name, input, cur_uri, cur_query, env);
                    match &mut mode {
                        Expansion::Plain => {}
                        Expansion::Subst(e) => {
                            if e.escape_pct && !(e.uri_escaped && var_reads_working_uri(name)) {
                                escape_var_value(out, start);
                            }
                        }
                        Expansion::TestString { escaped, .. } => {
                            if var_reads_working_uri(name) && out.len() > start {
                                escaped.push(start..out.len());
                            }
                        }
                    }
                    i = end + 1;
                    continue;
                }
                out.push('%');
                i += 1;
            }
            b'%' if i + 1 < n && b[i + 1].is_ascii_digit() => {
                let k = (b[i + 1] - b'0') as usize;
                if let Some(Some(val)) = cond_caps.get(k) {
                    match &mut mode {
                        Expansion::Plain => out.push_str(val),
                        Expansion::Subst(e) => {
                            let from = e
                                .cond_escaped
                                .and_then(|c| c.get(k))
                                .filter(|spans| !spans.is_empty())
                                .map_or(Provenance::Literal, |spans| Provenance::Spans(spans));
                            push_backref(out, val, e, from);
                        }
                        Expansion::TestString {
                            escaped,
                            cond_escaped,
                        } => {
                            let start = out.len();
                            out.push_str(val);
                            if let Some(spans) = cond_escaped.and_then(|c| c.get(k)) {
                                escaped
                                    .extend(spans.iter().map(|r| start + r.start..start + r.end));
                            }
                        }
                    }
                }
                i += 2;
            }
            b'$' if i + 1 < n && b[i + 1].is_ascii_digit() => {
                let k = (b[i + 1] - b'0') as usize;
                if let Some(Some(val)) = rule_caps.get(k) {
                    match &mut mode {
                        Expansion::Plain => out.push_str(val),
                        Expansion::Subst(e) => {
                            let from = if e.uri_escaped {
                                Provenance::Escaped
                            } else {
                                Provenance::Literal
                            };
                            push_backref(out, val, e, from);
                        }
                        Expansion::TestString { escaped, .. } => {
                            let start = out.len();
                            out.push_str(val);
                            escaped.push(start..out.len());
                        }
                    }
                }
                i += 2;
            }
            b'\\' if i + 1 < n => {
                // Backslash escape: emit the next (possibly multibyte) char literally.
                if let Some(ch) = template[i + 1..].chars().next() {
                    out.push(ch);
                    i += 1 + ch.len_utf8();
                } else {
                    i += 1;
                }
            }
            _ => {
                // Copy a run of plain bytes up to the next marker in one shot.
                let start = i;
                i += 1;
                while i < n && !matches!(b[i], b'%' | b'$' | b'\\') {
                    i += 1;
                }
                out.push_str(&template[start..i]);
            }
        }
    }
}

#[inline]
fn find_byte(b: &[u8], start: usize, target: u8) -> Option<usize> {
    b[start..]
        .iter()
        .position(|&c| c == target)
        .map(|p| start + p)
}

// ===========================================================================
// Evaluation
// ===========================================================================

pub(super) struct EvalState {
    pub(super) uri: String,
    pub(super) query: String,
    pub(super) env: BTreeMap<String, String>,
    /// Env keys set via `[E=...]`, recorded in insertion order for the outcome.
    pub(super) env_order: Vec<String>,
    /// Keys of `env_order` whose latest `[E=]` was an `[E=!VAR]` unset. Their
    /// `env` slot holds `""` so a later `%{ENV:VAR}` in this pass no longer sees
    /// the request seed (unset and empty expand alike).
    pub(super) env_unset: Vec<String>,
    /// Captures from the last successfully-matched condition (`%N`), slots 0..=9.
    /// A fixed stack array (not a `Vec`): rewrite captures are always exactly the
    /// 10 backref slots, so this removes a heap allocation per matched rule / cond
    /// — on the ~130-rule front-controller vhost that is up to ~130 fewer Vec
    /// allocations per request. Indexed via `.get()` in `expand`, so it is
    /// behavior-identical to the former `Vec<Option<String>>` (an empty Vec and an
    /// all-`None` array both expand a missing `%N` to empty).
    pub(super) last_cond_caps: [Option<String>; 10],
    /// True while the prefilter match set (computed from the initial URI) is
    /// still valid. Cleared once a rule rewrites `uri`, after which rules are
    /// evaluated normally (the cheap, rare fallback).
    pub(super) prefilter_valid: bool,
    /// The working URI is an absolute URL from a substitution without `[R]`;
    /// `evaluate` promotes it to a 302 once the rule loop ends (#665).
    pub(super) pending_absolute: bool,
    /// The working URI holds a substitution (URI-escaped, decoded once by the
    /// pipeline) instead of the decoded request path: a value taken from it is
    /// already escaped, so its `%` is not literal.
    pub(super) uri_escaped: bool,
    /// Escaped spans of `last_cond_caps` (`None`: every capture is literal).
    pub(super) last_cond_escaped: Option<CondEscaped>,
    /// Count of `[N]`/`[next]` restarts so far. Lives here (not in `run_pass`) so
    /// the guard accumulates ACROSS passes: a `[N]` returns from `run_pass` to
    /// restart, so a per-call counter would reset to 0 every restart and never
    /// fire (the guard was dead). OLS aborts a ruleset after MAX_ITERATIONS `[N]`
    /// jumps.
    pub(super) next_loops: usize,
    /// Set when a successfully-compiled fancy regex fails at match time. The
    /// current rule becomes a terminal fail-closed outcome.
    pub(super) regex_failed: bool,
}

impl EvalState {
    fn record_env(&mut self, k: String, v: String) {
        // `[E=!VAR]` unsets VAR (mod_rewrite; OLS `RequestVars::setEnv`, #780).
        if let Some(name) = k.strip_prefix('!') {
            if name.is_empty() {
                return;
            }
            let name = name.to_string();
            if !self.env_unset.contains(&name) {
                self.env_unset.push(name.clone());
            }
            if !self.env_order.contains(&name) {
                self.env_order.push(name.clone());
            }
            self.env.insert(name, String::new());
            return;
        }
        self.env_unset.retain(|u| *u != k);
        if !self.env_order.contains(&k) {
            self.env_order.push(k.clone());
        }
        self.env.insert(k, v);
    }

    /// The outcome's env list; an unset is reported as `("!VAR", "")`
    /// ([`crate::EnvAssignment`]).
    pub(super) fn env_vec(&self) -> Vec<(String, String)> {
        self.env_order
            .iter()
            .filter_map(|k| {
                if self.env_unset.contains(k) {
                    return Some((format!("!{k}"), String::new()));
                }
                self.env.get(k).map(|v| (k.clone(), v.clone()))
            })
            .collect()
    }
}

pub(super) enum PassResult {
    /// A terminal rule fired (`[F]`/`[G]`/`[P]`/`[R]`); stop entirely.
    Terminal(RewriteOutcome),
    /// Pass finished (no terminal rule); caller decides whether to restart
    /// (based on whether the URI changed). `end` is set when an `[END]` rule
    /// fired, which forces the outer loop to stop regardless of URI change.
    Continue { end: bool },
    /// A `[N]`/`[next]` rule fired: restart the rule set from the top
    /// immediately (consuming a loop iteration / guard count).
    Restart,
}

/// Outcome of applying a single rule whose pattern + conditions matched.
enum RuleApply {
    /// A terminal action fired; stop the whole engine.
    Terminal(RewriteOutcome),
    /// The rule matched (and may have rewritten); `last` indicates `[L]`/`[END]`
    /// stopped the pass, `end` distinguishes `[END]` (also stop the restart loop
    /// + subsequent rulesets) from a plain `[L]`.
    Matched { last: bool, end: bool },
    /// `[N]`/`[next]`: restart from the top.
    Restart,
}

pub(super) fn run_pass(
    rs: &RuleSet,
    input: &RewriteInput,
    state: &mut EvalState,
    hits: Option<&PatternSet>,
) -> PassResult {
    let rules = &rs.rules;
    let mut idx = 0usize;
    while idx < rules.len() {
        let rule = &rules[idx];
        match apply_rule(rs, input, state, rule, hits) {
            None => {
                // Pattern or conditions did not match. Advance to the next
                // rule, but if THIS rule was `[C]`/chained, skip the
                // subsequent chained rules (OLS rewriteengine.cpp:1486-1496).
                let mut chained = rule.flags.chain;
                idx += 1;
                while chained && idx < rules.len() {
                    chained = rules[idx].flags.chain;
                    idx += 1;
                }
            }
            Some(RuleApply::Terminal(outcome)) => {
                return PassResult::Terminal(outcome);
            }
            Some(RuleApply::Restart) => {
                // `[N]`/`[next]`: the guard count lives in `EvalState` so it
                // accumulates across restarts (a per-call counter reset every
                // restart and never fired — the guard was dead). OLS aborts a
                // ruleset after MAX_ITERATIONS `[N]` jumps to break a `[N]` loop.
                state.next_loops += 1;
                if state.next_loops > MAX_ITERATIONS {
                    // Possible infinite loop; bail (OLS logs + breaks).
                    return PassResult::Continue { end: false };
                }
                return PassResult::Restart;
            }
            Some(RuleApply::Matched { last, end }) => {
                if last {
                    // `[L]`/`[END]`: stop this pass. `end` propagates the
                    // restart-loop / cross-ruleset stop up to `evaluate`.
                    return PassResult::Continue { end };
                }
                // `[S=n]`: skip the next n rules. OLS advances by skip+1.
                // Saturate: a huge skip (e.g. usize::MAX) must end the pass,
                // never wrap back to the same rule.
                idx = idx.saturating_add(1).saturating_add(rule.flags.skip);
            }
        }
    }
    PassResult::Continue { end: false }
}

/// Try one rule against the current state. Returns `None` if the pattern or
/// conditions did not match; otherwise applies the rule's effects (env sets,
/// substitution) and returns how the loop should proceed.
fn apply_rule(
    rs: &RuleSet,
    input: &RewriteInput,
    state: &mut EvalState,
    rule: &Rule,
    hits: Option<&PatternSet>,
) -> Option<RuleApply> {
    // Prefilter fast-reject: if the multi-pattern set says this rule's pattern
    // did not match the (initial) target, skip the per-rule regex entirely. Skipped
    // for total-match rules (they match every target, so the lookup is pure waste).
    if state.prefilter_valid && rule.match_total.is_none() {
        if let (Some(idx), Some(h), Some(pf)) = (rule.prefilter_idx, hits, rs.prefilter.as_ref()) {
            if !pf.contains(h, idx) {
                return None;
            }
        }
    }
    // Fast reject before the regex: an anchored, case-sensitive, non-negated pattern
    // can only match a target that begins with its literal prefix. `literal_prefix`
    // is empty unless those conditions hold, so this never changes which rules match.
    // Scoped so `match_target`'s borrow of `state.uri` is released before the mutable
    // cond pre-screen below (the build is a cheap `Cow::Borrowed` in the common case).
    if !rule.literal_prefix.is_empty() {
        let match_target = select_match_target(rule, input, &state.uri);
        if !match_target.as_bytes().starts_with(&rule.literal_prefix) {
            return None;
        }
    }

    // Cond pre-screen: when none of this rule's conds reference a rule backref `$N`
    // (`!conds_need_rule_caps`), they depend only on `%{VAR}` (request-scoped) and
    // `%N` (earlier conds in THIS rule) — neither needs the pattern's captures. So
    // evaluate them first and bail before the (potentially expensive) regex when one
    // fails. This is a pure reject: a `$N`-free cond yields the identical boolean
    // before or after `captures()` (same vars, same in-pass `%N` order), and conds
    // have no observable side effects (file stats are cached; `%N` caps are reset
    // per-rule), so the screen returns `None` iff the real cond pass would. A pass is
    // final: nothing between here and the rule's effects touches the uri/query/env
    // the conds read, so a re-run would recompute the same verdict and the same `%N`
    // captures, which stay in `last_cond_caps`. Placed AFTER the literal_prefix reject
    // so a prefix-rejected rule never pays a cond stat. Kills the per-request regex
    // `captures()` on method/header-gated rules like `RewriteRule ^/(.*)$ … [P]`
    // cond'd on `%{REQUEST_METHOD}`, which otherwise matches every URI and captures
    // on every GET.
    let prescreened = !rule.conds_need_rule_caps && !rule.conds.is_empty();
    if prescreened {
        // Mirror the per-rule reset at the real cond loop below so a `%N` reference to
        // an unset slot expands empty (not a stale prior-rule value).
        state.last_cond_caps = empty_caps();
        state.last_cond_escaped = None;
        if !eval_conditions(&rule.conds, input, state, &[]) {
            if state.regex_failed {
                return Some(RuleApply::Terminal(RewriteOutcome::Failed {
                    env: state.env_vec(),
                    reason: "rewrite condition regex failed at match time",
                }));
            }
            return None;
        }
    }

    let match_target = select_match_target(rule, input, &state.uri);

    // Build the $0..$9 vector only when something references it; otherwise skip the
    // per-match 10-slot String allocation entirely (common for -/[F]/[L]/redirects).
    // A recognized total-match pattern always matches the whole target, so skip
    // `captures()` (and the regex run) and synthesize the slots directly — provably
    // identical to running the regex (see `synthesize_total_caps`).
    // `.` never matches a newline (a decoded `%0A`), so the whole-match shortcut
    // only holds for a target without one; otherwise run the regex (#953).
    let rule_caps = match rule
        .match_total
        .filter(|_| !match_target.as_bytes().contains(&b'\n'))
    {
        Some(tm) => {
            if rule.needs_rule_caps {
                synthesize_total_caps(match_target.as_ref(), tm)
            } else {
                empty_caps()
            }
        }
        None => {
            let caps = match rule.pattern.captures_checked(match_target.as_ref()) {
                Ok(caps) => caps,
                Err(()) => {
                    return Some(RuleApply::Terminal(RewriteOutcome::Failed {
                        env: state.env_vec(),
                        reason: "rewrite rule regex failed at match time",
                    }));
                }
            };
            let matched = caps.is_some() ^ rule.negate;
            if !matched {
                return None;
            }
            if rule.needs_rule_caps {
                capture_vec(match_target.as_ref(), rule, caps)
            } else {
                empty_caps()
            }
        }
    };

    // OLS resets `m_condMatches` to 0 at the start of each rule's cond loop
    // (rewriteengine.cpp:889), so `%N` only refers to a cond matched *within
    // this rule*; a rule that references `%1` without a matching regex cond
    // sees an empty value, not the previous rule's captures. Mirror that by
    // clearing the recorded cond captures before evaluating this rule's conds.
    if !prescreened {
        state.last_cond_caps = empty_caps();
        state.last_cond_escaped = None;
        if !eval_conditions(&rule.conds, input, state, &rule_caps) {
            if state.regex_failed {
                return Some(RuleApply::Terminal(RewriteOutcome::Failed {
                    env: state.env_vec(),
                    reason: "rewrite condition regex failed at match time",
                }));
            }
            return None;
        }
    }

    // Apply `[E=...]` env sets (always, even for `-` substitution). On a `[P]` rule,
    // OLS treats `E=Proxy-Host:value` as the upstream Host override, not an env var.
    let mut proxy_host: Option<String> = None;
    for (k, v) in &rule.flags.env_sets {
        let key = expand(
            k,
            input,
            &state.uri,
            &state.query,
            &state.env,
            &rule_caps,
            &state.last_cond_caps,
        );
        let val = expand(
            v,
            input,
            &state.uri,
            &state.query,
            &state.env,
            &rule_caps,
            &state.last_cond_caps,
        );
        if rule.flags.proxy && key.eq_ignore_ascii_case("Proxy-Host") {
            proxy_host = Some(val);
            continue;
        }
        state.record_env(key, val);
    }

    // `[F]` forbidden.
    if rule.flags.forbidden {
        return Some(RuleApply::Terminal(RewriteOutcome::Forbidden {
            env: state.env_vec(),
        }));
    }

    // `[G]` gone.
    if rule.flags.gone {
        return Some(RuleApply::Terminal(RewriteOutcome::Gone {
            env: state.env_vec(),
        }));
    }

    // Compute the substitution (unless `-`).
    let no_subst = rule.subst == "-";
    let mut subst_target: Option<String> = None;

    if !no_subst {
        // OLS builds every target from literal values; `[NE]` only leaves an
        // external URL unescaped (a Location, the 302 an absolute target becomes,
        // a `[P]` upstream), so there a value's `%` passes through verbatim.
        let escape_pct =
            !(rule.flags.noescape && (rule.flags.redirect.is_some() || rule.flags.proxy));
        let mut expanded = expand_subst(rule, input, state, &rule_caps, escape_pct);
        if escape_pct && rule.flags.noescape && is_absolute_uri(&expanded) {
            expanded = expand_subst(rule, input, state, &rule_caps, false);
        }
        // Apache percent-encodes the substitution by default; `[NE]`
        // (`noescape`) disables it. We escape the path portion (everything
        // before the first `?`) with the URI-path-safe set and the `?query`
        // tail with the query-safe set — leaving existing `%XX` triplets
        // untouched (no double-encoding) so QSA merges / pre-encoded targets
        // behave unchanged.
        let escaped = if rule.flags.noescape {
            expanded
        } else {
            escape_subst(&expanded)
        };
        subst_target = Some(escaped);
    }

    // `[P]` proxy: substitution is the upstream URL. (security #268) Apache merges
    // the original query into the proxied target unless the substitution carries its
    // own `?`; a trailing bare `?` DISCARDS it ([QSD]-style). The old code silently
    // dropped every inbound query, breaking token-bearing proxied URLs.
    if rule.flags.proxy {
        let target = subst_target.unwrap_or_else(|| state.uri.clone());
        let effective_query = if rule.flags.qsd { "" } else { &state.query };
        // #622: [QSA] must merge the original query even when the
        // substitution carries its own `?query` (same merge as redirects).
        let target = apply_query_to_location(&target, effective_query, rule.flags.qsa, input);
        return Some(RuleApply::Terminal(RewriteOutcome::Proxy {
            target_url: target,
            proxy_host,
            env: state.env_vec(),
            authority_substituted: !no_subst && super::proxy_authority_substituted(&rule.subst),
        }));
    }

    // `[R=NNN]` / `[R]`.
    if let Some(code) = rule.flags.redirect {
        // A non-3xx `[R=NNN]` (2xx/4xx/5xx) is NOT a redirect: Apache sets the
        // status and stops, with no `Location` header and no "document has
        // moved" body. The CORS preflight rule `- [R=200,L,...]` is the live
        // example. Emit the distinct `Status` outcome instead of `Redirect`.
        if !(300..400).contains(&code) {
            // The substitution (e.g. `$1` in `^(.*)$ $1 [R=200,L]`) is computed
            // but discarded: there is no Location and no body to produce.
            return Some(RuleApply::Terminal(RewriteOutcome::Status {
                code,
                suppress_body: true,
                env: state.env_vec(),
            }));
        }

        let location = match subst_target.as_deref() {
            Some(target) => {
                let (path, q) = split_subst(target);
                let path = if is_absolute_uri(path) {
                    path.to_string()
                } else {
                    resolve_subst_path(path, rs, input)
                };
                match q {
                    Some(q) => format!("{path}?{q}"),
                    None => path,
                }
            }
            None => state.uri.clone(),
        };
        // QSA on a redirect appends original query; QSD discards it.
        let effective_query = if rule.flags.qsd { "" } else { &state.query };
        let location = apply_query_to_location(&location, effective_query, rule.flags.qsa, input);
        // Apache fully-qualifies a path-only redirect target to an absolute URL
        // (scheme + authority from the request) before sending `Location`.
        let location = fully_qualify_redirect(&location, input);
        return Some(RuleApply::Terminal(RewriteOutcome::Redirect {
            code,
            location,
            env: state.env_vec(),
        }));
    }

    // Plain (internal) rewrite.
    if let Some(target) = subst_target {
        let (path, q) = split_subst(&target);
        // OLS promotes an absolute-URI result to a 302 only AFTER the rule loop, so
        // later rules still apply ([F], [E=], ...); see `evaluate` (#665).
        let absolute = is_absolute_uri(path);
        let new_uri = if absolute {
            path.to_string()
        } else {
            resolve_subst_path(path, rs, input)
        };
        state.pending_absolute = absolute;
        // `[QSD]` discards the current query before any merge.
        let base_query = if rule.flags.qsd { "" } else { &state.query };
        let new_query = compute_query(q, base_query, rule.flags.qsa);
        state.uri = new_uri;
        state.uri_escaped = true;
        state.query = new_query;
        // OLS `processRule` records every substitution as REDIRECT_STATUS for the
        // rules after it, which is what stops a Symfony-style
        // `%{ENV:REDIRECT_STATUS} =""` guard re-matching its own target (#880).
        // Overlay only: not part of the outcome env.
        state
            .env
            .insert("REDIRECT_STATUS".to_string(), "200".to_string());
        // The URI changed, so the prefilter set (computed from the initial URI)
        // no longer applies — evaluate remaining rules in full.
        state.prefilter_valid = false;
    } else if rule.flags.qsd {
        // `-` substitution with `[QSD]` still discards the query.
        state.query.clear();
    }

    if rule.flags.next {
        return Some(RuleApply::Restart);
    }

    Some(RuleApply::Matched {
        last: rule.flags.last,
        end: rule.flags.end,
    })
}

/// Pick the target a rule's pattern is matched against. Apache `.htaccess` rules
/// match the per-directory-relative path with the leading slash stripped
/// (`^threads/...`), while LiteSpeed inline vhost rules in this install anchor with
/// a leading slash (`^/tools\.json$`). In a PER-DIRECTORY context the strip always
/// happens first — for every pattern shape, `^/...` included — because matching a
/// nested file's slashed pattern against the FULL URI makes its deny/front-controller
/// rules inert or capture the wrong span. The slashed form is only honored for
/// vhost-level rulesets (no prefix). Borrows `uri` where possible (no per-rule
/// allocation in the common case).
fn select_match_target<'a>(rule: &Rule, input: &RewriteInput, uri: &'a str) -> Cow<'a, str> {
    if input.per_directory_prefix.is_some() {
        return rule_match_target(input, uri);
    }
    if pattern_expects_leading_slash(&rule.pattern_src) {
        if uri.starts_with('/') {
            Cow::Borrowed(uri)
        } else {
            Cow::Owned(format!("/{}", uri))
        }
    } else {
        rule_match_target(input, uri)
    }
}

pub(super) fn rule_match_target<'a>(input: &RewriteInput, uri: &'a str) -> Cow<'a, str> {
    if let Some(prefix) = &input.per_directory_prefix {
        let stripped = uri.trim_start_matches('/');
        if let Some(rest) = stripped.strip_prefix(prefix.as_str()) {
            return Cow::Borrowed(rest);
        }
        return Cow::Borrowed(stripped);
    }
    Cow::Borrowed(uri.trim_start_matches('/'))
}

/// True if the pattern is explicitly anchored to a leading slash, e.g.
/// `^/tools\.json$` or `^/(.*)$`. Such patterns (LiteSpeed inline-rule style)
/// match the slashed path; Apache `.htaccess`-style patterns (`^threads/...`)
/// match the slash-stripped path.
pub(super) fn pattern_expects_leading_slash(src: &str) -> bool {
    let after_anchor = src.strip_prefix('^').unwrap_or(src);
    after_anchor.starts_with('/') || after_anchor.starts_with("\\/")
}

/// Build the `$0..$9` capture vector. `$0` is the whole match.
/// An empty 10-slot capture array (all `None`) on the stack — no heap allocation.
#[inline]
fn empty_caps() -> [Option<String>; 10] {
    std::array::from_fn(|_| None)
}

fn capture_vec(target: &str, _rule: &Rule, caps: Option<Caps>) -> [Option<String>; 10] {
    let mut v = empty_caps();
    if let Some(c) = caps {
        for (i, slot) in v.iter_mut().enumerate() {
            *slot = c.get(i).map(|s| s.to_string());
        }
        if v[0].is_none() {
            v[0] = Some(target.to_string());
        }
    }
    v
}

/// Synthesize the `$0..$9` slots for a recognized total-match rule without running
/// the regex. For `.*`/`^.*$`/`(.*)`/`^(.*)$` the whole match is the entire target,
/// so `$0` = the target; `(.*)`/`^(.*)$` additionally capture group 1 = the target.
/// This is byte-identical to `capture_vec` over the real regex captures (verified
/// by `synthesized_total_caps_match_regex` + the golden/ols_parity suites).
fn synthesize_total_caps(target: &str, tm: TotalMatch) -> [Option<String>; 10] {
    let mut v = empty_caps();
    v[0] = Some(target.to_string());
    if matches!(tm, TotalMatch::OneGroup) {
        v[1] = Some(target.to_string());
    }
    v
}

/// Evaluate a rule's condition list, honoring `[OR]` chaining and per-cond `%N`
/// capture recording. Returns the overall AND/OR result. On success, the last
/// matched condition's captures are stored in `state.last_cond_caps`.
fn eval_conditions(
    conds: &[Cond],
    input: &RewriteInput,
    state: &mut EvalState,
    rule_caps: &[Option<String>],
) -> bool {
    if conds.is_empty() {
        return true;
    }
    // Mirror OLS `processRule`'s cond loop (rewriteengine.cpp:891-906) exactly:
    //
    //   while cond:
    //     if cond FAILED:
    //         if not [OR]: rule fails
    //         else: advance to next cond (try the rest of the OR group)
    //     else (cond PASSED):
    //         skip forward over the remaining [OR]-linked conds (short-circuit)
    //     advance once more
    //
    // The short-circuit matters: once a cond in an `[OR]` group passes, the
    // remaining members are NOT evaluated, so `%N` captures come from the
    // FIRST passing cond of the group (not the last). It also means a later
    // member's side effects / file stats never run.
    let mut i = 0;
    while i < conds.len() {
        let cond = &conds[i];
        let passed = eval_one_cond(cond, input, state, rule_caps);
        // An unevaluable cond must fail the rule (the caller turns it into a
        // fail-closed outcome) before negation or an `[OR]` sibling can pass it.
        if state.regex_failed {
            return false;
        }
        if passed {
            // Passed: skip the rest of this OR group.
            while conds[i].or_next && i + 1 < conds.len() {
                i += 1;
            }
        } else if !cond.or_next || i + 1 >= conds.len() {
            // Failed and either not OR-linked, OR a dangling trailing `[OR]` with no
            // following member to satisfy the group: the rule's cond list fails. A lone
            // trailing `[OR]` is thus a no-op (matches Apache), not a rule that fires
            // unconditionally.
            return false;
        }
        // else: failed but OR-linked with a next cond -> fall through to try it.
        i += 1;
    }
    true
}

std::thread_local! {
    /// Reused per-cond expansion buffers (the test string + a second for a lexical/numeric rhs).
    /// An expanded cond test is TRANSIENT — consumed by the regex match / file test / comparison
    /// and dropped before the next cond — so ONE thread-local buffer serves every cond and every
    /// request with zero per-cond allocation. This was the #1 per-request heap allocation on a
    /// heavy-`.htaccess` vhost (one `expand` String per RewriteCond × dozens of conds × every
    /// request). Captures still own their Strings (they escape into `last_cond_caps`).
    static COND_SCRATCH: std::cell::RefCell<(String, String)> =
        std::cell::RefCell::new((String::with_capacity(256), String::with_capacity(64)));
}

fn eval_one_cond(
    cond: &Cond,
    input: &RewriteInput,
    state: &mut EvalState,
    rule_caps: &[Option<String>],
) -> bool {
    COND_SCRATCH.with(|cell| match cell.try_borrow_mut() {
        Ok(mut guard) => eval_one_cond_in(cond, input, state, rule_caps, &mut guard),
        // A stat or header callback re-entered `evaluate` while this thread's scratch
        // is in use: the nested condition gets its own buffers instead of a panic.
        Err(_) => eval_one_cond_in(cond, input, state, rule_caps, &mut Default::default()),
    })
}

fn eval_one_cond_in(
    cond: &Cond,
    input: &RewriteInput,
    state: &mut EvalState,
    rule_caps: &[Option<String>],
    scratch: &mut (String, String),
) -> bool {
    let (test, rhs_buf) = scratch;
    test.clear();
    let mut escaped = Vec::new();
    let mode = if state.uri_escaped {
        Expansion::TestString {
            escaped: &mut escaped,
            cond_escaped: state.last_cond_escaped.as_ref(),
        }
    } else {
        Expansion::Plain
    };
    expand_with(
        test,
        &cond.test_string,
        input,
        &state.uri,
        &state.query,
        &state.env,
        rule_caps,
        &state.last_cond_caps,
        mode,
    );

    // %N captures are committed only if the condition ultimately PASSES (below):
    // a NEGATED regex whose pattern happens to match makes the cond evaluate
    // false, so it must not leak `%1`/`%2` to a later member of an `[OR]` group.
    let mut pending_caps = None;
    let mut pending_escaped = None;
    let result = match &cond.pattern {
        CondPattern::Regex(re, _) => match re.captures_checked(test.as_str()) {
            Ok(Some(c)) => {
                let mut caps = empty_caps();
                for (i, slot) in caps.iter_mut().enumerate() {
                    *slot = c.get(i).map(|s| s.to_string());
                }
                if !escaped.is_empty() {
                    pending_escaped = capture_escaped_spans(test, &c, &escaped);
                }
                pending_caps = Some(caps);
                true
            }
            Ok(None) => false,
            Err(()) => {
                state.regex_failed = true;
                false
            }
        },
        CondPattern::FileTest(kind) => file_test(input, test.as_str(), *kind),
        CondPattern::UrlAccess => true,
        CondPattern::Lexical(ord, rhs) => {
            rhs_buf.clear();
            expand_into(
                rhs_buf,
                rhs,
                input,
                &state.uri,
                &state.query,
                &state.env,
                rule_caps,
                &state.last_cond_caps,
            );
            // OLS compares with strcmp/strcasecmp (NC). Replicate the case folding so `[NC]`
            // lexical comparisons match; the non-NC path compares the buffers directly (no copy).
            let c = if cond.nocase {
                test.to_ascii_lowercase().cmp(&rhs_buf.to_ascii_lowercase())
            } else {
                test.as_str().cmp(rhs_buf.as_str())
            };
            match ord {
                Ordering::Less => c == std::cmp::Ordering::Less,
                Ordering::Greater => c == std::cmp::Ordering::Greater,
                Ordering::Equal => c == std::cmp::Ordering::Equal,
                Ordering::LessEqual => c != std::cmp::Ordering::Greater,
                Ordering::GreaterEqual => c != std::cmp::Ordering::Less,
            }
        }
        CondPattern::Numeric(op, rhs) => {
            rhs_buf.clear();
            expand_into(
                rhs_buf,
                rhs,
                input,
                &state.uri,
                &state.query,
                &state.env,
                rule_caps,
                &state.last_cond_caps,
            );
            // OLS uses strtoll (base 10), which parses a leading integer prefix
            // and yields 0 for a non-numeric string.
            let lhs = parse_leading_i64(test.as_str());
            let rhs_num = parse_leading_i64(rhs_buf.as_str());
            match op {
                NumOp::Eq => lhs == rhs_num,
                NumOp::Ne => lhs != rhs_num,
                NumOp::Gt => lhs > rhs_num,
                NumOp::Lt => lhs < rhs_num,
                NumOp::Ge => lhs >= rhs_num,
                NumOp::Le => lhs <= rhs_num,
            }
        }
    };

    let passed = result ^ cond.negate;
    if passed {
        if let Some(caps) = pending_caps {
            state.last_cond_caps = caps;
            state.last_cond_escaped = pending_escaped;
        }
    }
    passed
}

/// The escaped spans of each capture group, relative to the capture.
fn capture_escaped_spans(
    test: &str,
    caps: &Caps<'_>,
    escaped: &[Range<usize>],
) -> Option<CondEscaped> {
    let mut out: CondEscaped = Box::new(std::array::from_fn(|_| Vec::new()));
    let mut any = false;
    for (i, slot) in out.iter_mut().enumerate() {
        let Some(group) = caps.get(i) else {
            continue;
        };
        // A group is a subslice of the test string, so its offset is the pointer distance.
        let start = (group.as_ptr() as usize).wrapping_sub(test.as_ptr() as usize);
        let end = start + group.len();
        for r in escaped {
            let (s, e) = (r.start.max(start), r.end.min(end));
            if s < e {
                slot.push(s - start..e - start);
                any = true;
            }
        }
    }
    any.then_some(out)
}

/// Parse a leading base-10 integer the way C's `strtoll` does: skip leading
/// whitespace, accept an optional sign, then as many digits as possible;
/// anything else (or no digits) yields 0.
fn parse_leading_i64(s: &str) -> i64 {
    let s = s.trim_start();
    let bytes = s.as_bytes();
    let mut i = 0;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        i += 1;
    }
    let start_digits = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == start_digits {
        return 0;
    }
    // strtoll saturates on overflow.
    s[..i]
        .parse()
        .unwrap_or(if bytes[0] == b'-' { i64::MIN } else { i64::MAX })
}

/// Apply a `-f/-d/-l/-s/-x` test to `path`.
fn file_test(input: &RewriteInput, path: &str, kind: FileTestKind) -> bool {
    let tests = match &input.stat {
        StatSource::Precomputed(t) => Some(*t),
        StatSource::Live(_) | StatSource::LiveTests(_) => memo_live_tests(input, path),
        StatSource::None => None,
    };
    // A live `Metadata` hit derives `exists: true`, so `-e` holds for it as before.
    tests.is_some_and(|t| match kind {
        FileTestKind::File => t.is_file,
        FileTestKind::Dir => t.is_dir,
        FileTestKind::Link => t.is_link,
        FileTestKind::Size => t.is_nonempty,
        FileTestKind::Exists => t.exists || t.is_file || t.is_dir,
        FileTestKind::Exec => t.is_exec,
    })
}

fn memo_live_tests(input: &RewriteInput, path: &str) -> Option<FileTests> {
    let hit = FS_MEMO.with(|m| {
        let m = m.borrow();
        (m.active && m.test_valid && m.test_path == path).then_some(m.test)
    });
    if let Some(tests) = hit {
        return tests;
    }
    let p = std::path::Path::new(path);
    let tests = match &input.stat {
        StatSource::Live(f) => f(p).map(|md| FileTests::from_metadata(&md)),
        StatSource::LiveTests(f) => f(p),
        StatSource::Precomputed(_) | StatSource::None => None,
    };
    FS_MEMO.with(|m| {
        let m = &mut *m.borrow_mut();
        if m.active {
            m.test_path.clear();
            m.test_path.push_str(path);
            m.test = tests;
            m.test_valid = true;
        }
    });
    tests
}

/// Split a substitution into `(path, Option<query>)` on the first unescaped `?`.
fn split_subst(subst: &str) -> (&str, Option<&str>) {
    match subst.find('?') {
        Some(idx) => (&subst[..idx], Some(&subst[idx + 1..])),
        None => (subst, None),
    }
}

/// Resolve a substitution path into the new URI. Absolute (`/...`) and
/// scheme-bearing targets are used as-is; relative targets are joined to
/// `RewriteBase`, or — when no base is set — to the rule set's OWN directory
/// (the per-directory prefix), exactly as Apache resolves a relative
/// substitution in a `.htaccess`. Ignoring the per-directory context here made
/// every relative substitution in a nested ruleset resolve against `/`.
fn resolve_subst_path(path: &str, rs: &RuleSet, input: &RewriteInput) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    if path.starts_with('/') || has_scheme(path) {
        return path.to_string();
    }
    let base = match rs.base.as_deref() {
        Some(b) => b.to_string(),
        None => match input.per_directory_prefix.as_deref() {
            // "sub/" (relative to docroot, no leading slash) -> URL space "/sub".
            Some(prefix) if !prefix.is_empty() => format!("/{}", prefix),
            _ => "/".to_string(),
        },
    };
    let base = base.trim_end_matches('/');
    format!("{base}/{path}")
}

/// The scheme set OLS treats as an absolute substitution result.
pub(super) fn is_absolute_uri(s: &str) -> bool {
    const SCHEMES: [&str; 9] = [
        "http://",
        "https://",
        "ftp://",
        "gopher://",
        "mailto:",
        "news:",
        "nntp://",
        "ws://",
        "wss://",
    ];
    SCHEMES.iter().any(|p| {
        s.get(..p.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(p))
    })
}

fn has_scheme(s: &str) -> bool {
    if let Some(idx) = s.find("://") {
        s[..idx]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
            && idx > 0
    } else {
        false
    }
}

/// Percent-encode a substitution the way Apache `mod_rewrite` does by default
/// (i.e. when `[NE]` is absent). Only the **path** portion (everything before
/// the first `?`) is escaped with the path-safe set; the `?query` tail — if
/// any — keeps its `&`/`=`/existing-`%XX` structure but gets URI-forbidden
/// bytes (space/controls/non-ASCII/`#`/delimiters) percent-encoded, since `$N`
/// captures expand from the DECODED request path and must not yield an
/// unparsable target downstream.
///
/// Escaping rules (mirroring Apache's `T_ESCAPE_PATH` / `ap_escape_path_segment`
/// applied across the whole path, so reserved path delimiters survive):
///   * Unreserved chars `A-Z a-z 0-9 - _ . ~` and the path-meaningful set
///     `/ : @ & = + $ , ; ! * ' ( )` are kept verbatim.
///   * An already-valid `%XX` triplet (two hex digits) is kept verbatim — no
///     double-encoding (Apache does not re-escape an existing escape).
///   * Everything else (space -> `%20`, `<`, `>`, `"`, `{`, `}`, `|`, `\`, `^`,
///     control chars, non-ASCII bytes, ...) is percent-encoded.
fn escape_subst(subst: &str) -> String {
    let (path, query) = split_subst(subst);
    let mut out = String::with_capacity(subst.len());
    // An absolute substitution's `scheme://authority` is not a path: escaping it
    // turned an IPv6 literal's brackets into `%5B`/`%5D`, an unresolvable host.
    // Escape only what the authority grammar forbids there and the path after it.
    let path = match path.find("://").filter(|_| has_scheme(path)) {
        Some(idx) => {
            let auth_start = idx + 3;
            let auth_end = path[auth_start..]
                .find('/')
                .map_or(path.len(), |i| auth_start + i);
            out.push_str(&path[..auth_start]);
            for b in path[auth_start..auth_end].bytes() {
                if is_authority_safe(b) {
                    out.push(b as char);
                } else {
                    out.push('%');
                    out.push(hex_upper(b >> 4));
                    out.push(hex_upper(b & 0xf));
                }
            }
            &path[auth_end..]
        }
        None => path,
    };
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            // Preserve an existing `%XX` escape verbatim.
            out.push('%');
            out.push(bytes[i + 1] as char);
            out.push(bytes[i + 2] as char);
            i += 3;
            continue;
        }
        if is_path_safe(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0xf));
        }
        i += 1;
    }
    if let Some(q) = query {
        out.push('?');
        // The query tail is no longer raw: `$N` captures expand from the
        // DECODED request path, so a capture can carry a literal space/control
        // byte into the query — an unparsable URI that used to fall back to
        // serving the PRE-rewrite target at the static terminal. Encode only
        // what the URI grammar forbids there; `&`/`=`/existing `%XX` survive
        // so QSA merges and pre-encoded targets behave unchanged.
        for b in q.bytes() {
            if is_query_safe(b) {
                out.push(b as char);
            } else {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b & 0xf));
            }
        }
    }
    out
}

/// RFC 3986 authority bytes: unreserved, sub-delims, `:` `@`, the IP-literal
/// brackets and a `%` (pct-encoded / IPv6 zone).
fn is_authority_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'['
                | b']'
                | b'%'
        )
}

/// Characters left verbatim in a rewrite-substitution's `?query` tail: RFC3986
/// unreserved + the query-meaningful delimiters (`&` `=` `+` `;` `,` `$` `:`
/// `@` `/` `?` `!` `*` `'` `(` `)` and a preserved `%`). Everything else —
/// space, controls, non-ASCII, `"`, `<`, `>`, `\`, `^`, `` ` ``, `{`, `|`,
/// `}`, `#`, `[`, `]` — is percent-encoded.
fn is_query_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_'
                | b'.'
                | b'~'
                | b'&'
                | b'='
                | b'+'
                | b';'
                | b','
                | b'$'
                | b':'
                | b'@'
                | b'/'
                | b'?'
                | b'!'
                | b'*'
                | b'\''
                | b'('
                | b')'
                | b'%'
                | b'['
                | b']'
        )
}

/// Characters Apache leaves unescaped in a rewrite-substitution path: the
/// RFC3986 unreserved set plus the reserved path delimiters (`pchar` + `/`).
fn is_path_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_'
                | b'.'
                | b'~'
                | b'/'
                | b':'
                | b'@'
                | b'&'
                | b'='
                | b'+'
                | b'$'
                | b','
                | b';'
                | b'!'
                | b'*'
                | b'\''
                | b'('
                | b')'
        )
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

/// Fully-qualify a 3xx redirect `Location`. Apache turns a path-only target
/// (`/foo`) into an absolute URL (`https://host:port/foo`) using the request's
/// scheme + authority. A target that already carries a scheme (`http://...`,
/// `https://...`) is returned unchanged. A protocol-relative `//host/...` and a
/// non-path target (e.g. a `mailto:`-style with a scheme) are left as-is.
fn fully_qualify_redirect(location: &str, input: &RewriteInput) -> String {
    if has_scheme(location) || location.starts_with("//") {
        return location.to_string();
    }
    // Only path-absolute targets get qualified; a relative one is unusual for
    // an external redirect, but if it slips through we still anchor it at `/`.
    if !location.starts_with('/') {
        // Leave genuinely odd values (e.g. already-built `host/path`) alone.
        return location.to_string();
    }
    let scheme = if input.https { "https" } else { "http" };
    // Authority: SERVER_NAME (the caller passes the request Host for an explicitly
    // mapped alias, #688), else the Host header. Include a non-default port only when
    // SERVER_PORT was supplied, is non-default, and is real (a UDS listener reports 0).
    let host: &str = if !input.server_name.is_empty() {
        &input.server_name
    } else {
        &input.host
    };
    if host.is_empty() {
        // No authority available — fall back to the bare path (cannot qualify).
        return location.to_string();
    }
    // If the host already includes a port (`example.com:8443`), don't add one.
    let host_has_port = host
        .rsplit(':')
        .next()
        .is_some_and(|p| p.parse::<u16>().is_ok())
        && host.contains(':');
    match input.server_port {
        Some(port) if port != 0 && !host_has_port && !is_default_port(port, input.https) => {
            format!("{scheme}://{host}:{port}{location}")
        }
        _ => format!("{scheme}://{host}{location}"),
    }
}

fn is_default_port(port: u16, https: bool) -> bool {
    (https && port == 443) || (!https && port == 80)
}

/// Compute the new query string given the substitution's `?query` part, the
/// current query, and the `[QSA]` flag.
fn compute_query(subst_query: Option<&str>, current: &str, qsa: bool) -> String {
    match subst_query {
        Some(q) => {
            if qsa && !current.is_empty() {
                if q.is_empty() {
                    current.to_string()
                } else {
                    format!("{q}&{current}")
                }
            } else {
                // A bare trailing `?` (q == "") clears the query (Apache
                // behavior for tracking-param stripping).
                q.to_string()
            }
        }
        None => {
            // No `?` in substitution: keep current query (Apache carries it).
            current.to_string()
        }
    }
}

/// For redirects, fold the query into the Location. With QSA, append the
/// original query. A substitution ending in `?` strips it.
fn apply_query_to_location(
    location: &str,
    current_query: &str,
    qsa: bool,
    _input: &RewriteInput,
) -> String {
    let (path, sub_q) = split_subst(location);
    let final_q = compute_query(sub_q, current_query, qsa);
    if final_q.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{final_q}")
    }
}

#[cfg(test)]
mod total_match_tests {
    use super::*;

    /// Stage-2 invariant: the slots synthesized for a total-match pattern are
    /// byte-identical to running the real regex through `capture_vec`, for every
    /// allowed form, at a NON-root multi-segment target (pins $0 for the unanchored
    /// `.*`/`(.*)` greedy-from-pos-0 case).
    #[test]
    fn synthesized_total_caps_match_regex() {
        for target in ["foo/bar/baz", "x", "a.b.c?d", ""] {
            for (src, tm) in [
                (".*", TotalMatch::NoGroup),
                ("^.*$", TotalMatch::NoGroup),
                ("(.*)", TotalMatch::OneGroup),
                ("^(.*)$", TotalMatch::OneGroup),
            ] {
                let re = CompiledRegex::compile(src, false, 0).unwrap();
                let caps = re.captures(target);
                // Replicate capture_vec exactly (it ignores its &Rule arg).
                let mut expected: [Option<String>; 10] = std::array::from_fn(|_| None);
                if let Some(c) = caps {
                    for (i, slot) in expected.iter_mut().enumerate() {
                        *slot = c.get(i).map(|s| s.to_string());
                    }
                    if expected[0].is_none() {
                        expected[0] = Some(target.to_string());
                    }
                }
                assert_eq!(
                    synthesize_total_caps(target, tm),
                    expected,
                    "src={src:?} target={target:?}"
                );
            }
        }
    }
}
