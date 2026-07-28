//! Rule-set evaluation internals: `%{VAR}` resolution, template expansion, the
//! per-pass loop driver ([`run_pass`]/`apply_rule`), and the substitution /
//! redirect / query-string machinery. The public [`super::evaluate`] entry
//! drives these.

use std::borrow::Cow;
use std::collections::BTreeMap;

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
/// `%{TIME_YEAR}`, `%{TIME_MON}`, ...), the subrequest lookups `%{LA-U:...}` /
/// `%{LA-F:...}`, and the internal-map `%{...}` forms. They fall through to the
/// env lookup below, which returns `""` for unknown names.
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
        "REMOTE_ADDR" => out.push_str(&input.remote_addr),
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
        // modified by any rewriting. Use the FROZEN `input.uri`/`input.query`, never the evolving
        // `cur_uri`/`cur_query` (a non-[L] rewrite mutates those, so a later pass would otherwise
        // see the rewritten URI here).
        "THE_REQUEST" => {
            out.push_str(&input.method);
            out.push(' ');
            out.push_str(&input.uri);
            if !input.query.is_empty() {
                out.push('?');
                out.push_str(&input.query);
            }
            out.push(' ');
            out.push_str(&input.protocol);
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
fn push_request_filename(out: &mut String, input: &RewriteInput, cur_uri: &str) {
    let rel = cur_uri.trim_start_matches('/');
    let dr = input.docroot.to_string_lossy();
    out.push_str(dr.trim_end_matches('/'));
    out.push('/');
    out.push_str(rel);
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
                    resolve_var_into(out, name, input, cur_uri, cur_query, env);
                    i = end + 1;
                    continue;
                }
                out.push('%');
                i += 1;
            }
            b'%' if i + 1 < n && b[i + 1].is_ascii_digit() => {
                let k = (b[i + 1] - b'0') as usize;
                if let Some(Some(val)) = cond_caps.get(k) {
                    out.push_str(val);
                }
                i += 2;
            }
            b'$' if i + 1 < n && b[i + 1].is_ascii_digit() => {
                let k = (b[i + 1] - b'0') as usize;
                if let Some(Some(val)) = rule_caps.get(k) {
                    out.push_str(val);
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
    /// Count of `[N]`/`[next]` restarts so far. Lives here (not in `run_pass`) so
    /// the guard accumulates ACROSS passes: a `[N]` returns from `run_pass` to
    /// restart, so a per-call counter would reset to 0 every restart and never
    /// fire (the guard was dead). OLS aborts a ruleset after MAX_ITERATIONS `[N]`
    /// jumps; restart-on-URI-change passes are bounded separately by `uri_restarts`
    /// in [`super::evaluate`].
    pub(super) next_loops: usize,
}

impl EvalState {
    fn record_env(&mut self, k: String, v: String) {
        if !self.env_order.contains(&k) {
            self.env_order.push(k.clone());
        }
        self.env.insert(k, v);
    }

    pub(super) fn env_vec(&self) -> Vec<(String, String)> {
        self.env_order
            .iter()
            .filter_map(|k| self.env.get(k).map(|v| (k.clone(), v.clone())))
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
                idx += 1 + rule.flags.skip;
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
    // per-rule), so the screen returns `None` iff the real cond pass would. On a pass
    // we fall through to the unchanged capture + cond path (the cheap re-eval is the
    // rare case). Placed AFTER the literal_prefix reject so a prefix-rejected rule
    // never pays a cond stat. Kills the per-request regex `captures()` on
    // method/header-gated rules like `RewriteRule ^/(.*)$ … [P]` cond'd on
    // `%{REQUEST_METHOD}`, which otherwise matches every URI and captures on every GET.
    if !rule.conds_need_rule_caps && !rule.conds.is_empty() {
        // Mirror the per-rule reset at the real cond loop below so a `%N` reference to
        // an unset slot expands empty (not a stale prior-rule value).
        state.last_cond_caps = empty_caps();
        if !eval_conditions(&rule.conds, input, state, &[]) {
            return None;
        }
    }

    let match_target = select_match_target(rule, input, &state.uri);

    // Build the $0..$9 vector only when something references it; otherwise skip the
    // per-match 10-slot String allocation entirely (common for -/[F]/[L]/redirects).
    // A recognized total-match pattern always matches the whole target, so skip
    // `captures()` (and the regex run) and synthesize the slots directly — provably
    // identical to running the regex (see `synthesize_total_caps`).
    let rule_caps = match rule.match_total {
        Some(tm) => {
            if rule.needs_rule_caps {
                synthesize_total_caps(match_target.as_ref(), tm)
            } else {
                empty_caps()
            }
        }
        None => {
            let caps = rule.pattern.captures(match_target.as_ref());
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
    state.last_cond_caps = empty_caps();

    // Evaluate this rule's conditions.
    if !eval_conditions(&rule.conds, input, state, &rule_caps) {
        return None;
    }

    // Apply `[E=...]` env sets (always, even for `-` substitution).
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
        let expanded = expand(
            &rule.subst,
            input,
            &state.uri,
            &state.query,
            &state.env,
            &rule_caps,
            &state.last_cond_caps,
        );
        // Apache percent-encodes the substitution by default; `[NE]`
        // (`noescape`) disables it. We escape only the path portion (everything
        // before the first `?`) with the URI-path-safe set, leaving an existing
        // `%XX` triplet untouched (no double-encoding). The `?query` part is
        // left as-is so QSA merges / `?`-stripping below behave unchanged.
        let escaped = if rule.flags.noescape {
            expanded
        } else {
            escape_subst(&expanded)
        };
        subst_target = Some(escaped);
    }

    // `[P]` proxy: substitution is the upstream URL.
    if rule.flags.proxy {
        let target = subst_target.unwrap_or_else(|| state.uri.clone());
        return Some(RuleApply::Terminal(RewriteOutcome::Proxy {
            target_url: target,
            env: state.env_vec(),
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

        let location = subst_target.clone().unwrap_or_else(|| state.uri.clone());
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
        let new_uri = resolve_subst_path(path, rs, input);
        // `[QSD]` discards the current query before any merge.
        let base_query = if rule.flags.qsd { "" } else { &state.query };
        let new_query = compute_query(q, base_query, rule.flags.qsa);
        state.uri = new_uri;
        state.query = new_query;
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

/// What the rule pattern is matched against. At the per-directory level Apache
/// strips the directory prefix and the leading slash; we emulate that when a
/// `per_directory_prefix` is supplied, otherwise match the path with leading
/// slash removed (the common `.htaccess` convention used by all our fixtures,
/// whose patterns are written like `^threads/...` without a leading slash —
/// except the inline mcp rules which are written with a leading slash, so we
/// try both).
/// Pick the target a rule's pattern is matched against. Apache `.htaccess` rules
/// match the per-directory-relative path with the leading slash stripped
/// (`^threads/...`), while LiteSpeed inline vhost rules in this install anchor with
/// a leading slash (`^/tools\.json$`); we choose by the pattern's own shape. Borrows
/// `uri` where possible (no per-rule allocation in the common case).
fn select_match_target<'a>(rule: &Rule, input: &RewriteInput, uri: &'a str) -> Cow<'a, str> {
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
        if eval_one_cond(cond, input, state, rule_caps) {
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
    COND_SCRATCH.with(|cell| {
        let mut guard = cell.borrow_mut();
        let (test, rhs_buf) = &mut *guard;
        test.clear();
        expand_into(
            test,
            &cond.test_string,
            input,
            &state.uri,
            &state.query,
            &state.env,
            rule_caps,
            &state.last_cond_caps,
        );

        // %N captures are committed only if the condition ultimately PASSES (below):
        // a NEGATED regex whose pattern happens to match makes the cond evaluate
        // false, so it must not leak `%1`/`%2` to a later member of an `[OR]` group.
        let mut pending_caps = None;
        let result = match &cond.pattern {
            CondPattern::Regex(re, _) => match re.captures(test.as_str()) {
                Some(c) => {
                    let mut caps = empty_caps();
                    for (i, slot) in caps.iter_mut().enumerate() {
                        *slot = c.get(i).map(|s| s.to_string());
                    }
                    pending_caps = Some(caps);
                    true
                }
                None => false,
            },
            CondPattern::FileTest(kind) => file_test(input, test.as_str(), *kind),
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
            }
        }
        passed
    })
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
    s[..i].parse().unwrap_or(0)
}

/// Apply a `-f/-d/-l/-s/-x` test to `path`.
fn file_test(input: &RewriteInput, path: &str, kind: FileTestKind) -> bool {
    match &input.stat {
        StatSource::Precomputed(t) => match kind {
            FileTestKind::File => t.is_file,
            FileTestKind::Dir => t.is_dir,
            FileTestKind::Link => t.is_link,
            FileTestKind::Size => t.is_nonempty,
            FileTestKind::Exists => t.is_file || t.is_dir || t.is_link,
        },
        StatSource::Live(f) => match f(std::path::Path::new(path)) {
            Some(md) => {
                let t = FileTests::from_metadata(&md);
                match kind {
                    FileTestKind::File => t.is_file,
                    FileTestKind::Dir => t.is_dir,
                    FileTestKind::Link => t.is_link,
                    FileTestKind::Size => t.is_nonempty,
                    FileTestKind::Exists => true,
                }
            }
            None => false,
        },
        StatSource::LiveTests(f) => match f(std::path::Path::new(path)) {
            Some(t) => match kind {
                FileTestKind::File => t.is_file,
                FileTestKind::Dir => t.is_dir,
                FileTestKind::Link => t.is_link,
                FileTestKind::Size => t.is_nonempty,
                FileTestKind::Exists => t.is_file || t.is_dir || t.is_link,
            },
            None => false,
        },
        StatSource::None => false,
    }
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
/// `RewriteBase` (or `/`).
fn resolve_subst_path(path: &str, rs: &RuleSet, _input: &RewriteInput) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    if path.starts_with('/') || has_scheme(path) {
        return path.to_string();
    }
    // Relative: prepend RewriteBase.
    let base = rs.base.as_deref().unwrap_or("/");
    let base = base.trim_end_matches('/');
    format!("{base}/{path}")
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
/// the first `?`) is escaped; the `?query` tail — if any — is passed through
/// untouched because the engine handles QSA / `?`-stripping separately on it.
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
        out.push_str(q);
    }
    out
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
    // Authority: prefer the explicit SERVER_NAME, else the Host header. Include
    // a non-default port only when SERVER_PORT was supplied and is non-default.
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
        Some(port) if !host_has_port && !is_default_port(port, input.https) => {
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
