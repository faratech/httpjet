//! The rule model: [`RuleSet`], [`Rule`], [`Cond`], flag parsing, and the
//! [`evaluate`] driver that runs the Apache per-pass + restart-on-URI-change
//! loop.

mod eval;
mod parse;

use fancy_regex::Regex;
use regex_automata::{
    Input, MatchKind, PatternID, PatternSet,
    dfa::{Automaton, dense},
    meta,
    util::captures::Captures,
};

use crate::error::RewriteError;
use crate::input::RewriteInput;

use eval::{EvalState, PassResult, rule_match_target, run_pass};

/// Maximum number of full passes over the rule list before the engine gives up
/// (Apache uses an internal redirect limit of 10).
pub(crate) const MAX_ITERATIONS: usize = 10;

/// A parsed `mod_rewrite` rule set.
#[derive(Debug, Default)]
pub struct RuleSet {
    /// `RewriteEngine on/off`. When off, [`evaluate`] is a no-op.
    pub(crate) engine_on: bool,
    /// `RewriteBase` value, if any (used to resolve relative substitutions).
    pub(crate) base: Option<String>,
    /// The rules in source order.
    pub(crate) rules: Vec<Rule>,
    /// Multi-pattern prefilter over the "simple" rules (non-fancy, non-negated,
    /// stripped-target). One search tells us which of those rules' patterns match,
    /// so a request that matches none of the ~N redirect rules skips N individual
    /// regex evaluations. See [`Rule::prefilter_idx`].
    pub(crate) prefilter: Option<PrefilterSet>,
    /// Precomputed at parse time: this ruleset's outcome is a pure function of the
    /// base cache key (vhost, scheme, method, host, path, query) PLUS the values of
    /// [`Self::cache_key_vars`]. True iff every `%{VAR}` read is either cache-safe
    /// (already in the base key, see [`var_is_cache_safe`]) or a KEYABLE dynamic var
    /// (see [`keyable_var`]) whose value the pipeline adds to the key. `false`
    /// (fail-closed) for any ruleset reading a per-request-varying input we cannot
    /// key (`REMOTE_*`, `TIME*`, `ENV:*`, arbitrary `HTTP:*`, …).
    pub path_cacheable: bool,
    /// The KEYABLE dynamic vars this ruleset reads (e.g. `%{HTTP_USER_AGENT}` for a
    /// bot-detection block). Empty = fully path-cacheable (the historic case). When
    /// non-empty AND `path_cacheable`, the pipeline appends these vars' request
    /// values to the [outcome-cache key] so a UA-reading chain is cacheable without
    /// collapsing distinct UAs onto one entry.
    pub cache_key_vars: Vec<CacheKeyVar>,
    /// `%{ENV:NAME}` names this ruleset reads that classification treated as
    /// CONSTANT-EMPTY at rewrite-eval time (currently only `REDIRECT_STATUS`):
    /// httpjet itself never seeds them into the request env before/during rewrite
    /// evaluation. The pipeline MUST bypass the outcome cache for any request
    /// whose live env seed actually carries one of these names (a `SetEnvIf`
    /// writer, or a future internal seed) — the classification's purity argument
    /// only holds while the seed value is absent.
    pub assumed_empty_env: Vec<String>,
    /// Unique nonzero id assigned at parse time; keys the pipeline's bounded
    /// UA-classification cache (a reparsed/reloaded ruleset gets a fresh id, so
    /// stale classification entries can never be replayed against new rules).
    id: u64,
    /// `(rule_idx, cond_idx)` of every UA-reading `RewriteCond`, in source order,
    /// when this ruleset is [`Self::ua_classify_eligible`]. Empty otherwise.
    ua_conds: Vec<(usize, usize)>,
    /// True iff the rewrite outcome's ONLY dependence on the User-Agent value is
    /// through the boolean match results of `ua_conds` (see `compute_ua_classify`
    /// in `parse.rs`): the pipeline may then key outcomes on the match BITMAP
    /// instead of the raw UA string, collapsing real-world UA diversity onto a
    /// handful of cache entries.
    ua_classify_eligible: bool,
    /// Precomputed at parse time: any cond/rule reads `%{THE_REQUEST}`. The
    /// pipeline then attaches the VERBATIM pre-decode request target to the
    /// RewriteInput so the variable resolves from raw bytes (Apache documents
    /// THE_REQUEST as the original request line, never percent-decoded).
    pub uses_the_request: bool,
}

/// Monotonic id source for [`RuleSet::id`] (0 is reserved for `RuleSet::default()`,
/// which has no rules and is never classification-cached).
static RULESET_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl RuleSet {
    /// Unique nonzero parse-time id (0 only for a default-constructed empty set).
    pub fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn assign_id(&mut self) {
        self.id = RULESET_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether outcomes for this ruleset may be keyed on the UA-cond match bitmap
    /// instead of the raw User-Agent string (see [`Self::ua_cond_signature`]).
    pub fn ua_classify_eligible(&self) -> bool {
        self.ua_classify_eligible
    }

    /// Number of UA-reading conds covered by the signature (bitmap width).
    pub fn ua_cond_count(&self) -> usize {
        self.ua_conds.len()
    }

    /// The UA-cond match bitmap for `ua`: bit `i` is set iff the i-th UA-reading
    /// `RewriteCond`'s regex matches `ua`. A pure function of (`ua`, this ruleset)
    /// — the pipeline memoizes it per UA string. Only meaningful when
    /// [`Self::ua_classify_eligible`]; the eligibility computation guarantees every
    /// listed cond is a plain regex test whose test string is exactly the UA var,
    /// so matching the raw UA here reproduces eval's expansion exactly (an absent
    /// header expands to `""`; pass `""` for it).
    pub fn ua_cond_signature(&self, ua: &str) -> u64 {
        let mut sig = 0u64;
        for (bit, (ri, ci)) in self.ua_conds.iter().enumerate() {
            if let CondPattern::Regex(re, _) = &self.rules[*ri].conds[*ci].pattern
                && re.captures(ua).is_some()
            {
                sig |= 1 << bit;
            }
        }
        sig
    }
}

/// A per-request-varying `%{VAR}` that the outcome cache CAN key on (so a ruleset
/// reading it stays cacheable, with the value folded into the key). Deliberately a
/// tiny allowlist — adding a var here means its value must be resolvable in
/// `run_rewrite` and its cardinality acceptable under the cache's bounded LRU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheKeyVar {
    /// `%{HTTP_USER_AGENT}` (and the `%{HTTP:User-Agent}` form).
    UserAgent,
    /// `%{HTTP:Origin}` — the CORS request header. Small cardinality in practice
    /// (absent on the vast majority of requests; a handful of scheme+host values
    /// otherwise). The pipeline must key an ABSENT header distinctly from an
    /// empty one. Note the bare `%{HTTP_ORIGIN}` form is NOT a header read in
    /// this engine (it falls through to the env lookup), so only the `HTTP:`
    /// form maps here.
    Origin,
}

/// A pattern recognized at parse time as a guaranteed WHOLE-STRING match of any
/// target (`.*` / `^.*$` / `(.*)` / `^(.*)$`, not negated/nocase). Lets
/// [`apply_rule`](super::eval) skip the prefilter lookup + the regex `captures()`
/// and synthesize the slots directly: `$0` = the whole match for both; `$1` = the
/// whole match only for the parenthesized (`OneGroup`) forms.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TotalMatch {
    /// `.*` / `^.*$` — no capture group (`$0` only).
    NoGroup,
    /// `(.*)` / `^(.*)$` — one capture group (`$0` and `$1`).
    OneGroup,
}

/// One `RewriteRule Pattern Subst [flags]`, with its leading `RewriteCond`s.
#[derive(Debug)]
pub(crate) struct Rule {
    /// Set when `pattern` is a recognized total-match form (see [`TotalMatch`]);
    /// `apply_rule` then skips the prefilter + `captures()` and synthesizes slots.
    pub(crate) match_total: Option<TotalMatch>,
    /// Conditions evaluated before the rule (in source order).
    pub(crate) conds: Vec<Cond>,
    /// Compiled pattern matched against the current URI path.
    pub(crate) pattern: CompiledRegex,
    /// The raw pattern source (kept for diagnostics / golden tests).
    pub(crate) pattern_src: String,
    /// True if the pattern was written as `!pattern` (negated match).
    pub(crate) negate: bool,
    /// Substitution string (`-` means "no substitution").
    pub(crate) subst: String,
    /// Parsed rule flags.
    pub(crate) flags: RuleFlags,
    /// Index of this rule's pattern in [`RuleSet::prefilter`], if it is eligible
    /// (simple pattern, not negated, matched against the stripped target). When
    /// the prefilter says this index did not match, the full regex is skipped.
    pub(crate) prefilter_idx: Option<usize>,
    /// Precomputed at parse time: does anything (`subst`, `[E=...]`, or a cond's
    /// test string / comparison RHS) reference a rule backref `$N`? When false we
    /// skip building the `$0..$9` capture vector on a match (the common case for
    /// `-`/`[F]`/`[L]`/redirect rules), avoiding a per-match 10-slot `String` alloc.
    pub(crate) needs_rule_caps: bool,
    /// Precomputed at parse time: do any of this rule's `RewriteCond`s reference a
    /// rule backref `$N` (in the test string or a lexical/numeric RHS)? When false,
    /// the conds depend only on `%{VAR}`/`%N` — not the rule pattern's captures — so
    /// they can be evaluated as a reject-only screen BEFORE the pattern `captures()`,
    /// skipping the regex entirely when a cond fails (e.g. a `%{REQUEST_METHOD}`-gated
    /// `RewriteRule ^/(.*)$` on a GET). A strict subset of [`Self::needs_rule_caps`].
    pub(crate) conds_need_rule_caps: bool,
    /// Precomputed required literal prefix of the match target, when the pattern is
    /// `^`-anchored, case-sensitive, not negated, and matched against the stripped
    /// target (the common `.htaccess` form). Empty means "no fast-path". When set,
    /// a match REQUIRES `match_target.starts_with(literal_prefix)`, so we can
    /// `starts_with`-reject before paying for the full regex `captures()`.
    pub(crate) literal_prefix: Box<[u8]>,
}

/// Extract the required literal byte-prefix of the match target for a fast
/// `starts_with` reject before the regex runs. Returns empty (no fast-path) unless
/// the pattern is `^`-anchored, NOT negated, NOT case-insensitive, and NOT a
/// leading-slash (`^/…`) pattern — i.e. the ordinary `.htaccess` form matched
/// against the slash-stripped target. The prefix is the run of literal bytes after
/// `^` up to the first regex metacharacter; `/` is treated as literal. This is a
/// pure necessary-condition filter: any target that matches the anchored pattern
/// must start with these bytes, so rejecting on them never changes which rules match.
pub(crate) fn extract_literal_prefix(pattern_src: &str, negate: bool, nocase: bool) -> Box<[u8]> {
    if negate || nocase || !pattern_src.starts_with('^') {
        return Box::from(&b""[..]);
    }
    // Leading-slash patterns (`^/tools\.json$`) are matched against the *slashed* target
    // in apply_rule, and the prefix we extract here begins after `^` with that `/`, so it
    // is the correct slashed prefix — there is no need to exclude them (doing so left the
    // inline `^/…` proxy rules paying a full regex capture on every request).
    let bytes = pattern_src.as_bytes();
    let mut out = Vec::new();
    let mut i = 1; // skip the leading '^'
    while i < bytes.len() {
        match bytes[i] {
            // A quantifier governs the PRECEDING literal byte, which was already pushed.
            // `?`/`*`/`{` make that byte OPTIONAL (`^api/?`; `{0,n}`), so it is NOT part of
            // the required prefix — drop it and stop, else we'd wrongly reject e.g. `/api`.
            b'?' | b'*' | b'{' => {
                out.pop();
                break;
            }
            // `\X`: an escaped *literal* (X non-alphanumeric, e.g. `\.` `\/` `\-`) is a
            // required byte — decode it and continue. A class escape (`\d`/`\w`/`\s`, X
            // alphanumeric) or a trailing `\` ends the run.
            b'\\' => match bytes.get(i + 1) {
                Some(&n) if !n.is_ascii_alphanumeric() => {
                    out.push(n);
                    i += 2;
                    continue;
                }
                _ => break,
            },
            // A top-level alternation invalidates the WHOLE prefix concept: `^abc|def`
            // is `(^abc)|(def)`, so a target matching the right arm (`def`,`xdef`) need
            // NOT start with the left arm's bytes. This scan never enters a group (`(`
            // breaks below before any inner `|` is reached), so every `|` it sees is
            // top-level — abandon the fast-path entirely rather than keep the left arm.
            b'|' => return Box::from(&b""[..]),
            // Other metacharacters terminate the literal run without dropping a byte
            // (`+` one-or-more leaves its required byte in place).
            b'.' | b'[' | b']' | b'(' | b')' | b'}' | b'+' | b'^' | b'$' => break,
            c => out.push(c),
        }
        i += 1;
    }
    out.into_boxed_slice()
}

/// Recognize a pattern that matches ANY target as a whole-string match, from a
/// CONSERVATIVE literal allowlist only — `.*` / `^.*$` (no group) and `(.*)` /
/// `^(.*)$` (one group). Negated forms return `None` (a negated whole-match can
/// never fire). `[NC]` is accepted: these patterns are case-INdependent by
/// construction (#314d), so front-controller `[NC] ^.*$` catch-alls stop paying a
/// real regex per request.
/// Anything else (anchored prefixes, alternations, character classes) returns
/// `None` and takes the normal regex path. The empty pattern is intentionally
/// excluded (it is a zero-length match at pos 0, not a whole-string match).
fn recognize_total_match(src: &str, negate: bool, nocase: bool) -> Option<TotalMatch> {
    // (#314d) [NC] is admitted for the WHOLE-MATCH forms: `.*` matches every byte
    // sequence (including empty) regardless of case, so synthesizing the slots is
    // semantically identical to running `(?i)^.*$`. Negation still bails (a total
    // NEGATED match never fires). The literal `^.*` variants are matched exactly;
    // anything else takes the normal regex path.
    if negate {
        return None;
    }
    match src {
        ".*" | "^.*$" | "^.*" => Some(TotalMatch::NoGroup),
        "(.*)" | "^(.*)$" | "^(.*)" => Some(TotalMatch::OneGroup),
        _ => None,
    }
}

/// True if `s` contains a `$N` rule-backreference (a `$` immediately followed by a
/// digit). Conservative: an escaped `\$1` also returns true (harmless — we just
/// build captures we don't strictly need).
fn uses_dollar_backref(s: &str) -> bool {
    let b = s.as_bytes();
    b.windows(2).any(|w| w[0] == b'$' && w[1].is_ascii_digit())
}

/// One `RewriteCond TestString CondPattern [flags]`.
#[derive(Debug)]
pub(crate) struct Cond {
    /// The test string (contains `%{VAR}`, `$N`, `%N` interpolations).
    pub(crate) test_string: String,
    /// The condition pattern, in its original textual form (we keep it raw so
    /// we can dispatch on the special `-f`/`<`/`=` forms before regex).
    pub(crate) pattern: CondPattern,
    /// `[NC]` case-insensitive.
    pub(crate) nocase: bool,
    /// `[OR]` — OR with the *next* condition (default is AND).
    pub(crate) or_next: bool,
    /// Leading `!` negation on the pattern.
    pub(crate) negate: bool,
    pub(crate) line: usize,
}

/// The right-hand side of a `RewriteCond`.
#[derive(Debug)]
pub(crate) enum CondPattern {
    /// A regular expression match.
    Regex(CompiledRegex, String),
    /// File test: `-f`, `-d`, `-l`, `-s` (and the rarer `-x`, treated as exists).
    FileTest(FileTestKind),
    /// Lexical (string) comparison: `<str`, `>str`, `=str`, `<=str`, `>=str`.
    Lexical(Ordering, String),
    /// Numeric comparison: `-eq`, `-ne`, `-gt`, `-lt`, `-ge`, `-le`.
    Numeric(NumOp, String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileTestKind {
    File,
    Dir,
    Link,
    Size,
    Exists,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ordering {
    Less,
    Greater,
    Equal,
    LessEqual,
    GreaterEqual,
}

/// Numeric comparison operators for the `-eq`/`-ne`/`-gt`/`-lt`/`-ge`/`-le`
/// RewriteCond forms (OLS `COND_OP_*_NUM`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NumOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

/// Flags attached to a `RewriteRule`.
#[derive(Debug, Default, Clone)]
pub(crate) struct RuleFlags {
    /// `[L]` — last rule in this pass.
    pub(crate) last: bool,
    /// `[END]` — like `[L]` but ALSO stops the outer restart-on-URI-change loop
    /// and (via [`RewriteOutcome`]'s `end` flag) any subsequent `.htaccess` /
    /// ruleset processing in the pipeline. Apache 2.3.9+ semantics.
    pub(crate) end: bool,
    /// `[QSA]` — append the original query string to the substitution's query.
    pub(crate) qsa: bool,
    /// `[QSD]` — discard the original query string entirely.
    pub(crate) qsd: bool,
    /// `[R=code]` — external redirect with this status (defaults to 302 for `[R]`).
    pub(crate) redirect: Option<u16>,
    /// `[F]` — forbidden (403).
    pub(crate) forbidden: bool,
    /// `[G]` — gone (410).
    pub(crate) gone: bool,
    /// `[NC]` — case-insensitive pattern match.
    pub(crate) nocase: bool,
    /// `[P]` — proxy: the substitution is an upstream URL.
    pub(crate) proxy: bool,
    /// `[NE]` — do not escape the substitution.
    pub(crate) noescape: bool,
    /// `[C]` / `[chain]` — chain with the next rule: if *this* rule fails to
    /// match, OLS skips the chained rule(s) that follow.
    pub(crate) chain: bool,
    /// `[N]` / `[next]` — restart the rule set from the top (with the loop guard).
    pub(crate) next: bool,
    /// `[S=n]` / `[skip=n]` — on a successful match, skip the next `n` rules.
    pub(crate) skip: usize,
    /// `[E=var:val]` sets (in order).
    pub(crate) env_sets: Vec<(String, String)>,
}

/// The outcome of evaluating a [`RuleSet`] against a [`RewriteInput`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteOutcome {
    /// No rule matched / no change to the URI.
    Unchanged {
        /// Any `[E=...]` env mutations accumulated along the way.
        env: Vec<(String, String)>,
        /// `[END]` fired on a `- [END]`-style rule that set env / matched but
        /// left the URI unchanged: the pipeline must stop all further ruleset /
        /// `.htaccess` processing for this request (see [`RewriteOutcome::is_end`]).
        end: bool,
    },
    /// The URI (and possibly query) was internally rewritten.
    Rewritten {
        new_uri: String,
        new_query: Option<String>,
        env: Vec<(String, String)>,
        /// `[END]` fired on the matching rule: the pipeline must NOT run any
        /// subsequent ruleset / `.htaccess` and must NOT re-dispatch the
        /// rewritten URI back through the rewrite engine. `[L]` leaves this
        /// `false` (the rewritten URI may still pass through later rulesets).
        end: bool,
    },
    /// An external redirect with a 3xx status (`[R]`, `[R=301]`, `[R=302]`,
    /// `[R=303]`, `[R=307]`, ...). Carries a `Location`.
    Redirect {
        code: u16,
        location: String,
        env: Vec<(String, String)>,
    },
    /// `[R=NNN]` with a NON-3xx status (2xx / 4xx / 5xx). Apache treats this as
    /// "set this response status and STOP" — it does NOT emit a `Location`
    /// header and does NOT generate a "document has moved" body. The canonical
    /// live example is the CORS `OPTIONS` preflight rule
    /// `RewriteRule ^(.*)$ - [R=200,L,E=CORS_PREFLIGHT:1]` in `/web/news`.
    ///
    /// `suppress_body` is `true` for the `-`/`$1`-style "stop here" rules where
    /// no substitution body should be produced (always the case today); the
    /// pipeline should send a bare status (plus any `[E=...]`/`Header` set
    /// directives) with no entity for these.
    Status {
        code: u16,
        suppress_body: bool,
        env: Vec<(String, String)>,
    },
    /// `[F]` — respond 403.
    Forbidden { env: Vec<(String, String)> },
    /// `[G]` — respond 410.
    Gone { env: Vec<(String, String)> },
    /// `[P]` — proxy the request to this upstream URL.
    Proxy {
        target_url: String,
        env: Vec<(String, String)>,
    },
}

impl RewriteOutcome {
    /// The env mutations carried by this outcome (`[E=...]` sets), regardless of
    /// variant.
    pub fn env(&self) -> &[(String, String)] {
        match self {
            RewriteOutcome::Unchanged { env, .. }
            | RewriteOutcome::Rewritten { env, .. }
            | RewriteOutcome::Redirect { env, .. }
            | RewriteOutcome::Status { env, .. }
            | RewriteOutcome::Forbidden { env }
            | RewriteOutcome::Gone { env }
            | RewriteOutcome::Proxy { env, .. } => env,
        }
    }

    /// True if `[END]` fired and the caller must stop all further rewrite
    /// processing (subsequent rulesets / `.htaccess` files) for this request.
    /// Only `Rewritten { end: true, .. }` and `Unchanged { end: true, .. }` can
    /// be `true`; the other variants are already terminal (they short-circuit
    /// the pipeline on their own), so this returns `false` for them.
    pub fn is_end(&self) -> bool {
        matches!(
            self,
            RewriteOutcome::Rewritten { end: true, .. }
                | RewriteOutcome::Unchanged { end: true, .. }
        )
    }
}

/// A compiled rewrite pattern. Uses the **linear-time `regex` engine** whenever
/// the pattern compiles there, and falls back to the backtracking **`fancy_regex`**
/// only for patterns `regex` cannot handle (lookaround `(?=…)`/`(?!…)`/`(?<…)`,
/// in-pattern backreferences `\1`).
///
/// This is safe because `fancy_regex` itself delegates to the `regex` crate for
/// any pattern that uses no backtracking-only features — so a pattern that
/// `regex::Regex::new` accepts has *identical* match semantics under both engines.
/// `regex` is SIMD-accelerated and avoids `fancy_regex`'s per-call backtracking,
/// which profiling identified as httpjet's #1 CPU cost (per-rule, per-request).
#[derive(Debug)]
pub(crate) enum CompiledRegex {
    Fast(FastRegex),
    Fancy(Regex),
}

/// The linear-time engine, using `regex_automata::meta::Regex` directly (not the
/// high-level `regex::Regex`) so each search supplies an explicit **thread-local
/// `Cache`** keyed by [`FastRegex::id`]. The high-level wrapper owns one internal
/// cache pool with a single-owner-thread fast path; under tokio work-stealing the
/// connection task migrates across all workers, so the other threads take the
/// pool's cross-thread mutex slow path (`Pool::get_slow`, ~5% of CPU on the
/// 130-rule front controller). A per-thread cache removes that contention.
#[derive(Debug)]
pub struct FastRegex {
    re: meta::Regex,
    id: usize,
}

/// Per-`FastRegex` ids are assigned from this monotonic counter at compile time and
/// key the thread-local cache map below.
static FAST_REGEX_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Cap on the per-thread cache map. `.htaccess`/inline rulesets reload only on an
/// mtime change (the prod config tree is read-only, so effectively never), but a
/// reload assigns fresh ids and leaves the old entries behind — clear the map if it
/// ever grows past this bound rather than leak unboundedly. Caches rebuild lazily.
const FAST_REGEX_CACHE_CAP: usize = 1 << 14;

thread_local! {
    /// Per-thread `(Cache, Captures)` for each `FastRegex`, keyed by its id. Both
    /// are tied to a specific `meta::Regex`, so they are reused per id and never
    /// shared across regexes. No locking: a thread only ever touches its own map.
    static FAST_REGEX_CACHES: std::cell::RefCell<
        std::collections::HashMap<usize, (meta::Cache, Captures)>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

impl FastRegex {
    fn captures<'t>(&self, text: &'t str) -> Option<Caps<'t>> {
        FAST_REGEX_CACHES.with(|cell| {
            let mut map = cell.borrow_mut();
            if map.len() > FAST_REGEX_CACHE_CAP {
                map.clear();
            }
            let (cache, caps) = map
                .entry(self.id)
                .or_insert_with(|| (self.re.create_cache(), self.re.create_captures()));
            self.re.search_captures_with(cache, &Input::new(text), caps);
            if !caps.is_match() {
                return None;
            }
            // Copy the 0..=9 backref group spans out of the (reused, thread-local)
            // Captures so the returned `Caps` borrows only `text`, not the cache.
            let mut groups: [Option<(usize, usize)>; 10] = [None; 10];
            for (i, g) in groups.iter_mut().enumerate() {
                *g = caps.get_group(i).map(|sp| (sp.start, sp.end));
            }
            Some(Caps::Fast { groups, text })
        })
    }
}

/// The multi-pattern rewrite prefilter: a single **fully-compiled dense DFA**
/// (`regex_automata::dfa::dense`) over all eligible rule patterns. It is searched
/// once per request via [`Automaton::try_which_overlapping_matches`], which is
/// **cacheless** — a fully-determinized DFA holds no lazy state, so there is no
/// per-search `Cache` and no cross-thread `Pool` (the `regex::RegexSet` it replaces
/// pooled internally, the residual `Pool::get_slow` source even with an explicit
/// cache). Built with `MatchKind::All` so "which patterns matched anywhere" is
/// well-defined (the default leftmost semantics leave overlapping results
/// unspecified). A rule whose `prefilter_idx` is absent from the match set is a
/// guaranteed non-match and skips its per-rule regex.
#[derive(Debug)]
pub(crate) struct PrefilterSet {
    dfa: dense::DFA<Vec<u32>>,
}

impl PrefilterSet {
    /// Build the prefilter DFA over `pats`. Returns `None` if determinization
    /// exceeds the size limit (pathological pattern set) — the caller then keeps
    /// the per-rule path with no prefilter (correct, just unfiltered).
    fn new(pats: &[String]) -> Option<PrefilterSet> {
        // 8 MiB DFA / 16 MiB determinize caps: ample for the "simple" prefilter
        // patterns, bounded against a pathological vhost. On overflow → None.
        let dfa = dense::Builder::new()
            .configure(
                dense::Config::new()
                    .match_kind(MatchKind::All)
                    .dfa_size_limit(Some(8 * (1 << 20)))
                    .determinize_size_limit(Some(16 * (1 << 20))),
            )
            .build_many(pats)
            .ok()?;
        Some(PrefilterSet { dfa })
    }

    /// The set of pattern ids matching `text` (anywhere). On the unusual DFA error
    /// path (e.g. a quit byte) it fails **open** — every pattern is reported as a
    /// possible match so the per-rule regex still runs; the prefilter only ever
    /// *skips* a guaranteed non-match, never a possible one.
    fn matches(&self, text: &str) -> PatternSet {
        let mut set = PatternSet::new(self.dfa.pattern_len());
        if self
            .dfa
            .try_which_overlapping_matches(&Input::new(text), &mut set)
            .is_err()
        {
            for i in 0..self.dfa.pattern_len() {
                set.insert(PatternID::new_unchecked(i));
            }
        }
        set
    }

    /// Whether the rule at prefilter index `idx` matched. An out-of-range id never
    /// occurs (assigned at build) but defaults to "matched" so a stray index falls
    /// through to the real regex rather than wrongly skipping a rule.
    #[inline]
    pub(crate) fn contains(&self, set: &PatternSet, idx: usize) -> bool {
        match PatternID::new(idx) {
            Ok(pid) => set.contains(pid),
            Err(_) => true,
        }
    }
}

/// Capture groups from whichever engine matched; `get(i)` yields the i-th group
/// as a borrowed `&str` (zero-copy into the matched text).
pub(crate) enum Caps<'t> {
    /// `regex_automata` group byte-spans (0..=9) copied out of the thread-local
    /// Captures, plus the haystack they index into.
    Fast {
        groups: [Option<(usize, usize)>; 10],
        text: &'t str,
    },
    Fancy(fancy_regex::Captures<'t, str>),
}

impl<'t> Caps<'t> {
    #[inline]
    fn get(&self, i: usize) -> Option<&str> {
        match self {
            Caps::Fast { groups, text } => {
                groups.get(i).copied().flatten().map(|(s, e)| &text[s..e])
            }
            Caps::Fancy(c) => c.get(i).map(|m| m.as_str()),
        }
    }
}

impl CompiledRegex {
    /// Compile `src` (case-insensitive when `nocase`), preferring the linear-time
    /// `regex_automata` engine and falling back to `fancy_regex` for unsupported features.
    fn compile(src: &str, nocase: bool, line: usize) -> Result<CompiledRegex, RewriteError> {
        let prepared = if nocase {
            format!("(?i){src}")
        } else {
            src.to_string()
        };
        // `meta::Regex` is the same engine the high-level `regex` crate is built on,
        // so it accepts/rejects the identical pattern set with identical match
        // semantics — a pattern it rejects (lookaround / backref) still falls back
        // to `fancy_regex`, exactly as the former `regex::Regex::new` path did.
        if let Ok(re) = meta::Regex::new(&prepared) {
            let id = FAST_REGEX_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(CompiledRegex::Fast(FastRegex { re, id }));
        }
        Regex::new(&prepared)
            .map(CompiledRegex::Fancy)
            .map_err(|e| RewriteError::BadRegex {
                line,
                pattern: src.to_string(),
                source: Box::new(e),
            })
    }

    /// Run the pattern against `text`, returning the captures on a match.
    #[inline]
    pub(crate) fn captures<'t>(&self, text: &'t str) -> Option<Caps<'t>> {
        match self {
            CompiledRegex::Fast(r) => r.captures(text),
            // fancy_regex returns Result<Option<_>>; a regex *error* at match time
            // is treated as a non-match (matches the prior `.unwrap_or_default()`).
            CompiledRegex::Fancy(r) => r.captures(text).ok().flatten().map(Caps::Fancy),
        }
    }
}

// ===========================================================================
// Evaluation entry
// ===========================================================================

/// Run a [`RuleSet`] against a [`RewriteInput`]. Implements Apache's per-pass
/// loop: rules run top-to-bottom; a matched `[L]`/`[F]`/`[P]`/`[R]` stops the
/// pass; if any non-terminal rule rewrote the URI, the whole list is re-run
/// (up to [`MAX_ITERATIONS`]).
pub fn evaluate(rs: &RuleSet, input: &RewriteInput) -> RewriteOutcome {
    if !rs.engine_on {
        return RewriteOutcome::Unchanged {
            env: Vec::new(),
            end: false,
        };
    }

    let mut state = EvalState {
        // EvalState owns a mutable working copy (the engine rewrites it in place), so this
        // owns regardless of whether `input.uri` borrows — the one alloc the engine needs.
        uri: input.uri.to_string(),
        query: input.query.to_string(),
        // Overlay for `[E=...]` sets ONLY — starts empty. Reads fall through to the
        // borrowed seed (`input.env`) in resolve_var_into, so this avoids cloning the
        // seed BTreeMap once PER RULESET (the chain runs evaluate per ruleset). An
        // overlay entry shadows the seed, identical to the old "clone seed then insert
        // [E=] on top" (last-writer-wins preserved).
        env: std::collections::BTreeMap::new(),
        env_order: Vec::new(),
        last_cond_caps: std::array::from_fn(|_| None),
        prefilter_valid: true,
        next_loops: 0,
    };
    // Set true once an `[END]` rule fires, so the final outcome flags the
    // pipeline to stop subsequent rulesets / `.htaccess` processing.
    let mut ended = false;

    // Run the multi-pattern prefilter once against the initial stripped target.
    // `state.prefilter_valid` guards its use after any URI rewrite.
    let prefilter_target = rule_match_target(input, &input.uri);
    let hits: Option<PatternSet> = rs
        .prefilter
        .as_ref()
        .map(|pf| pf.matches(prefilter_target.as_ref()));
    let hits = hits.as_ref();

    // Two distinct restart kinds, each bounded at MAX_ITERATIONS (Apache's
    // internal-redirect limit):
    //   * restart-on-URI-change: counted by `uri_restarts` here;
    //   * `[N]`/`[next]` jumps: counted by `state.next_loops` inside `run_pass`,
    //     which bails to `Continue` once it exceeds MAX_ITERATIONS.
    // They are counted separately because a `[N]` jump returns out of `run_pass`
    // to restart the ruleset — if both shared this loop's counter, the per-call
    // `next_loops` would reset every restart and its guard would be dead code (the
    // bug being fixed). A `[N]` restart therefore does NOT consume the URI-change
    // budget, so the `[N]` guard can reach (and enforce) its own bound.
    let mut uri_restarts = 0usize;
    loop {
        let uri_before = state.uri.clone();
        match run_pass(rs, input, &mut state, hits) {
            PassResult::Terminal(outcome) => return outcome,
            PassResult::Restart => {
                // `[N]`/`[next]`: re-run the rule set from the top, regardless of
                // whether the URI changed (OLS jumps back to the first rule). The
                // jump was already counted + bounded by `state.next_loops`.
            }
            PassResult::Continue { end } => {
                if end {
                    // `[END]`: stop the per-pass loop AND the outer restart loop
                    // unconditionally — even if the URI changed this pass.
                    ended = true;
                    break;
                }
                if state.uri == uri_before {
                    // No URI change this pass and no terminal rule fired: done.
                    break;
                }
                // URI changed -> restart from the top, up to MAX_ITERATIONS times.
                uri_restarts += 1;
                if uri_restarts >= MAX_ITERATIONS {
                    break;
                }
            }
        }
    }

    if state.uri != *input.uri || state.query != *input.query {
        // `new_query` reports the *effective* query the rewritten URI carries:
        // `Some(q)` for a non-empty query (whether newly set or carried over via
        // QSA), `None` when the rewrite leaves no query string at all.
        RewriteOutcome::Rewritten {
            new_uri: state.uri.clone(),
            new_query: if state.query.is_empty() {
                None
            } else {
                Some(state.query.clone())
            },
            env: state.env_vec(),
            end: ended,
        }
    } else {
        RewriteOutcome::Unchanged {
            env: state.env_vec(),
            end: ended,
        }
    }
}
