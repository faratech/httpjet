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

use eval::{EvalState, FsMemoScope, PassResult, rule_match_target, run_pass};

/// Maximum number of full passes over the rule list before the engine gives up
/// (Apache uses an internal redirect limit of 10).
pub(crate) const MAX_ITERATIONS: usize = 10;

/// A parsed `mod_rewrite` rule set.
#[derive(Debug, Default)]
pub struct RuleSet {
    /// `RewriteEngine on/off`. When off, [`evaluate`] is a no-op.
    pub(crate) engine_on: bool,
    /// Whether a `RewriteEngine` line appeared. Without one, a per-directory
    /// ruleset inherits the enclosing context's engine state (OLS/Apache merge).
    pub(crate) engine_set: bool,
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
    /// Every request-header name read through `%{HTTP:...}` or a bare header
    /// variable (`HTTP_COOKIE`, `HTTP_REFERER`, ...), normalized lowercase.
    /// Unlike `cache_key_vars`, this is retained even when another input makes
    /// the ruleset non-path-cacheable: downstream page caching still needs to
    /// distinguish responses by these header values.
    pub header_reads: Vec<String>,
    /// (#857) The first `%{VAR}` read the origin page cache can neither key nor
    /// vary on (client/server address or port, protocol, `THE_REQUEST`, `TIME*`,
    /// `%{ENV:…}` / bare env reads). `None` = a response built under this set is
    /// a function of the page-cache key plus its header vary.
    pub page_cache_unkeyed: Option<Box<str>>,
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
    /// Any rule or cond reads `%{HTTP_USER_AGENT}`, whether or not the set is
    /// path-cacheable (the page cache must know even when the outcome cache cannot).
    reads_user_agent: bool,
    /// Stable (across restarts and rebuilds) identity of the UA conds behind
    /// [`Self::ua_cond_signature`]: FNV-1a over each UA cond's regex source and
    /// `[NC]` flag, in order. 0 unless [`Self::ua_classify_eligible`].
    ua_fingerprint: u64,
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
    /// Whether evaluating this set is guaranteed to return an unchanged URI and
    /// no rewrite environment. `RewriteEngine off` suppresses parsed rules just
    /// as completely as an empty rule list.
    pub fn is_noop(&self) -> bool {
        self.engine_state() == Some(false) || self.rules.is_empty()
    }

    /// The explicit `RewriteEngine` state, or `None` to inherit the parent's.
    pub fn engine_state(&self) -> Option<bool> {
        self.engine_set.then_some(self.engine_on)
    }

    /// (#857) Whether every input this set can read is covered by the page-cache
    /// key or its header vary. A set that never evaluates reads nothing.
    pub fn page_cache_keyed(&self) -> bool {
        self.page_cache_unkeyed.is_none() || self.is_noop()
    }

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

    /// Whether any rule or cond reads the User-Agent (independent of cacheability).
    pub fn reads_user_agent(&self) -> bool {
        self.reads_user_agent
    }

    /// The substitutions of `[P]` rules whose upstream host the request can choose
    /// (see [`proxy_authority_substituted`]).
    pub fn substituted_proxy_authorities(&self) -> impl Iterator<Item = &str> {
        self.rules
            .iter()
            .filter(|rule| rule.flags.proxy && proxy_authority_substituted(&rule.subst))
            .map(|rule| rule.subst.as_str())
    }

    /// Restart-stable identity of this ruleset's UA conds, for keys that outlive the
    /// process (the persistent page cache). [`Self::id`] is process-local.
    pub fn ua_fingerprint(&self) -> u64 {
        self.ua_fingerprint
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
    /// `%{HTTP:Accept}` — the content-negotiation header. Tiny real-world
    /// cardinality (a handful of per-UA-family constants), commonly read by
    /// SSE/webp gates (`RewriteCond %{HTTP:Accept} text/event-stream`). As with
    /// Origin, only the `HTTP:` form maps here (`%{HTTP_ACCEPT}` is not a
    /// header read in this engine).
    Accept,
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
    // #619: a top-level `|` ANYWHERE after the anchor invalidates the prefix,
    // even if a metacharacter (`$`,`.`,`[`,`+`) ends the literal run before
    // the scan below reaches it (e.g. `^a\.php$|b\.php$`).
    {
        let mut depth = 0usize;
        let mut in_class = false;
        let mut j = 1;
        while j < bytes.len() {
            match bytes[j] {
                b'\\' => j += 1,
                b'[' if !in_class => in_class = true,
                b']' if in_class => in_class = false,
                b'(' if !in_class => depth += 1,
                b')' if !in_class => depth = depth.saturating_sub(1),
                b'|' if !in_class && depth == 0 => return Box::from(&b""[..]),
                _ => {}
            }
            j += 1;
        }
    }
    let mut out = Vec::new();
    let mut i = 1; // skip the leading '^'
    while i < bytes.len() {
        match bytes[i] {
            // A quantifier governs the PRECEDING literal byte, which was already pushed.
            // `?`/`*`/`{` make that byte OPTIONAL (`^api/?`; `{0,n}`), so it is NOT part of
            // the required prefix — drop it and stop, else we'd wrongly reject e.g. `/api`.
            b'?' | b'*' | b'{' => {
                while out.pop().is_some_and(|b| b & 0xC0 == 0x80) {}
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
fn recognize_total_match(src: &str, negate: bool, _nocase: bool) -> Option<TotalMatch> {
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
    /// `-U` URL-access test: OLS `COND_OP_URL_ACC` never runs a subrequest and
    /// always matches (so `!-U` never does).
    UrlAccess,
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
    /// `-x`: an executable regular file (OLS COND_OP_EXEC).
    Exec,
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
    /// `[B]`-family backreference escaping of the substitution.
    pub(crate) backref_escape: Option<BackrefEscape>,
    /// `[UnsafeAllow3F]`: a `?` inside a path-part backreference may start the query.
    pub(crate) allow_3f: bool,
}

/// `[B]` / `[B=chars]` / `[BNP]` / `[BCTLS]` / `[BNE=chars]` (OLS `escape_uri`).
#[derive(Debug, Default, Clone)]
pub(crate) struct BackrefEscape {
    /// `[BNP]`: a space becomes `%20` instead of `+`.
    pub(crate) no_plus: bool,
    /// `[BCTLS]`: only control characters and spaces are escaped.
    pub(crate) ctls_only: bool,
    /// `[BNE=chars]`: characters left verbatim.
    pub(crate) no_escape: String,
    /// `[B=chars]`: only these characters are escaped.
    pub(crate) only: Option<String>,
}

/// The outcome of evaluating a [`RuleSet`] against a [`RewriteInput`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteOutcome {
    /// A configured backtracking expression hit a match-time engine limit.
    /// Callers must fail closed, never reinterpret this as a non-match and
    /// continue into a protected handler.
    Failed {
        env: Vec<(String, String)>,
        reason: &'static str,
    },
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
        /// OLS `[P,E=Proxy-Host:value]`: the outbound `Host` (and TLS SNI) for the
        /// upstream leg. Not recorded as an env var.
        proxy_host: Option<String>,
        env: Vec<(String, String)>,
        /// The upstream's scheme or authority came from a substitution, so the
        /// request may have chosen the host (see [`proxy_authority_substituted`]).
        authority_substituted: bool,
    },
}

/// Whether a `[P]` substitution's scheme or authority is built from a `$N`, `%N`,
/// `%{…}` or `${…}` expansion rather than literal text, i.e. whether the request
/// can choose the upstream host.
pub fn proxy_authority_substituted(subst: &str) -> bool {
    if subst == "-" {
        return false;
    }
    let Some(scheme_end) = subst.find("://") else {
        return true;
    };
    let authority_start = scheme_end + 3;
    let authority_end = subst[authority_start..]
        .find(['/', '?', '#'])
        .map_or(subst.len(), |end| authority_start + end);
    subst.as_bytes()[..authority_end]
        .windows(2)
        .any(|pair| matches!(pair[0], b'$' | b'%') && (pair[1].is_ascii_digit() || pair[1] == b'{'))
}

impl RewriteOutcome {
    /// The env mutations carried by this outcome (`[E=...]` sets), regardless of
    /// variant.
    pub fn env(&self) -> &[(String, String)] {
        match self {
            RewriteOutcome::Failed { env, .. }
            | RewriteOutcome::Unchanged { env, .. }
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
#[derive(Debug, Clone)]
pub(crate) enum CompiledRegex {
    Fast(FastRegex),
    Fancy(Regex),
    /// A `fancy_regex` pattern that is only a conjunction of lookaheads, matched with
    /// the linear-time engine (see [`LookaheadConjunction`]).
    Lookaheads(LookaheadConjunction),
}

/// `^(?=.*A)(?=.*B)…` and nothing else: the usual way to AND conditions in one PCRE
/// (the forum's member-preview cookie `SetEnvIf`). At `^`, `(?=.*A)` holds exactly when
/// some match of `A` starts within the subject's first line, so each `A` runs as one
/// linear-time search instead of `fancy_regex`'s backtracking VM walking the subject
/// per lookahead (~30 µs per evaluation on a 1.3 KB Cookie). Captures, which only the
/// backtracking engine reports for lookahead groups, still come from `fancy`.
#[derive(Debug, Clone)]
pub struct LookaheadConjunction {
    parts: Box<[FastRegex]>,
    fancy: Regex,
}

impl LookaheadConjunction {
    fn compile(prepared: &str, fancy: &Regex) -> Option<Self> {
        let parts = lookahead_conjunction_parts(prepared)?
            .iter()
            .map(|part| {
                let re = meta::Regex::new(part).ok()?;
                let id = FAST_REGEX_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(FastRegex { re, id })
            })
            .collect::<Option<Box<[_]>>>()?;
        Some(LookaheadConjunction {
            parts,
            fancy: fancy.clone(),
        })
    }

    fn is_match(&self, text: &str) -> bool {
        match text.find('\n') {
            // Every match starts in the only line (header values never hold a newline),
            // so the forward search suffices, without the reverse pass a match start costs.
            None => self.parts.iter().all(|part| part.is_match(text)),
            Some(first_line_end) => self.parts.iter().all(|part| {
                part.leftmost_start(text)
                    .is_some_and(|start| start <= first_line_end)
            }),
        }
    }
}

/// The parts `A`, `B`, … of a pattern that is exactly `^(?=.*A)(?=.*B)…`, each with the
/// pattern's leading case-insensitivity flag, or `None` for any other shape (another flag,
/// a lazy or possessive `.*`, anything outside the lookaheads, or a top-level `|` in a
/// lookahead: `(?=.*A|B)` is `.*A` or `B` at the start, not `A|B` anywhere).
fn lookahead_conjunction_parts(prepared: &str) -> Option<Vec<String>> {
    let mut rest = prepared;
    let mut flags = "";
    while let Some(after) = rest.strip_prefix("(?") {
        let end = after.find(')')?;
        let group = &after[..end];
        if group.is_empty() || !group.bytes().all(|b| b == b'i') {
            return None;
        }
        flags = "(?i)";
        rest = &after[end + 1..];
    }
    rest = rest.strip_prefix('^')?;
    let mut parts = Vec::new();
    while !rest.is_empty() {
        let body = rest.strip_prefix("(?=.*")?;
        if body.starts_with(['?', '+', '*', '{']) {
            return None;
        }
        let close = group_close(body.as_bytes())?;
        parts.push(format!("{flags}{}", &body[..close]));
        rest = &body[close + 1..];
    }
    (!parts.is_empty()).then_some(parts)
}

/// Index of the `)` closing a group whose body starts at `b[0]`; `None` when the body
/// alternates at its top level.
fn group_close(b: &[u8]) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'[' => i = class_close(b, i)?,
            b'(' => depth += 1,
            b')' if depth == 0 => return Some(i),
            b')' => depth -= 1,
            b'|' if depth == 0 => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

/// Index of the `]` closing the bracket class opened at `b[open]`.
fn class_close(b: &[u8], open: usize) -> Option<usize> {
    let mut i = open + 1;
    if b.get(i) == Some(&b'^') {
        i += 1;
    }
    if b.get(i) == Some(&b']') {
        i += 1;
    }
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'[' if b.get(i + 1) == Some(&b':') => {
                let name_end = b.get(i + 2..)?.windows(2).position(|w| w == b":]")?;
                i += 2 + name_end + 1;
            }
            b'[' => i = class_close(b, i)?,
            b']' => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// The linear-time engine, using `regex_automata::meta::Regex` directly (not the
/// high-level `regex::Regex`) so each search supplies an explicit **thread-local
/// `Cache`** keyed by [`FastRegex::id`]. The high-level wrapper owns one internal
/// cache pool with a single-owner-thread fast path; under tokio work-stealing the
/// connection task migrates across all workers, so the other threads take the
/// pool's cross-thread mutex slow path (`Pool::get_slow`, ~5% of CPU on the
/// 130-rule front controller). A per-thread cache removes that contention.
/// A clone keeps its `id`: it shares the original's compiled engine, so its
/// per-thread cache stays valid.
#[derive(Debug, Clone)]
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
    /// Start of the leftmost match in `text`.
    fn leftmost_start(&self, text: &str) -> Option<usize> {
        FAST_REGEX_CACHES.with(|cell| {
            let mut map = cell.borrow_mut();
            if map.len() > FAST_REGEX_CACHE_CAP {
                map.clear();
            }
            let (cache, _) = map
                .entry(self.id)
                .or_insert_with(|| (self.re.create_cache(), self.re.create_captures()));
            self.re
                .search_with(cache, &Input::new(text))
                .map(|m| m.start())
        })
    }

    fn is_match(&self, text: &str) -> bool {
        FAST_REGEX_CACHES.with(|cell| {
            let mut map = cell.borrow_mut();
            if map.len() > FAST_REGEX_CACHE_CAP {
                map.clear();
            }
            let (cache, _) = map
                .entry(self.id)
                .or_insert_with(|| (self.re.create_cache(), self.re.create_captures()));
            self.re
                .search_half_with(cache, &Input::new(text).earliest(true))
                .is_some()
        })
    }

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
    pub(crate) fn get(&self, i: usize) -> Option<&str> {
        match self {
            Caps::Fast { groups, text } => {
                groups.get(i).copied().flatten().map(|(s, e)| &text[s..e])
            }
            Caps::Fancy(c) => c.get(i).map(|m| m.as_str()),
        }
    }
}

/// PCRE (Apache/OLS) reads `\<` and `\>` as the literal brackets, where Rust's
/// regex syntax reads them as word boundaries: the common `(\<|%3C).*script` block
/// rule 403'd every `description` query and `^\<foo` never matched (#952).
pub(crate) fn pcre_literal_escapes(src: &str) -> std::borrow::Cow<'_, str> {
    if !src.contains("\\<") && !src.contains("\\>") {
        return std::borrow::Cow::Borrowed(src);
    }
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(n @ ('<' | '>')) => out.push(n),
            Some(n) => {
                out.push('\\');
                out.push(n);
            }
            None => out.push('\\'),
        }
    }
    std::borrow::Cow::Owned(out)
}

impl CompiledRegex {
    #[inline]
    pub(crate) fn can_fail_at_match_time(&self) -> bool {
        matches!(self, CompiledRegex::Fancy(_) | CompiledRegex::Lookaheads(_))
    }

    /// Compile `src` (case-insensitive when `nocase`), preferring the linear-time
    /// `regex_automata` engine and falling back to `fancy_regex` for unsupported features.
    pub(crate) fn compile(
        src: &str,
        nocase: bool,
        line: usize,
    ) -> Result<CompiledRegex, RewriteError> {
        let pcre = pcre_literal_escapes(src);
        let prepared = if nocase {
            format!("(?i){pcre}")
        } else {
            pcre.into_owned()
        };
        // `meta::Regex` is the same engine the high-level `regex` crate is built on,
        // so it accepts/rejects the identical pattern set with identical match
        // semantics — a pattern it rejects (lookaround / backref) still falls back
        // to `fancy_regex`, exactly as the former `regex::Regex::new` path did.
        if let Ok(re) = meta::Regex::new(&prepared) {
            let id = FAST_REGEX_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(CompiledRegex::Fast(FastRegex { re, id }));
        }
        let fancy = Regex::new(&prepared).map_err(|e| RewriteError::BadRegex {
            line,
            pattern: src.to_string(),
            source: Box::new(e),
        })?;
        Ok(match LookaheadConjunction::compile(&prepared, &fancy) {
            Some(conjunction) => CompiledRegex::Lookaheads(conjunction),
            None => CompiledRegex::Fancy(fancy),
        })
    }

    /// Run the pattern against `text`, returning the captures on a match.
    #[inline]
    pub(crate) fn captures<'t>(&self, text: &'t str) -> Option<Caps<'t>> {
        match self {
            CompiledRegex::Fast(r) => r.captures(text),
            // fancy_regex returns Result<Option<_>>; a regex *error* at match time
            // is treated as a non-match (matches the prior `.unwrap_or_default()`).
            CompiledRegex::Fancy(r)
            | CompiledRegex::Lookaheads(LookaheadConjunction { fancy: r, .. }) => {
                r.captures(text).ok().flatten().map(Caps::Fancy)
            }
        }
    }

    /// [`CompiledRegex::captures_checked`] without the groups. fancy_regex runs
    /// the same VM (same backtrack budget) for both, so match/no-match and the
    /// match-time error are identical; only the saves are not copied out.
    #[inline]
    pub(crate) fn is_match_checked(&self, text: &str) -> Result<bool, ()> {
        match self {
            CompiledRegex::Fast(r) => Ok(r.is_match(text)),
            CompiledRegex::Fancy(r) => r.is_match(text).map_err(|_| ()),
            CompiledRegex::Lookaheads(r) => Ok(r.is_match(text)),
        }
    }

    /// Checked runtime match used by request authorization/routing. Fancy
    /// regexes can fail after successful compilation (for example when their
    /// backtracking limit is exhausted); preserve that distinction.
    #[inline]
    pub(crate) fn captures_checked<'t>(&self, text: &'t str) -> Result<Option<Caps<'t>>, ()> {
        match self {
            CompiledRegex::Fast(r) => Ok(r.captures(text)),
            CompiledRegex::Fancy(r)
            | CompiledRegex::Lookaheads(LookaheadConjunction { fancy: r, .. }) => r
                .captures(text)
                .map(|caps| caps.map(Caps::Fancy))
                .map_err(|_| ()),
        }
    }
}

// ===========================================================================
// Evaluation entry
// ===========================================================================

/// Run a [`RuleSet`] against a [`RewriteInput`]: rules run top-to-bottom once;
/// a matched `[L]`/`[F]`/`[P]`/`[R]` stops the pass, and only `[N]` re-runs
/// the list (up to [`MAX_ITERATIONS`]).
/// True when an absolute `location` names the request's own URL (same scheme,
/// Host and path+query).
fn absolute_target_is_current(location: &str, input: &RewriteInput) -> bool {
    let scheme = if input.https { "https://" } else { "http://" };
    let Some(rest) = location
        .get(..scheme.len())
        .filter(|p| p.eq_ignore_ascii_case(scheme))
        .map(|_| &location[scheme.len()..])
    else {
        return false;
    };
    let (authority, path_query) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let default_port = if input.https { 443 } else { 80 };
    // `host[:port]` or `[v6][:port]`; `input.host` is port- and bracket-stripped.
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let Some((h, after)) = v6.split_once(']') else {
            return false;
        };
        let port = match after.strip_prefix(':') {
            Some(p) => match p.parse::<u16>() {
                Ok(p) => p,
                Err(_) => return false,
            },
            None if after.is_empty() => default_port,
            None => return false,
        };
        (h, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => (h, p),
                Err(_) => return false,
            },
            None => (authority, default_port),
        }
    };
    let current_port = input.host_port.unwrap_or(default_port);
    if !host.eq_ignore_ascii_case(&input.host) || port != current_port {
        return false;
    }
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_query, ""),
    };
    let path = if path.is_empty() { "/" } else { path };
    // The location is escaped; the input URI is decoded (OLS compares unescaped).
    query == input.query.as_ref() && percent_decoded(path) == input.uri.as_bytes()
}

fn percent_decoded(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        if b[i] == b'%'
            && let (Some(Some(h)), Some(Some(l))) =
                (b.get(i + 1).map(|&c| hex(c)), b.get(i + 2).map(|&c| hex(c)))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

pub fn evaluate(rs: &RuleSet, input: &RewriteInput) -> RewriteOutcome {
    evaluate_with_engine(rs, input, rs.engine_on)
}

/// [`evaluate`] with the effective engine state resolved by the caller (a
/// per-directory set without `RewriteEngine` inherits it; see
/// [`RuleSet::engine_state`]).
pub fn evaluate_with_engine(rs: &RuleSet, input: &RewriteInput, engine_on: bool) -> RewriteOutcome {
    if !engine_on {
        return RewriteOutcome::Unchanged {
            env: Vec::new(),
            end: false,
        };
    }

    let _fs_memo = FsMemoScope::enter();
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
        env_unset: Vec::new(),
        last_cond_caps: std::array::from_fn(|_| None),
        prefilter_valid: true,
        pending_absolute: false,
        uri_escaped: false,
        last_cond_escaped: None,
        next_loops: 0,
        regex_failed: false,
    };
    // Run the multi-pattern prefilter once against the initial stripped target.
    // `state.prefilter_valid` guards its use after any URI rewrite.
    let prefilter_target = rule_match_target(input, &input.uri);
    let hits: Option<PatternSet> = rs
        .prefilter
        .as_ref()
        .map(|pf| pf.matches(prefilter_target.as_ref()));
    let hits = hits.as_ref();

    // One pass, as OLS `processRuleSet`: a changed URI is final for this ruleset
    // (a target in another directory is handed to that directory's chain by the
    // pipeline). Only `[N]`/`[next]` re-runs it, bounded by `state.next_loops`.
    // Re-running on a changed URI re-matched a front controller's own target:
    // Symfony's `^index\.php` guard redirected every route, and `index.php/$1`
    // nested itself to MAX_ITERATIONS (#880).
    // `ended`: an `[END]` fired, so the outcome tells the pipeline to stop
    // subsequent rulesets / `.htaccess` processing.
    let ended = loop {
        match run_pass(rs, input, &mut state, hits) {
            PassResult::Terminal(outcome) => return outcome,
            PassResult::Restart => {}
            PassResult::Continue { end } => break end,
        }
    };

    if state.pending_absolute && eval::is_absolute_uri(&state.uri) {
        let mut location = std::mem::take(&mut state.uri);
        if !state.query.is_empty() {
            location.push('?');
            location.push_str(&state.query);
        }
        // OLS detectLoopRedirect: a target naming the current URL would loop forever.
        if absolute_target_is_current(&location, input) {
            return RewriteOutcome::Unchanged {
                env: state.env_vec(),
                end: ended,
            };
        }
        return RewriteOutcome::Redirect {
            code: 302,
            location,
            env: state.env_vec(),
        };
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

#[cfg(test)]
mod lookahead_conjunction_tests {
    use super::*;

    /// The forum's member-preview cookie rule, as `SetEnvIfNoCase` compiles it.
    const PREVIEW: &str = r"^(?=.*(?:^|;[[:space:]]*)xf_(?:user|session)=[^;]+(?:;|$))(?=.*(?:^|;[[:space:]]*)xf_style_id=51(?:;|$))";

    #[test]
    fn only_a_pure_lookahead_conjunction_is_split() {
        assert_eq!(
            lookahead_conjunction_parts("(?i)^(?=.*a(b)[)(]c)(?=.*d)").unwrap(),
            ["(?i)a(b)[)(]c", "(?i)d"]
        );
        assert_eq!(
            lookahead_conjunction_parts(r"^(?=.*[[:space:]\]]x)").unwrap(),
            [r"[[:space:]\]]x"]
        );
        for other in [
            "^(?=.*a|b)",
            "^(?=.*a)(?=.*b|c)",
            "^(?=.*a)b",
            "(?=.*a)",
            "^(?=.*?a)",
            "^(?=a)",
            "(?s)^(?=.*a)",
            "(?m)^(?=.*a)",
            "^(?!.*a)",
            "^(?=.*a",
            "^",
        ] {
            assert!(lookahead_conjunction_parts(other).is_none(), "{other}");
        }
        assert!(matches!(
            CompiledRegex::compile(PREVIEW, true, 1).unwrap(),
            CompiledRegex::Lookaheads(_)
        ));
        // A part the linear engine rejects keeps the backtracking engine.
        assert!(matches!(
            CompiledRegex::compile(r"^(?=.*(a)\1)", false, 1).unwrap(),
            CompiledRegex::Fancy(_)
        ));
    }

    /// The split engine agrees with `fancy_regex` on every input, including newlines
    /// (`.` stops at the first one) and case variants.
    #[test]
    fn split_conjunctions_match_exactly_what_fancy_regex_matches() {
        let patterns = [
            (PREVIEW, true),
            (PREVIEW, false),
            (r"^(?=.*foo)(?=.*bar)", false),
            (r"^(?=.*(?:^|;)a=1(?:;|$))", true),
            (r"^(?=.*b$)(?=.*^a)", false),
            (r"^(?=.*a[[:space:]]b)", false),
            (r"^(?=.*(?:foo|bar))(?=.*[|]x)", false),
        ];
        let atoms = [
            "xf_user=1",
            "XF_SESSION=ab",
            "xf_style_id=51",
            "xf_style_id=5",
            "xf_style_id=511",
            "; ",
            ";",
            " ",
            "\n",
            "\t",
            "a=1",
            "A=1",
            "foo",
            "BAR",
            "bar",
            "a",
            "b",
            "a\nb",
            "=",
            "é",
            "x",
            "|x",
            "xxbar",
        ];
        let compiled: Vec<_> = patterns
            .iter()
            .map(|(p, nocase)| {
                let prepared = if *nocase {
                    format!("(?i){p}")
                } else {
                    p.to_string()
                };
                let fancy = Regex::new(&prepared).unwrap();
                let split = LookaheadConjunction::compile(&prepared, &fancy)
                    .unwrap_or_else(|| panic!("{p} must split"));
                (fancy, split)
            })
            .collect();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut subject = String::new();
            let mut y = x;
            for _ in 0..(x % 9) {
                subject.push_str(atoms[(y % atoms.len() as u64) as usize]);
                y = y.rotate_left(7) ^ 0x5851_f42d_4c95_7f2d;
            }
            for (fancy, split) in &compiled {
                assert_eq!(
                    split.is_match(&subject),
                    fancy.is_match(&subject).unwrap(),
                    "{:?} on {subject:?}",
                    fancy.as_str()
                );
            }
        }
    }
}
