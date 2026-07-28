//! Rule-set parsing: the [`RuleSet::parse`] driver plus the tokenizers,
//! `RewriteCond`/`RewriteRule`/flag parsers, and OR-condition folding that turn
//! a raw `mod_rewrite` snippet into the evaluable model defined in the parent.

use crate::error::RewriteError;

use super::eval::pattern_expects_leading_slash;
use super::*;

// ===========================================================================
// Parsing
// ===========================================================================

/// True if `src` contains an unescaped `(` (a regex group). We only fold
/// group-free condition patterns into an alternation so the combined regex
/// introduces no capture groups and `%N` cond-backreference numbering is
/// preserved exactly.
fn regex_has_paren_group(src: &str) -> bool {
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'(' => return true,
            _ => i += 1,
        }
    }
    false
}

/// Whether a condition can be folded into a same-variable OR alternation: a
/// plain (non-negated) regex test whose pattern has no group. File/lexical/
/// numeric tests, negations, and grouped patterns are left untouched.
fn cond_or_foldable(c: &Cond) -> bool {
    !c.negate && matches!(&c.pattern, CondPattern::Regex(_, src) if !regex_has_paren_group(src))
}

/// Fold runs of consecutive `[OR]`-linked `RewriteCond`s that test the SAME
/// variable with group-free regexes into a single alternation cond, so e.g. a
/// 28-line `RewriteCond %{HTTP_USER_AGENT} Bot [OR]` crawler block becomes one
/// `(?:Bot1)|(?:Bot2)|…` match instead of 28 sequential regex evaluations.
///
/// Semantics-preserving: an OR group matches iff ANY member matches, which is
/// exactly what the alternation tests. Only whole, uniform groups are folded
/// (same `test_string`, same `nocase`, all foldable); anything else is kept
/// verbatim. The merged cond inherits the group's trailing `or_next` (`false`).
fn combine_or_conds(conds: Vec<Cond>) -> Vec<Cond> {
    let n = conds.len();
    let mut slots: Vec<Option<Cond>> = conds.into_iter().map(Some).collect();
    let mut out: Vec<Cond> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        // The OR group starting at i runs while `or_next` holds; it ends at the
        // first cond with `or_next == false` (inclusive).
        let mut end = i;
        while end < n && slots[end].as_ref().unwrap().or_next {
            end += 1;
        }
        if end >= n {
            end = n - 1; // trailing `[OR]` with no following cond (malformed); treat as group end
        }

        let first = slots[i].as_ref().unwrap();
        let foldable = end > i
            && (i..=end).all(|k| {
                let c = slots[k].as_ref().unwrap();
                cond_or_foldable(c)
                    && c.test_string == first.test_string
                    && c.nocase == first.nocase
            });

        if foldable {
            let nocase = first.nocase;
            let line = first.line;
            let test_string = first.test_string.clone();
            let last_or = slots[end].as_ref().unwrap().or_next; // always false here
            let alt = (i..=end)
                .map(|k| match &slots[k].as_ref().unwrap().pattern {
                    CondPattern::Regex(_, src) => format!("(?:{src})"),
                    _ => unreachable!("foldable implies Regex"),
                })
                .collect::<Vec<_>>()
                .join("|");
            // Only fold if the alternation actually compiles; otherwise keep the
            // originals (never drop conditions on a compile error).
            if let Ok(re) = CompiledRegex::compile(&alt, nocase, line) {
                for slot in &mut slots[i..=end] {
                    *slot = None;
                }
                out.push(Cond {
                    test_string,
                    pattern: CondPattern::Regex(re, alt),
                    nocase,
                    or_next: last_or,
                    negate: false,
                    line,
                });
                i = end + 1;
                continue;
            }
        }

        for slot in &mut slots[i..=end] {
            out.push(slot.take().unwrap());
        }
        i = end + 1;
    }
    out
}

/// A `%{VAR}` whose value is part of the outcome-cache key (path/host/query/
/// method/scheme) or constant per vhost. A rule referencing only these (plus
/// literals, `$N`/`%N` backrefs, and `-f`/`-d` tests) produces an outcome that
/// is a pure function of the cache key (within the cache's TTL). Everything else
/// — `HTTP_USER_AGENT`/`HTTP_COOKIE`/`HTTP:*` headers, `REMOTE_*`, `SERVER_ADDR`,
/// `SERVER_PORT`, `TIME*`, `THE_REQUEST`, `ENV:*`, and any unrecognized name —
/// is treated as varying (fail-closed).
fn var_is_cache_safe(var: &str) -> bool {
    matches!(
        var,
        "REQUEST_URI"
            | "REQUEST_FILENAME"
            | "SCRIPT_FILENAME"
            | "HTTP_HOST"
            | "QUERY_STRING"
            | "REQUEST_METHOD"
            | "HTTPS"
            | "REQUEST_SCHEME"
            | "SERVER_NAME"
            | "DOCUMENT_ROOT"
    )
}

/// An `%{ENV:NAME}` read that is CONSTANT-EMPTY at rewrite-eval time and may be
/// classified cache-safe, provided the pipeline verifies the live env seed does
/// not actually carry the name (recorded via [`RuleSet::assumed_empty_env`]).
///
/// `ENV:REDIRECT_STATUS`: httpjet sets `REDIRECT_STATUS` in exactly two places,
/// NEITHER of which the rewrite engine's `%{ENV:}` lookup (the `[E=]` overlay →
/// owned env → borrowed `ctx.env` seed chain, `eval.rs::resolve_var_into`) can
/// observe:
///   * `hj-lsapi`'s CGI env builder (`cgi.rs`) adds `REDIRECT_STATUS=200` to the
///     env HANDED TO lsphp — downstream of rewrite, never written to `ctx.env`.
///   * `pipeline::response_util::run_php_error_document` sets it on `ctx.env`
///     for an ErrorDocument PHP subrequest — a TERMINAL response path that runs
///     strictly after the request's one rewrite evaluation (both `dispatch()`
///     and the on-core fast path run the rewrite exactly once, on a fresh
///     per-request `ReqCtx`).
///
/// So under Apache/LSWS the live `RewriteCond %{ENV:REDIRECT_STATUS} ^(403|5)`
/// gates error subrequests, but in this engine it can only ever see `""` — a
/// constant — unless something seeds the name (e.g. a hypothetical `SetEnvIf
/// … REDIRECT_STATUS=…`), which the pipeline's seed check catches at runtime.
fn env_var_assumed_empty(var: &str) -> Option<&'static str> {
    let name = var.strip_prefix("ENV:")?;
    (name == "REDIRECT_STATUS").then_some("REDIRECT_STATUS")
}

/// A per-request-varying `%{VAR}` the outcome cache can KEY on (so a rule reading
/// it stays cacheable, with the value folded into the key). Conservative allowlist:
/// `%{HTTP_USER_AGENT}` / `%{HTTP:User-Agent}`, and `%{HTTP:Origin}`.
fn keyable_var(var: &str) -> Option<CacheKeyVar> {
    if var.eq_ignore_ascii_case("HTTP_USER_AGENT") {
        return Some(CacheKeyVar::UserAgent);
    }
    if let Some(hdr) = var.strip_prefix("HTTP:") {
        if hdr.eq_ignore_ascii_case("User-Agent") {
            return Some(CacheKeyVar::UserAgent);
        }
        if hdr.eq_ignore_ascii_case("Origin") {
            return Some(CacheKeyVar::Origin);
        }
    }
    None
}

/// Classify every `%{...}` reference in `s`: each must be cache-safe (already in
/// the base key), an assumed-empty env read (pushed into `assumed_env`), OR a
/// keyable dynamic var (pushed into `keys`). Returns `false` (uncacheable) on the
/// first var that is none of those, or a malformed `%{` with no closing `}`
/// (fail-closed). `$N`/`%N` backrefs are not `%{...}` and are inherently safe
/// (derived from the path/cond match).
fn string_cache_class(s: &str, keys: &mut Vec<CacheKeyVar>, assumed_env: &mut Vec<String>) -> bool {
    let mut rest = s;
    while let Some(p) = rest.find("%{") {
        let after = &rest[p + 2..];
        let Some(end) = after.find('}') else {
            return false;
        };
        let var = &after[..end];
        if !var_is_cache_safe(var) {
            if let Some(name) = env_var_assumed_empty(var) {
                if !assumed_env.iter().any(|n| n == name) {
                    assumed_env.push(name.to_string());
                }
            } else {
                match keyable_var(var) {
                    Some(kv) => {
                        if !keys.contains(&kv) {
                            keys.push(kv);
                        }
                    }
                    None => return false,
                }
            }
        }
        rest = &after[end + 1..];
    }
    true
}

/// True iff evaluating `rule` depends only on the base cache key plus keyable
/// dynamic vars (accumulated into `keys`) — its conditions, substitution, and
/// `[E=...]` values reference only cache-safe or keyable `%{VAR}`s. Filesystem
/// cond tests are allowed (staleness bounded by the outcome cache's TTL).
fn rule_cache_class(
    rule: &Rule,
    keys: &mut Vec<CacheKeyVar>,
    assumed_env: &mut Vec<String>,
) -> bool {
    let mut ok = string_cache_class(&rule.subst, keys, assumed_env);
    for (k, v) in &rule.flags.env_sets {
        ok &= string_cache_class(k, keys, assumed_env) && string_cache_class(v, keys, assumed_env);
    }
    for c in &rule.conds {
        ok &= string_cache_class(&c.test_string, keys, assumed_env);
        // The comparison RHS is also `%{VAR}`-expanded at eval time (see eval.rs), so
        // a per-request-varying var there (e.g. `=%{ENV:X}`, `>%{REMOTE_ADDR}`) must
        // make the ruleset uncacheable too — classifying only the LHS test_string
        // would wrongly memoize an outcome computed from an omitted varying input.
        if let CondPattern::Lexical(_, rhs) | CondPattern::Numeric(_, rhs) = &c.pattern {
            ok &= string_cache_class(rhs, keys, assumed_env);
        }
    }
    ok
}

/// True if `s` contains a `%N` cond-backreference (a `%` immediately followed by
/// a digit, NOT a `%{` var open). Mirror of [`uses_dollar_backref`].
fn uses_percent_backref(s: &str) -> bool {
    let b = s.as_bytes();
    b.windows(2).any(|w| w[0] == b'%' && w[1].is_ascii_digit())
}

/// True if `s` references the User-Agent through any `%{...}` form.
fn string_refs_ua(s: &str) -> bool {
    let mut rest = s;
    while let Some(p) = rest.find("%{") {
        let after = &rest[p + 2..];
        let Some(end) = after.find('}') else {
            return false;
        };
        if keyable_var(&after[..end]) == Some(CacheKeyVar::UserAgent) {
            return true;
        }
        rest = &after[end + 1..];
    }
    false
}

/// True iff `s` is EXACTLY one UA var reference (`%{HTTP_USER_AGENT}` /
/// `%{HTTP:User-Agent}`, any case) — no surrounding literals or other vars.
fn is_exact_ua_var(s: &str) -> bool {
    s.len() > 3
        && s.starts_with("%{")
        && s.ends_with('}')
        && !s[2..s.len() - 1].contains('}')
        && keyable_var(&s[2..s.len() - 1]) == Some(CacheKeyVar::UserAgent)
}

/// Decide UA-classification eligibility for a parsed, `path_cacheable` set that
/// reads the User-Agent, and collect its UA-cond positions. Sound iff the
/// outcome's ONLY dependence on the UA value is the boolean match result of each
/// UA cond — then keying on the match bitmap is exact. Conservative requirements:
///   * every UA read sits in a cond TEST STRING that is exactly the UA var
///     (`%{HTTP_USER_AGENT}` alone — a mixed string like `x%{HTTP_USER_AGENT}`
///     couples the match result to other inputs of the concatenation);
///   * that cond's pattern is a plain regex (file tests would stat a UA-derived
///     path; lexical/numeric comparisons are excluded for simplicity);
///   * no UA reference in any substitution, `[E=...]` set, or comparison RHS
///     (those embed the raw UA value in the outcome);
///   * no `%N` cond-backreference anywhere in the set: `%0`..`%9` resolve from
///     the LAST MATCHED cond, so any of them may expose a UA cond's matched
///     substring (which varies within one bitmap value, e.g. `Bot\w+`);
///   * at most 64 UA conds (the bitmap width).
///
/// Negated conds and `[NC]` are fine: negation/casefolding are applied
/// deterministically to/inside the memoized match result.
fn compute_ua_classify(rules: &[Rule]) -> (bool, Vec<(usize, usize)>) {
    let mut ua_conds: Vec<(usize, usize)> = Vec::new();
    for (ri, rule) in rules.iter().enumerate() {
        if string_refs_ua(&rule.subst) || uses_percent_backref(&rule.subst) {
            return (false, Vec::new());
        }
        for (k, v) in &rule.flags.env_sets {
            if string_refs_ua(k)
                || string_refs_ua(v)
                || uses_percent_backref(k)
                || uses_percent_backref(v)
            {
                return (false, Vec::new());
            }
        }
        for (ci, c) in rule.conds.iter().enumerate() {
            if uses_percent_backref(&c.test_string) {
                return (false, Vec::new());
            }
            if let CondPattern::Lexical(_, rhs) | CondPattern::Numeric(_, rhs) = &c.pattern
                && (string_refs_ua(rhs) || uses_percent_backref(rhs))
            {
                return (false, Vec::new());
            }
            if string_refs_ua(&c.test_string) {
                if !is_exact_ua_var(&c.test_string) || !matches!(c.pattern, CondPattern::Regex(..))
                {
                    return (false, Vec::new());
                }
                ua_conds.push((ri, ci));
            }
        }
    }
    if ua_conds.is_empty() || ua_conds.len() > 64 {
        return (false, Vec::new());
    }
    (true, ua_conds)
}

impl RuleSet {
    /// Parse a raw Apache `mod_rewrite` snippet into an evaluable [`RuleSet`].
    ///
    /// Recognizes `RewriteEngine`, `RewriteBase`, `RewriteCond`, and
    /// `RewriteRule`. Non-rewrite directives are ignored here (see
    /// [`crate::Htaccess`] for the directive-aware parser). Line continuations
    /// (`\` at EOL) are joined.
    pub fn parse(rules: &str) -> Result<RuleSet, RewriteError> {
        let mut set = RuleSet::default();
        let mut pending_conds: Vec<Cond> = Vec::new();

        for (line, raw) in logical_lines(rules) {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (directive, rest) = split_first_token(trimmed);
            match directive.to_ascii_lowercase().as_str() {
                "rewriteengine" => {
                    set.engine_on = matches!(
                        rest.trim().to_ascii_lowercase().as_str(),
                        "on" | "1" | "true" | "yes"
                    );
                }
                "rewritebase" => {
                    let b = rest.trim();
                    if !b.is_empty() {
                        set.base = Some(b.to_string());
                    }
                }
                "rewritecond" => {
                    pending_conds.push(parse_cond(rest, line)?);
                }
                "rewriterule" => {
                    let mut rule = parse_rule(rest, std::mem::take(&mut pending_conds), line)?;
                    // Fold same-variable OR-condition runs into one alternation
                    // regex (e.g. a 28-line User-Agent crawler block -> 1 match).
                    rule.conds = combine_or_conds(std::mem::take(&mut rule.conds));
                    set.rules.push(rule);
                }
                _ => {
                    // Not a rewrite directive — a stray cond block without a
                    // following rule is simply dropped (matches Apache, which
                    // discards orphaned conds).
                }
            }
        }

        // Build the multi-pattern prefilter over the "simple" rules: non-negated,
        // non-fancy (compiles as a plain `regex`), matched against the stripped
        // target. A prefilter miss is a guaranteed non-match (identical semantics
        // to the per-rule `fancy_regex`), so the per-rule regex can be skipped.
        let mut prefilter_pats: Vec<String> = Vec::new();
        for rule in &mut set.rules {
            if rule.negate || pattern_expects_leading_slash(&rule.pattern_src) {
                continue;
            }
            let prepared = if rule.flags.nocase {
                format!("(?i){}", rule.pattern_src)
            } else {
                rule.pattern_src.clone()
            };
            if regex::Regex::new(&prepared).is_ok() {
                rule.prefilter_idx = Some(prefilter_pats.len());
                prefilter_pats.push(prepared);
            }
        }
        if !prefilter_pats.is_empty() {
            set.prefilter = PrefilterSet::new(&prefilter_pats);
            if set.prefilter.is_none() {
                // DFA determinization exceeded the size limit — disable the prefilter
                // (rules are still evaluated per-rule, just unfiltered).
                for rule in &mut set.rules {
                    rule.prefilter_idx = None;
                }
            }
        }

        // Outcome-cacheability: safe to memoize by (vhost, scheme, method, host,
        // path, query) iff no rule reads a per-request-varying input. Filesystem
        // (`-f`/`-d`) tests and the safe request fields are fine — the pipeline's
        // outcome cache uses a short TTL that bounds fs staleness exactly like the
        // `-f`/`-d` `StatCache`. Empty rule set => trivially cacheable.
        let mut keys: Vec<CacheKeyVar> = Vec::new();
        let mut assumed_env: Vec<String> = Vec::new();
        set.path_cacheable = set
            .rules
            .iter()
            .all(|r| rule_cache_class(r, &mut keys, &mut assumed_env));
        // Only trust the accumulated keyable/assumed vars if the whole set is
        // cacheable; otherwise an uncacheable rule may have pushed a stray entry.
        if set.path_cacheable {
            set.cache_key_vars = keys;
            set.assumed_empty_env = assumed_env;
            if set.cache_key_vars.contains(&CacheKeyVar::UserAgent) {
                let (eligible, ua_conds) = compute_ua_classify(&set.rules);
                set.ua_classify_eligible = eligible;
                set.ua_conds = ua_conds;
            }
        } else {
            set.cache_key_vars = Vec::new();
            set.assumed_empty_env = Vec::new();
        }
        set.assign_id();
        Ok(set)
    }
}

/// Iterate over logical lines, joining backslash continuations. Yields
/// `(starting_line_number, joined_text)`.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start = 0usize;
    for (idx, line) in text.lines().enumerate() {
        let lineno = idx + 1;
        if buf.is_empty() {
            start = lineno;
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            buf.push_str(stripped);
            buf.push(' ');
        } else {
            buf.push_str(line);
            out.push((start, std::mem::take(&mut buf)));
        }
    }
    if !buf.is_empty() {
        out.push((start, buf));
    }
    out
}

/// Split off the first whitespace-delimited token, returning `(token, rest)`.
fn split_first_token(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    match s.find(char::is_whitespace) {
        Some(idx) => (&s[..idx], s[idx..].trim_start()),
        None => (s, ""),
    }
}

/// Tokenize a directive argument list, honoring double quotes (so a flag list
/// like `[E=var:"a b"]` or a quoted substitution stays intact). Returns the
/// whitespace-separated fields with surrounding quotes stripped.
fn tokenize_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut have_token = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                have_token = true;
            }
            '\\' if in_quotes => {
                // Only `\"` is an escape (a literal quote). Every other
                // backslash is preserved verbatim because patterns are regexes
                // (`\.`, `\d`, ...) and must keep their escapes.
                if let Some(&next) = chars.peek() {
                    if next == '"' {
                        cur.push('"');
                        chars.next();
                    } else {
                        cur.push('\\');
                    }
                } else {
                    cur.push('\\');
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if have_token {
                    out.push(std::mem::take(&mut cur));
                    have_token = false;
                }
            }
            c => {
                cur.push(c);
                have_token = true;
            }
        }
    }
    if have_token {
        out.push(cur);
    }
    out
}

fn parse_cond(rest: &str, line: usize) -> Result<Cond, RewriteError> {
    let args = tokenize_args(rest);
    if args.len() < 2 {
        return Err(RewriteError::Malformed {
            line,
            msg: "RewriteCond requires a test string and a pattern".into(),
        });
    }
    let test_string = args[0].clone();
    let mut pattern_raw = args[1].clone();

    // Optional trailing flag list `[NC,OR]`.
    let (nocase, or_next) = if let Some(flag_field) = args.get(2) {
        parse_cond_flags(flag_field)
    } else {
        (false, false)
    };

    let negate = if let Some(stripped) = pattern_raw.strip_prefix('!') {
        pattern_raw = stripped.to_string();
        true
    } else {
        false
    };

    let pattern = classify_cond_pattern(&pattern_raw, nocase, line)?;
    Ok(Cond {
        test_string,
        pattern,
        nocase,
        or_next,
        negate,
        line,
    })
}

fn parse_cond_flags(field: &str) -> (bool, bool) {
    let inner = field.trim_start_matches('[').trim_end_matches(']');
    let mut nocase = false;
    let mut or_next = false;
    for f in inner.split(',') {
        match f.trim().to_ascii_uppercase().as_str() {
            "NC" => nocase = true,
            "OR" => or_next = true,
            _ => {}
        }
    }
    (nocase, or_next)
}

fn classify_cond_pattern(
    raw: &str,
    nocase: bool,
    line: usize,
) -> Result<CondPattern, RewriteError> {
    // File tests: -f -d -l -s -x (single token).
    match raw {
        "-f" => return Ok(CondPattern::FileTest(FileTestKind::File)),
        "-d" => return Ok(CondPattern::FileTest(FileTestKind::Dir)),
        "-l" => return Ok(CondPattern::FileTest(FileTestKind::Link)),
        "-s" => return Ok(CondPattern::FileTest(FileTestKind::Size)),
        "-x" | "-e" => return Ok(CondPattern::FileTest(FileTestKind::Exists)),
        _ => {}
    }
    // Numeric comparisons: `-eq`/`-ne`/`-gt`/`-lt`/`-ge`/`-le` followed by the
    // operand (OLS consumes exactly the 3-char operator then the rest is the
    // pattern). These must be checked before the file tests / lexical forms.
    if let Some(rest) = raw.strip_prefix('-') {
        let op = match &rest.get(..2) {
            Some("eq") => Some(NumOp::Eq),
            Some("ne") => Some(NumOp::Ne),
            Some("gt") => Some(NumOp::Gt),
            Some("lt") => Some(NumOp::Lt),
            Some("ge") => Some(NumOp::Ge),
            Some("le") => Some(NumOp::Le),
            _ => None,
        };
        if let Some(op) = op {
            return Ok(CondPattern::Numeric(op, rest[2..].trim_start().to_string()));
        }
    }
    // Lexical comparisons. `>=`/`<=` must be tested before bare `>`/`<`.
    if let Some(rhs) = raw.strip_prefix(">=") {
        return Ok(CondPattern::Lexical(
            Ordering::GreaterEqual,
            rhs.to_string(),
        ));
    }
    if let Some(rhs) = raw.strip_prefix("<=") {
        return Ok(CondPattern::Lexical(Ordering::LessEqual, rhs.to_string()));
    }
    if let Some(rhs) = raw.strip_prefix('<') {
        return Ok(CondPattern::Lexical(Ordering::Less, rhs.to_string()));
    }
    if let Some(rhs) = raw.strip_prefix('>') {
        return Ok(CondPattern::Lexical(Ordering::Greater, rhs.to_string()));
    }
    if let Some(rhs) = raw.strip_prefix('=') {
        return Ok(CondPattern::Lexical(Ordering::Equal, rhs.to_string()));
    }
    // Regex.
    let re = CompiledRegex::compile(raw, nocase, line)?;
    Ok(CondPattern::Regex(re, raw.to_string()))
}

fn parse_rule(rest: &str, conds: Vec<Cond>, line: usize) -> Result<Rule, RewriteError> {
    let args = tokenize_args(rest);
    if args.len() < 2 {
        return Err(RewriteError::Malformed {
            line,
            msg: "RewriteRule requires a pattern and a substitution".into(),
        });
    }
    let mut pattern_src = args[0].clone();
    let subst = args[1].clone();
    let flags = if let Some(flag_field) = args.get(2) {
        parse_rule_flags(flag_field)
    } else {
        RuleFlags::default()
    };

    let negate = if let Some(stripped) = pattern_src.strip_prefix('!') {
        pattern_src = stripped.to_string();
        true
    } else {
        false
    };

    let pattern = CompiledRegex::compile(&pattern_src, flags.nocase, line)?;
    // Does any COND reference a `$N` rule backref (test string or lexical|numeric
    // RHS)? Computed separately because it gates the cond pre-screen in `apply_rule`.
    let conds_need_rule_caps = conds.iter().any(|c| {
        uses_dollar_backref(&c.test_string)
            || matches!(&c.pattern,
                CondPattern::Lexical(_, rhs) | CondPattern::Numeric(_, rhs)
                    if uses_dollar_backref(rhs))
    });
    // Does anything reference a `$N` rule backref? (subst, [E=...] sets, or any
    // cond). If not, skip capture extraction. Superset of `conds_need_rule_caps`.
    let needs_rule_caps = uses_dollar_backref(&subst)
        || flags
            .env_sets
            .iter()
            .any(|(k, v)| uses_dollar_backref(k) || uses_dollar_backref(v))
        || conds_need_rule_caps;
    let literal_prefix = extract_literal_prefix(&pattern_src, negate, flags.nocase);
    let match_total = recognize_total_match(&pattern_src, negate, flags.nocase);
    Ok(Rule {
        match_total,
        conds,
        pattern,
        pattern_src,
        negate,
        subst,
        flags,
        prefilter_idx: None, // assigned by RuleSet::parse after all rules are parsed
        needs_rule_caps,
        conds_need_rule_caps,
        literal_prefix,
    })
}

fn parse_rule_flags(field: &str) -> RuleFlags {
    let inner = field.trim();
    let inner = inner.strip_prefix('[').unwrap_or(inner);
    let inner = inner.strip_suffix(']').unwrap_or(inner);

    let mut flags = RuleFlags::default();
    for tok in split_flag_list(inner) {
        let tok = tok.trim();
        let upper = tok.to_ascii_uppercase();
        if upper == "L" || upper == "LAST" {
            flags.last = true;
        } else if upper == "END" {
            // Apache 2.3.9+: [END] = [L] + stop ALL further rewriting. It ends
            // the current pass (like [L]), the outer restart-on-URI-change loop,
            // AND subsequent .htaccess / ruleset processing (the latter signalled
            // out via RewriteOutcome's `end` flag).
            flags.last = true;
            flags.end = true;
        } else if upper == "QSA" || upper == "QSAPPEND" {
            flags.qsa = true;
        } else if upper == "QSD" || upper == "QSDISCARD" {
            flags.qsd = true;
        } else if upper == "F" || upper == "FORBIDDEN" {
            flags.forbidden = true;
            flags.last = true; // [F] implies last (OLS sets RULE_FLAG_LAST)
        } else if upper == "G" || upper == "GONE" {
            flags.gone = true;
            flags.last = true; // [G] implies last (OLS sets RULE_FLAG_LAST)
        } else if upper == "NC" || upper == "NOCASE" {
            flags.nocase = true;
        } else if upper == "P" || upper == "PROXY" || upper == "PT" || upper == "PASSTHROUGH" {
            // OLS: [PT]/[passthrough] also sets RULE_FLAG_LAST; it hands the
            // rewritten URI to the next handler rather than proxying out.
            // Without a separate handler stage we treat it like proxy's
            // last-stopping behavior but keep `proxy` only for true [P].
            if upper == "P" || upper == "PROXY" {
                flags.proxy = true;
            }
            flags.last = true; // [P]/[PT] imply last
        } else if upper == "NE" || upper == "NOESCAPE" {
            flags.noescape = true;
        } else if upper == "C" || upper == "CHAIN" {
            flags.chain = true;
        } else if upper == "N" || upper == "NEXT" {
            flags.next = true;
        } else if upper == "R" || upper == "REDIRECT" {
            flags.redirect = Some(302);
        } else if let Some(code) = upper.strip_prefix("R=") {
            flags.redirect = Some(parse_redirect_code(code));
        } else if let Some(code) = upper.strip_prefix("REDIRECT=") {
            flags.redirect = Some(parse_redirect_code(code));
        } else if let Some(n) = upper
            .strip_prefix("S=")
            .or_else(|| upper.strip_prefix("SKIP="))
        {
            // OLS uses strtol; a non-numeric value is a parse error there, but
            // we degrade to 0 (no skip) rather than failing the whole set.
            flags.skip = n.trim().parse().unwrap_or(0);
        } else if let Some(spec) = tok.strip_prefix("E=").or_else(|| tok.strip_prefix("env=")) {
            if let Some((k, v)) = parse_env_set(spec) {
                flags.env_sets.push((k, v));
            }
        }
        // Unknown flags ([T=...], [H=...], [DPI], etc.) are silently ignored.
    }
    flags
}

fn parse_redirect_code(code: &str) -> u16 {
    match code.to_ascii_lowercase().as_str() {
        "" | "temp" | "302" | "found" => 302,
        "permanent" | "301" => 301,
        "seeother" | "303" => 303,
        other => other.parse().unwrap_or(302),
    }
}

/// Parse one `E=var:val` set. The value may be quoted (already de-quoted by the
/// tokenizer) and may itself contain colons; only the first colon splits. A
/// colonless `E=var` sets `var` to the EMPTY string (present) — Apache semantics:
/// `[E=VAR]` marks VAR set, and the `env=` Header guard is presence-based
/// (`env_guard_passes`), so the empty value still fires it. Dropping the colonless
/// form (the old `split_once(':')?`) silently defeated guards like the live
/// `[E=cache-bypass-misc]` no-store rule. (Apache's `[E=!VAR]` unset form is not
/// modeled — httpjet's env is set-only.)
fn parse_env_set(spec: &str) -> Option<(String, String)> {
    if spec.is_empty() {
        return None;
    }
    match spec.split_once(':') {
        Some((k, v)) => Some((k.to_string(), v.to_string())),
        None => Some((spec.to_string(), String::new())),
    }
}

/// Split a flag list on commas, but NOT inside `[...]` or quotes, so
/// `E=Cache-Control:no-cache,E=no-cache:1` and `E="cache-vary:admin"` parse
/// correctly.
fn split_flag_list(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                // keep the quote out of the token; tokenize_args already removed
                // outer quotes for whole-args but flag values were not split yet.
            }
            ',' if !in_quotes => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}
