//! The `.htaccess` parser: [`Htaccess::parse`] plus access-directive
//! classification, section (`<Files*>`/`<Directory*>`/`<If>`) tracking, the
//! per-directive parsers, and the small line/tokenize helpers.

use fancy_regex::Regex;

use crate::error::RewriteError;
use crate::rules::{CacheKeyVar, RuleSet};

use super::cache::{cache_scope_path, parse_cache_key_modify};
use super::mod_access::parse_host_entries;
use super::*;

impl Htaccess {
    /// Parse a full `.htaccess` text into directives + an embedded [`RuleSet`].
    ///
    /// Lenient: unknown / unsupported directives are ignored, LSCache vendor
    /// directives are treated as no-ops (but `RewriteRule ... [E=...]` inside
    /// their blocks is still parsed into `rules`).
    pub fn parse(text: &str) -> Result<Htaccess, RewriteError> {
        let mut h = Htaccess::default();
        // Memo eligibility starts TRUE and is withdrawn by the first blocking directive.
        h.memo.eligible = true;
        // The rewrite engine wants the original rewrite directives — extract
        // them (across nested blocks) into one stream, then parse.
        let mut rewrite_stream = String::new();

        // Section parsing state: a stack of currently-open access sections.
        let mut section_stack: Vec<PendingSection> = Vec::new();
        // The legacy mod_access block of each scope (keyed by the innermost open
        // section's line, `None` = top level): its `Order`/`Allow`/`Deny` lines
        // accumulate into ONE `AccessRule` so they are judged together (#359).
        let mut legacy_slots: std::collections::HashMap<Option<usize>, usize> =
            std::collections::HashMap::new();

        for (lineno, raw) in logical_lines(text) {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Closing tags. Access rules are recorded eagerly when their
            // `Require`/`Allow`/`Deny` line is parsed (while the enclosing blocks
            // are still open), so closing a block only pops the stack.
            if line.starts_with("</") {
                let tag = closing_tag_name(line);
                if let Some(idx) = section_stack
                    .iter()
                    .rposition(|s| s.kind_name.eq_ignore_ascii_case(&tag))
                {
                    section_stack.remove(idx);
                }
                continue;
            }

            // Opening tags.
            if line.starts_with('<') {
                if let Some(pending) = PendingSection::open(line, lineno) {
                    section_stack.push(pending);
                }
                continue;
            }

            // Body lines. If we're inside an access section, capture its Require.
            let (directive, rest) = split_first(line);
            let dlow = directive.to_ascii_lowercase();

            // Rewrite directives always flow to the rewrite stream regardless of
            // the enclosing block (LiteSpeed honors RewriteRule inside IfModule).
            match dlow.as_str() {
                "rewriteengine" | "rewritebase" | "rewritecond" | "rewriterule" => {
                    rewrite_stream.push_str(line);
                    rewrite_stream.push('\n');
                    continue;
                }
                _ => {}
            }

            // Access directives. `Require` is recorded as an [`AccessRule`]
            // scoped by the conjunction of ALL currently-open blocks — including a
            // top-level rule (empty stack -> directory-wide, #4) and one nested
            // inside `<If>` whose enclosing <Files*>/<Directory*> would otherwise
            // lose it (#5). An unrecognized `Require` predicate (ip/host/valid-
            // user/user/group/...) is fail-closed to DENY unless it is explicitly
            // `(all) granted` (#2).
            if let Some(denied) = classify_access_directive(&dlow, rest) {
                record_access_rule(&mut h, &section_stack, denied);
                continue;
            }
            // Legacy mod_access: `Order`, `Allow from …`, `Deny from …` (every
            // operand form, not just `all`) accumulate into their scope's single
            // [`HostAccess`] block, evaluated per request against the client IP
            // and env (#359). Hostname operands cannot be evaluated here and are
            // recorded fail-closed.
            if matches!(dlow.as_str(), "order" | "allow" | "deny") {
                record_legacy_access(
                    &mut h,
                    &section_stack,
                    &mut legacy_slots,
                    &dlow,
                    rest,
                    lineno,
                );
                continue;
            }

            // The conjunction of ALL open-section scopes (outermost first), used
            // to scope Header/php_value ops to their enclosing
            // <Files*>/<DirectoryMatch>/<If>. Mirrors `record_access_rule`: an
            // <IfModule>/<Location*> block contributes no scope (`s.scope` None)
            // and is skipped, while a nested `<If ...><Files ...>` keeps BOTH so
            // the outer guard is honored rather than dropped.
            let cur_scopes: Vec<Scope> = section_stack
                .iter()
                .filter_map(|s| s.scope.clone())
                .collect();

            // Top-level (or in-block) directives we recognize.
            match dlow.as_str() {
                "header" => {
                    if let Some(mut op) = parse_header(rest) {
                        op.scopes = cur_scopes.clone();
                        h.headers.push(op);
                    }
                }
                "errordocument" => {
                    // `ErrorDocument code target`. The target may be a local
                    // path, an `http(s)://` URL, or a quoted inline message
                    // (which can contain spaces) — so split off the code and
                    // keep the remainder raw for classification.
                    let rest = rest.trim();
                    if let Some((code_str, target)) = rest.split_once(char::is_whitespace) {
                        if let Ok(code) = code_str.parse::<u16>() {
                            let raw = target.trim();
                            h.error_docs
                                .insert(code, crate::directives::ErrorDoc::classify(raw));
                        }
                    }
                }
                "setenvif" | "setenvifnocase" => {
                    if let Some(s) = parse_set_env_if(rest, dlow == "setenvifnocase", lineno) {
                        classify_set_env_if_for_memo(&mut h.memo, &s, lineno);
                        h.set_env_if.push(s);
                    }
                }
                // LSCache directives driving the origin page cache.
                "cachelookup" => {
                    // `CacheLookup [public|private] on|off` — the on/off token is
                    // last; scope is not distinguished for the lookup decision in
                    // Phase 1 (XenForo uses `CacheLookup public on`).
                    let on = rest
                        .split_whitespace()
                        .next_back()
                        .map(|t| t.eq_ignore_ascii_case("on"))
                        .unwrap_or(false);
                    h.cache_lookup = Some(on);
                }
                "cacheenable" => {
                    if let Some(p) = cache_scope_path(rest) {
                        h.cache_enable.push(p);
                    }
                }
                "cachedisable" => {
                    if let Some(p) = cache_scope_path(rest) {
                        h.cache_disable.push(p);
                    }
                }
                "cachekeymodify" => {
                    h.cache_key_modifiers.extend(parse_cache_key_modify(rest));
                }
                "directoryindex" => {
                    let toks = tokenize(rest);
                    if toks.iter().any(|t| t.eq_ignore_ascii_case("disabled")) {
                        h.directory_index.clear();
                    } else if !toks.is_empty() {
                        h.directory_index = toks;
                    }
                }
                // PHP ini overrides — passed to lsphp via the LSAPI special-env
                // section (NOT the regular CGI env, which the lsphp SAPI ignores).
                "php_value" | "php_admin_value" | "php_flag" | "php_admin_flag" => {
                    let kind = match dlow.as_str() {
                        "php_value" => PhpDirectiveKind::Value,
                        "php_admin_value" => PhpDirectiveKind::AdminValue,
                        "php_flag" => PhpDirectiveKind::Flag,
                        _ => PhpDirectiveKind::AdminFlag,
                    };
                    if let Some(mut pd) = parse_php_directive(rest, kind) {
                        pd.scopes = cur_scopes.clone();
                        h.php_directives.push(pd);
                    }
                }
                // `SetHandler application/x-httpd-php` forces PHP on every file in
                // scope regardless of extension; any other handler (`none`,
                // `default-handler`, …) records an explicit non-PHP reset.
                "sethandler" => {
                    let php = rest.trim().eq_ignore_ascii_case("application/x-httpd-php");
                    h.set_handlers.push(HandlerDirective {
                        php,
                        scopes: cur_scopes.clone(),
                    });
                }
                // `AddHandler/AddType application/x-httpd-php .html …` map extensions
                // to PHP for this directory subtree. Only the PHP handler/type is
                // recorded (a non-PHP `AddType text/html .shtml` is ignored).
                "addhandler" | "addtype" => {
                    let toks = tokenize(rest);
                    if toks
                        .first()
                        .is_some_and(|t| t.eq_ignore_ascii_case("application/x-httpd-php"))
                    {
                        let exts: Vec<String> = toks[1..]
                            .iter()
                            .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
                            .filter(|e| !e.is_empty())
                            .collect();
                        if !exts.is_empty() {
                            h.add_php_exts.push(AddPhpExt {
                                exts,
                                scopes: cur_scopes.clone(),
                            });
                        }
                    }
                }
                // Remaining vendor / no-op directives — recognized & dropped.
                "esi" | "h2earlyhints" | "fileetag" | "addoutputfilterbytype" | "allowoverride" => {
                }
                _ => {
                    // Unknown directive: ignore.
                }
            }
        }

        // Any sections left open at EOF (malformed) are simply dropped; their
        // access rules, if any, were already recorded when parsed.
        drop(section_stack);

        // Build the load-time scope indices once, now that `access_rules` and
        // `headers` are fully populated (so they share this Htaccess's Arc + mtime
        // TTL and can never be stale vs the rules they index).
        h.has_resp_op = !h.headers.is_empty();
        h.has_handler_override = !h.set_handlers.is_empty() || !h.add_php_exts.is_empty();
        h.access_index = build_access_index(&h.access_rules);
        h.header_index = build_header_index(&h.headers);

        h.rules = RuleSet::parse(&rewrite_stream)?;
        classify_rules_for_memo(&mut h.memo, &h.rules);
        Ok(h)
    }

    /// Does this `.htaccess` forbid serving the file at `path` (the basename and
    /// full request path are both checked against the access rules)?
    ///
    /// `request_path` is the full URI path; `basename` is the filename.
    /// Returns `true` if a `denied` rule matches and no later `granted` rule
    /// overrides it (rules are evaluated in source order; later wins, matching
    /// Apache's merge for same-scope `Require`). Backed by the same
    /// `access_rules` model as [`Htaccess::access_decision`], so it reflects
    /// directory-wide (#4), `<If>`-nested (#5), and fail-closed (#2) rules.
    pub fn is_forbidden(&self, request_path: &str, _basename: &str) -> bool {
        // `access_decision` derives the basename from `request_path` itself, so
        // the explicit `_basename` arg is retained only for the public signature.
        matches!(
            self.access_decision(request_path, "GET"),
            crate::directives::AccessDecision::Denied
        )
    }
}

// ===========================================================================
// Access directive classification + recording
// ===========================================================================

/// Classify an access directive line into a deny/grant decision, or `None` if
/// the directive is not an access directive.
///
/// Apache/LiteSpeed parity + fail-closed hardening:
/// * `Require all granted` / `Require granted` -> grant.
/// * `Require all denied`  / `Require denied`  -> deny.
/// * **Any other** `Require <predicate>` (`ip`, `host`, `valid-user`, `user`,
///   `group`, `env`, `expr`, `method`, ...) is an *authorization restriction*:
///   in Apache it RESTRICTS access, so modelling it as "no opinion" would leave
///   the resource fully open (the #2 bug). We cannot evaluate the predicate
///   here (no identity/IP context at parse time), so we fail **closed** -> deny.
/// * Legacy `Order`/`Allow from`/`Deny from` are NOT classified here — they
///   are accumulated per scope by [`record_legacy_access`]. `Satisfy` is not
///   modelled.
fn classify_access_directive(dlow: &str, rest: &str) -> Option<bool> {
    match dlow {
        "require" => {
            let r = rest.trim().to_ascii_lowercase();
            if r == "all granted" || r == "granted" {
                Some(false)
            } else {
                // `all denied`, `denied`, AND every authorization predicate
                // (ip/host/valid-user/user/group/...) -> deny (fail-closed).
                Some(true)
            }
        }
        _ => None,
    }
}

/// Fold one `Order` / `Allow from …` / `Deny from …` line into the
/// [`HostAccess`] block of the innermost open scope, creating that scope's rule
/// on first sight. The rule's scope matchers carry deny polarity (`denied:
/// true`) so an un-evaluable enclosing block fails closed, exactly like a
/// `Require` deny. An `Allow`/`Deny` line without the mandatory `from` keyword
/// is an Apache config error: a malformed `Deny` denies everything, a
/// malformed `Allow` grants nothing.
fn record_legacy_access(
    h: &mut Htaccess,
    stack: &[PendingSection],
    slots: &mut std::collections::HashMap<Option<usize>, usize>,
    dlow: &str,
    rest: &str,
    lineno: usize,
) {
    let key = stack.last().map(|s| s.lineno);
    let idx = match slots.get(&key) {
        Some(&i) => i,
        None => {
            let Some(matchers) = access_matchers(stack, true) else {
                return;
            };
            h.access_rules.push(AccessRule {
                matchers,
                denied: true,
                host_access: Some(HostAccess::default()),
            });
            let i = h.access_rules.len() - 1;
            slots.insert(key, i);
            i
        }
    };
    let ha = h.access_rules[idx]
        .host_access
        .as_mut()
        .expect("legacy slot always points at a host_access rule");
    match dlow {
        "order" => ha.order = AccessOrder::parse(rest),
        "allow" | "deny" => {
            let entries = match parse_host_entries(rest) {
                Some(e) => e,
                None if dlow == "deny" => vec![HostEntry::Unevaluable(rest.trim().to_string())],
                None => Vec::new(),
            };
            if entries.iter().any(|e| !matches!(e, HostEntry::All)) {
                h.memo.block(lineno, "access_ip_or_env");
            }
            for e in entries.iter().filter(|e| e.is_unevaluable()) {
                tracing::warn!(
                    line = lineno,
                    directive = dlow,
                    operand = ?e,
                    ".htaccess host/domain access operand is not evaluable (no reverse DNS); treated fail-closed"
                );
            }
            if dlow == "allow" {
                ha.allow.extend(entries);
            } else {
                ha.deny.extend(entries);
            }
        }
        _ => {}
    }
}

/// Record an [`AccessRule`] scoped by the conjunction of the currently-open
/// blocks. Files/FilesMatch contribute a basename matcher, Directory/
/// DirectoryMatch a path matcher, and `<If "%{REQUEST_URI} ...">` a URI
/// matcher; other blocks (IfModule, LocationMatch, ...) contribute nothing. An
/// empty matcher set is a directory-wide rule. For the common single-section
/// case the legacy flat `access` vec is also populated for back-compat.
fn record_access_rule(h: &mut Htaccess, stack: &[PendingSection], denied: bool) {
    if let Some(matchers) = access_matchers(stack, denied) {
        h.access_rules.push(AccessRule {
            matchers,
            denied,
            host_access: None,
        });
    }
}

/// The ANDed scope matchers of the currently-open blocks, or `None` when the
/// rule must be dropped (an uncompilable `<Files*>`/`<Directory*>`, or a grant
/// under an unverifiable `<If>`).
fn access_matchers(stack: &[PendingSection], denied: bool) -> Option<Vec<AccessMatcher>> {
    let mut matchers: Vec<AccessMatcher> = Vec::new();
    for sec in stack {
        match sec.kind {
            // A Files*/Directory* block whose pattern did not compile is unusable:
            // DON'T silently drop it and let the remaining matchers widen the rule's
            // scope (an empty-matcher rule would deny the WHOLE directory). Skip
            // recording entirely (`?`), matching the prior drop-on-uncompilable behavior.
            Some(SectionKind::Files) | Some(SectionKind::FilesMatch) => {
                matchers.push(AccessMatcher::Basename(sec.regex.clone()?));
            }
            Some(SectionKind::Directory) | Some(SectionKind::DirectoryMatch) => {
                matchers.push(AccessMatcher::Path(sec.regex.clone()?));
            }
            None => {
                // `<If>` contributes a URI condition; other None blocks (IfModule
                // etc.) carry an If-scope only when they are actually `<If>`.
                if let Some(scope) = &sec.scope {
                    if scope.kind == ScopeKind::If {
                        if let Some(uri_expr) = &scope.uri_expr {
                            matchers.push(AccessMatcher::IfUriExpr(uri_expr.clone()));
                        } else {
                            // A fully-unmodellable `<If>` (regex None, no `%{REQUEST_URI}`
                            // predicate) cannot be evaluated. A DENY still applies via the
                            // "always satisfied" matcher so a restriction is never silently
                            // lost; a GRANT must NOT widen access on an unverifiable
                            // condition, so drop the whole rule (fail-closed) — mirroring
                            // the uncompilable-Files/Directory drop above.
                            if scope.regex.is_none() && !denied {
                                return None;
                            }
                            matchers.push(AccessMatcher::IfUri {
                                regex: scope.regex.clone(),
                                negate: scope.negate,
                            });
                        }
                    }
                }
            }
        }
    }

    Some(matchers)
}

// ===========================================================================
// Section parsing
// ===========================================================================

struct PendingSection {
    kind: Option<SectionKind>,
    kind_name: String,
    regex: Option<Regex>,
    /// Source line of the opening tag — the identity of this scope for the
    /// per-scope legacy `Order`/`Allow`/`Deny` accumulation.
    lineno: usize,
    /// The scope a directive (e.g. `Header`) inside this block inherits. Set for
    /// `<Files*>`/`<Directory*>` and for the common `<If "%{REQUEST_URI} ...">`.
    scope: Option<Scope>,
}

impl PendingSection {
    fn open(line: &str, lineno: usize) -> Option<PendingSection> {
        // Strip leading '<' and trailing '>'.
        let inner = line.trim_start_matches('<').trim_end_matches('>');
        let (tag, args) = split_first(inner);
        let kind_name = tag.to_string();
        let tag_low = tag.to_ascii_lowercase();
        let kind = match tag_low.as_str() {
            "files" => Some(SectionKind::Files),
            "filesmatch" => Some(SectionKind::FilesMatch),
            "directorymatch" => Some(SectionKind::DirectoryMatch),
            "directory" => Some(SectionKind::Directory),
            // Blocks we descend into but don't treat as access scopes:
            // IfModule, LocationMatch, If, ... — we still need to balance their
            // close tags, so track them with kind=None.
            _ => None,
        };

        let (regex, _regex_src) = if kind.is_some() {
            // `<Files "name">`, `<Files ~ "regex">`, `<FilesMatch "regex">`.
            let mut a = args.trim();
            let mut is_regex_marker = false;
            if let Some(rest) = a.strip_prefix('~') {
                is_regex_marker = true;
                a = rest.trim();
            }
            let pat = unquote(a);
            let compiled = match kind {
                Some(SectionKind::Files) if !is_regex_marker => {
                    // `<Files "glob">` uses APACHE FNMATCH glob semantics, NOT
                    // regex: `*.log` must match `x.log` but not `xlog`. Translate
                    // the glob to an anchored regex so the uniform regex-matching
                    // path handles it. A metacharacter-free name reduces to an
                    // exact match.
                    Regex::new(&fnmatch_to_regex(&pat)).ok()
                }
                _ => Regex::new(&pat).ok(),
            };
            (compiled, pat)
        } else {
            (None, String::new())
        };

        // Compute the directive scope inherited by Header ops inside this block.
        let scope = match kind {
            Some(SectionKind::Files) => Some(Scope {
                kind: ScopeKind::Files,
                regex: regex.clone(),
                negate: false,
                uri_expr: None,
            }),
            Some(SectionKind::FilesMatch) => Some(Scope {
                kind: ScopeKind::FilesMatch,
                regex: regex.clone(),
                negate: false,
                uri_expr: None,
            }),
            Some(SectionKind::DirectoryMatch) => Some(Scope {
                kind: ScopeKind::DirectoryMatch,
                regex: regex.clone(),
                negate: false,
                uri_expr: None,
            }),
            Some(SectionKind::Directory) => Some(Scope {
                kind: ScopeKind::Directory,
                regex: regex.clone(),
                negate: false,
                uri_expr: None,
            }),
            None if tag_low == "if" => parse_if_scope(args),
            None => None,
        };

        Some(PendingSection {
            kind,
            kind_name,
            regex,
            lineno,
            scope,
        })
    }
}

fn closing_tag_name(line: &str) -> String {
    line.trim_start_matches("</")
        .trim_end_matches('>')
        .trim()
        .to_string()
}

/// Parse a `<If "...">` argument into a [`Scope`] when it tests
/// `%{REQUEST_URI}` against a regex (the only form the live configs use, e.g.
/// `<If "%{REQUEST_URI} =~ m#(^|/)\.#">` or `... !~ m#^/\.well-known/#`).
/// Returns `None` (no usable scope) for expressions we cannot model.
fn parse_if_scope(args: &str) -> Option<Scope> {
    let expr = unquote(args.trim());
    if let Some(uri_expr) = parse_if_uri_expr(&expr) {
        let first = uri_expr.first_cond();
        return Some(Scope {
            kind: ScopeKind::If,
            regex: first.regex.clone(),
            negate: first.negate,
            uri_expr: Some(uri_expr),
        });
    }
    // An `<If>` whose expression we cannot model (no `%{REQUEST_URI}` predicate, e.g.
    // `<If "%{HTTP_HOST} == ...">`) still yields an explicit If-scope rather than
    // `None`. Returning `None` made it indistinguishable from a scope-less `<IfModule>`,
    // which silently dropped the guard: an enclosed access GRANT then widened to the
    // whole directory (fail-OPEN). With `regex: None` + no URI expression the scope is
    // "always satisfied" for headers (lenient superset, unchanged), while
    // `record_access_rule` can recognize the absent URI expression and fail-close a grant.
    Some(Scope {
        kind: ScopeKind::If,
        regex: None,
        negate: false,
        uri_expr: None,
    })
}

fn parse_if_uri_expr(expr: &str) -> Option<UriExpr> {
    let expr = strip_if_outer_parens(expr.trim())?;
    let or_parts = split_if_top_level(expr, b"||")?;
    if or_parts.len() > 1 {
        return or_parts
            .into_iter()
            .map(parse_if_uri_expr)
            .collect::<Option<Vec<_>>>()
            .map(UriExpr::Or);
    }
    let and_parts = split_if_top_level(expr, b"&&")?;
    if and_parts.len() > 1 {
        return and_parts
            .into_iter()
            .map(parse_if_uri_expr)
            .collect::<Option<Vec<_>>>()
            .map(UriExpr::And);
    }
    parse_if_uri_cond(expr).map(UriExpr::Cond)
}

fn split_if_top_level<'a>(expr: &'a str, operator: &[u8; 2]) -> Option<Vec<&'a str>> {
    let bytes = expr.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut i = 0;
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut regex_delim: Option<u8> = None;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];
        if let Some(delim) = regex_delim {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == delim {
                regex_delim = None;
            }
            i += 1;
            continue;
        }
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'\'' || b == b'"' {
            quote = Some(b);
            i += 1;
            continue;
        }
        if b == b'm' && i + 1 < bytes.len() {
            let delim = bytes[i + 1];
            if !delim.is_ascii_alphanumeric() && !delim.is_ascii_whitespace() {
                regex_delim = Some(delim);
                i += 2;
                continue;
            }
        }
        if b == b'(' {
            depth += 1;
            i += 1;
            continue;
        }
        if b == b')' {
            depth = depth.checked_sub(1)?;
            i += 1;
            continue;
        }
        if depth == 0 && bytes.get(i..i + 2) == Some(operator.as_slice()) {
            let part = expr[start..i].trim();
            if part.is_empty() {
                return None;
            }
            parts.push(part);
            start = i + 2;
            i += 2;
            continue;
        }
        i += 1;
    }
    if depth != 0 || quote.is_some() || regex_delim.is_some() {
        return None;
    }
    let tail = expr[start..].trim();
    if tail.is_empty() {
        return None;
    }
    parts.push(tail);
    Some(parts)
}

fn strip_if_outer_parens(mut expr: &str) -> Option<&str> {
    loop {
        expr = expr.trim();
        if !expr.starts_with('(') {
            return Some(expr);
        }

        let bytes = expr.as_bytes();
        let mut i = 0;
        let mut depth = 0usize;
        let mut quote: Option<u8> = None;
        let mut regex_delim: Option<u8> = None;
        let mut escaped = false;
        let mut stripped = false;

        while i < bytes.len() {
            let b = bytes[i];
            if let Some(delim) = regex_delim {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == delim {
                    regex_delim = None;
                }
                i += 1;
                continue;
            }
            if let Some(q) = quote {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == q {
                    quote = None;
                }
                i += 1;
                continue;
            }
            if b == b'\'' || b == b'"' {
                quote = Some(b);
                i += 1;
                continue;
            }
            if b == b'm' && i + 1 < bytes.len() {
                let delim = bytes[i + 1];
                if !delim.is_ascii_alphanumeric() && !delim.is_ascii_whitespace() {
                    regex_delim = Some(delim);
                    i += 2;
                    continue;
                }
            }
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    if expr[i + 1..].trim().is_empty() {
                        expr = &expr[1..i];
                        stripped = true;
                    }
                    break;
                }
            }
            i += 1;
        }

        if quote.is_some() || regex_delim.is_some() || depth != 0 {
            return None;
        }
        if !stripped {
            return Some(expr);
        }
    }
}

fn parse_if_uri_cond(expr: &str) -> Option<UriCond> {
    let low = expr.to_ascii_lowercase();
    let pos = low.find("%{request_uri}")?;
    if !expr[..pos].trim().is_empty() {
        return None;
    }
    let after = expr[pos + "%{request_uri}".len()..].trim_start();
    let (negate, rest) = if let Some(r) = after.strip_prefix("!~") {
        (true, r)
    } else if let Some(r) = after.strip_prefix("=~") {
        (false, r)
    } else {
        return None;
    };
    let rest = rest.trim_start();
    // Apache `m#...#` (or `m/.../`, or a bare `re`) delimiter form.
    let pattern = if let Some(body) = rest.strip_prefix('m') {
        let body = body.trim_start();
        let delim = body.chars().next()?;
        let body = &body[delim.len_utf8()..];
        let mut escaped = false;
        let mut end = None;
        for (i, ch) in body.char_indices() {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == delim {
                end = Some(i);
                break;
            }
        }
        let end = end?;
        if !body[end + delim.len_utf8()..].trim().is_empty() {
            return None;
        }
        &body[..end]
    } else {
        let mut tokens = rest.split_whitespace();
        let pattern = tokens.next().unwrap_or(rest);
        if tokens.next().is_some() {
            return None;
        }
        pattern
    };
    let regex = Regex::new(pattern).ok()?;
    Some(UriCond {
        regex: Some(regex),
        negate,
    })
}

/// Translate an Apache `fnmatch` glob to an anchored regex. `*` -> `.*`, `?` ->
/// `.`, `[...]` classes are passed through (Apache and regex share the syntax),
/// and every other metacharacter is escaped so it is matched literally — this
/// is exactly what makes `*.log` match `x.log` but not `xlog`.
fn fnmatch_to_regex(glob: &str) -> String {
    let mut re = String::with_capacity(glob.len() + 4);
    re.push('^');
    let mut chars = glob.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '[' => {
                // Copy a character class verbatim (translate a leading `!` to
                // regex `^` negation). Find the closing ']'.
                re.push('[');
                if matches!(chars.peek(), Some('!')) {
                    chars.next();
                    re.push('^');
                }
                for cc in chars.by_ref() {
                    re.push(cc);
                    if cc == ']' {
                        break;
                    }
                }
            }
            // Regex metacharacters that must be escaped to stay literal.
            '.' | '+' | '(' | ')' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                re.push('\\');
                re.push(c);
            }
            other => re.push(other),
        }
    }
    re.push('$');
    re
}

// ===========================================================================
// Directive parsers
// ===========================================================================

fn parse_header(rest: &str) -> Option<HeaderDirective> {
    // [always|onsuccess] action name [value] [env=...]
    let mut toks = tokenize(rest);
    if toks.is_empty() {
        return None;
    }
    let mut always = false;
    if toks[0].eq_ignore_ascii_case("always") {
        always = true;
        toks.remove(0);
    } else if toks[0].eq_ignore_ascii_case("onsuccess") {
        toks.remove(0);
    }
    if toks.is_empty() {
        return None;
    }
    let action = match toks.remove(0).to_ascii_lowercase().as_str() {
        "set" => HeaderAction::Set,
        "add" => HeaderAction::Add,
        "append" => HeaderAction::Append,
        "merge" => HeaderAction::Merge,
        "unset" => HeaderAction::Unset,
        "echo" => HeaderAction::Echo,
        _ => return None,
    };
    if toks.is_empty() {
        return None;
    }
    let name = toks.remove(0);

    // The remaining tokens: an optional value, then an optional env=/expr= guard.
    let mut value = String::new();
    let mut env = None;
    let mut expr = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let tok = &toks[i];
        if let Some(g) = tok.strip_prefix("env=") {
            let (negate, var) = match g.strip_prefix('!') {
                Some(v) => (true, v.to_string()),
                None => (false, g.to_string()),
            };
            env = Some(EnvGuard { var, negate });
            i += 1;
        } else if tok.starts_with("expr=") {
            let mut raw = tok.trim_start_matches("expr=").to_string();
            i += 1;
            while i < toks.len() && !toks[i].starts_with("env=") {
                if !raw.is_empty() {
                    raw.push(' ');
                }
                raw.push_str(&toks[i]);
                i += 1;
            }
            expr = raw
                .split("&&")
                .filter_map(|part| parse_if_uri_cond(part.trim()))
                .collect();
        } else if value.is_empty() {
            value = tok.clone();
            i += 1;
        } else {
            i += 1;
        }
    }
    Some(HeaderDirective {
        action,
        name,
        value,
        env,
        expr,
        always,
        scopes: vec![],
    })
}

/// Memo classification of one `SetEnvIf`: the attribute must be a key-covered
/// special (path / query / GET-only method / Host) or a request header — which
/// then becomes a per-entry vary dimension. Client/server address and protocol
/// are neither, and a directive that seeds an `%{ENV:}` name the rewrite
/// classifier assumes constant-empty (`REDIRECT_STATUS`) would invalidate that
/// assumption for every later reader. Mirrors the attribute set of
/// `ReqAttrs::resolve`.
fn classify_set_env_if_for_memo(memo: &mut MemoClass, s: &SetEnvIf, lineno: usize) {
    if s.var.eq_ignore_ascii_case("REDIRECT_STATUS") {
        memo.block(lineno, "set_env_if_seeds_redirect_status");
        return;
    }
    let attr = s.attribute.as_str();
    let eq = |n: &str| attr.eq_ignore_ascii_case(n);
    if eq("request_uri")
        || eq("request_method")
        || eq("query_string")
        || eq("host")
        || eq("server_name")
    {
        return;
    }
    if eq("request_protocol") || eq("remote_addr") || eq("server_addr") {
        memo.block(lineno, "set_env_if_remote");
        return;
    }
    match fold_header_name(attr) {
        Some(name) => memo.vary(name),
        None => memo.block(lineno, "set_env_if_bad_attribute"),
    }
}

/// Memo classification of the rewrite ruleset: it must be outcome-cacheable on
/// the base key plus keyable vars; `Origin`/`Accept` reads become vary
/// dimensions, `User-Agent` reads are left to the pipeline (bitmap-keyed when
/// classify-eligible, raw otherwise).
fn classify_rules_for_memo(memo: &mut MemoClass, rules: &RuleSet) {
    if !rules.path_cacheable {
        memo.block(0, "rewrite_uncacheable");
        return;
    }
    for v in &rules.cache_key_vars {
        match v {
            CacheKeyVar::Origin => memo.vary("origin".to_string()),
            CacheKeyVar::Accept => memo.vary("accept".to_string()),
            CacheKeyVar::UserAgent => {}
        }
    }
}

fn parse_set_env_if(rest: &str, nocase: bool, line: usize) -> Option<SetEnvIf> {
    let toks = tokenize(rest);
    if toks.len() < 3 {
        return None;
    }
    let attribute = toks[0].clone();
    let regex_src = toks[1].clone();
    let assign = toks[2].clone();
    let (var, value) = match assign.split_once('=') {
        Some((k, v)) => (k.to_string(), v.to_string()),
        None => (assign, "1".to_string()),
    };
    let prepared = if nocase {
        format!("(?i){regex_src}")
    } else {
        regex_src.clone()
    };
    let regex = Regex::new(&prepared)
        .map_err(|e| {
            tracing::debug!(line, error = %e, "invalid SetEnvIf regex; skipping");
        })
        .ok()?;
    // (#312) Same literal-prefix extraction the RewriteRule prefilter uses; for
    // SetEnvIfNoCase the (?i) wrapper makes any prefix case-sensitive-invalid,
    // so pass nocase through (extractor returns empty for it).
    let literal_prefix = crate::rules::extract_literal_prefix(&regex_src, false, nocase);
    Some(SetEnvIf {
        attribute,
        regex,
        literal_prefix,
        var,
        value,
    })
}

// ===========================================================================
// Small text helpers
// ===========================================================================

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

fn split_first(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    match s.find(char::is_whitespace) {
        Some(idx) => (&s[..idx], s[idx..].trim_start()),
        None => (s, ""),
    }
}

/// Parse `php_value KEY VALUE` (and the admin/flag variants). The VALUE may be
/// quoted with embedded spaces (e.g. `auto_prepend_file "/web/p p.php"`), so use
/// the quote-aware [`tokenize`] and rejoin the tail. For the flag forms,
/// normalize `on`/`true`/`1` → `1` and `off`/`false`/`0` → `0` (Apache/LSWS).
fn parse_php_directive(rest: &str, kind: PhpDirectiveKind) -> Option<PhpDirective> {
    let toks = tokenize(rest);
    if toks.len() < 2 {
        return None;
    }
    let name = toks[0].clone();
    if name.is_empty() {
        return None;
    }
    let raw = toks[1..].join(" ");
    let value = match kind {
        PhpDirectiveKind::Flag | PhpDirectiveKind::AdminFlag => {
            match raw.trim().to_ascii_lowercase().as_str() {
                "on" | "true" | "yes" | "1" => "1".to_string(),
                "off" | "false" | "no" | "0" => "0".to_string(),
                other => other.to_string(),
            }
        }
        _ => raw,
    };
    Some(PhpDirective {
        kind,
        name,
        value,
        scopes: vec![],
    })
}

/// Tokenize honoring double quotes, stripping the outer quotes from each token.
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut have = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                have = true;
            }
            '\\' if in_quotes => {
                // Preserve backslashes (regex escapes); only `\"` is a literal
                // quote.
                if let Some(&n) = chars.peek() {
                    if n == '"' {
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
                if have {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            c => {
                cur.push(c);
                have = true;
            }
        }
    }
    if have {
        out.push(cur);
    }
    out
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_php_directives_with_quotes_and_flag_normalization() {
        let text = "\
php_value auto_prepend_file \"/web/public_html/pagecache.php\"
php_flag display_errors off
php_admin_value open_basedir /safe
php_admin_flag allow_url_fopen On
";
        let h = Htaccess::parse(text).unwrap();
        let d = &h.php_directives;
        assert_eq!(d.len(), 4);
        assert_eq!(
            d[0],
            PhpDirective {
                kind: PhpDirectiveKind::Value,
                name: "auto_prepend_file".into(),
                value: "/web/public_html/pagecache.php".into(),
                scopes: vec![],
            }
        );
        // php_flag off -> "0"
        assert_eq!(
            d[1],
            PhpDirective {
                kind: PhpDirectiveKind::Flag,
                name: "display_errors".into(),
                value: "0".into(),
                scopes: vec![],
            }
        );
        assert_eq!(d[2].kind, PhpDirectiveKind::AdminValue);
        assert_eq!(d[2].name, "open_basedir");
        // php_admin_flag On -> "1"
        assert_eq!(
            d[3],
            PhpDirective {
                kind: PhpDirectiveKind::AdminFlag,
                name: "allow_url_fopen".into(),
                value: "1".into(),
                scopes: vec![],
            }
        );
    }

    #[test]
    fn php_value_without_value_is_ignored() {
        let h = Htaccess::parse("php_value auto_prepend_file\n").unwrap();
        assert!(h.php_directives.is_empty());
    }

    #[test]
    fn set_handler_in_files_block_is_recorded_with_scope() {
        let h = Htaccess::parse(
            "<Files \"crontab.html\">\n  SetHandler application/x-httpd-php\n</Files>",
        )
        .unwrap();
        assert_eq!(h.set_handlers.len(), 1);
        assert!(h.set_handlers[0].php);
        assert_eq!(h.set_handlers[0].scopes.len(), 1);
        assert!(h.has_handler_override);
    }

    #[test]
    fn set_handler_none_is_a_non_php_reset() {
        let h = Htaccess::parse("SetHandler none\n").unwrap();
        assert_eq!(h.set_handlers.len(), 1);
        assert!(!h.set_handlers[0].php);
        assert!(h.set_handlers[0].scopes.is_empty()); // directory-wide
        assert!(h.has_handler_override);
    }

    #[test]
    fn add_handler_and_add_type_record_php_extensions() {
        for directive in [
            "AddHandler application/x-httpd-php .html .htm",
            "AddType application/x-httpd-php .html .htm",
        ] {
            let h = Htaccess::parse(directive).unwrap();
            assert_eq!(h.add_php_exts.len(), 1, "{directive}");
            assert_eq!(h.add_php_exts[0].exts, vec!["html", "htm"], "{directive}");
            assert!(h.has_handler_override, "{directive}");
        }
    }

    #[test]
    fn non_php_add_type_is_not_recorded() {
        let h = Htaccess::parse("AddType text/html .shtml\n").unwrap();
        assert!(h.add_php_exts.is_empty());
        assert!(!h.has_handler_override);
    }

    #[test]
    fn no_handler_directive_leaves_override_flag_false() {
        let h = Htaccess::parse("php_value auto_prepend_file \"/x.php\"\n").unwrap();
        assert!(!h.has_handler_override);
    }
}
