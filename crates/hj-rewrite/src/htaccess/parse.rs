//! The `.htaccess` parser: [`Htaccess::parse`] plus access-directive
//! classification, section (`<Files*>`/`<Directory*>`/`<If>`) tracking, the
//! per-directive parsers, and the small line/tokenize helpers.

use fancy_regex::Regex;
use std::path::PathBuf;

use crate::error::RewriteError;
use crate::rules::{CacheKeyVar, RuleSet};

use super::auth_scope::{AuthGroup, AuthRequirement};
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
        // Apache skips a leading UTF-8 BOM; kept, it would hide the first directive.
        let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
        let mut h = Htaccess::default();
        // Memo eligibility starts TRUE and is withdrawn by the first blocking directive.
        h.memo.eligible = true;
        // The rewrite engine wants the original rewrite directives — extract
        // them (across nested blocks) into one stream, then parse.
        let mut rewrite_stream = String::new();

        // Section parsing state: a stack of currently-open access sections.
        let mut section_stack: Vec<PendingSection> = Vec::new();
        let mut malformed_sections = false;
        // The legacy mod_access block of each scope (keyed by the innermost open
        // scoping section's line, `None` = top level): its `Order`/`Allow`/`Deny`
        // lines accumulate into ONE `AccessRule` so they are judged together (#359).
        let mut legacy_slots = LegacySlots::default();
        // Per nesting depth: the conditions of the `<If>`/`<ElseIf>` chain that a
        // following `<Else>`/`<ElseIf>` at that depth continues.
        let mut if_chains: std::collections::HashMap<usize, Vec<Option<UriExpr>>> =
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
                    malformed_sections |= idx + 1 != section_stack.len();
                    let closed = section_stack.remove(idx);
                    let depth = section_stack.len();
                    if_chains.retain(|d, _| *d <= depth);
                    match closed.branch {
                        Some(IfBranch::If(cond)) => {
                            if_chains.insert(depth, vec![cond]);
                        }
                        Some(IfBranch::ElseIf(cond)) => {
                            if let Some(chain) = if_chains.get_mut(&depth) {
                                chain.push(cond);
                            }
                        }
                        Some(IfBranch::Else) | None => {}
                    }
                    if let Some(kind) = closed.require_kind {
                        let denied = kind.fold(&closed.require_children).ok_or_else(|| {
                            RewriteError::Malformed {
                                line: closed.lineno,
                                msg: "authorization container without Require".into(),
                            }
                        })?;
                        match section_stack
                            .iter_mut()
                            .rev()
                            .find(|s| s.require_kind.is_some())
                        {
                            Some(parent) => parent.require_children.push(denied),
                            None => record_access_rule(&mut h, &section_stack, denied),
                        }
                    }
                } else {
                    malformed_sections = true;
                }
                continue;
            }

            // Opening tags.
            if line.starts_with('<') {
                malformed_sections |= !line.ends_with('>');
                malformed_sections |= auth_tokens(line).is_none();
                let depth = section_stack.len();
                let prior = if_chains.remove(&depth);
                let pending = PendingSection::open(line, lineno, prior.as_deref())?;
                // Apache: "<Files> cannot occur within <Limit> section" (likewise
                // Directory*/If*). Scoping inside a method block also has no
                // per-scope legacy slot to land in (#791).
                if pending.is_scoping() && section_stack.iter().any(|s| s.method.is_some()) {
                    return Err(RewriteError::Malformed {
                        line: lineno,
                        msg: format!(
                            "<{}> cannot occur within <Limit> section",
                            pending.kind_name
                        ),
                    });
                }
                // A Require container folds its children into one verdict recorded
                // under the container's own scope, so a <Limit>/<Files*>/<If> inside
                // it would widen its grant to every method and path (#800).
                if (pending.is_scoping() || pending.method.is_some())
                    && section_stack.iter().any(|s| s.require_kind.is_some())
                {
                    return Err(RewriteError::Malformed {
                        line: lineno,
                        msg: format!(
                            "<{}> inside a <Require*> container is not supported",
                            pending.kind_name
                        ),
                    });
                }
                if pending.method.is_some() {
                    // The memo keys GET only; a method filter could tell HEAD apart.
                    h.memo.block(lineno, "access_method_limit");
                }
                if matches!(pending.branch, Some(IfBranch::ElseIf(_))) {
                    if let Some(prior) = prior {
                        if_chains.insert(depth, prior);
                    }
                }
                section_stack.push(pending);
                continue;
            }
            if_chains.remove(&section_stack.len());

            // Body lines. If we're inside an access section, capture its Require.
            let (directive, rest) = split_first(line);
            let dlow = directive.to_ascii_lowercase();

            // Rewrite directives always flow to the rewrite stream regardless of
            // the enclosing block (LiteSpeed honors RewriteRule inside IfModule).
            // `RewriteMap` rides along so the rule parser fails the file closed
            // (Apache answers 500 for it in a per-directory file).
            match dlow.as_str() {
                "rewriteengine" | "rewritebase" | "rewritecond" | "rewriterule" | "rewritemap" => {
                    rewrite_stream.push_str(line);
                    rewrite_stream.push('\n');
                    continue;
                }
                _ => {}
            }

            // Auth directives are parsed as real directives, never discovered by
            // substrings in comments. Metadata and Require retain lexical scope.
            if record_auth(&mut h, &section_stack, &dlow, rest) {
                // A user predicate is a member the container cannot evaluate (deny).
                if let Some(container) = section_stack
                    .iter_mut()
                    .rev()
                    .find(|s| s.require_kind.is_some())
                    .filter(|_| dlow == "require")
                {
                    container.require_children.push(true);
                }
                continue;
            }

            // Access directives. `Require` is recorded as an [`AccessRule`]
            // scoped by the conjunction of ALL currently-open blocks — including a
            // top-level rule (empty stack -> directory-wide, #4) and one nested
            // inside `<If>` whose enclosing <Files*>/<Directory*> would otherwise
            // lose it (#5). An unrecognized `Require` predicate (ip/host/valid-
            // user/user/group/...) is fail-closed to DENY unless it is explicitly
            // `(all) granted` (#2).
            if let Some(denied) = classify_access_directive(&dlow, rest) {
                match section_stack
                    .iter_mut()
                    .rev()
                    .find(|s| s.require_kind.is_some())
                {
                    Some(container) => container.require_children.push(denied),
                    None => record_access_rule(&mut h, &section_stack, denied),
                }
                continue;
            }
            // Legacy mod_access: `Order`, `Allow from …`, `Deny from …` (every
            // operand form, not just `all`) accumulate into their scope's single
            // [`HostAccess`] block, evaluated per request against the client IP
            // and env (#359). Hostname operands cannot be evaluated here and are
            // recorded fail-closed.
            if matches!(dlow.as_str(), "order" | "allow" | "deny") {
                if section_stack.iter().any(|s| s.require_kind.is_some()) {
                    return Err(RewriteError::Malformed {
                        line: lineno,
                        msg: "legacy access directive inside an authorization container".into(),
                    });
                }
                if section_stack.iter().any(PendingSection::is_unmodelled) {
                    // Its Allow could only widen to the whole directory.
                    return Err(RewriteError::Malformed {
                        line: lineno,
                        msg: "legacy access directive inside an unsupported container".into(),
                    });
                }
                record_legacy_access(
                    &mut h,
                    &section_stack,
                    &mut legacy_slots,
                    &dlow,
                    rest,
                    lineno,
                )?;
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
                    if let Some(mut op) = parse_header(rest, lineno)? {
                        if cur_scopes
                            .iter()
                            .any(|scope| scope.kind == ScopeKind::If && scope.uri_expr.is_none())
                        {
                            return Err(RewriteError::Malformed {
                                line: lineno,
                                msg: "unsupported Header enclosing If expression".into(),
                            });
                        }
                        op.scopes = cur_scopes.clone();
                        h.headers.push(op);
                    }
                }
                "errordocument" => {
                    // `ErrorDocument code target`. The target may be a local
                    // path, an absolute URL, or a quoted inline message (which can
                    // contain spaces) — so split off the code and keep the
                    // remainder raw for classification.
                    let rest = rest.trim();
                    if let Some((code_str, target)) = rest.split_once(char::is_whitespace) {
                        if let Ok(code) = code_str.parse::<u16>() {
                            let doc = crate::directives::ErrorDoc::classify(target.trim());
                            // Apache ignores a URL for 401: the browser would never
                            // see the challenge.
                            if !(code == 401
                                && matches!(doc, crate::directives::ErrorDoc::External(_)))
                            {
                                h.error_docs.insert(code, doc);
                            }
                        }
                    }
                }
                "setenv" | "unsetenv" => {
                    let toks = tokenize(rest);
                    if !toks.is_empty() {
                        reject_unscopable(&section_stack, &cur_scopes, lineno, directive)?;
                        if dlow == "setenv" {
                            h.set_env.push(EnvDirective {
                                name: toks[0].clone(),
                                value: Some(toks[1..].join(" ")),
                                scopes: cur_scopes.clone(),
                            });
                        } else {
                            h.set_env.extend(toks.into_iter().map(|name| EnvDirective {
                                name,
                                value: None,
                                scopes: cur_scopes.clone(),
                            }));
                        }
                        h.has_scoped_set_env |= !cur_scopes.is_empty();
                    }
                }
                "adddefaultcharset" => {
                    if let Some(arg) = tokenize(rest).into_iter().next() {
                        reject_unscopable(&section_stack, &cur_scopes, lineno, directive)?;
                        let charset = if arg.eq_ignore_ascii_case("off") {
                            None
                        } else if arg.eq_ignore_ascii_case("on") {
                            Some("ISO-8859-1".to_string())
                        } else {
                            Some(arg)
                        };
                        h.default_charset.push(CharsetDirective {
                            charset,
                            scopes: cur_scopes.clone(),
                        });
                    }
                }
                "setenvif" | "setenvifnocase" | "browsermatch" | "browsermatchnocase" => {
                    // `BrowserMatch[NoCase] re VAR…` is mod_setenvif's alias for
                    // `SetEnvIf[NoCase] User-Agent re VAR…` (#779).
                    let browser;
                    let args = if dlow.starts_with("browsermatch") {
                        browser = format!("User-Agent {rest}");
                        browser.as_str()
                    } else {
                        rest
                    };
                    let nocase = dlow.ends_with("nocase");
                    {
                        let mut s = parse_set_env_if(args, nocase, lineno)?;
                        // A guard this parser cannot evaluate would either widen
                        // the assignment to the whole directory or drop it; both
                        // can open an `Allow/Deny from env=` (#781).
                        if section_stack.iter().any(PendingSection::is_unmodelled)
                            || cur_scopes
                                .iter()
                                .any(|sc| sc.kind == ScopeKind::If && sc.uri_expr.is_none())
                        {
                            return Err(RewriteError::Malformed {
                                line: lineno,
                                msg: "SetEnvIf inside an unsupported container".into(),
                            });
                        }
                        s.scopes = cur_scopes.clone();
                        h.has_scoped_set_env |= !s.scopes.is_empty();
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
                    // Apache mod_dir: a single `disabled` argument turns the index
                    // search off; next to other names it is a literal file name.
                    let toks = tokenize(rest);
                    if toks.len() == 1 && toks[0].eq_ignore_ascii_case("disabled") {
                        h.directory_index.clear();
                        h.directory_index_disabled = true;
                    } else if !toks.is_empty() {
                        h.directory_index = toks;
                        h.directory_index_disabled = false;
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
                        reject_unscopable(&section_stack, &cur_scopes, lineno, directive)?;
                        pd.scopes = cur_scopes.clone();
                        h.php_directives.push(pd);
                    }
                }
                "sethandler" | "forcetype" | "addhandler" | "addtype" | "removehandler"
                | "removetype" => {
                    if let Some(kind) = parse_handler_op(&dlow, rest) {
                        // Applied unconditionally, a guard we cannot evaluate would
                        // turn PHP routing on or off for the whole directory.
                        reject_unscopable(&section_stack, &cur_scopes, lineno, directive)?;
                        h.handler_ops.push(HandlerOp {
                            kind,
                            scopes: cur_scopes.clone(),
                        });
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

        // Unbalanced sections re-scope the rules after them (Apache answers 500),
        // so the cache's deny-all sentinel stands in for the whole file.
        if malformed_sections || !section_stack.is_empty() {
            return Err(RewriteError::Malformed {
                line: 1,
                msg: "unbalanced or malformed section".into(),
            });
        }
        drop(section_stack);

        // Build the load-time scope indices once, now that `access_rules` and
        // `headers` are fully populated (so they share this Htaccess's Arc + mtime
        // TTL and can never be stale vs the rules they index).
        h.has_resp_op = !h.headers.is_empty();
        h.has_handler_override = h.handler_ops.iter().any(HandlerOp::can_force_php);
        h.has_type_override = h.handler_ops.iter().any(HandlerOp::can_set_mime);
        if let Some(policy) = &mut h.auth {
            // Root metadata applies regardless of its line position. Enclosing
            // sections precede their descendants; sibling order remains intact.
            policy.groups.sort_by_key(|g| g.scope_id);
        }
        h.access_index = build_access_index(&h.access_rules);
        h.access_memo_useful = h.access_rules.iter().any(AccessRule::has_path_matcher);
        h.header_index = build_header_index(&h.headers);
        finish_set_env_if(&mut h);

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

/// Returns true when this directive belongs solely to auth (so it must not
/// also become a blanket access deny). Other Require predicates keep their
/// existing host-access semantics as well as replacing inherited auth groups.
fn record_auth(h: &mut Htaccess, stack: &[PendingSection], directive: &str, rest: &str) -> bool {
    let is_metadata = directive.starts_with("auth");
    if !is_metadata && directive != "require" {
        return false;
    }
    let parsed_tokens = auth_tokens(rest);
    let tokens = parsed_tokens.clone().unwrap_or_default();
    let provider = tokens
        .first()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let is_users = directive == "require" && matches!(provider.as_str(), "valid-user" | "user");
    let policy = h.auth.get_or_insert_with(AuthPolicy::default);
    policy.sensitive |= is_metadata || is_users || provider == "group" || parsed_tokens.is_none();
    // IfModule is transparent, like the existing parser; all other unknown
    // containers (RequireAny/All/None, Limit, Location, ...) are unsupported.
    let sections: Vec<_> = stack
        .iter()
        .filter(|s| !s.kind_name.eq_ignore_ascii_case("ifmodule"))
        .collect();
    let scope_id = sections.last().map_or(0, |s| s.lineno);
    let slot = if let Some(i) = policy.groups.iter().position(|g| g.scope_id == scope_id) {
        i
    } else {
        let mut matchers = Vec::new();
        let mut invalid_scope = false;
        for s in &sections {
            match &s.auth_matcher {
                Some(matcher) => matchers.push(matcher.clone()),
                None => invalid_scope = true,
            }
        }
        policy.groups.push(AuthGroup {
            scope_id,
            matchers,
            invalid_scope,
            ..Default::default()
        });
        policy.groups.len() - 1
    };
    let group = &mut policy.groups[slot];
    group.invalid_scope |= parsed_tokens.is_none();
    if is_metadata {
        let value = if tokens.len() == 1 {
            tokens[0].clone()
        } else {
            String::new()
        };
        match directive {
            "authtype" => group.auth_type = Some(value),
            "authname" => group.realm = Some(value),
            "authuserfile" => group.user_file = Some(PathBuf::from(value)),
            _ => group.invalid_scope = true, // unimplemented auth provider/merge controls
        }
        // Malformed metadata must not be repaired by an unrelated directive.
        group.invalid_scope |= tokens.len() != 1 || tokens[0].is_empty();
        return true;
    }
    let requirement = match provider.as_str() {
        "valid-user" if tokens.len() == 1 => AuthRequirement::Users {
            valid_user: true,
            users: Vec::new(),
        },
        "user" if tokens.len() > 1 => AuthRequirement::Users {
            valid_user: false,
            users: tokens[1..].to_vec(),
        },
        "granted" if tokens.len() == 1 => AuthRequirement::Granted,
        "all" if tokens.len() == 2 && tokens[1].eq_ignore_ascii_case("granted") => {
            AuthRequirement::Granted
        }
        _ => AuthRequirement::Denied,
    };
    // Only user predicates in the SAME lexical section form an implicit OR.
    // Mixed/unsupported boolean requirements cannot be safely modeled.
    group.require = Some(match (group.require.take(), requirement) {
        (None, next) => next,
        (
            Some(AuthRequirement::Users {
                valid_user: a,
                mut users,
            }),
            AuthRequirement::Users {
                valid_user: b,
                users: more,
            },
        ) => {
            users.extend(more);
            AuthRequirement::Users {
                valid_user: a || b,
                users,
            }
        }
        (Some(AuthRequirement::Granted), AuthRequirement::Granted) => AuthRequirement::Granted,
        _ => AuthRequirement::Denied,
    });
    is_users
}

// Auth tokens must not silently accept an unterminated quoted value. Preserve
// case, spaces within quoted usernames/realms, and both Apache quote forms.
fn auth_tokens(text: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut have = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else if ch == '\\' && chars.peek().is_some_and(|c| *c == q || *c == '\\') {
                token.push(chars.next()?);
            } else {
                token.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
            have = true;
        } else if ch.is_whitespace() {
            if have {
                result.push(std::mem::take(&mut token));
                have = false;
            }
        } else {
            token.push(ch);
            have = true;
        }
    }
    if quote.is_some() {
        return None;
    }
    if have {
        result.push(token);
    }
    Some(result)
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
            let toks = auth_tokens(rest).unwrap_or_default();
            let granted = match toks.as_slice() {
                [g] => g.eq_ignore_ascii_case("granted"),
                [a, g] => a.eq_ignore_ascii_case("all") && g.eq_ignore_ascii_case("granted"),
                _ => false,
            };
            if granted {
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

/// Where each scope's legacy block lives: the [`AccessRule`] index per scope
/// key, and the [`LimitedAccess`] index per (scope key, `<Limit>` section line).
#[derive(Default)]
struct LegacySlots {
    blocks: std::collections::HashMap<Option<usize>, usize>,
    limits: std::collections::HashMap<(Option<usize>, usize), usize>,
}

/// Fold one `Order` / `Allow from …` / `Deny from …` line into the
/// [`HostAccess`] block of the innermost open scoping section, creating that
/// scope's rule on first sight. `<IfModule>` is transparent and `<Limit>` /
/// `<LimitExcept>` only method-tags the line within the SAME block, as Apache
/// keeps one `mod_access_compat` config per section (#778). The rule's scope
/// matchers carry deny polarity (`denied: true`) so an un-evaluable enclosing
/// block fails closed, exactly like a `Require` deny. An `Allow`/`Deny` line
/// without the mandatory `from` keyword is an Apache config error: a malformed
/// `Deny` denies everything, a malformed `Allow` grants nothing.
fn record_legacy_access(
    h: &mut Htaccess,
    stack: &[PendingSection],
    slots: &mut LegacySlots,
    dlow: &str,
    rest: &str,
    lineno: usize,
) -> Result<(), RewriteError> {
    let mut limits = stack.iter().filter_map(|s| match &s.method {
        Some(AccessMatcher::Method { methods, except }) => Some((s.lineno, methods, *except)),
        _ => None,
    });
    let limit = limits.next();
    if limits.next().is_some() {
        return Err(RewriteError::Malformed {
            line: lineno,
            msg: "legacy access directive inside nested <Limit> sections".into(),
        });
    }
    let scoping = || stack.iter().filter(|s| s.method.is_none());
    let key = scoping()
        .rfind(|s| !s.kind_name.eq_ignore_ascii_case("ifmodule"))
        .map(|s| s.lineno);
    let idx = match slots.blocks.get(&key) {
        Some(&i) => i,
        None => {
            let Some(matchers) = access_matchers(scoping(), true) else {
                return Ok(());
            };
            h.access_rules.push(AccessRule {
                matchers,
                denied: true,
                host_access: Some(HostAccess::default()),
            });
            let i = h.access_rules.len() - 1;
            slots.blocks.insert(key, i);
            i
        }
    };
    let ha = h.access_rules[idx]
        .host_access
        .as_mut()
        .expect("legacy slot always points at a host_access rule");
    let entries = match dlow {
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
            entries
        }
        _ => Vec::new(),
    };
    let Some(limit) = limit else {
        ha.unlimited = true;
        match dlow {
            "order" => {
                // Apache rewrites `order[]` for every method, so a later
                // unlimited `Order` supersedes an earlier `<Limit>` one.
                ha.order = AccessOrder::parse(rest);
                for l in &mut ha.limited {
                    l.order = None;
                }
            }
            "allow" => ha.allow.extend(entries),
            _ => ha.deny.extend(entries),
        }
        return Ok(());
    };
    let (limit_line, methods, except) = limit;
    // Keyed by (block, section): a `<Limit>` index only ever names an entry of
    // the block it was created in (#791/#792).
    let li = *slots.limits.entry((key, limit_line)).or_insert_with(|| {
        ha.limited.push(LimitedAccess {
            methods: methods.clone(),
            except,
            order: None,
            allow: Vec::new(),
            deny: Vec::new(),
        });
        ha.limited.len() - 1
    });
    let Some(l) = ha.limited.get_mut(li) else {
        return Err(RewriteError::Malformed {
            line: lineno,
            msg: "legacy <Limit> slot out of range".into(),
        });
    };
    match dlow {
        "order" => l.order = Some(AccessOrder::parse(rest)),
        "allow" => l.allow.extend(entries),
        _ => l.deny.extend(entries),
    }
    Ok(())
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
fn access_matchers<'a>(
    stack: impl IntoIterator<Item = &'a PendingSection>,
    denied: bool,
) -> Option<Vec<AccessMatcher>> {
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
            None if sec.method.is_some() => matchers.extend(sec.method.clone()),
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
                } else if !denied && sec.is_unmodelled() {
                    // `<IfDefine>`, `<Location*>`, ...: the condition is not evaluated,
                    // so a deny still applies but a grant must not widen to the directory.
                    return None;
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
    auth_matcher: Option<AccessMatcher>,
    /// Source line of the opening tag — the identity of this scope for the
    /// per-scope legacy `Order`/`Allow`/`Deny` accumulation.
    lineno: usize,
    /// The scope a directive (e.g. `Header`) inside this block inherits. Set for
    /// `<Files*>`/`<Directory*>` and for the common `<If "%{REQUEST_URI} ...">`.
    scope: Option<Scope>,
    /// `<Limit>`/`<LimitExcept>`: the method matcher ANDed into enclosed access rules.
    method: Option<AccessMatcher>,
    /// `<RequireAll>`/`<RequireAny>`/`<RequireNone>`: enclosed `Require` verdicts
    /// (true = deny) are combined here and recorded as one rule on close.
    require_kind: Option<RequireKind>,
    require_children: Vec<bool>,
    branch: Option<IfBranch>,
}

/// A member of an `<If>`/`<ElseIf>`/`<Else>` chain, carrying its own condition
/// (`None` = not modellable).
enum IfBranch {
    If(Option<UriExpr>),
    ElseIf(Option<UriExpr>),
    Else,
}

#[derive(Clone, Copy)]
enum RequireKind {
    All,
    Any,
    None,
}

impl RequireKind {
    /// The container's deny verdict. Unevaluable predicates already count as deny,
    /// and `<RequireNone>` can never grant on its own, so it always denies.
    fn fold(self, children: &[bool]) -> Option<bool> {
        if children.is_empty() {
            return None;
        }
        Some(match self {
            RequireKind::All => children.iter().any(|d| *d),
            RequireKind::Any => children.iter().all(|d| *d),
            RequireKind::None => true,
        })
    }
}

/// The `<Else>`/`<ElseIf>` condition: no earlier member of the chain matched
/// (and, for `<ElseIf>`, its own condition holds).
fn else_expr(prior: Option<&[Option<UriExpr>]>, own: Option<Option<UriExpr>>) -> Option<UriExpr> {
    let prior = prior?.iter().cloned().collect::<Option<Vec<UriExpr>>>()?;
    let none_before = UriExpr::Not(Box::new(match <[UriExpr; 1]>::try_from(prior) {
        Ok([one]) => one,
        Err(many) => UriExpr::Or(many),
    }));
    match own {
        None => Some(none_before),
        Some(own) => Some(UriExpr::And(vec![none_before, own?])),
    }
}

impl PendingSection {
    /// `<Files*>`, `<Directory*>` and the `<If>` chain: the sections that narrow
    /// the request scope (and so key their own legacy access block).
    fn is_scoping(&self) -> bool {
        self.kind.is_some() || self.branch.is_some()
    }

    /// A container whose condition this parser does not model (anything but
    /// `IfModule`, `Files*`, `Directory*`, `If`/`ElseIf`/`Else`, `Limit*` and
    /// `Require*`).
    fn is_unmodelled(&self) -> bool {
        self.kind.is_none()
            && self.method.is_none()
            && self.require_kind.is_none()
            && self.scope.is_none()
            && !self.kind_name.eq_ignore_ascii_case("ifmodule")
    }

    /// An access section whose pattern does not compile is a parse error (#604):
    /// the whole file then fails closed through the cache's deny-all sentinel, as
    /// Apache answers 500 for the directory, instead of silently dropping the
    /// `Require`/`Deny` (and `Header`) rules it encloses.
    fn open(
        line: &str,
        lineno: usize,
        prior_if_chain: Option<&[Option<UriExpr>]>,
    ) -> Result<PendingSection, RewriteError> {
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
                // `<Files "glob">` uses APACHE FNMATCH glob semantics, NOT regex:
                // `*.log` must match `x.log` but not `xlog`. Translate the glob to
                // an anchored regex so the uniform regex-matching path handles it.
                // fnmatch never rejects a pattern, so a glob whose translation does
                // not compile (e.g. a reversed range) matches its text literally.
                Some(SectionKind::Files) if !is_regex_marker => Regex::new(&fnmatch_to_regex(&pat))
                    .or_else(|_| Regex::new(&format!("^{}$", fancy_regex::escape(&pat)))),
                _ => Regex::new(&crate::rules::pcre_literal_escapes(&pat)),
            }
            .map_err(|e| RewriteError::BadRegex {
                line: lineno,
                pattern: pat.clone(),
                source: Box::new(e),
            })?;
            (Some(compiled), pat)
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

        let mut method = None;
        let mut require_kind = None;
        let mut branch = None;
        let mut scope = scope;
        match tag_low.as_str() {
            "limit" | "limitexcept" => {
                let methods = tokenize(args);
                if methods.is_empty() {
                    return Err(RewriteError::Malformed {
                        line: lineno,
                        msg: format!("<{tag}> without methods"),
                    });
                }
                // Apache resolves names case-sensitively against its built-in
                // registry and cannot register a method from `.htaccess` (#793).
                if let Some(bad) = methods
                    .iter()
                    .find(|m| !super::mod_access::is_builtin_method(m))
                {
                    return Err(RewriteError::Malformed {
                        line: lineno,
                        msg: format!("could not register method '{bad}' for <{tag}>"),
                    });
                }
                if tag_low == "limit" && methods.iter().any(|m| m == "TRACE") {
                    return Err(RewriteError::Malformed {
                        line: lineno,
                        msg: "TRACE cannot be controlled by <Limit>".into(),
                    });
                }
                method = Some(AccessMatcher::Method {
                    methods,
                    except: tag_low == "limitexcept",
                });
            }
            "requireall" => require_kind = Some(RequireKind::All),
            "requireany" => require_kind = Some(RequireKind::Any),
            "requirenone" => require_kind = Some(RequireKind::None),
            "if" => {
                branch = Some(IfBranch::If(
                    scope.as_ref().and_then(|s| s.uri_expr.clone()),
                ))
            }
            "elseif" | "else" => {
                let own = (tag_low == "elseif").then(|| parse_if_uri_expr(&unquote(args.trim())));
                scope = Some(Scope {
                    kind: ScopeKind::If,
                    regex: None,
                    negate: false,
                    uri_expr: else_expr(prior_if_chain, own.clone()),
                });
                branch = Some(match own {
                    Some(own) => IfBranch::ElseIf(own),
                    None => IfBranch::Else,
                });
            }
            _ => {}
        }

        Ok(PendingSection {
            kind,
            kind_name,
            regex,
            auth_matcher: auth_section_matcher(kind, &tag_low, args),
            lineno,
            scope,
            method,
            require_kind,
            require_children: Vec::new(),
            branch,
        })
    }
}

fn auth_section_matcher(kind: Option<SectionKind>, tag: &str, args: &str) -> Option<AccessMatcher> {
    let tokens = auth_tokens(args)?;
    let (pattern, regex_marker) = match tokens.as_slice() {
        [pattern] if !pattern.is_empty() => (pattern, false),
        [marker, pattern] if marker == "~" && !pattern.is_empty() => (pattern, true),
        _ => return None,
    };
    match kind {
        Some(SectionKind::Files) if !regex_marker => Some(AccessMatcher::Basename(
            Regex::new(&fnmatch_to_regex(pattern)).ok()?,
        )),
        Some(SectionKind::Files | SectionKind::FilesMatch) => Some(AccessMatcher::Basename(
            Regex::new(&crate::rules::pcre_literal_escapes(pattern)).ok()?,
        )),
        Some(SectionKind::Directory) if !regex_marker => {
            let glob = fnmatch_to_regex(pattern.trim_end_matches('/'));
            let regex = Regex::new(&format!("{}(?:/|$)", glob.trim_end_matches('$'))).ok()?;
            Some(AccessMatcher::Path(regex))
        }
        Some(SectionKind::Directory | SectionKind::DirectoryMatch) => Some(AccessMatcher::Path(
            Regex::new(&crate::rules::pcre_literal_escapes(pattern)).ok()?,
        )),
        None if tag == "if" => parse_if_scope(pattern)?
            .uri_expr
            .map(AccessMatcher::IfUriExpr),
        None => None,
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

const MAX_IF_URI_EXPR_DEPTH: usize = 32;

fn parse_if_uri_expr(expr: &str) -> Option<UriExpr> {
    parse_if_uri_expr_at(expr, 0)
}

fn parse_if_uri_expr_at(expr: &str, depth: usize) -> Option<UriExpr> {
    // Tenant-controlled .htaccess must not turn recursive descent (and the
    // resulting tree's evaluation/drop) into a process stack-overflow abort.
    if depth > MAX_IF_URI_EXPR_DEPTH {
        return None;
    }
    let expr = strip_if_outer_parens(expr.trim())?;
    let or_parts = split_if_top_level(expr, b"||")?;
    if or_parts.len() > 1 {
        return or_parts
            .into_iter()
            .map(|part| parse_if_uri_expr_at(part, depth + 1))
            .collect::<Option<Vec<_>>>()
            .map(UriExpr::Or);
    }
    let and_parts = split_if_top_level(expr, b"&&")?;
    if and_parts.len() > 1 {
        return and_parts
            .into_iter()
            .map(|part| parse_if_uri_expr_at(part, depth + 1))
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
    let mut outer_depth = 0;
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
        outer_depth += 1;
        if outer_depth > MAX_IF_URI_EXPR_DEPTH {
            return None;
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
    // ap_expr regexes are delimited: `/re/` or `m<delim>re<delim>`, optionally
    // followed by the `i` flag. A bare token is not a regex literal.
    let (delim, body) = match rest.strip_prefix('m') {
        Some(body) => {
            let body = body.trim_start();
            let delim = body.chars().next()?;
            (delim, &body[delim.len_utf8()..])
        }
        None => ('/', rest.strip_prefix('/')?),
    };
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
    let nocase = match body[end + delim.len_utf8()..].trim() {
        "" => false,
        "i" => true,
        _ => return None,
    };
    // ap_expr regexes are PCRE: `\<`/`\>` are literal brackets (#978).
    let pattern = crate::rules::pcre_literal_escapes(&body[..end]);
    let pattern = if nocase {
        std::borrow::Cow::Owned(format!("(?i){pattern}"))
    } else {
        pattern
    };
    let regex = Regex::new(&pattern).ok()?;
    Some(UriCond {
        regex: Some(regex),
        negate,
    })
}

/// Whether the class opened by a `[` (iterator positioned just after it) has a
/// closing `]`: an optional leading `!`/`^` (negation), then at least one member (a `]` right
/// after the opening is a member), then a `]`.
fn glob_class_closes(mut rest: impl Iterator<Item = char> + Clone) -> bool {
    let mut peek = rest.clone();
    if matches!(peek.next(), Some('!' | '^')) {
        rest.next();
    }
    rest.next().is_some() && rest.any(|cc| cc == ']')
}

/// Translate an Apache `fnmatch` glob to an anchored regex. `*` -> `.*`, `?` ->
/// `.`, `[...]` classes are passed through (Apache and regex share the syntax),
/// and every other metacharacter is escaped so it is matched literally — this
/// is exactly what makes `*.log` match `x.log` but not `xlog`. Like fnmatch, a
/// `[` with no closing `]` is a literal bracket, so a glob always compiles.
fn fnmatch_to_regex(glob: &str) -> String {
    let mut re = String::with_capacity(glob.len() + 4);
    re.push('^');
    let mut chars = glob.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '[' if glob_class_closes(chars.clone()) => {
                // Copy a character class (translate a leading `!` to regex `^`
                // negation). A `]` right after the opening is a member, as in
                // fnmatch; a literal `[` or `\\` inside is escaped for the regex.
                re.push('[');
                if matches!(chars.peek(), Some('!' | '^')) {
                    chars.next();
                    re.push('^');
                }
                let mut first = true;
                for cc in chars.by_ref() {
                    if cc == ']' && !first {
                        re.push(']');
                        break;
                    }
                    if matches!(cc, '[' | ']' | '\\') {
                        re.push('\\');
                    }
                    re.push(cc);
                    first = false;
                }
            }
            // Regex metacharacters that must be escaped to stay literal.
            '.' | '+' | '(' | ')' | '{' | '}' | '^' | '$' | '|' | '\\' | '[' | ']' => {
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

fn parse_header(rest: &str, line: usize) -> Result<Option<HeaderDirective>, RewriteError> {
    // [always|onsuccess] action name [value] [env=...]
    let mut toks = header_tokens(rest).ok_or_else(|| RewriteError::Malformed {
        line,
        msg: "unbalanced Header quotes".into(),
    })?;
    if toks.is_empty() {
        return Ok(None);
    }
    let mut always = false;
    if toks[0].eq_ignore_ascii_case("always") {
        always = true;
        toks.remove(0);
    } else if toks[0].eq_ignore_ascii_case("onsuccess") {
        toks.remove(0);
    }
    if toks.is_empty() {
        return Ok(None);
    }
    let action = match toks.remove(0).to_ascii_lowercase().as_str() {
        "set" => HeaderAction::Set,
        "add" => HeaderAction::Add,
        "append" => HeaderAction::Append,
        "merge" => HeaderAction::Merge,
        "unset" => HeaderAction::Unset,
        "echo" => HeaderAction::Echo,
        _ => return Ok(None),
    };
    if toks.is_empty() {
        return Ok(None);
    }
    let name = toks.remove(0);

    // The remaining tokens: an optional value, then an optional env=/expr= guard.
    let mut value = String::new();
    let mut env = None;
    let mut expr = Vec::new();
    let mut has_expr = false;
    let mut i = 0;
    while i < toks.len() {
        let tok = &toks[i];
        if let Some(g) = tok.strip_prefix("env=") {
            if env.is_some() || g.is_empty() || g == "!" {
                return Err(RewriteError::Malformed {
                    line,
                    msg: "malformed or duplicate Header environment guard".into(),
                });
            }
            let (negate, var) = match g.strip_prefix('!') {
                Some(v) => (true, v.to_string()),
                None => (false, g.to_string()),
            };
            env = Some(EnvGuard { var, negate });
            i += 1;
        } else if tok.starts_with("expr=") {
            if has_expr {
                return Err(RewriteError::Malformed {
                    line,
                    msg: "duplicate Header expression".into(),
                });
            }
            has_expr = true;
            let mut raw = tok.strip_prefix("expr=").unwrap().to_string();
            i += 1;
            while i < toks.len() && !toks[i].starts_with("env=") {
                if !raw.is_empty() {
                    raw.push(' ');
                }
                raw.push_str(&toks[i]);
                i += 1;
            }
            expr = split_if_top_level(&raw, b"&&")
                .and_then(|parts| {
                    parts
                        .into_iter()
                        .map(|part| parse_if_uri_cond(part.trim()))
                        .collect::<Option<Vec<_>>>()
                })
                .filter(|conditions| !conditions.is_empty())
                .ok_or_else(|| RewriteError::Malformed {
                    line,
                    msg: "unsupported or malformed Header expression".into(),
                })?;
        } else if value.is_empty() {
            value = tok.clone();
            i += 1;
        } else {
            if tok != "early" {
                return Err(RewriteError::Malformed {
                    line,
                    msg: "unsupported Header trailing argument".into(),
                });
            }
            i += 1;
        }
    }
    let field_name = http::HeaderName::from_bytes(name.as_bytes()).ok();
    let interpolated = value.contains("%{");
    let static_value = match action {
        HeaderAction::Unset | HeaderAction::Echo => None,
        _ if interpolated => None,
        _ => http::HeaderValue::from_str(&value).ok(),
    };
    Ok(Some(HeaderDirective {
        action,
        name,
        value,
        field_name,
        static_value,
        interpolated,
        env,
        expr,
        always,
        scopes: vec![],
    }))
}

/// Accept either Apache quote delimiter, preserving inner quotes and regex
/// escapes. Incomplete quotes must never conceal a guard.
fn header_tokens(text: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut value = String::new();
    let mut quote = None;
    let mut present = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if quote.is_some() => {
                if chars.peek().copied() == quote {
                    value.push(chars.next()?);
                } else {
                    value.push(ch);
                }
                present = true;
            }
            '"' | '\'' if quote == Some(ch) => {
                quote = None;
            }
            '"' | '\'' if quote.is_none() => {
                quote = Some(ch);
                present = true;
            }
            ch if ch.is_whitespace() && quote.is_none() => {
                if present {
                    tokens.push(std::mem::take(&mut value));
                    present = false;
                }
            }
            ch => {
                value.push(ch);
                present = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if present {
        tokens.push(value);
    }
    Some(tokens)
}

/// Memo classification of one `SetEnvIf`: the attribute must be a key-covered
/// special (path / query / GET-only method / Host) or a request header — which
/// then becomes a per-entry vary dimension. Client/server address and protocol
/// are neither, and a directive that seeds an `%{ENV:}` name the rewrite
/// classifier assumes constant-empty (`REDIRECT_STATUS`) would invalidate that
/// assumption for every later reader. Mirrors the attribute set of
/// `ReqAttrs::resolve`. A header attribute that is absent falls back to the
/// env variable of that name (#794); that value is either a server variable
/// determined by the base key (`HTTPS`), or an earlier `SetEnvIf`'s output,
/// whose own inputs were classified here, so the fallback adds no input.
fn classify_set_env_if_for_memo(memo: &mut MemoClass, s: &SetEnvIf, lineno: usize) {
    if s.assigns
        .iter()
        .any(|(var, _)| var.eq_ignore_ascii_case("REDIRECT_STATUS"))
    {
        memo.block(lineno, "set_env_if_seeds_redirect_status");
        // Page-cache keying also consumes vary_headers, even when finished
        // response memoization is blocked. Retain the attribute's header read.
    }
    let attr = s.attribute.as_str();
    let eq = |n: &str| attr.eq_ignore_ascii_case(n);
    if eq("host") || eq("server_name") {
        // Finished memo keys already carry Host; the page-cache key uses the
        // canonical vhost and needs this read to distinguish request aliases.
        memo.vary("host".into());
        return;
    }
    if eq("request_uri") || eq("request_method") || eq("query_string") {
        return;
    }
    if eq("request_protocol") || eq("remote_addr") || eq("remote_host") || eq("server_addr") {
        memo.block(lineno, "set_env_if_remote");
        memo.unkeyed(lineno, "set_env_if_remote");
        return;
    }
    match fold_header_name(attr) {
        Some(name) => memo.vary(name),
        None => {
            memo.block(lineno, "set_env_if_bad_attribute");
            memo.unkeyed(lineno, "set_env_if_bad_attribute");
        }
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

/// A malformed directive is a parse error, as Apache refuses the directory: a
/// dropped `SetEnvIf` feeding `Deny from env=` would otherwise fail open.
fn parse_set_env_if(rest: &str, nocase: bool, line: usize) -> Result<SetEnvIf, RewriteError> {
    let malformed = |msg: String| RewriteError::Malformed { line, msg };
    let toks = tokenize(rest);
    if toks.len() < 3 {
        return Err(malformed(
            "SetEnvIf needs an attribute, a regex and a variable".into(),
        ));
    }
    let attribute = toks[0].clone();
    // mod_setenvif treats a name with any character outside `[-A-Za-z0-9_]` as
    // a regex over request-header NAMES. That reads an open-ended header set no
    // cache key can capture, so it is refused rather than dropped (#794).
    if attribute.is_empty()
        || !attribute
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(malformed(format!(
            "SetEnvIf header-name regex attribute {attribute:?} is not supported"
        )));
    }
    let regex_src = toks[1].clone();
    // `!VAR` unsets VAR (mod_setenvif); the whole token after `!` is the name.
    let assigns: Vec<(String, String)> = toks
        .iter()
        .skip(2)
        .map(|assign| {
            if assign.starts_with('!') {
                return (assign.clone(), String::new());
            }
            match assign.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (assign.clone(), "1".to_string()),
            }
        })
        .collect();
    let regex =
        crate::rules::CompiledRegex::compile(&regex_src, nocase, line).map_err(|e| match e {
            RewriteError::BadRegex { source, .. } => {
                malformed(format!("invalid SetEnvIf regex: {source}"))
            }
            other => other,
        })?;
    // (#312) Same literal-prefix extraction the RewriteRule prefilter uses, on
    // the same PCRE form the regex compiles; for SetEnvIfNoCase the (?i)
    // wrapper makes any prefix case-sensitive-invalid, so pass nocase through
    // (extractor returns empty for it).
    let literal_prefix = crate::rules::extract_literal_prefix(
        &crate::rules::pcre_literal_escapes(&regex_src),
        false,
        nocase,
    );
    let needs_caps = assigns
        .iter()
        .any(|(var, value)| !var.starts_with('!') && value.contains('$'));
    let regex_src = if nocase {
        format!("(?i){regex_src}")
    } else {
        regex_src
    };
    Ok(SetEnvIf {
        attr: crate::directives::SetEnvAttr::classify(&attribute),
        attribute,
        regex,
        regex_src: regex_src.into_boxed_str(),
        literal_prefix,
        assigns,
        scopes: Vec::new(),
        needs_caps,
        reuse_prev: false,
    })
}

/// (#977) Per-file facts that let each request's `SetEnvIf` run skip work
/// whose result is already known.
fn finish_set_env_if(h: &mut Htaccess) {
    let reuse: Vec<bool> = h
        .set_env_if
        .windows(2)
        .map(|w| matches!(w, [prev, cur] if tests_same_subject(prev, cur)))
        .collect();
    for (cur, reuse) in h.set_env_if.iter_mut().skip(1).zip(reuse) {
        cur.reuse_prev = reuse;
    }
    h.set_env_if_reads_conn = h.set_env_if.iter().any(|s| s.attr.reads_connection());
    h.cookie_env_absent = Some(h.eval_cookie_env(None));
}

/// Whether `cur` necessarily matches exactly when `prev` does: the same
/// attribute spelling (an env fallback prefers an exact-case name), pattern,
/// prefix and scopes, and `prev` assigns no variable the attribute's env
/// fallback could then read. Only a test without captures can be reused.
fn tests_same_subject(prev: &SetEnvIf, cur: &SetEnvIf) -> bool {
    let folded = |b: u8| match b {
        b'_' => b'-',
        b => b.to_ascii_lowercase(),
    };
    let names_attribute = |var: &str| {
        let var = var.strip_prefix('!').unwrap_or(var);
        var.len() == cur.attribute.len()
            && var
                .bytes()
                .zip(cur.attribute.bytes())
                .all(|(a, b)| folded(a) == folded(b))
    };
    !cur.needs_caps
        && prev.attribute == cur.attribute
        && prev.regex_src == cur.regex_src
        && prev.literal_prefix == cur.literal_prefix
        && prev.scopes == cur.scopes
        && !prev.assigns.iter().any(|(var, _)| names_attribute(var))
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
/// A directive whose effect must stay inside its enclosing section cannot sit in a
/// container this parser does not model (or an `<If>` whose expression it cannot
/// evaluate): applying it directory-wide or dropping it could each flip PHP
/// routing or ini policy, so the file fails closed as Apache-500 does.
fn reject_unscopable(
    section_stack: &[PendingSection],
    cur_scopes: &[Scope],
    lineno: usize,
    directive: &str,
) -> Result<(), RewriteError> {
    if section_stack.iter().any(PendingSection::is_unmodelled)
        || cur_scopes
            .iter()
            .any(|sc| sc.kind == ScopeKind::If && sc.uri_expr.is_none())
    {
        return Err(RewriteError::Malformed {
            line: lineno,
            msg: format!("{directive} inside an unsupported container"),
        });
    }
    Ok(())
}

/// Whether a handler name selects PHP. Fails toward PHP for the common vendor
/// spellings (`application/x-httpd-ea-php81`, `php-script`, an FPM `proxy:` URL)
/// so a renamed PHP handler never degrades to static source serving; the
/// highlighter `application/x-httpd-php-source` is not an executor.
fn handler_is_php(handler: &str) -> bool {
    let h = handler.to_ascii_lowercase();
    h.contains("php") && !h.contains("php-source")
}

/// Whether a MIME type selects PHP (`application/x-httpd-php`, `…-lsphp`,
/// `…-ea-php81`, …), excluding the `-source` highlighter type.
fn type_is_php(mime: &str) -> bool {
    let t = mime.to_ascii_lowercase();
    (t.starts_with("application/x-httpd-") || t.starts_with("x-httpd-"))
        && t.contains("php")
        && !t.contains("php-source")
}

fn type_spec(mime: &str) -> TypeSpec {
    TypeSpec {
        mime: mime.to_string(),
        php: type_is_php(mime),
    }
}

fn parse_handler_op(dlow: &str, rest: &str) -> Option<HandlerOpKind> {
    let toks = tokenize(rest);
    let exts = |toks: &[String]| -> Vec<String> {
        toks.iter()
            .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
            .filter(|e| !e.is_empty())
            .collect()
    };
    let first = toks.first()?;
    let none = first.eq_ignore_ascii_case("none");
    let kind = match dlow {
        "sethandler" => HandlerOpKind::SetHandler((!none).then(|| handler_is_php(first))),
        "forcetype" => HandlerOpKind::ForceType((!none).then(|| type_spec(first))),
        "addhandler" | "addtype" => {
            let exts = exts(&toks[1..]);
            if exts.is_empty() {
                return None;
            }
            if dlow == "addhandler" {
                HandlerOpKind::AddHandler {
                    exts,
                    php: handler_is_php(first),
                }
            } else {
                HandlerOpKind::AddType {
                    exts,
                    ty: type_spec(first),
                }
            }
        }
        _ => {
            let exts = exts(&toks);
            if exts.is_empty() {
                return None;
            }
            if dlow == "removehandler" {
                HandlerOpKind::RemoveHandler(exts)
            } else {
                HandlerOpKind::RemoveType(exts)
            }
        }
    };
    Some(kind)
}

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
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with("'") && s.ends_with("'")))
    {
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
        assert_eq!(h.handler_ops.len(), 1);
        assert_eq!(h.handler_ops[0].kind, HandlerOpKind::SetHandler(Some(true)));
        assert_eq!(h.handler_ops[0].scopes.len(), 1);
        assert!(h.has_handler_override);
    }

    #[test]
    fn set_handler_reset_forms() {
        let h = Htaccess::parse("SetHandler default-handler\n").unwrap();
        assert_eq!(
            h.handler_ops[0].kind,
            HandlerOpKind::SetHandler(Some(false))
        );
        assert!(h.handler_ops[0].scopes.is_empty()); // directory-wide
        // A pure reset can never select PHP, so the hot-path gate stays off.
        assert!(!h.has_handler_override);
        let h = Htaccess::parse("SetHandler None\n").unwrap();
        assert_eq!(h.handler_ops[0].kind, HandlerOpKind::SetHandler(None));
    }

    #[test]
    fn quoted_handler_and_type_values_are_dequoted() {
        // #851: the quoted spelling must not be recorded as a non-PHP handler.
        for (directive, kind) in [
            (
                "SetHandler \"application/x-httpd-php\"",
                HandlerOpKind::SetHandler(Some(true)),
            ),
            (
                "ForceType \"application/x-httpd-php\"",
                HandlerOpKind::ForceType(Some(TypeSpec {
                    mime: "application/x-httpd-php".into(),
                    php: true,
                })),
            ),
            (
                "AddHandler \"application/x-httpd-php\" \".html\"",
                HandlerOpKind::AddHandler {
                    exts: vec!["html".into()],
                    php: true,
                },
            ),
        ] {
            let h = Htaccess::parse(directive).unwrap();
            assert_eq!(h.handler_ops[0].kind, kind, "{directive}");
            assert!(h.has_handler_override, "{directive}");
        }
    }

    #[test]
    fn php_handler_spellings() {
        for handler in [
            "application/x-httpd-php",
            "APPLICATION/X-HTTPD-PHP",
            "application/x-httpd-lsphp",
            "application/x-httpd-ea-php81",
            "x-httpd-php",
            "php-script",
        ] {
            assert!(handler_is_php(handler), "{handler}");
        }
        assert!(!handler_is_php("application/x-httpd-php-source"));
        assert!(!handler_is_php("default-handler"));
        assert!(type_is_php("application/x-httpd-php"));
        assert!(type_is_php("application/x-httpd-ea-php74"));
        assert!(!type_is_php("application/x-httpd-php-source"));
        assert!(!type_is_php("text/x-php"));
        assert!(!type_is_php("image/webp"));
    }

    #[test]
    fn add_handler_and_add_type_record_php_extensions() {
        for directive in [
            "AddHandler application/x-httpd-php .html .htm",
            "AddType application/x-httpd-php .html .htm",
        ] {
            let h = Htaccess::parse(directive).unwrap();
            assert_eq!(h.handler_ops.len(), 1, "{directive}");
            match &h.handler_ops[0].kind {
                HandlerOpKind::AddHandler { exts, php }
                | HandlerOpKind::AddType {
                    exts,
                    ty: TypeSpec { php, .. },
                } => {
                    assert_eq!(exts, &vec!["html".to_string(), "htm".to_string()]);
                    assert!(php, "{directive}");
                }
                other => panic!("{directive}: {other:?}"),
            }
            assert!(h.has_handler_override, "{directive}");
        }
    }

    #[test]
    fn non_php_add_type_is_recorded_but_cannot_force() {
        // Recorded so it can override an inherited PHP mapping (#853), but it
        // never opens the hot-path gate on its own.
        let h = Htaccess::parse("AddType text/html .shtml\nRemoveHandler .html\n").unwrap();
        assert_eq!(h.handler_ops.len(), 2);
        assert!(!h.has_handler_override);
    }

    #[test]
    fn handler_and_php_value_inside_unevaluable_if_fail_closed() {
        // #852: an <If> we cannot evaluate would apply these directory-wide.
        for directive in [
            "SetHandler none",
            "SetHandler application/x-httpd-php",
            "ForceType application/x-httpd-php",
            "AddHandler application/x-httpd-php .html",
            "AddType application/x-httpd-php .html",
            "AddType text/plain .html",
            "RemoveHandler .html",
            "RemoveType .html",
            "php_value auto_prepend_file none",
        ] {
            let text = format!("<If \"%{{HTTP_HOST}} == 'static.example'\">\n{directive}\n</If>\n");
            assert!(
                matches!(Htaccess::parse(&text), Err(RewriteError::Malformed { .. })),
                "{directive}"
            );
            let text = format!("<IfDefine FOO>\n{directive}\n</IfDefine>\n");
            assert!(
                matches!(Htaccess::parse(&text), Err(RewriteError::Malformed { .. })),
                "{directive} in IfDefine"
            );
        }
        // An evaluable <If> and <IfModule> keep working.
        let h = Htaccess::parse(
            "<If \"%{REQUEST_URI} =~ m#^/admin#\">\nSetHandler application/x-httpd-php\n</If>\n\
             <IfModule mod_mime.c>\nAddType application/manifest+json .webmanifest\n</IfModule>\n",
        )
        .unwrap();
        assert_eq!(h.handler_ops.len(), 2);
    }

    #[test]
    fn directory_index_disabled_is_an_override() {
        let h = Htaccess::parse("DirectoryIndex disabled\n").unwrap();
        assert_eq!(h.directory_index_override(), Some(&[][..]));
        let h = Htaccess::parse("DirectoryIndex index.php\n").unwrap();
        assert_eq!(
            h.directory_index_override(),
            Some(&["index.php".to_string()][..])
        );
        assert_eq!(
            Htaccess::parse("").unwrap().directory_index_override(),
            None
        );
        // Next to other names `disabled` is a literal file name (Apache mod_dir).
        let h = Htaccess::parse("DirectoryIndex index.php disabled\n").unwrap();
        assert!(!h.directory_index_disabled);
        assert_eq!(h.directory_index, vec!["index.php", "disabled"]);
        // A later list re-enables the search.
        let h = Htaccess::parse("DirectoryIndex disabled\nDirectoryIndex a.php\n").unwrap();
        assert_eq!(
            h.directory_index_override(),
            Some(&["a.php".to_string()][..])
        );
    }

    #[test]
    fn no_handler_directive_leaves_override_flag_false() {
        let h = Htaccess::parse("php_value auto_prepend_file \"/x.php\"\n").unwrap();
        assert!(!h.has_handler_override);
    }
}
