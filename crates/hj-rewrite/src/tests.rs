//! Unit + golden tests. The golden tests feed *real* rules taken verbatim from
//! the live config on this host:
//!   - /web/public_html/.htaccess        (XenForo front controller, bot tagging)
//!   - /web/moontimenow/.htaccess         (HTTPS force, www canonical, lang/moon)
//!   - /web/news/.htaccess                (tracking-param strip, FilesMatch deny)
//!   - conf/vhosts/mcp.forum.example.xml (inline [P] proxy + SSE Accept)

use crate::*;
use std::collections::BTreeMap;

fn input(uri: &str) -> RewriteInput<'static> {
    RewriteInput::new(uri.to_string(), "/web/test")
}

// ---------------------------------------------------------------------------
// Parsing basics
// ---------------------------------------------------------------------------

#[test]
fn engine_off_is_noop() {
    let rs = RuleSet::parse("RewriteEngine Off\nRewriteRule ^.*$ index.php [L]").unwrap();
    assert!(!rs.engine_on);
    let out = evaluate(&rs, &input("/anything"));
    assert!(matches!(out, RewriteOutcome::Unchanged { .. }));
}

#[test]
fn literal_prefix_keeps_optional_quantifier_matches() {
    // Regression: the literal-prefix fast-reject must not drop a match when an early
    // literal char is governed by a quantifier (`?`/`*`/`{`). `^api/?$` must match
    // BOTH `/api/` and `/api` (the `/` is optional) — previously `/api` was rejected.
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^api/?$ api.php [L]").unwrap();
    assert!(
        matches!(
            evaluate(&rs, &input("/api/")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/api/"
    );
    assert!(
        matches!(
            evaluate(&rs, &input("/api")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/api must rewrite (was wrongly dropped by the literal-prefix filter)"
    );

    // A deny rule with an early optional char must NOT be bypassed.
    let deny = RuleSet::parse("RewriteEngine On\nRewriteRule ^colou?r - [F]").unwrap();
    assert!(matches!(
        evaluate(&deny, &input("/colour")),
        RewriteOutcome::Forbidden { .. }
    ));
    assert!(
        matches!(
            evaluate(&deny, &input("/color")),
            RewriteOutcome::Forbidden { .. }
        ),
        "/color must also be forbidden (deny rule was bypassed)"
    );

    // `*` (zero-or-more) makes the preceding char optional too.
    let star = RuleSet::parse("RewriteEngine On\nRewriteRule ^ab*c x.php [L]").unwrap();
    assert!(
        matches!(
            evaluate(&star, &input("/ac")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/ac vs ^ab*c"
    );

    // `+` (one-or-more) KEEPS its required byte — a non-matching target still rejects.
    let plus = RuleSet::parse("RewriteEngine On\nRewriteRule ^ab+c y.php [L]").unwrap();
    assert!(
        matches!(
            evaluate(&plus, &input("/abc")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/abc vs ^ab+c"
    );
    assert!(
        matches!(
            evaluate(&plus, &input("/ac")),
            RewriteOutcome::Unchanged { .. }
        ),
        "/ac must NOT match ^ab+c"
    );
}

#[test]
fn literal_prefix_unsound_for_top_level_alternation() {
    // Regression (#83): a top-level `|` is `(^A)|(B)`, so the literal-prefix fast-reject
    // must NOT keep the left arm's bytes — a target matching the RIGHT arm need not start
    // with them. Previously `^abc|def` extracted prefix `abc` and silently dropped `def`.
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^abc|def x.php [L]").unwrap();
    assert!(
        matches!(
            evaluate(&rs, &input("/def")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/def must match ^abc|def"
    );
    assert!(
        matches!(
            evaluate(&rs, &input("/xdef")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/xdef must match (unanchored right arm)"
    );
    assert!(
        matches!(
            evaluate(&rs, &input("/abc")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/abc still matches the left arm"
    );

    // The security-relevant case: a deny rule must not fail open on the right arm.
    let deny = RuleSet::parse("RewriteEngine On\nRewriteRule ^a\\.php|b\\.php - [F]").unwrap();
    assert!(
        matches!(
            evaluate(&deny, &input("/b.php")),
            RewriteOutcome::Forbidden { .. }
        ),
        "/b.php must be forbidden (was bypassed)"
    );
    assert!(
        matches!(
            evaluate(&deny, &input("/a.php")),
            RewriteOutcome::Forbidden { .. }
        ),
        "/a.php must be forbidden"
    );

    // Grouped alternation `^(abc|def)` was already correct (prefix empty via `(`) — keep it so.
    let grp = RuleSet::parse("RewriteEngine On\nRewriteRule ^(abc|def)$ y.php [L]").unwrap();
    assert!(
        matches!(
            evaluate(&grp, &input("/def")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/def vs ^(abc|def)$"
    );
    assert!(
        matches!(
            evaluate(&grp, &input("/abc")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/abc vs ^(abc|def)$"
    );

    // An ESCAPED pipe `\|` is a literal byte and must stay in the prefix.
    let esc = RuleSet::parse("RewriteEngine On\nRewriteRule ^a\\|b z.php [L]").unwrap();
    assert!(
        matches!(
            evaluate(&esc, &input("/a|b")),
            RewriteOutcome::Rewritten { .. }
        ),
        "/a|b vs ^a\\|b"
    );
    assert!(
        matches!(
            evaluate(&esc, &input("/b")),
            RewriteOutcome::Unchanged { .. }
        ),
        "/b must NOT match ^a\\|b"
    );
}

#[test]
fn parses_engine_base_and_rule() {
    let rs =
        RuleSet::parse("RewriteEngine On\nRewriteBase /app\nRewriteRule ^foo$ bar.php [L,QSA]")
            .unwrap();
    assert!(rs.engine_on);
    assert_eq!(rs.base.as_deref(), Some("/app"));
    assert_eq!(rs.rules.len(), 1);
    assert!(rs.rules[0].flags.last);
    assert!(rs.rules[0].flags.qsa);
}

#[test]
fn comments_and_blank_lines_ignored() {
    let rs = RuleSet::parse("# comment\n\nRewriteEngine On\n\n# another\n").unwrap();
    assert!(rs.engine_on);
    assert_eq!(rs.rules.len(), 0);
}

// ---------------------------------------------------------------------------
// Substitution + backrefs + QSA
// ---------------------------------------------------------------------------

#[test]
fn simple_rewrite_with_backref() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteRule ^moon/([a-z]+)/?$ location.php?city=$1 [L,QSA]",
    )
    .unwrap();
    let out = evaluate(&rs, &input("/moon/paris/"));
    match out {
        RewriteOutcome::Rewritten {
            new_uri, new_query, ..
        } => {
            assert_eq!(new_uri, "/location.php");
            assert_eq!(new_query.as_deref(), Some("city=paris"));
        }
        other => panic!("expected rewrite, got {other:?}"),
    }
}

#[test]
fn qsa_appends_original_query() {
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^moon/?$ location.php [L,QSA]").unwrap();
    let mut inp = input("/moon/");
    inp.query = "lang=fr".into();
    match evaluate(&rs, &inp) {
        RewriteOutcome::Rewritten {
            new_uri, new_query, ..
        } => {
            assert_eq!(new_uri, "/location.php");
            assert_eq!(new_query.as_deref(), Some("lang=fr"));
        }
        other => panic!("expected rewrite, got {other:?}"),
    }
}

#[test]
fn qsa_merges_subst_and_original_query() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteRule ^([a-z]{2})/moon/?$ location.php?lang=$1 [L,QSA]",
    )
    .unwrap();
    let mut inp = input("/fr/moon/");
    inp.query = "debug=1".into();
    match evaluate(&rs, &inp) {
        RewriteOutcome::Rewritten {
            new_uri, new_query, ..
        } => {
            assert_eq!(new_uri, "/location.php");
            assert_eq!(new_query.as_deref(), Some("lang=fr&debug=1"));
        }
        other => panic!("expected rewrite, got {other:?}"),
    }
}

#[test]
fn trailing_question_clears_query() {
    // /web/news strip-tracking-params rule shape: `$1?` clears query.
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^(.*)$ /$1? [R=301,L]").unwrap();
    let mut inp = input("/page");
    inp.query = "utm_source=x".into();
    match evaluate(&rs, &inp) {
        RewriteOutcome::Redirect { code, location, .. } => {
            assert_eq!(code, 301);
            assert_eq!(location, "/page"); // no query
        }
        other => panic!("expected redirect, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Flags: R, F, P, E, L
// ---------------------------------------------------------------------------

#[test]
fn redirect_default_is_302() {
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^old$ /new [R]").unwrap();
    match evaluate(&rs, &input("/old")) {
        RewriteOutcome::Redirect { code, location, .. } => {
            assert_eq!(code, 302);
            assert_eq!(location, "/new");
        }
        other => panic!("expected redirect, got {other:?}"),
    }
}

#[test]
fn forbidden_flag_yields_403() {
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule \"^\\.(?!htaccess)\" - [F,L]").unwrap();
    // A dotfile request — note the engine matches the stripped path.
    let out = evaluate(&rs, &input("/.git"));
    assert!(
        matches!(out, RewriteOutcome::Forbidden { .. }),
        "got {out:?}"
    );
    // .htaccess is exempt via negative lookahead.
    let out2 = evaluate(&rs, &input("/.htaccess"));
    assert!(
        matches!(out2, RewriteOutcome::Unchanged { .. }),
        "got {out2:?}"
    );
}

#[test]
fn proxy_flag_yields_proxy_outcome() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteRule ^/tools\\.json$ http://127.0.0.1:8002/tools.json [P,L]",
    )
    .unwrap();
    match evaluate(&rs, &input("/tools.json")) {
        RewriteOutcome::Proxy { target_url, .. } => {
            assert_eq!(target_url, "http://127.0.0.1:8002/tools.json");
        }
        other => panic!("expected proxy, got {other:?}"),
    }
}

#[test]
fn env_set_on_no_subst_rule() {
    let rs = RuleSet::parse("RewriteEngine On\nRewriteRule .* - [E=KNOWN_CRAWLER:1]").unwrap();
    let out = evaluate(&rs, &input("/foo"));
    assert_eq!(out.env(), &[("KNOWN_CRAWLER".to_string(), "1".to_string())]);
    assert!(matches!(out, RewriteOutcome::Unchanged { .. }));
}

#[test]
fn multiple_env_sets_with_quoted_values() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteRule .* - [E=Cache-Control:no-cache,E=\"cache-vary:admin\"]",
    )
    .unwrap();
    let out = evaluate(&rs, &input("/admin.php"));
    let env = out.env();
    assert!(env.contains(&("Cache-Control".to_string(), "no-cache".to_string())));
    assert!(env.contains(&("cache-vary".to_string(), "admin".to_string())));
}

#[test]
fn colonless_env_set_marks_var_present_with_empty_value() {
    // Apache `[E=VAR]` (no colon) sets VAR to "" (present). The live .htaccess uses
    // `[E=Cache-Control:no-cache,E=cache-bypass-misc]`; the colonless token must be set
    // so the presence-based `env=` Header guard fires — it was previously dropped, so the
    // `/misc/...` no-store guard never armed and those pages could be cached.
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteRule .* - [E=Cache-Control:no-cache,E=cache-bypass-misc]",
    )
    .unwrap();
    let env = evaluate(&rs, &input("/misc/cookies")).env().to_vec();
    assert!(env.contains(&("Cache-Control".to_string(), "no-cache".to_string())));
    assert!(
        env.contains(&("cache-bypass-misc".to_string(), String::new())),
        "colonless [E=cache-bypass-misc] must be present with an empty value, got {env:?}"
    );
}

// ---------------------------------------------------------------------------
// Conditions: variables, OR, NC, negation, file tests
// ---------------------------------------------------------------------------

#[test]
fn negated_regex_cond_does_not_leak_captures() {
    // A NEGATED regex whose pattern matches makes the cond FAIL; it must not leak its
    // `%1` capture to a later `[OR]` member. cond1 matches `/www/x` (so the negated cond
    // is false), cond2 (`1 =1`) passes the OR, and the rule's `%1` must expand to empty.
    let rs = RuleSet::parse(
        "RewriteEngine On\n\
         RewriteCond %{REQUEST_URI} !^/(www)/x [OR]\n\
         RewriteCond 1 =1\n\
         RewriteRule .* /out-%1 [L]",
    )
    .unwrap();
    match evaluate(&rs, &input("/www/x")) {
        RewriteOutcome::Rewritten { new_uri, .. } => {
            assert_eq!(
                new_uri, "/out-",
                "a negated-regex capture must not leak into %1"
            );
        }
        other => panic!("expected rewrite, got {other:?}"),
    }
}

#[test]
fn https_off_forces_redirect() {
    // moontimenow / news shape.
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]",
    )
    .unwrap();
    let mut inp = input("/page");
    inp.host = "news.forum.example".into();
    inp.https = false;
    match evaluate(&rs, &inp) {
        RewriteOutcome::Redirect { code, location, .. } => {
            assert_eq!(code, 301);
            assert_eq!(location, "https://news.forum.example/page");
        }
        other => panic!("expected redirect, got {other:?}"),
    }
    // When already HTTPS, no redirect.
    let mut inp2 = input("/page");
    inp2.host = "news.forum.example".into();
    inp2.https = true;
    assert!(matches!(
        evaluate(&rs, &inp2),
        RewriteOutcome::Unchanged { .. }
    ));
}

#[test]
fn www_canonical_redirect() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{HTTP_HOST} ^www\\.moon\\.example$ [NC]\nRewriteRule ^(.*)$ https://moon.example/$1 [L,R=301]",
    )
    .unwrap();
    let mut inp = input("/moon/paris");
    inp.host = "www.moon.example".into();
    match evaluate(&rs, &inp) {
        RewriteOutcome::Redirect { code, location, .. } => {
            assert_eq!(code, 301);
            assert_eq!(location, "https://moon.example/moon/paris");
        }
        other => panic!("expected redirect, got {other:?}"),
    }
}

#[test]
fn or_chained_conditions() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} Googlebot [OR]\nRewriteCond %{HTTP_USER_AGENT} Bingbot\nRewriteRule .* - [E=KNOWN_CRAWLER:1]",
    )
    .unwrap();
    // Googlebot matches first cond.
    let mut g = input("/");
    g.headers
        .insert("User-Agent".into(), "Mozilla Googlebot/2.1".into());
    assert_eq!(
        evaluate(&rs, &g).env(),
        &[("KNOWN_CRAWLER".into(), "1".into())]
    );
    // Bingbot matches second cond.
    let mut b = input("/");
    b.headers.insert("User-Agent".into(), "Bingbot/2.0".into());
    assert_eq!(
        evaluate(&rs, &b).env(),
        &[("KNOWN_CRAWLER".into(), "1".into())]
    );
    // Neither -> no env.
    let mut o = input("/");
    o.headers.insert("User-Agent".into(), "curl/8".into());
    assert!(evaluate(&rs, &o).env().is_empty());
}

#[test]
fn or_conds_folded_into_one_alternation() {
    // A same-variable OR run of group-free regexes folds to a single cond
    // (28-line crawler block -> 1 regex), with behavior preserved.
    let rs = RuleSet::parse(
        "RewriteEngine On\n\
         RewriteCond %{HTTP_USER_AGENT} Googlebot [OR]\n\
         RewriteCond %{HTTP_USER_AGENT} Bingbot [OR]\n\
         RewriteCond %{HTTP_USER_AGENT} DuckDuckBot\n\
         RewriteRule .* - [E=KNOWN_CRAWLER:1]",
    )
    .unwrap();
    assert_eq!(
        rs.rules[0].conds.len(),
        1,
        "3 same-var OR conds fold to 1 alternation"
    );

    // Any alternative still matches; an unmatched UA still does not.
    for ua in ["x Googlebot/2", "y Bingbot/2", "z DuckDuckBot/1"] {
        let mut g = input("/");
        g.headers.insert("User-Agent".into(), ua.into());
        assert_eq!(
            evaluate(&rs, &g).env(),
            &[("KNOWN_CRAWLER".into(), "1".into())],
            "{ua} should match the folded alternation"
        );
    }
    let mut o = input("/");
    o.headers.insert("User-Agent".into(), "curl/8".into());
    assert!(evaluate(&rs, &o).env().is_empty(), "non-bot must not match");
}

#[test]
fn dangling_trailing_or_does_not_fire_rule() {
    // A malformed config: the only RewriteCond carries a trailing `[OR]` with no second
    // member. Apache keeps the (sole) condition required; the rule must NOT fire when it
    // fails. Previously the dangling `[OR]` made the cond non-gating, firing the rule for
    // every request (a deny-all / mis-fire).
    let rs = RuleSet::parse(
        "RewriteEngine On\n\
         RewriteCond %{HTTP_USER_AGENT} ^BadBot [OR]\n\
         RewriteRule .* - [E=BLOCKED:1]",
    )
    .unwrap();
    assert_eq!(
        rs.rules[0].conds.len(),
        1,
        "lone trailing [OR] cond is kept"
    );

    // The condition matches -> the rule fires.
    let mut bad = input("/");
    bad.headers.insert("User-Agent".into(), "BadBot/1.0".into());
    assert_eq!(evaluate(&rs, &bad).env(), &[("BLOCKED".into(), "1".into())]);

    // The condition does NOT match -> the rule must NOT fire (the bug fired it anyway).
    let mut ok = input("/");
    ok.headers.insert("User-Agent".into(), "Mozilla/5.0".into());
    assert!(
        evaluate(&rs, &ok).env().is_empty(),
        "a failing sole cond with a dangling [OR] must still gate the rule"
    );
}

#[test]
fn or_conds_not_folded_when_unsafe() {
    // Mixed variables -> not folded (different inputs can't share an alternation).
    let rs = RuleSet::parse(
        "RewriteEngine On\n\
         RewriteCond %{HTTP_USER_AGENT} Bot [OR]\n\
         RewriteCond %{HTTP_HOST} ^x [OR]\n\
         RewriteCond %{HTTP_USER_AGENT} Spider\n\
         RewriteRule .* - [E=K:1]",
    )
    .unwrap();
    assert_eq!(
        rs.rules[0].conds.len(),
        3,
        "mixed-variable OR group not folded"
    );

    // A negated member blocks folding (Bot OR !Spider != (Bot|Spider)).
    let rs2 = RuleSet::parse(
        "RewriteEngine On\n\
         RewriteCond %{HTTP_USER_AGENT} Bot [OR]\n\
         RewriteCond %{HTTP_USER_AGENT} !Spider\n\
         RewriteRule .* - [E=K:1]",
    )
    .unwrap();
    assert_eq!(rs2.rules[0].conds.len(), 2, "negated member blocks folding");

    // A capturing group blocks folding (preserve %N numbering).
    let rs3 = RuleSet::parse(
        "RewriteEngine On\n\
         RewriteCond %{HTTP_USER_AGENT} (Bot) [OR]\n\
         RewriteCond %{HTTP_USER_AGENT} Spider\n\
         RewriteRule .* - [E=K:1]",
    )
    .unwrap();
    assert_eq!(
        rs3.rules[0].conds.len(),
        2,
        "capturing-group member blocks folding"
    );

    // Plain AND conds (no OR) are never folded.
    let rs4 = RuleSet::parse(
        "RewriteEngine On\n\
         RewriteCond %{HTTP_USER_AGENT} Bot\n\
         RewriteCond %{HTTP_USER_AGENT} Spider\n\
         RewriteRule .* - [E=K:1]",
    )
    .unwrap();
    assert_eq!(rs4.rules[0].conds.len(), 2, "AND conds not folded");
}

#[test]
fn cond_backref_percent_one() {
    // /web/news trailing-slash normalization uses %1 from the cond capture.
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{REQUEST_URI} (.+)/$\nRewriteRule ^ %1 [R=301,L]",
    )
    .unwrap();
    let inp = input("/threads/foo/");
    match evaluate(&rs, &inp) {
        RewriteOutcome::Redirect { location, .. } => assert_eq!(location, "/threads/foo"),
        other => panic!("expected redirect, got {other:?}"),
    }
}

#[test]
fn negated_cond() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{REQUEST_URI} !^/beta/\nRewriteRule ^index\\.(html|php)$ / [R=301,L]",
    )
    .unwrap();
    // /beta/index.php is exempt (pattern matches stripped path but cond fails).
    let out = evaluate(&rs, &input("/beta/index.php"));
    assert!(matches!(out, RewriteOutcome::Unchanged { .. }));
    match evaluate(&rs, &input("/index.php")) {
        RewriteOutcome::Redirect { location, .. } => assert_eq!(location, "/"),
        other => panic!("expected redirect, got {other:?}"),
    }
}

#[test]
fn file_test_precomputed() {
    // XenForo: if file/dir exists, stop (serve it).
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} -f [OR]\nRewriteCond %{REQUEST_FILENAME} -d\nRewriteRule ^.*$ - [NC,L]\nRewriteRule ^.*$ index.php [NC,L]",
    )
    .unwrap();
    // Existing file -> first rule matches, [L], no rewrite.
    let exists = input("/styles/x.css").file_tests(FileTests {
        is_file: true,
        ..Default::default()
    });
    assert!(matches!(
        evaluate(&rs, &exists),
        RewriteOutcome::Unchanged { .. }
    ));
    // Non-existent -> falls to index.php.
    let missing = input("/threads/foo.123").file_tests(FileTests::default());
    match evaluate(&rs, &missing) {
        RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/index.php"),
        other => panic!("expected rewrite to index.php, got {other:?}"),
    }
}

#[test]
fn lexical_comparison() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{HTTP_HOST} =evil.example.com\nRewriteRule ^(.*)$ - [F]",
    )
    .unwrap();
    let mut inp = input("/x");
    inp.host = "evil.example.com".into();
    assert!(matches!(
        evaluate(&rs, &inp),
        RewriteOutcome::Forbidden { .. }
    ));
    let mut ok = input("/x");
    ok.host = "good.example.com".into();
    assert!(matches!(
        evaluate(&rs, &ok),
        RewriteOutcome::Unchanged { .. }
    ));
}

#[test]
fn the_request_variable() {
    let _rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{THE_REQUEST} \\sPOST\\s\nRewriteRule .* - [E=ISPOST:1]",
    )
    .unwrap();
    let mut inp = input("/api").method("POST");
    inp.query = "a=1".into();
    // THE_REQUEST = "POST /api?a=1 HTTP/1.1" — but \s won't match a leading
    // boundary, so build the cond around the method token spacing instead.
    let _ = &mut inp;
    // Use a simpler cond verifying THE_REQUEST contains the method+space.
    let rs2 = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{THE_REQUEST} ^POST\\s\nRewriteRule .* - [E=ISPOST:1]",
    )
    .unwrap();
    assert_eq!(evaluate(&rs2, &inp).env(), &[("ISPOST".into(), "1".into())]);
}

#[test]
fn env_var_lookup_in_cond() {
    // mirrors the LSCache REDIRECT_STATUS cond.
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteCond %{ENV:REDIRECT_STATUS} ^(403|5)\nRewriteRule .* - [E=no-cache:1]",
    )
    .unwrap();
    let mut inp = input("/x");
    inp.env = BTreeMap::from([("REDIRECT_STATUS".to_string(), "503".to_string())]);
    assert_eq!(
        evaluate(&rs, &inp).env(),
        &[("no-cache".into(), "1".into())]
    );
}

#[test]
fn env_overlay_shadows_seed_and_falls_through() {
    // Stage-1 invariant: EvalState.env is an empty [E=] OVERLAY; reads fall through
    // to the seed (input.env). An [E=] write must SHADOW a same-named seed value
    // (last-writer-wins), and both %{ENV:NAME} and the bare %{NAME} fallthrough must
    // read the seed when the overlay has no entry. This pins behavior identical to
    // the old "clone seed then insert [E=] on top" map.
    let rs = RuleSet::parse(concat!(
        "RewriteEngine On\n",
        // (1) bare %{NAME} reads the seed
        "RewriteCond %{SEEDVAR} ^fromseed$\n",
        "RewriteRule .* - [E=GOTSEED:1]\n",
        // (2) %{ENV:NAME} reads the seed
        "RewriteCond %{ENV:SEEDVAR} ^fromseed$\n",
        "RewriteRule .* - [E=GOTENVSEED:1]\n",
        // (3) write into the overlay, then a later cond must read the OVERLAY value
        //     (newval), NOT the seed value (seedval) -> overlay shadows seed.
        "RewriteRule .* - [E=SHADOWED:newval]\n",
        "RewriteCond %{ENV:SHADOWED} ^newval$\n",
        "RewriteRule .* - [E=GOTSHADOW:1]\n",
    ))
    .unwrap();
    let mut inp = input("/x");
    inp.env = BTreeMap::from([
        ("SEEDVAR".to_string(), "fromseed".to_string()),
        ("SHADOWED".to_string(), "seedval".to_string()),
    ]);
    let env = evaluate(&rs, &inp).env().to_vec();
    assert!(
        env.contains(&("GOTSEED".into(), "1".into())),
        "bare %{{NAME}} must read seed: {env:?}"
    );
    assert!(
        env.contains(&("GOTENVSEED".into(), "1".into())),
        "%{{ENV:NAME}} must read seed: {env:?}"
    );
    assert!(
        env.contains(&("SHADOWED".into(), "newval".into())),
        "overlay [E=] must win: {env:?}"
    );
    assert!(
        env.contains(&("GOTSHADOW".into(), "1".into())),
        "cond must read overlay (newval), not seed (seedval): {env:?}"
    );
}

#[test]
fn env_seed_borrow_resolves_identically_to_owned_env() {
    // The hot path borrows ctx.env via `env_seed` (a slice) instead of cloning it into the owned
    // `env` map. This pins that the borrowed-seed read path is byte-identical to the owned path:
    // bare %{NAME} and %{ENV:NAME} both read the seed, and an [E=] overlay write still SHADOWS a
    // same-named seed entry (last-writer-wins). Mirror of env_overlay_shadows_seed_and_falls_through.
    let rs = RuleSet::parse(concat!(
        "RewriteEngine On\n",
        "RewriteCond %{SEEDVAR} ^fromseed$\n",
        "RewriteRule .* - [E=GOTSEED:1]\n",
        "RewriteCond %{ENV:SEEDVAR} ^fromseed$\n",
        "RewriteRule .* - [E=GOTENVSEED:1]\n",
        "RewriteRule .* - [E=SHADOWED:newval]\n",
        "RewriteCond %{ENV:SHADOWED} ^newval$\n",
        "RewriteRule .* - [E=GOTSHADOW:1]\n",
    ))
    .unwrap();
    // The seed slice must outlive `inp` (declared first, dropped last).
    let seed = vec![
        ("SEEDVAR".to_string(), "fromseed".to_string()),
        ("SHADOWED".to_string(), "seedval".to_string()),
    ];
    let mut inp = input("/x");
    inp.env_seed = Some(&seed);
    let env = evaluate(&rs, &inp).env().to_vec();
    assert!(
        env.contains(&("GOTSEED".into(), "1".into())),
        "bare %{{NAME}} must read borrowed seed: {env:?}"
    );
    assert!(
        env.contains(&("GOTENVSEED".into(), "1".into())),
        "%{{ENV:NAME}} must read borrowed seed: {env:?}"
    );
    assert!(
        env.contains(&("SHADOWED".into(), "newval".into())),
        "overlay [E=] must win over seed: {env:?}"
    );
    assert!(
        env.contains(&("GOTSHADOW".into(), "1".into())),
        "cond must read overlay (newval), not borrowed seed (seedval): {env:?}"
    );
}

// ---------------------------------------------------------------------------
// Iteration loop + restart
// ---------------------------------------------------------------------------

#[test]
fn restart_on_uri_change() {
    // First rule rewrites /a -> /b (no [L]); second rewrites /b -> /c.
    let rs =
        RuleSet::parse("RewriteEngine On\nRewriteRule ^a$ /b\nRewriteRule ^b$ /c [L]").unwrap();
    match evaluate(&rs, &input("/a")) {
        RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/c"),
        other => panic!("expected rewrite to /c, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Apache-correct semantic fixes:
//   1. [R=200] (non-3xx [R=NNN]) -> Status, no Location/body (not Redirect)
//   2. substitution percent-encoding + [NE] honoring
//   3. [END] stops the restart loop (and signals cross-ruleset stop)
//   4. path-only [R] target fully-qualified to an absolute URL
//   5. expanded %{...} variables (REMOTE_ADDR, SERVER_NAME, SERVER_ADDR, ...)
// ---------------------------------------------------------------------------

mod semantics {
    use super::*;

    // --- 1. [R=200] non-3xx redirect codes -------------------------------

    /// The live `/web/news` CORS preflight rule: `- [R=200,L,E=CORS_PREFLIGHT:1]`.
    /// Apache sets status 200 and STOPS; it does NOT emit a Location header or a
    /// "document has moved" body. We model that as the `Status` outcome.
    #[test]
    fn r200_options_preflight_is_status_not_redirect() {
        let rs = RuleSet::parse(
            "RewriteEngine On\nRewriteCond %{REQUEST_METHOD} OPTIONS\nRewriteRule ^(.*)$ - [R=200,L,E=CORS_PREFLIGHT:1]",
        )
        .unwrap();
        let inp = input("/api/data").method("OPTIONS");
        match evaluate(&rs, &inp) {
            RewriteOutcome::Status {
                code,
                suppress_body,
                env,
            } => {
                assert_eq!(code, 200);
                assert!(suppress_body, "no body for a `-` [R=200] rule");
                assert!(env.contains(&("CORS_PREFLIGHT".into(), "1".into())));
            }
            other => panic!("expected Status(200), got {other:?}"),
        }
    }

    /// `^(.*)$ $1 [R=200,L]` — even with a non-`-` substitution, a non-3xx R
    /// produces a bare Status (no Location), NOT a Redirect to `$1`.
    #[test]
    fn r200_with_subst_still_status_no_location() {
        let rs = RuleSet::parse(
            "RewriteEngine On\nRewriteCond %{REQUEST_METHOD} OPTIONS\nRewriteRule ^(.*)$ $1 [R=200,L]",
        )
        .unwrap();
        let inp = input("/whatever").method("OPTIONS");
        match evaluate(&rs, &inp) {
            RewriteOutcome::Status { code, .. } => assert_eq!(code, 200),
            other => panic!("expected Status(200), got {other:?}"),
        }
    }

    /// A 4xx `[R=410]`-style status is also a bare Status, not a Redirect.
    #[test]
    fn r404_is_status_not_redirect() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^gone$ - [R=404,L]").unwrap();
        match evaluate(&rs, &input("/gone")) {
            RewriteOutcome::Status { code, .. } => assert_eq!(code, 404),
            other => panic!("expected Status(404), got {other:?}"),
        }
    }

    /// A genuine 3xx `[R=301]` still produces a `Redirect` with a Location.
    #[test]
    fn r301_remains_redirect_with_location() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^old$ /new [R=301,L]").unwrap();
        match evaluate(&rs, &input("/old")) {
            RewriteOutcome::Redirect { code, location, .. } => {
                assert_eq!(code, 301);
                assert_eq!(location, "/new");
            }
            other => panic!("expected Redirect(301), got {other:?}"),
        }
    }

    // --- 2. substitution percent-encoding + [NE] -------------------------

    /// By default Apache percent-encodes the substitution: a space becomes
    /// `%20`. The reserved path delimiters (`/`) survive.
    #[test]
    fn default_encodes_space_in_substitution() {
        // A space-containing substitution must be quoted in the source (Apache
        // tokenizes on whitespace too). The space is then percent-encoded.
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^s$ \"/a b/c\" [L]").unwrap();
        match evaluate(&rs, &input("/s")) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/a%20b/c"),
            other => panic!("expected encoded rewrite, got {other:?}"),
        }
    }

    /// `[NE]` disables the default encoding — the space is emitted verbatim.
    #[test]
    fn ne_flag_disables_encoding() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^s$ \"/a b/c\" [L,NE]").unwrap();
        match evaluate(&rs, &input("/s")) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/a b/c"),
            other => panic!("expected verbatim rewrite, got {other:?}"),
        }
    }

    /// An already-`%XX`-escaped sequence carried into the substitution via a
    /// backref is NOT double-encoded (the `%` of `%20` is preserved, not turned
    /// into `%2520`). We feed `%20` through `$1` since a literal `%2` in the
    /// substitution source is otherwise consumed as a `%N` cond backref.
    #[test]
    fn no_double_encoding_of_existing_escape() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^(a%20b)$ /x/$1 [L]").unwrap();
        match evaluate(&rs, &input("/a%20b")) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/x/a%20b"),
            other => panic!("expected single-encoded rewrite, got {other:?}"),
        }
    }

    /// Default encoding also applies to a 3xx redirect Location's path, and
    /// `[NE]` disables it. Verified via an empty-host redirect so the path is
    /// not fully-qualified (keeps the assertion focused on encoding).
    #[test]
    fn redirect_location_default_encodes_space() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^s$ \"/a b\" [R=302,L]").unwrap();
        match evaluate(&rs, &input("/s")) {
            RewriteOutcome::Redirect { location, .. } => assert_eq!(location, "/a%20b"),
            other => panic!("expected encoded redirect, got {other:?}"),
        }
        let rs_ne =
            RuleSet::parse("RewriteEngine On\nRewriteRule ^s$ \"/a b\" [R=302,L,NE]").unwrap();
        match evaluate(&rs_ne, &input("/s")) {
            RewriteOutcome::Redirect { location, .. } => assert_eq!(location, "/a b"),
            other => panic!("expected verbatim redirect, got {other:?}"),
        }
    }

    // --- 3. [END] stops the restart loop AND signals cross-ruleset stop --

    /// `[END]` on a rewriting rule stops the outer restart-on-URI-change loop:
    /// a *following* rule that would otherwise re-fire against the rewritten
    /// URI must NOT run. With plain `[L]` the engine restarts and the second
    /// rule fires; `[END]` prevents that.
    #[test]
    fn end_stops_restart_loop() {
        // [L] variant: /a -> /b (pass ends), restart, ^b$ matches -> /c.
        let with_l =
            RuleSet::parse("RewriteEngine On\nRewriteRule ^a$ /b [L]\nRewriteRule ^b$ /c [L]")
                .unwrap();
        match evaluate(&with_l, &input("/a")) {
            RewriteOutcome::Rewritten { new_uri, end, .. } => {
                assert_eq!(new_uri, "/c", "[L] should restart and reach /c");
                assert!(!end);
            }
            other => panic!("expected /c, got {other:?}"),
        }
        // [END] variant: /a -> /b and STOP; the ^b$ rule never runs.
        let with_end =
            RuleSet::parse("RewriteEngine On\nRewriteRule ^a$ /b [END]\nRewriteRule ^b$ /c [L]")
                .unwrap();
        match evaluate(&with_end, &input("/a")) {
            RewriteOutcome::Rewritten { new_uri, end, .. } => {
                assert_eq!(new_uri, "/b", "[END] must stop before restart reaches /c");
                assert!(end, "[END] must set the cross-ruleset stop flag");
            }
            other => panic!("expected /b, got {other:?}"),
        }
    }

    /// `- [END]` with no URI change still flags `end` (so the pipeline stops all
    /// subsequent `.htaccess`/ruleset processing) via the `Unchanged` outcome.
    #[test]
    fn end_on_unchanged_sets_end_flag() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^keep$ - [END,E=DONE:1]").unwrap();
        let out = evaluate(&rs, &input("/keep"));
        assert!(out.is_end(), "is_end() must be true for `- [END]`");
        match out {
            RewriteOutcome::Unchanged { end, env } => {
                assert!(end);
                assert!(env.contains(&("DONE".into(), "1".into())));
            }
            other => panic!("expected Unchanged{{end:true}}, got {other:?}"),
        }
    }

    /// `[L]` (not `[END]`) leaves `is_end()` false even on a rewrite.
    #[test]
    fn last_does_not_set_end() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^x$ /y [L]").unwrap();
        let out = evaluate(&rs, &input("/x"));
        assert!(!out.is_end());
    }

    // --- 4. path-only [R] fully-qualified --------------------------------

    /// A path-only `[R]` target is fully-qualified to scheme+host from the
    /// request (Apache always sends an absolute Location).
    #[test]
    fn path_only_redirect_is_fully_qualified() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^old$ /new [R=301,L]").unwrap();
        let inp = input("/old").host("example.com").https(true);
        match evaluate(&rs, &inp) {
            RewriteOutcome::Redirect { location, .. } => {
                assert_eq!(location, "https://example.com/new");
            }
            other => panic!("expected fully-qualified redirect, got {other:?}"),
        }
    }

    /// http scheme + non-default port is reflected in the qualified Location.
    #[test]
    fn path_only_redirect_includes_nondefault_port() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^old$ /new [R=302,L]").unwrap();
        let inp = input("/old")
            .host("example.com")
            .https(false)
            .server_port(8080);
        match evaluate(&rs, &inp) {
            RewriteOutcome::Redirect { location, .. } => {
                assert_eq!(location, "http://example.com:8080/new");
            }
            other => panic!("expected port in redirect, got {other:?}"),
        }
    }

    /// A scheme-bearing `[R]` target is left as-is (already absolute).
    #[test]
    fn scheme_redirect_left_absolute() {
        let rs = RuleSet::parse(
            "RewriteEngine On\nRewriteRule ^(.*)$ https://other.example/$1 [R=301,L]",
        )
        .unwrap();
        let inp = input("/p").host("example.com").https(true);
        match evaluate(&rs, &inp) {
            RewriteOutcome::Redirect { location, .. } => {
                assert_eq!(location, "https://other.example/p");
            }
            other => panic!("expected absolute redirect, got {other:?}"),
        }
    }

    // --- 5. expanded %{...} variables ------------------------------------

    #[test]
    fn remote_addr_variable_resolves() {
        let rs = RuleSet::parse(
            "RewriteEngine On\nRewriteCond %{REMOTE_ADDR} ^10\\.\nRewriteRule .* - [E=INTERNAL:1]",
        )
        .unwrap();
        let inp = input("/x").remote_addr("10.0.0.5");
        assert!(
            evaluate(&rs, &inp)
                .env()
                .contains(&("INTERNAL".into(), "1".into()))
        );
        let inp2 = input("/x").remote_addr("8.8.8.8");
        assert!(matches!(
            evaluate(&rs, &inp2),
            RewriteOutcome::Unchanged { .. }
        ));
    }

    #[test]
    fn server_name_addr_port_variables_resolve() {
        let rs = RuleSet::parse(
            "RewriteEngine On\nRewriteRule .* - [E=SN:%{SERVER_NAME},E=SA:%{SERVER_ADDR},E=SP:%{SERVER_PORT},E=RP:%{REMOTE_PORT}]",
        )
        .unwrap();
        let inp = input("/x")
            .server_name("canonical.example")
            .server_addr("192.168.1.10")
            .server_port(8443)
            .remote_port(54321);
        let env = evaluate(&rs, &inp).env().to_vec();
        assert!(env.contains(&("SN".into(), "canonical.example".into())));
        assert!(env.contains(&("SA".into(), "192.168.1.10".into())));
        assert!(env.contains(&("SP".into(), "8443".into())));
        assert!(env.contains(&("RP".into(), "54321".into())));
    }

    /// `%{SERVER_PROTOCOL}` resolves to the request protocol, and `%{THE_REQUEST}`
    /// carries that same version token (no longer a hardcoded HTTP/1.1). When the
    /// protocol is unset it defaults to HTTP/1.1 for backward compatibility.
    #[test]
    fn server_protocol_resolves_and_the_request_uses_it() {
        let rs = RuleSet::parse(
            "RewriteEngine On\nRewriteRule .* - [E=PROTO:%{SERVER_PROTOCOL},E=TR:%{THE_REQUEST}]",
        )
        .unwrap();
        // Explicit HTTP/2.
        let env = evaluate(&rs, &input("/x").protocol("HTTP/2"))
            .env()
            .to_vec();
        assert!(env.contains(&("PROTO".into(), "HTTP/2".into())));
        assert!(
            env.iter().any(|(k, v)| k == "TR" && v.ends_with("HTTP/2")),
            "THE_REQUEST should end with the negotiated protocol, got {env:?}"
        );
        // Default (unset) is HTTP/1.1.
        let env2 = evaluate(&rs, &input("/y")).env().to_vec();
        assert!(env2.contains(&("PROTO".into(), "HTTP/1.1".into())));
    }

    /// %{THE_REQUEST} is the VERBATIM original request line (Apache: not modified by rewriting).
    /// Regression: a non-[L] rewrite that changes the URI earlier in the chain must NOT make a
    /// later %{THE_REQUEST} reflect the rewritten URI (it used the evolving working URI before).
    #[test]
    fn the_request_is_frozen_against_earlier_rewrite() {
        let rs = RuleSet::parse(
            "RewriteEngine On\nRewriteRule ^old$ /new\nRewriteRule .* - [E=TR:%{THE_REQUEST}]",
        )
        .unwrap();
        let env = evaluate(&rs, &input("/old")).env().to_vec();
        let tr = env
            .iter()
            .find(|(k, _)| k == "TR")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert!(
            tr.contains("/old"),
            "THE_REQUEST must show the original /old, got {tr:?}"
        );
        assert!(
            !tr.contains("new"),
            "THE_REQUEST must NOT reflect the rewritten /new, got {tr:?}"
        );
    }

    /// SERVER_NAME falls back to the Host header when no canonical name is set,
    /// and SERVER_PORT defaults from the TLS flag when unset.
    #[test]
    fn server_name_falls_back_to_host_and_port_defaults() {
        let rs = RuleSet::parse(
            "RewriteEngine On\nRewriteRule .* - [E=SN:%{SERVER_NAME},E=SP:%{SERVER_PORT}]",
        )
        .unwrap();
        let inp = input("/x").host("fromhost.example").https(true);
        let env = evaluate(&rs, &inp).env().to_vec();
        assert!(env.contains(&("SN".into(), "fromhost.example".into())));
        assert!(env.contains(&("SP".into(), "443".into())));
    }

    /// Genuinely-unavailable variables (TIME, LA-U) resolve to empty string.
    #[test]
    fn unavailable_variables_resolve_empty() {
        let rs = RuleSet::parse(
            "RewriteEngine On\nRewriteRule .* - [E=T:[%{TIME_YEAR}],E=U:[%{LA-U:REQUEST_FILENAME}]]",
        )
        .unwrap();
        let env = evaluate(&rs, &input("/x")).env().to_vec();
        assert!(env.contains(&("T".into(), "[]".into())));
        assert!(env.contains(&("U".into(), "[]".into())));
    }
}

// ---------------------------------------------------------------------------
// OLS-parity fixes: flag handling [G],[S=n],[C],[N],[QSD]; OR short-circuit;
// %N per-rule reset; numeric and >=/<= comparisons.
// ---------------------------------------------------------------------------

mod ols_parity {
    use super::*;

    /// `[G]` -> 410 Gone, terminal (OLS rewriterule.cpp:927-936 sets
    /// RULE_ACTION_GONE, SC_410, RULE_FLAG_LAST).
    #[test]
    fn gone_flag_yields_410() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^old/.*$ - [G]").unwrap();
        match evaluate(&rs, &input("/old/page")) {
            RewriteOutcome::Gone { .. } => {}
            other => panic!("expected Gone (410), got {other:?}"),
        }
        // Non-matching path is untouched.
        assert!(matches!(
            evaluate(&rs, &input("/new/page")),
            RewriteOutcome::Unchanged { .. }
        ));
    }

    /// `[S=n]` skips the next n rules on a successful match
    /// (OLS rewriteengine.cpp:1534-1543 advances by skip+1).
    #[test]
    fn skip_flag_skips_following_rules() {
        // If the first rule matches, skip the next 2 rules (the 410 + the
        // generic rewrite) and fall to the final pass-through.
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteRule ^keep/(.*)$ - [S=2]\n\
             RewriteRule ^keep/(.*)$ - [G]\n\
             RewriteRule ^keep/(.*)$ /blocked\n\
             RewriteRule ^keep/(.*)$ /final.php?p=$1 [L]",
        )
        .unwrap();
        match evaluate(&rs, &input("/keep/abc")) {
            RewriteOutcome::Rewritten {
                new_uri, new_query, ..
            } => {
                assert_eq!(new_uri, "/final.php");
                assert_eq!(new_query.as_deref(), Some("p=abc"));
            }
            other => panic!("expected skip past G/blocked to /final.php, got {other:?}"),
        }
    }

    /// `[C]`/chain: when a chained rule FAILS to match, the rule(s) chained to
    /// it are skipped (OLS rewriteengine.cpp:1486-1496).
    #[test]
    fn chain_skips_dependent_rule_on_failure() {
        // Rule 1 (chained) only matches /a; rule 2 is its chained continuation
        // that would forbid. For /b, rule1 fails so rule2 must be skipped, and
        // we fall through to rule 3.
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteRule ^a$ - [C]\n\
             RewriteRule ^.*$ - [F]\n\
             RewriteRule ^b$ /handled.php [L]",
        )
        .unwrap();
        // /b: rule1 (^a$) fails -> chained rule2 ([F]) is skipped -> rule3 hits.
        match evaluate(&rs, &input("/b")) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/handled.php"),
            other => panic!("expected /handled.php (chain skipped F), got {other:?}"),
        }
        // /a: rule1 matches -> rule2 ([F]) runs -> Forbidden.
        assert!(matches!(
            evaluate(&rs, &input("/a")),
            RewriteOutcome::Forbidden { .. }
        ));
    }

    /// `[N]`/next restarts the rule set from the top.
    #[test]
    fn next_flag_restarts_from_top() {
        // First rule strips one leading "x/" then [N] restarts; it keeps
        // stripping until none remain, then a guarded route fires once. The
        // route's pattern (`^leaf$`) is written so it cannot re-match its own
        // output (avoids the catch-all-feedback that a `^(.*)$` would create).
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteRule ^x/(.*)$ /$1 [N]\n\
             RewriteRule ^leaf$ /done.php?p=leaf [L]",
        )
        .unwrap();
        match evaluate(&rs, &input("/x/x/x/leaf")) {
            RewriteOutcome::Rewritten {
                new_uri, new_query, ..
            } => {
                assert_eq!(new_uri, "/done.php");
                assert_eq!(new_query.as_deref(), Some("p=leaf"));
            }
            other => panic!("expected repeated strip then /done.php, got {other:?}"),
        }
    }

    /// `[N]` infinite-loop guard: an always-restarting rule must terminate
    /// rather than spin forever (OLS aborts after 10 loops).
    #[test]
    fn next_flag_loop_guard_terminates() {
        let rs = RuleSet::parse("RewriteEngine On\nRewriteRule ^(.*)$ /$1 [N]").unwrap();
        // Must return (not hang). The URI is unchanged ("/x" -> "/x").
        let out = evaluate(&rs, &input("/x"));
        let _ = out; // any terminating outcome is acceptable.
    }

    /// OR short-circuit: once an early `[OR]` cond passes, later members of the
    /// group are NOT evaluated, so `%N` comes from the FIRST passing cond
    /// (OLS rewriteengine.cpp:900-904).
    #[test]
    fn or_group_percent_n_from_first_passing_cond() {
        // Two OR-linked regex conds both could match THE_REQUEST; the first
        // captures "FIRST", the second would capture "SECOND". Because the
        // first passes, %1 must be "alpha" (from cond 1), not "beta".
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{HTTP_HOST} ^(alpha)\\. [OR]\n\
             RewriteCond %{HTTP_HOST} (beta)$\n\
             RewriteRule ^(.*)$ /tag.php?who=%1 [L]",
        )
        .unwrap();
        let mut inp = input("/page");
        // Host matches BOTH conds; first should win.
        inp.host = "alpha.beta".into();
        match evaluate(&rs, &inp) {
            RewriteOutcome::Rewritten { new_query, .. } => {
                assert_eq!(new_query.as_deref(), Some("who=alpha"));
            }
            other => panic!("expected who=alpha (first cond), got {other:?}"),
        }
    }

    /// `%N` is reset per rule: a rule that references `%1` without a matching
    /// regex cond gets an empty value, not the previous rule's captures
    /// (OLS resets m_condMatches=0 per rule, rewriteengine.cpp:889).
    #[test]
    fn percent_n_reset_between_rules() {
        // Rule 1 captures %1="cap" but does NOT rewrite ([E] only). Rule 2 has
        // no cond and references %1 in its substitution: it must expand to
        // empty, not "cap".
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{HTTP_HOST} ^(cap)\\.example$\n\
             RewriteRule ^never-matches$ - [E=X:1]\n\
             RewriteRule ^(.*)$ /out.php?leftover=[%1] [L]",
        )
        .unwrap();
        let mut inp = input("/page");
        inp.host = "cap.example".into();
        match evaluate(&rs, &inp) {
            RewriteOutcome::Rewritten { new_query, .. } => {
                // %1 from rule1's cond must NOT leak into rule2.
                assert_eq!(new_query.as_deref(), Some("leftover=[]"));
            }
            other => panic!("expected empty %1 leftover, got {other:?}"),
        }
    }

    /// Numeric comparisons `-gt`/`-lt`/`-eq` parse the leading integer like
    /// strtoll (OLS rewriteengine.cpp:762-793).
    #[test]
    fn numeric_comparison_gt() {
        // OLS parseNextArg is whitespace-delimited, so the operator+operand
        // form is a single unspaced token: `-gt5` (or quoted `"-gt 5"`).
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{ENV:COUNT} -gt5\n\
             RewriteRule ^(.*)$ - [F]",
        )
        .unwrap();
        let mut hi = input("/x");
        hi.env = BTreeMap::from([("COUNT".to_string(), "10".to_string())]);
        assert!(matches!(
            evaluate(&rs, &hi),
            RewriteOutcome::Forbidden { .. }
        ));
        let mut lo = input("/x");
        lo.env = BTreeMap::from([("COUNT".to_string(), "3".to_string())]);
        assert!(matches!(
            evaluate(&rs, &lo),
            RewriteOutcome::Unchanged { .. }
        ));
        // Non-numeric test string -> strtoll yields 0, so 0 -gt 5 is false.
        let mut junk = input("/x");
        junk.env = BTreeMap::from([("COUNT".to_string(), "abc".to_string())]);
        assert!(matches!(
            evaluate(&rs, &junk),
            RewriteOutcome::Unchanged { .. }
        ));
    }

    #[test]
    fn numeric_comparison_eq_and_lt() {
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{ENV:N} -eq42\n\
             RewriteRule ^(.*)$ /matched.php [L]",
        )
        .unwrap();
        let mut inp = input("/x");
        inp.env = BTreeMap::from([("N".to_string(), "42".to_string())]);
        match evaluate(&rs, &inp) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/matched.php"),
            other => panic!("expected -eq match, got {other:?}"),
        }

        let rs_lt = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{ENV:N} -lt0\n\
             RewriteRule ^(.*)$ - [F]",
        )
        .unwrap();
        let mut neg = input("/x");
        neg.env = BTreeMap::from([("N".to_string(), "-7".to_string())]);
        assert!(matches!(
            evaluate(&rs_lt, &neg),
            RewriteOutcome::Forbidden { .. }
        ));
    }

    /// Lexical `>=` / `<=` comparisons (OLS COND_OP_GE / COND_OP_LE).
    #[test]
    fn lexical_ge_le_comparisons() {
        // %{HTTP_HOST} >= "m" forbids hosts lexically >= "m".
        let ge = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{HTTP_HOST} >=m\n\
             RewriteRule ^(.*)$ - [F]",
        )
        .unwrap();
        let mut z = input("/x");
        z.host = "zebra.com".into();
        assert!(matches!(
            evaluate(&ge, &z),
            RewriteOutcome::Forbidden { .. }
        ));
        let mut a = input("/x");
        a.host = "apple.com".into();
        assert!(matches!(
            evaluate(&ge, &a),
            RewriteOutcome::Unchanged { .. }
        ));

        // Boundary: exactly equal passes >= .
        let le = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{ENV:V} <=mango\n\
             RewriteRule ^(.*)$ - [F]",
        )
        .unwrap();
        let mut eq = input("/x");
        eq.env = BTreeMap::from([("V".to_string(), "mango".to_string())]);
        assert!(matches!(
            evaluate(&le, &eq),
            RewriteOutcome::Forbidden { .. }
        ));
    }

    /// `[NC]` applies to lexical comparisons (OLS uses strcasecmp).
    #[test]
    fn lexical_equal_nocase() {
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{HTTP_HOST} =EVIL.example.com [NC]\n\
             RewriteRule ^(.*)$ - [F]",
        )
        .unwrap();
        let mut inp = input("/x");
        inp.host = "evil.example.com".into();
        assert!(matches!(
            evaluate(&rs, &inp),
            RewriteOutcome::Forbidden { .. }
        ));
    }

    /// `[QSD]` discards the original query on an internal rewrite.
    #[test]
    fn qsd_discards_query() {
        let rs =
            RuleSet::parse("RewriteEngine On\nRewriteRule ^p/(.*)$ /serve.php [QSD,L]").unwrap();
        let mut inp = input("/p/article");
        inp.query = "utm_source=x&id=5".into();
        match evaluate(&rs, &inp) {
            RewriteOutcome::Rewritten {
                new_uri, new_query, ..
            } => {
                assert_eq!(new_uri, "/serve.php");
                assert_eq!(new_query, None, "QSD must drop the original query");
            }
            other => panic!("expected QSD-stripped rewrite, got {other:?}"),
        }
    }

    /// `[QSD]` on a redirect drops the query in the Location.
    #[test]
    fn qsd_discards_query_on_redirect() {
        let rs =
            RuleSet::parse("RewriteEngine On\nRewriteRule ^p/(.*)$ /go [R=301,QSD,L]").unwrap();
        let mut inp = input("/p/x");
        inp.query = "tracking=1".into();
        match evaluate(&rs, &inp) {
            RewriteOutcome::Redirect { location, .. } => assert_eq!(location, "/go"),
            other => panic!("expected QSD redirect with no query, got {other:?}"),
        }
    }

    /// `[PT]`/passthrough sets `last` (stops the pass) without producing a
    /// Proxy outcome (OLS rewriterule.cpp:990-999).
    #[test]
    fn passthrough_is_last_not_proxy() {
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteRule ^a$ /b.php [PT]\n\
             RewriteRule ^b\\.php$ /c.php [L]",
        )
        .unwrap();
        // [PT] is last -> stops the pass after rewriting to /b.php; since the
        // URI changed, the engine restarts and /b.php -> /c.php.
        match evaluate(&rs, &input("/a")) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/c.php"),
            other => panic!("expected /c.php, got {other:?}"),
        }
    }
}

// ===========================================================================
// GOLDEN TESTS — real rules from live files
// ===========================================================================

mod golden {
    use super::*;

    /// XenForo front controller (verbatim core from /web/public_html/.htaccess).
    const XENFORO: &str = r#"
RewriteEngine On

RewriteCond %{REQUEST_URI} ^/web/public_html/(.*)$ [NC]
RewriteRule ^web/public_html/(.*)$ /$1 [R=301,L]

RewriteRule ^compression(/.*)?$ /admin/compression$1 [R=301,L]
RewriteRule ^pages/Builds(.*)$ /builds$1 [R=301,L]
RewriteRule ^sitemap-news\.xml$ /sitemap-news.php [L]

RewriteCond %{HTTP_USER_AGENT} Googlebot [OR]
RewriteCond %{HTTP_USER_AGENT} Bingbot [OR]
RewriteCond %{HTTP_USER_AGENT} DuckDuckBot
RewriteRule .* - [E=KNOWN_CRAWLER:1]

RewriteCond %{REQUEST_FILENAME} -f [OR]
RewriteCond %{REQUEST_FILENAME} -l [OR]
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^.*$ - [NC,L]
RewriteRule ^(data/|js/|styles/|install/|favicon\.ico|crossdomain\.xml|robots\.txt) - [NC,L]

RewriteRule ^.*$ index.php [NC,L]
"#;

    #[test]
    fn xenforo_unknown_thread_routes_to_index() {
        let rs = RuleSet::parse(XENFORO).unwrap();
        let inp = input("/threads/some-thread.12345").file_tests(FileTests::default());
        match evaluate(&rs, &inp) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/index.php"),
            other => panic!("expected index.php, got {other:?}"),
        }
    }

    #[test]
    fn xenforo_existing_static_file_served_directly() {
        let rs = RuleSet::parse(XENFORO).unwrap();
        // file exists on disk -> the -f cond + [L] stops, no rewrite.
        let inp = input("/styles/public/logo.png").file_tests(FileTests {
            is_file: true,
            is_nonempty: true,
            ..Default::default()
        });
        assert!(matches!(
            evaluate(&rs, &inp),
            RewriteOutcome::Unchanged { .. }
        ));
    }

    #[test]
    fn xenforo_pages_builds_redirect() {
        let rs = RuleSet::parse(XENFORO).unwrap();
        let inp = input("/pages/Builds/windows11").file_tests(FileTests::default());
        match evaluate(&rs, &inp) {
            RewriteOutcome::Redirect { code, location, .. } => {
                assert_eq!(code, 301);
                assert_eq!(location, "/builds/windows11");
            }
            other => panic!("expected 301 redirect, got {other:?}"),
        }
    }

    #[test]
    fn xenforo_bot_tagging_sets_env_then_routes() {
        let rs = RuleSet::parse(XENFORO).unwrap();
        let mut inp = input("/threads/foo.1").file_tests(FileTests::default());
        inp.headers
            .insert("User-Agent".into(), "Mozilla Googlebot/2.1".into());
        let out = evaluate(&rs, &inp);
        assert!(out.env().contains(&("KNOWN_CRAWLER".into(), "1".into())));
        match out {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/index.php"),
            other => panic!("expected index.php, got {other:?}"),
        }
    }

    #[test]
    fn xenforo_sitemap_news_internal_rewrite() {
        // `^sitemap-news\.xml$ -> /sitemap-news.php [L]`. After the [L] rewrite,
        // the engine re-runs; the existence check (-f) on sitemap-news.php must
        // stop the loop before the catch-all `index.php`. Reflect reality with a
        // stat closure that reports `.php` files as present.
        let rs = RuleSet::parse(XENFORO).unwrap();
        let php_exists = |p: &std::path::Path| -> Option<std::fs::Metadata> {
            if p.extension().and_then(|e| e.to_str()) == Some("php") {
                std::fs::metadata("/etc/hostname").ok() // any real file -> is_file=true
            } else {
                None
            }
        };
        let mut inp = input("/sitemap-news.xml");
        inp.stat = StatSource::Live(&php_exists);
        match evaluate(&rs, &inp) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/sitemap-news.php"),
            other => panic!("expected internal rewrite, got {other:?}"),
        }
    }

    /// The dotfile-forbidding rule with negative lookahead.
    #[test]
    fn xenforo_dotfile_forbidden_via_lookahead() {
        let rs =
            RuleSet::parse("RewriteEngine On\nRewriteRule \"^\\.(?!htaccess)\" - [F,L]").unwrap();
        assert!(matches!(
            evaluate(&rs, &input("/.git")),
            RewriteOutcome::Forbidden { .. }
        ));
        assert!(matches!(
            evaluate(&rs, &input("/.env")),
            RewriteOutcome::Forbidden { .. }
        ));
        assert!(matches!(
            evaluate(&rs, &input("/.htaccess")),
            RewriteOutcome::Unchanged { .. }
        ));
    }

    /// moontimenow language/moon routing (verbatim core).
    const MOONTIME: &str = r#"
RewriteEngine On

RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

RewriteCond %{HTTP_HOST} ^www\.moon\.example$ [NC]
RewriteRule ^(.*)$ https://moon.example/$1 [L,R=301]

RewriteRule ^moon/?$ location.php [L,QSA]
RewriteRule ^moon/([-a-z0-9]+)/?$ location.php?city=$1 [L,QSA]
RewriteRule ^moon/(-?[\d.]+)/(-?[\d.]+)/?$ location.php?lat=$1&lng=$2 [L,QSA]
RewriteRule ^en/moon(/.*)?$ /moon$1 [L,R=301]
RewriteRule ^([a-z]{2})/moon/?$ location.php?lang=$1 [L,QSA]
RewriteRule ^([a-z]{2})/moon/([-a-z0-9]+)/?$ location.php?lang=$1&city=$2 [L,QSA]

RewriteRule ^langs/ - [F,L]
RewriteRule ^src/ - [F,L]
"#;

    fn moon_input(uri: &str) -> RewriteInput<'static> {
        let mut i = RewriteInput::new(uri.to_string(), "/web/moontimenow");
        i.host = "moon.example".into();
        i.https = true;
        i
    }

    #[test]
    fn moontime_https_force() {
        let rs = RuleSet::parse(MOONTIME).unwrap();
        let mut inp = moon_input("/moon/paris/");
        inp.https = false;
        match evaluate(&rs, &inp) {
            RewriteOutcome::Redirect { code, location, .. } => {
                assert_eq!(code, 301);
                assert_eq!(location, "https://moon.example/moon/paris/");
            }
            other => panic!("expected https redirect, got {other:?}"),
        }
    }

    #[test]
    fn moontime_www_canonical() {
        let rs = RuleSet::parse(MOONTIME).unwrap();
        let mut inp = moon_input("/eclipses");
        inp.host = "www.moon.example".into();
        match evaluate(&rs, &inp) {
            RewriteOutcome::Redirect { code, location, .. } => {
                assert_eq!(code, 301);
                assert_eq!(location, "https://moon.example/eclipses");
            }
            other => panic!("expected www redirect, got {other:?}"),
        }
    }

    #[test]
    fn moontime_lang_moon_route() {
        let rs = RuleSet::parse(MOONTIME).unwrap();
        // ^([a-z]{2})/moon/?$ -> location.php?lang=$1
        match evaluate(&rs, &moon_input("/fr/moon/")) {
            RewriteOutcome::Rewritten {
                new_uri, new_query, ..
            } => {
                assert_eq!(new_uri, "/location.php");
                assert_eq!(new_query.as_deref(), Some("lang=fr"));
            }
            other => panic!("expected location.php?lang=fr, got {other:?}"),
        }
    }

    #[test]
    fn moontime_city_route() {
        let rs = RuleSet::parse(MOONTIME).unwrap();
        match evaluate(&rs, &moon_input("/moon/new-york/")) {
            RewriteOutcome::Rewritten {
                new_uri, new_query, ..
            } => {
                assert_eq!(new_uri, "/location.php");
                assert_eq!(new_query.as_deref(), Some("city=new-york"));
            }
            other => panic!("expected city route, got {other:?}"),
        }
    }

    #[test]
    fn moontime_langs_forbidden() {
        let rs = RuleSet::parse(MOONTIME).unwrap();
        assert!(matches!(
            evaluate(&rs, &moon_input("/langs/fr.json")),
            RewriteOutcome::Forbidden { .. }
        ));
    }

    /// The moontimenow negative-lookahead FilesMatch for .txt files.
    #[test]
    fn moontime_txt_filesmatch_negative_lookahead() {
        let h = Htaccess::parse(
            "<FilesMatch \"^(?!robots\\.txt$|ads\\.txt$|a2c85e0468ce8b1733cda3012eca2a70\\.txt$).*\\.txt$\">\n    Require all denied\n</FilesMatch>",
        )
        .unwrap();
        assert!(h.is_forbidden("/secret.txt", "secret.txt"));
        assert!(!h.is_forbidden("/robots.txt", "robots.txt"));
        assert!(!h.is_forbidden("/ads.txt", "ads.txt"));
    }

    #[test]
    fn moontime_dotfile_except_htaccess() {
        let h = Htaccess::parse(
            "<FilesMatch \"^\\.(?!htaccess)\">\n  Require all denied\n</FilesMatch>",
        )
        .unwrap();
        assert!(h.is_forbidden("/.git", ".git"));
        assert!(!h.is_forbidden("/.htaccess", ".htaccess"));
    }

    // ----- LSCache directives (origin page cache) -----

    #[test]
    fn cache_directives_parse_lookup_keymodify() {
        // Mirrors the windowsforum .htaccess preamble.
        let h = Htaccess::parse(
            "CacheLookup public on\nCacheKeyModify -qs:utm* -qs:gclid -qs:fbclid -qs:ref -qs:source\n",
        )
        .unwrap();
        assert_eq!(h.cache_lookup, Some(true));
        assert_eq!(
            h.cache_key_modifiers,
            vec![
                CacheKeyModifier::StripQsPrefix("utm".into()),
                CacheKeyModifier::StripQs("gclid".into()),
                CacheKeyModifier::StripQs("fbclid".into()),
                CacheKeyModifier::StripQs("ref".into()),
                CacheKeyModifier::StripQs("source".into()),
            ]
        );
    }

    #[test]
    fn cache_directives_disable_and_fold() {
        let root = Htaccess::parse("CacheLookup public on\nCacheKeyModify -qs:utm*\n").unwrap();
        let sub = Htaccess::parse("CacheDisable public /\n").unwrap();
        assert_eq!(sub.cache_disable, vec!["/".to_string()]);

        // Chain = docroot file then the subdir's disable.
        let chain = vec![std::sync::Arc::new(root), std::sync::Arc::new(sub)];
        let d = cache_directives(&chain);
        assert_eq!(d.lookup, Some(true));
        assert_eq!(d.key_modifiers.len(), 1);
        // CacheDisable / => nothing under this chain is cacheable.
        assert!(!d.cacheable_for("/anything"));

        // Without the disable, the root chain alone is cacheable.
        let d2 = cache_directives(&chain[..1]);
        assert!(d2.cacheable_for("/forums/x"));
    }

    #[test]
    fn chain_cacheable_for_default_matches_fold_oracle() {
        // The lazy zero-alloc predicate the page-cache hot path uses MUST equal folding the chain
        // then calling cacheable_for_default (the allocating oracle), for every chain/path/default.
        use std::sync::Arc;
        let on =
            Arc::new(Htaccess::parse("CacheLookup public on\nCacheKeyModify -qs:utm*\n").unwrap());
        let off = Arc::new(Htaccess::parse("CacheLookup public off\n").unwrap());
        let disable_admin = Arc::new(Htaccess::parse("CacheDisable public /admin\n").unwrap());
        let disable_all = Arc::new(Htaccess::parse("CacheDisable public /\n").unwrap());
        let enable_all = Arc::new(Htaccess::parse("CacheEnable public /\n").unwrap());
        let enable_forums = Arc::new(Htaccess::parse("CacheEnable public /forums\n").unwrap());
        let empty = Arc::new(Htaccess::parse("# nothing\n").unwrap());

        let chains: Vec<Vec<Arc<Htaccess>>> = vec![
            vec![],
            vec![empty.clone()],
            vec![on.clone()],
            vec![off.clone()],
            vec![on.clone(), disable_admin.clone()],
            vec![on.clone(), disable_all.clone()],
            vec![on.clone(), off.clone()], // a later `off` wins over an earlier `on`
            vec![off.clone(), on.clone()], // a later `on` wins over an earlier `off`
            vec![empty.clone(), on.clone(), disable_admin.clone()],
            vec![enable_all.clone()],
            vec![enable_forums.clone()],
            vec![enable_forums.clone(), disable_admin.clone()],
            vec![enable_all.clone(), disable_admin.clone()],
            vec![off.clone(), enable_all.clone()], // explicit off wins over CacheEnable
            vec![enable_all.clone(), off.clone()],
        ];
        let paths = ["/", "/admin", "/admin/x", "/forums/x", "/administrator"];
        for chain in &chains {
            for &p in &paths {
                for default_on in [false, true] {
                    let oracle = cache_directives(chain).cacheable_for_default(p, default_on);
                    let lazy = chain_cacheable_for_default(chain, p, default_on);
                    assert_eq!(
                        lazy,
                        oracle,
                        "mismatch for path={p:?} default_on={default_on} chain_len={}",
                        chain.len()
                    );
                }
            }
        }
    }

    #[test]
    fn cache_enable_directive_enables_caching() {
        use std::sync::Arc;
        // The standard LiteSpeed/Apache opt-in `CacheEnable public /path` (no `CacheLookup`)
        // must make the chain cacheable for that prefix — it was previously parsed but ignored.
        let enable = Arc::new(Htaccess::parse("CacheEnable public /forums\n").unwrap());
        let chain = vec![enable.clone()];
        assert!(cache_directives(&chain).cacheable_for("/forums/thread-1"));
        assert!(chain_cacheable_for_default(
            &chain,
            "/forums/thread-1",
            false
        ));
        // A path outside the enabled prefix is not cached (no default-on, no CacheLookup).
        assert!(!cache_directives(&chain).cacheable_for("/members/"));
        assert!(!chain_cacheable_for_default(&chain, "/members/", false));

        // `CacheDisable` still wins over `CacheEnable` (disable precedence, matching LSWS).
        let disable = Arc::new(Htaccess::parse("CacheDisable public /forums/admin\n").unwrap());
        let chain2 = vec![enable.clone(), disable.clone()];
        assert!(cache_directives(&chain2).cacheable_for("/forums/thread-1"));
        assert!(!cache_directives(&chain2).cacheable_for("/forums/admin/x"));

        // An explicit `CacheLookup off` overrides `CacheEnable` (operator override).
        let off = Arc::new(Htaccess::parse("CacheLookup public off\n").unwrap());
        let chain3 = vec![enable, off];
        assert!(!cache_directives(&chain3).cacheable_for("/forums/thread-1"));
        assert!(!chain_cacheable_for_default(
            &chain3,
            "/forums/thread-1",
            false
        ));
    }

    #[test]
    fn cache_lookup_off_is_not_cacheable() {
        let h = Htaccess::parse("CacheLookup public off\n").unwrap();
        let chain = vec![std::sync::Arc::new(h)];
        assert!(!cache_directives(&chain).cacheable_for("/x"));
        // No CacheLookup at all => not cacheable (opt-in).
        let empty = Htaccess::parse("# nothing\n").unwrap();
        assert!(!cache_directives(&[std::sync::Arc::new(empty)]).cacheable_for("/x"));
    }

    /// news tracking-param strip + FilesMatch deny (verbatim core).
    const NEWS: &str = r#"
RewriteEngine On

RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]

RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_URI} (.+)/$
RewriteRule ^ %1 [R=301,L]

RewriteCond %{QUERY_STRING} ^(.*&)?(?:utm_source|utm_medium|utm_campaign|utm_term|utm_content|fbclid|gclid|msclkid|mc_cid|mc_eid)=[^&]*(?:&(.*))?$ [NC]
RewriteRule ^(.*)$ /$1?%1%2 [R=301,L,NE]

RewriteRule ^(category|prefix|tag|podcast|article|articles)/(.+?)/?$ router.php [L,QSA]
"#;

    fn news_input(uri: &str) -> RewriteInput<'static> {
        let mut i = RewriteInput::new(uri.to_string(), "/web/news");
        i.host = "publisher.example".into();
        i.https = true;
        i
    }

    #[test]
    fn news_strips_tracking_params_via_301() {
        let rs = RuleSet::parse(NEWS).unwrap();
        let mut inp = news_input("/article/foo").file_tests(FileTests {
            is_dir: false,
            ..Default::default()
        });
        inp.query = "utm_source=newsletter&id=5".into();
        match evaluate(&rs, &inp) {
            RewriteOutcome::Redirect { code, location, .. } => {
                assert_eq!(code, 301);
                assert_eq!(location, "https://publisher.example/article/foo?id=5");
            }
            other => panic!("expected tracking-strip redirect, got {other:?}"),
        }
    }

    #[test]
    fn news_no_tracking_params_routes_to_router() {
        let rs = RuleSet::parse(NEWS).unwrap();
        let inp = news_input("/category/security").file_tests(FileTests {
            is_dir: false,
            ..Default::default()
        });
        match evaluate(&rs, &inp) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/router.php"),
            other => panic!("expected router.php, got {other:?}"),
        }
    }

    #[test]
    fn news_trailing_slash_normalized() {
        let rs = RuleSet::parse(NEWS).unwrap();
        let inp = news_input("/category/security/").file_tests(FileTests {
            is_dir: false,
            ..Default::default()
        });
        match evaluate(&rs, &inp) {
            RewriteOutcome::Redirect { code, location, .. } => {
                assert_eq!(code, 301);
                // Apache fully-qualifies the path-only redirect target (item 4).
                assert_eq!(location, "https://publisher.example/category/security");
            }
            other => panic!("expected trailing-slash redirect, got {other:?}"),
        }
    }

    #[test]
    fn news_filesmatch_blocks_config() {
        let h = Htaccess::parse(
            "<FilesMatch \"(config\\.php|wp-config\\.php|.*\\.md|\\.log|\\.sql)$\">\n    Require all denied\n</FilesMatch>\n<Files \"robots.txt\">\n    Require all granted\n</Files>",
        )
        .unwrap();
        assert!(h.is_forbidden("/config.php", "config.php"));
        assert!(h.is_forbidden("/README.md", "README.md"));
        assert!(!h.is_forbidden("/robots.txt", "robots.txt"));
        assert!(!h.is_forbidden("/index.php", "index.php"));
    }

    /// The inline mcp.forum.example rules (verbatim from the vhost XML).
    const MCP: &str = r#"RewriteEngine On

RewriteRule ^/tools\.json$ http://127.0.0.1:8002/tools.json [P,L]
RewriteRule ^/\.well-known/(.*)$ http://127.0.0.1:8002/.well-known/$1 [P,L]
RewriteRule ^/health$ http://127.0.0.1:8002/health [P,L]
RewriteRule ^/authorize$ http://127.0.0.1:8002/authorize [P,L]

RewriteCond %{REQUEST_METHOD} ^(POST|DELETE)$
RewriteRule ^/(.*)$ http://127.0.0.1:8002/$1 [P,L]

RewriteCond %{HTTP:Accept} text/event-stream
RewriteRule ^/$ http://127.0.0.1:8002/ [P,L]
"#;

    #[test]
    fn mcp_tools_json_proxies() {
        let rs = RuleSet::parse(MCP).unwrap();
        match evaluate(&rs, &input("/tools.json")) {
            RewriteOutcome::Proxy { target_url, .. } => {
                assert_eq!(target_url, "http://127.0.0.1:8002/tools.json");
            }
            other => panic!("expected proxy, got {other:?}"),
        }
    }

    #[test]
    fn mcp_well_known_proxies_with_backref() {
        let rs = RuleSet::parse(MCP).unwrap();
        match evaluate(&rs, &input("/.well-known/oauth-authorization-server")) {
            RewriteOutcome::Proxy { target_url, .. } => {
                assert_eq!(
                    target_url,
                    "http://127.0.0.1:8002/.well-known/oauth-authorization-server"
                );
            }
            other => panic!("expected proxy, got {other:?}"),
        }
    }

    #[test]
    fn mcp_post_always_proxies() {
        let rs = RuleSet::parse(MCP).unwrap();
        let inp = input("/anything/here").method("POST");
        match evaluate(&rs, &inp) {
            RewriteOutcome::Proxy { target_url, .. } => {
                assert_eq!(target_url, "http://127.0.0.1:8002/anything/here");
            }
            other => panic!("expected proxy for POST, got {other:?}"),
        }
    }

    #[test]
    fn mcp_get_with_sse_accept_proxies_root() {
        let rs = RuleSet::parse(MCP).unwrap();
        let mut inp = input("/");
        inp.headers
            .insert("Accept".into(), "text/event-stream".into());
        match evaluate(&rs, &inp) {
            RewriteOutcome::Proxy { target_url, .. } => {
                assert_eq!(target_url, "http://127.0.0.1:8002/");
            }
            other => panic!("expected SSE proxy, got {other:?}"),
        }
    }

    #[test]
    fn mcp_browser_get_root_falls_through() {
        let rs = RuleSet::parse(MCP).unwrap();
        // GET / with a normal Accept -> no rule matches -> static fallthrough.
        let mut inp = input("/");
        inp.headers.insert("Accept".into(), "text/html".into());
        assert!(matches!(
            evaluate(&rs, &inp),
            RewriteOutcome::Unchanged { .. }
        ));
    }

    #[test]
    fn mcp_browser_get_static_path_falls_through() {
        let rs = RuleSet::parse(MCP).unwrap();
        let mut inp = input("/index.html");
        inp.headers.insert("Accept".into(), "text/html".into());
        assert!(matches!(
            evaluate(&rs, &inp),
            RewriteOutcome::Unchanged { .. }
        ));
    }
}

// ===========================================================================
// Htaccess directive parsing
// ===========================================================================

mod directives {
    use super::*;
    use crate::htaccess::HeaderAction;

    #[test]
    fn parses_header_ops() {
        let h = Htaccess::parse(
            "Header set X-Frame-Options \"SAMEORIGIN\"\nHeader unset Server\nHeader set Strict-Transport-Security \"max-age=63072000\" env=HTTPS",
        )
        .unwrap();
        assert_eq!(h.headers.len(), 3);
        assert_eq!(h.headers[0].action, HeaderAction::Set);
        assert_eq!(h.headers[0].name, "X-Frame-Options");
        assert_eq!(h.headers[0].value, "SAMEORIGIN");
        assert_eq!(h.headers[1].action, HeaderAction::Unset);
        assert_eq!(h.headers[1].name, "Server");
        assert_eq!(h.headers[2].env.as_ref().unwrap().var, "HTTPS");
        assert!(!h.headers[2].env.as_ref().unwrap().negate);
    }

    #[test]
    fn parses_set_env_if() {
        let h = Htaccess::parse(
            "SetEnvIf Origin \"^https://(forum\\.example)$\" ORIGIN_ALLOWED=$0\nSetEnvIf Query_String \"(^|&)amp=1(&|$)\" AMP_PAGE",
        )
        .unwrap();
        assert_eq!(h.set_env_if.len(), 2);
        assert_eq!(h.set_env_if[0].attribute, "Origin");
        assert_eq!(h.set_env_if[0].var, "ORIGIN_ALLOWED");
        assert_eq!(h.set_env_if[0].value, "$0");
        assert_eq!(h.set_env_if[1].var, "AMP_PAGE");
        assert_eq!(h.set_env_if[1].value, "1");
    }

    #[test]
    fn files_literal_vs_filesmatch_regex() {
        let h = Htaccess::parse(
            "<Files \"robots.txt\">\n  Require all granted\n</Files>\n<FilesMatch \"\\.log$\">\n  Require all denied\n</FilesMatch>",
        )
        .unwrap();
        // robots.txt literal: only exact name matches.
        assert!(!h.is_forbidden("/robots.txt", "robots.txt"));
        // a .log file is denied.
        assert!(h.is_forbidden("/app/error.log", "error.log"));
        // robots.txt.log should match the .log FilesMatch (denied).
        assert!(h.is_forbidden("/robots.txt.log", "robots.txt.log"));
    }

    #[test]
    fn directory_match_uses_request_path() {
        let h = Htaccess::parse(
            "<DirectoryMatch \"^.*/(\\.git|node_modules|vendor)$\">\n  Require all denied\n</DirectoryMatch>",
        )
        .unwrap();
        assert!(h.is_forbidden("/some/path/node_modules", "node_modules"));
        assert!(!h.is_forbidden("/some/path/public", "public"));
    }

    #[test]
    fn lscache_block_rewriterules_still_set_env() {
        // The <IfModule LiteSpeed> block: CacheLookup is a no-op, but the
        // RewriteRule [E=...] inside must still set env.
        let text = r#"
<IfModule LiteSpeed>
    CacheLookup public on
    CacheKeyModify -qs:utm*
    RewriteCond %{REQUEST_URI} ^/api/ [NC]
    RewriteRule .* - [E=no-cache-api:1]
</IfModule>
"#;
        let h = Htaccess::parse(text).unwrap();
        // The rewrite rule survived extraction into the embedded RuleSet, and
        // the engine was implicitly enabled by being inside the block (we add
        // RewriteEngine implicitly only if present; here there is none, so the
        // ruleset's engine flag is off — confirm by enabling).
        assert_eq!(h.rules.rules.len(), 1);
        // Force-enable to test the rule body (real file has RewriteEngine On above).
        let with_engine = RuleSet::parse(
            "RewriteEngine On\nRewriteCond %{REQUEST_URI} ^/api/ [NC]\nRewriteRule .* - [E=no-cache-api:1]",
        )
        .unwrap();
        let inp = RewriteInput::new("/api/foo", "/web/public_html");
        let out = evaluate(&with_engine, &inp);
        assert_eq!(out.env(), &[("no-cache-api".to_string(), "1".to_string())]);
        // And a non-/api path does not set it.
        let inp2 = RewriteInput::new("/threads/x", "/web/public_html");
        assert!(evaluate(&with_engine, &inp2).env().is_empty());
    }

    #[test]
    fn nested_ifmodule_balances_and_records_filesmatch() {
        // Header inside <FilesMatch> within <IfModule> — the access section is
        // still recorded (Require), and the nested IfModule is balanced.
        let text = r#"
<IfModule mod_headers.c>
  <FilesMatch "\.py$">
    Require all denied
  </FilesMatch>
</IfModule>
"#;
        let h = Htaccess::parse(text).unwrap();
        assert!(h.is_forbidden("/tool.py", "tool.py"));
        assert!(!h.is_forbidden("/index.php", "index.php"));
    }
}

// ===========================================================================
// HtaccessCache (filesystem-backed; uses a temp dir, default-runnable)
// ===========================================================================

mod cache_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("hj-rewrite-test-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn load_chain_walks_directories() {
        let root = tmp_dir("chain");
        fs::write(
            root.join(".htaccess"),
            "RewriteEngine On\nHeader set X-Root 1\n",
        )
        .unwrap();
        let sub = root.join("blog");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(".htaccess"), "Header set X-Blog 1\n").unwrap();

        let cache = HtaccessCache::new();
        let chain = cache.load_chain(&root, "/blog/post.html");
        assert_eq!(chain.len(), 2, "expected root + blog .htaccess");
        // Outermost first.
        assert!(chain[0].headers.iter().any(|h| h.name == "X-Root"));
        assert!(chain[1].headers.iter().any(|h| h.name == "X-Blog"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn load_chain_skips_missing_htaccess() {
        let root = tmp_dir("missing");
        fs::write(root.join(".htaccess"), "RewriteEngine On\n").unwrap();
        let sub = root.join("nodir");
        fs::create_dir_all(&sub).unwrap();
        // no .htaccess in sub
        let cache = HtaccessCache::new();
        let chain = cache.load_chain(&root, "/nodir/x.html");
        assert_eq!(chain.len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cache_invalidates_on_mtime_change() {
        let root = tmp_dir("mtime");
        let file = root.join(".htaccess");
        fs::write(&file, "Header set X-Version 1\n").unwrap();

        // TTL=0 forces revalidation on every call so we exercise the mtime path.
        let cache = HtaccessCache::with_revalidate_ttl(std::time::Duration::ZERO);
        let first = cache.get_or_load(&root).unwrap();
        assert_eq!(first.headers[0].value, "1");

        // Busy-wait so the filesystem mtime resolution ticks over, then rewrite.
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(20) {}
        fs::write(&file, "Header set X-Version 2\n").unwrap();

        let second = cache.get_or_load(&root).unwrap();
        assert_eq!(
            second.headers[0].value, "2",
            "cache should reparse on mtime change"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn clear_resets_cap_counter() {
        // Regression (live incident 2026-06-13): clear() must reset the soft-cap
        // counter, not just empty the map. A config reload calls clear(); if the
        // counter stayed pinned at the cap, the insert guard blocked all
        // re-caching and the heavy .htaccess re-parsed on every request,
        // recompiling its regex DFAs and burning multiple cores.
        let root = tmp_dir("clear_cap");
        fs::write(root.join(".htaccess"), "Header set X-V 1\n").unwrap();
        let cache = HtaccessCache::new();
        assert!(cache.get_or_load(&root).is_some());
        assert_eq!(cache.cap_count(), 1);

        cache.clear();
        assert_eq!(cache.cap_count(), 0, "clear() must reset the cap counter");

        // And a load after clear must re-populate (the user-visible symptom).
        assert!(cache.get_or_load(&root).is_some());
        assert_eq!(cache.cap_count(), 1);

        let _ = fs::remove_dir_all(&root);
    }
}

// ===========================================================================
// Live-file smoke tests (read-only). Marked #[ignore] because they depend on
// the production filesystem layout; run with `--ignored` on the live host to
// confirm the *actual* current .htaccess files parse and behave sanely.
// ===========================================================================

mod live {
    use super::*;

    fn parse_live(path: &str) -> Option<Htaccess> {
        let text = std::fs::read_to_string(path).ok()?;
        Some(Htaccess::parse(&text).expect("live .htaccess must parse"))
    }

    #[test]
    #[ignore = "reads production /web/*/.htaccess; run with --ignored on the live host"]
    fn public_html_parses_and_routes_to_index() {
        let h = parse_live("/web/public_html/.htaccess").expect("file present");
        assert!(h.rules.engine_on);
        // Front-controller fallthrough: an unknown thread URL -> index.php.
        let inp = input("/threads/whatever.99999").file_tests(FileTests::default());
        match evaluate(&h.rules, &inp) {
            RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/index.php"),
            other => panic!("expected index.php, got {other:?}"),
        }
        // Security: dotfiles are forbidden via the FilesMatch / rewrite rules.
        assert!(h.is_forbidden("/.env", ".env"));
    }

    #[test]
    #[ignore = "reads production /web/moontimenow/.htaccess"]
    fn moontimenow_parses_and_forces_https() {
        let h = parse_live("/web/moontimenow/.htaccess").expect("file present");
        let mut inp = RewriteInput::new("/moon/", "/web/moontimenow");
        inp.host = "moon.example".into();
        inp.https = false;
        match evaluate(&h.rules, &inp) {
            RewriteOutcome::Redirect { code, location, .. } => {
                assert_eq!(code, 301);
                assert!(location.starts_with("https://"));
            }
            other => panic!("expected https redirect, got {other:?}"),
        }
        // negative-lookahead .txt FilesMatch
        assert!(h.is_forbidden("/secret.txt", "secret.txt"));
        assert!(!h.is_forbidden("/robots.txt", "robots.txt"));
    }

    #[test]
    #[ignore = "reads production /web/news/.htaccess"]
    fn news_parses_and_strips_tracking() {
        let h = parse_live("/web/news/.htaccess").expect("file present");
        let mut inp = RewriteInput::new("/article/foo", "/web/news").file_tests(FileTests {
            is_dir: false,
            ..Default::default()
        });
        inp.host = "publisher.example".into();
        inp.https = true;
        inp.query = "utm_source=x&id=1".into();
        match evaluate(&h.rules, &inp) {
            RewriteOutcome::Redirect { code, location, .. } => {
                assert_eq!(code, 301);
                assert_eq!(location, "https://publisher.example/article/foo?id=1");
            }
            other => panic!("expected tracking-strip redirect, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Outcome-cacheability gate (RuleSet::path_cacheable)
// ---------------------------------------------------------------------------
mod path_cacheable_gate {
    use super::*;

    fn cacheable(src: &str) -> bool {
        RuleSet::parse(src).unwrap().path_cacheable
    }

    #[test]
    fn empty_ruleset_is_cacheable() {
        assert!(cacheable("RewriteEngine On"));
        assert!(cacheable(""));
    }

    #[test]
    fn front_controller_is_cacheable() {
        // The canonical pure front controller: only path/filename + -f/-d.
        assert!(cacheable(
            "RewriteEngine On\n\
             RewriteCond %{REQUEST_FILENAME} !-f\n\
             RewriteCond %{REQUEST_FILENAME} !-d\n\
             RewriteRule ^ index.php [L]"
        ));
    }

    #[test]
    fn safe_vars_are_cacheable() {
        // host / query / scheme / method / request-uri are all in the cache key.
        assert!(cacheable(
            "RewriteEngine On\n\
             RewriteCond %{HTTPS} off\n\
             RewriteCond %{HTTP_HOST} ^example\\.com$\n\
             RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]"
        ));
        assert!(cacheable(
            "RewriteEngine On\nRewriteCond %{QUERY_STRING} (^|&)x=1\nRewriteRule ^a$ /b [L]"
        ));
        // [E=...] referencing only safe vars stays cacheable.
        assert!(cacheable(
            "RewriteEngine On\nRewriteRule .* - [E=CANON:https://%{HTTP_HOST}%{REQUEST_URI}]"
        ));
    }

    #[test]
    fn varying_inputs_are_not_cacheable() {
        // Each of these reads a per-request-varying input that is NOT in the keyable
        // allowlist -> fail-closed (uncacheable).
        assert!(!cacheable(
            "RewriteEngine On\nRewriteCond %{HTTP_COOKIE} xf_session\nRewriteRule ^ /a [L]"
        ));
        assert!(!cacheable(
            "RewriteEngine On\nRewriteCond %{HTTP:Referer} example\nRewriteRule ^ - [L]"
        ));
        assert!(!cacheable(
            "RewriteEngine On\nRewriteCond %{REMOTE_ADDR} ^10\\.\nRewriteRule ^ /a [L]"
        ));
        assert!(!cacheable(
            "RewriteEngine On\nRewriteCond %{TIME_HOUR} ^02$\nRewriteRule ^ /a [L]"
        ));
        // Varying var inside a substitution also disqualifies.
        assert!(!cacheable(
            "RewriteEngine On\nRewriteRule ^a$ /b?ref=%{HTTP_REFERER} [L]"
        ));
        // A varying var in the comparison RHS (not just the LHS test_string) must also
        // disqualify — the RHS is %{VAR}-expanded at eval time.
        assert!(!cacheable(
            "RewriteEngine On\nRewriteCond %{REQUEST_URI} =%{REMOTE_ADDR}\nRewriteRule ^ /a [L]"
        ));
        assert!(!cacheable(
            "RewriteEngine On\nRewriteCond %{REQUEST_URI} >%{ENV:CUTOFF}\nRewriteRule ^ /a [L]"
        ));
    }

    #[test]
    fn user_agent_is_keyable_cacheable() {
        // Stage 4: %{HTTP_USER_AGENT} (and the %{HTTP:User-Agent} form) is KEYABLE —
        // a chain reading only it (plus base-key-safe vars) is cacheable, with
        // UserAgent recorded so the pipeline folds the UA value into the cache key.
        for src in [
            "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} Googlebot\nRewriteRule .* - [E=BOT:1]",
            "RewriteEngine On\nRewriteCond %{HTTP:User-Agent} Googlebot\nRewriteRule .* - [E=BOT:1]",
            // UA inside an [E=...] value is keyable too.
            "RewriteEngine On\nRewriteRule .* - [E=UA:%{HTTP_USER_AGENT}]",
        ] {
            let rs = RuleSet::parse(src).unwrap();
            assert!(rs.path_cacheable, "UA chain must be cacheable: {src}");
            assert_eq!(
                rs.cache_key_vars,
                vec![CacheKeyVar::UserAgent],
                "key var: {src}"
            );
        }
        // Mixing UA with a non-keyable var (Cookie) is still uncacheable.
        let mixed = RuleSet::parse(
            "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} Bot\nRewriteCond %{HTTP_COOKIE} x\nRewriteRule ^ - [L]",
        )
        .unwrap();
        assert!(!mixed.path_cacheable);
        assert!(
            mixed.cache_key_vars.is_empty(),
            "uncacheable set must carry no key vars"
        );
    }

    #[test]
    fn origin_is_keyable_cacheable() {
        // %{HTTP:Origin} is KEYABLE (small cardinality: absent on most requests,
        // a handful of scheme+host values otherwise) — the live CORS-preflight
        // block no longer poisons the chain.
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{REQUEST_METHOD} OPTIONS\n\
             RewriteCond %{HTTP:Origin} (google\\.com|cloudflare\\.com)$ [NC]\n\
             RewriteRule ^(.*)$ - [R=200,L,E=CORS_PREFLIGHT:1]",
        )
        .unwrap();
        assert!(rs.path_cacheable, "Origin-gated chain must be cacheable");
        assert_eq!(rs.cache_key_vars, vec![CacheKeyVar::Origin]);
        // Case-insensitive header-name form too.
        let rs =
            RuleSet::parse("RewriteEngine On\nRewriteCond %{HTTP:origin} x\nRewriteRule ^ - [L]")
                .unwrap();
        assert!(rs.path_cacheable);
        assert_eq!(rs.cache_key_vars, vec![CacheKeyVar::Origin]);
        // The bare %{HTTP_ORIGIN} form is NOT a header read in this engine (it
        // falls through to the env lookup) — it must stay unkeyable/uncacheable.
        assert!(!cacheable(
            "RewriteEngine On\nRewriteCond %{HTTP_ORIGIN} x\nRewriteRule ^ - [L]"
        ));
        // Mixing Origin with a non-keyable var (Cookie) is still uncacheable.
        assert!(!cacheable(
            "RewriteEngine On\nRewriteCond %{HTTP:Origin} x\nRewriteCond %{HTTP_COOKIE} y\nRewriteRule ^ - [L]"
        ));
    }

    #[test]
    fn env_redirect_status_is_assumed_empty_cache_safe() {
        // The live LSCache guard `RewriteCond %{ENV:REDIRECT_STATUS} ^(403|5)`:
        // httpjet never seeds REDIRECT_STATUS before rewrite evaluation (the CGI
        // builder and the ErrorDocument subrequest both run downstream), so the
        // read is constant-empty and must NOT poison the chain — but the assumed
        // name is recorded so the pipeline can verify the live env seed.
        let rs = RuleSet::parse(
            "RewriteEngine On\n\
             RewriteCond %{ENV:REDIRECT_STATUS} ^(403|5)\n\
             RewriteRule .* - [E=no-cache:1]",
        )
        .unwrap();
        assert!(rs.path_cacheable, "ENV:REDIRECT_STATUS must be cache-safe");
        assert!(rs.cache_key_vars.is_empty());
        assert_eq!(rs.assumed_empty_env, vec!["REDIRECT_STATUS".to_string()]);
        // Any OTHER env read stays fail-closed.
        let other =
            RuleSet::parse("RewriteEngine On\nRewriteCond %{ENV:HTTPS} on\nRewriteRule ^ /a [L]")
                .unwrap();
        assert!(!other.path_cacheable);
        assert!(other.assumed_empty_env.is_empty());
    }

    #[test]
    fn real_pure_vhost_is_cacheable_real_uncacheable() {
        // Ground-truth from the live config: moontimenow is pure; public_html
        // (windowsforum) is cacheable since the 2026-07-16 deploy replaced the
        // admin-cookie `RewriteCond %{HTTP_COOKIE}` with SetEnvIf — UA and
        // HTTP:Origin are keyable and ENV:REDIRECT_STATUS is assumed-empty.
        if let Ok(src) = std::fs::read_to_string("/web/moontimenow/.htaccess") {
            assert!(
                RuleSet::parse(&extract_rewrite(&src))
                    .unwrap()
                    .path_cacheable,
                "moontimenow should be cacheable"
            );
        }
        if let Ok(src) = std::fs::read_to_string("/web/public_html/.htaccess") {
            let rewrite = extract_rewrite(&src);
            assert!(
                !rewrite.contains("%{HTTP_COOKIE}"),
                "a %{{HTTP_COOKIE}} cond is back in the live .htaccess — the \
                 outcome cache is poisoned vhost-wide again (see \
                 /var/log/wf-perf-audit/htaccess-setenvif.draft.txt)"
            );
            let rs = RuleSet::parse(&rewrite).unwrap();
            assert!(rs.path_cacheable, "live (deployed) chain must be cacheable");
            assert!(rs.cache_key_vars.contains(&CacheKeyVar::UserAgent));
            assert!(rs.cache_key_vars.contains(&CacheKeyVar::Origin));
            assert_eq!(rs.assumed_empty_env, vec!["REDIRECT_STATUS".to_string()]);
            // And the UA read (the KNOWN_CRAWLER block: one exact-UA regex cond,
            // no %N anywhere) is bitmap-classifiable.
            assert!(
                rs.ua_classify_eligible(),
                "live UA block must be ua-classify eligible"
            );
            assert!(rs.ua_cond_count() >= 1);

            // Regression: ONE cookie cond re-poisons the whole chain.
            let poisoned = format!(
                "{rewrite}\nRewriteCond %{{HTTP_COOKIE}} (xf_session_admin) [NC]\nRewriteRule .* - [E=x:1]"
            );
            let rs = RuleSet::parse(&poisoned).unwrap();
            assert!(
                !rs.path_cacheable,
                "an HTTP_COOKIE cond must poison the chain"
            );
        }
    }

    /// Keep only Rewrite* directives (RuleSet::parse ignores others, but real
    /// .htaccess has Files/Header blocks; strip to be safe for the golden read).
    fn extract_rewrite(src: &str) -> String {
        src.lines()
            .filter(|l| {
                let t = l.trim_start().to_ascii_lowercase();
                t.starts_with("rewrite")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ---------------------------------------------------------------------------
// UA-classification eligibility + signature (RuleSet::ua_classify_*)
// ---------------------------------------------------------------------------
mod ua_classify {
    use super::*;

    fn parse(src: &str) -> RuleSet {
        RuleSet::parse(src).unwrap()
    }

    #[test]
    fn exact_ua_regex_conds_are_eligible() {
        // The canonical crawler block: exact-UA test string, plain regex, the
        // outcome depends on the UA only through the match boolean.
        let rs = parse(
            "RewriteEngine On\n\
             RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot|DuckDuckBot)\n\
             RewriteRule .* - [E=KNOWN_CRAWLER:1]",
        );
        assert!(rs.path_cacheable);
        assert!(rs.ua_classify_eligible());
        assert_eq!(rs.ua_cond_count(), 1);
        // Signature: bit 0 = the cond's regex match against the raw UA.
        assert_eq!(rs.ua_cond_signature("Mozilla/5.0 Googlebot/2.1"), 0b1);
        assert_eq!(rs.ua_cond_signature("Mozilla/5.0 Chrome/120"), 0b0);
        assert_eq!(rs.ua_cond_signature(""), 0b0);
        // Distinct UAs, same bitmap -> same outcome class (that's the point).
        assert_eq!(
            rs.ua_cond_signature("Bingbot/2.0"),
            rs.ua_cond_signature("DuckDuckBot/1.1")
        );
    }

    #[test]
    fn folded_or_block_and_negated_nc_conds_are_eligible() {
        // An [OR] UA run folds into one alternation cond (combine_or_conds);
        // negation and [NC] stay eligible (applied deterministically to the
        // memoized match result).
        let rs = parse(
            "RewriteEngine On\n\
             RewriteCond %{HTTP_USER_AGENT} googlebot [NC,OR]\n\
             RewriteCond %{HTTP_USER_AGENT} bingbot [NC]\n\
             RewriteRule .* - [E=BOT:1]\n\
             RewriteCond %{HTTP:User-Agent} !android [NC]\n\
             RewriteRule ^m/ /desktop [L]",
        );
        assert!(rs.ua_classify_eligible());
        assert_eq!(
            rs.ua_cond_count(),
            2,
            "OR run folds to one cond + the negated one"
        );
        assert_eq!(rs.ua_cond_signature("GoogleBot"), 0b01);
        assert_eq!(rs.ua_cond_signature("Android 14"), 0b10);
        assert_eq!(rs.ua_cond_signature("nothing"), 0b00);
    }

    #[test]
    fn ua_in_subst_env_value_or_rhs_is_ineligible_but_still_keyable() {
        // The raw UA value flows into the outcome -> bitmap keying would be
        // WRONG; the chain stays cacheable on the raw-UA key.
        for src in [
            "RewriteEngine On\nRewriteRule ^a$ /b?ua=%{HTTP_USER_AGENT} [L]",
            "RewriteEngine On\nRewriteRule .* - [E=UA:%{HTTP_USER_AGENT}]",
            "RewriteEngine On\nRewriteCond %{REQUEST_URI} =%{HTTP_USER_AGENT}\nRewriteRule ^ /a [L]",
        ] {
            let rs = parse(src);
            assert!(rs.path_cacheable, "still keyable: {src}");
            assert!(
                rs.cache_key_vars.contains(&CacheKeyVar::UserAgent),
                "still keyable: {src}"
            );
            assert!(!rs.ua_classify_eligible(), "must be ineligible: {src}");
        }
    }

    #[test]
    fn mixed_test_string_or_non_regex_pattern_is_ineligible() {
        // A test string that concatenates the UA with anything else couples the
        // match result to other inputs; a lexical comparison and a file test are
        // excluded by the regex-only requirement.
        for src in [
            "RewriteEngine On\nRewriteCond x%{HTTP_USER_AGENT} bot\nRewriteRule ^ - [L]",
            "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} =Googlebot\nRewriteRule ^ - [L]",
            "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} -f\nRewriteRule ^ - [L]",
        ] {
            let rs = parse(src);
            assert!(!rs.ua_classify_eligible(), "must be ineligible: {src}");
        }
    }

    #[test]
    fn percent_backref_anywhere_disqualifies() {
        // %0..%9 resolve from the LAST MATCHED cond — they can expose a UA
        // cond's matched substring, which varies within one bitmap value.
        let rs = parse(
            "RewriteEngine On\n\
             RewriteCond %{HTTP_USER_AGENT} (iPhone|Android)\n\
             RewriteRule ^(.*)$ /m/$1?dev=%1 [L]",
        );
        assert!(rs.path_cacheable);
        assert!(!rs.ua_classify_eligible(), "%N consumes UA captures");
    }

    #[test]
    fn ua_free_or_uncacheable_sets_are_ineligible() {
        // No UA read at all -> nothing to classify.
        let rs = parse("RewriteEngine On\nRewriteRule ^a$ /b [L]");
        assert!(!rs.ua_classify_eligible());
        assert_eq!(rs.ua_cond_count(), 0);
        // Uncacheable set (cookie) -> ineligible regardless of its UA cond.
        let rs = parse(
            "RewriteEngine On\n\
             RewriteCond %{HTTP_USER_AGENT} bot\n\
             RewriteCond %{HTTP_COOKIE} x\n\
             RewriteRule ^ - [L]",
        );
        assert!(!rs.path_cacheable);
        assert!(!rs.ua_classify_eligible());
    }

    #[test]
    fn parse_assigns_unique_nonzero_ids() {
        let a = parse("RewriteEngine On");
        let b = parse("RewriteEngine On");
        assert_ne!(a.id(), 0);
        assert_ne!(b.id(), 0);
        assert_ne!(a.id(), b.id(), "each parse mints a fresh id");
        assert_eq!(RuleSet::default().id(), 0, "default (empty) set keeps id 0");
    }

    #[test]
    fn signature_matches_eval_outcome_class() {
        // The soundness property the pipeline relies on: for an eligible set,
        // two UAs with EQUAL signatures produce IDENTICAL evaluate() outcomes
        // (same base-key inputs), and the signature distinguishes UAs whose
        // outcomes differ.
        let rs = parse(
            "RewriteEngine On\n\
             RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot)\n\
             RewriteRule ^blocked$ - [F]",
        );
        assert!(rs.ua_classify_eligible());
        let eval_with = |ua: &str| {
            let mut inp = RewriteInput::new("/blocked", "/tmp");
            if !ua.is_empty() {
                inp = inp.header("User-Agent", ua);
            }
            evaluate(&rs, &inp)
        };
        let bot_a = eval_with("Googlebot/2.1");
        let bot_b = eval_with("Bingbot/2.0");
        let human = eval_with("Mozilla/5.0 Chrome");
        let absent = eval_with("");
        assert_eq!(
            rs.ua_cond_signature("Googlebot/2.1"),
            rs.ua_cond_signature("Bingbot/2.0")
        );
        assert_eq!(format!("{bot_a:?}"), format!("{bot_b:?}"));
        assert_ne!(
            rs.ua_cond_signature("Googlebot/2.1"),
            rs.ua_cond_signature("Mozilla/5.0 Chrome")
        );
        assert_ne!(format!("{bot_a:?}"), format!("{human:?}"));
        // Absent UA == empty UA for both eval and signature.
        assert_eq!(
            rs.ua_cond_signature(""),
            rs.ua_cond_signature("Mozilla/5.0 Chrome")
        );
        assert_eq!(format!("{human:?}"), format!("{absent:?}"));
    }
}
