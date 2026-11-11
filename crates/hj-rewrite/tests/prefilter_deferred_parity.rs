//! (#1209) Building the rewrite prefilter is most of the cost of parsing a long rule
//! chain, so the `.htaccess` cache parses with the build deferred to a background
//! thread. A rule set must give the same outcomes eagerly built, before its deferred
//! build, and after it; and deferring must not change how the set is classified.

use hj_rewrite::{Htaccess, RewriteInput, RuleSet, evaluate};

/// Prefilter-eligible rules (plain patterns), ineligible ones (negated, lookahead),
/// conditions, case-insensitive matching and an internal rewrite that changes the URI.
const RULES: &str = "\
RewriteEngine On
RewriteRule ^old/(.*)$ /new/$1 [R=301,L]
RewriteRule ^blocked\\.php$ - [F]
RewriteCond %{QUERY_STRING} ^id=(\\d+)$
RewriteRule ^item$ /items/%1? [R=302,L]
RewriteRule ^(?!keep/)gone/ - [G]
RewriteRule ^API/(.*)$ /api.php?p=$1 [NC,QSA,L]
RewriteRule ^step$ /step-two
RewriteRule ^step-two$ /done [L]
RewriteRule !^(static|done)/ /index.php [L]
";

const TARGETS: &[(&str, &str)] = &[
    ("/old/page", ""),
    ("/blocked.php", ""),
    ("/item", "id=42"),
    ("/item", "x=1"),
    ("/gone/x", ""),
    ("/keep/gone/x", ""),
    ("/api/v1/users", "a=b"),
    ("/step", ""),
    ("/static/app.js", ""),
    ("/done/", ""),
    ("/", ""),
    ("/nothing/matches/here", "q=1"),
];

fn outcomes(rules: &RuleSet) -> Vec<String> {
    TARGETS
        .iter()
        .map(|(uri, query)| {
            let input = RewriteInput::new(*uri, "/var/www").query(*query);
            format!("{uri}?{query} => {:?}", evaluate(rules, &input))
        })
        .collect()
}

#[test]
fn deferred_rule_set_matches_eager_before_and_after_the_build() {
    let eager = RuleSet::parse(RULES).unwrap();
    assert!(!eager.prefilter_pending());
    let expected = outcomes(&eager);
    assert!(
        expected.iter().any(|line| line.contains("Redirect")),
        "the fixture must exercise real outcomes: {expected:#?}"
    );

    let deferred = RuleSet::parse_deferred(RULES).unwrap();
    assert!(deferred.prefilter_pending());
    assert_eq!(outcomes(&deferred), expected, "unfiltered evaluation");

    deferred.build_prefilter();
    assert!(!deferred.prefilter_pending());
    assert_eq!(outcomes(&deferred), expected, "filtered evaluation");
    deferred.build_prefilter();
    assert_eq!(outcomes(&deferred), expected, "a second build is a no-op");

    assert_eq!(deferred.path_cacheable, eager.path_cacheable);
    assert_eq!(deferred.cache_key_vars, eager.cache_key_vars);
    assert_eq!(deferred.header_reads, eager.header_reads);
    assert_eq!(deferred.page_cache_unkeyed, eager.page_cache_unkeyed);
}

#[test]
fn deferred_htaccess_keeps_its_memo_class_and_builds_once() {
    let text = format!("Header set X-Test 1\n{RULES}");
    let eager = Htaccess::parse(&text).unwrap();
    let deferred = Htaccess::parse_deferred(&text).unwrap();
    assert!(deferred.prefilter_pending());
    assert_eq!(deferred.memo.eligible, eager.memo.eligible);
    assert_eq!(outcomes(&deferred.rules), outcomes(&eager.rules));
    deferred.build_prefilter();
    assert!(!deferred.prefilter_pending());
    assert_eq!(outcomes(&deferred.rules), outcomes(&eager.rules));
}

#[test]
fn a_rule_set_without_prefilter_patterns_has_nothing_to_build() {
    let rules = RuleSet::parse_deferred("RewriteEngine On\nRewriteRule !^static/ /index.php [L]\n")
        .unwrap();
    assert!(!rules.prefilter_pending());
    rules.build_prefilter();
}
