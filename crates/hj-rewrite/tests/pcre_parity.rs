//! Regressions for PCRE parity in rewrite patterns: `\<`/`\>` are literal
//! brackets (#952; SetEnvIf, sections, `<If>` and `expr=` #978), and the
//! whole-match shortcut does not match across a decoded newline (#953).

use hj_rewrite::{
    AccessDecision, AccessSubject, HeaderLookup, Htaccess, ReqAttrs, RewriteInput, RewriteOutcome,
    RuleSet, evaluate,
};

fn run(rules: &str, uri: &str, query: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).expect("parse");
    let mut input = RewriteInput::new(uri.to_string(), "/web/docroot").host("h.test");
    input.query = query.into();
    input.per_directory_prefix = Some(String::new());
    evaluate(&rs, &input)
}

#[test]
fn escaped_angle_brackets_are_literal() {
    let block = "RewriteEngine On\n\
                 RewriteCond %{QUERY_STRING} (\\<|%3C).*script.*(\\>|%3E) [NC]\n\
                 RewriteRule .* - [F]\n";
    assert!(matches!(
        run(block, "/x", "q=description"),
        RewriteOutcome::Unchanged { .. }
    ));
    assert!(matches!(
        run(block, "/x", "q=<script>"),
        RewriteOutcome::Forbidden { .. }
    ));
    let anchored = "RewriteEngine On\nRewriteRule ^\\<foo - [F]\n";
    assert!(matches!(
        run(anchored, "/<foo", ""),
        RewriteOutcome::Forbidden { .. }
    ));
    assert!(matches!(
        run(anchored, "/foo", ""),
        RewriteOutcome::Unchanged { .. }
    ));
}

#[test]
fn total_match_shortcut_respects_newlines() {
    let fc = "RewriteEngine On\nRewriteRule ^(.*)$ /fc.php?u=$1 [L]\n";
    assert!(matches!(
        run(fc, "/a\nb", ""),
        RewriteOutcome::Unchanged { .. }
    ));
    let unanchored = "RewriteEngine On\nRewriteRule (.*) /fc.php?u=$1 [L]\n";
    match run(unanchored, "/a\nb", "") {
        RewriteOutcome::Rewritten { new_query, .. } => {
            assert_eq!(new_query.as_deref(), Some("u=a"))
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        run(fc, "/ab", ""),
        RewriteOutcome::Rewritten { .. }
    ));
}

fn ua_env(ht: &Htaccess, ua: &str) -> Vec<(String, String)> {
    let header = |n: &str| n.eq_ignore_ascii_case("user-agent").then(|| ua.to_string());
    let attrs = ReqAttrs {
        request_uri: "/x",
        method: "GET",
        header_lookup: Some(HeaderLookup(&header)),
        ..Default::default()
    };
    ht.eval_set_env(&attrs).expect("eval")
}

fn decide_with(ht: &Htaccess, path: &str, env: &[(String, String)]) -> AccessDecision {
    let set = |n: &str| env.iter().any(|(k, _)| k == n);
    let subject = AccessSubject {
        client_ip: Some("203.0.113.9".parse().unwrap()),
        env_set: Some(&set),
    };
    ht.access_decision_for(path, "GET", &subject)
}

/// (#978) SetEnvIf compiles through the same PCRE escapes as RewriteRule: a
/// `\<` that compiled as a word boundary never matched, opening `Deny from env=`.
#[test]
fn set_env_if_escaped_angle_brackets_are_literal() {
    let ht = Htaccess::parse(
        "SetEnvIf User-Agent \"^\\<\\?php\" bad\n\
         SetEnvIfNoCase User-Agent \"\\<SCRIPT\\>\" bad\n\
         Order Allow,Deny\nAllow from all\nDeny from env=bad\n",
    )
    .unwrap();
    for ua in ["<?php system('id'); ?>", "x <script> y"] {
        let env = ua_env(&ht, ua);
        assert!(env.iter().any(|(k, _)| k == "bad"), "{ua}: {env:?}");
        assert_eq!(decide_with(&ht, "/x", &env), AccessDecision::Denied, "{ua}");
    }
    for ua in ["php", "Mozilla/5.0 script", "?php"] {
        let env = ua_env(&ht, ua);
        assert!(env.is_empty(), "{ua}: {env:?}");
        assert_eq!(
            decide_with(&ht, "/x", &env),
            AccessDecision::Granted,
            "{ua}"
        );
    }
}

/// (#978) `<FilesMatch>`/`<Files ~>`/`<DirectoryMatch>` patterns are PCRE too.
#[test]
fn section_patterns_escaped_angle_brackets_are_literal() {
    let files = Htaccess::parse(
        "<FilesMatch \"^\\<\">\nRequire all denied\n</FilesMatch>\n\
         <Files ~ \"\\>$\">\nRequire all denied\n</Files>\n",
    )
    .unwrap();
    assert_eq!(
        files.access_decision("/d/<a.txt", "GET"),
        AccessDecision::Denied
    );
    assert_eq!(
        files.access_decision("/d/a.txt>", "GET"),
        AccessDecision::Denied
    );
    // As word boundaries these matched every word-led / word-ended basename.
    assert_eq!(
        files.access_decision("/d/a.txt", "GET"),
        AccessDecision::NoOpinion
    );
    let dir =
        Htaccess::parse("<DirectoryMatch \"^/\\<x\\>\">\nRequire all denied\n</DirectoryMatch>\n")
            .unwrap();
    assert_eq!(dir.access_decision("/<x>/f", "GET"), AccessDecision::Denied);
    assert_eq!(
        dir.access_decision("/x/f", "GET"),
        AccessDecision::NoOpinion
    );
}

/// (#978) `<If>` and `Header … expr=` regexes are ap_expr (PCRE) regexes.
#[test]
fn if_and_header_expr_escaped_angle_brackets_are_literal() {
    let deny = Htaccess::parse("<If \"%{REQUEST_URI} =~ m#^/\\<#\">\nRequire all denied\n</If>\n")
        .unwrap();
    assert_eq!(deny.access_decision("/<x", "GET"), AccessDecision::Denied);
    assert_eq!(deny.access_decision("/x", "GET"), AccessDecision::NoOpinion);

    let headers = Htaccess::parse(
        "<If \"%{REQUEST_URI} =~ m#\\<#\">\nHeader set X-Lt 1\n</If>\n\
         Header set X-Gt 1 \"expr=%{REQUEST_URI} =~ m#\\>$#\"\n",
    )
    .unwrap();
    let names = |path: &str| -> Vec<String> {
        headers
            .response_headers_for_request(path, path, 200, &[])
            .iter()
            .map(|op| op.name().to_string())
            .collect()
    };
    assert_eq!(names("/a<b"), ["X-Lt"]);
    assert_eq!(names("/a>"), ["X-Gt"]);
    assert!(names("/ab").is_empty(), "{:?}", names("/ab"));
}
