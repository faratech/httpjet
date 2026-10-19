//! `SetEnvIf` attribute resolution, assignment lists, `!VAR` unsets, the
//! `BrowserMatch` aliases and enclosing-section scopes (#779 #780 #781).

use hj_rewrite::{
    AccessDecision, AccessSubject, EnvAssignment, HeaderLookup, Htaccess, ReqAttrs, RewriteError,
    RewriteInput, RuleSet, evaluate,
};

fn env_for(
    ht: &Htaccess,
    uri: &str,
    header: &dyn Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let attrs = ReqAttrs {
        request_uri: uri,
        method: "GET",
        protocol: "HTTP/1.1",
        remote_addr: "203.0.113.9",
        host: "example.com",
        header_lookup: Some(HeaderLookup(header)),
        ..Default::default()
    };
    ht.eval_set_env(&attrs).unwrap()
}

#[test]
fn remote_host_is_the_client_address_never_a_header() {
    let ht = Htaccess::parse(
        "SetEnvIf Remote_Host \"^admin\\.corp\\.example$\" let_in\nOrder deny,allow\nDeny from all\nAllow from env=let_in\n",
    )
    .unwrap();
    let spoof = |name: &str| {
        name.eq_ignore_ascii_case("remote-host")
            .then(|| "admin.corp.example".to_string())
    };
    let env = env_for(&ht, "/x", &spoof);
    assert!(env.is_empty(), "{env:?}");
    let set = |n: &str| env.iter().any(|(k, _)| k == n);
    let subject = AccessSubject {
        client_ip: Some("203.0.113.9".parse().unwrap()),
        env_set: Some(&set),
    };
    assert_eq!(
        ht.access_decision_for("/x", "GET", &subject),
        AccessDecision::Denied
    );

    let by_addr = Htaccess::parse("SetEnvIf Remote_Host ^203\\.0\\.113\\. local\n").unwrap();
    assert_eq!(
        env_for(&by_addr, "/x", &|_| None),
        [("local".to_string(), "1".to_string())]
    );
    assert!(!by_addr.memo.eligible);
}

#[test]
fn every_assignment_of_a_matching_set_env_if_applies() {
    let ht = Htaccess::parse("SetEnvIf Request_URI \"\\.gif$\" image nolog kind=$0\n").unwrap();
    assert_eq!(
        env_for(&ht, "/a.gif", &|_| None),
        [
            ("image".to_string(), "1".to_string()),
            ("nolog".to_string(), "1".to_string()),
            ("kind".to_string(), ".gif".to_string()),
        ]
    );
    assert!(env_for(&ht, "/a.png", &|_| None).is_empty());
}

/// Judge access after merging `env` the way the pipeline does: a `!VAR`
/// assignment removes VAR.
fn decide(ht: &Htaccess, uri: &str, env: &[(String, String)]) -> AccessDecision {
    let mut merged: Vec<(String, String)> = Vec::new();
    for (k, v) in env {
        match EnvAssignment::classify(k, v) {
            EnvAssignment::Unset { name } => merged.retain(|(n, _)| n != name),
            EnvAssignment::Set { name, value } => {
                merged.retain(|(n, _)| n != name);
                merged.push((name.to_string(), value.to_string()));
            }
        }
    }
    let set = |n: &str| merged.iter().any(|(k, _)| k == n);
    let subject = AccessSubject {
        client_ip: Some("203.0.113.9".parse().unwrap()),
        env_set: Some(&set),
    };
    ht.access_decision_for(uri, "GET", &subject)
}

fn user_agent(value: &'static str) -> impl Fn(&str) -> Option<String> {
    move |n: &str| {
        n.eq_ignore_ascii_case("user-agent")
            .then(|| value.to_string())
    }
}

#[test]
fn browser_match_nocase_is_set_env_if_nocase_on_user_agent() {
    let ht = Htaccess::parse(
        "BrowserMatchNoCase \"badbot\" bad_bot\nOrder allow,deny\nAllow from all\nDeny from env=bad_bot\n",
    )
    .unwrap();
    let env = env_for(&ht, "/x", &user_agent("BadBot/1.0"));
    assert_eq!(env, [("bad_bot".to_string(), "1".to_string())]);
    assert_eq!(decide(&ht, "/x", &env), AccessDecision::Denied);
    let env = env_for(&ht, "/x", &user_agent("Mozilla/5.0"));
    assert_eq!(decide(&ht, "/x", &env), AccessDecision::Granted);
    // The User-Agent read is a memo vary dimension, like SetEnvIf User-Agent.
    assert!(ht.memo.vary_headers.iter().any(|h| h == "user-agent"));
}

#[test]
fn browser_match_is_case_sensitive() {
    let ht = Htaccess::parse("BrowserMatch ^Bad bad_bot\n").unwrap();
    assert_eq!(env_for(&ht, "/x", &user_agent("BadBot")).len(), 1);
    assert!(env_for(&ht, "/x", &user_agent("badbot")).is_empty());
}

#[test]
fn bang_assignment_unsets_the_variable() {
    let ht = Htaccess::parse(
        "SetEnvIf Request_URI \"^/pub\" ok\nSetEnvIf Request_URI \"^/pub/secret\" !ok\nOrder deny,allow\nDeny from all\nAllow from env=ok\n",
    )
    .unwrap();
    let env = env_for(&ht, "/pub/secret/x", &|_| None);
    assert_eq!(
        env,
        [
            ("ok".to_string(), "1".to_string()),
            ("!ok".to_string(), String::new()),
        ]
    );
    assert_eq!(decide(&ht, "/pub/secret/x", &env), AccessDecision::Denied);
    let env = env_for(&ht, "/pub/open", &|_| None);
    assert_eq!(decide(&ht, "/pub/open", &env), AccessDecision::Granted);
}

#[test]
fn env_assignment_decodes_the_bang_spelling() {
    assert_eq!(
        EnvAssignment::classify("!ok", ""),
        EnvAssignment::Unset { name: "ok" }
    );
    assert_eq!(
        EnvAssignment::classify("ok", "1"),
        EnvAssignment::Set {
            name: "ok",
            value: "1"
        }
    );
}

#[test]
fn files_scoped_set_env_if_runs_only_for_that_file() {
    let ht = Htaccess::parse(
        "<Files \"public.html\">\n  SetEnvIf Request_URI . open_it\n</Files>\nOrder deny,allow\nDeny from all\nAllow from env=open_it\n",
    )
    .unwrap();
    assert!(ht.has_scoped_set_env);
    let env = env_for(&ht, "/secret.txt", &|_| None);
    assert!(env.is_empty(), "{env:?}");
    assert_eq!(decide(&ht, "/secret.txt", &env), AccessDecision::Denied);
    let env = env_for(&ht, "/public.html", &|_| None);
    assert_eq!(decide(&ht, "/public.html", &env), AccessDecision::Granted);
    // A path-only scope is covered by the memo key: no new blocker.
    let only_scope =
        Htaccess::parse("<FilesMatch \"\\.css$\">\n  SetEnvIf Request_URI . css\n</FilesMatch>\n")
            .unwrap();
    assert!(only_scope.memo.eligible, "{:?}", only_scope.memo.blockers);
}

#[test]
fn if_scoped_set_env_if_matches_the_scope_path() {
    let ht = Htaccess::parse(
        "<If \"%{REQUEST_URI} =~ m#^/api/#\">\n  SetEnvIf Request_URI . api\n</If>\n",
    )
    .unwrap();
    assert_eq!(env_for(&ht, "/api/x", &|_| None).len(), 1);
    assert!(env_for(&ht, "/web/x", &|_| None).is_empty());
    // The pipeline supplies the normalized path, which decides the scope.
    let attrs = ReqAttrs {
        request_uri: "/api/../web/x",
        scope_path: "/web/x",
        ..Default::default()
    };
    assert!(ht.eval_set_env(&attrs).unwrap().is_empty());
}

#[test]
fn set_env_if_in_an_unmodelled_container_fails_closed() {
    for text in [
        "<If \"%{HTTP_HOST} == 'a'\">\n  SetEnvIf Request_URI . ok\n</If>\n",
        "<IfDefine X>\n  SetEnvIf Request_URI . ok\n</IfDefine>\n",
    ] {
        assert!(
            matches!(Htaccess::parse(text), Err(RewriteError::Malformed { .. })),
            "{text}"
        );
    }
    // IfModule and Limit stay transparent, as in Apache.
    for text in [
        "<IfModule mod_setenvif.c>\n  SetEnvIf Request_URI . ok\n</IfModule>\n",
        "<Limit GET>\n  SetEnvIf Request_URI . ok\n</Limit>\n",
    ] {
        let ht = Htaccess::parse(text).unwrap();
        assert_eq!(env_for(&ht, "/x", &|_| None).len(), 1, "{text}");
    }
}

#[test]
fn rewrite_bang_env_flag_unsets_the_variable() {
    let rs = RuleSet::parse(
        "RewriteEngine On\nRewriteRule ^secret - [E=!ok]\nRewriteRule ^ - [E=seen:%{ENV:ok}]\n",
    )
    .unwrap();
    let seed = vec![("ok".to_string(), "1".to_string())];
    let mut input = RewriteInput::new("/secret", "/nonexistent");
    input.per_directory_prefix = Some(String::new());
    input.env_seed = Some(&seed);
    let out = evaluate(&rs, &input);
    let env = out.env();
    assert!(
        env.iter().any(|(k, v)| k == "!ok" && v.is_empty()),
        "{env:?}"
    );
    assert!(!env.iter().any(|(k, _)| k == "ok"), "{env:?}");
    // Later rules in the same pass no longer see the seeded value.
    assert!(
        env.iter().any(|(k, v)| k == "seen" && v.is_empty()),
        "{env:?}"
    );

    // A set after the unset wins again.
    let rs =
        RuleSet::parse("RewriteEngine On\nRewriteRule ^ - [E=!ok]\nRewriteRule ^ - [E=ok:2]\n")
            .unwrap();
    let out = evaluate(&rs, &input);
    assert_eq!(out.env(), [("ok".to_string(), "2".to_string())]);
}

#[test]
fn malformed_set_env_if_fails_the_file_closed() {
    // A dropped SetEnvIf feeding `Deny from env=` would grant everyone (#786).
    for line in [
        "SetEnvIf User-Agent \"(unclosed\" bad_bot",
        "SetEnvIf User-Agent badbot",
        "BrowserMatch \"[z-a]\" bad_bot",
    ] {
        let text = format!("{line}\nOrder allow,deny\nAllow from all\nDeny from env=bad_bot\n");
        assert!(hj_rewrite::Htaccess::parse(&text).is_err(), "{line}");
    }
}

fn env_with_base(
    ht: &Htaccess,
    header: &dyn Fn(&str) -> Option<String>,
    base: &[(&str, &str)],
) -> Vec<(String, String)> {
    let env = |name: &str| {
        base.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.to_string())
    };
    let attrs = ReqAttrs {
        request_uri: "/x",
        method: "GET",
        header_lookup: Some(HeaderLookup(header)),
        env_lookup: Some(HeaderLookup(&env)),
        ..Default::default()
    };
    ht.eval_set_env(&attrs).unwrap()
}

#[test]
fn non_header_attribute_falls_back_to_earlier_env_assignments() {
    // #794: mod_setenvif reads subprocess_env when no header of that name exists.
    let ht = Htaccess::parse(
        "SetEnvIf User-Agent BadBot bad\nSetEnvIf bad ^1$ block\nOrder allow,deny\nAllow from all\nDeny from env=block\n",
    )
    .unwrap();
    let ua = |n: &str| {
        n.eq_ignore_ascii_case("user-agent")
            .then(|| "BadBot/1".to_string())
    };
    let env = env_with_base(&ht, &ua, &[]);
    assert!(env.iter().any(|(k, _)| k == "block"), "{env:?}");
    let set = |n: &str| env.iter().any(|(k, _)| k == n);
    let subject = AccessSubject {
        client_ip: Some("203.0.113.9".parse().unwrap()),
        env_set: Some(&set),
    };
    assert_eq!(
        ht.access_decision_for("/x", "GET", &subject),
        AccessDecision::Denied
    );
    // A benign agent sets neither.
    let env = env_with_base(&ht, &|_| None, &[]);
    assert!(env.is_empty(), "{env:?}");
}

#[test]
fn env_fallback_is_ordered_honors_unsets_and_prefers_headers() {
    // A rule only sees assignments made before it.
    let ht = Htaccess::parse("SetEnvIf flag . seen\nSetEnvIf Request_URI . flag=1\n").unwrap();
    assert_eq!(
        env_with_base(&ht, &|_| None, &[]),
        [("flag".to_string(), "1".to_string())]
    );
    // An unset hides both an earlier assignment and the base env.
    let ht = Htaccess::parse(
        "SetEnvIf Request_URI . flag=1\nSetEnvIf Request_URI . !flag\nSetEnvIf flag . seen\n",
    )
    .unwrap();
    let env = env_with_base(&ht, &|_| None, &[("flag", "base")]);
    assert!(!env.iter().any(|(k, _)| k == "seen"), "{env:?}");
    // The base env (server variables, earlier chain files) is visible,
    // case-insensitively, and capture expansion uses the env value.
    let ht = Htaccess::parse("SetEnvIf https ^(on)$ tls=$1\n").unwrap();
    assert_eq!(
        env_with_base(&ht, &|_| None, &[("HTTPS", "on")]),
        [("tls".to_string(), "on".to_string())]
    );
    // A present header wins over an env variable of the same name.
    let ht = Htaccess::parse("SetEnvIf X-Mode ^env$ from_env\nSetEnvIf X-Mode ^hdr$ from_hdr\n")
        .unwrap();
    let hdr = |n: &str| n.eq_ignore_ascii_case("x-mode").then(|| "hdr".to_string());
    let env = env_with_base(&ht, &hdr, &[("X-Mode", "env")]);
    assert_eq!(env, [("from_hdr".to_string(), "1".to_string())]);
    // Specials never fall back to the env.
    let ht = Htaccess::parse("SetEnvIf Request_Method ^env$ odd\n").unwrap();
    assert!(env_with_base(&ht, &|_| None, &[("Request_Method", "env")]).is_empty());
}

#[test]
fn header_name_regex_attribute_fails_closed() {
    // mod_setenvif would match `^X-Evil.*` against header NAMES; httpjet refuses
    // the file instead of silently never setting the variable (#794).
    for line in [
        "SetEnvIf ^X-Evil.* . bad",
        "SetEnvIfNoCase X-(Evil|Bad) . bad",
        "SetEnvIf X.Evil . bad",
    ] {
        let text = format!("{line}\nOrder allow,deny\nAllow from all\nDeny from env=bad\n");
        assert!(
            matches!(Htaccess::parse(&text), Err(RewriteError::Malformed { .. })),
            "{line}"
        );
    }
    assert!(Htaccess::parse("SetEnvIf X-Evil_Header-2 . bad\n").is_ok());
}

#[test]
fn env_attribute_keeps_memo_classification() {
    // The fallback only reads earlier rules' outputs, so a chained rule stays
    // memo-eligible with the header-shaped vary of its own name.
    let ht = Htaccess::parse("SetEnvIf Origin ^https://a$ ok\nSetEnvIf ok ^1$ cors\n").unwrap();
    assert!(ht.memo.eligible, "{:?}", ht.memo.blockers);
    assert_eq!(ht.memo.vary_headers, ["origin", "ok"]);
}

#[test]
fn absent_field_is_tested_as_the_empty_string() {
    // mod_setenvif: a missing header/variable is "", so `^$` matches it.
    let ht = Htaccess::parse(
        "SetEnvIf Referer ^$ noref\nOrder allow,deny\nAllow from all\nDeny from env=noref\n",
    )
    .unwrap();
    let none = |_: &str| None;
    let env = env_for(&ht, "/x", &none);
    assert_eq!(decide(&ht, "/x", &env), AccessDecision::Denied);
    let referer = |n: &str| {
        n.eq_ignore_ascii_case("referer")
            .then(|| "https://a/".to_string())
    };
    let env = env_for(&ht, "/x", &referer);
    assert_ne!(decide(&ht, "/x", &env), AccessDecision::Denied);

    let cookie = Htaccess::parse("SetEnvIf Cookie ^$ guest\n").unwrap();
    assert_eq!(
        cookie.eval_cookie_env(None).unwrap(),
        vec![("guest".to_string(), "1".to_string())]
    );
    assert_eq!(
        cookie.cookie_env(None).unwrap().as_ref(),
        [("guest".to_string(), "1".to_string())]
    );
    assert!(cookie.cookie_env(Some("a=1")).unwrap().is_empty());
}

/// (#979) `<If "%{REQUEST_URI} …">` around a SetEnvIf tests the request path
/// with its trailing `/` ([`ReqAttrs::if_path`]); `<Directory*>` keeps the
/// slash-stripped scope path.
#[test]
fn if_scoped_set_env_if_sees_the_trailing_slash() {
    let ht = Htaccess::parse(
        "<If \"%{REQUEST_URI} =~ m#^/private/$#\">\n  SetEnvIf Request_URI . BLOCK\n</If>\n\
         Order Allow,Deny\nAllow from all\nDeny from env=BLOCK\n",
    )
    .unwrap();
    let attrs = ReqAttrs {
        request_uri: "/private/",
        scope_path: "/private",
        if_path: "/private/",
        ..Default::default()
    };
    let env = ht.eval_set_env(&attrs).unwrap();
    assert_eq!(env, [("BLOCK".to_string(), "1".to_string())]);
    assert_eq!(decide(&ht, "/private", &env), AccessDecision::Denied);
    let file = ReqAttrs {
        request_uri: "/private/x",
        scope_path: "/private/x",
        if_path: "/private/x",
        ..Default::default()
    };
    assert!(ht.eval_set_env(&file).unwrap().is_empty());

    let dir = Htaccess::parse(
        "<DirectoryMatch \"^/private$\">\n  SetEnvIf Request_URI . D\n</DirectoryMatch>\n",
    )
    .unwrap();
    assert_eq!(dir.eval_set_env(&attrs).unwrap().len(), 1);
}

/// (#979) `SetEnv` inside `<If>` sees the trailing `/` too.
#[test]
fn if_scoped_set_env_sees_the_trailing_slash() {
    let ht = Htaccess::parse("<If \"%{REQUEST_URI} =~ m#^/private/$#\">\n  SetEnv P 1\n</If>\n")
        .unwrap();
    assert_eq!(
        hj_rewrite::set_env_assignments([&ht], "/private", "/private/", "index.html"),
        [("P".to_string(), "1".to_string())]
    );
    assert!(
        hj_rewrite::set_env_assignments([&ht], "/private", "/private", "index.html").is_empty()
    );
}

/// `Header` inside `<If>` keeps testing the final (rewritten) path, as Apache
/// does after the internal redirect: the forum's homepage `Link` block matches
/// every front-controller page, never the original request path.
#[test]
fn if_scoped_header_tests_the_rewritten_path() {
    let ht = Htaccess::parse(
        "<If \"%{REQUEST_URI} =~ m#^/(index\\.php)?$#\">\n  Header add Link \"</x>\"\n</If>\n",
    )
    .unwrap();
    let names = |rel_path: &str, request_path: &str| -> Vec<String> {
        hj_rewrite::chain_response_headers([&ht], rel_path, None, request_path, 200, &[])
            .iter()
            .map(|op| op.name().to_string())
            .collect()
    };
    assert_eq!(names("/index.php", "/threads/x.1/"), ["Link"]);
    assert!(names("/threads/x.1", "/threads/x.1/").is_empty());
}
