//! (#977) Shared SetEnvIf evaluation and header lookups are output-identical to
//! the per-directive loop they replace; (#978) parse-time PCRE form.

use std::cell::Cell;

use super::*;
use crate::htaccess::SetEnvIf;

const FORUM: &str = include_str!("../../tests/fixtures/forum_setenvif.htaccess");

/// Env-fallback chains, unsets, spelling variants, scopes and captures around
/// adjacent identical tests, where reuse must and must not happen.
const ADVERSARIAL: &str = "\
SetEnvIf X-A ^$ X-A=1
SetEnvIf X-A ^$ seen
SetEnvIf X-A ^1$ X_A=2
SetEnvIf X-A ^1$ seen_fold
SetEnvIf X-B ^(b+)$ B=$1
SetEnvIf X-B ^(b+)$ B2=$1
SetEnvIf X-B ^(b+)$ B3
SetEnvIf X-C c C1
SetEnvIf X-C c !X-C
SetEnvIf X-C c C3
SetEnvIf x-c c C4
SetEnvIfNoCase X-D d D1
SetEnvIf X-D (?i)d D2
<If \"%{REQUEST_URI} =~ m#^/s/#\">
SetEnvIf X-E e E1
</If>
SetEnvIf X-E e E2
<If \"%{REQUEST_URI} =~ m#^/s/#\">
SetEnvIf X-E e E3
SetEnvIf X-E e E4
</If>
SetEnvIf X_F f F1
SetEnvIf X_F f F2
SetEnvIf Request_URI ^/s/ X-G=1
SetEnvIf X-G 1 G1
SetEnvIf X-G 1 G2
SetEnvIf Origin ^https://a$ ok
SetEnvIf ok ^1$ cors
SetEnvIf ok ^1$ cors2
";

/// The `SetEnvIf` loop before #977/#978: each directive resolves its own
/// subject and runs `fancy_regex` captures compiled from its source.
struct Reference {
    regexes: Vec<fancy_regex::Regex>,
}

impl Reference {
    fn new(h: &Htaccess) -> Reference {
        Reference {
            regexes: h
                .set_env_if
                .iter()
                .map(|s| fancy_regex::Regex::new(&s.regex_src).unwrap())
                .collect(),
        }
    }

    fn resolve<'a>(attrs: &ReqAttrs<'a>, attribute: &str) -> Option<Cow<'a, str>> {
        let eq = |s: &str| attribute.eq_ignore_ascii_case(s);
        if eq("request_uri") {
            Some(Cow::Borrowed(attrs.request_uri))
        } else if eq("request_method") {
            Some(Cow::Borrowed(attrs.method))
        } else if eq("request_protocol") {
            Some(Cow::Borrowed(attrs.protocol))
        } else if eq("query_string") {
            Some(Cow::Borrowed(attrs.query_string))
        } else if eq("remote_addr") || eq("remote_host") {
            Some(Cow::Borrowed(attrs.remote_addr))
        } else if eq("server_addr") {
            Some(Cow::Borrowed(attrs.server_addr))
        } else if eq("host") || eq("server_name") {
            Some(Cow::Borrowed(attrs.host))
        } else {
            attrs.lookup_header(attribute).map(Cow::Owned)
        }
    }

    fn subject(
        rule: &SetEnvIf,
        re: &fancy_regex::Regex,
        subject: &str,
        out: &mut Vec<(String, String)>,
    ) -> Result<(), &'static str> {
        // A NoCase source starts with `(?i)`, which yields no prefix, as before.
        let prefix = crate::rules::extract_literal_prefix(&rule.regex_src, false, false);
        if !prefix.is_empty() && !subject.as_bytes().starts_with(&prefix) {
            return Ok(());
        }
        match re.captures(subject) {
            Ok(Some(caps)) => {
                for (var, value) in &rule.assigns {
                    let value = if var.starts_with('!') {
                        String::new()
                    } else {
                        expand(value, &caps)
                    };
                    out.push((var.clone(), value));
                }
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(_) => Err("SetEnvIf regex failed at match time"),
        }
    }

    fn eval_set_env(
        &self,
        h: &Htaccess,
        attrs: &ReqAttrs<'_>,
    ) -> Result<Vec<(String, String)>, &'static str> {
        let mut out = Vec::new();
        let scope_path = if attrs.scope_path.is_empty() {
            attrs.request_uri
        } else {
            attrs.scope_path
        };
        let if_path = if attrs.if_path.is_empty() {
            scope_path
        } else {
            attrs.if_path
        };
        let scope_basename = attrs.scope_basename.unwrap_or_else(|| basename(scope_path));
        for (s, re) in h.set_env_if.iter().zip(&self.regexes) {
            if !s.scopes.is_empty() && !scopes_match(&s.scopes, scope_path, if_path, scope_basename)
            {
                continue;
            }
            if let Some(subject) = Self::resolve(attrs, &s.attribute) {
                Self::subject(s, re, &subject, &mut out)?;
            } else if let Some(subject) = attrs.resolve_env(&s.attribute, &out) {
                Self::subject(s, re, &subject, &mut out)?;
            } else {
                Self::subject(s, re, "", &mut out)?;
            }
        }
        Ok(out)
    }

    fn eval_cookie_env(
        &self,
        h: &Htaccess,
        cookie: Option<&str>,
    ) -> Result<Vec<(String, String)>, &'static str> {
        let mut out = Vec::new();
        let cookie = cookie.unwrap_or("");
        for (rule, re) in h.set_env_if.iter().zip(&self.regexes) {
            if rule.attribute.eq_ignore_ascii_case("cookie") {
                Self::subject(rule, re, cookie, &mut out)?;
            }
        }
        Ok(out)
    }
}

fn expand(template: &str, caps: &fancy_regex::Captures<'_, str>) -> String {
    if !template.contains('$') {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            match chars.peek() {
                Some('$') => {
                    out.push('$');
                    chars.next();
                }
                Some(d) if d.is_ascii_digit() => {
                    let idx = (*d as u8 - b'0') as usize;
                    chars.next();
                    if let Some(m) = caps.get(idx) {
                        out.push_str(m.as_str());
                    }
                }
                _ => out.push('$'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// xorshift64: a deterministic input stream.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len())]
    }
}

const REAL_COOKIES: &[&str] = &[
    "xf_csrf=abc; xf_session_admin=deadbeef; xf_user=1%2Cx",
    "xf_user=1%2Cabc; xf_style_id=51",
    "xf_style_id=51; xf_session=abc",
    "xf_session=; xf_style_id=51",
    "XF_SESSION=a;xf_style_id=51",
    "xf_session=a; xf_style_id=510",
    "_ga=GA1.2.3; xf_csrf=q; cf_clearance=z",
    "xf_session_admin=1",
    "",
];

fn random_cookie(rng: &mut Rng) -> Option<String> {
    match rng.below(8) {
        0 => return None,
        1 | 2 => return Some(rng.pick(REAL_COOKIES).to_string()),
        _ => {}
    }
    const NAMES: &[&str] = &[
        "xf_user",
        "xf_session",
        "xf_session_admin",
        "xf_style_id",
        "xf_csrf",
        "_ga",
        "cf_clearance",
        "XF_USER",
        "Xf_Style_Id",
        "xf_sessionx",
        "x_xf_user",
        "wf_pref",
    ];
    const VALUES: &[&str] = &[
        "51", "5", "510", "abc", "", "1%2Cx", "deadbeef", "a b", "=51",
    ];
    const SEPS: &[&str] = &["; ", ";", ";\t", ";  ", " ; ", ";;"];
    let mut s = String::new();
    for i in 0..rng.below(6) {
        if i > 0 {
            s.push_str(rng.pick(SEPS));
        }
        s.push_str(rng.pick(NAMES));
        s.push('=');
        s.push_str(rng.pick(VALUES));
    }
    if rng.below(5) == 0 {
        s.push(';');
    }
    Some(s)
}

fn lookup_in<'a>(headers: &'a [(&'static str, String)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    }
}

/// Compare new and reference evaluation over `cases` random requests.
fn differential(text: &str, header_names: &[&'static str], values: &[&str], cases: usize) {
    let h = Htaccess::parse(text).unwrap();
    let reference = Reference::new(&h);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    const URIS: &[&str] = &[
        "/",
        "/beta",
        "/beta/",
        "/data",
        "/data/",
        "/js/",
        "/styles",
        "/data/attachments/",
        "/data/avatars",
        "/chat.php",
        "/tts.php",
        "/feed.rss",
        "/s/x",
        "/s/",
        "/threads/x.1/",
    ];
    const QUERIES: &[&str] = &["", "amp=1", "a=1&amp=1", "amp=10", "x=amp=1", "amp=1&b"];
    const ORIGINS: &[&str] = &[
        "https://windowsforum.com",
        "https://evil.com",
        "https://a.windowsforum.com",
        "https://googleads.g.doubleclick.net",
        "http://windowsforum.com",
        "https://a",
        "",
    ];
    const ENVS: &[&[(&str, &str)]] = &[
        &[],
        &[("HTTPS", "on")],
        &[("origin", "https://windowsforum.com")],
        &[("Cookie", "xf_session_admin=1"), ("X-A", "1")],
        &[("x-c", "c"), ("X-G", "1"), ("ok", "1")],
    ];
    for case in 0..cases {
        let mut headers: Vec<(&'static str, String)> = Vec::new();
        if let Some(cookie) = random_cookie(&mut rng) {
            headers.push(("Cookie", cookie));
        }
        if rng.below(3) > 0 {
            headers.push(("Origin", rng.pick(ORIGINS).to_string()));
        }
        for &name in header_names {
            if rng.below(2) == 0 {
                headers.push((name, rng.pick(values).to_string()));
            }
        }
        let base = ENVS[rng.below(ENVS.len())];
        let env = |name: &str| {
            base.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.to_string())
        };
        let lookup = lookup_in(&headers);
        let uri = rng.pick(URIS);
        let attrs = ReqAttrs {
            request_uri: uri,
            method: "GET",
            protocol: "HTTP/1.1",
            query_string: rng.pick(QUERIES),
            scope_path: uri
                .strip_suffix('/')
                .filter(|p| !p.is_empty())
                .unwrap_or(uri),
            if_path: uri,
            header_lookup: Some(HeaderLookup(&lookup)),
            env_lookup: Some(HeaderLookup(&env)),
            ..Default::default()
        };
        assert_eq!(
            h.eval_set_env(&attrs),
            reference.eval_set_env(&h, &attrs),
            "case {case}: {headers:?} {base:?} {uri}"
        );
        let cookie = headers
            .iter()
            .find(|(k, _)| *k == "Cookie")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            h.eval_cookie_env(cookie),
            reference.eval_cookie_env(&h, cookie),
            "case {case}: {cookie:?}"
        );
        assert_eq!(
            h.cookie_env(cookie).map(Cow::into_owned),
            reference.eval_cookie_env(&h, cookie),
            "case {case}: {cookie:?}"
        );
    }
}

#[test]
fn forum_set_env_if_matches_the_reference_loop() {
    differential(FORUM, &[], &[], 4000);
}

#[test]
fn adversarial_set_env_if_matches_the_reference_loop() {
    let h = Htaccess::parse(ADVERSARIAL).unwrap();
    let reuse: Vec<usize> = (0..h.set_env_if.len())
        .filter(|&i| h.set_env_if[i].reuse_prev)
        .collect();
    // B3 (after a capture rule), !X-C, D2, E4 (equal `<If>`), F2, G2, cors2.
    assert_eq!(reuse, [6, 8, 12, 16, 18, 21, 24]);
    differential(
        ADVERSARIAL,
        &["X-A", "X-B", "X-C", "X-D", "X-E", "X-F", "X-G", "ok"],
        &["", "1", "b", "bb", "c", "C", "d", "D", "e", "f", "x"],
        4000,
    );
}

#[test]
fn forum_parse_time_facts() {
    let h = Htaccess::parse(FORUM).unwrap();
    let reuse: Vec<usize> = (0..h.set_env_if.len())
        .filter(|&i| h.set_env_if[i].reuse_prev)
        .collect();
    // beta, xf_session_admin, and the WF5 preview lookahead pairs.
    assert_eq!(reuse, [7, 9, 11]);
    let caps: Vec<&str> = h
        .set_env_if
        .iter()
        .filter(|s| s.needs_caps)
        .map(|s| s.attribute.as_str())
        .collect();
    assert_eq!(caps, ["Origin"]);
    assert!(!h.set_env_if_reads_connection());
    assert_eq!(
        h.cookie_env(None).unwrap().as_ref(),
        h.eval_cookie_env(None).unwrap()
    );
}

#[test]
fn adjacent_identical_rules_share_one_evaluation() {
    let h = Htaccess::parse("SetEnvIf X-Foo ^bar$ A=1\nSetEnvIf X-Foo ^bar$ B=1\n").unwrap();
    assert!(h.set_env_if[1].reuse_prev);
    let header_calls = Cell::new(0);
    let env_calls = Cell::new(0);
    let header = |_: &str| {
        header_calls.set(header_calls.get() + 1);
        None
    };
    let env = |n: &str| {
        env_calls.set(env_calls.get() + 1);
        n.eq_ignore_ascii_case("x-foo").then(|| "bar".to_string())
    };
    let attrs = ReqAttrs {
        header_lookup: Some(HeaderLookup(&header)),
        env_lookup: Some(HeaderLookup(&env)),
        ..Default::default()
    };
    assert_eq!(
        h.eval_set_env(&attrs).unwrap(),
        [
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "1".to_string())
        ]
    );
    // One header read, and the second directive reused the first's env test.
    assert_eq!((header_calls.get(), env_calls.get()), (1, 1));

    // The forum's four Cookie directives copy the Cookie header once.
    let forum = Htaccess::parse(FORUM).unwrap();
    let reads = std::cell::RefCell::new(Vec::new());
    let cookie = |n: &str| {
        reads.borrow_mut().push(n.to_string());
        n.eq_ignore_ascii_case("cookie")
            .then(|| "xf_user=1; xf_style_id=51; xf_session_admin=1".to_string())
    };
    let attrs = ReqAttrs {
        request_uri: "/",
        header_lookup: Some(HeaderLookup(&cookie)),
        ..Default::default()
    };
    let env = forum.eval_set_env(&attrs).unwrap();
    assert_eq!(*reads.borrow(), ["Origin", "Cookie"]);
    assert_eq!(
        env.iter().filter(|(k, _)| k == "cache-vary").count(),
        2,
        "{env:?}"
    );
}

#[test]
fn reuse_respects_env_fallback_writes() {
    // The first directive's own assignment is the second one's subject, so the
    // second tests "1" against `^$`: `seen` is not set (unchanged behavior).
    let h = Htaccess::parse("SetEnvIf X-A ^$ X-A=1\nSetEnvIf X-A ^$ seen\n").unwrap();
    assert!(!h.set_env_if[1].reuse_prev);
    let attrs = ReqAttrs::default();
    let got = h.eval_set_env(&attrs).unwrap();
    assert_eq!(got, [("X-A".to_string(), "1".to_string())]);
    assert_eq!(Ok(got), Reference::new(&h).eval_set_env(&h, &attrs));

    // Conservative for unsets and for `_`/`-` spellings of the attribute.
    for text in [
        "SetEnvIf X-A ^$ !X-A\nSetEnvIf X-A ^$ seen\n",
        "SetEnvIf X-A ^$ x_a=1\nSetEnvIf X-A ^$ seen\n",
        "SetEnvIf X-A ^$ A\nSetEnvIf x-a ^$ seen\n",
        "SetEnvIf X-A ^(.*)$ A\nSetEnvIf X-A ^(.*)$ seen=$1\n",
    ] {
        let h = Htaccess::parse(text).unwrap();
        assert!(!h.set_env_if[1].reuse_prev, "{text}");
    }
}

#[test]
fn connection_attributes_are_flagged() {
    for (text, reads) in [
        ("SetEnvIf Remote_Addr ^1 a\n", true),
        ("SetEnvIf remote_host ^1 a\n", true),
        ("SetEnvIf Server_Addr ^1 a\n", true),
        ("SetEnvIf HOST ^a a\n", true),
        ("SetEnvIf Server_Name ^a a\n", true),
        (
            "SetEnvIf Request_URI ^/ a\nSetEnvIf User-Agent x a\n",
            false,
        ),
    ] {
        assert_eq!(
            Htaccess::parse(text).unwrap().set_env_if_reads_connection(),
            reads,
            "{text}"
        );
    }
}

#[test]
fn cached_absent_cookie_result_is_returned_as_is() {
    let mut h = Htaccess::parse("SetEnvIf Cookie ^$ guest\n").unwrap();
    assert_eq!(
        h.cookie_env_absent,
        Some(Ok(vec![("guest".to_string(), "1".to_string())]))
    );
    h.cookie_env_absent = Some(Err("boom"));
    assert_eq!(h.cookie_env(None).map(Cow::into_owned), Err("boom"));
    // A present Cookie is always evaluated live.
    assert!(h.cookie_env(Some("a=1")).unwrap().is_empty());
}

#[test]
fn set_env_if_compiles_the_pcre_form() {
    let h = Htaccess::parse("SetEnvIf Request_URI \"^\\<a\\>\" x\n").unwrap();
    let rule = &h.set_env_if[0];
    assert_eq!(rule.literal_prefix.as_ref(), b"<a>");
    assert!(matches!(rule.regex, crate::rules::CompiledRegex::Fast(_)));
    let attrs = |uri| ReqAttrs {
        request_uri: uri,
        ..Default::default()
    };
    assert!(h.eval_set_env(&attrs("/<a>")).unwrap().is_empty());
    assert_eq!(
        h.eval_set_env(&attrs("<a>/")).unwrap(),
        [("x".to_string(), "1".to_string())]
    );
}
