//! `<Limit>`/`<LimitExcept>` nesting and method names (#791 #792 #793): Apache
//! refuses scoping sections inside `<Limit>`, numbers `HEAD` as `GET`, and only
//! accepts its built-in, case-sensitive method names in `.htaccess`.

use hj_rewrite::{AccessDecision, AccessSubject, Htaccess, RewriteError};

fn ip(addr: &str) -> AccessSubject<'static> {
    AccessSubject {
        client_ip: Some(addr.parse().unwrap()),
        env_set: None,
    }
}

fn decide(ht: &Htaccess, path: &str, method: &str) -> AccessDecision {
    ht.access_decision_for(path, method, &ip("198.51.100.1"))
}

fn malformed(text: &str) -> bool {
    matches!(Htaccess::parse(text), Err(RewriteError::Malformed { .. }))
}

#[test]
fn scoping_sections_inside_limit_are_a_parse_error() {
    // The #791 crash repro: two Files blocks inside one Limit.
    assert!(malformed(
        "<Limit GET>\n<Files a.txt>\nDeny from all\n</Files>\n<Files b.txt>\nDeny from all\n</Files>\n</Limit>\n"
    ));
    for inner in [
        "<Files a.txt>",
        "<FilesMatch \"\\.txt$\">",
        "<Directory /x>",
        "<DirectoryMatch \"^/x\">",
        "<If \"%{REQUEST_URI} =~ m#^/a#\">",
    ] {
        let open = inner.split([' ', '>']).next().unwrap();
        let close = format!("</{}>", &open[1..]);
        for limit in ["Limit GET", "LimitExcept POST"] {
            let tag = limit.split(' ').next().unwrap();
            let text = format!("<{limit}>\n{inner}\nDeny from all\n{close}\n</{tag}>\n");
            assert!(malformed(&text), "{text}");
        }
        let text = format!(
            "<IfModule x>\n<Limit GET>\n<IfModule y>\n{inner}\n{close}\n</IfModule>\n</Limit>\n</IfModule>\n"
        );
        assert!(malformed(&text), "{text}");
    }
    // An Else following an If chain is equally a scope.
    assert!(malformed(
        "<If \"%{REQUEST_URI} =~ m#^/a#\">\n</If>\n<Limit GET>\n<Else>\n</Else>\n</Limit>\n"
    ));
}

#[test]
fn limit_inside_scoping_sections_stays_supported() {
    let ht = Htaccess::parse(
        "<Files a.txt>\n<Limit GET>\nDeny from all\n</Limit>\n</Files>\n<Files b.txt>\n<Limit POST>\nDeny from all\n</Limit>\n</Files>\n",
    )
    .unwrap();
    assert_eq!(decide(&ht, "/a.txt", "GET"), AccessDecision::Denied);
    assert_eq!(decide(&ht, "/a.txt", "POST"), AccessDecision::NoOpinion);
    assert_eq!(decide(&ht, "/b.txt", "POST"), AccessDecision::Denied);
    assert_eq!(decide(&ht, "/b.txt", "GET"), AccessDecision::NoOpinion);
}

#[test]
fn each_block_keeps_its_own_limit_slots() {
    // #792: two blocks with Limit sections; each deny must stay on its method.
    let ht = Htaccess::parse(
        "<Limit POST>\nDeny from all\n</Limit>\n<Files a.txt>\n<Limit GET>\nDeny from all\n</Limit>\n<Limit POST>\nAllow from all\n</Limit>\n</Files>\n",
    )
    .unwrap();
    assert_eq!(decide(&ht, "/a.txt", "GET"), AccessDecision::Denied);
    assert_eq!(decide(&ht, "/b.txt", "POST"), AccessDecision::Denied);
    assert_eq!(decide(&ht, "/b.txt", "GET"), AccessDecision::NoOpinion);
}

#[test]
fn limit_head_covers_get_and_get_covers_head() {
    let ht = Htaccess::parse("<Limit HEAD>\nDeny from all\n</Limit>\n").unwrap();
    assert_eq!(decide(&ht, "/x", "GET"), AccessDecision::Denied);
    assert_eq!(decide(&ht, "/x", "HEAD"), AccessDecision::Denied);
    assert_eq!(decide(&ht, "/x", "POST"), AccessDecision::NoOpinion);

    let ht = Htaccess::parse("<Limit GET>\nRequire all denied\n</Limit>\n").unwrap();
    assert_eq!(decide(&ht, "/x", "HEAD"), AccessDecision::Denied);
    let ht = Htaccess::parse("<Limit HEAD>\nRequire all denied\n</Limit>\n").unwrap();
    assert_eq!(decide(&ht, "/x", "GET"), AccessDecision::Denied);

    // LimitExcept HEAD excludes GET as well.
    let ht = Htaccess::parse("<LimitExcept HEAD>\nRequire all denied\n</LimitExcept>\n").unwrap();
    assert_eq!(decide(&ht, "/x", "GET"), AccessDecision::NoOpinion);
    assert_eq!(decide(&ht, "/x", "POST"), AccessDecision::Denied);
    let ht = Htaccess::parse("<LimitExcept HEAD>\nDeny from all\n</LimitExcept>\n").unwrap();
    assert_eq!(decide(&ht, "/x", "GET"), AccessDecision::NoOpinion);
    assert_eq!(decide(&ht, "/x", "PUT"), AccessDecision::Denied);
}

#[test]
fn unknown_or_lowercase_methods_are_a_parse_error() {
    for text in [
        "<Limit get post>\nDeny from all\n</Limit>\n",
        "<Limit GET post>\nRequire all denied\n</Limit>\n",
        "<LimitExcept Get>\nDeny from all\n</LimitExcept>\n",
        "<Limit BREW>\nDeny from all\n</Limit>\n",
        "<Limit TRACE>\nDeny from all\n</Limit>\n",
    ] {
        assert!(malformed(text), "{text}");
    }
    // Built-ins, including WebDAV names and LimitExcept TRACE, are accepted.
    for text in [
        "<Limit GET POST PUT DELETE OPTIONS PATCH>\nDeny from all\n</Limit>\n",
        "<Limit PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK>\nDeny from all\n</Limit>\n",
        "<LimitExcept GET TRACE>\nDeny from all\n</LimitExcept>\n",
    ] {
        assert!(Htaccess::parse(text).is_ok(), "{text}");
    }
}

/// Deterministic xorshift so the fuzz corpus is reproducible without a dev-dep.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[(self.next() % items.len() as u64) as usize]
    }
}

const OPENERS: &[(&str, &str)] = &[
    ("<IfModule mod_x.c>", "IfModule"),
    ("<Limit GET>", "Limit"),
    ("<Limit POST PUT>", "Limit"),
    ("<Limit HEAD>", "Limit"),
    ("<LimitExcept GET>", "LimitExcept"),
    ("<Files a.txt>", "Files"),
    ("<Files b.txt>", "Files"),
    ("<FilesMatch \"\\.php$\">", "FilesMatch"),
    ("<If \"%{REQUEST_URI} =~ m#^/a#\">", "If"),
    ("<ElseIf \"%{REQUEST_URI} =~ m#^/b#\">", "ElseIf"),
    ("<Else>", "Else"),
    ("<Directory /a>", "Directory"),
    ("<DirectoryMatch \"^/b\">", "DirectoryMatch"),
    ("<RequireAny>", "RequireAny"),
];

const BODIES: &[&str] = &[
    "Order Deny,Allow",
    "Order Allow,Deny",
    "Deny from all",
    "Allow from all",
    "Allow from 10.0.0.0/8",
    "Deny from env=bad",
    "Require all denied",
    "Require all granted",
    "SetEnvIf Request_URI . bad",
    "Header set X-A 1",
];

fn random_file(rng: &mut Rng) -> String {
    let mut out = String::new();
    let mut stack: Vec<&str> = Vec::new();
    for _ in 0..(rng.next() % 24) {
        match rng.next() % 3 {
            0 if stack.len() < 5 => {
                let (open, close) = OPENERS[(rng.next() % OPENERS.len() as u64) as usize];
                out.push_str(open);
                stack.push(close);
            }
            1 if !stack.is_empty() => {
                // Occasionally close out of order to exercise the balance check.
                let close = if rng.next().is_multiple_of(8) {
                    stack.remove(0)
                } else {
                    stack.pop().unwrap()
                };
                out.push_str(&format!("</{close}>"));
            }
            _ => out.push_str(rng.pick(BODIES)),
        }
        out.push('\n');
    }
    // Usually balance the file so the deeper parser paths run.
    if !rng.next().is_multiple_of(4) {
        while let Some(close) = stack.pop() {
            out.push_str(&format!("</{close}>\n"));
        }
    }
    out
}

#[test]
fn random_section_nestings_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut parsed = 0;
    for _ in 0..4_000 {
        let text = random_file(&mut rng);
        let result = std::panic::catch_unwind(|| {
            if let Ok(ht) = Htaccess::parse(&text) {
                for path in ["/a.txt", "/b.txt", "/x.php", "/a/y", "/b/z"] {
                    for method in ["GET", "HEAD", "POST", "PUT"] {
                        let _ = decide(&ht, path, method);
                    }
                }
                true
            } else {
                false
            }
        });
        match result {
            Ok(ok) => parsed += usize::from(ok),
            Err(_) => panic!("parser panicked on:\n{text}"),
        }
    }
    // The corpus must reach the evaluation paths, not only parse errors.
    assert!(parsed > 200, "only {parsed} files parsed");
}

#[test]
fn scoping_or_method_section_inside_a_require_container_fails_closed() {
    // Its grant would otherwise widen to every method and path (#800).
    for inner in [
        "<Limit GET>\nRequire all granted\n</Limit>",
        "<LimitExcept POST>\nRequire all granted\n</LimitExcept>",
        "<Files public.txt>\nRequire all granted\n</Files>",
        "<FilesMatch \"^pub\">\nRequire all granted\n</FilesMatch>",
        "<If \"%{REQUEST_URI} =~ m#^/public/#\">\nRequire all granted\n</If>",
    ] {
        for container in ["RequireAny", "RequireAll"] {
            let text = format!(
                "Require all denied\n<{container}>\nRequire ip 10.0.0.0/8\n{inner}\n</{container}>\n"
            );
            assert!(hj_rewrite::Htaccess::parse(&text).is_err(), "{text}");
        }
    }
    // A Require container inside <Limit> keeps working.
    hj_rewrite::Htaccess::parse(
        "<Limit POST>\n<RequireAny>\nRequire ip 10.0.0.0/8\n</RequireAny>\n</Limit>\n",
    )
    .unwrap();
}
