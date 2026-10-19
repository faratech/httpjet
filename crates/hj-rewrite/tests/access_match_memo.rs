//! The per-file access-match memo must be invisible: every decision a warm memo returns
//! equals a fresh parse's (empty memo) decision, and a memo hit still re-judges the
//! subject (client IP / env) instead of replaying an earlier request's verdict.

use std::net::IpAddr;

use hj_rewrite::{AccessDecision, AccessSubject, Htaccess};

const RULES: &str = r#"
<FilesMatch "\.(env|log|bak)$">
    Require all denied
</FilesMatch>
<Files "auth.md">
    Require all granted
</Files>
<If "%{REQUEST_URI} =~ m#^/internal/#">
    Require all denied
</If>
<If "%{REQUEST_URI} !~ m#^/(index\.php)?$# && %{REQUEST_URI} =~ m#^/admin#">
    Require all denied
</If>
<Files "status.php">
    Order Deny,Allow
    Deny from all
    Allow from 127.0.0.1
    Allow from env=trusted_probe
</Files>
<Limit POST PUT>
    Order Allow,Deny
    Allow from all
    Deny from 203.0.113.0/24
</Limit>
"#;

fn decide(h: &Htaccess, path: &str, method: &str, ip: &str, trusted: bool) -> AccessDecision {
    let ip: IpAddr = ip.parse().unwrap();
    let env_set = |name: &str| trusted && name == "trusted_probe";
    let subject = AccessSubject {
        client_ip: Some(ip),
        env_set: Some(&env_set),
    };
    let rel = match path.strip_suffix('/') {
        Some(p) if !p.is_empty() => p,
        _ => path,
    };
    h.access_decision_for_request(rel, path, method, &subject)
}

#[test]
fn warm_memo_decisions_equal_fresh_parse_decisions() {
    let warm = Htaccess::parse(RULES).unwrap();
    let paths = [
        "/",
        "/index.php",
        "/x.env",
        "/logs/app.log",
        "/auth.md",
        "/docs/auth.md",
        "/internal/",
        "/internal/a.txt",
        "/admin",
        "/admin/x.php",
        "/administer/",
        "/status.php",
        "/threads/a-thread.123/",
        "/robots.txt",
        "/a.bak/",
    ];
    let methods = ["GET", "HEAD", "POST", "PUT", "DELETE"];
    let subjects = [
        ("127.0.0.1", false),
        ("198.51.100.7", false),
        ("198.51.100.7", true),
        ("203.0.113.9", false),
    ];
    for round in 0..3 {
        for path in paths {
            for method in methods {
                for (ip, trusted) in subjects {
                    let fresh = Htaccess::parse(RULES).unwrap();
                    assert_eq!(
                        decide(&warm, path, method, ip, trusted),
                        decide(&fresh, path, method, ip, trusted),
                        "round {round}: {method} {path} from {ip} trusted={trusted}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_memo_hit_still_judges_the_current_subject() {
    let h = Htaccess::parse(RULES).unwrap();
    // Same path/method (one memo key), different subjects: the verdict must follow the
    // subject, not the first request that populated the entry.
    assert_eq!(
        decide(&h, "/status.php", "GET", "198.51.100.7", false),
        AccessDecision::Denied
    );
    assert_eq!(
        decide(&h, "/status.php", "GET", "127.0.0.1", false),
        AccessDecision::Granted
    );
    assert_eq!(
        decide(&h, "/status.php", "GET", "198.51.100.7", true),
        AccessDecision::Granted
    );
    assert_eq!(
        decide(&h, "/status.php", "GET", "198.51.100.7", false),
        AccessDecision::Denied
    );
    assert_eq!(
        decide(&h, "/upload", "POST", "203.0.113.9", false),
        AccessDecision::Denied
    );
    assert_ne!(
        decide(&h, "/upload", "POST", "198.51.100.7", false),
        AccessDecision::Denied
    );
}
