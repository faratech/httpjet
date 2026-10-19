//! #1030: `RewriteMap` is not implemented, so a `${map:key}` lookup used to be
//! compared as literal text and a map-driven deny served everyone. A rule set
//! that declares or uses a map now fails to parse: vhost inline rules refuse the
//! config and a `.htaccess` fails closed to the deny-all sentinel.

use std::fs;
use std::time::Duration;

use hj_rewrite::{Htaccess, HtaccessCache, RewriteError, RuleSet};

const MAP_DENY: &str = "RewriteEngine On\n\
     RewriteMap blocked txt:/etc/httpd/blocked.map\n\
     RewriteCond ${blocked:%{REMOTE_ADDR}|ok} ^deny$\n\
     RewriteRule .* - [F]\n";

fn malformed(rules: &str) -> bool {
    matches!(RuleSet::parse(rules), Err(RewriteError::Malformed { .. }))
}

#[test]
fn rewrite_map_directive_is_refused() {
    assert!(malformed(MAP_DENY));
    assert!(malformed("RewriteEngine On\nrewritemap m prg:/bin/cat\n"));
    assert!(malformed("RewriteMap m int:tolower\nRewriteRule ^/a$ /b\n"));
}

#[test]
fn map_lookups_are_refused_wherever_they_expand() {
    for rules in [
        "RewriteCond ${blocked:%{REMOTE_ADDR}|ok} ^deny$\nRewriteRule .* - [F]\n",
        "RewriteCond %{REMOTE_ADDR} =${blocked:x}\nRewriteRule .* - [F]\n",
        "RewriteCond %{QUERY_STRING} -eq ${n:x}\nRewriteRule .* - [F]\n",
        "RewriteRule ^/u/(.*)$ /users/${ids:$1|0} [R=302]\n",
        "RewriteRule ^/a$ - [E=role:${roles:%{REMOTE_USER}}]\n",
        "RewriteRule ^/a$ \"/b?c=${m:d}\"\n",
    ] {
        assert!(malformed(rules), "{rules}");
    }
}

#[test]
fn escaped_dollar_and_ordinary_backrefs_still_parse() {
    for rules in [
        "RewriteRule ^/a$ /b\\${c}\n",
        "RewriteRule ^/(.*)$ /x/$1{y}\n",
        "RewriteCond %{HTTP_HOST} ^(.+)$\nRewriteRule ^/(.*)$ https://%1/$1 [R=301,L]\n",
        "RewriteRule ^/a\\$ /b$\n",
    ] {
        RuleSet::parse(rules).unwrap_or_else(|e| panic!("{rules}: {e}"));
    }
}

#[test]
fn htaccess_with_a_map_fails_closed() {
    for text in [
        MAP_DENY,
        "<IfModule mod_rewrite.c>\nRewriteMap m txt:/x\n</IfModule>\n",
        "RewriteEngine On\nRewriteCond ${blocked:%{REMOTE_ADDR}|ok} ^deny$\nRewriteRule .* - [F]\n",
    ] {
        assert!(
            matches!(Htaccess::parse(text), Err(RewriteError::Malformed { .. })),
            "{text}"
        );
    }

    let dir = std::env::temp_dir().join(format!(
        "hj-rewrite-map-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(".htaccess"), MAP_DENY).unwrap();
    let cache = HtaccessCache::with_revalidate_ttl(Duration::from_secs(0));
    let parsed = cache
        .get_or_load_named(&dir, ".htaccess")
        .expect("a map-using file yields the deny-all sentinel");
    assert!(parsed.is_forbidden("/index.html", "index.html"));
    let _ = fs::remove_dir_all(dir);
}
