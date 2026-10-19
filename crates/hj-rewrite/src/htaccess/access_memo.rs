//! Per-file memo of which `access_rules` entries match a request.
//!
//! Matching (`AccessRule::matches`) is a pure function of the rel/request paths and
//! the method: the request subject (client IP, env) only enters `AccessRule::denies`,
//! which the caller still evaluates on every call. A pipeline request asks the same
//! question of the same file several times (pre/post rewrite, script target, scoped
//! auth) and every request to a front controller asks it about the same script, so
//! the regex scan is memoized here. The memo lives inside the parsed `Htaccess`: an
//! edited file reparses into a fresh, empty memo, so an entry can never outlive the
//! rules it indexes. Attacker-chosen paths are bounded by a per-shard cap (a full
//! shard is cleared) and a key-length limit.

use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, Mutex};

use rustc_hash::{FxBuildHasher, FxHashMap};

const SHARDS: usize = 16;
const SHARD_CAP: usize = 512;
const MAX_KEY_BYTES: usize = 1024;

#[derive(Default)]
pub struct AccessMatchMemo {
    shards: [Mutex<FxHashMap<Box<str>, Arc<[u16]>>>; SHARDS],
}

impl std::fmt::Debug for AccessMatchMemo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries: usize = self
            .shards
            .iter()
            .map(|s| s.lock().map_or(0, |m| m.len()))
            .sum();
        f.debug_struct("AccessMatchMemo")
            .field("entries", &entries)
            .finish()
    }
}

thread_local! {
    static KEY: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

impl AccessMatchMemo {
    /// The ascending indices of the matching rules for this request, computing them
    /// with `scan` on a miss. `None` (key too long, rule count beyond `u16`) means
    /// "not memoizable": the caller scans directly.
    pub(crate) fn matched(
        &self,
        rel_path: &str,
        request_path: &str,
        method: &str,
        rule_count: usize,
        scan: impl FnOnce() -> Vec<usize>,
    ) -> Option<Arc<[u16]>> {
        if rule_count > usize::from(u16::MAX)
            || rel_path.len() + request_path.len() + method.len() > MAX_KEY_BYTES
        {
            return None;
        }
        KEY.with(|k| {
            let mut key = k.borrow_mut();
            key.clear();
            // Length prefixes make the concatenation injective.
            use std::fmt::Write;
            let _ = write!(
                key,
                "{}:{method}{}:{rel_path}{request_path}",
                method.len(),
                rel_path.len()
            );
            let mut h = FxBuildHasher.build_hasher();
            h.write(key.as_bytes());
            let shard = self.shards.get((h.finish() as usize) % SHARDS)?;
            if let Some(hit) = shard.lock().ok()?.get(key.as_str()) {
                return Some(hit.clone());
            }
            let indices: Arc<[u16]> = scan()
                .into_iter()
                .map(|i| u16::try_from(i).unwrap_or(u16::MAX))
                .collect();
            let mut map = shard.lock().ok()?;
            if map.len() >= SHARD_CAP {
                map.clear();
            }
            map.insert(key.as_str().into(), indices.clone());
            Some(indices)
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().map_or(0, |m| m.len()))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memoizes_per_key_and_scans_once() {
        let memo = AccessMatchMemo::default();
        let mut scans = 0;
        for _ in 0..3 {
            let got = memo
                .matched("/a", "/a/", "GET", 4, || {
                    scans += 1;
                    vec![0, 2]
                })
                .unwrap();
            assert_eq!(&*got, &[0, 2]);
        }
        assert_eq!(scans, 1);
        // Every key component discriminates.
        for (rel, req, m) in [
            ("/a", "/a", "GET"),
            ("/a", "/a/", "POST"),
            ("/b", "/a/", "GET"),
        ] {
            let got = memo.matched(rel, req, m, 4, || vec![3]).unwrap();
            assert_eq!(&*got, &[3], "{rel} {req} {m}");
        }
        assert_eq!(memo.len(), 4);
    }

    #[test]
    fn length_prefixes_keep_split_points_apart() {
        let memo = AccessMatchMemo::default();
        assert_eq!(
            &*memo.matched("/ab", "c", "GET", 1, || vec![0]).unwrap(),
            &[0]
        );
        let other = memo.matched("/a", "bc", "GET", 1, Vec::new).unwrap();
        assert!(other.is_empty(), "same concatenation, different split");
    }

    fn decisions(h: &crate::Htaccess) -> Vec<crate::AccessDecision> {
        let mut out = Vec::new();
        for path in ["/", "/index.php", "/logs/a.log", "/admin/", "/x.md"] {
            let rel = path
                .strip_suffix('/')
                .filter(|p| !p.is_empty())
                .unwrap_or(path);
            for method in ["GET", "HEAD", "POST", "PUT", "DELETE"] {
                for ip in ["127.0.0.1", "198.51.100.7"] {
                    let subject = crate::AccessSubject {
                        client_ip: Some(ip.parse().unwrap()),
                        env_set: None,
                    };
                    out.push(h.access_decision_for_request(rel, path, method, &subject));
                }
            }
        }
        out
    }

    #[test]
    fn files_without_access_rules_never_touch_the_memo() {
        for text in [
            "",
            "RewriteEngine On\nRewriteRule ^a$ /b [L]\n",
            "Header set X-A b\nSetEnvIf Request_URI ^/x X=1\n",
        ] {
            let h = crate::Htaccess::parse(text).unwrap();
            assert!(h.access_rules.is_empty(), "{text:?}");
            assert!(
                decisions(&h)
                    .iter()
                    .all(|d| *d == crate::AccessDecision::NoOpinion),
                "{text:?}"
            );
            assert_eq!(h.access_memo.len(), 0, "{text:?}");
        }
    }

    #[test]
    fn matcher_free_rules_scan_directly_with_memoized_decisions() {
        for text in [
            "Require all denied\n",
            "Order deny,allow\nDeny from all\nAllow from 127.0.0.1\n",
            "<Limit POST PUT>\nRequire all denied\n</Limit>\n",
            "<LimitExcept GET>\nRequire all denied\n</LimitExcept>\nRequire all granted\n",
        ] {
            let h = crate::Htaccess::parse(text).unwrap();
            assert!(!h.access_rules.is_empty(), "{text:?}");
            assert!(!h.access_memo_useful, "{text:?}");
            let direct = decisions(&h);
            assert_eq!(h.access_memo.len(), 0, "{text:?}");
            let mut memoized = crate::Htaccess::parse(text).unwrap();
            memoized.access_memo_useful = true;
            assert_eq!(direct, decisions(&memoized), "{text:?}");
            assert_eq!(direct, decisions(&memoized), "warm: {text:?}");
            assert!(memoized.access_memo.len() > 0, "{text:?}");
        }
    }

    #[test]
    fn path_matchers_keep_the_memo() {
        let text = "<FilesMatch \"\\.log$\">\nRequire all denied\n</FilesMatch>\n\
                    <If \"%{REQUEST_URI} =~ m#^/admin#\">\nRequire all denied\n</If>\n";
        let h = crate::Htaccess::parse(text).unwrap();
        assert!(h.access_memo_useful);
        let warm = decisions(&h);
        assert!(h.access_memo.len() > 0);
        assert_eq!(warm, decisions(&crate::Htaccess::parse(text).unwrap()));
        assert!(warm.contains(&crate::AccessDecision::Denied));
    }

    #[test]
    fn bounded_by_shard_cap_and_key_length() {
        let memo = AccessMatchMemo::default();
        for i in 0..(SHARDS * SHARD_CAP * 3) {
            let p = format!("/p{i}");
            memo.matched(&p, &p, "GET", 1, Vec::new).unwrap();
        }
        assert!(memo.len() <= SHARDS * SHARD_CAP);
        let long = "x".repeat(MAX_KEY_BYTES);
        assert!(memo.matched(&long, "/", "GET", 1, Vec::new).is_none());
        assert!(memo.matched("/", "/", "GET", 70_000, Vec::new).is_none());
    }
}
