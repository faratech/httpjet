//! OLS `VHostMap::mapDomainList` / `addMaping` semantics for a listener's `<vhostMap>` domains.
//!
//! The model keeps each configured domain as written (lowercased); every consumer that turns
//! domains into lookups (the router, the SNI map, `httpjet check`) goes through
//! [`Listener::domain_routes`] so they agree on the three OLS normalizations:
//! a `:port` suffix is ignored, a leading `www.` is stripped for the lookup key (OLS
//! `m_iStripWWW`, on by default — the request side strips it too), and when two vhosts claim
//! the same key on one listener the FIRST mapping wins and the later one is reported.

use std::collections::HashMap;

use crate::model::Listener;

/// One accepted exact-domain mapping. `literal` is the configured domain with any port removed
/// (and IPv6 brackets dropped, matching the request side's normalized Host); `key` is `literal`
/// without a leading `www.`. Both route to `vhost`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRoute {
    /// Index into [`Listener::vhost_map`] of the mapping that declared it.
    pub map_index: usize,
    pub vhost: String,
    pub literal: String,
    pub key: String,
}

/// The accepted exact-domain routes of a listener plus a human-readable warning for each
/// normalization or rejected duplicate (the `*` catch-all is not a route).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainRoutes {
    pub routes: Vec<DomainRoute>,
    pub warnings: Vec<String>,
}

/// Strip a port from a configured domain the way OLS `mapDomainList` does: a bracketed IPv6
/// literal keeps everything up to `]` (returned without brackets, as request hosts are
/// normalized); a single `:` starts a port; a bare multi-colon IPv6 literal has no port.
/// `None` for an unterminated `[`.
fn strip_port(domain: &str) -> Option<&str> {
    if let Some(rest) = domain.strip_prefix('[') {
        return rest.split_once(']').map(|(inner, _)| inner);
    }
    if domain.matches(':').count() == 1 {
        return domain.split_once(':').map(|(host, _)| host);
    }
    Some(domain)
}

impl Listener {
    /// See the [module docs](self).
    pub fn domain_routes(&self) -> DomainRoutes {
        let mut out = DomainRoutes::default();
        let mut owner: HashMap<String, &str> = HashMap::new();
        for (map_index, map) in self.vhost_map.iter().enumerate() {
            for raw in &map.domains {
                let domain = raw.trim().to_ascii_lowercase();
                if domain.is_empty() || domain == "*" {
                    continue;
                }
                let Some(literal) = strip_port(&domain) else {
                    out.warnings.push(format!(
                        "listener {}: vhostMap domain '{domain}' (vhost {}) is missing ']' for an IPv6 literal — ignored",
                        self.name, map.vhost
                    ));
                    continue;
                };
                let has_port = match domain.strip_prefix('[') {
                    Some(rest) => rest
                        .split_once(']')
                        .is_some_and(|(_, tail)| !tail.is_empty()),
                    None => literal.len() != domain.len(),
                };
                if has_port {
                    out.warnings.push(format!(
                        "listener {}: vhostMap domain '{domain}' (vhost {}) carries a port — the port is ignored and it maps '{literal}'",
                        self.name, map.vhost
                    ));
                }
                let key = literal.strip_prefix("www.").unwrap_or(literal);
                if key.is_empty() {
                    continue;
                }
                match owner.get(key) {
                    Some(first) if *first != map.vhost => {
                        out.warnings.push(format!(
                            "listener {}: vhostMap domain '{domain}' is already mapped to vhost {first} — the later mapping to vhost {} is ignored (the first wins, as in OLS)",
                            self.name, map.vhost
                        ));
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        owner.insert(key.to_string(), map.vhost.as_str());
                    }
                }
                out.routes.push(DomainRoute {
                    map_index,
                    vhost: map.vhost.clone(),
                    literal: literal.to_string(),
                    key: key.to_string(),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{Listener, VhostMap};

    fn listener(maps: &[(&str, &[&str])]) -> Listener {
        Listener {
            name: "l".into(),
            address: "*:80".into(),
            secure: false,
            proxy_protocol: false,
            proxy_protocol_peers: vec![],
            uds_path: None,
            vhost_map: maps
                .iter()
                .map(|(vhost, domains)| VhostMap {
                    vhost: (*vhost).into(),
                    domains: domains.iter().map(|d| (*d).to_string()).collect(),
                })
                .collect(),
            tls: None,
        }
    }

    fn keys(l: &Listener) -> Vec<(String, String, String)> {
        l.domain_routes()
            .routes
            .into_iter()
            .map(|r| (r.literal, r.key, r.vhost))
            .collect()
    }

    #[test]
    fn www_and_port_are_stripped_like_ols_map_domain_list() {
        let l = listener(&[
            ("b", &["www.b.test"]),
            ("c", &["csite.test:8080"]),
            ("v6", &["[2001:db8::1]:443", "::1"]),
            ("d", &["*"]),
        ]);
        assert_eq!(
            keys(&l),
            vec![
                ("www.b.test".into(), "b.test".into(), "b".into()),
                ("csite.test".into(), "csite.test".into(), "c".into()),
                ("2001:db8::1".into(), "2001:db8::1".into(), "v6".into()),
                ("::1".into(), "::1".into(), "v6".into()),
            ]
        );
        let warnings = l.domain_routes().warnings;
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("csite.test:8080"));
        assert!(warnings[1].contains("[2001:db8::1]:443"));
    }

    #[test]
    fn duplicate_exact_domain_keeps_the_first_mapping_and_warns() {
        let l = listener(&[
            ("first", &["dup.test"]),
            ("second", &["dup.test", "other.test"]),
            ("third", &["www.dup.test"]),
        ]);
        assert_eq!(
            keys(&l),
            vec![
                ("dup.test".into(), "dup.test".into(), "first".into()),
                ("other.test".into(), "other.test".into(), "second".into()),
            ]
        );
        let warnings = l.domain_routes().warnings;
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("vhost first") && warnings[0].contains("vhost second"));
        assert!(warnings[1].contains("www.dup.test") && warnings[1].contains("vhost third"));
    }

    #[test]
    fn same_vhost_apex_and_www_both_route_without_warning() {
        let l = listener(&[("t", &["t.test", "www.t.test", "T.TEST"])]);
        assert_eq!(
            keys(&l),
            vec![
                ("t.test".into(), "t.test".into(), "t".into()),
                ("www.t.test".into(), "t.test".into(), "t".into()),
                ("t.test".into(), "t.test".into(), "t".into()),
            ]
        );
        assert!(l.domain_routes().warnings.is_empty());
    }

    #[test]
    fn unterminated_ipv6_bracket_is_ignored_with_a_warning() {
        let l = listener(&[("v", &["[::1"])]);
        let r = l.domain_routes();
        assert!(r.routes.is_empty());
        assert_eq!(r.warnings.len(), 1);
    }
}
