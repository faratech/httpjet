//! Virtual-host routing: resolve a (listener, SNI/Host) to a vhost.
//!
//! Mirrors LiteSpeed's `<vhostMapList>` semantics: exact domain match within
//! the listener, falling back to the `*` wildcard map (the default vhost).

use std::sync::Arc;

use rustc_hash::FxHashMap;

use hj_config::model::{ServerConfig, VHostConfig};

use crate::net::host_without_port_cow;

/// A resolved virtual host for a request.
#[derive(Clone)]
pub struct ResolvedVhost {
    pub name: String,
    pub config: Arc<VHostConfig>,
}

type RouteTarget = (String, Option<Arc<VHostConfig>>);

struct ListenerRoutes {
    /// lowercased exact domain -> (vhost name, pre-resolved VHostConfig)
    exact: FxHashMap<String, RouteTarget>,
    /// the `*` wildcard vhost name (catch-all default)
    default: Option<RouteTarget>,
}

pub struct Router {
    server: Arc<ServerConfig>,
    listeners: FxHashMap<String, ListenerRoutes>,
}

impl Router {
    pub fn build(server: Arc<ServerConfig>) -> Self {
        let target_for = |vhost: String| -> RouteTarget {
            let cfg = server.vhosts.get(&vhost).and_then(|d| d.config.clone());
            (vhost, cfg)
        };
        let mut listeners = FxHashMap::default();
        for l in &server.listeners {
            let mut exact = FxHashMap::default();
            let mut default = None;
            for m in &l.vhost_map {
                if m.domains.iter().any(|d| d.trim() == "*") {
                    default.get_or_insert_with(|| target_for(m.vhost.clone()));
                }
            }
            // OLS mapDomainList: port ignored, `www.` stripped for the key, first mapping of a
            // key wins. The configured `www.` spelling stays an exact (cacheable) alias; an
            // unconfigured `www.` only reaches the apex via the parent fallback (foreign).
            for r in l.domain_routes().routes {
                let target = target_for(r.vhost);
                exact.entry(r.key).or_insert_with(|| target.clone());
                exact.entry(r.literal).or_insert(target);
            }
            listeners.insert(l.name.clone(), ListenerRoutes { exact, default });
        }
        Router { server, listeners }
    }

    pub fn server(&self) -> &Arc<ServerConfig> {
        &self.server
    }

    /// Resolve the vhost for a request. `key_host` is the SNI (TLS) or Host
    /// header; the port is stripped and matching is case-insensitive.
    ///
    /// Resolution order: exact `<vhostMap>` domain → **iterative parent-domain
    /// fallback** → `*` wildcard default. The fallback strips the leftmost label
    /// repeatedly (`www.a.publisher.example` → `a.publisher.example` → `publisher.example`),
    /// matching the exact map at each step, so an unconfigured subdomain is served by
    /// the vhost that owns its parent domain instead of leaking to the global `*`
    /// catch-all (the foreign-host regression scenario: `www.publisher.example`
    /// reaching the `forum.example` default). Only an explicitly-configured parent can match, and
    /// such a host is still NON-canonical — the caller treats it as foreign (cache
    /// bypass + CDN de-cache), so the backend issues its own canonical redirect to the
    /// parent root; a fallback never serves another brand's body.
    pub fn resolve(&self, listener: &str, key_host: Option<&str>) -> Option<ResolvedVhost> {
        let (name, config) = self.resolve_ref(listener, key_host)?;
        Some(ResolvedVhost {
            name: name.to_owned(),
            config: config.clone(),
        })
    }

    /// Zero-allocation / zero-refcount-bump vhost resolution for the on-core fast path:
    /// borrows both the canonical vhost name and its `Arc<VHostConfig>` directly from the
    /// router table.
    #[inline]
    pub fn resolve_ref<'a>(
        &'a self,
        listener: &str,
        key_host: Option<&str>,
    ) -> Option<(&'a str, &'a Arc<VHostConfig>)> {
        let routes = self.listeners.get(listener)?;
        // Use the shared IPv6-aware helper; plain split(':').next() mangles
        // bracketed literals like [::1]:443 down to '[', missing every vhost match.
        let key = key_host.map(host_without_port_cow);
        let (name, config) = key
            .as_deref()
            .and_then(|k| Self::match_exact_or_parent(routes, k))
            .or(routes.default.as_ref())?;
        Some((name.as_str(), config.as_ref()?))
    }

    /// When [`resolve`](Self::resolve) returns `None`, distinguish "the host is genuinely unknown"
    /// (→ 404) from "the host resolves to a real vhost whose per-vhost config file FAILED to load"
    /// (config == None → the request would 404 silently). The latter is an operator
    /// misconfiguration (a bad reload, a partial deploy, a permission change), not a missing host,
    /// so the caller should surface a 503 + a loud log instead of a misleading 404. Cold path only
    /// (an error response), so the small duplicate match is irrelevant.
    pub fn host_known_but_unloaded(&self, listener: &str, key_host: Option<&str>) -> bool {
        let Some(routes) = self.listeners.get(listener) else {
            return false;
        };
        let key = key_host.map(host_without_port_cow);
        let target = key
            .as_deref()
            .and_then(|k| Self::match_exact_or_parent(routes, k))
            .or(routes.default.as_ref());
        match target {
            Some((n, cfg)) => cfg.is_none() && self.server.vhosts.contains_key(n),
            None => false,
        }
    }

    /// Exact match for `host`, else the vhost owning its nearest configured parent domain.
    /// Strips one leftmost label at a time and re-checks the exact map; stops at the first
    /// hit. The `contains('.')` guard means the last label group considered always has a dot
    /// (`example.com`), so a single-label registry suffix (`com`) is never looked up — and
    /// even if it were, only an explicitly-mapped domain is ever in `exact`, so a bare TLD
    /// can't match. `host` is already port-stripped + lowercased by the caller.
    fn match_exact_or_parent<'a>(
        routes: &'a ListenerRoutes,
        host: &str,
    ) -> Option<&'a RouteTarget> {
        if let Some(v) = routes.exact.get(host) {
            return Some(v);
        }
        let mut rest = host;
        while let Some((_, parent)) = rest.split_once('.') {
            if !parent.contains('.') {
                break;
            }
            if let Some(v) = routes.exact.get(parent) {
                return Some(v);
            }
            rest = parent;
        }
        None
    }

    /// The default (wildcard) vhost name for a listener, if any.
    pub fn default_vhost(&self, listener: &str) -> Option<&str> {
        self.listeners
            .get(listener)?
            .default
            .as_ref()
            .map(|(n, _)| n.as_str())
    }

    /// True when `host` is an exact `<vhostMap>` domain routed to `vhost` on any
    /// listener: an explicitly configured alias, never a wildcard-routed foreign host.
    pub fn host_maps_to_vhost(&self, host: &str, vhost: &str) -> bool {
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            let host = host.to_ascii_lowercase();
            self.listeners
                .values()
                .any(|r| r.exact.get(&host).is_some_and(|(v, _)| v == vhost))
        } else {
            self.listeners
                .values()
                .any(|r| r.exact.get(host).is_some_and(|(v, _)| v == vhost))
        }
    }

    /// True when `host` is an EXACT `<vhostMap>` domain on this listener — i.e. it was
    /// matched explicitly, NOT routed by the `*` wildcard fallback. Lets the page cache
    /// distinguish a configured hostname from a foreign Host that only reached a vhost via
    /// the catch-all default (e.g. an unconfigured `www.publisher.example` landing on the
    /// `forum.example` `*` vhost). Case-insensitive; the caller passes a port-stripped
    /// host (the exact map is keyed by lowercased domains — see `build`).
    pub fn host_is_exact(&self, listener: &str, host: &str) -> bool {
        self.listeners.get(listener).is_some_and(|r| {
            // Real-world hosts arrive lowercase already (CF/h2 normalize), so borrow
            // unless an uppercase byte forces the owned fold.
            if host.bytes().any(|b| b.is_ascii_uppercase()) {
                r.exact.contains_key(&host.to_ascii_lowercase())
            } else {
                r.exact.contains_key(host)
            }
        })
    }
}
