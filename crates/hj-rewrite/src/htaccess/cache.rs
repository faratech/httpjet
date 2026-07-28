//! The LSCache page-cache directives recorded from a `.htaccess`
//! (`CacheLookup`/`CacheEnable`/`CacheDisable`/`CacheKeyModify`) plus the
//! [`CacheDirectives`] chain fold that the origin page cache consults.

use super::Htaccess;

/// One `CacheKeyModify` query-string operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheKeyModifier {
    /// `-qs:NAME` — drop a query param by exact name from the cache key.
    StripQs(String),
    /// `-qs:NAME*` — drop every query param whose name starts with this prefix.
    StripQsPrefix(String),
}

/// Cache directives folded over a `.htaccess` chain (docroot → deepest dir).
///
/// The chain is already scoped to the request's path (only `.htaccess` files
/// along that path are loaded), so a `CacheDisable /` only affects requests
/// under that directory.
#[derive(Debug, Default, Clone)]
pub struct CacheDirectives {
    /// `CacheLookup` state — last value in the chain wins. `None` = unspecified.
    pub lookup: Option<bool>,
    /// Accumulated `CacheKeyModify` operations (chain order).
    pub key_modifiers: Vec<CacheKeyModifier>,
    /// `CacheEnable` path prefixes encountered along the chain (empty = dir-wide).
    pub enabled_paths: Vec<String>,
    /// `CacheDisable` path prefixes encountered along the chain.
    pub disabled_paths: Vec<String>,
}

/// A `Cache(En|Dis)able` path-prefix argument matches `req_path`. An empty prefix
/// (no path given) or `/` is directory-wide; otherwise it is a literal path prefix.
fn cache_path_matches(prefix: &str, req_path: &str) -> bool {
    prefix.is_empty() || prefix == "/" || req_path.starts_with(prefix)
}

impl CacheDirectives {
    /// Whether the origin page cache should be consulted/populated for
    /// `req_path`: caching is enabled AND no `CacheDisable` prefix matches.
    pub fn cacheable_for(&self, req_path: &str) -> bool {
        self.cacheable_for_default(req_path, false)
    }

    /// Like [`cacheable_for`](Self::cacheable_for), but when caching is *unspecified*
    /// the dir defaults to `default_on` instead of off. Used by the "default cache
    /// policy" mode (`--page-cache-default-vhost`): a non-LiteSpeed app (e.g.
    /// moontimenow) never writes `CacheLookup public on`, yet should still cache when
    /// the operator opted the server into default caching.
    ///
    /// Enable precedence: an EXPLICIT `CacheLookup off` always disables (operator
    /// override). Otherwise caching is on if `CacheLookup on`, or a `CacheEnable`
    /// prefix matches `req_path` (the standard LiteSpeed/Apache way to opt a path in —
    /// previously parsed but ignored), or `default_on`. A matching `CacheDisable`
    /// prefix then disables, always (disable wins over enable, matching LSWS).
    pub fn cacheable_for_default(&self, req_path: &str, default_on: bool) -> bool {
        let enabled = match self.lookup {
            Some(false) => return false,
            Some(true) => true,
            None => {
                default_on
                    || self
                        .enabled_paths
                        .iter()
                        .any(|p| cache_path_matches(p, req_path))
            }
        };
        if !enabled {
            return false;
        }
        !self
            .disabled_paths
            .iter()
            .any(|p| cache_path_matches(p, req_path))
    }
}

/// Fold the per-directory cache directives across a loaded `.htaccess` chain.
pub fn cache_directives(chain: &[std::sync::Arc<Htaccess>]) -> CacheDirectives {
    let mut d = CacheDirectives::default();
    for h in chain {
        if let Some(on) = h.cache_lookup {
            d.lookup = Some(on);
        }
        d.key_modifiers
            .extend(h.cache_key_modifiers.iter().cloned());
        d.enabled_paths.extend(h.cache_enable.iter().cloned());
        d.disabled_paths.extend(h.cache_disable.iter().cloned());
    }
    d
}

/// Zero-allocation equivalent of `cache_directives(chain).cacheable_for_default(req_path,
/// default_on)`, evaluated lazily over the chain. The page-cache hot path calls this on
/// every lookup/store, so it must NOT materialize the folded [`CacheDirectives`] (whose
/// `key_modifiers`/`disabled_paths` Vecs + per-entry string clones are pure waste when all
/// we need is a yes/no). Kept byte-for-byte equivalent to the fold — see the oracle test
/// `chain_cacheable_for_default_matches_fold_oracle`.
pub fn chain_cacheable_for_default(
    chain: &[std::sync::Arc<Htaccess>],
    req_path: &str,
    default_on: bool,
) -> bool {
    // `CacheLookup`: the last value specified along the chain wins; unspecified ⇒ `None`
    // (mirrors `CacheDirectives.lookup`).
    let mut lookup: Option<bool> = None;
    for h in chain {
        if let Some(on) = h.cache_lookup {
            lookup = Some(on);
        }
    }
    let enabled = match lookup {
        Some(false) => return false, // explicit `CacheLookup off` always disables
        Some(true) => true,
        // No `CacheLookup`: enabled by `default_on` or any matching `CacheEnable` prefix.
        None => {
            default_on
                || chain.iter().any(|h| {
                    h.cache_enable
                        .iter()
                        .any(|p| cache_path_matches(p, req_path))
                })
        }
    };
    if !enabled {
        return false;
    }
    // `CacheDisable`: any matching prefix (empty / `/` = directory-wide) disables.
    !chain.iter().any(|h| {
        h.cache_disable
            .iter()
            .any(|p| cache_path_matches(p, req_path))
    })
}

fn cache_is_scope(s: &str) -> bool {
    s.eq_ignore_ascii_case("public") || s.eq_ignore_ascii_case("private")
}

/// Parse the path argument of `Cache(En|Dis)able [public|private] [path]`.
/// Returns the path (empty string = directory-wide).
pub(super) fn cache_scope_path(rest: &str) -> Option<String> {
    let toks: Vec<&str> = rest.split_whitespace().collect();
    match toks.as_slice() {
        [scope, path] if cache_is_scope(scope) => Some((*path).to_string()),
        [single] if cache_is_scope(single) => Some(String::new()),
        [single] => Some((*single).to_string()),
        [] => Some(String::new()),
        _ => None,
    }
}

/// Parse `CacheKeyModify -qs:NAME -qs:PREFIX* ...` into modifiers.
pub(super) fn parse_cache_key_modify(rest: &str) -> Vec<CacheKeyModifier> {
    rest.split_whitespace()
        .filter_map(|tok| {
            let name = tok.strip_prefix("-qs:")?;
            if let Some(prefix) = name.strip_suffix('*') {
                Some(CacheKeyModifier::StripQsPrefix(prefix.to_string()))
            } else {
                Some(CacheKeyModifier::StripQs(name.to_string()))
            }
        })
        .collect()
}
