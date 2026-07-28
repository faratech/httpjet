//! `--page-cache-shared-paths` matchers: visitor-invariant endpoints a MEMBER
//! (logged-in) request may still read/populate on the PUBLIC cache tier.
//!
//! The private tier's cardinal rule is that a logged-in request never touches
//! public entries — rendered pages differ per login state. A narrow class of
//! endpoints is exempt by construction: HMAC-gated image responses
//! (`/proxy.php?image=…&hash=…`, `/wf-unfurl/image…`) whose bytes are identical
//! for every visitor. Routing those private wastes memory (per-session byte
//! duplication) and forces each member session's first view through the
//! backend. The operator opts such endpoints in with an explicit allowlist;
//! empty = feature inert (members keep today's private routing everywhere).
//!
//! Spec syntax (comma-separated, whitespace around items trimmed):
//! - `PATH?PARAM` — request path equals `PATH` exactly AND the raw query string
//!   carries the parameter `PARAM` (i.e. `PARAM=` at the start or after `&`).
//!   Example: `proxy.php?image` matches `/proxy.php?image=…&hash=…`.
//! - `PATH` — request path starts with `PATH`.
//!   Example: `/wf-unfurl/image` matches `/wf-unfurl/image/…`.
//!
//! A missing leading `/` is normalized on (`proxy.php?image` ≡
//! `/proxy.php?image`). Path and parameter matching is case-sensitive.
//! Malformed specs are rejected with a descriptive error so a typo fails the
//! deploy at startup instead of silently widening (or disabling) the allowlist.

/// One parsed `--page-cache-shared-paths` matcher. See the module docs for the
/// spec syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedPathMatcher {
    /// `PATH?PARAM`: path equals `path` exactly AND the query carries `param=`.
    ExactWithParam { path: String, param: String },
    /// `PATH`: path starts with `path` at a segment boundary.
    Prefix { path: String },
}

impl SharedPathMatcher {
    /// Does the (original, pre-rewrite) request `path` + raw `query` match?
    pub fn matches(&self, path: &str, query: &str) -> bool {
        match self {
            SharedPathMatcher::ExactWithParam { path: p, param } => {
                path == p && query_has_param(query, param)
            }
            // Segment-boundary anchored: `/wf-unfurl/image` matches itself and
            // `/wf-unfurl/image/…` but NOT `/wf-unfurl/imageXYZ` — a sibling
            // route added later must never be member-shared by accident (the
            // allowlist widens the private tier's cardinal rule; it has to be
            // exact about what it widens).
            SharedPathMatcher::Prefix { path: p } => match path.strip_prefix(p.as_str()) {
                Some(rest) => p.ends_with('/') || rest.is_empty() || rest.starts_with('/'),
                None => false,
            },
        }
    }
}

/// `query` carries the parameter `param` with a value — `param=` as a whole
/// parameter name at the start of the query or right after `&` (the same shape
/// the `.htaccess` `(^|&)image=` conditions test). Name match is exact and
/// case-sensitive; `paramx=…` or a bare `param` (no `=`) do not count.
fn query_has_param(query: &str, param: &str) -> bool {
    query.split('&').any(|kv| {
        kv.strip_prefix(param)
            .is_some_and(|rest| rest.starts_with('='))
    })
}

/// Strictly parse a `--page-cache-shared-paths` spec. Empty/whitespace-only ⇒
/// `Ok(vec![])` (feature inert). Any malformed item is a startup-fatal `Err`
/// with a message naming the offending matcher.
pub fn parse_shared_paths(spec: &str) -> Result<Vec<SharedPathMatcher>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for raw in spec.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            return Err(format!(
                "empty matcher in shared-paths spec {spec:?} (stray comma?)"
            ));
        }
        let (path, param) = match item.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (item, None),
        };
        if path.is_empty() {
            return Err(format!("matcher {item:?}: empty path before '?'"));
        }
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        if path
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '#' | '?'))
        {
            return Err(format!(
                "matcher {item:?}: path must not contain whitespace, '#', or a second '?'"
            ));
        }
        match param {
            None => {
                if path == "/" {
                    return Err(
                        "prefix matcher \"/\" would route EVERY member request to the public \
                         tier; list explicit endpoints instead"
                            .to_string(),
                    );
                }
                out.push(SharedPathMatcher::Prefix { path });
            }
            Some(param) => {
                if param.is_empty() {
                    return Err(format!(
                        "matcher {item:?}: empty query-parameter name after '?'"
                    ));
                }
                if param
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, '=' | '&' | '?' | '#'))
                {
                    return Err(format!(
                        "matcher {item:?}: query-parameter must be a bare name (no '=', '&', \
                         '?', '#', or whitespace)"
                    ));
                }
                out.push(SharedPathMatcher::ExactWithParam {
                    path,
                    param: param.to_string(),
                });
            }
        }
        if out[..out.len() - 1].contains(&out[out.len() - 1]) {
            return Err(format!("matcher {item:?}: duplicate of an earlier matcher"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_spec_is_inert() {
        assert_eq!(parse_shared_paths(""), Ok(Vec::new()));
        assert_eq!(parse_shared_paths("   "), Ok(Vec::new()));
    }

    #[test]
    fn parses_the_documented_prod_spec() {
        let m = parse_shared_paths("proxy.php?image, /wf-unfurl/image").unwrap();
        assert_eq!(
            m,
            vec![
                SharedPathMatcher::ExactWithParam {
                    path: "/proxy.php".into(),
                    param: "image".into()
                },
                SharedPathMatcher::Prefix {
                    path: "/wf-unfurl/image".into()
                },
            ]
        );
    }

    #[test]
    fn leading_slash_is_normalized_on() {
        assert_eq!(
            parse_shared_paths("proxy.php?image"),
            parse_shared_paths("/proxy.php?image")
        );
    }

    #[test]
    fn malformed_specs_are_rejected() {
        for bad in [
            "proxy.php?image,,x", // empty item
            "?image",             // empty path
            "/proxy.php?",        // empty param
            "/proxy.php?image=1", // param with '='
            "/proxy.php?image&x", // param with '&'
            "/proxy.php?a b",     // param with whitespace
            "/proxy .php?image",  // path with whitespace
            "/a#b",               // path with fragment
            "/",                  // match-everything prefix
            "/a?p, a?p",          // duplicate (post-normalization)
        ] {
            assert!(parse_shared_paths(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn exact_with_param_requires_exact_path_and_named_param() {
        let m = &parse_shared_paths("proxy.php?image").unwrap()[0];
        assert!(m.matches("/proxy.php", "image=https%3A%2F%2Fx&hash=abc"));
        assert!(m.matches("/proxy.php", "hash=abc&image=x"));
        // Path must be EXACT — no prefix creep.
        assert!(!m.matches("/proxy.php2", "image=x"));
        assert!(!m.matches("/sub/proxy.php", "image=x"));
        // Param must be the whole name with a value.
        assert!(!m.matches("/proxy.php", "imagex=1"));
        assert!(!m.matches("/proxy.php", "image"));
        assert!(!m.matches("/proxy.php", ""));
        // Link-proxy form (no image=) stays unmatched.
        assert!(!m.matches("/proxy.php", "link=https%3A%2F%2Fx&hash=abc"));
    }

    #[test]
    fn prefix_matches_by_path_prefix_only() {
        let m = &parse_shared_paths("/wf-unfurl/image").unwrap()[0];
        assert!(m.matches("/wf-unfurl/image", ""));
        assert!(m.matches("/wf-unfurl/image", "id=267754&v=1"));
        assert!(m.matches("/wf-unfurl/image/abc.webp", "w=640"));
        assert!(!m.matches("/wf-unfurl", ""));
        assert!(!m.matches("/other/wf-unfurl/image", ""));
        // Segment-boundary anchored: sibling routes never member-share.
        assert!(!m.matches("/wf-unfurl/imageXYZ", ""));
        assert!(!m.matches("/wf-unfurl/image-info", ""));
        assert!(!m.matches("/wf-unfurl/images/x", ""));
        // A trailing-slash prefix carries its own boundary.
        let m = &parse_shared_paths("/wf-unfurl/image/").unwrap()[0];
        assert!(m.matches("/wf-unfurl/image/abc.webp", ""));
        assert!(!m.matches("/wf-unfurl/image", ""));
    }
}
