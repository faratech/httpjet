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
            SharedPathMatcher::Prefix { path: p } => path_has_segment_prefix(path, p),
        }
    }
}

/// `path` starts with `prefix` at a path-segment boundary: `/a` matches `/a` and
/// `/a/…` but not `/ab`; a prefix ending in `/` matches anything below it.
pub fn path_has_segment_prefix(path: &str, prefix: &str) -> bool {
    match path.strip_prefix(prefix) {
        Some(rest) => prefix.ends_with('/') || rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// URL-decode a query parameter name (`+` → space, `%XX` → byte) and normalize
/// it using PHP's `PARSE_GET` / `php_register_variable_ex` rules (trim leading
/// spaces; map ` ` and `.` to `_`; detect `[` array syntax). Returns `None` on
/// malformed percent-encoding or non-UTF-8 (caller fails closed).
fn decode_php_get_param_name(raw: &str) -> Option<(String, bool)> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i).copied()? {
            b'+' => {
                decoded.push(b' ');
                i += 1;
            }
            b'%' => {
                let hi = (*bytes.get(i + 1)? as char).to_digit(16)?;
                let lo = (*bytes.get(i + 2)? as char).to_digit(16)?;
                decoded.push(((hi << 4) | lo) as u8);
                i += 3;
            }
            b => {
                decoded.push(b);
                i += 1;
            }
        }
    }
    // PHP's `php_register_variable_ex` treats the decoded name as a NUL-terminated
    // C string (`strlen`), so `image%00x=` overwrites `$_GET["image"]` (#1305).
    if decoded.contains(&0) {
        return None;
    }
    let s = std::str::from_utf8(&decoded).ok()?;
    let trimmed = s.trim_start_matches(' ');
    // Only treat `[` as array syntax when a closing `]` follows; PHP maps an
    // unmatched `[` to `_` and stops replacing ` ` / `.` / `[` after it (#1305, #1315).
    match trimmed.split_once('[') {
        Some((prefix, rest)) if rest.contains(']') => {
            let mut norm = String::with_capacity(prefix.len());
            for ch in prefix.chars() {
                norm.push(if matches!(ch, ' ' | '.') { '_' } else { ch });
            }
            Some((norm, true))
        }
        Some((prefix, rest)) => {
            let mut norm = String::with_capacity(trimmed.len());
            for ch in prefix.chars() {
                norm.push(if matches!(ch, ' ' | '.') { '_' } else { ch });
            }
            norm.push('_');
            norm.push_str(rest);
            Some((norm, false))
        }
        None => {
            let mut norm = String::with_capacity(trimmed.len());
            for ch in trimmed.chars() {
                norm.push(if matches!(ch, ' ' | '.') { '_' } else { ch });
            }
            Some((norm, false))
        }
    }
}

/// `query` carries the parameter `param` with a non-empty scalar value using
/// PHP `PARSE_GET` decoding, normalization, and last-wins semantics (#1294):
/// `image=1&image=&link=…`, `image=1&%69mage=&…`, `image=1&+image=&…`, and
/// `image=1&image[0]=…` all fail closed to `false`.
fn query_has_param(query: &str, param: &str) -> bool {
    let mut last_value: Option<&str> = None;
    for kv in query.split('&') {
        if kv.is_empty() {
            continue;
        }
        let (raw_name, value) = kv.split_once('=').unwrap_or((kv, ""));
        // Fast path: ASCII name with no `%`, `+`, ` `, `.`, or `[`.
        if !raw_name
            .bytes()
            .any(|b| matches!(b, b'%' | b'+' | b' ' | b'.' | b'['))
        {
            if raw_name == param {
                last_value = Some(value);
            }
            continue;
        }
        let Some((norm, is_array)) = decode_php_get_param_name(raw_name) else {
            return false;
        };
        if norm == param {
            last_value = if is_array { Some("") } else { Some(value) };
        }
    }
    last_value.is_some_and(|value| !value.is_empty())
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

    #[test]
    fn segment_prefix_rejects_sibling_routes() {
        assert!(path_has_segment_prefix("/whats-new", "/whats-new"));
        assert!(path_has_segment_prefix("/whats-new/posts/", "/whats-new"));
        assert!(path_has_segment_prefix("/whats-new/posts/", "/whats-new/"));
        assert!(!path_has_segment_prefix("/whats-newish/", "/whats-new"));
        assert!(!path_has_segment_prefix("/whats", "/whats-new"));
    }

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
        // So does the link proxy reached with an empty image value.
        assert!(!m.matches("/proxy.php", "image=&link=https%3A%2F%2Fx&hash=abc"));
        assert!(!m.matches("/proxy.php", "image="));
        // PHP last-wins semantics: a trailing empty or bare `image` overrides an earlier value.
        assert!(!m.matches("/proxy.php", "image=1&image=&link=https%3A%2F%2Fx"));
        assert!(!m.matches("/proxy.php", "image=1&image&link=https%3A%2F%2Fx"));
        assert!(m.matches("/proxy.php", "image=&image=1"));
        // PHP PARSE_GET URL-decoding / normalization bypasses (#1294):
        // percent-encoded key, leading space/`+`, array bracket suffix, or malformed `%` escape.
        assert!(!m.matches("/proxy.php", "image=1&%69mage=&link=https%3A%2F%2Fx"));
        assert!(!m.matches("/proxy.php", "image=1&+image=&link=https%3A%2F%2Fx"));
        assert!(!m.matches("/proxy.php", "image=1&%20image=&link=https%3A%2F%2Fx"));
        assert!(!m.matches("/proxy.php", "image=1&image[0]=&link=https%3A%2F%2Fx"));
        assert!(!m.matches("/proxy.php", "image=1&%ZZ=1&link=https%3A%2F%2Fx"));
        assert!(!m.matches("/proxy.php", "image=1&image%00x=&link=https%3A%2F%2Fx"));
        assert!(m.matches("/proxy.php", "%69mage=1&hash=abc"));
        // Unmatched `[` maps to `_` in PHP (#1305).
        let m_under = &parse_shared_paths("proxy.php?foo_bar").unwrap()[0];
        assert!(!m_under.matches("/proxy.php", "foo_bar=1&foo[bar="));
        assert!(m_under.matches("/proxy.php", "foo[bar=1"));
        // Characters after an unmatched `[` are NOT mapped to `_` in PHP (#1315).
        let m_two = &parse_shared_paths("proxy.php?foo_bar_baz").unwrap()[0];
        assert!(!m_two.matches("/proxy.php", "foo[bar.baz=1"));
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
