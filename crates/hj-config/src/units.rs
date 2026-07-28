//! Parsers for LiteSpeed's human-friendly size/time strings.

/// Parse a byte size like `100M`, `512M`, `2G`, `4194304`, `8K`.
/// Returns `None` on empty/garbage; callers supply their own default.
pub fn parse_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = match s.as_bytes()[s.len() - 1].to_ascii_uppercase() {
        b'K' => (&s[..s.len() - 1], 1024u64),
        b'M' => (&s[..s.len() - 1], 1024 * 1024),
        b'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
}

/// Parse a count of seconds; bare integer.
pub(crate) fn parse_secs(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok()
}

/// Split a comma/whitespace separated list (e.g. index files, suffixes).
pub(crate) fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ', '\t', '\n', '\r'])
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(parse_bytes("100M"), Some(100 * 1024 * 1024));
        assert_eq!(parse_bytes("4194304"), Some(4194304));
        assert_eq!(parse_bytes("8K"), Some(8192));
        assert_eq!(parse_bytes("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_bytes(""), None);
    }

    #[test]
    fn lists() {
        assert_eq!(
            split_list("index.html, index.php"),
            vec!["index.html", "index.php"]
        );
        assert_eq!(split_list("php, html"), vec!["php", "html"]);
    }
}
