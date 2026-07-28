//! The HPACK static table (RFC 7541 Appendix A) — 61 predefined header entries,
//! 1-indexed. Most of httpjet's response headers live here (`:status` 200/206/304/404,
//! `content-type`, `content-length`, `etag`, `last-modified`, `date`, `cache-control`,
//! `vary`, `accept-ranges`, `server`, `set-cookie`, `location`, `content-encoding`),
//! so a typical static/cached response encodes to a handful of indexed-name references
//! plus literal values — no allocation, minimal bytes.

/// `(name, value)`; an empty value means the entry indexes the name only.
pub static TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// 1-based index of an exact `(name, value)` match, if present.
///
/// O(1) `match` over the compile-time-constant table (the encoder calls this once
/// per response header; a 51-header response previously paid 51 × O(61) linear
/// scans here). Every `(name, value)` pair in [`TABLE`] is unique, so this is
/// exactly the old `position()` first-match — proven byte-identical to
/// `find_name_value_linear` by the `fast_lookup_matches_linear_oracle` test.
pub fn find_name_value(name: &str, value: &[u8]) -> Option<usize> {
    Some(match (name, value) {
        (":authority", b"") => 1,
        (":method", b"GET") => 2,
        (":method", b"POST") => 3,
        (":path", b"/") => 4,
        (":path", b"/index.html") => 5,
        (":scheme", b"http") => 6,
        (":scheme", b"https") => 7,
        (":status", b"200") => 8,
        (":status", b"204") => 9,
        (":status", b"206") => 10,
        (":status", b"304") => 11,
        (":status", b"400") => 12,
        (":status", b"404") => 13,
        (":status", b"500") => 14,
        ("accept-charset", b"") => 15,
        ("accept-encoding", b"gzip, deflate") => 16,
        ("accept-language", b"") => 17,
        ("accept-ranges", b"") => 18,
        ("accept", b"") => 19,
        ("access-control-allow-origin", b"") => 20,
        ("age", b"") => 21,
        ("allow", b"") => 22,
        ("authorization", b"") => 23,
        ("cache-control", b"") => 24,
        ("content-disposition", b"") => 25,
        ("content-encoding", b"") => 26,
        ("content-language", b"") => 27,
        ("content-length", b"") => 28,
        ("content-location", b"") => 29,
        ("content-range", b"") => 30,
        ("content-type", b"") => 31,
        ("cookie", b"") => 32,
        ("date", b"") => 33,
        ("etag", b"") => 34,
        ("expect", b"") => 35,
        ("expires", b"") => 36,
        ("from", b"") => 37,
        ("host", b"") => 38,
        ("if-match", b"") => 39,
        ("if-modified-since", b"") => 40,
        ("if-none-match", b"") => 41,
        ("if-range", b"") => 42,
        ("if-unmodified-since", b"") => 43,
        ("last-modified", b"") => 44,
        ("link", b"") => 45,
        ("location", b"") => 46,
        ("max-forwards", b"") => 47,
        ("proxy-authenticate", b"") => 48,
        ("proxy-authorization", b"") => 49,
        ("range", b"") => 50,
        ("referer", b"") => 51,
        ("refresh", b"") => 52,
        ("retry-after", b"") => 53,
        ("server", b"") => 54,
        ("set-cookie", b"") => 55,
        ("strict-transport-security", b"") => 56,
        ("transfer-encoding", b"") => 57,
        ("user-agent", b"") => 58,
        ("vary", b"") => 59,
        ("via", b"") => 60,
        ("www-authenticate", b"") => 61,
        _ => return None,
    })
}

/// 1-based index of the FIRST entry matching `name` (value ignored), if present.
/// `name` must already be lowercase (HTTP/2 requires lowercase header names).
///
/// O(1) `match` over the 57 distinct names; the 4 duplicated names return their
/// first table entry (`:method`→2, `:path`→4, `:scheme`→6, `:status`→8), matching
/// the old `position()`. Proven equal to `find_name_linear` by the equivalence test.
pub fn find_name(name: &str) -> Option<usize> {
    Some(match name {
        ":authority" => 1,
        ":method" => 2,
        ":path" => 4,
        ":scheme" => 6,
        ":status" => 8,
        "accept-charset" => 15,
        "accept-encoding" => 16,
        "accept-language" => 17,
        "accept-ranges" => 18,
        "accept" => 19,
        "access-control-allow-origin" => 20,
        "age" => 21,
        "allow" => 22,
        "authorization" => 23,
        "cache-control" => 24,
        "content-disposition" => 25,
        "content-encoding" => 26,
        "content-language" => 27,
        "content-length" => 28,
        "content-location" => 29,
        "content-range" => 30,
        "content-type" => 31,
        "cookie" => 32,
        "date" => 33,
        "etag" => 34,
        "expect" => 35,
        "expires" => 36,
        "from" => 37,
        "host" => 38,
        "if-match" => 39,
        "if-modified-since" => 40,
        "if-none-match" => 41,
        "if-range" => 42,
        "if-unmodified-since" => 43,
        "last-modified" => 44,
        "link" => 45,
        "location" => 46,
        "max-forwards" => 47,
        "proxy-authenticate" => 48,
        "proxy-authorization" => 49,
        "range" => 50,
        "referer" => 51,
        "refresh" => 52,
        "retry-after" => 53,
        "server" => 54,
        "set-cookie" => 55,
        "strict-transport-security" => 56,
        "transfer-encoding" => 57,
        "user-agent" => 58,
        "vary" => 59,
        "via" => 60,
        "www-authenticate" => 61,
        _ => return None,
    })
}

/// Look up a static-table entry by 1-based index.
pub fn get(index: usize) -> Option<(&'static str, &'static str)> {
    if index == 0 {
        return None;
    }
    TABLE.get(index - 1).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The original linear-scan implementations, kept as a test oracle so the O(1)
    /// `match` versions above are provably byte-identical (same indices ⇒ same wire).
    fn find_name_value_linear(name: &str, value: &str) -> Option<usize> {
        TABLE
            .iter()
            .position(|(n, v)| *n == name && *v == value)
            .map(|i| i + 1)
    }
    fn find_name_linear(name: &str) -> Option<usize> {
        TABLE.iter().position(|(n, _)| *n == name).map(|i| i + 1)
    }

    #[test]
    fn fast_lookup_matches_linear_oracle() {
        // Cross-product every table name × every table value (plus misses, wrong
        // values, and the empty value) and assert the `match` lookups agree with the
        // linear oracle on EVERY input — any transcription slip fails here, not on the wire.
        let names: Vec<&str> = TABLE
            .iter()
            .map(|(n, _)| *n)
            .chain([":STATUS", "x-unknown", "", "content-Type"])
            .collect();
        let values: Vec<&str> = TABLE
            .iter()
            .map(|(_, v)| *v)
            .chain(["", "weird", "200", "/", "gzip"])
            .collect();
        for &n in &names {
            assert_eq!(find_name(n), find_name_linear(n), "find_name({n:?})");
            for &v in &values {
                assert_eq!(
                    find_name_value(n, v.as_bytes()),
                    find_name_value_linear(n, v),
                    "find_name_value({n:?}, {v:?})"
                );
            }
        }
        // And every real entry resolves to its own 1-based index.
        for (i, (n, v)) in TABLE.iter().enumerate() {
            assert_eq!(
                find_name_value(n, v.as_bytes()),
                Some(i + 1),
                "entry {n:?}={v:?}"
            );
        }
    }

    #[test]
    fn known_indices() {
        assert_eq!(find_name_value(":status", b"200"), Some(8));
        assert_eq!(find_name_value(":method", b"GET"), Some(2));
        assert_eq!(find_name("content-type"), Some(31));
        assert_eq!(find_name("content-length"), Some(28));
        assert_eq!(find_name("etag"), Some(34));
        assert_eq!(find_name("last-modified"), Some(44));
        assert_eq!(find_name("date"), Some(33));
        assert_eq!(find_name("vary"), Some(59));
        assert_eq!(find_name("server"), Some(54));
        assert_eq!(get(8), Some((":status", "200")));
        assert_eq!(get(0), None);
        assert_eq!(get(62), None);
    }
}
