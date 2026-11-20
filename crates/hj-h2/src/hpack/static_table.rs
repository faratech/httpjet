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

/// Result of a single-pass static-table lookup for `(name, value)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticMatch {
    /// Both `name` and `value` matched this 1-based static-table entry.
    Exact(usize),
    /// Only `name` matched; carries the first 1-based static-table index for `name`.
    NameOnly(usize),
    /// `name` is not in the static table.
    None,
}

/// Single-pass static-table lookup returning either an exact `(name, value)` index or
/// the first `name`-only index in one `match` over `name`.
#[inline]
pub fn lookup(name: &str, value: &[u8]) -> StaticMatch {
    let idx = match name {
        ":authority" => 1,
        ":method" => {
            return match value {
                b"GET" => StaticMatch::Exact(2),
                b"POST" => StaticMatch::Exact(3),
                _ => StaticMatch::NameOnly(2),
            };
        }
        ":path" => {
            return match value {
                b"/" => StaticMatch::Exact(4),
                b"/index.html" => StaticMatch::Exact(5),
                _ => StaticMatch::NameOnly(4),
            };
        }
        ":scheme" => {
            return match value {
                b"http" => StaticMatch::Exact(6),
                b"https" => StaticMatch::Exact(7),
                _ => StaticMatch::NameOnly(6),
            };
        }
        ":status" => {
            return match value {
                b"200" => StaticMatch::Exact(8),
                b"204" => StaticMatch::Exact(9),
                b"206" => StaticMatch::Exact(10),
                b"304" => StaticMatch::Exact(11),
                b"400" => StaticMatch::Exact(12),
                b"404" => StaticMatch::Exact(13),
                b"500" => StaticMatch::Exact(14),
                _ => StaticMatch::NameOnly(8),
            };
        }
        "accept-charset" => 15,
        "accept-encoding" => {
            return if value == b"gzip, deflate" {
                StaticMatch::Exact(16)
            } else {
                StaticMatch::NameOnly(16)
            };
        }
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
        _ => return StaticMatch::None,
    };
    if value.is_empty() {
        StaticMatch::Exact(idx)
    } else {
        StaticMatch::NameOnly(idx)
    }
}

/// 1-based index of an exact `(name, value)` match, if present.
#[cfg(test)]
pub fn find_name_value(name: &str, value: &[u8]) -> Option<usize> {
    match lookup(name, value) {
        StaticMatch::Exact(idx) => Some(idx),
        _ => None,
    }
}

/// 1-based index of the FIRST entry matching `name` (value ignored), if present.
#[cfg(test)]
pub fn find_name(name: &str) -> Option<usize> {
    match lookup(name, b"\x01") {
        StaticMatch::Exact(idx) | StaticMatch::NameOnly(idx) => Some(idx),
        StaticMatch::None => None,
    }
}

/// Look up a static-table entry by 1-based index.
pub fn get(index: usize) -> Option<(&'static str, &'static str)> {
    if index == 0 {
        return None;
    }
    TABLE.get(index - 1).copied()
}

/// Pre-validated `http::HeaderName` for a 1-based static-table index when the entry
/// names a valid, non-connection-specific regular HTTP/2 request header.
/// Pseudo-headers (`1..=14`) and `transfer-encoding` (`57`, connection-specific)
/// return `None` so the caller handles pseudo-headers or rejects `transfer-encoding`.
#[inline]
pub fn request_header_name(index: usize) -> Option<http::HeaderName> {
    use http::header;
    Some(match index {
        15 => header::ACCEPT_CHARSET,
        16 => header::ACCEPT_ENCODING,
        17 => header::ACCEPT_LANGUAGE,
        18 => header::ACCEPT_RANGES,
        19 => header::ACCEPT,
        20 => header::ACCESS_CONTROL_ALLOW_ORIGIN,
        21 => header::AGE,
        22 => header::ALLOW,
        23 => header::AUTHORIZATION,
        24 => header::CACHE_CONTROL,
        25 => header::CONTENT_DISPOSITION,
        26 => header::CONTENT_ENCODING,
        27 => header::CONTENT_LANGUAGE,
        28 => header::CONTENT_LENGTH,
        29 => header::CONTENT_LOCATION,
        30 => header::CONTENT_RANGE,
        31 => header::CONTENT_TYPE,
        32 => header::COOKIE,
        33 => header::DATE,
        34 => header::ETAG,
        35 => header::EXPECT,
        36 => header::EXPIRES,
        37 => header::FROM,
        38 => header::HOST,
        39 => header::IF_MATCH,
        40 => header::IF_MODIFIED_SINCE,
        41 => header::IF_NONE_MATCH,
        42 => header::IF_RANGE,
        43 => header::IF_UNMODIFIED_SINCE,
        44 => header::LAST_MODIFIED,
        45 => header::LINK,
        46 => header::LOCATION,
        47 => header::MAX_FORWARDS,
        48 => header::PROXY_AUTHENTICATE,
        49 => header::PROXY_AUTHORIZATION,
        50 => header::RANGE,
        51 => header::REFERER,
        52 => header::REFRESH,
        53 => header::RETRY_AFTER,
        54 => header::SERVER,
        55 => header::SET_COOKIE,
        56 => header::STRICT_TRANSPORT_SECURITY,
        // 57 is "transfer-encoding" (connection-specific, illegal in HTTP/2 requests).
        58 => header::USER_AGENT,
        59 => header::VARY,
        60 => header::VIA,
        61 => header::WWW_AUTHENTICATE,
        _ => return None,
    })
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
        for idx in 1..=TABLE.len() {
            let (name, _) = get(idx).unwrap();
            let got = request_header_name(idx);
            if name.starts_with(':') || hj_core::is_connection_specific_request_header(name) {
                assert_eq!(got, None, "idx={idx} name={name}");
            } else {
                assert_eq!(
                    got.as_ref().map(|h| h.as_str()),
                    Some(name),
                    "idx={idx} name={name}"
                );
            }
        }
    }
}
