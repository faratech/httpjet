//! Network-peer trust helpers shared across transports (TCP TLS and QUIC/HTTP3).

use std::net::IpAddr;

/// Is `ip` exempt from the mandatory Cloudflare origin-pull client-cert
/// requirement (`clientVerify=2`)? Loopback/unspecified ONLY.
///
/// The origin-pull mTLS exists to keep *external* clients from reaching the origin
/// directly (only Cloudflare carries the client cert). On-box services legitimately
/// reach the origin without it, because `/etc/hosts` maps the public vhosts to
/// `127.0.0.1` so a fetch of `https://forum.example/...` hits the listener over
/// loopback. Everyone else — **including arbitrary RFC1918/LAN hosts** — must
/// present a valid cert.
///
/// History: this used to exempt the WHOLE RFC1918/ULA/link-local space (range
/// based), which let any private-LAN host bypass Cloudflare AOP (security audit
/// 2026-06-19, MEDIUM); it was narrowed to loopback/unspecified plus an explicit
/// `--cache-peer` allow-list, and the allow-list was removed with the peer node's
/// 2026-07-13 decommission. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unwrapped and
/// judged as its IPv4 form.
pub fn is_trusted_internal_peer(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Extract the host from a `Host` / `:authority` value, dropping any `:port` and
/// the brackets around an IPv6 literal, lowercased and with a trailing root dot
/// removed (`example.com.` → `example.com`).
///
/// Handles `example.com`, `example.com:443`, `[::1]`, and `[::1]:8443`. A plain
/// `split(':')` mangles the bracketed-IPv6 forms; this is the single host
/// normalizer shared by vhost routing, the mTLS HTTP→HTTPS redirect, and the
/// page-cache key host.
pub fn host_without_port(authority: &str) -> String {
    let a = authority.trim();
    let host = if let Some(rest) = a.strip_prefix('[') {
        // `[ipv6]` or `[ipv6]:port` — take up to the closing bracket.
        rest.split(']').next().unwrap_or(rest)
    } else if a.matches(':').count() > 1 {
        // Unbracketed multi-colon: a bare IPv6 literal (malformed in a Host header
        // per RFC 7230, but don't mangle it) — there is no port to strip.
        a
    } else {
        a.split(':').next().unwrap_or(a)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// RFC 3986 §3.1 URI scheme syntax. HTTP/2 permits valid non-HTTP schemes, so
/// transports use this syntax check without narrowing the value to `http` or
/// `https`.
pub fn valid_uri_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn uri_sub_delim(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

fn valid_uri_component(value: &str, allow_colon: bool) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || uri_sub_delim(b)
            || (allow_colon && b == b':')
        {
            i += 1;
        } else if b == b'%'
            && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            i += 3;
        } else {
            return false;
        }
    }
    true
}

fn valid_ip_literal(value: &str) -> bool {
    if value.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    // RFC 3986 §3.2.2 IPvFuture:
    // `"v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )`.
    let Some(rest) = value.strip_prefix('v').or_else(|| value.strip_prefix('V')) else {
        return false;
    };
    let Some((version, address)) = rest.split_once('.') else {
        return false;
    };
    !version.is_empty()
        && version.bytes().all(|b| b.is_ascii_hexdigit())
        && !address.is_empty()
        && address.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'-' | b'.' | b'_' | b'~' | b':')
                || uri_sub_delim(b)
        })
}

/// RFC 3986 §3.2 authority syntax. This validates the generic grammar rather
/// than DNS semantics so it is suitable for every valid HTTP/2 scheme.
pub fn valid_uri_authority(value: &str) -> bool {
    let host_port = if let Some((userinfo, host_port)) = value.rsplit_once('@') {
        if host_port.contains('@') || !valid_uri_component(userinfo, true) {
            return false;
        }
        host_port
    } else {
        value
    };

    if let Some(literal) = host_port.strip_prefix('[') {
        let Some(close) = literal.find(']') else {
            return false;
        };
        let (address, suffix) = literal.split_at(close);
        let suffix = &suffix[1..];
        return valid_ip_literal(address)
            && (suffix.is_empty()
                || suffix
                    .strip_prefix(':')
                    .is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit())));
    }

    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (host_port, None),
    };
    !host.contains(':')
        && valid_uri_component(host, false)
        && port.is_none_or(|port| port.bytes().all(|b| b.is_ascii_digit()))
}

/// Validate an HTTP(S) authority. RFC 3986's generic authority grammar permits
/// userinfo and an empty registered name, but HTTP request authorities permit
/// neither. Keep the generic validator separate so HTTP/2 can still carry valid
/// non-HTTP schemes.
pub fn valid_http_authority(value: &str) -> bool {
    !value.contains('@') && valid_uri_authority(value) && !host_without_port(value).is_empty()
}

#[cfg(test)]
mod tests {
    use super::{
        host_without_port, is_trusted_internal_peer, valid_http_authority, valid_uri_authority,
        valid_uri_scheme,
    };
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("parse ip")
    }

    #[test]
    fn loopback_is_always_exempt() {
        assert!(is_trusted_internal_peer(ip("127.0.0.1")));
        assert!(is_trusted_internal_peer(ip("127.0.0.53")));
        assert!(is_trusted_internal_peer(ip("::1")));
        assert!(is_trusted_internal_peer(ip("0.0.0.0")));
        // IPv4-mapped IPv6 of loopback is unwrapped.
        assert!(is_trusted_internal_peer(ip("::ffff:127.0.0.1")));
    }

    #[test]
    fn lan_hosts_are_not_exempt() {
        // An arbitrary RFC1918 / LAN host is not trusted — the audit-2026-06-19
        // narrowing (a cert-less private-LAN host must not bypass Cloudflare AOP).
        assert!(!is_trusted_internal_peer(ip("10.0.0.1")));
        assert!(!is_trusted_internal_peer(ip("172.16.5.4")));
        assert!(!is_trusted_internal_peer(ip("192.168.1.10")));
        assert!(!is_trusted_internal_peer(ip("169.254.1.1")));
        assert!(!is_trusted_internal_peer(ip("fd00::1")));
        assert!(!is_trusted_internal_peer(ip("fe80::1")));
    }

    #[test]
    fn public_peers_are_not_trusted() {
        // Cloudflare edge / arbitrary public IPs must still present a client cert.
        assert!(!is_trusted_internal_peer(ip("173.245.48.1"))); // a Cloudflare range
        assert!(!is_trusted_internal_peer(ip("8.8.8.8")));
        assert!(!is_trusted_internal_peer(ip("1.1.1.1")));
        assert!(!is_trusted_internal_peer(ip("203.0.113.7")));
        assert!(!is_trusted_internal_peer(ip("2606:4700:4700::1111")));
        // IPv4-mapped IPv6 of a public address is still public.
        assert!(!is_trusted_internal_peer(ip("::ffff:8.8.8.8")));
        // ...and loopback stays exempt through the public entry point.
        assert!(is_trusted_internal_peer(ip("127.0.0.1")));
        assert!(is_trusted_internal_peer(ip("::1")));
    }

    #[test]
    fn host_without_port_handles_ports_and_ipv6() {
        assert_eq!(host_without_port("example.com"), "example.com");
        assert_eq!(host_without_port("Example.COM:443"), "example.com");
        assert_eq!(host_without_port("forum.example."), "forum.example");
        assert_eq!(host_without_port("[::1]"), "::1");
        assert_eq!(host_without_port("[::1]:8443"), "::1");
        assert_eq!(
            host_without_port("[2606:4700::1111]:443"),
            "2606:4700::1111"
        );
        // Bare unbracketed IPv6 (malformed) is passed through, not truncated.
        assert_eq!(host_without_port("::1"), "::1");
    }

    #[test]
    fn uri_scheme_and_authority_validation_supports_generic_h2_syntax() {
        for scheme in ["http", "web+custom", "a.b-c"] {
            assert!(valid_uri_scheme(scheme), "{scheme}");
        }
        for scheme in ["", "1http", "http space", "http:"] {
            assert!(!valid_uri_scheme(scheme), "{scheme}");
        }
        for authority in [
            "example.com",
            "example.com:443",
            "[2001:db8::1]:8443",
            "[v1.a-b]:443",
            "user@example.com",
        ] {
            assert!(valid_uri_authority(authority), "{authority}");
        }
        for authority in [
            "bad host",
            "host/path",
            "[::1",
            "example.com:abc",
            "user@@example.com",
        ] {
            assert!(!valid_uri_authority(authority), "{authority}");
        }
    }

    #[test]
    fn http_authority_requires_a_host_and_forbids_userinfo() {
        for authority in ["example.com", "example.com:443", "[2001:db8::1]:8443"] {
            assert!(valid_http_authority(authority), "{authority}");
        }
        for authority in [
            "",
            ":443",
            "user@example.com",
            "bad host",
            "example.com:abc",
        ] {
            assert!(!valid_http_authority(authority), "{authority}");
        }
    }
}

/// Request headers that assert a client identity or scheme on behalf of a
/// proxy. Only a trusted proxy may supply them to a backend.
pub const FORWARDING_AUTHORITY_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "x-original-forwarded-for",
    "cf-connecting-ip",
    "true-client-ip",
    "client-ip",
    "fastly-client-ip",
    "x-cluster-client-ip",
];

/// Whether `name` asserts a client identity or scheme on behalf of a proxy.
///
/// Names compare case-insensitively with `_` folded to `-` (lsphp maps both to
/// the same `HTTP_*` variable). Besides the enumerated list, whole classes fail
/// closed (#585, #600): `forwarded*`, `x-forwarded*` (including a bare
/// `X-Forwarded`), `*-client-ip`, `*-real-ip`, Cloudflare's `CF-Connecting-IPv6`
/// and `Cf-Pseudo-IPv4`, and any `x-`/`cf-`/`true-`/`fastly-` name ending in
/// `-ip`, `-ipv4`, `-ipv6` or `-addr` (`X-Remote-Addr`, `X-Originating-IP`,
/// `X-AppEngine-User-IP`, `X-ProxyUser-Ip`, ...) — the lookup set of common
/// client-IP resolvers such as npm `request-ip`.
pub fn is_forwarding_authority_header(name: &str) -> bool {
    let n = name.as_bytes();
    if FORWARDING_AUTHORITY_HEADERS
        .iter()
        .any(|known| folded_eq(n, known.as_bytes()))
    {
        return true;
    }
    const IDENTITY_PREFIXES: [&[u8]; 4] = [b"x-", b"cf-", b"true-", b"fastly-"];
    const IDENTITY_SUFFIXES: [&[u8]; 4] = [b"-ip", b"-ipv4", b"-ipv6", b"-addr"];
    folded_eq(n, b"forwarded")
        || folded_starts(n, b"forwarded-")
        || folded_starts(n, b"x-forwarded")
        || folded_eq(n, b"client-ip")
        || folded_ends(n, b"-client-ip")
        || folded_eq(n, b"real-ip")
        || folded_ends(n, b"-real-ip")
        || folded_starts(n, b"cf-connecting-ip")
        || folded_eq(n, b"cf-pseudo-ipv4")
        || (IDENTITY_PREFIXES.iter().any(|p| folded_starts(n, p))
            && IDENTITY_SUFFIXES.iter().any(|s| folded_ends(n, s)))
}

fn fold(b: u8) -> u8 {
    if b == b'_' || b == b'.' {
        b'-'
    } else {
        b.to_ascii_lowercase()
    }
}

/// `name` equals the lowercase, dash-separated `lit` after folding.
fn folded_eq(name: &[u8], lit: &[u8]) -> bool {
    name.len() == lit.len() && name.iter().zip(lit).all(|(&a, &b)| fold(a) == b)
}

fn folded_starts(name: &[u8], lit: &[u8]) -> bool {
    name.len() >= lit.len() && folded_eq(&name[..lit.len()], lit)
}

fn folded_ends(name: &[u8], lit: &[u8]) -> bool {
    name.len() >= lit.len() && folded_eq(&name[name.len() - lit.len()..], lit)
}

#[cfg(test)]
mod forwarding_authority_tests {
    use super::*;

    #[test]
    fn forwarding_authority_names_are_lowercase_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for name in FORWARDING_AUTHORITY_HEADERS {
            assert_eq!(*name, name.to_ascii_lowercase());
            assert!(seen.insert(*name), "duplicate {name}");
            assert!(http::HeaderName::from_static(name).as_str() == *name);
        }
        assert!(is_forwarding_authority_header("CF-Connecting-IP"));
        assert!(!is_forwarding_authority_header("user-agent"));
    }

    /// Regression (#585): synonyms outside the enumerated list are still
    /// forwarding-authority headers; ordinary headers are not.
    #[test]
    fn forwarding_authority_synonyms_fail_closed() {
        for name in [
            "X-Client-IP",
            "X-Forwarded-Protocol",
            "X-Forwarded-Scheme",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "X_Forwarded_Protocol",
            "X.Forwarded.For",
            "CF.Connecting.IP",
        ] {
            assert!(is_forwarding_authority_header(name), "{name}");
        }
        for name in ["user-agent", "accept", "x-requested-with", "x-cache"] {
            assert!(!is_forwarding_authority_header(name), "{name}");
        }
    }

    /// Regression (#600): identity headers honored by common client-IP
    /// resolvers fail closed too, without catching ordinary `x-*` names.
    #[test]
    fn resolver_identity_headers_fail_closed() {
        for name in [
            "X-Forwarded",
            "X-AppEngine-User-IP",
            "Cf-Pseudo-IPv4",
            "CF-Connecting-IPv6",
            "X-ProxyUser-Ip",
            "X-Remote-Addr",
            "X-Remote-IP",
            "X-Originating-IP",
            "X_Forwarded_For",
            "True-Client-IPv6",
            "Fastly-Client-Addr",
        ] {
            assert!(is_forwarding_authority_header(name), "{name}");
        }
        for name in [
            "x-requested-with",
            "x-csrf-token",
            "x-api-key",
            "x-xss-protection",
            "x-content-type-options",
            "x-ship",
            "x-zip",
            "x-tip-jar",
            "cf-ray",
            "cf-ipcountry",
            "cf-visitor",
            "accept-encoding",
            "referer",
            "cookie",
        ] {
            assert!(!is_forwarding_authority_header(name), "{name}");
        }
    }
}
