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
