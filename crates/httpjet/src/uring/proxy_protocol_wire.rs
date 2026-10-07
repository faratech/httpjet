//! PROXY protocol v1/v2 header parsing (wire format only; the connection-level reader
//! and the trust policy live in `proxy_protocol`). Std only, so the fuzz workspace can
//! include this file directly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The PROXY v2 signature: `\r\n\r\n\0\r\nQUIT\n` (12 bytes), preceded by the
/// 4-byte length prefix position. The full fixed header is 16 bytes.
pub(crate) const V2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];
pub(crate) const V2_HEADER_LEN: usize = 16;
pub(crate) const V1_MAX_LINE: usize = 107;

/// A claimed source the origin reserves for its own local-trust boundary —
/// refused as malformed (see the module security note).
pub(crate) fn claimed_source_forbidden(ip: IpAddr) -> bool {
    let canonical = ip.to_canonical();
    canonical.is_loopback() || canonical.is_unspecified()
}

/// Parsed header outcome. `src` is absent for identity-preserving LOCAL (v2) or
/// UNKNOWN (v1) commands; callers then retain the socket peer. `consumed` is the
/// exact header length and is asserted by tests.
#[allow(dead_code)]
pub struct ProxyHeader {
    pub src: Option<SocketAddr>,
    pub consumed: usize,
}

/// Parse a complete v2 binary header from `buf` (must be `V2_HEADER_LEN + len`
/// bytes). Returns the source address and the total consumed length.
pub fn parse_v2(buf: &[u8]) -> Option<ProxyHeader> {
    if buf.len() < V2_HEADER_LEN || buf[..12] != V2_SIGNATURE {
        return None;
    }
    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if buf.len() < V2_HEADER_LEN + len {
        return None;
    }
    // LOCAL means the connection was made intentionally by the proxy without
    // relaying an upstream address. The family/protocol and payload are ignored.
    if ver_cmd & 0x0f == 0x00 {
        return Some(ProxyHeader {
            src: None,
            consumed: V2_HEADER_LEN + len,
        });
    }
    // Values other than LOCAL (0) and PROXY (1) are invalid commands.
    if ver_cmd & 0x0f != 0x01 {
        return None;
    }

    let family = buf[13] >> 4; // high nibble: AF_INET=1, AF_INET6=2
    let transport = buf[13] & 0x0f;
    // TCP listeners accept only STREAM tuples. DGRAM/UNSPEC must not be
    // interpreted as a stream peer address.
    if transport != 0x01 {
        return None;
    }
    let addr = &buf[V2_HEADER_LEN..V2_HEADER_LEN + len];
    let src = match family {
        0x1 => {
            // AF_INET + TCP: 4b src, 4b dst, 2b sport, 2b dport.
            if addr.len() < 12 {
                return None;
            }
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
                u16::from_be_bytes([addr[8], addr[9]]),
            )
        }
        0x2 => {
            // AF_INET6 + TCP: 16b src, 16b dst, 2b sport, 2b dport.
            if addr.len() < 36 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&addr[0..16]);
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(o)),
                u16::from_be_bytes([addr[32], addr[33]]),
            )
        }
        _ => return None,
    };
    if claimed_source_forbidden(src.ip()) {
        return None;
    }
    Some(ProxyHeader {
        src: Some(src),
        consumed: V2_HEADER_LEN + len,
    })
}

/// Parse a v1 text header line (`PROXY TCP4 src dst sport dport\r\n` / `UNKNOWN`).
pub fn parse_v1(line: &[u8]) -> Option<ProxyHeader> {
    let line = strip_crlf(line)?;
    let text = std::str::from_utf8(line).ok()?;
    let fields = text.strip_prefix("PROXY ")?;
    if fields == "UNKNOWN" || fields.starts_with("UNKNOWN ") {
        return Some(ProxyHeader {
            src: None,
            consumed: text.len() + 2,
        });
    }

    // Known families have exactly six fields separated by one SP. Validate both
    // endpoints and ports even though only the source tuple is retained; otherwise a
    // malformed destination or appended field can be smuggled through as a valid preface.
    let mut parts = text.split(' ');
    if parts.next()? != "PROXY" {
        return None;
    }
    let family = parts.next()?;
    let src = parts.next()?;
    let dst = parts.next()?;
    let sport = parse_v1_port(parts.next()?)?;
    let _dport = parse_v1_port(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    let ip: std::net::IpAddr = match family {
        "TCP4" => {
            let src = src.parse::<Ipv4Addr>().ok()?;
            dst.parse::<Ipv4Addr>().ok()?;
            src.into()
        }
        "TCP6" => {
            let src = src.parse::<Ipv6Addr>().ok()?;
            dst.parse::<Ipv6Addr>().ok()?;
            src.into()
        }
        _ => return None,
    };
    let consumed = text.len() + 2; // + CRLF
    if claimed_source_forbidden(ip) {
        return None;
    }
    Some(ProxyHeader {
        src: Some(SocketAddr::new(ip, sport)),
        consumed,
    })
}

fn parse_v1_port(value: &str) -> Option<u16> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

fn strip_crlf(line: &[u8]) -> Option<&[u8]> {
    line.strip_suffix(b"\r\n")
}

#[cfg(test)]
pub(crate) fn v2_header(len: u16, family: u8) -> Vec<u8> {
    let mut v = V2_SIGNATURE.to_vec();
    v.push(0x21); // version 2, command PROXY
    v.push(family);
    v.extend_from_slice(&len.to_be_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_tcp4_parses_source_address_and_length() {
        let mut buf = v2_header(12, 0x11);
        buf.extend_from_slice(&[203, 0, 113, 9]); // src
        buf.extend_from_slice(&[10, 0, 0, 1]); // dst
        buf.extend_from_slice(&[0x1f, 0x90]); // sport 8080
        buf.extend_from_slice(&[0x00, 0x50]); // dport 80
        buf.extend_from_slice(b"TAIL"); // over-read must not count
        let h = parse_v2(&buf).expect("parses");
        assert_eq!(h.src, Some(SocketAddr::from(([203, 0, 113, 9], 8080))));
        assert_eq!(h.consumed, 28);
    }

    #[test]
    fn v2_tcp6_parses_source_address() {
        let mut buf = v2_header(36, 0x21);
        buf.extend_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].repeat(2));
        buf.extend_from_slice(&[0x1f, 0x90]);
        buf.extend_from_slice(&[0x00, 0x50]);
        let h = parse_v2(&buf).expect("parses");
        assert!(h.src.unwrap().is_ipv6());
        assert_eq!(h.src.unwrap().port(), 8080);
        assert_eq!(h.consumed, 52);
    }

    #[test]
    fn v2_rejects_wrong_signature_or_version() {
        let mut buf = v2_header(0, 0x11);
        buf[0] = b'X';
        assert!(parse_v2(&buf).is_none());
        let mut buf2 = v2_header(0, 0x11);
        buf2[12] = 0x11; // version 1
        assert!(parse_v2(&buf2).is_none());
    }

    #[test]
    fn v2_local_preserves_peer_and_invalid_command_or_transport_is_rejected() {
        let mut local = v2_header(4, 0x12);
        local[12] = 0x20; // version 2, LOCAL; family/protocol and payload ignored
        local.extend_from_slice(b"junk");
        let h = parse_v2(&local).expect("LOCAL command is valid");
        assert_eq!(h.src, None);
        assert_eq!(h.consumed, local.len());

        let mut invalid_command = v2_header(12, 0x11);
        invalid_command[12] = 0x22;
        invalid_command.extend_from_slice(&[0; 12]);
        assert!(parse_v2(&invalid_command).is_none());

        let mut dgram = v2_header(12, 0x12);
        dgram.extend_from_slice(&[0; 12]);
        assert!(parse_v2(&dgram).is_none());
    }

    #[test]
    fn v1_text_parses_source_and_consumed_length() {
        let line = b"PROXY TCP4 203.0.113.9 10.0.0.1 8080 80\r\n";
        let h = parse_v1(line).expect("parses");
        assert_eq!(h.src, Some(SocketAddr::from(([203, 0, 113, 9], 8080))));
        assert_eq!(h.consumed, line.len());
        assert!(parse_v1(b"GET / HTTP/1.1\r\n").is_none());
    }

    /// A pp header must not be able to claim the origin's own local-trust
    /// addresses (loopback/unspecified): those flip the mTLS exemption, the
    /// purge/ready endpoint gate, and the plaintext mTLS-gate redirect. Such a
    /// header is malformed — the connection is closed — in both v1 and v2.
    #[test]
    fn claimed_loopback_or_unspecified_sources_are_refused() {
        // v2, IPv4: 127.0.0.1, 127.8.8.8, 0.0.0.0.
        for src in [[127u8, 0, 0, 1], [127, 8, 8, 8], [0, 0, 0, 0]] {
            let mut buf = v2_header(12, 0x11);
            buf.extend_from_slice(&src);
            buf.extend_from_slice(&[10, 0, 0, 1]);
            buf.extend_from_slice(&[0x1f, 0x90]);
            buf.extend_from_slice(&[0x00, 0x50]);
            assert!(
                parse_v2(&buf).is_none(),
                "v2 claimed {src:?} must be refused"
            );
        }
        // v2, IPv6: ::1, ::, ::ffff:127.0.0.1 (v4-mapped loopback).
        let v6_sources: Vec<[u8; 16]> = vec![
            {
                let mut o = [0u8; 16];
                o[15] = 1; // ::1
                o
            },
            [0u8; 16], // ::
            {
                let mut o = [0u8; 16];
                o[10] = 0xff;
                o[11] = 0xff;
                o[12] = 127; // ::ffff:127.0.0.1
                o
            },
        ];
        for o in v6_sources {
            let mut buf = v2_header(36, 0x21);
            buf.extend_from_slice(&o);
            buf.extend_from_slice(&o);
            buf.extend_from_slice(&[0x1f, 0x90]);
            buf.extend_from_slice(&[0x00, 0x50]);
            assert!(
                parse_v2(&buf).is_none(),
                "v2 claimed ::1-form must be refused"
            );
        }
        // v1 text: loopback, unspecified, v4-mapped.
        assert!(parse_v1(b"PROXY TCP4 127.0.0.1 10.0.0.1 8080 80\r\n").is_none());
        assert!(parse_v1(b"PROXY TCP4 0.0.0.0 10.0.0.1 8080 80\r\n").is_none());
        assert!(parse_v1(b"PROXY TCP6 ::1 2001:db8::1 8080 80\r\n").is_none());
        assert!(parse_v1(b"PROXY TCP6 ::ffff:127.0.0.1 2001:db8::1 8080 80\r\n").is_none());
        // A real relayed client address still parses.
        assert!(parse_v1(b"PROXY TCP4 198.51.100.7 10.0.0.1 443 80\r\n").is_some());
    }

    #[test]
    fn v1_known_family_requires_exact_fields_and_crlf() {
        for malformed in [
            b"PROXY tcp4 203.0.113.9 10.0.0.1 8080 80\r\n".as_slice(),
            b"PROXY TCP4 203.0.113.9 not-an-ip 8080 80\r\n".as_slice(),
            b"PROXY TCP4 203.0.113.9 ::1 8080 80\r\n".as_slice(),
            b"PROXY TCP6 ::1 127.0.0.1 8080 80\r\n".as_slice(),
            b"PROXY TCP4 203.0.113.9 10.0.0.1 +8080 80\r\n".as_slice(),
            b"PROXY TCP4 203.0.113.9 10.0.0.1 08080 80\r\n".as_slice(),
            b"PROXY TCP4 203.0.113.9 10.0.0.1 8080 invalid\r\n".as_slice(),
            b"PROXY TCP4 203.0.113.9 10.0.0.1 8080 80 extra\r\n".as_slice(),
            b"PROXY  TCP4 203.0.113.9 10.0.0.1 8080 80\r\n".as_slice(),
            b"PROXY TCP4 203.0.113.9 10.0.0.1 8080 80\n".as_slice(),
        ] {
            assert!(
                parse_v1(malformed).is_none(),
                "accepted malformed v1 preface: {malformed:?}"
            );
        }
        let tcp6 = b"PROXY TCP6 2001:db8::1 2001:db8::2 443 8443\r\n";
        assert_eq!(
            parse_v1(tcp6).and_then(|header| header.src),
            Some("[2001:db8::1]:443".parse().unwrap())
        );
    }

    #[test]
    fn v1_unknown_preserves_peer() {
        let line = b"PROXY UNKNOWN\r\n";
        let h = parse_v1(line).expect("UNKNOWN is a valid v1 command");
        assert_eq!(h.src, None);
        assert_eq!(h.consumed, line.len());
        let extended = b"PROXY UNKNOWN arbitrary trailing bytes are ignored\r\n";
        let extended = parse_v1(extended).expect("UNKNOWN permits an ignored trailing payload");
        assert_eq!(extended.src, None);
        assert!(parse_v1(b"PROXY UNKNOWN-without-delimiter\r\n").is_none());
        assert!(parse_v1(b"PROXY UNKNOWN\n").is_none());
    }
}
