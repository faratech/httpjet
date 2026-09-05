//! (Tier 2) PROXY protocol inbound (v2 binary + v1 text), for deployments where an
//! L4 load balancer (HAProxy/Spectrum/tunnel) fronts the origin and carries the real
//! client address. Per-LISTENER opt-in (`<listener><proxyProtocol>`): when enabled,
//! the first bytes of EVERY connection to that listener must be a PROXY header —
//! anything else is closed (fail-closed). A PROXY command's source address overrides
//! the TCP peer for client-IP resolution, ACLs, and logs; LOCAL/UNKNOWN retain it.
//!
//! Security: the listener opt-in IS the trust decision (nginx/HAProxy semantics) —
//! there is no per-peer list at accept time, so enabling it on a listener reachable
//! by untrusted clients lets them forge their client address. `check` warns when a
//! pp-enabled listener binds a wildcard/public address. (OLS models the equivalent
//! server-level `<proxyProtocol>` as a peer allow-list; httpjet's per-listener form
//! is deliberate — the flag scopes to exactly one accept path.)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The PROXY v2 signature: `\r\n\r\n\0\r\nQUIT\n` (12 bytes), preceded by the
/// 4-byte length prefix position. The full fixed header is 16 bytes.
const V2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];
const V2_HEADER_LEN: usize = 16;
const V1_MAX_LINE: usize = 107;

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
fn v2_header(len: u16, family: u8) -> Vec<u8> {
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

/// (Tier 1.2 accept-path wiring) Async reader: strips the PROXY header from the
/// start of a monoio TcpStream and returns the overridden source address.
/// Reads byte-by-byte (or in exact chunks) to avoid over-reading into TLS data.
/// Fail-closed: if the header is absent/malformed on a pp-enabled listener,
/// returns `None` (the caller closes the connection).
pub(crate) mod reader {
    use super::*;
    use monoio::io::AsyncReadRent;

    /// Read exactly `n` bytes from the stream. Returns the buffer.
    async fn read_exact<S: AsyncReadRent>(stream: &mut S, n: usize) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(n);
        let mut tmp = vec![0u8; 1];
        while buf.len() < n {
            let (res, t) = stream.read(tmp).await;
            tmp = t;
            let read_len = res?;
            if read_len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed during PROXY header",
                ));
            }
            buf.extend_from_slice(&tmp[..read_len]);
        }
        Ok(buf)
    }

    /// Read and strip the PROXY header. `timeout` is one deadline for the whole
    /// header, including its variable-length portion; `None` preserves the
    /// configured `connTimeout=0` meaning of no deadline. Returns
    /// `Some((src, consumed))` if a valid header was found and stripped, `None`
    /// if the stream doesn't start with a PROXY header (the caller must close the
    /// connection on a pp-enabled listener).
    pub(crate) async fn read_and_strip<S: AsyncReadRent>(
        stream: &mut S,
        timeout: Option<std::time::Duration>,
    ) -> std::io::Result<Option<ProxyHeader>> {
        let read = read_and_strip_unbounded(stream);
        match timeout {
            Some(duration) => monoio::time::timeout(duration, read).await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "PROXY protocol header timed out",
                )
            })?,
            None => read.await,
        }
    }

    async fn read_and_strip_unbounded<S: AsyncReadRent>(
        stream: &mut S,
    ) -> std::io::Result<Option<ProxyHeader>> {
        // Twelve bytes distinguish the binary v2 signature from the text v1
        // prefix without over-reading the minimal 15-byte `PROXY UNKNOWN\r\n`.
        let prefix = read_exact(stream, V2_SIGNATURE.len()).await?;
        if prefix == V2_SIGNATURE {
            let fixed_tail = read_exact(stream, V2_HEADER_LEN - V2_SIGNATURE.len()).await?;
            let mut header = prefix;
            header.extend_from_slice(&fixed_tail);
            // v2 binary: read the variable-length address block.
            let len = u16::from_be_bytes([header[14], header[15]]) as usize;
            let addr = read_exact(stream, len).await?;
            let mut full = header;
            full.extend_from_slice(&addr);
            Ok(parse_v2(&full))
        } else if prefix.starts_with(b"PROXY ") {
            // Possibly v1 text: read until \n (max V1_MAX_LINE bytes total).
            let mut line = prefix;
            while line.len() < V1_MAX_LINE {
                let (res, t) = stream.read(vec![0u8; 1]).await;
                if res? == 0 {
                    break;
                }
                let byte = t[0];
                line.push(byte);
                if byte == b'\n' {
                    break;
                }
            }
            Ok(parse_v1(&line))
        } else {
            // Neither v2 nor v1: not a PROXY connection.
            Ok(None)
        }
    }
}

#[cfg(test)]
mod accept_tests {
    //! The accept-path contract on a REAL loopback socket: strip exactly the header
    //! bytes (no over-read into the request/TLS stream), override the peer, and
    //! report absence so the caller can fail closed.
    use super::super::build_core_runtime;
    use super::reader::read_and_strip;
    use super::*;
    use monoio::io::AsyncReadRent;

    /// Serve one accepted connection through `read_and_strip`, then read exactly
    /// `follow_len` more bytes. Returns (real peer, strip outcome, those bytes).
    fn serve_one(payload: &[u8], follow_len: usize) -> (SocketAddr, Option<ProxyHeader>, Vec<u8>) {
        use std::io::Write;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut rt = build_core_runtime().unwrap();
            rt.block_on(async move {
                let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
                let (mut stream, peer) = listener.accept().await.unwrap();
                let stripped = read_and_strip(&mut stream, None).await.unwrap();
                let mut rest = Vec::with_capacity(follow_len);
                while rest.len() < follow_len {
                    let (res, buf) =
                        AsyncReadRent::read(&mut stream, vec![0u8; follow_len - rest.len()]).await;
                    let n = res.unwrap();
                    if n == 0 {
                        break;
                    }
                    rest.extend_from_slice(&buf[..n]);
                }
                let _ = tx.send((peer, stripped, rest));
            });
        });
        let mut client = std::net::TcpStream::connect(address).unwrap();
        client.write_all(payload).unwrap();
        rx.recv().unwrap()
    }

    #[test]
    fn v2_accept_path_overrides_peer_and_preserves_request() {
        let mut payload = v2_header(12, 0x11);
        payload.extend_from_slice(&[203, 0, 113, 9]); // src
        payload.extend_from_slice(&[10, 0, 0, 1]); // dst
        payload.extend_from_slice(&[0x1f, 0x90]); // sport 8080
        payload.extend_from_slice(&[0x00, 0x50]); // dport 80
        let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        payload.extend_from_slice(request);

        let (peer, stripped, rest) = serve_one(&payload, request.len());
        let h = stripped.expect("v2 header stripped on a pp-enabled connection");
        assert_eq!(h.src, Some(SocketAddr::from(([203, 0, 113, 9], 8080))));
        assert_ne!(
            Some(peer),
            h.src,
            "the overridden address replaces the TCP peer"
        );
        assert_eq!(
            h.consumed,
            payload.len() - request.len(),
            "only the header bytes are consumed"
        );
        assert_eq!(
            rest, request,
            "the request stream must arrive intact after the strip"
        );
    }

    #[test]
    fn v1_accept_path_overrides_peer_and_preserves_request() {
        let line = b"PROXY TCP4 198.51.100.22 10.0.0.1 5678 80\r\n";
        let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut payload = line.to_vec();
        payload.extend_from_slice(request);

        let (peer, stripped, rest) = serve_one(&payload, request.len());
        let h = stripped.expect("v1 header stripped on a pp-enabled connection");
        assert_eq!(h.src, Some(SocketAddr::from(([198, 51, 100, 22], 5678))));
        assert_ne!(Some(peer), h.src);
        assert_eq!(h.consumed, line.len());
        assert_eq!(rest, request);
    }

    #[test]
    fn identity_preserving_commands_do_not_consume_following_protocol_bytes() {
        let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut unknown = b"PROXY UNKNOWN\r\n".to_vec();
        unknown.extend_from_slice(request);
        let (peer, stripped, rest) = serve_one(&unknown, request.len());
        let h = stripped.expect("UNKNOWN header stripped");
        assert_eq!(h.src, None);
        assert!(peer.ip().is_loopback());
        assert_eq!(rest, request);

        let tls_prefix = [0x16, 0x03, 0x03, 0x00, 0x01];
        let mut local = v2_header(0, 0x00);
        local[12] = 0x20;
        local.extend_from_slice(&tls_prefix);
        let (peer, stripped, rest) = serve_one(&local, tls_prefix.len());
        let h = stripped.expect("LOCAL header stripped");
        assert_eq!(h.src, None);
        assert!(peer.ip().is_loopback());
        assert_eq!(rest, tls_prefix);
    }

    #[test]
    fn non_proxy_connection_is_reported_absent_for_fail_closed_close() {
        let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let (_peer, stripped, _rest) = serve_one(request, 0);
        assert!(
            stripped.is_none(),
            "a non-PROXY connection must be reported absent so the accept path closes it"
        );
    }

    #[test]
    fn partial_proxy_header_obeys_one_total_timeout() {
        use std::io::Write;
        use std::time::{Duration, Instant};

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut rt = build_core_runtime().unwrap();
            rt.block_on(async move {
                let listener = monoio::net::TcpListener::from_std(std_listener).unwrap();
                let (mut stream, _) = listener.accept().await.unwrap();
                let started = Instant::now();
                let err = match read_and_strip(&mut stream, Some(Duration::from_millis(100))).await
                {
                    Err(err) => err,
                    Ok(_) => panic!("a stalled partial header must time out"),
                };
                let _ = tx.send((err.kind(), started.elapsed()));
            });
        });

        let mut client = std::net::TcpStream::connect(address).unwrap();
        client.write_all(b"P").unwrap();
        let (kind, elapsed) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(kind, std::io::ErrorKind::TimedOut);
        assert!(
            elapsed >= Duration::from_millis(75) && elapsed < Duration::from_secs(1),
            "one 100 ms header deadline should fire promptly, got {elapsed:?}"
        );
        drop(client);
    }
}
