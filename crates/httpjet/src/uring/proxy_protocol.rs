//! (Tier 2) PROXY protocol inbound (v2 binary + v1 text), for deployments where an
//! L4 load balancer (HAProxy/Spectrum/tunnel) fronts the origin and carries the real
//! client address. Per-LISTENER opt-in (`<listener><proxyProtocol>`): when enabled,
//! the first bytes of EVERY connection to that listener must be a PROXY header —
//! anything else is closed (fail-closed). The header's source address then overrides
//! the TCP peer for client-IP resolution, ACLs, and logs.
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

/// Parsed header outcome: the real source address plus how many wire bytes the
/// header consumed (so the caller can prepend any over-read remainder). The
/// accept path's reader consumes exactly the header, so `consumed` is asserted
/// by tests rather than read in production code.
#[allow(dead_code)]
pub struct ProxyHeader {
    pub src: SocketAddr,
    pub consumed: usize,
}

/// Parse a complete v2 binary header from `buf` (must be `V2_HEADER_LEN + len`
/// bytes). Returns the source address and the total consumed length.
pub fn parse_v2(buf: &[u8]) -> Option<ProxyHeader> {
    if buf.len() < V2_HEADER_LEN || buf[..12] != V2_SIGNATURE {
        return None;
    }
    let ver_cmd = buf[12];
    // Only the LOCAL/PROXY commands of version 2.
    if ver_cmd >> 4 != 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if buf.len() < V2_HEADER_LEN + len {
        return None;
    }
    let family = buf[13] >> 4; // high nibble: AF_INET=1, AF_INET6=2
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
        src,
        consumed: V2_HEADER_LEN + len,
    })
}

/// Parse a v1 text header line (`PROXY TCP4 src dst sport dport\r\n` / `UNKNOWN`).
pub fn parse_v1(line: &[u8]) -> Option<ProxyHeader> {
    let line = strip_crlf(line)?;
    if !line.starts_with(b"PROXY ") {
        return None;
    }
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.split_whitespace();
    let _proto = parts.next()?;
    let ip: std::net::IpAddr = match parts.next()?.to_ascii_uppercase().as_str() {
        "TCP4" => parts.next()?.parse::<Ipv4Addr>().ok()?.into(),
        "TCP6" => parts.next()?.parse::<Ipv6Addr>().ok()?.into(),
        _ => return None,
    };
    let _dst = parts.next()?;
    let sport: u16 = parts.next()?.parse().ok()?;
    let _dport = parts.next()?;
    let consumed = text.len() + 2; // + CRLF
    Some(ProxyHeader {
        src: SocketAddr::new(ip, sport),
        consumed,
    })
}

fn strip_crlf(line: &[u8]) -> Option<&[u8]> {
    let line = line.strip_suffix(b"\n")?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    Some(line)
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
        assert_eq!(h.src, SocketAddr::from(([203, 0, 113, 9], 8080)));
        assert_eq!(h.consumed, 28);
    }

    #[test]
    fn v2_tcp6_parses_source_address() {
        let mut buf = v2_header(36, 0x21);
        buf.extend_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].repeat(2));
        buf.extend_from_slice(&[0x1f, 0x90]);
        buf.extend_from_slice(&[0x00, 0x50]);
        let h = parse_v2(&buf).expect("parses");
        assert!(h.src.is_ipv6());
        assert_eq!(h.src.port(), 8080);
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
    fn v1_text_parses_source_and_consumed_length() {
        let line = b"PROXY TCP4 203.0.113.9 10.0.0.1 8080 80\r\n";
        let h = parse_v1(line).expect("parses");
        assert_eq!(h.src, SocketAddr::from(([203, 0, 113, 9], 8080)));
        assert_eq!(h.consumed, line.len());
        assert!(parse_v1(b"GET / HTTP/1.1\r\n").is_none());
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

    /// Read and strip the PROXY header. Returns `Some((src, consumed))` if a valid
    /// header was found and stripped, `None` if the stream doesn't start with a
    /// PROXY header (the caller must close the connection on a pp-enabled listener).
    pub(crate) async fn read_and_strip<S: AsyncReadRent>(
        stream: &mut S,
    ) -> std::io::Result<Option<ProxyHeader>> {
        // Read the fixed v2 header (16 bytes) to check the signature.
        let header = read_exact(stream, V2_HEADER_LEN).await?;
        if header[..12] == V2_SIGNATURE {
            // v2 binary: read the variable-length address block.
            let len = u16::from_be_bytes([header[14], header[15]]) as usize;
            let addr = read_exact(stream, len).await?;
            let mut full = header;
            full.extend_from_slice(&addr);
            Ok(parse_v2(&full))
        } else if header[0] == b'P' {
            // Possibly v1 text: read until \n (max V1_MAX_LINE bytes total).
            let mut line = header.clone();
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
                let stripped = read_and_strip(&mut stream).await.unwrap();
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
        assert_eq!(h.src, SocketAddr::from(([203, 0, 113, 9], 8080)));
        assert_ne!(peer, h.src, "the overridden address replaces the TCP peer");
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
        assert_eq!(h.src, SocketAddr::from(([198, 51, 100, 22], 5678)));
        assert_ne!(peer, h.src);
        assert_eq!(h.consumed, line.len());
        assert_eq!(rest, request);
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
}
