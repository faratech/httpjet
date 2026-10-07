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
//!
//! One claim is refused outright: a source that is loopback or unspecified
//! (127/8, ::1, 0.0.0.0, ::, and v4-mapped forms). Those addresses are how the
//! origin recognizes its OWN local-trust boundary — the client-cert (mTLS)
//! exemption, the loopback-gated purge/ready endpoints, and the plaintext
//! mTLS-gate redirect — so a header claiming one would let an untrusted client
//! on a pp-enabled listener say "I am loopback" and cross all three. Genuine
//! load balancers never send loopback sources for relayed clients, so such a
//! header is malformed: the connection is closed (fail-closed), like any other
//! unparseable header.

pub use super::proxy_protocol_wire::*;

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
    use std::net::SocketAddr;

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
