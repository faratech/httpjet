//! (Tier 2) PROXY protocol inbound (v2 binary + v1 text), for deployments where an
//! L4 load balancer (HAProxy/Spectrum/tunnel) fronts the origin and carries the real
//! client address. Per-LISTENER opt-in (`<listener><proxyProtocol>`): when enabled,
//! the first bytes of EVERY connection to that listener must be a PROXY header —
//! anything else is closed (fail-closed). A PROXY command's source address overrides
//! the TCP peer for client-IP resolution, ACLs, and logs; LOCAL/UNKNOWN retain it.
//!
//! Security: the listener opt-in is necessary but not sufficient. Config validation
//! requires a non-empty `<proxyProtocolPeers>` allow-list on every pp-enabled
//! listener, and the accept path closes any connection whose real TCP sender is
//! not on that list BEFORE a header byte is read, so only those load balancers can
//! assert a client address. `check` still warns when a pp-enabled listener binds a
//! wildcard/public address: firewalling it to the listed peers is defense in depth.
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
/// Every read asks for at most the bytes the header still owes (exact-size reads
/// for v2, single bytes for the newline-terminated v1 line), so it never consumes
/// TLS/HTTP data. Fail-closed: if the header is absent/malformed on a pp-enabled
/// listener, returns `None` (the caller closes the connection).
pub(crate) mod reader {
    use super::*;
    use monoio::buf::IoBufMut;
    use monoio::io::AsyncReadRent;

    /// Buffer growth step for the v2 remainder: memory tracks the bytes that
    /// have actually arrived rather than the peer's declared u16 length.
    const V2_READ_CHUNK: usize = 16 * 1024;

    /// Append bytes to `buf` until it holds exactly `total`. Each read targets
    /// only the unfilled `[len, min(len + chunk, total))` window.
    async fn read_to<S: AsyncReadRent>(
        stream: &mut S,
        mut buf: Vec<u8>,
        total: usize,
    ) -> std::io::Result<Vec<u8>> {
        while buf.len() < total {
            let filled = buf.len();
            let want = (total - filled).min(V2_READ_CHUNK);
            if buf.capacity() - filled < want {
                buf.reserve_exact(want);
            }
            let (res, slice) = stream.read(buf.slice_mut(filled..filled + want)).await;
            buf = slice.into_inner();
            if res? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed during PROXY header",
                ));
            }
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
        let prefix = read_to(stream, Vec::new(), V2_SIGNATURE.len()).await?;
        if prefix == V2_SIGNATURE {
            let header = read_to(stream, prefix, V2_HEADER_LEN).await?;
            // v2 binary: the fixed header declares the variable-length remainder.
            let len = u16::from_be_bytes([header[14], header[15]]) as usize;
            let full = read_to(stream, header, V2_HEADER_LEN + len).await?;
            Ok(parse_v2(&full))
        } else if prefix.starts_with(b"PROXY ") {
            // Possibly v1 text: read until \n (max V1_MAX_LINE bytes total). The
            // line has no length prefix, so one byte per read is the only way to
            // stop exactly at its end.
            let mut line = prefix;
            line.reserve_exact(V1_MAX_LINE - line.len());
            while line.len() < V1_MAX_LINE {
                let filled = line.len();
                let (res, slice) = stream.read(line.slice_mut(filled..filled + 1)).await;
                line = slice.into_inner();
                if res? == 0 {
                    break;
                }
                if line[filled] == b'\n' {
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

    /// Serves `data` in reads of at most `max_read` bytes and counts them.
    struct CountingReader<'a> {
        data: &'a [u8],
        max_read: usize,
        reads: usize,
    }

    impl AsyncReadRent for CountingReader<'_> {
        fn read<T: monoio::buf::IoBufMut>(
            &mut self,
            mut buf: T,
        ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
            self.reads += 1;
            let amt = self.data.len().min(self.max_read).min(buf.bytes_total());
            // SAFETY: `write_ptr` is valid for `bytes_total()` writable bytes and
            // `amt` never exceeds that; `set_init` then covers exactly those bytes.
            unsafe {
                buf.write_ptr()
                    .copy_from_nonoverlapping(self.data.as_ptr(), amt);
                buf.set_init(amt);
            }
            self.data = &self.data[amt..];
            std::future::ready((Ok(amt), buf))
        }

        fn readv<T: monoio::buf::IoVecBufMut>(
            &mut self,
            buf: T,
        ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
            std::future::ready((Ok(0), buf))
        }
    }

    fn strip_counted(payload: &[u8], max_read: usize) -> (Option<ProxyHeader>, usize, Vec<u8>) {
        let mut rt = build_core_runtime().unwrap();
        rt.block_on(async {
            let mut reader = CountingReader {
                data: payload,
                max_read,
                reads: 0,
            };
            let stripped = read_and_strip(&mut reader, None).await.unwrap();
            (stripped, reader.reads, reader.data.to_vec())
        })
    }

    #[test]
    fn v2_max_length_remainder_is_read_in_bulk_without_over_read() {
        let tls_prefix = [0x16, 0x03, 0x03, 0x00, 0x01];
        let mut local = v2_header(u16::MAX, 0x00);
        local[12] = 0x20;
        local.resize(V2_HEADER_LEN + usize::from(u16::MAX), 0xab);
        let header_len = local.len();
        local.extend_from_slice(&tls_prefix);

        let (stripped, reads, rest) = strip_counted(&local, usize::MAX);
        let h = stripped.expect("max-length LOCAL header stripped");
        assert_eq!(h.consumed, header_len);
        assert_eq!(
            rest, tls_prefix,
            "bytes past the declared length stay unread"
        );
        assert!(
            reads <= 8,
            "a 64 KiB remainder must not cost one read per byte (took {reads} reads)"
        );

        let (stripped, reads, rest) = strip_counted(&local, 1000);
        assert_eq!(stripped.expect("fragmented header").consumed, header_len);
        assert_eq!(rest, tls_prefix);
        assert!(reads <= header_len / 1000 + 8, "took {reads} reads");
    }

    #[test]
    fn v1_line_stops_at_its_newline_under_bulk_delivery() {
        let line = b"PROXY TCP4 198.51.100.22 10.0.0.1 5678 80\r\n";
        let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut payload = line.to_vec();
        payload.extend_from_slice(request);

        let (stripped, _reads, rest) = strip_counted(&payload, usize::MAX);
        assert_eq!(stripped.expect("v1 header stripped").consumed, line.len());
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
