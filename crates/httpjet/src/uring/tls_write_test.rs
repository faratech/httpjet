//! Ciphertext write coalescing in the vendored monoio-rustls adapter (#971): every
//! record rustls has queued leaves in one socket write, and the bytes are unchanged.

use std::cell::RefCell;
use std::future::Future;
use std::io::{self, Read};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut, VecBuf};
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Splitable};

/// The client end of an in-memory TLS connection. Each server write is decrypted as
/// soon as it arrives, and the client's reply is queued for the server's next read.
struct Client {
    tls: rustls::ClientConnection,
    to_server: Vec<u8>,
    plaintext: Vec<u8>,
    /// Socket writes that delivered bytes.
    writes: usize,
    /// Socket write calls, failed ones included.
    calls: usize,
    /// Bytes a write call accepts at most: a full socket buffer's short write.
    max_write: usize,
    /// Every Nth write call is first Pending once, as a direct write that hit
    /// EAGAIN and fell back to the ring.
    pend_every: usize,
    /// This write call fails with a connection reset.
    fail_call: Option<usize>,
}

impl Client {
    fn deliver(&mut self, mut ciphertext: &[u8]) {
        let mut chunk = [0u8; 16 * 1024];
        while !ciphertext.is_empty() {
            self.tls.read_tls(&mut ciphertext).unwrap();
            self.tls.process_new_packets().unwrap();
            loop {
                match self.tls.reader().read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => self.plaintext.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("client read: {e}"),
                }
            }
        }
        while self.tls.wants_write() {
            self.tls.write_tls(&mut self.to_server).unwrap();
        }
    }
}

struct MemoryIo(Rc<RefCell<Client>>);

impl AsyncReadRent for MemoryIo {
    async fn read<T: IoBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        let mut client = self.0.borrow_mut();
        let n = client.to_server.len().min(buf.bytes_total());
        // SAFETY: `write_ptr` is valid for `bytes_total` bytes and `n` does not exceed it.
        unsafe {
            std::ptr::copy_nonoverlapping(client.to_server.as_ptr(), buf.write_ptr(), n);
            buf.set_init(n);
        }
        client.to_server.drain(..n);
        (Ok(n), buf)
    }

    async fn readv<T: IoVecBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        (Ok(0), buf)
    }
}

// SAFETY: the halves share one RefCell'd client and only ever run on one task;
// neither method holds the borrow across an await.
unsafe impl monoio::io::Split for MemoryIo {}

/// Pending once, then ready.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

const SINK_RESET: &str = "sink reset mid-batch";

impl AsyncWriteRent for MemoryIo {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let (call, max_write, pend_every, fail_call) = {
            let mut client = self.0.borrow_mut();
            client.calls += 1;
            (
                client.calls,
                client.max_write,
                client.pend_every,
                client.fail_call,
            )
        };
        if pend_every != 0 && call % pend_every == 0 {
            YieldOnce(false).await;
        }
        if fail_call == Some(call) {
            return (
                Err(io::Error::new(io::ErrorKind::ConnectionReset, SINK_RESET)),
                buf,
            );
        }
        // SAFETY: an IoBuf guarantees `bytes_init` initialized bytes at `read_ptr`.
        let bytes = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
        let n = bytes.len().min(max_write);
        let mut client = self.0.borrow_mut();
        client.writes += 1;
        client.deliver(&bytes[..n]);
        (Ok(n), buf)
    }

    async fn writev<T: IoVecBuf>(&mut self, _buf: T) -> BufResult<usize, T> {
        panic!("the TLS adapter flushes ciphertext with write_all")
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn handshake(
    version: &'static rustls::SupportedProtocolVersion,
) -> (
    monoio_rustls::ServerTlsStream<MemoryIo>,
    Rc<RefCell<Client>>,
) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let mut server = rustls::ServerConfig::builder_with_protocol_versions(&[version])
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server.send_tls13_tickets = 0;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client = rustls::ClientConfig::builder_with_protocol_versions(&[version])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();
    let mut tls = rustls::ClientConnection::new(Arc::new(client), name).unwrap();
    let mut to_server = Vec::new();
    while tls.wants_write() {
        tls.write_tls(&mut to_server).unwrap();
    }
    let client = Rc::new(RefCell::new(Client {
        tls,
        to_server,
        plaintext: Vec::new(),
        writes: 0,
        calls: 0,
        max_write: usize::MAX,
        pend_every: 0,
        fail_call: None,
    }));
    let acceptor = monoio_rustls::TlsAcceptor::from(Arc::new(server));
    let stream = acceptor.accept(MemoryIo(client.clone())).await.unwrap();
    assert!(!client.borrow().tls.is_handshaking());
    (stream, client)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn tls13_server_flight_and_multi_record_write_each_take_one_socket_write() {
    let mut runtime = super::build_core_runtime().unwrap();
    runtime.block_on(async {
        let (mut stream, client) = handshake(&rustls::version::TLS13).await;
        assert_eq!(
            client.borrow().writes,
            1,
            "ServerHello through Finished leave in one write"
        );

        let body = pattern(40 * 1024);
        let (written, _) = stream.write(body.clone()).await;
        assert_eq!(written.unwrap(), body.len());
        assert_eq!(client.borrow().writes, 2, "three records, one write");
        assert_eq!(client.borrow().plaintext, body);
    });
}

#[test]
fn full_rustls_batch_is_one_socket_write() {
    let mut runtime = super::build_core_runtime().unwrap();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        runtime.block_on(async {
            let (mut stream, client) = handshake(version).await;
            let before = client.borrow().writes;
            // rustls takes 64 KiB of plaintext per write: four full records.
            let body = pattern(64 * 1024);
            let parts: Vec<Vec<u8>> = body.chunks(8 * 1024).map(<[u8]>::to_vec).collect();
            let (written, _) = stream.writev(VecBuf::from(parts)).await;
            assert_eq!(written.unwrap(), body.len());
            assert_eq!(client.borrow().writes - before, 1, "{version:?}");
            assert_eq!(client.borrow().plaintext, body, "{version:?}");
        });
    }
}

/// Short socket writes (1000 bytes a call, every third call Pending first) under
/// multi-record batches, through the unsplit stream and the split write half (the
/// h2 path): the peer still decrypts every byte, whole and in order (#971).
#[test]
fn short_and_pending_socket_writes_deliver_every_record_intact() {
    let mut runtime = super::build_core_runtime().unwrap();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        runtime.block_on(async {
            let (mut stream, client) = handshake(version).await;
            {
                let mut client = client.borrow_mut();
                client.max_write = 1000;
                client.pend_every = 3;
            }
            let mut sent = Vec::new();

            let body = pattern(40 * 1024);
            let (written, _) = stream.write(body.clone()).await;
            assert_eq!(written.unwrap(), body.len(), "{version:?}");
            sent.extend_from_slice(&body);

            let body = pattern(64 * 1024);
            let parts: Vec<Vec<u8>> = body.chunks(8 * 1024).map(<[u8]>::to_vec).collect();
            let (written, _) = stream.writev(VecBuf::from(parts)).await;
            assert_eq!(written.unwrap(), body.len(), "{version:?}");
            sent.extend_from_slice(&body);

            let body = pattern(200 * 1024 + 17);
            let (written, _) = stream.write_all(body.clone()).await;
            assert_eq!(written.unwrap(), body.len(), "{version:?}");
            sent.extend_from_slice(&body);
            assert!(client.borrow().plaintext == sent, "{version:?}: unsplit");

            let (_read, mut write) = stream.into_split();
            let body = pattern(64 * 1024);
            let parts: Vec<Vec<u8>> = body.chunks(4 * 1024).map(<[u8]>::to_vec).collect();
            let (written, _) = write.writev(VecBuf::from(parts)).await;
            assert_eq!(written.unwrap(), body.len(), "{version:?}");
            sent.extend_from_slice(&body);

            let body = pattern(150 * 1024 + 3);
            let (written, _) = write.write_all(body.clone()).await;
            assert_eq!(written.unwrap(), body.len(), "{version:?}");
            sent.extend_from_slice(&body);

            let client = client.borrow();
            assert!(client.plaintext == sent, "{version:?}: split");
            assert!(
                client.writes > sent.len() / 1000,
                "{version:?}: the sink must really have taken short writes ({})",
                client.writes
            );
        });
    }
}

/// A socket error part-way through a multi-record batch fails that write; the next
/// write returns the stored error itself and never reaches the socket (#971).
#[test]
fn socket_error_mid_batch_is_returned_by_the_next_write() {
    let mut runtime = super::build_core_runtime().unwrap();
    for split in [false, true] {
        runtime.block_on(async {
            let (stream, client) = handshake(&rustls::version::TLS13).await;
            let writes = {
                let mut client = client.borrow_mut();
                client.max_write = 1000;
                client.fail_call = Some(client.calls + 5);
                client.writes
            };
            let body = pattern(40 * 1024);
            let (first, calls, second) = if split {
                let (_read, mut write) = stream.into_split();
                let (first, _) = write.write(body).await;
                let calls = client.borrow().calls;
                let (second, _) = write.write(pattern(100)).await;
                (first, calls, second)
            } else {
                let mut stream = stream;
                let (first, _) = stream.write(body).await;
                let calls = client.borrow().calls;
                let (second, _) = stream.write(pattern(100)).await;
                (first, calls, second)
            };
            let first = first.expect_err("the reset write fails");
            assert_eq!(
                first.kind(),
                io::ErrorKind::ConnectionReset,
                "split={split}"
            );
            assert_eq!(
                client.borrow().writes - writes,
                4,
                "split={split}: four short writes left before the reset"
            );
            let second = second.expect_err("the next write fails too");
            assert_eq!(
                second.kind(),
                io::ErrorKind::ConnectionReset,
                "split={split}"
            );
            assert_eq!(
                second.to_string(),
                SINK_RESET,
                "split={split}: the stored error"
            );
            assert_eq!(
                client.borrow().calls,
                calls,
                "split={split}: the stored error is returned without a socket write"
            );
        });
    }
}
