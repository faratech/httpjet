//! Kernel-TLS (kTLS) for the monoio io_uring TLS path, **with TLS 1.3 KeyUpdate
//! handling** so it survives a mid-stream rekey instead of dropping the connection.
//! Compiled only with `--features ktls`, activated only by `--ktls` (OFF by default).
//!
//! Flow: a per-connection [`hj_tls`] `KeyLog` captures this connection's raw TLS 1.3
//! traffic secrets during the handshake (rustls only surfaces them via `KeyLog`, and
//! `dangerous_extract_secrets` — which the previous draft used — both consumes the
//! connection AND yields key+iv only, not the secret needed to derive the next
//! generation). After the handshake we derive the AEAD key/iv from each secret
//! (HKDF-Expand-Label, RFC 8446 §7.1, via aws-lc-rs — already the rustls provider),
//! program the kernel socket (`TCP_ULP=tls` + `TLS_TX`/`TLS_RX`), and serve H1/H2 as
//! plaintext over the raw fd (kernel encrypt/decrypt) — killing the userspace AEAD +
//! copy on large-body egress. The drained post-handshake plaintext is handed to the
//! serve loop as a prefix, so the kernel RX resumes at the correct record sequence.
//!
//! **KeyUpdate:** the kernel surfaces a post-handshake non-application-data record as a
//! `recvmsg` control message that a plain read returns as `EIO`. [`KtlsStream`] catches
//! that, reads the record type, and: on an Alert/close_notify closes; on a Handshake
//! KeyUpdate derives the next RX traffic secret (`HKDF-Expand-Label(secret,"traffic
//! upd")`) and re-programs `TLS_RX` (sequence resets to 0). If the peer set
//! `update_requested`, we reply with our own KeyUpdate (a handshake record sent via
//! `sendmsg` + `TLS_SET_RECORD_TYPE`) and re-key `TLS_TX`. This is the per-RFC behaviour,
//! so a rekey no longer terminates the connection.
//!
//! Only TLS 1.3 is kTLS-upgraded; a TLS 1.2 connection (no KeyUpdate, different key
//! schedule) falls back to the userspace path in `handle_tls_bridged`.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Mutex;

use aws_lc_rs::hkdf::{Algorithm, HKDF_SHA256, HKDF_SHA384, KeyType, Prk};
use ktls_sys::bindings as kb;
use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};
use monoio::io::{AsyncReadRent, AsyncWriteRent, Split};
use rustls::{CipherSuite, KeyLog, SupportedCipherSuite};

// ── setsockopt / cmsg constants ───────────────────────────────────────────────
const SOL_TCP: libc::c_int = 6;
const TCP_ULP: libc::c_int = 31;
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
/// SOL_TLS cmsg type for `sendmsg` to set the emitted record's content type.
const TLS_SET_RECORD_TYPE: libc::c_int = 1;

/// TLS record content types.
const CONTENT_HANDSHAKE: u8 = 22;
/// TLS 1.3 post-handshake handshake message type for KeyUpdate.
const HS_KEY_UPDATE: u8 = 24;
/// KeyUpdate.request_update value.
const UPDATE_NOT_REQUESTED: u8 = 0;
const UPDATE_REQUESTED: u8 = 1;

/// TLS 1.3 version number for the kernel `tls_crypto_info` (major 3, minor 4).
const TLS_1_3_VERSION: u16 = 0x0304;

// ── per-connection secret capture ─────────────────────────────────────────────

/// rustls `KeyLog` that captures THIS connection's TLS 1.3 application traffic secrets
/// (`CLIENT_TRAFFIC_SECRET_0` = our RX, `SERVER_TRAFFIC_SECRET_0` = our TX). One instance
/// per connection (installed on a per-connection `ServerConfig`), so there is no
/// cross-connection race and no need to correlate by client_random.
#[derive(Debug, Default)]
pub(crate) struct ConnKeyLog {
    inner: Mutex<KeyLogState>,
}

#[derive(Debug, Default)]
struct KeyLogState {
    rx: Option<Vec<u8>>,
    tx: Option<Vec<u8>>,
}

impl ConnKeyLog {
    /// The captured (rx_secret, tx_secret) once the handshake has logged both.
    pub(crate) fn secrets(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let g = self.inner.lock().unwrap();
        Some((g.rx.clone()?, g.tx.clone()?))
    }
}

impl KeyLog for ConnKeyLog {
    fn will_log(&self, label: &str) -> bool {
        label == "CLIENT_TRAFFIC_SECRET_0" || label == "SERVER_TRAFFIC_SECRET_0"
    }
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        let mut g = self.inner.lock().unwrap();
        match label {
            "CLIENT_TRAFFIC_SECRET_0" => g.rx = Some(secret.to_vec()),
            "SERVER_TRAFFIC_SECRET_0" => g.tx = Some(secret.to_vec()),
            _ => {}
        }
    }
}

// ── cipher suite parameters ───────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum SuiteKind {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl SuiteKind {
    fn from_suite(s: SupportedCipherSuite) -> Option<Self> {
        match s.suite() {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Some(Self::Aes128Gcm),
            CipherSuite::TLS13_AES_256_GCM_SHA384 => Some(Self::Aes256Gcm),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Some(Self::Chacha20Poly1305),
            _ => None, // TLS 1.2 or unknown: caller falls back to userspace TLS
        }
    }
    fn hkdf_alg(self) -> Algorithm {
        match self {
            Self::Aes256Gcm => HKDF_SHA384,
            Self::Aes128Gcm | Self::Chacha20Poly1305 => HKDF_SHA256,
        }
    }
    fn hash_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 48,
            _ => 32,
        }
    }
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }
}

// ── HKDF-Expand-Label (RFC 8446 §7.1) ─────────────────────────────────────────

struct OkmLen(usize);
impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand_label(alg: Algorithm, secret: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let prk = Prk::new_less_safe(alg, secret);
    // struct HkdfLabel { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    // label is "tls13 " + `label`; context is empty for key/iv/"traffic upd".
    let mut full = Vec::with_capacity(6 + label.len());
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label);
    let mut info = Vec::with_capacity(3 + full.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(0); // empty context
    let mut out = vec![0u8; out_len];
    prk.expand(&[info.as_slice()], OkmLen(out_len))
        .and_then(|okm| okm.fill(&mut out))
        .expect("HKDF-Expand-Label");
    out
}

/// Next-generation application traffic secret: `HKDF-Expand-Label(secret,"traffic upd","",Hash.length)`.
fn next_traffic_secret(kind: SuiteKind, secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label(kind.hkdf_alg(), secret, b"traffic upd", kind.hash_len())
}

// ── program a kernel TLS key from a traffic secret ────────────────────────────

fn setsockopt(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    val: *const libc::c_void,
    len: libc::socklen_t,
) -> io::Result<()> {
    // SAFETY: `val`/`len` describe a fully-initialized C struct on the caller's stack for
    // the duration of the (synchronous) call; the kernel copies it in.
    let rc = unsafe { libc::setsockopt(fd, level, name, val, len) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn crypto_info_header(cipher_type: u32) -> kb::tls_crypto_info {
    kb::tls_crypto_info {
        version: TLS_1_3_VERSION,
        cipher_type: cipher_type as u16,
    }
}

/// Derive key+iv from `secret` for `kind` and install it on `fd` for `direction`
/// (`TLS_TX`/`TLS_RX`) at record sequence `seq` (0 after a handshake or a KeyUpdate).
fn set_tls_key(
    fd: RawFd,
    direction: libc::c_int,
    kind: SuiteKind,
    secret: &[u8],
    seq: u64,
) -> io::Result<()> {
    let alg = kind.hkdf_alg();
    let key = hkdf_expand_label(alg, secret, b"key", kind.key_len());
    let iv = hkdf_expand_label(alg, secret, b"iv", 12); // TLS 1.3 nonce length
    let rec_seq = seq.to_be_bytes();
    match kind {
        SuiteKind::Aes128Gcm => {
            let ci = kb::tls12_crypto_info_aes_gcm_128 {
                info: crypto_info_header(kb::TLS_CIPHER_AES_GCM_128),
                iv: iv[4..12].try_into().unwrap(),
                key: key[..16].try_into().unwrap(),
                salt: iv[0..4].try_into().unwrap(),
                rec_seq,
            };
            setsockopt(
                fd,
                SOL_TLS,
                direction,
                &ci as *const _ as *const _,
                std::mem::size_of_val(&ci) as _,
            )
        }
        SuiteKind::Aes256Gcm => {
            let ci = kb::tls12_crypto_info_aes_gcm_256 {
                info: crypto_info_header(kb::TLS_CIPHER_AES_GCM_256),
                iv: iv[4..12].try_into().unwrap(),
                key: key[..32].try_into().unwrap(),
                salt: iv[0..4].try_into().unwrap(),
                rec_seq,
            };
            setsockopt(
                fd,
                SOL_TLS,
                direction,
                &ci as *const _ as *const _,
                std::mem::size_of_val(&ci) as _,
            )
        }
        SuiteKind::Chacha20Poly1305 => {
            let ci = kb::tls12_crypto_info_chacha20_poly1305 {
                info: crypto_info_header(kb::TLS_CIPHER_CHACHA20_POLY1305),
                iv: iv[..12].try_into().unwrap(), // full 12-byte nonce, no salt
                key: key[..32].try_into().unwrap(),
                salt: kb::__IncompleteArrayField::new(),
                rec_seq,
            };
            setsockopt(
                fd,
                SOL_TLS,
                direction,
                &ci as *const _ as *const _,
                std::mem::size_of_val(&ci) as _,
            )
        }
    }
}

// ── sending a non-application-data record (our KeyUpdate reply) ────────────────

// cmsg components are aligned to libc::c_long.
#[cfg_attr(target_pointer_width = "32", repr(C, align(4)))]
#[cfg_attr(target_pointer_width = "64", repr(C, align(8)))]
struct Cmsg<const N: usize> {
    hdr: libc::cmsghdr,
    data: [u8; N],
}

/// Emit `payload` as a TLS record of `content_type` over the kTLS socket `fd`
/// (`sendmsg` with a `TLS_SET_RECORD_TYPE` control message). The kernel AEAD-encrypts it
/// with the current TX key.
fn send_record(fd: RawFd, content_type: u8, payload: &[u8]) -> io::Result<()> {
    let mut cmsg = Cmsg::<1> {
        hdr: libc::cmsghdr {
            cmsg_len: (std::mem::offset_of!(Cmsg::<1>, data) + 1) as _,
            cmsg_level: SOL_TLS,
            cmsg_type: TLS_SET_RECORD_TYPE,
        },
        data: [content_type],
    };
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };
    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: &mut cmsg as *mut _ as *mut _,
        msg_controllen: cmsg.hdr.cmsg_len as _,
        msg_flags: 0,
    };
    // SAFETY: msg/iov/cmsg are valid for the synchronous sendmsg; payload outlives the call.
    let rc = unsafe { libc::sendmsg(fd, &msg, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ── per-connection rekey state ────────────────────────────────────────────────

/// Live kTLS key state for one connection. The current RX/TX traffic secrets are kept so a
/// KeyUpdate can derive the next generation. `fd` is the (kTLS-upgraded) socket.
struct RekeyState {
    fd: RawFd,
    kind: SuiteKind,
    rx_secret: Vec<u8>,
    tx_secret: Vec<u8>,
}

impl RekeyState {
    /// Peer sent KeyUpdate: advance our RX secret and re-program `TLS_RX` (seq → 0).
    fn rekey_rx(&mut self) -> io::Result<()> {
        self.rx_secret = next_traffic_secret(self.kind, &self.rx_secret);
        set_tls_key(self.fd, TLS_RX, self.kind, &self.rx_secret, 0)
    }
    /// Advance our TX secret and re-program `TLS_TX` (seq → 0). Used when the peer's
    /// KeyUpdate requested we update in turn.
    fn rekey_tx(&mut self) -> io::Result<()> {
        self.tx_secret = next_traffic_secret(self.kind, &self.tx_secret);
        set_tls_key(self.fd, TLS_TX, self.kind, &self.tx_secret, 0)
    }
    /// Send our own KeyUpdate (request_update = not_requested) as a handshake record.
    fn send_key_update(&self) -> io::Result<()> {
        // handshake: msg_type(24) + uint24 length(1) + body: request_update(1 byte)
        let body = [HS_KEY_UPDATE, 0, 0, 1, UPDATE_NOT_REQUESTED];
        send_record(self.fd, CONTENT_HANDSHAKE, &body)
    }
}

/// Upgrade `fd` to a kTLS socket (TX + RX) from the captured TLS 1.3 traffic secrets and
/// return the live [`RekeyState`]. `suite` must be a kTLS-supported TLS 1.3 suite.
///
/// `tx_seq`/`rx_seq` are the record sequence numbers the connection has reached for each
/// direction (from `dangerous_extract_secrets`) — non-zero on TX when rustls has already
/// emitted post-handshake records (e.g. NewSessionTickets) under the app key, and on RX when
/// the peer pipelined application data we drained. Programming the kernel at the true
/// sequence is what lets us keep session tickets enabled (vs. forcing them off to pin seq 0).
fn upgrade_server(
    fd: RawFd,
    kind: SuiteKind,
    rx_secret: Vec<u8>,
    rx_seq: u64,
    tx_secret: Vec<u8>,
    tx_seq: u64,
) -> io::Result<RekeyState> {
    setsockopt(fd, SOL_TCP, TCP_ULP, c"tls".as_ptr() as *const _, 3)?;
    set_tls_key(fd, TLS_TX, kind, &tx_secret, tx_seq)?;
    set_tls_key(fd, TLS_RX, kind, &rx_secret, rx_seq)?;
    // Make the fd non-blocking so the direct-write fast path (KtlsStream::write) can fall
    // back to the io_uring write on EAGAIN instead of blocking the core. io_uring ops are
    // unaffected by O_NONBLOCK (they wait via the ring).
    // SAFETY: plain fcntl on our owned socket fd.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl >= 0 {
            let _ = libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
    Ok(RekeyState {
        fd,
        kind,
        rx_secret,
        tx_secret,
    })
}

// ── RX control-message handling ───────────────────────────────────────────────

enum RxControl {
    /// Control record consumed; the caller should retry the read.
    Continue,
    /// Peer sent an alert/close_notify; the connection is closed.
    Closed,
}

/// A plain read on a kTLS socket returned EIO because the next record is a non-application
/// record. Consume it via `recvmsg` (the record type is in a control message) and act on it.
fn handle_rx_control(state: &mut RekeyState) -> io::Result<RxControl> {
    use nix::sys::socket::{
        ControlMessageOwned, MsgFlags, SockaddrStorage, TlsGetRecordType, recvmsg,
    };
    use std::io::IoSliceMut;

    let mut data = [0u8; 64]; // KeyUpdate is 5 bytes decrypted; alerts 2
    let mut iov = [IoSliceMut::new(&mut data)];
    let mut cmsg_space = nix::cmsg_space!(u8);
    let msg =
        recvmsg::<SockaddrStorage>(state.fd, &mut iov, Some(&mut cmsg_space), MsgFlags::empty())
            .map_err(io::Error::from)?;
    let n = msg.bytes;
    let record_type = msg.cmsgs().ok().and_then(|mut c| {
        c.find_map(|m| match m {
            ControlMessageOwned::TlsGetRecordType(t) => Some(t),
            _ => None,
        })
    });

    match record_type {
        Some(TlsGetRecordType::Alert) => Ok(RxControl::Closed),
        Some(TlsGetRecordType::Handshake) => {
            // A post-handshake handshake record. To a server the realistic one is KeyUpdate.
            if n >= 5 && data[0] == HS_KEY_UPDATE {
                state.rekey_rx()?;
                if data[4] == UPDATE_REQUESTED {
                    // RFC 8446 §4.6.3: we MUST send our own KeyUpdate (not_requested) before
                    // our next application data, then our TX key advances.
                    state.send_key_update()?;
                    state.rekey_tx()?;
                }
            }
            Ok(RxControl::Continue)
        }
        // ChangeCipherSpec (middlebox compat) / unknown: ignore and retry.
        _ => Ok(RxControl::Continue),
    }
}

// ── KtlsStream: a monoio stream over the kTLS-upgraded fd ──────────────────────

/// Wraps the raw monoio stream after the kTLS upgrade. Writes go straight to the kernel
/// (which encrypts); reads transparently consume + act on RX control records (KeyUpdate /
/// alert) so the H1/H2 serve loop only ever sees plaintext application data.
pub(crate) struct KtlsStream<S> {
    inner: S,
    rekey: RekeyState,
}

impl<S: AsRawFd> KtlsStream<S> {
    fn fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

/// Build the kTLS stream: upgrade the fd (at the connection's current `rx_seq`/`tx_seq`) and
/// wrap `inner`. On upgrade error the caller must close (the fd was consumed into `inner`).
pub(crate) fn into_ktls_stream<S: AsRawFd>(
    inner: S,
    suite: SupportedCipherSuite,
    rx_secret: Vec<u8>,
    rx_seq: u64,
    tx_secret: Vec<u8>,
    tx_seq: u64,
) -> io::Result<KtlsStream<S>> {
    let kind = SuiteKind::from_suite(suite)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "kTLS: unsupported cipher suite"))?;
    let fd = inner.as_raw_fd();
    let rekey = upgrade_server(fd, kind, rx_secret, rx_seq, tx_secret, tx_seq)?;
    Ok(KtlsStream { inner, rekey })
}

impl<S: AsyncReadRent + AsRawFd> AsyncReadRent for KtlsStream<S> {
    fn read<T: IoBufMut>(
        &mut self,
        buf: T,
    ) -> impl std::future::Future<Output = BufResult<usize, T>> {
        async move {
            let mut buf = buf;
            loop {
                let (res, b) = self.inner.read(buf).await;
                buf = b;
                match res {
                    Ok(n) => return (Ok(n), buf),
                    Err(e) => {
                        if e.raw_os_error() == Some(libc::EIO) {
                            match handle_rx_control(&mut self.rekey) {
                                Ok(RxControl::Continue) => continue,
                                Ok(RxControl::Closed) => return (Ok(0), buf),
                                Err(e2) => return (Err(e2), buf),
                            }
                        }
                        return (Err(e), buf);
                    }
                }
            }
        }
    }

    fn readv<T: IoVecBufMut>(
        &mut self,
        buf: T,
    ) -> impl std::future::Future<Output = BufResult<usize, T>> {
        // Mirror scalar `read`: a kTLS post-handshake control record (TLS-1.3 KeyUpdate / alert)
        // surfaces as EIO on a plain readv too; consume + act on it (re-key / clean close) and
        // retry, so the serve loop only ever sees plaintext — rather than dropping the connection
        // on a legitimate RFC 8446 §4.6.3 KeyUpdate (#43). Same ownership rebind as `read`
        // (readv also consumes the buffer by value).
        async move {
            let mut buf = buf;
            loop {
                let (res, b) = self.inner.readv(buf).await;
                buf = b;
                match res {
                    Ok(n) => return (Ok(n), buf),
                    Err(e) => {
                        if e.raw_os_error() == Some(libc::EIO) {
                            match handle_rx_control(&mut self.rekey) {
                                Ok(RxControl::Continue) => continue,
                                Ok(RxControl::Closed) => return (Ok(0), buf),
                                Err(e2) => return (Err(e2), buf),
                            }
                        }
                        return (Err(e), buf);
                    }
                }
            }
        }
    }
}

impl<S: AsyncWriteRent> AsyncWriteRent for KtlsStream<S> {
    /// On a kTLS socket the app writes PLAINTEXT (the kernel encrypts), so we can use a
    /// plain `write(2)` syscall — exactly what tokio does — instead of an io_uring write op.
    /// On loopback bulk transfer the syscall is faster than io_uring's submit→reap round-trip
    /// (io_uring's edge is hiding *blocking* I/O; a loopback write never blocks). The fd is
    /// O_NONBLOCK, so a full socket buffer returns EAGAIN and we fall back to the io_uring
    /// write (which waits via the ring without blocking the core).
    fn write<T: IoBuf>(
        &mut self,
        buf: T,
    ) -> impl std::future::Future<Output = BufResult<usize, T>> {
        async move {
            let fd = self.rekey.fd;
            let len = buf.bytes_init();
            if len == 0 {
                return (Ok(0), buf);
            }
            // SAFETY: `buf` owns `len` initialized bytes at `read_ptr()` for this call.
            let n = unsafe { libc::write(fd, buf.read_ptr() as *const libc::c_void, len) };
            if n >= 0 {
                return (Ok(n as usize), buf);
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                // On Linux EAGAIN == EWOULDBLOCK (same errno), so one arm covers both.
                Some(libc::EAGAIN) => self.inner.write(buf).await,
                _ => (Err(err), buf),
            }
        }
    }
    fn writev<T: IoVecBuf>(
        &mut self,
        buf_vec: T,
    ) -> impl std::future::Future<Output = BufResult<usize, T>> {
        self.inner.writev(buf_vec)
    }
    fn flush(&mut self) -> impl std::future::Future<Output = io::Result<()>> {
        self.inner.flush()
    }
    fn shutdown(&mut self) -> impl std::future::Future<Output = io::Result<()>> {
        self.inner.shutdown()
    }
}

impl<S: AsRawFd> AsRawFd for KtlsStream<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd()
    }
}

// SAFETY: read and write touch disjoint state — writes go straight to the kernel socket;
// reads use the socket read side plus `rekey` (only mutated on the read path). `S` is itself
// `Split`, so its own read/write halves are disjoint. This matches monoio's model (and the
// monoio-rustls TLS stream, which is also `Split`); the h1/h2 serve loops drive read and
// write from a single task, so the rekey setsockopt is sequenced between socket operations.
unsafe impl<S: Split> Split for KtlsStream<S> {}
