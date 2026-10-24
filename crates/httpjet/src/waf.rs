use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use http_body::Body as _;
use http_body_util::{BodyExt, Full};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use hj_core::{BoxError, ReqCtx, Request};

const MAX_RESPONSE_HEAD: usize = 4096;
const MAX_INSPECT_BODY: u64 = 1024 * 1024;
const MAX_CONCURRENCY: usize = 4096;
const MAX_TIMEOUT: Duration = Duration::from_secs(30);
// Separate from the transport's request-body ledger: WAF inspection temporarily
// owns a hexadecimal body/header representation and the serialized JSON payload.
const SERIALIZATION_BUDGET: usize = 64 * 1024 * 1024;
const MIN_SERIALIZATION_CHARGE: usize = 16 * 1024;

fn process_serialization_budget() -> Arc<tokio::sync::Semaphore> {
    static BUDGET: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    BUDGET
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(SERIALIZATION_BUDGET)))
        .clone()
}

/// Where the sidecar listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SidecarAddr {
    /// Loopback TCP. Unauthenticated: while the sidecar is down any local user
    /// can bind the port, read request secrets and answer with verdicts.
    Tcp(SocketAddr),
    /// A unix socket whose listener must be an expected user (SO_PEERCRED).
    Unix(PathBuf),
}

impl From<SocketAddr> for SidecarAddr {
    fn from(address: SocketAddr) -> Self {
        SidecarAddr::Tcp(address)
    }
}

/// `--waf-sidecar-addr`: `unix:/absolute/path` or a loopback `ip:port`.
pub(crate) fn parse_sidecar_addr(value: &str) -> Result<SidecarAddr, String> {
    if let Some(path) = value.strip_prefix("unix:") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err("a unix WAF sidecar address must be an absolute path".into());
        }
        return Ok(SidecarAddr::Unix(path));
    }
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "expected unix:/path or a loopback socket address")?;
    if !address.ip().is_loopback() {
        return Err("a TCP WAF sidecar must be on loopback".into());
    }
    Ok(SidecarAddr::Tcp(address))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailurePolicy {
    Closed,
    Open,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allow,
    Block,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum InspectError {
    #[error("WAF sidecar configuration is invalid: {0}")]
    Configuration(&'static str),
    #[error("WAF sidecar timed out")]
    Timeout,
    #[error("WAF sidecar I/O failed")]
    Io,
    #[error("WAF sidecar serialization capacity is exhausted")]
    Capacity,
    #[error("WAF sidecar response is malformed")]
    Protocol,
    #[error("WAF sidecar socket is held by an unexpected user")]
    Identity,
}

pub(crate) struct Sidecar {
    address: SidecarAddr,
    /// The only uid a unix-socket sidecar may run as; `None` accepts root or
    /// this process's effective uid.
    peer_uid: Option<u32>,
    path: String,
    timeout: Duration,
    inspect_body_max: u64,
    policy: FailurePolicy,
    concurrency: Arc<tokio::sync::Semaphore>,
    serialization_budget: Arc<tokio::sync::Semaphore>,
}

impl Sidecar {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        address: impl Into<SidecarAddr>,
        peer_uid: Option<u32>,
        path: String,
        timeout: Duration,
        inspect_body_max: u64,
        max_concurrency: usize,
        policy: FailurePolicy,
    ) -> Result<Self, InspectError> {
        let address = address.into();
        match &address {
            SidecarAddr::Tcp(address) => {
                if !address.ip().is_loopback() || address.port() == 0 {
                    return Err(InspectError::Configuration("address must be loopback"));
                }
                tracing::warn!(
                    %address,
                    "WAF sidecar over TCP loopback is unauthenticated; prefer unix:/path"
                );
            }
            SidecarAddr::Unix(socket) => check_socket_dir(socket, peer_uid)?,
        }
        if !path.starts_with('/')
            || path.len() > 1024
            || path.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(InspectError::Configuration(
                "path must be an absolute HTTP path",
            ));
        }
        if timeout.is_zero()
            || timeout > MAX_TIMEOUT
            || max_concurrency == 0
            || max_concurrency > MAX_CONCURRENCY
            || inspect_body_max > MAX_INSPECT_BODY
        {
            return Err(InspectError::Configuration(
                "timeout, concurrency or body inspection bound is out of range",
            ));
        }
        Ok(Self {
            address,
            peer_uid,
            path,
            timeout,
            inspect_body_max,
            policy,
            concurrency: Arc::new(tokio::sync::Semaphore::new(max_concurrency)),
            // Generations overlap during transactional reload, so this is a
            // process-global budget rather than one fresh allowance per state.
            serialization_budget: process_serialization_budget(),
        })
    }

    pub(crate) fn failure_policy(&self) -> FailurePolicy {
        self.policy
    }

    pub(crate) fn inspect_body_max(&self) -> u64 {
        self.inspect_body_max
    }

    pub(crate) async fn inspect(
        &self,
        ctx: &ReqCtx,
        req: &mut Request,
        normalized_path: &str,
        include_body: bool,
    ) -> Result<Verdict, InspectError> {
        // (#582) Collect and restore the body BEFORE the timed sidecar
        // exchange. The old shape swapped the body out inside the timed
        // block, so a timeout mid-collect dropped the partially-read body
        // and fail-open dispatch forwarded an EMPTY body downstream.
        // Only the raw bytes are kept here (shared with the restored body); the
        // hex copy is made once the permit and byte lease are held.
        let body_raw = if include_body {
            let incoming = std::mem::replace(req.body_mut(), hj_core::empty_incoming());
            let bytes = incoming
                .collect()
                .await
                .map_err(|_| InspectError::Io)?
                .to_bytes();
            *req.body_mut() = Full::new(bytes.clone())
                .map_err(|never| match never {})
                .map_err(|error| Box::new(error) as BoxError)
                .boxed();
            Some(bytes)
        } else {
            None
        };
        tokio::time::timeout(self.timeout, async {
            let _permit = self
                .concurrency
                .acquire()
                .await
                .map_err(|_| InspectError::Io)?;
            // Acquire a conservative byte-weighted lease before making any
            // attacker-size-proportional copy. Holding a request-count permit is
            // not enough: at the accepted 1 MiB/4096 maxima, hex + JSON copies
            // could otherwise exhaust the process heap while the sidecar stalls.
            let charge = serialization_charge(ctx, req, normalized_path, include_body)?;
            let _serialization = self
                .serialization_budget
                .clone()
                .acquire_many_owned(charge)
                .await
                .map_err(|_| InspectError::Capacity)?;
            let body = body_raw.as_deref().map(hex);
            let headers: Vec<EncodedHeader<'_>> = req
                .headers()
                .iter()
                .map(|(name, value)| EncodedHeader {
                    name: name.as_str(),
                    value_hex: hex(value.as_bytes()),
                })
                .collect();
            let payload = serde_json::to_vec(&Inspection {
                version: 1,
                method: req.method().as_str(),
                path: normalized_path,
                query: req.uri().query().unwrap_or(""),
                vhost: &ctx.vhost_name,
                client_ip: ctx.client_ip.to_string(),
                protocol: ctx.protocol.as_str(),
                tls: ctx.is_tls,
                headers,
                body_hex: body,
                body_omitted: !include_body,
            })
            .map_err(|_| InspectError::Protocol)?;
            match &self.address {
                SidecarAddr::Tcp(address) => {
                    let stream = tokio::net::TcpStream::connect(address)
                        .await
                        .map_err(|_| InspectError::Io)?;
                    exchange(stream, &self.path, &address.to_string(), &payload).await
                }
                SidecarAddr::Unix(socket) => {
                    let stream = tokio::net::UnixStream::connect(socket)
                        .await
                        .map_err(|_| InspectError::Io)?;
                    // Before any request byte is sent: a squatter reads nothing.
                    let peer = stream.peer_cred().map_err(|_| InspectError::Io)?;
                    if !uid_allowed(peer.uid(), self.peer_uid) {
                        return Err(InspectError::Identity);
                    }
                    exchange(stream, &self.path, "localhost", &payload).await
                }
            }
        })
        .await
        .map_err(|_| InspectError::Timeout)?
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    path: &str,
    host: &str,
    payload: &[u8],
) -> Result<Verdict, InspectError> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|_| InspectError::Io)?;
    stream
        .write_all(payload)
        .await
        .map_err(|_| InspectError::Io)?;
    stream.flush().await.map_err(|_| InspectError::Io)?;
    read_verdict(&mut stream).await
}

fn uid_allowed(uid: u32, expected: Option<u32>) -> bool {
    match expected {
        Some(expected) => uid == expected,
        None => uid == 0 || uid == rustix::process::geteuid().as_raw(),
    }
}

/// The socket's directory must be a real directory owned by root or an allowed
/// user and not writable by others, so no other user can plant or swap the
/// socket. The listener itself is checked on every connection.
fn check_socket_dir(socket: &Path, peer_uid: Option<u32>) -> Result<(), InspectError> {
    use std::os::unix::fs::MetadataExt;
    let dir = socket.parent().ok_or(InspectError::Configuration(
        "unix socket path has no directory",
    ))?;
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|_| InspectError::Configuration("unix socket directory is missing"))?;
    if !meta.is_dir()
        || meta.mode() & 0o002 != 0
        || !(meta.uid() == 0 || uid_allowed(meta.uid(), peer_uid))
    {
        return Err(InspectError::Configuration(
            "unix socket directory must be owned by root or the sidecar user and not world-writable",
        ));
    }
    Ok(())
}

/// Conservative upper bound for allocations retained through sidecar I/O.
///
/// Body/header values exist once as hex strings and once in the JSON output;
/// the 6x charge also covers Vec growth. Other strings use JSON's worst-case
/// six-byte escape plus Vec growth (12x). A fixed per-request/header allowance
/// bounds collection metadata and small-request concurrency.
fn serialization_charge(
    ctx: &ReqCtx,
    req: &Request,
    normalized_path: &str,
    include_body: bool,
) -> Result<u32, InspectError> {
    let body = if include_body {
        usize::try_from(
            req.body()
                .size_hint()
                .exact()
                .ok_or(InspectError::Capacity)?,
        )
        .map_err(|_| InspectError::Capacity)?
    } else {
        0
    };
    let mut header_values = 0_usize;
    let mut header_names = 0_usize;
    let mut header_count = 0_usize;
    for (name, value) in req.headers() {
        header_values = header_values
            .checked_add(value.as_bytes().len())
            .ok_or(InspectError::Capacity)?;
        header_names = header_names
            .checked_add(name.as_str().len())
            .ok_or(InspectError::Capacity)?;
        header_count = header_count.checked_add(1).ok_or(InspectError::Capacity)?;
    }
    let text = req
        .method()
        .as_str()
        .len()
        .checked_add(normalized_path.len())
        .and_then(|n| n.checked_add(req.uri().query().unwrap_or("").len()))
        .and_then(|n| n.checked_add(ctx.vhost_name.len()))
        .and_then(|n| n.checked_add(ctx.protocol.as_str().len()))
        .and_then(|n| n.checked_add(45)) // longest textual IP address
        .ok_or(InspectError::Capacity)?;
    let charge = body
        .checked_mul(6)
        .and_then(|n| n.checked_add(header_values.checked_mul(6)?))
        .and_then(|n| n.checked_add(header_names.checked_mul(2)?))
        .and_then(|n| n.checked_add(text.checked_mul(12)?))
        .and_then(|n| n.checked_add(header_count.checked_mul(128)?))
        .and_then(|n| n.checked_add(MIN_SERIALIZATION_CHARGE))
        .ok_or(InspectError::Capacity)?
        .max(MIN_SERIALIZATION_CHARGE);
    if charge > SERIALIZATION_BUDGET {
        return Err(InspectError::Capacity);
    }
    u32::try_from(charge).map_err(|_| InspectError::Capacity)
}

#[derive(Serialize)]
struct Inspection<'a> {
    version: u8,
    method: &'a str,
    path: &'a str,
    query: &'a str,
    vhost: &'a str,
    client_ip: String,
    protocol: &'a str,
    tls: bool,
    headers: Vec<EncodedHeader<'a>>,
    body_hex: Option<String>,
    body_omitted: bool,
}

#[derive(Serialize)]
struct EncodedHeader<'a> {
    name: &'a str,
    value_hex: String,
}

#[cfg(test)]
thread_local! {
    static HEX_INPUT_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn hex(bytes: &[u8]) -> String {
    #[cfg(test)]
    HEX_INPUT_BYTES.with(|count| count.set(count.get() + bytes.len()));
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

async fn read_verdict<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Verdict, InspectError> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == MAX_RESPONSE_HEAD {
            return Err(InspectError::Protocol);
        }
        if stream
            .read_exact(&mut byte)
            .await
            .map_err(|_| InspectError::Io)?
            == 0
        {
            return Err(InspectError::Protocol);
        }
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head).map_err(|_| InspectError::Protocol)?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| {
            line.strip_prefix("HTTP/1.1 ")
                .or_else(|| line.strip_prefix("HTTP/1.0 "))
        })
        .and_then(|line| line.split(' ').next())
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(InspectError::Protocol)?;
    // A parsed block is a block whatever body or framing follows (the connection is
    // close-delimited): it must never become a sidecar failure that fail-open allows
    // (#934). An allow keeps the strict bodiless framing below.
    if status == 403 {
        return Ok(Verdict::Block);
    }
    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(InspectError::Protocol)?;
        http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| InspectError::Protocol)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(InspectError::Protocol);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<u64>()
                .map_err(|_| InspectError::Protocol)?;
            if content_length.replace(parsed).is_some() {
                return Err(InspectError::Protocol);
            }
        }
    }
    if content_length.unwrap_or(0) != 0 {
        return Err(InspectError::Protocol);
    }
    match status {
        204 => Ok(Verdict::Allow),
        403 => Ok(Verdict::Block),
        _ => Err(InspectError::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_loopback_absolute_and_bounded() {
        assert!(
            Sidecar::new(
                "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
                None,
                "/inspect".into(),
                Duration::from_millis(50),
                1024,
                2,
                FailurePolicy::Closed,
            )
            .is_ok()
        );
        assert!(
            Sidecar::new(
                "192.0.2.1:9000".parse::<SocketAddr>().unwrap(),
                None,
                "/inspect".into(),
                Duration::from_millis(50),
                1024,
                2,
                FailurePolicy::Closed,
            )
            .is_err()
        );
        assert!(
            Sidecar::new(
                "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
                None,
                "bad\r\npath".into(),
                Duration::from_millis(50),
                1024,
                2,
                FailurePolicy::Closed,
            )
            .is_err()
        );
    }

    #[test]
    fn sidecar_addresses_are_unix_paths_or_loopback() {
        assert_eq!(
            parse_sidecar_addr("unix:/run/waf/waf.sock"),
            Ok(SidecarAddr::Unix("/run/waf/waf.sock".into()))
        );
        assert_eq!(
            parse_sidecar_addr("127.0.0.1:9000"),
            Ok(SidecarAddr::Tcp("127.0.0.1:9000".parse().unwrap()))
        );
        for bad in ["unix:waf.sock", "unix:", "192.0.2.1:9000", "localhost:9000"] {
            assert!(parse_sidecar_addr(bad).is_err(), "{bad}");
        }
    }

    fn socket_dir(tag: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("hj-waf-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    fn unix_sidecar(socket: &Path, peer_uid: Option<u32>) -> Result<Sidecar, InspectError> {
        Sidecar::new(
            SidecarAddr::Unix(socket.to_path_buf()),
            peer_uid,
            "/inspect".into(),
            Duration::from_secs(2),
            1024,
            2,
            FailurePolicy::Open,
        )
    }

    /// Regression (#1132): a unix-socket sidecar answers only after its
    /// listener's uid checks out, and an unexpected listener is sent nothing.
    #[tokio::test]
    async fn unix_sidecar_verifies_the_listener_before_sending() {
        let dir = socket_dir("peer", 0o700);
        let socket = dir.join("waf.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let stub = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..2 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0_u8; 4096];
                let mut got = 0;
                while let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(200), sock.read(&mut buf)).await
                {
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
                let _ = sock
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
                received.push(got);
            }
            received
        });
        let ctx = context();
        let allowed = unix_sidecar(&socket, None).unwrap();
        let result = allowed
            .inspect(&ctx, &mut request(5), "/inspect", true)
            .await;
        assert!(matches!(result, Ok(Verdict::Allow)), "{result:?}");
        let me = rustix::process::geteuid().as_raw();
        let stranger = unix_sidecar(&socket, Some(me.wrapping_add(4242))).unwrap();
        let result = stranger
            .inspect(&ctx, &mut request(5), "/inspect", true)
            .await;
        assert!(matches!(result, Err(InspectError::Identity)), "{result:?}");
        let received = stub.await.unwrap();
        assert!(received[0] > 0, "the verified sidecar got the request");
        assert_eq!(
            received[1], 0,
            "an unexpected listener must receive nothing"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression (#1132): the socket's directory may not let other users plant
    /// or swap the socket.
    #[test]
    fn unix_sidecar_directory_must_be_private() {
        let open = socket_dir("open", 0o777);
        assert!(unix_sidecar(&open.join("waf.sock"), None).is_err());
        let private = socket_dir("private", 0o755);
        assert!(unix_sidecar(&private.join("waf.sock"), None).is_ok());
        assert!(unix_sidecar(Path::new("/nonexistent-hj-waf/waf.sock"), None).is_err());
        if rustix::process::geteuid().is_root() {
            let foreign = socket_dir("foreign", 0o755);
            let owner = rustix::process::Uid::from_raw(4242);
            rustix::fs::chown(&foreign, Some(owner), None).unwrap();
            assert!(unix_sidecar(&foreign.join("waf.sock"), Some(4242)).is_ok());
            assert!(unix_sidecar(&foreign.join("waf.sock"), Some(4343)).is_err());
            std::fs::remove_dir_all(&foreign).ok();
        }
        std::fs::remove_dir_all(&open).ok();
        std::fs::remove_dir_all(&private).ok();
    }

    #[test]
    fn binary_values_encode_without_loss_or_controls() {
        assert_eq!(hex(&[0, b'\r', 0xff]), "000dff");
    }

    fn context() -> ReqCtx {
        ReqCtx {
            server: Arc::new(Default::default()),
            vhost_name: "example.test".into(),
            vhost: Arc::new(Default::default()),
            peer_ip: "127.0.0.1".parse().unwrap(),
            client_ip: "203.0.113.10".parse().unwrap(),
            is_tls: true,
            peer_unix: false,
            protocol: hj_core::Proto::Http2,
            trusted_proxy: false,
            forwarding_trusted: false,
            env: vec![],
            local_addr: "127.0.0.1:443".parse().unwrap(),
            peer_port: 12345,
            tls: None,
            request_time: std::time::SystemTime::now(),
            request_id: hj_core::reqid::next(),
            redirect_guard: None,
        }
    }

    fn request(body_len: usize) -> Request {
        http::Request::builder()
            .method("POST")
            .uri("/inspect?q=1")
            .header("x-test", "value")
            .body(
                Full::new(bytes::Bytes::from(vec![0; body_len]))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }

    /// Regression (#934): a block with a body, chunked framing or an HTTP/1.0
    /// status line is still a block, never a sidecar failure.
    #[tokio::test]
    async fn framed_or_http10_block_is_still_a_block() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for reply in [
            &b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden"[..],
            b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nForbidden\r\n0\r\n\r\n",
            b"HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let stub = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0_u8; 4096];
                while let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(100), sock.read(&mut buf)).await
                {
                    if n == 0 {
                        break;
                    }
                }
                sock.write_all(reply).await.unwrap();
            });
            let sidecar = Sidecar::new(
                addr,
                None,
                "/inspect".into(),
                Duration::from_secs(2),
                1024,
                2,
                FailurePolicy::Open,
            )
            .unwrap();
            let ctx = context();
            let mut req = request(5);
            let result = sidecar.inspect(&ctx, &mut req, "/inspect", true).await;
            assert!(matches!(result, Ok(Verdict::Block)), "{result:?}");
            stub.await.unwrap();
        }
    }

    /// Regression (#582): a sidecar timeout must leave the original request
    /// body in `req` — fail-open dispatch forwards whatever body remains.
    #[tokio::test]
    async fn timeout_leaves_original_body_intact() {
        // Sidecar that accepts but never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stall = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let sidecar = Sidecar::new(
            addr,
            None,
            "/inspect".into(),
            Duration::from_millis(100),
            1024,
            2,
            FailurePolicy::Open,
        )
        .unwrap();
        let ctx = context();
        let mut req = request(5);
        let result = sidecar.inspect(&ctx, &mut req, "/inspect", true).await;
        assert!(matches!(result, Err(InspectError::Timeout)), "{result:?}");
        let bytes = req.body_mut().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 5, "original body must survive the timeout");
        stall.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn body_is_not_hex_encoded_while_waiting_for_a_permit() {
        let sidecar = Sidecar::new(
            "127.0.0.1:19092".parse::<SocketAddr>().unwrap(),
            None,
            "/inspect".into(),
            Duration::from_millis(50),
            MAX_INSPECT_BODY,
            1,
            FailurePolicy::Closed,
        )
        .unwrap();
        let held = sidecar.concurrency.clone().acquire_owned().await.unwrap();
        let ctx = context();
        let mut req = request(64 * 1024);
        HEX_INPUT_BYTES.with(|count| count.set(0));
        let result = sidecar.inspect(&ctx, &mut req, "/inspect", true).await;
        assert!(matches!(result, Err(InspectError::Timeout)), "{result:?}");
        assert_eq!(HEX_INPUT_BYTES.with(std::cell::Cell::get), 0);
        drop(held);
        let bytes = req.body_mut().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 64 * 1024);
    }

    #[test]
    fn serialization_charge_is_byte_weighted_and_conservative() {
        let ctx = context();
        let empty = serialization_charge(&ctx, &request(0), "/inspect", true).unwrap();
        let one_mib =
            serialization_charge(&ctx, &request(MAX_INSPECT_BODY as usize), "/inspect", true)
                .unwrap();
        assert!(empty as usize >= MIN_SERIALIZATION_CHARGE);
        assert!(one_mib as usize >= 6 * MAX_INSPECT_BODY as usize);
        assert!((one_mib as usize) < SERIALIZATION_BUDGET);
    }

    #[tokio::test]
    async fn aggregate_serialization_budget_blocks_then_releases() {
        let budget = Arc::new(tokio::sync::Semaphore::new(SERIALIZATION_BUDGET));
        let charge = serialization_charge(
            &context(),
            &request(MAX_INSPECT_BODY as usize),
            "/inspect",
            true,
        )
        .unwrap();
        let held = budget
            .clone()
            .acquire_many_owned(SERIALIZATION_BUDGET as u32)
            .await
            .unwrap();
        assert!(budget.clone().try_acquire_many_owned(charge).is_err());
        drop(held);
        let lease = budget.clone().try_acquire_many_owned(charge).unwrap();
        assert_eq!(
            budget.available_permits(),
            SERIALIZATION_BUDGET - charge as usize
        );
        drop(lease);
        assert_eq!(budget.available_permits(), SERIALIZATION_BUDGET);
    }

    #[test]
    fn reload_generations_share_the_process_serialization_budget() {
        let first = Sidecar::new(
            "127.0.0.1:19090".parse::<SocketAddr>().unwrap(),
            None,
            "/inspect".into(),
            Duration::from_millis(100),
            64 * 1024,
            128,
            FailurePolicy::Closed,
        )
        .unwrap();
        let second = Sidecar::new(
            "127.0.0.1:19091".parse::<SocketAddr>().unwrap(),
            None,
            "/inspect".into(),
            Duration::from_millis(100),
            64 * 1024,
            128,
            FailurePolicy::Closed,
        )
        .unwrap();
        assert!(Arc::ptr_eq(
            &first.serialization_budget,
            &second.serialization_budget
        ));
    }
}
