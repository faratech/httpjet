use std::{net::SocketAddr, sync::Arc, time::Duration};

use http_body::Body as _;
use http_body_util::{BodyExt, Full};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
}

pub(crate) struct Sidecar {
    address: SocketAddr,
    path: String,
    timeout: Duration,
    inspect_body_max: u64,
    policy: FailurePolicy,
    concurrency: Arc<tokio::sync::Semaphore>,
    serialization_budget: Arc<tokio::sync::Semaphore>,
}

impl Sidecar {
    pub(crate) fn new(
        address: SocketAddr,
        path: String,
        timeout: Duration,
        inspect_body_max: u64,
        max_concurrency: usize,
        policy: FailurePolicy,
    ) -> Result<Self, InspectError> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(InspectError::Configuration("address must be loopback"));
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
            let body = if include_body {
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
                Some(hex(&bytes))
            } else {
                None
            };
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
            let mut stream = tokio::net::TcpStream::connect(self.address)
                .await
                .map_err(|_| InspectError::Io)?;
            let head = format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                self.path,
                self.address,
                payload.len()
            );
            stream
                .write_all(head.as_bytes())
                .await
                .map_err(|_| InspectError::Io)?;
            stream
                .write_all(&payload)
                .await
                .map_err(|_| InspectError::Io)?;
            stream.flush().await.map_err(|_| InspectError::Io)?;
            read_verdict(&mut stream).await
        })
        .await
        .map_err(|_| InspectError::Timeout)?
    }
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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

async fn read_verdict(stream: &mut tokio::net::TcpStream) -> Result<Verdict, InspectError> {
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
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|line| line.split(' ').next())
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(InspectError::Protocol)?;
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
                "127.0.0.1:9000".parse().unwrap(),
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
                "192.0.2.1:9000".parse().unwrap(),
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
                "127.0.0.1:9000".parse().unwrap(),
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
            "127.0.0.1:19090".parse().unwrap(),
            "/inspect".into(),
            Duration::from_millis(100),
            64 * 1024,
            128,
            FailurePolicy::Closed,
        )
        .unwrap();
        let second = Sidecar::new(
            "127.0.0.1:19091".parse().unwrap(),
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
