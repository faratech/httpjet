use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, channel::Channel, combinators::BoxBody};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::oneshot,
    task::JoinHandle,
};

use hj_core::{
    Body, BoxError, Handler, HandlerError, ReqCtx, Request, Response,
    budget::{BodyBufferBudget, BodyBufferLease, DEFAULT_BODY_BUFFER_MEM},
};
use hj_lsapi::CgiEnvBuilder;

use crate::{
    FastCgiPool, PoolError, Record, RecordType, begin_request, encode_name_value_pairs,
    encode_stream, end_stream, parse_cgi_head, parse_end_request, parse_record,
};

const REQUEST_ID: u16 = 1;

/// A body up to this size is written inline before the response is read: it fits
/// the default socket send buffer, so the write completes without the application
/// reading it. A larger one is pumped concurrently with the response (#813).
const STDIN_INLINE_WRITE_MAX: usize = 64 * 1024;

type PooledConnection = crate::pool::PooledConnection;

/// Pipeline-pinned FastCGI target. Construction rejects relative paths, and the
/// fields are private so URI-to-filesystem fallback cannot be introduced by a
/// direct handler caller.
#[derive(Clone, Debug)]
pub struct FastCgiScript {
    script: PathBuf,
    script_name: Option<String>,
    path_info: Option<String>,
}

impl FastCgiScript {
    pub fn new(script: impl Into<PathBuf>) -> Result<Self, &'static str> {
        let script = script.into();
        if !script.is_absolute() {
            return Err("FastCGI script target must be absolute");
        }
        Ok(Self {
            script,
            script_name: None,
            path_info: None,
        })
    }

    pub fn script_name(mut self, value: impl Into<String>) -> Self {
        self.script_name = Some(value.into());
        self
    }

    pub fn path_info(mut self, value: impl Into<String>) -> Self {
        self.path_info = Some(value.into());
        self
    }
}

/// Bounded FastCGI responder handler. Routing must attach [`FastCgiScript`]
/// after resolving and validating the script beneath the configured context.
pub struct FastCgi {
    pool: Arc<FastCgiPool>,
    max_body: u64,
    max_params: usize,
    max_response_header: usize,
    max_response_headers: usize,
    read_timeout: Duration,
    stderr_limit: usize,
    body_budget: Arc<BodyBufferBudget>,
    base_env: Vec<(String, String)>,
}

impl FastCgi {
    pub fn new(pool: Arc<FastCgiPool>) -> Self {
        Self {
            pool,
            max_body: 16 * 1024 * 1024,
            max_params: 128 * 1024,
            max_response_header: 64 * 1024,
            max_response_headers: 256,
            read_timeout: Duration::from_secs(60),
            stderr_limit: 16 * 1024,
            body_budget: Arc::new(BodyBufferBudget::new(DEFAULT_BODY_BUFFER_MEM)),
            base_env: Vec::new(),
        }
    }

    pub fn max_body(mut self, bytes: u64) -> Self {
        self.max_body = bytes;
        self
    }

    pub fn body_buffer_budget(mut self, budget: Arc<BodyBufferBudget>) -> Self {
        self.body_budget = budget;
        self
    }

    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Add operator-controlled application environment without allowing it to
    /// replace CGI identity, request headers, TLS assertions, or redirect state.
    pub fn base_env(
        mut self,
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, String> {
        for (name, value) in values {
            if !safe_extra_env_name(&name) || value.as_bytes().contains(&0) {
                return Err(format!("unsafe FastCGI environment variable {name:?}"));
            }
            self.base_env.push((name, value));
        }
        Ok(self)
    }
}

#[async_trait]
impl Handler for FastCgi {
    async fn handle(&self, ctx: &mut ReqCtx, mut req: Request) -> Result<Response, HandlerError> {
        let target = req
            .extensions()
            .get::<FastCgiScript>()
            .cloned()
            .ok_or_else(|| HandlerError::Other("FastCGI script target was not resolved".into()))?;
        let declared = content_length(&req)?;
        if declared.is_some_and(|len| len > self.max_body) {
            return Err(HandlerError::PayloadTooLarge);
        }
        let (body, lease) = collect_body(req.body_mut(), self.max_body, &self.body_budget).await?;
        if declared.is_some_and(|len| len != body.len() as u64) {
            return Err(HandlerError::BadGateway(
                "request body length did not match Content-Length".into(),
            ));
        }
        // A bodyless GET/HEAD/... carries no Content-Length on the wire; inventing
        // `Content-Length: 0` would surface in getallheaders()/$_SERVER (as LSAPI, #765).
        let method_has_body = matches!(
            *req.method(),
            http::Method::POST | http::Method::PUT | http::Method::PATCH
        );
        if declared.is_some() || !body.is_empty() || method_has_body {
            req.headers_mut().insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(&body.len().to_string())
                    .map_err(|_| HandlerError::PayloadTooLarge)?,
            );
        }

        let mut builder = CgiEnvBuilder::new(&target.script)
            .server_software("httpjet")
            .extra_ref(&self.base_env);
        if let Some(value) = target.script_name {
            builder = builder.script_name(value);
        }
        if let Some(value) = target.path_info {
            builder = builder.path_info(value);
        }
        let env = builder.build(&req, ctx);
        let params = encode_name_value_pairs(
            REQUEST_ID,
            env.iter()
                .map(|(name, value)| (name.as_bytes(), value.as_bytes())),
            self.max_params,
        )
        .map_err(|_| HandlerError::RequestHeaderFieldsTooLarge)?;
        drop(env);

        // #832: FCGI_KEEP_CONN only for a request with no STDIN bytes. An
        // application that reads its input partially leaves the rest on the
        // socket, and php-fpm/php-cgi parse it as the next request on a kept
        // connection (a forged BEGIN_REQUEST with attacker-chosen params). Without
        // KEEP_CONN the application closes after END_REQUEST, discarding any tail.
        let keep_conn = body.is_empty();
        let mut conn = self.pool.acquire().await.map_err(map_pool_error)?;
        let mut conn = if body.len() > STDIN_INLINE_WRITE_MAX {
            write_head(&mut conn, params, self.read_timeout).await?;
            Conn::split(conn, body, lease, self.read_timeout)
        } else {
            write_request(&mut conn, params, &body, keep_conn, self.read_timeout).await?;
            drop(lease);
            Conn::Whole { conn, keep_conn }
        };

        let mut wire = BytesMut::with_capacity(16 * 1024);
        let mut header = BytesMut::new();
        let mut stderr_seen = 0_usize;
        let parsed = loop {
            let record = next_record(conn.reader(), &mut wire, self.read_timeout).await?;
            require_response_record(&record)?;
            match record.kind {
                RecordType::Stdout if record.content.is_empty() => {
                    return Err(HandlerError::BadGateway(
                        "FastCGI response ended before CGI headers".into(),
                    ));
                }
                RecordType::Stdout => {
                    if header.len() >= self.max_response_header {
                        return Err(HandlerError::BadGateway(
                            "FastCGI response headers exceeded configured bound".into(),
                        ));
                    }
                    header.extend_from_slice(&record.content);
                    match parse_cgi_head(
                        header.clone().freeze(),
                        self.max_response_header,
                        self.max_response_headers,
                    ) {
                        Ok(parsed) => break parsed,
                        Err(crate::ResponseError::Incomplete)
                            if header.len() <= self.max_response_header => {}
                        Err(error) => return Err(bad_response(error)),
                    }
                }
                RecordType::Stderr => {
                    log_stderr(&record.content, &mut stderr_seen, self.stderr_limit)
                }
                _ => {
                    return Err(HandlerError::BadGateway(
                        "unexpected FastCGI record before response headers".into(),
                    ));
                }
            }
        };

        let status = parsed.status;
        let headers = parsed.headers;
        let prefix = parsed.body_prefix;
        let is_head = req.method() == http::Method::HEAD;
        let expected = if is_head {
            None
        } else {
            response_content_length(&headers)?
        };

        let body = if is_head {
            tokio::spawn(pump_response(
                conn,
                wire,
                prefix,
                None,
                expected,
                self.read_timeout,
                stderr_seen,
                self.stderr_limit,
                true,
            ));
            Body::Empty
        } else {
            let (tx, channel) = Channel::<Bytes, BoxError>::new(8);
            tokio::spawn(pump_response(
                conn,
                wire,
                prefix,
                Some(tx),
                expected,
                self.read_timeout,
                stderr_seen,
                self.stderr_limit,
                false,
            ));
            Body::Stream(BoxBody::new(channel))
        };
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        Ok(response)
    }
}

fn map_pool_error(error: PoolError) -> HandlerError {
    match error {
        PoolError::Timeout => HandlerError::GatewayTimeout,
        PoolError::Connect => HandlerError::ServiceUnavailable,
    }
}

fn safe_extra_env_name(name: &str) -> bool {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && name
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_uppercase() || *byte == b'_');
    if !valid
        || name.starts_with("HTTP_")
        || name.starts_with("SSL_")
        || name.starts_with("REDIRECT_")
    {
        return false;
    }
    !matches!(
        name,
        "AUTH_TYPE"
            | "CONTENT_LENGTH"
            | "CONTENT_TYPE"
            | "DOCUMENT_ROOT"
            | "GATEWAY_INTERFACE"
            | "HTTPS"
            | "PATH_INFO"
            | "PATH_TRANSLATED"
            | "QUERY_STRING"
            | "REMOTE_ADDR"
            | "REMOTE_PORT"
            | "REMOTE_USER"
            | "REQUEST_METHOD"
            | "REQUEST_TIME"
            | "REQUEST_TIME_FLOAT"
            | "REQUEST_URI"
            | "SCRIPT_FILENAME"
            | "SCRIPT_NAME"
            | "SERVER_ADDR"
            | "SERVER_NAME"
            | "SERVER_PORT"
            | "SERVER_PROTOCOL"
            | "SERVER_SOFTWARE"
    )
}

async fn write_head(
    conn: &mut PooledConnection,
    params: Vec<Bytes>,
    timeout: Duration,
) -> Result<(), HandlerError> {
    let operation = async {
        conn.write_all(&begin_request(REQUEST_ID, false).expect("constant request id"))
            .await?;
        for record in params {
            conn.write_all(&record).await?;
        }
        conn.flush().await
    };
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| HandlerError::GatewayTimeout)?
        .map_err(HandlerError::Io)
}

async fn write_request(
    conn: &mut PooledConnection,
    params: Vec<Bytes>,
    body: &[u8],
    keep_conn: bool,
    timeout: Duration,
) -> Result<(), HandlerError> {
    let operation = async {
        conn.write_all(&begin_request(REQUEST_ID, keep_conn).expect("constant request id"))
            .await?;
        for record in params {
            conn.write_all(&record).await?;
        }
        for record in encode_stream(RecordType::Stdin, REQUEST_ID, body)
            .expect("bounded request id and chunks")
        {
            conn.write_all(&record).await?;
        }
        conn.write_all(&end_stream(RecordType::Stdin, REQUEST_ID).expect("constant request id"))
            .await?;
        conn.flush().await
    };
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| HandlerError::GatewayTimeout)?
        .map_err(HandlerError::Io)
}

/// The response side of one request. A large body is pumped by a separate task
/// that owns the write half (#813). Only a bodyless request asks the application
/// to keep the connection (#832), so only that one returns to the pool, after a
/// clean END_REQUEST.
enum Conn {
    Whole {
        conn: PooledConnection,
        keep_conn: bool,
    },
    Split {
        read: ReadHalf<PooledConnection>,
        stdin: StdinPump,
    },
}

struct StdinPump {
    /// Dropping (or sending on) this cancels an unfinished pump, which then shuts
    /// the write half down.
    cancel: Option<oneshot::Sender<()>>,
    task: JoinHandle<Option<WriteHalf<PooledConnection>>>,
}

impl Conn {
    fn split(
        conn: PooledConnection,
        body: Bytes,
        lease: BodyBufferLease,
        timeout: Duration,
    ) -> Self {
        let (read, write) = tokio::io::split(conn);
        let (cancel, cancelled) = oneshot::channel();
        let task = tokio::spawn(pump_stdin(write, body, lease, timeout, cancelled));
        Conn::Split {
            read,
            stdin: StdinPump {
                cancel: Some(cancel),
                task,
            },
        }
    }

    fn reader(&mut self) -> &mut (dyn AsyncRead + Unpin + Send) {
        match self {
            Conn::Whole { conn, .. } => conn,
            Conn::Split { read, .. } => read,
        }
    }

    /// Called after a clean END_REQUEST: return a kept connection to the pool.
    async fn finish_clean(self) {
        match self {
            Conn::Whole {
                mut conn,
                keep_conn: true,
            } => conn.mark_reusable(),
            Conn::Whole { .. } => {}
            Conn::Split { mut stdin, .. } => {
                if let Some(cancel) = stdin.cancel.take() {
                    let _ = cancel.send(());
                }
                let _ = (&mut stdin.task).await;
            }
        }
    }
}

async fn pump_stdin(
    mut write: WriteHalf<PooledConnection>,
    body: Bytes,
    lease: BodyBufferLease,
    timeout: Duration,
    mut cancelled: oneshot::Receiver<()>,
) -> Option<WriteHalf<PooledConnection>> {
    let operation = async {
        for chunk in body.chunks(u16::MAX as usize) {
            for record in encode_stream(RecordType::Stdin, REQUEST_ID, chunk)
                .expect("bounded request id and chunk")
            {
                tokio::time::timeout(timeout, write.write_all(&record))
                    .await
                    .map_err(|_| std::io::ErrorKind::TimedOut)??;
            }
        }
        let end = end_stream(RecordType::Stdin, REQUEST_ID).expect("constant request id");
        tokio::time::timeout(timeout, async {
            write.write_all(&end).await?;
            write.flush().await
        })
        .await
        .map_err(|_| std::io::ErrorKind::TimedOut)??;
        Ok::<(), std::io::Error>(())
    };
    // Biased toward the writes: once the application has drained STDIN the rest
    // completes in one poll, so a cancel racing a finished pump still reuses.
    let result = tokio::select! {
        biased;
        result = operation => result.map_err(Some),
        _ = &mut cancelled => Err(None),
    };
    drop(body);
    drop(lease);
    match result {
        Ok(()) => Some(write),
        Err(error) => {
            if let Some(error) = error {
                tracing::debug!(target: "hj_fastcgi", %error, "FastCGI STDIN pump failed");
            }
            let _ = tokio::time::timeout(Duration::from_secs(1), write.shutdown()).await;
            None
        }
    }
}

async fn next_record(
    conn: &mut (dyn AsyncRead + Unpin + Send),
    wire: &mut BytesMut,
    timeout: Duration,
) -> Result<Record, HandlerError> {
    loop {
        if let Some(record) = parse_record(wire).map_err(|error| {
            HandlerError::BadGateway(format!("malformed FastCGI record: {error}"))
        })? {
            return Ok(record);
        }
        let read = tokio::time::timeout(timeout, conn.read_buf(wire))
            .await
            .map_err(|_| HandlerError::GatewayTimeout)?
            .map_err(HandlerError::Io)?;
        if read == 0 {
            return Err(HandlerError::BadGateway(
                "FastCGI connection closed before END_REQUEST".into(),
            ));
        }
    }
}

fn require_response_record(record: &Record) -> Result<(), HandlerError> {
    if record.request_id != REQUEST_ID {
        return Err(HandlerError::BadGateway(
            "FastCGI response request id mismatch".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn pump_response(
    mut conn: Conn,
    mut wire: BytesMut,
    prefix: Bytes,
    mut tx: Option<http_body_util::channel::Sender<Bytes, BoxError>>,
    expected: Option<u64>,
    timeout: Duration,
    mut stderr_seen: usize,
    stderr_limit: usize,
    discard: bool,
) {
    let mut sent = 0_u64;
    // END_REQUEST implicitly ends STDOUT: php-fpm/php-cgi omit the empty STDOUT
    // record (#831), as nginx tolerates.
    let mut stdout_ended = false;
    let mut stderr_ended = false;
    let mut clean = feed(&mut tx, prefix, &mut sent, expected, discard).await;
    while clean {
        let record = match next_record(conn.reader(), &mut wire, timeout).await {
            Ok(record) => record,
            // Without END_REQUEST the body is truncated: abort it rather than end it
            // cleanly (#929).
            Err(error) => {
                tracing::warn!(target: "hj_fastcgi", %error, "FastCGI response stream failed");
                clean = false;
                break;
            }
        };
        if require_response_record(&record).is_err() {
            clean = false;
            break;
        }
        match record.kind {
            RecordType::Stdout if record.content.is_empty() && !stdout_ended => stdout_ended = true,
            RecordType::Stdout if !stdout_ended => {
                clean = feed(&mut tx, record.content, &mut sent, expected, discard).await;
            }
            RecordType::Stderr if record.content.is_empty() && !stderr_ended => {
                stderr_ended = true;
            }
            RecordType::Stderr if !stderr_ended => {
                log_stderr(&record.content, &mut stderr_seen, stderr_limit)
            }
            RecordType::EndRequest => {
                match parse_end_request(&record.content) {
                    Ok(app_status) if expected.is_none_or(|length| length == sent) => {
                        if app_status != 0 {
                            tracing::warn!(target: "hj_fastcgi", app_status, "FastCGI application returned nonzero status");
                        }
                        conn.finish_clean().await;
                        clean = true;
                    }
                    _ => clean = false,
                }
                break;
            }
            _ => {
                clean = false;
                break;
            }
        }
    }
    if !clean {
        tracing::warn!(target: "hj_fastcgi", "FastCGI response was incomplete; connection discarded");
        if let Some(sender) = tx.take() {
            sender.abort(Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete FastCGI response",
            )));
        }
    }
    drop(tx);
}

async fn feed(
    tx: &mut Option<http_body_util::channel::Sender<Bytes, BoxError>>,
    chunk: Bytes,
    sent: &mut u64,
    expected: Option<u64>,
    discard: bool,
) -> bool {
    if expected.is_some_and(|length| chunk.len() as u64 > length.saturating_sub(*sent)) {
        return false;
    }
    *sent += chunk.len() as u64;
    if !discard && !chunk.is_empty() {
        let Some(sender) = tx.as_mut() else {
            return false;
        };
        if sender.send_data(chunk).await.is_err() {
            return false;
        }
    }
    true
}

fn content_length(req: &Request) -> Result<Option<u64>, HandlerError> {
    let mut length = None;
    for value in req.headers().get_all(http::header::CONTENT_LENGTH) {
        let value = value
            .to_str()
            .ok()
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| HandlerError::BadGateway("invalid Content-Length".into()))?;
        if length.is_some_and(|previous| previous != value) {
            return Err(HandlerError::BadGateway(
                "conflicting Content-Length".into(),
            ));
        }
        length = Some(value);
    }
    Ok(length)
}

fn response_content_length(headers: &http::HeaderMap) -> Result<Option<u64>, HandlerError> {
    let mut length = None;
    for raw in headers.get_all(http::header::CONTENT_LENGTH) {
        for value in raw
            .to_str()
            .map_err(|_| HandlerError::BadGateway("invalid FastCGI Content-Length".into()))?
            .split(',')
        {
            let value = value
                .trim()
                .parse::<u64>()
                .map_err(|_| HandlerError::BadGateway("invalid FastCGI Content-Length".into()))?;
            if length.is_some_and(|previous| previous != value) {
                return Err(HandlerError::BadGateway(
                    "conflicting FastCGI Content-Length".into(),
                ));
            }
            length = Some(value);
        }
    }
    Ok(length)
}

async fn collect_body(
    body: &mut hj_core::IncomingBody,
    max: u64,
    budget: &Arc<BodyBufferBudget>,
) -> Result<(Bytes, BodyBufferLease), HandlerError> {
    let mut bytes = BytesMut::new();
    let mut lease = BodyBufferLease::new(Arc::clone(budget));
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|error| HandlerError::BadGateway(format!("request body: {error}")))?;
        if let Some(data) = frame.data_ref() {
            if data.len() as u64 > max.saturating_sub(bytes.len() as u64) {
                return Err(HandlerError::PayloadTooLarge);
            }
            if !lease.reserve(data.len() as u64) {
                return Err(HandlerError::ServiceUnavailable);
            }
            bytes.extend_from_slice(data);
        }
    }
    Ok((bytes.freeze(), lease))
}

fn bad_response(error: crate::ResponseError) -> HandlerError {
    HandlerError::BadGateway(format!("invalid FastCGI CGI response: {error}"))
}

fn log_stderr(bytes: &[u8], seen: &mut usize, limit: usize) {
    if *seen >= limit || bytes.is_empty() {
        return;
    }
    let keep = bytes.len().min(limit - *seen);
    *seen += keep;
    let escaped: String = String::from_utf8_lossy(&bytes[..keep])
        .chars()
        .flat_map(char::escape_default)
        .collect();
    tracing::warn!(target: "hj_fastcgi", stderr = %escaped, "FastCGI application stderr");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, net::IpAddr};

    use hj_core::{
        Proto,
        config::{ServerConfig, VHostConfig},
        empty_incoming,
    };
    use http_body_util::BodyExt;

    fn context() -> ReqCtx {
        let server = ServerConfig {
            server_root: Default::default(),
            server_name: String::new(),
            user: String::new(),
            group: String::new(),
            index_files: vec![],
            tuning: Default::default(),
            quic_enable: false,
            use_ip_in_proxy_header: 0,
            expires: Default::default(),
            cache: Default::default(),
            security: Default::default(),
            suexec: Default::default(),
            ext_processors: vec![],
            php_config: None,
            listeners: vec![],
            vhosts: BTreeMap::new(),
            vhost_order: vec![],
            mime: Default::default(),
        };
        ReqCtx {
            server: Arc::new(server),
            vhost_name: "example.test".into(),
            vhost: Arc::new(VHostConfig {
                doc_root: "/srv/www".into(),
                ..Default::default()
            }),
            peer_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_ip: "203.0.113.10".parse::<IpAddr>().unwrap(),
            is_tls: false,
            protocol: Proto::Http1,
            trusted_proxy: false,
            forwarding_trusted: false,
            env: vec![],
            local_addr: "127.0.0.1:8080".parse().unwrap(),
            peer_port: 50123,
            request_time: std::time::UNIX_EPOCH,
            request_id: Default::default(),
            tls: None,
            peer_unix: false,
            redirect_guard: None,
        }
    }

    async fn server_record(stream: &mut tokio::net::TcpStream, wire: &mut BytesMut) -> Record {
        loop {
            if let Some(record) = parse_record(wire).unwrap() {
                return record;
            }
            assert_ne!(stream.read_buf(wire).await.unwrap(), 0);
        }
    }

    fn decode_len(input: &mut &[u8]) -> usize {
        let first = input[0];
        if first & 0x80 == 0 {
            *input = &input[1..];
            first as usize
        } else {
            let value = u32::from_be_bytes([input[0] & 0x7f, input[1], input[2], input[3]]);
            *input = &input[4..];
            value as usize
        }
    }

    #[test]
    fn fastcgi_params_omit_untrusted_forwarding_headers() {
        let request = http::Request::builder()
            .uri("/app/tail")
            .header("Host", "example.test")
            .header("CF-Connecting-IP", "198.51.100.9")
            .header("X_Real_Ip", "127.0.0.1")
            .header("User-Agent", "curl/8")
            .body(hj_core::empty_incoming())
            .unwrap();
        let mut ctx = context();
        ctx.forwarding_trusted = false;
        let env: BTreeMap<String, String> =
            CgiEnvBuilder::new(std::path::Path::new("/srv/apps/index.fcgi"))
                .build(&request, &ctx)
                .into_iter()
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect();
        assert!(!env.contains_key("HTTP_CF_CONNECTING_IP"));
        assert!(!env.contains_key("HTTP_X_REAL_IP"));
        assert_eq!(env["HTTP_USER_AGENT"], "curl/8");
        assert!(env.contains_key("REMOTE_ADDR"));
    }

    fn decode_params(bytes: &[u8]) -> BTreeMap<String, String> {
        let mut input = bytes;
        let mut values = BTreeMap::new();
        while !input.is_empty() {
            let name_len = decode_len(&mut input);
            let value_len = decode_len(&mut input);
            let name = String::from_utf8(input[..name_len].to_vec()).unwrap();
            input = &input[name_len..];
            let value = String::from_utf8(input[..value_len].to_vec()).unwrap();
            input = &input[value_len..];
            values.insert(name, value);
        }
        values
    }

    #[tokio::test]
    async fn handler_pins_target_streams_response_and_reuses_only_clean_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = BytesMut::new();
            for iteration in 0..2 {
                let begin = server_record(&mut stream, &mut wire).await;
                assert_eq!(begin.kind, RecordType::BeginRequest);
                assert_eq!(
                    begin.content[2],
                    crate::FCGI_KEEP_CONN,
                    "bodyless request keeps"
                );
                let mut params = BytesMut::new();
                loop {
                    let record = server_record(&mut stream, &mut wire).await;
                    assert_eq!(record.kind, RecordType::Params);
                    if record.content.is_empty() {
                        break;
                    }
                    params.extend_from_slice(&record.content);
                }
                let env = decode_params(&params);
                assert_eq!(env["SCRIPT_FILENAME"], "/srv/apps/index.fcgi");
                assert_eq!(env["SCRIPT_NAME"], "/app");
                assert_eq!(env["PATH_INFO"], "/tail");
                // A bodyless GET must not invent CONTENT_LENGTH=0 (#765).
                assert!(!env.contains_key("CONTENT_LENGTH"), "{env:?}");
                let mut stdin = BytesMut::new();
                loop {
                    let record = server_record(&mut stream, &mut wire).await;
                    assert_eq!(record.kind, RecordType::Stdin);
                    if record.content.is_empty() {
                        break;
                    }
                    stdin.extend_from_slice(&record.content);
                }
                assert!(stdin.is_empty());
                let response = format!(
                    "Status: 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nbody-{iteration}"
                );
                for frame in
                    encode_stream(RecordType::Stdout, REQUEST_ID, response.as_bytes()).unwrap()
                {
                    stream.write_all(&frame).await.unwrap();
                }
                stream
                    .write_all(&end_stream(RecordType::Stdout, REQUEST_ID).unwrap())
                    .await
                    .unwrap();
                stream
                    .write_all(&end_stream(RecordType::Stderr, REQUEST_ID).unwrap())
                    .await
                    .unwrap();
                stream
                    .write_all(&crate::end_request(REQUEST_ID, 0).unwrap())
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
        });
        let pool = Arc::new(
            FastCgiPool::new(
                crate::Endpoint::Tcp(address),
                1,
                Duration::from_secs(1),
                Duration::from_secs(30),
            )
            .unwrap(),
        );
        let handler = FastCgi::new(pool);
        for iteration in 0..2 {
            let mut request = http::Request::builder()
                .uri("/app/tail?q=1")
                .header("host", "example.test")
                .body(empty_incoming())
                .unwrap();
            request.extensions_mut().insert(
                FastCgiScript::new("/srv/apps/index.fcgi")
                    .unwrap()
                    .script_name("/app")
                    .path_info("/tail"),
            );
            let response = handler.handle(&mut context(), request).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::CREATED);
            let body = match response.into_body() {
                Body::Stream(body) => body.collect().await.unwrap().to_bytes(),
                _ => panic!("expected streamed FastCGI body"),
            };
            assert_eq!(body, format!("body-{iteration}"));
        }
        server.await.unwrap();
    }

    /// #813: an application that writes a large response before draining a large
    /// STDIN must not deadlock against the request-body write.
    #[tokio::test]
    async fn large_body_is_pumped_concurrently_with_large_response() {
        const SIZE: usize = 8 * 1024 * 1024;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                // A bodied request never keeps its connection (#832).
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut wire = BytesMut::new();
                let begin = server_record(&mut stream, &mut wire).await;
                assert_eq!(begin.kind, RecordType::BeginRequest);
                assert_eq!(begin.content[2], 0, "bodied request must not set KEEP_CONN");
                while !server_record(&mut stream, &mut wire)
                    .await
                    .content
                    .is_empty()
                {}
                let head = format!("Content-Type: text/plain\r\nContent-Length: {SIZE}\r\n\r\n");
                for frame in encode_stream(RecordType::Stdout, REQUEST_ID, head.as_bytes()).unwrap()
                {
                    stream.write_all(&frame).await.unwrap();
                }
                for frame in
                    encode_stream(RecordType::Stdout, REQUEST_ID, &vec![b'o'; SIZE]).unwrap()
                {
                    stream.write_all(&frame).await.unwrap();
                }
                stream
                    .write_all(&end_stream(RecordType::Stdout, REQUEST_ID).unwrap())
                    .await
                    .unwrap();
                let mut stdin = 0_usize;
                loop {
                    let record = server_record(&mut stream, &mut wire).await;
                    assert_eq!(record.kind, RecordType::Stdin);
                    if record.content.is_empty() {
                        break;
                    }
                    assert!(record.content.iter().all(|byte| *byte == b'i'));
                    stdin += record.content.len();
                }
                assert_eq!(stdin, SIZE);
                stream
                    .write_all(&crate::end_request(REQUEST_ID, 0).unwrap())
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
        });
        let pool = Arc::new(
            FastCgiPool::new(
                crate::Endpoint::Tcp(address),
                1,
                Duration::from_secs(1),
                Duration::from_secs(30),
            )
            .unwrap(),
        );
        let handler = FastCgi::new(pool).read_timeout(Duration::from_secs(3));
        let started = std::time::Instant::now();
        // Two rounds on a one-connection pool: the second proves the first
        // connection released its slot after its pump finished.
        for _ in 0..2 {
            let mut request = http::Request::builder()
                .method(http::Method::PUT)
                .uri("/upload")
                .header("host", "example.test")
                .header("content-length", SIZE.to_string())
                .body(
                    http_body_util::Full::new(Bytes::from(vec![b'i'; SIZE]))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap();
            request
                .extensions_mut()
                .insert(FastCgiScript::new("/srv/apps/upload.fcgi").unwrap());
            let response = tokio::time::timeout(
                Duration::from_secs(10),
                handler.handle(&mut context(), request),
            )
            .await
            .expect("response head must not deadlock")
            .unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            let body = match response.into_body() {
                Body::Stream(body) => tokio::time::timeout(Duration::from_secs(10), body.collect())
                    .await
                    .expect("response body must not deadlock")
                    .unwrap()
                    .to_bytes(),
                _ => panic!("expected streamed FastCGI body"),
            };
            assert_eq!(body.len(), SIZE);
        }
        server.await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    fn fastcgi_pool(address: std::net::SocketAddr) -> Arc<FastCgiPool> {
        Arc::new(
            FastCgiPool::new(
                crate::Endpoint::Tcp(address),
                1,
                Duration::from_secs(1),
                Duration::from_secs(30),
            )
            .unwrap(),
        )
    }

    fn get_request(uri: &str) -> Request {
        let mut request = http::Request::builder()
            .uri(uri)
            .header("host", "example.test")
            .body(empty_incoming())
            .unwrap();
        request
            .extensions_mut()
            .insert(FastCgiScript::new("/srv/apps/index.php").unwrap());
        request
    }

    async fn streamed_body(response: Response) -> Result<Bytes, BoxError> {
        match response.into_body() {
            Body::Stream(body) => body.collect().await.map(|body| body.to_bytes()),
            _ => panic!("expected streamed FastCGI body"),
        }
    }

    /// Reads one request (BEGIN_REQUEST, PARAMS, STDIN) the way an application
    /// does; returns the keep-connection flag and the decoded params.
    async fn read_whole_request(
        stream: &mut tokio::net::TcpStream,
        wire: &mut BytesMut,
    ) -> (bool, BTreeMap<String, String>) {
        let begin = server_record(stream, wire).await;
        assert_eq!(begin.kind, RecordType::BeginRequest);
        let mut params = BytesMut::new();
        loop {
            let record = server_record(stream, wire).await;
            assert_eq!(record.kind, RecordType::Params);
            if record.content.is_empty() {
                break;
            }
            params.extend_from_slice(&record.content);
        }
        while !server_record(stream, wire).await.content.is_empty() {}
        (
            begin.content[2] & crate::FCGI_KEEP_CONN != 0,
            decode_params(&params),
        )
    }

    /// Writes a response as php-fpm/php-cgi do: STDOUT data, then END_REQUEST,
    /// with NO empty STDOUT terminator (#831).
    async fn write_php_response(stream: &mut tokio::net::TcpStream, payload: &str) {
        for frame in encode_stream(RecordType::Stdout, REQUEST_ID, payload.as_bytes()).unwrap() {
            stream.write_all(&frame).await.unwrap();
        }
        stream
            .write_all(&crate::end_request(REQUEST_ID, 0).unwrap())
            .await
            .unwrap();
        stream.flush().await.unwrap();
    }

    /// #831: END_REQUEST implicitly ends STDOUT; such a response completes and
    /// its connection is reused.
    #[tokio::test]
    async fn end_request_without_empty_stdout_completes_and_reuses_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = BytesMut::new();
            for iteration in 0..2 {
                let (keep, _) = read_whole_request(&mut stream, &mut wire).await;
                assert!(keep);
                write_php_response(
                    &mut stream,
                    &format!(
                        "Content-Type: text/plain\r\nContent-Length: 6\r\n\r\nbody-{iteration}"
                    ),
                )
                .await;
            }
        });
        let handler = FastCgi::new(fastcgi_pool(address));
        for iteration in 0..2 {
            let response = handler
                .handle(&mut context(), get_request("/index.php"))
                .await
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(
                streamed_body(response).await.unwrap(),
                format!("body-{iteration}")
            );
        }
        // One accept served both requests: the first connection was re-pooled.
        server.await.unwrap();
    }

    /// #1017: php-fpm/php-cgi register params through `php_register_variable_ex`
    /// too, so a directory-authored env name PHP folds onto a protected key
    /// (`REMOTE.ADDR` -> `REMOTE_ADDR`) never reaches the application params.
    #[tokio::test]
    async fn params_refuse_env_names_php_folds_onto_protected_vars() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = BytesMut::new();
            let (_, params) = read_whole_request(&mut stream, &mut wire).await;
            write_php_response(
                &mut stream,
                "Content-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
            )
            .await;
            params
        });
        let mut ctx = context();
        ctx.env = vec![
            ("REMOTE.ADDR".into(), "6.6.6.6".into()),
            (" HTTPS".into(), "on".into()),
            ("SSL.CLIENT.VERIFY".into(), "SUCCESS".into()),
            ("REMOTE[USER".into(), "admin".into()),
            ("HJ.CACHE.REFRESH".into(), "1".into()),
            ("APP.MODE".into(), "x".into()),
        ];
        let response = FastCgi::new(fastcgi_pool(address))
            .handle(&mut ctx, get_request("/index.php"))
            .await
            .unwrap();
        assert_eq!(streamed_body(response).await.unwrap(), "ok");
        let params = server.await.unwrap();
        assert_eq!(params["REMOTE_ADDR"], "203.0.113.10");
        for forged in [
            "REMOTE.ADDR",
            " HTTPS",
            "HTTPS",
            "SSL.CLIENT.VERIFY",
            "REMOTE[USER",
            "REMOTE_USER",
            "HJ.CACHE.REFRESH",
        ] {
            assert!(!params.contains_key(forged), "{forged:?} in {params:?}");
        }
        assert_eq!(params["APP.MODE"], "x");
    }

    /// #1003: PHP's `header('Connection: close')` idiom is served, its hop-by-hop
    /// fields dropped, instead of turning the response into a 502.
    #[tokio::test]
    async fn application_hop_by_hop_headers_are_dropped_from_a_served_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = BytesMut::new();
            read_whole_request(&mut stream, &mut wire).await;
            write_php_response(
                &mut stream,
                "Connection: close\r\nKeep-Alive: timeout=5, max=100\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
            )
            .await;
        });
        let handler = FastCgi::new(fastcgi_pool(address));
        let response = handler
            .handle(&mut context(), get_request("/index.php"))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert!(!response.headers().contains_key(http::header::CONNECTION));
        assert!(!response.headers().contains_key("keep-alive"));
        assert_eq!(response.headers()[http::header::CONTENT_TYPE], "text/plain");
        assert_eq!(streamed_body(response).await.unwrap(), "ok");
        server.await.unwrap();
    }

    /// #831 keeps the Content-Length check: END_REQUEST before the declared body
    /// length arrived still aborts the body.
    #[tokio::test]
    async fn end_request_before_declared_length_still_aborts_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = BytesMut::new();
            read_whole_request(&mut stream, &mut wire).await;
            write_php_response(&mut stream, "Content-Length: 10\r\n\r\nshort").await;
        });
        let handler = FastCgi::new(fastcgi_pool(address));
        let response = handler
            .handle(&mut context(), get_request("/index.php"))
            .await
            .unwrap();
        assert!(streamed_body(response).await.is_err());
        server.await.unwrap();
    }

    /// Regression (#929): a connection that ends mid-STDOUT, with no END_REQUEST and
    /// no Content-Length, aborts the body instead of ending it as complete.
    #[tokio::test]
    async fn eof_before_end_request_aborts_unframed_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = BytesMut::new();
            read_whole_request(&mut stream, &mut wire).await;
            for frame in encode_stream(
                RecordType::Stdout,
                REQUEST_ID,
                b"Content-Type: text/plain\r\n\r\npartial",
            )
            .unwrap()
            {
                stream.write_all(&frame).await.unwrap();
            }
            stream.flush().await.unwrap();
        });
        let handler = FastCgi::new(fastcgi_pool(address));
        let response = handler
            .handle(&mut context(), get_request("/index.php"))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(streamed_body(response).await.is_err());
    }

    /// Regression (#832): an application that reads its STDIN partially leaves
    /// the tail on the socket; on a kept connection php-fpm/php-cgi parse it as
    /// the next request. A forged BEGIN_REQUEST in that tail must never run as,
    /// or answer, a later request.
    #[tokio::test]
    async fn unread_stdin_tail_cannot_smuggle_a_request_onto_a_later_one() {
        const READ: usize = 16;
        let mut forged = BytesMut::new();
        forged.extend_from_slice(&begin_request(REQUEST_ID, true).unwrap());
        for record in encode_name_value_pairs(
            REQUEST_ID,
            [("SCRIPT_FILENAME", "/srv/apps/evil.php")],
            1024,
        )
        .unwrap()
        {
            forged.extend_from_slice(&record);
        }
        forged.extend_from_slice(&end_stream(RecordType::Stdin, REQUEST_ID).unwrap());
        let mut body = vec![b'A'; READ];
        body.extend_from_slice(&forged);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connections = 0_usize;
            let mut held = Vec::new();
            while let Ok(Ok((mut stream, _))) =
                tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
            {
                connections += 1;
                held.push(tokio::spawn(async move {
                    let mut wire = BytesMut::new();
                    loop {
                        let begin = loop {
                            match parse_record(&mut wire) {
                                Ok(Some(record)) => break record,
                                Ok(None) => {}
                                Err(_) => return,
                            }
                            if stream.read_buf(&mut wire).await.unwrap_or(0) == 0 {
                                return;
                            }
                        };
                        if begin.kind != RecordType::BeginRequest {
                            return;
                        }
                        let keep = begin.content[2] & crate::FCGI_KEEP_CONN != 0;
                        let mut params = BytesMut::new();
                        loop {
                            let record = server_record(&mut stream, &mut wire).await;
                            if record.content.is_empty() {
                                break;
                            }
                            params.extend_from_slice(&record.content);
                        }
                        let env = decode_params(&params);
                        if env.get("CONTENT_LENGTH").is_some_and(|len| len != "0") {
                            // The script reads READ bytes of php://input: the STDIN
                            // record header plus READ content bytes leave the socket.
                            while wire.len() < 8 + READ {
                                assert_ne!(stream.read_buf(&mut wire).await.unwrap(), 0);
                            }
                            let _ = wire.split_to(8 + READ);
                        } else {
                            while !server_record(&mut stream, &mut wire)
                                .await
                                .content
                                .is_empty()
                            {}
                        }
                        let payload = if env["SCRIPT_FILENAME"] == "/srv/apps/evil.php" {
                            "Content-Length: 4\r\n\r\nEVIL"
                        } else {
                            "Content-Length: 4\r\n\r\ngood"
                        };
                        write_php_response(&mut stream, payload).await;
                        if !keep {
                            return;
                        }
                    }
                }));
            }
            for task in held {
                task.abort();
            }
            connections
        });

        let handler = FastCgi::new(fastcgi_pool(address));
        let mut put = http::Request::builder()
            .method(http::Method::PUT)
            .uri("/upload.php")
            .header("host", "example.test")
            .header("content-length", body.len().to_string())
            .body(
                http_body_util::Full::new(Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();
        put.extensions_mut()
            .insert(FastCgiScript::new("/srv/apps/upload.php").unwrap());
        let response = handler.handle(&mut context(), put).await.unwrap();
        assert_eq!(streamed_body(response).await.unwrap(), "good");
        for _ in 0..2 {
            let response = handler
                .handle(&mut context(), get_request("/index.php"))
                .await
                .unwrap();
            assert_eq!(
                streamed_body(response).await.unwrap(),
                "good",
                "a later request received the smuggled response"
            );
        }
        // The PUT's connection was closed; both GETs share one kept connection.
        assert_eq!(server.await.unwrap(), 2);
    }

    /// LIVE (#831/#832): the real php-cgi in FastCGI mode on a temp unix socket.
    ///   cargo test -p hj-fastcgi -- --ignored live_php_cgi --nocapture
    #[tokio::test]
    #[ignore = "spawns the real php-cgi; run manually on an R&D box"]
    async fn live_php_cgi_responses_complete_and_tail_is_not_smuggled() {
        let php_cgi = std::path::Path::new("/usr/local/bin/php-cgi");
        if !php_cgi.exists() {
            eprintln!("php-cgi not found at {php_cgi:?}; skipping");
            return;
        }
        let dir = std::env::temp_dir().join(format!("hj-fastcgi-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hello.php"), b"<?php echo 'hello';\n").unwrap();
        std::fs::write(
            dir.join("partial.php"),
            b"<?php $f = fopen('php://input', 'r'); echo 'partial:', strlen(fread($f, 8192));\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("evil.php"),
            b"<?php file_put_contents(__DIR__ . '/evil-ran', '1'); echo 'EVIL';\n",
        )
        .unwrap();
        let socket = dir.join("php-cgi.sock");
        let mut child = tokio::process::Command::new(php_cgi)
            .arg("-b")
            .arg(&socket)
            .env_clear()
            .env("PHP_FCGI_CHILDREN", "0")
            .env("PHP_FCGI_MAX_REQUESTS", "1000")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let pool = Arc::new(
            FastCgiPool::new(
                crate::Endpoint::Unix(socket.clone()),
                1,
                Duration::from_secs(5),
                Duration::from_secs(30),
            )
            .unwrap(),
        );
        let handler = FastCgi::new(pool).read_timeout(Duration::from_secs(10));
        let script = |name: &str| FastCgiScript::new(dir.join(name)).unwrap();

        let mut results = Vec::new();
        for _ in 0..2 {
            let mut request = get_request("/hello.php");
            request.extensions_mut().insert(script("hello.php"));
            let response = handler.handle(&mut context(), request).await.unwrap();
            results.push(streamed_body(response).await.unwrap());
        }

        let evil = dir.join("evil.php").to_string_lossy().into_owned();
        let mut forged = BytesMut::new();
        forged.extend_from_slice(&begin_request(REQUEST_ID, true).unwrap());
        for record in encode_name_value_pairs(
            REQUEST_ID,
            [
                ("SCRIPT_FILENAME", evil.as_str()),
                ("REQUEST_METHOD", "GET"),
                ("SCRIPT_NAME", "/evil.php"),
                ("REQUEST_URI", "/evil.php"),
            ],
            4096,
        )
        .unwrap()
        {
            forged.extend_from_slice(&record);
        }
        forged.extend_from_slice(&end_stream(RecordType::Stdin, REQUEST_ID).unwrap());
        let mut body = vec![b'A'; 8192];
        body.extend_from_slice(&forged);
        let mut put = http::Request::builder()
            .method(http::Method::PUT)
            .uri("/partial.php")
            .header("host", "example.test")
            .header("content-length", body.len().to_string())
            .body(
                http_body_util::Full::new(Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();
        put.extensions_mut().insert(script("partial.php"));
        let response = handler.handle(&mut context(), put).await.unwrap();
        let put_body = streamed_body(response).await.unwrap();
        for _ in 0..2 {
            let mut request = get_request("/hello.php");
            request.extensions_mut().insert(script("hello.php"));
            let response = handler.handle(&mut context(), request).await.unwrap();
            results.push(streamed_body(response).await.unwrap());
        }
        let evil_ran = dir.join("evil-ran").exists();
        let _ = child.kill().await;
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("put={put_body:?} gets={results:?} evil_ran={evil_ran}");
        assert_eq!(put_body, "partial:8192");
        assert!(results.iter().all(|body| body == "hello"), "{results:?}");
        assert!(!evil_ran, "the body tail ran as a request");
    }

    #[tokio::test]
    async fn missing_or_relative_script_target_fails_closed_before_pool_use() {
        assert!(FastCgiScript::new("relative.fcgi").is_err());
        let pool = Arc::new(
            FastCgiPool::new(
                crate::Endpoint::Tcp("127.0.0.1:9".parse().unwrap()),
                1,
                Duration::from_millis(10),
                Duration::from_secs(1),
            )
            .unwrap(),
        );
        let error = match FastCgi::new(pool)
            .handle(&mut context(), http::Request::new(empty_incoming()))
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("missing target must fail"),
        };
        assert!(matches!(error, HandlerError::Other(_)));
    }

    #[test]
    fn configured_environment_cannot_override_request_identity() {
        let pool = Arc::new(
            FastCgiPool::new(
                crate::Endpoint::Tcp("127.0.0.1:9".parse().unwrap()),
                1,
                Duration::from_millis(10),
                Duration::from_secs(1),
            )
            .unwrap(),
        );
        assert!(
            FastCgi::new(pool.clone())
                .base_env([("APP_MODE".into(), "production".into())])
                .is_ok()
        );
        for name in [
            "SCRIPT_FILENAME",
            "REMOTE_ADDR",
            "HTTP_AUTHORIZATION",
            "SSL_CLIENT_VERIFY",
            "REDIRECT_STATUS",
            "bad-name",
        ] {
            assert!(
                FastCgi::new(pool.clone())
                    .base_env([(name.into(), "forged".into())])
                    .is_err(),
                "{name} must be protected"
            );
        }
    }
}
