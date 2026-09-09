use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, channel::Channel, combinators::BoxBody};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        let (body, _lease) = collect_body(req.body_mut(), self.max_body, &self.body_budget).await?;
        if declared.is_some_and(|len| len != body.len() as u64) {
            return Err(HandlerError::BadGateway(
                "request body length did not match Content-Length".into(),
            ));
        }
        req.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&body.len().to_string())
                .map_err(|_| HandlerError::PayloadTooLarge)?,
        );

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

        let mut conn = self.pool.acquire().await.map_err(map_pool_error)?;
        write_request(&mut conn, params, &body, self.read_timeout).await?;

        let mut wire = BytesMut::with_capacity(16 * 1024);
        let mut header = BytesMut::new();
        let mut stderr_seen = 0_usize;
        let parsed = loop {
            let record = next_record(&mut conn, &mut wire, self.read_timeout).await?;
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

async fn write_request(
    conn: &mut crate::pool::PooledConnection,
    params: Vec<Bytes>,
    body: &[u8],
    timeout: Duration,
) -> Result<(), HandlerError> {
    let operation = async {
        conn.write_all(&begin_request(REQUEST_ID, true).expect("constant request id"))
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

async fn next_record(
    conn: &mut crate::pool::PooledConnection,
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
    mut conn: crate::pool::PooledConnection,
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
    let mut stdout_ended = false;
    let mut stderr_ended = false;
    let mut clean = feed(&mut tx, prefix, &mut sent, expected, discard).await;
    while clean {
        let record = match next_record(&mut conn, &mut wire, timeout).await {
            Ok(record) => record,
            Err(error) => {
                tracing::warn!(target: "hj_fastcgi", %error, "FastCGI response stream failed");
                break;
            }
        };
        if require_response_record(&record).is_err() {
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
            RecordType::EndRequest if stdout_ended => {
                match parse_end_request(&record.content) {
                    Ok(app_status) if expected.is_none_or(|length| length == sent) => {
                        if app_status != 0 {
                            tracing::warn!(target: "hj_fastcgi", app_status, "FastCGI application returned nonzero status");
                        }
                        conn.mark_reusable();
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
                assert_eq!(
                    server_record(&mut stream, &mut wire).await.kind,
                    RecordType::BeginRequest
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
