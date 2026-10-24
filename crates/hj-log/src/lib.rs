//! httpjet logging: non-blocking **access** and **error** logging.
//!
//! Both loggers push records onto a bounded-free `mpsc` channel that is drained
//! by a single background tokio task owning the open file handle. The request
//! path therefore never blocks on disk I/O — it only does a channel send.
//!
//! # Access logging
//!
//! [`AccessLogger::spawn`] starts the writer task and returns a cheap, clonable
//! handle. Call [`AccessLogger::log`] from the request path (synchronous, never
//! blocks). Records carry an **injectable timestamp** ([`AccessRecord::ts`]) so
//! rendering is fully deterministic and unit-testable.
//!
//! Lines are rendered in the Apache/LiteSpeed **combined** or **common** log
//! format. LiteSpeed `logHeaders` is a bitmask (1 Referer, 2 User-Agent, 4 Host):
//! the default 3 is [`LogFormat::Combined`], 7 is [`LogFormat::CombinedHost`].
//!
//! # Rolling
//!
//! When the live file grows past `rolling_size`, it is renamed to a timestamped
//! sibling, optionally gzip-compressed (via `flate2`), and files older than
//! `keep_days` are pruned. [`AccessLogger::reopen`] re-opens the path for
//! `logrotate`/`SIGUSR1` compatibility.
//!
//! # Error logging
//!
//! [`ErrorLogger`] is a thin async appender over the same rolling writer,
//! emitting LiteSpeed-style `YYYY-MM-DD HH:MM:SS.uuuuuu [LEVEL] msg` lines. It is
//! handy for funnelling captured backend `stderr` into the server error log.
//!
//! ## Orchestrator usage
//!
//! ```no_run
//! # async fn demo() {
//! use hj_log::{AccessLogger, AccessRecord, LogFormat, ErrorLogger, LogLevel};
//! use std::time::SystemTime;
//!
//! let access = AccessLogger::spawn(
//!     "/usr/local/httpjet/logs/access.log",
//!     LogFormat::Combined,
//!     10 * 1024 * 1024, // roll at 10 MiB
//!     30,               // keep 30 days
//!     true,             // gzip archives
//! );
//!
//! access.log(AccessRecord {
//!     client_ip: "203.0.113.7".parse().unwrap(),
//!     ts: SystemTime::now(),
//!     method: "GET".into(),
//!     uri: "/index.html".into(),
//!     protocol: "HTTP/2".into(),
//!     status: 200,
//!     bytes: 1234,
//!     referer: Some("https://example.com/".into()),
//!     user_agent: Some("curl/8.0".into()),
//!     host: Some("example.com".into()),
//!     remote_user: None,
//!     request_id: None,
//!     peer_unix: false,
//! });
//!
//! let errlog = ErrorLogger::spawn(
//!     "/usr/local/httpjet/logs/error.log",
//!     20 * 1024 * 1024,
//!     30,
//!     true,
//! );
//! errlog.log(LogLevel::Notice, "server started");
//!
//! access.shutdown().await;
//! errlog.shutdown().await;
//! # }
//! ```

mod error_json;
mod fmt;
mod syslog;
mod tracing_layer;
mod writer;

use std::borrow::Cow;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;

use tokio::sync::{mpsc, oneshot};

pub use fmt::clf_time;
pub use syslog::{SyslogConfig, SyslogFacility, SyslogSeverity, SyslogTap, SyslogTarget};
pub use tracing_layer::ErrorLogLayer;
pub use writer::RollConfig;

/// (#8) Cap on the number of in-flight log `Line` records buffered toward the
/// writer task. A stalled writer (hung disk / multi-second gzip during a roll)
/// would otherwise let the unbounded queue grow with request volume until OOM;
/// past this cap we SHED lines (the request path must never block or OOM on
/// logging). Control messages (Reopen/Shutdown) are never counted and never shed.
const MAX_QUEUED_LINES: u64 = 65_536;

/// Byte budget for the same backlog, charged with each message's owned heap
/// capacity. Lines alone let oversized records (an 8 KiB URI plus 16 KiB of
/// logged headers, more once obs-text is `\xNN`-escaped) hold over 1.5 GiB per
/// logger. 64 MiB is twice what the line cap holds at a typical ~500 bytes per
/// record, so ordinary traffic still sheds on the line cap first.
const MAX_QUEUED_BYTES: u64 = 64 * 1024 * 1024;

/// Per-logger state shared between the logger handle and any supervisory code:
/// the in-flight line depth counter and a gone-flag that fires exactly once when
/// the writer task disappears. Stored per-logger (not process-wide) so that two
/// independent loggers each track their own liveness independently — a dead
/// error-log writer does not suppress the gone warning for the access-log writer.
pub(crate) struct LoggerStateInner {
    pub depth: AtomicU64,
    /// Owned bytes of the queued messages ([`Msg::queued_bytes`]).
    pub queued_bytes: AtomicU64,
    pub gone: AtomicBool,
    pub dropped: AtomicU64,
}

impl LoggerStateInner {
    pub(crate) fn new() -> Self {
        LoggerStateInner {
            depth: AtomicU64::new(0),
            queued_bytes: AtomicU64::new(0),
            gone: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
        }
    }

    /// Admit `lines` lines holding `bytes` owned bytes, or shed them (counted
    /// in `dropped`) when either budget would be exceeded.
    fn admit(&self, lines: u64, bytes: u64) -> bool {
        if self.depth.load(Ordering::Relaxed) + lines > MAX_QUEUED_LINES
            || self.queued_bytes.load(Ordering::Relaxed) + bytes > MAX_QUEUED_BYTES
        {
            self.dropped.fetch_add(lines, Ordering::Relaxed);
            return false;
        }
        self.depth.fetch_add(lines, Ordering::Relaxed);
        self.queued_bytes.fetch_add(bytes, Ordering::Relaxed);
        true
    }

    /// Undo an [`admit`](Self::admit) whose send failed because the writer is
    /// gone; warns once.
    fn writer_gone(&self, lines: u64, bytes: u64, what: &str) {
        self.depth.fetch_sub(lines, Ordering::Relaxed);
        self.queued_bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.dropped.fetch_add(lines, Ordering::Relaxed);
        if !self.gone.swap(true, Ordering::Relaxed) {
            // The writer will never drain again, so any lines that were still queued
            // when it died keep their never-released charge. Reset the gauges the
            // first time we notice — else stale charge can pin them at the shed cap.
            self.depth.store(0, Ordering::Relaxed);
            self.queued_bytes.store(0, Ordering::Relaxed);
            eprintln!("hj-log: {what} writer task gone; subsequent {what} lines are dropped");
        }
    }
}

pub(crate) type LoggerState = Arc<LoggerStateInner>;

/// Send a `Line` to the writer task; if it has gone away, emit ONE stderr line
/// (per-logger `gone` flag inside `state`) so a dead logger is *noticed* rather
/// than silently swallowing every subsequent record. Never blocks, never panics.
/// (Logging must not take the request path down — so this only warns; it does not
/// retry or error out.)
///
/// The backlog is charged BEFORE sending (so the writer's release can never
/// underflow it) and shed past `MAX_QUEUED_LINES` lines or `MAX_QUEUED_BYTES`
/// bytes, so a stalled writer can't grow the queue without bound.
fn send_or_warn(tx: &mpsc::UnboundedSender<Msg>, state: &LoggerState, msg: Msg, what: &str) {
    let bytes = msg.queued_bytes();
    if !state.admit(1, bytes) {
        return; // shed: writer backlogged at a cap — drop rather than risk OOM
    }
    if tx.send(msg).is_err() {
        state.writer_gone(1, bytes, what);
    }
}

/// Watch a writer task: if it ends by PANIC (not a clean `Shutdown`), shout to
/// stderr (→ the prod log) so the loss of logging is visible and names which file
/// died. The panic hook also catches it; this adds the "which logger" context. A
/// clean shutdown returns `Ok(())` and stays silent.
fn supervise_writer(handle: tokio::task::JoinHandle<()>, what: &'static str) {
    tokio::spawn(async move {
        if let Err(e) = handle.await {
            if e.is_panic() {
                eprintln!(
                    "hj-log: {what} writer task PANICKED ({e}); this log has STOPPED writing"
                );
            } else {
                eprintln!("hj-log: {what} writer task ended unexpectedly ({e})");
            }
        }
    });
}

/// Access-log line format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// `%h %l %u %t "%r" %>s %b` — the NCSA Common Log Format.
    Common,
    /// Common + `"%{Referer}i" "%{User-Agent}i"` — the Combined Log Format
    /// (LiteSpeed `logHeaders=3`, its default).
    Combined,
    /// Combined + `"%{Host}i"`: LiteSpeed `logHeaders` with bit 4 (`LOG_VHOST`)
    /// set, e.g. `logHeaders=7` (OLS `AccessLog::log`).
    CombinedHost,
    /// (Tier 2) One JSON object per line — structured logging for log shippers.
    /// Field order is fixed; absent optionals render as `null`.
    Json,
    /// Common + any other `logHeaders` selection (bits [`LOG_REFERER`],
    /// [`LOG_USERAGENT`], [`LOG_VHOST`]); see [`LogFormat::from_log_headers`].
    Headers(u8),
}

/// LiteSpeed `logHeaders` bit: append the quoted `Referer`.
pub const LOG_REFERER: u8 = 1;
/// LiteSpeed `logHeaders` bit: append the quoted `User-Agent`.
pub const LOG_USERAGENT: u8 = 2;
/// LiteSpeed `logHeaders` bit: append the quoted `Host`.
pub const LOG_VHOST: u8 = 4;

impl LogFormat {
    /// The text format for a LiteSpeed `logHeaders` bitmask (OLS
    /// `AccessLog::log`): 0 is Common, 3 Combined, 7 CombinedHost, anything else
    /// selects exactly the fields whose bits are set, in Referer/UA/Host order.
    pub fn from_log_headers(mask: u8) -> LogFormat {
        match mask & (LOG_REFERER | LOG_USERAGENT | LOG_VHOST) {
            0 => LogFormat::Common,
            3 => LogFormat::Combined,
            7 => LogFormat::CombinedHost,
            m => LogFormat::Headers(m),
        }
    }

    fn header_mask(self) -> u8 {
        match self {
            LogFormat::Common | LogFormat::Json => 0,
            LogFormat::Combined => LOG_REFERER | LOG_USERAGENT,
            LogFormat::CombinedHost => LOG_REFERER | LOG_USERAGENT | LOG_VHOST,
            LogFormat::Headers(m) => m,
        }
    }
}

/// JSON string escape: quotes, backslashes and control characters. `<`/`>` and
/// U+2028/9 are left as-is (the logs are UTF-8 text consumed line-wise).
fn json_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    for ch in v.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// One access-log event. Construct on the request path and hand to
/// [`AccessLogger::log`].
///
/// The [`ts`](AccessRecord::ts) field is injectable so callers (and tests) fully
/// control the rendered timestamp; nothing reads the wall clock during
/// formatting.
#[derive(Debug, Clone)]
pub struct AccessRecord {
    /// Client IP (already resolved, honoring trusted proxies). Formatted at render
    /// time on the writer task, so the request path stores the value, not a String.
    pub client_ip: IpAddr,
    /// Event time. Use `SystemTime::now()` in production.
    pub ts: SystemTime,
    /// Request method, e.g. `GET`. `Cow::Borrowed(&'static str)` for the standard verbs
    /// (every CF-fronted request) — no allocation; owned only for a custom method.
    pub method: Cow<'static, str>,
    /// Request target (path + query) exactly as it should appear in the log.
    pub uri: String,
    /// Protocol token, e.g. `HTTP/1.1`, `HTTP/2`, `HTTP/3` — a `&'static str` (no allocation).
    pub protocol: &'static str,
    /// Final response status code.
    pub status: u16,
    /// Response body bytes sent (the `%b` field).
    pub bytes: u64,
    /// Raw `Referer` header bytes, if present (escaped `\xNN` at render time, so
    /// a non-ASCII value is logged rather than dropped).
    pub referer: Option<Vec<u8>>,
    /// Raw `User-Agent` header bytes, if present.
    pub user_agent: Option<Vec<u8>>,
    /// Raw `Host` header bytes (`logHeaders` bit 4).
    pub host: Option<Vec<u8>>,
    /// The Basic-auth user the server VERIFIED (the `%u` field), if any — never a
    /// client-asserted value.
    pub remote_user: Option<String>,
    /// Per-request correlation id, rendered as a trailing ` reqid=<id>` token so a
    /// line is joinable with the error/php-slow logs. `None` (e.g. tests / records
    /// built without a `ReqCtx`) renders no token, keeping the legacy CLF/combined
    /// layout byte-identical.
    pub request_id: Option<String>,
    /// (Tier 2) The connection arrived over a unix domain socket: there is no
    /// client address, so the `%h` field renders as the literal `unix:` (nginx's
    /// exact behavior) instead of the fabricated loopback address.
    pub peer_unix: bool,
}

impl AccessRecord {
    /// Render this record into a single CLF/combined log line (no trailing
    /// newline). Quotes and backslashes inside header values are escaped so a
    /// crafted `User-Agent` cannot break the line structure.
    pub fn render(&self, format: LogFormat) -> String {
        let reqid = self.request_id.as_deref().map(escape);
        let mut out = Vec::with_capacity(192);
        render_line(
            &mut out,
            format,
            &LineFields {
                client_ip: self.client_ip,
                ts: self.ts,
                method: &self.method,
                path: &self.uri,
                query: None,
                protocol: self.protocol,
                status: self.status,
                bytes: self.bytes,
                referer: self.referer.as_deref(),
                user_agent: self.user_agent.as_deref(),
                host: self.host.as_deref(),
                remote_user: self.remote_user.as_deref(),
                request_id: reqid.as_ref().map(|r| r as &dyn std::fmt::Display),
                peer_unix: self.peer_unix,
            },
        );
        // Every byte the renderer emits is either escaped ASCII or a UTF-8 `&str`
        // copied through, so this never actually takes the lossy branch.
        match String::from_utf8(out) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        }
    }
}

/// (#349) Render one access line straight from BORROWED request data into a
/// reusable buffer, byte-identical to [`AccessRecord::render`] plus the
/// trailing newline. This is the serving-thread half of chunked logging: no
/// per-line Strings, no per-line channel send.
#[allow(clippy::too_many_arguments)]
pub fn render_access_line_into(
    out: &mut Vec<u8>,
    format: LogFormat,
    client_ip: std::net::IpAddr,
    ts: SystemTime,
    method: &str,
    path: &str,
    query: Option<&str>,
    protocol: &str,
    status: u16,
    bytes: u64,
    referer: Option<&[u8]>,
    user_agent: Option<&[u8]>,
    request_id: Option<&dyn std::fmt::Display>,
    peer_unix: bool,
) {
    render_access_line_with_host_into(
        out, format, client_ip, ts, method, path, query, protocol, status, bytes, referer,
        user_agent, None, None, request_id, peer_unix,
    );
}

/// [`render_access_line_into`] with the `Host` header (`logHeaders` bit 4) and the
/// verified Basic-auth user (`%u`).
#[allow(clippy::too_many_arguments)]
pub fn render_access_line_with_host_into(
    out: &mut Vec<u8>,
    format: LogFormat,
    client_ip: std::net::IpAddr,
    ts: SystemTime,
    method: &str,
    path: &str,
    query: Option<&str>,
    protocol: &str,
    status: u16,
    bytes: u64,
    referer: Option<&[u8]>,
    user_agent: Option<&[u8]>,
    host: Option<&[u8]>,
    remote_user: Option<&str>,
    request_id: Option<&dyn std::fmt::Display>,
    peer_unix: bool,
) {
    render_line(
        out,
        format,
        &LineFields {
            client_ip,
            ts,
            method,
            path,
            query,
            protocol,
            status,
            bytes,
            referer,
            user_agent,
            host,
            remote_user,
            request_id,
            peer_unix,
        },
    );
    out.push(b'\n');
}

struct LineFields<'a> {
    client_ip: IpAddr,
    ts: SystemTime,
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    protocol: &'a str,
    status: u16,
    bytes: u64,
    referer: Option<&'a [u8]>,
    user_agent: Option<&'a [u8]>,
    host: Option<&'a [u8]>,
    remote_user: Option<&'a str>,
    request_id: Option<&'a dyn std::fmt::Display>,
    peer_unix: bool,
}

/// The one line renderer behind [`AccessRecord::render`] and the borrowed chunk
/// path, so the two can never drift. No trailing newline.
fn render_line(out: &mut Vec<u8>, format: LogFormat, f: &LineFields<'_>) {
    use std::io::Write;
    if format == LogFormat::Json {
        let jopt = |v: Option<&[u8]>| {
            v.map(|s| format!("\"{}\"", json_escape_bytes(s)))
                .unwrap_or_else(|| "null".to_string())
        };
        let mut line = String::with_capacity(192);
        line.push_str("{\"ts\":\"");
        line.push_str(&json_escape(&fmt::clf_time(f.ts)));
        line.push_str("\",\"client_ip\":\"");
        if f.peer_unix {
            line.push_str("unix:");
        } else {
            line.push_str(&json_escape(&f.client_ip.to_string()));
        }
        line.push_str("\",\"remote_user\":");
        line.push_str(&jopt(f.remote_user.map(str::as_bytes)));
        line.push_str(",\"method\":\"");
        line.push_str(&json_escape(f.method));
        line.push_str("\",\"uri\":\"");
        line.push_str(&json_escape(f.path));
        if let Some(q) = f.query {
            line.push('?');
            line.push_str(&json_escape(q));
        }
        line.push_str("\",\"protocol\":\"");
        line.push_str(&json_escape(f.protocol));
        line.push_str("\",\"status\":");
        line.push_str(&f.status.to_string());
        line.push_str(",\"bytes\":");
        line.push_str(&f.bytes.to_string());
        line.push_str(",\"referer\":");
        line.push_str(&jopt(f.referer));
        line.push_str(",\"user_agent\":");
        line.push_str(&jopt(f.user_agent));
        line.push_str(",\"reqid\":");
        match f.request_id {
            Some(id) => line.push_str(&format!("\"{}\"", json_escape(&id.to_string()))),
            None => line.push_str("null"),
        }
        line.push('}');
        out.extend_from_slice(line.as_bytes());
        return;
    }
    if f.peer_unix {
        out.extend_from_slice(b"unix:");
    } else {
        let _ = write!(out, "{}", f.client_ip);
    }
    // OLS `AccessLog::log`: the verified auth user is quoted, ` - "alice" `.
    match f.remote_user {
        Some(user) if !user.is_empty() => {
            let _ = write!(out, " - \"{}\" ", escape_bytes(user.as_bytes()));
        }
        _ => out.extend_from_slice(b" - - "),
    }
    let _ = write!(out, "[{}] \"", fmt::clf_time(f.ts));
    let _ = write!(out, "{} ", escape(f.method));
    let _ = write!(out, "{}", escape(f.path));
    if let Some(q) = f.query {
        let _ = write!(out, "?{}", escape(q));
    }
    let _ = write!(out, " {}\" {} ", escape(f.protocol), f.status);
    // `%b`: OLS writes `-` when no body byte was sent (`contentWritten == 0`).
    if f.bytes == 0 {
        out.push(b'-');
    } else {
        let _ = write!(out, "{}", f.bytes);
    }
    let mask = format.header_mask();
    if mask & LOG_REFERER != 0 {
        let _ = write!(out, " \"{}\"", quoted_bytes(f.referer));
    }
    if mask & LOG_USERAGENT != 0 {
        let _ = write!(out, " \"{}\"", quoted_bytes(f.user_agent));
    }
    if mask & LOG_VHOST != 0 {
        let _ = write!(out, " \"{}\"", quoted_bytes(f.host));
    }
    if let Some(id) = f.request_id {
        // Trailing token in every text format so the line is joinable with the
        // error/php-slow logs; absent ⇒ nothing appended (legacy layout).
        let _ = write!(out, " reqid={}", id);
    }
}

/// Quoted optional header value: absent/empty -> `-` (so it reads `"-"`).
fn quoted_bytes(v: Option<&[u8]>) -> Cow<'_, str> {
    match v {
        Some(s) if !s.is_empty() => escape_bytes(s),
        _ => Cow::Borrowed("-"),
    }
}

/// Escape control chars, `"` and `\` so log lines stay one-per-event and
/// unambiguous (Apache uses the same `\xNN` / `\"` style escaping). Returns a
/// borrow when nothing needs escaping (the common case for method/uri/protocol and
/// well-behaved headers), allocating only when a special char is present. `render`
/// now runs on the writer task (see [`AccessLogger::log`]), so this saves work on
/// the writer rather than the request path, but the borrow-on-clean-input win stands.
fn escape(s: &str) -> Cow<'_, str> {
    let needs = s
        .bytes()
        .any(|b| b == b'"' || b == b'\\' || b < 0x20 || b >= 0x7f);
    if !needs {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) == 0x7f || (0x80..=0x9f).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// [`escape`] for raw header bytes (Apache `ap_escape_logitem`): ASCII renders
/// exactly as [`escape`] does, and every byte >= 0x80 becomes `\xNN`, so a
/// non-ASCII `User-Agent` is logged instead of collapsing to `-`.
fn escape_bytes(s: &[u8]) -> Cow<'_, str> {
    if !s
        .iter()
        .any(|&b| b == b'"' || b == b'\\' || !(0x20..0x7f).contains(&b))
        && let Ok(clean) = std::str::from_utf8(s)
    {
        return Cow::Borrowed(clean);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for &b in s {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b if !(0x20..0x7f).contains(&b) => out.push_str(&format!("\\x{b:02x}")),
            b => out.push(char::from(b)),
        }
    }
    Cow::Owned(out)
}

/// JSON string body for raw header bytes: valid UTF-8 is escaped as
/// [`json_escape`] does; each byte of an invalid sequence becomes the literal
/// text `\xNN` (JSON-encoded as `\\xNN`).
fn json_escape_bytes(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for chunk in s.utf8_chunks() {
        out.push_str(&json_escape(chunk.valid()));
        for b in chunk.invalid() {
            out.push_str(&format!("\\\\x{b:02x}"));
        }
    }
    out
}

/// Messages on the writer control channel.
enum Msg {
    /// A rendered log line (newline appended by the writer). Used by
    /// [`ErrorLogger`] and [`AccessLogger::log_line`], which render up front.
    Line(String),
    /// An access record rendered by the **writer task** (off the request path).
    /// Boxed so this variant doesn't bloat every `Line`/error-log node to the
    /// record's ~220 bytes (and trip clippy's `large_enum_variant`).
    /// The optional third element is a continuation line emitted IMMEDIATELY after
    /// the record (#248 logHeaders): same channel message, so it can never mis-align
    /// with its record under load.
    Record(Box<AccessRecord>, LogFormat, Option<String>),
    /// (#349) A block of PRE-RENDERED, newline-terminated access lines from a
    /// serving thread's chunk buffer (one message per ~hundreds of lines).
    /// The count keeps the shared depth/shed accounting line-accurate.
    Chunk(Vec<u8>, u32),
    /// Close and re-open the underlying file (logrotate / SIGUSR1).
    Reopen,
    /// Flush and shut down; the writer replies on the oneshot.
    Shutdown(oneshot::Sender<()>),
}

impl Msg {
    /// Heap bytes the message owns while queued; the writer releases the same
    /// amount when it takes the message.
    fn queued_bytes(&self) -> u64 {
        let owned = |bytes: &Option<Vec<u8>>| bytes.as_ref().map_or(0, Vec::capacity);
        let text = |text: &Option<String>| text.as_ref().map_or(0, String::capacity);
        let bytes = match self {
            Msg::Line(line) => line.capacity(),
            Msg::Chunk(chunk, _) => chunk.capacity(),
            Msg::Record(record, _, extra) => {
                let method = match &record.method {
                    Cow::Owned(method) => method.capacity(),
                    Cow::Borrowed(_) => 0,
                };
                std::mem::size_of::<AccessRecord>()
                    + method
                    + record.uri.capacity()
                    + owned(&record.referer)
                    + owned(&record.user_agent)
                    + owned(&record.host)
                    + text(&record.remote_user)
                    + text(&record.request_id)
                    + text(extra)
            }
            Msg::Reopen | Msg::Shutdown(_) => 0,
        };
        bytes as u64
    }
}

/// Non-blocking access logger handle. Cheap to [`Clone`]; all clones feed the
/// same writer task.
#[derive(Clone)]
pub struct AccessLogger {
    tx: mpsc::UnboundedSender<Msg>,
    format: LogFormat,
    /// Per-logger state: `(depth, gone)`. `depth` bounds the in-flight line
    /// queue; `gone` fires once when the writer task disappears.
    state: LoggerState,
}

impl AccessLogger {
    /// Spawn the writer task and return a handle.
    ///
    /// * `path` — the live log file (created if missing, appended otherwise).
    /// * `format` — [`LogFormat::Combined`] or [`LogFormat::Common`].
    /// * `rolling_size` — roll when the file exceeds this many bytes (`0`
    ///   disables size-based rolling).
    /// * `keep_days` — prune rolled files older than this many days (`0`
    ///   disables pruning).
    /// * `compress_archive` — gzip rolled files with `flate2`.
    ///
    /// Must be called from within a tokio runtime.
    pub fn spawn(
        path: impl AsRef<Path>,
        format: LogFormat,
        rolling_size: u64,
        keep_days: u64,
        compress_archive: bool,
    ) -> Self {
        let cfg = RollConfig {
            path: path.as_ref().to_path_buf(),
            rolling_size,
            keep_days,
            compress_archive,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let state: LoggerState = Arc::new(LoggerStateInner::new());
        supervise_writer(
            tokio::spawn(writer::run(cfg, rx, state.clone(), None)),
            "access-log",
        );
        AccessLogger { tx, format, state }
    }

    /// [`AccessLogger::spawn`] plus a (Tier 2) syslog tap: every rendered line is
    /// ALSO framed as a syslog datagram and sent best-effort from the writer
    /// task. The request path is untouched either way.
    pub fn spawn_with_syslog(
        path: impl AsRef<Path>,
        format: LogFormat,
        rolling_size: u64,
        keep_days: u64,
        compress_archive: bool,
        syslog: Option<SyslogTap>,
    ) -> Self {
        let cfg = RollConfig {
            path: path.as_ref().to_path_buf(),
            rolling_size,
            keep_days,
            compress_archive,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let state: LoggerState = Arc::new(LoggerStateInner::new());
        supervise_writer(
            tokio::spawn(writer::run(cfg, rx, state.clone(), syslog)),
            "access-log",
        );
        AccessLogger { tx, format, state }
    }

    /// Queue a record for writing. Never blocks and never panics; if the writer
    /// task has stopped the record is silently dropped (logging must not take
    /// the request path down).
    ///
    /// The record is rendered to a line on the **writer task**, not here — the
    /// CLF-timestamp + `format!` + escape work stays off the request hot path; the
    /// caller only boxes the record and does a channel send.
    pub fn log(&self, record: AccessRecord) {
        self.log_with_extra(record, None);
    }

    /// Queue a record plus an optional continuation line emitted immediately after
    /// it (#248 logHeaders) — one channel message, so the pair can never mis-align.
    pub fn log_with_extra(&self, record: AccessRecord, extra: Option<String>) {
        send_or_warn(
            &self.tx,
            &self.state,
            Msg::Record(Box::new(record), self.format, extra),
            "access-log",
        );
    }

    /// Queue a pre-rendered line (escape/format already applied by the caller).
    pub fn log_line(&self, line: impl Into<String>) {
        send_or_warn(&self.tx, &self.state, Msg::Line(line.into()), "access-log");
    }

    /// (#349) Queue a block of pre-rendered newline-terminated lines (built
    /// with [`render_access_line_into`]) as ONE message. Sheds the whole
    /// chunk, line-accurately, when the writer queue is at its bound.
    pub fn log_chunk(&self, chunk: Vec<u8>, lines: u32) {
        if lines == 0 || chunk.is_empty() {
            return;
        }
        let lines64 = u64::from(lines);
        let msg = Msg::Chunk(chunk, lines);
        let bytes = msg.queued_bytes();
        if !self.state.admit(lines64, bytes) {
            return;
        }
        if self.tx.send(msg).is_err() {
            self.state.writer_gone(lines64, bytes, "access-log");
        }
    }

    /// Request that the writer re-open the log file. Use from a SIGUSR1 handler
    /// or after `logrotate` moves the file. Non-blocking.
    pub fn reopen(&self) {
        let _ = self.tx.send(Msg::Reopen);
    }

    /// The active line format.
    pub fn format(&self) -> LogFormat {
        self.format
    }

    /// Number of records shed because the writer queue was full or gone.
    pub fn dropped_lines(&self) -> u64 {
        self.state.dropped.load(Ordering::Relaxed)
    }

    /// Flush all queued records and stop the writer task. Awaiting this returns
    /// once everything queued before the call has hit disk.
    pub async fn shutdown(self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(Msg::Shutdown(ack_tx)).is_ok() {
            let _ = ack_rx.await;
        }
    }
}

/// Severity tag for error-log lines, matching LiteSpeed's level names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Notice,
    Warn,
    Error,
}

impl LogLevel {
    /// The bracketed tag written to the log, e.g. `NOTICE`.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Notice => "NOTICE",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// Async error/stderr appender, sharing the rolling writer used by the access
/// logger. Emits `2026-05-31 13:55:36.000000 [LEVEL] message` lines.
#[derive(Clone)]
pub struct ErrorLogger {
    format: ErrorLogFormat,
    tx: mpsc::UnboundedSender<Msg>,
    /// Per-logger state: `(depth, gone)` (see [`AccessLogger`]).
    state: LoggerState,
}

/// Error-file format. Text preserves the historical output byte for byte.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ErrorLogFormat {
    #[default]
    Text,
    Json,
}

impl ErrorLogger {
    /// Spawn an error-log writer task. Parameters mirror
    /// [`AccessLogger::spawn`] (minus the line format).
    pub fn spawn(
        path: impl AsRef<Path>,
        rolling_size: u64,
        keep_days: u64,
        compress_archive: bool,
    ) -> Self {
        let format = match std::env::var("HTTPJET_ERROR_LOG_FORMAT").as_deref() {
            Ok("json") => ErrorLogFormat::Json,
            Ok("text") | Err(_) => ErrorLogFormat::Text,
            Ok(_) => {
                eprintln!(
                    "httpjet: invalid HTTPJET_ERROR_LOG_FORMAT; expected text or json, using text"
                );
                ErrorLogFormat::Text
            }
        };
        Self::spawn_with_format(path, rolling_size, keep_days, compress_archive, format)
    }

    pub fn spawn_with_format(
        path: impl AsRef<Path>,
        rolling_size: u64,
        keep_days: u64,
        compress_archive: bool,
        format: ErrorLogFormat,
    ) -> Self {
        let cfg = RollConfig {
            path: path.as_ref().to_path_buf(),
            rolling_size,
            keep_days,
            compress_archive,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let state: LoggerState = Arc::new(LoggerStateInner::new());
        supervise_writer(
            tokio::spawn(writer::run(cfg, rx, state.clone(), None)),
            "error-log",
        );
        ErrorLogger { tx, state, format }
    }

    /// Log a message at `level` using `SystemTime::now()` as the timestamp.
    pub fn log(&self, level: LogLevel, msg: impl AsRef<str>) {
        self.log_at(level, SystemTime::now(), msg);
    }

    /// Log a message with an explicit timestamp (deterministic; used in tests).
    pub fn log_at(&self, level: LogLevel, ts: SystemTime, msg: impl AsRef<str>) {
        if self.format == ErrorLogFormat::Json {
            self.structured_at(level, ts, None, msg.as_ref(), &[]);
            return;
        }
        let line = format!(
            "{} [{}] {}",
            fmt::error_time(ts),
            level.as_str(),
            sanitize_msg(msg.as_ref()),
        );
        send_or_warn(&self.tx, &self.state, Msg::Line(line), "error-log");
    }

    pub(crate) fn is_json(&self) -> bool {
        self.format == ErrorLogFormat::Json
    }

    pub(crate) fn structured_at(
        &self,
        level: LogLevel,
        ts: SystemTime,
        target: Option<&str>,
        message: &str,
        fields: &[(String, String)],
    ) {
        let line = error_json::render(level, ts, target, message, fields);
        send_or_warn(&self.tx, &self.state, Msg::Line(line), "error-log");
    }

    /// Append a captured backend `stderr` line verbatim at `INFO` level. Embedded
    /// newlines are turned into separate records so each line is timestamped.
    pub fn capture_stderr(&self, raw: impl AsRef<str>) {
        for chunk in raw.as_ref().split('\n') {
            let chunk = chunk.trim_end_matches('\r');
            if !chunk.is_empty() {
                self.log(LogLevel::Info, chunk);
            }
        }
    }

    /// Re-open the underlying file (logrotate / SIGUSR1). Non-blocking.
    pub fn reopen(&self) {
        let _ = self.tx.send(Msg::Reopen);
    }

    /// Number of records shed because the writer queue was full or gone.
    pub fn dropped_lines(&self) -> u64 {
        self.state.dropped.load(Ordering::Relaxed)
    }

    /// Flush and stop the writer task.
    pub async fn shutdown(self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(Msg::Shutdown(ack_tx)).is_ok() {
            let _ = ack_rx.await;
        }
    }
}

/// Keep error messages to a single physical line.
fn sanitize_msg(s: &str) -> String {
    s.replace('\r', "").replace('\n', " ")
}

#[cfg(test)]
mod json_render_tests {
    use super::*;

    #[test]
    fn json_line_is_valid_shape_and_escapes_quotes() {
        let mut out = Vec::new();
        render_access_line_into(
            &mut out,
            LogFormat::Json,
            "203.0.113.9".parse().unwrap(),
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            "GET",
            "/a?b=\"x\"",
            Some("c=d"),
            "HTTP/2",
            200,
            12,
            None,
            Some(b"Mozilla \"quoted\""),
            Some(&1u64),
            false,
        );
        let line = String::from_utf8(out).unwrap();
        assert!(line.starts_with("{\"ts\":\""));
        assert!(line.contains("\"method\":\"GET\""));
        assert!(line.contains("\"status\":200"));
        assert!(line.contains("\"bytes\":12"));
        assert!(line.contains("\"referer\":null"));
        let bslash = char::from(92);
        let expected_uri = [
            bslash.to_string(),
            String::from("\""),
            "x".to_string(),
            bslash.to_string(),
            String::from("\""),
        ]
        .join("");
        assert!(
            line.contains(&expected_uri),
            "quotes inside the query value are escaped: {line}"
        );
        assert!(line.ends_with("}\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn sample() -> AccessRecord {
        AccessRecord {
            client_ip: "203.0.113.7".parse().unwrap(),
            ts: UNIX_EPOCH + Duration::from_secs(971_186_136), // 2000-10-10T13:55:36Z
            method: "GET".into(),
            uri: "/index.html?x=1".into(),
            protocol: "HTTP/1.1".into(),
            status: 200,
            bytes: 2326,
            referer: Some("https://example.com/start".into()),
            user_agent: Some("Mozilla/5.0".into()),
            host: Some("example.com".into()),
            remote_user: None,
            request_id: None,
            peer_unix: false,
        }
    }

    #[test]
    fn combined_exact() {
        let r = sample();
        assert_eq!(
            r.render(LogFormat::Combined),
            "203.0.113.7 - - [10/Oct/2000:13:55:36 +0000] \"GET /index.html?x=1 HTTP/1.1\" 200 2326 \"https://example.com/start\" \"Mozilla/5.0\""
        );
    }

    #[test]
    fn common_exact() {
        let r = sample();
        assert_eq!(
            r.render(LogFormat::Common),
            "203.0.113.7 - - [10/Oct/2000:13:55:36 +0000] \"GET /index.html?x=1 HTTP/1.1\" 200 2326"
        );
    }

    #[test]
    fn request_id_appended_when_present() {
        let mut r = sample();
        r.request_id = Some("00000000deadbeef".into());
        // Trailing token in both formats; absent in the None case (the exact tests above).
        assert!(
            r.render(LogFormat::Common)
                .ends_with(" reqid=00000000deadbeef")
        );
        assert!(
            r.render(LogFormat::Combined)
                .ends_with(" reqid=00000000deadbeef")
        );
    }

    #[test]
    fn remote_user_rendered() {
        let mut r = sample();
        r.remote_user = Some("alice".into());
        // OLS `AccessLog::log` quotes the user: ` - "alice" [`.
        assert!(
            r.render(LogFormat::Common)
                .starts_with("203.0.113.7 - \"alice\" [")
        );
    }

    #[test]
    fn missing_headers_become_dash() {
        let mut r = sample();
        r.referer = None;
        r.user_agent = None;
        assert!(
            r.render(LogFormat::Combined)
                .ends_with("200 2326 \"-\" \"-\"")
        );
    }

    #[test]
    fn injection_is_escaped() {
        let mut r = sample();
        r.user_agent = Some("evil\" 500 0 \"\ninjected".into());
        let line = r.render(LogFormat::Combined);
        // exactly one line, quotes/newlines neutralized
        assert_eq!(line.lines().count(), 1);
        assert!(line.contains("\\\""));
        assert!(line.contains("\\n"));
        assert!(!line.contains("injected\n"));
    }

    #[test]
    fn error_line_format() {
        let ts = UNIX_EPOCH + Duration::new(971_186_136, 0);
        let line = format!(
            "{} [{}] {}",
            fmt::error_time(ts),
            LogLevel::Notice.as_str(),
            sanitize_msg("server\nstarted"),
        );
        assert_eq!(line, "2000-10-10 13:55:36.000000 [NOTICE] server started");
    }

    #[test]
    fn shed_lines_increment_drop_counter() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let state = Arc::new(LoggerStateInner::new());
        state.depth.store(MAX_QUEUED_LINES, Ordering::Relaxed);
        send_or_warn(&tx, &state, Msg::Line("dropped".into()), "access-log");
        assert_eq!(state.dropped.load(Ordering::Relaxed), 1);
        assert!(
            rx.try_recv().is_err(),
            "shed line must not enter the writer queue"
        );
    }

    /// Regression (#1142): the backlog is bounded in bytes as well as lines, so
    /// oversized records stop queueing at the byte budget long before the line
    /// cap, and every shed record is counted.
    #[test]
    fn byte_budget_sheds_oversized_backlog() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let state = Arc::new(LoggerStateInner::new());
        // An 8 KiB URI and 16 KiB of logged headers, as a hostile request can send.
        let big = || {
            let mut record = sample();
            record.uri = String::with_capacity(8 * 1024);
            record.uri.push('/');
            record.user_agent = Some(Vec::with_capacity(16 * 1024));
            Msg::Record(Box::new(record), LogFormat::Combined, None)
        };
        let charge = big().queued_bytes();
        assert!(charge > 24 * 1024, "{charge}");
        let sent = 4096_u64;
        for _ in 0..sent {
            send_or_warn(&tx, &state, big(), "access-log");
        }
        let mut queued = 0_u64;
        while rx.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, MAX_QUEUED_BYTES / charge);
        assert_eq!(state.depth.load(Ordering::Relaxed), queued);
        assert_eq!(state.queued_bytes.load(Ordering::Relaxed), queued * charge);
        assert_eq!(state.dropped.load(Ordering::Relaxed), sent - queued);

        // A chunk is charged by its capacity and shed whole, line-accurately.
        let state = Arc::new(LoggerStateInner::new());
        let logger = AccessLogger {
            tx,
            format: LogFormat::Common,
            state: state.clone(),
        };
        let chunk = 4 * 1024 * 1024;
        for _ in 0..MAX_QUEUED_BYTES / chunk as u64 {
            logger.log_chunk(vec![0; chunk], 7);
        }
        assert_eq!(state.dropped.load(Ordering::Relaxed), 0);
        logger.log_chunk(vec![0; chunk], 7);
        assert_eq!(state.dropped.load(Ordering::Relaxed), 7);
        assert_eq!(state.queued_bytes.load(Ordering::Relaxed), MAX_QUEUED_BYTES);
    }

    /// The writer releases exactly what was charged, so a drained backlog reads 0.
    #[tokio::test]
    async fn writer_releases_the_byte_charge() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("hj-log-bytes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let logger = AccessLogger::spawn(dir.join("access.log"), LogFormat::Combined, 0, 0, false);
        let state = logger.state.clone();
        for _ in 0..100 {
            logger.log(sample());
            logger.log_line("pre-rendered");
            logger.log_with_extra(sample(), Some("continuation".into()));
            logger.log_chunk(b"one\ntwo\n".to_vec(), 2);
        }
        logger.shutdown().await;
        assert_eq!(state.queued_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(state.depth.load(Ordering::Relaxed), 0);
        assert_eq!(state.dropped.load(Ordering::Relaxed), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// (#349) The borrowed chunk renderer must produce BYTE-IDENTICAL lines to
    /// AccessRecord::render (plus the trailing newline) for both formats.
    #[test]
    fn borrowed_render_matches_record_render() {
        let ts = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_766_000_000);
        for format in [
            LogFormat::Common,
            LogFormat::Combined,
            LogFormat::CombinedHost,
            LogFormat::Headers(LOG_VHOST),
            LogFormat::Headers(LOG_USERAGENT | LOG_VHOST),
            LogFormat::Json,
        ] {
            for (query, referer, ua, reqid) in [
                (None, None, None, None),
                (
                    Some("a=1&b=%22x"),
                    Some("https://ref.example/\"q"),
                    Some("UA/1.0 (X11; \u{7f}) caf\u{e9}"),
                    Some("00ffab12cd34ef56"),
                ),
            ] {
                let uri = match query {
                    Some(q) => format!("/p/th%20x?{q}"),
                    None => "/p/th%20x".to_string(),
                };
                let record = AccessRecord {
                    client_ip: "203.0.113.9".parse().unwrap(),
                    ts,
                    method: std::borrow::Cow::Borrowed("GET"),
                    uri,
                    protocol: "HTTP/2",
                    status: 200,
                    bytes: 1234,
                    referer: referer.map(|v: &str| v.as_bytes().to_vec()),
                    user_agent: ua.map(|v: &str| v.as_bytes().to_vec()),
                    host: reqid.map(|_| b"forum.example".to_vec()),
                    remote_user: reqid.map(|_| "alice".to_string()),
                    request_id: reqid.map(str::to_string),
                    peer_unix: false,
                };
                let mut expected = record.render(format).into_bytes();
                expected.push(b'\n');
                let mut got = Vec::new();
                let id_disp = reqid.map(|r| r.to_string());
                render_access_line_with_host_into(
                    &mut got,
                    format,
                    record.client_ip,
                    ts,
                    "GET",
                    "/p/th%20x",
                    query,
                    "HTTP/2",
                    200,
                    1234,
                    referer.map(str::as_bytes),
                    ua.map(str::as_bytes),
                    reqid.map(|_| &b"forum.example"[..]),
                    reqid.map(|_| "alice"),
                    id_disp.as_ref().map(|s| s as &dyn std::fmt::Display),
                    false,
                );
                assert_eq!(
                    String::from_utf8_lossy(&got),
                    String::from_utf8_lossy(&expected),
                    "format {format:?} query {query:?}"
                );
            }
        }
        // #633: JSON + peer_unix must also match AccessRecord (unix:, remote_user).
        let record = AccessRecord {
            client_ip: "127.0.0.1".parse().unwrap(),
            ts,
            method: std::borrow::Cow::Borrowed("GET"),
            uri: "/uds".to_string(),
            protocol: "HTTP/1.1",
            status: 200,
            bytes: 5,
            referer: None,
            user_agent: None,
            host: None,
            remote_user: None,
            request_id: None,
            peer_unix: true,
        };
        let mut expected = record.render(LogFormat::Json).into_bytes();
        expected.push(b'\n');
        let mut got = Vec::new();
        render_access_line_into(
            &mut got,
            LogFormat::Json,
            record.client_ip,
            ts,
            "GET",
            "/uds",
            None,
            "HTTP/1.1",
            200,
            5,
            None,
            None,
            None,
            true,
        );
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&expected)
        );
    }

    #[test]
    fn combined_host_appends_the_host_field() {
        // LiteSpeed logHeaders bit 4 (LOG_VHOST): Host follows the User-Agent (#825).
        let record = AccessRecord {
            client_ip: "203.0.113.9".parse().unwrap(),
            ts: SystemTime::UNIX_EPOCH,
            method: std::borrow::Cow::Borrowed("GET"),
            uri: "/".into(),
            protocol: "HTTP/2",
            status: 200,
            bytes: 1,
            referer: None,
            user_agent: Some("UA".into()),
            host: Some("forum.example".into()),
            remote_user: None,
            request_id: Some("ab".into()),
            peer_unix: false,
        };
        assert!(
            record
                .render(LogFormat::CombinedHost)
                .ends_with("\"-\" \"UA\" \"forum.example\" reqid=ab")
        );
        assert!(!record.render(LogFormat::Combined).contains("forum.example"));
    }

    /// Prod runs `logHeaders` 3 and 7: both must render byte-for-byte as before
    /// the per-bit selection existed (#917).
    #[test]
    fn log_headers_three_and_seven_are_byte_identical() {
        let r = sample();
        assert_eq!(LogFormat::from_log_headers(3), LogFormat::Combined);
        assert_eq!(LogFormat::from_log_headers(7), LogFormat::CombinedHost);
        assert_eq!(
            r.render(LogFormat::from_log_headers(3)),
            r#"203.0.113.7 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html?x=1 HTTP/1.1" 200 2326 "https://example.com/start" "Mozilla/5.0""#
        );
        assert_eq!(
            r.render(LogFormat::from_log_headers(7)),
            r#"203.0.113.7 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html?x=1 HTTP/1.1" 200 2326 "https://example.com/start" "Mozilla/5.0" "example.com""#
        );
    }

    #[test]
    fn log_headers_bits_select_each_field() {
        let r = sample();
        let head = r#"203.0.113.7 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html?x=1 HTTP/1.1" 200 2326"#;
        let cases: [(u8, &str); 8] = [
            (0, ""),
            (1, r#" "https://example.com/start""#),
            (2, r#" "Mozilla/5.0""#),
            (3, r#" "https://example.com/start" "Mozilla/5.0""#),
            (4, r#" "example.com""#),
            (5, r#" "https://example.com/start" "example.com""#),
            (6, r#" "Mozilla/5.0" "example.com""#),
            (
                7,
                r#" "https://example.com/start" "Mozilla/5.0" "example.com""#,
            ),
        ];
        for (mask, fields) in cases {
            assert_eq!(
                r.render(LogFormat::from_log_headers(mask)),
                format!("{head}{fields}"),
                "logHeaders={mask}"
            );
        }
        assert_eq!(LogFormat::from_log_headers(0), LogFormat::Common);
    }

    #[test]
    fn zero_body_bytes_render_dash_in_text_and_zero_in_json() {
        let mut r = sample();
        r.bytes = 0;
        assert!(
            r.render(LogFormat::Common)
                .ends_with(r#""GET /index.html?x=1 HTTP/1.1" 200 -"#)
        );
        assert!(r.render(LogFormat::Combined).contains(r#"" 200 - "https"#));
        assert!(r.render(LogFormat::Json).contains(r#""bytes":0,"#));
    }

    #[test]
    fn non_ascii_headers_are_escaped_not_dropped() {
        let mut r = sample();
        r.user_agent = Some(b"caf\xc3\xa9 \xff\"x\\".to_vec());
        r.referer = Some(b"https://r.example/\xe9".to_vec());
        r.host = Some(b"h\xc3\xb6st.example".to_vec());
        let line = r.render(LogFormat::CombinedHost);
        assert!(
            line.ends_with(
                r#" "https://r.example/\xe9" "caf\xc3\xa9 \xff\"x\\" "h\xc3\xb6st.example""#
            ),
            "{line}"
        );
        let json = r.render(LogFormat::Json);
        assert!(
            json.contains("\"user_agent\":\"caf\u{e9} \\\\xff\\\"x\\\\\""),
            "{json}"
        );
        assert!(
            json.contains(r#""referer":"https://r.example/\\xe9""#),
            "{json}"
        );
        let mut borrowed = Vec::new();
        render_access_line_with_host_into(
            &mut borrowed,
            LogFormat::CombinedHost,
            r.client_ip,
            r.ts,
            "GET",
            "/index.html",
            Some("x=1"),
            "HTTP/1.1",
            200,
            2326,
            r.referer.as_deref(),
            r.user_agent.as_deref(),
            r.host.as_deref(),
            None,
            None,
            false,
        );
        assert_eq!(String::from_utf8(borrowed).unwrap(), format!("{line}\n"));
    }

    #[test]
    fn remote_user_is_quoted_and_escaped_like_ols() {
        let mut r = sample();
        r.remote_user = Some("bob \"x\" caf\u{e9}".into());
        assert!(
            r.render(LogFormat::Combined)
                .starts_with(r#"203.0.113.7 - "bob \"x\" caf\xc3\xa9" ["#)
        );
        assert!(
            r.render(LogFormat::Json)
                .contains("\"remote_user\":\"bob \\\"x\\\" caf\u{e9}\"")
        );
    }
}
