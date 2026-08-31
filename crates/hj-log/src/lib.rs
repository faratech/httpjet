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
//! format. `logHeaders=7` in LiteSpeed corresponds to [`LogFormat::Combined`]
//! (Referer + User-Agent appended).
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

/// Per-logger state shared between the logger handle and any supervisory code:
/// the in-flight line depth counter and a gone-flag that fires exactly once when
/// the writer task disappears. Stored per-logger (not process-wide) so that two
/// independent loggers each track their own liveness independently — a dead
/// error-log writer does not suppress the gone warning for the access-log writer.
pub(crate) struct LoggerStateInner {
    pub depth: AtomicU64,
    pub gone: AtomicBool,
    pub dropped: AtomicU64,
}

impl LoggerStateInner {
    fn new() -> Self {
        LoggerStateInner {
            depth: AtomicU64::new(0),
            gone: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
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
/// `state.0` tracks the in-flight line backlog: count BEFORE sending (so the
/// writer's per-line decrement can never underflow it), and shed past
/// `MAX_QUEUED_LINES` so a stalled writer can't grow the queue without bound.
/// `state.1` is set once when the channel send fails (writer gone).
fn send_or_warn(tx: &mpsc::UnboundedSender<Msg>, state: &LoggerState, msg: Msg, what: &str) {
    if state.depth.load(Ordering::Relaxed) >= MAX_QUEUED_LINES {
        state.dropped.fetch_add(1, Ordering::Relaxed);
        return; // shed: writer backlogged at the cap — drop rather than risk OOM
    }
    state.depth.fetch_add(1, Ordering::Relaxed);
    if tx.send(msg).is_err() {
        state.depth.fetch_sub(1, Ordering::Relaxed);
        state.dropped.fetch_add(1, Ordering::Relaxed);
        if !state.gone.swap(true, Ordering::Relaxed) {
            // The writer will never drain again, so any lines that were still queued
            // when it died keep their never-decremented `depth` charge. Reset the
            // gauge to 0 the first time we notice — else stale charge can pin `depth`
            // at the shed cap and the count stops reflecting reality.
            state.depth.store(0, Ordering::Relaxed);
            eprintln!("hj-log: {what} writer task gone; subsequent {what} lines are dropped");
        }
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
    /// (LiteSpeed `logHeaders=7`).
    Combined,
    /// (Tier 2) One JSON object per line — structured logging for log shippers.
    /// Field order is fixed; absent optionals render as `null`.
    Json,
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
    /// `Referer` header, if present (combined format only).
    pub referer: Option<String>,
    /// `User-Agent` header, if present (combined format only).
    pub user_agent: Option<String>,
    /// `Host` header / vhost — retained for vhost-keyed splitting by callers.
    pub host: Option<String>,
    /// Authenticated remote user (the `%u` field), if any.
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
        use std::fmt::Write;
        if format == LogFormat::Json {
            let null = |v: Option<&str>| {
                v.map(|s| format!("\"{}\"", json_escape(s)))
                    .unwrap_or_else(|| "null".into())
            };
            let reqid = self
                .request_id
                .as_deref()
                .map(|id| format!("\"{}\"", json_escape(id)))
                .unwrap_or_else(|| "null".into());
            let client = if self.peer_unix {
                "unix:".to_string()
            } else {
                self.client_ip.to_string()
            };
            return format!(
                "{{\"ts\":\"{}\",\"client_ip\":\"{}\",\"remote_user\":{},\"method\":\"{}\",\"uri\":\"{}\",\"protocol\":\"{}\",\"status\":{},\"bytes\":{},\"referer\":{},\"user_agent\":{},\"reqid\":{}}}",
                fmt::clf_time(self.ts),
                json_escape(&client),
                null(self.remote_user.as_deref()),
                json_escape(&self.method),
                json_escape(&self.uri),
                json_escape(self.protocol),
                self.status,
                self.bytes,
                null(self.referer.as_deref()),
                null(self.user_agent.as_deref()),
                reqid,
            );
        }
        let client_field = if self.peer_unix {
            Cow::Borrowed("unix:")
        } else {
            Cow::Owned(self.client_ip.to_string())
        };
        let mut line = format!(
            "{} - {} [{}] \"{} {} {}\" {} {}",
            client_field,
            field_or_dash(self.remote_user.as_deref()),
            fmt::clf_time(self.ts),
            escape(&self.method),
            escape(&self.uri),
            escape(self.protocol),
            self.status,
            self.bytes,
        );
        if format == LogFormat::Combined {
            // Append directly into `line` rather than format!-ing a second String
            // and copying it in (one fewer allocation per combined line on the
            // writer task). `write!` to a String is infallible.
            let _ = write!(
                line,
                " \"{}\" \"{}\"",
                quoted_field(self.referer.as_deref()),
                quoted_field(self.user_agent.as_deref()),
            );
        }
        if let Some(id) = self.request_id.as_deref() {
            // Trailing token in both formats so the line is joinable with the
            // error/php-slow logs; absent ⇒ nothing appended (legacy layout).
            let _ = write!(line, " reqid={}", escape(id));
        }
        line
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
    referer: Option<&str>,
    user_agent: Option<&str>,
    request_id: Option<&dyn std::fmt::Display>,
    peer_unix: bool,
) {
    use std::io::Write;
    if format == LogFormat::Json {
        let je = |v: &str| json_escape(v);
        let jopt = |v: Option<&str>| {
            v.map(|s| format!("\"{}\"", je(s)))
                .unwrap_or_else(|| "null".to_string())
        };
        let mut line = String::with_capacity(192);
        line.push_str("{\"ts\":\"");
        line.push_str(&je(&fmt::clf_time(ts)));
        line.push_str("\",\"client_ip\":\"");
        line.push_str(&je(&client_ip.to_string()));
        line.push_str("\",\"method\":\"");
        line.push_str(&je(method));
        line.push_str("\",\"uri\":\"");
        line.push_str(&je(path));
        if let Some(q) = query {
            line.push('?');
            line.push_str(&je(q));
        }
        line.push_str("\",\"protocol\":\"");
        line.push_str(&je(protocol));
        line.push_str("\",\"status\":");
        line.push_str(&status.to_string());
        line.push_str(",\"bytes\":");
        line.push_str(&bytes.to_string());
        line.push_str(",\"referer\":");
        line.push_str(&jopt(referer));
        line.push_str(",\"user_agent\":");
        line.push_str(&jopt(user_agent));
        line.push_str(",\"reqid\":");
        line.push_str(&jopt(request_id.map(|d| d.to_string()).as_deref()));
        line.push('}');
        line.push('\n');
        out.extend_from_slice(line.as_bytes());
        return;
    }
    if peer_unix {
        let _ = write!(out, "unix: - - [{}] \"", fmt::clf_time(ts));
    } else {
        let _ = write!(out, "{} - - [{}] \"", client_ip, fmt::clf_time(ts));
    }
    let _ = write!(out, "{} ", escape(method));
    let _ = write!(out, "{}", escape(path));
    if let Some(q) = query {
        let _ = write!(out, "?{}", escape(q));
    }
    let _ = write!(out, " {}\" {} {}", escape(protocol), status, bytes);
    if format == LogFormat::Combined {
        let _ = write!(
            out,
            " \"{}\" \"{}\"",
            quoted_field(referer),
            quoted_field(user_agent),
        );
    }
    if let Some(id) = request_id {
        let _ = write!(out, " reqid={}", id);
    }
    out.push(b'\n');
}

/// Unquoted optional field: render `-` when absent/empty (the `%l`/`%u` fields).
fn field_or_dash(v: Option<&str>) -> Cow<'_, str> {
    match v {
        Some(s) if !s.is_empty() => escape(s),
        _ => Cow::Borrowed("-"),
    }
}

/// Quoted optional header value: absent -> `-` (so it reads `"-"`).
fn quoted_field(v: Option<&str>) -> Cow<'_, str> {
    match v {
        Some(s) if !s.is_empty() => escape(s),
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
        if self.state.depth.load(Ordering::Relaxed) + lines64 > MAX_QUEUED_LINES {
            self.state.dropped.fetch_add(lines64, Ordering::Relaxed);
            return;
        }
        self.state.depth.fetch_add(lines64, Ordering::Relaxed);
        if self.tx.send(Msg::Chunk(chunk, lines)).is_err() {
            self.state.depth.fetch_sub(lines64, Ordering::Relaxed);
            self.state.dropped.fetch_add(lines64, Ordering::Relaxed);
            if !self.state.gone.swap(true, Ordering::Relaxed) {
                self.state.depth.store(0, Ordering::Relaxed);
                eprintln!("hj-log: access-log writer task gone; subsequent lines are dropped");
            }
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
    tx: mpsc::UnboundedSender<Msg>,
    /// Per-logger state: `(depth, gone)` (see [`AccessLogger`]).
    state: LoggerState,
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
        ErrorLogger { tx, state }
    }

    /// Log a message at `level` using `SystemTime::now()` as the timestamp.
    pub fn log(&self, level: LogLevel, msg: impl AsRef<str>) {
        self.log_at(level, SystemTime::now(), msg);
    }

    /// Log a message with an explicit timestamp (deterministic; used in tests).
    pub fn log_at(&self, level: LogLevel, ts: SystemTime, msg: impl AsRef<str>) {
        let line = format!(
            "{} [{}] {}",
            fmt::error_time(ts),
            level.as_str(),
            sanitize_msg(msg.as_ref()),
        );
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
            Some("Mozilla \"quoted\""),
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
        assert!(
            r.render(LogFormat::Common)
                .starts_with("203.0.113.7 - alice [")
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

    /// (#349) The borrowed chunk renderer must produce BYTE-IDENTICAL lines to
    /// AccessRecord::render (plus the trailing newline) for both formats.
    #[test]
    fn borrowed_render_matches_record_render() {
        let ts = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_766_000_000);
        for format in [LogFormat::Common, LogFormat::Combined] {
            for (query, referer, ua, reqid) in [
                (None, None, None, None),
                (
                    Some("a=1&b=%22x"),
                    Some("https://ref.example/\"q"),
                    Some("UA/1.0 (X11; \u{7f})"),
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
                    referer: referer.map(str::to_string),
                    user_agent: ua.map(str::to_string),
                    host: None,
                    remote_user: None,
                    request_id: reqid.map(str::to_string),
                    peer_unix: false,
                };
                let mut expected = record.render(format).into_bytes();
                expected.push(b'\n');
                let mut got = Vec::new();
                let id_disp = reqid.map(|r| r.to_string());
                render_access_line_into(
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
                    referer,
                    ua,
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
    }
}
