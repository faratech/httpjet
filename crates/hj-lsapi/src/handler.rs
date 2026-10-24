//! The [`Lsapi`] [`Handler`]: dispatch an HTTP request to lsphp over LSAPI and
//! stream the response back without buffering (`respBuffer = 0`).
//!
//! Flow per request:
//! 1. Resolve `SCRIPT_FILENAME` (caller-supplied) and build the CGI env.
//! 2. Enforce `max_body` from the declared `Content-Length` BEFORE acquiring a
//!    connection (early 413 with no pool churn).
//! 3. Acquire a pooled UDS connection and send a BEGIN_REQUEST packet whose
//!    `m_reqBodyLen` carries a CONCRETE length, then STREAM the raw body bytes
//!    after it (we do not buffer the whole body in RAM).
//!    - Content-Length present: split the conn and run a body-writer task and the
//!      response-reader task concurrently (full duplex; never await the writer
//!      before reading the first response packet — lsphp may reply before it has
//!      drained the body, and its write buffer can fill while we push).
//!    - No Content-Length (chunked): buffer-to-cap to learn the length, send it as
//!      a concrete `m_reqBodyLen` plus a synthetic `Content-Length` header, then
//!      write the buffered bytes.
//! 4. Read RESP_HEADER -> build `http::Response`. Then stream RESP_STREAM packets
//!    into a `Body::Stream` and terminate on RESP_END. STDERR_STREAM packets are
//!    routed to `tracing` (the error log).
//! 5. If the client disconnects mid-stream, the body exceeds the declared length
//!    mid-stream, or the body errors, the connection is ABANDONED: we shut down
//!    the write half (closing the socket write direction so lsphp's body read
//!    returns short and the request fails fast) and poison the guard so the
//!    socket is never re-pooled. We do NOT write an ABORT_REQUEST control frame
//!    into the raw body byte stream — lsphp reads the bytes after BEGIN_REQUEST
//!    as RAW body content (see `LSAPI_ReadReqBody_r` in vendor/lsapilib.c, which
//!    reads exactly `m_reqBodyLen` bytes straight off the fd) and has NO
//!    ABORT_REQUEST consumer, so such a frame would only splice 8 garbage bytes
//!    into the body PHP receives.
//!
//! ## Body-length contract (verified against vendor/lsapilib.c)
//! BEGIN_REQUEST declares a CONCRETE `m_reqBodyLen` and lsphp reads EXACTLY that
//! many raw bytes off the socket. The streaming pump therefore MUST write exactly
//! `body_len` bytes:
//!   - fewer (under-delivery): lsphp blocks on the missing bytes; we never finish
//!     the body cleanly, so we poison + shut the write half.
//!   - more (over-delivery): lsphp reads only `body_len` and treats the surplus as
//!     the next LSAPI packet -> protocol desync on a reused socket. We stop at
//!     `body_len` and poison.
//!
//! Only an exact match deposits the write half, and even then a connection that
//! carried body bytes is closed rather than re-pooled after RESP_END (#833): a
//! body tail the script left unread is parsed by lsphp as a new request, whose
//! response would otherwise reach the next request on the socket. Any body PHP
//! is not known to read whole is written through `ScannedBodyWriter`, and one
//! that holds a request lsphp could run is refused with 400 before that request
//! is sent.
//!
//! ## Retry contract
//! [`Lsapi::handle`] reports a request as non-replayable once any byte has been
//! committed to the wire (BEGIN_REQUEST flushed or any body byte sent). Failures
//! *before* the first flush (pool-acquire timeout, connect error, BEGIN_REQUEST
//! write/flush error) are REPLAYABLE: with a [`Monitor`] attached the handler
//! nudges a restart, briefly awaits recovery, clears the pool, and retries ONCE.
//! If the supervisor is in `Bad` (backoff) the handler fails fast with
//! [`HandlerError::ServiceUnavailable`] (503). Post-flush failures surface as a
//! poisoned connection + aborted body stream and are NEVER replayed.
//!
//! ## Hung-request handling (Tier 1)
//! When a `max_process_time` is configured, the response read enforces it as a
//! TOTAL wall-clock deadline (in addition to the per-read idle `read_timeout`).
//! On expiry the connection is poisoned, our side is closed, and a 504 is
//! returned; lsphp notices on its next socket write. The monitor provides Tier 2
//! (SIGTERM→SIGKILL + master restart) for a worker wedged past the grace window.

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::channel::{Channel, Sender};
use http_body_util::combinators::BoxBody;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use hj_core::{Body, BoxError, Handler, HandlerError, ReqCtx, Request, Response};

use crate::body_writer::{BodyWriteError, ScannedBodyWriter};
use crate::cgi::CgiEnvBuilder;
use crate::monitor::{InFlightGuard, Monitor};
use crate::pool::{DialAdmission, LsapiPool, ResponseBodyPath, ReturnGuard, TrialGuard};
use crate::proto::{
    ENDIAN_BIT, HOST_LSAPI_ENDIAN, LsapiFrame, PACKET_HEADER_LEN, PacketType, RespHeader,
    SpecialEnvType, VERSION_B0, VERSION_B1, WireHeader, build_begin_request_framed_into,
};
use crate::supervisor::WorkerState;

/// Cap on how long the handler waits for the worker to recover before retrying a
/// pre-flush failure (min of this and the pool's init timeout is used).
const RECOVERY_WAIT_CAP: Duration = Duration::from_secs(2);

/// How many times an idempotent request is retried on a pre-response reset (a
/// recycling worker). 2 retries = up to 3 dispatches; bounded so a sustained
/// backend struggle can't amplify load unboundedly.
const IDEMPOTENT_RETRY_MAX: u32 = 2;

/// Largest PHP/LSAPI response body the read path will collect INLINE (into a
/// `Body::Full`) from packets already buffered after the header read, instead of
/// spawning the streaming pump. Bounds the inline buffering; anything larger (or
/// not fully buffered yet) falls back to the streaming channel. 64 KiB covers the
/// vast majority of dynamic pages while keeping a hard ceiling on inline memory.
// (#317a) Buffered-only inline ceiling: a response FULLY buffered after the header
// read returns Body::Full with no Channel + spawned pump. 256 KiB covers real page
// renders (the old 64 KiB streamed every large render despite it being entirely in
// the reader buffer). Memory stays bounded because draining never waits (try_parse
// plus at most INLINE_FILL_READS non-blocking reads) — dispatch NEVER awaits
// un-buffered body bytes (see the D1 barrier contract) — and
// declared-length truncation/over-delivery enforcement applies to the inlined body
// exactly as before.
const INLINE_BODY_CAP: usize = 256 * 1024;

/// Non-blocking socket reads the inline drain may add to complete a declared-length
/// body (#987): each takes up to a 64 KiB read buffer's spare room, so four cover
/// INLINE_BODY_CAP behind the header read.
const INLINE_FILL_READS: u32 = 4;

/// Largest single-chunk inline body copied out of its read buffer. A small copy
/// lands in a densely used size class and frees the pooled read buffer at once; a
/// larger body stays a zero-copy slice whose buffer returns to the pool when the
/// response is done (the page cache copies any body it keeps in RAM).
const INLINE_COPY_MAX: usize = 8 * 1024;

/// The first `len` bytes of `chunks` (`len` <= their total) as one `Bytes`.
fn inline_body(chunks: Vec<Bytes>, len: usize) -> Bytes {
    let mut chunks = chunks.into_iter();
    let Some(mut first) = chunks.next() else {
        return Bytes::new();
    };
    if first.len() >= len || chunks.as_slice().is_empty() {
        first.truncate(len);
        return if first.len() <= INLINE_COPY_MAX {
            Bytes::copy_from_slice(&first)
        } else {
            first
        };
    }
    let mut body = hj_core::BODY_BUFS.take_buf(len, hj_core::BODY_BUF_CAP);
    body.extend_from_slice(&first);
    for chunk in chunks {
        let take = (len - body.len()).min(chunk.len());
        body.extend_from_slice(chunk.get(..take).unwrap_or_default());
        if body.len() == len {
            break;
        }
    }
    hj_core::BODY_BUFS.freeze(body, hj_core::BODY_BUF_CAP)
}

/// Headers the pipeline typically adds to a PHP response after it is read.
const RESPONSE_HEADER_SLACK: usize = 12;

/// Short backoff before each idempotent-reset retry. During a recycle BURST the
/// first retry's fresh dial can ALSO re-hit a pool still mid-respawn; a brief pause
/// lets the recycle resolve / a fresh worker become available. Worst case
/// ~2×25ms = 50ms of added latency on a failing request.
const IDEMPOTENT_RETRY_BACKOFF: Duration = Duration::from_millis(25);
/// Largest POST body whose connection may be reused (#833): far below any sane
/// post_max_size, so PHP has always read it in full before the script runs.
const PREREAD_POST_MAX: i32 = 64 * 1024;

/// Whether PHP reads a POST of this Content-Type in full at request start: any
/// non-empty media type except `multipart/*`, whose rfc1867 handler reads lazily
/// and may stop early. The media type is cut where PHP's sapi_activate cuts it
/// (`;`, `,`, space), plus tab, so both sides see the same type.
fn php_preread_content_type(value: &[u8]) -> bool {
    let value = value.trim_ascii_start();
    let end = value
        .iter()
        .position(|&b| matches!(b, b';' | b',' | b' ' | b'\t'))
        .unwrap_or(value.len());
    let (media, _) = value.split_at(end);
    !media.is_empty()
        && !media
            .get(..10)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"multipart/"))
}

/// The header's value when it occurs exactly once: a repeated field could make
/// this gate and the value lsphp receives disagree.
fn single_header(
    headers: &http::HeaderMap,
    name: http::header::HeaderName,
) -> Option<&http::HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

#[cfg(test)]
mod preread_tests {
    #[test]
    fn multipart_post_is_never_assumed_preread() {
        // #835: rfc1867 reads lazily and stops early without a boundary.
        assert!(super::php_preread_content_type(
            b"application/x-www-form-urlencoded"
        ));
        assert!(super::php_preread_content_type(b"text/plain;charset=UTF-8"));
        assert!(!super::php_preread_content_type(b"multipart/form-data"));
        assert!(!super::php_preread_content_type(
            b" Multipart/Form-Data ; boundary=zz"
        ));
        assert!(!super::php_preread_content_type(b"  "));
        assert!(!super::php_preread_content_type(b";x=1"));
        // PHP cuts the media type at `,` and space too.
        assert!(!super::php_preread_content_type(b"multipart/form-data, x"));
        assert!(!super::php_preread_content_type(
            b"multipart/form-data boundary=zz"
        ));
        assert!(!super::php_preread_content_type(b"MULTIPART/mixed"));
    }

    #[test]
    fn repeated_content_type_is_not_trusted() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        assert!(super::single_header(&headers, http::header::CONTENT_TYPE).is_some());
        headers.append(
            http::header::CONTENT_TYPE,
            "multipart/form-data".parse().unwrap(),
        );
        assert!(super::single_header(&headers, http::header::CONTENT_TYPE).is_none());
    }
}

/// Per-request LSAPI timing breakdown, attached to the response's extensions so
/// the caller (telemetry) can split "waiting for a worker" from "actual render".
/// Distinguishes pool/worker CONTENTION (acquire, ttfb) — which more lsphp
/// workers would fix — from genuine PHP render time.
#[derive(Clone, Copy, Debug)]
pub struct LsapiTiming {
    /// Time spent acquiring a pooled lsphp connection (`pool.acquire`). A fat
    /// tail here = httpjet's connection pool is the bottleneck (raise the cap).
    pub acquire: Duration,
    /// Time from the request being committed (BEGIN_REQUEST flushed) to the first
    /// response byte (RESP_HEADER): lsphp worker pickup + render-to-first-byte. A
    /// fat tail with a SMALL `acquire` = lsphp workers are saturated (more workers).
    pub ttfb: Duration,
}

/// Attached to the response when the dispatch was RETRIED, so the pipeline's
/// php-slow log can attribute a slow TTFB to a retry (vs a first-attempt render).
/// Absent ⇒ first attempt succeeded. `kind` is `"preflush"` / `"idempotent_reset"`.
#[derive(Clone, Copy, Debug)]
pub struct LsapiRetryInfo {
    pub kind: &'static str,
}

/// Why a `Retry` was produced — selects the recovery action before each retry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RetryKind {
    /// Failure BEFORE the request was flushed (acquire / write / flush begin). The
    /// worker may be down, so recover (nudge a restart + clear stale sockets) first.
    PreFlush,
    /// A post-flush reset/EOF BEFORE any response byte, on an IDEMPOTENT request the
    /// client has seen nothing of. Covers both the stale-keep-alive race (a reused
    /// socket lsphp recycled) AND a fresh dial that reset during a recycle burst
    /// (the pool mid-respawn). Safe to replay on a fresh dial (NO restart); retried
    /// up to `IDEMPOTENT_RETRY_MAX` times with a short backoff so a burst can
    /// resolve, bounded so a real outage can't amplify load.
    IdempotentReset,
    /// BEGIN_REQUEST could not be written to a REUSED idle socket on a bodiless
    /// idempotent request: lsphp closed that keep-alive (idle/max-requests exit)
    /// and nothing was delivered. The backend is not implicated, so retry on a
    /// fresh dial at once — no restart nudge, no pool flush, no backoff.
    StaleReuse,
}

fn begin_failure_kind(bodiless_idempotent: bool, reused: bool) -> RetryKind {
    if bodiless_idempotent && reused {
        RetryKind::StaleReuse
    } else {
        RetryKind::PreFlush
    }
}

impl RetryKind {
    /// Stable label for the php-slow log's retry column (#133).
    fn as_log_str(self) -> &'static str {
        match self {
            RetryKind::PreFlush => "preflush",
            RetryKind::IdempotentReset => "idempotent_reset",
            RetryKind::StaleReuse => "stale_reuse",
        }
    }
}

/// If the dispatch succeeded AFTER one or more retries, stamp the response with
/// [`LsapiRetryInfo`] so the pipeline's php-slow log can attribute the TTFB to a
/// retry rather than a first-attempt render (#133). A first-attempt success or any
/// error is passed through unchanged.
fn tag_retry(
    r: Result<Response, HandlerError>,
    last_retry: Option<RetryKind>,
) -> Result<Response, HandlerError> {
    match (r, last_retry) {
        (Ok(mut resp), Some(kind)) => {
            resp.extensions_mut().insert(LsapiRetryInfo {
                kind: kind.as_log_str(),
            });
            Ok(resp)
        }
        (other, _) => other,
    }
}

/// Outcome of a single dispatch attempt. A `Retry` carries the replayable inputs
/// (env/headers/body) back out so the handler can retry on a fresh connection.
enum Attempt<B> {
    /// Response produced (or a terminal, non-replayable error inside it).
    Done(Result<Response, HandlerError>),
    /// Replayable failure: retry with the returned body. The pre-encoded
    /// BEGIN_REQUEST packet is owned by the `_retrying` loop and re-passed by
    /// reference, so only the body is carried back. `reason` is the error to
    /// surface if exhausted/blocked; `kind` selects the recovery action.
    Retry {
        body: B,
        reason: HandlerError,
        kind: RetryKind,
    },
}

/// A response-read failure tagged with whether it is safely retryable: a
/// connection death (reset / EOF) BEFORE any response byte, where the client has
/// seen nothing — so for an idempotent, bodyless request on a REUSED socket the
/// request can be replayed on a fresh dial. Everything else (a parse / internal /
/// build error, or a timeout — a hung worker a retry would only hang against
/// again) is terminal.
struct ReadFail {
    err: HandlerError,
    retryable: bool,
}

impl ReadFail {
    fn terminal(err: HandlerError) -> Self {
        ReadFail {
            err,
            retryable: false,
        }
    }
    fn retryable(err: HandlerError) -> Self {
        ReadFail {
            err,
            retryable: true,
        }
    }
}

/// A fresh empty request body for replaying a bodyless (GET/HEAD) request on a
/// stale-reuse retry — the original `IncomingBody` was moved into the first
/// attempt's body pump, and a bodyless request has nothing to replay anyway.
fn empty_incoming_body() -> hj_core::IncomingBody {
    use http_body_util::{BodyExt, Empty};
    Empty::<Bytes>::new()
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

/// `lease` rides inside the body so the buffered-body reservation lasts as long as
/// the detached pump still holds the bytes.
fn full_incoming_body(body: Bytes, lease: Option<Arc<BodyBufferLease>>) -> hj_core::IncomingBody {
    use http_body_util::{BodyExt, Full};
    Full::new(body)
        .map_frame(move |frame| {
            let _held = &lease;
            frame
        })
        .map_err(|e| Box::new(e) as BoxError)
        .boxed()
}

/// A buffered body up to this size is written inline before the response is read: it
/// fits the default AF_UNIX send buffer, so the write completes without lsphp reading
/// it. A larger one goes through the full-duplex streaming path (#806).
const BUFFERED_INLINE_WRITE_MAX: usize = 64 * 1024;

/// Request extension the pipeline inserts to pin an already-resolved
/// `SCRIPT_FILENAME` (e.g. a directory's `index.php`), so `REQUEST_URI` keeps
/// the original request path while `SCRIPT_FILENAME` points at the real script.
#[derive(Debug, Clone)]
pub struct LsapiScript {
    pub script: PathBuf,
    pub script_name: Option<String>,
    pub path_info: Option<String>,
    /// php.ini overrides from `.htaccess` (`php_value`/`php_admin_value`/`php_flag`/
    /// `php_admin_flag`), already resolved across the directory chain. These travel
    /// in the LSAPI **special-env** section (NOT the CGI env table) — lsphp's
    /// `alter_ini` is the only consumer, and it reads only special-env. `User`
    /// (`\x01\x02`) is applied PHP_INI_PERDIR (PHP rejects SYSTEM-level settings);
    /// `Admin` (`\x01\x04`) is PHP_INI_SYSTEM. See [`SpecialEnvType`].
    pub special_env: Vec<(SpecialEnvType, String, String)>,
}

/// LSAPI terminal handler. Construct one per lsphp socket (shared via `Arc`).
pub struct Lsapi {
    pool: Arc<LsapiPool>,
    /// How an incoming request URI path maps to a `SCRIPT_FILENAME` on disk.
    /// If `None`, `<doc_root><uri-path>` is used.
    script_root: Option<PathBuf>,
    /// Max request body to read into memory before sending (bytes).
    max_body: u64,
    /// Idle read timeout while waiting for lsphp output.
    read_timeout: Duration,
    /// Extra env appended to every request (PHP_VALUE/PHP_ADMIN_VALUE, ext env).
    base_env: Vec<(String, String)>,
    /// Resilience monitor: the single restart authority + in-flight tracker. When
    /// present the handler nudges restarts, retries pre-flush failures once, and
    /// brackets each request in the Tier 2 in-flight tracker.
    monitor: Option<Arc<Monitor>>,
    /// Retry a pre-flush failure once (only meaningful with a [`Monitor`]).
    retry: bool,
    /// Tier 1 total processing-time deadline across the response read. `None`
    /// disables it (only the per-read idle `read_timeout` applies).
    max_process_time: Option<Duration>,
    /// Server-wide cap on heap currently held by buffered (chunked / no-CL)
    /// request bodies (#236). Shared by every handler built from the registry.
    body_budget: Arc<BodyBufferBudget>,
}

/// Server-wide byte budget for request bodies that must be fully buffered into
/// heap before pool admission. Lives in hj-core so the io_uring transports share
/// the ONE instance (they commit body bytes before this handler ever runs); see
/// `hj_core::budget`.
pub use hj_core::budget::{BodyBufferBudget, BodyBufferLease, DEFAULT_BODY_BUFFER_MEM};

impl Lsapi {
    /// Create a handler over an existing pool.
    pub fn new(pool: Arc<LsapiPool>) -> Self {
        Lsapi {
            pool,
            script_root: None,
            max_body: 16 * 1024 * 1024,
            read_timeout: Duration::from_secs(60),
            base_env: Vec::new(),
            monitor: None,
            retry: true,
            max_process_time: None,
            body_budget: Arc::new(BodyBufferBudget::new(DEFAULT_BODY_BUFFER_MEM)),
        }
    }

    /// Share a server-wide buffered-body [`BodyBufferBudget`] (the registry wires
    /// one instance so every pool's handlers draw from the same cap).
    pub fn body_buffer_budget(mut self, budget: Arc<BodyBufferBudget>) -> Self {
        self.body_budget = budget;
        self
    }

    /// Attach the resilience [`Monitor`]. Enables pre-flush retry, fast-503 on a
    /// `Bad` supervisor, and Tier 2 in-flight tracking. The Tier 1
    /// `max_process_time` is also taken from the monitor unless overridden.
    pub fn monitor(mut self, monitor: Arc<Monitor>) -> Self {
        if self.max_process_time.is_none() {
            self.max_process_time = monitor.max_process_time();
        }
        self.monitor = Some(monitor);
        self
    }

    /// Enable/disable single retry of a pre-flush failure (default on).
    pub fn retry(mut self, enable: bool) -> Self {
        self.retry = enable;
        self
    }

    /// Override the Tier 1 total processing-time deadline.
    pub fn max_process_time(mut self, d: Option<Duration>) -> Self {
        self.max_process_time = d;
        self
    }

    /// Override the filesystem root used to resolve `SCRIPT_FILENAME` (otherwise
    /// the per-request vhost `doc_root` is used).
    pub fn script_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.script_root = Some(root.into());
        self
    }

    pub fn max_body(mut self, bytes: u64) -> Self {
        self.max_body = bytes;
        self
    }

    pub fn read_timeout(mut self, d: Duration) -> Self {
        self.read_timeout = d;
        self
    }

    /// Add env passed on every request (e.g. `PHP_ADMIN_VALUE` directives, or the
    /// ext-processor's configured `env`).
    pub fn base_env(mut self, env: impl IntoIterator<Item = (String, String)>) -> Self {
        self.base_env.extend(env);
        self
    }

    /// Resolve the absolute script path for a request. A pipeline-supplied
    /// [`LsapiScript`] extension (e.g. a resolved directory index) wins; else
    /// `<script_root|doc_root><uri-path>`.
    fn script_filename(&self, ctx: &ReqCtx, req: &Request) -> PathBuf {
        if let Some(ls) = req.extensions().get::<LsapiScript>() {
            return ls.script.clone();
        }
        let root = self
            .script_root
            .clone()
            .unwrap_or_else(|| ctx.vhost.doc_root.clone());
        let rel = req.uri().path().trim_start_matches('/');
        // Collapse `.`/`..` so this fallback (used only when no LsapiScript is attached) can
        // never escape `root` via `..`. The production pipeline normalizes the path AND always
        // attaches a resolved LsapiScript, so this is defensive — but a direct caller must not
        // be able to traverse out of the doc root.
        root.join(collapse_rel(rel))
    }
}

/// Collapse a relative URI path's empty/`.`/`..` segments into a root-confined relative
/// path: a `..` pops the last kept segment and a leading `..` is simply dropped, so
/// `root.join()` of the result can never escape `root`.
fn collapse_rel(rel: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out
}

impl Lsapi {
    /// Dispatch while returning the consumed request's head to the caller. The
    /// server pipeline needs the original headers only if post-dispatch target
    /// auth or ErrorDocument policy runs. Consuming the request lets the
    /// Content-Length path move its body into the LSAPI pump without allocating
    /// an empty boxed replacement, while still avoiding an unconditional
    /// HeaderMap clone on every successful PHP request.
    pub async fn handle_retaining_head(
        &self,
        ctx: &mut ReqCtx,
        mut req: Request,
    ) -> (Result<Response, HandlerError>, http::request::Parts) {
        let script = self.script_filename(ctx, &req);

        // Resolve a pipeline-supplied SCRIPT_NAME / PATH_INFO split + the php.ini
        // special-env (owned — cloned out of the extension so no borrow lingers).
        let mut builder = CgiEnvBuilder::new(&script).extra_ref(&self.base_env);
        let mut special_env: Vec<(SpecialEnvType, String, String)> = Vec::new();
        if let Some(ls) = req.extensions().get::<LsapiScript>() {
            if let Some(sn) = &ls.script_name {
                builder = builder.script_name(sn.clone());
            }
            if let Some(pi) = &ls.path_info {
                builder = builder.path_info(pi.clone());
            }
            special_env = ls.special_env.clone();
        }

        // Whether a post-flush reset on a REUSED socket is safe to replay: only
        // idempotent, bodyless methods (GET/HEAD). A POST etc. is never retried
        // post-flush (the backend may have begun processing it).
        let idempotent = matches!(*req.method(), http::Method::GET | http::Method::HEAD);
        let is_head = req.method() == http::Method::HEAD;

        // Two body paths: a known Content-Length STREAMS the body; chunked is
        // buffered to cap NOW (we must learn the length to give lsphp a concrete
        // m_reqBodyLen). The chunked collection takes a MUTABLE borrow of `req`, so
        // it must precede building the CGI env / wire headers, which take a SHARED
        // borrow of `req` (they hold `Cow::Borrowed` slices into it — the alloc win).
        let declared_len = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        // (#236) The lease lives to the end of `handle` so the reservation tracks
        // the buffered body's lifetime, not just the collection loop. Never read —
        // held purely for its Drop.
        // Held to the END of this fn: the RAII lease keeps the server-wide
        // buffered-body reservation alive while the buffer is handed to lsphp. A
        // concurrent body pump holds a clone until it finishes writing (#806).
        let body_lease: Option<Arc<BodyBufferLease>>;
        let buffered: Option<Bytes> = match declared_len {
            Some(_) => {
                body_lease = None;
                None
            }
            None => {
                let (b, lease) =
                    match collect_to_cap(req.body_mut(), self.max_body, &self.body_budget).await {
                        Ok(collected) => collected,
                        Err(error) => {
                            let (parts, _) = req.into_parts();
                            return (Err(error), parts);
                        }
                    };
                body_lease = Some(Arc::new(lease));
                Some(b)
            }
        };
        // A bodyless GET/HEAD/... carries no Content-Length on the wire; inventing
        // `Content-Length: 0` would surface in getallheaders()/$_SERVER, unlike LSWS.
        let method_has_body = matches!(
            *req.method(),
            http::Method::POST | http::Method::PUT | http::Method::PATCH
        );
        let buffered_len = buffered
            .as_ref()
            .filter(|body| !body.is_empty() || method_has_body)
            .map(|body| body.len().to_string());

        // Build the CGI env + raw wire headers (both borrow `req`). lsphp reads
        // $_SERVER HTTP_* / getallheaders() from the LSAPI header index over this
        // header block, NOT the CGI env table, so they are sent there too.
        let env = builder.build_with_content_length(&req, ctx, buffered_len.as_deref());
        // Synthesize Content-Length only in the LSAPI wire view.  The retained
        // request head remains byte-for-byte faithful for later policy checks.
        let headers = collect_wire_headers(&req, buffered_len.as_deref(), ctx.forwarding_trusted);

        // (#3 LSAPI u16 length truncation) Every CGI env pair and every wire-order
        // header is length-prefixed with a big-endian u16 in the BEGIN_REQUEST
        // frame (proto.rs), and that length INCLUDES the trailing NUL. A key/value
        // or header name/value whose byte length exceeds `u16::MAX - 1` would have
        // its prefix silently wrap while the full bytes are still emitted,
        // desyncing lsphp's env-table / header-index parser for the whole request
        // (and any subsequently pooled socket). hyper's header limits are far
        // larger than this, so an attacker can drive a single >64 KiB header value
        // (or a header mirrored to a giant HTTP_* env var). Reject fail-closed with
        // 431 BEFORE assembling the frame — this is a hard LSAPI protocol limit,
        // independent of (and stricter, per-field, than) `max_req_header_size`.
        if lsapi_fields_overflow_u16(&env)
            || lsapi_fields_overflow_u16(&headers)
            || lsapi_special_env_overflow_u16(&special_env)
        {
            drop(env);
            drop(headers);
            let (parts, _) = req.into_parts();
            return (Err(HandlerError::RequestHeaderFieldsTooLarge), parts);
        }

        // EARLY 413: if the client DECLARED a Content-Length over the cap, reject
        // it before touching the pool (no connection churn). The chunked path has
        // already enforced the cap incrementally inside collect_to_cap above.
        if let Some(len) = declared_len {
            if len > self.max_body {
                drop(env);
                drop(headers);
                let (parts, _) = req.into_parts();
                return (Err(HandlerError::PayloadTooLarge), parts);
            }
            // We also refuse anything that cannot fit lsphp's i32 m_reqBodyLen.
            if len > i32::MAX as u64 {
                drop(env);
                drop(headers);
                let (parts, _) = req.into_parts();
                return (Err(HandlerError::PayloadTooLarge), parts);
            }
        }

        // Encode the BEGIN_REQUEST packet ONCE into owned bytes — this is the LAST
        // read of `env`/`headers`, so their borrows of `req` end here and the body
        // can be consumed below. The packet is invariant across retries (the env,
        // headers and concrete body length are all fixed), so the dispatch loop
        // re-writes these same bytes on each attempt rather than rebuilding them.
        let body_len: i32 = match (declared_len, &buffered) {
            (Some(len), _) => len as i32,
            (None, Some(b)) => b.len() as i32,
            (None, None) => 0,
        };
        let mut begin = take_begin_buf();
        build_begin_request_framed_into(&mut begin, &env, &special_env, &headers, body_len);
        drop(env);
        drop(headers);
        // PHP reads a POST body in full before the script runs (the form handlers,
        // or php_default_post_reader for any other type) while enable_post_data_reading
        // is on and the body is under post_max_size, so no unread tail can follow
        // RESP_END and the socket may be reused. Any other bodied request closes its
        // connection: lsphp would parse an unread tail as a new request (#833).
        // PHP pre-reads only a POST that carries a Content-Type (sapi_activate), and
        // only through sapi_read_standard_form_data: multipart is consumed lazily by
        // rfc1867, which reads nothing on an early exit (no boundary, too many
        // parts), so it never qualifies (#835). An operator .user.ini/php.ini turning
        // enable_post_data_reading off is not visible here and must not be deployed
        // alongside this rule.
        let body_preread = req.method() == http::Method::POST
            && (0..=PREREAD_POST_MAX).contains(&body_len)
            && single_header(req.headers(), http::header::CONTENT_TYPE)
                .is_some_and(|v| php_preread_content_type(v.as_bytes()))
            && !special_env.iter().any(|(_, name, _)| {
                name.eq_ignore_ascii_case("enable_post_data_reading")
                    || name.eq_ignore_ascii_case("post_max_size")
            });
        let (parts, body) = req.into_parts();
        // Any other body may be left partly unread, and lsphp runs an unread tail
        // as its next request: refuse a body that holds one before dispatch. A
        // streamed body is checked by the pump as it arrives.
        if !body_preread
            && buffered
                .as_ref()
                .is_some_and(|b| !b.is_empty() && crate::proto::body_embeds_begin_request(b))
        {
            self.pool.note_embedded_begin();
            return_begin_buf(begin);
            return (Err(HandlerError::BadRequest), parts);
        }

        // `begin` is owned here and only borrowed (`&[u8]`) by the dispatch/retry
        // path, so it can be recycled to the per-thread freelist once dispatch
        // returns (the packet is invariant across retries and no longer needed once
        // the response is read).
        // Tier 2 in-flight tracking: held until THIS fn returns (response head ready —
        // the streaming body pump is a detached task, so a slow client download never
        // counts as PHP time). The guard is begun INSIDE dispatch, AFTER the pool is
        // acquired and BEGIN_REQUEST is flushed (the request-send boundary), so a
        // pool-acquire/queue backlog is NOT counted as worker processing time and cannot
        // make the monitor SIGTERM a healthy worker (#47). Dropped here at head-ready.
        let mut inflight: Option<InFlightGuard> = None;
        let result = match buffered {
            Some(buffered) => {
                drop(body);
                self.dispatch_buffered_retrying(
                    idempotent,
                    is_head,
                    body_preread,
                    &begin,
                    buffered,
                    body_lease.as_ref(),
                    &mut inflight,
                )
                .await
            }
            None => {
                self.dispatch_streaming_retrying(
                    idempotent,
                    is_head,
                    body_preread,
                    &begin,
                    body_len,
                    body,
                    &mut inflight,
                )
                .await
            }
        };
        return_begin_buf(begin);
        drop(inflight);
        (result, parts)
    }
}

#[async_trait]
impl Handler for Lsapi {
    async fn handle(&self, ctx: &mut ReqCtx, req: Request) -> Result<Response, HandlerError> {
        self.handle_retaining_head(ctx, req).await.0
    }
}

// Recycled BEGIN_REQUEST encode buffers. Reused across requests so the framed
// packet encode does not allocate (and page-fault) a fresh ~1-2 KB buffer every
// PHP request. `build_begin_request_framed_into` clears it before each encode, so
// a recycled buffer leaks nothing of the prior request. Capacity is bounded on
// return so one giant-header request can't bloat the cached buffer permanently.
thread_local! {
    static BEGIN_LOCAL: std::cell::RefCell<Vec<bytes::BytesMut>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
static BEGIN_BUFS: hj_core::TieredPool<bytes::BytesMut> =
    hj_core::TieredPool::new(&BEGIN_LOCAL, BUF_POOL_LOCAL, BUF_POOL_SHARED);

/// Largest recycled begin-buffer capacity we keep between requests (a request that
/// grew it past this is encoded then the oversized buffer is dropped, not cached).
const BEGIN_BUF_KEEP_CAP: usize = 16 * 1024;

// (#280) Spare `PacketReader` read buffers. A fresh `BytesMut::with_capacity(64 KiB)`
// per dispatch zeroed 64 KiB on every PHP render's TTFB path; recycling via Drop
// hands the allocation to the next reader instead. Several PHP requests are in
// flight per runtime thread and a reader often drops on another thread than it
// started on (a migrated task, the tail drain), so a single per-thread spare left
// most readers allocating, and with prod's immediate mimalloc purge faulting in,
// a fresh 64 KiB.
thread_local! {
    static PACKET_LOCAL: std::cell::RefCell<Vec<Vec<u8>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
static PACKET_BUFS: hj_core::TieredPool<Vec<u8>> =
    hj_core::TieredPool::new(&PACKET_LOCAL, BUF_POOL_LOCAL, BUF_POOL_SHARED);

/// Spare buffers one thread keeps in each pool above, and the shared overflow.
const BUF_POOL_LOCAL: usize = 8;
const BUF_POOL_SHARED: usize = 32;

/// Take a pooled begin buffer (or a fresh one). The borrow is synchronous
/// (never held across an `.await`), so it cannot conflict with another task that
/// the runtime parks onto this thread.
fn take_begin_buf() -> bytes::BytesMut {
    BEGIN_BUFS.take().unwrap_or_default()
}

/// Return the begin buffer for reuse, dropping it if it grew oversized.
fn return_begin_buf(buf: bytes::BytesMut) {
    if buf.capacity() <= BEGIN_BUF_KEEP_CAP {
        BEGIN_BUFS.give(buf);
    }
}

impl Lsapi {
    /// If a monitor is attached, fast-fail with 503 when the supervisor is in the
    /// `Bad` (backoff) state — no point dialing a worker that just failed to
    /// start. Returns `true` if the caller should bail with `ServiceUnavailable`.
    /// For external mode (no monitor), checks the circuit breaker instead.
    fn supervisor_is_bad(&self) -> bool {
        if let Some(m) = &self.monitor {
            return m.supervisor().state() == WorkerState::Bad;
        }
        self.pool.is_circuit_open()
    }

    /// Upfront gate; call ONCE per request to check if we should even attempt to
    /// acquire/dial. Returns `None` if we should fail fast (503). In owned mode this
    /// is a pure read of the monitor state; in external mode it may claim the single
    /// half-open trial slot if the breaker is open — the returned `TrialGuard` MUST
    /// be held for the whole dispatch so the slot is released on every exit path
    /// (success, failure, timeout, cancellation), never leaked (#125).
    fn admitted(&self) -> Option<Option<TrialGuard>> {
        if self.monitor.is_some() {
            return if self.supervisor_is_bad() {
                None
            } else {
                Some(None)
            };
        }
        match self.pool.admit_dial() {
            DialAdmission::Proceed => Some(None),
            DialAdmission::Trial(guard) => Some(Some(guard)),
            DialAdmission::Reject => None,
        }
    }

    /// Drive recovery for a replayable (pre-flush) failure: nudge the monitor,
    /// briefly await readiness up to `min(init_timeout, RECOVERY_WAIT_CAP)`, and
    /// clear the pool so the retry dials a fresh socket. In external mode (no monitor),
    /// just clear the pool and retry once. Returns `false` (do not retry) if the
    /// supervisor is `Bad` or the breaker is open in external mode.
    async fn recover_before_retry(&self) -> bool {
        let monitor = match &self.monitor {
            Some(m) => m,
            None => {
                // External mode: no supervisor to nudge. Just clear stale sockets
                // and retry if the breaker isn't currently open.
                if !self.pool.has_circuit_breaker() {
                    return false; // No breaker either; legacy behavior
                }
                if self.pool.is_circuit_open() {
                    return false; // Breaker open; don't retry
                }
                self.pool.clear();
                return true;
            }
        };
        // A Bad supervisor is in backoff; retrying now just races the backoff.
        if monitor.supervisor().state() == WorkerState::Bad {
            return false;
        }
        monitor.request_restart();
        // Briefly await a transition to Good (the monitor publishes state).
        let wait = self.pool_init_timeout().min(RECOVERY_WAIT_CAP);
        let mut rx = monitor.subscribe();
        let recovered = tokio::time::timeout(wait, async {
            loop {
                if *rx.borrow() == WorkerState::Good {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        })
        .await;
        // (item 7) The wait result was previously discarded; record (at debug) when
        // the worker did NOT recover in the window, so a wedged monitor is diagnosable
        // rather than invisible. The retry proceeds regardless (a still-dead worker
        // just fails the retry too).
        if recovered.is_err() {
            tracing::debug!(target: "hj_lsapi", ?wait, "lsphp did not return to Good within the recovery window; retrying anyway");
        }
        // Whether or not it recovered in time, drop stale idle sockets so the
        // retry dials fresh; a still-dead worker simply fails the retry too.
        self.pool.clear();
        true
    }

    /// The pool's effective init timeout (used to bound the recovery wait). We do
    /// not expose it on the pool, so mirror the handler's read timeout as a sane
    /// upper bound; the `RECOVERY_WAIT_CAP` is the real ceiling.
    fn pool_init_timeout(&self) -> Duration {
        RECOVERY_WAIT_CAP
    }

    /// Decide whether to proceed with a retry given the failure kind and how many
    /// retries have already happened, performing any recovery the kind requires.
    ///
    /// - `PreFlush` (the worker may be down): retry only on the FIRST failure, gated
    ///   on the monitor-driven `retry` flag, after `recover_before_retry()` nudges a
    ///   restart + clears stale sockets (which itself waits up to `RECOVERY_WAIT_CAP`).
    /// - `IdempotentReset` (a pre-response reset on an idempotent request; worker is
    ///   fine, request is replayable): retry up to `IDEMPOTENT_RETRY_MAX` times on a
    ///   fresh dial — no restart, just a short backoff so a recycle BURST can resolve.
    ///   Bail if the supervisor went `Bad` mid-burst, so a real outage 503s fast
    ///   instead of every request amplifying load by the retry budget.
    ///
    /// `attempt` is the number of failures so far (1 = the first dispatch failed).
    async fn proceed_with_retry(&self, kind: RetryKind, attempt: u32) -> bool {
        match kind {
            RetryKind::IdempotentReset => {
                attempt <= IDEMPOTENT_RETRY_MAX && !self.supervisor_is_bad()
            }
            RetryKind::StaleReuse => {
                // A dead pooled socket usually means its whole family died (master
                // crash, hard restart): drop every idle socket so the retry dials
                // fresh instead of walking through more dead ones. No restart nudge,
                // the backend is reachable.
                self.pool.clear();
                attempt <= IDEMPOTENT_RETRY_MAX && !self.supervisor_is_bad()
            }
            RetryKind::PreFlush => attempt == 1 && self.retry && self.recover_before_retry().await,
        }
    }

    /// Content-length path with a bounded retry loop (pre-flush recovery or
    /// stale-reused re-dial with backoff). `begin` is the pre-encoded
    /// BEGIN_REQUEST packet (owned here, re-written by reference each attempt);
    /// only the body is replayed.
    async fn dispatch_streaming_retrying(
        &self,
        idempotent: bool,
        is_head: bool,
        body_preread: bool,
        begin: &[u8],
        body_len: i32,
        body: hj_core::IncomingBody,
        inflight: &mut Option<InFlightGuard>,
    ) -> Result<Response, HandlerError> {
        // Held for the whole dispatch: on drop (any exit path) it releases the
        // breaker's half-open trial slot so recovery can be re-probed (#125).
        let _trial = match self.admitted() {
            Some(guard) => guard,
            None => return Err(HandlerError::ServiceUnavailable),
        };
        let mut body = body;
        let mut attempt: u32 = 0;
        let mut last_retry: Option<RetryKind> = None;
        loop {
            match self
                .dispatch_streaming(
                    idempotent,
                    is_head,
                    body_preread,
                    begin,
                    body_len,
                    body,
                    &mut *inflight,
                )
                .await
            {
                Attempt::Done(r) => return tag_retry(r, last_retry),
                Attempt::Retry {
                    body: b,
                    reason,
                    kind,
                } => {
                    attempt += 1;
                    if !self.proceed_with_retry(kind, attempt).await {
                        // Exhausted/blocked: 503 if the worker is bad, else the reason.
                        return Err(self.retry_exhausted(reason));
                    }
                    if matches!(kind, RetryKind::IdempotentReset) {
                        tokio::time::sleep(IDEMPOTENT_RETRY_BACKOFF).await;
                    }
                    last_retry = Some(kind);
                    body = b; // replay the body for the next attempt
                }
            }
        }
    }

    /// Buffered (chunked) path with a bounded retry loop (pre-flush recovery or
    /// stale-reused re-dial with backoff). `begin` is the pre-encoded
    /// BEGIN_REQUEST packet (owned here, re-written by reference each attempt).
    async fn dispatch_buffered_retrying(
        &self,
        idempotent: bool,
        is_head: bool,
        body_preread: bool,
        begin: &[u8],
        body: Bytes,
        lease: Option<&Arc<BodyBufferLease>>,
        inflight: &mut Option<InFlightGuard>,
    ) -> Result<Response, HandlerError> {
        // Held for the whole dispatch: on drop (any exit path) it releases the
        // breaker's half-open trial slot so recovery can be re-probed (#125).
        let _trial = match self.admitted() {
            Some(guard) => guard,
            None => return Err(HandlerError::ServiceUnavailable),
        };
        let mut body = body;
        let mut attempt: u32 = 0;
        let mut last_retry: Option<RetryKind> = None;
        loop {
            match self
                .dispatch_buffered(
                    idempotent,
                    is_head,
                    body_preread,
                    begin,
                    body,
                    lease,
                    &mut *inflight,
                )
                .await
            {
                Attempt::Done(r) => return tag_retry(r, last_retry),
                Attempt::Retry {
                    body: b,
                    reason,
                    kind,
                } => {
                    attempt += 1;
                    if !self.proceed_with_retry(kind, attempt).await {
                        return Err(self.retry_exhausted(reason));
                    }
                    if matches!(kind, RetryKind::IdempotentReset) {
                        tokio::time::sleep(IDEMPOTENT_RETRY_BACKOFF).await;
                    }
                    last_retry = Some(kind);
                    body = b;
                }
            }
        }
    }

    /// Map a final, still-replayable failure to a status: a `Bad` supervisor means
    /// the worker is down (503); otherwise surface the original bad-gateway reason.
    fn retry_exhausted(&self, reason: HandlerError) -> HandlerError {
        if self.supervisor_is_bad() {
            HandlerError::ServiceUnavailable
        } else {
            reason
        }
    }
}

impl Lsapi {
    /// CONTENT-LENGTH PATH: send BEGIN_REQUEST with the concrete length and then
    /// stream the raw body bytes on a separate owned write half while the response
    /// is read on the owned read half — concurrently, never awaiting the writer
    /// before the first response packet (lsphp may answer before draining body).
    async fn dispatch_streaming(
        &self,
        idempotent: bool,
        is_head: bool,
        body_preread: bool,
        begin: &[u8],
        body_len: i32,
        body: hj_core::IncomingBody,
        inflight: &mut Option<InFlightGuard>,
    ) -> Attempt<hj_core::IncomingBody> {
        // PRE-FLUSH (replayable): pool acquire. On failure, hand the (untouched)
        // body back so the caller can retry on a fresh connection.
        let acq_start = Instant::now();
        // (#315) GET/HEAD with no body: skip the pool's reuse probe — the
        // IdempotentReset replay below covers a dead reuse.
        let mut conn = match if idempotent && body_len == 0 {
            self.pool.acquire_unprobed().await
        } else {
            self.pool.acquire().await
        } {
            Ok(c) => c,
            Err(e) => match &e {
                // Capacity (semaphore timed out) / pool closed / breaker open. Retrying
                // would just re-wait the full init_timeout on the same exhausted
                // semaphore — doubling time-to-503 under overload — or re-hit an open
                // breaker. Fail fast with a terminal 503, no retry (#132).
                crate::pool::PoolError::Timeout(_)
                | crate::pool::PoolError::Closed
                | crate::pool::PoolError::CircuitOpen => {
                    return Attempt::Done(Err(HandlerError::ServiceUnavailable));
                }
                // Connection refused: the backend is down (lsphp restart window). Hand the
                // untouched body back so the caller can replay on a fresh connection.
                crate::pool::PoolError::Connect(_) => {
                    return Attempt::Retry {
                        body,
                        reason: HandlerError::BadGateway(format!("lsapi connect: {e}")),
                        kind: RetryKind::PreFlush,
                    };
                }
            },
        };
        let acquire = acq_start.elapsed();

        // Write the pre-encoded BEGIN_REQUEST on the (still un-split) conn so a
        // pre-flush failure is cleanly distinguishable (request is REPLAYABLE until
        // this flushes). The request body is NOT touched until after the flush
        // below, so a failure here is still safely replayable.
        let begin_fail_kind = begin_failure_kind(idempotent && body_len == 0, conn.is_reused());
        if let Err(e) = conn.stream_mut().write_all(begin).await {
            conn.poison();
            return Attempt::Retry {
                body,
                reason: HandlerError::BadGateway(format!("lsapi write begin: {e}")),
                kind: begin_fail_kind,
            };
        }
        if let Err(e) = conn.stream_mut().flush().await {
            conn.poison();
            return Attempt::Retry {
                body,
                reason: HandlerError::BadGateway(format!("lsapi flush begin: {e}")),
                kind: begin_fail_kind,
            };
        }
        // === COMMITTED: from here the request is non-replayable. ===

        // Tier 2 in-flight clock starts HERE — request committed to lsphp (BEGIN_REQUEST
        // flushed), so the pool acquire above is excluded (#47). On an idempotent-reset
        // retry this replaces the prior attempt's guard.
        // A bodied request starts the clock when its upload finishes instead (#660): the
        // Tier-2 kill must not fire on a slow but progressing upload (read_response).
        *inflight = if body_len > 0 {
            None
        } else {
            self.monitor.as_ref().map(|m| m.inflight().begin())
        };

        let (read_half, mut write_half, guard) = conn.into_split();
        let guard = Arc::new(guard);
        let scanned_body = (body_len > 0 && !body_preread).then(|| guard.clone());

        // Cancellation shared between the two halves. The response side notifies
        // it when it finishes (clean RESP_END, error, client disconnect, timeout)
        // so a body pump still blocked on a slow/stalled/abandoned upload unblocks
        // and drops its Arc<ReturnGuard> — releasing the semaphore permit and the
        // write-half fd instead of leaking them.
        let cancel = Arc::new(tokio::sync::Notify::new());
        let mut body_done = None;

        // (a) BODY-PUMP TASK: pull hyper frames -> write half, writing EXACTLY the
        //     declared `body_len` bytes. On a clean exact-length finish it deposits
        //     the write half so the socket can be re-pooled. On under/over-delivery,
        //     cap-exceed, IO error, body error, OR a cancel signal it shuts the
        //     write half down (closing the write direction so lsphp's body read
        //     returns short) and poisons the guard so the socket is never reused.
        let body_guard = guard.clone();
        let body_cancel = cancel.clone();
        let max_body = self.max_body;
        // Bound for an idle/stalled writer: if neither a body frame nor a socket
        // write makes progress for this long, abandon the upload (free the permit).
        let write_timeout = self.read_timeout;
        if body_len == 0 {
            // (#281) ZERO-LENGTH BODY (every GET/HEAD): the spawned pump would
            // immediately observe end-of-body and take the Complete path — flush +
            // deposit. Do it inline: one task spawn + Notify Arc pair + a scheduler
            // round-trip per PHP GET removed. No frame can arrive (the request has
            // no body to stream), so there is nothing the task would have raced;
            // the response side never waits on this task, and a later
            // `cancel.notify_*` with no listener is a harmless stored permit.
            if write_half.flush().await.is_err() {
                guard.poison();
            } else {
                guard.deposit_write(write_half);
            }
        } else {
            if body_preread {
                guard.mark_preread_body();
            } else {
                guard.mark_carried_body();
            }
            let done = Arc::new(tokio::sync::Notify::new());
            let pump_done = done.clone();
            body_done = Some(done);
            tokio::spawn(async move {
                pump_request_body(PumpArgs {
                    body,
                    write_half,
                    guard: body_guard,
                    cancel: body_cancel,
                    body_len: body_len as i64,
                    max_body,
                    idle_timeout: write_timeout,
                    scan: !body_preread,
                })
                .await;
                pump_done.notify_one();
            });
        }

        // (b) RESPONSE TASK is THIS function continuing on the read half. We read
        //     the first response packet immediately (no await on the writer), then
        //     hand the read half + guard to the streaming body pump. The body pump
        //     observes `cancel` once the response side is done.
        let sent_at = Instant::now();
        let response = self
            .read_response(
                read_half, guard, cancel, body_done, inflight, acquire, sent_at, is_head,
            )
            .await;
        // The pump flags the guard before it shuts the socket down, so a response
        // or read failure caused by that shutdown already sees the flag.
        if scanned_body.is_some_and(|guard| guard.embedded_begin_blocked()) {
            return Attempt::Done(Err(HandlerError::BadRequest));
        }
        match response {
            Ok(resp) => Attempt::Done(Ok(resp)),
            Err(ReadFail { err, retryable }) => {
                // IDEMPOTENT-RESET RETRY: a connection reset/closed before any
                // response byte, for an idempotent request with NO body to replay
                // (body_len == 0). The client has seen nothing; replay on a fresh dial
                // (the first attempt's empty pump finishes on its own). Covers both a
                // stale reused socket and a fresh dial that reset during a recycle
                // burst — the retry loop bounds + backs off either way.
                if retryable && idempotent && body_len == 0 {
                    Attempt::Retry {
                        body: empty_incoming_body(),
                        reason: err,
                        kind: RetryKind::IdempotentReset,
                    }
                } else {
                    Attempt::Done(Err(err))
                }
            }
        }
    }

    /// CHUNKED PATH: the body is already buffered (bounded to cap). Send
    /// BEGIN_REQUEST with the concrete buffered length, FLUSH it alone (the
    /// pre-flush replay boundary), then write the buffered body bytes, and read the
    /// response on the same connection (no split needed). BEGIN_REQUEST is flushed
    /// separately from the body so a partial write cannot deliver the whole packet
    /// (starting the PHP script) before a failure that would otherwise be replayed
    /// — see the inline comment below.
    async fn dispatch_buffered(
        &self,
        idempotent: bool,
        is_head: bool,
        body_preread: bool,
        begin: &[u8],
        body: Bytes,
        lease: Option<&Arc<BodyBufferLease>>,
        inflight: &mut Option<InFlightGuard>,
    ) -> Attempt<Bytes> {
        // A large buffered body written in full before any response read deadlocks
        // against a script that writes a large response before draining its input
        // (#806). Stream it concurrently with the response instead; the BEGIN packet
        // already carries the buffered length, and the streaming path hands back an
        // untouched body only for a pre-flush failure, so replaying the retained
        // bytes there is exactly as safe as replaying them here.
        if body.len() > BUFFERED_INLINE_WRITE_MAX {
            // collect_to_cap bounds a buffered body to i32::MAX.
            let body_len = body.len() as i32;
            return match self
                .dispatch_streaming(
                    idempotent,
                    is_head,
                    body_preread,
                    begin,
                    body_len,
                    full_incoming_body(body.clone(), lease.cloned()),
                    inflight,
                )
                .await
            {
                Attempt::Done(r) => Attempt::Done(r),
                Attempt::Retry { reason, kind, .. } => Attempt::Retry { body, reason, kind },
            };
        }
        // PRE-FLUSH (replayable): pool acquire. Hand the buffered body back on a
        // failure so the caller can replay it on a fresh connection.
        let acq_start = Instant::now();
        // (#315) Same skip as dispatch_streaming for a BUFFERED empty body.
        let mut conn = match if idempotent && body.is_empty() {
            self.pool.acquire_unprobed().await
        } else {
            self.pool.acquire().await
        } {
            Ok(c) => c,
            Err(e) => match &e {
                // Capacity (semaphore timed out) / pool closed / breaker open. Retrying
                // would just re-wait the full init_timeout on the same exhausted
                // semaphore — doubling time-to-503 under overload — or re-hit an open
                // breaker. Fail fast with a terminal 503, no retry (#132).
                crate::pool::PoolError::Timeout(_)
                | crate::pool::PoolError::Closed
                | crate::pool::PoolError::CircuitOpen => {
                    return Attempt::Done(Err(HandlerError::ServiceUnavailable));
                }
                // Connection refused: the backend is down (lsphp restart window). Hand the
                // untouched body back so the caller can replay on a fresh connection.
                crate::pool::PoolError::Connect(_) => {
                    return Attempt::Retry {
                        body,
                        reason: HandlerError::BadGateway(format!("lsapi connect: {e}")),
                        kind: RetryKind::PreFlush,
                    };
                }
            },
        };
        let acquire = acq_start.elapsed();

        // Write BEGIN_REQUEST ALONE first, then flush, BEFORE any body byte — the
        // same pre-flush boundary the streaming path uses. This is required for
        // replay safety: `write_all` loops over multiple `write()` syscalls, so if
        // we coalesced BEGIN_REQUEST + body into one buffer, a partial write could
        // deliver the COMPLETE BEGIN_REQUEST packet (plus some body) into lsphp's
        // socket buffer before erroring. lsphp's `readReq` (vendor/lsapilib.c:1361)
        // parses the whole BEGIN_REQUEST packet, then `LSAPI_Accept_r` returns and
        // the PHP script BEGINS EXECUTING (the body is pulled lazily later by
        // `LSAPI_ReadReqBody_r`, :1788). Replaying after that double-executes the
        // script — including its side effects. By writing BEGIN_REQUEST alone, a
        // partial/failed write of it leaves lsphp blocked inside `readReq` (the
        // packet is incomplete, Accept never returns, the script never starts), so
        // it is genuinely replayable.
        let begin_fail_kind = begin_failure_kind(idempotent && body.is_empty(), conn.is_reused());
        if let Err(e) = conn.stream_mut().write_all(begin).await {
            conn.poison();
            return Attempt::Retry {
                body,
                reason: HandlerError::BadGateway(format!("lsapi write begin: {e}")),
                kind: begin_fail_kind,
            };
        }
        if let Err(e) = conn.stream_mut().flush().await {
            conn.poison();
            return Attempt::Retry {
                body,
                reason: HandlerError::BadGateway(format!("lsapi flush begin: {e}")),
                kind: begin_fail_kind,
            };
        }
        // === COMMITTED: the BEGIN_REQUEST packet is on the wire; lsphp's readReq
        // can now return and the script can start. Everything past here is
        // NON-REPLAYABLE — a body write failure poisons the conn and surfaces a
        // terminal BadGateway, NEVER an Attempt::Retry (replaying would run the
        // script a second time). ===

        // Tier 2 in-flight clock starts HERE — request committed to lsphp (BEGIN_REQUEST
        // flushed), so the pool acquire above is excluded (#47). On an idempotent-reset
        // retry this replaces the prior attempt's guard.
        *inflight = self.monitor.as_ref().map(|m| m.inflight().begin());
        if !body.is_empty() {
            // Bound the buffered-body write the same way the streaming pump bounds its writes
            // (`write_timeout = self.read_timeout`). A worker wedged before/while reading the body
            // backpressures the UDS; without a deadline `write_all`/`flush` block indefinitely while
            // HOLDING the pool permit, so one stuck worker can pin pool slots (availability DoS).
            // Post-flush this is NON-REPLAYABLE, so on expiry poison + terminal 502.
            let write_body = async {
                let s = conn.stream_mut();
                if body_preread {
                    s.write_all(&body).await.map_err(BodyWriteError::Io)?;
                } else {
                    ScannedBodyWriter::new(body.len() as u64)
                        .push(s, body.clone())
                        .await?;
                }
                s.flush().await.map_err(BodyWriteError::Io)
            };
            match tokio::time::timeout(self.read_timeout, write_body).await {
                Ok(Ok(())) => {}
                Ok(Err(BodyWriteError::EmbeddedBegin)) => {
                    conn.poison();
                    self.pool.note_embedded_begin();
                    return Attempt::Done(Err(HandlerError::BadRequest));
                }
                Ok(Err(BodyWriteError::Io(e))) => {
                    conn.poison();
                    return Attempt::Done(Err(HandlerError::BadGateway(format!(
                        "lsapi write body: {e}"
                    ))));
                }
                Err(_) => {
                    conn.poison();
                    return Attempt::Done(Err(HandlerError::BadGateway(
                        "lsapi write body: timeout".to_string(),
                    )));
                }
            }
        }

        // Split so the response pump owns a read half + a ReturnGuard like the
        // streaming path. The write half is already done; deposit it immediately
        // so a clean read can re-pool the socket.
        let (read_half, write_half, guard) = conn.into_split();
        if !body.is_empty() {
            if body_preread {
                guard.mark_preread_body();
            } else {
                guard.mark_carried_body();
            }
        }
        guard.deposit_write(write_half);
        // No concurrent body pump here, so the cancel notify has no listener; pass
        // a fresh one to keep one read_response signature.
        let cancel = Arc::new(tokio::sync::Notify::new());
        let sent_at = Instant::now();
        match self
            .read_response(
                read_half,
                Arc::new(guard),
                cancel,
                None,
                inflight,
                acquire,
                sent_at,
                is_head,
            )
            .await
        {
            Ok(resp) => Attempt::Done(Ok(resp)),
            Err(ReadFail { err, retryable }) => {
                // IDEMPOTENT-RESET RETRY: a connection reset/closed before any
                // response byte, for an idempotent request with no body. A buffered
                // payload is byte-replayable, but after BEGIN+body are flushed the PHP
                // worker may already have acted on it, so keep post-flush replay bodyless.
                if retryable && idempotent && body.is_empty() {
                    Attempt::Retry {
                        body,
                        reason: err,
                        kind: RetryKind::IdempotentReset,
                    }
                } else {
                    Attempt::Done(Err(err))
                }
            }
        }
    }

    /// Read RESP_HEADER off `read_half`, build the response head, and spawn the
    /// streaming body pump (RESP_STREAM -> channel) over the rest of the read half.
    /// `guard` re-pools the socket once BOTH the read completed cleanly here AND
    /// the write side deposited its half.
    #[allow(clippy::too_many_arguments)]
    async fn read_response(
        &self,
        mut read_half: OwnedReadHalf,
        guard: Arc<ReturnGuard>,
        cancel: Arc<tokio::sync::Notify>,
        mut body_done: Option<Arc<tokio::sync::Notify>>,
        inflight: &mut Option<InFlightGuard>,
        acquire: Duration,
        sent_at: Instant,
        is_head: bool,
    ) -> Result<Response, ReadFail> {
        // Any early return from header-reading means the response side is done;
        // wake a body pump that may still be blocked so it stops and frees its
        // permit + write-half fd. We use `notify_one` (not `notify_waiters`) so the
        // signal is STORED as a permit if the body pump is momentarily not parked
        // on `cancel.notified()` — closing the lost-wakeup window. (The body pump's
        // idle_timeout is a further backstop, so a leak can never be permanent.)
        let fail = |guard: &Arc<ReturnGuard>, cancel: &Arc<tokio::sync::Notify>| {
            guard.poison();
            cancel.notify_one();
        };
        // Tier 1 TOTAL processing deadline (in addition to the per-read idle
        // timeout). Spans BOTH the header read here and the streaming body below.
        // While a request-body pump is still delivering, neither the idle timeout
        // nor the deadline runs (LSWS: the extapp timeout starts once the body is
        // fully sent); the pump's own idle timer bounds a stalled upload, and its
        // end (complete OR abort) arms both clocks.
        let deadline = || self.max_process_time.map(|d| Instant::now() + d);
        let mut reader = PacketReader::with_deadline(
            self.read_timeout,
            if body_done.is_none() {
                deadline()
            } else {
                None
            },
        );
        let mut accept_worker_pid = true;
        let resp_header = loop {
            let next = match &body_done {
                None => reader.next(&mut read_half).await,
                Some(done) => tokio::select! {
                    biased;
                    r = reader.next_untimed(&mut read_half) => r,
                    _ = done.notified() => {
                        body_done = None;
                        reader.deadline = deadline();
                        *inflight = self.monitor.as_ref().map(|m| m.inflight().begin());
                        continue;
                    }
                },
            };
            match next {
                Ok(Some(frame)) => match frame.ptype {
                    PacketType::RespHeader => {
                        match RespHeader::parse_flagged(&frame.body, frame.flag) {
                            Ok(h) => break h,
                            Err(e) => {
                                fail(&guard, &cancel);
                                return Err(ReadFail::terminal(HandlerError::BadGateway(format!(
                                    "lsapi resp header: {e}"
                                ))));
                            }
                        }
                    }
                    PacketType::StderrStream => {
                        if accept_worker_pid {
                            if let Some(pid) = lsapi_worker_pid(&frame.body) {
                                guard.record_worker_pid(pid);
                            } else {
                                log_stderr(&frame.body);
                            }
                            accept_worker_pid = false;
                        } else {
                            log_stderr(&frame.body);
                        }
                    }
                    PacketType::ReqReceived => {
                        accept_worker_pid = false;
                    }
                    PacketType::RespEnd | PacketType::ConnClose => {
                        fail(&guard, &cancel);
                        return Err(ReadFail::terminal(HandlerError::BadGateway(
                            "lsapi response ended before headers".into(),
                        )));
                    }
                    PacketType::InternalError => {
                        fail(&guard, &cancel);
                        return Err(ReadFail::terminal(HandlerError::BadGateway(
                            "lsapi internal error".into(),
                        )));
                    }
                    _ => {
                        accept_worker_pid = false;
                    }
                },
                Ok(None) => {
                    // EOF before any response byte: a reused keep-alive socket lsphp
                    // closed (the stale-reuse race) → retryable on a fresh dial.
                    fail(&guard, &cancel);
                    return Err(ReadFail::retryable(HandlerError::BadGateway(
                        "lsapi closed before headers".into(),
                    )));
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    // A hung worker, not a stale socket — a retry would just hang
                    // again, so this is terminal (504).
                    fail(&guard, &cancel);
                    return Err(ReadFail::terminal(HandlerError::GatewayTimeout));
                }
                Err(e) => {
                    // Connection reset before any response byte (e.g. ECONNRESET):
                    // the stale-reuse race → retryable on a fresh dial.
                    fail(&guard, &cancel);
                    return Err(ReadFail::retryable(HandlerError::BadGateway(format!(
                        "lsapi read: {e}"
                    ))));
                }
            }
        };
        // First response byte (RESP_HEADER) received — this is the TTFB boundary.
        let ttfb = sent_at.elapsed();
        if body_done.is_some() {
            reader.deadline = deadline();
            *inflight = self.monitor.as_ref().map(|m| m.inflight().begin());
        }

        let declared_len = match parse_response_content_length(&resp_header.headers) {
            Ok(len) => len,
            Err(reason) => {
                fail(&guard, &cancel);
                return Err(ReadFail::terminal(HandlerError::BadGateway(format!(
                    "invalid lsapi Content-Length: {reason}"
                ))));
            }
        };

        // Build the response head straight into a pre-sized map, consuming the
        // parsed header list (no per-field clone). The slack covers the fields the
        // response transforms add (Date, `.htaccess` Header ops, Content-Encoding,
        // Vary, cache status), which otherwise regrew an exactly sized map.
        let status = http::StatusCode::from_u16(resp_header.status).unwrap_or(http::StatusCode::OK);
        let mut head = http::HeaderMap::with_capacity(
            resp_header.headers.len() + usize::from(declared_len.is_some()) + RESPONSE_HEADER_SLACK,
        );
        let mut has_status_header = None;
        for (name, value) in resp_header.headers {
            // PHP may emit a "Status: 404 Not Found" header.
            if name.as_str().eq_ignore_ascii_case("status") {
                if let Some(code) = value
                    .to_str()
                    .ok()
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|c| c.parse::<u16>().ok())
                    .and_then(|c| http::StatusCode::from_u16(c).ok())
                {
                    has_status_header = Some(code);
                }
                continue;
            }
            // Parsed and normalized once above. Re-emitting every upstream field
            // would preserve ambiguous duplicates in the downstream HeaderMap.
            if name == http::header::CONTENT_LENGTH {
                continue;
            }
            if let Err(e) = head.try_append(name, value) {
                fail(&guard, &cancel);
                return Err(ReadFail::terminal(HandlerError::Other(format!(
                    "build response: {e}"
                ))));
            }
        }
        if let Some(len) = declared_len
            && let Err(e) = head.try_append(http::header::CONTENT_LENGTH, len.into())
        {
            fail(&guard, &cancel);
            return Err(ReadFail::terminal(HandlerError::Other(format!(
                "build response: {e}"
            ))));
        }
        let status = has_status_header.unwrap_or(status);
        // A 1xx is never a final response: forwarded, an H1 client waits forever for the
        // real one and H2/H3 frame a malformed stream (#668).
        if status.is_informational() {
            fail(&guard, &cancel);
            return Err(ReadFail::terminal(HandlerError::BadGateway(format!(
                "lsapi final status {} is informational",
                status.as_u16()
            ))));
        }
        let enforced_len = if hj_core::response_body_forbidden(is_head, status) {
            None
        } else {
            declared_len
        };
        // (#949) A script that opts out of buffering (`X-Accel-Buffering: no`, then
        // `flush()`) is feeding a client that consumes it as it arrives: it keeps the
        // streaming path and its unbuffered-feed marker.
        let unbuffered = accel_buffering_off(&head);
        let mut response = Response::new(Body::Empty);
        *response.status_mut() = status;
        *response.headers_mut() = head;
        response
            .extensions_mut()
            .insert(LsapiTiming { acquire, ttfb });

        // FAST PATH (the common PHP response): lsphp usually delivers the whole
        // response (RESP_HEADER + RESP_STREAM + RESP_END) in one socket write, so the
        // body packets are ALREADY in the reader's buffer after the header read. Drain
        // them with the SYNC `try_parse` and, if the whole body is in hand, return a
        // `Body::Full` — skipping the per-request response Channel + a spawned pump
        // task (a real cross-core hop between the LSAPI read and the h2/h1 send).
        //
        // (D1, #987) A declared Content-Length within the inline cap completes the
        // body once that many bytes are in hand: lsphp sends RESP_END only after the
        // app's post-flush deferred work (~100ms on XenForo pages). A few NON-BLOCKING
        // reads take in what the socket already holds; nothing un-buffered is ever
        // awaited here. RESP_END still decides re-pooling: when it is not buffered
        // yet, a tail task drains to it under the streaming pump's rules.
        //
        // The moment more bytes would have to be awaited, or the body exceeds
        // INLINE_BODY_CAP, fall back to the streaming pump, handing it the chunks
        // already collected as a `prelude` so none are lost.
        let complete_at = enforced_len.filter(|&len| len <= INLINE_BODY_CAP as u64 && !unbuffered);
        let mut prelude: Vec<Bytes> = Vec::new();
        let mut prelude_len: usize = 0;
        let mut fills = 0;
        enum InlineEnd {
            Repool,    // clean RESP_END: deposit the read half so the socket re-pools
            Poison,    // ConnClose before RESP_END: complete only with a satisfied Content-Length
            Tail(u64), // declared length in hand before RESP_END: a task drains to it
        }
        let inline_end: Option<InlineEnd> = loop {
            match reader.try_parse() {
                Ok(Some(frame)) => match frame.ptype {
                    PacketType::RespStream => {
                        prelude_len += frame.body.len();
                        if !frame.body.is_empty() {
                            prelude.push(frame.body);
                        }
                        if prelude_len > INLINE_BODY_CAP {
                            break None; // too big to inline -> stream the remainder
                        }
                    }
                    PacketType::StderrStream => log_stderr(&frame.body),
                    PacketType::ReqReceived => {}
                    PacketType::RespEnd => break Some(InlineEnd::Repool),
                    PacketType::ConnClose => break Some(InlineEnd::Poison),
                    PacketType::InternalError => {
                        fail(&guard, &cancel);
                        return Err(ReadFail::terminal(HandlerError::BadGateway(
                            "lsapi internal error".into(),
                        )));
                    }
                    _ => {}
                },
                // No more COMPLETE packet is buffered.
                Ok(None) => {
                    if let Some(len) = complete_at {
                        if prelude_len as u64 >= len {
                            break Some(InlineEnd::Tail(len));
                        }
                        if fills < INLINE_FILL_READS && reader.try_fill(&read_half) {
                            fills += 1;
                            continue;
                        }
                    }
                    // A socket read would have to wait: hand off to the async
                    // streaming pump (with the prelude).
                    break None;
                }
                Err(e) => {
                    fail(&guard, &cancel);
                    return Err(ReadFail::terminal(HandlerError::BadGateway(format!(
                        "lsapi resp parse: {e}"
                    ))));
                }
            }
        };

        if let Some(end) = inline_end {
            if matches!(end, InlineEnd::Poison) && enforced_len.is_none() {
                fail(&guard, &cancel);
                return Err(ReadFail::terminal(HandlerError::BadGateway(
                    "lsapi connection closed before RESP_END".into(),
                )));
            }
            if let Some(len) = enforced_len
                && (prelude_len as u64) < len
            {
                fail(&guard, &cancel);
                return Err(ReadFail::terminal(HandlerError::BadGateway(format!(
                    "lsapi response body truncated: declared {len} bytes, received {prelude_len}"
                ))));
            }
            let over_delivered = enforced_len.is_some_and(|len| prelude_len as u64 > len);
            let body = inline_body(
                prelude,
                enforced_len.map_or(prelude_len, |len| len as usize),
            );
            let path = match end {
                // Only a response that ended cleanly and honored its declared
                // length may return the LSAPI socket to the pool.
                // Bytes buffered past RESP_END (litespeed_finish_request's trailing
                // CONN_CLOSE) mean lsphp is closing this socket, or the stream is
                // out of sync; either way it must not be reused.
                InlineEnd::Repool if !over_delivered && !reader.has_buffered() => {
                    guard.deposit_read(read_half);
                    cancel.notify_one();
                    ResponseBodyPath::Inline
                }
                InlineEnd::Repool | InlineEnd::Poison => {
                    fail(&guard, &cancel);
                    ResponseBodyPath::Inline
                }
                // The consumer's body is already complete, so the tail only drains,
                // exactly as the streaming pump does once it has forwarded the
                // declared length.
                InlineEnd::Tail(len) => {
                    tokio::spawn(pump_body(
                        ResponseTail {
                            read_half,
                            reader,
                            guard,
                            cancel,
                            declared_len: enforced_len,
                        },
                        None,
                        Vec::new(),
                        len,
                        over_delivered,
                    ));
                    ResponseBodyPath::InlineTail
                }
            };
            self.pool.note_response_body(path);
            response
                .extensions_mut()
                .insert(hj_core::FreshBody::of(&body));
            *response.body_mut() = Body::Full(body);
            return Ok(response);
        }

        // STREAMING PATH: spawn a task that pumps RESP_STREAM -> channel body,
        // emitting the already-collected `prelude` chunks first so nothing buffered
        // during the header/inline phase is lost.
        //
        // (D1) The declared Content-Length lets the pump END the consumer's body the
        // moment that many bytes have been forwarded: lsphp holds the stream open past
        // the last content byte while the app runs post-flush deferred work (XenForo
        // jobs/session/stats — ~100ms on real pages) before RESP_END, and without the
        // declared length every store/collect/egress path waits that out on the
        // client's clock.
        let (tx, channel) = Channel::<Bytes, BoxError>::new(8);
        tokio::spawn(pump_body(
            ResponseTail {
                read_half,
                reader,
                guard,
                cancel,
                declared_len: enforced_len,
            },
            Some(tx),
            prelude,
            0,
            false,
        ));
        self.pool.note_response_body(ResponseBodyPath::Streamed);

        let boxed: BoxBody<Bytes, BoxError> = BoxBody::new(channel);
        *response.body_mut() = Body::Stream(boxed);
        // (#949) The transport streams a body so marked instead of holding it to
        // the buffering threshold; other PHP output keeps the buffered path.
        if unbuffered {
            response.extensions_mut().insert(hj_core::ProxiedBody);
        }
        Ok(response)
    }
}

fn accel_buffering_off(headers: &http::HeaderMap) -> bool {
    headers
        .get_all("x-accel-buffering")
        .iter()
        .any(|v| v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"no"))
}

/// Arguments to [`pump_request_body`] (grouped to keep the spawn call readable).
struct PumpArgs {
    body: hj_core::IncomingBody,
    write_half: OwnedWriteHalf,
    guard: Arc<ReturnGuard>,
    /// Woken by the response side when it is done; lets a stalled writer bail.
    cancel: Arc<tokio::sync::Notify>,
    /// The CONCRETE `m_reqBodyLen` declared in BEGIN_REQUEST. lsphp will read
    /// exactly this many raw bytes off the socket, so the pump must write exactly
    /// this many for the socket to stay framed/re-poolable.
    body_len: i64,
    /// Hard ceiling (defense-in-depth); the per-request `body_len` is the precise
    /// cap and is normally hit first.
    max_body: u64,
    /// Idle ceiling: if no body frame arrives / no write completes within this
    /// window, abandon the upload so the permit + fd are not leaked.
    idle_timeout: Duration,
    /// PHP may leave the body partly unread: write it through a
    /// `ScannedBodyWriter`.
    scan: bool,
}

/// Why the body pump stopped, deciding whether the write half is re-poolable.
enum PumpEnd {
    /// Wrote exactly `body_len` bytes and the body ended cleanly: depositable.
    Complete,
    /// Anything else (short body, over-delivery, cap, IO/body error, cancel,
    /// idle timeout): the socket is desynced/dead and must NOT be re-pooled.
    Abort,
    /// The body holds bytes lsphp could run as a new request; they were not
    /// written and the request must fail.
    EmbeddedBegin,
}

/// Pump the REQUEST body to lsphp on the owned write half.
///
/// Pulls hyper `IncomingBody` frames (`BodyExt::frame`) and writes their data to
/// the write half, requiring the total to equal the declared `body_len` (the
/// concrete `m_reqBodyLen` lsphp will read). On an exact, clean finish it flushes
/// (but does NOT shut the half down — the conn is pooled and lsphp keys off
/// `m_reqBodyLen`, not EOF) and deposits the write half so the socket can be
/// re-pooled once the response is also fully read.
///
/// On ANY other outcome — under-delivery (`written < body_len`), over-delivery
/// (`written > body_len`), `max_body` exceeded, IO error, body error, a cancel
/// signal from the response side, or an idle timeout — it ABANDONS the upload:
/// it shuts the write half DOWN (closing the socket's write direction so lsphp's
/// `lsapi_read` on the body returns short and the request fails fast) and poisons
/// the guard so the socket is never reused. It does NOT write an ABORT_REQUEST
/// control frame: lsphp reads post-BEGIN_REQUEST bytes as RAW body, not as LSAPI
/// packets, and has no ABORT_REQUEST consumer (vendor/lsapilib.c), so an ABORT
/// frame would only corrupt the body PHP receives.
async fn pump_request_body(args: PumpArgs) {
    use http_body_util::BodyExt;
    let PumpArgs {
        mut body,
        mut write_half,
        guard,
        cancel,
        body_len,
        max_body,
        idle_timeout,
        scan,
    } = args;
    let cap = (max_body as i64).min(body_len.max(0));
    let mut scanned = scan.then(|| ScannedBodyWriter::new(body_len.max(0) as u64));
    let mut written: i64 = 0;

    // (LST1) One pinned idle timer, reused (reset per use) for both the frame-read
    // and the write waits below, instead of allocating a fresh `tokio::time::timeout`
    // (a new `Sleep`) on every frame. Cancellation behaviour is unchanged: the timer
    // arm aborts the upload exactly as the old `timeout(...)` did.
    let timer = tokio::time::sleep(idle_timeout);
    tokio::pin!(timer);
    let end = loop {
        // Race the next body frame against (a) the response side cancelling and
        // (b) an idle timeout. Either of the latter abandons the upload.
        timer.as_mut().reset(tokio::time::Instant::from_std(
            Instant::now() + idle_timeout,
        ));
        let frame = tokio::select! {
            // Same priority as the old `cancel` vs `timeout(frame)`: cancel, then
            // the frame, then the idle timer.
            biased;
            _ = cancel.notified() => break PumpEnd::Abort,
            f = body.frame() => f,
            _ = timer.as_mut() => break PumpEnd::Abort, // idle timeout
        };
        match frame {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    if data.is_empty() {
                        continue;
                    }
                    written += data.len() as i64;
                    // Precise per-request cap: never write past the declared
                    // length (over-delivery would desync the next pooled request)
                    // and never past the hard ceiling.
                    if written > cap {
                        break PumpEnd::Abort;
                    }
                    let data = frame.into_data().expect("checked data_ref");
                    // Bound the write itself so a stalled lsphp reader (backpressure)
                    // cannot block us forever and leak the permit. Reuse the pinned
                    // timer, reset to a fresh idle window.
                    timer.as_mut().reset(tokio::time::Instant::from_std(
                        Instant::now() + idle_timeout,
                    ));
                    let wrote = tokio::select! {
                        biased;
                        _ = cancel.notified() => break PumpEnd::Abort,
                        w = write_body_data(&mut write_half, scanned.as_mut(), data) => w,
                        _ = timer.as_mut() => break PumpEnd::Abort, // write idle timeout
                    };
                    match wrote {
                        Ok(()) => {}
                        Err(BodyWriteError::EmbeddedBegin) => break PumpEnd::EmbeddedBegin,
                        // (item 7) Surface a broken-pipe/closed-socket write to lsphp
                        // instead of silently aborting the upload with no trace.
                        Err(BodyWriteError::Io(e)) => {
                            tracing::warn!(target: "hj_lsapi", error = %e, "lsphp request-body write failed; aborting upload");
                            break PumpEnd::Abort;
                        }
                    }
                    // lsphp reads exactly `body_len` bytes; once we have written
                    // them all we are DONE — do not await the body's final `None`
                    // (which may never come, or may race the response side's
                    // cancel and wrongly abort a complete upload).
                    if written == body_len {
                        break PumpEnd::Complete;
                    }
                }
                // Trailer frames carry no request body bytes for LSAPI; ignore.
            }
            Some(Err(_e)) => break PumpEnd::Abort, // client body errored
            None => {
                // End of body. Only an EXACT match is depositable; a short body
                // leaves lsphp waiting for the missing bytes.
                break if written == body_len {
                    PumpEnd::Complete
                } else {
                    PumpEnd::Abort
                };
            }
        }
    };

    match end {
        PumpEnd::Complete => {
            // Flush (but do NOT shut down — that would close the write direction
            // and break keep-alive). Deposit so the guard can reunite + re-pool
            // once the response is fully read.
            if write_half.flush().await.is_err() {
                guard.poison();
                return;
            }
            guard.deposit_write(write_half);
        }
        PumpEnd::Abort => {
            // Shut the write direction down so lsphp's raw body read returns short
            // (the only thing that actually stops it — there is no ABORT consumer)
            // and poison so the socket is dropped, never re-pooled. The response
            // side does not wait on `cancel`; it unblocks via its socket read
            // erroring on this shutdown or via its own read timeout, so we do not
            // need to notify here. Dropping this task's Arc<ReturnGuard> next is
            // what releases the semaphore permit.
            let _ = write_half.shutdown().await;
            guard.poison();
        }
        PumpEnd::EmbeddedBegin => {
            guard.block_embedded_begin();
            // Both directions: lsphp's body read ends at what was already written,
            // and its response writes fail, so the response side ends promptly.
            let _ = rustix::net::shutdown(write_half.as_ref(), rustix::net::Shutdown::Both);
        }
    }
}

async fn write_body_data(
    write_half: &mut OwnedWriteHalf,
    scanned: Option<&mut ScannedBodyWriter>,
    data: Bytes,
) -> Result<(), BodyWriteError> {
    match scanned {
        Some(writer) => writer.push(write_half, data).await,
        None => write_half
            .write_all(&data)
            .await
            .map_err(BodyWriteError::Io),
    }
}

/// The read side of an LSAPI response once its head is built: what the body pump
/// needs to finish the body and then settle the socket.
struct ResponseTail {
    read_half: OwnedReadHalf,
    reader: PacketReader,
    guard: Arc<ReturnGuard>,
    cancel: Arc<tokio::sync::Notify>,
    declared_len: Option<u64>,
}

/// Pump RESP_STREAM packets into the channel body, ending on RESP_END/close.
/// STDERR goes to tracing. On any error path (including the client receiver going
/// away mid-stream) we poison the guard so the connection is not reused; on a
/// clean RESP_END we deposit the read half so the guard can re-pool the socket
/// (only succeeds if the body writer also deposited its half).
///
/// `tx = None` with `sent` at the declared length is the inline tail: the consumer
/// already holds the whole body, so this only drains to RESP_END. `over_delivered`
/// carries bytes the inline drain already saw past the declared length.
async fn pump_body(
    tail: ResponseTail,
    tx: Option<Sender<Bytes, BoxError>>,
    prelude: Vec<Bytes>,
    mut sent: u64,
    mut over_delivered: bool,
) {
    let ResponseTail {
        mut read_half,
        mut reader,
        guard,
        cancel,
        declared_len,
    } = tail;
    // Whatever happens, when this task ends it wakes the body pump (the only task
    // that waits on `cancel`) in case it is still blocked on a slow/stalled/
    // abandoned upload, so it stops and drops its Arc<ReturnGuard> (freeing the
    // semaphore permit + write-half fd). On a clean RESP_END the body pump should
    // already have finished (it stops as soon as it has written `body_len` bytes);
    // on any error/disconnect this is the mechanism that prevents the permit/fd
    // leak. `notify_one` stores a permit if the pump is not currently parked, so
    // the wakeup is never lost.
    // (D1) `tx = None` means the consumer's body is COMPLETE (the declared
    // Content-Length was reached): from then on this task only DRAINS to RESP_END so
    // the socket can re-pool — the client/store/egress side is no longer waiting.
    // Over-delivery past the declared length is truncated for downstream framing
    // and poisons the LSAPI socket; under-delivery aborts the consumer body as a
    // truncated upstream response. Without Content-Length, RESP_END is the only
    // completion signal: lsphp always writes it (LSAPI_Finish_r), so CONN_CLOSE or
    // EOF before it means the worker died mid-response and the consumer body is
    // aborted, never ended cleanly (a clean end would let the page cache store the
    // truncated page).
    let mut tx = tx;
    if declared_len == Some(0) {
        tx = None;
    }
    // First emit any RESP_STREAM chunks the inline fast-path already parsed off the
    // buffer before deciding the response was too large / incomplete to inline.
    for chunk in prelude {
        match feed_chunk(&mut tx, &mut sent, declared_len, &mut over_delivered, chunk).await {
            FeedOutcome::Forwarded => {}
            FeedOutcome::ReceiverGone => {
                guard.poison();
                cancel.notify_one();
                return;
            }
        }
    }
    loop {
        match reader.next(&mut read_half).await {
            Ok(Some(frame)) => match frame.ptype {
                PacketType::RespStream => {
                    match feed_chunk(
                        &mut tx,
                        &mut sent,
                        declared_len,
                        &mut over_delivered,
                        frame.body,
                    )
                    .await
                    {
                        FeedOutcome::Forwarded => {}
                        FeedOutcome::ReceiverGone => {
                            // Receiver (client) went away. We only own the read half
                            // here, so we cannot write ABORT from this task; poison so
                            // the socket is dropped, not reused, and wake the writer.
                            guard.poison();
                            cancel.notify_one();
                            return;
                        }
                    }
                }
                PacketType::StderrStream => log_stderr(&frame.body),
                PacketType::RespEnd => {
                    if guard.embedded_begin_blocked() {
                        if let Some(tx) = tx.take() {
                            tx.abort("request body held an LSAPI request".into());
                        }
                        guard.poison();
                        cancel.notify_one();
                        return;
                    }
                    if declared_len.is_some_and(|total| sent < total) {
                        if let Some(tx) = tx.take() {
                            tx.abort("lsapi response body ended before Content-Length".into());
                        }
                        guard.poison();
                        cancel.notify_one();
                        return;
                    }
                    break;
                }
                PacketType::ConnClose => {
                    if let Some(tx) = tx.take() {
                        tx.abort("lsapi connection closed before RESP_END".into());
                    }
                    guard.poison();
                    cancel.notify_one();
                    return;
                }
                PacketType::InternalError => {
                    if let Some(tx) = tx.take() {
                        tx.abort("lsapi internal error".into());
                    }
                    guard.poison();
                    cancel.notify_one();
                    return;
                }
                _ => {}
            },
            Ok(None) => {
                if let Some(tx) = tx.take() {
                    tx.abort("lsapi response EOF before RESP_END".into());
                }
                guard.poison();
                cancel.notify_one();
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                if let Some(tx) = tx.take() {
                    tx.abort("lsapi upstream timeout".into());
                }
                guard.poison();
                cancel.notify_one();
                return;
            }
            Err(e) => {
                if let Some(tx) = tx.take() {
                    tx.abort(Box::new(e) as BoxError);
                }
                guard.poison();
                cancel.notify_one();
                return;
            }
        }
    }
    // Dropping `tx` ends the body cleanly (a no-op if the declared length already did).
    drop(tx);
    // Wake the body pump in case it is still blocked (e.g. lsphp answered before
    // draining the whole body). This is harmless if it already finished.
    cancel.notify_one();
    if !over_delivered && !reader.has_buffered() {
        // Deposit the read half so the guard can reunite + re-pool — this only
        // re-pools if the body writer also deposited its write half cleanly.
        guard.deposit_read(read_half);
    } else {
        guard.poison();
    }
}

enum FeedOutcome {
    /// Chunk forwarded (or discarded post-completion / truncated at the declared
    /// length) — keep pumping.
    Forwarded,
    /// The response consumer dropped mid-body — poison and stop.
    ReceiverGone,
}

/// Forward one RESP_STREAM chunk to the consumer, ending the consumer's body
/// (dropping the sender) the moment the declared Content-Length is reached.
async fn feed_chunk(
    tx: &mut Option<Sender<Bytes, BoxError>>,
    sent: &mut u64,
    declared_len: Option<u64>,
    over_delivered: &mut bool,
    mut chunk: Bytes,
) -> FeedOutcome {
    if let Some(total) = declared_len {
        let remaining = total.saturating_sub(*sent);
        if chunk.len() as u64 > remaining {
            *over_delivered = true;
            chunk.truncate(remaining as usize);
        }
    }
    let Some(sender) = tx.as_mut() else {
        return FeedOutcome::Forwarded; // body already complete: drain-only
    };
    if !chunk.is_empty() {
        let len = chunk.len() as u64;
        if sender.send_data(chunk).await.is_err() {
            return FeedOutcome::ReceiverGone;
        }
        *sent += len;
    }
    if declared_len.is_some_and(|total| *sent >= total) {
        *tx = None;
    }
    FeedOutcome::Forwarded
}

fn parse_response_content_length(
    headers: &[(http::HeaderName, http::HeaderValue)],
) -> Result<Option<u64>, &'static str> {
    let mut declared = None;
    for (_, raw_value) in headers
        .iter()
        .filter(|(name, _)| name.as_str().eq_ignore_ascii_case("content-length"))
    {
        let Ok(value_str) = raw_value.to_str() else {
            return Err("malformed value");
        };
        for raw in value_str.split(',') {
            let value = raw.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("malformed value");
            }
            let value = value.parse::<u64>().map_err(|_| "value overflow")?;
            match declared {
                Some(previous) if previous != value => return Err("conflicting values"),
                Some(_) => {}
                None => declared = Some(value),
            }
        }
    }
    Ok(declared)
}

/// Collect a body fully into memory, enforcing `max_body` AS FRAMES ARRIVE
/// (returns `PayloadTooLarge` the moment the accumulated size exceeds the cap, so
/// a runaway chunked body cannot OOM us). Used for the chunked (no Content-Length)
/// path where we must learn the length before sending a concrete `m_reqBodyLen`.
///
/// (#236) Every frame also reserves against the server-wide [`BodyBufferBudget`]
/// before it enters heap, so aggregate buffered memory across concurrent chunked
/// uploads is bounded by the budget rather than `connections x max_body`. Returns
/// the buffer plus its [`BodyBufferLease`] — keep the lease alive alongside the
/// buffer and exhaustion maps to 503 (server capacity), not 413.
async fn collect_to_cap(
    body: &mut hj_core::IncomingBody,
    max_body: u64,
    budget: &Arc<BodyBufferBudget>,
) -> Result<(Bytes, BodyBufferLease), HandlerError> {
    use http_body_util::BodyExt;
    let mut lease = BodyBufferLease::new(Arc::clone(budget));
    // (L8) Pre-size the collector instead of growing an empty BytesMut frame by frame: an 8 KiB
    // floor covers the common small chunked POST without the 0→8→…→8 KiB realloc chain, bounded
    // by `max_body` so a tiny cap can't over-allocate. (This is the chunked / no-Content-Length
    // path, so there is no declared length to size from — a modest fixed floor is the lever.)
    // (#317b) Allocate on the FIRST data frame instead of up front: this path also runs
    // for bodyless GET/HEAD (no Content-Length), which previously paid an unused 8 KiB.
    let mut buf = bytes::BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|e| HandlerError::BadGateway(format!("read request body: {e}")))?;
        if let Some(data) = frame.data_ref() {
            if buf.is_empty() && !data.is_empty() {
                // (L8 floor, deferred) 8 KiB covers the common small chunked POST without
                // the 0->8->... realloc chain; still bounded by `max_body`.
                buf.reserve((8 * 1024).min(max_body.max(1)) as usize);
            }
            if (buf.len() as u64) + (data.len() as u64) > max_body {
                return Err(HandlerError::PayloadTooLarge);
            }
            if !lease.reserve(data.len() as u64) {
                return Err(HandlerError::ServiceUnavailable);
            }
            buf.extend_from_slice(data);
        }
    }
    if buf.len() > i32::MAX as usize {
        return Err(HandlerError::PayloadTooLarge);
    }
    Ok((buf.freeze(), lease))
}

/// (#3) The BEGIN_REQUEST frame length-prefixes every env key/value (and every
/// known header's value) with a big-endian u16 that INCLUDES the trailing NUL.
/// A field byte-length of `u16::MAX` (65535) or more would make `len + 1` (the
/// NUL-inclusive prefix) wrap, silently truncating the prefix while the full
/// bytes are still written — desyncing lsphp's parser. So the largest safe field
/// byte-length is `u16::MAX - 1`.
const LSAPI_MAX_FIELD_LEN: usize = (u16::MAX as usize) - 1;

/// True if any `(key, value)` in `fields` has a key OR value whose byte length
/// would overflow the LSAPI u16 length prefix (see [`LSAPI_MAX_FIELD_LEN`]).
fn lsapi_fields_overflow_u16<F: WireHeader>(fields: &[F]) -> bool {
    fields
        .iter()
        .any(|f| f.name().len() > LSAPI_MAX_FIELD_LEN || f.value().len() > LSAPI_MAX_FIELD_LEN)
}

/// As [`lsapi_fields_overflow_u16`] but for the special-env (php.ini override)
/// table, whose wire key is prefixed with two control bytes (`\x01` + the
/// permission byte) before the name. The encoded keyLen is `2 + name + 1`, so the
/// name's own byte budget is two smaller than a regular field. In practice these
/// come from operator-controlled `.htaccess`, but the guard keeps the u16 length
/// prefix from silently wrapping (which would desync lsphp's parser) regardless.
fn lsapi_special_env_overflow_u16(fields: &[(SpecialEnvType, String, String)]) -> bool {
    fields.iter().any(|(_, name, value)| {
        name.len() > LSAPI_MAX_FIELD_LEN - 2 || value.len() > LSAPI_MAX_FIELD_LEN
    })
}

/// Insert or overwrite a `Content-Length` header in the wire-order header list so
/// the synthesized concrete length is visible to lsphp's header index (and a `-2`
/// re-read would still find it). Case-insensitive on the existing name.
/// Collect the request headers in wire order for lsphp's LSAPI header index
/// (the source of `getallheaders()` / `$_SERVER` HTTP_* on the SAPI side).
///
/// lsphp maps every header-block name to `HTTP_*` too, so the block is filtered by
/// the same [`crate::cgi::header_forwardable`] rule as the env table.
///
/// Non-UTF-8 header values (obs-text per RFC 7230) are accepted via lossy conversion.
fn collect_wire_headers<'r>(
    req: &'r Request,
    content_length: Option<&'r str>,
    forwarding_trusted: bool,
) -> Vec<WireField<'r>> {
    let mut headers: Vec<_> = req
        .headers()
        .iter()
        .filter(|(name, _)| {
            crate::cgi::header_forwardable(name.as_str(), forwarding_trusted)
                && !(content_length.is_some() && *name == http::header::CONTENT_LENGTH)
        })
        .map(|(name, value)| {
            let value = value.to_str().map(Cow::Borrowed).unwrap_or_else(|_| {
                Cow::Owned(String::from_utf8_lossy(value.as_bytes()).into_owned())
            });
            let known = crate::proto::known_header_index(name.as_str());
            WireField {
                name: wire_header_name(name.as_str(), known),
                value,
                known,
            }
        })
        .collect();
    if let Some(length) = content_length {
        headers.push(WireField {
            name: Cow::Borrowed("content-length"),
            value: Cow::Borrowed(length),
            known: crate::proto::known_header_index("content-length"),
        });
    }
    headers
}

/// A request header bound for lsphp's header block, with its well-known index
/// slot resolved once: the name mapping and both builder passes all need it.
struct WireField<'r> {
    name: Cow<'r, str>,
    value: Cow<'r, str>,
    known: Option<usize>,
}

impl WireHeader for WireField<'_> {
    fn name(&self) -> &str {
        &self.name
    }
    fn value(&self) -> &str {
        &self.value
    }
    fn known_index(&self) -> Option<usize> {
        self.known
    }
}

/// The name lsphp reports for a header (`getallheaders()`, #950). A well-known
/// header is sent by index slot, so the SAPI names it from its own table and the
/// name text is never read. Any other name is reported verbatim; the h1 case is
/// gone by now (the `http` crate lower-cases), so restore the conventional
/// Title-Case FPM/Apache present (`x-hub-signature-256` -> `X-Hub-Signature-256`).
/// Only `[A-Za-z0-9-]` names get here ([`crate::cgi::header_forwardable`]), so the
/// mapping is case-only: `HTTP_*` names and duplicate grouping are unchanged.
fn wire_header_name(name: &str, known: Option<usize>) -> Cow<'_, str> {
    if known.is_some() {
        return Cow::Borrowed(name);
    }
    let mut out = String::with_capacity(name.len());
    let mut start = true;
    for c in name.chars() {
        out.push(if start {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        });
        start = c == '-';
    }
    Cow::Owned(out)
}

fn log_stderr(body: &[u8]) {
    let text = String::from_utf8_lossy(body);
    for line in text.lines() {
        if !line.trim().is_empty() {
            tracing::error!(target: "lsphp.stderr", "{line}");
        }
    }
}

fn lsapi_worker_pid(body: &[u8]) -> Option<u32> {
    if body.len() != 8 || &body[..4] != b"\0PID" {
        return None;
    }
    let pid = i32::from_ne_bytes(body[4..8].try_into().expect("four-byte PID frame"));
    u32::try_from(pid).ok().filter(|pid| *pid > 0)
}

/// Incremental LSAPI packet reader over an `AsyncRead` with a per-read idle
/// timeout AND an optional absolute (total) processing deadline (Tier 1).
///
/// Reads land in a pooled buffer that stays writable until the first response-body
/// frame is taken from it. Taking one freezes the buffer: body frames are zero-copy
/// slices of it, and its memory returns to [`PACKET_BUFS`] when the last slice
/// drops, on whichever thread that happens. Control frames are copied out, so they
/// never freeze a buffer, and the next read moves the unparsed tail into a fresh
/// pooled buffer once.
struct PacketReader {
    /// Writable read buffer; the unparsed bytes are `buf[start..]`. Empty while
    /// `frozen` holds the current buffer.
    buf: Vec<u8>,
    start: usize,
    /// The current buffer once a body frame was sliced from it; the unparsed bytes
    /// are then `frozen[start..]`.
    frozen: Option<Bytes>,
    /// Per-read idle ceiling: no progress within this window -> `TimedOut`.
    timeout: Duration,
    /// Absolute total-processing deadline; reads also fail `TimedOut` once it
    /// passes. `None` disables it (only the idle `timeout` applies).
    deadline: Option<Instant>,
    /// A socket error a non-blocking [`Self::try_fill`] hit, returned by the next
    /// read that would otherwise have reached the socket (and seen it there).
    parked: Option<std::io::Error>,
}

impl PacketReader {
    /// Per-read target and pooled buffer size: lsphp delivers a whole response in
    /// one socket write on the fast path, so reading up to 64 KiB per syscall lets
    /// the sync inline-drain fast path cover bodies up to `INLINE_BODY_CAP` without
    /// falling back to the streaming pump.
    const READ_CHUNK: usize = 64 * 1024;

    /// Spare room below which a read first makes more.
    const MIN_READ_ROOM: usize = 16 * 1024;

    fn with_deadline(timeout: Duration, deadline: Option<Instant>) -> Self {
        PacketReader {
            buf: PACKET_BUFS.take_buf(0, Self::READ_CHUNK),
            start: 0,
            frozen: None,
            timeout,
            deadline,
            parked: None,
        }
    }

    fn unparsed(&self) -> &[u8] {
        let all: &[u8] = match &self.frozen {
            Some(frozen) => frozen,
            None => &self.buf,
        };
        all.get(self.start..).unwrap_or_default()
    }

    /// The full length of the packet at the head of the unparsed bytes, once its
    /// header is buffered (`try_parse` rejects an implausible one first).
    fn pending_packet_len(&self) -> usize {
        match self.header() {
            Some(header) => Self::packet_len(&header).min(crate::proto::MAX_PACKET_LEN),
            None => 0,
        }
    }

    fn header(&self) -> Option<[u8; PACKET_HEADER_LEN]> {
        self.unparsed().get(..PACKET_HEADER_LEN)?.try_into().ok()
    }

    /// The length field of a packet header, in the sender's byte order: this host's
    /// LSAPI_ENDIAN (BIG on aarch64), swapped only on a real cross-endian mismatch.
    /// See HOST_LSAPI_ENDIAN in proto.rs.
    fn packet_len(header: &[u8; PACKET_HEADER_LEN]) -> usize {
        let lb = [header[4], header[5], header[6], header[7]];
        (if header[3] & ENDIAN_BIT == HOST_LSAPI_ENDIAN {
            u32::from_le_bytes(lb)
        } else {
            u32::from_be_bytes(lb)
        }) as usize
    }

    /// Make `buf` writable with room for the next read, and for the rest of a
    /// partial packet whose header is already buffered (so a large packet is
    /// gathered in one buffer instead of being re-copied on every read).
    fn ensure_read_room(&mut self) {
        let unparsed = self.unparsed().len();
        let need = Self::MIN_READ_ROOM.max(self.pending_packet_len().saturating_sub(unparsed));
        if let Some(frozen) = self.frozen.take() {
            let tail = frozen.get(self.start..).unwrap_or_default();
            let mut buf = PACKET_BUFS.take_buf(tail.len() + need, Self::READ_CHUNK);
            buf.extend_from_slice(tail);
            self.buf = buf;
            self.start = 0;
            return;
        }
        if self.buf.capacity() - self.buf.len() < need {
            if self.start > 0 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            self.buf.reserve(need);
        }
    }

    /// Append whatever the socket already holds, WITHOUT waiting; true if bytes
    /// were appended. An error is parked for the next read rather than lost; EOF
    /// recurs on that read by itself.
    fn try_fill(&mut self, r: &OwnedReadHalf) -> bool {
        if self.parked.is_some() {
            return false;
        }
        self.ensure_read_room();
        match r.try_read_buf(&mut self.buf) {
            Ok(n) => n > 0,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                false
            }
            Err(e) => {
                self.parked = Some(e);
                false
            }
        }
    }

    /// Read the next complete LSAPI packet. Returns `Ok(None)` on clean EOF.
    async fn next<R>(&mut self, r: &mut R) -> std::io::Result<Option<LsapiFrame>>
    where
        R: AsyncReadExt + Unpin,
    {
        self.next_inner(r, true).await
    }

    /// [`Self::next`] without the idle timeout or deadline; the caller bounds the
    /// wait. Cancel-safe: buffered bytes stay buffered.
    async fn next_untimed<R>(&mut self, r: &mut R) -> std::io::Result<Option<LsapiFrame>>
    where
        R: AsyncReadExt + Unpin,
    {
        self.next_inner(r, false).await
    }

    async fn next_inner<R>(&mut self, r: &mut R, timed: bool) -> std::io::Result<Option<LsapiFrame>>
    where
        R: AsyncReadExt + Unpin,
    {
        // (LST1) Reuse ONE pinned timer across every read in this call instead of
        // allocating a fresh `tokio::time::timeout` (hence a new `Sleep`) per loop
        // iteration — a PHP response arriving in N TCP segments otherwise churns N
        // timer registrations. Reset it to the effective wake before each read.
        // Semantics are unchanged: the idle timeout restarts each read, the optional
        // total deadline is fixed, and the wait is the nearer of the two.
        let timer = tokio::time::sleep(self.timeout);
        tokio::pin!(timer);
        loop {
            if let Some(frame) = self.try_parse()? {
                return Ok(Some(frame));
            }
            let now = Instant::now();
            // If the total processing deadline already passed, fail TimedOut now.
            if let Some(dl) = self.deadline.filter(|_| timed) {
                if dl <= now {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "lsapi total processing deadline exceeded",
                    ));
                }
            }
            // Effective wake = min(now + idle timeout, total deadline).
            let idle_deadline = now + self.timeout;
            let effective = match self.deadline {
                Some(dl) => dl.min(idle_deadline),
                None => idle_deadline,
            };
            if let Some(e) = self.parked.take() {
                return Err(e);
            }
            timer
                .as_mut()
                .reset(tokio::time::Instant::from_std(effective));
            // Read straight into `buf`'s spare capacity — one copy, no tmp-then-
            // extend memcpy of every byte. `read_buf` is cancel-safe (a timer win
            // means nothing was appended), and 0 means EOF since there is spare room.
            self.ensure_read_room();
            let n = tokio::select! {
                // Prefer making read progress over firing the timer (matches the
                // old `timeout(wait, read)`, which polled the read first).
                biased;
                res = r.read_buf(&mut self.buf) => match res {
                    Ok(n) => n,
                    Err(e) => return Err(e),
                },
                _ = timer.as_mut(), if timed => {
                    // Distinguish a true deadline expiry from an idle gap only in
                    // the message; both map to GatewayTimeout/abort (504) upstream.
                    let msg = match self.deadline {
                        Some(dl) if dl <= Instant::now() => {
                            "lsapi total processing deadline exceeded"
                        }
                        _ => "lsapi read timeout",
                    };
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, msg));
                }
            };
            if n == 0 {
                // EOF. If we have a partial packet it's an error, else clean end.
                if !self.has_buffered() {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "lsapi truncated packet",
                ));
            }
        }
    }

    fn has_buffered(&self) -> bool {
        !self.unparsed().is_empty()
    }

    fn try_parse(&mut self) -> std::io::Result<Option<LsapiFrame>> {
        let Some(header) = self.header() else {
            return Ok(None);
        };
        if header[0] != VERSION_B0 || header[1] != VERSION_B1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "lsapi bad magic",
            ));
        }
        let flag = header[3];
        let total = Self::packet_len(&header);
        if !(PACKET_HEADER_LEN..=crate::proto::MAX_PACKET_LEN).contains(&total) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "lsapi implausible packet length",
            ));
        }
        if self.unparsed().len() < total {
            return Ok(None);
        }
        let ptype = PacketType::from_u8(header[2]).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "lsapi unknown packet type")
        })?;
        let body = if ptype == PacketType::RespStream && total > PACKET_HEADER_LEN {
            let body_at = self.start + PACKET_HEADER_LEN..self.start + total;
            let buf = &mut self.buf;
            self.frozen
                .get_or_insert_with(|| PACKET_BUFS.freeze(std::mem::take(buf), Self::READ_CHUNK))
                .slice(body_at)
        } else {
            Bytes::copy_from_slice(
                self.unparsed()
                    .get(PACKET_HEADER_LEN..total)
                    .unwrap_or_default(),
            )
        };
        self.start += total;
        if self.frozen.is_none() && self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
        Ok(Some(LsapiFrame { ptype, body, flag }))
    }
}

impl Drop for PacketReader {
    /// Park a writable buffer for the next reader, cleared so no byte of this
    /// response survives into it. A frozen buffer returns by itself once its last
    /// body slice drops.
    fn drop(&mut self) {
        if self.frozen.is_none() {
            PACKET_BUFS.give_buf(std::mem::take(&mut self.buf), Self::READ_CHUNK);
        }
    }
}

#[cfg(test)]
mod inline_body_tests {
    use std::time::Duration;

    use bytes::Bytes;
    use tokio::io::AsyncWriteExt;

    use super::{BUF_POOL_LOCAL, INLINE_COPY_MAX, PACKET_LOCAL, PacketReader, inline_body};
    use crate::proto::{HOST_LSAPI_ENDIAN, PACKET_HEADER_LEN, PacketType, VERSION_B0, VERSION_B1};

    fn packet(ptype: PacketType, body: &[u8]) -> Vec<u8> {
        let mut out = vec![VERSION_B0, VERSION_B1, ptype as u8, HOST_LSAPI_ENDIAN];
        out.extend_from_slice(&((PACKET_HEADER_LEN + body.len()) as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    fn stream_packet(body: &[u8]) -> Vec<u8> {
        packet(PacketType::RespStream, body)
    }

    fn pooled_len() -> usize {
        PACKET_LOCAL.with(|pool| pool.borrow().len())
    }

    fn pooled_contains(addr: *const u8) -> bool {
        PACKET_LOCAL.with(|pool| pool.borrow().iter().any(|b| b.as_ptr() == addr))
    }

    #[test]
    fn joins_and_cuts_chunks_at_the_declared_length() {
        let chunks = |parts: &[&'static [u8]]| -> Vec<Bytes> {
            parts.iter().map(|p| Bytes::from_static(p)).collect()
        };
        assert!(inline_body(Vec::new(), 0).is_empty());
        assert_eq!(
            &inline_body(chunks(&[b"abc", b"def", b"ghi"]), 9)[..],
            b"abcdefghi"
        );
        assert_eq!(
            &inline_body(chunks(&[b"abc", b"def", b"ghi"]), 7)[..],
            b"abcdefg"
        );
        assert_eq!(&inline_body(chunks(&[b"abcdef", b"xyz"]), 4)[..], b"abcd");
        assert_eq!(&inline_body(chunks(&[b"abcdef"]), 3)[..], b"abc");
        assert!(inline_body(chunks(&[b"abc"]), 0).is_empty());
    }

    // A small single chunk is copied (freeing its read buffer at once); a larger
    // one stays a slice.
    #[test]
    fn copies_small_single_chunks_and_slices_large_ones() {
        let small = Bytes::from(vec![7u8; INLINE_COPY_MAX]);
        let body = inline_body(vec![small.clone()], small.len());
        assert!(body.is_unique());
        assert_ne!(body.as_ptr(), small.as_ptr());

        let large = Bytes::from(vec![7u8; INLINE_COPY_MAX + 1]);
        let body = inline_body(vec![large.clone()], large.len());
        assert_eq!(body.as_ptr(), large.as_ptr());
    }

    // A body frame is a zero-copy slice of the read buffer, and that buffer goes
    // back to the pool only once the last such slice drops.
    #[test]
    fn a_frozen_buffer_returns_to_the_pool_after_its_last_body_slice() {
        PACKET_LOCAL.with(|pool| pool.borrow_mut().clear());
        let mut reader = PacketReader::with_deadline(Duration::from_secs(1), None);
        let base = reader.buf.as_ptr();
        reader.buf.extend_from_slice(&stream_packet(&[1u8; 128]));
        reader.buf.extend_from_slice(&stream_packet(&[2u8; 64]));
        let first = reader.try_parse().unwrap().unwrap();
        let second = reader.try_parse().unwrap().unwrap();
        assert_eq!(
            first.body.as_ptr() as usize,
            base as usize + PACKET_HEADER_LEN
        );
        assert_eq!(&second.body[..], &[2u8; 64][..]);
        drop(reader);
        drop(first);
        assert!(!pooled_contains(base), "returned while a body slice lived");
        drop(second);
        assert!(pooled_contains(base));
    }

    // Control frames are copied out, so they never freeze the buffer: it is reused
    // in place for the next read.
    #[test]
    fn control_frames_leave_the_buffer_writable() {
        let mut reader = PacketReader::with_deadline(Duration::from_secs(1), None);
        let base = reader.buf.as_ptr();
        reader
            .buf
            .extend_from_slice(&packet(PacketType::StderrStream, b"warn"));
        reader
            .buf
            .extend_from_slice(&packet(PacketType::RespEnd, b""));
        let stderr = reader.try_parse().unwrap().unwrap();
        assert_eq!(&stderr.body[..], b"warn");
        let end = reader.try_parse().unwrap().unwrap();
        assert_eq!(end.ptype, PacketType::RespEnd);
        assert!(reader.frozen.is_none());
        assert!(!reader.has_buffered());
        assert_eq!(reader.start, 0);
        reader.ensure_read_room();
        assert_eq!(reader.buf.as_ptr(), base);
    }

    // A packet cut by the end of a frozen buffer moves into a fresh buffer sized
    // for the whole packet, and completes there.
    #[test]
    fn a_packet_split_across_reads_reassembles_in_one_buffer() {
        let mut reader = PacketReader::with_deadline(Duration::from_secs(1), None);
        let big: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let tail = stream_packet(&big);
        reader.buf.extend_from_slice(&stream_packet(b"head"));
        reader.buf.extend_from_slice(&tail[..10_000]);
        let head = reader.try_parse().unwrap().unwrap();
        assert_eq!(&head.body[..], b"head");
        assert!(reader.try_parse().unwrap().is_none());
        reader.ensure_read_room();
        assert!(reader.frozen.is_none());
        assert!(reader.buf.capacity() >= tail.len());
        let room = reader.buf.as_ptr();
        reader.buf.extend_from_slice(&tail[10_000..150_000]);
        reader.ensure_read_room();
        assert_eq!(reader.buf.as_ptr(), room, "a partial packet was re-copied");
        reader.buf.extend_from_slice(&tail[150_000..]);
        let body = reader.try_parse().unwrap().unwrap();
        assert_eq!(&body.body[..], &big[..]);
        assert!(!reader.has_buffered());
    }

    #[test]
    fn malformed_headers_are_refused() {
        for bytes in [
            vec![b'X', b'S', 7, HOST_LSAPI_ENDIAN, 8, 0, 0, 0],
            vec![VERSION_B0, VERSION_B1, 7, HOST_LSAPI_ENDIAN, 4, 0, 0, 0],
            vec![VERSION_B0, VERSION_B1, 0xEE, HOST_LSAPI_ENDIAN, 8, 0, 0, 0],
            {
                let mut v = vec![VERSION_B0, VERSION_B1, 7, HOST_LSAPI_ENDIAN];
                v.extend_from_slice(&((crate::proto::MAX_PACKET_LEN + 1) as u32).to_le_bytes());
                v
            },
        ] {
            let mut reader = PacketReader::with_deadline(Duration::from_secs(1), None);
            reader.buf.extend_from_slice(&bytes);
            assert!(reader.try_parse().is_err(), "accepted {bytes:?}");
        }
    }

    // Concurrent readers on one thread each park their buffer, so the next wave
    // reuses all of them instead of allocating (and faulting in) fresh ones.
    #[test]
    fn concurrent_readers_recycle_every_buffer_up_to_the_pool_size() {
        PACKET_LOCAL.with(|pool| pool.borrow_mut().clear());
        let readers: Vec<_> = (0..BUF_POOL_LOCAL)
            .map(|_| PacketReader::with_deadline(Duration::from_secs(1), None))
            .collect();
        let mut bases: Vec<_> = readers.iter().map(|r| r.buf.as_ptr()).collect();
        drop(readers);
        assert_eq!(pooled_len(), BUF_POOL_LOCAL);

        let again: Vec<_> = (0..BUF_POOL_LOCAL)
            .map(|_| PacketReader::with_deadline(Duration::from_secs(1), None))
            .collect();
        for reader in &again {
            let at = bases.iter().position(|&b| b == reader.buf.as_ptr());
            assert!(
                at.is_some(),
                "a reader allocated instead of reusing a parked buffer"
            );
            bases.swap_remove(at.unwrap());
        }
    }

    // A read with buffered bytes and room to spare reads into that room instead of
    // growing the buffer past the recyclable size.
    #[test]
    fn a_read_with_room_left_does_not_grow_the_buffer() {
        let mut reader = PacketReader::with_deadline(Duration::from_secs(1), None);
        let base = reader.buf.as_ptr();
        reader.buf.extend_from_slice(&[0u8; 20 * 1024]);
        reader.ensure_read_room();
        assert_eq!(reader.buf.as_ptr(), base);
        assert_eq!(reader.buf.capacity(), PacketReader::READ_CHUNK);
    }

    #[tokio::test]
    async fn try_fill_takes_only_what_the_socket_already_holds() {
        let (ours, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let (mut read_half, _write_half) = ours.into_split();
        let mut reader = PacketReader::with_deadline(Duration::from_secs(1), None);

        peer.write_all(&stream_packet(b"queued")).await.unwrap();
        read_half.readable().await.unwrap();
        assert!(reader.try_fill(&read_half));
        let frame = reader.try_parse().unwrap().unwrap();
        assert_eq!(&frame.body[..], b"queued");
        assert!(
            !reader.try_fill(&read_half),
            "nothing queued: must not wait"
        );

        drop(peer);
        read_half.readable().await.unwrap();
        assert!(!reader.try_fill(&read_half));
        assert!(reader.next(&mut read_half).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn next_reads_body_frames_across_socket_writes() {
        let (ours, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let (mut read_half, _write_half) = ours.into_split();
        let mut reader = PacketReader::with_deadline(Duration::from_secs(5), None);
        let body: Vec<u8> = (0..150_000u32).map(|i| (i * 7) as u8).collect();
        let wire = [stream_packet(&body), packet(PacketType::RespEnd, b"")].concat();
        let writer = tokio::spawn(async move {
            for part in wire.chunks(9_973) {
                peer.write_all(part).await.unwrap();
            }
            peer
        });
        let frame = reader.next(&mut read_half).await.unwrap().unwrap();
        assert_eq!(frame.ptype, PacketType::RespStream);
        assert_eq!(&frame.body[..], &body[..]);
        let end = reader.next(&mut read_half).await.unwrap().unwrap();
        assert_eq!(end.ptype, PacketType::RespEnd);
        drop(writer.await.unwrap());
        assert!(reader.next(&mut read_half).await.unwrap().is_none());
    }
}

#[cfg(test)]
mod overflow_tests {
    use super::{LSAPI_MAX_FIELD_LEN, lsapi_fields_overflow_u16};

    #[test]
    fn fields_within_u16_are_ok() {
        let fields = vec![
            ("HTTP_X_PAD".to_string(), "A".repeat(LSAPI_MAX_FIELD_LEN)),
            ("REQUEST_METHOD".to_string(), "GET".to_string()),
        ];
        assert!(!lsapi_fields_overflow_u16(&fields));
    }

    #[test]
    fn value_one_past_limit_overflows() {
        // 65535 bytes -> prefix `len + 1` = 65536 wraps to 0: must be rejected.
        let fields = vec![(
            "HTTP_X_PAD".to_string(),
            "A".repeat(LSAPI_MAX_FIELD_LEN + 1),
        )];
        assert!(lsapi_fields_overflow_u16(&fields));
    }

    #[test]
    fn oversized_value_like_70k_header_overflows() {
        // The audit's concrete case: `X-Pad: <70000 'A'>` mirrored to HTTP_X_PAD.
        let fields = vec![("HTTP_X_PAD".to_string(), "A".repeat(70000))];
        assert!(lsapi_fields_overflow_u16(&fields));
    }

    #[test]
    fn oversized_key_overflows() {
        let fields = vec![("X".repeat(70000), "v".to_string())];
        assert!(lsapi_fields_overflow_u16(&fields));
    }
}

#[cfg(test)]
mod body_budget_tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use hj_core::{HandlerError, IncomingBody};
    use http_body_util::BodyExt;

    use super::{BodyBufferBudget, collect_to_cap};

    /// A single-frame body of `len` bytes (one data frame => one budget acquire).
    fn body_of(len: usize) -> IncomingBody {
        http_body_util::Full::<Bytes>::new(vec![0u8; len].into())
            .map_err(|e| Box::new(e) as hj_core::BoxError)
            .boxed()
    }

    // (#236) Concurrent chunked uploads must be bounded by the server-wide
    // budget, not by connections x max_body.
    #[tokio::test]
    async fn concurrent_bodies_respect_global_budget() {
        let budget = Arc::new(BodyBufferBudget::new(1024 * 1024)); // 1 MiB total
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let b = budget.clone();
            tasks.push(tokio::spawn(async move {
                // Each upload wants 512 KiB against a 1 MiB shared budget: at
                // most two can ever be resident at once.
                collect_to_cap(&mut body_of(512 * 1024), 16 * 1024 * 1024, &b).await
            }));
        }
        let (mut ok, mut unavailable) = (0usize, 0usize);
        let mut leases = Vec::new();
        for t in tasks {
            match t.await.unwrap() {
                Ok((_, lease)) => {
                    ok += 1;
                    leases.push(lease);
                }
                Err(HandlerError::ServiceUnavailable) => unavailable += 1,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert_eq!(ok + unavailable, 8);
        assert!(unavailable >= 1, "budget must reject when exhausted");
        assert!(ok >= 1, "budget must still admit under the cap");
        drop(leases);
        assert_eq!(budget.in_flight(), 0, "leases must release exactly once");
    }

    #[tokio::test]
    async fn small_body_admits_and_releases() {
        let budget = Arc::new(BodyBufferBudget::new(64 * 1024));
        let (buf, lease) = collect_to_cap(&mut body_of(16 * 1024), 1024 * 1024, &budget)
            .await
            .unwrap();
        assert_eq!(buf.len(), 16 * 1024);
        assert_eq!(budget.in_flight(), 16 * 1024);
        drop(lease);
        assert_eq!(budget.in_flight(), 0);
    }

    #[tokio::test]
    async fn per_request_cap_still_wins_over_budget() {
        let budget = Arc::new(BodyBufferBudget::new(u64::MAX));
        let err = collect_to_cap(&mut body_of(2 * 1024 * 1024), 1024 * 1024, &budget)
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::PayloadTooLarge));
    }

    #[test]
    fn zero_budget_disables_accounting() {
        let budget = BodyBufferBudget::new(0);
        assert!(budget.try_acquire(u64::MAX / 2));
        assert_eq!(budget.in_flight(), 0);
    }
}

#[cfg(test)]
mod wire_header_tests {
    use super::{collect_wire_headers, empty_incoming_body};

    // (#8 httpoxy / CVE-2016-5385) The client `Proxy` header must never reach
    // lsphp's wire header index, where it would become HTTP_PROXY in $_SERVER.
    #[test]
    fn collect_wire_headers_drops_proxy() {
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "forum.example")
            .header("Proxy", "http://evil/")
            .header("User-Agent", "curl/8")
            .body(empty_incoming_body())
            .unwrap();
        let headers = collect_wire_headers(&req, None, true);
        assert!(
            !headers.iter().any(|h| h.name.eq_ignore_ascii_case("proxy")),
            "Proxy header must be stripped from the LSAPI wire header index"
        );
        // Benign headers still pass through.
        assert!(
            headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("user-agent"))
        );
        assert!(headers.iter().any(|h| h.name.eq_ignore_ascii_case("host")));
    }

    #[test]
    fn collect_wire_headers_drops_underscore_names_and_untrusted_forwarding() {
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "forum.example")
            .header("User-Agent", "curl/8")
            .header("X_Real_Ip", "127.0.0.1")
            .header("X_Forwarded_For", "127.0.0.1")
            .header("CF-Connecting-IP", "198.51.100.9")
            .body(empty_incoming_body())
            .unwrap();
        let has = |headers: &[super::WireField<'_>], name: &str| {
            headers.iter().any(|h| h.name.eq_ignore_ascii_case(name))
        };
        for trusted in [false, true] {
            let headers = collect_wire_headers(&req, None, trusted);
            assert!(!has(&headers, "x_real_ip"), "trusted={trusted}");
            assert!(!has(&headers, "x_forwarded_for"), "trusted={trusted}");
            assert!(has(&headers, "user-agent"));
            assert_eq!(has(&headers, "cf-connecting-ip"), trusted);
        }
    }

    // (#990) Carrying each header's slot resolved once encodes the same packet as
    // resolving it in the builder.
    #[test]
    fn cached_header_slots_encode_identically() {
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Host", "forum.example")
            .header("User-Agent", "curl/8")
            .header("x-hub-signature-256", "sha256=abc")
            .header("Cookie", "a=1")
            .header("dnt", "1")
            .header("Accept-Encoding", "zstd")
            .body(empty_incoming_body())
            .unwrap();
        let fields = collect_wire_headers(&req, Some("3"), true);
        let tuples: Vec<(String, String)> = fields
            .iter()
            .map(|h| (h.name.to_string(), h.value.to_string()))
            .collect();
        let env = [("REQUEST_METHOD", "POST"), ("SCRIPT_NAME", "/index.php")];
        assert_eq!(
            crate::proto::build_begin_request_framed(&env, &[], &fields, 3),
            crate::proto::build_begin_request_framed(&env, &[], &tuples, 3)
        );
    }

    #[test]
    fn concrete_body_length_does_not_mutate_the_request_head() {
        let req = http::Request::builder()
            .uri("/index.php")
            .header("Content-Length", "malformed")
            .body(empty_incoming_body())
            .unwrap();
        let headers = collect_wire_headers(&req, Some("3"), true);
        let lengths: Vec<_> = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
            .map(|h| (h.value.as_ref(), h.known))
            .collect();
        assert_eq!(
            lengths,
            [("3", crate::proto::known_header_index("content-length"))]
        );
        assert_eq!(req.headers()[http::header::CONTENT_LENGTH], "malformed");
    }
}

#[cfg(test)]
mod response_length_tests {
    use super::parse_response_content_length;

    fn headers(values: &[&str]) -> Vec<(http::HeaderName, http::HeaderValue)> {
        values
            .iter()
            .map(|value| {
                (
                    http::header::HeaderName::from_static("content-length"),
                    http::HeaderValue::from_str(value).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn accepts_and_coalesces_identical_values() {
        assert_eq!(parse_response_content_length(&[]).unwrap(), None);
        assert_eq!(
            parse_response_content_length(&headers(&["003", "3", "3, 3"])).unwrap(),
            Some(3)
        );
    }

    #[test]
    fn rejects_conflicting_malformed_and_overflow_values() {
        assert!(parse_response_content_length(&headers(&["3", "4"])).is_err());
        assert!(parse_response_content_length(&headers(&["3, 4"])).is_err());
        for malformed in ["", "+3", "-1", "3x", "3,,3", "18446744073709551616"] {
            assert!(
                parse_response_content_length(&headers(&[malformed])).is_err(),
                "accepted malformed value {malformed:?}"
            );
        }
    }
}

#[cfg(test)]
mod collapse_rel_tests {
    use super::collapse_rel;
    use std::path::PathBuf;

    #[test]
    fn collapses_dot_dot_and_confines_to_root() {
        // `..` can never escape: a leading `..` is dropped, an interior one pops.
        assert_eq!(
            collapse_rel("../../etc/passwd"),
            PathBuf::from("etc/passwd")
        );
        assert_eq!(collapse_rel("a/../b"), PathBuf::from("b"));
        assert_eq!(collapse_rel("a/./b/c.php"), PathBuf::from("a/b/c.php"));
        assert_eq!(collapse_rel("a/b/../../../../x"), PathBuf::from("x"));
        // A clean path is unchanged; empty stays empty (root).
        assert_eq!(
            collapse_rel("dir/index.php"),
            PathBuf::from("dir/index.php")
        );
        assert_eq!(collapse_rel(""), PathBuf::from(""));
        // `root.join(collapsed)` therefore stays under root.
        let root = PathBuf::from("/var/www");
        assert!(
            root.join(collapse_rel("../../etc/passwd"))
                .starts_with(&root)
        );
    }
}

#[cfg(test)]
mod retry_tag_tests {
    use super::*;

    #[test]
    fn tag_retry_stamps_only_on_success_after_retry() {
        // #133: a first-attempt success carries no retry marker; a success AFTER a
        // retry is tagged with the retry kind; an error is passed through untagged.
        let ok = || {
            http::Response::builder()
                .status(200)
                .body(hj_core::Body::Empty)
                .unwrap()
        };

        // First attempt (no retry): no marker.
        let r = tag_retry(Ok(ok()), None).unwrap();
        assert!(r.extensions().get::<LsapiRetryInfo>().is_none());

        // Success after a PreFlush retry: marker present with the right label.
        let r = tag_retry(Ok(ok()), Some(RetryKind::PreFlush)).unwrap();
        assert_eq!(
            r.extensions().get::<LsapiRetryInfo>().unwrap().kind,
            "preflush"
        );

        // Success after an IdempotentReset retry.
        let r = tag_retry(Ok(ok()), Some(RetryKind::IdempotentReset)).unwrap();
        assert_eq!(
            r.extensions().get::<LsapiRetryInfo>().unwrap().kind,
            "idempotent_reset"
        );

        // An error is passed through unchanged even if a retry happened.
        let e = tag_retry(
            Err(HandlerError::ServiceUnavailable),
            Some(RetryKind::PreFlush),
        );
        assert!(matches!(e, Err(HandlerError::ServiceUnavailable)));
    }
}

#[cfg(test)]
mod worker_pid_tests {
    use super::lsapi_worker_pid;

    #[test]
    fn accepts_only_exact_positive_native_pid_frames() {
        let mut frame = [0u8; 8];
        frame[..4].copy_from_slice(b"\0PID");
        frame[4..].copy_from_slice(&1234i32.to_ne_bytes());
        assert_eq!(lsapi_worker_pid(&frame), Some(1234));

        frame[4..].copy_from_slice(&0i32.to_ne_bytes());
        assert_eq!(lsapi_worker_pid(&frame), None);
        frame[4..].copy_from_slice(&(-1i32).to_ne_bytes());
        assert_eq!(lsapi_worker_pid(&frame), None);
        assert_eq!(lsapi_worker_pid(b"\0PIDshort"), None);
        assert_eq!(lsapi_worker_pid(b"stderr!"), None);
    }
}
