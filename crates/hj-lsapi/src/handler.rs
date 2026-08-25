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
//! Only an exact match deposits the write half for re-pooling.
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

use crate::cgi::CgiEnvBuilder;
use crate::monitor::{InFlightGuard, Monitor};
use crate::pool::{DialAdmission, LsapiPool, ReturnGuard, TrialGuard};
use crate::proto::{
    ENDIAN_BIT, HOST_LSAPI_ENDIAN, LsapiFrame, PACKET_HEADER_LEN, PacketType, RespHeader,
    SpecialEnvType, VERSION_B0, VERSION_B1, build_begin_request_framed_into,
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
const INLINE_BODY_CAP: usize = 64 * 1024;

/// Short backoff before each idempotent-reset retry. During a recycle BURST the
/// first retry's fresh dial can ALSO re-hit a pool still mid-respawn; a brief pause
/// lets the recycle resolve / a fresh worker become available. Worst case
/// ~2×25ms = 50ms of added latency on a failing request.
const IDEMPOTENT_RETRY_BACKOFF: Duration = Duration::from_millis(25);

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
}

impl RetryKind {
    /// Stable label for the php-slow log's retry column (#133).
    fn as_log_str(self) -> &'static str {
        match self {
            RetryKind::PreFlush => "preflush",
            RetryKind::IdempotentReset => "idempotent_reset",
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

#[async_trait]
impl Handler for Lsapi {
    async fn handle(&self, ctx: &mut ReqCtx, mut req: Request) -> Result<Response, HandlerError> {
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
        #[allow(unused_variables, unused_assignments)]
        // Held to the END of this fn (never read, only dropped): the RAII lease
        // keeps the server-wide buffered-body reservation alive while the buffer
        // is handed to lsphp.
        let _body_lease: Option<BodyBufferLease>;
        let buffered: Option<Bytes> = match declared_len {
            Some(_) => {
                _body_lease = None;
                None
            }
            None => {
                let (b, lease) =
                    collect_to_cap(req.body_mut(), self.max_body, &self.body_budget).await?;
                _body_lease = Some(lease);
                Some(b)
            }
        };
        if let Some(b) = &buffered {
            let value = http::HeaderValue::from_str(&b.len().to_string())
                .map_err(|_| HandlerError::PayloadTooLarge)?;
            req.headers_mut()
                .insert(http::header::CONTENT_LENGTH, value);
        }

        // Build the CGI env + raw wire headers (both borrow `req`). lsphp reads
        // $_SERVER HTTP_* / getallheaders() from the LSAPI header index over this
        // header block, NOT the CGI env table, so they are sent there too.
        let env = builder.build(&req, ctx);
        let mut headers = collect_wire_headers(&req);
        // Synthesize Content-Length for the chunked path so lsphp's CGI env /
        // header index agree (and a -2 re-read still finds a concrete value).
        if let Some(b) = &buffered {
            inject_content_length(&mut headers, b.len());
        }

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
            return Err(HandlerError::RequestHeaderFieldsTooLarge);
        }

        // EARLY 413: if the client DECLARED a Content-Length over the cap, reject
        // it before touching the pool (no connection churn). The chunked path has
        // already enforced the cap incrementally inside collect_to_cap above.
        if let Some(len) = declared_len {
            if len > self.max_body {
                return Err(HandlerError::PayloadTooLarge);
            }
            // We also refuse anything that cannot fit lsphp's i32 m_reqBodyLen.
            if len > i32::MAX as u64 {
                return Err(HandlerError::PayloadTooLarge);
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
                self.dispatch_buffered_retrying(
                    idempotent,
                    is_head,
                    &begin,
                    buffered,
                    &mut inflight,
                )
                .await
            }
            None => {
                let (_parts, body) = req.into_parts();
                self.dispatch_streaming_retrying(
                    idempotent,
                    is_head,
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
        result
    }
}

// Recycled BEGIN_REQUEST encode buffer, one per worker thread. Reused across
// requests on the same thread so the framed packet encode does not allocate (and
// page-fault) a fresh ~1-2 KB buffer every PHP request. `build_begin_request_framed_into`
// clears it before each encode, so a recycled buffer leaks nothing of the prior
// request. Capacity is bounded on return so one giant-header request can't bloat
// the cached buffer permanently.
thread_local! {
    static BEGIN_BUF: std::cell::RefCell<Option<bytes::BytesMut>> =
        const { std::cell::RefCell::new(None) };
}

/// Largest recycled begin-buffer capacity we keep between requests (a request that
/// grew it past this is encoded then the oversized buffer is dropped, not cached).
const BEGIN_BUF_KEEP_CAP: usize = 16 * 1024;

/// Take the thread-local begin buffer (or a fresh one). The borrow is synchronous
/// (never held across an `.await`), so it cannot conflict with another task that
/// the runtime parks onto this thread.
fn take_begin_buf() -> bytes::BytesMut {
    BEGIN_BUF
        .with(|b| b.borrow_mut().take())
        .unwrap_or_default()
}

/// Return the begin buffer for reuse, dropping it if it grew oversized.
fn return_begin_buf(buf: bytes::BytesMut) {
    if buf.capacity() <= BEGIN_BUF_KEEP_CAP {
        BEGIN_BUF.with(|b| *b.borrow_mut() = Some(buf));
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
                .dispatch_streaming(idempotent, is_head, begin, body_len, body, &mut *inflight)
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
        begin: &[u8],
        body: Bytes,
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
                .dispatch_buffered(idempotent, is_head, begin, body, &mut *inflight)
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
        begin: &[u8],
        body_len: i32,
        body: hj_core::IncomingBody,
        inflight: &mut Option<InFlightGuard>,
    ) -> Attempt<hj_core::IncomingBody> {
        // PRE-FLUSH (replayable): pool acquire. On failure, hand the (untouched)
        // body back so the caller can retry on a fresh connection.
        let acq_start = Instant::now();
        let mut conn = match self.pool.acquire().await {
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
        if let Err(e) = conn.stream_mut().write_all(begin).await {
            conn.poison();
            return Attempt::Retry {
                body,
                reason: HandlerError::BadGateway(format!("lsapi write begin: {e}")),
                kind: RetryKind::PreFlush,
            };
        }
        if let Err(e) = conn.stream_mut().flush().await {
            conn.poison();
            return Attempt::Retry {
                body,
                reason: HandlerError::BadGateway(format!("lsapi flush begin: {e}")),
                kind: RetryKind::PreFlush,
            };
        }
        // === COMMITTED: from here the request is non-replayable. ===

        // Tier 2 in-flight clock starts HERE — request committed to lsphp (BEGIN_REQUEST
        // flushed), so the pool acquire above is excluded (#47). On an idempotent-reset
        // retry this replaces the prior attempt's guard.
        *inflight = self.monitor.as_ref().map(|m| m.inflight().begin());

        let (read_half, write_half, guard) = conn.into_split();
        let guard = Arc::new(guard);

        // Cancellation shared between the two halves. The response side notifies
        // it when it finishes (clean RESP_END, error, client disconnect, timeout)
        // so a body pump still blocked on a slow/stalled/abandoned upload unblocks
        // and drops its Arc<ReturnGuard> — releasing the semaphore permit and the
        // write-half fd instead of leaking them.
        let cancel = Arc::new(tokio::sync::Notify::new());

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
        tokio::spawn(async move {
            pump_request_body(PumpArgs {
                body,
                write_half,
                guard: body_guard,
                cancel: body_cancel,
                body_len: body_len as i64,
                max_body,
                idle_timeout: write_timeout,
            })
            .await;
        });

        // (b) RESPONSE TASK is THIS function continuing on the read half. We read
        //     the first response packet immediately (no await on the writer), then
        //     hand the read half + guard to the streaming body pump. The body pump
        //     observes `cancel` once the response side is done.
        let sent_at = Instant::now();
        match self
            .read_response(read_half, guard, cancel, acquire, sent_at, is_head)
            .await
        {
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
        begin: &[u8],
        body: Bytes,
        inflight: &mut Option<InFlightGuard>,
    ) -> Attempt<Bytes> {
        // PRE-FLUSH (replayable): pool acquire. Hand the buffered body back on a
        // failure so the caller can replay it on a fresh connection.
        let acq_start = Instant::now();
        let mut conn = match self.pool.acquire().await {
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
        if let Err(e) = conn.stream_mut().write_all(begin).await {
            conn.poison();
            return Attempt::Retry {
                body,
                reason: HandlerError::BadGateway(format!("lsapi write begin: {e}")),
                kind: RetryKind::PreFlush,
            };
        }
        if let Err(e) = conn.stream_mut().flush().await {
            conn.poison();
            return Attempt::Retry {
                body,
                reason: HandlerError::BadGateway(format!("lsapi flush begin: {e}")),
                kind: RetryKind::PreFlush,
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
                s.write_all(&body).await?;
                s.flush().await
            };
            match tokio::time::timeout(self.read_timeout, write_body).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
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
    async fn read_response(
        &self,
        mut read_half: OwnedReadHalf,
        guard: Arc<ReturnGuard>,
        cancel: Arc<tokio::sync::Notify>,
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
        let deadline = self.max_process_time.map(|d| Instant::now() + d);
        let mut reader = PacketReader::with_deadline(self.read_timeout, deadline);
        let mut accept_worker_pid = true;
        let resp_header = loop {
            match reader.next(&mut read_half).await {
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

        let declared_len = match parse_response_content_length(&resp_header.headers) {
            Ok(len) => len,
            Err(reason) => {
                fail(&guard, &cancel);
                return Err(ReadFail::terminal(HandlerError::BadGateway(format!(
                    "invalid lsapi Content-Length: {reason}"
                ))));
            }
        };

        // Build the response head.
        let status = http::StatusCode::from_u16(resp_header.status).unwrap_or(http::StatusCode::OK);
        let mut builder = http::Response::builder().status(status);
        let mut has_status_header = None;
        for (name, value) in &resp_header.headers {
            // PHP may emit a "Status: 404 Not Found" header.
            if name.eq_ignore_ascii_case("status") {
                if let Some(code) = value
                    .split_whitespace()
                    .next()
                    .and_then(|c| c.parse::<u16>().ok())
                    .and_then(|c| http::StatusCode::from_u16(c).ok())
                {
                    has_status_header = Some(code);
                }
                continue;
            }
            // Parsed and normalized once above. Re-emitting every upstream field
            // would preserve ambiguous duplicates in the downstream HeaderMap.
            if name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                http::header::HeaderValue::from_str(value),
            ) {
                builder = builder.header(hn, hv);
            }
        }
        if let Some(code) = has_status_header {
            builder = builder.status(code);
        }
        if let Some(len) = declared_len {
            builder = builder.header(http::header::CONTENT_LENGTH, len.to_string());
        }
        let status = has_status_header.unwrap_or(status);
        let enforced_len = if hj_core::response_body_forbidden(is_head, status) {
            None
        } else {
            declared_len
        };

        // FAST PATH (the common small PHP response): lsphp usually delivers the
        // whole response (RESP_HEADER + RESP_STREAM + RESP_END) in one socket write,
        // so the body packets are ALREADY in the reader's buffer after the header
        // read. Drain them with the SYNC `try_parse` (no extra socket read / await)
        // and, if the whole body is in hand, return a `Body::Full` — skipping the
        // per-request response Channel + a spawned pump task (a real cross-core hop
        // between the LSAPI read and the h2/h1 send). The moment more bytes are
        // needed (Ok(None)) or the body exceeds INLINE_BODY_CAP, fall back to the
        // streaming pump, handing it the chunks already collected as a `prelude` so
        // none are lost. Re-pool / poison handling mirrors the streaming path.
        let mut prelude: Vec<Bytes> = Vec::new();
        let mut prelude_len: usize = 0;
        enum InlineEnd {
            Repool, // clean RESP_END: deposit the read half so the socket re-pools
            Poison, // ConnClose: serve what we have but drop the socket
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
                // No more COMPLETE packet is buffered — a socket read is needed, so
                // hand off to the async streaming pump (with the prelude).
                Ok(None) => break None,
                Err(e) => {
                    fail(&guard, &cancel);
                    return Err(ReadFail::terminal(HandlerError::BadGateway(format!(
                        "lsapi resp parse: {e}"
                    ))));
                }
            }
        };

        if let Some(end) = inline_end {
            let mut body = match prelude.len() {
                0 => Bytes::new(),
                1 => prelude.into_iter().next().expect("len==1"),
                _ => {
                    let mut buf = bytes::BytesMut::with_capacity(prelude_len);
                    for c in &prelude {
                        buf.extend_from_slice(c);
                    }
                    buf.freeze()
                }
            };
            let over_delivered = enforced_len.is_some_and(|len| body.len() as u64 > len);
            if let Some(len) = enforced_len {
                if (body.len() as u64) < len {
                    fail(&guard, &cancel);
                    return Err(ReadFail::terminal(HandlerError::BadGateway(format!(
                        "lsapi response body truncated: declared {len} bytes, received {}",
                        body.len()
                    ))));
                }
                if over_delivered {
                    body.truncate(len as usize);
                }
            }
            match end {
                // Only a response that ended cleanly and honored its declared
                // length may return the LSAPI socket to the pool.
                InlineEnd::Repool if !over_delivered => {
                    guard.deposit_read(read_half);
                    cancel.notify_one();
                }
                InlineEnd::Repool | InlineEnd::Poison => fail(&guard, &cancel),
            }
            let mut response = builder.body(Body::Full(body)).map_err(|e| {
                ReadFail::terminal(HandlerError::Other(format!("build response: {e}")))
            })?;
            response
                .extensions_mut()
                .insert(LsapiTiming { acquire, ttfb });
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
            read_half,
            reader,
            tx,
            guard,
            cancel,
            prelude,
            enforced_len,
        ));

        let boxed: BoxBody<Bytes, BoxError> = BoxBody::new(channel);
        let mut response = builder
            .body(Body::Stream(boxed))
            .map_err(|e| ReadFail::terminal(HandlerError::Other(format!("build response: {e}"))))?;
        response
            .extensions_mut()
            .insert(LsapiTiming { acquire, ttfb });
        Ok(response)
    }
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
}

/// Why the body pump stopped, deciding whether the write half is re-poolable.
enum PumpEnd {
    /// Wrote exactly `body_len` bytes and the body ended cleanly: depositable.
    Complete,
    /// Anything else (short body, over-delivery, cap, IO/body error, cancel,
    /// idle timeout): the socket is desynced/dead and must NOT be re-pooled.
    Abort,
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
    } = args;
    let cap = (max_body as i64).min(body_len.max(0));
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
                        w = write_half.write_all(&data) => w,
                        _ = timer.as_mut() => break PumpEnd::Abort, // write idle timeout
                    };
                    match wrote {
                        Ok(()) => {}
                        // (item 7) Surface a broken-pipe/closed-socket write to lsphp
                        // instead of silently aborting the upload with no trace.
                        Err(e) => {
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
    }
}

/// Pump RESP_STREAM packets into the channel body, ending on RESP_END/close.
/// STDERR goes to tracing. On any error path (including the client receiver going
/// away mid-stream) we poison the guard so the connection is not reused; on a
/// clean RESP_END we deposit the read half so the guard can re-pool the socket
/// (only succeeds if the body writer also deposited its half).
async fn pump_body(
    mut read_half: OwnedReadHalf,
    mut reader: PacketReader,
    tx: Sender<Bytes, BoxError>,
    guard: Arc<ReturnGuard>,
    cancel: Arc<tokio::sync::Notify>,
    prelude: Vec<Bytes>,
    declared_len: Option<u64>,
) {
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
    // truncated upstream response. Without Content-Length, RESP_END remains the
    // authoritative boundary.
    let mut tx = Some(tx);
    let mut sent: u64 = 0;
    let mut over_delivered = false;
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
    let mut clean_end = false;
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
                    if declared_len.is_some_and(|total| sent < total) {
                        if let Some(tx) = tx.take() {
                            tx.abort("lsapi response body ended before Content-Length".into());
                        }
                        guard.poison();
                        cancel.notify_one();
                        return;
                    }
                    clean_end = true;
                    break;
                }
                PacketType::ConnClose => {
                    if declared_len.is_some_and(|total| sent < total) {
                        if let Some(tx) = tx.take() {
                            tx.abort("lsapi response body closed before Content-Length".into());
                        }
                    }
                    guard.poison();
                    break;
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
                if declared_len.is_some_and(|total| sent < total) {
                    if let Some(tx) = tx.take() {
                        tx.abort("lsapi response EOF before Content-Length".into());
                    }
                }
                guard.poison();
                break;
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
    if clean_end && !over_delivered {
        // Deposit the read half so the guard can reunite + re-pool — this only
        // re-pools if the body writer also deposited its write half cleanly.
        guard.deposit_read(read_half);
    }
    // On a non-clean end the guard was poisoned above; dropping it (and the
    // read half) closes the socket.
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
    headers: &[(String, String)],
) -> Result<Option<u64>, &'static str> {
    let mut declared = None;
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        for raw in value.split(',') {
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
    let initial = (8 * 1024).min(max_body) as usize;
    let mut buf = bytes::BytesMut::with_capacity(initial);
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|e| HandlerError::BadGateway(format!("read request body: {e}")))?;
        if let Some(data) = frame.data_ref() {
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
fn lsapi_fields_overflow_u16<K: AsRef<str>, V: AsRef<str>>(fields: &[(K, V)]) -> bool {
    fields.iter().any(|(k, v)| {
        k.as_ref().len() > LSAPI_MAX_FIELD_LEN || v.as_ref().len() > LSAPI_MAX_FIELD_LEN
    })
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
fn inject_content_length<'r>(headers: &mut Vec<(Cow<'r, str>, Cow<'r, str>)>, len: usize) {
    let value = len.to_string();
    if let Some(slot) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        slot.1 = Cow::Owned(value);
    } else {
        headers.push((Cow::Borrowed("content-length"), Cow::Owned(value)));
    }
}

/// Collect the request headers in wire order for lsphp's LSAPI header index
/// (the source of `getallheaders()` / `$_SERVER` HTTP_* on the SAPI side).
///
/// httpoxy (CVE-2016-5385): the client `Proxy` header is dropped here — it would
/// otherwise surface as HTTP_PROXY and let an attacker hijack CGI-mode PHP's
/// outbound calls. This mirrors the same drop in [`CgiEnvBuilder::build`] for the
/// env table; both LSAPI feeds must be filtered.
///
/// Non-UTF-8 header values (obs-text per RFC 7230) are accepted via lossy conversion.
fn collect_wire_headers(req: &Request) -> Vec<(Cow<'_, str>, Cow<'_, str>)> {
    req.headers()
        .iter()
        .filter(|(name, _)| !name.as_str().eq_ignore_ascii_case("proxy"))
        .map(|(name, value)| {
            let v = value.to_str().map(Cow::Borrowed).unwrap_or_else(|_| {
                Cow::Owned(String::from_utf8_lossy(value.as_bytes()).into_owned())
            });
            (Cow::Borrowed(name.as_str()), v)
        })
        .collect()
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
struct PacketReader {
    buf: bytes::BytesMut,
    /// Per-read idle ceiling: no progress within this window -> `TimedOut`.
    timeout: Duration,
    /// Absolute total-processing deadline; reads also fail `TimedOut` once it
    /// passes. `None` disables it (only the idle `timeout` applies).
    deadline: Option<Instant>,
}

impl PacketReader {
    /// Build a reader with a per-read idle `timeout` and an optional Tier 1
    /// total-processing `deadline` (`None` = only the idle timeout applies).
    /// Per-read target: lsphp delivers a whole response in one socket write on the
    /// fast path, so reading up to 64 KiB per syscall (instead of a 16 KiB stack
    /// buffer copied into `buf`) lets the sync inline-drain fast path actually
    /// cover bodies up to `INLINE_BODY_CAP` — a 60 KiB page previously exhausted
    /// the buffer at ~16 KiB at header-parse time and fell back to the streaming
    /// pump (a spawn + per-chunk channel hops). Also the initial capacity: 8 KiB
    /// was outgrown by nearly every page render, costing a realloc per request.
    const READ_CHUNK: usize = 64 * 1024;

    fn with_deadline(timeout: Duration, deadline: Option<Instant>) -> Self {
        PacketReader {
            buf: bytes::BytesMut::with_capacity(Self::READ_CHUNK),
            timeout,
            deadline,
        }
    }

    /// Read the next complete LSAPI packet. Returns `Ok(None)` on clean EOF.
    async fn next<R>(&mut self, r: &mut R) -> std::io::Result<Option<LsapiFrame>>
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
            if let Some(dl) = self.deadline {
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
            timer
                .as_mut()
                .reset(tokio::time::Instant::from_std(effective));
            // Read straight into `buf`'s spare capacity — one copy, no tmp-then-
            // extend memcpy of every byte. `read_buf` is cancel-safe (a timer win
            // means nothing was appended), and 0 means EOF since we just reserved.
            self.buf.reserve(Self::READ_CHUNK);
            let n = tokio::select! {
                // Prefer making read progress over firing the timer (matches the
                // old `timeout(wait, read)`, which polled the read first).
                biased;
                res = r.read_buf(&mut self.buf) => match res {
                    Ok(n) => n,
                    Err(e) => return Err(e),
                },
                _ = timer.as_mut() => {
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
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "lsapi truncated packet",
                ));
            }
        }
    }

    fn try_parse(&mut self) -> std::io::Result<Option<LsapiFrame>> {
        if self.buf.len() < PACKET_HEADER_LEN {
            return Ok(None);
        }
        if self.buf[0] != VERSION_B0 || self.buf[1] != VERSION_B1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "lsapi bad magic",
            ));
        }
        let flag = self.buf[3];
        let lb = [self.buf[4], self.buf[5], self.buf[6], self.buf[7]];
        // Match this host's LSAPI_ENDIAN (BIG on aarch64); swap only on a real
        // cross-endian mismatch. See HOST_LSAPI_ENDIAN in proto.rs.
        let total = if flag & ENDIAN_BIT == HOST_LSAPI_ENDIAN {
            u32::from_le_bytes(lb)
        } else {
            u32::from_be_bytes(lb)
        } as usize;
        if !(PACKET_HEADER_LEN..=crate::proto::MAX_PACKET_LEN).contains(&total) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "lsapi implausible packet length",
            ));
        }
        if self.buf.len() < total {
            return Ok(None);
        }
        let type_byte = self.buf[2];
        let ptype = PacketType::from_u8(type_byte).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "lsapi unknown packet type")
        })?;
        let mut packet = self.buf.split_to(total);
        use bytes::Buf;
        packet.advance(PACKET_HEADER_LEN);
        Ok(Some(LsapiFrame {
            ptype,
            body: packet.freeze(),
            flag,
        }))
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
        let headers = collect_wire_headers(&req);
        assert!(
            !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("proxy")),
            "Proxy header must be stripped from the LSAPI wire header index"
        );
        // Benign headers still pass through.
        assert!(
            headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        );
        assert!(headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")));
    }
}

#[cfg(test)]
mod response_length_tests {
    use super::parse_response_content_length;

    fn headers(values: &[&str]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|value| ("Content-Length".to_string(), (*value).to_string()))
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
