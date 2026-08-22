//! (attribution) Per-request PHP render log — the per-URL/user-class attribution
//! the aggregate telemetry histograms cannot give. The 2026-06 diagnosis
//! (docs/perf-diagnosis-2026-06-09.md) proved PHP render time is 86.5–98.8% of
//! production request wall time, with ~11% of renders over 100 ms — but the
//! histograms can't say WHICH routes or user classes form that tail. This log
//! can: one TSV line per slow render, plus a 1-in-128 sample of ALL PHP requests
//! so tail shares can be normalized against the population.
//!
//! Line format (tab-separated, no header — fixed columns, like an access log):
//!
//! `ts  kind  lb  user  method  status  ttfb_us  acquire_us  dispatch_us  bytes  retry  host  uri  reqid`
//!
//! * `ts` — unix epoch milliseconds
//! * `kind` — `slow` (TTFB over threshold) or `samp` (population sample)
//! * `lb` — `1` when the RAW peer is loopback (synthetic ab/h2load benches +
//!   local ops; same split as the telemetry `*_loopback` counters, so
//!   benchmarking never pollutes the production picture)
//! * `user` — `auth` when an `xf_user`/`xf_session` cookie is PRESENT (presence
//!   only — cookie values are never read or written), else `guest`
//! * `ttfb_us` — render time to first byte (the histogram's `lsapi_ttfb`);
//!   falls back to `dispatch_us` when the backend died pre-byte
//! * `bytes` — declared Content-Length (`0` when streaming/undeclared)
//! * `uri` — path+query, capped at 200 bytes
//!
//! Writing rides the existing `hj_log::AccessLogger` writer task: non-blocking
//! on the request path, size-rolled, gzip-archived, day-pruned, supervised.

use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hj_core::Request;

/// 1-in-N population sample rate. Power of two — the decision is a mask, and the
/// counter is shared across worker threads (relaxed; exactness doesn't matter).
const SAMPLE_EVERY: u64 = 128;
/// Longest URI written per line. Long enough for any real route + query; caps
/// what a crafted query string can force into the log.
const MAX_URI_BYTES: usize = 200;

pub struct PhpSlowLog {
    logger: hj_log::AccessLogger,
    threshold_us: u64,
    tick: AtomicU64,
}

/// Request identity captured BEFORE dispatch consumes the `Request`. Whether the
/// line is written is only known after the render (the decision needs the TTFB),
/// so the identity must be owned up front. Cost: two small String allocations per
/// PHP request when the log is enabled — the dispatch path already clones the
/// full header map for the GET/HEAD self-redirect retry, so this is noise.
pub struct PreCapture {
    method: http::Method,
    host: String,
    uri: String,
    auth: bool,
    request_id: String,
}

impl PreCapture {
    /// `host` is the already-resolved request host (the caller has it on hand
    /// for the page-cache key; don't recompute). `request_id` is the `ReqCtx`
    /// correlation id so a slow render is joinable with the access/error logs.
    pub fn from_request(req: &Request, host: String, request_id: String) -> Self {
        let uri = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let mut uri = uri.to_string();
        if uri.len() > MAX_URI_BYTES {
            let mut cut = MAX_URI_BYTES;
            while !uri.is_char_boundary(cut) {
                cut -= 1;
            }
            uri.truncate(cut);
        }
        // Presence-only scan: a logged-in visitor carries xf_user (remember-me)
        // and/or xf_session. Values are never extracted.
        let auth = req
            .headers()
            .get(http::header::COOKIE)
            .map(|v| {
                let b = v.as_bytes();
                contains(b, b"xf_user=") || contains(b, b"xf_session=")
            })
            .unwrap_or(false);
        PreCapture {
            method: req.method().clone(),
            host,
            uri,
            auth,
            request_id,
        }
    }
}

impl PhpSlowLog {
    /// Spawn the writer task and return the shared handle. Must be called inside
    /// the tokio runtime. Rolls at 64 MiB, gzips archives, prunes after 7 days
    /// (~5 MB/day at 2026-06 production volume; benchmarks add bursts but those
    /// lines carry `lb=1` and the roll bounds the damage).
    pub fn spawn(path: impl AsRef<Path>, threshold_ms: u64) -> Arc<Self> {
        // Format field is unused — every line goes through `log_line` pre-rendered.
        let logger =
            hj_log::AccessLogger::spawn(path, hj_log::LogFormat::Common, 64 * 1024 * 1024, 7, true);
        Arc::new(PhpSlowLog {
            logger,
            threshold_us: threshold_ms.saturating_mul(1000),
            tick: AtomicU64::new(0),
        })
    }

    /// Decide and (maybe) emit the line for one completed PHP dispatch.
    /// `timing` is the FIRST attempt's `(acquire, ttfb)` — matching what the
    /// `lsapi_acquire`/`lsapi_ttfb` histograms record — and is `None` only when
    /// the backend produced no response byte at all.
    /// `retry_kind` indicates if this was a retried request (e.g., "preflush", "idempotent_reset")
    /// or `"-"` for a non-retried first attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        pre: PreCapture,
        timing: Option<(Duration, Duration)>,
        dispatch: Duration,
        status: u16,
        bytes: u64,
        loopback: bool,
        retry_kind: &str,
    ) {
        let sampled = self
            .tick
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(SAMPLE_EVERY);
        let dispatch_us = dispatch.as_micros() as u64;
        let (acquire_us, ttfb_us) = match timing {
            Some((a, t)) => (a.as_micros() as u64, t.as_micros() as u64),
            None => (0, dispatch_us),
        };
        let slow = ttfb_us >= self.threshold_us;
        if !(slow || sampled) {
            return;
        }
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let line = format!(
            "{ts_ms}\t{kind}\t{lb}\t{user}\t{method}\t{status}\t{ttfb_us}\t{acquire_us}\t{dispatch_us}\t{bytes}\t{retry}\t{host}\t{uri}\t{reqid}",
            kind = if slow { "slow" } else { "samp" },
            lb = loopback as u8,
            user = if pre.auth { "auth" } else { "guest" },
            method = pre.method.as_str(),
            retry = retry_kind,
            host = clean(&pre.host),
            uri = clean(&pre.uri),
            reqid = clean(&pre.request_id),
        );
        self.logger.log_line(line);
    }

    /// Re-open the underlying file (SIGUSR1 / logrotate), like the access log.
    pub fn reopen(&self) {
        self.logger.reopen();
    }
}

/// Keep every line one-per-event: control bytes (incl. tab) in wire-derived
/// fields become `_`. `http`'s Uri/HeaderValue already reject most of this; the
/// filter is belt-and-braces for the TSV structure.
fn clean(s: &str) -> Cow<'_, str> {
    if !s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .map(|c| {
                if (c as u32) < 0x20 || c as u32 == 0x7f {
                    '_'
                } else {
                    c
                }
            })
            .collect(),
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_scan_matches_presence_only() {
        assert!(contains(b"xf_csrf=abc; xf_user=1%2Cdef", b"xf_user="));
        assert!(contains(b"xf_session=deadbeef", b"xf_session="));
        assert!(!contains(b"xf_csrf=abc; other=1", b"xf_user="));
        assert!(!contains(b"", b"xf_user="));
    }

    #[test]
    fn clean_replaces_control_bytes() {
        assert_eq!(clean("/threads/a.1/"), "/threads/a.1/");
        assert_eq!(clean("a\tb\nc"), "a_b_c");
    }
}
