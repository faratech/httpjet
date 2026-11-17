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
//! `ts  kind  lb  user  method  status  ttfb_us  acquire_us  dispatch_us  bytes  retry  host  uri  reqid  xfcache`
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
//! * `xfcache` — the PHP response's `X-XF-Cache-Status` (`PREBHIT` = pre-bootstrap
//!   Redis DB1 serve, `PREBHIT-MEMBER` = member shell, `HIT` = XF post-bootstrap
//!   page cache), `-` when absent (a full render, or a non-page response). Appended
//!   2026-10-04 as the LAST column so fixed-index readers of the first 14 keep working.
//!
//! Writing rides the existing `hj_log::AccessLogger` writer task: non-blocking
//! on the request path, size-rolled, gzip-archived, day-pruned, supervised.

use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(test)]
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

/// Owned identity for a selected log line. The pipeline retains the original
/// request head during LSAPI dispatch, so ordinary unsampled requests need not
/// materialize it.
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
    #[cfg(test)]
    pub fn from_request(req: &Request, host: String, request_id: String) -> Self {
        Self::from_head(req.method(), req.uri(), req.headers(), host, request_id)
    }

    pub fn from_parts(parts: &http::request::Parts, host: String, request_id: String) -> Self {
        Self::from_head(&parts.method, &parts.uri, &parts.headers, host, request_id)
    }

    fn from_head(
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        host: String,
        request_id: String,
    ) -> Self {
        let uri = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let uri = bounded_uri(uri).to_owned();
        // Presence-only scan: a logged-in visitor carries xf_user (remember-me)
        // and/or xf_session. Values are never extracted.
        let auth = headers
            .get(http::header::COOKIE)
            .map(|v| {
                let b = v.as_bytes();
                contains(b, b"xf_user=") || contains(b, b"xf_session=")
            })
            .unwrap_or(false);
        PreCapture {
            method: method.clone(),
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
        pre: impl FnOnce() -> PreCapture,
        timing: Option<(Duration, Duration)>,
        dispatch: Duration,
        status: u16,
        bytes: u64,
        loopback: bool,
        retry_kind: &str,
        xf_cache: Option<&str>,
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
        let pre = pre();
        let line = format!(
            "{ts_ms}\t{kind}\t{lb}\t{user}\t{method}\t{status}\t{ttfb_us}\t{acquire_us}\t{dispatch_us}\t{bytes}\t{retry}\t{host}\t{uri}\t{reqid}\t{xfcache}",
            kind = if slow { "slow" } else { "samp" },
            lb = loopback as u8,
            user = if pre.auth { "auth" } else { "guest" },
            method = pre.method.as_str(),
            retry = retry_kind,
            host = clean(&pre.host),
            uri = clean(&pre.uri),
            reqid = clean(&pre.request_id),
            xfcache = clean(xf_cache.unwrap_or("-")),
        );
        self.logger.log_line(line);
    }

    /// Re-open the underlying file (SIGUSR1 / logrotate), like the access log.
    pub fn reopen(&self) {
        self.logger.reopen();
    }
}

fn bounded_uri(uri: &str) -> &str {
    let mut end = uri.len().min(MAX_URI_BYTES);
    while !uri.is_char_boundary(end) {
        end -= 1;
    }
    &uri[..end]
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

    fn request(uri: &str) -> Request {
        http::Request::builder()
            .method("POST")
            .uri(uri)
            .header(http::header::COOKIE, "other=value; xf_session=synthetic")
            .body(hj_core::empty_incoming())
            .unwrap()
    }

    #[test]
    fn retained_head_matches_original_log_identity() {
        let req = request("http://example.test/original?q=retained");
        let before =
            PreCapture::from_request(&req, "example.test".into(), "0123456789abcdef".into());
        let (parts, _) = req.into_parts();
        let after =
            PreCapture::from_parts(&parts, "example.test".into(), "0123456789abcdef".into());
        assert_eq!(before.method, after.method);
        assert_eq!(before.host, after.host);
        assert_eq!(before.uri, after.uri);
        assert_eq!(before.auth, after.auth);
        assert_eq!(before.request_id, after.request_id);
    }

    #[test]
    fn long_uri_is_bounded_before_owning_its_storage() {
        let req = request(&format!("/original?q={}", "x".repeat(20_000)));
        let (parts, _) = req.into_parts();
        let pre = PreCapture::from_parts(&parts, "example.test".into(), "0123456789abcdef".into());
        assert_eq!(pre.uri.len(), MAX_URI_BYTES);
        assert!(pre.uri.capacity() <= MAX_URI_BYTES);
        let utf8 = format!("{}é", "x".repeat(MAX_URI_BYTES - 1));
        assert_eq!(bounded_uri(&utf8).len(), MAX_URI_BYTES - 1);
    }

    #[tokio::test]
    async fn only_selected_or_slow_records_materialize_identity() {
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hj-php-log-{}-{unique}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let fixture = Fixture(dir);
        let path = fixture.0.join("php.tsv");
        let log = PhpSlowLog::spawn(&path, 250);
        let req = request("/original?q=retained");
        let (parts, _) = req.into_parts();
        let identities = std::cell::Cell::new(0_u32);
        let identity = || {
            identities.set(identities.get() + 1);
            PreCapture::from_parts(&parts, "example.test".into(), "0123456789abcdef".into())
        };
        for _ in 0..256 {
            log.record(
                identity,
                Some((Duration::from_micros(2), Duration::from_micros(200))),
                Duration::from_micros(300),
                200,
                64,
                true,
                "-",
                Some("PREBHIT"),
            );
        }
        assert_eq!(identities.get(), 2);
        for (timing, dispatch) in [
            (
                Some((Duration::from_micros(2), Duration::from_millis(300))),
                Duration::from_millis(400),
            ),
            (None, Duration::from_millis(300)),
            (
                Some((Duration::from_micros(2), Duration::from_millis(250))),
                Duration::from_millis(300),
            ),
        ] {
            log.record(
                identity,
                timing,
                dispatch,
                502,
                0,
                false,
                "idempotent_reset",
                None,
            );
        }
        assert_eq!(identities.get(), 5);
        let contents = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(&path)
                    && contents.lines().count() == 5
                {
                    break contents;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the isolated log writer must flush every selected record");
        let lines: Vec<Vec<&str>> = contents
            .lines()
            .map(|line| line.split('\t').collect())
            .collect();
        assert_eq!(
            lines.iter().map(|line| line[1]).collect::<Vec<_>>(),
            ["samp", "samp", "slow", "slow", "slow"]
        );
        for line in &lines {
            assert_eq!(line.len(), 15);
            assert_eq!(line[3], "auth");
            assert_eq!(line[4], "POST");
            assert_eq!(line[11], "example.test");
            assert_eq!(line[12], "/original?q=retained");
            assert_eq!(line[13], "0123456789abcdef");
        }
        assert_eq!(
            &lines[0][2..],
            [
                "1",
                "auth",
                "POST",
                "200",
                "200",
                "2",
                "300",
                "64",
                "-",
                "example.test",
                "/original?q=retained",
                "0123456789abcdef",
                "PREBHIT"
            ]
        );
        assert_eq!(lines[3][6], "300000");
        assert_eq!(lines[3][7], "0");
        println!(
            "php_log_identity_probe fast_requests=256 fast_identities=2 slow_requests=3 slow_identities=3 uri_cap_bytes={MAX_URI_BYTES}"
        );
        drop(log);
    }

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
