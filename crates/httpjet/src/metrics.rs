//! (OPS1) Minimal loopback-only metrics endpoint.
//!
//! Serves a Prometheus text snapshot of the page-cache hit/miss counters (the
//! single most important operational number once `--page-cache` is live), plus a
//! request counter and an active-connections gauge. Deliberately tiny: a raw
//! HTTP/1.1 responder bound to loopback and gated behind `--metrics-addr`, so it
//! adds nothing to the request hot path and exposes no control surface. Every
//! request (any method/path) returns the same snapshot.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hj_pagecache::CacheStats;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::state::{Metrics, ServerState};

const CACHE_ENTRIES_MIN_INTERVAL_MS: u64 = 1_000;

/// The metrics endpoint exposes an UNAUTHENTICATED control+diagnostic surface — cache-URL
/// enumeration (`/cache-entries`), process/mimalloc stats, a state-mutating `/__alloc-count?reset`,
/// and (profiling builds) a up-to-60s `/debug/pprof/profile` CPU profiler. The module is documented
/// loopback-only, but nothing previously constrained `--metrics-addr`, so a misconfigured
/// `0.0.0.0:9090` exposed all of it to the network. Enforce the guarantee: only a loopback bind
/// address is allowed (a `127.0.0.0/8` / `::1` socket is unreachable off-box). The caller refuses
/// to bind anything else. (The sibling peer-purge endpoint re-checks the raw source IP for the
/// same reason; here the bind constraint is sufficient because the socket itself is unreachable.)
pub(crate) fn metrics_bind_allowed(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcMem {
    vm_rss_bytes: u64,
    rss_anon_bytes: u64,
}

fn proc_mem() -> Option<ProcMem> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    Some(parse_proc_mem(&s)).filter(|m| m.vm_rss_bytes > 0 || m.rss_anon_bytes > 0)
}

fn parse_proc_mem(status: &str) -> ProcMem {
    let mut out = ProcMem::default();
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            out.vm_rss_bytes = parse_kib_field(v);
        } else if let Some(v) = line.strip_prefix("RssAnon:") {
            out.rss_anon_bytes = parse_kib_field(v);
        }
    }
    out
}

fn parse_kib_field(field: &str) -> u64 {
    field
        .split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_mul(1024)
}

/// Accept loop for the metrics listener. Runs until cancelled (the task is
/// aborted with the other listeners on shutdown). Loopback-only. Besides the
/// Prometheus snapshot it serves an on-demand raw pprof CPU profile at
/// `/debug/pprof/profile` when built with `--features profiling` (telemetry
/// points at the slow phase; this drills to the line).
pub async fn serve_metrics(
    listener: TcpListener,
    state: Arc<ServerState>,
    profile_token: Option<String>,
) {
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "metrics: accept error");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let state = state.clone();
        let token = profile_token.clone();
        tokio::spawn(async move {
            // Defense-in-depth: the listener is bind-constrained to loopback (metrics_bind_allowed),
            // so this is always true in practice — but gate the state-mutating / expensive control
            // routes (CPU profiler, alloc-count reset) on it directly so they stay
            // loopback-only even if the bind constraint is ever loosened to allow remote read-only.
            let peer_loopback = peer.ip().is_loopback();
            // Read the request head (bounded so a slow/garbage client can't pin the
            // task). The path is only inspected for the pprof route; every
            // other request returns the metrics snapshot.
            let mut buf = [0u8; 1024];
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) => n,
                _ => 0,
            };

            #[cfg(feature = "profiling")]
            if peer_loopback {
                if let Some((head, body)) = profile::try_handle(&buf[..n], token.as_deref()).await {
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                    return;
                }
            }
            #[cfg(not(feature = "profiling"))]
            {
                let _ = &token;
            }

            // Loopback-only cache-contents listing: enumerate what's ACTUALLY cached (URL classes
            // + largest entries) so "what's junk?" is answerable directly, not inferred.
            if request_target(&buf[..n]).is_some_and(|t| t.starts_with("/cache-entries")) {
                if !try_enter_cache_entries_render(&state) {
                    let body = "cache-entries render throttled\n";
                    let head = format!(
                        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nRetry-After: 1\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(body.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    return;
                }
                let body = render_cache_entries(&state);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
                let _ = stream.shutdown().await;
                return;
            }

            // Alloc-count (h2 alloc-campaign harness). Returns the global allocation-call
            // counter; `?reset` zeroes it first. 0 unless built `--features allocount`.
            // Measure allocs/request = (read after a fixed h2load run) - (reset before) / N.
            if request_target(&buf[..n]).is_some_and(|t| t.starts_with("/__alloc-count")) {
                // `?reset` mutates state — loopback peers only (defense-in-depth; read is harmless).
                if peer_loopback && request_target(&buf[..n]).is_some_and(|t| t.contains("reset")) {
                    crate::allocount::ALLOC_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
                }
                let body = format!(
                    "{}\n",
                    crate::allocount::ALLOC_COUNT.load(std::sync::atomic::Ordering::Relaxed)
                );
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
                let _ = stream.shutdown().await;
                return;
            }

            // Loopback-only mimalloc diagnostics: process RSS/swap + mimalloc's own
            // stats dump, so the swap-retention picture (reserved vs committed vs
            // in-use → retention or a real leak) is answerable on the live binary.
            if request_target(&buf[..n]).is_some_and(|t| t.starts_with("/__mimalloc-stats")) {
                let body = render_mimalloc_stats();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
                let _ = stream.shutdown().await;
                return;
            }

            let body = render(&state);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(body.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// On-demand CPU profile endpoint (`--features profiling`). Loopback-only + an
/// optional shared token; samples the WHOLE process (all worker threads) for a
/// bounded window and returns raw pprof protobuf bytes. Rendering is deliberately
/// left to external tools such as `go tool pprof`. The pprof guard lives entirely
/// inside a `spawn_blocking` closure so it never crosses an `.await` (it is not
/// `Send`).
#[cfg(feature = "profiling")]
mod profile {
    use pprof::protos::Message as _;

    /// Returns `Some((http_head, body))` if the request targets
    /// `/debug/pprof/profile`,
    /// else `None` (let the caller serve the metrics snapshot).
    pub async fn try_handle(req: &[u8], token: Option<&str>) -> Option<(String, Vec<u8>)> {
        let target = request_target(req)?;
        let rest = target.strip_prefix("/debug/pprof/profile")?;
        // Only the bare path (optionally with a query) — not /debug/pprof/profileX.
        if !(rest.is_empty() || rest.starts_with('?')) {
            return None;
        }
        let q = rest.strip_prefix('?').unwrap_or("");
        if let Some(expected) = token {
            if param(q, "token").as_deref() != Some(expected) {
                let body = b"forbidden: bad or missing ?token\n".to_vec();
                return Some((head(403, "text/plain", body.len()), body));
            }
        }
        let secs = param(q, "seconds")
            .and_then(|s| s.parse().ok())
            .unwrap_or(10u64)
            .clamp(1, 60);
        let hz = param(q, "hz")
            .and_then(|s| s.parse().ok())
            .unwrap_or(99i32)
            .clamp(11, 997);
        match tokio::task::spawn_blocking(move || capture(secs, hz)).await {
            Ok(Some(profile)) => Some((
                head(200, "application/octet-stream", profile.len()),
                profile,
            )),
            _ => {
                let body = b"pprof capture failed (see error log)\n".to_vec();
                Some((head(500, "text/plain", body.len()), body))
            }
        }
    }

    /// Sample the process for `secs` at `hz` Hz and encode the report in Google's
    /// pprof protobuf format. Sync (runs on a blocking thread); the guard never
    /// escapes this frame.
    fn capture(secs: u64, hz: i32) -> Option<Vec<u8>> {
        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(hz)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()
            .map_err(|e| tracing::warn!(error = %e, "pprof: profiler start failed"))
            .ok()?;
        std::thread::sleep(std::time::Duration::from_secs(secs));
        let report = guard
            .report()
            .build()
            .map_err(|e| tracing::warn!(error = %e, "pprof: report build failed"))
            .ok()?;
        let profile = report
            .pprof()
            .map_err(|e| tracing::warn!(error = %e, "pprof: protobuf conversion failed"))
            .ok()?;
        Some(profile.encode_to_vec())
    }

    fn head(status: u16, content_type: &str, len: usize) -> String {
        let reason = match status {
            200 => "OK",
            403 => "Forbidden",
            _ => "Internal Server Error",
        };
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
        )
    }

    /// Extract the request target (second token of the request line).
    fn request_target(req: &[u8]) -> Option<String> {
        let line = req.split(|&b| b == b'\n').next()?;
        let s = std::str::from_utf8(line).ok()?;
        Some(s.split_whitespace().nth(1)?.to_string())
    }

    /// First `key=value` in a `&`-separated query string.
    fn param(query: &str, key: &str) -> Option<String> {
        query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::try_handle;

        #[tokio::test]
        async fn pprof_route_is_exact_and_token_gated() {
            assert!(
                try_handle(b"GET /debug/pprof/profile-extra HTTP/1.1\r\n\r\n", None)
                    .await
                    .is_none()
            );

            let (head, body) = try_handle(
                b"GET /debug/pprof/profile?token=wrong HTTP/1.1\r\n\r\n",
                Some("secret"),
            )
            .await
            .expect("pprof route");
            assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"));
            assert_eq!(body, b"forbidden: bad or missing ?token\n");
        }
    }
}

/// Snapshot the live counters into the Prometheus text body.
fn render(state: &ServerState) -> String {
    let mut body = render_metrics(
        state.metrics.requests_total.load(Ordering::Relaxed),
        state.metrics.active_conns.load(Ordering::Relaxed),
        state.metrics.active_requests.load(Ordering::Relaxed),
        PeerPurgeCounters {
            received: state.metrics.purges_received.load(Ordering::Relaxed),
        },
        state.metrics.fast_memo_hits.load(Ordering::Relaxed),
        state.metrics.fast_memo_stores.load(Ordering::Relaxed),
        state.metrics.fast_memo_ineligible.load(Ordering::Relaxed),
        state.metrics.fast_cookie_none.load(Ordering::Relaxed),
        state
            .metrics
            .fast_cookie_member_session
            .load(Ordering::Relaxed),
        state
            .metrics
            .fast_cookie_benign_only
            .load(Ordering::Relaxed),
        state.metrics.tls_handshakes_full.load(Ordering::Relaxed),
        state.metrics.tls_handshakes_resumed.load(Ordering::Relaxed),
        state.page_cache.as_ref().map(|pc| pc.stats()),
    );
    body.push_str(&format!(
        "# HELP httpjet_proxy_failover_total Requests served by a failover upstream peer because the primary was marked bad (Tier 1.2).\n# TYPE httpjet_proxy_failover_total counter\nhttpjet_proxy_failover_total {}\n",
        state.proxy.pool().failovers_total()
    ));
    body.push_str(&format!(
        "# HELP httpjet_throttle_rejected_total Per-client-IP requests refused by the request throttle (disabled = always 0).\n# TYPE httpjet_throttle_rejected_total counter\nhttpjet_throttle_rejected_total {}\n",
        state.client_throttle.rejected_total()
    ));
    body.push_str(&format!(
        "# HELP httpjet_throttle_allowed_total Per-client-IP requests admitted by the request throttle.\n# TYPE httpjet_throttle_allowed_total counter\nhttpjet_throttle_allowed_total {}\n",
        state.client_throttle.allowed_total()
    ));
    // Per-request telemetry (counters + latency histograms) self-renders.
    state.telemetry.render_into(&mut body);
    append_lsapi_pool_metrics(
        &mut body,
        state
            .lsapi
            .as_ref()
            .and_then(|registry| registry.default_pool_stats()),
    );
    append_rewrite_metrics(&mut body, state);
    append_xf_capsule_metrics(&mut body, &state.metrics);
    append_shared_path_metrics(&mut body, state);
    append_dict_recompress_metrics(&mut body, &state.page_cache_dict_metrics);
    // Point-in-time gauge: stale-while-revalidate background refreshes in flight.
    if state.page_cache.is_some() {
        body.push_str(
            "# HELP httpjet_pagecache_refresh_inflight Background SWR refreshes in flight.\n",
        );
        body.push_str("# TYPE httpjet_pagecache_refresh_inflight gauge\n");
        body.push_str(&format!(
            "httpjet_pagecache_refresh_inflight {}\n",
            state.page_cache_refresh.inflight_count()
        ));
    }
    append_runtime_diagnostics(
        &mut body,
        RuntimeDiagnostics {
            cache_entries_renders: state.metrics.cache_entries_renders.load(Ordering::Relaxed),
            cache_entries_throttled: state
                .metrics
                .cache_entries_throttled
                .load(Ordering::Relaxed),
            access_log_dropped: state
                .access_log
                .as_ref()
                .map(|l| l.dropped_lines())
                .unwrap_or(0),
        },
    );
    body
}

fn append_lsapi_pool_metrics(out: &mut String, stats: Option<hj_lsapi::PoolStats>) {
    let Some(stats) = stats else {
        return;
    };
    for (name, help, value) in [
        (
            "httpjet_lsapi_generation_advances_total",
            "External lsphp generation advances observed by this web process.",
            stats.generation_advances,
        ),
        (
            "httpjet_lsapi_stale_idle_drops_total",
            "Idle LSAPI connections discarded after a generation advance.",
            stats.stale_idle_drops,
        ),
        (
            "httpjet_lsapi_stale_checked_out_drops_total",
            "Checked-out LSAPI connections refused re-pooling after a generation advance.",
            stats.stale_checked_out_drops,
        ),
        (
            "httpjet_lsapi_stale_worker_retire_signals_total",
            "Response-complete old-generation lsphp workers retired through pinned pidfds.",
            stats.stale_worker_retire_signals,
        ),
        (
            "httpjet_lsapi_stale_worker_retire_failures_total",
            "Pinned old-generation lsphp worker retirement signals that failed.",
            stats.stale_worker_retire_failures,
        ),
        (
            "httpjet_lsapi_worker_attribution_failures_total",
            "LSAPI connections whose accepting worker could not be pinned through UNIX_DIAG and procfs.",
            stats.worker_attribution_failures,
        ),
        (
            "httpjet_lsapi_eagain_retries_total",
            "LSAPI fresh-dial EAGAIN failures retried as transient backlog pressure.",
            stats.eagain_retries,
        ),
        (
            "httpjet_lsapi_eagain_terminal_exhaustions_total",
            "LSAPI fresh-dial EAGAIN failures that exhausted the retry window.",
            stats.eagain_terminal_exhaustions,
        ),
    ] {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} counter\n"));
        out.push_str(&format!("{name} {value}\n"));
    }
}

fn append_dict_recompress_metrics(
    out: &mut String,
    metrics_by_vhost: &dashmap::DashMap<
        String,
        std::sync::Arc<crate::state::DictRecompressMetrics>,
    >,
) {
    if metrics_by_vhost.is_empty() {
        return;
    }
    let mut rows: Vec<_> = metrics_by_vhost
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    out.push_str(
        "# HELP httpjet_pagecache_dict_recompress_total First-hit dictionary recompression jobs by result.\n",
    );
    out.push_str("# TYPE httpjet_pagecache_dict_recompress_total counter\n");
    out.push_str(
        "# HELP httpjet_pagecache_dict_recompress_bytes_total First-hit dictionary recompression bytes by stage.\n",
    );
    out.push_str("# TYPE httpjet_pagecache_dict_recompress_bytes_total counter\n");
    for (vhost, metrics) in rows {
        let vhost = vhost
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        out.push_str(&format!(
            "httpjet_pagecache_dict_recompress_total{{vhost=\"{vhost}\",result=\"queued\"}} {}\n",
            metrics.queued.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "httpjet_pagecache_dict_recompress_total{{vhost=\"{vhost}\",result=\"dropped\"}} {}\n",
            metrics.dropped.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "httpjet_pagecache_dict_recompress_total{{vhost=\"{vhost}\",result=\"attempted\"}} {}\n",
            metrics.attempts.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "httpjet_pagecache_dict_recompress_total{{vhost=\"{vhost}\",result=\"completed\"}} {}\n",
            metrics.completed.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "httpjet_pagecache_dict_recompress_total{{vhost=\"{vhost}\",result=\"skipped\"}} {}\n",
            metrics.skipped.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "httpjet_pagecache_dict_recompress_bytes_total{{vhost=\"{vhost}\",stage=\"input\"}} {}\n",
            metrics.input_bytes.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "httpjet_pagecache_dict_recompress_bytes_total{{vhost=\"{vhost}\",stage=\"output\"}} {}\n",
            metrics.output_bytes.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "httpjet_pagecache_dict_recompress_bytes_total{{vhost=\"{vhost}\",stage=\"saved\"}} {}\n",
            metrics.saved_bytes.load(Ordering::Relaxed)
        ));
    }
}

/// Rewrite-outcome cache effectiveness + the UA-classification memo size.
fn append_rewrite_metrics(out: &mut String, state: &ServerState) {
    let mut metric = |name: &str, kind: &str, help: &str, value: u64| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    };
    metric(
        "httpjet_rewrite_outcome_hits_total",
        "counter",
        "Rewrite-outcome cache hits (memoized decision skipped chain evaluation).",
        state.metrics.rewrite_outcome_hits.load(Ordering::Relaxed),
    );
    metric(
        "httpjet_rewrite_outcome_misses_total",
        "counter",
        "Rewrite-outcome cache misses (cacheable chain, evaluated and stored).",
        state.metrics.rewrite_outcome_misses.load(Ordering::Relaxed),
    );
    metric(
        "httpjet_rewrite_outcome_uncacheable_total",
        "counter",
        "Requests whose rewrite chain read an unkeyable per-request input (cache bypassed).",
        state
            .metrics
            .rewrite_outcome_uncacheable
            .load(Ordering::Relaxed),
    );
    metric(
        "httpjet_rewrite_ua_classify_entries",
        "gauge",
        "Entries in the (ruleset, User-Agent) -> match-bitmap classification memo.",
        state.ua_classify.len() as u64,
    );
}

fn append_xf_capsule_metrics(out: &mut String, metrics: &Metrics) {
    let hits_dedicated = metrics.xf_capsule_hits_dedicated.load(Ordering::Relaxed);
    let stale_hits_dedicated = metrics
        .xf_capsule_stale_hits_dedicated
        .load(Ordering::Relaxed);
    let hits_public_fallback = metrics
        .xf_capsule_hits_public_fallback
        .load(Ordering::Relaxed);
    let stale_hits_public_fallback = metrics
        .xf_capsule_stale_hits_public_fallback
        .load(Ordering::Relaxed);
    let misses_dedicated = metrics.xf_capsule_misses_dedicated.load(Ordering::Relaxed);
    let misses_public_fallback = metrics
        .xf_capsule_misses_public_fallback
        .load(Ordering::Relaxed);
    let bypass_not_allowed = metrics
        .xf_capsule_bypass_not_allowed
        .load(Ordering::Relaxed);
    let dedicated_stores = metrics.xf_capsule_dedicated_stores.load(Ordering::Relaxed);
    let hits_member = metrics.xf_capsule_hits_member.load(Ordering::Relaxed);
    let hits_guest = metrics.xf_capsule_hits_guest.load(Ordering::Relaxed);
    let shell_age_sum = metrics
        .xf_capsule_shell_age_secs_sum
        .load(Ordering::Relaxed);
    let shell_age_count = metrics
        .xf_capsule_shell_age_secs_count
        .load(Ordering::Relaxed);
    let canary_filtered = metrics.xf_capsule_canary_filtered.load(Ordering::Relaxed);

    out.push_str("# HELP httpjet_xf_capsule_hits_total XenForo capsule hits by source.\n");
    out.push_str("# TYPE httpjet_xf_capsule_hits_total counter\n");
    out.push_str(&format!(
        "httpjet_xf_capsule_hits_total{{source=\"dedicated\"}} {hits_dedicated}\n"
    ));
    out.push_str(&format!(
        "httpjet_xf_capsule_hits_total{{source=\"public_fallback\"}} {hits_public_fallback}\n"
    ));
    out.push_str(
        "# HELP httpjet_xf_capsule_stale_hits_total XenForo capsule stale hits by source.\n",
    );
    out.push_str("# TYPE httpjet_xf_capsule_stale_hits_total counter\n");
    out.push_str(&format!(
        "httpjet_xf_capsule_stale_hits_total{{source=\"dedicated\"}} {stale_hits_dedicated}\n"
    ));
    out.push_str(&format!(
        "httpjet_xf_capsule_stale_hits_total{{source=\"public_fallback\"}} {stale_hits_public_fallback}\n"
    ));
    out.push_str("# HELP httpjet_xf_capsule_misses_total XenForo capsule misses by reason.\n");
    out.push_str("# TYPE httpjet_xf_capsule_misses_total counter\n");
    out.push_str(&format!(
        "httpjet_xf_capsule_misses_total{{reason=\"dedicated_miss\"}} {misses_dedicated}\n"
    ));
    out.push_str(&format!(
        "httpjet_xf_capsule_misses_total{{reason=\"public_fallback_miss\"}} {misses_public_fallback}\n"
    ));
    out.push_str(&format!(
        "httpjet_xf_capsule_misses_total{{reason=\"not_allowed\"}} {bypass_not_allowed}\n"
    ));
    out.push_str(
        "# HELP httpjet_xf_capsule_dedicated_stores_total Dedicated capsule shells stored \
         (un-gated by W-TinyLFU; watch vs evictions for LRU churn).\n",
    );
    out.push_str("# TYPE httpjet_xf_capsule_dedicated_stores_total counter\n");
    out.push_str(&format!(
        "httpjet_xf_capsule_dedicated_stores_total {dedicated_stores}\n"
    ));

    out.push_str(
        "# HELP httpjet_xf_capsule_hits_by_class_total XenForo capsule hits by requester class \
         (member = logged-in opt-in; guest = anonymous).\n",
    );
    out.push_str("# TYPE httpjet_xf_capsule_hits_by_class_total counter\n");
    out.push_str(&format!(
        "httpjet_xf_capsule_hits_by_class_total{{class=\"member\"}} {hits_member}\n"
    ));
    out.push_str(&format!(
        "httpjet_xf_capsule_hits_by_class_total{{class=\"guest\"}} {hits_guest}\n"
    ));

    out.push_str(
        "# HELP httpjet_xf_capsule_shell_age_secs Served capsule shell age (seconds) summary; \
         sum/count = mean served shell age.\n",
    );
    out.push_str("# TYPE httpjet_xf_capsule_shell_age_secs summary\n");
    out.push_str(&format!(
        "httpjet_xf_capsule_shell_age_secs_sum {shell_age_sum}\n"
    ));
    out.push_str(&format!(
        "httpjet_xf_capsule_shell_age_secs_count {shell_age_count}\n"
    ));

    out.push_str(
        "# HELP httpjet_xf_capsule_canary_filtered_total Member capsule requests dropped because \
         the deterministic member-canary bucket rejected them (ramp denominator).\n",
    );
    out.push_str("# TYPE httpjet_xf_capsule_canary_filtered_total counter\n");
    out.push_str(&format!(
        "httpjet_xf_capsule_canary_filtered_total {canary_filtered}\n"
    ));
}

/// (shared-paths) Member→public routing telemetry for `--page-cache-shared-paths`. The
/// matcher-count gauge doubles as the feature-detection probe for
/// `scripts/cache_private_test.sh` (0 / absent ⇒ feature off), so keep its name stable.
fn append_shared_path_metrics(out: &mut String, state: &ServerState) {
    let Some(pc) = state.page_cache.as_ref() else {
        return;
    };
    let cfg = pc.config();
    out.push_str(
        "# HELP httpjet_pagecache_shared_paths_matchers Configured --page-cache-shared-paths \
         matchers (0 = feature off).\n",
    );
    out.push_str("# TYPE httpjet_pagecache_shared_paths_matchers gauge\n");
    out.push_str(&format!(
        "httpjet_pagecache_shared_paths_matchers {}\n",
        cfg.shared_public_paths.len()
    ));
    if cfg.shared_public_paths.is_empty() {
        return;
    }
    out.push_str(
        "# HELP httpjet_pagecache_shared_paths_canary_percent Sticky member canary for \
         shared-path public routing (--page-cache-shared-paths-canary-percent).\n",
    );
    out.push_str("# TYPE httpjet_pagecache_shared_paths_canary_percent gauge\n");
    out.push_str(&format!(
        "httpjet_pagecache_shared_paths_canary_percent {}\n",
        cfg.shared_paths_canary_percent
    ));
    out.push_str(
        "# HELP httpjet_pagecache_shared_path_public_routes_total Member lookups routed to the \
         PUBLIC tier via the shared-path allowlist.\n",
    );
    out.push_str("# TYPE httpjet_pagecache_shared_path_public_routes_total counter\n");
    out.push_str(&format!(
        "httpjet_pagecache_shared_path_public_routes_total {}\n",
        state
            .metrics
            .page_cache_shared_path_public_routes
            .load(Ordering::Relaxed)
    ));
    out.push_str(
        "# HELP httpjet_pagecache_shared_path_canary_skipped_total Member lookups matching a \
         shared-path matcher but kept private by the canary bucket.\n",
    );
    out.push_str("# TYPE httpjet_pagecache_shared_path_canary_skipped_total counter\n");
    out.push_str(&format!(
        "httpjet_pagecache_shared_path_canary_skipped_total {}\n",
        state
            .metrics
            .page_cache_shared_path_canary_skipped
            .load(Ordering::Relaxed)
    ));
}

fn try_enter_cache_entries_render(state: &ServerState) -> bool {
    let now = unix_ms();
    let last = state.metrics.cache_entries_last_ms.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last) < CACHE_ENTRIES_MIN_INTERVAL_MS {
        state
            .metrics
            .cache_entries_throttled
            .fetch_add(1, Ordering::Relaxed);
        return false;
    }
    match state.metrics.cache_entries_last_ms.compare_exchange(
        last,
        now,
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        Ok(_) => {
            state
                .metrics
                .cache_entries_renders
                .fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(_) => {
            state
                .metrics
                .cache_entries_throttled
                .fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

#[derive(Default)]
struct RuntimeDiagnostics {
    cache_entries_renders: u64,
    cache_entries_throttled: u64,
    access_log_dropped: u64,
}

fn append_runtime_diagnostics(out: &mut String, d: RuntimeDiagnostics) {
    let mut metric = |name: &str, kind: &str, help: &str, value: u64| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    };
    metric(
        "httpjet_debug_cache_entries_renders_total",
        "counter",
        "Accepted /cache-entries debug renders.",
        d.cache_entries_renders,
    );
    metric(
        "httpjet_debug_cache_entries_throttled_total",
        "counter",
        "/cache-entries debug renders rejected by the local throttle.",
        d.cache_entries_throttled,
    );
    metric(
        "httpjet_log_access_dropped_lines_total",
        "counter",
        "Access-log lines shed because the non-blocking writer queue was full or gone.",
        d.access_log_dropped,
    );
}

/// Extract the request target (2nd token of the request line) from a raw HTTP head.
fn request_target(req: &[u8]) -> Option<String> {
    let line = req.split(|&b| b == b'\n').next()?;
    let s = std::str::from_utf8(line).ok()?;
    Some(s.split_whitespace().nth(1)?.to_string())
}

/// Render the live page-cache contents (loopback debug): per-URL-class histogram + the largest
/// entries, so an operator can see EXACTLY what is cached (and whether it's the recurring set or
/// junk) instead of inferring from aggregate counters.
fn render_cache_entries(state: &ServerState) -> String {
    let Some(pc) = state.page_cache.as_ref() else {
        return "page cache not enabled (start with --page-cache)\n".to_string();
    };
    let l = pc.list_entries(std::time::Instant::now(), 60);
    let mut out = String::with_capacity(8192);
    out.push_str(&format!(
        "page-cache contents: {} entries, {:.2} MiB total ({} bytes)\n",
        l.total_entries,
        l.total_bytes as f64 / (1024.0 * 1024.0),
        l.total_bytes
    ));
    out.push_str("\nby URL class  (entries | bytes | avg/entry):\n");
    for (class, n, bytes) in &l.classes {
        out.push_str(&format!(
            "  {:>6}  {:>11}  {:>8}/e  {}\n",
            n,
            bytes,
            bytes / n.max(&1),
            class
        ));
    }
    out.push_str(&format!(
        "\ntop {} entries by size  (stored = dict-compressed when dgen!=0):\n",
        l.top.len()
    ));
    out.push_str(&format!(
        "  {:>9} {:>8} {:>10} {:>6} {:>7}  url [status]\n",
        "stored", "variant", "dgen", "age_s", "ttl_s"
    ));
    for e in &l.top {
        out.push_str(&format!(
            "  {:>9} {:>8} {:>10} {:>6} {:>7}  {} [{}]\n",
            e.stored_bytes,
            e.variant_bytes,
            e.dict_gen,
            e.age_secs,
            e.ttl_secs,
            e.identity.replace('\n', " "),
            e.status
        ));
    }
    let s = pc.stats();
    out.push_str(&format!(
        "\nram: entries={} mem_bytes={} hot_bytes={} meta={} raw_meta={} decoded={} tag_keys={} tag_memberships={} tag_index_bytes={} tag_purge_tombstones={} tag_purge_floor_ms={}   disk: bytes={} / max={} ({:.0}%) evictions={} swept_expired={} missing_files={} orphan_reclaimed={} orphan_deferred={}\n",
        s.entries,
        s.memory_bytes,
        s.hot_bytes,
        s.meta_compressed_bytes,
        s.meta_raw_bytes,
        s.decoded_entries,
        s.tag_keys,
        s.tag_memberships,
        s.tag_index_bytes,
        s.tag_purge_tombstones,
        s.tag_purge_floor_ms,
        s.disk_bytes,
        s.disk_max_bytes,
        if s.disk_max_bytes > 0 { s.disk_bytes as f64 * 100.0 / s.disk_max_bytes as f64 } else { 0.0 },
        s.disk_evictions,
        s.swept_expired,
        s.missing_file_invalidations,
        s.orphan_reclaimed,
        s.orphan_deferred,
    ));
    out.push_str(
        "note: mem_bytes = LRU index + tag_index_bytes; --page-cache-mem caps the index alone, so mem_bytes may read slightly above the cap\n",
    );
    out.push_str(&format!(
        "evict_age: lt_1h={} h1_6={} h6_24={} ge_24h={}   expired_misses={}\n",
        s.disk_evict_ages[0],
        s.disk_evict_ages[1],
        s.disk_evict_ages[2],
        s.disk_evict_ages[3],
        s.expired_misses,
    ));
    out.push_str(&format!(
        "health: hits={} misses={} stores={} purges={} store_purge_rejects={} disk_read_err={} disk_write_err={} disk_full_err={} meta_decode_err={} key_id_collisions={} poisoned_locks={} store_commit_hold_us={} store_commit_calls={}\n",
        s.hits,
        s.misses,
        s.stores,
        s.purges,
        s.store_purge_rejections,
        s.disk_read_errors,
        s.disk_write_errors,
        s.disk_full_errors,
        s.meta_decode_errors,
        s.key_id_collisions,
        s.poisoned_locks,
        s.store_commit_hold_us,
        s.store_commit_calls
    ));
    out.push_str(&format!(
        "capsule: dedicated_stores={} hits_dedicated={} hits_public_fallback={} misses={} disk_evictions={}\n",
        state
            .metrics
            .xf_capsule_dedicated_stores
            .load(Ordering::Relaxed),
        state.metrics.xf_capsule_hits_dedicated.load(Ordering::Relaxed),
        state
            .metrics
            .xf_capsule_hits_public_fallback
            .load(Ordering::Relaxed),
        state.metrics.xf_capsule_misses_dedicated.load(Ordering::Relaxed)
            + state
                .metrics
                .xf_capsule_misses_public_fallback
                .load(Ordering::Relaxed),
        s.disk_evictions,
    ));
    if s.poisoned_locks > 0 {
        out.push_str("  WARNING: a writer/scan lock was poisoned (panic mid-mutation) — page-cache indexes may be inconsistent\n");
    }
    out
}

/// Render a loopback diagnostics snapshot: process RSS/swap + mimalloc's internal
/// stats (arenas reserved/committed/purged, retained pages). Free-form text, so it
/// is a sibling route rather than folded into the Prometheus `render` (which has a
/// strict `version=0.0.4` line format).
fn render_mimalloc_stats() -> String {
    let mut out = String::with_capacity(8192);
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if line.starts_with("VmRSS:")
                || line.starts_with("VmSwap:")
                || line.starts_with("VmSize:")
                || line.starts_with("VmData:")
                || line.starts_with("VmHWM:")
            {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out.push_str("\n--- mimalloc stats ---\n");
    out.push_str(&mimalloc_stats_text());
    out
}

/// Capture `mi_stats_print_out` into a String. We deliberately read mimalloc's own
/// dump (version-agnostic) rather than `mi_option_get(N)` with hardcoded option
/// numbers: libmimalloc-sys 0.1.49's named `mi_option_*` constants carry v1/v2
/// numbering while the linked C tree is v3, so raw integers would query the wrong
/// option.
fn mimalloc_stats_text() -> String {
    use std::os::raw::{c_char, c_void};

    // mimalloc invokes this synchronously with NUL-terminated UTF-8 chunks; append
    // each onto the String behind `arg`.
    extern "C" fn sink(msg: *const c_char, arg: *mut c_void) {
        if msg.is_null() || arg.is_null() {
            return;
        }
        // SAFETY: `arg` is the `&mut String` passed to mi_stats_print_out below;
        // mimalloc calls this on our thread, before it returns, so the borrow is
        // live and unaliased. `msg` is a NUL-terminated C string owned by mimalloc,
        // valid for this call only — we copy it out and never retain the pointer.
        unsafe {
            let buf = &mut *(arg as *mut String);
            let c = std::ffi::CStr::from_ptr(msg);
            buf.push_str(&c.to_string_lossy());
        }
    }

    let mut buf = String::new();
    // SAFETY: `Some(sink)` matches `mi_output_fun`'s signature and we pass a pointer
    // to the live local `buf` as its `arg`; mimalloc invokes `sink` synchronously
    // and stores neither pointer past the call. The callback is panic-free (the
    // release profile is `panic = "abort"`, so a panic across the FFI boundary
    // would abort rather than be UB — but it cannot panic here).
    unsafe {
        libmimalloc_sys::mi_stats_print_out(Some(sink), (&mut buf as *mut String).cast());
    }
    buf
}

/// (OPS3) Loopback purge-endpoint counters, snapshotted for the metrics render.
#[derive(Clone, Copy, Default)]
struct PeerPurgeCounters {
    received: u64,
}

/// Pure renderer (split out for unit testing): format the metrics from raw values.
fn render_metrics(
    requests: u64,
    active: u64,
    active_requests: u64,
    peer_purge: PeerPurgeCounters,
    fast_memo_hits: u64,
    fast_memo_stores: u64,
    fast_memo_ineligible: u64,
    fast_cookie_none: u64,
    fast_cookie_member_session: u64,
    fast_cookie_benign_only: u64,
    tls_handshakes_full: u64,
    tls_handshakes_resumed: u64,
    cache: Option<CacheStats>,
) -> String {
    let mut out = String::with_capacity(768);
    let mut metric = |name: &str, kind: &str, help: &str, value: String| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    };
    metric(
        "httpjet_requests_total",
        "counter",
        "Total requests served.",
        requests.to_string(),
    );
    metric(
        "httpjet_active_connections",
        "gauge",
        "Currently open connections.",
        active.to_string(),
    );
    metric(
        "httpjet_active_requests",
        "gauge",
        "Requests currently executing in the handler (response-head phase).",
        active_requests.to_string(),
    );
    metric(
        "httpjet_pagecache_purges_received_total",
        "counter",
        "Loopback page-cache purges received on /__hj_cache_purge and applied.",
        peer_purge.received.to_string(),
    );
    metric(
        "httpjet_fast_memo_hits_total",
        "counter",
        "Finished-response memo hits served on the on-core fast path (#349).",
        fast_memo_hits.to_string(),
    );
    metric(
        "httpjet_fast_memo_stores_total",
        "counter",
        "Finished-response memo stores (first full-pipeline serve per key/TTL).",
        fast_memo_stores.to_string(),
    );
    metric(
        "httpjet_fast_memo_ineligible_total",
        "counter",
        "Memo-eligible static requests whose .htaccess chain refused the store (see `httpjet check`).",
        fast_memo_ineligible.to_string(),
    );
    metric(
        "httpjet_fast_cookie_none_total",
        "counter",
        "Fast-path GET/HEAD requests with no Cookie header (#343 Step 1).",
        fast_cookie_none.to_string(),
    );
    metric(
        "httpjet_fast_cookie_member_session_total",
        "counter",
        "Cookied fast-path GET/HEAD requests carrying a member/session cookie marker.",
        fast_cookie_member_session.to_string(),
    );
    metric(
        "httpjet_fast_cookie_benign_only_total",
        "counter",
        "Cookied fast-path GET/HEAD requests with NO member/session marker (the benign-cookie fast-path candidate pool, #343 Step 1).",
        fast_cookie_benign_only.to_string(),
    );
    metric(
        "httpjet_tls_handshakes_full_total",
        "counter",
        "TLS connections that completed a full handshake (rustls HandshakeKind::Full | FullWithHelloRetryRequest).",
        tls_handshakes_full.to_string(),
    );
    metric(
        "httpjet_tls_handshakes_resumed_total",
        "counter",
        "TLS connections that completed a resumed handshake (session ticket/PSK).",
        tls_handshakes_resumed.to_string(),
    );
    if let Some(s) = cache {
        let lookups = s.hits + s.misses;
        let ratio = if lookups > 0 {
            s.hits as f64 / lookups as f64
        } else {
            0.0
        };
        metric(
            "httpjet_pagecache_hits_total",
            "counter",
            "Page-cache hits.",
            s.hits.to_string(),
        );
        metric(
            "httpjet_pagecache_misses_total",
            "counter",
            "Page-cache misses.",
            s.misses.to_string(),
        );
        metric(
            "httpjet_pagecache_stores_total",
            "counter",
            "Page-cache stores.",
            s.stores.to_string(),
        );
        metric(
            "httpjet_pagecache_purges_total",
            "counter",
            "Page-cache tag purges.",
            s.purges.to_string(),
        );
        metric(
            "httpjet_pagecache_store_purge_rejections_total",
            "counter",
            "Page-cache stores rejected because a relevant purge happened after render start.",
            s.store_purge_rejections.to_string(),
        );
        metric(
            "httpjet_pagecache_entries",
            "gauge",
            "Current cached entries.",
            s.entries.to_string(),
        );
        metric(
            "httpjet_pagecache_memory_bytes",
            "gauge",
            "Exact cache-accounted RAM bytes held by the page-cache index (owned metadata/decoded metadata/tag strings/tag-index allocations/variants/any in-RAM body; tmpfs bodies excluded).",
            s.memory_bytes.to_string(),
        );
        if let Some(pm) = proc_mem() {
            let cache_resident = s.memory_bytes.saturating_add(s.hot_bytes);
            metric(
                "httpjet_process_rss_bytes",
                "gauge",
                "Current process resident set size from /proc/self/status VmRSS.",
                pm.vm_rss_bytes.to_string(),
            );
            metric(
                "httpjet_process_rss_anon_bytes",
                "gauge",
                "Current anonymous resident set size from /proc/self/status RssAnon.",
                pm.rss_anon_bytes.to_string(),
            );
            metric(
                "httpjet_pagecache_unaccounted_rss_anon_bytes",
                "gauge",
                "RssAnon bytes not covered by exact page-cache memory_bytes plus hot_bytes.",
                pm.rss_anon_bytes.saturating_sub(cache_resident).to_string(),
            );
        }
        metric(
            "httpjet_pagecache_meta_compressed_bytes",
            "gauge",
            "Resident page-cache metadata bytes after zstd compression.",
            s.meta_compressed_bytes.to_string(),
        );
        metric(
            "httpjet_pagecache_meta_raw_bytes",
            "gauge",
            "Resident page-cache metadata bytes before zstd compression.",
            s.meta_raw_bytes.to_string(),
        );
        metric(
            "httpjet_pagecache_decoded_entries",
            "gauge",
            "Resident page-cache entries with decoded metadata memoized in RAM.",
            s.decoded_entries.to_string(),
        );
        metric(
            "httpjet_pagecache_tag_keys",
            "gauge",
            "Distinct purge-tag keys in the page-cache reverse index.",
            s.tag_keys.to_string(),
        );
        metric(
            "httpjet_pagecache_tag_memberships",
            "gauge",
            "Exact live key memberships across all page-cache purge-tag sets.",
            s.tag_memberships.to_string(),
        );
        metric(
            "httpjet_pagecache_tag_index_bytes",
            "gauge",
            "Exact reverse tag-index allocation bytes exposed by the underlying hash tables.",
            s.tag_index_bytes.to_string(),
        );
        metric(
            "httpjet_pagecache_tag_purge_tombstones",
            "gauge",
            "Exact retained tag-purge wall stamps protecting peer-fill adoption.",
            s.tag_purge_tombstones.to_string(),
        );
        metric(
            "httpjet_pagecache_tag_purge_floor_milliseconds",
            "gauge",
            "Persisted coarse wall floor subsuming pruned peer-fill tag tombstones.",
            s.tag_purge_floor_ms.to_string(),
        );
        metric(
            "httpjet_pagecache_disk_bytes",
            "gauge",
            "Charged tmpfs file-tier footprint bytes (0 without one).",
            s.disk_bytes.to_string(),
        );
        metric(
            "httpjet_pagecache_disk_max_bytes",
            "gauge",
            "Configured tmpfs file-tier budget (--page-cache-disk-mem; 0 without a file tier).",
            s.disk_max_bytes.to_string(),
        );
        metric(
            "httpjet_pagecache_disk_evictions_total",
            "counter",
            "File entries evicted because the tmpfs file-tier budget was exceeded.",
            s.disk_evictions.to_string(),
        );
        metric(
            "httpjet_pagecache_swept_expired_total",
            "counter",
            "Past-deadline ghost entries reclaimed by the proactive expiry sweep.",
            s.swept_expired.to_string(),
        );
        metric(
            "httpjet_pagecache_expired_misses_total",
            "counter",
            "Counted lookups that met an entry past its retention window (TTL re-renders).",
            s.expired_misses.to_string(),
        );
        for (i, name) in [
            "httpjet_pagecache_disk_evict_age_lt_1h_total",
            "httpjet_pagecache_disk_evict_age_1h_6h_total",
            "httpjet_pagecache_disk_evict_age_6h_24h_total",
            "httpjet_pagecache_disk_evict_age_ge_24h_total",
        ]
        .iter()
        .enumerate()
        {
            metric(
                name,
                "counter",
                "Disk-LRU evictions by entry age at eviction.",
                s.disk_evict_ages[i].to_string(),
            );
        }
        metric(
            "httpjet_pagecache_missing_file_invalidations_total",
            "counter",
            "Resident file-backed entries invalidated because their tmpfs body was missing.",
            s.missing_file_invalidations.to_string(),
        );
        metric(
            "httpjet_pagecache_orphan_reclaimed_total",
            "counter",
            "Superseded tmpfs page-cache files reclaimed by orphan reconciliation.",
            s.orphan_reclaimed.to_string(),
        );
        metric(
            "httpjet_pagecache_orphan_deferred_total",
            "counter",
            "Old-enough orphan candidates kept because reconciliation could not prove deletion was safe.",
            s.orphan_deferred.to_string(),
        );
        metric(
            "httpjet_pagecache_hit_ratio",
            "gauge",
            "Hit ratio over total lookups.",
            format!("{ratio:.4}"),
        );
        metric(
            "httpjet_pagecache_hot_bytes",
            "gauge",
            "Bytes resident in the in-RAM hot tier in front of the file store (0 without one).",
            s.hot_bytes.to_string(),
        );
        metric(
            "httpjet_pagecache_disk_read_errors_total",
            "counter",
            "File-tier body reads that failed (each degraded to a miss).",
            s.disk_read_errors.to_string(),
        );
        metric(
            "httpjet_pagecache_disk_write_errors_total",
            "counter",
            "File-tier persists that failed (entry stayed in RAM).",
            s.disk_write_errors.to_string(),
        );
        metric(
            "httpjet_pagecache_disk_full_errors_total",
            "counter",
            "File-tier persists that failed specifically due to a full tmpfs (ENOSPC).",
            s.disk_full_errors.to_string(),
        );
        metric(
            "httpjet_pagecache_meta_decode_errors_total",
            "counter",
            "Resident metadata blobs that failed to decode and were invalidated.",
            s.meta_decode_errors.to_string(),
        );
        metric(
            "httpjet_pagecache_key_id_collisions_total",
            "counter",
            "Compact page-cache key-id collisions refused as misses or skipped stores.",
            s.key_id_collisions.to_string(),
        );
        metric(
            "httpjet_pagecache_poisoned_locks_total",
            "counter",
            "Writer/scan locks force-recovered from a poison (panic mid-mutation); nonzero means page-cache indexes may be inconsistent.",
            s.poisoned_locks.to_string(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_bind_only_allows_loopback() {
        // Regression (#88): the metrics endpoint MUST be loopback-only (unauthenticated control
        // surface). Loopback v4/v6 are allowed; a wildcard or LAN/public address is refused.
        for ok in ["127.0.0.1:9090", "127.0.0.5:9090", "[::1]:9090"] {
            assert!(
                metrics_bind_allowed(&ok.parse().unwrap()),
                "{ok} must be allowed"
            );
        }
        for bad in [
            "0.0.0.0:9090",
            "192.0.2.1:9090",
            "192.168.1.2:9090",
            "[::]:9090",
            "203.0.113.4:9090",
        ] {
            assert!(
                !metrics_bind_allowed(&bad.parse().unwrap()),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn render_includes_core_counters() {
        let body = render_metrics(
            42,
            3,
            1,
            PeerPurgeCounters::default(),
            0,
            0,
            0,
            7,
            2,
            1,
            90,
            10,
            None,
        );
        assert!(body.contains("httpjet_requests_total 42\n"));
        assert!(body.contains("httpjet_active_connections 3\n"));
        assert!(body.contains("httpjet_active_requests 1\n"));
        // Peer-purge counters are always present (0 when idle).
        assert!(body.contains("httpjet_pagecache_purges_received_total 0\n"));
        // (#343 Step 1) cookie census + TLS handshake split always render.
        assert!(body.contains("httpjet_fast_cookie_none_total 7\n"));
        assert!(body.contains("httpjet_fast_cookie_member_session_total 2\n"));
        assert!(body.contains("httpjet_fast_cookie_benign_only_total 1\n"));
        assert!(body.contains("httpjet_tls_handshakes_full_total 90\n"));
        assert!(body.contains("httpjet_tls_handshakes_resumed_total 10\n"));
        // No page cache => no pagecache hit/miss metrics.
        assert!(!body.contains("httpjet_pagecache_hits_total"));
        // Well-formed Prometheus: every metric line is preceded by HELP+TYPE.
        assert!(body.contains("# TYPE httpjet_requests_total counter\n"));
    }

    #[test]
    fn render_computes_hit_ratio() {
        let stats = CacheStats {
            hits: 30,
            misses: 10,
            stores: 5,
            purges: 1,
            store_purge_rejections: 3,
            entries: 12,
            poisoned_locks: 2,
            ..CacheStats::default()
        };
        let body = render_metrics(
            100,
            2,
            0,
            PeerPurgeCounters::default(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            Some(stats),
        );
        assert!(body.contains("httpjet_pagecache_hits_total 30\n"));
        assert!(body.contains("httpjet_pagecache_misses_total 10\n"));
        // 30 / (30+10) = 0.75.
        assert!(
            body.contains("httpjet_pagecache_hit_ratio 0.7500\n"),
            "got:\n{body}"
        );
        assert!(
            body.contains("httpjet_pagecache_store_purge_rejections_total 3\n"),
            "got:\n{body}"
        );
        assert!(
            body.contains("httpjet_pagecache_poisoned_locks_total 2\n"),
            "got:\n{body}"
        );
    }

    #[test]
    fn lsapi_pool_metrics_expose_reload_and_backlog_outcomes() {
        let mut body = String::new();
        append_lsapi_pool_metrics(
            &mut body,
            Some(hj_lsapi::PoolStats {
                generation_advances: 2,
                stale_idle_drops: 3,
                stale_checked_out_drops: 4,
                stale_worker_retire_signals: 5,
                stale_worker_retire_failures: 6,
                worker_attribution_failures: 7,
                eagain_retries: 8,
                eagain_terminal_exhaustions: 9,
            }),
        );
        for expected in [
            "httpjet_lsapi_generation_advances_total 2\n",
            "httpjet_lsapi_stale_idle_drops_total 3\n",
            "httpjet_lsapi_stale_checked_out_drops_total 4\n",
            "httpjet_lsapi_stale_worker_retire_signals_total 5\n",
            "httpjet_lsapi_stale_worker_retire_failures_total 6\n",
            "httpjet_lsapi_worker_attribution_failures_total 7\n",
            "httpjet_lsapi_eagain_retries_total 8\n",
            "httpjet_lsapi_eagain_terminal_exhaustions_total 9\n",
        ] {
            assert!(body.contains(expected), "missing {expected:?} in:\n{body}");
        }
    }

    #[test]
    fn hit_ratio_zero_when_no_lookups() {
        let body = render_metrics(
            0,
            0,
            0,
            PeerPurgeCounters::default(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            Some(CacheStats::default()),
        );
        assert!(body.contains("httpjet_pagecache_hit_ratio 0.0000\n"));
    }

    #[test]
    fn parse_proc_mem_extracts_rss_fields() {
        let p = parse_proc_mem(
            "Name:\thttpjet\nVmRSS:\t  1234 kB\nRssAnon:\t  1000 kB\nVmSwap:\t7 kB\n",
        );
        assert_eq!(p.vm_rss_bytes, 1234 * 1024);
        assert_eq!(p.rss_anon_bytes, 1000 * 1024);
    }

    #[test]
    fn xf_capsule_metrics_include_sources_and_reasons() {
        let metrics = Metrics::default();
        metrics
            .xf_capsule_hits_dedicated
            .fetch_add(3, Ordering::Relaxed);
        metrics
            .xf_capsule_stale_hits_dedicated
            .fetch_add(13, Ordering::Relaxed);
        metrics
            .xf_capsule_hits_public_fallback
            .fetch_add(2, Ordering::Relaxed);
        metrics
            .xf_capsule_stale_hits_public_fallback
            .fetch_add(17, Ordering::Relaxed);
        metrics
            .xf_capsule_misses_dedicated
            .fetch_add(5, Ordering::Relaxed);
        metrics
            .xf_capsule_misses_public_fallback
            .fetch_add(7, Ordering::Relaxed);
        metrics
            .xf_capsule_bypass_not_allowed
            .fetch_add(11, Ordering::Relaxed);
        metrics
            .xf_capsule_hits_member
            .fetch_add(4, Ordering::Relaxed);
        metrics
            .xf_capsule_hits_guest
            .fetch_add(1, Ordering::Relaxed);
        metrics
            .xf_capsule_shell_age_secs_sum
            .fetch_add(1234, Ordering::Relaxed);
        metrics
            .xf_capsule_shell_age_secs_count
            .fetch_add(5, Ordering::Relaxed);
        metrics
            .xf_capsule_canary_filtered
            .fetch_add(9, Ordering::Relaxed);

        let mut body = String::new();
        append_xf_capsule_metrics(&mut body, &metrics);

        assert!(body.contains("httpjet_xf_capsule_hits_total{source=\"dedicated\"} 3\n"));
        assert!(body.contains("httpjet_xf_capsule_hits_total{source=\"public_fallback\"} 2\n"));
        assert!(body.contains("httpjet_xf_capsule_stale_hits_total{source=\"dedicated\"} 13\n"));
        assert!(
            body.contains("httpjet_xf_capsule_stale_hits_total{source=\"public_fallback\"} 17\n")
        );
        assert!(body.contains("httpjet_xf_capsule_misses_total{reason=\"dedicated_miss\"} 5\n"));
        assert!(
            body.contains("httpjet_xf_capsule_misses_total{reason=\"public_fallback_miss\"} 7\n")
        );
        assert!(body.contains("httpjet_xf_capsule_misses_total{reason=\"not_allowed\"} 11\n"));
        assert!(body.contains("httpjet_xf_capsule_hits_by_class_total{class=\"member\"} 4\n"));
        assert!(body.contains("httpjet_xf_capsule_hits_by_class_total{class=\"guest\"} 1\n"));
        assert!(body.contains("httpjet_xf_capsule_shell_age_secs_sum 1234\n"));
        assert!(body.contains("httpjet_xf_capsule_shell_age_secs_count 5\n"));
        assert!(body.contains("httpjet_xf_capsule_canary_filtered_total 9\n"));
    }

    #[test]
    fn dict_recompress_metrics_report_closed_results_and_real_savings() {
        let by_vhost = dashmap::DashMap::new();
        let metrics = std::sync::Arc::new(crate::state::DictRecompressMetrics::default());
        metrics.queued.store(5, Ordering::Relaxed);
        metrics.attempts.store(5, Ordering::Relaxed);
        metrics.completed.store(3, Ordering::Relaxed);
        metrics.skipped.store(2, Ordering::Relaxed);
        metrics.input_bytes.store(1_000, Ordering::Relaxed);
        metrics.output_bytes.store(400, Ordering::Relaxed);
        metrics.saved_bytes.store(600, Ordering::Relaxed);
        by_vhost.insert("example.com".to_owned(), metrics);

        let mut body = String::new();
        append_dict_recompress_metrics(&mut body, &by_vhost);
        for expected in [
            "result=\"queued\"} 5\n",
            "result=\"attempted\"} 5\n",
            "result=\"completed\"} 3\n",
            "result=\"skipped\"} 2\n",
            "stage=\"input\"} 1000\n",
            "stage=\"output\"} 400\n",
            "stage=\"saved\"} 600\n",
        ] {
            assert!(body.contains(expected), "missing {expected:?} in:\n{body}");
        }
    }

    #[test]
    fn runtime_diagnostics_include_debug_and_log_counters() {
        let mut body = String::new();
        append_runtime_diagnostics(
            &mut body,
            RuntimeDiagnostics {
                cache_entries_renders: 2,
                cache_entries_throttled: 3,
                access_log_dropped: 4,
            },
        );
        assert!(
            body.contains("httpjet_debug_cache_entries_renders_total 2\n"),
            "{body}"
        );
        assert!(
            body.contains("httpjet_debug_cache_entries_throttled_total 3\n"),
            "{body}"
        );
        assert!(
            body.contains("httpjet_log_access_dropped_lines_total 4\n"),
            "{body}"
        );
    }
}
