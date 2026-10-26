//! In-process per-request telemetry: fixed-size, lock-free aggregates recorded
//! on every real hit so the bottleneck can be read off **production traffic**
//! (millions of requests) instead of guessed from synthetic benches that can't
//! clear the noise floor on a contended box.
//!
//! # Footprint
//! Every metric is a fixed set of atomics — an [`AtomicHistogram`] is 18
//! `AtomicU64`s (buckets + `+Inf` + sum + count), ~150 bytes; one
//! [`TelemetryShard`] is a few KB and **never grows with traffic** (each request
//! is a handful of `fetch_add(Relaxed)`s, no allocation, no lock). Durability + a
//! time-series come from a periodic disk snapshot (see `run_flush`), not from
//! holding anything per-request in RAM.
//!
//! # Per-core sharding
//! Production traffic is homogeneous (mostly h2, mostly 2xx, cache hits landing in
//! the same 1–2 histogram buckets), so a handful of atoms would otherwise be
//! incremented by *every* worker thread and ping-pong between cores. [`Telemetry`]
//! therefore holds `SHARDS` cache-line-padded [`TelemetryShard`]s and each thread
//! records into its own (a one-time thread-local index); reads sum across shards.
//! Writes never contend; the fixed cost is `SHARDS × few KB` of RAM (~80 KB), still
//! constant in traffic. Reads (scrape / 30 s flush) sum the shards — rare and cheap.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::time::Duration;

/// Upper bounds (inclusive, microseconds) for the latency histogram buckets.
/// Spans 50 µs … 5 s; values above the last bound land in the `+Inf` bucket.
/// 50µs/100µs catch page-cache memory serves; 5–50 ms the PHP renders; the tail
/// catches slow/stalled backends.
const LE_US: [u64; 16] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_500_000, 5_000_000,
];
const NB: usize = LE_US.len();

/// Exact response codes broken out as their own counters (in addition to the
/// 2xx/3xx/4xx/5xx classes), so an operator can tell a 404 flood from a 403, or a
/// 502 from a 503, on the live scrape. A fixed set ⇒ bounded cardinality.
const STATUS_CODES: [u16; 10] = [400, 403, 404, 410, 414, 429, 500, 502, 503, 504];

/// Max distinct vhosts tracked with their own series. The config has ~11; 32 is
/// comfortable headroom and the largest array length `derive(Default)` covers. The
/// reserved last slot ([`VHOST_OVERFLOW`]) catches any unmapped/foreign host and
/// any vhost beyond the cap, so the label cardinality is hard-bounded.
const MAX_VHOSTS: usize = 32;
const VHOST_OVERFLOW: usize = MAX_VHOSTS - 1;

/// Sample 1-in-N requests for the fine-grained per-phase timers (rewrite, cache
/// lookup, compress) so their extra `Instant` reads stay off the every-request
/// hot path. Power of two. The always-on signals (counters, `request_duration`,
/// `lsapi_dispatch`) are NOT sampled.
pub const PHASE_SAMPLE_RATE: u64 = 16;

/// Lock-free latency histogram. `record` is one branchless-ish bucket search +
/// three `fetch_add(Relaxed)`. Buckets store the count that fell **in** each
/// bucket (non-cumulative); the Prometheus render accumulates them.
#[derive(Default)]
pub struct AtomicHistogram {
    buckets: [AtomicU64; NB],
    /// Count of samples greater than the last finite bound (`+Inf` bucket).
    inf: AtomicU64,
    /// Sum of all recorded durations, in microseconds.
    sum_us: AtomicU64,
    /// Total number of recorded samples.
    count: AtomicU64,
}

impl AtomicHistogram {
    pub fn record(&self, d: Duration) {
        let us = d.as_micros().min(u64::MAX as u128) as u64;
        // Linear scan over 16 bounds — cheaper than a branchy binary search at
        // this size and fully predictable for the common (small) durations.
        let mut i = 0;
        while i < NB {
            if us <= LE_US[i] {
                self.buckets[i].fetch_add(1, Relaxed);
                break;
            }
            i += 1;
        }
        if i == NB {
            self.inf.fetch_add(1, Relaxed);
        }
        self.sum_us.fetch_add(us, Relaxed);
        self.count.fetch_add(1, Relaxed);
    }

    fn snapshot(&self) -> HistogramSnapshot {
        let mut buckets = [0u64; NB];
        for (i, b) in self.buckets.iter().enumerate() {
            buckets[i] = b.load(Relaxed);
        }
        HistogramSnapshot {
            buckets,
            inf: self.inf.load(Relaxed),
            sum_us: self.sum_us.load(Relaxed),
            count: self.count.load(Relaxed),
        }
    }
}

#[derive(Default)]
struct HistogramSnapshot {
    buckets: [u64; NB],
    inf: u64,
    sum_us: u64,
    count: u64,
}

impl HistogramSnapshot {
    /// Fold another snapshot into this one (per-shard aggregation at read time).
    fn merge(&mut self, other: &HistogramSnapshot) {
        for i in 0..NB {
            self.buckets[i] += other.buckets[i];
        }
        self.inf += other.inf;
        self.sum_us += other.sum_us;
        self.count += other.count;
    }

    fn render_into(&self, name: &str, help: &str, out: &mut String) {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
        let mut cum = 0u64;
        for i in 0..NB {
            cum += self.buckets[i];
            // le bounds are emitted in seconds (Prometheus base unit).
            let le = LE_US[i] as f64 / 1_000_000.0;
            out.push_str(&format!("{name}_bucket{{le=\"{le}\"}} {cum}\n"));
        }
        cum += self.inf;
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {cum}\n"));
        out.push_str(&format!(
            "{name}_sum {:.6}\n",
            self.sum_us as f64 / 1_000_000.0
        ));
        out.push_str(&format!("{name}_count {}\n", self.count));
    }
}

/// Per-vhost request + status-class counters and a latency histogram, held inside
/// every shard so writes stay lock-free and cache-isolated (no new contention).
/// ~200 bytes; `MAX_VHOSTS` of these per shard × `SHARDS` ≈ 400 KB total, constant
/// in traffic.
#[derive(Default)]
pub struct VhostMetrics {
    requests: AtomicU64,
    status_2xx: AtomicU64,
    status_3xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
    /// Per-vhost split of the funnel's `cache_hits` / `cache_misses` (2026-10-04): the
    /// globals mix every vhost and content type, so a cache validation could not say what
    /// share of ONE site's page views httpjet served.
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    duration: AtomicHistogram,
}

/// One shard of the per-request counters + latency histograms. [`Telemetry`]
/// holds `SHARDS` of these (one per core); a request records into the calling
/// thread's shard and reads sum across all shards.
#[derive(Default)]
pub struct TelemetryShard {
    // --- outcome counters (every request, ~free) ---
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_bypass: AtomicU64,
    /// Subset of `cache_hits` served STALE (stale-while-revalidate), each triggering at most
    /// one background refresh. A high ratio vs `cache_hits` means SWR is doing real work.
    pub cache_stale_serves: AtomicU64,
    // --- loopback subset: requests whose RAW peer IP is loopback, i.e. synthetic
    //     ab/h2load benches + local ops, NOT real CF-fronted traffic. Subtract from the
    //     totals above to read the REAL (organic) hit/miss/bypass mix; without this,
    //     loopback benchmarking pollutes the production hit ratio. ---
    pub cache_hits_loopback: AtomicU64,
    pub cache_misses_loopback: AtomicU64,
    pub cache_bypass_loopback: AtomicU64,
    pub cache_stale_serves_loopback: AtomicU64,
    // --- W-TinyLFU store admission (at cache_store): admitted = stored; rejected = a
    //     long-tail one-hit-wonder the frequency sketch declined to store/precompress. ---
    pub cache_admitted: AtomicU64,
    pub cache_rejected: AtomicU64,
    // --- cache DISPOSITION (response-level, at store time): WHY a backend GET
    //     was/wasn't cacheable. This is the data that decides the private-cache
    //     (P3) go/no-go: is the bypass logged-in (`env_no_cache`/`private`) or
    //     just app-not-marked (`not_opted_in`)? ---
    pub disp_store_public: AtomicU64,
    pub disp_env_no_cache: AtomicU64,
    pub disp_not_opted_in: AtomicU64,
    pub disp_private: AtomicU64,
    pub disp_no_store: AtomicU64,
    pub disp_other: AtomicU64,
    /// Responses stored (or storable) in the per-session PRIVATE tier.
    pub disp_store_private: AtomicU64,
    /// Backend 5xx renders answered with a retained stale entry (stale-if-error).
    pub cache_sie_serves: AtomicU64,
    pub served_static: AtomicU64,
    pub served_php: AtomicU64,
    pub served_proxy: AtomicU64,
    pub proto_h1: AtomicU64,
    pub proto_h2: AtomicU64,
    pub proto_h3: AtomicU64,
    pub status_2xx: AtomicU64,
    pub status_3xx: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,
    // --- latency histograms ---
    /// Total `handle()` wall time, every request (always-on).
    pub request_duration: AtomicHistogram,
    /// The LSAPI/PHP backend call (cache-MISS path only — the minority, where
    /// detail is wanted; always-on there). Directly measures lsphp render time +
    /// the spawn/channel overhead the optimization targets.
    pub lsapi_dispatch: AtomicHistogram,
    /// LSAPI pool/connection acquire time (httpjet connection-pool contention).
    pub lsapi_acquire: AtomicHistogram,
    /// Request-committed → first response byte (lsphp worker pickup + render start);
    /// a fat tail here with a small `lsapi_acquire` = lsphp workers are saturated.
    pub lsapi_ttfb: AtomicHistogram,
    // --- per-phase code-area breakdown (SAMPLED 1/N to bound clock-read cost) ---
    /// `.htaccess` / rewrite-engine evaluation (the named front-controller cost).
    pub phase_rewrite: AtomicHistogram,
    /// Page-cache lookup (the hit fast-path's own cost).
    pub phase_cache_lookup: AtomicHistogram,
    /// Response transforms — compression (gzip/br/zstd) + header rules.
    pub phase_compress: AtomicHistogram,
    /// (Tier 1.5) Reverse-proxy upstream forward duration (checkout + response head).
    pub phase_upstream: AtomicHistogram,
    /// Page-cache store block on the miss path (metadata encode + tmpfs write + commit),
    /// which runs before the miss response is built.
    pub phase_store: AtomicHistogram,
    /// Collecting a cacheable backend body before the miss is served, split by framing:
    /// no Content-Length (progressive template output) vs a declared Content-Length.
    pub phase_collect_nocl: AtomicHistogram,
    pub phase_collect_cl: AtomicHistogram,
    /// Monotonic per-request tick used only to drive 1/N phase sampling (a single
    /// relaxed counter; the decision is `tick & (rate-1) == 0`).
    pub sample_tick: AtomicU64,
    /// Per-vhost breakdown, indexed by [`Telemetry::vhost_idx`]; slot
    /// [`VHOST_OVERFLOW`] catches unmapped/foreign hosts + any beyond the cap.
    /// `Box`ed so the ~6 KB array lives on the heap — otherwise `SHARDS` copies of
    /// it make `Telemetry` too large to construct on the stack (`Arc::new` builds
    /// the value before moving it to the heap).
    per_vhost: Box<[VhostMetrics; MAX_VHOSTS]>,
    /// Exact-code counters parallel to [`STATUS_CODES`] (global by-code detail).
    status_code: [AtomicU64; STATUS_CODES.len()],
}

/// Stable column order for the disk snapshot + the counter render. Keep in sync
/// with [`Telemetry::counter_values`].
pub const COUNTER_NAMES: [&str; 38] = [
    "cache_hits",
    "cache_misses",
    "cache_bypass",
    "cache_stale_serves",
    "disp_store_public",
    "disp_env_no_cache",
    "disp_not_opted_in",
    "disp_private",
    "disp_no_store",
    "disp_other",
    "served_static",
    "served_php",
    "served_proxy",
    "proto_h1",
    "proto_h2",
    "proto_h3",
    "status_2xx",
    "status_3xx",
    "status_4xx",
    "status_5xx",
    // Appended (kept after the original 20 so the TSV column order stays stable for readers).
    "cache_hits_loopback",
    "cache_misses_loopback",
    "cache_bypass_loopback",
    "cache_stale_serves_loopback",
    "cache_admitted",
    "cache_rejected",
    "disp_store_private",
    "cache_sie_serves",
    // Appended: exact-code counters (parallel to STATUS_CODES). Kept after the
    // originals so the TSV column order stays stable for readers.
    "status_400",
    "status_403",
    "status_404",
    "status_410",
    "status_414",
    "status_429",
    "status_500",
    "status_502",
    "status_503",
    "status_504",
];

impl TelemetryShard {
    /// Record protocol + status class on the response funnel (every request).
    /// `vhost_idx` is the dense bucket from [`Telemetry::vhost_idx`].
    pub fn record_request(
        &self,
        proto: hj_core::Proto,
        status: u16,
        dur: Duration,
        vhost_idx: usize,
    ) {
        self.request_duration.record(dur);
        let vh = &self.per_vhost[vhost_idx.min(VHOST_OVERFLOW)];
        vh.requests.fetch_add(1, Relaxed);
        vh.duration.record(dur);
        if let Some(i) = STATUS_CODES.iter().position(|c| *c == status) {
            self.status_code[i].fetch_add(1, Relaxed);
        }
        match proto {
            hj_core::Proto::Http1 | hj_core::Proto::Http10 => &self.proto_h1,
            hj_core::Proto::Http2 => &self.proto_h2,
            hj_core::Proto::Http3 => &self.proto_h3,
        }
        .fetch_add(1, Relaxed);
        let (global, per_vh) = match status / 100 {
            // 1xx (e.g. a successful WebSocket `101 Switching Protocols`) is informational,
            // not a final 2xx/5xx outcome — do NOT fold it into status_5xx (which would make
            // every WS upgrade read as a server error and inflate the 5xx alerting signal).
            1 => return,
            2 => (&self.status_2xx, &vh.status_2xx),
            3 => (&self.status_3xx, &vh.status_3xx),
            4 => (&self.status_4xx, &vh.status_4xx),
            _ => (&self.status_5xx, &vh.status_5xx),
        };
        global.fetch_add(1, Relaxed);
        per_vh.fetch_add(1, Relaxed);
    }

    /// Record the response-level cache disposition (from `classify_response`),
    /// so `:9090` shows WHY backend GETs are/aren't cacheable — the data that
    /// decides whether private caching (P3) is worth its risk.
    pub fn record_cache_disposition(&self, d: &hj_pagecache::Disposition) {
        use hj_pagecache::Disposition;
        match d {
            Disposition::StorePublic { .. } => &self.disp_store_public,
            Disposition::StorePrivate { .. } => &self.disp_store_private,
            Disposition::Bypass(r) => match *r {
                "env-no-cache" => &self.disp_env_no_cache,
                "not-opted-in" => &self.disp_not_opted_in,
                "private-deferred" => &self.disp_private,
                "no-store" | "no-cache" | "cache-control" => &self.disp_no_store,
                _ => &self.disp_other, // method / status / future codes
            },
        }
        .fetch_add(1, Relaxed);
    }

    /// All histograms in stable order: `(prom_name, help, tsv_prefix, &hist)`.
    /// Single source of truth for render / snapshot / header so they can't drift.
    fn histograms(&self) -> [(&'static str, &'static str, &'static str, &AtomicHistogram); 11] {
        [
            (
                "httpjet_request_duration_seconds",
                "Total handle() wall time per request.",
                "request_duration",
                &self.request_duration,
            ),
            (
                "httpjet_lsapi_dispatch_seconds",
                "LSAPI/PHP backend call time (cache-miss path).",
                "lsapi_dispatch",
                &self.lsapi_dispatch,
            ),
            (
                "httpjet_lsapi_acquire_seconds",
                "LSAPI pool/connection acquire time (pool contention).",
                "lsapi_acquire",
                &self.lsapi_acquire,
            ),
            (
                "httpjet_lsapi_ttfb_seconds",
                "Request committed to first response byte (worker pickup + render start).",
                "lsapi_ttfb",
                &self.lsapi_ttfb,
            ),
            (
                "httpjet_phase_rewrite_seconds",
                "Rewrite/.htaccess evaluation (sampled).",
                "phase_rewrite",
                &self.phase_rewrite,
            ),
            (
                "httpjet_phase_cache_lookup_seconds",
                "Page-cache lookup (sampled).",
                "phase_cache_lookup",
                &self.phase_cache_lookup,
            ),
            (
                "httpjet_phase_compress_seconds",
                "Response transforms / compression (sampled).",
                "phase_compress",
                &self.phase_compress,
            ),
            (
                "httpjet_phase_upstream_seconds",
                "Reverse-proxy upstream forward: checkout through response head (sampled).",
                "phase_upstream",
                &self.phase_upstream,
            ),
            (
                "httpjet_phase_store_seconds",
                "Page-cache store before the miss response is built (sampled).",
                "phase_store",
                &self.phase_store,
            ),
            (
                "httpjet_phase_collect_nocl_seconds",
                "Collecting a cacheable body with no Content-Length before serving it (sampled).",
                "phase_collect_nocl",
                &self.phase_collect_nocl,
            ),
            (
                "httpjet_phase_collect_cl_seconds",
                "Collecting a cacheable body with a declared Content-Length before serving it (sampled).",
                "phase_collect_cl",
                &self.phase_collect_cl,
            ),
        ]
    }

    /// 1/`rate` sampler for the fine-grained phase timers (`rate` a power of two;
    /// ≤1 = every request). One relaxed `fetch_add` + a mask — cheap enough to
    /// call on every request to decide whether to take the (costlier) `Instant`s.
    pub fn sample_phase(&self, rate: u64) -> bool {
        if rate <= 1 {
            return true;
        }
        self.sample_tick.fetch_add(1, Relaxed) & (rate - 1) == 0
    }

    fn counter_values(&self) -> [u64; COUNTER_NAMES.len()] {
        [
            self.cache_hits.load(Relaxed),
            self.cache_misses.load(Relaxed),
            self.cache_bypass.load(Relaxed),
            self.cache_stale_serves.load(Relaxed),
            self.disp_store_public.load(Relaxed),
            self.disp_env_no_cache.load(Relaxed),
            self.disp_not_opted_in.load(Relaxed),
            self.disp_private.load(Relaxed),
            self.disp_no_store.load(Relaxed),
            self.disp_other.load(Relaxed),
            self.served_static.load(Relaxed),
            self.served_php.load(Relaxed),
            self.served_proxy.load(Relaxed),
            self.proto_h1.load(Relaxed),
            self.proto_h2.load(Relaxed),
            self.proto_h3.load(Relaxed),
            self.status_2xx.load(Relaxed),
            self.status_3xx.load(Relaxed),
            self.status_4xx.load(Relaxed),
            self.status_5xx.load(Relaxed),
            self.cache_hits_loopback.load(Relaxed),
            self.cache_misses_loopback.load(Relaxed),
            self.cache_bypass_loopback.load(Relaxed),
            self.cache_stale_serves_loopback.load(Relaxed),
            self.cache_admitted.load(Relaxed),
            self.cache_rejected.load(Relaxed),
            self.disp_store_private.load(Relaxed),
            self.cache_sie_serves.load(Relaxed),
            self.status_code[0].load(Relaxed),
            self.status_code[1].load(Relaxed),
            self.status_code[2].load(Relaxed),
            self.status_code[3].load(Relaxed),
            self.status_code[4].load(Relaxed),
            self.status_code[5].load(Relaxed),
            self.status_code[6].load(Relaxed),
            self.status_code[7].load(Relaxed),
            self.status_code[8].load(Relaxed),
            self.status_code[9].load(Relaxed),
        ]
    }
}

/// Number of per-core telemetry shards. Power of two so the thread→shard map is a
/// cheap mask. Sized to cover the worker pool + tokio blocking threads with
/// headroom (prod runs `--workers 8`); past this, threads share shards (still
/// correct, just re-introduces a little contention for thread #SHARDS and beyond).
pub(crate) const SHARDS: usize = 64;

/// One [`TelemetryShard`] padded to its own cache line(s) so two shards never
/// share a line (which would defeat the point). 128 bytes also dodges the x86
/// adjacent-line prefetcher pulling a neighbouring shard's line.
#[repr(align(128))]
#[derive(Default)]
struct PaddedShard(TelemetryShard);

/// Lazily-assigned, stable per-thread shard index: one atomic bump on a thread's
/// first telemetry write, then a thread-local read forever after.
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static SHARD_IDX: usize = NEXT_SHARD.fetch_add(1, Relaxed) % SHARDS;
}

/// The calling thread's shard index, for other per-thread counters sharded the same way.
pub(crate) fn shard_index() -> usize {
    SHARD_IDX.with(|i| *i)
}

/// Per-core sharded telemetry: writes hit the calling thread's shard (no
/// cross-core contention); reads sum across shards. Shared behind `Arc`, recorded
/// from the request path, rendered for `:9090`, and snapshotted to disk.
pub struct Telemetry {
    shards: [PaddedShard; SHARDS],
    /// Dense vhost name → bucket index. Built once at boot and carried across a
    /// SIGHUP reload via the shared `Arc` (so counters stay monotonic); a vhost
    /// added at reload routes to the overflow bucket until a full restart.
    vhost_index: std::collections::HashMap<String, usize>,
    /// Bucket index → render label (length `MAX_VHOSTS`; empty slot = unused;
    /// `VHOST_OVERFLOW` = `__other__`).
    vhost_names: Vec<String>,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new(std::iter::empty())
    }
}

impl Telemetry {
    /// Build with a dense index over the config's vhost names. Up to
    /// `MAX_VHOSTS-1` distinct vhosts get their own bucket (assigned in iteration
    /// order); the rest — and any unmapped/foreign host at request time — fold into
    /// the reserved `__other__` overflow bucket.
    pub fn new(vhosts: impl IntoIterator<Item = String>) -> Self {
        let mut vhost_index = std::collections::HashMap::new();
        let mut vhost_names = vec![String::new(); MAX_VHOSTS];
        for name in vhosts {
            if vhost_index.len() >= VHOST_OVERFLOW {
                break; // remaining vhosts fold into __other__
            }
            let idx = vhost_index.len();
            if *vhost_index.entry(name.clone()).or_insert(idx) == idx {
                vhost_names[idx] = name;
            }
        }
        vhost_names[VHOST_OVERFLOW] = "__other__".to_string();
        // `[T; N]: Default` only covers N ≤ 32, so build the shard array explicitly.
        Telemetry {
            shards: std::array::from_fn(|_| PaddedShard::default()),
            vhost_index,
            vhost_names,
        }
    }

    /// Resolve a vhost name to its dense bucket index (overflow if unmapped).
    #[inline]
    pub fn vhost_idx(&self, name: &str) -> usize {
        self.vhost_index
            .get(name)
            .copied()
            .unwrap_or(VHOST_OVERFLOW)
    }
    /// The calling thread's shard. Resolve this at each record site (a ~1 ns
    /// thread-local read) rather than caching it across `.await`s — a tokio task
    /// can migrate workers, and re-resolving keeps every write on the *current*
    /// thread's shard (a cached reference could let two threads hit one shard and
    /// re-introduce the contention this is meant to remove).
    #[inline]
    pub fn shard(&self) -> &TelemetryShard {
        SHARD_IDX.with(|i| &self.shards[*i].0)
    }

    /// Record protocol + status class + total wall time (every request).
    /// `vhost_idx` comes from [`Self::vhost_idx`] (resolve it on the funnel).
    pub fn record_request(
        &self,
        proto: hj_core::Proto,
        status: u16,
        dur: Duration,
        vhost_idx: usize,
    ) {
        self.shard().record_request(proto, status, dur, vhost_idx);
    }

    /// Record the response-level cache disposition (see
    /// [`TelemetryShard::record_cache_disposition`]).
    pub fn record_cache_disposition(&self, d: &hj_pagecache::Disposition) {
        self.shard().record_cache_disposition(d);
    }

    /// Record a cache HIT. `loopback` (the RAW peer IP is loopback) additionally bumps the
    /// loopback subset, so `real = total − loopback` excludes synthetic ab/h2load + ops traffic.
    /// `vhost` (the resolved request host) also bumps that vhost's series; an unmapped name
    /// lands in `__other__`.
    pub fn record_cache_hit(&self, loopback: bool, vhost: &str) {
        let s = self.shard();
        s.cache_hits.fetch_add(1, Relaxed);
        s.per_vhost[self.vhost_idx(vhost)]
            .cache_hits
            .fetch_add(1, Relaxed);
        if loopback {
            s.cache_hits_loopback.fetch_add(1, Relaxed);
        }
    }

    /// Record a cache MISS (+ loopback subset, + vhost series). See [`Self::record_cache_hit`].
    pub fn record_cache_miss(&self, loopback: bool, vhost: &str) {
        let s = self.shard();
        s.cache_misses.fetch_add(1, Relaxed);
        s.per_vhost[self.vhost_idx(vhost)]
            .cache_misses
            .fetch_add(1, Relaxed);
        if loopback {
            s.cache_misses_loopback.fetch_add(1, Relaxed);
        }
    }

    /// Record a cache BYPASS (+ loopback subset). See [`Self::record_cache_hit`].
    pub fn record_cache_bypass(&self, loopback: bool) {
        let s = self.shard();
        s.cache_bypass.fetch_add(1, Relaxed);
        if loopback {
            s.cache_bypass_loopback.fetch_add(1, Relaxed);
        }
    }

    /// Record a STALE serve (a subset of hits; the caller also calls
    /// [`Self::record_cache_hit`]). `loopback` bumps the loopback subset too.
    pub fn record_cache_stale_serve(&self, loopback: bool) {
        let s = self.shard();
        s.cache_stale_serves.fetch_add(1, Relaxed);
        if loopback {
            s.cache_stale_serves_loopback.fetch_add(1, Relaxed);
        }
    }

    /// Record the W-TinyLFU store-admission decision (at `cache_store`): admitted = stored,
    /// rejected = a one-hit-wonder the frequency sketch declined to store/precompress.
    pub fn record_cache_admission(&self, admitted: bool) {
        let s = self.shard();
        if admitted {
            s.cache_admitted.fetch_add(1, Relaxed);
        } else {
            s.cache_rejected.fetch_add(1, Relaxed);
        }
    }

    /// 1/`rate` sampler for the fine-grained phase timers (see
    /// [`TelemetryShard::sample_phase`]). Per-shard tick; the aggregate sampling
    /// rate is still ≈1/`rate`.
    pub fn sample_phase(&self, rate: u64) -> bool {
        self.shard().sample_phase(rate)
    }

    /// Sum each counter across all shards (read-side aggregation; scrape/flush only).
    fn counter_values(&self) -> [u64; COUNTER_NAMES.len()] {
        let mut acc = [0u64; COUNTER_NAMES.len()];
        for s in &self.shards {
            let v = s.0.counter_values();
            for (a, x) in acc.iter_mut().zip(v.iter()) {
                *a += *x;
            }
        }
        acc
    }

    /// Aggregate the `idx`-th histogram across all shards into one snapshot.
    fn aggregate_histogram(&self, idx: usize) -> HistogramSnapshot {
        let mut agg = HistogramSnapshot::default();
        for s in &self.shards {
            agg.merge(&s.0.histograms()[idx].3.snapshot());
        }
        agg
    }

    /// Sum the `i`-th vhost bucket's `(requests, 2xx, 3xx, 4xx, 5xx)` across shards.
    fn aggregate_vhost_counters(&self, i: usize) -> [u64; 5] {
        let mut acc = [0u64; 5];
        for s in &self.shards {
            let v = &s.0.per_vhost[i];
            acc[0] += v.requests.load(Relaxed);
            acc[1] += v.status_2xx.load(Relaxed);
            acc[2] += v.status_3xx.load(Relaxed);
            acc[3] += v.status_4xx.load(Relaxed);
            acc[4] += v.status_5xx.load(Relaxed);
        }
        acc
    }

    /// Aggregate the `i`-th vhost bucket's `[cache_hits, cache_misses]` across shards.
    fn aggregate_vhost_cache(&self, i: usize) -> [u64; 2] {
        let mut acc = [0u64; 2];
        for s in &self.shards {
            let v = &s.0.per_vhost[i];
            acc[0] += v.cache_hits.load(Relaxed);
            acc[1] += v.cache_misses.load(Relaxed);
        }
        acc
    }

    /// Aggregate the `i`-th vhost bucket's latency histogram across shards.
    fn aggregate_vhost_histogram(&self, i: usize) -> HistogramSnapshot {
        let mut agg = HistogramSnapshot::default();
        for s in &self.shards {
            agg.merge(&s.0.per_vhost[i].duration.snapshot());
        }
        agg
    }

    /// Per-vhost request/status/latency series (live scrape only — deliberately NOT
    /// in the TSV snapshot, which would balloon ~30× wider). One series block per
    /// named bucket (+ the `__other__` overflow), summed across shards.
    fn render_per_vhost(&self, out: &mut String) {
        let active: Vec<usize> = (0..MAX_VHOSTS)
            .filter(|&i| !self.vhost_names[i].is_empty())
            .collect();
        let counters: Vec<(usize, [u64; 5])> = active
            .iter()
            .map(|&i| (i, self.aggregate_vhost_counters(i)))
            .collect();
        out.push_str(
            "# HELP httpjet_requests_by_vhost Requests per vhost.\n\
             # TYPE httpjet_requests_by_vhost counter\n",
        );
        for (i, c) in &counters {
            let name = label_escape(&self.vhost_names[*i]);
            out.push_str(&format!(
                "httpjet_requests_by_vhost{{vhost=\"{name}\"}} {}\n",
                c[0]
            ));
        }
        out.push_str(
            "# HELP httpjet_responses_by_vhost Responses per vhost by status class.\n\
             # TYPE httpjet_responses_by_vhost counter\n",
        );
        for (i, c) in &counters {
            let name = label_escape(&self.vhost_names[*i]);
            for (class, val) in ["2xx", "3xx", "4xx", "5xx"].iter().zip(&c[1..]) {
                out.push_str(&format!(
                    "httpjet_responses_by_vhost{{vhost=\"{name}\",class=\"{class}\"}} {val}\n"
                ));
            }
        }
        let cache: Vec<(usize, [u64; 2])> = active
            .iter()
            .map(|&i| (i, self.aggregate_vhost_cache(i)))
            .collect();
        out.push_str(
            "# HELP httpjet_cache_hits_by_vhost Page-cache hits per vhost (the funnel's cache_hits split by vhost).\n\
             # TYPE httpjet_cache_hits_by_vhost counter\n",
        );
        for (i, c) in &cache {
            let name = label_escape(&self.vhost_names[*i]);
            out.push_str(&format!(
                "httpjet_cache_hits_by_vhost{{vhost=\"{name}\"}} {}\n",
                c[0]
            ));
        }
        out.push_str(
            "# HELP httpjet_cache_misses_by_vhost Page-cache misses per vhost (the funnel's cache_misses split by vhost).\n\
             # TYPE httpjet_cache_misses_by_vhost counter\n",
        );
        for (i, c) in &cache {
            let name = label_escape(&self.vhost_names[*i]);
            out.push_str(&format!(
                "httpjet_cache_misses_by_vhost{{vhost=\"{name}\"}} {}\n",
                c[1]
            ));
        }
        out.push_str(
            "# HELP httpjet_request_duration_by_vhost_seconds Per-vhost handle() wall time.\n\
             # TYPE httpjet_request_duration_by_vhost_seconds histogram\n",
        );
        for &i in &active {
            let name = label_escape(&self.vhost_names[i]);
            let h = self.aggregate_vhost_histogram(i);
            let mut cum = 0u64;
            for b in 0..NB {
                cum += h.buckets[b];
                let le = LE_US[b] as f64 / 1_000_000.0;
                out.push_str(&format!(
                    "httpjet_request_duration_by_vhost_seconds_bucket{{vhost=\"{name}\",le=\"{le}\"}} {cum}\n"
                ));
            }
            cum += h.inf;
            out.push_str(&format!(
                "httpjet_request_duration_by_vhost_seconds_bucket{{vhost=\"{name}\",le=\"+Inf\"}} {cum}\n"
            ));
            out.push_str(&format!(
                "httpjet_request_duration_by_vhost_seconds_sum{{vhost=\"{name}\"}} {:.6}\n",
                h.sum_us as f64 / 1_000_000.0
            ));
            out.push_str(&format!(
                "httpjet_request_duration_by_vhost_seconds_count{{vhost=\"{name}\"}} {}\n",
                h.count
            ));
        }
    }

    /// Append the Prometheus exposition for all telemetry counters + histograms,
    /// summed across shards.
    pub fn render_into(&self, out: &mut String) {
        let v = self.counter_values();
        for (name, value) in COUNTER_NAMES.iter().zip(v.iter()) {
            out.push_str(&format!(
                "# HELP httpjet_{name} Telemetry counter.\n# TYPE httpjet_{name} counter\nhttpjet_{name} {value}\n"
            ));
        }
        // Derived at-a-glance gauges: the REAL (loopback-excluded) cache hit ratio and the
        // W-TinyLFU admission accept ratio. Computed from the counters above so a scraper need
        // not subtract loopback itself; `real = total − loopback`.
        let get = |name: &str| -> u64 {
            COUNTER_NAMES
                .iter()
                .position(|n| *n == name)
                .map(|i| v[i])
                .unwrap_or(0)
        };
        let real_hits = get("cache_hits").saturating_sub(get("cache_hits_loopback"));
        let real_misses = get("cache_misses").saturating_sub(get("cache_misses_loopback"));
        let real_lookups = real_hits + real_misses;
        let real_ratio = if real_lookups > 0 {
            real_hits as f64 / real_lookups as f64
        } else {
            0.0
        };
        out.push_str(
            "# HELP httpjet_cache_hit_ratio_real Cache hit ratio over REAL (non-loopback) lookups.\n\
             # TYPE httpjet_cache_hit_ratio_real gauge\n",
        );
        out.push_str(&format!("httpjet_cache_hit_ratio_real {real_ratio:.4}\n"));
        let admitted = get("cache_admitted");
        let admit_total = admitted + get("cache_rejected");
        let admit_ratio = if admit_total > 0 {
            admitted as f64 / admit_total as f64
        } else {
            0.0
        };
        out.push_str(
            "# HELP httpjet_cache_admit_ratio Fraction of cacheable stores admitted by W-TinyLFU.\n\
             # TYPE httpjet_cache_admit_ratio gauge\n",
        );
        out.push_str(&format!("httpjet_cache_admit_ratio {admit_ratio:.4}\n"));
        // Histogram name/help/order is identical for every shard — read it off shard 0.
        for (idx, (name, help, _, _)) in self.shards[0].0.histograms().iter().enumerate() {
            self.aggregate_histogram(idx).render_into(name, help, out);
        }
        self.render_per_vhost(out);
    }

    /// One TSV snapshot row (no timestamp — the flusher prepends it): all
    /// counters, then each histogram's buckets + `inf` + `sum_us` + `count`, summed
    /// across shards, then the trailing [`EXTRA_NAMES`] section. A reader diffs two
    /// rows to get any window. Pairs with [`Self::tsv_header`].
    pub fn snapshot_row(&self, extra: &ExtraSample) -> String {
        let mut cells: Vec<String> = self
            .counter_values()
            .iter()
            .map(|v| v.to_string())
            .collect();
        let nhist = self.shards[0].0.histograms().len();
        for idx in 0..nhist {
            let s = self.aggregate_histogram(idx);
            for b in s.buckets {
                cells.push(b.to_string());
            }
            cells.push(s.inf.to_string());
            cells.push(s.sum_us.to_string());
            cells.push(s.count.to_string());
        }
        cells.extend(extra.values().iter().map(|v| v.to_string()));
        cells.join("\t")
    }

    /// Tab-separated header matching [`Self::snapshot_row`] (sans the leading
    /// `ts` column the flusher adds).
    pub fn tsv_header() -> String {
        let mut cols: Vec<String> = COUNTER_NAMES.iter().map(|c| c.to_string()).collect();
        // Drive the prefixes from the same list render/snapshot use (via a default
        // shard, since the names are static).
        for (_, _, prefix, _) in TelemetryShard::default().histograms() {
            for i in 0..NB {
                cols.push(format!("{prefix}_le_{}us", LE_US[i]));
            }
            cols.push(format!("{prefix}_inf"));
            cols.push(format!("{prefix}_sum_us"));
            cols.push(format!("{prefix}_count"));
        }
        cols.extend(EXTRA_NAMES.iter().map(|c| c.to_string()));
        cols.join("\t")
    }
}

/// Trailing TSV section, after the histogram columns so every earlier column keeps its
/// position: process/transport measurements sampled once per flush, never on a request.
/// Cumulative counters (raw totals since process start; diff two rows like the leading
/// counters): `tls_handshakes_*`, `conn_*_closes_*`, `cpu_ticks_*` (USER_HZ ticks),
/// `slices_*` (schedstat timeslices), `minflt_total` and `pagecache_*_total`: the
/// `httpjet_pagecache_*_total` metrics, so a drop in `pagecache_entries` /
/// `pagecache_disk_bytes` names its mechanism (purge, expiry sweep, eviction; a body
/// file deleted underneath the store counts as a disk read error on its next hit, and
/// `pagecache_missing_file_invalidations_total` stays 0 like its metric).
/// Instantaneous gauges at the row's `ts`: `active_*`, `rss_anon_bytes`,
/// `pagecache_*_bytes`, `pagecache_entries` and `lsapi_inflight_now`;
/// `lsapi_inflight_max_tick` is the peak in-flight count since the previous row.
/// A source that cannot be read (no page cache, no PHP pool, a /proc failure) emits 0.
pub const EXTRA_NAMES: [&str; 29] = [
    "tls_handshakes_full",
    "tls_handshakes_resumed",
    "conn_idle_closes_h1",
    "conn_peer_closes_h1",
    "conn_idle_closes_h2",
    "conn_peer_closes_h2",
    "active_connections",
    "active_requests",
    "rss_anon_bytes",
    "pagecache_memory_bytes",
    "pagecache_hot_bytes",
    "pagecache_disk_bytes",
    "lsapi_inflight_now",
    "lsapi_inflight_max_tick",
    "cpu_ticks_tokio",
    "cpu_ticks_uring_tls",
    "cpu_ticks_uring",
    "cpu_ticks_other",
    "slices_tokio",
    "slices_uring_tls",
    "minflt_total",
    "pagecache_entries",
    "pagecache_purges_total",
    "pagecache_purges_received_total",
    "pagecache_swept_expired_total",
    "pagecache_evictions_total",
    "pagecache_disk_evictions_total",
    "pagecache_missing_file_invalidations_total",
    "pagecache_disk_read_errors_total",
];

/// One sample of the [`EXTRA_NAMES`] columns.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExtraSample {
    pub tls_handshakes_full: u64,
    pub tls_handshakes_resumed: u64,
    pub conn_idle_closes_h1: u64,
    pub conn_peer_closes_h1: u64,
    pub conn_idle_closes_h2: u64,
    pub conn_peer_closes_h2: u64,
    pub active_connections: u64,
    pub active_requests: u64,
    pub rss_anon_bytes: u64,
    /// Bytes charged against `--page-cache-mem` (excludes the tag index).
    pub pagecache_memory_bytes: u64,
    pub pagecache_hot_bytes: u64,
    pub pagecache_disk_bytes: u64,
    pub lsapi_inflight_now: u64,
    pub lsapi_inflight_max_tick: u64,
    pub cpu: CpuTotals,
    pub pagecache_entries: u64,
    pub pagecache_purges_total: u64,
    /// Loopback `/__hj_cache_purge` requests applied (a subset of `pagecache_purges_total`).
    pub pagecache_purges_received_total: u64,
    pub pagecache_swept_expired_total: u64,
    pub pagecache_evictions_total: u64,
    pub pagecache_disk_evictions_total: u64,
    pub pagecache_missing_file_invalidations_total: u64,
    pub pagecache_disk_read_errors_total: u64,
}

impl ExtraSample {
    /// Values in [`EXTRA_NAMES`] order.
    fn values(&self) -> [u64; EXTRA_NAMES.len()] {
        [
            self.tls_handshakes_full,
            self.tls_handshakes_resumed,
            self.conn_idle_closes_h1,
            self.conn_peer_closes_h1,
            self.conn_idle_closes_h2,
            self.conn_peer_closes_h2,
            self.active_connections,
            self.active_requests,
            self.rss_anon_bytes,
            self.pagecache_memory_bytes,
            self.pagecache_hot_bytes,
            self.pagecache_disk_bytes,
            self.lsapi_inflight_now,
            self.lsapi_inflight_max_tick,
            self.cpu.ticks_tokio,
            self.cpu.ticks_uring_tls,
            self.cpu.ticks_uring,
            self.cpu.ticks_other,
            self.cpu.slices_tokio,
            self.cpu.slices_uring_tls,
            self.cpu.minflt_total,
            self.pagecache_entries,
            self.pagecache_purges_total,
            self.pagecache_purges_received_total,
            self.pagecache_swept_expired_total,
            self.pagecache_evictions_total,
            self.pagecache_disk_evictions_total,
            self.pagecache_missing_file_invalidations_total,
            self.pagecache_disk_read_errors_total,
        ]
    }
}

/// Per-thread-class CPU totals; see [`CpuSampler`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CpuTotals {
    pub ticks_tokio: u64,
    pub ticks_uring_tls: u64,
    pub ticks_uring: u64,
    pub ticks_other: u64,
    pub slices_tokio: u64,
    pub slices_uring_tls: u64,
    pub minflt_total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreadClass {
    Tokio,
    UringTls,
    Uring,
    Other,
}

/// By thread name (`comm`, 15 bytes max): the tokio runtime's workers and blocking
/// pool, the TLS listener cores (`hj-uring-tls-N`), every other io_uring core
/// (`hj-uring-N`, `hj-uring-h3p-N`, ...), and everything else.
fn classify_thread(comm: &str) -> ThreadClass {
    if comm.starts_with("tokio") {
        ThreadClass::Tokio
    } else if comm.starts_with("hj-uring-tls") {
        ThreadClass::UringTls
    } else if comm.starts_with("hj-uring") {
        ThreadClass::Uring
    } else {
        ThreadClass::Other
    }
}

#[derive(Debug, Clone, Copy)]
struct ThreadSample {
    tid: u32,
    class: ThreadClass,
    ticks: u64,
    slices: u64,
}

/// Turns per-thread `/proc/self/task/*` readings into monotonic per-class totals.
/// Threads come and go (the tokio blocking pool idles threads out), so each class
/// accumulates per-thread deltas between samples instead of summing live threads;
/// `ticks_other` is the process total (which keeps exited threads' time) minus the
/// classified sum, so the four tick columns add up to the process's CPU and a thread's
/// final unsampled ticks land in `other` rather than vanishing.
#[derive(Debug, Default)]
pub struct CpuSampler {
    last: std::collections::HashMap<u32, (ThreadClass, u64, u64)>,
    acc: CpuTotals,
}

impl CpuSampler {
    fn absorb(&mut self, threads: &[ThreadSample]) {
        let mut next = std::collections::HashMap::with_capacity(threads.len());
        for t in threads {
            if t.class == ThreadClass::Other {
                continue;
            }
            // A reused tid (or a renamed thread) restarts from zero.
            let (dt, ds) = match self.last.get(&t.tid) {
                Some(&(class, ticks, slices))
                    if class == t.class && t.ticks >= ticks && t.slices >= slices =>
                {
                    (t.ticks - ticks, t.slices - slices)
                }
                _ => (t.ticks, t.slices),
            };
            let acc = &mut self.acc;
            match t.class {
                ThreadClass::Tokio => {
                    acc.ticks_tokio += dt;
                    acc.slices_tokio += ds;
                }
                ThreadClass::UringTls => {
                    acc.ticks_uring_tls += dt;
                    acc.slices_uring_tls += ds;
                }
                ThreadClass::Uring => acc.ticks_uring += dt,
                ThreadClass::Other => {}
            }
            next.insert(t.tid, (t.class, t.ticks, t.slices));
        }
        self.last = next;
    }

    fn totals(&self, process_ticks: u64, minflt_total: u64) -> CpuTotals {
        let a = self.acc;
        CpuTotals {
            ticks_other: process_ticks
                .saturating_sub(a.ticks_tokio + a.ticks_uring_tls + a.ticks_uring),
            minflt_total,
            ..a
        }
    }

    /// Read `/proc/self/task/*` and `/proc/self/stat` (blocking; a few dozen tiny
    /// procfs reads). A thread that exits mid-scan is skipped; an unreadable process
    /// stat yields 0 for `ticks_other` and `minflt_total`.
    fn sample(&mut self) -> CpuTotals {
        let mut threads = Vec::new();
        if let Ok(dir) = std::fs::read_dir("/proc/self/task") {
            for entry in dir.flatten() {
                let Some(tid) = entry.file_name().to_str().and_then(|t| t.parse().ok()) else {
                    continue;
                };
                let base = entry.path();
                let Ok(comm) = std::fs::read_to_string(base.join("comm")) else {
                    continue;
                };
                let class = classify_thread(comm.trim_end());
                if class == ThreadClass::Other {
                    continue;
                }
                let Some(stat) = std::fs::read_to_string(base.join("stat"))
                    .ok()
                    .and_then(|s| parse_proc_stat(&s))
                else {
                    continue;
                };
                let slices = if matches!(class, ThreadClass::Tokio | ThreadClass::UringTls) {
                    std::fs::read_to_string(base.join("schedstat"))
                        .ok()
                        .and_then(|s| parse_schedstat_slices(&s))
                        .unwrap_or(0)
                } else {
                    0
                };
                threads.push(ThreadSample {
                    tid,
                    class,
                    ticks: stat.ticks,
                    slices,
                });
            }
        }
        self.absorb(&threads);
        let process = std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|s| parse_proc_stat(&s))
            .unwrap_or_default();
        self.totals(process.ticks, process.minflt)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ProcStat {
    minflt: u64,
    /// utime + stime.
    ticks: u64,
}

/// `minflt` (field 10) and `utime`+`stime` (fields 14, 15) of a `/proc/*/stat` line. The
/// `comm` field may contain spaces or parentheses, so fields are counted from the LAST `)`.
fn parse_proc_stat(line: &str) -> Option<ProcStat> {
    let (_, rest) = line.rsplit_once(')')?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // `rest` starts at field 3 (state).
    let field = |n: usize| fields.get(n - 3)?.parse::<u64>().ok();
    Some(ProcStat {
        minflt: field(10)?,
        ticks: field(14)?.saturating_add(field(15)?),
    })
}

/// Third `/proc/*/schedstat` field: timeslices run on a CPU.
fn parse_schedstat_slices(line: &str) -> Option<u64> {
    line.split_whitespace().nth(2)?.parse().ok()
}

/// Gathers the [`EXTRA_NAMES`] columns for the flusher from the gen-0 [`ServerState`],
/// whose counters, page cache and PHP pools are shared by every SIGHUP generation.
///
/// [`ServerState`]: crate::state::ServerState
pub struct TelemetrySampler {
    state: std::sync::Arc<crate::state::ServerState>,
    cpu: std::sync::Mutex<CpuSampler>,
}

impl TelemetrySampler {
    pub fn new(state: std::sync::Arc<crate::state::ServerState>) -> Self {
        TelemetrySampler {
            state,
            cpu: std::sync::Mutex::new(CpuSampler::default()),
        }
    }

    pub fn telemetry(&self) -> &Telemetry {
        &self.state.telemetry
    }

    fn sample_blocking(&self) -> ExtraSample {
        let state = &*self.state;
        let m = &state.metrics;
        let (h2_idle, h2_peer) = hj_h2::server::connection_close_counts();
        let page = state
            .page_cache
            .as_ref()
            .map(|pc| pc.footprint())
            .unwrap_or_default();
        let (lsapi_now, lsapi_max) = state
            .lsapi
            .as_ref()
            .and_then(|registry| registry.default_pool_inflight())
            .unwrap_or_default();
        let cpu = self
            .cpu
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sample();
        ExtraSample {
            tls_handshakes_full: m.tls_handshakes_full.load(Relaxed),
            tls_handshakes_resumed: m.tls_handshakes_resumed.load(Relaxed),
            conn_idle_closes_h1: m.h1_idle_closes.load(Relaxed),
            conn_peer_closes_h1: m.h1_peer_closes.load(Relaxed),
            conn_idle_closes_h2: h2_idle,
            conn_peer_closes_h2: h2_peer,
            active_connections: m.active_conns.load(Relaxed),
            active_requests: m.active_requests.load(Relaxed),
            rss_anon_bytes: crate::metrics::proc_mem().map_or(0, |p| p.rss_anon_bytes),
            pagecache_memory_bytes: page.index_ram_bytes,
            pagecache_hot_bytes: page.hot_bytes,
            pagecache_disk_bytes: page.disk_bytes,
            lsapi_inflight_now: lsapi_now,
            lsapi_inflight_max_tick: lsapi_max,
            cpu,
            pagecache_entries: page.entries,
            pagecache_purges_total: page.purges,
            pagecache_purges_received_total: m.purges_received.load(Relaxed),
            pagecache_swept_expired_total: page.swept_expired,
            pagecache_evictions_total: page.evictions,
            pagecache_disk_evictions_total: page.disk_evictions,
            pagecache_missing_file_invalidations_total: page.missing_file_invalidations,
            pagecache_disk_read_errors_total: page.disk_read_errors,
        }
    }

    /// One sample, taken on the blocking pool (procfs reads + one short lock per
    /// page-cache shard) so it never stalls the runtime the flusher shares.
    async fn sample(self: &std::sync::Arc<Self>) -> ExtraSample {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.sample_blocking())
            .await
            .unwrap_or_default()
    }
}

/// Background task: append a cumulative telemetry snapshot to `path` every
/// `interval` until shutdown. The final row is the caller's [`flush_once`] after the
/// connection drain: a second shutdown flush from here raced the runtime teardown
/// and failed its write. Once-per-interval, so plain async file I/O (never on a
/// request hot path). Writes the TSV header when the file is new; a reader diffs two
/// rows for any window. Rotates to `<path>.1` past 32 MiB.
pub async fn run_flush(
    sampler: std::sync::Arc<TelemetrySampler>,
    path: std::path::PathBuf,
    interval: std::time::Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    tracing::info!(path = %path.display(), secs = interval.as_secs(), "telemetry: disk snapshot flush enabled");
    rotate_stale_schema(&path).await;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.cancelled() => break,
        }
        flush_once(&sampler, &path).await;
    }
}

/// (schema) Never mix column generations in one file: columns are appended
/// over releases, but the header is only written when the file is created —
/// by 2026-06 one file held 147/154/160-col rows under a stale 147-col
/// header, silently breaking every name-addressed diff reader. If the
/// existing header doesn't match the current schema, rotate the file out so
/// this generation starts fresh with its own header.
async fn rotate_stale_schema(path: &std::path::Path) {
    use tokio::io::AsyncBufReadExt;
    let expected = format!("ts\t{}", Telemetry::tsv_header());
    if let Ok(f) = tokio::fs::File::open(path).await {
        let mut first = String::new();
        let mut r = tokio::io::BufReader::new(f);
        if r.read_line(&mut first).await.is_ok()
            && !first.is_empty()
            && first.trim_end() != expected
        {
            let _ = tokio::fs::rename(path, path.with_extension("tsv.1")).await;
            tracing::info!(path = %path.display(), "telemetry: snapshot schema changed; rotated old file to .tsv.1");
        }
    }
}

pub async fn flush_once(sampler: &std::sync::Arc<TelemetrySampler>, path: &std::path::Path) {
    let extra = sampler.sample().await;
    append_snapshot(sampler.telemetry(), &extra, path).await;
}

async fn append_snapshot(t: &Telemetry, extra: &ExtraSample, path: &std::path::Path) {
    use tokio::io::AsyncWriteExt;
    // Size-based rotation: keep exactly one backup (`<path>.1`).
    if let Ok(md) = tokio::fs::metadata(path).await {
        if md.len() > 32 * 1024 * 1024 {
            let _ = tokio::fs::rename(path, path.with_extension("tsv.1")).await;
        }
    }
    let fresh = tokio::fs::metadata(path).await.is_err();
    let mut f = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "telemetry: snapshot open failed");
            return;
        }
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut buf = String::new();
    if fresh {
        buf.push_str("ts\t");
        buf.push_str(&Telemetry::tsv_header());
        buf.push('\n');
    }
    buf.push_str(&ts.to_string());
    buf.push('\t');
    buf.push_str(&t.snapshot_row(extra));
    buf.push('\n');
    if let Err(e) = f.write_all(buf.as_bytes()).await {
        tracing::warn!(error = %e, "telemetry: snapshot write failed");
    } else if let Err(e) = f.flush().await {
        tracing::warn!(error = %e, "telemetry: snapshot flush failed");
    }
}

/// Escape a Prometheus label value (`\`, `"`, newline). Vhost names are hostnames
/// (already safe), but escape so a malformed config name can't break the exposition.
fn label_escape(s: &str) -> Cow<'_, str> {
    if !s.bytes().any(|b| b == b'\\' || b == b'"' || b == b'\n') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_buckets_and_sum() {
        let h = AtomicHistogram::default();
        h.record(Duration::from_micros(40)); // bucket 0 (<=50us)
        h.record(Duration::from_micros(60)); // bucket 1 (<=100us)
        h.record(Duration::from_millis(3)); // 3000us -> bucket 6 (<=5000us)
        h.record(Duration::from_secs(10)); // > 5s -> +Inf
        let s = h.snapshot();
        assert_eq!(s.count, 4);
        assert_eq!(s.buckets[0], 1);
        assert_eq!(s.buckets[1], 1);
        assert_eq!(s.inf, 1);
        assert_eq!(s.sum_us, 40 + 60 + 3_000 + 10_000_000);
        // Cumulative render: le=+Inf bucket must equal count.
        let mut out = String::new();
        h.snapshot().render_into("t", "h", &mut out);
        assert!(out.contains("t_bucket{le=\"+Inf\"} 4\n"), "{out}");
        assert!(out.contains("t_count 4\n"));
    }

    fn counter(v: &[u64; COUNTER_NAMES.len()], name: &str) -> u64 {
        v[COUNTER_NAMES.iter().position(|n| *n == name).unwrap()]
    }

    #[test]
    fn record_request_counts_proto_and_status() {
        let t = Telemetry::default();
        let vi = t.vhost_idx("x");
        t.record_request(hj_core::Proto::Http2, 200, Duration::from_micros(80), vi);
        t.record_request(hj_core::Proto::Http2, 503, Duration::from_millis(2), vi);
        t.record_request(hj_core::Proto::Http1, 301, Duration::from_micros(70), vi);
        // Read via the aggregating path (here all three landed on the test thread's shard).
        let v = t.counter_values();
        assert_eq!(counter(&v, "proto_h2"), 2);
        assert_eq!(counter(&v, "proto_h1"), 1);
        assert_eq!(counter(&v, "status_2xx"), 1);
        assert_eq!(counter(&v, "status_3xx"), 1);
        assert_eq!(counter(&v, "status_5xx"), 1);
        assert_eq!(t.aggregate_histogram(0).count, 3); // request_duration is histogram 0
    }

    #[test]
    fn per_vhost_and_by_code_breakdown() {
        let t = Telemetry::new(["a.com".to_string(), "b.com".to_string()]);
        let a = t.vhost_idx("a.com");
        let b = t.vhost_idx("b.com");
        let other = t.vhost_idx("unknown.com");
        assert_ne!(a, b);
        assert_eq!(other, VHOST_OVERFLOW);
        t.record_request(hj_core::Proto::Http2, 200, Duration::from_micros(80), a);
        t.record_request(hj_core::Proto::Http2, 404, Duration::from_micros(90), a);
        t.record_request(hj_core::Proto::Http2, 502, Duration::from_millis(2), b);
        t.record_request(hj_core::Proto::Http2, 200, Duration::from_micros(70), other);
        // Global by-exact-code counters.
        let v = t.counter_values();
        assert_eq!(counter(&v, "status_404"), 1);
        assert_eq!(counter(&v, "status_502"), 1);
        // Per-vhost render series (live scrape).
        let mut out = String::new();
        t.render_into(&mut out);
        assert!(
            out.contains("httpjet_requests_by_vhost{vhost=\"a.com\"} 2"),
            "{out}"
        );
        assert!(
            out.contains("httpjet_requests_by_vhost{vhost=\"b.com\"} 1"),
            "{out}"
        );
        assert!(
            out.contains("httpjet_requests_by_vhost{vhost=\"__other__\"} 1"),
            "{out}"
        );
        assert!(
            out.contains("httpjet_responses_by_vhost{vhost=\"a.com\",class=\"4xx\"} 1"),
            "{out}"
        );
        assert!(
            out.contains("httpjet_responses_by_vhost{vhost=\"b.com\",class=\"5xx\"} 1"),
            "{out}"
        );
        assert!(
            out.contains("httpjet_request_duration_by_vhost_seconds_count{vhost=\"a.com\"} 2"),
            "{out}"
        );
        // by-exact-code also renders as a flat counter.
        assert!(out.contains("httpjet_status_404 1\n"), "{out}");
    }

    #[test]
    fn aggregation_sums_across_shards() {
        let t = Telemetry::default();
        // Write directly into distinct shards; the read side must sum them.
        t.shards[0].0.cache_hits.fetch_add(3, Relaxed);
        t.shards[5].0.cache_hits.fetch_add(4, Relaxed);
        t.shards[1]
            .0
            .request_duration
            .record(Duration::from_micros(40));
        t.shards[9]
            .0
            .request_duration
            .record(Duration::from_micros(60));
        let v = t.counter_values();
        assert_eq!(counter(&v, "cache_hits"), 7);
        let h = t.aggregate_histogram(0);
        assert_eq!(h.count, 2);
        assert_eq!(h.sum_us, 100);
    }

    #[test]
    fn snapshot_row_matches_header_arity() {
        let t = Telemetry::default();
        let header = Telemetry::tsv_header();
        let cols: Vec<&str> = header.split('\t').collect();
        let row = t.snapshot_row(&ExtraSample::default());
        assert_eq!(cols.len(), row.split('\t').count());
        // Counters + 11 histograms * (16 buckets + inf + sum + count = 19) + the trailing
        // section, which must stay LAST so every earlier column keeps its position.
        let fixed = COUNTER_NAMES.len() + 11 * (NB + 3);
        assert_eq!(cols.len(), fixed + EXTRA_NAMES.len());
        assert_eq!(cols[fixed - 1], "phase_collect_cl_count");
        assert_eq!(&cols[fixed..], &EXTRA_NAMES[..]);
        let unique: std::collections::HashSet<&str> = cols.iter().copied().collect();
        assert_eq!(unique.len(), cols.len(), "column names must be unique");
    }

    #[test]
    fn extra_values_follow_extra_names() {
        let e = ExtraSample {
            tls_handshakes_full: 1,
            tls_handshakes_resumed: 2,
            conn_idle_closes_h1: 3,
            conn_peer_closes_h1: 4,
            conn_idle_closes_h2: 5,
            conn_peer_closes_h2: 6,
            active_connections: 7,
            active_requests: 8,
            rss_anon_bytes: 9,
            pagecache_memory_bytes: 10,
            pagecache_hot_bytes: 11,
            pagecache_disk_bytes: 12,
            lsapi_inflight_now: 13,
            lsapi_inflight_max_tick: 14,
            cpu: CpuTotals {
                ticks_tokio: 15,
                ticks_uring_tls: 16,
                ticks_uring: 17,
                ticks_other: 18,
                slices_tokio: 19,
                slices_uring_tls: 20,
                minflt_total: 21,
            },
            pagecache_entries: 22,
            pagecache_purges_total: 23,
            pagecache_purges_received_total: 24,
            pagecache_swept_expired_total: 25,
            pagecache_evictions_total: 26,
            pagecache_disk_evictions_total: 27,
            pagecache_missing_file_invalidations_total: 28,
            pagecache_disk_read_errors_total: 29,
        };
        let expected: Vec<u64> = (1..=EXTRA_NAMES.len() as u64).collect();
        assert_eq!(e.values().to_vec(), expected);
    }

    #[test]
    fn thread_classifier_by_comm() {
        for (comm, class) in [
            ("tokio-rt-worker", ThreadClass::Tokio),
            ("tokio-runtime-w", ThreadClass::Tokio),
            ("hj-uring-tls-0", ThreadClass::UringTls),
            ("hj-uring-tls-15", ThreadClass::UringTls),
            ("hj-uring-0", ThreadClass::Uring),
            ("hj-uring-h3p-7", ThreadClass::Uring),
            ("hj-uring-h2-3", ThreadClass::Uring),
            ("hj-uring-bridge", ThreadClass::Uring),
            ("httpjet", ThreadClass::Other),
            ("lsphp", ThreadClass::Other),
            ("", ThreadClass::Other),
        ] {
            assert_eq!(classify_thread(comm), class, "{comm}");
        }
    }

    #[test]
    fn proc_stat_parsing_counts_fields_after_the_last_paren() {
        // Real shape: a comm with spaces and parentheses must not shift the fields.
        let line = "4122921 (my (odd) name) S 1 4122921 4122921 0 -1 4194560 3162 0 7 0 \
                    40 5 0 0 17 -3 38 0 17281586 2800082944 248954";
        assert_eq!(
            parse_proc_stat(line),
            Some(ProcStat {
                minflt: 3162,
                ticks: 45
            })
        );
        assert_eq!(parse_proc_stat("garbage"), None);
        assert_eq!(parse_proc_stat("1 (x) S 1 2"), None);
        assert_eq!(
            parse_schedstat_slices("97352608 87256497 3170\n"),
            Some(3170)
        );
        assert_eq!(parse_schedstat_slices("1 2"), None);
    }

    #[test]
    fn cpu_sampler_accumulates_monotonic_deltas_per_class() {
        let t = |tid, class, ticks, slices| ThreadSample {
            tid,
            class,
            ticks,
            slices,
        };
        let mut s = CpuSampler::default();
        s.absorb(&[
            t(1, ThreadClass::Tokio, 100, 10),
            t(2, ThreadClass::Tokio, 50, 5),
            t(3, ThreadClass::UringTls, 30, 3),
            t(4, ThreadClass::Uring, 20, 2),
            t(5, ThreadClass::Other, 1_000, 99),
        ]);
        let c = s.totals(500, 77);
        assert_eq!(
            (c.ticks_tokio, c.ticks_uring_tls, c.ticks_uring),
            (150, 30, 20)
        );
        assert_eq!((c.slices_tokio, c.slices_uring_tls), (15, 3));
        assert_eq!(c.ticks_other, 500 - 200, "residual of the process total");
        assert_eq!(c.minflt_total, 77);

        // Thread 2 (a blocking-pool thread) exits; its ticks stay counted. Thread 1 moves
        // on; tid 3 is reused by a NEW tls thread with fewer ticks (restarts from zero).
        s.absorb(&[
            t(1, ThreadClass::Tokio, 130, 12),
            t(3, ThreadClass::UringTls, 4, 1),
            t(4, ThreadClass::Uring, 25, 2),
        ]);
        let c = s.totals(600, 80);
        assert_eq!(
            (c.ticks_tokio, c.ticks_uring_tls, c.ticks_uring),
            (180, 34, 25)
        );
        assert_eq!((c.slices_tokio, c.slices_uring_tls), (17, 4));
        assert_eq!(c.ticks_other, 600 - 239);

        // A tid reappearing under another class is a new thread, not a delta.
        s.absorb(&[t(1, ThreadClass::Uring, 5, 0)]);
        assert_eq!(s.totals(0, 0).ticks_uring, 30);
        assert_eq!(s.totals(0, 0).ticks_other, 0, "saturates, never wraps");
    }

    #[test]
    fn cpu_sampler_reads_this_process() {
        let mut s = CpuSampler::default();
        let first = s.sample();
        assert!(first.minflt_total > 0, "{first:?}");
        let second = s.sample();
        assert!(second.minflt_total >= first.minflt_total);
        assert!(second.ticks_other + second.ticks_tokio >= first.ticks_tokio);
    }

    #[test]
    fn real_hit_ratio_excludes_loopback() {
        let t = Telemetry::default();
        // 10 hits total, 4 of them loopback; 6 misses total, 1 loopback.
        // real = 6 hits / (6 hits + 5 misses) = 0.5455.
        for _ in 0..6 {
            t.record_cache_hit(false, "");
        }
        for _ in 0..4 {
            t.record_cache_hit(true, "");
        }
        for _ in 0..5 {
            t.record_cache_miss(false, "");
        }
        t.record_cache_miss(true, "");
        t.record_cache_admission(true);
        for _ in 0..3 {
            t.record_cache_admission(false);
        }
        let v = t.counter_values();
        assert_eq!(counter(&v, "cache_hits"), 10);
        assert_eq!(counter(&v, "cache_hits_loopback"), 4);
        assert_eq!(counter(&v, "cache_misses"), 6);
        assert_eq!(counter(&v, "cache_misses_loopback"), 1);
        assert_eq!(counter(&v, "cache_admitted"), 1);
        assert_eq!(counter(&v, "cache_rejected"), 3);
        let mut out = String::new();
        t.render_into(&mut out);
        // real hits = 10-4 = 6; real misses = 6-1 = 5; 6/11 = 0.5455.
        assert!(
            out.contains("httpjet_cache_hit_ratio_real 0.5455\n"),
            "{out}"
        );
        // admit ratio = 1/(1+3) = 0.25.
        assert!(out.contains("httpjet_cache_admit_ratio 0.2500\n"), "{out}");
    }

    #[test]
    fn per_vhost_cache_counters_render() {
        let t = Telemetry::new(["a.example".to_string(), "b.example".to_string()]);
        t.record_cache_hit(false, "a.example");
        t.record_cache_hit(true, "a.example");
        t.record_cache_miss(false, "b.example");
        t.record_cache_hit(false, "unknown.example");
        let mut out = String::new();
        t.render_into(&mut out);
        assert!(
            out.contains("httpjet_cache_hits_by_vhost{vhost=\"a.example\"} 2\n"),
            "{out}"
        );
        assert!(
            out.contains("httpjet_cache_misses_by_vhost{vhost=\"a.example\"} 0\n"),
            "{out}"
        );
        assert!(
            out.contains("httpjet_cache_misses_by_vhost{vhost=\"b.example\"} 1\n"),
            "{out}"
        );
        assert!(
            out.contains("httpjet_cache_hits_by_vhost{vhost=\"__other__\"} 1\n"),
            "{out}"
        );
        // The per-vhost split never changes the global funnel counters.
        let v = t.counter_values();
        assert_eq!(counter(&v, "cache_hits"), 3);
        assert_eq!(counter(&v, "cache_misses"), 1);
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "httpjet_telemetry_{tag}_{}_{}.tsv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn cell<'a>(header: &str, row: &'a str, name: &str) -> &'a str {
        let idx = header
            .split('\t')
            .position(|c| c == name)
            .unwrap_or_else(|| panic!("no column {name}"));
        row.split('\t').nth(idx).unwrap()
    }

    #[tokio::test]
    async fn append_snapshot_writes_header_and_named_cells() {
        let t = Telemetry::default();
        t.record_cache_hit(false, "");
        let path = temp_path("append");
        let extra = ExtraSample {
            lsapi_inflight_max_tick: 42,
            cpu: CpuTotals {
                minflt_total: 9,
                ..CpuTotals::default()
            },
            ..ExtraSample::default()
        };
        append_snapshot(&t, &extra, &path).await;
        append_snapshot(&t, &ExtraSample::default(), &path).await;
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            body.lines().count(),
            3,
            "header once, then two rows: {body}"
        );
        let header = body.lines().next().unwrap();
        let row = body.lines().nth(1).unwrap();
        assert_eq!(cell(header, row, "cache_hits"), "1", "{body}");
        assert_eq!(cell(header, row, "lsapi_inflight_max_tick"), "42");
        assert_eq!(cell(header, row, "minflt_total"), "9");
        assert_eq!(cell(header, row, "request_duration_count"), "0");
        let _ = std::fs::remove_file(path);
    }

    /// A file written before the page-cache counter columns existed is rotated out
    /// at startup, so its rows never sit under the new header; a current one stays.
    #[tokio::test]
    async fn schema_change_rotates_the_old_file_out() {
        let path = temp_path("schema");
        let rotated = path.with_extension("tsv.1");
        let current = format!("ts\t{}", Telemetry::tsv_header());
        let cols: Vec<&str> = current.split('\t').collect();
        let old = cols[..cols.len() - 8].join("\t");
        assert!(old.ends_with("\tminflt_total"), "{old}");
        std::fs::write(&path, format!("{old}\n1\t0\n")).unwrap();
        rotate_stale_schema(&path).await;
        assert!(!path.exists());
        assert!(std::fs::read_to_string(&rotated).unwrap().starts_with(&old));

        let extra = ExtraSample {
            pagecache_disk_read_errors_total: 5,
            ..ExtraSample::default()
        };
        append_snapshot(&Telemetry::default(), &extra, &path).await;
        let body = std::fs::read_to_string(&path).unwrap();
        let header = body.lines().next().unwrap();
        assert_eq!(header, current);
        let row = body.lines().nth(1).unwrap();
        assert_eq!(cell(header, row, "pagecache_disk_read_errors_total"), "5");

        rotate_stale_schema(&path).await;
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(rotated);
    }

    /// The flusher's sampler reads the gen-0 state's shared counters, the page cache and
    /// procfs, and the row lands under the right header names.
    #[tokio::test]
    async fn flush_once_samples_server_state_into_named_columns() {
        use crate::state::{RewriteTuning, ServerState, XfCapsuleConfig};
        let server_root = std::env::temp_dir().join(format!(
            "httpjet_telemetry_srv_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(server_root.join("logs")).unwrap();
        let server = hj_core::config::ServerConfig {
            server_root: server_root.clone(),
            ..hj_core::config::ServerConfig::default()
        };
        let page_cache = std::sync::Arc::new(hj_pagecache::PageStore::new(
            hj_pagecache::StoreConfig::default(),
        ));
        let file_id = |inode| hj_pagecache::FileId {
            size: 1,
            mtime_secs: 1,
            mtime_nanos: 0,
            inode,
        };
        for (path, inode) in [("/a", 1), ("/b", 2)] {
            assert!(page_cache.store_static(
                1,
                std::path::Path::new(path),
                file_id(inode),
                bytes::Bytes::from_static(b"x"),
                std::sync::Arc::from("text/plain"),
                String::new(),
                String::new(),
            ));
        }
        // A changed file identity tears the cached copy down: one eviction.
        assert!(
            page_cache
                .get_static(
                    1,
                    std::path::Path::new("/b"),
                    &file_id(3),
                    std::time::Instant::now()
                )
                .is_none()
        );
        page_cache.purge_tags(&["t"]);
        page_cache.purge_all();
        let state = ServerState::new(
            std::sync::Arc::new(server),
            None,
            None,
            Some(page_cache.clone()),
            std::sync::Arc::new(hj_compress::PageDictRegistry::empty()),
            1,
            XfCapsuleConfig::disabled(),
            None,
            false,
            None,
            false,
            RewriteTuning::default(),
        )
        .unwrap();
        state.metrics.active_conns.store(7, Relaxed);
        state.metrics.active_requests.store(3, Relaxed);
        state.metrics.tls_handshakes_full.store(11, Relaxed);
        state.metrics.tls_handshakes_resumed.store(2, Relaxed);
        state.metrics.h1_idle_closes.store(5, Relaxed);
        state.metrics.h1_peer_closes.store(6, Relaxed);
        state.metrics.purges_received.store(4, Relaxed);
        let sampler = std::sync::Arc::new(TelemetrySampler::new(state));
        let path = temp_path("sampler");
        flush_once(&sampler, &path).await;
        let body = std::fs::read_to_string(&path).unwrap();
        let header = body.lines().next().unwrap();
        let row = body.lines().nth(1).unwrap();
        assert_eq!(header.split('\t').count(), row.split('\t').count());
        assert_eq!(cell(header, row, "active_connections"), "7");
        assert_eq!(cell(header, row, "active_requests"), "3");
        assert_eq!(cell(header, row, "tls_handshakes_full"), "11");
        assert_eq!(cell(header, row, "tls_handshakes_resumed"), "2");
        assert_eq!(cell(header, row, "conn_idle_closes_h1"), "5");
        assert_eq!(cell(header, row, "conn_peer_closes_h1"), "6");
        assert_eq!(cell(header, row, "lsapi_inflight_now"), "0");
        assert_eq!(cell(header, row, "pagecache_disk_bytes"), "0");
        assert_eq!(cell(header, row, "pagecache_entries"), "1");
        assert_eq!(cell(header, row, "pagecache_purges_total"), "2");
        assert_eq!(cell(header, row, "pagecache_purges_received_total"), "4");
        assert_eq!(cell(header, row, "pagecache_evictions_total"), "1");
        let stats = page_cache.stats();
        for (name, value) in [
            ("pagecache_entries", stats.entries),
            ("pagecache_purges_total", stats.purges),
            ("pagecache_swept_expired_total", stats.swept_expired),
            ("pagecache_evictions_total", stats.evictions),
            ("pagecache_disk_evictions_total", stats.disk_evictions),
            (
                "pagecache_missing_file_invalidations_total",
                stats.missing_file_invalidations,
            ),
            ("pagecache_disk_read_errors_total", stats.disk_read_errors),
        ] {
            assert_eq!(cell(header, row, name), value.to_string(), "{name}");
        }
        assert_ne!(cell(header, row, "rss_anon_bytes"), "0");
        assert_ne!(cell(header, row, "minflt_total"), "0");
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(server_root);
    }
}
