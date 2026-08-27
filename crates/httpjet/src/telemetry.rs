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
            hj_core::Proto::Http1 => &self.proto_h1,
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
    fn histograms(&self) -> [(&'static str, &'static str, &'static str, &AtomicHistogram); 7] {
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
const SHARDS: usize = 64;

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
    pub fn record_cache_hit(&self, loopback: bool) {
        let s = self.shard();
        s.cache_hits.fetch_add(1, Relaxed);
        if loopback {
            s.cache_hits_loopback.fetch_add(1, Relaxed);
        }
    }

    /// Record a cache MISS (+ loopback subset). See [`Self::record_cache_hit`].
    pub fn record_cache_miss(&self, loopback: bool) {
        let s = self.shard();
        s.cache_misses.fetch_add(1, Relaxed);
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

    /// One cumulative TSV snapshot row (no timestamp — the flusher prepends it):
    /// all counters, then each histogram's buckets + `inf` + `sum_us` + `count`,
    /// summed across shards. A reader diffs two rows to get any window. Pairs with
    /// [`Self::tsv_header`].
    pub fn snapshot_row(&self) -> String {
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
        cols.join("\t")
    }
}

/// Background task: append a cumulative telemetry snapshot to `path` every
/// `interval`, plus a final flush on shutdown. Once-per-interval, so plain async
/// file I/O (never on a request hot path). Writes the TSV header when the file is
/// new; a reader diffs two rows for any window. Rotates to `<path>.1` past 32 MiB.
pub async fn run_flush(
    telemetry: std::sync::Arc<Telemetry>,
    path: std::path::PathBuf,
    interval: std::time::Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    tracing::info!(path = %path.display(), secs = interval.as_secs(), "telemetry: disk snapshot flush enabled");
    // (schema) Never mix column generations in one file: columns are appended
    // over releases, but the header is only written when the file is created —
    // by 2026-06 one file held 147/154/160-col rows under a stale 147-col
    // header, silently breaking every name-addressed diff reader. If the
    // existing header doesn't match the current schema, rotate the file out so
    // this generation starts fresh with its own header.
    {
        use tokio::io::AsyncBufReadExt;
        let expected = format!("ts\t{}", Telemetry::tsv_header());
        if let Ok(f) = tokio::fs::File::open(&path).await {
            let mut first = String::new();
            let mut r = tokio::io::BufReader::new(f);
            if r.read_line(&mut first).await.is_ok()
                && !first.is_empty()
                && first.trim_end() != expected
            {
                let _ = tokio::fs::rename(&path, path.with_extension("tsv.1")).await;
                tracing::info!(path = %path.display(), "telemetry: snapshot schema changed; rotated old file to .tsv.1");
            }
        }
    }
    loop {
        let stopping = tokio::select! {
            _ = tokio::time::sleep(interval) => false,
            _ = shutdown.cancelled() => true,
        };
        append_snapshot(&telemetry, &path).await;
        if stopping {
            break;
        }
    }
}

pub async fn flush_once(t: &Telemetry, path: &std::path::Path) {
    append_snapshot(t, path).await;
}

async fn append_snapshot(t: &Telemetry, path: &std::path::Path) {
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
    buf.push_str(&t.snapshot_row());
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
        let cols = Telemetry::tsv_header().split('\t').count();
        let cells = t.snapshot_row().split('\t').count();
        assert_eq!(cols, cells);
        // Counters + 7 histograms * (16 buckets + inf + sum + count = 19).
        assert_eq!(cols, COUNTER_NAMES.len() + 7 * (NB + 3));
    }

    #[test]
    fn real_hit_ratio_excludes_loopback() {
        let t = Telemetry::default();
        // 10 hits total, 4 of them loopback; 6 misses total, 1 loopback.
        // real = 6 hits / (6 hits + 5 misses) = 0.5455.
        for _ in 0..6 {
            t.record_cache_hit(false);
        }
        for _ in 0..4 {
            t.record_cache_hit(true);
        }
        for _ in 0..5 {
            t.record_cache_miss(false);
        }
        t.record_cache_miss(true);
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

    #[tokio::test]
    async fn flush_once_writes_snapshot_file() {
        let t = Telemetry::default();
        t.record_cache_hit(false);
        let path = std::env::temp_dir().join(format!(
            "httpjet_telemetry_flush_{}.tsv",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        flush_once(&t, &path).await;
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2, "{body}");
        let header = body.lines().next().unwrap();
        let row = body.lines().nth(1).unwrap();
        let hit_idx = header.split('\t').position(|c| c == "cache_hits").unwrap();
        assert_eq!(row.split('\t').nth(hit_idx), Some("1"), "{body}");
        let _ = std::fs::remove_file(path);
    }
}
