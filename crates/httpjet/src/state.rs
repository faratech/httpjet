//! Shared, immutable-per-generation server state handed to every connection.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio_util::sync::CancellationToken;

use hj_acl::AccessControl;
use hj_compress::{Compress, ExpiresRules};
use hj_core::Router;
use hj_core::config::{ExtKind, ExtProcessor, ServerConfig};
use hj_http::ServeConfig;
use hj_log::{AccessLogger, LogFormat};

/// (Tier 2) Access-log format: `HTTPJET_ACCESS_LOG_FORMAT=json` selects one
/// JSON object per line for log shippers; anything else is the Combined Log
/// Format. Process-lifetime, read once per logger construction.
pub(crate) fn access_log_format() -> LogFormat {
    if std::env::var("HTTPJET_ACCESS_LOG_FORMAT").as_deref() == Ok("json") {
        LogFormat::Json
    } else {
        LogFormat::Combined
    }
}

use hj_lsapi::LsapiRegistry;
use hj_proxy::{Proxy, ProxyTarget};
use hj_rewrite::{HtaccessCache, RuleSet};
use hj_static::StaticFiles;

use crate::statcache::{DEFAULT_STAT_TTL, StatCache};

/// (Tier 2) Resolve the GeoIP/ASN label lists against the CidrList source.
/// Labels configured without a readable db, a malformed db, or a label the db
/// does not know are HARD build errors: an inert or silently-partial geo ACL
/// would admit denied regions instead of failing loudly.
fn build_geo_rules(server: &ServerConfig) -> Result<hj_acl::GeoRules, String> {
    let sec = &server.security;
    let configured = !sec.geo_allow.is_empty()
        || !sec.geo_deny.is_empty()
        || !sec.asn_allow.is_empty()
        || !sec.asn_deny.is_empty();
    if !configured {
        return Ok(hj_acl::GeoRules::default());
    }
    let Some(path) = &sec.geo_db_file else {
        return Err(
            "geoAllow/geoDeny/asnAllow/asnDeny configured but <geoipDBFile> is absent              — the rules would be inert"
                .to_string(),
        );
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading geo db {}: {e}", path.display()))?;
    let source = hj_geo::CidrList::parse(&text)
        .map_err(|e| format!("parsing geo db {}: {e}", path.display()))?;
    hj_acl::GeoRules::resolve(
        &source,
        &sec.geo_allow,
        &sec.geo_deny,
        &sec.asn_allow,
        &sec.asn_deny,
    )
}

/// (Tier 2) Optional syslog sink for the UNIFIED access log, configured through
/// the process environment like the other process-lifetime log knobs:
///   - `HTTPJET_SYSLOG_TARGET` — `udp://host:port`, bare `host:port`, or a unix
///     dgram path (`/run/systemd/journal/syslog`). Absent = sink disabled.
///   - `HTTPJET_SYSLOG_FACILITY` (default `daemon`), `HTTPJET_SYSLOG_SEVERITY`
///     (default `info`), `HTTPJET_SYSLOG_RFC=3164` (default 5424),
///     `HTTPJET_SYSLOG_HOSTNAME` (default the server name).
/// An unreachable target disables the sink with a warning; file logging is
/// unaffected either way. Returns `None` when disabled.
fn build_syslog_tap(server: &ServerConfig) -> Option<hj_log::SyslogTap> {
    let raw = std::env::var("HTTPJET_SYSLOG_TARGET").ok()?;
    let target = match hj_log::SyslogTarget::parse(&raw) {
        Some(t) => t,
        None => {
            tracing::warn!(
                value = %raw,
                "HTTPJET_SYSLOG_TARGET is unparseable; syslog access-log sink disabled"
            );
            return None;
        }
    };
    let facility = std::env::var("HTTPJET_SYSLOG_FACILITY")
        .ok()
        .and_then(|v| hj_log::SyslogFacility::parse(&v))
        .unwrap_or(hj_log::SyslogFacility::Daemon);
    let severity = std::env::var("HTTPJET_SYSLOG_SEVERITY")
        .ok()
        .and_then(|v| hj_log::SyslogSeverity::parse(&v))
        .unwrap_or(hj_log::SyslogSeverity::Info);
    let rfc5424 = std::env::var("HTTPJET_SYSLOG_RFC").as_deref() != Ok("3164");
    let hostname =
        std::env::var("HTTPJET_SYSLOG_HOSTNAME").unwrap_or_else(|_| server.server_name.clone());
    let app_name =
        std::env::var("HTTPJET_SYSLOG_APP_NAME").unwrap_or_else(|_| "httpjet".to_string());
    match hj_log::SyslogTap::new(hj_log::SyslogConfig {
        target,
        facility,
        severity,
        app_name,
        hostname,
        rfc5424,
    }) {
        Ok(tap) => {
            tracing::info!("syslog access-log sink enabled");
            Some(tap)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "syslog sink unreachable at startup; disabled (file logging unaffected)"
            );
            None
        }
    }
}

/// (#248) A vhost's own access logger plus its `logHeaders` bitmask.
#[derive(Clone)]
pub struct VhostAccessLogger {
    pub logger: Arc<AccessLogger>,
    /// Nonzero ⇒ request headers accompany each record (LSWS `logHeaders`).
    pub log_headers: u8,
}

#[derive(Debug, Clone)]
pub struct XfCapsuleConfig {
    pub enabled: bool,
    pub vhosts: HashSet<String>,
    pub path_prefixes: Vec<String>,
    pub safe_get_mode: XfCapsuleSafeGetMode,
    pub stale_secs: u32,
    pub canary_percent: u8,
    pub allow_members: bool,
    pub member_canary_percent: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfCapsuleSafeGetMode {
    Prefixes,
    AllGetClassified,
}

impl XfCapsuleConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            vhosts: HashSet::new(),
            path_prefixes: Vec::new(),
            safe_get_mode: XfCapsuleSafeGetMode::Prefixes,
            stale_secs: 0,
            canary_percent: 0,
            allow_members: false,
            member_canary_percent: 0,
        }
    }
}

/// Rewrite-outcome-cache tuning (`--rewrite-outcome-ttl-ms` / `--rewrite-ua-classify`).
/// CLI-lifetime, carried across SIGHUP reloads like the other flag-derived state.
#[derive(Debug, Clone, Copy)]
pub struct RewriteTuning {
    /// Outcome-cache TTL. `Duration::ZERO` disables the cache entirely.
    pub outcome_ttl: std::time::Duration,
    /// Key UA-reading chains on the UA-cond match bitmap instead of the raw
    /// User-Agent string (deploy-time decision; default OFF).
    pub ua_classify: bool,
}

impl Default for RewriteTuning {
    fn default() -> Self {
        RewriteTuning {
            outcome_ttl: crate::pipeline::DEFAULT_REWRITE_OUTCOME_TTL,
            ua_classify: false,
        }
    }
}

/// State shared across all workers and connections. Cheap to clone (`Arc`).
pub struct ServerState {
    pub server: Arc<ServerConfig>,
    pub router: Arc<Router>,
    pub serve_config: ServeConfig,
    /// Server-wide byte budget shared by every layer that buffers request bodies
    /// into heap (io_uring H1/H2/H3 transport buffering + hj-lsapi collect_to_cap).
    /// Process-lifetime: carried across SIGHUP so reservations never straddle two caps.
    pub body_budget: Arc<hj_core::budget::BodyBufferBudget>,
    /// Terminal static-file handler.
    pub static_handler: StaticFiles,
    /// Per-vhost lsphp pool registry (None if PHP is disabled or the default
    /// pool failed to start). With suEXEC off this holds exactly one entry (the
    /// canonical `"php"` pool) behaving byte-for-byte like today's single pool.
    pub lsapi: Option<Arc<LsapiRegistry>>,
    /// Reverse-proxy engine for this config generation. Reload retains unchanged
    /// upstream Arcs while obsolete named definitions drain with the old state.
    pub proxy: Arc<Proxy>,
    /// `.htaccess` parse cache (per-directory, mtime-invalidated).
    pub rewrite_cache: Arc<HtaccessCache>,
    /// Pre-parsed inline `<rewrite><rules>` per vhost (by vhost name).
    pub inline_rules: HashMap<String, Arc<RuleSet>>,
    /// Ext processors by name (proxy targets for vhost proxy contexts).
    pub ext_by_name: HashMap<String, ExtProcessor>,
    /// File suffixes routed to PHP (lowercased), from `phpConfig` (php, html).
    pub php_suffixes: HashSet<String>,
    /// IP allow/deny + trusted-proxy XFF resolution.
    pub acl: Arc<AccessControl>,
    /// Per-client-IP request throttle (Tier 1.1; disabled unless <perIpRate> > 0).
    pub client_throttle: hj_acl::ClientThrottle,
    /// (Tier 2) Resolved GeoIP/ASN rules (empty/inert unless <geoipDBFile> plus
    /// label lists are configured). Judged against the RESOLVED client IP.
    pub geo: Arc<hj_acl::GeoRules>,
    /// gzip response compression (type-gated).
    pub compress: Arc<Compress>,
    /// The post-handler response-transform pipeline, applied in order by
    /// `pipeline::handle` (cache-small-static → expires → compress → deny-CDN-cache
    /// → advertise-h3). A new transform plugs in here; built once per generation
    /// from the fields above (see `build_transforms`).
    pub transforms: Vec<Arc<dyn hj_core::ResponseTransform>>,
    /// Access logger (None if logging could not be set up).
    pub access_log: Option<Arc<AccessLogger>>,
    /// (#248) Per-vhost access loggers for vhosts declaring their OWN
    /// `<logging><accessLog useServer=0>` file, with the LSWS `logHeaders` bitmask
    /// (nonzero = emit request headers with each record). A vhost absent here
    /// rides the unified [`ServerState::access_log`].
    pub vhost_access_logs: HashMap<String, VhostAccessLogger>,
    /// (#248) Per-vhost rolling ERROR writers for vhosts declaring their own
    /// `<logging><log useServer=0>` file. Receives mirrored 5xx/handler errors.
    pub vhost_error_logs: HashMap<String, Arc<AccessLogger>>,
    /// Static-file body cache. Shares the page-cache store when `--page-cache` is enabled;
    /// otherwise this is a static-only RAM store with the static tuning caps.
    pub static_cache: Arc<hj_pagecache::PageStore>,
    /// TTL-coalesced `-f`/`-d` cache for the rewrite front-controller tests.
    pub stat_cache: Arc<StatCache>,
    /// TTL-coalesced cache of rewrite outcomes for `path_cacheable` rulesets
    /// (lets repeated requests skip full ruleset evaluation). TTL from
    /// `--rewrite-outcome-ttl-ms` (0 = off).
    pub rewrite_outcomes: Arc<crate::pipeline::RewriteOutcomeCache>,
    /// `--rewrite-ua-classify`: key UA-reading chains by the UA-cond match
    /// bitmap instead of the raw User-Agent (see `UaClassifyCache`).
    pub rewrite_ua_classify: bool,
    /// Bounded (ruleset id, UA) -> match-bitmap memo backing `rewrite_ua_classify`.
    /// Cleared wholesale on SIGHUP reload (rulesets reparse with fresh ids).
    pub ua_classify: Arc<crate::pipeline::UaClassifyCache>,
    /// `Alt-Svc` header value advertising HTTP/3 (set when QUIC is enabled),
    /// pre-parsed to a `HeaderValue` once at startup so the per-response insert is a
    /// cheap clone instead of a `HeaderValue::from_str` parse + alloc on every TLS
    /// response (Alt-Svc is emitted on every h1/h2 response over HTTPS).
    pub alt_svc: Option<http::HeaderValue>,
    /// (#2 mTLS trust-boundary) Vhost names that are served by a secure listener
    /// mandating client-cert verification (`clientVerify == 2`, i.e. Cloudflare
    /// authenticated origin pull). A request for such a vhost arriving on a plain
    /// (non-TLS) listener bypasses that mTLS gate entirely, so the pipeline forces
    /// it to HTTPS instead of running the backend handlers unauthenticated. Empty
    /// when no listener requires client certs (then the plain listener is
    /// unrestricted, exactly as before).
    pub mtls_required_vhosts: HashSet<String>,
    /// Origin full-page cache (LSCache equivalent). `None` unless the operator
    /// passed `--page-cache`; when `None` the pipeline cache hooks are inert.
    pub page_cache: Option<Arc<hj_pagecache::PageStore>>,
    /// (dedup) Per-vhost zstd dictionaries (+ optional global fallback) for INTERNALLY storing
    /// cached bodies far smaller (`--page-cache-dict-vhost`, `--page-cache-dict`). A vhost with no
    /// matching dict and no fallback stores identity (today's behaviour). When a dict resolves,
    /// `cache_store` dict-compresses the stored body (tagged with the dict's generation) and the
    /// serve/fill paths decode it by generation, regardless of vhost; served bytes are always
    /// standard codecs.
    pub page_cache_dicts: Arc<hj_compress::PageDictRegistry>,
    /// Single-flight registry for the page cache: collapses concurrent misses of the same
    /// key into one backend render (prevents a hot page's TTL-expiry stampede). Inert
    /// unless `page_cache` is `Some` — the pipeline only consults it on a cacheable miss.
    pub page_cache_inflight: Arc<crate::lscache::InflightRegistry>,
    /// Stale-while-revalidate background-refresh coordinator: one refresh per key,
    /// globally concurrency-capped. Inert unless `page_cache` is `Some` and an entry
    /// is served stale.
    pub page_cache_refresh: Arc<crate::lscache::RefreshRegistry>,
    /// (PC2-lazy) On-first-hit variant-fill coordinator: one fill per key, globally
    /// concurrency-capped. SEPARATE from `page_cache_refresh` (its own semaphore) so a burst of
    /// variant fills can't starve stale-while-revalidate refreshes. Inert unless `page_cache` is
    /// `Some` and an identity-only entry is hit.
    pub page_cache_variant_fill: Arc<crate::lscache::RefreshRegistry>,
    /// (off-path dict) Bounded pool for the DEFERRED dict-compress: the store path stores the body
    /// identity-only and replaces it with the dict-compressed form on this pool, so the level-19
    /// zstd never blocks the miss response that produced it. Separate from the variant-fill pool so
    /// neither starves the other. Inert unless `page_cache` is `Some` and `page_cache_dicts` is
    /// non-empty.
    pub page_cache_dict_fill: Arc<crate::lscache::RefreshRegistry>,
    /// Per-vhost dictionary recompression work/savings. Populated only by first-hit background
    /// jobs, so the map is bounded by configured cache vhosts and stays off request hot paths.
    pub page_cache_dict_metrics: Arc<dashmap::DashMap<String, Arc<DictRecompressMetrics>>>,
    /// (W-TinyLFU) Store-admission frequency sketch: only keys that show reuse are admitted to
    /// the cache, so the long tail behind Cloudflare can't churn out the hot set or waste
    /// precompression CPU. Preserved across config reloads (keeps learned frequencies). Inert
    /// unless `page_cache` is `Some` (recorded on lookup, consulted on store).
    pub page_cache_admission: Arc<hj_pagecache::AdmissionFilter>,
    /// (W-TinyLFU) Base admission bar (`--page-cache-admit-threshold`): the minimum frequency a
    /// cacheable response must show before it is stored. `2` = store on the 2nd sighting
    /// (miss-miss-hit, the long-tail-rejecting default); `1` = store on the 1st (miss-hit, cache
    /// everything). Size-weighting adds +1 per 256 KiB on top (see `lscache::admission_threshold`).
    pub page_cache_admit_base: u8,
    /// XenForo hot-capsule tier. Reuses the page cache store but keys public-equivalent
    /// capsule shells separately so cookie-bearing read requests can avoid PHP.
    pub xf_capsule: XfCapsuleConfig,
    /// (OPS3) Cross-node page-cache purge coherence: forwards acted-on purges to
    /// the peer node(s) and authenticates inbound peer purges. `None` unless
    /// `--page-cache` + a secret + a peer are configured; then every hook is inert.
    pub peer_purge: Option<crate::peer_purge::PurgeForwarder>,
    /// OPS counters, grouped (see [`Metrics`]). Each inner `Arc<AtomicU64>` is SHARED
    /// across config generations: a SIGHUP reload clones `metrics` (one Arc), so a
    /// `ConnGuard`/`RequestGuard` created under any generation, and the drain loop, all
    /// touch the one true counters (see [`ServerState::reload`]).
    pub metrics: Arc<Metrics>,
    /// In-process per-request telemetry (lock-free histograms + counters), shared
    /// across config generations exactly like `metrics` so a SIGHUP reload keeps
    /// the same accumulators (see [`ServerState::reload`]).
    pub telemetry: Arc<crate::telemetry::Telemetry>,
    /// (attribution) Per-request PHP slow/sample log (`--php-slow-log`), the
    /// per-URL/user-class breakdown behind the `lsapi_ttfb` histogram. Carried
    /// across config reloads like `telemetry` (one writer task for the process
    /// lifetime). `None` = disabled — zero work on the dispatch path.
    pub php_slow: Option<Arc<crate::phpslow::PhpSlowLog>>,
    /// (obs) When set (`--request-id-header`), echo the per-request correlation id
    /// as an `X-Request-Id` response header. CLI-lifetime, so it is carried across a
    /// SIGHUP reload from `old` (not re-derived from config).
    pub request_id_header: bool,
    /// (OPS2) Shutdown signal. The io_uring accept loops select on it (stop accepting
    /// + drain in-flight connections); the main loop then drains `active_conns`.
    pub shutdown: CancellationToken,
}

/// Runtime OPS counters, held behind one `Arc<Metrics>` on [`ServerState`] and carried
/// across a SIGHUP reload by a single `Arc` clone (so every config generation, every
/// `ConnGuard`/`RequestGuard`, and the drain loop share the same atomics). Each field is
/// itself an `Arc<AtomicU64>` so the guards capture exactly the handle they need.
/// One full cache line, so a hot atomic never shares its line with neighbors.
#[repr(align(64))]
#[derive(Default)]
pub struct PaddedAtomic(pub AtomicU64);

impl std::ops::Deref for PaddedAtomic {
    type Target = AtomicU64;
    fn deref(&self) -> &AtomicU64 {
        &self.0
    }
}

#[derive(Default)]
pub struct Metrics {
    /// (OPS1) Total requests served, incremented at the access-log point.
    /// (#321) Cache-line padded: incremented by EVERY worker at the access-log
    /// point, so an unpadded line ping-pongs across cores on every request.
    pub requests_total: Arc<PaddedAtomic>,
    /// (OPS1) Currently-open connections (the io_uring accept loop does ±1 around each
    /// connection task); the graceful-drain loop waits on this reaching the in-flight count.
    pub active_conns: Arc<AtomicU64>,
    /// (OPS2 / observability) Requests currently executing inside `pipeline::handle` (a
    /// guard ±1) — producing the response head, NOT spanning the streamed body — so it is
    /// a handler-concurrency gauge, not the drain signal.
    pub active_requests: Arc<AtomicU64>,
    /// (OPS3) Local loopback purges received on /__hj_cache_purge and applied.
    pub purges_received: Arc<AtomicU64>,
    /// (#349) Finished-response memo hits served on the on-core fast path.
    pub fast_memo_hits: Arc<AtomicU64>,
    /// (#349) Finished-response memo stores (first full-pipeline serve per key/TTL).
    pub fast_memo_stores: Arc<AtomicU64>,
    /// (#349) Memo-eligible static requests whose `.htaccess` chain refused the store
    /// (a `MemoClass` blocker) — "why is this vhost not memoizing" in one number.
    pub fast_memo_ineligible: Arc<AtomicU64>,
    /// (#343 Step 1) Fast-path GET/HEAD requests carrying NO Cookie header.
    pub fast_cookie_none: Arc<AtomicU64>,
    /// (#343 Step 1) Cookied GET/HEAD requests whose cookie names include the
    /// configured member/session markers — presumed logged-in, not a fast-path
    /// extension candidate.
    pub fast_cookie_member_session: Arc<AtomicU64>,
    /// (#343 Step 1) Cookied GET/HEAD requests with NO member/session marker — the
    /// benign-cookie population an on-core fast-path extension could serve.
    pub fast_cookie_benign_only: Arc<AtomicU64>,
    /// TLS connections that completed a FULL handshake (rustls `HandshakeKind::Full`
    /// or `FullWithHelloRetryRequest`). Compared against `_resumed` to size the
    /// resumption win the client-verify `NoServerSessions` posture forfeits.
    pub tls_handshakes_full: Arc<AtomicU64>,
    /// TLS connections that completed a RESUMED handshake (session ticket/PSK).
    pub tls_handshakes_resumed: Arc<AtomicU64>,
    /// Last accepted `/cache-entries` debug render, in unix milliseconds.
    pub cache_entries_last_ms: Arc<AtomicU64>,
    /// Accepted `/cache-entries` renders.
    pub cache_entries_renders: Arc<AtomicU64>,
    /// `/cache-entries` requests rejected by the debug-render throttle.
    pub cache_entries_throttled: Arc<AtomicU64>,
    /// Rewrite-outcome cache hits (a memoized result skipped full chain evaluation).
    pub rewrite_outcome_hits: Arc<AtomicU64>,
    /// Rewrite-outcome cache misses (cacheable chain, evaluated + stored).
    pub rewrite_outcome_misses: Arc<AtomicU64>,
    /// Requests whose rewrite chain was not outcome-cacheable (an unkeyable
    /// per-request input — e.g. `%{HTTP_COOKIE}` — poisons the whole chain), or
    /// whose live env seed carried an assumed-empty name. Not counted when the
    /// cache is disabled outright (`--rewrite-outcome-ttl-ms 0`).
    pub rewrite_outcome_uncacheable: Arc<AtomicU64>,
    /// XenForo capsule hits served from the dedicated capsule key.
    pub xf_capsule_hits_dedicated: Arc<AtomicU64>,
    /// XenForo capsule stale hits served from the dedicated capsule key.
    pub xf_capsule_stale_hits_dedicated: Arc<AtomicU64>,
    /// XenForo capsule hits served from a safe public shell fallback.
    pub xf_capsule_hits_public_fallback: Arc<AtomicU64>,
    /// XenForo capsule stale hits served from a safe public shell fallback.
    pub xf_capsule_stale_hits_public_fallback: Arc<AtomicU64>,
    /// XenForo capsule misses on the dedicated capsule key.
    pub xf_capsule_misses_dedicated: Arc<AtomicU64>,
    /// XenForo capsule misses on the public shell fallback key.
    pub xf_capsule_misses_public_fallback: Arc<AtomicU64>,
    /// XenForo capsule requests bypassed because lookup preconditions failed.
    pub xf_capsule_bypass_not_allowed: Arc<AtomicU64>,
    /// Dedicated capsule shells stored. The dedicated key deliberately skips the W-TinyLFU
    /// admission gate (see `lscache::cache_store`), so this gauges the un-gated store rate —
    /// watch it against capsule evictions for LRU churn before adding a separate admission sketch.
    pub xf_capsule_dedicated_stores: Arc<AtomicU64>,
    /// Capsule hits served to a logged-in MEMBER request (member opt-in cookie present). Paired
    /// with `xf_capsule_hits_guest` this answers "are members actually hitting the capsule, or
    /// falling through to PHP?" — bumped at every capsule serve site alongside the per-source
    /// counters above.
    pub xf_capsule_hits_member: Arc<AtomicU64>,
    /// Capsule hits served to a GUEST request (no member candidate cookie).
    pub xf_capsule_hits_guest: Arc<AtomicU64>,
    /// Shell-age summary (Prometheus summary style): the sum of `now - stored_at` (seconds) over
    /// every capsule hit. `…/count` gives the mean served shell age — validates the stale window.
    pub xf_capsule_shell_age_secs_sum: Arc<AtomicU64>,
    /// Count of shell-age observations (one per capsule hit); denominator for the age summary.
    pub xf_capsule_shell_age_secs_count: Arc<AtomicU64>,
    /// Member capsule requests dropped because the deterministic member-canary bucket rejected
    /// them (the member opted in but their sticky bucket is outside the ramp). Makes the ramp
    /// denominator visible; distinct from `xf_capsule_bypass_not_allowed` (other precondition
    /// failures).
    pub xf_capsule_canary_filtered: Arc<AtomicU64>,
    /// (shared-paths) Member lookups routed to the PUBLIC cache tier because the request
    /// matched a `--page-cache-shared-paths` matcher and the sticky canary admitted it.
    /// Counted once per request (at the cache-lookup routing decision, not the store's).
    pub page_cache_shared_path_public_routes: Arc<AtomicU64>,
    /// (shared-paths) Member lookups that matched a `--page-cache-shared-paths` matcher but
    /// were kept on the private tier by the deterministic canary bucket (ramp denominator).
    pub page_cache_shared_path_canary_skipped: Arc<AtomicU64>,
}

#[derive(Default)]
pub struct DictRecompressMetrics {
    pub queued: AtomicU64,
    /// Finalize tasks NOT spawned: dict pool saturated (`DICT_FILL_CONCURRENCY`
    /// slots busy) or duplicate key in flight. A store burst that exceeds the
    /// pool leaves its overflow as full-size identity — this is the visibility
    /// for that (previously silent) degradation.
    pub dropped: AtomicU64,
    pub attempts: AtomicU64,
    pub completed: AtomicU64,
    pub skipped: AtomicU64,
    pub input_bytes: AtomicU64,
    pub output_bytes: AtomicU64,
    pub saved_bytes: AtomicU64,
    /// Per-vhost Unix timestamp for the rate-limited saturation warning.
    pub last_saturation_warn_epoch_secs: AtomicU64,
}

/// The config-derived half of [`ServerState`] — everything rebuilt from a parsed
/// `ServerConfig`. A SIGHUP reload recomputes exactly this and carries the runtime
/// half (caches, pools, logger, counters, shutdown) over unchanged.
struct ConfigDerived {
    router: Arc<Router>,
    serve_config: ServeConfig,
    static_handler: StaticFiles,
    inline_rules: HashMap<String, Arc<RuleSet>>,
    ext_by_name: HashMap<String, ExtProcessor>,
    php_suffixes: HashSet<String>,
    acl: Arc<AccessControl>,
    client_throttle: hj_acl::ClientThrottle,
    compress: Arc<Compress>,
    expires: Arc<ExpiresRules>,
    mtls_required_vhosts: HashSet<String>,
}

/// Build the config-derived half from a parsed config. Used by both
/// [`ServerState::new`] (boot) and [`ServerState::reload`] (SIGHUP) so the two
/// can never drift.
fn build_config_derived(
    server: &Arc<ServerConfig>,
    cf_send_zstd: bool,
) -> Result<ConfigDerived, String> {
    let router = Arc::new(Router::build(server.clone()));
    let serve_config = ServeConfig::from_tuning(&server.tuning);
    let php_suffixes = server
        .php_config
        .as_ref()
        .map(|p| p.suffixes.iter().map(|s| s.to_ascii_lowercase()).collect())
        .unwrap_or_default();

    // Pre-parse each vhost's inline rewrite rules once.
    let mut inline_rules = HashMap::new();
    for (name, decl) in &server.vhosts {
        if let Some(cfg) = &decl.config {
            if cfg.rewrite.enable && !cfg.rewrite.rules.trim().is_empty() {
                match RuleSet::parse(&cfg.rewrite.rules) {
                    Ok(rs) => {
                        inline_rules.insert(name.clone(), Arc::new(rs));
                    }
                    Err(e) => {
                        tracing::warn!(vhost = %name, error = %e, "failed to parse inline rewrite rules");
                    }
                }
            }
        }
    }

    let ext_by_name = server
        .ext_processors
        .iter()
        .map(|e| (e.name.clone(), e.clone()))
        .collect();

    // (#2) Collect the set of vhosts whose trust model REQUIRES mTLS, i.e. they are mapped on a
    // secure listener with `clientVerify == 2` (require). ONLY mode 2 mandates a client cert; modes
    // 1 and 3 are OPTIONAL (OLS SSL_VERIFY_PEER — a missing cert is allowed), so they do not require
    // mTLS and must not be conflated with 2. These required vhosts must not be served on a
    // plain-HTTP listener without TLS.
    let mut mtls_required_vhosts: HashSet<String> = HashSet::new();
    for l in &server.listeners {
        let requires_cert = l.secure
            && l.tls
                .as_ref()
                .map(|t| t.client_verify == 2)
                .unwrap_or(false);
        if requires_cert {
            for m in &l.vhost_map {
                mtls_required_vhosts.insert(m.vhost.clone());
            }
        }
    }

    let acl = Arc::new(AccessControl::from_security(&server.security)?);
    let client_throttle = hj_acl::ClientThrottle::from_tuning(&server.tuning);
    let compress = Arc::new(Compress::from_tuning(&server.tuning).with_cf_send_zstd(cf_send_zstd));
    let expires = Arc::new(if server.expires.enabled {
        ExpiresRules::from_pairs(
            server
                .expires
                .by_type
                .iter()
                .map(|(t, v)| (t.clone(), v.clone())),
        )
    } else {
        ExpiresRules::from_pairs(std::iter::empty::<(String, String)>())
    });

    Ok(ConfigDerived {
        router,
        serve_config,
        static_handler: StaticFiles::new(),
        inline_rules,
        ext_by_name,
        php_suffixes,
        acl,
        client_throttle,
        compress,
        expires,
        mtls_required_vhosts,
    })
}

fn configured_proxy_targets(server: &ServerConfig) -> Vec<ProxyTarget> {
    server
        .ext_processors
        .iter()
        .chain(
            server
                .vhosts
                .values()
                .filter_map(|decl| decl.config.as_deref())
                .flat_map(|vhost| vhost.extra_ext_processors.iter()),
        )
        .filter(|processor| processor.kind == ExtKind::Proxy)
        .map(ProxyTarget::from_ext_processor)
        .collect()
}

/// Build the post-handler response-transform pipeline in its fixed order. Called from
/// both `ServerState::new` and `reload` so the two generations stay identical.
fn build_transforms(
    static_cache: &Arc<hj_pagecache::PageStore>,
    expires: &Arc<ExpiresRules>,
    vhost_expires: &HashMap<String, Arc<ExpiresRules>>,
    compress: &Arc<Compress>,
    alt_svc: &Option<http::HeaderValue>,
) -> Vec<Arc<dyn hj_core::ResponseTransform>> {
    use crate::pipeline::{
        AltSvcTransform, CacheStaticTransform, DenyRedirectCdnTransform, ExpiresTransform,
        SubFilterTransform,
    };
    vec![
        Arc::new(CacheStaticTransform {
            static_cache: static_cache.clone(),
        }),
        Arc::new(ExpiresTransform {
            expires: expires.clone(),
            vhost_expires: vhost_expires.clone(),
        }),
        // (Tier 2) sub_filter runs BEFORE compress so the filtered body is then
        // compressed by the ordinary transform (nginx's filter order).
        Arc::new(SubFilterTransform),
        compress.clone(),
        Arc::new(DenyRedirectCdnTransform),
        Arc::new(AltSvcTransform {
            alt_svc: alt_svc.clone(),
        }),
    ]
}

/// Per-vhost `<expires>` blocks (audit): parsed into `VHostConfig.expires` for years
/// but never consulted — only the server-level `expiresByType` applied. A vhost with
/// its OWN enabled block overrides the server rules entirely (LSWS semantics).
fn build_vhost_expires(server: &ServerConfig) -> HashMap<String, Arc<ExpiresRules>> {
    let mut out = HashMap::new();
    for (name, decl) in &server.vhosts {
        let Some(cfg) = &decl.config else { continue };
        let Some(ex) = &cfg.expires else { continue };
        if !ex.enabled {
            continue;
        }
        out.insert(
            name.clone(),
            Arc::new(ExpiresRules::from_pairs(
                ex.by_type.iter().map(|(t, v)| (t.clone(), v.clone())),
            )),
        );
    }
    out
}

fn static_store_config(server: &ServerConfig) -> hj_pagecache::StoreConfig {
    let caps = hj_cache::CacheCaps::from_tuning(&server.tuning);
    hj_pagecache::StoreConfig {
        max_mem_bytes: caps.total_in_mem.saturating_add(caps.total_mmap).max(1),
        max_disk_bytes: 0,
        store_path: None,
        hot_mem_bytes: 0,
        max_obj_bytes: caps.max_mmap_file,
        max_static_obj_bytes: caps.max_mmap_file,
        ..hj_pagecache::StoreConfig::default()
    }
}

impl ServerState {
    /// (#248) The access logger for a request served by `vhost_name`: the vhost's
    /// own `<logging><accessLog>` file when it declares one, else the unified log.
    pub fn access_logger_for(&self, vhost_name: &str) -> Option<&Arc<AccessLogger>> {
        self.vhost_access_logs
            .get(vhost_name)
            .map(|v| &v.logger)
            .or(self.access_log.as_ref())
    }

    /// (#248) The vhost's own error-log writer, if its `<logging><log>` declares one.
    pub fn vhost_error_logger(&self, vhost_name: &str) -> Option<&Arc<AccessLogger>> {
        self.vhost_error_logs.get(vhost_name)
    }

    // Boot-time constructor; the params mirror the CLI flags one-to-one.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: Arc<ServerConfig>,
        lsapi: Option<Arc<LsapiRegistry>>,
        alt_svc: Option<String>,
        page_cache: Option<Arc<hj_pagecache::PageStore>>,
        page_cache_dicts: Arc<hj_compress::PageDictRegistry>,
        page_cache_admit_base: u8,
        xf_capsule: XfCapsuleConfig,
        peer_purge: Option<crate::peer_purge::PurgeForwarder>,
        cf_send_zstd: bool,
        php_slow: Option<Arc<crate::phpslow::PhpSlowLog>>,
        request_id_header: bool,
        rewrite_tuning: RewriteTuning,
    ) -> Result<Arc<Self>, String> {
        // (OPS2) One shutdown token the io_uring accept loops select on (stop accepting,
        // then drain in-flight connections before teardown).
        let shutdown = CancellationToken::new();
        let cd = build_config_derived(&server, cf_send_zstd)?;
        let static_cache = page_cache.clone().unwrap_or_else(|| {
            Arc::new(hj_pagecache::PageStore::new(static_store_config(&server)))
        });

        // Spawn the access logger (we are inside the tokio runtime here).
        // keep_days=7: this is by far the highest-volume log (~GBs/day at prod
        // traffic); forensic value past a week is low, and disk headroom on the
        // single node matters more than deep access history.
        let access_log = {
            let path = server.server_root.join("logs/httpjet_access.log");
            // This combined log is the unified access record for every vhost that
            // does not declare its OWN <logging><accessLog> (#248), and it rolled
            // at just 10MB x 7 days — too thin for incident forensics
            // (cache-poisoning reports, Cloudflare disputes). Defaults raised;
            // env-overridable without a CLI surface change.
            let rolling_bytes = std::env::var("HTTPJET_ACCESS_ROLLING_BYTES")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(50 * 1024 * 1024);
            let keep_days = std::env::var("HTTPJET_ACCESS_KEEP_DAYS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30);
            Some(Arc::new(AccessLogger::spawn_with_syslog(
                path,
                crate::state::access_log_format(),
                rolling_bytes,
                keep_days,
                true,
                build_syslog_tap(&server),
            )))
        };

        // (#248) One rolling writer per vhost declaring its own access file.
        let mut vhost_access_logs: HashMap<String, VhostAccessLogger> = HashMap::new();
        let mut vhost_error_logs: HashMap<String, Arc<AccessLogger>> = HashMap::new();
        for (name, decl) in &server.vhosts {
            let Some(cfg) = decl.config.as_deref() else {
                continue;
            };
            let Some(spec) = cfg.access_log_file.as_ref() else {
                continue;
            };
            tracing::info!(
                vhost = %name,
                path = %spec.path.display(),
                "per-vhost access log active (LSWS <logging><accessLog useServer=0>)"
            );
            vhost_access_logs.insert(
                name.clone(),
                VhostAccessLogger {
                    logger: Arc::new(AccessLogger::spawn(
                        &spec.path,
                        crate::state::access_log_format(),
                        spec.rolling_bytes,
                        spec.keep_days,
                        false,
                    )),
                    log_headers: spec.log_headers,
                },
            );
            // (#248) The matching per-vhost error file (rolling writer reused for
            // arbitrary error lines).
            if let Some(err) = cfg.error_log_file.as_ref() {
                vhost_error_logs.insert(
                    name.clone(),
                    Arc::new(AccessLogger::spawn(
                        &err.path,
                        crate::state::access_log_format(),
                        err.rolling_bytes,
                        err.keep_days,
                        false,
                    )),
                );
            }
        }

        // Parse Alt-Svc once (unparseable degrades to none) and build the transform pipeline.
        let alt_svc = alt_svc.and_then(|s| http::HeaderValue::from_str(&s).ok());
        let vhost_expires = build_vhost_expires(&server);
        let transforms = build_transforms(
            &static_cache,
            &cd.expires,
            &vhost_expires,
            &cd.compress,
            &alt_svc,
        );
        // Bound on concurrent stale-while-revalidate background renders. Kept small so a
        // burst of stale hits can't starve live traffic of lsphp workers; excess refreshes
        // are skipped (the stale entry stays servable and the next hit retries).
        const REFRESH_CONCURRENCY: usize = 8;
        // (PC2-lazy) Variant fills are short + lower-priority than refreshes; a small cap bounds
        // their CPU (excess fills are skipped and retried on the next hit).
        const VARIANT_FILL_CONCURRENCY: usize = 4;
        // Dictionary compression runs on every STORE (not just the first hit), so this cap is what
        // bounds its CPU against live traffic. Deliberately narrow: an encode is tens of ms, and a
        // dropped job is harmless — the identity entry stays fully servable and the next hit
        // retries it. Two slots clear the observed store rate several times over.
        const DICT_FILL_CONCURRENCY: usize = 2;
        // Telemetry carries a dense per-vhost index, built once here from the config
        // vhost names (captured before `server` is moved into the struct below) and
        // kept across SIGHUP via the shared `Arc`.
        let telemetry = Arc::new(crate::telemetry::Telemetry::new(
            server.vhosts.keys().cloned(),
        ));
        let geo = Arc::new(build_geo_rules(&server)?);
        Ok(Arc::new(ServerState {
            server,
            router: cd.router,
            page_cache_inflight: Arc::new(crate::lscache::InflightRegistry::default()),
            page_cache_refresh: crate::lscache::RefreshRegistry::new(REFRESH_CONCURRENCY),
            page_cache_variant_fill: crate::lscache::RefreshRegistry::new(VARIANT_FILL_CONCURRENCY),
            page_cache_dict_fill: crate::lscache::RefreshRegistry::new(DICT_FILL_CONCURRENCY),
            page_cache_dict_metrics: Arc::new(dashmap::DashMap::new()),
            page_cache_admission: Arc::new(hj_pagecache::AdmissionFilter::new(
                page_cache
                    .as_ref()
                    .map(|c| c.config().max_mem_bytes)
                    .unwrap_or(128 * 1024 * 1024),
            )),
            page_cache_admit_base,
            xf_capsule,
            serve_config: cd.serve_config,
            // One server-wide buffered-body cap shared with the LSAPI handlers'
            // collect_to_cap (when PHP is enabled); transports reserve here too.
            body_budget: lsapi.as_ref().map(|r| r.body_budget()).unwrap_or_else(|| {
                Arc::new(hj_core::budget::BodyBufferBudget::new(
                    hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
                ))
            }),
            static_handler: cd.static_handler,
            lsapi,
            proxy: Arc::new(Proxy::new()),
            rewrite_cache: Arc::new(HtaccessCache::new()),
            inline_rules: cd.inline_rules,
            ext_by_name: cd.ext_by_name,
            php_suffixes: cd.php_suffixes,
            acl: cd.acl,
            client_throttle: cd.client_throttle,
            geo,
            compress: cd.compress,
            transforms,
            access_log,
            vhost_access_logs,
            vhost_error_logs,
            static_cache,
            stat_cache: Arc::new(StatCache::new(DEFAULT_STAT_TTL)),
            rewrite_outcomes: Arc::new(crate::pipeline::RewriteOutcomeCache::new(
                rewrite_tuning.outcome_ttl,
            )),
            rewrite_ua_classify: rewrite_tuning.ua_classify,
            ua_classify: Arc::new(crate::pipeline::UaClassifyCache::new()),
            alt_svc,
            mtls_required_vhosts: cd.mtls_required_vhosts,
            page_cache,
            page_cache_dicts,
            peer_purge,
            metrics: Arc::new(Metrics::default()),
            telemetry,
            php_slow,
            request_id_header,
            shutdown,
        }))
    }

    /// (OPS6) Build the next config generation for a SIGHUP hot-reload: recompute
    /// the config-derived half from `server`, and carry long-lived runtime state
    /// forward — the page cache stays warm, the lsphp pool keeps running, the
    /// access logger task is reused, and the shared counters + shutdown token are
    /// cloned so in-flight `ConnGuard`s and the drain loop all keep targeting the
    /// one true gauge. The proxy pool gets a filtered generation that retains
    /// Arcs only for definitions still present in the new config. The caller
    /// atomically swaps the result
    /// in (`ArcSwap::store`); new connections pick it up, in-flight ones finish on
    /// the generation they started with. Listener/TLS/lsphp-pool changes are NOT
    /// applied here (the sockets/acceptor/pool live outside `ServerState`) — the
    /// SIGHUP handler rejects a reload that touches those.
    pub fn reload(old: &ServerState, server: Arc<ServerConfig>) -> Result<Arc<Self>, String> {
        // CF_SEND_ZSTD is a process-lifetime CLI flag; carry it across SIGHUP by
        // reading it back off the old generation's Compress (its single home).
        let cd = build_config_derived(&server, old.compress.cf_send_zstd())?;
        // (#10) Drop the accumulated `.htaccess` parse cache on reload. The cache is
        // keyed by attacker-controlled request directory prefixes (every absent
        // intermediate dir of a requested path inserts a miss entry), so for an
        // htaccess-enabled vhost (allowOverride=31) it grows with request-path
        // cardinality. The per-insert soft cap (hj-rewrite) bounds steady-state growth;
        // clearing here drops the whole map on SIGHUP so a reload also reclaims it (and
        // picks up `.htaccess` edits immediately, instead of relying on mtime checks).
        old.rewrite_cache.clear();
        // Also drop the INLINE-rewrite outcome memo — it carries no rule version, so a warm
        // entry would replay the pre-reload rewrite/redirect/forbid decision for up to one TTL
        // after a SIGHUP that edits inline RewriteRules (the htaccess cache clear above only
        // covers `.htaccess`). Reload should take effect immediately for both.
        old.rewrite_outcomes.clear();
        // And the UA-classification memo: reparsed rulesets get fresh ids (so stale
        // entries could never be replayed anyway), but the reload is the natural
        // point to drop the dead ones wholesale rather than let them squat the cap.
        old.ua_classify.clear();
        // Rebuild the transform pipeline from the NEW expires/compress + carried-over
        // static cache/alt_svc, so the reloaded generation behaves identically.
        let transforms = build_transforms(
            &old.static_cache,
            &cd.expires,
            // Per-vhost <expires> is config-derived: a SIGHUP re-reads it live.
            &build_vhost_expires(&server),
            &cd.compress,
            &old.alt_svc,
        );
        let proxy = Arc::new(old.proxy.next_generation(configured_proxy_targets(&server)));
        // (#234) The PageStore freezes its `StoreConfig` at BOOT (main.rs builds it
        // exactly once and this reload carries the same Arc forward), so a SIGHUP
        // edit to the server-level `<cache>` block silently keeps the boot-time
        // TTL/status/POST policy even though the reload logs success. Per-vhost
        // `<cache>` blocks DO hot-apply (`vhost_allows_public` reads them live) —
        // only these four boot-frozen fields can diverge. Say so loudly instead of
        // letting an operator believe a mitigation took effect.
        if old.page_cache.is_some() {
            let (o, n) = (&old.server.cache, &server.cache);
            if o.default_ttl_secs != n.default_ttl_secs
                || o.default_private_ttl_secs != n.default_private_ttl_secs
                || o.cacheable_status != n.cacheable_status
                || o.enable_post_cache != n.enable_post_cache
            {
                tracing::warn!(
                    old_ttl = o.default_ttl_secs,
                    new_ttl = n.default_ttl_secs,
                    "SIGHUP: server-level <cache> policy changed but the running page-cache \
                     store keeps its BOOT-time TTL/status/POST settings — RESTART httpjet to \
                     apply it (per-vhost <cache> blocks hot-apply; this warning does not)"
                );
            }
            // (#234 residual) The boot-frozen fields are NOT only those four: the
            // static-cache object caps are derived from <tuning> once at boot, so a
            // SIGHUP tuning edit also silently keeps the old behavior. Say so.
            let (ot, nt) = (&old.server.tuning, &server.tuning);
            if ot.max_mmap_file_size != nt.max_mmap_file_size
                || ot.max_cached_file_size != nt.max_cached_file_size
                || ot.total_in_mem_cache_size != nt.total_in_mem_cache_size
                || ot.total_mmap_cache_size != nt.total_mmap_cache_size
            {
                tracing::warn!(
                    "SIGHUP: <tuning> cache-size caps changed but maxStaticObjBytes was \
                     frozen from them at BOOT — RESTART httpjet to apply"
                );
            }
        }
        // (#234 residual) quicEnable is read exactly once at boot to build the H3
        // listener; a SIGHUP flip neither applies nor warns — make it loud instead.
        if old.server.quic_enable != server.quic_enable {
            tracing::warn!(
                old = old.server.quic_enable,
                new = server.quic_enable,
                "SIGHUP: <quic><quicEnable> changed but the QUIC/H3 listener is fixed at \
                 BOOT — RESTART httpjet to apply"
            );
        }
        let geo = Arc::new(build_geo_rules(&server)?);
        Ok(Arc::new(ServerState {
            server,
            router: cd.router,
            serve_config: cd.serve_config,
            // Process-lifetime budget: reservations in flight when a SIGHUP lands must
            // release against the SAME cap they were admitted under.
            body_budget: old.body_budget.clone(),
            static_handler: cd.static_handler,
            inline_rules: cd.inline_rules,
            ext_by_name: cd.ext_by_name,
            php_suffixes: cd.php_suffixes,
            acl: cd.acl,
            client_throttle: cd.client_throttle,
            geo,
            compress: cd.compress,
            transforms,
            mtls_required_vhosts: cd.mtls_required_vhosts,
            // ---- runtime half: carried forward (proxy filtered to new config) ----
            lsapi: old.lsapi.clone(),
            proxy,
            rewrite_cache: old.rewrite_cache.clone(),
            static_cache: old.static_cache.clone(),
            stat_cache: old.stat_cache.clone(),
            rewrite_outcomes: old.rewrite_outcomes.clone(),
            rewrite_ua_classify: old.rewrite_ua_classify,
            ua_classify: old.ua_classify.clone(),
            access_log: old.access_log.clone(),
            // (#248) Per-vhost log writers are process-lifetime like the unified one:
            // a SIGHUP that adds/removes a vhost log file takes effect on RESTART
            // (spawning duplicate writers per generation would double-write).
            vhost_access_logs: old.vhost_access_logs.clone(),
            vhost_error_logs: old.vhost_error_logs.clone(),
            page_cache: old.page_cache.clone(),
            page_cache_dicts: old.page_cache_dicts.clone(),
            page_cache_inflight: old.page_cache_inflight.clone(),
            page_cache_refresh: old.page_cache_refresh.clone(),
            page_cache_variant_fill: old.page_cache_variant_fill.clone(),
            page_cache_dict_fill: old.page_cache_dict_fill.clone(),
            page_cache_dict_metrics: old.page_cache_dict_metrics.clone(),
            // Preserve the learned admission frequencies across a config reload.
            page_cache_admission: old.page_cache_admission.clone(),
            page_cache_admit_base: old.page_cache_admit_base,
            xf_capsule: old.xf_capsule.clone(),
            peer_purge: old.peer_purge.clone(),
            alt_svc: old.alt_svc.clone(),
            // One Arc clone carries ALL counters across the generation (shared atomics).
            metrics: old.metrics.clone(),
            telemetry: old.telemetry.clone(),
            php_slow: old.php_slow.clone(),
            request_id_header: old.request_id_header,
            shutdown: old.shutdown.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hj_core::config::{ExtAddress, VHostConfig, VHostDecl};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "httpjet-state-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("logs")).unwrap();
        root
    }

    fn processor(name: &str, port: u16) -> ExtProcessor {
        ExtProcessor {
            name: name.into(),
            kind: ExtKind::Proxy,
            address: ExtAddress::HostPort(format!("127.0.0.1:{port}")),
            extra_addresses: Vec::new(),
            max_conns: 10,
            init_timeout: Duration::from_secs(5),
            retry_timeout: Duration::ZERO,
            pc_keep_alive_timeout: Duration::from_secs(60),
            resp_buffer: false,
            env: Vec::new(),
            auto_start: 0,
            path: None,
            backlog: 0,
            client_cert_file: None,
            client_key_file: None,
            instances: 1,
            run_on_startup: 0,
        }
    }

    fn config(
        root: &Path,
        global: Vec<ExtProcessor>,
        per_vhost: Vec<(&str, ExtProcessor)>,
    ) -> Arc<ServerConfig> {
        let mut server = ServerConfig {
            server_root: root.to_path_buf(),
            ext_processors: global,
            ..ServerConfig::default()
        };
        for (name, processor) in per_vhost {
            let vhost = VHostConfig {
                doc_root: root.to_path_buf(),
                extra_ext_processors: vec![processor],
                ..VHostConfig::default()
            };
            server.vhosts.insert(
                name.into(),
                VHostDecl {
                    name: name.into(),
                    vh_root: root.to_path_buf(),
                    config_file: PathBuf::new(),
                    allow_symbol_link: Some(true),
                    restrained: false,
                    enable_script: true,
                    config: Some(Arc::new(vhost)),
                },
            );
            server.vhost_order.push(name.into());
        }
        Arc::new(server)
    }

    fn state(server: Arc<ServerConfig>) -> Arc<ServerState> {
        ServerState::new(
            server,
            None,
            None,
            None,
            Arc::new(hj_compress::PageDictRegistry::empty()),
            1,
            XfCapsuleConfig::disabled(),
            None,
            false,
            None,
            false,
            RewriteTuning::default(),
        )
        .unwrap()
    }

    fn pooled(state: &ServerState, target: &ProxyTarget) -> Arc<hj_proxy::Upstream> {
        state.proxy.pool().get_or_create(
            target,
            target.max_conns.unwrap(),
            target.keep_alive.unwrap(),
            target.connect_timeout.unwrap(),
        )
    }

    #[tokio::test]
    async fn reload_bounds_replaced_named_pool_generations_and_keeps_unchanged() {
        let root = temp_root("reload-pool");
        let a = processor("api", 8002);
        let b = processor("api", 8003);
        let cfg_a = config(&root, vec![a.clone()], Vec::new());
        let cfg_b = config(&root, vec![b.clone()], Vec::new());
        let target_a = ProxyTarget::from_ext_processor(&a);
        let target_b = ProxyTarget::from_ext_processor(&b);

        let mut generation = state(cfg_a.clone());
        let upstream_a = pooled(&generation, &target_a);
        let unchanged = ServerState::reload(&generation, cfg_a.clone()).unwrap();
        assert_eq!(unchanged.proxy.pool().len(), 1);
        assert!(Arc::ptr_eq(&upstream_a, &pooled(&unchanged, &target_a)));
        generation = unchanged;

        for (server, target) in [
            (cfg_b.clone(), &target_b),
            (cfg_a.clone(), &target_a),
            (cfg_b.clone(), &target_b),
            (cfg_a.clone(), &target_a),
        ] {
            let next = ServerState::reload(&generation, server).unwrap();
            assert_eq!(next.proxy.pool().len(), 0);
            pooled(&next, target);
            assert_eq!(next.proxy.pool().len(), 1);
            generation = next;
        }
    }

    #[tokio::test]
    async fn reload_retains_same_name_endpoints_from_distinct_vhosts() {
        let root = temp_root("reload-vhosts");
        let a = processor("shared", 8101);
        let b = processor("shared", 8102);
        let server = config(
            &root,
            Vec::new(),
            vec![("one", a.clone()), ("two", b.clone())],
        );
        let target_a = ProxyTarget::from_ext_processor(&a);
        let target_b = ProxyTarget::from_ext_processor(&b);
        let old = state(server.clone());
        let upstream_a = pooled(&old, &target_a);
        let upstream_b = pooled(&old, &target_b);
        let next = ServerState::reload(&old, server).unwrap();

        assert_eq!(next.proxy.pool().len(), 2);
        assert!(Arc::ptr_eq(&upstream_a, &pooled(&next, &target_a)));
        assert!(Arc::ptr_eq(&upstream_b, &pooled(&next, &target_b)));
    }
}
