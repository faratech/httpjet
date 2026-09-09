//! Shared, immutable-per-generation server state handed to every connection.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio_util::sync::CancellationToken;

use hj_acl::AccessControl;
use hj_compress::{Compress, ExpiresRules};
use hj_core::Router;
use hj_core::config::{ExtAddress, ExtKind, ExtProcessor, ServerConfig};
use hj_fastcgi::{Endpoint as FastCgiEndpoint, FastCgi, FastCgiPool};
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
    #[cfg(feature = "acme")]
    pub acme: Option<Arc<crate::acme_runtime::Routing>>,
    pub generation: u64,
    /// Reused only by application-compatible reloads. Resource replacement must
    /// publish a fresh epoch together with its matching listener trust policy.
    pub(crate) trust_epoch: Arc<()>,
    /// Set by the first API transaction; subsequent reloads retain this epoch
    /// while generation separates response-cache entries across configurations.
    pub response_cache_epoch: Option<Arc<str>>,
    pub config_fingerprint: String,
    pub server: Arc<ServerConfig>,
    pub router: Arc<Router>,
    pub serve_config: ServeConfig,
    /// Server-wide byte budget shared by every layer that buffers request bodies
    /// into heap (io_uring H1/H2/H3 transport buffering + hj-lsapi collect_to_cap).
    /// Process-lifetime: carried across SIGHUP so reservations never straddle two caps.
    pub body_budget: Arc<hj_core::budget::BodyBufferBudget>,
    /// Process-lifetime request content-decoding policy. Gzip is the historical
    /// default; optional Brotli/zstd choices are injected from the CLI after
    /// boot construction and carried unchanged across configuration reloads.
    pub(crate) request_decompression: crate::uring::request_body::RequestDecompression,
    /// Optional loopback request-inspection sidecar. Process-lifetime CLI
    /// policy, carried unchanged across application configuration reloads.
    pub waf: Option<Arc<crate::waf::Sidecar>>,
    /// Compile-time linked request/response extensions. Empty in the shipped
    /// binary; process-lifetime and carried unchanged across config reloads.
    pub extensions: Arc<hj_extension::ExtensionRegistry>,
    /// Terminal static-file handler.
    pub static_handler: StaticFiles,
    /// Per-vhost lsphp pool registry (None if PHP is disabled or the default
    /// pool failed to start). With suEXEC off this holds exactly one entry (the
    /// canonical `"php"` pool) behaving byte-for-byte like today's single pool.
    pub lsapi: Option<Arc<LsapiRegistry>>,
    /// Opt-in FastCGI handlers keyed by `(vhost scope, processor name)`.
    /// A scoped processor always wins over a global processor of the same name.
    pub fastcgi: HashMap<(Option<String>, String), Arc<FastCgi>>,
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
    /// Replaced on reload; in-flight requests retain their generation's memo.
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
    let mut targets: Vec<_> = server
        .ext_processors
        .iter()
        .filter(|processor| processor.kind == ExtKind::Proxy)
        .map(ProxyTarget::from_ext_processor)
        .collect();
    for (name, decl) in &server.vhosts {
        if let Some(vhost) = &decl.config {
            targets.extend(
                vhost
                    .extra_ext_processors
                    .iter()
                    .filter(|ep| ep.kind == ExtKind::Proxy)
                    .map(|ep| {
                        ProxyTarget::from_ext_processor(ep).in_scope(format!("vhost:{name}"))
                    }),
            );
        }
    }
    targets
}

fn configured_fastcgi_handlers(
    server: &ServerConfig,
    body_budget: &Arc<hj_core::budget::BodyBufferBudget>,
) -> Result<HashMap<(Option<String>, String), Arc<FastCgi>>, String> {
    fn insert(
        handlers: &mut HashMap<(Option<String>, String), Arc<FastCgi>>,
        scope: Option<String>,
        processor: &ExtProcessor,
        max_body: u64,
        body_budget: &Arc<hj_core::budget::BodyBufferBudget>,
    ) -> Result<(), String> {
        if processor.kind != ExtKind::FastCgi {
            return Ok(());
        }
        let endpoint = match &processor.address {
            ExtAddress::Tcp(address) => FastCgiEndpoint::Tcp(*address),
            ExtAddress::HostPort(address) if !address.trim().is_empty() => {
                FastCgiEndpoint::TcpHost(address.clone())
            }
            ExtAddress::Uds(path) if !path.as_os_str().is_empty() => {
                FastCgiEndpoint::Unix(path.clone())
            }
            _ => {
                return Err(format!(
                    "FastCGI processor {} has an empty address",
                    processor.name
                ));
            }
        };
        let pool = Arc::new(
            FastCgiPool::new(
                endpoint,
                processor.max_conns as usize,
                processor.init_timeout,
                processor.pc_keep_alive_timeout,
            )
            .map_err(|error| format!("FastCGI processor {}: {error}", processor.name))?,
        );
        let handler = FastCgi::new(pool)
            .max_body(max_body)
            .body_buffer_budget(Arc::clone(body_budget))
            .base_env(processor.env.clone())?;
        let key = (scope, processor.name.clone());
        if handlers.insert(key, Arc::new(handler)).is_some() {
            return Err(format!("duplicate FastCGI processor {}", processor.name));
        }
        Ok(())
    }

    let mut handlers = HashMap::new();
    for processor in &server.ext_processors {
        insert(
            &mut handlers,
            None,
            processor,
            server.tuning.max_req_body_size,
            body_budget,
        )?;
    }
    for (vhost_name, declaration) in &server.vhosts {
        if let Some(vhost) = &declaration.config {
            for processor in &vhost.extra_ext_processors {
                insert(
                    &mut handlers,
                    Some(vhost_name.clone()),
                    processor,
                    server.tuning.max_req_body_size,
                    body_budget,
                )?;
            }
        }
    }
    Ok(handlers)
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
    pub(crate) fn fastcgi_handler(
        &self,
        vhost_name: &str,
        processor_name: &str,
    ) -> Option<&Arc<FastCgi>> {
        self.fastcgi
            .get(&(Some(vhost_name.to_string()), processor_name.to_string()))
            .or_else(|| self.fastcgi.get(&(None, processor_name.to_string())))
    }

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
        let proxy = Arc::new(Proxy::with_targets(configured_proxy_targets(&server)));
        let geo = Arc::new(build_geo_rules(&server)?);
        let body_budget = lsapi.as_ref().map(|r| r.body_budget()).unwrap_or_else(|| {
            Arc::new(hj_core::budget::BodyBufferBudget::new(
                hj_core::budget::DEFAULT_BODY_BUFFER_MEM,
            ))
        });
        let fastcgi = configured_fastcgi_handlers(&server, &body_budget)?;
        let extensions = Arc::new(crate::extensions::compiled_registry());
        for (name, kind) in extensions.registrations() {
            tracing::info!(extension = name, kind, "compile-time extension registered");
        }
        Ok(Arc::new(ServerState {
            generation: 1,
            trust_epoch: Arc::new(()),
            response_cache_epoch: None,
            #[cfg(feature = "acme")]
            acme: None,
            config_fingerprint: crate::admin::fingerprint(&server),
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
            body_budget,
            request_decompression: Default::default(),
            waf: None,
            extensions,
            static_handler: cd.static_handler,
            lsapi,
            fastcgi,
            proxy,
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
        let generation = old
            .generation
            .checked_add(1)
            .ok_or("generation exhausted")?;
        #[cfg(feature = "acme")]
        if let Some(acme) = &old.acme {
            acme.validate_reload(server.clone())?;
        }
        // CF_SEND_ZSTD is a process-lifetime CLI flag; carry it across SIGHUP by
        // reading it back off the old generation's Compress (its single home).
        let cd = build_config_derived(&server, old.compress.cf_send_zstd())?;
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
        let fastcgi = configured_fastcgi_handlers(&server, &old.body_budget)?;
        Ok(Arc::new(ServerState {
            generation,
            trust_epoch: old.trust_epoch.clone(),
            response_cache_epoch: old.response_cache_epoch.clone(),
            #[cfg(feature = "acme")]
            acme: old.acme.clone(),
            config_fingerprint: crate::admin::fingerprint(&server),
            server,
            router: cd.router,
            serve_config: cd.serve_config,
            // Process-lifetime budget: reservations in flight when a SIGHUP lands must
            // release against the SAME cap they were admitted under.
            body_budget: old.body_budget.clone(),
            request_decompression: old.request_decompression,
            waf: old.waf.clone(),
            extensions: old.extensions.clone(),
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
            fastcgi,
            proxy,
            // Candidate construction must not clear live caches. Separate generations
            // also prevent an in-flight old request repopulating the new rule memo.
            rewrite_cache: Arc::new(HtaccessCache::new()),
            static_cache: old.static_cache.clone(),
            stat_cache: old.stat_cache.clone(),
            rewrite_outcomes: Arc::new(old.rewrite_outcomes.empty_generation()),
            rewrite_ua_classify: old.rewrite_ua_classify,
            ua_classify: Arc::new(crate::pipeline::UaClassifyCache::new()),
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
            load_balance: Default::default(),
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
    async fn admin_write_network_validates_publishes_and_rejects_stale() {
        use crate::{
            admin_auth::AuthToken, admin_resources::ResourceRoots, admin_write::Control,
            config_transaction::Coordinator,
        };
        use arc_swap::ArcSwap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        async fn send(
            addr: std::net::SocketAddr,
            method: &str,
            path: &str,
            revision: &str,
            body: &str,
            authorized: bool,
        ) -> (u16, serde_json::Value) {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let auth = if authorized { TOKEN } else { "invalid" };
            let extra = if method == "GET" {
                String::new()
            } else {
                format!(
                    "If-Match: \"{revision}\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                    body.len()
                )
            };
            let request = format!(
                "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {auth}\r\n{extra}\r\n{body}"
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut bytes = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            let response = String::from_utf8(bytes).unwrap();
            let (head, body) = response.split_once("\r\n\r\n").unwrap();
            (
                head.split_whitespace().nth(1).unwrap().parse().unwrap(),
                serde_json::from_str(body).unwrap(),
            )
        }
        let root = temp_root("admin-write");
        let xml = "<httpServerConfig><serverName>fixture</serverName></httpServerConfig>";
        let cfg = Arc::new(hj_config::parse_bundle(&root, xml, &Default::default(), "").unwrap());
        let initial = state(cfg);
        let holder = Arc::new(ArcSwap::from(initial.clone()));
        let coordinator = Arc::new(Coordinator::new(holder.clone()).unwrap());
        let revision = coordinator.revision();
        let notifications = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let notify = notifications.clone();
        let control = Arc::new(Control::new(
            coordinator.clone(),
            Arc::new(ResourceRoots::new(&[root.clone()]).unwrap()),
            false,
            None,
            Arc::new(move || {
                notify.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(crate::admin_write::serve(
            listener,
            Arc::new(AuthToken::fixture(TOKEN.as_bytes())),
            control,
        ));
        let body = serde_json::json!({"server_xml": "<httpServerConfig><serverName>fixture</serverName><indexFiles>next.html</indexFiles></httpServerConfig>", "vhosts": [], "mime": "text/plain = txt"}).to_string();
        assert_eq!(
            send(addr, "PUT", "/v1/config", &revision, &body, false)
                .await
                .0,
            401
        );
        assert!(Arc::ptr_eq(&initial, &holder.load_full()));
        let validated = send(addr, "POST", "/v1/config/validate", &revision, &body, true).await;
        assert_eq!(validated.0, 200);
        assert_eq!(validated.1["published"], false);
        assert!(Arc::ptr_eq(&initial, &holder.load_full()));
        let committed = send(addr, "PUT", "/v1/config", &revision, &body, true).await;
        assert_eq!(committed.0, 200);
        assert_eq!(holder.load().server.index_files, vec!["next.html"]);
        assert_eq!(holder.load().generation, 2);
        assert_eq!(committed.1["persistence"], "volatile");
        assert_eq!(committed.1["revision"], coordinator.revision());
        assert_eq!(
            send(addr, "PUT", "/v1/config", &revision, &body, true)
                .await
                .0,
            412
        );
        let current = coordinator.revision();
        assert_eq!(
            send(addr, "PUT", "/v1/config", &current, "{broken secret", true)
                .await
                .0,
            400
        );
        assert_eq!(holder.load().generation, 2);
        assert_eq!(notifications.load(std::sync::atomic::Ordering::SeqCst), 1);
        let observed = send(addr, "GET", "/v1/revision", "", "", true).await;
        assert_eq!(observed.1["revision"], current);
        let restart = serde_json::json!({"server_xml": "<httpServerConfig><user>secret-user</user></httpServerConfig>", "vhosts": [], "mime": ""}).to_string();
        let rejected = send(addr, "PUT", "/v1/config", &current, &restart, true).await;
        assert_eq!(rejected.0, 409);
        assert_eq!(rejected.1, serde_json::json!({"error": "restart_required"}));
        assert_eq!(holder.load().generation, 2);
        let (a, b) = tokio::join!(
            send(addr, "PUT", "/v1/config", &current, &body, true),
            send(addr, "PUT", "/v1/config", &current, &body, true),
        );
        assert_eq!(usize::from(a.0 == 200) + usize::from(b.0 == 200), 1);
        assert!([200, 412, 503].contains(&a.0) && [200, 412, 503].contains(&b.0));
        assert_eq!(holder.load().generation, 3);
        assert_eq!(notifications.load(std::sync::atomic::Ordering::SeqCst), 2);
        coordinator.close();
        initial.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_write_publishes_prepared_tcp_trust_generation() {
        use crate::{
            admin_protocol::{Operation, Request},
            admin_resources::ResourceRoots,
            admin_write::{Control, TcpReplacementPolicy},
            config_transaction::Coordinator,
            listener_plan::{TcpLaunchPolicy, UdsLaunchPolicy},
            resource_generation::TransportResources,
            uring::{ListenerBinding, pipeline_admission, spawn_uring_http, spawn_uring_uds},
        };
        use arc_swap::ArcSwap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = temp_root("admin-tcp-resource");
        let xml = |name: &str| {
            format!(
                "<httpServerConfig><listenerList><listener><name>{name}</name>\
                 <address>127.0.0.1:1</address><secure>0</secure></listener>\
                 </listenerList></httpServerConfig>"
            )
        };
        let initial_xml = xml("old-http");
        let cfg = Arc::new(
            hj_config::parse_bundle(&root, &initial_xml, &Default::default(), "").unwrap(),
        );
        let initial = state(cfg);
        let holder = Arc::new(ArcSwap::from(initial.clone()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let admission = pipeline_admission(holder.clone());
        let workers = spawn_uring_http(
            holder.clone(),
            Arc::from("old-http"),
            address,
            1,
            Some(vec![listener]),
            admission.clone(),
            ListenerBinding::default(),
        )
        .unwrap();
        let uds_path = root.join("http.sock");
        let uds_workers = spawn_uring_uds(
            holder.clone(),
            Arc::from("old-http"),
            uds_path.clone(),
            None,
            admission.clone(),
        )
        .unwrap();
        let coordinator = Arc::new(
            Coordinator::new(holder.clone())
                .unwrap()
                .with_tcp_launch_policy(TcpLaunchPolicy {
                    http: address,
                    https: None,
                })
                .with_uds_launch_policy(UdsLaunchPolicy {
                    path: uds_path.clone(),
                }),
        );
        coordinator
            .install_initial_resources(
                TransportResources::new(initial.trust_epoch.clone(), vec![workers, uds_workers])
                    .unwrap(),
            )
            .unwrap();
        let control = Control::new(
            coordinator.clone(),
            Arc::new(ResourceRoots::new(std::slice::from_ref(&root)).unwrap()),
            false,
            None,
            Arc::new(|| {}),
        )
        .with_tcp_replacement(TcpReplacementPolicy {
            acme_bootstrap: false,
            ktls: false,
            admission,
        });
        let replacement_xml = xml("new-http");
        let request = |operation| Request {
            operation,
            revision: Some(coordinator.revision()),
            body: serde_json::json!({
                "server_xml": &replacement_xml,
                "vhosts": [],
                "mime": ""
            })
            .to_string()
            .into_bytes(),
        };
        let validated = control.execute(request(Operation::Validate)).await;
        assert_eq!(
            validated.0, 200,
            "resource validation response: {validated:?}"
        );
        assert!(Arc::ptr_eq(&initial, &holder.load_full()));
        let mut validation_probe = tokio::net::UnixStream::connect(&uds_path).await.unwrap();
        validation_probe
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut validation_response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            validation_probe.read_to_end(&mut validation_response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(validation_response.starts_with(b"HTTP/1.1 "));
        let response = control.execute(request(Operation::Publish)).await;
        assert_eq!(
            response.0, 200,
            "resource publication response: {response:?}"
        );
        assert_eq!(holder.load().generation, 2);
        assert_eq!(holder.load().server.listeners[0].name, "new-http");
        assert!(!Arc::ptr_eq(
            &initial.trust_epoch,
            &holder.load().trust_epoch
        ));

        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 "));

        let mut uds_client = tokio::net::UnixStream::connect(&uds_path).await.unwrap();
        uds_client
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut uds_response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            uds_client.read_to_end(&mut uds_response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(uds_response.starts_with(b"HTTP/1.1 "));

        coordinator.close();
        initial.shutdown.cancel();
        coordinator.finish_shutdown();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn admin_cancelled_writer_releases_admission_without_publishing() {
        use crate::{
            admin_protocol::{Operation, Request},
            admin_resources::ResourceRoots,
            admin_write::Control,
            config_transaction::Coordinator,
        };
        use arc_swap::ArcSwap;
        let root = temp_root("admin-cancel");
        let xml = "<httpServerConfig/>";
        let cfg = Arc::new(hj_config::parse_bundle(&root, xml, &Default::default(), "").unwrap());
        let initial = state(cfg);
        let holder = Arc::new(ArcSwap::from(initial.clone()));
        let coordinator = Arc::new(Coordinator::new(holder.clone()).unwrap());
        let control = Arc::new(Control::new(
            coordinator.clone(),
            Arc::new(ResourceRoots::new(&[root.clone()]).unwrap()),
            false,
            None,
            Arc::new(|| {}),
        ));
        let request = || Request {
            operation: Operation::Publish,
            revision: Some(coordinator.revision()),
            body: serde_json::json!({"server_xml": xml, "vhosts": [], "mime": ""})
                .to_string()
                .into_bytes(),
        };
        let held = coordinator.begin().await;
        let pending_request = request();
        let pending_control = control.clone();
        let pending = tokio::spawn(async move { pending_control.execute(pending_request).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while control.available_candidates() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(control.execute(request()).await.0, 503);
        let read = tokio::time::timeout(
            Duration::from_secs(1),
            control.execute(Request {
                operation: Operation::Revision,
                revision: None,
                body: Vec::new(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(read.0, 200);
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        assert_eq!(control.available_candidates(), 1);
        assert!(Arc::ptr_eq(&initial, &holder.load_full()));
        // A writer waiting for SIGHUP also has a bounded lock-acquisition deadline.
        let timed_out = control.execute(request()).await;
        assert_eq!(timed_out, (503, "{\"error\":\"busy\"}".into()));
        assert_eq!(control.available_candidates(), 1);
        drop(held);
        assert_eq!(control.execute(request()).await.0, 200);
        assert_eq!(holder.load().generation, 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn reload_candidate_owns_fresh_rewrite_caches() {
        let root = temp_root("candidate-caches");
        let cfg = config(&root, Vec::new(), Vec::new());
        let old = state(cfg.clone());
        let rules =
            hj_rewrite::Htaccess::parse("RewriteEngine On\nRewriteRule ^ /next [L]").unwrap();
        old.ua_classify.get_or_compute(&rules.rules, "test-agent");
        assert_eq!(old.ua_classify.len(), 1);
        let next = ServerState::reload(&old, cfg.clone()).unwrap();
        assert!(!Arc::ptr_eq(&old.rewrite_cache, &next.rewrite_cache));
        assert!(!Arc::ptr_eq(&old.rewrite_outcomes, &next.rewrite_outcomes));
        assert!(!Arc::ptr_eq(&old.ua_classify, &next.ua_classify));
        assert_eq!(old.ua_classify.len(), 1);
        assert_eq!(next.ua_classify.len(), 0);
        drop(next);
        let mut invalid = (*cfg).clone();
        invalid.security.geo_allow.push("US".into());
        assert!(ServerState::reload(&old, Arc::new(invalid)).is_err());
        assert_eq!(old.ua_classify.len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn connection_views_follow_only_compatible_application_generations() {
        use crate::config_transaction::{Coordinator, PublishError};
        use crate::serving_generation::ServingView;
        let root = temp_root("connection-generations");
        let cfg = config(&root, Vec::new(), Vec::new());
        let initial = state(cfg.clone());
        let holder = Arc::new(arc_swap::ArcSwap::from(initial.clone()));
        let worker = ServingView::new(holder.clone());
        let early_connection = worker.pin_connection();
        let application = ServerState::reload(&initial, cfg.clone()).unwrap();
        assert!(Arc::ptr_eq(&initial.trust_epoch, &application.trust_epoch));
        holder.store(application.clone());
        assert!(Arc::ptr_eq(&early_connection.load_full(), &application));
        let later_connection = worker.pin_connection();

        // A trust-epoch change requires the resource publication path; the
        // existing application-only writer must not silently accept it.
        let mut replacement = ServerState::reload(&application, cfg).unwrap();
        Arc::get_mut(&mut replacement).unwrap().trust_epoch = Arc::new(());
        let coordinator = Coordinator::new(holder.clone()).unwrap();
        let transaction = coordinator.begin().await;
        let revision = transaction.revision();
        assert_eq!(
            transaction.publish(&revision, replacement.clone()),
            Err(PublishError::ResourceRequired)
        );
        assert!(Arc::ptr_eq(&holder.load_full(), &application));

        // Model a future complete resource-bundle publication. Each old
        // connection stays with its acceptance snapshot, never the new trust.
        holder.store(replacement.clone());
        assert!(Arc::ptr_eq(&early_connection.load_full(), &initial));
        assert!(Arc::ptr_eq(&later_connection.load_full(), &application));
        assert!(Arc::ptr_eq(
            &ServingView::new(holder).pin_connection().load_full(),
            &replacement
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn transaction_preconditions_serialize_writers_and_reject_old_incarnations() {
        use crate::config_transaction::{Coordinator, PublishError};
        use arc_swap::ArcSwap;
        let root = temp_root("transaction-publication");
        let cfg = config(&root, Vec::new(), Vec::new());
        let old = state(cfg.clone());
        let holder = Arc::new(ArcSwap::from(old.clone()));
        let coordinator = Arc::new(Coordinator::new(holder.clone()).unwrap());
        let first = coordinator.begin().await;
        let old_revision = first.revision();
        let next = ServerState::reload(&old, cfg.clone()).unwrap();

        // A second writer must wait, then observe the published generation.
        let waiting = coordinator.clone();
        let task = tokio::spawn(async move {
            let transaction = waiting.begin().await;
            (transaction.current.generation, transaction.revision())
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        first.publish(&old_revision, next.clone()).unwrap();
        let (generation, new_revision) = task.await.unwrap();
        assert_eq!(generation, 2);
        assert_ne!(old_revision, new_revision);
        assert!(Arc::ptr_eq(&holder.load_full(), &next));

        let rejected = coordinator.begin().await;
        let third = ServerState::reload(&next, cfg.clone()).unwrap();
        assert_eq!(
            rejected.publish(&old_revision, third.clone()),
            Err(PublishError::Conflict)
        );
        assert!(Arc::ptr_eq(&holder.load_full(), &next));

        let invalid = coordinator.begin().await;
        let revision = invalid.revision();
        assert_eq!(
            invalid.publish(&revision, next.clone()),
            Err(PublishError::InvalidGeneration)
        );
        assert!(Arc::ptr_eq(&holder.load_full(), &next));

        // A new coordinator models a process restart at the same generation.
        let restarted = Coordinator::new(Arc::new(ArcSwap::from(next.clone()))).unwrap();
        let transaction = restarted.begin().await;
        assert_ne!(transaction.revision(), new_revision);
        assert_eq!(
            transaction.publish(&new_revision, third),
            Err(PublishError::Conflict)
        );

        // Dropping validation-only work never publishes a generation.
        drop(coordinator.begin().await);
        assert!(Arc::ptr_eq(&holder.load_full(), &next));
        let pending = coordinator.begin().await;
        let revision = pending.revision();
        let prepared = ServerState::reload(&next, cfg.clone()).unwrap();
        coordinator.close();
        assert_eq!(
            pending.publish(&revision, prepared),
            Err(PublishError::Closed)
        );
        assert!(Arc::ptr_eq(&holder.load_full(), &next));
        let mut exhausted = state(cfg.clone());
        Arc::get_mut(&mut exhausted).unwrap().generation = u64::MAX;
        assert!(
            matches!(ServerState::reload(&exhausted, cfg), Err(error) if error == "generation exhausted")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn resource_publication_bounds_retirement_without_joining_under_lock() {
        use crate::config_transaction::{Coordinator, PublishError};
        use crate::resource_generation::TransportResources;
        use std::sync::mpsc;
        use std::time::Duration;
        struct Signals {
            activated: mpsc::Receiver<u64>,
            stopped: mpsc::Receiver<()>,
            release: mpsc::Sender<()>,
        }
        fn resources(
            state: &Arc<ServerState>,
            holder: &Arc<arc_swap::ArcSwap<ServerState>>,
        ) -> (TransportResources, Signals) {
            let mut group =
                crate::uring::WorkerGroup::for_epoch(&state.shutdown, state.trust_epoch.clone());
            let gate = group.activation_gate();
            let (activated_tx, activated) = mpsc::channel();
            let (stopped_tx, stopped) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            let holder = holder.clone();
            group
                .spawn(std::thread::Builder::new(), move |shutdown| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .unwrap();
                    if runtime.block_on(gate.wait()) {
                        activated_tx.send(holder.load().generation).unwrap();
                        runtime.block_on(shutdown.cancelled());
                        stopped_tx.send(()).unwrap();
                        // Deliberately keep retirement unfinished until released.
                        // Dropping the test's sender also releases on a panic path.
                        let _ = release_rx.recv();
                    } else {
                        let _ = activated_tx.send(0);
                        let _ = stopped_tx.send(());
                    }
                })
                .unwrap();
            (
                TransportResources::new(state.trust_epoch.clone(), vec![group]).unwrap(),
                Signals {
                    activated,
                    stopped,
                    release,
                },
            )
        }
        fn next(old: &Arc<ServerState>) -> Arc<ServerState> {
            let mut state = ServerState::reload(old, old.server.clone()).unwrap();
            Arc::get_mut(&mut state).unwrap().trust_epoch = Arc::new(());
            state
        }
        let root = temp_root("resource-publication");
        let initial = state(config(&root, Vec::new(), Vec::new()));
        let holder = Arc::new(arc_swap::ArcSwap::from(initial.clone()));
        let coordinator = Coordinator::new(holder.clone()).unwrap();
        let (owned, first) = resources(&initial, &holder);
        coordinator.install_initial_resources(owned).unwrap();
        assert_eq!(
            first
                .activated
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            1
        );

        let second_state = next(&initial);
        for rejection in ["revision", "owner_epoch", "unchanged_epoch", "cancelled"] {
            let submitted = if rejection == "unchanged_epoch" {
                ServerState::reload(&initial, initial.server.clone()).unwrap()
            } else {
                second_state.clone()
            };
            let owner_state = if rejection == "owner_epoch" {
                &initial
            } else {
                &submitted
            };
            let (owned, rejected) = resources(owner_state, &holder);
            if rejection == "cancelled" {
                owned.stop();
            }
            let transaction = coordinator.begin().await;
            let revision = if rejection == "revision" {
                "stale-revision".into()
            } else {
                transaction.revision()
            };
            let expected = if rejection == "revision" {
                PublishError::Conflict
            } else {
                PublishError::ResourceRequired
            };
            assert_eq!(
                transaction.publish_resources(&revision, submitted, owned),
                Err(expected)
            );
            assert_eq!(
                rejected
                    .activated
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap(),
                0
            );
            assert!(Arc::ptr_eq(&holder.load_full(), &initial));
            assert!(
                first.stopped.try_recv().is_err(),
                "rejected candidate must not stop the active set"
            );
        }
        let (owned, second) = resources(&second_state, &holder);
        let transaction = coordinator.begin().await;
        let revision = transaction.revision();
        transaction
            .publish_resources(&revision, second_state.clone(), owned)
            .unwrap();
        first.stopped.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            second
                .activated
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            2
        );
        assert_eq!(
            coordinator.reap_retired(),
            0,
            "unfinished workers retain their slot"
        );

        let third_state = next(&second_state);
        let (owned, third) = resources(&third_state, &holder);
        let transaction = coordinator.begin().await;
        let revision = transaction.revision();
        transaction
            .publish_resources(&revision, third_state.clone(), owned)
            .unwrap();
        second.stopped.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            third
                .activated
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            3
        );

        let fourth_state = next(&third_state);
        let preflight = coordinator.begin().await;
        assert!(matches!(
            preflight.candidate_view(fourth_state.clone()),
            Err(PublishError::RetirementBusy)
        ));
        drop(preflight);
        let (owned, rejected) = resources(&fourth_state, &holder);
        let transaction = coordinator.begin().await;
        let revision = transaction.revision();
        assert_eq!(
            transaction.publish_resources(&revision, fourth_state.clone(), owned),
            Err(PublishError::RetirementBusy)
        );
        assert_eq!(
            rejected
                .activated
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            0
        );
        assert!(Arc::ptr_eq(&holder.load_full(), &third_state));

        first.release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while coordinator.reap_retired() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let (owned, fourth) = resources(&fourth_state, &holder);
        let transaction = coordinator.begin().await;
        let revision = transaction.revision();
        transaction
            .publish_resources(&revision, fourth_state.clone(), owned)
            .unwrap();
        third.stopped.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            fourth
                .activated
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            4
        );

        coordinator.close();
        fourth.stopped.recv_timeout(Duration::from_secs(2)).unwrap();
        let fifth_state = next(&fourth_state);
        let preflight = coordinator.begin().await;
        assert!(matches!(
            preflight.candidate_view(fifth_state.clone()),
            Err(PublishError::Closed)
        ));
        drop(preflight);
        let (owned, rejected) = resources(&fifth_state, &holder);
        let transaction = coordinator.begin().await;
        let revision = transaction.revision();
        assert_eq!(
            transaction.publish_resources(&revision, fifth_state, owned),
            Err(PublishError::Closed)
        );
        assert_eq!(
            rejected
                .activated
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            0
        );
        assert!(Arc::ptr_eq(&holder.load_full(), &fourth_state));
        second.release.send(()).unwrap();
        third.release.send(()).unwrap();
        fourth.release.send(()).unwrap();
        coordinator.finish_shutdown();
        coordinator.finish_shutdown(); // idempotent, with no remaining owners
        drop(coordinator);
        std::fs::remove_dir_all(root).unwrap();
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
    async fn admin_reads_published_generation_without_mutation_or_paths() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let root = temp_root("admin-snapshot");
        let cfg = config(&root, Vec::new(), Vec::new());
        let old = state(cfg.clone());
        let next = ServerState::reload(&old, cfg).unwrap();
        assert_eq!(old.generation, 1);
        assert_eq!(next.generation, 2);
        assert_eq!(old.config_fingerprint, next.config_fingerprint);
        let holder = Arc::new(arc_swap::ArcSwap::from(old));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(crate::admin::serve(listener, holder.clone()));
        for (method, generation) in [("GET", 1), ("POST", 2), ("GET", 2)] {
            let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            socket
                .write_all(
                    format!("{method} /v1/status HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut response = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                socket.read_to_string(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            if method == "GET" {
                assert!(response.starts_with("HTTP/1.1 200"));
                assert!(response.contains(&format!("\"generation\":{generation}")));
                assert!(!response.contains(root.to_str().unwrap()));
            } else {
                assert!(response.starts_with("HTTP/1.1 405"));
            }
            holder.store(next.clone());
        }
        task.abort();
        let _ = task.await;
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
        let target_a = target_a.in_scope("vhost:one");
        let target_b = target_b.in_scope("vhost:two");
        let upstream_a = pooled(&old, &target_a);
        let upstream_b = pooled(&old, &target_b);
        let next = ServerState::reload(&old, server).unwrap();

        assert_eq!(next.proxy.pool().len(), 2);
        assert!(Arc::ptr_eq(&upstream_a, &pooled(&next, &target_a)));
        assert!(Arc::ptr_eq(&upstream_b, &pooled(&next, &target_b)));
    }
}
