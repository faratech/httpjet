//! httpjet — a Rust drop-in replacement for LiteSpeed.
//!
//! `check` loads and summarizes the LiteSpeed config. `serve` runs the full
//! LSWS-compatible edge: HTTP/1.1, native HTTP/2, HTTP/3, TLS/mTLS, rewrite,
//! proxy, static files, LSAPI/PHP, logging, and the LSCache-equivalent page cache.
//! Production is systemd/socket-activation managed on :80/:443; test instances
//! should use alternate ports and their own lsphp socket.

mod allocount;
mod lscache;
mod memtrim;
mod metrics;
mod peer_purge;
mod phpslow;
mod pipeline;
mod server;
mod statcache;
mod state;
mod telemetry;
mod uring;

/// Process-wide allocator. mimalloc replaces glibc malloc to cut arena-lock /
/// futex contention under the multi-thread tokio runtime — the bottleneck
/// `RESULTS.md` named (futex ≈75% of syscall time). Applies to every crate.
/// Under `--features allocount` it is wrapped to count allocations (the h2
/// alloc-campaign measurement harness); a normal/PGO build uses plain mimalloc.
#[cfg(not(feature = "allocount"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "allocount")]
#[global_allocator]
static GLOBAL: allocount::Counting = allocount::Counting;

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use clap::{Parser, Subcommand, ValueEnum};
use hj_core::config::ExtKind;

use crate::state::{ServerState, XfCapsuleSafeGetMode};

#[derive(Parser, Debug)]
#[command(
    name = "httpjet",
    version,
    about = "Rust drop-in replacement for LiteSpeed"
)]
struct Cli {
    /// Server root containing conf/httpd_config.xml (LiteSpeed-compatible).
    #[arg(long, default_value = "/usr/local/lsws")]
    root: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
// Parsed once at startup; the Serve-vs-Check size gap is irrelevant (and boxing
// a clap subcommand's args struct is awkward).
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Load and print a summary of the parsed configuration.
    Check {
        /// Lint the vhost/listener topology and exit non-zero on findings:
        /// docroots shared by two vhosts (error), apex domains mapped without
        /// their `www.` twin, vhosts with no exact vhostMap domain. Also
        /// prints a `vhost-map-fingerprint:` diagnostic for comparing local
        /// check output over time; split-DNS nodes are not expected to match.
        #[arg(long)]
        strict: bool,
    },
    /// Serve the configured vhosts.
    Serve(ServeArgs),
    /// (OPS7) Run a standalone, persistent lsphp pool (the LSAPI "external app"
    /// half of a zero-downtime deploy): bind the socket, spawn + supervise lsphp,
    /// and park until SIGTERM. `serve --lsphp-external <socket>` connects to it,
    /// so the web tier can restart without cold-starting PHP.
    Lsphp(LsphpArgs),
    /// Ask the running standalone lsphp supervisor to replace its worker
    /// generation without closing the systemd-owned LSAPI listener.
    LsphpReload(LsphpReloadArgs),
}

#[derive(Parser, Debug)]
struct LsphpArgs {
    /// Socket lsphp listens on (the same path `serve --lsphp-external` dials).
    #[arg(long, default_value = "/tmp/php8-httpjet.sock")]
    php_socket: PathBuf,
    /// LSAPI child count. 0 (default) = honor the lsws config's
    /// `PHP_LSAPI_CHILDREN` / `maxConns`; > 0 overrides it. Persistent
    /// supervision normalizes values below 2 to 2.
    #[arg(long, default_value_t = 0)]
    php_children: u32,
    /// Root-only control socket used by `lsphp-reload`. Default:
    /// `<php-socket>.control`, beside the pool's own LSAPI socket, so a test
    /// pool can never answer the production control path. Production passes
    /// /run/httpjet/lsphp-control.sock explicitly in the systemd unit.
    #[arg(long)]
    control_socket: Option<PathBuf>,
    /// Shared generation epoch observed by external LSAPI client pools.
    /// Default: `<php-socket>.generation`, so a test pool can never advance
    /// the production epoch (which would drop the live web tier's pooled
    /// connections and retire its workers against a foreign marker).
    /// Production passes /run/httpjet/lsphp.generation explicitly.
    #[arg(long)]
    generation_file: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct LsphpReloadArgs {
    /// Root-only control socket exposed by the standalone lsphp supervisor.
    #[arg(long, default_value = "/run/httpjet/lsphp-control.sock")]
    control_socket: PathBuf,
    /// Maximum time to wait for candidate readiness and old-generation drain.
    #[arg(long, default_value_t = 90)]
    timeout_secs: u64,
}

#[derive(Parser, Debug)]
struct ServeArgs {
    /// Address for the plain-HTTP listener.
    #[arg(long, default_value = "127.0.0.1:8080")]
    http_addr: SocketAddr,
    /// Address for the TLS listener. Empty to disable.
    #[arg(long, default_value = "127.0.0.1:4443")]
    https_addr: String,
    /// Number of accept-loop workers (SO_REUSEPORT sockets). Defaults to CPUs.
    #[arg(long)]
    workers: Option<usize>,
    /// Local testing / explicit rollback only: drop the mandatory Cloudflare
    /// client-cert requirement so TLS content can be tested locally without a
    /// Cloudflare-issued client cert.
    /// Without this flag, clientVerify=2 is enforced (handshakes without a
    /// valid client cert are rejected — the production fail-closed behavior).
    #[arg(long)]
    no_mtls: bool,
    /// Do not spawn lsphp; PHP requests fall back to static serving.
    #[arg(long)]
    no_php: bool,
    /// LSAPI worker children for the lsphp pool. 0 (default) = honor the lsws
    /// config's `PHP_LSAPI_CHILDREN` / `maxConns` (true drop-in). A value > 0 is
    /// an explicit override (e.g. to cap concurrency on a shared box); values
    /// below 2 are normalized to 2 for persistent supervision.
    #[arg(long, default_value_t = 0)]
    php_children: u32,
    /// Socket path for httpjet's OWN lsphp pool — deliberately separate from the
    /// production php8.sock so the two never contend.
    #[arg(long, default_value = "/tmp/php8-httpjet.sock")]
    php_socket: PathBuf,
    /// (OPS7) EXTERNAL lsphp: connect to an lsphp master already listening on this
    /// socket (run by a separate `httpjet lsphp` process) instead of spawning one.
    /// Lets the web tier restart for a zero-downtime binary deploy without cold-
    /// starting PHP. Overrides --php-socket. Mutually exclusive with spawning.
    #[arg(long)]
    lsphp_external: Option<PathBuf>,
    /// Shared lsphp generation epoch used to invalidate pooled external
    /// connections after a supervisor reload or restart. When supplied with
    /// --lsphp-external, startup fails if the 16-byte mapping cannot be opened.
    #[arg(long)]
    lsphp_generation_file: Option<PathBuf>,
    #[command(flatten)]
    page_cache: PageCacheArgs,
    #[command(flatten)]
    xf_capsule: XfCapsuleArgs,
    /// (CF_SEND_ZSTD) Compress responses to a trusted-proxy (Cloudflare) peer as zstd,
    /// ignoring the forwarded Accept-Encoding. CF asks the origin for br/gzip but decodes
    /// an origin `Content-Encoding: zstd` and re-encodes per browser at its edge — so this
    /// hands CF the cheapest-to-produce form (zstd ≪ brotli to compress) without changing
    /// what browsers receive. Officially unsupported CF↔origin; opt-in, default off. Never
    /// applies to untrusted (direct) clients. Off ⇒ byte-identical to today.
    #[arg(long, default_value_t = false)]
    cf_send_zstd: bool,
    /// (OPS1) Loopback-only Prometheus metrics endpoint address. Empty to
    /// disable. Exposes the page-cache hit/miss ratio (the key operational
    /// number once --page-cache is live) plus request/connection counters.
    #[arg(long, default_value = "127.0.0.1:9090")]
    metrics_addr: String,
    /// (telemetry) Append a cumulative per-request telemetry snapshot row to this
    /// file every --telemetry-flush-secs: durability across restarts + a
    /// self-contained time-series for the two-node A/B. Empty = no disk flush (the
    /// in-RAM aggregates + the :9090 endpoint still work). e.g. logs/telemetry.tsv
    #[arg(long, default_value = "")]
    telemetry_file: String,
    /// (telemetry) Snapshot flush interval in seconds (only used when
    /// --telemetry-file is set). Fixed RAM; ~1 MB/day on disk at the default.
    #[arg(long, default_value_t = 30)]
    telemetry_flush_secs: u64,
    /// (attribution) Per-request PHP render log: a TSV line for every LSAPI
    /// request whose render TTFB exceeds --php-slow-threshold-ms, plus a 1-in-128
    /// sample of ALL PHP requests as the population baseline — the per-URL /
    /// user-class attribution behind the lsapi_ttfb histogram. Rolls at 64 MiB,
    /// gzip archives, 30-day prune. Empty = disabled. e.g. logs/php-slow.tsv
    #[arg(long, default_value = "")]
    php_slow_log: String,
    /// (attribution) "Slow" threshold in milliseconds for --php-slow-log.
    #[arg(long, default_value_t = 50)]
    php_slow_threshold_ms: u64,
    /// (ops2/resilience) Total request processing deadline in milliseconds. When
    /// exceeded, the handler closes the connection (504); in OWNED/spawn mode the
    /// monitor also kills+restarts the worker (Tier-2). Under --lsphp-external (prod)
    /// there is no monitor in this process, so only the Tier-1 504 applies — a wedged
    /// worker is NOT auto-reclaimed here. 0 = no deadline (matches the LiteSpeed XML
    /// `maxProcessTime` 0-means-unlimited convention). Absent ⇒ the XML value if
    /// present, else no deadline. Must be conservative: too low kills slow renders.
    #[arg(long)]
    php_max_process_time_ms: Option<u64>,
    /// (obs) Echo the per-request correlation id (also in the access/error/php-slow
    /// logs) as an `X-Request-Id` response header, so a client/CDN can join a
    /// response to the server-side logs. Off by default.
    #[arg(long, default_value_t = false)]
    request_id_header: bool,
    /// (mem) Interval (seconds) for the background mimalloc OS-trim that calls
    /// mi_collect(force) to hand retained/cold arena pages back to the OS (counters
    /// the swap retention seen in prod after a burst). 0 = disable.
    #[arg(long, default_value_t = 120)]
    mimalloc_trim_secs: u64,
    /// (mem) Only run the mimalloc trim when process RSS+swap (read from
    /// /proc/self/status) is at least this many MiB; 0 = always. Lets a small,
    /// healthy process skip the collect entirely. Default 768: well above the
    /// measured healthy steady-state (x86 ~360 MiB, ARM ~240 MiB) so a process
    /// at rest never pays the force-collect cost, while genuine post-burst
    /// arena retention still trips the safety-net reclaim.
    #[arg(long, default_value_t = 768)]
    mimalloc_trim_threshold_mib: u64,
    /// (profiling) Optional shared token guarding the /debug/pprof/profile endpoint
    /// (only built with `--features profiling`; loopback-only regardless). Empty
    /// = no token (loopback is the only guard).
    #[arg(long, default_value = "")]
    profile_token: String,
    /// (OPS3) Peer node `host:port` to forward page-cache purges to, so the
    /// active-active pair stays coherent (repeatable). Point it at the peer's
    /// EXISTING HTTP port (e.g. `192.0.2.3:80`); purges are received on that
    /// listener via a reserved path gated by loopback/configured peer source IP
    /// — no extra port is opened.
    /// The peer's IP is the trusted inbound source. Requires --page-cache; without
    /// a peer, peer-purge is inert. Inbound purges are authenticated by the
    /// private/LAN source-IP gate (no shared secret).
    #[arg(long)]
    cache_peer: Vec<String>,
    /// (rewrite) TTL in milliseconds for the rewrite-outcome cache (memoized
    /// rewrite decisions for `path_cacheable` chains, keyed by vhost/scheme/
    /// method/host/path/query + any keyable header vars). 0 disables the cache
    /// entirely. The default (1000 ms) matches the historical hard-coded TTL —
    /// it bounds `-f`/`-d` filesystem staleness exactly like the StatCache and
    /// lets `.htaccess` edits take effect within ~1 s.
    #[arg(long = "rewrite-outcome-ttl-ms", default_value_t = 1000)]
    rewrite_outcome_ttl_ms: u64,
    /// (rewrite) Key UA-reading rewrite chains by the bitmap of matching
    /// User-Agent RewriteConds instead of the raw UA string, when parse-time
    /// analysis proves the outcome depends on the UA only through those match
    /// results. Collapses real-world UA diversity (near-zero hit rate on raw
    /// UAs) onto a handful of outcome-cache entries. Default OFF — enabling is
    /// a deploy-time decision.
    #[arg(long = "rewrite-ua-classify", default_value_t = false)]
    rewrite_ua_classify: bool,
    /// (uring, STAGED) Kernel-TLS the io_uring TLS path: after the rustls handshake,
    /// upgrade the socket to kTLS so H1/H2 serve plaintext over the raw fd (kernel
    /// encrypt/decrypt), removing the userspace AEAD copy on large-body egress. Runs
    /// only on the io_uring TLS path (the default transport). Only active in a
    /// `--features ktls` build; otherwise startup fails. TLS 1.3 only (1.2 falls back
    /// to userspace); peer KeyUpdate is handled (RX rekey + reply). STAGED — validate
    /// on an alt port before production.
    #[arg(long = "ktls", default_value_t = false)]
    ktls: bool,
}

/// The `--page-cache-*` flag family, grouped (clap-flattened into the serve args).
/// Every `long` name is EXPLICIT and must never change — the prod systemd drop-ins
/// pass these exact strings.
#[derive(clap::Args, Debug)]
struct PageCacheArgs {
    /// Enable the LSCache-equivalent origin full-page cache (OFF by default;
    /// opt-in / R&D). Per-vhost `<cache><enableCache>` + `.htaccess CacheLookup`
    /// still gate each request, and the app must opt responses in via
    /// `X-LiteSpeed-Cache-Control`. With this flag absent the cache is inert.
    #[arg(long = "page-cache")]
    enabled: bool,
    /// RAM budget (bytes) for the in-process index: entry metadata + precompressed
    /// variants + any in-RAM body. With --page-cache-store-path, persisted (tmpfs)
    /// bodies do NOT count here — they are bounded by --page-cache-disk-mem instead —
    /// so this should be sized for metadata, not body bytes. Without a file tier it
    /// is the whole body budget, as before. Default 128 MiB.
    #[arg(long = "page-cache-mem", default_value_t = 128 * 1024 * 1024)]
    mem: u64,
    /// tmpfs file-tier footprint budget (bytes) for --page-cache-store-path: the disk
    /// LRU evicts the least-recently-served entry once charged file footprint under
    /// the store path exceeds this. tmpfs IS RAM, so size it against the box's
    /// headroom (with dict compression a 2 GiB cap holds the compressed equivalent
    /// of ~7–18 GiB of pages). 0 ⇒ fall back to --page-cache-mem. Ignored without a
    /// file tier. Default 2 GiB.
    #[arg(long = "page-cache-disk-mem", default_value_t = 2 * 1024 * 1024 * 1024)]
    disk_mem: u64,
    /// Directory for the PERSISTENT tmpfs file tier. The default is "none":
    /// bodies stay in the in-process RAM cache and flush on restart. Pass an
    /// explicit directory such as /dev/shm/jetcache to opt into the
    /// LiteSpeed-Enterprise-style store where bodies live as files and the cache
    /// survives restarts via a boot-time warm scan. The LiteSpeed config's
    /// cacheStorePath is intentionally NOT used.
    #[arg(long = "page-cache-store-path", default_value = "none")]
    store_path: String,
    /// Byte cap of the in-RAM hot tier in front of the file store (zero-syscall
    /// zero-copy serves for the hottest bodies). Only meaningful with
    /// --page-cache-store-path. Default 192 MiB.
    #[arg(long = "page-cache-hot-mem", default_value_t = 192 * 1024 * 1024)]
    hot_mem: u64,
    /// (dedup) Path to a shared zstd dictionary used to store cached bodies far smaller. CMS pages
    /// share ~60%+ of their bytes as position-shifted boilerplate that only a dictionary captures;
    /// with this set, `cache_store` dict-compresses the stored body (the SERVED bytes stay standard
    /// zstd/br/gzip — browsers/CF can't decode a private dict). Absent/empty/unreadable ⇒ bodies
    /// are stored as plain identity (today's behaviour). Build one from a reviewed local corpus
    /// with scripts/train-pagecache-dict-from-files.sh.
    #[arg(long = "page-cache-dict", default_value = "")]
    dict: String,
    /// Comma-separated `vhost=path` pairs: a PER-VHOST zstd dictionary, trained on that vhost's own
    /// content (train one local corpus per vhost). A
    /// shared dictionary trained on one site's boilerplate does little for a differently templated
    /// site, so each vhost compresses against its own. A vhost not listed here falls back to
    /// --page-cache-dict if set, else stores identity (today's behaviour). Example:
    /// `forum.example=conf/pagecache-forum.dict,moon.example=conf/pagecache-moon.dict`.
    #[arg(long = "page-cache-dict-vhost", default_value = "")]
    dict_vhost: String,
    /// (W-TinyLFU) Base admission bar: minimum frequency a cacheable response must show before it
    /// is STORED. 2 = store on the 2nd sighting (miss-miss-hit; rejects the long-tail of
    /// one-hit-wonders — the default). 1 = store on the 1st sighting (miss-hit; cache everything —
    /// now cheap with --page-cache-dict, with the store's byte LRU protecting the hot set).
    /// Size-weighting adds +1 per 256 KiB on top. Watch httpjet_cache_hit_ratio_real to tune.
    #[arg(long = "page-cache-admit-threshold", default_value_t = 2)]
    admit_threshold: u8,
    /// Comma-separated public-vary cookie names: a cacheable public response may
    /// declare `X-LiteSpeed-Vary: cookie=NAME,...` and the entry is keyed by
    /// these cookies' values (shared, non-sensitive prefs). Default matches the
    /// XenForo style/language set.
    #[arg(
        long = "page-cache-vary-cookies",
        default_value = "xf_style_variation,xf_style_id,xf_language_id"
    )]
    vary_cookies: String,
    /// Comma-separated cookie names that forbid public caching if a public
    /// response tries to Set-Cookie them (session guard). Default: XenForo.
    #[arg(
        long = "page-cache-private-cookies",
        default_value = "xf_session,xf_user"
    )]
    private_cookies: String,
    /// Enable the per-session PRIVATE cache tier: an `X-LiteSpeed-Cache-Control:
    /// private[,max-age=N]` response from a logged-in request is stored keyed by
    /// the session cookie and served only to that same session. OFF by default —
    /// without the flag a private opt-in bypasses exactly as before.
    #[arg(long = "page-cache-private")]
    private_enabled: bool,
    /// Request cookie whose VALUE keys a private entry's owner (the session).
    #[arg(
        long = "page-cache-private-session-cookie",
        default_value = "xf_session"
    )]
    private_session_cookie: String,
    /// Request cookie whose PRESENCE routes a request to the private tier
    /// (the logged-in marker; XenForo's remember cookie).
    #[arg(long = "page-cache-private-user-cookie", default_value = "xf_user")]
    private_user_cookie: String,
    /// (shared-paths) Comma-separated matchers for visitor-invariant endpoints that MEMBER
    /// (logged-in) requests may still read/populate on the PUBLIC cache tier — sharing one
    /// entry across guests and every member session instead of duplicating per session and
    /// re-rendering each member's first view through PHP. Two matcher forms: `PATH?PARAM`
    /// (path equals PATH exactly AND the query carries `PARAM=`, e.g. `proxy.php?image`)
    /// and `PATH` (path prefix, e.g. `/wf-unfurl/image`); a missing leading `/` is
    /// normalized on. ONLY list endpoints whose bytes are identical for every visitor
    /// (HMAC-gated image proxies) — never HTML pages. Malformed specs abort startup.
    /// Empty/absent = feature inert (kill switch; members keep today's private routing).
    /// GLOBAL like the other --page-cache-private-* knobs — not per-vhost — but a matching
    /// request still passes every per-vhost public gate (`vhost` cache policy, `.htaccess`
    /// CacheLookup) and every public-store guard before it is served or stored.
    #[arg(long = "page-cache-shared-paths", default_value = "")]
    shared_paths: String,
    /// (shared-paths) Deterministic percentage (0-100) of member requests matching
    /// --page-cache-shared-paths that actually route to the public tier; the rest keep
    /// today's private-tier behavior. Sticky per member (bucketed by a hash of the
    /// user/session cookie value, exactly like --xf-capsule-member-canary-percent), so one
    /// member never flickers between tiers. 100 = all matching requests.
    #[arg(long = "page-cache-shared-paths-canary-percent", default_value_t = 100)]
    shared_paths_canary_percent: u8,
    /// Comma-separated vhost names put into "standards mode": they honor a standard
    /// `Cache-Control: public, max-age=N` as a cache opt-in (OpenLiteSpeed's `checkPublicCache`
    /// equivalent), get a default public cache policy when they declare no `<cache>` block, and
    /// default `CacheLookup` to on — so a non-LiteSpeed app (e.g. moon.example) caches like a
    /// standards-compliant shared cache. ALLOWLIST, not a global switch: a vhost not listed is
    /// unaffected (X-LiteSpeed opt-in only), so opting one content site in can't make an
    /// unrelated vhost (status/admin API) cache a response it merely marked public. All other
    /// guards (GET-only, Set-Cookie/private-cookie, vary, status, self-redirect) always apply.
    #[arg(long = "page-cache-standard-vhosts", default_value = "")]
    standard_vhosts: String,
    /// (peer-fetch) Enable cross-node cache FILL: on a local page-cache MISS, ask the
    /// `--cache-peer` for the entry (over the existing purge interconnect) and adopt
    /// it instead of rendering. OFF by default — deploying the binary is a no-op until
    /// turned on per node. Requires `--page-cache` + `--cache-peer`; Redis pre-bootstrap
    /// stays as the fallback.
    #[arg(long = "cache-peer-fill", default_value_t = false)]
    cache_peer_fill: bool,
    /// (peer-fetch) Per-fetch timeout in MILLISECONDS — it is on the request latency
    /// path, so keep it small (the WireGuard RTT is sub-ms); a slow/down peer falls
    /// through to a local render via the circuit breaker.
    #[arg(long = "cache-peer-fill-timeout-ms", default_value_t = 50)]
    cache_peer_fill_timeout_ms: u64,
    /// (peer-fetch) Negative-cache TTL in SECONDS: after the peer 404s a key, skip
    /// re-asking it (no round-trip) for this long. Kills the wasted RTT on long-tail /
    /// uncacheable keys that neither node caches. 0 keeps the built-in default (10s).
    #[arg(long = "cache-peer-fill-negcache-secs", default_value_t = 10)]
    cache_peer_fill_negcache_secs: u64,
    /// Stale-while-revalidate window (seconds) applied when the app declares none. 0 = off
    /// (serve only fresh unless the app sets stale-while-revalidate / max-stale).
    #[arg(long = "page-cache-stale-default-secs", default_value_t = 0)]
    stale_default_secs: u32,
    /// Hard cap (seconds) on the stale-while-revalidate window honored from the app.
    #[arg(long = "page-cache-stale-max-secs", default_value_t = 86_400)]
    stale_max_secs: u32,
    /// Hard cap (seconds) on the stale-if-error window honored from the app.
    #[arg(long = "page-cache-stale-if-error-max-secs", default_value_t = 86_400)]
    stale_if_error_max_secs: u32,
    /// Stale-if-error window (seconds) applied when the app declares none: how long past
    /// freshness a public entry stays servable as a backend-5xx fallback (a brief lsphp/DB
    /// outage serves slightly-stale pages instead of error pages). 0 = off (the prior
    /// behavior: only an app-declared stale-if-error window arms the fallback).
    #[arg(long = "page-cache-stale-if-error-default-secs", default_value_t = 0)]
    stale_if_error_default_secs: u32,
}

/// XenForo hot-capsule tier. It reuses the page cache store but serves a
/// public-equivalent shell from a separate key space before PHP/LSAPI.
#[derive(clap::Args, Debug)]
struct XfCapsuleArgs {
    /// Enable XenForo public-shell capsules. Requires --page-cache; otherwise inert.
    #[arg(long = "xf-capsule")]
    capsule_enabled: bool,
    /// Comma-separated resolved vhost names allowed to serve capsules. Empty
    /// DISABLES the capsule tier for every vhost (#239 fail-closed default).
    #[arg(long = "xf-capsule-vhosts", default_value = "")]
    vhosts: String,
    /// Comma-separated request-path prefixes eligible for capsule lookup/store.
    #[arg(
        long = "xf-capsule-paths",
        default_value = "/,/forums/,/threads/,/whats-new/,/help/"
    )]
    paths: String,
    /// Capsule route coverage. `prefixes` honors --xf-capsule-paths;
    /// `all-get-classified` uses a conservative unsafe-route classifier.
    #[arg(
        long = "xf-capsule-safe-get-mode",
        value_enum,
        default_value = "prefixes"
    )]
    safe_get_mode: XfCapsuleSafeGetCliMode,
    /// Stale-while-revalidate window for capsule shell entries. This is applied
    /// to public-shell capsule stores even if the app declares a smaller window.
    #[arg(long = "xf-capsule-stale-secs", default_value_t = 86_400)]
    stale_secs: u32,
    /// Deterministic percentage of eligible requests that may be served a capsule hit.
    #[arg(long = "xf-capsule-canary-percent", default_value_t = 100)]
    canary_percent: u8,
    /// Allow explicitly-marked member-cookie requests to receive public-shell capsules.
    #[arg(long = "xf-capsule-members", default_value_t = false)]
    allow_members: bool,
    /// Deterministic percentage of eligible member-cookie requests that may receive capsules.
    #[arg(long = "xf-capsule-member-canary-percent", default_value_t = 0)]
    member_canary_percent: u8,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum XfCapsuleSafeGetCliMode {
    Prefixes,
    AllGetClassified,
}

fn normalize_capsule_prefix(prefix: String) -> Option<String> {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return None;
    }
    if prefix == "/" {
        return Some("/".to_string());
    }
    let mut p = if prefix.starts_with('/') {
        prefix.to_string()
    } else {
        format!("/{prefix}")
    };
    if !p.ends_with('/') {
        p.push('/');
    }
    Some(p)
}

fn xf_capsule_config(args: &XfCapsuleArgs, page_cache_enabled: bool) -> state::XfCapsuleConfig {
    if !args.capsule_enabled || !page_cache_enabled {
        return state::XfCapsuleConfig::disabled();
    }
    let vhosts = split_csv(&args.vhosts)
        .into_iter()
        .map(|v| v.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let path_prefixes = split_csv(&args.paths)
        .into_iter()
        .filter_map(normalize_capsule_prefix)
        .collect::<Vec<_>>();
    state::XfCapsuleConfig {
        enabled: true,
        vhosts,
        path_prefixes,
        safe_get_mode: match args.safe_get_mode {
            XfCapsuleSafeGetCliMode::Prefixes => XfCapsuleSafeGetMode::Prefixes,
            XfCapsuleSafeGetCliMode::AllGetClassified => XfCapsuleSafeGetMode::AllGetClassified,
        },
        stale_secs: args.stale_secs,
        canary_percent: args.canary_percent.min(100),
        allow_members: args.allow_members,
        member_canary_percent: args.member_canary_percent.min(100),
    }
}

fn main() -> anyhow::Result<()> {
    // Dev smoke / validation hooks for the pure-io_uring substrate (env-gated; never affect
    // the normal serve path). Each boots a minimal monoio server and blocks.
    if let Ok(addr) = std::env::var("HJ_URING_SMOKE") {
        tracing_subscriber::fmt()
            .with_env_filter(default_env_filter())
            .init();
        let addr: std::net::SocketAddr = addr.parse()?;
        uring::serve_smoke(addr, 2)?;
        return Ok(());
    }
    // H1 over io_uring serving the REAL pipeline (bridge → pipeline::handle).
    if let Ok(addr) = std::env::var("HJ_URING_SERVE") {
        tracing_subscriber::fmt()
            .with_env_filter(default_env_filter())
            .init();
        let addr: std::net::SocketAddr = addr.parse()?;
        let root = std::env::var("HJ_ROOT").unwrap_or_else(|_| "/usr/local/lsws".to_string());
        uring::serve_uring(std::path::Path::new(&root), addr, 2)?;
        return Ok(());
    }
    // H3 over monoio io_uring via the quinn-proto driver.
    if let Ok(addr) = std::env::var("HJ_URING_H3_SMOKE") {
        tracing_subscriber::fmt()
            .with_env_filter(default_env_filter())
            .init();
        let addr: std::net::SocketAddr = addr.parse()?;
        let cfg = uring::h3::self_signed_config()?;
        uring::h3::serve_h3_smoke(addr, 2, cfg)?;
        return Ok(());
    }
    // H2 (h2c) over monoio io_uring via hj-h2's serve_local.
    if let Ok(addr) = std::env::var("HJ_URING_H2_SMOKE") {
        tracing_subscriber::fmt()
            .with_env_filter(default_env_filter())
            .init();
        let addr: std::net::SocketAddr = addr.parse()?;
        uring::serve_h2_smoke(addr, 2)?;
        return Ok(());
    }
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Check { strict: false }) {
        Command::Check { strict } => {
            // One-shot config dump: plain stdout logging is enough.
            tracing_subscriber::fmt()
                .with_env_filter(default_env_filter())
                .init();
            check(&cli.root, strict)
        }
        // `serve` installs its own layered subscriber (stdout + persistent error
        // log) inside the runtime — see `init_logging`.
        Command::Serve(args) => serve(&cli.root, args),
        Command::Lsphp(args) => lsphp(&cli.root, args),
        Command::LsphpReload(args) => lsphp_reload(args),
    }
}

/// The tracing env-filter: `RUST_LOG` if set, else `info`.
fn default_env_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
}

/// Handle for the SIGUSR2 runtime log-level toggle (the reloadable `EnvFilter`).
type LogReloadHandle =
    tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>;

/// Install the global tracing subscriber for `serve`: a reloadable `EnvFilter`
/// gate, the stdout `fmt` layer (→ systemd prod log), and an [`hj_log::ErrorLogLayer`]
/// persisting WARN+ events to a rolling `logs/httpjet_error.log` so faults survive
/// journal rotation. Also installs a panic hook. MUST be called within a tokio
/// runtime context (the error logger spawns a writer task). Returns the reload
/// handle (SIGUSR2) and the error logger (SIGUSR1 reopen).
fn init_logging(root: &std::path::Path) -> (LogReloadHandle, hj_log::ErrorLogger) {
    use tracing_subscriber::prelude::*;
    let (filter_layer, reload_handle) =
        tracing_subscriber::reload::Layer::new(default_env_filter());
    // keep_days=30 (unlike access/php-slow at 7): errors are low-volume but
    // high-value — postmortems reach back weeks, so they get the deeper window.
    let err_logger = hj_log::ErrorLogger::spawn(
        root.join("logs/httpjet_error.log"),
        20 * 1024 * 1024,
        30,
        true,
    );
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .with(hj_log::ErrorLogLayer::new(err_logger.clone()))
        .init();
    install_panic_hook();
    (reload_handle, err_logger)
}

/// Route panics into `tracing::error!(target:"panic", …)` (→ the structured error
/// log) *in addition to* the default hook (backtrace to stderr → systemd prod log).
/// Without this, a panicking spawned task vanishes with no structured record.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        tracing::error!(target: "panic", location = %location, "panic: {msg}");
        default(info);
    }));
}

/// Split a comma-separated CLI list into trimmed, non-empty entries.
fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Load + prepare a page-cache dict from `path`; `role` (a vhost name, or "fallback") is only for
/// the log line. `None` on a missing/unreadable/empty file — logged, never fatal.
fn load_page_dict(path: &str, role: &str) -> Option<Arc<hj_compress::PageDict>> {
    match std::fs::read(path) {
        Ok(bytes) => match hj_compress::PageDict::new(bytes, hj_compress::DEFAULT_DICT_LEVEL) {
            Some(d) => {
                tracing::info!(path = %path, role = %role, dict_bytes = d.raw_len(), generation = d.generation(), "page-cache dedup dictionary loaded");
                Some(Arc::new(d))
            }
            None => {
                tracing::warn!(path = %path, role = %role, "page-cache dict file is empty; dedup disabled for this entry");
                None
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, path = %path, role = %role, "page-cache dict unreadable; dedup disabled for this entry");
            None
        }
    }
}

/// httpjet's OWN persistent file-tier root when the operator explicitly asks for
/// the default file store. Deliberately NOT LiteSpeed's `cacheStorePath`
/// (`/dev/shm/lscache`): sharing that directory risks colliding with a resurrected
/// LiteSpeed, and httpjet's boot scan unlinks foreign `.tmp` and unparseable
/// `.pc` files it finds anywhere under its root.
const DEFAULT_PAGE_CACHE_STORE_PATH: &str = "/dev/shm/jetcache";
const PAGE_CACHE_MAX_OBJECT_BYTES: u64 = 100 * 1024 * 1024;
pub(crate) const RUNTIME_THREAD_STACK_BYTES: usize = 2 * 1024 * 1024;

/// Resolve the file-tier root from the CLI value. Empty/`none`/`off`/`ram` keep the
/// page cache RAM-only; `default`/`jetcache` select httpjet's own tmpfs root; any
/// other value is taken verbatim. The LiteSpeed config's `cacheStorePath` is
/// intentionally NOT consulted.
fn resolve_page_cache_store_path(cli: &str) -> Option<std::path::PathBuf> {
    match cli.trim() {
        "" | "none" | "off" | "ram" => None,
        "default" | "jetcache" => Some(std::path::PathBuf::from(DEFAULT_PAGE_CACHE_STORE_PATH)),
        p => Some(std::path::PathBuf::from(p)),
    }
}

fn serve(root: &std::path::Path, args: ServeArgs) -> anyhow::Result<()> {
    let workers = args
        .workers
        .or_else(|| std::thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(4)
        .max(1);
    // (#235) tokio panics on worker_threads(0); an explicit --workers 0 used to take
    // the whole process down at startup. Clamp to 1 and tell the operator.
    if args.workers == Some(0) {
        eprintln!("--workers 0 is invalid; running with 1 worker");
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_stack_size(RUNTIME_THREAD_STACK_BYTES)
        .on_thread_park(memtrim::collect_if_requested_on_thread)
        .on_thread_stop(memtrim::force_collect)
        .enable_all()
        .build()?;

    // Initialize logging FIRST: inside the runtime context (the persistent error
    // logger spawns a writer task) and BEFORE config load, so startup warnings are
    // captured. The `enter` guard is scoped and dropped before `block_on`.
    let (reload_handle, err_logger) = {
        let _enter = rt.enter();
        init_logging(root)
    };

    let mut cfg = hj_config::load(root)?;

    // Local-test override: relax the mandatory client-cert check so TLS can be
    // tested locally without a Cloudflare-issued client cert.
    apply_no_mtls(&mut cfg, args.no_mtls);
    if args.no_mtls {
        tracing::warn!(
            "--no-mtls: client-cert verification DISABLED (local testing / explicit rollback only)"
        );
    }
    let server = Arc::new(cfg);

    let http_listener_name: Arc<str> = server
        .listeners
        .iter()
        .find(|l| !l.secure)
        .or_else(|| server.listeners.first())
        .map(|l| l.name.clone())
        .unwrap_or_else(|| "Default".to_string())
        .into();

    // The secure listener (if any) drives the TLS config + routing under :443.
    let secure_listener = server.listeners.iter().find(|l| l.secure).cloned();

    let https_addr: Option<SocketAddr> = match args.https_addr.trim() {
        "" => None,
        s => Some(
            s.parse()
                .map_err(|e| anyhow::anyhow!("invalid --https-addr {s:?}: {e}"))?,
        ),
    };

    // Build the unified rustls config up front (surfaces cert errors before bind).
    // (OPS9) The `_reloadable` variants also return a CertReloadHandle: the cert
    // material lives behind an ArcSwap inside the (fixed) ServerConfig, so SIGHUP
    // can re-read renewed cert files and swap them in without a restart.
    hj_tls::install_crypto_provider()?;
    let want_ktls = args.ktls && cfg!(feature = "ktls");
    let (tls_config, tls_cert_handle) = match (&secure_listener, https_addr) {
        (Some(l), Some(_)) => {
            let (cfg, handle) = hj_tls::build_server_config_reloadable(&server, l)?;
            (Some(cfg), Some(handle))
        }
        _ => (None, None),
    };
    // kTLS (staged, io_uring only) needs a per-connection KeyLog to recover the TLS 1.3
    // traffic secrets for a KeyUpdate rekey — built from a shared config TEMPLATE so each
    // connection cheaply gets its own config+KeyLog. Built only when `--ktls` is active in a
    // `--features ktls` build; otherwise `None` (the userspace TLS path is used).
    let (ktls_template, ktls_cert_handle): (
        Option<std::sync::Arc<hj_tls::KtlsConfigTemplate>>,
        Option<hj_tls::CertReloadHandle>,
    ) = match (&secure_listener, https_addr) {
        (Some(l), Some(_)) if want_ktls => {
            let (template, handle) = hj_tls::build_ktls_template(&server, l)?;
            (Some(std::sync::Arc::new(template)), Some(handle))
        }
        _ => (None, None),
    };
    let _ = &ktls_template; // consumed only on the io_uring TLS path
    // HTTP/3 (QUIC) config: same SNI resolver + Cloudflare mTLS verifier, ALPN h3.
    // Raw h3-ALPN rustls config captured for the io_uring H3 path (it builds its own
    // quinn-proto ServerConfig); `None` unless the uring H3 driver is requested. `rustls`
    // is a uring-only optional dep, so this binding only exists in a uring build.
    // Raw h3-ALPN rustls config for the io_uring H3 driver (it builds its own quinn-proto
    // ServerConfig). `quic_cert_handle` is the reloadable cert handle registered for SIGHUP.
    let mut h3_rustls_cfg: Option<std::sync::Arc<rustls::ServerConfig>> = None;
    let quic_cert_handle = match (&secure_listener, https_addr) {
        (Some(l), Some(_)) if server.quic_enable => {
            let (h3_tls, handle) =
                hj_tls::build_server_config_alpn_reloadable(&server, l, vec![b"h3".to_vec()])?;
            h3_rustls_cfg = Some(h3_tls);
            Some(handle)
        }
        _ => None,
    };
    let alt_svc = https_addr
        .filter(|_| h3_rustls_cfg.is_some())
        .map(|a| format!("h3=\":{}\"; ma=86400", a.port()));

    let php_socket = args.php_socket.clone();
    let php_children = args.php_children;
    let no_php = args.no_php;
    let lsphp_external = args.lsphp_external.clone();
    let metrics_addr = args.metrics_addr.trim().to_string();
    let profile_token = {
        let t = args.profile_token.trim();
        (!t.is_empty()).then(|| t.to_string())
    };

    rt.block_on(async move {
        // Build the per-vhost lsphp pool REGISTRY. With suEXEC off (the default)
        // it holds exactly ONE pool (the canonical "php" key) on the existing
        // separate socket, the server user/group, no chroot — byte-for-byte
        // today's single-pool behavior. The registry lazily starts additional
        // jailed pools on demand only when suEXEC is on + we are root + a vhost
        // resolves to distinct credentials. Each pool owns its own
        // {supervisor, pool, monitor, handler} quartet (the wiring main.rs used to
        // build by hand). We eagerly start the default "php" pool so the hot path
        // is a pure map lookup.
        let php_registry: Option<Arc<hj_lsapi::LsapiRegistry>> = match (&server.php_config, no_php) {
            (Some(php), false) => {
                // External lsphp (--lsphp-external) overrides the spawn socket; we
                // then build a CLIENT-ONLY registry below (no spawn/supervise).
                let lsphp_sock = lsphp_external.as_deref().unwrap_or(php_socket.as_path());
                let mut sup_cfg = hj_lsapi::SupervisorConfig::from_php_config(
                    php,
                    lsphp_sock,
                    &server.user,
                    &server.group,
                );
                // Honor the lsws config's child count by default (from_php_config
                // read it from PHP_LSAPI_CHILDREN / maxConns); --php-children > 0
                // is an explicit operator override.
                if php_children > 0 {
                    sup_cfg.children = php_children;
                }
                sup_cfg.normalize();
                // The supervisor sets LSAPI_CHILDREN/PHP_LSAPI_CHILDREN
                // authoritatively from sup_cfg.children, so drop the raw env
                // duplicates to keep a single source of truth.
                sup_cfg
                    .env
                    .retain(|(k, _)| k != "PHP_LSAPI_CHILDREN" && k != "LSAPI_CHILDREN");
                let effective_php_children = sup_cfg.children;

                // Idle TTL for pooled keep-alive sockets = PC keep-alive.
                let idle_ttl = if php.pc_keep_alive_timeout.is_zero() {
                    std::time::Duration::from_secs(30)
                } else {
                    php.pc_keep_alive_timeout
                };

                // 0 means "no limit" — matching the LiteSpeed XML `maxProcessTime` convention
                // (hj-config maps 0/absent/garbage to None) — NOT an instant Duration::ZERO
                // deadline that 504s every request (#136). An EXPLICIT 0 overrides the XML value
                // (the operator chose no limit); only an ABSENT flag falls back to the XML.
                let max_process_time = match args.php_max_process_time_ms {
                    Some(0) => None,
                    Some(ms) => Some(Duration::from_millis(ms)),
                    None => php.max_process_time,
                };
                // The Tier-2 kill (monitor-driven worker SIGKILL + restart) only exists in
                // OWNED/spawn mode: external mode has no monitor in this process, so a wedged
                // worker producing no output is never reclaimed here. Warn so the operator knows
                // the flag gives Tier-1 (504) only under --lsphp-external (#138).
                if max_process_time.is_some() && lsphp_external.is_some() {
                    tracing::warn!(
                        "--php-max-process-time-ms with --lsphp-external enforces only the Tier-1 \
                         504 deadline in this process; the Tier-2 hung-worker kill/restart lives in \
                         the separate `httpjet lsphp` pool and does not fire for wedged workers"
                    );
                }

                let registry = if lsphp_external.is_some() {
                    let registry = hj_lsapi::LsapiRegistry::new_external(
                        sup_cfg,
                        idle_ttl,
                        max_process_time,
                        server.tuning.max_req_body_size,
                    );
                    if let Some(path) = args.lsphp_generation_file.as_deref()
                        && !registry.set_external_generation_file(path)
                    {
                        return Err(anyhow::anyhow!(
                            "explicit external lsphp generation file {} is unavailable or malformed",
                            path.display()
                        ));
                    }
                    registry
                } else {
                    hj_lsapi::LsapiRegistry::new(
                        sup_cfg,
                        idle_ttl,
                        max_process_time,
                        server.tuning.max_req_body_size,
                    )
                };
                // Eagerly resolve the default "php" pool. When spawning, this
                // starts lsphp (a failure disables PHP → static fallback). In
                // external mode it just wires the client pool (no connect yet — the
                // first request dials), so it cannot fail here.
                match registry.start_default().await {
                    Ok(_) => {
                        if lsphp_external.is_some() {
                            tracing::info!(socket = %lsphp_sock.display(), "lsphp EXTERNAL pool wired (client-only; master owned by httpjet-lsphp)");
                        } else {
                            tracing::info!(socket = %php_socket.display(), children = effective_php_children, "lsphp default pool started (registry up)");
                        }
                        Some(registry)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "lsphp failed to start; PHP disabled (static fallback)");
                        None
                    }
                }
            }
            _ => None,
        };

        // (dedup) Load the per-vhost zstd dictionaries (+ optional global fallback) if configured +
        // the cache is on. A missing/unreadable/empty file logs a warning and disables dedup for
        // that entry (bodies stored as identity) — never fatal. Held behind an Arc on ServerState.
        // Loaded BEFORE the store is built: the store's boot scan needs the dict GENERATIONS to
        // keep persisted dict-compressed bodies.
        let page_cache_dicts: Arc<hj_compress::PageDictRegistry> = if args.page_cache.enabled {
            let fallback = if !args.page_cache.dict.trim().is_empty() {
                load_page_dict(args.page_cache.dict.trim(), "fallback")
            } else {
                None
            };
            let mut by_vhost = HashMap::new();
            for entry in split_csv(&args.page_cache.dict_vhost) {
                match entry.split_once('=') {
                    Some((vhost, path)) if !vhost.trim().is_empty() && !path.trim().is_empty() => {
                        let vhost = vhost.trim().to_ascii_lowercase();
                        if let Some(d) = load_page_dict(path.trim(), &vhost) {
                            by_vhost.insert(vhost, d);
                        }
                    }
                    _ => tracing::warn!(entry = %entry, "page-cache-dict-vhost entry malformed (expected vhost=path); skipping"),
                }
            }
            Arc::new(hj_compress::PageDictRegistry::new(by_vhost, fallback))
        } else {
            Arc::new(hj_compress::PageDictRegistry::empty())
        };

        // (shared-paths) Parsed unconditionally so a malformed spec aborts startup even
        // when --page-cache is off (a typo must fail the deploy, not silently disable
        // the allowlist on the next flag flip).
        let shared_public_paths = hj_pagecache::parse_shared_paths(&args.page_cache.shared_paths)
            .map_err(|e| anyhow::anyhow!("--page-cache-shared-paths: {e}"))?;

        // Origin full-page cache (LSCache equivalent). Built only when the
        // operator passes --page-cache; otherwise `None` and the pipeline pays a
        // single always-false branch. Limits come from the server `<cache>` block.
        let page_cache = if args.page_cache.enabled {
            let cc = &server.cache;
            let store_path = resolve_page_cache_store_path(&args.page_cache.store_path);
            // (security #260) Integrity key for persisted HJPC containers: a same-uid
            // writer (compromised lsphp) can no longer forge/relocate entries that the
            // boot scan adopts. Best-effort — if /run/httpjet is unusable we log loudly
            // and run untagged rather than refuse to serve.
            if store_path.is_some() {
                // Persistent, pre-provisioned (root:0400 nobody) so the tag survives
                // reboots; uid nobody must read it to tag writes. Same-uid lsphp can
                // read it too — an accepted residual documented in issue #260 (the
                // full fix is a dedicated PHP uid).
                if let Err(e) = hj_pagecache::diskstore::init_integrity_key(
                    &PathBuf::from("/usr/local/httpjet/conf/.jetcache.key"),
                ) {
                    tracing::warn!(error = %e, "jetcache integrity key unavailable; persisted containers run WITHOUT integrity tags");
                }
            }
            let static_caps = hj_cache::CacheCaps::from_tuning(&server.tuning);
            let store_cfg = hj_pagecache::StoreConfig {
                max_mem_bytes: args.page_cache.mem,
                max_disk_bytes: args.page_cache.disk_mem,
                store_path: store_path.clone(),
                hot_mem_bytes: args.page_cache.hot_mem,
                expected_dict_gens: page_cache_dicts.all_generations(),
                max_obj_bytes: PAGE_CACHE_MAX_OBJECT_BYTES,
                max_static_obj_bytes: static_caps.max_mmap_file,
                default_public_ttl: std::time::Duration::from_secs(cc.default_ttl_secs as u64),
                default_private_ttl: std::time::Duration::from_secs(
                    cc.default_private_ttl_secs as u64,
                ),
                cacheable_status: cc.cacheable_status.clone(),
                cache_post: cc.enable_post_cache,
                vary_cookies: split_csv(&args.page_cache.vary_cookies),
                private_cookies: split_csv(&args.page_cache.private_cookies),
                standard_cc_vhosts: split_csv(&args.page_cache.standard_vhosts),
                default_stale_secs: args.page_cache.stale_default_secs,
                default_sie_secs: args.page_cache.stale_if_error_default_secs,
                max_stale_secs: args.page_cache.stale_max_secs,
                max_stale_if_error_secs: args.page_cache.stale_if_error_max_secs,
                private_enabled: args.page_cache.private_enabled,
                private_session_cookie: args.page_cache.private_session_cookie.trim().to_string(),
                private_user_cookie: args.page_cache.private_user_cookie.trim().to_string(),
                shared_public_paths: shared_public_paths.clone(),
                shared_paths_canary_percent: args.page_cache.shared_paths_canary_percent.min(100),
            };
            tracing::info!(
                mem_bytes = args.page_cache.mem,
                default_ttl_secs = cc.default_ttl_secs,
                vary_cookies = %args.page_cache.vary_cookies,
                "origin page cache ENABLED (--page-cache)"
            );
            if let Some(p) = &store_path {
                tracing::info!(
                    path = %p.display(),
                    hot_mem_bytes = args.page_cache.hot_mem,
                    disk_mem_bytes = args.page_cache.disk_mem,
                    "PERSISTENT tmpfs file tier ENABLED (--page-cache-store-path)"
                );
            }
            if args.page_cache.private_enabled {
                tracing::info!(
                    session_cookie = %args.page_cache.private_session_cookie,
                    user_cookie = %args.page_cache.private_user_cookie,
                    default_ttl_secs = cc.default_private_ttl_secs,
                    "per-session PRIVATE cache tier ENABLED (--page-cache-private)"
                );
            }
            if !shared_public_paths.is_empty() {
                tracing::info!(
                    matchers = ?shared_public_paths,
                    canary_percent = args.page_cache.shared_paths_canary_percent.min(100),
                    "member shared-path PUBLIC routing ENABLED (--page-cache-shared-paths)"
                );
            }
            Some(Arc::new(hj_pagecache::PageStore::new(store_cfg)))
        } else {
            None
        };

        // (OPS3) Cross-node purge coherence — built only alongside the page cache,
        // and only when at least one peer is given. Inbound purges are authenticated
        // purely by the private/LAN source-IP gate (no shared secret).
        let peer_purge = page_cache.is_some().then(|| {
            let pp = peer_purge::PurgeForwarder::from_config(&args.cache_peer)
                .with_fill(
                    args.page_cache.cache_peer_fill,
                    args.page_cache.cache_peer_fill_timeout_ms,
                    args.page_cache.cache_peer_fill_negcache_secs,
                );
            if pp.peer_addrs().is_empty() {
                tracing::info!("page-cache purge endpoint enabled (loopback-only; no --cache-peer)");
            } else {
                tracing::info!(peers = ?pp.peer_addrs(), "cross-node page-cache purge coherence ENABLED");
            }
            pp
        });

        // (security) Install the mTLS-exempt peer allow-list BEFORE any listener
        // accepts. The origin-pull client-cert check exempts loopback (on-box
        // `/etc/hosts` fetches) + these explicit `--cache-peer` IPs (the active-active
        // sibling node) ONLY — narrowed from the old whole-RFC1918 exemption that let
        // any private-LAN host bypass Cloudflare AOP (audit 2026-06-19). Resolved
        // independently of `--page-cache` so the mTLS boundary is correct even with the
        // cache off.
        {
            let exempt: Vec<std::net::IpAddr> = args
                .cache_peer
                .iter()
                .filter_map(|p| p.to_socket_addrs().ok())
                .flatten()
                .map(|a| a.ip())
                .collect();
            if !exempt.is_empty() {
                tracing::info!(peers = ?exempt, "mTLS-exempt peer allow-list installed (loopback + --cache-peer)");
            }
            hj_core::set_exempt_peers(exempt);
        }

        // Honor the `CF_SEND_ZSTD` env var too (clap's `env` feature isn't enabled), so
        // either `--cf-send-zstd` or `CF_SEND_ZSTD=1` turns it on.
        let cf_send_zstd = args.cf_send_zstd
            || std::env::var("CF_SEND_ZSTD")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        // (attribution) Per-request PHP slow/sample log — spawned here (inside the
        // runtime) and carried across SIGHUP reloads via ServerState::reload.
        let php_slow = {
            let p = args.php_slow_log.trim();
            (!p.is_empty()).then(|| {
                tracing::info!(path = %p, threshold_ms = args.php_slow_threshold_ms, "php slow-request log ENABLED");
                phpslow::PhpSlowLog::spawn(p, args.php_slow_threshold_ms)
            })
        };
        let xf_capsule = xf_capsule_config(&args.xf_capsule, args.page_cache.enabled);
        if args.xf_capsule.capsule_enabled && !args.page_cache.enabled {
            tracing::warn!("xf-capsule requested without --page-cache; capsule tier disabled");
        } else if xf_capsule.enabled {
            tracing::info!(
                vhosts = ?xf_capsule.vhosts,
                paths = ?xf_capsule.path_prefixes,
                canary_percent = xf_capsule.canary_percent,
                allow_members = xf_capsule.allow_members,
                member_canary_percent = xf_capsule.member_canary_percent,
                safe_get_mode = ?xf_capsule.safe_get_mode,
                stale_secs = xf_capsule.stale_secs,
                "XenForo hot capsule tier ENABLED (--xf-capsule)"
            );
            // (#96/#239) Surface the silent-footgun configs: since the closed-default
            // fix, an empty vhost set DISABLES the capsule tier entirely — warn so an
            // operator who expected it on understands why nothing is served. Also:
            // allow_members with a 0% member canary looks enabled but serves no
            // members at all.
            if xf_capsule.vhosts.is_empty() {
                tracing::warn!(
                    "xf-capsule: --xf-capsule-vhosts is empty — the capsule tier is DISABLED for every vhost; pass an explicit list (e.g. windowsforum.com) to enable it"
                );
            }
            if xf_capsule.allow_members && xf_capsule.member_canary_percent == 0 {
                tracing::warn!(
                    "xf-capsule: --xf-capsule-members is set but --xf-capsule-member-canary-percent is 0 — NO members will be served capsules (set a non-zero member canary to ramp)"
                );
            }
        }
        let rewrite_tuning = crate::state::RewriteTuning {
            outcome_ttl: std::time::Duration::from_millis(args.rewrite_outcome_ttl_ms),
            ua_classify: args.rewrite_ua_classify,
        };
        if args.rewrite_outcome_ttl_ms == 0 {
            tracing::info!("rewrite-outcome cache DISABLED (--rewrite-outcome-ttl-ms 0)");
        } else if args.rewrite_outcome_ttl_ms != 1000 || args.rewrite_ua_classify {
            tracing::info!(
                ttl_ms = args.rewrite_outcome_ttl_ms,
                ua_classify = args.rewrite_ua_classify,
                "rewrite-outcome cache tuning"
            );
        }
        let state = ServerState::new(server, php_registry.clone(), alt_svc, page_cache, page_cache_dicts, args.page_cache.admit_threshold, xf_capsule, peer_purge, cf_send_zstd, php_slow, args.request_id_header, rewrite_tuning);
        // (persist) Rebuild the page-cache index from the tmpfs file tier in the
        // background — the server serves from request #1, with not-yet-scanned keys
        // simply missing during the ~seconds-long walk. Each kept key pre-warms the
        // W-TinyLFU admission sketch so a post-restart refresh of a warm entry isn't
        // rejected by an empty-sketch frequency bar.
        if let Some(pc) = state.page_cache.as_ref().filter(|pc| pc.has_disk()) {
            let pc = pc.clone();
            let admission = state.page_cache_admission.clone();
            tokio::task::spawn_blocking(move || {
                let sum = pc.load_from_disk(|key| admission.record(lscache::hash_key(key)));
                if sum.loaded > 0 {
                    memtrim::force_collect_logged("page-cache warm scan complete");
                }
            });
        }
        if let Some(pc) = state.page_cache.as_ref() {
            // 30 s maintenance tick (off the runtime — spawn_blocking, sync work). This runs in
            // RAM-only mode too: expiry-heap reclamation and bounded purge-epoch pruning are not
            // file-tier concerns, and otherwise a long-lived RAM-only process retains both forever.
            // `maintenance()` drains each shard's deadline min-heap (reclaiming past-deadline entries
            // through the one synchronous teardown funnel: file unlink + budget drop + tag GC),
            // evicts idle hot-tier bodies, and prunes the bounded tag_purge_epoch map. There is no
            // reconcile/orphan/missing-file reclaimer: the bespoke sharded store unlinks a superseded
            // tmpfs file SYNCHRONOUSLY under the owning shard lock on the calling thread, so a
            // fileless live entry (the old `entries ≫ .pc files` strand) is structurally
            // unrepresentable — `entries == .pc files` holds after every op, no settle required.
            let pc = pc.clone();
            let shutdown = state.shutdown.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                            let pc = pc.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                pc.maintenance(std::time::Duration::from_secs(90));
                                memtrim::collect_if_requested_on_thread();
                            }).await;
                        }
                        _ = shutdown.cancelled() => break,
                    }
                }
            });
        }
        // (OPS6) Hold the live config behind an ArcSwap so a SIGHUP reload can swap
        // it under the accept loops without disturbing in-flight connections. Keep
        // the gen-0 `state` Arc for the metrics endpoint + the drain loop (the
        // runtime half — counters, shutdown, caches, pools — is shared across
        // generations, so gen-0 reflects current totals after any reload).
        let holder: Arc<ArcSwap<ServerState>> = Arc::new(ArcSwap::from(state.clone()));

        // (OPS8) Adopt systemd socket-activation fds when present so a binary
        // deploy (`systemctl restart httpjet.service`) never closes the listen
        // sockets → zero backlog / new-connection RST at the origin. Absent
        // LISTEN_FDS (alt-port test instances, manual runs) we self-bind exactly
        // as before. Inherited fds are classified by the configured ports.
        let https_listen_port = https_addr.map(|a| a.port()).unwrap_or(443);
        // `inh_quic` is `mut` so the io_uring H3 path can `.take()` the inherited UDP
        // fds for the quinn-proto driver.
        let (inh_http, inh_https, mut inh_quic) =
            match server::listeners_from_env(args.http_addr.port(), https_listen_port)? {
                Some(i) => (Some(i.http), Some(i.https), Some(i.quic)),
                None => (None, None, None),
            };

        // The HTTP/TLS/H3 listeners are the pure-io_uring thread-per-core (monoio) transport,
        // which shares THIS runtime's full ServerState (via `holder`) through the cross-runtime
        // bridge, so behavior is identical at the pipeline layer. In prod systemd hands us the
        // socket-activation fds (bound as root, passed to this `nobody` process); alt-port /
        // manual runs self-bind one SO_REUSEPORT socket per worker inside `uring`.
        // kTLS (staged) runs on the io_uring TLS path of a `--features ktls` build.
        let use_ktls = args.ktls && want_ktls;
        if args.ktls && !use_ktls && !cfg!(feature = "ktls") {
            anyhow::bail!("--ktls requires a `--features ktls` build");
        }
        if use_ktls {
            tracing::warn!("kTLS ENABLED (staged): serving TLS 1.3 over kernel-TLS sockets on the io_uring path (TLS 1.2 falls back to userspace). Peer KeyUpdate is handled (RX rekey + reply). Validate before production.");
        }
        // Convert the inherited (tokio) HTTP listeners back to std for the monoio cores' from_std.
        let inh_http_std = inh_http
            .map(|v| v.into_iter().map(|l| l.into_std()).collect::<std::io::Result<Vec<_>>>())
            .transpose()?;
        let bridge_admission = uring::pipeline_admission(holder.clone());
        uring::spawn_uring_http(
            holder.clone(),
            http_listener_name.clone(),
            args.http_addr,
            workers,
            inh_http_std,
            bridge_admission.clone(),
        )?;
        tracing::info!(%args.http_addr, listener = %http_listener_name, workers, "plain HTTP up (io_uring thread-per-core transport)");
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        if let (Some(addr), Some(tls_config), Some(l)) =
            (https_addr, tls_config, secure_listener.as_ref())
        {
            let name: Arc<str> = l.name.clone().into();
            let mtls = if args.no_mtls { 0 } else { l.tls.as_ref().map(|t| t.client_verify).unwrap_or(0) };
            let inh_https_std = inh_https
                .map(|v| v.into_iter().map(|l| l.into_std()).collect::<std::io::Result<Vec<_>>>())
                .transpose()?;
            uring::spawn_uring_https(
                holder.clone(),
                name.clone(),
                addr,
                workers,
                tls_config,
                mtls == 2,
                ktls_template.clone(),
                inh_https_std,
                bridge_admission.clone(),
            )?;
            tracing::info!(%addr, listener = %name, client_verify = mtls, workers, ktls = use_ktls, "TLS up (io_uring thread-per-core transport; H1/H2 over rustls-on-monoio; mTLS required for external peers when client_verify=2, loopback/private-LAN exempt)");
        }

        // HTTP/3 (QUIC) on the same address (UDP) — io_uring quinn-proto driver → real pipeline.
        if let (Some(addr), Some(h3cfg), Some(l)) =
            (https_addr, h3_rustls_cfg.take(), secure_listener.as_ref())
        {
            let name: Arc<str> = l.name.clone().into();
            let mtls = if args.no_mtls { 0 } else { l.tls.as_ref().map(|t| t.client_verify).unwrap_or(0) };
            match uring::spawn_uring_h3(
                holder.clone(),
                name.clone(),
                addr,
                workers,
                h3cfg,
                mtls == 2,
                inh_quic.take(),
                bridge_admission.clone(),
            ) {
                Ok(()) => tracing::warn!(%addr, listener = %name, client_verify = mtls, "h3/QUIC up (io_uring quinn-proto driver → real pipeline; mTLS required for external peers when client_verify=2, loopback/private-LAN exempt)"),
                Err(e) => anyhow::bail!("failed to start io_uring h3 listener: {e}"),
            }
        }

        // (OPS1) Loopback metrics endpoint (default 127.0.0.1:9090; empty = off).
        if !metrics_addr.is_empty() {
            match metrics_addr.parse::<SocketAddr>() {
                Ok(addr) if !metrics::metrics_bind_allowed(&addr) => {
                    tracing::error!(
                        %addr,
                        "refusing non-loopback --metrics-addr: the metrics endpoint is an \
                         UNAUTHENTICATED control+diagnostic surface (cache-URL enumeration, \
                         process stats, /__alloc-count?reset, profiling /debug/pprof/profile) and is \
                         documented loopback-only — not binding it (use 127.0.0.1 or ::1)"
                    );
                }
                Ok(addr) => match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => {
                        handles.push(tokio::spawn(metrics::serve_metrics(
                            listener,
                            state.clone(),
                            profile_token.clone(),
                        )));
                        tracing::info!(%addr, "metrics endpoint up (Prometheus text)");
                    }
                    Err(e) => tracing::error!(error = %e, %addr, "failed to bind metrics endpoint"),
                },
                Err(e) => tracing::error!(error = %e, addr = %metrics_addr, "invalid --metrics-addr"),
            }
        }

        // (mem) Periodic mimalloc OS-trim: return retained/cold arena memory so it
        // does not accumulate as swapped-out dirty pages on a memory-pressured box.
        if args.mimalloc_trim_secs > 0 {
            memtrim::configure_connection_close_trim(
                args.mimalloc_trim_threshold_mib.saturating_mul(1024 * 1024),
            );
            handles.push(tokio::spawn(memtrim::run_trim(
                std::time::Duration::from_secs(args.mimalloc_trim_secs),
                args.mimalloc_trim_threshold_mib.saturating_mul(1024 * 1024),
                state.shutdown.clone(),
            )));
        } else {
            memtrim::disable_connection_close_trim();
        }

        // (telemetry) Periodic disk snapshot of the in-RAM aggregates (durability
        // across restarts + a self-contained time-series for the two-node A/B).
        if !args.telemetry_file.trim().is_empty() && args.telemetry_flush_secs > 0 {
            handles.push(tokio::spawn(telemetry::run_flush(
                state.telemetry.clone(),
                std::path::PathBuf::from(args.telemetry_file.trim()),
                std::time::Duration::from_secs(args.telemetry_flush_secs),
                state.shutdown.clone(),
            )));
        }

        tracing::info!(workers, vhosts = state.server.vhosts.len(), "httpjet serving. Ctrl-C to stop.");
        // Serve until SIGINT/SIGTERM (systemctl stop / kill). SIGUSR1 reopens the
        // logs (logrotate); SIGUSR2 toggles the log level at runtime — neither
        // exits, so the wait is a loop.
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigusr1 = signal(SignalKind::user_defined1()).expect("install SIGUSR1 handler");
        let mut sigusr2 = signal(SignalKind::user_defined2()).expect("install SIGUSR2 handler");
        let mut sighup = signal(SignalKind::hangup()).expect("install SIGHUP handler");
        let mut debug_on = false;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = sigterm.recv() => break,
                _ = sighup.recv() => {
                    // (OPS6) Hot-reload the config: re-parse the XML and atomically
                    // swap the live config generation. Connections + the page cache
                    // + the lsphp pool are untouched; new connections pick up the new
                    // config, in-flight ones finish on the one they started with.
                    // A parse error or a change that needs a restart (listener/TLS
                    // sockets, lsphp pool) is logged and the current config kept —
                    // the reload can never take the edge down.
                    tracing::info!("SIGHUP: reloading config");
                    match hj_config::load(root) {
                        Ok(mut cfg) => {
                            // Re-apply the same CLI overrides the boot config got, so
                            // the comparison + the swapped generation stay consistent
                            // with the already-built TLS acceptor (else --no-mtls would
                            // make every reload look like a TLS change and get rejected).
                            apply_no_mtls(&mut cfg, args.no_mtls);
                            let new_server = Arc::new(cfg);
                            let cur = holder.load_full();
                            if let Some(reason) = hard_config_change(&cur.server, &new_server) {
                                tracing::warn!(
                                    reason,
                                    "SIGHUP: change requires a restart — keeping current config (hot-reload covers vhost/rewrite/access/expires/tuning only)"
                                );
                            } else if let Some(vhosts) = reload_would_brick_vhosts(&cur.server, &new_server) {
                                // A per-vhost file that now fails to parse/read would regress a live
                                // host to a silent 404 (config==None passes hard_config_change since
                                // vhost content is the soft-reloadable half). Refuse the swap and
                                // keep the working config rather than brick the host on a bad reload.
                                tracing::error!(
                                    vhosts = %vhosts,
                                    "SIGHUP: reload would 404 mapped vhost(s) whose per-vhost config file failed to load — keeping current config"
                                );
                            } else {
                                // (OPS9) Live cert reload: re-read the (possibly
                                // renewed) cert files and swap them into the running
                                // resolver — new handshakes use the new certs, no
                                // restart. A load failure keeps the current certs.
                                // Done BEFORE new_server is consumed by reload().
                                if let Some(secure) = new_server.listeners.iter().find(|l| l.secure) {
                                    visit_present_named(
                                        [
                                            ("TLS", tls_cert_handle.as_ref()),
                                            ("kTLS", ktls_cert_handle.as_ref()),
                                            ("QUIC", quic_cert_handle.as_ref()),
                                        ],
                                        |kind, handle| {
                                            if let Err(e) = handle.reload(&new_server, secure) {
                                                tracing::error!(error = %e, kind, "SIGHUP: certificate reload failed; keeping current certs");
                                            }
                                        },
                                    );
                                }
                                // (audit) Be precise about what "certs" means: only the
                                // SNI/default SERVER certs are swapped. The client-cert
                                // verifier (CA trust store) is baked into the immutable
                                // rustls config at boot — a renewed/rotated origin-pull CA
                                // needs a restart, and the log must not claim otherwise.
                                let has_ca_listener = new_server.listeners.iter().any(|l| {
                                    l.tls.as_ref().is_some_and(|t| t.ca_cert_file.is_some())
                                });
                                if has_ca_listener {
                                    tracing::warn!(
                                        "SIGHUP: client-CA trust stores are BOOT-frozen; if an origin-pull CA changed, RESTART httpjet"
                                    );
                                }
                                holder.store(ServerState::reload(&cur, new_server));
                                bridge_admission.limit_changed();
                                tracing::info!("SIGHUP: config hot-reloaded (config + SNI server certs; client-CA stores boot-frozen; cache + lsphp + connections preserved)");
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "SIGHUP: config reload FAILED — keeping current config");
                        }
                    }
                }
                _ = sigusr1.recv() => {
                    // (OPS4) logrotate moved/renamed the files: reopen by inode so we
                    // stop writing to the rotated-away descriptors. Non-blocking.
                    tracing::info!("SIGUSR1: reopening access + error logs");
                    if let Some(log) = &state.access_log {
                        log.reopen();
                    }
                    // (#248) Per-vhost access + error writers rotate with everything else.
                    for v in state.vhost_access_logs.values() {
                        v.logger.reopen();
                    }
                    for e in state.vhost_error_logs.values() {
                        e.reopen();
                    }
                    if let Some(sl) = &state.php_slow {
                        sl.reopen();
                    }
                    err_logger.reopen();
                }
                _ = sigusr2.recv() => {
                    // (OPS5) Toggle httpjet's log level at runtime — turn up verbosity
                    // on a live issue without a restart. The error file stays warn+
                    // regardless (the ErrorLogLayer gates on level independently).
                    debug_on = !debug_on;
                    let directive = if debug_on { "httpjet=debug" } else { "httpjet=info" };
                    match reload_handle.reload(tracing_subscriber::EnvFilter::new(directive)) {
                        Ok(()) => tracing::info!(level = directive, "SIGUSR2: log level toggled"),
                        Err(e) => tracing::error!(error = %e, "SIGUSR2: log-level reload failed"),
                    }
                }
            }
        }
        // (OPS2) Graceful drain. Cancel the shared shutdown token: the accept loops
        // stop taking new connections, and every live connection's serve loop calls
        // hyper's `graceful_shutdown` — finishing its in-flight request/response
        // (including a streaming body) then closing, and closing idle keep-alives
        // promptly (GOAWAY / Connection: close). We then wait for `active_conns` to
        // reach zero so nothing is killed mid-response on a deploy/monit restart.
        // The budget stays under the unit's TimeoutStopSec=20 (leaving headroom for
        // the lsphp drain below) so systemd never SIGKILLs us mid-drain; an
        // unbounded stream (SSE/long-poll) that never ends is cut at the budget.
        tracing::info!("shutdown signal received; draining connections");
        state.shutdown.cancel();
        let drain_budget = std::time::Duration::from_secs(12);
        let drain_start = std::time::Instant::now();
        loop {
            let open = state.metrics.active_conns.load(std::sync::atomic::Ordering::Relaxed);
            if open == 0 {
                break;
            }
            if drain_start.elapsed() >= drain_budget {
                tracing::warn!(open_conns = open, "drain budget exceeded; stopping with connections still open");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        tracing::info!(
            drained_ms = drain_start.elapsed().as_millis() as u64,
            "connections drained; stopping"
        );
        if !args.telemetry_file.trim().is_empty() && args.telemetry_flush_secs > 0 {
            telemetry::flush_once(
                &state.telemetry,
                std::path::Path::new(args.telemetry_file.trim()),
            )
            .await;
        }
        for h in handles {
            h.abort();
        }
        // Drain every started lsphp pool. drain_all preserves the Phase-3
        // cancel-before-drain semantics per pool: it cancels each monitor ticker
        // (so the monitor does not fight the intentional stop with a restart),
        // bounds the ticker stop, then gracefully drains the supervisor. The
        // supervisor's own Drop is the final backstop for any child.
        if let Some(registry) = &php_registry {
            registry.drain_all().await?;
            tracing::info!("lsphp pools drained");
        }
        Ok::<_, anyhow::Error>(())
    })
}

/// Detect systemd socket activation for the standalone lsphp pool. If
/// `httpjet-lsphp.socket` handed us a `ListenStream` fd, adopt it so the lsphp
/// master accepts on the PERSISTENT (systemd-owned) socket — which survives a
/// restart of `httpjet-lsphp.service`, so the web tier never sees ECONNREFUSED
/// during a restart. Returns `Ok(None)` when not socket-activated (the self-bind
/// fallback for alt-port / manual runs). Mirrors [`server::listeners_from_env`].
fn lsphp_listen_fd_from_env() -> std::io::Result<Option<std::os::fd::OwnedFd>> {
    use std::os::fd::FromRawFd;
    let pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let n = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|s| s.parse::<i32>().ok());
    let (Some(pid), Some(n)) = (pid, n) else {
        return Ok(None);
    };
    // This is consumed once, and the spawned lsphp master uses `env_clear`, so retaining
    // LISTEN_* avoids unsafe process-global environment mutation in Rust 2024.
    if pid != std::process::id() {
        return Ok(None);
    }
    if n != 1 {
        return Err(std::io::Error::other(format!(
            "httpjet-lsphp.socket must pass exactly ONE ListenStream fd, got {n}"
        )));
    }
    // systemd passes activation fds starting at fd 3 (SD_LISTEN_FDS_START).
    // SAFETY: systemd handed us fd 3; we take sole ownership for the process lifetime.
    let sock = unsafe { socket2::Socket::from_raw_fd(3) };
    server::set_cloexec(&sock)?;
    let domain = sock.domain()?;
    let ty = sock.r#type()?;
    if domain != socket2::Domain::UNIX || ty != socket2::Type::STREAM {
        return Err(std::io::Error::other(
            "socket-activation fd 3 is not an AF_UNIX stream socket",
        ));
    }
    Ok(Some(std::os::fd::OwnedFd::from(sock)))
}

/// Default per-pool state path: `<php-socket>.<suffix>`. Keeping the derived
/// defaults beside the pool's own LSAPI socket means an R&D `httpjet lsphp`
/// that overrides only --php-socket can neither fail on the root-owned
/// /run/httpjet directory nor write the production generation/control state.
fn lsphp_sibling_path(socket: &std::path::Path, suffix: &str) -> PathBuf {
    let mut path = socket.as_os_str().to_os_string();
    path.push(".");
    path.push(suffix);
    PathBuf::from(path)
}

struct ControlSocketGuard(PathBuf);

impl Drop for ControlSocketGuard {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.0).is_ok_and(|meta| meta.file_type().is_socket()) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

fn bind_lsphp_control(
    path: &std::path::Path,
) -> std::io::Result<(tokio::net::UnixListener, ControlSocketGuard)> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("lsphp control socket {} is already active", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to replace non-socket control path {}",
                    path.display()
                ),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok((listener, ControlSocketGuard(path.to_path_buf())))
}

fn systemd_notify(message: &str) -> std::io::Result<()> {
    let Some(socket_name) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    send_systemd_notify(socket_name.as_os_str(), message)
}

fn send_systemd_notify(socket_name: &OsStr, message: &str) -> std::io::Result<()> {
    let name = socket_name.as_bytes();
    if name.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is empty",
        ));
    }

    let raw_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_capacity = address.sun_path.len();
    let address_len = if name[0] == b'@' {
        if name.len() > path_capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "abstract NOTIFY_SOCKET name is too long",
            ));
        }
        for (dst, src) in address.sun_path[1..].iter_mut().zip(&name[1..]) {
            *dst = *src as libc::c_char;
        }
        std::mem::offset_of!(libc::sockaddr_un, sun_path) + name.len()
    } else {
        if name.len() >= path_capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NOTIFY_SOCKET path is too long",
            ));
        }
        for (dst, src) in address.sun_path.iter_mut().zip(name) {
            *dst = *src as libc::c_char;
        }
        std::mem::offset_of!(libc::sockaddr_un, sun_path) + name.len() + 1
    };
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            message.as_ptr().cast(),
            message.len(),
            libc::MSG_NOSIGNAL,
            (&raw const address).cast(),
            address_len as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if sent as usize != message.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "short write to NOTIFY_SOCKET",
        ));
    }
    Ok(())
}

async fn write_control_response(stream: &mut tokio::net::UnixStream, response: &str) {
    use tokio::io::AsyncWriteExt;
    if let Err(e) = stream.write_all(response.as_bytes()).await {
        tracing::warn!(error = %e, "failed to write lsphp control response");
    }
}

async fn run_lsphp_control(
    listener: tokio::net::UnixListener,
    _guard: ControlSocketGuard,
    registry: Arc<hj_lsapi::LsapiRegistry>,
    publisher: Arc<hj_lsapi::ExternalGenerationWriter>,
    shutdown: tokio_util::sync::CancellationToken,
) -> std::io::Result<()> {
    use tokio::io::AsyncBufReadExt;

    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        // Accept/credential errors here are per-connection (ECONNABORTED,
        // EMFILE) — never a reason to tear down the whole PHP pool. The brief
        // sleep keeps a persistently failing listener from spinning hot.
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "transient lsphp control accept failure");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let credentials = match stream.peer_cred() {
            Ok(credentials) => credentials,
            Err(error) => {
                tracing::warn!(%error, "could not read lsphp control peer credentials");
                continue;
            }
        };
        if credentials.uid() != 0 {
            let mut stream = stream;
            write_control_response(&mut stream, "ERR root credentials required\n").await;
            continue;
        }

        let mut reader = tokio::io::BufReader::new(stream);
        let mut command = String::new();
        match tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut command)).await {
            Ok(Ok(0)) => continue,
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "failed to read lsphp control request");
                continue;
            }
            Err(_) => {
                let mut stream = reader.into_inner();
                write_control_response(&mut stream, "ERR control request timed out\n").await;
                continue;
            }
        }
        let mut stream = reader.into_inner();
        if command.trim() != "reload" {
            write_control_response(&mut stream, "ERR unsupported command\n").await;
            continue;
        }

        let _ = systemd_notify("STATUS=Starting candidate lsphp generation");
        let generation_before = publisher.load();
        match registry.hot_reload_default().await {
            Ok(_) => {
                let published_generation = publisher.load();
                if published_generation <= generation_before {
                    return Err(std::io::Error::other(
                        "lsphp promotion completed without advancing the published generation",
                    ));
                }
                let forced_cleanup_total =
                    registry.default_forced_cleanup_count().unwrap_or_default();
                let _ = systemd_notify(&format!(
                    "STATUS=lsphp generation {published_generation} ready; forced_cleanup_total={forced_cleanup_total}"
                ));
                tracing::info!(
                    generation = published_generation,
                    forced_cleanup_total,
                    "lsphp generation {published_generation} ready"
                );
                write_control_response(
                    &mut stream,
                    &format!(
                        "OK generation={published_generation} forced_cleanup_total={forced_cleanup_total}\n"
                    ),
                )
                .await;
            }
            Err(e) => {
                let published_generation = publisher.load();
                tracing::error!(
                    error = %e,
                    generation_before,
                    published_generation,
                    "lsphp hot reload failed"
                );
                let _ = systemd_notify(&format!(
                    "STATUS=lsphp reload failed; published_generation={published_generation}"
                ));
                write_control_response(
                    &mut stream,
                    &format!(
                        "ERR published_generation={published_generation} reload failed: {e}\n"
                    ),
                )
                .await;
            }
        }
    }
}

fn lsphp_reload(args: LsphpReloadArgs) -> anyhow::Result<()> {
    use std::io::{BufRead, Write};

    let mut stream = std::os::unix::net::UnixStream::connect(&args.control_socket)?;
    let timeout = Duration::from_secs(args.timeout_secs.max(1));
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"reload\n")?;
    stream.flush()?;
    let mut response = String::new();
    std::io::BufReader::new(stream).read_line(&mut response)?;
    let response = response.trim();
    if let Some(detail) = response.strip_prefix("OK ") {
        println!("lsphp reload complete: {detail}");
        return Ok(());
    }
    if let Some(detail) = response.strip_prefix("ERR ") {
        anyhow::bail!("lsphp reload failed: {detail}");
    }
    anyhow::bail!("invalid response from lsphp control socket: {response:?}")
}

/// (OPS7) Run a standalone, persistent lsphp pool until SIGTERM — the LSAPI
/// "external app" half of a zero-downtime deploy. Binds (or adopts, under socket
/// activation) the socket, spawns + supervises lsphp (reusing the normal registry),
/// then parks. The web tier (`serve --lsphp-external <socket>`) connects to this
/// socket as a pure client, so it can restart for a binary upgrade without
/// cold-starting PHP.
fn lsphp(root: &std::path::Path, args: LsphpArgs) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(default_env_filter())
        .init();
    // Adopt a systemd socket-activated listen fd if present (clears LISTEN_* env).
    let inherited_fd = lsphp_listen_fd_from_env()?;
    let cfg = hj_config::load(root)?;
    let server = Arc::new(cfg);
    let php = server
        .php_config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no <phpConfig> in the config — nothing to run"))?
        .clone();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(RUNTIME_THREAD_STACK_BYTES)
        .on_thread_park(memtrim::collect_if_requested_on_thread)
        .on_thread_stop(memtrim::force_collect)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let generation_file = args
            .generation_file
            .clone()
            .unwrap_or_else(|| lsphp_sibling_path(&args.php_socket, "generation"));
        let control_socket = args
            .control_socket
            .clone()
            .unwrap_or_else(|| lsphp_sibling_path(&args.php_socket, "control"));
        let generation_publisher = Arc::new(hj_lsapi::ExternalGenerationWriter::open_or_create(
            &generation_file,
        )?);
        // Same SupervisorConfig the in-process pool would build (children/env/socket).
        let mut sup_cfg = hj_lsapi::SupervisorConfig::from_php_config(
            &php,
            &args.php_socket,
            &server.user,
            &server.group,
        );
        if args.php_children > 0 {
            sup_cfg.children = args.php_children;
        }
        sup_cfg.normalize();
        sup_cfg
            .env
            .retain(|(k, _)| k != "PHP_LSAPI_CHILDREN" && k != "LSAPI_CHILDREN");
        let idle_ttl = if php.pc_keep_alive_timeout.is_zero() {
            std::time::Duration::from_secs(30)
        } else {
            php.pc_keep_alive_timeout
        };

        // The deploy script also checks this; retain a startup guard for manual units.
        let children = sup_cfg.children;
        let backlog = sup_cfg.backlog;
        if children > backlog {
            tracing::warn!(
                children = children,
                max_backlog = backlog,
                "lsphp worker cap exceeds configured listen backlog; queued dials may fail under load"
            );
        }

        let registry = hj_lsapi::LsapiRegistry::new(
            sup_cfg,
            idle_ttl,
            php.max_process_time,
            server.tuning.max_req_body_size,
        );
        // Hand the inherited socket-activation fd to the default pool's supervisor (if any),
        // so lsphp adopts the persistent socket instead of binding the path.
        let socket_activated = inherited_fd.is_some();
        if let Some(fd) = inherited_fd {
            registry.set_listen_fd(fd);
        }
        let hook_publisher = generation_publisher.clone();
        let promotion_hook: hj_lsapi::PromotionHook = Arc::new(move |core_generation, marker| {
            let published_generation =
                hook_publisher.advance_with_marker(core_generation, marker);
            tracing::info!(
                core_generation,
                generation = published_generation,
                "lsphp generation epoch published"
            );
        });
        if !registry.set_default_promotion_hook(promotion_hook) {
            return Err(std::io::Error::other(
                "failed to install the default lsphp promotion hook before startup",
            )
            .into());
        }
        registry.start_default().await?;
        let _core_generation = registry.default_generation().ok_or_else(|| {
            std::io::Error::other("default lsphp pool started without a generation")
        })?;
        let published_generation = generation_publisher.load();
        let (control_listener, control_guard) = bind_lsphp_control(&control_socket)?;
        let forced_cleanup_total = registry
            .default_forced_cleanup_count()
            .unwrap_or_default();
        tracing::info!(
            socket = %args.php_socket.display(),
            children = children,
            socket_activated,
            generation = published_generation,
            forced_cleanup_total,
            control_socket = %control_socket.display(),
            "standalone lsphp pool up; serving LSAPI until SIGTERM"
        );
        systemd_notify(&format!(
            "READY=1\nSTATUS=lsphp generation {published_generation} ready; forced_cleanup_total={forced_cleanup_total}"
        ))?;
        tracing::info!(
            generation = published_generation,
            forced_cleanup_total,
            "lsphp generation {published_generation} ready"
        );

        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let control_shutdown = tokio_util::sync::CancellationToken::new();
        let mut control_task = tokio::spawn(run_lsphp_control(
            control_listener,
            control_guard,
            registry.clone(),
            generation_publisher,
            control_shutdown.clone(),
        ));
        let control_error = tokio::select! {
            _ = tokio::signal::ctrl_c() => None,
            _ = sigterm.recv() => None,
            result = &mut control_task => Some(match result {
                Ok(Ok(())) => anyhow::anyhow!("lsphp control server exited unexpectedly"),
                Ok(Err(error)) => error.into(),
                Err(error) => anyhow::anyhow!("lsphp control task failed: {error}"),
            }),
        };
        let _ = systemd_notify("STOPPING=1\nSTATUS=Draining lsphp pool");
        if control_error.is_none() {
            control_shutdown.cancel();
            if tokio::time::timeout(Duration::from_secs(5), &mut control_task)
                .await
                .is_err()
            {
                tracing::warn!("lsphp control task did not stop within 5s; aborting it");
                control_task.abort();
                let _ = control_task.await;
            }
        }
        tracing::info!("shutdown signal received; draining lsphp pool");
        if let Err(error) = registry.drain_all().await {
            tracing::error!(%error, "lsphp pool failed to drain completely; exiting with failure");
            let _ = systemd_notify("STATUS=lsphp shutdown cleanup failed");
            if let Some(control_error) = &control_error {
                tracing::error!(error = %control_error, "lsphp control server also failed before shutdown");
            }
            return Err(error.into());
        }
        tracing::info!("lsphp pool drained; exiting");
        if let Some(error) = control_error {
            return Err(error);
        }
        Ok::<_, anyhow::Error>(())
    })
}

/// Apply the `--no-mtls` local-test override to a freshly-parsed config: relax
/// the mandatory client-cert check on every secure listener. Applied identically
/// at boot AND on every SIGHUP reload so the running TLS acceptor, the
/// `mtls_required_vhosts` set, and the hot-reload comparison all stay consistent.
fn apply_no_mtls(cfg: &mut hj_core::config::ServerConfig, no_mtls: bool) {
    if no_mtls {
        for l in &mut cfg.listeners {
            if let Some(tls) = l.tls.as_mut() {
                tls.client_verify = 0;
            }
        }
    }
}

fn visit_present_named<T>(
    handles: [(&'static str, Option<&T>); 3],
    mut visit: impl FnMut(&'static str, &T),
) {
    for (name, handle) in handles {
        if let Some(handle) = handle {
            visit(name, handle);
        }
    }
}

/// (OPS6) Decide whether a re-parsed config can be hot-reloaded. Returns
/// `Some(reason)` when a change touches state that lives OUTSIDE the swappable
/// `ServerState` — the bound listener sockets / TLS acceptor, or the lsphp pool —
/// so applying it via an `ArcSwap` swap would be inconsistent (e.g. the router's
/// mTLS-required set would change while the TLS acceptor stays put) or simply
/// ineffective. Such a change needs a restart; everything else (vhosts, rewrite,
/// access control, expires, tuning) is safe to swap. `None` ⇒ safe to hot-reload.
fn hard_config_change(
    old: &hj_core::config::ServerConfig,
    new: &hj_core::config::ServerConfig,
) -> Option<&'static str> {
    if listener_sig(old) != listener_sig(new) {
        return Some("listener address / TLS binding changed");
    }
    if php_pool_sig(old) != php_pool_sig(new) {
        return Some("lsphp pool config changed");
    }
    None
}

/// Signature of the listener BINDINGS + TLS material (NOT the vhost map — routing
/// is rebuilt on reload). A change here means sockets/acceptor must be rebuilt.
fn listener_sig(c: &hj_core::config::ServerConfig) -> String {
    let mut s = String::new();
    for l in &c.listeners {
        s.push_str(&format!(
            "{}|{}|{}|{:?}\n",
            l.name, l.address, l.secure, l.tls
        ));
    }
    s
}

/// Signature of the lsphp POOL-affecting config (the live pool is shared across
/// reloads and never restarted here, so a change to these needs a restart). The
/// `suffixes` are deliberately excluded — routing-only, and rebuilt on reload.
fn php_pool_sig(c: &hj_core::config::ServerConfig) -> String {
    match &c.php_config {
        None => String::from("none"),
        Some(p) => {
            // The registry retains the whole pool config, server credentials, and
            // LSAPI body cap across SIGHUP. Only suffix routing is rebuilt in the
            // swappable ServerState, so remove that one soft field from the clone.
            let mut retained = p.clone();
            retained.suffixes.clear();
            format!(
                "{:?}|{:?}|{}|{retained:?}",
                c.user, c.group, c.tuning.max_req_body_size
            )
        }
    }
}

fn check(root: &std::path::Path, strict: bool) -> anyhow::Result<()> {
    let cfg = hj_config::load(root)?;
    println!("httpjet config check — root: {}", cfg.server_root.display());
    println!("  server name : {}", cfg.server_name);
    println!("  run as      : {}:{}", cfg.user, cfg.group);
    println!("  QUIC enabled: {}", cfg.quic_enable);
    println!(
        "  tuning      : maxConn={} keepAlive={:?} maxBody={}MiB",
        cfg.tuning.max_connections,
        cfg.tuning.keep_alive_timeout,
        cfg.tuning.max_req_body_size / (1024 * 1024)
    );

    println!("  listeners ({}):", cfg.listeners.len());
    for l in &cfg.listeners {
        let tls = match &l.tls {
            Some(t) => {
                // OCSP stapling is parsed but NOT implemented (no responder fetch); say so
                // rather than printing `stapling=true`, which falsely implies it is active.
                // Harmless behind Cloudflare, which terminates TLS to clients.
                let stapling = if t.enable_stapling {
                    "requested(no-op: unimplemented)"
                } else {
                    "off"
                };
                format!(
                    " TLS[clientVerify={} stapling={} ca={}]",
                    t.client_verify,
                    stapling,
                    t.ca_cert_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                )
            }
            None => String::new(),
        };
        println!(
            "    - {} @ {} ({} maps){}",
            l.name,
            l.address,
            l.vhost_map.len(),
            tls
        );
    }

    println!("  ext processors ({}):", cfg.ext_processors.len());
    for e in &cfg.ext_processors {
        let kind = match e.kind {
            ExtKind::Proxy => "proxy",
            ExtKind::Lsapi => "lsapi",
        };
        println!("    - {} [{}] -> {:?}", e.name, kind, e.address);
    }

    if let Some(php) = &cfg.php_config {
        println!(
            "  php         : {} suffixes={:?} detached={}",
            php.command.display(),
            php.suffixes,
            php.detached_mode
        );
    }

    let loaded = cfg.vhosts.values().filter(|d| d.config.is_some()).count();
    println!("  vhosts ({}, {} files loaded):", cfg.vhosts.len(), loaded);
    for name in &cfg.vhost_order {
        let decl = &cfg.vhosts[name];
        let docroot = decl
            .config
            .as_ref()
            .map(|c| c.doc_root.display().to_string())
            .unwrap_or_else(|| "<not loaded>".into());
        println!("    - {:<28} -> {}", name, docroot);
    }

    lint_topology(&cfg, strict)
}

/// Vhosts that are mapped on a listener (exact or wildcard) but whose per-vhost config file did NOT
/// load (config == None) — each would 404 every request to its host. Config-load tolerates a bad
/// per-vhost file with a warn+continue, so this is the seam where that becomes visible. Shared by
/// [`lint_topology`] (deploy gate) and the SIGHUP reload guard.
fn mapped_unloaded_vhosts(cfg: &hj_config::ServerConfig) -> Vec<&str> {
    let all_mapped: std::collections::HashSet<&str> = cfg
        .listeners
        .iter()
        .flat_map(|l| l.vhost_map.iter())
        .map(|m| m.vhost.as_str())
        .collect();
    cfg.vhost_order
        .iter()
        .filter(|name| {
            all_mapped.contains(name.as_str()) && cfg.vhosts[name.as_str()].config.is_none()
        })
        .map(|s| s.as_str())
        .collect()
}

/// For a SIGHUP hot-reload: the mapped vhosts the new config would newly break (config file fails
/// to load) that the current config still serves fine — i.e. a regression that would silently 404
/// a live host. `None` = no regression (a host already broken before the reload doesn't block it).
fn reload_would_brick_vhosts(
    cur: &hj_config::ServerConfig,
    new: &hj_config::ServerConfig,
) -> Option<String> {
    let cur_unloaded: std::collections::HashSet<&str> =
        mapped_unloaded_vhosts(cur).into_iter().collect();
    let regressed: Vec<&str> = mapped_unloaded_vhosts(new)
        .into_iter()
        .filter(|v| !cur_unloaded.contains(v))
        .collect();
    (!regressed.is_empty()).then(|| regressed.join(", "))
}

/// Vhost/listener topology lints + a local topology fingerprint. Every shape
/// here is a generalization of a real foreign-host leak; the test names use reserved domains.
/// a missing `www.` mapping falling to the `*` catch-all.
fn lint_topology(cfg: &hj_config::ServerConfig, strict: bool) -> anyhow::Result<()> {
    let mut warnings: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    // Canonicalized listener -> sorted (domain -> vhost) table. Feeds both the
    // www-symmetry lint and the diagnostic fingerprint, so it represents exactly
    // what is routable on this node. Wildcards participate.
    let mut table: Vec<String> = Vec::new();
    for l in &cfg.listeners {
        let mut maps: Vec<(String, &str)> = l
            .vhost_map
            .iter()
            .flat_map(|m| {
                m.domains
                    .iter()
                    .map(move |d| (d.to_ascii_lowercase(), m.vhost.as_str()))
            })
            .collect();
        maps.sort();
        for (domain, vhost) in &maps {
            table.push(format!("{}\t{}\t{}", l.name, domain, vhost));
        }
        let exact: std::collections::HashSet<&str> = maps
            .iter()
            .filter(|(d, _)| d != "*")
            .map(|(d, _)| d.as_str())
            .collect();
        // www-symmetry: an apex mapped without its `www.` twin is the exact shape
        // of the regression (www.publisher.example → `*` → foreign vhost).
        for (domain, vhost) in &maps {
            if domain == "*" || domain.starts_with("www.") {
                continue;
            }
            // Only apexes (one dot) — `news.forum.example` has no conventional www twin.
            if domain.matches('.').count() == 1 {
                let www = format!("www.{domain}");
                if !exact.contains(www.as_str()) {
                    warnings.push(format!(
                        "listener {}: apex '{}' (vhost {}) has no '{}' mapping — that host falls to the catch-all",
                        l.name, domain, vhost, www
                    ));
                }
            }
        }
    }

    // A declared vhost with no exact domain on any listener is reachable only via
    // `*` (or not at all) — flag it so an accidental mapping deletion is loud.
    let mapped: std::collections::HashSet<&str> = cfg
        .listeners
        .iter()
        .flat_map(|l| l.vhost_map.iter())
        .filter(|m| m.domains.iter().any(|d| d != "*"))
        .map(|m| m.vhost.as_str())
        .collect();
    for name in &cfg.vhost_order {
        if !mapped.contains(name.as_str()) {
            warnings.push(format!(
                "vhost '{name}' has no exact vhostMap domain on any listener"
            ));
        }
    }

    // A non-"*" wildcard vhostMap domain (e.g. "*.example.com") is stored as a LITERAL exact key
    // the router never matches (httpjet has no glob matcher, unlike OLS) — those hosts silently fall
    // to the "*" default vhost. Warn (not error: it degrades to the catch-all, not an invariant
    // break). Mirrors the parse-time tracing::warn, but visible in the println-based `check` output.
    for l in &cfg.listeners {
        for m in &l.vhost_map {
            for d in m
                .domains
                .iter()
                .filter(|d| hj_config::is_unsupported_wildcard_domain(d))
            {
                warnings.push(format!(
                    "listener {}: vhostMap domain '{}' (vhost {}) is a wildcard pattern — unsupported (only '*' matches); stored as a literal key that never matches",
                    l.name, d, m.vhost
                ));
            }
        }
    }

    // Two vhosts sharing a docroot breaks the isolation invariant every path-keyed
    // cache (static cache, statcache, htaccess cache) relies on — hard error.
    let mut by_docroot: std::collections::BTreeMap<String, Vec<&str>> = Default::default();
    for name in &cfg.vhost_order {
        if let Some(c) = cfg.vhosts[name].config.as_ref() {
            by_docroot
                .entry(c.doc_root.display().to_string())
                .or_default()
                .push(name);
        }
    }
    for (docroot, vhosts) in &by_docroot {
        if vhosts.len() > 1 {
            errors.push(format!(
                "docroot '{}' is shared by vhosts {:?}",
                docroot, vhosts
            ));
        }
    }

    // A vhost that is MAPPED on a listener but whose per-vhost config file failed to load is
    // reachable by routing yet would 404 EVERY request to that host — a silent per-host outage (a
    // bad reload, a partial deploy/rsync, or a permission change). Hard error so `check --strict`
    // and the deploy gate catch the broken file before traffic does.
    for name in mapped_unloaded_vhosts(cfg) {
        errors.push(format!(
            "vhost '{name}' is mapped on a listener but its per-vhost config file did not load — every request to it would 404"
        ));
    }

    table.sort();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for line in &table {
        for &b in line.as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h ^= 0x0a;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    println!("  vhost-map-fingerprint: fnv1a64:{h:016x}");

    for w in &warnings {
        println!("  lint WARN : {w}");
    }
    for e in &errors {
        println!("  lint ERROR: {e}");
    }
    // Warnings are ops hygiene (the live config carries known ones and
    // /usr/local/lsws is read-only); only ERRORS — invariant breaks like a shared
    // docroot — fail strict, so the deploy gate can't brick on a pre-existing WARN.
    if strict && !errors.is_empty() {
        anyhow::bail!(
            "strict lint failed: {} error(s), {} warning(s)",
            errors.len(),
            warnings.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsphp_default_state_paths_derive_from_the_pool_socket() {
        let socket = PathBuf::from("/tmp/php8-httpjet-test.sock");
        assert_eq!(
            lsphp_sibling_path(&socket, "generation"),
            PathBuf::from("/tmp/php8-httpjet-test.sock.generation")
        );
        assert_eq!(
            lsphp_sibling_path(&socket, "control"),
            PathBuf::from("/tmp/php8-httpjet-test.sock.control")
        );
    }

    #[test]
    fn systemd_notify_sends_to_filesystem_socket() {
        let path = std::env::temp_dir().join(format!(
            "httpjet-notify-test-{}-{}.sock",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let _ = std::fs::remove_file(&path);
        let receiver = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        send_systemd_notify(path.as_os_str(), "READY=1\nSTATUS=test").unwrap();
        let mut message = [0u8; 64];
        let received = receiver.recv(&mut message).unwrap();
        assert_eq!(&message[..received], b"READY=1\nSTATUS=test");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn page_cache_store_path_defaults_to_ram_only() {
        assert_eq!(resolve_page_cache_store_path(""), None);
        assert_eq!(resolve_page_cache_store_path("  "), None);
        assert_eq!(resolve_page_cache_store_path("none"), None);
        assert_eq!(
            resolve_page_cache_store_path("default"),
            Some(std::path::PathBuf::from("/dev/shm/jetcache"))
        );
        assert_eq!(
            resolve_page_cache_store_path("jetcache"),
            Some(std::path::PathBuf::from("/dev/shm/jetcache"))
        );
    }

    #[test]
    fn page_cache_store_path_cli_override_and_ram_rollback() {
        assert_eq!(
            resolve_page_cache_store_path("/dev/shm/custom"),
            Some(std::path::PathBuf::from("/dev/shm/custom"))
        );
        // The in-RAM-only rollback / kill-switch.
        assert_eq!(resolve_page_cache_store_path("none"), None);
        assert_eq!(resolve_page_cache_store_path("off"), None);
        assert_eq!(resolve_page_cache_store_path("ram"), None);
    }

    #[test]
    fn php_pool_signature_covers_every_retained_registry_input() {
        let mut base = hj_core::config::ServerConfig {
            user: "nobody".into(),
            group: "nobody".into(),
            php_config: Some(hj_core::config::PhpConfig::default()),
            ..Default::default()
        };
        let assert_hard = |changed: hj_core::config::ServerConfig| {
            assert_eq!(
                hard_config_change(&base, &changed),
                Some("lsphp pool config changed")
            );
        };

        let mut changed = base.clone();
        changed.tuning.max_req_body_size += 1;
        assert_hard(changed);
        let mut changed = base.clone();
        changed.user = "www-data".into();
        assert_hard(changed);
        let mut changed = base.clone();
        changed.group = "www-data".into();
        assert_hard(changed);
        let mut changed = base.clone();
        changed.php_config.as_mut().unwrap().retry_timeout = Duration::from_secs(3);
        assert_hard(changed);
        let mut changed = base.clone();
        changed.php_config.as_mut().unwrap().min_restart_interval = Duration::from_secs(11);
        assert_hard(changed);
        let mut changed = base.clone();
        changed.php_config.as_mut().unwrap().max_restart_backoff = Duration::from_secs(31);
        assert_hard(changed);

        base.php_config.as_mut().unwrap().suffixes = vec!["php".into()];
        let mut routing_only = base.clone();
        routing_only.php_config.as_mut().unwrap().suffixes = vec!["html".into()];
        assert_eq!(hard_config_change(&base, &routing_only), None);
    }

    #[test]
    fn certificate_reload_visits_the_ktls_handle() {
        let tls = 1;
        let ktls = 2;
        let quic = 3;
        let mut visited = Vec::new();
        visit_present_named(
            [
                ("TLS", Some(&tls)),
                ("kTLS", Some(&ktls)),
                ("QUIC", Some(&quic)),
            ],
            |name, handle| visited.push((name, *handle)),
        );
        assert_eq!(visited, vec![("TLS", 1), ("kTLS", 2), ("QUIC", 3)]);
    }
}
