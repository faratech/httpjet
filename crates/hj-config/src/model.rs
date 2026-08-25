//! The clean, normalized configuration object model that the rest of httpjet
//! consumes. Produced from the raw LiteSpeed XML by [`crate::parse`] after
//! `$VAR` substitution and include/template resolution.
//!
//! This module is the *frozen contract*: other crates (hj-core, hj-tls,
//! hj-static, hj-lsapi, hj-rewrite, hj-proxy, ...) program against these types.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Top-level server configuration (from `httpd_config.xml`).
#[derive(Debug, Clone, Default)]
pub struct ServerConfig {
    /// `$SERVER_ROOT` — the install root (e.g. `/usr/local/lsws`).
    pub server_root: PathBuf,
    /// Resolved server name (`$HOSTNAME` expanded).
    pub server_name: String,
    pub user: String,
    pub group: String,
    pub index_files: Vec<String>,
    pub tuning: Tuning,
    pub quic_enable: bool,
    /// `useIpInProxyHeader` (LiteSpeed range 0..=4, default 2):
    /// - 0 = never trust X-Forwarded-For / proxy headers.
    /// - 1 = always trust X-Forwarded-For (any peer).
    /// - 2 = trust X-Forwarded-For (and CF-Connecting-IP / CF real-ip) only
    ///   when the peer is in a `T`-flagged trusted network. **Default.**
    /// - 3 = like 2 (trusted-peer-only, Cloudflare real-ip aware); differs
    ///   only in TLS-handshake handling downstream, not in IP extraction.
    /// - 4 = like 1 (always trust), without the Cloudflare real-ip path.
    ///
    /// httpjet stores the raw level; hj-core decides whether to honor the
    /// header for a given client using [`AccessRule::trusted`].
    pub use_ip_in_proxy_header: u8,
    pub expires: ExpiresConfig,
    /// Server-level `<cache>` block (origin full-page cache defaults).
    pub cache: CacheConfig,
    pub security: Security,
    /// Server-wide suEXEC / privilege-drop policy for local (lsphp) workers.
    /// **Default OFF** — see [`SuExecPolicy`]. When disabled (or when httpjet is
    /// not running as root) workers run as the server user/group with no chroot,
    /// exactly as today.
    pub suexec: SuExecPolicy,
    pub ext_processors: Vec<ExtProcessor>,
    pub php_config: Option<PhpConfig>,
    pub listeners: Vec<Listener>,
    /// Virtual hosts declared in the server file, keyed by name (insertion order kept in `vhost_order`).
    pub vhosts: BTreeMap<String, VHostDecl>,
    pub vhost_order: Vec<String>,
    /// MIME map parsed from `mime.properties`.
    pub mime: MimeMap,
}

/// Performance/limits block (`<tuning>` + a few top-level knobs).
#[derive(Debug, Clone)]
pub struct Tuning {
    pub max_connections: u32,
    pub conn_timeout: Duration,
    pub keep_alive_timeout: Duration,
    pub max_keep_alive_req: u32,
    pub max_req_url_len: usize,
    pub max_req_header_size: usize,
    pub max_req_body_size: u64,
    pub max_cached_file_size: u64,
    pub total_in_mem_cache_size: u64,
    pub max_mmap_file_size: u64,
    pub total_mmap_cache_size: u64,
    /// LiteSpeed `fileETag` bitmask (range 0..=28, default 28). Bits:
    /// INODE=4, MTIME=8, SIZE=16; ALL = 4|8|16 = 28 (the default). A 0 value
    /// emits no ETag. See OLS httpcontext.h ETAG_* and staticfilecachedata.cpp.
    pub file_etag: u32,
    pub enable_gzip: bool,
    pub enable_dyn_gzip: bool,
    pub enable_zstd: bool,
    pub enable_dyn_zstd: bool,
    pub enable_brotli: bool,
    pub enable_dyn_brotli: bool,
    /// zstd compression level (1-22; default 3).
    pub zstd_level: u32,
    /// brotli quality (0-11; default 5).
    pub brotli_quality: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            max_connections: 65000,
            conn_timeout: Duration::from_secs(60),
            keep_alive_timeout: Duration::from_secs(5),
            max_keep_alive_req: 1000,
            max_req_url_len: 8192,
            max_req_header_size: 16380,
            max_req_body_size: 100 * 1024 * 1024,
            max_cached_file_size: 4 * 1024 * 1024,
            total_in_mem_cache_size: 4096 * 1024 * 1024,
            max_mmap_file_size: 256 * 1024,
            total_mmap_cache_size: 2048 * 1024 * 1024,
            file_etag: 28,
            enable_gzip: true,
            enable_dyn_gzip: true,
            enable_zstd: true,
            enable_dyn_zstd: true,
            enable_brotli: true,
            enable_dyn_brotli: true,
            zstd_level: 3,
            brotli_quality: 5,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExpiresConfig {
    pub enabled: bool,
    /// (type-glob, header-value) pairs, e.g. ("image/*", "A604800").
    pub by_type: Vec<(String, String)>,
}

/// Server-level `<cache>` block — drives the LSCache-equivalent origin
/// full-page cache (see `hj-pagecache`). All fields carry LiteSpeed defaults.
///
/// `enabled` here only reflects that the config configures caching; the runtime
/// `--page-cache` flag is the master switch and per-vhost
/// [`VhostCachePolicy::enable_cache`] gates each vhost.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// `cacheStorePath` (live: `/dev/shm/lscache`) — parsed for completeness but
    /// NOT used by httpjet's page cache. The file tier lives at its own CLI root
    /// (`--page-cache-store-path`, default `/dev/shm/jetcache`) so it never shares a
    /// directory with LiteSpeed.
    pub store_path: PathBuf,
    /// `expireInSeconds` — default public TTL (live: 900).
    pub default_ttl_secs: u32,
    /// `privateExpireInSeconds` — default private TTL (live: 0 = disabled).
    pub default_private_ttl_secs: u32,
    /// `cacheStatusCode` — cacheable response statuses (live: `200,301`).
    pub cacheable_status: Vec<u16>,
    /// `enablePostCache` — cache POST responses (live: 0).
    pub enable_post_cache: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            store_path: PathBuf::from("/dev/shm/lscache"),
            default_ttl_secs: 900,
            default_private_ttl_secs: 0,
            cacheable_status: vec![200, 301],
            enable_post_cache: false,
        }
    }
}

/// Per-vhost `<cache>` + `<cachePolicy>` — whether (and how) this vhost may use
/// the origin page cache.
#[derive(Debug, Clone, Default)]
pub struct VhostCachePolicy {
    /// `<cache><enableCache>` — vhost master enable.
    pub enable_cache: bool,
    /// `<cachePolicy><enablePublicCache>` (defaults true when caching enabled).
    pub enable_public: bool,
    /// `<cachePolicy><enablePrivateCache>`.
    pub enable_private: bool,
}

/// A POSIX resource limit's independently-configured soft and hard values.
/// `None` for either side means that side was not configured and should retain
/// the process's inherited value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RlimitPair {
    pub soft: Option<u64>,
    pub hard: Option<u64>,
}

impl RlimitPair {
    pub fn is_empty(self) -> bool {
        self.soft.is_none() && self.hard.is_none()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Security {
    /// Server-wide `<fileAccessControl><followSymbolLink>`: when set, symlinks
    /// are followed for ALL vhosts regardless of per-vhost `allowSymbolLink`.
    pub follow_symlink: bool,
    /// Globs of filesystem paths that must never be served.
    pub access_deny_dir: Vec<String>,
    /// IP allow rules; `ALL` plus CIDRs. Entries ending in `T` are "trusted"
    /// (eligible to set proxy headers) — see [`AccessRule::trusted`].
    pub access_control: Vec<AccessRule>,
    /// Server-wide `<security><CGIRLimit>` CPU soft/hard limits, in seconds.
    /// `None` = neither side configured.
    pub cgi_cpu_limit_secs: Option<RlimitPair>,
}

#[derive(Debug, Clone)]
pub struct AccessRule {
    /// `"ALL"` (or `"*"`) or a CIDR/IP string like `"173.245.48.0/20"`. Any
    /// trailing `T`/`t` trust flag has already been stripped.
    pub spec: String,
    /// LiteSpeed `T` suffix: this network is a trusted reverse proxy
    /// (OLS `AC_TRUST`). Per OLS `checkTrust`, the flag only takes effect on
    /// **allow** rules — a `T` on a deny rule is ignored, so `trusted` is
    /// never `true` when `allow` is `false`.
    pub trusted: bool,
    pub allow: bool,
}

/// Server-wide suEXEC / privilege-drop policy (LiteSpeed `<extprocessor>`-level
/// suEXEC + `uidMin`/`gidMin` floors). This is the **master gate** for the
/// per-vhost isolation feature.
///
/// # Fail-safe defaults
/// `enable` defaults to `false`: with the feature off, lsphp workers run as the
/// server user/group with no chroot — byte-for-byte today's behavior. When
/// enabled, [`uid_min`](Self::uid_min)/[`gid_min`](Self::gid_min) are the hard
/// floors below which a resolved worker credential is rejected (mirrors OLS
/// `ServerProcessConfig::getUidMin`/`getGidMin`, default 100 — see
/// localworker.cpp:447-456). A resolved uid/gid of 0 (root) is **always**
/// rejected regardless of the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuExecPolicy {
    /// Master enable. **Default `false`** (feature OFF).
    pub enable: bool,
    /// Minimum acceptable worker uid (LiteSpeed `uidMin`, default 100).
    pub uid_min: u32,
    /// Minimum acceptable worker gid (LiteSpeed `gidMin`, default 100).
    pub gid_min: u32,
    /// Linux-namespace isolation policy (Phase 5a). **Default OFF** — when
    /// `namespaces.enable` is false the worker shares the server's namespaces
    /// exactly as today. Honored only when [`enable`](Self::enable) is set,
    /// httpjet runs as root, and the relevant per-namespace flag is on (see
    /// `JailConfig::resolve` in hj-lsapi).
    pub namespaces: NamespacePolicy,
}

impl Default for SuExecPolicy {
    fn default() -> Self {
        SuExecPolicy {
            enable: false,
            uid_min: 100,
            gid_min: 100,
            namespaces: NamespacePolicy::default(),
        }
    }
}

/// Linux-namespace isolation policy (Phase 5a). **Default OFF** — every field
/// defaults to `false`, so an absent `<namespace>` block leaves workers sharing
/// the server's namespaces (today's behavior).
///
/// `enable` is the master gate; the per-namespace flags select which namespaces
/// the worker is `unshare(2)`d into when the feature is active. The flags are
/// only meaningful while `enable` is set (a flag with `enable=false` is ignored
/// — see `JailConfig::resolve` in hj-lsapi, which collapses a disabled policy to
/// an empty [`NamespaceFlags`]).
///
/// # Per-namespace semantics
/// - [`mount`](Self::mount) (`CLONE_NEWNS`): a private mount namespace. With
///   chroot already giving the worker a path view, 5a does **no** mount
///   choreography (no remount/pivot) — this just detaches the worker's mount
///   propagation.
/// - [`pid`](Self::pid) (`CLONE_NEWPID`): a new PID namespace. **Currently not
///   honored.** Per `unshare(2)`, the process that execs lsphp stays in the old
///   PID namespace and only its children enter the new one — so the lsphp
///   master's FIRST forked worker becomes PID 1, and that worker's routine
///   recycling (LSAPI_MAX_REQS / idle pruning) would SIGKILL the whole pool when
///   it exits. Honoring this safely needs a fork-based PID-1 reaper, so the flag
///   is accepted in config but stripped fail-safe before any `unshare(2)` (see
///   `NamespaceFlags::pid` in hj-lsapi). It still participates in jail keying.
/// - [`net`](Self::net) (`CLONE_NEWNET`): a fresh network namespace with only a
///   (down) loopback. **This breaks outbound networking from PHP** (no DB/HTTP
///   egress), so it is the most opt-in flag.
/// - [`uts`](Self::uts) (`CLONE_NEWUTS`): a private hostname/NIS domain.
/// - [`ipc`](Self::ipc) (`CLONE_NEWIPC`): a private System V IPC / POSIX MQ
///   namespace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NamespacePolicy {
    /// Master enable for namespace isolation. **Default `false`**.
    pub enable: bool,
    /// Unshare the mount namespace (`CLONE_NEWNS`). **Default `false`**.
    pub mount: bool,
    /// Unshare the PID namespace (`CLONE_NEWPID`). **Default `false`**. Note:
    /// currently accepted but not honored — stripped fail-safe before any
    /// `unshare(2)` (see the per-namespace semantics above and
    /// `NamespaceFlags::pid` in hj-lsapi).
    pub pid: bool,
    /// Unshare the network namespace (`CLONE_NEWNET`); loopback-only, breaks
    /// outbound PHP networking. **Default `false`**.
    pub net: bool,
    /// Unshare the UTS (hostname) namespace (`CLONE_NEWUTS`). **Default `false`**.
    pub uts: bool,
    /// Unshare the IPC namespace (`CLONE_NEWIPC`). **Default `false`**.
    pub ipc: bool,
}

/// An external processor: a proxy upstream or an LSAPI (PHP) app.
#[derive(Debug, Clone)]
pub struct ExtProcessor {
    pub name: String,
    pub kind: ExtKind,
    pub address: ExtAddress,
    pub max_conns: u32,
    pub init_timeout: Duration,
    pub retry_timeout: Duration,
    pub pc_keep_alive_timeout: Duration,
    /// `respBuffer`: 0 = stream (don't buffer).
    pub resp_buffer: bool,
    // lsapi-only
    pub env: Vec<(String, String)>,
    pub auto_start: u8,
    pub path: Option<PathBuf>,
    pub backlog: u32,
    pub instances: u32,
    pub run_on_startup: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKind {
    Proxy,
    Lsapi,
}

/// Address of an external processor: a TCP socket or a Unix domain socket path.
#[derive(Debug, Clone)]
pub enum ExtAddress {
    Tcp(SocketAddr),
    /// Raw host:port that may not parse to a SocketAddr yet (resolved later).
    HostPort(String),
    Uds(PathBuf),
}

#[derive(Debug, Clone, Default)]
pub struct PhpConfig {
    pub handler_id: String,
    pub command: PathBuf,
    /// Suffixes handled by PHP — note this install maps both `php` AND `html`.
    pub suffixes: Vec<String>,
    pub env: Vec<(String, String)>,
    pub max_conns: u32,
    pub init_timeout: Duration,
    pub retry_timeout: Duration,
    pub pc_keep_alive_timeout: Duration,
    /// LiteSpeed `backlog`: pending LSAPI connections allowed on the listen
    /// socket before the kernel rejects or defers another dial.
    pub backlog: u32,
    pub run_on_startup: i32,
    pub mem_soft_limit: Option<u64>,
    pub mem_hard_limit: Option<u64>,
    pub detached_mode: bool,
    /// LiteSpeed `maxProcessTime` — wall-clock cap on a single request before
    /// the worker is killed. `None` = no cap (today's behavior).
    pub max_process_time: Option<Duration>,
    /// RLIMIT_CPU seconds applied to the worker (LiteSpeed CPU soft/hard).
    /// `None` = neither side configured (inherit both).
    pub cpu_limit_secs: Option<RlimitPair>,
    /// LiteSpeed `procSoftLimit` — RLIMIT_NPROC soft value. `None` = inherit.
    pub proc_soft_limit: Option<u64>,
    /// LiteSpeed `procHardLimit` — RLIMIT_NPROC hard value. `None` = inherit.
    pub proc_hard_limit: Option<u64>,
    /// LiteSpeed `extMaxIdleTime` — idle time before an idle worker is recycled.
    /// `None` = never idle-recycle (today's behavior).
    pub max_idle_time: Option<Duration>,
    /// Minimum interval between debounced restarts (LiteSpeed's hard-coded 10s
    /// `tryRestart` window). Default 10s.
    pub min_restart_interval: Duration,
    /// Upper bound on exponential restart backoff after repeated failures.
    /// Default 30s.
    pub max_restart_backoff: Duration,
}

#[derive(Debug, Clone)]
pub struct Listener {
    pub name: String,
    pub address: String,
    pub secure: bool,
    pub vhost_map: Vec<VhostMap>,
    pub tls: Option<ListenerTls>,
}

#[derive(Debug, Clone)]
pub struct VhostMap {
    pub vhost: String,
    /// Domains this maps; `*` means catch-all/default.
    pub domains: Vec<String>,
}

/// TLS material on a listener. The `ca_cert_file` here is the **client-cert
/// verification root** (Cloudflare authenticated origin pull CA) — NOT a
/// server chain. Keep distinct from [`VhSsl::ca_cert_file`].
#[derive(Debug, Clone)]
pub struct ListenerTls {
    pub key_file: PathBuf,
    pub cert_file: PathBuf,
    pub cert_chain: bool,
    pub ca_cert_file: Option<PathBuf>,
    /// LiteSpeed `clientVerify`: 0=none, 1=optional, 2=require, 3=optional_no_ca.
    pub client_verify: u8,
    pub verify_depth: u32,
    pub enable_stapling: bool,
}

/// A virtual host as declared in the server config (before its file is loaded).
#[derive(Debug, Clone)]
pub struct VHostDecl {
    pub name: String,
    pub vh_root: PathBuf,
    pub config_file: PathBuf,
    /// LSWS tri-state `<allowSymbolLink>` on the DECLARATION: `Some(v)` = explicit
    /// override, `None` = inherit the server-wide `followSymbolLink`.
    pub allow_symbol_link: Option<bool>,
    /// (#249 drift class) LSWS `restrained`: confine this vhost's file access to
    /// vhRoot. httpjet enforces it by refusing symlink-following (the follow arm
    /// cannot confine targets), i.e. restrained ⇒ allow_symbol_link=false.
    pub restrained: bool,
    pub enable_script: bool,
    /// The loaded per-vhost configuration (filled by `parse::load`).
    pub config: Option<Arc<VHostConfig>>,
}

/// The per-vhost configuration loaded from `conf/vhosts/<name>.xml`.
#[derive(Debug, Clone, Default)]
pub struct VHostConfig {
    pub doc_root: PathBuf,
    pub index_files: Vec<String>,
    pub allow_symbol_link: bool,
    /// The vhost FILE's explicit `<allowSymbolLink>` (tri-state), collapsed into the
    /// effective `allow_symbol_link` by `load_vhost_files`: file override → decl
    /// override → server `followSymbolLink`.
    pub allow_symbol_link_override: Option<bool>,
    pub rewrite: InlineRewrite,
    pub contexts: Vec<Context>,
    pub script_handlers: Vec<ScriptHandler>,
    pub websockets: Vec<WebSocketMap>,
    pub vhssl: Option<VhSsl>,
    pub expires: Option<ExpiresConfig>,
    /// Per-vhost `<cache>` policy (`None` = caching not enabled for this vhost).
    pub cache_policy: Option<VhostCachePolicy>,
    pub extra_ext_processors: Vec<ExtProcessor>,
    /// Per-vhost suEXEC isolation (LiteSpeed `setUIDMode`/`chrootMode`/
    /// `chrootPath`). `None` = no per-vhost override: the worker uses the server
    /// user/group with no chroot. Only honored when [`SuExecPolicy::enable`] is
    /// set **and** httpjet runs as root (see `JailConfig::resolve` in hj-lsapi).
    pub isolation: Option<VHostIsolation>,
    /// `<htAccess><allowOverride>` bitmask. `0` = `.htaccess` processing disabled
    /// for this vhost; `31` ("all", the live install) = fully enabled. Default 0
    /// (off) so a vhost with no `<htAccess>` block never loads `.htaccess`.
    pub allow_override: u32,
    /// True when the vhost XML carried an EXPLICIT `<allowOverride>` value. An explicit
    /// `0` forbids ALL override processing outright — `autoLoadHtaccess` must not
    /// re-enable the chain behind an operator's hardening (audit).
    pub allow_override_explicit: bool,
    /// (#248) The vhost's OWN `<logging><accessLog>` file (`useServer=0` + a
    /// fileName). `None` ⇒ the vhost rides the unified access log.
    pub access_log_file: Option<VhostLogFile>,
    /// (#248) The vhost's OWN `<logging><log>` error file. Backend/handler errors
    /// for this vhost are mirrored here; `None` ⇒ unified error log only.
    pub error_log_file: Option<VhostLogFile>,
    /// `<htAccess><accessFileName>`. The per-directory override file name; the
    /// parser fills `.htaccess` when the element is absent/empty. Derived
    /// `Default` is `""` — consult [`VHostConfig::access_file_name_or_default`].
    pub access_file_name: String,
}

/// A per-vhost log file declared in `<logging>` (#248), with LiteSpeed rolling
/// parameters. `$VAR`s are already substituted at parse time.
#[derive(Debug, Clone)]
pub struct VhostLogFile {
    pub path: PathBuf,
    /// Roll the live file once it exceeds this many bytes (LSWS `rollingSize`;
    /// 50M default). `0` disables size rolling.
    pub rolling_bytes: u64,
    /// Prune rolled files older than this many days (LSWS `keepDays`; 0 disables).
    pub keep_days: u64,
    /// LSWS `logHeaders` bitmask. Nonzero ⇒ request headers accompany each record.
    pub log_headers: u8,
}

impl VHostConfig {
    /// The configured per-directory access file name, defaulting to `.htaccess`
    /// when unset/empty (guards the `..Default::default()` construction path).
    pub fn access_file_name_or_default(&self) -> &str {
        if self.access_file_name.is_empty() {
            ".htaccess"
        } else {
            self.access_file_name.as_str()
        }
    }

    /// Whether `.htaccess` (`allowOverride`) is enabled for this vhost.
    pub fn htaccess_allowed(&self) -> bool {
        self.allow_override != 0
    }

    /// Whether ANY per-directory override processing may run. An EXPLICIT
    /// `<allowOverride>0</allowOverride>` forbids it outright; a merely-absent
    /// block defers to `<rewrite><autoLoadHtaccess>`.
    pub fn overrides_enabled(&self, auto_load_htaccess: bool) -> bool {
        if self.allow_override == 0 && self.allow_override_explicit {
            return false;
        }
        self.htaccess_allowed() || auto_load_htaccess
    }
}

/// Inline `<rewrite>` block: enable flag + the raw Apache-style rules text.
#[derive(Debug, Clone, Default)]
pub struct InlineRewrite {
    pub enable: bool,
    pub auto_load_htaccess: bool,
    pub base: Option<String>,
    /// Raw rules text (a whole Apache mod_rewrite snippet); parsed by hj-rewrite.
    pub rules: String,
}

/// A context entry from `<contextList>`, tagged by its `<type>` child.
#[derive(Debug, Clone)]
pub struct Context {
    pub kind: ContextKind,
    pub uri: String,
    pub location: Option<PathBuf>,
    /// For proxy/lsapi contexts: the ext-processor handler name.
    pub handler: Option<String>,
    pub enabled: bool,
    /// Raw `<extraHeaders>` text (newline-delimited header ops).
    pub extra_headers: Vec<(String, String)>,
    /// Per-context `addDefaultCharset` (on/off/1/true). Default `false`.
    pub add_default_charset: bool,
    /// `addDefaultCharsetCustomized`; `None` = server default (UTF-8).
    pub charset: Option<String>,
    /// (#249) Context-level `<cachePolicy>` (LSWS six-flag set). A context whose
    /// `enable_cache=0` or `check_public_cache=0` FORBIDS public page-cache
    /// entries under its URI prefix regardless of the vhost policy; the private
    /// pair gates the private tier the same way. `None` = block absent ⇒ inherit.
    pub cache_policy: Option<ContextCachePolicy>,
}

/// The LSWS per-context cache flags. All six are modeled for fidelity; httpjet's
/// enforcement uses the public pair (`enable_cache` + `check_public_cache`) and
/// the private pair (`enable_private_cache` + `check_private_cache`);
/// `respect_cacheable`/`enable_post_cache` are recorded for parity/diagnostics.
#[derive(Debug, Clone, Copy)]
pub struct ContextCachePolicy {
    pub check_public_cache: bool,
    pub check_private_cache: bool,
    pub respect_cacheable: bool,
    pub enable_cache: bool,
    pub enable_private_cache: bool,
    pub enable_post_cache: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextKind {
    Static,
    Proxy,
    Lsapi,
    Cgi,
    Rails,
    Redirect,
    AppServer,
    Other,
}

#[derive(Debug, Clone)]
pub struct ScriptHandler {
    /// File suffix, lowercased (e.g. `"php"`).
    pub suffix: String,
    /// `<type>` mapped via `context_kind` (e.g. `lsapi` => [`ContextKind::Lsapi`]).
    pub kind: ContextKind,
    /// The ext-processor handler name (e.g. `"php8"`).
    pub handler: String,
}

#[derive(Debug, Clone)]
pub struct WebSocketMap {
    pub uri: String,
    pub address: String,
}

/// Per-vhost suEXEC isolation, parsed from LiteSpeed's per-vhost
/// `setUIDMode`/`chrootMode`/`chrootPath`.
///
/// The `user`/`group` names are resolved to numeric uid/gid in the **parent**
/// (never in `pre_exec`); see `JailConfig::resolve` in hj-lsapi. When
/// [`from_docroot_owner`](Self::from_docroot_owner) is set (OLS `UID_DOCROOT`),
/// the worker credentials come from the document root's owner instead of the
/// `user`/`group` fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VHostIsolation {
    /// User name (or numeric uid) to drop the worker to. Ignored when
    /// [`from_docroot_owner`](Self::from_docroot_owner) is set.
    pub user: String,
    /// Group name (or numeric gid). Empty = the user's primary group. Ignored
    /// when [`from_docroot_owner`](Self::from_docroot_owner) is set.
    pub group: String,
    /// chroot policy for the worker (see [`ChrootMode`]).
    pub chroot: ChrootMode,
    /// LiteSpeed `setUIDMode == UID_DOCROOT`: take the worker's uid/gid from the
    /// document root's owner rather than the `user`/`group` fields. This mirrors
    /// OLS `LocalWorker::workerExec` (localworker.cpp:440-456).
    pub from_docroot_owner: bool,
    /// Per-vhost Linux-namespace override (Phase 5a). `None` = **inherit** the
    /// server policy ([`SuExecPolicy::namespaces`]); `Some` replaces it wholesale
    /// for this vhost. Like the server policy, it is only honored when the server
    /// suEXEC feature is enabled and httpjet runs as root.
    pub namespaces: Option<NamespacePolicy>,
}

/// Where to `chroot` a suEXEC worker (LiteSpeed `chrootMode`):
/// `CHROOT_NONE`/`CHROOT_VHROOT`/`CHROOT_PATH` (localworker.cpp:473-483).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ChrootMode {
    /// No chroot (`CHROOT_NONE`). Today's behavior.
    #[default]
    None,
    /// chroot into the vhost root (`CHROOT_VHROOT`).
    VhRoot,
    /// chroot into an explicit path (`CHROOT_PATH`).
    Path(PathBuf),
}

/// Per-vhost SSL. `ca_cert_file` here is **server chain material** appended to
/// the leaf when `cert_chain` is set — NOT a client verifier.
#[derive(Debug, Clone)]
pub struct VhSsl {
    pub key_file: PathBuf,
    pub cert_file: PathBuf,
    pub cert_chain: bool,
    pub ca_cert_file: Option<PathBuf>,
}

/// MIME type map (suffix -> content-type), from `mime.properties`.
#[derive(Debug, Clone, Default)]
pub struct MimeMap {
    pub by_suffix: BTreeMap<String, String>,
}

impl MimeMap {
    pub fn content_type(&self, suffix: &str) -> Option<&str> {
        self.by_suffix
            .get(&suffix.to_ascii_lowercase())
            .map(|s| s.as_str())
    }
}
