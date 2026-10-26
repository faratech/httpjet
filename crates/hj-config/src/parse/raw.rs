//! Permissive "raw" serde structs that mirror the LiteSpeed XML schema.
//! Every field is optional so the liberal/legacy XML LiteSpeed tolerates
//! (empty elements, missing fields) deserialises without error.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Raw structs (mirror the XML; all permissive)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawServer {
    #[serde(rename = "serverName", default)]
    pub(super) server_name: Option<String>,
    #[serde(default)]
    pub(super) user: Option<String>,
    #[serde(default)]
    pub(super) group: Option<String>,
    #[serde(rename = "indexFiles", default)]
    pub(super) index_files: Option<String>,
    #[serde(rename = "useIpInProxyHeader", default)]
    pub(super) use_ip_in_proxy_header: Option<String>,
    #[serde(default)]
    pub(super) quic: Option<RawQuic>,
    #[serde(default)]
    pub(super) tuning: Option<RawTuning>,
    #[serde(default)]
    pub(super) expires: Option<RawExpires>,
    #[serde(default)]
    pub(super) cache: Option<RawServerCache>,
    #[serde(default)]
    pub(super) security: Option<RawSecurity>,
    /// OLS `getChild("security", 1)` falls back to the root node, so a bare
    /// root-level `<accessControl>` is the server ACL when `<security>` is absent.
    #[serde(rename = "accessControl", default)]
    pub(super) access_control: Option<RawAccessControl>,
    /// Root-level forms of the other `<security>` children (same OLS fallback).
    #[serde(rename = "accessDenyDir", default)]
    pub(super) access_deny_dir: Option<RawAccessDenyDir>,
    #[serde(rename = "fileAccessControl", default)]
    pub(super) file_access_control: Option<RawFileAccessControl>,
    #[serde(default)]
    pub(super) suexec: Option<RawSuExec>,
    #[serde(rename = "extProcessorList", default)]
    pub(super) ext_processor_list: Option<RawExtList>,
    #[serde(rename = "phpConfig", default)]
    pub(super) php_config: Option<RawPhpConfig>,
    #[serde(rename = "virtualHostList", default)]
    pub(super) vhost_list: Option<RawVHostList>,
    #[serde(rename = "listenerList", default)]
    pub(super) listener_list: Option<RawListenerList>,
    #[serde(rename = "vhTemplateList", default)]
    pub(super) vh_template_list: Option<RawVhTemplateList>,
    /// Server-level suffix routes, inherited by every vhost (#928).
    #[serde(rename = "scriptHandlerList", default)]
    pub(super) script_handler_list: Option<RawScriptHandlerList>,
    /// Vhost names the WebAdmin "Disable" action lists; each answers 403 (#1000).
    #[serde(rename = "suspendedVhosts", default)]
    pub(super) suspended_vhosts: Option<String>,
    #[serde(rename = "apacheConf", default)]
    pub(super) apache_conf: Option<String>,
    /// Server `<htAccess>`: the default and ceiling for every vhost (#1028).
    #[serde(rename = "htAccess", default)]
    pub(super) htaccess: Option<RawHtAccess>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVhTemplateList {
    #[serde(rename = "vhTemplate", default)]
    pub(super) vh_template: Vec<RawVhTemplate>,
}

/// Templates are not instantiated; only the presence of members matters.
#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVhTemplate {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) member: Vec<RawVhTemplateMember>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVhTemplateMember {
    #[serde(rename = "vhName", default)]
    pub(super) vh_name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawQuic {
    #[serde(rename = "quicEnable", default)]
    pub(super) quic_enable: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawTuning {
    #[serde(rename = "maxConnections", default)]
    pub(super) max_connections: Option<String>,
    #[serde(rename = "connTimeout", default)]
    pub(super) conn_timeout: Option<String>,
    #[serde(rename = "maxKeepAliveReq", default)]
    pub(super) max_keep_alive_req: Option<String>,
    #[serde(rename = "keepAliveTimeout", default)]
    pub(super) keep_alive_timeout: Option<String>,
    #[serde(rename = "maxReqURLLen", default)]
    pub(super) max_req_url_len: Option<String>,
    #[serde(rename = "maxReqHeaderSize", default)]
    pub(super) max_req_header_size: Option<String>,
    #[serde(rename = "maxReqBodySize", default)]
    pub(super) max_req_body_size: Option<String>,
    #[serde(rename = "perIpRate", default)]
    pub(super) per_ip_rate: Option<u32>,
    #[serde(rename = "perIpRateWindowSecs", default)]
    pub(super) per_ip_rate_window: Option<u32>,
    #[serde(rename = "bandwidthLimit", default)]
    pub(super) bandwidth_limit: Option<u32>,
    #[serde(rename = "maxCachedFileSize", default)]
    pub(super) max_cached_file_size: Option<String>,
    #[serde(rename = "totalInMemCacheSize", default)]
    pub(super) total_in_mem_cache_size: Option<String>,
    #[serde(rename = "maxMMapFileSize", default)]
    pub(super) max_mmap_file_size: Option<String>,
    #[serde(rename = "totalMMapCacheSize", default)]
    pub(super) total_mmap_cache_size: Option<String>,
    #[serde(rename = "fileETag", default)]
    pub(super) file_etag: Option<String>,
    #[serde(rename = "enableGzipCompress", default)]
    pub(super) enable_gzip: Option<String>,
    #[serde(rename = "enableDynGzipCompress", default)]
    pub(super) enable_dyn_gzip: Option<String>,
    #[serde(rename = "enableZstdCompress", default)]
    pub(super) enable_zstd: Option<String>,
    #[serde(rename = "enableDynZstdCompress", default)]
    pub(super) enable_dyn_zstd: Option<String>,
    #[serde(rename = "enableBrCompress", default)]
    pub(super) enable_brotli: Option<String>,
    #[serde(rename = "enableDynBrCompress", default)]
    pub(super) enable_dyn_brotli: Option<String>,
    #[serde(rename = "gzipCompressLevel", default)]
    pub(super) gzip_level: Option<String>,
    #[serde(rename = "compressibleTypes", default)]
    pub(super) compressible_types: Option<String>,
    #[serde(rename = "zstdCompressLevel", default)]
    pub(super) zstd_level: Option<String>,
    #[serde(rename = "brCompressLevel", default)]
    pub(super) brotli_quality: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawExpires {
    #[serde(rename = "enableExpires", default)]
    pub(super) enable_expires: Option<String>,
    #[serde(rename = "expiresByType", default)]
    pub(super) expires_by_type: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawServerCache {
    #[serde(rename = "cacheStorePath", default)]
    pub(super) store_path: Option<String>,
    #[serde(rename = "expireInSeconds", default)]
    pub(super) expire_in_seconds: Option<String>,
    #[serde(rename = "privateExpireInSeconds", default)]
    pub(super) private_expire_in_seconds: Option<String>,
    #[serde(rename = "cacheStatusCode", default)]
    pub(super) cache_status_code: Option<String>,
    #[serde(rename = "enablePostCache", default)]
    pub(super) enable_post_cache: Option<String>,
    #[serde(default)]
    pub(super) storage: Option<RawServerCacheStorage>,
    #[serde(rename = "cachePolicy", default)]
    pub(super) cache_policy: Option<RawServerCachePolicy>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawServerCacheStorage {
    #[serde(rename = "cacheStorePath", default)]
    pub(super) store_path: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawServerCachePolicy {
    #[serde(rename = "expireInSeconds", default)]
    pub(super) expire_in_seconds: Option<String>,
    #[serde(rename = "privateExpireInSeconds", default)]
    pub(super) private_expire_in_seconds: Option<String>,
    #[serde(rename = "cacheStatusCode", default)]
    pub(super) cache_status_code: Option<String>,
    #[serde(rename = "enablePostCache", default)]
    pub(super) enable_post_cache: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVhostCache {
    #[serde(rename = "enableCache", default)]
    pub(super) enable_cache: Option<String>,
    #[serde(rename = "cachePolicy", default)]
    pub(super) cache_policy: Option<RawCachePolicy>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawCachePolicy {
    #[serde(rename = "enablePublicCache", default)]
    pub(super) enable_public: Option<String>,
    #[serde(rename = "enablePrivateCache", default)]
    pub(super) enable_private: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawSecurity {
    #[serde(rename = "fileAccessControl", default)]
    pub(super) file_access_control: Option<RawFileAccessControl>,
    #[serde(rename = "accessDenyDir", default)]
    pub(super) access_deny_dir: Option<RawAccessDenyDir>,
    #[serde(rename = "accessControl", default)]
    pub(super) access_control: Option<RawAccessControl>,
    #[serde(rename = "CGIRLimit", default)]
    pub(super) cgi_rlimit: Option<RawCgiRLimit>,
    // (Tier 2) httpjet-native GeoIP/ASN ACL: label lists resolved against a
    // CidrList file at state build (see hj-geo / hj_acl::GeoRules).
    #[serde(rename = "geoipDBFile", default)]
    pub(super) geo_db_file: Option<String>,
    #[serde(rename = "geoAllow", default)]
    pub(super) geo_allow: Option<String>,
    #[serde(rename = "geoDeny", default)]
    pub(super) geo_deny: Option<String>,
    #[serde(rename = "asnAllow", default)]
    pub(super) asn_allow: Option<String>,
    #[serde(rename = "asnDeny", default)]
    pub(super) asn_deny: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawCgiRLimit {
    #[serde(rename = "CPUSoftLimit", default)]
    pub(super) cpu_soft_limit: Option<String>,
    #[serde(rename = "CPUHardLimit", default)]
    pub(super) cpu_hard_limit: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawFileAccessControl {
    #[serde(rename = "followSymbolLink", default)]
    pub(super) follow_symbol_link: Option<String>,
    /// Read only to refuse it when enabled: httpjet does not enforce ownership.
    #[serde(rename = "forceStrictOwnership", default)]
    pub(super) force_strict_ownership: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawAccessDenyDir {
    #[serde(default)]
    pub(super) dir: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawAccessControl {
    #[serde(default)]
    pub(super) allow: Option<String>,
    #[serde(default)]
    pub(super) deny: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawSuExec {
    #[serde(default)]
    pub(super) enable: Option<String>,
    #[serde(rename = "uidMin", default)]
    pub(super) uid_min: Option<String>,
    #[serde(rename = "gidMin", default)]
    pub(super) gid_min: Option<String>,
    /// Optional server-wide `<namespace>` block (Phase 5a). Absent => OFF.
    #[serde(default)]
    pub(super) namespace: Option<RawNamespace>,
}

/// A `<namespace>` block: master `enable` plus per-namespace flags. Each is a
/// LiteSpeed-style truthy string (`1`/`true`). Absent flag => `false`.
#[derive(Debug, Deserialize, Default)]
pub(super) struct RawNamespace {
    #[serde(default)]
    pub(super) enable: Option<String>,
    #[serde(default)]
    pub(super) mount: Option<String>,
    #[serde(default)]
    pub(super) pid: Option<String>,
    #[serde(default)]
    pub(super) net: Option<String>,
    #[serde(default)]
    pub(super) uts: Option<String>,
    #[serde(default)]
    pub(super) ipc: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawExtList {
    #[serde(rename = "extProcessor", default)]
    pub(super) ext_processor: Vec<RawExtProcessor>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawExtProcessor {
    #[serde(rename = "healthCheck", default)]
    pub(super) health_check: Option<RawHealthCheck>,
    #[serde(rename = "loadBalancePolicy", default)]
    pub(super) load_balance_policy: Option<String>,
    #[serde(rename = "addressWeights", default)]
    pub(super) address_weights: Option<String>,
    #[serde(rename = "type", default)]
    pub(super) kind: Option<String>,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) address: Vec<String>,
    #[serde(rename = "maxConns", default)]
    pub(super) max_conns: Option<String>,
    #[serde(rename = "pcKeepAliveTimeout", default)]
    pub(super) pc_keep_alive_timeout: Option<String>,
    #[serde(rename = "initTimeout", default)]
    pub(super) init_timeout: Option<String>,
    #[serde(rename = "retryTimeout", default)]
    pub(super) retry_timeout: Option<String>,
    #[serde(rename = "respBuffer", default)]
    pub(super) resp_buffer: Option<String>,
    #[serde(rename = "clientCertFile", default)]
    pub(super) client_cert_file: Option<String>,
    #[serde(rename = "clientKeyFile", default)]
    pub(super) client_key_file: Option<String>,
    #[serde(default)]
    pub(super) env: Vec<String>,
    #[serde(rename = "autoStart", default)]
    pub(super) auto_start: Option<String>,
    #[serde(default)]
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) backlog: Option<String>,
    #[serde(default)]
    pub(super) instances: Option<String>,
    #[serde(rename = "runOnStartUp", default)]
    pub(super) run_on_startup: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawHealthCheck {
    pub(super) mode: Option<String>,
    pub(super) interval: Option<String>,
    pub(super) timeout: Option<String>,
    pub(super) rise: Option<String>,
    pub(super) fall: Option<String>,
    pub(super) path: Option<String>,
    pub(super) host: Option<String>,
    #[serde(rename = "expectedStatus", default)]
    pub(super) expected_status: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawPhpConfig {
    #[serde(rename = "detachedMode", default)]
    pub(super) detached_mode: Option<String>,
    /// LSWS `setRepeated('id')`: one entry per handler (#1027).
    #[serde(rename = "phpHandler", default)]
    pub(super) php_handler: Vec<RawPhpHandler>,
    #[serde(default)]
    pub(super) env: Vec<String>,
    #[serde(rename = "maxConns", default)]
    pub(super) max_conns: Option<String>,
    #[serde(rename = "initTimeout", default)]
    pub(super) init_timeout: Option<String>,
    #[serde(rename = "retryTimeout", default)]
    pub(super) retry_timeout: Option<String>,
    #[serde(rename = "pcKeepAliveTimeout", default)]
    pub(super) pc_keep_alive_timeout: Option<String>,
    #[serde(default)]
    pub(super) backlog: Option<String>,
    #[serde(rename = "runOnStartUp", default)]
    pub(super) run_on_startup: Option<String>,
    #[serde(rename = "memSoftLimit", default)]
    pub(super) mem_soft_limit: Option<String>,
    #[serde(rename = "memHardLimit", default)]
    pub(super) mem_hard_limit: Option<String>,
    #[serde(rename = "maxProcessTime", default)]
    pub(super) max_process_time: Option<String>,
    #[serde(rename = "procSoftLimit", default)]
    pub(super) proc_soft_limit: Option<String>,
    #[serde(rename = "procHardLimit", default)]
    pub(super) proc_hard_limit: Option<String>,
    #[serde(rename = "extMaxIdleTime", default)]
    pub(super) max_idle_time: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawPhpHandler {
    #[serde(default)]
    pub(super) id: Option<String>,
    #[serde(default)]
    pub(super) command: Option<String>,
    #[serde(default)]
    pub(super) suffixes: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVHostList {
    #[serde(rename = "virtualHost", default)]
    pub(super) vhost: Vec<RawVHostDecl>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVHostDecl {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(rename = "vhRoot", default)]
    pub(super) vh_root: Option<String>,
    #[serde(rename = "configFile", default)]
    pub(super) config_file: Option<String>,
    #[serde(rename = "allowSymbolLink", default)]
    pub(super) allow_symbol_link: Option<String>,
    #[serde(rename = "enableScript", default)]
    pub(super) enable_script: Option<String>,
    /// (#249 drift class) LSWS `restrained`: confine the vhost to its vhRoot.
    #[serde(default)]
    pub(super) restrained: Option<String>,
    /// OLS auto-maps a vhost to these listeners; httpjet only maps through
    /// `<vhostMapList>`, so a declared value is refused (#921).
    #[serde(default)]
    pub(super) listeners: Option<String>,
    #[serde(default)]
    pub(super) enabled: Option<String>,
    /// Read only to refuse it when enabled (see the server-level field).
    #[serde(rename = "forceStrictOwnership", default)]
    pub(super) force_strict_ownership: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawListenerList {
    #[serde(default)]
    pub(super) listener: Vec<RawListener>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawListener {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) address: Option<String>,
    #[serde(default)]
    pub(super) secure: Option<String>,
    #[serde(rename = "vhostMapList", default)]
    pub(super) vhost_map_list: Option<RawVhostMapList>,
    #[serde(rename = "keyFile", default)]
    pub(super) key_file: Option<String>,
    #[serde(rename = "certFile", default)]
    pub(super) cert_file: Option<String>,
    #[serde(rename = "certChain", default)]
    pub(super) cert_chain: Option<String>,
    #[serde(rename = "CACertFile", default)]
    pub(super) ca_cert_file: Option<String>,
    #[serde(rename = "proxyProtocol", default)]
    pub(super) proxy_protocol: Option<String>,
    #[serde(rename = "proxyProtocolPeers", default)]
    pub(super) proxy_protocol_peers: Option<String>,
    #[serde(rename = "crlFile", default)]
    pub(super) crl_file: Option<String>,
    #[serde(rename = "enableStapling", default)]
    pub(super) enable_stapling: Option<String>,
    #[serde(rename = "clientVerify", default)]
    pub(super) client_verify: Option<String>,
    #[serde(rename = "verifyDepth", default)]
    pub(super) verify_depth: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVhostMapList {
    #[serde(rename = "vhostMap", default)]
    pub(super) vhost_map: Vec<RawVhostMap>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVhostMap {
    #[serde(default)]
    pub(super) vhost: Option<String>,
    #[serde(default)]
    pub(super) domain: Option<String>,
}

// --- per-vhost file ---

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVHostConfig {
    #[serde(rename = "docRoot", default)]
    pub(super) doc_root: Option<String>,
    #[serde(rename = "indexFiles", default)]
    pub(super) index_files: Option<String>,
    /// Flat-form companion of `<indexFiles>` (OLS `indexFiles_useServer`).
    #[serde(rename = "indexFiles_useServer", default)]
    pub(super) index_files_use_server: Option<String>,
    /// The `<index>` block the LSWS webadmin writes (OLS `configIndex`).
    #[serde(default)]
    pub(super) index: Option<RawIndex>,
    #[serde(rename = "allowSymbolLink", default)]
    pub(super) allow_symbol_link: Option<String>,
    #[serde(default)]
    pub(super) rewrite: Option<RawRewrite>,
    #[serde(rename = "htAccess", default)]
    pub(super) htaccess: Option<RawHtAccess>,
    #[serde(rename = "scriptHandlerList", default)]
    pub(super) script_handler_list: Option<RawScriptHandlerList>,
    #[serde(rename = "contextList", default)]
    pub(super) context_list: Option<RawContextList>,
    #[serde(rename = "websocketList", default)]
    pub(super) websocket_list: Option<RawWebsocketList>,
    #[serde(default)]
    pub(super) vhssl: Option<RawVhSsl>,
    #[serde(default)]
    pub(super) expires: Option<RawExpires>,
    #[serde(default)]
    pub(super) cache: Option<RawVhostCache>,
    #[serde(rename = "extProcessorList", default)]
    pub(super) ext_processor_list: Option<RawExtList>,
    // --- per-vhost suEXEC isolation ---
    #[serde(rename = "setUIDMode", default)]
    pub(super) set_uid_mode: Option<String>,
    #[serde(rename = "chrootMode", default)]
    pub(super) chroot_mode: Option<String>,
    #[serde(rename = "chrootPath", default)]
    pub(super) chroot_path: Option<String>,
    #[serde(rename = "suexecUser", default)]
    pub(super) suexec_user: Option<String>,
    #[serde(rename = "suexecGroup", default)]
    pub(super) suexec_group: Option<String>,
    /// Optional per-vhost `<namespace>` override (Phase 5a). Absent => inherit
    /// the server policy.
    #[serde(default)]
    pub(super) namespace: Option<RawNamespace>,
    /// (#248) Per-vhost `<logging>` block (error `<log>` + `<accessLog>`).
    #[serde(default)]
    pub(super) logging: Option<RawLogging>,
    #[serde(default)]
    pub(super) security: Option<RawVhostSecurity>,
    #[serde(rename = "realmList", default)]
    pub(super) realm_list: Option<RawRealmList>,
    /// Root-level form, read by OLS when `<security>` is absent.
    #[serde(rename = "accessControl", default)]
    pub(super) access_control: Option<RawScopedAccessControl>,
    #[serde(rename = "vhDomain", default)]
    pub(super) vh_domain: Option<String>,
    // Not implemented: parsed only so a non-empty block refuses the load (#925).
    #[serde(rename = "phpIniOverride", default)]
    pub(super) php_ini_override: Option<String>,
    #[serde(rename = "customErrorPages", default)]
    pub(super) custom_error_pages: Option<RawCustomErrorPages>,
    #[serde(rename = "apacheConf", default)]
    pub(super) apache_conf: Option<String>,
    #[serde(default)]
    pub(super) enabled: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawCustomErrorPages {
    #[serde(rename = "errorPage", default)]
    pub(super) error_page: Vec<RawErrorPage>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawErrorPage {
    #[serde(rename = "errCode", default)]
    pub(super) err_code: Option<String>,
    #[serde(default)]
    pub(super) url: Option<String>,
}

/// (#248) One `<logging>` block: an error-log spec plus an access-log spec, each
/// carrying `useServer` (0 = this vhost's OWN file), a file path, and LiteSpeed
/// rolling parameters.
#[derive(Debug, Deserialize, Default)]
pub(super) struct RawLogging {
    #[serde(rename = "log", default)]
    pub(super) log: Option<RawLogFileSpec>,
    #[serde(rename = "accessLog", default)]
    pub(super) access_log: Option<RawAccessLogSpec>,
}

/// Shared shape of `<log>` / `<accessLog>` children.
#[derive(Debug, Deserialize, Default)]
pub(super) struct RawLogFileSpec {
    #[serde(rename = "useServer", default)]
    pub(super) use_server: Option<String>,
    #[serde(rename = "fileName", default)]
    pub(super) file_name: Option<String>,
    #[serde(rename = "rollingSize", default)]
    pub(super) rolling_size: Option<String>,
    #[serde(rename = "keepDays", default)]
    pub(super) keep_days: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawAccessLogSpec {
    #[serde(rename = "useServer", default)]
    pub(super) use_server: Option<String>,
    #[serde(rename = "fileName", default)]
    pub(super) file_name: Option<String>,
    #[serde(rename = "rollingSize", default)]
    pub(super) rolling_size: Option<String>,
    #[serde(rename = "keepDays", default)]
    pub(super) keep_days: Option<String>,
    /// LSWS bitmask; bit 0 = request line + Referer/UA, higher bits add header
    /// capture. Nonzero ⇒ httpjet emits the request headers with each record.
    #[serde(rename = "logHeaders", default)]
    pub(super) log_headers: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawRewrite {
    #[serde(default)]
    pub(super) enable: Option<String>,
    #[serde(rename = "autoLoadHtaccess", default)]
    pub(super) auto_load_htaccess: Option<String>,
    #[serde(default)]
    pub(super) base: Option<String>,
    #[serde(default)]
    pub(super) rules: Option<String>,
    /// OLS `configRewriteMap`; maps are not implemented, so a declared one
    /// refuses the load (#1030).
    #[serde(default)]
    pub(super) map: Vec<RawRewriteMap>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawRewriteMap {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) location: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawHtAccess {
    #[serde(rename = "allowOverride", default)]
    pub(super) allow_override: Option<String>,
    #[serde(rename = "accessFileName", default)]
    pub(super) access_file_name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawScriptHandlerList {
    #[serde(rename = "scriptHandler", default)]
    pub(super) script_handler: Vec<RawScriptHandler>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawScriptHandler {
    #[serde(default)]
    pub(super) suffix: Option<String>,
    #[serde(rename = "type", default)]
    pub(super) kind: Option<String>,
    #[serde(default)]
    pub(super) handler: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawContextList {
    #[serde(default)]
    pub(super) context: Vec<RawContext>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawContext {
    #[serde(rename = "type", default)]
    pub(super) kind: Option<String>,
    #[serde(default)]
    pub(super) uri: Option<String>,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) handler: Option<String>,
    #[serde(default)]
    pub(super) enabled: Option<String>,
    #[serde(rename = "allowBrowse", default)]
    pub(super) allow_browse: Option<String>,
    #[serde(rename = "extraHeaders", default)]
    pub(super) extra_headers: Option<String>,
    #[serde(rename = "addDefaultCharset", default)]
    pub(super) add_default_charset: Option<String>,
    #[serde(
        rename = "defaultCharsetCustomized",
        alias = "addDefaultCharsetCustomized",
        default
    )]
    pub(super) charset: Option<String>,
    // httpjet-native per-context resource controls. Keep the raw strings so
    // conversion can distinguish an absent directive from an explicit zero
    // and reject malformed values instead of silently applying a default.
    #[serde(rename = "maxReqBodySize", default)]
    pub(super) max_req_body_size: Option<String>,
    #[serde(rename = "bandwidthLimit", default)]
    pub(super) bandwidth_limit: Option<String>,
    #[serde(rename = "responseTimeout", default)]
    pub(super) response_timeout: Option<String>,
    /// (#249) LSWS six-flag context `<cachePolicy>` (+ microCache5xx).
    #[serde(rename = "cachePolicy", default)]
    pub(super) cache_policy: Option<RawContextCachePolicy>,
    // (Tier 2) httpjet-native sub_filter block: repeatable
    // `<subFilter>SEARCH => REPLACEMENT</subFilter>` plus modifiers.
    #[serde(rename = "subFilter", default)]
    pub(super) sub_filter: Vec<String>,
    #[serde(rename = "subFilterOnce", default)]
    pub(super) sub_filter_once: Option<String>,
    #[serde(rename = "subFilterTypes", default)]
    pub(super) sub_filter_types: Option<String>,
    #[serde(rename = "subFilterMaxBody", default)]
    pub(super) sub_filter_max_body: Option<String>,
    // Context access control and HTTP auth are not enforced; parsed only so a
    // declared policy rejects the config instead of being dropped.
    #[serde(rename = "accessControl", default)]
    pub(super) access_control: Option<RawScopedAccessControl>,
    #[serde(default)]
    pub(super) realm: Option<String>,
    #[serde(default)]
    pub(super) required: Option<String>,
    #[serde(default)]
    pub(super) authorizer: Option<String>,
    #[serde(default)]
    pub(super) auth: Option<RawContextAuth>,
    #[serde(rename = "phpIniOverride", default)]
    pub(super) php_ini_override: Option<String>,
    #[serde(rename = "customErrorPages", default)]
    pub(super) custom_error_pages: Option<RawCustomErrorPages>,
    // Not implemented per context: parsed only so a declared one refuses the
    // load instead of being dropped (#999).
    #[serde(default)]
    pub(super) rewrite: Option<RawRewrite>,
    #[serde(rename = "apacheConf", default)]
    pub(super) apache_conf: Option<String>,
    #[serde(rename = "forceType", default)]
    pub(super) force_type: Option<String>,
    #[serde(rename = "addMIMEType", default)]
    pub(super) add_mime_type: Option<String>,
    #[serde(rename = "allowOverride", default)]
    pub(super) allow_override: Option<String>,
}

/// OLS reads a context's realm from an `<auth>` child when present.
#[derive(Debug, Deserialize, Default)]
pub(super) struct RawContextAuth {
    #[serde(default)]
    pub(super) realm: Option<String>,
    #[serde(default)]
    pub(super) required: Option<String>,
}

/// Vhost/context `<accessControl>`; `allowList`/`denyList` are accepted
/// spellings so they cannot slip past the fail-closed check either.
#[derive(Debug, Deserialize, Default)]
pub(super) struct RawScopedAccessControl {
    #[serde(default, alias = "allowList")]
    pub(super) allow: Vec<String>,
    #[serde(default, alias = "denyList")]
    pub(super) deny: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVhostSecurity {
    #[serde(rename = "accessControl", default)]
    pub(super) access_control: Option<RawScopedAccessControl>,
    #[serde(rename = "realmList", default)]
    pub(super) realm_list: Option<RawRealmList>,
    /// Read only to refuse it when enabled: httpjet has no hotlink protection.
    #[serde(rename = "hotlinkCtrl", default)]
    pub(super) hotlink_ctrl: Option<RawHotlinkCtrl>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawHotlinkCtrl {
    #[serde(rename = "enableHotlinkCtrl", default)]
    pub(super) enable: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawRealmList {
    #[serde(default)]
    pub(super) realm: Vec<RawRealm>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawRealm {
    #[serde(default)]
    pub(super) name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawContextCachePolicy {
    #[serde(rename = "checkPublicCache", default)]
    pub(super) check_public_cache: Option<String>,
    #[serde(rename = "checkPrivateCache", default)]
    pub(super) check_private_cache: Option<String>,
    #[serde(rename = "respectCacheable", default)]
    pub(super) respect_cacheable: Option<String>,
    #[serde(rename = "enableCache", default)]
    pub(super) enable_cache: Option<String>,
    #[serde(rename = "enablePrivateCache", default)]
    pub(super) enable_private_cache: Option<String>,
    #[serde(rename = "enablePostCache", default)]
    pub(super) enable_post_cache: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawWebsocketList {
    #[serde(default)]
    pub(super) websocket: Vec<RawWebsocket>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawWebsocket {
    #[serde(default)]
    pub(super) uri: Option<String>,
    #[serde(default)]
    pub(super) address: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawVhSsl {
    #[serde(rename = "keyFile", default)]
    pub(super) key_file: Option<String>,
    #[serde(rename = "certFile", default)]
    pub(super) cert_file: Option<String>,
    #[serde(rename = "certChain", default)]
    pub(super) cert_chain: Option<String>,
    #[serde(rename = "CACertFile", default)]
    pub(super) ca_cert_file: Option<String>,
    // Client-certificate verification is listener-only in httpjet; parsed so a
    // vhost that requires it refuses the load (#1029).
    #[serde(rename = "clientVerify", default)]
    pub(super) client_verify: Option<String>,
    #[serde(rename = "verifyDepth", default)]
    pub(super) verify_depth: Option<String>,
    #[serde(rename = "crlFile", default)]
    pub(super) crl_file: Option<String>,
    #[serde(rename = "CACertPath", default)]
    pub(super) ca_cert_path: Option<String>,
}

/// `<index><useServer/><indexFiles/><autoIndex/></index>`.
#[derive(Debug, Deserialize, Default)]
pub(super) struct RawIndex {
    #[serde(rename = "useServer", default)]
    pub(super) use_server: Option<String>,
    #[serde(rename = "indexFiles", default)]
    pub(super) index_files: Option<String>,
    #[serde(rename = "autoIndex", default)]
    pub(super) auto_index: Option<String>,
}
