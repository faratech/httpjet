//! Parse LiteSpeed XML config into the normalized [`crate::model`] types.
//!
//! Strategy: deserialize the XML into permissive "raw" structs with `quick-xml`
//! (every field optional), then convert to the clean model, applying `$VAR`
//! substitution and interpreting unions/booleans. The raw layer absorbs the
//! liberal/legacy XML LiteSpeed tolerates (empty elements, missing fields).

mod raw;
mod scalar;
mod vhost;

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{ConfigError, Result};
use crate::model::*;
use crate::subst::SubstCtx;
use crate::units::{parse_bytes, parse_secs, split_list};

use raw::*;
use scalar::*;

#[cfg(test)]
pub(crate) use vhost::parse_vhost_config;
use vhost::{convert_vhost_decls, load_vhost_files};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load the full server config rooted at `server_root` (e.g. `/usr/local/lsws`),
/// reading `conf/httpd_config.xml` and every referenced vhost file.
pub fn load(server_root: impl AsRef<Path>) -> Result<ServerConfig> {
    let server_root = server_root.as_ref().to_path_buf();
    let main = server_root.join("conf/httpd_config.xml");
    let mut cfg = load_server_file(&server_root, &main)?;
    load_vhost_files(&mut cfg)?;
    // mime.properties (best-effort; absence is not fatal)
    let mime_path = server_root.join("conf/mime.properties");
    if let Ok(text) = std::fs::read_to_string(&mime_path) {
        cfg.mime = parse_mime(&text);
    }
    Ok(cfg)
}

/// Parse just the server file (no vhost-file loading); useful for tests.
pub(crate) fn load_server_file(server_root: &Path, path: &Path) -> Result<ServerConfig> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let raw: RawServer = quick_xml::de::from_str(&text).map_err(|e| ConfigError::Xml {
        path: path.to_path_buf(),
        msg: e.to_string(),
    })?;

    let hostname = nonempty(raw.server_name.clone())
        .filter(|s| !s.contains('$'))
        .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into()));
    let ctx = SubstCtx {
        server_root: server_root.to_string_lossy().into_owned(),
        hostname: hostname.clone(),
        ..Default::default()
    };

    let tuning = convert_tuning(raw.tuning.unwrap_or_default());
    let expires = convert_expires(raw.expires);
    let cache = convert_server_cache(raw.cache);
    let security = convert_security(raw.security, &ctx);
    let suexec = convert_suexec(raw.suexec);
    let ext_processors = convert_ext_list(raw.ext_processor_list, &ctx);
    let php_config = raw
        .php_config
        .map(|p| convert_php(p, &ctx, security.cgi_cpu_limit_secs));
    let listeners = convert_listeners(raw.listener_list, &ctx);
    let (vhosts, vhost_order) = convert_vhost_decls(raw.vhost_list, &ctx);

    Ok(ServerConfig {
        server_root: server_root.to_path_buf(),
        server_name: hostname,
        user: nonempty(raw.user).unwrap_or_else(|| "nobody".into()),
        group: nonempty(raw.group).unwrap_or_else(|| "nobody".into()),
        index_files: raw
            .index_files
            .as_deref()
            .map(split_list)
            .unwrap_or_else(|| vec!["index.html".into()]),
        tuning,
        quic_enable: raw.quic.map(|q| truthy(&q.quic_enable)).unwrap_or(false),
        // OLS: getLongValue(pRoot,"useIpInProxyHeader",0,4,2) — range 0..=4,
        // default 2 when absent/invalid (NOT 0). See httpserver.cpp:3478.
        use_ip_in_proxy_header: bounded_u8(&raw.use_ip_in_proxy_header, 0, 4, 2),
        expires,
        cache,
        security,
        suexec,
        ext_processors,
        php_config,
        listeners,
        vhosts,
        vhost_order,
        mime: MimeMap::default(),
    })
}

fn convert_tuning(r: RawTuning) -> Tuning {
    let d = Tuning::default();
    Tuning {
        max_connections: u32_of(&r.max_connections, d.max_connections),
        conn_timeout: secs_of(&r.conn_timeout, 60),
        keep_alive_timeout: secs_of(&r.keep_alive_timeout, 5),
        max_keep_alive_req: u32_of(&r.max_keep_alive_req, d.max_keep_alive_req),
        max_req_url_len: bytes_of(&r.max_req_url_len, d.max_req_url_len as u64) as usize,
        max_req_header_size: bytes_of(&r.max_req_header_size, d.max_req_header_size as u64)
            as usize,
        max_req_body_size: bytes_of(&r.max_req_body_size, d.max_req_body_size),
        max_cached_file_size: bytes_of(&r.max_cached_file_size, d.max_cached_file_size),
        total_in_mem_cache_size: bytes_of(&r.total_in_mem_cache_size, d.total_in_mem_cache_size),
        max_mmap_file_size: bytes_of(&r.max_mmap_file_size, d.max_mmap_file_size),
        total_mmap_cache_size: bytes_of(&r.total_mmap_cache_size, d.total_mmap_cache_size),
        // OLS: getLongValue(pNode,"fileETag",0,28,28) — bits INODE=4|MTIME=8|
        // SIZE=16 (ALL=28). Out-of-range falls back to 28. See httpserver.cpp:2770.
        file_etag: bounded_u8(&r.file_etag, 0, 28, d.file_etag as u8) as u32,
        enable_gzip: r
            .enable_gzip
            .as_ref()
            .map(|_| truthy(&r.enable_gzip))
            .unwrap_or(true),
        enable_dyn_gzip: r
            .enable_dyn_gzip
            .as_ref()
            .map(|_| truthy(&r.enable_dyn_gzip))
            .unwrap_or(true),
        enable_zstd: r
            .enable_zstd
            .as_ref()
            .map(|_| truthy(&r.enable_zstd))
            .unwrap_or(true),
        enable_dyn_zstd: r
            .enable_dyn_zstd
            .as_ref()
            .map(|_| truthy(&r.enable_dyn_zstd))
            .unwrap_or(true),
        enable_brotli: r
            .enable_brotli
            .as_ref()
            .map(|_| truthy(&r.enable_brotli))
            .unwrap_or(true),
        enable_dyn_brotli: r
            .enable_dyn_brotli
            .as_ref()
            .map(|_| truthy(&r.enable_dyn_brotli))
            .unwrap_or(true),
        // OLS-style bounded parse: out-of-range/absent falls back to the default.
        zstd_level: bounded_u8(&r.zstd_level, 1, 22, 3) as u32,
        brotli_quality: bounded_u8(&r.brotli_quality, 0, 11, 5) as u32,
        per_ip_rate: r.per_ip_rate.unwrap_or(0),
        per_ip_rate_window: std::time::Duration::from_secs(
            u64::from(r.per_ip_rate_window.unwrap_or(1)).max(1),
        ),
        bandwidth_limit: u64::from(r.bandwidth_limit.unwrap_or(0)),
    }
}

fn convert_expires(r: Option<RawExpires>) -> ExpiresConfig {
    let r = match r {
        Some(r) => r,
        None => return ExpiresConfig::default(),
    };
    ExpiresConfig {
        enabled: truthy(&r.enable_expires),
        by_type: r
            .expires_by_type
            .as_deref()
            .map(parse_expires_by_type)
            .unwrap_or_default(),
    }
}

fn convert_server_cache(r: Option<RawServerCache>) -> CacheConfig {
    let r = match r {
        Some(r) => r,
        None => return CacheConfig::default(),
    };
    let d = CacheConfig::default();
    let store_path = r
        .store_path
        .or_else(|| r.storage.as_ref().and_then(|s| s.store_path.clone()));
    let expire_in_seconds = r.expire_in_seconds.or_else(|| {
        r.cache_policy
            .as_ref()
            .and_then(|p| p.expire_in_seconds.clone())
    });
    let private_expire_in_seconds = r.private_expire_in_seconds.or_else(|| {
        r.cache_policy
            .as_ref()
            .and_then(|p| p.private_expire_in_seconds.clone())
    });
    let cache_status_code = r.cache_status_code.or_else(|| {
        r.cache_policy
            .as_ref()
            .and_then(|p| p.cache_status_code.clone())
    });
    let enable_post_cache = r.enable_post_cache.or_else(|| {
        r.cache_policy
            .as_ref()
            .and_then(|p| p.enable_post_cache.clone())
    });
    CacheConfig {
        store_path: nonempty(store_path)
            .map(PathBuf::from)
            .unwrap_or(d.store_path),
        default_ttl_secs: u32_of(&expire_in_seconds, d.default_ttl_secs),
        default_private_ttl_secs: u32_of(&private_expire_in_seconds, d.default_private_ttl_secs),
        cacheable_status: cache_status_code
            .as_deref()
            .map(parse_cacheable_status)
            .unwrap_or(d.cacheable_status),
        enable_post_cache: truthy(&enable_post_cache),
    }
}

fn convert_security(r: Option<RawSecurity>, ctx: &SubstCtx) -> Security {
    let r = match r {
        Some(r) => r,
        None => return Security::default(),
    };
    let access_deny_dir = r
        .access_deny_dir
        .map(|d| d.dir.into_iter().map(|s| ctx.expand(s.trim())).collect())
        .unwrap_or_default();
    let mut access_control = Vec::new();
    if let Some(ac) = r.access_control {
        if let Some(allow) = ac.allow {
            access_control.extend(parse_access(&allow, true));
        }
        if let Some(deny) = ac.deny {
            access_control.extend(parse_access(&deny, false));
        }
    }
    let follow_symlink = r
        .file_access_control
        .as_ref()
        .map(|f| follow_symlink_value(&f.follow_symbol_link))
        .unwrap_or(false);
    let cgi_cpu_limit_secs = r.cgi_rlimit.and_then(|rl| {
        let pair = RlimitPair {
            soft: rl.cpu_soft_limit.as_deref().and_then(parse_pos_u64),
            hard: rl.cpu_hard_limit.as_deref().and_then(parse_pos_u64),
        };
        (!pair.is_empty()).then_some(pair)
    });
    let split_labels = |v: &Option<String>| -> Vec<String> {
        v.as_deref()
            .map(|s| {
                s.split([',', ' ', '\t'])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let parse_asns = |v: &Option<String>| -> Vec<u32> {
        split_labels(v)
            .into_iter()
            .filter_map(|s| s.trim_start_matches("AS").parse::<u32>().ok())
            .collect()
    };
    Security {
        follow_symlink,
        access_deny_dir,
        access_control,
        cgi_cpu_limit_secs,
        geo_db_file: r
            .geo_db_file
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .map(|p| PathBuf::from(ctx.expand(&p.to_string_lossy()))),
        geo_allow: split_labels(&r.geo_allow),
        geo_deny: split_labels(&r.geo_deny),
        asn_allow: parse_asns(&r.asn_allow),
        asn_deny: parse_asns(&r.asn_deny),
    }
}

/// Convert the server `<suexec>` block into a [`SuExecPolicy`]. Absent block →
/// the all-default OFF policy (`enable=false`, `uid_min=100`, `gid_min=100`).
/// `uidMin`/`gidMin` mirror OLS `ServerProcessConfig` defaults of 100.
fn convert_suexec(r: Option<RawSuExec>) -> SuExecPolicy {
    let r = match r {
        Some(r) => r,
        None => return SuExecPolicy::default(),
    };
    let d = SuExecPolicy::default();
    SuExecPolicy {
        enable: truthy(&r.enable),
        uid_min: u32_of(&r.uid_min, d.uid_min),
        gid_min: u32_of(&r.gid_min, d.gid_min),
        // Absent <namespace> block => the all-default OFF policy.
        namespaces: convert_namespace(r.namespace).unwrap_or_default(),
    }
}

/// Convert a `<namespace>` block into a [`NamespacePolicy`]. Returns `None` when
/// the block is absent (the caller decides what an absent block means: the
/// server falls back to the OFF default; a per-vhost override inherits). Per-flag
/// values use the same LiteSpeed `truthy` parse as the rest of the config, so
/// `1`/`true` enable a flag and anything else (or absence) leaves it `false`.
fn convert_namespace(r: Option<RawNamespace>) -> Option<NamespacePolicy> {
    let r = r?;
    Some(NamespacePolicy {
        enable: truthy(&r.enable),
        mount: truthy(&r.mount),
        pid: truthy(&r.pid),
        net: truthy(&r.net),
        uts: truthy(&r.uts),
        ipc: truthy(&r.ipc),
    })
}

fn convert_ext_list(r: Option<RawExtList>, ctx: &SubstCtx) -> Vec<ExtProcessor> {
    let r = match r {
        Some(r) => r,
        None => return Vec::new(),
    };
    r.ext_processor
        .into_iter()
        .filter_map(|e| convert_ext(e, ctx))
        .collect()
}

fn convert_ext(e: RawExtProcessor, ctx: &SubstCtx) -> Option<ExtProcessor> {
    let name = nonempty(e.name)?;
    let kind = match e.kind.as_deref().map(str::trim) {
        Some("lsapi") => ExtKind::Lsapi,
        _ => ExtKind::Proxy,
    };
    // (Tier 1.2) Every <address> element is a peer; the first is primary and the
    // rest are failover peers tried in order when the primary's breaker is open.
    let mut addr_iter = e.address.iter().map(|s| ext_address(s.as_str()));
    let address = addr_iter.next().unwrap_or(ext_address(""));
    let extra_addresses: Vec<_> = addr_iter.collect();
    Some(ExtProcessor {
        name,
        kind,
        address,
        extra_addresses,
        client_cert_file: nonempty(e.client_cert_file).map(|p| PathBuf::from(ctx.expand(&p))),
        client_key_file: nonempty(e.client_key_file).map(|p| PathBuf::from(ctx.expand(&p))),
        max_conns: u32_of(&e.max_conns, 100),
        init_timeout: secs_of(&e.init_timeout, 60),
        retry_timeout: secs_of(&e.retry_timeout, 0),
        pc_keep_alive_timeout: secs_of(&e.pc_keep_alive_timeout, 60),
        resp_buffer: truthy(&e.resp_buffer),
        env: e.env.iter().filter_map(|s| parse_env_pair(s)).collect(),
        auto_start: u8_of(&e.auto_start),
        path: nonempty(e.path).map(|p| PathBuf::from(ctx.expand(&p))),
        backlog: u32_of(&e.backlog, 100),
        instances: u32_of(&e.instances, 1),
        run_on_startup: e
            .run_on_startup
            .as_deref()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
    })
}

fn convert_php(p: RawPhpConfig, ctx: &SubstCtx, cpu_limit_secs: Option<RlimitPair>) -> PhpConfig {
    let h = p.php_handler.unwrap_or_default();
    PhpConfig {
        handler_id: nonempty(h.id).unwrap_or_else(|| "php".into()),
        command: PathBuf::from(ctx.expand(h.command.as_deref().unwrap_or(""))),
        suffixes: h
            .suffixes
            .as_deref()
            .map(split_list)
            .unwrap_or_else(|| vec!["php".into()]),
        env: p.env.iter().filter_map(|s| parse_env_pair(s)).collect(),
        max_conns: u32_of(&p.max_conns, 100),
        init_timeout: secs_of(&p.init_timeout, 60),
        retry_timeout: secs_of(&p.retry_timeout, 0),
        pc_keep_alive_timeout: secs_of(&p.pc_keep_alive_timeout, 30),
        backlog: u32_of(&p.backlog, 1024),
        run_on_startup: p
            .run_on_startup
            .as_deref()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
        mem_soft_limit: p.mem_soft_limit.as_deref().and_then(parse_bytes),
        mem_hard_limit: p.mem_hard_limit.as_deref().and_then(parse_bytes),
        detached_mode: truthy(&p.detached_mode),
        // LiteSpeed maxProcessTime / extMaxIdleTime are second counts; a value
        // of 0 (or absent/garbage) means "no limit", which we map to None.
        max_process_time: p
            .max_process_time
            .as_deref()
            .and_then(parse_secs)
            .filter(|&s| s > 0)
            .map(Duration::from_secs),
        cpu_limit_secs,
        proc_soft_limit: p.proc_soft_limit.as_deref().and_then(parse_pos_u64),
        proc_hard_limit: p.proc_hard_limit.as_deref().and_then(parse_pos_u64),
        max_idle_time: p
            .max_idle_time
            .as_deref()
            .and_then(parse_secs)
            .filter(|&s| s > 0)
            .map(Duration::from_secs),
        min_restart_interval: Duration::from_secs(10),
        max_restart_backoff: Duration::from_secs(30),
    }
}

fn convert_listeners(r: Option<RawListenerList>, ctx: &SubstCtx) -> Vec<Listener> {
    let r = match r {
        Some(r) => r,
        None => return Vec::new(),
    };
    r.listener
        .into_iter()
        .filter_map(|l| {
            let name = nonempty(l.name)?;
            let address = nonempty(l.address).unwrap_or_else(|| "*:80".into());
            let secure = truthy(&l.secure);
            let vhost_map = l
                .vhost_map_list
                .map(|m| {
                    m.vhost_map
                        .into_iter()
                        .filter_map(|vm| {
                            let vhost = nonempty(vm.vhost)?;
                            // OLS mapDomainList (vhostmap.cpp:581) lowercases
                            // every domain (strnlower) before mapping, so
                            // matching is case-insensitive. The literal "*"
                            // catch-all and wildcard patterns are unaffected.
                            let domains = vm
                                .domain
                                .as_deref()
                                .map(split_list)
                                .unwrap_or_default()
                                .into_iter()
                                .map(|d| d.to_ascii_lowercase())
                                .inspect(|d| {
                                    // Only the bare "*" catch-all is a real wildcard here. A pattern
                                    // like "*.example.com" is stored as a LITERAL exact key the
                                    // router can never match (httpjet has no glob matcher, unlike
                                    // OLS), so those hosts silently fall to the "*" default vhost.
                                    // Warn at parse time so it isn't a silent misconfiguration.
                                    if crate::is_unsupported_wildcard_domain(d) {
                                        tracing::warn!(
                                            vhost = %vhost, domain = %d,
                                            "vhostMap wildcard pattern is unsupported (only the bare '*' catch-all matches) — stored as a literal key that never matches; those hosts fall to the '*' default vhost"
                                        );
                                    }
                                })
                                .collect();
                            Some(VhostMap { vhost, domains })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let tls = if secure || l.cert_file.is_some() {
                Some(ListenerTls {
                    key_file: PathBuf::from(ctx.expand(l.key_file.as_deref().unwrap_or(""))),
                    cert_file: PathBuf::from(ctx.expand(l.cert_file.as_deref().unwrap_or(""))),
                    cert_chain: truthy(&l.cert_chain),
                    ca_cert_file: nonempty(l.ca_cert_file).map(|p| PathBuf::from(ctx.expand(&p))),
                    // OLS: getLongValue(pNode,"clientVerify",0,3,0). 0=none,
                    // 1=optional, 2=require, 3=optional_no_ca. Out-of-range → 0.
                    client_verify: bounded_u8(&l.client_verify, 0, 3, 0),
                    // OLS: getLongValue(pNode,"verifyDepth",1,INT_MAX,1) — min 1,
                    // default 1, clamps above. See configctx.cpp:844.
                    verify_depth: bounded_u32_clamp_max(&l.verify_depth, 1, 1),
                    enable_stapling: truthy(&l.enable_stapling),
                    crl_file: l
                        .crl_file
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(std::path::PathBuf::from),
                })
            } else {
                None
            };
            // (Tier 2) `unix:`/`uds:` address prefix ⇒ serve HTTP over a UDS path.
            let uds_path = address
                .strip_prefix("unix:")
                .or_else(|| address.strip_prefix("uds:"))
                .map(|p| PathBuf::from(ctx.expand(p)));
            Some(Listener {
                name,
                address,
                secure,
                vhost_map,
                tls,
                uds_path,
                proxy_protocol: truthy(&l.proxy_protocol),
            })
        })
        .collect()
}

/// Parse `mime.properties`. LiteSpeed uses `mime/type = suffix1, suffix2`
/// (the side containing `/` is the type).
pub(crate) fn parse_mime(text: &str) -> MimeMap {
    let mut by_suffix = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        let (lhs, rhs) = (lhs.trim(), rhs.trim());
        let (mime, suffixes) = if lhs.contains('/') {
            (lhs, rhs)
        } else {
            (rhs, lhs)
        };
        if !mime.contains('/') {
            continue;
        }
        for suf in split_list(suffixes) {
            by_suffix.insert(suf.to_ascii_lowercase(), mime.to_string());
        }
    }
    MimeMap { by_suffix }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- (Tier 2) per-listener proxyProtocol -----

    #[test]
    fn proxy_protocol_is_per_listener_and_available_on_plain_listeners() {
        use super::raw::{RawListener, RawListenerList};
        let list = RawListenerList {
            listener: vec![
                RawListener {
                    name: Some("plain-pp".into()),
                    address: Some("127.0.0.1:8080".into()),
                    proxy_protocol: Some("1".into()),
                    ..Default::default()
                },
                RawListener {
                    name: Some("plain".into()),
                    address: Some("127.0.0.1:8081".into()),
                    ..Default::default()
                },
            ],
        };
        let listeners = convert_listeners(Some(list), &Default::default());
        assert_eq!(listeners.len(), 2);
        let pp = listeners.iter().find(|l| l.name == "plain-pp").unwrap();
        assert!(
            pp.proxy_protocol && pp.tls.is_none(),
            "a plain (non-TLS) listener can carry the flag"
        );
        let plain = listeners.iter().find(|l| l.name == "plain").unwrap();
        assert!(
            !plain.proxy_protocol,
            "the flag must not leak across listeners"
        );
    }

    // ----- useIpInProxyHeader: OLS getLongValue(...,0,4,2) -----

    #[test]
    fn use_ip_in_proxy_header_default_is_2_when_absent() {
        // OLS httpserver.cpp:3478 defaults the level to 2 (trust from trusted
        // networks), NOT 0. A config that omits the tag must still honour
        // proxy headers from trusted (Cloudflare) peers.
        assert_eq!(bounded_u8(&None, 0, 4, 2), 2);
    }

    #[test]
    fn use_ip_in_proxy_header_in_range_passes_through() {
        for v in 0u8..=4 {
            assert_eq!(bounded_u8(&Some(v.to_string()), 0, 4, 2), v);
        }
    }

    #[test]
    fn use_ip_in_proxy_header_out_of_range_falls_back_to_default() {
        // OLS returns the default (not a clamp) for out-of-range values.
        assert_eq!(bounded_u8(&Some("5".into()), 0, 4, 2), 2);
        assert_eq!(bounded_u8(&Some("99".into()), 0, 4, 2), 2);
        assert_eq!(bounded_u8(&Some("-1".into()), 0, 4, 2), 2);
        assert_eq!(bounded_u8(&Some("garbage".into()), 0, 4, 2), 2);
    }

    // ----- allowSymbolLink tri-state (audit M4) -----

    #[test]
    fn vhost_symlink_override_is_explicit_only_when_present() {
        // An explicit 0 must survive as an override (Some(false)) so load_vhost_files
        // can DENY following on this vhost while the server allows it; absent = None.
        let vh = |sym: &str| {
            format!(
                r#"<virtualHostConfig>
                    <docRoot>$VH_ROOT/html</docRoot>
                    {sym}
                </virtualHostConfig>"#
            )
        };
        let vc0 = parse_vhost_config(
            &vh("<allowSymbolLink>0</allowSymbolLink>"),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(vc0.allow_symbol_link_override, Some(false));
        let vc1 = parse_vhost_config(
            &vh("<allowSymbolLink>1</allowSymbolLink>"),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(vc1.allow_symbol_link_override, Some(true));
        let vcn = parse_vhost_config(&vh(""), &Default::default()).unwrap();
        assert_eq!(
            vcn.allow_symbol_link_override, None,
            "absent tag must inherit the server default, not force-deny"
        );
        // And the effective merge: explicit 0 beats a follow-everything server.
        assert!(!vc0.allow_symbol_link);
    }

    // ----- per-vhost <logging> (#248) -----

    #[test]
    fn vhost_logging_use_server_zero_yields_own_files() {
        // Modeled on the live windowsforum.com.xml block: useServer=0 + fileName
        // means THIS vhost writes its own files; logHeaders rides the access spec.
        let text = r#"<virtualHostConfig>
            <logging>
                <log>
                    <useServer>0</useServer>
                    <fileName>$SERVER_ROOT/logs/vh_error.log</fileName>
                    <logLevel>INFO</logLevel>
                    <rollingSize>50M</rollingSize>
                </log>
                <accessLog>
                    <useServer>0</useServer>
                    <fileName>/usr/local/lsws/logs/vh_access.log</fileName>
                    <logHeaders>7</logHeaders>
                    <rollingSize>50M</rollingSize>
                    <keepDays>3</keepDays>
                </accessLog>
            </logging>
        </virtualHostConfig>"#;
        let vc = parse_vhost_config(
            text,
            &crate::parse::SubstCtx {
                server_root: "/usr/local/lsws".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let acc = vc.access_log_file.expect("own access log parsed");
        assert_eq!(
            acc.path,
            PathBuf::from("/usr/local/lsws/logs/vh_access.log")
        );
        assert_eq!(acc.rolling_bytes, 50 * 1024 * 1024);
        assert_eq!(acc.keep_days, 3);
        assert_eq!(acc.log_headers, 7, "logHeaders must ride along");
        let err = vc.error_log_file.expect("own error log parsed");
        assert_eq!(
            err.path,
            PathBuf::from("/usr/local/lsws/logs/vh_error.log"),
            "$SERVER_ROOT must substitute"
        );
    }

    #[test]
    fn vhost_logging_absent_or_use_server_uses_unified() {
        let mk = |inner: &str| format!("<virtualHostConfig>{inner}</virtualHostConfig>");
        // Absent block entirely.
        let vc = parse_vhost_config(&mk("<docRoot>/web</docRoot>"), &Default::default()).unwrap();
        assert!(vc.access_log_file.is_none() && vc.error_log_file.is_none());
        // useServer=1 ⇒ inherit the unified logs; no separate file.
        let vc = parse_vhost_config(
            &mk(
                "<logging><accessLog><useServer>1</useServer><fileName>/tmp/a.log</fileName></accessLog></logging>",
            ),
            &Default::default(),
        )
        .unwrap();
        assert!(
            vc.access_log_file.is_none(),
            "useServer=1 must NOT create an own file"
        );
    }

    // ----- context <cachePolicy> (#249) -----

    #[test]
    fn context_cache_policy_six_flags_parse_with_lsws_defaults() {
        // Modeled on the live search.windowsforum.com.xml proxy context: all six
        // flags explicit 0 = "never check/enable any caching in this context".
        let text = r#"<virtualHostConfig>
            <contextList>
                <context>
                    <type>proxy</type>
                    <uri>/</uri>
                    <handler>fastapi</handler>
                    <cachePolicy>
                        <checkPublicCache>0</checkPublicCache>
                        <checkPrivateCache>0</checkPrivateCache>
                        <respectCacheable>0</respectCacheable>
                        <enableCache>0</enableCache>
                        <enablePrivateCache>0</enablePrivateCache>
                        <enablePostCache>0</enablePostCache>
                    </cachePolicy>
                </context>
                <context>
                    <type>static</type>
                    <uri>/assets/</uri>
                    <location>/web/assets</location>
                </context>
            </contextList>
        </virtualHostConfig>"#;
        let vc = parse_vhost_config(text, &crate::parse::SubstCtx::default()).unwrap();
        assert_eq!(vc.contexts.len(), 2);
        let p = vc.contexts[0]
            .cache_policy
            .expect("cachePolicy parsed for the proxy context");
        assert!(!p.enable_cache && !p.check_public_cache);
        assert!(!p.enable_private_cache && !p.check_private_cache);
        assert!(!p.enable_post_cache);
        // Absent block ⇒ None (inherit vhost policy), not a deny-all.
        assert!(vc.contexts[1].cache_policy.is_none());
    }

    #[test]
    fn cacheable_status_parse() {
        assert_eq!(parse_cacheable_status("200,301"), vec![200, 301]);
        assert_eq!(parse_cacheable_status("301, 200, 200"), vec![200, 301]);
        assert_eq!(parse_cacheable_status(""), vec![200, 301]); // fallback
        assert_eq!(parse_cacheable_status("garbage"), vec![200, 301]); // fallback
    }

    #[test]
    fn server_cache_defaults_when_absent() {
        let c = convert_server_cache(None);
        assert_eq!(c.default_ttl_secs, 900);
        assert_eq!(c.default_private_ttl_secs, 0);
        assert_eq!(c.cacheable_status, vec![200, 301]);
        assert!(!c.enable_post_cache);
    }

    #[test]
    fn server_cache_xml_mapping() {
        let raw: RawServerCache = quick_xml::de::from_str(
            r#"<cache>
                <cacheStorePath>/dev/shm/lscache</cacheStorePath>
                <expireInSeconds>900</expireInSeconds>
                <privateExpireInSeconds>0</privateExpireInSeconds>
                <cacheStatusCode>200,301</cacheStatusCode>
                <enablePostCache>0</enablePostCache>
            </cache>"#,
        )
        .unwrap();
        let c = convert_server_cache(Some(raw));
        assert_eq!(c.store_path, PathBuf::from("/dev/shm/lscache"));
        assert_eq!(c.default_ttl_secs, 900);
        assert_eq!(c.cacheable_status, vec![200, 301]);
        assert!(!c.enable_post_cache);
    }

    #[test]
    fn server_cache_nested_xml_mapping() {
        let raw: RawServerCache = quick_xml::de::from_str(
            r#"<cache>
                <storage>
                    <cacheStorePath>/dev/shm/livecache</cacheStorePath>
                </storage>
                <cachePolicy>
                    <expireInSeconds>120</expireInSeconds>
                    <privateExpireInSeconds>45</privateExpireInSeconds>
                    <cacheStatusCode>200, 301, 404</cacheStatusCode>
                    <enablePostCache>1</enablePostCache>
                </cachePolicy>
            </cache>"#,
        )
        .unwrap();
        let c = convert_server_cache(Some(raw));
        assert_eq!(c.store_path, PathBuf::from("/dev/shm/livecache"));
        assert_eq!(c.default_ttl_secs, 120);
        assert_eq!(c.default_private_ttl_secs, 45);
        assert_eq!(c.cacheable_status, vec![200, 301, 404]);
        assert!(c.enable_post_cache);
    }

    #[test]
    fn vhost_cache_absent_or_disabled_is_none() {
        assert!(vhost::convert_vhost_cache(None).is_none());
        let raw: raw::RawVhostCache =
            quick_xml::de::from_str("<cache><enableCache>0</enableCache></cache>").unwrap();
        assert!(vhost::convert_vhost_cache(Some(raw)).is_none());
    }

    #[test]
    fn vhost_cache_enabled_defaults_public_on() {
        let raw: raw::RawVhostCache = quick_xml::de::from_str(
            r#"<cache>
                <enableCache>1</enableCache>
                <cachePolicy>
                    <enablePublicCache>1</enablePublicCache>
                    <enablePrivateCache>1</enablePrivateCache>
                </cachePolicy>
            </cache>"#,
        )
        .unwrap();
        let p = vhost::convert_vhost_cache(Some(raw)).expect("enabled");
        assert!(p.enable_cache && p.enable_public && p.enable_private);

        // enableCache=1 with no <cachePolicy> => public on, private off.
        let raw2: raw::RawVhostCache =
            quick_xml::de::from_str("<cache><enableCache>1</enableCache></cache>").unwrap();
        let p2 = vhost::convert_vhost_cache(Some(raw2)).unwrap();
        assert!(p2.enable_public && !p2.enable_private);
    }

    // ----- fileETag: OLS getLongValue(...,0,28,28) -----

    #[test]
    fn file_etag_default_and_range() {
        assert_eq!(bounded_u8(&None, 0, 28, 28), 28); // ALL = INODE|MTIME|SIZE
        assert_eq!(bounded_u8(&Some("0".into()), 0, 28, 28), 0); // no ETag
        assert_eq!(bounded_u8(&Some("24".into()), 0, 28, 28), 24); // MTIME|SIZE
        // Out of range -> default 28.
        assert_eq!(bounded_u8(&Some("29".into()), 0, 28, 28), 28);
        assert_eq!(bounded_u8(&Some("128".into()), 0, 28, 28), 28);
    }

    // ----- zstd / brotli compression tuning -----

    #[test]
    fn zstd_brotli_tuning_defaults() {
        // Absent tags -> codecs enabled, default levels (zstd 3, brotli q5).
        let t = convert_tuning(RawTuning::default());
        assert!(t.enable_zstd && t.enable_dyn_zstd);
        assert!(t.enable_brotli && t.enable_dyn_brotli);
        assert_eq!(t.zstd_level, 3);
        assert_eq!(t.brotli_quality, 5);
    }

    #[test]
    fn zstd_brotli_tuning_xml_mapping() {
        let xml = r#"<tuning>
            <enableZstdCompress>0</enableZstdCompress>
            <enableBrCompress>1</enableBrCompress>
            <zstdCompressLevel>19</zstdCompressLevel>
            <brCompressLevel>11</brCompressLevel>
        </tuning>"#;
        let raw: RawTuning = quick_xml::de::from_str(xml).unwrap();
        let t = convert_tuning(raw);
        assert!(!t.enable_zstd, "enableZstdCompress=0 disables zstd");
        assert!(t.enable_brotli, "enableBrCompress=1 enables brotli");
        assert_eq!(t.zstd_level, 19);
        assert_eq!(t.brotli_quality, 11);
    }

    #[test]
    fn zstd_brotli_level_out_of_range_falls_back() {
        let xml = "<tuning><zstdCompressLevel>99</zstdCompressLevel>\
                   <brCompressLevel>50</brCompressLevel></tuning>";
        let t = convert_tuning(quick_xml::de::from_str(xml).unwrap());
        assert_eq!(t.zstd_level, 3);
        assert_eq!(t.brotli_quality, 5);
    }

    // ----- clientVerify: OLS getLongValue(...,0,3,0) -----

    #[test]
    fn client_verify_range_and_default() {
        assert_eq!(bounded_u8(&None, 0, 3, 0), 0);
        for v in 0u8..=3 {
            assert_eq!(bounded_u8(&Some(v.to_string()), 0, 3, 0), v);
        }
        assert_eq!(bounded_u8(&Some("4".into()), 0, 3, 0), 0); // out of range
    }

    // ----- verifyDepth: OLS getLongValue(...,1,INT_MAX,1) -----

    #[test]
    fn verify_depth_min_one_default_one() {
        assert_eq!(bounded_u32_clamp_max(&None, 1, 1), 1);
        assert_eq!(bounded_u32_clamp_max(&Some("0".into()), 1, 1), 1); // < min -> default
        assert_eq!(bounded_u32_clamp_max(&Some("5".into()), 1, 1), 5);
        // Above u32 clamps to u32::MAX (mirrors INT_MAX clamp branch).
        assert_eq!(
            bounded_u32_clamp_max(&Some("99999999999".into()), 1, 1),
            u32::MAX
        );
    }

    // ----- accessControl: 'T' trust flag, allow-only (OLS checkTrust) -----

    #[test]
    fn allow_t_flag_marks_trusted_and_strips_suffix() {
        let rules = parse_access("173.245.48.0/20T, 103.21.244.0/22", true);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].spec, "173.245.48.0/20");
        assert!(rules[0].trusted);
        assert!(rules[0].allow);
        // No T -> not trusted.
        assert_eq!(rules[1].spec, "103.21.244.0/22");
        assert!(!rules[1].trusted);
    }

    #[test]
    fn lowercase_t_flag_also_recognized() {
        let rules = parse_access("10.0.0.0/8t", true);
        assert_eq!(rules[0].spec, "10.0.0.0/8");
        assert!(rules[0].trusted);
    }

    #[test]
    fn deny_t_flag_is_stripped_but_not_trusted() {
        // OLS checkTrust only upgrades allow entries to AC_TRUST; a T on a
        // deny entry is stripped and ignored (the network stays denied).
        let rules = parse_access("192.168.1.0/24T", false);
        assert_eq!(rules[0].spec, "192.168.1.0/24");
        assert!(!rules[0].trusted, "deny rule must never be trusted");
        assert!(!rules[0].allow);
    }

    #[test]
    fn access_all_keyword_preserved() {
        let rules = parse_access("ALL", true);
        assert_eq!(rules[0].spec, "ALL");
        assert!(rules[0].allow);
        assert!(!rules[0].trusted);
    }

    // ----- (Tier 2) unix: listener addresses -----

    #[test]
    fn unix_address_yields_uds_path() {
        let list = crate::parse::raw::RawListenerList {
            listener: vec![
                crate::parse::raw::RawListener {
                    name: Some("uds".into()),
                    address: Some("unix:/run/httpjet/http.sock".into()),
                    ..Default::default()
                },
                crate::parse::raw::RawListener {
                    name: Some("tcp".into()),
                    address: Some("127.0.0.1:8080".into()),
                    ..Default::default()
                },
            ],
        };
        let listeners = convert_listeners(Some(list), &Default::default());
        assert_eq!(
            listeners[0].uds_path,
            Some(PathBuf::from("/run/httpjet/http.sock")),
            "the unix: prefix is stripped into uds_path"
        );
        assert!(
            listeners[0].address.starts_with("unix:"),
            "address stays verbatim for listener_sig"
        );
        assert_eq!(listeners[1].uds_path, None, "TCP addresses are untouched");
    }

    // ----- (Tier 2) geo ACL label lists -----

    #[test]
    fn geo_acl_lists_parse() {
        let raw = RawSecurity {
            geo_db_file: Some("/x/geo.db".into()),
            geo_allow: Some("US, DE".into()),
            asn_deny: Some("AS64512 13335".into()),
            ..Default::default()
        };
        let sec = convert_security(Some(raw), &SubstCtx::default());
        assert_eq!(sec.geo_db_file, Some(PathBuf::from("/x/geo.db")));
        assert_eq!(sec.geo_allow, vec!["US", "DE"]);
        assert_eq!(sec.asn_deny, vec![64512, 13335]);
        let none = convert_security(None, &SubstCtx::default());
        assert!(none.geo_db_file.is_none() && none.geo_allow.is_empty());
    }

    // ----- vhostMap domain lowercasing (OLS mapDomainList strnlower) -----

    #[test]
    fn convert_security_deny_t_not_trusted() {
        let raw = RawSecurity {
            file_access_control: None,
            access_deny_dir: None,
            access_control: Some(RawAccessControl {
                allow: Some("173.245.48.0/20T".into()),
                deny: Some("5.6.7.0/24T".into()),
            }),
            cgi_rlimit: None,
            ..Default::default()
        };
        let sec = convert_security(Some(raw), &SubstCtx::default());
        let allow_rule = sec.access_control.iter().find(|r| r.allow).unwrap();
        assert!(allow_rule.trusted);
        let deny_rule = sec.access_control.iter().find(|r| !r.allow).unwrap();
        assert_eq!(deny_rule.spec, "5.6.7.0/24");
        assert!(!deny_rule.trusted);
    }

    #[test]
    fn cgi_cpu_rlimit_maps_to_php_config() {
        let dir = std::env::temp_dir().join(format!(
            "httpjet_cfg_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("conf")).unwrap();
        std::fs::write(
            dir.join("conf/httpd_config.xml"),
            r#"<httpServerConfig>
                <serverName>test</serverName>
                <security>
                    <CGIRLimit>
                        <CPUSoftLimit>300</CPUSoftLimit>
                        <CPUHardLimit>600</CPUHardLimit>
                    </CGIRLimit>
                </security>
                <phpConfig>
                    <phpHandler>
                        <id>php</id>
                        <command>/usr/bin/php</command>
                        <suffixes>php</suffixes>
                    </phpHandler>
                </phpConfig>
            </httpServerConfig>"#,
        )
        .unwrap();
        let cfg = load_server_file(&dir, &dir.join("conf/httpd_config.xml")).unwrap();
        let expected = RlimitPair {
            soft: Some(300),
            hard: Some(600),
        };
        assert_eq!(cfg.security.cgi_cpu_limit_secs, Some(expected));
        assert_eq!(
            cfg.php_config.as_ref().unwrap().cpu_limit_secs,
            Some(expected)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn php_backlog_is_parsed_and_defaults_to_existing_supervisor_value() {
        let ctx = SubstCtx::default();
        let parsed = convert_php(
            RawPhpConfig {
                backlog: Some("8192".into()),
                ..Default::default()
            },
            &ctx,
            None,
        );
        assert_eq!(parsed.backlog, 8192);

        let defaulted = convert_php(RawPhpConfig::default(), &ctx, None);
        assert_eq!(defaulted.backlog, 1024);
    }

    // ----- Phase 5a: <namespace> policy parsing (default OFF) -----

    #[test]
    fn namespace_absent_is_off_default() {
        // No <namespace> block in <suexec> => the all-default OFF policy.
        let policy = convert_suexec(Some(RawSuExec {
            enable: Some("1".into()),
            uid_min: None,
            gid_min: None,
            namespace: None,
        }));
        assert_eq!(policy.namespaces, NamespacePolicy::default());
        assert!(!policy.namespaces.enable);
        assert!(!policy.namespaces.mount);
        assert!(!policy.namespaces.pid);
        assert!(!policy.namespaces.net);
        assert!(!policy.namespaces.uts);
        assert!(!policy.namespaces.ipc);
    }

    #[test]
    fn namespace_no_suexec_block_is_off() {
        // No <suexec> at all => default OFF suexec AND OFF namespaces.
        let policy = convert_suexec(None);
        assert_eq!(policy.namespaces, NamespacePolicy::default());
    }

    #[test]
    fn namespace_per_flag_parsing() {
        let ns = convert_namespace(Some(RawNamespace {
            enable: Some("1".into()),
            mount: Some("true".into()),
            pid: Some("1".into()),
            net: None,                   // absent => false
            uts: Some("0".into()),       // explicit 0 => false
            ipc: Some("garbage".into()), // non-truthy => false
        }))
        .unwrap();
        assert!(ns.enable);
        assert!(ns.mount);
        assert!(ns.pid);
        assert!(!ns.net);
        assert!(!ns.uts);
        assert!(!ns.ipc);
    }

    #[test]
    fn namespace_block_present_but_disabled() {
        // <namespace> present with enable absent => master OFF even if flags set.
        let ns = convert_namespace(Some(RawNamespace {
            enable: None,
            net: Some("1".into()),
            ..Default::default()
        }))
        .unwrap();
        assert!(!ns.enable);
        assert!(ns.net); // flag recorded, but enable gates it downstream
    }

    #[test]
    fn vhost_namespace_only_override_records_isolation() {
        // A per-vhost <namespace> with no setUID/chroot still yields a
        // VHostIsolation carrying the override (Some), with no-op cred/chroot.
        let ns = NamespacePolicy {
            enable: true,
            net: true,
            ..Default::default()
        };
        let iso = vhost::convert_isolation(
            &None, // setUIDMode absent
            &None, // chrootMode absent
            &None,
            &None,
            &None,
            Some(ns),
            &SubstCtx::default(),
        )
        .expect("namespace-only override must produce a VHostIsolation");
        assert_eq!(iso.chroot, ChrootMode::None);
        assert!(!iso.from_docroot_owner);
        assert_eq!(iso.namespaces, Some(ns));
    }

    #[test]
    fn vhost_no_isolation_and_no_namespace_is_none() {
        // Nothing declared => no per-vhost isolation (inherit server policy).
        let iso = vhost::convert_isolation(
            &None,
            &None,
            &None,
            &None,
            &None,
            None,
            &SubstCtx::default(),
        );
        assert!(iso.is_none());
    }

    #[test]
    fn vhost_suexec_without_namespace_inherits() {
        // setUIDMode set but no <namespace> => isolation present, namespaces None
        // (None = inherit the server policy).
        let iso = vhost::convert_isolation(
            &Some("1".into()),
            &None,
            &None,
            &Some("appuser".into()),
            &Some("appgrp".into()),
            None,
            &SubstCtx::default(),
        )
        .unwrap();
        assert_eq!(iso.user, "appuser");
        assert!(iso.namespaces.is_none());
    }

    // ----- expiresByType A/M prefix retained verbatim -----

    #[test]
    fn expires_by_type_keeps_base_prefix() {
        // OLS ExpiresCtrl::parse treats a leading A/a = access-relative and
        // M/m = modify-relative; httpjet keeps the raw value for hj-static to
        // interpret, so the prefix must survive the split unchanged.
        let pairs = parse_expires_by_type("image/*=A604800, text/css=M86400");
        assert_eq!(pairs[0], ("image/*".into(), "A604800".into()));
        assert_eq!(pairs[1], ("text/css".into(), "M86400".into()));
    }
}
