//! Parse LiteSpeed XML config into the normalized [`crate::model`] types.
//!
//! Strategy: deserialize the XML into permissive "raw" structs with `quick-xml`
//! (every field optional), then convert to the clean model, applying `$VAR`
//! substitution and interpreting unions/booleans. The raw layer absorbs the
//! liberal/legacy XML LiteSpeed tolerates (empty elements, missing fields).

mod balance;
mod raw;
mod scalar;
mod vhost;
mod xmlnorm;

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
    load_report(server_root).map(|(cfg, _)| cfg)
}

/// [`load`], also returning the declared vhosts whose files were skipped.
pub fn load_report(server_root: impl AsRef<Path>) -> Result<(ServerConfig, Vec<SkippedVhost>)> {
    let server_root = server_root.as_ref().to_path_buf();
    let main = server_root.join("conf/httpd_config.xml");
    let text = read_config_file(&main, MAX_CONFIG_FILE_BYTES)?;
    let (mut cfg, inherit) = parse_server_parts(&server_root, &main, &text, false)?;
    let skipped = load_vhost_files(&mut cfg, &inherit)?;
    // mime.properties (best-effort; absence is not fatal)
    let mime_path = server_root.join("conf/mime.properties");
    if let Ok(text) = read_config_file(&mime_path, MAX_CONFIG_FILE_BYTES) {
        cfg.mime = parse_mime(&text);
    }
    Ok((cfg, skipped))
}

/// Parse a complete in-memory configuration without reading config files.
/// Vhost documents are keyed by declaration name, not by submitted file paths.
/// Resource paths are normalized but NOT authorized here; callers must validate
/// them before building runtime state. Errors intentionally contain no input.
pub fn parse_bundle(
    server_root: &Path,
    server_xml: &str,
    vhosts: &std::collections::BTreeMap<String, String>,
    mime: &str,
) -> std::result::Result<ServerConfig, crate::BundleError> {
    use crate::BundleError;
    let size = vhosts.iter().try_fold(
        server_xml
            .len()
            .checked_add(mime.len())
            .ok_or(BundleError)?,
        |size, (name, xml)| size.checked_add(name.len())?.checked_add(xml.len()),
    );
    if size.is_none_or(|size| size > 1024 * 1024) || vhosts.len() > 128 {
        return Err(BundleError);
    }
    bundle_document(server_xml, "httpServerConfig")?;
    for xml in vhosts.values() {
        bundle_document(xml, "virtualHostConfig")?;
    }
    // Legacy file parsing logs operator diagnostics that can contain XML values.
    // A synchronous submission must not emit those values to ambient sinks.
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        let (mut cfg, inherit) =
            parse_server_parts(server_root, Path::new("<submission>"), server_xml, true)
                .map_err(|_| BundleError)?;
        if cfg.vhost_order.len() != cfg.vhosts.len()
            || cfg.vhosts.len() != vhosts.len()
            || cfg.vhosts.keys().ne(vhosts.keys())
        {
            return Err(BundleError);
        }
        vhost::load_vhost_sources(&mut cfg, &inherit, true, |name, _| Ok(vhosts[name].clone()))
            .map_err(|_| BundleError)?;
        cfg.mime = parse_mime(mime);
        Ok(cfg)
    })
}

fn bundle_document(text: &str, root: &str) -> std::result::Result<(), crate::BundleError> {
    use crate::BundleError;
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(text);
    let mut depth = 0usize;
    let mut seen_root = false;
    loop {
        let event = reader.read_event().map_err(|_| BundleError)?;
        let opens = matches!(event, Event::Start(_));
        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                if depth >= 64 {
                    return Err(BundleError);
                }
                if depth == 0 {
                    if seen_root || tag.name().as_ref() != root {
                        return Err(BundleError);
                    }
                    seen_root = true;
                }
                if opens {
                    depth += 1;
                }
            }
            Event::End(_) => depth = depth.checked_sub(1).ok_or(BundleError)?,
            Event::DocType(_) => return Err(BundleError),
            Event::Text(value) if depth == 0 => {
                if !value.as_ref().bytes().all(|b| b.is_ascii_whitespace()) {
                    return Err(BundleError);
                }
            }
            Event::CData(_) | Event::GeneralRef(_) if depth == 0 => return Err(BundleError),
            Event::Eof => return (seen_root && depth == 0).then_some(()).ok_or(BundleError),
            _ => {}
        }
    }
}

/// Upper bound for any single configuration file read from disk. Real LiteSpeed
/// configs are tens of KiB; this keeps a runaway or hostile file from being
/// buffered whole by a reload.
pub(crate) const MAX_CONFIG_FILE_BYTES: u64 = 16 << 20;

pub(crate) fn read_config_file(path: &Path, max: u64) -> Result<String> {
    use std::io::Read;
    let io = |source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let too_large = |len| ConfigError::TooLarge {
        path: path.to_path_buf(),
        len,
        max,
    };
    let file = std::fs::File::open(path).map_err(io)?;
    let len = file.metadata().map_err(io)?.len();
    if len > max {
        return Err(too_large(len));
    }
    let mut text = String::new();
    file.take(max + 1).read_to_string(&mut text).map_err(io)?;
    if text.len() as u64 > max {
        return Err(too_large(text.len() as u64));
    }
    Ok(text)
}

/// Parse just the server file (no vhost-file loading); useful for tests.
#[cfg(test)]
pub(crate) fn load_server_file(server_root: &Path, path: &Path) -> Result<ServerConfig> {
    let text = read_config_file(path, MAX_CONFIG_FILE_BYTES)?;
    parse_server_text(server_root, path, &text)
}

#[cfg(test)]
fn parse_server_text(server_root: &Path, path: &Path, text: &str) -> Result<ServerConfig> {
    parse_server_parts(server_root, path, text, false).map(|(cfg, _)| cfg)
}

/// Server-level state merged into each vhost when its file loads.
struct VhostInherit {
    /// The server `<scriptHandlerList>`, under each vhost's own handlers (#928).
    script_handlers: Vec<ScriptHandler>,
    /// Vhosts their declaration disables or `<suspendedVhosts>` lists (#1000).
    disabled: std::collections::BTreeSet<String>,
    /// The server `<htAccess><allowOverride>` (only 31 loads, #1028).
    allow_override: Option<u32>,
}

fn parse_server_parts(
    server_root: &Path,
    path: &Path,
    text: &str,
    strict: bool,
) -> Result<(ServerConfig, VhostInherit)> {
    let text = xmlnorm::normalize(text, path);
    let mut raw: RawServer = quick_xml::de::from_str(&text).map_err(|e| ConfigError::Xml {
        path: path.to_path_buf(),
        msg: e.to_string(),
    })?;
    reject_template_members(path, raw.vh_template_list.as_ref())?;
    vhost::reject_apache_conf(path, "server", raw.apache_conf.as_deref())?;
    let allow_override = vhost::server_allow_override(path, raw.htaccess.as_ref())?;
    let script_handlers = vhost::convert_script_handlers(raw.script_handler_list.take(), path)?;

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
    let raw_security = match raw.security {
        Some(security) => Some(security),
        None if raw.access_control.is_some()
            || raw.access_deny_dir.is_some()
            || raw.file_access_control.is_some() =>
        {
            Some(RawSecurity {
                access_control: raw.access_control,
                access_deny_dir: raw.access_deny_dir,
                file_access_control: raw.file_access_control,
                ..RawSecurity::default()
            })
        }
        None => None,
    };
    let security = convert_security(raw_security, &ctx, path)?;
    let suexec = convert_suexec(raw.suexec);
    let ext_processors = convert_ext_list(raw.ext_processor_list, &ctx, path)?;
    let php_config = raw
        .php_config
        .map(|p| convert_php(p, &ctx, path))
        .transpose()?;
    let listeners = convert_listeners(raw.listener_list, &ctx);
    for listener in &listeners {
        listener
            .validate_proxy_protocol()
            .map_err(|reason| ConfigError::InvalidValue {
                path: path.to_path_buf(),
                directive: "proxyProtocolPeers",
                value: listener.name.clone(),
                reason,
            })?;
    }
    let (vhosts, vhost_order, disabled) = convert_vhost_decls(
        raw.vhost_list,
        raw.suspended_vhosts.as_deref(),
        &ctx,
        path,
        strict,
    )?;

    let cfg = ServerConfig {
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
    };
    Ok((
        cfg,
        VhostInherit {
            script_handlers,
            disabled,
            allow_override,
        },
    ))
}

/// Template members would be instantiated as vhosts by OLS; httpjet does not
/// expand templates, so a member is refused instead of left unserved (#921).
/// A template with no members (the stock LSWS set) is inert and loads.
fn reject_template_members(path: &Path, list: Option<&RawVhTemplateList>) -> Result<()> {
    for template in list.into_iter().flat_map(|l| &l.vh_template) {
        if let Some(member) = template.member.first() {
            return Err(ConfigError::InvalidValue {
                path: path.to_path_buf(),
                directive: "vhTemplate.member",
                value: member.vh_name.as_deref().unwrap_or("").trim().to_string(),
                reason: format!(
                    "template {:?}: vhTemplate members are not supported; declare the vhost in <virtualHostList>",
                    template.name.as_deref().unwrap_or("").trim()
                ),
            });
        }
    }
    Ok(())
}

fn convert_tuning(r: RawTuning) -> Tuning {
    let d = Tuning::default();
    // LSWS/OLS `enableBrCompress` is the dynamic brotli LEVEL, 0 (off) to 6
    // (`getLongValue(.., 0, 6, 4)`), not a boolean. Absent keeps brotli on.
    let br_level = r
        .enable_brotli
        .as_ref()
        .map(|_| ols_long_value(&r.enable_brotli, 0, 6, 4) as u8);
    Tuning {
        max_connections: u32_of(&r.max_connections, d.max_connections),
        conn_timeout: secs_in_range(&r.conn_timeout, 60, 1..=10_000, "connTimeout"),
        keep_alive_timeout: secs_in_range(&r.keep_alive_timeout, 5, 1..=10_000, "keepAliveTimeout"),
        // OLS range 0..=32767; out of range falls back to the default.
        max_keep_alive_req: Some(u32_of(&r.max_keep_alive_req, d.max_keep_alive_req))
            .filter(|v| *v <= 32_767)
            .unwrap_or(d.max_keep_alive_req),
        // OLS httpserver.cpp: maxReqURLLen 100..=MAX_URL_LEN (64 KiB),
        // maxReqHeaderSize 1024..=131072-4, maxReqBodySize >= 4096 (#926).
        max_req_url_len: bytes_in_range(
            &r.max_req_url_len,
            d.max_req_url_len as u64,
            100..=65_536,
            "maxReqURLLen",
        ) as usize,
        max_req_header_size: bytes_in_range(
            &r.max_req_header_size,
            d.max_req_header_size as u64,
            1024..=131_068,
            "maxReqHeaderSize",
        ) as usize,
        max_req_body_size: bytes_in_range(
            &r.max_req_body_size,
            d.max_req_body_size,
            4096..=u64::MAX,
            "maxReqBodySize",
        ),
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
        enable_brotli: br_level != Some(0),
        enable_dyn_brotli: r
            .enable_dyn_brotli
            .as_ref()
            .map(|_| truthy(&r.enable_dyn_brotli))
            .unwrap_or(true),
        gzip_level: bounded_u8(&r.gzip_level, 1, 9, d.gzip_level as u8) as u32,
        // OLS reads an absent element as `default`; a present one, even empty, is the list.
        compressible_types: r
            .compressible_types
            .as_deref()
            .map(split_list)
            .unwrap_or(d.compressible_types),
        // OLS-style bounded parse: out-of-range/absent falls back to the default.
        zstd_level: bounded_u8(&r.zstd_level, 1, 22, 3) as u32,
        // The httpjet-native `brCompressLevel` wins; without it a LiteSpeed config's
        // `enableBrCompress` level is the quality it asked for.
        brotli_quality: bounded_u8(
            &r.brotli_quality,
            0,
            11,
            br_level.filter(|l| *l != 0).unwrap_or(5),
        ) as u32,
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
        enable_declared: r
            .enable_expires
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty()),
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

fn convert_security(r: Option<RawSecurity>, ctx: &SubstCtx, path: &Path) -> Result<Security> {
    let r = match r {
        Some(r) => r,
        None => return Ok(Security::default()),
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
    // OLS enforces it (getLongValue 0..1, default 0); serving another user's files
    // without that check must not happen silently.
    if let Some(strict) = r
        .file_access_control
        .as_ref()
        .map(|f| &f.force_strict_ownership)
        .filter(|strict| ols_long_value(strict, 0, 1, 0) != 0)
    {
        return Err(ConfigError::InvalidValue {
            path: path.to_path_buf(),
            directive: "forceStrictOwnership",
            value: strict.clone().unwrap_or_default(),
            reason:
                "file ownership checks are not enforced by httpjet; refusing to serve without them"
                    .into(),
        });
    }
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
                s.split(|c: char| c == ',' || c.is_whitespace())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let parse_asns = |directive: &'static str, v: &Option<String>| -> Result<Vec<u32>> {
        split_labels(v)
            .into_iter()
            .map(|token| {
                let digits = token
                    .get(..2)
                    .filter(|prefix| prefix.eq_ignore_ascii_case("AS"))
                    .map_or(token.as_str(), |_| &token[2..]);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ConfigError::InvalidValue {
                        path: path.to_path_buf(),
                        directive,
                        value: token,
                        reason: "expected an ASN number with at most one optional AS prefix".into(),
                    });
                }
                digits
                    .parse::<u32>()
                    .map_err(|_| ConfigError::InvalidValue {
                        path: path.to_path_buf(),
                        directive,
                        value: token,
                        reason: "ASN is out of range".into(),
                    })
            })
            .collect()
    };
    Ok(Security {
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
        asn_allow: parse_asns("asnAllow", &r.asn_allow)?,
        asn_deny: parse_asns("asnDeny", &r.asn_deny)?,
    })
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

fn convert_ext_list(
    r: Option<RawExtList>,
    ctx: &SubstCtx,
    path: &Path,
) -> Result<Vec<ExtProcessor>> {
    let r = match r {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };
    for e in &r.ext_processor {
        balance::parse(e, path)?;
        // OLS extappregistry.cpp drops a processor with a missing or unknown
        // <type>; httpjet refuses the config instead of guessing proxy (#927).
        if nonempty(e.name.clone()).is_some() && ext_kind(e.kind.as_deref()).is_none() {
            return Err(ConfigError::InvalidValue {
                path: path.to_path_buf(),
                directive: "extProcessor.type",
                value: e.kind.as_deref().unwrap_or("").trim().to_string(),
                reason: format!(
                    "extProcessor {:?}: expected lsapi, fcgi, or proxy",
                    e.name.as_deref().unwrap_or("").trim()
                ),
            });
        }
    }
    Ok(r.ext_processor
        .into_iter()
        .filter_map(|e| convert_ext(e, ctx))
        .collect())
}

/// OLS `HandlerType::getHandlerType` compares case-insensitively.
fn ext_kind(kind: Option<&str>) -> Option<ExtKind> {
    let t = kind?.trim();
    let is = |name: &str| t.eq_ignore_ascii_case(name);
    if is("lsapi") {
        Some(ExtKind::Lsapi)
    } else if is("fcgi") || is("fastcgi") {
        Some(ExtKind::FastCgi)
    } else if is("proxy") {
        Some(ExtKind::Proxy)
    } else {
        None
    }
}

fn convert_ext(e: RawExtProcessor, ctx: &SubstCtx) -> Option<ExtProcessor> {
    let load_balance = balance::parse(&e, Path::new("<validated>")).ok()?;
    let name = nonempty(e.name)?;
    let kind = ext_kind(e.kind.as_deref())?;
    // (Tier 1.2) Every <address> element is a peer; the first is primary and the
    // rest are failover peers tried in order when the primary's breaker is open.
    let mut addr_iter = e.address.iter().map(|s| ext_address(s.as_str()));
    let address = addr_iter.next().unwrap_or(ext_address(""));
    let extra_addresses: Vec<_> = addr_iter.collect();
    Some(ExtProcessor {
        load_balance,
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

/// The `<phpHandler>` list (#1027). LSWS treats each handler's `<id>` as a
/// handled suffix beside its `<suffixes>`. httpjet runs one PHP pool, so the
/// handlers merge when they share a command and refuse the load otherwise:
/// sending one handler's scripts to another handler's binary is not its config.
fn convert_php_handlers(
    handlers: Vec<RawPhpHandler>,
    ctx: &SubstCtx,
    path: &Path,
) -> Result<(String, PathBuf, Vec<String>)> {
    let mut first: Option<(String, PathBuf)> = None;
    let mut listed: Option<Vec<String>> = None;
    let mut ids = Vec::new();
    for h in handlers {
        let id = nonempty(h.id).unwrap_or_else(|| "php".into());
        let command = PathBuf::from(ctx.expand(h.command.as_deref().unwrap_or("")));
        match &first {
            None => first = Some((id.clone(), command)),
            Some((first_id, first_command)) if *first_command != command => {
                return Err(ConfigError::InvalidValue {
                    path: path.to_path_buf(),
                    directive: "phpHandler.command",
                    value: format!(
                        "{first_id}={} {id}={}",
                        first_command.display(),
                        command.display()
                    ),
                    reason: "httpjet runs one PHP pool; all <phpHandler> commands must match"
                        .into(),
                });
            }
            Some(_) => {}
        }
        if let Some(list) = h.suffixes.as_deref() {
            // OLS skips leading dots (HttpMime::addUpdateSuffixMimeMap): a hand-written
            // `.php` must route PHP, not leave every script to the static handler.
            listed.get_or_insert_with(Vec::new).extend(
                split_list(list)
                    .into_iter()
                    .map(|suffix| suffix.trim_start_matches('.').to_string())
                    .filter(|suffix| !suffix.is_empty()),
            );
        }
        ids.push(id);
    }
    let mut suffixes: Vec<String> = Vec::new();
    for suffix in listed
        .unwrap_or_else(|| vec!["php".into()])
        .into_iter()
        .chain(ids)
    {
        if !suffixes.iter().any(|s| s.eq_ignore_ascii_case(&suffix)) {
            suffixes.push(suffix);
        }
    }
    let (handler_id, command) = first.unwrap_or_else(|| ("php".into(), PathBuf::new()));
    Ok((handler_id, command, suffixes))
}

fn convert_php(p: RawPhpConfig, ctx: &SubstCtx, path: &Path) -> Result<PhpConfig> {
    let (handler_id, command, suffixes) = convert_php_handlers(p.php_handler, ctx, path)?;
    Ok(PhpConfig {
        handler_id,
        command,
        suffixes,
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
        // OLS LocalWorkerConfig runs local workers with unlimited CPU:
        // `<CGIRLimit>` caps a CGI process, while RLIMIT_CPU accumulates over a
        // persistent lsphp worker's life and would kill it mid-request (#1037).
        cpu_limit_secs: None,
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
    })
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
            // OLS justSSLContext roots relative TLS files at $SERVER_ROOT (#1001).
            let tls = if secure || l.cert_file.is_some() {
                Some(ListenerTls {
                    key_file: vhost::server_rooted(ctx, l.key_file.as_deref().unwrap_or("")),
                    cert_file: vhost::server_rooted(ctx, l.cert_file.as_deref().unwrap_or("")),
                    cert_chain: truthy(&l.cert_chain),
                    ca_cert_file: nonempty(l.ca_cert_file).map(|p| vhost::server_rooted(ctx, &p)),
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
                        .map(|p| vhost::server_rooted(ctx, p)),
                })
            } else {
                None
            };
            // (Tier 2) `unix:`/`uds:` address prefix ⇒ serve HTTP over a UDS path.
            let uds_path = address
                .strip_prefix("unix:")
                .or_else(|| address.strip_prefix("uds:"))
                .map(|p| PathBuf::from(ctx.expand(p)));
            let listener = Listener {
                name,
                address,
                secure,
                vhost_map,
                tls,
                uds_path,
                proxy_protocol: truthy(&l.proxy_protocol),
                proxy_protocol_peers: l.proxy_protocol_peers.as_deref().map(split_list).unwrap_or_default(),
            };
            for warning in listener.domain_routes().warnings {
                tracing::warn!("{warning}");
            }
            Some(listener)
        })
        .collect()
}

/// Parse `mime.properties`. LiteSpeed uses `mime/type = suffix1, suffix2`
/// (the side containing `/` is the type).
pub(crate) fn parse_mime(text: &str) -> MimeMap {
    let mut by_suffix = std::collections::BTreeMap::new();
    let mut default_type = None;
    for line in text.lines() {
        // OLS loadMime cuts every line at its first `#`, inline comments included.
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
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
            let suf = suf.to_ascii_lowercase();
            if suf == "default" {
                default_type = Some(mime.to_string());
                continue;
            }
            by_suffix.insert(suf, mime.to_string());
        }
    }
    MimeMap {
        by_suffix,
        default_type,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (#605): connTimeout/keepAliveTimeout outside LiteSpeed's [1, 10000]
    /// fall back to the defaults instead of becoming unbounded deadlines.
    #[test]
    fn connection_timeouts_out_of_range_use_the_defaults() {
        let tuning = |conn: &str, keep: &str| {
            convert_tuning(RawTuning {
                conn_timeout: Some(conn.into()),
                keep_alive_timeout: Some(keep.into()),
                ..Default::default()
            })
        };
        let t = tuning("0", "0");
        assert_eq!(t.conn_timeout, Duration::from_secs(60));
        assert_eq!(t.keep_alive_timeout, Duration::from_secs(5));
        let t = tuning("20000", "10001");
        assert_eq!(t.conn_timeout, Duration::from_secs(60));
        assert_eq!(t.keep_alive_timeout, Duration::from_secs(5));
        let t = tuning("30", "10000");
        assert_eq!(t.conn_timeout, Duration::from_secs(30));
        assert_eq!(t.keep_alive_timeout, Duration::from_secs(10_000));
    }

    #[test]
    fn fastcgi_processor_has_a_distinct_opt_in_identity() {
        for kind in ["fcgi", "fastcgi"] {
            let xml = format!(
                "<httpServerConfig><extProcessorList><extProcessor><name>app</name>\
                 <type>{kind}</type><address>uds:///run/app.sock</address>\
                 </extProcessor></extProcessorList></httpServerConfig>"
            );
            let config =
                parse_server_text(Path::new("/srv/httpjet"), Path::new("test.xml"), &xml).unwrap();
            assert_eq!(config.ext_processors.len(), 1);
            assert_eq!(config.ext_processors[0].kind, ExtKind::FastCgi);
            assert!(matches!(
                config.ext_processors[0].address,
                ExtAddress::Uds(_)
            ));
        }
    }

    #[test]
    fn listener_crl_file_is_var_expanded() {
        use super::raw::{RawListener, RawListenerList};
        let ctx = crate::subst::SubstCtx {
            server_root: "/usr/local/lsws".into(),
            ..Default::default()
        };
        let list = RawListenerList {
            listener: vec![RawListener {
                name: Some("tls".into()),
                address: Some("127.0.0.1:8443".into()),
                secure: Some("1".into()),
                key_file: Some("$SERVER_ROOT/conf/k.pem".into()),
                cert_file: Some("$SERVER_ROOT/conf/c.pem".into()),
                crl_file: Some("$SERVER_ROOT/conf/ca.crl".into()),
                ..Default::default()
            }],
        };
        let listeners = convert_listeners(Some(list), &ctx);
        let tls = listeners[0].tls.as_ref().unwrap();
        assert_eq!(
            tls.crl_file,
            Some(PathBuf::from("/usr/local/lsws/conf/ca.crl"))
        );
    }

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
                    proxy_protocol_peers: Some("192.0.2.10, 198.51.100.0/24".into()),
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

    /// OLS getLongValue reads with strtoll: a leading integer, K/M/G scaling, no
    /// digits as 0; absent/empty or out-of-range values take the default.
    #[test]
    fn ols_long_value_mirrors_strtoll_and_the_range_default() {
        let v = |s: Option<&str>| ols_long_value(&s.map(str::to_string), 0, 1, 1);
        for (input, want) in [
            (None, 1),
            (Some(""), 1),
            (Some("  "), 1),
            (Some("0"), 0),
            (Some(" 1 "), 1),
            (Some("+0"), 0),
            (Some("-0"), 0),
            (Some("0abc"), 0),
            (Some("true"), 0),
            (Some("off"), 0),
            (Some("2"), 1),
            (Some("-1"), 1),
            (Some("1k"), 1),
            (Some("99999999999999999999"), 1),
        ] {
            assert_eq!(v(input), want, "{input:?}");
        }
        assert_eq!(ols_long_value(&Some("2K".into()), 0, 4096, 7), 2048);
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
        let text = r#"<virtualHostConfig><docRoot>/web</docRoot>
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
    fn vhost_log_headers_defaults_to_three_like_ols() {
        let parse = |extra: &str| {
            let text = format!(
                "<virtualHostConfig><docRoot>/web</docRoot><logging><accessLog><useServer>0</useServer><fileName>/tmp/a.log</fileName>{extra}</accessLog></logging></virtualHostConfig>"
            );
            parse_vhost_config(&text, &Default::default())
                .unwrap()
                .access_log_file
                .expect("own access log")
                .log_headers
        };
        assert_eq!(parse(""), 3, "absent logHeaders = OLS default 3");
        assert_eq!(parse("<logHeaders>0</logHeaders>"), 0);
        assert_eq!(parse("<logHeaders>5</logHeaders>"), 5);
        assert_eq!(parse("<logHeaders>9</logHeaders>"), 3, "out of range");
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
                "<docRoot>/web</docRoot><logging><accessLog><useServer>1</useServer><fileName>/tmp/a.log</fileName></accessLog></logging>",
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
        let text = r#"<virtualHostConfig><docRoot>/web</docRoot>
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
    fn context_native_resource_controls_preserve_absent_and_explicit_zero() {
        let text = r#"<virtualHostConfig><docRoot>/web</docRoot>
            <contextList>
                <context>
                    <type>proxy</type><uri>/configured</uri><handler>app</handler>
                    <maxReqBodySize>1K</maxReqBodySize>
                    <bandwidthLimit>2048</bandwidthLimit>
                    <responseTimeout>7</responseTimeout>
                </context>
                <context>
                    <type>proxy</type><uri>/absent</uri><handler>app</handler>
                </context>
                <context>
                    <type>proxy</type><uri>/zero</uri><handler>app</handler>
                    <maxReqBodySize>0</maxReqBodySize>
                    <bandwidthLimit>0</bandwidthLimit>
                </context>
            </contextList>
        </virtualHostConfig>"#;
        let vc = parse_vhost_config(text, &crate::parse::SubstCtx::default()).unwrap();
        let configured = &vc.contexts[0];
        assert_eq!(configured.max_body_override, Some(1024));
        assert_eq!(configured.bandwidth_limit, 2048);
        assert_eq!(configured.timeout_override, Some(7));
        let absent = &vc.contexts[1];
        assert_eq!(absent.max_body_override, None);
        assert_eq!(absent.bandwidth_limit, 0);
        assert_eq!(absent.timeout_override, None);
        let zero = &vc.contexts[2];
        assert_eq!(zero.max_body_override, Some(0));
        assert_eq!(zero.bandwidth_limit, 0);
        assert_eq!(zero.timeout_override, None);
    }

    #[test]
    fn context_native_resource_controls_reject_malformed_values() {
        for (directive, value) in [
            ("maxReqBodySize", "12XB"),
            ("bandwidthLimit", "-1"),
            ("responseTimeout", "1.5"),
            // #1004: a zero upstream deadline would 504 every request.
            ("responseTimeout", "0"),
            ("responseTimeout", " 0 "),
        ] {
            let text = format!(
                "<virtualHostConfig><docRoot>/web</docRoot><contextList><context><uri>/api</uri><{directive}>{value}</{directive}></context></contextList></virtualHostConfig>"
            );
            let err = parse_vhost_config(&text, &crate::parse::SubstCtx::default())
                .expect_err("a provided malformed native value must fail config parsing");
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidValue {
                        directive: found,
                        ..
                    } if found == directive
                ),
                "unexpected error for {directive}: {err}"
            );
        }
    }

    #[test]
    fn script_handler_rejects_missing_unknown_and_unsupported_types() {
        for raw_type in ["", "<type>lsapii</type>", "<type>proxy</type>"] {
            let text = format!(
                "<virtualHostConfig><docRoot>/web</docRoot><scriptHandlerList><scriptHandler><suffix>php</suffix>{raw_type}<handler>php8</handler></scriptHandler></scriptHandlerList></virtualHostConfig>"
            );
            let err = parse_vhost_config(&text, &crate::parse::SubstCtx::default())
                .expect_err("an unsafe script-handler type must fail config parsing");
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidValue {
                        directive: "scriptHandler.type",
                        ..
                    }
                ),
                "unexpected error for {raw_type:?}: {err}"
            );
        }
    }

    #[test]
    fn script_handler_requires_executable_handler_but_keeps_static_opt_out() {
        let executable = "<virtualHostConfig><docRoot>/web</docRoot><scriptHandlerList><scriptHandler><suffix>php</suffix><type>lsapi</type></scriptHandler></scriptHandlerList></virtualHostConfig>";
        let err = parse_vhost_config(executable, &crate::parse::SubstCtx::default())
            .expect_err("an executable script route without a handler must fail");
        assert!(matches!(
            err,
            ConfigError::InvalidValue {
                directive: "scriptHandler.handler",
                ..
            }
        ));

        let explicit_static = "<virtualHostConfig><docRoot>/web</docRoot><scriptHandlerList><scriptHandler><suffix>html</suffix><type>static</type></scriptHandler></scriptHandlerList></virtualHostConfig>";
        let parsed = parse_vhost_config(explicit_static, &crate::parse::SubstCtx::default())
            .expect("an explicit static suffix override remains valid");
        assert_eq!(parsed.script_handlers.len(), 1);
        assert_eq!(parsed.script_handlers[0].kind, ContextKind::Static);
        assert!(parsed.script_handlers[0].handler.is_empty());
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

    fn tuning_of(xml: &str) -> Tuning {
        convert_tuning(quick_xml::de::from_str(xml).unwrap())
    }

    /// Regression (#1020): LSWS/OLS `enableBrCompress` is the dynamic brotli
    /// level 0-6 (`getLongValue(.., 0, 6, 4)`); `truthy` dropped OLS's stock `4`.
    #[test]
    fn enable_br_compress_is_a_level() {
        let t = tuning_of("<tuning><enableBrCompress>4</enableBrCompress></tuning>");
        assert!(t.enable_brotli);
        assert_eq!(t.brotli_quality, 4);
        let t = tuning_of("<tuning><enableBrCompress>0</enableBrCompress></tuning>");
        assert!(!t.enable_brotli);
        assert_eq!(t.brotli_quality, 5);
        let t = tuning_of(
            "<tuning><enableBrCompress>6</enableBrCompress>\
             <brCompressLevel>9</brCompressLevel></tuning>",
        );
        assert!(t.enable_brotli);
        assert_eq!(t.brotli_quality, 9, "brCompressLevel wins");
        // Out of range falls back to OLS's default level 4; strtoll reads `true` as 0.
        let t = tuning_of("<tuning><enableBrCompress>7</enableBrCompress></tuning>");
        assert!(t.enable_brotli);
        assert_eq!(t.brotli_quality, 4);
        let t = tuning_of("<tuning><enableBrCompress>true</enableBrCompress></tuning>");
        assert!(!t.enable_brotli);
        // Absent: on at the httpjet default, as before.
        let t = tuning_of("<tuning></tuning>");
        assert!(t.enable_brotli);
        assert_eq!(t.brotli_quality, 5);
    }

    #[test]
    fn gzip_level_and_compressible_types() {
        let t = tuning_of("<tuning></tuning>");
        assert_eq!(t.gzip_level, 6);
        assert_eq!(t.compressible_types, ["default"]);
        let t = tuning_of(
            "<tuning><gzipCompressLevel>9</gzipCompressLevel>\
             <compressibleTypes>default, !text/css,\napplication/wasm</compressibleTypes></tuning>",
        );
        assert_eq!(t.gzip_level, 9);
        assert_eq!(
            t.compressible_types,
            ["default", "!text/css", "application/wasm"]
        );
        for bad in ["0", "10", "x"] {
            let t = tuning_of(&format!(
                "<tuning><gzipCompressLevel>{bad}</gzipCompressLevel></tuning>"
            ));
            assert_eq!(t.gzip_level, 6, "{bad}");
        }
        // A present but empty list names no type (OLS); only an absent one is `default`.
        let t = tuning_of("<tuning><compressibleTypes></compressibleTypes></tuning>");
        assert!(t.compressible_types.is_empty());
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
        let sec = convert_security(Some(raw), &SubstCtx::default(), Path::new("<test>")).unwrap();
        assert_eq!(sec.geo_db_file, Some(PathBuf::from("/x/geo.db")));
        assert_eq!(sec.geo_allow, vec!["US", "DE"]);
        assert_eq!(sec.asn_deny, vec![64512, 13335]);
        let none = convert_security(None, &SubstCtx::default(), Path::new("<test>")).unwrap();
        assert!(none.geo_db_file.is_none() && none.geo_allow.is_empty());
    }

    #[test]
    fn asn_acl_lists_accept_mixed_case_prefixes_and_all_whitespace() {
        let raw = RawSecurity {
            asn_allow: Some("as13335,\nAS64512\t42\r\naS7".into()),
            ..Default::default()
        };
        let sec = convert_security(Some(raw), &SubstCtx::default(), Path::new("<test>")).unwrap();
        assert_eq!(sec.asn_allow, vec![13335, 64512, 42, 7]);
    }

    #[test]
    fn asn_acl_lists_reject_every_malformed_or_overflowing_token() {
        for token in ["AS", "ASAS13335", "AS13x", "-1", "+1", "4294967296"] {
            let raw = RawSecurity {
                asn_allow: Some(format!("13335,{token}")),
                ..Default::default()
            };
            let err = convert_security(Some(raw), &SubstCtx::default(), Path::new("<test>"))
                .expect_err("malformed ASN tokens must not be silently filtered");
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidValue {
                        directive: "asnAllow",
                        ..
                    }
                ),
                "unexpected error for {token}: {err}"
            );
        }
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
        let sec = convert_security(Some(raw), &SubstCtx::default(), Path::new("<test>")).unwrap();
        let allow_rule = sec.access_control.iter().find(|r| r.allow).unwrap();
        assert!(allow_rule.trusted);
        let deny_rule = sec.access_control.iter().find(|r| !r.allow).unwrap();
        assert_eq!(deny_rule.spec, "5.6.7.0/24");
        assert!(!deny_rule.trusted);
    }

    #[test]
    fn cgi_cpu_rlimit_is_not_applied_to_php_workers() {
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
        // #1037: OLS gives local workers unlimited CPU; the CGI limit stays CGI's.
        assert_eq!(cfg.php_config.as_ref().unwrap().cpu_limit_secs, None);
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
            Path::new("<test>"),
        )
        .unwrap();
        assert_eq!(parsed.backlog, 8192);

        let defaulted = convert_php(RawPhpConfig::default(), &ctx, Path::new("<test>")).unwrap();
        assert_eq!(defaulted.backlog, 1024);
        assert_eq!(defaulted.handler_id, "php");
        assert_eq!(defaulted.suffixes, ["php"]);
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

#[cfg(test)]
mod read_limit_tests {
    use super::*;

    #[test]
    fn oversized_config_file_is_rejected() {
        let dir = std::env::temp_dir().join(format!("hj-config-limit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.xml");
        std::fs::write(&path, vec![b'x'; 65]).unwrap();
        assert!(matches!(
            read_config_file(&path, 64),
            Err(ConfigError::TooLarge {
                len: 65,
                max: 64,
                ..
            })
        ));
        std::fs::write(&path, vec![b'x'; 64]).unwrap();
        assert_eq!(read_config_file(&path, 64).unwrap().len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----- #773: unenforced vhost/context access control fails closed -----

    fn vhost_with(body: &str) -> String {
        format!("<virtualHostConfig><docRoot>/web</docRoot>{body}</virtualHostConfig>")
    }

    fn context_with(body: &str) -> String {
        vhost_with(&format!(
            "<contextList><context><type>null</type><uri>/admin/</uri>{body}</context></contextList>"
        ))
    }

    fn rejected(xml: &str, directive: &str) {
        match parse_vhost_config(xml, &Default::default()) {
            Err(ConfigError::InvalidValue { directive: d, .. }) => {
                assert_eq!(d, directive, "{xml}")
            }
            other => panic!("expected {directive} rejection for {xml}, got {other:?}"),
        }
    }

    #[test]
    fn context_access_control_and_auth_are_rejected() {
        rejected(
            &context_with(
                "<accessControl><allow>127.0.0.1</allow><deny>ALL</deny></accessControl>",
            ),
            "accessControl",
        );
        rejected(
            &context_with("<accessControl><deny>203.0.113.0/24</deny></accessControl>"),
            "accessControl",
        );
        rejected(
            &context_with("<accessControl><allow>10.0.0.0/8</allow></accessControl>"),
            "accessControl",
        );
        rejected(
            &context_with("<accessControl><denyList>1.2.3.4</denyList></accessControl>"),
            "accessControl",
        );
        rejected(&context_with("<realm>admins</realm>"), "realm");
        rejected(&context_with("<required>user bob</required>"), "required");
        rejected(
            &context_with("<authorizer>authz</authorizer>"),
            "authorizer",
        );
        rejected(&context_with("<auth><realm>admins</realm></auth>"), "realm");
    }

    #[test]
    fn vhost_access_control_and_realms_are_rejected() {
        rejected(
            &vhost_with(
                "<security><accessControl><allow>ALL</allow><deny>203.0.113.0/24</deny></accessControl></security>",
            ),
            "accessControl",
        );
        rejected(
            &vhost_with(
                "<security><realmList><realm><type>file</type><name>admins</name></realm></realmList></security>",
            ),
            "realmList",
        );
        rejected(
            &vhost_with("<realmList><realm><name>admins</name></realm></realmList>"),
            "realmList",
        );
    }

    #[test]
    fn empty_or_open_access_control_still_parses() {
        // The live admin.windowsforum.com.xml shape: an empty context block.
        for xml in [
            context_with("<accessControl>\n      </accessControl>"),
            context_with("<accessControl><allow></allow><deny></deny></accessControl>"),
            context_with("<accessControl><allow>*</allow><deny></deny></accessControl>"),
            context_with("<accessControl><allowList>*</allowList></accessControl>"),
            context_with("<authName>Admin area</authName>"),
            // The LiteSpeed vhost template default.
            vhost_with(
                "<security><hotlinkCtrl></hotlinkCtrl><realmList>\n</realmList><accessControl><allow>*</allow><deny></deny></accessControl></security>",
            ),
            vhost_with("<security><accessControl><allow>ALL</allow></accessControl></security>"),
        ] {
            parse_vhost_config(&xml, &Default::default())
                .unwrap_or_else(|e| panic!("{xml} must parse: {e}"));
        }
    }

    // ----- #790: OLS reads a root-level <accessControl> without <security> -----

    #[test]
    fn root_level_vhost_access_control_is_rejected() {
        rejected(
            &vhost_with(
                "<accessControl><allow>ALL</allow><deny>203.0.113.0/24</deny></accessControl>",
            ),
            "accessControl",
        );
        parse_vhost_config(
            &vhost_with("<accessControl><allow>*</allow></accessControl>"),
            &Default::default(),
        )
        .expect("an open root-level block is a no-op");
    }

    #[test]
    fn root_level_server_access_control_is_the_server_acl() {
        let text = "<httpServerConfig><accessControl><allow>ALL</allow><deny>203.0.113.0/24</deny></accessControl></httpServerConfig>";
        let cfg = parse_server_text(Path::new("/tmp"), Path::new("<test>"), text).unwrap();
        assert!(
            cfg.security
                .access_control
                .iter()
                .any(|r| !r.allow && r.spec.contains("203.0.113.0/24")),
            "{:?}",
            cfg.security.access_control
        );
        let wrapped = "<httpServerConfig><security><accessControl><allow>ALL</allow></accessControl></security><accessControl><deny>ALL</deny></accessControl></httpServerConfig>";
        let cfg = parse_server_text(Path::new("/tmp"), Path::new("<test>"), wrapped).unwrap();
        assert!(
            cfg.security.access_control.iter().all(|r| r.allow),
            "<security> wins"
        );
    }

    // ----- #802: OLS context types -----

    fn one_context(kind: &str, extra: &str) -> String {
        vhost_with(&format!(
            "<contextList><context><type>{kind}</type><uri>/app/</uri>{extra}</context></contextList>"
        ))
    }

    #[test]
    fn context_types_are_case_insensitive_and_null_is_static() {
        for (kind, want) in [
            ("null", ContextKind::Static),
            ("NULL", ContextKind::Static),
            ("Static", ContextKind::Static),
            ("static", ContextKind::Static),
            ("", ContextKind::Static),
            ("Proxy", ContextKind::Proxy),
            ("proxy", ContextKind::Proxy),
        ] {
            let extra = if want == ContextKind::Proxy {
                "<handler>app</handler>"
            } else {
                "<location>/srv/app/</location><extraHeaders>X-A: 1</extraHeaders>"
            };
            let cfg = parse_vhost_config(&one_context(kind, extra), &Default::default())
                .unwrap_or_else(|e| panic!("{kind:?}: {e}"));
            let c = &cfg.contexts[0];
            assert_eq!(c.kind, want, "{kind:?}");
            if want == ContextKind::Static {
                assert_eq!(c.location.as_deref(), Some(Path::new("/srv/app/")));
                assert_eq!(c.extra_headers, vec![("X-A".into(), "1".into())]);
            }
        }
    }

    #[test]
    fn unimplemented_context_types_are_rejected() {
        for kind in [
            "fcgi",
            "FCGI",
            "servlet",
            "redirect",
            "Redirect",
            "lsapi",
            "appserver",
            "rails",
            "module",
            "cgi",
            "webapp",
            "loadbalancer",
            "bogus",
        ] {
            rejected(
                &one_context(kind, "<handler>x</handler><location>/x</location>"),
                "context.type",
            );
        }
    }

    // ----- #803: context allowBrowse -----

    #[test]
    fn context_allow_browse_is_parsed() {
        let browse = |kind: &str, v: &str| {
            parse_vhost_config(
                &one_context(kind, &format!("<handler>app</handler>{v}")),
                &Default::default(),
            )
            .unwrap()
            .contexts[0]
                .allow_browse
        };
        assert!(browse("null", ""));
        assert!(browse("null", "<allowBrowse>1</allowBrowse>"));
        assert!(!browse("null", "<allowBrowse>0</allowBrowse>"));
        assert!(!browse("static", "<allowBrowse> 0 </allowBrowse>"));
        // OLS forces browsing on for handler contexts.
        assert!(browse("proxy", "<allowBrowse>0</allowBrowse>"));
        rejected(
            &one_context("null", "<allowBrowse>maybe</allowBrowse>"),
            "allowBrowse",
        );
    }

    // ----- #828: context addDefaultCharset is tri-state -----

    #[test]
    fn context_add_default_charset_distinguishes_absent_from_off() {
        let charset = |v: &str| {
            parse_vhost_config(&one_context("null", v), &Default::default())
                .unwrap()
                .contexts[0]
                .add_default_charset
        };
        assert_eq!(charset(""), None, "absent inherits");
        assert_eq!(
            charset("<addDefaultCharset>off</addDefaultCharset>"),
            Some(false)
        );
        assert_eq!(
            charset("<addDefaultCharset>On</addDefaultCharset>"),
            Some(true)
        );
    }

    // ----- #804: root-level accessDenyDir / fileAccessControl -----

    #[test]
    fn root_level_deny_dir_and_file_access_control_fold_without_security() {
        let text = "<httpServerConfig><accessDenyDir><dir>/etc/*</dir><dir>$SERVER_ROOT/conf/*</dir></accessDenyDir><fileAccessControl><followSymbolLink>1</followSymbolLink></fileAccessControl></httpServerConfig>";
        let cfg = parse_server_text(Path::new("/srv/ls"), Path::new("<test>"), text).unwrap();
        assert_eq!(
            cfg.security.access_deny_dir,
            vec!["/etc/*".to_string(), "/srv/ls/conf/*".to_string()]
        );
        assert!(cfg.security.follow_symlink);
        let wrapped = "<httpServerConfig><security><accessDenyDir><dir>/a/*</dir></accessDenyDir></security><accessDenyDir><dir>/b/*</dir></accessDenyDir><fileAccessControl><followSymbolLink>1</followSymbolLink></fileAccessControl></httpServerConfig>";
        let cfg = parse_server_text(Path::new("/srv/ls"), Path::new("<test>"), wrapped).unwrap();
        assert_eq!(cfg.security.access_deny_dir, vec!["/a/*".to_string()]);
        assert!(!cfg.security.follow_symlink, "<security> wins");
    }

    // ----- bug bash 2026-10-25: directives that were silently unenforced -----

    #[test]
    fn extra_headers_accept_only_name_value_lines() {
        let ok = parse_vhost_config(
            &one_context(
                "static",
                "<location>/srv/app/</location><extraHeaders>Vary: Accept\nCache-Control: public, max-age=300\n\n</extraHeaders>",
            ),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(ok.contexts[0].extra_headers.len(), 2);
        for ops in [
            "set Cache-Control no-store",
            "Header always set X-Frame-Options DENY",
            "unset X-Powered-By",
            "Header set Content-Security-Policy \"default-src https://x\"",
        ] {
            let text = one_context(
                "static",
                &format!("<location>/srv/app/</location><extraHeaders>{ops}</extraHeaders>"),
            );
            let err = parse_vhost_config(&text, &Default::default()).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidValue {
                        directive: "extraHeaders",
                        ..
                    }
                ),
                "{ops}: {err}"
            );
        }
    }

    #[test]
    fn proxy_context_extra_headers_are_refused_unless_empty() {
        let empty = one_context(
            "proxy",
            "<handler>app</handler><extraHeaders>\n\n</extraHeaders>",
        );
        assert!(parse_vhost_config(&empty, &Default::default()).is_ok());
        let set = one_context(
            "proxy",
            "<handler>app</handler><extraHeaders>X-Frame-Options: DENY</extraHeaders>",
        );
        assert!(matches!(
            parse_vhost_config(&set, &Default::default()).unwrap_err(),
            ConfigError::InvalidValue {
                directive: "extraHeaders",
                ..
            }
        ));
    }

    #[test]
    fn enabled_hotlink_control_and_strict_ownership_are_refused() {
        let vh = |v: &str| {
            vhost_with(&format!(
                "<security><hotlinkCtrl><enableHotlinkCtrl>{v}</enableHotlinkCtrl><suffixes>jpg</suffixes></hotlinkCtrl></security>"
            ))
        };
        // OLS getLongValue(0..1, default 0): out of range reads as off.
        for v in ["0", "", "2", "-1"] {
            assert!(
                parse_vhost_config(&vh(v), &Default::default()).is_ok(),
                "{v:?}"
            );
        }
        let bare = vhost_with("<security><hotlinkCtrl></hotlinkCtrl></security>");
        assert!(parse_vhost_config(&bare, &Default::default()).is_ok());
        assert!(matches!(
            parse_vhost_config(&vh("1"), &Default::default()).unwrap_err(),
            ConfigError::InvalidValue {
                directive: "enableHotlinkCtrl",
                ..
            }
        ));
        let server = |v: &str| {
            format!(
                "<httpServerConfig><fileAccessControl><forceStrictOwnership>{v}</forceStrictOwnership></fileAccessControl></httpServerConfig>"
            )
        };
        let parse =
            |text: String| parse_server_text(Path::new("/srv/ls"), Path::new("<test>"), &text);
        assert!(parse(server("0")).is_ok());
        assert!(parse(server("2")).is_ok());
        assert!(matches!(
            parse(server("1")).unwrap_err(),
            ConfigError::InvalidValue {
                directive: "forceStrictOwnership",
                ..
            }
        ));
        let declared = "<httpServerConfig><virtualHostList><virtualHost><name>a</name>\
            <vhRoot>/srv/a</vhRoot><configFile>/srv/a/vhconf.xml</configFile>\
            <forceStrictOwnership>1</forceStrictOwnership></virtualHost></virtualHostList>\
            </httpServerConfig>";
        assert!(matches!(
            parse(declared.to_string()).unwrap_err(),
            ConfigError::InvalidValue {
                directive: "virtualHost.forceStrictOwnership",
                ..
            }
        ));
    }

    #[test]
    fn extra_headers_none_means_none_and_stops_inheritance() {
        for none in ["NONE", "none", " None \n"] {
            let text = one_context(
                "static",
                &format!("<location>/srv/app/</location><extraHeaders>{none}</extraHeaders>"),
            );
            let cfg = parse_vhost_config(&text, &Default::default())
                .unwrap_or_else(|e| panic!("{none:?}: {e}"));
            assert!(cfg.contexts[0].extra_headers.is_empty());
            assert!(!cfg.contexts[0].inherit_extra_headers);
        }
        let text = one_context(
            "static",
            "<location>/srv/app/</location><extraHeaders>X-A: 1</extraHeaders>",
        );
        let cfg = parse_vhost_config(&text, &Default::default()).unwrap();
        assert!(cfg.contexts[0].inherit_extra_headers);
    }

    #[test]
    fn dotted_php_suffixes_route_like_bare_ones() {
        let text = "<httpServerConfig><phpConfig><phpHandler><id>lsphp</id><command>/usr/bin/php</command><suffixes>.php, .html</suffixes></phpHandler></phpConfig></httpServerConfig>";
        let cfg = parse_server_text(Path::new("/srv/ls"), Path::new("<test>"), text).unwrap();
        let suffixes = &cfg.php_config.as_ref().unwrap().suffixes;
        assert!(
            suffixes.iter().any(|s| s == "php") && suffixes.iter().any(|s| s == "html"),
            "{suffixes:?}"
        );
        assert!(!suffixes.iter().any(|s| s.starts_with('.')), "{suffixes:?}");
    }

    // ----- round 9: OLS config forms -----

    #[test]
    fn vhost_index_block_follows_use_server() {
        let own = parse_vhost_config(
            &vhost_with(
                "<index><useServer>0</useServer><indexFiles>index.php</indexFiles></index>",
            ),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(own.index_files, vec!["index.php".to_string()]);
        assert_eq!(own.index_use_server, Some(0));
        let server = parse_vhost_config(
            &vhost_with("<index><indexFiles>index.php</indexFiles></index>"),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(server.index_use_server, Some(1), "useServer defaults to 1");
        // The flat form keeps its historical meaning (the live mcp vhost).
        let flat = parse_vhost_config(
            &vhost_with("<indexFiles>index.html</indexFiles>"),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(flat.index_files, vec!["index.html".to_string()]);
        assert_eq!(flat.index_use_server, None);
    }

    #[test]
    fn context_default_charset_customized_is_read() {
        let vc = parse_vhost_config(
            &context_with(
                "<addDefaultCharset>on</addDefaultCharset><defaultCharsetCustomized>windows-1252</defaultCharsetCustomized>",
            ),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(vc.contexts[0].charset.as_deref(), Some("windows-1252"));
    }

    #[test]
    fn mime_inline_comments_are_stripped() {
        let m = parse_mime("text/plain = xyz # plain text\n# whole line\n");
        assert_eq!(
            m.by_suffix.get("xyz").map(String::as_str),
            Some("text/plain")
        );
    }

    /// Regression (#944): `default = <type>` sets the fallback type (OLS
    /// `m_pDefault`) instead of mapping a literal `.default` suffix.
    #[test]
    fn mime_default_entry_is_the_fallback_type() {
        let m = parse_mime("default = text/plain\ntext/html = html\n");
        assert_eq!(m.default_type(), "text/plain");
        assert!(m.content_type("default").is_none());
        assert_eq!(m.content_type("html"), Some("text/html"));
        let m = parse_mime("image/png = Default, foo\n");
        assert_eq!(m.default_type(), "image/png");
        assert_eq!(m.content_type("foo"), Some("image/png"));
        assert_eq!(parse_mime("").default_type(), "application/octet-stream");
    }
}
