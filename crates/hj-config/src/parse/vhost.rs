//! Per-vhost XML file loading and conversion: `convert_vhost_decls`,
//! `load_vhost_files`, and `parse_vhost_config`.

use std::path::PathBuf;
use std::sync::Arc;

use crate::error::{ConfigError, Result};
use crate::model::*;
use crate::subst::SubstCtx;
use crate::units::{parse_bytes, parse_secs, split_list};

use super::raw::{RawLogFileSpec, RawVHostConfig, RawVHostList};
use super::scalar::u32_of;
use super::scalar::{
    bounded_u8, charset_on, context_kind, follow_symlink_value, lsws_size, nonempty,
    parse_extra_headers, symlink_override, truthy,
};
// convert_ext_list / convert_expires / convert_namespace live in the parent mod
use super::{convert_expires, convert_ext_list, convert_namespace};

/// Convert a per-vhost `<cache>` block. Returns `None` when caching is not
/// enabled for the vhost (absent block or `enableCache` off), so the pipeline
/// treats the vhost as non-cacheable. When enabled with no explicit
/// `<cachePolicy>`, public caching defaults on (LiteSpeed behavior).
pub(super) fn convert_vhost_cache(
    r: Option<super::raw::RawVhostCache>,
) -> Option<VhostCachePolicy> {
    let r = r?;
    if !truthy(&r.enable_cache) {
        return None;
    }
    let (enable_public, enable_private) = match r.cache_policy {
        Some(p) => (
            p.enable_public
                .as_ref()
                .map(|_| truthy(&p.enable_public))
                .unwrap_or(true),
            truthy(&p.enable_private),
        ),
        None => (true, false),
    };
    Some(VhostCachePolicy {
        enable_cache: true,
        enable_public,
        enable_private,
    })
}

pub(super) fn convert_vhost_decls(
    r: Option<RawVHostList>,
    ctx: &SubstCtx,
) -> (std::collections::BTreeMap<String, VHostDecl>, Vec<String>) {
    let mut map = std::collections::BTreeMap::new();
    let mut order = Vec::new();
    let r = match r {
        Some(r) => r,
        None => return (map, order),
    };
    for v in r.vhost {
        let name = match nonempty(v.name) {
            Some(n) => n,
            None => continue,
        };
        // Per-vhost substitution context binds $VH_NAME and $VH_ROOT.
        let vh_root_raw = v.vh_root.as_deref().unwrap_or("");
        let mut vctx = ctx.clone();
        vctx.vh_name = name.clone();
        vctx.vh_root = vctx.expand(vh_root_raw);
        let mut config_file = PathBuf::from(vctx.expand(v.config_file.as_deref().unwrap_or("")));
        // LiteSpeed allows bare relative configFile paths (e.g. mcp's
        // "conf/vhosts/...") resolved against $SERVER_ROOT.
        if config_file.is_relative() {
            config_file = PathBuf::from(&ctx.server_root).join(config_file);
        }
        order.push(name.clone());
        map.insert(
            name.clone(),
            VHostDecl {
                name,
                vh_root: PathBuf::from(vctx.vh_root.clone()),
                config_file,
                allow_symbol_link: symlink_override(&v.allow_symbol_link),
                restrained: v.restrained.as_deref().map(str::trim) == Some("1"),
                enable_script: v
                    .enable_script
                    .as_ref()
                    .map(|_| truthy(&v.enable_script))
                    .unwrap_or(true),
                config: None,
            },
        );
    }
    (map, order)
}

/// Load every vhost's per-vhost XML file into its `VHostDecl::config`.
pub(super) fn load_vhost_files(cfg: &mut ServerConfig) -> Result<()> {
    let server_root = cfg.server_root.clone();
    let hostname = cfg.server_name.clone();
    let follow_symlink = cfg.security.follow_symlink;
    let names: Vec<String> = cfg.vhost_order.clone();
    for name in names {
        let (config_file, vh_root, decl_symlink_override, decl_restrained) = {
            let decl = &cfg.vhosts[&name];
            (
                decl.config_file.clone(),
                decl.vh_root.clone(),
                decl.allow_symbol_link,
                decl.restrained,
            )
        };
        let text = match std::fs::read_to_string(&config_file) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(vhost = %name, path = %config_file.display(), error = %e, "skipping vhost: cannot read config file");
                continue;
            }
        };
        let vctx = SubstCtx {
            server_root: server_root.to_string_lossy().into_owned(),
            hostname: hostname.clone(),
            vh_name: name.clone(),
            vh_root: vh_root.to_string_lossy().into_owned(),
        };
        match parse_vhost_config(&text, &vctx) {
            Ok(mut vc) => {
                // Effective symlink policy (LSWS tri-state, audit M4): the vhost FILE's
                // explicit <allowSymbolLink> overrides, else the DECLARATION's, else the
                // server-wide followSymbolLink. The old OR-merge made an explicit
                // hardening `0` impossible to express. (#249) A RESTRAINED vhost never
                // follows symlinks: the follow arm cannot confine targets to vhRoot.
                vc.allow_symbol_link = !decl_restrained
                    && vc
                        .allow_symbol_link_override
                        .or(decl_symlink_override)
                        .unwrap_or(follow_symlink);
                if let Some(decl) = cfg.vhosts.get_mut(&name) {
                    decl.config = Some(Arc::new(vc));
                }
            }
            Err(e @ ConfigError::InvalidValue { .. }) => return Err(e),
            Err(e) => {
                tracing::warn!(vhost = %name, error = %e, "skipping vhost: parse error");
            }
        }
    }
    Ok(())
}

/// Parse a per-vhost XML file body into [`VHostConfig`].
pub(crate) fn parse_vhost_config(text: &str, ctx: &SubstCtx) -> Result<VHostConfig> {
    let config_path = PathBuf::from(format!("<vhost {}>", ctx.vh_name));
    let raw: RawVHostConfig = quick_xml::de::from_str(text).map_err(|e| ConfigError::Xml {
        path: config_path.clone(),
        msg: e.to_string(),
    })?;

    let rewrite = raw
        .rewrite
        .map(|rw| InlineRewrite {
            enable: truthy(&rw.enable),
            auto_load_htaccess: truthy(&rw.auto_load_htaccess),
            base: nonempty(rw.base),
            rules: rw.rules.unwrap_or_default(),
        })
        .unwrap_or_default();

    let contexts =
        raw.context_list
            .map(|cl| {
                cl.context
                    .into_iter()
                    .map(|mut c| -> Result<Option<Context>> {
                        let sub_filter = convert_sub_filter(&c);
                        let Some(uri) = nonempty(c.uri.take()) else {
                            return Ok(None);
                        };
                        let parse_value = |directive: &'static str,
                                           raw: &Option<String>,
                                           parse: fn(&str) -> Option<u64>,
                                           expected: &'static str|
                         -> Result<Option<u64>> {
                            match raw {
                                None => Ok(None),
                                Some(value) => parse(value).map(Some).ok_or_else(|| {
                                    ConfigError::InvalidValue {
                                        path: config_path.clone(),
                                        directive,
                                        value: value.clone(),
                                        reason: format!("{expected} in context {uri:?}"),
                                    }
                                }),
                            }
                        };
                        let max_body_override = parse_value(
                            "maxReqBodySize",
                            &c.max_req_body_size,
                            parse_bytes,
                            "expected a non-negative byte size with an optional K/M/G suffix",
                        )?;
                        let bandwidth_limit = parse_value(
                            "bandwidthLimit",
                            &c.bandwidth_limit,
                            parse_bytes,
                            "expected a non-negative byte rate with an optional K/M/G suffix",
                        )?
                        .unwrap_or(0);
                        let timeout_override = parse_value(
                            "responseTimeout",
                            &c.response_timeout,
                            parse_secs,
                            "expected a non-negative integer number of seconds",
                        )?;
                        Ok(Some(Context {
                            kind: context_kind(&c.kind),
                            uri,
                            location: nonempty(c.location).map(|p| PathBuf::from(ctx.expand(&p))),
                            handler: nonempty(c.handler),
                            enabled: c
                                .enabled
                                .as_ref()
                                .map(|_| truthy(&c.enabled))
                                .unwrap_or(true),
                            extra_headers: c
                                .extra_headers
                                .as_deref()
                                .map(parse_extra_headers)
                                .unwrap_or_default(),
                            add_default_charset: charset_on(&c.add_default_charset),
                            charset: nonempty(c.charset),
                            max_body_override,
                            bandwidth_limit,
                            timeout_override,
                            sub_filter,
                            cache_policy: c.cache_policy.map(|p| {
                                // A present-but-absent FLAG defaults ON (LSWS
                                // getLongValue(..,default) semantics), except
                                // enablePostCache which OLS defaults off.
                                let f = |v: &Option<String>, d: bool| {
                                    v.as_deref()
                                        .map(|s| {
                                            let t = s.trim();
                                            t == "1" || t == "2" || t.eq_ignore_ascii_case("true")
                                        })
                                        .unwrap_or(d)
                                };
                                ContextCachePolicy {
                                    check_public_cache: f(&p.check_public_cache, true),
                                    check_private_cache: f(&p.check_private_cache, true),
                                    respect_cacheable: f(&p.respect_cacheable, true),
                                    enable_cache: f(&p.enable_cache, true),
                                    enable_private_cache: f(&p.enable_private_cache, true),
                                    enable_post_cache: f(&p.enable_post_cache, false),
                                }
                            }),
                        }))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .collect();

    let websockets = raw
        .websocket_list
        .map(|wl| {
            wl.websocket
                .into_iter()
                .filter_map(|w| {
                    Some(WebSocketMap {
                        uri: nonempty(w.uri)?,
                        address: nonempty(w.address)?,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let vhssl = raw.vhssl.and_then(|s| {
        let cert_file = nonempty(s.cert_file)?;
        let key_file = nonempty(s.key_file)?;
        Some(VhSsl {
            key_file: PathBuf::from(ctx.expand(&key_file)),
            cert_file: PathBuf::from(ctx.expand(&cert_file)),
            cert_chain: truthy(&s.cert_chain),
            ca_cert_file: nonempty(s.ca_cert_file).map(|p| PathBuf::from(ctx.expand(&p))),
        })
    });

    let isolation = convert_isolation(
        &raw.set_uid_mode,
        &raw.chroot_mode,
        &raw.chroot_path,
        &raw.suexec_user,
        &raw.suexec_group,
        convert_namespace(raw.namespace),
        ctx,
    );

    let script_handlers = raw
        .script_handler_list
        .map(|shl| {
            shl.script_handler
                .into_iter()
                .filter_map(|sh| {
                    let suffix = nonempty(sh.suffix)?.trim().to_ascii_lowercase();
                    let kind = context_kind(&sh.kind);
                    // A `static` override carries no ext-processor; handler-dispatching
                    // kinds (lsapi/cgi/proxy/appserver/...) still require one.
                    let handler = match nonempty(sh.handler) {
                        Some(h) => h,
                        None if matches!(kind, ContextKind::Static | ContextKind::Other) => {
                            String::new()
                        }
                        None => return None,
                    };
                    Some(ScriptHandler {
                        suffix,
                        kind,
                        handler,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // `<htAccess>`: allowOverride bitmask + accessFileName. Absent block => off.
    // An EXPLICIT `0` is recorded separately (audit): it FORBIDS overrides, while a
    // merely-absent block defers to `<rewrite><autoLoadHtaccess>`.
    let ht_access = raw.htaccess;
    let allow_override_explicit = ht_access
        .as_ref()
        .is_some_and(|h| h.allow_override.is_some());
    let (allow_override, access_file_name) = ht_access
        .map(|h| {
            let bits = h
                .allow_override
                .as_deref()
                .map(str::trim)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            // Parser fills ".htaccess" when the element is absent/empty.
            let name = nonempty(h.access_file_name).unwrap_or_else(|| ".htaccess".to_string());
            (bits, name)
        })
        .unwrap_or((0, String::new()));

    // (#248) Per-vhost `<logging>`: only an explicit `useServer=0` + fileName means
    // "this vhost writes its OWN file"; useServer=1/absent rides the unified logs.
    let own_file = |spec: Option<&RawLogFileSpec>| -> Option<VhostLogFile> {
        let s = spec?;
        if !s
            .use_server
            .as_deref()
            .map(str::trim)
            .unwrap_or("1")
            .eq_ignore_ascii_case("0")
        {
            return None;
        }
        let path = nonempty(s.file_name.clone())?;
        Some(VhostLogFile {
            path: PathBuf::from(ctx.expand(&path)),
            rolling_bytes: lsws_size(&s.rolling_size, 50 * 1024 * 1024),
            keep_days: u32_of(&s.keep_days, 30) as u64,
            log_headers: 0,
        })
    };
    let mut access_log_file = raw
        .logging
        .as_ref()
        .and_then(|l| l.access_log.as_ref())
        .and_then(|a| {
            own_file(Some(&RawLogFileSpec {
                use_server: a.use_server.clone(),
                file_name: a.file_name.clone(),
                rolling_size: a.rolling_size.clone(),
                keep_days: a.keep_days.clone(),
            }))
        });
    if let (Some(f), Some(a)) = (
        access_log_file.as_mut(),
        raw.logging.as_ref().and_then(|l| l.access_log.as_ref()),
    ) {
        f.log_headers = u32_of(&a.log_headers, 0) as u8;
    }
    let error_log_file = own_file(raw.logging.as_ref().and_then(|l| l.log.as_ref()));

    Ok(VHostConfig {
        doc_root: PathBuf::from(ctx.expand(raw.doc_root.as_deref().unwrap_or(""))),
        index_files: raw
            .index_files
            .as_deref()
            .map(split_list)
            .unwrap_or_default(),
        allow_symbol_link: follow_symlink_value(&raw.allow_symbol_link),
        allow_symbol_link_override: symlink_override(&raw.allow_symbol_link),
        rewrite,
        contexts,
        script_handlers,
        websockets,
        vhssl,
        expires: raw.expires.map(|e| convert_expires(Some(e))),
        cache_policy: convert_vhost_cache(raw.cache),
        extra_ext_processors: convert_ext_list(raw.ext_processor_list, ctx),
        isolation,
        allow_override,
        allow_override_explicit,
        access_log_file,
        error_log_file,
        access_file_name,
    })
}

/// Build a [`VHostIsolation`] from per-vhost `setUIDMode`/`chrootMode`/
/// `chrootPath` (+ optional `suexecUser`/`suexecGroup`).
///
/// LiteSpeed `setUIDMode` (localworker.cpp / vhost.cpp): `0` = server uid/gid
/// (no override), `1` = explicit suEXEC user/group, `2` = `UID_DOCROOT` (take
/// the doc-root owner). `chrootMode`: `0` = none, `1` = `CHROOT_VHROOT`,
/// `2` = `CHROOT_PATH` (localworker.cpp:473-483).
///
/// Returns `None` (no per-vhost isolation, today's behavior) when there is
/// nothing to override: `setUIDMode` is absent/`0`, `chrootMode` is absent/`0`,
/// **and** there is no per-vhost `<namespace>` block. A namespace-only override
/// (no setUID/chroot) still produces a [`VHostIsolation`] so the override is
/// carried; the credential/chroot fields stay at their no-op defaults and the
/// *master gate* + root gate in `JailConfig::resolve` still govern whether
/// anything is applied. This only records config intent.
pub(super) fn convert_isolation(
    set_uid_mode: &Option<String>,
    chroot_mode: &Option<String>,
    chroot_path: &Option<String>,
    suexec_user: &Option<String>,
    suexec_group: &Option<String>,
    namespaces: Option<NamespacePolicy>,
    ctx: &SubstCtx,
) -> Option<VHostIsolation> {
    // OLS getLongValue(..., setUIDMode, 0, 2, 0) / chrootMode 0..=2, default 0.
    let uid_mode = bounded_u8(set_uid_mode, 0, 2, 0);
    let chroot_mode_v = bounded_u8(chroot_mode, 0, 2, 0);
    if uid_mode == 0 && chroot_mode_v == 0 && namespaces.is_none() {
        return None;
    }
    let chroot = match chroot_mode_v {
        1 => ChrootMode::VhRoot,
        2 => match nonempty(chroot_path.clone()) {
            Some(p) => ChrootMode::Path(PathBuf::from(ctx.expand(&p))),
            // chrootMode=PATH but no path given → treat as no chroot (OLS
            // nulls the chroot when getChroot() is empty, localworker.cpp:481).
            None => ChrootMode::None,
        },
        _ => ChrootMode::None,
    };
    Some(VHostIsolation {
        user: nonempty(suexec_user.clone()).unwrap_or_default(),
        group: nonempty(suexec_group.clone()).unwrap_or_default(),
        chroot,
        // setUIDMode == 2 (UID_DOCROOT) takes credentials from the doc-root owner.
        from_docroot_owner: uid_mode == 2,
        namespaces,
    })
}

/// (Tier 2) Build the context's sub_filter plan: repeatable
/// `<subFilter>SEARCH => REPLACEMENT</subFilter>` children plus the
/// `subFilterOnce`/`subFilterTypes`/`subFilterMaxBody` modifiers. Absent when
/// no rule is configured.
fn convert_sub_filter(c: &super::raw::RawContext) -> Option<Box<crate::SubFilterConfig>> {
    use crate::units::parse_bytes;
    if c.sub_filter.is_empty() {
        return None;
    }
    let mut cfg = crate::SubFilterConfig::default();
    for (idx, rule) in c.sub_filter.iter().enumerate() {
        let Some((search, replace)) = rule.split_once("=>") else {
            // A rule without the `=>` separator would silently never match;
            // that's a config bug, not a no-op.
            tracing::warn!(
                rule = %rule,
                "subFilter rule {idx}: missing `=>` separator — context sub_filter DISABLED"
            );
            return None;
        };
        cfg.rules
            .push((search.trim().to_string(), replace.trim().to_string()));
    }
    if let Some(v) = c.sub_filter_once.as_deref() {
        cfg.once = v.trim() == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Some(v) = c.sub_filter_types.as_deref() {
        let types: Vec<String> = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !types.is_empty() {
            cfg.types = types;
        }
    }
    if let Some(n) = c.sub_filter_max_body.as_deref().and_then(parse_bytes) {
        cfg.max_body = n;
    }
    Some(Box::new(cfg))
}
