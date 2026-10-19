//! Per-vhost XML file loading and conversion: `convert_vhost_decls`,
//! `load_vhost_files`, and `parse_vhost_config`.

use std::path::PathBuf;
use std::sync::Arc;

use crate::error::{ConfigError, Result};
use crate::model::*;
use crate::subst::SubstCtx;
use crate::units::{parse_bytes, parse_secs, split_list};

use super::raw::{
    RawContext, RawHtAccess, RawLogFileSpec, RawRewrite, RawScopedAccessControl, RawVHostConfig,
    RawVHostList, RawVhSsl,
};
use super::scalar::u32_of;
use super::scalar::{
    bounded_u8, charset_on, context_kind, follow_symlink_value, lsws_size, nonempty,
    ols_long_value, parse_extra_headers, symlink_override, truthy,
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

/// Declarations by name, their order, and the names whose declaration
/// disables them or that `<suspendedVhosts>` lists.
type VhostDecls = (
    std::collections::BTreeMap<String, VHostDecl>,
    Vec<String>,
    std::collections::BTreeSet<String>,
);

pub(super) fn convert_vhost_decls(
    r: Option<RawVHostList>,
    suspended: Option<&str>,
    ctx: &SubstCtx,
    path: &std::path::Path,
    strict: bool,
) -> Result<VhostDecls> {
    let mut map = std::collections::BTreeMap::new();
    let mut order = Vec::new();
    // OLS `checkSuspendedVHostList`: exact names; any listed vhost is disabled.
    let mut disabled: std::collections::BTreeSet<String> = suspended
        .map(split_list)
        .unwrap_or_default()
        .into_iter()
        .collect();
    let r = match r {
        Some(r) => r,
        None => return Ok((map, order, disabled)),
    };
    for v in r.vhost {
        let name = match nonempty(v.name) {
            Some(n) => n,
            None => continue,
        };
        // OLS addVHost refuses a second vhost with the same name (#924).
        if map.contains_key(&name) {
            if strict {
                return Err(ConfigError::InvalidValue {
                    path: path.to_path_buf(),
                    directive: "virtualHost.name",
                    value: name,
                    reason: "duplicate virtualHost name".into(),
                });
            }
            tracing::warn!(vhost = %name, "duplicate virtualHost name; keeping the first declaration");
            continue;
        }
        if let Some(listeners) = nonempty(v.listeners) {
            return Err(ConfigError::InvalidValue {
                path: path.to_path_buf(),
                directive: "virtualHost.listeners",
                value: listeners,
                reason: format!(
                    "vhost {name:?}: listener auto-mapping is not supported; map it with <vhostMapList>"
                ),
            });
        }
        // Per-vhost substitution context binds $VH_NAME and $VH_ROOT.
        let vh_root_raw = v.vh_root.as_deref().unwrap_or("");
        let mut vctx = ctx.clone();
        vctx.vh_name = name.clone();
        vctx.vh_root = server_rooted(&vctx, vh_root_raw)
            .to_string_lossy()
            .into_owned();
        let mut config_file = PathBuf::from(vctx.expand(v.config_file.as_deref().unwrap_or("")));
        // LiteSpeed allows bare relative configFile paths (e.g. mcp's
        // "conf/vhosts/...") resolved against $SERVER_ROOT.
        if config_file.is_relative() {
            config_file = PathBuf::from(&ctx.server_root).join(config_file);
        }
        // OLS `serverEnabled(getLongValue(.., "enabled", 0, 1, 1))`.
        if ols_long_value(&v.enabled, 0, 1, 1) == 0 {
            disabled.insert(name.clone());
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
    Ok((map, order, disabled))
}

/// Load every vhost's per-vhost XML file into its `VHostDecl::config`.
pub(super) fn load_vhost_files(
    cfg: &mut ServerConfig,
    inherit: &super::VhostInherit,
) -> Result<Vec<SkippedVhost>> {
    load_vhost_sources(cfg, inherit, false, |_, path| {
        super::read_config_file(path, super::MAX_CONFIG_FILE_BYTES)
    })
}

pub(super) fn load_vhost_sources(
    cfg: &mut ServerConfig,
    inherit: &super::VhostInherit,
    strict: bool,
    mut source: impl FnMut(&str, &std::path::Path) -> Result<String>,
) -> Result<Vec<SkippedVhost>> {
    let mut skipped = Vec::new();
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
        let text = match source(&name, &config_file) {
            Ok(t) => t,
            Err(e) if strict => return Err(e),
            Err(e) => {
                tracing::warn!(vhost = %name, path = %config_file.display(), error = %e, "skipping vhost: cannot read config file");
                skipped.push(SkippedVhost { name, error: e });
                continue;
            }
        };
        let vctx = SubstCtx {
            server_root: server_root.to_string_lossy().into_owned(),
            hostname: hostname.clone(),
            vh_name: name.clone(),
            vh_root: vh_root.to_string_lossy().into_owned(),
            ..Default::default()
        };
        match parse_vhost_config(&text, &vctx) {
            Ok(mut vc) => {
                // OLS: the declaration gates the file's <enabled>, and the
                // suspended list overrides both (#1000).
                vc.disabled |= inherit.disabled.contains(&name);
                // LSWS: a vhost without its own allowOverride takes the server's.
                if !vc.allow_override_explicit
                    && let Some(bits) = inherit.allow_override
                {
                    vc.allow_override = bits;
                }
                // OLS: a vhost inherits the server's script handlers; its own
                // entry wins per suffix (#928).
                for handler in &inherit.script_handlers {
                    if !vc
                        .script_handlers
                        .iter()
                        .any(|h| h.suffix == handler.suffix)
                    {
                        vc.script_handlers.push(handler.clone());
                    }
                }
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
                vc.index_files = match vc.index_use_server {
                    Some(1) => Vec::new(),
                    Some(2) => cfg
                        .index_files
                        .iter()
                        .chain(&vc.index_files)
                        .cloned()
                        .collect(),
                    _ => std::mem::take(&mut vc.index_files),
                };
                if let Some(decl) = cfg.vhosts.get_mut(&name) {
                    decl.config = Some(Arc::new(vc));
                }
            }
            // An InvalidValue is a directive the vhost declares but httpjet cannot
            // honor (access control/realms #773, phpIniOverride/customErrorPages
            // #925, apacheConf/context rewrite/forceType #999) or a malformed value
            // (#919/#1004): it refuses the whole load, so a reload keeps the old
            // state. Anything else (unreadable file, XML error, no <docRoot>) skips
            // only this vhost, as OLS does (#1010).
            Err(e) if strict || matches!(e, ConfigError::InvalidValue { .. }) => return Err(e),
            Err(e) => {
                tracing::warn!(vhost = %name, error = %e, "skipping vhost: parse error");
                skipped.push(SkippedVhost { name, error: e });
            }
        }
    }
    Ok(skipped)
}

fn unenforced(
    path: &std::path::Path,
    directive: &'static str,
    value: String,
    scope: &str,
) -> ConfigError {
    ConfigError::InvalidValue {
        path: path.to_path_buf(),
        directive,
        value,
        reason: format!(
            "{scope} {directive} is not enforced by httpjet; refusing to serve it unprotected"
        ),
    }
}

/// `true` when an `<accessControl>` admits every client: no deny entries and an
/// allow list (if any) of only `ALL`/`*`, the LiteSpeed template default.
fn access_control_is_open(ac: &RawScopedAccessControl) -> bool {
    let tokens = |v: &[String]| v.iter().flat_map(|s| split_list(s)).collect::<Vec<_>>();
    tokens(&ac.deny).is_empty()
        && tokens(&ac.allow).iter().all(|t| {
            let t = match t.strip_suffix(['T', 't']) {
                Some(rest) if !rest.is_empty() => rest,
                _ => t.as_str(),
            };
            t == "*" || t.eq_ignore_ascii_case("ALL")
        })
}

fn reject_scoped_access_control(
    path: &std::path::Path,
    scope: &str,
    ac: Option<&RawScopedAccessControl>,
) -> Result<()> {
    match ac {
        Some(ac) if !access_control_is_open(ac) => Err(unenforced(
            path,
            "accessControl",
            format!("allow={:?} deny={:?}", ac.allow, ac.deny),
            scope,
        )),
        _ => Ok(()),
    }
}

/// Vhost-level `<security>` access control and realms are not implemented. A
/// declared restriction must fail the load rather than serve without it.
fn reject_unenforced_vhost_security(path: &std::path::Path, raw: &RawVHostConfig) -> Result<()> {
    match raw.security.as_ref() {
        Some(sec) => reject_scoped_access_control(path, "vhost", sec.access_control.as_ref())?,
        None => reject_scoped_access_control(path, "vhost", raw.access_control.as_ref())?,
    }
    let declared = [
        raw.security.as_ref().and_then(|s| s.realm_list.as_ref()),
        raw.realm_list.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find(|l| !l.realm.is_empty());
    if let Some(list) = declared {
        let names: Vec<_> = list
            .realm
            .iter()
            .map(|r| r.name.as_deref().unwrap_or("").trim().to_string())
            .collect();
        return Err(unenforced(path, "realmList", names.join(","), "vhost"));
    }
    Ok(())
}

fn reject_unenforced_context_security(path: &std::path::Path, c: &RawContext) -> Result<()> {
    let scope = format!("context {:?}", c.uri.as_deref().unwrap_or(""));
    reject_scoped_access_control(path, &scope, c.access_control.as_ref())?;
    let auth = c.auth.as_ref();
    for (directive, value) in [
        ("realm", c.realm.as_ref()),
        ("required", c.required.as_ref()),
        ("authorizer", c.authorizer.as_ref()),
        ("realm", auth.and_then(|a| a.realm.as_ref())),
        ("required", auth.and_then(|a| a.required.as_ref())),
    ] {
        if let Some(v) = value.map(|v| v.trim()).filter(|v| !v.is_empty()) {
            return Err(unenforced(path, directive, v.to_string(), &scope));
        }
    }
    Ok(())
}

fn doc_root_join(doc_root: &str, relative: &str) -> PathBuf {
    std::path::Path::new(doc_root).join(relative)
}

/// OLS `ConfigCtx::getRootPath`: a path starting with neither `/` nor `$` is
/// relative to `$SERVER_ROOT`, not to the process cwd (`/` under systemd) (#1001).
pub(super) fn server_rooted(ctx: &SubstCtx, raw: &str) -> PathBuf {
    let raw = raw.trim();
    let expanded = PathBuf::from(ctx.expand(raw));
    if raw.is_empty() || raw.starts_with(['/', '$']) {
        expanded
    } else {
        std::path::Path::new(&ctx.server_root).join(expanded)
    }
}

/// The first line of an Apache-style block that is not blank or a `#` comment.
fn first_directive(text: Option<&str>) -> Option<&str> {
    text?
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
}

/// LSWS `<apacheConf>` (server, vhost or context) embeds Apache directives that
/// httpjet does not apply, so a non-empty block refuses the load (#999).
pub(super) fn reject_apache_conf(
    path: &std::path::Path,
    scope: &str,
    apache_conf: Option<&str>,
) -> Result<()> {
    match first_directive(apache_conf) {
        Some(line) => Err(unenforced(path, "apacheConf", line.to_string(), scope)),
        None => Ok(()),
    }
}

/// Context-level `<rewrite>` rules, `<forceType>`/`<addMIMEType>` (#999) and
/// `<allowOverride>` (#1028) are not implemented. OLS applies context rules when
/// the context's `<enable>` (default: the vhost's) is on; an empty or disabled
/// block stays inert, as does `forceType none`, which only clears an inherited
/// forced type.
fn reject_unimplemented_context_directives(
    path: &std::path::Path,
    scope: &str,
    c: &RawContext,
    vhost_rewrite_enable: bool,
) -> Result<()> {
    if let Some(rw) = c.rewrite.as_ref() {
        let enabled = ols_long_value(&rw.enable, 0, 1, i64::from(vhost_rewrite_enable)) == 1;
        if let Some(rule) = first_directive(rw.rules.as_deref()).filter(|_| enabled) {
            return Err(unenforced(path, "rewrite", rule.to_string(), scope));
        }
    }
    if let Some(force) = nonempty(c.force_type.clone()).filter(|t| !t.eq_ignore_ascii_case("none"))
    {
        return Err(unenforced(path, "forceType", force, scope));
    }
    if let Some(mime) = nonempty(c.add_mime_type.clone()) {
        return Err(unenforced(path, "addMIMEType", mime, scope));
    }
    if let Some(mask) = nonempty(c.allow_override.clone()) {
        return Err(unenforced(path, "allowOverride", mask, scope));
    }
    Ok(())
}

/// LSWS gates `.htaccess` directives per category (Limit 1, Auth 2, FileInfo 4,
/// Indexes 8, Options 16) at server, vhost and context level, each level only
/// narrowing the one above. httpjet applies all of them or none per vhost, so a
/// partial mask refuses the load rather than run directives the operator
/// disallowed, e.g. an uploaded `ForceType` turning an image into PHP (#1028).
fn partial_allow_override(path: &std::path::Path, scope: &str, mask: &str) -> ConfigError {
    ConfigError::InvalidValue {
        path: path.to_path_buf(),
        directive: "allowOverride",
        value: mask.trim().to_string(),
        reason: format!(
            "{scope} allowOverride categories are not enforced by httpjet, which implements \
             only 0 (none) and 31 (all) per vhost; refusing to serve it unprotected"
        ),
    }
}

fn allow_override_is(mask: &str, accepted: &[u32]) -> bool {
    mask.trim()
        .parse::<u32>()
        .is_ok_and(|bits| accepted.contains(&bits))
}

/// The server `<htAccess>` is the default and ceiling for every vhost. Only the
/// all-categories mask (inherited by a vhost without its own) and the default
/// access file name load (#1028).
pub(super) fn server_allow_override(
    path: &std::path::Path,
    ht: Option<&RawHtAccess>,
) -> Result<Option<u32>> {
    let Some(ht) = ht else {
        return Ok(None);
    };
    if let Some(name) = nonempty(ht.access_file_name.clone())
        && name != ".htaccess"
    {
        return Err(unenforced(path, "accessFileName", name, "server"));
    }
    match ht.allow_override.as_deref() {
        None => Ok(None),
        Some(mask) if allow_override_is(mask, &[31]) => Ok(Some(31)),
        Some(mask) => Err(partial_allow_override(path, "server", mask)),
    }
}

/// OLS builds a vhost's own SSL context with `clientVerify` (applied on SNI);
/// httpjet verifies client certificates per listener only, so a vhost that asks
/// for one refuses the load instead of serving every client (#1029).
/// `verifyDepth`, `crlFile` and `CACertPath` only act with it.
fn reject_vhost_client_verify(path: &std::path::Path, ssl: &RawVhSsl) -> Result<()> {
    let mode = ols_long_value(&ssl.client_verify, 0, 3, 0);
    if mode == 0 {
        return Ok(());
    }
    let declared: Vec<String> = std::iter::once(format!("clientVerify={mode}"))
        .chain(
            [
                ("verifyDepth", &ssl.verify_depth),
                ("crlFile", &ssl.crl_file),
                ("CACertPath", &ssl.ca_cert_path),
            ]
            .into_iter()
            .filter_map(|(name, v)| {
                let v = v.as_deref().map(str::trim).filter(|v| !v.is_empty())?;
                Some(format!("{name}={v}"))
            }),
        )
        .collect();
    Err(unenforced(
        path,
        "clientVerify",
        declared.join(" "),
        "vhost vhssl",
    ))
}

/// OLS `configRewriteMap` registers `<rewrite><map>` lookups for the vhost's
/// rules and `.htaccess` files; httpjet has no maps, so `${map:key}` would be
/// compared literally and a map-driven deny would serve everyone (#1030). OLS
/// skips a map without a name or location; any declared value refuses here.
fn reject_rewrite_maps(path: &std::path::Path, rewrite: Option<&RawRewrite>) -> Result<()> {
    for map in rewrite.into_iter().flat_map(|rw| &rw.map) {
        let name = map.name.as_deref().unwrap_or("").trim();
        let location = map.location.as_deref().unwrap_or("").trim();
        if !name.is_empty() || !location.is_empty() {
            return Err(unenforced(
                path,
                "rewrite.map",
                format!("{name} {location}").trim().to_string(),
                "vhost",
            ));
        }
    }
    Ok(())
}

/// `<phpIniOverride>` and `<customErrorPages>` are not implemented: a vhost or
/// context that declares one (e.g. `php_admin_value open_basedir`) must not load
/// without it (#925). Empty blocks, as in the stock LSWS templates, are inert.
fn reject_unimplemented_blocks(
    path: &std::path::Path,
    scope: &str,
    php_ini_override: &Option<String>,
    custom_error_pages: Option<&super::raw::RawCustomErrorPages>,
) -> Result<()> {
    if let Some(line) = php_ini_override.as_deref().and_then(|text| {
        text.lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
    }) {
        return Err(unenforced(path, "phpIniOverride", line.to_string(), scope));
    }
    if let Some(page) = custom_error_pages.and_then(|c| c.error_page.first()) {
        return Err(unenforced(
            path,
            "customErrorPages",
            format!(
                "{} {}",
                page.err_code.as_deref().unwrap_or("").trim(),
                page.url.as_deref().unwrap_or("").trim()
            ),
            scope,
        ));
    }
    Ok(())
}

/// Parse a per-vhost XML file body into [`VHostConfig`].
pub(crate) fn parse_vhost_config(text: &str, ctx: &SubstCtx) -> Result<VHostConfig> {
    let config_path = PathBuf::from(format!("<vhost {}>", ctx.vh_name));
    let text = super::xmlnorm::normalize(text, &config_path);
    let raw: RawVHostConfig = quick_xml::de::from_str(&text).map_err(|e| ConfigError::Xml {
        path: config_path.clone(),
        msg: e.to_string(),
    })?;

    reject_unenforced_vhost_security(&config_path, &raw)?;
    reject_unimplemented_blocks(
        &config_path,
        "vhost",
        &raw.php_ini_override,
        raw.custom_error_pages.as_ref(),
    )?;
    reject_apache_conf(&config_path, "vhost", raw.apache_conf.as_deref())?;

    // OLS configBasics fails a vhost without a document root; an empty element
    // carries no value in the OLS XML tree, so it is missing too (#1001).
    let Some(doc_root_raw) = nonempty(raw.doc_root.clone()) else {
        return Err(ConfigError::MissingDirective {
            path: config_path,
            directive: "docRoot",
            reason: "a vhost needs a document root".into(),
        });
    };
    // OLS resolves $DOC_ROOT / $VH_DOMAIN for everything after <docRoot> (#920).
    let mut ctx = ctx.clone();
    if ctx.vh_domain.is_empty() {
        ctx.vh_domain = nonempty(raw.vh_domain.clone()).unwrap_or_else(|| ctx.vh_name.clone());
    }
    let doc_root = server_rooted(&ctx, &doc_root_raw);
    ctx.doc_root = doc_root.to_string_lossy().into_owned();
    let ctx = &ctx;

    reject_rewrite_maps(&config_path, raw.rewrite.as_ref())?;
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
                        reject_unenforced_context_security(&config_path, &c)?;
                        let sub_filter = convert_sub_filter(&c);
                        let Some(uri) = nonempty(c.uri.take()) else {
                            return Ok(None);
                        };
                        let scope = format!("context {uri:?}");
                        reject_unimplemented_blocks(
                            &config_path,
                            &scope,
                            &c.php_ini_override,
                            c.custom_error_pages.as_ref(),
                        )?;
                        reject_apache_conf(&config_path, &scope, c.apache_conf.as_deref())?;
                        reject_unimplemented_context_directives(
                            &config_path,
                            &scope,
                            &c,
                            rewrite.enable,
                        )?;
                        // OLS accepts `/...` or `exp:` (regex) URIs. Regex
                        // contexts are not implemented; storing one as a
                        // literal prefix would never match and drop its
                        // policy, so refuse it (#919).
                        if !uri.starts_with('/') {
                            let reason = if super::scalar::strip_prefix_ci(&uri, "exp:").is_some() {
                                "regex (exp:) contexts are not supported"
                            } else {
                                "context URI must start with '/'"
                            };
                            return Err(ConfigError::InvalidValue {
                                path: config_path.clone(),
                                directive: "context.uri",
                                value: uri,
                                reason: reason.to_string(),
                            });
                        }
                        let kind = context_kind(&c.kind);
                        // Only static and proxy contexts are routed. Any other
                        // type would otherwise fall through to static serving
                        // (publishing e.g. an fcgi app's source), so reject it.
                        if !matches!(kind, ContextKind::Static | ContextKind::Proxy) {
                            return Err(ConfigError::InvalidValue {
                                path: config_path.clone(),
                                directive: "context.type",
                                value: c.kind.as_deref().unwrap_or("").trim().to_string(),
                                reason: format!(
                                    "context {uri:?}: only static (null) and proxy contexts are implemented"
                                ),
                            });
                        }
                        // OLS forces allowBrowse on for handler contexts (type >= cgi).
                        let allow_browse = match c.allow_browse.as_deref().map(str::trim) {
                            _ if kind == ContextKind::Proxy => true,
                            None | Some("") | Some("1") => true,
                            Some("0") => false,
                            Some(other) => {
                                return Err(ConfigError::InvalidValue {
                                    path: config_path.clone(),
                                    directive: "allowBrowse",
                                    value: other.to_string(),
                                    reason: format!("expected 0 or 1 in context {uri:?}"),
                                });
                            }
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
                        // A zero deadline would 504 every request while the
                        // upstream still runs it; LiteSpeed timeouts are >= 1 s
                        // (#1004).
                        let timeout_override = parse_value(
                            "responseTimeout",
                            &c.response_timeout,
                            |v| parse_secs(v).filter(|&secs| secs > 0),
                            "expected a positive integer number of seconds",
                        )?;
                        Ok(Some(Context {
                            kind,
                            uri,
                            // OLS: a location not starting with `$` or `/` is
                            // relative to $DOC_ROOT (httpvhost.cpp configContext).
                            location: nonempty(c.location).map(|p| {
                                if p.starts_with(['$', '/']) {
                                    PathBuf::from(ctx.expand(&p))
                                } else {
                                    doc_root_join(&ctx.doc_root, &ctx.expand(&p))
                                }
                            }),
                            handler: nonempty(c.handler),
                            enabled: c
                                .enabled
                                .as_ref()
                                .map(|_| truthy(&c.enabled))
                                .unwrap_or(true),
                            allow_browse,
                            extra_headers: c
                                .extra_headers
                                .as_deref()
                                .map(parse_extra_headers)
                                .unwrap_or_default(),
                            add_default_charset: c
                                .add_default_charset
                                .as_ref()
                                .map(|_| charset_on(&c.add_default_charset)),
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

    if let Some(ssl) = raw.vhssl.as_ref() {
        reject_vhost_client_verify(&config_path, ssl)?;
    }
    let vhssl = raw.vhssl.and_then(|s| {
        let cert_file = nonempty(s.cert_file)?;
        let key_file = nonempty(s.key_file)?;
        Some(VhSsl {
            key_file: server_rooted(ctx, &key_file),
            cert_file: server_rooted(ctx, &cert_file),
            cert_chain: truthy(&s.cert_chain),
            ca_cert_file: nonempty(s.ca_cert_file).map(|p| server_rooted(ctx, &p)),
        })
    });

    // A present-but-out-of-range isolation mode must fail the vhost load, not
    // silently degrade to "no isolation" (the OLS-parity default in
    // convert_isolation is for absent/unparsable values only).
    for (directive, raw_value) in [
        ("setUIDMode", &raw.set_uid_mode),
        ("chrootMode", &raw.chroot_mode),
    ] {
        if let Some(v) = raw_value
            .as_deref()
            .map(str::trim)
            .and_then(|s| s.parse::<i64>().ok())
        {
            if !(0..=2).contains(&v) {
                return Err(ConfigError::InvalidValue {
                    path: config_path.clone(),
                    directive: directive,
                    value: v.to_string(),
                    reason: "must be 0 (none), 1, or 2".to_string(),
                });
            }
        }
    }

    let isolation = convert_isolation(
        &raw.set_uid_mode,
        &raw.chroot_mode,
        &raw.chroot_path,
        &raw.suexec_user,
        &raw.suexec_group,
        convert_namespace(raw.namespace),
        ctx,
    );

    let script_handlers = convert_script_handlers(raw.script_handler_list, &config_path)?;

    // `<htAccess>`: allowOverride bitmask + accessFileName. Absent block => off.
    // An EXPLICIT `0` is recorded separately (audit): it FORBIDS overrides, while a
    // merely-absent block defers to `<rewrite><autoLoadHtaccess>`.
    let ht_access = raw.htaccess;
    if let Some(mask) = ht_access.as_ref().and_then(|h| h.allow_override.as_deref())
        && !allow_override_is(mask, &[0, 31])
    {
        return Err(partial_allow_override(&config_path, "vhost", mask));
    }
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
            // OLS getLogFilePath keeps the stdout/stderr names verbatim.
            path: if path == "stdout" || path == "stderr" {
                PathBuf::from(path)
            } else {
                server_rooted(ctx, &path)
            },
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
        // OLS `httplogsource.cpp`: logHeaders is 0..=7, default 3 (Referer + UA).
        f.log_headers = match u32_of(&a.log_headers, 3) {
            v @ 0..=7 => v as u8,
            _ => 3,
        };
    }
    let error_log_file = own_file(raw.logging.as_ref().and_then(|l| l.log.as_ref()));

    // The `<index>` block (OLS configIndex: useServer defaults to 1) wins over the
    // flat `<indexFiles>`; a flat list with no `indexFiles_useServer` keeps its
    // historical meaning, the vhost's own list.
    let (index_list, index_use_server) = match raw.index.as_ref() {
        Some(index) => {
            if index
                .auto_index
                .as_deref()
                .is_some_and(|v| matches!(v.trim(), "1" | "on" | "On"))
            {
                tracing::warn!(
                    "<index><autoIndex> is not implemented; directory listings stay off"
                );
            }
            (
                index.index_files.clone(),
                Some(u32_of(&index.use_server, 1).min(2) as u8),
            )
        }
        None => (
            raw.index_files.clone(),
            raw.index_files_use_server
                .as_ref()
                .map(|_| u32_of(&raw.index_files_use_server, 1).min(2) as u8),
        ),
    };
    Ok(VHostConfig {
        doc_root,
        index_files: index_list.as_deref().map(split_list).unwrap_or_default(),
        index_use_server,
        allow_symbol_link: follow_symlink_value(&raw.allow_symbol_link),
        allow_symbol_link_override: symlink_override(&raw.allow_symbol_link),
        rewrite,
        contexts,
        script_handlers,
        websockets,
        vhssl,
        expires: raw.expires.map(|e| convert_expires(Some(e))),
        cache_policy: convert_vhost_cache(raw.cache),
        extra_ext_processors: convert_ext_list(raw.ext_processor_list, ctx, &config_path)?,
        isolation,
        allow_override,
        allow_override_explicit,
        access_log_file,
        error_log_file,
        access_file_name,
        // OLS `enable(getLongValue(.., "enabled", 0, 1, 1))` on the vhost file.
        disabled: ols_long_value(&raw.enabled, 0, 1, 1) == 0,
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

/// Convert a `<scriptHandlerList>` (vhost or server level) with the
/// fail-closed type/handler validation.
pub(super) fn convert_script_handlers(
    list: Option<super::raw::RawScriptHandlerList>,
    config_path: &std::path::Path,
) -> Result<Vec<ScriptHandler>> {
    let mut script_handlers = Vec::new();
    for sh in list.into_iter().flat_map(|l| l.script_handler) {
        let Some(suffix) = nonempty(sh.suffix) else {
            continue;
        };
        let suffix = suffix.trim().to_ascii_lowercase();
        let raw_kind = sh.kind.as_deref().map(str::trim).unwrap_or("");
        let kind = context_kind(&sh.kind);
        // `context_kind` deliberately defaults an ordinary context with no
        // type to static. A scriptHandler is different: silently treating a
        // missing, misspelled, or unsupported executable type as static can
        // publish the script's source. Only the route kinds implemented by
        // suffix dispatch, plus an explicit static opt-out, are accepted.
        if raw_kind.is_empty()
            || !matches!(
                kind,
                ContextKind::Static | ContextKind::Lsapi | ContextKind::Cgi
            )
        {
            return Err(ConfigError::InvalidValue {
                path: config_path.to_path_buf(),
                directive: "scriptHandler.type",
                value: raw_kind.to_string(),
                reason: format!(
                    "suffix {suffix:?} requires an explicit static, lsapi, or cgi type"
                ),
            });
        }
        // An explicit `static` override intentionally has no processor.
        // Executable routes without a handler are configuration errors; do
        // not discard them and let their suffix fall through to static.
        let handler = match nonempty(sh.handler) {
            Some(handler) => handler,
            None if kind == ContextKind::Static => String::new(),
            None => {
                return Err(ConfigError::InvalidValue {
                    path: config_path.to_path_buf(),
                    directive: "scriptHandler.handler",
                    value: String::new(),
                    reason: format!(
                        "executable suffix {suffix:?} requires an ext-processor handler"
                    ),
                });
            }
        };
        // The suffix field is a comma-separated list (OLS httpmime.cpp splits it;
        // LSWS webadmin documents it): one handler per suffix, or `php74, php8x`
        // matches nothing and serves the scripts as source (#936).
        for part in suffix.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if part.contains('.') {
                return Err(ConfigError::InvalidValue {
                    path: config_path.to_path_buf(),
                    directive: "scriptHandler.suffix",
                    value: suffix.clone(),
                    reason: format!("suffix {part:?} must not contain '.'"),
                });
            }
            script_handlers.push(ScriptHandler {
                suffix: part.to_string(),
                kind,
                handler: handler.clone(),
            });
        }
    }
    Ok(script_handlers)
}
