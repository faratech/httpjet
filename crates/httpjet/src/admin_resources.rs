use hj_core::config::{ExtKind, ExtProcessor, ServerConfig};
use std::fmt::Debug;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidResource;

pub(crate) struct ResourceRoots(Vec<PathBuf>);

impl ResourceRoots {
    pub(crate) fn new(roots: &[PathBuf]) -> Result<Self, InvalidResource> {
        if roots.is_empty() || roots.len() > 32 {
            return Err(InvalidResource);
        }
        let roots = roots
            .iter()
            .map(|root| {
                let root = root.canonicalize().map_err(|_| InvalidResource)?;
                if !root.is_dir() || root.parent().is_none() {
                    return Err(InvalidResource);
                }
                Ok(root)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(roots))
    }

    fn check(&self, path: &Path, directory: bool) -> Result<(), InvalidResource> {
        if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(InvalidResource);
        }
        let canonical = path.canonicalize().map_err(|_| InvalidResource)?;
        if !self.0.iter().any(|root| canonical.starts_with(root)) {
            return Err(InvalidResource);
        }
        let metadata = canonical.metadata().map_err(|_| InvalidResource)?;
        if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
            return Err(InvalidResource);
        }
        Ok(())
    }

    /// This authorizes explicit config references at submission time. It is not
    /// a filesystem sandbox: operators must control these roots and their links.
    pub(crate) fn validate(&self, cfg: &ServerConfig) -> Result<(), InvalidResource> {
        if let Some(path) = &cfg.security.geo_db_file {
            self.check(path, false)?;
        }
        let mut processors: Vec<&ExtProcessor> = cfg.ext_processors.iter().collect();
        for decl in cfg.vhosts.values() {
            let vhost = decl.config.as_deref().ok_or(InvalidResource)?;
            self.check(&decl.vh_root, true)?;
            self.check(&vhost.doc_root, true)?;
            for context in &vhost.contexts {
                if context.kind == hj_core::config::ContextKind::Static {
                    if let Some(path) = &context.location {
                        self.check(path, true)?;
                    }
                }
            }
            processors.extend(vhost.extra_ext_processors.iter());
        }
        for processor in processors {
            if processor.kind == ExtKind::Proxy {
                for path in [&processor.client_cert_file, &processor.client_key_file]
                    .into_iter()
                    .flatten()
                {
                    self.check(path, false)?;
                }
            }
        }
        Ok(())
    }

    /// Authorize certificate and verifier inputs before a TCP trust candidate
    /// opens them. ACME bootstrap may omit the listener default identity, but
    /// client-verifier and vhost certificate inputs remain required resources.
    pub(crate) fn validate_tcp_trust(
        &self,
        cfg: &ServerConfig,
        acme_bootstrap: bool,
    ) -> Result<(), InvalidResource> {
        for listener in cfg.listeners.iter().filter(|listener| listener.secure) {
            let tls = listener.tls.as_ref().ok_or(InvalidResource)?;
            if !acme_bootstrap {
                self.check(&tls.cert_file, false)?;
                self.check(&tls.key_file, false)?;
            }
            for path in [&tls.ca_cert_file, &tls.crl_file].into_iter().flatten() {
                self.check(path, false)?;
            }
        }
        for vhost in cfg
            .vhosts
            .values()
            .filter_map(|decl| decl.config.as_deref())
        {
            if let Some(tls) = &vhost.vhssl {
                self.check(&tls.cert_file, false)?;
                self.check(&tls.key_file, false)?;
                if let Some(path) = &tls.ca_cert_file {
                    self.check(path, false)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RestartRequired;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplacementClass {
    Application,
    TcpTrust,
}

// These model types do not implement equality. Compare complete Debug values
// internally, never returning or logging the values (they can contain secrets).
fn same<T: Debug>(old: &T, new: &T) -> bool {
    format!("{old:?}") == format!("{new:?}")
}

fn retained_processors(processors: &[ExtProcessor]) -> Vec<&ExtProcessor> {
    processors
        .iter()
        // LSAPI owns an external/spawned process family outside ServerState.
        // Proxy and FastCGI pools are generation-owned and drain with old state.
        .filter(|p| p.kind == ExtKind::Lsapi)
        .collect()
}

/// Classify a submission without granting bind authority. TCP trust replacement
/// keeps configuration-declared UDS and QUIC topology fixed; an operator-owned
/// CLI UDS endpoint is preserved separately by resource acquisition, while a
/// fixed QUIC endpoint receives a coherent in-place TLS/trust replacement.
/// Topology planning and descriptor acquisition perform the remaining checks.
pub(crate) fn classify_replacement(
    old: &ServerConfig,
    new: &ServerConfig,
) -> Result<ReplacementClass, RestartRequired> {
    let mut old_listeners = old.listeners.clone();
    let mut new_listeners = new.listeners.clone();
    for listener in old_listeners.iter_mut().chain(&mut new_listeners) {
        // TLS resolvers capture these mappings outside the application state.
        if !listener.secure {
            listener.vhost_map.clear();
        }
    }
    let mut old_php = old.php_config.clone();
    let mut new_php = new.php_config.clone();
    for php in old_php.iter_mut().chain(&mut new_php) {
        php.suffixes.clear();
    }
    let caps = |c: &ServerConfig| {
        (
            c.tuning.max_cached_file_size,
            c.tuning.total_in_mem_cache_size,
            c.tuning.max_mmap_file_size,
            c.tuning.total_mmap_cache_size,
        )
    };
    let listener_change = !same(&old_listeners, &new_listeners);
    if old.server_root != new.server_root
        || old.user != new.user
        || old.group != new.group
        || old.quic_enable != new.quic_enable
        || !same(&old_php, &new_php)
        || !same(&old.suexec, &new.suexec)
        || old.security.cgi_cpu_limit_secs != new.security.cgi_cpu_limit_secs
        || !same(&old.cache, &new.cache)
        || caps(old) != caps(new)
        || (old.php_config.is_some()
            && old.tuning.max_req_body_size != new.tuning.max_req_body_size)
        || !same(
            &retained_processors(&old.ext_processors),
            &retained_processors(&new.ext_processors),
        )
    {
        return Err(RestartRequired);
    }
    let mut tls_vhost_change = false;
    for name in old.vhosts.keys().chain(new.vhosts.keys()) {
        let before = old.vhosts.get(name).and_then(|v| v.config.as_deref());
        let after = new.vhosts.get(name).and_then(|v| v.config.as_deref());
        tls_vhost_change |= !same(
            &before.and_then(|v| v.vhssl.as_ref()),
            &after.and_then(|v| v.vhssl.as_ref()),
        );
        if !same(
            &before.and_then(|v| v.isolation.as_ref()),
            &after.and_then(|v| v.isolation.as_ref()),
        ) || !same(
            &before.and_then(|v| v.access_log_file.as_ref()),
            &after.and_then(|v| v.access_log_file.as_ref()),
        ) || !same(
            &before.and_then(|v| v.error_log_file.as_ref()),
            &after.and_then(|v| v.error_log_file.as_ref()),
        ) || !same(
            &before
                .map(|v| retained_processors(&v.extra_ext_processors))
                .unwrap_or_default(),
            &after
                .map(|v| retained_processors(&v.extra_ext_processors))
                .unwrap_or_default(),
        ) {
            return Err(RestartRequired);
        }
    }
    if listener_change || tls_vhost_change {
        let stable_tcp_shape = old.listeners.len() == new.listeners.len()
            && old.listeners.iter().zip(&new.listeners).all(|(old, new)| {
                old.secure == new.secure
                    && old.address == new.address
                    && old.uds_path.is_none()
                    && new.uds_path.is_none()
            });
        if !stable_tcp_shape {
            return Err(RestartRequired);
        }
        Ok(ReplacementClass::TcpTrust)
    } else {
        Ok(ReplacementClass::Application)
    }
}

/// Preserve the original application-only guard until the resource endpoint
/// explicitly opts into the separately prepared TCP transaction.
#[cfg(test)]
pub(crate) fn validate_retained(
    old: &ServerConfig,
    new: &ServerConfig,
) -> Result<(), RestartRequired> {
    match classify_replacement(old, new)? {
        ReplacementClass::Application => Ok(()),
        ReplacementClass::TcpTrust => Err(RestartRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hj_core::config::{
        ExtAddress, ExtProcessor, Listener, ListenerTls, LoadBalanceConfig, VHostConfig, VHostDecl,
        VhostLogFile, VhostMap,
    };
    use std::{path::PathBuf, sync::Arc};

    fn config() -> ServerConfig {
        let mut cfg = ServerConfig::default();
        cfg.listeners.push(Listener {
            name: "local".into(),
            address: "127.0.0.1:18080".into(),
            secure: false,
            vhost_map: vec![],
            tls: None,
            uds_path: None,
            proxy_protocol: false,
        });
        cfg.vhosts.insert(
            "site".into(),
            VHostDecl {
                name: "site".into(),
                vh_root: PathBuf::from("/site"),
                config_file: PathBuf::new(),
                allow_symbol_link: None,
                restrained: false,
                enable_script: true,
                config: Some(Arc::new(VHostConfig::default())),
            },
        );
        cfg
    }

    #[test]
    fn retained_resources_reject_without_exposing_values() {
        let old = config();
        let changes: &[fn(&mut ServerConfig)] = &[
            |c| c.listeners[0].proxy_protocol = true,
            |c| c.listeners[0].uds_path = Some("/secret/socket".into()),
            |c| c.listeners[0].address = "127.0.0.1:18081".into(),
            |c| c.quic_enable = true,
            |c| c.user = "root".into(),
            |c| c.group = "root".into(),
            |c| c.server_root = "/secret/root".into(),
            |c| c.tuning.total_in_mem_cache_size += 1,
            |c| c.cache.default_ttl_secs += 1,
            |c| c.suexec.enable = true,
            |c| {
                Arc::make_mut(c.vhosts.get_mut("site").unwrap().config.as_mut().unwrap())
                    .access_log_file = Some(VhostLogFile {
                    path: "/secret/log".into(),
                    rolling_bytes: 100,
                    keep_days: 1,
                    log_headers: 0,
                })
            },
        ];
        for change in changes {
            let mut next = old.clone();
            change(&mut next);
            assert_eq!(validate_retained(&old, &next), Err(RestartRequired));
        }
        assert_eq!(format!("{:?}", RestartRequired), "RestartRequired");
    }

    #[test]
    fn application_configuration_remains_reloadable() {
        let old = config();
        let mut next = old.clone();
        next.listeners[0].vhost_map.push(VhostMap {
            vhost: "site".into(),
            domains: vec!["example.test".into()],
        });
        next.tuning.per_ip_rate = 40;
        next.tuning.enable_gzip = false;
        let site = Arc::make_mut(
            next.vhosts
                .get_mut("site")
                .unwrap()
                .config
                .as_mut()
                .unwrap(),
        );
        site.doc_root = "/site/next".into();
        site.rewrite.rules = "RewriteRule ^ /next [L]".into();
        assert_eq!(validate_retained(&old, &next), Ok(()));
        let mut tls_old = old.clone();
        tls_old.listeners[0].secure = true;
        next.listeners[0].secure = true;
        assert_eq!(validate_retained(&tls_old, &next), Err(RestartRequired));
    }

    #[test]
    fn generation_owned_fastcgi_changes_reload_but_lsapi_changes_do_not() {
        let processor = |kind: ExtKind, address: &str| ExtProcessor {
            name: "app".into(),
            kind,
            address: ExtAddress::Uds(address.into()),
            extra_addresses: vec![],
            load_balance: LoadBalanceConfig::default(),
            client_cert_file: None,
            client_key_file: None,
            max_conns: 4,
            init_timeout: std::time::Duration::from_secs(1),
            retry_timeout: std::time::Duration::ZERO,
            pc_keep_alive_timeout: std::time::Duration::from_secs(30),
            resp_buffer: false,
            env: vec![],
            auto_start: 0,
            path: None,
            backlog: 16,
            instances: 1,
            run_on_startup: 0,
        };
        let mut old = config();
        old.ext_processors
            .push(processor(ExtKind::FastCgi, "/run/app-old.sock"));
        let mut changed = old.clone();
        changed.ext_processors[0].address = ExtAddress::Uds("/run/app-new.sock".into());
        assert_eq!(
            classify_replacement(&old, &changed),
            Ok(ReplacementClass::Application)
        );

        let mut lsapi_old = config();
        lsapi_old
            .ext_processors
            .push(processor(ExtKind::Lsapi, "/run/php-old.sock"));
        let mut lsapi_changed = lsapi_old.clone();
        lsapi_changed.ext_processors[0].address = ExtAddress::Uds("/run/php-new.sock".into());
        assert_eq!(
            classify_replacement(&lsapi_old, &lsapi_changed),
            Err(RestartRequired)
        );
    }

    #[test]
    fn tcp_trust_changes_are_distinct_from_application_only_updates() {
        let old = config();
        for change in [
            |cfg: &mut ServerConfig| cfg.listeners[0].name = "replacement".into(),
            |cfg: &mut ServerConfig| cfg.listeners[0].proxy_protocol = true,
        ] {
            let mut next = old.clone();
            change(&mut next);
            assert_eq!(
                classify_replacement(&old, &next),
                Ok(ReplacementClass::TcpTrust)
            );
            assert_eq!(validate_retained(&old, &next), Err(RestartRequired));
        }

        let mut quic = old.clone();
        quic.quic_enable = true;
        let mut changed = quic.clone();
        changed.listeners[0].proxy_protocol = true;
        assert_eq!(
            classify_replacement(&quic, &changed),
            Ok(ReplacementClass::TcpTrust)
        );
        changed.quic_enable = false;
        assert_eq!(classify_replacement(&quic, &changed), Err(RestartRequired));

        let mut uds = old.clone();
        uds.listeners[0].uds_path = Some("/tmp/httpjet-test.sock".into());
        let mut changed = uds.clone();
        changed.listeners[0].name = "replacement".into();
        assert_eq!(classify_replacement(&uds, &changed), Err(RestartRequired));

        let mut moved = old.clone();
        moved.listeners[0].address = "127.0.0.1:18081".into();
        assert_eq!(classify_replacement(&old, &moved), Err(RestartRequired));
    }

    #[test]
    fn resource_roots_reject_escape_missing_and_nonregular_files() {
        let root = std::env::temp_dir().join(format!(
            "httpjet-admin-roots-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("allowed/site")).unwrap();
        std::fs::create_dir(root.join("outside")).unwrap();
        std::fs::write(root.join("allowed/data"), "fixture").unwrap();
        std::os::unix::fs::symlink(root.join("outside"), root.join("allowed/escape")).unwrap();
        let roots = ResourceRoots::new(&[root.join("allowed")]).unwrap();
        assert!(roots.check(&root.join("allowed/site"), true).is_ok());
        assert!(roots.check(&root.join("allowed/data"), false).is_ok());
        for path in [
            root.join("allowed/escape"),
            root.join("allowed/../outside"),
            root.join("allowed/missing"),
            PathBuf::from("relative"),
        ] {
            assert_eq!(roots.check(&path, true), Err(InvalidResource));
        }
        assert_eq!(
            roots.check(&root.join("allowed/site"), false),
            Err(InvalidResource)
        );
        assert!(ResourceRoots::new(&[PathBuf::from("/")]).is_err());
        assert!(ResourceRoots::new(&[]).is_err());
        let mut cfg = config();
        let decl = cfg.vhosts.get_mut("site").unwrap();
        decl.vh_root = root.join("allowed/site");
        Arc::make_mut(decl.config.as_mut().unwrap()).doc_root = decl.vh_root.clone();
        assert!(roots.validate(&cfg).is_ok());
        cfg.listeners[0].secure = true;
        cfg.listeners[0].tls = Some(ListenerTls {
            key_file: root.join("allowed/data"),
            cert_file: root.join("allowed/data"),
            cert_chain: true,
            ca_cert_file: None,
            client_verify: 0,
            verify_depth: 1,
            enable_stapling: false,
            crl_file: None,
        });
        assert!(roots.validate_tcp_trust(&cfg, false).is_ok());
        cfg.listeners[0].tls.as_mut().unwrap().key_file = root.join("outside/secret");
        assert_eq!(roots.validate_tcp_trust(&cfg, false), Err(InvalidResource));
        assert!(roots.validate_tcp_trust(&cfg, true).is_ok());
        cfg.security.geo_db_file = Some(root.join("outside/secret"));
        assert_eq!(roots.validate(&cfg), Err(InvalidResource));
        std::fs::remove_dir_all(root).unwrap();
    }
}
