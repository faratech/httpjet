//! Opt-in ACME lifecycle. Nothing runs without explicit CLI configuration.
use hj_acme::{
    AcmeConfig, AcmeManager, CertificateValidator, ChallengeRegistry, Directory, ManagerError,
};
use hj_config::model::{Listener, ServerConfig};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct AcmeArgs {
    #[arg(long, requires_all = ["acme_domains", "acme_store", "acme_accept_terms"])]
    acme_directory: Option<String>,
    #[arg(long, value_delimiter = ',', requires = "acme_directory")]
    acme_domains: Vec<String>,
    #[arg(long, requires = "acme_directory")]
    acme_store: Option<PathBuf>,
    #[arg(long, requires = "acme_directory")]
    acme_accept_terms: bool,
    /// Start with no listener default certificate; TLS fails until ACME succeeds.
    #[arg(long, requires = "acme_directory")]
    pub acme_bootstrap: bool,
    /// Permit loopback CA HTTP and alternate loopback validation ports for tests.
    #[arg(long, requires = "acme_directory")]
    acme_test_mode: bool,
    #[arg(long, requires = "acme_test_mode")]
    acme_test_ca_root: Option<PathBuf>,
    #[arg(long, requires = "acme_test_mode")]
    acme_test_issuer_root: Option<PathBuf>,
    /// Recover an uncertain newOrder URL from the same account's CA records.
    #[arg(long, requires = "acme_directory")]
    acme_reconcile_order: Option<String>,
    /// Provider-neutral authenticated DNS controller endpoint (selects DNS-01).
    #[arg(long, requires_all = ["acme_directory", "acme_dns_zones"])]
    acme_dns_webhook: Option<String>,
    #[arg(long, value_delimiter = ',', requires = "acme_dns_webhook")]
    acme_dns_zones: Vec<String>,
    #[arg(long, requires = "acme_dns_webhook")]
    acme_dns_token_file: Option<PathBuf>,
    #[arg(long, requires_all = ["acme_dns_webhook", "acme_test_mode"])]
    acme_dns_test_root: Option<PathBuf>,
}

pub(crate) struct Routing {
    registry: ChallengeRegistry,
    listener: String,
    secure_listener: String,
    bindings: Vec<(String, String)>,
    dns01: bool,
}
impl Routing {
    pub fn validate_reload(&self, server: Arc<ServerConfig>) -> Result<(), String> {
        let router = hj_core::Router::build(server);
        for (domain, vhost) in &self.bindings {
            for listener in [&self.listener, &self.secure_listener] {
                if self.dns01 && listener == &self.listener {
                    continue;
                }
                if !router
                    .resolve(listener, Some(domain))
                    .is_some_and(|r| &r.name == vhost)
                {
                    return Err(
                        "ACME domain/listener bindings are boot-frozen; restart to change them"
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }
    pub fn response(
        &self,
        listener: &str,
        request: &hj_core::Request,
        is_tls: bool,
    ) -> Option<hj_core::Response> {
        if self.dns01 || listener != self.listener || is_tls {
            return None;
        }
        let authority = request
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .or_else(|| request.uri().authority().map(|a| a.as_str()))?;
        let result = self
            .registry
            .lookup(request.method(), authority, request.uri(), is_tls)?;
        if request.headers().get_all(http::header::HOST).iter().count() > 1 {
            return Some(
                http::Response::builder()
                    .status(400)
                    .header("cache-control", "no-store")
                    .body(hj_core::Body::Empty)
                    .unwrap(),
            );
        }
        let mut response = http::Response::builder().status(result.status);
        *response.headers_mut().unwrap() = result.headers();
        Some(
            response
                .body(hj_core::Body::Full(bytes::Bytes::copy_from_slice(
                    result.body.as_bytes(),
                )))
                .unwrap(),
        )
    }
}

pub(crate) struct Prepared {
    manager: AcmeManager,
    validator: CertificateValidator,
    domains: Vec<String>,
    targets: CertificateTargets,
    pub routing: Arc<Routing>,
}

/// Active certificate resolvers selected at the resource-publication boundary.
/// Publication and renewal serialize here so a candidate receives the latest
/// managed certificate before it becomes reachable. Retired generations are
/// not updated because their acceptors have already stopped.
#[derive(Clone, Default)]
pub(crate) struct CertificateTargets(Arc<std::sync::RwLock<CertificateTargetState>>);

#[derive(Default)]
struct CertificateTargetState {
    handles: Vec<(Arc<str>, hj_tls::CertReloadHandle)>,
    managed: Option<(Vec<String>, Arc<rustls::sign::CertifiedKey>)>,
}

impl CertificateTargets {
    pub(crate) fn replace(
        &self,
        handles: Vec<(Arc<str>, hj_tls::CertReloadHandle)>,
    ) -> anyhow::Result<()> {
        let mut state = self.0.write().expect("ACME target lock poisoned");
        if let Some((domains, key)) = &state.managed {
            for (_, handle) in &handles {
                handle.replace_managed(domains, key.clone())?;
            }
        }
        state.handles = handles;
        Ok(())
    }

    fn install(
        &self,
        domains: &[String],
        key: Arc<rustls::sign::CertifiedKey>,
    ) -> anyhow::Result<()> {
        let mut state = self.0.write().expect("ACME target lock poisoned");
        for (_, handle) in &state.handles {
            handle.replace_managed(domains, key.clone())?;
        }
        state.managed = Some((domains.to_vec(), key));
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn names(&self) -> Vec<Arc<str>> {
        self.0
            .read()
            .expect("ACME target lock poisoned")
            .handles
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }
}
fn root(path: Option<&PathBuf>) -> anyhow::Result<Option<Vec<u8>>> {
    use std::io::Read;
    path.map(|path| {
        let file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 65536, "ACME test root exceeds limit");
        Ok(bytes)
    })
    .transpose()
}

fn dns_token(path: Option<&PathBuf>) -> anyhow::Result<Option<String>> {
    use rustix::fs::{Mode, OFlags};
    use std::{io::Read, os::unix::fs::MetadataExt};
    path.map(|path| {
        anyhow::ensure!(path.is_absolute(), "DNS credential path must be absolute");
        let file = std::fs::File::from(rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
                && metadata.len() <= 4096,
            "unsafe DNS credential metadata"
        );
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 4096, "DNS credential exceeds limit");
        let token = String::from_utf8(bytes)
            .map_err(|_| anyhow::anyhow!("DNS credential must be UTF-8"))?;
        Ok(token.trim_end_matches(['\r', '\n']).to_owned())
    })
    .transpose()
}
impl Prepared {
    pub fn open(
        args: &AcmeArgs,
        server: Arc<ServerConfig>,
        http_listener: &str,
        secure: Option<&Listener>,
        http_addr: SocketAddr,
        https_addr: Option<SocketAddr>,
    ) -> anyhow::Result<Option<Self>> {
        let Some(directory) = &args.acme_directory else {
            return Ok(None);
        };
        let secure =
            secure.ok_or_else(|| anyhow::anyhow!("ACME requires a configured TLS listener"))?;
        anyhow::ensure!(
            https_addr.is_some(),
            "ACME requires the TLS listener to be enabled"
        );
        if args.acme_test_mode {
            anyhow::ensure!(
                http_addr.ip().is_loopback() && https_addr.unwrap().ip().is_loopback(),
                "ACME test mode requires loopback listeners"
            );
        } else if args.acme_dns_webhook.is_none() {
            anyhow::ensure!(http_addr.port() == 80, "HTTP-01 requires public port 80");
        }
        let config_builder = if args.acme_dns_webhook.is_some() {
            AcmeConfig::new_dns01
        } else {
            AcmeConfig::new
        };
        let config = config_builder(
            Directory::parse(directory, args.acme_test_mode)?,
            &args
                .acme_domains
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            args.acme_store
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing ACME store"))?,
            args.acme_accept_terms,
        )?;
        let router = hj_core::Router::build(server);
        let mut bindings = Vec::new();
        for domain in config.domains() {
            let name = domain.verification_name();
            let tls = router
                .resolve(&secure.name, Some(&name))
                .ok_or_else(|| anyhow::anyhow!("ACME identifier has no TLS vhost"))?;
            if !config.is_dns01() {
                let plain = router
                    .resolve(http_listener, Some(&name))
                    .ok_or_else(|| anyhow::anyhow!("ACME identifier has no HTTP vhost"))?;
                anyhow::ensure!(
                    plain.name == tls.name,
                    "ACME HTTP/TLS vhost mapping differs"
                );
            }
            bindings.push((name, tls.name.clone()));
        }
        let ca_root = root(args.acme_test_ca_root.as_ref())?;
        let issuer_root = root(args.acme_test_issuer_root.as_ref())?;
        let validator = CertificateValidator::new(issuer_root.as_deref())?;
        let domains = config
            .domains()
            .iter()
            .map(|d| d.as_str().to_owned())
            .collect();
        let dns01 = config.is_dns01();
        let mut manager = if let Some(endpoint) = &args.acme_dns_webhook {
            let scope = hj_acme::DnsScope::new(
                &args
                    .acme_dns_zones
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )?;
            let dns_root = root(args.acme_dns_test_root.as_ref())?;
            let provider = hj_acme::WebhookDnsProvider::new(
                Directory::parse(endpoint, args.acme_test_mode)?,
                scope,
                dns_token(args.acme_dns_token_file.as_ref())?,
                dns_root.as_deref(),
            )?;
            AcmeManager::open_dns01(config, ca_root.as_deref(), Arc::new(provider))?
        } else {
            AcmeManager::open(config, ca_root.as_deref())?
        };
        if let Some(url) = &args.acme_reconcile_order {
            manager.reconcile_order(url)?;
        }
        let routing = Arc::new(Routing {
            registry: manager.challenges(),
            listener: http_listener.to_owned(),
            secure_listener: secure.name.clone(),
            bindings,
            dns01,
        });
        Ok(Some(Self {
            manager,
            validator,
            domains,
            targets: CertificateTargets::default(),
            routing,
        }))
    }
    pub fn attach_handles(
        &mut self,
        handles: Vec<(Arc<str>, hj_tls::CertReloadHandle)>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !handles.is_empty(),
            "ACME requires a live certificate resolver"
        );
        self.targets.replace(handles)?;
        if let Some(pair) = self.manager.installed(&self.validator)? {
            self.targets.install(&self.domains, pair.certified_key())?;
        }
        Ok(())
    }
    pub(crate) fn certificate_targets(&self) -> CertificateTargets {
        self.targets.clone()
    }
    pub async fn run(
        mut self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<()> {
        // Replay crash-left cleanup immediately, not at the next renewal date.
        // A failed cleanup leaves its journal intact and stops new mutations.
        self.manager.cleanup_dns().await?;
        loop {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let wait = self.manager.next_attempt_unix().saturating_sub(now);
            tokio::select! { _ = shutdown.cancelled() => { self.manager.cleanup_dns().await?; return Ok(()); }, _ = tokio::time::sleep(Duration::from_secs(wait.min(3600))) => {} }
            if wait > 3600 {
                continue;
            }
            let result = tokio::select! { _ = shutdown.cancelled() => None, result = self.manager.issue() => Some(result) };
            let Some(result) = result else {
                self.manager.cleanup_dns().await?;
                return Ok(());
            };
            match result {
                Ok(issued) => match self.manager.install(issued, &self.validator) {
                    Ok(pair) => {
                        self.targets.install(&self.domains, pair.certified_key())?;
                        tracing::info!("ACME certificate generation committed and activated");
                    }
                    Err(error) => {
                        tracing::error!(%error, "ACME installation failed; previous live certificate retained");
                        if error == ManagerError::Storage {
                            return Err(error.into());
                        }
                    }
                },
                Err(error) => {
                    tracing::warn!(%error, "ACME attempt did not complete");
                    if matches!(
                        error,
                        ManagerError::Storage | ManagerError::State | ManagerError::UncertainOrder
                    ) {
                        return Err(error.into());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    #[test]
    fn dns_credentials_require_private_regular_nonlinked_files() {
        use std::{
            fs,
            os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        };
        let root =
            std::env::temp_dir().join(format!("hj-dns-credential-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let token = root.join("token");
        fs::write(&token, "test-credential-with-enough-bytes\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(dns_token(Some(&token)).is_err());
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            dns_token(Some(&token)).unwrap().as_deref(),
            Some("test-credential-with-enough-bytes")
        );
        let alias = root.join("alias");
        symlink(&token, &alias).unwrap();
        assert!(dns_token(Some(&alias)).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&token, &alias).unwrap();
        assert!(dns_token(Some(&token)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn routing_reserves_raw_challenges_only_on_its_plain_listener() {
        let config = AcmeConfig::new(
            Directory::parse("https://ca.test/dir", false).unwrap(),
            &["example.test"],
            "/tmp/unused-acme".into(),
            true,
        )
        .unwrap();
        let registry = ChallengeRegistry::new(&config);
        let domain = hj_acme::Domain::parse("example.test").unwrap();
        let token = "A".repeat(22);
        let _lease = registry
            .register(&domain, &token, &"A".repeat(43), Duration::from_secs(60))
            .unwrap();
        let routing = Routing {
            registry,
            listener: "http".into(),
            secure_listener: "https".into(),
            bindings: vec![],
            dns01: false,
        };
        let request = |path: &str| {
            http::Request::builder()
                .uri(path)
                .header("host", "example.test")
                .body(
                    http_body_util::Empty::<bytes::Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap()
        };
        let path = format!("/.well-known/acme-challenge/{token}");
        assert_eq!(
            routing
                .response("http", &request(&path), false)
                .unwrap()
                .status(),
            200
        );
        assert!(routing.response("http", &request(&path), true).is_none());
        assert!(routing.response("other", &request(&path), false).is_none());
        for malformed in [
            format!("{path}?"),
            "/.well-known/acme-challenge/../index.php".into(),
            "/.well-known/acme-challenge/%2e%2e/index.php".into(),
        ] {
            let response = routing
                .response("http", &request(&malformed), false)
                .unwrap();
            assert_eq!(response.status(), 404);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let mut duplicate = request(&path);
        duplicate
            .headers_mut()
            .append("host", "other.test".parse().unwrap());
        assert_eq!(
            routing
                .response("http", &duplicate, false)
                .unwrap()
                .status(),
            400
        );
    }
}
