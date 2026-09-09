//! Durable single-order ACME HTTP-01 driver. Certificate activation is separate.
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, Key, NewOrder, OrderStatus,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    AcmeConfig, CertificateValidator, ChallengeRegistry, Domain, PrivateStore,
    ValidatedCertificate, transport::BoundedHttp,
};
use crate::{DnsProvider, DnsRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerError {
    Storage,
    State,
    Crypto,
    Authority,
    Challenge,
    Timeout,
    Backoff,
    UncertainOrder,
    Dns,
}
impl fmt::Display for ManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Storage => "ACME durable storage failed; reconcile before retry",
            Self::State => "ACME persisted state is invalid or belongs to another configuration",
            Self::Crypto => "ACME key or CSR operation failed",
            Self::Authority => "ACME authority operation failed",
            Self::Challenge => "ACME authorization or challenge rejected",
            Self::Timeout => "ACME order deadline exceeded",
            Self::Backoff => "ACME retry is not due",
            Self::Dns => "ACME DNS challenge operation failed; cleanup intent retained",
            Self::UncertainOrder => {
                "ACME order creation was interrupted; explicit reconciliation required"
            }
        })
    }
}
impl std::error::Error for ManagerError {}

// Never derive Debug on persisted state or keys. All serialized snapshots stay
// in PrivateStore; operator-facing errors intentionally omit CA response text.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    directory: String,
    domains: Vec<String>,
    account_key: Vec<u8>,
    account_id: Option<String>,
    order: Option<PendingOrder>,
    next_attempt: u64,
    failures: u32,
    installed: Option<IssuedCertificate>,
    #[serde(default)]
    dns_identity: Option<String>,
    #[serde(default)]
    dns_cleanup: Vec<DnsRecord>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingOrder {
    // None is a write-ahead marker: never automatically repeat newOrder after
    // losing its response. ACME has no idempotency key for this operation.
    url: Option<String>,
    private_key: String,
    csr: Vec<u8>,
}

/// An issued pair is not trusted/installed until the TLS validation step succeeds.
/// No Debug implementation to keep the private key out of logs.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedCertificate {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

pub struct AcmeManager {
    config: AcmeConfig,
    store: PrivateStore,
    state: Snapshot,
    http: BoundedHttp,
    challenges: ChallengeRegistry,
    dns: Option<Arc<dyn DnsProvider>>,
}

impl AcmeManager {
    /// Construction does not contact a CA. A fresh account key is persisted
    /// before any possible registration, making account creation restart-safe.
    /// `test_root` replaces platform roots; it never disables certificate checks.
    pub fn open(config: AcmeConfig, test_root: Option<&[u8]>) -> Result<Self, ManagerError> {
        if config.is_dns01() {
            return Err(ManagerError::State);
        }
        Self::open_inner(config, test_root, None)
    }

    pub fn open_dns01(
        config: AcmeConfig,
        test_root: Option<&[u8]>,
        provider: Arc<dyn DnsProvider>,
    ) -> Result<Self, ManagerError> {
        if !config.is_dns01() || !config.domains().iter().all(|d| provider.scope().permits(d)) {
            return Err(ManagerError::State);
        }
        Self::open_inner(config, test_root, Some(provider))
    }

    fn open_inner(
        config: AcmeConfig,
        test_root: Option<&[u8]>,
        dns: Option<Arc<dyn DnsProvider>>,
    ) -> Result<Self, ManagerError> {
        let dns_identity = dns.as_ref().map(|p| p.identity());
        if dns_identity
            .as_ref()
            .is_some_and(|i| i.is_empty() || i.len() > 4096)
        {
            return Err(ManagerError::State);
        }
        let http = BoundedHttp::new(config.directory().clone(), test_root)
            .map_err(|_| ManagerError::Authority)?;
        let mut store = PrivateStore::open(&config).map_err(|_| ManagerError::Storage)?;
        let domains = config
            .domains()
            .iter()
            .map(|d| d.as_str().to_owned())
            .collect::<Vec<_>>();
        let state = match store.read().map_err(|_| ManagerError::Storage)? {
            Some(bytes) => {
                let state: Snapshot =
                    serde_json::from_slice(&bytes).map_err(|_| ManagerError::State)?;
                if state.version != 1
                    || state.dns_identity != dns_identity
                    || state.dns_cleanup.len() > 100
                    || state.dns_cleanup.iter().any(|r| {
                        !dns.as_ref().is_some_and(|p| {
                            r.valid_for(p.scope())
                                && r.domain().is_ok_and(|d| {
                                    config
                                        .domains()
                                        .iter()
                                        .any(|configured| configured.dns_base() == d.as_str())
                                })
                        })
                    })
                    || state.directory != config.directory().uri().to_string()
                    || state.domains != domains
                    || state.account_key.len() > 4096
                    || state.account_key.is_empty()
                    || state
                        .account_id
                        .as_ref()
                        .is_some_and(|u| !u.parse().is_ok_and(|u| http.permits(&u)))
                    || state.order.as_ref().is_some_and(|o| {
                        o.private_key.len() > 8192
                            || o.csr.len() > 64 * 1024
                            || o.url
                                .as_ref()
                                .is_some_and(|u| !u.parse().is_ok_and(|u| http.permits(&u)))
                    })
                {
                    return Err(ManagerError::State);
                }
                Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(state.account_key.clone()))
                    .map_err(|_| ManagerError::State)?;
                state
            }
            None => {
                let (_, key) = Key::generate_pkcs8().map_err(|_| ManagerError::Crypto)?;
                let state = Snapshot {
                    version: 1,
                    directory: config.directory().uri().to_string(),
                    domains,
                    account_key: key.secret_pkcs8_der().to_vec(),
                    account_id: None,
                    order: None,
                    next_attempt: 0,
                    failures: 0,
                    installed: None,
                    dns_identity,
                    dns_cleanup: Vec::new(),
                };
                store
                    .replace(&serde_json::to_vec(&state).map_err(|_| ManagerError::State)?)
                    .map_err(|_| ManagerError::Storage)?;
                state
            }
        };
        let challenges = ChallengeRegistry::new(&config);
        Ok(Self {
            config,
            store,
            state,
            http,
            challenges,
            dns,
        })
    }

    pub fn challenges(&self) -> ChallengeRegistry {
        self.challenges.clone()
    }

    fn persist(&mut self) -> Result<(), ManagerError> {
        self.store
            .replace(&serde_json::to_vec(&self.state).map_err(|_| ManagerError::State)?)
            .map_err(|_| ManagerError::Storage)
    }

    /// Runs one bounded issuance/recovery attempt, retaining the same CSR/key on
    /// every retry. Caller must activate then acknowledge before starting renewal.
    pub async fn issue(&mut self) -> Result<IssuedCertificate, ManagerError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ManagerError::State)?
            .as_secs();
        if now < self.state.next_attempt {
            return Err(ManagerError::Backoff);
        }
        if self.state.order.as_ref().is_some_and(|o| o.url.is_none()) {
            return Err(ManagerError::UncertainOrder);
        }
        let backoff = 300_u64.saturating_mul(1 << self.state.failures.min(8));
        let jitter = u64::from(*self.state.account_key.last().unwrap()) * (backoff / 5) / 256;
        self.state.next_attempt = now.saturating_add(backoff + jitter);
        self.state.failures = self.state.failures.saturating_add(1);
        self.persist()?;
        self.cleanup_dns().await?;
        let result = tokio::time::timeout(Duration::from_secs(120), self.issue_inner())
            .await
            .unwrap_or(Err(ManagerError::Timeout));
        if self.http.retry_after() > self.state.next_attempt {
            self.state.next_attempt = self.http.retry_after();
            self.persist()?;
        }
        self.cleanup_dns().await?;
        result
    }

    async fn issue_inner(&mut self) -> Result<IssuedCertificate, ManagerError> {
        let builder = Account::builder_with_http(Box::new(self.http.clone()));
        let der = PrivatePkcs8KeyDer::from(self.state.account_key.clone());
        let account = if let Some(id) = &self.state.account_id {
            builder
                .from_parts(id.clone(), der, self.state.directory.clone())
                .await
                .map_err(|_| ManagerError::Authority)?
        } else {
            let key = Key::from_pkcs8_der(der.clone_key()).map_err(|_| ManagerError::Crypto)?;
            let (account, _) = builder
                .create_from_key(
                    (key, PrivateKeyDer::Pkcs8(der)),
                    self.state.directory.clone(),
                )
                .await
                .map_err(|_| ManagerError::Authority)?;
            if !account.id().parse().is_ok_and(|u| self.http.permits(&u)) {
                return Err(ManagerError::Authority);
            }
            self.state.account_id = Some(account.id().to_owned());
            self.persist()?;
            account
        };
        let mut order = if let Some(pending) = &self.state.order {
            account
                .order(pending.url.clone().ok_or(ManagerError::UncertainOrder)?)
                .await
                .map_err(|_| ManagerError::Authority)?
        } else {
            let key = rcgen::KeyPair::generate().map_err(|_| ManagerError::Crypto)?;
            let mut params = rcgen::CertificateParams::new(self.state.domains.clone())
                .map_err(|_| ManagerError::Crypto)?;
            params.distinguished_name = rcgen::DistinguishedName::new();
            let csr = params
                .serialize_request(&key)
                .map_err(|_| ManagerError::Crypto)?;
            self.state.order = Some(PendingOrder {
                url: None,
                private_key: key.serialize_pem(),
                csr: csr.der().to_vec(),
            });
            self.persist()?;
            let identifiers = self
                .state
                .domains
                .iter()
                .cloned()
                .map(Identifier::Dns)
                .collect::<Vec<_>>();
            let order = account
                .new_order(&NewOrder::new(&identifiers))
                .await
                .map_err(|_| ManagerError::Authority)?;
            if !order.url().parse().is_ok_and(|u| self.http.permits(&u)) {
                return Err(ManagerError::Authority);
            }
            self.state.order.as_mut().unwrap().url = Some(order.url().to_owned());
            self.persist()?;
            order
        };
        let mut leases = Vec::new();
        if order.state().authorizations.len() > 100 {
            return Err(ManagerError::Authority);
        }
        let mut names = BTreeSet::new();
        let mut authorizations = order.authorizations();
        while let Some(auth) = authorizations.next().await {
            let mut auth = auth.map_err(|_| ManagerError::Authority)?;
            let domain = (if self.config.is_dns01() {
                Domain::parse_dns01(&auth.identifier().to_string())
            } else {
                Domain::parse(&auth.identifier().to_string())
            })
            .map_err(|_| ManagerError::Challenge)?;
            if !self.config.domains().contains(&domain) || !names.insert(domain.clone()) {
                return Err(ManagerError::Challenge);
            }
            match auth.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => return Err(ManagerError::Challenge),
            }
            let mut challenge = auth
                .challenge(if self.config.is_dns01() {
                    ChallengeType::Dns01
                } else {
                    ChallengeType::Http01
                })
                .ok_or(ManagerError::Challenge)?;
            if let Some(provider) = self.dns.clone() {
                let record = DnsRecord::new(&domain, challenge.key_authorization().dns_value())
                    .map_err(|_| ManagerError::Dns)?;
                if !provider.scope().permits(&domain) {
                    return Err(ManagerError::Dns);
                }
                // Record intent BEFORE touching DNS. Unknown present outcomes
                // are recoverable by idempotent exact-value cleanup on restart.
                self.state.dns_cleanup.push(record.clone());
                self.persist()?;
                tokio::time::timeout(Duration::from_secs(5), provider.present(&record))
                    .await
                    .map_err(|_| ManagerError::Dns)?
                    .map_err(|_| ManagerError::Dns)?;
                loop {
                    if tokio::time::timeout(Duration::from_secs(5), provider.ready(&record))
                        .await
                        .map_err(|_| ManagerError::Dns)?
                        .map_err(|_| ManagerError::Dns)?
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            } else {
                leases.push(
                    self.challenges
                        .register(
                            &domain,
                            &challenge.token,
                            account.key_thumbprint(),
                            Duration::from_secs(180),
                        )
                        .map_err(|_| ManagerError::Challenge)?,
                );
            }
            challenge
                .set_ready()
                .await
                .map_err(|_| ManagerError::Authority)?;
        }
        if names != *self.config.domains() {
            return Err(ManagerError::Challenge);
        }
        loop {
            match order.state().status {
                OrderStatus::Pending => {}
                OrderStatus::Ready => {
                    order
                        .finalize_csr(&self.state.order.as_ref().unwrap().csr)
                        .await
                        .map_err(|_| ManagerError::Authority)?;
                }
                OrderStatus::Processing => {}
                OrderStatus::Valid => {
                    let pem = order
                        .certificate()
                        .await
                        .map_err(|_| ManagerError::Authority)?
                        .ok_or(ManagerError::Authority)?;
                    return Ok(IssuedCertificate {
                        certificate_pem: pem,
                        private_key_pem: self.state.order.as_ref().unwrap().private_key.clone(),
                    });
                }
                OrderStatus::Invalid => {
                    self.state.order = None;
                    self.persist()?;
                    return Err(ManagerError::Authority);
                }
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ManagerError::State)?
                .as_secs();
            tokio::time::sleep(Duration::from_secs(
                self.http.retry_after().saturating_sub(now).clamp(2, 120),
            ))
            .await;
            order.refresh().await.map_err(|_| ManagerError::Authority)?;
        }
    }

    /// Validate and commit the pair in the SAME atomic account/order snapshot.
    /// Only the returned validated object may be published to live resolvers.
    /// A failed disk write must leave the previous resolver generation untouched.
    pub fn install(
        &mut self,
        issued: IssuedCertificate,
        validator: &CertificateValidator,
    ) -> Result<ValidatedCertificate, ManagerError> {
        if !self.state.dns_cleanup.is_empty() {
            return Err(ManagerError::Dns);
        }
        let validated = validator.validate(&issued, &self.config)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ManagerError::State)?
            .as_secs();
        let remaining = validated.expires_unix().saturating_sub(now);
        let jitter = u64::from(self.state.account_key[0]) * (remaining / 20) / 256;
        self.state.next_attempt = now.saturating_add((remaining * 2 / 3).saturating_sub(jitter));
        self.state.installed = Some(issued);
        self.state.failures = 0;
        self.state.order = None;
        self.persist()?;
        Ok(validated)
    }

    /// Revalidate the durable complete pair at boot, without network traffic.
    pub fn installed(
        &self,
        validator: &CertificateValidator,
    ) -> Result<Option<ValidatedCertificate>, ManagerError> {
        self.state
            .installed
            .as_ref()
            .map(|pair| validator.validate(pair, &self.config))
            .transpose()
    }

    pub fn next_attempt_unix(&self) -> u64 {
        self.state.next_attempt
    }

    /// Bounded cooperative shutdown/restart cleanup. Failed operations stay in
    /// the private journal, blocking new challenge mutations until reconciled.
    /// SIGKILL cannot run async cleanup; the next owner replays this journal.
    pub async fn cleanup_dns(&mut self) -> Result<(), ManagerError> {
        if self.state.dns_cleanup.is_empty() {
            return Ok(());
        }
        tokio::time::timeout(Duration::from_secs(20), self.cleanup_dns_inner())
            .await
            .map_err(|_| ManagerError::Dns)?
    }
    async fn cleanup_dns_inner(&mut self) -> Result<(), ManagerError> {
        let provider = self.dns.clone().ok_or(ManagerError::State)?;
        while let Some(record) = self.state.dns_cleanup.last().cloned() {
            if !record.valid_for(provider.scope()) {
                return Err(ManagerError::State);
            }
            tokio::time::timeout(Duration::from_secs(5), provider.cleanup(&record))
                .await
                .map_err(|_| ManagerError::Dns)?
                .map_err(|_| ManagerError::Dns)?;
            self.state.dns_cleanup.pop();
            self.persist()?;
        }
        Ok(())
    }

    /// Reconcile an interrupted newOrder using a URL recovered by the operator
    /// from this account's CA records. It is never a general URL fetch surface.
    pub fn reconcile_order(&mut self, url: &str) -> Result<(), ManagerError> {
        if !url.parse().is_ok_and(|u| self.http.permits(&u)) {
            return Err(ManagerError::State);
        }
        let pending = self.state.order.as_mut().ok_or(ManagerError::State)?;
        if pending.url.is_some() {
            return Err(ManagerError::State);
        }
        pending.url = Some(url.to_owned());
        self.persist()
    }
}

#[cfg(test)]
#[path = "manager_tests.rs"]
mod tests;
