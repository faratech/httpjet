//! Optional generation-bound OCSP state. No network work in the resolver.
use crate::CertReloadHandle;
use anyhow::{Result, anyhow, ensure};
use hj_ocsp::{Decision, Endpoint, RefreshPool, Slot, Staple};
use parking_lot::Mutex;
use rustls::sign::CertifiedKey;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};

const MAX_IDENTITIES: usize = 128;

/// Resumption skips certificate selection. OCSP-enabled listeners must disable
/// both stateful and stateless resumption so every new connection checks status.
pub fn disable_resumption(config: &mut rustls::ServerConfig) {
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.ticketer = Arc::new(NoTickets);
}
#[derive(Debug)]
struct NoTickets;
impl rustls::server::ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// One shared, bounded manager for all enabled listener resolver handles.
pub struct Stapling {
    endpoint: Endpoint,
    required: bool,
    slots: Mutex<HashMap<Vec<u8>, Weak<Slot>>>,
    pool: Arc<RefreshPool>,
}
impl Stapling {
    pub fn new(endpoint: &str, loopback_test: bool, required: bool) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            endpoint: Endpoint::new(endpoint, loopback_test)?,
            required,
            slots: Mutex::new(HashMap::new()),
            pool: Arc::new(RefreshPool::default()),
        }))
    }
    pub(crate) fn register(
        &self,
        keys: impl Iterator<Item = Arc<CertifiedKey>>,
    ) -> Result<Arc<Slots>> {
        let mut registry = self.slots.lock();
        registry.retain(|_, value| value.strong_count() > 0);
        let mut selected = HashMap::new();
        for key in keys {
            ensure!(
                (2..=8).contains(&key.cert.len()),
                "OCSP needs leaf plus immediate issuer (at most eight certificates)"
            );
            let total = key.cert.iter().map(|c| c.as_ref().len()).sum::<usize>();
            ensure!(total <= hj_ocsp::MAX_RESPONSE, "OCSP chain exceeds 64 KiB");
            let leaf = key.cert[0].as_ref();
            // Exact leaf identity, never SNI/public-key identity. A chain-only
            // change must not reset a previously verified revocation. Reuse
            // pins the first verified issuer and its conservative expiry cap.
            let identity = leaf.to_vec();
            if selected.contains_key(leaf) {
                continue;
            }
            let slot = match registry.get(&identity).and_then(Weak::upgrade) {
                Some(slot) => slot,
                None => {
                    ensure!(
                        registry.len() < MAX_IDENTITIES,
                        "OCSP live generation identity limit reached"
                    );
                    let slot = Slot::new(
                        leaf,
                        key.cert[1].as_ref(),
                        self.endpoint.clone(),
                        self.required,
                    )?;
                    registry.insert(identity, Arc::downgrade(&slot));
                    slot
                }
            };
            selected.insert(
                leaf.to_vec(),
                Entry {
                    slot,
                    stapled: Mutex::new(None),
                },
            );
        }
        Ok(Arc::new(Slots { selected }))
    }
    pub fn active_identities(&self) -> usize {
        self.slots
            .lock()
            .values()
            .filter(|s| s.strong_count() > 0)
            .count()
    }
    /// At most four jobs in flight; callers run this on the application runtime
    /// and cancel/drop it during shutdown. Retired generations own their slots
    /// only while a resolver still holds that generation, not indefinitely.
    pub async fn refresh(&self) {
        let slots: Vec<_> = self
            .slots
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        let mut jobs = tokio::task::JoinSet::new();
        for slot in slots {
            if !slot.due() {
                continue;
            }
            if jobs.len() == 4 {
                let _ = jobs.join_next().await;
            }
            let pool = self.pool.clone();
            jobs.spawn(async move { pool.refresh(&slot).await });
        }
        while jobs.join_next().await.is_some() {}
    }
}

struct Entry {
    slot: Arc<Slot>,
    stapled: Mutex<Option<(Arc<Staple>, Arc<CertifiedKey>)>>,
}
pub(crate) struct Slots {
    selected: HashMap<Vec<u8>, Entry>,
}
impl std::fmt::Debug for Slots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspSlots")
            .field("identities", &self.selected.len())
            .finish()
    }
}
impl Slots {
    pub(crate) fn resolve(&self, key: Arc<CertifiedKey>) -> Option<Arc<CertifiedKey>> {
        let entry = self.selected.get(key.cert.first()?.as_ref())?;
        match entry.slot.decision() {
            Decision::Reject => None,
            Decision::Omit => {
                if key.ocsp.is_none() {
                    Some(key)
                } else {
                    let mut clean = (*key).clone();
                    clean.ocsp = None;
                    Some(Arc::new(clean))
                }
            }
            Decision::Staple(staple) => {
                let bytes = staple.bytes()?;
                let mut cached = entry.stapled.lock();
                if let Some((old, key)) = &*cached {
                    if Arc::ptr_eq(old, &staple) {
                        return Some(key.clone());
                    }
                }
                let mut next = (*key).clone();
                next.ocsp = Some(bytes.to_vec());
                let next = Arc::new(next);
                *cached = Some((staple, next.clone()));
                Some(next)
            }
        }
    }
}

impl CertReloadHandle {
    /// Boot-time opt-in only, before listeners begin accepting. Both file and
    /// managed generations are prepared before activation; failures publish none.
    /// Caller MUST also disable resumption on all configs using this handle.
    /// Subsequent reload/ACME replacement carries matching slots atomically with
    /// the generation. The manager cannot be swapped or disabled while serving.
    pub fn enable_ocsp(&self, manager: Arc<Stapling>) -> Result<()> {
        if self.2.load_full().is_some() {
            return Err(anyhow!("OCSP manager already installed"));
        }
        let mut file = (**self.0.load()).clone();
        let mut managed = (**self.1.load()).clone();
        file.stapling = Some(
            manager.register(
                file.sni
                    .by_name
                    .values()
                    .flatten()
                    .cloned()
                    .chain(file.default.iter().cloned()),
            )?,
        );
        managed.stapling = Some(manager.register(managed.by_name.values().flatten().cloned())?);
        self.2.store(Some(manager));
        self.0.store(Arc::new(file));
        self.1.store(Arc::new(managed));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReloadableResolver, SniCertMap, SniWithDefault};
    use arc_swap::ArcSwap;
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    fn ca() -> CertifiedIssuer<'static, KeyPair> {
        crate::install_crypto_provider().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
    }
    fn key(ca: &CertifiedIssuer<'_, KeyPair>) -> Arc<CertifiedKey> {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["example.test".into()])
            .unwrap()
            .signed_by(&key, ca)
            .unwrap();
        Arc::new(
            CertifiedKey::from_der(
                vec![cert.der().clone(), ca.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
                &crate::provider().unwrap(),
            )
            .unwrap(),
        )
    }
    fn manager(required: bool) -> Arc<Stapling> {
        Stapling::new("http://127.0.0.1:12345/ocsp", true, required).unwrap()
    }
    #[test]
    fn exact_certificate_generations_keep_their_own_slots() {
        let ca = ca();
        let a = key(&ca);
        let b = key(&ca);
        let manager = manager(true);
        let first = manager.register(std::iter::once(a.clone())).unwrap();
        let same = manager.register(std::iter::once(a.clone())).unwrap();
        let next = manager.register(std::iter::once(b.clone())).unwrap();
        assert_eq!(manager.active_identities(), 2);
        assert!(Arc::ptr_eq(
            &first.selected[a.cert[0].as_ref()].slot,
            &same.selected[a.cert[0].as_ref()].slot
        ));
        assert!(!next.selected.contains_key(a.cert[0].as_ref()));
        assert!(first.resolve(b).is_none());
        drop(first);
        drop(same);
        assert_eq!(manager.active_identities(), 1);
    }
    #[test]
    fn identity_budget_is_bounded_and_retired_generations_are_reclaimed() {
        let ca = ca();
        let manager = manager(false);
        let mut generations = Vec::new();
        for _ in 0..MAX_IDENTITIES {
            generations.push(manager.register(std::iter::once(key(&ca))).unwrap());
        }
        let next = key(&ca);
        assert!(manager.register(std::iter::once(next.clone())).is_err());
        generations.pop();
        let _next = manager.register(std::iter::once(next)).unwrap();
        assert_eq!(manager.active_identities(), MAX_IDENTITIES);
    }
    #[test]
    fn managed_rejection_cannot_fall_back_to_the_file_certificate() {
        let ca = ca();
        let key = key(&ca);
        let file = SniWithDefault {
            sni: SniCertMap::new(),
            default: Some(key.clone()),
            stapling: None,
        };
        let mut managed = SniCertMap::new();
        managed.add("example.test", key.clone());
        let manager = manager(true);
        managed.stapling = Some(manager.register(std::iter::once(key.clone())).unwrap());
        let resolver = ReloadableResolver(
            Arc::new(ArcSwap::from_pointee(file)),
            Arc::new(ArcSwap::from_pointee(managed)),
        );
        let mut config = rustls::ServerConfig::builder_with_provider(crate::provider().unwrap())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        disable_resumption(&mut config);
        assert!(!config.session_storage.can_cache());
        assert!(!config.ticketer.enabled());
        assert_eq!(config.send_tls13_tickets, 0);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(crate::provider().unwrap())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            "example.test".try_into().unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        server.read_tls(&mut hello.as_slice()).unwrap();
        assert!(server.process_new_packets().is_err());
    }
}
