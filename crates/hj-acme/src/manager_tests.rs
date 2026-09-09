use super::*;
use crate::Directory;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hj-acme-manager-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn config(&self, directory: &str) -> AcmeConfig {
        AcmeConfig::new(
            Directory::parse(directory, true).unwrap(),
            &["example.test"],
            self.0.clone(),
            true,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn account_identity_is_durable_and_config_bound_before_network() {
    let f = Fixture::new();
    let config = f.config("http://127.0.0.1:1/dir");
    let manager = AcmeManager::open(config.clone(), None).unwrap();
    let key = manager.state.account_key.clone();
    drop(manager);
    let mut manager = AcmeManager::open(config.clone(), None).unwrap();
    assert_eq!(key, manager.state.account_key);
    assert_eq!(manager.issue().await.err(), Some(ManagerError::Authority));
    assert_eq!(manager.issue().await.err(), Some(ManagerError::Backoff));
    drop(manager);
    assert!(matches!(
        AcmeManager::open(f.config("http://127.0.0.1:2/dir"), None),
        Err(ManagerError::State)
    ));
}

#[tokio::test]
async fn uncertain_creation_never_reissues_on_restart() {
    let f = Fixture::new();
    let config = f.config("http://127.0.0.1:1/dir");
    let mut manager = AcmeManager::open(config.clone(), None).unwrap();
    manager.state.order = Some(PendingOrder {
        url: None,
        private_key: "pending".into(),
        csr: vec![],
    });
    manager.persist().unwrap();
    drop(manager);
    let mut manager = AcmeManager::open(config, None).unwrap();
    assert_eq!(
        manager.issue().await.err(),
        Some(ManagerError::UncertainOrder)
    );
    assert_eq!(
        manager.reconcile_order("http://127.0.0.1:2/order/1"),
        Err(ManagerError::State)
    );
    manager
        .reconcile_order("http://127.0.0.1:1/order/1")
        .unwrap();
    assert_eq!(
        manager.state.order.as_ref().unwrap().url.as_deref(),
        Some("http://127.0.0.1:1/order/1")
    );
}

#[tokio::test]
async fn authority_retry_after_survives_restart() {
    let f = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = f.config(&format!("http://{}/dir", listener.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket.write_all(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 86400\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
    });
    let mut manager = AcmeManager::open(config.clone(), None).unwrap();
    assert_eq!(manager.issue().await.err(), Some(ManagerError::Authority));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(manager.next_attempt_unix() >= now + 86390);
    drop(manager);
    let mut manager = AcmeManager::open(config, None).unwrap();
    assert_eq!(manager.issue().await.err(), Some(ManagerError::Backoff));
    server.await.unwrap();
}

struct Process(Child);
struct FakeDns {
    scope: crate::DnsScope,
    values: Mutex<BTreeSet<String>>,
    fail_cleanup: std::sync::atomic::AtomicBool,
    stall_present: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl crate::DnsProvider for FakeDns {
    fn scope(&self) -> &crate::DnsScope {
        &self.scope
    }
    fn identity(&self) -> String {
        format!("fake-dns:{}", self.scope.identity())
    }
    async fn present(&self, record: &crate::DnsRecord) -> Result<(), crate::DnsError> {
        self.values
            .lock()
            .unwrap()
            .insert(record.value().to_owned());
        if self.stall_present.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        Ok(())
    }
    async fn ready(&self, record: &crate::DnsRecord) -> Result<bool, crate::DnsError> {
        Ok(self.values.lock().unwrap().contains(record.value()))
    }
    async fn cleanup(&self, record: &crate::DnsRecord) -> Result<(), crate::DnsError> {
        if self.fail_cleanup.load(Ordering::Relaxed) {
            return Err(crate::DnsError);
        }
        self.values.lock().unwrap().remove(record.value());
        Ok(())
    }
}

#[tokio::test]
async fn dns_cancelled_present_is_recovered_without_deleting_unrelated_txt() {
    use crate::DnsProvider;
    let f = Fixture::new();
    let config = AcmeConfig::new_dns01(
        Directory::parse("http://127.0.0.1:1/dir", true).unwrap(),
        &["*.example.test"],
        f.0.clone(),
        true,
    )
    .unwrap();
    let provider = Arc::new(FakeDns {
        scope: crate::DnsScope::new(&["example.test"]).unwrap(),
        values: Mutex::new(BTreeSet::from(["unrelated-owner-value".to_owned()])),
        fail_cleanup: std::sync::atomic::AtomicBool::new(false),
        stall_present: std::sync::atomic::AtomicBool::new(true),
    });
    let mut manager = AcmeManager::open_dns01(config.clone(), None, provider.clone()).unwrap();
    let record = crate::DnsRecord::new(
        &Domain::parse_dns01("*.example.test").unwrap(),
        "A".repeat(43),
    )
    .unwrap();
    manager.state.dns_cleanup.push(record.clone());
    manager.persist().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(5), provider.present(&record))
            .await
            .is_err()
    );
    assert!(provider.ready(&record).await.unwrap());
    drop(manager); // simulate process loss with a recorded unknown present outcome
    let changed_scope = Arc::new(FakeDns {
        scope: crate::DnsScope::new(&["example.test", "other.test"]).unwrap(),
        values: Mutex::new(BTreeSet::new()),
        fail_cleanup: std::sync::atomic::AtomicBool::new(false),
        stall_present: std::sync::atomic::AtomicBool::new(false),
    });
    assert!(matches!(
        AcmeManager::open_dns01(config.clone(), None, changed_scope),
        Err(ManagerError::State)
    ));
    provider.fail_cleanup.store(true, Ordering::Relaxed);
    let mut manager = AcmeManager::open_dns01(config.clone(), None, provider.clone()).unwrap();
    assert_eq!(manager.cleanup_dns().await, Err(ManagerError::Dns));
    assert_eq!(manager.state.dns_cleanup.len(), 1);
    drop(manager);
    provider.fail_cleanup.store(false, Ordering::Relaxed);
    let mut manager = AcmeManager::open_dns01(config, None, provider.clone()).unwrap();
    manager.cleanup_dns().await.unwrap();
    assert!(manager.state.dns_cleanup.is_empty());
    assert_eq!(
        *provider.values.lock().unwrap(),
        BTreeSet::from(["unrelated-owner-value".to_owned()])
    );
}

#[test]
fn failed_candidate_validation_preserves_installed_pair() {
    let f = Fixture::new();
    let config = f.config("http://127.0.0.1:1/dir");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["example.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let validator = CertificateValidator::new(Some(cert.pem().as_bytes())).unwrap();
    let mut manager = AcmeManager::open(config.clone(), None).unwrap();
    let valid = manager
        .install(
            IssuedCertificate {
                certificate_pem: cert.pem(),
                private_key_pem: key.serialize_pem(),
            },
            &validator,
        )
        .unwrap();
    let before = manager.store.read().unwrap();
    let bad = IssuedCertificate {
        certificate_pem: cert.pem(),
        private_key_pem: rcgen::KeyPair::generate().unwrap().serialize_pem(),
    };
    assert_eq!(
        manager.install(bad, &validator).err(),
        Some(ManagerError::Crypto)
    );
    assert_eq!(manager.store.read().unwrap(), before);
    drop(manager);
    let reopened = AcmeManager::open(config, None).unwrap();
    assert_eq!(
        reopened
            .installed(&validator)
            .unwrap()
            .unwrap()
            .certified_key()
            .cert,
        valid.certified_key().cert
    );
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Requires explicit prebuilt Pebble v2.10.1 binaries and its source fixture root.
/// All binds are ephemeral loopback; validation is REAL, never ALWAYS_VALID.
#[tokio::test]
#[ignore = "requires HJ_PEBBLE_BIN, HJ_PEBBLE_DNS_BIN and HJ_PEBBLE_SOURCE"]
async fn pebble_issuance_recovery_and_renewal() {
    let pebble = std::env::var("HJ_PEBBLE_BIN").expect("HJ_PEBBLE_BIN");
    let dns_bin = std::env::var("HJ_PEBBLE_DNS_BIN").expect("HJ_PEBBLE_DNS_BIN");
    let source = PathBuf::from(std::env::var("HJ_PEBBLE_SOURCE").expect("HJ_PEBBLE_SOURCE"));
    let f = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = listener.local_addr().unwrap().port();
    let ca_port = port();
    let management_port = port();
    let dns_port = port();
    let dns_management = port();
    let ca_config = serde_json::json!({"pebble": {
        "listenAddress": format!("127.0.0.1:{ca_port}"),
        "managementListenAddress": format!("127.0.0.1:{management_port}"),
        "certificate": source.join("test/certs/localhost/cert.pem"),
        "privateKey": source.join("test/certs/localhost/key.pem"),
        "httpPort": http_port, "tlsPort": port(), "externalAccountBindingRequired": false,
        "keyAlgorithm": "ecdsa", "retryAfter": {"authz": 1, "order": 1}
    }});
    let config_path = f.0.join("pebble.json");
    fs::write(&config_path, serde_json::to_vec(&ca_config).unwrap()).unwrap();
    let _dns = Process(
        Command::new(dns_bin)
            .args([
                "-dnsserver",
                &format!("127.0.0.1:{dns_port}"),
                "-management",
                &format!("127.0.0.1:{dns_management}"),
                "-http01",
                "",
                "-https01",
                "",
                "-tlsalpn01",
                "",
                "-doh",
                "",
                "-defaultIPv6",
                "",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let _ca = Process(
        Command::new(pebble)
            .arg("-config")
            .arg(&config_path)
            .args(["-dnsserver", &format!("127.0.0.1:{dns_port}")])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_AUTHZREUSE", "0")
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .env_remove("PEBBLE_VA_ALWAYS_VALID")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let root = fs::read(source.join("test/certs/pebble.minica.pem")).unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .tls_certs_only([reqwest::Certificate::from_pem(&root).unwrap()])
        .build()
        .unwrap();
    let issuer_url = format!("https://127.0.0.1:{management_port}/roots/0");
    let issuer = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(response) = client.get(&issuer_url).send().await
                && response.status().is_success()
            {
                break response.bytes().await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("Pebble ready");
    let config = f.config(&format!("https://127.0.0.1:{ca_port}/dir"));
    let mut manager = AcmeManager::open(config.clone(), Some(&root)).unwrap();
    let registry = Arc::new(Mutex::new(manager.challenges()));
    let hits = Arc::new(AtomicU64::new(0));
    let server_registry = registry.clone();
    let server_hits = hits.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let request = tokio::time::timeout(Duration::from_secs(2), async {
                while !buffer.ends_with(b"\r\n\r\n") && buffer.len() < 8192 {
                    let mut b = [0; 1];
                    if socket.read(&mut b).await.unwrap_or(0) == 0 {
                        break;
                    }
                    buffer.push(b[0]);
                }
            })
            .await;
            if request.is_err() {
                continue;
            }
            let text = String::from_utf8_lossy(&buffer);
            let path = text
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let host = text
                .lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
                        .map(|(_, v)| v.trim())
                })
                .unwrap();
            let response = server_registry
                .lock()
                .unwrap()
                .lookup(&http::Method::GET, host, &path.parse().unwrap(), false)
                .unwrap();
            if response.status == http::StatusCode::OK {
                server_hits.fetch_add(1, Ordering::Relaxed);
            }
            let wire = format!(
                "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.status.as_u16(),
                response.body.len(),
                response.body
            );
            let _ = socket.write_all(wire.as_bytes()).await;
        }
    });
    let first = manager.issue().await.expect("initial HTTP-01 issuance");
    assert!(
        hits.load(Ordering::Relaxed) > 0,
        "CA must fetch registry token"
    );
    let account_id = manager.state.account_id.clone();
    let order_url = manager.state.order.as_ref().unwrap().url.clone();
    // Crash after issuance but before installation: recover the SAME order/key.
    manager.state.next_attempt = 0;
    manager.persist().unwrap();
    drop(manager);
    let mut manager = AcmeManager::open(config.clone(), Some(&root)).unwrap();
    *registry.lock().unwrap() = manager.challenges();
    let recovered = manager.issue().await.expect("recover valid order");
    assert_eq!(recovered.certificate_pem, first.certificate_pem);
    assert_eq!(recovered.private_key_pem, first.private_key_pem);
    assert_eq!(manager.state.order.as_ref().unwrap().url, order_url);
    let validator = CertificateValidator::new(Some(&issuer)).unwrap();
    let installed = manager
        .install(recovered, &validator)
        .expect("verified durable pair");
    assert!(installed.expires_unix() > 0);
    drop(manager);
    let mut manager = AcmeManager::open(config, Some(&root)).unwrap();
    assert!(manager.installed(&validator).unwrap().is_some());
    assert_eq!(manager.state.account_id, account_id);
    manager.state.next_attempt = 0; // advance only the synthetic renewal schedule
    manager.persist().unwrap();
    *registry.lock().unwrap() = manager.challenges();
    let previous_hits = hits.load(Ordering::Relaxed);
    let renewed = manager.issue().await.expect("renewal HTTP-01 issuance");
    assert_ne!(renewed.certificate_pem, first.certificate_pem);
    assert!(hits.load(Ordering::Relaxed) > previous_hits);
    manager.install(renewed, &validator).unwrap();
    assert_eq!(manager.state.account_id, account_id);
    server.abort();
    let _ = server.await;
}
