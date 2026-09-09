use super::*;

struct FixtureTls {
    server: Arc<rustls::ServerConfig>,
    certificate: rustls::pki_types::CertificateDer<'static>,
    client: Option<(rustls::pki_types::CertificateDer<'static>, Vec<u8>)>,
}

impl FixtureTls {
    fn new(require_client: bool) -> Self {
        hj_tls::install_crypto_provider().unwrap();
        let signed = rcgen::generate_simple_self_signed(vec!["canon.test".into()]).unwrap();
        let certificate = signed.cert.der().clone();
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(signed.signing_key.serialize_der()).unwrap();
        let client = require_client.then(|| {
            let signed = rcgen::generate_simple_self_signed(vec!["client.test".into()]).unwrap();
            (
                signed.cert.der().clone(),
                signed.signing_key.serialize_der(),
            )
        });
        let builder = rustls::ServerConfig::builder();
        let builder = if let Some((cert, _)) = &client {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.clone()).unwrap();
            builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .unwrap(),
            )
        } else {
            builder.with_no_client_auth()
        };
        let mut server = builder
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            server: Arc::new(server),
            certificate,
            client,
        }
    }
}

enum FixtureStream {
    Plain(std::net::TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>>),
}

impl std::io::Read for FixtureStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}
impl std::io::Write for FixtureStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn fixture_connect(address: SocketAddr, tls: Option<&FixtureTls>) -> FixtureStream {
    try_fixture_connect(address, tls).unwrap()
}

fn try_fixture_connect(
    address: SocketAddr,
    tls: Option<&FixtureTls>,
) -> std::io::Result<FixtureStream> {
    let mut socket = std::net::TcpStream::connect(address)?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let Some(tls) = tls else {
        return Ok(FixtureStream::Plain(socket));
    };
    // Trust only the expected certificate, never bypass certificate validation.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(tls.certificate.clone()).unwrap();
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut config = if let Some((cert, key)) = &tls.client {
        builder
            .with_client_auth_cert(
                vec![cert.clone()],
                rustls::pki_types::PrivateKeyDer::try_from(key.clone()).unwrap(),
            )
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), "canon.test".try_into().unwrap()).unwrap();
    while connection.is_handshaking() {
        connection.complete_io(&mut socket)?;
    }
    assert_eq!(connection.peer_certificates().unwrap()[0], tls.certificate);
    Ok(FixtureStream::Tls(Box::new(rustls::StreamOwned::new(
        connection, socket,
    ))))
}

fn request_over_fixture(address: SocketAddr, tls: Option<&FixtureTls>) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut client = fixture_connect(address, tls);
    client
        .write_all(b"GET /index.html HTTP/1.1\r\nHost: canon.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).unwrap();
    bytes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn distinct_http_candidate_publishes_then_drains_old_resource_generation() {
    http_candidate_replacement(false, false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_address_http_candidate_preserves_accept_queue() {
    http_candidate_replacement(true, false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_address_tls_candidate_rotates_certificate_and_drains_old_response() {
    http_candidate_replacement(true, true, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_address_tls_candidate_requires_new_client_auth_while_old_response_drains() {
    http_candidate_replacement(true, true, true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_address_single_shot_handoff() {
    const CHILD: &str = "HTTPJET_TEST_SINGLE_HANDOFF";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "uring::generation_test::same_address_single_shot_handoff",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    // Process isolation keeps this global runtime option from racing other tests.
    MULTISHOT_ACCEPT.store(false, std::sync::atomic::Ordering::Relaxed);
    http_candidate_replacement(true, false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renamed_http_listener_hands_off_old_identity_and_drains_old_requests() {
    http_candidate_replacement(true, false, false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planned_tcp_acquisition_owns_both_endpoints_and_rolls_back_together() {
    hj_tls::install_crypto_provider().unwrap();
    use crate::config_transaction::Coordinator;
    use crate::resource_generation::TransportResources;
    let root = std::env::temp_dir().join(format!(
        "hj-tcp-plan-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let state = crate::pipeline::e2e::build_state(root.clone());
    let server_root = state.server.server_root.clone();
    let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let https = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    http.set_nonblocking(true).unwrap();
    https.set_nonblocking(true).unwrap();
    let http_addr = http.local_addr().unwrap();
    let https_addr = https.local_addr().unwrap();
    let mut config = (*state.server).clone();
    let mut secure = config.listeners[0].clone();
    secure.name = "tls".into();
    secure.secure = true;
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap())
        .unwrap();
    let signing_key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["canon.test".into()])
        .unwrap()
        .signed_by(&signing_key, &ca)
        .unwrap();
    let signed = rcgen::CertifiedKey { cert, signing_key };
    let cert_file = root.join("candidate-cert.pem");
    let key_file = root.join("candidate-key.pem");
    std::fs::write(&cert_file, format!("{}{}", signed.cert.pem(), ca.pem())).unwrap();
    std::fs::write(&key_file, signed.signing_key.serialize_pem()).unwrap();
    secure.tls = Some(hj_core::config::ListenerTls {
        cert_file,
        key_file,
        cert_chain: true,
        ca_cert_file: None,
        client_verify: 0,
        verify_depth: 1,
        enable_stapling: false,
        crl_file: None,
    });
    config.listeners.push(secure);
    let state = ServerState::reload(&state, Arc::new(config.clone())).unwrap();
    verify_certificate_owner_replacement(state.clone()).await;
    let holder = Arc::new(arc_swap::ArcSwap::from(state.clone()));
    let coordinator = Coordinator::new(holder.clone())
        .unwrap()
        .with_tcp_launch_policy(crate::listener_plan::TcpLaunchPolicy {
            http: http_addr,
            https: Some(https_addr),
        });
    #[cfg(feature = "ocsp")]
    let responder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    #[cfg(feature = "ocsp")]
    let coordinator = {
        use clap::Parser;
        responder.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/", responder.local_addr().unwrap());
        let args = crate::ServeArgs::try_parse_from([
            "httpjet",
            "--ocsp-responder",
            &endpoint,
            "--ocsp-required",
            "--ocsp-test-mode",
        ])
        .unwrap();
        coordinator.with_ocsp_policy(args.ocsp)
    };
    let mut groups = Vec::new();
    let mut owners = Vec::new();
    for (socket, name, tls) in [(&https, "tls", true), (&http, "http", false)] {
        let mut group = WorkerGroup::for_tcp_epoch(
            &state.shutdown,
            state.trust_epoch.clone(),
            worker_group::TcpListenerId {
                name: name.into(),
                tls,
            },
        );
        owners.push(group.register_acceptor(socket).unwrap());
        groups.push(group);
    }
    coordinator
        .install_initial_resources(
            TransportResources::new(state.trust_epoch.clone(), groups).unwrap(),
        )
        .unwrap();
    let transaction = coordinator.begin().await;
    let acquired = transaction.acquire_tcp_plan(&config).unwrap();
    assert_eq!(acquired.http.listeners[0].local_addr().unwrap(), http_addr);
    assert_eq!(
        acquired.https.as_ref().unwrap().listeners[0]
            .local_addr()
            .unwrap(),
        https_addr
    );
    drop(acquired);
    // A discarded complete candidate neither steals nor cancels the sources.
    drop(transaction.acquire_tcp_plan(&config).unwrap());
    let mut next = ServerState::reload(&state, Arc::new(config.clone())).unwrap();
    Arc::get_mut(&mut next).unwrap().trust_epoch = Arc::new(());
    let policy = || {
        transaction
            .prepare_tcp_tls(next.clone(), false, false)
            .unwrap()
            .unwrap()
    };
    #[cfg(feature = "ocsp")]
    {
        use clap::Parser;
        let bare = || {
            crate::tcp_candidate::TcpTlsPolicy::prepare(
                next.clone(),
                worker_group::TcpListenerId {
                    name: "tls".into(),
                    tls: true,
                },
                false,
                false,
            )
            .unwrap()
        };
        assert!(
            transaction
                .prepare_tcp_workers(
                    next.clone(),
                    Some(bare()),
                    pipeline_admission(holder.clone())
                )
                .is_err()
        );
        let endpoint = format!("http://{}/", responder.local_addr().unwrap());
        let weaker = crate::ServeArgs::try_parse_from([
            "httpjet",
            "--ocsp-responder",
            &endpoint,
            "--ocsp-test-mode",
        ])
        .unwrap();
        let weaker = bare()
            .with_ocsp(&weaker.ocsp, http_addr, https_addr)
            .unwrap();
        assert!(
            transaction
                .prepare_tcp_workers(
                    next.clone(),
                    Some(weaker),
                    pipeline_admission(holder.clone())
                )
                .is_err()
        );
    }
    // A different candidate with the same generation and trust epoch is still
    // not the snapshot whose certificates/policy were prepared.
    let mut other = ServerState::reload(&state, Arc::new(config.clone())).unwrap();
    Arc::get_mut(&mut other).unwrap().trust_epoch = next.trust_epoch.clone();
    let wrong_snapshot = transaction.prepare_tcp_tls(other, false, false).unwrap();
    assert!(
        transaction
            .prepare_tcp_workers(
                next.clone(),
                wrong_snapshot,
                pipeline_admission(holder.clone())
            )
            .is_err()
    );
    let key_path = &config.listeners[1].tls.as_ref().unwrap().key_file;
    std::fs::write(key_path, "invalid candidate key").unwrap();
    assert!(
        transaction
            .prepare_tcp_tls(next.clone(), false, false)
            .is_err()
    );
    std::fs::write(key_path, signed.signing_key.serialize_pem()).unwrap();
    assert!(
        transaction
            .prepare_tcp_workers(next.clone(), None, pipeline_admission(holder.clone()))
            .is_err()
    );
    let prepared = transaction
        .prepare_tcp_workers(
            next.clone(),
            Some(policy()),
            pipeline_admission(holder.clone()),
        )
        .unwrap();
    assert_eq!(prepared.group_count(), 2);
    #[cfg(feature = "ocsp")]
    assert!(prepared.has_ocsp_refresh());
    drop(prepared);
    // Inject a wrong predecessor after valid acquisition. HTTPS fails after
    // HTTP is already prepared; both candidate groups must stop and join.
    let mut wrong = transaction.acquire_tcp_plan(&config).unwrap();
    wrong.https.as_mut().unwrap().predecessor = wrong.http.predecessor.clone();
    assert!(
        crate::tcp_candidate::prepare(
            wrong,
            transaction.tcp_plan(&next.server).unwrap(),
            None,
            transaction.candidate_view(next.clone()).unwrap(),
            Some(policy()),
            pipeline_admission(holder.clone())
        )
        .is_err()
    );
    // Retire only the TLS descriptor owner. HTTP acquisition succeeds first,
    // then the missing TLS source rejects and drops the partial candidate.
    owners[0].cancel();
    assert!(matches!(
        transaction.acquire_tcp_plan(&config),
        Err(crate::config_transaction::PublishError::ResourceRequired)
    ));
    drop(
        transaction
            .tcp_handoff(
                &worker_group::TcpListenerId {
                    name: "http".into(),
                    tls: false,
                },
                http_addr,
            )
            .unwrap(),
    );
    drop(transaction);
    #[cfg(feature = "ocsp")]
    {
        tokio::task::yield_now().await;
        assert!(
            matches!(responder.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "inactive candidates must not contact the OCSP responder"
        );
    }
    coordinator.finish_shutdown();
    for owner in &mut owners {
        owner.cancel();
    }
    drop((owners, http, https));
    // No accepted streams here: address reuse proves rollback released all fds.
    drop(std::net::TcpListener::bind(http_addr).unwrap());
    drop(std::net::TcpListener::bind(https_addr).unwrap());
    state.shutdown.cancel();
    drop(coordinator);
    drop(state);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(server_root).unwrap();
}

async fn verify_certificate_owner_replacement(state: Arc<ServerState>) {
    use crate::config_transaction::Coordinator;
    use crate::resource_generation::TransportResources;
    let coordinator = Coordinator::new(Arc::new(arc_swap::ArcSwap::from(state.clone()))).unwrap();
    #[cfg(feature = "acme")]
    let acme_targets = crate::acme_runtime::CertificateTargets::default();
    #[cfg(feature = "acme")]
    let coordinator = coordinator.with_acme_targets(Some(acme_targets.clone()));
    let resources = |state: &Arc<ServerState>| {
        let listener = state.server.listeners.iter().find(|l| l.secure).unwrap();
        let identity = worker_group::TcpListenerId {
            name: listener.name.clone().into(),
            tls: true,
        };
        let bundle =
            hj_tls::PreparedListenerTls::prepare(&state.server, listener, false, false, false)
                .unwrap();
        let group = WorkerGroup::for_tcp_epoch(
            &state.shutdown,
            state.trust_epoch.clone(),
            identity.clone(),
        );
        TransportResources::new(state.trust_epoch.clone(), vec![group])
            .unwrap()
            .with_certificate(identity, bundle.certificates)
            .unwrap()
    };
    coordinator
        .install_initial_resources(resources(&state))
        .unwrap();
    #[cfg(feature = "acme")]
    assert_eq!(
        acme_targets.names(),
        vec![Arc::<str>::from(
            state
                .server
                .listeners
                .iter()
                .find(|l| l.secure)
                .unwrap()
                .name
                .clone()
        )]
    );
    let transaction = coordinator.begin().await;
    transaction.reload_certificates(&state.server).unwrap();
    let mut config = (*state.server).clone();
    config.listeners.iter_mut().find(|l| l.secure).unwrap().name = "replacement-tls".into();
    assert!(transaction.reload_certificates(&config).is_err());
    let mut next = ServerState::reload(&state, Arc::new(config)).unwrap();
    Arc::get_mut(&mut next).unwrap().trust_epoch = Arc::new(());
    #[cfg(feature = "acme")]
    {
        let discarded = resources(&next);
        assert_eq!(
            acme_targets.names(),
            vec![Arc::<str>::from(
                state
                    .server
                    .listeners
                    .iter()
                    .find(|l| l.secure)
                    .unwrap()
                    .name
                    .clone()
            )],
            "candidate preparation must not redirect ACME renewals"
        );
        drop(discarded);
    }
    let revision = transaction.revision();
    transaction
        .publish_resources(&revision, next.clone(), resources(&next))
        .unwrap();
    #[cfg(feature = "acme")]
    assert_eq!(
        acme_targets.names(),
        vec![Arc::<str>::from("replacement-tls")],
        "publication must atomically switch ACME renewal targets"
    );
    let transaction = coordinator.begin().await;
    transaction.reload_certificates(&next.server).unwrap();
    assert!(
        transaction.reload_certificates(&state.server).is_err(),
        "reload must not select the retired listener's handle"
    );
    coordinator.close();
    assert!(transaction.reload_certificates(&next.server).is_err());
    drop(transaction);
    coordinator.finish_shutdown();
}

async fn http_candidate_replacement(
    same_address: bool,
    tls: bool,
    require_client: bool,
    rename: bool,
) {
    use crate::config_transaction::Coordinator;
    use crate::resource_generation::TransportResources;
    use std::io::{BufRead, Read, Write};
    let old_tls = tls.then(|| FixtureTls::new(false));
    let next_tls = tls.then(|| FixtureTls::new(require_client));
    let listener_identity = worker_group::TcpListenerId {
        name: "http".into(),
        tls,
    };
    let root = std::env::temp_dir().join(format!(
        "hj-resource-http-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let before = root.join("before");
    let after = root.join("after");
    let updated = root.join("updated");
    std::fs::create_dir_all(&before).unwrap();
    std::fs::create_dir(&after).unwrap();
    std::fs::create_dir(&updated).unwrap();
    let old_body = vec![b'o'; 8 * 1024 * 1024];
    std::fs::write(before.join("index.html"), &old_body).unwrap();
    std::fs::write(after.join("index.html"), b"new resource generation").unwrap();
    std::fs::write(updated.join("index.html"), b"subsequent application reload").unwrap();
    let old = crate::pipeline::e2e::build_state(before);
    let server_root = old.server.server_root.clone();
    let holder = Arc::new(arc_swap::ArcSwap::from(old.clone()));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let old_address = listener.local_addr().unwrap();
    let coordinator = Coordinator::new(holder.clone())
        .unwrap()
        .with_tcp_launch_policy(crate::listener_plan::TcpLaunchPolicy {
            http: old_address,
            https: Some(old_address),
        });
    let group = if let Some(tls) = &old_tls {
        spawn_uring_https(
            holder.clone(),
            "http".into(),
            old_address,
            1,
            tls.server.clone(),
            false,
            None,
            Some(vec![listener]),
            pipeline_admission(holder.clone()),
            ListenerBinding::default(),
        )
    } else {
        spawn_uring_http(
            holder.clone(),
            "http".into(),
            old_address,
            1,
            Some(vec![listener]),
            pipeline_admission(holder.clone()),
            ListenerBinding::default(),
        )
    }
    .unwrap();
    coordinator
        .install_initial_resources(
            TransportResources::new(old.trust_epoch.clone(), vec![group]).unwrap(),
        )
        .unwrap();

    let client = fixture_connect(old_address, old_tls.as_ref());
    let mut old_client = std::io::BufReader::new(client);
    old_client
        .get_mut()
        .write_all(b"GET /index.html HTTP/1.1\r\nHost: canon.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut head = String::new();
    loop {
        let mut line = String::new();
        assert!(old_client.read_line(&mut line).unwrap() > 0);
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    assert!(head.starts_with("HTTP/1.1 200"));
    assert!(
        head.to_ascii_lowercase()
            .contains("content-length: 8388608")
    );
    assert!(
        old.metrics
            .active_conns
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );

    let mut config = (*old.server).clone();
    if rename {
        config.listeners[0].name = "renamed".into();
    }
    let candidate_name: Arc<str> = config.listeners[0].name.clone().into();
    Arc::make_mut(
        config
            .vhosts
            .get_mut("testvh")
            .unwrap()
            .config
            .as_mut()
            .unwrap(),
    )
    .doc_root = after;
    let mut next = ServerState::reload(&old, Arc::new(config)).unwrap();
    Arc::get_mut(&mut next).unwrap().trust_epoch = Arc::new(());
    let transaction = coordinator.begin().await;
    let planned = transaction.tcp_plan(&next.server).unwrap();
    assert_eq!(planned.http.address, old_address);
    if !tls {
        assert_eq!(planned.http.identity.name, candidate_name);
        assert!(planned.https.is_none());
    }
    let revision = transaction.revision();
    let view = transaction.candidate_view(next.clone()).unwrap();
    assert!(matches!(
        transaction.tcp_handoff(&listener_identity, "127.0.0.1:0".parse().unwrap()),
        Err(crate::config_transaction::PublishError::ResourceRequired)
    ));
    if !tls && same_address {
        let mut missing_tls = (*next.server).clone();
        let mut secure = missing_tls.listeners[0].clone();
        secure.name = "missing-secure".into();
        secure.secure = true;
        missing_tls.listeners.push(secure);
        assert!(matches!(
            transaction.acquire_tcp_plan(&missing_tls),
            Err(crate::config_transaction::PublishError::ResourceRequired)
        ));
        // An unsupported addition rejects without diverting the active queue.
        assert!(request_over_fixture(old_address, None).ends_with(&old_body));
    }
    assert!(matches!(
        transaction.tcp_handoff(
            &worker_group::TcpListenerId {
                name: "missing-listener".into(),
                tls
            },
            old_address
        ),
        Err(crate::config_transaction::PublishError::ResourceRequired)
    ));
    assert!(
        Arc::ptr_eq(&view.load_full(), &next),
        "preparation must use the unpublished candidate"
    );
    let (new_address, resources) = if same_address && !tls {
        // Exercise coordinator acquisition and worker preparation, including
        // rollback of a fully ready but never activated candidate.
        drop(
            transaction
                .prepare_tcp_workers(next.clone(), None, pipeline_admission(holder.clone()))
                .unwrap(),
        );
        assert!(request_over_fixture(old_address, None).ends_with(&old_body));
        let groups = transaction
            .prepare_tcp_workers(next.clone(), None, pipeline_admission(holder.clone()))
            .unwrap();
        (old_address, groups)
    } else {
        let (listener, predecessor) = if same_address {
            let mut handoff = if tls {
                transaction
                    .tcp_handoff(&listener_identity, old_address)
                    .unwrap()
            } else {
                let acquired = transaction.acquire_tcp_plan(&next.server).unwrap();
                assert!(acquired.https.is_none());
                acquired.http
            };
            assert_eq!(handoff.listeners.len(), 1);
            (handoff.listeners.remove(0), Some(handoff.predecessor))
        } else {
            (std::net::TcpListener::bind("127.0.0.1:0").unwrap(), None)
        };
        listener.set_nonblocking(true).unwrap();
        let new_address = listener.local_addr().unwrap();
        let group = if let Some(tls) = &next_tls {
            spawn_uring_https(
                view,
                candidate_name.clone(),
                new_address,
                1,
                tls.server.clone(),
                require_client,
                None,
                Some(vec![listener]),
                pipeline_admission(holder.clone()),
                ListenerBinding::default(),
            )
        } else {
            spawn_uring_http(
                view,
                candidate_name.clone(),
                new_address,
                1,
                Some(vec![listener]),
                pipeline_admission(holder.clone()),
                ListenerBinding::default(),
            )
        }
        .unwrap();
        if same_address {
            assert_eq!(new_address, old_address);
            group.follow_acceptors(predecessor.unwrap()).unwrap();
        }
        (
            new_address,
            TransportResources::new(next.trust_epoch.clone(), vec![group]).unwrap(),
        )
    };
    let queued = if same_address {
        // Preparing duplicate ownership must not divert traffic from the old
        // accept queue into an inactive SO_REUSEPORT group's separate queue.
        assert!(request_over_fixture(old_address, old_tls.as_ref()).ends_with(&old_body));
        None
    } else {
        let mut new_client = std::net::TcpStream::connect(new_address).unwrap();
        new_client
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        new_client
            .write_all(b"GET /index.html HTTP/1.1\r\nHost: canon.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut probe = [0u8; 1];
        let error = new_client
            .read(&mut probe)
            .expect_err("candidate must not serve before publication");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        Some(FixtureStream::Plain(new_client))
    };
    assert!(Arc::ptr_eq(&holder.load_full(), &old));
    transaction
        .publish_resources(&revision, next.clone(), resources)
        .unwrap();
    let mut new_client = queued.unwrap_or_else(|| {
        let mut client = fixture_connect(new_address, next_tls.as_ref());
        client
            .write_all(b"GET /index.html HTTP/1.1\r\nHost: canon.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        client
    });
    if let FixtureStream::Plain(client) = &new_client {
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
    }
    let mut new_response = Vec::new();
    new_client.read_to_end(&mut new_response).unwrap();
    assert!(new_response.starts_with(b"HTTP/1.1 200"));
    assert!(new_response.ends_with(b"new resource generation"));
    if require_client {
        let expected = next_tls.as_ref().unwrap();
        let no_identity = FixtureTls {
            server: expected.server.clone(),
            certificate: expected.certificate.clone(),
            client: None,
        };
        let refused = (|| -> std::io::Result<()> {
            let mut client = try_fixture_connect(new_address, Some(&no_identity))?;
            client.write_all(
                b"GET /index.html HTTP/1.1\r\nHost: canon.test\r\nConnection: close\r\n\r\n",
            )?;
            let mut bytes = [0u8; 1];
            // TLS 1.3 can deliver the rejection after the client's handshake
            // appears finished; a read must never expose an HTTP response.
            let n = client.read(&mut bytes)?;
            if n == 0 {
                return Err(std::io::Error::other("client authentication rejected"));
            }
            Ok(())
        })();
        let error = refused.expect_err("new TLS policy must reject a client with no certificate");
        assert!(
            matches!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::AlertReceived(
                    rustls::AlertDescription::CertificateRequired
                ))
            ),
            "expected an explicit client-certificate rejection, not a timeout or transport failure: {error:?}"
        );
    }
    // Listener retirement must precede response drain. In particular, an armed
    // multishot SQE must not keep consuming accepts for the entire drain window.
    if !same_address {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while std::net::TcpStream::connect(old_address).is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("old acceptor must stop while its large response is still draining");
    }
    assert!(
        old.metrics
            .active_conns
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
    let mut drained = Vec::new();
    old_client.read_to_end(&mut drained).unwrap();
    assert_eq!(
        drained, old_body,
        "old in-flight response must finish under its original generation"
    );
    drop(old_client);
    drop(new_client);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while coordinator.reap_retired() == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    if !same_address {
        assert!(std::net::TcpStream::connect(old_address).is_err());
    }

    // Candidate views must reference the live holder, not a private holder that
    // would stop observing subsequent compatible application reloads.
    let mut config = (*next.server).clone();
    Arc::make_mut(
        config
            .vhosts
            .get_mut("testvh")
            .unwrap()
            .config
            .as_mut()
            .unwrap(),
    )
    .doc_root = updated;
    let application = ServerState::reload(&next, Arc::new(config)).unwrap();
    let transaction = coordinator.begin().await;
    let revision = transaction.revision();
    transaction.publish(&revision, application).unwrap();
    assert!(
        request_over_fixture(new_address, next_tls.as_ref())
            .ends_with(b"subsequent application reload")
    );
    coordinator.close();
    let closed = coordinator.begin().await;
    assert!(matches!(
        closed.tcp_handoff(&listener_identity, old_address),
        Err(crate::config_transaction::PublishError::Closed)
    ));
    drop(closed);
    coordinator.finish_shutdown();
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(server_root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_uses_request_snapshot_across_application_publication() {
    let root = std::env::temp_dir().join(format!(
        "hj-request-snapshot-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let before = root.join("before");
    let after = root.join("after");
    std::fs::create_dir_all(&before).unwrap();
    std::fs::create_dir(&after).unwrap();
    std::fs::write(before.join("index.html"), b"before publication").unwrap();
    std::fs::write(after.join("index.html"), b"after publication").unwrap();
    let old = crate::pipeline::e2e::build_state(before);
    let server_root = old.server.server_root.clone();
    let holder = Arc::new(arc_swap::ArcSwap::from(old.clone()));
    let bridge = build_pipeline_bridge(
        holder.clone(),
        "http".into(),
        pipeline_admission(holder.clone()),
    );
    let mut config = (*old.server).clone();
    Arc::make_mut(
        config
            .vhosts
            .get_mut("testvh")
            .unwrap()
            .config
            .as_mut()
            .unwrap(),
    )
    .doc_root = after;
    let next = ServerState::reload(&old, Arc::new(config)).unwrap();
    holder.store(next);
    let make_request = || {
        http::Request::builder()
            .uri("/index.html")
            .header("host", "canon.test")
            .body(hj_core::empty_incoming())
            .unwrap()
    };
    let ctx = BridgeCtx::plain(
        "127.0.0.1:32123".parse().unwrap(),
        "127.0.0.1:8080".parse().unwrap(),
        Proto::Http1,
    );
    let mut pinned_ctx = ctx.clone();
    pinned_ctx.request_generation = Some(RequestGeneration(old));
    let response = bridge.dispatch_response(make_request(), pinned_ctx).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let (body, truncated) = bridge::buffer_body(response.into_body()).await;
    assert!(!truncated);
    assert_eq!(body.as_ref(), b"before publication");
    let response = bridge.dispatch_response(make_request(), ctx).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let (body, truncated) = bridge::buffer_body(response.into_body()).await;
    assert!(!truncated);
    assert_eq!(body.as_ref(), b"after publication");
    drop(bridge);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(server_root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_owner_survives_trust_publication_and_requires_matching_policy() {
    let root = std::env::temp_dir().join(format!(
        "hj-quic-publication-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let base = crate::pipeline::e2e::build_state(root.clone());
    let mut config = (*base.server).clone();
    config.quic_enable = true;
    let initial = ServerState::reload(&base, Arc::new(config)).unwrap();
    let server_root = initial.server.server_root.clone();
    let holder = Arc::new(arc_swap::ArcSwap::from(initial.clone()));
    let bridge = build_pipeline_bridge(
        holder.clone(),
        "http".into(),
        pipeline_admission(holder.clone()),
    );
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let mut initial_tls = (*FixtureTls::new(false).server).clone();
    initial_tls.alpn_protocols = vec![b"h3".to_vec()];
    let (group, handle) = h3::serve_h3_pipeline(
        address,
        1,
        Arc::new(initial_tls),
        bridge,
        false,
        h3::H3RuntimeConfig::new(
            || (h3::H3RequestLimits::new(16_384, 1024), 8),
            initial.metrics.active_conns.clone(),
            initial.body_budget.clone(),
        )
        .with_serving_view(crate::serving_generation::ServingView::new(holder.clone())),
        Some(vec![socket]),
        initial.shutdown.clone(),
    )
    .unwrap();
    let quic =
        crate::resource_generation::QuicResources::new(group, handle.clone(), &initial.trust_epoch)
            .unwrap();
    let coordinator = crate::config_transaction::Coordinator::new(holder.clone()).unwrap();
    coordinator
        .install_initial_resources_with_quic(
            crate::resource_generation::TransportResources::new(
                initial.trust_epoch.clone(),
                Vec::new(),
            )
            .unwrap(),
            Some(quic),
        )
        .unwrap();

    let mut next = ServerState::reload(&initial, initial.server.clone()).unwrap();
    Arc::get_mut(&mut next).unwrap().trust_epoch = Arc::new(());
    let revision = coordinator.revision();
    let rejected = coordinator.begin().await.publish_resources(
        &revision,
        next.clone(),
        crate::resource_generation::TransportResources::new(next.trust_epoch.clone(), Vec::new())
            .unwrap(),
    );
    assert_eq!(
        rejected,
        Err(crate::config_transaction::PublishError::ResourceRequired)
    );
    assert!(Arc::ptr_eq(&holder.load_full(), &initial));

    let transaction = coordinator.begin().await;
    let view = transaction.candidate_view(next.clone()).unwrap();
    let mut replacement_tls = (*FixtureTls::new(false).server).clone();
    replacement_tls.alpn_protocols = vec![b"h3".to_vec()];
    let policy = h3::PreparedQuicPolicy::prepare(view, Arc::new(replacement_tls), true).unwrap();
    let resources =
        crate::resource_generation::TransportResources::new(next.trust_epoch.clone(), Vec::new())
            .unwrap()
            .with_quic_policy(policy)
            .unwrap();
    transaction
        .publish_resources(&revision, next.clone(), resources)
        .unwrap();

    assert!(Arc::ptr_eq(&holder.load_full(), &next));
    let (requires_client, epoch) = handle.test_snapshot();
    assert!(requires_client);
    assert!(Arc::ptr_eq(&epoch.unwrap(), &next.trust_epoch));
    assert!(std::net::UdpSocket::bind(address).is_err());

    coordinator.finish_shutdown();
    let rebound = std::net::UdpSocket::bind(address).unwrap();
    drop(rebound);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(server_root).unwrap();
}

#[tokio::test]
async fn http_only_launch_does_not_require_configured_quic_resource() {
    let root =
        std::env::temp_dir().join(format!("hj-http-only-quic-config-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let base = crate::pipeline::e2e::build_state(root.clone());
    let mut config = (*base.server).clone();
    config.quic_enable = true;
    let state = ServerState::reload(&base, Arc::new(config)).unwrap();
    let holder = Arc::new(arc_swap::ArcSwap::from(state.clone()));
    let coordinator = crate::config_transaction::Coordinator::new(holder)
        .unwrap()
        .with_tcp_launch_policy(crate::listener_plan::TcpLaunchPolicy {
            http: "127.0.0.1:18080".parse().unwrap(),
            https: None,
        });
    coordinator
        .install_initial_resources(
            crate::resource_generation::TransportResources::new(
                state.trust_epoch.clone(),
                Vec::new(),
            )
            .unwrap(),
        )
        .expect("disabled HTTPS means configured QUIC is not an effective resource");
    coordinator.close();
    coordinator.finish_shutdown();
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires python3 with aioquic; synthetic loopback QUIC only"]
async fn live_quic_reload_pins_established_and_updates_fresh_connections() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

    let root = std::env::temp_dir().join(format!(
        "hj-live-quic-reload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let before = root.join("before");
    let after = root.join("after");
    std::fs::create_dir_all(&before).unwrap();
    std::fs::create_dir(&after).unwrap();
    std::fs::write(before.join("index.html"), b"before publication").unwrap();
    std::fs::write(after.join("index.html"), b"after publication").unwrap();
    let initial = crate::pipeline::e2e::build_state(before);
    let server_root = initial.server.server_root.clone();
    let holder = Arc::new(arc_swap::ArcSwap::from(initial.clone()));
    let bridge = build_pipeline_bridge(
        holder.clone(),
        "http".into(),
        pipeline_admission(holder.clone()),
    );
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let (group, handle) = h3::serve_h3_pipeline(
        address,
        1,
        h3::self_signed_config().unwrap(),
        bridge,
        false,
        h3::H3RuntimeConfig::new(
            || (h3::H3RequestLimits::new(16_384, 1024), 8),
            initial.metrics.active_conns.clone(),
            initial.body_budget.clone(),
        )
        .with_serving_view(crate::serving_generation::ServingView::new(holder.clone())),
        Some(vec![socket]),
        initial.shutdown.clone(),
    )
    .unwrap();
    group.activate();

    let mut child = tokio::process::Command::new("python3")
        .arg("-B")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/h3_generation_client.py"
        ))
        .arg(address.port().to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut stdout = tokio::io::BufReader::new(stdout);
    let mut ready = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(8),
        stdout.read_line(&mut ready),
    )
    .await
    .expect("H3 client readiness timeout")
    .unwrap();
    if ready.is_empty() {
        let status = child.wait().await.unwrap();
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .await
            .unwrap();
        panic!("H3 reload client exited before readiness ({status}): {stderr}");
    }
    assert_eq!(ready.trim(), "READY");

    let mut config = (*initial.server).clone();
    Arc::make_mut(
        config
            .vhosts
            .get_mut("testvh")
            .unwrap()
            .config
            .as_mut()
            .unwrap(),
    )
    .doc_root = after;
    let mut next = ServerState::reload(&initial, Arc::new(config)).unwrap();
    Arc::get_mut(&mut next).unwrap().trust_epoch = Arc::new(());
    let policy = h3::PreparedQuicPolicy::prepare(
        crate::serving_generation::ServingView::candidate(holder.clone(), next.clone()),
        h3::self_signed_config().unwrap(),
        false,
    )
    .unwrap();
    holder.store(next);
    handle.publish(policy);
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"\n")
        .await
        .unwrap();
    child.stdin.take();

    let mut output = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stdout.read_to_string(&mut output),
    )
    .await
    .expect("H3 client completion timeout")
    .unwrap();
    let status = child.wait().await.unwrap();
    if !status.success() {
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .await
            .unwrap();
        panic!("H3 reload client failed: {stderr}");
    }
    assert!(output.contains("PASS: established H3 stayed pinned"));

    drop(group);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(server_root).unwrap();
}
