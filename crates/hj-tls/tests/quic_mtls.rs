//! Regression tests for QUIC/HTTP3 mTLS enforcement design.
//!
//! The design: both TCP and QUIC use the *optional* client-cert verifier for
//! `clientVerify=2`. The TLS handshake always completes without a client cert.
//! After the handshake the application layer (TCP: https accept loop via
//! `is_trusted_internal_peer`; QUIC: `hj_http::h3::serve_h3_connection`) refuses
//! any non-loopback / non-private-LAN peer that presented none.
//!
//! These tests pin the handshake-layer behaviour. If someone were to re-introduce
//! a fail-closed verifier path (a removed dead branch), the handshake tests below
//! would fail, making the regression immediately visible.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use hj_config::model::{Listener, ListenerTls, ServerConfig};
use hj_tls::{build_server_config, build_server_config_alpn, install_crypto_provider};

// ── helpers ────────────────────────────────────────────────────────────────

fn gen_cert(names: &[&str]) -> (String, String) {
    let certified =
        rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("generate self-signed cert");
    (certified.cert.pem(), certified.signing_key.serialize_pem())
}

fn write_tmp(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p).expect("create temp file");
    f.write_all(contents.as_bytes()).expect("write temp file");
    p
}

fn tmpdir() -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "hj-tls-quic-mtls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).expect("create tmpdir");
    base
}

fn base_server() -> ServerConfig {
    ServerConfig {
        server_root: PathBuf::from("/tmp"),
        server_name: "test".into(),
        user: "nobody".into(),
        group: "nobody".into(),
        index_files: vec![],
        tuning: Default::default(),
        quic_enable: false,
        use_ip_in_proxy_header: 0,
        expires: Default::default(),
        cache: Default::default(),
        security: Default::default(),
        suexec: Default::default(),
        ext_processors: vec![],
        php_config: None,
        listeners: vec![],
        vhosts: Default::default(),
        vhost_order: vec![],
        mime: Default::default(),
    }
}

/// Drive an in-process TLS handshake against `server_cfg` with a client that
/// trusts the server leaf and presents NO client certificate.
/// Returns `Ok(())` if the handshake completes, `Err` on server-side rejection.
fn handshake_without_client_cert(
    server_cfg: Arc<rustls::ServerConfig>,
    leaf_pem: &str,
) -> Result<(), rustls::Error> {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection};

    let mut roots = RootCertStore::empty();
    let leaf_der = rustls_pemfile::certs(&mut leaf_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    roots.add(leaf_der).unwrap();
    let client_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let name = ServerName::try_from("forum.example").unwrap();
    let mut client = ClientConnection::new(Arc::new(client_cfg), name).unwrap();
    let mut srv = ServerConnection::new(server_cfg).unwrap();

    for _ in 0..16 {
        let mut c2s = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut c2s).unwrap();
        }
        if !c2s.is_empty() {
            let mut sl = &c2s[..];
            while !sl.is_empty() {
                srv.read_tls(&mut sl).unwrap();
            }
            srv.process_new_packets()?;
        }
        let mut s2c = Vec::new();
        while srv.wants_write() {
            srv.write_tls(&mut s2c).unwrap();
        }
        if !s2c.is_empty() {
            let mut sl = &s2c[..];
            while !sl.is_empty() {
                client.read_tls(&mut sl).unwrap();
            }
            let _ = client.process_new_packets();
        }
        if !client.is_handshaking() && !srv.is_handshaking() {
            break;
        }
    }
    if srv.is_handshaking() {
        return Err(rustls::Error::General("handshake did not complete".into()));
    }
    Ok(())
}

// ── tests ──────────────────────────────────────────────────────────────────

/// QUIC `clientVerify=2` must use the optional verifier: a cert-less handshake
/// completes, deferring enforcement to the application layer
/// (`hj_http::h3::serve_h3_connection`). If this fails, someone re-introduced
/// the fail-closed verifier path that was removed as dead code.
#[test]
fn quic_clientverify2_handshake_completes_without_client_cert() {
    install_crypto_provider().expect("install crypto provider");
    let dir = tmpdir();
    let (leaf_pem, key_pem) = gen_cert(&["forum.example"]);
    let cert = write_tmp(&dir, "cert.pem", &leaf_pem);
    let key = write_tmp(&dir, "key.pem", &key_pem);
    let (ca_pem, _) = gen_cert(&["origin-pull-ca.example.com"]);
    let ca_file = write_tmp(&dir, "ca.pem", &ca_pem);

    let server = base_server();
    let listener = Listener {
        name: "TLS".into(),
        address: "*:443".into(),
        secure: true,
        vhost_map: vec![],
        tls: Some(ListenerTls {
            key_file: key,
            cert_file: cert,
            cert_chain: false,
            ca_cert_file: Some(ca_file),
            client_verify: 2,
            verify_depth: 1,
            enable_stapling: false,
        }),
    };

    let cfg = build_server_config_alpn(&server, &listener, vec![b"h3".to_vec()])
        .expect("QUIC clientVerify=2 config must build");

    // Handshake must complete: the optional verifier allows a missing client cert.
    // Rejection of non-internal peers happens post-handshake in h3::serve_h3_connection.
    handshake_without_client_cert(cfg, &leaf_pem)
        .expect("QUIC optional verifier must complete handshake without client cert");
}

/// TCP `clientVerify=2` must also use the optional verifier (same design).
/// Placed here to compare both paths side-by-side and confirm neither regresses.
#[test]
fn tcp_clientverify2_handshake_completes_without_client_cert() {
    install_crypto_provider().expect("install crypto provider");
    let dir = tmpdir();
    let (leaf_pem, key_pem) = gen_cert(&["forum.example"]);
    let cert = write_tmp(&dir, "cert.pem", &leaf_pem);
    let key = write_tmp(&dir, "key.pem", &key_pem);
    let (ca_pem, _) = gen_cert(&["origin-pull-ca.example.com"]);
    let ca_file = write_tmp(&dir, "ca.pem", &ca_pem);

    let server = base_server();
    let listener = Listener {
        name: "TLS".into(),
        address: "*:443".into(),
        secure: true,
        vhost_map: vec![],
        tls: Some(ListenerTls {
            key_file: key,
            cert_file: cert,
            cert_chain: false,
            ca_cert_file: Some(ca_file),
            client_verify: 2,
            verify_depth: 1,
            enable_stapling: false,
        }),
    };

    let cfg =
        build_server_config(&server, &listener).expect("TCP clientVerify=2 config must build");

    handshake_without_client_cert(cfg, &leaf_pem)
        .expect("TCP optional verifier must complete handshake without client cert");
}
