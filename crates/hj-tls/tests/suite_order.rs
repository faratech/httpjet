#[test]
fn provider_prefers_aes128_sha256() {
    hj_tls::install_crypto_provider().unwrap();
    let p = rustls::crypto::CryptoProvider::get_default().unwrap();
    let first = p
        .cipher_suites
        .iter()
        .find(|s| matches!(s, rustls::SupportedCipherSuite::Tls13(_)))
        .unwrap();
    eprintln!("first tls13 suite: {:?}", first.suite());
    assert_eq!(first.suite(), rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    assert!(
        !p.cipher_suites
            .iter()
            .any(|s| s.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384),
        "AES_256_GCM_SHA384 must be excluded (client-preference negotiation would pick it)"
    );
}
