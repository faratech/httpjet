//! Validate a complete issued pair before persistence or resolver replacement.
use crate::{AcmeConfig, Domain, IssuedCertificate, ManagerError};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{ServerName, UnixTime},
    sign::CertifiedKey,
};
use std::{collections::BTreeSet, sync::Arc};
use x509_parser::{extensions::GeneralName, prelude::FromDer};

pub struct CertificateValidator {
    verifier: Arc<WebPkiServerVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

/// Constructible only by strict certificate validation. Certificate and signing
/// key remain an indivisible pair when handed to an SNI resolver.
pub struct ValidatedCertificate {
    pub(crate) key: Arc<CertifiedKey>,
    pub(crate) expires: u64,
}
impl ValidatedCertificate {
    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        self.key.clone()
    }
    pub fn expires_unix(&self) -> u64 {
        self.expires
    }
}

impl CertificateValidator {
    /// Public WebPKI roots by default; an explicit test root replaces them.
    /// The issuance root can differ from the CA HTTPS endpoint's test root.
    pub fn new(test_root: Option<&[u8]>) -> Result<Self, ManagerError> {
        let mut roots = RootCertStore::empty();
        if let Some(pem) = test_root {
            if pem.len() > 64 * 1024 {
                return Err(ManagerError::State);
            }
            for cert in rustls_pemfile::certs(&mut &pem[..]) {
                roots
                    .add(cert.map_err(|_| ManagerError::State)?)
                    .map_err(|_| ManagerError::State)?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|_| ManagerError::State)?;
        Ok(Self { verifier, provider })
    }

    pub fn validate(
        &self,
        issued: &IssuedCertificate,
        config: &AcmeConfig,
    ) -> Result<ValidatedCertificate, ManagerError> {
        if issued.certificate_pem.len() > 64 * 1024 || issued.private_key_pem.len() > 8192 {
            return Err(ManagerError::Crypto);
        }
        let chain = rustls_pemfile::certs(&mut issued.certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ManagerError::Crypto)?;
        if chain.is_empty() || chain.len() > 8 {
            return Err(ManagerError::Crypto);
        }
        let (remaining, leaf) =
            x509_parser::certificate::X509Certificate::from_der(chain[0].as_ref())
                .map_err(|_| ManagerError::Crypto)?;
        if !remaining.is_empty() {
            return Err(ManagerError::Crypto);
        }
        let san = leaf
            .subject_alternative_name()
            .map_err(|_| ManagerError::Crypto)?
            .ok_or(ManagerError::Crypto)?;
        let mut names = BTreeSet::new();
        for name in &san.value.general_names {
            let GeneralName::DNSName(name) = name else {
                return Err(ManagerError::Crypto);
            };
            let domain = if config.is_dns01() {
                Domain::parse_dns01(name)
            } else {
                Domain::parse(name)
            }
            .map_err(|_| ManagerError::Crypto)?;
            if !names.insert(domain) {
                return Err(ManagerError::Crypto);
            }
        }
        if names != *config.domains() {
            return Err(ManagerError::Crypto);
        }
        let expires = u64::try_from(leaf.validity().not_after.timestamp())
            .map_err(|_| ManagerError::Crypto)?;
        let now = UnixTime::now();
        if expires <= now.as_secs() {
            return Err(ManagerError::Crypto);
        }
        for domain in config.domains() {
            let name = ServerName::try_from(domain.verification_name())
                .map_err(|_| ManagerError::Crypto)?;
            self.verifier
                .verify_server_cert(&chain[0], &chain[1..], &name, &[], now)
                .map_err(|_| ManagerError::Crypto)?;
        }
        let private_key = rustls_pemfile::private_key(&mut issued.private_key_pem.as_bytes())
            .map_err(|_| ManagerError::Crypto)?
            .ok_or(ManagerError::Crypto)?;
        let key = CertifiedKey::from_der(chain, private_key, &self.provider)
            .map_err(|_| ManagerError::Crypto)?;
        key.keys_match().map_err(|_| ManagerError::Crypto)?;
        Ok(ValidatedCertificate {
            key: Arc::new(key),
            expires,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Directory;
    #[test]
    fn certificate_requires_trusted_matching_key_and_exact_dns_set() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.test".to_owned()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let config = AcmeConfig::new(
            Directory::parse("https://ca.test/dir", false).unwrap(),
            &["example.test"],
            "/tmp/not-opened".into(),
            true,
        )
        .unwrap();
        let validator = CertificateValidator::new(Some(cert.pem().as_bytes())).unwrap();
        let mut pair = IssuedCertificate {
            certificate_pem: cert.pem(),
            private_key_pem: key.serialize_pem(),
        };
        assert!(validator.validate(&pair, &config).is_ok());
        assert!(
            CertificateValidator::new(None)
                .unwrap()
                .validate(&pair, &config)
                .is_err()
        );
        pair.private_key_pem = rcgen::KeyPair::generate().unwrap().serialize_pem();
        assert!(validator.validate(&pair, &config).is_err());
        pair.private_key_pem = key.serialize_pem();
        let other = AcmeConfig::new(
            Directory::parse("https://ca.test/dir", false).unwrap(),
            &["other.test"],
            "/tmp/not-opened".into(),
            true,
        )
        .unwrap();
        assert!(validator.validate(&pair, &other).is_err());
        let extra = rcgen::CertificateParams::new(vec!["example.test".into(), "extra.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let extra_validator = CertificateValidator::new(Some(extra.pem().as_bytes())).unwrap();
        pair.certificate_pem = extra.pem();
        assert!(extra_validator.validate(&pair, &config).is_err());
        let mut expired = rcgen::CertificateParams::new(vec!["example.test".into()]).unwrap();
        expired.not_before = rcgen::date_time_ymd(2000, 1, 1);
        expired.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let expired = expired.self_signed(&key).unwrap();
        let expired_validator = CertificateValidator::new(Some(expired.pem().as_bytes())).unwrap();
        pair.certificate_pem = expired.pem();
        assert!(expired_validator.validate(&pair, &config).is_err());
    }
}
