//! Opt-in durable ACME HTTP-01 issuance, recovery and certificate validation.
//! Configuration/registry construction is inert; opening a manager provisions
//! private local state, and only `AcmeManager::issue` contacts the configured CA.
mod certificate;
mod challenge;
mod config;
mod dns;
mod manager;
mod storage;
mod transport;

pub use certificate::{CertificateValidator, ValidatedCertificate};
pub use challenge::{ChallengeError, ChallengeLease, ChallengeRegistry, ChallengeResponse};
pub use config::{AcmeConfig, ConfigError, Directory, Domain};
pub use dns::{DnsError, DnsProvider, DnsRecord, DnsScope, WebhookDnsProvider};
pub use manager::{AcmeManager, IssuedCertificate, ManagerError};
pub use storage::PrivateStore;
