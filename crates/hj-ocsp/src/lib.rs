//! Bounded OCSP validation. TLS remains rustls; this crate authenticates staples.
mod fetch;
mod ffi;
mod refresh;
pub use fetch::Endpoint;
pub use refresh::{Decision, RefreshPool, Slot};

use foreign_types::ForeignTypeRef;
use openssl::{
    asn1::{Asn1GeneralizedTimeRef, Asn1Time, Asn1TimeRef},
    hash::MessageDigest,
    nid::Nid,
    ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspRequest, OcspResponse, OcspResponseStatus},
    stack::Stack,
    x509::{X509, X509VerifyResult, store::X509StoreBuilder, verify::X509VerifyFlags},
};
use std::{
    fmt,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MAX_RESPONSE: usize = 64 * 1024;
const MAX_AGE: u64 = 7 * 86400;
const SKEW: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OCSP input, authorization or freshness rejected")
    }
}
impl std::error::Error for Error {}
impl From<openssl::error::ErrorStack> for Error {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Self
    }
}

/// An authenticated response with immutable wall-clock and monotonic expiry.
/// Construction is private: the resolver must never attach unverified bytes.
pub struct Staple {
    der: Vec<u8>,
    expires: u64,
    deadline: Instant,
}
impl Staple {
    pub fn bytes(&self) -> Option<&[u8]> {
        self.bytes_at(SystemTime::now(), Instant::now())
    }
    pub fn expires_unix(&self) -> u64 {
        self.expires
    }
    fn bytes_at(&self, wall: SystemTime, mono: Instant) -> Option<&[u8]> {
        (wall.duration_since(UNIX_EPOCH).ok()?.as_secs() < self.expires && mono < self.deadline)
            .then_some(self.der.as_slice())
    }
}

/// Non-GOOD outcomes are returned only after signature, identity and time checks.
pub enum Verdict {
    Good(Staple),
    Revoked,
    Unknown,
}

/// Pins the exact leaf and immediate issuer; no AIA or trust-root downloading.
pub struct Identity {
    leaf: X509,
    issuer: X509,
    valid_from: u64,
    valid_until: u64,
    must_staple: bool,
}
impl Identity {
    pub fn new(leaf_der: &[u8], issuer_der: &[u8]) -> Result<Self, Error> {
        if openssl::version::number() < 0x3000_0000
            || leaf_der.is_empty()
            || issuer_der.is_empty()
            || leaf_der.len() > MAX_RESPONSE
            || issuer_der.len() > MAX_RESPONSE
        {
            return Err(Error);
        }
        let leaf = X509::from_der(leaf_der)?;
        let issuer = X509::from_der(issuer_der)?;
        let issuer_key = issuer.public_key()?;
        if leaf.to_der()? != leaf_der
            || issuer.to_der()? != issuer_der
            || !ffi::is_ca(&issuer)
            || issuer.issued(&leaf) != X509VerifyResult::OK
            || !leaf.verify(&issuer_key)?
        {
            return Err(Error);
        }
        let valid_from = unix(leaf.not_before())?.max(unix(issuer.not_before())?);
        let valid_until = unix(leaf.not_after())?.min(unix(issuer.not_after())?);
        if valid_until <= valid_from {
            return Err(Error);
        }
        Ok(Self {
            must_staple: ffi::must_staple(&leaf)?,
            leaf,
            issuer,
            valid_from,
            valid_until,
        })
    }
    fn cert_id(&self) -> Result<OcspCertId, Error> {
        // Current lightweight OCSP profile uses SHA-256 for issuer identity.
        Ok(OcspCertId::from_cert(
            MessageDigest::sha256(),
            &self.leaf,
            &self.issuer,
        )?)
    }
    pub fn request(&self) -> Result<Vec<u8>, Error> {
        let mut request = OcspRequest::new()?;
        request.add_id(self.cert_id()?)?;
        Ok(request.to_der()?)
    }
    pub fn validate(&self, der: &[u8]) -> Result<Verdict, Error> {
        self.validate_at(der, SystemTime::now(), Instant::now())
    }
    fn validate_at(&self, der: &[u8], wall: SystemTime, mono: Instant) -> Result<Verdict, Error> {
        let now = wall
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error)?
            .as_secs();
        if der.is_empty()
            || der.len() > MAX_RESPONSE
            || now < self.valid_from
            || now >= self.valid_until
        {
            return Err(Error);
        }
        let response = OcspResponse::from_der(der)?;
        if response.status() != OcspResponseStatus::SUCCESSFUL || response.to_der()? != der {
            return Err(Error);
        }
        let basic = response.basic()?;
        let (produced, algorithm) = ffi::profile(&basic)?;
        if !matches!(
            algorithm,
            Nid::SHA256WITHRSAENCRYPTION
                | Nid::SHA384WITHRSAENCRYPTION
                | Nid::SHA512WITHRSAENCRYPTION
                | Nid::ECDSA_WITH_SHA256
                | Nid::ECDSA_WITH_SHA384
                | Nid::ECDSA_WITH_SHA512
        ) {
            return Err(Error);
        }
        let mut candidates = Stack::new()?;
        candidates.push(self.issuer.clone())?;
        let mut trust = X509StoreBuilder::new()?;
        trust.add_cert(self.issuer.clone())?;
        trust.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        let mut params = openssl::x509::verify::X509VerifyParam::new()?;
        params.set_time(now.try_into().map_err(|_| Error)?);
        params.set_auth_level(2);
        trust.set_param(&params)?;
        // NO_EXPLICIT prevents unrelated explicitly trusted OCSP roots from
        // substituting for the issuer/delegated-responder authorization check.
        basic.verify(&candidates, &trust.build(), OcspFlag::NO_EXPLICIT)?;
        let id = self.cert_id()?;
        let status = basic.find_status(&id).ok_or(Error)?;
        let this_update = generalized_unix(status.this_update)?;
        let next_update = generalized_unix(status.next_update().ok_or(Error)?)?;
        let produced = generalized_unix(produced)?;
        let expires = next_update
            .min(this_update.saturating_add(MAX_AGE))
            .min(self.valid_until)
            .min(unix(ffi::signer_expiry(&basic, &candidates)?)?);
        if this_update > now.saturating_add(SKEW)
            || now.saturating_sub(this_update) > MAX_AGE
            || produced > now.saturating_add(SKEW)
            || produced.saturating_add(SKEW) < this_update
            || next_update <= this_update
            || expires <= now
        {
            return Err(Error);
        }
        if status.status == OcspCertStatus::REVOKED {
            return Ok(Verdict::Revoked);
        }
        if status.status == OcspCertStatus::UNKNOWN {
            return Ok(Verdict::Unknown);
        }
        if status.status != OcspCertStatus::GOOD {
            return Err(Error);
        }
        Ok(Verdict::Good(Staple {
            der: der.to_vec(),
            expires,
            deadline: mono
                .checked_add(Duration::from_secs(expires - now))
                .ok_or(Error)?,
        }))
    }
}

fn unix(time: &Asn1TimeRef) -> Result<u64, Error> {
    let epoch = Asn1Time::from_unix(0)?;
    let diff = epoch.diff(time)?;
    let seconds = i64::from(diff.days) * 86400 + i64::from(diff.secs);
    seconds.try_into().map_err(|_| Error)
}
fn generalized_unix(time: &Asn1GeneralizedTimeRef) -> Result<u64, Error> {
    // SAFETY: OpenSSL typedefs ASN1_TIME and ASN1_GENERALIZEDTIME to ASN1_STRING;
    // the borrowed pointer stays owned by its response for this conversion.
    unix(unsafe { Asn1TimeRef::from_ptr(time.as_ptr().cast()) })
}

#[cfg(test)]
mod tests;
