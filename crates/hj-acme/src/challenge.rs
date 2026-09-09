use crate::{AcmeConfig, Domain};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

const PREFIX: &str = "/.well-known/acme-challenge/";
const CAPACITY: usize = 128;
const MAX_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeError {
    Identifier,
    Token,
    Thumbprint,
    Expiry,
    Conflict,
    Capacity,
}
impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ACME challenge rejected: {self:?}")
    }
}
impl std::error::Error for ChallengeError {}

type Key = (Domain, String);
struct Entry {
    id: u64,
    expires: Instant,
    body: Arc<str>,
}
struct Inner {
    entries: BTreeMap<Key, Entry>,
    sequence: u64,
}

/// A bounded in-memory HTTP-01 registry; cloning shares the same active orders.
/// Only the future issuer may publish entries; requests never register tokens.
#[derive(Clone)]
pub struct ChallengeRegistry {
    domains: Arc<BTreeSet<Domain>>,
    inner: Arc<Mutex<Inner>>,
}

/// Removing/dropping an order removes its challenge, including cancellation.
/// IDs prevent an expired old lease from deleting a newer entry for the same key.
#[must_use = "dropping the lease removes the active challenge"]
pub struct ChallengeLease {
    key: Key,
    id: u64,
    inner: Weak<Mutex<Inner>>,
}
impl Drop for ChallengeLease {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut state = inner.lock().unwrap_or_else(|e| e.into_inner());
            if state
                .entries
                .get(&self.key)
                .is_some_and(|entry| entry.id == self.id)
            {
                state.entries.remove(&self.key);
            }
        }
    }
}

/// Transport-neutral result. The integration MUST terminate routing on Some,
/// use these headers unchanged, and never insert challenge responses in caches.
pub struct ChallengeResponse {
    pub status: http::StatusCode,
    pub body: Arc<str>,
}
impl ChallengeResponse {
    pub fn headers(&self) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        if self.status == http::StatusCode::METHOD_NOT_ALLOWED {
            headers.insert(http::header::ALLOW, http::HeaderValue::from_static("GET"));
        }
        headers
    }
}

fn base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn valid_token(value: &str) -> bool {
    (22..=256).contains(&value.len()) && base64url(value)
}

impl ChallengeRegistry {
    pub fn new(config: &AcmeConfig) -> Self {
        Self {
            domains: Arc::new(config.domains().clone()),
            inner: Arc::new(Mutex::new(Inner {
                entries: BTreeMap::new(),
                sequence: 0,
            })),
        }
    }
    pub fn register(
        &self,
        domain: &Domain,
        token: &str,
        thumbprint: &str,
        ttl: Duration,
    ) -> Result<ChallengeLease, ChallengeError> {
        self.register_at(domain, token, thumbprint, ttl, Instant::now())
    }
    fn register_at(
        &self,
        domain: &Domain,
        token: &str,
        thumbprint: &str,
        ttl: Duration,
        now: Instant,
    ) -> Result<ChallengeLease, ChallengeError> {
        if !self.domains.contains(domain) {
            return Err(ChallengeError::Identifier);
        }
        if !valid_token(token) {
            return Err(ChallengeError::Token);
        }
        // SHA-256 JWK thumbprint = 32 bytes / 43 unpadded base64url chars.
        // The final sextet has two zero padding bits; reject non-canonical forms.
        if thumbprint.len() != 43
            || !base64url(thumbprint)
            || !b"AEIMQUYcgkosw048".contains(&thumbprint.as_bytes()[42])
        {
            return Err(ChallengeError::Thumbprint);
        }
        if ttl.is_zero() || ttl > MAX_TTL {
            return Err(ChallengeError::Expiry);
        }
        let expires = now.checked_add(ttl).ok_or(ChallengeError::Expiry)?;
        let key = (domain.clone(), token.to_owned());
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.entries.retain(|_, entry| entry.expires > now);
        if state.entries.contains_key(&key) {
            return Err(ChallengeError::Conflict);
        }
        if state.entries.len() >= CAPACITY {
            return Err(ChallengeError::Capacity);
        }
        let id = state
            .sequence
            .checked_add(1)
            .ok_or(ChallengeError::Capacity)?;
        state.sequence = id;
        state.entries.insert(
            key.clone(),
            Entry {
                id,
                expires,
                body: format!("{token}.{thumbprint}").into(),
            },
        );
        Ok(ChallengeLease {
            key,
            id,
            inner: Arc::downgrade(&self.inner),
        })
    }

    /// `physical_tls` is the actual transport, never a forwarded scheme header.
    /// `authority` is the validated request authority, not a wildcard vhost name.
    /// No decoding, dot-segment removal or filesystem lookup occurs here.
    pub fn lookup(
        &self,
        method: &http::Method,
        authority: &str,
        uri: &http::Uri,
        physical_tls: bool,
    ) -> Option<ChallengeResponse> {
        self.lookup_at(method, authority, uri, physical_tls, Instant::now())
    }
    fn lookup_at(
        &self,
        method: &http::Method,
        authority: &str,
        uri: &http::Uri,
        physical_tls: bool,
        now: Instant,
    ) -> Option<ChallengeResponse> {
        if physical_tls || authority.len() > 260 || authority.contains('@') {
            return None;
        }
        let authority: http::uri::Authority = authority.parse().ok()?;
        if authority.as_str().contains(':') && authority.port_u16().is_none() {
            return None;
        }
        let domain = Domain::parse(authority.host()).ok()?;
        if !self.domains.contains(&domain) {
            return None;
        }
        let token = uri.path().strip_prefix(PREFIX)?;
        let empty = |status| {
            Some(ChallengeResponse {
                status,
                body: Arc::from(""),
            })
        };
        if !valid_token(token)
            || uri.query().is_some()
            || uri.authority().is_some()
            || uri.scheme().is_some()
        {
            return empty(http::StatusCode::NOT_FOUND);
        }
        if method != http::Method::GET {
            return empty(http::StatusCode::METHOD_NOT_ALLOWED);
        }
        let key = (domain, token.to_owned());
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .entries
            .get(&key)
            .is_some_and(|entry| entry.expires <= now)
        {
            state.entries.remove(&key);
        }
        let Some(entry) = state.entries.get(&key) else {
            return empty(http::StatusCode::NOT_FOUND);
        };
        Some(ChallengeResponse {
            status: http::StatusCode::OK,
            body: entry.body.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Directory;
    const TOKEN: &str = "0123456789abcdefghijklmnopqrstu";
    const THUMB: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    fn setup() -> (ChallengeRegistry, Domain) {
        let config = AcmeConfig::new(
            Directory::parse("https://ca.test/dir", false).unwrap(),
            &["example.test", "other.test"],
            "/tmp/synthetic-acme".into(),
            true,
        )
        .unwrap();
        (
            ChallengeRegistry::new(&config),
            Domain::parse("example.test").unwrap(),
        )
    }
    fn uri(token: &str) -> http::Uri {
        format!("{PREFIX}{token}").parse().unwrap()
    }
    #[test]
    fn host_scope_exact_path_and_non_cacheable_response() {
        let (registry, domain) = setup();
        let lease = registry.register(&domain, TOKEN, THUMB, MAX_TTL).unwrap();
        let response = registry
            .lookup(&http::Method::GET, "EXAMPLE.TEST.:80", &uri(TOKEN), false)
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(&*response.body, format!("{TOKEN}.{THUMB}"));
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            registry
                .lookup(&http::Method::GET, "other.test", &uri(TOKEN), false)
                .unwrap()
                .status,
            404
        );
        assert!(
            registry
                .lookup(&http::Method::GET, "foreign.test", &uri(TOKEN), false)
                .is_none()
        );
        assert!(
            registry
                .lookup(&http::Method::GET, "example.test", &uri(TOKEN), true)
                .is_none()
        );
        for bad in [
            "x/../../../index.php",
            "../threads",
            "%2e%2e/index.php",
            "x%2f..%2fadmin",
            "index.php",
            "short",
            "abcdefghijklmnopqrstuv?x=1",
            "abcdefghijklmnopqrstuv/",
        ] {
            assert_eq!(
                registry
                    .lookup(&http::Method::GET, "example.test", &uri(bad), false)
                    .unwrap()
                    .status,
                404,
                "{bad}"
            );
        }
        let response = registry
            .lookup(&http::Method::POST, "example.test", &uri(TOKEN), false)
            .unwrap();
        assert_eq!(response.status, 405);
        assert_eq!(response.headers()["allow"], "GET");
        let absolute: http::Uri = format!("http://foreign.test{PREFIX}{TOKEN}")
            .parse()
            .unwrap();
        assert_eq!(
            registry
                .lookup(&http::Method::GET, "example.test", &absolute, false)
                .unwrap()
                .status,
            404
        );
        for authority in [
            "user@example.test",
            "example.test:99999",
            "example.test:bad",
            "example.test.evil",
            "example.test%00",
            "example.test..",
        ] {
            assert!(
                registry
                    .lookup(&http::Method::GET, authority, &uri(TOKEN), false)
                    .is_none(),
                "{authority}"
            );
        }
        drop(lease);
        assert_eq!(
            registry
                .lookup(&http::Method::GET, "example.test", &uri(TOKEN), false)
                .unwrap()
                .status,
            404
        );
    }
    #[test]
    fn invalid_registration_is_rejected() {
        let (registry, domain) = setup();
        assert!(matches!(
            registry.register(
                &Domain::parse("foreign.test").unwrap(),
                TOKEN,
                THUMB,
                MAX_TTL
            ),
            Err(ChallengeError::Identifier)
        ));
        for token in [
            "",
            "short",
            "abcdefghijklmnopqrstuv=",
            "abcdefghijklmnopqrstuv/",
            "abcdefghijklmnopqrstuv.",
        ] {
            assert!(matches!(
                registry.register(&domain, token, THUMB, MAX_TTL),
                Err(ChallengeError::Token)
            ));
        }
        assert!(matches!(
            registry.register(&domain, TOKEN, &format!("{}B", &THUMB[..42]), MAX_TTL),
            Err(ChallengeError::Thumbprint)
        ));
        for ttl in [Duration::ZERO, MAX_TTL + Duration::from_secs(1)] {
            assert!(matches!(
                registry.register(&domain, TOKEN, THUMB, ttl),
                Err(ChallengeError::Expiry)
            ));
        }
    }
    #[test]
    fn expiry_and_old_lease_cannot_remove_new_challenge() {
        let (registry, domain) = setup();
        let now = Instant::now();
        let old = registry
            .register_at(&domain, TOKEN, THUMB, Duration::from_secs(1), now)
            .unwrap();
        assert!(matches!(
            registry.register_at(&domain, TOKEN, THUMB, MAX_TTL, now),
            Err(ChallengeError::Conflict)
        ));
        let later = now + Duration::from_secs(1);
        assert_eq!(
            registry
                .lookup_at(
                    &http::Method::GET,
                    "example.test",
                    &uri(TOKEN),
                    false,
                    later
                )
                .unwrap()
                .status,
            404
        );
        let new = registry
            .register_at(&domain, TOKEN, THUMB, MAX_TTL, later)
            .unwrap();
        drop(old);
        assert_eq!(
            registry
                .lookup_at(
                    &http::Method::GET,
                    "example.test",
                    &uri(TOKEN),
                    false,
                    later
                )
                .unwrap()
                .status,
            200
        );
        drop(new);
    }
    #[test]
    fn registry_capacity_and_raii_cancellation() {
        let (registry, domain) = setup();
        let mut leases = Vec::new();
        for index in 0..CAPACITY {
            leases.push(
                registry
                    .register(&domain, &format!("{TOKEN}{index}"), THUMB, MAX_TTL)
                    .unwrap(),
            );
        }
        assert!(matches!(
            registry.register(&domain, TOKEN, THUMB, MAX_TTL),
            Err(ChallengeError::Capacity)
        ));
        leases.pop();
        let lease = registry.register(&domain, TOKEN, THUMB, MAX_TTL).unwrap();
        drop(leases);
        drop(lease);
        assert!(registry.inner.lock().unwrap().entries.is_empty());
    }
}
