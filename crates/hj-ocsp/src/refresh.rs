//! Per-certificate lifecycle; network operations never run on a handshake.
use crate::{Endpoint, Error, Identity, Staple, Verdict};
use parking_lot::Mutex;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub enum Decision {
    Staple(Arc<Staple>),
    Omit,
    Reject,
}
struct State {
    staple: Option<Arc<Staple>>,
    revoked: bool,
    in_flight: bool,
    failures: u8,
    next_attempt: Instant,
}

/// One immutable certificate identity. Certificate replacement needs a new
/// slot; hostname-only or public-key-only reuse is not a valid identity match.
pub struct Slot {
    identity: Arc<Identity>,
    endpoint: Endpoint,
    required: bool,
    jitter: u64,
    state: Mutex<State>,
}
impl Slot {
    pub fn new(
        leaf: &[u8],
        issuer: &[u8],
        endpoint: Endpoint,
        required: bool,
    ) -> Result<Arc<Self>, Error> {
        let identity = Identity::new(leaf, issuer)?;
        let required = required || identity.must_staple;
        let digest = openssl::sha::sha256(leaf);
        let jitter = u64::from_be_bytes(digest[..8].try_into().map_err(|_| Error)?) % 31;
        Ok(Arc::new(Self {
            identity: Arc::new(identity),
            endpoint,
            required,
            jitter,
            state: Mutex::new(State {
                staple: None,
                revoked: false,
                in_flight: false,
                failures: 0,
                next_attempt: Instant::now(),
            }),
        }))
    }
    pub fn decision(&self) -> Decision {
        let state = self.state.lock();
        if state.revoked {
            return Decision::Reject;
        }
        match state.staple.as_ref().filter(|s| s.bytes().is_some()) {
            Some(staple) => Decision::Staple(staple.clone()),
            None if self.required => Decision::Reject,
            None => Decision::Omit,
        }
    }
    pub fn due(&self) -> bool {
        self.due_at(Instant::now())
    }
    fn due_at(&self, now: Instant) -> bool {
        let state = self.state.lock();
        !state.revoked && !state.in_flight && now >= state.next_attempt
    }
    fn begin(self: &Arc<Self>, now: Instant) -> Option<Lease> {
        let mut state = self.state.lock();
        if state.revoked || state.in_flight || now < state.next_attempt {
            return None;
        }
        state.in_flight = true;
        // Schedule BEFORE I/O, including ambiguous/cancelled fetch outcomes.
        let seconds = (30_u64 << state.failures.min(7)).min(3600) + self.jitter;
        state.failures = state.failures.saturating_add(1);
        state.next_attempt = now + Duration::from_secs(seconds);
        Some(Lease(self.clone()))
    }
    fn apply(&self, result: Result<Verdict, Error>, now: Instant) {
        let mut state = self.state.lock();
        if state.revoked {
            return;
        }
        match result {
            Ok(Verdict::Good(staple)) if staple.bytes().is_some() => {
                let remaining = staple.deadline.saturating_duration_since(now).as_secs();
                let wait = (remaining * 2 / 3)
                    .saturating_sub(self.jitter)
                    .clamp(1, 3600);
                state.staple = Some(Arc::new(staple));
                state.failures = 0;
                state.next_attempt = now + Duration::from_secs(wait);
            }
            Ok(Verdict::Revoked) => {
                state.revoked = true;
                state.staple = None;
            }
            // UNKNOWN, bad signatures, HTTP failures and expired candidates do
            // not replace a still-fresh response or extend its deadline.
            _ => {}
        }
    }
}
struct Lease(Arc<Slot>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.state.lock().in_flight = false;
    }
}

/// Share one pool across all active slots: at most four network/validation jobs.
pub struct RefreshPool {
    permits: Arc<tokio::sync::Semaphore>,
}
impl Default for RefreshPool {
    fn default() -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }
}
impl RefreshPool {
    /// Returns false when not due or capacity is occupied. No queued waiters.
    pub async fn refresh(&self, slot: &Arc<Slot>) -> bool {
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            return false;
        };
        let Some(_lease) = slot.begin(Instant::now()) else {
            return false;
        };
        let result = match slot.identity.request() {
            Ok(request) => match slot.endpoint.fetch(&request).await {
                Ok(bytes) => {
                    let identity = slot.identity.clone();
                    // Retain the permit inside a non-cancellable blocking job;
                    // dropping this future cannot start a fifth verifier.
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        identity.validate(&bytes)
                    })
                    .await
                    .unwrap_or(Err(Error))
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        slot.apply(result, Instant::now());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    fn slot(required: bool) -> Arc<Slot> {
        let fixture = crate::tests::fixture();
        Slot::new(
            &fixture.leaf.cert.to_der().unwrap(),
            &fixture.ca.cert.to_der().unwrap(),
            Endpoint::new("http://127.0.0.1:12345/", true).unwrap(),
            required,
        )
        .unwrap()
    }
    fn staple(seconds: u64) -> Staple {
        Staple {
            der: b"synthetic lifecycle state, not a validation fixture".to_vec(),
            expires: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + seconds,
            deadline: Instant::now() + Duration::from_secs(seconds),
        }
    }
    #[test]
    fn optional_required_expiry_and_verified_revocation_are_distinct() {
        let optional = slot(false);
        let required = slot(true);
        assert!(matches!(optional.decision(), Decision::Omit));
        assert!(matches!(required.decision(), Decision::Reject));
        required.apply(Ok(Verdict::Good(staple(60))), Instant::now());
        assert!(matches!(required.decision(), Decision::Staple(_)));
        required.apply(Err(Error), Instant::now());
        required.apply(Ok(Verdict::Unknown), Instant::now());
        assert!(matches!(required.decision(), Decision::Staple(_)));
        required.apply(Ok(Verdict::Revoked), Instant::now());
        required.apply(Ok(Verdict::Good(staple(60))), Instant::now());
        assert!(matches!(required.decision(), Decision::Reject));
        assert!(!required.due_at(Instant::now() + Duration::from_secs(10000)));
        let expired = slot(true);
        expired.state.lock().staple = Some(Arc::new(staple(0)));
        assert!(matches!(expired.decision(), Decision::Reject));
    }
    #[test]
    fn cancellation_releases_slot_but_retains_backoff() {
        let slot = slot(false);
        let now = Instant::now();
        let lease = slot.begin(now).unwrap();
        assert!(slot.begin(now).is_none());
        drop(lease);
        assert!(!slot.due_at(now));
        assert!(slot.due_at(now + Duration::from_secs(61)));
    }
}
