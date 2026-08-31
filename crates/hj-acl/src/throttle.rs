//! Per-client-IP request throttle (audit 2026-08-30 Tier 1.1).
//!
//! LSWS's signature anti-abuse feature and the one protection the transports
//! cannot provide: global admission gates (`maxConnections`, the bridge's
//! in-flight cap) are indifferent to WHO is spending the budget, so a single
//! flood source can starve everyone. This throttle keeps a fixed-window request
//! count per client IP and refuses further requests from an IP once it exceeds
//! the configured rate.
//!
//! Deliberate posture:
//! * **Disabled by default.** Limits are operator opt-in (`<perIpRate>`); a
//!   shared NAT/campus egress IP aggregates many real visitors, and a wrongly
//!   defaulted limit would lock them all out.
//! * **Fail-open on state pressure.** A shard that saturates with distinct IPs
//!   evicts expired windows first; if it is still full, the request is ALLOWED
//!   untracked — an untracked flood degrades fairness, never availability.
//! * **Fixed window.** Cheap and deterministic; the boundary burst (2× rate) is
//!   acceptable for an origin shielded by Cloudflare's edge.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Shard count: lock isolation across cores without per-IP hashing cost beyond
/// one multiply. 64 × 128-entry typical occupancy is a few KB.
const SHARDS: usize = 64;

/// Hard cap on tracked IPs per shard. Bounds memory against a spoofed/distinct-IP
/// flood regardless of window size.
const MAX_IPS_PER_SHARD: usize = 4096;

#[derive(Clone, Copy)]
struct Window {
    start: Instant,
    count: u32,
}

pub struct ClientThrottle {
    rate: u32,
    window: Duration,
    shards: Vec<Mutex<HashMap<IpAddr, Window>>>,
    rejected: AtomicU64,
    allowed: AtomicU64,
}

impl std::fmt::Debug for ClientThrottle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientThrottle")
            .field("rate", &self.rate)
            .field("window", &self.window)
            .finish()
    }
}

impl ClientThrottle {
    /// Disabled throttle: every request is allowed and nothing is tracked.
    pub fn disabled() -> Self {
        Self {
            rate: 0,
            window: Duration::from_secs(1),
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            rejected: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
        }
    }

    /// Build from the server `<tuning>` block. `per_ip_rate == 0` disables.
    pub fn from_tuning(t: &hj_core::config::Tuning) -> Self {
        if t.per_ip_rate == 0 {
            return Self::disabled();
        }
        let mut throttle = Self {
            rate: t.per_ip_rate,
            window: t.per_ip_rate_window,
            ..Self::disabled()
        };
        throttle.rate = t.per_ip_rate;
        throttle.window = t.per_ip_rate_window;
        throttle
    }

    pub fn enabled(&self) -> bool {
        self.rate != 0
    }

    /// Count one request from `ip`; `false` when the IP is over its window rate.
    pub fn allow(&self, ip: IpAddr) -> bool {
        if self.rate == 0 {
            return true;
        }
        let now = Instant::now();
        let shard = &self.shards[shard_of(ip)];
        let mut map = shard.lock();
        if map.len() >= MAX_IPS_PER_SHARD {
            map.retain(|_, w| now.duration_since(w.start) < self.window);
        }
        let Some(w) = map.get_mut(&ip) else {
            if map.len() >= MAX_IPS_PER_SHARD {
                // Still saturated after eviction: allow untracked (fail-open).
                return true;
            }
            map.insert(
                ip,
                Window {
                    start: now,
                    count: 1,
                },
            );
            return true;
        };
        if now.duration_since(w.start) >= self.window {
            *w = Window {
                start: now,
                count: 1,
            };
            return true;
        }
        if w.count >= self.rate {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        w.count += 1;
        self.allowed.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn rejected_total(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    pub fn allowed_total(&self) -> u64 {
        self.allowed.load(Ordering::Relaxed)
    }
}

fn shard_of(ip: IpAddr) -> usize {
    let mut h = 0x9e37_79b9_7f4a_7c15u64;
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            for b in v4.octets() {
                h = (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
            }
        }
        IpAddr::V6(v6) => {
            for b in v6.octets() {
                h = (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
            }
        }
    }
    (h >> 48) as usize % SHARDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn throttle(rate: u32) -> ClientThrottle {
        let mut t = ClientThrottle::disabled();
        t.rate = rate;
        t.window = Duration::from_secs(60);
        t
    }

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
    }

    #[test]
    fn disabled_throttle_allows_everything() {
        let t = ClientThrottle::disabled();
        assert!(!t.enabled());
        for _ in 0..10_000 {
            assert!(t.allow(ip(1)));
        }
        assert_eq!(t.rejected_total(), 0);
    }

    #[test]
    fn rate_is_enforced_per_ip_and_windows_are_independent() {
        let t = throttle(3);
        assert!(t.enabled());
        for _ in 0..3 {
            assert!(t.allow(ip(1)));
        }
        assert!(!t.allow(ip(1)), "over-rate IP is refused");
        assert!(t.allow(ip(2)), "a different IP is unaffected");
        assert_eq!(t.rejected_total(), 1);
    }

    #[test]
    fn v6_and_v4_are_distinct_clients() {
        let t = throttle(1);
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        assert!(t.allow(v4));
        assert!(t.allow(v6));
        assert!(!t.allow(v4));
    }

    #[test]
    fn window_rollover_resets_the_count() {
        let mut t = ClientThrottle::disabled();
        t.rate = 1;
        t.window = Duration::ZERO;
        // ZERO window: every check rolls the window over, so nothing is ever denied.
        assert!(t.allow(ip(3)));
        assert!(t.allow(ip(3)));
    }

    #[test]
    fn saturated_shard_fails_open() {
        let mut t = ClientThrottle::disabled();
        t.rate = 1;
        t.window = Duration::from_secs(60);
        // Saturate every shard's tracked capacity with distinct single-use IPs.
        let cap = SHARDS * MAX_IPS_PER_SHARD;
        for i in 0..cap {
            let v = IpAddr::V4(Ipv4Addr::new(172, (i >> 16) as u8, (i >> 8) as u8, i as u8));
            assert!(t.allow(v));
        }
        // Beyond tracked capacity a NEW IP is still admitted (fail-open: an
        // untracked flood degrades fairness, never availability).
        assert!(t.allow(IpAddr::V4(Ipv4Addr::new(173, 0, 0, 1))));
        // An over-rate REPEAT of a tracked IP is still refused.
        let tracked = IpAddr::V4(Ipv4Addr::new(172, 0, 0, 1));
        assert!(!t.allow(tracked));
        assert_eq!(t.rejected_total(), 1);
    }
}
