use super::*;
use hj_core::config::{LoadBalanceConfig, LoadBalancePolicy};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct GroupKey {
    peers: Vec<PoolKey>,
    config: LoadBalanceConfig,
}
impl GroupKey {
    pub(super) fn new(t: &ProxyTarget, max: u32, keep: Duration, connect: Duration) -> Self {
        Self {
            peers: t
                .peers()
                .iter()
                .map(|p| {
                    PoolKey::new(
                        p,
                        t.max_conns.unwrap_or(max),
                        t.keep_alive.unwrap_or(keep),
                        t.connect_timeout.unwrap_or(connect),
                    )
                })
                .collect(),
            config: t.load_balance.clone(),
        }
    }
    pub(super) fn authenticated(&self) -> bool {
        self.peers.iter().any(PoolKey::has_configured_tls_identity)
    }
}
pub(super) struct Peer {
    pub(super) health: Mutex<super::health::HealthState>,
    pub(super) target: ProxyTarget,
    pub(super) upstream: Arc<Upstream>,
    weight: u16,
    active: AtomicU64,
    selected: AtomicU64,
    failures: AtomicU64,
}
pub(super) struct Group {
    pub(super) peers: Vec<Arc<Peer>>,
    pub(super) config: LoadBalanceConfig,
    currents: Mutex<Vec<i64>>,
}
/// A request, not a reusable connection. Move into the response or relay owner.
pub struct RequestReservation {
    peer: Arc<Peer>,
    successful: bool,
    pub(crate) permit: Option<OwnedSemaphorePermit>,
}
impl RequestReservation {
    pub(crate) fn response_received(&mut self) {
        self.successful = true;
    }
}
impl Drop for RequestReservation {
    fn drop(&mut self) {
        self.peer.active.fetch_sub(1, Ordering::Relaxed);
        if !self.successful {
            self.peer.failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}
#[derive(Debug)]
pub struct PeerSnapshot {
    pub healthy: bool,
    pub probes: u64,
    pub transitions: u64,
    pub scope: String,
    pub group: String,
    pub peer: usize,
    pub active: u64,
    pub selections: u64,
    pub failures: u64,
}
impl Group {
    fn select(&self) -> Option<(Arc<Upstream>, RequestReservation)> {
        let mut current = self.currents.lock();
        let active: Vec<_> = self
            .peers
            .iter()
            .map(|p| p.active.load(Ordering::Relaxed))
            .collect();
        let now = now_epoch_ms();
        let mut candidates: Vec<usize> = self
            .peers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                let bad = p
                    .upstream
                    .bad_until
                    .lock()
                    .as_ref()
                    .map(|v| v.load(Ordering::Relaxed))
                    .unwrap_or(0);
                (bad <= now && p.health.lock().healthy).then_some(i)
            })
            .collect();
        if self.config.policy == LoadBalancePolicy::WeightedLeastActive {
            if let Some(best) = candidates.iter().copied().min_by(|&a, &b| {
                (u128::from(active[a]) * u128::from(self.peers[b].weight))
                    .cmp(&(u128::from(active[b]) * u128::from(self.peers[a].weight)))
            }) {
                let min = active[best];
                let weight = self.peers[best].weight;
                candidates.retain(|&i| {
                    u128::from(active[i]) * u128::from(weight)
                        == u128::from(min) * u128::from(self.peers[i].weight)
                });
            }
        }
        let selected = if self.config.policy == LoadBalancePolicy::PrimaryFirst {
            *candidates.first()?
        } else {
            let mut total = 0i64;
            for &i in &candidates {
                let w = i64::from(self.peers[i].weight);
                current[i] += w;
                total += w;
            }
            let best = candidates
                .into_iter()
                .max_by_key(|&i| (current[i], std::cmp::Reverse(i)))?;
            current[best] -= total;
            best
        };
        let peer = self.peers[selected].clone();
        peer.active.fetch_add(1, Ordering::Relaxed);
        peer.selected.fetch_add(1, Ordering::Relaxed);
        Some((
            peer.upstream.clone(),
            RequestReservation {
                peer,
                successful: false,
                permit: None,
            },
        ))
    }
}
impl UpstreamPool {
    pub(crate) fn select(
        &self,
        target: &ProxyTarget,
        max: u32,
        keep: Duration,
        connect: Duration,
    ) -> Result<(Arc<Upstream>, Option<RequestReservation>), hj_core::HandlerError> {
        // No group allocation or scheduler on the unchanged default path.
        if target.name.is_none() || target.load_balance == LoadBalanceConfig::default() {
            return Ok((self.get_or_create(target, max, keep, connect), None));
        }
        self.group(target, max, keep, connect)
            .select()
            .map(|(up, r)| (up, Some(r)))
            .ok_or(hj_core::HandlerError::ServiceUnavailable)
    }
    pub(super) fn group(
        &self,
        target: &ProxyTarget,
        max: u32,
        keep: Duration,
        connect: Duration,
    ) -> Arc<Group> {
        let key = GroupKey::new(target, max, keep, connect);
        self.groups
            .lock()
            .entry(key)
            .or_insert_with(|| {
                let peers: Vec<_> = target
                    .peers()
                    .into_iter()
                    .enumerate()
                    .map(|(i, mut p)| {
                        p.failover.clear();
                        let upstream = self.get_or_create(&p, max, keep, connect);
                        Arc::new(Peer {
                            health: Mutex::new(super::health::HealthState::new(
                                target.load_balance.health_check.is_none(),
                            )),
                            target: p,
                            upstream,
                            weight: target.load_balance.weights.get(i).copied().unwrap_or(1),
                            active: AtomicU64::new(0),
                            selected: AtomicU64::new(0),
                            failures: AtomicU64::new(0),
                        })
                    })
                    .collect();
                Arc::new(Group {
                    currents: Mutex::new(vec![0; peers.len()]),
                    peers,
                    config: target.load_balance.clone(),
                })
            })
            .clone()
    }
    pub fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        let published = self.published_groups.lock().clone();
        let groups = published.unwrap_or_else(|| self.groups.lock().values().cloned().collect());
        groups
            .iter()
            .flat_map(|g| {
                g.peers.iter().enumerate().map(|(i, p)| {
                    let health = p.health.lock();
                    PeerSnapshot {
                        healthy: health.healthy,
                        probes: health.probes,
                        transitions: health.transitions,
                        scope: p.target.scope.clone().unwrap_or_default(),
                        group: p.target.name.clone().unwrap_or_default(),
                        peer: i,
                        active: p.active.load(Ordering::Relaxed),
                        selections: p.selected.load(Ordering::Relaxed),
                        failures: p.failures.load(Ordering::Relaxed),
                    }
                })
            })
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn target(policy: LoadBalancePolicy) -> ProxyTarget {
        let mut t = ProxyTarget::parse_url("http://127.0.0.1:1")
            .unwrap()
            .in_scope("server");
        t.name = Some("test".into());
        t.failover.push(TargetTransport::Tcp("127.0.0.1:2".into()));
        t.load_balance = LoadBalanceConfig {
            policy,
            weights: vec![2, 1],
            ..Default::default()
        };
        t
    }
    fn select(pool: &UpstreamPool, t: &ProxyTarget) -> (Arc<Upstream>, Option<RequestReservation>) {
        pool.select(t, 10, Duration::from_secs(5), Duration::from_secs(1))
            .unwrap()
    }
    #[test]
    fn weighted_round_robin_and_drop_accounting() {
        let p = UpstreamPool::new();
        let t = target(LoadBalancePolicy::WeightedRoundRobin);
        let mut counts = [0; 2];
        for _ in 0..300 {
            let (up, mut guard) = select(&p, &t);
            counts[usize::from(up.authority.ends_with(":2"))] += 1;
            guard.as_mut().unwrap().response_received();
        }
        assert_eq!(counts, [200, 100]);
        assert!(
            p.peer_snapshots()
                .iter()
                .all(|s| s.active == 0 && s.failures == 0)
        );
    }
    #[test]
    #[ignore = "release-only isolated selector comparison"]
    fn release_default_selection_comparison() {
        assert!(!cfg!(debug_assertions), "run with --release");
        let p = UpstreamPool::new();
        let mut t = target(LoadBalancePolicy::PrimaryFirst);
        t.load_balance = LoadBalanceConfig::default();
        let mut direct = Vec::new();
        let mut selection = Vec::new();
        for round in 0..10 {
            for indirect in [round % 2 == 0, round % 2 != 0] {
                let start = std::time::Instant::now();
                for _ in 0..20_000 {
                    if indirect {
                        std::hint::black_box(select(&p, &t));
                    } else {
                        std::hint::black_box(p.get_or_create(
                            &t,
                            10,
                            Duration::from_secs(5),
                            Duration::from_secs(1),
                        ));
                    }
                }
                let elapsed = start.elapsed().as_nanos();
                if indirect {
                    selection.push(elapsed);
                } else {
                    direct.push(elapsed);
                }
            }
        }
        direct.sort_unstable();
        selection.sort_unstable();
        let ratio = selection[5] as f64 / direct[5] as f64;
        eprintln!(
            "default selector/direct median ratio: {ratio:.3}; selector {} ns/op",
            selection[5] / 20_000
        );
        assert!(
            p.groups.lock().is_empty(),
            "default must allocate no groups"
        );
        // A generous smoke threshold avoids treating host scheduling noise as a benchmark.
        assert!(ratio < 2.0, "unexpected default-path selection overhead");
    }

    #[test]
    fn least_active_counts_retained_requests_and_isolates_scopes() {
        let p = UpstreamPool::new();
        let t = target(LoadBalancePolicy::WeightedLeastActive);
        let (a, ga) = select(&p, &t);
        let (b, gb) = select(&p, &t);
        assert_ne!(a.authority, b.authority);
        let (_, gc) = select(&p, &t);
        assert_eq!(p.peer_snapshots().iter().map(|s| s.active).sum::<u64>(), 3);
        let (_, gd) = select(&p, &t.clone().in_scope("vhost:other"));
        assert_eq!(p.groups.lock().len(), 2);
        drop((ga, gb, gc, gd));
        assert!(p.peer_snapshots().iter().all(|s| s.active == 0));
    }
}
