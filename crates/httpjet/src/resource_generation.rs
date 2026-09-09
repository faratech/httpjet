//! Bounded ownership of active and retiring transport generations.
use crate::uring::WorkerGroup;
use std::sync::Arc;

pub(crate) const MAX_RETIRING_GENERATIONS: usize = 2;

#[derive(Debug)]
pub(crate) struct ResourceOwnershipError;
impl std::fmt::Display for ResourceOwnershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("transport resources must be inactive, own the candidate trust epoch, and have unique TCP and UDS listener identities")
    }
}
impl std::error::Error for ResourceOwnershipError {}

pub(crate) struct TransportResources {
    pub(crate) trust_epoch: Arc<()>,
    groups: Vec<WorkerGroup>,
    certificates: std::collections::BTreeMap<Arc<str>, hj_tls::CertReloadHandle>,
    quic_policy: Option<crate::uring::h3::PreparedQuicPolicy>,
    // Declared after workers so shutdown joins their drain before releasing
    // certificate refresh ownership. Retirement stop() intentionally preserves it.
    #[cfg(feature = "ocsp")]
    ocsp: Option<crate::ocsp_runtime::RefreshTask>,
}

/// Process-lifetime ownership of the bound UDP endpoints. Trust publications
/// update their accept policy in place; restarting SO_REUSEPORT QUIC workers
/// would strand established connection IDs on the wrong endpoint.
pub(crate) struct QuicResources {
    group: WorkerGroup,
    policy: crate::uring::h3::QuicReloadHandle,
}

impl QuicResources {
    pub(crate) fn new(
        group: WorkerGroup,
        policy: crate::uring::h3::QuicReloadHandle,
        epoch: &Arc<()>,
    ) -> Result<Self, ResourceOwnershipError> {
        if !group.is_prepared_for(epoch) {
            group.stop();
            return Err(ResourceOwnershipError);
        }
        Ok(Self { group, policy })
    }

    pub(crate) fn activate(&self) {
        self.group.activate();
    }

    pub(crate) fn stop(&self) {
        self.group.stop();
    }

    pub(crate) fn publish(&self, policy: crate::uring::h3::PreparedQuicPolicy) {
        self.policy.publish(policy);
    }
}

impl TransportResources {
    pub(crate) fn with_quic_policy(
        mut self,
        policy: crate::uring::h3::PreparedQuicPolicy,
    ) -> Result<Self, ResourceOwnershipError> {
        if self.quic_policy.is_some() || !policy.is_prepared_for(&self.trust_epoch) {
            return Err(ResourceOwnershipError);
        }
        self.quic_policy = Some(policy);
        Ok(self)
    }

    pub(crate) fn has_quic_policy(&self) -> bool {
        self.quic_policy.is_some()
    }

    pub(crate) fn take_quic_policy(&mut self) -> Option<crate::uring::h3::PreparedQuicPolicy> {
        self.quic_policy.take()
    }

    pub(crate) fn with_certificate(
        mut self,
        identity: crate::uring::worker_group::TcpListenerId,
        handle: hj_tls::CertReloadHandle,
    ) -> Result<Self, ResourceOwnershipError> {
        if !identity.tls
            || !self.is_prepared_for(&self.trust_epoch)
            || self.certificates.contains_key(&identity.name)
            || !self
                .groups
                .iter()
                .any(|group| group.tcp_identity() == Some(&identity))
        {
            return Err(ResourceOwnershipError);
        }
        self.certificates.insert(identity.name, handle);
        Ok(self)
    }

    pub(crate) fn certificate_handles(&self) -> Vec<(Arc<str>, hj_tls::CertReloadHandle)> {
        self.certificates
            .iter()
            .map(|(name, handle)| (name.clone(), handle.clone()))
            .collect()
    }
    #[cfg(all(test, feature = "ocsp"))]
    pub(crate) fn has_ocsp_refresh(&self) -> bool {
        self.ocsp.is_some()
    }
    #[cfg(test)]
    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }
    #[cfg(feature = "ocsp")]
    pub(crate) fn with_ocsp(
        mut self,
        manager: Arc<hj_tls::ocsp::Stapling>,
        shutdown: &tokio_util::sync::CancellationToken,
    ) -> Result<Self, ResourceOwnershipError> {
        if !self.is_prepared_for(&self.trust_epoch)
            || self.ocsp.is_some()
            || shutdown.is_cancelled()
        {
            return Err(ResourceOwnershipError);
        }
        self.ocsp = Some(crate::ocsp_runtime::RefreshTask::prepare(manager, shutdown));
        Ok(self)
    }
    pub(crate) fn tcp_handoff_source(
        &self,
        identity: &crate::uring::worker_group::TcpListenerId,
    ) -> std::io::Result<crate::uring::worker_group::TcpHandoffSource> {
        self.groups
            .iter()
            .find(|group| group.tcp_identity() == Some(identity))
            .ok_or_else(|| std::io::Error::other("unknown TCP listener identity"))?
            .tcp_handoff_source()
    }
    pub(crate) fn uds_handoff_source(
        &self,
        path: &std::path::Path,
    ) -> std::io::Result<crate::uring::worker_group::UdsHandoffSource> {
        self.groups
            .iter()
            .find(|group| group.uds_identity() == Some(path))
            .ok_or_else(|| std::io::Error::other("unknown UDS listener identity"))?
            .uds_handoff_source()
    }
    pub(crate) fn new(
        trust_epoch: Arc<()>,
        groups: Vec<WorkerGroup>,
    ) -> Result<Self, ResourceOwnershipError> {
        let mut identities = std::collections::HashSet::new();
        let mut uds_identities = std::collections::HashSet::new();
        if groups.iter().any(|group| {
            !group.is_prepared_for(&trust_epoch)
                || group
                    .tcp_identity()
                    .is_some_and(|identity| !identities.insert(identity))
                || group
                    .uds_identity()
                    .is_some_and(|identity| !uds_identities.insert(identity.to_path_buf()))
        }) {
            for group in &groups {
                group.stop();
            }
            return Err(ResourceOwnershipError);
        }
        Ok(Self {
            trust_epoch,
            groups,
            certificates: Default::default(),
            quic_policy: None,
            #[cfg(feature = "ocsp")]
            ocsp: None,
        })
    }

    pub(crate) fn activate(&self) {
        #[cfg(feature = "ocsp")]
        if let Some(task) = &self.ocsp {
            task.activate();
        }
        for group in &self.groups {
            group.activate();
        }
    }

    pub(crate) fn is_prepared_for(&self, epoch: &Arc<()>) -> bool {
        #[cfg(feature = "ocsp")]
        if self.ocsp.as_ref().is_some_and(|task| !task.is_prepared()) {
            return false;
        }
        Arc::ptr_eq(&self.trust_epoch, epoch)
            && self.groups.iter().all(|group| group.is_prepared_for(epoch))
    }

    pub(crate) fn stop(&self) {
        for group in &self.groups {
            group.stop();
        }
    }

    fn is_finished(&self) -> bool {
        self.groups.iter().all(WorkerGroup::is_finished)
    }
}

impl Drop for TransportResources {
    fn drop(&mut self) {
        // Signal every group before joining any: drain windows overlap rather
        // than serially delaying cancellation of later transport families.
        self.stop();
    }
}

pub(crate) struct ResourceSlots {
    pub(crate) active: Option<TransportResources>,
    retired: [Option<TransportResources>; MAX_RETIRING_GENERATIONS],
}

impl Default for ResourceSlots {
    fn default() -> Self {
        Self {
            active: None,
            retired: std::array::from_fn(|_| None),
        }
    }
}

impl ResourceSlots {
    pub(crate) fn has_capacity(&self) -> bool {
        self.active.is_none() || self.retired.iter().any(Option::is_none)
    }

    /// Requires an already checked free retirement slot. Only moves owners and
    /// signals workers; no join, bind, allocation or thread creation occurs.
    pub(crate) fn replace(&mut self, next: TransportResources) {
        let slot = if self.active.is_some() {
            Some(
                self.retired
                    .iter_mut()
                    .find(|slot| slot.is_none())
                    .expect("retirement capacity checked before publication"),
            )
        } else {
            None
        };
        if let Some(old) = self.active.replace(next) {
            old.stop();
            *slot.expect("active resource set has a retirement slot") = Some(old);
        }
        self.active.as_ref().unwrap().activate();
    }

    /// Move only finished owners out. The caller drops/joins them AFTER releasing
    /// its publication mutex. An uninterruptible worker keeps its slot occupied.
    pub(crate) fn take_finished(
        &mut self,
    ) -> [Option<TransportResources>; MAX_RETIRING_GENERATIONS] {
        std::array::from_fn(|i| {
            if self.retired[i]
                .as_ref()
                .is_some_and(TransportResources::is_finished)
            {
                self.retired[i].take()
            } else {
                None
            }
        })
    }

    pub(crate) fn stop(&self) {
        if let Some(active) = &self.active {
            active.stop();
        }
        for retired in self.retired.iter().flatten() {
            retired.stop();
        }
    }
}

impl Drop for ResourceSlots {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uring::worker_group::TcpListenerId;

    #[cfg(feature = "ocsp")]
    #[tokio::test]
    async fn retiring_workers_keep_refresh_until_generation_owner_is_dropped() {
        let parent = tokio_util::sync::CancellationToken::new();
        let epoch = Arc::new(());
        let mut resources = TransportResources::new(epoch.clone(), Vec::new()).unwrap();
        let (started_tx, started) = tokio::sync::oneshot::channel();
        let (dropped_tx, mut dropped) = tokio::sync::oneshot::channel();
        struct OnDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        resources.ocsp = Some(crate::ocsp_runtime::RefreshTask::prepare_with(
            &parent,
            move |_| async move {
                let _guard = OnDrop(Some(dropped_tx));
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            },
        ));
        assert!(resources.is_prepared_for(&epoch));
        resources.activate();
        tokio::time::timeout(std::time::Duration::from_secs(1), started)
            .await
            .unwrap()
            .unwrap();
        resources.stop();
        tokio::task::yield_now().await;
        assert!(matches!(
            dropped.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        drop(resources);
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped)
            .await
            .unwrap()
            .unwrap();
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn tcp_identity_selection_is_order_independent_and_transport_scoped() {
        let parent = tokio_util::sync::CancellationToken::new();
        let epoch = Arc::new(());
        let mut owners = Vec::new();
        let mut groups = Vec::new();
        let mut expected = Vec::new();
        for (name, tls) in [("shared", true), ("other", false), ("shared", false)] {
            let identity = TcpListenerId {
                name: name.into(),
                tls,
            };
            let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let mut group = WorkerGroup::for_tcp_epoch(&parent, epoch.clone(), identity.clone());
            owners.push(group.register_acceptor(&socket).unwrap());
            expected.push((identity, socket.local_addr().unwrap()));
            groups.push(group);
        }
        let resources = TransportResources::new(epoch, groups).unwrap();
        resources.activate();
        for (identity, address) in expected.into_iter().rev() {
            let handoff = resources
                .tcp_handoff_source(&identity)
                .unwrap()
                .prepare(address)
                .unwrap();
            assert_eq!(handoff.listeners.len(), 1);
            assert_eq!(handoff.listeners[0].local_addr().unwrap(), address);
        }
        assert!(
            resources
                .tcp_handoff_source(&TcpListenerId {
                    name: "missing".into(),
                    tls: false,
                })
                .is_err()
        );
        drop(resources);
        drop(owners);
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn duplicate_tcp_identities_reject_the_entire_candidate() {
        let parent = tokio_util::sync::CancellationToken::new();
        let epoch = Arc::new(());
        let identity = TcpListenerId {
            name: "http".into(),
            tls: false,
        };
        let groups = (0..2)
            .map(|_| WorkerGroup::for_tcp_epoch(&parent, epoch.clone(), identity.clone()))
            .collect();
        assert!(TransportResources::new(epoch, groups).is_err());
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn resource_sets_reject_untagged_mismatched_and_active_workers() {
        let parent = tokio_util::sync::CancellationToken::new();
        let epoch = Arc::new(());
        assert!(TransportResources::new(epoch.clone(), vec![WorkerGroup::new(&parent)]).is_err());
        assert!(
            TransportResources::new(
                epoch.clone(),
                vec![WorkerGroup::for_epoch(&parent, Arc::new(()))]
            )
            .is_err()
        );
        let active = WorkerGroup::for_epoch(&parent, epoch.clone());
        active.activate();
        assert!(TransportResources::new(epoch.clone(), vec![active]).is_err());
        let cancelled = WorkerGroup::for_epoch(&parent, epoch.clone());
        cancelled.stop();
        assert!(TransportResources::new(epoch.clone(), vec![cancelled]).is_err());
        let prepared = WorkerGroup::for_epoch(&parent, epoch.clone());
        assert!(TransportResources::new(epoch, vec![prepared]).is_ok());
        let uds_epoch = Arc::new(());
        let unregistered_uds = WorkerGroup::for_uds_epoch(
            &parent,
            uds_epoch.clone(),
            "/tmp/unregistered-httpjet.sock".into(),
        );
        assert!(TransportResources::new(uds_epoch, vec![unregistered_uds]).is_err());
        assert!(!parent.is_cancelled());
    }
}
