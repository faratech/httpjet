//! Shared publication boundary for configuration writers; serving stays lock-free.
use crate::resource_generation::{QuicResources, ResourceSlots, TransportResources};
use crate::state::ServerState;
use arc_swap::ArcSwap;
use std::{io::Read, sync::Arc};
use tokio::sync::{Mutex, MutexGuard};

#[derive(Default)]
struct Publication {
    closed: bool,
    resources: ResourceSlots,
    quic: Option<QuicResources>,
}

pub(crate) struct Coordinator {
    #[cfg(feature = "acme")]
    acme_targets: Option<crate::acme_runtime::CertificateTargets>,
    #[cfg(feature = "ocsp")]
    ocsp_policy: Option<crate::ocsp_runtime::OcspArgs>,
    tcp_launch_policy: Option<crate::listener_plan::TcpLaunchPolicy>,
    uds_launch_policy: Option<crate::listener_plan::UdsLaunchPolicy>,
    holder: Arc<ArcSwap<ServerState>>,
    incarnation: String,
    writer: Mutex<()>,
    publication: std::sync::Mutex<Publication>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublishError {
    Conflict,
    InvalidGeneration,
    ResourceRequired,
    RetirementBusy,
    Closed,
}

impl Coordinator {
    #[cfg(feature = "acme")]
    pub(crate) fn with_acme_targets(
        mut self,
        targets: Option<crate::acme_runtime::CertificateTargets>,
    ) -> Self {
        self.acme_targets = targets;
        self
    }
    #[cfg(feature = "ocsp")]
    pub(crate) fn with_ocsp_policy(mut self, policy: crate::ocsp_runtime::OcspArgs) -> Self {
        self.ocsp_policy = Some(policy);
        self
    }
    pub(crate) fn with_tcp_launch_policy(
        mut self,
        policy: crate::listener_plan::TcpLaunchPolicy,
    ) -> Self {
        self.tcp_launch_policy = Some(policy);
        self
    }
    pub(crate) fn with_uds_launch_policy(
        mut self,
        policy: crate::listener_plan::UdsLaunchPolicy,
    ) -> Self {
        self.uds_launch_policy = Some(policy);
        self
    }
    pub(crate) fn close(&self) {
        let mut publication = self.publication.lock().expect("publication mutex poisoned");
        publication.closed = true;
        publication.resources.stop();
        if let Some(quic) = &publication.quic {
            quic.stop();
        }
    }

    #[cfg(test)]
    pub(crate) fn install_initial_resources(
        &self,
        resources: TransportResources,
    ) -> Result<(), PublishError> {
        self.install_initial_resources_with_quic(resources, None)
    }

    pub(crate) fn install_initial_resources_with_quic(
        &self,
        resources: TransportResources,
        quic: Option<QuicResources>,
    ) -> Result<(), PublishError> {
        let mut publication = self.publication.lock().expect("publication mutex poisoned");
        if publication.closed {
            return Err(PublishError::Closed);
        }
        // QUIC is effective only when the operator actually launched HTTPS.
        // XML may keep `quicEnable=1` while `--https-addr ""` intentionally
        // runs an HTTP-only test instance; that topology owns no UDP resource.
        let expects_quic = self.tcp_launch_policy.map_or_else(
            || self.holder.load().server.quic_enable,
            |policy| policy.https.is_some() && self.holder.load().server.quic_enable,
        );
        if publication.resources.active.is_some()
            || publication.quic.is_some()
            || !resources.is_prepared_for(&self.holder.load().trust_epoch)
            || resources.has_quic_policy()
            || quic.is_some() != expects_quic
            || cfg!(feature = "acme")
                && self.acme_enabled()
                && resources.certificate_handles().is_empty()
        {
            return Err(PublishError::ResourceRequired);
        }
        #[cfg(feature = "acme")]
        if let Some(targets) = &self.acme_targets {
            targets
                .replace(resources.certificate_handles())
                .map_err(|_| PublishError::ResourceRequired)?;
        }
        publication.quic = quic;
        publication.resources.replace(resources);
        if let Some(quic) = &publication.quic {
            quic.activate();
        }
        Ok(())
    }

    pub(crate) fn reap_retired(&self) -> usize {
        let finished = {
            let mut publication = self.publication.lock().expect("publication mutex poisoned");
            publication.resources.take_finished()
        };
        let count = finished.iter().filter(|owner| owner.is_some()).count();
        drop(finished);
        count
    }

    /// Final synchronous join while the application runtime is still alive.
    /// Unlike periodic reaping this may wait for the worker drain deadline.
    pub(crate) fn finish_shutdown(&self) {
        let resources = {
            let mut publication = self.publication.lock().expect("publication mutex poisoned");
            publication.closed = true;
            publication.resources.stop();
            if let Some(quic) = &publication.quic {
                quic.stop();
            }
            (
                std::mem::take(&mut publication.resources),
                publication.quic.take(),
            )
        };
        drop(resources);
    }

    pub(crate) fn shutdown(&self) -> tokio_util::sync::CancellationToken {
        self.holder.load().shutdown.clone()
    }
    pub(crate) fn revision(&self) -> String {
        format!("{}-{}", self.incarnation, self.holder.load().generation)
    }
    pub(crate) fn new(holder: Arc<ArcSwap<ServerState>>) -> std::io::Result<Self> {
        let mut entropy = [0_u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
        let incarnation = entropy.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            #[cfg(feature = "acme")]
            acme_targets: None,
            #[cfg(feature = "ocsp")]
            ocsp_policy: None,
            tcp_launch_policy: None,
            uds_launch_policy: None,
            holder,
            incarnation,
            writer: Mutex::new(()),
            publication: std::sync::Mutex::new(Publication::default()),
        })
    }

    fn acme_enabled(&self) -> bool {
        #[cfg(feature = "acme")]
        {
            self.acme_targets.is_some()
        }
        #[cfg(not(feature = "acme"))]
        {
            false
        }
    }

    /// A writer owns the boundary through validation/build/publication. Request
    /// readers do not acquire it. The mutable endpoint must bound admission
    /// before waiting here, rather than creating unbounded candidate waiters.
    pub(crate) async fn begin(&self) -> Transaction<'_> {
        let lock = self.writer.lock().await;
        Transaction {
            owner: self,
            current: self.holder.load_full(),
            _lock: lock,
        }
    }
}

pub(crate) struct Transaction<'a> {
    owner: &'a Coordinator,
    pub(crate) current: Arc<ServerState>,
    _lock: MutexGuard<'a, ()>,
}

impl Transaction<'_> {
    /// Resolve current-generation handles under publication ownership, then do
    /// certificate I/O outside that mutex while retaining the writer guard.
    /// This is SIGHUP's certificate-only reload, not an atomic multi-cert commit.
    pub(crate) fn reload_certificates(
        &self,
        server: &hj_core::config::ServerConfig,
    ) -> anyhow::Result<()> {
        let handles = {
            let publication = self
                .owner
                .publication
                .lock()
                .expect("publication mutex poisoned");
            if publication.closed || !Arc::ptr_eq(&self.current, &self.owner.holder.load_full()) {
                anyhow::bail!("certificate reload generation is no longer active");
            }
            let active =
                publication.resources.active.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("active certificate resource owner is missing")
                })?;
            if !Arc::ptr_eq(&active.trust_epoch, &self.current.trust_epoch) {
                anyhow::bail!("certificate resource epoch differs from active state");
            }
            active.certificate_handles()
        };
        let targets = handles
            .iter()
            .map(|(name, handle)| {
                let mut matches = server
                    .listeners
                    .iter()
                    .filter(|l| l.secure && l.name == name.as_ref());
                let listener = matches
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("active certificate listener is missing"))?;
                if matches.next().is_some() {
                    anyhow::bail!("active certificate listener is ambiguous");
                }
                Ok((handle, listener))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        for (handle, listener) in targets {
            handle.reload(server, listener)?;
        }
        Ok(())
    }
    #[allow(dead_code)]
    pub(crate) fn prepare_tcp_tls(
        &self,
        next: Arc<ServerState>,
        bootstrap: bool,
        ktls: bool,
    ) -> anyhow::Result<Option<crate::tcp_candidate::TcpTlsPolicy>> {
        self.candidate_view(next.clone())
            .map_err(|e| anyhow::anyhow!("candidate admission: {e:?}"))?;
        let plan = self
            .tcp_plan(&next.server)
            .map_err(|e| anyhow::anyhow!("candidate plan: {e:?}"))?;
        #[cfg(feature = "ocsp")]
        if self.owner.ocsp_policy.as_ref().is_some_and(|p| p.enabled()) && plan.https.is_none() {
            anyhow::bail!("OCSP launch policy requires candidate HTTPS");
        }
        plan.https
            .map(|target| {
                let tls = crate::tcp_candidate::TcpTlsPolicy::prepare(
                    next.clone(),
                    target.identity,
                    bootstrap,
                    ktls,
                )?;
                #[cfg(feature = "ocsp")]
                let tls = if let Some(policy) = &self.owner.ocsp_policy {
                    tls.with_ocsp(policy, plan.http.address, target.address)?
                } else {
                    tls
                };
                Ok(tls)
            })
            .transpose()
    }
    /// Prepare the TCP portion against one unpublished candidate snapshot.
    /// This does not publish or replace non-TCP resources.
    #[allow(dead_code)]
    pub(crate) fn prepare_tcp_workers(
        &self,
        next: Arc<ServerState>,
        tls: Option<crate::tcp_candidate::TcpTlsPolicy>,
        admission: crate::uring::bridge::BridgeAdmission,
    ) -> anyhow::Result<TransportResources> {
        #[cfg(feature = "ocsp")]
        if !tls.as_ref().map_or_else(
            || !self.owner.ocsp_policy.as_ref().is_some_and(|p| p.enabled()),
            |p| p.matches_ocsp(self.owner.ocsp_policy.as_ref()),
        ) {
            anyhow::bail!("candidate OCSP attachment differs from launch policy");
        }
        let view = self
            .candidate_view(next.clone())
            .map_err(|e| anyhow::anyhow!("candidate admission: {e:?}"))?;
        let plan = self
            .tcp_plan(&next.server)
            .map_err(|e| anyhow::anyhow!("candidate plan: {e:?}"))?;
        let acquired = self
            .acquire_tcp_plan(&next.server)
            .map_err(|e| anyhow::anyhow!("candidate sockets: {e:?}"))?;
        let uds = self
            .acquire_uds()
            .map_err(|e| anyhow::anyhow!("candidate UDS socket: {e:?}"))?;
        crate::tcp_candidate::prepare(acquired, plan, uds, view, tls, admission)
    }

    fn acquire_uds(
        &self,
    ) -> Result<
        Option<(
            crate::listener_plan::UdsLaunchPolicy,
            crate::uring::worker_group::PreparedUdsHandoff,
        )>,
        PublishError,
    > {
        let Some(policy) = self.owner.uds_launch_policy.clone() else {
            return Ok(None);
        };
        let source = {
            let publication = self
                .owner
                .publication
                .lock()
                .expect("publication mutex poisoned");
            if publication.closed {
                return Err(PublishError::Closed);
            }
            if !Arc::ptr_eq(&self.current, &self.owner.holder.load_full()) {
                return Err(PublishError::Conflict);
            }
            if !publication.resources.has_capacity() {
                return Err(PublishError::RetirementBusy);
            }
            let active = publication
                .resources
                .active
                .as_ref()
                .ok_or(PublishError::ResourceRequired)?;
            if !Arc::ptr_eq(&active.trust_epoch, &self.current.trust_epoch) {
                return Err(PublishError::ResourceRequired);
            }
            active
                .uds_handoff_source(&policy.path)
                .map_err(|_| PublishError::ResourceRequired)?
        };
        let prepared = source
            .prepare(&policy.path)
            .map_err(|_| PublishError::ResourceRequired)?;
        Ok(Some((policy, prepared)))
    }
    /// Reconcile all planned TCP endpoints with the current owner. This only
    /// supports handoffs, including renamed listeners. Add/remove transitions
    /// reject before acquisition; lookup failure never falls back to a bind.
    #[allow(dead_code)]
    pub(crate) fn acquire_tcp_plan(
        &self,
        candidate: &hj_core::config::ServerConfig,
    ) -> Result<crate::listener_plan::AcquiredTcpPlan, PublishError> {
        use crate::listener_plan::TcpTransition;
        let plan = self.tcp_plan(candidate)?;
        let previous = self.tcp_plan(&self.current.server)?;
        let changes = plan.transitions_from(&previous);
        if changes
            .iter()
            .any(|change| !matches!(change, TcpTransition::Handoff { .. }))
        {
            return Err(PublishError::ResourceRequired);
        }
        let mut http = None;
        let mut https = None;
        for change in changes {
            let TcpTransition::Handoff {
                source,
                target,
                address,
            } = change
            else {
                unreachable!()
            };
            let acquired = self.tcp_handoff(&source, address)?;
            if target.tls {
                https = Some(acquired);
            } else {
                http = Some(acquired);
            }
        }
        Ok(crate::listener_plan::AcquiredTcpPlan {
            http: http.ok_or(PublishError::ResourceRequired)?,
            https,
        })
    }
    /// Pure planning only. Binding/handoff and full resource admission remain
    /// separate, and the network API still rejects resource-changing requests.
    #[allow(dead_code)]
    pub(crate) fn tcp_plan<'a>(
        &self,
        candidate: &'a hj_core::config::ServerConfig,
    ) -> Result<crate::listener_plan::TcpPlan<'a>, PublishError> {
        self.owner
            .tcp_launch_policy
            .map(|p| p.plan(candidate))
            .ok_or(PublishError::ResourceRequired)
    }
    /// Acquire duplicates from the current owner, not from a fresh bind on the
    /// same address. Selection uses the listener name and TCP/TLS transport kind,
    /// never an incidental position in the startup resource vector.
    #[allow(dead_code)] // Submitted topology mapping is not exposed yet.
    pub(crate) fn tcp_handoff(
        &self,
        identity: &crate::uring::worker_group::TcpListenerId,
        expected_address: std::net::SocketAddr,
    ) -> Result<crate::uring::worker_group::PreparedTcpHandoff, PublishError> {
        let source = {
            let publication = self
                .owner
                .publication
                .lock()
                .expect("publication mutex poisoned");
            if publication.closed {
                return Err(PublishError::Closed);
            }
            if !Arc::ptr_eq(&self.current, &self.owner.holder.load_full()) {
                return Err(PublishError::Conflict);
            }
            if !publication.resources.has_capacity() {
                return Err(PublishError::RetirementBusy);
            }
            let active = publication
                .resources
                .active
                .as_ref()
                .ok_or(PublishError::ResourceRequired)?;
            if !Arc::ptr_eq(&active.trust_epoch, &self.current.trust_epoch) {
                return Err(PublishError::ResourceRequired);
            }
            active
                .tcp_handoff_source(identity)
                .map_err(|_| PublishError::ResourceRequired)?
        };
        source
            .prepare(expected_address)
            .map_err(|_| PublishError::ResourceRequired)
    }
    /// Check resource admission before acquisition. Publication rechecks these
    /// conditions; shutdown may race a candidate's blocking setup work.
    #[allow(dead_code)]
    pub(crate) fn candidate_view(
        &self,
        next: Arc<ServerState>,
    ) -> Result<crate::serving_generation::ServingView, PublishError> {
        let publication = self
            .owner
            .publication
            .lock()
            .expect("publication mutex poisoned");
        if publication.closed {
            return Err(PublishError::Closed);
        }
        if !Arc::ptr_eq(&self.current, &self.owner.holder.load_full()) {
            return Err(PublishError::Conflict);
        }
        if !publication.resources.has_capacity() {
            return Err(PublishError::RetirementBusy);
        }
        if self.current.generation.checked_add(1) != Some(next.generation) {
            return Err(PublishError::InvalidGeneration);
        }
        if Arc::ptr_eq(&self.current.trust_epoch, &next.trust_epoch)
            || publication
                .resources
                .active
                .as_ref()
                .is_none_or(|active| !Arc::ptr_eq(&active.trust_epoch, &self.current.trust_epoch))
        {
            return Err(PublishError::ResourceRequired);
        }
        Ok(crate::serving_generation::ServingView::candidate(
            self.owner.holder.clone(),
            next,
        ))
    }

    pub(crate) fn next_revision(&self) -> String {
        // Called only after ServerState::reload checked generation overflow.
        format!("{}-{}", self.owner.incarnation, self.current.generation + 1)
    }
    pub(crate) fn revision(&self) -> String {
        format!("{}-{}", self.owner.incarnation, self.current.generation)
    }

    /// Check immediately before publication, even if the candidate was built
    /// earlier. The incarnation prevents preconditions surviving a restart.
    pub(crate) fn publish(
        self,
        expected: &str,
        next: Arc<ServerState>,
    ) -> Result<(), PublishError> {
        self.publish_inner(expected, next, None)
    }

    /// Internal resource publication path. Network configuration still rejects
    /// resource changes until candidate acquisition and per-resource gates exist.
    #[allow(dead_code)]
    pub(crate) fn publish_resources(
        self,
        expected: &str,
        next: Arc<ServerState>,
        resources: TransportResources,
    ) -> Result<(), PublishError> {
        self.publish_inner(expected, next, Some(resources))
    }

    fn publish_inner(
        self,
        expected: &str,
        next: Arc<ServerState>,
        mut resources: Option<TransportResources>,
    ) -> Result<(), PublishError> {
        // Serialize shutdown with the complete publication/health transition.
        let mut publication = self
            .owner
            .publication
            .lock()
            .expect("publication mutex poisoned");
        if publication.closed {
            return Err(PublishError::Closed);
        }
        if expected != self.revision()
            || !Arc::ptr_eq(&self.current, &self.owner.holder.load_full())
        {
            return Err(PublishError::Conflict);
        }
        if self.current.generation.checked_add(1) != Some(next.generation) {
            return Err(PublishError::InvalidGeneration);
        }
        // Application-only publication cannot install a new trust epoch without
        // a matching prepared resource bundle and retirement transaction.
        if let Some(resources) = &resources {
            if !resources.is_prepared_for(&next.trust_epoch)
                || self.owner.acme_enabled() && resources.certificate_handles().is_empty()
                || Arc::ptr_eq(&self.current.trust_epoch, &next.trust_epoch)
                || publication.resources.active.as_ref().is_none_or(|active| {
                    !Arc::ptr_eq(&active.trust_epoch, &self.current.trust_epoch)
                })
            {
                return Err(PublishError::ResourceRequired);
            }
            if resources.has_quic_policy() != publication.quic.is_some() {
                return Err(PublishError::ResourceRequired);
            }
            if !publication.resources.has_capacity() {
                return Err(PublishError::RetirementBusy);
            }
        } else if !Arc::ptr_eq(&self.current.trust_epoch, &next.trust_epoch) {
            return Err(PublishError::ResourceRequired);
        }
        #[cfg(feature = "acme")]
        if let (Some(targets), Some(resources)) = (&self.owner.acme_targets, &resources) {
            // Apply the latest managed certificate while the candidate remains
            // unreachable. After this succeeds no fallible operation remains.
            targets
                .replace(resources.certificate_handles())
                .map_err(|_| PublishError::ResourceRequired)?;
        }
        self.owner.holder.store(next.clone());
        if let Some(policy) = resources
            .as_mut()
            .and_then(TransportResources::take_quic_policy)
        {
            publication
                .quic
                .as_ref()
                .expect("QUIC policy presence validated before publication")
                .publish(policy);
        }
        self.current.proxy.pool().stop_health_checks();
        next.proxy.pool().activate_health_checks();
        if let Some(resources) = resources {
            publication.resources.replace(resources);
        }
        Ok(())
    }
}
