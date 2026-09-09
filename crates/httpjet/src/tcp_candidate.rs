//! Candidate TCP worker acquisition. Publication belongs to the coordinator.
use crate::{
    listener_plan::{AcquiredTcpPlan, TcpPlan},
    serving_generation::ServingView,
    uring,
};
use std::sync::Arc;

/// Already-prepared TLS policy. Certificate-manager attachment must happen
/// before these configs are shared with candidate workers.
pub(crate) struct TcpTlsPolicy {
    candidate: Arc<crate::state::ServerState>,
    listener: crate::uring::worker_group::TcpListenerId,
    config: Arc<rustls::ServerConfig>,
    quic: Option<Arc<rustls::ServerConfig>>,
    require_client_cert: bool,
    ktls: Option<Arc<hj_tls::KtlsConfigTemplate>>,
    certificates: hj_tls::CertReloadHandle,
    #[cfg(feature = "ocsp")]
    ocsp: Option<Arc<hj_tls::ocsp::Stapling>>,
    #[cfg(feature = "ocsp")]
    ocsp_policy: Option<crate::ocsp_runtime::OcspArgs>,
}

impl TcpTlsPolicy {
    pub(crate) fn prepare(
        candidate: Arc<crate::state::ServerState>,
        identity: crate::uring::worker_group::TcpListenerId,
        bootstrap: bool,
        ktls: bool,
    ) -> anyhow::Result<Self> {
        let mut matches = candidate
            .server
            .listeners
            .iter()
            .filter(|l| l.secure && l.name == identity.name.as_ref());
        let listener = matches
            .next()
            .ok_or_else(|| anyhow::anyhow!("candidate TLS listener is missing"))?;
        if !identity.tls || matches.next().is_some() {
            anyhow::bail!("candidate TLS listener identity is ambiguous");
        }
        let require_client_cert = listener.tls.as_ref().is_some_and(|t| t.client_verify == 2);
        let bundle = hj_tls::PreparedListenerTls::prepare(
            &candidate.server,
            listener,
            bootstrap,
            candidate.server.quic_enable,
            ktls,
        )?;
        Ok(Self {
            candidate,
            listener: identity,
            config: bundle.tcp,
            quic: bundle.quic,
            require_client_cert,
            ktls: bundle.ktls.map(Arc::new),
            certificates: bundle.certificates,
            #[cfg(feature = "ocsp")]
            ocsp: None,
            #[cfg(feature = "ocsp")]
            ocsp_policy: None,
        })
    }

    #[cfg(feature = "ocsp")]
    pub(crate) fn with_ocsp(
        mut self,
        args: &crate::ocsp_runtime::OcspArgs,
        http: std::net::SocketAddr,
        https: std::net::SocketAddr,
    ) -> anyhow::Result<Self> {
        let mut tcp = Some(self.config);
        let mut quic = self.quic;
        self.ocsp = crate::ocsp_runtime::prepare(
            args,
            http,
            Some(https),
            &mut tcp,
            &mut self.ktls,
            &mut quic,
            std::iter::once(self.certificates.clone()),
        )?;
        self.config = tcp.expect("OCSP preparation retains TCP config");
        self.quic = quic;
        self.ocsp_policy = Some(args.clone());
        Ok(self)
    }

    #[cfg(feature = "ocsp")]
    pub(crate) fn matches_ocsp(&self, expected: Option<&crate::ocsp_runtime::OcspArgs>) -> bool {
        match expected.filter(|p| p.enabled()) {
            Some(expected) => self.ocsp.is_some() && self.ocsp_policy.as_ref() == Some(expected),
            None => self.ocsp.is_none(),
        }
    }

    #[allow(dead_code)] // Resource-owned certificate-manager attachment follows.
    pub(crate) fn certificate_handle(&self) -> hj_tls::CertReloadHandle {
        self.certificates.clone()
    }
}

/// Returns only the TCP portion of the candidate. Callers must still acquire
/// all non-TCP resources and validate the complete generation before publishing.
pub(crate) fn prepare(
    acquired: AcquiredTcpPlan,
    plan: TcpPlan<'_>,
    uds: Option<(
        crate::listener_plan::UdsLaunchPolicy,
        crate::uring::worker_group::PreparedUdsHandoff,
    )>,
    view: ServingView,
    tls: Option<TcpTlsPolicy>,
    admission: uring::bridge::BridgeAdmission,
) -> anyhow::Result<crate::resource_generation::TransportResources> {
    let epoch = view.trust_epoch();
    let certificates = tls
        .as_ref()
        .map(|policy| (policy.listener.clone(), policy.certificate_handle()));
    #[cfg(feature = "ocsp")]
    let shutdown = view.load_full().shutdown.clone();
    #[cfg(feature = "ocsp")]
    let ocsp = tls.as_ref().and_then(|policy| policy.ocsp.clone());
    if plan.https.is_some() != acquired.https.is_some() || plan.https.is_some() != tls.is_some() {
        anyhow::bail!("candidate TCP/TLS resources do not match the plan");
    }
    if let (Some(target), Some(policy)) = (&plan.https, &tls) {
        if !Arc::ptr_eq(&policy.candidate, &view.load_full()) || target.identity != policy.listener
        {
            anyhow::bail!("TLS policy belongs to a different candidate or listener");
        }
    }
    let quic_policy = match tls.as_ref() {
        Some(policy) => policy
            .quic
            .clone()
            .map(|config| {
                uring::h3::PreparedQuicPolicy::prepare(
                    view.clone(),
                    config,
                    policy.require_client_cert,
                )
            })
            .transpose()?,
        None => None,
    };
    if quic_policy.is_some() != view.load_full().server.quic_enable {
        anyhow::bail!("candidate QUIC policy does not match configured topology");
    }
    if acquired.http.listeners.is_empty()
        || acquired
            .https
            .as_ref()
            .is_some_and(|h| h.listeners.is_empty())
    {
        // An empty inherited list would trigger the factory's self-bind path.
        anyhow::bail!("candidate TCP handoff has no owned descriptors");
    }
    let mut groups = Vec::with_capacity(2 + usize::from(uds.is_some()));
    let uds_listener_name = plan.http.identity.name.clone();
    let http = uring::spawn_uring_http(
        view.clone(),
        plan.http.identity.name,
        plan.http.address,
        acquired.http.listeners.len(),
        Some(acquired.http.listeners),
        admission.clone(),
        uring::ListenerBinding {
            proxy_protocol: plan.http.listener.is_some_and(|l| l.proxy_protocol),
        },
    )?;
    http.follow_acceptors(acquired.http.predecessor)?;
    groups.push(http);
    if let (Some(target), Some(acquired), Some(tls)) = (plan.https, acquired.https, tls) {
        let https = uring::spawn_uring_https(
            view.clone(),
            target.identity.name,
            target.address,
            acquired.listeners.len(),
            tls.config,
            tls.require_client_cert,
            tls.ktls,
            Some(acquired.listeners),
            admission.clone(),
            uring::ListenerBinding {
                proxy_protocol: target.listener.is_some_and(|l| l.proxy_protocol),
            },
        )?;
        https.follow_acceptors(acquired.predecessor)?;
        groups.push(https);
    }
    if let Some((policy, prepared)) = uds {
        groups.push(uring::spawn_uring_uds(
            view,
            uds_listener_name,
            policy.path,
            Some(uring::UdsListenerInput::Handoff(prepared)),
            admission,
        )?);
    }
    let resources = crate::resource_generation::TransportResources::new(epoch, groups)?;
    let resources = if let Some(policy) = quic_policy {
        resources.with_quic_policy(policy)?
    } else {
        resources
    };
    let resources = if let Some((identity, handle)) = certificates {
        resources.with_certificate(identity, handle)?
    } else {
        resources
    };
    #[cfg(feature = "ocsp")]
    let resources = if let Some(manager) = ocsp {
        resources.with_ocsp(manager, &shutdown)?
    } else {
        resources
    };
    Ok(resources)
}
