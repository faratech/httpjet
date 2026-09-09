use crate::{
    admin_auth::AuthToken,
    admin_protocol::{self, Operation, Request},
    admin_resources::{self, ResourceRoots},
    admin_submission,
    config_transaction::Coordinator,
    state::ServerState,
};
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Semaphore};

pub(crate) struct Control {
    pub(crate) coordinator: Arc<Coordinator>,
    pub(crate) roots: Arc<ResourceRoots>,
    pub(crate) no_mtls: bool,
    pub(crate) per_ip_rate: Option<u32>,
    pub(crate) on_publish: Arc<dyn Fn() + Send + Sync>,
    tcp_replacement: Option<TcpReplacementPolicy>,
    candidates: Arc<Semaphore>,
}

#[derive(Clone)]
pub(crate) struct TcpReplacementPolicy {
    pub(crate) acme_bootstrap: bool,
    pub(crate) ktls: bool,
    pub(crate) admission: crate::uring::bridge::BridgeAdmission,
}

impl Control {
    pub(crate) fn new(
        coordinator: Arc<Coordinator>,
        roots: Arc<ResourceRoots>,
        no_mtls: bool,
        per_ip_rate: Option<u32>,
        on_publish: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            coordinator,
            roots,
            no_mtls,
            per_ip_rate,
            on_publish,
            tcp_replacement: None,
            candidates: Arc::new(Semaphore::new(1)),
        }
    }

    pub(crate) fn with_tcp_replacement(mut self, policy: TcpReplacementPolicy) -> Self {
        self.tcp_replacement = Some(policy);
        self
    }

    #[cfg(test)]
    pub(crate) fn available_candidates(&self) -> usize {
        self.candidates.available_permits()
    }

    pub(crate) async fn execute(&self, request: Request) -> (u16, String) {
        if request.operation == Operation::Revision {
            let revision = self.coordinator.revision();
            return (
                200,
                serde_json::json!({"revision": revision, "persistence": "volatile"}).to_string(),
            );
        }
        let Ok(permit) = self.candidates.clone().try_acquire_owned() else {
            return failure(503, "busy");
        };
        let Ok(transaction) =
            tokio::time::timeout(Duration::from_secs(5), self.coordinator.begin()).await
        else {
            return failure(503, "busy");
        };
        let expected = request.revision.unwrap_or_default();
        if expected != transaction.revision() {
            return failure(412, "revision_conflict");
        }
        let current = transaction.current.clone();
        let roots = self.roots.clone();
        let no_mtls = self.no_mtls;
        let per_ip_rate = self.per_ip_rate;
        let tcp_replacement = self.tcp_replacement.clone();
        let cache_epoch: Arc<str> = Arc::from(expected.as_str());
        let build = tokio::task::spawn_blocking(move || {
            // Keep admission occupied even if the caller times out or disconnects.
            let _permit = permit;
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                let mut cfg = admin_submission::parse(&current.server.server_root, &request.body)
                    .map_err(|_| (400, "invalid_submission"))?;
                crate::apply_no_mtls(&mut cfg, no_mtls);
                if let Some(rate) = per_ip_rate {
                    cfg.tuning.per_ip_rate = rate;
                }
                let replacement = admin_resources::classify_replacement(&current.server, &cfg)
                    .map_err(|_| (409, "restart_required"))?;
                if replacement == admin_resources::ReplacementClass::TcpTrust
                    && tcp_replacement.is_none()
                {
                    return Err((409, "restart_required"));
                }
                roots
                    .validate(&cfg)
                    .map_err(|_| (422, "invalid_resource"))?;
                if replacement == admin_resources::ReplacementClass::TcpTrust {
                    roots
                        .validate_tcp_trust(
                            &cfg,
                            tcp_replacement
                                .as_ref()
                                .is_some_and(|policy| policy.acme_bootstrap),
                        )
                        .map_err(|_| (422, "invalid_resource"))?;
                }
                for decl in cfg.vhosts.values() {
                    let vhost = decl.config.as_deref().ok_or((422, "invalid_config"))?;
                    if vhost.rewrite.enable && !vhost.rewrite.rules.trim().is_empty() {
                        hj_rewrite::RuleSet::parse(&vhost.rewrite.rules)
                            .map_err(|_| (422, "invalid_config"))?;
                    }
                }
                if crate::reload_would_brick_vhosts(&current.server, &cfg).is_some() {
                    return Err((422, "invalid_config"));
                }
                let mut next = ServerState::reload(&current, Arc::new(cfg))
                    .map_err(|_| (422, "invalid_config"))?;
                if next.response_cache_epoch.is_none() {
                    Arc::get_mut(&mut next)
                        .expect("unpublished candidate is uniquely owned")
                        .response_cache_epoch = Some(cache_epoch);
                }
                if replacement == admin_resources::ReplacementClass::TcpTrust {
                    Arc::get_mut(&mut next)
                        .expect("unpublished candidate is uniquely owned")
                        .trust_epoch = Arc::new(());
                }
                Ok((next, replacement))
            })
        });
        let (next, replacement) = match tokio::time::timeout(Duration::from_secs(10), build).await {
            Ok(Ok(Ok(next))) => next,
            Ok(Ok(Err((status, code)))) => return failure(status, code),
            Ok(Err(_)) => return failure(500, "build_failed"),
            Err(_) => return failure(503, "build_timeout"),
        };
        let resources = if replacement == admin_resources::ReplacementClass::TcpTrust {
            let policy = self
                .tcp_replacement
                .as_ref()
                .expect("TCP replacement was admitted only with launch policy");
            let tls =
                match transaction.prepare_tcp_tls(next.clone(), policy.acme_bootstrap, policy.ktls)
                {
                    Ok(tls) => tls,
                    Err(_) => return failure(409, "restart_required"),
                };
            match transaction.prepare_tcp_workers(next.clone(), tls, policy.admission.clone()) {
                Ok(resources) => Some(resources),
                Err(_) => return failure(409, "restart_required"),
            }
        } else {
            None
        };
        if request.operation == Operation::Validate {
            return (200, serde_json::json!({"revision": expected, "valid": true, "published": false, "persistence": "volatile"}).to_string());
        }
        let revision = transaction.next_revision();
        let published = if let Some(resources) = resources {
            transaction.publish_resources(&expected, next, resources)
        } else {
            transaction.publish(&expected, next)
        };
        if let Err(error) = published {
            return match error {
                crate::config_transaction::PublishError::Closed => failure(503, "shutting_down"),
                crate::config_transaction::PublishError::RetirementBusy => {
                    failure(503, "retirement_busy")
                }
                crate::config_transaction::PublishError::ResourceRequired => {
                    failure(409, "restart_required")
                }
                _ => failure(412, "revision_conflict"),
            };
        }
        (self.on_publish)();
        (
            200,
            serde_json::json!({"revision": revision, "published": true, "persistence": "volatile"})
                .to_string(),
        )
    }
}

fn failure(status: u16, code: &'static str) -> (u16, String) {
    (status, serde_json::json!({"error": code}).to_string())
}

pub(crate) async fn serve(listener: TcpListener, auth: Arc<AuthToken>, control: Arc<Control>) {
    let Ok(local) = listener.local_addr() else {
        return;
    };
    if !local.ip().is_loopback() {
        return;
    }
    let mut tasks = tokio::task::JoinSet::new();
    let shutdown = control.coordinator.shutdown();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept(), if tasks.len() < 4 => {
                let Ok((mut stream, peer)) = accepted else { break; };
                if !peer.ip().is_loopback() { continue; }
                let auth = auth.clone();
                let control = control.clone();
                tasks.spawn(async move {
                    let (status, body) = match admin_protocol::receive(&mut stream, local, &auth).await {
                        Ok(request) => control.execute(request).await,
                        Err(status) => failure(status, "invalid_request"),
                    };
                    tracing::info!(status, revision = %control.coordinator.revision(), "configuration control request completed");
                    // Publication is final even if the response connection disappears.
                    // The client can resolve an uncertain result via GET /v1/revision.
                    let _ = tokio::time::timeout(Duration::from_secs(5), async {
                        let head = format!("HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        stream.write_all(head.as_bytes()).await?;
                        stream.write_all(body.as_bytes()).await?;
                        stream.shutdown().await
                    }).await;
                });
            }
        }
    }
}
