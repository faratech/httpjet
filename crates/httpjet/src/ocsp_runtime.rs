//! Explicit OCSP opt-in. Existing XML alone does not initiate responder traffic.
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(clap::Args, Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct OcspArgs {
    /// Explicit HTTP(S) responder for the listener's certificate issuer(s).
    #[arg(long)]
    ocsp_responder: Option<String>,
    /// Refuse new TLS handshakes without a fresh authenticated OCSP response.
    #[arg(long, requires = "ocsp_responder")]
    ocsp_required: bool,
    /// Permit a literal-loopback responder, with loopback serving addresses only.
    #[arg(long, requires = "ocsp_responder")]
    ocsp_test_mode: bool,
}

impl OcspArgs {
    pub(crate) fn enabled(&self) -> bool {
        self.ocsp_responder.is_some()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare(
    args: &OcspArgs,
    http_addr: SocketAddr,
    https_addr: Option<SocketAddr>,
    tcp: &mut Option<Arc<rustls::ServerConfig>>,
    ktls: &mut Option<Arc<hj_tls::KtlsConfigTemplate>>,
    quic: &mut Option<Arc<rustls::ServerConfig>>,
    handles: impl Iterator<Item = hj_tls::CertReloadHandle>,
) -> anyhow::Result<Option<Arc<hj_tls::ocsp::Stapling>>> {
    let Some(endpoint) = &args.ocsp_responder else {
        return Ok(None);
    };
    anyhow::ensure!(
        https_addr.is_some() && tcp.is_some(),
        "OCSP requires an enabled TLS listener"
    );
    if args.ocsp_test_mode {
        anyhow::ensure!(
            http_addr.ip().is_loopback() && https_addr.unwrap().ip().is_loopback(),
            "OCSP test mode requires loopback serving addresses"
        );
    }
    let manager = hj_tls::ocsp::Stapling::new(endpoint, args.ocsp_test_mode, args.ocsp_required)?;
    for config in [tcp, quic].into_iter().filter_map(Option::as_mut) {
        let config = Arc::get_mut(config).ok_or_else(|| {
            anyhow::anyhow!("OCSP must be configured before TLS configs are shared")
        })?;
        hj_tls::ocsp::disable_resumption(config);
    }
    if let Some(template) = ktls {
        Arc::get_mut(template)
            .ok_or_else(|| {
                anyhow::anyhow!("OCSP must be configured before kTLS template is shared")
            })?
            .disable_ocsp_resumption();
    }
    for handle in handles {
        handle.enable_ocsp(manager.clone())?;
    }
    tracing::info!(
        identities = manager.active_identities(),
        required = args.ocsp_required,
        "OCSP manager configured; TLS resumption disabled; responder traffic starts after serving"
    );
    Ok(Some(manager))
}

pub(crate) async fn run(
    manager: Arc<hj_tls::ocsp::Stapling>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    loop {
        tokio::select! { _ = shutdown.cancelled() => return, _ = manager.refresh() => {} }
        tokio::select! { _ = shutdown.cancelled() => return, _ = tokio::time::sleep(Duration::from_secs(1)) => {} }
    }
}

/// Prepared refresh task owned by one resource generation. It stays alive
/// during worker retirement; dropping the owner cancels and aborts the task.
pub(crate) struct RefreshTask {
    activation: tokio_util::sync::CancellationToken,
    shutdown: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl RefreshTask {
    pub(crate) fn prepare(
        manager: Arc<hj_tls::ocsp::Stapling>,
        parent: &tokio_util::sync::CancellationToken,
    ) -> Self {
        Self::prepare_with(parent, move |shutdown| run(manager, shutdown))
    }

    pub(crate) fn prepare_with<F, Fut>(parent: &tokio_util::sync::CancellationToken, run: F) -> Self
    where
        F: FnOnce(tokio_util::sync::CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let activation = tokio_util::sync::CancellationToken::new();
        let shutdown = parent.child_token();
        let gate = activation.clone();
        let stop = shutdown.clone();
        let task = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                _ = gate.cancelled() => {},
            }
            run(stop).await;
        });
        Self {
            activation,
            shutdown,
            task,
        }
    }

    pub(crate) fn is_prepared(&self) -> bool {
        !self.activation.is_cancelled() && !self.shutdown.is_cancelled() && !self.task.is_finished()
    }

    pub(crate) fn activate(&self) {
        self.activation.cancel();
    }
}

impl Drop for RefreshTask {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[tokio::test]
    async fn refresh_waits_for_activation_and_owner_drop_cancels_it() {
        let parent = tokio_util::sync::CancellationToken::new();
        let (started_tx, mut started) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped) = tokio::sync::oneshot::channel();
        struct OnDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let task = RefreshTask::prepare_with(&parent, move |shutdown| async move {
            let _guard = OnDrop(Some(dropped_tx));
            let _ = started_tx.send(());
            shutdown.cancelled().await;
        });
        tokio::task::yield_now().await;
        assert!(task.is_prepared());
        assert!(matches!(
            started.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        task.activate();
        tokio::time::timeout(Duration::from_secs(1), started)
            .await
            .unwrap()
            .unwrap();
        assert!(!task.is_prepared());
        drop(task);
        tokio::time::timeout(Duration::from_secs(1), dropped)
            .await
            .unwrap()
            .unwrap();
        assert!(!parent.is_cancelled());
    }

    #[tokio::test]
    async fn discarded_and_shutdown_candidates_never_start_refresh() {
        for shutdown_first in [false, true] {
            let parent = tokio_util::sync::CancellationToken::new();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let task = RefreshTask::prepare_with(&parent, move |_| async move {
                let _ = tx.send(());
            });
            if shutdown_first {
                parent.cancel();
                task.activate();
            }
            drop(task);
            assert!(
                tokio::time::timeout(Duration::from_secs(1), rx)
                    .await
                    .unwrap()
                    .is_err()
            );
        }
    }
}
