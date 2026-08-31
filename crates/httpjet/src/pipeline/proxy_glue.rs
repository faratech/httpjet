//! Proxy-stage glue: reverse-proxy a request (or surface a 5xx), relay a
//! WebSocket upgrade, and resolve a proxy `<context>` to its [`ProxyTarget`].

use std::sync::Arc;

use async_trait::async_trait;
use hj_core::{Handler, HandlerError, ReqCtx, Request, Response};
use hj_proxy::{Proxy, ProxyTarget};
use http::StatusCode;

use crate::state::ServerState;
use crate::uring::bridge::{UringUpgradeIo, UringUpgradeRequest};

use super::error_page;

/// Terminal [`Handler`] for a resolved reverse-proxy target. Binds the
/// [`ProxyTarget`] (which `Handler::handle` cannot carry as an argument) so proxy
/// contexts flow through the same `run_handler` path as the static + LSAPI
/// terminals. A proxy fault renders the error page in-place — keeping the
/// upstream-authority correlation log the generic `run_handler` 5xx line lacks —
/// so `handle` never surfaces `Err`.
pub(super) struct ProxyHandler {
    pub telemetry: Arc<crate::telemetry::Telemetry>,
    pub response_timeout_override: Option<u64>,
    pub proxy: Arc<Proxy>,
    pub target: ProxyTarget,
}

#[async_trait]
impl Handler for ProxyHandler {
    async fn handle(&self, ctx: &mut ReqCtx, req: Request) -> Result<Response, HandlerError> {
        // Capture before `forward` consumes `req`, for the 5xx-with-cause log.
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        // (Tier 1.5) Upstream forward latency: checkout through response head — the
        // reverse-proxy's one observable so backend degradation is visible in metrics.
        let upstream_t0 = std::time::Instant::now();
        match self
            .proxy
            .forward(ctx, req, &self.target, self.response_timeout_override)
            .await
        {
            Ok(resp) => {
                self.telemetry
                    .shard()
                    .phase_upstream
                    .record(upstream_t0.elapsed());
                Ok(resp)
            }
            Err(e) => {
                let status = e.status();
                // (item 4) Proxy faults are 502/503/504 — always server errors; correlate.
                tracing::warn!(
                    vhost = %ctx.vhost_name, method = %method, path = %path,
                    upstream = %self.target.authority, status = status.as_u16(), cause = %e,
                    "proxy 5xx"
                );
                Ok(error_page(status))
            }
        }
    }
}

/// Proxy a WebSocket upgrade: open the upstream, relay the 101, then bridge the
/// two upgraded streams.
pub(super) async fn proxy_websocket(
    state: &ServerState,
    ctx: &ReqCtx,
    mut req: Request,
    target: ProxyTarget,
) -> Response {
    let uring_upgrade = req.extensions_mut().remove::<UringUpgradeRequest>();
    let client_on_upgrade = uring_upgrade
        .is_none()
        .then(|| hyper::upgrade::on(&mut req));

    let upgrade = match state.proxy.proxy_websocket(ctx, req, &target).await {
        Ok(u) => u,
        Err(e) => {
            // Backend down on a WS upgrade → genuine fault (item 3).
            tracing::warn!(error = %e, "websocket upstream error");
            return error_page(e.status());
        }
    };
    if !upgrade.is_switching() {
        // Upstream refused the upgrade; relay its response to the client.
        return upgrade.response;
    }

    let upstream_io = match upgrade.upstream.into_io() {
        Some(io) => io,
        None => return error_page(StatusCode::BAD_GATEWAY),
    };
    let resp = upgrade.response;

    if let Some(handoff) = uring_upgrade {
        let io = start_uring_upgrade_relay(hyper_util::rt::TokioIo::new(upstream_io));
        if handoff.handoff(io).await.is_err() {
            return error_page(StatusCode::BAD_GATEWAY);
        }
        return resp;
    }

    // After we return `resp` (101), hyper upgrades the client connection; the
    // future resolves with the client IO, which we bridge to the upstream.
    tokio::spawn(async move {
        match client_on_upgrade
            .expect("hyper upgrade future present")
            .await
        {
            Ok(client_upgraded) => {
                let client_io = hyper_util::rt::TokioIo::new(client_upgraded);
                if let Err(e) = hj_proxy::Proxy::relay_upgraded(client_io, upstream_io).await {
                    tracing::debug!(error = %e, "websocket relay ended");
                }
            }
            Err(e) => tracing::debug!(error = %e, "client upgrade failed"),
        }
    });
    resp
}

fn start_uring_upgrade_relay<U>(upstream: U) -> UringUpgradeIo
where
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (to_upstream, mut downstream_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(8);
    let (upstream_tx, from_upstream) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, ()>>(8);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(upstream);
        let downstream_to_upstream = async {
            while let Some(bytes) = downstream_rx.recv().await {
                if writer.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        };
        let upstream_to_downstream = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if upstream_tx
                            .send(Ok(bytes::Bytes::copy_from_slice(&buf[..n])))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = upstream_tx.send(Err(())).await;
                        break;
                    }
                }
            }
        };
        tokio::select! {
            _ = downstream_to_upstream => {}
            _ = upstream_to_downstream => {}
        }
    });
    UringUpgradeIo {
        to_upstream,
        from_upstream,
    }
}

/// The longest-matching enabled proxy context for `path`, returning its handler.
pub(super) fn matching_proxy_context(ctx: &ReqCtx, path: &str) -> Option<String> {
    use hj_core::config::ContextKind;
    ctx.vhost
        .contexts
        .iter()
        .filter(|c| {
            c.kind == ContextKind::Proxy && c.enabled && super::context_uri_matches(path, &c.uri)
        })
        .max_by_key(|c| c.uri.len())
        .and_then(|c| c.handler.clone())
}

/// Resolve a proxy-context handler name to a [`ProxyTarget`]. (#3) Vhost-local
/// `<extProcessorList>` entries win over the global server map so a per-vhost
/// processor (e.g. status.forum.example's `stats_api`) is reachable and
/// cannot be shadowed by a same-named global processor.
pub(super) fn resolve_proxy_target(
    state: &ServerState,
    ctx: &ReqCtx,
    handler: &str,
) -> Option<ProxyTarget> {
    if let Some(ep) = ctx
        .vhost
        .extra_ext_processors
        .iter()
        .find(|e| e.name == handler)
    {
        return Some(ProxyTarget::from_ext_processor(ep));
    }
    state
        .ext_by_name
        .get(handler)
        .map(ProxyTarget::from_ext_processor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn uring_upgrade_relay_moves_bytes_both_directions() {
        let (client, mut upstream_peer) = tokio::io::duplex(1024);
        let mut io = start_uring_upgrade_relay(client);

        io.to_upstream
            .send(bytes::Bytes::from_static(b"client-frame"))
            .await
            .unwrap();
        let mut received = [0u8; 12];
        upstream_peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"client-frame");

        upstream_peer.write_all(b"upstream-frame").await.unwrap();
        let received = io.from_upstream.recv().await.unwrap().unwrap();
        assert_eq!(&received[..], b"upstream-frame");
    }
}
