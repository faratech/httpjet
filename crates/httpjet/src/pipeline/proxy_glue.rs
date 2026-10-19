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
        #[cfg(feature = "otel")]
        let req = {
            let mut req = req;
            if crate::otel::enabled() && self.target.name.is_some() {
                crate::otel::inject(req.headers_mut());
            }
            req
        };
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
    req: Request,
    target: ProxyTarget,
) -> Response {
    #[cfg(feature = "otel")]
    if crate::otel::enabled() {
        return crate::otel::backend(crate::otel::BackendKind::WebSocket, async {
            let mut req = req;
            if target.name.is_some() {
                crate::otel::inject(req.headers_mut());
            }
            Ok(proxy_websocket_inner(state, ctx, req, target).await)
        })
        .await
        .unwrap_or_else(|e| error_page(e.status()));
    }
    proxy_websocket_inner(state, ctx, req, target).await
}

async fn proxy_websocket_inner(
    state: &ServerState,
    ctx: &ReqCtx,
    mut req: Request,
    target: ProxyTarget,
) -> Response {
    let uring_upgrade = req.extensions_mut().remove::<UringUpgradeRequest>();
    let client_on_upgrade = uring_upgrade
        .is_none()
        .then(|| hyper::upgrade::on(&mut req));

    let mut upgrade = match state.proxy.proxy_websocket(ctx, req, &target).await {
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
    let reservation = upgrade.reservation.take();
    // (#583) Default-target maxConns permit; held for the relay's lifetime.
    let permit = upgrade.permit.take();

    if let Some(handoff) = uring_upgrade {
        let io = start_uring_upgrade_relay(
            hyper_util::rt::TokioIo::new(upstream_io),
            reservation,
            permit,
        );
        if handoff.handoff(io).await.is_err() {
            return error_page(StatusCode::BAD_GATEWAY);
        }
        return resp;
    }

    // After we return `resp` (101), hyper upgrades the client connection; the
    // future resolves with the client IO, which we bridge to the upstream.
    tokio::spawn(async move {
        let _reservation = reservation;
        let _permit = permit;
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

/// After one direction of an upgraded relay reaches a clean EOF, the other direction
/// keeps relaying (a WebSocket Close reply, a half-closed tunnel's tail) for at most
/// this long, so a peer that never closes its half cannot pin the relay — and its
/// maxConns permit — forever.
pub(crate) const UPGRADE_HALF_CLOSE_DRAIN: std::time::Duration = std::time::Duration::from_secs(30);

fn start_uring_upgrade_relay<U>(
    upstream: U,
    reservation: Option<hj_proxy::RequestReservation>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> UringUpgradeIo
where
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    start_uring_upgrade_relay_with_drain(upstream, reservation, permit, UPGRADE_HALF_CLOSE_DRAIN)
}

fn start_uring_upgrade_relay_with_drain<U>(
    upstream: U,
    reservation: Option<hj_proxy::RequestReservation>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    drain: std::time::Duration,
) -> UringUpgradeIo
where
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (to_upstream, mut downstream_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(8);
    let (upstream_tx, from_upstream) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, ()>>(8);
    tokio::spawn(async move {
        let _reservation = reservation;
        let _permit = permit;
        let (mut reader, mut writer) = tokio::io::split(upstream);
        // Each direction returns true on a clean EOF (half-close), false on an error.
        // Like copy_bidirectional, a clean EOF shuts down the opposite write half and
        // lets the other direction run on; an error ends the whole relay.
        let downstream_to_upstream = async move {
            while let Some(bytes) = downstream_rx.recv().await {
                if writer.write_all(&bytes).await.is_err() {
                    return false;
                }
            }
            writer.shutdown().await.is_ok()
        };
        let upstream_to_downstream = async move {
            let mut buf = vec![0u8; 16 * 1024];
            let clean = loop {
                // A client side that has gone entirely ends the drain at once.
                let read = tokio::select! {
                    read = reader.read(&mut buf) => read,
                    _ = upstream_tx.closed() => break false,
                };
                match read {
                    Ok(0) => break true,
                    Ok(n) => {
                        if upstream_tx
                            .send(Ok(bytes::Bytes::copy_from_slice(&buf[..n])))
                            .await
                            .is_err()
                        {
                            break false;
                        }
                    }
                    Err(_) => {
                        let _ = upstream_tx.send(Err(())).await;
                        break false;
                    }
                }
            };
            // Dropping the sender is the client-side EOF signal.
            drop(upstream_tx);
            clean
        };
        let mut downstream_to_upstream = std::pin::pin!(downstream_to_upstream);
        let mut upstream_to_downstream = std::pin::pin!(upstream_to_downstream);
        tokio::select! {
            clean = &mut downstream_to_upstream => {
                if clean {
                    let _ = tokio::time::timeout(drain, upstream_to_downstream).await;
                }
            }
            clean = &mut upstream_to_downstream => {
                if clean {
                    let _ = tokio::time::timeout(drain, downstream_to_upstream).await;
                }
            }
        }
    });
    UringUpgradeIo {
        to_upstream,
        from_upstream,
    }
}

/// The longest-matching enabled proxy context for `path`. The match remains
/// visible when its handler is absent so callers can fail closed instead of
/// confusing an invalid match with no proxy context.
fn matching_proxy_context_in<'a>(
    contexts: &'a [hj_core::config::Context],
    path: &str,
) -> Option<&'a hj_core::config::Context> {
    use hj_core::config::ContextKind;
    let proxy = contexts
        .iter()
        .filter(|c| {
            c.kind == ContextKind::Proxy && c.enabled && super::context_uri_matches(path, &c.uri)
        })
        .max_by_key(|c| c.uri.len())?;
    // OLS resolves ONE most-specific context of any kind: a static context nested under
    // the proxy mount (the "app + local assets dir" layout) serves locally.
    let shadowed = contexts.iter().any(|c| {
        c.kind == ContextKind::Static
            && c.enabled
            && c.uri.len() > proxy.uri.len()
            && super::context_uri_matches(path, &c.uri)
    });
    (!shadowed).then_some(proxy)
}

pub(super) fn matching_proxy_context<'a>(
    ctx: &'a ReqCtx,
    path: &str,
) -> Option<&'a hj_core::config::Context> {
    matching_proxy_context_in(&ctx.vhost.contexts, path)
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
        return (ep.kind == hj_core::config::ExtKind::Proxy).then(|| {
            ProxyTarget::from_ext_processor(ep).in_scope(format!("vhost:{}", ctx.vhost_name))
        });
    }
    state
        .ext_by_name
        .get(handler)
        .filter(|processor| processor.kind == hj_core::config::ExtKind::Proxy)
        .map(ProxyTarget::from_ext_processor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn context(uri: &str, handler: Option<&str>, enabled: bool) -> hj_core::config::Context {
        hj_core::config::Context {
            kind: hj_core::config::ContextKind::Proxy,
            uri: uri.into(),
            location: None,
            handler: handler.map(str::to_string),
            enabled,
            allow_browse: true,
            extra_headers: Vec::new(),
            add_default_charset: None,
            charset: None,
            cache_policy: None,
            max_body_override: None,
            bandwidth_limit: 0,
            timeout_override: None,
            sub_filter: None,
        }
    }

    #[test]
    fn longest_proxy_match_is_preserved_when_its_handler_is_missing() {
        let contexts = vec![
            context("/", Some("fallback"), true),
            context("/api", None, true),
            context("/api/private", Some("disabled"), false),
        ];
        let matched = matching_proxy_context_in(&contexts, "/api/private/report")
            .expect("the enabled /api context must remain the effective match");
        assert_eq!(matched.uri, "/api");
        assert!(matched.handler.is_none());
    }

    #[tokio::test]
    async fn uring_upgrade_relay_moves_bytes_both_directions() {
        let (client, mut upstream_peer) = tokio::io::duplex(1024);
        let mut io = start_uring_upgrade_relay(client, None, None);

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

    /// Regression (#805): a client half-close (FIN) must shut down the upstream write
    /// half and keep relaying upstream->client until upstream EOF, so a WebSocket
    /// server's Close reply sent after the client's FIN still reaches the client.
    #[tokio::test]
    async fn uring_upgrade_relay_drains_upstream_after_client_half_close() {
        let (client, mut upstream_peer) = tokio::io::duplex(1024);
        let UringUpgradeIo {
            to_upstream,
            mut from_upstream,
        } = start_uring_upgrade_relay(client, None, None);

        to_upstream
            .send(bytes::Bytes::from_static(b"close-frame"))
            .await
            .unwrap();
        drop(to_upstream);
        let mut received = Vec::new();
        upstream_peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(
            &received, b"close-frame",
            "client EOF reaches upstream as EOF"
        );

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        upstream_peer.write_all(b"close-reply").await.unwrap();
        upstream_peer.shutdown().await.unwrap();
        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), from_upstream.recv())
            .await
            .expect("upstream reply after client half-close")
            .expect("relay still open")
            .unwrap();
        assert_eq!(&reply[..], b"close-reply");
        let end = tokio::time::timeout(std::time::Duration::from_secs(2), from_upstream.recv())
            .await
            .expect("upstream EOF ends the relay");
        assert!(end.is_none(), "upstream EOF closes the client direction");
    }

    /// The drain after a half-close is bounded: an upstream that never closes its half
    /// cannot hold the relay (and its maxConns permit) past the drain deadline.
    #[tokio::test]
    async fn uring_upgrade_relay_half_close_drain_is_bounded() {
        let (client, upstream_peer) = tokio::io::duplex(1024);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let UringUpgradeIo {
            to_upstream,
            mut from_upstream,
        } = start_uring_upgrade_relay_with_drain(
            client,
            None,
            Some(permit),
            std::time::Duration::from_millis(50),
        );
        drop(to_upstream);
        let end = tokio::time::timeout(std::time::Duration::from_secs(2), from_upstream.recv())
            .await
            .expect("drain deadline ends the relay");
        assert!(end.is_none());
        for _ in 0..100 {
            if semaphore.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(semaphore.available_permits(), 1, "maxConns permit released");
        drop(upstream_peer);
    }
}
