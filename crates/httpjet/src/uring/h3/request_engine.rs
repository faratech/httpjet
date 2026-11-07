//! H3 application dispatch with a generation-pinned on-core cache path.
//!
//! QUIC remains the single transport owner. This engine runs only after the
//! existing H3 framing, QPACK, request-body and trust checks have succeeded.
//! The same finalized-response policy used by H1/H2 decides on-core eligibility;
//! all declines retain the original request snapshot through the bridge.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::uring::bridge::{Bridge, BridgeCtx, BridgeResp};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
#[repr(u8)]
pub(crate) enum H3EngineMode {
    #[default]
    Legacy = 0,
    Accelerated = 1,
    Auto = 2,
}

static ENGINE_MODE: AtomicU8 = AtomicU8::new(H3EngineMode::Legacy as u8);
static ON_CORE_RESPONSES: AtomicU64 = AtomicU64::new(0);
static BRIDGED_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TELEMETRY_FALLBACKS: AtomicU64 = AtomicU64::new(0);

/// Startup configuration is snapshotted by each listener generation. Existing
/// connections keep the engine admitted with their listener and trust policy.
pub(crate) fn configure_engine_mode(mode: H3EngineMode) {
    ENGINE_MODE.store(mode as u8, Ordering::Relaxed);
}

pub(crate) struct H3EngineCounts {
    pub on_core_responses: u64,
    pub bridged_requests: u64,
    pub telemetry_fallbacks: u64,
}

pub(crate) fn engine_counts() -> H3EngineCounts {
    H3EngineCounts {
        on_core_responses: ON_CORE_RESPONSES.load(Ordering::Relaxed),
        bridged_requests: BRIDGED_REQUESTS.load(Ordering::Relaxed),
        telemetry_fallbacks: TELEMETRY_FALLBACKS.load(Ordering::Relaxed),
    }
}

#[derive(Clone)]
pub(crate) struct H3RequestEngine {
    mode: H3EngineMode,
    listener_name: Arc<str>,
}

impl H3RequestEngine {
    pub(super) fn allows_inline(&self) -> bool {
        self.mode != H3EngineMode::Legacy
    }

    pub(crate) fn configured(listener_name: Arc<str>) -> Self {
        let mode = match ENGINE_MODE.load(Ordering::Relaxed) {
            1 => H3EngineMode::Accelerated,
            2 => H3EngineMode::Auto,
            _ => H3EngineMode::Legacy,
        };
        Self {
            mode,
            listener_name,
        }
    }

    pub(crate) async fn dispatch(
        &self,
        bridge: &Bridge,
        request: hj_core::Request,
        context: BridgeCtx,
    ) -> Option<BridgeResp> {
        if self.mode != H3EngineMode::Legacy {
            // The existing H3 bridge owns tracing roots. Preserve those roots
            // until an on-core H3 tracing boundary is qualified independently.
            #[cfg(feature = "otel")]
            let telemetry_active = crate::otel::enabled();
            #[cfg(not(feature = "otel"))]
            let telemetry_active = false;
            if telemetry_active {
                TELEMETRY_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            } else if let Some(snapshot) = context.request_generation.as_ref() {
                if let Some(response) = super::super::CoreHandler::fast_for_listener(
                    &self.listener_name,
                    &snapshot.0,
                    &context,
                    &request,
                )
                .await
                {
                    ON_CORE_RESPONSES.fetch_add(1, Ordering::Relaxed);
                    return bridge
                        .forward_fast_response(response, context.response_budget)
                        .await;
                }
            }
            // A fast-path decline leaves the driver's inline poll before acquiring
            // bridge admission or waking Tokio. The same pinned request resumes in
            // its Monoio task with its generation, trust context and guards intact.
            super::scheduling::defer_bridge_from_inline().await;
        }
        BRIDGED_REQUESTS.fetch_add(1, Ordering::Relaxed);
        bridge.dispatch(request, context).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serving_generation::RequestGeneration;
    use crate::uring::bridge::BridgeBody;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture {
        root: std::path::PathBuf,
        state: Arc<crate::state::ServerState>,
    }

    impl Fixture {
        fn new(body: &[u8]) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "hj-h3-request-engine-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("asset.txt"), body).unwrap();
            let state = crate::pipeline::e2e::build_state(root.clone());
            Self { root, state }
        }

        fn context(&self) -> BridgeCtx {
            let mut context = BridgeCtx::plain(
                "127.0.0.1:30100".parse().unwrap(),
                "127.0.0.1:8443".parse().unwrap(),
                hj_core::Proto::Http3,
            );
            context.is_tls = true;
            context.sni = Some(Arc::from("canon.test"));
            context.request_generation = Some(RequestGeneration(self.state.clone()));
            context
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
            let _ = std::fs::remove_dir_all(&self.state.server.server_root);
        }
    }

    fn request() -> hj_core::Request {
        http::Request::builder()
            .version(http::Version::HTTP_3)
            .uri("/asset.txt")
            .header(http::header::HOST, "canon.test")
            .header(http::header::ACCEPT_ENCODING, "identity")
            .body(hj_core::empty_incoming())
            .unwrap()
    }

    fn engine(mode: H3EngineMode) -> H3RequestEngine {
        H3RequestEngine {
            mode,
            listener_name: Arc::from("http"),
        }
    }

    #[tokio::test]
    async fn accelerated_static_response_bypasses_bridge_and_keeps_date() {
        let fixture = Fixture::new(b"cached H3 representation");
        let bridged = Arc::new(AtomicUsize::new(0));
        let copy = bridged.clone();
        let bridge = crate::uring::bridge::spawn_on_current(1, move |_, _| {
            copy.fetch_add(1, Ordering::Relaxed);
            async { http::Response::new(hj_core::Body::Empty) }
        });
        let response = engine(H3EngineMode::Accelerated)
            .dispatch(&bridge, request(), fixture.context())
            .await
            .unwrap();
        assert_eq!(response.status, http::StatusCode::OK);
        assert!(response.headers.contains_key(http::header::DATE));
        let BridgeBody::Full(body) = response.body else {
            panic!("cached response must remain buffered");
        };
        assert_eq!(body, b"cached H3 representation"[..]);
        assert_eq!(bridged.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn declined_request_reaches_bridge_with_same_generation_and_trust_context() {
        let fixture = Fixture::new(b"asset");
        let expected = fixture.state.clone();
        let bridge = crate::uring::bridge::spawn_on_current(1, move |req, context| {
            assert!(Arc::ptr_eq(
                &context.request_generation.as_ref().unwrap().0,
                &expected
            ));
            assert_eq!(context.sni.as_deref(), Some("canon.test"));
            assert!(context.is_tls);
            assert_eq!(context.proto, hj_core::Proto::Http3);
            assert_eq!(req.headers()[http::header::RANGE], "bytes=1-3");
            async {
                http::Response::builder()
                    .status(http::StatusCode::PARTIAL_CONTENT)
                    .body(hj_core::Body::Full(bytes::Bytes::from_static(b"sse")))
                    .unwrap()
            }
        });
        let mut req = request();
        req.headers_mut().insert(
            http::header::RANGE,
            http::HeaderValue::from_static("bytes=1-3"),
        );
        let response = engine(H3EngineMode::Auto)
            .dispatch(&bridge, req, fixture.context())
            .await
            .unwrap();
        assert_eq!(response.status, http::StatusCode::PARTIAL_CONTENT);
        let BridgeBody::Full(body) = response.body else {
            panic!("small fallback remains buffered");
        };
        assert_eq!(body, b"sse"[..]);
    }

    #[tokio::test]
    async fn legacy_mode_and_missing_snapshot_preserve_bridge_contract() {
        let fixture = Fixture::new(b"asset");
        let bridged = Arc::new(AtomicUsize::new(0));
        let copy = bridged.clone();
        let bridge = crate::uring::bridge::spawn_on_current(1, move |_, _| {
            copy.fetch_add(1, Ordering::Relaxed);
            async {
                http::Response::builder()
                    .status(http::StatusCode::ACCEPTED)
                    .body(hj_core::Body::Empty)
                    .unwrap()
            }
        });
        let response = engine(H3EngineMode::Legacy)
            .dispatch(&bridge, request(), fixture.context())
            .await
            .unwrap();
        assert_eq!(response.status, http::StatusCode::ACCEPTED);
        let mut context = fixture.context();
        context.request_generation = None;
        let response = engine(H3EngineMode::Accelerated)
            .dispatch(&bridge, request(), context)
            .await
            .unwrap();
        assert_eq!(response.status, http::StatusCode::ACCEPTED);
        assert_eq!(bridged.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn exceptional_fast_response_keeps_streaming_and_completion() {
        use http_body_util::BodyExt;
        let bridge = crate::uring::bridge::spawn_on_current(1, |_, _| async {
            panic!("already selected responses must not redispatch")
        });
        let body = http_body_util::Full::new(bytes::Bytes::from_static(b"live event\n"))
            .map_err(|never| match never {})
            .boxed();
        let mut response = http::Response::builder()
            .header(http::header::CONTENT_TYPE, "text/event-stream")
            .body(hj_core::Body::Stream(body))
            .unwrap();
        let completed = Arc::new(AtomicUsize::new(0));
        let copy = completed.clone();
        response
            .extensions_mut()
            .insert(hj_core::ResponseCompletion::new(move |end| {
                assert_eq!(end, hj_core::ResponseEnd::Complete);
                copy.fetch_add(1, Ordering::Relaxed);
            }));
        let mut response = bridge
            .forward_fast_response(response, crate::uring::bridge::connection_response_budget())
            .await
            .unwrap();
        let BridgeBody::Stream { mut rx, .. } = response.body else {
            panic!("event stream must not be buffered to completion");
        };
        assert_eq!(rx.recv().await.unwrap().unwrap(), b"live event\n"[..]);
        assert!(rx.recv().await.is_none());
        response
            .completion
            .take()
            .unwrap()
            .finish(hj_core::ResponseEnd::Complete);
        assert_eq!(completed.load(Ordering::Relaxed), 1);
    }
}
