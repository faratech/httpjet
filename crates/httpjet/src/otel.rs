//! Explicit, opt-in spans. No blanket export of log fields or request metadata.
use opentelemetry::{
    Context, KeyValue, global,
    trace::{FutureExt, SpanKind, TraceContextExt, Tracer},
};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
mod batch;
static BATCH_STATS: std::sync::OnceLock<std::sync::Arc<batch::Stats>> = std::sync::OnceLock::new();
pub fn span_stats() -> (u64, u64, u64, u64) {
    BATCH_STATS.get().map_or((0, 0, 0, 0), |s| {
        (
            s.queued.load(Ordering::Relaxed),
            s.dropped.load(Ordering::Relaxed),
            s.exported.load(Ordering::Relaxed),
            s.failed.load(Ordering::Relaxed),
        )
    })
}
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

static ENABLED: AtomicBool = AtomicBool::new(false);
static TRUSTED_PARENTS: std::sync::OnceLock<Vec<std::net::IpAddr>> = std::sync::OnceLock::new();

fn parse_trusted_parents(value: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
    anyhow::ensure!(
        value.len() <= 4096,
        "OTel trusted-parent list exceeds 4096 bytes"
    );
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut peers = Vec::new();
    for part in value.split(',') {
        anyhow::ensure!(
            peers.len() < 128,
            "OTel trusted-parent list exceeds 128 entries"
        );
        let peer: std::net::IpAddr = part
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("OTel trusted parents require exact IP addresses"))?;
        anyhow::ensure!(
            !peer.is_unspecified() && !peer.is_multicast(),
            "invalid OTel trusted-parent address"
        );
        peers.push(peer);
    }
    Ok(peers)
}

/// This trust decision is separate from forwarded-client-IP trust. Never import
/// baggage or tracestate, even from an explicitly authorized tracing gateway.
fn extract_parent(headers: &mut http::HeaderMap, trusted: bool) -> Context {
    use opentelemetry::propagation::TextMapPropagator;
    struct Parent<'a>(&'a str);
    impl opentelemetry::propagation::Extractor for Parent<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            (key == "traceparent").then_some(self.0)
        }
        fn keys(&self) -> Vec<&str> {
            vec!["traceparent"]
        }
    }
    let mut parent = Context::new();
    if trusted && headers.get_all("traceparent").iter().count() == 1 {
        if let Some(value) = headers.get("traceparent").and_then(|v| v.to_str().ok()) {
            // Deliberately support only the fixed-size W3C version-00 format.
            if value.len() == 55
                && value.starts_with("00-")
                && value.bytes().enumerate().all(|(i, b)| {
                    if [2, 35, 52].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                })
            {
                parent = opentelemetry_sdk::propagation::TraceContextPropagator::new()
                    .extract_with_context(&Context::new(), &Parent(value));
            }
        }
    }
    for name in ["traceparent", "tracestate", "baggage"] {
        headers.remove(name);
    }
    parent
}

pub fn inbound_parent(
    headers: &mut http::HeaderMap,
    peer: std::net::IpAddr,
    direct_tcp: bool,
) -> Context {
    let trusted = direct_tcp
        && TRUSTED_PARENTS
            .get()
            .is_some_and(|peers| peers.contains(&peer));
    extract_parent(headers, trusted)
}
static EXPORT_ATTEMPTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXPORT_FAILURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub fn export_stats() -> (u64, u64) {
    (
        EXPORT_ATTEMPTS.load(Ordering::Relaxed),
        EXPORT_FAILURES.load(Ordering::Relaxed),
    )
}
static METRICS: std::sync::OnceLock<RequestMetrics> = std::sync::OnceLock::new();
struct RequestMetrics {
    completed: opentelemetry::metrics::Counter<u64>,
    duration: opentelemetry::metrics::Histogram<f64>,
    exports: opentelemetry::metrics::Counter<u64>,
}
impl RequestMetrics {
    fn new(meter: &opentelemetry::metrics::Meter) -> Self {
        Self {
            completed: meter
                .u64_counter("httpjet.pipeline.requests.completed")
                .build(),
            duration: meter
                .f64_histogram("httpjet.pipeline.response_head.duration")
                .with_unit("s")
                .build(),
            exports: meter.u64_counter("httpjet.otel.http.exports").build(),
        }
    }
    fn response_head(&self, status: http::StatusCode, duration: Duration) {
        let attributes = [KeyValue::new(
            "http.response.status_code",
            i64::from(status.as_u16()),
        )];
        self.completed.add(1, &attributes);
        self.duration.record(duration.as_secs_f64(), &attributes);
    }
}

#[derive(Debug)]
struct BoundedClient(reqwest::blocking::Client);
impl BoundedClient {
    fn new() -> anyhow::Result<Self> {
        Ok(Self(
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()?,
        ))
    }
}
#[async_trait::async_trait]
impl opentelemetry_http::HttpClient for BoundedClient {
    async fn send_bytes(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> Result<http::Response<bytes::Bytes>, opentelemetry_http::HttpError> {
        let result = self.send_bounded(request);
        EXPORT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        if !result.as_ref().is_ok_and(|r| r.status().is_success()) {
            EXPORT_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(m) = METRICS.get() {
            let success = result.as_ref().is_ok_and(|r| r.status().is_success());
            m.exports.add(
                1,
                &[KeyValue::new(
                    "outcome",
                    if success { "success" } else { "failure" },
                )],
            );
        }
        result
    }
}
impl BoundedClient {
    fn send_bounded(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> Result<http::Response<bytes::Bytes>, opentelemetry_http::HttpError> {
        use std::io::Read;
        let response = self.0.execute(request.try_into()?)?;
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        response.take(65537).read_to_end(&mut body)?;
        if body.len() > 65536 {
            return Err("OTLP response exceeds 64 KiB".into());
        }
        let mut result = http::Response::builder().status(status).body(body.into())?;
        *result.headers_mut() = headers;
        Ok(result)
    }
}

pub struct Runtime(
    SdkTracerProvider,
    Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
);
impl Drop for Runtime {
    fn drop(&mut self) {
        ENABLED.store(false, Ordering::Relaxed);
        // The metrics SDK currently ignores its shutdown timeout argument. Bound
        // the caller's wait independently; the HTTP client still bounds each export.
        let trace = self.0.clone();
        let metrics = self.1.take();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = trace.shutdown_with_timeout(Duration::from_secs(2));
            if let Some(m) = metrics {
                let _ = m.shutdown();
            }
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(Duration::from_secs(3));
    }
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}
#[cfg(test)]
pub(crate) fn enable_for_isolated_test() {
    ENABLED.store(true, Ordering::Relaxed);
}

pub fn execution_path(on_core: bool) {
    Context::current().span().set_attribute(KeyValue::new(
        "httpjet.execution.path",
        if on_core { "on-core" } else { "bridge" },
    ));
}

pub fn init() -> anyhow::Result<Option<Runtime>> {
    if std::env::var("HTTPJET_OTEL").as_deref() != Ok("1") {
        anyhow::ensure!(
            std::env::var("HTTPJET_OTEL_METRICS").as_deref() != Ok("1"),
            "HTTPJET_OTEL_METRICS requires HTTPJET_OTEL=1"
        );
        return Ok(None);
    }
    let ratio = std::env::var("HTTPJET_OTEL_SAMPLE_RATIO")
        .unwrap_or_else(|_| "0.01".into())
        .parse::<f64>()?;
    anyhow::ensure!(
        ratio.is_finite() && (0.0..=1.0).contains(&ratio),
        "invalid HTTPJET_OTEL_SAMPLE_RATIO"
    );
    let trusted_parents =
        parse_trusted_parents(&std::env::var("HTTPJET_OTEL_TRUSTED_PARENTS").unwrap_or_default())?;
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_http_client(BoundedClient::new()?)
        .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
        .with_timeout(Duration::from_secs(2))
        .build()?;
    let processor = batch::Processor::new(exporter, 2048, 256, Duration::from_secs(1))?;
    let _ = BATCH_STATS.set(processor.stats.clone());
    let provider = SdkTracerProvider::builder()
        .with_span_processor(processor)
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            ratio,
        ))))
        .with_resource(
            opentelemetry_sdk::Resource::builder_empty()
                .with_service_name("httpjet")
                .build(),
        )
        .build();
    let metrics = if std::env::var("HTTPJET_OTEL_METRICS").as_deref() == Ok("1") {
        use opentelemetry::metrics::MeterProvider;
        let exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_http_client(BoundedClient::new()?)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_timeout(Duration::from_secs(2))
            .build()?;
        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
            .with_interval(Duration::from_secs(30))
            .build();
        let metrics = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(
                opentelemetry_sdk::Resource::builder_empty()
                    .with_service_name("httpjet")
                    .build(),
            )
            .build();
        let meter = metrics.meter("httpjet");
        let _ = METRICS.set(RequestMetrics::new(&meter));
        Some(metrics)
    } else {
        None
    };
    global::set_tracer_provider(provider.clone());
    let _ = TRUSTED_PARENTS.set(trusted_parents);
    ENABLED.store(true, Ordering::Relaxed);
    Ok(Some(Runtime(provider, metrics)))
}

struct End(Context);
pub struct Stage {
    _end: End,
}
#[derive(Clone, Copy)]
pub enum StageKind {
    Rewrite,
    CacheLookup,
    CacheStore,
}
pub fn stage(kind: StageKind) -> Option<Stage> {
    if !enabled() {
        return None;
    }
    let parent = Context::current();
    if !parent.span().is_recording() {
        return None;
    }
    let name = match kind {
        StageKind::Rewrite => "httpjet.rewrite",
        StageKind::CacheLookup => "httpjet.cache.lookup",
        StageKind::CacheStore => "httpjet.cache.store",
    };
    let tracer = global::tracer("httpjet");
    let span = tracer
        .span_builder(name)
        .with_kind(SpanKind::Internal)
        .start_with_context(&tracer, &parent);
    Some(Stage {
        _end: End(parent.with_span(span)),
    })
}
impl Drop for End {
    fn drop(&mut self) {
        self.0.span().end();
    }
}

struct TracedBody {
    body: hj_core::StreamBody,
    end: Option<End>,
}
impl TracedBody {
    fn finish(&mut self, outcome: &'static str) {
        if let Some(end) = self.end.take() {
            end.0
                .span()
                .set_attribute(KeyValue::new("httpjet.body.outcome", outcome));
        }
    }
}
impl Drop for TracedBody {
    fn drop(&mut self) {
        self.finish("cancelled");
    }
}
impl http_body::Body for TracedBody {
    type Data = bytes::Bytes;
    type Error = hj_core::BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let _context = self.end.as_ref().map(|end| end.0.clone().attach());
        let result = std::pin::Pin::new(&mut self.body).poll_frame(cx);
        match &result {
            std::task::Poll::Ready(None) => self.finish("complete"),
            std::task::Poll::Ready(Some(Err(_))) => self.finish("error"),
            std::task::Poll::Ready(Some(Ok(_))) if self.body.is_end_stream() => {
                self.finish("complete")
            }
            _ => {}
        }
        result
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}
fn retain_stream_span(response: &mut hj_core::Response, end: End) {
    use http_body::Body as _;
    use http_body_util::BodyExt;
    let body = std::mem::replace(response.body_mut(), hj_core::Body::Empty);
    *response.body_mut() = match body {
        hj_core::Body::Stream(body) if body.is_end_stream() => {
            end.0
                .span()
                .set_attribute(KeyValue::new("httpjet.body.outcome", "complete"));
            hj_core::Body::Stream(body)
        }
        hj_core::Body::Stream(body) => hj_core::Body::Stream(
            TracedBody {
                body,
                end: Some(end),
            }
            .boxed(),
        ),
        body => body,
    };
}

#[derive(Clone)]
pub struct TransportContext(pub Context);

/// Owned by a transport request, not by the pipeline's response-head future.
pub struct RequestTrace {
    end: Option<End>,
    started: std::time::Instant,
}
impl RequestTrace {
    pub fn new(parent: Context) -> Self {
        let tracer = global::tracer("httpjet");
        let span = tracer
            .span_builder("httpjet.request")
            .with_kind(SpanKind::Server)
            .start_with_context(&tracer, &parent);
        Self {
            end: Some(End(parent.with_span(span))),
            started: std::time::Instant::now(),
        }
    }
    pub fn context(&self) -> Context {
        self.end.as_ref().unwrap().0.clone()
    }
    pub fn response_head(&self, status: http::StatusCode) {
        if let Some(m) = METRICS.get() {
            m.response_head(status, self.started.elapsed());
        }
        self.context().span().set_attribute(KeyValue::new(
            "http.response.status_code",
            i64::from(status.as_u16()),
        ));
    }
    pub fn finish(mut self, outcome: &'static str) {
        if let Some(end) = self.end.take() {
            end.0
                .span()
                .set_attribute(KeyValue::new("httpjet.body.outcome", outcome));
        }
    }
    pub fn retain_stream(mut self, response: &mut hj_core::Response) {
        retain_stream_span(response, self.end.take().unwrap());
    }
    pub fn completion(self) -> hj_core::ResponseCompletion {
        hj_core::ResponseCompletion::new(move |end| {
            self.finish(match end {
                hj_core::ResponseEnd::Complete => "complete",
                hj_core::ResponseEnd::Error => "error",
                hj_core::ResponseEnd::Cancelled => "cancelled",
            })
        })
    }
}
impl Drop for RequestTrace {
    fn drop(&mut self) {
        if let Some(end) = self.end.take() {
            end.0
                .span()
                .set_attribute(KeyValue::new("httpjet.body.outcome", "cancelled"));
        }
    }
}

pub async fn in_context<T>(context: Context, future: impl Future<Output = T>) -> T {
    future.with_context(context).await
}

#[derive(Clone)]
pub struct ResponseHead {
    context: Context,
    started: std::time::Instant,
}
impl ResponseHead {
    pub fn record(self, status: http::StatusCode) {
        self.context.span().set_attribute(KeyValue::new(
            "http.response.status_code",
            i64::from(status.as_u16()),
        ));
        if let Some(metrics) = METRICS.get() {
            metrics.response_head(status, self.started.elapsed());
        }
    }
}

pub async fn request_with_completion(
    parent: Context,
    future: impl Future<Output = hj_core::Response>,
) -> hj_core::Response {
    let trace = RequestTrace::new(parent);
    let context = trace.context();
    let mut response = in_context(context.clone(), future).await;
    response.extensions_mut().insert(ResponseHead {
        context,
        started: trace.started,
    });
    response.extensions_mut().insert(trace.completion());
    response
}

pub async fn request_with_parent(
    parent: Context,
    future: impl Future<Output = hj_core::Response>,
) -> hj_core::Response {
    let trace = RequestTrace::new(parent);
    let mut response = future.with_context(trace.context()).await;
    trace.response_head(response.status());
    trace.retain_stream(&mut response);
    response
}

#[derive(Clone, Copy)]
pub enum BackendKind {
    Static,
    Proxy,
    WebSocket,
    Lsapi,
    FastCgi,
    #[cfg(test)]
    Generic,
}

impl BackendKind {
    fn span_spec(self) -> (&'static str, SpanKind) {
        match self {
            Self::Static => ("httpjet.static", SpanKind::Internal),
            Self::Proxy => ("httpjet.proxy", SpanKind::Client),
            Self::WebSocket => ("httpjet.websocket", SpanKind::Client),
            Self::Lsapi => ("httpjet.lsapi", SpanKind::Client),
            Self::FastCgi => ("httpjet.fastcgi", SpanKind::Client),
            #[cfg(test)]
            Self::Generic => ("httpjet.backend", SpanKind::Internal),
        }
    }
}

pub async fn backend(
    kind: BackendKind,
    future: impl Future<Output = Result<hj_core::Response, hj_core::HandlerError>>,
) -> Result<hj_core::Response, hj_core::HandlerError> {
    let tracer = global::tracer("httpjet");
    let (name, span_kind) = kind.span_spec();
    let span = tracer
        .span_builder(name)
        .with_kind(span_kind)
        .start_with_context(&tracer, &Context::current());
    let context = Context::current().with_span(span);
    let end = End(context.clone());
    let mut result = future.with_context(context.clone()).await;
    let status = result
        .as_ref()
        .map(|r| r.status())
        .unwrap_or_else(|e| e.status());
    context.span().set_attribute(KeyValue::new(
        "http.response.status_code",
        i64::from(status.as_u16()),
    ));
    if let Ok(response) = &mut result {
        retain_stream_span(response, end);
    }
    result
}

pub fn inject(headers: &mut http::HeaderMap) {
    let cx = Context::current();
    let span = cx.span();
    let sc = span.span_context();
    if sc.is_valid() {
        let value = format!(
            "00-{}-{}-{:02x}",
            sc.trace_id(),
            sc.span_id(),
            sc.trace_flags().to_u8()
        );
        if let Ok(value) = value.parse() {
            headers.insert("traceparent", value);
        }
    }
}

#[cfg(test)]
#[path = "otel/lsapi_test.rs"]
mod lsapi_test;

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_sdk::trace::{SpanData, SpanExporter};
    use std::sync::{Arc, Mutex};

    async fn request(future: impl Future<Output = hj_core::Response>) -> hj_core::Response {
        request_with_parent(Context::new(), future).await
    }

    #[test]
    fn inbound_parent_trust_and_header_boundaries() {
        const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(parse_trusted_parents("").unwrap().is_empty());
        assert_eq!(parse_trusted_parents("127.0.0.1, ::1").unwrap().len(), 2);
        for invalid in [
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "10.0.0.0/8",
            "host",
            "127.0.0.1,",
        ] {
            assert!(parse_trusted_parents(invalid).is_err());
        }
        assert!(parse_trusted_parents(&vec!["127.0.0.1"; 129].join(",")).is_err());
        assert!(parse_trusted_parents(&" ".repeat(4097)).is_err());
        for trusted in [false, true] {
            for (value, duplicate, valid) in [
                (VALID, false, true),
                (VALID, true, false),
                (
                    "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
                    false,
                    false,
                ),
                (
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
                    false,
                    false,
                ),
                (
                    "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                    false,
                    false,
                ),
                ("invalid", false, false),
            ] {
                let mut headers = http::HeaderMap::new();
                headers.insert("traceparent", value.parse().unwrap());
                if duplicate {
                    headers.append("traceparent", VALID.parse().unwrap());
                }
                headers.insert("tracestate", "vendor=secret".parse().unwrap());
                headers.insert("baggage", "secret=value".parse().unwrap());
                let cx = extract_parent(&mut headers, trusted);
                assert_eq!(cx.span().span_context().is_valid(), trusted && valid);
                assert!(cx.span().span_context().trace_state().header().is_empty());
                assert!(headers.is_empty());
            }
        }
    }

    #[derive(Debug, Clone)]
    struct Capture(Arc<Mutex<Vec<SpanData>>>);
    impl SpanExporter for Capture {
        async fn export(&self, batch: Vec<SpanData>) -> opentelemetry_sdk::error::OTelSdkResult {
            self.0.lock().unwrap().extend(batch);
            Ok(())
        }
    }

    #[test]
    fn metrics_reach_otlp_collector() {
        use opentelemetry::metrics::MeterProvider;
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                if let Ok((s, _)) = listener.accept() {
                    break s;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                socket.read_exact(&mut b).unwrap();
                head.push(b[0]);
                assert!(head.len() < 8192);
            }
            let head = String::from_utf8(head).unwrap().to_lowercase();
            assert!(head.starts_with("post /v1/metrics http/1.1"));
            assert!(head.contains("application/x-protobuf"));
            let size: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert!(size < 65536);
            let mut body = vec![0; size];
            socket.read_exact(&mut body).unwrap();
            use opentelemetry_proto::tonic::{
                collector::metrics::v1::ExportMetricsServiceRequest,
                common::v1::any_value::Value as AttributeValue,
                metrics::v1::{metric::Data, number_data_point::Value},
            };
            use prost::Message;
            let decoded = ExportMetricsServiceRequest::decode(body.as_slice()).unwrap();
            let metrics: Vec<_> = decoded
                .resource_metrics
                .iter()
                .flat_map(|r| &r.scope_metrics)
                .flat_map(|s| &s.metrics)
                .collect();
            let completed = metrics
                .iter()
                .find(|m| m.name == "httpjet.pipeline.requests.completed")
                .unwrap();
            let Some(Data::Sum(sum)) = &completed.data else {
                panic!("expected sum")
            };
            assert!(sum.is_monotonic);
            assert_eq!(sum.data_points.len(), 1);
            let point = &sum.data_points[0];
            assert_eq!(point.value, Some(Value::AsInt(3)));
            assert_eq!(point.attributes.len(), 1);
            assert_eq!(point.attributes[0].key, "http.response.status_code");
            assert_eq!(
                point.attributes[0].value.as_ref().unwrap().value,
                Some(AttributeValue::IntValue(200))
            );
            let duration = metrics
                .iter()
                .find(|m| m.name == "httpjet.pipeline.response_head.duration")
                .unwrap();
            assert_eq!(duration.unit, "s");
            let Some(Data::Histogram(histogram)) = &duration.data else {
                panic!("expected histogram")
            };
            assert_eq!(histogram.data_points.len(), 1);
            let point = &histogram.data_points[0];
            assert_eq!(point.count, 3);
            assert_eq!(point.sum, Some(0.375));
            assert_eq!(point.bucket_counts.iter().sum::<u64>(), 3);
            assert_eq!(point.attributes, sum.data_points[0].attributes);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_http_client(BoundedClient::new().unwrap())
            .with_endpoint(format!("http://{addr}/v1/metrics"))
            .build()
            .unwrap();
        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
            .with_interval(Duration::from_secs(3600))
            .build();
        let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_reader(reader)
            .build();
        let meter = provider.meter("test");
        let metrics = RequestMetrics::new(&meter);
        for _ in 0..3 {
            metrics.response_head(http::StatusCode::OK, Duration::from_millis(125));
        }
        provider.force_flush().unwrap();
        server.join().unwrap();
        // Shutdown can perform a final export; a closed collector must remain bounded.
        let start = std::time::Instant::now();
        let _ = provider.shutdown();
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn collector_http_boundaries() {
        use std::io::{Read, Write};
        let client = BoundedClient::new().unwrap();
        for mode in ["large", "redirect", "stall"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut b = [0];
                    socket.read_exact(&mut b).unwrap();
                    header.push(b[0]);
                    assert!(header.len() < 8192);
                }
                match mode {
                    "large" => {
                        let _ =
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n");
                        let _ = socket.write_all(&vec![b'a'; 65537]);
                    }
                    "redirect" => {
                        socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n").unwrap();
                    }
                    _ => {
                        let mut b = [0];
                        let _ = socket.read(&mut b);
                    }
                }
            });
            let request = http::Request::builder()
                .uri(format!("http://{addr}/"))
                .body(bytes::Bytes::new())
                .unwrap();
            let start = std::time::Instant::now();
            let response = client.send_bounded(request);
            if mode == "redirect" {
                assert_eq!(response.unwrap().status(), 302);
            } else {
                assert!(response.is_err());
            }
            assert!(start.elapsed() < Duration::from_secs(3));
            server.join().unwrap();
        }
    }

    #[test]
    fn request_backend_parentage_and_real_otlp_export() {
        use std::io::{Read, Write};
        let captured = Capture(Arc::default());
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(captured.clone())
            .build();
        global::set_tracer_provider(provider.clone());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            request(async {
                backend(BackendKind::Generic, async {
                    let mut headers = http::HeaderMap::new();
                    inject(&mut headers);
                    let h = headers["traceparent"].to_str().unwrap();
                    assert_eq!(h.len(), 55);
                    assert!(h.starts_with("00-"));
                    Ok(http::Response::new(hj_core::Body::Empty))
                })
                .await
                .unwrap()
            })
            .await;
        });
        provider.force_flush().unwrap();
        let spans = captured.0.lock().unwrap().clone();
        assert_eq!(spans.len(), 2);
        let root = spans.iter().find(|s| s.name == "httpjet.request").unwrap();
        let child = spans.iter().find(|s| s.name == "httpjet.backend").unwrap();
        assert_eq!(child.parent_span_id, root.span_context.span_id());
        assert_eq!(child.span_context.trace_id(), root.span_context.trace_id());
        assert_eq!(root.attributes.len(), 1);
        assert_eq!(root.attributes[0].key.as_str(), "http.response.status_code");
        // The explicitly trusted gateway can join an existing distributed trace.
        captured.0.lock().unwrap().clear();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        let parent = extract_parent(&mut headers, true);
        rt.block_on(request_with_parent(parent, async {
            http::Response::new(hj_core::Body::Empty)
        }));
        let joined = captured.0.lock().unwrap().clone();
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].parent_span_id.to_string(), "00f067aa0ba902b7");
        assert_eq!(
            joined[0].span_context.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        captured.0.lock().unwrap().clear();
        let mut wire_parent = None;
        rt.block_on(request(async {
            let (response, wire) = lsapi_test::roundtrip().await;
            wire_parent = Some(wire);
            response
        }));
        let lsapi_spans = captured.0.lock().unwrap().clone();
        let lsapi = lsapi_spans
            .iter()
            .find(|s| s.name == "httpjet.lsapi")
            .unwrap();
        let root = lsapi_spans
            .iter()
            .find(|s| s.name == "httpjet.request")
            .unwrap();
        assert_eq!(lsapi.span_kind, SpanKind::Client);
        assert_eq!(lsapi.parent_span_id, root.span_context.span_id());
        assert_eq!(
            wire_parent.unwrap(),
            format!(
                "00-{}-{}-01",
                lsapi.span_context.trace_id(),
                lsapi.span_context.span_id()
            )
        );
        // A retained streaming body must keep both request and backend spans open.
        captured.0.lock().unwrap().clear();
        rt.block_on(async {
            use http_body_util::BodyExt;
            for consume in [true, false] {
                captured.0.lock().unwrap().clear();
                let response = request(async {
                    backend(BackendKind::Generic, async {
                        let stream = http_body_util::Full::new(bytes::Bytes::from_static(b"body"))
                            .map_err(|e| -> hj_core::BoxError { match e {} })
                            .boxed();
                        Ok(http::Response::new(hj_core::Body::Stream(stream)))
                    })
                    .await
                    .unwrap()
                })
                .await;
                assert!(captured.0.lock().unwrap().is_empty());
                if consume {
                    let hj_core::Body::Stream(body) = response.into_body() else {
                        panic!("expected stream")
                    };
                    assert_eq!(body.collect().await.unwrap().to_bytes(), "body");
                } else {
                    drop(response);
                }
                let spans = captured.0.lock().unwrap();
                assert_eq!(spans.len(), 2);
                let outcome = if consume { "complete" } else { "cancelled" };
                assert!(
                    spans.iter().all(|s| s
                        .attributes
                        .iter()
                        .any(|a| a.key.as_str() == "httpjet.body.outcome"
                            && a.value.as_str() == outcome))
                );
            }
        });
        provider.shutdown().unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let collector = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                if let Ok((socket, _)) = listener.accept() {
                    break socket;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "collector not contacted"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() < 8192);
            }
            let header = String::from_utf8(header).unwrap().to_lowercase();
            assert!(header.starts_with("post /v1/traces http/1.1"));
            assert!(header.contains("application/x-protobuf"));
            let size: usize = header
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert!(size < 65536);
            let mut body = vec![0; size];
            socket.read_exact(&mut body).unwrap();
            use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
            use prost::Message;
            let decoded = ExportTraceServiceRequest::decode(body.as_slice()).unwrap();
            assert_eq!(decoded.resource_spans.len(), 1);
            let resource = &decoded.resource_spans[0];
            assert!(resource.resource.as_ref().unwrap().attributes.iter().any(|a| {
                a.key == "service.name" && a.value.as_ref().is_some_and(|v| {
                    matches!(&v.value, Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s)) if s == "httpjet.synthetic")
                })
            }));
            let spans: Vec<_> = resource.scope_spans.iter().flat_map(|s| &s.spans).collect();
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].name, "synthetic.export");
            assert_eq!(spans[0].trace_id.len(), 16);
            assert_eq!(spans[0].span_id.len(), 8);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_http_client(BoundedClient::new().unwrap())
            .with_endpoint(format!("http://{addr}/v1/traces"))
            .with_timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(
                batch::Processor::new(exporter, 16, 4, Duration::from_millis(50)).unwrap(),
            )
            .with_resource(
                opentelemetry_sdk::Resource::builder_empty()
                    .with_service_name("httpjet.synthetic")
                    .build(),
            )
            .build();
        let tracer = provider.tracer("httpjet.test");
        let mut span = tracer.start("synthetic.export");
        opentelemetry::trace::Span::end(&mut span);
        provider.force_flush().unwrap();
        provider.shutdown().unwrap();
        collector.join().unwrap();
    }
}
