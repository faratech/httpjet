//! Loss-accounted, nonblocking SDK SpanProcessor. The SDK's batch processor
//! keeps its queue-drop count private; this adapter makes loss observable.
use opentelemetry::Context;
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    trace::{Span, SpanData, SpanExporter, SpanProcessor},
};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub(super) struct Stats {
    pub queued: AtomicU64,
    pub dropped: AtomicU64,
    pub exported: AtomicU64,
    pub failed: AtomicU64,
}

struct QueuedSpan {
    span: Option<SpanData>,
    stats: Arc<Stats>,
}
impl Drop for QueuedSpan {
    fn drop(&mut self) {
        self.stats.queued.fetch_sub(1, Ordering::Relaxed);
        // Includes queue overflow, closed worker, and the enqueue/shutdown race.
        if self.span.is_some() {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}
enum Message {
    Span(QueuedSpan),
    Flush(mpsc::SyncSender<OTelSdkResult>),
    Resource(Resource),
}

#[derive(Debug, Clone)]
pub(super) struct Processor {
    tx: mpsc::SyncSender<Message>,
    stop: Arc<AtomicBool>,
    done: Arc<(Mutex<Option<bool>>, Condvar)>,
    pub stats: Arc<Stats>,
}

fn export<E: SpanExporter>(
    exporter: &E,
    batch: &mut Vec<SpanData>,
    stats: &Stats,
) -> OTelSdkResult {
    if batch.is_empty() {
        return Ok(());
    }
    let count = batch.len() as u64;
    let result = futures_executor::block_on(exporter.export(std::mem::take(batch)));
    if result.is_ok() {
        &stats.exported
    } else {
        &stats.failed
    }
    .fetch_add(count, Ordering::Relaxed);
    result
}

impl Processor {
    pub fn new<E: SpanExporter + 'static>(
        mut exporter: E,
        capacity: usize,
        batch_size: usize,
        interval: Duration,
    ) -> std::io::Result<Self> {
        assert!(capacity > 0 && batch_size > 0 && !interval.is_zero());
        let (tx, rx) = mpsc::sync_channel(capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::new((Mutex::new(None), Condvar::new()));
        let stats = Arc::new(Stats::default());
        let worker_stop = stop.clone();
        let worker_done = done.clone();
        let worker_stats = stats.clone();
        std::thread::Builder::new()
            .name("httpjet-otel-export".into())
            .spawn(move || {
                let mut batch = Vec::with_capacity(batch_size);
                let mut last = Instant::now();
                loop {
                    let message = if worker_stop.load(Ordering::Acquire) {
                        match rx.try_recv() {
                            Ok(m) => Ok(m),
                            Err(_) => break,
                        }
                    } else {
                        rx.recv_timeout(interval.saturating_sub(last.elapsed()))
                    };
                    match message {
                        Ok(Message::Span(mut queued)) => {
                            batch.push(queued.span.take().unwrap());
                            drop(queued);
                            if batch.len() >= batch_size {
                                let _ = export(&exporter, &mut batch, &worker_stats);
                                last = Instant::now();
                            }
                        }
                        Ok(Message::Flush(reply)) => {
                            let _ = reply.send(export(&exporter, &mut batch, &worker_stats));
                            last = Instant::now();
                        }
                        Ok(Message::Resource(resource)) => exporter.set_resource(&resource),
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            let _ = export(&exporter, &mut batch, &worker_stats);
                            last = Instant::now();
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                let result = export(&exporter, &mut batch, &worker_stats);
                let shutdown = exporter.shutdown_with_timeout(Duration::from_secs(2));
                *worker_done.0.lock().unwrap() = Some(result.and(shutdown).is_ok());
                worker_done.1.notify_all();
            })?;
        Ok(Self {
            tx,
            stop,
            done,
            stats,
        })
    }

    fn send_until(&self, mut message: Message, deadline: Instant) -> OTelSdkResult {
        loop {
            match self.tx.try_send(message) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(OTelSdkError::AlreadyShutdown);
                }
                Err(mpsc::TrySendError::Full(m)) => message = m,
            }
            if Instant::now() >= deadline {
                return Err(OTelSdkError::Timeout(Duration::ZERO));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl SpanProcessor for Processor {
    fn on_start(&self, _: &mut Span, _: &Context) {}
    fn on_end(&self, span: SpanData) {
        if !span.span_context.is_sampled() {
            return;
        }
        if self.stop.load(Ordering::Acquire) {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.stats.queued.fetch_add(1, Ordering::Relaxed);
        // Never wait on collector IO or queue capacity on a request thread.
        let _ = self.tx.try_send(Message::Span(QueuedSpan {
            span: Some(span),
            stats: self.stats.clone(),
        }));
    }
    fn force_flush(&self) -> OTelSdkResult {
        if self.stop.load(Ordering::Acquire) {
            return Err(OTelSdkError::AlreadyShutdown);
        }
        let timeout = Duration::from_secs(3);
        let deadline = Instant::now() + timeout;
        let (tx, rx) = mpsc::sync_channel(1);
        self.send_until(Message::Flush(tx), deadline)?;
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| OTelSdkError::Timeout(timeout))?
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.stop.store(true, Ordering::Release);
        let result = self.done.0.lock().unwrap();
        let (result, _) = self
            .done
            .1
            .wait_timeout_while(result, timeout, |r| r.is_none())
            .unwrap();
        match *result {
            Some(true) => Ok(()),
            Some(false) => Err(OTelSdkError::InternalFailure(
                "telemetry final export or shutdown failed".into(),
            )),
            None => Err(OTelSdkError::Timeout(timeout)),
        }
    }
    fn set_resource(&mut self, resource: &Resource) {
        // SDK calls this during provider construction, before request serving.
        // A fresh processor's queue is empty, so the command cannot overflow.
        self.tx
            .try_send(Message::Resource(resource.clone()))
            .expect("initial telemetry resource queue");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::{Span as _, Tracer, TracerProvider};
    use opentelemetry_sdk::trace::SdkTracerProvider;

    #[derive(Debug)]
    struct GateExporter {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        first: AtomicBool,
        fail: Arc<AtomicBool>,
    }
    impl SpanExporter for GateExporter {
        async fn export(&self, _: Vec<SpanData>) -> OTelSdkResult {
            if self.first.swap(false, Ordering::Relaxed) {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            if self.fail.load(Ordering::Relaxed) {
                Err(OTelSdkError::InternalFailure("synthetic outage".into()))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn queue_saturation_loss_recovery_and_flush() {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let fail = Arc::new(AtomicBool::new(true));
        let processor = Processor::new(
            GateExporter {
                entered: entered_tx,
                release: Mutex::new(release_rx),
                first: AtomicBool::new(true),
                fail: fail.clone(),
            },
            2,
            1,
            Duration::from_millis(20),
        )
        .unwrap();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor.clone())
            .build();
        let tracer = provider.tracer("queue-test");
        tracer.start("blocking-first").end();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        for _ in 0..100 {
            tracer.start("burst").end();
        }
        assert!(
            start.elapsed() < Duration::from_millis(250),
            "request path must not wait on collector"
        );
        assert_eq!(processor.stats.queued.load(Ordering::Relaxed), 2);
        assert_eq!(processor.stats.dropped.load(Ordering::Relaxed), 98);
        assert_eq!(processor.stats.exported.load(Ordering::Relaxed), 0);
        release_tx.send(()).unwrap();
        // Earlier full batches may fail before this flush barrier. Those losses
        // are reported by counters, independently of the final batch result.
        let _ = processor.force_flush();
        assert_eq!(processor.stats.failed.load(Ordering::Relaxed), 3);
        assert_eq!(processor.stats.queued.load(Ordering::Relaxed), 0);
        fail.store(false, Ordering::Relaxed);
        tracer.start("recovered").end();
        processor.force_flush().unwrap();
        assert_eq!(processor.stats.exported.load(Ordering::Relaxed), 1);
        processor
            .shutdown_with_timeout(Duration::from_secs(1))
            .unwrap();
        processor
            .shutdown_with_timeout(Duration::from_secs(1))
            .unwrap();
        tracer.start("after-shutdown").end();
        assert_eq!(processor.stats.dropped.load(Ordering::Relaxed), 99);
    }

    #[test]
    fn shutdown_wait_is_bounded_while_exporter_is_blocked() {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let processor = Processor::new(
            GateExporter {
                entered: entered_tx,
                release: Mutex::new(release_rx),
                first: AtomicBool::new(true),
                fail: Arc::new(AtomicBool::new(false)),
            },
            2,
            1,
            Duration::from_millis(20),
        )
        .unwrap();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor.clone())
            .build();
        provider.tracer("shutdown-test").start("blocked").end();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        assert!(matches!(
            processor.shutdown_with_timeout(Duration::from_millis(25)),
            Err(OTelSdkError::Timeout(_))
        ));
        assert!(start.elapsed() < Duration::from_millis(250));
        release_tx.send(()).unwrap();
        processor
            .shutdown_with_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(processor.stats.exported.load(Ordering::Relaxed), 1);
    }
}
