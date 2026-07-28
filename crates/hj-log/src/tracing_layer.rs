//! A [`tracing_subscriber::Layer`] that funnels `WARN` and `ERROR` tracing events
//! into the rolling [`ErrorLogger`] file, so server-side faults survive in a
//! persistent, rotated error log instead of only the (rotatable, mixed) journal.
//!
//! Layered alongside the normal `fmt` (stdout) layer: every event still reaches
//! stdout; warn+ additionally lands in `httpjet_error.log`.
//!
//! ## Recursion guard (load-bearing)
//!
//! The writer task itself reports failures via `tracing::error!(target: "hj_log",
//! …)`. Without a guard, a write failure would become a tracing event that this
//! layer forwards back into the same writer — an infinite loop. We therefore DROP
//! any event whose target is exactly `hj_log`. Those events still reach stdout
//! (the `fmt` layer) and the stderr fallback in [`crate`], so nothing is lost;
//! they simply never re-enter the file writer.

use std::fmt::Write as _;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::{ErrorLogger, LogLevel};

/// Tracing layer writing warn+error events into an [`ErrorLogger`].
pub struct ErrorLogLayer {
    logger: ErrorLogger,
}

impl ErrorLogLayer {
    /// Build a layer that writes into `logger`. Clone the logger if the caller
    /// also needs it for SIGUSR1 `reopen()`.
    pub fn new(logger: ErrorLogger) -> Self {
        ErrorLogLayer { logger }
    }
}

impl<S: Subscriber> Layer<S> for ErrorLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let md = event.metadata();
        // tracing's `Level` Ord: ERROR < WARN < INFO < DEBUG < TRACE, so "more
        // verbose than WARN" is `> Level::WARN`. Keep only WARN and ERROR.
        if *md.level() > Level::WARN {
            return;
        }
        // Recursion guard: the writer reports its own failures via
        // `tracing::error!(target: "hj_log", …)` — the ONLY events whose write could
        // be triggered by this layer. Drop exactly that target so a write failure
        // can't loop back into the writer. (Exact match, not a prefix, so events from
        // the hj_log crate's own module paths — e.g. in tests — are not swallowed.)
        if md.target() == "hj_log" {
            return;
        }

        let mut collector = FieldCollector::default();
        event.record(&mut collector);

        // Compose: "<target> <message> <k=v …> (file:line)". The ErrorLogger
        // prepends the timestamp + "[LEVEL]".
        let mut line = String::with_capacity(collector.message.len() + collector.kvs.len() + 32);
        line.push_str(md.target());
        if !collector.message.is_empty() {
            line.push(' ');
            line.push_str(&collector.message);
        }
        if !collector.kvs.is_empty() {
            line.push(' ');
            line.push_str(&collector.kvs);
        }
        if let (Some(file), Some(lineno)) = (md.file(), md.line()) {
            let _ = write!(line, " ({file}:{lineno})");
        }

        let level = if *md.level() == Level::ERROR {
            LogLevel::Error
        } else {
            LogLevel::Warn
        };
        self.logger.log(level, line);
    }
}

/// Flattens an event's fields into a human line: the `message` field becomes the
/// main text; all other fields are appended as `key=value`.
#[derive(Default)]
struct FieldCollector {
    message: String,
    kvs: String,
}

impl Visit for FieldCollector {
    // The catch-all: `Visit`'s typed `record_*` methods default to `record_debug`,
    // so implementing this one captures every field (Display `%x`, Debug `?x`, and
    // typed values alike).
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            // `Arguments`/`DisplayValue` Debug renders the formatted text (no quotes).
            let _ = write!(self.message, "{value:?}");
        } else {
            if !self.kvs.is_empty() {
                self.kvs.push(' ');
            }
            let _ = write!(self.kvs, "{}={:?}", field.name(), value);
        }
    }

    // Render string fields without the Debug quotes for readability.
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            if !self.kvs.is_empty() {
                self.kvs.push(' ');
            }
            let _ = write!(self.kvs, "{}={}", field.name(), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorLogger;
    use tracing_subscriber::prelude::*;

    /// WARN + ERROR land in the file; INFO and `target:"hj_log"` events are dropped
    /// (the recursion guard). Uses a real ErrorLogger over a temp file.
    #[tokio::test(flavor = "multi_thread")]
    async fn layer_writes_warn_error_and_drops_info_and_hj_log() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("hj-errlayer-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let logger = ErrorLogger::spawn(&path, 0, 0, false);
        let layer = ErrorLogLayer::new(logger.clone());
        // `set_global_default` (unlike scoped `with_default`) raises the process-wide
        // runtime max level, so the `tracing::*` macros below are actually enabled.
        // This is the only subscriber-installing test in this (writer-only) binary.
        tracing::subscriber::set_global_default(
            tracing_subscriber::registry()
                .with(layer)
                .with(tracing_subscriber::filter::LevelFilter::TRACE),
        )
        .expect("install global subscriber for the layer test");

        tracing::error!(code = 502, "backend down");
        tracing::warn!("slow upstream");
        tracing::info!("this should NOT be in the error log");
        tracing::error!(target: "hj_log", "writer self-report should be dropped");

        // Flush the writer to disk.
        logger.shutdown().await;
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);

        assert!(
            body.contains("[ERROR]") && body.contains("backend down"),
            "got: {body}"
        );
        assert!(body.contains("code=502"), "kv field missing: {body}");
        assert!(
            body.contains("[WARN]") && body.contains("slow upstream"),
            "got: {body}"
        );
        assert!(!body.contains("this should NOT"), "info leaked: {body}");
        assert!(
            !body.contains("writer self-report"),
            "recursion guard failed: {body}"
        );
    }
}
