use std::time::Instant;

/// Lab-only counters emitted when a connection closes. The short sample starts
/// when the loop observes a ready response and ends after its batch flush.
#[derive(Default)]
pub(super) struct SendTiming {
    first_short: Option<Instant>,
    short_only_us: [u64; 17],
    with_bulk_us: [u64; 17],
    flushes: u64,
    over_64k: u64,
    max_wire_bytes: usize,
}

impl SendTiming {
    pub(super) fn short_ready(&mut self) {
        self.first_short.get_or_insert_with(Instant::now);
    }

    pub(super) fn flushed(&mut self, bytes: usize, bulk: bool) {
        self.flushes += 1;
        self.over_64k += u64::from(bytes > 64 * 1024);
        self.max_wire_bytes = self.max_wire_bytes.max(bytes);
        if let Some(start) = self.first_short.take() {
            let micros = start.elapsed().as_micros();
            let bucket = micros.checked_ilog2().unwrap_or(0).min(16) as usize;
            let histogram = if bulk {
                &mut self.with_bulk_us
            } else {
                &mut self.short_only_us
            };
            histogram[bucket] += 1;
        }
    }
}

impl Drop for SendTiming {
    fn drop(&mut self) {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "h2 send timing flushes={} over_64k={} max_wire_bytes={} short_only_us={:?} with_bulk_us={:?}",
            self.flushes,
            self.over_64k,
            self.max_wire_bytes,
            self.short_only_us,
            self.with_bulk_us
        );
    }
}
