//! Large buffered encodes on the bridged request path, run in slices.
//!
//! The encode stays on its own task and thread and gives the worker back between
//! slices, so a multi-megabyte body does not stall the requests queued behind it.
//! Nothing moves to another thread: the allocator heap and codec contexts are the
//! worker's own.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct BufferedWork {
    threshold: AtomicU64,
    encodes: AtomicU64,
    bytes: AtomicU64,
}

impl BufferedWork {
    pub fn set_threshold(&self, bytes: u64) {
        self.threshold.store(bytes, Ordering::Release);
    }

    /// Smallest body encoded in slices; zero turns the feature off.
    pub fn threshold(&self) -> u64 {
        self.threshold.load(Ordering::Acquire)
    }

    pub fn record_encode(&self, bytes: u64) {
        self.encodes.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn encodes(&self) -> u64 {
        self.encodes.load(Ordering::Relaxed)
    }

    pub fn encoded_input_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}
