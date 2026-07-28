//! Per-request correlation id.
//!
//! A single [`ReqId`] is minted once per request at the transport boundary and
//! threaded through [`crate::ReqCtx`] into every log sink (access, error,
//! php-slow) so one request is joinable across all of them. Minting is a single
//! relaxed atomic increment finalized through a per-process seed — no syscall,
//! no lock, no RNG on the hot path (mirrors the lock-free per-thread counter
//! idiom the metrics shards use).

use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Per-request correlation id. `Copy` so cloning a `ReqCtx` (e.g. a background
/// SWR-refresh subrequest) inherits the parent's id for free, and so adding it
/// to `ReqCtx` does not perturb the derived `Clone`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReqId(u64);

static COUNTER: AtomicU64 = AtomicU64::new(0);
static SEED: OnceLock<u64> = OnceLock::new();

/// Per-process seed, minted once. Mixing it into every id keeps ids from
/// repeating across a restart and from being trivially enumerable, while
/// minting stays a single relaxed increment.
fn seed() -> u64 {
    *SEED.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        splitmix64(nanos ^ ((std::process::id() as u64) << 32) ^ 0x9E37_79B9_7F4A_7C15)
    })
}

/// Mint a fresh request id: one relaxed `fetch_add` + a finalizing mix.
#[inline]
pub fn next() -> ReqId {
    let n = COUNTER.fetch_add(1, Relaxed);
    ReqId(splitmix64(seed().wrapping_add(n)))
}

/// SplitMix64 finalizer — turns the sequential counter into a well-distributed
/// 64-bit value so consecutive ids share no visible prefix.
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

impl ReqId {
    /// The raw 64-bit value (for hashing / numeric joins).
    #[inline]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// The `Default` is the all-zero sentinel (`0000000000000000`) — only for test
/// helpers and contexts that predate a real mint; production always mints via
/// [`next`] at the transport boundary.
impl Default for ReqId {
    fn default() -> Self {
        ReqId(0)
    }
}

impl fmt::Display for ReqId {
    /// Lower-hex, zero-padded to 16 chars, written straight through the
    /// formatter — no allocation. Callers that need an owned value use
    /// `.to_string()` (one small alloc, off the per-request fast path).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}
