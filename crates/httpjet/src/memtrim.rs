//! Periodic mimalloc OS-trim.
//!
//! mimalloc v3 retains freed arena memory for fast reuse; under sustained memory
//! pressure on a shared box that cold, committed memory gets swapped out instead
//! of returned to the OS (prod observed ~15 GiB of `[anon:mimalloc]` in swap while
//! the live working set was ~2 GiB). `mi_collect(true)` forces mimalloc to run a
//! full reclaim and hand retained pages back to the OS. We run it on a low
//! frequency, optionally gated on an RSS+swap threshold so a small, healthy
//! process never pays the collect cost. The systemd env drop-in
//! (MIMALLOC_ARENA_EAGER_COMMIT=0 / MIMALLOC_ALLOW_THP=0) is the steady-state
//! lever; this task is the safety net that drains retention after a burst.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;

static THREAD_COLLECT_EPOCH: AtomicU64 = AtomicU64::new(0);
static CLOSE_COLLECT_THRESHOLD_BYTES: AtomicU64 = AtomicU64::new(u64::MAX);
static LAST_CLOSE_COLLECT_MS: AtomicU64 = AtomicU64::new(0);

const DEFAULT_CLOSE_COLLECT_THRESHOLD_BYTES: u64 = 384 * 1024 * 1024;
const CLOSE_COLLECT_MIN_INTERVAL_MS: u64 = 30_000;

thread_local! {
    static LAST_THREAD_COLLECT_EPOCH: Cell<u64> = const { Cell::new(0) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemSnapshot {
    pub rss: u64,
    pub swap: u64,
}

/// Background task: every `interval`, if process RSS+swap is at least
/// `threshold_bytes` (0 = always), force mimalloc to release retained memory to
/// the OS. Runs until `shutdown` is cancelled (then exits without a final collect
/// — the process is going away anyway).
pub async fn run_trim(interval: Duration, threshold_bytes: u64, shutdown: CancellationToken) {
    tracing::info!(
        secs = interval.as_secs(),
        threshold_mib = threshold_bytes / (1024 * 1024),
        "mimalloc periodic OS-trim enabled"
    );
    loop {
        let stopping = tokio::select! {
            _ = tokio::time::sleep(interval) => false,
            _ = shutdown.cancelled() => true,
        };
        if stopping {
            break;
        }
        let before = read_snapshot();
        if should_collect(before, threshold_bytes) {
            // The full reclaim does madvise/decommit syscalls (single-ms to tens-of-ms);
            // run it on the blocking pool so it never stalls an async worker mid-request
            // (mirrors the page-cache maintenance tick). A JoinError (task panic) is the
            // only failure and is intentionally ignored — the next tick retries.
            let epoch = request_thread_collect();
            let _ = tokio::task::spawn_blocking(move || {
                force_collect();
                mark_current_thread_collected(epoch);
            })
            .await;
            let after = read_snapshot();
            tracing::debug!(
                epoch,
                rss_mib = before.map_or(0, |m| m.rss / (1024 * 1024)),
                swap_mib = before.map_or(0, |m| m.swap / (1024 * 1024)),
                rss_after_mib = after.map_or(0, |m| m.rss / (1024 * 1024)),
                swap_after_mib = after.map_or(0, |m| m.swap / (1024 * 1024)),
                "mimalloc collect(force) ran"
            );
        }
    }
}

/// Ask every long-lived runtime thread to collect its own mimalloc heap at its next safe hook.
pub fn request_thread_collect() -> u64 {
    THREAD_COLLECT_EPOCH.fetch_add(1, Ordering::AcqRel) + 1
}

/// Cheap runtime-thread hook: one relaxed load unless a collect epoch is pending.
pub fn collect_if_requested_on_thread() {
    let epoch = THREAD_COLLECT_EPOCH.load(Ordering::Acquire);
    if epoch == 0 {
        return;
    }
    LAST_THREAD_COLLECT_EPOCH.with(|last| {
        if last.get() != epoch {
            force_collect();
            last.set(epoch);
        }
    });
}

pub fn configure_connection_close_trim(periodic_threshold_bytes: u64) {
    let threshold = if periodic_threshold_bytes == 0 {
        0
    } else {
        periodic_threshold_bytes.min(DEFAULT_CLOSE_COLLECT_THRESHOLD_BYTES)
    };
    CLOSE_COLLECT_THRESHOLD_BYTES.store(threshold, Ordering::Release);
}

pub fn disable_connection_close_trim() {
    CLOSE_COLLECT_THRESHOLD_BYTES.store(u64::MAX, Ordering::Release);
}

pub fn collect_after_connection_close() {
    let threshold = CLOSE_COLLECT_THRESHOLD_BYTES.load(Ordering::Acquire);
    if threshold == u64::MAX {
        return;
    }
    let now = unix_ms();
    if !claim_close_collect_window(now) {
        return;
    }

    let before = read_snapshot();
    if !should_collect(before, threshold) {
        return;
    }
    let epoch = request_thread_collect();
    tracing::debug!(
        epoch,
        rss_mib = before.map_or(0, |m| m.rss / (1024 * 1024)),
        swap_mib = before.map_or(0, |m| m.swap / (1024 * 1024)),
        "mimalloc collect(force) requested after connection close"
    );
}

/// Force a full mimalloc reclaim on the current thread.
pub fn force_collect() {
    // SAFETY: `mi_collect` is mimalloc's documented, thread-safe public entry point.
    // It walks the allocator's own heaps/arenas, takes no pointer into our memory,
    // and `force=true` runs the full reclaim. It is the same libmimalloc backing
    // #[global_allocator], so there is no cross-allocator hazard.
    unsafe { libmimalloc_sys::mi_collect(true) };
}

/// Force a reclaim and log before/after RSS. Intended for one-shot off-path burst cleanup.
pub fn force_collect_logged(reason: &'static str) {
    let epoch = request_thread_collect();
    let before = read_snapshot();
    force_collect();
    mark_current_thread_collected(epoch);
    let after = read_snapshot();
    tracing::info!(
        reason,
        epoch,
        rss_mib = before.map_or(0, |m| m.rss / (1024 * 1024)),
        swap_mib = before.map_or(0, |m| m.swap / (1024 * 1024)),
        rss_after_mib = after.map_or(0, |m| m.rss / (1024 * 1024)),
        swap_after_mib = after.map_or(0, |m| m.swap / (1024 * 1024)),
        "mimalloc collect(force) ran"
    );
}

fn mark_current_thread_collected(epoch: u64) {
    LAST_THREAD_COLLECT_EPOCH.with(|last| last.set(epoch));
}

/// Parse VmRSS + VmSwap (bytes) from `/proc/self/status`. `None` off Linux or on
/// any parse failure (caller then treats the gate as "always trim").
fn read_snapshot() -> Option<MemSnapshot> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_status_snapshot(&s)
}

fn parse_status_snapshot(s: &str) -> Option<MemSnapshot> {
    let mut rss = None;
    let mut swap = None;
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            rss = parse_kib(v);
        } else if let Some(v) = line.strip_prefix("VmSwap:") {
            swap = parse_kib(v);
        }
    }
    Some(MemSnapshot {
        rss: rss?,
        swap: swap?,
    })
}

fn should_collect(snapshot: Option<MemSnapshot>, threshold_bytes: u64) -> bool {
    threshold_bytes == 0
        || snapshot
            .map(|m| m.rss.saturating_add(m.swap) >= threshold_bytes)
            .unwrap_or(true)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn claim_close_collect_window(now_ms: u64) -> bool {
    loop {
        let prev = LAST_CLOSE_COLLECT_MS.load(Ordering::Acquire);
        if prev != 0 && now_ms.saturating_sub(prev) < CLOSE_COLLECT_MIN_INTERVAL_MS {
            return false;
        }
        if LAST_CLOSE_COLLECT_MS
            .compare_exchange(prev, now_ms, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }
    }
}

/// `"  2156 kB"` → bytes.
fn parse_kib(field: &str) -> Option<u64> {
    field
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()
        .map(|k| k * 1024)
}

#[cfg(test)]
mod tests {
    use super::{
        MemSnapshot, collect_if_requested_on_thread, parse_kib, parse_status_snapshot,
        request_thread_collect, should_collect,
    };

    #[test]
    fn parse_kib_handles_status_field() {
        assert_eq!(parse_kib("  2156 kB"), Some(2156 * 1024));
        assert_eq!(parse_kib("\t0 kB"), Some(0));
        assert_eq!(parse_kib("12345 kB\n"), Some(12345 * 1024));
        assert_eq!(parse_kib("   "), None);
        assert_eq!(parse_kib("notanumber kB"), None);
    }

    #[test]
    fn parse_status_snapshot_extracts_rss_and_swap() {
        let s = "Name:\thttpjet\nVmRSS:\t  2048 kB\nVmSwap:\t  512 kB\n";
        assert_eq!(
            parse_status_snapshot(s),
            Some(MemSnapshot {
                rss: 2048 * 1024,
                swap: 512 * 1024,
            })
        );
    }

    #[test]
    fn threshold_gate_treats_unknown_as_collect() {
        assert!(should_collect(None, 768 * 1024 * 1024));
        assert!(should_collect(Some(MemSnapshot { rss: 10, swap: 0 }), 0));
        assert!(!should_collect(
            Some(MemSnapshot {
                rss: 100 * 1024 * 1024,
                swap: 0,
            }),
            768 * 1024 * 1024,
        ));
        assert!(should_collect(
            Some(MemSnapshot {
                rss: 700 * 1024 * 1024,
                swap: 100 * 1024 * 1024,
            }),
            768 * 1024 * 1024,
        ));
    }

    #[test]
    fn requested_collect_epoch_increases() {
        let a = request_thread_collect();
        let b = request_thread_collect();
        assert!(b > a);
        collect_if_requested_on_thread();
    }
}
