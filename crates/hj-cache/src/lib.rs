//! Shared cache primitives for httpjet.
//!
//! The former two-tier (in-mem + mmap) static `FileCache` had no runtime
//! consumers — the binary's static serving goes through `hj-pagecache`, and the
//! page index builds on this crate's [`sharded::ShardedCache`] — so it was
//! removed (#298). What remains is:
//!
//! * [`sharded`] — the shared, strongly-consistent sharded byte-weighted LRU
//!   primitive that `hj-pagecache`'s page store indexes with.
//! * [`CacheCaps`] — tuning-derived capacity caps (`from_tuning`), still used by
//!   the binary to size the page-cache `StoreConfig`.

use hj_config::model::Tuning;

/// The shared, strongly-consistent sharded byte-weighted LRU primitive. Lives here (not a
/// separate crate) so it is the one in-process cache `hj-pagecache`'s page store
/// builds on (`hj_cache::sharded::ShardedCache`).
pub mod sharded;

/// Default in-memory tier cap when none can be derived: 256 MiB.
///
/// Kept modest even though [`Tuning`] may ask for far more; `from_tuning`
/// honours the configured value but clamps it.
const DEFAULT_IN_MEM_CAP: u64 = 256 * 1024 * 1024;

/// Default per-file ceiling for the in-memory tier: 1 MiB.
const DEFAULT_MAX_IN_MEM_FILE: u64 = 1024 * 1024;

/// Default mmap tier cap: 512 MiB of mapped address space.
const DEFAULT_MMAP_CAP: u64 = 512 * 1024 * 1024;

/// Default per-file ceiling for the mmap tier: 16 MiB.
const DEFAULT_MAX_MMAP_FILE: u64 = 16 * 1024 * 1024;

/// Hard upper clamp on the in-mem tier, regardless of config: 1 GiB.
const ABS_MAX_IN_MEM_CAP: u64 = 1024 * 1024 * 1024;

/// Hard upper clamp on the mmap tier, regardless of config: 2 GiB.
const ABS_MAX_MMAP_CAP: u64 = 2 * 1024 * 1024 * 1024;

/// Tunable, soft-capped capacities derived from the server `<tuning>` block.
#[derive(Debug, Clone, Copy)]
pub struct CacheCaps {
    /// Largest single file (bytes) eligible for the in-memory tier.
    pub max_in_mem_file: u64,
    /// Total in-memory tier budget (bytes) before LRU eviction kicks in.
    pub total_in_mem: u64,
    /// Largest single file (bytes) eligible for the mmap tier.
    pub max_mmap_file: u64,
    /// Total mapped-region budget (bytes) before LRU eviction kicks in.
    pub total_mmap: u64,
}

impl Default for CacheCaps {
    fn default() -> Self {
        CacheCaps {
            max_in_mem_file: DEFAULT_MAX_IN_MEM_FILE,
            total_in_mem: DEFAULT_IN_MEM_CAP,
            max_mmap_file: DEFAULT_MAX_MMAP_FILE,
            total_mmap: DEFAULT_MMAP_CAP,
        }
    }
}

/// Clamp a configured in-mem cap to the modest absolute ceiling.
fn clamp_in_mem_cap(requested: u64) -> u64 {
    requested.clamp(1, ABS_MAX_IN_MEM_CAP)
}

/// Clamp a configured mmap cap to the absolute ceiling.
fn clamp_mmap_cap(requested: u64) -> u64 {
    requested.clamp(1, ABS_MAX_MMAP_CAP)
}

impl CacheCaps {
    /// Derive caps from server [`Tuning`], clamping the totals so we never
    /// promise more than this box can spare even if the config asks for it.
    ///
    /// LiteSpeed's defaults (e.g. 4 GiB `total_in_mem_cache_size`) are far too
    /// large for a small box, so the totals are clamped while the per-file
    /// ceilings are honoured directly.
    pub fn from_tuning(t: &Tuning) -> Self {
        let max_in_mem_file = if t.max_cached_file_size == 0 {
            DEFAULT_MAX_IN_MEM_FILE
        } else {
            t.max_cached_file_size
        };
        let max_mmap_file = if t.max_mmap_file_size == 0 {
            DEFAULT_MAX_MMAP_FILE
        } else {
            t.max_mmap_file_size
        };
        let total_in_mem = if t.total_in_mem_cache_size == 0 {
            DEFAULT_IN_MEM_CAP
        } else {
            clamp_in_mem_cap(t.total_in_mem_cache_size)
        };
        let total_mmap = if t.total_mmap_cache_size == 0 {
            DEFAULT_MMAP_CAP
        } else {
            clamp_mmap_cap(t.total_mmap_cache_size)
        };
        CacheCaps {
            // A per-file ceiling above its tier total is nonsensical; clamp it.
            max_in_mem_file: max_in_mem_file.min(total_in_mem),
            total_in_mem,
            // The mmap tier should accept everything the in-mem tier rejects, up
            // to its own per-file ceiling, but never more than the tier total.
            max_mmap_file: max_mmap_file.max(max_in_mem_file).min(total_mmap),
            total_mmap,
        }
    }
}

#[cfg(test)]
mod caps_tests {
    use super::*;

    #[test]
    fn caps_from_tuning_are_clamped() {
        let t = Tuning::default(); // total_in_mem_cache_size = 4 GiB
        let caps = CacheCaps::from_tuning(&t);
        assert!(
            caps.total_in_mem <= ABS_MAX_IN_MEM_CAP,
            "in-mem cap must be clamped, got {}",
            caps.total_in_mem
        );
        assert!(caps.total_mmap <= ABS_MAX_MMAP_CAP);
        assert!(caps.max_in_mem_file <= caps.total_in_mem);
    }
}
