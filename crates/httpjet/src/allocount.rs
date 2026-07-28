//! Allocation-counting global allocator — the measurement harness for the h2
//! allocation-reduction campaign. The [`Counting`] wrapper is wired as
//! `#[global_allocator]` ONLY under `--features allocount`; otherwise this module
//! is inert ([`ALLOC_COUNT`] stays 0) and plain mimalloc is the allocator, so a
//! normal/PGO build pays nothing. The counter is read/reset via the loopback
//! `/__alloc-count` metrics route to measure allocs-per-request (reset → run a
//! fixed h2load → read → divide by request count). PGO does not change WHAT
//! allocates, so a non-PGO counting build gives a valid per-request alloc count.

#[cfg(feature = "allocount")]
use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::AtomicU64;
#[cfg(feature = "allocount")]
use std::sync::atomic::Ordering;

/// Total `alloc`/`alloc_zeroed`/`realloc` calls since process start (or last
/// `/__alloc-count?reset`). Only advances when [`Counting`] is the active global
/// allocator (i.e. under `--features allocount`); inert otherwise. Frees aren't
/// counted — the campaign metric is allocation *calls per request*.
pub static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);

/// mimalloc, instrumented to count allocation calls. A zero-cost passthrough to
/// `mimalloc::MiMalloc` plus one `Relaxed` atomic increment on each allocating call.
/// Only compiled when wired as the global allocator (`--features allocount`).
#[cfg(feature = "allocount")]
pub struct Counting;

#[cfg(feature = "allocount")]
unsafe impl GlobalAlloc for Counting {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.alloc(layout) }
    }
    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { mimalloc::MiMalloc.dealloc(ptr, layout) }
    }
    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.alloc_zeroed(layout) }
    }
    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.realloc(ptr, layout, new_size) }
    }
}
