//! Recycled heap memory for large, short-lived per-request values.
//!
//! Production mimalloc runs with `purge_delay=0`: a page whose last block is
//! freed is decommitted at once, and the next allocation faults it back in.
//! A per-request future or buffer of several KiB lands in a size class with
//! only a handful of blocks per page, so every burst of requests re-faulted
//! those pages. These pools keep freed memory for the next request instead:
//! [`Recycled`] for values that need a stable address (pinned futures), and
//! [`TieredPool`] for owned buffers.
//!
//! Both are per-thread free lists backed by a shared overflow list. A request
//! is often allocated on one thread and finished on another (a migrated task,
//! a tail task, a spawn from a single receiver loop); with per-thread lists
//! alone one thread's list overflows and frees while another's runs dry and
//! allocates. Moves between the tiers are batched, so the shared lock is taken
//! once per several values, not per request. Every tier is capped, so the pools
//! only grow to the peak concurrency they serve.

use std::alloc::Layout;
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};
use std::thread::LocalKey;

/// Distinct layouts pooled; further layouts fall through to the allocator.
const MAX_LAYOUTS: usize = 8;
/// Bytes of free slots one thread keeps per layout (at least one slot).
pub const LOCAL_POOL_BYTES: usize = 512 * 1024;
/// Bytes of free slots the shared overflow keeps per layout (at least one slot).
pub const SHARED_POOL_BYTES: usize = 1024 * 1024;

fn slots(bytes: usize, layout: Layout) -> usize {
    (bytes / layout.size()).max(1)
}

/// A free slot: plain memory of its bucket's layout.
struct Slot(NonNull<u8>);

// SAFETY: a free slot holds no value; it is memory owned by whichever list holds it.
unsafe impl Send for Slot {}

struct Bucket {
    layout: Layout,
    free: Vec<Slot>,
}

struct Pool {
    buckets: Vec<Bucket>,
}

impl Pool {
    const fn new() -> Self {
        Self {
            buckets: Vec::new(),
        }
    }

    fn bucket(&mut self, layout: Layout) -> Option<&mut Bucket> {
        let idx = match self.buckets.iter().position(|b| b.layout == layout) {
            Some(idx) => idx,
            None if self.buckets.len() < MAX_LAYOUTS => {
                self.buckets.push(Bucket {
                    layout,
                    free: Vec::new(),
                });
                self.buckets.len() - 1
            }
            None => return None,
        };
        self.buckets.get_mut(idx)
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        for bucket in &mut self.buckets {
            for slot in bucket.free.drain(..) {
                // SAFETY: every pooled slot came from `std::alloc::alloc(bucket.layout)`
                // (see `alloc_slot`) and is owned by the pool alone.
                unsafe { std::alloc::dealloc(slot.0.as_ptr(), bucket.layout) };
            }
        }
    }
}

thread_local! {
    static LOCAL: RefCell<Pool> = const { RefCell::new(Pool::new()) };
}

static SHARED: Mutex<Pool> = Mutex::new(Pool::new());

fn take_slot(layout: Layout) -> Option<Slot> {
    LOCAL
        .try_with(|local| {
            let mut local = local.try_borrow_mut().ok()?;
            let bucket = local.bucket(layout)?;
            if let Some(slot) = bucket.free.pop() {
                return Some(slot);
            }
            let mut shared = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
            let from = shared.bucket(layout)?;
            let n = (slots(LOCAL_POOL_BYTES, layout) / 2)
                .max(1)
                .min(from.free.len());
            let at = from.free.len() - n;
            bucket.free.extend(from.free.drain(at..));
            bucket.free.pop()
        })
        .ok()
        .flatten()
}

/// Pool `slot`; hands it back when every tier is full.
fn give_slot(slot: Slot, layout: Layout) -> Option<Slot> {
    let local_cap = slots(LOCAL_POOL_BYTES, layout);
    let fallback = Slot(slot.0);
    LOCAL
        .try_with(|local| {
            let Ok(mut local) = local.try_borrow_mut() else {
                return Some(slot);
            };
            let Some(bucket) = local.bucket(layout) else {
                return Some(slot);
            };
            if bucket.free.len() >= local_cap {
                let mut shared = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
                let Some(to) = shared.bucket(layout) else {
                    return Some(slot);
                };
                let room = slots(SHARED_POOL_BYTES, layout).saturating_sub(to.free.len());
                let n = (local_cap / 2).max(1).min(room);
                let at = bucket.free.len() - n;
                to.free.extend(bucket.free.drain(at..));
                if n == 0 {
                    return Some(slot);
                }
            }
            bucket.free.push(slot);
            None
        })
        .unwrap_or(Some(fallback))
}

fn alloc_slot(layout: Layout) -> NonNull<u8> {
    if let Some(slot) = take_slot(layout) {
        return slot.0;
    }
    // SAFETY: callers pass a non-zero-sized layout.
    let raw = unsafe { std::alloc::alloc(layout) };
    NonNull::new(raw).unwrap_or_else(|| std::alloc::handle_alloc_error(layout))
}

fn release_slot(ptr: NonNull<u8>, layout: Layout) {
    if let Some(slot) = give_slot(Slot(ptr), layout) {
        // SAFETY: `ptr` came from `alloc_slot(layout)`; the pools declined it, so this
        // is its only owner.
        unsafe { std::alloc::dealloc(slot.0.as_ptr(), layout) };
    }
}

/// A per-thread free list of owned values backed by a shared overflow list (see
/// the module docs). Declare the thread-local tier with `thread_local!` and pass
/// it in: `static POOL: TieredPool<BytesMut> = TieredPool::new(&LOCAL, 8, 32);`.
pub struct TieredPool<T: 'static> {
    local: &'static LocalKey<RefCell<Vec<T>>>,
    shared: Mutex<Vec<T>>,
    local_cap: usize,
    shared_cap: usize,
}

impl<T: Send + 'static> TieredPool<T> {
    pub const fn new(
        local: &'static LocalKey<RefCell<Vec<T>>>,
        local_cap: usize,
        shared_cap: usize,
    ) -> Self {
        Self {
            local,
            shared: Mutex::new(Vec::new()),
            local_cap,
            shared_cap,
        }
    }

    pub fn take(&self) -> Option<T> {
        self.local
            .try_with(|local| {
                let mut local = local.try_borrow_mut().ok()?;
                if let Some(value) = local.pop() {
                    return Some(value);
                }
                let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
                let n = (self.local_cap / 2).max(1).min(shared.len());
                let at = shared.len() - n;
                local.extend(shared.drain(at..));
                local.pop()
            })
            .ok()
            .flatten()
    }

    /// Keep `value` for reuse; it is dropped (outside any lock) when every tier is full.
    pub fn give(&self, value: T) {
        let mut value = Some(value);
        let _ = self.local.try_with(|local| {
            let Ok(mut local) = local.try_borrow_mut() else {
                return;
            };
            if local.len() >= self.local_cap {
                let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
                let room = self.shared_cap.saturating_sub(shared.len());
                let n = (self.local_cap / 2).max(1).min(room);
                let at = local.len() - n;
                shared.extend(local.drain(at..));
                if n == 0 {
                    return;
                }
            }
            if let Some(value) = value.take() {
                local.push(value);
            }
        });
        drop(value);
    }
}

/// An owned value in a recycled heap slot: `Box`-like (stable address, so a pinned
/// future stays sound), but its memory is reused by the next `Recycled` of the
/// same layout on whichever thread drops it.
pub struct Recycled<T> {
    ptr: NonNull<T>,
}

// SAFETY: `Recycled<T>` uniquely owns its `T`, exactly like `Box<T>`.
unsafe impl<T: Send> Send for Recycled<T> {}
// SAFETY: shared access only ever yields `&T`.
unsafe impl<T: Sync> Sync for Recycled<T> {}
// The value never moves after `new`; moving the handle does not move it.
impl<T> Unpin for Recycled<T> {}

impl<T> Recycled<T> {
    pub fn new(value: T) -> Self {
        let layout = Layout::new::<T>();
        if layout.size() == 0 {
            let ptr = NonNull::<T>::dangling();
            // SAFETY: a zero-sized write through a dangling, aligned pointer is valid.
            unsafe { ptr.as_ptr().write(value) };
            return Self { ptr };
        }
        let ptr = alloc_slot(layout).cast::<T>();
        // SAFETY: the slot is a fresh or recycled allocation of `T`'s layout that
        // nothing else references.
        unsafe { ptr.as_ptr().write(value) };
        Self { ptr }
    }
}

impl<T> std::ops::Deref for Recycled<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: `ptr` holds an initialized `T` until `drop`.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> std::ops::DerefMut for Recycled<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, and `&mut self` makes the access unique.
        unsafe { self.ptr.as_mut() }
    }
}

impl<F: Future> Future for Recycled<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        // SAFETY: the future lives at a fixed heap address until `drop` runs its
        // destructor in place, so pinning it is sound even though the handle is Unpin.
        unsafe { Pin::new_unchecked(&mut *self.get_mut().ptr.as_ptr()) }.poll(cx)
    }
}

impl<T> Drop for Recycled<T> {
    fn drop(&mut self) {
        struct Release(NonNull<u8>, Layout);
        impl Drop for Release {
            fn drop(&mut self) {
                release_slot(self.0, self.1);
            }
        }
        let layout = Layout::new::<T>();
        // Returned after the value's destructor, even if it unwinds.
        let _release = (layout.size() != 0).then(|| Release(self.ptr.cast(), layout));
        // SAFETY: `ptr` holds an initialized `T` that is dropped exactly once, here.
        unsafe { std::ptr::drop_in_place(self.ptr.as_ptr()) };
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Recycled<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (**self).fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn a_dropped_slot_is_reused_by_the_next_value_of_its_layout() {
        let first = Recycled::new([7u8; 3000]);
        let addr = &*first as *const [u8; 3000];
        drop(first);
        let second = Recycled::new([9u8; 3000]);
        assert_eq!(&*second as *const [u8; 3000], addr);
        assert!(second.iter().all(|&b| b == 9));
    }

    #[test]
    fn drop_runs_the_value_destructor_once() {
        let marker = Rc::new(());
        let held = Recycled::new((Rc::clone(&marker), [0u64; 64]));
        assert_eq!(Rc::strong_count(&marker), 2);
        drop(held);
        assert_eq!(Rc::strong_count(&marker), 1);
    }

    #[test]
    fn nested_values_recycle_without_reentrancy_panics() {
        let inner = Recycled::new([1u32; 900]);
        let outer = Recycled::new((inner, [2u32; 700]));
        drop(outer);
        let again = Recycled::new((Recycled::new([3u32; 900]), [4u32; 700]));
        assert_eq!(again.0[0], 3);
    }

    fn pooled(layout: Layout) -> (usize, usize) {
        let local = LOCAL.with(|p| {
            p.borrow()
                .buckets
                .iter()
                .find(|b| b.layout == layout)
                .map_or(0, |b| b.free.len())
        });
        let shared = SHARED
            .lock()
            .unwrap()
            .buckets
            .iter()
            .find(|b| b.layout == layout)
            .map_or(0, |b| b.free.len());
        (local, shared)
    }

    #[test]
    fn overflow_spills_to_the_shared_tier_up_to_its_cap() {
        type Big = [u8; 128 * 1024];
        let layout = Layout::new::<Big>();
        let held: Vec<_> = (0..16).map(|_| Recycled::new([0u8; 128 * 1024])).collect();
        drop(held);
        let (local, shared) = pooled(layout);
        assert!(local <= slots(LOCAL_POOL_BYTES, layout));
        assert!(shared <= slots(SHARED_POOL_BYTES, layout));
        assert_eq!(
            local + shared,
            slots(LOCAL_POOL_BYTES, layout) + slots(SHARED_POOL_BYTES, layout)
        );
    }

    // A slot freed on another thread comes back through the shared tier instead of
    // the allocator.
    #[test]
    fn slots_freed_on_another_thread_are_reused_here() {
        type Mid = [u8; 96 * 1024];
        let held: Vec<_> = (0..12).map(|_| Recycled::new([1u8; 96 * 1024])).collect();
        let addrs: Vec<_> = held.iter().map(|r| &**r as *const Mid as usize).collect();
        std::thread::spawn(move || drop(held)).join().unwrap();
        let again: Vec<_> = (0..4).map(|_| Recycled::new([2u8; 96 * 1024])).collect();
        for r in &again {
            assert!(addrs.contains(&(&**r as *const Mid as usize)));
        }
    }

    #[test]
    fn a_tiered_pool_moves_values_between_threads() {
        thread_local! {
            static BUFS: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
        }
        static POOL: TieredPool<Vec<u8>> = TieredPool::new(&BUFS, 2, 4);
        let bufs: Vec<_> = (0..8).map(|i| vec![i as u8; 16]).collect();
        let ptrs: Vec<_> = bufs.iter().map(|b| b.as_ptr() as usize).collect();
        std::thread::spawn(move || bufs.into_iter().for_each(|b| POOL.give(b)))
            .join()
            .unwrap();
        // The giving thread kept 2 locally (now freed with it) and spilled 4.
        let mut got = Vec::new();
        while let Some(b) = POOL.take() {
            got.push(b.as_ptr() as usize);
        }
        assert_eq!(got.len(), 4);
        assert!(got.iter().all(|p| ptrs.contains(p)));
    }

    #[test]
    fn zero_sized_values_need_no_slot() {
        let unit = Recycled::new(());
        assert_eq!(*unit, ());
    }

    #[test]
    fn a_recycled_future_polls_in_place() {
        let fut = Recycled::new(async {
            let pad = [5u8; 2048];
            std::future::ready(()).await;
            pad[2047]
        });
        let out = block_on(fut);
        assert_eq!(out, 5);
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }
}
