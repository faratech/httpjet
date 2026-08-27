//! httpjet patch (#335): a PROVIDED BUFFER RING (`IORING_REGISTER_PBUF_RING`)
//! backing multishot receive.
//!
//! One ring of `entries` fixed-size buffers is registered per driver under a
//! buffer-group id; armed `RecvMulti` operations draw from it — the kernel
//! picks a free buffer per datagram/segment and reports its id in the CQE
//! flags, so steady-state receive costs ZERO submissions. The consumer copies
//! the bytes out at CQE consumption and immediately recycles the buffer
//! (publishing it back at the ring tail), which keeps buffer occupancy
//! transient and the group small.
//!
//! Memory: ring metadata is `entries * 16` bytes (page-aligned as the kernel
//! maps it); payload is `entries * buf_size` of ordinary heap — with the
//! defaults (256 x 8 KiB) that is 2 MiB + 4 KiB per driver, and nothing here
//! is memlock-charged beyond the metadata page(s) (#345 lesson: stay far from
//! `LimitMEMLOCK` under an unprivileged user).

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::io;

use io_uring::types::BufRingEntry;

pub(crate) const DEFAULT_BUF_GROUP: u16 = 7;
pub(crate) const DEFAULT_ENTRIES: u16 = 256; // power of two required
pub(crate) const DEFAULT_BUF_SIZE: usize = 8 * 1024;

pub(crate) struct BufRing {
    bgid: u16,
    entries: u16,
    buf_size: usize,
    /// Kernel-visible ring of [`BufRingEntry`] (page-aligned; registered).
    ring: *mut BufRingEntry,
    ring_layout: Layout,
    /// Payload backing store, `entries * buf_size` bytes.
    bufs: Box<[u8]>,
    /// Local tail mirror; the kernel reads the published tail from the ring.
    tail: u16,
}

impl BufRing {
    pub(crate) fn new(entries: u16, buf_size: usize, bgid: u16) -> Self {
        assert!(entries.is_power_of_two());
        let ring_layout =
            Layout::from_size_align(entries as usize * size_of::<BufRingEntry>(), 4096)
                .expect("buf ring layout");
        // SAFETY: layout has non-zero size; zeroed memory is a valid initial
        // state for the entry array (entries are fully written before the
        // tail publishes them).
        let ring = unsafe { alloc_zeroed(ring_layout) } as *mut BufRingEntry;
        assert!(!ring.is_null(), "buf ring alloc failed");
        Self {
            bgid,
            entries,
            buf_size,
            ring,
            ring_layout,
            bufs: vec![0u8; entries as usize * buf_size].into_boxed_slice(),
            tail: 0,
        }
    }

    pub(crate) fn bgid(&self) -> u16 {
        self.bgid
    }

    /// Register with the kernel and publish every buffer as available.
    ///
    /// # Safety
    /// The ring memory must stay alive and pinned at this address until
    /// `unregister_buf_ring(bgid)` (the driver owns `BufRing` for its whole
    /// lifetime and never moves it — it is boxed).
    pub(crate) unsafe fn register(&mut self, submitter: &io_uring::Submitter<'_>) -> io::Result<()> {
        unsafe {
            submitter.register_buf_ring(self.ring as u64, self.entries, self.bgid)?;
        }
        for bid in 0..self.entries {
            self.push(bid);
        }
        self.publish();
        Ok(())
    }

    /// Slice of buffer `bid` holding `len` received bytes.
    ///
    /// # Safety
    /// `bid` must be a buffer id the kernel just reported in a CQE for this
    /// group (i.e. currently owned by userspace) and `len <= buf_size`.
    pub(crate) unsafe fn slice(&self, bid: u16, len: usize) -> &[u8] {
        debug_assert!(bid < self.entries);
        debug_assert!(len <= self.buf_size);
        let start = bid as usize * self.buf_size;
        &self.bufs[start..start + len]
    }

    /// Hand buffer `bid` back to the kernel (visible after [`Self::publish`]).
    pub(crate) fn recycle(&mut self, bid: u16) {
        self.push(bid);
        self.publish();
    }

    fn push(&mut self, bid: u16) {
        let mask = self.entries - 1;
        let idx = (self.tail & mask) as usize;
        // SAFETY: idx < entries; the slot at `tail` is owned by userspace
        // until the tail store publishes it.
        unsafe {
            let entry = &mut *self.ring.add(idx);
            entry.set_addr(self.bufs.as_ptr().add(bid as usize * self.buf_size) as u64);
            entry.set_len(self.buf_size as u32);
            entry.set_bid(bid);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    fn publish(&mut self) {
        // SAFETY: tail pointer lives inside the registered ring memory.
        unsafe {
            let tail_ptr = BufRingEntry::tail(self.ring) as *mut u16;
            std::sync::atomic::AtomicU16::from_ptr(tail_ptr)
                .store(self.tail, std::sync::atomic::Ordering::Release);
        }
    }
}

impl Drop for BufRing {
    fn drop(&mut self) {
        // The driver unregisters (or the ring fd is closed, which drops the
        // registration kernel-side) before the memory goes away.
        unsafe { dealloc(self.ring as *mut u8, self.ring_layout) };
    }
}
