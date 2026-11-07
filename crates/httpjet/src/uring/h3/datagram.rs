use std::cell::{Cell, RefCell};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicU8, Ordering};

use monoio::net::udp::UdpSocket;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
#[repr(u8)]
pub(crate) enum GsoSegments {
    #[default]
    #[value(name = "10")]
    Ten = 10,
    #[value(name = "20")]
    Twenty = 20,
}

/// Maximum messages per sendmmsg call; GSO datagrams still count individually
/// against the connection's existing cooperative transmit budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
#[repr(u8)]
pub(crate) enum SendBatch {
    #[default]
    #[value(name = "1")]
    One = 1,
    #[value(name = "4")]
    Four = 4,
    #[value(name = "8")]
    Eight = 8,
    #[value(name = "16")]
    Sixteen = 16,
}

static CONFIGURED_SEND_BATCH: AtomicU8 = AtomicU8::new(1);
pub(crate) fn configure_send_batch(value: SendBatch) {
    CONFIGURED_SEND_BATCH.store(value as u8, Ordering::Relaxed);
}
fn configured_send_batch() -> SendBatch {
    match CONFIGURED_SEND_BATCH.load(Ordering::Relaxed) {
        4 => SendBatch::Four,
        8 => SendBatch::Eight,
        16 => SendBatch::Sixteen,
        _ => SendBatch::One,
    }
}

struct QueuedTransmit {
    destination: SocketAddr,
    ecn: Option<quinn_udp::EcnCodepoint>,
    segment_size: Option<usize>,
    src_ip: Option<IpAddr>,
    contents: Vec<u8>,
}
impl QueuedTransmit {
    fn borrowed(&self) -> Transmit<'_> {
        Transmit {
            destination: self.destination,
            ecn: self.ecn,
            contents: &self.contents,
            segment_size: self.segment_size,
            src_ip: self.src_ip,
        }
    }
}

/// Bounded endpoint-owned payloads. A buffer returns to the pool only after its
/// complete message was accepted or the scalar-equivalent error dropped it.
/// Nothing borrowed by sendmmsg survives that synchronous syscall.
struct SendQueue {
    pending: Vec<QueuedTransmit>,
    free: Vec<Vec<u8>>,
    limit: usize,
}
impl SendQueue {
    fn new(limit: usize) -> Self {
        Self {
            pending: Vec::with_capacity(limit),
            free: (0..limit)
                .map(|_| Vec::with_capacity(super::MAX_DATAGRAM))
                .collect(),
            limit,
        }
    }
    fn enqueue(&mut self, transmit: quinn_proto::Transmit, buffer: &mut Vec<u8>) {
        // Callers check `batch_has_room` first, so a reserved buffer is always free.
        let mut replacement = self
            .free
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(super::MAX_DATAGRAM));
        replacement.clear();
        std::mem::swap(buffer, &mut replacement);
        replacement.truncate(transmit.size);
        self.pending.push(QueuedTransmit {
            destination: transmit.destination,
            ecn: transmit
                .ecn
                .and_then(|e| quinn_udp::EcnCodepoint::from_bits(e as u8)),
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
            contents: replacement,
        });
    }
    fn consume(&mut self, count: usize) {
        for mut transmit in self.pending.drain(..count) {
            transmit.contents.clear();
            self.free.push(transmit.contents);
        }
    }
    fn flush_with(&mut self, mut send: impl FnMut(&[QueuedTransmit]) -> io::Result<usize>) -> bool {
        // Every successful iteration consumes at least one message, so this is
        // bounded by the fixed queue capacity even for repeated short sends.
        while !self.pending.is_empty() {
            match send(&self.pending) {
                Ok(count) if count > 0 && count <= self.pending.len() => self.consume(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return false,
                Ok(_) => return false,
                // Like the existing scalar adapter, a permanent UDP send error
                // drops this one transmit. QUIC's loss recovery retains authority.
                Err(_) => self.consume(1),
            }
        }
        true
    }
}

static CONFIGURED_SEGMENTS: AtomicU8 = AtomicU8::new(GsoSegments::Ten as u8);

/// Startup only. Each UDP driver snapshots this once at construction; packet
/// transmission reads no configuration atomic and existing drivers never change.
pub(crate) fn configure_gso_segments(value: GsoSegments) {
    CONFIGURED_SEGMENTS.store(value as u8, Ordering::Relaxed);
}

fn configured_segments() -> GsoSegments {
    match CONFIGURED_SEGMENTS.load(Ordering::Relaxed) {
        20 => GsoSegments::Twenty,
        _ => GsoSegments::Ten,
    }
}

pub(super) fn segment_cap(kernel_limit: usize, requested: GsoSegments, remaining: usize) -> usize {
    kernel_limit.max(1).min(requested as usize).min(remaining)
}

pub(super) struct IoUringDatagram {
    socket: UdpSocket,
    state: UdpSocketState,
    segment_limit: GsoSegments,
    send_queue: Option<RefCell<SendQueue>>,
    send_blocked: Cell<bool>,
    #[cfg(test)]
    force_batch_would_block: Cell<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SendOutcome {
    Sent,
    Dropped,
    Unavailable,
}

impl IoUringDatagram {
    pub(super) fn new(socket: UdpSocket) -> io::Result<Self> {
        // SAFETY: the owned socket outlives the temporary borrowed descriptor.
        let fd = unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
        let state = UdpSocketState::new(UdpSockRef::from(&fd))?;
        Ok(Self {
            socket,
            state,
            segment_limit: configured_segments(),
            send_queue: match configured_send_batch() {
                SendBatch::One => None,
                batch => Some(RefCell::new(SendQueue::new(batch as usize))),
            },
            send_blocked: Cell::new(false),
            #[cfg(test)]
            force_batch_would_block: Cell::new(false),
        })
    }

    #[cfg(test)]
    pub(super) fn from_parts_with_limit(
        socket: UdpSocket,
        state: UdpSocketState,
        segment_limit: GsoSegments,
        send_batch: SendBatch,
    ) -> Self {
        Self {
            socket,
            state,
            segment_limit,
            send_queue: match send_batch {
                SendBatch::One => None,
                batch => Some(RefCell::new(SendQueue::new(batch as usize))),
            },
            send_blocked: Cell::new(false),
            #[cfg(test)]
            force_batch_would_block: Cell::new(false),
        }
    }

    #[inline]
    pub(super) fn batch_enabled(&self) -> bool {
        self.send_queue.is_some()
    }
    pub(super) fn send_blocked(&self) -> bool {
        self.send_blocked.get()
    }
    pub(super) fn has_pending_sends(&self) -> bool {
        self.send_queue
            .as_ref()
            .is_some_and(|queue| !queue.borrow().pending.is_empty())
    }
    pub(super) fn batch_has_room(&self) -> bool {
        self.send_queue.as_ref().is_some_and(|queue| {
            let queue = queue.borrow();
            queue.pending.len() < queue.limit
        })
    }
    /// Only called after `batch_has_room`, which is false without a configured queue.
    pub(super) fn queue_transmit(&self, transmit: quinn_proto::Transmit, buffer: &mut Vec<u8>) {
        if let Some(queue) = &self.send_queue {
            queue.borrow_mut().enqueue(transmit, buffer);
        }
    }
    /// Attempt the queued prefix once per progress step. On EAGAIN the endpoint
    /// selects writability alongside RX and deadlines, retaining every payload.
    pub(super) fn flush_pending(&self) -> bool {
        let Some(queue) = &self.send_queue else {
            return true;
        };
        if self.send_blocked.get() {
            return false;
        }
        let fd = unsafe { BorrowedFd::borrow_raw(self.socket.as_raw_fd()) };
        let empty = queue.borrow_mut().flush_with(|pending| {
            #[cfg(test)]
            if self.force_batch_would_block.replace(false) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            // `flush_with` only calls this with a non-empty queue of at most `limit`
            // (<= MAX_SEND_BATCH) transmits; unused array slots repeat the last one.
            let Some(last) = pending.last() else {
                return Ok(0);
            };
            let count = pending.len().min(quinn_udp::MAX_SEND_BATCH);
            let transmits: [Transmit<'_>; quinn_udp::MAX_SEND_BATCH] =
                std::array::from_fn(|i| pending.get(i).unwrap_or(last).borrowed());
            self.state.try_send_batch(
                UdpSockRef::from(&fd),
                transmits.get(..count).unwrap_or_default(),
            )
        });
        self.send_blocked.set(!empty);
        empty
    }
    #[cfg(test)]
    pub(super) fn defer_next_batch_for_test(&self) {
        self.force_batch_would_block.set(true);
    }
    #[cfg(test)]
    pub(super) fn pending_send_count(&self) -> usize {
        self.send_queue
            .as_ref()
            .map_or(0, |queue| queue.borrow().pending.len())
    }

    pub(super) async fn writable(&self) -> io::Result<()> {
        self.socket.writable(false).await?;
        self.send_blocked.set(false);
        Ok(())
    }

    #[inline]
    pub(super) fn transmit_segment_cap(&self, remaining: usize) -> usize {
        // Kernel capability remains dynamic: an EIO/EINVAL send can lower it to
        // one. Never cache that capability alongside the startup configuration.
        segment_cap(self.state.max_gso_segments(), self.segment_limit, remaining)
    }

    #[inline]
    pub(super) fn recv(
        &self,
        buffers: &mut [std::io::IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> io::Result<usize> {
        // SAFETY: the owned socket outlives the temporary borrowed descriptor.
        let fd = unsafe { BorrowedFd::borrow_raw(self.socket.as_raw_fd()) };
        self.state.recv(UdpSockRef::from(&fd), buffers, metadata)
    }

    pub(super) async fn send(&self, transmit: &Transmit<'_>) -> SendOutcome {
        loop {
            // SAFETY: the owned socket outlives the temporary borrowed descriptor.
            let fd = unsafe { BorrowedFd::borrow_raw(self.socket.as_raw_fd()) };
            match self.state.try_send(UdpSockRef::from(&fd), transmit) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if self.socket.writable(false).await.is_err() {
                        return SendOutcome::Unavailable;
                    }
                }
                Ok(()) => return SendOutcome::Sent,
                Err(_) => return SendOutcome::Dropped,
            }
        }
    }

    pub(super) async fn readable(&self) -> io::Result<()> {
        self.socket.readable(false).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_cap_and_remaining_flush_budget_both_bound_gso() {
        for requested in [GsoSegments::Ten, GsoSegments::Twenty] {
            for kernel in [0, 1, 8, 16, 64] {
                for remaining in 0..=20 {
                    let cap = segment_cap(kernel, requested, remaining);
                    assert!(cap <= remaining && cap <= requested as usize);
                    assert_eq!(cap, kernel.max(1).min(requested as usize).min(remaining));
                }
            }
        }
        assert_eq!(segment_cap(64, GsoSegments::Ten, 20), 10);
        assert_eq!(segment_cap(64, GsoSegments::Twenty, 20), 20);
        assert_eq!(segment_cap(64, GsoSegments::Twenty, 3), 3);
    }

    #[test]
    fn dynamic_kernel_fallback_overrides_either_requested_batch_size() {
        for requested in [GsoSegments::Ten, GsoSegments::Twenty] {
            assert!(segment_cap(64, requested, 20) > 1);
            assert_eq!(segment_cap(1, requested, 20), 1);
        }
    }
    fn enqueue_byte(queue: &mut SendQueue, byte: u8) -> *const u8 {
        let mut buffer = vec![byte; 32];
        let pointer = buffer.as_ptr();
        queue.enqueue(
            quinn_proto::Transmit {
                destination: "127.0.0.1:12345".parse().unwrap(),
                ecn: Some(quinn_proto::EcnCodepoint::Ect0),
                size: buffer.len(),
                segment_size: None,
                src_ip: Some("127.0.0.1".parse().unwrap()),
            },
            &mut buffer,
        );
        pointer
    }

    #[test]
    fn batch_short_send_then_would_block_retains_exact_tail_and_buffers() {
        let mut queue = SendQueue::new(4);
        let pointers: Vec<_> = (1..=4).map(|byte| enqueue_byte(&mut queue, byte)).collect();
        let mut calls = 0;
        assert!(!queue.flush_with(|pending| {
            calls += 1;
            if calls == 1 {
                assert_eq!(
                    pending.iter().map(|p| p.contents[0]).collect::<Vec<_>>(),
                    vec![1, 2, 3, 4]
                );
                Ok(2)
            } else {
                assert_eq!(
                    pending.iter().map(|p| p.contents[0]).collect::<Vec<_>>(),
                    vec![3, 4]
                );
                Err(io::ErrorKind::WouldBlock.into())
            }
        }));
        assert_eq!(queue.pending.len(), 2);
        assert_eq!(queue.pending[0].contents.as_ptr(), pointers[2]);
        assert_eq!(queue.pending[1].contents.as_ptr(), pointers[3]);
        assert_eq!(queue.free.len(), 2);
        assert!(queue.flush_with(|pending| {
            assert_eq!(
                pending[0].borrowed().src_ip,
                Some("127.0.0.1".parse().unwrap())
            );
            assert_eq!(
                pending[1].borrowed().ecn,
                Some(quinn_udp::EcnCodepoint::Ect0)
            );
            Ok(pending.len())
        }));
        assert_eq!(queue.free.len(), 4);
    }

    #[test]
    fn batch_permanent_error_drops_only_the_unaccepted_head() {
        let mut queue = SendQueue::new(4);
        for byte in 1..=3 {
            enqueue_byte(&mut queue, byte);
        }
        let mut heads = Vec::new();
        assert!(queue.flush_with(|pending| {
            heads.push(pending[0].contents[0]);
            if heads.len() == 1 {
                Err(io::ErrorKind::InvalidInput.into())
            } else {
                Ok(pending.len())
            }
        }));
        assert_eq!(heads, vec![1, 2]);
        assert!(queue.pending.is_empty());
        assert_eq!(queue.free.len(), 4);
    }

    #[test]
    fn batch_zero_progress_keeps_the_unaccepted_payload() {
        let mut queue = SendQueue::new(4);
        enqueue_byte(&mut queue, 9);
        assert!(!queue.flush_with(|_| Ok(0)));
        assert_eq!(queue.pending[0].contents[0], 9);
        assert_eq!(queue.free.len(), 3);
    }
}
