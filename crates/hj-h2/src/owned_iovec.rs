//! Cancellation-safe owned buffers for monoio vectored writes.

use std::io;

use bytes::Bytes;

/// One range within a backing allocation supplied to [`OwnedIoVec::from_backings`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoVecSpan {
    pub backing: usize,
    pub offset: usize,
    pub len: usize,
}

impl IoVecSpan {
    pub const fn new(backing: usize, offset: usize, len: usize) -> Self {
        Self {
            backing,
            offset,
            len,
        }
    }
}

/// An [`monoio::buf::IoVecBuf`] that owns every allocation referenced by its iovecs.
///
/// Monoio retains only the `IoVecBuf` value when a submitted io_uring future is
/// cancelled. Keeping the backing [`Bytes`] here therefore keeps every kernel-visible
/// pointer alive until the completion is reaped, even if the request future is dropped.
pub struct OwnedIoVec {
    iovecs: Vec<libc::iovec>,
    backings: Vec<Bytes>,
    first: usize,
    remaining: usize,
}

impl OwnedIoVec {
    /// Build one full-span iovec per non-empty backing allocation.
    pub fn from_bytes(backings: Vec<Bytes>) -> io::Result<Self> {
        let spans = backings
            .iter()
            .enumerate()
            .filter(|(_, bytes)| !bytes.is_empty())
            .map(|(backing, bytes)| IoVecSpan::new(backing, 0, bytes.len()))
            .collect();
        Self::from_backings(backings, spans)
    }

    /// Build iovecs over validated ranges of owned backing allocations.
    pub fn from_backings(backings: Vec<Bytes>, spans: Vec<IoVecSpan>) -> io::Result<Self> {
        let mut iovecs = Vec::with_capacity(spans.len());
        let mut remaining = 0usize;
        for span in spans {
            if span.len == 0 {
                continue;
            }
            let backing = backings.get(span.backing).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "iovec backing index out of range",
                )
            })?;
            let end = span.offset.checked_add(span.len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "iovec range overflow")
            })?;
            if end > backing.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "iovec range exceeds backing allocation",
                ));
            }
            remaining = remaining.checked_add(span.len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "vectored payload too large")
            })?;
            // SAFETY: `span` was bounds-checked against `backing`; `Bytes` owns a stable
            // allocation whose address is unaffected when the handle itself moves.
            let base = unsafe { backing.as_ptr().add(span.offset) };
            iovecs.push(libc::iovec {
                iov_base: base.cast_mut().cast(),
                iov_len: span.len,
            });
        }
        Ok(Self {
            iovecs,
            backings,
            first: 0,
            remaining,
        })
    }

    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    pub const fn is_empty(&self) -> bool {
        self.remaining == 0
    }

    /// Advance past bytes accepted by the last write operation.
    ///
    /// Call this only after monoio returns ownership of the buffer. The next write then
    /// exposes only the unwritten suffix while all original backing allocations remain owned.
    pub fn consume(&mut self, mut written: usize) -> io::Result<()> {
        if written > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vectored write exceeded queued bytes",
            ));
        }
        self.remaining -= written;
        while written > 0 {
            let iovec = self.iovecs.get_mut(self.first).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing iovec for queued bytes")
            })?;
            let consumed = written.min(iovec.iov_len);
            // SAFETY: `consumed <= iov_len`, so the new base remains within or one past
            // the same live backing allocation retained by `self.backings`.
            iovec.iov_base = unsafe { (iovec.iov_base as *mut u8).add(consumed) }.cast();
            iovec.iov_len -= consumed;
            written -= consumed;
            if iovec.iov_len == 0 {
                self.first += 1;
            }
        }
        Ok(())
    }

    /// Recover the owned allocations after the final completion.
    pub fn into_backings(self) -> Vec<Bytes> {
        self.backings
    }
}

// SAFETY: the iovec array is never reallocated while monoio owns this value, and every
// iovec points into a `Bytes` allocation retained in `backings`. Both the metadata and
// pointees therefore remain valid and at stable addresses through cancellation and delayed
// io_uring completion. `consume` mutates metadata only after ownership has been returned.
unsafe impl monoio::buf::IoVecBuf for OwnedIoVec {
    fn read_iovec_ptr(&self) -> *const libc::iovec {
        // SAFETY: `first` is advanced at most to `iovecs.len()`; a one-past pointer is
        // valid when the corresponding length returned below is zero.
        unsafe { self.iovecs.as_ptr().add(self.first) }
    }

    fn read_iovec_len(&self) -> usize {
        self.iovecs.len() - self.first
    }
}

/// Write every queued byte, retaining ownership of all backing allocations across each
/// completion and returning them to the caller when the final write completes.
pub async fn write_all_owned<W>(stream: &mut W, mut buffer: OwnedIoVec) -> io::Result<OwnedIoVec>
where
    W: monoio::io::AsyncWriteRent + ?Sized,
{
    while !buffer.is_empty() {
        let (result, returned) = stream.writev(buffer).await;
        buffer = returned;
        let written = result?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        buffer.consume(written)?;
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use monoio::io::AsyncWriteRent;
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn partial_consumption_preserves_the_exact_suffix() {
        let mut owned = OwnedIoVec::from_bytes(vec![
            Bytes::from_static(b"head"),
            Bytes::from_static(b"payload"),
            Bytes::from_static(b"tail"),
        ])
        .unwrap();
        owned.consume(6).unwrap();
        assert_eq!(owned.remaining(), 9);

        let ptr = monoio::buf::IoVecBuf::read_iovec_ptr(&owned);
        let len = monoio::buf::IoVecBuf::read_iovec_len(&owned);
        let bytes = (0..len)
            .flat_map(|index| {
                // SAFETY: the trait contract guarantees `len` valid initialized iovecs.
                let iovec = unsafe { &*ptr.add(index) };
                // SAFETY: every iovec is backed by `owned`, which remains alive here.
                unsafe { std::slice::from_raw_parts(iovec.iov_base as *const u8, iovec.iov_len) }
                    .to_vec()
            })
            .collect::<Vec<_>>();
        assert_eq!(bytes, b"yloadtail");
    }

    struct DropOwner {
        bytes: Vec<u8>,
        dropped: Arc<AtomicBool>,
    }

    impl AsRef<[u8]> for DropOwner {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for DropOwner {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[test]
    fn dropped_write_future_keeps_payload_alive_until_completion() {
        let dropped = Arc::new(AtomicBool::new(false));
        let observed = dropped.clone();
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (mut writer, _reader) = monoio::net::UnixStream::pair().unwrap();
            let fill = [0u8; 16 * 1024];
            loop {
                // SAFETY: `fill` is initialized for its full length and the fd belongs to
                // `writer`; MSG_DONTWAIT makes saturation deterministic without blocking.
                let result = unsafe {
                    libc::send(
                        writer.as_raw_fd(),
                        fill.as_ptr().cast(),
                        fill.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    break;
                }
            }

            let bytes = Bytes::from_owner(DropOwner {
                bytes: vec![7u8; 4096],
                dropped: dropped.clone(),
            });
            let owned = OwnedIoVec::from_bytes(vec![bytes]).unwrap();
            let write = writer.writev(owned);
            drop(write);

            assert!(
                !dropped.load(Ordering::Acquire),
                "the io_uring lifecycle must retain the owned payload after future drop"
            );
        });
        drop(runtime);
        assert!(
            observed.load(Ordering::Acquire),
            "driver teardown must eventually release the retained payload"
        );
    }
}
