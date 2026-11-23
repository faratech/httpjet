use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use crate::driver;

pub(crate) mod close;
pub(crate) mod read;
pub(crate) mod write;

mod accept;
// httpjet patch (#334): the multishot-accept op type is named by the listener.
#[cfg(all(target_os = "linux", feature = "iouring"))]
pub(crate) use accept::AcceptMulti;
mod connect;
mod fsync;
mod open;
mod poll;
mod recv;
mod send;
#[cfg(unix)]
mod statx;

#[cfg(feature = "mkdirat")]
mod mkdir;

#[cfg(feature = "unlinkat")]
mod unlink;

#[cfg(feature = "renameat")]
mod rename;

#[cfg(all(unix, feature = "symlinkat"))]
mod symlink;

#[cfg(all(target_os = "linux", feature = "splice"))]
mod splice;

/// In-flight operation
pub(crate) struct Op<T: 'static + OpAble> {
    // Driver running the operation
    pub(super) driver: driver::Inner,

    // Operation index in the slab(useless for legacy)
    pub(super) index: usize,

    // Per-operation data
    pub(super) data: Option<T>,
}

/// Operation completion. Returns stored state with the result of the operation.
#[derive(Debug)]
pub(crate) struct Completion<T> {
    pub(crate) data: T,
    pub(crate) meta: CompletionMeta,
}

/// Operation completion meta info.
#[derive(Debug)]
pub(crate) struct CompletionMeta {
    pub(crate) result: io::Result<MaybeFd>,
    #[allow(unused)]
    pub(crate) flags: u32,
}

/// MaybeFd is a wrapper for fd or a normal number. If it is marked as fd, it will close the fd when
/// dropped.
/// Use `into_inner` to take the inner fd or number and skip the drop.
///
/// This wrapper is designed to be used in the syscall return value. It can prevent fd leak when the
/// operation is cancelled.
#[derive(Debug)]
pub(crate) struct MaybeFd {
    is_fd: bool,
    fd: u32,
}

impl MaybeFd {
    #[inline]
    pub(crate) unsafe fn new_result(fdr: io::Result<u32>, is_fd: bool) -> io::Result<Self> {
        fdr.map(|fd| Self { is_fd, fd })
    }

    #[inline]
    pub(crate) unsafe fn new_fd_result(fdr: io::Result<u32>) -> io::Result<Self> {
        fdr.map(|fd| Self { is_fd: true, fd })
    }

    #[inline]
    pub(crate) fn new_non_fd_result(fdr: io::Result<u32>) -> io::Result<Self> {
        fdr.map(|fd| Self { is_fd: false, fd })
    }

    #[inline]
    pub(crate) const unsafe fn new_fd(fd: u32) -> Self {
        Self { is_fd: true, fd }
    }

    #[inline]
    pub(crate) const fn new_non_fd(fd: u32) -> Self {
        Self { is_fd: false, fd }
    }

    #[inline]
    pub(crate) const fn into_inner(self) -> u32 {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }

    #[inline]
    pub(crate) const fn zero() -> Self {
        Self {
            is_fd: false,
            fd: 0,
        }
    }

    #[inline]
    pub(crate) fn fd(&self) -> u32 {
        self.fd
    }
}

impl Drop for MaybeFd {
    fn drop(&mut self) {
        // The fd close only executed when:
        // 1. the operation is cancelled
        // 2. the cancellation failed
        // 3. the returned result is a fd
        // So this is a relatively cold path. For simplicity, we just do a close syscall here
        // instead of pushing close op.
        if self.is_fd {
            unsafe {
                libc::close(self.fd as libc::c_int);
            }
        }
    }
}

pub(crate) trait OpAble {
    #[cfg(all(target_os = "linux", feature = "iouring"))]
    const RET_IS_FD: bool = false;
    #[cfg(all(target_os = "linux", feature = "iouring"))]
    const SKIP_CANCEL: bool = false;
    #[cfg(all(target_os = "linux", feature = "iouring"))]
    fn uring_op(&mut self) -> io_uring::squeue::Entry;

    #[cfg(any(feature = "legacy", feature = "poll-io"))]
    fn legacy_interest(&self) -> Option<(super::ready::Direction, usize)>;
    #[cfg(any(feature = "legacy", feature = "poll-io"))]
    fn legacy_call(&mut self) -> io::Result<MaybeFd>;
}

/// If legacy is enabled and iouring is not, we can expose io interface in a poll-like way.
/// This can provide better compatibility for crates programmed in poll-like way.
#[allow(dead_code)]
#[cfg(any(feature = "legacy", feature = "poll-io"))]
pub(crate) trait PollLegacy {
    #[cfg(feature = "legacy")]
    fn poll_legacy(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<CompletionMeta>;
    #[cfg(feature = "poll-io")]
    fn poll_io(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<CompletionMeta>;
}

#[cfg(any(feature = "legacy", feature = "poll-io"))]
impl<T: OpAble> PollLegacy for T {
    #[cfg(feature = "legacy")]
    #[inline]
    fn poll_legacy(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<CompletionMeta> {
        #[cfg(all(feature = "iouring", feature = "tokio-compat"))]
        unsafe {
            extern "C" {
                #[link_name = "tokio-compat can only be enabled when legacy feature is enabled and \
                               iouring is not"]
                fn trigger() -> !;
            }
            trigger()
        }

        #[cfg(not(all(feature = "iouring", feature = "tokio-compat")))]
        driver::CURRENT.with(|this| this.poll_op(self, 0, _cx))
    }

    #[cfg(feature = "poll-io")]
    #[inline]
    fn poll_io(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<CompletionMeta> {
        driver::CURRENT.with(|this| this.poll_legacy_op(self, cx))
    }
}

impl<T: OpAble> Op<T> {
    /// Submit an operation to uring.
    ///
    /// `state` is stored during the operation tracking any state submitted to
    /// the kernel.
    pub(super) fn submit_with(data: T) -> io::Result<Op<T>> {
        driver::CURRENT.with(|this| this.submit_with(data))
    }

    /// Try submitting an operation to uring
    #[allow(unused)]
    pub(super) fn try_submit_with(data: T) -> io::Result<Op<T>> {
        if driver::CURRENT.is_set() {
            Op::submit_with(data)
        } else {
            Err(io::ErrorKind::Other.into())
        }
    }

    pub(crate) fn op_canceller(&self) -> OpCanceller {
        #[cfg(feature = "legacy")]
        if is_legacy() {
            return if let Some((dir, id)) = self.data.as_ref().unwrap().legacy_interest() {
                OpCanceller {
                    index: id,
                    direction: Some(dir),
                }
            } else {
                OpCanceller {
                    index: 0,
                    direction: None,
                }
            };
        }
        OpCanceller {
            index: self.index,
            #[cfg(feature = "legacy")]
            direction: None,
        }
    }
}

impl<T> Future for Op<T>
where
    T: Unpin + OpAble + 'static,
{
    type Output = Completion<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        let data_mut = me.data.as_mut().expect("unexpected operation state");
        let meta = ready!(me.driver.poll_op::<T>(data_mut, me.index, cx));

        me.index = usize::MAX;
        let data = me.data.take().expect("unexpected operation state");
        Poll::Ready(Completion { data, meta })
    }
}

#[cfg(all(target_os = "linux", feature = "iouring"))]
impl<T: OpAble> Drop for Op<T> {
    #[inline]
    fn drop(&mut self) {
        self.driver
            .drop_op(self.index, &mut self.data, T::SKIP_CANCEL);
    }
}

/// httpjet patch (#334): an armed MULTISHOT operation — one SQE producing a
/// stream of completions until its terminal CQE. `data` (e.g. the listener's
/// `SharedFd`) is pinned for the op's lifetime. io_uring-driver only.
pub(crate) struct MultiOp<T: 'static> {
    driver: super::Inner,
    index: usize,
    data: Option<T>,
}

impl<T> MultiOp<T> {
    #[cfg(all(target_os = "linux", feature = "iouring"))]
    pub(crate) fn new(driver: super::Inner, index: usize, data: T) -> Self {
        Self {
            driver,
            index,
            data: Some(data),
        }
    }

    #[cfg(all(target_os = "linux", feature = "iouring"))]
    pub(crate) fn data_mut(&mut self) -> &mut T {
        unsafe { self.data.as_mut().unwrap_unchecked() }
    }

    /// Arm a multishot operation on the current driver. `owns_fds` marks ops
    /// whose Ok results are kernel-created fds this process owns (multishot
    /// accept) so discarded results are closed, never leaked.
    pub(crate) fn submit_with(data: T, owns_fds: bool) -> io::Result<MultiOp<T>>
    where
        T: OpAble,
    {
        driver::CURRENT.with(|this| this.submit_multi_with(data, owns_fds))
    }

    /// `Ready(Some)` = next completion; `Ready(None)` = terminal CQE seen and
    /// queue drained (re-arm with a fresh `submit_with` to continue).
    pub(crate) fn poll_next_completion(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<CompletionMeta>> {
        if self.index == usize::MAX {
            return Poll::Ready(None);
        }
        let result = self.driver.poll_multi_op(self.index, cx);
        if matches!(result, Poll::Ready(None)) {
            // poll_multi removes the terminal slot. Never let a later poll,
            // cancellation or Drop touch a new operation reusing that index.
            self.index = usize::MAX;
        }
        result
    }

    /// Request cancellation without detaching the completion consumer. The
    /// caller must keep polling through the terminal CQE to prove quiescence.
    pub(crate) fn cancel(&mut self) {
        if self.index != usize::MAX {
            // SAFETY: this MultiOp still owns the live slab index; the terminal
            // polling path invalidates it before the index can be reused.
            unsafe {
                self.driver.cancel_op(&OpCanceller {
                    index: self.index,
                    #[cfg(feature = "legacy")]
                    direction: None,
                });
            }
        }
    }
}

impl<T> Drop for MultiOp<T> {
    fn drop(&mut self) {
        if self.index != usize::MAX {
            self.driver.drop_multi_op(self.index);
        }
    }
}

/// Check if current driver is legacy.
#[allow(unused)]
#[cfg(not(target_os = "linux"))]
#[inline]
pub const fn is_legacy() -> bool {
    true
}

/// Check if current driver is legacy.
#[cfg(target_os = "linux")]
#[inline]
pub fn is_legacy() -> bool {
    super::CURRENT.with(|inner| inner.is_legacy())
}

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub(crate) struct OpCanceller {
    pub(super) index: usize,
    #[cfg(feature = "legacy")]
    pub(super) direction: Option<super::ready::Direction>,
}

impl OpCanceller {
    pub(crate) unsafe fn cancel(&self) {
        super::CURRENT.with(|inner| inner.cancel_op(self))
    }
}
