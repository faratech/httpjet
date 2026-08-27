/// Monoio Driver.
#[allow(dead_code)]
pub(crate) mod op;
#[cfg(all(feature = "poll-io", unix))]
pub(crate) mod poll;
#[cfg(any(feature = "legacy", feature = "poll-io"))]
pub(crate) mod ready;
#[cfg(any(feature = "legacy", feature = "poll-io"))]
pub(crate) mod scheduled_io;
#[allow(dead_code)]
pub(crate) mod shared_fd;
#[cfg(feature = "sync")]
pub(crate) mod thread;

#[cfg(feature = "legacy")]
mod legacy;
#[cfg(all(target_os = "linux", feature = "iouring"))]
mod uring;

mod util;

use std::{
    io,
    task::{Context, Poll},
    time::Duration,
};

#[allow(unreachable_pub)]
#[cfg(feature = "legacy")]
pub use self::legacy::LegacyDriver;
#[cfg(feature = "legacy")]
use self::legacy::LegacyInner;
use self::op::{CompletionMeta, Op, OpAble};
#[cfg(all(target_os = "linux", feature = "iouring"))]
pub use self::uring::IoUringDriver;
#[cfg(all(target_os = "linux", feature = "iouring"))]
use self::uring::UringInner;

/// Unpark a runtime of another thread.
pub(crate) mod unpark {
    #[allow(dead_code, unreachable_pub)]
    pub trait Unpark: Sync + Send + 'static {
        /// Unblocks a thread that is blocked by the associated `Park` handle.
        ///
        /// Calling `unpark` atomically makes available the unpark token, if it
        /// is not already available.
        ///
        /// # Panics
        ///
        /// This function **should** not panic, but ultimately, panics are left
        /// as an implementation detail. Refer to the documentation for
        /// the specific `Unpark` implementation
        fn unpark(&self) -> std::io::Result<()>;
    }
}

impl unpark::Unpark for Box<dyn unpark::Unpark> {
    fn unpark(&self) -> io::Result<()> {
        (**self).unpark()
    }
}

impl unpark::Unpark for std::sync::Arc<dyn unpark::Unpark> {
    fn unpark(&self) -> io::Result<()> {
        (**self).unpark()
    }
}

/// Core driver trait.
pub trait Driver {
    /// Run with driver TLS.
    fn with<R>(&self, f: impl FnOnce() -> R) -> R;
    /// Submit ops to kernel and process returned events.
    fn submit(&self) -> io::Result<()>;
    /// Wait infinitely and process returned events.
    fn park(&self) -> io::Result<()>;
    /// Wait with timeout and process returned events.
    fn park_timeout(&self, duration: Duration) -> io::Result<()>;

    /// The struct to wake thread from another.
    #[cfg(feature = "sync")]
    type Unpark: unpark::Unpark;

    /// Get Unpark.
    #[cfg(feature = "sync")]
    fn unpark(&self) -> Self::Unpark;
}

scoped_thread_local!(pub(crate) static CURRENT: Inner);

#[derive(Clone)]
pub(crate) enum Inner {
    #[cfg(all(target_os = "linux", feature = "iouring"))]
    Uring(std::rc::Rc<std::cell::UnsafeCell<UringInner>>),
    #[cfg(feature = "legacy")]
    Legacy(std::rc::Rc<std::cell::UnsafeCell<LegacyInner>>),
}

impl Inner {
    fn submit_with<T: OpAble>(&self, data: T) -> io::Result<Op<T>> {
        match self {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            Inner::Uring(this) => UringInner::submit_with_data(this, data),
            #[cfg(feature = "legacy")]
            Inner::Legacy(this) => LegacyInner::submit_with_data(this, data),
            #[cfg(all(
                not(feature = "legacy"),
                not(all(target_os = "linux", feature = "iouring"))
            ))]
            _ => {
                util::feature_panic();
            }
        }
    }

    #[allow(unused)]
    fn poll_op<T: OpAble>(
        &self,
        data: &mut T,
        index: usize,
        cx: &mut Context<'_>,
    ) -> Poll<CompletionMeta> {
        match self {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            Inner::Uring(this) => UringInner::poll_op(this, index, cx),
            #[cfg(feature = "legacy")]
            Inner::Legacy(this) => LegacyInner::poll_op::<T>(this, data, cx),
            #[cfg(all(
                not(feature = "legacy"),
                not(all(target_os = "linux", feature = "iouring"))
            ))]
            _ => {
                util::feature_panic();
            }
        }
    }

    #[cfg(feature = "poll-io")]
    fn poll_legacy_op<T: OpAble>(
        &self,
        data: &mut T,
        cx: &mut Context<'_>,
    ) -> Poll<CompletionMeta> {
        match self {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            Inner::Uring(this) => UringInner::poll_legacy_op(this, data, cx),
            #[cfg(feature = "legacy")]
            Inner::Legacy(this) => LegacyInner::poll_op::<T>(this, data, cx),
            #[cfg(all(
                not(feature = "legacy"),
                not(all(target_os = "linux", feature = "iouring"))
            ))]
            _ => {
                util::feature_panic();
            }
        }
    }

    #[allow(unused)]
    fn drop_op<T: 'static>(&self, index: usize, data: &mut Option<T>) {
        match self {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            Inner::Uring(this) => UringInner::drop_op(this, index, data),
            #[cfg(feature = "legacy")]
            Inner::Legacy(_) => {}
            #[cfg(all(
                not(feature = "legacy"),
                not(all(target_os = "linux", feature = "iouring"))
            ))]
            _ => {
                util::feature_panic();
            }
        }
    }

    // httpjet patch (#334): MULTISHOT ops are io_uring-only (the legacy/epoll
    // driver has no equivalent — callers must fall back to single-shot there).
    fn submit_multi_with<T: OpAble>(&self, data: T, owns_fds: bool) -> io::Result<op::MultiOp<T>> {
        match self {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            Inner::Uring(this) => UringInner::submit_multi_with_data(this, data, owns_fds),
            #[cfg(feature = "legacy")]
            Inner::Legacy(_) => {
                let _ = (data, owns_fds);
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "multishot ops require the io_uring driver",
                ))
            }
            #[cfg(all(
                not(feature = "legacy"),
                not(all(target_os = "linux", feature = "iouring"))
            ))]
            _ => {
                util::feature_panic();
            }
        }
    }

    fn poll_multi_op(
        &self,
        index: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Option<op::CompletionMeta>> {
        match self {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            Inner::Uring(this) => UringInner::poll_multi_op(this, index, cx),
            #[cfg(feature = "legacy")]
            Inner::Legacy(_) => unreachable!("multishot ops require the io_uring driver"),
            #[cfg(all(
                not(feature = "legacy"),
                not(all(target_os = "linux", feature = "iouring"))
            ))]
            _ => {
                util::feature_panic();
            }
        }
    }

    fn drop_multi_op(&self, index: usize) {
        match self {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            Inner::Uring(this) => UringInner::drop_multi_op(this, index),
            #[cfg(feature = "legacy")]
            Inner::Legacy(_) => {}
            #[cfg(all(
                not(feature = "legacy"),
                not(all(target_os = "linux", feature = "iouring"))
            ))]
            _ => {
                util::feature_panic();
            }
        }
    }

    #[allow(unused)]
    pub(super) unsafe fn cancel_op(&self, op_canceller: &op::OpCanceller) {
        match self {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            Inner::Uring(this) => UringInner::cancel_op(this, op_canceller.index),
            #[cfg(feature = "legacy")]
            Inner::Legacy(this) => {
                if let Some(direction) = op_canceller.direction {
                    LegacyInner::cancel_op(this, op_canceller.index, direction)
                }
            }
            #[cfg(all(
                not(feature = "legacy"),
                not(all(target_os = "linux", feature = "iouring"))
            ))]
            _ => {
                util::feature_panic();
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "iouring", feature = "legacy"))]
    fn is_legacy(&self) -> bool {
        matches!(self, Inner::Legacy(..))
    }

    #[cfg(all(target_os = "linux", feature = "iouring", not(feature = "legacy")))]
    fn is_legacy(&self) -> bool {
        false
    }

    #[allow(unused)]
    #[cfg(not(all(target_os = "linux", feature = "iouring")))]
    fn is_legacy(&self) -> bool {
        true
    }
}

/// The unified UnparkHandle.
#[cfg(feature = "sync")]
#[derive(Clone)]
pub(crate) enum UnparkHandle {
    #[cfg(all(target_os = "linux", feature = "iouring"))]
    Uring(self::uring::UnparkHandle),
    #[cfg(feature = "legacy")]
    Legacy(self::legacy::UnparkHandle),
}

#[cfg(feature = "sync")]
impl unpark::Unpark for UnparkHandle {
    fn unpark(&self) -> io::Result<()> {
        match self {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            UnparkHandle::Uring(inner) => inner.unpark(),
            #[cfg(feature = "legacy")]
            UnparkHandle::Legacy(inner) => inner.unpark(),
            #[cfg(all(
                not(feature = "legacy"),
                not(all(target_os = "linux", feature = "iouring"))
            ))]
            _ => {
                util::feature_panic();
            }
        }
    }
}

#[cfg(all(feature = "sync", target_os = "linux", feature = "iouring"))]
impl From<self::uring::UnparkHandle> for UnparkHandle {
    fn from(inner: self::uring::UnparkHandle) -> Self {
        Self::Uring(inner)
    }
}

#[cfg(all(feature = "sync", feature = "legacy"))]
impl From<self::legacy::UnparkHandle> for UnparkHandle {
    fn from(inner: self::legacy::UnparkHandle) -> Self {
        Self::Legacy(inner)
    }
}

#[cfg(feature = "sync")]
impl UnparkHandle {
    #[allow(unused)]
    pub(crate) fn current() -> Self {
        CURRENT.with(|inner| match inner {
            #[cfg(all(target_os = "linux", feature = "iouring"))]
            Inner::Uring(this) => UringInner::unpark(this).into(),
            #[cfg(feature = "legacy")]
            Inner::Legacy(this) => LegacyInner::unpark(this).into(),
        })
    }
}
