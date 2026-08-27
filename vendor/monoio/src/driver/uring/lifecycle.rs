//! Uring state lifecycle.
//! Partly borrow from tokio-uring.

use std::{
    io,
    task::{Context, Poll, Waker},
};

use crate::{driver::op::CompletionMeta, utils::slab::Ref};

pub(crate) enum Lifecycle {
    /// The operation has been submitted to uring and is currently in-flight
    Submitted,

    /// The submitter is waiting for the completion of the operation
    Waiting(Waker),

    /// The submitter no longer has interest in the operation result. The state
    /// must be passed to the driver and held until the operation completes.
    #[allow(dead_code)]
    Ignored(Box<dyn std::any::Any>),

    /// The operation has completed.
    Completed(io::Result<u32>, u32),

    /// httpjet patch (#334): a MULTISHOT operation (one armed SQE, a stream of
    /// CQEs flagged `IORING_CQE_F_MORE`, then one terminal CQE without it).
    /// The slab slot stays alive across completions; results queue here until
    /// the consumer pops them. `done` = terminal CQE seen; `detached` =
    /// consumer dropped (drain-and-discard, closing owned fds); `owns_fds` =
    /// each Ok result is a kernel-created fd the process owns (multishot
    /// accept) and must be closed rather than leaked when discarded.
    MultiShot {
        results: std::collections::VecDeque<(io::Result<u32>, u32)>,
        waker: Option<Waker>,
        done: bool,
        detached: bool,
        owns_fds: bool,
    },
}

impl<'a> Ref<'a, Lifecycle> {
    pub(crate) fn complete(mut self, result: io::Result<u32>, flags: u32) {
        let ref_mut = &mut *self;
        match ref_mut {
            Lifecycle::Submitted => {
                *ref_mut = Lifecycle::Completed(result, flags);
            }
            Lifecycle::Waiting(_) => {
                let old = std::mem::replace(ref_mut, Lifecycle::Completed(result, flags));
                match old {
                    Lifecycle::Waiting(waker) => {
                        waker.wake();
                    }
                    _ => unsafe { std::hint::unreachable_unchecked() },
                }
            }
            Lifecycle::Ignored(..) => {
                self.remove();
            }
            Lifecycle::Completed(..) => unsafe { std::hint::unreachable_unchecked() },
            Lifecycle::MultiShot {
                results,
                waker,
                done,
                detached,
                owns_fds,
            } => {
                let more = io_uring::cqueue::more(flags);
                if *detached {
                    // Consumer is gone: discard, closing any fd we now own.
                    if *owns_fds {
                        if let Ok(fd) = &result {
                            unsafe { libc::close(*fd as libc::c_int) };
                        }
                    }
                    if !more {
                        self.remove();
                    }
                    return;
                }
                results.push_back((result, flags));
                if !more {
                    *done = true;
                }
                if let Some(w) = waker.take() {
                    w.wake();
                }
            }
        }
    }

    /// httpjet patch (#334): pop the next queued multishot completion.
    /// `Ready(Some)` = one completion; `Ready(None)` = the stream terminated
    /// (terminal CQE seen and queue drained — the consumer may re-arm);
    /// `Pending` = armed and waiting.
    pub(crate) fn poll_multi(mut self, cx: &mut Context<'_>) -> Poll<Option<CompletionMeta>> {
        let ref_mut = &mut *self;
        match ref_mut {
            Lifecycle::MultiShot {
                results,
                waker,
                done,
                ..
            } => {
                if let Some((result, flags)) = results.pop_front() {
                    return Poll::Ready(Some(CompletionMeta { result, flags }));
                }
                if *done {
                    self.remove();
                    return Poll::Ready(None);
                }
                match waker {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    _ => *waker = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    /// httpjet patch (#334): the multishot consumer is going away. Discards
    /// queued results (closing owned fds), and reports whether the slot is
    /// already terminal (true ⇒ removed here; false ⇒ caller must cancel the
    /// armed SQE and the terminal CQE will remove the slot).
    pub(crate) fn detach_multi(mut self) -> bool {
        let ref_mut = &mut *self;
        match ref_mut {
            Lifecycle::MultiShot {
                results,
                waker,
                done,
                detached,
                owns_fds,
            } => {
                waker.take();
                if *owns_fds {
                    for (result, _) in results.iter() {
                        if let Ok(fd) = result {
                            unsafe { libc::close(*fd as libc::c_int) };
                        }
                    }
                }
                results.clear();
                *detached = true;
                if *done {
                    self.remove();
                    return true;
                }
                false
            }
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn poll_op(mut self, cx: &mut Context<'_>) -> Poll<CompletionMeta> {
        let ref_mut = &mut *self;
        match ref_mut {
            Lifecycle::Submitted => {
                *ref_mut = Lifecycle::Waiting(cx.waker().clone());
                return Poll::Pending;
            }
            Lifecycle::Waiting(waker) => {
                if !waker.will_wake(cx.waker()) {
                    *ref_mut = Lifecycle::Waiting(cx.waker().clone());
                }
                return Poll::Pending;
            }
            _ => {}
        }

        match self.remove() {
            Lifecycle::Completed(result, flags) => Poll::Ready(CompletionMeta { result, flags }),
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    // return if the op must has been finished
    pub(crate) fn drop_op<T: 'static>(mut self, data: &mut Option<T>) -> bool {
        let ref_mut = &mut *self;
        match ref_mut {
            Lifecycle::Submitted | Lifecycle::Waiting(_) => {
                if let Some(data) = data.take() {
                    *ref_mut = Lifecycle::Ignored(Box::new(data));
                } else {
                    *ref_mut = Lifecycle::Ignored(Box::new(())); // () is a ZST, so it does not
                                                                 // allocate
                };
                return false;
            }
            Lifecycle::Completed(..) => {
                self.remove();
            }
            Lifecycle::Ignored(..) => unsafe { std::hint::unreachable_unchecked() },
            // MultiOp uses detach_multi, never drop_op.
            Lifecycle::MultiShot { .. } => unsafe { std::hint::unreachable_unchecked() },
        }
        true
    }
}
