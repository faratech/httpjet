use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Instant;

static INLINE_READY: AtomicU64 = AtomicU64::new(0);
static INLINE_DEFERRED: AtomicU64 = AtomicU64::new(0);
static INLINE_SPILLED: AtomicU64 = AtomicU64::new(0);
const MAX_INLINE_ATTEMPTS: usize = 8;

thread_local! {
    // This covers one synchronous poll only, never a suspended task. A request
    // that declines the on-core path must leave the I/O driver before handing
    // work to the side runtime, as it would with normal task dispatch.
    static INLINE_POLL: Cell<bool> = const { Cell::new(false) };
}

struct InlinePollScope(bool);

impl InlinePollScope {
    fn enter() -> Self {
        Self(INLINE_POLL.replace(true))
    }
}

impl Drop for InlinePollScope {
    fn drop(&mut self) {
        INLINE_POLL.set(self.0);
    }
}

/// Finish the inline attempt before admitting work to the side runtime. A
/// pending inline future is always spawned by `inline_or_spawn`, whose first
/// task poll resumes here. Tasks that already left the driver proceed directly;
/// they incur no extra yield, wakeup, or scheduling round trip.
pub(super) async fn defer_bridge_from_inline() {
    poll_fn(|_| {
        if INLINE_POLL.get() {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await
}

pub(crate) struct SchedulingCounts {
    pub ready: u64,
    pub deferred: u64,
    pub spilled: u64,
}

pub(crate) fn counts() -> SchedulingCounts {
    SchedulingCounts {
        ready: INLINE_READY.load(Ordering::Relaxed),
        deferred: INLINE_DEFERRED.load(Ordering::Relaxed),
        spilled: INLINE_SPILLED.load(Ordering::Relaxed),
    }
}

pub(super) struct InlineBudget(usize);

impl Default for InlineBudget {
    fn default() -> Self {
        Self(MAX_INLINE_ATTEMPTS)
    }
}

pub(super) async fn dispatch_work<F>(future: F, eligible: bool, budget: &mut InlineBudget)
where
    F: Future<Output = ()> + 'static,
{
    if !eligible {
        monoio::spawn(future);
    } else if budget.0 == 0 {
        INLINE_SPILLED.fetch_add(1, Ordering::Relaxed);
        monoio::spawn(future);
    } else {
        budget.0 -= 1;
        inline_or_spawn(future).await;
    }
}

pub(super) async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => monoio::time::sleep_until(deadline.into()).await,
        None => std::future::pending::<()>().await,
    }
}

pub(super) async fn inline_or_spawn<F>(future: F)
where
    F: Future<Output = ()> + 'static,
{
    // A pending future may already hold internal references after its first poll.
    // Moving only the recycled handle preserves its pinned allocation and progress.
    let mut future = hj_core::Recycled::new(future);
    let first = poll_fn(|cx| {
        let _scope = InlinePollScope::enter();
        Poll::Ready(Pin::new(&mut future).poll(cx))
    })
    .await;
    match first {
        Poll::Ready(()) => {
            INLINE_READY.fetch_add(1, Ordering::Relaxed);
        }
        Poll::Pending => {
            INLINE_DEFERRED.fetch_add(1, Ordering::Relaxed);
            monoio::spawn(future);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::marker::PhantomPinned;
    use std::rc::Rc;
    use std::task::{Context, Waker};
    use std::time::Duration;

    #[test]
    fn elapsed_deadline_is_ready_even_when_first_polled_late() {
        let mut runtime = crate::uring::build_core_runtime().unwrap();
        runtime.block_on(async {
            let deadline = Instant::now() + Duration::from_millis(5);
            let mut sleep = hj_core::Recycled::new(sleep_until_opt(Some(deadline)));
            monoio::time::sleep(Duration::from_millis(20)).await;
            let first = poll_fn(|cx| Poll::Ready(Pin::new(&mut sleep).poll(cx))).await;
            assert!(first.is_ready());
        });
    }

    #[test]
    fn ready_work_completes_before_returning_to_the_driver() {
        let completed = Rc::new(Cell::new(0));
        let copy = completed.clone();
        let mut runtime = crate::uring::build_core_runtime().unwrap();
        runtime.block_on(async move {
            inline_or_spawn(async move { copy.set(copy.get() + 1) }).await;
            assert_eq!(completed.get(), 1);
        });
    }

    #[test]
    fn bridge_handoff_begins_after_the_inline_attempt_returns() {
        let probes = Rc::new(Cell::new(0));
        let starts = Rc::new(Cell::new(0));
        let probed = probes.clone();
        let started = starts.clone();
        let (done, completed) = tokio::sync::oneshot::channel();
        let mut runtime = crate::uring::build_core_runtime().unwrap();
        runtime.block_on(async move {
            inline_or_spawn(async move {
                probed.set(probed.get() + 1);
                // A nested completed probe must restore the enclosing scope.
                inline_or_spawn(async {}).await;
                defer_bridge_from_inline().await;
                started.set(started.get() + 1);
                done.send(()).unwrap();
            })
            .await;
            assert_eq!(probes.get(), 1);
            assert_eq!(starts.get(), 0, "bridge work started inside the driver");
            completed.await.unwrap();
            assert_eq!(probes.get(), 1, "the request was restarted");
            assert_eq!(starts.get(), 1);
        });
    }

    #[test]
    fn ordinary_task_handoff_is_ready_on_its_first_poll() {
        let mut runtime = crate::uring::build_core_runtime().unwrap();
        runtime.block_on(async {
            let mut handoff = hj_core::Recycled::new(defer_bridge_from_inline());
            let first = poll_fn(|cx| Poll::Ready(Pin::new(&mut handoff).poll(cx))).await;
            assert!(
                first.is_ready(),
                "ordinary dispatch incurred an extra yield"
            );
        });
    }

    #[test]
    fn inline_panic_does_not_leave_later_tasks_deferred() {
        let mut runtime = crate::uring::build_core_runtime().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(inline_or_spawn(async { panic!("request panic") }));
        }));
        assert!(result.is_err());
        runtime.block_on(async {
            let mut handoff = hj_core::Recycled::new(defer_bridge_from_inline());
            let first = poll_fn(|cx| Poll::Ready(Pin::new(&mut handoff).poll(cx))).await;
            assert!(first.is_ready(), "inline scope survived its poll unwinding");
        });
    }

    #[test]
    fn cancellation_before_bridge_handoff_releases_guards_without_dispatch() {
        let starts = Rc::new(Cell::new(0));
        let inflight = Rc::new(Cell::new(1));
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancellation = cancel.clone();
        let started = starts.clone();
        let count = inflight.clone();
        let (dropped, released) = tokio::sync::oneshot::channel();
        struct Release(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Release {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let release = Release(Some(dropped));
        let mut runtime = crate::uring::build_core_runtime().unwrap();
        runtime.block_on(async move {
            let work = async move {
                let _inflight = super::super::InflightGuard(count);
                let _release = release;
                defer_bridge_from_inline().await;
                started.set(started.get() + 1);
            };
            inline_or_spawn(super::super::run_cancelable_request(cancellation, work)).await;
            assert_eq!(starts.get(), 0);
            cancel.cancel();
            released.await.unwrap();
            assert_eq!(starts.get(), 0, "cancelled request reached the bridge");
            assert_eq!(inflight.get(), 0);
        });
    }

    struct AddressChecked {
        address: Cell<usize>,
        starts: Rc<Cell<usize>>,
        ready: Rc<Cell<bool>>,
        waker: Rc<RefCell<Option<Waker>>>,
        done: RefCell<Option<tokio::sync::oneshot::Sender<()>>>,
        _pinned: PhantomPinned,
    }

    impl Future for AddressChecked {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let this = self.as_ref().get_ref();
            let address = this as *const Self as usize;
            if this.address.get() == 0 {
                this.address.set(address);
                this.starts.set(this.starts.get() + 1);
            } else {
                assert_eq!(this.address.get(), address, "polled future moved");
            }
            if !this.ready.get() {
                *this.waker.borrow_mut() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            this.done.borrow_mut().take().unwrap().send(()).unwrap();
            Poll::Ready(())
        }
    }

    #[test]
    fn pending_work_keeps_its_pinned_address_and_executes_once() {
        let starts = Rc::new(Cell::new(0));
        let ready = Rc::new(Cell::new(false));
        let waker = Rc::new(RefCell::new(None));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let future = AddressChecked {
            address: Cell::new(0),
            starts: starts.clone(),
            ready: ready.clone(),
            waker: waker.clone(),
            done: RefCell::new(Some(tx)),
            _pinned: PhantomPinned,
        };
        let mut runtime = crate::uring::build_core_runtime().unwrap();
        runtime.block_on(async move {
            inline_or_spawn(future).await;
            assert_eq!(starts.get(), 1);
            ready.set(true);
            waker.borrow_mut().take().unwrap().wake();
            rx.await.unwrap();
            assert_eq!(starts.get(), 1);
        });
    }

    #[test]
    fn cancellation_drops_the_preserved_pending_work_and_its_guards() {
        struct Release {
            dropped: Rc<Cell<usize>>,
            done: Option<tokio::sync::oneshot::Sender<()>>,
        }
        impl Drop for Release {
            fn drop(&mut self) {
                self.dropped.set(self.dropped.get() + 1);
                let _ = self.done.take().unwrap().send(());
            }
        }
        let dropped = Rc::new(Cell::new(0));
        let inflight = Rc::new(Cell::new(1));
        let cancel = tokio_util::sync::CancellationToken::new();
        let copy = cancel.clone();
        let count = inflight.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let release = Release {
            dropped: dropped.clone(),
            done: Some(tx),
        };
        let mut runtime = crate::uring::build_core_runtime().unwrap();
        runtime.block_on(async move {
            let work = async move {
                let _inflight = super::super::InflightGuard(count);
                let _release = release;
                std::future::pending::<()>().await;
            };
            inline_or_spawn(super::super::run_cancelable_request(copy, work)).await;
            assert_eq!(dropped.get(), 0);
            cancel.cancel();
            rx.await.unwrap();
            assert_eq!(dropped.get(), 1);
            assert_eq!(inflight.get(), 0);
        });
    }

    #[test]
    fn mixed_ready_and_pending_work_spills_after_the_per_drive_limit() {
        let started = Rc::new(Cell::new(0));
        let completed = Rc::new(Cell::new(0));
        let (done_tx, done_rx) = flume::bounded(32);
        let mut runtime = crate::uring::build_core_runtime().unwrap();
        runtime.block_on(async move {
            let mut budget = InlineBudget::default();
            let mut release = Vec::new();
            for index in 0..32 {
                let started = started.clone();
                let completed = completed.clone();
                let done = done_tx.clone();
                let (tx, rx) = tokio::sync::oneshot::channel();
                release.push(tx);
                dispatch_work(
                    async move {
                        started.set(started.get() + 1);
                        if index % 2 == 1 {
                            rx.await.unwrap();
                        }
                        completed.set(completed.get() + 1);
                        done.send(index).unwrap();
                    },
                    true,
                    &mut budget,
                )
                .await;
            }
            assert_eq!(started.get(), MAX_INLINE_ATTEMPTS);
            assert_eq!(completed.get(), MAX_INLINE_ATTEMPTS / 2);
            for sender in release {
                let _ = sender.send(());
            }
            let mut results = Vec::new();
            for _ in 0..32 {
                results.push(done_rx.recv_async().await.unwrap());
            }
            results.sort_unstable();
            assert_eq!(results, (0..32).collect::<Vec<_>>());
            assert_eq!(started.get(), 32);
            assert_eq!(completed.get(), 32);
        });
    }
}
