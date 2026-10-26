//! Per-core deadlines for H1 response writes without a timer per write.
//!
//! Every H1 write runs under a send-progress deadline (#1125), and almost every write
//! completes long before it. A monoio timer per write paid a timer-wheel insert and
//! removal each time, which cost the hot H1 paths several percent CPU, so small complete
//! responses were once written with no deadline at all, and a client that left earlier
//! responses unread (or shrank its receive window) could hold such a write open
//! indefinitely. Instead a pending write records its deadline and waker in this core's
//! table, and one sweeper task per core, running only while a write is registered, wakes
//! the writes past their deadline. Like the other per-thread waker registries, this
//! assumes one monoio runtime per thread for the thread's life, as the serving cores run.

use std::cell::RefCell;
use std::task::Waker;
use std::time::{Duration, Instant};

/// How often the sweeper checks the registered deadlines: the most a deadline can be
/// overrun by. Send-progress windows are seconds long.
const SWEEP_EVERY: Duration = Duration::from_millis(100);

struct Entry {
    deadline: Instant,
    waker: Waker,
    expired: bool,
}

#[derive(Default)]
struct Table {
    entries: Vec<Option<Entry>>,
    free: Vec<usize>,
    live: usize,
    sweeping: bool,
}

thread_local! {
    static TABLE: RefCell<Table> = RefCell::new(Table::default());
}

/// One write's deadline. Registered on the write's first pending poll and removed on
/// drop.
pub(crate) struct Deadline {
    at: Instant,
    slot: Option<usize>,
}

impl Deadline {
    pub(crate) fn new(at: Instant) -> Self {
        Deadline { at, slot: None }
    }

    /// Whether the sweeper found the deadline passed.
    pub(crate) fn expired(&self) -> bool {
        self.slot.is_some_and(|slot| {
            TABLE.with(|t| {
                t.borrow()
                    .entries
                    .get(slot)
                    .and_then(Option::as_ref)
                    .is_some_and(|e| e.expired)
            })
        })
    }

    /// The write is pending: wake `waker` once the deadline passes.
    pub(crate) fn arm(&mut self, waker: &Waker) {
        TABLE.with(|t| {
            let mut t = t.borrow_mut();
            if let Some(entry) = self
                .slot
                .and_then(|slot| t.entries.get_mut(slot))
                .and_then(Option::as_mut)
            {
                if !entry.waker.will_wake(waker) {
                    entry.waker = waker.clone();
                }
                return;
            }
            let entry = Some(Entry {
                deadline: self.at,
                waker: waker.clone(),
                expired: false,
            });
            let free = t.free.pop();
            let slot = match free.and_then(|slot| Some((slot, t.entries.get_mut(slot)?))) {
                Some((slot, free)) => {
                    *free = entry;
                    slot
                }
                None => {
                    t.entries.push(entry);
                    t.entries.len() - 1
                }
            };
            self.slot = Some(slot);
            t.live += 1;
            if !t.sweeping {
                t.sweeping = true;
                monoio::spawn(sweep());
            }
        });
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        let Some(slot) = self.slot else {
            return;
        };
        // The table outlives every Deadline on this thread except during thread teardown.
        let _ = TABLE.try_with(|t| {
            let mut t = t.borrow_mut();
            if let Some(entry) = t.entries.get_mut(slot)
                && entry.take().is_some()
            {
                t.free.push(slot);
                t.live -= 1;
            }
        });
    }
}

async fn sweep() {
    loop {
        monoio::time::sleep(SWEEP_EVERY).await;
        let now = Instant::now();
        let mut due = Vec::new();
        let more = TABLE.with(|t| {
            let mut t = t.borrow_mut();
            for entry in t.entries.iter_mut().flatten() {
                if !entry.expired && entry.deadline <= now {
                    entry.expired = true;
                    due.push(entry.waker.clone());
                }
            }
            if t.live == 0 {
                t.sweeping = false;
            }
            t.live > 0
        });
        // Woken outside the borrow, which the woken writes take again when polled.
        for waker in due {
            waker.wake();
        }
        if !more {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::Poll;

    async fn under(deadline: Duration, work: impl Future<Output = ()>) -> bool {
        let mut work = pin!(work);
        let mut watch = Deadline::new(Instant::now() + deadline);
        std::future::poll_fn(|cx| {
            if watch.expired() {
                return Poll::Ready(false);
            }
            match work.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(true),
                Poll::Pending => {
                    watch.arm(cx.waker());
                    Poll::Pending
                }
            }
        })
        .await
    }

    #[test]
    fn a_stuck_write_is_woken_past_its_deadline_and_the_sweeper_stops() {
        let mut runtime = super::super::build_core_runtime().unwrap();
        runtime.block_on(async {
            let started = Instant::now();
            assert!(!under(Duration::from_millis(50), std::future::pending()).await);
            let took = started.elapsed();
            assert!(took >= Duration::from_millis(50), "{took:?}");
            assert!(
                took < Duration::from_millis(50) + 4 * SWEEP_EVERY,
                "{took:?}"
            );

            assert!(
                under(
                    Duration::from_secs(5),
                    monoio::time::sleep(Duration::from_millis(20))
                )
                .await
            );
            TABLE.with(|t| assert_eq!(t.borrow().live, 0, "every deadline was released"));
            monoio::time::sleep(3 * SWEEP_EVERY).await;
            TABLE.with(|t| assert!(!t.borrow().sweeping, "an idle core keeps no sweeper"));
        });
    }

    #[test]
    fn slots_are_reused_and_many_writes_share_one_sweeper() {
        let mut runtime = super::super::build_core_runtime().unwrap();
        runtime.block_on(async {
            let mut done = Vec::new();
            for i in 0..32u64 {
                done.push(monoio::spawn(under(
                    Duration::from_secs(5),
                    monoio::time::sleep(Duration::from_millis(5 + i % 7)),
                )));
            }
            for handle in done {
                assert!(handle.await);
            }
            TABLE.with(|t| {
                let t = t.borrow();
                assert_eq!(t.live, 0);
                assert!(t.entries.len() <= 32);
                assert_eq!(t.free.len(), t.entries.len());
            });
        });
    }
}
