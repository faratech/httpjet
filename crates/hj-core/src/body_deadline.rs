//! (#1035) Progress-based deadline for receiving one request body, shared by the
//! io_uring H1, native H2 and H3 transports.
//!
//! A body's deadline starts at `start + timeout` (LiteSpeed `connTimeout`). Each time
//! [`BODY_MIN_PROGRESS`] bytes have arrived since the last extension it moves to
//! `now + timeout`, never beyond `start + ceiling`. OpenLiteSpeed applies `connTimeout`
//! as an idle timeout, so a healthy upload slower than one window finishes there too;
//! the floor keeps #509's bound on a client that trickles bytes to hold its connection
//! and body-budget lease, and the ceiling bounds even a steady one.

use std::time::Duration;

/// Request-body bytes that must arrive within one timeout window to extend the
/// deadline (~273 B/s at 60 s). A trickle below it is cut at the timeout, as before.
pub const BODY_MIN_PROGRESS: u64 = 16 * 1024;

/// Hard bound on receiving one request body, however steadily it progresses.
pub const BODY_DEADLINE_CEILING: Duration = Duration::from_secs(15 * 60);

/// One request body's extension state: its ceiling and the cumulative byte count at the
/// last extension. The transport owns the deadline itself and passes it in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyProgress<I> {
    ceiling: I,
    mark: u64,
}

impl<I> BodyProgress<I>
where
    I: Copy + Ord + std::ops::Add<Duration, Output = I>,
{
    /// Starts at `start`; `received` counts bytes already in hand, which never extend.
    pub fn new(start: I, ceiling: Duration, received: u64) -> Self {
        Self {
            ceiling: start + ceiling,
            mark: received,
        }
    }

    /// Whether the cumulative `received` is [`BODY_MIN_PROGRESS`] past the last extension.
    pub fn due(&self, received: u64) -> bool {
        received.saturating_sub(self.mark) >= BODY_MIN_PROGRESS
    }

    /// Once due, move `deadline` to `now() + timeout`, capped at the ceiling and never
    /// earlier than it already is; `now` is called only then. Returns whether it moved.
    pub fn extend(
        &mut self,
        deadline: &mut I,
        received: u64,
        timeout: Duration,
        now: impl FnOnce() -> I,
    ) -> bool {
        if !self.due(received) {
            return false;
        }
        self.mark = received;
        let extended = (now() + timeout).min(self.ceiling);
        if extended <= *deadline {
            return false;
        }
        *deadline = extended;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const TIMEOUT: Duration = Duration::from_secs(60);

    fn no_clock() -> Instant {
        panic!("the clock is read only when the floor is crossed")
    }

    #[test]
    fn progress_below_the_floor_never_extends_or_reads_the_clock() {
        let start = Instant::now();
        let mut deadline = start + TIMEOUT;
        let mut progress = BodyProgress::new(start, BODY_DEADLINE_CEILING, 0);
        for received in [1, 100, BODY_MIN_PROGRESS - 1] {
            assert!(!progress.extend(&mut deadline, received, TIMEOUT, no_clock));
        }
        assert_eq!(deadline, start + TIMEOUT);
    }

    #[test]
    fn each_floor_of_progress_restarts_the_window() {
        let start = Instant::now();
        let mut deadline = start + TIMEOUT;
        let mut progress = BodyProgress::new(start, BODY_DEADLINE_CEILING, 0);
        let first = start + Duration::from_secs(50);
        assert!(progress.extend(&mut deadline, BODY_MIN_PROGRESS, TIMEOUT, || first));
        assert_eq!(deadline, first + TIMEOUT);
        // The count restarts at the extension: the next floor is measured from there.
        assert!(!progress.extend(&mut deadline, 2 * BODY_MIN_PROGRESS - 1, TIMEOUT, no_clock));
        let second = first + Duration::from_secs(50);
        assert!(progress.extend(&mut deadline, 2 * BODY_MIN_PROGRESS, TIMEOUT, || second));
        assert_eq!(deadline, second + TIMEOUT);
    }

    #[test]
    fn bytes_in_hand_at_the_start_do_not_extend() {
        let start = Instant::now();
        let mut deadline = start + TIMEOUT;
        let mut progress = BodyProgress::new(start, BODY_DEADLINE_CEILING, 64 * 1024);
        assert!(!progress.extend(&mut deadline, 64 * 1024 + 1, TIMEOUT, no_clock));
        assert!(progress.due(64 * 1024 + BODY_MIN_PROGRESS));
    }

    #[test]
    fn extensions_stop_at_the_ceiling() {
        let start = Instant::now();
        let ceiling = Duration::from_secs(90);
        let mut deadline = start + TIMEOUT;
        let mut progress = BodyProgress::new(start, ceiling, 0);
        let late = start + Duration::from_secs(55);
        assert!(progress.extend(&mut deadline, BODY_MIN_PROGRESS, TIMEOUT, || late));
        assert_eq!(deadline, start + ceiling);
        let later = late + Duration::from_secs(20);
        assert!(!progress.extend(&mut deadline, 2 * BODY_MIN_PROGRESS, TIMEOUT, || later));
        assert_eq!(deadline, start + ceiling);
    }

    #[test]
    fn a_ceiling_below_the_timeout_never_shortens_the_deadline() {
        let start = Instant::now();
        let mut deadline = start + TIMEOUT;
        let mut progress = BodyProgress::new(start, Duration::from_secs(30), 0);
        let now = start + Duration::from_secs(10);
        assert!(!progress.extend(&mut deadline, BODY_MIN_PROGRESS, TIMEOUT, || now));
        assert_eq!(deadline, start + TIMEOUT);
    }
}
