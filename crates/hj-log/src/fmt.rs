//! Timestamp formatting helpers shared by the access and error loggers.
//!
//! These render `std::time::SystemTime` values without pulling in a date/time
//! crate, keeping the dependency surface small and the output deterministic for
//! a given instant (no hidden "now" reads).

use std::cell::RefCell;
use std::time::{SystemTime, UNIX_EPOCH};

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Broken-down UTC civil time. Always UTC; httpjet logs in UTC like LiteSpeed's
/// default and tags lines with `+0000`.
struct Civil {
    year: i64,
    month: u32, // 1..=12
    day: u32,   // 1..=31
    hour: u32,
    min: u32,
    sec: u32,
}

/// Convert a `SystemTime` to broken-down UTC fields using the well-known
/// civil-from-days algorithm (Howard Hinnant). Times before the epoch clamp to
/// the epoch — log timestamps are never in the past relative to 1970.
fn to_civil(ts: SystemTime) -> Civil {
    let secs = ts
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;

    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u32;
    let min = ((rem % 3600) / 60) as u32;
    let sec = (rem % 60) as u32;

    // days since 1970-01-01 -> civil date
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    Civil {
        year,
        month,
        day,
        hour,
        min,
        sec,
    }
}

/// Format the CLF timestamp for an already-broken-down civil time.
fn clf_fmt(c: &Civil) -> String {
    format!(
        "{:02}/{}/{:04}:{:02}:{:02}:{:02} +0000",
        c.day,
        MONTHS[(c.month - 1) as usize],
        c.year,
        c.hour,
        c.min,
        c.sec,
    )
}

/// Apache/CLF timestamp, e.g. `10/Oct/2000:13:55:36 +0000`.
///
/// Cached per-thread at 1-second granularity (CLF's own resolution): a burst of
/// requests served within the same wall-clock second by one worker formats the
/// civil-time math + string once and clones the cached value thereafter, instead of
/// recomputing `to_civil` + a 6-field `format!` per request. Mirrors how hyper caches
/// the `Date` header. The cache key is the whole-second epoch value, so distinct
/// timestamps (e.g. in unit tests) always re-render correctly.
pub fn clf_time(ts: SystemTime) -> String {
    let secs = ts
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    thread_local! {
        static CACHE: RefCell<(u64, String)> = const { RefCell::new((u64::MAX, String::new())) };
    }
    CACHE.with(|cell| {
        let mut cell = cell.borrow_mut();
        if cell.0 != secs {
            cell.1 = clf_fmt(&to_civil(ts));
            cell.0 = secs;
        }
        cell.1.clone()
    })
}

/// LiteSpeed-style error-log prefix timestamp with microseconds, e.g.
/// `2026-05-31 13:55:36.000000`.
pub fn error_time(ts: SystemTime) -> String {
    let c = to_civil(ts);
    let micros = ts
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_micros())
        .unwrap_or(0);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
        c.year, c.month, c.day, c.hour, c.min, c.sec, micros,
    )
}

/// Compact stamp used in rolled-file names, e.g. `2026_05_31_135536`.
/// Sortable and filesystem-safe.
pub fn roll_stamp(ts: SystemTime) -> String {
    let c = to_civil(ts);
    format!(
        "{:04}_{:02}_{:02}_{:02}{:02}{:02}",
        c.year, c.month, c.day, c.hour, c.min, c.sec,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn clf_epoch() {
        assert_eq!(clf_time(UNIX_EPOCH), "01/Jan/1970:00:00:00 +0000");
    }

    #[test]
    fn clf_known_instant() {
        // 2000-10-10T13:55:36Z == 971186136
        assert_eq!(clf_time(at(971_186_136)), "10/Oct/2000:13:55:36 +0000");
    }

    #[test]
    fn error_time_micros() {
        let t = UNIX_EPOCH + Duration::new(971_186_136, 123_456_000);
        assert_eq!(error_time(t), "2000-10-10 13:55:36.123456");
    }

    #[test]
    fn roll_stamp_format() {
        assert_eq!(roll_stamp(at(971_186_136)), "2000_10_10_135536");
    }

    #[test]
    fn leap_year_day() {
        // 2024-02-29T00:00:00Z == 1709164800
        assert_eq!(clf_time(at(1_709_164_800)), "29/Feb/2024:00:00:00 +0000");
    }
}
