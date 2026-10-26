//! `--fast-early-bridge`: hand a request to `dispatch()` before the on-core prefix when that
//! prefix provably cannot serve it.
//!
//! A cookieless route-shaped request runs the `.htaccess` chain, SetEnvIf, access and rewrite
//! on-core only to find a page-cache miss and bridge, and `dispatch()` then runs all of it
//! again. When the page cache cannot answer the path (no entry can be resident for it, or the
//! cache would bypass it anyway) and the static branch is certain to decline, nothing on-core
//! can serve the request, so it bridges at once. `dispatch()` is the full pipeline either way:
//! bridging earlier changes where the work runs, never what is served.
//!
//! `shadow` evaluates the decision but keeps today's path, counting each predicted request
//! that the on-core path nonetheless served (a forfeit if the mode were `on`).

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use super::fast_bridge::FastBridge;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Mode {
    Off = 0,
    Shadow = 1,
    On = 2,
}

impl Mode {
    pub(crate) fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "" => Some(Mode::Off),
            "shadow" => Some(Mode::Shadow),
            "on" | "1" => Some(Mode::On),
            _ => None,
        }
    }

    fn from_u8(v: u8) -> Mode {
        match v {
            1 => Mode::Shadow,
            2 => Mode::On,
            _ => Mode::Off,
        }
    }
}

/// The mode a new [`EarlyBridge`] starts in (set once from the command line).
pub(crate) static DEFAULT_MODE: AtomicU8 = AtomicU8::new(Mode::Off as u8);

/// Which on-core branch served a request the early bridge had predicted.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Branch {
    PageCache = 0,
    Static = 1,
}

pub(crate) struct EarlyBridge {
    mode: AtomicU8,
    /// Indexed by [`Self::reason_slot`].
    predicted: [AtomicU64; 2],
    /// Indexed by [`Branch`].
    forfeits: [AtomicU64; 2],
}

impl Default for EarlyBridge {
    fn default() -> Self {
        EarlyBridge {
            mode: AtomicU8::new(DEFAULT_MODE.load(Ordering::Relaxed)),
            predicted: Default::default(),
            forfeits: Default::default(),
        }
    }
}

impl EarlyBridge {
    pub(crate) fn mode(&self) -> Mode {
        Mode::from_u8(self.mode.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    pub(crate) fn set_mode(&self, mode: Mode) {
        self.mode.store(mode as u8, Ordering::Relaxed);
    }

    fn reason_slot(why: FastBridge) -> Option<usize> {
        match why {
            FastBridge::EarlyNoCache => Some(0),
            FastBridge::EarlyCacheAbsent => Some(1),
            _ => None,
        }
    }

    pub(crate) fn predict(&self, why: FastBridge) {
        if let Some(c) = Self::reason_slot(why).and_then(|i| self.predicted.get(i)) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn forfeit(&self, branch: Branch) {
        if let Some(c) = self.forfeits.get(branch as usize) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn predicted_snapshot(&self) -> [(&'static str, u64); 2] {
        let [no_cache, absent] = &self.predicted;
        [
            (
                FastBridge::EarlyNoCache.label(),
                no_cache.load(Ordering::Relaxed),
            ),
            (
                FastBridge::EarlyCacheAbsent.label(),
                absent.load(Ordering::Relaxed),
            ),
        ]
    }

    pub(crate) fn forfeit_snapshot(&self) -> [(&'static str, u64); 2] {
        let [page_cache, static_] = &self.forfeits;
        [
            ("page_cache", page_cache.load(Ordering::Relaxed)),
            ("static", static_.load(Ordering::Relaxed)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_parse_and_round_trip() {
        assert_eq!(Mode::parse("off"), Some(Mode::Off));
        assert_eq!(Mode::parse(" Shadow "), Some(Mode::Shadow));
        assert_eq!(Mode::parse("on"), Some(Mode::On));
        assert_eq!(Mode::parse("sometimes"), None);
        let eb = EarlyBridge::default();
        assert_eq!(eb.mode(), Mode::Off, "off unless configured");
        eb.set_mode(Mode::Shadow);
        assert_eq!(eb.mode(), Mode::Shadow);
    }

    #[test]
    fn only_early_reasons_are_counted_as_predictions() {
        let eb = EarlyBridge::default();
        eb.predict(FastBridge::EarlyCacheAbsent);
        eb.predict(FastBridge::EarlyCacheAbsent);
        eb.predict(FastBridge::Rewritten);
        eb.forfeit(Branch::Static);
        assert_eq!(eb.predicted_snapshot()[1], ("early_cache_absent", 2));
        assert_eq!(eb.predicted_snapshot()[0].1, 0);
        assert_eq!(eb.forfeit_snapshot(), [("page_cache", 0), ("static", 1)]);
    }
}
