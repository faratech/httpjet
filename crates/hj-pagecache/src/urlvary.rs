//! Per-URL cookie vary: the LiteSpeed `X-LiteSpeed-Vary: cookie=NAME` semantics for cookies
//! outside the global vary set.
//!
//! A response that declares `X-LiteSpeed-Vary: cookie=tz_date` makes THAT URL vary on the
//! `tz_date` cookie; other URLs keep their key. The store records a *spec* per base key (the
//! key every request computes today, before any per-URL dimension): base hash → sorted cookie
//! names. A lookup whose base key has a spec extends the key with those cookies' values from
//! the request; a URL without a spec never pays anything beyond one atomic load.
//!
//! The extension is appended to the key's `vary_value` as [`MARKER`] + `name=token;…`, so a
//! persisted (HJPC) variant entry is self-describing: the boot scan strips the suffix to
//! recover the base key and the names, and rebuilds the spec. Cookie values cannot contain
//! NUL or `;` (both are illegal in a `Cookie` header value / its separator), so the LAST
//! marker always splits a key unambiguously, and a key that never declared a per-URL vary
//! carries no marker at all — its bytes are exactly the historic key.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::key::{PageCacheKey, PhpCookieName, php_cookie_lookup};

/// Most extra cookie names one URL may vary on.
pub const MAX_NAMES: usize = 4;
/// Longest accepted vary cookie name.
pub const MAX_NAME_LEN: usize = 64;
/// Longest cookie value folded into a key; a longer value makes the request uncacheable.
pub const MAX_VALUE_LEN: usize = 128;
/// Variants one base key tracks; a new one past it evicts the least recently used.
pub const MAX_VARIANTS: usize = 64;
/// Distinct base keys that may carry a spec at once.
pub const MAX_SPECS: usize = 16_384;
/// Bound on the spec map's own (approximate) memory, independent of the page budgets.
pub const MAX_SPEC_BYTES: usize = 16 * 1024 * 1024;
/// A spec with no resident variant is dropped by `maintenance` once idle this long.
pub const SPEC_IDLE: Duration = Duration::from_secs(600);

/// Separates the base `vary_value` from the per-URL extension.
pub const MARKER: &str = "\0lsvary:";

/// A cookie name usable as a per-URL vary dimension (LSWS names are plain tokens).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Sorted, de-duplicated per-URL names with every globally-varied cookie removed (those are
/// already in every key). `None` when a name is malformed or there are more than [`MAX_NAMES`].
pub fn normalize_names<'a, S: AsRef<str>>(
    names: impl IntoIterator<Item = &'a str>,
    global: &[S],
) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        if global.iter().any(|g| g.as_ref() == name) {
            continue;
        }
        if !valid_name(name) {
            return None;
        }
        if !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    }
    if out.len() > MAX_NAMES {
        return None;
    }
    out.sort_unstable();
    Some(out)
}

/// The key extension for `names` (sorted) from the request `Cookie` header, or `None` when a
/// value cannot be keyed exactly (longer than [`MAX_VALUE_LEN`], or PHP's array form).
/// Absent and empty values are distinct (`-` vs `v:`), as they are in `$_COOKIE`.
pub fn suffix(cookie: Option<&str>, names: &[String]) -> Option<String> {
    let mut out = String::with_capacity(MARKER.len() + names.len() * 16);
    out.push_str(MARKER);
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            out.push(';');
        }
        out.push_str(name);
        out.push('=');
        match cookie.and_then(|c| php_cookie_lookup(c, name)) {
            None => out.push('-'),
            Some((PhpCookieName::Scalar(_), _, value)) if value.len() <= MAX_VALUE_LEN => {
                out.push_str("v:");
                out.push_str(value);
            }
            Some(_) => return None,
        }
    }
    Some(out)
}

/// `base` extended by a [`suffix`].
pub fn extend(base: &PageCacheKey, suffix: &str) -> PageCacheKey {
    let mut key = base.clone();
    key.vary_value.push_str(suffix);
    key
}

/// Split a variant key into its base key and the names it varies on; `None` for a key that
/// carries no (well-formed) extension.
pub fn split(key: &PageCacheKey) -> Option<(PageCacheKey, Vec<String>)> {
    let at = key.vary_value.rfind(MARKER)?;
    let ext = &key.vary_value[at + MARKER.len()..];
    let mut names = Vec::new();
    for part in ext.split(';') {
        let (name, token) = part.split_once('=')?;
        if !valid_name(name) || !(token == "-" || token.starts_with("v:")) {
            return None;
        }
        names.push(name.to_string());
    }
    if names.is_empty() || names.len() > MAX_NAMES || !names.windows(2).all(|w| w[0] < w[1]) {
        return None;
    }
    let mut base = key.clone();
    base.vary_value.truncate(at);
    Some((base, names))
}

/// An independent fingerprint of the base key, so a 64-bit base-hash collision (FNV is not
/// collision-resistant) never applies one URL's spec to another. `DefaultHasher::new()` is
/// fixed-seed SipHash: stable within and across processes.
fn base_check(base: &PageCacheKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    base.hash(&mut h);
    h.finish()
}

/// The hash a URL's path pre-filter bit is taken from: what [`PageCacheKey::vhost_id`] and
/// [`PageCacheKey::path`] are for every key family of one request, so a caller can ask "may
/// this path vary?" without building a key.
pub fn path_filter_hash(vhost_id: u32, path: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in vhost_id.to_le_bytes().iter().chain(path.as_bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

const FILTER_LOG2_BITS: u32 = 16;

/// A lock-free membership pre-filter over hashes. A set bit may be stale (a false positive
/// just costs the probe it saves); a member always has its bit set, which callers keep true by
/// marking under a shared gate that a rebuild or clear takes exclusively (see
/// `UrlVarySpecs::gate`).
pub(crate) struct BitFilter {
    words: Box<[AtomicU64]>,
    shift: u32,
}

impl BitFilter {
    fn new() -> Self {
        Self::with_log2_bits(FILTER_LOG2_BITS)
    }

    /// A filter of `2^log2_bits` bits (at least 64).
    pub(crate) fn with_log2_bits(log2_bits: u32) -> Self {
        let log2_bits = log2_bits.clamp(6, 40);
        BitFilter {
            words: (0..(1u64 << log2_bits) / 64)
                .map(|_| AtomicU64::new(0))
                .collect(),
            shift: 64 - log2_bits,
        }
    }

    #[inline]
    fn slot(&self, hash: u64) -> (usize, u64) {
        let bit = (hash ^ (hash >> 29)).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> self.shift;
        ((bit >> 6) as usize, 1u64 << (bit & 63))
    }

    /// Fraction of bits set (the false-positive rate of a single probe).
    pub(crate) fn fill_ratio(&self) -> f64 {
        let set: u64 = self
            .words
            .iter()
            .map(|w| u64::from(w.load(Ordering::Relaxed).count_ones()))
            .sum();
        set as f64 / (self.words.len() as f64 * 64.0)
    }

    pub(crate) fn set(&self, hash: u64) {
        let (w, mask) = self.slot(hash);
        if let Some(word) = self.words.get(w)
            && word.load(Ordering::Relaxed) & mask == 0
        {
            word.fetch_or(mask, Ordering::Release);
        }
    }

    #[inline]
    pub(crate) fn test(&self, hash: u64) -> bool {
        let (w, mask) = self.slot(hash);
        self.words
            .get(w)
            .is_some_and(|word| word.load(Ordering::Acquire) & mask != 0)
    }

    pub(crate) fn clear(&self) {
        for word in self.words.iter() {
            word.store(0, Ordering::Release);
        }
    }

    /// Replace the contents with exactly `hashes`.
    pub(crate) fn rebuild(&self, hashes: impl Iterator<Item = u64>) {
        self.install(self.words_for(hashes), std::iter::empty());
    }

    /// The word array holding exactly `hashes`, for [`Self::install`]; building it
    /// touches only fresh memory, so it needs none of the caller's locks.
    pub(crate) fn words_for(&self, hashes: impl Iterator<Item = u64>) -> Vec<u64> {
        let mut fresh = vec![0u64; self.words.len()];
        for hash in hashes {
            let (w, mask) = self.slot(hash);
            if let Some(word) = fresh.get_mut(w) {
                *word |= mask;
            }
        }
        fresh
    }

    /// Replace the contents with `words` (from [`Self::words_for`]) plus `extra`.
    pub(crate) fn install(&self, mut words: Vec<u64>, extra: impl Iterator<Item = u64>) {
        for hash in extra {
            let (w, mask) = self.slot(hash);
            if let Some(word) = words.get_mut(w) {
                *word |= mask;
            }
        }
        for (word, value) in self.words.iter().zip(words) {
            word.store(value, Ordering::Release);
        }
    }
}

/// Approximate heap + map bytes of one spec without variants, and per tracked variant.
const SPEC_BYTES: usize = 160;
const VARIANT_BYTES: usize = 48;

struct Spec {
    names: Arc<[String]>,
    check: u64,
    /// [`path_filter_hash`] of the base key (to rebuild the path pre-filter).
    path_hash: u64,
    /// Variant key hash → last use (ms on the map's clock).
    variants: HashMap<u64, AtomicU64>,
    /// Newest variant stored under this spec (the boot scan's newest-wins tie-break).
    newest: Instant,
    /// Last store or served hit (ms on the map's clock).
    touched: AtomicU64,
    /// Bytes this spec is charged in [`UrlVarySpecs::bytes`].
    charged: usize,
}

impl Spec {
    fn cost(&self) -> usize {
        SPEC_BYTES
            + self.names.iter().map(|n| n.len() + 24).sum::<usize>()
            + self.variants.len() * VARIANT_BYTES
    }
}

/// What the boot scan does with one restored entry.
pub(crate) enum ScanVerdict {
    Keep,
    /// The restored entry lost to a newer spec decision: invalidate it.
    Drop,
}

/// The per-store spec map. Lock order: a spec shard lock may be held while a page shard is
/// locked (residency checks, invalidations), never the reverse.
///
/// Accounting invariant: `len` and `bytes` change only inside the map-shard critical
/// section that inserts, mutates or removes the spec they describe, so they equal the sum
/// over resident specs once concurrent operations settle (no bulk reset ever races them).
/// Memory is bounded by [`MAX_SPECS`] and [`MAX_SPEC_BYTES`]; the least recently touched
/// spec is evicted to admit a new one.
pub(crate) struct UrlVarySpecs {
    map: DashMap<u64, Spec>,
    len: AtomicUsize,
    bytes: AtomicUsize,
    clock: Instant,
    /// Pre-filter over base hashes: a URL with no spec is answered by one atomic load.
    bases: BitFilter,
    /// Pre-filter over [`path_filter_hash`] (for callers that hold no key).
    paths: BitFilter,
    /// Held shared around every mark + insert, exclusively by a filter rebuild or clear, so
    /// a rebuild's word stores never erase a concurrently inserted spec's bit. Lookups never
    /// take it. Order: gate, then map shard, then page shard.
    gate: parking_lot::RwLock<()>,
    /// Map probes made (the pre-filters' effectiveness, asserted by tests).
    #[cfg(test)]
    probes: AtomicUsize,
}

impl Default for UrlVarySpecs {
    fn default() -> Self {
        UrlVarySpecs {
            map: DashMap::new(),
            len: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            clock: Instant::now(),
            bases: BitFilter::new(),
            paths: BitFilter::new(),
            gate: parking_lot::RwLock::new(()),
            #[cfg(test)]
            probes: AtomicUsize::new(0),
        }
    }
}

/// A touch rewrites the shared last-use stamps at most this often.
const TOUCH_GRANULARITY_MS: u64 = 1000;

impl UrlVarySpecs {
    fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len.load(Ordering::Acquire) == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }

    /// Lock-free: `false` means no spec exists for `base_hash`.
    #[inline]
    pub(crate) fn may_have(&self, base_hash: u64) -> bool {
        if self.is_empty() || !self.bases.test(base_hash) {
            return false;
        }
        #[cfg(test)]
        self.probes.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Lock-free: `false` means no spec exists for any key of `vhost_id` + `path`.
    pub(crate) fn may_vary_path(&self, vhost_id: u32, path: &str) -> bool {
        !self.is_empty() && self.paths.test(path_filter_hash(vhost_id, path))
    }

    /// Before (or while) `spec` is in the map under `base_hash`.
    fn mark(&self, base_hash: u64, spec: &Spec) {
        self.bases.set(base_hash);
        self.paths.set(spec.path_hash);
    }

    /// Inside the spec's shard lock: re-charge `spec` after a mutation.
    fn recharge(&self, spec: &mut Spec) {
        let cost = spec.cost();
        if cost > spec.charged {
            self.bytes.fetch_add(cost - spec.charged, Ordering::AcqRel);
        } else {
            self.bytes.fetch_sub(spec.charged - cost, Ordering::AcqRel);
        }
        spec.charged = cost;
    }

    /// Inside the spec's shard lock, as it leaves the map.
    fn uncharge(&self, spec: &Spec) {
        self.len.fetch_sub(1, Ordering::AcqRel);
        self.bytes.fetch_sub(spec.charged, Ordering::AcqRel);
    }

    /// Inside the slot's shard lock, as `spec` enters the map.
    fn charge_new(&self, spec: &mut Spec) {
        spec.charged = spec.cost();
        self.len.fetch_add(1, Ordering::AcqRel);
        self.bytes.fetch_add(spec.charged, Ordering::AcqRel);
    }

    fn retire(spec: &Spec, base_hash: u64, invalidate: &impl Fn(u64)) {
        for hash in spec.variants.keys() {
            invalidate(*hash);
        }
        invalidate(base_hash);
    }

    pub(crate) fn names(&self, base_hash: u64, base: &PageCacheKey) -> Option<Arc<[String]>> {
        if !self.may_have(base_hash) {
            return None;
        }
        let spec = self.map.get(&base_hash)?;
        (spec.check == base_check(base)).then(|| spec.names.clone())
    }

    /// A served hit on `variant_hash`: keeps the spec and the variant recently used.
    pub(crate) fn touch(&self, base_hash: u64, variant_hash: u64) {
        if !self.may_have(base_hash) {
            return;
        }
        if let Some(spec) = self.map.get(&base_hash) {
            let now = self.now_ms();
            // Read first: a hot variant writes its shared stamps at most once a second.
            let stale = |stamp: &AtomicU64| {
                now.saturating_sub(stamp.load(Ordering::Relaxed)) >= TOUCH_GRANULARITY_MS
            };
            if stale(&spec.touched) {
                spec.touched.store(now, Ordering::Relaxed);
            }
            if let Some(used) = spec.variants.get(&variant_hash)
                && stale(used)
            {
                used.store(now, Ordering::Relaxed);
            }
        }
    }

    /// The URL no longer varies: drop its spec, retiring every variant and the base entry.
    pub(crate) fn drop_spec(&self, base: &PageCacheKey, base_hash: u64, invalidate: impl Fn(u64)) {
        if !self.may_have(base_hash) {
            return;
        }
        let check = base_check(base);
        let removed = self.map.remove_if(&base_hash, |_, spec| {
            let hit = spec.check == check;
            if hit {
                self.uncharge(spec);
            }
            hit
        });
        if let Some((_, spec)) = removed {
            Self::retire(&spec, base_hash, &invalidate);
        }
    }

    /// Evict the least recently touched spec (never `keep`). `false` when there is none.
    fn evict_oldest(&self, keep: u64, invalidate: &impl Fn(u64)) -> bool {
        let victim = self
            .map
            .iter()
            .filter(|e| *e.key() != keep)
            .min_by_key(|e| e.value().touched.load(Ordering::Relaxed))
            .map(|e| *e.key());
        let Some(victim) = victim else {
            return false;
        };
        let removed = self.map.remove_if(&victim, |_, spec| {
            self.uncharge(spec);
            true
        });
        if let Some((_, spec)) = removed {
            Self::retire(&spec, victim, invalidate);
        }
        true
    }

    /// Record an ADMITTED variant of a varying URL just before it is stored: (re)set the
    /// spec to `names` (non-empty) and register `variant_hash`, evicting the least recently
    /// used variant at the per-URL cap and the least recently touched spec at the global
    /// bounds. `false` ⇒ do not store (a base-hash collision, or no room could be made).
    /// The caller has already retired the un-varied base entry.
    pub(crate) fn prepare(
        &self,
        base: &PageCacheKey,
        base_hash: u64,
        names: &[String],
        variant_hash: u64,
        resident: impl Fn(u64) -> bool,
        invalidate: impl Fn(u64),
    ) -> bool {
        let check = base_check(base);
        let now_ms = self.now_ms();
        // Make room BEFORE taking a slot: the scan read-locks every map shard.
        if !self.map.contains_key(&base_hash) {
            let new_cost =
                SPEC_BYTES + VARIANT_BYTES + names.iter().map(|n| n.len() + 24).sum::<usize>();
            while (self.len() >= MAX_SPECS || self.bytes() + new_cost > MAX_SPEC_BYTES)
                && self.evict_oldest(base_hash, &invalidate)
            {}
            if self.len() >= MAX_SPECS || self.bytes() + new_cost > MAX_SPEC_BYTES {
                return false;
            }
        }
        // Shared: excludes only a filter rebuild/clear, never another store or a lookup.
        let _gate = self.gate.read();
        match self.map.entry(base_hash) {
            Entry::Occupied(mut slot) => {
                let spec = slot.get_mut();
                if spec.check != check {
                    return false;
                }
                if *spec.names != *names {
                    for hash in spec.variants.keys() {
                        invalidate(*hash);
                    }
                    spec.variants.clear();
                    spec.names = names.into();
                }
                let full = |spec: &Spec| {
                    spec.variants.len() >= MAX_VARIANTS
                        || self.bytes() + VARIANT_BYTES > MAX_SPEC_BYTES
                };
                if !spec.variants.contains_key(&variant_hash) && full(spec) {
                    spec.variants.retain(|hash, _| resident(*hash));
                    self.recharge(spec);
                    // At the per-URL cap or the global byte bound, a new variant replaces
                    // this URL's least recently used one instead of growing the map.
                    if full(spec) {
                        let lru = spec
                            .variants
                            .iter()
                            .min_by_key(|(_, used)| used.load(Ordering::Relaxed))
                            .map(|(hash, _)| *hash);
                        if let Some(lru) = lru {
                            spec.variants.remove(&lru);
                            invalidate(lru);
                        }
                    }
                }
                spec.variants.insert(variant_hash, AtomicU64::new(now_ms));
                spec.newest = Instant::now();
                spec.touched.store(now_ms, Ordering::Relaxed);
                self.recharge(spec);
                self.mark(base_hash, spec);
                true
            }
            Entry::Vacant(slot) => {
                let mut variants = HashMap::new();
                variants.insert(variant_hash, AtomicU64::new(now_ms));
                let mut spec = Spec {
                    names: names.into(),
                    check,
                    path_hash: path_filter_hash(base.vhost_id, &base.path),
                    variants,
                    newest: Instant::now(),
                    touched: AtomicU64::new(now_ms),
                    charged: 0,
                };
                self.charge_new(&mut spec);
                self.mark(base_hash, &spec);
                slot.insert(spec);
                true
            }
        }
    }

    /// After a store: is the stored entry still the one the spec map routes to? A concurrent
    /// store with a different vary decision may have run between `prepare` and the commit.
    pub(crate) fn confirm(
        &self,
        base: &PageCacheKey,
        base_hash: u64,
        names: &[String],
        stored_hash: u64,
    ) -> bool {
        if !self.may_have(base_hash) {
            return names.is_empty();
        }
        let check = base_check(base);
        match self.map.get(&base_hash).filter(|spec| spec.check == check) {
            None => names.is_empty(),
            Some(spec) => *spec.names == *names && spec.variants.contains_key(&stored_hash),
        }
    }

    /// Fold one boot-restored entry into the spec map (newest decision wins).
    pub(crate) fn register_scanned(
        &self,
        key: &PageCacheKey,
        key_hash: u64,
        stored_at: Instant,
        hash_of: impl Fn(&PageCacheKey) -> u64,
        base_stored_at: impl Fn(u64) -> Option<Instant>,
        invalidate: impl Fn(u64),
    ) -> ScanVerdict {
        let now_ms = self.now_ms();
        let Some((base, names)) = split(key) else {
            // An un-varied entry: it loses to a newer spec for the same base key.
            if self.is_empty() {
                return ScanVerdict::Keep;
            }
            let check = base_check(key);
            let removed = self.map.remove_if(&key_hash, |_, spec| {
                let newer = spec.check == check && stored_at > spec.newest;
                if newer {
                    self.uncharge(spec);
                }
                newer
            });
            if let Some((_, spec)) = removed {
                for hash in spec.variants.keys() {
                    invalidate(*hash);
                }
                return ScanVerdict::Keep;
            }
            return match self.map.get(&key_hash) {
                Some(spec) if spec.check == check => ScanVerdict::Drop,
                _ => ScanVerdict::Keep,
            };
        };
        let base_hash = hash_of(&base);
        let check = base_check(&base);
        // Shared: excludes only a filter rebuild/clear, never another store or a lookup.
        let _gate = self.gate.read();
        match self.map.entry(base_hash) {
            Entry::Occupied(mut slot) => {
                let spec = slot.get_mut();
                if spec.check != check {
                    return ScanVerdict::Drop;
                }
                if *spec.names != *names {
                    if stored_at <= spec.newest {
                        return ScanVerdict::Drop;
                    }
                    for hash in spec.variants.keys() {
                        invalidate(*hash);
                    }
                    spec.variants.clear();
                    spec.names = names.into();
                }
                if !spec.variants.contains_key(&key_hash)
                    && (spec.variants.len() >= MAX_VARIANTS
                        || self.bytes() + VARIANT_BYTES > MAX_SPEC_BYTES)
                {
                    return ScanVerdict::Drop;
                }
                spec.variants.insert(key_hash, AtomicU64::new(now_ms));
                spec.newest = spec.newest.max(stored_at);
                spec.touched.store(now_ms, Ordering::Relaxed);
                self.recharge(spec);
                self.mark(base_hash, spec);
                ScanVerdict::Keep
            }
            Entry::Vacant(slot) => {
                if base_stored_at(base_hash).is_some_and(|at| at >= stored_at) {
                    return ScanVerdict::Drop;
                }
                let new_cost =
                    SPEC_BYTES + VARIANT_BYTES + names.iter().map(|n| n.len() + 24).sum::<usize>();
                if self.len() >= MAX_SPECS || self.bytes() + new_cost > MAX_SPEC_BYTES {
                    return ScanVerdict::Drop;
                }
                invalidate(base_hash);
                let mut variants = HashMap::new();
                variants.insert(key_hash, AtomicU64::new(now_ms));
                let mut spec = Spec {
                    names: names.into(),
                    check,
                    path_hash: path_filter_hash(base.vhost_id, &base.path),
                    variants,
                    newest: stored_at,
                    touched: AtomicU64::new(now_ms),
                    charged: 0,
                };
                self.charge_new(&mut spec);
                self.mark(base_hash, &spec);
                slot.insert(spec);
                ScanVerdict::Keep
            }
        }
    }

    /// Drop every spec (purge-all). Each removal is uncharged inside its own shard lock, so a
    /// store racing the purge keeps `len`/`bytes` exact.
    pub(crate) fn clear(&self) {
        {
            // A spec marked before the zeroing is removed by the retain below; one marked
            // after it keeps its bits.
            let _gate = self.gate.write();
            self.bases.clear();
            self.paths.clear();
        }
        self.map.retain(|_, spec| {
            self.uncharge(spec);
            false
        });
    }

    /// Forget non-resident variants; drop idle specs with none left (and the base entry they
    /// shadow).
    pub(crate) fn prune(&self, resident: impl Fn(u64) -> bool, invalidate: impl Fn(u64)) {
        if self.is_empty() {
            return;
        }
        let now_ms = self.now_ms();
        let idle_ms = SPEC_IDLE.as_millis() as u64;
        self.map.retain(|base_hash, spec| {
            spec.variants.retain(|hash, _| resident(*hash));
            let touched = spec.touched.load(Ordering::Relaxed);
            let keep = !spec.variants.is_empty() || now_ms.saturating_sub(touched) < idle_ms;
            if keep {
                self.recharge(spec);
            } else {
                self.uncharge(spec);
                invalidate(*base_hash);
            }
            keep
        });
        // Rebuild the pre-filters from the survivors. The gate excludes every mark+insert for
        // the snapshot + word stores, so no concurrently stored spec loses its bit.
        let _gate = self.gate.write();
        self.bases.rebuild(self.map.iter().map(|e| *e.key()));
        self.paths
            .rebuild(self.map.iter().map(|e| e.value().path_hash));
    }

    #[cfg(test)]
    fn settled_totals(&self) -> (usize, usize) {
        self.map
            .iter()
            .fold((0, 0), |(n, b), e| (n + 1, b + e.value().charged))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PageCacheKey {
        PageCacheKey::public(7, true, "tdih.example", "/", "")
    }
    #[test]
    fn names_are_sorted_deduped_and_drop_global_cookies() {
        let global = vec!["xf_style_id".to_string()];
        assert_eq!(
            normalize_names(["tz_date", "a-b", "xf_style_id", "tz_date"], &global).unwrap(),
            vec!["a-b".to_string(), "tz_date".to_string()]
        );
        assert_eq!(
            normalize_names(["xf_style_id"], &global).unwrap(),
            Vec::<String>::new()
        );
        assert!(normalize_names(["bad name"], &global).is_none());
        assert!(normalize_names(["x;y"], &global).is_none());
        assert!(normalize_names([&"n".repeat(65)[..]], &global).is_none());
        assert!(normalize_names(["a", "b", "c", "d", "e"], &global).is_none());
        assert!(normalize_names(["a", "b", "c", "d"], &global).is_some());
    }

    #[test]
    fn suffix_distinguishes_absent_empty_and_values() {
        let names = vec!["tz_date".to_string()];
        let absent = suffix(None, &names).unwrap();
        let other = suffix(Some("xf_csrf=1"), &names).unwrap();
        let empty = suffix(Some("tz_date="), &names).unwrap();
        let d17 = suffix(Some("a=1; tz_date=10-17"), &names).unwrap();
        let d18 = suffix(Some("tz_date=10-18"), &names).unwrap();
        assert_eq!(absent, "\0lsvary:tz_date=-");
        assert_eq!(absent, other);
        assert_eq!(empty, "\0lsvary:tz_date=v:");
        assert_eq!(d17, "\0lsvary:tz_date=v:10-17");
        assert_ne!(d17, d18);
        assert_ne!(absent, empty);
        let long = format!("tz_date={}", "x".repeat(MAX_VALUE_LEN + 1));
        assert!(suffix(Some(&long), &names).is_none());
        let ok = format!("tz_date={}", "x".repeat(MAX_VALUE_LEN));
        assert!(suffix(Some(&ok), &names).is_some());
        assert!(suffix(Some("tz_date[a]=1"), &names).is_none());
    }

    #[test]
    fn split_inverts_extend_and_ignores_plain_keys() {
        let mut b = base();
        b.vary_value = "\0httpjet-config:1:2\0xf_style_id=v:3".into();
        let names = vec!["a".to_string(), "tz_date".to_string()];
        let sfx = suffix(Some("tz_date=10-17; a=x=y"), &names).unwrap();
        let k = extend(&b, &sfx);
        let (got_base, got_names) = split(&k).unwrap();
        assert_eq!(got_base, b);
        assert_eq!(got_names, names);
        assert!(split(&b).is_none());
        assert!(split(&base()).is_none());
    }

    fn hash(k: &PageCacheKey) -> u64 {
        crate::key_hash(k)
    }

    fn variant(b: &PageCacheKey, v: &str) -> PageCacheKey {
        extend(
            b,
            &suffix(Some(&format!("tz_date={v}")), &["tz_date".into()]).unwrap(),
        )
    }

    #[test]
    fn boot_scan_keeps_the_newest_vary_decision() {
        let specs = UrlVarySpecs::default();
        let b = base();
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let tz = variant(&b, "1");
        let lang = extend(&b, &suffix(Some("lang=fr"), &["lang".into()]).unwrap());
        let invalidated = std::cell::RefCell::new(Vec::new());
        let inv = |h: u64| invalidated.borrow_mut().push(h);
        let scan = |k: &PageCacheKey, t: Instant, base_at: Option<Instant>| {
            specs.register_scanned(k, hash(k), t, hash, |_| base_at, inv)
        };
        // An older un-varied base entry already restored loses to the variant.
        assert!(matches!(scan(&tz, at(10), Some(at(5))), ScanVerdict::Keep));
        assert_eq!(invalidated.borrow().as_slice(), &[hash(&b)]);
        assert_eq!(
            &*specs.names(hash(&b), &b).unwrap(),
            ["tz_date".to_string()]
        );
        // An older variant under a different vary set is dropped ...
        assert!(matches!(scan(&lang, at(5), None), ScanVerdict::Drop));
        // ... a newer one replaces the spec and retires the older variants.
        invalidated.borrow_mut().clear();
        assert!(matches!(scan(&lang, at(20), None), ScanVerdict::Keep));
        assert_eq!(invalidated.borrow().as_slice(), &[hash(&tz)]);
        assert_eq!(&*specs.names(hash(&b), &b).unwrap(), ["lang".to_string()]);
        // An un-varied base entry older than the spec is dropped; a newer one wins.
        assert!(matches!(scan(&b, at(15), None), ScanVerdict::Drop));
        assert!(matches!(scan(&b, at(30), None), ScanVerdict::Keep));
        assert!(specs.names(hash(&b), &b).is_none());
        assert_eq!((specs.len(), specs.bytes()), (0, 0));
        // A variant older than a restored base entry is dropped.
        let specs2 = UrlVarySpecs::default();
        assert!(matches!(
            specs2.register_scanned(&tz, hash(&tz), at(1), hash, |_| Some(at(2)), |_| {}),
            ScanVerdict::Drop
        ));
        assert!(specs2.is_empty());
    }

    #[test]
    fn a_colliding_base_hash_never_borrows_another_urls_spec() {
        let specs = UrlVarySpecs::default();
        let b = base();
        let other = PageCacheKey::public(7, true, "tdih.example", "/other", "");
        let names = vec!["tz_date".to_string()];
        assert!(specs.prepare(&b, 1, &names, 10, |_| true, |_| {}));
        assert!(specs.names(1, &other).is_none());
        assert!(!specs.prepare(&other, 1, &names, 11, |_| true, |_| {}));
        specs.drop_spec(&other, 1, |_| {});
        assert!(specs.names(1, &b).is_some());
    }

    #[test]
    fn the_per_url_cap_evicts_the_least_recently_used_variant() {
        let specs = UrlVarySpecs::default();
        let b = base();
        let names = vec!["tz_date".to_string()];
        let evicted = std::cell::RefCell::new(Vec::new());
        // Every variant stays resident (warm or stale-retained): residency cannot free a slot.
        for i in 0..MAX_VARIANTS as u64 {
            assert!(specs.prepare(
                &b,
                1,
                &names,
                100 + i,
                |_| true,
                |h| evicted.borrow_mut().push(h)
            ));
            std::thread::sleep(Duration::from_millis(1));
        }
        // Variant 100 is the oldest store, but a served hit makes 101 the LRU instead (touch
        // rewrites a stamp at most once per TOUCH_GRANULARITY_MS).
        std::thread::sleep(Duration::from_millis(TOUCH_GRANULARITY_MS + 50));
        specs.touch(1, 100);
        evicted.borrow_mut().clear();
        assert!(specs.prepare(&b, 1, &names, 9, |_| true, |h| evicted.borrow_mut().push(h)));
        assert_eq!(evicted.borrow().as_slice(), &[101]);
        assert!(specs.confirm(&b, 1, &names, 9));
        assert!(specs.confirm(&b, 1, &names, 100));
        assert!(!specs.confirm(&b, 1, &names, 101));
        assert_eq!(specs.settled_totals(), (specs.len(), specs.bytes()));
    }

    #[test]
    fn global_bounds_evict_the_least_recently_touched_spec() {
        let specs = UrlVarySpecs::default();
        let names = vec!["tz_date".to_string()];
        for i in 0..MAX_SPECS as u64 {
            let b = PageCacheKey::public(7, true, "tdih.example", format!("/?q={i}"), "");
            assert!(specs.prepare(&b, i, &names, 1_000_000 + i, |_| true, |_| {}));
        }
        assert_eq!(specs.len(), MAX_SPECS);
        assert!(specs.bytes() <= MAX_SPEC_BYTES);
        let hot = PageCacheKey::public(7, true, "tdih.example", "/?q=0", "");
        // (touch rewrites a stamp at most once per TOUCH_GRANULARITY_MS)
        std::thread::sleep(Duration::from_millis(TOUCH_GRANULARITY_MS + 50));
        specs.touch(0, 1_000_000);
        let retired = std::cell::RefCell::new(Vec::new());
        let newcomer = PageCacheKey::public(7, true, "tdih.example", "/new", "");
        assert!(specs.prepare(
            &newcomer,
            u64::MAX,
            &names,
            7,
            |_| true,
            |h| retired.borrow_mut().push(h)
        ));
        assert_eq!(specs.len(), MAX_SPECS);
        assert!(specs.names(0, &hot).is_some(), "the touched spec survives");
        // The evicted spec's variant and base were retired with it.
        assert_eq!(retired.borrow().len(), 2);
        assert!(specs.names(u64::MAX, &newcomer).is_some());
        assert_eq!(specs.settled_totals(), (specs.len(), specs.bytes()));
    }

    /// `clear` racing stores and prunes must leave the counters equal to the map: a desync
    /// either wraps `len` (refusing every new varying URL) or hides a live spec.
    #[test]
    fn accounting_survives_clear_racing_prepare_and_prune() {
        let specs = Arc::new(UrlVarySpecs::default());
        let names: Arc<[String]> = vec!["tz_date".to_string()].into();
        for round in 0..20u64 {
            std::thread::scope(|s| {
                for t in 0..4u64 {
                    let specs = specs.clone();
                    let names = names.clone();
                    s.spawn(move || {
                        for i in 0..300u64 {
                            let h = (round << 32) | (t << 16) | i;
                            let b = PageCacheKey::public(7, true, "x", format!("/{h}"), "");
                            specs.prepare(&b, h, &names, h ^ 0xff, |_| true, |_| {});
                            if i % 7 == 0 {
                                specs.drop_spec(&b, h, |_| {});
                            }
                        }
                    });
                }
                let a = specs.clone();
                s.spawn(move || {
                    for _ in 0..50 {
                        a.clear();
                    }
                });
                let p = specs.clone();
                s.spawn(move || {
                    for _ in 0..50 {
                        p.prune(|h| h % 3 != 0, |_| {});
                    }
                });
            });
            assert_eq!(
                specs.settled_totals(),
                (specs.len(), specs.bytes()),
                "{round}"
            );
        }
        specs.clear();
        specs.prune(|_| false, |_| {});
        assert_eq!((specs.len(), specs.bytes()), (0, 0));
        assert!(specs.is_empty());
        let b = base();
        assert!(specs.prepare(&b, 1, &names, 2, |_| true, |_| {}));
        assert_eq!(specs.len(), 1);
    }

    /// While specs exist, a URL without one is answered by the lock-free pre-filters: no map
    /// probe (beyond the rare false positive), and the same for the store-side calls.
    #[test]
    fn non_varying_lookups_skip_the_map_while_specs_exist() {
        let specs = UrlVarySpecs::default();
        let names = vec!["tz_date".to_string()];
        let b = base();
        assert!(specs.prepare(&b, hash(&b), &names, 99, |_| true, |_| {}));
        assert!(specs.names(hash(&b), &b).is_some());
        assert!(specs.may_vary_path(b.vhost_id, &b.path));
        let before = specs.probes.load(Ordering::Relaxed);
        for i in 0..10_000 {
            let other = PageCacheKey::public(7, true, "tdih.example", format!("/p{i}"), "");
            let h = hash(&other);
            assert!(specs.names(h, &other).is_none());
            assert!(specs.confirm(&other, h, &[], h));
            specs.drop_spec(&other, h, |_| panic!("nothing to retire"));
            specs.touch(h, h);
            // The path filter is consulted by callers that hold no key at all.
            let _ = specs.may_vary_path(other.vhost_id, &other.path);
        }
        // One bit is set of 65,536: 40,000 probes expect < 1 false positive per call kind.
        let probes = specs.probes.load(Ordering::Relaxed) - before;
        assert!(probes <= 8, "{probes} map probes for URLs without a spec");
        // Once the spec is gone, its own hash and path stop probing too.
        specs.clear();
        let before = specs.probes.load(Ordering::Relaxed);
        assert!(specs.names(hash(&b), &b).is_none());
        assert!(!specs.may_vary_path(b.vhost_id, &b.path));
        assert_eq!(specs.probes.load(Ordering::Relaxed), before);
    }

    /// The byte bound holds while existing specs GROW (new variants on known URLs), and a
    /// new varying URL is still admitted once the bound is reached.
    #[test]
    fn the_byte_bound_holds_under_variant_growth() {
        let specs = UrlVarySpecs::default();
        let names = vec!["tz_date".to_string()];
        let urls = 6_000u64;
        for v in 0..MAX_VARIANTS as u64 {
            for u in 0..urls {
                let b = PageCacheKey::public(7, true, "x", format!("/u{u}"), "");
                specs.prepare(&b, u, &names, (u << 8) | v, |_| true, |_| {});
            }
            assert!(
                specs.bytes() <= MAX_SPEC_BYTES,
                "{} > {MAX_SPEC_BYTES} after {v} rounds",
                specs.bytes()
            );
        }
        assert_eq!(specs.settled_totals(), (specs.len(), specs.bytes()));
        let fresh = PageCacheKey::public(7, true, "x", "/fresh", "");
        assert!(specs.prepare(&fresh, u64::MAX, &names, 1, |_| true, |_| {}));
        assert!(specs.names(u64::MAX, &fresh).is_some());
        assert!(specs.bytes() <= MAX_SPEC_BYTES);
    }

    /// A filter rebuild (prune) racing new specs must never erase a stored spec's bits: every
    /// spec is visible through both pre-filters as soon as its `prepare` returns.
    #[test]
    fn filter_rebuild_never_hides_a_concurrently_stored_spec() {
        let specs = Arc::new(UrlVarySpecs::default());
        let names: Arc<[String]> = vec!["tz_date".to_string()].into();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let misses = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|s| {
            let p = specs.clone();
            let halt = stop.clone();
            s.spawn(move || {
                while !halt.load(Ordering::Relaxed) {
                    p.prune(|_| true, |_| {});
                }
            });
            let mut workers = Vec::new();
            for t in 0..4u64 {
                let specs = specs.clone();
                let names = names.clone();
                let misses = misses.clone();
                workers.push(s.spawn(move || {
                    for i in 0..3_000u64 {
                        let b = PageCacheKey::public(7, true, "x", format!("/{t}/{i}"), "");
                        let h = hash(&b);
                        assert!(specs.prepare(&b, h, &names, h ^ 1, |_| true, |_| {}));
                        if specs.names(h, &b).is_none() || !specs.may_vary_path(7, &b.path) {
                            misses.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }));
            }
            for w in workers {
                w.join().unwrap();
            }
            stop.store(true, Ordering::Relaxed);
        });
        assert_eq!(
            misses.load(Ordering::Relaxed),
            0,
            "pre-filter false negatives"
        );
        // And after the race settles every spec is still found.
        let found = (0..4u64)
            .flat_map(|t| (0..3_000u64).map(move |i| (t, i)))
            .filter(|(t, i)| {
                let b = PageCacheKey::public(7, true, "x", format!("/{t}/{i}"), "");
                specs.names(hash(&b), &b).is_some()
            })
            .count();
        assert_eq!(found, specs.len());
    }
}
