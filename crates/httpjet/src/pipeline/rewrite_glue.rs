//! Rewrite-stage glue: run the inline + `.htaccess` rewrite chain (with the
//! outcome cache), build the [`RewriteInput`], and the request-path
//! decode/normalize/encode helpers every downstream consumer agrees on.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hj_core::{ReqCtx, Request};
use hj_rewrite::{
    CacheKeyVar, HeaderLookup, Htaccess, RewriteInput, RewriteOutcome, RuleSet, StatSource,
    evaluate,
};
use http::Uri;

use crate::state::ServerState;

/// Process-start instant anchoring [`RewriteOutcomeCache::last_prune`] millis.
fn prune_epoch() -> &'static std::time::Instant {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(std::time::Instant::now)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RwResult {
    Proxy {
        target_url: String,
        env: Vec<(String, String)>,
    },
    Redirect {
        code: u16,
        location: String,
        env: Vec<(String, String)>,
    },
    Status {
        code: u16,
        env: Vec<(String, String)>,
    },
    Forbidden,
    Gone,
    /// `query` mirrors the rewrite engine's effective query: `Some(q)` for a query the
    /// rewritten URI carries (newly set, or the original retained when the substitution had
    /// no `?query`), and `None` when the rewrite leaves NO query at all — `[QSD]`, or a
    /// substitution that dropped it. `None` must become an empty query, NOT the original
    /// (resurrecting the original is what defeated `[QSD]`).
    Rewritten {
        path: String,
        query: Option<String>,
        env: Vec<(String, String)>,
    },
    Unchanged {
        env: Vec<(String, String)>,
    },
}

/// Default TTL for the rewrite-outcome cache. Matched to `StatCache`'s 1 s TTL:
/// a cached outcome incorporates the `-f`/`-d` filesystem state seen at eval
/// time, so reusing it for ≤1 s keeps the same filesystem-staleness guarantee
/// the rest of the server already accepts (and lets `.htaccess` edits take
/// effect within ~1 s, like any fs change).
pub(crate) const DEFAULT_REWRITE_OUTCOME_TTL: Duration = Duration::from_secs(1);

/// Upper bound on one [`OutcomeKey`]'s total string footprint; oversized
/// requests bypass the outcome cache (see `run_rewrite`). Generous for real
/// traffic: thread-slug paths run a few hundred bytes, UAs under ~400.
const MAX_OUTCOME_KEY_BYTES: usize = 2048;

/// UAs longer than this are junk (real UAs top out well under 1 KiB): their
/// classify bitmap is computed but never memoized, so a flood can't occupy
/// [`UaClassifyCache`]'s cap.
const MAX_MEMO_UA_BYTES: usize = 1024;

/// Cache key for a memoizable rewrite outcome. Only used for rulesets whose
/// [`hj_rewrite::RuleSet::path_cacheable`] is true, so the outcome is a pure
/// function of exactly these fields (plus filesystem state, bounded by the TTL).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OutcomeKey {
    vhost: String,
    https: bool,
    method: String,
    host: String,
    path: String,
    query: String,
    /// Values of the chain's KEYABLE dynamic vars (currently just `%{HTTP_USER_AGENT}`),
    /// folded in so a UA-reading chain caches per (base key, UA) instead of being
    /// uncacheable. Empty when no ruleset reads a keyable var.
    key_vars: String,
}

/// TTL-coalesced, bounded cache of rewrite outcomes for `path_cacheable`
/// rulesets — lets repeated requests skip full ruleset evaluation. Mirrors
/// `StatCache`: cap-gated inserts (cold entries skip caching once full) and a
/// lazy per-read TTL check.
#[derive(Debug, Clone)]
struct OutcomeSlot {
    at: Instant,
    outcome: RwResult,
    key: OutcomeKey,
}

pub(crate) struct RewriteOutcomeCache {
    /// (#313) Hash-first: keyed by an FxHash over the borrowed key parts so a
    /// lookup never builds the 7-String OutcomeKey; the stored full key verifies
    /// equality on hit (a rare hash collision degrades to a miss / replaces on
    /// insert — an efficiency loss, never wrong content).
    map: DashMap<u64, OutcomeSlot>,
    ttl: Duration,
    cap: usize,
    /// Approximate entry count for the cap gate — `DashMap::len()` sweeps every
    /// shard, and a full map paid that sweep on every insert attempt. Entries
    /// are never removed (TTL expiry replaces in place), so a counter bumped on
    /// new-key insert is exact up to insert races.
    count: AtomicUsize,
    /// (L3) Last time `prune_expired` ran, in millis since the process-start epoch
    /// ([`prune_epoch`]). Gates the O(N) sweep so a flood of distinct new keys at the
    /// cap triggers a full-map prune at most once per TTL instead of on every insert.
    /// An atomic (not a Mutex): the gate is checked on the REQUEST path at cap, and a
    /// global lock there serializes every worker under a crawler flood.
    last_prune: std::sync::atomic::AtomicU64,
    /// (#313) Gate for the BOUNDED synchronous rescue in `insert_hashed`: when the
    /// async sweep hasn't freed a slot in time, ONE caller per 10x TTL may run the
    /// O(N) walk inline so a legitimately-expired-at-cap cache keeps admitting;
    /// everyone else skips the insert instead of re-walking.
    last_sync_prune: std::sync::atomic::AtomicU64,
}

impl RewriteOutcomeCache {
    pub(crate) fn new(ttl: Duration) -> Self {
        RewriteOutcomeCache {
            map: DashMap::new(),
            ttl,
            cap: 65_536,
            count: AtomicUsize::new(0),
            last_prune: std::sync::atomic::AtomicU64::new(0),
            last_sync_prune: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn with_cap(ttl: Duration, cap: usize) -> Self {
        RewriteOutcomeCache {
            map: DashMap::new(),
            ttl,
            cap,
            count: AtomicUsize::new(0),
            last_prune: std::sync::atomic::AtomicU64::new(0),
            last_sync_prune: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Drop every memoized outcome and reset the count. Called on SIGHUP reload so a
    /// changed INLINE RewriteRule takes effect immediately, mirroring the sibling
    /// `rewrite_cache.clear()` (the OutcomeKey carries no rule version, so a warm entry
    /// would otherwise replay the pre-reload decision for up to one TTL).
    pub(crate) fn clear(&self) {
        self.map.clear();
        self.count.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Fresh cached outcome for `key`, or `None` if absent/expired/disabled.
    fn get(&self, key: &OutcomeKey) -> Option<RwResult> {
        self.probe(Self::key_hash(key), &|k| k == key)
    }

    /// Borrowed-parts probe (#313): hashes without allocating, then verifies the
    /// stored full key against the caller's borrows.
    fn probe(&self, hash: u64, matches: &dyn Fn(&OutcomeKey) -> bool) -> Option<RwResult> {
        if self.ttl.is_zero() {
            return None;
        }
        let e = self.map.get(&hash)?;
        if e.at.elapsed() < self.ttl && matches(&e.key) {
            Some(e.outcome.clone())
        } else {
            None
        }
    }

    /// FxHash over every key component (domain-separated by length-prefixed
    /// writes via Hasher::write's internal scheme? No — write() is raw bytes, so
    /// separators are written explicitly).
    fn key_hash(key: &OutcomeKey) -> u64 {
        Self::parts_hash(
            &key.vhost,
            key.https,
            &key.method,
            &key.host,
            &key.path,
            &key.query,
            &key.key_vars,
        )
    }

    fn parts_hash(
        vhost: &str,
        https: bool,
        method: &str,
        host: &str,
        path: &str,
        query: &str,
        key_vars: &str,
    ) -> u64 {
        use std::hash::Hasher;
        let mut h = rustc_hash::FxHasher::default();
        for part in [vhost, method, host, path, query, key_vars] {
            h.write(&(part.len() as u32).to_le_bytes());
            h.write(part.as_bytes());
        }
        h.write(&[https as u8]);
        h.finish()
    }

    /// Store `outcome` for `key` (refreshing an existing entry; otherwise only
    /// when below the cap, so memory is bounded without an eviction sweep).
    fn insert(self: &Arc<Self>, key: OutcomeKey, outcome: RwResult) {
        let hash = Self::key_hash(&key);
        self.insert_hashed(hash, key, outcome);
    }

    /// Store under a caller-computed hash with the borrowed parts verified at probe
    /// time (#313). At cap for a NEW key: trigger the (detached, once-per-TTL)
    /// sweep and otherwise SKIP the insert — the cache is best-effort. The removed
    /// synchronous fallback re-ran the full O(N) walk ON THE REQUEST THREAD for
    /// every cold insert while the map stayed full of LIVE entries (nothing to
    /// expire), so a crawler flood at cap stalled every worker on DashMap shard
    /// walks between the once-per-TTL async sweeps.
    fn insert_hashed(self: &Arc<Self>, hash: u64, key: OutcomeKey, outcome: RwResult) {
        if self.ttl.is_zero() {
            return;
        }
        if self.count.load(Ordering::Relaxed) >= self.cap && !self.map.contains_key(&hash) {
            self.maybe_prune_expired();
            if self.count.load(Ordering::Relaxed) >= self.cap {
                // The detached sweep hasn't landed yet. ONE caller per 10x TTL may
                // run the walk inline so an expired-at-cap cache keeps admitting;
                // every other cold insert just skips (best-effort).
                let now = prune_epoch().elapsed().as_millis() as u64;
                let window = (self.ttl.as_millis() as u64).saturating_mul(10).max(100);
                let last = self.last_sync_prune.load(Ordering::Relaxed);
                // last == 0 means never run: allow immediately regardless of the
                // (process-uptime based) clock being younger than the window.
                if last == 0
                    || now.saturating_sub(last) >= window
                        && self
                            .last_sync_prune
                            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                            .is_ok()
                {
                    self.prune_expired();
                }
                if self.count.load(Ordering::Relaxed) >= self.cap {
                    return;
                }
            }
        }
        if self
            .map
            .insert(
                hash,
                OutcomeSlot {
                    at: Instant::now(),
                    outcome,
                    key,
                },
            )
            .is_none()
        {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Run `prune_expired` at most once per TTL (L3). Between sweeps the cap simply keeps
    /// rejecting cold new keys (unchanged behavior), so this only bounds the sweep frequency,
    /// never correctness. The gate is a lock-free CAS on an atomic; the winner hands the
    /// O(N) sweep to a DETACHED THREAD so no request thread ever iterates the whole map
    /// while holding DashMap shard locks (a crawler flood at cap must not stall serving).
    fn maybe_prune_expired(self: &Arc<Self>) {
        let now = prune_epoch().elapsed().as_millis() as u64;
        let last = self.last_prune.load(Ordering::Relaxed);
        if now.saturating_sub(last) < self.ttl.as_millis() as u64 {
            return;
        }
        if self
            .last_prune
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let sweeper = Arc::clone(self);
        std::thread::Builder::new()
            .name("rewrite-outcome-prune".into())
            .spawn(move || sweeper.prune_expired())
            .map(|_| ())
            .unwrap_or_else(|_| self.prune_expired());
    }

    fn prune_expired(&self) {
        let ttl = self.ttl;
        let expired: Vec<u64> = self
            .map
            .iter()
            .filter_map(|e| (e.value().at.elapsed() >= ttl).then(|| *e.key()))
            .collect();
        for hash in expired {
            if self.map.remove(&hash).is_some() {
                self.count.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Whether the outcome cache is on at all (`--rewrite-outcome-ttl-ms 0` = off).
    fn enabled(&self) -> bool {
        !self.ttl.is_zero()
    }
}

/// Bounded memo of `(ruleset id, User-Agent) -> UA-cond match bitmap`
/// ([`RuleSet::ua_cond_signature`]) so the crawler-block regexes run once per
/// distinct UA per ruleset instead of once per request. The value is a pure
/// function of its key — a ruleset reparse/reload mints a fresh id
/// ([`RuleSet::id`]), so entries for dead rulesets can never be replayed; they
/// are dropped wholesale by [`Self::clear`] on SIGHUP (see
/// `ServerState::reload`) and otherwise bounded by the insert cap. No TTL: the
/// mapping never goes stale while the id lives.
pub(crate) struct UaClassifyCache {
    map: DashMap<(u64, String), u64>,
    cap: usize,
    count: AtomicUsize,
    /// Last cap-triggered wholesale flush — see [`Self::maybe_flush_full`].
    last_flush: std::sync::Mutex<Instant>,
}

impl UaClassifyCache {
    pub(crate) fn new() -> Self {
        UaClassifyCache {
            map: DashMap::new(),
            cap: 65_536,
            count: AtomicUsize::new(0),
            last_flush: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// The memoized bitmap for (`rs`, `ua`), computing + (cap-gated) inserting on miss.
    fn get_or_compute(&self, rs: &RuleSet, ua: &str) -> u64 {
        if ua.len() > MAX_MEMO_UA_BYTES {
            return rs.ua_cond_signature(ua);
        }
        let key = (rs.id(), ua.to_string());
        if let Some(sig) = self.map.get(&key) {
            return *sig;
        }
        let sig = rs.ua_cond_signature(ua);
        if self.count.load(Ordering::Relaxed) >= self.cap {
            self.maybe_flush_full();
        }
        if self.count.load(Ordering::Relaxed) < self.cap && self.map.insert(key, sig).is_none() {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
        sig
    }

    /// Entries have no TTL (the mapping never goes stale while the ruleset id
    /// lives), so a junk-UA flood that fills the cap would otherwise pin the
    /// memo cold until SIGHUP. Flush wholesale at most once per hour when full:
    /// legitimate UAs re-memoize at one regex pass each; the flood pays its own
    /// cost.
    fn maybe_flush_full(&self) {
        let mut last = self
            .last_flush
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.elapsed() < Duration::from_secs(3600) {
            return;
        }
        *last = Instant::now();
        drop(last);
        self.clear();
    }

    /// Wholesale invalidation (SIGHUP config reload).
    pub(crate) fn clear(&self) {
        self.map.clear();
        self.count.store(0, Ordering::Relaxed);
    }

    /// Approximate entry count (metrics gauge).
    pub(crate) fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

/// Run the inline rewrite rules then the `.htaccess` chain (`chain`, already
/// loaded + gated by the caller); return the first non-`Unchanged` outcome (env
/// from skipped `Unchanged` rulesets is merged).
///
/// Per-ruleset behavior:
/// * `RewriteInput::per_directory_prefix` (#6) is set to each `.htaccess`'s
///   directory path relative to docroot so `-f`/`-d`/`%{REQUEST_FILENAME}`
///   resolve against the right file for nested directories. The inline ruleset
///   has no prefix.
/// * `is_end()` (A): an `[END]` outcome stops processing every later ruleset and
///   the rewritten URI is NOT re-dispatched through the engine.
///
/// Wraps [`run_rewrite_inner`] with the outcome cache: when every ruleset in the
/// effective chain (inline + `.htaccess`) is `path_cacheable`, the result is
/// memoized by [`OutcomeKey`] for the configured TTL (`--rewrite-outcome-ttl-ms`,
/// default [`DEFAULT_REWRITE_OUTCOME_TTL`]; 0 disables the cache). Uncacheable
/// chains (e.g. any rule reading `%{HTTP_COOKIE}`) bypass the cache with no
/// added work beyond the per-ruleset boolean check.
pub(super) fn run_rewrite(
    state: &ServerState,
    ctx: &ReqCtx,
    req: &Request,
    chain: &[(PathBuf, Arc<Htaccess>)],
    path: &str,
    query: &str,
) -> RwResult {
    if !state.rewrite_outcomes.enabled() {
        // `--rewrite-outcome-ttl-ms 0`: the cache is off entirely — no key build,
        // no counters (disabled is not "uncacheable").
        return run_rewrite_inner(state, ctx, req, chain, path, query);
    }
    let inline = state.inline_rules.get(&ctx.vhost_name);
    let cacheable = inline.is_none_or(|rs| rs.path_cacheable)
        && chain.iter().all(|(_, ht)| ht.rules.path_cacheable);
    // The `%{ENV:REDIRECT_STATUS}`-style constant-empty classification only holds
    // while the live env seed really lacks the name (see `assumed_empty_env`): a
    // `SetEnvIf … REDIRECT_STATUS=…` (or any future pre-rewrite seed) would make
    // the outcome depend on an input outside the key. `ctx.env` at this point IS
    // the exact seed the engine will read (SetEnvIf already merged), so checking
    // it dynamically covers every possible writer.
    let assumed_env_absent = || {
        let seeded = |rs: &RuleSet| {
            rs.assumed_empty_env
                .iter()
                .any(|name| ctx.get_env(name).is_some())
        };
        !(inline.is_some_and(|rs| seeded(rs)) || chain.iter().any(|(_, ht)| seeded(&ht.rules)))
    };
    if !cacheable || !assumed_env_absent() {
        state
            .metrics
            .rewrite_outcome_uncacheable
            .fetch_add(1, Ordering::Relaxed);
        return run_rewrite_inner(state, ctx, req, chain, path, query);
    }
    // Fold in the values of the KEYABLE dynamic vars the chain reads (User-Agent,
    // Origin) so a header-gated chain (e.g. a bot-detection or CORS-preflight
    // block) is cacheable per (base key, header values) rather than uncacheable.
    // The cache key must include EVERY dynamic var the chain reads; parse-time
    // classification guarantees a cacheable ruleset reads only base-key-safe,
    // assumed-empty, or keyable vars. Fragments are '\n'-separated with a
    // per-var tag — header values can never contain a newline (HeaderValue
    // rejects CR/LF), so the encoding is injective.
    let uses = |v: CacheKeyVar| {
        inline.is_some_and(|rs| rs.cache_key_vars.contains(&v))
            || chain
                .iter()
                .any(|(_, ht)| ht.rules.cache_key_vars.contains(&v))
    };
    let mut key_vars = String::new();
    if uses(CacheKeyVar::UserAgent) {
        // Same extraction the engine's lazy header_lookup performs (get_all +
        // first decodable value), so key and evaluation always agree; the engine
        // expands an absent UA to "", so absent and empty may share a fragment.
        let ua = keyed_header(req, http::header::USER_AGENT.as_str());
        let ua = ua.as_deref().unwrap_or("");
        let classified = state.rewrite_ua_classify
            && inline.is_none_or(|rs| {
                !rs.cache_key_vars.contains(&CacheKeyVar::UserAgent) || rs.ua_classify_eligible()
            })
            && chain.iter().all(|(_, ht)| {
                !ht.rules.cache_key_vars.contains(&CacheKeyVar::UserAgent)
                    || ht.rules.ua_classify_eligible()
            });
        if classified {
            // Key on the per-ruleset UA-cond match bitmaps instead of the raw UA:
            // real-world UA diversity collapses onto a handful of entries. The
            // ruleset id in each fragment pins the bitmap to the exact rules that
            // produced it (a reparse mints a new id).
            use std::fmt::Write;
            key_vars.push_str("u!");
            let mut push_sig = |rs: &RuleSet| {
                if rs.cache_key_vars.contains(&CacheKeyVar::UserAgent) {
                    let sig = state.ua_classify.get_or_compute(rs, ua);
                    let _ = write!(key_vars, "{:x}:{:x};", rs.id(), sig);
                }
            };
            if let Some(rs) = inline {
                push_sig(rs);
            }
            for (_, ht) in chain {
                push_sig(&ht.rules);
            }
        } else {
            key_vars.push_str("u=");
            key_vars.push_str(ua);
        }
    }
    if uses(CacheKeyVar::Origin) {
        // Absent MUST key distinctly from empty ("o-" vs "o="): the engine
        // expands both to "", but keeping them distinct costs one entry and
        // stays correct if that expansion ever changes.
        match keyed_header(req, "origin") {
            None => key_vars.push_str("\no-"),
            Some(v) => {
                key_vars.push_str("\no=");
                key_vars.push_str(&v);
            }
        }
    }
    // (#313) Borrow every key part for the size guard and the hash-first probe;
    // the owned OutcomeKey is built only on the miss path that inserts.
    let host = rewrite_host(ctx, req);
    let https = ctx.is_tls;
    let method = req.method().as_str();
    let vhost = ctx.vhost_name.as_str();
    let host_s: &str = &host;
    // Every key component except the vhost is client-controlled (path, query,
    // Host, UA, Origin, method). Unbounded, a flood of distinct oversized keys
    // holds cap × tens-of-KiB resident (the Rewritten value echoes path+query
    // again) while rejecting legitimate cold keys. Oversized requests bypass
    // the cache — fail closed to a fresh eval, same as an uncacheable chain.
    let key_bytes =
        vhost.len() + method.len() + host_s.len() + path.len() + query.len() + key_vars.len();
    if key_bytes > MAX_OUTCOME_KEY_BYTES {
        state
            .metrics
            .rewrite_outcome_uncacheable
            .fetch_add(1, Ordering::Relaxed);
        return run_rewrite_inner(state, ctx, req, chain, path, query);
    }
    let hash =
        RewriteOutcomeCache::parts_hash(vhost, https, method, host_s, path, query, &key_vars);
    if let Some(hit) = state.rewrite_outcomes.probe(hash, &|k| {
        k.vhost == vhost
            && k.https == https
            && k.method == method
            && k.host == host_s
            && k.path == path
            && k.query == query
            && k.key_vars == key_vars
    }) {
        state
            .metrics
            .rewrite_outcome_hits
            .fetch_add(1, Ordering::Relaxed);
        return hit;
    }
    state
        .metrics
        .rewrite_outcome_misses
        .fetch_add(1, Ordering::Relaxed);
    let result = run_rewrite_inner(state, ctx, req, chain, path, query);
    let key = OutcomeKey {
        vhost: vhost.to_string(),
        https,
        method: method.to_string(),
        host: host_s.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        key_vars,
    };
    state
        .rewrite_outcomes
        .insert_hashed(hash, key, result.clone());
    result
}

/// Header extraction for outcome-cache keying, byte-identical to the engine's
/// lazy `header_lookup` (`run_rewrite_inner`): case-insensitive name, FIRST
/// decodable value wins, `None` when absent or undecodable. Keying MUST see
/// exactly what evaluation sees, or two requests the engine distinguishes could
/// share a key (e.g. a duplicate header whose first value is non-UTF-8).
fn keyed_header(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .next()
        .map(|s| s.to_string())
}

/// The `Host` header (port stripped), falling back to the vhost name — the value
/// the engine sees as `%{HTTP_HOST}` and a component of [`OutcomeKey`]. Uses the
/// IPv6-aware [`hj_core::host_without_port`] (a naive `split(':')` mangles a bracketed
/// `[::1]:443` to `[`); this also matches how the router resolves the vhost, so the
/// rewrite host is consistent with routing. The fallback vhost name borrows.
fn rewrite_host<'a>(ctx: &'a ReqCtx, req: &'a Request) -> Cow<'a, str> {
    req.headers()
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| Cow::Owned(hj_core::host_without_port(h)))
        .unwrap_or_else(|| Cow::Borrowed(ctx.vhost_name.as_str()))
}

/// Evaluate the inline rewrite rules then the `.htaccess` chain (uncached).
fn run_rewrite_inner(
    state: &ServerState,
    ctx: &ReqCtx,
    req: &Request,
    chain: &[(PathBuf, Arc<Htaccess>)],
    path: &str,
    query: &str,
) -> RwResult {
    // Rule sets: inline first, then the docroot→leaf htaccess chain.
    let inline = state.inline_rules.get(&ctx.vhost_name).cloned();

    // A2: no rules anywhere — skip building the (costly) RewriteInput entirely.
    if inline.is_none() && chain.is_empty() {
        return RwResult::Unchanged { env: Vec::new() };
    }

    let docroot = ctx.vhost.doc_root.clone();
    // A3 (final): the front-controller `!-f`/`!-d` tests stat the request path on
    // every request; serve them from a 1 s TTL-coalesced cache (Metadata isn't
    // storable, so cache the derived FileTests) to drop the last redundant statx.
    let stat = |p: &Path| state.stat_cache.tests(p);
    // Resolve request headers LAZILY from the live request instead of copying the
    // whole header set into `RewriteInput` up front — the engine only reads the
    // few headers a rule actually references (`%{HTTP:..}` / `%{HTTP_*}`).
    // Case-insensitive name match (HeaderMap::get_all), skip non-UTF-8 values, and on a duplicate
    // header name the FIRST decodable value wins — matching `apply_set_env` (SetEnvIf) and
    // Apache/LiteSpeed. Both stages MUST pick the same occurrence, or a deny/cache rule split
    // across SetEnvIf + RewriteCond could be evaded by sending two values of the keyed header
    // (the stages would evaluate against different values). (Was `.next_back()` = last value.)
    let header_lookup = |name: &str| -> Option<String> {
        req.headers()
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .next()
            .map(|s| s.to_string())
    };
    // (#3 / A) Populate the expanded %{} variables from ctx. Only the formatted IPs must
    // own; `method`/`host`/`uri`/`query`/`server_name`/`protocol` are borrowed into the
    // `RewriteInput` (Cow), so the uncacheable hot path builds no per-request Strings for them.
    let remote_addr = ip_to_string(ctx.client_ip);
    let server_addr = ip_to_string(ctx.local_addr.ip());
    let server_port = ctx.local_addr.port();

    // A1: build the request representation ONCE — it is identical for every
    // ruleset (first-match-wins; only `per_directory_prefix` is adjusted below).
    let mut input = RewriteInput::new(path, docroot)
        .method(req.method().as_str())
        .host(rewrite_host(ctx, req))
        .https(ctx.is_tls)
        .query(query)
        .remote_addr(remote_addr)
        .remote_port(ctx.peer_port)
        .server_addr(server_addr)
        .server_name(ctx.vhost_name.as_str())
        .server_port(server_port)
        .protocol(ctx.protocol.as_str());
    input.header_lookup = Some(HeaderLookup(&header_lookup));
    // Seed the env the rewrite engine reads (%{ENV:NAME}) from ctx (SetEnvIf +
    // anything set earlier), so .htaccess RewriteConds see SetEnvIf results. Borrow
    // ctx.env directly rather than cloning every entry into a fresh BTreeMap per
    // request (the engine only reads it; `[E=]` sets land in EvalState's overlay).
    input.env_seed = Some(&ctx.env);
    input.stat = StatSource::LiveTests(&stat);

    // (ruleset, per_directory_prefix). Inline rules have no prefix; each
    // .htaccess uses its directory path relative to docroot (no leading slash,
    // trailing slash) so Apache's per-directory prefix stripping is reproduced.
    let mut rulesets: Vec<(&hj_rewrite::RuleSet, Option<String>)> = Vec::new();
    if let Some(rs) = inline.as_deref() {
        rulesets.push((rs, None));
    }
    for (dir, ht) in chain {
        rulesets.push((&ht.rules, per_dir_prefix(&ctx.vhost.doc_root, dir)));
    }

    // (audit) %{THE_REQUEST} must resolve from the VERBATIM pre-decode target.
    // `req.uri()` still carries the raw percent-encoded bytes — attach them only
    // when some ruleset actually reads the variable (zero cost otherwise).
    if rulesets.iter().any(|(rs, _)| rs.uses_the_request) {
        let raw = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| req.uri().path().to_string());
        input.raw_request_target = Some(raw);
    }

    let mut merged_env: Vec<(String, String)> = Vec::new();
    for (rs, prefix) in rulesets {
        input.per_directory_prefix = prefix;
        let outcome = evaluate(rs, &input);
        // Merge this ruleset's env regardless of outcome shape.
        let is_end = outcome.is_end();
        match outcome {
            RewriteOutcome::Unchanged { env, .. } => {
                merged_env.extend(env);
                // [END] on a `-` rule: stop the whole chain; the URI is unchanged.
                if is_end {
                    return RwResult::Unchanged { env: merged_env };
                }
            }
            RewriteOutcome::Proxy {
                target_url,
                mut env,
                ..
            } => {
                let mut all = std::mem::take(&mut merged_env);
                all.append(&mut env);
                return RwResult::Proxy {
                    target_url,
                    env: all,
                };
            }
            RewriteOutcome::Redirect {
                code,
                location,
                mut env,
                ..
            } => {
                let mut all = std::mem::take(&mut merged_env);
                all.append(&mut env);
                return RwResult::Redirect {
                    code,
                    location,
                    env: all,
                };
            }
            RewriteOutcome::Status { code, mut env, .. } => {
                let mut all = std::mem::take(&mut merged_env);
                all.append(&mut env);
                return RwResult::Status { code, env: all };
            }
            RewriteOutcome::Forbidden { .. } => return RwResult::Forbidden,
            RewriteOutcome::Gone { .. } => return RwResult::Gone,
            RewriteOutcome::Rewritten {
                new_uri,
                new_query,
                mut env,
                ..
            } => {
                let mut all = std::mem::take(&mut merged_env);
                all.append(&mut env);
                // Pass the engine's `Option` query through unchanged: `None` (incl. `[QSD]`)
                // means "no query", which the dispatch loop turns into an empty string —
                // NOT the original query (that bug made `[QSD]` a no-op).
                return RwResult::Rewritten {
                    path: new_uri,
                    query: new_query,
                    env: all,
                };
            }
        }
    }
    RwResult::Unchanged { env: merged_env }
}

/// The path of an `.htaccess`'s directory relative to `docroot`, normalized for
/// `RewriteInput::per_directory_prefix`: no leading slash, with a trailing
/// slash (e.g. `/web/app` + `/web/app/sub` -> `Some("sub/")`). Returns `None`
/// for the docroot itself (no prefix to strip) or if `dir` is not under
/// `docroot`.
fn per_dir_prefix(docroot: &Path, dir: &Path) -> Option<String> {
    let rel = dir.strip_prefix(docroot).ok()?;
    if rel.as_os_str().is_empty() {
        return None;
    }
    let mut s = rel.to_string_lossy().replace('\\', "/");
    if !s.ends_with('/') {
        s.push('/');
    }
    Some(s)
}

/// Render an IP for `%{REMOTE_ADDR}`/`%{SERVER_ADDR}` (empty -> `""` upstream).
pub(super) fn ip_to_string(ip: std::net::IpAddr) -> String {
    ip.to_string()
}

/// (#1 security) Percent-decode a raw request-target path into the canonical
/// path every consumer must agree on. Mirrors `hj-static`'s `clean_request_path`
/// decode stage exactly: decode `%XX`, reject a malformed escape, reject an
/// embedded NUL, and require valid UTF-8. Returns the decoded path (still with
/// its leading `/`; `.`/`..` collapsing is done later by `resolved_rel_path`),
/// or `None` to signal a 400 for a request the filesystem layer would also
/// refuse. Idempotent for already-decoded paths with no `%`.
pub(super) fn decode_request_path(raw: &str) -> Option<Cow<'_, str>> {
    // Shared RFC 3986 decode (single-sourced with hj-static); post-conditions:
    // reject an embedded NUL and require valid UTF-8. The no-% case borrows (#319).
    hj_core::percent_decode_cow(raw)
}

/// Percent-encode a decoded path so a single decode by a terminal handler
/// recovers it byte-for-byte. Only `/` (the path separator) and the RFC 3986
/// unreserved set pass through literally; everything else — notably `%`, `?`,
/// `#`, and control bytes — is `%XX`-escaped. Used when re-injecting a rewritten
/// (decoded) path back into `req.uri()` (#1).
pub(super) fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        match b {
            b'/' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            other => {
                out.push('%');
                out.push(
                    char::from_digit((other >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((other & 0xf) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Whether a rewritten target still needs [`percent_encode_path`] before it can
/// ride in `req.uri()`. The engine's substitution output is ALREADY escaped
/// (`escape_subst`) — and `%<digit>` in a substitution is a backreference, so
/// re-encoding it would double-encode (`%20` -> `%2520`, a file that does not
/// exist). Only a raw `[NE]` (noescape) target carries URI-forbidden bytes.
pub(super) fn needs_encoding(path: &str) -> bool {
    let b = path.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'/'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'@' => i += 1,
            b'%' if i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit() =>
            {
                i += 3;
            }
            _ => return true,
        }
    }
    false
}

/// The directory portion of a normalized URL path: everything up to and INCLUDING the last `/`.
/// `/a/b/file` → `/a/b/`, `/index.php` → `/`, `/` → `/`. Used to detect when a rewrite routes the
/// request into a different directory (so the destination `.htaccess` chain must be reloaded).
pub(super) fn url_parent_dir(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    }
}

/// The docroot-relative path with a leading `/`, normalized to defeat traversal
/// / encoding tricks before access checks and header/error scoping. Collapses
/// `.`/`..`/empty segments; the result always starts with `/`.
pub(super) fn resolved_rel_path(path: &str) -> String {
    // Fast path (the common case — a clean absolute URL like `/dir/file.ext`): an
    // already-canonical path resolves to itself, so return it in ONE allocation, skipping
    // the `Vec<&str>` + `join` the collapse otherwise needs. This is the per-request
    // path-normalization hot spot (called several times per request across the pipeline);
    // OLS resolves once from a pool — this approximates that for the dominant clean-path case.
    if is_canonical_abs(path) {
        return path.to_string();
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    // Build the result directly (no intermediate `out.join("/")` allocation).
    let mut s = String::with_capacity(path.len() + 1);
    for seg in &out {
        s.push('/');
        s.push_str(seg);
    }
    if s.is_empty() {
        s.push('/');
    }
    s
}

/// True iff `path` is already in the canonical form [`resolved_rel_path`] produces: an absolute
/// path (leading `/`) with at least one segment and no empty (`//`), `.`, or `..` segments. For
/// such a path the collapse is the identity, enabling the zero-`Vec` fast path. Root `/` and any
/// trailing-slash path are NOT canonical (the collapse drops them), so they take the slow path.
fn is_canonical_abs(path: &str) -> bool {
    let mut it = path.split('/');
    if it.next() != Some("") {
        return false; // must start with '/'
    }
    let mut any = false;
    for seg in it {
        any = true;
        if seg.is_empty() || seg == "." || seg == ".." {
            return false;
        }
    }
    any
}

/// Like [`resolved_rel_path`] (same `.`/`..`/empty-segment collapse for the M1
/// traversal-defeat property) but PRESERVES a single trailing `/`. This is the
/// canonical request path fed to the rewrite engine and the suffix/dir-index
/// router, both of which are slash-sensitive: `resolve_script`'s directory-index
/// fallback gates on `path.ends_with('/')`, and front-controller rewrites
/// (`RewriteCond %{REQUEST_FILENAME} !-d`) intentionally leave a real directory's
/// trailing slash in place. Dropping it (as `resolved_rel_path` does) routes
/// `/dir/` -> `/dir`, loses the PHP dir-index, and leaks the index source via the
/// static handler. The leading slash is always present; the result equals
/// `resolved_rel_path` for any path that does not end in `/`, and root `/` is
/// preserved.
pub(super) fn normalized_request_path(path: &str) -> String {
    let mut norm = resolved_rel_path(path);
    // Re-attach the trailing slash the collapse dropped, but never produce `//`
    // (root, or a path that already normalized to `/`, stays `/`).
    if path.ends_with('/') && !norm.ends_with('/') {
        norm.push('/');
    }
    norm
}

pub(super) fn build_uri(path: &str, query: &str) -> Option<Uri> {
    let s = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    Uri::try_from(s).ok()
}

pub(super) fn clean_rel(path: &str) -> Option<PathBuf> {
    // Fast path: a canonical absolute path with no NUL maps directly to the relative
    // `PathBuf` (just strip the leading `/`) in one allocation, skipping the per-segment
    // `PathBuf::push` (and its incremental reallocations).
    if is_canonical_abs(path) && !path.contains('\0') {
        return Some(PathBuf::from(&path[1..]));
    }
    let mut out = PathBuf::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains('\0') {
            return None;
        }
        out.push(seg);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn okey(path: &str) -> OutcomeKey {
        OutcomeKey {
            vhost: "v".into(),
            https: true,
            method: "GET".into(),
            host: "h".into(),
            path: path.into(),
            query: String::new(),
            key_vars: String::new(),
        }
    }

    // Regression: a bracketed IPv6 Host must not be mangled into the rewrite host /
    // OutcomeKey. The old `h.split(':').next()` turned `[::1]:443` into `[`, poisoning
    // the rewrite-outcome cache key and %{HTTP_HOST}. rewrite_host now delegates to the
    // IPv6-aware hj_core::host_without_port (same normalization the router uses).
    #[test]
    fn rewrite_host_handles_ipv6_and_ports() {
        use hj_core::Proto;
        use hj_core::config::{MimeMap, ServerConfig, VHostConfig};
        use std::collections::BTreeMap;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let server = ServerConfig {
            server_root: std::path::PathBuf::from("/tmp"),
            server_name: "test".into(),
            user: "nobody".into(),
            group: "nobody".into(),
            index_files: vec!["index.html".into()],
            tuning: Default::default(),
            quic_enable: false,
            use_ip_in_proxy_header: 0,
            expires: Default::default(),
            cache: Default::default(),
            security: Default::default(),
            suexec: Default::default(),
            ext_processors: vec![],
            php_config: None,
            listeners: vec![],
            vhosts: BTreeMap::new(),
            vhost_order: vec![],
            mime: MimeMap::default(),
        };
        let ctx = ReqCtx {
            server: Arc::new(server),
            vhost_name: "fallback.example".into(),
            vhost: Arc::new(VHostConfig::default()),
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            is_tls: true,
            protocol: Proto::Http1,
            trusted_proxy: false,
            env: Vec::new(),
            local_addr: SocketAddr::from(([127, 0, 0, 1], 443)),
            peer_port: 12345,
            tls: None,
            redirect_guard: None,
            request_time: std::time::SystemTime::now(),
            request_id: Default::default(),
        };
        let mk = |host: Option<&str>| {
            let mut b = http::Request::builder().method("GET").uri("/");
            if let Some(h) = host {
                b = b.header(http::header::HOST, h);
            }
            b.body(hj_core::empty_incoming()).unwrap()
        };
        // Bracketed IPv6 (+ optional port) must keep the address, not collapse to "[".
        assert_eq!(
            rewrite_host(&ctx, &mk(Some("[2606:4700::1111]:443"))),
            "2606:4700::1111"
        );
        assert_eq!(rewrite_host(&ctx, &mk(Some("[::1]"))), "::1");
        // Ordinary host:port still strips the port (and normalizes case, like the router).
        assert_eq!(
            rewrite_host(&ctx, &mk(Some("Example.COM:8080"))),
            "example.com"
        );
        // No Host header → fall back to the vhost name.
        assert_eq!(rewrite_host(&ctx, &mk(None)), "fallback.example");
    }

    #[test]
    fn outcome_cache_hit_miss_and_disable() {
        let c = Arc::new(RewriteOutcomeCache::new(DEFAULT_REWRITE_OUTCOME_TTL));
        assert!(c.get(&okey("/a")).is_none(), "cold miss");
        c.insert(
            okey("/a"),
            RwResult::Unchanged {
                env: vec![("X".into(), "1".into())],
            },
        );
        match c.get(&okey("/a")) {
            Some(RwResult::Unchanged { env }) => assert_eq!(env, vec![("X".into(), "1".into())]),
            _ => panic!("expected cached Unchanged"),
        }
        // Distinct key (different path) is a miss — keys are exact.
        assert!(c.get(&okey("/b")).is_none());

        // ttl=0 disables caching entirely (insert is a no-op, get always misses).
        let off = Arc::new(RewriteOutcomeCache::new(Duration::ZERO));
        off.insert(okey("/a"), RwResult::Forbidden);
        assert!(off.get(&okey("/a")).is_none());
    }

    #[test]
    fn outcome_cache_key_vars_distinguish_entries() {
        // Stage 4: the same path with a different keyable-var fragment (e.g. UA:
        // bot vs browser) must be DISTINCT cache entries — a bot's outcome must not
        // be served to a browser. okey_ua builds the key with a key_vars fragment.
        let okey_ua = |path: &str, ua: &str| OutcomeKey {
            key_vars: ua.into(),
            ..okey(path)
        };
        let c = Arc::new(RewriteOutcomeCache::new(DEFAULT_REWRITE_OUTCOME_TTL));
        c.insert(okey_ua("/p", "Googlebot"), RwResult::Forbidden);
        // Same path, different UA fragment -> MISS (no cross-UA bleed).
        assert!(
            c.get(&okey_ua("/p", "Mozilla")).is_none(),
            "browser must not hit the bot entry"
        );
        // Same path + same UA fragment -> HIT.
        assert!(matches!(
            c.get(&okey_ua("/p", "Googlebot")),
            Some(RwResult::Forbidden)
        ));
    }

    #[test]
    fn outcome_cache_respects_ttl_expiry() {
        let c = Arc::new(RewriteOutcomeCache::new(Duration::from_millis(20)));
        c.insert(okey("/a"), RwResult::Gone);
        assert!(c.get(&okey("/a")).is_some(), "fresh hit");
        std::thread::sleep(Duration::from_millis(35));
        assert!(c.get(&okey("/a")).is_none(), "expired after TTL");
    }

    #[test]
    fn outcome_cache_prunes_expired_entries_at_cap() {
        let c = Arc::new(RewriteOutcomeCache::with_cap(Duration::from_millis(20), 2));
        c.insert(okey("/a"), RwResult::Gone);
        c.insert(okey("/b"), RwResult::Forbidden);
        std::thread::sleep(Duration::from_millis(35));
        c.insert(okey("/c"), RwResult::Gone);
        assert!(matches!(c.get(&okey("/c")), Some(RwResult::Gone)));
        // The prune now runs on a detached thread; wait briefly for it to land.
        for _ in 0..200 {
            if c.get(&okey("/a")).is_none() && c.get(&okey("/b")).is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(c.get(&okey("/a")).is_none());
        assert!(c.get(&okey("/b")).is_none());
    }

    #[test]
    fn per_dir_prefix_relative_to_docroot() {
        let docroot = Path::new("/web/app");
        // docroot itself -> no prefix.
        assert_eq!(per_dir_prefix(docroot, Path::new("/web/app")), None);
        // A nested directory -> "sub/" (no leading slash, trailing slash).
        assert_eq!(
            per_dir_prefix(docroot, Path::new("/web/app/sub")),
            Some("sub/".to_string())
        );
        assert_eq!(
            per_dir_prefix(docroot, Path::new("/web/app/a/b")),
            Some("a/b/".to_string())
        );
        // Outside docroot -> None (defensive).
        assert_eq!(per_dir_prefix(docroot, Path::new("/other")), None);
    }

    #[test]
    fn normalized_request_path_preserves_trailing_slash() {
        // Collapses traversal/encoding artifacts exactly like `resolved_rel_path`...
        assert_eq!(normalized_request_path("/secret/../public"), "/public");
        assert_eq!(normalized_request_path("/a//./b"), "/a/b");
        assert_eq!(normalized_request_path("/../../etc/passwd"), "/etc/passwd");
        // ...but KEEPS the trailing slash that directory routing depends on.
        assert_eq!(normalized_request_path("/community/"), "/community/");
        assert_eq!(normalized_request_path("/a/b/"), "/a/b/");
        // A `..` that collapses back down to a directory still ends in `/`.
        assert_eq!(normalized_request_path("/a/b/../"), "/a/");
        // Root stays a single slash (never `//`), and a non-slash path is unchanged.
        assert_eq!(normalized_request_path("/"), "/");
        assert_eq!(normalized_request_path("/index.php"), "/index.php");
    }

    #[test]
    fn resolved_rel_path_normalizes_traversal_and_encoding_artifacts() {
        // Plain path is unchanged (leading slash kept).
        assert_eq!(resolved_rel_path("/config/db.php"), "/config/db.php");
        // Empty / `.` segments collapse.
        assert_eq!(resolved_rel_path("/a//./b"), "/a/b");
        // `..` pops the previous segment so a denied file cannot be reached via
        // traversal (#5 security: /secret/../public stays inside).
        assert_eq!(resolved_rel_path("/secret/../public"), "/public");
        assert_eq!(resolved_rel_path("/a/b/../../c"), "/c");
        // Leading `..` cannot climb above root.
        assert_eq!(resolved_rel_path("/../../etc/passwd"), "/etc/passwd");
        // Root and trailing slash.
        assert_eq!(resolved_rel_path("/"), "/");
        assert_eq!(resolved_rel_path("/dir/"), "/dir");
        // Canonical fast path: a clean absolute path is returned identically (no collapse).
        assert_eq!(resolved_rel_path("/__hjbench/1k.bin"), "/__hjbench/1k.bin");
        assert_eq!(resolved_rel_path("/a/b/c/d.ext"), "/a/b/c/d.ext");
        // is_canonical_abs must NOT shortcut these (would otherwise return un-normalized):
        assert_eq!(resolved_rel_path("/a/./b"), "/a/b"); // dot segment
        assert_eq!(resolved_rel_path("//a"), "/a"); // empty leading segment
        assert_eq!(resolved_rel_path("a/b"), "/a/b"); // no leading slash
    }

    #[test]
    fn url_parent_dir_returns_directory_component() {
        assert_eq!(url_parent_dir("/a/b/file"), "/a/b/");
        assert_eq!(url_parent_dir("/index.php"), "/");
        assert_eq!(url_parent_dir("/"), "/");
        assert_eq!(url_parent_dir("/dir/"), "/dir/");
        assert_eq!(url_parent_dir("/whats-new/"), "/whats-new/");
        assert_eq!(url_parent_dir("/threads/x.1/"), "/threads/x.1/");
    }

    #[test]
    fn cross_dir_rewrite_reload_only_when_dest_dir_is_not_an_ancestor() {
        // (#8) The pipeline reloads the .htaccess chain iff dir(orig) does NOT start with dir(cur)
        // — i.e. the destination directory's .htaccess wasn't already covered by the original chain
        // (which holds every ANCESTOR of orig_path). This keeps the hot front-controller rewrite
        // free while a sideways/deeper rewrite into a protected dir reloads.
        let needs_reload =
            |orig: &str, cur: &str| !url_parent_dir(orig).starts_with(url_parent_dir(cur));
        // Front-controller: /whats-new/ -> /index.php. dir(cur)="/" IS an ancestor → NO reload.
        assert!(!needs_reload("/whats-new/", "/index.php"));
        assert!(!needs_reload("/threads/x.1/", "/index.php"));
        // Same directory → no reload.
        assert!(!needs_reload("/a/x", "/a/y"));
        // Rewrite DEEPER into a subdir not in the original chain → reload.
        assert!(needs_reload("/x", "/protected/secret"));
        // Sideways into a different subdir → reload.
        assert!(needs_reload("/a/x", "/b/y"));
        // The trailing slash prevents a non-segment prefix from looking like an ancestor:
        // dir(orig)="/sub/" does NOT start with dir(cur)="/su/" → reload.
        assert!(needs_reload("/sub/y", "/su/x"));
    }

    #[test]
    fn decode_request_path_matches_filesystem_view() {
        // (#1) The access-check path must equal what the static handler decodes.
        // Encoded letters/dots/slashes decode so a denied file cannot hide behind
        // an encoding.
        assert_eq!(
            decode_request_path("/sec%72et.txt").as_deref(),
            Some("/secret.txt")
        );
        assert_eq!(
            decode_request_path("/index%2Ephp").as_deref(),
            Some("/index.php")
        );
        assert_eq!(
            decode_request_path("/%2Egit/config").as_deref(),
            Some("/.git/config")
        );
        // Encoded slash decodes; `resolved_rel_path` then collapses the `..` the
        // handler would also produce (defeating `/foo%2F..%2Fsecret`).
        assert_eq!(
            decode_request_path("/foo%2F..%2Fsecret").as_deref(),
            Some("/foo/../secret")
        );
        assert_eq!(resolved_rel_path("/foo/../secret"), "/secret");
        // Already-decoded path with no `%` is unchanged (idempotent).
        assert_eq!(
            decode_request_path("/a/b/c.php").as_deref(),
            Some("/a/b/c.php")
        );
        // Malformed escape, embedded NUL, and invalid UTF-8 are rejected (-> 400).
        assert_eq!(decode_request_path("/bad%2"), None);
        assert_eq!(decode_request_path("/bad%zz"), None);
        assert_eq!(decode_request_path("/a%00b"), None);
        assert_eq!(decode_request_path("/a%FF%FEb"), None); // not valid UTF-8
    }

    #[test]
    fn percent_encode_path_roundtrips_through_decode() {
        // A decoded path containing a literal `%`/`?`/`#`/space re-encodes so a
        // single handler decode recovers it exactly (no double-decode, #1).
        for p in [
            "/a/b.php",
            "/has space.txt",
            "/lit%25eral",
            "/q?x#frag",
            "/.git/cfg",
        ] {
            let enc = percent_encode_path(p);
            assert_eq!(
                decode_request_path(&enc).as_deref(),
                Some(p),
                "roundtrip {p}"
            );
        }
        // The path separator stays literal (not escaped) so routing still works.
        assert_eq!(percent_encode_path("/a/b/c"), "/a/b/c");
    }

    fn ua_ruleset() -> Htaccess {
        Htaccess::parse("RewriteCond %{HTTP_USER_AGENT} badbot [NC]\nRewriteRule ^ - [F]").unwrap()
    }

    #[test]
    fn oversized_ua_is_computed_but_never_memoized() {
        let ht = ua_ruleset();
        let cache = UaClassifyCache::new();
        let junk = "x".repeat(MAX_MEMO_UA_BYTES + 1);
        let sig = cache.get_or_compute(&ht.rules, &junk);
        assert_eq!(sig, ht.rules.ua_cond_signature(&junk));
        assert_eq!(cache.len(), 0, "junk UA must not occupy the memo");
        // A plausible UA still memoizes, and matching stays correct.
        assert_eq!(
            cache.get_or_compute(&ht.rules, "Mozilla/5.0 badbot"),
            ht.rules.ua_cond_signature("Mozilla/5.0 badbot")
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn full_ua_memo_flushes_after_the_flush_interval() {
        let ht = ua_ruleset();
        let mut cache = UaClassifyCache::new();
        cache.cap = 2;
        cache.get_or_compute(&ht.rules, "ua-one");
        cache.get_or_compute(&ht.rules, "ua-two");
        assert_eq!(cache.len(), 2);
        // At cap, inside the flush interval: a new UA computes but is rejected.
        cache.get_or_compute(&ht.rules, "ua-three");
        assert_eq!(cache.len(), 2, "cap holds inside the flush interval");
        // Age the last flush past the interval: the next at-cap insert flushes
        // wholesale and memoizes the new UA (self-heal from a junk-UA flood).
        let Some(past) = Instant::now().checked_sub(Duration::from_secs(2 * 3600)) else {
            return; // clock too young to backdate (fresh-boot CI); covered above
        };
        *cache
            .last_flush
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = past;
        cache.get_or_compute(&ht.rules, "ua-three");
        assert_eq!(
            cache.len(),
            1,
            "flush drops the old entries, admits the new"
        );
    }
}
