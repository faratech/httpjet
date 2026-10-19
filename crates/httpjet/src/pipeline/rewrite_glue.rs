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
    evaluate_with_engine,
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
    Failed {
        reason: &'static str,
    },
    Proxy {
        target_url: String,
        proxy_host: Option<String>,
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
    /// An internal rewrite produced a path with a malformed escape, an embedded NUL or
    /// invalid UTF-8 once decoded; refused like an undecodable request target.
    InvalidTarget,
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

impl RwResult {
    /// Move the outcome's `[E=]` env out, leaving it empty.
    pub(super) fn take_env(&mut self) -> Vec<(String, String)> {
        match self {
            RwResult::Proxy { env, .. }
            | RwResult::Redirect { env, .. }
            | RwResult::Status { env, .. }
            | RwResult::Rewritten { env, .. }
            | RwResult::Unchanged { env } => std::mem::take(env),
            RwResult::Failed { .. }
            | RwResult::Forbidden
            | RwResult::Gone
            | RwResult::InvalidTarget => Vec::new(),
        }
    }
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
    /// The listener port: a path-only `[R]` Location carries a non-default
    /// SERVER_PORT, so two ports must not share an outcome (#692).
    port: u16,
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
    pub(crate) fn empty_generation(&self) -> Self {
        Self::new(self.ttl)
    }

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

    /// Fresh cached outcome for `key`, or `None` if absent/expired/disabled.
    /// Production probes via `parts_hash` + `probe` (#313); the owned-key pair
    /// (`get`/`insert`) survives for the in-file tests.
    #[cfg(test)]
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
    #[cfg(test)]
    fn key_hash(key: &OutcomeKey) -> u64 {
        Self::parts_hash(
            &key.vhost,
            key.https,
            key.port,
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
        port: u16,
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
        h.write(&port.to_le_bytes());
        h.finish()
    }

    /// Store `outcome` for `key` (refreshing an existing entry; otherwise only
    /// when below the cap, so memory is bounded without an eviction sweep).
    #[cfg(test)]
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
                if self.claim_sync_prune(now, window) {
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

    /// Claim the rare synchronous prune slot. The due check and CAS stay in the
    /// same boolean group so the initial `last == 0` sentinel cannot bypass the
    /// CAS and let every at-cap request run an O(N) sweep. Store at least 1:
    /// process uptime may still be millisecond zero on the first claim, and
    /// writing zero would leave the sentinel armed.
    fn claim_sync_prune(&self, now: u64, window: u64) -> bool {
        let last = self.last_sync_prune.load(Ordering::Relaxed);
        (last == 0 || now.saturating_sub(last) >= window)
            && self
                .last_sync_prune
                .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
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
/// Borrowed form of a [`UaClassifyCache`] key. Hashes exactly like the owned
/// `(u64, String)` tuple (field order, `str` hashing), so a lookup needs no allocation.
#[derive(Hash)]
struct UaKeyRef<'a>(u64, &'a str);

impl dashmap::Equivalent<(u64, String)> for UaKeyRef<'_> {
    fn equivalent(&self, key: &(u64, String)) -> bool {
        self.0 == key.0 && self.1 == key.1
    }
}

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
    /// A hit allocates nothing: the probe borrows the UA.
    pub(crate) fn get_or_compute(&self, rs: &RuleSet, ua: &str) -> u64 {
        if ua.len() > MAX_MEMO_UA_BYTES {
            return rs.ua_cond_signature(ua);
        }
        if let Some(sig) = self.map.get(&UaKeyRef(rs.id(), ua)) {
            return *sig;
        }
        let sig = rs.ua_cond_signature(ua);
        if self.count.load(Ordering::Relaxed) >= self.cap {
            self.maybe_flush_full();
        }
        if self.count.load(Ordering::Relaxed) < self.cap
            && self.map.insert((rs.id(), ua.to_string()), sig).is_none()
        {
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

    /// Wholesale invalidation when reclaiming a full memo.
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
#[cfg(test)]
pub(super) fn run_rewrite(
    state: &ServerState,
    ctx: &ReqCtx,
    req: &Request,
    chain: &[(PathBuf, Arc<Htaccess>)],
    path: &str,
    query: &str,
) -> RwResult {
    run_rewrite_traced(
        state,
        ctx,
        req,
        chain,
        path,
        query,
        &mut RewriteTrace::default(),
    )
}

/// One internal redirect of a rewrite: the URI a rewrite moved the request to and
/// the `.htaccess` chain (differing from the one evaluated before it) whose rules
/// then ran for that URI. Apache/OLS run the access phase of every such hop before
/// its rewrite outcome is honoured, so the caller must enforce `chain`'s access and
/// auth for `path` and render a terminal outcome produced there with `chain`.
#[derive(Debug, Clone)]
pub(super) struct RewriteHop {
    pub(super) path: String,
    pub(super) chain: Vec<(PathBuf, Arc<Htaccess>)>,
}

/// What a rewrite evaluated beyond the caller's chain (see [`run_rewrite_inner`]).
#[derive(Debug, Default)]
pub(super) struct RewriteTrace {
    /// Every `.htaccess` outside the caller's chain whose rules ran. Callers keying a
    /// cache on `chain`'s reads must add these, or decline when it is non-empty.
    pub(super) extra: Vec<(PathBuf, Arc<Htaccess>)>,
    /// Every hop into a different chain, in order. The last hop's chain produced the
    /// outcome; with no hop, the caller's chain did.
    pub(super) hops: Vec<RewriteHop>,
}

impl RewriteTrace {
    /// Whether the outcome depends on more than `chain` (the caller's chain) and the
    /// final-target checks every rewrite gets: a chain outside `chain` ran, or some
    /// hop's access phase is not implied by those checks. A hop is implied when it
    /// entered the final rewritten path itself with a subset of `chain` holding no
    /// auth realm: dispatch then checks that path against `chain` (or the identical
    /// reloaded chain), and a deny anywhere in a chain denies (the front controller
    /// `/sub/x` -> `/index.php` keeps its on-core path and outcome cache). An
    /// enclosing realm may be lifted by a deeper chain, so auth always counts.
    pub(super) fn needs_dispatch(
        &self,
        chain: &[(PathBuf, Arc<Htaccess>)],
        outcome: &RwResult,
    ) -> bool {
        if !self.extra.is_empty() {
            return true;
        }
        if self.hops.is_empty() {
            return false;
        }
        let RwResult::Rewritten { path, .. } = outcome else {
            return true;
        };
        self.hops.iter().any(|hop| {
            hop.path != *path
                || hop.chain.iter().any(|(dir, ht)| {
                    ht.has_auth() || !chain.iter().any(|(d, h)| d == dir && Arc::ptr_eq(h, ht))
                })
        })
    }
}

/// [`run_rewrite`] that also reports, in `trace`, the chains a rewrite moved the
/// request into (see [`RewriteTrace`]).
pub(super) fn run_rewrite_traced(
    state: &ServerState,
    ctx: &ReqCtx,
    req: &Request,
    chain: &[(PathBuf, Arc<Htaccess>)],
    path: &str,
    query: &str,
    trace: &mut RewriteTrace,
) -> RwResult {
    let raw_request_target = req
        .uri()
        .path_and_query()
        .map(|target| target.as_str())
        .unwrap_or_else(|| req.uri().path());
    run_rewrite_with_headers(
        state,
        ctx,
        req.method().as_str(),
        req.headers(),
        raw_request_target,
        chain,
        path,
        query,
        trace,
    )
}

/// Header-borrowing rewrite entry point for internal requests. ErrorDocument
/// policy has a synthetic method/URI but must inspect the outer request headers;
/// accepting those pieces directly avoids cloning the entire HeaderMap merely
/// to feed the engine's already-lazy header lookup.
pub(super) fn run_rewrite_with_headers(
    state: &ServerState,
    ctx: &ReqCtx,
    method: &str,
    headers: &http::HeaderMap,
    raw_request_target: &str,
    chain: &[(PathBuf, Arc<Htaccess>)],
    path: &str,
    query: &str,
    trace: &mut RewriteTrace,
) -> RwResult {
    #[cfg(feature = "otel")]
    let _trace_stage = crate::otel::stage(crate::otel::StageKind::Rewrite);
    if !state.rewrite_outcomes.enabled() {
        // `--rewrite-outcome-ttl-ms 0`: the cache is off entirely — no key build,
        // no counters (disabled is not "uncacheable").
        return run_rewrite_inner(
            state,
            ctx,
            method,
            headers,
            raw_request_target,
            chain,
            path,
            query,
            trace,
        );
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
        return run_rewrite_inner(
            state,
            ctx,
            method,
            headers,
            raw_request_target,
            chain,
            path,
            query,
            trace,
        );
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
        let ua = keyed_header(headers, http::header::USER_AGENT.as_str());
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
        match keyed_header(headers, "origin") {
            None => key_vars.push_str("\no-"),
            Some(v) => {
                key_vars.push_str("\no=");
                key_vars.push_str(&v);
            }
        }
    }
    if uses(CacheKeyVar::Accept) {
        // Same absent-vs-empty discipline as Origin.
        match keyed_header(headers, "accept") {
            None => key_vars.push_str("\na-"),
            Some(v) => {
                key_vars.push_str("\na=");
                key_vars.push_str(&v);
            }
        }
    }
    // The self-redirect guard reads the Host header's port (#703).
    if let Some(p) = host_header_port(headers) {
        key_vars.push_str("\nhp=");
        key_vars.push_str(&p.to_string());
    }
    // (#313) Borrow every key part for the size guard and the hash-first probe;
    // the owned OutcomeKey is built only on the miss path that inserts.
    let host = rewrite_host(ctx, headers);
    let https = ctx.is_tls;
    let port = ctx.local_addr.port();
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
        return run_rewrite_inner(
            state,
            ctx,
            method,
            headers,
            raw_request_target,
            chain,
            path,
            query,
            trace,
        );
    }
    let hash =
        RewriteOutcomeCache::parts_hash(vhost, https, port, method, host_s, path, query, &key_vars);
    if let Some(hit) = state.rewrite_outcomes.probe(hash, &|k| {
        k.vhost == vhost
            && k.https == https
            && k.port == port
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
    let result = run_rewrite_inner(
        state,
        ctx,
        method,
        headers,
        raw_request_target,
        chain,
        path,
        query,
        trace,
    );
    // A rewrite that ran rules outside `chain` depends on inputs the key (built from
    // `chain`'s reads) does not cover, and a hop whose access the caller must enforce
    // has to reach it (a hit carries no hops).
    if trace.needs_dispatch(chain, &result) {
        return result;
    }
    let key = OutcomeKey {
        vhost: vhost.to_string(),
        https,
        port,
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

/// The page-cache key fragment for a request whose rewrite conditions read the
/// User-Agent (#603): `fingerprint:bitmap;` for every UA-reading ruleset (the vhost's
/// inline rules, then `chain`, which must be the chain whose conds actually ran) where
/// some UA condition matched. The fingerprint is restart-stable because the page cache
/// persists. `None` when nothing reads the UA, when no condition matched (ordinary
/// browsers keep the historic key), or when a UA read is not classifiable — keying on
/// the raw UA would shatter the public cache, so `httpjet check` warns about those.
pub(crate) fn page_cache_ua_class(
    state: &ServerState,
    ctx: &ReqCtx,
    chain: &[(PathBuf, Arc<Htaccess>)],
    headers: &http::HeaderMap,
) -> Option<String> {
    let inline = state
        .inline_rules
        .get(&ctx.vhost_name)
        .map(|rs| &**rs)
        .filter(|rs| rs.reads_user_agent());
    let mut readers = inline
        .into_iter()
        .chain(chain.iter().map(|(_, ht)| &ht.rules))
        .filter(|rs| rs.reads_user_agent())
        .peekable();
    readers.peek()?;
    if !state.rewrite_ua_classify {
        return None;
    }
    let ua = headers
        .get_all(http::header::USER_AGENT)
        .iter()
        .next()
        .map(hj_core::header_value_lossy);
    let ua = ua.as_deref().unwrap_or("");
    let mut class = String::new();
    for rs in readers {
        if !rs.ua_classify_eligible() {
            return None;
        }
        let sig = state.ua_classify.get_or_compute(rs, ua);
        if sig != 0 {
            use std::fmt::Write;
            let _ = write!(class, "{:x}:{:x};", rs.ua_fingerprint(), sig);
        }
    }
    (!class.is_empty()).then_some(class)
}

/// (#857) Whether the vhost's inline rules or any of `chains` read a request
/// input the page cache neither keys nor varies on (client/server address or
/// port, protocol, time, env). A response built under such a chain may depend
/// on that input, so the request must neither read nor populate the cache.
/// The classification is parse-time ([`hj_rewrite::Htaccess::page_cache_keyed`]).
pub(crate) fn page_cache_unkeyed<'a>(
    state: &ServerState,
    ctx: &ReqCtx,
    chains: impl IntoIterator<Item = &'a Htaccess>,
) -> bool {
    state
        .inline_rules
        .get(&ctx.vhost_name)
        .is_some_and(|rs| !rs.page_cache_keyed())
        || chains.into_iter().any(|ht| !ht.page_cache_keyed())
}

#[cfg(test)]
thread_local! {
    /// `page_cache_header_vary` calls made on this thread.
    pub(crate) static HEADER_VARY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// (#617/#618) Page-cache key fragment for every OTHER request header the
/// applied rules read — SetEnvIf attributes (`memo.vary_headers`) and
/// `RewriteCond %{HTTP:...}` vars (`cache_key_vars`) from the chain whose
/// conds actually ran PLUS the vhost's inline rules (the same sources as
/// [`page_cache_ua_class`], not just the destination chain). Each present
/// header contributes `name:<fnv64>;` in sorted order; absent headers keep
/// the historic key. `user-agent` is excluded only when a rewrite cond set
/// is fully UA-classifiable and no SetEnvIf reads it; otherwise its raw value
/// is folded. `origin` is included so inline and pre-rewrite Origin reads key
/// per-Origin even when the destination chain does not read it.
/// Cookie reads confined to SetEnvIf discriminate on the evaluated assignments,
/// including capture expansions. Raw Cookie remains required for rewrite reads.
pub(crate) fn page_cache_header_vary(
    state: &ServerState,
    ctx: &ReqCtx,
    chain: &[(PathBuf, Arc<Htaccess>)],
    headers: &http::HeaderMap,
) -> Option<String> {
    use std::collections::BTreeSet;
    #[cfg(test)]
    HEADER_VARY_CALLS.with(|n| n.set(n.get() + 1));
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut rulesets: Vec<&hj_rewrite::RuleSet> = Vec::new();
    if let Some(rs) = state.inline_rules.get(&ctx.vhost_name) {
        rulesets.push(rs);
    }
    let mut setenv_reads_user_agent = false;
    let mut rewrite_reads_cookie = false;
    for (_, ht) in chain {
        for name in &ht.memo.vary_headers {
            if name == "user-agent" {
                setenv_reads_user_agent = true;
            }
            names.insert(name.as_str());
        }
        rulesets.push(&ht.rules);
    }
    for rs in &rulesets {
        for name in &rs.header_reads {
            names.insert(name.as_str());
            rewrite_reads_cookie |= name == "cookie";
        }
        for v in &rs.cache_key_vars {
            match v {
                hj_rewrite::CacheKeyVar::Origin => {
                    names.insert("origin");
                }
                hj_rewrite::CacheKeyVar::Accept => {
                    names.insert("accept");
                }
                hj_rewrite::CacheKeyVar::UserAgent => {}
            }
        }
    }
    let rewrite_ua_unclassified = rulesets.iter().any(|rs| {
        rs.reads_user_agent() && !(state.rewrite_ua_classify && rs.ua_classify_eligible())
    });
    if !setenv_reads_user_agent && !rewrite_ua_unclassified {
        names.remove("user-agent");
    }
    let mut out = String::new();
    if names.contains("cookie") && !rewrite_reads_cookie {
        let cookie = keyed_header(headers, "cookie");
        let mut assignments = String::new();
        let evaluated: Result<(), &'static str> = chain.iter().try_for_each(|(_, ht)| {
            for (name, value) in ht.cookie_env(cookie.as_deref())?.iter() {
                use std::fmt::Write;
                // Length prefixes preserve assignment boundaries and order,
                // including values expanded from regex capture groups.
                let _ = write!(assignments, "{}:{name}{}:{value}", name.len(), value.len());
            }
            Ok(())
        });
        if evaluated.is_ok() {
            names.remove("cookie");
            if !assignments.is_empty() {
                // '@' cannot occur in a request-header name, keeping this
                // derived dimension separate from arbitrary HTTP:* reads.
                append_header_vary(&mut out, "@cookie-env", &assignments);
            }
        }
        // Regex errors retain the full raw Cookie discrimination. Normal
        // SetEnvIf evaluation refuses those requests before cache lookup.
    }
    for name in names {
        let Some(value) = keyed_header(headers, name) else {
            continue;
        };
        append_header_vary(&mut out, name, &value);
    }
    (!out.is_empty()).then_some(out)
}

fn append_header_vary(out: &mut String, name: &str, value: &str) {
    use std::fmt::Write;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in value.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let _ = write!(out, "{name}:{hash:016x};");
}

/// Header extraction for outcome-cache keying, byte-identical to the engine's
/// lazy `header_lookup` (`run_rewrite_inner`): case-insensitive name, FIRST
/// value wins (decoded lossily when non-ASCII, #360), `None` when absent. Keying
/// MUST see exactly what evaluation sees, or two requests the engine
/// distinguishes could share a key (e.g. a duplicate header whose first value is
/// non-ASCII).
fn keyed_header(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(name)
        .iter()
        .next()
        .map(|v| hj_core::header_value_lossy(v).into_owned())
}

/// The `Host` header (port stripped), falling back to the vhost name — the value
/// the engine sees as `%{HTTP_HOST}` and a component of [`OutcomeKey`]. Uses the
/// IPv6-aware [`hj_core::host_without_port`] (a naive `split(':')` mangles a bracketed
/// `[::1]:443` to `[`); this also matches how the router resolves the vhost, so the
/// rewrite host is consistent with routing. The fallback vhost name borrows.
/// The explicit port in the Host header (`host:8080`, `[::1]:8443`), if any.
fn host_header_port(headers: &http::HeaderMap) -> Option<u16> {
    let h = headers.get(http::header::HOST)?.to_str().ok()?.trim();
    let port = match h.strip_prefix('[') {
        Some(v6) => v6.split_once(']')?.1.strip_prefix(':')?,
        None => h.rsplit_once(':')?.1,
    };
    port.parse().ok()
}

fn rewrite_host<'a>(ctx: &'a ReqCtx, headers: &'a http::HeaderMap) -> Cow<'a, str> {
    headers
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| Cow::Owned(hj_core::host_without_port(h)))
        .unwrap_or_else(|| Cow::Borrowed(ctx.vhost_name.as_str()))
}

/// Apache's `LimitInternalRecursion` default: a request may be internally
/// redirected this many times before it fails with a 500.
pub(super) const MAX_INTERNAL_REDIRECTS: usize = 10;

/// `RwResult::Failed` reason for a rewrite loop that exceeded
/// [`MAX_INTERNAL_REDIRECTS`].
pub(super) const INTERNAL_REDIRECT_LIMIT: &str = "internal redirect limit exceeded";

/// The `.htaccess` chain for `path` after a rewrite moved the request out of
/// `cur_path` (whose chain is `cur_chain`). `None` means the destination chain
/// holds exactly the directories already evaluated, so OLS stays in the same
/// context and no rule re-runs. An ancestor-or-equal destination is a prefix of
/// `cur_chain` (the walk visits the same directories), so the hot front
/// controller (`/whats-new/` -> `/index.php`) needs no filesystem lookup.
fn destination_chain(
    state: &ServerState,
    ctx: &ReqCtx,
    cur_chain: &[(PathBuf, Arc<Htaccess>)],
    cur_path: &str,
    path: &str,
) -> Option<Vec<(PathBuf, Arc<Htaccess>)>> {
    let dest_dir = url_parent_dir(path);
    if url_parent_dir(cur_path).starts_with(dest_dir) {
        let target = ctx.vhost.doc_root.join(dest_dir.trim_start_matches('/'));
        let kept = cur_chain
            .iter()
            .filter(|(dir, _)| target.starts_with(dir))
            .count();
        if kept == cur_chain.len() {
            return None;
        }
        return Some(
            cur_chain
                .iter()
                .filter(|(dir, _)| target.starts_with(dir))
                .cloned()
                .collect(),
        );
    }
    let dest = if ctx
        .vhost
        .overrides_enabled(ctx.vhost.rewrite.auto_load_htaccess)
    {
        state.rewrite_cache.load_chain_with_dirs(
            &ctx.vhost.doc_root,
            path,
            ctx.vhost.access_file_name_or_default(),
        )
    } else {
        Vec::new()
    };
    let same = dest.len() == cur_chain.len()
        && dest
            .iter()
            .zip(cur_chain)
            .all(|((a, ha), (b, hb))| a == b && Arc::ptr_eq(ha, hb));
    (!same).then_some(dest)
}

/// Evaluate the inline rewrite rules then the `.htaccess` chain (uncached).
///
/// A non-`[END]` rewrite re-enters per-directory processing for the new URI, as
/// OLS does (`postRewriteProcess` -> context rewrite) and Apache does through
/// its internal redirect: an inline (server-context) rewrite runs the rewritten
/// URI's chain instead of the original's, and a per-directory rewrite that
/// moves the request into a different chain runs that whole chain (root-first,
/// like a direct request for the new URI) with `REDIRECT_STATUS=200` and the
/// accumulated env visible. A rewrite that stays within the evaluated chain
/// stops, as in OLS. More than [`MAX_INTERNAL_REDIRECTS`] re-entries fail.
///
/// Every evaluated `.htaccess` that is not in `chain` is appended to `trace.extra`:
/// the outcome then depends on rules outside the caller's chain, so the outcome
/// cache must not store it and page-cache/memo keys must include their reads.
/// Every move into a different chain is appended to `trace.hops`.
fn run_rewrite_inner(
    state: &ServerState,
    ctx: &ReqCtx,
    method: &str,
    headers: &http::HeaderMap,
    raw_request_target: &str,
    chain: &[(PathBuf, Arc<Htaccess>)],
    path: &str,
    query: &str,
    trace: &mut RewriteTrace,
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
    // Case-insensitive name match (HeaderMap::get_all); on a duplicate header name the FIRST
    // value wins — matching `apply_set_env` (SetEnvIf) and Apache/LiteSpeed. Both stages MUST
    // pick the same occurrence, or a deny/cache rule split across SetEnvIf + RewriteCond could
    // be evaded by sending two values of the keyed header (the stages would evaluate against
    // different values). (Was `.next_back()` = last value.) A non-ASCII value is decoded
    // lossily (the view lsphp gets), never skipped (#360).
    let header_lookup = |name: &str| -> Option<String> {
        headers
            .get_all(name)
            .iter()
            .next()
            .map(|v| hj_core::header_value_lossy(v).into_owned())
    };
    // (#3 / A) Populate the expanded %{} variables from ctx. Only the formatted IPs must
    // own; `method`/`host`/`uri`/`query`/`server_name`/`protocol` are borrowed into the
    // `RewriteInput` (Cow), so the uncacheable hot path builds no per-request Strings for them.
    let remote_addr = ip_to_string(ctx.client_ip);
    let server_addr = ip_to_string(ctx.local_addr.ip());
    let server_port = ctx.local_addr.port();

    // A1: build the request representation ONCE — it is identical for every
    // ruleset (first-match-wins; only `per_directory_prefix` is adjusted below).
    let host = rewrite_host(ctx, headers);
    // SERVER_NAME (and so a path-only [R] Location) follows an explicitly mapped alias
    // like OLS/Apache, but a wildcard-routed foreign Host keeps the canonical vhost
    // name so the catch-all vhost never redirects to an arbitrary host (#688).
    let server_name: Cow<'_, str> = if !host.eq_ignore_ascii_case(&ctx.vhost_name)
        && state.router.host_maps_to_vhost(&host, &ctx.vhost_name)
    {
        Cow::Owned(host.to_ascii_lowercase())
    } else {
        Cow::Borrowed(ctx.vhost_name.as_str())
    };
    let mut input = RewriteInput::new(path, docroot)
        .method(method)
        .host(host)
        .https(ctx.is_tls)
        .query(query)
        .remote_addr(remote_addr)
        .remote_port(ctx.peer_port)
        .server_addr(server_addr)
        .server_name(server_name)
        .server_port(server_port)
        .protocol(ctx.protocol.as_str());
    input.header_lookup = Some(HeaderLookup(&header_lookup));
    input.host_port = host_header_port(headers);
    // Seed the env the rewrite engine reads (%{ENV:NAME}) from ctx (SetEnvIf +
    // anything set earlier), so .htaccess RewriteConds see SetEnvIf results. Borrow
    // ctx.env directly rather than cloning every entry into a fresh BTreeMap per
    // request (the engine only reads it; `[E=]` sets land in EvalState's overlay).
    input.env_seed = Some(&ctx.env);
    input.stat = StatSource::LiveTests(&stat);

    // (audit) %{THE_REQUEST} must resolve from the VERBATIM pre-decode target.
    // `req.uri()` still carries the raw percent-encoded bytes — attach them only
    // when some ruleset actually reads the variable (zero cost otherwise).
    let attach_the_request = |input: &mut RewriteInput<'_>, rs: &RuleSet| {
        if rs.uses_the_request && input.raw_request_target.is_none() {
            input.raw_request_target = Some(raw_request_target.to_owned());
        }
    };

    let mut merged_env: Vec<(String, String)> = Vec::new();
    // The latest internal rewrite (canonical path, engine query), if any.
    let mut rewritten: Option<(String, Option<String>)> = None;
    let finish =
        |rewritten: Option<(String, Option<String>)>, env: Vec<(String, String)>| match rewritten {
            Some((path, query)) => RwResult::Rewritten { path, query, env },
            None => RwResult::Unchanged { env },
        };

    // Server context: the vhost's inline rules see the original URI once.
    if let Some(rs) = inline.as_deref() {
        attach_the_request(&mut input, rs);
        input.per_directory_prefix = None;
        input.server_context = true;
        let outcome = evaluate_with_engine(rs, &input, rs.engine_state().unwrap_or(false));
        let is_end = outcome.is_end();
        match outcome {
            RewriteOutcome::Unchanged { env, .. } => {
                carry_env_forward(&mut input.env, &env);
                merged_env.extend(env);
                // [END] on a `-` rule: stop the whole chain; the URI is unchanged.
                if is_end {
                    return RwResult::Unchanged { env: merged_env };
                }
            }
            RewriteOutcome::Rewritten {
                new_uri,
                new_query,
                env,
                ..
            } => {
                carry_env_forward(&mut input.env, &env);
                merged_env.extend(env);
                let Some(path) = canonical_rewritten_path(&new_uri) else {
                    return RwResult::InvalidTarget;
                };
                // [END] also suppresses every per-directory pass (Apache/OLS).
                if is_end {
                    return RwResult::Rewritten {
                        path,
                        query: new_query,
                        env: merged_env,
                    };
                }
                // OLS sets REDIRECT_STATUS on every substitution, the vhost
                // rewrite's included, so the per-directory chain sees it.
                input
                    .env
                    .insert("REDIRECT_STATUS".to_string(), "200".to_string());
                rewritten = Some((path, new_query));
            }
            other => return terminal_outcome(other, merged_env),
        }
    }

    // Per-directory phase. After an inline rewrite this is the rewritten URI's
    // chain (OLS maps the context from the new URI after the vhost rewrite).
    let mut hop_chain: Cow<'_, [(PathBuf, Arc<Htaccess>)]> = Cow::Borrowed(chain);
    if let Some((new_path, new_query)) = &rewritten {
        if let Some(dest) = destination_chain(state, ctx, chain, path, new_path) {
            note_extra(&mut trace.extra, chain, &dest);
            trace.hops.push(RewriteHop {
                path: new_path.clone(),
                chain: dest.clone(),
            });
            hop_chain = Cow::Owned(dest);
        }
        input.uri = Cow::Owned(new_path.clone());
        input.query = Cow::Owned(new_query.clone().unwrap_or_default());
    }
    let mut redirects = 0usize;
    loop {
        // A per-directory ruleset without `RewriteEngine` inherits the nearest
        // enclosing state, rooted at the vhost's rewrite enable (OLS context merge).
        let mut inherited_engine = ctx.vhost.rewrite.enable;
        let mut moved = false;
        for (dir, ht) in hop_chain.iter() {
            let rs = &ht.rules;
            attach_the_request(&mut input, rs);
            input.per_directory_prefix = per_dir_prefix(&ctx.vhost.doc_root, dir);
            input.server_context = false;
            let engine_on = rs.engine_state().unwrap_or(inherited_engine);
            inherited_engine = engine_on;
            let outcome = evaluate_with_engine(rs, &input, engine_on);
            let is_end = outcome.is_end();
            match outcome {
                RewriteOutcome::Unchanged { env, .. } => {
                    carry_env_forward(&mut input.env, &env);
                    merged_env.extend(env);
                    if is_end {
                        return finish(rewritten, merged_env);
                    }
                }
                RewriteOutcome::Rewritten {
                    new_uri,
                    new_query,
                    env,
                    ..
                } => {
                    carry_env_forward(&mut input.env, &env);
                    merged_env.extend(env);
                    let Some(path) = canonical_rewritten_path(&new_uri) else {
                        return RwResult::InvalidTarget;
                    };
                    // Pass the engine's `Option` query through unchanged: `None` (incl.
                    // `[QSD]`) means "no query", which the dispatch loop turns into an
                    // empty string — NOT the original query (that bug made `[QSD]` a no-op).
                    rewritten = Some((path, new_query));
                    if is_end {
                        return finish(rewritten, merged_env);
                    }
                    moved = true;
                    break;
                }
                other => return terminal_outcome(other, merged_env),
            }
        }
        if !moved {
            break;
        }
        let Some((new_path, new_query)) = &rewritten else {
            break;
        };
        let Some(dest) = destination_chain(state, ctx, &hop_chain, &input.uri, new_path) else {
            break;
        };
        redirects += 1;
        if redirects > MAX_INTERNAL_REDIRECTS {
            return RwResult::Failed {
                reason: INTERNAL_REDIRECT_LIMIT,
            };
        }
        note_extra(&mut trace.extra, chain, &dest);
        trace.hops.push(RewriteHop {
            path: new_path.clone(),
            chain: dest.clone(),
        });
        // The internal redirect's env (Apache sets it on the redirected request;
        // OLS sets it on every rewrite). Engine-only: lsphp gets its own.
        input
            .env
            .insert("REDIRECT_STATUS".to_string(), "200".to_string());
        input.uri = Cow::Owned(new_path.clone());
        input.query = Cow::Owned(new_query.clone().unwrap_or_default());
        hop_chain = Cow::Owned(dest);
    }
    finish(rewritten, merged_env)
}

/// Record each `dest` entry the caller's `chain` does not hold (once).
fn note_extra(
    extra: &mut Vec<(PathBuf, Arc<Htaccess>)>,
    chain: &[(PathBuf, Arc<Htaccess>)],
    dest: &[(PathBuf, Arc<Htaccess>)],
) {
    let same = |(a, ha): &(PathBuf, Arc<Htaccess>), (b, hb): &(PathBuf, Arc<Htaccess>)| {
        a == b && Arc::ptr_eq(ha, hb)
    };
    for entry in dest {
        if !chain.iter().any(|c| same(c, entry)) && !extra.iter().any(|e| same(e, entry)) {
            extra.push(entry.clone());
        }
    }
}

/// Map a terminal (non-rewrite, non-unchanged) engine outcome, prefixing the env
/// merged from every earlier ruleset.
fn terminal_outcome(outcome: RewriteOutcome, mut all: Vec<(String, String)>) -> RwResult {
    match outcome {
        RewriteOutcome::Failed { reason, .. } => RwResult::Failed { reason },
        RewriteOutcome::Proxy {
            target_url,
            proxy_host,
            mut env,
        } => {
            all.append(&mut env);
            RwResult::Proxy {
                target_url,
                proxy_host,
                env: all,
            }
        }
        RewriteOutcome::Redirect {
            code,
            location,
            mut env,
            ..
        } => {
            all.append(&mut env);
            RwResult::Redirect {
                code,
                location,
                env: all,
            }
        }
        RewriteOutcome::Status { code, mut env, .. } => {
            all.append(&mut env);
            RwResult::Status { code, env: all }
        }
        RewriteOutcome::Forbidden { .. } => RwResult::Forbidden,
        RewriteOutcome::Gone { .. } => RwResult::Gone,
        RewriteOutcome::Unchanged { env, .. } => {
            all.extend(env);
            RwResult::Unchanged { env: all }
        }
        RewriteOutcome::Rewritten {
            new_uri,
            new_query,
            mut env,
            ..
        } => {
            all.append(&mut env);
            match canonical_rewritten_path(&new_uri) {
                Some(path) => RwResult::Rewritten {
                    path,
                    query: new_query,
                    env: all,
                },
                None => RwResult::InvalidTarget,
            }
        }
    }
}

/// Make one ruleset's `[E=]` output visible to the `%{ENV:}` reads of every later
/// ruleset (OLS `setEnv` writes the request env the next ruleset reads, #822).
/// `carried` is the engine's owned env layer, which shadows the borrowed `ctx.env`
/// seed: an unset is recorded as `""` so the seed value is hidden (unset and empty
/// expand alike). The reserved `HJ_` namespace stays out of reach, exactly as when
/// the assignment is later merged into `ctx.env`.
fn carry_env_forward(
    carried: &mut std::collections::BTreeMap<String, String>,
    env: &[(String, String)],
) {
    for (key, value) in env {
        let assignment = hj_rewrite::EnvAssignment::classify(key, value);
        let name = assignment.name();
        if name.is_empty() || !super::htaccess_apply::env_key_allowed(name) {
            continue;
        }
        let value = match assignment {
            hj_rewrite::EnvAssignment::Set { value, .. } => value,
            hj_rewrite::EnvAssignment::Unset { .. } => "",
        };
        carried.insert(name.to_string(), value.to_string());
    }
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

/// The canonical form of an internal rewrite target. The engine's substitution is
/// URI-escaped, and Apache adopts an internal rewrite through an internal redirect that
/// percent-decodes and dot-normalizes the path again before the per-directory walk,
/// access checks and file mapping. Decoding exactly once here gives every downstream
/// consumer (destination chain, access checks, script split, static handler) the same
/// path. A decoded `%2F` is a separator, the same policy as the request's first decode.
pub(super) fn canonical_rewritten_path(new_uri: &str) -> Option<String> {
    decode_request_path(new_uri).map(|decoded| normalized_request_path(&decoded))
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
            b'/'
            | b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
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
            | b'@' => {
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
            port: 443,
            method: "GET".into(),
            host: "h".into(),
            path: path.into(),
            query: String::new(),
            key_vars: String::new(),
        }
    }

    #[test]
    fn host_header_port_parses_named_and_v6_hosts() {
        let port = |h: &str| {
            let mut m = http::HeaderMap::new();
            m.insert(http::header::HOST, h.parse().unwrap());
            host_header_port(&m)
        };
        assert_eq!(port("example.com"), None);
        assert_eq!(port("example.com:8080"), Some(8080));
        assert_eq!(port("[::1]"), None);
        assert_eq!(port("[::1]:8443"), Some(8443));
    }

    #[test]
    fn outcome_key_separates_listener_ports() {
        // #692: a path-only [R] Location carries the listener port.
        let c = Arc::new(RewriteOutcomeCache::new(DEFAULT_REWRITE_OUTCOME_TTL));
        c.insert(okey("/p"), RwResult::Forbidden);
        assert!(c.get(&okey("/p")).is_some());
        assert!(
            c.get(&OutcomeKey {
                port: 8443,
                ..okey("/p")
            })
            .is_none()
        );
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
            forwarding_trusted: false,
            env: Vec::new(),
            local_addr: SocketAddr::from(([127, 0, 0, 1], 443)),
            peer_port: 12345,
            peer_unix: false,
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
            rewrite_host(&ctx, mk(Some("[2606:4700::1111]:443")).headers()),
            "2606:4700::1111"
        );
        assert_eq!(rewrite_host(&ctx, mk(Some("[::1]")).headers()), "::1");
        // Ordinary host:port still strips the port (and normalizes case, like the router).
        assert_eq!(
            rewrite_host(&ctx, mk(Some("Example.COM:8080")).headers()),
            "example.com"
        );
        // No Host header → fall back to the vhost name.
        assert_eq!(rewrite_host(&ctx, mk(None).headers()), "fallback.example");
    }

    #[test]
    fn empty_generation_preserves_old_outcomes_and_ttl() {
        let old = Arc::new(RewriteOutcomeCache::new(Duration::from_secs(45)));
        old.insert(okey("/a"), RwResult::Forbidden);
        let next = Arc::new(old.empty_generation());
        assert_eq!(next.ttl, Duration::from_secs(45));
        assert!(next.get(&okey("/a")).is_none());
        assert!(matches!(old.get(&okey("/a")), Some(RwResult::Forbidden)));
        old.insert(okey("/late"), RwResult::Forbidden);
        assert!(next.get(&okey("/late")).is_none());
        next.insert(okey("/a"), RwResult::Gone);
        assert!(matches!(old.get(&okey("/a")), Some(RwResult::Forbidden)));
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
    fn sync_prune_initial_claim_uses_cas_and_disarms_zero_sentinel() {
        let c = RewriteOutcomeCache::with_cap(Duration::from_millis(20), 2);
        assert!(c.claim_sync_prune(0, 100), "first caller claims the slot");
        assert_eq!(
            c.last_sync_prune.load(Ordering::Relaxed),
            1,
            "millisecond-zero claim must not leave the never-run sentinel armed"
        );
        assert!(
            !c.claim_sync_prune(0, 100),
            "a second caller inside the window must not run another synchronous sweep"
        );
        assert!(
            c.claim_sync_prune(101, 100),
            "a later window may claim again"
        );
    }

    #[test]
    fn full_live_cache_runs_only_one_sync_prune_inside_the_window() {
        let c = Arc::new(RewriteOutcomeCache::with_cap(Duration::from_secs(60), 2));
        c.insert(okey("/a"), RwResult::Gone);
        c.insert(okey("/b"), RwResult::Forbidden);
        assert_eq!(c.count.load(Ordering::Relaxed), 2);

        c.insert(okey("/cold-1"), RwResult::Gone);
        let first_claim = c.last_sync_prune.load(Ordering::Relaxed);
        assert_ne!(
            first_claim, 0,
            "the real at-cap insert gate must claim and disarm the initial sentinel"
        );
        assert_eq!(c.count.load(Ordering::Relaxed), 2, "the cap remains hard");
        assert!(c.get(&okey("/cold-1")).is_none());

        for path in ["/cold-2", "/cold-3", "/cold-4"] {
            c.insert(okey(path), RwResult::Gone);
            assert!(c.get(&okey(path)).is_none());
        }
        assert_eq!(
            c.last_sync_prune.load(Ordering::Relaxed),
            first_claim,
            "later cold inserts over a live full cache must not sweep again inside the window"
        );
        assert_eq!(c.count.load(Ordering::Relaxed), 2);
        assert!(matches!(c.get(&okey("/a")), Some(RwResult::Gone)));
        assert!(matches!(c.get(&okey("/b")), Some(RwResult::Forbidden)));
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
    fn rewritten_targets_decode_once_and_normalize() {
        for (target, canonical) in [
            ("/3d/%2e%2e/robots.txt", Some("/robots.txt")),
            ("/files/a%20b.txt", Some("/files/a b.txt")),
            ("/files/100%25.txt", Some("/files/100%.txt")),
            ("/files/a%2Fb/../c", Some("/files/a/c")),
            ("/community/", Some("/community/")),
            ("/index.php", Some("/index.php")),
            ("/a%00b", None),
            ("/bad%zz", None),
            ("/%FF", None),
        ] {
            assert_eq!(
                canonical_rewritten_path(target).as_deref(),
                canonical,
                "{target}"
            );
        }
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
            "/a+b;c=d,e(f)@g!h'i*j$k&l:m",
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

    #[tokio::test]
    async fn child_htaccess_without_rewrite_engine_inherits_the_parent_state() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let root = std::env::temp_dir().join(format!("hj-engine-inherit-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let state = super::super::e2e::build_state(root.clone());
        let mk_ctx = |vhost: Arc<hj_core::config::VHostConfig>| ReqCtx {
            server: Arc::clone(&state.server),
            vhost_name: "e2e".into(),
            vhost,
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            is_tls: false,
            protocol: hj_core::Proto::Http1,
            trusted_proxy: false,
            forwarding_trusted: false,
            env: Vec::new(),
            local_addr: SocketAddr::from(([127, 0, 0, 1], 80)),
            peer_port: 12345,
            peer_unix: false,
            tls: None,
            redirect_guard: None,
            request_time: std::time::SystemTime::now(),
            request_id: Default::default(),
        };
        let vhost = |enable: bool| {
            let mut v = hj_core::config::VHostConfig {
                doc_root: root.clone(),
                ..Default::default()
            };
            v.rewrite.enable = enable;
            Arc::new(v)
        };
        let child = Arc::new(Htaccess::parse("RewriteRule ^private - [F]\n").unwrap());
        let parsed = |src: &str| Arc::new(Htaccess::parse(src).unwrap());
        let run = |ctx: &ReqCtx, chain: &[(PathBuf, Arc<Htaccess>)]| {
            run_rewrite_inner(
                &state,
                ctx,
                "GET",
                &http::HeaderMap::new(),
                "/sub/private",
                chain,
                "/sub/private",
                "",
                &mut RewriteTrace::default(),
            )
        };
        let off_vhost = mk_ctx(vhost(false));
        let on_parent = [
            (root.clone(), parsed("RewriteEngine On\n")),
            (root.join("sub"), Arc::clone(&child)),
        ];
        assert!(matches!(run(&off_vhost, &on_parent), RwResult::Forbidden));
        let off_parent = [
            (root.clone(), parsed("RewriteEngine Off\n")),
            (root.join("sub"), Arc::clone(&child)),
        ];
        assert!(matches!(
            run(&mk_ctx(vhost(true)), &off_parent),
            RwResult::Unchanged { .. }
        ));
        let child_only = [(root.join("sub"), Arc::clone(&child))];
        assert!(matches!(
            run(&mk_ctx(vhost(true)), &child_only),
            RwResult::Forbidden
        ));
        assert!(matches!(
            run(&off_vhost, &child_only),
            RwResult::Unchanged { .. }
        ));
        let _ = std::fs::remove_dir_all(&root);
    }
}
