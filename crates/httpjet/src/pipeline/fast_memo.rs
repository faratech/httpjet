//! (#349) Finished-response memo for the on-core static fast path.
//!
//! DEFAULT-ON; disable with `--no-fast-memo` (or env `HJ_FAST_MEMO=0`). Under
//! saturating multiplexed small-file load the fast path is instruction-bound
//! re-deriving an identical response per request (chain probe + SetEnvIf +
//! rewrite + ACL + static handler + transforms ≈ 25-30% of serving CPU); this
//! memo replays the finished response for a repeat key instead (measured
//! 2-3x on h2 small-file throughput with a dedicated load generator).
//! Per-thread (no locks), 1 s TTL — stricter than nginx's
//! `open_file_cache_valid` 60 s default — so any filesystem/`.htaccess`/purge
//! change is visible within a second, and every DISTINCT key passes the full
//! pipeline once before it is ever memoized.
//!
//! Correctness model: a response may be replayed only when it is provably a
//! pure function of the memo key PLUS the entry's own vary-set. The key is
//! (listener, scheme, trusted-proxy bit, vhost, Host + where it came from, raw
//! path?query, Accept-Encoding); the trust bit matters because compression
//! hands a trusted (Cloudflare) peer zstd regardless of `Accept-Encoding` under
//! `CF_SEND_ZSTD`. The vary-set is the HTTP `Vary` of the entry: the raw value
//! of every request header the chain reads (`SetEnvIf Origin …`,
//! `RewriteCond %{HTTP:Origin}` …) and, for a User-Agent-reading ruleset, the
//! UA-cond match bitmap it keys on ([`hj_rewrite::RuleSet::ua_cond_signature`],
//! pinned to the exact parsed ruleset). The store site enforces the model with:
//! * request gates — GET, no `Cookie`/`Range`/`If-*`/`Authorization`;
//! * chain gates — every `.htaccess` in the loaded chain is
//!   [`hj_rewrite::MemoClass`]-eligible (parse-time, fail-closed: SetEnvIf on
//!   client/server address or protocol, IP/env access rules, and any rewrite
//!   input outside the key + keyable vars all withdraw eligibility) and the
//!   vhost inline ruleset is `path_cacheable`; `Header` directives conditional on
//!   env/`<If>` are covered because this engine models those conditions on
//!   URI/env only, and env is itself a function of key + vary-set;
//! * response gates — status 200, in-memory `Body::Full`, no `Set-Cookie`.
//! The probe runs BEFORE the chain is loaded — a hit does no chain work at all —
//! which is why each entry carries its vary-set rather than the pipeline
//! recomputing one. `Date` is appended at protocol serialization (not stored),
//! `X-Request-Id` is re-applied per hit by `record_fast_serve`, and per-hit
//! logging/metrics stay live (hits go through the same observability funnel as
//! every serve).

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hj_core::{Body, Request, Response};
use hj_rewrite::{Htaccess, RuleSet};

use super::UaClassifyCache;

const TTL: Duration = Duration::from_secs(1);
const MAX_ENTRIES: usize = 2048;
/// Bodies above this never memoize: large files stream/bridge anyway and one
/// giant `Bytes` per thread per key would pin RAM for no throughput win.
pub(crate) const MAX_BODY: usize = 1024 * 1024;
/// Per-thread cap on the SUM of memoized body bytes. Without it the worst case
/// is MAX_ENTRIES x MAX_BODY = 2 GiB per worker; with it, memo RSS is bounded
/// at workers x 64 MiB. Exceeding it clears the map (same policy as the entry
/// cap — the hot set re-primes within a second).
const MAX_BYTES: usize = 64 * 1024 * 1024;
/// Distinct vary-sets kept per base key (a crawler and a browser class, a
/// couple of CORS origins). Overflow drops the bucket rather than growing it.
const MAX_VARIANTS: usize = 4;
/// A vary header value longer than this never memoizes (the outcome cache's
/// oversized-key discipline): the entry would be single-use and pin its bytes.
const MAX_VARY_VALUE: usize = 1024;
/// Expired store records reclaimed per probe/store at most, so a burst of
/// distinct keys is freed a few buckets at a time on the serving core instead
/// of waiting for a cap to clear the whole map.
const RECLAIM_BATCH: usize = 8;
/// The reclaim queue only outgrows the entry cap when stores replace live
/// entries in place; past this it clears like the other caps.
const MAX_QUEUED: usize = 2 * MAX_ENTRIES;

/// Kill switch, default ON. `main` clears it for `--no-fast-memo` or env
/// `HJ_FAST_MEMO=0` BEFORE any listener accepts, so a relaxed load is fine.
pub(crate) static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub(super) fn enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Where the routing host came from. A `Host` header and a URI authority
/// spelling the same bytes still resolve `%{HTTP_HOST}` / `SetEnvIf Host`
/// differently (header value vs. the vhost-name fallback), so they never share
/// an entry.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum HostSource {
    Header,
    Authority,
}

pub(super) struct MemoKey<'a> {
    pub generation: u64,
    pub allow_page_responses: bool,
    pub response_epoch: Option<&'a str>,
    pub purge_epoch: u64,
    pub listener: &'a str,
    pub https: bool,
    pub trusted_proxy: bool,
    pub vhost: &'a str,
    pub host_src: HostSource,
    pub host: &'a [u8],
    pub path: &'a str,
    pub query: &'a str,
    pub ae: &'a [u8],
}

/// The ruleset a [`VaryItem::UaClass`] bitmap was computed against, pinned so a
/// reparse can never be judged with stale bits (the entry dies with its TTL).
#[derive(Clone)]
pub(super) enum UaRules {
    Chain(Arc<Htaccess>),
    Inline(Arc<RuleSet>),
}

impl UaRules {
    fn rules(&self) -> &RuleSet {
        match self {
            UaRules::Chain(h) => &h.rules,
            UaRules::Inline(r) => r,
        }
    }

    fn same(&self, other: &UaRules) -> bool {
        match (self, other) {
            (UaRules::Chain(a), UaRules::Chain(b)) => Arc::ptr_eq(a, b),
            (UaRules::Inline(a), UaRules::Inline(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

/// One dimension of an entry's vary-set.
pub(super) enum VaryItem {
    /// The raw FIRST value of a request header (absent ≠ present-but-empty).
    Header {
        name: http::HeaderName,
        value: Option<Bytes>,
    },
    /// The UA-cond match bitmap of a User-Agent-reading ruleset.
    UaClass { rules: UaRules, bits: u64 },
}

impl VaryItem {
    fn matches(&self, req: &Request, ua_cache: &UaClassifyCache) -> bool {
        match self {
            VaryItem::Header { name, value } => {
                req.headers().get(name).map(|v| v.as_bytes()) == value.as_deref()
            }
            VaryItem::UaClass { rules, bits } => {
                ua_cache.get_or_compute(rules.rules(), &ua_for_classify(req)) == *bits
            }
        }
    }

    fn same(&self, other: &VaryItem) -> bool {
        match (self, other) {
            (VaryItem::Header { name: a, value: va }, VaryItem::Header { name: b, value: vb }) => {
                a == b && va == vb
            }
            (
                VaryItem::UaClass { rules: a, bits: ba },
                VaryItem::UaClass { rules: b, bits: bb },
            ) => ba == bb && a.same(b),
            _ => false,
        }
    }
}

/// The raw first value of `name`, as a vary item (the header's absence is a
/// value too).
pub(super) fn vary_header(req: &Request, name: http::HeaderName) -> VaryItem {
    let value = req
        .headers()
        .get(&name)
        .map(|v| Bytes::copy_from_slice(v.as_bytes()));
    VaryItem::Header { name, value }
}

/// The User-Agent exactly as the rewrite engine and its outcome cache see it:
/// first value, decoded lossily, absent ⇒ `""` (see `keyed_header` in
/// `rewrite_glue`). Probe and store MUST classify the same string.
pub(super) fn ua_for_classify(req: &Request) -> Cow<'_, str> {
    req.headers()
        .get(http::header::USER_AGENT)
        .map(hj_core::header_value_lossy)
        .unwrap_or(Cow::Borrowed(""))
}

fn vary_same(a: &[VaryItem], b: &[VaryItem]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.same(y))
}

struct MemoEntry {
    generation: u64,
    page: Option<crate::lscache::PublicResponseMemo>,
    response_epoch: Option<Arc<str>>,
    purge_epoch: u64,
    listener: String,
    https: bool,
    trusted_proxy: bool,
    vhost: String,
    host_src: HostSource,
    host: Vec<u8>,
    path: String,
    query: String,
    ae: Vec<u8>,
    vary: Vec<VaryItem>,
    status: http::StatusCode,
    headers: http::HeaderMap,
    /// `headers` ends with a placeholder `Date` that each replay overwrites in place.
    stamp_date: bool,
    body: Bytes,
    expires: Instant,
}

#[derive(Default)]
struct Memo {
    /// Base-key hash → the variants (distinct vary-sets) stored under it.
    map: HashMap<u64, Vec<MemoEntry>>,
    /// Sum of `body.len()` across every variant (the [`MAX_BYTES`] budget).
    bytes: usize,
    /// Number of variants across `map` (the [`MAX_ENTRIES`] cap).
    count: usize,
    /// `(expires, base-key hash)` per store, in store order. A record can
    /// outlive its entry (replaced, drained, probed away); reclaiming it then
    /// only drops whatever in that bucket has expired.
    expiry: VecDeque<(Instant, u64)>,
}

impl Memo {
    fn clear(&mut self) {
        self.map.clear();
        self.expiry.clear();
        self.bytes = 0;
        self.count = 0;
    }

    /// Drop bucket `h`'s expired variants; `true` while any variant is left.
    fn drop_expired(&mut self, h: u64, now: Instant) -> bool {
        let Memo {
            map, bytes, count, ..
        } = self;
        let Some(bucket) = map.get_mut(&h) else {
            return false;
        };
        bucket.retain(|e| {
            let live = now < e.expires;
            if !live {
                *bytes -= e.body.len();
                *count -= 1;
            }
            live
        });
        if bucket.is_empty() {
            map.remove(&h);
            return false;
        }
        true
    }

    fn reclaim_expired(&mut self, now: Instant) {
        for _ in 0..RECLAIM_BATCH {
            match self.expiry.front() {
                Some(&(expires, h)) if expires <= now => {
                    self.expiry.pop_front();
                    self.drop_expired(h, now);
                }
                _ => return,
            }
        }
    }
}

thread_local! {
    static MEMO: RefCell<Memo> = RefCell::new(Memo::default());
}

fn key_hash(k: &MemoKey) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    k.generation.hash(&mut h);
    {
        k.response_epoch.hash(&mut h);
        k.purge_epoch.hash(&mut h);
    }
    k.listener.hash(&mut h);
    k.https.hash(&mut h);
    k.trusted_proxy.hash(&mut h);
    k.vhost.hash(&mut h);
    k.host_src.hash(&mut h);
    k.host.hash(&mut h);
    k.path.hash(&mut h);
    k.query.hash(&mut h);
    k.ae.hash(&mut h);
    h.finish()
}

/// Identity guard (page-cache rule 2): a hash collision degrades to a miss,
/// never a wrong response.
fn matches(e: &MemoEntry, k: &MemoKey) -> bool {
    if e.response_epoch.as_deref() != k.response_epoch || e.purge_epoch != k.purge_epoch {
        return false;
    }
    e.generation == k.generation
        && e.https == k.https
        && e.trusted_proxy == k.trusted_proxy
        && e.host_src == k.host_src
        && e.listener == k.listener
        && e.vhost == k.vhost
        && e.host == k.host
        && e.path == k.path
        && e.query == k.query
        && e.ae == k.ae
}

pub(super) fn probe(
    k: &MemoKey,
    req: &Request,
    ua_cache: &UaClassifyCache,
    now: Instant,
) -> Option<(Response, Option<crate::lscache::PublicResponseMemo>)> {
    let h = key_hash(k);
    MEMO.with(|m| {
        let mut m = m.borrow_mut();
        m.reclaim_expired(now);
        if !m.drop_expired(h, now) {
            return None;
        }
        let e = m.map.get(&h)?.iter().find(|e| {
            (k.allow_page_responses || e.page.is_none())
                && e.page.as_ref().is_none_or(|page| page.lease.is_current())
                && matches(e, k)
                && e.vary.iter().all(|v| v.matches(req, ua_cache))
        })?;
        if e.page.is_some() && Instant::now() >= e.expires {
            return None;
        }
        let mut resp = http::Response::new(Body::Full(e.body.clone()));
        *resp.status_mut() = e.status;
        *resp.headers_mut() = e.headers.clone();
        if e.stamp_date {
            resp.headers_mut()
                .insert(http::header::DATE, hj_core::http_date_now());
        }
        Some((resp, e.page.clone()))
    })
}

#[cfg(test)]
pub(super) fn store(k: &MemoKey, vary: Vec<VaryItem>, resp: &Response, now: Instant) {
    store_until(k, vary, resp, now, now + TTL);
}

pub(super) fn store_until(
    k: &MemoKey,
    vary: Vec<VaryItem>,
    resp: &Response,
    now: Instant,
    policy_deadline: Instant,
) -> bool {
    let page = resp
        .extensions()
        .get::<crate::lscache::PublicResponseMemo>()
        .cloned();
    if page.as_ref().is_some_and(|page| {
        !k.allow_page_responses || page.purge_epoch != k.purge_epoch || !page.lease.is_current()
    }) || (page.is_some()
        && (resp.status() != http::StatusCode::OK
            || resp.headers().contains_key(http::header::SET_COOKIE)))
    {
        return false;
    }
    let expires = (now + TTL)
        .min(policy_deadline)
        .min(page.as_ref().map_or(policy_deadline, |page| page.deadline));
    if expires <= Instant::now() {
        return false;
    }

    let Body::Full(body) = resp.body() else {
        return false;
    };
    if body.len() > MAX_BODY {
        return false;
    }
    if vary
        .iter()
        .any(|v| matches!(v, VaryItem::Header { value: Some(b), .. } if b.len() > MAX_VARY_VALUE))
    {
        return false;
    }
    let h = key_hash(k);
    // A cloned HeaderMap has no spare entry capacity, so stamping Date on each replay
    // regrew the whole header array (a ~6 KiB realloc + copy on the forum, re-faulting
    // fresh pages under MIMALLOC_PURGE_DELAY=0). Store the slot; a replay overwrites it.
    let mut headers = if page.is_some() {
        // A hit can expose HeaderValue slices of a larger metadata buffer.
        // Own compact values instead of pinning that buffer in this extra memo.
        if resp.headers().len() > 64 {
            return false;
        }
        let mut compact = http::HeaderMap::with_capacity(resp.headers().len() + 1);
        let mut charge = 0usize;
        for (name, value) in resp.headers() {
            charge = charge
                .saturating_add(name.as_str().len())
                .saturating_add(value.len())
                .saturating_add(64);
            if charge > 8192 {
                return false;
            }
            let Ok(value) = http::HeaderValue::from_bytes(value.as_bytes()) else {
                return false;
            };
            compact.append(name.clone(), value);
        }
        compact
    } else {
        resp.headers().clone()
    };
    let stamp_date = !headers.contains_key(http::header::DATE);
    if stamp_date {
        headers.insert(http::header::DATE, hj_core::http_date_now());
    }
    let is_page = page.is_some();
    let entry = MemoEntry {
        generation: k.generation,
        page,
        response_epoch: k.response_epoch.map(Arc::from),
        purge_epoch: k.purge_epoch,
        listener: k.listener.to_owned(),
        https: k.https,
        trusted_proxy: k.trusted_proxy,
        vhost: k.vhost.to_owned(),
        host_src: k.host_src,
        host: k.host.to_owned(),
        path: k.path.to_owned(),
        query: k.query.to_owned(),
        ae: k.ae.to_owned(),
        vary,
        status: resp.status(),
        headers,
        stamp_date,
        // Held for the memo's TTL. A pooled egress buffer (marked `FreshBody` by its producer)
        // is copied out, or the entry would pin it whole while the byte budget counted only
        // its length; any other body (the static cache's exact-size bytes) is shared.
        body: if is_page
            || resp
                .extensions()
                .get::<hj_core::FreshBody>()
                .is_some_and(|fresh| fresh.names(body))
        {
            Bytes::copy_from_slice(body)
        } else {
            body.clone()
        },
        expires,
    };
    MEMO.with(|m| {
        let mut m = m.borrow_mut();
        m.reclaim_expired(now);
        if m.count >= MAX_ENTRIES
            || m.bytes + entry.body.len() > MAX_BYTES
            || m.expiry.len() >= MAX_QUEUED
        {
            m.clear();
        }
        m.expiry.push_back((expires, h));
        let Memo {
            map, bytes, count, ..
        } = &mut *m;
        let bucket = map.entry(h).or_default();
        if let Some(i) = bucket
            .iter()
            .position(|e| matches(e, k) && vary_same(&e.vary, &entry.vary))
        {
            *bytes -= bucket[i].body.len();
            *bytes += entry.body.len();
            bucket[i] = entry;
            return true;
        }
        if bucket.len() >= MAX_VARIANTS {
            for e in bucket.drain(..) {
                *bytes -= e.body.len();
                *count -= 1;
            }
        }
        *bytes += entry.body.len();
        *count += 1;
        bucket.push(entry);
        true
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key<'a>(path: &'a str, ae: &'a [u8]) -> MemoKey<'a> {
        MemoKey {
            generation: 1,
            allow_page_responses: false,
            response_epoch: None,
            purge_epoch: 0,
            listener: "l1",
            https: true,
            trusted_proxy: false,
            vhost: "v",
            host_src: HostSource::Header,
            host: b"v",
            path,
            query: "",
            ae,
        }
    }

    fn req(headers: &[(&str, &str)]) -> Request {
        let mut b = http::Request::builder().method("GET").uri("/x");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(hj_core::empty_incoming()).unwrap()
    }

    fn resp(body: &'static [u8]) -> Response {
        let mut r = http::Response::new(Body::Full(Bytes::from_static(body)));
        r.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain"),
        );
        r
    }

    fn ua_cache() -> UaClassifyCache {
        UaClassifyCache::new()
    }

    fn page_lease() -> (
        hj_pagecache::PageStore,
        hj_pagecache::PageCacheKey,
        hj_pagecache::SnapshotLease,
    ) {
        let store = hj_pagecache::PageStore::new(hj_pagecache::StoreConfig::default());
        let key = hj_pagecache::PageCacheKey::public(1, true, "test", "/lease", "");
        store.store(
            key.clone(),
            hj_pagecache::CachedResponse {
                status: 200,
                identity: "memo-test".into(),
                headers: Vec::new(),
                body: hj_pagecache::PageBody::InMem(Bytes::from_static(b"lease")),
                variants: Vec::new(),
                variants_filled: false,
                dict_gen: 0,
                tags: Vec::new(),
                vary_cookie_name: String::new(),
                vary_value: String::new(),
                scope: hj_pagecache::PageScope::Public,
                stored_at: Instant::now(),
                ttl: Duration::from_secs(60),
                swr: Duration::ZERO,
                sie: Duration::ZERO,
            },
        );
        let hj_pagecache::EntryState::Fresh(snapshot) =
            store.get_entry_uncounted(&key, "memo-test", Instant::now())
        else {
            panic!("fixture must have a fresh native entry");
        };
        let lease = store.lease_snapshot(&key, &snapshot).unwrap();
        (store, key, lease)
    }

    #[test]
    fn public_page_memo_stops_at_age_tick_and_respects_its_disable_switch() {
        let (_store, _key, lease) = page_lease();
        let now = Instant::now();
        let mut k = key("/page-age-boundary", b"");
        k.allow_page_responses = true;
        let mut response = resp(b"page");
        response
            .headers_mut()
            .insert(http::header::AGE, http::HeaderValue::from_static("9"));
        response
            .extensions_mut()
            .insert(crate::lscache::PublicResponseMemo {
                key_hash: 123,
                purge_epoch: 0,
                deadline: now + Duration::from_millis(250),
                lease,
            });
        assert!(store_until(
            &k,
            Vec::new(),
            &response,
            now,
            now + Duration::from_secs(5)
        ));
        let ua = ua_cache();
        let request = req(&[]);
        let (hit, page) = probe(&k, &request, &ua, now + Duration::from_millis(249)).unwrap();
        assert_eq!(hit.headers()[http::header::AGE], "9");
        assert_eq!(page.unwrap().key_hash, 123);
        assert!(hit.extensions().is_empty());
        k.allow_page_responses = false;
        assert!(probe(&k, &request, &ua, now).is_none());
        k.allow_page_responses = true;
        assert!(probe(&k, &request, &ua, now + Duration::from_millis(250)).is_none());
    }

    #[test]
    fn public_page_memo_rejects_a_revoked_fill_and_preserves_response_vary() {
        let (_store, _key, lease) = page_lease();
        let now = Instant::now();
        let mut k = key("/page-language", b"");
        k.allow_page_responses = true;
        let mut response = resp(b"english");
        response.headers_mut().insert(
            http::header::VARY,
            http::HeaderValue::from_static("Accept-Language, Accept-Encoding"),
        );
        response
            .extensions_mut()
            .insert(crate::lscache::PublicResponseMemo {
                key_hash: 456,
                purge_epoch: 0,
                deadline: now + TTL,
                lease,
            });
        let english = req(&[("accept-language", "en")]);
        let german = req(&[("accept-language", "de")]);
        let vary = super::super::page_memo_vary(&english, response.headers(), Vec::new()).unwrap();
        k.purge_epoch = 1;
        assert!(!store_until(
            &k,
            super::super::page_memo_vary(&english, response.headers(), Vec::new()).unwrap(),
            &response,
            now,
            now + TTL,
        ));
        k.purge_epoch = 0;
        assert!(store_until(&k, vary, &response, now, now + TTL));
        let ua = ua_cache();
        assert!(probe(&k, &english, &ua, now).is_some());
        assert!(probe(&k, &german, &ua, now).is_none());
        assert!(probe(&k, &req(&[]), &ua, now).is_none());
        response
            .headers_mut()
            .insert(http::header::VARY, http::HeaderValue::from_static("*"));
        assert!(super::super::page_memo_vary(&english, response.headers(), Vec::new()).is_none());
    }

    #[test]
    fn public_page_memo_compacts_header_and_body_backing_allocations() {
        let (_store, _key, lease) = page_lease();
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct Owner {
            bytes: Vec<u8>,
            dropped: Arc<AtomicBool>,
        }
        impl AsRef<[u8]> for Owner {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Relaxed);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let mut backing = vec![b'x'; 4 * 1024 * 1024];
        backing[..4].copy_from_slice(b"body");
        let owner = Bytes::from_owner(Owner {
            bytes: backing,
            dropped: dropped.clone(),
        });
        let mut response = http::Response::new(Body::Full(owner.slice(..4)));
        response.headers_mut().insert(
            "x-test",
            http::HeaderValue::from_maybe_shared(owner.slice(4..8)).unwrap(),
        );
        let now = Instant::now();
        response
            .extensions_mut()
            .insert(crate::lscache::PublicResponseMemo {
                key_hash: 789,
                purge_epoch: 0,
                deadline: now + TTL,
                lease,
            });
        let mut k = key("/page-compact", b"");
        k.allow_page_responses = true;
        assert!(store_until(&k, Vec::new(), &response, now, now + TTL));
        drop(response);
        drop(owner);
        assert!(dropped.load(Ordering::Relaxed));
        let (hit, _) = probe(&k, &req(&[]), &ua_cache(), now).unwrap();
        assert_eq!(hit.headers()["x-test"], "xxxx");
        assert!(matches!(hit.body(), Body::Full(bytes) if bytes.as_ref() == b"body"));
    }

    #[test]
    fn public_page_memo_stops_after_key_invalidation_without_a_tag_purge() {
        let (store, key, lease) = page_lease();
        let now = Instant::now();
        let mut k = self::key("/page-key-revoked", b"");
        k.allow_page_responses = true;
        let mut response = resp(b"page");
        response
            .extensions_mut()
            .insert(crate::lscache::PublicResponseMemo {
                key_hash: 999,
                purge_epoch: 0,
                deadline: now + TTL,
                lease: lease.clone(),
            });
        assert!(store_until(&k, Vec::new(), &response, now, now + TTL));
        assert!(probe(&k, &req(&[]), &ua_cache(), now).is_some());
        let epoch = store.purge_epoch();
        store.invalidate_key(&key);
        assert_eq!(
            store.purge_epoch(),
            epoch,
            "key invalidation has its own revocation"
        );
        assert!(!lease.is_current());
        assert!(probe(&k, &req(&[]), &ua_cache(), now).is_none());
    }

    #[test]
    fn public_page_snapshot_lease_stops_after_mutation_and_store_drop() {
        let (store, key, lease) = page_lease();
        let hj_pagecache::EntryState::Fresh(before) =
            store.get_entry_uncounted(&key, "memo-test", Instant::now())
        else {
            panic!("fresh fixture");
        };
        store.fill_variants(&key, "memo-test", before.stored_at, Vec::new(), None);
        assert!(!lease.is_current());
        assert!(store.lease_snapshot(&key, &before).is_none());
        let hj_pagecache::EntryState::Fresh(after) =
            store.get_entry_uncounted(&key, "memo-test", Instant::now())
        else {
            panic!("fresh successor");
        };
        let successor = store.lease_snapshot(&key, &after).unwrap();
        assert!(successor.is_current());
        drop(store);
        assert!(!successor.is_current());
    }

    #[test]
    fn public_page_snapshot_leases_do_not_survive_concurrent_mutation_acknowledgement() {
        use std::sync::Barrier;

        let (store, page_key, original) = page_lease();
        let store = Arc::new(store);
        let hj_pagecache::EntryState::Fresh(template) =
            store.get_entry_uncounted(&page_key, "memo-test", Instant::now())
        else {
            panic!("fresh fixture");
        };
        // Retain old payload snapshots while repeatedly replacing their nodes.
        // Payload ownership must not keep an old permission to serve alive.
        let start = Barrier::new(5);
        let mut held = vec![original];
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                start.wait();
                for round in 0..128 {
                    assert!(store.store(page_key.clone(), template.as_ref().clone()));
                    match round % 4 {
                        0 => store.fill_variants(
                            &page_key,
                            "memo-test",
                            template.stored_at,
                            Vec::new(),
                            None,
                        ),
                        1 => store.invalidate_key(&page_key),
                        2 => {
                            store.purge_all();
                        }
                        _ => {}
                    }
                    std::thread::yield_now();
                }
                store.invalidate_key(&page_key);
            });
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        let mut leases = Vec::new();
                        for _ in 0..512 {
                            if let hj_pagecache::EntryState::Fresh(snapshot) =
                                store.get_entry_uncounted(&page_key, "memo-test", Instant::now())
                                && let Some(lease) = store.lease_snapshot(&page_key, &snapshot)
                            {
                                leases.push(lease);
                            }
                            std::thread::yield_now();
                        }
                        leases
                    })
                })
                .collect();
            writer.join().unwrap();
            for reader in readers {
                held.extend(reader.join().unwrap());
            }
        });
        assert!(held.iter().all(|lease| !lease.is_current()));
        assert!(store.lease_snapshot(&page_key, &template).is_none());
    }

    #[test]
    fn replays_stamp_a_fresh_date_in_place_and_keep_a_backend_date() {
        let now = Instant::now();
        let request = req(&[]);
        let cache = ua_cache();
        let undated = key("/undated", b"");
        store(&undated, Vec::new(), &resp(b"x"), now);
        let (hit, _) = probe(&undated, &request, &cache, now).unwrap();
        let names: Vec<_> = hit.headers().keys().map(|n| n.as_str()).collect();
        assert_eq!(
            names,
            ["content-type", "date"],
            "Date stays last, as stamp_date appends it"
        );
        assert_eq!(hit.headers()[http::header::DATE], hj_core::http_date_now());

        let dated = key("/dated", b"");
        let mut backend = resp(b"y");
        backend.headers_mut().insert(
            http::header::DATE,
            http::HeaderValue::from_static("Mon, 01 Jan 2024 00:00:00 GMT"),
        );
        store(&dated, Vec::new(), &backend, now);
        let (hit, _) = probe(&dated, &request, &cache, now).unwrap();
        assert_eq!(
            hit.headers()[http::header::DATE],
            "Mon, 01 Jan 2024 00:00:00 GMT"
        );
    }

    #[test]
    fn memo_cannot_outlive_consulted_policy_deadline() {
        let now = Instant::now();
        let deadline = now + std::time::Duration::from_millis(20);
        let key = key("/policy-deadline", b"");
        let request = req(&[]);
        let cache = ua_cache();
        store_until(&key, Vec::new(), &resp(b"public"), now, deadline);
        assert!(probe(&key, &request, &cache, now).is_some());
        assert!(probe(&key, &request, &cache, deadline).is_none());
        store_until(&key, Vec::new(), &resp(b"expired"), now, now);
        assert!(probe(&key, &request, &cache, now).is_none());
    }

    #[test]
    fn configuration_generation_never_replays_an_old_response() {
        let now = Instant::now();
        let request = req(&[]);
        let cache = ua_cache();
        let old = key("/generation", b"");
        store(&old, Vec::new(), &resp(b"old"), now);
        let mut next = key("/generation", b"");
        next.generation = 2;
        assert!(probe(&next, &request, &cache, now).is_none());
        store(&next, Vec::new(), &resp(b"new"), now);
        store(&old, Vec::new(), &resp(b"late old"), now);
        assert!(
            matches!(probe(&next, &request, &cache, now).unwrap().0.into_body(), Body::Full(bytes) if bytes.as_ref() == b"new")
        );
    }

    #[test]
    fn roundtrip_and_ttl() {
        let t0 = Instant::now();
        let r = req(&[]);
        let c = ua_cache();
        store(&key("/a", b""), Vec::new(), &resp(b"hello"), t0);
        let (hit, _) = probe(&key("/a", b""), &r, &c, t0).expect("fresh hit");
        assert_eq!(hit.status(), http::StatusCode::OK);
        assert_eq!(
            hit.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain"
        );
        match hit.body() {
            Body::Full(b) => assert_eq!(&b[..], b"hello"),
            _ => panic!("expected Full body"),
        }
        assert!(
            probe(&key("/a", b""), &r, &c, t0 + Duration::from_millis(1500)).is_none(),
            "expired entry must miss"
        );
    }

    #[test]
    fn native_memo_does_not_reuse_revoked_purge_or_response_epoch() {
        let now = Instant::now();
        let request = req(&[]);
        let ua = ua_cache();
        let before = key("/revoked", b"");
        store(&before, Vec::new(), &resp(b"old"), now);
        assert!(probe(&before, &request, &ua, now).is_some());
        let mut after = key("/revoked", b"");
        after.purge_epoch = 1;
        assert!(probe(&after, &request, &ua, now).is_none());
        after.purge_epoch = 0;
        after.response_epoch = Some("new-epoch");
        assert!(probe(&after, &request, &ua, now).is_none());
    }

    #[test]
    fn key_fields_isolate_entries() {
        let t0 = Instant::now();
        let r = req(&[]);
        let c = ua_cache();
        store(&key("/b", b""), Vec::new(), &resp(b"plain"), t0);
        assert!(
            probe(&key("/b", b"gzip"), &r, &c, t0).is_none(),
            "AE must key"
        );
        assert!(
            probe(&key("/c", b""), &r, &c, t0).is_none(),
            "path must key"
        );
        let mut k2 = key("/b", b"");
        k2.https = false;
        assert!(probe(&k2, &r, &c, t0).is_none(), "scheme must key");
        let mut k3 = key("/b", b"");
        k3.trusted_proxy = true;
        assert!(
            probe(&k3, &r, &c, t0).is_none(),
            "trusted-proxy bit must key (CF_SEND_ZSTD picks the codec by trust)"
        );
        let mut k4 = key("/b", b"");
        k4.host_src = HostSource::Authority;
        assert!(probe(&k4, &r, &c, t0).is_none(), "host source must key");
    }

    #[test]
    fn vary_header_absent_present_and_value_all_distinct() {
        let t0 = Instant::now();
        let c = ua_cache();
        let origin = http::HeaderName::from_static("origin");
        let none = req(&[]);
        let a = req(&[("origin", "https://a.test")]);
        let b = req(&[("origin", "https://b.test")]);
        store(
            &key("/v", b""),
            vec![vary_header(&none, origin.clone())],
            &resp(b"none"),
            t0,
        );
        store(
            &key("/v", b""),
            vec![vary_header(&a, origin.clone())],
            &resp(b"a"),
            t0,
        );
        let body = |r: Option<(Response, Option<crate::lscache::PublicResponseMemo>)>| match r
            .map(|(hit, _)| hit.into_body())
        {
            Some(Body::Full(b)) => b,
            _ => panic!("expected hit"),
        };
        assert_eq!(&body(probe(&key("/v", b""), &none, &c, t0))[..], b"none");
        assert_eq!(&body(probe(&key("/v", b""), &a, &c, t0))[..], b"a");
        assert!(
            probe(&key("/v", b""), &b, &c, t0).is_none(),
            "an unseen vary value must miss, never borrow a sibling variant"
        );
    }

    #[test]
    fn ua_class_keys_on_the_match_bitmap_not_the_string() {
        let t0 = Instant::now();
        let c = ua_cache();
        let rs = Arc::new(
            RuleSet::parse(
                "RewriteEngine On\n\
                 RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot)\n\
                 RewriteRule .* - [E=KNOWN_CRAWLER:1]",
            )
            .unwrap(),
        );
        assert!(rs.ua_classify_eligible());
        let bot = req(&[("user-agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")]);
        let bits = c.get_or_compute(&rs, &ua_for_classify(&bot));
        store(
            &key("/u", b""),
            vec![VaryItem::UaClass {
                rules: UaRules::Inline(rs.clone()),
                bits,
            }],
            &resp(b"bot"),
            t0,
        );
        let other_bot = req(&[(
            "user-agent",
            "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
        )]);
        assert!(
            probe(&key("/u", b""), &other_bot, &c, t0).is_some(),
            "a different UA string in the same class hits"
        );
        let browser = req(&[("user-agent", "Mozilla/5.0 Chrome/120")]);
        assert!(
            probe(&key("/u", b""), &browser, &c, t0).is_none(),
            "a UA outside the class misses"
        );
        assert!(
            probe(&key("/u", b""), &req(&[]), &c, t0).is_none(),
            "an absent UA classifies as \"\" — outside the class"
        );
    }

    #[test]
    fn variant_bucket_is_bounded_and_same_vary_replaces() {
        let t0 = Instant::now();
        let c = ua_cache();
        let name = http::HeaderName::from_static("origin");
        for i in 0..MAX_VARIANTS {
            let r = req(&[("origin", &format!("https://o{i}.test"))]);
            store(
                &key("/w", b""),
                vec![vary_header(&r, name.clone())],
                &resp(b"x"),
                t0,
            );
        }
        let first = req(&[("origin", "https://o0.test")]);
        assert!(probe(&key("/w", b""), &first, &c, t0).is_some());
        // Same vary-set again: replaced in place, still MAX_VARIANTS entries.
        store(
            &key("/w", b""),
            vec![vary_header(&first, name.clone())],
            &resp(b"y"),
            t0,
        );
        MEMO.with(|m| assert_eq!(m.borrow().count, MAX_VARIANTS));
        // One more distinct variant overflows the bucket: it is dropped wholesale.
        let extra = req(&[("origin", "https://extra.test")]);
        store(
            &key("/w", b""),
            vec![vary_header(&extra, name.clone())],
            &resp(b"z"),
            t0,
        );
        assert!(probe(&key("/w", b""), &first, &c, t0).is_none());
        assert!(probe(&key("/w", b""), &extra, &c, t0).is_some());
        MEMO.with(|m| assert_eq!(m.borrow().count, 1));
    }

    #[test]
    fn oversized_vary_value_never_stores() {
        let t0 = Instant::now();
        let c = ua_cache();
        let big = "x".repeat(MAX_VARY_VALUE + 1);
        let r = req(&[("origin", &big)]);
        store(
            &key("/big", b""),
            vec![vary_header(&r, http::HeaderName::from_static("origin"))],
            &resp(b"x"),
            t0,
        );
        assert!(probe(&key("/big", b""), &r, &c, t0).is_none());
    }

    #[test]
    fn byte_budget_clears_rather_than_grows() {
        let t0 = Instant::now();
        let r = req(&[]);
        let c = ua_cache();
        let big: &'static [u8] = Box::leak(vec![7u8; MAX_BODY].into_boxed_slice());
        let big_resp = || http::Response::new(Body::Full(Bytes::from_static(big)));
        let n = MAX_BYTES / MAX_BODY;
        let paths: Vec<String> = (0..=n).map(|i| format!("/budget/{i}")).collect();
        for p in &paths[..n] {
            store(&key(p, b""), Vec::new(), &big_resp(), t0);
        }
        assert!(
            probe(&key(&paths[0], b""), &r, &c, t0).is_some(),
            "budget full, all kept"
        );
        // One more store exceeds MAX_BYTES: the map clears instead of growing.
        store(&key(&paths[n], b""), Vec::new(), &big_resp(), t0);
        assert!(
            probe(&key(&paths[0], b""), &r, &c, t0).is_none(),
            "cleared on overflow"
        );
        assert!(
            probe(&key(&paths[n], b""), &r, &c, t0).is_some(),
            "new entry kept"
        );
        MEMO.with(|m| {
            let m = m.borrow();
            assert_eq!(m.bytes, MAX_BODY, "accounting reset with the clear");
            assert_eq!(m.count, 1);
        });
    }

    /// (count, bytes, buckets, queued reclaim records) of this thread's memo.
    fn accounting() -> (usize, usize, usize, usize) {
        MEMO.with(|m| {
            let m = m.borrow();
            (m.count, m.bytes, m.map.len(), m.expiry.len())
        })
    }

    #[test]
    fn a_store_past_the_ttl_reclaims_expired_entries() {
        let t0 = Instant::now();
        let dead = b"dead body";
        for i in 0..RECLAIM_BATCH {
            store(
                &key(&format!("/burst/{i}"), b""),
                Vec::new(),
                &resp(dead),
                t0,
            );
        }
        let n = RECLAIM_BATCH;
        assert_eq!(accounting(), (n, n * dead.len(), n, n));
        let later = t0 + TTL + Duration::from_millis(1);
        store(&key("/live", b""), Vec::new(), &resp(b"live"), later);
        assert_eq!(
            accounting(),
            (1, 4, 1, 1),
            "only the live entry stays accounted"
        );
        assert!(probe(&key("/live", b""), &req(&[]), &ua_cache(), later).is_some());
    }

    #[test]
    fn reclaim_is_bounded_per_call_and_runs_on_probes() {
        let t0 = Instant::now();
        let n = 3 * RECLAIM_BATCH + 1;
        for i in 0..n {
            store(&key(&format!("/b/{i}"), b""), Vec::new(), &resp(b"x"), t0);
        }
        let r = req(&[]);
        let c = ua_cache();
        let later = t0 + TTL;
        assert!(probe(&key("/absent", b""), &r, &c, later).is_none());
        let left = n - RECLAIM_BATCH;
        assert_eq!(accounting(), (left, left, left, left));
        for _ in 0..3 {
            assert!(probe(&key("/absent", b""), &r, &c, later).is_none());
        }
        assert_eq!(accounting(), (0, 0, 0, 0));
    }

    #[test]
    fn reclaim_never_drops_a_live_entry() {
        let t0 = Instant::now();
        let r = req(&[]);
        let c = ua_cache();
        store(&key("/r", b""), Vec::new(), &resp(b"old"), t0);
        let t1 = t0 + Duration::from_millis(600);
        // Replaced in place: the first record now names a live successor.
        store(&key("/r", b""), Vec::new(), &resp(b"new"), t1);
        store(&key("/s", b""), Vec::new(), &resp(b"s"), t1);
        let t2 = t0 + TTL + Duration::from_millis(1);
        store(&key("/t", b""), Vec::new(), &resp(b"t"), t2);
        assert_eq!(accounting(), (3, 5, 3, 3));
        assert!(
            matches!(probe(&key("/r", b""), &r, &c, t2).map(|(hit, _)| hit.into_body()), Some(Body::Full(b)) if b.as_ref() == b"new")
        );
        assert!(probe(&key("/s", b""), &r, &c, t2).is_some());
    }

    #[test]
    fn reclaim_queue_is_bounded() {
        let t0 = Instant::now();
        for _ in 0..MAX_QUEUED {
            store(&key("/q", b""), Vec::new(), &resp(b"q"), t0);
        }
        assert_eq!(accounting(), (1, 1, 1, MAX_QUEUED));
        store(&key("/q", b""), Vec::new(), &resp(b"q"), t0);
        assert_eq!(
            accounting(),
            (1, 1, 1, 1),
            "an overfull queue clears like the caps"
        );
    }

    #[test]
    fn streaming_bodies_never_stored() {
        let t0 = Instant::now();
        let r = http::Response::new(Body::Empty);
        store(&key("/d", b""), Vec::new(), &r, t0);
        assert!(probe(&key("/d", b""), &req(&[]), &ua_cache(), t0).is_none());
    }
}
