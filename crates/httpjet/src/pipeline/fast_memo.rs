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
use std::collections::HashMap;
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
const MAX_BODY: usize = 1024 * 1024;
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
    None,
}

pub(super) struct MemoKey<'a> {
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
    body: Bytes,
    stored: Instant,
}

#[derive(Default)]
struct Memo {
    /// Base-key hash → the variants (distinct vary-sets) stored under it.
    map: HashMap<u64, Vec<MemoEntry>>,
    /// Sum of `body.len()` across every variant (the [`MAX_BYTES`] budget).
    bytes: usize,
    /// Number of variants across `map` (the [`MAX_ENTRIES`] cap).
    count: usize,
}

thread_local! {
    static MEMO: RefCell<Memo> = RefCell::new(Memo::default());
}

fn key_hash(k: &MemoKey) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
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
    e.https == k.https
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
) -> Option<Response> {
    let h = key_hash(k);
    MEMO.with(|m| {
        let mut m = m.borrow_mut();
        let Memo { map, bytes, count } = &mut *m;
        let empty = {
            let bucket = map.get_mut(&h)?;
            bucket.retain(|e| {
                let live = now.duration_since(e.stored) <= TTL;
                if !live {
                    *bytes -= e.body.len();
                    *count -= 1;
                }
                live
            });
            bucket.is_empty()
        };
        if empty {
            map.remove(&h);
            return None;
        }
        let e = map
            .get(&h)?
            .iter()
            .find(|e| matches(e, k) && e.vary.iter().all(|v| v.matches(req, ua_cache)))?;
        let mut resp = http::Response::new(Body::Full(e.body.clone()));
        *resp.status_mut() = e.status;
        *resp.headers_mut() = e.headers.clone();
        Some(resp)
    })
}

pub(super) fn store(k: &MemoKey, vary: Vec<VaryItem>, resp: &Response, now: Instant) {
    let Body::Full(body) = resp.body() else {
        return;
    };
    if body.len() > MAX_BODY {
        return;
    }
    if vary
        .iter()
        .any(|v| matches!(v, VaryItem::Header { value: Some(b), .. } if b.len() > MAX_VARY_VALUE))
    {
        return;
    }
    let h = key_hash(k);
    let entry = MemoEntry {
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
        headers: resp.headers().clone(),
        body: body.clone(),
        stored: now,
    };
    MEMO.with(|m| {
        let mut m = m.borrow_mut();
        if m.count >= MAX_ENTRIES || m.bytes + entry.body.len() > MAX_BYTES {
            m.map.clear();
            m.bytes = 0;
            m.count = 0;
        }
        let Memo { map, bytes, count } = &mut *m;
        let bucket = map.entry(h).or_default();
        if let Some(i) = bucket
            .iter()
            .position(|e| matches(e, k) && vary_same(&e.vary, &entry.vary))
        {
            *bytes -= bucket[i].body.len();
            *bytes += entry.body.len();
            bucket[i] = entry;
            return;
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
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key<'a>(path: &'a str, ae: &'a [u8]) -> MemoKey<'a> {
        MemoKey {
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

    #[test]
    fn roundtrip_and_ttl() {
        let t0 = Instant::now();
        let r = req(&[]);
        let c = ua_cache();
        store(&key("/a", b""), Vec::new(), &resp(b"hello"), t0);
        let hit = probe(&key("/a", b""), &r, &c, t0).expect("fresh hit");
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
        let body = |r: Option<Response>| match r.map(Response::into_body) {
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

    #[test]
    fn streaming_bodies_never_stored() {
        let t0 = Instant::now();
        let r = http::Response::new(Body::Empty);
        store(&key("/d", b""), Vec::new(), &r, t0);
        assert!(probe(&key("/d", b""), &req(&[]), &ua_cache(), t0).is_none());
    }
}
