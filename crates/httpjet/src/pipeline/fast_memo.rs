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
//! pure function of the memo key (listener, scheme, vhost, raw Host, raw
//! path?query, Accept-Encoding). The store site enforces that with:
//! * request gates — GET, no `Cookie`/`Range`/`If-*`/`Authorization`;
//! * chain gates — every `.htaccess` in the loaded chain has NO `SetEnvIf`, NO
//!   access rules (they may depend on client IP, which is not keyed), and a
//!   rewrite `RuleSet` that is `path_cacheable` with no `cache_key_vars` and
//!   no `assumed_empty_env` (same classification the rewrite-outcome cache
//!   trusts); the vhost inline ruleset must satisfy the same predicate.
//!   `Header` directives conditional on env/`<If>` are covered: this engine
//!   models those conditions on URI/env only, and under the gates above env is
//!   itself a pure function of the key;
//! * response gates — status 200, in-memory `Body::Full`, no `Set-Cookie`.
//! `Date` is appended at protocol serialization (not stored), `X-Request-Id`
//! is re-applied per hit by `record_fast_serve`, and per-hit logging/metrics
//! stay live (hits go through the same observability funnel as every serve).

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hj_core::{Body, Response};

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

/// Kill switch, default ON. `main` clears it for `--no-fast-memo` or env
/// `HJ_FAST_MEMO=0` BEFORE any listener accepts, so a relaxed load is fine.
pub(crate) static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub(super) fn enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

pub(super) struct MemoKey<'a> {
    pub listener: &'a str,
    pub https: bool,
    pub vhost: &'a str,
    pub host: &'a [u8],
    pub path: &'a str,
    pub query: &'a str,
    pub ae: &'a [u8],
    /// Injective encoding of the request values of every keyable dynamic var
    /// the vhost's inline ruleset reads (see [`keyvar_fold`]). Empty when the
    /// ruleset reads none.
    pub vars: Vec<u8>,
}

/// Fold the request values of the inline ruleset's keyable vars (UA / Origin /
/// Accept — the same allowlist the rewrite-outcome cache keys on) into an
/// injective byte string: per var, a tag byte, then absent (0xFF) or a
/// length-prefixed raw first header value. The chain gate at the store site
/// still requires `.htaccess` rulesets to read NO keyable vars, so the inline
/// set — available identically at probe and store time — is the only source.
pub(super) fn keyvar_fold(vars: &[hj_rewrite::CacheKeyVar], req: &hj_core::Request) -> Vec<u8> {
    let mut out = Vec::new();
    for v in vars {
        let (tag, name) = match v {
            hj_rewrite::CacheKeyVar::UserAgent => (b'u', "user-agent"),
            hj_rewrite::CacheKeyVar::Origin => (b'o', "origin"),
            hj_rewrite::CacheKeyVar::Accept => (b'a', "accept"),
        };
        out.push(tag);
        match req.headers().get(name) {
            None => out.push(0xFF),
            Some(val) => {
                let b = val.as_bytes();
                out.push(0x00);
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
        }
    }
    out
}

struct MemoEntry {
    listener: String,
    https: bool,
    vhost: String,
    host: Vec<u8>,
    path: String,
    query: String,
    ae: Vec<u8>,
    vars: Vec<u8>,
    status: http::StatusCode,
    headers: http::HeaderMap,
    body: Bytes,
    stored: Instant,
}

#[derive(Default)]
struct Memo {
    map: HashMap<u64, MemoEntry>,
    /// Sum of `body.len()` across `map` (the [`MAX_BYTES`] budget).
    bytes: usize,
}

thread_local! {
    static MEMO: RefCell<Memo> = RefCell::new(Memo::default());
}

fn key_hash(k: &MemoKey) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    k.listener.hash(&mut h);
    k.https.hash(&mut h);
    k.vhost.hash(&mut h);
    k.host.hash(&mut h);
    k.path.hash(&mut h);
    k.query.hash(&mut h);
    k.ae.hash(&mut h);
    k.vars.hash(&mut h);
    h.finish()
}

/// Identity guard (page-cache rule 2): a hash collision degrades to a miss,
/// never a wrong response.
fn matches(e: &MemoEntry, k: &MemoKey) -> bool {
    e.https == k.https
        && e.listener == k.listener
        && e.vhost == k.vhost
        && e.host == k.host
        && e.path == k.path
        && e.query == k.query
        && e.ae == k.ae
        && e.vars == k.vars
}

pub(super) fn probe(k: &MemoKey, now: Instant) -> Option<Response> {
    let h = key_hash(k);
    MEMO.with(|m| {
        let mut m = m.borrow_mut();
        let expired = match m.map.get(&h) {
            None => return None,
            Some(e) => {
                if !matches(e, k) {
                    return None;
                }
                now.duration_since(e.stored) > TTL
            }
        };
        if expired {
            if let Some(e) = m.map.remove(&h) {
                m.bytes -= e.body.len();
            }
            return None;
        }
        let e = m.map.get(&h).unwrap();
        let mut resp = http::Response::new(Body::Full(e.body.clone()));
        *resp.status_mut() = e.status;
        *resp.headers_mut() = e.headers.clone();
        Some(resp)
    })
}

pub(super) fn store(k: &MemoKey, resp: &Response, now: Instant) {
    let Body::Full(body) = resp.body() else {
        return;
    };
    if body.len() > MAX_BODY {
        return;
    }
    let h = key_hash(k);
    let entry = MemoEntry {
        listener: k.listener.to_owned(),
        https: k.https,
        vhost: k.vhost.to_owned(),
        host: k.host.to_owned(),
        path: k.path.to_owned(),
        query: k.query.to_owned(),
        ae: k.ae.to_owned(),
        vars: k.vars.clone(),
        status: resp.status(),
        headers: resp.headers().clone(),
        body: body.clone(),
        stored: now,
    };
    MEMO.with(|m| {
        let mut m = m.borrow_mut();
        if m.map.len() >= MAX_ENTRIES || m.bytes + entry.body.len() > MAX_BYTES {
            m.map.clear();
            m.bytes = 0;
        }
        m.bytes += entry.body.len();
        if let Some(old) = m.map.insert(h, entry) {
            m.bytes -= old.body.len();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key<'a>(path: &'a str, ae: &'a [u8]) -> MemoKey<'a> {
        MemoKey {
            listener: "l1",
            https: true,
            vhost: "v",
            host: b"v",
            path,
            query: "",
            ae,
            vars: Vec::new(),
        }
    }

    fn resp(body: &'static [u8]) -> Response {
        let mut r = http::Response::new(Body::Full(Bytes::from_static(body)));
        r.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain"),
        );
        r
    }

    #[test]
    fn roundtrip_and_ttl() {
        let t0 = Instant::now();
        store(&key("/a", b""), &resp(b"hello"), t0);
        let hit = probe(&key("/a", b""), t0).expect("fresh hit");
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
            probe(&key("/a", b""), t0 + Duration::from_millis(1500)).is_none(),
            "expired entry must miss"
        );
    }

    #[test]
    fn key_fields_isolate_entries() {
        let t0 = Instant::now();
        store(&key("/b", b""), &resp(b"plain"), t0);
        assert!(probe(&key("/b", b"gzip"), t0).is_none(), "AE must key");
        assert!(probe(&key("/c", b""), t0).is_none(), "path must key");
        let mut k2 = key("/b", b"");
        k2.https = false;
        assert!(probe(&k2, t0).is_none(), "scheme must key");
    }

    #[test]
    fn byte_budget_clears_rather_than_grows() {
        let t0 = Instant::now();
        let big: &'static [u8] = Box::leak(vec![7u8; MAX_BODY].into_boxed_slice());
        let big_resp = || http::Response::new(Body::Full(Bytes::from_static(big)));
        let n = MAX_BYTES / MAX_BODY;
        let paths: Vec<String> = (0..=n).map(|i| format!("/budget/{i}")).collect();
        for p in &paths[..n] {
            store(&key(p, b""), &big_resp(), t0);
        }
        assert!(
            probe(&key(&paths[0], b""), t0).is_some(),
            "budget full, all kept"
        );
        // One more store exceeds MAX_BYTES: the map clears instead of growing.
        store(&key(&paths[n], b""), &big_resp(), t0);
        assert!(
            probe(&key(&paths[0], b""), t0).is_none(),
            "cleared on overflow"
        );
        assert!(probe(&key(&paths[n], b""), t0).is_some(), "new entry kept");
        MEMO.with(|m| {
            let m = m.borrow();
            assert_eq!(m.bytes, MAX_BODY, "accounting reset with the clear");
        });
    }

    #[test]
    fn streaming_bodies_never_stored() {
        let t0 = Instant::now();
        let r = http::Response::new(Body::Empty);
        store(&key("/d", b""), &r, t0);
        assert!(probe(&key("/d", b""), t0).is_none());
    }
}
