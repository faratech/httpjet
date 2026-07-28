//! (OPS3) Cross-node page-cache purge coherence.
//!
//! httpjet runs as an active-active pair; each node has its OWN in-RAM page
//! cache. An `X-LiteSpeed-Purge` only reaches the node that served the
//! originating write request, so without propagation the peer keeps serving
//! stale pages until TTL. This module FORWARDS each acted-on purge to the
//! configured peer(s) and ACCEPTS inbound peer purges — **on the node's
//! existing `:80` listener**, not a dedicated port: a reserved request path is
//! intercepted at the very top of the pipeline (before vhost routing / the
//! mTLS gate), so there is no new socket and no firewall change.
//!
//! Double-gated: (1) the reserved request path, (2) the RAW TCP peer-IP must be a
//! CONFIGURED peer (`--cache-peer`) or loopback (for a local ops purge). This is
//! un-spoofable over TCP (it is the immediate connection source, not the XFF /
//! CF-resolved client IP), and is a NARROW allow-list — a configured peer or
//! `127.0.0.1`/`::1`, NOT any private-range address (a shared VPC/subnet can hold
//! untrusted hosts). A request arriving via Cloudflare has peer = the CF edge's
//! PUBLIC IP, fails the gate, and falls through to normal handling (a plain 404) —
//! the endpoint is invisible to anything but the configured interconnect. There is
//! **no shared secret**: the configured peer set IS the trust boundary.
//!
//! Loop-free by construction: only `lscache::cache_store` (the response path
//! that saw the backend's purge header) calls [`PurgeForwarder::forward`]; an
//! inbound purge is applied LOCALLY and never re-forwarded. Purges are
//! idempotent, so a redundant delivery (e.g. the app also fans out) is a no-op.
//!
//! Transport: plaintext HTTP/1.1 over the private interconnect, in the
//! minimalist style of the metrics listener (no HTTP-client dependency).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use hj_core::{Body, Request, Response};
use hj_pagecache::{PageCacheKey, Purge, parse_purge};

use crate::state::ServerState;
use crate::telemetry::PeerFetchEvent;

/// Reserved request path for a cross-node purge (POSTed to the peer's `:80`).
pub const PURGE_PATH: &str = "/__hj_cache_purge";
/// (peer-fetch) Reserved request path for a cross-node cache FILL: a node that
/// missed locally asks the peer for the entry instead of rendering. The serialized
/// key travels in the `FETCH_KEY_HEADER` (so the inbound handler stays sync — no
/// async body read); the response body is the entry's HJPC bytes, or 404.
pub const FETCH_PATH: &str = "/__hj_cache_get";
/// Header carrying the hex-encoded serialized `(PageCacheKey, identity)` to fetch.
const FETCH_KEY_HEADER: &str = "x-hj-cache-key";
/// Per-peer consecutive-failure count that trips the circuit breaker.
const FETCH_FAIL_THRESHOLD: u32 = 3;
/// How long a tripped peer is skipped before one trial fetch is allowed again.
const FETCH_COOLDOWN: Duration = Duration::from_secs(5);
/// Default negative-cache TTL: how long a key the peer just 404'd is skipped (no
/// round-trip) before we re-ask. Overridable via `--cache-peer-fill-negcache-secs`.
const PEER_MISS_TTL: Duration = Duration::from_secs(10);
/// Hard cap on negative-cache entries (a key-hash flood can't grow it unbounded).
const NEG_CACHE_MAX: usize = 100_000;
/// Max idle keep-alive connections kept per peer.
const POOL_MAX_IDLE: usize = 8;
/// Discard a pooled connection idle longer than this (peers close idle sockets).
const POOL_IDLE_MAX_AGE: Duration = Duration::from_secs(30);
/// Reserved request path for a page-cache readiness probe (loopback/peer only): 200 once the boot
/// warm-scan has finished, 503 while still warming. Lets an ops check or the restart-persistence
/// gate wait for warm-up WITHOUT probing a real URL — a probe during the scan window misses,
/// re-primes the key, wins `load_scanned`'s tie-break, and UNLINKS the persisted entry under test.
pub const READY_PATH: &str = "/__hj_cache_ready";
/// Header carrying the raw `X-LiteSpeed-Purge` directive being propagated.
const PURGE_HEADER: &str = "x-litespeed-purge";
/// Per-peer forward budget — best-effort, must never delay the response path.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

/// Cross-node purge configuration, shared (behind the `ServerState` `Arc`).
/// Built whenever `--page-cache` is on — with NO `--cache-peer` it still exists
/// in loopback-only mode (the documented local ops purge; `forward` is then a
/// no-op over zero peers). Gating its construction on having a peer silently
/// killed the loopback purge on single-node setups: the POST fell through to
/// the backend as a normal request. `Clone` is cheap (a `Vec` + `HashSet` of
/// addrs) and lets a SIGHUP reload carry it into the next config generation.
#[derive(Clone)]
pub struct PurgeForwarder {
    /// Peers to forward acted-on purges to (their existing `host:80`).
    peers: Vec<SocketAddr>,
    /// Raw TCP source IPs allowed to PUSH purges to us: the configured peers'
    /// IPs (canonicalized so an IPv4-mapped form matches). Loopback is additionally
    /// accepted via `is_loopback()` for a local ops purge.
    allowed: HashSet<IpAddr>,
    /// (peer-fetch) Whether cross-node cache FILL on a local miss is enabled
    /// (`--cache-peer-fill`). OFF by default — deploying the binary is a no-op
    /// until an operator turns it on per node.
    fill_enabled: bool,
    /// (peer-fetch) Budget for one peer fetch — it is on the request latency path,
    /// so it must be SHORT; a slow/down peer falls through to a local render.
    fetch_timeout: Duration,
    /// (peer-fetch) Per-peer circuit breaker so a down/slow peer is skipped fast.
    health: Arc<Mutex<HashMap<SocketAddr, PeerHealth>>>,
    /// (peer-fetch, Part A) Negative cache of recently peer-MISSED key hashes →
    /// skip-until. A key the peer just 404'd is skipped (no round-trip) for `neg_ttl`,
    /// killing the wasted RTT on the long-tail/uncacheable keys that dominate misses.
    neg_cache: Arc<Mutex<HashMap<u64, Instant>>>,
    /// (peer-fetch, Part A) Negative-cache TTL (`--cache-peer-fill-negcache-secs`).
    neg_ttl: Duration,
    /// (peer-fetch, Part B) Idle keep-alive connections per peer, so a fetch reuses a
    /// socket instead of paying a fresh TCP-connect RTT every time.
    pool: Arc<Mutex<HashMap<SocketAddr, Vec<PooledConn>>>>,
}

#[derive(Default)]
struct PeerHealth {
    consecutive_failures: u32,
    skip_until: Option<Instant>,
}

/// An idle keep-alive connection to a peer, stamped so a too-old one is discarded.
struct PooledConn {
    stream: TcpStream,
    since: Instant,
}

impl PurgeForwarder {
    fn new(peers: Vec<SocketAddr>) -> Self {
        let allowed = peers.iter().map(|a| a.ip().to_canonical()).collect();
        Self {
            peers,
            allowed,
            fill_enabled: false,
            fetch_timeout: Duration::from_millis(50),
            health: Arc::new(Mutex::new(HashMap::new())),
            neg_cache: Arc::new(Mutex::new(HashMap::new())),
            neg_ttl: PEER_MISS_TTL,
            pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// (peer-fetch) Enable cross-node fill and set the per-fetch timeout (ms; 0 keeps
    /// the default) + negative-cache TTL (secs; 0 keeps the default). Called once at
    /// construction from `--cache-peer-fill`.
    pub fn with_fill(mut self, enabled: bool, timeout_ms: u64, negcache_secs: u64) -> Self {
        self.fill_enabled = enabled;
        if timeout_ms > 0 {
            self.fetch_timeout = Duration::from_millis(timeout_ms);
        }
        if negcache_secs > 0 {
            self.neg_ttl = Duration::from_secs(negcache_secs);
        }
        self
    }

    /// Whether cross-node fill is enabled (the pipeline gate).
    pub fn fill_enabled(&self) -> bool {
        self.fill_enabled
    }

    /// Build from CLI config. Always purge-capable from loopback; cross-node
    /// forwarding only for the `--cache-peer`s that resolve (a peer list that is
    /// absent or fully unresolvable degrades to loopback-only, errors logged —
    /// never to a dead endpoint). Inbound purges are authenticated by the narrow
    /// peer-IP allow-list (configured peers + loopback); no secret is required.
    pub fn from_config(peers_arg: &[String]) -> Self {
        let mut peers = Vec::new();
        for p in peers_arg {
            match p.to_socket_addrs() {
                Ok(mut it) => match it.next() {
                    Some(addr) => peers.push(addr),
                    None => tracing::error!(peer = %p, "--cache-peer resolved to no address"),
                },
                Err(e) => tracing::error!(error = %e, peer = %p, "invalid --cache-peer"),
            }
        }
        Self::new(peers)
    }

    /// The configured peer addresses (for the startup log line).
    pub fn peer_addrs(&self) -> &[SocketAddr] {
        &self.peers
    }

    /// Pipeline hook: if `req` is an inbound peer purge from a configured peer (or
    /// loopback), apply it locally and return the ack response; otherwise `None`
    /// (the caller falls through to normal request handling). Called at the top of
    /// `handle()`, so the per-request cost for normal traffic is a single path
    /// comparison.
    ///
    /// `peer_ip` MUST be the raw TCP peer (not the XFF-resolved client IP) — it is
    /// the sole authenticator, so an attacker-controlled forwarded header must
    /// never reach it.
    pub fn handle_inbound(
        &self,
        req: &Request,
        peer_ip: IpAddr,
        state: &Arc<ServerState>,
    ) -> Option<Response> {
        let path = req.uri().path();
        // Readiness probe: same narrow source gate as the purge endpoint (loopback / configured
        // peer), invisible to anyone else. 200 once the boot warm-scan is done, 503 while warming.
        if path == READY_PATH {
            if !source_trusted(peer_ip, &self.allowed) {
                return None; // untrusted source → normal handling (404), endpoint stays invisible
            }
            let (warm, loaded) = state
                .page_cache
                .as_ref()
                .map(|pc| (pc.is_warm(), pc.scan_loaded()))
                .unwrap_or((true, 0));
            return Some(ready_ack(warm, loaded));
        }
        // (peer-fetch) Inbound cross-node FILL request: same narrow source gate. The
        // serialized (key, identity) is in a header (sync-readable); we look up the
        // LOCAL store only (never recurse to a peer → loop-free) and return the
        // entry's HJPC bytes (200) or 404. Invisible to any untrusted source.
        if path == FETCH_PATH {
            if !source_trusted(peer_ip, &self.allowed) {
                return None;
            }
            let Some(store) = state.page_cache.as_ref() else {
                return Some(ack(StatusCode::NOT_FOUND));
            };
            let parsed = req
                .headers()
                .get(FETCH_KEY_HEADER)
                .and_then(|v| v.to_str().ok())
                .and_then(from_hex)
                .and_then(|b| deserialize_key(&b));
            let Some((key, identity)) = parsed else {
                return Some(ack(StatusCode::BAD_REQUEST));
            };
            return Some(match store.serialize_entry(&key, &identity) {
                Some(bytes) => fetch_body_response(bytes),
                None => ack(StatusCode::NOT_FOUND),
            });
        }
        let directive = req
            .headers()
            .get(PURGE_HEADER)
            .and_then(|v| v.to_str().ok());
        match classify(path, peer_ip, &self.allowed, directive) {
            Verdict::Passthrough => None,
            Verdict::BadRequest => Some(ack(StatusCode::BAD_REQUEST)),
            Verdict::Apply(purge) => {
                if let Some(store) = state.page_cache.as_ref() {
                    match purge {
                        Purge::All => store.purge_all(),
                        Purge::Tags(tags) => {
                            let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
                            store.purge_tags(&refs);
                        }
                    }
                    state
                        .metrics
                        .purges_received
                        .fetch_add(1, Ordering::Relaxed);
                }
                Some(ack(StatusCode::NO_CONTENT))
            }
        }
    }

    /// Best-effort fan-out of a raw `X-LiteSpeed-Purge` directive to every peer.
    /// One detached task per peer so it never blocks the response path; outcomes
    /// are counted + logged, never surfaced to the client. Called ONLY from
    /// `cache_store` (loop-free: inbound purges do not re-forward).
    pub fn forward(&self, directive: &str, state: &Arc<ServerState>) {
        let directive = directive.trim().to_string();
        if directive.is_empty() {
            return;
        }
        for &peer in &self.peers {
            let directive = directive.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let res = tokio::time::timeout(FORWARD_TIMEOUT, send_purge(peer, &directive)).await;
                match res {
                    Ok(Ok(())) => {
                        state
                            .metrics
                            .purges_forwarded
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(e)) => {
                        state
                            .metrics
                            .purge_forward_failures
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%peer, error = %e, "peer purge forward failed");
                    }
                    Err(_) => {
                        state
                            .metrics
                            .purge_forward_failures
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%peer, "peer purge forward timed out");
                    }
                }
            });
        }
    }

    /// (peer-fetch) Try to fill a local miss from a peer. Returns the entry's HJPC
    /// bytes on a peer HIT, else `None` (disabled / negative-cached / peer miss / down).
    /// `key_hash` keys the negative cache; `key_blob_hex` is the hex-encoded serialized
    /// `(key, identity)`. SHORT timeout + per-peer circuit breaker + negative cache —
    /// this is on the request latency path, so a slow/down/empty peer must never delay
    /// the local render, and a key the peer recently lacked is skipped with NO round-trip.
    pub async fn fetch(
        &self,
        key_hash: u64,
        key_blob_hex: &str,
        state: &Arc<ServerState>,
    ) -> Option<Vec<u8>> {
        if !self.fill_enabled || self.peers.is_empty() {
            return None;
        }
        // (Part A) The peer recently 404'd this key — skip the round-trip and render.
        if self.neg_cached(key_hash) {
            state
                .metrics
                .peer_fetch_skipped
                .fetch_add(1, Ordering::Relaxed);
            state.telemetry.record_peer_fetch(PeerFetchEvent::Skipped);
            return None;
        }
        state
            .metrics
            .peer_fetch_attempts
            .fetch_add(1, Ordering::Relaxed);
        state.telemetry.record_peer_fetch(PeerFetchEvent::Attempt);
        let mut saw_404 = false;
        for &peer in &self.peers {
            if self.peer_tripped(peer) {
                continue;
            }
            match tokio::time::timeout(self.fetch_timeout, self.send_fetch(peer, key_blob_hex))
                .await
            {
                Ok(Ok(Some(bytes))) => {
                    self.peer_ok(peer);
                    self.neg_clear(key_hash); // serveable again
                    state
                        .metrics
                        .peer_fetch_hits
                        .fetch_add(1, Ordering::Relaxed);
                    state.telemetry.record_peer_fetch(PeerFetchEvent::Hit);
                    return Some(bytes);
                }
                Ok(Ok(None)) => {
                    // Peer reachable but doesn't have it — not a failure.
                    self.peer_ok(peer);
                    saw_404 = true;
                }
                Ok(Err(_)) | Err(_) => {
                    self.peer_failed(peer);
                    state
                        .metrics
                        .peer_fetch_failures
                        .fetch_add(1, Ordering::Relaxed);
                    state.telemetry.record_peer_fetch(PeerFetchEvent::Failure);
                }
            }
        }
        // Negative-cache only on a genuine peer-404 (reachable, no entry) — NOT on a
        // transport failure (the breaker handles a down peer; the key may exist once it
        // recovers, so don't suppress future fetches for it).
        if saw_404 {
            self.neg_insert(key_hash);
        }
        state
            .metrics
            .peer_fetch_misses
            .fetch_add(1, Ordering::Relaxed);
        state.telemetry.record_peer_fetch(PeerFetchEvent::Miss);
        None
    }

    /// (Part A) Whether `key_hash` is currently negative-cached (peer recently 404'd it).
    fn neg_cached(&self, key_hash: u64) -> bool {
        let m = self.neg_cache.lock().unwrap();
        matches!(m.get(&key_hash), Some(&until) if Instant::now() < until)
    }

    fn neg_insert(&self, key_hash: u64) {
        let now = Instant::now();
        let mut m = self.neg_cache.lock().unwrap();
        if m.len() >= NEG_CACHE_MAX {
            m.retain(|_, until| *until > now); // drop expired first
            if m.len() >= NEG_CACHE_MAX {
                m.clear(); // pathological flood: reset rather than grow unbounded
            }
        }
        m.insert(key_hash, now + self.neg_ttl);
    }

    fn neg_clear(&self, key_hash: u64) {
        self.neg_cache.lock().unwrap().remove(&key_hash);
    }

    /// (Part B) Fetch from one peer, reusing a pooled keep-alive socket when available.
    /// On any error with a REUSED socket, retries ONCE with a fresh connect so a stale
    /// pooled connection can never turn a real peer-hit into a spurious miss.
    async fn send_fetch(
        &self,
        peer: SocketAddr,
        key_blob_hex: &str,
    ) -> std::io::Result<Option<Vec<u8>>> {
        if let Some(stream) = self.pool_checkout(peer) {
            if let Ok((result, reusable)) = fetch_over(stream, &peer, key_blob_hex).await {
                if let Some(s) = reusable {
                    self.pool_return(peer, s);
                }
                return Ok(result);
            }
            // Stale/broken pooled conn — fall through to a fresh connect.
        }
        let stream = TcpStream::connect(peer).await?;
        let (result, reusable) = fetch_over(stream, &peer, key_blob_hex).await?;
        if let Some(s) = reusable {
            self.pool_return(peer, s);
        }
        Ok(result)
    }

    /// Pop a still-fresh idle connection for `peer` (discarding any too-old to reuse).
    fn pool_checkout(&self, peer: SocketAddr) -> Option<TcpStream> {
        let now = Instant::now();
        let mut p = self.pool.lock().unwrap();
        let v = p.get_mut(&peer)?;
        while let Some(c) = v.pop() {
            if now.duration_since(c.since) < POOL_IDLE_MAX_AGE {
                return Some(c.stream);
            }
        }
        None
    }

    /// Return a clean (read-to-boundary, keep-alive) connection to the idle pool.
    fn pool_return(&self, peer: SocketAddr, stream: TcpStream) {
        let mut p = self.pool.lock().unwrap();
        let v = p.entry(peer).or_default();
        if v.len() < POOL_MAX_IDLE {
            v.push(PooledConn {
                stream,
                since: Instant::now(),
            });
        }
    }

    fn peer_tripped(&self, peer: SocketAddr) -> bool {
        let mut h = self.health.lock().unwrap();
        let e = h.entry(peer).or_default();
        match e.skip_until {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                e.skip_until = None; // cooldown elapsed: allow one trial
                false
            }
            None => false,
        }
    }

    fn peer_ok(&self, peer: SocketAddr) {
        let mut h = self.health.lock().unwrap();
        let e = h.entry(peer).or_default();
        e.consecutive_failures = 0;
        e.skip_until = None;
    }

    fn peer_failed(&self, peer: SocketAddr) {
        let mut h = self.health.lock().unwrap();
        let e = h.entry(peer).or_default();
        e.consecutive_failures = e.consecutive_failures.saturating_add(1);
        if e.consecutive_failures >= FETCH_FAIL_THRESHOLD {
            e.skip_until = Some(Instant::now() + FETCH_COOLDOWN);
        }
    }
}

/// (peer-fetch) Serialize `(key, identity)` to the hex blob carried in the fetch
/// request header. Public so the lscache miss path can build the request.
pub fn serialize_fetch_key(key: &PageCacheKey, identity: &str) -> String {
    to_hex(&serialize_key(key, identity))
}

fn serialize_key(key: &PageCacheKey, identity: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + key.host.len() + key.path.len() + identity.len());
    b.extend_from_slice(&key.vhost_id.to_le_bytes());
    b.push(key.secure as u8);
    b.extend_from_slice(&key.private_owner.to_le_bytes());
    for s in [
        key.host.as_str(),
        key.path.as_str(),
        key.normalized_query.as_str(),
        key.vary_value.as_str(),
        identity,
    ] {
        b.extend_from_slice(&(s.len() as u32).to_le_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    b
}

fn deserialize_key(b: &[u8]) -> Option<(PageCacheKey, String)> {
    if b.len() < 13 {
        return None;
    }
    let vhost_id = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let secure = b[4] != 0;
    let private_owner = u64::from_le_bytes([b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12]]);
    let mut p = 13usize;
    let read_str = |p: &mut usize| -> Option<String> {
        if *p + 4 > b.len() {
            return None;
        }
        let len = u32::from_le_bytes([b[*p], b[*p + 1], b[*p + 2], b[*p + 3]]) as usize;
        *p += 4;
        if len > (1 << 20) || *p + len > b.len() {
            return None;
        }
        let s = std::str::from_utf8(&b[*p..*p + len]).ok()?.to_string();
        *p += len;
        Some(s)
    };
    let host = read_str(&mut p)?;
    let path = read_str(&mut p)?;
    let normalized_query = read_str(&mut p)?;
    let vary_value = read_str(&mut p)?;
    let identity = read_str(&mut p)?;
    Some((
        PageCacheKey {
            vhost_id,
            secure,
            host,
            path,
            normalized_query,
            vary_value,
            private_owner,
        },
        identity,
    ))
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(char::from_digit((x >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((x & 0xf) as u32, 16).unwrap());
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < s.len() {
        let hi = (s[i] as char).to_digit(16)?;
        let lo = (s[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn fetch_body_response(bytes: Vec<u8>) -> Response {
    http::Response::builder()
        .status(StatusCode::OK)
        .header("content-length", bytes.len().to_string())
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes))
        .unwrap()
}

fn format_fetch_request(host: &SocketAddr, key_blob_hex: &str) -> String {
    // No `Connection: close` — HTTP/1.1 defaults to keep-alive so the socket can be
    // pooled and reused. The server may still close (handled: a closed/`Connection:
    // close` response just yields a non-reusable result).
    format!(
        "POST {FETCH_PATH} HTTP/1.1\r\nHost: {host}\r\n{FETCH_KEY_HEADER}: {key_blob_hex}\r\nContent-Length: 0\r\n\r\n"
    )
}

/// Perform ONE fetch exchange over `stream` (which may be freshly connected or a pooled
/// keep-alive socket). Returns the result PLUS the stream iff it was read cleanly to the
/// message boundary and the peer kept it alive (so it can be pooled). `Err` on any
/// I/O/protocol error — the caller drops the socket (and, if it was pooled, retries fresh).
async fn fetch_over(
    mut stream: TcpStream,
    peer: &SocketAddr,
    key_blob_hex: &str,
) -> std::io::Result<(Option<Vec<u8>>, Option<TcpStream>)> {
    stream
        .write_all(format_fetch_request(peer, key_blob_hex).as_bytes())
        .await?;
    stream.flush().await?;

    const MAX_RESP: usize = 300 * 1024 * 1024; // matches the store body bound
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut tmp = [0u8; 64 * 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_RESP {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer fetch response too large",
            ));
        }
        if let Some((status, body_start, content_len)) = parse_head(&buf) {
            // Reusable only if read to an exact boundary AND the peer didn't say close.
            let keep = !head_has_conn_close(&buf[..body_start]);
            let reusable = |s| if keep { Some(s) } else { None };
            match status {
                200 => {
                    if let Some(cl) = content_len {
                        // A peer-supplied Content-Length is untrusted (a buggy/version-skewed peer,
                        // or an on-path attacker on the plaintext interconnect). Reject anything past
                        // the response bound BEFORE computing `body_start + cl`: in a release build
                        // (no overflow-checks) that add wraps for a huge `cl` to a value < body_start,
                        // making `buf[body_start..end]` a start>end range that panics — and with
                        // `panic = "abort"` set for release that aborts the whole process. Failing the
                        // fetch here degrades to a local render instead.
                        if cl > MAX_RESP {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "peer fetch content-length too large",
                            ));
                        }
                        if let Some(end) = body_start.checked_add(cl) {
                            if buf.len() >= end {
                                let body = buf[body_start..end].to_vec();
                                return Ok((Some(body), reusable(stream)));
                            }
                        }
                    }
                    // no content-length → must read to EOF (never reusable)
                }
                404 => return Ok((None, reusable(stream))), // 404 ack: Content-Length 0
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "peer fetch unexpected status",
                    ));
                }
            }
        }
    }
    // Connection closed: a 200 without content-length means body = everything past head.
    // EOF ⇒ socket is gone, never reusable.
    match parse_head(&buf) {
        Some((200, body_start, _)) => Ok((Some(buf[body_start..].to_vec()), None)),
        Some((404, _, _)) => Ok((None, None)),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer fetch incomplete response",
        )),
    }
}

/// Whether the response head carries `Connection: close` (so the socket must not be
/// pooled). `head` is the bytes up to and including the blank-line terminator.
fn head_has_conn_close(head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return true; // unparseable → be conservative, don't reuse
    };
    text.split("\r\n").any(|line| {
        line.split_once(':').is_some_and(|(n, v)| {
            n.trim().eq_ignore_ascii_case("connection") && v.trim().eq_ignore_ascii_case("close")
        })
    })
}

/// Parse the response head: `(status_code, body_start_offset, content_length)`.
fn parse_head(buf: &[u8]) -> Option<(u16, usize, Option<usize>)> {
    let pos = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..pos]).ok()?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let mut sp = status_line.split_whitespace();
    let _http = sp.next()?;
    let status: u16 = sp.next()?.parse().ok()?;
    let mut content_len = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_len = val.trim().parse::<usize>().ok();
            }
        }
    }
    Some((status, pos + 4, content_len))
}

/// The pure authenticate-and-classify step — no I/O, no store, no `Request` —
/// the security-critical logic, fully unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Not a (valid-source) purge: fall through to normal request handling.
    Passthrough,
    /// Valid source (a configured peer / loopback), but no usable purge directive.
    BadRequest,
    /// Valid source + valid directive.
    Apply(Purge),
}

/// Source-IP gate shared by the purge and readiness endpoints: only a CONFIGURED peer (the private
/// interconnect) or loopback (a local ops request) is trusted. `to_canonical` unwraps an
/// IPv4-mapped IPv6 peer so a dual-stack `::ffff:a.b.c.d` still matches a v4 allow-list entry /
/// loopback. A non-peer source — a CF-relayed request (peer = the CF edge's PUBLIC IP), a
/// direct-to-origin attacker, OR any other (even private) LAN host — is untrusted and the caller
/// falls through to the normal 404 path, never learning the endpoint exists. The narrow allow-list
/// (not a broad private-range membership) is the trust boundary now that there is no secret.
fn source_trusted(peer_ip: IpAddr, allowed: &HashSet<IpAddr>) -> bool {
    let ip = peer_ip.to_canonical();
    ip.is_loopback() || allowed.contains(&ip)
}

fn classify(
    path: &str,
    peer_ip: IpAddr,
    allowed: &HashSet<IpAddr>,
    directive: Option<&str>,
) -> Verdict {
    if path != PURGE_PATH {
        return Verdict::Passthrough;
    }
    if !source_trusted(peer_ip, allowed) {
        return Verdict::Passthrough;
    }
    match directive {
        Some(d) if !d.trim().is_empty() => Verdict::Apply(parse_purge(d)),
        _ => Verdict::BadRequest,
    }
}

/// Format the outbound purge request (split out so it is unit-testable and so
/// the no-injection property is checked). `directive` is a valid header value
/// (it came from `HeaderValue::to_str`, i.e. visible ASCII, no CR/LF).
fn format_purge_request(host: &SocketAddr, directive: &str) -> String {
    format!(
        "POST {PURGE_PATH} HTTP/1.1\r\nHost: {host}\r\n{PURGE_HEADER}: {directive}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

async fn send_purge(peer: SocketAddr, directive: &str) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(peer).await?;
    stream
        .write_all(format_purge_request(&peer, directive).as_bytes())
        .await?;
    stream.flush().await?;
    // Verify the peer actually ACKed with 204 rather than blindly counting every
    // forward as a success. A peer that REJECTS the purge — e.g. a 404 from its own
    // source-IP gate (this node not in the peer's --cache-peer list), or a 301/404
    // from the vhost on a binary that predates the endpoint — would otherwise be
    // recorded as `purges_forwarded`, hiding a broken cross-node purge path. Read
    // until the status line terminator: TCP may split even this tiny response.
    let mut buf = [0u8; 256];
    let mut n = 0usize;
    while n < buf.len() {
        let got = stream.read(&mut buf[n..]).await?;
        if got == 0 {
            break;
        }
        n += got;
        if buf[..n].iter().any(|&b| b == b'\r' || b == b'\n') {
            break;
        }
    }
    if !response_is_204(&buf[..n]) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer purge was not acknowledged with 204",
        ));
    }
    Ok(())
}

/// Whether a peer purge response head is a `204`. Parses the `HTTP/1.x 204 ...`
/// status line (which leads the response, so a short read still captures it); an
/// empty, truncated, or non-204 reply yields `false` → a counted forward failure.
fn response_is_204(head: &[u8]) -> bool {
    let line_end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    let Ok(text) = std::str::from_utf8(&head[..line_end]) else {
        return false;
    };
    let mut parts = text.split_whitespace();
    let _version = parts.next();
    parts.next() == Some("204")
}

fn ack(status: StatusCode) -> Response {
    http::Response::builder()
        .status(status)
        .body(Body::Empty)
        .unwrap()
}

/// Readiness response. Carries `x-hj-cache-ready: 1|0` (so a client can DISTINGUISH the real
/// endpoint from a normal app response at the same path on a binary that predates the endpoint —
/// which would route /__hj_cache_ready through the vhost and return a 200/301/404 page WITHOUT this
/// header) and `x-hj-cache-loaded: <n>` (entries the boot warm-scan restored from the file tier).
/// 200 + ready `1` = warm (boot scan done); 503 + `0` = still warming.
fn ready_ack(warm: bool, loaded: u64) -> Response {
    let (status, flag) = if warm {
        (StatusCode::OK, "1")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "0")
    };
    http::Response::builder()
        .status(status)
        .header("x-hj-cache-ready", flag)
        .header("x-hj-cache-loaded", loaded.to_string())
        .body(Body::Empty)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "192.0.2.3"; // a configured documentation-range peer
    const OTHER_LAN: &str = "192.168.0.99"; // a private NON-peer (must be rejected)
    const PUBLIC: &str = "203.0.113.9"; // a public source (e.g. a CF edge / attacker)

    fn allowed() -> HashSet<IpAddr> {
        let mut s = HashSet::new();
        s.insert(PEER.parse().unwrap());
        s
    }

    #[test]
    fn classify_applies_tags_from_configured_peer() {
        assert_eq!(
            classify(
                PURGE_PATH,
                PEER.parse().unwrap(),
                &allowed(),
                Some("tag=t1,t2")
            ),
            Verdict::Apply(Purge::Tags(vec!["t1".into(), "t2".into()]))
        );
    }

    #[test]
    fn classify_applies_purge_all_on_star_from_configured_peer() {
        assert_eq!(
            classify(PURGE_PATH, PEER.parse().unwrap(), &allowed(), Some("*")),
            Verdict::Apply(Purge::All)
        );
    }

    #[test]
    fn classify_allows_loopback() {
        // A local ops purge from 127.0.0.1 / ::1 is trusted (loopback), even though it is
        // never in the peer allow-list.
        for lo in ["127.0.0.1", "::1"] {
            assert_eq!(
                classify(PURGE_PATH, lo.parse().unwrap(), &allowed(), Some("*")),
                Verdict::Apply(Purge::All),
                "loopback {lo} should purge"
            );
        }
    }

    #[test]
    fn classify_rejects_nonpeer_private_source() {
        // The key tightening over a broad-RFC1918 gate: a private NON-peer (another host on
        // the LAN/VPC) must NOT be able to purge — only the configured peer(s).
        assert_eq!(
            classify(
                PURGE_PATH,
                OTHER_LAN.parse().unwrap(),
                &allowed(),
                Some("*")
            ),
            Verdict::Passthrough
        );
    }

    #[test]
    fn classify_passes_through_public_source() {
        // A request via Cloudflare (peer = CF edge PUBLIC IP) or any direct attacker must
        // look like a normal 404, never revealing the endpoint.
        assert_eq!(
            classify(PURGE_PATH, PUBLIC.parse().unwrap(), &allowed(), Some("*")),
            Verdict::Passthrough
        );
    }

    #[test]
    fn classify_matches_ipv4_mapped_peer_but_not_mapped_public() {
        // A dual-stack listener may report the v4 peer as ::ffff:192.0.2.3 — still a match.
        assert_eq!(
            classify(
                PURGE_PATH,
                "::ffff:192.0.2.3".parse().unwrap(),
                &allowed(),
                Some("*")
            ),
            Verdict::Apply(Purge::All)
        );
        // ...but a mapped PUBLIC v4 is still rejected.
        assert_eq!(
            classify(
                PURGE_PATH,
                "::ffff:203.0.113.9".parse().unwrap(),
                &allowed(),
                Some("*")
            ),
            Verdict::Passthrough
        );
    }

    #[test]
    fn source_trusted_gate_matches_purge_semantics() {
        // The readiness endpoint reuses this gate: loopback + configured peer trusted; a non-peer
        // private host, a public source, and an IPv4-mapped public are NOT.
        let a = allowed();
        assert!(source_trusted("127.0.0.1".parse().unwrap(), &a));
        assert!(source_trusted("::1".parse().unwrap(), &a));
        assert!(source_trusted(PEER.parse().unwrap(), &a));
        assert!(source_trusted("::ffff:192.0.2.3".parse().unwrap(), &a)); // dual-stack peer
        assert!(!source_trusted(OTHER_LAN.parse().unwrap(), &a)); // non-peer private host
        assert!(!source_trusted(PUBLIC.parse().unwrap(), &a)); // CF edge / attacker
        assert!(!source_trusted("::ffff:203.0.113.9".parse().unwrap(), &a)); // mapped public
    }

    #[test]
    fn classify_passes_through_non_purge_path() {
        assert_eq!(
            classify("/whats-new/", PEER.parse().unwrap(), &allowed(), Some("*")),
            Verdict::Passthrough
        );
    }

    #[test]
    fn classify_bad_request_when_no_directive() {
        assert_eq!(
            classify(PURGE_PATH, PEER.parse().unwrap(), &allowed(), None),
            Verdict::BadRequest
        );
        assert_eq!(
            classify(PURGE_PATH, PEER.parse().unwrap(), &allowed(), Some("  ")),
            Verdict::BadRequest
        );
    }

    #[test]
    fn response_204_parsing() {
        assert!(response_is_204(
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        ));
        assert!(response_is_204(b"HTTP/1.0 204 \r\n"));
        assert!(response_is_204(b"HTTP/1.1 204")); // short read, no CRLF yet
        // Rejections / garbage must NOT count as a successful forward.
        assert!(!response_is_204(b"HTTP/1.1 404 Not Found\r\n"));
        assert!(!response_is_204(b"HTTP/1.1 301 Moved Permanently\r\n"));
        assert!(!response_is_204(b"HTTP/1.1 200 OK\r\n"));
        assert!(!response_is_204(b"")); // empty / connection died
        assert!(!response_is_204(b"\xff\xfe garbage"));
    }

    #[tokio::test]
    async fn send_purge_accepts_fragmented_status_line() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 1024];
            let _ = stream.read(&mut req).await.unwrap();
            stream.write_all(b"HTTP/1.1 ").await.unwrap();
            tokio::task::yield_now().await;
            stream
                .write_all(b"204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        send_purge(addr, "tag=t1").await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn new_builds_allowlist_from_peers() {
        let pf = PurgeForwarder::from_config(&["192.0.2.3:80".into()]);
        assert!(pf.allowed.contains(&"192.0.2.3".parse::<IpAddr>().unwrap()));
        assert!(
            !pf.allowed
                .contains(&"192.168.0.99".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn forward_request_carries_directive_without_injection_or_secret() {
        let addr: SocketAddr = "192.0.2.3:80".parse().unwrap();
        let req = format_purge_request(&addr, "tag=thread_1");
        assert!(req.starts_with("POST /__hj_cache_purge HTTP/1.1\r\n"));
        assert!(req.contains("x-litespeed-purge: tag=thread_1\r\n"));
        assert!(
            !req.to_ascii_lowercase().contains("secret"),
            "no secret header is sent anymore"
        );
        assert!(req.contains("Content-Length: 0\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn peerless_forwarder_is_loopback_only_not_dead() {
        // Regression: with no --cache-peer the endpoint used to not exist at all, so the
        // documented loopback ops purge fell through to the backend on single-node setups.
        let pf = PurgeForwarder::from_config(&[]);
        assert!(pf.peer_addrs().is_empty());
        assert_eq!(
            classify(
                PURGE_PATH,
                "127.0.0.1".parse().unwrap(),
                &pf.allowed,
                Some("*")
            ),
            Verdict::Apply(Purge::All),
            "loopback purge must work without any configured peer"
        );
        assert_eq!(
            classify(
                PURGE_PATH,
                OTHER_LAN.parse().unwrap(),
                &pf.allowed,
                Some("*")
            ),
            Verdict::Passthrough,
            "non-loopback stays rejected when no peers are configured"
        );
    }

    #[test]
    fn fetch_key_serde_round_trips() {
        let key = PageCacheKey {
            vhost_id: 0xDEAD_BEEF,
            secure: true,
            host: "forum.example".into(),
            path: "/threads/example.1/".into(),
            normalized_query: "page=2".into(),
            vary_value: "xf_style_id=3".into(),
            private_owner: 0,
        };
        let identity = "https\nforum.example\n/threads/example.1/";
        let blob = serialize_fetch_key(&key, identity);
        let bytes = from_hex(&blob).unwrap();
        let (k2, id2) = deserialize_key(&bytes).unwrap();
        assert_eq!(k2, key);
        assert_eq!(id2, identity);
    }

    #[test]
    fn deserialize_key_rejects_truncated_or_overrun() {
        assert!(deserialize_key(b"").is_none());
        assert!(deserialize_key(&[0u8; 5]).is_none());
        // valid 13-byte header, then a string length claiming bytes that aren't there.
        let mut b = vec![0u8; 13];
        b.extend_from_slice(&100u32.to_le_bytes());
        assert!(deserialize_key(&b).is_none());
    }

    #[test]
    fn hex_round_trips_and_rejects_bad() {
        let v = vec![0u8, 1, 15, 16, 255, 128];
        assert_eq!(from_hex(&to_hex(&v)).unwrap(), v);
        assert!(from_hex("xyz").is_none()); // odd length
        assert!(from_hex("zz").is_none()); // non-hex digit
    }

    #[test]
    fn parse_head_extracts_status_and_len() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: x\r\n\r\nhello";
        let (status, body_start, cl) = parse_head(r).unwrap();
        assert_eq!(status, 200);
        assert_eq!(cl, Some(5));
        assert_eq!(&r[body_start..], b"hello");
        assert_eq!(
            parse_head(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap().0,
            404
        );
        assert!(parse_head(b"HTTP/1.1 200 OK\r\n").is_none()); // head not terminated yet
    }

    #[test]
    fn fetch_request_targets_get_path_with_key_header() {
        let addr: SocketAddr = "192.0.2.3:80".parse().unwrap();
        let req = format_fetch_request(&addr, "abcd1234");
        assert!(req.starts_with("POST /__hj_cache_get HTTP/1.1\r\n"));
        assert!(req.contains("x-hj-cache-key: abcd1234\r\n"));
        assert!(req.contains("Content-Length: 0\r\n"));
        // keep-alive: must NOT force close (so the socket can be pooled).
        assert!(!req.to_ascii_lowercase().contains("connection: close"));
    }

    #[test]
    fn negative_cache_skips_clears_and_expires() {
        let pf = PurgeForwarder::from_config(&["192.0.2.3:80".into()]);
        assert!(!pf.neg_cached(42)); // empty
        pf.neg_insert(42); // peer 404'd → skip for neg_ttl
        assert!(pf.neg_cached(42));
        pf.neg_clear(42); // peer has it again
        assert!(!pf.neg_cached(42));
        // an entry whose deadline is already in the past is not "cached".
        pf.neg_cache
            .lock()
            .unwrap()
            .insert(7, Instant::now() - Duration::from_secs(1));
        assert!(!pf.neg_cached(7));
    }

    #[test]
    fn negative_cache_stays_bounded_under_flood() {
        let pf = PurgeForwarder::from_config(&[]);
        for i in 0..(NEG_CACHE_MAX as u64 + 25) {
            pf.neg_insert(i);
        }
        assert!(pf.neg_cache.lock().unwrap().len() <= NEG_CACHE_MAX);
    }

    #[test]
    fn conn_close_detection() {
        assert!(head_has_conn_close(
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
        ));
        assert!(head_has_conn_close(
            b"HTTP/1.1 200 OK\r\nconnection:  CLOSE \r\n\r\n"
        ));
        assert!(!head_has_conn_close(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        ));
        assert!(!head_has_conn_close(
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n"
        ));
    }

    #[tokio::test]
    async fn pool_returns_reuses_and_drops_stale() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept and HOLD connections so the client side stays open.
        let _server = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let pf = PurgeForwarder::from_config(&[]);
        assert!(pf.pool_checkout(addr).is_none()); // empty pool
        let s = TcpStream::connect(addr).await.unwrap();
        pf.pool_return(addr, s);
        assert!(pf.pool_checkout(addr).is_some()); // fresh conn reused
        // A too-old pooled conn is discarded on checkout (peers close idle sockets).
        let stale = TcpStream::connect(addr).await.unwrap();
        pf.pool
            .lock()
            .unwrap()
            .entry(addr)
            .or_default()
            .push(PooledConn {
                stream: stale,
                since: Instant::now() - POOL_IDLE_MAX_AGE - Duration::from_secs(1),
            });
        assert!(pf.pool_checkout(addr).is_none());
    }

    #[tokio::test]
    async fn fetch_over_rejects_absurd_content_length_without_panicking() {
        // (audit-2026-07-01) A peer answering /__hj_cache_get with a Content-Length past the
        // response bound must FAIL the fetch, not overflow `body_start + cl` (which, with no
        // overflow-checks, wraps below body_start) into a start>end slice that panics — and with
        // `panic = "abort"` that would abort the whole process on the request path.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = s.read(&mut scratch).await; // consume the fetch request
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nx")
                .await;
            let _ = s.flush().await;
            let _ = s.read(&mut scratch).await; // block until the client drops (head stays readable)
        });
        let client = TcpStream::connect(addr).await.unwrap();
        let res = fetch_over(client, &addr, "deadbeef").await;
        assert!(
            matches!(&res, Err(e) if e.kind() == std::io::ErrorKind::InvalidData),
            "absurd Content-Length must degrade to an InvalidData error, got {res:?}"
        );
        server.abort();
    }
}
