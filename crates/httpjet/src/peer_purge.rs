//! (OPS3) The loopback-gated page-cache ops endpoints on the main listener.
//!
//! Serves two reserved request paths, intercepted at the very top of the
//! pipeline (before vhost routing / the mTLS gate) so there is no extra socket
//! and no firewall change:
//! * [`PURGE_PATH`] — apply an `X-LiteSpeed-Purge` directive (`tag=…` / `*`)
//!   to the local page cache (the documented local ops purge, used by
//!   `lscache_purge.php` and the deploy smoke).
//! * [`READY_PATH`] — page-cache boot warm-scan readiness probe.
//!
//! Double-gated: (1) the reserved request path, (2) the RAW TCP peer IP must be
//! loopback (`127.0.0.1`/`::1`). The raw peer is un-spoofable over TCP (it is
//! the immediate connection source, not the XFF / CF-resolved client IP). A
//! request arriving via Cloudflare has peer = the CF edge's PUBLIC IP, fails
//! the gate, and falls through to normal handling (a plain 404) — the
//! endpoints are invisible to anything off-box. There is no shared secret:
//! loopback IS the trust boundary.
//!
//! History: this module used to also fan purges out to the active-active peer
//! node (`--cache-peer`) and pull cross-node cache fills. The peer node was
//! decommissioned 2026-07-13; the fan-out/fill machinery was removed with it
//! (see git history), leaving the loopback endpoints.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use http::StatusCode;

use hj_core::{Body, Request, Response};
use hj_pagecache::{Purge, parse_purge};

use crate::state::ServerState;

/// Reserved request path for a local ops page-cache purge (POST from loopback).
pub const PURGE_PATH: &str = "/__hj_cache_purge";
/// Reserved request path for a page-cache readiness probe (loopback only): 200 once the boot
/// warm-scan has finished, 503 while still warming. Lets an ops check or the restart-persistence
/// gate wait for warm-up WITHOUT probing a real URL — a probe during the scan window misses,
/// re-primes the key, wins `load_scanned`'s tie-break, and UNLINKS the persisted entry under test.
pub const READY_PATH: &str = "/__hj_cache_ready";
/// Header carrying the raw `X-LiteSpeed-Purge` directive.
const PURGE_HEADER: &str = "x-litespeed-purge";

/// The purge/readiness endpoint handler, shared behind the `ServerState` `Arc`.
/// Built whenever `--page-cache` is on. Gating its construction on anything
/// narrower once silently killed the loopback purge on single-node setups: the
/// POST fell through to the backend as a normal request. `Clone` is trivial and
/// lets a SIGHUP reload carry it into the next config generation.
#[derive(Clone)]
pub struct PurgeForwarder {}

impl PurgeForwarder {
    pub(crate) fn new() -> Self {
        Self {}
    }

    /// Pipeline hook: if `req` is a loopback request for a reserved cache
    /// endpoint, handle it and return the ack response; otherwise `None` (the
    /// caller falls through to normal request handling). Called at the top of
    /// both entry paths, so the per-request cost for normal traffic is a single
    /// path comparison.
    ///
    /// `peer_ip` MUST be the raw TCP peer (not the XFF-resolved client IP) — it
    /// is the sole authenticator, so an attacker-controlled forwarded header
    /// must never reach it.
    pub fn handle_inbound(
        &self,
        req: &Request,
        peer_ip: IpAddr,
        state: &Arc<ServerState>,
    ) -> Option<Response> {
        let path = req.uri().path();
        // Readiness probe: same loopback source gate as the purge endpoint, invisible to
        // anyone else. 200 once the boot warm-scan is done, 503 while warming.
        if path == READY_PATH {
            if !source_trusted(peer_ip) {
                return None; // untrusted source → normal handling (404), endpoint stays invisible
            }
            let (warm, loaded) = state
                .page_cache
                .as_ref()
                .map(|pc| (pc.is_warm(), pc.scan_loaded()))
                .unwrap_or((true, 0));
            return Some(ready_ack(warm, loaded));
        }
        let directive = req
            .headers()
            .get(PURGE_HEADER)
            .and_then(|v| v.to_str().ok());
        match classify(path, peer_ip, directive) {
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
}

/// The pure authenticate-and-classify step — no I/O, no store, no `Request` —
/// the security-critical logic, fully unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Not a (valid-source) purge: fall through to normal request handling.
    Passthrough,
    /// Valid source (loopback), but no usable purge directive.
    BadRequest,
    /// Valid source + valid directive.
    Apply(Purge),
}

/// Source-IP gate shared by the purge and readiness endpoints: only loopback (a local ops
/// request) is trusted. `to_canonical` unwraps an IPv4-mapped IPv6 peer so a dual-stack
/// `::ffff:127.0.0.1` still matches. Any other source — a CF-relayed request (peer = the CF
/// edge's PUBLIC IP), a direct-to-origin attacker, or ANY LAN/VPC host — is untrusted and the
/// caller falls through to the normal 404 path, never learning the endpoint exists.
fn source_trusted(peer_ip: IpAddr) -> bool {
    peer_ip.to_canonical().is_loopback()
}

fn classify(path: &str, peer_ip: IpAddr, directive: Option<&str>) -> Verdict {
    if path != PURGE_PATH {
        return Verdict::Passthrough;
    }
    if !source_trusted(peer_ip) {
        return Verdict::Passthrough;
    }
    match directive {
        Some(d) if !d.trim().is_empty() => Verdict::Apply(parse_purge(d)),
        _ => Verdict::BadRequest,
    }
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

    const OTHER_LAN: &str = "192.168.0.99"; // a private NON-loopback host (must be rejected)
    const PUBLIC: &str = "203.0.113.9"; // a public source (e.g. a CF edge / attacker)

    #[test]
    fn classify_allows_loopback() {
        for lo in ["127.0.0.1", "::1"] {
            assert_eq!(
                classify(PURGE_PATH, lo.parse().unwrap(), Some("*")),
                Verdict::Apply(Purge::All),
                "loopback {lo} should purge"
            );
        }
    }

    #[test]
    fn classify_applies_tags_from_loopback() {
        assert_eq!(
            classify(PURGE_PATH, "127.0.0.1".parse().unwrap(), Some("tag=t1,t2")),
            Verdict::Apply(Purge::Tags(vec!["t1".into(), "t2".into()]))
        );
    }

    #[test]
    fn classify_rejects_private_lan_source() {
        // Loopback-only: a private host on the LAN/VPC must NOT be able to purge.
        assert_eq!(
            classify(PURGE_PATH, OTHER_LAN.parse().unwrap(), Some("*")),
            Verdict::Passthrough
        );
    }

    #[test]
    fn classify_passes_through_public_source() {
        // A request via Cloudflare (peer = CF edge PUBLIC IP) or any direct attacker must
        // look like a normal 404, never revealing the endpoint.
        assert_eq!(
            classify(PURGE_PATH, PUBLIC.parse().unwrap(), Some("*")),
            Verdict::Passthrough
        );
    }

    #[test]
    fn classify_matches_ipv4_mapped_loopback_but_not_mapped_public() {
        // A dual-stack listener may report the v4 peer as ::ffff:127.0.0.1 — still loopback.
        assert_eq!(
            classify(PURGE_PATH, "::ffff:127.0.0.1".parse().unwrap(), Some("*")),
            Verdict::Apply(Purge::All)
        );
        // ...but a mapped PUBLIC v4 is still rejected.
        assert_eq!(
            classify(PURGE_PATH, "::ffff:203.0.113.9".parse().unwrap(), Some("*")),
            Verdict::Passthrough
        );
    }

    #[test]
    fn source_trusted_gate_matches_purge_semantics() {
        // The readiness endpoint reuses this gate: loopback trusted; a private host, a
        // public source, and an IPv4-mapped public are NOT.
        assert!(source_trusted("127.0.0.1".parse().unwrap()));
        assert!(source_trusted("::1".parse().unwrap()));
        assert!(source_trusted("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!source_trusted(OTHER_LAN.parse().unwrap()));
        assert!(!source_trusted(PUBLIC.parse().unwrap()));
        assert!(!source_trusted("::ffff:203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn classify_passes_through_non_purge_path() {
        assert_eq!(
            classify("/whats-new/", "127.0.0.1".parse().unwrap(), Some("*")),
            Verdict::Passthrough
        );
    }

    #[test]
    fn classify_bad_request_when_no_directive() {
        assert_eq!(
            classify(PURGE_PATH, "127.0.0.1".parse().unwrap(), None),
            Verdict::BadRequest
        );
        assert_eq!(
            classify(PURGE_PATH, "127.0.0.1".parse().unwrap(), Some("  ")),
            Verdict::BadRequest
        );
    }

    #[test]
    fn peerless_endpoint_is_loopback_only_not_dead() {
        // Regression (kept from the peer era): the loopback ops purge must exist on a
        // single-node setup — gating the endpoint's construction on having a peer once
        // made the documented loopback purge fall through to the backend.
        let _pf = PurgeForwarder::new();
        assert_eq!(
            classify(PURGE_PATH, "127.0.0.1".parse().unwrap(), Some("*")),
            Verdict::Apply(Purge::All),
            "loopback purge must work with no peers configured"
        );
        assert_eq!(
            classify(PURGE_PATH, OTHER_LAN.parse().unwrap(), Some("*")),
            Verdict::Passthrough,
            "non-loopback stays rejected"
        );
    }
}
