//! Header rewriting for the reverse proxy hop.
//!
//! Implements the LiteSpeed-compatible forwarding semantics:
//! - hop-by-hop headers are stripped before the request leaves us and before
//!   the upstream response is handed back to the client;
//! - `X-Forwarded-For` is *appended to* (never replaced), preserving any chain
//!   already present;
//! - `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Real-IP` are set from the
//!   request context;
//! - the original `Host` header is preserved as seen by the client (we do not
//!   rewrite it to the upstream authority — LiteSpeed forwards the client Host
//!   so the backend can do name-based vhosting / generate correct absolute
//!   URLs).

use std::net::IpAddr;

use hj_core::ReqCtx;
use http::header::{CONNECTION, HOST, HeaderMap, HeaderName, HeaderValue};

/// Hop-by-hop headers that must never be forwarded across a proxy hop
/// (RFC 7230 §6.1). `Upgrade` is handled specially: it is stripped for ordinary
/// requests but preserved for WebSocket upgrades (see [`is_websocket_upgrade`]).
pub(crate) const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Remove all hop-by-hop headers from `headers`.
///
/// In addition to the well-known list, any header *named in* the `Connection`
/// header's comma list is also removed (per RFC 7230), then `Connection`
/// itself. When `keep_upgrade` is true the `Upgrade` header and a
/// `Connection: upgrade` token are left intact so a WebSocket/h2c upgrade can
/// be replayed to the upstream.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    // Collect connection-token-named headers first.
    let mut conn_named: Vec<HeaderName> = Vec::new();
    for v in headers.get_all(CONNECTION).iter() {
        if let Ok(s) = v.to_str() {
            for tok in s.split(',') {
                let tok = tok.trim();
                if tok.is_empty() {
                    continue;
                }
                if keep_upgrade && tok.eq_ignore_ascii_case("upgrade") {
                    continue;
                }
                if let Ok(name) = HeaderName::from_bytes(tok.as_bytes()) {
                    conn_named.push(name);
                }
            }
        }
    }
    for name in conn_named {
        headers.remove(&name);
    }

    for h in HOP_BY_HOP {
        if keep_upgrade && (*h == "upgrade" || *h == "connection") {
            continue;
        }
        // remove() with a &str target requires a HeaderName; build once.
        if let Ok(name) = HeaderName::from_bytes(h.as_bytes()) {
            headers.remove(&name);
        }
    }

    // Strip any Proxy-* headers (Proxy-Connection and friends are non-standard
    // hop-by-hop leftovers we never want to forward).
    let proxy_named: Vec<HeaderName> = headers
        .keys()
        .filter(|k| {
            let n = k.as_str();
            n.len() >= 6 && n[..6].eq_ignore_ascii_case("proxy-")
        })
        .cloned()
        .collect();
    for name in proxy_named {
        headers.remove(&name);
    }
}

/// True if these request headers represent a WebSocket upgrade
/// (`Upgrade: websocket` + a `Connection` token containing `upgrade`).
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade_ws = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if !upgrade_ws {
        return false;
    }
    headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false)
}

/// Append `ip` to the `X-Forwarded-For` chain, preserving existing entries.
fn append_xff(headers: &mut HeaderMap, ip: IpAddr) {
    use std::fmt::Write as _;
    let xff = HeaderName::from_static("x-forwarded-for");
    // Build the combined chain directly into ONE String (existing entries + new ip), without
    // the intermediate Vec<String> + per-token allocation + join the old version did per
    // proxied request.
    let mut joined = String::new();
    for v in headers.get_all(&xff).iter() {
        if let Ok(s) = v.to_str() {
            for part in s.split(',') {
                let part = part.trim();
                if !part.is_empty() {
                    if !joined.is_empty() {
                        joined.push_str(", ");
                    }
                    joined.push_str(part);
                }
            }
        }
    }
    if !joined.is_empty() {
        joined.push_str(", ");
    }
    let _ = write!(joined, "{ip}");
    headers.remove(&xff);
    if let Ok(val) = HeaderValue::from_str(&joined) {
        headers.insert(xff, val);
    }
}

/// Apply all forward-direction header rewrites to a request that is about to be
/// sent to the upstream. `keep_upgrade` preserves WebSocket upgrade headers.
///
/// Semantics:
/// - strip hop-by-hop headers,
/// - append `ctx.client_ip` to `X-Forwarded-For`,
/// - set `X-Forwarded-Proto` (`https` when `ctx.is_tls`, else `http`),
/// - set `X-Forwarded-Host` from the inbound `Host`,
/// - set `X-Real-IP` to `ctx.client_ip`,
/// - leave the original `Host` header untouched.
pub(crate) fn rewrite_request_headers(headers: &mut HeaderMap, ctx: &ReqCtx, keep_upgrade: bool) {
    // Capture the inbound Host before we touch anything, for X-Forwarded-Host.
    let inbound_host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    strip_hop_by_hop(headers, keep_upgrade);

    append_xff(headers, ctx.client_ip);

    let proto = if ctx.is_tls { "https" } else { "http" };
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(if proto == "https" { "https" } else { "http" }),
    );

    if let Some(host) = inbound_host {
        if let Ok(val) = HeaderValue::from_str(&host) {
            headers.insert(HeaderName::from_static("x-forwarded-host"), val);
        }
    }

    if let Ok(val) = HeaderValue::from_str(&ctx.client_ip.to_string()) {
        headers.insert(HeaderName::from_static("x-real-ip"), val);
    }
}

/// Strip hop-by-hop headers from an upstream *response* before returning it to
/// the client. `keep_upgrade` is true only for a successful `101` switch.
pub(crate) fn sanitize_response_headers(headers: &mut HeaderMap, keep_upgrade: bool) {
    strip_hop_by_hop(headers, keep_upgrade);
    // `x-cache-optimizer` labels drive the CDN redirect-cache allow-list in the
    // pipeline egress transform. Only the trusted LSAPI origin (the app's
    // CacheOptimizer addon) may assert them — a proxied upstream must not be
    // able to mark its redirects edge-cacheable.
    headers.remove("x-cache-optimizer");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use hj_core::config::{ServerConfig, VHostConfig};
    use hj_core::{Proto, ReqCtx};

    fn dummy_ctx(client_ip: IpAddr, is_tls: bool) -> ReqCtx {
        // Build a minimal ServerConfig/VHostConfig via Default-ish construction.
        let server = ServerConfig {
            server_root: Default::default(),
            server_name: String::new(),
            user: String::new(),
            group: String::new(),
            index_files: vec![],
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
            vhosts: Default::default(),
            vhost_order: vec![],
            mime: Default::default(),
        };
        ReqCtx {
            server: Arc::new(server),
            vhost_name: "test".into(),
            vhost: Arc::new(VHostConfig::default()),
            peer_ip: client_ip,
            client_ip,
            is_tls,
            protocol: Proto::Http1,
            trusted_proxy: false,
            env: vec![],
            local_addr: "127.0.0.1:8080".parse().unwrap(),
            peer_port: 0,
            request_time: std::time::SystemTime::now(),
            request_id: Default::default(),
            upstream_id: None,
            tls: None,
        }
    }

    #[test]
    fn xff_appends_not_replaces() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("203.0.113.7, 70.0.0.1"),
        );
        let ctx = dummy_ctx("198.51.100.9".parse().unwrap(), false);
        rewrite_request_headers(&mut h, &ctx, false);
        let xff = h.get("x-forwarded-for").unwrap().to_str().unwrap();
        assert_eq!(xff, "203.0.113.7, 70.0.0.1, 198.51.100.9");
    }

    #[test]
    fn xff_sets_when_absent() {
        let mut h = HeaderMap::new();
        let ctx = dummy_ctx("198.51.100.9".parse().unwrap(), true);
        rewrite_request_headers(&mut h, &ctx, false);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "198.51.100.9");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(h.get("x-real-ip").unwrap(), "198.51.100.9");
    }

    #[test]
    fn host_preserved_and_forwarded_host_set() {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("example.com"));
        let ctx = dummy_ctx("10.0.0.1".parse().unwrap(), false);
        rewrite_request_headers(&mut h, &ctx, false);
        assert_eq!(h.get(HOST).unwrap(), "example.com");
        assert_eq!(h.get("x-forwarded-host").unwrap(), "example.com");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn hop_by_hop_stripped() {
        let mut h = HeaderMap::new();
        h.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, X-Custom-Hop"),
        );
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("x-custom-hop", HeaderValue::from_static("secret"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        h.insert("te", HeaderValue::from_static("trailers"));
        h.insert("x-keep", HeaderValue::from_static("yes"));
        let ctx = dummy_ctx("10.0.0.1".parse().unwrap(), false);
        rewrite_request_headers(&mut h, &ctx, false);
        assert!(!h.contains_key(CONNECTION));
        assert!(!h.contains_key("keep-alive"));
        assert!(
            !h.contains_key("x-custom-hop"),
            "connection-listed header not stripped"
        );
        assert!(!h.contains_key("transfer-encoding"));
        assert!(!h.contains_key("proxy-connection"));
        assert!(!h.contains_key("te"));
        assert!(h.contains_key("x-keep"), "ordinary header should survive");
    }

    #[test]
    fn websocket_upgrade_preserved_when_kept() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(
            "sec-websocket-key",
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        assert!(is_websocket_upgrade(&h));
        let ctx = dummy_ctx("10.0.0.1".parse().unwrap(), false);
        rewrite_request_headers(&mut h, &ctx, true);
        assert_eq!(h.get(http::header::UPGRADE).unwrap(), "websocket");
        assert!(h.contains_key(CONNECTION));
        assert!(
            h.contains_key("sec-websocket-key"),
            "Sec-WebSocket-* preserved"
        );
    }

    #[test]
    fn websocket_upgrade_stripped_when_not_kept() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        strip_hop_by_hop(&mut h, false);
        assert!(!h.contains_key(http::header::UPGRADE));
        assert!(!h.contains_key(CONNECTION));
    }
}
