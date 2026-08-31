//! Per-request context shared across the pipeline.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use hj_config::model::{ServerConfig, VHostConfig};

/// Which protocol the request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Http1,
    Http2,
    Http3,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Http1 => "HTTP/1.1",
            Proto::Http2 => "HTTP/2",
            Proto::Http3 => "HTTP/3",
        }
    }
}

/// Mutable per-request context handed to handlers and transforms.
///
/// Owns `Arc`s (no borrows) so it is `'static` and works cleanly with
/// `async_trait` handlers. `Clone` is derived so an internal subrequest (e.g.
/// an ESI fragment fetch) can build an isolated context from the parent's; all
/// fields are value/`Arc` types, so a clone is independent and cheap.
#[derive(Clone)]
pub struct ReqCtx {
    pub server: Arc<ServerConfig>,
    pub vhost_name: String,
    pub vhost: Arc<VHostConfig>,
    /// The directly-connected peer address.
    pub peer_ip: IpAddr,
    /// The resolved client IP after honoring trusted proxy headers.
    pub client_ip: IpAddr,
    /// Effective request scheme: `true` = the client is on HTTPS. This is the
    /// *physical* connection TLS, OR — when the peer is a `trusted_proxy` — an
    /// `X-Forwarded-Proto: https` / `CF-Visitor` assertion from that proxy (so a
    /// cleartext CDN→origin hop still presents the client's real scheme to the
    /// backend / rewrite / page cache). For the *physical* TLS handshake (client
    /// cert, `SSL_*` env, Alt-Svc) test [`Self::tls`]`.is_some()`, not this flag.
    pub is_tls: bool,
    pub protocol: Proto,
    /// True if `peer_ip` is a trusted reverse proxy (e.g. a Cloudflare range)
    /// and (on TLS) presented a valid client cert.
    pub trusted_proxy: bool,
    /// Environment variables set by rewrite `[E=...]` flags, consumed by later
    /// conditions and `Header ... env=` directives.
    pub env: Vec<(String, String)>,
    /// The listener's bound local address (`SERVER_ADDR` / `SERVER_PORT`).
    pub local_addr: SocketAddr,
    /// The directly-connected peer's TCP port (`REMOTE_PORT`).
    pub peer_port: u16,
    /// Request arrival time (`REQUEST_TIME` / `REQUEST_TIME_FLOAT`).
    pub request_time: SystemTime,
    /// Per-request correlation id, minted once at the transport boundary and
    /// emitted into every log sink so one request is joinable across them.
    pub request_id: crate::reqid::ReqId,
    /// TLS parameters, `Some` on TLS/QUIC connections.
    pub tls: Option<TlsParams>,
    /// (Tier 2) The connection arrived over a unix-domain socket: there is no
    /// address, so `peer_ip`/`client_ip` are loopback fabrications and the
    /// filesystem mode/owner is the real access boundary. ACLs, the per-IP
    /// throttle, and `REMOTE_ADDR` see loopback; the access log renders `unix:`.
    pub peer_unix: bool,
    /// Request identity consumed by the redirect-decache transform (see the
    /// pipeline's `deny_redirect_cdn_headers`), reached only on 3xx responses.
    /// (#318) A dedicated field — not `env` — so setting it costs one host
    /// String plus a `Bytes` refcount bump (the old env plumbing materialized
    /// four Strings per request), and a config rule can never overwrite it
    /// (the reserved `HJ_` env-prefix guard existed for exactly that).
    pub redirect_guard: Option<RedirectGuard>,
}

/// The ORIGINAL request identity stashed for redirect-response evaluation:
/// path+query as received (Bytes-backed, cheap to clone) and the request host
/// pre-normalized the same way the page-cache keys it (lowercased,
/// port-stripped).
#[derive(Clone)]
pub struct RedirectGuard {
    pub host: String,
    pq: Option<http::uri::PathAndQuery>,
}

impl RedirectGuard {
    pub fn new(host: String, pq: Option<http::uri::PathAndQuery>) -> Self {
        RedirectGuard { host, pq }
    }

    /// `path?query` rendered lazily from the stored [`http::uri::PathAndQuery`],
    /// with an empty query dropped (`/x?` → `/x`) so the entry paths that don't
    /// run `strip_empty_query` still agree with the ones that do. `None` for
    /// the URI forms that have no path (authority-form CONNECT).
    pub fn path_query(&self) -> Option<&str> {
        let pq = self.pq.as_ref()?;
        match pq.query() {
            Some(q) if !q.is_empty() => Some(pq.as_str()),
            _ => Some(pq.path()),
        }
    }
}

/// TLS connection parameters exposed to handlers (`HTTPS`, `SSL_*` env vars).
///
/// (#302) The heap payload is Arc-shared: built once per CONNECTION, but cloned
/// per request (every `ReqCtx`/`BridgeCtx` copy on the fast path carries one, and
/// prod's mTLS listener populates all six `ClientCert` strings). `Deref` keeps
/// every read site field-access identical; a clone is an refcount bump.
#[derive(Debug, Clone)]
pub struct TlsParams(std::sync::Arc<TlsParamsInner>);

impl std::ops::Deref for TlsParams {
    type Target = TlsParamsInner;
    fn deref(&self) -> &TlsParamsInner {
        &self.0
    }
}

#[derive(Debug)]
pub struct TlsParamsInner {
    pub protocol: &'static str,
    pub cipher: String,
    pub client_cert: Option<ClientCert>,
}

impl TlsParams {
    pub fn new(protocol: &'static str, cipher: String, client_cert: Option<ClientCert>) -> Self {
        TlsParams(std::sync::Arc::new(TlsParamsInner {
            protocol,
            cipher,
            client_cert,
        }))
    }
}

/// Verified client certificate details (mTLS / Cloudflare authenticated origin pull).
#[derive(Debug, Clone)]
pub struct ClientCert {
    pub subject_dn: String,
    pub issuer_dn: String,
    pub serial_hex: String,
    pub verified: bool,
    pub not_before: String,
    pub not_after: String,
}

impl ReqCtx {
    pub fn set_env(&mut self, key: impl Into<String>, val: impl Into<String>) {
        let key = key.into();
        if let Some(slot) = self.env.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = val.into();
        } else {
            self.env.push((key, val.into()));
        }
    }

    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}
