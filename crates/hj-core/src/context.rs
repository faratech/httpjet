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
    /// Trusted upstream correlation id (Cloudflare `cf-ray`) when the peer is a
    /// `trusted_proxy`; lets a request be joined to CF's edge logs. `None` for
    /// direct/untrusted peers (an untrusted `cf-ray` is never honored).
    pub upstream_id: Option<String>,
    /// TLS parameters, `Some` on TLS/QUIC connections.
    pub tls: Option<TlsParams>,
}

/// TLS connection parameters exposed to handlers (`HTTPS`, `SSL_*` env vars).
#[derive(Debug, Clone)]
pub struct TlsParams {
    pub protocol: &'static str,
    pub cipher: String,
    pub client_cert: Option<ClientCert>,
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
