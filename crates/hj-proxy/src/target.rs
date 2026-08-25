//! Proxy target resolution.
//!
//! A [`ProxyTarget`] names where a request should be forwarded. It can be built
//! from a configured `ExtProcessor{kind:Proxy}`, from a vhost `WebSocketMap`, or
//! parsed from an ad-hoc URL produced by a rewrite `[P]` rule
//! (e.g. `http://127.0.0.1:8002/$1`, `http://localhost:2812/tools.json`).
//!
//! The substituted path that follows the authority (already `$1`-expanded by
//! hj-rewrite) is carried in [`ProxyTarget::path_and_query`]; if empty the
//! original request path is used unchanged.

use std::fmt;
use std::time::Duration;

use hj_core::config::{ExtAddress, ExtProcessor, WebSocketMap};

/// Transport used to reach an upstream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TargetTransport {
    /// `host:port` reached over TCP (`HostPort` or already-resolved `Tcp`).
    Tcp(String),
    /// Unix domain socket at this path.
    Uds(String),
}

/// A resolved reverse-proxy destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    /// Scheme as written (`http` / `https` / `ws` / `wss`). `https`/`wss`
    /// indicate the *upstream* leg is TLS (rare for LSWS backends, but parsed).
    pub scheme: String,
    /// The authority used both for the TCP connection and the upstream `Host`
    /// fallback, e.g. `127.0.0.1:8002`.
    pub authority: String,
    /// How to physically reach the upstream.
    pub(crate) transport: TargetTransport,
    /// Path (+query) to send upstream. Empty means "use the request's own
    /// path-and-query unchanged".
    pub path_and_query: String,
    /// Optional ext-processor / logical name (included in the pool identity for
    /// observability, but never used without the physical endpoint).
    pub name: Option<String>,
    /// Optional LiteSpeed extProcessor pool limits. Ad-hoc rewrite targets and
    /// websocket maps use the process defaults.
    pub max_conns: Option<u32>,
    pub keep_alive: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    /// LiteSpeed `retryTimeout`: bounds the ONE transparent retry of a bodyless
    /// idempotent request whose pooled connection died between checkout and send
    /// (audit: parsed for years, consumed nowhere). `None`/zero → a 5 s cap.
    pub retry_timeout: Option<Duration>,
}

impl ProxyTarget {
    /// True if the upstream leg should itself be TLS.
    pub fn is_tls(&self) -> bool {
        self.scheme.eq_ignore_ascii_case("https") || self.scheme.eq_ignore_ascii_case("wss")
    }

    /// True if this is a WebSocket scheme (`ws`/`wss`).
    pub fn is_websocket(&self) -> bool {
        self.scheme.eq_ignore_ascii_case("ws") || self.scheme.eq_ignore_ascii_case("wss")
    }

    /// The key under which connections to this target are pooled.
    pub fn pool_key(&self) -> String {
        match (&self.name, &self.transport) {
            (Some(n), TargetTransport::Tcp(hp)) => {
                format!("ext:{n}:tcp:{}://{hp}", self.scheme)
            }
            (Some(n), TargetTransport::Uds(p)) => format!("ext:{n}:uds:{p}"),
            (None, TargetTransport::Tcp(hp)) => format!("tcp:{}://{hp}", self.scheme),
            (None, TargetTransport::Uds(p)) => format!("uds:{p}"),
        }
    }

    /// Parse an ad-hoc proxy URL from a rewrite `[P]` rule.
    ///
    /// Accepts `http://host:port/path`, `https://...`, `ws://...`, `wss://...`,
    /// and a Unix-socket form `unix:/path/to.sock|/upstream/path` (LiteSpeed
    /// `uds://` style). A missing port defaults to 80 for http/ws and 443 for
    /// https/wss. The path (if any) becomes [`Self::path_and_query`].
    pub fn parse_url(url: &str) -> Result<ProxyTarget, TargetParseError> {
        let url = url.trim();
        if url.is_empty() {
            return Err(TargetParseError("empty target".into()));
        }

        // Unix-domain forms: `unix:/path.sock|/req/path` or `uds:///path.sock`.
        if let Some(rest) = url
            .strip_prefix("unix:")
            .or_else(|| url.strip_prefix("uds:"))
        {
            let rest = rest.trim_start_matches('/');
            let (sock, path) = match rest.split_once('|') {
                Some((s, p)) => (s.to_string(), normalize_path(p)),
                None => (rest.to_string(), String::new()),
            };
            if sock.is_empty() {
                return Err(TargetParseError("empty unix socket path".into()));
            }
            let sock = format!("/{}", sock.trim_start_matches('/'));
            return Ok(ProxyTarget {
                scheme: "http".into(),
                authority: "localhost".into(),
                transport: TargetTransport::Uds(sock),
                path_and_query: path,
                name: None,
                max_conns: None,
                keep_alive: None,
                connect_timeout: None,
                retry_timeout: None,
            });
        }

        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| TargetParseError(format!("missing scheme in {url:?}")))?;
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
            return Err(TargetParseError(format!("unsupported scheme {scheme:?}")));
        }

        // Split authority from path/query. A query-only absolute URI (`http://h?x=1`)
        // is equivalent to path `/` plus that query.
        let path_start = rest.find('/').into_iter().chain(rest.find('?')).min();
        let (authority_raw, path) = match path_start {
            Some(i) if rest.as_bytes()[i] == b'?' => (&rest[..i], format!("/{}", &rest[i..])),
            Some(i) => (&rest[..i], normalize_path(&rest[i..])),
            None => (rest, String::new()),
        };
        if authority_raw.is_empty() {
            return Err(TargetParseError(format!("missing authority in {url:?}")));
        }
        // Strip any userinfo@ (we do not forward credentials in the authority).
        let authority_raw = authority_raw.rsplit('@').next().unwrap_or(authority_raw);

        let authority = authority_raw_with_port(authority_raw, &scheme);

        Ok(ProxyTarget {
            transport: TargetTransport::Tcp(authority.clone()),
            scheme,
            authority,
            path_and_query: path,
            name: None,
            max_conns: None,
            keep_alive: None,
            connect_timeout: None,
            retry_timeout: None,
        })
    }

    /// Build a target from an `ExtProcessor` of kind `Proxy`.
    pub fn from_ext_processor(ep: &ExtProcessor) -> ProxyTarget {
        let (authority, transport) = match &ep.address {
            ExtAddress::Tcp(sa) => (sa.to_string(), TargetTransport::Tcp(sa.to_string())),
            ExtAddress::HostPort(hp) => {
                let hp = hp.trim_start_matches("UDS://"); // defensive
                (hp.to_string(), TargetTransport::Tcp(hp.to_string()))
            }
            ExtAddress::Uds(p) => (
                "localhost".to_string(),
                TargetTransport::Uds(p.to_string_lossy().into_owned()),
            ),
        };
        ProxyTarget {
            scheme: "http".into(),
            authority,
            transport,
            path_and_query: String::new(),
            name: Some(ep.name.clone()),
            max_conns: Some(ep.max_conns),
            keep_alive: Some(ep.pc_keep_alive_timeout),
            connect_timeout: Some(ep.init_timeout),
            retry_timeout: Some(ep.retry_timeout),
        }
    }

    /// Build a target from a vhost `WebSocketMap`. The map's `address` is a bare
    /// `host:port` (LiteSpeed form); scheme is set to `ws`.
    pub fn from_websocket_map(ws: &WebSocketMap) -> ProxyTarget {
        let addr = ws.address.trim();
        // Allow an explicit ws://… address too.
        if addr.contains("://") {
            if let Ok(mut t) = Self::parse_url(addr) {
                if t.scheme == "http" {
                    t.scheme = "ws".into();
                }
                return t;
            }
        }
        let authority = authority_raw_with_port(addr, "ws");
        ProxyTarget {
            scheme: "ws".into(),
            authority: authority.clone(),
            transport: TargetTransport::Tcp(authority),
            path_and_query: String::new(),
            name: None,
            max_conns: None,
            keep_alive: None,
            connect_timeout: None,
            retry_timeout: None,
        }
    }
}

impl fmt::Display for ProxyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}{}",
            self.scheme, self.authority, self.path_and_query
        )
    }
}

/// Default the port if the authority lacks one, returning `host:port`.
fn authority_raw_with_port(authority: &str, scheme: &str) -> String {
    // IPv6 literal `[::1]:port` or `[::1]`.
    if authority.starts_with('[') {
        if authority.contains("]:") {
            return authority.to_string();
        }
        let port = default_port(scheme);
        return format!("{authority}:{port}");
    }
    if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:{}", default_port(scheme))
    }
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" | "wss" => 443,
        _ => 80,
    }
}

/// Ensure the upstream path starts with `/` (the `find('/')` split already
/// guarantees this for parsed URLs, but rewrite output may omit it).
fn normalize_path(p: &str) -> String {
    if p.is_empty() {
        String::new()
    } else if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid proxy target: {0}")]
pub struct TargetParseError(pub String);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    use hj_core::config::{ExtKind, WebSocketMap};
    use std::time::Duration;

    #[test]
    fn parse_basic_http_with_path() {
        let t = ProxyTarget::parse_url("http://127.0.0.1:8002/tools.json").unwrap();
        assert_eq!(t.scheme, "http");
        assert_eq!(t.authority, "127.0.0.1:8002");
        assert_eq!(t.transport, TargetTransport::Tcp("127.0.0.1:8002".into()));
        assert_eq!(t.path_and_query, "/tools.json");
        assert!(!t.is_tls());
        assert!(!t.is_websocket());
    }

    #[test]
    fn parse_localhost_default_port() {
        let t = ProxyTarget::parse_url("http://localhost/$1").unwrap();
        assert_eq!(t.authority, "localhost:80");
        assert_eq!(t.path_and_query, "/$1");
    }

    #[test]
    fn parse_https_default_port() {
        let t = ProxyTarget::parse_url("https://backend.internal/api/v1").unwrap();
        assert_eq!(t.authority, "backend.internal:443");
        assert!(t.is_tls());
    }

    #[test]
    fn parse_no_path() {
        let t = ProxyTarget::parse_url("http://127.0.0.1:2812").unwrap();
        assert_eq!(t.authority, "127.0.0.1:2812");
        assert_eq!(t.path_and_query, "");
    }

    #[test]
    fn parse_query_only_absolute_target() {
        let t = ProxyTarget::parse_url("http://backend.internal?health=1").unwrap();
        assert_eq!(t.authority, "backend.internal:80");
        assert_eq!(t.path_and_query, "/?health=1");
    }

    #[test]
    fn parse_ws_scheme() {
        let t = ProxyTarget::parse_url("ws://127.0.0.1:8080/ws").unwrap();
        assert!(t.is_websocket());
        assert_eq!(t.authority, "127.0.0.1:8080");
    }

    #[test]
    fn parse_ipv6() {
        let t = ProxyTarget::parse_url("http://[::1]:9000/x").unwrap();
        assert_eq!(t.authority, "[::1]:9000");
        let t2 = ProxyTarget::parse_url("http://[::1]/x").unwrap();
        assert_eq!(t2.authority, "[::1]:80");
    }

    #[test]
    fn parse_unix_socket() {
        let t = ProxyTarget::parse_url("unix:/var/run/app.sock|/upstream/path").unwrap();
        assert_eq!(
            t.transport,
            TargetTransport::Uds("/var/run/app.sock".into())
        );
        assert_eq!(t.path_and_query, "/upstream/path");
    }

    #[test]
    fn parse_rejects_unknown_scheme() {
        assert!(ProxyTarget::parse_url("ftp://x/y").is_err());
        assert!(ProxyTarget::parse_url("").is_err());
        assert!(ProxyTarget::parse_url("noscheme").is_err());
    }

    #[test]
    fn from_ext_processor_tcp() {
        let ep = ExtProcessor {
            name: "mcp-api".into(),
            kind: ExtKind::Proxy,
            address: ExtAddress::Tcp("127.0.0.1:8002".parse::<SocketAddr>().unwrap()),
            max_conns: 100,
            init_timeout: Duration::from_secs(60),
            retry_timeout: Duration::from_secs(0),
            pc_keep_alive_timeout: Duration::from_secs(60),
            resp_buffer: false,
            env: vec![],
            auto_start: 0,
            path: None,
            backlog: 0,
            instances: 1,
            run_on_startup: 0,
        };
        let t = ProxyTarget::from_ext_processor(&ep);
        assert_eq!(t.authority, "127.0.0.1:8002");
        assert_eq!(t.name.as_deref(), Some("mcp-api"));
        assert_eq!(t.pool_key(), "ext:mcp-api:tcp:http://127.0.0.1:8002");
        assert_eq!(t.max_conns, Some(100));
        assert_eq!(t.keep_alive, Some(Duration::from_secs(60)));
        assert_eq!(t.connect_timeout, Some(Duration::from_secs(60)));
    }

    #[test]
    fn from_websocket_map_bare_hostport() {
        let ws = WebSocketMap {
            uri: "/".into(),
            address: "127.0.0.1:8001".into(),
        };
        let t = ProxyTarget::from_websocket_map(&ws);
        assert!(t.is_websocket());
        assert_eq!(t.authority, "127.0.0.1:8001");
    }

    #[test]
    fn pool_key_distinguishes_adhoc() {
        let a = ProxyTarget::parse_url("http://127.0.0.1:8002/a").unwrap();
        let b = ProxyTarget::parse_url("http://127.0.0.1:8003/b").unwrap();
        assert_ne!(a.pool_key(), b.pool_key());
        // Path does not affect the pool key.
        let c = ProxyTarget::parse_url("http://127.0.0.1:8002/different").unwrap();
        assert_eq!(a.pool_key(), c.pool_key());
    }
}
