//! `hj-http`: the per-connection serve-tuning config ([`ServeConfig`]) shared by the
//! request transport.
//!
//! Historically this crate also held the tokio HTTP/1.1 (hyper) and HTTP/3 (quinn)
//! transport adapters. Those were removed once the pure-io_uring (monoio) transport
//! became the ONLY transport: H1/h2c, TLS H1/H2, and H3 are now served by `crate::uring`
//! (in the `httpjet` binary) over io_uring, bridging into the shared tokio pipeline.
//! What remains here is the protocol-agnostic tuning the orchestrator derives from the
//! LiteSpeed `<tuning>` block (via [`ServeConfig::from_tuning`]) and stamps onto
//! `ServerState`, where the io_uring H1/H2/H3 paths read it (deadlines + size caps).

use std::time::Duration;

pub use hj_core::budget::BandwidthThrottle;

/// Tunables applied to each served connection.
///
/// These mirror the LiteSpeed connection-tuning knobs the orchestrator reads from
/// [`hj_core::config::Tuning`]. Defaults are conservative and safe for a public-facing
/// server. The io_uring transport reads these off `ServerState::serve_config`.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// (Tier 2) Per-connection bandwidth limit (bytes/sec). 0 = unlimited.
    pub bandwidth_limit: u64,
    /// h1 keep-alive: `Some(d)` keeps the connection open between requests and bounds the
    /// idle wait at `d` (the io_uring H1 loop arms this on the next-request read);
    /// `None` disables keep-alive (one request per connection). HTTP/2 has its own
    /// idle/preface timeouts in the native hj-h2 stack and ignores this.
    pub keep_alive_timeout: Option<Duration>,
    /// Maximum time allowed to read the request head (h1). Bounds a slowloris that
    /// dribbles or never completes the header block; the io_uring H1 loop applies it to
    /// the head read (and the TLS handshake). `None` leaves the read unbounded.
    pub header_read_timeout: Option<Duration>,
    /// Maximum number of requests to serve on a single keep-alive connection before
    /// signaling the client to close (h1). `0` means unlimited.
    pub max_keepalive_requests: u32,
    /// Max request header buffer (bytes). Mirrors LiteSpeed `maxReqHeaderSize`; the
    /// io_uring H1 path caps its head buffer at this, and the native h2/h3 paths advertise
    /// + enforce it as `SETTINGS_MAX_HEADER_LIST_SIZE` / `max_field_section_size`.
    pub max_req_header_size: usize,
    /// Max buffered request body size for transports that must assemble a body before
    /// dispatch. Mirrors LiteSpeed `maxReqBodySize` (io_uring H1/H3 + native h2 enforce it).
    pub max_req_body_size: usize,
    /// Max request-target (path + query) length. Mirrors LiteSpeed `maxReqURLLen`;
    /// enforced in the pipeline (`414 URI Too Long`).
    pub max_req_url_len: usize,
}

impl Default for ServeConfig {
    fn default() -> Self {
        ServeConfig {
            keep_alive_timeout: Some(Duration::from_secs(75)),
            header_read_timeout: Some(Duration::from_secs(30)),
            max_keepalive_requests: 1000,
            max_req_header_size: 16380,
            max_req_body_size: 100 * 1024 * 1024,
            max_req_url_len: 8192,
            bandwidth_limit: 0,
        }
    }
}

impl ServeConfig {
    /// Build a [`ServeConfig`] from the server-wide [`hj_core::config::Tuning`] block,
    /// translating LiteSpeed semantics: a `0` keep-alive timeout means "no keep-alive".
    pub fn from_tuning(t: &hj_core::config::Tuning) -> Self {
        let keep_alive_timeout = if t.keep_alive_timeout.is_zero() {
            None
        } else {
            Some(t.keep_alive_timeout)
        };
        let header_read_timeout = if t.conn_timeout.is_zero() {
            None
        } else {
            Some(t.conn_timeout)
        };
        ServeConfig {
            keep_alive_timeout,
            header_read_timeout,
            max_keepalive_requests: t.max_keep_alive_req,
            max_req_header_size: t.max_req_header_size,
            max_req_body_size: t.max_req_body_size as usize,
            max_req_url_len: t.max_req_url_len,
            bandwidth_limit: t.bandwidth_limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_config_defaults_enable_keepalive_and_surface_limits() {
        let c = ServeConfig::default();
        assert!(
            c.keep_alive_timeout.is_some(),
            "h1 keep-alive on by default"
        );
        assert_eq!(c.max_req_header_size, 16380);
        assert_eq!(c.max_req_url_len, 8192);
    }

    #[test]
    fn from_tuning_disables_keepalive_when_timeout_zero() {
        let t = hj_core::config::Tuning {
            keep_alive_timeout: Duration::ZERO,
            ..hj_core::config::Tuning::default()
        };
        let c = ServeConfig::from_tuning(&t);
        assert_eq!(c.keep_alive_timeout, None);
    }
}
