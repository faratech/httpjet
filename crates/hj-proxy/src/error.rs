//! Proxy-layer error type and its mapping to [`hj_core::HandlerError`].

use hj_core::HandlerError;

/// Errors raised while connecting to or talking with an upstream.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProxyError {
    #[error("upstream connect failed: {0}")]
    Connect(#[source] std::io::Error),
    #[error("upstream connect timed out")]
    ConnectTimeout,
    #[error("upstream handshake failed: {0}")]
    Handshake(String),
    #[error("upstream request failed: {0}")]
    Request(String),
    #[error("upstream response timed out")]
    ResponseTimeout,
    #[error("request body upload stalled (no progress within the inactivity timeout)")]
    BodyTimeout,
    #[error("upstream circuit breaker open (too many recent connect failures)")]
    CircuitOpen,
    #[error("{0}")]
    Other(String),
}

impl ProxyError {
    /// Map this error to the gateway-style [`HandlerError`] the pipeline expects.
    /// Connect failures, handshake errors and request errors become `502`;
    /// timeouts become `504`.
    pub(crate) fn into_handler_error(self) -> HandlerError {
        match self {
            ProxyError::ConnectTimeout | ProxyError::ResponseTimeout | ProxyError::BodyTimeout => {
                HandlerError::GatewayTimeout
            }
            ProxyError::Connect(_)
            | ProxyError::Handshake(_)
            | ProxyError::Request(_)
            | ProxyError::CircuitOpen => HandlerError::BadGateway(self.to_string()),
            ProxyError::Other(_) => HandlerError::BadGateway(self.to_string()),
        }
    }
}

impl From<ProxyError> for HandlerError {
    fn from(e: ProxyError) -> Self {
        e.into_handler_error()
    }
}
