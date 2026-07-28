//! The `Handler` and `ResponseTransform` contracts — the integration seam the
//! static/lsapi/proxy/rewrite crates implement.

use async_trait::async_trait;

use crate::body::{Body, IncomingBody};
use crate::context::ReqCtx;

/// A request as seen by handlers: standard `http::Request` with a type-erased
/// incoming body.
pub type Request = http::Request<IncomingBody>;

/// A response a handler produces.
pub type Response = http::Response<Body>;

#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("not found")]
    NotFound,
    #[error("forbidden")]
    Forbidden,
    #[error("bad gateway: {0}")]
    BadGateway(String),
    #[error("service unavailable")]
    ServiceUnavailable,
    #[error("upstream timeout")]
    GatewayTimeout,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("request header fields too large")]
    RequestHeaderFieldsTooLarge,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl HandlerError {
    /// HTTP status code this error maps to.
    pub fn status(&self) -> http::StatusCode {
        use http::StatusCode as S;
        match self {
            HandlerError::NotFound => S::NOT_FOUND,
            HandlerError::Forbidden => S::FORBIDDEN,
            HandlerError::BadGateway(_) => S::BAD_GATEWAY,
            HandlerError::ServiceUnavailable => S::SERVICE_UNAVAILABLE,
            HandlerError::GatewayTimeout => S::GATEWAY_TIMEOUT,
            HandlerError::PayloadTooLarge => S::PAYLOAD_TOO_LARGE,
            HandlerError::RequestHeaderFieldsTooLarge => S::REQUEST_HEADER_FIELDS_TOO_LARGE,
            HandlerError::Io(_) | HandlerError::Other(_) => S::INTERNAL_SERVER_ERROR,
        }
    }
}

/// A terminal request handler (static files, LSAPI/PHP, reverse proxy, ...).
#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(&self, ctx: &mut ReqCtx, req: Request) -> Result<Response, HandlerError>;
}

/// A response post-processor (expires headers, ETag/conditional, compression,
/// access logging, ...). Applied in order after the terminal handler.
#[async_trait]
pub trait ResponseTransform: Send + Sync {
    async fn transform(&self, ctx: &ReqCtx, resp: &mut Response);
}

/// Build a simple buffered response with a status and text/plain body.
pub fn text_response(status: http::StatusCode, body: impl Into<Body>) -> Response {
    let mut resp = http::Response::new(body.into());
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}
