//! httpjet core contracts: the protocol-agnostic request/response types, the
//! [`Handler`]/[`ResponseTransform`] traits, per-request [`ReqCtx`], and the
//! vhost [`Router`]. Other crates implement handlers/transforms against these.

pub mod body;
pub mod budget;
pub mod context;
pub mod handler;
pub mod http_util;
pub mod net;
pub mod reqid;
pub mod router;

pub use body::{Body, BoxError, CountingBody, FileBody, IncomingBody, StreamBody, empty_incoming};
pub use context::{ClientCert, Proto, RedirectGuard, ReqCtx, TlsParams};
pub use handler::{Handler, HandlerError, Request, Response, ResponseTransform, text_response};
pub use http_util::{
    CONNECTION_SPECIFIC_REQUEST_HEADERS, body_forbidden_status, coalesce_cookie_crumbs,
    header_value_lossy, http_date_now, if_none_match_matches,
    is_connection_specific_request_header, percent_decode, percent_decode_cow,
    response_body_forbidden, sanitize_h2_h3_body_headers, stamp_date, strip_hop_by_hop_response,
};
pub use net::{host_without_port, is_trusted_internal_peer};
pub use reqid::ReqId;
pub use router::{ResolvedVhost, Router};

// Re-export the config model so downstream crates can `use hj_core::config::*`.
pub mod config {
    pub use hj_config::model::*;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn body_content_length() {
        assert_eq!(Body::Empty.content_length(), Some(0));
        assert_eq!(
            Body::Full(Bytes::from_static(b"hello")).content_length(),
            Some(5)
        );
    }

    #[test]
    fn text_response_builds() {
        let r = text_response(http::StatusCode::NOT_FOUND, "nope");
        assert_eq!(r.status(), http::StatusCode::NOT_FOUND);
        assert!(r.headers().contains_key(http::header::CONTENT_TYPE));
    }
}
