//! Bounded FastCGI client primitives.
//!
//! The crate is deliberately not wired into request routing yet. Protocol,
//! pooling and script-target validation land independently so an incomplete
//! gateway can never turn a configured script into source-file serving.

mod handler;
mod pool;
mod proto;
mod response;

pub use handler::{FastCgi, FastCgiScript};
pub use pool::{Endpoint, FastCgiPool, PoolError};
pub use proto::{
    FCGI_KEEP_CONN, FCGI_RESPONDER, Record, RecordType, WireError, begin_request,
    encode_name_value_pairs, encode_stream, end_request, end_stream, parse_record,
};
pub use response::{CgiHead, ResponseError, parse_cgi_head, parse_end_request};
