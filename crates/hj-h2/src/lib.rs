//! hj-h2: httpjet's native HTTP/2 server transport.
//!
//! Serves every ALPN-confirmed h2-over-TLS connection (hyper still handles HTTP/1.1).
//! One tokio task per connection multiplexes all of its streams concurrently — no
//! per-stream spawn — via `FuturesUnordered`, with a connection-scoped [`hpack`]
//! codec for headers. Response bodies (in-memory, streaming PHP/proxy/SSE, and
//! async-streamed files) are written under HTTP/2 send flow control and coalesced
//! into one vectored write per wake, with large bodies referenced zero-copy from
//! page-cache `Bytes`. Inbound frames are validated for RFC 7540 conformance
//! (stream association/state, frame sizes, header-block continuity, §8.1.2 request
//! headers). Plugs into [`hj_core`]'s frozen service closure, so handlers and
//! response transforms are unchanged.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod conn;
pub mod frame;
pub mod hpack;
#[cfg(feature = "monoio")]
pub mod owned_iovec;
pub mod server;
