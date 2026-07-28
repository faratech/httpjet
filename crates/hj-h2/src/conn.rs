//! Connection-level constants for the HTTP/2 server.
//!
//! The framed-I/O state machine now lives in [`crate::server`] (a split-read/write,
//! cancel-safe, multiplexing loop); this module just holds the connection preface.

/// The HTTP/2 connection preface a client sends first (RFC 7540 §3.5).
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
