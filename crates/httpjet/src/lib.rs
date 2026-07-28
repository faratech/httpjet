//! Library surface of the `httpjet` package.
//!
//! The binary (`src/main.rs`) is the real server; this lib exists only to expose a
//! few pure, std-only modules to out-of-tree tooling (the `fuzz/` harnesses) without
//! dragging in the async / monoio / TLS stack. It shares source with the binary via
//! `#[path]`, so the fuzzed code is byte-for-byte the served code.

/// Pure HTTP/1.1 request-framing primitives (chunked decode, CL/TE classification).
/// Same file the binary compiles as `uring::codec`; the request smuggling /
/// chunked-desync bug class lives here, so it is the fuzz target surface.
#[path = "uring/codec.rs"]
pub mod codec;
