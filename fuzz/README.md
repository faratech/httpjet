# httpjet fuzz harnesses

Out-of-workspace `cargo-fuzz` suite for the untrusted-byte parsers. It is **not** a
workspace member (own `[workspace]` in `Cargo.toml`), so `cargo build` / `cargo test`
over `crates/*` never see its nightly-only tooling. The crate uses edition 2024 and
requires Rust 1.97; fuzzing
needs nightly + libFuzzer; always invoke per-call with `+nightly` (do **not** add a
`rust-toolchain.toml` — that would force nightly on the whole repo / PGO build).

## Targets

| target | crate | what it fuzzes |
|--------|-------|----------------|
| `hpack_decode` | hj-h2 | HPACK decoder on arbitrary bytes — no panic |
| `hpack_roundtrip` | hj-h2 | encode→decode equality (encoder/decoder divergence, dynamic-table desync) |
| `lsapi_resp_header` | hj-lsapi | LSAPI RESP_HEADER length-array parser — no panic |
| `h1_chunked_decode` | uring/codec.rs | chunked decoder — no panic, in-bounds `Done`, one-shot == incremental |
| `h1_request_framing` | uring/codec.rs | segmentation-independent request-head limits plus the RFC 7230 §3.3.3 framing invariant |

The H1 targets `#[path]`-include `crates/httpjet/src/uring/codec.rs` directly — the
**same source the server compiles** (so fuzzed code can't diverge from served code),
without dragging monoio/quinn/TLS into the ASan build.

## Run

```bash
cargo +nightly install cargo-fuzz          # one-time
cargo +nightly fuzz run <target> -- -max_total_time=300
```

## When a crash is found

```bash
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-XXXX
```

Then promote the minimized bytes to a hardcoded `#[test]` in the **owning crate** (the
project convention), so the stable test suite guards the regression forever:
- H1 codec → `crates/httpjet/src/uring/codec.rs` `mod tests`
- HPACK → `crates/hj-h2/tests/`
- LSAPI → `crates/hj-lsapi/tests/`

## Seeding the corpus (optional)

Seed from the existing byte-frame builders for faster coverage:
`crates/hj-lsapi/tests/dispatch.rs` (`put_packet` / `resp_header_body`),
`crates/hj-h2/tests/server_conformance.rs` (HEADERS blocks), and the inline
`chunked_tests` vectors in `crates/httpjet/src/uring/mod.rs`.
