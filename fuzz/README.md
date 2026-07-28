# Fuzzing

The out-of-workspace `cargo-fuzz` suite covers HPACK, LSAPI response headers,
and HTTP/1 framing/chunked decoding.

```bash
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run <target> -- -max_total_time=300
```

Targets: `hpack_decode`, `hpack_roundtrip`, `lsapi_resp_header`,
`h1_chunked_decode`, and `h1_request_framing`.

Minimize a crash with:

```bash
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-XXXX
```

Then add the minimized input as a regression test in the owning crate.
