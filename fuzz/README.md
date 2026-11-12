# Fuzzing

The out-of-workspace `cargo-fuzz` suite covers HPACK, HTTP/2 frame handling, LSAPI
response headers and packet streams, FastCGI records, HTTP/1 framing/chunked decoding,
HTTP/3 QPACK field sections and wire parsers, PROXY protocol v1/v2 headers, the
page-cache control headers the application emits, and the page-cache container format.

```bash
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run <target> -- -max_total_time=300
```

Targets: `hpack_decode`, `hpack_roundtrip`, `h2_frames`, `lsapi_resp_header`,
`lsapi_packet_stream`, `fastcgi_records`, `h1_chunked_decode`, `h1_request_framing`,
`qpack_decode`, `h3_request_stream`, `h3_control`, `proxy_protocol_parse`,
`lscache_control`, and `pagecache_container`. QPACK and PROXY protocol parsing live in
std-only modules
(`uring/qpack.rs`, `uring/proxy_protocol_wire.rs`) so the targets include the exact
server source; `proxy_protocol_parse` has reviewed seeds carrying the v2 signature.

Four targets assert behaviour rather than only the absence of a crash:

- `h2_frames` drives the whole HTTP/2 server (`hj_h2::server::serve`) over an in-memory
  pipe with a paused clock. What the server writes back must be whole frames, on client
  streams only, with nothing sent on a stream it already ended.
- `lsapi_packet_stream` runs the production LSAPI packet reader through a seam compiled
  only with `--cfg fuzzing` (`hj_lsapi::handler::fuzz_read_packets`). The packets must
  not depend on how the bytes were split across reads and must equal what `LsapiCodec`
  decodes.
- `fastcgi_records` checks that records parsed from the whole input equal records parsed
  byte by byte, and that a parsed STDOUT record survives an encode/parse round trip.
- `pagecache_container` takes a whole page-cache container file and runs the boot scan's
  decode of its header and metadata block through a `--cfg fuzzing` seam
  (`hj_pagecache::diskstore::fuzzing::Container`). The lengths it reports must add up to
  the input, and the metadata block the store writes for what it decoded must have the
  same length and decode to the same metadata. No integrity key is installed, so the
  tag is not checked. `fuzz/Cargo.toml` repeats the server workspace's `dashmap` patch
  for this target: the page cache builds against `vendor/dashmap`.

The two HTTP/3 targets include the std-only `uring/h3_wire.rs` (with `uring/qpack.rs`
and `uring/codec.rs`) and assert behaviour as well:

- `h3_request_stream` gives a request stream to `H3FrameCounter` at once and in small
  reads, under header and body limits the input selects. Both deliveries must report the
  same result, field sections, body and request; what is buffered must stay within the
  limits; and a stream taken without an error must hold the frames a plain walk of the
  same bytes finds.
- `h3_control` does the same for the control-stream parser and for a bare SETTINGS
  payload. The settings must equal an independent decode of the payload, a SETTINGS
  frame over the payload bound must be refused, and the identifiers the parser remembers
  are bounded by the bytes it was given. The varint reader is compared with a one-shot
  decode on every input.

Not covered yet: the HTTP/3 code that works on connection state and stays in
`uring/h3.rs` (stream-type dispatch, per-connection byte accounting).

Minimize a crash with:

```bash
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-XXXX
```

Then add the minimized input as a regression test in the owning crate.

## Continuous checks

The two H1 targets and `crates/httpjet/tests/h1_corpus.rs` call the same
`h1_properties.rs` functions against the exact codec source used by the server.
Reviewed seeds are stored as hex in `seeds/`; `-` represents an empty input.
Stable-Rust CI replays them, every truncation and bounded single-byte mutations:

```bash
cargo test --locked -p httpjet --test h1_corpus -- --nocapture
```

For local ASan fuzzing with explicit budgets:

```bash
# Default pinned toolchain: nightly-2026-08-31; cargo-fuzz 0.13.2.
FUZZ_SECONDS=300 bash scripts/fuzz-bounded.sh h1_request_framing
```

The wrapper validates the target/time, materializes H1 seeds without overwriting
existing corpus entries, fetches against the committed fuzz lockfile, builds
offline, and rejects successful runs that change the lockfile. Build timeout is
900 seconds; execution has a separate requested-budget-plus-30-second wall cap
and 10-second forced-termination grace. libFuzzer additionally limits each input
to 5 seconds, input length to 4096 bytes and RSS to 1536 MiB. `FUZZ_SECONDS` is
1..600 (default 300). `FUZZ_TOOLCHAIN` can select an installed local nightly.
New-function symbol printing is disabled because host LLVM symbolizers can stall;
sanitizer diagnostics remain enabled and bounded by the wall timeout.

The `fuzz.yml` workflow, kept in the public repository, runs the listed targets weekly
and on demand with at most two concurrent jobs. A new target has to be added to that
workflow's matrix and to the allowlist in `scripts/fuzz-bounded.sh`. Corpora/crash artifacts and the lockfile are retained for
14 days, including on failure. Jobs start from checked-in seeds, not automatically
trusted artifacts from prior runs. Review/minimize failures and promote useful
inputs to `seeds/` (H1) or crate regression tests. The short local smoke runs are
not evidence of vulnerability absence or a completed exhaustive fuzz campaign.
