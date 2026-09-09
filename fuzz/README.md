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

`.github/workflows/fuzz.yml` runs all five targets nightly/manually with at most
two concurrent jobs. Corpora/crash artifacts and the lockfile are retained for
14 days, including on failure. Jobs start from checked-in seeds, not automatically
trusted artifacts from prior runs. Review/minimize failures and promote useful
inputs to `seeds/` (H1) or crate regression tests. The short local smoke runs are
not evidence of vulnerability absence or a completed exhaustive fuzz campaign.
