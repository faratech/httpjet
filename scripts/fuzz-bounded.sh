#!/usr/bin/env bash
# Bounded, single-process ASan fuzz job; no server sockets or production state.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
target=${1:?supply a fuzz target}
case "$target" in
  h1_chunked_decode|h1_request_framing)
    python3 -B scripts/fuzz-seeds.py "$target" ;;
  hpack_decode|hpack_roundtrip|lsapi_resp_header) ;;
  *) echo "unknown fuzz target" >&2; exit 2 ;;
esac
seconds=${FUZZ_SECONDS:-300}
[[ "$seconds" =~ ^[1-9][0-9]{0,2}$ ]] && (( seconds <= 600 )) || {
  echo "FUZZ_SECONDS must be 1..600" >&2; exit 2;
}
toolchain=${FUZZ_TOOLCHAIN:-nightly-2026-08-31}
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
export CARGO_INCREMENTAL=0
mkdir -p "fuzz/artifacts/$target"
# Fetch against the committed lock before cargo-fuzz (which has no --locked).
cargo "+$toolchain" fetch --manifest-path fuzz/Cargo.toml --locked
lock_before=$(sha256sum fuzz/Cargo.lock)
timeout --kill-after=10s 900s env CARGO_NET_OFFLINE=true \
  cargo "+$toolchain" fuzz build "$target"
set +e
timeout --kill-after=10s "$((seconds + 30))s" env CARGO_NET_OFFLINE=true \
  cargo "+$toolchain" fuzz run "$target" -- \
  "-max_total_time=$seconds" -timeout=5 -max_len=4096 -rss_limit_mb=1536 \
  -print_final_stats=1 -print_funcs=0
result=$?
set -e
[[ "$(sha256sum fuzz/Cargo.lock)" = "$lock_before" ]] || {
  echo "cargo-fuzz modified the pinned lockfile" >&2; exit 1;
}
exit "$result"
