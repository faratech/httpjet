#!/usr/bin/env bash
# Source-build one native, fully static musl payload. No arbitrary binary input.
set -euo pipefail
if [ "$#" -ne 2 ]; then echo 'usage: build-musl.sh ARCH OUTPUT_BINARY' >&2; exit 2; fi
payload_arch=$1
payload_output=$(realpath -m "$2")
payload_root=$(cd "$(dirname "$0")/../.." && pwd)
case "$payload_arch:$(uname -m)" in
  amd64:x86_64) payload_target=x86_64-unknown-linux-musl; payload_cpu=x86-64; payload_cflags='-O2 -march=x86-64 -mtune=generic' ;;
  arm64:aarch64|arm64:arm64) payload_target=aarch64-unknown-linux-musl; payload_cpu=generic; payload_cflags='-O2 -march=armv8-a -mtune=generic' ;;
  *) echo 'payload must build natively on amd64 or arm64' >&2; exit 1 ;;
esac
for payload_tool in rustup rustc cargo musl-gcc readelf python3; do
  command -v "$payload_tool" >/dev/null || { echo "static build needs $payload_tool" >&2; exit 1; }
done
export RUSTUP_TOOLCHAIN=1.99.1
[ "$(rustc --version | awk '{print $2}')" = 1.99.1 ] || { echo 'Rust1.99.1 required' >&2; exit 1; }
rustup target add --toolchain 1.99.1 "$payload_target"
export RUSTFLAGS="-Ctarget-cpu=$payload_cpu -Cforce-frame-pointers=yes -Ctarget-feature=+crt-static -Clinker=musl-gcc"
unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET
export CC=musl-gcc CXX=musl-gcc TARGET_CC=musl-gcc TARGET_CXX=musl-gcc
export CFLAGS="$payload_cflags" CXXFLAGS="$payload_cflags" TARGET_CFLAGS="$payload_cflags" TARGET_CXXFLAGS="$payload_cflags"
export AWS_LC_SYS_CFLAGS="$payload_cflags" CARGO_INCREMENTAL=0
payload_target_key=${payload_target//-/_}
cd "$payload_root"
env "CC_$payload_target=musl-gcc" "CC_$payload_target_key=musl-gcc" \
    "CXX_$payload_target=musl-gcc" "CXX_$payload_target_key=musl-gcc" \
    "CFLAGS_$payload_target=$payload_cflags" "CFLAGS_$payload_target_key=$payload_cflags" \
    "CXXFLAGS_$payload_target=$payload_cflags" "CXXFLAGS_$payload_target_key=$payload_cflags" \
    cargo rustc --locked --release -p httpjet --bin httpjet --target "$payload_target" \
      -- -C link-arg=-Wl,--no-dynamic-linker
install -D -m0755 "${CARGO_TARGET_DIR:-target}/$payload_target/release/httpjet" "$payload_output"
python3 "$payload_root/packaging/release/build-session.py" elf "$payload_output" "$payload_arch"
