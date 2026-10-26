#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 2 ]; then echo 'usage: build-probe.sh ARCH OUTPUT' >&2; exit 2; fi
probe_arch=$1
probe_output=$(realpath -m "$2")
probe_root=$(cd "$(dirname "$0")/../.." && pwd)
case "$probe_arch:$(uname -m)" in
  amd64:x86_64) probe_flags=(-march=x86-64 -mtune=generic) ;;
  arm64:aarch64|arm64:arm64) probe_flags=(-march=armv8-a -mtune=generic) ;;
  *) echo 'qualification probe must build natively' >&2; exit 1 ;;
esac
# musl user headers take precedence; Linux UAPI/asm headers are libc-neutral.
probe_gnu_triplet=$(gcc -dumpmachine)
musl-gcc -O2 -static -Wall -Wextra -Werror "${probe_flags[@]}" \
    -idirafter /usr/include -idirafter "/usr/include/$probe_gnu_triplet" \
    "$probe_root/packaging/release/io-uring-probe.c" -o "$probe_output"
python3 "$probe_root/packaging/release/build-session.py" elf "$probe_output" "$probe_arch"
