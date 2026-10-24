#!/usr/bin/env bash
# Build a minimal LSAPI app against stock and patched lsapilib.c and replay the three
# cases from lsapilib-hardening.patch over a unix socket (needs gcc, python3 and the
# stdlib LSAPI client /web/scripts/lsapi_probe.py, or LSAPI_PROBE=<path>).
#   bash packaging/lsphp/verify/run.sh /path/to/php-src/sapi/litespeed/lsapilib.c
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:?usage: run.sh <stock lsapilib.c>}"
WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/lsapilib-verify.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
cp "$HERE"/harness.c "$HERE"/test_lsapilib.py "$HERE"/php_config.h "$WORK"/
cp -r "$HERE"/Zend "$WORK"/
cp "$(dirname "$SRC")"/lsapilib.h "$(dirname "$SRC")"/lsapidef.h "$WORK"/
cp "$SRC" "$WORK"/lsapilib-orig.c
cp "$SRC" "$WORK"/lsapilib.c
(cd "$WORK" && patch -s -p3 lsapilib.c < "$HERE/../lsapilib-hardening.patch" && mv lsapilib.c lsapilib-patched.c)
for v in orig patched; do
  gcc -O1 -g -fsanitize=address -I"$WORK" -o "$WORK/harness-$v" "$WORK/harness.c" "$WORK/lsapilib-$v.c" -ldl
done
python3 -I "$WORK/test_lsapilib.py"
