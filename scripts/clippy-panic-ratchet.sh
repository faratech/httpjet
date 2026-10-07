#!/usr/bin/env bash
# clippy-panic-ratchet.sh — keep panic-capable code in the request-serving crates from
# growing. Release builds use panic = "abort", so a reachable unwrap/expect/index/panic
# restarts the server. Counts clippy's unwrap_used / expect_used / indexing_slicing /
# panic / unreachable warnings per (file, lint) in non-test code of httpjet, hj-h2 and
# hj-lsapi, and fails when any count exceeds scripts/clippy-panic-baseline.txt.
#
# Usage: bash scripts/clippy-panic-ratchet.sh [--update]
#   --update rewrites the baseline (commit it with the change that justified it).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BASELINE=scripts/clippy-panic-baseline.txt

current="$(mktemp)"
trap 'rm -f "$current"' EXIT
cargo clippy --locked -p httpjet -p hj-h2 -p hj-lsapi --message-format=json 2>/dev/null \
  | python3 -I -c '
import json, sys, collections
lints = {"clippy::unwrap_used", "clippy::expect_used", "clippy::indexing_slicing",
         "clippy::panic", "clippy::unreachable"}
counts, seen = collections.Counter(), set()
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    m = msg.get("message") or {}
    code = (m.get("code") or {}).get("code")
    spans = [s for s in m.get("spans", []) if s.get("is_primary")]
    if code not in lints or not spans:
        continue
    span = spans[0]
    key = (span["file_name"], span["line_start"], span["column_start"], code)
    if key in seen:
        continue
    seen.add(key)
    counts[(span["file_name"], code.split("::", 1)[1])] += 1
for (path, lint), n in sorted(counts.items()):
    print(path, lint, n)
' >"$current"

if [ "${1:-}" = "--update" ]; then
  cp "$current" "$BASELINE"
  echo "baseline updated: $(wc -l <"$BASELINE") file/lint entries"
  exit 0
fi
[ -f "$BASELINE" ] || { echo "missing $BASELINE (run with --update)" >&2; exit 2; }

status=0
while read -r file lint count; do
  allowed="$(awk -v f="$file" -v l="$lint" '$1==f && $2==l {print $3}' "$BASELINE")"
  if [ "$count" -gt "${allowed:-0}" ]; then
    echo "panic ratchet: $file $lint $count > baseline ${allowed:-0}"
    status=1
  fi
done <"$current"
[ "$status" = 0 ] && echo "panic ratchet: no growth ($(awk '{s+=$3} END {print s+0}' "$current") sites tracked)"
exit "$status"
