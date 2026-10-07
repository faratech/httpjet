#!/usr/bin/env bash
# deps-advisory.sh — fail when RustSec reports anything for Cargo.lock, or when a
# transport-critical crate has a newer compatible release than the lockfiles pin.
#
# Advisory databases lag upstream security releases: quinn-proto 0.11.19 (2026-09-30,
# GHSA-53rm-773f-4q8c) was in neither RustSec nor Dependabot six days later. The
# version watch is the early signal; review the upstream changelog when it fires.
#
# Usage: [REPORT=path.md] bash scripts/deps-advisory.sh
# Exit status: 0 clean, 1 findings (report lists them), 2 tool failure.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CRITICAL='quinn-proto|quinn-udp|rustls|rustls-webpki|rustls-pki-types|aws-lc-rs|aws-lc-sys|tokio|httparse|io-uring|zstd-safe|zstd-sys|brotli|brotli-decompressor|h2|hyper|http|mio|socket2|openssl|openssl-sys|bcrypt|libc'
report="$(mktemp)"
trap 'rm -f "$report" "$report.audit" "$report.update"' EXIT
findings=0

command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1 || {
  echo "cargo-audit is required (cargo install cargo-audit --locked)" >&2
  exit 2
}

{
  echo "# Dependency advisory report"
  echo
  echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) at $(git rev-parse --short HEAD 2>/dev/null || echo unknown)."
  echo
  echo "## RustSec (cargo audit, warnings denied)"
  echo
} >"$report"
if cargo audit --deny warnings >"$report.audit" 2>&1; then
  echo "No advisories." >>"$report"
else
  findings=1
  { echo '```'; grep -vE '^\s*(Fetching|Loaded|Updating|Scanning)' "$report.audit"; echo '```'; } >>"$report"
fi

for manifest in Cargo.toml fuzz/Cargo.toml; do
  [ -f "$manifest" ] || continue
  { echo; echo "## Newer compatible transport-critical releases (${manifest%Cargo.toml}Cargo.lock)"; echo; } >>"$report"
  if ! cargo update --dry-run --manifest-path "$manifest" >"$report.update" 2>&1; then
    { echo '```'; cat "$report.update"; echo '```'; } >>"$report"
    exit 2
  fi
  pending="$(grep -E "^\s*Updating ($CRITICAL) v" "$report.update" | sed 's/^ *//' || true)"
  if [ -n "$pending" ]; then
    findings=1
    { echo '```'; echo "$pending"; echo '```'; } >>"$report"
  else
    echo "None." >>"$report"
  fi
done

[ -n "${REPORT:-}" ] && cp "$report" "$REPORT"
cat "$report"
exit "$findings"
