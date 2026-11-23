#!/usr/bin/env bash
# update-deps.sh — bump every Rust dependency to its ABSOLUTE latest version.
#
# Unlike `cargo update` (which only moves within the version requirements already
# in Cargo.toml, i.e. semver-compatible), this rewrites the requirements in
# Cargo.toml / [workspace.dependencies] up to the newest published release —
# INCLUDING incompatible (major) bumps — via cargo-edit's `cargo upgrade`, then
# refreshes Cargo.lock and verifies the tree still builds and tests green. Locally
# patched forks are excluded and upgraded manually through vendor/PATCHES.md.
#
# It does NOT commit. It leaves the changes in your working tree so you can review
# `git diff` and keep or revert only the dependency changes.
#
# Usage:
#   scripts/update-deps.sh            # upgrade to latest (incl. major), build + test
#   scripts/update-deps.sh --dry-run  # show what WOULD change, modify nothing
#   scripts/update-deps.sh --no-test  # upgrade + build, skip the test run
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DRY_RUN=0
RUN_TESTS=1
FORK_EXCLUDES=(
  --exclude flume
  --exclude nix
  --exclude hashbrown
  # Keep OpenSSL and hj-ocsp on the same ForeignType traits.
  --exclude foreign-types
)
# Derive fork protection from the actual Cargo patch table so a newly
# vendored crate cannot be missed by the updater.
forks="$(python3 - <<'EOF'
from pathlib import Path
import tomllib

manifest = tomllib.loads(Path("Cargo.toml").read_text())
for name, patch in manifest.get("patch", {}).get("crates-io", {}).items():
    if isinstance(patch, dict) and patch.get("path", "").startswith("vendor/"):
        print(name)
EOF
)"
while IFS= read -r fork; do
  [ -n "$fork" ] && FORK_EXCLUDES+=(--exclude "$fork")
done <<< "$forks"

for a in "$@"; do
  case "$a" in
    --dry-run|-n) DRY_RUN=1 ;;
    --no-test)    RUN_TESTS=0 ;;
    -h|--help)    sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

log() { printf '\033[1;34m[deps %s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
err() { printf '\033[1;31m[deps ERROR]\033[0m %s\n' "$*" >&2; }

# 1. Ensure cargo-edit (provides `cargo upgrade`) is available.
if ! cargo upgrade --version >/dev/null 2>&1; then
  log "cargo-edit not found; installing (cargo install cargo-edit --locked --version 0.13.14)..."
  cargo install cargo-edit --locked --version 0.13.14
fi
log "using $(cargo upgrade --version 2>/dev/null || echo 'cargo upgrade')"

# 2. Warn on a dirty tree so the resulting diff is purely the dep bump.
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  if [ -n "$(git -C "$ROOT" status --porcelain -- Cargo.toml 'crates/*/Cargo.toml' Cargo.lock 2>/dev/null)" ]; then
    err "Cargo.toml/Cargo.lock already have uncommitted changes — commit or stash first"
    err "so the upgrade diff is reviewable in isolation. Aborting."
    exit 1
  fi
fi

if [ "$DRY_RUN" = 1 ]; then
  log "DRY RUN — showing latest available upgrades (incompatible incl.), no files changed:"
  cargo upgrade --incompatible allow --pinned allow "${FORK_EXCLUDES[@]}" --dry-run
  log "dry run complete. Re-run without --dry-run to apply."
  exit 0
fi

# 3. Rewrite requirements in Cargo.toml / [workspace.dependencies] to latest,
#    allowing incompatible (major) and pinned bumps — the "absolute latest".
log "bumping all dependency requirements to latest (incl. major)..."
cargo upgrade --incompatible allow --pinned allow "${FORK_EXCLUDES[@]}"

# 4. Refresh Cargo.lock to the newest versions within the new requirements.
log "updating Cargo.lock..."
cargo update

# Check the exact package paths in the resolved graph. Inverse cargo tree
# lookups can be ambiguous when a transitive caller uses another version.
python3 - <<'EOF'
import json
from pathlib import Path
import subprocess
import tomllib

manifest = tomllib.loads(Path("Cargo.toml").read_text())
patches = manifest["patch"]["crates-io"]
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"]
))
resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
paths = {
    (p["name"], Path(p["manifest_path"]).resolve())
    for p in metadata["packages"] if p["id"] in resolved
}
for name, patch in patches.items():
    if isinstance(patch, dict) and patch.get("path", "").startswith("vendor/"):
        path = (Path(patch["path"]) / "Cargo.toml").resolve()
        if (name, path) not in paths:
            raise SystemExit(f"patched crate {name!r} did not resolve from {path.parent}")
EOF

# 5. Verify the workspace still builds (native release) and, by default, tests pass.
log "verifying: cargo build --release ..."
if ! cargo build --release; then
  err "BUILD FAILED after upgrade — review the dependency diff"
  exit 1
fi
if [ "$RUN_TESTS" = 1 ]; then
  log "verifying: cargo test --workspace ..."
  if ! cargo test --workspace; then
    err "TESTS FAILED after upgrade — review the dependency diff"
    exit 1
  fi
fi

# 6. Summary.
log "upgrade applied and verified. Changed manifests/lock:"
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  git -C "$ROOT" --no-pager diff --stat -- Cargo.toml 'crates/*/Cargo.toml' Cargo.lock || true
fi
cat <<EOF

Next steps:
  - Review:        git diff Cargo.toml crates/*/Cargo.toml
  - Cross-build:   scripts/build-all.sh both
  - Keep it:       stage the reviewed dependency changes for a separate commit
EOF
log "done."
