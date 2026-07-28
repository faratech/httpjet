#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 <new-output-directory> [git-ref]" >&2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    usage
    exit 2
fi

repo=$(git rev-parse --show-toplevel)
destination=$1
ref=${2:-HEAD}

case "$destination" in
    /*) ;;
    *)
        echo "output directory must be an absolute path" >&2
        exit 2
        ;;
esac

if [ -e "$destination" ]; then
    echo "refusing to use an existing output path: $destination" >&2
    exit 1
fi

git -C "$repo" rev-parse --verify "${ref}^{commit}" >/dev/null
mkdir -m 0700 "$destination"

mapfile -t paths < <(
    sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' \
        "$repo/scripts/public-source-files.txt"
)

git -C "$repo" archive --format=tar "$ref" -- "${paths[@]}" |
    tar -xf - -C "$destination" \
        --exclude='crates/hj-pagecache/BESPOKE_DESIGN.md' \
        --exclude='vendor/*/.github'

for forbidden in \
    AGENTS.md CLAUDE.md REMEDIATION.md RESULTS.md notes.md \
    bin conf docs logs run systemd target; do
    if [ -e "$destination/$forbidden" ]; then
        echo "private path escaped the allowlist: $forbidden" >&2
        exit 1
    fi
done

secret_pattern='(^|[^A-Za-z0-9_])(-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|sk-(proj-)?[A-Za-z0-9_-]{20,})'
if command -v rg >/dev/null 2>&1; then
    mapfile -t suspect_files < <(
        rg --files-with-matches --hidden --glob '!.git/**' -- "$secret_pattern" \
            "$destination" || true
    )
    if [ "${#suspect_files[@]}" -ne 0 ]; then
        echo "possible credential material found in public snapshot:" >&2
        printf '  %s\n' "${suspect_files[@]#"$destination"/}" >&2
        exit 1
    fi
else
    echo "warning: rg is unavailable; run a credential scanner before publishing" >&2
fi

"$destination/crates/hj-pagecache/scripts/generate-synthetic-meta-dict.py" \
    --check

"$destination/scripts/check-dependency-licenses.py" \
    --check "$destination/DEPENDENCY_LICENSES.md"

echo "public source snapshot created at $destination"
