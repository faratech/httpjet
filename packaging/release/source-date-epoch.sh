#!/bin/sh
# Resolve an annotated or lightweight tag to the commit timestamp only.
set -eu
[ "$#" -eq 1 ] || { echo 'usage: source-date-epoch.sh GIT_REF' >&2; exit 2; }
commit=$(git rev-parse --verify "$1^{commit}")
epoch=$(git show -s --format=%ct "$commit")
case "$epoch" in ''|*[!0-9]*) echo 'invalid source commit timestamp' >&2; exit 1 ;; esac
printf '%s\n' "$epoch"
