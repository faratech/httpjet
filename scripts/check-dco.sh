#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <git-revision-range>" >&2
    exit 2
fi

range=$1
failed=0
count=0

while IFS= read -r commit; do
    [ -n "$commit" ] || continue
    count=$((count + 1))
    author=$(git show -s --format='%an <%ae>' "$commit")
    body=$(git show -s --format='%B' "$commit")
    if ! grep -Fqi "Signed-off-by: $author" <<<"$body"; then
        echo "$commit is missing: Signed-off-by: $author" >&2
        failed=1
    fi
done < <(git rev-list --no-merges "$range")

if [ "$count" -eq 0 ]; then
    echo "no non-merge commits found in $range" >&2
    exit 2
fi

if [ "$failed" -ne 0 ]; then
    echo "DCO check failed; amend the listed commits with git commit -s" >&2
    exit 1
fi

echo "DCO check passed for $count commit(s)"
