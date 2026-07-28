#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <output.dict> <sample-file-or-directory> [...]" >&2
    exit 2
fi

output=$1
shift

if ! command -v zstd >/dev/null 2>&1; then
    echo "zstd is required" >&2
    exit 1
fi

if [ -e "$output" ]; then
    echo "refusing to overwrite existing output: $output" >&2
    exit 1
fi

for input in "$@"; do
    if [ ! -e "$input" ]; then
        echo "sample path does not exist: $input" >&2
        exit 1
    fi
done

echo "Training $output from reviewed local samples."
echo "Do not use credentials, private responses, session data, or customer content."
zstd --train -r "$@" -o "$output"
zstd --list "$output"
