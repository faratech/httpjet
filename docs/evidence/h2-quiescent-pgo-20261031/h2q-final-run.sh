#!/usr/bin/env bash
# Prepared only. Root must schedule the serialized SINGULARITY runtime slot.
set -euo pipefail
test "$#" -eq 1
case "$1" in capacity|rate15000) ;; *) exit 2 ;; esac
ulimit -n 65536
export PYTHONDONTWRITEBYTECODE=1
source /var/tmp/h2q-pgo-common.sh
pgo_check_inputs
pgo_check_profile_review
exec env -i PATH=/usr/local/bin:/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/var/tmp/httpjet-h3-tools/python \
    HJ_BENCH_ADDR=127.0.0.2 HJ_BENCH_BIND=127.0.0.2 \
    taskset -c 10 python3 -B /var/tmp/h2q-final-run.py "$1"
