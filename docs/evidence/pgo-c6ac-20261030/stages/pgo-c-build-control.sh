#!/usr/bin/env bash
# Prepared only; execute separately after completed-C review and slot scheduling.
set -euo pipefail
source /var/tmp/pgo-c-common.sh
pgo_check_inputs
pgo_build "$PGO_RUN/target-control" "$PGO_BASE" control
pgo_check_inputs
pgo_freeze "$PGO_RUN/target-control" control
