#!/usr/bin/env bash
# Prepared only; execute separately after completed-C review and slot scheduling.
set -euo pipefail
source /var/tmp/pgo-c-common.sh
pgo_check_inputs
pgo_check_profile_review
pgo_build "$PGO_RUN/target-use" "$PGO_BASE -Cprofile-use=$PGO_RUN/runtime.profdata -Cllvm-args=-pgo-warn-missing-function" use
python3 - <<'PY'
import hashlib,json,os,re
from pathlib import Path
r=Path(os.environ['PGO_RUN']);p=r/'logs/build-use.log';lines=p.read_text().splitlines()
fatal=[line for line in lines if re.search(r'profile data may be out of date|function control flow change|hash mismatch|profile[- ]hash.*mismatch',line,re.I)]
missing=[line for line in lines if re.search(r'no profile data|profile data (?:is )?(?:missing|not found)|missing profile data|missing[- ]function.*warning',line,re.I)]
record={'log':str(p),'log_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
 'control_flow_or_profile_hash_mismatches':fatal,'missing_function_warnings':missing,
 'accepted_for_correctness_qualification':not fatal,'performance_qualified':False}
(r/'profile-use-warnings.json').write_text(json.dumps(record,indent=2)+'\n')
assert not fatal, 'profile/control-flow mismatch; full build log and warning record retained'
PY
pgo_check_inputs
pgo_check_profile_review
pgo_freeze "$PGO_RUN/target-use" use
