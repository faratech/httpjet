#!/usr/bin/env bash
# Same-source static pilot; run only after frozen PGO-use correctness qualification.
set -euo pipefail
source /var/tmp/pgo-c-common.sh
pgo_check_inputs
pgo_check_profile_review
python3 - <<'PY'
import hashlib,json,os
from pathlib import Path
r=Path(os.environ['PGO_RUN'])
summary=json.loads((r/'completed-c-summary.json').read_text())
frozen=Path('/var/tmp/httpjet-continuation/final-c-harness')
inputs=summary['provenance']['source_inputs']
assert 'scripts/integrated_bench.py' in inputs and 'scripts/bench_environment_run.py' in inputs
for name,record in inputs.items():
    path=frozen/name
    assert path.resolve()==Path(record['path']).resolve(),name
    assert path.is_file() and not path.is_symlink(),name
    assert hashlib.sha256(path.read_bytes()).hexdigest()==record['sha256'],name
for label in ('use','control'):
    assert json.loads((r/f'build-{label}.json').read_text())['exit']==0
    files=json.loads((r/f'{label}-artifacts.json').read_text())
    assert len(files)==4
    for name,row in files.items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==row['sha256'],name
q=json.loads((r/'qualification-v2/qualification.json').read_text())
assert q['passed'] is True
assert q['artifacts']==json.loads((r/'use-artifacts.json').read_text())
control=json.loads((r/'build-control.json').read_text())
use=json.loads((r/'build-use.json').read_text())
base='-Ctarget-cpu=native -Cforce-frame-pointers=yes'
assert control['rustflags']==base
assert use['rustflags']==f'{base} -Cprofile-use={r}/runtime.profdata -Cllvm-args=-pgo-warn-missing-function'
assert control['features']==use['features'] and control['profile']==use['profile']
PY
exec env -i PATH=/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/var/tmp/httpjet-h3-tools/python PYTHONDONTWRITEBYTECODE=1 \
    python3 -B /var/tmp/httpjet-continuation/final-c-harness/scripts/integrated_bench.py \
    --profile true-lo --comparison source \
    --release /var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet \
    --native-baseline "$PGO_RUN/bin-control/httpjet" \
    --candidate "$PGO_RUN/bin-use/httpjet" \
    --native-baseline-receipt "$PGO_RUN/build-control.json" \
    --candidate-receipt "$PGO_RUN/build-use.json" \
    --http-client /var/tmp/hjc/httpjet-http-load-bind \
    --h3-client /var/tmp/httpjet-continuation/h3-bind-client-20261030/bin/httpjet-h3-load-bind \
    --protocols h1,h1s,h2c,h2,h3 --sizes 1024,32768 --cases static \
    --cycles 3 --requests 100000 --warmup 5000 \
    --connections 32 --streams 4 --server-cpu 8 \
    --client-cpus 0,2,4,6,12,14 --observer-cpu 10 \
    --source-baseline-arg=--h1-kernel=off \
    --source-baseline-arg=--page-cache-response-memo \
    --source-baseline-arg=--h3-gso-segments=20 \
    --source-baseline-arg=--h3-send-batch=1 \
    --source-baseline-h3-engine accelerated \
    --h3-gso-segments 20 --h3-send-batch 1 \
    --results "$PGO_RUN/pilot-static-same-source-v1"
