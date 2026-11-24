#!/usr/bin/env bash
# Prepared only; execute separately after completed-C review and slot scheduling.
set -euo pipefail
source /var/tmp/pgo-c-common.sh
pgo_check_inputs
pgo_verify_gen
test ! -e "$PGO_RUN/training-complete.json"
python3 - <<'PY'
import json, os
from pathlib import Path
run = Path(os.environ['PGO_RUN'])
binary = str(run/'bin-gen/httpjet')
helper = str(run/'bin-gen/httpjet-beeper-h1')
base = ['--page-cache-response-memo']
arms = [{'name':'native', 'binary':binary, 'serve_args':base+['--h1-kernel','off']}]
for mode in ['polling','readiness']:
    arms.append({'name':'h1-'+mode, 'binary':binary,
                 'serve_args':base+['--h1-kernel','required','--h1-kernel-wakeup',mode],
                 'launcher':{'binary':helper}})
arms.append({'name':'h2-kernel', 'binary':binary,
             'serve_args':base+['--h1-kernel','required','--h2-kernel'],
             'launcher':{'binary':helper}})
(run/'training-arms.json').write_text(json.dumps(arms,indent=2)+'\n')
PY
pgo_python() {
    env -i PATH=/usr/local/bin:/usr/bin:/bin \
        PYTHONPATH=/var/tmp/httpjet-h3-tools/python PYTHONDONTWRITEBYTECODE=1 \
        HJ_BENCH_ADDR=127.0.0.2 HJ_BENCH_BIND=127.0.0.2 python3 -B "$@"
}
pgo_http=(--arms "$PGO_RUN/training-arms.json" --client /var/tmp/hjc/httpjet-http-load-bind
          --workers 1 --server-cpus 8 --connections 64 --streams 4 --client-threads 6
          --client-cpus 0,2,4,6,12,14)
for pgo_size in 1024 32768; do
    pgo_requests=30000; pgo_warmup=2000
    if [ "$pgo_size" = 32768 ]; then pgo_requests=8000; pgo_warmup=1000; fi
    pgo_name="http-native-$pgo_size"
    pgo_python "$PGO_HARNESS/http_engine_check.py" "${pgo_http[@]}" \
        --sequence native --protocols h1,h1s,h2c,h2 --cases static,pagecache,range \
        --size "$pgo_size" --requests "$pgo_requests" --warmup "$pgo_warmup" \
        --profile-dir "$PGO_RUN/raw/$pgo_name" --results "$PGO_RUN/results/$pgo_name" \
        >"$PGO_RUN/logs/$pgo_name.log" 2>&1
done
pgo_python "$PGO_HARNESS/http_engine_check.py" "${pgo_http[@]}" \
    --sequence h1-polling,h1-readiness --protocols h1 --cases static,pagecache \
    --size 1024 --requests 30000 --warmup 2000 \
    --profile-dir "$PGO_RUN/raw/h1-kernel" --results "$PGO_RUN/results/h1-kernel" \
    >"$PGO_RUN/logs/h1-kernel.log" 2>&1
pgo_python "$PGO_HARNESS/http_engine_check.py" "${pgo_http[@]}" \
    --sequence h2-kernel --protocols h2c --cases static,pagecache \
    --size 1024 --requests 30000 --warmup 2000 \
    --profile-dir "$PGO_RUN/raw/h2-kernel-1024" --results "$PGO_RUN/results/h2-kernel-1024" \
    >"$PGO_RUN/logs/h2-kernel-1024.log" 2>&1
pgo_python "$PGO_HARNESS/http_engine_check.py" "${pgo_http[@]}" \
    --sequence h2-kernel --protocols h2c --cases pagecache \
    --size 32768 --requests 8000 --warmup 1000 \
    --profile-dir "$PGO_RUN/raw/h2-kernel-32768" --results "$PGO_RUN/results/h2-kernel-32768" \
    >"$PGO_RUN/logs/h2-kernel-32768.log" 2>&1

for pgo_size in 1024 32768; do
    pgo_requests=30000; pgo_warmup=2000
    if [ "$pgo_size" = 32768 ]; then pgo_requests=8000; pgo_warmup=1000; fi
    for pgo_shape in 20:1 10:4; do
        pgo_gso=${pgo_shape%:*}; pgo_batch=${pgo_shape#*:}
        for pgo_case in all range; do
            pgo_name="h3-$pgo_size-g$pgo_gso-b$pgo_batch-$pgo_case"
            pgo_python "$PGO_HARNESS/h3_engine_check.py" \
                --candidate "$PGO_RUN/bin-gen/httpjet" --candidate-page-response-memo \
                --client /var/tmp/httpjet-continuation/h3-bind-client-20261030/bin/httpjet-h3-load-bind \
                --sequence legacy,accelerated --case "$pgo_case" \
                --candidate-arg="--h3-gso-segments=$pgo_gso" \
                --candidate-arg="--h3-send-batch=$pgo_batch" \
                --workers 2 --server-cpus 8,10 --connections 32 --streams 4 \
                --client-threads 6 --client-cpus 0,2,4,6,12,14 \
                --size "$pgo_size" --requests "$pgo_requests" --warmup "$pgo_warmup" \
                --profile-dir "$PGO_RUN/raw/$pgo_name" --results "$PGO_RUN/results/$pgo_name" \
                >"$PGO_RUN/logs/$pgo_name.log" 2>&1
        done
    done
done

pgo_check_inputs
pgo_verify_gen
python3 - <<'PY'
import json,os
from pathlib import Path
p=Path(os.environ['PGO_RUN'])/'training-complete.json'
p.write_text(json.dumps({'commands_finished':True,'expected_arms':55,
 'scope':'training only; merge stage validates all arms, identities and raw profiles'},indent=2)+'\n')
PY
