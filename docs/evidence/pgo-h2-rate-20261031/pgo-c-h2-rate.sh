#!/usr/bin/env bash
# Prepared only. Run separately after the release matrix and runtime-slot review.
# Bounded offered load: admission can queue; failures are retained, never retried.
set -euo pipefail
source /var/tmp/pgo-c-common.sh
export PGO_RATE_OUT="$PGO_RUN/h2-rate15000-v1"
export PGO_RATE_MONITOR="$PGO_RUN/rate-monitor-v1"
export PGO_RATE_HARNESS="$PGO_RUN/rate-harness"
export PGO_RATE_ARMS="$PGO_RUN/h2-rate15000-arms-v1.json"
export PGO_RATE_RUNNER="$(readlink -f -- "${BASH_SOURCE[0]}")"
export PGO_RATE_CLIENT=/var/tmp/httpjet-http-paced-client-v2/bin/httpjet-http-load-paced
ulimit -n 65536
for pgo_rate_path in "$PGO_RATE_OUT" "$PGO_RATE_MONITOR" "$PGO_RATE_ARMS" \
    "$PGO_RUN/h2-rate15000-inputs-before-v1.json" "$PGO_RUN/h2-rate15000-inputs-after-v1.json" \
    "$PGO_RUN/h2-rate15000-status-v1.json" "$PGO_RUN/h2-rate15000-after-v1.log"; do
    test ! -e "$pgo_rate_path"
    test ! -L "$pgo_rate_path"
done

pgo_rate_integrity() {
    local phase="$1"
    # A separate shell preserves errexit when this function is called by EXIT cleanup.
    bash -c 'set -euo pipefail; source /var/tmp/pgo-c-common.sh; pgo_check_inputs; pgo_check_profile_review' || return "$?"
    python3 - "$phase" <<'PY'
import hashlib,json,os,re,socket,subprocess,sys
from pathlib import Path
assert socket.gethostname().upper()=='SINGULARITY' and os.geteuid()==0
r=Path(os.environ['PGO_RUN']);harness=Path(os.environ['PGO_RATE_HARNESS'])
phase=sys.argv[1];assert phase in ('before','after')
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
capacity=r/'final-pgo-release-true-lo-v1'
capacity_summary=json.loads((capacity/'summary.json').read_text())
capacity_integrity=json.loads((capacity/'final-integrity.json').read_text())
assert capacity_summary['status']=='complete' and len(capacity_summary['cells'])==20
assert capacity_integrity['status']=='passed' and capacity_integrity['completed_arms']==240
assert capacity_integrity['summary_sha256']==h(capacity/'summary.json')
pins={str(r/'bin-use/httpjet'):'0ca04dcb8d3b9d07e02ac19658546d7882d6f2719c6937be2f259ca65eef83c5',
 str(r/'bin-use/httpjet-beeper-h1'):'1cce1f3ca5837e5d68b9be757438af28a88be789468372392bf6148a3987721d',
 '/var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet':'3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec',
 os.environ['PGO_RATE_CLIENT']:'0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6'}
for name,sha in pins.items():
 p=Path(name);assert p.is_file() and not p.is_symlink() and os.access(p,os.X_OK) and h(p)==sha,name
use=json.loads((r/'use-artifacts.json').read_text())
q=json.loads((r/'qualification-v2/qualification.json').read_text())
assert q['passed'] is True and q['artifacts']==use
assert len(use)==4
for name,row in use.items():assert h(Path(name))==row['sha256'],name
build=json.loads((r/'build-use.json').read_text());warnings=json.loads((r/'profile-use-warnings.json').read_text())
assert build['exit']==0 and build['rustflags']==f'-Ctarget-cpu=native -Cforce-frame-pointers=yes -Cprofile-use={r}/runtime.profdata -Cllvm-args=-pgo-warn-missing-function'
assert warnings['accepted_for_correctness_qualification'] is True and not warnings['control_flow_or_profile_hash_mismatches']
route=json.loads(subprocess.run(['ip','-j','route','get','127.0.0.2','from','127.0.0.2'],check=True,capture_output=True,text=True).stdout)
assert any(row.get('dev')=='lo' for row in route),'true-lo route must use lo'
manifest_path=r/'rate-harness-sha256.json'
manifest=json.loads(manifest_path.read_text())
required={f'scripts/{n}.py' for n in ['http_engine_check','h3_engine_check','bench_environment_run',
 'bench_cpu','bench_hw_counters','bench_syscall_counts']}
required|={'packaging/debian/conf/'+n for n in ['httpd_config.xml','mime.properties','vhosts/default.xml']}
assert isinstance(manifest,dict) and required<=set(manifest)
for name,sha in manifest.items():
 rel=Path(name);assert not rel.is_absolute() and '..' not in rel.parts,name
 assert isinstance(sha,str) and re.fullmatch('[0-9a-f]{64}',sha),name
 p=harness/rel;assert p.is_file() and not p.is_symlink() and h(p)==sha,name
arms=[{'name':'release','binary':'/var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet','serve_args':[]},
 {'name':'native','binary':str(r/'bin-use/httpjet'),'serve_args':['--h1-kernel','off','--page-cache-response-memo']},
 {'name':'kernel','binary':str(r/'bin-use/httpjet'),
  'serve_args':['--h1-kernel','required','--h2-kernel','--page-cache-response-memo'],
  'launcher':{'binary':str(r/'bin-use/httpjet-beeper-h1')}}]
arm_path=Path(os.environ['PGO_RATE_ARMS'])
if phase=='before':
 with arm_path.open('x') as f:json.dump(arms,f,indent=2);f.write('\n')
else:assert json.loads(arm_path.read_text())==arms
paths=[manifest_path,arm_path,r/'use-artifacts.json',r/'build-use.json',r/'profile-use-warnings.json',
 r/'pgo-inputs.json',r/'build-source-manifest.json',r/'merge-receipt.json',r/'coverage-review.json',
 r/'profile-inputs.json',r/'qualification-v2/qualification.json',Path('/var/tmp/pgo-c-common.sh'),
 capacity/'summary.json',capacity/'final-integrity.json',
 Path(os.environ['PGO_RATE_RUNNER'])]
snapshot={'pins':pins,'input_sha256':{str(p):h(p) for p in paths},'harness_sha256':manifest,
 'network':{'server':'127.0.0.2','client_bind':'127.0.0.2'},
 'scope':'bounded offered-load comparison; process CPU includes server/helper user+system, not whole-server CPU'}
before=r/'h2-rate15000-inputs-before-v1.json'
if phase=='after':assert json.loads(before.read_text())==snapshot,'input drift during rate comparison'
with (r/f'h2-rate15000-inputs-{phase}-v1.json').open('x') as f:json.dump(snapshot,f,indent=2);f.write('\n')
PY
}

pgo_rate_integrity before
PGO_RATE_PID=''
pgo_rate_signal() {
    local code="$1"
    if test -n "$PGO_RATE_PID" && kill -0 "$PGO_RATE_PID" 2>/dev/null; then
        # The owned observer forwards TERM to its harness and reaps its server.
        kill -TERM "$PGO_RATE_PID" 2>/dev/null || true
        wait "$PGO_RATE_PID" || true
    fi
    PGO_RATE_PID=''
    exit "$code"
}
pgo_rate_finish() {
    local original="$?" after=0 report=0
    trap - EXIT INT TERM HUP
    set +e
    pgo_rate_integrity after >"$PGO_RUN/h2-rate15000-after-v1.log" 2>&1 || after=$?
    python3 - "$original" "$after" <<'PY'
import hashlib,ipaddress,json,os,sys
from pathlib import Path
r=Path(os.environ['PGO_RUN']);out=Path(os.environ['PGO_RATE_OUT']);monitor=Path(os.environ['PGO_RATE_MONITOR'])
sequence=['release','native','kernel','kernel','native','release'];errors=[];rows=[]
for case in ('static','pagecache'):
 for cycle in (1,2,3):
  for pos,name in enumerate(sequence,1):
   p=out/f'h2c-{case}-{cycle}-{pos}-{name}';f=p/'result.json'
   try:
    v=json.loads(f.read_text());c=v['client'];o=c['offered_load'];hw=v['hardware_counters']
    assert not (p/'failure.json').exists() and v['benchmark_valid'] is True
    assert c['benchmark_valid'] and c['requested']==c['completed']==c['succeeded']==60000
    assert c['failed']==c['unattempted']==0 and not c['errors'] and not c['driver_errors']
    assert c['warmup_requested']==c['warmup_completed']==c['warmup_succeeded']==5000
    assert c['latency_scope']=='scheduled_to_completion' and o['rate_spec']=='15000'
    sockets=c['client_sockets'];assert len(sockets)==32
    assert all(ipaddress.ip_address(x['local_address'].rsplit(':',1)[0].strip('[]'))==ipaddress.ip_address('127.0.0.2') for x in sockets)
    assert o['concurrency_limit']==128 and not o['fully_open_loop']
    assert o['dispatched']==60000 and o['expired_before_dispatch']==0
    assert all(o[k]['count']==60000 for k in ('scheduled_all_outcomes','service','dispatch_lateness'))
    assert hw['valid'] and hw['include_user'] is True and hw['exclude_kernel'] is True
    assert v['client_cpu_headroom_gate']['passed'] and v['metric_deltas_include_client_warmup'] is True
    assert json.loads((p/'server-exit.json').read_text())['exit']==0
    k=v['metric_deltas'].get('httpjet_h2_kernel_successes_total')
    assert (k is not None and 0<k<=65000) if name=='kernel' else k in (0,None)
    rows.append({'case':case,'cycle':cycle,'position':pos,'arm':name,'source':str(f),
     'source_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'kernel_successes':k,
     'peak_in_flight':o['peak_in_flight'],'concurrency_waits':o['concurrency_waits']})
   except Exception as e:errors.append({'arm':str(p),'error':str(e),'type':type(e).__name__})
events=monitor/'environment.jsonl';end=None
try:
 end=json.loads(events.read_text().splitlines()[-1])
 assert end['command_exit']==0 and end['compiler_overlap_observed'] is False
except Exception as e:errors.append({'monitor':str(events),'error':str(e),'type':type(e).__name__})
passed=int(sys.argv[1])==int(sys.argv[2])==0 and len(rows)==36 and not errors
record={'passed':passed,'command_exit':int(sys.argv[1]),'final_integrity_exit':int(sys.argv[2]),
 'completed_arms':len(rows),'expected_arms':36,'measured_responses':2160000 if passed else None,
 'warmup_responses':180000 if passed else None,'rows':rows,'errors':errors,'monitor':end,
 'results':str(out),'monitor_directory':str(monitor),
 'scope':'bounded offered load, not unrestricted open loop; no automatic retries or reconnects; failed arms remain in place'}
with (r/'h2-rate15000-status-v1.json').open('x') as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps({'passed':passed,'completed_arms':len(rows),'errors':len(errors)}))
sys.exit(0 if passed else 1)
PY
    report=$?
    if test "$original" -ne 0; then exit "$original"; fi
    if test "$after" -ne 0; then exit "$after"; fi
    exit "$report"
}
trap pgo_rate_finish EXIT
trap 'pgo_rate_signal 130' INT
trap 'pgo_rate_signal 143' TERM
trap 'pgo_rate_signal 129' HUP
env -i PATH=/usr/local/bin:/usr/bin:/bin PYTHONPATH=/var/tmp/httpjet-h3-tools/python \
    PYTHONDONTWRITEBYTECODE=1 HJ_BENCH_ADDR=127.0.0.2 HJ_BENCH_BIND=127.0.0.2 \
    taskset -c 10 python3 -B "$PGO_RATE_HARNESS/scripts/bench_environment_run.py" \
    --output "$PGO_RATE_MONITOR" --quiet-seconds 10 --interval-seconds 1 -- \
    python3 -B "$PGO_RATE_HARNESS/scripts/http_engine_check.py" \
    --arms "$PGO_RATE_ARMS" --client "$PGO_RATE_CLIENT" \
    --sequence release,native,kernel,kernel,native,release --rounds 3 \
    --protocols h2c --cases static,pagecache --size 1024 --rate 15000 \
    --requests 60000 --warmup 5000 --connections 32 --streams 4 \
    --workers 1 --server-cpus 8 --client-threads 6 --client-cpus 0,2,4,6,12,14 \
    --client-timeout-secs 10 --server-hardware-counters --require-client-cpu-headroom \
    --results "$PGO_RATE_OUT" &
PGO_RATE_PID=$!
wait "$PGO_RATE_PID"
PGO_RATE_PID=''
