#!/usr/bin/env bash
# Prepared only. Run separately on SINGULARITY after freezing bin-use and inputs.
set -euo pipefail
source /var/tmp/pgo-c-common.sh

test "$PGO_RUN" = /var/tmp/httpjet-continuation/pgo-c6ac-v1
export PGO_QUAL_OUT="$PGO_RUN/qualification-v2"
export PGO_QUAL_HARNESS="$PGO_RUN/qualification-harness"
export PGO_QUAL_RUNNER="$(readlink -f -- "${BASH_SOURCE[0]}")"
export PGO_QUAL_SOURCE_COMMIT=1371045361b3caef938bd530e9f24246c0ecb368
export PGO_QUAL_H3_CLIENT=/var/tmp/httpjet-continuation/h3-bind-client-20261030/bin/httpjet-h3-load-bind
export PGO_QUAL_HTTP_CLIENT=/var/tmp/hjc/httpjet-http-load-bind

python3 - <<'PY'
import os, socket
assert socket.gethostname().upper() == 'SINGULARITY', 'qualification is SINGULARITY-only'
assert os.geteuid() == 0, 'owned fixtures require root to drop the server to nobody'
PY
ulimit -n 65536
test ! -e "$PGO_QUAL_OUT"
test ! -L "$PGO_QUAL_OUT"
install -d -m 0755 "$PGO_QUAL_OUT" "$PGO_QUAL_OUT/logs" "$PGO_QUAL_OUT/steps"

pgo_qual_integrity() {
    local phase="$1"
    # Keep common's errexit checks in their own shell: the step recorder catches
    # failures with ||, which would otherwise disable errexit inside functions.
    bash -c 'set -euo pipefail; source /var/tmp/pgo-c-common.sh; pgo_check_inputs; pgo_check_profile_review' || return "$?"
    python3 - "$phase" <<'PY'
import hashlib, json, os, re, sys
from pathlib import Path

run = Path(os.environ['PGO_RUN'])
out = Path(os.environ['PGO_QUAL_OUT'])
harness = Path(os.environ['PGO_QUAL_HARNESS'])
phase = sys.argv[1]
assert phase in {'before', 'after'}
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

use_file = run / 'use-artifacts.json'
artifacts = json.loads(use_file.read_text())
names = {'httpjet', 'httpjet-beeper-h1', 'httpjet-beeper-observe', 'httpjet-quic-steer'}
expected_paths = {str(run / 'bin-use' / name) for name in names}
assert set(artifacts) == expected_paths, 'use-artifacts must name exactly the four frozen bin-use files'
for name, record in artifacts.items():
    path = Path(name)
    assert path.is_file() and not path.is_symlink(), name
    assert os.access(path, os.X_OK), name
    assert path.stat().st_size == record['bytes'], name
    assert digest(path) == record['sha256'], name

manifest_file = run / 'qualification-harness-sha256.json'
manifest = json.loads(manifest_file.read_text())
assert isinstance(manifest, dict) and len(manifest) == 17, 'expected all 17 frozen qualification inputs'
required_scripts = {
    'beeper_h1_late_check.py', 'beeper_h1_serve_check.py',
    'beeper_h2_serve_check.py', 'beeper_h2_expiry_check.py',
    'h3_shutdown_check.py', 'cache_required_lab.py', 'beeper_native_check.py',
    'h3_engine_check.py', 'http_engine_check.py', 'cache_xurl_test.sh', 'cache_scheme_test.sh',
    'bench_cpu.py', 'bench_hw_counters.py', 'bench_syscall_counts.py',
}
assert {f'scripts/{name}' for name in required_scripts} <= set(manifest)
assert sum(name.startswith('packaging/debian/conf/') for name in manifest) == 3
for name, expected in manifest.items():
    relative = Path(name)
    assert not relative.is_absolute() and '..' not in relative.parts, name
    assert isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected), name
    path = harness / relative
    assert path.is_file() and not path.is_symlink(), name
    assert digest(path) == expected, name

build = json.loads((run / 'build-use.json').read_text())
assert build['exit'] == 0
assert f'-Cprofile-use={run}/runtime.profdata' in build['rustflags']
assert '-Cprofile-generate' not in build['rustflags']
warnings = json.loads((run / 'profile-use-warnings.json').read_text())
assert warnings['accepted_for_correctness_qualification'] is True
assert not warnings['control_flow_or_profile_hash_mismatches']

paths = [
    run / 'pgo-inputs.json', run / 'build-source-manifest.json',
    run / 'completed-c-summary.json', run / 'bpf-objects.json', use_file,
    manifest_file, run / 'build-use.json', run / 'profile-use-warnings.json',
    run / 'runtime.profdata', run / 'profile-inputs.json',
    run / 'merge-receipt.json', run / 'coverage-review.json',
    Path('/var/tmp/pgo-c-common.sh'), Path(os.environ['PGO_QUAL_RUNNER']),
    Path(os.environ['PGO_QUAL_H3_CLIENT']),
    Path(os.environ['PGO_QUAL_HTTP_CLIENT']),
    out / 'ua-arms.json', out / 'http-native-arms.json',
]
snapshot = {
    'source_runtime_commit_label': os.environ['PGO_QUAL_SOURCE_COMMIT'],
    'input_sha256': {str(path): digest(path) for path in paths},
    'use_artifacts': artifacts,
    'qualification_harness_sha256': manifest,
    'scope': 'live correctness; no performance qualification',
}
if phase == 'after':
    before = json.loads((out / 'inputs-before.json').read_text())
    assert snapshot == before, 'qualification inputs changed during the gates'
(out / f'inputs-{phase}.json').write_text(json.dumps(snapshot, indent=2) + '\n')
print(f'{phase}: source/profile/input checks and all four frozen PGO-use binaries verified')
PY
}

pgo_qual_finish() {
    local original_code="$1" after_code=0 receipt_code=0
    trap - EXIT INT TERM
    set +e
    pgo_qual_integrity after >"$PGO_QUAL_OUT/logs/inputs-after.log" 2>&1 || after_code=$?
    python3 - "$original_code" "$after_code" <<'PY'
import datetime, hashlib, json, os, sys
from pathlib import Path

out = Path(os.environ['PGO_QUAL_OUT'])
expected = ['inputs-before', 'h1-late-readiness', 'h1-h2-ua', 'h2-oversize',
            'h2-expiry', 'tls-smoke', 'h3-shutdown', 'cache-required', 'h3-gso20-batch1']
active_path = out / 'active-step.json'
if active_path.exists():
    active = json.loads(active_path.read_text())
    step_path = out / 'steps' / f'{active["name"]}.json'
    if not step_path.exists():
        active.update(returncode=int(sys.argv[1]) or 1, interrupted=True,
                      finished_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        log = Path(active['log'])
        if log.exists():
            active['log_sha256'] = hashlib.sha256(log.read_bytes()).hexdigest()
        step_path.write_text(json.dumps(active, indent=2) + '\n')
steps = [json.loads((out / 'steps' / f'{name}.json').read_text())
         for name in expected if (out / 'steps' / f'{name}.json').exists()]
successful = {step['name'] for step in steps if step['returncode'] == 0}
cleanup, cleanup_errors = [], []
def cleanup_record(gate, relative, valid, fields):
    path = out / relative
    if not path.exists():
        if gate in successful:
            cleanup_errors.append(f'{gate}: missing {relative}')
        return
    row = {'gate': gate, 'path': str(path),
           'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    try:
        data = json.loads(path.read_text())
        row['valid'] = bool(valid(data))
        row['summary'] = {key: data[key] for key in fields if key in data}
    except Exception as error:
        row.update(valid=False, error=str(error))
    cleanup.append(row)
    if gate in successful and not row['valid']:
        cleanup_errors.append(f'{gate}: invalid {relative}')

for arm in ['native', 'kernel']:
    cleanup_record('h1-late-readiness', f'h1-late-readiness/{arm}/cleanup.json',
                   lambda d: d.get('proved') is True, ['proved'])
    cleanup_record('h1-late-readiness', f'h1-late-readiness/{arm}/exits.json',
                   lambda d: d.get('server') == 0 and d.get('backend') in (0, -15),
                   ['server', 'backend'])
for arm in ['native', 'polling', 'readiness']:
    cleanup_record('h1-h2-ua', f'h1-h2-ua/{arm}/cleanup.json',
                   lambda d: d.get('proved') is True, ['proved'])
    cleanup_record('h1-h2-ua', f'h1-h2-ua/{arm}/exit.json',
                   lambda d: d.get('returncode') == 0, ['pid', 'returncode'])
for gate in ['h2-oversize', 'h2-expiry']:
    for arm in ['native', 'kernel']:
        cleanup_record(gate, f'{gate}/{arm}/cleanup.json',
                       lambda d: d.get('proved') is True, ['proved'])
        cleanup_record(gate, f'{gate}/{arm}/exit.json',
                       lambda d: d.get('returncode') == 0, ['pid', 'returncode'])
for mode in ['legacy', 'accelerated']:
    for case in ['delivery', 'stop', 'unacked']:
        cleanup_record('h3-shutdown', f'h3-shutdown/{mode}-{case}/result.json',
                       lambda d: d.get('passed') is True and d.get('process_reaped') is True
                       and d.get('cleanup_exit_code') == 0 and not d.get('cleanup_errors')
                       and len(d.get('released_listeners', [])) == 4,
                       ['passed', 'pid', 'process_reaped', 'cleanup_exit_code',
                        'released_listeners', 'cleanup_errors'])
cleanup_record('cache-required', 'cache-required/cleanup.json',
               lambda d: d.get('clean') is True, ['clean', 'processes', 'listeners'])
for gate, count in [('tls-smoke', 6), ('h3-gso20-batch1', 2)]:
    exits = sorted((out / gate).glob('*/server-exit.json'))
    if gate in successful and len(exits) != count:
        cleanup_errors.append(f'{gate}: expected {count} server exit receipts, found {len(exits)}')
    for path in exits:
        cleanup_record(gate, str(path.relative_to(out)),
                       lambda d: d.get('exit') == 0, ['pid', 'exit'])

passed = (int(sys.argv[1]) == 0 and int(sys.argv[2]) == 0
          and len(steps) == len(expected)
          and [step['name'] for step in steps] == expected
          and all(step['returncode'] == 0 for step in steps) and not cleanup_errors)
before = (json.loads((out / 'inputs-before.json').read_text())
          if (out / 'inputs-before.json').exists() else {})
record = {
    'passed': passed, 'recorded_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'original_exit': int(sys.argv[1]), 'final_integrity_exit': int(sys.argv[2]),
    'scope': 'post-PGO live correctness only; preflight rates are not performance evidence',
    'source_runtime_commit_label': os.environ['PGO_QUAL_SOURCE_COMMIT'],
    'artifacts': before.get('use_artifacts', {}),
    'expected_steps': expected, 'steps': steps,
    'cleanup': cleanup, 'cleanup_errors': cleanup_errors,
    'before_after_inputs': {
        phase: {'path': str(out / f'inputs-{phase}.json'),
                'sha256': hashlib.sha256((out / f'inputs-{phase}.json').read_bytes()).hexdigest()}
        for phase in ['before', 'after'] if (out / f'inputs-{phase}.json').exists()
    },
    'final_integrity_log': str(out / 'logs/inputs-after.log'),
    'live_artifacts_exercised': ['httpjet', 'httpjet-beeper-h1'],
    'hash_verified_artifacts': ['httpjet', 'httpjet-beeper-h1', 'httpjet-beeper-observe', 'httpjet-quic-steer'],
}
(out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'passed': passed, 'receipt': str(out / 'qualification.json')}))
sys.exit(0 if passed else 1)
PY
    receipt_code=$?
    if test "$original_code" -ne 0; then exit "$original_code"; fi
    if test "$after_code" -ne 0; then exit "$after_code"; fi
    exit "$receipt_code"
}
trap 'pgo_qual_finish "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

pgo_qual_step() {
    local name="$1" started code=0
    shift
    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    python3 - "$name" "$started" "$@" <<'PY'
import json, os, sys
from pathlib import Path
out = Path(os.environ['PGO_QUAL_OUT'])
name, started = sys.argv[1:3]
record = {'name': name, 'started_at_utc': started, 'command': sys.argv[3:],
          'log': str(out / 'logs' / f'{name}.log'), 'returncode': None}
(out / 'active-step.json').write_text(json.dumps(record, indent=2) + '\n')
PY
    "$@" >"$PGO_QUAL_OUT/logs/$name.log" 2>&1 || code=$?
    python3 - "$name" "$started" "$code" "$@" <<'PY'
import datetime, hashlib, json, os, sys
from pathlib import Path
out = Path(os.environ['PGO_QUAL_OUT'])
name, started, code = sys.argv[1:4]
log = out / 'logs' / f'{name}.log'
record = {'name': name, 'started_at_utc': started,
          'finished_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'returncode': int(code), 'command': sys.argv[4:], 'log': str(log),
          'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
(out / 'steps' / f'{name}.json').write_text(json.dumps(record, indent=2) + '\n')
(out / 'active-step.json').unlink(missing_ok=True)
print(f'{name}: exit {code}', flush=True)
PY
    return "$code"
}

cat >"$PGO_QUAL_OUT/ua-arms.json" <<'JSON'
[
  {
    "name": "native",
    "serve_args": ["--h1-kernel", "off", "--h1-kernel-wakeup", "polling", "--h1-kernel-max-body", "32768", "--request-id-header"],
    "require_readiness": false
  },
  {
    "name": "polling",
    "serve_args": ["--h1-kernel", "required", "--h1-kernel-wakeup", "polling", "--h1-kernel-max-body", "32768", "--request-id-header"],
    "require_hits": true,
    "require_readiness": false
  },
  {
    "name": "readiness",
    "serve_args": ["--h1-kernel", "required", "--h1-kernel-wakeup", "readiness", "--h1-kernel-max-body", "32768", "--request-id-header"],
    "require_hits": true,
    "require_readiness": true
  }
]
JSON

python3 - <<'PY'
import json, os
from pathlib import Path
out = Path(os.environ['PGO_QUAL_OUT'])
arms = [{'name': 'native', 'binary': str(Path(os.environ['PGO_RUN']) / 'bin-use/httpjet'),
         'serve_args': ['--page-cache-response-memo', '--h1-kernel', 'off']}]
(out / 'http-native-arms.json').write_text(json.dumps(arms, indent=2) + '\n')
PY

pgo_qual_step inputs-before pgo_qual_integrity before

pgo_qual_python=(env -i PATH=/usr/local/bin:/usr/bin:/bin
    PYTHONPATH=/var/tmp/httpjet-h3-tools/python PYTHONDONTWRITEBYTECODE=1
    HJ_BENCH_ADDR=127.0.0.2 HJ_BENCH_BIND=127.0.0.2 python3 -B)
# The H1/H2 handoff corpora explicitly bind their helper/backend to .1.
# Keep their imported readiness helper on the same address. These are
# correctness gates; timed comparisons below continue to use true-lo .2.
pgo_qual_handoff_python=(env -i PATH=/usr/local/bin:/usr/bin:/bin
    PYTHONPATH=/var/tmp/httpjet-h3-tools/python PYTHONDONTWRITEBYTECODE=1
    HJ_BENCH_ADDR=127.0.0.1 HJ_BENCH_BIND=127.0.0.1 python3 -B)
pgo_qual_scripts="$PGO_QUAL_HARNESS/scripts"
pgo_qual_binary="$PGO_RUN/bin-use/httpjet"
pgo_qual_helper="$PGO_RUN/bin-use/httpjet-beeper-h1"

pgo_qual_step h1-late-readiness "${pgo_qual_handoff_python[@]}" "$pgo_qual_scripts/beeper_h1_late_check.py" \
    --binary "$pgo_qual_binary" --helper "$pgo_qual_helper" --wakeup readiness \
    --results "$PGO_QUAL_OUT/h1-late-readiness"

# Only this corpus uses a 32 KiB H1 cap: it asserts the 32 KiB boundary hits.
pgo_qual_step h1-h2-ua "${pgo_qual_handoff_python[@]}" "$pgo_qual_scripts/beeper_h1_serve_check.py" \
    --binary "$pgo_qual_binary" --helper "$pgo_qual_helper" --arms "$PGO_QUAL_OUT/ua-arms.json" \
    --hit-metric httpjet_h1_kernel_successes_total --h2-ua-corpus \
    --results "$PGO_QUAL_OUT/h1-h2-ua"

pgo_qual_step h2-oversize "${pgo_qual_handoff_python[@]}" "$pgo_qual_scripts/beeper_h2_serve_check.py" \
    --binary "$pgo_qual_binary" --helper "$pgo_qual_helper" --results "$PGO_QUAL_OUT/h2-oversize"

pgo_qual_step h2-expiry "${pgo_qual_handoff_python[@]}" "$pgo_qual_scripts/beeper_h2_expiry_check.py" \
    --binary "$pgo_qual_binary" --helper "$pgo_qual_helper" --results "$PGO_QUAL_OUT/h2-expiry"

pgo_qual_step tls-smoke "${pgo_qual_python[@]}" "$pgo_qual_scripts/http_engine_check.py" \
    --arms "$PGO_QUAL_OUT/http-native-arms.json" --client "$PGO_QUAL_HTTP_CLIENT" \
    --sequence native --protocols h1s,h2 --cases static,pagecache,range --rounds 1 \
    --size 1024 --requests 1000 --warmup 100 --workers 1 --server-cpus 8 \
    --client-cpus 0,2,4,6,12,14 --client-threads 6 --connections 32 --streams 4 \
    --results "$PGO_QUAL_OUT/tls-smoke"

pgo_qual_step h3-shutdown "${pgo_qual_python[@]}" "$pgo_qual_scripts/h3_shutdown_check.py" \
    --candidate "$pgo_qual_binary" --modes legacy,accelerated --cases delivery,stop,unacked \
    --server-cpus 8 --source-commit "$PGO_QUAL_SOURCE_COMMIT" --results "$PGO_QUAL_OUT/h3-shutdown"

pgo_qual_step cache-required "${pgo_qual_python[@]}" "$pgo_qual_scripts/cache_required_lab.py" \
    --binary "$pgo_qual_binary" --address 127.0.0.2 --results "$PGO_QUAL_OUT/cache-required"

# Delivery preflight at the actual matrix transport settings; no timing claim.
pgo_qual_step h3-gso20-batch1 "${pgo_qual_python[@]}" "$pgo_qual_scripts/h3_engine_check.py" \
    --candidate "$pgo_qual_binary" --candidate-page-response-memo --client "$PGO_QUAL_H3_CLIENT" \
    --sequence accelerated --case all --steering off --rounds 1 \
    --candidate-arg=--h3-gso-segments=20 --candidate-arg=--h3-send-batch=1 \
    --workers 1 --server-cpus 8 --client-cpus 0,2,4,6,12,14 --client-threads 6 \
    --size 1024 --requests 1000 --warmup 100 --connections 32 --streams 4 \
    --results "$PGO_QUAL_OUT/h3-gso20-batch1"
