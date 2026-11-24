#!/usr/bin/env python3
"""Exact shipped release versus qualified retained candidate, SINGULARITY only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

ROOT = Path('/var/tmp/httpjet-continuation/exact-release-p99-v1')
TOOLS = Path('/var/tmp/httpjet-continuation/h2-repaired-final-bench-v1/tools')
PGO = Path('/var/tmp/httpjet-continuation/h2-repaired-pgo-v1')
RELEASE = ROOT / 'httpjet-release'
CANDIDATE = PGO / 'bin-use/httpjet'
OWNER = Path('/var/tmp/h2r-pgo.py')
OWNER_SHA = 'a53cde6cef97db96d98680434bc7692668ce1fee19a5d1536e53979d1f8622ef'
RELEASE_SHA = '3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec'
CANDIDATE_SHA = 'abf7a79c1eb9593c3af7e77e60c4aaf4a5b30873d0e2b989283c88b662db9c48'
HELPER = Path('/var/tmp/httpjet-continuation/h2-certified-linear-pull-v1/bin/helper')
CLIENT = Path('/var/tmp/httpjet-http-paced-client-v2/bin/httpjet-http-load-paced')
H3_CLIENT = Path('/var/tmp/httpjet-continuation/h3-bind-client-20261030/bin/httpjet-h3-load-bind')
ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'PYTHONPATH': '/var/tmp/httpjet-h3-tools/python',
       'PYTHONDONTWRITEBYTECODE': '1', 'HJ_BENCH_ADDR': '127.0.0.2', 'HJ_BENCH_BIND': '127.0.0.2'}

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def save(p, v):
    with Path(p).open('x') as f:
        json.dump(v, f, indent=2, allow_nan=False)
        f.write('\n')

def main():
    assert socket.gethostname().upper() == 'SINGULARITY' and os.geteuid() == 0
    assert len(sys.argv) == 1
    os.umask(0o022)
    os.sched_setaffinity(0, {10})
    assert sha(OWNER) == OWNER_SHA
    spec = importlib.util.spec_from_file_location('retained_candidate_guard', OWNER)
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    spec = importlib.util.spec_from_file_location('benchmark_owned_commands', OWNER)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    run = ROOT / 'run-v1'
    run.mkdir(mode=0o755, exist_ok=False)
    (run / 'logs').mkdir()
    owner.RUN = run
    owner.enable_owned_subreaper()
    q = PGO / 'qualification-use-v1/qualification.json'
    manifest = TOOLS / 'files.sha256'
    assert sha(manifest) == '610a1fcd94110760e51021c25027452824b7bc31132f2c4e410f6a807f9728c7'
    assert sha(TOOLS / 'scripts/integrated_bench.py') == '823de4b84de075f163e715fd227c163df44a1eb5a8887d71aabf4f1bd7216432'
    pins = {}
    for line in manifest.read_text().splitlines():
        value, name = line.split(maxsplit=1)
        name = name.lstrip('*')
        assert not Path(name).is_absolute() and '..' not in Path(name).parts and name not in pins
        assert sha(TOOLS / name) == value
        pins[name] = value
    assert len(pins) == 10
    def snapshot():
        guard.inputs()
        guard.check_review()
        artifacts = guard.verify_artifacts('use')
        qualification = json.loads(q.read_text())
        release = json.loads((ROOT / 'release-receipt.json').read_text())
        assert qualification['passed'] is True and len(qualification['completed']) == 11
        assert qualification['artifacts'] == artifacts and qualification['helper_sha256'] == guard.HELPER_SHA
        assert release['release'] == 'v0.1.10-11' and release['binary_sha256'] == RELEASE_SHA
        assert sha(ROOT / 'release.tar.gz') == release['asset_sha256'] == '67695c65902e0437fbecffe8b94c502e98d635dff78aee5dcc604f3e9f5900c2'
        assert sha(RELEASE) == RELEASE_SHA and sha(CANDIDATE) == CANDIDATE_SHA
        assert sha(CLIENT) == '0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6'
        assert sha(H3_CLIENT) == 'afee4fd337ce7289c3a3122abba27fd3fa47605535d50f9b43aa4dff22e33a77'
        assert all(sha(TOOLS / name) == value for name, value in pins.items())
        docker = ['docker', '--host', 'unix:///var/run/docker.sock']
        containers = subprocess.check_output(docker + ['ps', '-q'], text=True).strip()
        assert not containers, 'Docker workloads active; preserve run and stop before measurements'
        identity = json.loads(subprocess.check_output(docker + ['info', '--format', '{{json .}}'], text=True))
        return {'artifacts': artifacts, 'helper': guard.helper_inputs(), 'tools': pins,
            'docker': {'endpoint': 'unix:///var/run/docker.sock', 'id': identity['ID'], 'name': identity['Name'], 'running': []},
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'files': {str(p): sha(p) for p in [Path(__file__).resolve(), OWNER, RELEASE, CANDIDATE, HELPER,
                CLIENT, H3_CLIENT, q, manifest, ROOT / 'release-receipt.json', ROOT / 'release.tar.gz',
                PGO / 'use-artifacts.json', PGO / 'use-fingerprint.json', PGO / 'profile-use-warnings.json',
                PGO / 'coverage-review.json', PGO / 'merge-receipt.json', PGO / 'profile-inputs.json',
                PGO / 'runtime.profdata']}}
    command = ['python3', '-B', str(TOOLS / 'scripts/integrated_bench.py'),
        '--release', str(RELEASE), '--native-baseline', str(RELEASE), '--candidate', str(CANDIDATE),
        '--http-client', str(CLIENT), '--h3-client', str(H3_CLIENT), '--helper', str(HELPER),
        '--python', '/usr/bin/python3', '--pythonpath', ENV['PYTHONPATH'], '--profile', 'true-lo',
        '--comparison', 'release', '--sizes', '1024', '--cases', 'static,pagecache', '--cycles', '3',
        '--requests', '60000', '--warmup', '5000', '--rate', '15000', '--connections', '32', '--streams', '4',
        '--server-cpu', '8', '--observer-cpu', '10', '--client-cpus', '0,2,4,6,12,14',
        '--release-receipt', str(ROOT / 'release-receipt.json'), '--candidate-receipt', str(q),
        '--protocols', 'h1,h1s,h2c,h2,h3', '--h1-kernel', '--h1-wakeup', 'readiness', '--h2-kernel',
        '--h3-gso-segments', '20', '--h3-send-batch', '1', '--results', str(run / 'release-comparison')]
    save(run / 'plan.json', {'command': command, 'planned_arms': 120,
        'scope': 'Exact public v0.1.10-11 binary versus retained qualified ABF; 1KiB static and warm page cache, 15k offered requests/sec; 3 ABBA cycles for H1/H1TLS/H2c/H2TLS/H3. Plain H1/H2 kernel enabled candidate only; TLS native; H3 accelerated candidate. Linux VM CPU includes clients; this is not a capacity test.'})
    before = snapshot()
    save(run / 'inputs-before.json', before)
    error, integrity_error, completed = None, None, False
    try:
        result = owner.owned_run('release-comparison', command, env=ENV, kind='corpus')
        assert result['passed'] and result['exit'] == 0
        completed = True
    except BaseException as e:
        error = f'{type(e).__name__}: {e}'
    finally:
        try:
            assert not (run / 'pending-cleanup.json').exists()
            after = snapshot()
            save(run / 'inputs-after.json', after)
            assert before == after
        except BaseException as e:
            integrity_error = f'{type(e).__name__}: {e}'
        save(run / 'completion.json', {'passed': completed and error is None and integrity_error is None,
            'planned_arms': 120, 'error': error, 'integrity_error': integrity_error})
    return 0 if completed and error is None and integrity_error is None else 1

if __name__ == '__main__':
    raise SystemExit(main())
