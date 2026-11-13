#!/usr/bin/env python3
"""Run one new, immutable final H2 comparison; execute only on SINGULARITY.

Prepared only. No retry, restart, reconnect or cleanup of unrelated processes.
The tested observer/harness owns and reaps its own process tree.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys

RUN = Path('/var/tmp/httpjet-continuation/h2-quiescent-v2/pgo-v1')
HARNESS = RUN.parent / 'harness-current'
OLD = Path('/var/tmp/httpjet-continuation/pgo-c6ac-v1/bin-use/httpjet')
RELEASE = Path('/var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet')
FIXED = {str(OLD): '0ca04dcb8d3b9d07e02ac19658546d7882d6f2719c6937be2f259ca65eef83c5',
         str(RELEASE): '3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec'}
CLIENTS = {
    'capacity': ('/var/tmp/hjc/httpjet-http-load-bind',
                 'e5c21fa94ea72c965cd4cfea950977c2bb771a4a5842a58499a5b1355c758b8f'),
    'rate15000': ('/var/tmp/httpjet-http-paced-client-v2/bin/httpjet-http-load-paced',
                  '0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6'),
}
CHECKS = {'h2-oversize', 'h2-expiry', 'h2-lifecycle', 'h1-h2-ua', 'cache-required',
          'tls-smoke', 'h3-shutdown', 'h3-gso20-batch1', 'h1-late-readiness', 'inputs-before'}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode), f'not a regular nonsymlink file: {path}')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    sha(path)
    return json.loads(Path(path).read_text(), parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))


def write(path, value):
    with Path(path).open('x') as file:
        json.dump(value, file, indent=2, allow_nan=False)
        file.write('\n')


def process_census(executables):
    """Observe matching artifact processes; never signal them by pathname."""
    rows = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            executable = str((entry / 'exe').resolve(strict=True))
            if executable not in executables:
                continue
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            rows.append({'pid': int(entry.name), 'starttime_ticks': int(fields[19]),
                         'executable': executable})
        except (OSError, ValueError, IndexError):
            continue
    return sorted(rows, key=lambda row: row['pid'])


def snapshot(plan):
    # Both functions are read-only source/profile integrity checks on this host.
    subprocess.run(['bash', '-c', 'set -euo pipefail; source /var/tmp/h2q-pgo-common.sh; '
                    'pgo_check_inputs; pgo_check_profile_review'], check=True)
    use = read(RUN / 'use-artifacts.json')
    expected = {str(RUN / 'bin-use' / name) for name in
                ['httpjet', 'httpjet-beeper-h1', 'httpjet-beeper-observe', 'httpjet-quic-steer']}
    require(set(use) == expected, 'fresh artifact inventory differs')
    pins = dict(FIXED)
    for path, row in use.items():
        require(sha(path) == row['sha256'] and Path(path).stat().st_size == row['bytes']
                and os.access(path, os.X_OK), f'fresh artifact changed: {path}')
        pins[path] = row['sha256']
    pins[plan['client']] = plan['client_sha256']
    for path, value in pins.items():
        require(sha(path) == value and os.access(path, os.X_OK), f'artifact pin mismatch: {path}')
    qpath = RUN / 'final-qualification/qualification.json'
    q = read(qpath)
    require(q['schema'] == 1 and q['passed'] is True and q['artifacts'] == use,
            'final functional qualification does not bind exact fresh artifacts')
    checks = q['checks']
    names = [row['name'] for row in checks]
    require(len(names) == len(set(names)) and CHECKS <= set(names), 'required functional checks absent')
    paths = [qpath]
    for row in checks:
        p = Path(row['receipt_path'])
        require(row['passed'] is True and p.is_absolute() and sha(p) == row['receipt_sha256'],
                f'qualification receipt failed/drifted: {row["name"]}')
        paths.append(p)
    build = read(RUN / 'build-use.json')
    flags = f'-Ctarget-cpu=native -Cforce-frame-pointers=yes -Cprofile-use={RUN}/runtime.profdata -Cllvm-args=-pgo-warn-missing-function'
    require(build['exit'] == 0 and build['rustflags'] == flags, 'unexpected fresh PGO build')
    warnings = read(RUN / 'profile-use-warnings.json')
    require(warnings['accepted_for_correctness_qualification'] is True
            and not warnings['control_flow_or_profile_hash_mismatches'], 'PGO profile mismatch')
    audit = read(RUN / 'use-fingerprint-audit.json')
    require(audit['verified'] is True, 'fresh fingerprint audit failed')
    for row in audit['fingerprints'].values():
        require(sha(row['copy']) == row['sha256'] and row['rustflags'] == flags.split(),
                'fresh fingerprint drift')
        paths.append(Path(row['copy']))
    inputs = read(RUN / 'pgo-inputs.json')
    object_path = Path(inputs['bpf_reference']['root']) / 'objects/h1_serve'
    object_bytes = object_path.read_bytes()
    binding = audit['helper_bpf_binding']
    fresh_helper = RUN / 'bin-use/httpjet-beeper-h1'
    require(binding['helper_sha256'] == sha(fresh_helper)
            and binding['h1_serve_sha256'] == sha(object_path)
            and fresh_helper.read_bytes().find(object_bytes) == binding['object_offset'] >= 0,
            'fresh helper does not embed selected qualified serving object')
    harness = {f'scripts/{name}': value for name, value in inputs['harness_sha256'].items()}
    harness.update(inputs['fixture_sha256'])
    required = {f'scripts/{name}.py' for name in ['http_engine_check', 'h3_engine_check',
                'bench_cpu', 'bench_hw_counters', 'bench_syscall_counts', 'bench_environment_run']}
    required |= {'packaging/debian/conf/' + name for name in
                 ['httpd_config.xml', 'mime.properties', 'vhosts/default.xml']}
    require(required <= set(harness), 'frozen harness inventory incomplete')
    for name, value in harness.items():
        rel = Path(name)
        require(not rel.is_absolute() and '..' not in rel.parts
                and sha(HARNESS / rel) == value, f'frozen harness drift: {name}')
    paths.extend(RUN / name for name in ['use-artifacts.json', 'build-use.json',
        'profile-use-warnings.json', 'use-fingerprint-audit.json', 'use.rustc_info.json',
        'pgo-inputs.json', 'build-source-manifest.json', 'qualified-inputs.json',
        'bpf-objects.json', 'bpf-source-identity', 'merge-receipt.json',
        'profile-inputs.json', 'coverage-review.json', 'runtime.profdata'])
    paths.extend(Path(name) for name in ['/var/tmp/h2q-pgo-common.sh',
        '/var/tmp/h2q-final-run.sh', '/var/tmp/h2q-final-run.py', '/var/tmp/h2q-final-summarize.py'])
    paths.extend([Path(plan['control']) / 'plan.json', Path(plan['control']) / 'arms.json'])
    route = json.loads(subprocess.run(['ip', '-j', 'route', 'get', '127.0.0.2', 'from', '127.0.0.2'],
                                     check=True, capture_output=True, text=True).stdout)
    require(any(row.get('dev') == 'lo' for row in route), 'benchmark route does not use lo')
    census = process_census(set(pins))
    require(not census, f'selected artifact processes still present: {census}')
    return {'pins': pins, 'inputs': {str(p): sha(p) for p in paths}, 'harness': harness,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'uname': list(os.uname()), 'network': {'server': '127.0.0.2', 'client_bind': '127.0.0.2'},
            'selected_artifact_processes': census}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=CLIENTS)
    args = parser.parse_args()
    require(socket.gethostname().upper() == 'SINGULARITY' and os.geteuid() == 0,
            'execute only as root on SINGULARITY')
    require(os.sched_getaffinity(0) == {10}, 'runner/observer must use CPU10')
    control = RUN / f'h2-final-{args.mode}-v1'
    require(not control.exists() and not control.is_symlink(), 'retain existing run; choose a reviewed new version')
    control.mkdir(mode=0o755)
    client, client_sha = CLIENTS[args.mode]
    pairs = [('fresh-native', 'fresh-kernel'), ('old-native', 'old-kernel')]
    if args.mode == 'capacity':
        pairs.append(('release', 'release-kernel'))
    sequence = [name for a, b in pairs for name in [a, b, b, a]]
    binary, helper = str(RUN / 'bin-use/httpjet'), str(RUN / 'bin-use/httpjet-beeper-h1')
    native_args = ['--h1-kernel', 'off', '--page-cache-response-memo']
    kernel_args = ['--h1-kernel', 'required', '--h2-kernel', '--page-cache-response-memo']
    arms = [{'name': 'fresh-native', 'binary': binary, 'serve_args': native_args},
            {'name': 'old-native', 'binary': str(OLD), 'serve_args': native_args}]
    if args.mode == 'capacity':
        arms.append({'name': 'release', 'binary': str(RELEASE), 'serve_args': []})
    arms.extend({'name': b, 'binary': binary, 'serve_args': kernel_args,
                 'launcher': {'binary': helper}} for _, b in pairs)
    plan = {'schema': 1, 'mode': args.mode, 'control': str(control), 'harness': str(HARNESS),
            'results': str(control / 'results'), 'monitor': str(control / 'monitor'),
            'arms': arms, 'pairs': pairs, 'sequence': sequence, 'rounds': 3,
            'cases': ['static', 'pagecache'], 'size': 1024, 'client': client, 'client_sha256': client_sha,
            'requests': 200000 if args.mode == 'capacity' else 60000,
            'warmup': 10000 if args.mode == 'capacity' else 5000,
            'rate': None if args.mode == 'capacity' else '15000',
            'scope': 'per-worker true-loopback experiment; no timing improvement is an acceptance precondition'}
    write(control / 'plan.json', plan)
    write(control / 'arms.json', arms)
    before = snapshot(plan)
    write(control / 'inputs-before.json', before)
    command = ['python3', '-B', str(HARNESS / 'scripts/http_engine_check.py'),
        '--arms', str(control / 'arms.json'), '--client', client, '--sequence', ','.join(sequence),
        '--rounds', '3', '--protocols', 'h2c', '--cases', 'static,pagecache', '--size', '1024',
        '--requests', str(plan['requests']), '--warmup', str(plan['warmup']),
        '--workers', '1', '--server-cpus', '8', '--client-threads', '6',
        '--client-cpus', '0,2,4,6,12,14', '--connections', '32', '--streams', '4',
        '--client-timeout-secs', '10', '--server-hardware-counters', '--require-client-cpu-headroom',
        '--results', plan['results']]
    if plan['rate']:
        command.extend(['--rate', plan['rate']])
    observed = ['python3', '-B', str(HARNESS / 'scripts/bench_environment_run.py'),
                '--output', plan['monitor'], '--quiet-seconds', '10', '--interval-seconds', '1', '--', *command]
    write(control / 'command.json', observed)
    process = None
    code, interrupted, integrity_error = None, None, None
    def interrupt(signum, _):
        raise KeyboardInterrupt(signum)
    for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
        signal.signal(sig, interrupt)
    try:
        process = subprocess.Popen(observed, stdin=subprocess.DEVNULL)
        code = process.wait()
    except KeyboardInterrupt as error:
        interrupted = str(error)
        if process is not None and process.poll() is None:
            # Exact owned Popen PID. Observer signals and reaps its harness tree.
            process.terminate()
            code = process.wait()
        if code == 0 or code is None:
            code = 130
    finally:
        try:
            after = snapshot(plan)
            write(control / 'inputs-after.json', after)
            require(after == before, 'source/artifact/boot/network identity drift during trial')
        except Exception as error:
            integrity_error = f'{type(error).__name__}: {error}'
        write(control / 'run-status.json', {'command_exit': code, 'interrupted': interrupted,
            'final_integrity_error': integrity_error, 'same_inputs_and_boot': integrity_error is None,
            'scope': 'execution/integrity only; summarizer independently validates every planned arm'})
    summary_code = subprocess.run(['python3', '-B', '/var/tmp/h2q-final-summarize.py', str(control),
                                  '--output', str(control / 'summary.json')]).returncode
    return code if code else (1 if integrity_error else summary_code)


if __name__ == '__main__':
    sys.exit(main())
