#!/usr/bin/env python3
"""Summarize the sealed PGO H2 rate study, retaining every planned arm.

Prepared only. Usage: python3 -B summarize-pgo-h2-rate.py [INPUT] --output NEW.json
No aggregate performance medians are emitted unless the entire planned run seals.
"""
import argparse
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import stat
import statistics
import sys

RUN = Path('/var/tmp/httpjet-continuation/pgo-c6ac-v1')
ROOT = RUN / 'h2-rate15000-v1'
MONITOR = RUN / 'rate-monitor-v1'
CLIENT = Path('/var/tmp/httpjet-http-paced-client-v2/bin/httpjet-http-load-paced')
PINS = {
    str(RUN / 'bin-use/httpjet'): '0ca04dcb8d3b9d07e02ac19658546d7882d6f2719c6937be2f259ca65eef83c5',
    str(RUN / 'bin-use/httpjet-beeper-h1'): '1cce1f3ca5837e5d68b9be757438af28a88be789468372392bf6148a3987721d',
    '/var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet': '3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec',
    str(CLIENT): '0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6',
}
SEQUENCE = ['release', 'native', 'kernel', 'kernel', 'native', 'release']
CASES = ['static', 'pagecache']
METRICS = ['rps', 'scheduled_p99_us', 'service_p99_us', 'dispatch_lateness_p99_us',
           'process_cpu_us_per_response', 'user_instructions_per_response',
           'user_cycles_per_response', 'whole_vm_busy_us_per_response', 'kernel_success_fraction']
SOURCES = {}
ISSUES = []


def require(value, message):
    if not value:
        raise ValueError(message)


def reject_constant(value):
    raise ValueError(f'nonfinite JSON constant: {value}')


def digest(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode), f'not a regular, nonsymlink file: {path}')
    data = path.read_bytes()
    identity = {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    if str(path) in SOURCES:
        require(SOURCES[str(path)] == identity, f'file changed during analysis: {path}')
    SOURCES[str(path)] = identity
    return identity['sha256']


def read_json(path, issues, required=True):
    path = Path(path)
    try:
        digest(path)
        return json.loads(path.read_text(), parse_constant=reject_constant)
    except (OSError, ValueError) as error:
        if required or path.exists():
            issues.append(f'{path}: {type(error).__name__}: {error}')
        return None


def attempt(label, operation):
    try:
        return operation()
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
        ISSUES.append(f'{label}: {type(error).__name__}: {error}')
        return None


def number(value):
    require(not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value) and value >= 0, f'invalid measurement: {value!r}')
    return value


def expected_arms():
    release = '/var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet'
    binary, helper = str(RUN / 'bin-use/httpjet'), str(RUN / 'bin-use/httpjet-beeper-h1')
    return {
        'release': {'name': 'release', 'binary': release, 'sha256': PINS[release], 'serve_args': []},
        'native': {'name': 'native', 'binary': binary, 'sha256': PINS[binary],
                   'serve_args': ['--h1-kernel', 'off', '--page-cache-response-memo']},
        'kernel': {'name': 'kernel', 'binary': binary, 'sha256': PINS[binary],
                   'serve_args': ['--h1-kernel', 'required', '--h2-kernel', '--page-cache-response-memo'],
                   'launcher': {'binary': helper, 'sha256': PINS[helper], 'args': []}},
    }


def check_global(root, before, after, manifest, metadata, status):
    require(before == after and isinstance(before, dict), 'pre/post input snapshots are absent or differ')
    require(before['pins'] == PINS, 'snapshot binary identities differ from the selected PGO/release/client')
    require(before['network'] == {'server': '127.0.0.2', 'client_bind': '127.0.0.2'}, 'wrong network profile')
    require(before['harness_sha256'] == manifest and isinstance(manifest, dict), 'harness manifest drift')
    required = {f'scripts/{n}.py' for n in ['http_engine_check', 'h3_engine_check', 'bench_environment_run',
                                          'bench_cpu', 'bench_hw_counters', 'bench_syscall_counts']}
    required |= {'packaging/debian/conf/' + n for n in ['httpd_config.xml', 'mime.properties', 'vhosts/default.xml']}
    require(required <= set(manifest), 'required harness/fixture inputs are absent')
    for name, sha in manifest.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, f'unsafe manifest path: {name}')
        require(isinstance(sha, str) and re.fullmatch('[0-9a-f]{64}', sha), f'invalid SHA: {name}')
        require(digest(RUN / 'rate-harness' / relative) == sha, f'harness/fixture hash mismatch: {name}')
    required_inputs = [RUN / name for name in ['rate-harness-sha256.json', 'h2-rate15000-arms-v1.json',
        'use-artifacts.json', 'build-use.json', 'profile-use-warnings.json', 'pgo-inputs.json',
        'build-source-manifest.json', 'merge-receipt.json', 'coverage-review.json', 'profile-inputs.json',
        'qualification-v2/qualification.json', 'final-pgo-release-true-lo-v1/summary.json',
        'final-pgo-release-true-lo-v1/final-integrity.json']]
    required_inputs += [Path('/var/tmp/pgo-c-common.sh'), Path('/var/tmp/pgo-c-h2-rate.sh')]
    require({str(p) for p in required_inputs} <= set(before['input_sha256']), 'required source/script receipts are unpinned')
    for name, sha in before['input_sha256'].items():
        require(digest(Path(name)) == sha, f'source/script receipt hash mismatch: {name}')
    for name, sha in PINS.items():
        require(digest(Path(name)) == sha, f'current binary hash mismatch: {name}')
    source = json.loads((RUN / 'build-source-manifest.json').read_text())
    require(isinstance(source, dict) and source, 'runtime source manifest absent')
    for name, sha in source.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, f'unsafe runtime source path: {name}')
        # AGENTS.md is a tracked alias of CLAUDE.md. Accept source aliases only
        # when their resolved target stays inside this frozen source tree.
        resolved = (RUN / 'src' / relative).resolve(strict=True)
        require(resolved.is_relative_to((RUN / 'src').resolve()), f'escaping runtime source alias: {name}')
        require(digest(resolved) == sha, f'runtime source hash mismatch: {name}')
    capacity = json.loads((RUN / 'final-pgo-release-true-lo-v1/summary.json').read_text())
    seal = json.loads((RUN / 'final-pgo-release-true-lo-v1/final-integrity.json').read_text())
    require(capacity['status'] == 'complete' and len(capacity['cells']) == 20
            and all(c['status'] == 'complete' for c in capacity['cells']), 'capacity prerequisite is incomplete')
    require(seal['status'] == 'passed' and seal['completed_arms'] == 240
            and seal['summary_sha256'] == digest(RUN / 'final-pgo-release-true-lo-v1/summary.json'), 'capacity seal mismatch')
    require(metadata['host'][1].upper() == 'SINGULARITY', 'wrong execution host')
    require(metadata['training_only'] is False and metadata['arms'] == expected_arms(), 'wrong arms or training mode')
    args = metadata['arguments']
    options = {'rounds': 3, 'requests': 60000, 'warmup': 5000, 'size': 1024, 'connections': 32, 'streams': 4,
        'workers': 1, 'client_threads': 6, 'client_timeout_secs': 10, 'server_cpus': '8',
        'client_cpus': '0,2,4,6,12,14', 'protocols': 'h2c', 'cases': 'static,pagecache', 'rate': '15000',
        'sequence': ','.join(SEQUENCE), 'server_hardware_counters': True,
        'require_client_cpu_headroom': True, 'profile_dir': None, 'core_pinning': False}
    require(all(args.get(k) == value for k, value in options.items()), 'recorded workload/gate options differ')
    require(metadata['client'] == {'path': str(CLIENT), 'sha256': PINS[str(CLIENT)]}, 'client identity mismatch')
    require(metadata['manifest_sha256'] == digest(RUN / 'h2-rate15000-arms-v1.json'), 'arm manifest hash mismatch')
    require(metadata['harness'] == {'path': str(RUN / 'rate-harness/scripts/http_engine_check.py'),
                                  'sha256': manifest['scripts/http_engine_check.py']}, 'HTTP harness identity mismatch')
    for key, name in [('shared_helper_sha256', 'h3_engine_check'), ('cpu_helper_sha256', 'bench_cpu'),
                      ('hardware_helper_sha256', 'bench_hw_counters')]:
        require(metadata[key] == manifest[f'scripts/{name}.py'], f'{key} mismatch')
    require(status['passed'] is True and status['command_exit'] == status['final_integrity_exit'] == 0
            and status['completed_arms'] == status['expected_arms'] == 36 and not status['errors'], 'run status is not sealed')
    require(status['results'] == str(root) and status['monitor_directory'] == str(MONITOR), 'wrong result/monitor paths')
    require(status['measured_responses'] == 2160000 and status['warmup_responses'] == 180000, 'sealed response totals differ')


def arm(root, case, cycle, position, mode):
    directory = root / f'h2c-{case}-{cycle}-{position}-{mode}'
    issues = []
    row = {'case': case, 'cycle': cycle, 'position': position, 'mode': mode, 'directory': str(directory),
           'status': 'not_started' if not directory.exists() else 'incomplete', 'issues': issues, 'metrics': None}
    result = read_json(directory / 'result.json', issues)
    exited = read_json(directory / 'server-exit.json', issues)
    failure = read_json(directory / 'failure.json', issues, False)
    row.update(source=str(directory / 'result.json'), failure=failure, server_exit=exited)
    row['source_sha256'] = SOURCES.get(str(directory / 'result.json'), {}).get('sha256')
    if result is None:
        if (directory / 'failure.json').exists() or (isinstance(exited, dict) and exited.get('exit') != 0):
            row['status'] = 'failed'
        return row
    client = result.get('client') if isinstance(result, dict) else None
    try:
        require(not issues and not (directory / 'failure.json').exists(), 'missing, invalid or failed arm receipts')
        require(result['arm'] == expected_arms()[mode], 'wrong server/helper/serving flags')
        require(result['protocol'] == 'h2c' and result['case'] == case, 'wrong protocol/fixture')
        require(result['benchmark_valid'] is True and not result['training_only']
                and not result.get('diagnostic_only') and result['client_exit'] == 0, 'unqualified result')
        require(client['benchmark_valid'] and client['phase'] == 'measured' and client['protocol'] == 'h2', 'invalid client phase/protocol')
        require(client['requested'] == client['completed'] == client['succeeded'] == 60000
                and client['failed'] == client['unattempted'] == 0
                and not client['errors'] and not client['driver_errors'], 'failed or incomplete measured requests')
        require(client['warmup_requested'] == client['warmup_completed'] == client['warmup_succeeded'] == 5000, 'warmup incomplete')
        require(client['body_bytes'] == 1024 and client['verified_body_bytes'] == client['received_body_bytes'] == 61440000
                and client['expected_status'] == 200 and client['status_counts'] == {'200': 60000}, 'body/status verification incomplete')
        require(client['latency_scope'] == 'scheduled_to_completion' and client['requested_rate'] == '15000', 'wrong latency scope/rate')
        offered = client['offered_load']
        require(offered['rate_spec'] == '15000' and offered['concurrency_limit'] == 128
                and offered['fully_open_loop'] is False and offered['dispatched'] == 60000
                and offered['expired_before_dispatch'] == 0, 'rate/admission/failure semantics differ')
        require(all(offered[k]['count'] == 60000 for k in ['scheduled_all_outcomes', 'service', 'dispatch_lateness']), 'latency outcome counts incomplete')
        sockets = client['client_sockets']
        require(len(sockets) == 32 and all(ipaddress.ip_address(x['local_address'].rsplit(':', 1)[0].strip('[]'))
                == ipaddress.ip_address('127.0.0.2') for x in sockets), 'actual client bind proof missing')
        require(type(exited['exit']) is int and exited['exit'] == 0, 'server did not exit cleanly')
        hw, gate = result['hardware_counters'], result['client_cpu_headroom_gate']
        require(hw['valid'] and hw['include_user'] is True and hw['exclude_kernel'] is True
                and gate['valid'] and gate['passed'], 'PMU/headroom gate failed')
        require(result['metric_deltas_include_client_warmup'] is True, 'unknown counter denominator')
        count = result['metric_deltas'].get('httpjet_h2_kernel_successes_total')
        if count is not None: number(count)
        require((count is not None and 0 < number(count) <= 65000) if mode == 'kernel'
                else count in (0, None), 'kernel activation/native ownership mismatch')
        vm = result['linux_cpu_ticks']
        ticks = number(vm['ticks_per_second']); require(ticks > 0, 'invalid CPU timebase')
        values = [vm['delta']['cpu']] if 'cpu' in vm['delta'] else [v for k, v in vm['delta'].items() if k.startswith('cpu') and k[3:].isdigit()]
        require(bool(values), 'whole-VM CPU counters missing')
        busy = sum(number(v[k]) for v in values for k in ['user', 'nice', 'system', 'irq', 'softirq'])
        metrics = {'rps': client['successful_requests_per_sec'], 'scheduled_p99_us': client['p99_us'],
            'service_p99_us': offered['service']['p99_us'], 'dispatch_lateness_p99_us': offered['dispatch_lateness']['p99_us'],
            'process_cpu_us_per_response': 1e6 * (number(result['cpu']['server_user_secs']) + number(result['cpu']['server_system_secs'])) / 65000,
            'user_instructions_per_response': number(hw['totals']['instructions']) / 65000,
            'user_cycles_per_response': number(hw['totals']['cycles']) / 65000,
            'whole_vm_busy_us_per_response': 1e6 * busy / ticks / 65000,
            'kernel_success_fraction': count / 65000 if count is not None else None}
        for value in metrics.values():
            if value is not None: number(value)
        require(metrics['rps'] > 0 and metrics['user_instructions_per_response'] > 0 and metrics['user_cycles_per_response'] > 0, 'nonpositive measured work')
        peak, waits = number(offered['peak_in_flight']), number(offered['concurrency_waits'])
        require(peak <= 128 and type(peak) is int and type(waits) is int, 'invalid admission statistics')
        running = number(hw['minimum_running_fraction'])
        require(0 < running <= 1.000001, 'invalid PMU running fraction')
        row.update(status='complete', metrics=metrics, peak_in_flight=peak, concurrency_waits=waits,
            kernel_successes=count, pmu_running_fraction=running,
            recorded_arm=result['arm'], latency_counts={k: offered[k]['count'] for k in ['scheduled_all_outcomes', 'service', 'dispatch_lateness']},
            denominator={'measured_responses': 60000, 'warmup_responses': 5000, 'whole_client_span_responses': 65000})
    except (KeyError, TypeError, ValueError, AttributeError, ZeroDivisionError) as error:
        issues.append(f'{type(error).__name__}: {error}')
        failed = (directory / 'failure.json').exists() or (isinstance(exited, dict) and exited.get('exit') != 0)
        failed |= isinstance(result, dict) and (result.get('client_exit', 0) != 0 or result.get('benchmark_valid') is False)
        failed |= isinstance(client, dict) and bool(client.get('failed', 0) or client.get('unattempted', 0)
                                                    or client.get('benchmark_valid') is False)
        row.update(status='failed' if failed else 'incomplete', raw_client=client, recorded_arm=result.get('arm') if isinstance(result, dict) else None)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', nargs='?', type=Path, default=ROOT)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(not args.output.exists() and not args.output.is_symlink(), 'output must be a new file')
    root = args.input.resolve()
    require(root == ROOT, f'this experiment expects input {ROOT}')
    before = read_json(RUN / 'h2-rate15000-inputs-before-v1.json', ISSUES)
    after = read_json(RUN / 'h2-rate15000-inputs-after-v1.json', ISSUES)
    manifest = read_json(RUN / 'rate-harness-sha256.json', ISSUES)
    metadata = read_json(root / 'metadata.json', ISSUES)
    status = read_json(RUN / 'h2-rate15000-status-v1.json', ISSUES)
    attempt('input/identity/seal validation', lambda: check_global(root, before, after, manifest, metadata, status))
    rows = [arm(root, case, cycle, position, mode) for case in CASES for cycle in [1, 2, 3]
            for position, mode in enumerate(SEQUENCE, 1)]
    expected = {r['source'] for r in rows}
    unplanned = []
    for path in sorted(root.glob('*/result.json')):
        if str(path) not in expected:
            unplanned.append({'source': str(path), 'status': 'unplanned', 'result': read_json(path, ISSUES)})
    if unplanned: ISSUES.append(f'{len(unplanned)} unplanned result records; none will be aggregated')
    events_path = MONITOR / 'environment.jsonl'
    events = attempt('observer log', lambda: [json.loads(line) for line in events_path.read_text().splitlines()])
    if events is not None:
        attempt('observer log hash', lambda: digest(events_path))
        attempt('observer validation', lambda: require(bool(events) and events[-1].get('event') == 'finished'
            and events[-1].get('command_exit') == 0 and events[-1].get('compiler_overlap_observed') is False
            and events[0].get('event') == 'configuration' and events[0].get('observer_affinity') == [10]
            and events[0].get('quiet_seconds') == 10 and events[0].get('interval_seconds') == 1
            and not any(e.get('event') == 'running' and e.get('compilers') for e in events), 'observer completion/compiler evidence failed'))
    if isinstance(status, dict):
        attempt('sealed observer evidence', lambda: require(bool(events) and status.get('monitor') == events[-1], 'monitor differs from sealed status'))
        sealed_rows = {r['source']: r for r in status.get('rows', [])}
        attempt('sealed arm hashes', lambda: require(len(sealed_rows) == 36 and all(
            r['source'] in sealed_rows and r['source_sha256'] == sealed_rows[r['source']]['source_sha256'] for r in rows), 'arm files differ from final status receipt'))
    # Catch mutation during analysis before constructing any medians.
    for path, identity in list(SOURCES.items()):
        attempt('final file immutability', lambda p=path, sha=identity['sha256']: require(digest(Path(p)) == sha, f'input changed: {p}'))
    complete = not ISSUES and not unplanned and len(rows) == 36 and all(r['status'] == 'complete' for r in rows)
    groups = []
    for case in CASES:
        for mode in ['release', 'native', 'kernel']:
            group = [r for r in rows if r['case'] == case and r['mode'] == mode]
            valid = [r for r in group if r['status'] == 'complete']
            groups.append({'case': case, 'mode': mode, 'planned_arms': 6, 'validated_arms': len(valid),
                'status': 'complete' if complete else 'unqualified',
                'max_peak_in_flight': max((r['peak_in_flight'] for r in valid), default=None),
                'total_concurrency_waits': sum(r['concurrency_waits'] for r in valid),
                'arms_at_cap': sum(r['peak_in_flight'] == 128 for r in valid),
                'admission_statistics_scope': 'validated arms only; partial counts are not complete-run estimates',
                'medians': {k: statistics.median(v) if v else None for k in METRICS
                    for v in [[r['metrics'][k] for r in group if r['metrics'][k] is not None]]} if complete else None})
    report = {'schema': 1, 'status': 'complete' if complete else 'failed' if any(r['status'] == 'failed' for r in rows)
        or (isinstance(status, dict) and status.get('passed') is False) else 'incomplete',
        'input': str(root), 'issues': ISSUES, 'rows': rows, 'unplanned_rows': unplanned, 'groups': groups,
        'offered_rate': 15000, 'concurrency_limit': 128, 'fully_open_loop': False,
        'sequence': SEQUENCE, 'cycles': 3, 'requests_per_arm': 60000, 'warmup_per_arm': 5000,
        'planned_arms': 36, 'validated_arms': sum(r['status'] == 'complete' for r in rows),
        'measured_responses': 2160000 if complete else None, 'warmup_responses': 180000 if complete else None,
        'monitor': events[-1] if events else None, 'run_status': status, 'artifacts': PINS,
        'source_inputs': SOURCES, 'summarizer': {'path': str(Path(__file__).resolve()), 'sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        'scopes': {'latency': 'scheduled-to-completion, service and dispatch lateness p99 are distinct; never add quantiles',
            'aggregation': 'medians of the six complete per-arm values per fixture/mode; not pooled request percentiles; all36 arms and global seals must validate',
            'offered_load': 'bounded admission at128; peak/cap/wait counts remain visible; not unrestricted open loop or proof of continuous unsaturation',
            'throughput': 'rate-matched15k/s; achieved RPS validates delivery at this offered rate, not maximum capacity',
            'process_cpu': 'server and helper user+system CPU over the whole client span, including handshake/warmup/measurement/output/drain; denominator65000; excludes kernel/IRQ work charged elsewhere',
            'pmu': 'server/helper user-mode instructions/cycles only; kernel/IRQ/hypervisor work excluded; denominator65000',
            'whole_vm': 'all Linux CPUs user+nice+system+IRQ+softIRQ, converted using recorded tick timebase; includes clients/unrelated Linux work; Windows host unobserved',
            'interpretation': 'process CPU and VM busy are separate scopes; neither establishes whole-server CPU savings or performance superiority'}}
    with args.output.open('x') as out:
        json.dump(report, out, indent=2, allow_nan=False); out.write('\n')
    print('case\tmode\tstatus\tarms\trps\tscheduled_p99_ms\tservice_p99_ms\tdispatch_p99_ms\tprocess_cpu_us/R\tVM_busy_us/R\tpeak\twaits\tarms_at128')
    for group in groups:
        m = group['medians']
        values = [f'{m[k] / 1000:.3f}' for k in ['scheduled_p99_us', 'service_p99_us', 'dispatch_lateness_p99_us']] if m else ['n/a'] * 3
        print('\t'.join(map(str, [group['case'], group['mode'], group['status'], f"{group['validated_arms']}/6",
            f"{m['rps']:.1f}" if m else 'n/a', *values,
            f"{m['process_cpu_us_per_response']:.2f}" if m else 'n/a', f"{m['whole_vm_busy_us_per_response']:.2f}" if m else 'n/a',
            group['max_peak_in_flight'], group['total_concurrency_waits'], group['arms_at_cap']])) )
    return 0 if complete else 1


if __name__ == '__main__':
    sys.exit(main())
