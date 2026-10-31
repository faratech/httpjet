#!/usr/bin/env python3
"""Independent final H2/H1/H3 receipt/CSV seal from saved files only."""
import argparse
import collections
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

REMOTE = Path('/var/tmp/httpjet-continuation/h2-repaired-final-bench-v1')
APP = 'abf7a79c1eb9593c3af7e77e60c4aaf4a5b30873d0e2b989283c88b662db9c48'
C7 = '24ccc3a889018e9c9a739ac1619da4f1c860f732dd3421c55daea2321e1fe12c'
HELPER = '0e7be72d437dd255e332ec1f6bd05554ae91ac2f54844793b1fe08691b184f4e'
HTTP_CLIENT = '0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6'
H3_CLIENT = 'afee4fd337ce7289c3a3122abba27fd3fa47605535d50f9b43aa4dff22e33a77'
BUSY = ['user', 'nice', 'system', 'irq', 'softirq']
METRICS = ['RPS', 'process_cpu_us_R', 'user_instructions_R', 'user_cycles_R', 'VM_busy_us_R',
           'scheduled_p99_us', 'service_p99_us', 'dispatch_lateness_p99_us', 'offload_fraction']


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def eq(a, b, tolerance=1e-8):
    assert math.isclose(a, b, rel_tol=1e-10, abs_tol=tolerance), (a, b)


def write_csv(path, rows):
    with path.open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def median(rows):
    return {key: statistics.median(row[key] for row in rows) for key in METRICS}


def delta(before, after):
    return {key: 100 * (after[key] / before[key] - 1) if before[key] else None for key in METRICS}


def prom(path):
    return {line.rsplit(None, 1)[0]: float(line.rsplit(None, 1)[1]) for line in path.read_text().splitlines()
            if line and not line.startswith('#')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    raw, out = args.raw.resolve(), args.out.resolve()
    assert not out.exists()
    local = lambda path: raw / Path(path).relative_to(REMOTE)
    rows, monitors, source_seals, admissions, outliers = [], [], {}, [], []
    raw_latency_rows = 0
    for phase, expected_jobs in [('run-h2-v1', ['same-use-h2', 'production-source']),
                                 ('run-h1h3-v1', ['production-source'])]:
        root = raw / phase
        completion, before, after = read(root / 'completion.json'), read(root / 'inputs-before.json'), read(root / 'inputs-after.json')
        assert completion['passed'] and completion['completed'] == expected_jobs and completion['error'] is None and completion['integrity_error'] is None
        assert before == after and (root / 'inputs-before.json').read_bytes() == (root / 'inputs-after.json').read_bytes()
        assert before['boot_id'] == '07a57341-882b-4a8b-8ab7-099d91374bda'
        assert next(iter(before['artifacts'].values()))['sha256'] == APP and before['helper']['sha256'] == HELPER
        assert before['c7']['source_entries_verified'] == 847
        source_seals[phase] = {p.name: sha(p) for p in [root / 'completion.json', root / 'plan.json', root / 'inputs-before.json', root / 'inputs-after.json']}
        for comparison in expected_jobs:
            tree = root / comparison
            plan = read(tree / 'plan.json')
            assert plan['profile'] == 'true-lo' and plan['expected_route_device'] == 'lo' and plan['rate'] == '15000'
            assert plan['environment']['HJ_BENCH_ADDR'] == plan['environment']['HJ_BENCH_BIND'] == '127.0.0.2'
            artifacts = plan['artifacts']
            baseline_sha = APP if comparison == 'same-use-h2' else C7
            assert artifacts['candidate']['sha256'] == APP and artifacts['native_baseline']['sha256'] == baseline_sha and artifacts['helper']['sha256'] == HELPER
            assert artifacts['http_client']['sha256'] == HTTP_CLIENT and artifacts['h3_client']['sha256'] == H3_CLIENT
            assert any(row.get('dev') == 'lo' for row in read(tree / 'route.json'))
            assert read(tree / 'completion.json')['completed_jobs'] == len(plan['jobs'])
            assert len(plan['jobs']) == (4 if phase == 'run-h1h3-v1' else 2)
            for job in plan['jobs']:
                protocol, case = job['protocol'], job['case']
                directory, measurements = local(job['directory']), local(job['results'])
                assert protocol in (['h1', 'h3'] if phase == 'run-h1h3-v1' else ['h2c']) and case in ['static', 'pagecache'] and job['size'] == 1024
                metadata = read(measurements / 'metadata.json')
                options = metadata['arguments']
                for key, expected in {'rounds': 3, 'requests': 60000, 'warmup': 5000, 'size': 1024,
                    'connections': 32, 'streams': 4, 'workers': 1, 'rate': '15000', 'server_hardware_counters': True,
                    'require_client_cpu_headroom': True, 'profile_dir': None}.items():
                    assert options[key] == expected, (job, key, options[key])
                if protocol == 'h3':
                    assert options['loader'] is None and options['baseline_h3_engine'] is None and options['sequence'] == 'baseline,accelerated,accelerated,baseline'
                else:
                    assert options['sequence'] == 'baseline,candidate,candidate,baseline'
                events = [json.loads(line) for line in (directory / 'monitor/environment.jsonl').read_text().splitlines()]
                config, final = events[0], events[-1]
                assert config['event'] == 'configuration' and config['quiet_seconds'] == 10 and final['event'] == 'finished'
                assert final['command_exit'] == 0 and final['compiler_overlap_observed'] is False and not final['unique_compilers']
                assert all(not event['compilers'] for event in events if event['event'] == 'running')
                assert all(a['monotonic_ns'] < b['monotonic_ns'] for a, b in zip(events, events[1:]))
                end = read(directory / 'exit.json')
                assert end['exit_code'] == 0 and not end['aborted'] and not end['forced_observer_kill'] and end['failure'] is None
                coverage = read(directory / 'kernel-coverage.json')
                assert not coverage['errors']
                monitors.append({'phase': phase, 'comparison': comparison, 'protocol': protocol, 'case': case,
                    'configuration': config, 'finished': final, 'sha256': sha(directory / 'monitor/environment.jsonl')})
                reports = sorted(measurements.glob('*/result.json'))
                assert len(reports) == 12 and not list(directory.glob('failure.json'))
                expected_positions = {(cycle, position) for cycle in [1, 2, 3] for position in [1, 2, 3, 4]}
                seen = set()
                aggregate = read(measurements / 'results.json')
                for path in reports:
                    arm_dir = path.parent
                    pattern = r'(?:h[12]c?-)?(?:static|pagecache)-([123])-([1234])-(baseline|candidate|accelerated)'
                    match = re.fullmatch(pattern, arm_dir.name)
                    assert match, arm_dir
                    cycle, position = int(match[1]), int(match[2]); role = 'baseline' if position in [1, 4] else 'candidate'
                    assert (cycle, position) not in seen and (match[3] == 'baseline') == (role == 'baseline')
                    seen.add((cycle, position))
                    value, server_exit = read(path), read(arm_dir / 'server-exit.json')
                    assert value in aggregate and server_exit['exit'] == 0 and not (arm_dir / 'failure.json').exists()
                    assert value['training_only'] is False and value['diagnostic_only'] is False
                    client = value['client']; offered = client['offered_load']
                    assert client['benchmark_valid'] and client['phase'] == 'measured'
                    assert client['requested'] == client['completed'] == client['succeeded'] == 60000 and client['failed'] == client['unattempted'] == 0 and not client['errors']
                    assert client['warmup_completed'] == 5000 and client['body_bytes'] == 1024 and client['expected_status'] == 200
                    assert client['requested_rate'] == '15000' and client['latency_scope'] == 'scheduled_to_completion'
                    expected_limit = 32 if protocol == 'h1' else 128
                    assert offered['concurrency_limit'] == expected_limit and offered['dispatched'] == 60000 and offered['expired_before_dispatch'] == 0 and not offered['fully_open_loop']
                    assert value['client_cpu_headroom_gate']['valid'] and value['client_cpu_headroom_gate']['passed'] and not value['cpu']['client_measured_saturation_warning']
                    assert len(client['client_sockets']) == 32 and all(s['local_address'].startswith('127.0.0.2:') for s in client['client_sockets'])
                    if protocol != 'h3':
                        assert client['warmup_requested'] == client['warmup_succeeded'] == 5000 and not client['driver_errors']
                        assert client['verified_body_bytes'] == client['received_body_bytes'] == 60000 * 1024 and client['status_counts'] == {'200': 60000}
                        assert value['arm']['sha256'] == (baseline_sha if role == 'baseline' else APP)
                        if role == 'candidate':
                            assert value['arm']['launcher']['sha256'] == HELPER
                    else:
                        assert value['server_binary_sha256'] == (C7 if role == 'baseline' else APP) and not value['loader']
                        assert value['client_binary_sha256'] == H3_CLIENT
                    latencies, service, lateness, phases, ids = [], [], [], collections.Counter(), collections.defaultdict(set)
                    with (arm_dir / 'latencies.tsv').open() as stream:
                        for record in csv.DictReader(stream, delimiter='\t'):
                            label = record.get('phase', 'measured')
                            assert label in ['warmup', 'measured'] and int(record['request']) not in ids[label]
                            ids[label].add(int(record['request'])); phases[label] += 1; raw_latency_rows += 1
                            assert record['bytes'] == '1024' and not record['error']
                            if 'status' in record:
                                assert record['status'] == '200'
                            if label == 'measured':
                                scheduled, dispatched, completed = map(int, [record['scheduled_offset_ns'], record['dispatch_offset_ns'], record['completion_offset_ns']])
                                assert record['dispatched'] == 'true'
                                eq(float(record['latency_us']), (completed - scheduled) / 1000, .001)
                                eq(float(record['service_latency_us']), (completed - dispatched) / 1000, .001)
                                eq(float(record['dispatch_lateness_us']), (dispatched - scheduled) / 1000, .001)
                                latencies.append((completed - scheduled) / 1000); service.append((completed - dispatched) / 1000); lateness.append((dispatched - scheduled) / 1000)
                    assert phases['measured'] == 60000 and phases['warmup'] == (0 if protocol == 'h3' else 5000)
                    for values, expected in [(latencies, client['p99_us']), (service, offered['service']['p99_us']), (lateness, offered['dispatch_lateness']['p99_us'])]:
                        values.sort(); eq(values[math.ceil(len(values) * .99) - 1], expected, .001)
                    cpu, hw = value['cpu'], value['hardware_counters']; old, new = cpu['server_process_ticks_before'], cpu['server_process_ticks_after']
                    helper_used = protocol != 'h3' and role == 'candidate'
                    assert old['pids'] == new['pids'] and len(old['pids']) == (2 if helper_used else 1)
                    assert hw['valid'] and hw['minimum_running_fraction'] == 1 and all(hw['totals'][key] > 0 for key in ['cycles', 'instructions'])
                    assert sorted(hw.get('process_pids', [hw['pid']])) == sorted(old['pids'])
                    ticks = value['linux_cpu_ticks']['ticks_per_second']; assert ticks == 100
                    eq(cpu['server_user_secs'], (new['user'] - old['user']) / ticks); eq(cpu['server_system_secs'], (new['system'] - old['system']) / ticks)
                    delta_vm = value['linux_cpu_ticks']['delta']['cpu']; assert all(n >= 0 for n in delta_vm.values())
                    previous, following = prom(arm_dir / 'before.prom'), prom(arm_dir / 'after.prom')
                    for key, val in value['metric_deltas'].items():
                        eq(val, following.get(key, 0) - previous.get(key, 0))
                    metric = f'httpjet_{"h1" if protocol == "h1" else "h2"}_kernel_successes_total'
                    success = value['metric_deltas'].get(metric)
                    if protocol != 'h3' and role == 'candidate':
                        assert success is not None and 0 < success <= 65000 and value['metric_deltas'][f'httpjet_{"h1" if protocol == "h1" else "h2"}_kernel_failures_total'] == 0
                    elif protocol != 'h3' and success is not None:
                        assert success == 0
                    if protocol == 'h3' and role == 'candidate':
                        assert value['metric_deltas']['httpjet_h3_request_engine_total{path="on_core"}'] > 0
                    assert value['metric_deltas']['httpjet_pagecache_hits_total'] > 0 if case == 'pagecache' else 'cache' in value['cache_evidence'] or 'memo' in value['cache_evidence']
                    row = {'phase': phase, 'comparison': comparison, 'protocol': protocol, 'case': case, 'cycle': cycle, 'position': position,
                        'role': role, 'RPS': client['successful_requests_per_sec'], 'process_cpu_us_R': (cpu['server_user_secs'] + cpu['server_system_secs']) * 1e6 / 65000,
                        'user_instructions_R': hw['totals']['instructions'] / 65000, 'user_cycles_R': hw['totals']['cycles'] / 65000,
                        'VM_busy_us_R': sum(delta_vm[key] for key in BUSY) * 1e6 / ticks / 65000,
                        'scheduled_p99_us': client['p99_us'], 'service_p99_us': offered['service']['p99_us'],
                        'dispatch_lateness_p99_us': offered['dispatch_lateness']['p99_us'], 'offload_fraction': success / 65000 if success is not None and protocol != 'h3' else 0,
                        'helper_used': helper_used, 'admission_limit': expected_limit,
                        'admission_waits': offered['concurrency_waits'], 'peak_in_flight': offered['peak_in_flight']}
                    rows.append(row)
                    if row['admission_waits']:
                        admissions.append(row)
                    if row['scheduled_p99_us'] > 10000:
                        outliers.append(row)
                assert seen == expected_positions
    assert len(rows) == 96 and raw_latency_rows == 6120000 and len(monitors) == 8
    grouped, changes, cycles = [], [], []
    combinations = sorted({(r['comparison'], r['protocol'], r['case']) for r in rows})
    for comparison, protocol, case in combinations:
        selected = [r for r in rows if (r['comparison'], r['protocol'], r['case']) == (comparison, protocol, case)]
        by_role = {role: median([r for r in selected if r['role'] == role]) for role in ['baseline', 'candidate']}
        for role, values in by_role.items():
            grouped.append({'comparison': comparison, 'protocol': protocol, 'case': case, 'role': role, 'arms': 6, **values})
        aggregate_change = delta(by_role['baseline'], by_role['candidate']); changes.append({'comparison': comparison, 'protocol': protocol, 'case': case, **aggregate_change})
        for cycle in [1, 2, 3]:
            pair = {role: median([r for r in selected if r['role'] == role and r['cycle'] == cycle]) for role in ['baseline', 'candidate']}
            change = delta(pair['baseline'], pair['candidate'])
            opposite = [key for key in METRICS if change[key] is not None and aggregate_change[key] is not None and change[key] * aggregate_change[key] < 0]
            cycles.append({'comparison': comparison, 'protocol': protocol, 'case': case, 'cycle': cycle, **change, 'opposite_direction': ';'.join(opposite)})
    out.mkdir()
    write_csv(out / 'arms.csv', rows); write_csv(out / 'groups.csv', grouped); write_csv(out / 'changes-percent.csv', changes); write_csv(out / 'cycles-percent.csv', cycles)
    manifest = [{'path': str(p.relative_to(raw)), 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(raw.rglob('*')) if p.is_file()]
    (out / 'raw-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    receipt = {'schema': 1, 'passed': True, 'arms': 96, 'measured_responses': 5760000, 'warmup_completed_responses': 480000,
        'raw_latency_rows_verified': raw_latency_rows, 'H3_raw_schema_limitation': 'H3 TSV contains measured latency/bytes/error only, without status or warmup rows; status and completed warmups are checked through client summaries and the pinned validating harness/client.',
        'scope': 'Synthetic warm 1 KiB matched-rate comparisons only. Process CPU includes helper for H1/H2 kernel arms; H3 is native accelerated without helper.',
        'source_before_after_seals': source_seals, 'boot_id': '07a57341-882b-4a8b-8ab7-099d91374bda', 'monitors': monitors,
        'comparisons': changes, 'cycles': cycles, 'admission_wait_arms': admissions, 'p99_above_10ms_arms': outliers,
        'normalization': {'CPU_PMU_VM_denominator': 65000, 'latency_denominator': 60000, 'tick_hz': 100,
            'latency': 'Scheduled arrival to completion; median of six arm p99 values, not pooled request p99. Service/dispatch quantiles separate, never added.',
            'load': '15,000 R/s with bounded admission: H1=32, H2/H3=128; not unrestricted open loop or measured capacity.',
            'process_CPU': 'Server plus helper user+system over entire client span; excludes kernel/IRQ charged elsewhere.',
            'PMU': 'User-mode server/helper instructions/cycles; excludes kernel/IRQ/hypervisor.',
            'VM_CPU': 'All Linux CPUs user+nice+system+IRQ+softIRQ; includes clients/unrelated work; Windows host unobserved.'},
        'limitations': ['C7 is a fresh native rebuild of historically attributed production source, not exact deployed994127 provenance.',
            'One-second compiler sampling does not observe sub-interval activity or Windows-host scheduling.',
            'Any VM increases remain visible; server process CPU reductions do not establish universal overall CPU gains.'],
        'raw_manifest_sha256': sha(out / 'raw-manifest.json'), 'recompute_sha256': sha(__file__),
        'outputs_sha256': {p.name: sha(p) for p in out.iterdir() if p.is_file()}}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'receipt': str(out / 'receipt.json'), 'sha256': sha(out / 'receipt.json'), 'changes': changes,
                      'admission_wait_arms': len(admissions), 'total_admission_waits': sum(row['admission_waits'] for row in admissions)}))


if __name__ == '__main__':
    main()
