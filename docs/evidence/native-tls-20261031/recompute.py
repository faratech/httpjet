#!/usr/bin/env python3
"""Recompute the sealed native TLS48 experiment from saved evidence only."""
import argparse
import collections
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

REMOTE = Path('/var/tmp/httpjet-continuation/h2-repaired-tls-native-bench-v1')
APP = 'abf7a79c1eb9593c3af7e77e60c4aaf4a5b30873d0e2b989283c88b662db9c48'
C7 = '24ccc3a889018e9c9a739ac1619da4f1c860f732dd3421c55daea2321e1fe12c'
CLIENT = '0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6'
DRIVER = '97d2baf65c4a3e4889d359eaa187c68c0242807510ef5bf5ffab0cc62ce1e221'
TOOLS_MANIFEST = '610a1fcd94110760e51021c25027452824b7bc31132f2c4e410f6a807f9728c7'
BOOT = '07a57341-882b-4a8b-8ab7-099d91374bda'
BUSY = ['user', 'nice', 'system', 'irq', 'softirq']
METRICS = ['RPS', 'process_cpu_us_R', 'user_instructions_R', 'user_cycles_R',
           'VM_busy_us_R', 'scheduled_p99_us', 'service_p99_us', 'dispatch_lateness_p99_us']


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
    root = raw / 'run-v1'
    completion, before, after = [read(root / name) for name in ['completion.json', 'inputs-before.json', 'inputs-after.json']]
    assert completion['passed'] and completion['planned_arms'] == 48 and completion['phase'] == 'native-tls'
    assert completion['completed'] == ['production-source'] and completion['error'] is None and completion['integrity_error'] is None
    assert before == after and (root / 'inputs-before.json').read_bytes() == (root / 'inputs-after.json').read_bytes()
    assert before['boot_id'] == before['c7']['boot_id'] == BOOT
    assert len(before['artifacts']) == 1 and next(iter(before['artifacts'].values()))['sha256'] == APP
    assert before['c7']['source_entries_verified'] == 847
    assert before['files']['/var/tmp/h2r-tls-native-bench.py'] == DRIVER
    assert before['files']['/var/tmp/httpjet-continuation/h2-repaired-final-bench-v1/tools/files.sha256'] == TOOLS_MANIFEST
    tree = root / 'production-source'
    plan = read(tree / 'plan.json')
    assert plan['profile'] == 'true-lo' and plan['expected_route_device'] == 'lo' and plan['rate'] == '15000'
    assert plan['environment']['HJ_BENCH_ADDR'] == plan['environment']['HJ_BENCH_BIND'] == '127.0.0.2'
    artifacts = plan['artifacts']
    assert artifacts['candidate']['sha256'] == APP and artifacts['native_baseline']['sha256'] == artifacts['release']['sha256'] == C7
    assert artifacts['http_client']['sha256'] == CLIENT and 'helper' not in artifacts
    assert any(row.get('dev') == 'lo' for row in read(tree / 'route.json'))
    assert read(tree / 'completion.json')['completed_jobs'] == len(plan['jobs']) == 4
    assert set((j['protocol'], j['case']) for j in plan['jobs']) == {(p, c) for p in ['h1s', 'h2'] for c in ['static', 'pagecache']}
    harness = tree / 'harness'
    count = 0
    for name, pin in plan['source_inputs'].items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        assert sha(harness / name) == pin['sha256'] == before['tools'][name]
        count += 1
    assert count == len(before['tools']) == 10
    rows, monitors, admissions = [], [], []
    raw_latency_rows = 0
    for job in plan['jobs']:
        protocol, case = job['protocol'], job['case']
        directory, measurements = local(job['directory']), local(job['results'])
        assert job['size'] == 1024
        assert job['arms'] == [{'name': 'baseline', 'binary': artifacts['native_baseline']['path'], 'serve_args': ['--no-mtls']},
                               {'name': 'candidate', 'binary': artifacts['candidate']['path'], 'serve_args': ['--page-cache-response-memo']}]
        assert all(not k['requested'] and k['expected'] == 'zero' for k in job['kernel_expectations'].values())
        assert all('launcher' not in arm for arm in read(directory / 'arms.json'))
        metadata = read(measurements / 'metadata.json'); options = metadata['arguments']
        for key, expected in {'rounds': 3, 'requests': 60000, 'warmup': 5000, 'size': 1024, 'connections': 32,
            'streams': 4, 'workers': 1, 'rate': '15000', 'server_hardware_counters': True,
            'require_client_cpu_headroom': True, 'profile_dir': None, 'kernel_sample_bin': None, 'kernel_sample_lib': None,
            'sequence': 'baseline,candidate,candidate,baseline', 'server_cpus': '8', 'client_cpus': '0,2,4,6,12,14'}.items():
            assert options[key] == expected, (job, key, options[key])
        assert metadata['training_only'] is metadata['diagnostic_only'] is False
        events = [json.loads(line) for line in (directory / 'monitor/environment.jsonl').read_text().splitlines()]
        config, final = events[0], events[-1]
        assert config['event'] == 'configuration' and config['quiet_seconds'] == 10 and final['event'] == 'finished'
        assert final['command_exit'] == 0 and final['compiler_overlap_observed'] is False and not final['unique_compilers']
        assert all(not e['compilers'] for e in events if e['event'] == 'running')
        assert all(a['monotonic_ns'] < b['monotonic_ns'] for a, b in zip(events, events[1:]))
        exit_info = read(directory / 'exit.json')
        assert exit_info['exit_code'] == 0 and not exit_info['aborted'] and not exit_info['forced_observer_kill'] and exit_info['failure'] is None
        coverage = read(directory / 'kernel-coverage.json'); assert not coverage['errors']
        monitors.append({'protocol': protocol, 'case': case, 'configuration': config, 'finished': final,
                         'sha256': sha(directory / 'monitor/environment.jsonl')})
        reports = sorted(measurements.glob('*/result.json'))
        assert len(reports) == 12 and not (directory / 'failure.json').exists()
        expected_positions = {(c, p) for c in [1, 2, 3] for p in [1, 2, 3, 4]}
        seen = set(); aggregate = read(measurements / 'results.json')
        for path in reports:
            arm_dir = path.parent
            match = re.fullmatch(r'h(?:1s|2)-(?:static|pagecache)-([123])-([1234])-(baseline|candidate)', arm_dir.name)
            assert match, arm_dir
            cycle, position = int(match[1]), int(match[2]); role = 'baseline' if position in [1, 4] else 'candidate'
            assert (cycle, position) not in seen and match[3] == role
            seen.add((cycle, position))
            value, server_exit = read(path), read(arm_dir / 'server-exit.json')
            assert value in aggregate and server_exit['exit'] == value['client_exit'] == 0 and not (arm_dir / 'failure.json').exists()
            assert value['training_only'] is value['diagnostic_only'] is False and value['benchmark_valid']
            assert all(value[k] is None for k in ['kernel_profile', 'profile_directory', 'profile_file_pattern', 'profile_server'])
            assert value['arm']['sha256'] == (C7 if role == 'baseline' else APP) and 'launcher' not in value['arm']
            assert value['correctness']['tls_verified'] is True and value['correctness']['protocol'] == protocol
            client = value['client']; offered = client['offered_load']
            assert client['benchmark_valid'] and client['phase'] == 'measured' and not client['driver_errors']
            assert client['requested'] == client['completed'] == client['succeeded'] == 60000
            assert client['failed'] == client['unattempted'] == 0 and not client['errors']
            assert client['warmup_requested'] == client['warmup_completed'] == client['warmup_succeeded'] == 5000
            assert client['body_bytes'] == 1024 and client['expected_status'] == 200 and client['status_counts'] == {'200': 60000}
            assert client['verified_body_bytes'] == client['received_body_bytes'] == 60000 * 1024
            assert client['requested_rate'] == '15000' and client['latency_scope'] == 'scheduled_to_completion'
            limit = 32 if protocol == 'h1s' else 128
            assert offered['concurrency_limit'] == limit and offered['dispatched'] == 60000 and offered['expired_before_dispatch'] == 0 and not offered['fully_open_loop']
            assert value['client_cpu_headroom_gate']['valid'] and value['client_cpu_headroom_gate']['passed'] and not value['cpu']['client_measured_saturation_warning']
            assert len(client['client_sockets']) == 32 and all(s['local_address'].startswith('127.0.0.2:') for s in client['client_sockets'])
            latencies, service, lateness, phases, ids = [], [], [], collections.Counter(), collections.defaultdict(set)
            with (arm_dir / 'latencies.tsv').open() as stream:
                for record in csv.DictReader(stream, delimiter='\t'):
                    label = record['phase']; request = int(record['request'])
                    assert label in ['warmup', 'measured'] and request not in ids[label]
                    ids[label].add(request); phases[label] += 1; raw_latency_rows += 1
                    assert record['bytes'] == '1024' and record['status'] == '200' and not record['error']
                    if label == 'measured':
                        scheduled, dispatched, completed = map(int, [record['scheduled_offset_ns'], record['dispatch_offset_ns'], record['completion_offset_ns']])
                        assert record['dispatched'] == 'true'
                        eq(float(record['latency_us']), (completed - scheduled) / 1000, .001)
                        eq(float(record['service_latency_us']), (completed - dispatched) / 1000, .001)
                        eq(float(record['dispatch_lateness_us']), (dispatched - scheduled) / 1000, .001)
                        latencies.append((completed - scheduled) / 1000)
                        service.append((completed - dispatched) / 1000); lateness.append((dispatched - scheduled) / 1000)
            assert phases == {'measured': 60000, 'warmup': 5000}
            for values, expected in [(latencies, client['p99_us']), (service, offered['service']['p99_us']), (lateness, offered['dispatch_lateness']['p99_us'])]:
                values.sort(); eq(values[math.ceil(len(values) * .99) - 1], expected, .001)
            cpu, hw = value['cpu'], value['hardware_counters']
            old, new = cpu['server_process_ticks_before'], cpu['server_process_ticks_after']
            assert old['pids'] == new['pids'] and len(old['pids']) == 1
            assert hw['valid'] and hw['minimum_running_fraction'] == 1 and all(hw['totals'][k] > 0 for k in ['cycles', 'instructions'])
            assert hw['pid'] == old['pids'][0] and hw['include_user'] and hw['exclude_kernel'] and hw['exclude_hypervisor'] and hw['exclude_guest']
            assert not hw['inherit_child_processes']
            ticks = value['linux_cpu_ticks']['ticks_per_second']; assert ticks == 100
            eq(cpu['server_user_secs'], (new['user'] - old['user']) / ticks)
            eq(cpu['server_system_secs'], (new['system'] - old['system']) / ticks)
            delta_vm = value['linux_cpu_ticks']['delta']['cpu']; assert all(n >= 0 for n in delta_vm.values())
            previous, following = prom(arm_dir / 'before.prom'), prom(arm_dir / 'after.prom')
            for key, val in value['metric_deltas'].items():
                eq(val, following.get(key, 0) - previous.get(key, 0))
                if '_kernel_' in key:
                    assert val == 0, (arm_dir, key, val)
            assert all(n >= 0 for n in value['kernel_counters_delta'].values())
            assert value['metric_deltas']['httpjet_pagecache_hits_total'] > 0 if case == 'pagecache' else 'cache' in value['cache_evidence'] or 'memo' in value['cache_evidence']
            row = {'protocol': protocol, 'case': case, 'cycle': cycle, 'position': position, 'role': role,
                'RPS': client['successful_requests_per_sec'],
                'process_cpu_us_R': (cpu['server_user_secs'] + cpu['server_system_secs']) * 1e6 / 65000,
                'user_instructions_R': hw['totals']['instructions'] / 65000, 'user_cycles_R': hw['totals']['cycles'] / 65000,
                'VM_busy_us_R': sum(delta_vm[k] for k in BUSY) * 1e6 / ticks / 65000,
                'scheduled_p99_us': client['p99_us'], 'service_p99_us': offered['service']['p99_us'],
                'dispatch_lateness_p99_us': offered['dispatch_lateness']['p99_us'],
                'helper_used': False, 'kernel_offload_successes': 0, 'admission_limit': limit,
                'admission_waits': offered['concurrency_waits'], 'peak_in_flight': offered['peak_in_flight'],
                'VM_tcp_retransmissions': value['kernel_counters_delta']['tcp_RetransSegs'],
                'VM_tcp_timeouts': value['kernel_counters_delta']['tcp_TCPTimeouts']}
            rows.append(row)
            if row['admission_waits']:
                admissions.append(row)
        assert seen == expected_positions
    assert len(rows) == 48 and raw_latency_rows == 3120000 and len(monitors) == 4
    grouped, changes, cycles = [], [], []
    for protocol, case in sorted({(r['protocol'], r['case']) for r in rows}):
        selected = [r for r in rows if (r['protocol'], r['case']) == (protocol, case)]
        roles = {role: median([r for r in selected if r['role'] == role]) for role in ['baseline', 'candidate']}
        for role, values in roles.items():
            grouped.append({'protocol': protocol, 'case': case, 'role': role, 'arms': 6, **values})
        aggregate_change = delta(roles['baseline'], roles['candidate'])
        changes.append({'protocol': protocol, 'case': case, **aggregate_change})
        for cycle in [1, 2, 3]:
            pair = {role: median([r for r in selected if r['role'] == role and r['cycle'] == cycle]) for role in ['baseline', 'candidate']}
            change = delta(pair['baseline'], pair['candidate'])
            opposite = [k for k in METRICS if change[k] is not None and aggregate_change[k] is not None and change[k] * aggregate_change[k] < 0]
            cycles.append({'protocol': protocol, 'case': case, 'cycle': cycle, **change, 'opposite_direction': ';'.join(opposite)})
    out.mkdir()
    write_csv(out / 'arms.csv', rows); write_csv(out / 'groups.csv', grouped)
    write_csv(out / 'changes-percent.csv', changes); write_csv(out / 'cycles-percent.csv', cycles)
    manifest = [{'path': str(p.relative_to(raw)), 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(raw.rglob('*')) if p.is_file()]
    (out / 'raw-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    receipt = {'schema': 1, 'passed': True, 'arms': 48, 'measured_responses': 2880000, 'warmup_completed_responses': 240000,
        'raw_latency_rows_verified': raw_latency_rows, 'scope': 'Native encrypted H1/H2 only, no helper or kernel serving. Warm 1 KiB static/page cache, matched 15,000 R/s.',
        'artifact_sha256': {'candidate': APP, 'historical_production_source_control': C7, 'client': CLIENT},
        'source_before_after_exact': True, 'boot_id': BOOT,
        'source_seals': {p.name: sha(p) for p in [root / 'completion.json', root / 'plan.json', root / 'inputs-before.json', root / 'inputs-after.json']},
        'monitors': monitors, 'comparisons': changes, 'cycles': cycles, 'admission_wait_arms': admissions,
        'normalization': {'CPU_PMU_VM_denominator': 65000, 'latency_denominator': 60000, 'tick_hz': 100,
            'latency': 'Scheduled arrival to completion; median of six arm p99 values, not pooled request p99. Service/dispatch quantiles separate, never added.',
            'load': '15,000 R/s bounded admission: H1s=32, H2=128; not unrestricted open loop or measured capacity.',
            'process_CPU': 'One server process user+system over the entire client span including warmup; excludes kernel/IRQ charged elsewhere.',
            'PMU': 'User-mode server instructions/cycles; excludes kernel/IRQ/hypervisor/guest.',
            'VM_CPU': 'All Linux CPUs user+nice+system+IRQ+softIRQ, including clients/unrelated work; Windows host unobserved.'},
        'limitations': ['C7 is a fresh native rebuild of historically attributed production source, not exact deployed 994127 bytes.',
            'Candidate uses the opt-in page-response memo. These are native TLS gains/losses and are not evidence of Beeper kernel TLS serving.',
            'One-second compiler sampling cannot observe sub-interval activity or Windows-host scheduling.',
            'Forum preview/test containers were closed after this experiment; these measurements retain the earlier background-service context.'],
        'raw_manifest_sha256': sha(out / 'raw-manifest.json'), 'recompute_sha256': sha(__file__),
        'outputs_sha256': {p.name: sha(p) for p in out.iterdir() if p.is_file()}}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'receipt': str(out / 'receipt.json'), 'sha256': sha(out / 'receipt.json'), 'changes': changes,
        'admission_wait_arms': len(admissions), 'total_admission_waits': sum(r['admission_waits'] for r in admissions)}))


if __name__ == '__main__':
    main()
