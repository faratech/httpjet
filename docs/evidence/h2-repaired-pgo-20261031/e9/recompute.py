#!/usr/bin/env python3
"""Recompute the sealed 24-arm E9/helper0e rate evidence; never runs an engine."""
import argparse
import collections
import csv
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

SERVER = 'e9be9eca3c2fa6ad0f01e493696e1d3f74899345b81e705423e6c3a799112676'
HELPER = '0e7be72d437dd255e332ec1f6bd05554ae91ac2f54844793b1fe08691b184f4e'
CLIENT = '0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6'
BUSY = ['user', 'nice', 'system', 'irq', 'softirq']
LOWER = ['process_cpu_us_R', 'scheduled_p99_us', 'service_p99_us', 'VM_busy_us_R']


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def equal(a, b, tolerance=1e-8):
    assert math.isclose(a, b, rel_tol=1e-10, abs_tol=tolerance), (a, b)


def prom(path):
    return {line.rsplit(None, 1)[0]: float(line.rsplit(None, 1)[1])
            for line in Path(path).read_text().splitlines() if line and not line.startswith('#')}


def med(rows, keys):
    return {key: statistics.median(row[key] for row in rows) for key in keys}


def changes(before, after):
    return {key: 100 * (after[key] / before[key] - 1) if before[key] else None for key in before}


def write_csv(path, rows):
    with path.open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    base, out = args.raw.resolve(), args.out.resolve()
    assert not out.exists(), 'preserve earlier seals; choose a new output directory'
    root = base / 'h2-pgo-rate-v1'
    monitor = base / 'h2-pgo-rate-v1-monitor'
    metadata, scope = read(root / 'metadata.json'), read(base / 'h2-pgo-rate-scope-v1.json')
    options = metadata['arguments']
    assert metadata['training_only'] is False and metadata['diagnostic_only'] is False
    expected_options = {'protocols': 'h2c', 'cases': 'static,pagecache', 'sequence': 'native,repaired,repaired,native',
        'rounds': 3, 'size': 1024, 'requests': 60000, 'warmup': 5000, 'rate': '15000',
        'connections': 32, 'streams': 4, 'workers': 1, 'server_cpus': '8',
        'client_cpus': '0,2,4,6,12,14', 'server_hardware_counters': True,
        'require_client_cpu_headroom': True, 'profile_dir': None, 'kernel_sample_bin': None}
    assert all(options[key] == value for key, value in expected_options.items())
    assert scope['server_sha256'] == SERVER and scope['helper_sha256'] == HELPER and scope['ret_ms'] == 1
    assert metadata['client']['sha256'] == CLIENT
    assert sha(base / 'h2-pgo-rate-arms-v1.json') == metadata['manifest_sha256']
    assert metadata['arms']['native']['sha256'] == metadata['arms']['repaired']['sha256'] == SERVER
    assert metadata['arms']['repaired']['launcher']['sha256'] == HELPER
    assert metadata['harness']['sha256'] == '6b7b239d1dfc07c2ae81efcf5ea597e2f402cff35a27b145fe70d36fd5004655'
    assert metadata['hardware_helper_sha256'] == '243f2644b60c5df6dbe46ea79f39b073c11c2e7db60f99a0c422457f1a430f69'
    environment = [json.loads(line) for line in (monitor / 'environment.jsonl').read_text().splitlines()]
    config, final = environment[0], environment[-1]
    assert config['event'] == 'configuration' and final['event'] == 'finished'
    assert final['command_exit'] == 0 and final['compiler_overlap_observed'] is False and not final['unique_compilers']
    assert config['quiet_seconds'] == 10 and config['interval_seconds'] == 1 and config['observer_affinity'] == [10]
    assert config['observer_sha256'] == 'ddc9968d15a845e7e584fff5756546979a268e42b619c6812b8402ebe47b3dd2'
    samples = [row for row in environment if row['event'] in ['waiting', 'running']]
    assert samples and all(not row['compilers'] for row in samples)
    assert all(a['monotonic_ns'] < b['monotonic_ns'] for a, b in zip(environment, environment[1:]))
    quiet = next(row for row in environment if row['event'] == 'quiet_start')
    assert quiet['monotonic_ns'] - next(row for row in environment if row['event'] == 'waiting')['monotonic_ns'] >= 10_000_000_000
    provenance = read(base / 'frozen-helper-provenance/provenance.json')
    assert sha(base / 'frozen-helper-provenance/provenance.json') == '839a29a749231a806efe5acfcbbdf3439d969d4f57c5fb5bb273f14510cb6723'
    assert provenance['artifact']['sha256'] == HELPER and provenance['object_sha256']['h1_serve'] == '4bdf891e8a249de182c68714a48ae29ed1c6dbb1e43d90a063dfd8421932677b'
    assert provenance['source_h2_sha256'] == '0cd1e3a8796a283e963b9a5b4c905295d2810743a6b3f51f8b4d1e8e4782ab99'
    expected = {(case, cycle, position, arm) for case in ['static', 'pagecache'] for cycle in [1, 2, 3]
                for position, arm in enumerate(['native', 'repaired', 'repaired', 'native'], 1)}
    aggregate = read(root / 'results.json')
    assert len(aggregate) == 24
    rows, identities, admissions = [], set(), []
    for directory in sorted(root.glob('h2c-*')):
        match = re.fullmatch(r'h2c-(static|pagecache)-([123])-([1234])-(native|repaired)', directory.name)
        assert match and directory.is_dir(), directory
        case, cycle, position, arm = match[1], int(match[2]), int(match[3]), match[4]
        key = (case, cycle, position, arm)
        assert key in expected and key not in identities
        identities.add(key)
        result, client, end = read(directory / 'result.json'), read(directory / 'client.json'), read(directory / 'server-exit.json')
        assert result in aggregate and result['client'] == client and result['arm'] == metadata['arms'][arm]
        assert result['case'] == case and result['protocol'] == 'h2c' and result['benchmark_valid'] is True
        assert not result['training_only'] and not result['diagnostic_only'] and result['client_exit'] == end['exit'] == 0
        assert not (directory / 'failure.json').exists()
        assert client['benchmark_valid'] is True and client['phase'] == 'measured' and client['protocol'] == 'h2'
        assert client['requested'] == client['completed'] == client['succeeded'] == 60000
        assert client['warmup_requested'] == client['warmup_completed'] == client['warmup_succeeded'] == 5000
        assert client['failed'] == client['unattempted'] == 0 and not client['errors'] and not client['driver_errors']
        assert client['body_bytes'] == 1024 and client['verified_body_bytes'] == client['received_body_bytes'] == 60000 * 1024
        assert client['expected_status'] == 200 and client['status_counts'] == {'200': 60000}
        assert client['latency_scope'] == 'scheduled_to_completion' and client['requested_rate'] == '15000'
        assert client['connections'] == 32 and client['streams_per_connection'] == 4
        assert len(client['client_sockets']) == 32
        assert all(s['local_address'].startswith('127.0.0.2:') and s['peer_address'].startswith('127.0.0.2:') for s in client['client_sockets'])
        offered = client['offered_load']
        assert offered['concurrency_limit'] == 128 and offered['dispatched'] == 60000 and offered['expired_before_dispatch'] == 0
        assert not offered['fully_open_loop'] and offered['peak_in_flight'] <= 128
        assert result['client_cpu_headroom_gate']['valid'] and result['client_cpu_headroom_gate']['passed']
        assert result['client_cpu_busy_gate']['valid'] and result['client_cpu_busy_gate']['passed']
        assert not result['cpu']['client_measured_saturation_warning']
        latency, service, lateness = [], [], []
        phases = collections.Counter()
        request_ids = {'warmup': set(), 'measured': set()}
        with (directory / 'latencies.tsv').open() as stream:
            for raw in csv.DictReader(stream, delimiter='\t'):
                phase = raw['phase']
                assert phase in request_ids and int(raw['request']) not in request_ids[phase]
                request_ids[phase].add(int(raw['request']))
                phases[phase] += 1
                assert raw['status'] == '200' and raw['bytes'] == '1024' and not raw['error']
                if phase == 'measured':
                    scheduled, dispatched, completed = map(int, [raw['scheduled_offset_ns'], raw['dispatch_offset_ns'], raw['completion_offset_ns']])
                    assert raw['dispatched'] == 'true' and raw['expired_before_dispatch'] == 'false'
                    equal(float(raw['latency_us']), (completed - scheduled) / 1000, .001)
                    equal(float(raw['service_latency_us']), (completed - dispatched) / 1000, .001)
                    equal(float(raw['dispatch_lateness_us']), (dispatched - scheduled) / 1000, .001)
                    latency.append((completed - scheduled) / 1000)
                    service.append((completed - dispatched) / 1000)
                    lateness.append((dispatched - scheduled) / 1000)
        assert phases == {'warmup': 5000, 'measured': 60000}
        for values, expected_p99 in [(latency, client['p99_us']), (service, offered['service']['p99_us']),
                                     (lateness, offered['dispatch_lateness']['p99_us'])]:
            values.sort()
            equal(values[math.ceil(len(values) * .99) - 1], expected_p99, .001)
        cpu, hw = result['cpu'], result['hardware_counters']
        before, after = cpu['server_process_ticks_before'], cpu['server_process_ticks_after']
        assert before['pids'] == after['pids'] and len(before['pids']) == (2 if arm == 'repaired' else 1)
        assert end['pid'] in before['pids'] and hw['valid'] and hw['minimum_running_fraction'] == 1.0
        assert sorted(hw.get('process_pids', [hw['pid']])) == sorted(before['pids'])
        assert all(hw['totals'][event] > 0 for event in ['cycles', 'instructions'])
        ticks, denominator = cpu['ticks_per_second'], 65000
        assert ticks == client['clock_ticks_per_second'] == result['linux_cpu_ticks']['ticks_per_second'] == 100
        equal(cpu['server_user_secs'], (after['user'] - before['user']) / ticks)
        equal(cpu['server_system_secs'], (after['system'] - before['system']) / ticks)
        components = {}
        for old, new in zip(before['processes'], after['processes']):
            assert old['pid'] == new['pid']
            components[old['pid']] = ((new['user_ticks'] - old['user_ticks']) + (new['system_ticks'] - old['system_ticks'])) * 1e6 / ticks / denominator
        vm = result['linux_cpu_ticks']['delta']['cpu']
        vm_busy = sum(vm[name] for name in BUSY)
        assert all(value >= 0 for value in vm.values())
        old_prom, new_prom = prom(directory / 'before.prom'), prom(directory / 'after.prom')
        for name, value in result['metric_deltas'].items():
            equal(value, new_prom.get(name, 0) - old_prom.get(name, 0))
        metrics = result['metric_deltas']
        failures = metrics['httpjet_h2_kernel_failures_total']
        successes = metrics['httpjet_h2_kernel_successes_total']
        assert failures == 0
        if arm == 'repaired':
            assert 0 < successes <= denominator and metrics['httpjet_h2_kernel_candidates_total'] > 0
            assert metrics['httpjet_h2_kernel_readiness_errors_total'] == 0
        else:
            assert successes == 0
        cache_metric = 'httpjet_fast_memo_hits_total' if case == 'static' else 'httpjet_pagecache_hits_total'
        assert metrics[cache_metric] > 0
        if case == 'pagecache':
            assert metrics['httpjet_pagecache_lookup_total{path="response_memo",result="hit"}'] > 0
        row = {'case': case, 'cycle': cycle, 'position': position, 'arm': arm,
            'measured_responses': 60000, 'warmup_responses': 5000, 'CPU_PMU_VM_denominator': denominator,
            'RPS': client['successful_requests_per_sec'], 'scheduled_p99_us': client['p99_us'],
            'service_p99_us': offered['service']['p99_us'], 'dispatch_lateness_p99_us': offered['dispatch_lateness']['p99_us'],
            'process_cpu_us_R': (cpu['server_user_secs'] + cpu['server_system_secs']) * 1e6 / denominator,
            'process_user_us_R': cpu['server_user_secs'] * 1e6 / denominator,
            'process_system_us_R': cpu['server_system_secs'] * 1e6 / denominator,
            'helper_cpu_us_R': components[end['pid']] if arm == 'repaired' else 0,
            'web_cpu_us_R': sum(value for pid, value in components.items() if arm != 'repaired' or pid != end['pid']),
            'VM_busy_us_R': vm_busy * 1e6 / ticks / denominator,
            'user_instructions_R': hw['totals']['instructions'] / denominator,
            'user_cycles_R': hw['totals']['cycles'] / denominator,
            'offload_fraction': successes / denominator, 'reported_kernel_failures': failures,
            'admission_waits': offered['concurrency_waits'], 'peak_in_flight': offered['peak_in_flight']}
        equal(row['process_cpu_us_R'], row['helper_cpu_us_R'] + row['web_cpu_us_R'])
        rows.append(row)
        if offered['concurrency_waits']:
            admissions.append({key: row[key] for key in ['case', 'cycle', 'position', 'arm', 'admission_waits', 'peak_in_flight']})
    assert identities == expected and len(rows) == 24
    keys = [key for key in rows[0] if key in ['RPS', 'scheduled_p99_us', 'service_p99_us', 'dispatch_lateness_p99_us',
        'process_cpu_us_R', 'process_user_us_R', 'process_system_us_R', 'helper_cpu_us_R', 'web_cpu_us_R',
        'VM_busy_us_R', 'user_instructions_R', 'user_cycles_R', 'offload_fraction']]
    groups = {(case, arm): med([row for row in rows if (row['case'], row['arm']) == (case, arm)], keys)
              for case in ['static', 'pagecache'] for arm in ['native', 'repaired']}
    comparisons, cycles = [], []
    for case in ['static', 'pagecache']:
        delta = changes(groups[case, 'native'], groups[case, 'repaired'])
        comparisons.append({'case': case, **delta})
        for cycle in [1, 2, 3]:
            by_arm = {arm: med([row for row in rows if (row['case'], row['cycle'], row['arm']) == (case, cycle, arm)], keys)
                      for arm in ['native', 'repaired']}
            change = changes(by_arm['native'], by_arm['repaired'])
            opposite = [key for key in keys if change[key] is not None and delta[key] is not None and change[key] * delta[key] < 0]
            cycles.append({'case': case, 'cycle': cycle, **change, 'opposite_aggregate_direction': ';'.join(opposite)})
    out.mkdir()
    manifest = []
    for path in sorted(base.rglob('*')):
        if path.is_file():
            manifest.append({'path': str(path.relative_to(base)), 'bytes': path.stat().st_size, 'sha256': sha(path)})
    (out / 'raw-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    write_csv(out / 'arms.csv', sorted(rows, key=lambda row: (row['case'], row['cycle'], row['position'])))
    write_csv(out / 'groups.csv', [{'case': case, 'arm': arm, 'arms': 6, **values} for (case, arm), values in groups.items()])
    write_csv(out / 'changes-percent.csv', comparisons)
    write_csv(out / 'cycles-percent.csv', cycles)
    table = ['| Fixture | Process CPU us/R, native → repaired | Change | Scheduled p99 us, native → repaired | Change | VM busy us/R, native → repaired | Change |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for row in comparisons:
        case = row['case']; b, a = groups[case, 'native'], groups[case, 'repaired']
        table.append(f'| {case} | {b["process_cpu_us_R"]:.3f} → {a["process_cpu_us_R"]:.3f} | {row["process_cpu_us_R"]:+.2f}% | {b["scheduled_p99_us"]:.3f} → {a["scheduled_p99_us"]:.3f} | {row["scheduled_p99_us"]:+.2f}% | {b["VM_busy_us_R"]:.3f} → {a["VM_busy_us_R"]:.3f} | {row["VM_busy_us_R"]:+.2f}% |')
    (out / 'TABLE.md').write_text('\n'.join(table) + '\n\nSix arm medians per fixture/arm. These are matched-rate latency/CPU results, not capacity gains. Process CPU includes server+helper user+system over all65,000 client responses per arm. VM busy includes clients and unrelated Linux work; Windows-host work is unobserved. Scheduled p99 is the median of six arm p99 values, not a pooled request quantile.\n')
    receipt = {'schema': 1, 'passed': True, 'scope': scope['scope'], 'server_sha256': SERVER, 'helper_sha256': HELPER,
        'client_sha256': CLIENT, 'harness_sha256': metadata['harness']['sha256'], 'repaired_helper_source': provenance['source_h2_sha256'],
        'source_snapshot': {'separate_before_after_snapshot_taken': False, 'limitation': 'No separate source/boot snapshot was taken for this short direct run. Per-arm artifact hashes and existing frozen helper/source provenance are bound; do not claim a separate source-snapshot seal.'},
        'counts': {'arms': 24, 'measured_responses': 1440000, 'warmup_responses': 120000, 'all_latency_rows_verified': 1560000,
                   'groups': 4, 'ABBA_cycles': 6, 'raw_files': len(manifest)},
        'checks': {'all_client_body_status_valid': True, 'all_raw_latency_status_bytes_errors_checked': True,
                   'raw_scheduled_service_dispatch_p99_recomputed': True, 'all_server_exits_zero': True,
                   'all_PMU_valid_running_fraction_one': True, 'all_client_headroom_passed': True,
                   'all_repaired_offload_positive': True, 'all_reported_H2_kernel_failures_zero': True,
                   'sampled_compiler_overlap': False, 'all_sampled_compiler_lists_empty': True},
        'monitor': {'configuration': config, 'finished': final, 'running_samples': sum(row['event'] == 'running' for row in environment),
                    'limitations': 'One-second Linux compiler sampling; sub-interval and Windows-host activity unobserved.'},
        'normalization': {'CPU_PMU_VM_responses_per_arm': 65000, 'latency_responses_per_arm': 60000,
            'ticks_per_second': 100, 'VM_busy_fields': BUSY, 'latency': 'scheduled-to-completion; service and dispatch quantiles separate, never added',
            'load': '15000 R/s bounded admission128; not unrestricted open loop',
            'PMU': 'server/helper user-mode only; kernel/IRQ/hypervisor excluded',
            'VM': 'all Linux CPUs; clients/unrelated work included; Windows host unobserved'},
        'groups': {f'{case}/{arm}': values for (case, arm), values in groups.items()},
        'changes_percent': comparisons, 'cycles_percent': cycles, 'admission_wait_arms': admissions,
        'outliers': [{key: row[key] for key in ['case', 'cycle', 'position', 'arm', 'scheduled_p99_us']}
                     for row in rows if row['scheduled_p99_us'] > 10000],
        'process_CPU_and_p99_improve_all_cycles': all(row['process_cpu_us_R'] < 0 and row['scheduled_p99_us'] < 0 for row in cycles),
        'VM_CPU_improves_all_cycles': all(row['VM_busy_us_R'] < 0 for row in cycles),
        'conclusion': 'Server/helper process CPU and scheduled latency improve, while aggregate whole-VM busy CPU increases in both fixtures. This does not establish lower overall CPU or achievement of the production CPU goal.',
        'provenance_scope': 'E9 native versus unchanged E9 app plus repaired helper0e, RETRY1ms. Not C7 or deployed994127; known old-app H1 timeout issue is outside this H2-only comparison.',
        'recompute_sha256': sha(__file__), 'raw_manifest_sha256': sha(out / 'raw-manifest.json'),
        'outputs_sha256': {p.name: sha(p) for p in out.iterdir() if p.is_file()}}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'receipt': str(out / 'receipt.json'), 'sha256': sha(out / 'receipt.json'),
                      'changes_percent': comparisons, 'cycles': [{key: row[key] for key in ['case', 'cycle', *LOWER]} for row in cycles],
                      'admission_wait_arms': admissions}))


if __name__ == '__main__':
    main()
