#!/usr/bin/env python3
"""Seal all planned H2 arms, retaining failures and every cycle direction.

Prepared only. Runtime validation is restricted to SINGULARITY. No performance
improvement is required to produce a valid complete summary.
"""
import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import stat
import statistics
import sys

RUN = Path('/var/tmp/httpjet-continuation/h2-quiescent-v2/pgo-v1')
OLD = '/var/tmp/httpjet-continuation/pgo-c6ac-v1/bin-use/httpjet'
RELEASE = '/var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet'
FIXED_PINS = {OLD: '0ca04dcb8d3b9d07e02ac19658546d7882d6f2719c6937be2f259ca65eef83c5',
              RELEASE: '3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec'}
CLIENTS = {'capacity': ('/var/tmp/hjc/httpjet-http-load-bind',
                        'e5c21fa94ea72c965cd4cfea950977c2bb771a4a5842a58499a5b1355c758b8f'),
           'rate15000': ('/var/tmp/httpjet-http-paced-client-v2/bin/httpjet-http-load-paced',
                         '0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6')}
CASES = ['static', 'pagecache']
CPU_FIELDS = ['user', 'nice', 'system', 'irq', 'softirq']
SOURCES = {}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode), f'not a regular nonsymlink file: {path}')
    data = path.read_bytes()
    value = hashlib.sha256(data).hexdigest()
    identity = {'path': str(path), 'sha256': value, 'bytes': len(data)}
    require(str(path) not in SOURCES or SOURCES[str(path)] == identity, f'input changed during analysis: {path}')
    SOURCES[str(path)] = identity
    return value


def read(path):
    sha(path)
    return json.loads(Path(path).read_text(), parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))


def number(value):
    require(not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value) and value >= 0, f'invalid numeric measurement: {value!r}')
    return value


def normalized_arms(plan, pins):
    arms = {}
    for arm in plan['arms']:
        item = dict(arm)
        item['sha256'] = pins[item['binary']]
        if 'launcher' in item:
            item['launcher'] = dict(item['launcher'])
            item['launcher'].update(args=[], sha256=pins[item['launcher']['binary']])
        arms[item['name']] = item
    return arms


def arm_record(control, plan, arms, case, cycle, position, name):
    directory = control / 'results' / f'h2c-{case}-{cycle}-{position}-{name}'
    row = {'case': case, 'cycle': cycle, 'position': position, 'arm': name,
           'directory': str(directory), 'status': 'incomplete', 'issues': [], 'metrics': None}
    result = client = None
    try:
        if (directory / 'failure.json').exists():
            row['failure'] = read(directory / 'failure.json')
        result = read(directory / 'result.json')
        row['source_sha256'] = sha(directory / 'result.json')
        exited = read(directory / 'server-exit.json')
        row['server_exit'] = exited
        require('failure' not in row, 'arm failure receipt exists')
        require(result['arm'] == arms[name] and result['protocol'] == 'h2c' and result['case'] == case,
                'wrong arm/binary/flags or fixture')
        require(result['benchmark_valid'] is True and result['client_exit'] == 0
                and result['training_only'] is False and not result.get('diagnostic_only'),
                'unqualified or sampled/training result')
        client = result['client']
        count, warm = plan['requests'], plan['warmup']
        total = count + warm
        require(client['benchmark_valid'] and client['phase'] == 'measured' and client['protocol'] == 'h2',
                'invalid client protocol/phase')
        require(client['requested'] == client['completed'] == client['succeeded'] == count
                and client['failed'] == client['unattempted'] == 0
                and not client['errors'] and not client['driver_errors'], 'failed/incomplete measured requests')
        require(client['warmup_requested'] == client['warmup_completed'] == client['warmup_succeeded'] == warm,
                'failed/incomplete warmup')
        require(client['body_bytes'] == 1024 and client['verified_body_bytes'] == client['received_body_bytes'] == count * 1024
                and client['expected_status'] == 200 and client['status_counts'] == {'200': count},
                'body/status mismatch')
        sockets = client['client_sockets']
        require(len(sockets) == 32, 'socket count differs')
        require(all(ipaddress.ip_address(sock['local_address'].rsplit(':', 1)[0].strip('[]'))
                    == ipaddress.ip_address('127.0.0.2') for sock in sockets), 'actual client bind is not 127.0.0.2')
        require(type(exited['exit']) is int and exited['exit'] == 0, 'server did not exit cleanly')
        hw = result['hardware_counters']
        gate = result['client_cpu_headroom_gate']
        require(hw['valid'] and hw['include_user'] is True and hw['exclude_kernel'] is True
                and gate['valid'] and gate['passed'], 'PMU/headroom evidence failed')
        running = number(hw['minimum_running_fraction'])
        require(0 < running <= 1.000001, 'invalid PMU running fraction')
        cpu = result['cpu']
        before, after = cpu['server_process_ticks_before'], cpu['server_process_ticks_after']
        require(set(before['pids']) == set(after['pids']), 'server/helper process inventory changed during client span')
        if 'launcher' in arms[name]:
            require(len(before['pids']) >= 2 and set(hw['process_pids']) == set(before['pids'])
                    and hw['process_tree_stable_at_boundaries'], 'helper+server CPU/PMU coverage missing')
        require(result['metric_deltas_include_client_warmup'] is True, 'counter denominator unknown')
        delta = result['metric_deltas']
        successes = delta.get('httpjet_h2_kernel_successes_total')
        require((successes is not None and 0 < number(successes) <= total) if 'launcher' in arms[name]
                else successes in [None, 0], 'kernel activation/native ownership mismatch')
        if case == 'static':
            require(delta.get('httpjet_fast_memo_hits_total', 0) > 0, 'static cache not used')
        else:
            require(delta.get('httpjet_pagecache_hits_total', 0) > 0, 'origin page cache not used')
            if '--page-cache-response-memo' in arms[name]['serve_args']:
                require(delta.get('httpjet_pagecache_lookup_total{path="response_memo",result="hit"}', 0) > 0,
                        'page response memo not used')
        command = read(directory / 'client-command.json')
        require(command[command.index('--bind') + 1] == '127.0.0.2'
                and command[command.index('--connect') + 1].startswith('127.0.0.2:'), 'wrong destination/source command')
        require(command[command.index('--connections') + 1] == '32'
                and command[command.index('--streams') + 1] == '4', 'wrong concurrency')
        vm = result['linux_cpu_ticks']
        ticks = number(vm['ticks_per_second'])
        require(ticks > 0, 'invalid tick timebase')
        values = [vm['delta']['cpu']] if 'cpu' in vm['delta'] else [value for key, value in vm['delta'].items()
                  if key.startswith('cpu') and key[3:].isdigit()]
        require(bool(values), 'whole-VM counters absent')
        busy = sum(number(value[field]) for value in values for field in CPU_FIELDS)
        metrics = {'rps': number(client['successful_requests_per_sec']), 'p99_us': number(client['p99_us']),
            'process_cpu_us_per_response': 1e6 * (number(cpu['server_user_secs']) + number(cpu['server_system_secs'])) / total,
            'process_user_us_per_response': 1e6 * number(cpu['server_user_secs']) / total,
            'process_system_us_per_response': 1e6 * number(cpu['server_system_secs']) / total,
            'user_instructions_per_response': number(hw['totals']['instructions']) / total,
            'user_cycles_per_response': number(hw['totals']['cycles']) / total,
            'whole_vm_busy_ticks_per_response': busy / total,
            'whole_vm_busy_us_per_response': 1e6 * busy / ticks / total,
            'kernel_success_fraction': successes / total if successes is not None else None}
        # Each per-arm component is measured before aggregating. Never derive a
        # median total by adding independently computed component medians.
        cpu_ticks = number(cpu['ticks_per_second'])
        require(cpu_ticks > 0, 'invalid process tick timebase')
        process_before = {record['pid']: record for record in before['processes']}
        process_after = {record['pid']: record for record in after['processes']}
        require(set(process_before) == set(process_after) == set(before['pids']), 'process component coverage incomplete')
        components = {}
        for pid in process_before:
            components[pid] = sum(number(process_after[pid][field] - process_before[pid][field])
                                  for field in ['user_ticks', 'system_ticks'])
        helper_ticks = components[exited['pid']] if 'launcher' in arms[name] else 0
        metrics['helper_cpu_us_per_response'] = 1e6 * helper_ticks / cpu_ticks / total
        metrics['web_cpu_us_per_response'] = 1e6 * (sum(components.values()) - helper_ticks) / cpu_ticks / total
        require(metrics['rps'] > 0 and metrics['user_instructions_per_response'] > 0
                and metrics['user_cycles_per_response'] > 0, 'nonpositive measured work')
        if plan['rate']:
            offered = client['offered_load']
            require(client['latency_scope'] == 'scheduled_to_completion' and client['requested_rate'] == '15000',
                    'wrong offered rate/latency scope')
            require(offered['rate_spec'] == '15000' and offered['concurrency_limit'] == 128
                    and offered['fully_open_loop'] is False and offered['dispatched'] == count
                    and offered['expired_before_dispatch'] == 0, 'invalid offered-load/admission outcomes')
            require(all(offered[key]['count'] == count for key in
                        ['scheduled_all_outcomes', 'service', 'dispatch_lateness']), 'latency outcome counts differ')
            metrics.update(service_p99_us=number(offered['service']['p99_us']),
                           dispatch_lateness_p99_us=number(offered['dispatch_lateness']['p99_us']))
            row['admission'] = {key: number(offered[key]) for key in ['peak_in_flight', 'concurrency_waits']}
            require(row['admission']['peak_in_flight'] <= 128, 'admission cap exceeded')
        else:
            require(client.get('requested_rate') is None and client.get('offered_load') is None,
                    'capacity arm unexpectedly paced')
        row.update(status='complete', metrics=metrics, kernel_successes=successes,
                   pmu_running_fraction=running, observed_client_latency_scope=client.get('latency_scope'),
                   process_cpu_coverage={'before_pids': before['pids'], 'after_pids': after['pids'],
                                         'includes_helper': 'launcher' in arms[name]},
                   kernel_metrics={key: value for key, value in delta.items() if 'h2_kernel' in key},
                   denominator={'measured': count, 'warmup': warm, 'whole_client_span': total})
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, ZeroDivisionError) as error:
        row['issues'].append(f'{type(error).__name__}: {error}')
        row.update(status='failed' if 'failure' in row else 'incomplete', raw_client=client)
    return row


def medians(rows):
    keys = set().union(*(row['metrics'] for row in rows))
    return {key: statistics.median(values) if values else None for key in sorted(keys)
            for values in [[row['metrics'].get(key) for row in rows if row['metrics'].get(key) is not None]]}


def delta_percent(old, new):
    return 100 * (new / old - 1) if old else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('control', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(socket.gethostname().upper() == 'SINGULARITY', 'analysis validation only on SINGULARITY')
    require(not args.output.exists() and not args.output.is_symlink(), 'retain existing summary')
    control = args.control.resolve(strict=True)
    require(control.parent == RUN and control.name in ['h2-final-capacity-v1', 'h2-final-rate15000-v1'],
            'unexpected trial root')
    plan = read(control / 'plan.json')
    require(plan['mode'] in ['capacity', 'rate15000'], 'wrong mode')
    mode = plan['mode']
    pairs = [['fresh-native', 'fresh-kernel'], ['old-native', 'old-kernel']]
    if mode == 'capacity':
        pairs.append(['release', 'release-kernel'])
    sequence = [name for a, b in pairs for name in [a, b, b, a]]
    require(plan['pairs'] == pairs and plan['sequence'] == sequence and plan['rounds'] == 3
            and plan['cases'] == CASES and plan['size'] == 1024, 'planned design differs')
    require(plan['requests'] == (200000 if mode == 'capacity' else 60000)
            and plan['warmup'] == (10000 if mode == 'capacity' else 5000)
            and plan['rate'] == (None if mode == 'capacity' else '15000'), 'planned count/rate differs')
    require(plan['control'] == str(control) and control.name == f'h2-final-{mode}-v1'
            and plan['results'] == str(control / 'results') and plan['monitor'] == str(control / 'monitor')
            and plan['harness'] == str(RUN.parent / 'harness-current')
            and (plan['client'], plan['client_sha256']) == CLIENTS[mode], 'planned paths/client differ')
    binary, helper = str(RUN / 'bin-use/httpjet'), str(RUN / 'bin-use/httpjet-beeper-h1')
    native_args = ['--h1-kernel', 'off', '--page-cache-response-memo']
    kernel_args = ['--h1-kernel', 'required', '--h2-kernel', '--page-cache-response-memo']
    raw_arms = {'fresh-native': {'name': 'fresh-native', 'binary': binary, 'serve_args': native_args},
                'old-native': {'name': 'old-native', 'binary': OLD, 'serve_args': native_args}}
    if mode == 'capacity':
        raw_arms['release'] = {'name': 'release', 'binary': RELEASE, 'serve_args': []}
    raw_arms.update({name: {'name': name, 'binary': binary, 'serve_args': kernel_args,
                           'launcher': {'binary': helper}} for _, name in pairs})
    require(len(plan['arms']) == len(raw_arms)
            and {row['name']: row for row in plan['arms']} == raw_arms, 'planned arms/flags differ')
    issues = []
    before = after = status = metadata = events = None
    def inspect(label, operation):
        try:
            return operation()
        except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
            issues.append(f'{label}: {type(error).__name__}: {error}')
            return None
    before = inspect('before', lambda: read(control / 'inputs-before.json'))
    after = inspect('after', lambda: read(control / 'inputs-after.json'))
    status = inspect('run status', lambda: read(control / 'run-status.json'))
    inspect('source/boot equality', lambda: require(isinstance(before, dict) and before == after,
                                                   'input/boot snapshots absent or differ'))
    if isinstance(before, dict):
        def check_pins():
            use = read(RUN / 'use-artifacts.json')
            expected = dict(FIXED_PINS)
            expected.update({path: row['sha256'] for path, row in use.items()})
            expected[plan['client']] = plan['client_sha256']
            require(before['pins'] == expected and before['network'] == {
                    'server': '127.0.0.2', 'client_bind': '127.0.0.2'}
                    and before['selected_artifact_processes'] == [], 'snapshot artifact/network/cleanup pins differ')
        inspect('binary/control pins', check_pins)
        for path, value in {**before['pins'], **before['inputs']}.items():
            inspect('current immutable input', lambda p=path, v=value: require(sha(p) == v, f'input drift: {p}'))
        for name, value in before['harness'].items():
            inspect('current harness', lambda n=name, v=value: require(sha(Path(plan['harness']) / n) == v, f'harness drift: {n}'))
    inspect('execution status', lambda: require(isinstance(status, dict) and status['command_exit'] == 0
            and status['interrupted'] is None and status['same_inputs_and_boot'] is True
            and status['final_integrity_error'] is None, 'execution/integrity did not seal'))
    arms = normalized_arms(plan, before['pins']) if isinstance(before, dict) else {}
    metadata = inspect('metadata', lambda: read(control / 'results/metadata.json'))
    def check_metadata():
        require(metadata['host'][1].upper() == 'SINGULARITY' and metadata['arms'] == arms
                and metadata['training_only'] is False and metadata.get('diagnostic_only') is False,
                'wrong runtime host/arms/mode')
        options = {'rounds': 3, 'requests': plan['requests'], 'warmup': plan['warmup'], 'size': 1024,
            'connections': 32, 'streams': 4, 'workers': 1, 'client_threads': 6, 'client_timeout_secs': 10,
            'server_cpus': '8', 'client_cpus': '0,2,4,6,12,14', 'protocols': 'h2c', 'cases': 'static,pagecache',
            'rate': plan['rate'], 'sequence': ','.join(sequence), 'server_hardware_counters': True,
            'require_client_cpu_headroom': True, 'profile_dir': None, 'core_pinning': False}
        require(all(metadata['arguments'].get(key) == value for key, value in options.items()), 'runtime options differ')
        require(metadata['client'] == {'path': plan['client'], 'sha256': plan['client_sha256']}, 'wrong client')
        require(metadata['manifest_sha256'] == sha(control / 'arms.json'), 'wrong arm manifest')
        require(metadata['harness']['sha256'] == before['harness']['scripts/http_engine_check.py'], 'wrong harness')
    inspect('metadata design', check_metadata)
    events_path = control / 'monitor/environment.jsonl'
    def read_events():
        sha(events_path)
        return [json.loads(line) for line in events_path.read_text().splitlines()]
    events = inspect('observer log', read_events)
    inspect('compiler/observer gate', lambda: require(bool(events) and events[0]['event'] == 'configuration'
        and events[0]['observer_affinity'] == [10] and events[0]['quiet_seconds'] == 10
        and events[0]['interval_seconds'] == 1 and events[-1]['event'] == 'finished'
        and events[-1]['command_exit'] == 0 and events[-1]['compiler_overlap_observed'] is False
        and not any(row.get('compilers') for row in events if row['event'] == 'running'),
        'observer did not finish cleanly without observed compiler overlap'))
    rows = [arm_record(control, plan, arms, case, cycle, position, name)
            for case in CASES for cycle in [1, 2, 3] for position, name in enumerate(sequence, 1)]
    expected_paths = {str(Path(row['directory']) / 'result.json') for row in rows}
    unplanned = sorted(str(path) for path in (control / 'results').glob('*/result.json')
                       if str(path) not in expected_paths)
    if unplanned:
        issues.append(f'unplanned arms: {unplanned}')
    for path, item in list(SOURCES.items()):
        inspect('final input hash', lambda p=path, value=item['sha256']: require(sha(p) == value, f'input drift: {p}'))
    complete = not issues and all(row['status'] == 'complete' for row in rows)
    groups, comparisons = [], []
    for case in CASES:
        for name in arms:
            subset = [row for row in rows if row['case'] == case and row['arm'] == name]
            groups.append({'case': case, 'arm': name, 'planned': 6,
                'validated': sum(row['status'] == 'complete' for row in subset),
                'medians': medians(subset) if complete else None,
                'admission': [row.get('admission') for row in subset] if plan['rate'] else None})
        if complete:
            for a, b in pairs:
                aa = [row for row in rows if row['case'] == case and row['arm'] == a]
                bb = [row for row in rows if row['case'] == case and row['arm'] == b]
                am, bm = medians(aa), medians(bb)
                changes = {key: delta_percent(am[key], bm[key]) for key in am
                           if am[key] is not None and bm[key] is not None}
                cycles = []
                for cycle in [1, 2, 3]:
                    ac = medians([row for row in aa if row['cycle'] == cycle])
                    bc = medians([row for row in bb if row['cycle'] == cycle])
                    cd = {key: delta_percent(ac[key], bc[key]) for key in changes}
                    cycles.append({'cycle': cycle, 'baseline_medians': ac, 'kernel_medians': bc,
                                   'kernel_change_percent': cd,
                                   'opposite_aggregate_direction': [key for key in cd if cd[key] is not None
                                        and changes[key] is not None and cd[key] * changes[key] < 0]})
                comparisons.append({'case': case, 'baseline': a, 'kernel': b,
                    'baseline_medians': am, 'kernel_medians': bm, 'kernel_change_percent': changes,
                    'cycles': cycles, 'observed_cpu_lower': bm['process_cpu_us_per_response'] < am['process_cpu_us_per_response'],
                    'observed_p99_lower': bm['p99_us'] < am['p99_us']})
    report = {'schema': 1, 'status': 'complete' if complete else 'unqualified', 'mode': mode,
        'plan': plan, 'planned_arms': len(rows), 'validated_arms': sum(row['status'] == 'complete' for row in rows),
        'measured_responses': len(rows) * plan['requests'] if complete else None,
        'warmup_responses': len(rows) * plan['warmup'] if complete else None,
        'issues': issues, 'rows': rows, 'unplanned_rows': unplanned, 'groups': groups, 'comparisons': comparisons,
        'observed_boot_id': before.get('boot_id') if isinstance(before, dict) else None,
        'source_inputs': SOURCES, 'run_status': status, 'monitor': events[-1] if events else None,
        'scopes': {'latency': 'capacity: actual-request-to-completion at fixed concurrency; rate15000: scheduled-to-completion, with service and dispatch lateness separate; never add quantiles',
          'aggregation': 'six arm medians per fixture/name; p99 is a median of arm percentiles, not a pooled request percentile; all planned arms must seal before aggregation',
          'offered_load': 'rate15000 uses bounded admission at128, not unrestricted open loop; per-arm cap/wait counts retained',
          'process_cpu': 'server/helper user+system over entire client span, including handshake/warmup/measurement/output/drain, divided by measured+warmup responses; kernel/IRQ work charged elsewhere excluded',
          'pmu': 'server/helper user-mode instructions/cycles only; kernel/IRQ/hypervisor work excluded; whole-span response denominator',
          'whole_vm': 'all Linux VM CPUs user+nice+system+IRQ+softIRQ, retained as ticks/R and converted with recorded tick timebase; clients and unrelated Linux work included; Windows-host CPU/scheduling unobserved; kernel BPF may run in client/IRQ contexts outside server-owned process CPU',
          'goal': 'validity does not depend on favorable performance; primary rate CPU comparisons are fresh kernel versus both native PGO controls; capacity release p99 closes original regression only if observed lower for both fixtures; goal achievement is a separate assessment'}}
    with args.output.open('x') as file:
        json.dump(report, file, indent=2, allow_nan=False)
        file.write('\n')
    print(f'{mode}: {report["status"]}; {report["validated_arms"]}/{len(rows)} arms validated', flush=True)
    for item in comparisons:
        print(json.dumps({key: item[key] for key in ['case', 'baseline', 'kernel', 'baseline_medians',
            'kernel_medians', 'kernel_change_percent', 'observed_cpu_lower', 'observed_p99_lower']}), flush=True)
    return 0 if complete else 1


if __name__ == '__main__':
    sys.exit(main())
