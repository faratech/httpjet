#!/usr/bin/env python3
"""Validate and recompute exact-release p99 from saved evidence; launches nothing.

--raw is the extracted contents of exact-release-p99-v1, including run-v1.
All source artifacts and raw results remain immutable. Output must be new.
"""
import argparse
import collections
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

REMOTE = Path('/var/tmp/httpjet-continuation/exact-release-p99-v1')
APP = 'abf7a79c1eb9593c3af7e77e60c4aaf4a5b30873d0e2b989283c88b662db9c48'
RELEASE = '3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec'
ARCHIVE = '67695c65902e0437fbecffe8b94c502e98d635dff78aee5dcc604f3e9f5900c2'
HELPER = '0e7be72d437dd255e332ec1f6bd05554ae91ac2f54844793b1fe08691b184f4e'
HTTP_CLIENT = '0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6'
H3_CLIENT = 'afee4fd337ce7289c3a3122abba27fd3fa47605535d50f9b43aa4dff22e33a77'
DRIVER = '1055dbbb31af5ba9a2d3da1a3e54cd2868257c97c9090dd68f30cecce8eb4296'
OWNER = 'a53cde6cef97db96d98680434bc7692668ce1fee19a5d1536e53979d1f8622ef'
TOOLS_MANIFEST = '610a1fcd94110760e51021c25027452824b7bc31132f2c4e410f6a807f9728c7'
QUALIFICATION = 'bb8850619fd76372f63da27fd665ea28c31152eb65e88d6c44bce53843a6f7d3'
BOOT = '07a57341-882b-4a8b-8ab7-099d91374bda'
BUSY = ['user', 'nice', 'system', 'irq', 'softirq']
METRICS = ['RPS', 'process_cpu_us_R', 'user_instructions_R', 'user_cycles_R',
           'VM_busy_us_R', 'scheduled_p99_us', 'service_p99_us', 'dispatch_lateness_p99_us']


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read(path):
    return json.loads(Path(path).read_text(), parse_constant=lambda v: (_ for _ in ()).throw(ValueError(v)))


def eq(a, b, tolerance=1e-8):
    assert math.isfinite(a) and math.isfinite(b) and math.isclose(a, b, rel_tol=1e-10, abs_tol=tolerance), (a, b)


def prom(path):
    return {line.rsplit(None, 1)[0]: float(line.rsplit(None, 1)[1]) for line in Path(path).read_text().splitlines()
            if line and not line.startswith('#')}


def write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def write_csv(path, rows):
    with Path(path).open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def option(command, name):
    assert command.count(name) == 1, (name, command)
    return command[command.index(name) + 1]


def median(rows):
    return {key: statistics.median(row[key] for row in rows) for key in METRICS}


def delta(before, after):
    return {key: 100 * (after[key] / before[key] - 1) if before[key] else None for key in METRICS}


def hardware_audit(hw, pids):
    assert hw['valid'] and hw['minimum_running_fraction'] == 1
    assert sorted(hw.get('process_pids', [hw['pid']])) == sorted(pids)
    assert hw['include_user'] and hw['exclude_kernel'] and hw['exclude_hypervisor'] and hw['exclude_guest']
    assert not hw['inherit_child_processes'] and hw['inherit_future_threads']
    if len(pids) == 2:
        assert hw['process_tree_stable_at_boundaries'] and hw['initial_thread_identities_stable_while_present']
        assert all(row['accepted'] for row in hw['topology_checks'])
    totals = collections.Counter()
    thread_count = 0
    for process in hw.get('processes', [hw]):
        assert process['valid'] and process['pid'] in pids
        process_totals = collections.Counter()
        assert process['include_user'] and process['exclude_kernel'] and process['exclude_hypervisor'] and process['exclude_guest']
        assert not process['inherit_child_processes']
        for thread in process['threads']:
            thread_count += 1
            for event in ['cycles', 'instructions']:
                counter = thread['counters'][event]
                raw, enabled, running = [counter[k] for k in ['raw', 'time_enabled_ns', 'time_running_ns']]
                assert all(type(v) is int and v >= 0 for v in [raw, enabled, running])
                assert enabled == running and not counter['multiplexed']
                if enabled == 0:
                    assert raw == counter['value'] == 0 and counter['unscheduled']
                else:
                    assert counter['value'] == raw and not counter['unscheduled'] and counter['running_fraction'] == 1
                process_totals[event] += raw
        assert dict(process_totals) == process['totals']
        totals.update(process_totals)
    assert dict(totals) == hw['totals'] and all(totals[k] > 0 for k in ['cycles', 'instructions'])
    return thread_count


def latency_audit(directory, protocol, client):
    values = {key: [] for key in ['scheduled', 'service', 'lateness']}
    phases, ids = collections.Counter(), collections.defaultdict(set)
    rows = 0
    with (directory / 'latencies.tsv').open() as stream:
        for record in csv.DictReader(stream, delimiter='\t'):
            label = record.get('phase', 'measured')
            request = int(record['request'])
            assert label in ['warmup', 'measured'] and request not in ids[label]
            ids[label].add(request)
            phases[label] += 1
            rows += 1
            assert record['bytes'] == '1024' and not record['error']
            if protocol != 'h3':
                assert record['status'] == '200'
            if label == 'measured':
                scheduled, dispatched, completed = [int(record[k]) for k in
                    ['scheduled_offset_ns', 'dispatch_offset_ns', 'completion_offset_ns']]
                assert 0 <= scheduled <= dispatched <= completed and record['dispatched'] == 'true'
                if 'expired_before_dispatch' in record:
                    assert record['expired_before_dispatch'] == 'false'
                current = {'scheduled': (completed - scheduled) / 1000,
                           'service': (completed - dispatched) / 1000,
                           'lateness': (dispatched - scheduled) / 1000}
                for name, column in [('scheduled', 'latency_us'), ('service', 'service_latency_us'),
                                     ('lateness', 'dispatch_lateness_us')]:
                    eq(current[name], float(record[column]), .001)
                    values[name].append(current[name])
    assert phases['measured'] == 60000 and ids['measured'] == set(range(60000))
    assert phases['warmup'] == (0 if protocol == 'h3' else 5000)
    if protocol != 'h3':
        assert ids['warmup'] == set(range(5000))
    quantiles = {}
    for name, summary in [('scheduled', client), ('service', client['offered_load']['service']),
                          ('lateness', client['offered_load']['dispatch_lateness'])]:
        values[name].sort()
        quantiles[name] = values[name][math.ceil(60000 * .99) - 1]
        eq(quantiles[name], summary['p99_us'], .001)
    eq(quantiles['scheduled'], client['offered_load']['scheduled_all_outcomes']['p99_us'], .001)
    return rows, quantiles


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    raw, out = args.raw.resolve(), args.out.resolve()
    assert raw.is_dir() and not out.exists()
    local = lambda p: raw / Path(p).relative_to(REMOTE)
    root = raw / 'run-v1'
    completion, before, after = [read(root / p) for p in
        ['completion.json', 'inputs-before.json', 'inputs-after.json']]
    assert completion['passed'] and completion['planned_arms'] == 120
    assert completion['error'] is completion['integrity_error'] is None
    assert before == after and (root / 'inputs-before.json').read_bytes() == (root / 'inputs-after.json').read_bytes()
    assert before['boot_id'] == BOOT and before['helper']['sha256'] == HELPER
    assert len(before['artifacts']) == 1 and next(iter(before['artifacts'].values()))['sha256'] == APP
    assert before['files']['/var/tmp/h2r-exact-release-bench.py'] == DRIVER
    assert before['files']['/var/tmp/h2r-pgo.py'] == OWNER
    assert before['files']['/var/tmp/httpjet-continuation/h2-repaired-final-bench-v1/tools/files.sha256'] == TOOLS_MANIFEST
    assert before['docker']['endpoint'] == 'unix:///var/run/docker.sock' and before['docker']['running'] == []
    assert before['docker']['id'] and before['docker']['name']
    assert before['files'][str(REMOTE / 'httpjet-release')] == RELEASE
    assert before['files'][str(REMOTE / 'release.tar.gz')] == ARCHIVE
    assert not (root / 'pending-cleanup.json').exists() and not (root / 'active-command.json').exists()
    owned = read(root / 'logs/release-comparison-command.json')
    assert owned['passed'] and owned['exit'] == 0 and not owned['pending_cleanup']
    assert not owned['pending_children'] and not owned['private_session_members'] and not owned['signals_received']
    assert owned['interrupted'] is None and owned['log_complete']
    assert sha(root / 'logs/release-comparison.log') == owned['log_sha256']
    tree = root / 'release-comparison'
    plan = read(tree / 'plan.json')
    assert plan['profile'] == 'true-lo' and plan['expected_route_device'] == 'lo' and plan['rate'] == '15000'
    assert plan['environment']['HJ_BENCH_ADDR'] == plan['environment']['HJ_BENCH_BIND'] == '127.0.0.2'
    artifacts = plan['artifacts']
    for name, expected in [('release', RELEASE), ('native_baseline', RELEASE), ('candidate', APP),
                           ('helper', HELPER), ('http_client', HTTP_CLIENT), ('h3_client', H3_CLIENT)]:
        assert artifacts[name]['sha256'] == expected
    assert artifacts['candidate_receipt']['sha256'] == QUALIFICATION
    release_receipt = read(tree / 'receipts/release_receipt')
    assert release_receipt['release'] == 'v0.1.10-11' and release_receipt['binary_sha256'] == RELEASE
    assert release_receipt['asset_sha256'] == ARCHIVE and release_receipt['member'] == 'httpjet-0.1.10-11/bin/httpjet'
    assert sha(tree / 'receipts/release_receipt') == artifacts['release_receipt']['sha256']
    assert sha(tree / 'receipts/candidate_receipt') == QUALIFICATION
    qualification = read(tree / 'receipts/candidate_receipt')
    assert qualification['passed'] and len(qualification['completed']) == 11 and qualification['helper_sha256'] == HELPER
    assert any(row.get('dev') == 'lo' for row in read(tree / 'route.json'))
    assert read(tree / 'completion.json')['completed_jobs'] == len(plan['jobs']) == 10
    assert {(j['protocol'], j['case']) for j in plan['jobs']} == {
        (p, c) for p in ['h1', 'h1s', 'h2c', 'h2', 'h3'] for c in ['static', 'pagecache']}
    assert len(plan['source_inputs']) == len(before['tools']) == 10
    for name, pin in plan['source_inputs'].items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        assert sha(tree / 'harness' / name) == pin['sha256'] == before['tools'][name]
    rows, monitors = [], []
    total_latency_rows = pmu_threads = 0
    for job in plan['jobs']:
        protocol, case = job['protocol'], job['case']
        directory, measurements = local(job['directory']), local(job['results'])
        assert job['comparison'] == 'release' and job['size'] == 1024
        metadata = read(measurements / 'metadata.json')
        options = metadata['arguments']
        for key, expected in {'rounds': 3, 'requests': 60000, 'warmup': 5000, 'size': 1024,
            'connections': 32, 'streams': 4, 'workers': 1, 'rate': '15000', 'server_hardware_counters': True,
            'require_client_cpu_headroom': True, 'profile_dir': None, 'server_cpus': '8',
            'client_cpus': '0,2,4,6,12,14', 'client_threads': 6}.items():
            assert options[key] == expected, (protocol, case, key, options[key])
        assert metadata['diagnostic_only'] is False
        if protocol == 'h3':
            assert options['loader'] is options['baseline_h3_engine'] is options['strace_bin'] is None
            assert options['sequence'] == 'baseline,accelerated,accelerated,baseline' and options['baseline_arg'] == []
            assert options['candidate_page_response_memo'] and options['candidate_arg'] == ['--h3-gso-segments=20', '--h3-send-batch=1']
            assert options['steering'] == 'off' and options['client_shared_udp_socket'] is False
        else:
            assert metadata['training_only'] is False and options['kernel_sample_bin'] is options['kernel_sample_lib'] is None
            assert options['sequence'] == 'baseline,candidate,candidate,baseline'
            expected_extra = ['--page-cache-response-memo']
            if protocol == 'h1':
                expected_extra += ['--h1-kernel', 'required', '--h1-kernel-wakeup', 'readiness']
            elif protocol == 'h2c':
                expected_extra += ['--h1-kernel', 'required', '--h2-kernel']
            expected_arms = [{'name': 'baseline', 'binary': artifacts['release']['path'], 'serve_args': []},
                {'name': 'candidate', 'binary': artifacts['candidate']['path'], 'serve_args': expected_extra}]
            if protocol in ['h1', 'h2c']:
                expected_arms[1]['launcher'] = {'binary': artifacts['helper']['path'], 'args': []}
            assert job['arms'] == read(directory / 'arms.json') == expected_arms
        events = [json.loads(line) for line in (directory / 'monitor/environment.jsonl').read_text().splitlines()]
        config, final = events[0], events[-1]
        assert config['event'] == 'configuration' and config['quiet_seconds'] == 10 and config['observer_affinity'] == [10]
        assert final['event'] == 'finished' and final['command_exit'] == 0 and final['compiler_overlap_observed'] is False
        assert not final['unique_compilers'] and all(not e['compilers'] for e in events if e['event'] == 'running')
        assert all(a['monotonic_ns'] < b['monotonic_ns'] for a, b in zip(events, events[1:]))
        exit_info = read(directory / 'exit.json')
        assert exit_info['exit_code'] == 0 and not exit_info['aborted'] and not exit_info['forced_observer_kill']
        assert exit_info['failure'] is None and not (directory / 'failure.json').exists()
        coverage = read(directory / 'kernel-coverage.json')
        assert not coverage['errors']
        monitors.append({'protocol': protocol, 'case': case, 'configuration': config, 'finished': final,
                         'sha256': sha(directory / 'monitor/environment.jsonl')})
        reports = sorted(measurements.glob('*/result.json'))
        assert len(reports) == 12
        aggregate = read(measurements / 'results.json')
        assert len(aggregate) == 12
        seen = set()
        for path in reports:
            arm_dir = path.parent
            pattern = (r'(?:h1|h1s|h2c|h2)-(?:static|pagecache)-([123])-([1234])-(baseline|candidate)'
                       if protocol != 'h3' else r'(?:static|pagecache)-([123])-([1234])-(baseline|accelerated)')
            match = re.fullmatch(pattern, arm_dir.name)
            assert match, arm_dir
            cycle, position = int(match[1]), int(match[2])
            role = 'baseline' if position in [1, 4] else 'candidate'
            assert (cycle, position) not in seen and (match[3] == 'baseline') == (role == 'baseline')
            seen.add((cycle, position))
            value, server_exit = read(path), read(arm_dir / 'server-exit.json')
            assert value in aggregate and server_exit['exit'] == 0 and not (arm_dir / 'failure.json').exists()
            assert value['training_only'] is value['diagnostic_only'] is False
            helper_used = protocol in ['h1', 'h2c'] and role == 'candidate'
            client, offered = value['client'], value['client']['offered_load']
            assert read(arm_dir / 'client.json') == client
            assert client['benchmark_valid'] and client['phase'] == 'measured'
            assert client['requested'] == client['completed'] == client['succeeded'] == 60000
            assert client['failed'] == client['unattempted'] == 0 and not client['errors']
            assert client['warmup_completed'] == 5000 and client['body_bytes'] == 1024 and client['expected_status'] == 200
            assert client['requested_rate'] == '15000' and client['latency_scope'] == 'scheduled_to_completion'
            eq(client['successful_requests_per_sec'], 60000 / client['elapsed_secs'], .001)
            assert client['connections'] == 32 and client['streams_per_connection'] == (1 if protocol in ['h1', 'h1s'] else 4)
            limit = 32 if protocol in ['h1', 'h1s'] else 128
            assert offered['concurrency_limit'] == limit and offered['dispatched'] == 60000
            assert offered['expired_before_dispatch'] == 0 and offered['fully_open_loop'] is False
            assert all(offered[k]['count'] == 60000 for k in ['service', 'dispatch_lateness', 'scheduled_all_outcomes'])
            assert type(offered['concurrency_waits']) is int and offered['concurrency_waits'] >= 0
            assert type(offered['peak_in_flight']) is int and 0 <= offered['peak_in_flight'] <= limit
            assert value['client_cpu_headroom_gate']['valid'] and value['client_cpu_headroom_gate']['passed']
            assert not value['cpu']['client_measured_saturation_warning']
            sockets = client['client_sockets']
            assert len(sockets) == 32 and len({s['local_address'] for s in sockets}) == 32
            assert all(s['local_address'].startswith('127.0.0.2:') for s in sockets)
            server_command, client_command = [read(arm_dir / name) for name in ['server-command.json', 'client-command.json']]
            assert option(client_command, '--bind') == '127.0.0.2'
            assert option(client_command, '--rate') == '15000' and option(client_command, '--connections') == '32'
            assert option(client_command, '--body').endswith('/content/asset.txt')
            assert '--no-fast-memo' not in server_command and '--page-cache' in server_command
            assert '--insecure' not in client_command and '--no-mtls' not in server_command
            tls = protocol in ['h1s', 'h2', 'h3']
            assert ('--ca' in client_command) == tls
            if tls:
                assert option(client_command, '--ca').endswith('/root/tls/fixture.crt')
                assert option(client_command, '--url').startswith('https://localhost:')
            else:
                assert option(client_command, '--url').startswith('http://localhost:')
            if protocol != 'h3':
                assert value['benchmark_valid'] and value['client_exit'] == 0
                assert not client['driver_errors'] and client['warmup_requested'] == client['warmup_succeeded'] == 5000
                assert client['verified_body_bytes'] == client['received_body_bytes'] == 60000 * 1024
                assert client['status_counts'] == {'200': 60000}
                assert value['arm']['sha256'] == (RELEASE if role == 'baseline' else APP)
                assert value['correctness']['protocol'] == protocol and value['correctness']['tls_verified'] == tls
                assert bool(value['arm'].get('launcher')) == helper_used
                if helper_used:
                    assert value['arm']['launcher']['sha256'] == HELPER
                assert all(value[k] is None for k in ['kernel_profile', 'profile_directory', 'profile_file_pattern', 'profile_server'])
            else:
                assert value['server_binary_sha256'] == (RELEASE if role == 'baseline' else APP)
                assert value['client_binary_sha256'] == H3_CLIENT and not value['loader'] and value['syscall_summary'] is None
                assert value['network_addresses'] == {'server': '127.0.0.2', 'client_bind': '127.0.0.2'}
                assert len(value['correctness']['checks']) >= 5
                assert value['correctness']['headers'][':status'] == '200'
            count, quantiles = latency_audit(arm_dir, protocol, client)
            total_latency_rows += count
            cpu, hw = value['cpu'], value['hardware_counters']
            old, new = cpu['server_process_ticks_before'], cpu['server_process_ticks_after']
            assert old['pids'] == new['pids'] and len(old['pids']) == (2 if helper_used else 1)
            pmu_threads += hardware_audit(hw, old['pids'])
            ticks = value['linux_cpu_ticks']['ticks_per_second']
            assert ticks == 100
            assert new['user'] >= old['user'] and new['system'] >= old['system']
            eq(cpu['server_user_secs'], (new['user'] - old['user']) / ticks)
            eq(cpu['server_system_secs'], (new['system'] - old['system']) / ticks)
            for snapshot in [old, new]:
                assert sum(p['user_ticks'] for p in snapshot['processes']) == snapshot['user']
                assert sum(p['system_ticks'] for p in snapshot['processes']) == snapshot['system']
            linux = value['linux_cpu_ticks']
            for name, counters in linux['delta'].items():
                assert all(v >= 0 for v in counters.values())
                for key, val in counters.items():
                    assert val == linux['after'][name][key] - linux['before'][name].get(key, 0)
            previous, following = prom(arm_dir / 'before.prom'), prom(arm_dir / 'after.prom')
            assert value['metric_deltas_include_client_warmup'] is True
            for key, val in value['metric_deltas'].items():
                eq(val, following.get(key, 0) - previous.get(key, 0))
            metric = 'httpjet_' + ('h1' if protocol in ['h1', 'h1s'] else 'h2') + '_kernel_successes_total'
            successes = value['metric_deltas'].get(metric) if protocol != 'h3' else None
            if helper_used:
                assert successes is not None and 0 < successes <= 65000
                assert value['metric_deltas'][metric.replace('successes', 'failures')] == 0
            elif protocol != 'h3' and successes is not None:
                assert successes == 0
            if case == 'pagecache':
                assert value['metric_deltas']['httpjet_pagecache_hits_total'] > 0
                if role == 'candidate':
                    assert value['metric_deltas']['httpjet_pagecache_lookup_total{path="response_memo",result="hit"}'] > 0
            elif protocol != 'h3' or role == 'candidate':
                assert value['metric_deltas']['httpjet_fast_memo_hits_total'] > 0
            else:
                assert previous['httpjet_pagecache_entries'] > 0 and following['httpjet_pagecache_entries'] > 0
            if protocol == 'h3' and role == 'candidate':
                assert value['metric_deltas']['httpjet_h3_request_engine_total{path="on_core"}'] > 0
            row = {'protocol': protocol, 'case': case, 'cycle': cycle, 'position': position, 'role': role,
                'RPS': client['successful_requests_per_sec'],
                'process_cpu_us_R': (cpu['server_user_secs'] + cpu['server_system_secs']) * 1e6 / 65000,
                'user_instructions_R': hw['totals']['instructions'] / 65000,
                'user_cycles_R': hw['totals']['cycles'] / 65000,
                'VM_busy_us_R': sum(linux['delta']['cpu'][k] for k in BUSY) * 1e6 / ticks / 65000,
                'scheduled_p99_us': quantiles['scheduled'], 'service_p99_us': quantiles['service'],
                'dispatch_lateness_p99_us': quantiles['lateness'], 'helper_used': helper_used,
                'kernel_successes': successes, 'kernel_fraction': successes / 65000 if successes is not None else None,
                'admission_limit': limit, 'admission_waits': offered['concurrency_waits'],
                'peak_in_flight': offered['peak_in_flight'],
                'VM_tcp_retransmissions': value.get('kernel_counters_delta', {}).get('tcp_RetransSegs'),
                'VM_tcp_timeouts': value.get('kernel_counters_delta', {}).get('tcp_TCPTimeouts')}
            rows.append(row)
        assert seen == {(c, p) for c in [1, 2, 3] for p in [1, 2, 3, 4]}
    assert len(rows) == 120 and total_latency_rows == 7680000 and len(monitors) == 10
    grouped, changes, cycles = [], [], []
    for protocol, case in sorted({(r['protocol'], r['case']) for r in rows}):
        selected = [r for r in rows if (r['protocol'], r['case']) == (protocol, case)]
        roles = {role: median([r for r in selected if r['role'] == role]) for role in ['baseline', 'candidate']}
        for role, values in roles.items():
            grouped.append({'protocol': protocol, 'case': case, 'role': role, 'arms': 6, **values})
        aggregate_change = delta(roles['baseline'], roles['candidate'])
        changes.append({'protocol': protocol, 'case': case, **aggregate_change})
        for cycle in [1, 2, 3]:
            pair = {role: median([r for r in selected if r['role'] == role and r['cycle'] == cycle])
                    for role in ['baseline', 'candidate']}
            change = delta(pair['baseline'], pair['candidate'])
            opposite = [k for k in METRICS if change[k] is not None and aggregate_change[k] is not None
                        and change[k] * aggregate_change[k] < 0]
            cycles.append({'protocol': protocol, 'case': case, 'cycle': cycle, **change,
                           'opposite_direction': ';'.join(opposite)})
    out.mkdir()
    write_csv(out / 'arms.csv', rows)
    write_csv(out / 'groups.csv', grouped)
    write_csv(out / 'changes-percent.csv', changes)
    write_csv(out / 'cycles-percent.csv', cycles)
    manifest = [{'path': str(p.relative_to(raw)), 'bytes': p.stat().st_size, 'sha256': sha(p)}
                for p in sorted(raw.rglob('*')) if p.is_file()]
    write_json(out / 'raw-manifest.json', manifest)
    admission_rows = [r for r in rows if r['admission_waits']]
    receipt = {'schema': 1, 'passed': True, 'arms': 120, 'measured_responses': 7200000,
        'warmup_completed_responses': 600000, 'raw_latency_rows_verified': total_latency_rows,
        'PMU_thread_records_recomputed': pmu_threads, 'boot_id': BOOT,
        'artifacts': {'release': RELEASE, 'archive': ARCHIVE, 'candidate': APP, 'helper': HELPER,
                      'http_client': HTTP_CLIENT, 'h3_client': H3_CLIENT},
        'scope': 'Exact shipped v0.1.10-11 versus retained ABF candidate; warm synthetic 1KiB, same 15k R/s offered load, 3 ABBA cycles.',
        'source_before_after_exact': True,
        'source_seals': {p.name: sha(p) for p in [root / 'plan.json', root / 'completion.json',
            root / 'inputs-before.json', root / 'inputs-after.json']},
        'owned_cleanup_receipt_sha256': sha(root / 'logs/release-comparison-command.json'),
        'monitors': monitors, 'comparisons': changes, 'cycles': cycles,
        'admission_wait_arms': admission_rows,
        'total_admission_waits': sum(r['admission_waits'] for r in rows),
        'normalization': {'CPU_PMU_VM_denominator': 65000, 'latency_denominator': 60000, 'tick_hz': 100,
            'latency': 'Scheduled arrival to completion; reported cell p99 is median of six arm p99 values, not pooled request p99. Service and dispatch-lateness quantiles remain separate.',
            'load': '15,000 R/s bounded admission: H1/H1TLS=32, H2c/H2TLS/H3=128. Admission waits remain included. Not an unrestricted open-loop or capacity test.',
            'process_CPU': 'Server plus helper where used, user+system over 65,000 client responses including warmup; kernel/IRQ charged elsewhere excluded.',
            'PMU': 'Recomputed user-mode server/helper thread counts; excludes kernel/IRQ/hypervisor/guest.',
            'VM_CPU': 'All Linux CPUs user+nice+system+IRQ+softIRQ; includes clients and unrelated work; Windows host unobserved.'},
        'limitations': ['Exact public release comparison measures combined source/compiler/profile/runtime effects; it does not isolate Beeper.',
            'Both arms keep caches enabled. Candidate additionally enables finished page-response memo and accelerated H3; TLS paths do not use kernel serving.',
            'H3 TSV omits warmup and status fields; measured bytes/error/timing are recomputed; status/body/warmup validity is checked through pinned validating clients/harness and summaries.',
            'Docker empty and host/source invariance are checked before/after; compiler activity is sampled each second, not continuously. Windows scheduling and short unsampled activity remain unobserved.',
            'Process CPU improvements do not establish whole-VM CPU improvements; all cell/cycle directions are retained.'],
        'raw_manifest_sha256': sha(out / 'raw-manifest.json'), 'recompute_sha256': sha(__file__),
        'outputs_sha256': {p.name: sha(p) for p in out.iterdir() if p.is_file()}}
    write_json(out / 'receipt.json', receipt)
    print(json.dumps({'receipt': str(out / 'receipt.json'), 'sha256': sha(out / 'receipt.json'),
                      'changes': changes, 'admission_wait_arms': len(admission_rows),
                      'total_admission_waits': receipt['total_admission_waits']}))


if __name__ == '__main__':
    main()
