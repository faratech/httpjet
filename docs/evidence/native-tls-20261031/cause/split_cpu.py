#!/usr/bin/env python3
"""Split saved TLS48 user/system CPU and PMU by arm and ABBA cycle."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--raw', required=True, type=Path)
p.add_argument('--out', required=True, type=Path)
a = p.parse_args()
assert not a.out.exists()
metrics = ['user_cpu_us_R', 'system_cpu_us_R', 'total_cpu_us_R',
           'user_instructions_R', 'user_cycles_R', 'IPC', 'scheduled_p99_us', 'service_p99_us']
rows = []
for path in sorted(a.raw.rglob('result.json')):
    value = json.loads(path.read_text())
    cpu, hw = value['cpu'], value['hardware_counters']
    name = path.parent.name.split('-')
    rows.append({'protocol': value['protocol'], 'case': value['case'],
        'cycle': int(name[-3]), 'position': int(name[-2]), 'role': name[-1],
        'user_cpu_us_R': cpu['server_user_secs'] * 1e6 / 65000,
        'system_cpu_us_R': cpu['server_system_secs'] * 1e6 / 65000,
        'total_cpu_us_R': (cpu['server_user_secs'] + cpu['server_system_secs']) * 1e6 / 65000,
        'user_instructions_R': hw['totals']['instructions'] / 65000,
        'user_cycles_R': hw['totals']['cycles'] / 65000,
        'IPC': hw['totals']['instructions'] / hw['totals']['cycles'],
        'scheduled_p99_us': value['client']['p99_us'],
        'service_p99_us': value['client']['offered_load']['service']['p99_us'],
        'result_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
assert len(rows) == 48
groups, changes = [], []
for protocol, case in sorted({(r['protocol'], r['case']) for r in rows}):
    for cycle in ['all', 1, 2, 3]:
        selected = [r for r in rows if r['protocol'] == protocol and r['case'] == case
                    and (cycle == 'all' or r['cycle'] == cycle)]
        values = {}
        for role in ['baseline', 'candidate']:
            result = {k: statistics.median(r[k] for r in selected if r['role'] == role) for k in metrics}
            values[role] = result
            groups.append({'protocol': protocol, 'case': case, 'cycle': cycle, 'role': role, **result})
        changes.append({'protocol': protocol, 'case': case, 'cycle': cycle,
            **{k: 100 * (values['candidate'][k] / values['baseline'][k] - 1)
               if values['baseline'][k] else None for k in metrics}})
a.out.mkdir()
for name, data in [('arms', rows), ('groups', groups), ('changes-percent', changes)]:
    with (a.out / (name + '.csv')).open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=data[0])
        writer.writeheader()
        writer.writerows(data)
