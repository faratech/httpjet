#!/usr/bin/env python3
"""Read-only derivation from sealed benchmark JSON; writes new local CSVs only."""
import collections
import csv
import hashlib
import json
from pathlib import Path
import statistics

ROOT = Path('/var/tmp/httpjet-regression-review-v1')
SOURCE = Path('/var/tmp/httpjet-exact-release-p99-independent-v1')
RAW = SOURCE / 'raw'
SEALED = SOURCE / 'sealed-v1'
RECEIPT_SHA = 'b9c25bc383cf28dd8c560758140110028e663ff0c2c122fc8aabb777019e87ec'

def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def read(path):
    return json.loads(Path(path).read_text())

def output(name, value):
    with (ROOT / name).open('x') as f:
        json.dump(value, f, indent=2, allow_nan=False)
        f.write('\n')

def table(name, rows):
    with (ROOT / name).open('x', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

def change(before, after):
    return (after / before - 1) * 100 if before else None

def main():
    assert sha(SEALED / 'receipt.json') == RECEIPT_SHA
    receipt = read(SEALED / 'receipt.json')
    assert receipt['passed'] and receipt['arms'] == 120
    assert sha(SEALED / 'raw-manifest.json') == receipt['raw_manifest_sha256']
    pins = {x['path']: x for x in read(SEALED / 'raw-manifest.json')}
    rows, processes, cpu_rows, inputs, network = [], [], [], [], []
    base = RAW / 'run-v1/release-comparison/release'
    for cell in sorted(base.iterdir()):
        for path in sorted((cell / 'measurements').glob('*/result.json')):
            relative = str(path.relative_to(RAW))
            assert sha(path) == pins[relative]['sha256'] and path.stat().st_size == pins[relative]['bytes']
            inputs.append({'path': relative, 'bytes': path.stat().st_size, 'sha256': sha(path)})
            value = read(path)
            protocol, case, _ = cell.name.split('-')
            fields = path.parent.name.split('-')
            cycle, position = int(fields[-3]), int(fields[-2])
            role = 'baseline' if fields[-1] == 'baseline' else 'candidate'
            helper = protocol in ['h1', 'h2c'] and role == 'candidate'
            cpu = value['cpu']
            before, after = [cpu['server_process_ticks_' + name] for name in ['before', 'after']]
            assert before['pids'] == after['pids'] and len(after['pids']) == (2 if helper else 1)
            for phase, snapshot in [('before', before), ('after', after)]:
                assert snapshot['rss_bytes'] == sum(p['VmRSS'] for p in snapshot['processes'])
                assert snapshot['hwm_sum_bytes'] == sum(p['VmHWM'] for p in snapshot['processes'])
                for p in snapshot['processes']:
                    assert all(type(p[k]) is int and p[k] > 0 for k in ['pid', 'VmRSS', 'VmHWM'])
                    assert p['VmHWM'] >= p['VmRSS']
                    process_role = 'helper' if helper and p['pid'] == value['hardware_counters']['pid'] else 'web'
                    processes.append({'protocol': protocol, 'case': case, 'cycle': cycle, 'position': position,
                        'role': role, 'phase': phase, 'process_role': process_role, **p})
            metadata = {'protocol': protocol, 'case': case, 'cycle': cycle, 'position': position, 'role': role}
            after_by_role = {p['process_role']: p for p in processes[-len(after['processes']):]}
            rows.append({**metadata, 'helper_used': helper, 'before_rss_bytes': before['rss_bytes'],
                'after_rss_bytes': after['rss_bytes'], 'rss_growth_bytes': after['rss_bytes'] - before['rss_bytes'],
                'before_hwm_sum_bytes': before['hwm_sum_bytes'], 'after_hwm_sum_bytes': after['hwm_sum_bytes'],
                'after_web_rss_bytes': after_by_role['web']['VmRSS'],
                'after_helper_rss_bytes': after_by_role['helper']['VmRSS'] if helper else 0})
            linux = value['linux_cpu_ticks']; tick_hz = linux['ticks_per_second']
            assert tick_hz == 100
            counters = linux['delta']['cpu']
            cpu_rows.append({**metadata,
                'server_cpu_us_R': (cpu['server_user_secs'] + cpu['server_system_secs']) * 1e6 / 65000,
                'client_cpu_us_R': (cpu['client_user_secs'] + cpu['client_system_secs']) * 1e6 / 65000,
                'VM_busy_us_R': sum(counters[k] for k in ['user','nice','system','irq','softirq']) * 1e6 / tick_hz / 65000,
                'VM_user_us_R': (counters['user'] + counters['nice']) * 1e6 / tick_hz / 65000,
                'VM_system_us_R': counters['system'] * 1e6 / tick_hz / 65000,
                'VM_softirq_us_R': counters['softirq'] * 1e6 / tick_hz / 65000,
                'VM_irq_us_R': counters['irq'] * 1e6 / tick_hz / 65000})
            k = value.get('kernel_counters_delta')
            network.append({**metadata, 'captured': k is not None,
                **{name:k.get(name) if k is not None else None for name in
                    ['tcp_RetransSegs','tcp_TCPTimeouts','tcp_TCPBacklogDrop','tcp_TCPSpuriousRTOs','softirq_net_rx','softirq_sched']}})
    assert len(rows) == 120
    table('memory-arms.csv', rows)
    table('memory-processes.csv', processes)
    table('client-vm-arms.csv', cpu_rows)
    table('network-counters.csv', network)
    grouped, cycles, cpu_groups, cpu_cycles = [], [], [], []
    memory_metrics = [k for k in rows[0] if k.endswith('_bytes')]
    cpu_metrics = [k for k in cpu_rows[0] if k.endswith('_us_R')]
    for protocol, case in sorted({(x['protocol'],x['case']) for x in rows}):
        for cycle in [None,1,2,3]:
            sel=lambda data,role:[x for x in data if x['protocol']==protocol and x['case']==case and x['role']==role and (cycle is None or x['cycle']==cycle)]
            for data,metrics,target in [(rows,memory_metrics,grouped if cycle is None else cycles),
                                       (cpu_rows,cpu_metrics,cpu_groups if cycle is None else cpu_cycles)]:
                record={'protocol':protocol,'case':case}
                if cycle is not None:record['cycle']=cycle
                expected=6 if cycle is None else 2
                assert all(len(sel(data,role))==expected for role in ['baseline','candidate'])
                for metric in metrics:
                    med={role:statistics.median(x[metric] for x in sel(data,role)) for role in ['baseline','candidate']}
                    record['baseline_'+metric]=med['baseline'];record['candidate_'+metric]=med['candidate']
                    record['change_pct_'+metric]=change(med['baseline'],med['candidate'])
                target.append(record)
    table('memory-groups.csv',grouped);table('memory-cycles.csv',cycles)
    table('client-vm-groups.csv',cpu_groups);table('client-vm-cycles.csv',cpu_cycles)
    output('inputs.json',{'sealed_receipt_sha256':RECEIPT_SHA,'raw_manifest_sha256':receipt['raw_manifest_sha256'],'results':inputs})
    outputs={p.name:sha(p) for p in ROOT.iterdir() if p.is_file()}
    output('receipt.json',{'passed':True,'arms':120,'process_snapshot_rows':len(processes),
        'method':'Six-arm medians per role; two-arm medians per paired cycle. Memory is post-client process RSS, summed over server/helper where present.',
        'sanity':'Every VmRSS/VmHWM positive integer; VmHWM>=VmRSS; snapshot sums match recorded aggregate; per-arm process identities unchanged.',
        'sealed_input_receipt_sha256':RECEIPT_SHA,'input_result_hashes_verified':120,
        'limitations':['Summed RSS may double-count shared resident pages; this is not PSS, BPF map memory, kernel socket memory or system memory.',
            'Summed process VmHWM values are individual high-water marks, not simultaneous aggregate peaks.',
            'Short 1KiB/32-connection workload: no leak, long-run growth, many-connection or large-cache qualification.',
            'Server/client CPU and /proc/stat snapshots broadly bracket the same whole client run but are sequential, with PMU setup/stop between boundaries. Component medians are not additive; do not treat VM minus process CPU as exact attributable kernel cost.',
            'Whole-VM kernel network counters include unrelated traffic; no per-socket attribution. H3 JSON does not capture kernel_counters_delta; null is unmeasured, not zero.'],
        'outputs_sha256':outputs})
    print(json.dumps({'passed':True,'output_root':str(ROOT),'memory_regressions':[{'protocol':x['protocol'],'case':x['case'],'baseline_MiB':x['baseline_after_rss_bytes']/2**20,'candidate_MiB':x['candidate_after_rss_bytes']/2**20,'change_pct':x['change_pct_after_rss_bytes']} for x in grouped if x['change_pct_after_rss_bytes']>0],'receipt_sha256':sha(ROOT/'receipt.json')}))

if __name__ == '__main__':
    main()
