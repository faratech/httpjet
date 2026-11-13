#!/usr/bin/env python3
"""Render the sealed H2 PGO rate study from local, pinned records only."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics

SUMMARY_SHA = '8e5dbed8e0f832afca18aed80c5880393388e64ecd25cc54791a55bc0e38c656'
RUN = '/var/tmp/httpjet-continuation/pgo-c6ac-v1'
SEQUENCE = ['release', 'native', 'kernel', 'kernel', 'native', 'release']
CASES = ['static', 'pagecache']
MODES = ['release', 'native', 'kernel']
LABELS = {'release': 'Release v0.1.10-11', 'native': 'PGO native', 'kernel': 'PGO kernel'}
PINS = {
    RUN + '/bin-use/httpjet': '0ca04dcb8d3b9d07e02ac19658546d7882d6f2719c6937be2f259ca65eef83c5',
    RUN + '/bin-use/httpjet-beeper-h1': '1cce1f3ca5837e5d68b9be757438af28a88be789468372392bf6148a3987721d',
    '/var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet': '3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec',
    '/var/tmp/httpjet-http-paced-client-v2/bin/httpjet-http-load-paced': '0cb400bd7a56df95a03219ff227195e2ca6168ca1cf98c02b8ce48ac5ffacca6',
}


def check(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text())


def key(row):
    return row['case'], row['cycle'], row['position'], row.get('mode', row.get('arm'))


def validate(folder):
    path = folder / 'summary.json'
    check(sha(path) == SUMMARY_SHA, 'summary identity changed')
    s, seal, status = load(path), load(folder / 'integrity.json'), load(folder / 'run-status.json')
    check(s['status'] == 'complete' and not s['issues'] and not s['unplanned_rows'], 'unqualified summary')
    check(s['planned_arms'] == s['validated_arms'] == 36 and len(s['rows']) == 36, 'incomplete planned arms')
    check(s['sequence'] == SEQUENCE and s['cycles'] == 3 and s['offered_rate'] == 15000
          and s['concurrency_limit'] == 128 and s['fully_open_loop'] is False, 'workload drift')
    check(s['requests_per_arm'] == 60000 and s['warmup_per_arm'] == 5000
          and s['measured_responses'] == 2160000 and s['warmup_responses'] == 180000, 'response totals differ')
    check(s['artifacts'] == PINS, 'wrong binary identities')
    check(seal['status'] == 'passed' and seal['completed_arms'] == 36 and seal['summary_sha256'] == SUMMARY_SHA
          and seal['measured_responses'] == 2160000 and seal['warmup_responses'] == 180000
          and seal['all_pinned_binaries_unchanged'] is True
          and seal['no_owned_benchmark_executables_running'] is True, 'integrity seal failed')
    check(status == s['run_status'] and status['passed'] is True and not status['errors']
          and status['command_exit'] == status['final_integrity_exit'] == 0
          and status['completed_arms'] == status['expected_arms'] == 36, 'rate execution did not seal')
    expected = [(c, n, p, m) for c in CASES for n in [1, 2, 3] for p, m in enumerate(SEQUENCE, 1)]
    check([key(r) for r in s['rows']] == expected, 'wrong arm positions/order')
    sealed = {key(r): r for r in status['rows']}
    check(set(sealed) == set(expected) and len(status['rows']) == 36, 'sealed row identity mismatch')
    for row in s['rows']:
        check(row['status'] == 'complete' and not row['issues'] and row['failure'] is None
              and type(row['server_exit']['exit']) is int and row['server_exit']['exit'] == 0, 'failed/incomplete arm')
        check(row['source_sha256'] == sealed[key(row)]['source_sha256']
              == s['source_inputs'][row['source']]['sha256'], 'arm source hash mismatch')
        check(row['denominator'] == {'measured_responses': 60000, 'warmup_responses': 5000,
                                    'whole_client_span_responses': 65000}, 'wrong CPU/counter denominator')
        check(all(v == 60000 for v in row['latency_counts'].values())
              and set(row['latency_counts']) == {'scheduled_all_outcomes', 'service', 'dispatch_lateness'}, 'latency outcomes incomplete')
        check(0 <= row['peak_in_flight'] <= 128 and row['concurrency_waits'] >= 0
              and 0 < row['pmu_running_fraction'] <= 1.000001, 'invalid admission/PMU evidence')
        arm = row['recorded_arm']
        check(arm['name'] == row['mode'] and arm['sha256'] == PINS[arm['binary']], 'wrong recorded binary')
        if row['mode'] == 'release':
            check(arm['binary'].endswith('/baselines/v0.1.10-11/httpjet') and arm['serve_args'] == []
                  and 'launcher' not in arm, 'release has experimental arguments')
        elif row['mode'] == 'native':
            check(arm['binary'] == RUN + '/bin-use/httpjet'
                  and arm['serve_args'] == ['--h1-kernel', 'off', '--page-cache-response-memo']
                  and 'launcher' not in arm, 'native configuration differs')
        else:
            check(arm['binary'] == RUN + '/bin-use/httpjet'
                  and arm['serve_args'] == ['--h1-kernel', 'required', '--h2-kernel', '--page-cache-response-memo']
                  and arm['launcher'] == {'binary': RUN + '/bin-use/httpjet-beeper-h1',
                                         'sha256': PINS[RUN + '/bin-use/httpjet-beeper-h1'], 'args': []}, 'kernel configuration differs')
        for value in row['metrics'].values():
            check(value is None or (isinstance(value, (int, float)) and not isinstance(value, bool)
                                    and math.isfinite(value) and value >= 0), 'invalid row metric')
        count = row['kernel_successes']
        check((count is not None and 0 < count <= 65000) if row['mode'] == 'kernel'
              else count in (0, None), 'kernel activation/ownership mismatch')
        check(row['metrics']['kernel_success_fraction'] == (None if count is None else count / 65000), 'kernel denominator drift')
    groups = {(g['case'], g['mode']): g for g in s['groups']}
    check(len(s['groups']) == len(groups) == 6 and set(groups) == {(c, m) for c in CASES for m in MODES}, 'missing groups')
    for (case, mode), group in groups.items():
        rows = [r for r in s['rows'] if r['case'] == case and r['mode'] == mode]
        check(group['status'] == 'complete' and group['planned_arms'] == group['validated_arms'] == len(rows) == 6, 'partial group')
        for metric, value in group['medians'].items():
            values = [r['metrics'][metric] for r in rows if r['metrics'][metric] is not None]
            check(value == (statistics.median(values) if values else None), f'median mismatch: {case}/{mode}/{metric}')
        check(group['max_peak_in_flight'] == max(r['peak_in_flight'] for r in rows)
              and group['total_concurrency_waits'] == sum(r['concurrency_waits'] for r in rows)
              and group['arms_at_cap'] == sum(r['peak_in_flight'] == 128 for r in rows), 'admission summary mismatch')
    check(sum(r['peak_in_flight'] == 128 for r in s['rows']) == 7
          and sum(r['concurrency_waits'] for r in s['rows']) == 594, 'expected admission totals differ')
    before, after = [load(folder / f'h2-rate15000-inputs-{p}-v1.json') for p in ['before', 'after']]
    check(before == after and before['pins'] == PINS, 'pre/post inputs drift')
    copies = {'pgo-c-h2-rate.sh': '/var/tmp/pgo-c-h2-rate.sh',
              'pgo-c-rate-harness-sha256.json': RUN + '/rate-harness-sha256.json'}
    for local, remote in copies.items():
        check(sha(folder / local) == before['input_sha256'][remote], f'copied input mismatch: {local}')
    check(sha(folder / 'summarize-pgo-h2-rate.py') == s['summarizer']['sha256'], 'analyzer copy mismatch')
    rejected = load(folder / 'analysis-v1-rejected.json')
    check(rejected['status'] == 'incomplete' and any('AGENTS.md' in i for i in rejected['issues'])
          and all(g['medians'] is None for g in rejected['groups']), 'rejected analysis receipt differs')
    previous = {key(r): r for r in rejected['rows']}
    check(set(previous) == set(expected) and all(previous[key(r)]['source_sha256'] == r['source_sha256']
          and previous[key(r)]['metrics'] == r['metrics'] for r in s['rows']), 'benchmark data changed across analyzer fix')
    return s, groups


def percent(a, b):
    return 100 * (a / b - 1)


def delta(a, b):
    return f'{percent(a, b):+.2f}%'


def render(s, groups):
    med = lambda c, m: groups[c, m]['medians']
    lines = ['# H2 PGO at matched lower load: native and kernel tradeoffs', '',
        'Measured and published **31 October 2026**.', '',
        'At an offered 15,000 requests/s, the PGO candidate in native H2 mode uses less process CPU than '
        'the exact release in both fixtures. Enabling kernel H2 on the same PGO build increases process CPU '
        'and the across-arm median service p99. Scheduled p99 moves in different directions for static and page-cache traffic. '
        'This is a matched-rate comparison, not a capacity ranking.', '',
        'The [full release capacity matrix](pgo-release-2026-10-31.md) and '
        '[same-source PGO pilot](pgo-pilot-2026-10-30.md) answer separate questions. '
        'Native-candidate versus release results combine the candidate implementation, page-response memo and build/profile effects; '
        'they do not isolate PGO or Beeper alone. The native/kernel pair uses the same PGO binary and isolates the requested kernel option.', '',
        '## Workload and completeness', '',
        'All **36 arms**, **2,160,000 measured responses** and **180,000 warmup responses** validated. '
        'Every arm uses 60,000 measured requests plus 5,000 warmup requests, a 1 KiB body, H2c, '
        '32 connections with four streams each, one server worker on CPU 8 and six client threads on CPUs 0,2,4,6,12,14. '
        'The observer runs on CPU 10. Both ends use `127.0.0.2` on SINGULARITY; the recorded route uses Linux loopback.', '',
        'Each of the static and origin page-cache fixtures runs three symmetric '
        '`release, native, kernel, kernel, native, release` cycles. Existing caches are enabled and warmed; '
        'the candidate native/kernel arms both enable the finished page-response memo. PHP is disabled. '
        'The release receives no experimental arguments. The kernel arm uses the pinned privileged helper; '
        'unsupported input retains native ownership.', '',
        'Admission is bounded at **128** concurrent requests. **7/36 arms reached that cap**, with **594 admission waits** '
        'across the complete run. These measurements are neither unrestricted open-loop load nor proof of continuous unsaturation. '
        'Failures, expiry and unattempted outcomes are checked; there are no retries or reconnects to hide them.', '',
        '## All six groups', '',
        'Values below are medians of six complete arm values per fixture/mode. The p99 columns are '
        'medians of per-arm percentiles, not percentiles recalculated from pooled requests. '
        'Scheduled-to-completion, service and dispatch-lateness p99 are distinct; do not add their quantiles.', '',
        '| Fixture | Mode | Achieved RPS | Scheduled p99 ms | Service p99 ms | Dispatch p99 ms | Process CPU µs/R |',
        '|---|---|---:|---:|---:|---:|---:|']
    for case in CASES:
        for mode in MODES:
            m = med(case, mode)
            lines.append(f"| {case} | {LABELS[mode]} | {m['rps']:,.1f} | {m['scheduled_p99_us']/1000:.3f} | "
                         f"{m['service_p99_us']/1000:.3f} | {m['dispatch_lateness_p99_us']/1000:.3f} | {m['process_cpu_us_per_response']:.2f} |")
    lines += ['', 'Achieved throughput is approximately 14,994–14,998 requests/s because the offered rate is fixed. '
        'Its small differences do not establish maximum-throughput gains.', '',
        '| Fixture | Comparison | Process CPU Δ | Scheduled p99 Δ | Service p99 Δ |',
        '|---|---|---:|---:|---:|']
    for case in CASES:
        for a, b, label in [('native', 'release', 'PGO native / release'), ('kernel', 'native', 'PGO kernel / PGO native')]:
            ma, mb = med(case, a), med(case, b)
            lines.append(f"| {case} | {label} | {delta(ma['process_cpu_us_per_response'], mb['process_cpu_us_per_response'])} | "
                         f"{delta(ma['scheduled_p99_us'], mb['scheduled_p99_us'])} | {delta(ma['service_p99_us'], mb['service_p99_us'])} |")
    lines += ['', 'Kernel serving accounts for approximately **97.9%** of requests in each kernel group '
        '(counter window includes warmup). Its higher process CPU is therefore observed while offload is active. '
        'The static kernel group has a slightly lower across-arm median scheduled p99; the page-cache kernel group has a higher one.', '',
        '## CPU counters and admission', '',
        '| Fixture / mode | User instructions/R | VM busy µs/R | Kernel-hit median [min, max] | Peak in flight | Admission waits | Arms at 128 |',
        '|---|---:|---:|---|---:|---:|---:|']
    for case in CASES:
        for mode in MODES:
            g, m = groups[case, mode], med(case, mode)
            fractions = [r['metrics']['kernel_success_fraction'] for r in s['rows'] if r['case'] == case and r['mode'] == mode
                         and r['metrics']['kernel_success_fraction'] is not None]
            hits = 'not exposed' if not fractions else f"{100*statistics.median(fractions):.2f}% [{100*min(fractions):.2f}%, {100*max(fractions):.2f}%]"
            lines.append(f"| {case} / {LABELS[mode]} | {m['user_instructions_per_response']:,.0f} | {m['whole_vm_busy_us_per_response']:.2f} | "
                         f"{hits} | {g['max_peak_in_flight']} | {g['total_concurrency_waits']} | {g['arms_at_cap']} |")
    lines += ['', 'Process CPU is server plus helper **user + system** time over the whole client span, including '
        'handshake, warmup, measurement, client output and teardown. The server’s later shutdown/drain is outside '
        'this span. Its denominator is **65,000 responses** per arm. '
        'It excludes kernel/IRQ work charged elsewhere. PMU instructions and cycles count **user mode only**, '
        'with the same 65,000-response denominator; they exclude kernel, IRQ and hypervisor work.', '',
        'VM busy includes all Linux CPUs and clients/unrelated Linux work. The analyzer converts '
        '`user + nice + system + irq + softirq` ticks with each arm’s recorded '
        '`linux_cpu_ticks.ticks_per_second`: `busy_ticks × 1,000,000 / ticks_per_second / 65,000`. '
        'Windows host activity is unobserved. These process, PMU and VM measures have different scopes; '
        'none alone establishes whole-server CPU savings.', '',
        '## Cycle variation', '',
        'Each delta uses the ratio of the two-arm medians within that cycle. These observations are not confidence intervals. '
        'For example, native static scheduled p99 rises in one cycle despite its lower across-arm median. '
        'Kernel process CPU is higher than native in every cycle of both fixtures.', '',
        '| Fixture | Cycle | Native / release CPU Δ | Native / release scheduled p99 Δ | Kernel / native CPU Δ | Kernel / native scheduled p99 Δ | Kernel / native service p99 Δ |',
        '|---|---:|---:|---:|---:|---:|---:|']
    for case in CASES:
        for cycle in [1, 2, 3]:
            r = [x for x in s['rows'] if x['case'] == case and x['cycle'] == cycle]
            m = {mode: {k: statistics.median(x['metrics'][k] for x in r if x['mode'] == mode)
                        for k in ['process_cpu_us_per_response', 'scheduled_p99_us', 'service_p99_us']} for mode in MODES}
            d = lambda a, b, k: delta(m[a][k], m[b][k])
            lines.append(f"| {case} | {cycle} | {d('native','release','process_cpu_us_per_response')} | {d('native','release','scheduled_p99_us')} | "
                         f"{d('kernel','native','process_cpu_us_per_response')} | {d('kernel','native','scheduled_p99_us')} | {d('kernel','native','service_p99_us')} |")
    lines += ['', '## Operational interpretation', '',
        'For CPU-sensitive or service-latency-sensitive operation at this tested lower H2c load, '
        'prefer the native H2 path. Kernel H2 remains an opt-in '
        'capacity option with the CPU/latency costs shown here and in the full capacity matrix. '
        'This result does not establish an automatic rate threshold or change runtime defaults. '
        'Other rates, bodies, congestion, encrypted H2 and real application traffic require their own measurements.', '',
        '## Evidence and analyzer correction', '',
        '[All 36 arms](../docs/evidence/pgo-h2-rate-20261031/arms.csv), '
        '[complete summary](../docs/evidence/pgo-h2-rate-20261031/summary.json), '
        '[integrity seal](../docs/evidence/pgo-h2-rate-20261031/integrity.json), '
        '[run status](../docs/evidence/pgo-h2-rate-20261031/run-status.json), '
        '[analyzer](../docs/evidence/pgo-h2-rate-20261031/summarize-pgo-h2-rate.py) and '
        '[renderer](../docs/evidence/pgo-h2-rate-20261031/render-report.py) retain the identities and derivation.', '',
        'The [first analysis receipt](../docs/evidence/pgo-h2-rate-20261031/analysis-v1-rejected.json) '
        'is retained. Source verification initially rejected the legitimate tracked `AGENTS.md → CLAUDE.md` alias '
        'because it required a regular file at the alias path. The corrected analyzer resolves source aliases '
        'only to targets inside the frozen source tree and hashes the regular target. The same 36 benchmark arms '
        'were then summarized: no benchmark rerun or arm selection occurred. The rejected receipt has no aggregate '
        'medians, and every retained arm’s source hash and metric values match this completed analysis.', '',
        f'Summary SHA256: `{SUMMARY_SHA}`.', '',
        '| Artifact | SHA256 |', '|---|---|']
    for label, path in [('release', '/var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet'),
                        ('PGO candidate', RUN + '/bin-use/httpjet'), ('PGO helper', RUN + '/bin-use/httpjet-beeper-h1'),
                        ('paced client', '/var/tmp/httpjet-http-paced-client-v2/bin/httpjet-http-load-paced')]:
        lines.append(f'| {label} | `{PINS[path]}` |')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    folder = args.folder.resolve()
    output = args.output or Path(__file__).resolve().parents[3] / 'beeper/h2-pgo-rate-2026-10-31.md'
    summary, groups = validate(folder)
    fields = ['case', 'cycle', 'position', 'mode', 'status', *summary['groups'][0]['medians'],
              'kernel_successes', 'peak_in_flight', 'concurrency_waits', 'pmu_running_fraction', 'source_sha256', 'source']
    with (folder / 'arms.csv').open('w', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=fields, lineterminator='\n')
        writer.writeheader()
        for row in summary['rows']:
            writer.writerow({k: row['metrics'].get(k, row.get(k)) for k in fields})
    output.write_text(render(summary, groups))
    print(f'Rendered all 36 arms and six groups from summary {SUMMARY_SHA}')


if __name__ == '__main__':
    main()
