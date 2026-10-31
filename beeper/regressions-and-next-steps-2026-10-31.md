# Regression ledger and next steps

CPU and memory remain open costs in retained candidate `abf7a79c…`. The latest exact-release study improves server/helper CPU, but increases process RSS on plaintext kernel paths and H3. A separate, earlier native PGO comparison still records higher static HTTPS H2 server CPU. These comparisons have different controls and must stay separate.

This ledger analyzes existing SINGULARITY evidence. No new server, build, kernel or benchmark was run for it. The baseline distinction matters: “release” below is the exact distributed v0.1.10-11; “native PGO” is a fresh historical-source build, `24ccc3a8…`.

## Current candidate versus the exact shipped release

The [120-arm release comparison](release-p99-2026-10-31.md) covers warm 1 KiB responses at 15,000 offered requests/s, three ABBA cycles, with caches enabled on both binaries. Its existing seal verifies 7.2 million measured responses and 600,000 warmups. The resource derivation verifies all 120 result hashes against that sealed manifest.

| Resource or outcome | Observed change | Qualification |
|---|---|---|
| Server/helper CPU | Lower in all ten cells and all 30 paired cycles | No process-CPU regression against the shipped release in this workload |
| Whole-VM CPU, H1 HTTPS page cache | **+13.98%** | Cycles +35.83%, +3.00%, −8.40%; server CPU falls 43.60%, so cause remains unattributed |
| Summed process RSS, plaintext H1/H2c | **+17.0–17.9 MiB, +34.2–39.2%** | Higher in every paired cycle; includes the helper |
| Process RSS, H3 | **+3.7–4.0 MiB, +6.4–6.7%** | Higher in every paired cycle |
| Load-generator CPU per response | H1 plaintext **+8.1–8.7%**; H3 **+8.0–8.9%** | Higher in every cycle; this is benchmark-client work, not a browser-energy measurement |
| Responses, status/body, protocol, clean exits | All passed | Covered synthetic fixtures and existing qualification gates; not exhaustive application correctness |
| Throughput at the offered load | All cell medians approximately 14,994–14,997 requests/s | This capped-rate experiment cannot establish maximum-capacity gains or losses |

Memory below is the median **post-client RSS**, not proportional set size or a simultaneous system peak. Plaintext candidate rows sum HTTPJet plus its helper; other rows cover HTTPJet alone.

| Protocol | Fixture | Release RSS | Candidate RSS | Increase |
|---|---|---:|---:|---:|
| H1 plaintext | Static | 45.40 MiB | 63.21 MiB | +17.80 MiB (+39.21%) |
| H1 plaintext | Page cache | 48.94 MiB | 66.84 MiB | +17.90 MiB (+36.58%) |
| H2c plaintext | Static | 45.75 MiB | 63.52 MiB | +17.77 MiB (+38.83%) |
| H2c plaintext | Page cache | 49.75 MiB | 66.76 MiB | +17.01 MiB (+34.19%) |
| H3 | Static | 57.95 MiB | 61.68 MiB | +3.73 MiB (+6.44%) |
| H3 | Page cache | 60.19 MiB | 64.24 MiB | +4.04 MiB (+6.72%) |

The plaintext helper accounts for roughly 12.2–12.4 MiB RSS; web-process RSS also increases. These component medians need not sum to the median total. H1/H2 HTTPS post-client RSS instead decreases in every cycle, by 0.7–8.8% in the overall medians.

RSS sums can double-count shared resident pages and do not account for all kernel/BPF/socket allocations. VmHWM is captured per process, but summing those independent high-water marks does not produce a simultaneous peak. This short, 32-connection fixture does not prove a leak, sustained growth or memory scaling. [Memory groups](../docs/evidence/regression-review-20261031/memory-groups.csv), [all cycles](../docs/evidence/regression-review-20261031/memory-cycles.csv), [per-process snapshots](../docs/evidence/regression-review-20261031/memory-processes.csv).

The H1 HTTPS page-cache client CPU rises 38.620→39.456 µs/response (+2.16%, higher in all three cycles). Whole-VM system and softIRQ medians increase while user CPU falls. The process and VM snapshots are sequential; PMU setup/stop and unrelated work lie in the observation span. Neither differences of medians nor VM-minus-process CPU provide an exact attributable kernel cost. [Client/VM groups](../docs/evidence/regression-review-20261031/client-vm-groups.csv).

A further **diagnostic signal**, not an established server regression: VM-wide TCP retransmissions total 13 in release H2c arms and 140 in candidate H2c arms, across twelve arms per role. Captured TCP timeouts, backlog drops and spurious RTOs are zero. These counters include unrelated traffic and need per-socket attribution. The H3 JSON has no corresponding kernel-counter delta; it is unmeasured, not zero. [Network counters](../docs/evidence/regression-review-20261031/network-counters.csv).

## Stricter native-PGO comparisons remain relevant

These earlier campaigns used fresh source-specific PGO builds. They finished before the forum containers were stopped, so their measurements must not be pooled with the newer release campaign.

| Case and control | Regression beyond p99 | Repeat consistency |
|---|---|---|
| Static H2 HTTPS versus historical-source native PGO | **Server CPU +10.20%; VM CPU +7.43%** | Server CPU and VM CPU higher in all three paired cycles |
| Static H1 plaintext versus historical-source native PGO | **VM CPU +13.41%** | Higher in all three cycles despite server/helper CPU −59.91% |
| Static H2c versus historical-source native PGO | **VM CPU +4.54%** | Higher in all three cycles despite server/helper CPU −55.35% |
| Static H1 HTTPS versus historical-source native PGO | **VM CPU +19.65%**; process CPU +0.50% | Mixed cycles; the small process difference does not establish a stable regression |
| Static H2c kernel on versus off in the same candidate binary | **VM CPU +1.57%** | Higher in all three cycles despite process CPU −57.21% |

[Native HTTPS results](native-tls-followup-2026-10-31.md) and [plaintext/H3 and same-binary H2 results](h2-repaired-pgo-2026-10-31.md) retain complete arm/cycle tables and their build qualifications. Process-CPU reductions can coexist with higher VM work; both must be acceptance measures.

Static H2 HTTPS is the strongest server-CPU regression signal: server user CPU rises 22.22%, while system CPU rises 1.79%. The crypto and TLS source trees match. Native C compiler flags and some compiled native H2 handoff machinery differ, but neither is a proven cause. The next controlled experiment must record effective native compiler arguments/object identities and preserve valid source-specific PGO. [CPU/source investigation](../docs/evidence/native-tls-20261031/cause/FINDINGS.md).

The direct native-H2-future prototype was separately tested and **rejected for promotion**: static scheduled p99 rises 6.39% overall and in every cycle. Process CPU changes −0.93% overall, but worsens 6.02% and 3.57% in two cycles. Lower instruction counts alone did not establish a better engine. Retained ABF remains the control. [Rejection seal](../docs/evidence/regression-review-20261031/rejected-native-future-seal.json), [paired experiment](../docs/evidence/regression-review-20261031/rejected-native-future-TABLE.md).

The Unix send-hook prototype is outside the retained candidate. Its failure/quarantine recovery and pressure/performance behavior remain unqualified; it must pass those gates before replacing the TCP carrier. Functional guest success is not a latency or recovery guarantee.

## Recommended next work on SINGULARITY

1. **Confirm the native-PGO CPU signals under the current quiet host conditions.** Use fresh paired controls for static H2 HTTPS and the plaintext static paths, retaining both caches. Keep exact-release and same-binary mode comparisons distinct. Carry the H1 HTTPS page-cache VM signal into the same focused campaign.
2. **Target static H2 HTTPS user CPU first.** Compare one controlled build or source change at a time, with effective compiler/object records and valid fresh PGO when needed. Require lower server CPU without worse p99, whole-VM CPU or correctness. Keep the rejected native-future build out of promotion.
3. **Attribute work outside the server.** Separately profile kernel/softIRQ and client work in H1 HTTPS page-cache and plaintext kernel cases. Track TCP_INFO on owned client/carrier sockets to test the retransmission signal. Preserve benchmark-client CPU as a separate measure; do not count shifting work to it as a server-only success.
4. **Measure and reduce the memory cost.** Record web/helper PSS, BPF-map and socket memory, and FD occupancy at idle and under load. Use connection-count and worker-count sweeps to separate fixed helper costs from per-connection/per-worker growth. Keep long-soak growth, cache pressure and large-body cases as explicit remaining qualifications.
5. **Recheck H1 static scheduling stability, then qualify the Unix carrier.** Preserve all latency outliers. The Unix path needs bounded failure/closure, pin retirement and capacity recovery under pressure before performance comparisons. Retain the current candidate until those tests pass.

The next decision should use per-request server/helper CPU, whole-VM CPU, client CPU, scheduled p99, PSS/kernel memory, errors and owned cleanup together. Current capped warm-fixture results provide no maximum-capacity or sustained-memory guarantee.

Derived [resource receipt](../docs/evidence/regression-review-20261031/receipt.json) and [analysis source](../docs/evidence/regression-review-20261031/derive.py) bind the memory/client/network findings to the previously sealed release results. This ledger makes no production change and proposes no new release.

Credit to [Laurin Brandner (@lerboe)](https://github.com/lerboe), [Beeper](https://github.com/lerboe/beeper) and [hyper-fast-path](https://github.com/lerboe/hyper-fast-path) for the parsing work informing the H1/H2 experiments. H3 execution changes are HTTPJet work around Quinn.
