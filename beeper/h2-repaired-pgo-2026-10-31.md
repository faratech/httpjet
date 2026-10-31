# Repaired HTTPJet PGO: lower process CPU and tail latency, mixed VM CPU

The repaired build completed all 96 matched-load benchmark arms on SINGULARITY. Against a fresh native PGO rebuild of the historically attributed production source, server/helper CPU per response fell 55–68% for H2c, and scheduled p99 fell 18–29%. Whole-VM CPU improved for page-cache hits and regressed for static H1/H2 traffic. The overall CPU target remains open for those static paths.

These are warm, synthetic **1 KiB** responses at **15,000 requests/s**. H1 and H2c use plaintext connections; H3 uses QUIC/TLS. This study does not establish HTTPS/H2 performance gains, full-site speedups or throughput-capacity multipliers. The proposed Unix send hook is absent from these binaries.

## Production-source comparison

Each row summarizes six baseline and six candidate arms across three ABBA cycles. Percentages compare medians; negative values mean less CPU or lower latency. H1 uses readiness-driven kernel serving, H2c uses kernel serving, and H3 uses the accelerated native engine without a BPF serving helper.

| Protocol | Fixture | Server/helper CPU | Scheduled p99 | Whole-VM busy CPU |
|---|---|---:|---:|---:|
| H1 | Static cache | −59.91% | −18.69% | **+13.41%** |
| H1 | Origin page cache | −67.84% | −21.97% | −20.74% |
| H2c | Static cache | −55.35% | −18.16% | **+4.54%** |
| H2c | Origin page cache | −68.31% | −29.04% | −4.53% |
| H3 | Static cache | −47.35% | −78.06% | −18.78% |
| H3 | Origin page cache | −26.83% | −31.92% | −27.00% |

All 18 production-source fixture/cycle comparisons improved process CPU and scheduled p99. H3 tail gains varied substantially between cycles. H3 page-cache dispatch-lateness p99 rose 3.55%, despite lower service and scheduled p99. Static H1 and H2c VM CPU increased in every cycle. [Per-arm data](../docs/evidence/h2-repaired-pgo-20261031/final/arms.csv), [cycle changes](../docs/evidence/h2-repaired-pgo-20261031/final/cycles-percent.csv).

The baseline is frozen binary `24ccc3a8…`, rebuilt and trained natively on SINGULARITY from C7 source `c07d3457…`. It is **not** a reproduction of deployed binary `994127ae…` with its unknown original profile, exact source cleanliness and CPU target. The candidate is frozen binary `abf7a79c…`, built from combined source `3946cd5e…`, with helper `0e7be72d…` and serving ELF `4bdf891e…`. The reviewed runtime changes are published on the continuation branch through `326f74dc…`; the subsequent benchmark-tool commit changes no serving code.

Both builds use Rust 1.99.1, host-native CPU optimization, frame pointers, thin LTO and profile-guided optimization. Each receives its own runtime training. C7 uses its historical profiling feature and explicit native C/C++ flags; the candidate uses the experimental serving/observer/steering features with CFLAGS unset. The comparison measures their combined source/build behavior, rather than isolating Beeper alone. Both retain static-body caching and enable the origin page cache; each fixture's eligible response path is warmed before measurement. The candidate also enables its finished page-response memo; C7 does not expose that option. H3 uses candidate GSO20/send-batch1. [Build warning and identity review](../docs/evidence/h2-repaired-pgo-20261031/candidate-warning-review.json), [control review](../docs/evidence/h2-repaired-pgo-20261031/production-source-warning-review.json).

## Same-binary H2 mode comparison

The first 24 arms use the exact same `abf7a79c…` application with kernel mode off and on. This separates the mode change from the application build/profile comparison.

| Fixture | Server/helper CPU, native → kernel | Change | Scheduled p99, native → kernel | Change | Whole-VM CPU change |
|---|---:|---:|---:|---:|---:|
| Static cache | 16.538 → 7.077 µs/response | −57.21% | 2177.307 → 1738.265 µs | −20.16% | **+1.57%** |
| Origin page cache | 17.846 → 6.615 µs/response | −62.93% | 2298.709 → 1735.653 µs | −24.49% | −1.07% |

All six fixture/cycle comparisons improved process CPU and scheduled p99. One page-cache cycle increased VM CPU, so its small aggregate decrease is not a consistent per-cycle result. The earlier E9 application with the repaired helper separately recorded process-CPU reductions of 57–59% and p99 reductions of 22–26%, with VM CPU increases of 2–6%. Its compact receipt explicitly records that no separate source before/after snapshot was taken for that earlier direct run. The final 96-arm campaign seals both source/profile inputs and artifacts before and after. [Earlier E9 receipt](../docs/evidence/h2-repaired-pgo-20261031/e9/receipt.json), [final receipt](../docs/evidence/h2-repaired-pgo-20261031/final/receipt.json).

## Correctness and measurement boundaries

The final campaign verified **5,760,000 measured responses** and **480,000 completed warmups**. Independent recomputation checked 6,120,000 raw latency rows: H3 TSVs omit their 120,000 warmup rows and per-row status, so H3 status/body validity and warmup completion are checked through the pinned validating clients and summaries. All eight compiler monitors were clean, all PMU and client-headroom gates passed, and both phases preserved identical source/profile/artifact snapshots. No failed or negative row was dropped.

The load generator has bounded admission: 32 slots for H1 and 128 for H2/H3. Admission waits affected 37 arms, totaling 19,340 waits, chiefly native H3 (16,339). These are not unrestricted open-loop results. Scheduled p99 measures intended arrival through completion; service and dispatch-lateness quantiles remain separate. Reported p99 is the median of six arm p99 values, rather than a pooled request quantile.

Process CPU includes the server and helper user/system time over 65,000 client responses per arm. It excludes kernel or IRQ work charged elsewhere. PMU counts cover user-mode server/helper instructions and cycles. VM busy time includes all Linux CPUs, clients and unrelated work; Windows-host scheduling and activity remain unobserved. One-second compiler sampling cannot exclude sub-interval activity.

Before timing, the repaired application passed all 11 wire/lifecycle/cache gates: H1 late enrollment and H1/H2 UA parity, H2 core, both 70-case certificate corpora, expiry, four owner-lifecycle cases, TLS checks, H3 shutdown, cache isolation and H3 delivery. Independent seals verify 18 cleanup proofs and six H3 drain/STOP/non-ACK cases. C7 separately passed 15 native protocol/fixture cells plus cache-isolation gates. Fresh profile use had zero CFG/hash mismatches; all 633 candidate missing-function warnings were attributed to build tooling or the auxiliary fuzz-library copy. [Candidate seal](../docs/evidence/h2-repaired-pgo-20261031/candidate-qualification-seal.json), [C7 seal](../docs/evidence/h2-repaired-pgo-20261031/production-source-qualification-seal.json).

## Remaining kernel cost

A separate four-arm diagnostic retained all-CPU kernel samples and owned-program runtime counters. Roughly half the non-idle kernel-arm samples included TCP/psock/network frames; the extra deferred socket response path appeared in about 15–16%. Owned BPF appeared in about 5%; poll/readiness stayed below 0.5%. These overlapping stack families are not exclusive CPU shares. The capture contained no sampled iterator-helper frames and too few direct JIT leaves to justify a copy-loop rewrite.

Owned BPF elapsed invocation time was about 3.33 µs/response for static and 3.79 µs for page-cache traffic. It includes helpers and interruptions, excludes subsequent socket dispatch, and must not be added to process CPU. The measured extra socket path is the next research target. A Unix send-side verdict hook is being prepared separately; it has no runtime or performance qualification yet. [Diagnostic ranking](../docs/evidence/h2-repaired-pgo-20261031/kernel-cost-ranking.json).

A separate H3 static-field ownership prototype passed 128 targeted tests. It is absent from `abf7a79c…` and has no measured performance gain. No production deployment, service restart or kernel installation is part of this report.

Credit to [Laurin Brandner (@lerboe)](https://github.com/lerboe), [Beeper](https://github.com/lerboe/beeper) and [hyper-fast-path](https://github.com/lerboe/hyper-fast-path). Beeper informs the H1/H2 parsing work; the H3 engine changes are HTTPJet work around Quinn.
