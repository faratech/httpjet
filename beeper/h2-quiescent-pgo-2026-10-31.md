# H2 ownership with fresh PGO: remaining VM cost

Measured **31 October 2026**, on SINGULARITY only.

The ownership and pin-limit fixes reduce **server/helper process CPU and p99
versus both native PGO controls**, and capacity p99 versus the exact release.
However, **whole-VM busy CPU rises at 15,000 requests/s**, especially for page-cache
traffic. The CPU goal continues; an overall CPU win is unproven.

The [interim investigation](h2-quiescent-owner-2026-10-31.md) explains the
never-polled receive fence, non-consuming readiness and bounded H2 image-pin
limit. Reviewed integration: **`96ddc5d6`**; [component source binding](../docs/evidence/h2-quiescent-pgo-20261031/source-binding.json). Frozen fresh-PGO server/helper SHA256
prefixes: **`e9be9eca3c2f…` / `b9b924c3eb6c…`**. Profile use reported zero
CFG/profile-hash mismatches. The [847 missing-function warnings](../docs/evidence/h2-quiescent-pgo-20261031/profile-use-warnings.json)
remain visible, principally build utilities/untrained auxiliaries, plus six
tooling-library instances. Exact combined PGO artifacts passed all ten
[qualification steps](../docs/evidence/h2-quiescent-pgo-20261031/qualification.json);
source formatting checks passed.

## Fresh native PGO → fresh kernel PGO

Six-arm medians; CPU: µs/response; p99: ms. VM busy includes clients/unrelated work.

| Capacity / fixture | RPS | p99 | Process CPU | VM busy CPU |
|---|---:|---:|---:|---:|
| Static | 96,680 → 183,180 | 5.421 → 4.045 | 10.17 → 2.76 | 38.90 → 38.10 |
| Page cache | 94,792 → 168,182 | 5.290 → 4.142 | 10.50 → 3.05 | 40.24 → 40.31 |

| 15k/s / fixture | Scheduled p99 | Service p99 | Process CPU | VM busy CPU |
|---|---:|---:|---:|---:|
| Static | 4.453 → 1.999 | 2.387 → 0.458 | 22.85 → 9.31 | 102.77 → 105.00 |
| Page cache | 2.617 → 2.019 | 1.034 → 0.490 | 22.69 → 9.31 | 93.92 → 110.15 |

At 15k/s, VM busy rises **2.17% / 17.28%** against fresh native PGO. Scheduled,
service and dispatch-lateness quantiles are separate; never add them. Achieved
rates near 15k/s establish delivery at that offered rate, not capacity gains.

## Interleaved prior-native and release controls

Kernel values belong to their respective matched pairs. Raw names
`old-kernel` and `release-kernel` both run the **fresh kernel implementation**.
Prior native is `0ca04dcb…`; release is exact `v0.1.10-11`, `3b1ecbe1…`.

| Study / fixture / control | p99 ms, control → kernel | Process µs/R | VM µs/R |
|---|---:|---:|---:|
| Capacity / static / prior native | 5.402 → 3.937 | 10.36 → 2.83 | 41.05 → 36.48 |
| Capacity / page / prior native | 5.397 → 4.049 | 10.33 → 3.07 | 41.67 → 40.43 |
| Capacity / static / release | 5.862 → 3.906 | 13.19 → 2.71 | 45.29 → 37.83 |
| Capacity / page / release | 7.574 → 4.385 | 23.24 → 3.10 | 63.17 → 41.48 |
| 15k/s / static / prior native | 2.644 → 1.940 | 21.69 → 9.08 | 93.08 → 100.54 |
| 15k/s / page / prior native | 2.586 → 2.031 | 22.08 → 9.15 | 90.23 → 100.31 |

Process CPU and p99 improve in every cycle. All opposite-sign cycles appear
below; VM ticks/time describe one quantity. These are not confidence intervals.

| Study / fixture / control / metric | Across-arm Δ | Opposite cycle Δ |
|---|---:|---|
| Capacity / static / prior / VM | −11.14% | C3 +4.15% |
| Capacity / page / fresh / VM | +0.18% | C1 −2.91%; C3 −4.08% |
| Capacity / page / prior / VM | −2.97% | C3 +4.12% |
| 15k / static / fresh / RPS | −0.0030% | C1 +0.0052%; C3 +0.0002% |
| 15k / static / fresh / VM | +2.17% | C3 −8.49% |
| 15k / static / prior / RPS | +0.0122% | C2 −0.0035% |
| 15k / static / prior / VM | +8.02% | C3 −4.97% |
| 15k / page / fresh / RPS | +0.0019% | C2 −0.0091%; C3 −0.0034% |
| 15k / page / prior / RPS | −0.0095% | C2 +0.0030%; C3 +0.0115% |

## Scope and evidence

Three ABBA cycles per pair/fixture produced **72 capacity arms, 14.4M measured
+720k warmups**, and **48 paced arms, 2.88M measured +240k warmups**. All bodies
and statuses validated. Caches were enabled and warmed: 1 KiB H2c, 32 connections,
four streams, worker CPU8, observer CPU10, clients `0,2,4,6,12,14`; both ends
bound `127.0.0.2` over Linux loopback. No compiler overlap was observed.

Paced admission is bounded at128: **7 native arms reached the cap, with 2,496
waits**; kernel arms recorded neither. Failed/expired requests were zero.
Percentiles are per-arm, not pooled. Process CPU includes server and helper
user+system over the client span, divided by requests+warmup; user PMU excludes
kernel work. Kernel/IRQ work charged elsewhere, whole-VM activity and unmeasured
Windows-host CPU prevent total CPU savings claims. Controls were interleaved
on boot `07a57341…`; historical absolutes across the outage/reboot are not fair
direct comparisons.

Evidence: [capacity](../docs/evidence/h2-quiescent-pgo-20261031/capacity-summary.json),
[paced load](../docs/evidence/h2-quiescent-pgo-20261031/rate-summary.json),
[all 120 arms](../docs/evidence/h2-quiescent-pgo-20261031/arms.csv), and
[independent audit](../docs/evidence/h2-quiescent-pgo-20261031/independent-audit.json).
The separate certificate experiment is outside this result.

Research builds on [Beeper](https://github.com/lerboe/beeper) and
[hyper-fast-path](https://github.com/lerboe/hyper-fast-path) by
[Laurin Brandner (@lerboe)](https://github.com/lerboe).
