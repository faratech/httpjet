# PGO Candidate C against the exact release: complete capacity matrix

Measured and published **31 October 2026**.

Across-arm median throughput rises in 20/20 cells and falls in 0/20. Median arm p99 rises in 2/20 cells; measured process CPU per response rises in 0/20. These direction counts do not establish an overall winner. Every cell and opposite-sign cycle is retained below.

This compares the exact shipped **v0.1.10-11** with the PGO Candidate C binary. Both arms enable and warm their caches; the release cache is active. Candidate changes include the finished page-response memo, PGO, H1/H2 kernel paths and the accelerated H3 engine with GSO limit 20/send batch 1. These are combined build/runtime effects and cannot all be attributed to Beeper. The [previous C matrix](final-matrix-2026-10-30.md) retains source-control comparisons; the [same-source PGO pilot](pgo-pilot-2026-10-30.md) isolates PGO on the C runtime. There is no matched release-source PGO control here, and pilot percentages are not additive components of these deltas.

## Artifact identity

| Artifact | SHA256 |
|---|---|
| release | `3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec` |
| candidate | `0ca04dcb8d3b9d07e02ac19658546d7882d6f2719c6937be2f259ca65eef83c5` |
| helper | `1cce1f3ca5837e5d68b9be757438af28a88be789468372392bf6148a3987721d` |

The helper is the PGO-built privileged `httpjet-beeper-h1` launcher for plaintext kernel arms. The candidate enables H1 polling and H2 kernel serving only on plaintext paths, with the default 16 KiB body cap. The 32 KiB requested-kernel cases serve natively; oversized H2 publication candidates must remain zero. TLS retains native ownership. H3 remains Quinn-owned userspace QUIC/TLS, not in-kernel QUIC.

## All twenty cells

Values are medians of six arms per binary: **release → candidate (Δ)**, with `Δ = 100 × (candidate/release − 1)`. Positive p99/CPU/count deltas mean higher latency/cost. The p99 is a median of arm percentiles, not a percentile recomputed from merged requests. Kernel percentages show the six-arm median [minimum, maximum] over measured plus warm-up responses. A missing release counter is labeled `not exposed`, not measured zero.

### 1 KiB / static

| Protocol | RPS (Δ) | Arm p99 ms (Δ) | Kernel-hit fraction release → candidate |
|---|---|---|---|
| H1 plaintext | 66,498 → 134,381 (+102.08%) | 0.965 → 0.823 (-14.75%) | not exposed → 99.9824% [99.9805%, 99.9833%] |
| H1 TLS | 64,912 → 91,476 (+40.92%) | 1.011 → 0.705 (-30.30%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H2c | 113,983 → 180,724 (+58.55%) | 2.398 → 4.837 (+101.70%) | not exposed → 84.9838% [82.8295%, 88.6805%] |
| H2 TLS | 69,683 → 100,774 (+44.62%) | 4.073 → 3.256 (-20.05%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H3 | 15,392 → 50,961 (+231.09%) | 15.878 → 5.552 (-65.04%) | n/a (QUIC in userspace) |

| Protocol | Process CPU µs/R (Δ) | User instructions/R (Δ) | User cycles/R (Δ) | VM busy ticks/R (Δ) |
|---|---|---|---|---|
| H1 plaintext | 14.952 → 1.667 (-88.85%) | 27,564 → 3,422 (-87.59%) | 30,809 → 3,171 (-89.71%) | 0.004926 → 0.004438 (-9.91%) |
| H1 TLS | 15.405 → 10.929 (-29.06%) | 36,783 → 28,305 (-23.05%) | 38,253 → 21,163 (-44.68%) | 0.005140 → 0.004236 (-17.60%) |
| H2c | 8.690 → 4.952 (-43.01%) | 32,290 → 8,206 (-74.59%) | 26,487 → 7,083 (-73.26%) | 0.003048 → 0.003438 (+12.81%) |
| H2 TLS | 14.381 → 9.952 (-30.79%) | 36,970 → 26,995 (-26.98%) | 38,848 → 23,784 (-38.78%) | 0.005564 → 0.004598 (-17.37%) |
| H3 | 65.095 → 19.667 (-69.79%) | 128,847 → 44,572 (-65.41%) | 174,013 → 61,940 (-64.40%) | 0.015888 → 0.008721 (-45.11%) |

### 1 KiB / pagecache

| Protocol | RPS (Δ) | Arm p99 ms (Δ) | Kernel-hit fraction release → candidate |
|---|---|---|---|
| H1 plaintext | 42,271 → 135,965 (+221.65%) | 1.481 → 0.848 (-42.74%) | not exposed → 99.8902% [99.8538%, 99.9152%] |
| H1 TLS | 35,515 → 76,970 (+116.73%) | 1.889 → 1.034 (-45.24%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H2c | 55,105 → 180,144 (+226.91%) | 4.781 → 4.934 (+3.20%) | not exposed → 84.9638% [36.6943%, 89.2324%] |
| H2 TLS | 37,811 → 89,684 (+137.19%) | 6.445 → 3.642 (-43.50%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H3 | 20,350 → 43,626 (+114.38%) | 13.340 → 6.469 (-51.50%) | n/a (QUIC in userspace) |

| Protocol | Process CPU µs/R (Δ) | User instructions/R (Δ) | User cycles/R (Δ) | VM busy ticks/R (Δ) |
|---|---|---|---|---|
| H1 plaintext | 23.714 → 1.643 (-93.07%) | 62,057 → 3,451 (-94.44%) | 70,553 → 3,223 (-95.43%) | 0.006638 → 0.004467 (-32.71%) |
| H1 TLS | 28.024 → 12.810 (-54.29%) | 72,261 → 29,494 (-59.18%) | 90,290 → 24,903 (-72.42%) | 0.007645 → 0.004619 (-39.58%) |
| H2c | 18.238 → 5.000 (-72.58%) | 67,472 → 8,390 (-87.56%) | 66,890 → 7,593 (-88.65%) | 0.005000 → 0.003505 (-29.90%) |
| H2 TLS | 26.476 → 11.214 (-57.64%) | 72,906 → 28,187 (-61.34%) | 85,695 → 27,111 (-68.36%) | 0.008386 → 0.005060 (-39.66%) |
| H3 | 49.119 → 23.286 (-52.59%) | 122,220 → 46,919 (-61.61%) | 154,919 → 71,702 (-53.72%) | 0.013419 → 0.010014 (-25.37%) |

### 32 KiB / static

| Protocol | RPS (Δ) | Arm p99 ms (Δ) | Kernel-hit fraction release → candidate |
|---|---|---|---|
| H1 plaintext | 53,994 → 57,014 (+5.59%) | 1.214 → 1.211 (-0.26%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H1 TLS | 22,516 → 26,523 (+17.79%) | 3.135 → 3.091 (-1.42%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H2c | 60,589 → 68,185 (+12.54%) | 4.868 → 4.595 (-5.60%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H2 TLS | 25,544 → 27,804 (+8.85%) | 9.093 → 8.782 (-3.42%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H3 | 8,712 → 19,948 (+128.96%) | 24.555 → 11.428 (-53.46%) | n/a (QUIC in userspace) |

| Protocol | Process CPU µs/R (Δ) | User instructions/R (Δ) | User cycles/R (Δ) | VM busy ticks/R (Δ) |
|---|---|---|---|---|
| H1 plaintext | 18.643 → 17.476 (-6.26%) | 27,630 → 23,565 (-14.71%) | 30,251 → 22,453 (-25.78%) | 0.005940 → 0.005960 (+0.32%) |
| H1 TLS | 45.119 → 38.952 (-13.67%) | 110,414 → 102,175 (-7.46%) | 107,285 → 83,053 (-22.59%) | 0.011719 → 0.011988 (+2.30%) |
| H2c | 16.476 → 14.643 (-11.13%) | 32,851 → 24,942 (-24.08%) | 29,129 → 20,110 (-30.96%) | 0.007060 → 0.006774 (-4.05%) |
| H2 TLS | 39.143 → 35.952 (-8.15%) | 113,618 → 103,223 (-9.15%) | 83,161 → 67,390 (-18.96%) | 0.014267 → 0.013790 (-3.34%) |
| H3 | 114.619 → 50.119 (-56.27%) | 331,650 → 219,607 (-33.78%) | 311,403 → 145,353 (-53.32%) | 0.034821 → 0.020755 (-40.40%) |

### 32 KiB / pagecache

| Protocol | RPS (Δ) | Arm p99 ms (Δ) | Kernel-hit fraction release → candidate |
|---|---|---|---|
| H1 plaintext | 32,843 → 60,465 (+84.10%) | 2.521 → 0.996 (-60.48%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H1 TLS | 14,942 → 30,084 (+101.33%) | 4.900 → 1.957 (-60.06%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H2c | 42,295 → 70,029 (+65.57%) | 5.901 → 4.467 (-24.30%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H2 TLS | 19,337 → 28,164 (+45.65%) | 12.294 → 8.449 (-31.28%) | not exposed → 0.0000% [0.0000%, 0.0000%] |
| H3 | 9,479 → 19,726 (+108.09%) | 27.280 → 11.685 (-57.17%) | n/a (QUIC in userspace) |

| Protocol | Process CPU µs/R (Δ) | User instructions/R (Δ) | User cycles/R (Δ) | VM busy ticks/R (Δ) |
|---|---|---|---|---|
| H1 plaintext | 30.643 → 16.595 (-45.84%) | 62,167 → 24,263 (-60.97%) | 75,063 → 21,383 (-71.51%) | 0.008240 → 0.005764 (-30.05%) |
| H1 TLS | 66.881 → 33.500 (-49.91%) | 145,787 → 103,227 (-29.19%) | 170,047 → 72,240 (-57.52%) | 0.013807 → 0.010657 (-22.81%) |
| H2c | 23.619 → 14.190 (-39.92%) | 68,261 → 26,098 (-61.77%) | 62,408 → 19,658 (-68.50%) | 0.007924 → 0.006531 (-17.58%) |
| H2 TLS | 51.857 → 35.548 (-31.45%) | 149,467 → 104,314 (-30.21%) | 134,208 → 67,339 (-49.82%) | 0.016579 → 0.013769 (-16.95%) |
| H3 | 105.476 → 50.690 (-51.94%) | 324,637 → 221,061 (-31.91%) | 298,368 → 147,622 (-50.52%) | 0.032957 → 0.020681 (-37.25%) |

## Three ABBA cycles

A = release; B = candidate. Each entry is the ratio-of-two-arm-medians RPS delta, followed by `[min(B)/max(A) − 1, max(B)/min(A) − 1]`. These bounds describe observed arm spread, not confidence intervals.

| Cell | Cycle 1 RPS Δ [range] | Cycle 2 RPS Δ [range] | Cycle 3 RPS Δ [range] |
|---|---|---|---|
| 1 KiB H1 plaintext / static | +106.51% [+104.61%, +108.43%] | +99.82% [+84.75%, +115.56%] | +89.66% [+69.24%, +110.41%] |
| 1 KiB H1 TLS / static | +25.36% [+8.47%, +43.37%] | +45.04% [+35.63%, +54.86%] | +40.19% [+36.62%, +43.82%] |
| 1 KiB H2c / static | +65.74% [+49.22%, +82.99%] | +60.19% [+49.74%, +72.03%] | +46.86% [+45.14%, +48.60%] |
| 1 KiB H2 TLS / static | +43.02% [+40.71%, +45.35%] | +46.00% [+31.60%, +61.43%] | +43.81% [+41.52%, +46.12%] |
| 1 KiB H3 / static | +235.32% [+223.19%, +247.52%] | +189.00% [+148.58%, +230.91%] | +266.36% [+234.81%, +298.94%] |
| 1 KiB H1 plaintext / pagecache | +228.71% [+186.98%, +274.58%] | +249.24% [+222.21%, +278.48%] | +206.50% [+192.25%, +221.08%] |
| 1 KiB H1 TLS / pagecache | +120.57% [+99.42%, +144.59%] | +100.43% [+84.47%, +119.00%] | +107.86% [+76.03%, +147.02%] |
| 1 KiB H2c / pagecache | +261.65% [+225.00%, +306.29%] | +235.12% [+210.78%, +260.33%] | +157.71% [-37.91%, +594.63%] |
| 1 KiB H2 TLS / pagecache | +122.14% [+102.43%, +143.00%] | +161.00% [+148.94%, +173.73%] | +134.63% [+130.46%, +138.90%] |
| 1 KiB H3 / pagecache | +102.96% [+59.47%, +159.92%] | +107.09% [+75.66%, +139.97%] | +128.01% [+108.62%, +149.96%] |
| 32 KiB H1 plaintext / static | -1.93% [-16.26%, +14.62%] | +9.78% [-1.78%, +22.40%] | +5.79% [-3.64%, +15.80%] |
| 32 KiB H1 TLS / static | +26.37% [+15.72%, +38.23%] | +6.57% [-9.62%, +24.82%] | -18.81% [-71.36%, +49.63%] |
| 32 KiB H2c / static | +10.11% [+7.55%, +12.78%] | +19.66% [+5.58%, +37.15%] | +19.30% [+12.77%, +26.31%] |
| 32 KiB H2 TLS / static | +8.55% [+2.32%, +15.12%] | +6.78% [+4.66%, +8.90%] | +12.34% [+5.17%, +20.30%] |
| 32 KiB H3 / static | +178.77% [+138.75%, +234.41%] | +125.56% [+115.11%, +136.20%] | +110.54% [+105.87%, +115.39%] |
| 32 KiB H1 plaintext / pagecache | +92.17% [+79.50%, +105.40%] | +73.39% [+52.00%, +95.75%] | +80.81% [+68.47%, +93.92%] |
| 32 KiB H1 TLS / pagecache | +117.44% [+90.52%, +147.24%] | +95.48% [+88.19%, +103.02%] | +98.07% [+91.42%, +105.01%] |
| 32 KiB H2c / pagecache | +60.64% [+56.76%, +64.58%] | +59.86% [+52.90%, +66.95%] | +70.58% [+67.82%, +73.38%] |
| 32 KiB H2 TLS / pagecache | +41.11% [+28.59%, +55.70%] | +33.49% [+25.71%, +42.28%] | +49.88% [+38.77%, +61.85%] |
| 32 KiB H3 / pagecache | +98.23% [+74.77%, +124.67%] | +109.12% [+103.63%, +114.69%] | +105.55% [+67.64%, +150.73%] |

### Opposite-sign cycles

Every metric whose cycle direction opposes its across-arm median direction appears here. Positive aggregate deltas do not imply that every arm or cycle improved.

| Cell | Metric | Across-arm Δ | Cycle 1 Δ | Cycle 2 Δ | Cycle 3 Δ |
|---|---|---|---|---|---|
| 1 KiB H1 TLS / static | Arm p99 ms | -30.30% | +0.76% | -42.48% | -30.30% |
| 1 KiB H2c / pagecache | Arm p99 ms | +3.20% | -17.57% | -7.30% | +45.94% |
| 32 KiB H1 plaintext / static | RPS | +5.59% | -1.93% | +9.78% | +5.79% |
| 32 KiB H1 plaintext / static | Arm p99 ms | -0.26% | +68.84% | -2.97% | -9.17% |
| 32 KiB H1 plaintext / static | Process CPU µs/R | -6.26% | +1.29% | -8.74% | -5.87% |
| 32 KiB H1 plaintext / static | VM busy ticks/R | +0.32% | +8.03% | -4.64% | -1.87% |
| 32 KiB H1 TLS / static | RPS | +17.79% | +26.37% | +6.57% | -18.81% |
| 32 KiB H1 TLS / static | Arm p99 ms | -1.42% | -19.44% | +50.74% | +312.93% |
| 32 KiB H1 TLS / static | Process CPU µs/R | -13.67% | -21.45% | -7.20% | +81.11% |
| 32 KiB H1 TLS / static | VM busy ticks/R | +2.30% | -10.46% | +8.11% | +28.63% |
| 32 KiB H2c / static | Arm p99 ms | -5.60% | +0.77% | -17.28% | -17.19% |

## Measurement scope and limits

The sealed matrix contains **20 cells, 240 arms, 48,000,000 measured responses and 2,400,000 warm-up responses**: three A–B–B–A cycles, each arm containing 200,000 measured requests after 10,000 warm-up requests. Both server destination and client source bind are literal `127.0.0.2` on SINGULARITY Linux/WSL2. One server worker uses CPU 8; six clients use separate physical cores `0,2,4,6,12,14`. There are 32 connections; H2/H3 use four streams per connection and H1 is sequential per connection. This is per-worker true-loopback capacity.

- **RPS/p99:** measured requests only at fixed concurrency. This is saturation/completion latency, not scheduled offered-load latency. A capacity change can alter the load experienced by each arm.
- **Process CPU:** observed server/descendant user + system CPU over the whole client span, including handshake, warm-up, output and teardown, divided by 210,000 responses. Kernel/IRQ work charged elsewhere is excluded.
- **PMU instructions/cycles:** server user mode only over that whole span and the same denominator; kernel, IRQ, softirq and hypervisor work are excluded. These are not total CPU costs.
- **VM busy ticks:** all Linux VM CPUs' user + nice + system + IRQ + softirq ticks per whole-span response, including clients and unrelated work; idle/iowait/steal are excluded. No tick-to-time conversion is inferred. Windows-host CPU/scheduling cost is unmeasured. VM busy is not server-owned CPU.
- Both warm static-cache and origin-page-cache fixtures are shown. Page-cache content is generated static content with PHP disabled; this does not qualify dynamic applications or production-site performance. Neither throughput, process CPU nor VM busy alone establishes total-server CPU savings.

## Evidence and regeneration

The [raw summary](../docs/evidence/pgo-release-20261031/capacity-summary.json) retains every arm, command, scope and cycle ratio. The [integrity receipt](../docs/evidence/pgo-release-20261031/integrity.json) seals completion, unchanged artifacts and absence of owned benchmark processes. Summary SHA256: `eb948cbf34f675472149d80543ea10a73c17b7f4f54408508764d6b88d13a034`. The [arm CSV](../docs/evidence/pgo-release-20261031/arms.csv) retains all 240 rows. The [standalone renderer](../docs/evidence/pgo-release-20261031/render-report.py) requires the sealed complete matrix, exact binaries/helper and recomputed displayed arithmetic.

```sh
python3 docs/evidence/pgo-release-20261031/render-report.py
```

The H1/H2 research builds on [Beeper](https://github.com/lerboe/beeper) and [hyper-fast-path](https://github.com/lerboe/hyper-fast-path) by [Laurin Brandner (@lerboe)](https://github.com/lerboe). H3 execution changes are HTTPJet work around Quinn.
