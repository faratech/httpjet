# Measurements and negative results

These are research results from the SINGULARITY lab, recorded on 2026-10-29. They
use generated content and isolated loopback fixtures. They do not establish a
general performance improvement over a shipped HTTPJet release. Earlier **v3**
measurements are historical checkpoints; **v5** includes later correctness and
scheduling changes. The final v5 saturation and matched offered-load matrices
are included below; their gains remain conditional and their losses are retained.

## Comparators and artifact identity

**B**, except in tables explicitly labeled exact shipped, means the original
runtime-source baseline rebuilt with native profile-guided
optimization (PGO). Its runtime source matches released
[v0.1.10-11](https://github.com/faratech/httpjet/releases/tag/v0.1.10-11), public
source commit `5ea8675352231d3e5d4788e60b0b7a05b3777ff9`. **B is not the exact
shipped static archive binary.** Native PGO comparisons and tests of the shipped
artifact are separate evidence classes.

**L** means the experimental binary using bridged application dispatch. **A**
means that same binary trying the shared on-core cache path before bridge
fallback. L includes unconditional experimental transport changes; it is not a
synonym for the original baseline.

| Artifact | Source identity / qualification | Binary SHA-256 |
|---|---|---|
| v3 B | Runtime-source equivalent to the release commit above; native PGO | `eab5f6e541694951bb519b9fdd9ece003986cf7180a8c8c746d412085421b972` |
| v3 L and A | Experimental checkpoint `edc73bba36998f8ddd5a6f35e3daafb98787197f`; native PGO | `5eb5007538a2b4d7e9945e7cf26c0f8196c8aece3a5fcb8b68d37dfb9b8c5e6e` |
| v3 H3 client | Independently implemented validating client; frozen measurement build | `8019560a4f4d9106d14a67365bb79e26c6633b1b22a8013128faa73ec43fde76` |
| v3 CID-steering launcher | Experimental helper; separately built from the server | `ed5505ffb403e04eb68dcff260674424bffb345aab74a8a2da1014f4dfcac360` |
| v5 matched-native B | Runtime-source equivalent to the release commit above; matched native PGO | `b2712264638f67c2e8e52d158b3d074bd72e107247efd4b8eb49ba6f7645db04` |
| v5 L and A | Experimental serving checkpoint `8bfc217150b69684d42f38182117c887b46c8651`; matched native PGO | `4a4dcd18caf297549ab839a529d80f2b23bc86e20d0095a1fa21d01b6156e210` |
| v5 H3 client | Failure-reporting revision of the validating client | `7ec8199c486dc10044b4c25760f14ad83506bab8ba067b7d20579e0f54c98fe2` |
| Exact shipped amd64 release binary | Extracted from the v0.1.10-11 static archive; B only in tables labeled exact shipped | `3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec` |

The v3 and v5 server builds used the same compiler identity, release profile,
native code generation, frame pointers and optional steering feature. Each used
its own compatible PGO data. The v5 matched profile covers successful 1 KiB and
32 KiB cache workloads plus 32 KiB Range requests; large-transfer profiles were
excluded from both baseline and candidate after baseline qualification failed.
Both candidate build logs recorded zero control-flow-profile hash mismatches.
A compatible build does not make different source/profile checkpoints an
isolated performance comparison.

## H3 measurement method

The H3 timing arms use verified TLS, identity encoding, persistent connections
and full status/body validation. There are no automatic reconnects or retries.
Caches are enabled in both baseline and candidate. Cached static content and
origin page-cache hits are separate fixtures; the static-cache baseline must
not be described as cache-disabled. Accelerated static hits can additionally
use the existing finished-response memo where eligible.

The retained arms use independent client UDP sockets, 32 connections and four
concurrent streams per connection, with separated client/server CPU affinity.
Warmup and handshakes precede the measured phase. Full byte verification and
client scheduling remain inside measurement. Each client socket requested
4 MiB receive and send buffers; the kernel reported 8 MiB for each. Those are
buffer capacities, not measured resident-memory consumption.

Rates below are successful complete responses per second. Latencies use
nearest-rank percentiles for completed requests, in milliseconds. This is a
fixed-concurrency saturation workload; latency excludes requests not yet
admitted by a worker. It is not an open-loop offered-rate latency benchmark.
Repeated arms remain separate so drift is visible. Figures are rounded to two
decimal places for rates and three for latency; original evidence retains more
precision.

## Historical v3 cache matrix

The order within each fixture is B, L, A, A, L, B. Steering is off throughout.
Each 1 KiB arm validates 500,000 measured responses; each 32 KiB arm validates
100,000. Every arm below completed its requested count with zero response errors
and zero observed client-socket receive drops.

### 1 KiB: cached static

| Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | B | 27,212.27 | 4.462 | 11.833 |
| 2 | L | 29,555.10 | 4.159 | 10.056 |
| 3 | A | 40,334.29 | 2.928 | 8.314 |
| 4 | A | 47,294.50 | 2.637 | 5.456 |
| 5 | L | 27,907.06 | 4.414 | 10.756 |
| 6 | B | 28,542.05 | 4.291 | 10.761 |

### 1 KiB: origin page cache

| Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | B | 36,892.29 | 3.303 | 7.565 |
| 2 | L | 33,993.12 | 3.566 | 8.352 |
| 3 | A | 39,502.55 | 3.129 | 6.919 |
| 4 | A | 36,732.03 | 3.350 | 7.245 |
| 5 | L | 33,109.17 | 3.685 | 8.441 |
| 6 | B | 29,132.02 | 3.938 | 12.548 |

### 32 KiB: cached static

| Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | B | 7,432.45 | 16.391 | 37.224 |
| 2 | L | 7,137.88 | 17.187 | 38.939 |
| 3 | A | 7,591.09 | 16.303 | 43.977 |
| 4 | A | 8,541.74 | 15.067 | 29.973 |
| 5 | L | 7,222.16 | 17.254 | 35.636 |
| 6 | B | 7,446.41 | 16.894 | 33.129 |

### 32 KiB: origin page cache

| Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | B | 6,155.16 | 19.618 | 48.512 |
| 2 | L | 7,615.69 | 16.526 | 35.399 |
| 3 | A | 8,320.14 | 15.594 | 28.277 |
| 4 | A | 8,329.33 | 15.514 | 28.399 |
| 5 | L | 7,704.39 | 15.860 | 36.639 |
| 6 | B | 7,768.36 | 16.183 | 33.234 |

The strongest v3 observation is the 1 KiB static case: A's two rates are above
both B rates, with lower p99 in both accelerated arms. The median rate difference
is approximately 57%. That number describes this historical hot-cache fixture;
it is not a general release-speedup claim. The other fixtures show substantial
drift or overlapping ranges. In particular, one accelerated 32 KiB static arm
has a higher p99 than either original-baseline arm.

## Historical v3 bridge-only Range control

These are full-body 32 KiB **206** responses. All four arms validate 100,000
responses each, with zero on-core selections, zero response errors and zero
observed client-socket drops. They deliberately exercise bridge fallback.

| Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | L | 7,726.92 | 15.903 | 34.620 |
| 2 | A | 7,674.63 | 14.972 | 51.191 |
| 3 | A | 7,763.31 | 14.878 | 47.962 |
| 4 | L | 7,971.31 | 15.475 | 34.400 |

This checkpoint exposed a tail-latency regression: A had approximately
48–51 ms p99 versus approximately 34 ms for L, despite similar throughput.
That regression remained part of the evidence and motivated later scheduling
work.

## Historical v3 steering controls

### Dispatch comparison with steering enabled in both modes

Steering is on for **every** row in these two tables. Each arm validates 100,000
responses. These rows compare L and A while steering is enabled; they cannot
establish a benefit from enabling BPF steering.

### Cached static, 32 KiB

| Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | L | 7,283.05 | 16.688 | 40.052 |
| 2 | A | 8,651.60 | 14.753 | 29.745 |
| 3 | A | 8,560.55 | 14.210 | 36.321 |
| 4 | L | 8,322.67 | 14.801 | 32.407 |

### Origin page cache, 32 KiB

| Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | L | 8,314.65 | 15.022 | 31.533 |
| 2 | A | 9,112.94 | 13.987 | 26.750 |
| 3 | A | 8,868.74 | 14.347 | 27.816 |
| 4 | L | 7,753.86 | 16.029 | 34.165 |

### Separate steering off/on control

The application mode is A throughout. Each arm validates 50,000 responses per
fixture, in off, on, on, off order. These are the separate steering-cost controls,
not the dispatch comparison above.

### Cached static, 32 KiB

| Arm | CID steering | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | off | 9,316.28 | 13.613 | 28.673 |
| 2 | on | 9,301.15 | 13.539 | 29.041 |
| 3 | on | 7,465.28 | 16.596 | 42.133 |
| 4 | off | 8,738.81 | 14.822 | 27.108 |

### Origin page cache, 32 KiB

| Arm | CID steering | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | off | 9,252.58 | 13.176 | 28.482 |
| 2 | on | 9,188.70 | 13.824 | 26.417 |
| 3 | on | 8,925.49 | 14.324 | 27.359 |
| 4 | off | 8,625.73 | 14.319 | 34.236 |

All steering-control arms completed their counts with zero response errors and
zero observed client-socket drops. Their rates vary enough that they do not
establish a repeatable BPF throughput gain. Across all 44 retained v3 timing
arms above, 8,800,000 measured responses were validated; warmup and separate
correctness probes are additional work.

## Final v5 cache matrices

These 48 arms validate 14,400,000 measured status-200 responses, with zero
response errors and zero observed client UDP receive drops. Both server workers
were active in every arm; all server exit records were zero and post-run body
buffer gauges returned to zero. Steering is off. Caches are enabled equally.

Within each fixture the order is B, L, A, A, L, B. Each 1 KiB arm has 500,000
measured requests and 10,000 warmup requests; each 32 KiB arm has 100,000 and
5,000 respectively. The tables preserve individual arms rather than averaging
away drift. The first two matrices use the matched native-PGO baseline. The
other two use the exact shipped executable: that comparison also includes
compiler, code-generation and profile differences.

### Matched native PGO: 1 KiB

| Fixture | Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---|---:|---|---:|---:|---:|
| static | 1 | B | 23,239.54 | 5.067 | 15.449 |
| static | 2 | L | 24,644.98 | 4.890 | 13.049 |
| static | 3 | A | 38,658.21 | 3.064 | 8.583 |
| static | 4 | A | 30,610.55 | 3.539 | 16.703 |
| static | 5 | L | 21,896.71 | 5.525 | 14.238 |
| static | 6 | B | 21,541.45 | 5.533 | 15.369 |
| pagecache | 1 | B | 14,173.46 | 5.309 | 63.987 |
| pagecache | 2 | L | 24,233.05 | 4.725 | 15.766 |
| pagecache | 3 | A | 37,840.50 | 3.297 | 6.638 |
| pagecache | 4 | A | 33,224.99 | 3.478 | 10.752 |
| pagecache | 5 | L | 22,332.46 | 4.696 | 24.172 |
| pagecache | 6 | B | 21,332.08 | 4.990 | 23.574 |

### Matched native PGO: 32 KiB

| Fixture | Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---|---:|---|---:|---:|---:|
| static | 1 | B | 5,118.55 | 22.697 | 68.805 |
| static | 2 | L | 5,129.54 | 22.660 | 73.329 |
| static | 3 | A | 5,793.30 | 18.485 | 82.866 |
| static | 4 | A | 6,154.56 | 18.897 | 62.532 |
| static | 5 | L | 5,562.22 | 21.065 | 61.985 |
| static | 6 | B | 5,462.50 | 21.659 | 58.507 |
| pagecache | 1 | B | 6,209.89 | 19.598 | 46.647 |
| pagecache | 2 | L | 5,751.84 | 20.079 | 60.526 |
| pagecache | 3 | A | 6,296.32 | 18.513 | 57.233 |
| pagecache | 4 | A | 6,781.17 | 18.438 | 41.733 |
| pagecache | 5 | L | 6,464.59 | 18.926 | 45.873 |
| pagecache | 6 | B | 5,599.97 | 20.982 | 62.275 |

### Exact shipped baseline: 1 KiB

| Fixture | Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---|---:|---|---:|---:|---:|
| static | 1 | B | 13,774.51 | 7.843 | 37.587 |
| static | 2 | L | 21,703.03 | 5.534 | 14.381 |
| static | 3 | A | 38,949.74 | 3.141 | 7.447 |
| static | 4 | A | 33,639.97 | 3.274 | 13.848 |
| static | 5 | L | 23,320.76 | 5.243 | 12.703 |
| static | 6 | B | 14,616.82 | 7.745 | 28.050 |
| pagecache | 1 | B | 14,277.86 | 7.237 | 36.399 |
| pagecache | 2 | L | 20,254.23 | 5.470 | 21.968 |
| pagecache | 3 | A | 19,976.85 | 4.965 | 31.983 |
| pagecache | 4 | A | 19,308.80 | 5.043 | 32.376 |
| pagecache | 5 | L | 22,385.55 | 4.975 | 19.640 |
| pagecache | 6 | B | 19,873.59 | 5.962 | 16.148 |

### Exact shipped baseline: 32 KiB

| Fixture | Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---|---:|---|---:|---:|---:|
| static | 1 | B | 4,418.76 | 26.610 | 71.363 |
| static | 2 | L | 5,257.88 | 22.446 | 60.137 |
| static | 3 | A | 5,701.59 | 19.449 | 79.744 |
| static | 4 | A | 5,660.77 | 19.277 | 75.318 |
| static | 5 | L | 5,586.18 | 21.678 | 49.732 |
| static | 6 | B | 4,278.37 | 27.813 | 71.330 |
| pagecache | 1 | B | 4,298.96 | 27.154 | 79.922 |
| pagecache | 2 | L | 5,704.99 | 20.603 | 55.905 |
| pagecache | 3 | A | 5,952.89 | 19.531 | 63.282 |
| pagecache | 4 | A | 6,888.59 | 17.771 | 53.674 |
| pagecache | 5 | L | 6,100.28 | 19.695 | 50.445 |
| pagecache | 6 | B | 5,272.82 | 22.788 | 56.454 |

Across these four fixtures, descriptive A/B median throughput differences are
approximately +55%, +100%, +13% and +11% against matched native builds, and
+156%, +15%, +31% and +34% against the shipped executable (1 KiB static,
1 KiB page cache, 32 KiB static, 32 KiB page cache, respectively). These are
conditional observations from two repetitions per mode, not confidence
intervals or universal speedup estimates.

The shipped 1 KiB page-cache A range overlaps the later B arm and trails both
L arms. Native baseline page-cache throughput also drifts substantially.
The shipped 32 KiB static A arms have worse p99 (75.318 and 79.744 ms) than
either B arm (71.330 and 71.363 ms), despite higher throughput. Broad
performance superiority therefore remains unproven. The H3 engine changes
and native build/profile effects must not be attributed to Beeper parsing or
CID steering alone.

Preflight and periodic checks observed no compilers during these matrices.
Unobserved Windows-host activity, CPU frequency, individual client-thread
limits and kernel scheduling can still affect results. Process CPU does not
include all kernel/IRQ work; no production-wide or whole-machine CPU saving
is claimed.

## Final v5 matched offered-load controls

A separate validating client schedules arrivals from a monotonic clock.
Its primary latency is scheduled-arrival to completion, including admission
backlog. It also records service latency and dispatch lateness. Concurrency is
bounded at 128 slots: these are bounded-admission measurements, not an
unrestricted open-loop test. All logical outcomes are retained; invalid arms
report null primary metrics and are not retried.

B is the exact shipped binary; L and A are the same v5 candidate binary.
The new client SHA-256 is
`bb753fc5e0e9dc83abcf454c3b97b0c70bab1d7d1e2850edd9efeefeeed3bf37`.
The 24 arms validate 1,560,000 measured responses with zero response errors,
zero observed client UDP drops and no expired arrivals. Both workers were
active in every arm; all exit records were zero and post-run body-buffer
gauges returned to zero. No compilers were observed during the matrices.

The 32 KiB workload offers 2,500 requests/s for 30,000 measured requests per
arm, after 5,000 unpaced warmup requests. The 1 KiB workload offers 8,000/s for
100,000 measured requests, after 10,000 warmup. Each fixture retains the
B, L, A, A, L, B order. Achieved throughput remains close to offered throughput
by construction and is not evidence of increased saturation capacity.

### 32 KiB at 2,500 requests/s

| Fixture | Arm | Dispatch | Scheduled p99 ms | Service p99 ms | Dispatch-late p99 ms | Bound waits |
|---|---:|---|---:|---:|---:|---:|
| static | 1 | B | 4.032 | 3.342 | 1.118 | 0 |
| static | 2 | L | 4.038 | 3.333 | 1.197 | 0 |
| static | 3 | A | 3.382 | 2.291 | 1.860 | 0 |
| static | 4 | A | 3.758 | 2.882 | 1.618 | 0 |
| static | 5 | L | 4.014 | 3.316 | 1.197 | 0 |
| static | 6 | B | 35.321 | 30.043 | 5.812 | 35 |
| pagecache | 1 | B | 7.170 | 6.075 | 1.471 | 0 |
| pagecache | 2 | L | 10.464 | 8.209 | 2.459 | 0 |
| pagecache | 3 | A | 6.400 | 4.971 | 1.854 | 0 |
| pagecache | 4 | A | 3.734 | 2.959 | 1.438 | 0 |
| pagecache | 5 | L | 27.050 | 22.105 | 6.637 | 0 |
| pagecache | 6 | B | 62.170 | 47.454 | 18.731 | 138 |

### 1 KiB at 8,000 requests/s

| Fixture | Arm | Dispatch | Scheduled p99 ms | Service p99 ms | Dispatch-late p99 ms | Bound waits |
|---|---:|---|---:|---:|---:|---:|
| static | 1 | B | 3.915 | 2.965 | 1.966 | 0 |
| static | 2 | L | 29.690 | 12.133 | 14.921 | 322 |
| static | 3 | A | 11.119 | 6.241 | 3.451 | 66 |
| static | 4 | A | 3.849 | 2.512 | 2.029 | 0 |
| static | 5 | L | 28.775 | 16.996 | 14.061 | 585 |
| static | 6 | B | 11.919 | 9.647 | 2.165 | 99 |
| pagecache | 1 | B | 20.154 | 14.480 | 6.861 | 300 |
| pagecache | 2 | L | 3.362 | 2.041 | 1.983 | 0 |
| pagecache | 3 | A | 4.259 | 2.948 | 2.019 | 0 |
| pagecache | 4 | A | 3.133 | 1.458 | 2.037 | 0 |
| pagecache | 5 | L | 3.232 | 1.713 | 1.972 | 0 |
| pagecache | 6 | B | 5.323 | 4.262 | 1.978 | 0 |

At the tested 32 KiB offered rate, A has lower scheduled p99 than L in both
repetitions of both fixtures. The 1 KiB results are mixed: page-cache L and A
overlap, while static L has larger tails in this window. Seven arms reach
the admission bound; late shipped-baseline 32 KiB arms show substantial drift.
Client timer granularity, admission limits and unobserved host activity limit
generalization. These controls support a conditional responsiveness benefit,
not a universal latency, throughput or CPU win.

## Final v5 bridge-only Range control

The final v5 candidate and v5 client identified above are fixed across all four
arms. Each validates 100,000 full-body 32 KiB 206 responses. Every arm completed
its count with zero errors, zero on-core selections and zero observed client
receive drops. L and A remain modes of the same candidate, not comparisons
against the shipped binary.

| Arm | Dispatch | Responses/s | p50 ms | p99 ms |
|---:|---|---:|---:|---:|
| 1 | L | 5,677.92 | 20.628 | 62.351 |
| 2 | A | 6,078.33 | 20.111 | 45.510 |
| 3 | A | 5,101.74 | 22.616 | 65.449 |
| 4 | L | 5,048.45 | 22.390 | 69.050 |

A's median rate is about 4.2% above L in this window, smaller than the observed
within-mode drift: approximately 11% for L and 16% for A. A's p99 is below its
adjacent L arm in both pairs, so the earlier relative tail regression is not
reproduced here. This is limited evidence, not a universal tail guarantee or a
precise speedup estimate.

The lower absolute rates relative to v3 have no established single cause. The
client request and phase-loop source bodies are byte-identical between the two
client checkpoints; invalid-run reporting and teardown/output organization
changed outside the timed request loop. Measured client CPU per 100,000 requests
was similar, with no observed increase explaining the slowdown. Aggregate
client CPU use did not demonstrate saturation of its available CPU allocation;
that does not exclude a particular client-thread or I/O limit.

The v5 window recorded more server process system CPU and a higher whole-VM
softirq share. Process CPU and VM counters cover different scopes, and VM
counters include unrelated work. They identify changed conditions, not an
attributed cause. Source, PGO corpus/profile and client binary also differ
between v3 and v5. Historical rates therefore cannot isolate a server revision's
cost. The separate v5 matrices above compare fixed artifacts within each window.

## Rejected body-expansion egress microprobes

These are fixed-response TCP serialization probes, not whole-server H1/H2
benchmarks. A one-byte request selects an immutable body and fixed HTTP-style
headers; the receiver checks all header/body bytes. The probe does not measure
HTTP parsing, routing, cache policy, TLS, or an HTTP/2 connection engine. Its
baseline is ordinary native sending, not the released HTTPJet binary.

**N** below means ordinary native sending; **E** means experimental kernel body
expansion after native response selection. Each row completes 20,000 verified
responses. For every E row, kernel counters reported 20,000 expansions, zero
errors, and exactly body-size × 20,000 expanded bytes. Native rows do not load
the expansion program. Server-thread CPU is the recorded thread's CPU time,
not total machine or kernel/IRQ cost.

| Probe | Source qualification | Binary SHA-256 |
|---|---|---|
| First expansion probe | Earlier exact source snapshot was not frozen; do not claim an exact source-hash build reproduction | `6a033de018c24120f1b368ea8afafdf77aaf702742be5e3e1c142f4a87cbba89` |
| Bound-body expansion probe | Optimized source archive retained separately; per-response map updates were removed from its hot path | `e69c4f8190e2769910fb9e3d5a4a3bb1765ab6980ddc8cf53f9fc8a6280ca7d0` |

Both probes were release builds with the same CPU target and frame-pointer
policy. Each matrix used N, E, E, N order for each body size.

### First expansion probe

| Body bytes | Arm | Path | Responses/s | Server-thread CPU s |
|---:|---:|---|---:|---:|
| 1,024 | 1 | N | 4,096.09 | 0.338674 |
| 1,024 | 2 | E | 3,358.86 | 0.610182 |
| 1,024 | 3 | E | 3,374.52 | 0.642225 |
| 1,024 | 4 | N | 3,399.35 | 0.419560 |
| 32,768 | 1 | N | 2,623.66 | 0.528811 |
| 32,768 | 2 | E | 2,681.01 | 0.902060 |
| 32,768 | 3 | E | 2,613.79 | 0.976971 |
| 32,768 | 4 | N | 3,306.99 | 0.432468 |

### Bound-body expansion probe

| Body bytes | Arm | Path | Responses/s | Server-thread CPU s |
|---:|---:|---|---:|---:|
| 1,024 | 1 | N | 4,388.22 | 0.338847 |
| 1,024 | 2 | E | 4,229.03 | 0.395733 |
| 1,024 | 3 | E | 3,633.90 | 0.469240 |
| 1,024 | 4 | N | 3,606.22 | 0.393803 |
| 32,768 | 1 | N | 3,473.01 | 0.432592 |
| 32,768 | 2 | E | 3,217.53 | 0.703253 |
| 32,768 | 3 | E | 3,157.57 | 0.702877 |
| 32,768 | 4 | N | 2,507.71 | 0.633028 |

Each matrix validates 160,000 responses. Both expansion variants consume more
server-thread CPU per response than the corresponding native control medians.
Wall-rate ranges overlap or drift, including a late slow native arm in the
bound-body probe; a reliable wall-time benefit was not established. The optional
body-expansion writer, BPF program and probe were removed from the implementation
branch rather than promoted. This result must not be presented as successful
H1/H2 integration.

A separate parity check covers body sizes 1, 255, 256, 257, 1,024 and 32,768 bytes,
100 verified responses each. All six checks passed, including the per-commit
verification used by that check. The throughput matrices themselves did not run
that additional per-commit query on every response.

## Large-transfer failures and qualification boundary

| Control | Phase / requested work | Verified successes | Timeouts | Meaning |
|---|---|---:|---:|---|
| Historical v3 original-source native baseline, 2 MiB bodies | 512 measured requests | 508 | 4 | Invalid throughput comparison; failure must not be discarded |
| Later original-source instrumented baseline, 2 MiB bodies | 32 warmup attempts; 128 measured requests planned | 28 warmup responses | 4 | Warmup failed; all 128 measured requests remained unattempted |

These are native source-baseline controls, not an exact shipped-archive
reproduction. The failed measured run's old client emitted a numeric rate for
its successful subset; that rate is intentionally not used here. The later
client marks invalid runs explicitly and emits null throughput. Candidate
large-body correctness successes cannot be compared with a failed baseline to
manufacture a throughput gain. Failed large-transfer training was excluded from
both sides of the final matched PGO comparison.

The experimental transport subsequently gained regressions for retained runnable
QUIC work and response FIN acknowledgement during shutdown. Those fixes and the
following controls establish particular correctness properties; they do not
qualify all large-body workloads or establish a large-transfer speedup.

## Final optimized v5 shutdown controls

The immutable v5 candidate above was used for all six cases. A validating QUIC
client gates outgoing ACKs at the first body DATA event, with receive windows
larger than the warmed 2 MiB cached response. In the full-delivery case it sends
SIGTERM there, observes GOAWAY while the body is incomplete, then resumes ACKs
and validates every byte. This is an event-gated correctness control, not a
fixed-sleep race or a performance benchmark.

The live precondition combines an observed cache-hit response, sufficient
transport windows and the source ordering of full-response queueing before the
first flush. There is no live exported FIN-accepted counter. Independent modeled
QUIC tests cover the precise accepted-but-unsent versus FIN-acknowledged ordering.

| Mode | Case | Received body bytes | Bytes at GOAWAY observation | Shutdown s | Body-budget bytes after STOP |
|---|---|---:|---:|---:|---:|
| L | delivery | 2,097,152 | 22,148 | 0.262077 | — |
| L | stop | 11,795 | — | 0.064382 | 0 |
| L | unacked | 27,868 | — | 15.057389 | — |
| A | delivery | 2,097,152 | 18,261 | 0.213122 | — |
| A | stop | 11,795 | — | 0.064319 | 0 |
| A | unacked | 30,476 | — | 15.013290 | — |

Both delivery cases received the exact 2,097,152-byte body after shutdown began.
The STOP cases deliberately cancel the response: the live body-budget gauge
falls from 2,097,322 bytes to zero before shutdown is requested. Non-acknowledging
peers intentionally leave incomplete responses; the server exits near its
15-second grace bound. A dash means that measurement does not apply, not that a
zero was observed.

All six cases passed, with zero client receive drops, zero server/cleanup exit
codes and all owned listeners released. The process used an unprivileged service
account without supplementary groups. No production configuration or services
were used. These shutdown timings must not be marketed as request-latency or
throughput gains.

## Evidence and remaining limits

The following digests identify the retained audit inputs. Their raw files are
not included here because they contain operational metadata; these Markdown
tables are a curated research summary, not a binary or reproduction bundle.

| Input | SHA-256 |
|---|---|
| Frozen v3 44-arm summary | `8a3506ca1fade3bd457d8be2b7e6843770fafbe6beff42d44beb5bc3854d6c02` |
| First egress 8-arm matrix | `bd15a394fc9e82fcddc9c302769b34a43c59f4428c9fec705b7477915c141787` |
| Bound-body egress 8-arm matrix | `0b242480caca9577064b286f0f543464b5ea9014f6f9d25fe4e515faefdaa4f5` |
| Egress size-parity checks | `6ce9a0b55a0a16dbf629a300c31bfed3daf2e4dcf6b67e0f7c22d2d9e427e7f3` |
| Final v5 Range 4-arm evidence | `8b6500c9cc2299fa5db0d503ff200c020bb89b637c920142e59e4caa1be3570d` |
| Final optimized v5 shutdown 6-case evidence | `ca7457c4ca56759380a8d1b785654d6345e084937b0e9c3e866aa827a2549ee6` |
| Final v5 native 1 KiB 12-arm matrix | `a91587cc77b5932e04873e832973f3f0dc448410e2b01a5862fe577014ec73f8` |
| Final v5 native 32 KiB 12-arm matrix | `4197b954e7109fe0b07b07bf9f45f32fa125f5c0b3555bcec614abef63d99000` |
| Final v5 shipped 1 KiB 12-arm matrix | `592eb1d0ffd80ac6aeb8404986ceba6059ee1adfd0485556690d3986d84ca49d` |
| Final v5 shipped 32 KiB 12-arm matrix | `0bad931d3b8418de5cccf158082d118437c24092f7033fdda751c4534ab11031` |
| Offered-load shipped 1 KiB 12-arm matrix | `67561833ca8b653193a7c1caf224fb6b05fc1c6e5e8bf0d00fa593266198192d` |
| Offered-load shipped 32 KiB 12-arm matrix | `b58b7d90d4909d22d3cc828156ec82f3ecd40ebb71c40c244e991def3aaf7a52` |

The evidence covers one lab environment and synthetic public-cache fixtures,
with a small number of repeated timing arms. It does not establish production,
Internet-path, authenticated-cache, dynamic-backend, migration or physical-NIC
performance. Client receive-drop observations do not prove absence of server-side
or other network loss. Source/build identities and scope matter more than a
single favorable rate.

The H3 prototype retains Quinn for QUIC/TLS, packet protection, congestion and
flow control, and retains io_uring packet I/O. CID steering and application cache
dispatch are distinct changes. These measurements establish neither kernel H3
termination, AF_XDP zero-copy, end-to-end zero-copy networking, nor a general
performance superiority of a completed Beeper integration.
