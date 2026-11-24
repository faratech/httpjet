# Native H2 TLS service-future comparison

The new build does not establish a broad improvement. Static-response scheduled
p99 regressed in every cycle, while process CPU changes were mixed. Page-cache
responses showed a small latency improvement, with one CPU cycle worse.

All 24 arms were valid. Both artifacts enabled response memoization and used
native H2 over strictly verified fixture TLS, with no helper or kernel serving.

| Warm 1 KiB case | Metric | Old ABF | New native future | Change |
|---|---|---:|---:|---:|
| Static | Process CPU, us/response | 24.923 | 24.692 | -0.93% |
| Static | Scheduled p99, ms | 2.177 | 2.316 | **+6.39%** |
| Static | Service p99, ms | 0.970 | 1.119 | **+15.33%** |
| Static | Whole-VM busy CPU, us/response | 81.385 | 79.462 | -2.36% |
| Static | Server user instructions/response | 32,334.63 | 31,250.16 | -3.35% |
| Static | Server user cycles/response | 44,658.82 | 44,150.91 | -1.14% |
| Static | Successful requests/s | 14,996.46 | 14,995.47 | -0.007% |
| Page cache | Process CPU, us/response | 27.000 | 25.769 | -4.56% |
| Page cache | Scheduled p99, ms | 2.372 | 2.301 | -3.01% |
| Page cache | Service p99, ms | 1.242 | 1.134 | -8.71% |
| Page cache | Whole-VM busy CPU, us/response | 96.846 | 86.000 | -11.20% |
| Page cache | Server user instructions/response | 33,376.72 | 32,412.30 | -2.89% |
| Page cache | Server user cycles/response | 49,853.44 | 47,630.92 | -4.46% |
| Page cache | Successful requests/s | 14,994.28 | 14,996.31 | +0.014% |

Each value is the median of six arm values. CPU and PMU counts cover all 65,000
responses per arm, including warmup; p99 covers 60,000 measured responses.
Latency is scheduled arrival to completion. Scheduled, service and dispatch
quantiles are separate statistics and must not be added. Tick-based CPU has
100 Hz resolution, or about 0.154 us/response per tick in each arm. Component
medians need not sum to the median of per-arm total CPU.

## Per-cycle changes, new versus old

| Case | Cycle | Process CPU | Scheduled p99 | Whole-VM busy CPU |
|---|---:|---:|---:|---:|
| Static | 1 | **+6.02%** | **+7.53%** | -5.83% |
| Static | 2 | **+3.57%** | **+6.16%** | **+7.61%** |
| Static | 3 | -9.17% | **+1.01%** | **+6.19%** |
| Page cache | 1 | -1.88% | -2.50% | -8.31% |
| Page cache | 2 | -13.58% | -6.01% | -30.37% |
| Page cache | 3 | **+0.86%** | -0.48% | -7.46% |

The lower instruction count is consistent across cycles, but it does not
establish an overall CPU or latency win. The static p99 regression and mixed
CPU results do not support promoting this prototype on this evidence.

## Validated scope and limits

The raw audit checked 1,560,000 rows: 1,440,000 measured and 120,000 warmup
responses. Every response had the expected 1 KiB body and status; all 24 server
exits and both compiler-free monitors passed. All 160 PMU thread records summed
correctly, with running fraction 1.0 and no multiplexing. Average client-CPU busy
fraction peaked at 27.46%, below the 85% gate. No admission waits were recorded;
peak in-flight counts were 67 for static and 120 for page cache, below the client
bound of 128. This bound is not a server admission setting.

The old and new artifacts use the same features, native Rust CPU flags, frame
pointers and unset CFLAGS/CXXFLAGS, with separately gathered source-specific
55-server PGO profiles. The only changed Rust source is
`crates/httpjet/src/uring/mod.rs`. This is a controlled comparison of two
source/profile artifacts; it does not isolate a profile-independent causal cost.
Both endpoint records show the explicit local Docker daemon empty, the same boot
ID and no sampled VM/build processes. Endpoint records cannot prove whole-interval
quietness, and one-second compiler sampling cannot observe shorter activity.

Process CPU covers one server process and excludes kernel/IRQ work charged
elsewhere. PMU is server user mode only. Whole-VM CPU includes clients and
unrelated Linux work; Windows-host activity is unobserved. Whole-VM TCP counters
recorded 30 retransmissions and zero timeouts, without causal attribution.
These are warm fixture results at an offered 15,000 requests/s, not measured
capacity, public-network latency, kernel TLS serving or Unix-hook performance.
