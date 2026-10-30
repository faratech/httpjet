# Continuation: kernel serving and transport CPU

This is an experimental progress record, dated 30 October 2026. It does not
announce a production deployment or a faster release. All runtime validation
uses owned loopback fixtures on SINGULARITY.

The upstream work is [Beeper](https://github.com/lerboe/beeper) and
[hyper-fast-path](https://github.com/lerboe/hyper-fast-path), by
[Laurin Brandner (@lerboe)](https://github.com/lerboe). Their current READMEs
describe HTTP/1.1 and HTTP/2 parsing and static serving. Their Axum comparison
does not predict a gain over HTTPJet's existing caches. Beeper's README was
checked at `6135c588add5f7760c11d0e0cda1997bdaa5adca`; hyper-fast-path's at
`f7f556f17c745cadfdd2fd73fc549e38dd4b1ddc`.

## Work continued from the earlier implementation

The continuation starts from experimental source `a7d22f4c`, not from an empty
implementation. The first continuation checkpoint tested here is `f7555d80`. The main changes
and validation since that starting point are:

- Preserve the actual socket-registration error through helper RPC. A map
  update returning EOPNOTSUPP can decline acceleration safely; converting it
  to EIO had incorrectly turned a recoverable refusal into a connection close.
- Extend H1/H2 exported identity with exact raw User-Agent bytes and explicit
  absent/present distinction. A generic response still shares an entry where
  policy proves User-Agent independence. Authentication, private cookies,
  unmodelled dependencies and ambiguous input retain native handling.
- Allow H1 enrollment after native cache misses and body-bearing history.
  Enrollment checks exact received-byte accounting, empty input and transmit
  queues, and acknowledged prior output before transferring ownership.
  Pending protocol state is not discarded or replayed blindly.
- Add an optional persistent H1 readiness wait. The polling mode remains the
  default; a correct alternative is not automatically a faster alternative.
- Add a bounded sendmmsg path to a pinned Quinn UDP fork. The default remains
  a one-message send. The batch retains unsent datagrams across EAGAIN and
  preserves ECN, source-address and GSO fallback handling. A persistent writable
  wait prevents retry cancellation from losing progress.

The optimized checkpoint passed the 166-case-per-arm H1 late-enrollment corpus
with readiness enabled, and the 145-case-per-arm H1/H2 User-Agent corpus across
native, polling and readiness modes. Earlier combined checks also exercised
H2 control frames, fragmented headers, HPACK changes, flow-control suspension
and native handoff. These are bounded test corpora, not proof of all possible
protocol interleavings.

TLS remains under its native owner. H3 acceleration is HTTPJet's shared cache
and Quinn transport work; no Beeper HTTP/3 parser or in-kernel QUIC termination
is claimed. The io_uring path remains necessary for TLS, misses, unsupported
requests, protocol control and safe fallback.

## Initial candidate identity and measurement controls

The initial integrated server's SHA-256 is
`3c20b62faff9b210e3dd2b017df0d1e55af52792beeceeacf815629c409e14b0`.
It uses serving ABI 5 and helper RPC 2, native CPU code generation, frame
pointers, thin LTO and no PGO. PGO preparation and instrumented training are
separate work; training rates must never enter timing comparisons.

There are two distinct controls:

| Control | Server SHA-256 | Meaning |
|---|---|---|
| Exact v0.1.10-11 amd64 archive | `3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec` | What a user downloads; different build recipe from the native experiment |
| Runtime-source-equivalent native rebuild, `46be2c2e` | `f18f6299cf5d91429df589870d6d5021b1d592f5aa93fdf986be528f2428b2e9` | Native CPU, frame pointers, thin LTO and no PGO, for a closer source comparison |

Both controls retain their existing caches. The integrated candidate additionally
enables the new page-response memo. Plaintext kernel serving must show actual
success-counter increases for eligible fixtures. A command-line flag alone
does not establish that the kernel served any response.

The fixtures use `maxKeepAliveReq=32767`. HTTPJet applies that compatibility
cap during configuration parsing even though the field is a 32-bit integer;
it is not a Rust or eBPF limit. A larger value currently selects the 1,000-request
default, which changes connection churn and makes it unsuitable for these
comparisons.

SINGULARITY has two different loopback routes. Binding both client and server
to `127.0.0.2` selects Linux `lo`; `127.0.0.1` traverses the WSL/Hyper-V loopback
interface. Results from these routes are not combined into a code-change gain.
The current integrated matrix uses `127.0.0.2` on both ends and records client
socket addresses and the selected route.

Every measured response must have the expected status and exact body. Three
ABBA cycles per cell retain all repetitions. User-mode hardware counters are
separate from whole-process CPU and whole-VM CPU counters. User PMU counts omit
kernel work; whole-VM counters include client and unrelated work. Neither alone
is a measurement of total server CPU. A client CPU headroom failure, compiler
overlap, missing arm or nonzero server exit invalidates the affected comparison.

## Tuning decisions before the full matrix

The readiness pilot validates 1.6 million measured H1 responses. In its static
1 KiB cell, polling achieved a median 164,045 responses/s and readiness 152,899
responses/s, a 6.8% decrease. The page-cache cell had large baseline drift.
Polling therefore remains selected for the subsequent performance comparison.

A three-cycle 32 KiB H3 page-cache comparison of GSO 20 / send batch 1 against
GSO 10 / send batch 4 gave descriptive median changes of +7.0% throughput,
-12.0% p99 and -9.1% process CPU per response. User instructions declined by
about 1.0%. The within-cycle p99 changes were +55.1%, +26.0% and -23.9%, so there is
no reliable page-cache latency winner. This selects an experimental capacity
comparison configuration; it does not change the default
or establish a universal gain.

The H2 flush-vector reuse prototype is retained on a separate branch. Its
small instruction reduction came with mixed throughput and latency results,
so it is not included in the integrated candidate.

## Remaining qualification

The latest matrix stopped after 72 measured arms (14.4 million validated
responses), at an H2 page-cache activation failure. Five cells completed all
three ABBA cycles. The sixth served correct responses but one candidate arm
recorded zero kernel hits, so it failed the acceleration-coverage gate. The
remaining planned cells have not run. Production settings and binaries have
not changed.

The completed cells below compare the exact shipped release with the integrated
candidate, all at 1 KiB. Values are descriptive medians over six arms per
implementation. User/process CPU omits offloaded kernel work; VM busy includes
clients and unrelated Linux activity. These are different measurement scopes.

| Protocol / cache | Responses/s: release / candidate | p99 ms: release / candidate | Process CPU change | VM busy per response change |
|---|---:|---:|---:|---:|
| h1 / static | 74,764 / 144,727 | 0.908 / 0.768 | -86.7% | -2.8% |
| h1 / pagecache | 45,198 / 142,007 | 1.474 / 0.790 | -91.1% | -29.2% |
| h1s / static | 60,193 / 59,661 | 1.139 / 1.117 | +0.6% | +1.5% |
| h1s / pagecache | 40,759 / 67,396 | 1.533 / 0.946 | -39.2% | -25.1% |
| h2c / static | 84,765 / 149,954 | 3.051 / 5.621 | -47.1% | +1.8% |

The H2c static cell illustrates why throughput alone is insufficient: its
throughput rises while p99 and whole-VM CPU per response worsen. Small static
HTTPS/H1 remains approximately level. Broad superiority is therefore still
unproven even among the completed cells.

Source inspection identifies an H2 expiry-recovery hole: the native owner can
consider an open but expired kernel entry ready, suppressing new publication,
while the refresh path is unreachable after failed registration or native
handoff. The failing arm repeatedly attempted activation and rejected expired
entries without recovering. Freshness checks must remain intact; the repair
must let native cache authority publish a fresh representation. The exact
expired-entry history is inferred from the retained refusal counters and
immutable-field validation; raw entry timestamps were not captured in that arm.

The subsequent repair checks the current image key, epoch and deadline through
the native registry. An expired open index no longer suppresses publication.
Evicted log metadata cannot hide a current image: the fast metadata hint has an
authoritative bounded fallback. The deterministic regression first reproduced
zero recovered kernel hits across 512 correct responses on the old binary;
the repaired build recovered 510/512 after the same 2.1-second native hold.
The existing 16-case H2 handoff corpus also passed.

The repaired build has SHA-256
`8bfbf568094bc2545b43219db469f334af4a9d2c73ab8c922741b454b05a0b90`.
Its runtime inputs match source `d0f1d027`; it also includes bounded H1 response
buffer reuse and local H3 completion pumping. All 1,076 server tests passed,
as did the H1 late-enrollment and H1/H2 User-Agent corpora and six H3 delivery,
cancellation and shutdown controls. These are correctness results.

A repeated three-cycle H2 page-cache comparison then passed kernel-coverage
checks in every candidate arm. Median throughput was 45,707 versus 119,083
responses/s, process CPU 21.83 versus 7.93 us/response, and saturated p99 5.289
versus 6.671 ms, release versus candidate. The throughput gain therefore still
comes with a saturated tail-latency loss. This compares the combined cache and
kernel changes, not the parser in isolation.

The next gates are the remaining protocol/size matrix, Range controls and equal
offered-load tails. The buffer changes are also being compared directly with
the previous integrated binary. PGO remains a separate experiment, with
independently trained source baselines and no training rates counted as
benchmark evidence.

## Buffer optimization comparison

A separate comparison used the previous integrated binary (`3c20b62f…`) as
the baseline, with the same memo and H3 GSO/batch settings. It tested H1 TLS
buffer reuse and the additional H3 local-completion change. Three ABBA cycles
were planned for each cell. Seven cells completed; the final H3 page-cache
32 KiB cell stopped when one request timed out in its last baseline arm.
That arm completed 199,036 of 200,000 requests: 199,035 succeeded, one timed
out, and 964 remained unattempted. The cause is still under investigation;
it is not evidence that the new change fixes a reliability defect.

The complete cells below show candidate changes against that integrated
baseline, not against the public release. Values are ratios of six-arm
medians; repeated arms show substantial host/run variation.

| Cell | Throughput | p99 | Process CPU/response | User instructions/response |
|---|---:|---:|---:|---:|
| h1s static 1 KiB | +3.36% | +4.27% | -2.81% | -1.21% |
| h1s pagecache 1 KiB | +5.97% | -7.62% | -4.47% | -0.70% |
| h3 static 1 KiB | -6.61% | +9.27% | +7.82% | -3.68% |
| h3 pagecache 1 KiB | -2.67% | +10.39% | +1.72% | -1.07% |
| h1s static 32 KiB | +2.15% | -23.56% | -1.58% | -0.38% |
| h1s pagecache 32 KiB | +3.46% | -26.11% | -0.43% | -0.24% |
| h3 static 32 KiB | -10.83% | +8.28% | +11.39% | -0.23% |

H1 buffer reuse is retained for further qualification. Its gains are small;
these figures do not establish a whole-server CPU reduction in every case.
The additional H3 local-completion change is reverted in `9c87355d`: despite
fewer instructions, the completed H3 cells consumed more process CPU and had
lower throughput and worse p99. This reversion retains the main accelerated
H3 engine, its cache path and its existing transport improvements. The failed
baseline arm and all other observations remain retained.

A separate [scheduler fairness regression](h3-scheduler-fairness-20261030.md)
then showed that repeated overdue work could prevent a queued request from
receiving its first poll. The repaired scheduling boundary passed 128 H3
tests and the full 1,075-test server suite. This establishes that conditional
defect and its repair; it does not prove the earlier timeout had that cause.

## Rustls metadata experiment

A separate fork of rustls 0.23.46 replaced the temporary vector of slice
references in small vectored writes with a bounded stack array. Encryption,
record boundaries, payload copying and the large-vector fallback were
unchanged. The [upstream function](https://github.com/rustls/rustls/blob/f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb/rustls/src/conn.rs#L392)
was checked before making the experiment.

The fork passed four focused TLS tests, 33 existing TLS-library tests, the
1,075-test server suite, cache isolation gates and live protocol/shutdown
checks. Production-dependent ignored tests remained skipped. Both builds used
the same native compiler profile, TLS features and caches. The control was
`0a7cec3500f73188b7c705c1bc60871ab448fa02884d0e3b46f12a3db633b922`;
the fork was
`4ffb6d8b296226a2a4ec9aaf0c5ee2690d67e5113d9ab213d49dfb99bfe954dd`.

All 48 timing arms completed: three ABBA cycles per 1 KiB cell, with 200,000
measured responses plus 10,000 warmup responses each. Changes below are fork
versus control medians, not comparisons with the public release.

| Cell | Throughput | p99 | Process CPU/response | User instructions/response |
|---|---:|---:|---:|---:|
| h1s static | -0.09% | -0.44% | +0.00% | -0.22% |
| h1s pagecache | +1.47% | -10.22% | -2.14% | -0.22% |
| h2 static | -0.93% | +0.47% | +0.89% | -0.00% |
| h2 pagecache | +1.40% | -0.46% | -1.41% | -0.01% |

The stable instruction reduction was only about 0.22% for H1 TLS and near zero
for H2. Throughput variation between repeated cycles exceeded the apparent
gain. The fork is retained as an experiment and is not merged into the
continuation build: the measurements do not justify its additional vendored
dependency and update burden. Stock rustls remains the selected dependency for continued qualification.

## H2 at the same offered rate

The selected stock-rustls build was also compared at a scheduled 15,000
requests/s using a separately qualified paced HTTP client. Three symmetric
release/native/kernel/kernel/native/release cycles ran for each 1 KiB cache
fixture. All 2,160,000 measured responses validated; each arm also had 5,000
unpaced warmup requests. Both native and kernel candidate modes enabled the
page-response memo, and the release retained its existing caches.

These are bounded offered-load measurements, not unrestricted open-loop
results. Fourteen of the 36 arms reached the 128-request limit and recorded
admission waits (2,743 total). Scheduled latency includes those waits; service
latency excludes admission backlog. The table reports medians of per-arm
percentiles, not pooled percentiles. CPU values cover the whole client span
and divide by measured plus warmup responses.

| Cache | Mode | Scheduled p99 ms | Service p99 ms | Process CPU us/response | VM busy us/response |
|---|---|---:|---:|---:|---:|
| static | release | 2.005 | 0.624 | 18.08 | 85.15 |
| static | native | 2.138 | 0.731 | 18.77 | 78.69 |
| static | kernel | 3.786 | 2.987 | 27.77 | 113.08 |
| pagecache | release | 2.573 | 1.199 | 27.92 | 81.77 |
| pagecache | native | 2.492 | 1.011 | 22.77 | 97.08 |
| pagecache | kernel | 5.292 | 3.180 | 28.15 | 113.54 |

All modes achieved approximately the requested rate. The kernel path served
about 97% of requests in its arms, but used more process CPU and had worse p99
in this workload. Lower user-mode instruction counts did not establish lower
total CPU cost. VM busy values include clients and unrelated Linux activity;
they are not total-server CPU attribution, and Windows-host work is unobserved.

The kernel option therefore remains an opt-in capacity path. The native
io_uring path remains necessary and preferable for CPU/latency in this tested
load regime. Higher saturated throughput does not make a path universally
faster or cheaper. The larger capacity matrix is still in progress.

## Oversized H2 responses exposed a remaining cost

The next capacity run completed 16 of its 40 planned cells (192 valid arms,
38.4 million measured responses) before being stopped for an implementation
fix. All 1 KiB release comparisons improved median throughput, but the 32 KiB
plaintext H2 static fixture regressed from 67,941 to 42,219 responses/s.
Process CPU rose from 14.60 to 23.67 us/response. Responses remained correct.

The 16 KiB kernel body limit correctly kept these responses native. However,
each candidate arm still queued 209,968 publication candidates and started
roughly 52,500 asynchronous publication attempts, all unable to serve that
body. Native authority was run again before the late size check declined it.
H1 already had an early check; H2 lacked it. The 32 KiB H2 page-cache fixture
was near throughput parity rather than benefiting from the new memo.

Qualification paused to add a conservative early H2 check of actual body
length before canonicalizing the request or queueing publication. The final
authoritative size check remains necessary, and unknown-length bodies must
retain their existing handling. The interrupted run is not a completed capacity qualification.

The early check is implemented and passed 1,076 server tests, 227 H2 tests,
the live large-response/small-response handoff, expiry recovery and both
required cache-isolation gates. It reads actual body metadata, not an HTTP
Content-Length header, and leaves unknown-length bodies on their previous
path. The corrected binary is
`6ac144f2449750d6063963c0994f30c933c11df8e8dbfa548b1a7b4a71e51e8f`.

A single ABBA pilot against the prior candidate validated 800,000 measured
32 KiB H2c static responses. The two corrected arms queued zero publication
candidates and zero publication tasks. Descriptive medians improved by 76.4%
in throughput, 54.0% in p99 and 43.6% in process CPU per response. These are
preliminary paired results, not a replacement for the full matrix. A new
release/native-source capacity matrix is running on the corrected build.

## Individual tuning arms

All 28 arms below passed response validation, client-headroom checks and 100%
PMU scheduling coverage. H1 uses 200,000 measured plus 10,000 warmup requests
per arm. Initial H3 tuning uses 100,000 plus 10,000; H3 confirmation uses
100,000 plus 50,000. One server worker and six client threads were used.
CPU and instructions divide their complete counter span by measured plus
warmup responses; throughput and p99 cover the measured phase only. Process
CPU omits kernel work charged elsewhere.

### h1-wakeup-true-lo-v1

| Case | Cycle / position | Setting | Responses/s | p99 ms | Process CPU us/response | User instructions/response |
|---|---:|---|---:|---:|---:|---:|
| pagecache | 1 / 1 | polling | 147786.3 | 0.737 | 1.71 | 6547.8 |
| pagecache | 1 / 2 | readiness | 144231.3 | 0.779 | 2.05 | 6716.2 |
| pagecache | 1 / 3 | readiness | 152889.7 | 0.716 | 1.71 | 6692.6 |
| pagecache | 1 / 4 | polling | 94695.0 | 1.301 | 2.81 | 6625.2 |
| static | 1 / 1 | polling | 163648.0 | 0.640 | 1.48 | 6490.2 |
| static | 1 / 2 | readiness | 154485.3 | 0.686 | 1.71 | 6653.2 |
| static | 1 / 3 | readiness | 151312.8 | 0.702 | 1.81 | 6654.4 |
| static | 1 / 4 | polling | 164442.2 | 0.631 | 1.57 | 6493.1 |

### h3-transport-choice32k-v1

| Case | Cycle / position | Setting | Responses/s | p99 ms | Process CPU us/response | User instructions/response |
|---|---:|---|---:|---:|---:|---:|
| pagecache | 1 / 1 | batch4_gso10 | 10644.1 | 21.054 | 93.82 | 266301.8 |
| pagecache | 1 / 2 | batch1_gso20 | 11503.3 | 22.888 | 88.82 | 263567.5 |
| pagecache | 1 / 3 | batch1_gso20 | 8601.4 | 40.191 | 111.27 | 263875.1 |
| pagecache | 1 / 4 | batch4_gso10 | 10271.9 | 25.825 | 98.18 | 266345.1 |
| static | 1 / 1 | batch4_gso10 | 10593.9 | 21.030 | 95.45 | 264175.3 |
| static | 1 / 2 | batch1_gso20 | 13484.3 | 18.062 | 77.09 | 261234.6 |
| static | 1 / 3 | batch1_gso20 | 12877.8 | 17.311 | 77.91 | 261273.7 |
| static | 1 / 4 | batch4_gso10 | 11512.5 | 21.994 | 85.64 | 264107.4 |

### h3-transport-page32k-confirm-v1

| Case | Cycle / position | Setting | Responses/s | p99 ms | Process CPU us/response | User instructions/response |
|---|---:|---|---:|---:|---:|---:|
| pagecache | 1 / 1 | batch4_gso10 | 11850.7 | 19.402 | 82.60 | 266137.5 |
| pagecache | 1 / 2 | batch1_gso20 | 14802.3 | 14.797 | 67.40 | 263477.9 |
| pagecache | 1 / 3 | batch1_gso20 | 9844.2 | 39.102 | 88.67 | 263534.0 |
| pagecache | 1 / 4 | batch4_gso10 | 13613.6 | 15.354 | 77.87 | 266123.4 |
| pagecache | 2 / 1 | batch4_gso10 | 12271.7 | 17.709 | 79.47 | 266183.3 |
| pagecache | 2 / 2 | batch1_gso20 | 13176.7 | 17.885 | 75.73 | 263249.9 |
| pagecache | 2 / 3 | batch1_gso20 | 13613.3 | 27.770 | 75.60 | 263448.1 |
| pagecache | 2 / 4 | batch4_gso10 | 12940.6 | 18.536 | 85.80 | 266194.5 |
| pagecache | 3 / 1 | batch4_gso10 | 14293.4 | 18.666 | 68.67 | 266307.1 |
| pagecache | 3 / 2 | batch1_gso20 | 17259.6 | 14.853 | 59.53 | 263496.3 |
| pagecache | 3 / 3 | batch1_gso20 | 16774.8 | 14.232 | 58.47 | 263321.2 |
| pagecache | 3 / 4 | batch4_gso10 | 14714.6 | 19.548 | 69.80 | 266122.6 |
