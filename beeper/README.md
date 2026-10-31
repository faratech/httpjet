# Beeper research for HTTPJet

Research snapshot: **31 October 2026**. Integration and benchmarking are ongoing.

This work builds on [Beeper](https://github.com/lerboe/beeper) and
[hyper-fast-path](https://github.com/lerboe/hyper-fast-path) by
[Laurin Brandner (@lerboe)](https://github.com/lerboe). Beeper provides the H1/H2
parsing research and implementation that motivated these experiments. The H3
execution changes described here are HTTPJet work around Quinn; they do not
attribute QUIC termination or an HTTP/3 parser to Beeper.

The question is practical: how much useful work can kernel assistance remove
when the comparison server already has a static-body cache, a finished-response
memo and an origin page cache?

The [30 October continuation](continuation-2026-10-30.md) records the subsequent
Rust parser, H1/H2 serving and H3 transport work. The earlier measurement tables
below remain evidence for their original binaries, not the latest build.

The [complete 30 October matrix](final-matrix-2026-10-30.md) and its per-arm CSV
cover the corrected Candidate C against both the exact release and a native
source rebuild.

The [candidate C PGO experiment](../docs/performance/beeper-pgo-c6ac-2026-10-30.md)
records the next build comparison. Its instrumented build and training are
separate from performance qualification.

The [completed same-source PGO pilot](pgo-pilot-2026-10-30.md) measures the compiler
profile separately. The [completed PGO release matrix](pgo-release-2026-10-31.md)
then compares the integrated build with the shipped release.

The [matched-load H2 follow-up](h2-pgo-rate-2026-10-31.md) measures CPU and latency
at 15,000 requests/s on the same PGO build, with kernel serving off and on.

The [H2 ownership and pin-limit checkpoint](h2-quiescent-owner-2026-10-31.md)
records the source fixes and their controlled non-PGO experiment. The
[fresh PGO follow-up](h2-quiescent-pgo-2026-10-31.md) now qualifies the combined
implementation: server/helper CPU and p99 improve, while lower-load whole-VM
CPU remains higher. Optimization continues.

The [packet-preparation regression](h2-packet-preparation-2026-10-31.md) explains
a stress failure in the next certified-header candidate and its correctness
repair at its earlier evidence checkpoint.

The [repaired PGO follow-up](h2-repaired-pgo-2026-10-31.md) now validates that
application across all 11 correctness gates and 96 matched-load benchmark arms.
Process CPU and tail latency improve across H1, H2c and H3; whole-VM CPU remains
higher for static H1/H2c traffic. The proposed Unix send hook is not part of those results.

## Findings so far

- **Quiescent H2 ownership fixes the tested process-CPU and tail regressions.**
  The fresh PGO study validates 120 arms and 17.28 million measured responses.
  Against the same binary in native mode, capacity rises 77–89% and p99 falls
  22–25%; at 15,000 requests/s process CPU falls about 59%. Whole-VM CPU at
  that lower load instead rises 2.2% for static and 17.3% for page-cache
  traffic, so an overall CPU win remains unproven. The source fixes are
  committed; further kernel parsing work remains experimental.
- **The PGO release matrix improves every tested throughput median.** All 48
  million measured responses validated across 20 cells. Relative to the exact
  shipped v0.1.10-11, throughput medians rose 5.6–231.1% and process CPU per
  response fell in all cells. Arm p99 fell in 18 cells; 1 KiB H2c kernel serving
  instead raised static p99 101.7% and page-cache p99 3.2%. These are combined
  runtime/build effects, with all caches enabled; kernel work outside the process
  is not included in the process CPU result. The matched-load H2 follow-up is
  separate from this capacity matrix.
- **The earlier PGO build favored native H2 at the tested lower load.** At 15,000
  requests/s with 1 KiB bodies, native process CPU is 19.9% below the release for
  static content and 43.6% below it for page-cache hits. Kernel H2 instead costs
  52.6–56.3% more process CPU than native PGO H2 and has higher service p99.
  Both kernel groups record about 97.9% offload hits. Scheduled p99 is mixed,
  and bounded admission reached its cap in 7 of 36 arms. Kernel H2 remains an
  opt-in capacity option; the runtime default is unchanged.
- **The corrected C matrix is complete, with mixed results.** All 96 million
  measured responses validated. Against the exact shipped release, page-cache
  throughput medians improved by approximately 17–230%, while several static
  cells remained about 4–7% slower. Build/profile effects and CPU/latency
  tradeoffs remain explicit; the subsequent profile-guided pilot is reported
  separately.
- **PGO improved every static throughput median in its same-source pilot.**
  All 12 million measured responses validated. Median throughput increased
  4.6–49.9% and process CPU per response fell 4.4–32.8%. Eight cells improved
  throughput in every cycle. The 32 KiB H2c result varied sharply and its pooled
  p99 rose 9.6%; 32 KiB H2-TLS had one slightly negative throughput cycle.
  This pilot does not compare against the release or establish whole-system
  CPU savings.
- **Cache-aware comparisons matter.** The 29 October H3 matched native-PGO matrices
  show descriptive median throughput gains of approximately 55%, 100%, 13% and
  11% for 1 KiB static, 1 KiB page cache, 32 KiB static and 32 KiB page cache.
  All 14.4 million measured responses validate. Exact shipped-binary matrices
  also show conditional gains, but include build/profile effects. Repeated
  arms reveal drift and worse 32 KiB static p99; broad superiority is unproven.
- **Matched offered-load latency is mixed.** At 2,500 requests/s and 32 KiB,
  accelerated dispatch has lower scheduled p99 than bridged dispatch in both
  repetitions of both cache fixtures. The 1 KiB results overlap or drift.
  Admission is bounded; these are not unrestricted open-loop measurements.
- **Moving only response bodies into BPF did not pay.** A native-owned SK_MSG
  experiment kept HTTP processing in userspace and expanded selected bodies in
  the kernel. Even after eliminating per-hit map syscalls, server-thread CPU
  was higher in both tested sizes. That tier was removed from compiled code.
- **CID steering is separate from request acceleration.** Scoped eBPF routing
  selected the owning QUIC worker correctly. A separate on/off comparison did
  not establish a throughput gain on this loopback topology.
- **Correctness controls changed the implementation.** Large transfers exposed
  lost runnable QUIC work at a cooperative scheduling limit. Shutdown testing
  also required retaining response state until FIN acknowledgement. The revised
  optimized H3 engine passed delivery, cancellation and bounded-drain controls.

See [measurements](measurements.md) for individual arms, failures, hashes and
measurement limits, and [design and methods](design-and-methods.md) for the
integration contracts and remaining work.

## Current integration status

| Area | Evidence and remaining work |
|---|---|
| H1 | Experimental plaintext kernel cache serving, raw User-Agent identity, ordered fallback and safe late enrollment have live correctness evidence. HTTPS retains native TLS. Candidate C's full comparison is published; static-file weaknesses remain. |
| H2 | Plaintext kernel serving has HPACK, flow-control, expiry, ownership and lifecycle evidence. Quiescent receive ownership and multiplexed pin bounds lower process CPU and p99 in the fresh PGO study; lower-load whole-VM CPU remains higher. Known oversized bodies avoid publication work; unsupported input and HTTPS retain native ownership. |
| H3 | Shared on-core cache dispatch, owned payload transfer, bounded scheduling and response-drain fixes are implemented experimentally. A pinned Quinn UDP fork adds optional sendmmsg batching. Quinn owns QUIC/TLS and io_uring supplies packet I/O. |
| Optional routing | CID-aware reuseport steering has functional evidence. Migration and state-preserving restart remain outside its qualification. |
| Release comparison | The exact v0.1.10-11 archive is pinned. Candidate C completed 40 cells against that archive and a native-source rebuild. The PGO integration then completed 20 release cells with higher throughput and lower process CPU medians throughout; H2c tail-latency and CPU-scope limits remain explicit. Earlier failed attempts remain retained. |

All runtime experiments use **SINGULARITY** and literal loopback destinations.
No public origin or CDN is a load-test target. Results include unsuccessful and
unprofitable experiments; no production-wide CPU saving is established.

## Scope of this publication

This directory publishes research notes and condensed measurements. Some
prototype variants have not yet been published as independently buildable
source. Their recorded identities distinguish experiments, but do not make a
public release checkout sufficient to reproduce every variant. The methods and
data should be read with that limitation.

The integrated prototype meets this study's throughput and process-CPU target
across the full release matrix while retaining native io_uring fallback.
Qualification remains limited to the tested SINGULARITY fixtures; universal
latency, whole-system CPU and production-site superiority are not established.
Kernel H2's measured lower-load tradeoffs remain explicit. No production
deployment is part of this work.
