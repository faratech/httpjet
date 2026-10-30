# Beeper research for HTTPJet

Research snapshot: **30 October 2026**. Integration and benchmarking are ongoing.

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

## Findings so far

- **Cache-aware comparisons matter.** Final H3 matched native-PGO matrices
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
| H1 | Experimental plaintext kernel cache serving, raw User-Agent identity, ordered fallback and safe late enrollment have live correctness evidence. HTTPS retains native TLS. The latest release comparison is incomplete. |
| H2 | Experimental plaintext kernel serving has live HPACK, flow-control and native-handoff evidence. Unsupported input and HTTPS retain native protocol ownership. The latest release comparison is incomplete. |
| H3 | Shared on-core cache dispatch, owned payload transfer, bounded scheduling and response-drain fixes are implemented experimentally. A pinned Quinn UDP fork adds optional sendmmsg batching. Quinn owns QUIC/TLS and io_uring supplies packet I/O. |
| Optional routing | CID-aware reuseport steering has functional evidence. Migration and state-preserving restart remain outside its qualification. |
| Release comparison | The exact v0.1.10-11 archive is pinned. Earlier matrices are complete; the latest integrated matrix stopped on an H2 expiry-recovery qualification failure; it compares that archive separately from a matching native-source rebuild. General performance superiority remains unproven. |

All runtime experiments use **SINGULARITY** and literal loopback destinations.
No public origin or CDN is a load-test target. Results include unsuccessful and
unprofitable experiments; no production-wide CPU saving is established.

## Scope of this publication

This directory publishes research notes and condensed measurements. Some
prototype variants have not yet been published as independently buildable
source. Their recorded identities distinguish experiments, but do not make a
public release checkout sufficient to reproduce every variant. The methods and
data should be read with that limitation.

The remaining target is complete H1/H2/H3 integration, equivalent cache and
policy behavior, safe io_uring fallback, and repeated performance comparisons
against the latest release. Observation hooks and one fast fixture do not
complete that target.
