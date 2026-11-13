# H2 kernel ownership and response-pin limits: interim results

Research checkpoint, **31 October 2026**. All builds and runtime experiments ran
on **SINGULARITY**. Fresh PGO qualification and the final native-PGO comparison
remain pending.

The [earlier matched-load PGO study](h2-pgo-rate-2026-10-31.md) exposed a real
CPU regression at 15,000 requests/s: native H2 used **17.69/17.23 µs per response**
for static/page-cache traffic, versus **27.00/26.92 µs** with kernel H2 enabled.
Lower user-mode instruction counts did not mean lower process CPU.

## Keeping native receives out of kernel-owned intervals

Separate kernel samples found substantial web-process work in
`tcp_bpf_recvmsg_parser`, `tcp_poll`, `io_recv` and io_uring poll/submission paths.
Source inspection found a native rental receive remained submitted while the
kernel owner was active. This supports a receive/poll-churn hypothesis; sample
counts themselves are diagnostic, not a performance comparison.

Owner source **`39fad6a4`** now borrows a never-polled `ReadPollFence` witness
through arming, parking and adoption. A started receive declines kernel ownership
without cancellation. A duplicated socket descriptor supplies persistent,
non-consuming readiness; `MSG_PEEK|MSG_DONTWAIT` distinguishes data, EOF and
spurious wakes. Maintenance retains an absolute 20 ms deadline, with a 1 ms
spurious-wake backoff. Stream IDs and connection credit are adopted before native
input or shutdown output resumes.

## A measured H2 reference-cap failure

H2 inherited H1's **64-reference limit per response image**. New diagnostics
distinguish cap exhaustion from stale/closed gates and CAS retry exhaustion.
The controlled diagnostic runs attributed the observed pin failures to the cap.

H2 now permits **64 connections × 16 outstanding batches × 8 responses = 8192**
references per image, including the selecting batch. This bounds healthy queue
occupancy; it does not prove that references cannot become stranded. The hard
limit still fails closed. H1 remains at 64; gate version checks, eight CAS
attempts, map/serving ABI, HPACK, ACK and flow-control behavior are unchanged.

Pin-limit source is committed as **`cc48622d`**. The [independent audit](../docs/evidence/h2-quiescent-20261031/pin-limit-audit.json) retains every arm, source hash and cycle.

The matched pin-limit experiment used one unchanged non-PGO V2 server and two
helpers built with the same non-PGO native/frame-pointer recipe. Only H2's pin
limit differed. Three ABBA cycles per fixture produced **24 valid arms, 4.8 million
measured responses and 240,000 warmups**, with caches enabled and warmed, 1 KiB
bodies, 32 connections and four streams. Both endpoints used `127.0.0.2` over
Linux loopback. Body/status, PMU and client-headroom checks passed; the observer
reported no compiler overlap.

| Fixture | Pin limit | RPS | Arm p99 ms | Process CPU µs/R |
|---|---:|---:|---:|---:|
| Static | 64 | 175,975 | 4.959 | 4.024 |
| Static | 8192 | 174,389 | 4.079 | 3.500 |
| Page cache | 64 | 154,325 | 5.563 | 4.571 |
| Page cache | 8192 | 164,774 | 4.322 | 3.667 |

These are six-arm medians, including medians of arm p99 values. CPU and p99
fell in every cycle. Static throughput's aggregate decline includes opposite
cycle directions: **+9.80%, +3.10%, −12.10%**. Page-cache throughput rose in all
three cycles. The 8192 variant recorded zero reference-cap denials.

Process CPU includes server/helper user+system time over the client span,
divided by 210,000 responses per arm. It excludes kernel/IRQ work charged
elsewhere; user-mode PMU excludes that work too. These results do not establish
whole-server CPU savings or superiority over native PGO H2.

## Qualification and component identity

V2 ownership with the prior **`1cce1f3c…` helper** passed expiry and four
handoff/shutdown/helper-failure lifecycle cases. The wide helper with V2 passed
the 16-case H2 corpus and H1/H2 user-agent policy checks. Final PGO qualification must validate the
combined artifacts again.

The V2 server SHA256 is `1c21f69c…f3eb3feb`; diagnostic-64/wide helpers are
`711e9b25…fde223` / `f1e69cbb…33ede89`. The selected wide `h1_serve` ELF is
`353abef9…29b16`. These component identities are separate from the pending
fresh PGO binaries.

This research builds on [Beeper](https://github.com/lerboe/beeper) and
[hyper-fast-path](https://github.com/lerboe/hyper-fast-path) by
[Laurin Brandner (@lerboe)](https://github.com/lerboe).
