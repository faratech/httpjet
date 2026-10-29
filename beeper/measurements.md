# Measurements and negative results

These are research results from the SINGULARITY lab, recorded on 2026-10-29. They
use generated content and isolated loopback fixtures. They do not establish a
general performance improvement over a shipped HTTPJet release. Earlier **v3**
measurements are historical checkpoints; **v5** includes later correctness and
scheduling changes. A final v5 cache-performance conclusion is deliberately
absent from this document.

## Comparators and artifact identity

**B** means the original runtime-source baseline rebuilt with native profile-guided
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
| v5 L and A | Experimental serving checkpoint `8bfc217150b69684d42f38182117c887b46c8651`; matched native PGO | `4a4dcd18caf297549ab839a529d80f2b23bc86e20d0095a1fa21d01b6156e210` |
| v5 H3 client | Failure-reporting revision of the validating client | `7ec8199c486dc10044b4c25760f14ad83506bab8ba067b7d20579e0f54c98fe2` |
| Exact shipped amd64 release binary | Extracted from the v0.1.10-11 static archive; not B in the timing tables | `3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec` |

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
cost. No final v5 cache-performance claim is made here.

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
