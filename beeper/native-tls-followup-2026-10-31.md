# Native HTTPS follow-up: cached pages improve, static H2 regresses

The encrypted-traffic follow-up found a material static H2 regression in the current experimental build: **10.20% more server CPU per response and 6.67% higher scheduled p99** than the freshly rebuilt production-source PGO control. Page-cache traffic improved for both protocols. These results are separate from the plaintext Beeper kernel-serving measurements; neither HTTPS arm uses a helper or kernel serving.

All 48 arms completed on SINGULARITY, using the same frozen C7 control `24ccc3a8…` and candidate `abf7a79c…`. Each cell has three ABBA cycles, warm 1 KiB responses, 60,000 measured plus 5,000 warmup requests per arm, and an offered 15,000 requests/s. The clients verify the fixture CA and negotiated protocol. Caches remain enabled; the candidate also enables its page-response memo. C7 is a new native PGO rebuild of historically attributed production source, rather than exact deployed `994127ae…` bytes.

| Protocol / fixture | Server CPU, C7 → candidate | Change | Scheduled p99, C7 → candidate | Change | Whole-VM CPU change |
|---|---:|---:|---:|---:|---:|
| H1 over TLS / static | 15.308 → 15.385 µs/response | +0.50% | 1.890 → 1.899 ms | +0.48% | **+19.65%** |
| H1 over TLS / page cache | 20.846 → 16.385 µs/response | −21.40% | 2.165 → 2.040 ms | −5.80% | −22.85% |
| H2 over TLS / static | 27.154 → 29.923 µs/response | **+10.20%** | 2.382 → 2.541 ms | **+6.67%** | **+7.43%** |
| H2 over TLS / page cache | 45.231 → 31.923 µs/response | −29.42% | 5.777 → 4.392 ms | −23.98% | −24.03% |

Static H2 CPU worsened in every cycle; its p99 worsened in cycles 2 and 3. Static H1 TLS was essentially flat in the arm medians and varied by cycle. Page-cache CPU fell in all three cycles for both protocols, but H1 page-cache p99 worsened in one cycle. H2 page-cache CPU, p99 and VM busy improved in every cycle. The ratio of six-arm medians is distinct from each cycle's two-arm-median ratio. [Arm records](../docs/evidence/native-tls-20261031/arms.csv), [all cycle directions](../docs/evidence/native-tls-20261031/cycles-percent.csv).

Independent validation checked 2,880,000 measured responses, 240,000 completed warmups and all 3,120,000 raw latency rows. All exact body/status, TLS, PMU, client-headroom, zero-offload, exit and source/profile/artifact-integrity checks passed. All four sampled compiler monitors were clear. Admission waits affected 29 arms, totaling 4,742; H1 had 32 slots and H2 had 128. This is bounded offered-load measurement, rather than unrestricted open-loop traffic or a capacity test. [Sealed receipt](../docs/evidence/native-tls-20261031/receipt.json).

Server CPU is user plus system time for one process across all 65,000 responses per arm. PMU covers user mode. VM busy time includes clients and unrelated Linux activity; Windows-host work remains unobserved. Reported p99 is the median of six arm p99 values. The nine forum preview/test containers were closed after this experiment finished. Future comparisons use fresh controls under that new background-service state. [Post-run context](../docs/evidence/native-tls-20261031/post-run-context.json).

## Investigation, not yet a fix

The H2 static regression is mainly user CPU: its median rises 22.22%, while system CPU rises 1.79%. User instructions rise 1.86% and user cycles 13.99%. Those counters do not establish whether code layout, memory stalls, scheduling or another effect caused the regression. Component medians need not sum to the median total.

The crypto dependency versions and complete monoio, monoio-rustls and hj-tls source trees match between controls. Their effective native C compiler flags have not been fully matched: C7 explicitly sets native/frame-pointer CFLAGS, while the candidate leaves them unset. That is a possible controlled build experiment, not an established cause.

Source inspection also found an extra captured-response async wrapper in native H2 even when TLS has no kernel owner or capture inbox. A separate one-function experiment selects a direct native service future while preserving active kernel capture and read-ownership machinery. It requires fresh PGO and paired qualification before any performance claim or promotion. [Source and CPU-split investigation](../docs/evidence/native-tls-20261031/cause/FINDINGS.md).

The optional Unix send-hook prototype is a different experiment. It targets the existing kernel carrier's socket overhead and has no measured gain in these results. No production deployment or host-kernel replacement is implied.

Credit to [Laurin Brandner (@lerboe)](https://github.com/lerboe), [Beeper](https://github.com/lerboe/beeper) and [hyper-fast-path](https://github.com/lerboe/hyper-fast-path), whose H1/H2 parsing work informed the wider experiment.
