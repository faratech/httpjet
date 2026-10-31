# Native TLS comparison on SINGULARITY

Fresh native PGO rebuild of historical production source C7 compared with the repaired ABF application. Both arms serve encrypted traffic natively; neither uses a helper or kernel serving. The candidate enables the page-response memo. These figures are separate from Beeper kernel-serving results.

All 48 arms passed exact body/status and TLS fixture checks. The audit verified all 3,120,000 raw latency rows (2,880,000 measured plus 240,000 warmup), all four compiler monitors, PMU running fraction 1.0, client CPU headroom, clean server/client exits, zero offload, and exact source/profile/artifact snapshots before and after.

| Protocol / warm 1 KiB fixture | Server CPU us/R C7 → ABF | CPU change | Scheduled p99 ms C7 → ABF | p99 change | VM busy CPU change |
|---|---:|---:|---:|---:|---:|
| H1 over TLS / static | 15.308 → 15.385 | +0.50% | 1.890 → 1.899 | +0.48% | +19.65% |
| H1 over TLS / page cache | 20.846 → 16.385 | -21.40% | 2.165 → 2.040 | -5.80% | -22.85% |
| H2 over TLS / static | 27.154 → 29.923 | +10.20% | 2.382 → 2.541 | +6.67% | +7.43% |
| H2 over TLS / page cache | 45.231 → 31.923 | -29.42% | 5.777 → 4.392 | -23.98% | -24.03% |

The static H2 CPU regression occurs in all three ABBA cycles (+5.32%, +7.46%, +4.35%); its p99 regresses in cycles 2 and 3 (−0.62%, +5.98%, +33.86%). Static H1 TLS is effectively flat in the arm medians and varies by cycle. Page-cache CPU falls in all three cycles for both protocols, but H1 TLS page-cache p99 regresses 5.21% in cycle 3. H2 page-cache CPU, p99 and VM busy all improve in every cycle. All cycle directions, including reversals, are retained in cycles-percent.csv.

These are matched-rate comparisons at 15,000 requests/s, not capacity measurements. Each cell uses three ABBA cycles with 60,000 measured and 5,000 warmup responses per arm; group values are medians of six arm values per role. H1 TLS admission is capped at 32, H2 at 128. Admission waits occurred in 29 arms (4,742 waits): H1 baseline 11/587, H1 candidate 12/290, H2 baseline 3/2,401 and H2 candidate 3/1,464. The saved VM-wide TCP counters contain 330 retransmissions and zero timeouts; they include unrelated traffic.

Server CPU is user plus system time for one server process, normalized across all 65,000 responses including warmup. User PMU excludes kernel, IRQ and hypervisor work. VM busy CPU includes clients and unrelated Linux activity, so it is not the server cost alone; Windows host work is unobserved. Scheduled p99 covers the 60,000 measured requests; service and dispatch p99 remain separate.

C7 is a new native rebuild of historically attributed production source, not an exact rebuild of the deployed 994127 binary. One-second compiler sampling cannot exclude sub-interval work. The nine forum preview/test containers were closed after this run completed; this study retains its earlier background-service context. Future hook comparisons need new controls after that closure.

The compact receipt and CSVs are derived from private raw evidence by recompute.py. No application, build or performance workload ran during this independent audit.
