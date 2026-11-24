# Matched-rate cached-response results

All rows use warm 1 KiB responses at a fixed 15,000 requests/s. Each value is the median of six arms; p99 is a median of arm p99 values. These are latency and CPU results, not measured throughput-capacity multipliers.

| Comparison | Protocol | Fixture | Process CPU us/R, baseline → candidate | CPU change | Scheduled p99 us, baseline → candidate | p99 change | VM busy change |
|---|---|---|---:|---:|---:|---:|---:|
| C7 source | H1 | Static | 16.308 → 6.538 | -59.91% | 2163.460 → 1759.193 | -18.69% | +13.41% |
| C7 source | H1 | Page cache | 19.615 → 6.308 | -67.84% | 2234.497 → 1743.666 | -21.97% | -20.74% |
| C7 source | H2C | Static | 16.538 → 7.385 | -55.35% | 2188.387 → 1791.024 | -18.16% | +4.54% |
| C7 source | H2C | Page cache | 21.846 → 6.923 | -68.31% | 2456.315 → 1742.952 | -29.04% | -4.53% |
| C7 source | H3 | Static | 55.077 → 29.000 | -47.35% | 12690.350 → 2784.477 | -78.06% | -18.78% |
| C7 source | H3 | Page cache | 49.308 → 36.077 | -26.83% | 7299.858 → 4969.950 | -31.92% | -27.00% |
| Same USE | H2C | Static | 16.538 → 7.077 | -57.21% | 2177.307 → 1738.265 | -20.16% | +1.57% |
| Same USE | H2C | Page cache | 17.846 → 6.615 | -62.93% | 2298.709 → 1735.653 | -24.49% | -1.07% |

Process CPU includes server plus helper user+system for H1/H2 kernel arms; H3 uses the accelerated native engine without the helper. Whole-VM busy CPU includes the clients and unrelated Linux work; Windows-host work is unobserved. Static H1/H2 VM increases remain negative findings.

All 24 fixture/cycle comparisons improve process CPU and scheduled p99, with substantial cycle-to-cycle variation in H3 tail-latency gains. Admission waits occur in 37 arms, totaling 19,340: H1 uses 32 slots; H2/H3 use 128. Most waits are in the native H3 baseline. This is bounded admission, not unrestricted open loop.

The clients completed 5.76 million measured and 480,000 warmup responses. The raw TSV audit covers 6.12 million rows because H3 does not emit its 120,000 warmup rows or per-row status; its expected status/body validity and warmup completion are checked in the validating client summaries.

C7 is a fresh native rebuild of historically attributed production source, not proof of the original deployed994127 build inputs. Same-USE H2 keeps the exact candidate application on both sides. Full before/after inputs and all eight sampled compiler monitors are sealed in receipt.json.
