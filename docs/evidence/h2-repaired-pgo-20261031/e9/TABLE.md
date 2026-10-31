| Fixture | Process CPU us/R, native → repaired | Change | Scheduled p99 us, native → repaired | Change | VM busy us/R, native → repaired | Change |
|---|---:|---:|---:|---:|---:|---:|
| static | 18.538 → 7.615 | -58.92% | 2463.224 → 1826.822 | -25.84% | 88.462 → 93.538 | +5.74% |
| pagecache | 19.000 → 8.231 | -56.68% | 2427.944 → 1891.797 | -22.08% | 90.154 → 91.846 | +1.88% |

Six arm medians per fixture/arm. These are matched-rate latency/CPU results, not capacity gains. Process CPU includes server+helper user+system over all65,000 client responses per arm. VM busy includes clients and unrelated Linux work; Windows-host work is unobserved. Scheduled p99 is the median of six arm p99 values, not a pooled request quantile.
