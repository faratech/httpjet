# Regression review of exact released-binary comparison

Derived from the unchanged 120 result JSON files covered by sealed receipt b9c25bc3. No new application execution or benchmark.

| Protocol | Fixture | Median after-RSS MiB: release | Candidate | Increase | Cycle changes |
|---|---|---:|---:|---:|---|
| h1 | pagecache | 48.939 | 66.840 | +36.58% | +39.62%, +31.25%, +40.69% |
| h1 | static | 45.404 | 63.205 | +39.21% | +41.46%, +38.44%, +34.87% |
| h2c | pagecache | 49.752 | 66.764 | +34.19% | +28.71%, +34.44%, +39.94% |
| h2c | static | 45.752 | 63.518 | +38.83% | +43.97%, +40.67%, +39.38% |
| h3 | pagecache | 60.193 | 64.236 | +6.72% | +8.73%, +4.18%, +9.56% |
| h3 | static | 57.949 | 61.682 | +6.44% | +4.51%, +7.20%, +3.31% |

All six increased-RSS cells increase in every paired cycle. Native TLS post-run RSS decreases in all cycles. Plaintext candidate helpers account for roughly 12.2–12.4 MiB RSS, with candidate web-process RSS also higher. Component medians need not add to the aggregate median.

RSS is the process-resident set after the whole client process. Plain kernel arms sum HTTPJet and helper RSS; shared resident pages can be double-counted. BPF maps and socket kernel memory are excluded. VmHWM is captured per process; summing high-water marks does not give a simultaneous aggregate peak. A short 1 KiB/32-connection run does not establish a leak or scaling at many workers/connections.

H1 TLS page-cache CPU: server 26.462→14.923 µs/response (−43.60%); client 38.620→39.456 (+2.16%); whole Linux VM 74.308→84.692 (+13.98%). Client cost increases in all three paired cycles (+1.84%, +5.63%, +1.21%). VM direction is mixed (+35.83%, +3.00%, −8.40%). Aggregate VM system-time medians increase 21.154→29.538 µs/response, softIRQ 21.538→26.846, while user time falls. Component medians are not additive.

Server/client and VM observations bracket the whole client process with sequential boundaries; PMU setup/stop fall between some boundaries. They are sufficiently related for a broad split, but VM minus process CPU is not an exact attributable kernel-work measurement. VM counters include unrelated Linux work; Windows is unobserved. No server or Beeper cause is established.

Whole-VM TCP retransmission diagnostic: H2c release 13 versus candidate 140 across 12 arms per role (780,000 completed responses per role including warmup). All captured TCP timeout, backlog-drop and spurious-RTO counters are zero. The counters are VM-wide, so the extra retransmissions are a signal requiring per-socket attribution, not a validated connection-loss regression. H3 kernel-counter deltas are absent and remain null, not zero.

No process-CPU, user-instruction or user-cycle regression in any of the 30 paired cells. Tiny throughput median differences at a capped 15,000 offered requests/s do not establish capacity change. Existing validation confirms all response/status/TLS/body checks and headroom gates passed. FD occupancy, PSS, BPF map/socket memory, process syscall counts, sustained leak behavior and large-cache/connection-scale regressions are not qualified by this dataset.

Suggested next checks on SINGULARITY: (1) reproduce H1 TLS whole-VM split with per-core/per-thread kernel profiles, keeping timing and instrumented diagnostic runs separate; (2) capture PSS, map and socket memory versus worker/connection/cache size to decide whether the 17–18 MiB plaintext and 4 MiB H3 overhead is acceptable; (3) attribute H2c retransmissions to actual benchmark versus dummy/control sockets; (4) run a bounded capacity/body-size/connection sweep only after repeatability is established.
