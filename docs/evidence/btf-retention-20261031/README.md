# First BTF-retention experiment: compact publication evidence

This directory retains the rejected first scoped-BTF candidate, not the later
canonical-table timing study. Both original independent dataset seals pass;
the original functional qualification remains failed and the candidate was
not promoted. See the accompanying beeper/btf-retention-2026-10-31.md report.

initial72/ and confirmation24/ contain byte-identical reviewed compact CSVs,
their original receipt.json and summary-seal.json. Each source seal binds a
private raw manifest and independent auditor hash; raw latency TSVs, memory
rollups, fixture TLS material, source trees, executables and archives are not
published here. The confirmation seal retains the original 72-arm receipt hash.

publication-review.json records selected source hashes and recomputation of
all compact group medians/change ratios. It does not claim to rerun the raw
latency audit. provenance.json pins measured app/helper/BPF artifacts and
changed source hashes. Its canonical follow-up field is a coordinator-supplied
progress boundary, not a result included in either published timing dataset.

CPU/PMU/VM denominators are 65,000 (initial) and 205,000 (confirmation), including
warmups. Latency denominators are 60,000 and 200,000 measured responses. Memory
is sequential post-client smaps_rollup; kernel allocations and cold peaks are
unmeasured. Helper private memory is not whole-engine RAM. All negative arm,
cycle and admission values remain. No measured arm was excluded or rerun.
