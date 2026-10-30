# Profile-guided build of candidate C

This experiment follows the [completed, non-PGO matrix](../../beeper/final-matrix-2026-10-30.md).
That matrix established large page-cache and H3 capacity gains, but retained
static-file regressions against the shipped release. PGO is a separate build
experiment intended to address those remaining costs. It does not change the
runtime implementation or turn a training run into a benchmark.

All build, training, correctness and timing work runs on **SINGULARITY**. Network
fixtures bind both endpoints to `127.0.0.2`, use generated configuration and
content, and leave production listeners, PHP pools and cache directories alone.

## Frozen inputs

- Runtime source: candidate C, including the early H2 oversized-body admission
  guard. The verified reference binary is
  `6ac144f2449750d6063963c0994f30c933c11df8e8dbfa548b1a7b4a71e51e8f`.
- Source root:
  `/var/tmp/httpjet-continuation/h2-oversize-c-ed7a4fda/src`; the flat
  `build-source-manifest.json` beside it pins the source files.
- PGO root: `/var/tmp/httpjet-continuation/pgo-c6ac-v1`.
- Rust/Cargo 1.99.1 and matching LLVM/llvm-profdata 23.1.1. Release opt-level 3,
  thin LTO, one codegen unit, panic abort, native CPU and frame pointers.
- Stock registry rustls 0.23.46. The rejected rustls allocation experiment is
  excluded.
- Four pinned, prebuilt BPF objects, serving ABI 5 and helper RPC ABI 2. Rust PGO
  does not optimize these objects.
- Offline, locked builds with two jobs. The server and three helper binaries are
  built together, into separate `target-gen`, `target-use` and `target-control`
  directories. C/C++ compiler flags are left unchanged in every build.

## Stages

The [stage scripts](../evidence/pgo-c6ac-20261030/stages) are retained with this
experiment's evidence. Run each stage separately; do not chain a training
failure into a profile-use build.

1. **Setup** requires the complete C summary and verifies source, fixture,
   harness and BPF hashes before copying the owned inputs.
2. **Generate** builds instrumented binaries and freezes them in `bin-gen`.
   `build-raw` contains possible build-script/proc-macro profiles and is excluded
   from runtime training.
3. **Train** runs 55 arms: native H1/H1 TLS/H2c/H2 TLS; polling and readiness H1
   offload; eligible H2 offload and oversized H2 native fallback; both H3 engines
   with scalar/batched transmission. Static, page-cache and Range fixtures cover
   1 KiB and 32 KiB bodies where applicable. Every response is checked. These
   instrumented throughput and CPU values are **not performance evidence**.
4. **Merge** requires clean server exits and a nonempty profile for each actual
   server PID, including servers started through the privileged H1 helper.
   It records profile paths and hashes before merging only runtime profiles.
   Eligible H2 arms must have real kernel hits; the oversized H2 arm must have
   neither kernel hits nor queued publication candidates.
5. **Inspect coverage** records observed function/branch coverage and the exact
   profile/input hashes in `coverage-review.json`. This is a technical inspection
   record, not a human approval requirement. Missing or mismatched coverage must
   be investigated before accepting a profile-use artifact.
6. **Use** builds with that reviewed profile. Control-flow/profile-hash mismatch
   diagnostics reject the artifact; missing-function diagnostics are retained
   for inspection. Frozen outputs go to `bin-use`.
7. **Control** builds the same source with the same options, without PGO, and
   freezes `bin-control`. The release/source baselines from the earlier matrix
   remain immutable; this profile must never be applied to their different code.

The older [f755 runbook](beeper-pgo-runbook-2026-10-30.md) describes an earlier,
unexecuted recipe. Its source, paths and training matrix are superseded here.
The build/generate/train/merge/use sequence and missing-function warning follow
the [rustc PGO documentation](https://doc.rust-lang.org/rustc/profile-guided-optimization.html).
This recipe retains its existing Cargo target configuration and isolates build
profiles in `build-raw`, rather than changing the target selection between builds.

## Acceptance and measurement

Successful training and compilation are prerequisites, not evidence of a win.
Before timing the profile-use binaries, rerun the protocol handoff, cache-isolation
and H3 shutdown checks against those exact frozen artifacts. Then compare them
with the same-source non-PGO control, with both caches enabled, using alternating
arms and the existing body/status, CPU-headroom and compiler-overlap checks.

Keep build, profile and feature effects distinct. A favorable PGO comparison
still needs a new comparison against the exact shipped release. Retain negative
cells, native fallback costs and latency results. The existing low-load H2
offload CPU/latency regression remains an open limitation unless a new matched
offered-load experiment demonstrates otherwise.

This synthetic profile covers the exercised paths, not real PHP workloads,
authenticated traffic, production content distributions or every cold/error
branch. H3 CID steering is not enabled by this training matrix.

## Recorded execution

The instrumented build completed successfully. Its four Cargo fingerprints
confirm the intended profile-generation flags and release profile; the copied
BPF objects match their pinned hashes. The instrumented server SHA-256 is
`e8efed0ee5a975956770ddb71e4a99d15f6fd0bb7bd811adea9d6144b2f5391e`.

All 55 training arms then completed successfully: 1,100,000 checked responses
and 85,000 warmup responses. The ledger identifies 55 server profiles and seven
helper profiles; every recorded process exited. H1 kernel and readiness counters
increased in their intended arms. H2's eligible arms recorded kernel hits, while
the oversized arm recorded zero hits and zero publication candidates. The
strict merge passed for all 62 attributed files.

The merged profile contains 29,484 records and 337,612 IR counter slots. The
coverage review found nonzero counters in native H1/H2 and TLS handlers, HPACK,
H3 pumping/transmission, cache lookup/memos and kernel handoff paths. Shared
library frequencies include both server and helper activity. All 712 records
whose symbols match `lsapi` are cold, consistent with the no-PHP fixtures.
These are IR execution counters, not source coverage percentages or CPU samples.

These are build/training milestones only. No PGO performance result is claimed
by these receipts.
