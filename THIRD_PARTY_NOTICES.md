# Third-party notices

httpjet includes and depends on third-party software. The project license does
not replace those components' own license terms.

Compatibility work used public documentation, black-box behavior, and review
of GPL-licensed OpenLiteSpeed source. No OpenLiteSpeed source tree is vendored
in this repository.

## Vendored source

| Component | Version or basis | License | Location |
|---|---|---|---|
| dashmap | 7.0.0-rc2, locally patched | MIT | `vendor/dashmap/` |
| monoio | 0.2.4, locally patched | MIT OR Apache-2.0 | `vendor/monoio/` |
| monoio-rustls | 0.4.0, locally patched | MIT OR Apache-2.0 | `vendor/monoio-rustls/` |
| pprof-rs | 0.15.0, locally patched | Apache-2.0 | `vendor/pprof/` |
| LiteSpeed SAPI definitions and reference C implementation | PHP source distribution material | BSD-3-Clause | `crates/hj-lsapi/vendor/` |

The complete license texts are retained beside the vendored sources.
`vendor/PATCHES.md` records the upstream revisions and local changes. Files
modified from Apache-2.0 sources carry a prominent modification notice.

The LSAPI materials retain their original copyright and BSD notices. Neither
their inclusion nor protocol compatibility implies endorsement by their
authors.

## Cargo dependencies

The Rust dependency graph is pinned in `Cargo.lock`. Run
`python3 scripts/check-dependency-licenses.py` to inspect its generated license
inventory. Binary distributors must review the exact graph they ship and
reproduce every required notice. Optional features can change that graph.

The `profiling` feature emits raw pprof protobuf data. Rendering is deliberately
left to an external tool so the CDDL-licensed `inferno` renderer is not linked
into or distributed with httpjet.
