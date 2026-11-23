# Third-party notices

Third-party components keep their own licenses:

| Component | License | Location |
|---|---|---|
| dashmap | MIT | `vendor/dashmap/` |
| monoio | MIT OR Apache-2.0 | `vendor/monoio/` |
| monoio-rustls | MIT OR Apache-2.0 | `vendor/monoio-rustls/` |
| rust-openssl | Apache-2.0 | `vendor/openssl/` |
| pprof-rs | Apache-2.0 | `vendor/pprof/` |
| quinn-udp | MIT OR Apache-2.0 | `vendor/quinn-udp/` |
| rustls | Apache-2.0 OR ISC OR MIT | `vendor/rustls/` |
| LSAPI reference material | BSD-3-Clause | `crates/hj-lsapi/vendor/` |
| Moby default seccomp profile | Apache-2.0 | `packaging/oci/seccomp-httpjet.json` |

License texts remain with the vendored sources; local changes are summarized
in `vendor/PATCHES.md`. Run `python3 scripts/check-dependency-licenses.py` for
the locked Cargo dependency inventory. The rust-openssl wrapper macro
includes code adapted from foreign-types 0.3.2 under Apache-2.0.

Compatibility work used public documentation, black-box behavior, and
GPL-licensed OpenLiteSpeed source. No OpenLiteSpeed source tree is vendored.
The profiling feature emits raw pprof data and does not distribute the
CDDL-licensed `inferno` renderer.

The OCI seccomp profile is derived from `moby/profiles` commit
`61eaf32614c7c71b60bd8927d3e6a4ffc8ff1f31`. Its default allowlist is retained
and the three io_uring syscalls required by httpjet are added.
