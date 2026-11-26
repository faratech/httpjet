# Patched upstream crates

These directories use exact crates.io releases or the pinned upstream revisions below,
with HTTPJet changes layered on top. Cargo cannot
deduplicate SemVer-incompatible requirements without changing the dependent crate's manifest, so
the workspace patches them locally until upstream releases accept the newer dependency lines.

The path patches are a binary-workspace integration mechanism: crates published independently do
not inherit a consumer's top-level `[patch.crates-io]`. Do not publish these fork directories under
the upstream package names, and remove or upstream the patches before publishing workspace crates.
Each patched package is also pinned with an exact `=` requirement so a future compatible crates.io
release cannot silently outrank and bypass the local fork during `cargo update`.
The dependency update script excludes the forks and their coupled Flume, Nix, and Hashbrown lines;
upgrade each pair together so the deduplicated graph cannot silently split again.

| Crate | Upstream release | crates.io source revision | Local patch |
|---|---:|---|---|
| `dashmap` | 7.0.0-rc2 | `366ce7e7872866a06de66eb95002fa6cf2c117a7` | Hashbrown 0.15 to 0.17.2; preserve `inline-more`; calculate optional `typesize` accounting directly from Hashbrown 0.17 allocations; align the declared and standalone toolchain MSRV with Hashbrown 0.17's Rust 1.85 requirement. |
| `monoio` | 0.2.4 | `f7827ddd54e0a6c7e9d1805109df041fd101994b` | Flume 0.11 to 0.12.0 and Nix 0.26 to 0.32.0; declare the Nix `process` and `sched` features used by CPU affinity; remove a Rust 1.96-invalid `must_use` attribute from a trait implementation; suppress upstream internal dead-code warnings in feature-subset builds.; MULTISHOT op support (#334): a `MultiShot` slab lifecycle that bounds pending owned accept completions to 64 per stream (plus one terminal error without a descriptor) and immediately closes excess descriptors, preserving terminal completion and cancellation, and queues per-CQE results while `IORING_CQE_F_MORE` is set (detached streams close owned fds instead of leaking them; the terminal CQE frees the slot; drop cancels the armed SQE via AsyncCancel), a `MultiOp<T>` handle with `poll_next_completion`, an `AcceptMulti` op (no per-connection sockaddr — callers use getpeername), and `TcpListener::accept_multi()` returning an `AcceptMultiStream`; io_uring driver only, the legacy driver reports `Unsupported`; set `SOCK_CLOEXEC` atomically on regular and multishot io_uring accepts so accepted client sockets cannot leak through a concurrent process spawn; port the driver to io-uring 0.7 (generic `Builder<S, C>` defaults, 2026-09 dependency refresh) with the multishot lifecycle re-applied unchanged; make Unix `SharedFd::try_unwrap` move its valid driver state out of a `ManuallyDrop` instead of constructing an invalid uninitialized enum, and apply the same ownership-transfer pattern to `UnixListener::into_raw_fd`; disable the TCP-oriented default `SO_REUSEPORT` option in `UnixListener::bind`, since Linux rejects it for AF_UNIX; lift Socket2 0.5 to 0.6 (TCP_NODELAY accessors renamed `tcp_nodelay`/`set_tcp_nodelay`) and the legacy driver's Mio 0.8 to 1.x, and replace the unmaintained fxhash with rustc-hash 2 for the runtime's FxHashMap caches (2026-10 dependency refresh); expose `TcpStream::set_tcp_user_timeout` (Linux, via the existing Socket2 `all` dependency) so httpjet can bound unacknowledged sends, including zero-window probing (2026-10-13 audit). |
| `monoio-rustls` | 0.4.0 | `30c43d9bcdc3a3f2ecbd193be0f262e2a9b1d922` | Lift thiserror 1 to 2 (2026-10 dependency refresh); implement owning-buffer `writev` instead of the upstream first-iovec-only stub so native HTTP/2 vectored flushes remain correct and efficient; include the upstream dual-license texts omitted from the crates.io package.; allocate the ciphertext write buffer uninitialized (#349) — the Buffer's read/write invariants never expose an unwritten byte, and the 64 KiB-per-accept (512 KiB burst-growth) zero fill was pure handshake-path cost; represent that storage as `Box<[MaybeUninit<u8>]>` and expose only its initialized prefix, preserving the no-zero-fill optimization without creating an invalid initialized slice; hold no write buffer while idle (#494): a flushed 64 KiB buffer returns to a per-thread pool (cap 32) and the next write takes a warm one, a burst-grown buffer is freed, and a buffer an io_uring write owns (`None`) is never released; send every queued record in one socket write (#971): the write buffer implements `write_vectored`, copying further records only whole and only into space it already holds, and the pooled buffer is sized for a full 64 KiB rustls batch (four records plus framing); drop the upstream `connect` example and its dev-dependencies so `cargo test -p monoio-rustls` can run the fork's tests from the workspace; drop the unused `bytes` dependency (rustc `unused_crate_dependencies`); a write future dropped mid-flight (a read that flushed alerts, cancelled by a shutdown select) leaves no buffer, and every later write/flush/do_io returns `BrokenPipe` instead of panicking on `expect` (#1050).; `writev` converts up to 64 iovecs to plaintext slices on the stack (was 8), so a native HTTP/2 flush batch builds no descriptor `Vec`, and an empty iovec becomes an empty slice instead of a slice over a possibly null base. |
| `pprof` | 0.15.0 | `c2d6e7b9aa0abf405fcd435d949e6502771fbce0` | Nix 0.26 to 0.32.0; retain one process-lifetime `OwnedFd` validation pipe initialized before sampling, eliminating the upstream atomic close/reopen race while keeping signal-time checks allocation-free; probe candidate addresses through the raw write(2) pointer without first constructing an unvalidated Rust slice; prefer the frame-pointer backend when both alternative unwinder features are present so Cargo's all-features validation is well-defined; make elided output lifetimes explicit for Rust 1.97 lint cleanliness; drop the unused `cfg-if` and `prost-derive` dependencies (rustc `unused_crate_dependencies`; the generated protobuf types derive through `prost`). |
| `rustls` | 0.23.46 | `f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb` | Transfer a bounded batch of already encoded TLS records to the owning transport. The record layer still controls encryption, ordering, and keys. Keep the borrowed descriptors for a two-slice plaintext write on the stack. A single queued record uses one descriptor for the ciphertext write. |

## Current upstream bases

Use the crate's package directory within the upstream tree. The versions in
Cargo remain exact pins even when the source incorporates unreleased commits.

| Fork | Upstream repository | Current base | Package directory |
|---|---|---|---|
| `dashmap` | `xacrimon/dashmap` | `366ce7e7872866a06de66eb95002fa6cf2c117a7` | `.` |
| `monoio` | `bytedance/monoio` | `8675e9406ea7943c441d969e38c3f5fc198ef6d1` | `monoio/` |
| `monoio-rustls` | `monoio-rs/monoio-tls` | `30c43d9bcdc3a3f2ecbd193be0f262e2a9b1d922` | `monoio-rustls/` |
| `openssl` | `rust-openssl/rust-openssl` | `321ba6c2877ecdd475e4a43043ea8f8f0500e37a` (crates.io 0.10.82) | `openssl/` |
| `pprof` | `tikv/pprof-rs` | `01cff82dbe6fe110a707bf2b38d8ebb1d14a18f8` | `.` |
| `quinn-udp` | `quinn-rs/quinn` | `0f9432f7c1cab0ea1469d02a935a89dae28693b7` | `quinn-udp/` |
| `rustls` | `rustls/rustls` | `f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb` | `rustls/` |

Rebase the rustls and monoio-rustls receive changes together. Rustls exposes
`Reader::read_into_spare` for the adapter. Both adapter read paths publish only
the prefix that rustls initialized.

Monoio's multishot accepts share upstream's `MaybeFd` ownership model.
A discarded result closes its descriptor on drop. Multishot completions are
handled before upstream's `SEND_ZC` notification logic. pprof uses SHA-2 0.11
for the build-time proto checksum, removing the old `generic-array` chain.
The OpenSSL fork implements `foreign-types` 0.5 using the existing wrapper
names and pointer layout. It uses upstream `openssl-sys` 0.9.118. The crate
source contains no upstream private-key fixtures. To run its tests, copy the
fork to scratch, restore the `test/` directory from the verified 0.10.82
crate archive, and extract the PEM string in its original `src/pkey_ctx.rs`
into `test/httpjet-upstream-pkey-ctx.pem` in the scratch copy.

The Rustls queue transfer and the Monoio Rustls writer are one change. Replay
them together whenever either upstream base changes. The I/O adapter owns each
detached batch until the write completes. A canceled or failed write closes the
stream. Smaller batches use the existing buffered path. On AArch64, select
owned batches after a large application write so the ordinary split flush keeps
its buffered path.

## Repeat a refresh

1. Obtain clean snapshots of the recorded base and the proposed new revision
   from upstream. Verify the full Git commit IDs before exporting them (or use
   verified crates.io archives for a published release). Use the same snapshot
   format for both inputs. Use the package directories from the table.
2. Run `python3 scripts/rebase-vendor.py CRATE OLD_CRATE_DIR NEW_CRATE_DIR /var/tmp/NEW_STAGE`.
   It copies the result to `NEW_STAGE/crate`, preserving local-only files and
   three-way merging tracked files. Resolve every entry in `conflicts.txt`.
   Review upstream additions and renames against the staged result.
3. Review `Cargo.upstream.diff` and carry forward relevant manifest changes
   in the normalized local manifest, including new features, targets and
   dependencies. Keep exact pins and coupled requirements in sync. Update
   the base table and any crate-specific provenance. Apply the reviewed result
   to the checkout, including reviewed deletions. Keep upstream test keys and
   `*.orig` files out of the export.
4. Refresh all affected lockfiles. Check the resolved vendor paths and
   duplicate dependency lines, run RustSec and the license check, and rerun
   the workspace, vendor, and affected loopback protocol gates. If upstream
   has adopted all local behavior, remove the patch only after those gates
   also pass against the upstream release.

## quinn-udp 0.6.3 (experimental H3 send batching)

Pinned with `try_send_batch` for Linux/Android. Preserves scalar ancillary and
GSO fallback behavior, and reports only accepted prefixes. See
[`quinn-udp/HTTPJET-VENDOR.md`](quinn-udp/HTTPJET-VENDOR.md). The crates.io
`Cargo.toml.orig` is not kept: Debian's `dh_clean` deletes `*.orig` files, which
changed the release source tree under the package build.
