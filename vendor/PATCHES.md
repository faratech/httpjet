# Patched upstream crates

These directories are based on exact crates.io release sources with narrow dependency lifts. Cargo cannot
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
| `dashmap` | 7.0.0-rc2 | `366ce7e7872866a06de66eb95002fa6cf2c117a7` | Hashbrown 0.15 to 0.17.1; preserve `inline-more`; calculate optional `typesize` accounting directly from Hashbrown 0.17 allocations; align the declared and standalone toolchain MSRV with Hashbrown 0.17's Rust 1.85 requirement. |
| `monoio` | 0.2.4 | `f7827ddd54e0a6c7e9d1805109df041fd101994b` | Flume 0.11 to 0.12.0 and Nix 0.26 to 0.31.3; declare the Nix `process` and `sched` features used by CPU affinity; remove a Rust 1.96-invalid `must_use` attribute from a trait implementation; suppress upstream internal dead-code warnings in feature-subset builds.; MULTISHOT op support (#334): a `MultiShot` slab lifecycle that queues per-CQE results while `IORING_CQE_F_MORE` is set (detached streams close owned fds instead of leaking them; the terminal CQE frees the slot; drop cancels the armed SQE via AsyncCancel), a `MultiOp<T>` handle with `poll_next_completion`, an `AcceptMulti` op (no per-connection sockaddr — callers use getpeername), and `TcpListener::accept_multi()` returning an `AcceptMultiStream`; io_uring driver only, the legacy driver reports `Unsupported`.; PROVIDED-BUFFER-RING multishot receive (#335): per-driver lazily-registered pbuf ring (256 x 8 KiB), `RecvMulti` op on the MultiShot lifecycle, `TcpStream::recv_multi()` returning an `AsyncReadRent`-shaped stream with copy-on-consume + immediate recycle and transparent re-arm on cancel/ENOBUFS |
| `monoio-rustls` | 0.4.0 | `30c43d9bcdc3a3f2ecbd193be0f262e2a9b1d922` | Implement owning-buffer `writev` instead of the upstream first-iovec-only stub so native HTTP/2 vectored flushes remain correct and efficient; include the upstream dual-license texts omitted from the crates.io package.; allocate the ciphertext write buffer uninitialized (#349) — the Buffer's read/write invariants never expose an unwritten byte, and the 64 KiB-per-accept (512 KiB burst-growth) zero fill was pure handshake-path cost. |
| `pprof` | 0.15.0 | `c2d6e7b9aa0abf405fcd435d949e6502771fbce0` | Nix 0.26 to 0.31.3; retain one process-lifetime `OwnedFd` validation pipe initialized before sampling, eliminating the upstream atomic close/reopen race while keeping signal-time checks allocation-free; probe candidate addresses through the raw write(2) pointer without first constructing an unvalidated Rust slice; prefer the frame-pointer backend when both alternative unwinder features are present so Cargo's all-features validation is well-defined; make elided output lifetimes explicit for Rust 1.97 lint cleanliness. |

When an upstream release adopts these dependency versions, replace the corresponding path patch
with that release, run `cargo update`, confirm the old package version disappears from
`cargo tree -d --all-features`, and rerun the full workspace, vendor, profiling, and kTLS gates.
