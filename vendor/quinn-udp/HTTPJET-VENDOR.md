# HTTPJet quinn-udp experiment

Upstream: quinn-udp 0.6.3, https://github.com/quinn-rs/quinn.
Crates.io checksum: `47091c86514c2e11452cb228dee77037334b99d92a23e4c69aa5982261f39247`.
The original MIT and Apache-2.0 licenses are retained.

This pinned copy adds a Linux/Android `try_send_batch` API, bounded at sixteen
messages. It reuses upstream ancillary-data encoding for ECN, source address
and UDP segmentation. Success consumes only the reported message prefix;
EINTR retries only a call with no accepted prefix. WouldBlock consumes nothing.
Other errors run the existing raw scalar send for the head, retaining upstream
GSO disablement and unsupported-ancillary fallback. The existing best-effort
`send` API is never used for progress accounting.

HTTPJet uses the extension only with `--h3-send-batch 4|8|16`; default `1` keeps
its scalar adapter. No QUIC encryption, packet assembly, congestion, loss,
pacing or flow-control logic changes. Upstream scalar send is factored through
`send_with_flags` solely to guarantee nonblocking batch error recovery.

The syscall extension tests run from a standalone checker outside the workspace,
without upstream's benchmark-only Criterion dependency. Runtime qualification used
an isolated loopback lab; the batch path stays opt-in.
