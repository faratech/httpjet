# HTTP/3 scheduler fairness, 2026-10-30

The H3 endpoint now gives queued request tasks a scheduling turn after an
overdue-deadline pump and before resuming retained pump work. This is a
correctness change; its throughput and latency effects have not been measured.
The base is `c122c44f7e21781e0b2abe5108cb37b5ca61edea`.

The overdue path previously ran the pump and immediately continued its outer
loop. A pump can finish synchronously while other connections already have due
work, so repeated passes can keep the endpoint in one poll. An inline request
that declines the cache path deliberately returns `Pending` before bridge
dispatch; `monoio::spawn` then queues its continuation. That continuation needs
the endpoint to relinquish the executor.

A self-wake is insufficient with this Monoio scheduler. A task notified while
running is requeued at the front (`vendor/monoio/src/task/harness.rs` and
`vendor/monoio/src/scheduler.rs`), ahead of children already queued behind it.
The shared H3 helper instead awaits `monoio::spawn(async {})`: the marker joins
the queue behind existing work and wakes the idle endpoint when it completes.
The global scheduler is unchanged. The empty pending-work branch remains
inert and allocates no marker task. Response framing, body ownership, ACK
leases and the bounded send/receive pump are unchanged.

The deterministic regression drives real expired handshakes through the
connection deadline index and H3 pump after queuing a request with the actual
inline-to-spawn handoff. Two old-style pump turns demonstrably leave the child
unpolled. The repaired continuation must run that child before its next turn.
A second regression covers the pending-work helper directly; the existing
empty-queue, flow-control, cancellation and shutdown checks remain enabled.

Native SINGULARITY verification used Rust/Cargo 1.99.1, `--offline --locked`,
two build jobs and features `beeper-h2-serve,beeper-observer,quic-bpf`.
All 32 BPF source inputs matched the previous qualification; the four existing
serving-ABI-5/RPC-2 BPF objects were reused unchanged.

| Check | Result |
| --- | --- |
| Original overdue continuation | Regression failed: child did not run |
| Self-waking yield | Same regression failed |
| Queued notifier | Regression passed |
| Final shared JoinHandle boundary, full H3 suite | 128 passed, 0 failed |
| Full server suite with the same runtime source | 1,075 passed, 0 failed, 1 ignored |

The compact hashes, source manifest, compiler flags and retained log paths are
in [the private qualification receipt](../docs/evidence/beeper-next-20261030/h3-fairness.json).
Raw source and test artifacts remain on SINGULARITY under
`/var/tmp/httpjet-continuation/h3-due-fairness-c122/`.

This does not establish the cause of the earlier baseline timeout in
`next-6469-v1/buffer-source-comparison-v1/source/h3-pagecache-32768/measurements/pagecache-3-4-baseline`.
That arm completed 199,036 of 200,000 requests: 199,035 succeeded, request 56,097
hit its 10-second client deadline, and 964 were unattempted after fail-fast.
The counters show 209,036 inline attempts including warmup, but 209,035
accounted responses: one deferred attempt lacked a matching on-core/bridge
count. All 32 client connections reported zero lost packets and client UDP
drops were zero. These observations support investigating deferred work; they
do not identify the timed-out stream's phase or prove this scheduling defect
caused that failure. The unsuccessful arm and negative performance comparisons
remain valid retained evidence, not a successful performance result.
