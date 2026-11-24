# Native TLS static H2 regression: source and recipe investigation

This is local analysis of the sealed 48-arm experiment and pinned source/build
records. No build, application load, profile collection or benchmark ran.

The static H2 regression is mainly in user work. Median user CPU rises from
9.692 to 11.846 us/response (+22.22%); system CPU changes from 17.154 to 17.462
(+1.79%). Combined process CPU rises 10.20%. User instructions rise 1.86%, user
cycles rise 13.99%, and the median per-arm instructions/cycle falls 9.25%.
User CPU rises in all three cycles (+8.47%, +16.55%, +17.18%); instructions
also rise each cycle (+2.42%, +1.85%, +1.87%). These observations direct the
next investigation toward user code/build effects; they do not identify the
cause. CPU component medians need not sum to the median combined CPU.

| Native TLS fixture | User CPU change | System CPU change | User instructions | User cycles |
|---|---:|---:|---:|---:|
| H1 static | -3.90% | +0.80% | -1.28% | +2.32% |
| H1 page cache | -44.14% | +2.24% | -47.17% | -39.63% |
| H2 static | +22.22% | +1.79% | +1.86% | +13.99% |
| H2 page cache | -42.41% | -19.14% | -43.93% | -36.73% |

All CPU and PMU values cover the complete client span and divide by 65,000
responses, including warmup. PMU is server user mode only. The accompanying
CSVs retain all 48 arms and each ABBA cycle. No crypto-specific stack or CPU
frequency measurement is available, so instruction/cycle differences alone
cannot attribute the regression to crypto, code layout, caching or scheduling.

The TLS dependency versions are unchanged: rustls 0.23.46, webpki 0.103.16,
aws-lc-rs 1.18.2, aws-lc-sys 0.46.0, monoio 0.2.4, monoio-rustls 0.4.0,
and h2 0.4.20. Their lockfile dependency lists match. The complete
vendor/monoio, vendor/monoio-rustls and crates/hj-tls Git trees are identical
between C7 and candidate commit 3946. Quinn UDP 0.6.3 switches to a vendored
copy, which concerns H3/UDP. C7's profiling feature enables pprof, whose
sampling guard is created only by an explicit diagnostic profile request.
The experiment did not request one. This does not prove identical machine
code layout, but there is no source evidence of active per-request sampling.

The actual build receipts establish one controllable native-code difference:
C7 sets CFLAGS and CXXFLAGS to
`-march=native -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer`, while
ABF leaves both unset. Both use the same native Rust CPU and frame-pointer
flags, release optimization 3, thin LTO and one codegen unit. AWS-LC's pinned
builder consumes the C flag environment: builder/main.rs:1141 resolves the
flags, and builder/cc_builder.rs:370 applies them to the C builder. The
retained local records do not contain its actual C compiler argv, dependency
unit features, assembly-selection record or native object hashes. No retained
evidence proves the flags caused the regression.

There is also concrete H2 work compiled into the candidate's native path.
The TLS connection cannot create a kernel owner (uring/mod.rs:1852); capture
is false and no BPF request block is copied. Nevertheless, kernel-handoff is
a build feature, so native H2 uses ReadPollFence (server/mod.rs:1887).
Its poll wrapper updates phase, and its replacement method checks/resets
phase. The loop also retains owner Option checks and a native byte counter.
Per-request capture and observer checks remain, with empty options. This
does not add an extra heap allocation relative to C7's existing boxed read.

The service closure also differs: C7 directly returns the fast/bridge async
future; candidate uring/mod.rs:1903 builds that future with an internal
response/core return, then wraps it in another async future at line 1913 to
publish captured candidates. TLS has no inbox, but the generic closure still
contains that compiled state machine. The older source explicitly comments
that another async wrapper had enlarged H2 FuturesUnordered nodes. This makes
an owner-free native specialization a concrete source experiment, not a
validated fix. HPACK now tracks table generations on inserts/size updates and
caches Date literals; neither change is isolated by these measurements.

A bounded next build experiment can change only the candidate's C flags in a
fresh target/output namespace while retaining exact Rust source, features,
tools, Rust flags, profile file and helper. Record effective C compiler argv,
AWS-LC build outputs/unit fingerprints and native object hashes. Frozen Rust
profiles are eligible only if the new actual Cargo unit/CFG identities remain
compatible: reject CFG/hash mismatches, changed runtime profile identities or
new missing-serving-function warnings. If identities differ, collect a fresh
profile instead. The existing pipeline's unset-CFLAGS receipt must remain
immutable; this needs a distinct recipe and artifact receipt.

After focused native TLS/H3 correctness, compare the original ABF and matched-C
variant with fresh controls on the now-quieter host. The original ABF is the
direct control for isolating this input. Do not compare a new build only with
the older C7 measurements and call that proof. A native H2 source
specialization changes Rust CFG and requires fresh generation/training/use;
it must retain the active-owner read-ownership and cancellation guarantees.
Neither experiment is executed or authorized by this note.
