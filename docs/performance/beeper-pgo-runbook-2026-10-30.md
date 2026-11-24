# Isolated native PGO for the frozen HTTPJet integration

This is the historical, unexecuted f755 recipe. The later
[candidate C experiment](beeper-pgo-c6ac-2026-10-30.md) supersedes its source,
paths and training matrix after the complete non-PGO benchmark.

Prepared on 2026-10-30. These commands have **not** been executed. Wait until the
active SINGULARITY timing campaign has ended and its owned processes are reaped.
Run all blocks in one Bash session on SINGULARITY. Do not run the production
`scripts/build-pgo.sh` or the old `/var/tmp/hjc/pgo2.sh` as a substitute.

The runtime source is frozen at
`f7555d80f857475806bbae2e742ad38af8ebcd4b`. At preparation, current HEAD
`351ae04649bf00fc96b9cb2e314c8ac1cefdf02d` had no changes from that commit under
`crates`, `vendor`, `bpf`, `.cargo`, `Cargo.toml` or `Cargo.lock`. Later harness
changes are independent inputs. The native compiler is Rust 1.99.1, LLVM 23.1.1;
its matching `llvm-profdata` exists at the path below. No tools need installing.

The retained release profile is opt-level 3, thin LTO, one codegen unit,
panic=abort, strip=debuginfo, native CPU and frame pointers. This recipe leaves
CFLAGS/CXXFLAGS unset. The production PGO script additionally sets native C/C++
flags: adopting those would be a separate build-recipe change and require the
same flags in the control build. Rust PGO does not optimize or regenerate the
verified serving ABI 5 / helper RPC ABI 2 BPF objects.

## Set up and verify the isolated inputs

```bash
set -euo pipefail
export PGO_RUN=/var/tmp/httpjet-continuation/pgo-f7555d80-v1
export PGO_FROZEN=/var/tmp/httpjet-continuation/integrated-f7555d80
PGO_HARNESS_SOURCE=/var/tmp/httpjet-continuation/harness-integrated/scripts
PGO_HARNESS="$PGO_RUN/harness/scripts"
PGO_TOOLBIN=/var/tmp/httpjet-h3-tools/rust/bin
export PGO_PROFDATA=/var/tmp/httpjet-h3-tools/rust/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata
PGO_BASE='-Ctarget-cpu=native -Cforce-frame-pointers=yes'
test ! -e "$PGO_RUN"
install -d -m 0755 "$PGO_RUN"/{src,raw,build-raw,tmp,logs,results,bin-use,harness/scripts,harness/packaging/debian}
cp -a "$PGO_FROZEN/src/." "$PGO_RUN/src/"
cp -a "$PGO_FROZEN/src/packaging/debian/conf" "$PGO_RUN/harness/packaging/debian/conf"
for pgo_script in http_engine_check.py h3_engine_check.py bench_cpu.py bench_hw_counters.py bench_syscall_counts.py; do
    cp "$PGO_HARNESS_SOURCE/$pgo_script" "$PGO_HARNESS/$pgo_script"
done
python3 - <<'PY'
import hashlib, json, os, shutil
from pathlib import Path
run, frozen = Path(os.environ['PGO_RUN']), Path(os.environ['PGO_FROZEN'])
manifest = json.loads((frozen/'source-inputs.json').read_text())
assert manifest['commit'] == 'f7555d80f857475806bbae2e742ad38af8ebcd4b'
files = manifest['files']
entries = files.items() if isinstance(files, dict) else ((row['path'], row['sha256']) for row in files)
for name, value in entries:
    expected = value['sha256'] if isinstance(value, dict) else value
    assert hashlib.sha256((run/'src'/name).read_bytes()).hexdigest() == expected, name
objects = json.loads((frozen/'bpf-objects.json').read_text())
for name, expected in objects['hashes'].items():
    assert hashlib.sha256((frozen/'objects'/name).read_bytes()).hexdigest() == expected, name
for name in ['source-inputs.json', 'bpf-objects.json', 'provenance.json']:
    shutil.copy2(frozen/name, run/name)
for path in (run/'harness/scripts').glob('*.py'):
    assert path.stat().st_size > 0
print('Frozen runtime source and all four prebuilt BPF objects verified')
PY
```

Do not skip a verification failure or install a missing tool. Resolve the
specific drift first. The copied HTTP harness must contain
`server_profile_nonempty` and the helper-child PID check. At preparation its
SHA-256 was `e9849c5295e8ee01dae547b09130bbe3798677b2a70fd738efb38e11d5e81193`;
H3 was `534c38a4acd453c59dc21ced0b8cbf8885466f2cecc763eb2967a97151e2a4a2`.
Record any subsequently reviewed harness update separately from runtime source.

## Build the instrumented binaries

```bash
cd "$PGO_RUN/src"
pgo_build() {
    env -i PATH="$PGO_TOOLBIN:/usr/local/bin:/usr/bin:/bin" \
        CARGO_HOME=/var/tmp/httpjet-h3-tools/cargo CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true \
        CARGO_TARGET_DIR="$1" TMPDIR="$PGO_RUN/tmp" \
        HTTPJET_BPF_PREBUILT_DIR="$PGO_FROZEN/objects" RUSTFLAGS="$2" \
        nice -n 10 cargo build --release --offline --locked \
        -p httpjet -p hj-kernel-fastpath -p hj-quic-steering \
        --bin httpjet --bin httpjet-beeper-h1 --bin httpjet-beeper-observe --bin httpjet-quic-steer \
        --features httpjet/beeper-h2-serve,httpjet/beeper-observer,httpjet/quic-bpf
}
pgo_build "$PGO_RUN/target-gen" "$PGO_BASE -Cprofile-generate=$PGO_RUN/build-raw" >"$PGO_RUN/logs/build-gen.log" 2>&1
```

The fallback `build-raw` directory may receive profiles from instrumented build
scripts or proc macros. **Never merge it into runtime training data.** Runtime
profiles below go into new per-arm directories under `raw`; their leaves are
owned by the fixture's nobody UID/GID and mode 0750. The reviewed harness adds
only LLVM_PROFILE_FILE, including after the H1 helper's child environment reset.

## Train only synthetic isolated fixtures

The addresses below are the named true-lo profile: both server and client use
127.0.0.2. There are no production XML files, PHP pools, external routes, mTLS
exceptions on live listeners, or production cache directories in this phase.
Every request still receives protocol/status/body and cache-path validation.
Instrumentation makes all rates and CPU values **training output only**.

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
run = Path(os.environ['PGO_RUN'])
binary = str(run/'target-gen/release/httpjet')
helper = str(run/'target-gen/release/httpjet-beeper-h1')
base = ['--page-cache-response-memo']
arms = [{'name':'native', 'binary':binary, 'serve_args':base+['--h1-kernel','off']}]
for mode in ['polling','readiness']:
    arms.append({'name':'h1-'+mode, 'binary':binary,
                 'serve_args':base+['--h1-kernel','required','--h1-kernel-wakeup',mode],
                 'launcher':{'binary':helper}})
arms.append({'name':'h2-kernel', 'binary':binary,
             'serve_args':base+['--h1-kernel','required','--h2-kernel'],
             'launcher':{'binary':helper}})
(run/'training-arms.json').write_text(json.dumps(arms,indent=2)+'\n')
PY
pgo_python() {
    env -i PATH=/usr/local/bin:/usr/bin:/bin \
        PYTHONPATH=/var/tmp/httpjet-h3-tools/python PYTHONDONTWRITEBYTECODE=1 \
        HJ_BENCH_ADDR=127.0.0.2 HJ_BENCH_BIND=127.0.0.2 python3 -B "$@"
}
pgo_http=(--arms "$PGO_RUN/training-arms.json" --client /var/tmp/hjc/httpjet-http-load-bind
          --workers 1 --server-cpus 8 --connections 64 --streams 4 --client-threads 6
          --client-cpus 0,2,4,6,12,14)
for pgo_size in 1024 32768; do
    pgo_requests=30000; pgo_warmup=2000
    if [ "$pgo_size" = 32768 ]; then pgo_requests=8000; pgo_warmup=1000; fi
    pgo_name="http-native-$pgo_size"
    pgo_python "$PGO_HARNESS/http_engine_check.py" "${pgo_http[@]}" \
        --sequence native --protocols h1,h1s,h2c,h2 --cases static,pagecache,range \
        --size "$pgo_size" --requests "$pgo_requests" --warmup "$pgo_warmup" \
        --profile-dir "$PGO_RUN/raw/$pgo_name" --results "$PGO_RUN/results/$pgo_name" \
        >"$PGO_RUN/logs/$pgo_name.log" 2>&1
done
pgo_python "$PGO_HARNESS/http_engine_check.py" "${pgo_http[@]}" \
    --sequence h1-polling,h1-readiness --protocols h1 --cases static,pagecache \
    --size 1024 --requests 30000 --warmup 2000 \
    --profile-dir "$PGO_RUN/raw/h1-kernel" --results "$PGO_RUN/results/h1-kernel" \
    >"$PGO_RUN/logs/h1-kernel.log" 2>&1
pgo_python "$PGO_HARNESS/http_engine_check.py" "${pgo_http[@]}" \
    --sequence h2-kernel --protocols h2c --cases static,pagecache,range \
    --size 1024 --requests 30000 --warmup 2000 \
    --profile-dir "$PGO_RUN/raw/h2-kernel" --results "$PGO_RUN/results/h2-kernel" \
    >"$PGO_RUN/logs/h2-kernel.log" 2>&1

for pgo_size in 1024 32768; do
    pgo_requests=30000; pgo_warmup=2000
    if [ "$pgo_size" = 32768 ]; then pgo_requests=8000; pgo_warmup=1000; fi
    for pgo_shape in 20:1 10:4; do
        pgo_gso=${pgo_shape%:*}; pgo_batch=${pgo_shape#*:}
        for pgo_case in all range; do
            pgo_name="h3-$pgo_size-g$pgo_gso-b$pgo_batch-$pgo_case"
            pgo_python "$PGO_HARNESS/h3_engine_check.py" \
                --candidate "$PGO_RUN/target-gen/release/httpjet" --candidate-page-response-memo \
                --client /var/tmp/httpjet-continuation/h3-bind-client-20261030/bin/httpjet-h3-load-bind \
                --sequence legacy,accelerated --case "$pgo_case" \
                --candidate-arg="--h3-gso-segments=$pgo_gso" \
                --candidate-arg="--h3-send-batch=$pgo_batch" \
                --workers 2 --server-cpus 8,10 --connections 32 --streams 4 \
                --client-threads 6 --client-cpus 0,2,4,6,12,14 \
                --size "$pgo_size" --requests "$pgo_requests" --warmup "$pgo_warmup" \
                --profile-dir "$PGO_RUN/raw/$pgo_name" --results "$PGO_RUN/results/$pgo_name" \
                >"$PGO_RUN/logs/$pgo_name.log" 2>&1
        done
    done
done
```

This includes native H1/TLS/H2/TLS, both H1 wakeup branches, opt-in H2c kernel
handoff, both H3 dispatch engines, scalar/batched sends, two body sizes, warmed
static/page cache, and native Range controls. It does not enable kernel H2 in a
deployment or establish production, authenticated-session, or large-object gains.
H3 CID steering stays off. Do not add PMU, rate or headroom-qualification options
to these training commands. Every invocation has a distinct profile root.

## Validate every server's profile and merge

HTTP already enforces actual server PID coverage, preserving helper profiles
separately. H3 needs this additional post-exit check; its loader is not used.
Do not accept a helper-only profile or a successful request log with no profile.

```bash
python3 - <<'PY'
import hashlib, json, os, subprocess
from pathlib import Path
run = Path(os.environ['PGO_RUN'])
checked = []
for metadata_path in sorted((run/'results').glob('*/metadata.json')):
    metadata = json.loads(metadata_path.read_text())
    profile_root = Path(metadata['arguments']['profile_dir'])
    exits = sorted(metadata_path.parent.glob('*/server-exit.json'))
    assert exits, metadata_path
    for exit_path in exits:
        arm = exit_path.parent
        result = json.loads((arm/'result.json').read_text())
        end = json.loads(exit_path.read_text())
        assert result['training_only'] is True, arm
        assert end['exit'] == 0, arm
        assert result['client']['failed'] == 0, arm
        assert result['client']['completed'] == result['client']['succeeded'] == result['client']['requested'], arm
        identity = result.get('profile_server')
        server_pid = identity['pid'] if identity else end['pid']
        files = [p for p in (profile_root/arm.name).glob(f'*-{server_pid}.profraw')
                 if p.is_file() and not p.is_symlink() and p.stat().st_size > 0]
        assert files, f'no nonempty server profile: {arm}, pid={server_pid}'
        if identity:
            assert result['server_profile_nonempty'] is True, arm
        checked.append({'arm':str(arm), 'server_pid':server_pid,
                        'profiles':[str(p) for p in files]})
assert len(checked) == 55, f'incomplete training matrix: {len(checked)} arms'
raw = sorted(p for p in (run/'raw').rglob('*.profraw')
             if p.is_file() and not p.is_symlink() and p.stat().st_size > 0)
assert raw
receipt = {'checked_arms':checked, 'raw_profiles':[
    {'path':str(p), 'bytes':p.stat().st_size, 'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    for p in raw], 'excluded_build_profiles':str(run/'build-raw')}
(run/'profile-inputs.json').write_text(json.dumps(receipt,indent=2)+'\n')
with (run/'logs/merge.log').open('x') as log:
    subprocess.run([os.environ['PGO_PROFDATA'], 'merge', '--failure-mode=any',
                    '-o', str(run/'runtime.profdata'), *map(str,raw)],
                   stdout=log, stderr=subprocess.STDOUT, check=True)
PY
"$PGO_PROFDATA" show --counts --all-functions "$PGO_RUN/runtime.profdata" >"$PGO_RUN/logs/profile-counts.txt"
```

The fixed matrix has 24 native HTTP arms, four H1 kernel arms, three H2 kernel
arms and 24 H3 arms: **55 arms**. Preserve all failed profiles/logs; do not merge
unverified remnants from another attempt, source, toolchain or architecture.
Inspect nonzero coverage for the native H2 server, H3 drive/dispatch, memo/cache
and kernel-controller paths before accepting the profile.

## Build, freeze and qualify profile use

```bash
pgo_build "$PGO_RUN/target-use" "$PGO_BASE -Cprofile-use=$PGO_RUN/runtime.profdata -Cllvm-args=-pgo-warn-missing-function" \
    >"$PGO_RUN/logs/build-use.log" 2>&1
for pgo_binary in httpjet httpjet-beeper-h1 httpjet-beeper-observe httpjet-quic-steer; do
    install -m 0555 "$PGO_RUN/target-use/release/$pgo_binary" "$PGO_RUN/bin-use/$pgo_binary"
done
python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
run = Path(os.environ['PGO_RUN'])
items = list((run/'bin-use').iterdir()) + [run/'runtime.profdata']
manifest = {str(p):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in items}
(run/'profile-use-artifacts.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
```

Review the entire build-use log. Control-flow/profile-hash mismatch warnings
invalidate this qualification. Record missing-function warnings; cold,
untrained features are not evidence of full coverage. Recheck that embedded
object hashes remain the same four ABI 5 inputs. Run focused protocol/cache,
handoff and graceful-stop correctness checks before timing the PGO binaries.

To isolate PGO from source and build-recipe changes, build a same-source control:

```bash
pgo_build "$PGO_RUN/target-control" "$PGO_BASE" >"$PGO_RUN/logs/build-control.log" 2>&1
```

Compare this control with profile-use using identical clients/config/cache and
the same named network profile. Keep exact shipped-release comparisons separate.
The older 46be source baseline needs its **own** matching training/profile if it
is rebuilt with PGO; never feed it f755's profile. Neither an optimized build nor
a clean profile merge establishes a performance gain without fresh paired loads.
