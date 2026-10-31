#!/usr/bin/env bash
# Definitions only. Each stage runs separately after the complete C matrix is reviewed.
# First: PGO_C_SUMMARY=/absolute/completed-C.json bash /var/tmp/pgo-c-setup.sh
# Then run build-gen, train, merge separately. Inspect profile-counts.txt and
# write coverage-review.json from the hash-filled example with actual findings.
# build-control and build-use remain separate invocations; no stage chains them.
set -euo pipefail
export PGO_RUN=/var/tmp/httpjet-continuation/pgo-c6ac-v1
export PGO_C_ROOT=/var/tmp/httpjet-continuation/h2-oversize-c-ed7a4fda
export PGO_BPF_ROOT=/var/tmp/httpjet-continuation/integrated-f7555d80
export PGO_C_SUMMARY="${PGO_C_SUMMARY:-$PGO_RUN/completed-c-summary.json}"
export PGO_EXPECTED_C_SHA=6ac144f2449750d6063963c0994f30c933c11df8e8dbfa548b1a7b4a71e51e8f
export PGO_HARNESS_SOURCE=/var/tmp/httpjet-continuation/final-c-harness/scripts
export PGO_HARNESS="$PGO_RUN/harness/scripts"
export PGO_TOOLBIN=/var/tmp/httpjet-h3-tools/rust/bin
export PGO_PROFDATA=/var/tmp/httpjet-h3-tools/rust/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata
export PGO_BASE='-Ctarget-cpu=native -Cforce-frame-pointers=yes'

pgo_require_summary() {
    python3 - <<'PY'
import hashlib,json,os,socket
from pathlib import Path
assert socket.gethostname().upper() == 'SINGULARITY' and os.geteuid() == 0
p=Path(os.environ['PGO_C_SUMMARY']);s=json.loads(p.read_text())
assert s['status']=='complete' and len(s['cells'])==40
assert all(c['status']=='complete' for c in s['cells'])
a=s['provenance']['artifacts']['candidate']
assert a['sha256']==os.environ['PGO_EXPECTED_C_SHA']
assert hashlib.sha256(Path(a['path']).read_bytes()).hexdigest()==a['sha256']
PY
}

pgo_check_inputs() {
    pgo_require_summary
    python3 - <<'PY'
import hashlib,json,os,tomllib
from pathlib import Path
r=Path(os.environ['PGO_RUN']);b=Path(os.environ['PGO_BPF_ROOT'])
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
i=json.loads((r/'pgo-inputs.json').read_text())
assert h(Path(os.environ['PGO_C_SUMMARY']))==i['completed_summary_sha256']
assert h(r/'build-source-manifest.json')==i['source_manifest_sha256']
for name,expected in json.loads((r/'build-source-manifest.json').read_text()).items():
    assert h(r/'src'/name)==expected,name
m=tomllib.loads((r/'src/Cargo.toml').read_text())
assert 'rustls' not in m.get('patch',{}).get('crates-io',{})
p=[p for p in tomllib.loads((r/'src/Cargo.lock').read_text())['package'] if p['name']=='rustls']
assert len(p)==1 and p[0]['version']=='0.23.46' and p[0].get('source','').startswith('registry+')
assert p[0]['checksum']=='48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf'
assert h(r/'bpf-objects.json')==i['bpf_manifest_sha256']
identity=json.loads((b/'provenance.json').read_text())
assert identity['serving_abi']==5 and identity['helper_rpc_abi']==2
for name,expected in json.loads((r/'bpf-objects.json').read_text())['hashes'].items():
    assert h(b/'objects'/name)==expected,name
for name,expected in i['harness_sha256'].items():
    assert h(r/'harness/scripts'/name)==expected,name
for name,expected in i['fixture_sha256'].items():
    assert h(r/'harness'/name)==expected,name
PY
}

pgo_build() {
    local target="$1" flags="$2" stage="$3" code=0
    local log="$PGO_RUN/logs/build-$stage.log"
    test ! -e "$log"
    cd "$PGO_RUN/src"
    env -i PATH="$PGO_TOOLBIN:/usr/local/bin:/usr/bin:/bin" \
        CARGO_HOME=/var/tmp/httpjet-h3-tools/cargo CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true \
        CARGO_TARGET_DIR="$target" TMPDIR="$PGO_RUN/tmp" \
        HTTPJET_BPF_PREBUILT_DIR="$PGO_BPF_ROOT/objects" RUSTFLAGS="$flags" \
        RUSTC="$PGO_TOOLBIN/rustc" \
        nice -n 10 "$PGO_TOOLBIN/cargo" build --release --offline --locked \
        -p httpjet -p hj-kernel-fastpath -p hj-quic-steering \
        --bin httpjet --bin httpjet-beeper-h1 --bin httpjet-beeper-observe --bin httpjet-quic-steer \
        --features httpjet/beeper-h2-serve,httpjet/beeper-observer,httpjet/quic-bpf \
        >"$log" 2>&1 || code=$?
    python3 - "$stage" "$target" "$flags" "$code" <<'PY'
import hashlib,json,os,sys
from pathlib import Path
r=Path(os.environ['PGO_RUN']);stage,target,flags,code=sys.argv[1:]
log=r/'logs'/f'build-{stage}.log'
record={'stage':stage,'target':target,'rustflags':flags,'exit':int(code),'jobs':2,
        'profile':'release/opt3/thinLTO/codegen1/panic-abort/strip-debuginfo',
        'features':['httpjet/beeper-h2-serve','httpjet/beeper-observer','httpjet/quic-bpf'],
        'prebuilt_bpf':str(Path(os.environ['PGO_BPF_ROOT'])/'objects'),
        'log':str(log),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),
        'scope':'build receipt only; no performance result'}
(r/f'build-{stage}.json').write_text(json.dumps(record,indent=2)+'\n')
PY
    return "$code"
}

pgo_freeze() {
    local target="$1" label="$2"
    test ! -e "$PGO_RUN/$label-artifacts.json"
    for binary in httpjet httpjet-beeper-h1 httpjet-beeper-observe httpjet-quic-steer; do
        install -m 0555 "$target/release/$binary" "$PGO_RUN/bin-$label/$binary"
    done
    python3 - "$label" <<'PY'
import hashlib,json,os,sys
from pathlib import Path
r=Path(os.environ['PGO_RUN']);label=sys.argv[1]
files={str(p):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
       for p in sorted((r/f'bin-{label}').iterdir())}
(r/f'{label}-artifacts.json').write_text(json.dumps(files,indent=2)+'\n')
PY
}

pgo_verify_gen() {
    python3 - <<'PY'
import hashlib,json,os
from pathlib import Path
r=Path(os.environ['PGO_RUN'])
assert json.loads((r/'build-gen.json').read_text())['exit']==0
files=json.loads((r/'gen-artifacts.json').read_text());assert len(files)==4
for name,record in files.items():
    assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==record['sha256'],name
PY
}

pgo_check_profile_review() {
    # This is a technical inspection record, writable by the reviewing agent;
    # it is not a request for human permission or an automatic coverage verdict.
    python3 - <<'PY'
import hashlib,json,os
from pathlib import Path
r=Path(os.environ['PGO_RUN']);h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads((r/'merge-receipt.json').read_text())
assert h(r/'runtime.profdata')==m['profile_sha256']
assert h(r/'profile-inputs.json')==m['profile_inputs_sha256']
for row in json.loads((r/'profile-inputs.json').read_text())['raw_profiles']:
    assert h(Path(row['path']))==row['sha256'],row['path']
review=json.loads((r/'coverage-review.json').read_text())
assert review['profile_sha256']==m['profile_sha256']
assert review['profile_inputs_sha256']==m['profile_inputs_sha256']
assert isinstance(review.get('coverage_notes'),str) and review['coverage_notes'].strip()
PY
}
