#!/usr/bin/env bash
# Prepared only; execute separately after completed-C review and slot scheduling.
set -euo pipefail
source /var/tmp/pgo-c-common.sh
pgo_require_summary
test ! -e "$PGO_RUN"
test ! -L "$PGO_RUN"
install -d -m 0755 "$PGO_RUN"
install -d -m 0755 "$PGO_RUN"/{src,raw,build-raw,tmp,logs,results,bin-gen,bin-use,bin-control,harness/scripts,harness/packaging/debian}
cp -a "$PGO_C_ROOT/src/." "$PGO_RUN/src/"
cp -a "$PGO_C_ROOT/src/packaging/debian/conf" "$PGO_RUN/harness/packaging/debian/conf"
for pgo_script in http_engine_check.py h3_engine_check.py bench_cpu.py bench_hw_counters.py bench_syscall_counts.py; do
    cp "$PGO_HARNESS_SOURCE/$pgo_script" "$PGO_HARNESS/$pgo_script"
done
python3 - <<'PY'
import hashlib, json, os, re, shutil, tomllib
from pathlib import Path
run, source, bpf = (Path(os.environ[name]) for name in ['PGO_RUN', 'PGO_C_ROOT', 'PGO_BPF_ROOT'])
summary_path = Path(os.environ['PGO_C_SUMMARY'])
summary = json.loads(summary_path.read_text())
assert summary['status'] == 'complete' and len(summary['cells']) == 40
assert all(cell['status'] == 'complete' for cell in summary['cells'])
candidate = summary['provenance']['artifacts']['candidate']
assert candidate['sha256'] == '6ac144f2449750d6063963c0994f30c933c11df8e8dbfa548b1a7b4a71e51e8f'
assert hashlib.sha256(Path(candidate['path']).read_bytes()).hexdigest() == candidate['sha256']
manifest_path = source/'build-source-manifest.json'
files = json.loads(manifest_path.read_text())
assert isinstance(files, dict) and files, 'expected the flat C build-source manifest'
for name, expected in files.items():
    relative = Path(name)
    assert not relative.is_absolute() and '..' not in relative.parts, name
    assert isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected), name
    assert hashlib.sha256((run/'src'/name).read_bytes()).hexdigest() == expected, name
manifest = tomllib.loads((run/'src/Cargo.toml').read_text())
assert 'rustls' not in manifest.get('patch', {}).get('crates-io', {}), 'C must use stock rustls'
lock = tomllib.loads((run/'src/Cargo.lock').read_text())
rustls = [package for package in lock['package'] if package['name'] == 'rustls']
assert len(rustls) == 1 and rustls[0]['version'] == '0.23.46'
assert rustls[0].get('source', '').startswith('registry+')
assert rustls[0]['checksum'] == '48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf'
objects = json.loads((bpf/'bpf-objects.json').read_text())
identity = json.loads((bpf/'provenance.json').read_text())
assert identity['serving_abi'] == 5 and identity['helper_rpc_abi'] == 2
for name, expected in objects['hashes'].items():
    assert hashlib.sha256((bpf/'objects'/name).read_bytes()).hexdigest() == expected, name
shutil.copy2(manifest_path, run/'build-source-manifest.json')
shutil.copy2(bpf/'bpf-objects.json', run/'bpf-objects.json')
shutil.copy2(summary_path, run/'completed-c-summary.json')
for path in (run/'harness/scripts').glob('*.py'):
    assert path.stat().st_size > 0
inputs = {'candidate_reference':candidate,
          'source_manifest_sha256':hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
          'completed_summary_sha256':hashlib.sha256(summary_path.read_bytes()).hexdigest(),
          'harness_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in (run/'harness/scripts').glob('*.py')}}
(run/'pgo-inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
print('C source, stock-rustls selection and all four prebuilt ABI 5 objects verified')
PY

python3 - <<'PY'
import hashlib,json,os
from pathlib import Path
r=Path(os.environ['PGO_RUN']);p=r/'pgo-inputs.json'
i=json.loads(p.read_text())
i['bpf_manifest_sha256']=hashlib.sha256((r/'bpf-objects.json').read_bytes()).hexdigest()
i['fixture_sha256']={str(q.relative_to(r/'harness')):hashlib.sha256(q.read_bytes()).hexdigest()
                      for q in (r/'harness/packaging/debian/conf').rglob('*') if q.is_file()}
p.write_text(json.dumps(i,indent=2)+'\n')
PY
pgo_check_inputs
