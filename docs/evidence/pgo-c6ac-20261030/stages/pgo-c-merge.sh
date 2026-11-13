#!/usr/bin/env bash
# Prepared only; execute separately after completed-C review and slot scheduling.
set -euo pipefail
source /var/tmp/pgo-c-common.sh
pgo_check_inputs
pgo_verify_gen
test -f "$PGO_RUN/training-complete.json"
test ! -e "$PGO_RUN/runtime.profdata"
test ! -e "$PGO_RUN/profile-inputs.json"
python3 - <<'PY'
import hashlib, json, os, re, stat, subprocess
from pathlib import Path
run = Path(os.environ['PGO_RUN']).resolve()
raw_root = run/'raw'
h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
artifacts = {Path(p).resolve(): record for p, record in
             json.loads((run/'gen-artifacts.json').read_text()).items()}
server_exe = (run/'bin-gen/httpjet').resolve()
helper_exe = (run/'bin-gen/httpjet-beeper-h1').resolve()
for executable in (server_exe, helper_exe):
    assert executable in artifacts and h(executable) == artifacts[executable]['sha256'], executable

def verify_binary(record, expected=None):
    assert isinstance(record, dict) and record.get('path'), record
    executable = Path(record['path']).resolve(strict=True)
    if expected is not None:
        assert executable == expected, (executable, expected)
    actual = h(executable)
    if record.get('sha256') is not None:
        assert actual == record['sha256'], executable
    if expected is not None:
        assert actual == artifacts[expected]['sha256'], executable
    return executable, actual

def binary_record(record):
    return {'path': record['binary'], 'sha256': record.get('sha256')}

# Reject aliases and special files before reading profiles (including FIFOs).
assert raw_root.is_dir() and not raw_root.is_symlink(), raw_root
for path in raw_root.rglob('*'):
    info = path.lstat()
    assert not stat.S_ISLNK(info.st_mode), f'symlink in runtime profiles: {path}'
    assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), f'nonregular runtime profile path: {path}'
checked, attributed = [], {}
for metadata_path in sorted((run/'results').glob('*/metadata.json')):
    metadata = json.loads(metadata_path.read_text())
    profile_root = Path(metadata['arguments']['profile_dir']).resolve(strict=True)
    assert profile_root.is_relative_to(raw_root), profile_root
    exits = sorted(metadata_path.parent.glob('*/server-exit.json'))
    assert exits, metadata_path
    # These identities were captured by the harness before runtime training.
    if 'client' in metadata:
        verify_binary(metadata['client'])
    for name, record in metadata.get('binaries', {}).items():
        verify_binary(record, server_exe if name in ('candidate', 'baseline') else None)
    for exit_path in exits:
        arm = exit_path.parent
        result = json.loads((arm/'result.json').read_text())
        end = json.loads(exit_path.read_text())
        assert result['training_only'] is True, arm
        assert end['exit'] == 0, arm
        assert result['client']['failed'] == 0, arm
        assert result['client']['completed'] == result['client']['succeeded'] == result['client']['requested'], arm
        assert result['client']['benchmark_valid'] is True, arm
        assert result['client']['requested'] == int(metadata['arguments']['requests']), arm
        identity = result.get('profile_server')
        launcher = None
        if 'arm' in result:
            assert identity and result.get('server_profile_nonempty') is True, arm
            declared = metadata['arms'][result['arm']['name']]
            verify_binary(binary_record(result['arm']), server_exe)
            verify_binary(binary_record(declared), server_exe)
            assert Path(identity['executable']).resolve(strict=True) == server_exe, arm
            launcher = result['arm'].get('launcher')
            assert bool(launcher) == bool(declared.get('launcher')), arm
            if launcher:
                verify_binary(binary_record(launcher), helper_exe)
                verify_binary(binary_record(declared['launcher']), helper_exe)
        else:
            assert not result.get('loader'), 'H3 loader profiles are not part of this training matrix'
            if result.get('server_binary_sha256') is not None:
                assert result['server_binary_sha256'] == artifacts[server_exe]['sha256'], arm
        if result.get('client_binary_sha256') is not None and 'client' in metadata.get('binaries', {}):
            assert result['client_binary_sha256'] == metadata['binaries']['client']['sha256'], arm
        server_pid = identity['pid'] if identity else end['pid']
        assert type(server_pid) is int and server_pid > 0, arm
        processes = {server_pid: {'role':'server', 'scope':'unprivileged HTTPJet runtime',
                     'executable':str(server_exe), 'executable_sha256':artifacts[server_exe]['sha256']}}
        if identity:
            processes[server_pid]['starttime_ticks'] = identity['starttime_ticks']
        if launcher:
            helper_pid = end['pid']
            assert type(helper_pid) is int and helper_pid > 0 and helper_pid != server_pid, arm
            processes[helper_pid] = {'role':'helper', 'scope':'privileged owned H1/H2 launcher runtime',
                'executable':str(helper_exe), 'executable_sha256':artifacts[helper_exe]['sha256']}
        else:
            assert server_pid == end['pid'], arm
        profile_dir = profile_root/arm.name
        assert profile_dir.is_dir() and not profile_dir.is_symlink(), profile_dir
        files, server_files = [], []
        for path in sorted(profile_dir.glob('*.profraw')):
            assert stat.S_ISREG(path.lstat().st_mode), path
            if path.stat().st_size == 0:
                continue
            match = re.fullmatch(r'(.+)-(\d+)\.profraw', path.name)
            assert match, f'profile lacks module/PID attribution: {path}'
            pid = int(match[2])
            assert pid in processes, f'unrecorded process profile: {path}'
            canonical = path.resolve(strict=True)
            assert canonical.is_relative_to(raw_root) and canonical not in attributed, canonical
            record = {'path':str(canonical), 'bytes':path.stat().st_size, 'sha256':h(path),
                      'arm':str(arm), 'metadata':str(metadata_path), 'process_pid':pid,
                      'module_id':match[1], **processes[pid]}
            attributed[canonical] = record
            files.append(str(canonical))
            if pid == server_pid:
                server_files.append(str(canonical))
        assert server_files, f'no nonempty server profile: {arm}, pid={server_pid}'
        if identity:
            assert result['server_profile_nonempty'] is True, arm
        # If the HTTP harness recorded output hashes, check them independently.
        for output in result.get('profile_outputs', []):
            path = Path(output['path']).resolve(strict=True)
            if output.get('bytes', 0) > 0:
                assert path in attributed and h(path) == output['sha256'], path
        if result.get('arm', {}).get('name') in ('h1-polling', 'h1-readiness'):
            assert result['metric_deltas']['httpjet_h1_kernel_successes_total'] > 0, arm
            if result['arm']['name'] == 'h1-readiness':
                for name in ('bindings', 'submissions'):
                    assert result['metric_deltas'][f'httpjet_h1_kernel_readiness_{name}_total'] > 0, arm
        if result.get('arm', {}).get('name') == 'h2-kernel':
            count = result['metric_deltas']['httpjet_h2_kernel_successes_total']
            size = int(metadata['arguments']['size'])
            assert count == 0 if size == 32768 else count > 0, arm
            if size == 32768:
                assert result['metric_deltas']['httpjet_h2_kernel_candidates_total'] == 0, arm
        checked.append({'arm':str(arm), 'server_pid':server_pid, 'processes':processes,
                        'server_profiles':server_files, 'profiles':files})
assert len(checked) == 55, f'incomplete training matrix: {len(checked)} arms'
raw = sorted(p for p in (run/'raw').rglob('*.profraw')
             if p.is_file() and p.stat().st_size > 0)
assert raw
actual = {p.resolve(strict=True) for p in raw}
assert actual == set(attributed), {'unrecorded_profiles':sorted(map(str,actual-set(attributed))),
                                   'missing_profiles':sorted(map(str,set(attributed)-actual))}
assert all(h(path) == attributed[path]['sha256'] for path in actual), 'profile changed during attribution'
receipt = {'checked_arms':checked, 'raw_profiles':[attributed[p] for p in sorted(attributed)],
           'scope':'only attributed server/helper runtime profiles from accepted training arms',
           'excluded_build_profiles':str(run/'build-raw')}
(run/'profile-inputs.json').write_text(json.dumps(receipt,indent=2)+'\n')
with (run/'logs/merge.log').open('x') as log:
    subprocess.run([os.environ['PGO_PROFDATA'], 'merge', '--failure-mode=any',
                    '-o', str(run/'runtime.profdata'), *map(str,raw)],
                   stdout=log, stderr=subprocess.STDOUT, check=True)
PY
"$PGO_PROFDATA" show --counts --all-functions "$PGO_RUN/runtime.profdata" >"$PGO_RUN/logs/profile-counts.txt"

python3 - <<'PY'
import hashlib,json,os
from pathlib import Path
r=Path(os.environ['PGO_RUN']);h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
record={'profile_sha256':h(r/'runtime.profdata'),'profile_inputs_sha256':h(r/'profile-inputs.json'),
 'counts_log':str(r/'logs/profile-counts.txt'),'counts_log_sha256':h(r/'logs/profile-counts.txt'),
 'scope':'merged verified runtime training profiles; no performance result'}
(r/'merge-receipt.json').write_text(json.dumps(record,indent=2)+'\n')
review={k:record[k] for k in ['profile_sha256','profile_inputs_sha256']}
review['coverage_notes']=''
(r/'coverage-review.example.json').write_text(json.dumps(review,indent=2)+'\n')
PY
printf '%s\n' 'Merge finished. Inspect profile-counts.txt; record observed coverage in coverage-review.json before build-use. No build-use was started.'
