#!/usr/bin/env python3
"""Release identities, portable ELF checks, qualification and signed APT staging."""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
import gzip
import hashlib
import json
from pathlib import Path
import sys
# Also support importlib consumers such as the isolated native builder.
sys.path.insert(0,str(Path(__file__).resolve().parent))
import re
import shutil
import subprocess
import tempfile
import tarfile
import io
import stat
import support
import urllib.request

ARCHES = ('amd64', 'arm64')
DISTROS = ('debian12', 'debian13', 'ubuntu24.04', 'ubuntu26.04')
CHECKS = ('install', 'rerun', 'http', 'scripts-denied', 'bridged-transfer', 'restart',
          'config-preserved', 'upgrade', 'downgrade', 'remove', 'purge', 'occupied-port',
          'no-php-no-cache', 'io-uring-denied', 'reinstall', 'reboot')
REPO_URL = 'https://httpjet-packages.pages.dev/apt'

def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, stdout=subprocess.PIPE,
                          text=True, **kwargs).stdout

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def load(path):
    return json.loads(Path(path).read_text())

def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')

def version(value):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value):
        raise ValueError('version must be X.Y.Z')
    return value

def filename(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*', value):
        raise ValueError(f'invalid artifact basename: {value!r}')
    return value

def fingerprint(value):
    if not re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', value):
        raise ValueError('supply a full uppercase archive signing fingerprint')
    return value

def key_fingerprint(key):
    with tempfile.TemporaryDirectory(prefix='httpjet-key-') as temporary:
        output = run(['gpg', '--batch', '--homedir', temporary, '--with-colons',
                      '--import-options', 'show-only', '--import', key], stderr=subprocess.PIPE)
    primaries = []; pending = False
    for line in output.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            pending = True
        elif pending and fields[0] == 'fpr':
            primaries.append(fields[9]); pending = False
    if len(primaries) != 1:
        raise ValueError('archive key must contain exactly one primary public key')
    return fingerprint(primaries[0])

def validate_key(key, expected):
    if key_fingerprint(key) != fingerprint(expected):
        raise ValueError('archive public key does not match the approved fingerprint')

def render_installer(template, output, key, expected, repository, installer_helper=None):
    validate_key(key, expected)
    if not re.fullmatch(r'https://[A-Za-z0-9.:-]+(?:/[A-Za-z0-9._~-]+)+', repository):
        raise ValueError('repository must be HTTPS without credentials/query/fragment')
    armor = key.read_text().strip()
    if not armor.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'):
        raise ValueError('installer requires an ASCII armored public key')
    body = template.read_text()
    for marker, replacement in {
        '@HTTPJET_ARCHIVE_PUBLIC_KEY@': armor,
        '@HTTPJET_ARCHIVE_KEY_FINGERPRINT@': expected,
        '@HTTPJET_REPOSITORY_URL@': repository,
    }.items():
        if marker not in body:
            raise ValueError(f'missing installer marker {marker}')
        body = body.replace(marker, replacement)
    if '@HTTPJET_RELEASE_BASE_URL@' in body:
        body=body.replace('@HTTPJET_RELEASE_BASE_URL@',repository.removesuffix('/apt')+'/releases')
    if '@HTTPJET_INSTALLER_PYTHON@' in body:
        helper=installer_helper or Path(__file__).parents[1]/'services/manage.py'
        import ast
        helper_text=Path(helper).read_text();ast.parse(helper_text)
        body=body.replace('@HTTPJET_INSTALLER_PYTHON@',helper_text.rstrip())
    if re.search(r'@HTTPJET_[A-Z_]+@', body):
        raise ValueError('unresolved installer marker')
    output.write_text(body); output.chmod(0o755)

def validate_elf(binary, arch, libc="gnu"):
    if arch not in ARCHES:
        raise ValueError('unsupported architecture')
    header = run(['readelf', '-hW', binary])
    expected = 'Advanced Micro Devices X86-64' if arch == 'amd64' else 'AArch64'
    if not re.search(r'Machine:\s*' + re.escape(expected) + r'\s*$', header, re.M):
        raise ValueError(f'ELF architecture is not {arch}')
    versions = run(['readelf', '-VW', binary])
    required = [tuple(map(int, match)) for match in re.findall(r'\bGLIBC_([0-9]+)\.([0-9]+)\b', versions)]
    if libc == 'gnu' and (not required or max(required) > (2, 36) or 'GLIBC_PRIVATE' in versions):
        raise ValueError('ELF requires unsupported glibc (maximum 2.36)')
    if libc not in ('gnu','musl'):
        raise ValueError('unsupported libc validation contract')
    needed = re.findall(r'\(NEEDED\).*?\[([^]]+)\]', run(['readelf', '-dW', binary]))
    allowed = {'libc.so.6', 'libm.so.6', 'libgcc_s.so.1', 'libpthread.so.0', 'libdl.so.2',
               'librt.so.1', 'ld-linux-x86-64.so.2', 'ld-linux-aarch64.so.1'}
    if libc == 'musl' and (needed or required or 'GLIBC_' in versions or re.search(r'^\s*INTERP\b',run(['readelf','-lW',binary]),re.M)):
        raise ValueError('fully static musl contract forbids PT_INTERP, DT_NEEDED and GLIBC versions')
    if set(needed) - allowed:
        raise ValueError(f'unexpected runtime libraries: {set(needed) - allowed}')
    if arch == 'amd64' and re.search(r'x86 ISA needed:.*x86-64-v[234]', run(['readelf', '-nW', binary])):
        raise ValueError('ELF requires newer than baseline x86-64')
    return {'architecture': arch, 'libc':libc, 'linkage':'static' if libc=='musl' else 'dynamic', 'glibc_max': '.'.join(map(str, max(required))) if required else None,
            'needed': sorted(needed), 'cpu_baseline': 'x86-64' if arch == 'amd64' else 'armv8-a'}

def verify_artifacts(directory, manifest):
    if manifest.get('schema')==2:
        import universal
        return universal.verify_artifacts(directory,manifest)
    version(manifest['version'])
    if manifest['tag'] != 'v' + manifest['version'] or set(manifest['packages']) != set(ARCHES):
        raise ValueError('malformed release manifest')
    for name, data in manifest['artifacts'].items():
        path = directory / filename(name)
        if path.is_symlink() or not path.is_file() or sha(path) != data['sha256'] or path.stat().st_size != data['size']:
            raise ValueError(f'artifact mismatch: {name}')

def create_manifest(directory, output):
    if load(directory/'provenance-amd64.json').get('release_id'):
        import universal
        return universal.create_manifest(directory,output)
    provenances = [load(directory / f'provenance-{arch}.json') for arch in ARCHES]
    first = provenances[0]; release_version = version(first['version'])
    artifacts = {}; packages = {}
    for arch, provenance in zip(ARCHES, provenances):
        for field in ('version', 'commit', 'tag', 'source_date_epoch', 'archive_fingerprint'):
            if provenance[field] != first[field]:
                raise ValueError(f'native builds disagree on {field}')
        if provenance['architecture'] != arch or provenance['debian_version'] != release_version + '-1':
            raise ValueError('invalid package version/architecture')
        if provenance['tag'] != 'v' + release_version or provenance['rustc_version'] != '1.99.1':
            raise ValueError('tag/Cargo identity or toolchain mismatch')
        if not re.fullmatch(r'[0-9a-f]{40}', provenance['commit']):
            raise ValueError('invalid source commit')
        for name, description in provenance['artifacts'].items():
            filename(name)
            if name in artifacts and artifacts[name] != description:
                raise ValueError(f'native builds disagree on {name}')
            if sha(directory / name) != description['sha256'] or (directory / name).stat().st_size != description['size']:
                raise ValueError(f'artifact mismatch: {name}')
            artifacts[name] = description
        deb = provenance['package']
        if deb != f'httpjet_{release_version}-1_{arch}.deb':
            raise ValueError('unexpected .deb name')
        identity = run(['dpkg-deb', '-f', directory / deb, 'Package', 'Version', 'Architecture'])
        if identity != f'Package: httpjet\nVersion: {release_version}-1\nArchitecture: {arch}\n':
            raise ValueError('.deb identity does not match release')
        with tempfile.TemporaryDirectory(prefix='httpjet-elf-') as temporary:
            run(['dpkg-deb', '-x', directory / deb, temporary])
            validate_elf(Path(temporary) / 'usr/bin/httpjet', arch)
        packages[arch] = deb
        name = f'provenance-{arch}.json'
        artifacts[name] = {'sha256': sha(directory / name), 'size': (directory / name).stat().st_size}
    manifest = {'schema': 1, 'version': release_version, 'tag': 'v' + release_version,
                'commit': first['commit'], 'archive_fingerprint': first['archive_fingerprint'],
                'packages': packages, 'artifacts': artifacts}
    write_json(output, manifest)
    (output.parent / 'SHA256SUMS').write_text(''.join(f"{data['sha256']}  {name}\n" for name, data in sorted(artifacts.items()))
                                            + f'{sha(output)}  {output.name}\n')

def verify_receipt(directory, manifest, row):
    if row['manifest_sha256'] != sha(directory / 'manifest.json') or row['package_sha256'] != sha(directory / manifest['packages'][row['architecture']]):
        raise ValueError('receipt does not identify this candidate')
    if row['status'] != 'passed' or set(row['checks']) != set(CHECKS) or any(v != 'passed' for v in row['checks'].values()):
        raise ValueError('incomplete/failed lifecycle qualification')
    if row['runner'] != 'qemu-tcg' or not re.fullmatch(r'[0-9a-f]{128}', row['image_sha512']):
        raise ValueError('receipt lacks verified VM image identity')
    if row['baseline_kind'] not in ('previous-stable', 'first-release-fixture'):
        raise ValueError('missing upgrade baseline identity')

def qualify(directory, receipts, output):
    if load(directory/'manifest.json').get('schema')==2:
        import universal
        return universal.qualify(directory,receipts,output)
    manifest = load(directory / 'manifest.json'); verify_artifacts(directory, manifest)
    rows = []
    for distro in DISTROS:
        for arch in ARCHES:
            receipt = receipts / f'{distro}-{arch}.json'; row = load(receipt)
            if (row['distro'], row['architecture']) != (distro, arch):
                raise ValueError('qualification target mismatch')
            verify_receipt(directory, manifest, row)
            log = receipts / filename(row['log'])
            if sha(log) != row['log_sha256']:
                raise ValueError('qualification log mismatch')
            shutil.copyfile(receipt, directory / receipt.name); shutil.copyfile(log, directory / log.name)
            rows.append({'receipt': receipt.name, 'sha256': sha(receipt), 'log': log.name, 'log_sha256': sha(log)})
    write_json(output, {'schema': 1, 'manifest_sha256': sha(directory / 'manifest.json'), 'targets': rows, 'status': 'passed'})

def verify_qualification(directory):
    if load(directory/'manifest.json').get('schema')==2:
        import universal
        return universal.verify_qualification(directory)
    expected = {(d, a) for d in DISTROS for a in ARCHES}
    qualification = load(directory / 'qualification.json')
    if qualification['status'] != 'passed' or qualification['manifest_sha256'] != sha(directory / 'manifest.json'):
        raise ValueError('release has no matching qualification')
    actual = set(); manifest = load(directory / 'manifest.json')
    for target in qualification['targets']:
        receipt = directory / filename(target['receipt']); log = directory / filename(target['log'])
        if sha(receipt) != target['sha256'] or sha(log) != target['log_sha256']:
            raise ValueError('qualification evidence hash mismatch')
        row = load(receipt); pair = (row['distro'], row['architecture'])
        if pair in actual or pair not in expected:
            raise ValueError('invalid/duplicate qualification pair')
        verify_receipt(directory, manifest, row)
        if row['log_sha256'] != target['log_sha256']:
            raise ValueError('inconsistent qualification evidence')
        actual.add(pair)
    if actual != expected:
        raise ValueError('all eight VM targets must pass before stable publication')

def stage(directory, output, key, expected, template, repository=REPO_URL, candidate=False, now=None, previous=None, installer_helper=None):
    if load(directory/'manifest.json').get('schema')==2:
        import universal
        return universal.stage(directory,output,key,expected,template,repository,candidate,now,previous,installer_helper)
    if output.exists():
        raise ValueError('snapshot output must not exist')
    validate_key(key, expected)
    manifest = load(directory / 'manifest.json'); verify_artifacts(directory, manifest)
    if manifest['archive_fingerprint'] != expected:
        raise ValueError('candidate was built with another archive key')
    if not candidate:
        verify_qualification(directory)
    output.mkdir(parents=True)
    pool = output / 'pool/main/h/httpjet'; pool.mkdir(parents=True)
    release_dir = output / 'releases' / manifest['tag']; release_dir.mkdir(parents=True)
    if previous is not None:
        for old in (previous / 'history').glob('*.deb'):
            shutil.copyfile(old, pool / old.name)
    for name in manifest['artifacts']:
        destination = (pool if name.endswith('.deb') else release_dir) / name
        if destination.exists() and sha(destination) != sha(directory / name):
            raise ValueError('immutable package identity collision')
        shutil.copyfile(directory / name, destination)
    for name in ('manifest.json', 'SHA256SUMS'):
        shutil.copyfile(directory / name, release_dir / name)
    if not candidate:
        for row in load(directory / 'qualification.json')['targets']:
            for field in ('receipt', 'log'):
                name = filename(row[field]); shutil.copyfile(directory / name, release_dir / name)
        shutil.copyfile(directory / 'qualification.json', release_dir / 'qualification.json')
    all_packages = run(['apt-ftparchive', 'packages', 'pool'], cwd=output)
    for arch in ARCHES:
        stanzas = [s for s in all_packages.strip().split('\n\n') if re.search(r'^Architecture: (?:' + arch + r'|all)$', s, re.M)]
        if len(stanzas) < 2:
            raise ValueError('snapshot needs daemon and architecture-independent keyring')
        index = output / f'dists/stable/main/binary-{arch}/Packages'; index.parent.mkdir(parents=True)
        index.write_text('\n\n'.join(stanzas) + '\n\n')
        index.with_name('Packages.gz').write_bytes(gzip.compress(index.read_bytes(), mtime=0))
        for path in (index, index.with_name('Packages.gz')):
            hashed = index.parent / 'by-hash/SHA256' / sha(path); hashed.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, hashed)
    if previous is not None and load(previous/'manifest.json')['version'] == manifest['version']:
        shutil.copyfile(previous/'approved-install.sh',output/'install.sh')
    else:
        render_installer(template, output/'install.sh', key, expected, repository)
    shutil.copyfile(output/'install.sh',release_dir/'install.sh')
    shutil.copyfile(key,release_dir/'httpjet-archive-keyring.asc')
    now = now or datetime.now(timezone.utc)
    metadata = run(['apt-ftparchive', 'release', 'dists/stable'], cwd=output)
    metadata = '\n'.join(line for line in metadata.splitlines() if not line.startswith('Date:')) + '\n'
    qualification_hash = 'unqualified' if candidate else sha(directory / 'qualification.json')
    fields = {'Origin': 'httpjet', 'Label': 'httpjet', 'Suite': 'stable', 'Codename': 'stable',
              'Architectures': 'amd64 arm64', 'Components': 'main', 'Acquire-By-Hash': 'yes',
              'Date': format_datetime(now, usegmt=True), 'Valid-Until': format_datetime(now + timedelta(days=30), usegmt=True),
              'X-Httpjet-Version': manifest['version'], 'X-Httpjet-Manifest-SHA256': sha(directory / 'manifest.json'),
              'X-Httpjet-Installer-SHA256': sha(output/'install.sh'),
              'X-Httpjet-Qualification-SHA256': qualification_hash, 'X-Httpjet-Archive-Fingerprint': expected}
    release = output / 'dists/stable/Release'
    release.write_text(''.join(f'{k}: {v}\n' for k, v in fields.items()) + metadata)
    for args in (['--clearsign', '--output', release.with_name('InRelease')],
                 ['--armor', '--detach-sign', '--output', release.with_name('Release.gpg')]):
        run(['gpg', '--batch', '--yes', '--pinentry-mode', 'loopback', '--local-user', expected, '--digest-algo', 'SHA256', *args, release])
    shutil.copyfile(key, output / 'httpjet-archive-keyring.asc')
    write_json(output / 'publication.json', {'schema': 1, 'qualified': not candidate,
               'version': manifest['version'], 'manifest_sha256': sha(directory / 'manifest.json'),
               'qualification_sha256': qualification_hash, 'archive_fingerprint': expected,
               'inrelease_sha256': sha(release.with_name('InRelease'))})
    return output

def download(url, output):
    if not url.startswith('https://'):
        raise ValueError('downloads require HTTPS')
    with urllib.request.urlopen(url, timeout=90) as response, output.open('wb') as stream:
        if not response.url.startswith('https://'):
            raise ValueError('refusing HTTPS downgrade redirect')
        shutil.copyfileobj(response, stream)

def fetch_current(repository, output, key, expected, universal_release=False):
    """Fetch ONLY the hashes/version already approved by the current InRelease."""
    if universal_release:
        import universal
        return universal.fetch_current(repository,output,key,expected)
    validate_key(key, expected); output.mkdir(parents=True, exist_ok=False)
    signed = output / 'current.InRelease'; download(repository + '/dists/stable/InRelease', signed)
    with tempfile.TemporaryDirectory(prefix='httpjet-gpgv-') as temporary:
        keyring = Path(temporary) / 'archive.gpg'
        run(['gpg', '--batch', '--yes', '--dearmor', '--output', keyring, key])
        release = run(['gpgv', '--keyring', keyring, '--output', '-', signed])
    fields = dict(line.split(': ', 1) for line in release.splitlines() if ': ' in line and not line.startswith(' '))
    now = datetime.now(timezone.utc)
    issued = parsedate_to_datetime(fields['Date']); expires = parsedate_to_datetime(fields['Valid-Until'])
    if issued > now + timedelta(hours=1) or expires <= now or expires <= issued or expires-issued > timedelta(days=30,minutes=1):
        raise ValueError('current signed repository Date/Valid-Until is expired or invalid')
    current_version = version(fields['X-Httpjet-Version'])
    if fields['X-Httpjet-Archive-Fingerprint'] != expected or not re.fullmatch(r'[0-9a-f]{64}', fields['X-Httpjet-Qualification-SHA256']):
        raise ValueError('current repository has no matching qualification/key identity')
    base = repository + '/releases/v' + current_version
    for name, field in (('manifest.json', 'X-Httpjet-Manifest-SHA256'), ('qualification.json', 'X-Httpjet-Qualification-SHA256')):
        download(base + '/' + name, output / name)
        if sha(output / name) != fields[field]:
            raise ValueError('signed current repository identity mismatch')
    download(base+'/install.sh',output/'approved-install.sh')
    if sha(output/'approved-install.sh') != fields['X-Httpjet-Installer-SHA256']:
        raise ValueError('approved bootstrap installer hash mismatch')
    manifest = load(output / 'manifest.json')
    if manifest['version'] != current_version:
        raise ValueError('current manifest version mismatch')
    for name in manifest['artifacts']:
        filename(name)
        url = repository + '/pool/main/h/httpjet/' + name if name.endswith('.deb') else base + '/' + name
        download(url, output / name)
    for row in load(output / 'qualification.json')['targets']:
        for field in ('receipt', 'log'):
            name = filename(row[field]); download(base + '/' + name, output / name)
    download(base + '/SHA256SUMS', output / 'SHA256SUMS')
    verify_artifacts(output, manifest); verify_qualification(output)
    history = output / 'history'; history.mkdir()
    section = None; signed_hashes = {}
    for line in release.splitlines():
        if not line.startswith(' '):
            section = line.rstrip(':')
        elif section == 'SHA256':
            digest, size, name = line.split(); signed_hashes[name] = (digest, int(size))
    for arch in ARCHES:
        relative = f'main/binary-{arch}/Packages'
        index = output / f'previous-Packages-{arch}'
        download(repository + '/dists/stable/' + relative, index)
        if (sha(index), index.stat().st_size) != signed_hashes[relative]:
            raise ValueError('previous Packages index is not authenticated by current InRelease')
        for stanza in index.read_text().strip().split('\n\n'):
            fields = dict(line.split(': ',1) for line in stanza.splitlines() if ': ' in line and not line.startswith(' '))
            if fields['Package'] not in ('httpjet','httpjet-archive-keyring') or fields['Architecture'] not in (arch,'all'):
                raise ValueError('unexpected historical package')
            name = filename(fields['Filename'].removeprefix('pool/main/h/httpjet/'))
            if fields['Filename'] != 'pool/main/h/httpjet/' + name or not re.fullmatch(r'[0-9a-f]{64}',fields['SHA256']):
                raise ValueError('unsafe previous package record')
            destination = history / name
            if not destination.exists():
                download(repository + '/' + fields['Filename'], destination)
            if sha(destination) != fields['SHA256'] or destination.stat().st_size != int(fields['Size']):
                raise ValueError('historical package hash mismatch')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    elf = commands.add_parser('elf'); elf.add_argument('binary', type=Path); elf.add_argument('architecture', choices=ARCHES); elf.add_argument('--libc', choices=('gnu','musl'), default='gnu')
    manifest = commands.add_parser('manifest'); manifest.add_argument('directory', type=Path)
    qualification = commands.add_parser('qualify'); qualification.add_argument('directory', type=Path); qualification.add_argument('receipts', type=Path)
    carriers=commands.add_parser('sign-carriers');carriers.add_argument('directory',type=Path);carriers.add_argument('--public-key',required=True,type=Path);carriers.add_argument('--fingerprint',required=True)
    for action in ('stage', 'fetch-current', 'render'):
        command = commands.add_parser(action)
        command.add_argument('--public-key', required=True, type=Path); command.add_argument('--fingerprint', required=True)
        command.add_argument('--repository', default=REPO_URL); command.add_argument('--output', required=True, type=Path)
        if action in ('stage', 'render'):
            command.add_argument('--template', type=Path, default=Path('packaging/installer/install.sh.in'))
        if action=='fetch-current':command.add_argument('--universal',action='store_true')
        if action in ('stage','render'):command.add_argument('--installer-helper',type=Path)
        if action == 'stage':
            command.add_argument('--directory', required=True, type=Path)
            command.add_argument('--candidate', action='store_true', help='local test snapshot; publish.py rejects this')
            command.add_argument('--previous', type=Path, help='authenticated fetch-current output to retain older APT versions')
    args = parser.parse_args()
    if args.command=='sign-carriers':
        import universal
        universal.sign_carriers(args.directory,args.public_key,args.fingerprint)
    elif args.command == 'elf':
        print(json.dumps(validate_elf(args.binary, args.architecture, args.libc), sort_keys=True))
    elif args.command == 'manifest':
        create_manifest(args.directory, args.directory / 'manifest.json')
    elif args.command == 'qualify':
        qualify(args.directory, args.receipts, args.directory / 'qualification.json')
    elif args.command == 'stage':
        stage(args.directory, args.output, args.public_key, args.fingerprint, args.template, args.repository, args.candidate, previous=args.previous, installer_helper=args.installer_helper)
    elif args.command == 'render':
        render_installer(args.template, args.output, args.public_key, args.fingerprint, args.repository, installer_helper=args.installer_helper)
    elif args.command == 'fetch-current':
        fetch_current(args.repository, args.output, args.public_key, args.fingerprint, args.universal)

if __name__ == '__main__':
    main()
