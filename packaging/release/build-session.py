#!/usr/bin/env python3
"""Bind source-built static payloads to one private carrier-packaging session."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import tomllib


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def source_digest(root):
    root = Path(root).resolve()
    digest = hashlib.sha256()
    excluded = {'.git', 'target', 'dist', 'debian/build', 'debian/tmp',
                'debian/.debhelper', 'debian/httpjet', 'debian/httpjet-archive-keyring',
                'debian/httpjet-dbgsym'}
    for directory, directories, files in os.walk(root):
        relative = Path(directory).relative_to(root)
        digest.update(b'directory\0' + relative.as_posix().encode() + b'\0'
                      + str(stat.S_IMODE(Path(directory).stat().st_mode)).encode() + b'\0')
        directories[:] = sorted(name for name in directories
            if name != '__pycache__' and (relative / name).as_posix() not in excluded)
        for name in sorted(files):
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            if rel.startswith('debian/') and (name in ('files', 'debhelper-build-stamp', 'autoreconf.before', 'autoreconf.after')
                    or name.endswith(('.substvars', '.debhelper', '.debhelper.log'))):
                continue
            info = path.lstat()
            digest.update(rel.encode() + b'\0' + str(stat.S_IMODE(info.st_mode)).encode() + b'\0')
            if path.is_symlink():
                digest.update(b'link\0' + os.readlink(path).encode())
            elif path.is_file():
                digest.update(b'file\0' + bytes.fromhex(sha(path)))
            else:
                raise ValueError(f'unsupported source input: {rel}')
    return digest.hexdigest()


def command(*arguments):
    return subprocess.run(list(map(str, arguments)), check=True, capture_output=True, text=True).stdout


def static_elf(binary, arch):
    machine = {'amd64': 'Advanced Micro Devices X86-64', 'arm64': 'AArch64'}[arch]
    if machine not in command('readelf', '-hW', binary):
        raise ValueError('payload ELF architecture mismatch')
    if 'INTERP' in command('readelf', '-lW', binary):
        raise ValueError('static payload must not have PT_INTERP')
    if '(NEEDED)' in command('readelf', '-dW', binary):
        raise ValueError('static payload must not have DT_NEEDED')
    if 'GLIBC_' in command('readelf', '-VW', binary):
        raise ValueError('static payload must not need GLIBC symbol versions')
    if arch == 'amd64' and any(level in command('readelf', '-nW', binary)
                              for level in ('x86-64-v2', 'x86-64-v3', 'x86-64-v4')):
        raise ValueError('payload requires a newer CPU than baseline x86-64')
    return {'architecture': arch, 'libc': 'musl', 'linkage': 'static',
            'cpu_baseline': 'x86-64' if arch == 'amd64' else 'armv8-a'}


def load_session(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('carrier session must not be a symbolic link')
    path = path.resolve(strict=True)
    if path.stat().st_uid != os.geteuid() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('carrier session must be a private directory owned by the builder')
    return path, json.loads((path / 'session.json').read_text())


def create_session(root, session, commit, tag, arch, release_id, epoch):
    root = Path(root).resolve(strict=True)
    version = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['package']['version']
    expected = command('dpkg-parsechangelog', '-l' + str(root / 'debian/changelog'), '-S', 'Version').strip()
    if release_id != expected or release_id.rsplit('-', 1)[0] != version:
        raise ValueError('source/Cargo/package release identities disagree')
    session = Path(session)
    session.mkdir(mode=0o700)
    save(session / 'session.json', {'schema': 1, 'token': secrets.token_hex(32),
        'source_root': str(root), 'source_tree_sha256': source_digest(root), 'commit': commit,
        'tag': tag, 'architecture': arch, 'release_id': release_id, 'version': version,
        'source_date_epoch': int(epoch), 'phase': 'source-ready'})


def seal(session_path, binary):
    session_path, session = load_session(session_path)
    if session['phase'] != 'source-ready' or source_digest(session['source_root']) != session['source_tree_sha256']:
        raise ValueError('source changed during payload compilation or session was already consumed')
    static_elf(binary, session['architecture'])
    if command(binary, '--version').strip() != 'httpjet ' + session['version']:
        raise ValueError('source payload version mismatch')
    destination = session_path / 'httpjet'
    shutil.copyfile(binary, destination)
    destination.chmod(0o755)
    receipt = {key: session[key] for key in ('source_root', 'source_tree_sha256', 'commit', 'tag',
        'architecture', 'release_id', 'version', 'source_date_epoch')}
    receipt.update({'schema': 1, 'binary': str(destination), 'binary_sha256': sha(destination),
                    'libc': 'musl', 'linkage': 'static', 'rustc_version': '1.99.1',
                    'target': {'amd64': 'x86_64-unknown-linux-musl', 'arm64': 'aarch64-unknown-linux-musl'}[session['architecture']]})
    receipt['mac'] = hmac.new(bytes.fromhex(session['token']), canonical(receipt), hashlib.sha256).hexdigest()
    save(session_path / 'payload.json', receipt)
    session['phase'] = 'payload-built'
    save(session_path / 'session.json', session)


def consume(session_path, receipt_path, root, arch, release_id, destination):
    session_path, session = load_session(session_path)
    receipt_path = Path(receipt_path).resolve(strict=True)
    if receipt_path != session_path / 'payload.json' or session['phase'] != 'payload-built':
        raise ValueError('carrier receipt is not from the active source-build session')
    receipt = json.loads(receipt_path.read_text())
    mac = receipt.pop('mac')
    expected_mac = hmac.new(bytes.fromhex(session['token']), canonical(receipt), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError('carrier payload receipt authentication failed')
    for key, value in {'source_root': str(Path(root).resolve()), 'architecture': arch,
                       'release_id': release_id}.items():
        if receipt[key] != value or receipt[key] != session[key]:
            raise ValueError(f'carrier payload {key} does not match this build')
    for key in ('commit', 'tag', 'source_tree_sha256'):
        if receipt[key] != session[key]:
            raise ValueError(f'carrier payload {key} does not match source session')
    if source_digest(root) != receipt['source_tree_sha256']:
        raise ValueError('carrier source differs from the source-built payload')
    binary = Path(receipt['binary'])
    if binary != session_path / 'httpjet' or binary.is_symlink() or sha(binary) != receipt['binary_sha256']:
        raise ValueError('carrier binary differs from source-built payload')
    static_elf(binary, arch)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(binary, destination)
    destination.chmod(0o755)
    return receipt


def compile_payload(session_path):
    session_path, session = load_session(session_path)
    if session['phase'] != 'source-ready' or source_digest(session['source_root']) != session['source_tree_sha256']:
        raise ValueError('source session is not ready for compilation')
    output = session_path / 'compiled-source'
    subprocess.run(['bash', str(Path(session['source_root']) / 'packaging/release/build-musl.sh'),
                    session['architecture'], str(output)], check=True)
    seal(session_path, output)
    output.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    child = sub.add_parser('elf'); child.add_argument('binary'); child.add_argument('arch')
    child = sub.add_parser('session')
    for field in ('root', 'session', 'commit', 'tag', 'arch', 'release_id', 'epoch'): child.add_argument(field)
    child = sub.add_parser('compile'); child.add_argument('session')
    child = sub.add_parser('consume')
    for field in ('session', 'receipt', 'root', 'arch', 'release_id', 'destination'): child.add_argument(field)
    args = parser.parse_args()
    if args.action == 'elf': print(json.dumps(static_elf(args.binary, args.arch)))
    elif args.action == 'session': create_session(args.root, args.session, args.commit, args.tag, args.arch, args.release_id, args.epoch)
    elif args.action == 'compile': compile_payload(args.session)
    else: consume(args.session, args.receipt, args.root, args.arch, args.release_id, args.destination)


if __name__ == '__main__':
    main()
