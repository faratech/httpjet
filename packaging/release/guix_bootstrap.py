#!/usr/bin/env python3
"""Pinned, authenticated Guix bootstrap for disposable qualification builders."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request

VERSION = '1.5.0'
# The GNU release announcement endorses this signing key and both archive hashes.
ANNOUNCEMENT = 'https://lists.nongnu.org/archive/html/guix-devel/2026-01/msg00125.html'
KEY_SOURCE = 'https://codeberg.org/efraim.gpg'
FINGERPRINT = 'A28BF40C3E551372662D14F741AAE7DCCA3D8351'
KEY_SHA256 = '5f122137a46bbfe4e3173d7be08948a2c7fdbba4f0d584c1a8055a288473ff28'
KEY = Path(__file__).with_name('guix-1.5.0.pub')
PROFILE = Path('/var/guix/profiles/per-user/root/current-guix')
ARCHIVES = {
    'amd64': ('x86_64-linux', 'aa41025489c5061543e9c48873eaa829b900b2da75d40f9648913622f5f47817', 135985908),
    'arm64': ('aarch64-linux', 'a5d58b1d0294cad6adb1f2aff627d37feb5db763fdffbceb8551f2b12123cf39', 135049676),
}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def descriptor(architecture):
    system, digest, size = ARCHIVES[architecture]
    name = 'guix-binary-' + VERSION + '.' + system + '.tar.xz'
    url = 'https://ftp.gnu.org/gnu/guix/' + name
    return {'version': VERSION, 'system': system, 'archive': name, 'url': url,
            'sha256': digest, 'size': size, 'signature_url': url + '.sig',
            'primary_fingerprint': FINGERPRINT, 'key_sha256': KEY_SHA256,
            'key_source': KEY_SOURCE, 'release_announcement': ANNOUNCEMENT,
            'script_sha256': sha(__file__)}


def stage(directory):
    directory = Path(directory)
    if KEY.is_symlink() or sha(KEY) != KEY_SHA256:
        raise ValueError('approved Guix bootstrap public key changed')
    for source in (Path(__file__), KEY):
        target = directory / source.name
        if target.exists() or target.is_symlink():
            raise ValueError('Guix bootstrap input already exists')
        shutil.copyfile(source, target)


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, target):
        parts = urllib.parse.urlsplit(target)
        if parts.scheme != 'https' or parts.username or parts.password:
            raise ValueError('Guix bootstrap refuses an HTTPS downgrade or credential redirect')
        return super().redirect_request(request, fp, code, message, headers, target)


def download(url, output, limit):
    request = urllib.request.Request(url, headers={'User-Agent': 'httpjet-guix-bootstrap/' + VERSION})
    with urllib.request.build_opener(HTTPSRedirect()).open(request, timeout=90) as response, output.open('xb') as stream:
        if urllib.parse.urlsplit(response.url).scheme != 'https':
            raise ValueError('Guix bootstrap download left HTTPS')
        count = 0
        while block := response.read(min(1024 * 1024, limit + 1 - count)):
            count += len(block)
            if count > limit:
                raise ValueError('Guix bootstrap download exceeds pinned size bound')
            stream.write(block)


def execute(arguments, **options):
    try:
        return subprocess.run(list(map(str, arguments)), check=True, capture_output=True,
                              text=True, timeout=120, **options).stdout
    except subprocess.CalledProcessError as error:
        raise RuntimeError('Guix bootstrap command failed (' + Path(str(arguments[0])).name
                           + '):\n' + (error.stderr or '')[-6000:]) from error


def verify(architecture, archive, signature, key, work):
    expected = descriptor(architecture)
    if key.is_symlink() or not key.is_file() or sha(key) != KEY_SHA256:
        raise ValueError('Guix bootstrap public key differs from approved bytes')
    if archive.is_symlink() or archive.stat().st_size != expected['size'] or sha(archive) != expected['sha256']:
        raise ValueError('Guix bootstrap archive differs from pinned release SHA256/size')
    if signature.is_symlink() or not signature.is_file() or signature.stat().st_size > 65536:
        raise ValueError('invalid Guix bootstrap signature file')
    home = work / 'gnupg'
    home.mkdir(mode=0o700)
    command = ['gpg', '--batch', '--no-options', '--homedir', home, '--no-auto-key-retrieve']
    execute(command + ['--import', key])
    listing = execute(command + ['--with-colons', '--list-keys'])
    primary, pending = [], False
    for line in listing.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            if fields[1] in ('r', 'e', 'd'):
                raise ValueError('Guix bootstrap signing key is revoked, expired or disabled')
            pending = True
        elif pending and fields[0] == 'fpr':
            primary.append(fields[9]); pending = False
    if primary != [FINGERPRINT]:
        raise ValueError('Guix bootstrap primary fingerprint differs from the approved release key')
    status = execute(['gpgv', '--status-fd', '1', '--keyring', home / 'pubring.kbx', signature, archive])
    valid = [line.split()[2:] for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    if len(valid) != 1 or not (valid[0][0] == FINGERPRINT or valid[0][-1] == FINGERPRINT):
        raise ValueError('Guix bootstrap lacks the approved full-key signature')
    return {**expected, 'signature_valid': True, 'checksum_verified': True}


def validate_archive(archive):
    total, count = 0, 0
    with tarfile.open(archive, 'r|xz') as source:
        for member in source:
            if member.name == '.':
                continue
            if not member.name.startswith('./'):
                raise ValueError('Guix bootstrap archive prefix changed')
            path = PurePosixPath(member.name[2:])
            if path.is_absolute() or '..' in path.parts or not path.parts:
                raise ValueError('unsafe Guix bootstrap archive path')
            if path.parts[0] != 'gnu' and path != PurePosixPath('var') and not path.is_relative_to('var/guix'):
                raise ValueError('Guix bootstrap may install only /gnu and /var/guix')
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError('Guix bootstrap archive contains a device or special file')
            total += member.size; count += 1
            if total > 4 * 1024**3 or count > 100000:
                raise ValueError('Guix bootstrap archive exceeds its extraction bound')


def bootstrap(architecture, receipt, artifacts=None):
    if os.geteuid() != 0 or not Path('/.dockerenv').is_file():
        raise ValueError('Guix bootstrap is restricted to the disposable builder container')
    native = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if native != architecture:
        raise ValueError('Guix bootstrap must run on its native architecture')
    if any(path.exists() or path.is_symlink() for path in (Path('/gnu'), Path('/var/guix'))):
        raise ValueError('Guix bootstrap refuses an existing store/profile')
    expected = descriptor(architecture)
    with tempfile.TemporaryDirectory(prefix='httpjet-guix-bootstrap-') as temporary:
        work = Path(temporary)
        archive = work / expected['archive']; signature = work / (expected['archive'] + '.sig')
        if artifacts:
            for destination in (archive, signature):
                source = Path(artifacts) / destination.name
                if source.is_symlink() or not source.is_file():
                    raise ValueError('offline Guix bootstrap input is not a regular file')
                shutil.copyfile(source, destination)
        else:
            download(expected['url'], archive, expected['size'])
            download(expected['signature_url'], signature, 65536)
        report = verify(architecture, archive, signature, KEY, work)
        validate_archive(archive)
        execute(['tar', '--extract', '--strip-components=1', '--no-same-owner', '--file', archive, '-C', '/'])
    if not (PROFILE / 'bin/guix').is_file() or not (PROFILE / 'bin/guix-daemon').is_file():
        raise ValueError('authenticated Guix archive did not provide the expected profile')
    version = execute([PROFILE / 'bin/guix', '--version']).splitlines()[0]
    if version != 'guix (GNU Guix) ' + VERSION:
        raise ValueError('Guix bootstrap activated an unexpected version')
    report.update(status='passed', scope='disposable-guix-builder-bootstrap', native_architecture=architecture,
                  profile=str(PROFILE), observed_version=version)
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=tuple(ARCHIVES), required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--inside-builder', action='store_true', required=True)
    args = parser.parse_args()
    print(json.dumps(bootstrap(args.architecture, args.receipt, args.artifacts), sort_keys=True))


if __name__ == '__main__':
    main()
