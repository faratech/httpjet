#!/usr/bin/env python3
"""Build a disposable ext4 qualification disk from hash-locked upstream inputs.

No host filesystem is mounted. The real target init takes over after the guest's
temporary SSH/bootstrap setup; the installer is tested under that target init.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

from release import download, sha, write_json


RECIPES = {'alpine': 'apk', 'void-musl': 'xbps', 'devuan-sysv': 'apt',
           'arch': 'pacman', 'gentoo-openrc': 'emerge', 'slackware-sysv': 'slackware'}


def archive_name(name, prefix=''):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError(f'unsafe rootfs archive path: {name!r}')
    parts = tuple(part for part in path.parts if part not in ('', '.'))
    if prefix:
        expected = PurePosixPath(prefix).parts
        if parts[:len(expected)] != expected:
            raise ValueError('rootfs member is outside its declared archive prefix')
        parts = parts[len(expected):]
    return Path(*parts) if parts else Path('.')


def safe_path(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('unsafe target path')
    current = root
    for component in relative.parts[:-1]:
        current /= component
        if current.is_symlink():
            raise ValueError('refusing to traverse a rootfs symlink on the host')
        if current.exists() and not current.is_dir():
            raise ValueError('rootfs parent is not a directory')
        current.mkdir(mode=0o700, exist_ok=True)
    return root / relative


def metadata(path, member):
    if not 0 <= member.uid < 2**32 - 1 or not 0 <= member.gid < 2**32 - 1:
        raise ValueError('rootfs member has invalid numeric ownership')
    if os.geteuid() == 0:
        os.chown(path, member.uid, member.gid, follow_symlinks=False)
    if not path.is_symlink():
        os.chmod(path, member.mode & 0o7777)
        os.utime(path, (member.mtime, member.mtime), follow_symlinks=False)


def extract_rootfs(archive, root, prefix='', compression=None, ignored_members=()):
    root = Path(root)
    root.mkdir(mode=0o700)
    links = []
    directories = []
    total = 0
    decoder = None
    if compression == 'tar.zst' or str(archive).endswith(('.tar.zst', '.tar.zstd')):
        decoder = subprocess.Popen(['zstd', '--decompress', '--stdout', str(archive)], stdout=subprocess.PIPE)
        opened = tarfile.open(fileobj=decoder.stdout, mode='r|')
    else:
        opened = tarfile.open(archive, mode='r|*')
    count = 0
    ignored = set()
    try:
        with opened:
            for member in opened:
                count += 1
                total += member.size
                if count > 500000 or total > 8 * 1024**3:
                    raise ValueError('rootfs exceeds qualification extraction limits')
                # Arch's official bootstrap includes two top-level informational
                # files alongside the root directory. Never extract them, and
                # continue to reject every other member outside the prefix.
                if member.name in ignored_members:
                    if not member.isfile() or member.name in ignored:
                        raise ValueError('invalid rootfs archive metadata member')
                    ignored.add(member.name)
                    continue
                relative = archive_name(member.name, prefix)
                if relative == Path('.'):
                    if member.isdir():
                        directories.append((root, member))
                    continue
                path = safe_path(root, relative)
                if member.issym() or member.islnk():
                    links.append((relative, member))
                elif member.isdir():
                    if path.exists() and not path.is_dir():
                        raise ValueError('conflicting rootfs directory')
                    path.mkdir(mode=0o700, exist_ok=True)
                    directories.append((path, member))
                elif member.isfile():
                    with path.open('xb') as target, opened.extractfile(member) as source:
                        shutil.copyfileobj(source, target)
                    metadata(path, member)
                elif relative.parts[0] not in ('dev', 'run', 'tmp'):
                    raise ValueError('rootfs contains a persistent special file')
        pending = links
        while pending:
            later = []
            for relative, member in pending:
                path = safe_path(root, relative)
                if path.exists() or path.is_symlink():
                    raise ValueError('conflicting rootfs link')
                if member.issym():
                    if '\x00' in member.linkname:
                        raise ValueError('invalid rootfs symlink')
                    os.symlink(member.linkname, path)
                    metadata(path, member)
                else:
                    linked = safe_path(root, archive_name(member.linkname, prefix))
                    if not linked.exists():
                        later.append((relative, member))
                        continue
                    if linked.is_symlink() or not stat.S_ISREG(linked.lstat().st_mode):
                        raise ValueError('rootfs hardlink target is not a local regular file')
                    os.link(linked, path, follow_symlinks=False)
            if len(later) == len(pending):
                raise ValueError('unresolved rootfs hardlinks')
            pending = later
        for path, member in sorted(directories, key=lambda item: len(item[0].parts), reverse=True):
            metadata(path, member)
        if decoder is not None:
            # Drain normal tar padding so the decoder can finish instead of
            # treating its still-open output pipe as a failed archive.
            padding = 0
            while chunk := decoder.stdout.read(65536):
                padding += len(chunk)
                if padding > 1024 * 1024 or any(chunk):
                    raise ValueError('unexpected data after the rootfs tar archive')
            if decoder.wait(timeout=10) != 0:
                raise ValueError('zstd rootfs decoding failed')
    finally:
        if decoder is not None:
            decoder.stdout.close()
            if decoder.poll() is None:
                decoder.terminate()
            decoder.wait()
    return {'members': count, 'expanded_bytes': total}


def locked_blob(source, work, name, artifact_dir=None, artifact_manifest=None):
    if not isinstance(source, dict) or not re.fullmatch(r'[0-9a-f]{64}', source.get('sha256', '')):
        raise ValueError('qualification input needs a pinned SHA256')
    path = work / name
    if 'artifact' in source:
        artifact = source['artifact']
        if not isinstance(artifact, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*', artifact):
            raise ValueError('qualification artifact requires a strict basename')
        if artifact_dir is None or not isinstance(artifact_manifest, dict):
            raise ValueError('local qualification artifact needs its authenticated manifest')
        description = artifact_manifest.get('artifacts', {}).get(artifact, {})
        local = Path(artifact_dir) / artifact
        if local.is_symlink() or not local.is_file() or description.get('sha256') != source['sha256'] or local.stat().st_size != description.get('size'):
            raise ValueError('qualification artifact is not bound by its manifest')
        shutil.copyfile(local, path)
    else:
        url = source.get('url', '')
        if not url.startswith('https://'):
            raise ValueError('qualification inputs require HTTPS')
        download(url, path)
    if sha(path) != source['sha256']:
        raise ValueError('qualification input checksum mismatch: ' + name)
    return path


def inject(root, relative, content, mode):
    path = safe_path(root, relative)
    if path.is_symlink():
        path.unlink()
    if path.exists() and not path.is_file():
        raise ValueError('qualification setup would replace a non-file')
    path.write_bytes(content)
    path.chmod(mode)


def seed_slackware_fstab(root, recipe):
    if recipe != 'slackware-sysv':
        return
    path = safe_path(root, Path('etc/fstab'))
    if not path.exists() and not path.is_symlink():
        inject(root, 'etc/fstab', b'/dev/vda / ext4 defaults 0 1\ntmpfs /dev/shm tmpfs defaults 0 0\n', 0o644)


def build(row, lock, work, public_key, artifact_dir=None, artifact_manifest=None):
    if os.geteuid() != 0:
        raise ValueError('rootfs image creation requires isolated root to preserve target numeric ownership')
    work = Path(work)
    if work.exists():
        raise ValueError('rootfs build directory must be new')
    recipe = row['source']['recipe']
    if recipe not in RECIPES or lock.get('bootstrap') != recipe:
        raise ValueError('rootfs lock does not match a trusted qualification recipe')
    target_init = lock.get('init', '')
    if not target_init.startswith('/') or '..' in PurePosixPath(target_init).parts or '\n' in target_init:
        raise ValueError('rootfs lock needs an absolute target init path')
    public_key = Path(public_key).read_text().strip()
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?', public_key):
        raise ValueError('qualification needs one generated Ed25519 SSH public key')
    work.mkdir(mode=0o700)
    archive = locked_blob(lock['rootfs'], work, 'rootfs.archive', artifact_dir, artifact_manifest)
    kernel = locked_blob(lock['kernel'], work, 'kernel', artifact_dir, artifact_manifest)
    initrd = locked_blob(lock['initrd'], work, 'initrd', artifact_dir, artifact_manifest)
    root = work / 'root'
    prefix = lock['rootfs'].get('strip_prefix', '')
    ignored = ('pkglist.x86_64.txt', 'version') if recipe == 'arch' and prefix == 'root.x86_64' else ()
    extracted = extract_rootfs(archive, root, prefix, lock['rootfs'].get('format'), ignored)
    seed_slackware_fstab(root, recipe)
    inject(root, 'httpjet-qualification-init', Path(__file__).with_name('rootfs-init.sh').read_bytes(), 0o700)
    inject(root, 'httpjet-qualification-recipe', (recipe + '\n').encode(), 0o600)
    inject(root, 'httpjet-qualification-target-init', (target_init + '\n').encode(), 0o600)
    inject(root, 'httpjet-qualification-ssh.pub', (public_key + '\n').encode(), 0o600)
    if lock.get('prepared') is True:
        inject(root, 'httpjet-qualification-prepared', b'1\n', 0o600)
    image = work / 'rootfs.ext4'
    with image.open('xb') as output:
        output.truncate(16 * 1024**3)
    subprocess.run(['mkfs.ext4', '-F', '-q', '-d', str(root), str(image)], check=True)
    console = 'ttyAMA0' if row['architecture'] == 'arm64' else 'ttyS0'
    result = {'disk': str(image), 'format': 'raw', 'kernel': str(kernel), 'initrd': str(initrd),
              'kernel_args': f'root=/dev/vda rootfstype=ext4 rw rootwait console={console} init=/httpjet-qualification-init',
              'rootfs_sha256': lock['rootfs']['sha256'], 'kernel_sha256': lock['kernel']['sha256'],
              'initrd_sha256': lock['initrd']['sha256'],
              'bootstrap_sha256': sha(Path(__file__).with_name('rootfs-init.sh')),
              'builder_sha256': sha(Path(__file__)),
              'ssh_public_sha256': hashlib.sha256((public_key + '\n').encode()).hexdigest(),
              'recipe': recipe, **extracted}
    write_json(work / 'rootfs-evidence.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--row', required=True, type=Path)
    parser.add_argument('--lock', required=True, type=Path)
    parser.add_argument('--public-key', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--artifact-directory', type=Path)
    parser.add_argument('--artifact-manifest', type=Path)
    args = parser.parse_args()
    print(json.dumps(build(json.loads(args.row.read_text()), json.loads(args.lock.read_text()),
                           args.output, args.public_key, args.artifact_directory,
                           json.loads(args.artifact_manifest.read_text()) if args.artifact_manifest else None), sort_keys=True))


if __name__ == '__main__':
    main()
