#!/usr/bin/env python3
"""Package one authenticated same-run source payload into DEB, RPM and tar."""
import argparse
import gzip
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


session_tool = module('httpjet_build_session', 'build-session.py')
inspection = module('httpjet_carrier_inspection', 'payload.py')


def run(*arguments, **options):
    return subprocess.run(list(map(str, arguments)), check=True, **options)


def copy(source, destination, mode=0o644):
    destination = Path(destination); destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination); destination.chmod(mode)


def archive(directory, destination, epoch):
    with Path(destination).open('wb') as output, gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as tar:
            for path in [directory, *sorted(directory.rglob('*'))]:
                if path.is_symlink() or not (path.is_dir() or path.is_file()):
                    raise ValueError(f'carrier asset must be a regular file/directory: {path}')
                relative = path.relative_to(directory.parent)
                info = tar.gettarinfo(str(path), arcname=str(relative))
                info.uid = info.gid = 0; info.uname = info.gname = 'root'; info.mtime = epoch
                if path.is_file():
                    with path.open('rb') as data: tar.addfile(info, data)
                else: tar.addfile(info)


def build(root, session, output, arch, release_id):
    root = root.resolve(); output = output.resolve(); output.mkdir(parents=True, exist_ok=True)
    if any(name in os.environ for name in ('HTTPJET_PACKAGE_TEST', 'HTTPJET_TEST_PREBUILT')):
        raise ValueError('production carriers refuse test/prebuilt hooks')
    version, revision = release_id.rsplit('-', 1)
    if not revision.isdigit() or int(revision) < 1:
        raise ValueError('invalid release revision')
    receipt_path = session / 'payload.json'
    with tempfile.TemporaryDirectory(prefix='httpjet-carriers-') as temporary:
        work = Path(temporary)
        verified = work / 'httpjet'
        receipt = session_tool.consume(session, receipt_path, root, arch, release_id, verified)
        epoch = receipt['source_date_epoch']; binary_sha = receipt['binary_sha256']
        env = os.environ | {'HTTPJET_BUILD_SESSION': str(session), 'HTTPJET_CARRIER_RECEIPT': str(receipt_path),
                            'SOURCE_DATE_EPOCH': str(epoch)}
        run('dpkg-buildpackage', '-us', '-uc', '-b', cwd=root, env=env)
        deb = f'httpjet_{release_id}_{arch}.deb'
        deb_key = f'httpjet-archive-keyring_{release_id}_all.deb'
        for name in (deb, deb_key, f'httpjet_{release_id}_{arch}.buildinfo'):
            copy(root.parent / name, output / name)
        inspection.verify_carrier_binary(output / deb, 'deb', binary_sha)
        run('make', '-f', 'debian/rules', 'clean', cwd=root)
        session_tool.consume(session, receipt_path, root, arch, release_id, verified)

        portable = work / f'httpjet-{release_id}'
        copy(verified, portable / 'bin/httpjet', 0o755)
        shutil.copytree(root / 'packaging/debian/conf', portable / 'share/httpjet/conf')
        shutil.copytree(root / 'packaging/debian/welcome', portable / 'share/httpjet/welcome')
        shutil.copytree(root / 'packaging/services', portable / 'share/httpjet/services',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'tests', 'test_*'))
        for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
            copy(root / name, portable / 'share/doc/httpjet' / name)
        tar_name = f'httpjet-{release_id}-linux-{arch}-static.tar.gz'
        archive(portable, output / tar_name, epoch)
        if inspection.sha_bytes(inspection.tar_binary(output / tar_name, release_id)) != binary_sha:
            raise ValueError('portable carrier changed the source payload')

        rpm_top = work / 'rpm'
        for name in ('SOURCES', 'SPECS', 'BUILD', 'BUILDROOT', 'RPMS', 'SRPMS'):
            (rpm_top / name).mkdir(parents=True)
        rpm_payload = work / f'httpjet-{release_id}-payload'
        copy(verified, rpm_payload / 'usr/bin/httpjet', 0o755)
        shutil.copytree(root / 'packaging/debian/conf', rpm_payload / 'etc/httpjet/conf')
        shutil.copytree(root / 'packaging/debian/welcome', rpm_payload / 'usr/share/httpjet/welcome')
        copy(root / 'debian/httpjet.service', rpm_payload / 'usr/lib/systemd/system/httpjet.service')
        copy(root / 'packaging/rpm/package-helper.sh', rpm_payload / 'usr/libexec/httpjet/package-helper', 0o755)
        copy(root / 'packaging/rpm/README.md', rpm_payload / 'usr/share/doc/httpjet/README.md')
        copy(root / 'THIRD_PARTY_NOTICES.md', rpm_payload / 'usr/share/doc/httpjet/THIRD_PARTY_NOTICES.md')
        copy(root / 'LICENSE', rpm_payload / 'usr/share/licenses/httpjet/LICENSE')
        archive(rpm_payload, rpm_top / 'SOURCES' / f'httpjet-{release_id}-payload.tar.gz', epoch)
        copy(root / 'packaging/debian/archive-keyring.asc', rpm_top / 'SOURCES/archive-keyring.asc')
        copy(root / 'packaging/rpm/preinstall.sh', rpm_top / 'SOURCES/preinstall.sh')
        rpm_arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}[arch]
        run('python3', '-B', root / 'packaging/rpm/test_scriptlets.py', cwd=root)
        run('rpmbuild', '-bb', '--target', rpm_arch, '--define', f'_topdir {rpm_top}',
            '--define', f'httpjet_version {version}', '--define', f'httpjet_revision {revision}',
            '--define', '_buildhost reproducible.httpjet.invalid',
            '--define', 'use_source_date_epoch_as_buildtime 1',
            '--define', 'clamp_mtime_to_source_date_epoch 1',
            root / 'packaging/rpm/httpjet.spec', env=env)
        rpm_name = f'httpjet-{release_id}.{rpm_arch}.rpm'
        rpm_key = f'httpjet-archive-keyring-{release_id}.noarch.rpm'
        for name, directory in ((rpm_name, rpm_arch), (rpm_key, 'noarch')):
            copy(rpm_top / 'RPMS' / directory / name, output / name)
        inspection.verify_carrier_binary(output / rpm_name, 'rpm', binary_sha)
        session_tool.consume(session, receipt_path, root, arch, release_id, verified)
        result = {'package': deb, 'rpm_package': rpm_name, 'keyring_deb': deb_key,
                  'keyring_rpm': rpm_key, 'portable': tar_name, 'binary_sha256': binary_sha,
                  'source_tree_sha256': receipt['source_tree_sha256'], 'rpm_signed': False}
        (output / f'carriers-{arch}.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'session', 'output'): parser.add_argument(name, type=Path)
    parser.add_argument('arch', choices=('amd64', 'arm64')); parser.add_argument('release_id')
    arguments = parser.parse_args()
    build(arguments.root, arguments.session.resolve(), arguments.output, arguments.arch, arguments.release_id)
