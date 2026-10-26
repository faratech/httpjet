#!/usr/bin/env python3
"""Derive a non-root OCI image from verified native release artifacts."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
BASE_IMAGE = 'alpine@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f'
BINARY_PATH = '/usr/bin/httpjet'
PROBE_PATH = '/usr/libexec/httpjet/io-uring-probe'
spec = importlib.util.spec_from_file_location('httpjet_oci_payload', HERE / 'payload.py')
payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(payload)
spec = importlib.util.spec_from_file_location('httpjet_oci_static', HERE / 'build-session.py')
static = importlib.util.module_from_spec(spec); spec.loader.exec_module(static)


def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content); path.chmod(mode)


def docker(host, *arguments, capture=False):
    command = ['docker'] + (['--host', host] if host else []) + list(map(str, arguments))
    result = subprocess.run(command, check=True, env=os.environ | {'DOCKER_BUILDKIT': '0'},
                            stdout=subprocess.PIPE if capture else None, text=True)
    return result.stdout.strip() if capture else None


def verified_native(directory, arch):
    path = directory / f'provenance-{arch}.json'
    if path.is_symlink(): raise ValueError('native provenance must be a regular file')
    data = json.loads(path.read_text())
    if data['schema'] != 2 or data['architecture'] != arch or data['libc'] != 'musl':
        raise ValueError('native static build provenance is required')
    if data['target'] != {'amd64': 'x86_64-unknown-linux-musl', 'arm64': 'aarch64-unknown-linux-musl'}[arch]:
        raise ValueError('native payload target mismatch')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-[1-9][0-9]*', data['release_id']):
        raise ValueError('invalid canonical release identity')
    for name, description in data['artifacts'].items():
        if Path(name).name != name: raise ValueError('invalid native artifact basename')
        artifact = directory / name
        if artifact.is_symlink() or not artifact.is_file() or sha(artifact) != description['sha256'] or artifact.stat().st_size != description['size']:
            raise ValueError('native artifact changed before OCI derivation: ' + name)
    return path, data


def build(directory, arch, base, host):
    native_arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if native_arch != arch: raise ValueError('OCI image must build on its native architecture')
    if not re.fullmatch(r'(?:docker.io/library/)?alpine@sha256:[0-9a-f]{64}', base):
        raise ValueError('OCI base must be an immutable official Alpine digest')
    provenance_path, provenance = verified_native(directory, arch)
    release_id = provenance['release_id']; descriptor = provenance['binaries'][arch]
    tar_description = provenance['artifacts'].get(descriptor['artifact'], {})
    if descriptor.get('libc') != 'musl' or tar_description.get('kind') != 'portable' \
        or tar_description.get('architecture') != arch or tar_description.get('libc') != 'musl':
        raise ValueError('OCI input is not the attested native portable payload')
    archive = directory / descriptor['artifact']; binary = payload.tar_binary(archive, release_id)
    if hashlib.sha256(binary).hexdigest() != descriptor['binary_sha256']:
        raise ValueError('OCI source binary differs from native attestation')
    probe = directory / f'io-uring-probe-{arch}'
    if probe.name not in provenance['artifacts'] or not probe.is_file():
        raise ValueError('OCI qualifier is missing from native attestation')
    probe_description = provenance['artifacts'][probe.name]
    if probe_description.get('kind') != 'qualifier' or probe_description.get('architecture') != arch \
        or probe_description.get('libc') != 'musl':
        raise ValueError('OCI qualifier descriptor mismatch')
    image_archive = directory / f'httpjet-{release_id}-linux-{arch}-oci.tar'
    native_record = directory / f'native-source-provenance-{arch}.json'
    if image_archive.exists() or native_record.exists(): raise ValueError('OCI output already exists')
    image_tag = f'httpjet-build:{release_id}-{arch}-{descriptor["binary_sha256"][:12]}'
    with tempfile.TemporaryDirectory(prefix='httpjet-oci-build-') as temporary:
        context = Path(temporary)
        write(context / 'root' / BINARY_PATH.lstrip('/'), binary, 0o755)
        write(context / 'root' / PROBE_PATH.lstrip('/'), probe.read_bytes(), 0o755)
        static.static_elf(context / 'root' / BINARY_PATH.lstrip('/'), arch)
        static.static_elf(context / 'root' / PROBE_PATH.lstrip('/'), arch)
        prefix = f'httpjet-{release_id}/share/httpjet/'
        with tarfile.open(archive, 'r:*') as source:
            for relative in ('conf/httpd_config.xml', 'conf/mime.properties', 'conf/vhosts/default.xml', 'welcome/index.html'):
                member = source.getmember(prefix + relative)
                if not member.isfile(): raise ValueError('OCI asset must be a regular file')
                target = 'etc/httpjet/' + relative if relative.startswith('conf/') else 'var/www/httpjet/index.html'
                write(context / 'root' / target, source.extractfile(member).read())
        args = ['--root', '/etc/httpjet', 'serve', '--http-addr', '0.0.0.0:8080', '--https-addr=',
                '--metrics-addr=', '--no-php', '--no-multishot-accept', '--ready-file', '/run/httpjet/ready']
        recipe = f'''FROM {base}
COPY root/ /
RUN addgroup -g 10001 httpjet && adduser -D -H -u 10001 -G httpjet -s /sbin/nologin httpjet \\
 && mkdir -p /run/httpjet /var/log/httpjet /var/lib/httpjet \\
 && chown 10001:10001 /run/httpjet /var/log/httpjet /var/lib/httpjet \\
 && chmod 0750 /run/httpjet /var/log/httpjet /var/lib/httpjet
USER 10001:10001
WORKDIR /var/lib/httpjet
ENV HTTPJET_LOG_DIR=/var/log/httpjet RUST_LOG=httpjet=info
EXPOSE 8080/tcp
VOLUME ["/run/httpjet", "/var/log/httpjet"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["{BINARY_PATH}"]
CMD {json.dumps(args)}
'''
        (context / 'Dockerfile').write_text(recipe)
        docker(host, 'pull', '--platform', f'linux/{arch}', base)
        base_inspect = json.loads(docker(host, 'image', 'inspect', base, capture=True))[0]
        if base_inspect['Architecture'] != arch: raise ValueError('OCI base architecture mismatch')
        docker(host, 'build', '--network', 'none', '--platform', f'linux/{arch}', '--tag', image_tag, context)
        inspect = json.loads(docker(host, 'image', 'inspect', image_tag, capture=True))[0]
        if inspect['Architecture'] != arch or inspect['Config']['User'] != '10001:10001':
            raise ValueError('OCI image architecture/user mismatch')
        container = docker(host, 'create', '--network', 'none', image_tag, capture=True)
        try:
            copied_binary = context / 'image-httpjet'; copied_probe = context / 'image-probe'
            docker(host, 'cp', container + ':' + BINARY_PATH, copied_binary)
            docker(host, 'cp', container + ':' + PROBE_PATH, copied_probe)
            if copied_binary.is_symlink() or sha(copied_binary) != descriptor['binary_sha256'] or copied_probe.is_symlink() or sha(copied_probe) != sha(probe):
                raise ValueError('OCI image changed a native executable')
        finally:
            docker(host, 'rm', '--volumes', container)
        optional = docker(host, 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                          '--security-opt', 'no-new-privileges', '--entrypoint', '/bin/sh', image_tag,
                          '-c', 'command -v python3 || command -v gpg || true', capture=True)
        if optional: raise ValueError('OCI runtime unexpectedly contains Python/GPG')
        docker(host, 'save', '--output', image_archive, image_tag)
    shutil.copyfile(provenance_path, native_record)
    image = {'artifact': image_archive.name, 'archive': image_archive.name, 'archive_sha256': sha(image_archive),
             'image_id': inspect['Id'], 'tag': image_tag, 'image_tag': image_tag, 'architecture': arch,
             'base_image': base, 'base': base, 'binary_path': BINARY_PATH, 'probe_path': PROBE_PATH,
             'base_image_id': base_inspect['Id'], 'base_architecture': base_inspect['Architecture'],
             'base_layer_diffids': base_inspect['RootFS']['Layers'],
             'binary_sha256': descriptor['binary_sha256'], 'probe_sha256': sha(probe),
             'uid': 10001, 'gid': 10001, 'http_port': 8080, 'readonly_friendly': True,
             'producer_sha256': sha(Path(__file__))}
    provenance['oci_images'] = {arch: image}
    provenance['artifacts'][native_record.name] = {'kind': 'provenance', 'architecture': arch, 'libc': 'musl',
        'sha256': sha(native_record), 'size': native_record.stat().st_size}
    provenance['artifacts'][image_archive.name] = {'kind': 'oci-image', 'architecture': arch, 'libc': 'musl',
        'sha256': sha(image_archive), 'size': image_archive.stat().st_size}
    temporary = provenance_path.with_suffix('.json.new')
    temporary.write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n'); temporary.replace(provenance_path)
    print(json.dumps(image, indent=2, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path); parser.add_argument('architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--base', default=BASE_IMAGE); parser.add_argument('--docker-host', default=os.getenv('DOCKER_HOST'))
    options = parser.parse_args(); build(options.directory.resolve(), options.architecture, options.base, options.docker_host)
