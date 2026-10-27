#!/usr/bin/env python3
"""Scoped container builders and TCG launchers for declarative qualification."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import time
import urllib.parse
import uuid
import guix_bootstrap

ROOT = Path(__file__).resolve().parents[2]
DEBIAN_BUILDER = 'rust:1.99.1-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8'
SYSTEMS = {'amd64': 'x86_64-linux', 'arm64': 'aarch64-linux'}


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def tree_hash(directory):
    value = hashlib.sha256()
    for path in sorted(Path(directory).rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            value.update(path.relative_to(directory).as_posix().encode() + b'\0' + bytes.fromhex(digest(path)))
    return value.hexdigest()


def engine(*arguments, capture=False):
    host = os.getenv('HTTPJET_QUALIFICATION_DOCKER_HOST', os.getenv('DOCKER_HOST'))
    command = ['docker'] + (['--host', host] if host else []) + list(map(str, arguments))
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE if capture else None,
                            text=True, timeout=120)
    return result.stdout.strip() if capture else None


def validate(row, lock, release_base, ports):
    if row['executor'] not in ('nix-image', 'guix-image'): raise ValueError('not a declarative support row')
    native = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if row['architecture'] != native: raise ValueError('declarative qualification must use native architecture')
    definition = lock['definition']
    if definition['system'] != SYSTEMS[native]: raise ValueError('declarative system/architecture mismatch')
    relative = 'packaging/nix' if row['executor'] == 'nix-image' else 'packaging/guix'
    expected_recipe = relative + ('/qualification.nix' if row['executor'] == 'nix-image' else '/qualification.scm')
    if definition.get('recipe') != expected_recipe: raise ValueError('unexpected declarative image recipe')
    directory = ROOT / relative
    if tree_hash(directory) != definition['sha256']: raise ValueError('declarative definition differs from signed image lock')
    if row['executor'] == 'guix-image' and lock.get('bootstrap') != guix_bootstrap.descriptor(native):
        raise ValueError('Guix bootstrap differs from authenticated image inputs')
    uri = urllib.parse.urlsplit(release_base)
    if uri.scheme != 'https' or not uri.hostname or uri.username or uri.password or uri.query or uri.fragment:
        raise ValueError('declarative release base must be authenticated HTTPS')
    for name in ('ssh', 'http', 'tls', 'quic'):
        if type(ports[name]) is not int or not 1024 <= ports[name] <= 65535:
            raise ValueError('qualification forwards must use explicit unprivileged ports')
    if len({ports[name] for name in ('ssh', 'http', 'tls')}) != 3:
        raise ValueError('qualification TCP forwards must be distinct')
    return directory


def guix_lock(manifest, arch, release_base):
    binary = manifest['binaries'][arch]; artifact = manifest['artifacts'][binary['artifact']]
    values = {'release-id': manifest['release_id'], 'uri': release_base + '/' + manifest['release_id'] + '/' + binary['artifact'],
              'sha256': artifact['sha256'], 'binary-sha256': binary['binary_sha256'], 'system': SYSTEMS[arch]}
    return '(use-modules (httpjet packages))\n(httpjet-binary-package\n' + ''.join(
        '  #:' + key + ' ' + json.dumps(value) + '\n' for key, value in values.items()) + ')\n'


def guix_builder_profile():
    profile = json.loads((ROOT / 'packaging/oci/seccomp-httpjet.json').read_text())
    profile['syscalls'].append({'names': ['unshare'], 'action': 'SCMP_ACT_ALLOW',
        'args': [{'index': 0, 'value': 0x10000000, 'op': 'SCMP_CMP_EQ'}]})
    # Guix 1.5 build.cc applies PER_LINUX | ADDR_NO_RANDOMIZE to native build
    # children for reproducibility. Keep this exact exception in the builder
    # copy; the web container profile and the host ASLR policy stay unchanged.
    profile['syscalls'].append({'names': ['personality'], 'action': 'SCMP_ACT_ALLOW',
        'args': [{'index': 0, 'value': 0x40000, 'op': 'SCMP_CMP_EQ'}]})
    return profile


def nix_script(system, release_base, ports, previous, certificate):
    arguments = ['--no-out-link', '--option', 'sandbox', 'false', '--option', 'build-users-group', '',
                 '--option', 'max-jobs', '2', '--option', 'cores', '2', '/inputs/definitions/qualification.nix',
                 '--arg', 'releaseManifest', '/inputs/manifest.json', '--arg', 'sshPublicKey', '/inputs/ssh-public.key',
                 '--argstr', 'releaseBase', release_base, '--argstr', 'system', system]
    for name, argument in (('ssh', 'sshPort'), ('http', 'httpPort'), ('tls', 'tlsPort'), ('quic', 'quicPort')):
        arguments += ['--arg', argument, str(ports[name])]
    if previous: arguments += ['--arg', 'previousManifest', '/inputs/previous-manifest.json']
    if certificate: arguments += ['--arg', 'certificate', '/inputs/httpjet-qualification-ca.crt']
    command = 'nix-build ' + shlex.join(arguments)
    return '''#!/bin/bash
set -euo pipefail
if test -e /dev/kvm; then
  echo 'httpjet: Nix qualification builder must not expose /dev/kvm; TCG is required' >&2
  exit 1
fi
export NIX_REMOTE=local
if [ -f /inputs/httpjet-qualification-ca.crt ]; then
  bundle=''
  for candidate in "${NIX_SSL_CERT_FILE:-}" /etc/ssl/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem; do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then bundle=$candidate; break; fi
  done
  test -n "$bundle" || { echo 'Nix builder public CA bundle is unavailable' >&2; exit 1; }
  cat "$bundle" /inputs/httpjet-qualification-ca.crt > /tmp/httpjet-builder-ca.pem
  export NIX_SSL_CERT_FILE=/tmp/httpjet-builder-ca.pem SSL_CERT_FILE=/tmp/httpjet-builder-ca.pem GIT_SSL_CAINFO=/tmp/httpjet-builder-ca.pem
fi
''' + f'''vm=$({command} -A vm)
closure=$({command} -A systemClosure)
hash=$(nix --extra-experimental-features nix-command hash path --type sha256 --base16 "$closure")
printf '%s\\n%s\\n%s\\n' "$hash" "$closure" "$vm" > /work/build.ready.tmp
mv /work/build.ready.tmp /work/build.ready
export NIX_DISK_IMAGE=/work/nixos-guest.qcow2
exec "$vm/bin/run-httpjet-qualification-vm"
'''


def guix_script(arch, ports, certificate):
    image_type = 'qcow2-gpt' if arch == 'arm64' else 'qcow2'
    net = 'user,id=net0,' + ','.join([
        f'hostfwd=tcp:127.0.0.1:{ports["ssh"]}-:22', f'hostfwd=tcp:127.0.0.1:{ports["http"]}-:18080',
        f'hostfwd=tcp:127.0.0.1:{ports["tls"]}-:18443', f'hostfwd=udp:127.0.0.1:{ports["quic"]}-:18443'])
    if arch == 'arm64':
        qemu = ['qemu-system-aarch64', '-machine', 'virt,gic-version=3', '-cpu', 'cortex-a72',
                '-bios', '/usr/share/qemu-efi-aarch64/QEMU_EFI.fd', '-device', 'virtio-net-device,netdev=net0']
    else:
        qemu = ['qemu-system-x86_64', '-cpu', 'max', '-device', 'virtio-net-pci,netdev=net0']
    qemu += ['-accel', 'tcg,thread=multi', '-smp', '2', '-m', '2048', '-display', 'none', '-monitor', 'none',
             '-serial', 'stdio', '-netdev', net, '-drive', 'file=/work/guest-overlay.qcow2,if=virtio,format=qcow2']
    return '''#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
printf '#!/bin/sh\\nexit 101\\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
apt-get update
apt-get install -y --no-install-recommends python3 gnupg xz-utils tar git ca-certificates curl openssh-client qemu-utils qemu-system-x86 qemu-system-arm qemu-efi-aarch64
if [ -f /inputs/httpjet-qualification-ca.crt ]; then
  cp /inputs/httpjet-qualification-ca.crt /usr/local/share/ca-certificates/httpjet-qualification.crt
  update-ca-certificates
  export HTTPJET_GUIX_TEST_CA=/inputs/httpjet-qualification-ca.crt
else
  unset HTTPJET_GUIX_TEST_CA
fi
export GUIX_TLS_CERTIFICATE_DIRECTORY=/etc/ssl/certs
export SSL_CERT_DIR=/etc/ssl/certs
export HTTPJET_GUIX_RELEASE_LOCK=/inputs/release-lock.scm
export HTTPJET_QUALIFICATION_SSH_KEY=/inputs/ssh-public.key
''' + f'''export HTTPJET_GUIX_SYSTEM={shlex.quote(SYSTEMS[arch])}
python3 -B /inputs/guix_bootstrap.py --inside-builder --architecture {shlex.quote(arch)} --receipt /work/guix-bootstrap.json
export GUIX_PROFILE=/var/guix/profiles/per-user/root/current-guix
source "$GUIX_PROFILE/etc/profile"
export GUIX_TLS_CERTIFICATE_DIRECTORY=/etc/ssl/certs SSL_CERT_DIR=/etc/ssl/certs
guix-daemon --disable-chroot --build-users-group= > /work/guix-daemon.log 2>&1 &
daemon_pid=$!
trap 'kill "$daemon_pid" 2>/dev/null || true' EXIT
for attempt in $(seq 1 30); do test -S /var/guix/daemon-socket/socket && break; sleep 1; done
for httpjet_cache in ci.guix.gnu.org bordeaux.guix.gnu.org; do
  guix archive --authorize < "$GUIX_PROFILE/share/guix/$httpjet_cache.pub"
done
image=$(guix time-machine -C /inputs/definitions/channels.scm -- -L /inputs/definitions system image --system={SYSTEMS[arch]} --image-type={image_type} --image-size=8G --max-jobs=2 --cores=2 /inputs/definitions/qualification.scm)
cp "$image" /work/system.qcow2
hash=$(sha256sum /work/system.qcow2 | cut -d' ' -f1)
printf '%s\\n%s\\n' "$hash" "$image" > /work/build.ready.tmp
mv /work/build.ready.tmp /work/build.ready
qemu-img create -f qcow2 -F qcow2 -b /work/system.qcow2 /work/guest-overlay.qcow2
''' + 'exec ' + shlex.join(qemu) + '\n'


@contextmanager
def run(row, lock, manifest_path, release_base, ssh_public_key, new_dir, ports,
        previous_manifest=None, test_ca=None):
    """Build then launch one isolated VM; the caller owns SSH/lifecycle checks."""
    definition = validate(row, lock, release_base, ports)
    manifest = json.loads(Path(manifest_path).read_text())
    arch = row['architecture']; directory = Path(new_dir).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    inputs = directory / 'inputs'; inputs.mkdir(mode=0o755)
    output = directory / 'output'; output.mkdir(mode=0o755)
    shutil.copytree(definition, inputs / 'definitions', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    if tree_hash(inputs / 'definitions') != lock['definition']['sha256']:
        raise ValueError('declarative source changed while creating its private snapshot')
    shutil.copyfile(manifest_path, inputs / 'manifest.json')
    shutil.copyfile(ssh_public_key, inputs / 'ssh-public.key')
    if previous_manifest: shutil.copyfile(previous_manifest, inputs / 'previous-manifest.json')
    if test_ca: shutil.copyfile(test_ca, inputs / 'httpjet-qualification-ca.crt')
    if row['executor'] == 'nix-image':
        builder = lock['builder']['image']
        script = nix_script(lock['definition']['system'], release_base, ports, bool(previous_manifest), bool(test_ca))
    else:
        if digest(inputs / 'definitions/channels.scm') != lock['channels_sha256']:
            raise ValueError('Guix authenticated channel pin changed')
        guix_bootstrap.stage(inputs)
        builder = lock.get('builder', {}).get('image', DEBIAN_BUILDER)
        (inputs / 'release-lock.scm').write_text(guix_lock(manifest, arch, release_base))
        if previous_manifest:
            (inputs / 'previous-release-lock.scm').write_text(guix_lock(json.loads(Path(previous_manifest).read_text()), arch, release_base))
        script = guix_script(arch, ports, bool(test_ca))
    if not re.fullmatch(r'[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}', builder):
        raise ValueError('declarative builder image must be digest-pinned')
    (inputs / 'run.sh').write_text(script)
    name = 'httpjet-declarative-' + uuid.uuid4().hex
    arguments = ['create', '--name', name, '--platform', 'linux/' + arch, '--network', 'host', '--cpus', '2', '--memory', '6g',
                 '--memory-swap', '6g', '--pids-limit', '2048', '--ulimit', 'memlock=8388608:8388608',
                 '--add-host', 'httpjet-qualification.local:127.0.0.1',
                 '--volume', str(inputs) + ':/inputs:ro', '--volume', str(output) + ':/work',
                 '--workdir', '/work', '--entrypoint',
                 '/nix/var/nix/profiles/default/bin/bash' if row['executor'] == 'nix-image' else '/bin/bash']
    if row['executor'] == 'guix-image':
        # Image construction uses a user namespace for mkfs; no host policy,
        # privileged mode, mount namespace, devices or host store are granted.
        profile = guix_builder_profile()
        profile_path = directory / 'builder-seccomp.json'
        profile_path.write_text(json.dumps(profile))
        arguments += ['--security-opt', 'seccomp=' + str(profile_path)]
    arguments += [builder, '/inputs/run.sh']
    container = None; process = None; log = None
    try:
        engine('pull', '--platform', 'linux/' + arch, builder)
        container = engine(*arguments, capture=True)
        if not re.fullmatch('[0-9a-f]{64}', container): raise ValueError('Docker did not return one allocated container ID')
        host = os.getenv('HTTPJET_QUALIFICATION_DOCKER_HOST', os.getenv('DOCKER_HOST'))
        command = ['docker'] + (['--host', host] if host else []) + ['start', '--attach', container]
        log = (directory / 'builder-console.log').open('wb')
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        timeout = int(os.getenv('HTTPJET_DECLARATIVE_BUILD_TIMEOUT_SECS', '7200'))
        if not 30 <= timeout <= 14400: raise ValueError('declarative build timeout out of bounds')
        deadline = time.monotonic() + timeout
        ready = output / 'build.ready'
        while not ready.exists():
            if process.poll() is not None:
                tail = (directory / 'builder-console.log').read_text(errors='replace')[-6000:]
                raise RuntimeError('declarative builder/VM exited before image readiness:\n' + tail)
            if time.monotonic() >= deadline: raise TimeoutError('declarative image build timed out')
            time.sleep(1)
        values = ready.read_text().splitlines()
        if len(values) < 2 or not re.fullmatch('[0-9a-f]{64}', values[0]):
            raise ValueError('declarative image builder did not report a content identity')
        image = {'sha256': values[0], 'origin': lock['definition']['origin'],
                 'kind': 'nixos-closure' if row['executor'] == 'nix-image' else 'guix-qcow2',
                 'store_path': values[1], 'builder_image': builder}
        if row['executor'] == 'guix-image':
            if digest(output / 'system.qcow2') != image['sha256']:
                raise ValueError('Guix image changed before starting the overlay')
        baseline = json.loads(Path(previous_manifest).read_text())['release_id'] if previous_manifest else manifest['release_id'] + '-fixture'
        yield {'process': process, 'image': image, 'container_id': container,
               'baseline_kind': 'previous-stable' if previous_manifest else 'first-release-fixture',
               'baseline_version': baseline, 'inputs': str(inputs), 'output': str(output),
               'log': str(directory / 'builder-console.log')}
    finally:
        if container and re.fullmatch('[0-9a-f]{64}', container):
            try: engine('stop', '--time', '10', container)
            except (subprocess.SubprocessError, OSError): pass
            try: engine('rm', '--force', '--volumes', container)
            except (subprocess.SubprocessError, OSError): pass
        if process and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=10)
        if log: log.close()
