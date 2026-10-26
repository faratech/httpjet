#!/usr/bin/env python3
"""Qualify an attested rootful Podman service in a disposable CoreOS VM.

Python remains in the controller/tool container, never the OS or app image.
No OS rebase or package-layer operation is performed or claimed.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

import matrix_vm as matrix
import payload
import protocols
import release as release_api
import support
import universal
import vm

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REMOTE = '/var/lib/httpjet-qualification'
UNIT = 'httpjet-qualification.service'
TOOLS = 'rust:1.99.1-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8'


def tree_hash(directory):
    result = hashlib.sha256()
    for path in sorted(Path(directory).rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            result.update(path.relative_to(directory).as_posix().encode() + b'\0' + bytes.fromhex(release_api.sha(path)))
    return result.hexdigest()


def ignition(public_key, name):
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?', public_key):
        raise ValueError('CoreOS qualification needs one temporary Ed25519 public key')
    if not re.fullmatch(r'httpjet-coreos-[0-9a-f]{32}', name): raise ValueError('invalid allocated container name')
    definition = json.loads((HERE / 'images/coreos.bu').read_text())
    if (definition['variant'], definition['version']) != ('fcos', '1.6.0'):
        raise ValueError('unsupported CoreOS definition schema')
    # coreos.bu is JSON, which is a valid YAML subset. This intentionally small
    # renderer supports only the audited fields used by the locked definition.
    users = []
    for user in definition['passwd']['users']:
        users.append({'name': user['name'], 'groups': user['groups'], 'homeDir': user['home_dir'], 'shell': user['shell'],
                      'sshAuthorizedKeys': [public_key if key == '@SSH_PUBLIC_KEY@' else key for key in user['ssh_authorized_keys']]})
    files = []
    for file in definition['storage']['files']:
        text = file['contents']['inline']
        files.append({'path': file['path'], 'mode': file['mode'],
                      'contents': {'source': 'data:text/plain;base64,' + base64.b64encode(text.encode()).decode()}})
    units = []
    for unit in definition['systemd']['units']:
        rendered = dict(unit)
        if 'contents' in unit: rendered['contents'] = unit['contents'].replace('@CONTAINER_NAME@', name)
        units.append(rendered)
    return {'ignition': {'version': '3.5.0'}, 'passwd': {'users': users},
            'storage': {'directories': definition['storage']['directories'], 'files': files}, 'systemd': {'units': units}}


def qemu_args(arch, directory, ports):
    program = 'qemu-system-aarch64' if arch == 'arm64' else 'qemu-system-x86_64'
    forwards = (f"user,id=n,hostfwd=tcp:127.0.0.1:{ports['ssh']}-:22,"
                f"hostfwd=tcp:127.0.0.1:{ports['http']}-:18080,"
                f"hostfwd=tcp:127.0.0.1:{ports['tls']}-:18443,"
                f"hostfwd=udp:127.0.0.1:{ports['quic']}-:18443")
    args = [program, '-accel', 'tcg,thread=multi', '-cpu', 'max', '-smp', '2', '-m', '2048',
            '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
            '-drive', f'file={directory}/guest.qcow2,if=virtio,format=qcow2',
            '-fw_cfg', f'name=opt/com.coreos/config,file={directory}/ignition.json',
            '-netdev', forwards, '-device', 'virtio-net-pci,netdev=n']
    if arch == 'arm64': args += ['-machine', 'virt', '-bios', '/usr/share/qemu-efi-aarch64/QEMU_EFI.fd']
    return args


@contextmanager
def _machine(row, lock, directory, public_key, ports, name):
    if lock['definition']['recipe'] != 'packaging/release/images/coreos.bu' or lock['definition']['sha256'] != tree_hash(HERE / 'images'):
        raise ValueError('CoreOS definition differs from the authenticated lock')
    cloud = lock['cloud']
    if cloud.get('format') != 'qcow2.xz' or not re.fullmatch('[0-9a-f]{64}', cloud.get('uncompressed_sha256', '')):
        raise ValueError('CoreOS lock requires both compressed and decoded image hashes')
    compressed = directory / 'coreos.qcow2.xz'; release_api.download(cloud['url'], compressed)
    if release_api.sha(compressed) != cloud['sha256']: raise ValueError('official CoreOS compressed image mismatch')
    base = directory / 'base.qcow2'
    with lzma.open(compressed, 'rb') as source, base.open('wb') as destination: shutil.copyfileobj(source, destination, 1024*1024)
    if release_api.sha(base) != cloud['uncompressed_sha256']: raise ValueError('official CoreOS decoded image mismatch')
    base.chmod(0o444)
    (directory / 'ignition.json').write_text(json.dumps(ignition(public_key, name), indent=2) + '\n')
    args = qemu_args(row['architecture'], '/work', ports)
    script = ('#!/bin/bash\nset -euo pipefail\nexport DEBIAN_FRONTEND=noninteractive\n'
              'apt-get update\napt-get install -y --no-install-recommends qemu-utils qemu-system-x86 qemu-system-arm qemu-efi-aarch64\n'
              'qemu-img create -f qcow2 -F qcow2 -b /work/base.qcow2 /work/guest.qcow2\n'
              'qemu-img resize /work/guest.qcow2 +8G\nexec ' + shlex.join(args) + '\n')
    (directory / 'launch.sh').write_text(script)
    host = os.getenv('HTTPJET_QUALIFICATION_DOCKER_HOST', os.getenv('DOCKER_HOST'))
    prefix = ['docker'] + (['--host', host] if host else [])
    container = None; process = None
    with (directory / 'console.log').open('wb') as console:
        try:
            subprocess.run(prefix + ['pull', TOOLS], check=True, stdout=console, stderr=subprocess.STDOUT, timeout=180)
            container = subprocess.run(prefix + ['create', '--network', 'host', '--cpus', '2', '--memory', '3g',
                '--memory-swap', '3g', '--volume', str(directory) + ':/work', '--workdir', '/work',
                '--entrypoint', '/bin/bash', TOOLS, '/work/launch.sh'], check=True, capture_output=True, text=True).stdout.strip()
            if not re.fullmatch('[0-9a-f]{64}', container): raise ValueError('invalid allocated CoreOS tool container ID')
            process = subprocess.Popen(prefix + ['start', '--attach', container], stdin=subprocess.DEVNULL,
                                       stdout=console, stderr=subprocess.STDOUT, start_new_session=True)
            yield {'process': process, 'console': directory / 'console.log',
                   'image': {'kind': 'coreos-podman-qcow2', 'sha256': cloud['sha256'],
                             'uncompressed_sha256': cloud['uncompressed_sha256'], 'origin': cloud['url']}}
        finally:
            if container and re.fullmatch('[0-9a-f]{64}', container):
                subprocess.run(prefix + ['rm', '--force', '--volumes', container], capture_output=True, timeout=30)
            if process and process.poll() is None:
                process.terminate()
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)


class Guest:
    def __init__(self, key, port, known, transcript): self.key, self.port, self.known, self.transcript = key, port, known, transcript
    def call(self, *arguments, check=True, timeout=180):
        result = matrix.ssh(self.key, self.port, self.known, list(arguments), timeout=timeout, check=check)
        self.transcript.write(result.stdout or b''); self.transcript.flush()
        return result
    def root(self, *arguments, **options): return self.call('sudo', '-n', *arguments, **options)
    def script(self, text, **options): return self.root('sh', '-c', text, **options)
    def podman(self, *arguments, **options): return self.root('podman', *arguments, **options)
    def policy(self):
        result = self.call('cat', '/proc/sys/kernel/io_uring_disabled', check=False)
        return result.stdout.decode().strip() if result.returncode == 0 else None
    def inspect(self, name, image=False):
        value = json.loads(self.podman(*(['image', 'inspect'] if image else ['inspect']), name).stdout)[0]
        if image and not value['Id'].startswith('sha256:'): value['Id'] = 'sha256:' + value['Id']
        return value


def ready(guest, name, deadline, alive):
    while time.monotonic() < deadline:
        if not alive(): raise RuntimeError('CoreOS VM exited while waiting for app readiness')
        try: record = guest.inspect(name)
        except (RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError):
            time.sleep(.5); continue
        if not record['State']['Running']:
            if record['State'].get('Status') in ('created', 'configured', 'starting'):
                time.sleep(.5); continue
            raise RuntimeError('CoreOS Podman app exited before activation')
        result = guest.podman('exec', name, '/bin/busybox', 'cat', '/run/httpjet/ready', check=False)
        if result.returncode == 0 and result.stdout == b'1\n': return
        time.sleep(.5)
    raise TimeoutError('CoreOS app did not publish PID1 activation readiness')


def sandbox(guest, name, metadata):
    text = guest.podman('exec', name, '/bin/busybox', 'cat', '/proc/1/status').stdout.decode()
    fields = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    for key, expected in (('Uid', metadata['uid']), ('Gid', metadata['gid'])):
        if any(int(value) != expected for value in fields[key].split()): raise ValueError('CoreOS app identity mismatch')
    if int(fields['CapEff'].strip(), 16) or int(fields['CapBnd'].strip(), 16) or fields['NoNewPrivs'].strip() != '1':
        raise ValueError('CoreOS app must have zero capabilities and no-new-privileges')
    executable = guest.podman('exec', name, '/bin/busybox', 'readlink', '/proc/1/exe').stdout.decode().strip()
    if executable != metadata['binary_path']: raise ValueError('CoreOS PID1 is not the attested binary')
    hashed = guest.podman('exec', name, '/bin/busybox', 'sha256sum', executable).stdout.decode().split()[0]
    if hashed != metadata['binary_sha256']: raise ValueError('CoreOS running ELF changed')
    mounts = guest.podman('exec', name, '/bin/busybox', 'cat', '/proc/1/mountinfo').stdout.decode()
    if not any(line.split()[4] == '/' and 'ro' in line.split()[5].split(',') for line in mounts.splitlines()):
        raise ValueError('CoreOS container root mount is writable')
    arguments = guest.podman('exec', name, '/bin/busybox', 'cat', '/proc/1/cmdline').stdout.split(b'\0')
    if b'--no-multishot-accept' not in arguments: raise ValueError('CoreOS compatibility launch flag was omitted')
    record = guest.inspect(name)
    if record['HostConfig'].get('Privileged') or record['HostConfig'].get('NetworkMode') != 'host':
        raise ValueError('CoreOS Podman route differs from its explicit guest-host network scope')
    return {'uid': metadata['uid'], 'gid': metadata['gid'], 'binary_sha256': hashed, 'init': 'systemd',
            'no_multishot_accept': True, 'readonly_rootfs': True, 'effective_capabilities': 0,
            'bounding_capabilities': 0, 'no_new_privileges': True, 'container_id': record['Id'],
            'network_scope': 'host network of isolated disposable QEMU guest', 'executable': executable}


def fixtures(directory, image, artifacts):
    directory.mkdir(mode=0o700)
    for name in ('configuration/conf/vhosts', 'site', 'certs', 'negative-ready'):
        (directory / name).mkdir(parents=True, exist_ok=True)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=portable.test',
                    '-addext', 'subjectAltName=DNS:portable.test,IP:127.0.0.1', '-keyout', str(directory / 'certs/key.pem'),
                    '-out', str(directory / 'certs/cert.pem')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (directory / 'site/large.bin').write_bytes(protocols.BODY)
    (directory / 'site/compress.html').write_bytes(protocols.COMPRESSIBLE)
    (directory / 'site/operator-content.txt').write_text('operator-owned CoreOS volume\n')
    maps = '<vhostMapList><vhostMap><vhost>portable.test</vhost><domain>portable.test,www.portable.test,*</domain></vhostMap></vhostMapList>'
    (directory / 'configuration/conf/httpd_config.xml').write_text(
        '<httpServerConfig><serverName>portable.test</serverName><indexFiles>compress.html</indexFiles>'
        '<quic><quicEnable>1</quicEnable></quic><virtualHostList><virtualHost><name>portable.test</name>'
        '<vhRoot>/site</vhRoot><configFile>$SERVER_ROOT/conf/vhosts/default.xml</configFile>'
        '<allowSymbolLink>0</allowSymbolLink><enableScript>0</enableScript></virtualHost></virtualHostList>'
        f'<listenerList><listener><name>http</name><address>0.0.0.0:18080</address><secure>0</secure>{maps}</listener>'
        '<listener><name>https</name><address>0.0.0.0:18443</address><secure>1</secure>'
        f'<certFile>/certs/cert.pem</certFile><keyFile>/certs/key.pem</keyFile><clientVerify>0</clientVerify>{maps}'
        '</listener></listenerList></httpServerConfig>')
    (directory / 'configuration/conf/vhosts/default.xml').write_text(
        '<virtualHostConfig><docRoot>/site</docRoot><indexFiles>compress.html</indexFiles><allowSymbolLink>0</allowSymbolLink></virtualHostConfig>')
    (directory / 'configuration/conf/mime.properties').write_text('application/octet-stream=bin,txt\ntext/html=html\n')
    shutil.copyfile(ROOT / 'packaging/oci/seccomp-httpjet.json', directory / 'seccomp.json')
    args = ['--root', '/etc/httpjet', 'serve', '--http-addr', '0.0.0.0:18080', '--https-addr', '0.0.0.0:18443',
            '--metrics-addr=', '--no-php', '--no-multishot-accept', '--workers', '1', '--no-core-pinning',
            '--ready-file', '/run/httpjet/ready', '--mimalloc-trim-secs', '1', '--mimalloc-trim-threshold-mib', '0']
    (directory / 'profile.env').write_text('HTTPJET_IMAGE=' + image['image_id'] + '\nHTTPJET_ARGS=' + shlex.join(args) + '\n')
    shutil.copyfile(artifacts / image['artifact'], directory / 'candidate-image.tar')
    for path in directory.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (directory / 'certs/key.pem').chmod(0o600)
    return args


def operator_prepare(guest, lock, image, work):
    before = guest.policy()
    report = {'scope': 'disposable-qualification-image', 'before': before, 'after': before, 'changed': False}
    desired = lock.get('operator_configuration')
    if not desired: return report
    if desired != {'scope': 'disposable-qualification-image', 'io_uring_disabled': 0, 'record_stock_policy': True}:
        raise ValueError('CoreOS operator policy is outside the authenticated disposable scope')
    guest.root('test', '-f', '/etc/httpjet-disposable-qualification')
    if before in ('1', '2'):
        result = guest.podman('run', '--rm', '--network', 'host', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=' + REMOTE + '/seccomp.json',
            '--ulimit', 'memlock=8388608:8388608', '--entrypoint', image['probe_path'], image['image_id'], check=False)
        stock = json.loads(result.stdout); report['stock_probe'] = stock
        if stock.get('uid') != 10001 or before == '2' and stock.get('status') != 'failed':
            raise ValueError('CoreOS stock policy proof did not run/fail under the real app identity')
        guest.script("test \"$(stat -c '%u' /etc/httpjet-disposable-qualification)\" = 0 && "
                     "printf '0\\n' > /proc/sys/kernel/io_uring_disabled && "
                     "printf '# Disposable locked qualification choice only\\nkernel.io_uring_disabled=0\\n' > /etc/sysctl.d/99-httpjet-qualification-operator.conf")
        report.update(after=guest.policy(), changed=True)
        if report['after'] != '0': raise ValueError('CoreOS operator policy did not apply')
    return report


@contextmanager
def private_key_lifetime(path):
    try: yield
    finally: Path(path).unlink(missing_ok=True)


def negative_probe(guest, image, work):
    before = guest.policy()
    guest.script('mkdir -p ' + REMOTE + '/negative-ready && chown 10001:10001 ' + REMOTE + '/negative-ready && chmod 0750 ' + REMOTE + '/negative-ready')
    command = ['run', '--rm', '--network', 'host', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=' + REMOTE + '/seccomp.json',
        '--ulimit', 'memlock=8388608:8388608', '--mount', 'type=tmpfs,dst=/var/log/httpjet,tmpfs-size=16m,tmpfs-mode=0750,U,noexec,nosuid,nodev',
        '--volume', REMOTE + '/negative-ready:/run/httpjet:rw,z',
        '--volume', REMOTE + '/configuration:/etc/httpjet:ro,z', '--volume', REMOTE + '/site:/site:ro,z',
        '--volume', REMOTE + '/certs:/certs:ro,z', '--entrypoint', image['probe_path'], image['image_id'],
        '--deny-exec', image['binary_path'], '--root', '/etc/httpjet', 'serve', '--http-addr', '127.0.0.1:18081',
        '--https-addr=', '--metrics-addr=', '--no-php', '--workers', '1', '--no-multishot-accept', '--ready-file', '/run/httpjet/denied-ready']
    result = guest.podman(*command, check=False, timeout=45)
    text = result.stdout.decode(errors='replace'); (work / 'negative.log').write_text(text[-65536:])
    records = []
    for line in text.splitlines():
        try: value = json.loads(line)
        except json.JSONDecodeError: continue
        if value.get('mode') == 'deny-exec': records.append(value)
    missing = guest.script('test ! -e ' + REMOTE + '/negative-ready/denied-ready && test ! -L ' + REMOTE + '/negative-ready/denied-ready', check=False).returncode == 0
    unchanged = before == guest.policy()
    if result.returncode == 0 or len(records) != 1 or records[0].get('uid') != 10001 \
        or records[0].get('global_policy_changed') is not False or not unchanged or not missing \
        or 'build monoio runtime' not in text or 'os error 1)' not in text:
        raise ValueError('CoreOS process-local denial did not genuinely block the real server')
    return {'status': 'expected_failure', 'uid': 10001, 'exit_code': result.returncode, 'errno': 1,
            'global_policy_changed': False, 'ready_file_created': False, 'scope': 'CoreOS app process-local seccomp', 'log': 'negative.log'}


def qualify(row, lock, manifest, artifacts, new_dir, timeout=7200):
    if row['executor'] != 'coreos' or row['route'] != 'immutable': raise ValueError('not a CoreOS container-route row')
    if {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(os.uname().machine) != row['architecture']:
        raise ValueError('CoreOS qualification must use native architecture')
    if not 60 <= timeout <= 14400: raise ValueError('CoreOS qualification timeout out of bounds')
    work = Path(new_dir).resolve(); work.mkdir(mode=0o700, parents=True)
    artifacts = Path(artifacts).resolve(); image = manifest['oci_images'][row['architecture']]
    descriptor = manifest['artifacts'][image['artifact']]
    if release_api.sha(artifacts / image['artifact']) != descriptor['sha256']: raise ValueError('CoreOS candidate archive changed')
    decoded = payload.oci_binary(artifacts / image['artifact'], row['architecture'])
    if decoded['image_id'] != image['image_id'] or hashlib.sha256(decoded['binary']).hexdigest() != image['binary_sha256']:
        raise ValueError('CoreOS candidate image/ELF differs from attestation')
    executable = work / 'inspected-httpjet'; executable.write_bytes(decoded['binary'])
    release_api.validate_elf(executable, row['architecture'], 'musl')
    key = work / 'ssh'; subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    ports = {'ssh': matrix.port(), 'http': matrix.port(), 'tls': matrix.port(True)}; ports['quic'] = ports['tls']
    name = 'httpjet-coreos-' + uuid.uuid4().hex
    fixture_dir = work / 'payload'; fixtures(fixture_dir, image, artifacts)
    known = work / 'known_hosts'; log = work / 'coreos.log'; checks = {'static-elf': 'passed'}
    files = {}; deadline = time.monotonic() + timeout
    with private_key_lifetime(fixture_dir/'certs/key.pem'), log.open('wb') as transcript, _machine(row, lock, work, key.with_suffix('.pub').read_text().strip(), ports, name) as machine:
        guest = Guest(key, ports['ssh'], known, transcript)
        alive = lambda: machine['process'].poll() is None
        vm.wait_probe([*vm.ssh_args(key, ports['ssh'], known), 'true'], deadline=deadline, alive=alive, label='CoreOS Ignition SSH')
        guest.script('command -v podman >/dev/null && command -v tar >/dev/null && ! command -v python3 >/dev/null')
        upload = '/var/tmp/httpjet-coreos-input-' + uuid.uuid4().hex
        matrix.send_tree(key, ports['ssh'], known, fixture_dir, upload)
        guest.script('cp -a ' + shlex.quote(upload) + '/. ' + REMOTE + '/ && chown -R 0:0 ' + REMOTE + ' && chmod 0700 ' + REMOTE + ' && chown 10001:10001 ' + REMOTE + '/certs/key.pem && chmod 0400 ' + REMOTE + '/certs/key.pem')
        copied = guest.root('sha256sum', REMOTE + '/candidate-image.tar').stdout.decode().split()[0]
        if copied != descriptor['sha256']: raise ValueError('CoreOS uploaded archive bytes changed')
        guest.podman('load', '--input', REMOTE + '/candidate-image.tar', timeout=300)
        if guest.inspect(image['image_id'], True)['Id'] != image['image_id']: raise ValueError('CoreOS loaded a different image')
        operator = operator_prepare(guest, lock, image, work)
        guest.root('touch', REMOTE + '/image-ready')
        guest.root('systemctl', 'start', UNIT)
        ready(guest, name, min(deadline, time.monotonic()+45), alive)
        service = sandbox(guest, name, image)
        guest.root('systemctl', 'is-enabled', '--quiet', UNIT)
        checks.update({'container-route': 'passed', 'nonroot-readonly': 'passed', 'unprivileged': 'passed'})
        before = guest.policy(); positive = json.loads(guest.podman('exec', name, image['probe_path']).stdout)
        if positive.get('status') != 'passed' or positive.get('uid') != 10001 or not all(positive.get('operations', {}).get(k) is True for k in ('setup','register_probe','enter_nop')) or before != guest.policy():
            raise ValueError('CoreOS io_uring operation probe failed under the actual app identity')
        positive.update(global_policy_changed=False, scope='CoreOS app container', kernel=guest.call('uname','-r').stdout.decode().strip())
        checks['io-uring-positive'] = 'passed'
        server = {'uid': 10001, 'binary_sha256': image['binary_sha256'], 'body_size': len(protocols.BODY),
                  'body_sha256': hashlib.sha256(protocols.BODY).hexdigest(), 'no_multishot_accept': True}
        runtime = protocols.check(server, '127.0.0.1', ports['http'], ports['tls'], fixture_dir / 'certs/cert.pem')
        runtime.update(scope='CoreOS-container-sandbox', network_scope=service['network_scope'])
        for key_name in ('http', 'tls', 'h2', 'h3'):
            if runtime['protocols'].get(key_name) is not True: raise ValueError('CoreOS protocol was not observed: '+key_name)
            checks[key_name] = 'passed'
        checks['large-transfer'] = 'passed'
        negative = negative_probe(guest, image, work); checks['io-uring-negative'] = 'passed'
        guest.root('systemctl', 'restart', UNIT); ready(guest, name, min(deadline,time.monotonic()+45), alive)
        sandbox(guest, name, image)
        operator_hash = hashlib.sha256((fixture_dir / 'site/operator-content.txt').read_bytes()).hexdigest()
        if hashlib.sha256(protocols.http_body('127.0.0.1',ports['http'],'/operator-content.txt')[0]).hexdigest() != operator_hash:
            raise ValueError('CoreOS volume content changed after restart')
        checks.update(restart='passed', **{'volume-preserved':'passed','content-preserved':'passed'})
        old_boot = guest.call('cat','/proc/sys/kernel/random/boot_id').stdout.decode().strip()
        try: guest.root('systemctl','reboot',check=False,timeout=15)
        except subprocess.TimeoutExpired: pass
        vm.wait_probe([*vm.ssh_args(key,ports['ssh'],known),'cat /proc/sys/kernel/random/boot_id'],
            deadline=min(deadline,time.monotonic()+300),alive=alive,
            success=lambda result: result.returncode==0 and result.stdout.strip()!=old_boot and re.fullmatch(r'[0-9a-f-]{36}',result.stdout.strip()) is not None,
            label='CoreOS real reboot')
        new_boot = guest.call('cat','/proc/sys/kernel/random/boot_id').stdout.decode().strip()
        ready(guest,name,min(deadline,time.monotonic()+45),alive)
        guest.root('systemctl','is-active','--quiet',UNIT)
        sandbox(guest,name,image)
        if hashlib.sha256(protocols.http_body('127.0.0.1',ports['http'],'/operator-content.txt')[0]).hexdigest()!=operator_hash:
            raise ValueError('CoreOS persistent /var volume failed after real reboot')
        checks['reboot']='passed'
        guest.root('systemctl','disable','--now',UNIT)
        guest.podman('rm','--ignore','--force',name)
        guest.root('mv','/etc/systemd/system/'+UNIT,REMOTE+'/uninstalled.service')
        guest.root('systemctl','daemon-reload')
        if guest.podman('container','exists',name,check=False).returncode==0:raise ValueError('CoreOS container uninstall left the app present')
        if guest.root('cat',REMOTE+'/site/operator-content.txt').stdout!=b'operator-owned CoreOS volume\n':raise ValueError('CoreOS uninstall removed operator data')
        checks['container-uninstall']='passed'
        boot={'before':old_boot,'after':new_boot,'changed':old_boot!=new_boot,'persistent_unit':UNIT,'persistent_volume':REMOTE+'/site'}
        for filename,value,role in [('service.json',service,'service'),('positive.json',positive,'uring-positive'),
             ('negative.json',negative,'uring-negative'),('runtime.json',runtime,'runtime'),('operator.json',operator,'operator'),('boot.json',boot,'reboot')]:
            path=work/filename;path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');files[role]=path
        files['uring-denial-log']=work/'negative.log';files['console']=work/'console.log'
        result={'image':{**machine['image'],'operator_configuration':operator},'service':service,'runtime':runtime,
                'positive':positive,'negative':negative,'checks':checks,'files':files,'log':log}
    (fixture_dir/'certs/key.pem').unlink(missing_ok=True)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('artifacts','snapshot','public-key','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--row',required=True);parser.add_argument('--fingerprint',required=True)
    parser.add_argument('--timeout',type=int,default=7200);args=parser.parse_args()
    manifest=release_api.load(args.artifacts/'manifest.json');support.identity_from_manifest(manifest)
    release_api.validate_key(args.public_key,args.fingerprint)
    universal.verify_signed(args.artifacts/'manifest.json',args.snapshot/'releases'/manifest['release_id']/'manifest.json.asc',args.public_key)
    universal.verify_artifacts(args.artifacts,manifest)
    row=next(value for value in support.bound_policy(args.artifacts,manifest)['rows'] if value['id']==args.row)
    lock=release_api.load(args.artifacts/'qualification-images.json')['rows'][row['id']]
    args.output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='httpjet-coreos-') as temporary:
        result=qualify(row,lock,manifest,args.artifacts,Path(temporary)/'machine',args.timeout)
        checks={**result['checks'],'artifact-signature':'passed'}
        evidence={}
        for role,path in result['files'].items():
            filename,item=matrix.append_evidence(args.output,row['id'],path.name,path,role);evidence[filename]=item
        log=args.output/(row['id']+'.log');shutil.copyfile(result['log'],log)
        destination=args.output/(row['id']+'.json')
        receipt=matrix.receipt(row,manifest,lock,result['image'],result['service']['uid'],checks,
            result['positive'],result['negative'],result['runtime'],{'kind':'container-route-no-os-rebase'},log,evidence,destination,
            manifest['oci_images'][row['architecture']])
        receipt['manifest_sha256']=release_api.sha(args.artifacts/'manifest.json')
        support.verify_row(row,receipt,manifest,receipt['manifest_sha256'],lock)
        release_api.write_json(destination,receipt)
        print('qualified CoreOS Podman route '+row['id'])


if __name__=='__main__':main()
