#!/usr/bin/env python3
"""Qualify an attested OCI image with a separate client container and private netns."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
from xml.sax.saxutils import escape

import protocols
import probe

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CLIENT_BASE = 'rust:1.99.1-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8'


def command(engine, *arguments, check=True, timeout=180):
    result = subprocess.run([engine, *map(str, arguments)], timeout=timeout,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(f'{engine} {arguments[0]} failed ({result.returncode}):\n' +
                           (result.stdout + result.stderr)[-12000:])
    return result


def inspect(engine, target, image=False):
    record = json.loads(command(engine, *(['image', 'inspect'] if image else ['inspect']), target).stdout)[0]
    if image and len(record.get('Id', '')) == 64 and not record['Id'].startswith('sha256:'):
        record['Id'] = 'sha256:' + record['Id']
    return record


def client_image(engine, supplied=None):
    if supplied:
        return inspect(engine, supplied, True)['Id']
    with tempfile.TemporaryDirectory(prefix='httpjet-oci-client-') as temporary:
        directory = Path(temporary)
        (directory / 'Dockerfile').write_text(
            f'FROM {CLIENT_BASE}\nRUN apt-get update && apt-get install -y --no-install-recommends '
            'python3 python3-venv ca-certificates && python3 -m venv /opt/client '
            '&& /opt/client/bin/pip install --no-cache-dir aioquic==1.7.0 h2==4.4.1 '
            'cryptography==50.0.2 pylsqpack==1.0.0 && rm -rf /var/lib/apt/lists/*\n'
            'ENV PATH=/opt/client/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n')
        tag = 'httpjet-qualification-client:1'
        command(engine, 'build', '--network', 'host', '--tag', tag, directory, timeout=900)
    return inspect(engine, tag, True)['Id']


def make_fixture(work, uid, gid, certificate=None, key=None):
    for name in ('configuration/conf/vhosts', 'site', 'certs', 'code/packaging/release', 'code/scripts', 'output'):
        path = work / name
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755)
    if certificate and key:
        shutil.copyfile(certificate, work / 'certs/cert.pem')
        shutil.copyfile(key, work / 'certs/key.pem')
    else:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=portable.test', '-addext', 'subjectAltName=DNS:portable.test',
                        '-keyout', str(work / 'certs/key.pem'), '-out', str(work / 'certs/cert.pem')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (work / 'certs/cert.pem').chmod(0o644)
    (work / 'certs/key.pem').chmod(0o400)
    os.chown(work / 'certs/key.pem', uid, gid)
    (work / 'site/large.bin').write_bytes(protocols.BODY)
    (work / 'site/compress.html').write_bytes(protocols.COMPRESSIBLE)
    (work / 'site/operator-content.txt').write_text('operator-owned OCI content\n')
    maps = '<vhostMapList><vhostMap><vhost>portable.test</vhost><domain>portable.test,www.portable.test,*</domain></vhostMap></vhostMapList>'
    (work / 'configuration/conf/httpd_config.xml').write_text(
        '<httpServerConfig><serverName>portable.test</serverName><indexFiles>compress.html</indexFiles>'
        '<quic><quicEnable>1</quicEnable></quic><virtualHostList><virtualHost><name>portable.test</name>'
        '<vhRoot>/site</vhRoot><configFile>$SERVER_ROOT/conf/vhosts/default.xml</configFile>'
        '<allowSymbolLink>0</allowSymbolLink><enableScript>0</enableScript></virtualHost></virtualHostList>'
        f'<listenerList><listener><name>http</name><address>0.0.0.0:8080</address><secure>0</secure>{maps}</listener>'
        '<listener><name>https</name><address>0.0.0.0:8443</address><secure>1</secure>'
        f'<certFile>/certs/cert.pem</certFile><keyFile>/certs/key.pem</keyFile><clientVerify>0</clientVerify>{maps}'
        '</listener></listenerList></httpServerConfig>')
    (work / 'configuration/conf/vhosts/default.xml').write_text(
        '<virtualHostConfig><docRoot>/site</docRoot><indexFiles>compress.html</indexFiles>'
        '<allowSymbolLink>0</allowSymbolLink></virtualHostConfig>')
    (work / 'configuration/conf/mime.properties').write_text('text/html=html\napplication/octet-stream=bin,txt\n')
    shutil.copyfile(HERE / 'protocols.py', work / 'code/packaging/release/protocols.py')
    shutil.copyfile(ROOT / 'scripts/h3get.py', work / 'code/scripts/h3get.py')
    for branch in ('configuration', 'site', 'code'):
        root = work / branch
        root.chmod(0o755)
        for path in root.rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
    os.chown(work / 'output', uid, gid)
    (work / 'output').chmod(0o750)


def owned_tmpfs(engine, destination, uid, gid):
    if engine == 'podman':
        # Podman rejects uid/gid in --tmpfs. U assigns the mount to the
        # already verified image user, including when the probe is PID1.
        return ['--mount', f'type=tmpfs,dst={destination},tmpfs-size=16m,tmpfs-mode=0750,U,noexec,nosuid,nodev']
    return ['--tmpfs', f'{destination}:rw,noexec,nosuid,nodev,size=16m,mode=0750,uid={uid},gid={gid}']


def runtime_options(work, uid, gid, security_profile, engine='docker', readiness_directory=None):
    options = ['--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--security-opt', 'seccomp=' + str(security_profile), '--ulimit', 'memlock=8388608:8388608',
               '--cpus', '2', '--memory', '2g']
    if readiness_directory is None:
        options += owned_tmpfs(engine, '/run/httpjet', uid, gid)
    options += owned_tmpfs(engine, '/var/log/httpjet', uid, gid)
    options += ['--env', 'RUST_LOG=warn']
    if readiness_directory is not None:
        options += ['--volume', str(readiness_directory) + ':/run/httpjet:rw,z']
    return options


def verify_process(engine, container, metadata):
    status = command(engine, 'exec', container, '/bin/busybox', 'cat', '/proc/1/status').stdout
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    if any(int(value) != metadata['uid'] for value in fields['Uid'].split()):
        raise ValueError('OCI daemon is not the attested unprivileged UID')
    if any(int(value) != metadata['gid'] for value in fields['Gid'].split()):
        raise ValueError('OCI daemon is not the attested unprivileged GID')
    if int(fields['CapEff'].strip(), 16) != 0 or int(fields['CapBnd'].strip(), 16) != 0 or fields['NoNewPrivs'].strip() != '1':
        raise ValueError('OCI daemon capabilities/no-new-privileges differ from policy')
    executable = command(engine, 'exec', container, '/bin/busybox', 'readlink', '/proc/1/exe').stdout.strip()
    if executable != metadata['binary_path']:
        raise ValueError('OCI PID1 is not the attested server')
    hashed = command(engine, 'exec', container, '/bin/busybox', 'sha256sum', executable).stdout.split()[0]
    if hashed != metadata['binary_sha256']:
        raise ValueError('OCI running executable bytes differ from the native payload')
    root_mount = command(engine, 'exec', container, '/bin/busybox', 'cat', '/proc/1/mountinfo').stdout
    if not any(line.split()[4] == '/' and 'ro' in line.split()[5].split(',') for line in root_mount.splitlines()):
        raise ValueError('OCI root mount is not read-only')
    container_record = inspect(engine, container)
    if container_record.get('HostConfig', {}).get('Privileged') or container_record.get('HostConfig', {}).get('NetworkMode') != 'none':
        raise ValueError('OCI runtime changed privileged/private-network policy')
    return {'uid': metadata['uid'], 'gid': metadata['gid'], 'privileged': False,
            'network': 'none', 'effective_capabilities': 0, 'bounding_capabilities': 0,
            'no_new_privileges': True, 'readonly_rootfs': True, 'binary_sha256': hashed,
            'executable': executable, 'pid_namespace_pid': 1}

def wait_ready(engine, container):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        record = inspect(engine, container)
        if not record['State']['Running']:
            raise ValueError('OCI server exited before readiness: ' + command(engine, 'logs', container, check=False).stdout[-4000:])
        result = command(engine, 'exec', container, '/bin/busybox', 'cat', '/run/httpjet/ready', check=False)
        if result.returncode == 0 and result.stdout == '1\n':
            return
        time.sleep(.2)
    raise TimeoutError('OCI server did not publish exact PID1 readiness')


def client_options(work, container, uid, gid):
    return ['--rm', '--network', 'container:' + container, '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--user', f'{uid}:{gid}',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m',
            '--volume', str(work / 'code') + ':/code:ro,Z',
            '--volume', str(work / 'client-cert.pem') + ':/cert.pem:ro,Z',
            '--volume', str(work / 'server.json') + ':/server.json:ro,Z',
            '--volume', str(work / 'output') + ':/out:rw,Z',
            '--env', 'PYTHONDONTWRITEBYTECODE=1']


def client_request(engine, client, container, work, uid, gid, path):
    code = ('import sys,json,hashlib;sys.path.insert(0,"/code/packaging/release");'
            'import protocols;body,_=protocols.http_body("127.0.0.1",8080,sys.argv[1]);'
            'print(json.dumps({"size":len(body),"sha256":hashlib.sha256(body).hexdigest()}))')
    return json.loads(command(engine, 'run', *client_options(work, container, uid, gid),
                              client, 'python3', '-B', '-c', code, path).stdout)


def qualify(metadata, work, engine='docker', client=None, certificate=None, key=None):
    if os.geteuid() != 0:
        raise ValueError('OCI qualification needs isolated root for fixture ownership')
    if metadata.get('uid') != 10001 or metadata.get('gid') != 10001:
        raise ValueError('OCI metadata must identify the dedicated non-root account')
    image = inspect(engine, metadata['image_id'], True)
    if image['Id'] != metadata['image_id'] or image['Config'].get('User') != '10001:10001':
        raise ValueError('OCI image identity/default user mismatch')
    if image['Config'].get('Entrypoint') != [metadata['binary_path']]:
        raise ValueError('OCI image entrypoint is not the native payload')
    if image['Architecture'] != metadata['architecture']:
        raise ValueError('OCI architecture mismatch')
    work = Path(work).resolve()
    work.mkdir(mode=0o700)
    uid, gid = metadata['uid'], metadata['gid']
    make_fixture(work, uid, gid, certificate, key)
    shutil.copyfile(work / 'certs/cert.pem', work / 'client-cert.pem')
    (work / 'client-cert.pem').chmod(0o644)
    (work / 'server.json').write_text(json.dumps({'uid': uid, 'binary_sha256': metadata['binary_sha256'],
        'body_size': len(protocols.BODY), 'body_sha256': hashlib.sha256(protocols.BODY).hexdigest(),
        'no_multishot_accept': True}))
    (work / 'server.json').chmod(0o644)
    security_profile = ROOT / 'packaging/oci/seccomp-httpjet.json'
    options = runtime_options(work, uid, gid, security_profile, engine=engine)
    shared = ['--volume', str(work / 'configuration') + ':/etc/httpjet:ro,z',
              '--volume', str(work / 'site') + ':/site:ro,z',
              '--volume', str(work / 'certs') + ':/certs:ro,z']
    client = client_image(engine, client)
    name = 'httpjet-oci-' + uuid.uuid4().hex
    policy_before = probe.policy()
    report = {'schema': 2, 'status': 'failed', 'image_id': image['Id'], 'client_image_id': client,
              'architecture': metadata['architecture'], 'binary_sha256': metadata['binary_sha256']}
    try:
        command(engine, 'run', '-d', '--name', name, *options, image['Id'])
        wait_ready(engine, name)
        report['sandbox'] = verify_process(engine, name, metadata)
        welcome = command(engine, 'exec', name, '/bin/busybox', 'sha256sum', '/var/www/httpjet/index.html').stdout.split()[0]
        if client_request(engine, client, name, work, uid, gid, '/')['sha256'] != welcome:
            raise ValueError('default OCI welcome differs from the packaged page')
        report['default_http'] = True
        positive = json.loads(command(engine, 'exec', name, metadata['probe_path']).stdout)
        if positive.get('status') != 'passed' or positive.get('uid') != uid or not all(positive.get('operations', {}).get(k) is True for k in ('setup','register_probe','enter_nop')):
            raise ValueError('OCI io_uring operation probe failed')
        positive['scope'] = 'container-sandbox'
        positive['global_policy_changed'] = policy_before != probe.policy()
        positive['kernel'] = os.uname().release
        if positive['global_policy_changed']:
            raise ValueError('kernel policy changed during OCI qualification')
        report['positive'] = positive
        command(engine, 'restart', '--time', '25', name)
        wait_ready(engine, name)
        if client_request(engine, client, name, work, uid, gid, '/')['sha256'] != welcome:
            raise ValueError('OCI welcome failed after restart')
        report['restart'] = True
        command(engine, 'rm', '-f', '--volumes', name)
        args = ['--root','/etc/httpjet','serve','--http-addr','0.0.0.0:8080','--https-addr','0.0.0.0:8443',
                '--metrics-addr=','--no-php','--no-multishot-accept','--workers','1','--no-core-pinning',
                '--ready-file','/run/httpjet/ready','--mimalloc-trim-secs','1','--mimalloc-trim-threshold-mib','0']
        command(engine, 'run', '-d', '--name', name, *options, *shared, image['Id'], *args)
        wait_ready(engine, name)
        verify_process(engine, name, metadata)
        command(engine, 'run', *client_options(work, name, uid, gid), client, 'python3','-B',
                '/code/packaging/release/protocols.py','check','--server-json','/server.json',
                '--certificate','/cert.pem','--host','127.0.0.1','--http-port','8080','--tls-port','8443',
                '--output','/out/runtime.json')
        runtime = work / 'output/runtime.json'
        if runtime.is_symlink() or not runtime.is_file():
            raise ValueError('OCI client did not produce a regular runtime record')
        report['runtime'] = json.loads(runtime.read_text())
        operator_hash = hashlib.sha256((work / 'site/operator-content.txt').read_bytes()).hexdigest()
        command(engine, 'restart', '--time','25',name)
        wait_ready(engine, name)
        if client_request(engine, client, name, work, uid, gid, '/operator-content.txt')['sha256'] != operator_hash:
            raise ValueError('OCI operator volume did not survive restart')
        report['volume_preserved'] = True
        report['runtime']['scope'] = 'container-sandbox'
        command(engine, 'rm', '-f', '--volumes', name)
        negative_ready = work / 'negative-readiness'
        negative_ready.mkdir(mode=0o750)
        os.chown(negative_ready, uid, gid)
        negative_ready.chmod(0o750)
        negative_options = runtime_options(work, uid, gid, security_profile, engine=engine,
                                           readiness_directory=negative_ready)
        denied = command(engine, 'run','--rm',*negative_options,*shared,'--entrypoint',metadata['probe_path'],
                         image['Id'],'--deny-exec',metadata['binary_path'],*args,check=False)
        text = denied.stdout + denied.stderr
        (work / 'negative.log').write_text(text[:65536])
        rows = []
        for line in denied.stdout.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value,dict) and value.get('mode')=='deny-exec':rows.append(value)
        unchanged = policy_before == probe.policy()
        ready_created = (negative_ready / 'ready').exists() or (negative_ready / 'ready').is_symlink()
        if denied.returncode == 0 or len(rows)!=1 or rows[0].get('uid')!=uid or 'build monoio runtime' not in text or 'os error 1)' not in text or not unchanged or ready_created:
            raise ValueError('OCI process-local denial did not produce genuine io_uring failure')
        report['negative'] = {'status':'expected_failure','uid':uid,'exit_code':denied.returncode,'errno':1,
                              'global_policy_changed':False,'ready_file_created':ready_created,
                              'scope':'container-sandbox'}
        report['global_policy_changed'] = not unchanged
        report['status'] = 'passed'
        return report
    finally:
        logs = command(engine,'logs',name,check=False)
        (work/'container.log').write_text((logs.stdout+logs.stderr)[-65536:])
        command(engine,'rm','-f','--volumes',name,check=False)
        (work/'certs/key.pem').unlink(missing_ok=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', required=True, type=Path)
    parser.add_argument('--architecture', choices=('amd64','arm64'))
    parser.add_argument('--engine', default='docker', choices=('docker','podman'))
    parser.add_argument('--client-image')
    parser.add_argument('--certificate', type=Path)
    parser.add_argument('--key', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data = json.loads(args.metadata.read_text())
    if 'oci_images' in data:
        if not args.architecture: parser.error('native provenance requires --architecture')
        data = data['oci_images'][args.architecture]
    report = qualify(data,args.output.parent/(args.output.stem+'.work'),args.engine,args.client_image,
                     args.certificate,args.key)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__ == '__main__':
    main()
