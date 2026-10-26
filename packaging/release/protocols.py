#!/usr/bin/env python3
"""Isolated unprivileged runtime fixture; clients may use forwarded VM ports."""

import argparse
import asyncio
import gzip
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from xml.sax.saxutils import escape

BODY = bytes(range(256)) * 4097
COMPRESSIBLE = b'<html>' + b'portable compression fixture ' * 4096 + b'</html>'
NAME = 'portable.test'


def write(path, value, mode=0o644):
    Path(path).write_bytes(value if isinstance(value, bytes) else value.encode())
    Path(path).chmod(mode)


def process_identity(pid):
    directory = Path('/proc') / str(pid)
    try:
        uids = next(line for line in (directory / 'status').read_text().splitlines()
                    if line.startswith('Uid:')).split()[1:]
        text = (directory / 'stat').read_text()
        return {'pid': pid, 'uid': int(uids[1]),
                'start_ticks': int(text[text.rfind(')') + 2:].split()[19]),
                'executable': str((directory / 'exe').resolve(strict=True))}
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def start(binary, directory, uid, gid, certificate, key, http_port, tls_port,
          bind='0.0.0.0', no_multishot_accept=False):
    if uid <= 0 or gid <= 0 or (os.geteuid() != 0 and (uid, gid) != (os.geteuid(), os.getegid())):
        raise ValueError('runtime fixture must use its non-root service account')
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o711)
    directory.chmod(0o711)
    (directory / 'conf/vhosts').mkdir(parents=True)
    (directory / 'html').mkdir()
    for name in ('conf', 'conf/vhosts', 'html'):
        (directory / name).chmod(0o755)
    for name in ('logs', 'readiness'):
        location = directory / name
        location.mkdir(mode=0o750)
        location.chmod(0o750)
        if os.geteuid() == 0:
            os.chown(location, uid, gid)
    executable = directory / 'httpjet'
    shutil.copyfile(binary, executable)
    executable.chmod(0o755)
    shutil.copyfile(certificate, directory / 'cert.pem')
    shutil.copyfile(key, directory / 'key.pem')
    (directory / 'cert.pem').chmod(0o644)
    (directory / 'key.pem').chmod(0o400)
    if os.geteuid() == 0:
        os.chown(directory / 'key.pem', uid, gid)
    write(directory / 'html/large.bin', BODY)
    write(directory / 'html/compress.html', COMPRESSIBLE)
    write(directory / 'conf/mime.properties', 'application/octet-stream=bin\ntext/html=html\n')
    xml_root = escape(str(directory))
    maps = f'<vhostMapList><vhostMap><vhost>{NAME}</vhost><domain>{NAME},www.{NAME},*</domain></vhostMap></vhostMapList>'
    write(directory / 'conf/httpd_config.xml',
          f'<httpServerConfig><serverName>{NAME}</serverName><indexFiles>compress.html</indexFiles>'
          f'<quic><quicEnable>1</quicEnable></quic><virtualHostList><virtualHost><name>{NAME}</name>'
          f'<vhRoot>{xml_root}/html</vhRoot><configFile>$SERVER_ROOT/conf/vhosts/default.xml</configFile>'
          '<enableScript>0</enableScript><allowSymbolLink>0</allowSymbolLink></virtualHost></virtualHostList>'
          f'<listenerList><listener><name>http</name><address>{bind}:{http_port}</address><secure>0</secure>{maps}</listener>'
          f'<listener><name>https</name><address>{bind}:{tls_port}</address><secure>1</secure>'
          f'<keyFile>{xml_root}/key.pem</keyFile><certFile>{xml_root}/cert.pem</certFile><clientVerify>0</clientVerify>'
          f'{maps}</listener></listenerList></httpServerConfig>')
    write(directory / 'conf/vhosts/default.xml',
          f'<virtualHostConfig><docRoot>{xml_root}/html</docRoot><indexFiles>compress.html</indexFiles>'
          '<allowSymbolLink>0</allowSymbolLink></virtualHostConfig>')
    ready = directory / 'readiness/pid'
    arguments = [str(executable), '--root', str(directory), 'serve', '--http-addr', f'{bind}:{http_port}',
                 '--https-addr', f'{bind}:{tls_port}', '--metrics-addr=', '--workers', '1',
                 '--no-core-pinning', '--no-php', '--ready-file', str(ready),
                 '--mimalloc-trim-secs', '1', '--mimalloc-trim-threshold-mib', '0']
    if no_multishot_accept:
        arguments.append('--no-multishot-accept')
    credentials = {}
    if os.geteuid() == 0:
        account = pwd.getpwuid(uid).pw_name
        credentials = {'user': uid, 'group': gid, 'extra_groups': os.getgrouplist(account, gid)}
    try:
        with (directory / 'server.log').open('wb') as log:
            process = subprocess.Popen(arguments, env={'PATH': '/usr/bin:/bin', 'HTTPJET_LOG_DIR': str(directory / 'logs'),
                                       'RUST_LOG': 'warn'}, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       start_new_session=True, **credentials)
    except BaseException:
        (directory / 'key.pem').unlink(missing_ok=True)
        raise
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('runtime server failed: ' + (directory / 'server.log').read_text()[-8000:])
            if ready.exists() and ready.read_text() == str(process.pid) + '\n':
                break
            time.sleep(.1)
        else:
            raise TimeoutError('runtime fixture did not publish readiness')
        identity = process_identity(process.pid)
        if not identity or identity['uid'] != uid or identity['executable'] != str(executable):
            raise ValueError('runtime process identity mismatch')
        report = {'schema': 2, 'scope': 'unprivileged-runtime', **identity,
                  'binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
                  'http_port': http_port, 'tls_port': tls_port,
                  'no_multishot_accept': no_multishot_accept,
                  'body_size': len(BODY), 'body_sha256': hashlib.sha256(BODY).hexdigest()}
        write(directory / 'server.json', json.dumps(report, sort_keys=True) + '\n', 0o600)
        return report
    except BaseException:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
        (directory / 'key.pem').unlink(missing_ok=True)
        raise

def http_body(host, port, path, certificate=None, encoding=None):
    if certificate is None:
        stream = socket.create_connection((host, port), timeout=10)
    else:
        context = ssl.create_default_context(cafile=str(certificate))
        context.set_alpn_protocols(['http/1.1'])
        stream = context.wrap_socket(socket.create_connection((host, port), timeout=10), server_hostname=NAME)
    with stream:
        accept = f'Accept-Encoding: {encoding}\r\n' if encoding else ''
        stream.sendall(f'GET {path} HTTP/1.1\r\nHost: {NAME}\r\n{accept}Connection: close\r\n\r\n'.encode())
        response = http.client.HTTPResponse(stream)
        response.begin()
        if response.status != 200:
            raise ValueError('runtime HTTP status ' + str(response.status))
        deadline = time.monotonic() + 30
        body = bytearray()
        while len(body) <= len(BODY):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('runtime HTTP body deadline')
            stream.settimeout(min(10, remaining))
            chunk = response.read1(min(65536, len(BODY) + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        if len(body) > len(BODY):
            raise ValueError('runtime HTTP body exceeds its bound')
        return bytes(body), dict(response.getheaders())


def http2_body(host, port, certificate):
    import h2.connection
    import h2.events
    context = ssl.create_default_context(cafile=str(certificate))
    context.set_alpn_protocols(['h2'])
    with context.wrap_socket(socket.create_connection((host, port), timeout=15), server_hostname=NAME) as stream:
        if stream.selected_alpn_protocol() != 'h2':
            raise ValueError('HTTP/2 ALPN negotiation failed')
        client = h2.connection.H2Connection()
        client.initiate_connection(); stream.sendall(client.data_to_send())
        client.send_headers(1, [(b':method', b'GET'), (b':scheme', b'https'),
                               (b':authority', NAME.encode()), (b':path', b'/large.bin')], end_stream=True)
        stream.sendall(client.data_to_send())
        received, status, done = bytearray(), None, False
        deadline = time.monotonic() + 30
        while not done:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('HTTP/2 runtime deadline')
            stream.settimeout(min(15, remaining))
            packet = stream.recv(65536)
            if not packet:
                raise ValueError('HTTP/2 stream ended early')
            for event in client.receive_data(packet):
                if isinstance(event, h2.events.ResponseReceived):
                    status = dict(event.headers).get(b':status')
                elif isinstance(event, h2.events.DataReceived):
                    received.extend(event.data)
                    if len(received) > len(BODY):
                        raise ValueError('HTTP/2 body exceeds runtime fixture bound')
                    client.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    done = True
                elif isinstance(event, (h2.events.StreamReset, h2.events.ConnectionTerminated)):
                    raise ValueError('HTTP/2 request failed: ' + str(event))
            if data := client.data_to_send():
                stream.sendall(data)
        if status != b'200':
            raise ValueError('HTTP/2 status is not 200')
        return bytes(received)


async def http3_body(host, port, certificate):
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
    from h3get import H3Client
    class BoundedClient(H3Client):
        def quic_event_received(self, event):
            super().quic_event_received(event)
            if any(length > len(BODY) for length in self._length.values()):
                for future in self._done.values():
                    if not future.done():
                        future.set_exception(ValueError('HTTP/3 body exceeds runtime fixture bound'))
                self.close(error_code=0x10C, reason_phrase='runtime response size exceeded')
    configuration = QuicConfiguration(is_client=True, alpn_protocols=['h3'])
    configuration.server_name = NAME
    configuration.verify_mode = ssl.CERT_REQUIRED
    configuration.load_verify_locations(cafile=str(certificate))
    async with connect(host, port, configuration=configuration, create_protocol=BoundedClient) as client:
        await client.wait_connected()
        status, body = await client.get(NAME, '/large.bin')
        if status != b'200':
            raise ValueError('HTTP/3 status is not 200')
        return body


def check(server, host, http_port, tls_port, certificate):
    if server.get('uid', 0) <= 0 or server.get('body_size') != len(BODY) or server.get('body_sha256') != hashlib.sha256(BODY).hexdigest():
        raise ValueError('runtime fixture identity/body mismatch')
    protocols, hashes = {}, {}
    for name in ('http', 'tls', 'h2', 'h3'):
        if name == 'http': body, _ = http_body(host, http_port, '/large.bin')
        elif name == 'tls': body, _ = http_body(host, tls_port, '/large.bin', certificate)
        elif name == 'h2': body = http2_body(host, tls_port, certificate)
        else: body = asyncio.run(asyncio.wait_for(http3_body(host, tls_port, certificate), 30))
        if body != BODY:
            raise ValueError(name + ' response differs from complete runtime fixture')
        protocols[name] = True
        hashes[name] = hashlib.sha256(body).hexdigest()
    body, headers = http_body(host, http_port, '/compress.html', encoding='gzip')
    headers = {name.lower(): value for name, value in headers.items()}
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as decoder:
        decoded = decoder.read(len(COMPRESSIBLE) + 1)
    if headers.get('content-encoding') != 'gzip' or decoded != COMPRESSIBLE:
        raise ValueError('gzip compression did not preserve its body')
    time.sleep(2)
    after_trim, _ = http_body(host, http_port, '/large.bin')
    if after_trim != BODY:
        raise ValueError('runtime did not preserve its body after allocator trim interval')
    return {'schema': 2, 'scope': 'unprivileged-runtime', 'status': 'passed',
            'uid': server['uid'], 'binary_sha256': server['binary_sha256'], 'protocols': protocols,
            'body_size': len(BODY), 'body_sha256': server['body_sha256'], 'hashes': hashes,
            'compression_gzip': True, 'allocator_trim_soak_seconds': 2,
            'no_multishot_accept': server['no_multishot_accept']}


def stop(directory):
    directory = Path(directory)
    record = json.loads((directory / 'server.json').read_text())
    actual = process_identity(record['pid'])
    expected = {key: record[key] for key in ('pid', 'uid', 'start_ticks', 'executable')}
    if actual and actual != expected:
        raise ValueError('refusing to stop a different process')
    if actual:
        os.kill(record['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 20
        while process_identity(record['pid']) == expected and time.monotonic() < deadline:
            time.sleep(.1)
        if process_identity(record['pid']) == expected:
            os.kill(record['pid'], signal.SIGKILL)
    (directory / 'key.pem').unlink(missing_ok=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='mode', required=True)
    starting = subparsers.add_parser('start')
    for name in ('binary', 'directory', 'certificate', 'key'):
        starting.add_argument('--' + name, required=True, type=Path)
    for name in ('uid', 'gid', 'http-port', 'tls-port'):
        starting.add_argument('--' + name, required=True, type=int)
    starting.add_argument('--bind', default='0.0.0.0')
    starting.add_argument('--no-multishot-accept', action='store_true')
    checking = subparsers.add_parser('check')
    for name in ('server-json', 'certificate', 'output'):
        checking.add_argument('--' + name, required=True, type=Path)
    checking.add_argument('--host', default='127.0.0.1')
    checking.add_argument('--http-port', required=True, type=int)
    checking.add_argument('--tls-port', required=True, type=int)
    stopping = subparsers.add_parser('stop')
    stopping.add_argument('--directory', required=True, type=Path)
    args = parser.parse_args()
    if args.mode == 'start':
        report = start(args.binary, args.directory, args.uid, args.gid, args.certificate, args.key,
                       args.http_port, args.tls_port, args.bind, args.no_multishot_accept)
    elif args.mode == 'check':
        report = check(json.loads(args.server_json.read_text()), args.host, args.http_port, args.tls_port, args.certificate)
        write(args.output, json.dumps(report, indent=2, sort_keys=True) + '\n', 0o600)
    else:
        stop(args.directory)
        report = {'status': 'stopped'}
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
