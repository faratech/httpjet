#!/usr/bin/env python3
"""Record real unprivileged io_uring operation and process-local denial evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import tempfile


def policy():
    path = Path('/proc/sys/kernel/io_uring_disabled')
    return path.read_text().strip() if path.exists() else None


def identity(uid, gid):
    if uid <= 0 or gid < 0:
        raise ValueError('qualification must use a non-root service account')
    if os.geteuid() == 0:
        try:
            account = pwd.getpwuid(uid).pw_name
            groups = os.getgrouplist(account, gid)
        except KeyError:
            groups = [gid]
        # Use the service account's groups, never the privileged caller's.
        return {'user': uid, 'group': gid, 'extra_groups': sorted(set(groups))}
    if (os.geteuid(), os.getegid()) != (uid, gid):
        raise ValueError('caller cannot assume the requested service identity')
    return {}


def execute(command, uid, gid, environment=None, timeout=15):
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}
    env.update(environment or {})
    return subprocess.run([str(value) for value in command], env=env,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          start_new_session=True, timeout=timeout, **identity(uid, gid))


def positive(probe, uid, gid):
    before = policy()
    result = execute([Path(probe).resolve()], uid, gid)
    try:
        evidence = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError('io_uring probe did not produce one JSON evidence record') from error
    passed = (result.returncode == 0 and evidence.get('status') == 'passed'
              and evidence.get('uid') == uid and uid > 0
              and all(evidence.get('operations', {}).get(key) is True
                      for key in ('setup', 'register_probe', 'enter_nop')))
    evidence.update(exit_code=result.returncode, global_policy_changed=before != policy(),
                    kernel=os.uname().release)
    if not passed or evidence['global_policy_changed']:
        evidence['status'] = 'failed'
    return evidence


def negative(probe, server, root, uid, gid, log_file, timeout=15, no_multishot_accept=False):
    identity(uid, gid)
    before = policy()
    with tempfile.TemporaryDirectory(prefix='httpjet-deny-probe-', dir='/var/tmp') as temporary:
        work = Path(temporary)
        work.chmod(0o711)
        for name in ('logs', 'readiness'):
            directory = work / name
            directory.mkdir(mode=0o700)
            if os.geteuid() == 0:
                os.chown(directory, uid, gid)
        ready = work / 'readiness/ready'
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        command = [Path(probe).resolve(), '--deny-exec', Path(server).resolve(),
                   '--root', Path(root).resolve(), 'serve', '--http-addr', f'127.0.0.1:{port}',
                   '--https-addr=', '--metrics-addr=', '--workers', '1', '--no-core-pinning',
                   '--no-php', '--ready-file', ready]
        if no_multishot_accept:
            command.append('--no-multishot-accept')
        try:
            result = execute(command, uid, gid,
                             {'HTTPJET_LOG_DIR': str(work / 'logs'), 'RUST_LOG': 'warn'}, timeout)
            output = result.stdout + result.stderr
            exit_code = result.returncode
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or b''
            stderr = error.stderr or b''
            output = (stdout.decode(errors='replace') if isinstance(stdout, bytes) else stdout)
            output += (stderr.decode(errors='replace') if isinstance(stderr, bytes) else stderr)
            exit_code = None
        records = []
        for line in output.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict) and record.get('mode') == 'deny-exec':
                records.append(record)
        uring_failure = 'build monoio runtime' in output or 'io_uring_setup' in output
        errno = (1 if 'Operation not permitted' in output or 'os error 1)' in output else (
            38 if 'Function not implemented' in output or 'os error 38)' in output else None)) if uring_failure else None
        unchanged = before == policy()
        passed = (len(records) == 1 and records[0].get('uid') == uid
                  and records[0].get('global_policy_changed') is False
                  and exit_code is not None and exit_code != 0 and errno in (1, 38)
                  and unchanged and not ready.exists())
        log_file = Path(log_file)
        log_file.write_text(output[:65536])
        return {'schema': 1, 'status': 'expected_failure' if passed else 'failed',
                'uid': uid, 'exit_code': exit_code, 'errno': errno,
                'global_policy_changed': not unchanged, 'ready_file_created': ready.exists(),
                'log': log_file.name, 'log_sha256': hashlib.sha256(log_file.read_bytes()).hexdigest(),
                'kernel': os.uname().release}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('positive', 'negative'))
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--uid', required=True, type=int)
    parser.add_argument('--gid', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--no-multishot-accept', action='store_true')
    args = parser.parse_args()
    if args.mode == 'positive':
        evidence = positive(args.probe, args.uid, args.gid)
    else:
        if args.server is None or args.root is None:
            parser.error('negative mode requires --server and --root')
        evidence = negative(args.probe, args.server, args.root, args.uid, args.gid,
                            args.output.with_suffix('.log'),
                            no_multishot_accept=args.no_multishot_accept)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    print(json.dumps(evidence, sort_keys=True))
    raise SystemExit(0 if evidence['status'] in ('passed', 'expected_failure') else 1)


if __name__ == '__main__':
    main()
