#!/usr/bin/env python3
"""CoreOS policy contracts only; no VM or operating system is qualified here."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('httpjet_coreos_selinux', HERE / 'coreos-check.py')
coreos = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coreos)


def cil_forms(text):
    """Parse the complete small CIL policy, including any added top-level grants."""
    tokens = re.findall(r'\(|\)|[^\s()]+', re.sub(r';[^\n]*', '', text))
    stack, forms = [], []
    for token in tokens:
        if token == '(':
            node = []
            (stack[-1] if stack else forms).append(node)
            stack.append(node)
        elif token == ')':
            if not stack:
                raise ValueError('unbalanced CIL')
            stack.pop()
        elif stack:
            stack[-1].append(token)
        else:
            raise ValueError('unexpected top-level CIL atom')
    if stack:
        raise ValueError('unclosed CIL')
    return forms


class CoreOSSelinux(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='httpjet-coreos-selinux-unit-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.name = 'httpjet-coreos-' + 'a' * 32
        self.row = next(row for row in coreos.support.rows() if row['executor'] == 'coreos')

    def test_policy_grants_only_dedicated_domain_ring_operations(self):
        self.assertEqual(cil_forms(coreos.SELINUX_POLICY.read_text()), [
            ['block', 'httpjet_container',
             ['blockinherit', 'container'],
             ['typeattributeset', 'container_net_domain', ['process']],
             ['allow', 'process', 'io_uring_t', ['anon_inode', ['create', 'map', 'read', 'write']]]]
        ])

    def test_policy_descriptor_binds_actual_source_bytes(self):
        descriptor = coreos.selinux_descriptor()
        self.assertEqual(descriptor, {
            'domain': 'httpjet_container.process',
            'policy_sha256': hashlib.sha256(coreos.SELINUX_POLICY.read_bytes()).hexdigest(),
            'base_template': '/usr/share/udica/templates/base_container.cil',
        })
        altered = self.work / 'altered.cil'
        altered.write_bytes(coreos.SELINUX_POLICY.read_bytes() + b'\n; changed source\n')
        with mock.patch.object(coreos, 'SELINUX_POLICY', altered):
            self.assertNotEqual(coreos.selinux_descriptor()['policy_sha256'], descriptor['policy_sha256'])

    def test_ignition_embeds_exact_root_owned_policy_and_orders_loader(self):
        ignition = coreos.ignition('ssh-ed25519 AAAA unit-only', self.name)
        policy = next(file for file in ignition['storage']['files']
                      if file['path'] == '/etc/selinux/httpjet-container.cil')
        self.assertEqual(policy['mode'], 0o644)
        self.assertEqual(policy.get('user', {}).get('id', 0), 0)
        self.assertEqual(policy.get('group', {}).get('id', 0), 0)
        prefix, encoded = policy['contents']['source'].split(',', 1)
        self.assertEqual(prefix, 'data:text/plain;base64')
        self.assertEqual(base64.b64decode(encoded, validate=True), coreos.SELINUX_POLICY.read_bytes())
        units = {unit['name']: unit for unit in ignition['systemd']['units']}
        loader = units[coreos.SELINUX_UNIT]
        self.assertTrue(loader['enabled'])
        self.assertIn('Before=' + coreos.UNIT, loader['contents'])
        self.assertIn('Type=oneshot', loader['contents'])
        self.assertIn('RemainAfterExit=yes', loader['contents'])
        command = next(line.removeprefix('ExecStart=') for line in loader['contents'].splitlines()
                       if line.startswith('ExecStart='))
        self.assertEqual(shlex.split(command), ['/usr/sbin/semodule', '-i', coreos.SELINUX_BASE,
                                               '/etc/selinux/httpjet-container.cil'])
        app = units[coreos.UNIT]['contents']
        self.assertIn('Requires=' + coreos.SELINUX_UNIT, app)
        after = next(line for line in app.splitlines() if line.startswith('After='))
        self.assertIn(coreos.SELINUX_UNIT, after.split('=', 1)[1].split())
        self.assertIn('--security-opt=label=type:' + coreos.SELINUX_DOMAIN, app)
        self.assertNotIn('label=disable', app)

    def test_documented_units_use_same_required_loader_and_label(self):
        text = (HERE / 'images/README.md').read_text()
        loader, app = re.findall(r'```ini\n(.*?)\n```', text, re.S)
        self.assertIn('Before=httpjet.service', loader)
        self.assertIn('ExecStart=/usr/sbin/semodule -i ' + coreos.SELINUX_BASE
                      + ' /etc/selinux/httpjet-container.cil', loader)
        self.assertIn('Requires=' + coreos.SELINUX_UNIT, app)
        self.assertIn('--security-opt=label=type:' + coreos.SELINUX_DOMAIN, app)
        self.assertIn('-o root -g root -m 0644 /var/tmp/httpjet-container.cil', text)
        self.assertIn('test "$(getenforce)" = Enforcing', text)
        self.assertNotIn('label=disable', app)

    def test_missing_or_changed_policy_lock_rejects_before_download(self):
        lock = {'selinux': coreos.selinux_descriptor(),
                'definition': {'recipe': 'packaging/release/images/coreos.bu',
                               'sha256': coreos.tree_hash(HERE / 'images')}}
        edits = [lambda value: value.pop('selinux'),
                 lambda value: value['selinux'].update(domain='container_t'),
                 lambda value: value['selinux'].update(policy_sha256='0' * 64),
                 lambda value: value['selinux'].update(base_template='/tmp/untrusted.cil')]
        for edit in edits:
            with self.subTest(edit=edit):
                changed = copy.deepcopy(lock)
                edit(changed)
                with mock.patch.object(coreos.release_api, 'download') as download, \
                        mock.patch.object(coreos.subprocess, 'run') as execute:
                    with self.assertRaisesRegex(ValueError, 'SELinux policy differs'):
                        with coreos._machine(self.row, changed, self.work, 'ssh-ed25519 AAAA unit-only', {}, self.name):
                            self.fail('unauthenticated policy reached VM launch')
                    download.assert_not_called()
                    execute.assert_not_called()

    def sandbox_guest(self, domain=coreos.SELINUX_DOMAIN, mode='Enforcing'):
        metadata = {'uid': 10001, 'gid': 10001, 'binary_path': '/usr/bin/httpjet', 'binary_sha256': 'b' * 64}
        guest = mock.Mock()
        record = {'Id': 'a' * 64, 'HostConfig': {'Privileged': False, 'NetworkMode': 'host'},
                  'ProcessLabel': 'system_u:system_r:' + domain + ':s0:c123,c456'}
        guest.inspect.return_value = record
        guest.call.return_value = subprocess.CompletedProcess([], 0, (mode + '\n').encode())
        files = {
            '/proc/1/status': b'Uid:\t10001 10001 10001 10001\nGid:\t10001 10001 10001 10001\nCapEff:\t00000000\nCapBnd:\t00000000\nNoNewPrivs:\t1\n',
            '/proc/1/mountinfo': b'1 0 0:1 / / ro,relatime - overlay overlay ro\n',
            '/proc/1/cmdline': b'/usr/bin/httpjet\0serve\0--no-multishot-accept\0',
        }
        def podman(*arguments, **_options):
            operation, target = arguments[-2:]
            if operation == 'cat':
                data = files[target]
            elif operation == 'readlink':
                data = b'/usr/bin/httpjet\n'
            elif operation == 'sha256sum':
                data = ('b' * 64 + '  /usr/bin/httpjet\n').encode()
            else:
                raise AssertionError('unexpected mocked Podman operation: ' + repr(arguments))
            return subprocess.CompletedProcess([], 0, data)
        guest.podman.side_effect = podman
        return guest, metadata

    def test_runtime_accepts_observed_dedicated_enforcing_domain(self):
        guest, metadata = self.sandbox_guest()
        result = coreos.sandbox(guest, self.name, metadata)
        self.assertEqual(result['selinux_domain'], coreos.SELINUX_DOMAIN)
        self.assertIs(result['selinux_enforcing'], True)
        self.assertEqual(result['uid'], 10001)
        guest.call.assert_called_once_with('getenforce')

    def test_runtime_rejects_default_domain_and_non_enforcing_modes(self):
        cases = [('container_t', 'Enforcing'), ('unconfined_t', 'Enforcing'),
                 (coreos.SELINUX_DOMAIN + '_other', 'Enforcing'),
                 (coreos.SELINUX_DOMAIN, 'Permissive'), (coreos.SELINUX_DOMAIN, 'Disabled')]
        for domain, mode in cases:
            with self.subTest(domain=domain, mode=mode):
                guest, metadata = self.sandbox_guest(domain, mode)
                with self.assertRaisesRegex(ValueError, 'enforcing dedicated SELinux'):
                    coreos.sandbox(guest, self.name, metadata)

    def test_process_local_denial_keeps_the_same_dedicated_label(self):
        guest = mock.Mock()
        guest.policy.return_value = '0'
        output = json.dumps({'mode': 'deny-exec', 'uid': 10001, 'global_policy_changed': False})
        output += '\nfailed to build monoio runtime: Operation not permitted (os error 1)\n'
        guest.podman.return_value = subprocess.CompletedProcess([], 1, output.encode())
        guest.script.return_value = subprocess.CompletedProcess([], 0, b'')
        image = {'probe_path': '/probe', 'binary_path': '/usr/bin/httpjet', 'image_id': 'sha256:' + 'a' * 64}
        result = coreos.negative_probe(guest, image, self.work)
        self.assertEqual(result['errno'], 1)
        arguments = guest.podman.call_args.args
        self.assertIn('label=type:' + coreos.SELINUX_DOMAIN, arguments)
        self.assertIn('--deny-exec', arguments)
        self.assertNotIn('label=disable', arguments)
        self.assertNotIn('--privileged', arguments)
        self.assertIs(result['global_policy_changed'], False)
        self.assertEqual(guest.policy.call_count, 2)

    def test_receipt_requires_matching_policy_enforcement_and_base_hash(self):
        row = self.row
        lock = {'selinux': coreos.selinux_descriptor()}
        image = {'artifact': 'UNIT-ONLY-oci.tar', 'image_id': 'sha256:' + 'e' * 64}
        manifest = {**coreos.support.identity('0.0.1-1'),
                    'binaries': {row['architecture']: {'artifact': 'UNIT-ONLY.tar.gz', 'binary_sha256': 'b' * 64}},
                    'artifacts': {'UNIT-ONLY.tar.gz': {'sha256': 'a' * 64}, image['artifact']: {'sha256': 'd' * 64}},
                    'oci_images': {row['architecture']: image}}
        receipt = {'schema': 2, 'row_id': row['id'], 'release_id': manifest['release_id'],
                   'architecture': row['architecture'], 'route': row['route'], 'init': row['init'],
                   'status': 'passed', 'manifest_sha256': 'c' * 64, 'payload_sha256': 'a' * 64,
                   'binary_sha256': 'b' * 64, 'service_uid': 10001,
                   'container_image_id': image['image_id'], 'container_image_sha256': 'd' * 64,
                   'checks': {name: 'passed' for name in row['checks']},
                   'image': {'sha256': 'f' * 64, 'origin': 'https://example.invalid/UNIT-ONLY',
                             'input_sha256': hashlib.sha256(json.dumps(lock, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                             'selinux': {**lock['selinux'], 'mode': 'Enforcing', 'base_template_sha256': '1' * 64}},
                   'io_uring': {'positive': {'status': 'passed', 'uid': 10001, 'global_policy_changed': False,
                                             'operations': {'setup': True, 'register_probe': True, 'enter_nop': True}},
                                'negative': {'status': 'expected_failure', 'uid': 10001, 'exit_code': 1, 'errno': 1,
                                             'ready_file_created': False, 'global_policy_changed': False}},
                   'kernel': {'no_multishot_accept': True}}
        coreos.support.verify_row(row, receipt, manifest, 'c' * 64, lock)
        edits = [lambda value: value['image'].pop('selinux'),
                 lambda value: value['image']['selinux'].update(domain='container_t'),
                 lambda value: value['image']['selinux'].update(policy_sha256='0' * 64),
                 lambda value: value['image']['selinux'].update(mode='Permissive'),
                 lambda value: value['image']['selinux'].update(base_template_sha256='not-a-sha256')]
        for edit in edits:
            with self.subTest(edit=edit):
                changed = copy.deepcopy(receipt)
                edit(changed)
                with self.assertRaisesRegex(ValueError, 'enforcing dedicated SELinux policy proof'):
                    coreos.support.verify_row(row, changed, manifest, 'c' * 64, lock)


if __name__ == '__main__':
    unittest.main()
