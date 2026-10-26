#!/usr/bin/env python3
"""Check genuine syscall evidence and reject unrelated startup failures."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import probe


class KernelProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('cc')
        if compiler is None:
            raise unittest.SkipTest('C compiler required for qualification helper tests')
        cls.temporary = tempfile.TemporaryDirectory(prefix='httpjet-probe-test-', dir='/var/tmp')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.root.chmod(0o755)
        cls.binary = cls.root / 'io-uring-probe'
        subprocess.run([compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(Path(__file__).with_name('io-uring-probe.c')), '-o', str(cls.binary)], check=True)
        cls.uid = 65534 if os.geteuid() == 0 else os.geteuid()
        cls.gid = 65534 if os.geteuid() == 0 else os.getegid()

    def test_real_operations_or_actionable_failure(self):
        before = probe.policy()
        evidence = probe.positive(self.binary, self.uid, self.gid)
        self.assertEqual(evidence['uid'], self.uid)
        self.assertFalse(evidence['global_policy_changed'])
        self.assertEqual(before, probe.policy())
        if evidence['status'] == 'passed':
            self.assertEqual(evidence['exit_code'], 0)
            self.assertTrue(all(evidence['operations'].values()))
        else:
            # Host policy can deny io_uring; such a record cannot qualify a release.
            self.assertEqual(evidence['status'], 'failed')
            self.assertNotEqual(evidence['exit_code'], 0)
            self.assertIn(evidence['errno'], (1, 12, 13, 22, 38))

    def test_process_filter_blocks_setup_without_host_policy_change(self):
        before = probe.policy()
        result = probe.execute([self.binary, '--deny-exec', self.binary], self.uid, self.gid)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(result.returncode, 1)
        self.assertEqual(rows[0]['mode'], 'deny-exec')
        self.assertEqual(rows[0]['uid'], self.uid)
        self.assertEqual(rows[1]['operation'], 'setup')
        self.assertEqual(rows[1]['errno'], 1)
        self.assertEqual(rows[1]['status'], 'failed')
        self.assertEqual(before, probe.policy())

    def test_root_cannot_qualify(self):
        with self.assertRaisesRegex(ValueError, 'non-root'):
            probe.positive(self.binary, 0, 0)

    def test_changed_policy_cannot_report_success(self):
        body = {'status': 'passed', 'uid': self.uid,
                'operations': {'setup': True, 'register_probe': True, 'enter_nop': True}}
        result = subprocess.CompletedProcess([], 0, json.dumps(body), '')
        with patch.object(probe, 'execute', return_value=result), patch.object(probe, 'policy', side_effect=['0', '2']):
            evidence = probe.positive(self.binary, self.uid, self.gid)
        self.assertEqual(evidence['status'], 'failed')
        self.assertTrue(evidence['global_policy_changed'])

    def test_config_permission_error_is_not_io_uring_denial(self):
        server = self.root / 'permission-failure'
        server.write_text('#!/bin/sh\nprintf "Permission denied (os error 13)\\n" >&2\nexit 1\n')
        server.chmod(0o755)
        evidence = probe.negative(self.binary, server, self.root, self.uid, self.gid,
                                  self.root / 'permission.log')
        self.assertEqual(evidence['status'], 'failed')
        self.assertIsNone(evidence['errno'])
        self.assertFalse(evidence['global_policy_changed'])

    def test_unrelated_eperm_is_not_runtime_denial_evidence(self):
        server = self.root / 'unrelated-eperm'
        server.write_text('#!/bin/sh\nprintf "Unrelated file operation: Operation not permitted (os error 1)\\n" >&2\nexit 1\n')
        server.chmod(0o755)
        evidence = probe.negative(self.binary, server, self.root, self.uid, self.gid,
                                  self.root / 'unrelated.log')
        self.assertEqual(evidence['status'], 'failed')
        self.assertIsNone(evidence['errno'])


if __name__ == '__main__':
    unittest.main()
