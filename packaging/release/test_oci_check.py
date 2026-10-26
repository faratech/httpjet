#!/usr/bin/env python3
"""Owned tmpfs and observable denial-readiness mounts for each OCI engine."""
import importlib.util
from pathlib import Path
import sys
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('httpjet_oci_check', HERE / 'oci-check.py')
oci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oci)


class RuntimeMounts(unittest.TestCase):
    def setUp(self):
        self.work = Path('/qualification')
        self.profile = self.work / 'seccomp.json'
        self.uid = self.gid = 10001
        self.base = ['--network', 'none', '--read-only', '--cap-drop', 'ALL',
                     '--security-opt', 'no-new-privileges', '--security-opt',
                     'seccomp=' + str(self.profile), '--ulimit', 'memlock=8388608:8388608',
                     '--cpus', '2', '--memory', '2g']

    def options(self, engine='docker', **keywords):
        return oci.runtime_options(self.work, self.uid, self.gid, self.profile, engine=engine, **keywords)

    def test_docker_options_remain_identical(self):
        expected = self.base + [
            '--tmpfs', '/run/httpjet:rw,noexec,nosuid,nodev,size=16m,mode=0750,uid=10001,gid=10001',
            '--tmpfs', '/var/log/httpjet:rw,noexec,nosuid,nodev,size=16m,mode=0750,uid=10001,gid=10001',
            '--env', 'RUST_LOG=warn']
        self.assertEqual(self.options(), expected)
        self.assertEqual(oci.runtime_options(self.work, self.uid, self.gid, self.profile), expected)

    def test_podman_uses_owned_tmpfs_mounts_without_unsupported_uid_options(self):
        expected = self.base + [
            '--mount', 'type=tmpfs,dst=/run/httpjet,tmpfs-size=16m,tmpfs-mode=0750,U,noexec,nosuid,nodev',
            '--mount', 'type=tmpfs,dst=/var/log/httpjet,tmpfs-size=16m,tmpfs-mode=0750,U,noexec,nosuid,nodev',
            '--env', 'RUST_LOG=warn']
        options = self.options('podman')
        self.assertEqual(options, expected)
        self.assertNotIn('--tmpfs', options)
        self.assertFalse(any('uid=' in value or 'gid=' in value for value in options))

    def test_denial_replaces_only_the_run_mount_with_an_observable_bind(self):
        ready = self.work / 'negative-readiness'
        for engine, flag in (('docker', '--tmpfs'), ('podman', '--mount')):
            with self.subTest(engine=engine):
                options = self.options(engine, readiness_directory=ready)
                mounts = [options[index + 1] for index, value in enumerate(options) if value == flag]
                self.assertEqual(len(mounts), 1)
                self.assertIn('/var/log/httpjet', mounts[0])
                self.assertNotIn('/run/httpjet', mounts[0])
                self.assertEqual(options[-2:], ['--volume', str(ready) + ':/run/httpjet:rw,z'])
                self.assertEqual(sum('/run/httpjet' in value for value in options), 1)
                self.assertEqual(options[:len(self.base)], self.base)
                self.assertIn('RUST_LOG=warn', options)


if __name__ == '__main__':
    unittest.main()
