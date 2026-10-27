#!/usr/bin/env python3
"""Exercise container certificate creation without a Docker daemon."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class ContainerCertificate(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-container-cert-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tls = self.root / 'tls'
        self.binary = self.root / 'httpjet'
        self.binary.write_text('#!/bin/sh\nprintf "server: %s\\n" "$*"\n')
        self.binary.chmod(0o755)
        self.entry = self.root / 'entrypoint.sh'
        self.entry.write_text((HERE / 'entrypoint.sh').read_text()
                              .replace('/var/lib/httpjet/tls', str(self.tls))
                              .replace('/usr/bin/httpjet', str(self.binary)))
        self.entry.chmod(0o755)

    def invoke(self):
        return subprocess.run([str(self.entry), '--version'], text=True, capture_output=True)

    def test_unique_certificate_is_created_and_preserved(self):
        first = self.invoke()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn('server: --version', first.stdout)
        key = self.tls / 'default.key'
        cert = self.tls / 'default.crt'
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        original = (key.read_bytes(), cert.read_bytes())
        subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '0'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        second = self.invoke()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(original, (key.read_bytes(), cert.read_bytes()))

    def test_incomplete_pair_is_not_overwritten(self):
        self.tls.mkdir()
        key = self.tls / 'default.key'
        key.write_bytes(b'administrator data')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('incomplete or unsafe TLS pair', result.stderr)
        self.assertEqual(key.read_bytes(), b'administrator data')
        self.assertFalse((self.tls / 'default.crt').exists())


if __name__ == '__main__':
    unittest.main()
