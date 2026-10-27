"""Pinned Guix bootstrap contracts; no host store is installed by these tests."""
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import guix_bootstrap as bootstrap
import declarative


class GuixBootstrap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gpg') or not shutil.which('gpgv'):
            raise unittest.SkipTest('requires GnuPG')
        cls.temporary = tempfile.TemporaryDirectory(prefix='httpjet-guix-unit-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.home = cls.root / 'signing'; cls.home.mkdir(mode=0o700)
        cls.command = ['gpg', '--batch', '--no-options', '--homedir', str(cls.home)]
        subprocess.run(cls.command + ['--pinentry-mode', 'loopback', '--passphrase', '',
            '--quick-generate-key', 'httpjet Guix UNIT ONLY <unit@example.invalid>', 'ed25519', 'sign', '1d'],
            check=True, capture_output=True)
        cls.addClassCleanup(lambda: subprocess.run(['gpgconf', '--homedir', str(cls.home), '--kill', 'all'], capture_output=True))
        cls.key = cls.root / 'unit.pub'
        cls.key.write_bytes(subprocess.run(cls.command + ['--armor', '--export'], check=True, capture_output=True).stdout)
        listing = subprocess.run(cls.command + ['--with-colons', '--list-keys'], check=True, capture_output=True, text=True).stdout
        cls.fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        cls.archive = cls.root / 'unit-archive'
        cls.archive.write_bytes(b'UNIT ONLY, NOT A GUIX BOOTSTRAP\n')
        subprocess.run(cls.command + ['--detach-sign', str(cls.archive)], check=True, capture_output=True)
        cls.signature = Path(str(cls.archive) + '.sig')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='case-', dir=self.root)
        self.addCleanup(temporary.cleanup); self.work = Path(temporary.name)
        self.addCleanup(lambda: subprocess.run(['gpgconf', '--homedir', str(self.work / 'gnupg'), '--kill', 'all'], capture_output=True))

    def verify_unit(self, signature=None, fingerprint=None, digest=None):
        with mock.patch.object(bootstrap, 'FINGERPRINT', fingerprint or self.fingerprint), \
             mock.patch.object(bootstrap, 'KEY_SHA256', bootstrap.sha(self.key)), \
             mock.patch.dict(bootstrap.ARCHIVES, {'amd64': ('x86_64-linux', digest or bootstrap.sha(self.archive), self.archive.stat().st_size)}):
            return bootstrap.verify('amd64', self.archive, signature or self.signature, self.key, self.work)

    def test_valid_hash_full_primary_and_real_signature_are_all_required(self):
        result = self.verify_unit()
        self.assertIs(result['checksum_verified'], True)
        self.assertIs(result['signature_valid'], True)
        self.assertEqual(result['primary_fingerprint'], self.fingerprint)

    def test_hash_mismatch_rejects_before_any_gpg_execution(self):
        with mock.patch.object(bootstrap, 'execute') as execute:
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                self.verify_unit(digest='0' * 64)
            execute.assert_not_called()

    def test_wrong_approved_primary_is_fatal_even_with_valid_signed_bytes(self):
        with self.assertRaisesRegex(ValueError, 'primary fingerprint'):
            self.verify_unit(fingerprint='0' * 40)

    def test_bad_detached_signature_is_fatal(self):
        signature = self.work / 'corrupt.sig'
        signature.write_bytes(b'not a signature')
        with self.assertRaises(RuntimeError):
            self.verify_unit(signature=signature)

    def test_production_inputs_pin_both_native_architectures_and_public_key_bytes(self):
        self.assertEqual(bootstrap.sha(bootstrap.KEY), bootstrap.KEY_SHA256)
        self.assertTrue(bootstrap.KEY.read_bytes().startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'))
        for arch, system in (('amd64', 'x86_64-linux'), ('arm64', 'aarch64-linux')):
            result = bootstrap.descriptor(arch)
            self.assertEqual(result['system'], system)
            self.assertIn('guix-binary-1.5.0.' + system + '.tar.xz', result['url'])
            self.assertEqual(result['primary_fingerprint'], 'A28BF40C3E551372662D14F741AAE7DCCA3D8351')

    def test_staged_builder_has_exact_source_and_approved_public_key(self):
        bootstrap.stage(self.work)
        self.assertEqual(bootstrap.sha(self.work / bootstrap.KEY.name), bootstrap.KEY_SHA256)
        self.assertEqual(bootstrap.sha(self.work / 'guix_bootstrap.py'), bootstrap.sha(bootstrap.__file__))
        with self.assertRaises(ValueError):
            bootstrap.stage(self.work)

    def test_bootstrap_cannot_install_a_host_store_as_an_unprivileged_caller(self):
        with mock.patch.object(bootstrap.os, 'geteuid', return_value=1000), mock.patch.object(bootstrap, 'download') as download:
            with self.assertRaisesRegex(ValueError, 'disposable builder'):
                bootstrap.bootstrap('amd64', self.work / 'receipt.json')
            download.assert_not_called()
        self.assertFalse((self.work / 'receipt.json').exists())

    def test_tls_redirect_cannot_downgrade_or_embed_credentials(self):
        request = bootstrap.urllib.request.Request('https://ftp.gnu.org/gnu/guix/unit')
        for target in ('http://mirror.example/unit', 'https://user:password@mirror.example/unit'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                bootstrap.HTTPSRedirect().redirect_request(request, None, 302, 'Found', {}, target)

    def test_archive_paths_devices_and_unexpected_roots_reject(self):
        for name in ('./gnu/../etc/passwd', '/gnu/file', './etc/passwd', './var/spool/file'):
            with self.subTest(name=name):
                archive = self.work / 'paths.tar.xz'
                with tarfile.open(archive, 'w:xz') as output:
                    member = tarfile.TarInfo(name); member.size = 1
                    output.addfile(member, io.BytesIO(b'x'))
                with self.assertRaises(ValueError):
                    bootstrap.validate_archive(archive)

    def test_builder_verifies_bootstrap_before_daemon_and_preserves_channel_auth(self):
        ports = {'ssh': 22022, 'http': 22080, 'tls': 22443, 'quic': 22443}
        script = declarative.guix_script('amd64', ports, False)
        self.assertNotIn('install -y --no-install-recommends guix ', script)
        self.assertLess(script.index('/inputs/guix_bootstrap.py'), script.index('guix-daemon --'))
        self.assertLess(script.index('guix archive --authorize'), script.index('guix time-machine'))
        self.assertIn('guix time-machine -C /inputs/definitions/channels.scm', script)
        self.assertIn('$GUIX_PROFILE/share/guix/$httpjet_cache.pub', script)


if __name__ == '__main__':
    unittest.main()
