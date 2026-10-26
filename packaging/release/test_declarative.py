#!/usr/bin/env python3
"""Exercise locked declarative dispatch and exact allocated-process cleanup."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('httpjet_declarative', Path(__file__).with_name('declarative.py'))
driver = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(driver)


class Builders(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-declarative-test-')
        self.addCleanup(self.temporary.cleanup); self.root = Path(self.temporary.name)
        self.source = self.root / 'source'; definitions = self.source / 'packaging/nix'; definitions.mkdir(parents=True)
        (definitions / 'qualification.nix').write_text('{ }: {}\n')
        self.row = {'executor': 'nix-image', 'architecture': 'amd64'}
        self.lock = {'definition': {'system': 'x86_64-linux', 'sha256': driver.tree_hash(definitions),
                                   'recipe': 'packaging/nix/qualification.nix',
                                   'origin': 'https://example.invalid/pinned-definition'},
                     'builder': {'image': 'nixos/nix@sha256:' + '1'*64}}
        self.manifest = self.root / 'manifest.json'; self.manifest.write_text(json.dumps({'release_id': '0.1.10-1'}))
        self.key = self.root / 'ssh.pub'; self.key.write_text('ssh-ed25519 fixture\n')
        self.directory = self.root / 'new-vm'
        self.ports = {'ssh': 22022, 'http': 22080, 'tls': 22443, 'quic': 22443}

    def manager(self):
        return driver.run(self.row, self.lock, self.manifest, 'https://httpjet-qualification.local:25443/releases',
                          self.key, self.directory, self.ports)

    def test_changed_definition_fails_before_engine_or_directory(self):
        self.lock['definition']['sha256'] = '0'*64
        with mock.patch.object(driver, 'ROOT', self.source), mock.patch.object(driver.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(driver, 'engine') as engine:
            with self.assertRaisesRegex(ValueError, 'differs from signed image lock'):
                with self.manager(): pass
            engine.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_privileged_host_port_is_not_used(self):
        self.ports['ssh'] = 22
        with mock.patch.object(driver, 'ROOT', self.source), mock.patch.object(driver.platform, 'machine', return_value='x86_64'):
            with self.assertRaisesRegex(ValueError, 'unprivileged ports'):
                with self.manager(): pass

    def test_nar_identity_and_cleanup_are_bound_to_allocated_container(self):
        calls = []; identifier = 'a'*64
        process = mock.Mock(); process.poll.return_value = None
        def engine(*arguments, capture=False):
            calls.append(arguments)
            if arguments[0] == 'create':
                (self.directory / 'output/build.ready').write_text('b'*64 + '\n/nix/store/system\n/nix/store/vm\n')
                return identifier
        with mock.patch.object(driver, 'ROOT', self.source), mock.patch.object(driver.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(driver, 'engine', side_effect=engine), mock.patch.object(driver.subprocess, 'Popen', return_value=process):
            with self.assertRaisesRegex(RuntimeError, 'guest failure'):
                with self.manager() as result:
                    self.assertEqual(result['image']['sha256'], 'b'*64)
                    self.assertEqual(result['image']['kind'], 'nixos-closure')
                    (self.directory / 'output/nixos-guest.qcow2').write_bytes(b'live mutable disk')
                    raise RuntimeError('guest failure')
        self.assertIn(('stop', '--time', '10', identifier), calls)
        self.assertIn(('rm', '--force', '--volumes', identifier), calls)
        process.terminate.assert_called_once()

    def test_native_guix_image_format_and_tcg(self):
        text = driver.guix_script('arm64', self.ports, True)
        self.assertIn('--image-type=qcow2-gpt', text)
        self.assertIn('tcg,thread=multi', text)
        self.assertNotIn('-enable-kvm', text)
        self.assertIn('hostfwd=tcp:127.0.0.1:22022-:22', text)

    def test_nix_builder_has_merged_ca_and_explicit_ports(self):
        text = driver.nix_script('x86_64-linux', 'https://httpjet-qualification.local:25443/releases', self.ports, True, True)
        self.assertIn('GIT_SSL_CAINFO=/tmp/httpjet-builder-ca.pem', text)
        self.assertIn('--arg httpPort 22080', text)
        self.assertIn('--arg previousManifest /inputs/previous-manifest.json', text)
        self.assertIn('hash path --type sha256 --base16', text)


if __name__ == '__main__': unittest.main()
