#!/usr/bin/env python3
"""Verify the prepared Slackware input is pinned before image construction."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('httpjet_resolve_images', Path(__file__).with_name('resolve-images.py'))
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)

SLACKWARE_URL = ('https://mirrors.slackware.com/slackware/slackware-iso/'
                 'slackware64-15.0-iso/slackware64-15.0-install-dvd.iso')
SLACKWARE_SHA256 = '4b32d575097f2238fa9dc1cd753286493a4be95a3004e9b1e81748b4f1d0c5da'


class PreparedSlackwareImage(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-image-resolver-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / 'cache'
        self.output = self.root / 'output'
        self.cache.mkdir(); self.output.mkdir()
        self.row = {'id': 'slackware-15.0-amd64', 'architecture': 'amd64',
                    'source': {'recipe': 'slackware-sysv'}}

    def test_official_input_and_pinned_digest_bind_the_prepared_artifact(self):
        prepared = b'unit-only prepared image'
        source = self.root / 'input.iso'
        source.write_bytes(b'unit-only ISO placeholder')
        def build(command, **kwargs):
            self.assertEqual(command[2], 'slackware-sysv')
            self.assertEqual(command[3], str(source))
            self.assertEqual(command[4], SLACKWARE_SHA256)
            Path(command[5]).write_bytes(prepared)
        with patch.object(resolver, 'materialize', return_value=source) as materialize, \
             patch.object(resolver.subprocess, 'run', side_effect=build), \
             patch.object(resolver, 'kernel', return_value=({'sha256':'a'*64}, {'sha256':'b'*64})):
            lock, artifacts = resolver.prepare_media(self.row, self.cache, self.output)
        requested = materialize.call_args.args[0]
        self.assertEqual(requested['url'], SLACKWARE_URL)
        self.assertEqual(requested['sha256'], SLACKWARE_SHA256)
        self.assertEqual(lock['installation_media'], requested)
        artifact = lock['rootfs']['artifact']
        self.assertEqual(lock['rootfs']['origin'], SLACKWARE_URL)
        self.assertEqual(lock['rootfs']['sha256'], hashlib.sha256(prepared).hexdigest())
        self.assertEqual(artifacts[artifact]['sha256'], lock['rootfs']['sha256'])
        self.assertEqual(artifacts[artifact]['size'], len(prepared))

    def test_bad_download_stops_before_image_construction(self):
        with patch.object(resolver, 'download', side_effect=lambda url, path: path.write_bytes(b'incorrect ISO')), \
             patch.object(resolver.subprocess, 'run') as build:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                resolver.prepare_media(self.row, self.cache, self.output)
        build.assert_not_called()


if __name__ == '__main__': unittest.main()
