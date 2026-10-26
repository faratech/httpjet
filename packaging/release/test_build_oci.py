#!/usr/bin/env python3
"""Reject mismatched native inputs before an OCI engine can be invoked."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('httpjet_build_oci', Path(__file__).with_name('build-oci.py'))
producer = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(producer)


class NativeInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-oci-input-test-')
        self.addCleanup(self.temporary.cleanup); self.root = Path(self.temporary.name)
        (self.root / 'input').write_bytes(b'attested native input')
        self.data = {'schema': 2, 'architecture': 'amd64', 'libc': 'musl',
            'target': 'x86_64-unknown-linux-musl', 'release_id': '0.1.10-1',
            'artifacts': {'input': {'sha256': hashlib.sha256(b'attested native input').hexdigest(), 'size': 21}}}
        self.save()

    def save(self): (self.root / 'provenance-amd64.json').write_text(json.dumps(self.data))

    def test_native_hash_bound_inputs_are_accepted(self):
        _, value = producer.verified_native(self.root, 'amd64')
        self.assertEqual(value['release_id'], '0.1.10-1')

    def test_changed_native_bytes_are_rejected(self):
        (self.root / 'input').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'changed before OCI'):
            producer.verified_native(self.root, 'amd64')

    def test_wrong_linkage_or_target_is_rejected(self):
        for field, value in (('libc', 'gnu'), ('target', 'x86_64-unknown-linux-gnu')):
            with self.subTest(field=field):
                original = self.data[field]; self.data[field] = value; self.save()
                with self.assertRaises(ValueError): producer.verified_native(self.root, 'amd64')
                self.data[field] = original

    def test_floating_base_is_rejected_before_docker(self):
        with mock.patch.object(producer.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(producer, 'docker') as engine:
            with self.assertRaisesRegex(ValueError, 'immutable official Alpine'):
                producer.build(self.root, 'amd64', 'alpine:latest', None)
            engine.assert_not_called()


if __name__ == '__main__': unittest.main()
