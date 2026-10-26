#!/usr/bin/env python3
"""Exercise source/session/carrier binding independently of compiler fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('httpjet_build_session', Path(__file__).with_name('build-session.py'))
payload = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(payload)


class CarrierBinding(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-payload-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'; self.source.mkdir()
        (self.source / 'Cargo.toml').write_text('[workspace.package]\nversion="0.1.10"\n')
        (self.source / 'debian').mkdir()
        self.session = self.root / 'session'
        self.binary = self.root / 'compiled-binary'; self.binary.write_bytes(b'source-built payload fixture')
        self.destination = self.root / 'carrier/httpjet'

    def prepare(self, session=None):
        session = session or self.session
        with mock.patch.object(payload, 'command', return_value='0.1.10-1\n'):
            payload.create_session(self.source, session, 'a'*40, 'v0.1.10', 'amd64', '0.1.10-1', '1')
        with mock.patch.object(payload, 'static_elf'), mock.patch.object(payload, 'command', return_value='httpjet 0.1.10\n'):
            payload.seal(session, self.binary)
        return session

    def consume(self, arch='amd64', release_id='0.1.10-1', receipt=None):
        with mock.patch.object(payload, 'static_elf'):
            return payload.consume(self.session, receipt or self.session / 'payload.json', self.source,
                                   arch, release_id, self.destination)

    def test_same_run_source_bound_payload_is_copied_unchanged(self):
        self.prepare(); self.consume()
        self.assertEqual(self.destination.read_bytes(), self.binary.read_bytes())

    def test_source_edit_after_compilation_is_rejected(self):
        self.prepare(); (self.source / 'changed.rs').write_text('different source')
        with self.assertRaisesRegex(ValueError, 'source differs'): self.consume()

    def test_binary_replacement_is_rejected(self):
        self.prepare(); (self.session / 'httpjet').write_bytes(b'not the compiled payload')
        with self.assertRaisesRegex(ValueError, 'binary differs'): self.consume()

    def test_receipt_edit_is_rejected(self):
        self.prepare(); path = self.session / 'payload.json'
        value = json.loads(path.read_text()); value['commit'] = 'b'*40; path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'authentication'): self.consume()

    def test_wrong_release_and_architecture_are_rejected(self):
        self.prepare()
        for arguments in ({'arch': 'arm64'}, {'release_id': '0.1.10-2'}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError): self.consume(**arguments)

    def test_receipt_from_another_run_is_rejected(self):
        self.prepare(); other = self.prepare(self.root / 'other-session')
        with self.assertRaisesRegex(ValueError, 'active source-build session'):
            self.consume(receipt=other / 'payload.json')

    def test_generated_staging_is_ignored_but_registry_inputs_are_bound(self):
        before = payload.source_digest(self.source)
        (self.source / 'debian/build').mkdir(); (self.source / 'debian/build/httpjet').write_text('staging')
        (self.source / 'debian/autoreconf.before').write_text('generated')
        self.assertEqual(payload.source_digest(self.source), before)
        path = self.source / 'vendor/registry/input.orig'; path.parent.mkdir(parents=True); path.write_text('upstream source')
        self.assertNotEqual(payload.source_digest(self.source), before)

    def test_dynamic_binary_is_not_accepted_as_a_static_payload(self):
        with self.assertRaisesRegex(ValueError, 'PT_INTERP|architecture'): payload.static_elf('/usr/bin/true', 'amd64')

    def test_compile_owns_the_bound_source_build_instead_of_accepting_an_input_binary(self):
        with mock.patch.object(payload, 'command', return_value='0.1.10-1\n'):
            payload.create_session(self.source, self.session, 'a'*40, 'v0.1.10', 'amd64', '0.1.10-1', '1')
        def compiler(arguments, check):
            self.assertEqual(arguments[:3], ['bash', str(self.source / 'packaging/release/build-musl.sh'), 'amd64'])
            Path(arguments[3]).write_bytes(self.binary.read_bytes())
        with mock.patch.object(payload.subprocess, 'run', side_effect=compiler), \
             mock.patch.object(payload, 'static_elf'), \
             mock.patch.object(payload, 'command', return_value='httpjet 0.1.10\n'):
            payload.compile_payload(self.session)
        self.consume()
        self.assertEqual(self.destination.read_bytes(), self.binary.read_bytes())
        self.assertFalse((self.session / 'compiled-source').exists())


if __name__ == '__main__':
    unittest.main()
