#!/usr/bin/env python3
"""Test independent native carriers and the single shared RPM keyring."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('httpjet_carriers', Path(__file__).with_name('package-carriers.py'))
carriers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(carriers)


class RpmCarrierSelection(unittest.TestCase):
    def test_only_amd64_emits_the_shared_noarch_keyring(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-rpm-carriers-') as temporary:
            root = Path(temporary)
            outputs = {}
            for arch, machine in (('amd64','x86_64'), ('arm64','aarch64')):
                top=root/arch/'top';out=root/arch/'out';out.mkdir(parents=True)
                for directory in (top/'RPMS'/machine, top/'RPMS/noarch'):directory.mkdir(parents=True)
                package=f'httpjet-1.2.3-4.{machine}.rpm'
                keyring='httpjet-archive-keyring-1.2.3-4.noarch.rpm'
                (top/'RPMS'/machine/package).write_bytes(('server-'+arch).encode())
                (top/'RPMS/noarch'/keyring).write_bytes(('keyring-'+arch).encode())
                result=carriers.copy_rpm_carriers(top,out,arch,'1.2.3-4')
                self.assertEqual(result[0],package)
                self.assertEqual((out/package).read_bytes(),('server-'+arch).encode())
                outputs[arch]=(out,result)
            self.assertEqual(outputs['amd64'][1][1],keyring)
            self.assertEqual((outputs['amd64'][0]/keyring).read_bytes(),b'keyring-amd64')
            self.assertIsNone(outputs['arm64'][1][1])
            self.assertFalse((outputs['arm64'][0]/keyring).exists())


if __name__ == '__main__':
    unittest.main()
