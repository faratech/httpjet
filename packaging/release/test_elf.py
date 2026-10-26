#!/usr/bin/env python3
"""Static release-validator tests; no release or VM qualification is implied."""
import unittest
from unittest.mock import patch
import release

class ELFTests(unittest.TestCase):
    def check(self, arch='amd64', version='2.36', libraries='libc.so.6', notes=''):
        machine='Advanced Micro Devices X86-64' if arch=='amd64' else 'AArch64'
        result=['Machine: '+machine+'\n','Name: GLIBC_'+version+'\n',f'(NEEDED) Shared library: [{libraries}]\n',notes]
        with patch.object(release,'run',side_effect=result):
            return release.validate_elf('fixture',arch)
    def test_baseline_and_arm(self):
        self.assertEqual(self.check()['glibc_max'],'2.36')
        self.assertEqual(self.check(arch='arm64')['cpu_baseline'],'armv8-a')
    def test_future_glibc(self):
        with self.assertRaises(ValueError):self.check(version='2.38')
    def test_unexpected_dependency(self):
        with self.assertRaises(ValueError):self.check(libraries='libssl.so.3')
    def test_x86_isa(self):
        with self.assertRaises(ValueError):self.check(notes='x86 ISA needed: x86-64-v3')
    def test_wrong_architecture(self):
        with patch.object(release,'run',return_value='Machine: AArch64\n'):
            with self.assertRaises(ValueError):release.validate_elf('fixture','amd64')


class StaticELFTests(unittest.TestCase):
    def fixture(self,program='LOAD 0x0',dynamic='There is no dynamic section',versions='No version information found'):
        return patch.object(release,'run',side_effect=['Machine: Advanced Micro Devices X86-64\n',versions,dynamic,program,'x86 ISA needed: x86-64-baseline'])
    def test_static_pie_needs_no_glibc_floor(self):
        with self.fixture():result=release.validate_elf('unit-fixture','amd64','musl')
        self.assertEqual(result['linkage'],'static');self.assertIsNone(result['glibc_max'])
    def test_interpreter_is_forbidden(self):
        with self.fixture(program='  INTERP 0x1200'):
            with self.assertRaisesRegex(ValueError,'PT_INTERP'):release.validate_elf('unit-fixture','amd64','musl')
    def test_shared_dependency_is_forbidden(self):
        with self.fixture(dynamic='(NEEDED) Shared library: [libc.so.6]'):
            with self.assertRaisesRegex(ValueError,'DT_NEEDED'):release.validate_elf('unit-fixture','amd64','musl')
    def test_glibc_versions_are_forbidden(self):
        with self.fixture(versions='Name: GLIBC_2.17'):
            with self.assertRaisesRegex(ValueError,'GLIBC'):release.validate_elf('unit-fixture','amd64','musl')

if __name__=='__main__':unittest.main()
