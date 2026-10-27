#!/usr/bin/env python3
"""Generic dependency checks accept modern gpg2 without requiring legacy gpg."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

class GnuPGPrerequisite(unittest.TestCase):
    def test_gpg2_only_and_modern_gpg_only_are_accepted_without_dependency_install(self):
        source=Path(__file__).with_name('install.sh.in').read_text()
        body=source.split('generic_prerequisites() {',1)[1].split('\n}\n',1)[0]
        for gpg in ('gpg2','gpg'):
            with self.subTest(gpg=gpg),tempfile.TemporaryDirectory(prefix='httpjet-gpg-prerequisite-') as temporary:
                directory=Path(temporary)
                for name in ('curl','python3','setpriv',gpg):
                    tool=directory/name;tool.write_text('#!/bin/sh\nprintf "%s\\n" --ambient-caps\n');tool.chmod(0o755)
                (directory/'grep').symlink_to(shutil.which('grep'))
                script='fail() { printf "%s\\n" "$*" >&2; exit 1; }\nrequire_command() { command -v "$1" >/dev/null || fail "$1"; }\ngeneric_prerequisites() {'+body+'\n}\ngeneric_prerequisites\n'
                result=subprocess.run(['/bin/sh','-s'],input=script,text=True,capture_output=True,env={'PATH':str(directory)})
                self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
