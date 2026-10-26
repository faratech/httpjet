#!/usr/bin/env python3
"""Fail-closed source-trainer tests; full build/gate is separately exercised."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
HELPER=ROOT/'packaging/release/bootstrap-trainer.sh'

class TrainerTests(unittest.TestCase):
    def test_bad_source_checksum_stops_before_extraction_and_compile(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-trainer-unit-') as temporary:
            work=Path(temporary);tools=work/'fake-bin';tools.mkdir();output=work/'trainer'
            curl=tools/'curl';curl.write_text('''#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then shift; destination=$1; fi
  shift
done
printf 'not-the-upstream-source' > "$destination"
''');curl.chmod(0o755)
            for tool in ('tar','make'):
                wrapper=tools/tool;wrapper.write_text('#!/bin/sh\nprintf called > "'+str(work/tool)+'"\nexit 99\n');wrapper.chmod(0o755)
            result=subprocess.run(['bash',str(HELPER),str(output)],env={**os.environ,'PATH':str(tools)+':'+os.environ['PATH']},capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('checksum mismatch',result.stderr)
            self.assertEqual((output/'source.tar.gz').read_text(),'not-the-upstream-source')
            self.assertFalse((work/'tar').exists());self.assertFalse((work/'make').exists())
    def test_existing_output_is_never_reused(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-trainer-unit-') as temporary:
            result=subprocess.run(['bash',str(HELPER),temporary],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('must not already exist',result.stderr)

if __name__=='__main__':unittest.main()
