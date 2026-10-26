#!/usr/bin/env python3
"""Exercise source timestamps using real annotated and lightweight Git tags."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('source-date-epoch.sh')


class SourceDateEpoch(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-source-date-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Unit Test')
        self.git('config', 'user.email', 'unit@example.invalid')
        (self.root/'fixture').write_text('unit-only source\n')
        self.git('add', 'fixture')
        self.git('commit', '-qm', 'source')
        self.expected = self.git('show', '-s', '--format=%ct', 'HEAD').stdout.strip()

    def git(self, *arguments):
        return subprocess.run(['git', '-C', str(self.root), *arguments],
                              text=True, capture_output=True, check=True)

    def test_annotated_tag_resolves_only_to_commit_time(self):
        self.git('tag', '-a', 'v1.2.3-2', '-m', 'multi-line release tag\nmetadata must not enter the timestamp')
        raw = self.git('show', '-s', '--format=%ct', 'v1.2.3-2').stdout
        self.assertIn('multi-line release tag', raw)  # the reproduced failure shape
        result = subprocess.run(['sh', str(SCRIPT), 'v1.2.3-2'], cwd=self.root,
                                text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout.strip(), self.expected)
        self.assertRegex(result.stdout.strip(), r'^\d+$')

    def test_lightweight_tag_and_missing_tag(self):
        self.git('tag', 'v1.2.3')
        result = subprocess.run(['sh', str(SCRIPT), 'v1.2.3'], cwd=self.root,
                                text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout.strip(), self.expected)
        result = subprocess.run(['sh', str(SCRIPT), 'v9.9.9'], cwd=self.root,
                                text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
