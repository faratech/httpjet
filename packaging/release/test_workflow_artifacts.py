#!/usr/bin/env python3
"""Ensure lifecycle receipts cannot accidentally download large OS inputs."""
from pathlib import Path
import re
import unittest
import support

WORKFLOW = Path(__file__).resolve().parents[2]/'.github/workflows/installer-release.yml'


class WorkflowArtifactContracts(unittest.TestCase):
    def test_prepared_media_are_separate_and_only_requested_by_matching_rows(self):
        text = WORKFLOW.read_text()
        prepared = {row['id'] for row in support.rows()
                    if row['source'].get('recipe') in ('devuan-sysv', 'slackware-sysv')}
        self.assertEqual(prepared, {'devuan-stable-amd64', 'slackware-15.0-amd64'})
        for row in prepared:
            self.assertIn('name: qualification-rootfs-' + row, text)
            self.assertIn('path: image-inputs/qualification-rootfs-' + row + '.tar.gz', text)
            self.assertIn("matrix.row_id == '" + row + "'", text)
        self.assertIn('!candidate/qualification-rootfs-*.tar.gz', text)
        self.assertIn('name: qualification-rootfs-${{ matrix.row_id }}', text)

    def test_receipt_download_cannot_match_image_artifacts(self):
        text = WORKFLOW.read_text()
        self.assertIn('name: receipt-${{ matrix.row_id }}', text)
        self.assertIn('pattern: receipt-*', text)
        self.assertNotRegex(text, r'pattern:\s*qualification-\*')
        self.assertRegex(text, r'name:\s*qualification-images\s+path:\s*image-inputs/qualification-images\.json')


if __name__ == '__main__':
    unittest.main()
