#!/usr/bin/env python3
"""Keep prepared OS media out of the artifacts used for public release."""
from pathlib import Path
import re
import unittest

import support

WORKFLOWS = Path(__file__).resolve().parents[2]/'.github/workflows'


def artifact_steps(text, action):
    steps = re.split(r'^      - |^  (?=[a-z])', text, flags=re.M)
    return [step for step in steps
            if re.search(rf'^(?:        )?uses: actions/{action}-artifact@', step, re.M)]


class WorkflowArtifactContracts(unittest.TestCase):
    def test_prepared_media_are_separate_from_the_signed_candidate(self):
        text = (WORKFLOWS/'installer-release.yml').read_text()
        uploads = artifact_steps(text, 'upload')
        prepared = {row['id'] for row in support.rows()
                    if row['source'].get('recipe') in ('devuan-sysv', 'slackware-sysv')}
        self.assertEqual(prepared, {'devuan-stable-amd64', 'slackware-15.0-amd64'})
        for row in prepared:
            name = 'qualification-rootfs-' + row
            steps = [step for step in uploads if 'name: ' + name + '\n' in step]
            self.assertEqual(len(steps), 1)
            self.assertIn(f'path: image-inputs/{name}.tar.gz', steps[0])
        image_steps = [step for step in uploads if 'name: qualification-images\n' in step]
        self.assertEqual(len(image_steps), 1)
        self.assertIn('path: image-inputs/qualification-images.json', image_steps[0])
        candidate = [step for step in uploads if 'name: signed-candidate\n' in step]
        self.assertEqual(len(candidate), 1)
        self.assertIn('            candidate/\n            !candidate/qualification-rootfs-*.tar.gz\n',
                      candidate[0])

    def test_build_only_publisher_downloads_only_the_named_signed_candidate(self):
        text = (WORKFLOWS/'installer-publish-now.yml').read_text()
        steps = artifact_steps(text, 'download')
        self.assertEqual(len(steps), 1)
        self.assertIn('name: signed-candidate\n', steps[0])
        self.assertIn('path: candidate-input\n', steps[0])
        self.assertIn('run-id: ${{ inputs.candidate_run_id || github.event.workflow_run.id }}', steps[0])
        self.assertNotRegex(steps[0], r'\bpattern:')


if __name__ == '__main__':
    unittest.main()
