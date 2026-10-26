#!/usr/bin/env python3
"""Public-byte checks use fixtures; they do not publish or qualify releases."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('httpjet_check_public', Path(__file__).with_name('check-public.py'))
check_public = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_public)


class Response(io.BytesIO):
    def __init__(self, url, body):
        super().__init__(body)
        self.url = url


class PublicChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-public-check-')
        self.addCleanup(self.temporary.cleanup)
        self.snapshot = Path(self.temporary.name)
        (self.snapshot / 'apt').mkdir()
        (self.snapshot / 'publication.json').write_text(json.dumps({'release_id': '0.0.1-1'}))
        self.payloads = {}
        for url, path in check_public.objects(self.snapshot):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('UNIT ONLY: ' + path.relative_to(self.snapshot).as_posix()).encode())
            self.payloads[url] = path.read_bytes()

    def response(self, request, timeout):
        self.assertEqual(timeout, 30)
        return Response(request.full_url, self.payloads[request.full_url])

    def test_optional_website_skip_keeps_package_and_release_checks(self):
        with patch.object(check_public.urllib.request, 'urlopen', side_effect=self.response) as opened:
            check_public.verify(self.snapshot, website_redirect=False)
        visited = {call.args[0].full_url for call in opened.call_args_list}
        self.assertNotIn('https://httpjet.net/install.sh', visited)
        self.assertIn('https://httpjet-packages.pages.dev/apt/install.sh', visited)
        self.assertIn('https://httpjet-packages.pages.dev/releases/stable.json.asc', visited)
        self.assertIn('https://httpjet-packages.pages.dev/rpm/aarch64/repodata/repomd.xml.asc', visited)
        self.assertIn('https://httpjet-packages.pages.dev/releases/0.0.1-1/qualification.json.asc', visited)

    def test_default_still_checks_website_redirect(self):
        with patch.object(check_public.urllib.request, 'urlopen', side_effect=self.response) as opened:
            check_public.verify(self.snapshot)
        self.assertIn('https://httpjet.net/install.sh', {call.args[0].full_url for call in opened.call_args_list})

    def test_changed_public_bytes_fail_even_without_website(self):
        self.payloads['https://httpjet-packages.pages.dev/releases/stable.json'] = b'tampered fixture'
        with patch.object(check_public.urllib.request, 'urlopen', side_effect=self.response):
            with self.assertRaisesRegex(ValueError, 'public bytes differ'):
                check_public.verify(self.snapshot, website_redirect=False)

    def test_redirect_to_insecure_transport_fails(self):
        with patch.object(check_public.urllib.request, 'urlopen', return_value=Response('http://example.invalid/', b'')):
            with self.assertRaisesRegex(ValueError, 'left HTTPS'):
                check_public.verify(self.snapshot, website_redirect=False)


if __name__ == '__main__':
    unittest.main()
