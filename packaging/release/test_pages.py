#!/usr/bin/env python3
"""Projection/retention tests; synthetic bytes never qualify a real release."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

import pages
import release


class PagesProjection(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-pages-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.source = self.work / 'snapshot'; self.source.mkdir()
        self.key = self.work / 'public.asc'; self.key.write_text('UNIT PUBLIC KEY')
        self.fingerprint = 'A' * 40
        self.info = {'release_id': '1.2.3-1', 'previous_stable_sha256': None}
        self.write('apt/install.sh', b'UNIT INSTALLER')
        self.write('apt/pool/main/h/httpjet/httpjet_1.2.3-1_amd64.deb', b'UNIT DEB')
        self.write('apt/dists/stable/InRelease', b'UNIT SIGNED INDEX')
        self.write('rpm/x86_64/Packages/httpjet-1.2.3-1.x86_64.rpm', b'UNIT RPM')
        self.write('rpm/x86_64/repodata/repomd.xml', b'UNIT RPM INDEX')
        self.write('releases/1.2.3-1/manifest.json', b'UNIT MANIFEST')
        self.write('releases/1.2.3-1/httpjet-source.tar.xz', b'UNIT LARGE SOURCE')
        self.write('releases/stable.json', json.dumps({'release_id': '1.2.3-1'}).encode())
        self.write('releases/stable.json.asc', b'UNIT SIGNATURE')
        self.info['stable_sha256'] = release.sha(self.source / 'releases/stable.json')
        patcher = mock.patch.object(pages.snapshot, 'verify', return_value=self.info)
        patcher.start(); self.addCleanup(patcher.stop)
        signing = mock.patch.object(pages.universal, 'sign', side_effect=lambda path, key: Path(str(path)+'.asc').write_bytes(b'UNIT INDEX SIGNATURE'))
        signing.start(); self.addCleanup(signing.stop)

    def write(self, name, data):
        path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        return path

    def project(self, **kwargs):
        with mock.patch.object(pages, 'precondition'):
            return pages.project(self.source, self.work / 'site', self.key, self.fingerprint, **kwargs)

    def previous(self):
        base = self.work / 'previous'; base.mkdir()
        pointer = base / 'current-stable.json'; pointer.write_text('{"release_id":"1.2.2-1"}')
        data = b'OLD IMMUTABLE BYHASH'
        name = 'apt/dists/stable/main/binary-amd64/by-hash/SHA256/' + 'f' * 64
        path = base / 'pages-retention' / name; path.parent.mkdir(parents=True); path.write_bytes(data)
        old = {'release_id': '1.2.2-1', 'repository': 'faratech/httpjet', 'stable_sha256': release.sha(pointer),
               'objects': {name: pages.descriptor(path)}, 'releases': {'1.2.2-1': {'tag': 'v1.2.2', 'assets': {}}}}
        self.info['previous_stable_sha256'] = old['stable_sha256']
        return base, old, name

    def test_projection_keeps_native_bytes_redirects_large_assets_and_has_true404_file(self):
        # Source/OCI objects exceed the actual Pages limit and remain on GitHub.
        with (self.source / 'releases/1.2.3-1/httpjet-source.tar.xz').open('wb') as stream:
            stream.truncate(pages.MAX_FILE + 1)
        self.project()
        site = self.work / 'site'
        self.assertFalse((site / 'releases/1.2.3-1').exists())
        self.assertEqual((site / 'apt/pool/main/h/httpjet/httpjet_1.2.3-1_amd64.deb').read_bytes(), b'UNIT DEB')
        self.assertEqual((site / '_redirects').read_text(), '/releases/1.2.3-1/* https://github.com/faratech/httpjet/releases/download/v1.2.3/:splat 302\n')
        self.assertIn('no-store', (site / '_headers').read_text())
        self.assertTrue((site / '404.html').is_file())
        index = release.load(site / pages.INDEX)
        self.assertEqual(index['stable_sha256'], self.info['stable_sha256'])
        item = index['releases']['1.2.3-1']['assets']['httpjet-source.tar.xz']
        self.assertEqual(item, pages.descriptor(self.source / 'releases/1.2.3-1/httpjet-source.tar.xz'))

    def test_old_immutable_files_and_redirects_survive_without_ci_artifact_retention(self):
        previous, old, name = self.previous()
        with mock.patch.object(pages, 'read_index', return_value=old):
            result = self.project(previous=previous)
        self.assertEqual((self.work / 'site' / name).read_bytes(), b'OLD IMMUTABLE BYHASH')
        self.assertEqual(result['releases']['1.2.2-1']['tag'], 'v1.2.2')

    def test_over_limit_redirect_history_fails_before_output_creation(self):
        previous, old, _ = self.previous()
        old['releases'] = {f'0.0.{n}-1': {'tag': f'v0.0.{n}', 'assets': {}} for n in range(100)}
        with mock.patch.object(pages, 'read_index', return_value=old), self.assertRaisesRegex(ValueError, '100 dynamic'):
            self.project(previous=previous)
        self.assertFalse((self.work / 'site').exists())

    def test_changed_or_missing_retention_fails_closed(self):
        previous, old, name = self.previous()
        (previous / 'pages-retention' / name).write_bytes(b'tampered')
        with mock.patch.object(pages, 'read_index', return_value=old), self.assertRaisesRegex(ValueError, 'retained Pages file changed'):
            self.project(previous=previous)

    def test_oversized_native_file_is_rejected_instead_of_omitted(self):
        with mock.patch.object(pages, 'MAX_FILE', 5), self.assertRaisesRegex(ValueError, 'file descriptor'):
            self.project()

    def test_precondition_only_treats_exact_pointer404_as_initial_absence(self):
        url = pages.ORIGIN + '/releases/stable.json'
        for code, address in ((403, url), (500, url), (404, pages.ORIGIN + '/other')):
            with self.subTest(code=code, address=address):
                error = urllib.error.HTTPError(address, code, 'fixture', {}, None)
                with mock.patch.object(release, 'download', side_effect=error), self.assertRaises(urllib.error.HTTPError):
                    pages.precondition(self.info, self.key, self.fingerprint)
                error.close()
        error = urllib.error.HTTPError(url, 404, 'fixture', {}, None)
        with mock.patch.object(release, 'download', side_effect=error):
            pages.precondition(self.info, self.key, self.fingerprint)
            with self.assertRaises(urllib.error.HTTPError):
                pages.precondition({**self.info, 'previous_stable_sha256': 'f' * 64}, self.key, self.fingerprint)
        error.close()

    def test_precondition_rejects_stable_changed_since_staging(self):
        def download(url, path): path.write_bytes(b'new stable')
        with mock.patch.object(release, 'download', side_effect=download):
            with self.assertRaisesRegex(ValueError, 'stable changed'):
                pages.precondition({**self.info, 'previous_stable_sha256': 'f' * 64}, self.key, self.fingerprint)

    def test_retention_rejects_unsafe_paths_and_mutable_objects(self):
        for name in ('../private', '/etc/passwd', 'apt/../../private', '_httpjet/state', 'apt/install.sh', 'rpm/x86_64/repodata/repomd.xml'):
            with self.subTest(name=name), self.assertRaises(ValueError): pages.relative(name, True)


if __name__ == '__main__': unittest.main()
