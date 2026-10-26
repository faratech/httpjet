#!/usr/bin/env python3
"""Real GPG authentication of Pages retention; fixtures are not releases."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error
import pages
import release


class SignedRetention(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gpg'): raise unittest.SkipTest('requires GPG')
        cls.temporary = tempfile.TemporaryDirectory(prefix='httpjet-pages-signing-unit-')
        cls.addClassCleanup(cls.temporary.cleanup); cls.root = Path(cls.temporary.name)
        home = cls.root / 'gnupg'; home.mkdir(mode=0o700)
        patcher = mock.patch.dict(os.environ, {'GNUPGHOME': str(home)})
        patcher.start(); cls.addClassCleanup(patcher.stop)
        cls.addClassCleanup(lambda: subprocess.run(['gpgconf', '--kill', 'all'], capture_output=True))
        release.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                     'Pages UNIT ONLY <unit@example.invalid>', 'ed25519', 'sign', '1d'])
        cls.key = cls.root / 'public.asc'; cls.key.write_text(release.run(['gpg', '--armor', '--export']))
        cls.fingerprint = release.key_fingerprint(cls.key)

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(dir=self.root)); self.site = self.work / 'site'; self.site.mkdir()
        pointer = self.site / 'releases/stable.json'; pointer.parent.mkdir(); now = datetime.now(timezone.utc)
        release.write_json(pointer, {'schema': 2, 'release_id': '1.2.3-1', 'archive_fingerprint': self.fingerprint,
            'issued_at': now.strftime('%Y-%m-%dT%H:%M:%SZ'), 'expires_at': (now+timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')})
        pages.universal.sign(pointer, self.fingerprint)
        self.name = 'apt/pool/main/h/httpjet/httpjet_1.2.3-1_amd64.deb'
        native = self.site/self.name; native.parent.mkdir(parents=True); native.write_bytes(b'UNIT NATIVE CARRIER')
        for name, text in (('404.html', pages.NOT_FOUND), ('_headers', pages.HEADERS), ('_redirects', 'UNIT REDIRECT')):
            (self.site/name).write_text(text)
        self.value = {'schema': 1, 'release_id': '1.2.3-1', 'repository': 'faratech/httpjet',
            'archive_fingerprint': self.fingerprint, 'stable_sha256': release.sha(pointer),
            'releases': {'1.2.3-1': {'tag': 'v1.2.3', 'assets': {}}}, 'objects': {self.name: pages.descriptor(native)},
            'site_objects': {p.relative_to(self.site).as_posix(): pages.descriptor(p) for p in self.site.rglob('*') if p.is_file()}}
        release.write_json(self.site/pages.INDEX, self.value); pages.universal.sign(self.site/pages.INDEX, self.fingerprint)

    def download(self, url, target):
        source = self.site/url.removeprefix(pages.ORIGIN+'/')
        if not source.is_file(): raise urllib.error.HTTPError(url, 404, 'missing fixture', {}, None)
        shutil.copyfile(source, target)

    def test_real_gpg_index_rejects_changed_signed_bytes(self):
        pointer = self.site/'releases/stable.json'
        self.assertEqual(pages.read_index(self.site,self.key,self.fingerprint,pointer),self.value)
        path = self.site/pages.INDEX; path.write_text(path.read_text()+'\n')
        with self.assertRaises(subprocess.CalledProcessError): pages.read_index(self.site,self.key,self.fingerprint,pointer)

    def test_fetch_retention_authenticates_and_checks_native_bytes(self):
        for tamper in (False,True):
            output = self.work/str(tamper); output.mkdir(); pointer = output/'current-stable.json'
            shutil.copyfile(self.site/'releases/stable.json',pointer)
            if tamper: (self.site/self.name).write_bytes(b'TAMPERED')
            with mock.patch.object(release,'download',side_effect=self.download):
                if tamper:
                    with self.assertRaisesRegex(ValueError,'retained Pages object changed'):
                        pages.fetch_retention(pages.ORIGIN,output,self.key,self.fingerprint,pointer)
                else:
                    pages.fetch_retention(pages.ORIGIN,output,self.key,self.fingerprint,pointer)
                    self.assertEqual((output/'pages-retention'/self.name).read_bytes(),b'UNIT NATIVE CARRIER')

    def test_public_verifier_checks_signed_index_and_rejects_spa200(self):
        with mock.patch.object(release,'download',side_effect=self.download) as calls:
            self.assertEqual(pages.verify(self.site,self.key,self.fingerprint)['missing_status'],404)
        self.assertIn(pages.ORIGIN+'/'+pages.INDEX+'.asc',[c.args[0] for c in calls.call_args_list])
        def spa(url,target):
            if '/missing-' in url: target.write_bytes(b'fake SPA success')
            else: self.download(url,target)
        with mock.patch.object(release,'download',side_effect=spa),self.assertRaisesRegex(ValueError,'real 404'):
            pages.verify(self.site,self.key,self.fingerprint)

    def test_precondition_verifies_signed_pointer_and_completed_retry(self):
        info = {'release_id':'1.2.3-1','stable_sha256':self.value['stable_sha256'],'previous_stable_sha256':'f'*64}
        with mock.patch.object(release,'download',side_effect=self.download): pages.precondition(info,self.key,self.fingerprint)
        (self.site/'releases/stable.json.asc').write_bytes(b'BAD SIGNATURE')
        with mock.patch.object(release,'download',side_effect=self.download),self.assertRaises(subprocess.CalledProcessError):
            pages.precondition(info,self.key,self.fingerprint)


if __name__=='__main__': unittest.main()
