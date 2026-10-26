#!/usr/bin/env python3
"""Synthetic qualification fixtures only; never VM release evidence."""
import shutil
import unittest
from unittest.mock import patch
import release
import publish
import test_repository_contract as contracts

class QualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        contracts.RepositoryContract.setUpClass()
        cls.addClassCleanup(contracts.RepositoryContract.doClassCleanups)
    def setUp(self):
        self.fixture=contracts.RepositoryContract(methodName='runTest');self.fixture.setUp()
        self.directory=self.fixture.artifacts;self.manifest=release.load(self.directory/'manifest.json')
    def receipts(self):
        directory=self.fixture.work/'receipts';directory.mkdir()
        for distro in release.DISTROS:
            for arch in release.ARCHES:
                stem=distro+'-'+arch;log=directory/(stem+'.log');log.write_text('UNIT FIXTURE ONLY: no VM ran\n')
                release.write_json(directory/(stem+'.json'),{
                    'schema':1,'distro':distro,'architecture':arch,'status':'passed','runner':'qemu-tcg',
                    'manifest_sha256':release.sha(self.directory/'manifest.json'),
                    'package_sha256':release.sha(self.directory/self.manifest['packages'][arch]),
                    'checks':{c:'passed' for c in release.CHECKS},'image_sha512':'0'*128,
                    'baseline_kind':'first-release-fixture','log':log.name,'log_sha256':release.sha(log)})
        return directory
    def stable(self):
        release.qualify(self.directory,self.receipts(),self.directory/'qualification.json')
        return release.stage(self.directory,self.fixture.work/'stable',self.fixture.public_key,
                             self.fixture.fingerprint,contracts.ROOT/'packaging/installer/install.sh.in')
    def test_all_receipts_bound_and_stable_verifies(self):
        snapshot=self.stable();publication=publish.verify_snapshot(snapshot,self.fixture.public_key,self.fixture.fingerprint)
        self.assertTrue(publication['qualified'])
        (self.directory/'debian12-amd64.log').write_text('tampered\n')
        with self.assertRaises(ValueError):release.verify_qualification(self.directory)
    def test_byhash_tampering_rejected(self):
        snapshot=self.stable();blob=next(snapshot.glob('dists/stable/main/binary-*/by-hash/SHA256/*'))
        blob.write_text('tampered')
        with self.assertRaises(ValueError):publish.verify_snapshot(snapshot,self.fixture.public_key,self.fixture.fingerprint)
    def test_missing_vm_pair_rejected(self):
        receipts=self.receipts();(receipts/'ubuntu26.04-arm64.json').unlink()
        with self.assertRaises(FileNotFoundError):release.qualify(self.directory,receipts,self.directory/'qualification.json')
    def test_weekly_refresh_preserves_installer_and_version(self):
        snapshot=self.stable();approved=self.fixture.work/'approved'
        def download(url,destination):
            relative=url.removeprefix(release.REPO_URL+'/');shutil.copyfile(snapshot/relative,destination)
        with patch.object(release,'download',side_effect=download):
            release.fetch_current(release.REPO_URL,approved,self.fixture.public_key,self.fixture.fingerprint)
        refreshed=release.stage(approved,self.fixture.work/'refreshed',self.fixture.public_key,self.fixture.fingerprint,
                                self.fixture.work/'NONEXISTENT-template',previous=approved)
        self.assertEqual((snapshot/'install.sh').read_bytes(),(refreshed/'install.sh').read_bytes())
        self.assertEqual(release.load(refreshed/'publication.json')['manifest_sha256'],release.sha(self.directory/'manifest.json'))
        publish.verify_snapshot(refreshed,self.fixture.public_key,self.fixture.fingerprint)

if __name__=='__main__':unittest.main()
