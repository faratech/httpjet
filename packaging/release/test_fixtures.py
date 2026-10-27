#!/usr/bin/env python3
"""Manifest epoch and architecture envelopes for private lifecycle fixtures."""
import os
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import fixtures
import release

EPOCH=1790000000

class FixtureEpoch(unittest.TestCase):
    def test_manifest_overrides_ambient_without_changing_caller(self):
        with mock.patch.dict(os.environ,{'SOURCE_DATE_EPOCH':'invalid ambient'}):
            self.assertEqual(fixtures.build_environment({'source_date_epoch':EPOCH})['SOURCE_DATE_EPOCH'],str(EPOCH))
            self.assertEqual(os.environ['SOURCE_DATE_EPOCH'],'invalid ambient')

    def test_invalid_epoch_fails_before_any_native_tool(self):
        for value in (None,True,False,'1790000000',1.5,-1,2**32):
            with self.subTest(value=value),mock.patch.object(fixtures,'run') as tool:
                with self.assertRaisesRegex(ValueError,'source_date_epoch'):
                    fixtures.native_fixture(Path('/unused'),{'source_date_epoch':value},'amd64',Path('/unused'),Path('/unused'),'UNIT')
                tool.assert_not_called()

    def test_build_commands_use_manifest_epoch_and_architecture(self):
        class Observed(Exception):pass
        for arch,machine in (('amd64','x86_64'),('arm64','aarch64')):
            with self.subTest(arch=arch),tempfile.TemporaryDirectory(prefix='httpjet-fixture-epoch-') as temporary:
                root=Path(temporary);key=root/'key';key.write_text('UNIT PUBLIC KEY')
                manifest={'source_date_epoch':EPOCH,'release_id':'0.1.10-6','upstream_version':'0.1.10','revision':6,
                    'packages':{arch:'unused.deb'},'rpm_packages':{arch:'unused.rpm'},'binaries':{arch:{'binary_sha256':'0'*64}}}
                def execute(args,**options):
                    if args[:2]==['dpkg-deb','-R']:
                        control=Path(args[-1])/'DEBIAN/control';control.parent.mkdir(parents=True);control.write_text('Version: 0.1.10-6\n')
                    if args[:2]==['dpkg-deb','--build']:
                        self.assertEqual(options['env']['SOURCE_DATE_EPOCH'],str(EPOCH));Path(args[-1]).write_bytes(b'UNIT DEB')
                    if args[0]=='rpmbuild':
                        self.assertEqual(options['env']['SOURCE_DATE_EPOCH'],str(EPOCH))
                        self.assertEqual(args[args.index('--target')+1],machine);raise Observed()
                with mock.patch.dict(os.environ,{'SOURCE_DATE_EPOCH':'invalid ambient'}), \
                    mock.patch.object(fixtures,'run',side_effect=execute), \
                    mock.patch.object(fixtures.payload,'verify_carrier_binary'),self.assertRaises(Observed):
                    fixtures.native_fixture(root,manifest,arch,root,key,'UNIT')

TOOLS=('dpkg-deb','rpmbuild','rpmsign','bsdtar','rpm2cpio','rpmkeys','rpm','gpg')
@unittest.skipUnless(all(shutil.which(tool) for tool in TOOLS),'real regression needs RPM/DEB/archive/GPG tools')
class RealNativeFixture(unittest.TestCase):
    def input_packages(self,work,arch,machine,key,environment):
        root=Path(__file__).resolve().parents[2];directory=work/arch;directory.mkdir()
        binary=('INERT '+arch+' UNIT FIXTURE; NEVER EXECUTE\n').encode()
        tree=directory/'deb';control=tree/'DEBIAN/control';control.parent.mkdir(parents=True)
        control.parent.chmod(0o755)
        control.write_text('Package: httpjet\nVersion: 0.1.10-6\nArchitecture: '+arch+'\nMaintainer: UNIT ONLY <unit@example.invalid>\nDescription: Inert private fixture regression\n')
        control.chmod(0o644)
        server=tree/'usr/bin/httpjet';server.parent.mkdir(parents=True);server.write_bytes(binary);server.chmod(0o755)
        deb=directory/'input.deb';release.run(['dpkg-deb','--build','--root-owner-group',tree,deb],env=environment)
        top=directory/'rpm'
        for name in ('SOURCES','BUILD','BUILDROOT','RPMS','SRPMS','SPECS'):(top/name).mkdir(parents=True)
        package=directory/'httpjet-0.1.10-6-payload';package.mkdir();shutil.copytree(tree/'usr',package/'usr')
        shutil.copytree(root/'packaging/debian/conf',package/'etc/httpjet/conf')
        shutil.copytree(root/'packaging/debian/welcome',package/'usr/share/httpjet/welcome')
        assets={'debian/httpjet.service':'usr/lib/systemd/system/httpjet.service',
            'packaging/rpm/package-helper.sh':'usr/libexec/httpjet/package-helper',
            'packaging/rpm/README.md':'usr/share/doc/httpjet/README.md',
            'THIRD_PARTY_NOTICES.md':'usr/share/doc/httpjet/THIRD_PARTY_NOTICES.md','LICENSE':'usr/share/licenses/httpjet/LICENSE'}
        for source,target in assets.items():
            destination=package/target;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/source,destination)
        with tarfile.open(top/'SOURCES/httpjet-0.1.10-6-payload.tar.gz','w:gz') as archive:archive.add(package,arcname=package.name)
        shutil.copyfile(key,top/'SOURCES/archive-keyring.asc');shutil.copyfile(root/'packaging/rpm/preinstall.sh',top/'SOURCES/preinstall.sh')
        release.run(['rpmbuild','-bb','--target',machine,'--define','_topdir '+str(top),
            '--define','httpjet_version 0.1.10','--define','httpjet_revision 6',root/'packaging/rpm/httpjet.spec'],env=environment)
        rpm=directory/'input.rpm';shutil.copyfile(top/'RPMS'/machine/f'httpjet-0.1.10-6.{machine}.rpm',rpm)
        manifest={'source_date_epoch':EPOCH,'release_id':'0.1.10-6','upstream_version':'0.1.10','revision':6,
            'packages':{arch:deb.name},'rpm_packages':{arch:rpm.name},'binaries':{arch:{'binary_sha256':hashlib.sha256(binary).hexdigest()}}}
        return directory,manifest

    def test_real_both_arch_fixture_packages_build_sign_and_keep_manifest_epoch(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-real-fixture-') as temporary:
            work=Path(temporary);home=work/'gnupg';home.mkdir(mode=0o700)
            with mock.patch.dict(os.environ,{'GNUPGHOME':str(home)}):
                try:
                    release.run(['gpg','--batch','--pinentry-mode','loopback','--passphrase','',
                        '--quick-generate-key','Fixture UNIT ONLY <unit@example.invalid>','rsa2048','sign','1d'])
                    key=work/'public.asc';key.write_text(release.run(['gpg','--armor','--export']))
                    fingerprint=release.key_fingerprint(key)
                    database=work/'rpmdb';database.mkdir()
                    release.run(['rpm','--dbpath',database,'--initdb']);release.run(['rpmkeys','--dbpath',database,'--import',key])
                    for arch,machine in (('amd64','x86_64'),('arm64','aarch64')):
                        environment={**os.environ,'SOURCE_DATE_EPOCH':str(EPOCH)}
                        directory,manifest=self.input_packages(work,arch,machine,key,environment)
                        output=directory/'baseline';output.mkdir()
                        with mock.patch.dict(os.environ,{'SOURCE_DATE_EPOCH':'invalid ambient'}):
                            if arch=='amd64':os.environ.pop('SOURCE_DATE_EPOCH')
                            result=fixtures.native_fixture(directory,manifest,arch,output,key,fingerprint)
                        self.assertEqual(result['release_id'],'0.1.10-5')
                        self.assertEqual(release.run(['dpkg-deb','-f',output/result['deb'],'Version','Architecture']),
                            'Version: 0.1.10-5\nArchitecture: '+arch+'\n')
                        self.assertEqual(release.run(['rpm','-qp','--qf','%{VERSION}-%{RELEASE}\n%{ARCH}\n%{BUILDTIME}\n',output/result['rpm']]),
                            '0.1.10-5\n'+machine+'\n'+str(EPOCH)+'\n')
                        verified=release.run(['rpmkeys','--dbpath',database,'--checksig','--verbose',output/result['rpm']])
                        self.assertTrue(fixtures.universal.rpm_signature_verified(verified))
                finally:subprocess.run(['gpgconf','--kill','all'],capture_output=True)

if __name__=='__main__':unittest.main()
