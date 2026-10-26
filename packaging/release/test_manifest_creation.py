#!/usr/bin/env python3
"""Manifest assembly regressions; fixture bytes never qualify an executable."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import payload
import release
import support
import universal

class ManifestCreation(unittest.TestCase):
    def test_image_lock_branch_preserves_policy_descriptor(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-manifest-unit-') as temporary:
            directory=Path(temporary);ident=support.identity('1.2.3-1');fingerprint='A'*40
            binary=b'NON EXECUTABLE UNIT FIXTURE';digest=payload.sha_bytes(binary)
            base='docker.io/library/alpine@sha256:'+'f'*64
            signatures={}
            for arch,machine in [('amd64','x86_64'),('arm64','aarch64')]:
                names={f'httpjet-1.2.3-1-linux-{arch}-static.tar.gz':('portable',arch,'musl'),
                       f'httpjet_1.2.3-1_{arch}.deb':('deb',arch,'musl'),
                       f'httpjet-1.2.3-1.{machine}.rpm':('rpm',arch,'musl'),
                       'httpjet-archive-keyring_1.2.3-1_all.deb':('keyring-deb','all','none'),
                       'httpjet-archive-keyring-1.2.3-1.noarch.rpm':('keyring-rpm','all','none'),
                       f'httpjet-1.2.3-1-linux-{arch}-oci.tar':('oci-image',arch,'musl')}
                artifacts={}
                for name,(kind,architecture,libc) in names.items():
                    path=directory/name;path.write_bytes(binary)
                    artifacts[name]={'kind':kind,'architecture':architecture,'libc':libc,'sha256':digest,'size':len(binary)}
                    if kind in ('rpm','keyring-rpm'):signatures[name]={'sha256':digest}
                build={**ident,'architecture':arch,'commit':'0'*40,'source_date_epoch':0,'archive_fingerprint':fingerprint,
                       'rustc_version':'1.99.1','compatibility_flags':['--no-multishot-accept'],
                       'target':{'amd64':'x86_64-unknown-linux-musl','arm64':'aarch64-unknown-linux-musl'}[arch],
                       'binary_sha256':digest,'artifacts':artifacts,'oci_images':{arch:{
                           'artifact':f'httpjet-1.2.3-1-linux-{arch}-oci.tar','image_id':'sha256:'+'b'*64,'base_image':base}}}
                release.write_json(directory/f'provenance-{arch}.json',build)
            release.write_json(directory/'carrier-signatures.json',signatures)
            release.write_json(directory/'qualification-images.json',{'schema':1,'release_id':ident['release_id'],
                'matrix_sha256':support.digest(support.POLICY),'rows':{row['id']:{} for row in support.rows()},
                'oci_bases':{arch:{'image':base} for arch in support.ARCHES}})
            def query(arguments):
                if arguments[0]=='dpkg-deb':
                    arch=Path(arguments[2]).stem.rsplit('_',1)[1]
                    return f'Package: httpjet\nVersion: 1.2.3-1\nArchitecture: {arch}\n'
                if arguments[0]=='rpm':return 'httpjet\n1.2.3\n1\n'+Path(arguments[-1]).stem.rsplit('.',1)[1]+'\n'
                raise AssertionError(arguments)
            with patch.object(release,'run',side_effect=query),patch.object(release,'validate_elf'), \
                 patch.object(payload,'tar_binary',return_value=binary),patch.object(payload,'verify_carrier_binary'), \
                 patch.object(payload,'oci_binary',return_value={'image_id':'sha256:'+'b'*64,'binary':binary}), \
                 patch.object(universal,'verify_rpm_signatures'):
                universal.create_manifest(directory,directory/'manifest.json')
            result=release.load(directory/'manifest.json')
            self.assertEqual(result['support_matrix'],support.policy_descriptor(directory/'support-matrix.json'))
            self.assertEqual(set(result['oci_images']),set(support.ARCHES))
            self.assertEqual(support.bound_policy(directory,result)['id'],support.load_policy()['id'])


class RpmTrust(unittest.TestCase):
    def test_rpm_4_and_6_signatures_and_failure_reports(self):
        reports = (
            'Header V4 EdDSA/SHA256 Signature, key ID eec8f743: OK\n',
            'Header OpenPGP V4 EdDSA/SHA256 signature, key fingerprint: '
            'b8666bafb71468a1f88f68afab7a6274eec8f743: OK\n'
            'Header SHA256 digest: OK\nPayload SHA256 digest: OK\n',
        )
        for report in reports:
            with self.subTest(report=report):self.assertTrue(universal.rpm_signature_verified(report))
        for report in ('Header SHA256 digest: OK\n',
                       'Header OpenPGP signature, key fingerprint: abc: NOKEY\n',
                       'Header OpenPGP signature: NOT OK\n',
                       'Header OpenPGP signature: BAD\nHeader SHA256 digest: OK\n',
                       'Header OpenPGP signature: OK\nPayload digest: NOT OK\n'):
            with self.subTest(report=report):self.assertFalse(universal.rpm_signature_verified(report))

    def test_signature_checks_use_scoped_keyring_and_reject_unsigned(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-rpm-trust-unit-') as temporary:
            directory=Path(temporary);ident=support.identity('1.2.3-1')
            manifest={**ident,'archive_fingerprint':'A'*40,'artifacts':{
                'httpjet-archive-keyring_1.2.3-1_all.deb':{'kind':'keyring-deb'},
                'httpjet-1.2.3-1.x86_64.rpm':{'kind':'rpm'},
                'httpjet-1.2.3-1.aarch64.rpm':{'kind':'rpm'},
                'httpjet-archive-keyring-1.2.3-1.noarch.rpm':{'kind':'keyring-rpm'}}}
            def query(arguments):
                if arguments[:2]==['dpkg-deb','--extract']:
                    key=Path(arguments[-1])/'usr/share/keyrings/httpjet-archive-keyring.asc';key.parent.mkdir(parents=True);key.write_text('UNIT PUBLIC KEY')
                if arguments[0]=='rpmkeys' and '--checksig' in arguments:return '    Header V4 RSA/SHA512 Signature, key ID aaaaaaaa: OK\n'
                return ''
            with patch.object(release,'run',side_effect=query) as calls,patch.object(release,'validate_key') as key:
                universal.verify_rpm_signatures(directory,manifest)
                key.assert_called_once();self.assertEqual(key.call_args.args[1],manifest['archive_fingerprint'])
                for call in calls.call_args_list:
                    if call.args[0][0]=='rpmkeys':self.assertIn('--dbpath',call.args[0])
            for report in ('digests OK\n','Header V4 RSA/SHA512 Signature, key ID aaaaaaaa: NOKEY\n','Header V4 RSA/SHA512 Signature: NOT OK\n'):
                def invalid(arguments):
                    result=query(arguments)
                    return report if arguments[0]=='rpmkeys' and '--checksig' in arguments else result
                with patch.object(release,'run',side_effect=invalid),patch.object(release,'validate_key'),self.assertRaisesRegex(ValueError,'signature'):
                    universal.verify_rpm_signatures(directory,manifest)

if __name__=='__main__':unittest.main()
