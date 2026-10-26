#!/usr/bin/env python3
"""Schema-2 signing/staging contracts with non-executable, unit-only payloads.

The RPM metadata producer and carrier-signature verifier are fixtures; GPG,
APT, tar/OCI inspection and the cross-document verifiers run for real. These
fabricated receipts never prove OS, executable, RPM or release qualification.
"""
from datetime import datetime, timedelta, timezone
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import payload
import release
import snapshot
import support
import universal

ROOT = Path(__file__).resolve().parents[2]


def archive_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, value, mode in entries:
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(value), mode
            archive.addfile(member, io.BytesIO(value))
    return stream.getvalue()


class UniversalRepository(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('gpg', 'gpgv', 'dpkg-deb', 'apt-ftparchive'):
            if not shutil.which(tool): raise unittest.SkipTest('requires '+tool)
        cls.temporary = tempfile.TemporaryDirectory(prefix='httpjet-v2-signing-unit-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        cls.home = cls.base/'gnupg'; cls.home.mkdir(mode=0o700)
        cls.environment = patch.dict(os.environ, {'GNUPGHOME': str(cls.home)})
        cls.environment.start(); cls.addClassCleanup(cls.environment.stop)
        cls.addClassCleanup(lambda: subprocess.run(['gpgconf', '--kill', 'all'], capture_output=True))
        release.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                     '--quick-generate-key', 'httpjet v2 UNIT ONLY <unit@example.invalid>',
                     'ed25519', 'sign', '1d'])
        cls.key = cls.base/'unit-public.asc'
        cls.key.write_text(release.run(['gpg', '--armor', '--export']))
        cls.fingerprint = release.key_fingerprint(cls.key)

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='case-', dir=self.base))
        self.directory = self.work/'artifacts'; self.directory.mkdir()
        self.ident = support.identity('0.0.1-1')
        self.manifest = {'schema': 2, **self.ident, 'commit': '0'*40, 'source_date_epoch': 0,
                         'archive_fingerprint': self.fingerprint, 'runtime': support.load_policy()['runtime'],
                         'binaries': {}, 'packages': {}, 'rpm_packages': {}, 'oci_images': {}, 'artifacts': {}}
        self.make_artifacts()
        self.make_qualification()
        self.rpm_patch = patch.object(universal, 'rpm_repository', side_effect=self.rpm_metadata_fixture)
        self.rpm_patch.start(); self.addCleanup(self.rpm_patch.stop)
        self.rpm_signatures = patch.object(universal, 'verify_rpm_signatures')
        self.rpm_signatures.start(); self.addCleanup(self.rpm_signatures.stop)

    def artifact(self, name, data, kind, architecture='all', libc='none'):
        path = self.directory/name; path.write_bytes(data)
        self.manifest['artifacts'][name] = {'kind': kind, 'architecture': architecture, 'libc': libc,
                                          'sha256': release.sha(path), 'size': len(data)}
        return path

    def deb(self, architecture, name='httpjet'):
        tree = self.work/('deb-'+name+'-'+architecture)
        (tree/'DEBIAN').mkdir(parents=True)
        (tree/'DEBIAN/control').write_text(
            'Package: '+name+'\nVersion: 0.0.1-1\nArchitecture: '+architecture+'\n'
            'Maintainer: Unit Only <unit@example.invalid>\nDescription: non-executable unit fixture\n')
        (tree/'usr/share/unit-only').mkdir(parents=True)
        (tree/'usr/share/unit-only/NOTICE').write_text('NOT A RELEASE\n')
        path = self.work/(name+'_0.0.1-1_'+architecture+'.deb')
        release.run(['dpkg-deb', '--build', '--root-owner-group', tree, path])
        return self.artifact(path.name, path.read_bytes(), 'deb' if name=='httpjet' else 'keyring-deb',
                             architecture, 'musl' if name=='httpjet' else 'none').name

    def make_artifacts(self):
        self.deb('all', 'httpjet-archive-keyring')
        for arch in support.ARCHES:
            binary = ('NON-EXECUTABLE '+arch+' UNIT FIXTURE\n').encode()
            name = 'httpjet-0.0.1-1-linux-'+arch+'-static.tar.gz'
            self.artifact(name, gzip.compress(archive_bytes([
                ('httpjet-0.0.1-1/bin/httpjet', binary, 0o755)]), mtime=0), 'portable', arch, 'musl')
            self.manifest['binaries'][arch] = {'artifact': name, 'binary_sha256': payload.sha_bytes(binary), 'libc': 'musl'}
            self.manifest['packages'][arch] = self.deb(arch)
            rpm = 'httpjet-0.0.1-1.'+{'amd64':'x86_64','arm64':'aarch64'}[arch]+'.rpm'
            self.artifact(rpm, b'NOT AN RPM: unit metadata fixture\n', 'rpm', arch, 'musl')
            self.manifest['rpm_packages'][arch] = rpm
            layer = archive_bytes([('usr/bin/httpjet', binary, 0o755),
                                   ('usr/libexec/httpjet/io-uring-probe', b'NOT EXECUTABLE\n', 0o755)])
            diff = 'sha256:'+payload.sha_bytes(layer)
            config = json.dumps({'os':'linux', 'architecture':arch,
                'config':{'User':'10001:10001', 'Entrypoint':['/usr/bin/httpjet']},
                'rootfs':{'type':'layers', 'diff_ids':[diff]}}, sort_keys=True).encode()
            image = archive_bytes([('config.json', config, 0o644), ('layer.tar', layer, 0o644),
                ('manifest.json', json.dumps([{'Config':'config.json','Layers':['layer.tar']}]).encode(), 0o644)])
            name = 'httpjet-0.0.1-1-linux-'+arch+'-oci.tar'
            self.artifact(name, image, 'oci-image', arch, 'musl')
            base = 'docker.io/library/alpine@sha256:'+'f'*64
            self.manifest['oci_images'][arch] = {'artifact':name, 'image_id':'sha256:'+payload.sha_bytes(config),
                'base_image':base, 'base_layer_diffids':[diff], 'base_architecture':arch}
        policy = self.artifact('support-matrix.json', support.POLICY.read_bytes(), 'qualification-policy')
        self.manifest['support_matrix'] = support.policy_descriptor(policy)
        images = {'schema':1, 'release_id':self.ident['release_id'], 'matrix_sha256':release.sha(policy),
                  'rows':{row['id']:{'unit_only':'not an OS qualification'} for row in support.rows()},
                  'oci_bases':{arch:{'image':'docker.io/library/alpine@sha256:'+'f'*64} for arch in support.ARCHES}}
        self.images = images
        self.artifact('qualification-images.json', json.dumps(images).encode(), 'qualification-inputs')
        release.write_json(self.directory/'manifest.json', self.manifest)
        (self.directory/'SHA256SUMS').write_text('UNIT ONLY\n')

    def make_qualification(self):
        targets = []
        for row in support.rows():
            arch, prefix = row['architecture'], row['id']
            binary = self.manifest['binaries'][arch]
            positive = {'status':'passed','uid':10001,'global_policy_changed':False,
                        'operations':{'setup':True,'register_probe':True,'enter_nop':True}}
            negative = {'status':'expected_failure','uid':10001,'exit_code':1,'errno':1,
                        'global_policy_changed':False,'ready_file_created':False}
            runtime = {'status':'passed','uid':10001,'binary_sha256':binary['binary_sha256'],
                       'no_multishot_accept':True, 'body_size':1048576, 'body_sha256':'e'*64,
                       'protocols':{name:True for name in ('http','tls','h2','h3')},
                       'hashes':{name:'e'*64 for name in ('http','tls','h2','h3')}}
            service = {'scope':'installed-init-service','uid':10001,'binary_sha256':binary['binary_sha256'],
                       'init':row['init'],'no_multishot_accept':True}
            attachments = {}
            for suffix, value, role in [('positive.json',positive,'uring-positive'), ('negative.json',negative,'uring-negative'),
                    ('runtime.json',runtime,'runtime'), ('service.json',service,'service')]:
                path = self.directory/(prefix+'-'+suffix); release.write_json(path,value)
                attachments[path.name] = {'sha256':release.sha(path),'size':path.stat().st_size,'role':role}
            denied = self.directory/(prefix+'-denial.log'); denied.write_text('UNIT ONLY: no process was run\n')
            attachments[denied.name] = {'sha256':release.sha(denied),'size':denied.stat().st_size,'role':'uring-denial-log'}
            log = self.directory/(prefix+'.log'); log.write_text('UNIT ONLY: no operating system was qualified\n')
            lock = self.images['rows'][prefix]
            receipt = {'schema':2,'row_id':prefix,'release_id':self.ident['release_id'],'architecture':arch,
                'route':row['route'],'init':row['init'],'status':'passed','service_uid':10001,
                'manifest_sha256':release.sha(self.directory/'manifest.json'),
                'payload_sha256':self.manifest['artifacts'][binary['artifact']]['sha256'],
                'binary_sha256':binary['binary_sha256'],'checks':{name:'passed' for name in row['checks']},
                'image':{'sha256':'a'*64,'origin':'https://example.invalid/unit-only',
                    'input_sha256':payload.sha_bytes(json.dumps(lock,sort_keys=True,separators=(',',':')).encode())},
                'io_uring':{'positive':positive,'negative':negative},'kernel':{'no_multishot_accept':True},
                'log':log.name,'log_sha256':release.sha(log),'evidence':attachments}
            if row['route'] in ('oci','immutable'):
                image = self.manifest['oci_images'][arch]
                receipt.update(container_image_id=image['image_id'],
                               container_image_sha256=self.manifest['artifacts'][image['artifact']]['sha256'])
            path = self.directory/(prefix+'.json'); release.write_json(path,receipt)
            targets.append({'row_id':prefix,'receipt':path.name,'sha256':release.sha(path),
                            'log':log.name,'log_sha256':release.sha(log),'evidence':attachments})
        release.write_json(self.directory/'qualification.json', {'schema':2,'release_id':self.ident['release_id'],
            'manifest_sha256':release.sha(self.directory/'manifest.json'), 'support_matrix_sha256':self.manifest['support_matrix']['sha256'],
            'status':'passed','targets':targets})

    def rpm_metadata_fixture(self, directory, output, manifest, previous, key, expected):
        # Simulate createrepo-c output, retaining real detached-signature checks.
        for arch, machine in (('amd64','x86_64'),('arm64','aarch64')):
            root = output/'rpm'/machine; (root/'Packages').mkdir(parents=True); (root/'repodata').mkdir()
            name = manifest['rpm_packages'][arch]; package = root/'Packages'/name
            shutil.copyfile(directory/name,package)
            primary = gzip.compress(('<metadata xmlns="http://linux.duke.edu/metadata/common"><package>'
                '<checksum type="sha256">'+release.sha(package)+'</checksum><location href="Packages/'+name+'"/>'
                '</package></metadata>').encode(), mtime=0)
            (root/'repodata/primary.xml.gz').write_bytes(primary)
            document = root/'repodata/repomd.xml'
            document.write_text('<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary">'
                '<checksum type="sha256">'+payload.sha_bytes(primary)+'</checksum>'
                '<location href="repodata/primary.xml.gz"/></data></repomd>')
            universal.sign(document,expected)

    def stage(self, candidate=False):
        return universal.stage(self.directory,self.work/'snapshot',self.key,self.fingerprint,
                               ROOT/'packaging/installer/install.sh.in',candidate=candidate)

    def test_signed_schema2_snapshot_and_publication_order(self):
        staged = self.stage()
        self.assertTrue(snapshot.verify(staged,self.key,self.fingerprint)['qualified'])
        names = [path.relative_to(staged).as_posix() for path in snapshot.order(staged)]
        self.assertEqual(names[-1],'releases/stable.json')
        self.assertLess(names.index('apt/dists/stable/InRelease'),names.index('releases/stable.json.asc'))
        self.assertEqual((staged/'apt/install.sh').read_bytes(),(staged/'releases/0.0.1-1/install.sh').read_bytes())

    def test_candidate_is_refused_at_publication_boundary(self):
        with self.assertRaisesRegex(ValueError,'qualified'):
            snapshot.verify(self.stage(candidate=True),self.key,self.fingerprint)

    def test_bound_payload_tampering_is_rejected(self):
        staged = self.stage()
        artifact = self.manifest['binaries']['amd64']['artifact']
        (staged/'releases/0.0.1-1'/artifact).write_bytes(b'tampered unit fixture')
        with self.assertRaisesRegex(ValueError,'artifact descriptor/bytes'):
            snapshot.verify(staged,self.key,self.fingerprint)

    def test_signed_but_expired_pointer_is_rejected(self):
        staged = self.stage(); path = staged/'releases/stable.json'
        pointer = release.load(path); now = datetime.now(timezone.utc)
        pointer.update(issued_at=(now-timedelta(days=31)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                       expires_at=(now-timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        release.write_json(path,pointer); universal.sign(path,self.fingerprint)
        publication = release.load(staged/'publication.json'); publication['stable_sha256'] = release.sha(path)
        release.write_json(staged/'publication.json',publication)
        with self.assertRaisesRegex(ValueError,'expired'):
            snapshot.verify(staged,self.key,self.fingerprint)

    def test_missing_matrix_row_is_rejected_before_staging(self):
        path = self.directory/'qualification.json'; proof = release.load(path); proof['targets'].pop()
        release.write_json(path,proof)
        with self.assertRaisesRegex(ValueError,'every required'):
            self.stage()
        self.assertFalse((self.work/'snapshot').exists())

    def test_signed_native_index_must_bind_the_universal_manifest(self):
        staged = self.stage(); document = staged/'apt/dists/stable/Release'
        text = document.read_text().replace('X-Httpjet-Manifest-SHA256: '+release.sha(self.directory/'manifest.json'),
                                           'X-Httpjet-Manifest-SHA256: '+'0'*64)
        document.write_text(text)
        release.run(['gpg','--batch','--yes','--local-user',self.fingerprint,'--clearsign',
                     '--output',document.with_name('InRelease'),document])
        with self.assertRaisesRegex(ValueError,'native and universal'):
            snapshot.verify(staged,self.key,self.fingerprint)


if __name__ == '__main__': unittest.main()
