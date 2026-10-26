#!/usr/bin/env python3
"""Qualified asset selection and GitHub publication contracts; no live writes."""
import contextlib,copy,hashlib,io,tempfile,unittest,urllib.parse
from pathlib import Path
from unittest import mock
import github_assets as gh
import release,support
import test_universal_repository as repository_fixture

def manifest():
    value={**support.identity('1.2.3-1'),'commit':'a'*40,'artifacts':{},'binaries':{},'packages':{},'rpm_packages':{},'oci_images':{}}
    for arch,machine in (('amd64','x86_64'),('arm64','aarch64')):
        names={'portable':f'httpjet-1.2.3-1-linux-{arch}-static.tar.gz','deb':f'httpjet_1.2.3-1_{arch}.deb',
               'rpm':f'httpjet-1.2.3-1.{machine}.rpm','oci-image':f'httpjet-1.2.3-1-linux-{arch}-oci.tar'}
        for kind,name in names.items():value['artifacts'][name]={'kind':kind}
        value['binaries'][arch]={'artifact':names['portable']};value['packages'][arch]=names['deb']
        value['rpm_packages'][arch]=names['rpm'];value['oci_images'][arch]={'artifact':names['oci-image']}
    for name,kind in [('httpjet-archive-keyring_1.2.3-1_all.deb','keyring-deb'),('httpjet-archive-keyring-1.2.3-1.noarch.rpm','keyring-rpm'),
                      ('httpjet-1.2.3-1-source.tar.xz','source'),('support-matrix.json','qualification-policy'),
                      ('qualification-images.json','qualification-inputs'),('private-os-image.tar.gz','qualification-image')]:
        value['artifacts'][name]={'kind':kind}
    return value

class FakeGithub:
    def __init__(self,value):self.manifest=value;self.releases=[];self.assets=[];self.calls=[];self.tag_sha=value['commit'];self.next_id=17
    def json(self,method,path,body=None):
        self.calls.append((method,path))
        if '/git/ref/tags/' in path:return {'object':{'type':'commit','sha':self.tag_sha}}
        if path.endswith('/releases?per_page=100&page=1'):return copy.deepcopy(self.releases)
        if '/assets?per_page=100&page=1' in path:return copy.deepcopy(self.assets)
        if method=='POST' and path.endswith('/releases'):
            item={**body,'id':self.next_id,'html_url':'https://github.com/faratech/httpjet/releases/tag/'+body['tag_name']}
            self.releases.append(item);return copy.deepcopy(item)
        if path.endswith('/releases/'+str(self.next_id)) and self.releases:
            if method=='PATCH':self.releases[0].update(body)
            return copy.deepcopy(self.releases[0])
        raise AssertionError((method,path,body))
    def request(self,method,path,body=None,**kwargs):
        self.calls.append((method,path));name=urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['name'][0]
        value={'name':name,'state':'uploaded','size':len(body),'digest':'sha256:'+hashlib.sha256(body).hexdigest()}
        self.assets.append(value);return copy.deepcopy(value)

class GithubAssets(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='httpjet-github-release-unit-');self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.value=manifest();self.directory=self.root/'qualified';self.directory.mkdir()
        for name in gh.software_names(self.value):
            path=self.directory/name;path.write_bytes(('unit-only '+name).encode())
            if name in self.value['artifacts']:
                self.value['artifacts'][name].update(sha256=release.sha(path),size=path.stat().st_size)
        for name in gh.GENERATED:(self.directory/name).write_bytes(('generated '+name).encode())
        self.value['support_matrix']={'sha256':release.sha(self.directory/'support-matrix.json')}
        release.write_json(self.directory/'manifest.json',self.value)
        release.write_json(self.directory/'qualification.json',{'status':'passed','release_id':'1.2.3-1',
            'manifest_sha256':release.sha(self.directory/'manifest.json'),'support_matrix_sha256':self.value['support_matrix']['sha256']})
    def test_selects_bound_software_and_excludes_prepared_os_images(self):
        output=self.root/'subjects'
        with mock.patch.object(gh.universal,'verify_artifacts') as artifacts,mock.patch.object(gh.universal,'verify_qualification') as qualification:
            names=gh.prepare_qualified(self.directory,output)
        artifacts.assert_called_once();qualification.assert_called_once();self.assertNotIn('private-os-image.tar.gz',names)
        self.assertEqual(set(names),{p.name for p in output.iterdir()});self.assertIn('qualification.json',names)
        for name in names:self.assertEqual((output/name).read_bytes(),(self.directory/name).read_bytes())
    def test_rejects_missing_required_artifact_and_collision(self):
        value=copy.deepcopy(self.value);del value['artifacts'][value['packages']['arm64']]
        with self.assertRaisesRegex(ValueError,'omits'):gh.software_names(value)
        value=copy.deepcopy(self.value);value['artifacts']['install.sh']={'kind':'license'}
        with self.assertRaisesRegex(ValueError,'collides'):gh.software_names(value)
    def test_preparation_rejects_symlink(self):
        target=self.directory/'SHA256SUMS';target.unlink();target.symlink_to('/etc/passwd')
        with mock.patch.object(gh.universal,'verify_artifacts'),mock.patch.object(gh.universal,'verify_qualification'):
            with self.assertRaisesRegex(ValueError,'regular file'):gh.prepare_qualified(self.directory,self.root/'subjects')
    def test_context_must_identify_public_release_tag_and_commit(self):
        self.assertEqual(gh.validate_tag_context(self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40),'v1.2.3')
        for repo,ref,sha in [('faratech/httpjet-internal','refs/tags/v1.2.3','a'*40),('faratech/httpjet','refs/heads/main','a'*40),('faratech/httpjet','refs/tags/v1.2.3','b'*40)]:
            with self.subTest(repo=repo,ref=ref,sha=sha),self.assertRaises(ValueError):gh.validate_tag_context(self.value,repo,ref,sha)
    def test_packaging_revision_uses_distinct_tag(self):
        value={**self.value,**support.identity('1.2.3-2')}
        self.assertEqual(gh.validate_tag_context(value,'faratech/httpjet','refs/tags/v1.2.3-2','a'*40),'v1.2.3-2')
        with self.assertRaises(ValueError):gh.validate_tag_context(value,'faratech/httpjet','refs/tags/v1.2.3','a'*40)
        body=gh.release_body('v1.2.3-2','a'*40,'f'*64)
        self.assertIn('httpjet-1.2.3-2-linux-amd64-static.tar.gz',body)
        self.assertIn('--source-ref refs/tags/v1.2.3-2',body)
        self.assertIn('.github/workflows/installer-release.yml',body)
        self.assertIn('.github/workflows/installer-publish.yml',body)
    def test_snapshot_selection_adds_final_generated_metadata(self):
        root=self.root/'snapshot';data=root/'releases/1.2.3-1';data.mkdir(parents=True);(root/'apt').mkdir()
        for path in self.directory.iterdir():(data/path.name).write_bytes(path.read_bytes())
        for name in gh.GENERATED:
            target=root/'apt'/name if name=='httpjet-archive-keyring.asc' else data/name
            target.write_bytes(('signed fixture '+name).encode())
        with mock.patch.object(gh.contracts,'verify',return_value={'release_id':'1.2.3-1'}):gh.prepare_snapshot(root,self.root/'key','A'*40,self.root/'assets',self.root/'generated')
        self.assertEqual({p.name for p in (self.root/'generated').iterdir()},set(gh.GENERATED))
        for name in gh.GENERATED:self.assertEqual((self.root/'assets'/name).read_bytes(),(self.root/'generated'/name).read_bytes())
    def test_publish_is_draft_first_digest_checked_and_idempotent(self):
        client=FakeGithub(self.value);url=gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertTrue(url.endswith('/v1.2.3'));self.assertFalse(client.releases[0]['draft'])
        self.assertEqual({a['name'] for a in client.assets},{p.name for p in self.directory.iterdir()})
        uploads=sum(method=='POST' and '/assets?' in path for method,path in client.calls)
        gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertEqual(sum(method=='POST' and '/assets?' in path for method,path in client.calls),uploads)
    def test_retry_rejects_altered_asset_without_overwrite(self):
        client=FakeGithub(self.value);gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        client.assets[0]['digest']='sha256:'+'0'*64;prior=len(client.calls)
        with self.assertRaisesRegex(ValueError,'differs from qualified'):gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertFalse(any(method in ('POST','PATCH') for method,_ in client.calls[prior:]))
    def test_changed_tag_stops_before_any_release_write(self):
        client=FakeGithub(self.value);client.tag_sha='b'*40
        with self.assertRaisesRegex(ValueError,'tag changed'):gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertFalse(any(method in ('POST','PATCH') for method,_ in client.calls))
    def test_unrelated_existing_release_is_never_taken_over(self):
        client=FakeGithub(self.value);client.releases=[{'tag_name':'v1.2.3','body':'other release','draft':True,'id':17}]
        with self.assertRaisesRegex(ValueError,'matching qualified'):gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertFalse(any(method in ('POST','PATCH') for method,_ in client.calls))
    def test_changed_local_payload_or_missing_installer_aborts_before_release_write(self):
        for action in ('tamper','missing'):
            with self.subTest(action=action):
                client=FakeGithub(self.value)
                path=self.directory/(self.value['packages']['amd64'] if action=='tamper' else 'install.sh')
                old=path.read_bytes()
                if action=='tamper':path.write_bytes(b'tampered')
                else:path.unlink()
                try:
                    with self.assertRaisesRegex(ValueError,'asset'):gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
                    self.assertFalse(any(method in ('POST','PATCH') for method,_ in client.calls))
                finally:path.write_bytes(old)
    def test_failed_upload_retains_draft_and_retries_without_replacing_assets(self):
        class InterruptOnce(FakeGithub):
            failed=False
            def request(self,method,path,body=None,**kwargs):
                if len(self.assets)==2 and not self.failed:self.failed=True;raise OSError('unit upload interruption')
                return super().request(method,path,body,**kwargs)
        client=InterruptOnce(self.value)
        with self.assertRaises(OSError):gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertTrue(client.releases[0]['draft']);self.assertEqual(len(client.assets),2)
        gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertFalse(client.releases[0]['draft'])
        self.assertEqual(len(client.assets),len(list(self.directory.iterdir())))
    def test_public_downloads_match_qualified_bytes_including_latest_installer(self):
        requests=[]
        class Response(io.BytesIO):
            url='https://release-assets.githubusercontent.com/test-only'
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def open(inner,request,timeout):
                url=request.full_url;requests.append(url)
                name=urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit('/',1)[1])
                return Response((self.directory/name).read_bytes())
        with contextlib.redirect_stdout(io.StringIO()):
            gh.verify_public(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,Opener())
        self.assertEqual(len(requests),len(list(self.directory.iterdir()))+1)
        self.assertTrue(requests[-1].endswith('/releases/latest/download/install.sh'))
    def test_public_download_rejects_wrong_bytes_and_untrusted_redirect(self):
        class Response(io.BytesIO):
            url='https://release-assets.githubusercontent.com/test-only'
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def open(self,request,timeout):return Response(b'bad bytes')
        with self.assertRaisesRegex(ValueError,'qualified'):
            gh.public_asset(Opener(),'https://github.com/faratech/httpjet/releases/download/v1/install.sh',
                            {'size':9,'sha256':'0'*64})
        for url in ('http://github.com/foo','https://github.com.example.invalid/foo','https://example.invalid/foo'):
            with self.subTest(url=url),self.assertRaisesRegex(ValueError,'approved HTTPS'):gh.safe_download_url(url)


class SignedSnapshotRoundTrip(unittest.TestCase):
    def test_qualification_and_promotion_subjects_are_byte_identical(self):
        # Reuse the real GPG/APT unit-only fixture. The RPM repository/signature
        # adapters are fixture mocks; this never qualifies or publishes a release.
        fixture=repository_fixture.UniversalRepository
        fixture.setUpClass()
        case=fixture('test_signed_schema2_snapshot_and_publication_order')
        try:
            case.setUp();staged=case.stage()
            names=sorted(set(case.manifest['artifacts'])|{'manifest.json','qualification.json','SHA256SUMS'})
            with mock.patch.object(gh,'software_names',return_value=names):
                gh.prepare_qualified(case.directory,case.work/'qualified-assets')
                gh.prepare_snapshot(staged,case.key,case.fingerprint,case.work/'published-assets',case.work/'generated-assets')
            for name in names:
                self.assertEqual((case.work/'qualified-assets'/name).read_bytes(),(case.work/'published-assets'/name).read_bytes())
            self.assertEqual((case.work/'generated-assets/install.sh').read_bytes(),(staged/'apt/install.sh').read_bytes())
        finally:
            case.doCleanups();fixture.doClassCleanups()

if __name__=='__main__':unittest.main()
