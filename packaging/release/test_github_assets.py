#!/usr/bin/env python3
"""Qualified asset selection and GitHub publication contracts; no live writes."""
import contextlib,copy,hashlib,http.server,io,os,re,ssl,subprocess,tempfile,threading,unittest,urllib.parse,urllib.request
from datetime import timedelta
from pathlib import Path
from unittest import mock
import github_assets as gh
import release,support
import pages as hosting
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
    def __init__(self,value):self.manifest=value;self.releases=[];self.assets=[];self.calls=[];self.bodies=[];self.tag_sha=value['commit'];self.next_id=17
    def json(self,method,path,body=None):
        self.calls.append((method,path))
        if body is not None:self.bodies.append((method,path,copy.deepcopy(body)))
        if '/git/ref/tags/' in path:return {'object':{'type':'commit','sha':self.tag_sha}}
        if path.endswith('/releases?per_page=100&page=1'):return copy.deepcopy(self.releases)
        if '/assets?per_page=100&page=' in path:
            page=int(urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['page'][0])
            return copy.deepcopy(self.assets[(page-1)*100:page*100])
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
    def add_proof(self):
        entries={}
        for name in ('unit-row.json','unit-row.log','unit-row-service.json'):
            path=self.directory/name;path.write_text('UNIT-ONLY qualification evidence '+name)
            entries[name]={'sha256':release.sha(path),'size':path.stat().st_size}
        qualification=release.load(self.directory/'qualification.json')
        qualification['targets']=[{'receipt':'unit-row.json','sha256':entries['unit-row.json']['sha256'],
            'log':'unit-row.log','log_sha256':entries['unit-row.log']['sha256'],
            'evidence':{'unit-row-service.json':{**entries['unit-row-service.json'],'role':'service'}}}]
        release.write_json(self.directory/'qualification.json',qualification)
        return qualification,set(entries)
    def test_qualified_selection_attests_publishes_and_verifies_flat_proof_files(self):
        _,proof=self.add_proof()
        with mock.patch.object(gh.universal,'verify_artifacts'),mock.patch.object(gh.universal,'verify_qualification'):
            names=gh.prepare_qualified(self.directory,self.root/'subjects')
        self.assertTrue(proof.issubset(names))
        self.assertTrue(all('/' not in name for name in names))
        client=FakeGithub(self.value)
        gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertTrue(proof.issubset({asset['name'] for asset in client.assets}))
        self.assertNotIn('private-os-image.tar.gz',names)
    def test_proof_tampering_collisions_and_private_archives_reject_before_write(self):
        qualification,_=self.add_proof()
        for case in ('tamper','reserved','private','unsafe'):
            with self.subTest(case=case):
                changed=copy.deepcopy(qualification)
                if case=='tamper':changed['targets'][0]['sha256']='0'*64
                elif case=='reserved':changed['targets'][0]['receipt']='manifest.json'
                elif case=='private':changed['targets'][0]['receipt']='private-os-image.tar.gz'
                else:changed['targets'][0]['receipt']='../outside'
                release.write_json(self.directory/'qualification.json',changed)
                client=FakeGithub(self.value)
                with self.assertRaises(ValueError):
                    gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
                self.assertFalse(any(method in ('POST','PATCH') for method,_ in client.calls))
        release.write_json(self.directory/'qualification.json',qualification)
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
        self.assertEqual(client.releases[0]['make_latest'],'false')
        self.assertTrue(all(body.get('make_latest')=='false' for _,_,body in client.bodies))
        self.assertEqual({a['name'] for a in client.assets},{p.name for p in self.directory.iterdir()})
        uploads=sum(method=='POST' and '/assets?' in path for method,path in client.calls)
        gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertEqual(sum(method=='POST' and '/assets?' in path for method,path in client.calls),uploads)
    def test_latest_is_separate_and_never_uploads_or_creates_assets(self):
        client=FakeGithub(self.value)
        gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        prior=len(client.calls)
        url=gh.promote_latest(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertTrue(url.endswith('/v1.2.3'))
        self.assertEqual(client.releases[0]['make_latest'],'true')
        self.assertEqual(client.bodies[-1][2],{'make_latest':'true'})
        self.assertFalse(any(method=='POST' for method,_ in client.calls[prior:]))
        uploads=len(client.assets)
        gh.promote_latest(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertEqual(len(client.assets),uploads)
    def test_latest_refuses_missing_draft_incomplete_or_altered_publication(self):
        cases=('missing','draft','missing-asset','changed-asset','changed-marker','changed-tag')
        for case in cases:
            with self.subTest(case=case):
                client=FakeGithub(self.value)
                gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
                if case=='missing':client.releases.clear()
                elif case=='draft':client.releases[0]['draft']=True
                elif case=='missing-asset':client.assets.pop()
                elif case=='changed-asset':client.assets[0]['digest']='sha256:'+'0'*64
                elif case=='changed-marker':client.releases[0]['body']='unrelated'
                else:client.tag_sha='0'*40
                prior=len(client.calls)
                with self.assertRaises(ValueError):
                    gh.promote_latest(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
                self.assertFalse(any(method in ('POST','PATCH') for method,_ in client.calls[prior:]))
    def test_latest_rechecks_tag_after_asset_verification(self):
        client=FakeGithub(self.value)
        gh.publish(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        prior=len(client.calls)
        with mock.patch.object(gh,'tag_commit',side_effect=['a'*40,'b'*40]):
            with self.assertRaisesRegex(ValueError,'tag changed before latest'):
                gh.promote_latest(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,client)
        self.assertFalse(any(method in ('POST','PATCH') for method,_ in client.calls[prior:]))
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
            gh.verify_public(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,Opener(),require_latest=True)
        self.assertEqual(len(requests),len(list(self.directory.iterdir()))+1)
        self.assertTrue(requests[-1].endswith('/releases/latest/download/install.sh'))
    def test_tag_verification_does_not_require_latest_before_pages_activation(self):
        requests=[]
        class Response(io.BytesIO):
            url='https://release-assets.githubusercontent.com/unit-only'
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def open(inner,request,timeout):
                requests.append(request.full_url)
                name=urllib.parse.unquote(urllib.parse.urlsplit(request.full_url).path.rsplit('/',1)[1])
                return Response((self.directory/name).read_bytes())
        with contextlib.redirect_stdout(io.StringIO()):
            gh.verify_public(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,Opener())
        self.assertEqual(len(requests),len(list(self.directory.iterdir())))
        self.assertFalse(any('/latest/' in url for url in requests))
    def test_latest_redirect_retries_old_bytes_but_tag_tampering_does_not_retry(self):
        class Response(io.BytesIO):
            url='https://release-assets.githubusercontent.com/unit-only'
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            latest_calls=0
            bad_tag=False
            def open(inner,request,timeout):
                url=request.full_url
                name=urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit('/',1)[1])
                if '/latest/' in url:
                    inner.latest_calls+=1
                    if inner.latest_calls==1:return Response(b'previous installer')
                elif inner.bad_tag:return Response(b'tampered tag asset')
                return Response((self.directory/name).read_bytes())
        opener=Opener()
        with contextlib.redirect_stdout(io.StringIO()),mock.patch.object(gh.time,'sleep') as sleep:
            gh.verify_public(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,opener,require_latest=True)
            sleep.assert_called_once_with(5)
        self.assertEqual(opener.latest_calls,2)
        opener=Opener();opener.bad_tag=True
        with mock.patch.object(gh.time,'sleep') as sleep:
            with self.assertRaisesRegex(ValueError,'qualified'):
                gh.verify_public(self.directory,self.value,'faratech/httpjet','refs/tags/v1.2.3','a'*40,opener,require_latest=True)
            sleep.assert_not_called()
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


class PublicationWorkflow(unittest.TestCase):
    """Execute the actual workflow shell gates against local non-network shims."""
    ROOT=Path(__file__).resolve().parents[2]
    NAMES={'Verify promotion attestations and publish the non-latest release',
           'Verify public tagged GitHub release downloads',
           'Project the complete signed Pages snapshot',
           'Deploy, verify and promote while holding the publisher lease'}
    PHASES=['github-publish','tag-check','pages-project','leased-deploy']

    def workflow(self,name):return (self.ROOT/'.github/workflows'/name).read_text()

    def selected_runs(self):
        result=[]
        for name,body in re.findall(r'^      - name: ([^\n]+)\n(.*?)(?=^      - |\Z)',self.workflow('installer-publish.yml'),re.M|re.S):
            if name not in self.NAMES:continue
            self.assertNotIn('        if:',body)
            lines=body.splitlines()
            for number,line in enumerate(lines):
                if line.startswith('        run: '):
                    command=line.removeprefix('        run: ')
                    result.append('\n'.join(value[10:] for value in lines[number+1:]) if command=='|' else command)
                    break
        self.assertEqual(len(result),len(self.NAMES))
        return result

    def execute(self,failure=''):
        with tempfile.TemporaryDirectory(prefix='httpjet-workflow-order-unit-') as temporary:
            root=Path(temporary);binary=root/'bin';binary.mkdir();trace=root/'trace'
            for name in ('github-release-assets','github-promotion-assets'):
                (root/name).mkdir();(root/name/'install.sh').write_text('unit fixture, never published\n')
            shim='''#!/bin/sh
set -eu
case "${0##*/}" in gh) exit 0 ;; esac
case "$*" in
*'github_assets.py publish '*) phase=github-publish ;;
*'github_assets.py verify-public '*) phase=tag-check ;;
*'pages.py project '*) phase=pages-project ;;
*'pages.py deploy '*) phase=leased-deploy ;;
*) exit 91 ;;
esac
printf '%s\\n' "$phase" >> "$HTTPJET_TEST_TRACE"
if [ "${HTTPJET_TEST_FAIL:-}" = "$phase" ]; then exit 23; fi
'''
            for name in ('python3','gh'):
                path=binary/name;path.write_text(shim);path.chmod(0o700)
            environment={'PATH':str(binary)+os.pathsep+os.defpath,
                'HTTPJET_TEST_TRACE':str(trace),'HTTPJET_TEST_FAIL':failure,
                'GITHUB_REPOSITORY':'faratech/httpjet','GITHUB_SHA':'a'*40,'GITHUB_REF':'refs/tags/v1.2.3',
                'ARCHIVE_FINGERPRINT':'A'*40,'CLOUDFLARE_API_TOKEN':'unit-only','CLOUDFLARE_ACCOUNT_ID':'f'*32}
            script='set -euo pipefail\n'+'\n'.join(self.selected_runs())
            result=subprocess.run(['/bin/bash','-c',script],cwd=root,env=environment,capture_output=True,text=True,timeout=10)
            return result,trace.read_text().splitlines() if trace.exists() else []

    def test_real_shell_steps_verify_tagged_assets_before_leased_publication(self):
        result,trace=self.execute();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(trace,self.PHASES)

    def test_any_failed_gate_stops_remaining_publication_steps(self):
        for failure in self.PHASES:
            with self.subTest(failure=failure):
                result,trace=self.execute(failure)
                self.assertEqual(result.returncode,23,result.stderr)
                self.assertEqual(trace,self.PHASES[:self.PHASES.index(failure)+1])

    def test_source_and_promotion_attestations_remain_before_publication(self):
        text=self.workflow('installer-publish.yml')
        markers=['verify-run.py','validate_tag_context','Stage signed stable snapshot',
                 'Verify build-workflow attestations','Attest the rendered bootstrap',
                 'Verify promotion attestations','github_assets.py publish ']
        positions=[text.index(marker) for marker in markers]
        self.assertEqual(positions,sorted(positions))
        self.assertIn('environment: httpjet-stable',text)
        self.assertIn('attestations: write',text)
        self.assertIn('--github-assets github-release-assets',text)
        self.assertNotIn('github_assets.py latest ',text)
        self.assertIn('release.REPO_URL.removesuffix',text)
        qualification=self.workflow('installer-release.yml')
        self.assertLess(qualification.index('github_assets.py qualified'),qualification.index('Attest final signed software'))
        self.assertIn('subject-path: github-qualified-assets/*',qualification)

    def test_refresh_retains_current_and_uses_same_protected_private_lease(self):
        promotion=self.workflow('installer-publish.yml');refresh=self.workflow('installer-refresh.yml')
        self.assertIn('fetch-current --universal',refresh)
        self.assertIn('--directory approved --previous approved',refresh)
        self.assertIn('--previous approved --repository',refresh)
        self.assertNotIn('github_assets.py',refresh);self.assertNotIn('--github-assets',refresh)
        self.assertNotIn('contents: write',refresh)
        self.assertEqual(re.search(r'^  group: (.+)$',promotion,re.M).group(1),re.search(r'^  group: (.+)$',refresh,re.M).group(1))
        for text in (promotion,refresh):
            self.assertIn('environment: httpjet-stable',text)
            self.assertIn('pages.py deploy --snapshot snapshot --directory pages-site',text)
            self.assertNotIn('publish.py snapshot',text)
            self.assertIn('CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}',text)
            self.assertIn('CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}',text)
            self.assertIn('HTTPJET_S3_BUCKET:',text)


class SignedSnapshotRoundTrip(unittest.TestCase):
    def test_retry_after_pages_commit_preserves_assets_and_verifies_redirected_qualification(self):
        fixture=repository_fixture.UniversalRepository
        fixture.setUpClass();case=fixture('test_signed_schema2_snapshot_and_publication_order')
        server=None;thread=None;selection=None
        try:
            case.setUp();staged=case.stage()
            assets=case.work/'github-assets'
            names=sorted(set(case.manifest['artifacts'])|{'manifest.json','qualification.json','SHA256SUMS'})
            selection=mock.patch.object(gh,'software_names',return_value=names);selection.start()
            gh.prepare_snapshot(staged,case.key,case.fingerprint,assets,case.work/'generated')
            projected=case.work/'pages-site'
            with mock.patch.object(hosting,'precondition'):
                hosting.project(staged,projected,case.key,case.fingerprint)
            site_root=[projected]
            certificate=case.work/'test-only-cert.pem';private_key=case.work/'test-only-key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-days','1',
                '-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1',
                '-keyout',str(private_key),'-out',str(certificate)],check=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            redirected=[]
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self,*_arguments):pass
                def do_GET(self):
                    path=urllib.parse.urlsplit(self.path).path
                    base='/releases/'+case.manifest['release_id']+'/'
                    if path.startswith(base):
                        name=release.filename(urllib.parse.unquote(path.removeprefix(base)))
                        redirected.append(name)
                        self.send_response(302)
                        self.send_header('Location','/github-assets/'+urllib.parse.quote(name,safe=''))
                        self.end_headers();return
                    if path.startswith('/github-assets/'):
                        target=assets/release.filename(urllib.parse.unquote(path.removeprefix('/github-assets/')))
                    else:
                        if '..' in Path(path).parts:self.send_error(404);return
                        target=site_root[0]/path.removeprefix('/')
                    if not target.is_file():self.send_error(404);return
                    content=target.read_bytes();self.send_response(200)
                    self.send_header('Content-Length',str(len(content)));self.end_headers();self.wfile.write(content)
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            server_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.load_cert_chain(certificate,private_key)
            server.socket=server_tls.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            origin='https://127.0.0.1:'+str(server.server_port)
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(certificate))))
            clients=[]
            class FailLatestOnce(FakeGithub):
                failing=True
                applied=False
                def json(inner,method,path,body=None):
                    if method=='PATCH' and body=={'make_latest':'true'} and inner.failing:
                        inner.failing=False
                        if inner.applied:super().json(method,path,body)
                        raise OSError('UNIT ONLY: lost latest-promotion acknowledgement')
                    return super().json(method,path,body)
            ref='refs/tags/'+case.manifest['tag'];commit=case.manifest['commit']
            for applied in (False,True):
                client=FailLatestOnce(case.manifest);client.applied=applied
                gh.publish(assets,case.manifest,'faratech/httpjet',ref,commit,client)
                with self.assertRaises(OSError):
                    gh.promote_latest(assets,case.manifest,'faratech/httpjet',ref,commit,client)
                clients.append(client)
            # Native-history adapters are outside this proof-publication test.
            # The real downloader, HTTP redirects, GPG and full matrix verifier run.
            with mock.patch.object(gh.universal,'signed_apt_history'),mock.patch.object(gh.universal,'signed_rpm_history'), \
                    mock.patch('urllib.request.urlopen',side_effect=opener.open), \
                    mock.patch.object(release,'REPO_URL',origin+'/apt'):
                current=gh.universal.fetch_current(origin+'/apt',case.work/'fetched',case.key,case.fingerprint)
            gh.universal.verify_qualification(current)
            required=set()
            for target in release.load(current/'qualification.json')['targets']:
                required.update((target['receipt'],target['log']));required.update(target['evidence'])
            self.assertTrue(required.issubset(redirected))
            self.assertTrue(required.issubset({path.name for path in assets.iterdir()}))
            self.assertNotIn('private-os-image.tar.gz',redirected)
            # A retry follows explicit recovery of the retained private publisher
            # lease. It must reuse every immutable GitHub byte despite new metadata.
            retry=case.work/'retry-snapshot'
            issued=support.utc_timestamp(release.load(projected/'releases/stable.json')['issued_at'])
            gh.universal.stage(case.directory,retry,case.key,case.fingerprint,
                repository_fixture.ROOT/'packaging/installer/install.sh.in',previous=current,now=issued+timedelta(minutes=1))
            retry_assets=case.work/'retry-assets'
            gh.prepare_snapshot(retry,case.key,case.fingerprint,retry_assets,case.work/'retry-generated')
            self.assertEqual(gh.expected_assets(assets),gh.expected_assets(retry_assets))
            self.assertEqual(release.load(retry/'publication.json')['previous_stable_sha256'],release.sha(current/'current-stable.json'))
            retry_site=case.work/'retry-pages'
            check_previous=hosting.precondition
            with mock.patch('urllib.request.urlopen',side_effect=opener.open), \
                    mock.patch.object(hosting,'precondition',side_effect=lambda info,key,fingerprint:check_previous(info,key,fingerprint,base=origin)):
                hosting.project(retry,retry_site,case.key,case.fingerprint,previous=current)
                site_root[0]=retry_site
                self.assertEqual(hosting.verify(retry_site,case.key,case.fingerprint,base=origin)['status'],'passed')
            for client in clients:
                prior=len(client.calls)
                gh.publish(retry_assets,case.manifest,'faratech/httpjet',ref,commit,client)
                self.assertFalse(any(method in ('POST','PATCH') for method,_ in client.calls[prior:]))
                if client.applied:self.assertEqual(client.releases[0]['make_latest'],'true')
                gh.promote_latest(retry_assets,case.manifest,'faratech/httpjet',ref,commit,client)
                self.assertEqual(client.releases[0]['make_latest'],'true')
        finally:
            if server:server.shutdown();server.server_close()
            if thread:thread.join(timeout=5)
            if selection:selection.stop()
            case.doCleanups();fixture.doClassCleanups()

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
