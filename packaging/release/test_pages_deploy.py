#!/usr/bin/env python3
"""No deployment occurs: verify lease, precondition and latest ordering."""
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error
import github_assets
import pages
import publish
import publish_v2


class DeploymentLease(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-pages-deploy-unit-')
        self.addCleanup(self.temporary.cleanup); self.work=Path(self.temporary.name)
        self.source=self.work/'snapshot'; self.site=self.work/'site'; self.site.mkdir(); self.source.mkdir()
        self.key=self.work/'public.asc'; self.receipt=self.work/'receipt.json'; self.events=[]
        self.info={'release_id':'1.2.3-1','stable_sha256':'a'*64}
        @contextmanager
        def lease(store,digest):
            self.assertEqual(digest,self.info['stable_sha256']); self.events.append('lease')
            try: yield
            except BaseException: self.events.append('retained'); raise
            else: self.events.append('released')
        def execute(arguments,**kwargs):
            self.events.append('deploy' if arguments[0]=='npx' else 'redirects')
        patches=[mock.patch.object(pages.snapshot,'verify',return_value=self.info),
                 mock.patch.object(pages,'read_index',return_value=self.info),mock.patch.object(publish,'S3'),
                 mock.patch.object(publish_v2,'publication_lock',side_effect=lease),
                 mock.patch.object(pages,'precondition',side_effect=lambda *a:self.events.append('precondition')),
                 mock.patch.object(pages.subprocess,'run',side_effect=execute),
                 mock.patch.object(pages,'verify',side_effect=lambda *a:self.events.append('files') or {'status':'passed'})]
        for patcher in patches: patcher.start(); self.addCleanup(patcher.stop)

    def test_lease_covers_pointer_recheck_deploy_public_bytes_and_redirects(self):
        pages.deploy(self.source,self.site,self.key,'FPR',self.receipt)
        self.assertEqual(self.events,['lease','precondition','deploy','files','redirects','released'])
        self.assertTrue(self.receipt.is_file())

    def test_deployment_failure_retains_lease_and_never_writes_success(self):
        with mock.patch.object(pages.subprocess,'run',side_effect=RuntimeError('deploy failed')):
            with self.assertRaisesRegex(RuntimeError,'deploy failed'):
                pages.deploy(self.source,self.site,self.key,'FPR',self.receipt)
        self.assertEqual(self.events,['lease','precondition','retained']); self.assertFalse(self.receipt.exists())

    def test_latest_and_public_latest_check_run_inside_same_lease(self):
        assets=self.work/'github'; assets.mkdir(); directory=self.source/'releases/1.2.3-1'; directory.mkdir(parents=True)
        for path in (assets/'manifest.json',directory/'manifest.json'):path.write_text('{"release_id":"1.2.3-1"}')
        environment={'GITHUB_REPOSITORY':'faratech/httpjet','GITHUB_REF':'refs/tags/v1.2.3','GITHUB_SHA':'b'*40,'GH_TOKEN':'UNIT ONLY'}
        with mock.patch.dict(os.environ,environment),mock.patch.object(github_assets,'validate_tag_context'), \
             mock.patch.object(github_assets,'Github'), \
             mock.patch.object(github_assets,'promote_latest',side_effect=lambda *a:self.events.append('latest')), \
             mock.patch.object(github_assets,'verify_public',side_effect=lambda *a,**kw:self.events.append('latest-check')) as verified:
            pages.deploy(self.source,self.site,self.key,'FPR',self.receipt,assets)
        self.assertEqual(self.events,['lease','precondition','deploy','files','redirects','latest','latest-check','released'])
        self.assertTrue(verified.call_args.kwargs['require_latest'])


class EmptyBootstrap(unittest.TestCase):
    def test_public_diagnostics_are_bounded_and_do_not_print_cookies(self):
        error=urllib.error.HTTPError(pages.ORIGIN+'/',403,'forbidden',
            {'CF-Ray':'fixture-ray','CF-Mitigated':'challenge','Set-Cookie':'DO NOT LOG'},io.BytesIO(b'x'*10000))
        result=pages.public_http_diagnostic(error)
        self.assertEqual(result['status'],403);self.assertEqual(len(result['body_prefix']),4096)
        self.assertEqual(result['headers'],{'CF-Ray':'fixture-ray','CF-Mitigated':'challenge'})
        error.close()

    def test_bootstrap_contains_exactly_three_harmless_files(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-empty-pages-unit-') as temporary:
            output=Path(temporary)/'site'; pages.bootstrap(output)
            self.assertEqual({p.name for p in output.iterdir()},{'index.html','404.html','_headers'})
            self.assertIn('No qualified release has been published',(output/'index.html').read_text())
            with self.assertRaises(ValueError):pages.bootstrap(output)

    def test_origin_probe_requires_real404_and_denies_public_writes(self):
        class Response(io.BytesIO):
            status=200;url=pages.ORIGIN+'/';headers={'Cache-Control':'no-store'}
        def opened(request,timeout):
            if isinstance(request,str):url=request;method='GET'
            else:url=request.full_url;method=request.get_method()
            self.assertEqual(request.get_header('User-agent'),pages.release.USER_AGENT)
            if url==pages.ORIGIN+'/':return Response(pages.BOOTSTRAP.encode() if method=='GET' else b'')
            raise urllib.error.HTTPError(url,405 if method=='PUT' else 404,'fixture',{},None)
        with mock.patch.object(pages.urllib.request,'urlopen',side_effect=opened):
            report=pages.probe_bootstrap()
        self.assertEqual(report['write_status'],405);self.assertEqual(report['missing_status'],404)
        self.assertFalse(report['package_release_live'])
        with mock.patch.object(pages.urllib.request,'urlopen',side_effect=opened) as requests:
            report=pages.probe_bootstrap(read_only=True)
        self.assertFalse(report['write_tested']);self.assertIsNone(report['write_status'])
        self.assertEqual({call.args[0].get_method() for call in requests.call_args_list},{'GET','HEAD'})


if __name__=='__main__':unittest.main()
