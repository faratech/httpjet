#!/usr/bin/env python3
"""Release HTTP requests identify the app without changing trust/authentication."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import patch
import release

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('httpjet_resolver_http',HERE/'resolve-images.py')
resolver=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(resolver)

class Response(io.BytesIO):
    def __init__(self,value,url):
        super().__init__(value if isinstance(value,bytes) else json.dumps(value).encode());self.url=url

class ReleaseUserAgent(unittest.TestCase):
    def test_metadata_token_and_registry_requests_identify_application(self):
        requests=[]
        def opened(request,timeout):
            requests.append(request);self.assertEqual(timeout,45)
            if request.full_url.startswith('https://auth.docker.io/'):
                value={'token':'UNIT-ONLY-registry-token'}
            elif request.full_url.startswith('https://registry-1.docker.io/'):
                self.assertEqual(request.get_header('Authorization'),'Bearer UNIT-ONLY-registry-token')
                self.assertIn('application/vnd.oci.image.index',request.get_header('Accept'))
                value={'manifests':[{'digest':'sha256:'+'a'*64,'platform':{'os':'linux','architecture':'amd64'}}]}
            else:value=b'UNIT CHECKSUM METADATA\n'
            return Response(value,request.full_url)
        with patch.object(resolver.urllib.request,'urlopen',side_effect=opened):
            self.assertEqual(resolver.text('https://example.invalid/SHA256SUMS'),'UNIT CHECKSUM METADATA\n')
            image=resolver.oci_reference('library/alpine','3','amd64')
        self.assertEqual(len(requests),3)
        self.assertEqual(image['sha256'],'a'*64)
        self.assertTrue(all(request.get_header('User-agent')==release.USER_AGENT for request in requests))
        self.assertIsNone(requests[0].get_header('Authorization'))
        self.assertIsNone(requests[1].get_header('Authorization'))

    def test_https_only_and_redirect_downgrade_rejection_are_preserved(self):
        with patch.object(resolver.urllib.request,'urlopen') as opened:
            with self.assertRaisesRegex(ValueError,'requires HTTPS'):resolver.text('http://example.invalid/image')
            opened.assert_not_called()
        with patch.object(resolver.urllib.request,'urlopen',return_value=Response(b'UNIT','http://example.invalid/image')):
            with self.assertRaisesRegex(ValueError,'downgraded HTTPS'):resolver.text('https://example.invalid/image')

    def test_verify_run_retains_api_auth_and_full_source_checks(self):
        policy=b'UNIT ONLY: NOT A QUALIFICATION POLICY\n';commit='a'*40;repository='unit/httpjet'
        manifest={'schema':2,'commit':commit,'tag':'v0.0.1','support_matrix':{'sha256':hashlib.sha256(policy).hexdigest()}}
        replies=[{'conclusion':'success','status':'completed','event':'push','path':'.github/workflows/installer-release.yml',
                  'head_sha':commit,'head_repository':{'full_name':repository}},
                 {'object':{'type':'tag','sha':'b'*40}},{'object':{'type':'commit','sha':commit}},
                 {'content':base64.b64encode(policy).decode()}]
        requests=[]
        def opened(request,timeout):
            requests.append(request);self.assertEqual(timeout,30)
            self.assertTrue(request.full_url.startswith('https://api.github.com/repos/'+repository+'/'))
            return Response(replies[len(requests)-1],request.full_url)
        with patch.dict(os.environ,{'GH_TOKEN':'UNIT-ONLY-token','GITHUB_REPOSITORY':repository}), \
             patch.object(sys,'argv',['verify-run.py','1234','/UNIT-ONLY']), \
             patch.object(release,'load',return_value=manifest),patch.object(release,'verify_artifacts') as artifacts, \
             patch.object(release,'verify_qualification') as qualification, \
             patch('urllib.request.urlopen',side_effect=opened),contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(HERE/'verify-run.py'),run_name='__main__')
        self.assertEqual(len(requests),4);artifacts.assert_called_once();qualification.assert_called_once()
        for request in requests:
            self.assertEqual(request.get_header('User-agent'),release.USER_AGENT)
            self.assertEqual(request.get_header('Authorization'),'Bearer UNIT-ONLY-token')
            self.assertEqual(request.get_header('Accept'),'application/vnd.github+json')
            self.assertEqual(request.get_header('X-github-api-version'),'2022-11-28')

if __name__=='__main__':unittest.main()
