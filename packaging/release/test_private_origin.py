"""Mocked private CAS/cleanup contracts; no remote storage is contacted."""
import importlib.util,io,json,tempfile,unittest,urllib.error
from pathlib import Path
from unittest import mock
HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('private_probe',HERE/'check-private-origin.py')
probe=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(probe)

class Response(io.BytesIO):
    def __init__(self,data=b'',headers=None,url='',status=200):
        super().__init__(data);self.headers=headers or {};self.url=url;self.status=status

class Store:
    def __init__(self,fault=None):self.data=None;self.version=0;self.calls=[];self.fault=fault
    def request(self,method,key,data=b'',headers=None):
        headers=headers or {};self.calls.append((method,key,headers))
        tag='"'+str(self.version)+'"'
        def fail(code):raise urllib.error.HTTPError('https://unit.invalid/private',code,'UNIT ONLY',{},io.BytesIO())
        if method=='GET':
            if self.data is None:fail(404)
            return Response(self.data,{'ETag':tag})
        if method=='DELETE':
            if self.fault=='delete-denied':fail(403)
            self.data=None;return Response()
        if method!='PUT':raise AssertionError(method)
        if self.fault!='ignore-conditions':
            if headers.get('if-none-match')=='*' and self.data is not None:fail(412)
            if 'if-match' in headers and headers['if-match']!=tag and self.fault!='ignore-stale':fail(412)
        self.data=data;self.version+=1
        if self.fault=='lost-ack' and self.version==1:raise urllib.error.URLError('UNIT ONLY lost response')
        return Response(headers={} if self.fault=='missing-etag' else {'ETag':'"'+str(self.version)+'"'})

class PrivateOrigin(unittest.TestCase):
    def public(self,store,status=403):
        def open(request,timeout):
            self.assertIsNotNone(store.data)
            self.assertEqual(request.get_method(),'GET')
            self.assertEqual(request.get_header('User-agent'),probe.release.USER_AGENT)
            self.assertIsNone(request.get_header('Authorization'))
            if status==200:return Response(store.data,url=request.full_url)
            raise urllib.error.HTTPError(request.full_url,status,'UNIT ONLY',{},io.BytesIO())
        return mock.Mock(open=mock.Mock(side_effect=open))
    def test_realistic_cas_and_cleanup_touch_only_one_random_private_probe(self):
        store=Store();result=probe.probe(store,self.public(store))
        self.assertEqual(result['status'],'passed');self.assertTrue(result['object_deleted']);self.assertFalse(result['publication_lock_touched'])
        self.assertIsNone(store.data);self.assertEqual({key for _,key,_ in store.calls},{result['object_key']})
        self.assertRegex(result['object_key'],r'^_httpjet/credential-probes/[0-9a-f]{64}\.json$')
        self.assertNotIn('publication.lock',result['object_key'])
        puts=[headers for method,_,headers in store.calls if method=='PUT']
        self.assertEqual([item.get('if-none-match') for item in puts[:2]],['*','*'])
        self.assertEqual(puts[2]['if-match'],puts[3]['if-match'])
        self.assertEqual([method for method,_,_ in store.calls[-2:]],['DELETE','GET'])
    def test_ignored_precondition_or_lost_ack_still_cleans_up(self):
        for fault in ('ignore-conditions','ignore-stale','missing-etag','lost-ack'):
            with self.subTest(fault=fault):
                store=Store(fault)
                with self.assertRaises((ValueError,urllib.error.URLError)):probe.probe(store,self.public(store))
                self.assertIsNone(store.data);self.assertIn('DELETE',[method for method,_,_ in store.calls])
    def test_collision_never_deletes_an_unowned_object(self):
        store=Store();store.data=b'unowned'
        with self.assertRaises(urllib.error.HTTPError):probe.probe(store,self.public(store))
        self.assertEqual(store.data,b'unowned');self.assertNotIn('DELETE',[method for method,_,_ in store.calls])
    def test_cleanup_failure_cannot_report_success(self):
        store=Store('delete-denied')
        with self.assertRaisesRegex(RuntimeError,'cleanup failed'):probe.probe(store,self.public(store))
    def test_public_access_or_redirect_cannot_report_privacy(self):
        for status in (200,302,500):
            store=Store()
            with self.assertRaises((ValueError,urllib.error.HTTPError)):probe.probe(store,self.public(store,status))
            self.assertIsNone(store.data)
    def test_readonly_pages_probe_sends_only_get_and_head(self):
        methods=[]
        def open(request,timeout):
            methods.append(request.get_method())
            self.assertEqual(request.get_header('User-agent'),probe.release.USER_AGENT)
            if request.full_url==probe.pages.ORIGIN+'/':
                return Response(probe.pages.BOOTSTRAP.encode() if request.get_method()=='GET' else b'',{'Cache-Control':'no-store'},request.full_url)
            raise urllib.error.HTTPError(request.full_url,404,'UNIT ONLY',{},io.BytesIO())
        result=probe.pages_readonly(mock.Mock(open=mock.Mock(side_effect=open)))
        self.assertEqual(result['status'],'passed');self.assertEqual(len(methods),6);self.assertEqual(set(methods),{'GET','HEAD'})
    def test_honest_identity_does_not_relax_pages_bootstrap_or_404_checks(self):
        for mode in ('403','changed-body','missing-returns-200'):
            with self.subTest(mode=mode):
                def open(request,timeout):
                    self.assertEqual(request.get_header('User-agent'),probe.release.USER_AGENT)
                    if mode=='403':raise urllib.error.HTTPError(request.full_url,403,'UNIT ONLY',{},io.BytesIO())
                    if request.full_url==probe.pages.ORIGIN+'/':
                        body=b'changed' if mode=='changed-body' else (probe.pages.BOOTSTRAP.encode() if request.get_method()=='GET' else b'')
                        return Response(body,{'Cache-Control':'no-store'},request.full_url)
                    return Response(b'SPA fallback',url=request.full_url)
                with self.assertRaises((ValueError,urllib.error.HTTPError)) as raised:
                    probe.pages_readonly(mock.Mock(open=mock.Mock(side_effect=open)))
                if isinstance(raised.exception,urllib.error.HTTPError):raised.exception.close()

if __name__=='__main__':unittest.main()
