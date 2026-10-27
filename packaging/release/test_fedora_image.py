"""Mocked Fedora transport; real stream hashes and atomic staging checks."""
import contextlib,copy,hashlib,io,tempfile,unittest,urllib.error,urllib.request
from pathlib import Path
import fedora_image as image
import release
URL='https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/aarch64/images/Fedora-Cloud-Base-Generic-44-1.7.aarch64.qcow2'

class Response(io.BytesIO):
    status=200
    def __init__(self,data,url):super().__init__(data);self.url=url
class Opener:
    def __init__(self,events):self.events=list(events);self.requests=[]
    def open(self,request,timeout):
        self.requests.append(request)
        if not self.events:raise AssertionError('unexpected network attempt')
        result=self.events.pop(0)
        if isinstance(result,Exception):raise result
        return result
def missing(code=404):return urllib.error.HTTPError('https://mirror.example/image?never-log-token',code,'UNIT ONLY',{},io.BytesIO())

class FedoraImage(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='httpjet-fedora-unit-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.target=self.root/'base-image';self.data=b'UNIT IMAGE NOT BOOTABLE'
        self.asset={'origin':image.CATALOG,'format':'qcow2','url':URL,'sha256':hashlib.sha256(self.data).hexdigest()}
        self.log=io.StringIO();redirect=contextlib.redirect_stdout(self.log);redirect.__enter__();self.addCleanup(redirect.__exit__,None,None,None)
    def test_original_mirror404_falls_back_to_same_official_direct_bytes(self):
        direct=image.locations(self.asset)[1];opener=Opener([missing(),Response(self.data,direct)]);before=copy.deepcopy(self.asset)
        report=image.fetch(self.asset,self.target,opener)
        self.assertEqual(self.asset,before);self.assertEqual(report['sha256'],before['sha256']);self.assertEqual(self.target.read_bytes(),self.data)
        self.assertEqual([r.full_url for r in opener.requests],[URL,direct])
        self.assertTrue(all(r.get_header('User-agent')==release.USER_AGENT for r in opener.requests))
        self.assertNotIn('never-log-token',self.log.getvalue());self.assertEqual(len(list(self.root.iterdir())),1)
    def test_archives_keep_the_identical_version_architecture_and_filename(self):
        urls=image.locations(self.asset);opener=Opener([missing(),missing(),Response(self.data,urls[2])])
        image.fetch(self.asset,self.target,opener)
        self.assertEqual([r.full_url for r in opener.requests],urls)
        self.assertEqual(urls[2],URL.replace('https://download.fedoraproject.org/pub/','https://archives.fedoraproject.org/pub/archive/'))
        self.assertEqual(hashlib.sha256(self.target.read_bytes()).hexdigest(),self.asset['sha256'])
    def test_bad_checksum_or403_is_fatal_and_leaves_no_partial_image(self):
        for event in (Response(b'wrong bytes',URL),missing(403)):
            opener=Opener([event])
            with self.assertRaises((ValueError,urllib.error.HTTPError)):image.fetch(self.asset,self.target,opener)
            self.assertEqual(len(opener.requests),1);self.assertEqual(list(self.root.iterdir()),[])
    def test_unavailable_locations_are_bounded_and_preserve_no_partial_data(self):
        opener=Opener([missing(),urllib.error.URLError('UNIT network failure'),missing()])
        with self.assertRaises(RuntimeError):image.fetch(self.asset,self.target,opener)
        self.assertEqual(len(opener.requests),3);self.assertEqual(list(self.root.iterdir()),[])
    def test_invalid_metadata_fails_before_network(self):
        for update in ({'origin':'https://example.invalid/catalog'},{'url':URL.replace('https:','http:')},{'url':URL+'?unlocked=version'},{'url':URL.replace('/44/','/../')},{'sha256':'invalid'},{'format':'raw'}):
            with self.subTest(update=update):
                opener=Opener([])
                with self.assertRaises(ValueError):image.fetch({**self.asset,**update},self.target,opener)
                self.assertEqual(opener.requests,[]);self.assertEqual(list(self.root.iterdir()),[])
    def test_existing_destination_is_preserved(self):
        self.target.write_bytes(b'owner bytes')
        with self.assertRaises(ValueError):image.fetch(self.asset,self.target,Opener([]))
        self.assertEqual(self.target.read_bytes(),b'owner bytes')
    def test_redirects_preserve_https_honest_identity_and_redact_queries(self):
        events=[];handler=image.Redirect(events);request=urllib.request.Request(URL,headers={'User-Agent':release.USER_AGENT})
        with self.assertRaises(image.UnsafeRedirect):handler.redirect_request(request,None,302,'Found',{},'http://mirror.example/image')
        redirected=handler.redirect_request(request,None,302,'Found',{},'https://mirror.example/image?never-log-token')
        self.assertEqual(redirected.get_header('User-agent'),release.USER_AGENT);self.assertNotIn('never-log-token',repr(events))
    def test_rejected_downgrade_can_use_independent_https_without_following_http(self):
        direct=image.locations(self.asset)[1];opener=Opener([image.UnsafeRedirect('UNIT refused HTTP'),Response(self.data,direct)])
        image.fetch(self.asset,self.target,opener)
        self.assertTrue(all(r.full_url.startswith('https://') for r in opener.requests));self.assertEqual(self.target.read_bytes(),self.data)
    def test_head_diagnostics_never_claim_checksum_or_write_an_image(self):
        direct=image.locations(self.asset)[1];opener=Opener([missing(),Response(b'',direct),missing()])
        result=image.probe(self.asset,opener)
        self.assertTrue(all(r.get_method()=='HEAD' for r in opener.requests))
        self.assertTrue(all(record['checksum_verified'] is False for record in result))
        self.assertEqual([record['status'] for record in result],[404,200,404]);self.assertEqual(list(self.root.iterdir()),[])
    def test_partial_timeout_does_not_prefix_the_successful_fallback(self):
        class Interrupted(Response):
            reads=0
            def read(self,size):
                self.reads+=1
                if self.reads==1:return b'partial failed bytes'
                raise TimeoutError('UNIT failed stream')
        direct=image.locations(self.asset)[1];opener=Opener([Interrupted(b'',URL),Response(self.data,direct)])
        image.fetch(self.asset,self.target,opener)
        self.assertEqual(self.target.read_bytes(),self.data)

if __name__=='__main__':unittest.main()
