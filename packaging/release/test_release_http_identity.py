#!/usr/bin/env python3
"""Release identity survives real HTTPS redirects with verified TLS."""
import http.server
import shutil
import ssl
import subprocess
import tempfile
from pathlib import Path
import threading
import unittest
from unittest import mock
import urllib.request
import release


class HTTPIdentity(unittest.TestCase):
    def test_https_redirect_preserves_identity_and_exact_bytes(self):
        if not shutil.which('openssl'): self.skipTest('requires OpenSSL')
        with tempfile.TemporaryDirectory(prefix='httpjet-http-identity-') as temporary:
            root=Path(temporary);key=root/'key.pem';certificate=root/'cert.pem'
            subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-days','1',
                '-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1',
                '-keyout',str(key),'-out',str(certificate)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            seen=[];body=b'HTTPJET UNIT HTTPS REDIRECT BYTES\n'
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    seen.append((self.path,self.headers.get('User-Agent')))
                    if self.path=='/start':
                        self.send_response(302);self.send_header('Location','/payload');self.end_headers()
                    else:
                        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(certificate,key)
            server.socket=tls.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(certificate))))
                with mock.patch.object(release.urllib.request,'urlopen',side_effect=opener.open):
                    release.download('https://127.0.0.1:'+str(server.server_port)+'/start',root/'download')
                self.assertEqual((root/'download').read_bytes(),body)
                self.assertEqual(seen,[('/start',release.USER_AGENT),('/payload',release.USER_AGENT)])
            finally:
                server.shutdown();server.server_close();thread.join()

    def test_http_input_still_rejected_before_network_access(self):
        with tempfile.TemporaryDirectory() as temporary,mock.patch.object(release.urllib.request,'urlopen') as opened:
            with self.assertRaisesRegex(ValueError,'require HTTPS'):
                release.download('http://example.invalid/file',Path(temporary)/'file')
            opened.assert_not_called()


if __name__=='__main__':unittest.main()
