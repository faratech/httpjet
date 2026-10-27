#!/usr/bin/env python3
"""Verified TLS shutdown: complete bytes must end with close_notify."""
import contextlib,functools,http.client,http.server,socket,ssl,subprocess,tempfile,threading,unittest,urllib.request
from pathlib import Path
from https_fixture import HTTPSFixtureServer

class HTTPSShutdown(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='httpjet-tls-test-');cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name);cls.cert=cls.root/'cert';cls.key=cls.root/'key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1',
            '-keyout',str(cls.key),'-out',str(cls.cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (cls.root/'body').write_bytes(b'UNIT TLS BODY\n')

    @contextlib.contextmanager
    def server(self,kind=HTTPSFixtureServer,handler=None):
        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self,*args):pass
        server=kind(('127.0.0.1',0),handler or functools.partial(Quiet,directory=self.root))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.cert,self.key)
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:yield server
        finally:server.shutdown();server.server_close();thread.join()

    def client(self,server):
        return ssl.create_default_context(cafile=str(self.cert)).wrap_socket(
            socket.create_connection(server.server_address),server_hostname='127.0.0.1',suppress_ragged_eofs=False)

    def test_raw_tcp_close_reproduces_actual_unexpected_eof(self):
        with self.server(http.server.ThreadingHTTPServer) as server,self.client(server) as client:
            client.sendall(b'GET /body HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n');body=b''
            with self.assertRaises(ssl.SSLEOFError):
                while chunk:=client.recv(4096):body+=chunk
            self.assertTrue(body.endswith(b'UNIT TLS BODY\n'))

    def test_close_notify_keeps_exact_bytes_and_ends_tls_cleanly(self):
        with self.server(HTTPSFixtureServer) as server,self.client(server) as client:
            self.assertEqual(client.context.verify_mode,ssl.CERT_REQUIRED)
            client.sendall(b'GET /body HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n');body=b''
            while chunk:=client.recv(4096):body+=chunk
            self.assertTrue(body.endswith(b'UNIT TLS BODY\n'));client.unwrap().close()

    def test_untrusted_certificate_is_still_rejected(self):
        with self.server() as server:
            raw=socket.create_connection(server.server_address)
            try:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    ssl.create_default_context().wrap_socket(raw,server_hostname='127.0.0.1')
            finally:raw.close()

    def test_truncated_body_is_still_rejected(self):
        class Truncated(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Length','100');self.end_headers();self.wfile.write(b'short')
        with self.server(handler=Truncated) as server:
            opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(self.cert))))
            with opener.open('https://127.0.0.1:'+str(server.server_port)+'/') as response:
                with self.assertRaises(http.client.IncompleteRead):response.read()

    def test_peer_without_shutdown_reply_cannot_hang_cleanup(self):
        closed=threading.Event()
        class Observed(HTTPSFixtureServer):
            tls_shutdown_timeout=0.1
            def close_request(self,request):
                super().close_request(request);closed.set()
        with self.server(Observed) as server,self.client(server) as client:
            client.sendall(b'GET /body HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n')
            while client.recv(4096):pass
            self.assertTrue(closed.wait(1))

if __name__=='__main__':unittest.main()
