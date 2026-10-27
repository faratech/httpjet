#!/usr/bin/env python3
"""Exercise the declarative guest's real loopback HTTP readiness probe."""
import http.client
import http.server
import importlib.util
from pathlib import Path
import threading
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('declarative_guest', Path(__file__).with_name('declarative-guest.py'))
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)


class Readiness(unittest.TestCase):
    def test_real_http_response_is_read(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'qualification welcome')
            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        connection = http.client.HTTPConnection
        with mock.patch.object(guest.http_client, 'HTTPConnection',
                               side_effect=lambda host, port, timeout: connection(host, server.server_port, timeout=timeout)):
            self.assertEqual(guest.http(), b'qualification welcome')
            guest.ready(timeout=2)

    def test_readiness_retries_http_protocol_errors(self):
        with mock.patch.object(guest, 'http', side_effect=[http.client.HTTPException('temporary'), b'ok']), \
             mock.patch.object(guest.time, 'sleep'):
            guest.ready(timeout=2)


if __name__ == '__main__':
    unittest.main()
