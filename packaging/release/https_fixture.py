#!/usr/bin/env python3
"""HTTPS repository fixture with a complete, bounded TLS shutdown."""
import http.server
import ssl


class HTTPSFixtureServer(http.server.ThreadingHTTPServer):
    tls_shutdown_timeout = 2

    def shutdown_request(self, request):
        try:
            if isinstance(request, ssl.SSLSocket):
                # TCPServer closes the TCP stream directly. OpenSSL-based APT
                # correctly rejects that EOF without the TLS close_notify.
                # Bound the peer's response so an idle client cannot hang cleanup.
                request.settimeout(self.tls_shutdown_timeout)
                try:
                    request.unwrap()
                except (OSError, ValueError):
                    # A client may have closed first; always release the socket.
                    pass
        finally:
            super().shutdown_request(request)
