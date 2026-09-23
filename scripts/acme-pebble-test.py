#!/usr/bin/env python3
"""Local-only ACME acceptance: HTTP-01/DNS-01, TLS activation and renewal."""
import argparse
import asyncio
import http.client
import http.server
import json
import os
import re
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def get(http_port, path, method="GET"):
    connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=2)
    try:
        connection.request(method, path, headers={"Host": "example.test"})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def certificate(tls_port, context, name="example.test"):
    with socket.create_connection(("127.0.0.1", tls_port), timeout=2) as sock:
        with context.wrap_socket(sock, server_hostname=name) as tls:
            return tls.getpeercert(binary_form=True)


def wait_for(probe, processes, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if any(process.poll() is not None for process in processes):
            raise RuntimeError("fixture process exited unexpectedly")
        try:
            result = probe()
            if result:
                return result
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    raise TimeoutError("fixture readiness/acceptance deadline exceeded")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--pebble", type=Path, required=True)
    parser.add_argument("--dns", type=Path, required=True)
    parser.add_argument("--pebble-source", type=Path, required=True)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--dns01", action="store_true")
    args = parser.parse_args()
    for field in ("binary", "pebble", "dns", "pebble_source"):
        setattr(args, field, getattr(args, field).resolve(strict=True))
    repo = Path(__file__).resolve().parent.parent
    processes = []
    webhook = None
    with tempfile.TemporaryDirectory(prefix="hj-acme-runtime-") as directory:
        root = Path(directory)
        try:
            shutil.copytree(repo / "examples/litespeed", root, dirs_exist_ok=True)
            store = root / "acme"
            store.mkdir(mode=0o700)
            # Existing synthetic TLS configuration remains in force until issuance.
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
                            "-days", "1", "-subj", "/CN=bootstrap.invalid"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            if args.bootstrap:
                (root / "cert.pem").unlink()
                (root / "key.pem").unlink()
            ports = set()
            while len(ports) < 6:
                ports.add(port())
            http_port, tls_port, ca_port, management_port, dns_port, dns_management = ports
            xml = root / "conf/httpd_config.xml"
            tree = ET.parse(xml)
            ET.SubElement(ET.SubElement(tree.getroot(), "quic"), "quicEnable").text = "1"
            listeners = tree.getroot().find("listenerList")
            listeners.find("listener/address").text = f"127.0.0.1:{http_port}"
            listener = ET.SubElement(listeners, "listener")
            for key, value in {"name": "https", "address": f"127.0.0.1:{tls_port}",
                               "secure": "1", "keyFile": str(root / "key.pem"),
                               "certFile": str(root / "cert.pem")}.items():
                ET.SubElement(listener, key).text = value
            mapping = ET.SubElement(ET.SubElement(listener, "vhostMapList"), "vhostMap")
            ET.SubElement(mapping, "vhost").text = "example.test"
            ET.SubElement(mapping, "domain").text = "example.test"
            if args.dns01:
                mapping.find("domain").text = "example.test,*.example.test"
            tree.write(xml, encoding="utf-8", xml_declaration=True)
            ca_config = {"pebble": {
                "listenAddress": f"127.0.0.1:{ca_port}",
                "managementListenAddress": f"127.0.0.1:{management_port}",
                "certificate": str(args.pebble_source / "test/certs/localhost/cert.pem"),
                "privateKey": str(args.pebble_source / "test/certs/localhost/key.pem"),
                "httpPort": http_port, "tlsPort": tls_port, "keyAlgorithm": "ecdsa",
                "externalAccountBindingRequired": False, "retryAfter": {"authz": 1, "order": 1}}}
            config_path = root / "pebble.json"
            config_path.write_text(json.dumps(ca_config))

            def spawn(command, name, env=None):
                with (root / name).open("ab") as log:
                    process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
                processes.append(process)
                return process

            dns = spawn([str(args.dns), "-dnsserver", f"127.0.0.1:{dns_port}", "-management",
                         f"127.0.0.1:{dns_management}", "-http01", "", "-https01", "",
                         "-tlsalpn01", "", "-doh", "", "-defaultIPv6", ""], "dns.log")
            env = os.environ.copy()
            env.pop("PEBBLE_VA_ALWAYS_VALID", None)
            env.update(PEBBLE_VA_NOSLEEP="1", PEBBLE_AUTHZREUSE="0", PEBBLE_WFE_NONCEREJECT="0")
            ca = spawn([str(args.pebble), "-config", str(config_path), "-dnsserver",
                        f"127.0.0.1:{dns_port}"], "ca.log", env)
            ca_root = args.pebble_source / "test/certs/pebble.minica.pem"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca_root))))

            def fetch_root():
                with opener.open(f"https://127.0.0.1:{management_port}/roots/0", timeout=2) as response:
                    return response.read(65536)

            issuer = wait_for(fetch_root, [ca, dns])
            values = {"unrelated-owner-value"}
            provider_calls = []
            values_lock = threading.Lock()
            if args.dns01:
                dns_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

                def sync_txt():
                    # This is an isolated fake provider. It owns this test-only
                    # RRset and rewrites it while preserving every other value.
                    payload = {"host": "_acme-challenge.example.test."}
                    request = urllib.request.Request(f"http://127.0.0.1:{dns_management}/clear-txt", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
                    with dns_opener.open(request, timeout=2):
                        pass
                    for value in values:
                        payload["value"] = value
                        request = urllib.request.Request(f"http://127.0.0.1:{dns_management}/set-txt", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
                        with dns_opener.open(request, timeout=2):
                            pass

                class Provider(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *_args):
                        pass

                    def do_POST(self):
                        try:
                            assert self.path == "/dns"
                            assert self.headers.get("Authorization") == "Bearer fixture-only-dns-credential"
                            length = int(self.headers["Content-Length"])
                            assert 0 < length < 2048
                            request = json.loads(self.rfile.read(length))
                            assert request["version"] == 1
                            assert request["name"] == "_acme-challenge.example.test"
                            value = request["value"]
                            assert re.fullmatch(r"[A-Za-z0-9_-]{43}", value)
                            operation = request["operation"]
                            assert operation in {"present", "ready", "cleanup"}
                            with values_lock:
                                if operation == "present":
                                    values.add(value)
                                    sync_txt()
                                elif operation == "cleanup":
                                    values.discard(value)
                                    sync_txt()
                                provider_calls.append(operation)
                                ready = value in values
                            body = json.dumps({"ok": True, "ready": ready}).encode()
                            self.send_response(200)
                        except Exception:
                            body = b'{"ok":false}'
                            self.send_response(400)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)

                webhook = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
                webhook.daemon_threads = True
                threading.Thread(target=webhook.serve_forever, daemon=True).start()
                token_file = root / "dns-token"
                token_file.write_text("fixture-only-dns-credential")
                token_file.chmod(0o600)
            issuer_path = root / "issuer.pem"
            issuer_path.write_bytes(issuer)
            context = ssl.create_default_context(cafile=str(issuer_path))
            command = [str(args.binary), "--root", str(root), "serve", "--no-php", "--workers", "1",
                       "--http-addr", f"127.0.0.1:{http_port}", "--https-addr", f"127.0.0.1:{tls_port}",
                       "--metrics-addr", "", "--page-cache", "--acme-directory", f"https://127.0.0.1:{ca_port}/dir",
                       "--acme-domains", "example.test", "--acme-store", str(store), "--acme-accept-terms",
                       "--acme-test-mode", "--acme-test-ca-root", str(ca_root), "--acme-test-issuer-root", str(issuer_path)]
            if args.bootstrap:
                command.append("--acme-bootstrap")
            if args.dns01:
                command[command.index("--acme-domains") + 1] = "example.test,*.example.test"
                command += ["--acme-dns-webhook", f"http://127.0.0.1:{webhook.server_port}/dns", "--acme-dns-zones", "example.test", "--acme-dns-token-file", str(token_file)]
            server = spawn(command, "server.log")
            first = wait_for(lambda: certificate(tls_port, context), [server, ca, dns], 140)
            print(f"PASS: real {'DNS-01' if args.dns01 else 'HTTP-01'} -> validated TLS activation")
            if args.dns01:
                assert certificate(tls_port, context, "child.example.test") == first
                try:
                    certificate(tls_port, context, "nested.child.example.test")
                    raise AssertionError("wildcard matched multiple labels")
                except ssl.SSLError:
                    pass
                with values_lock:
                    assert values == {"unrelated-owner-value"}
                    assert provider_calls.count("present") >= 2
                    assert provider_calls.count("cleanup") >= 2
                assert "fixture-only-dns-credential" not in (store / "state.snapshot").read_text()
                print("PASS: wildcard matches one label; TXT cleanup preserves unrelated values; no persisted provider credential")
            # Validate managed TLS on the native H2 and QUIC/H3 paths too.
            import h2.connection
            import h2.events
            context.set_alpn_protocols(["h2"])
            with socket.create_connection(("127.0.0.1", tls_port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname="example.test") as tls:
                    assert tls.selected_alpn_protocol() == "h2"
                    connection = h2.connection.H2Connection()
                    connection.initiate_connection()
                    connection.send_headers(1, [(":method", "GET"), (":scheme", "https"),
                        (":authority", "example.test"), (":path", "/")], end_stream=True)
                    tls.sendall(connection.data_to_send())
                    ended = False
                    while not ended:
                        data = tls.recv(65536)
                        assert data, "H2 EOF before response"
                        for event in connection.receive_data(data):
                            if isinstance(event, h2.events.ResponseReceived):
                                assert dict(event.headers)[b":status"] == b"200"
                            if isinstance(event, h2.events.StreamEnded):
                                ended = True
            context.set_alpn_protocols(["http/1.1"])

            async def h3_probe():
                from aioquic.asyncio import connect
                from aioquic.quic.configuration import QuicConfiguration
                from h3get import H3Client
                config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name="example.test")
                config.load_verify_locations(cafile=str(issuer_path))
                async with connect("127.0.0.1", tls_port, configuration=config, create_protocol=H3Client) as client:
                    status, body = await client.get("example.test", "/")
                    assert status == b"200" and body
            asyncio.run(asyncio.wait_for(h3_probe(), timeout=15))
            print("PASS: trusted managed certificate on native HTTP/2 and HTTP/3")
            token = "A" * 22
            if not args.dns01:
                check_http_paths(http_port, token)
            server.send_signal(signal.SIGHUP)
            time.sleep(0.5)
            assert certificate(tls_port, context) == first
            print("PASS: SIGHUP preserves managed certificate overlay")
            stop(server)
            processes.remove(server)
            if args.dns01:
                # Simulate loss after a provider mutation but before acknowledgement.
                snapshot_path = store / "state.snapshot"
                snapshot = json.loads(snapshot_path.read_text())
                interrupted = "B" * 43
                snapshot["dns_cleanup"] = [{"name": "_acme-challenge.example.test", "value": interrupted}]
                snapshot_path.write_text(json.dumps(snapshot))
                with values_lock:
                    values.add(interrupted)
                    sync_txt()
            server = spawn(command, "server.log")
            assert wait_for(lambda: certificate(tls_port, context), [server, ca, dns]) == first
            if args.dns01:
                def cleaned():
                    with values_lock:
                        return values == {"unrelated-owner-value"}
                wait_for(cleaned, [server, ca, dns], 10)
                assert not json.loads((store / "state.snapshot").read_text())["dns_cleanup"]
                print("PASS: restart replays pending exact-value DNS cleanup before renewal")
            print("PASS: restart restores the same durable certificate pair")
            stop(server)
            processes.remove(server)
            snapshot_path = store / "state.snapshot"
            snapshot = json.loads(snapshot_path.read_text())
            account = snapshot["account_id"]
            snapshot["next_attempt"] = 0  # only this disposable test's renewal clock
            snapshot_path.write_text(json.dumps(snapshot))
            server = spawn(command, "server.log")

            def renewed():
                candidate = certificate(tls_port, context)
                return candidate if candidate != first else None

            wait_for(renewed, [server, ca, dns], 140)
            assert json.loads(snapshot_path.read_text())["account_id"] == account
            print("PASS: renewal activates a new certificate without replacing the account")
        except BaseException:
            for path in root.glob("*.log"):
                print(path.name, path.read_text(errors="replace")[-10000:])
            raise
        finally:
            for process in reversed(processes):
                stop(process)
            if webhook:
                webhook.shutdown()
                webhook.server_close()


def check_http_paths(http_port, token):
    for path in [f"/.well-known/acme-challenge/{token}", f"/.well-known/acme-challenge/{token}?",
                 "/.well-known/acme-challenge/../index.html", "/.well-known/acme-challenge/%2e%2e/index.html"]:
        status, headers, body = get(http_port, path)
        assert status == 404, (path, status)
        assert headers.get("cache-control") == "no-store", headers
        assert b"Example" not in body
    assert get(http_port, f"/.well-known/acme-challenge/{token}", "POST")[0] == 405
    print("PASS: unknown/traversal/query tokens terminal, uncached; unsupported method rejected")


if __name__ == "__main__":
    main()
