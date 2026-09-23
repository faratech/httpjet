#!/usr/bin/env python3
"""Synthetic OCSP authority and real alternate-port httpjet TLS acceptance."""
import argparse
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import http.client
import http.server
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
from urllib.parse import unquote_to_bytes
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.dont_write_bytecode = True


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_for(probe, process, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("test server exited")
        try:
            result = probe()
            if result:
                return result
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    raise TimeoutError("acceptance deadline exceeded")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--optional", action="store_true")
    parser.add_argument("--must-staple", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    repo = Path(__file__).resolve().parent.parent
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated OCSP test CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(ca_key.public_key()).serial_number(1000)
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    certificates = {}
    modes = {}
    gate = threading.Event()
    lock = threading.Lock()
    calls = []

    class Responder(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            self.respond(False)

        def do_GET(self):
            self.respond(True)

        def respond(self, get):
            try:
                if get:
                    assert self.path.startswith("/ocsp/") and len(self.path) <= 255
                    der = base64.b64decode(unquote_to_bytes(self.path[len("/ocsp/"):]), validate=True)
                else:
                    length = int(self.headers.get("Content-Length", "0"))
                    assert self.path == "/ocsp" and 0 < length <= 4096
                    der = self.rfile.read(length)
                request = ocsp.load_der_ocsp_request(der)
                assert request.hash_algorithm.name == "sha256"
                serial = request.serial_number
                assert gate.wait(5), "fixture gate deadline"
                with lock:
                    cert = certificates[serial]
                    mode = modes[serial]
                    calls.append((serial, mode))
                if mode == "unavailable":
                    self.send_error(503)
                    return
                timestamp = datetime.now(timezone.utc)
                revoked = mode == "revoked"
                response = (ocsp.OCSPResponseBuilder().add_response(
                    cert=cert, issuer=ca, algorithm=hashes.SHA256(),
                    cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
                    this_update=timestamp - timedelta(seconds=1),
                    next_update=timestamp + timedelta(seconds=8),
                    revocation_time=timestamp - timedelta(seconds=30) if revoked else None,
                    revocation_reason=x509.ReasonFlags.key_compromise if revoked else None)
                    .responder_id(ocsp.OCSPResponderEncoding.NAME, ca)
                    .sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
                self.send_response(200)
                self.send_header("Content-Type", "application/ocsp-response")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            except (AssertionError, ValueError, KeyError):
                self.send_error(400)
            except (BrokenPipeError, ConnectionResetError):
                pass

    responder = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Responder)
    responder.daemon_threads = True
    thread = threading.Thread(target=responder.serve_forever, daemon=True)
    thread.start()
    process = None
    with tempfile.TemporaryDirectory(prefix="hj-ocsp-runtime-") as directory:
        root = Path(directory)
        try:
            shutil.copytree(repo / "examples/litespeed", root, dirs_exist_ok=True)
            (root / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

            def install(serial):
                key = ec.generate_private_key(ec.SECP256R1())
                builder = (x509.CertificateBuilder().subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "example.test")]))
                    .issuer_name(ca.subject).public_key(key.public_key()).serial_number(serial)
                    .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                    .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
                if args.must_staple:
                    builder = builder.add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False)
                cert = builder.sign(ca_key, hashes.SHA256())
                with lock:
                    certificates[serial] = cert
                    modes[serial] = "good"
                (root / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                (root / "key.pem").chmod(0o600)
                (root / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM)
                    + ca.public_bytes(serialization.Encoding.PEM))
                return cert.public_bytes(serialization.Encoding.DER)

            initial = install(1)
            http_port, tls_port = port(), port()
            while tls_port == http_port:
                tls_port = port()
            xml = root / "conf/httpd_config.xml"
            tree = ET.parse(xml)
            ET.SubElement(ET.SubElement(tree.getroot(), "quic"), "quicEnable").text = "1"
            listeners = tree.getroot().find("listenerList")
            listeners.find("listener/address").text = f"127.0.0.1:{http_port}"
            listener = ET.SubElement(listeners, "listener")
            for key, value in {"name": "https", "address": f"127.0.0.1:{tls_port}",
                               "secure": "1", "certFile": str(root / "cert.pem"),
                               "keyFile": str(root / "key.pem"), "enableStapling": "1"}.items():
                ET.SubElement(listener, key).text = value
            mapping = ET.SubElement(ET.SubElement(listener, "vhostMapList"), "vhostMap")
            ET.SubElement(mapping, "vhost").text = "example.test"
            ET.SubElement(mapping, "domain").text = "example.test"
            tree.write(xml, encoding="utf-8", xml_declaration=True)
            command = [str(binary), "--root", str(root), "serve", "--no-php", "--workers", "1",
                       "--http-addr", f"127.0.0.1:{http_port}", "--https-addr", f"127.0.0.1:{tls_port}",
                       "--metrics-addr", "", "--ocsp-responder", f"http://127.0.0.1:{responder.server_port}/ocsp",
                       "--ocsp-test-mode"]
            if not args.optional:
                command.append("--ocsp-required")
            with (root / "server.log").open("wb") as log:
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            context = ssl.create_default_context(cafile=str(root / "ca.pem"))

            def peer():
                with socket.create_connection(("127.0.0.1", tls_port), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname="example.test") as tls:
                        return tls.getpeercert(binary_form=True)

            def rejected():
                try:
                    peer()
                    return False
                except ssl.SSLError:
                    return True

            def http_ready():
                connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=2)
                try:
                    connection.request("GET", "/", headers={"Host": "example.test"})
                    return connection.getresponse().status == 200
                finally:
                    connection.close()

            def status():
                result = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{tls_port}",
                    "-servername", "example.test", "-CAfile", str(root / "ca.pem"), "-verify_return_error",
                    "-verify_hostname", "example.test", "-status"], input=b"", capture_output=True, timeout=5)
                assert result.returncode == 0, "TLS status probe failed"
                return result.stdout.decode()

            async def h3_probe():
                from aioquic.asyncio import connect
                from aioquic.quic.configuration import QuicConfiguration
                from h3get import H3Client
                config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name="example.test")
                config.load_verify_locations(cafile=str(root / "ca.pem"))
                async with connect("127.0.0.1", tls_port, configuration=config, create_protocol=H3Client) as client:
                    code, body = await client.get("example.test", "/")
                    assert code == b"200" and body

            def h3_rejected():
                try:
                    asyncio.run(asyncio.wait_for(h3_probe(), timeout=3))
                    return False
                except (ConnectionError, TimeoutError):
                    return True

            wait_for(http_ready, process)
            required = not args.optional or args.must_staple
            if required:
                assert rejected(), "required policy accepted a cold identity"
            else:
                assert peer() == initial
            gate.set()
            wait_for(lambda: peer() == initial, process)
            wait_for(lambda: "Cert Status: good" in status(), process)
            print("PASS: real authenticated OCSP response is stapled on TLS")
            context.set_alpn_protocols(["h2"])
            assert peer() == initial
            context.set_alpn_protocols(["http/1.1"])
            asyncio.run(asyncio.wait_for(h3_probe(), timeout=5))
            print("PASS: validated certificate serves native H2 and H3 with OCSP policy enabled")
            with lock:
                modes[1] = "unavailable"
            assert peer() == initial, "temporary failure discarded a fresh staple"
            wait_for(lambda: any(serial == 1 and mode == "unavailable" for serial, mode in calls), process)
            if required:
                wait_for(rejected, process, seconds=12)
                assert h3_rejected(), "HTTP/3 bypassed expired required OCSP status"
            else:
                wait_for(lambda: "OCSP response: no response sent" in status(), process, seconds=12)
            print("PASS: transient failure preserves fresh state, expiry enforces configured policy")
            replacement = install(2)
            process.send_signal(signal.SIGHUP)
            wait_for(lambda: peer() == replacement, process)
            wait_for(lambda: "Cert Status: good" in status(), process)
            print("PASS: SIGHUP replacement obtains its own authenticated staple")
            with lock:
                modes[2] = "revoked"
            wait_for(rejected, process)
            assert h3_rejected(), "HTTP/3 bypassed verified revocation"
            with lock:
                modes[2] = "good"
            reloads = (root / "server.log").read_text().count("SIGHUP: config hot-reloaded")
            process.send_signal(signal.SIGHUP)
            wait_for(lambda: (root / "server.log").read_text().count("SIGHUP: config hot-reloaded") > reloads, process)
            assert rejected(), "same certificate reload bypassed verified revocation"
            print("PASS: verified revocation refuses new handshakes and survives same-certificate reload")
        except Exception:
            print(f"Synthetic responder calls: {calls}", file=sys.stderr)
            if (root / "server.log").exists():
                print("\n".join((root / "server.log").read_text(errors="replace").splitlines()[-20:]), file=sys.stderr)
            raise
        finally:
            gate.set()
            stop(process)
            responder.shutdown()
            responder.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    main()
