#!/usr/bin/env python3
"""Run canonical TLS h2spec against a synthetic, disposable httpjet instance."""
import argparse
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--binary", required=True, type=Path)
    args.add_argument("--h2spec", default="h2spec")
    cfg = args.parse_args()
    binary = cfg.binary.resolve(strict=True)  # Never fall back to an installed binary.
    version = subprocess.check_output([cfg.h2spec, "--version"], text=True, timeout=5)
    if "2.6.0" not in version:
        raise RuntimeError(f"h2spec 2.6.0 required: {version}")
    repo = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="hj-ci-h2-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "examples/litespeed", root, dirs_exist_ok=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
                        "-days", "1", "-subj", "/CN=example.test"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        http_port, tls_port = port(), port()
        while tls_port == http_port:
            tls_port = port()
        xml = root / "conf/httpd_config.xml"
        tree = ET.parse(xml)
        listeners = tree.getroot().find("listenerList")
        listeners.find("listener/address").text = f"127.0.0.1:{http_port}"
        listener = ET.SubElement(listeners, "listener")
        for key, value in {"name": "https", "address": f"127.0.0.1:{tls_port}",
                           "secure": "1", "keyFile": str(root / "key.pem"),
                           "certFile": str(root / "cert.pem")}.items():
            ET.SubElement(listener, key).text = value
        mapping = ET.SubElement(ET.SubElement(listener, "vhostMapList"), "vhostMap")
        ET.SubElement(mapping, "vhost").text = "example.test"
        ET.SubElement(mapping, "domain").text = "example.test,localhost"
        tree.write(xml, encoding="utf-8", xml_declaration=True)
        command = [str(binary), "--root", str(root), "serve", "--no-php", "--no-mtls",
                   "--workers", "1", "--http-addr", f"127.0.0.1:{http_port}",
                   "--https-addr", f"127.0.0.1:{tls_port}", "--metrics-addr", ""]
        with (root / "server.log").open("wb") as log:
            server = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}),
                    urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
                while True:
                    if server.poll() is not None:
                        raise RuntimeError("synthetic server exited before readiness")
                    try:
                        req = urllib.request.Request(f"https://127.0.0.1:{tls_port}/", headers={"Host": "example.test"})
                        with opener.open(req, timeout=1) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("synthetic server readiness timed out")
                    time.sleep(0.1)
                result = subprocess.run([cfg.h2spec, "-t", "-k", "-h", "127.0.0.1",
                                         "-p", str(tls_port), "-o", "5"],
                                        capture_output=True, text=True, timeout=300)
                print(result.stdout)
                print(result.stderr)
                if result.returncode or "146 tests, 146 passed" not in result.stdout:
                    raise RuntimeError("canonical h2spec gate did not pass 146/146")
            except BaseException:
                log.flush()
                print((root / "server.log").read_text(errors="replace")[-16000:])
                raise
            finally:
                if server.poll() is None:
                    server.terminate()
                    try:
                        server.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)


if __name__ == "__main__":
    main()
