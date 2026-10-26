#!/usr/bin/env python3
"""Run the packaged default against isolated static content and loopback ports."""

import argparse
import http.client
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[2]


class DefaultConfig(unittest.TestCase):
    binary = None

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="httpjet-default-", dir="/var/tmp")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.root.chmod(0o755)
        executable = cls.root / "httpjet"
        shutil.copyfile(cls.binary, executable)
        executable.chmod(0o755)
        cls.executable = executable
        config = cls.root / "configuration"
        shutil.copytree(REPO / "packaging/debian/conf", config / "conf")
        cls.config = config
        content = cls.root / "content"
        content.mkdir()
        content.chmod(0o755)
        cls.welcome = (REPO / "packaging/debian/welcome/index.html").read_bytes()
        (content / "index.html").write_bytes(cls.welcome)
        (content / "healthy.txt").write_bytes(b"static content is available\n")
        for name in ("secret.php", "secret.PHTML", "secret.phar", "secret.phps", "secret.php7.gz.br"):
            (content / name).write_bytes(b"<?php /* package-source-marker */ ?>\n")
        for name in ("httpd_config.xml", "vhosts/default.xml"):
            path = config / "conf" / name
            path.write_text(path.read_text().replace("/var/www/httpjet", str(content)))
        for path in (config, *config.rglob("*"), *content.rglob("*")):
            path.chmod(0o755 if path.is_dir() else 0o644)
        logs = cls.root / "logs"
        logs.mkdir(mode=0o750)
        identity = {}
        if os.geteuid() == 0:
            nobody = pwd.getpwnam("nobody")
            os.chown(logs, nobody.pw_uid, nobody.pw_gid)
            identity = {"user": nobody.pw_uid, "group": nobody.pw_gid, "extra_groups": []}
        cls.identity = identity
        cls.env = {
            "PATH": "/usr/bin:/bin",
            "HTTPJET_LOG_DIR": str(logs),
            "RUST_LOG": "warn",
        }
        check = subprocess.run(
            [str(executable), "--root", str(config), "check", "--strict"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=cls.env,
            start_new_session=True,
            **identity,
            check=False,
        )
        if check.returncode:
            raise RuntimeError(f"default config strict check failed: {check.stdout}\n{check.stderr}")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            cls.port = reservation.getsockname()[1]
        cls.server = subprocess.Popen(
            [str(executable), "--root", str(config), "serve", "--http-addr", f"127.0.0.1:{cls.port}",
             "--https-addr=", "--metrics-addr=", "--no-php", "--workers", "1", "--no-multishot-accept"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=cls.env,
            start_new_session=True,
            **identity,
        )
        cls.addClassCleanup(cls.stop_server)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if cls.server.poll() is not None:
                raise RuntimeError(f"isolated default server exited: {cls.server.returncode}")
            try:
                status, body = cls.request("/")
                if status == 200 and body == cls.welcome:
                    return
            except OSError:
                pass
            time.sleep(0.05)
        raise RuntimeError("isolated default server did not serve the canonical welcome within 10 seconds")

    @classmethod
    def stop_server(cls):
        if cls.server.poll() is None:
            cls.server.terminate()
            try:
                cls.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.server.kill()
                cls.server.wait(timeout=5)

    @classmethod
    def request(cls, path, host="arbitrary.invalid"):
        connection = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=1)
        try:
            connection.request("GET", path, headers={"Host": host, "Connection": "close"})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_wildcard_host_serves_exact_canonical_welcome(self):
        self.assertEqual(self.request("/"), (200, self.welcome))

    def test_localhost_names_serve_welcome(self):
        for host in ("localhost", "www.localhost"):
            with self.subTest(host=host):
                self.assertEqual(self.request("/", host), (200, self.welcome))

    def test_ordinary_static_file_is_available(self):
        self.assertEqual(self.request("/healthy.txt"), (200, b"static content is available\n"))

    def test_php_sources_compressed_forms_and_path_info_are_denied(self):
        for path in (
            "/secret.php", "/secret.PHTML", "/secret.phar", "/secret.phps",
            "/secret.php7.gz.br", "/secret.php/path-info", "/secret.phps/path-info",
            "/secret.php7.gz.br/path-info", "/secret.%70%68%70",
        ):
            with self.subTest(path=path):
                status, body = self.request(path)
                self.assertEqual(status, 403)
                self.assertNotIn(b"package-source-marker", body)

    def test_validation_refuses_a_vhost_unreadable_by_the_service_account(self):
        restricted = self.root / "restricted"
        shutil.copytree(self.config, restricted)
        vhost = restricted / "conf/vhosts/default.xml"
        vhost.chmod(0o600 if os.geteuid() == 0 else 0)
        command = [str(self.executable), "--root", str(restricted), "check", "--strict"]
        if os.geteuid() == 0:
            root_check = subprocess.run(command, capture_output=True, env=self.env, check=False)
            self.assertEqual(root_check.returncode, 0, root_check.stderr)
        account_check = subprocess.run(command, capture_output=True, env=self.env,
                                       start_new_session=True, **self.identity, check=False)
        self.assertNotEqual(account_check.returncode, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    arguments, remaining = parser.parse_known_args()
    DefaultConfig.binary = arguments.binary.resolve(strict=True)
    unittest.main(argv=[__file__, *remaining])
