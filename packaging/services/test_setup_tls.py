#!/usr/bin/env python3
"""An existing TLS pair is validated before HTTPS is enabled or reported ready."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SETUP_TLS = HERE / "setup-tls"
CONFIGURATION = HERE.parent / "debian/conf/httpd_config.xml"


def openssl(*arguments):
    subprocess.run(["openssl", *arguments], stdin=subprocess.DEVNULL, capture_output=True, check=True)


@unittest.skipUnless(shutil.which("openssl"), "openssl is required")
class ExistingPairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory(prefix="httpjet-setup-tls-material-")
        cls.addClassCleanup(cls.material.cleanup)
        base = Path(cls.material.name)
        cls.pairs = {}
        for name, algorithm in (("rsa", ["rsa:2048"]), ("other", ["rsa:2048"]),
                                ("ec", ["ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"])):
            key, certificate = base / (name + ".key"), base / (name + ".crt")
            openssl("req", "-x509", "-newkey", *algorithm, "-sha256", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(certificate))
            cls.pairs[name] = (key.read_bytes(), certificate.read_bytes())
        encrypted = base / "encrypted.key"
        openssl("pkey", "-in", str(base / "rsa.key"), "-aes256", "-passout", "pass:test-only", "-out", str(encrypted))
        cls.encrypted_key = encrypted.read_bytes()
        cls.env = dict(os.environ)
        if os.geteuid() != 0:
            # setup-tls insists on root-owned directories and chowns to root. Without
            # root, present this user's files as root-owned and skip the chown.
            shims = base / "bin"
            shims.mkdir()
            (shims / "stat").write_text(
                "#!/bin/sh\n"
                f"out=$({shutil.which('stat')} \"$@\") || exit\n"
                "case \"$2\" in %u) echo 0;; %u:%a) echo \"0:${out#*:}\";; *) echo \"$out\";; esac\n")
            (shims / "chown").write_text("#!/bin/sh\nexit 0\n")
            for shim in shims.iterdir():
                shim.chmod(0o755)
            cls.env["PATH"] = f"{shims}:{cls.env['PATH']}"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="httpjet-setup-tls-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "root"
        configuration = self.root / "etc/httpjet/conf"
        configuration.mkdir(parents=True, mode=0o755)
        for directory in (self.root / "etc", self.root / "etc/httpjet"):
            directory.chmod(0o755)
        shutil.copyfile(CONFIGURATION, configuration / "httpd_config.xml")
        self.tls = self.root / "etc/httpjet/tls"
        self.settings = self.root / "etc/httpjet/listeners.env"

    def place(self, key, certificate):
        shutil.rmtree(self.tls, ignore_errors=True)
        self.settings.unlink(missing_ok=True)
        self.tls.mkdir(mode=0o750)
        self.tls.chmod(0o750)
        (self.tls / "default.key").write_bytes(key)
        (self.tls / "default.crt").write_bytes(certificate)

    def setup_tls(self, mode="fresh"):
        result = subprocess.run([str(SETUP_TLS), str(self.root), str(os.getgid()), mode], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, env=self.env, timeout=60)
        self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)
        return result

    def assert_accepted(self, key, certificate):
        self.place(key, certificate)
        result = self.setup_tls()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("HTTPS bootstrap ready", result.stdout)
        self.assertEqual(self.settings.read_text(), "HTTPJET_HTTPS_ADDR=0.0.0.0:443\n")
        self.assertEqual((self.tls / "default.key").read_bytes(), key)
        self.assertEqual((self.tls / "default.crt").read_bytes(), certificate)

    def assert_rejected(self, key, certificate, message):
        self.place(key, certificate)
        for mode in ("fresh", "upgrade"):
            with self.subTest(mode=mode):
                result = self.setup_tls(mode)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertFalse(self.settings.exists() or self.settings.is_symlink())
                self.assertEqual((self.tls / "default.key").read_bytes(), key)
                self.assertEqual((self.tls / "default.crt").read_bytes(), certificate)

    def test_generated_pair_is_accepted_unchanged_on_the_next_run(self):
        first = self.setup_tls()
        self.assertEqual(first.returncode, 0, first.stderr)
        key = (self.tls / "default.key").read_bytes()
        self.settings.unlink()
        second = self.setup_tls()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("HTTPS bootstrap ready", second.stdout)
        self.assertTrue(self.settings.exists())
        self.assertEqual((self.tls / "default.key").read_bytes(), key)

    def test_valid_administrator_pairs_are_accepted(self):
        for name in ("rsa", "ec"):
            with self.subTest(name=name):
                self.assert_accepted(*self.pairs[name])

    def test_empty_key_is_rejected(self):
        self.assert_rejected(b"", self.pairs["rsa"][1], "private key is empty, corrupt or encrypted")

    def test_empty_pair_is_rejected(self):
        self.assert_rejected(b"", b"", "certificate is empty or corrupt")

    def test_garbage_certificate_is_rejected(self):
        garbage = b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"
        self.assert_rejected(self.pairs["rsa"][0], garbage, "certificate is empty or corrupt")

    def test_truncated_key_is_rejected(self):
        key = self.pairs["rsa"][0]
        self.assert_rejected(key[:len(key) // 2], self.pairs["rsa"][1], "private key is empty, corrupt or encrypted")

    def test_mismatched_pair_is_rejected(self):
        self.assert_rejected(self.pairs["other"][0], self.pairs["rsa"][1], "does not match its certificate")
        self.assert_rejected(self.pairs["ec"][0], self.pairs["rsa"][1], "does not match its certificate")

    def test_encrypted_key_is_rejected_without_prompting(self):
        self.assert_rejected(self.encrypted_key, self.pairs["rsa"][1], "private key is empty, corrupt or encrypted")


if __name__ == "__main__":
    unittest.main()
