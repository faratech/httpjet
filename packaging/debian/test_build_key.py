#!/usr/bin/env python3
"""Check package key admission using disposable public-key fixtures."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]


class BuildKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="httpjet-key-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.source = cls.root / "source"
        (cls.source / "packaging/debian").mkdir(parents=True)
        (cls.source / "debian").mkdir()
        shutil.copyfile(REPO / "Cargo.toml", cls.source / "Cargo.toml")
        shutil.copyfile(REPO / "debian/changelog", cls.source / "debian/changelog")
        shutil.copyfile(REPO / "packaging/debian/build-binary.sh", cls.source / "packaging/debian/build-binary.sh")
        cls.key = cls.source / "packaging/debian/archive-keyring.asc"
        cls.home = cls.root / "gnupg"
        cls.home.mkdir(mode=0o700)
        cls.addClassCleanup(subprocess.run, ["gpgconf", "--homedir", str(cls.home), "--kill", "gpg-agent"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.gpg = ["gpg", "--batch", "--homedir", str(cls.home)]
        for identity, usage in (("signing-fixture", "sign"), ("certification-fixture", "cert")):
            subprocess.run(cls.gpg + ["--pinentry-mode", "loopback", "--passphrase", "",
                           "--quick-generate-key", identity, "ed25519", usage, "1d"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.armor = subprocess.run(cls.gpg + ["--armor", "--export", "signing-fixture"],
                                   check=True, capture_output=True).stdout
        cls.binary = subprocess.run(cls.gpg + ["--export", "signing-fixture"],
                                    check=True, capture_output=True).stdout
        cls.nonsigning = subprocess.run(cls.gpg + ["--armor", "--export", "certification-fixture"],
                                        check=True, capture_output=True).stdout

    def build(self, payload):
        self.key.write_bytes(payload)
        env = os.environ | {"HTTPJET_PACKAGE_TEST": "1", "HTTPJET_TEST_PREBUILT": "/usr/bin/true"}
        return subprocess.run(["/bin/sh", str(self.source / "packaging/debian/build-binary.sh")],
                              env=env, capture_output=True, text=True, check=False)

    def test_armored_public_signing_key_is_accepted(self):
        result = self.build(self.armor)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_binary_key_cannot_be_installed_with_an_asc_extension(self):
        result = self.build(self.binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ASCII-armored public key", result.stderr)

    def test_truncated_armor_is_rejected(self):
        result = self.build(self.armor.replace(b"-----END PGP PUBLIC KEY BLOCK-----", b""))
        self.assertNotEqual(result.returncode, 0)

    def test_key_without_signing_capability_is_rejected(self):
        result = self.build(self.nonsigning)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public signing key", result.stderr)

    def test_private_key_armor_is_rejected(self):
        result = self.build(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture\n-----END PGP PRIVATE KEY BLOCK-----\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("never private key material", result.stderr)


if __name__ == "__main__":
    unittest.main()
