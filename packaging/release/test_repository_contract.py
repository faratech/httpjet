#!/usr/bin/env python3
"""Real signing and APT metadata tests using text-only, non-release packages.

No executable candidate, VM qualification receipt or published object is created.
"""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release
import publish

ROOT = Path(__file__).resolve().parents[2]


def command(*args):
    return subprocess.run([str(arg) for arg in args], check=True,
                          capture_output=True, text=True).stdout


class RepositoryContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ("gpg", "gpgv", "apt-ftparchive", "dpkg-deb"):
            if not shutil.which(tool):
                raise unittest.SkipTest(f"repository tests require {tool}")
        cls.temporary = tempfile.TemporaryDirectory(prefix="httpjet-repository-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        cls.base.chmod(0o755)
        cls.gpg_home = cls.base / "gnupg"
        cls.gpg_home.mkdir(mode=0o700)
        cls.environment = patch.dict(os.environ, {"GNUPGHOME": str(cls.gpg_home)})
        cls.environment.start()
        cls.addClassCleanup(cls.environment.stop)
        cls.addClassCleanup(lambda: subprocess.run(
            ["gpgconf", "--kill", "all"], capture_output=True, check=False))
        command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-generate-key", "httpjet TEST ONLY <test@example.invalid>",
                "ed25519", "sign", "1d")
        cls.public_key = cls.base / "test-public.asc"
        cls.public_key.write_text(command("gpg", "--armor", "--export"))
        cls.fingerprint = release.key_fingerprint(cls.public_key)

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="case-", dir=self.base))
        self.artifacts = self.work / "artifacts"
        self.artifacts.mkdir()
        self.version = "0.0.1"
        packages = {arch: self.make_package("httpjet", "0.0.1-1", arch).name
                    for arch in release.ARCHES}
        self.make_package("httpjet-archive-keyring", "0.0.1-1", "all")
        manifest = {
            "schema": 1, "version": self.version, "tag": "v" + self.version,
            "commit": "0" * 40, "archive_fingerprint": self.fingerprint,
            "packages": packages,
            "artifacts": {path.name: {"sha256": release.sha(path), "size": path.stat().st_size}
                          for path in self.artifacts.iterdir()},
        }
        release.write_json(self.artifacts / "manifest.json", manifest)
        (self.artifacts / "SHA256SUMS").write_text("".join(
            f"{data['sha256']}  {name}\n" for name, data in sorted(manifest["artifacts"].items())))

    def make_package(self, name, version, architecture, destination=None):
        tree = self.work / f"{name}-{version}-{architecture}"
        (tree / "DEBIAN").mkdir(parents=True)
        (tree / "DEBIAN/control").write_text(
            f"Package: {name}\nVersion: {version}\nArchitecture: {architecture}\n"
            "Maintainer: Test Only <test@example.invalid>\nDescription: disposable fixture\n")
        content = tree / "usr/share/httpjet-test"
        content.mkdir(parents=True)
        (content / "fixture.txt").write_text("NOT A RELEASE CANDIDATE\n")
        result = (destination or self.artifacts) / f"{name}_{version}_{architecture}.deb"
        command("dpkg-deb", "--build", "--root-owner-group", tree, result)
        return result

    def stage(self, **kwargs):
        return release.stage(
            self.artifacts, self.work / "snapshot", self.public_key, self.fingerprint,
            ROOT / "packaging/installer/install.sh.in", candidate=True, **kwargs)

    def test_signed_indexes_include_architecture_and_keyring(self):
        snapshot = self.stage()
        signed = snapshot / "dists/stable/InRelease"
        verified = publish.verified_release(signed, self.public_key)
        self.assertEqual(verified, signed.with_name("Release").read_text())
        self.assertIn("Acquire-By-Hash: yes\n", verified)
        for arch in release.ARCHES:
            index = snapshot / f"dists/stable/main/binary-{arch}/Packages"
            text = index.read_text()
            self.assertIn("Package: httpjet\n", text)
            self.assertIn("Package: httpjet-archive-keyring\n", text)
            self.assertIn(f"Architecture: {arch}\n", text)
            self.assertIn("Architecture: all\n", text)
            self.assertEqual((index.parent / "by-hash/SHA256" / release.sha(index)).read_bytes(),
                             index.read_bytes())

    def test_historical_versions_remain_in_indexes(self):
        previous = self.work / "previous"
        history = previous / "history"
        history.mkdir(parents=True)
        release.write_json(previous / "manifest.json", {"version": "0.0.0"})
        for arch in release.ARCHES:
            self.make_package("httpjet", "0.0.0-1", arch, history)
        snapshot = self.stage(previous=previous)
        for arch in release.ARCHES:
            text = (snapshot / f"dists/stable/main/binary-{arch}/Packages").read_text()
            self.assertIn("Version: 0.0.0-1\n", text)
            self.assertIn("Version: 0.0.1-1\n", text)
            self.assertIn("Package: httpjet-archive-keyring\n", text)

    def test_apt_authenticates_and_downloads_both_fixture_packages(self):
        if not shutil.which("apt-get"):
            self.skipTest("APT client is unavailable")
        snapshot = self.stage()
        self.work.chmod(0o755)
        apt = self.work / "apt-client"
        for directory in ("etc", "state", "cache", "lists/partial", "archives/partial", "log"):
            (apt / directory).mkdir(parents=True, exist_ok=True)
        (apt / "status").touch()
        source = apt / "etc/test.sources"
        source.write_text(
            f"Types: deb\nURIs: {snapshot.as_uri()}\nSuites: stable\nComponents: main\n"
            f"Architectures: amd64\nSigned-By: {self.public_key}\n")
        options = [
            "-o", f"Dir::Etc={apt / 'etc'}",
            "-o", f"Dir::Etc::sourcelist={source}",
            "-o", "Dir::Etc::sourceparts=-",
            "-o", f"Dir::State={apt / 'state'}",
            "-o", f"Dir::State::status={apt / 'status'}",
            "-o", f"Dir::State::lists={apt / 'lists'}",
            "-o", f"Dir::Cache={apt / 'cache'}",
            "-o", f"Dir::Cache::archives={apt / 'archives'}",
            "-o", f"Dir::Log={apt / 'log'}",
            "-o", "APT::Architecture=amd64",
            "-o", "Acquire::Languages=none",
        ]
        command("apt-get", *options, "update", "--error-on=any")
        output = command("apt-get", *options, "--download-only", "--yes", "install",
                         "httpjet=0.0.1-1", "httpjet-archive-keyring")
        self.assertIn("httpjet-archive-keyring", output)
        self.assertIn("httpjet", output)

    def test_candidate_cannot_be_published(self):
        with self.assertRaisesRegex(ValueError, "qualified"):
            publish.verify_snapshot(self.stage(), self.public_key, self.fingerprint)

    def test_stable_requires_vm_qualification(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            release.stage(self.artifacts, self.work / "stable", self.public_key,
                          self.fingerprint, ROOT / "packaging/installer/install.sh.in")

    def test_inrelease_is_published_last(self):
        snapshot = self.stage()
        names = [path.relative_to(snapshot).as_posix()
                 for path in publish.publication_order(snapshot)]
        self.assertEqual(names[-1], "dists/stable/InRelease")
        def immutable(name):
            return name.startswith(("pool/", "releases/")) or "/by-hash/" in name
        first_mutable = next(i for i, name in enumerate(names) if not immutable(name))
        self.assertTrue(all(immutable(name) for name in names[:first_mutable]))
        self.assertFalse(any(immutable(name) for name in names[first_mutable:]))

    def test_rendered_installer_matches_trust_and_is_valid_shell(self):
        installer = self.stage() / "install.sh"
        text = installer.read_text()
        self.assertNotIn("@HTTPJET_", text)
        self.assertIn(self.fingerprint, text)
        self.assertIn(self.public_key.read_text().strip(), text)
        command("sh", "-n", installer)

    def test_fingerprint_mismatch_fails_before_staging(self):
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            release.stage(self.artifacts, self.work / "bad", self.public_key, "0" * 40,
                          ROOT / "packaging/installer/install.sh.in", candidate=True)
        self.assertFalse((self.work / "bad").exists())

    def test_expired_metadata_is_rejected_before_artifact_downloads(self):
        now = datetime.now(timezone.utc)
        document = self.work / "expired.Release"
        signed = self.work / "expired.InRelease"
        document.write_text(
            f"Date: {release.format_datetime(now - timedelta(days=31), usegmt=True)}\n"
            f"Valid-Until: {release.format_datetime(now - timedelta(days=1), usegmt=True)}\n"
            "X-Httpjet-Version: 0.0.1\n"
            f"X-Httpjet-Archive-Fingerprint: {self.fingerprint}\n"
            f"X-Httpjet-Manifest-SHA256: {'0' * 64}\n"
            f"X-Httpjet-Qualification-SHA256: {'0' * 64}\n")
        command("gpg", "--batch", "--yes", "--local-user", self.fingerprint,
                "--clearsign", "--output", signed, document)
        def download_only_inrelease(url, destination):
            self.assertTrue(url.endswith("/dists/stable/InRelease"),
                            "expired metadata triggered an artifact download")
            shutil.copyfile(signed, destination)
        with patch.object(release, "download", side_effect=download_only_inrelease) as download:
            with self.assertRaisesRegex(ValueError, "expired|expiry|Valid-Until|stale"):
                release.fetch_current(release.REPO_URL, self.work / "download",
                                      self.public_key, self.fingerprint)
        self.assertEqual(download.call_count, 1)


if __name__ == "__main__":
    unittest.main()
