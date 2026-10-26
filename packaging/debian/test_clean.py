#!/usr/bin/env python3
"""Verify Debian cleanup preserves Cargo's immutable vendored input files."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]


class VendoredCleanup(unittest.TestCase):
    def test_initial_and_final_clean_preserve_registry_checksums(self):
        with tempfile.TemporaryDirectory(prefix="httpjet-clean-test-") as temporary:
            root = Path(temporary)
            shutil.copytree(REPO / "debian", root / "debian", ignore=shutil.ignore_patterns(
                ".debhelper", "build", "httpjet", "httpjet-archive-keyring", "*.substvars",
                "*.debhelper", "files", "debhelper-build-stamp"))
            crate = root / "vendor/registry/fixture"
            (crate / "tests").mkdir(parents=True)
            files = {"Cargo.toml.orig": b"[package]\nname='fixture'\n",
                     "tests/reference.orig": b"upstream fixture input\n"}
            expected = {}
            for relative, content in files.items():
                (crate / relative).write_bytes(content)
                expected[relative] = hashlib.sha256(content).hexdigest()
            (crate / ".cargo-checksum.json").write_text(json.dumps({"files": expected}))
            for _ in range(2):
                (root / "project-junk.orig").write_text("disposable project build output\n")
                (root / "debian/build").mkdir(exist_ok=True)
                (root / "debian/build/httpjet").write_text("disposable binary\n")
                result = subprocess.run(["make", "-f", "debian/rules", "clean"], cwd=root,
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((root / "project-junk.orig").exists())
                self.assertFalse((root / "debian/build").exists())
                for relative, checksum in expected.items():
                    self.assertEqual(hashlib.sha256((crate / relative).read_bytes()).hexdigest(), checksum)


if __name__ == "__main__":
    unittest.main()
