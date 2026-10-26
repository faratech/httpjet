#!/usr/bin/env python3
"""Isolated state, archive, signature and privilege-boundary regression tests."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import signal
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("httpjet_generic", HERE / "manage.py")
generic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generic)

class FakeManager(generic.Manager):
    invalid = False
    def account(self, state):
        return (12345, 12345)
    def validate(self, binary, state):
        if self.invalid:
            raise generic.InstallError("invalid candidate configuration")
    def prepare(self, state):
        state["launch_tick"] = 0
        self.save(state)

class GenericStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="httpjet-generic-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manager = FakeManager(self.root / "system")
        self.manager.root.mkdir(mode=0o700)
        self.key = self.root / "public.asc"
        self.key.write_text("TEST ONLY PUBLIC KEY\n")
        self.external = patch.object(generic, "run", return_value=subprocess.CompletedProcess([], 1, "", ""))
        self.external.start()
        self.addCleanup(self.external.stop)

    def payload(self, release):
        root = self.root / ("payload-" + release)
        if root.exists():
            return root
        (root / "bin").mkdir(parents=True)
        (root / "bin/httpjet").write_bytes(b"TEST ONLY ELF " + release.encode())
        (root / "bin/httpjet").chmod(0o755)
        share = root / "share/httpjet"
        shutil.copytree(HERE.parents[0] / "debian/conf", share / "conf")
        shutil.copytree(HERE.parents[0] / "debian/welcome", share / "welcome")
        shutil.copytree(HERE, share / "services", ignore=shutil.ignore_patterns("__pycache__"))
        return root

    def install(self, release):
        self.manager.install(self.payload(release), release, "amd64", "none", "https://example.invalid/releases", self.key, "A" * 40)

    def test_upgrade_and_rollback_preserve_content_config_and_stopped_state(self):
        self.install("1.0.0-1")
        configuration = self.manager.path("/etc/httpjet/conf/httpd_config.xml")
        configuration.write_text("operator configuration\n")
        page = self.manager.path("/var/www/httpjet/index.html")
        page.write_text("operator content\n")
        self.install("1.1.0-2")
        state = self.manager.load()
        self.assertEqual(state["current"], "1.1.0-2")
        self.assertEqual(state["previous"], "1.0.0-1")
        self.assertEqual(configuration.read_text(), "operator configuration\n")
        self.assertEqual(page.read_text(), "operator content\n")
        self.assertEqual(self.manager.link.resolve(), self.manager.prefix / "releases/1.1.0-2/bin/httpjet")
        self.manager.install(self.manager.prefix / "releases/1.0.0-1", "1.0.0-1", "amd64", "none",
                             state["base"], self.manager.state_dir / "archive.asc", "A" * 40)
        self.assertEqual(self.manager.load()["current"], "1.0.0-1")
        self.assertEqual(page.read_text(), "operator content\n")

    def test_invalid_upgrade_keeps_previous_pointer(self):
        self.install("1.0.0-1")
        before = os.readlink(self.manager.link)
        self.manager.invalid = True
        with self.assertRaisesRegex(generic.InstallError, "invalid candidate"):
            self.install("1.1.0-1")
        self.assertEqual(os.readlink(self.manager.link), before)
        self.assertEqual(self.manager.load()["current"], "1.0.0-1")

    def test_no_unmanaged_or_native_takeover(self):
        binary = self.manager.path("/usr/local/bin/httpjet")
        binary.parent.mkdir(parents=True)
        binary.write_text("unmanaged\n")
        with self.assertRaisesRegex(generic.InstallError, "unmanaged"):
            self.install("1.0.0-1")
        self.assertEqual(binary.read_text(), "unmanaged\n")
        binary.unlink()
        with patch.object(generic, "run", return_value=subprocess.CompletedProcess([], 0, "install ok installed", "")):
            with self.assertRaisesRegex(generic.InstallError, "native"):
                self.install("1.0.0-1")

    def test_replaced_pointer_and_changed_privileged_helper_refuse_upgrade(self):
        self.install("1.0.0-1")
        self.manager.link.unlink()
        self.manager.link.symlink_to(self.key)
        with self.assertRaisesRegex(generic.InstallError, "link was replaced"):
            self.install("1.1.0-1")
        self.manager.link.unlink()
        self.manager.pointer("1.0.0-1")
        (self.manager.prefix / "libexec/launch").write_text("operator modified helper\n")
        with self.assertRaisesRegex(generic.InstallError, "modified a privileged helper"):
            self.install("1.2.0-1")

    def test_uninstall_preserves_sites_and_modified_release(self):
        self.install("1.0.0-1")
        page = self.manager.path("/var/www/httpjet/index.html")
        original = page.read_bytes()
        binary = self.manager.prefix / "releases/1.0.0-1/bin/httpjet"
        binary.write_text("operator modified binary\n")
        self.manager.uninstall(self.manager.load())
        self.assertFalse(self.manager.link.is_symlink())
        self.assertEqual(page.read_bytes(), original)
        self.assertTrue(binary.exists())
        self.assertIsNone(self.manager.load()["current"])

    def test_private_state_modes_and_uid_cutoff_not_used(self):
        self.install("1.0.0-1")
        self.assertEqual(self.manager.load()["uid"], 12345)
        self.assertEqual(self.manager.state_file.stat().st_mode & 0o777, 0o600)
        self.manager.state_file.chmod(0o644)
        with self.assertRaisesRegex(generic.InstallError, "private"):
            self.manager.load()

    def test_failed_activation_rolls_back_running_version_and_remains_retryable(self):
        self.install("1.0.0-1")
        self.manager.active = True
        self.manager.running = lambda state: self.manager.active
        calls = []
        def service(action, state):
            calls.append((action, state["current"]))
            self.manager.active = action == "start"
            if action == "start" and state["current"] == "1.1.0-1":
                raise generic.InstallError("candidate not ready")
        self.manager.service = service
        with self.assertRaisesRegex(generic.InstallError, "candidate not ready"):
            self.install("1.1.0-1")
        state = self.manager.load()
        self.assertEqual(state["current"], "1.0.0-1")
        self.assertIn("1.1.0-1", state["versions"])
        self.assertTrue(self.manager.active)
        self.assertEqual(calls[-1], ("start", "1.0.0-1"))
        self.assertEqual(self.manager.link.resolve(), self.manager.prefix / "releases/1.0.0-1/bin/httpjet")

    def test_readiness_requires_exact_pid_private_file_and_fresh_start(self):
        runtime = self.manager.ready.parent
        runtime.mkdir(parents=True)
        self.manager.ready.write_bytes(b"123\n")
        self.manager.ready.chmod(0o600)
        state = {"uid": os.geteuid()}
        process = {"pid": 123, "started": 200, "executable": "test-only"}
        with patch.object(self.manager, "process", return_value=process):
            self.assertEqual(self.manager.ready_identity(state, 200), process)
            self.assertIsNone(self.manager.ready_identity(state, 201))
            self.manager.ready.chmod(0o644)
            self.assertIsNone(self.manager.ready_identity(state))
            self.manager.ready.chmod(0o600)
            self.manager.ready.write_bytes(b"123\nextra")
            self.assertIsNone(self.manager.ready_identity(state))
        self.manager.ready.unlink()
        self.manager.ready.symlink_to(self.key)
        self.assertIsNone(self.manager.ready_identity(state))

    def test_stop_does_not_signal_reused_pid(self):
        state = {"uid": 12345, "process": {"pid": 123, "started": 100, "executable": "old"}}
        with patch.object(self.manager, "ready_identity", return_value=None), patch.object(self.manager, "process", return_value={"pid": 123, "started": 200, "executable": "other"}), patch.object(generic.os, "kill") as kill:
            self.manager.stop_exact(state)
            kill.assert_not_called()

    def test_initialization_failure_resumes_and_keeps_admin_edits(self):
        with patch.object(self.manager, "initialize_defaults", side_effect=generic.InstallError("interrupted before config")):
            with self.assertRaisesRegex(generic.InstallError, "interrupted"):
                self.install("1.0.0-1")
        self.assertFalse(self.manager.load()["initialized"])
        configuration = self.manager.path("/etc/httpjet/conf/httpd_config.xml")
        configuration.parent.mkdir(parents=True)
        configuration.write_text("administrator recovered config\n")
        self.install("1.0.0-1")
        self.assertEqual(configuration.read_text(), "administrator recovered config\n")
        self.assertTrue(self.manager.load()["initialized"])
        self.assertEqual(self.manager.load()["current"], "1.0.0-1")

    def test_root_umask_does_not_make_public_program_directories_private(self):
        before = os.umask(0o077)
        try:
            self.install("1.0.0-1")
        finally:
            os.umask(before)
        for relative in ("/opt/httpjet", "/opt/httpjet/releases", "/usr/local/bin", "/etc/httpjet/conf"):
            self.assertEqual(self.manager.path(relative).stat().st_mode & 0o777, 0o755)

    def test_slackware_hooks_preserve_mode_bytes_and_disabled_optout(self):
        directory = self.manager.path("/etc/rc.d")
        directory.mkdir(parents=True)
        original = b"#!/bin/sh\necho administrator\n\n"
        local = directory / "rc.local"
        local.write_bytes(original)
        local.chmod(0o750)
        shutdown = directory / "rc.local_shutdown"
        shutdown.write_bytes(b"#!/bin/sh\necho shutdown\n")
        shutdown.chmod(0o700)
        self.manager.slackware_hooks(True)
        self.assertEqual(local.stat().st_mode & 0o777, 0o750)
        self.assertEqual(shutdown.stat().st_mode & 0o777, 0o700)
        self.assertTrue(local.read_bytes().startswith(original))
        self.manager.slackware_hooks(False)
        self.assertEqual(local.read_bytes(), original)
        local.chmod(0o640)
        with self.assertRaisesRegex(generic.InstallError, "non-executable"):
            self.manager.slackware_hooks(True)
        self.assertEqual(local.stat().st_mode & 0o777, 0o640)
        self.assertEqual(local.read_bytes(), original)

    def test_validate_initializes_target_groups_without_caller_groups(self):
        manager = generic.Manager(self.manager.root)
        with patch.object(generic, "run") as command, patch.object(generic.os, "initgroups") as groups, patch.object(generic.os, "setgid") as gid, patch.object(generic.os, "setuid") as uid, patch.object(generic.os, "setgroups") as caller_groups:
            manager.validate(self.key, {"uid": 12345, "gid": 22222})
            command.call_args.kwargs["preexec_fn"]()
            groups.assert_called_once_with("httpjet", 22222)
            gid.assert_called_once_with(22222)
            uid.assert_called_once_with(12345)
            caller_groups.assert_not_called()

    def test_launch_preserves_only_notify_and_target_group_initialization(self):
        class Identity:
            def lstat(self): return SimpleNamespace(st_mode=0o100644, st_uid=0, st_nlink=1)
            def read_text(self): return '{"uid":12345,"gid":22222}'
        class Ready:
            def exists(self): return False
            def is_symlink(self): return False
            def __str__(self): return '/run/httpjet/ready'
        with patch.object(generic, "Path", side_effect=lambda value: Identity() if value.endswith('identity.json') else Ready()), patch.object(generic.os, "geteuid", return_value=0), patch.object(generic.os, "umask"), patch.object(generic.shutil, "which", return_value="/usr/bin/setpriv"), patch.object(generic.os, "execve") as execute, patch.dict(os.environ, {"NOTIFY_SOCKET":"@test-notify","PRIVATE_API_TOKEN":"do-not-forward"}, clear=True):
            generic.launch()
            arguments, environment = execute.call_args.args[1:]
            self.assertIn("--init-groups", arguments)
            self.assertNotIn("--clear-groups", arguments)
            self.assertIn("--no-multishot-accept", arguments)
            self.assertEqual(environment["NOTIFY_SOCKET"], "@test-notify")
            self.assertEqual(set(environment), {"PATH","HTTPJET_LOG_DIR","RUST_LOG","NOTIFY_SOCKET"})

    def test_process_matches_current_release_and_recovers_recorded_live_pid(self):
        self.install("1.0.0-1")
        self.install("1.1.0-1")
        proc = self.manager.path("/proc/123")
        proc.mkdir(parents=True)
        (proc / "status").write_text("Uid:\t12345\t12345\t12345\t12345\nGid:\t12345\t12345\t12345\t12345\n")
        fields = ["S"] + ["0"] * 19
        fields[19] = "200"
        (proc / "stat").write_text("123 (httpjet) " + " ".join(fields))
        (proc / "cmdline").write_bytes(b"httpjet\0--ready-file\0" + str(self.manager.ready).encode() + b"\0")
        (proc / "exe").symlink_to(self.manager.prefix / "releases/1.0.0-1/bin/httpjet")
        state = self.manager.load()
        with self.assertRaisesRegex(generic.InstallError, "different release"):
            self.manager.process(123, state)
        (proc / "exe").unlink()
        (proc / "exe").symlink_to(self.manager.prefix / "releases/1.1.0-1/bin/httpjet")
        identity = self.manager.process(123, state)
        self.assertEqual(identity["started"], 200)
        state["process"] = identity
        self.assertTrue(self.manager.running(state))

    def test_no_root_log_open_follows_worker_symlink(self):
        self.install("1.0.0-1")
        log = self.manager.path("/var/log/httpjet/service.log")
        log.parent.mkdir(parents=True)
        log.symlink_to(self.key)
        before = self.key.read_bytes()
        with patch.object(generic.subprocess, "Popen") as spawn, patch.object(self.manager, "wait_ready"):
            self.manager.direct_start(self.manager.load())
            self.assertEqual(spawn.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(spawn.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(self.key.read_bytes(), before)

    def test_owned_nss_identity_above_uid_1000_is_valid(self):
        def query(command, **kwargs):
            text = "httpjet:x:70000:70001::/var/lib/httpjet:/sbin/nologin\n" if command[1] == "passwd" else "httpjet:x:70001:\n"
            return subprocess.CompletedProcess(command, 0, text, "")
        with patch.object(generic.shutil, "which", return_value="/usr/bin/getent"), patch.object(generic, "run", side_effect=query):
            self.assertEqual(generic.Manager(self.manager.root).account({"uid":70000,"gid":70001}), (70000,70001))

    def test_immutable_same_version_cannot_replace_bytes(self):
        self.install("1.0.0-1")
        (self.payload("1.0.0-1") / "bin/httpjet").write_text("changed signed payload same version")
        with self.assertRaisesRegex(generic.InstallError, "immutable"):
            self.install("1.0.0-1")

    @unittest.skipUnless(hasattr(os,"pidfd_open") and hasattr(signal,"pidfd_send_signal"), "pidfd API unavailable")
    def test_pidfd_signals_only_our_owned_test_child(self):
        process = subprocess.Popen(["sleep","30"])
        identity = {"pid":process.pid,"started":100,"executable":"test-only"}
        try:
            with patch.object(self.manager,"ready_identity",return_value=identity), patch.object(self.manager,"process",side_effect=lambda pid,state: identity if process.poll() is None else None), patch.object(generic.os,"kill") as legacy_signal:
                self.manager.stop_exact({})
                legacy_signal.assert_not_called()
            self.assertEqual(process.wait(timeout=3), -signal.SIGTERM)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)

class ArchiveBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="httpjet-extract-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def archive(self, members):
        destination = self.root / "payload.tar.gz"
        with tarfile.open(destination, "w:gz") as output:
            for name, kind in members:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = 1
                    output.addfile(member, io.BytesIO(b"x"))
                else:
                    member.linkname = "/etc/shadow"
                    output.addfile(member)
        return destination

    def test_traversal_links_devices_and_duplicates_fail_before_extract(self):
        cases = [([(name, tarfile.REGTYPE)], "path") for name in ("/absolute", "httpjet-1.0.0-1/../outside", "httpjet-1.0.0-1/a\\b", "httpjet-1.0.0-1/./x")]
        cases += [([("httpjet-1.0.0-1/link", kind)], "unsupported") for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE)]
        cases.append(([('httpjet-1.0.0-1/a', tarfile.REGTYPE)] * 2, "duplicate"))
        for number, (members, message) in enumerate(cases):
            with self.subTest(members=members):
                target = self.root / str(number)
                with self.assertRaises(generic.InstallError):
                    generic.safe_extract(self.archive(members), target, "1.0.0-1")
                self.assertEqual(list(target.iterdir()), [])

    def test_busybox_setpriv_fails_closed_without_ambient_support(self):
        with patch.object(generic.shutil, "which", return_value="/bin/setpriv"), patch.object(generic, "run", return_value=subprocess.CompletedProcess([], 0, "BusyBox setpriv --reuid", "")):
            with self.assertRaisesRegex(generic.InstallError, "ambient"):
                generic.require_cap_launcher()

    def test_bad_hash_never_enters_extraction(self):
        name = "httpjet-1.0.0-1-linux-amd64-static.tar.gz"
        document = {"schema": 2, "release_id": "1.0.0-1", "archive_fingerprint": "A" * 40,
                    "binaries": {"amd64": {"artifact": name, "libc": "musl", "binary_sha256": "0" * 64}},
                    "artifacts": {name: {"architecture": "amd64", "libc": "musl", "sha256": "0" * 64, "size": 3}}}
        def download(url, path, limit):
            path.write_text(json.dumps(document) if url.endswith("manifest.json") else "bad")
        with patch.object(generic, "download", side_effect=download), patch.object(generic, "verify_signature"), patch.object(generic, "safe_extract") as extract:
            with self.assertRaisesRegex(generic.InstallError, "hash/size"):
                generic.fetch_release("https://example.invalid/releases", "1.0.0-1", "amd64", self.root / "key", "A" * 40, self.root)
            extract.assert_not_called()

class RealSignatureTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("gpg"), "full GPG unavailable")
    def test_real_public_key_signature_then_modified_document_rejection(self):
        with tempfile.TemporaryDirectory(prefix="httpjet-signature-test-") as temporary:
            root = Path(temporary)
            home = root / "signer"
            home.mkdir(mode=0o700)
            command = ["gpg", "--batch", "--homedir", str(home)]
            try:
                subprocess.run(command + ["--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "httpjet TEST ONLY <test@example.invalid>", "ed25519", "sign", "1d"], check=True, capture_output=True)
                metadata = subprocess.run(command + ["--with-colons", "--list-keys"], check=True, capture_output=True, text=True).stdout
                fingerprint = next(line.split(":")[9] for line in metadata.splitlines() if line.startswith("fpr:"))
                key = root / "public.asc"
                key.write_bytes(subprocess.run(command + ["--armor", "--export"], check=True, capture_output=True).stdout)
                document, signature_file = root / "manifest.json", root / "manifest.json.asc"
                document.write_text('{"test_only":true}\n')
                subprocess.run(command + ["--armor", "--detach-sign", "--output", str(signature_file), str(document)], check=True, capture_output=True)
                generic.verify_signature(document, signature_file, key, fingerprint, root / "verifier")
                document.write_text('{"modified":true}\n')
                with self.assertRaises(subprocess.CalledProcessError):
                    generic.verify_signature(document, signature_file, key, fingerprint, root / "verifier")
                with self.assertRaisesRegex(generic.InstallError, "fingerprint"):
                    generic.verify_signature(document, signature_file, key, "0" * 40, root / "other")
            finally:
                subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)

if __name__ == "__main__":
    unittest.main()
