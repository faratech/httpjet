#!/usr/bin/env python3
"""Mock installer host operations inside a disposable filesystem and PATH."""

import json
import os
from pathlib import Path
import subprocess
import sys
import shutil
import tempfile
import unittest


TEMPLATE = Path(__file__).with_name("install.sh.in")
KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nNOT-A-REAL-KEY\n-----END PGP PUBLIC KEY BLOCK-----"
WELCOME = b"<!doctype html><title>httpjet</title><h1>Welcome to httpjet</h1>\n"
MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
state = json.loads(pathlib.Path(os.environ["MOCK_STATE"]).read_text())
with open(os.environ["MOCK_LOG"], "a") as log:
    log.write(json.dumps([name] + args) + "\n")
if name == "id": print(state.get("uid", "0"))
elif name == "uname": print(state.get("kernel", "Linux") if args == ["-s"] else state.get("machine", "x86_64"))
elif name == "dpkg": print(state.get("architecture", "amd64"))
elif name == "dpkg-query":
    if args[0] == "-W":
        status = state.get("package_status", "install ok installed" if state.get("managed") else "")
        if not status: sys.exit(1)
        print(status, end="")
    elif args[0] == "-S" and state.get("owned_key"): print("httpjet-archive-keyring: " + args[1])
    else: sys.exit(1)
elif name == "systemctl":
    if args[0] == "show":
        if state.get("systemd_failure"): sys.exit(1)
        print("255" if "--property=Version" in args else state.get("load_state", "not-found"))
    elif args[0] == "is-active": sys.exit(0 if state.get("active", True) else 3)
    else: raise SystemExit("unexpected mutating systemctl command: " + repr(args))
elif name == "ss":
    if state.get("ss_failure"): sys.exit(1)
    if state.get("port_busy"): print("LISTEN 0 511 0.0.0.0:80 0.0.0.0:*")
elif name == "apt-get":
    if args[0] == "update" and state.get("apt_update_failure"): sys.exit(100)
    if args[0] == "install" and state.get("apt_install_failure"): sys.exit(100)
elif name == "curl":
    if state.get("curl_failure"): sys.exit(7)
    pathlib.Path(args[args.index("--output") + 1]).write_bytes(bytes.fromhex(state["welcome"]) if not state.get("wrong_welcome") else b"another website")
    print(state.get("http_status", "200"), end="")
elif name == "timeout": sys.exit(subprocess.run(args[3:] if args[0] == "-k" else args[2:] if args[0].startswith("--kill-after=") else args[1:]).returncode)
elif name == "rpm":
    if args[0] == "--import": pass
    elif args[0] == "--eval": print(state.get("rpm_compare", "0"))
    elif args[0] == "-qf":
        if not state.get("owned_rpm_key"): sys.exit(1)
        print("httpjet-archive-keyring", end="")
    elif args[0] == "-q" and state.get("rpm_managed"):
        print(state.get("rpm_version", "0.1.0-1") if "--qf" in args else "httpjet-0.1.0-1", end="")
    else: sys.exit(1)
elif name in ("dnf", "yum", "zypper"):
    if state.get("rpm_signature_failure"): sys.exit(1)
elif name == "setpriv":
    print("BusyBox setpriv" if state.get("busybox_setpriv") else "--ambient-caps --inh-caps --bounding-set --reuid --clear-groups")
elif name == "gpg": print("GnuPG")
elif name == "python3":
    if "-c" in args and 'json.load' in args[args.index("-c") + 1]: print(state.get("recorded_init", "none"))
    else: print("mock Python helper")
elif name == "journalctl": print("mock bounded service diagnostics")
elif name == "sleep": pass
else: raise SystemExit("unexpected command: " + name)
'''


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="httpjet-installer-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "root"
        self.bin = Path(self.temporary.name) / "bin"
        self.bin.mkdir()
        for path in ("etc/ssl/certs", "run/systemd/system", "tmp", "usr/share/httpjet/welcome"):
            (self.root / path).mkdir(parents=True)
        self.os_release = self.root / "etc/os-release"
        self.os_release.write_text('ID=debian\nVERSION_ID="12"\nVERSION="12 (bookworm)"\n')
        (self.root / "etc/ssl/certs/ca-certificates.crt").write_text("test trust store\n")
        (self.root / "usr/share/httpjet/welcome/index.html").write_bytes(WELCOME)
        mock = self.bin / "mock-command"
        mock.write_text(MOCK.replace("/usr/bin/env python3", sys.executable))
        mock.chmod(0o755)
        for command in ("id", "uname", "dpkg", "dpkg-query", "systemctl", "ss", "apt-get", "curl", "timeout", "journalctl", "sleep", "rpm", "dnf", "yum", "zypper", "setpriv", "gpg"):
            (self.bin / command).symlink_to(mock)
        self.state_path = Path(self.temporary.name) / "state.json"
        self.log_path = Path(self.temporary.name) / "calls.jsonl"
        self.script_path = Path(self.temporary.name) / "install.sh"

    def run_installer(self, *args, unrendered=False, **state):
        state.setdefault("welcome", WELCOME.hex())
        self.state_path.write_text(json.dumps(state))
        self.log_path.write_text("")
        text = TEMPLATE.read_text()
        if not unrendered:
            text = text.replace("@HTTPJET_ARCHIVE_PUBLIC_KEY@", KEY)
            text = text.replace("@HTTPJET_ARCHIVE_KEY_FINGERPRINT@", "A" * 40)
            text = text.replace("@HTTPJET_REPOSITORY_URL@", "https://packages.httpjet.net/apt")
            text = text.replace("@HTTPJET_RELEASE_BASE_URL@", "https://packages.httpjet.net/releases")
            text = text.replace("@HTTPJET_INSTALLER_PYTHON@", "# mocked signed-download controller")
        if state.get("generic_mock") and not (self.bin / "python3").exists():
            (self.bin / "python3").symlink_to(self.bin / "mock-command")
        text = text.replace("FILESYSTEM_ROOT=''", f"FILESYSTEM_ROOT='{self.root}'")
        text = text.replace("PATH='/usr/sbin:/usr/bin:/sbin:/bin'", f"PATH='{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin'")
        if state.get("busybox_shell"):
            # Some BusyBox ash builds resolve applets (such as id and dpkg)
            # before PATH. Explicit functions keep every mocked operation in
            # the fixture while exercising the real BusyBox shell parser.
            names = sorted(path.name for path in self.bin.iterdir()
                           if path.is_symlink() and path.name.isidentifier())
            functions = ''.join(f'{name}() {{ "{self.bin / name}" "$@"; }}\n' for name in names)
            text = text.replace('#!/bin/sh\n', '#!/bin/sh\n' + functions, 1)
        if state.get("missing_ss"):
            text = text.replace("command -v ss >/dev/null 2>&1", "false")
        self.script_path.write_text(text)
        env = dict(os.environ, MOCK_STATE=str(self.state_path), MOCK_LOG=str(self.log_path))
        runner = [shutil.which("busybox"), "sh"] if state.get("busybox_shell") else ["/bin/sh"]
        result = subprocess.run([*runner, str(self.script_path), *args], env=env, text=True, capture_output=True, timeout=15)
        calls = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        return result, calls

    def assert_no_apt(self, calls):
        self.assertFalse(any(call[0] == "apt-get" for call in calls), calls)
        self.assertFalse((self.root / "etc/apt/sources.list.d/httpjet.sources").exists())

    def assert_clean(self):
        self.assertEqual(list((self.root / "tmp").iterdir()), [])
        self.assertFalse(list(self.root.rglob(".httpjet-install.*")))

    def test_fresh_install_uses_scoped_signed_archive_and_exact_http_probe(self):
        result, calls = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("welcome page passed", result.stdout)
        source = (self.root / "etc/apt/sources.list.d/httpjet.sources").read_text()
        self.assertEqual(source, "Types: deb\nURIs: https://packages.httpjet.net/apt\nSuites: stable\nComponents: main\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/httpjet-archive-keyring.asc\n")
        self.assertNotIn("Trusted:", source)
        self.assertEqual((self.root / "usr/share/keyrings/httpjet-archive-keyring.asc").read_text(), KEY + "\n")
        self.assertEqual((self.root / "usr/share/keyrings").stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.root / "etc/apt/sources.list.d").stat().st_mode & 0o777, 0o755)
        self.assertEqual([call for call in calls if call[:2] == ["apt-get", "install"]], [["apt-get", "install", "--yes", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "httpjet-archive-keyring", "httpjet"]])
        self.assertTrue(any(call[0] == "curl" and "--noproxy" in call and "--max-time" in call for call in calls))
        self.assertFalse(any(call[0] == "journalctl" for call in calls))
        self.assert_clean()

    def test_managed_rerun_keeps_custom_sites_and_stopped_service(self):
        config = self.root / "etc/httpjet/conf/httpd_config.xml"
        config.parent.mkdir(parents=True)
        config.write_text("custom configuration\n")
        content = self.root / "var/www/httpjet/index.html"
        content.parent.mkdir(parents=True)
        content.write_text("custom website\n")
        result, calls = self.run_installer(managed=True, active=False, port_busy=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(config.read_text(), "custom configuration\n")
        self.assertEqual(content.read_text(), "custom website\n")
        self.assertTrue(any("Dpkg::Options::=--force-confold" in call for call in calls))
        self.assertFalse(any(call[0] in ("curl", "ss") or call[:2] == ["systemctl", "is-active"] for call in calls))
        self.assertFalse(any(call[0] == "systemctl" and call[1] in ("start", "stop", "restart", "enable", "disable") for call in calls))
        source = self.root / "etc/apt/sources.list.d/httpjet.sources"
        before = source.stat().st_mtime_ns
        result, _ = self.run_installer(managed=True, active=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.stat().st_mtime_ns, before)
        self.assert_clean()

    def test_version_pin_and_invalid_arguments(self):
        result, calls = self.run_installer("--version", "0.12.3-2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("httpjet=0.12.3-2" in call and "--allow-downgrades" in call for call in calls))
        for args in (("--version", "1.2.3;touch"), ("--version", "1.2.3-N"), ("--version",), ("--unknown",), ("--version", "1.2.3-1", "--version", "2.0.0-1")):
            with self.subTest(args=args):
                result, calls = self.run_installer(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call[0] == "apt-get" for call in calls))

    def test_distribution_version_does_not_replace_unpinned_or_pinned_package(self):
        for args, expected in (((), "httpjet"), (("--version", "0.12.3-2"), "httpjet=0.12.3-2")):
            with self.subTest(args=args):
                result, calls = self.run_installer(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                installation = next(call for call in calls if call[:2] == ["apt-get", "install"])
                self.assertEqual(installation[-1], expected)

    def test_distribution_and_architecture_matrix(self):
        for distro, version in (("debian", "12"), ("debian", "13"), ("ubuntu", "24.04"), ("ubuntu", "26.04")):
            for arch, machine in (("amd64", "x86_64"), ("arm64", "aarch64")):
                with self.subTest(distro=distro, version=version, arch=arch):
                    self.os_release.write_text(f'ID={distro}\nVERSION_ID="{version}"\n')
                    source = self.root / "etc/apt/sources.list.d/httpjet.sources"
                    source.unlink(missing_ok=True)
                    result, _ = self.run_installer(architecture=arch, machine=machine)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"Architectures: {arch}\n", source.read_text())

    def test_root_platform_and_systemd_failures_precede_changes(self):
        for state in ({"uid": "1000"}, {"kernel": "Darwin"}, {"architecture": "riscv64", "machine": "riscv64"}, {"architecture": "arm64", "machine": "x86_64"}, {"systemd_failure": True}):
            with self.subTest(state=state):
                result, calls = self.run_installer(**state)
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_apt(calls)
        self.os_release.write_text('ID=nixos\nVERSION_ID="26.05"\n')
        result, calls = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_apt(calls)

    def test_busy_port_refused_before_missing_prerequisites(self):
        (self.root / "etc/ssl/certs/ca-certificates.crt").unlink()
        result, calls = self.run_installer(port_busy=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("will not stop", result.stderr)
        self.assert_no_apt(calls)

    def test_proc_fallback_detects_ipv6_listener_before_dependency_install(self):
        proc = self.root / "proc/net"
        proc.mkdir(parents=True)
        (proc / "tcp").write_text("sl local_address rem_address st\n")
        (proc / "tcp6").write_text("0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A\n")
        result, calls = self.run_installer(missing_ss=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TCP port 80 is occupied", result.stderr)
        self.assert_no_apt(calls)
        (proc / "tcp6").write_text("sl local_address rem_address st\n")
        result, calls = self.run_installer(missing_ss=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["apt-get", "install", "--yes", "--no-install-recommends", "ca-certificates", "curl", "iproute2"], calls)

    def test_failed_port_inspection_and_incomplete_package_are_refused(self):
        for state in ({"ss_failure": True}, {"missing_ss": True}, {"package_status": "install ok unpacked"}):
            with self.subTest(state=state):
                result, calls = self.run_installer(**state)
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_apt(calls)

    def test_key_rotation_requires_existing_keyring_package_ownership(self):
        key = self.root / "usr/share/keyrings/httpjet-archive-keyring.asc"
        key.parent.mkdir(parents=True)
        key.write_text("an unknown pre-existing key\n")
        result, calls = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unmanaged archive key", result.stderr)
        self.assert_no_apt(calls)
        self.assertEqual(key.read_text(), "an unknown pre-existing key\n")
        result, _ = self.run_installer(owned_key=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(key.read_text(), "an unknown pre-existing key\n")

    def test_unmanaged_paths_and_units_are_preserved(self):
        for relative in ("etc/httpjet", "usr/local/httpjet/bin/httpjet", "etc/systemd/system/httpjet.service", "var/www/httpjet"):
            with self.subTest(path=relative):
                existing = self.root / relative
                existing.parent.mkdir(parents=True, exist_ok=True)
                existing.write_text("preserve this\n")
                result, calls = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unmanaged", result.stderr)
                self.assertEqual(existing.read_text(), "preserve this\n")
                self.assert_no_apt(calls)
                existing.unlink()
        result, calls = self.run_installer(load_state="loaded")
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_apt(calls)

    def test_template_fails_without_host_commands_but_help_works(self):
        result, calls = self.run_installer(unrendered=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assert_clean()
        result, calls = self.run_installer("--help", unrendered=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stdout)
        self.assertEqual(calls, [])

    def test_different_repo_or_symlink_destination_is_preserved(self):
        source = self.root / "etc/apt/sources.list.d/httpjet.sources"
        source.parent.mkdir(parents=True)
        source.write_text("custom repository\n")
        result, calls = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(source.read_text(), "custom repository\n")
        self.assertFalse(any(call[0] == "apt-get" for call in calls))
        source.unlink()
        target = self.root / "elsewhere"
        target.write_text("leave this alone\n")
        source.symlink_to(target)
        result, calls = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic-link", result.stderr)
        self.assertEqual(target.read_text(), "leave this alone\n")
        self.assertFalse(any(call[0] == "apt-get" for call in calls))
        self.assert_clean()

    def test_apt_failure_reports_bounded_journal_and_cleans_temporaries(self):
        result, calls = self.run_installer(apt_install_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("APT could not install", result.stderr)
        self.assertIn(["journalctl", "--unit", "httpjet.service", "--lines", "40", "--no-pager"], calls)
        self.assertFalse(any(call[0] == "curl" for call in calls))
        self.assert_clean()

    def test_unverified_metadata_stops_before_package_install(self):
        result, calls = self.run_installer(apt_update_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verify or refresh", result.stderr)
        self.assertFalse(any(call[:2] == ["apt-get", "install"] for call in calls))
        self.assertFalse((self.root / "etc/apt/sources.list.d/httpjet.sources").exists())
        self.assertFalse((self.root / "usr/share/keyrings/httpjet-archive-keyring.asc").exists())
        self.assert_clean()

    def test_wrong_welcome_non200_and_unready_service_fail_with_bound(self):
        for state in ({"wrong_welcome": True}, {"http_status": "201"}, {"active": False}):
            with self.subTest(state=state):
                result, calls = self.run_installer(**state)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("bounded startup check", result.stderr)
                self.assertEqual(sum(call[:2] == ["systemctl", "is-active"] for call in calls), 15)
                self.assertTrue(any(call[0] == "journalctl" for call in calls))
                self.assert_clean()


    def test_no_distro_version_allowlist(self):
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="999.123"\nVERSION="future metadata"\n')
        result, calls = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(call[:2] == ["apt-get", "install"] for call in calls))

    @unittest.skipUnless(shutil.which("busybox"), "BusyBox unavailable")
    def test_real_busybox_shell_and_timeout_flags(self):
        result, _ = self.run_installer(busybox_shell=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result, calls = self.run_installer(busybox_shell=True, uid="1000")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("run installer as root", result.stderr)
        self.assertFalse(any(call[0] == "apt-get" for call in calls))
        result = subprocess.run([shutil.which("busybox"), "timeout", "-k", "1", "1", "true"], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generic_unknown_family_requires_explicit_none_then_dispatches(self):
        self.os_release.write_text('ID=customlinux\nVERSION_ID="rolling"\n')
        (self.root / "run/systemd/system").rmdir()
        result, calls = self.run_installer("--method", "binary", generic_mock=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown init", result.stderr)
        self.assert_no_apt(calls)
        result, calls = self.run_installer("--method", "binary", "--init", "none", "--version", "1.2.3-2", generic_mock=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        command = next(call for call in calls if call[0] == "python3" and "bootstrap" in call)
        self.assertIn("none", command)
        self.assertIn("1.2.3-2", command)
        self.assertFalse(any(call[0] in ("apt-get", "dnf") for call in calls))

    def test_generic_native_takeover_and_busybox_setpriv_fail_closed(self):
        result, calls = self.run_installer("--method", "binary", "--init", "none", managed=True, generic_mock=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native APT", result.stderr)
        self.assert_no_apt(calls)
        result, calls = self.run_installer("--method", "binary", "--init", "none", busybox_setpriv=True, generic_mock=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BusyBox setpriv", result.stderr)
        self.assertFalse(any(call[0] == "python3" and "bootstrap" in call for call in calls))

    def test_rpm_checks_both_signatures_and_pin(self):
        self.os_release.write_text('ID=fedora\nVERSION_ID="999"\n')
        result, calls = self.run_installer("--version", "1.2.3-2")
        self.assertEqual(result.returncode, 0, result.stderr)
        source = (self.root / "etc/yum.repos.d/httpjet.repo").read_text()
        self.assertIn("repo_gpgcheck=1\n", source)
        self.assertIn("gpgcheck=1\n", source)
        self.assertIn("pkg_gpgcheck=1\n", source)
        self.assertIn("baseurl=https://packages.httpjet.net/rpm/x86_64", source)
        installs = [call for call in calls if call[0] == "dnf" and "install" in call]
        self.assertEqual(len(installs), 1)
        self.assertIn("httpjet-1.2.3-2", installs[0])
        self.assertIn("--setopt=httpjet.repo_gpgcheck=1", installs[0])

    def test_rpm_signature_failure_no_unsigned_or_generic_fallback(self):
        self.os_release.write_text('ID=fedora\nVERSION_ID="999"\n')
        result, calls = self.run_installer(rpm_signature_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == "dnf" and "install" in call for call in calls))
        self.assertFalse(any("--nogpgcheck" in call or "--allow-unauthenticated" in call for call in calls))

    def test_zypper_uses_zypp_directory_and_oldpackage(self):
        self.os_release.write_text('ID=opensuse-tumbleweed\nID_LIKE="opensuse suse"\n')
        (self.bin / "dnf").unlink()
        (self.bin / "yum").unlink()
        result, calls = self.run_installer("--version", "1.2.3-2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "etc/zypp/repos.d/httpjet.repo").exists())
        self.assertTrue(any(call[0] == "zypper" and "--oldpackage" in call and "httpjet=1.2.3-2" in call for call in calls))

if __name__ == "__main__":
    unittest.main()
