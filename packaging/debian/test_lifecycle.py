#!/usr/bin/env python3
"""Execute maintainer hooks in temporary filesystem roots with mocked accounts.

No package is installed and no real user, systemd unit or web directory changes.
VM package lifecycle tests remain the authority for dpkg/systemd integration.
"""

import os
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]


class MaintainerLifecycle(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="httpjet-maintainer-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commands = self.root / "commands"
        self.commands.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.env = os.environ | {
            "PATH": f"{self.commands}:/usr/bin:/bin",
            "HTTPJET_HOOK_TEST_STATE": str(self.state),
            "DPKG_ROOT": "",
        }
        self.path("/run/systemd/system").mkdir(parents=True)
        self.command(
            "getent",
            'case "$1" in\n'
            'passwd) record=account ;;\n'
            'group) record=group ;;\n'
            '*) exit 2 ;;\n'
            'esac\n'
            '[ -f "$HTTPJET_HOOK_TEST_STATE/$record" ] || exit 2\n'
            'cat "$HTTPJET_HOOK_TEST_STATE/$record"\n',
        )
        self.command(
            "adduser",
            'printf "%s\\n" "$*" >> "$HTTPJET_HOOK_TEST_STATE/adduser.log"\n',
        )
        self.command(
            "dpkg-query",
            '[ -f "$HTTPJET_HOOK_TEST_STATE/owned" ] || exit 1\n'
            'printf "httpjet: %s\\n" "$3"\n',
        )
        self.command(
            "deb-systemd-invoke",
            'printf "%s\\n" "$*" >> "$HTTPJET_HOOK_TEST_STATE/service.log"\n',
        )
        self.command("runuser", 'while [ "$1" != -- ]; do shift; done\nshift\nexec "$@"\n')
        self.template = self.path("/usr/share/httpjet/welcome/index.html")
        self.template.parent.mkdir(parents=True)
        shutil.copyfile(REPO / "packaging/debian/welcome/index.html", self.template)

    def path(self, absolute):
        return self.root / absolute.lstrip("/")

    def command(self, name, body):
        script = self.commands / name
        script.write_text("#!/bin/sh\nset -eu\n" + body)
        script.chmod(0o755)

    def account(self, *, uid="321", home=None, shell="/usr/sbin/nologin"):
        if home is None:
            home = self.path("/var/lib/httpjet")
        (self.state / "account").write_text(f"httpjet:x:{uid}:321::{home}:{shell}\n")
        (self.state / "group").write_text("httpjet:x:321:\n")

    def run_hook(self, name, *arguments):
        if name == "postinst":
            binary = self.path("/usr/bin/httpjet")
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_text(
                '#!/bin/sh\nset -eu\n'
                f'printf "%s\\n" "$*" >> {shlex.quote(str(self.state / "check.log"))}\n'
                f'env > {shlex.quote(str(self.state / "validation.env"))}\n'
                f'[ ! -f {shlex.quote(str(self.state / "invalid-config"))} ]\n'
            )
            binary.chmod(0o755)
        script = (REPO / f"debian/httpjet.{name}").read_text()
        # Rewrite only known managed paths; PATH substitutes identity/package
        # lookups, so there is no route from these hooks to host account tools.
        for prefix in (
            "/usr/local/sbin/httpjet",
            "/usr/local/bin/httpjet",
            "/usr/lib/systemd/system/httpjet.service",
            "/lib/systemd/system/httpjet.service",
            "/etc/systemd/system/httpjet.service",
            "/usr/sbin/httpjet",
            "/usr/bin/httpjet",
            "/usr/share/httpjet",
            "/run/systemd/system",
            "/etc/httpjet",
            "/var/lib/httpjet",
            "/var/log/httpjet",
            "/var/www",
        ):
            script = script.replace(prefix, str(self.path(prefix)))
        script = script.replace("#DEBHELPER#", ': > "$HTTPJET_HOOK_TEST_STATE/helper-reached"')
        script = script.replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={self.commands}:/usr/bin:/bin")
        return subprocess.run(
            ["/bin/sh", "-s", "--", *arguments],
            input=script,
            text=True,
            capture_output=True,
            env=self.env,
            check=False,
        )

    def test_fresh_docroot_is_seeded_with_canonical_bytes_and_modes(self):
        result = self.run_hook("postinst", "configure")
        self.assertEqual(result.returncode, 0, result.stderr)
        target = self.path("/var/www/httpjet/index.html")
        self.assertEqual(target.read_bytes(), self.template.read_bytes())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o755)
        self.assertIn("--system", (self.state / "adduser.log").read_text())
        self.assertEqual((self.state / "service.log").read_text(), "start httpjet.service\n")

    def test_existing_empty_docroot_is_not_seeded(self):
        self.path("/var/www/httpjet").mkdir(parents=True)
        result = self.run_hook("postinst", "configure")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.path("/var/www/httpjet").iterdir()), [])

    def test_custom_content_survives_upgrade_and_reconfiguration(self):
        target = self.path("/var/www/httpjet/index.html")
        target.parent.mkdir(parents=True)
        target.write_text("administrator website\n")
        self.account()
        for arguments in (("configure", "0.1.9-1"), ("configure",)):
            result = self.run_hook("postinst", *arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_text(), "administrator website\n")
        self.assertFalse((self.state / "adduser.log").exists())

    def test_docroot_symlink_is_never_followed_for_seeding(self):
        external = self.root / "administrator-content"
        external.mkdir()
        self.path("/var/www").mkdir(parents=True)
        self.path("/var/www/httpjet").symlink_to(external, target_is_directory=True)
        result = self.run_hook("postinst", "configure")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(external.iterdir()), [])

    def test_first_install_refuses_unmanaged_binary_config_and_unit(self):
        for absolute in (
            "/usr/bin/httpjet",
            "/etc/httpjet/conf/httpd_config.xml",
            "/etc/systemd/system/httpjet.service",
        ):
            with self.subTest(absolute=absolute):
                candidate = self.path(absolute)
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("independent installation\n")
                result = self.run_hook("preinst", "install")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refusing unmanaged installation", result.stderr)
                self.assertEqual(candidate.read_text(), "independent installation\n")
                candidate.unlink()

    def test_first_install_refuses_unmanaged_dropins(self):
        self.path("/etc/systemd/system/httpjet.service.d").mkdir(parents=True)
        result = self.run_hook("preinst", "install")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unmanaged httpjet.service drop-ins", result.stderr)

    def test_upgrade_and_removed_package_reinstall_keep_administrator_overrides(self):
        candidate = self.path("/etc/systemd/system/httpjet.service")
        candidate.parent.mkdir(parents=True)
        candidate.write_text("administrator override\n")
        for arguments in (("upgrade", "0.1.9-1"), ("install", "0.1.9-1")):
            result = self.run_hook("preinst", *arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(candidate.read_text(), "administrator override\n")

    def test_incompatible_existing_account_is_refused(self):
        for kwargs in ({"uid": "1001"}, {"uid": "0"}, {"shell": "/bin/bash"}):
            with self.subTest(kwargs=kwargs):
                self.account(**kwargs)
                result = self.run_hook("postinst", "configure")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not the dedicated httpjet system account", result.stderr)
                self.assertFalse(self.path("/var/www/httpjet").exists())

    def test_retained_system_account_allows_purge_reinstall(self):
        self.account()
        result = self.run_hook("postinst", "configure")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.state / "adduser.log").exists())

    def test_invalid_upgrade_never_reaches_service_restart_helper(self):
        self.account()
        (self.state / "invalid-config").touch()
        result = self.run_hook("postinst", "configure", "0.1.9-1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("check --strict", (self.state / "check.log").read_text())
        self.assertFalse((self.state / "helper-reached").exists())
        self.assertFalse((self.state / "service.log").exists())

    def test_upgrades_never_use_the_fresh_install_start(self):
        self.account()
        result = self.run_hook("postinst", "configure", "0.1.9-1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.state / "helper-reached").exists())
        self.assertFalse((self.state / "service.log").exists())

    def test_upgrade_does_not_recreate_a_deleted_docroot(self):
        self.account()
        result = self.run_hook("postinst", "configure", "0.1.9-1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.path("/var/www/httpjet").exists())

    def test_remove_stops_service_before_package_helper(self):
        result = self.run_hook("prerm", "remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.state / "service.log").read_text(), "stop httpjet.service\n")
        self.assertTrue((self.state / "helper-reached").exists())

    def test_upgrade_never_stops_service_before_config_validation(self):
        for action in ("upgrade", "failed-upgrade", "deconfigure"):
            with self.subTest(action=action):
                result = self.run_hook("prerm", action, "0.1.10-7")
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.state / "service.log").exists())

    def test_offline_root_and_non_systemd_removal_never_touch_host_service(self):
        self.env["DPKG_ROOT"] = str(self.root)
        result = self.run_hook("prerm", "remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env["DPKG_ROOT"] = ""
        self.path("/run/systemd/system").rmdir()
        result = self.run_hook("prerm", "remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.state / "service.log").exists())

    def test_failed_stop_aborts_removal_before_helper(self):
        self.command("deb-systemd-invoke", "exit 9\n")
        result = self.run_hook("prerm", "remove")
        self.assertEqual(result.returncode, 9)
        self.assertFalse((self.state / "helper-reached").exists())

    def test_service_account_validation_drops_the_root_environment(self):
        self.account()
        self.env["HTTPJET_TEST_SECRET"] = "root-only-fixture-secret"
        result = self.run_hook("postinst", "configure", "0.1.9-1")
        self.assertEqual(result.returncode, 0, result.stderr)
        environment = (self.state / "validation.env").read_text()
        self.assertNotIn("HTTPJET_TEST_SECRET", environment)
        self.assertNotIn("HTTPJET_HOOK_TEST_STATE", environment)

    def test_purge_removes_only_empty_state_and_log_roots(self):
        self.account()
        for absolute in ("/var/lib/httpjet", "/var/log/httpjet"):
            self.path(absolute).mkdir(parents=True)
        site = self.path("/var/www/httpjet/index.html")
        site.parent.mkdir(parents=True)
        site.write_text("administrator website\n")
        account = (self.state / "account").read_bytes()
        result = self.run_hook("postrm", "purge")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.path("/var/lib/httpjet").exists())
        self.assertFalse(self.path("/var/log/httpjet").exists())
        self.assertEqual(site.read_text(), "administrator website\n")
        self.assertEqual((self.state / "account").read_bytes(), account)

    def test_purge_preserves_nonempty_state_logs_and_site_content(self):
        for absolute in ("/var/lib/httpjet/certificate.pem", "/var/log/httpjet/history.log",
                         "/var/www/httpjet/index.html"):
            path = self.path(absolute)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("administrator data\n")
        for _ in range(2):
            result = self.run_hook("postrm", "purge")
            self.assertEqual(result.returncode, 0, result.stderr)
        for absolute in ("/var/lib/httpjet/certificate.pem", "/var/log/httpjet/history.log",
                         "/var/www/httpjet/index.html"):
            self.assertEqual(self.path(absolute).read_text(), "administrator data\n")

    def test_remove_preserves_even_empty_state_directories(self):
        for absolute in ("/var/lib/httpjet", "/var/log/httpjet"):
            self.path(absolute).mkdir(parents=True)
        result = self.run_hook("postrm", "remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.path("/var/lib/httpjet").is_dir())
        self.assertTrue(self.path("/var/log/httpjet").is_dir())

    def test_purge_never_follows_state_directory_symlinks(self):
        target = self.root / "administrator-certificate-store"
        target.mkdir()
        (target / "certificate.pem").write_text("administrator certificate\n")
        state = self.path("/var/lib/httpjet")
        state.parent.mkdir(parents=True)
        state.symlink_to(target, target_is_directory=True)
        result = self.run_hook("postrm", "purge")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(state.is_symlink())
        self.assertEqual((target / "certificate.pem").read_text(), "administrator certificate\n")


if __name__ == "__main__":
    unittest.main()
