#!/usr/bin/env python3
"""Run RPM transaction helpers in private roots without installing a package."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]


class RpmTransactions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-rpm-hooks-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commands = self.root / 'commands'; self.commands.mkdir()
        self.state = self.root / 'state'; self.state.mkdir()
        self.path('/run/systemd/system').mkdir(parents=True)
        self.env = os.environ | {'PATH': f'{self.commands}:/usr/bin:/bin', 'HTTPJET_RPM_SECRET': 'must-not-cross-uid'}
        self.script('stat', "printf '0:700\\n'\n")
        self.script('runuser', 'while [ "$1" != -- ]; do shift; done\nshift\nexec "$@"\n')
        self.script('systemctl', f'printf "%s\\n" "$*" >> {shlex.quote(str(self.state / "service.log"))}\n'
                    + f'if [ "$1" = is-enabled ]; then cat {shlex.quote(str(self.state / "enabled"))}; fi\n')
        (self.state / 'enabled').write_text('enabled\n')
        binary = self.path('/usr/bin/httpjet'); binary.parent.mkdir(parents=True)
        binary.write_text('#!/bin/sh\n' + f'env > {shlex.quote(str(self.state / "validation.env"))}\n'
                          + f'[ ! -f {shlex.quote(str(self.state / "invalid"))} ]\n')
        binary.chmod(0o755)
        helper = self.path('/usr/libexec/httpjet/setup-tls'); helper.parent.mkdir(parents=True)
        helper.write_text('#!/bin/sh\nexit 0\n'); helper.chmod(0o755)
        template = self.path('/usr/share/httpjet/welcome/index.html'); template.parent.mkdir(parents=True)
        template.write_bytes((REPO / 'packaging/debian/welcome/index.html').read_bytes())

    def path(self, absolute): return self.root / absolute.lstrip('/')

    def script(self, name, body):
        path = self.commands / name; path.write_text('#!/bin/sh\nset -eu\n' + body); path.chmod(0o755)

    def helper(self, *arguments):
        body = (REPO / 'packaging/rpm/package-helper.sh').read_text()
        for prefix in ('/usr/libexec/httpjet/setup-tls', '/run/httpjet-package', '/run/systemd/system', '/usr/bin/httpjet',
                       '/etc/httpjet', '/usr/share/httpjet', '/var/www'):
            body = body.replace(prefix, str(self.path(prefix)))
        body = body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin', f'PATH={self.commands}:/usr/bin:/bin')
        return subprocess.run(['/bin/sh', '-s', '--', *arguments], input=body, env=self.env,
                              text=True, capture_output=True, check=False)

    def configure(self, count='2'):
        result = self.helper('configure', count, '0.1.10-1')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fresh_seed_then_validation_then_start(self):
        self.configure('1')
        result = self.helper('commit', '0.1.10-1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.path('/var/www/httpjet/index.html').read_bytes(),
                         self.path('/usr/share/httpjet/welcome/index.html').read_bytes())
        log = (self.state / 'service.log').read_text()
        self.assertIn('enable httpjet.service\nstart httpjet.service', log)
        self.assertNotIn('HTTPJET_RPM_SECRET', (self.state / 'validation.env').read_text())

    def test_upgrade_only_tries_restart_and_does_not_recreate_site(self):
        self.configure()
        result = self.helper('commit', '0.1.10-1')
        self.assertEqual(result.returncode, 0, result.stderr)
        log = (self.state / 'service.log').read_text()
        self.assertIn('try-restart httpjet.service', log)
        self.assertNotRegex(log, r'(?m)^(?:enable|start) ')
        self.assertFalse(self.path('/var/www/httpjet').exists())

    def test_invalid_upgrade_cannot_reach_any_manager_action(self):
        self.configure(); (self.state / 'invalid').touch()
        result = self.helper('commit', '0.1.10-1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state / 'service.log').exists())
        self.assertIn('existing process was left running', result.stderr)

    def test_masked_upgrade_never_restarts_or_enables(self):
        self.configure(); (self.state / 'enabled').write_text('masked\n')
        result = self.helper('commit', '0.1.10-1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotRegex((self.state / 'service.log').read_text(), r'(?m)^(?:start|enable|try-restart) ')

    def test_transaction_identity_mismatch_is_rejected(self):
        self.configure()
        result = self.helper('commit', '0.1.10-2')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state / 'service.log').exists())

    def test_transaction_directory_symlink_is_rejected(self):
        target = self.root / 'administrator'; target.mkdir()
        self.path('/run/httpjet-package').symlink_to(target, target_is_directory=True)
        result = self.helper('configure', '1', '0.1.10-1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(target.iterdir()), [])

    def test_old_postun_has_no_restart_command(self):
        spec = (REPO / 'packaging/rpm/httpjet.spec').read_text()
        postun = spec.split('\n%postun\n', 1)[1].split('\n%post ', 1)[0]
        self.assertNotRegex(postun, r'(?m)^\s*systemctl[^\n]*(?:try-restart| restart)')
        self.assertIn('rmdir /var/lib/httpjet /var/log/httpjet', postun)


if __name__ == '__main__': unittest.main()
