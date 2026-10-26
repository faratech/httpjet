#!/usr/bin/env python3
"""The root container must clean only its own extracted staging tree."""
import importlib.util
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'httpjet_prepare_rootfs', Path(__file__).with_name('images') / 'prepare-rootfs.py')
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class PreparedRootfsCleanup(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-prepare-rootfs-', dir='/var/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.sibling = self.work/'runner-owned.txt'
        self.sibling.write_text('keep')

    def tree(self, kind, source, output, work, root):
        (root/'owned'/'nested').mkdir(parents=True)
        (root/'owned'/'nested'/'file').write_text('temporary fixture')
        output.write_text('prepared unit artifact')

    def test_cleanup_preserves_output_and_sibling(self):
        output = self.work/'rootfs.tar.gz'
        with patch.object(prepare, 'inside_tree', side_effect=self.tree):
            prepare.inside('devuan-sysv', self.work/'source.iso', output, self.work)
        self.assertFalse((self.work/'root').exists())
        self.assertEqual(output.read_text(), 'prepared unit artifact')
        self.assertEqual(self.sibling.read_text(), 'keep')
    def test_failed_builder_still_removes_only_created_tree(self):
        def fail(*args):
            self.tree(*args)
            raise RuntimeError('unit-only builder failure')
        with patch.object(prepare, 'inside_tree', side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, 'builder failure'):
                prepare.inside('slackware-sysv', self.work/'source.iso', self.work/'output', self.work)
        self.assertFalse((self.work/'root').exists())
        self.assertEqual(self.sibling.read_text(), 'keep')

    def test_preexisting_tree_is_never_removed(self):
        existing = self.work/'root'
        existing.mkdir()
        (existing/'keep').write_text('administrator data')
        with self.assertRaises(FileExistsError):
            prepare.inside('devuan-sysv', self.work/'source.iso', self.work/'output', self.work)
        self.assertEqual((existing/'keep').read_text(), 'administrator data')

    @unittest.skipUnless(os.geteuid() == 0, 'ownership regression needs an isolated root-created tree')
    def test_runner_can_clean_its_parent_after_root_created_tree(self):
        nobody = pwd.getpwnam('nobody')
        # Model a sticky temporary parent where the runner may remove its own
        # directory but cannot remove an unrelated root-owned sibling.
        self.work.chmod(0o1733)
        runner = self.work/'runner'
        runner.mkdir(mode=0o700)
        os.chown(runner, nobody.pw_uid, nobody.pw_gid)
        with patch.object(prepare, 'inside_tree', side_effect=self.tree):
            prepare.inside('devuan-sysv', runner/'source.iso', runner/'output', runner)
        self.assertFalse((runner/'root').exists())
        result = subprocess.run(['python3', '-c', 'import shutil,sys; shutil.rmtree(sys.argv[1])', str(runner)],
                                user=nobody.pw_uid, group=nobody.pw_gid, extra_groups=[],
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.sibling.read_text(), 'keep')


class SlackwareBootstrap(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-slackware-bootstrap-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)/'root'
        self.scripts = self.root/'bootstrap-scripts'
        for path in (self.root/'dev', self.root/'sbin', self.scripts):path.mkdir(parents=True)
        self.ldconfig = self.root/'sbin/ldconfig'
        self.ldconfig.write_text('unit fixture');self.ldconfig.chmod(0o755)
        (self.scripts/'busybox').write_text('unit fixture')
        (self.scripts/'0000.sh').write_text('unit fixture')

    def test_bootstrap_disables_ldconfig_until_libraries_are_seeded(self):
        seen = []
        def run(arguments,**kwargs):
            seen.append((arguments,stat.S_IMODE(self.ldconfig.stat().st_mode),kwargs['env']['PATH']))
            return subprocess.CompletedProcess(arguments,0)
        with patch.object(prepare.subprocess,'check_output',return_value='cat\nmv\n'), \
             patch.object(prepare.subprocess,'run',side_effect=run), patch.object(prepare,'call') as call:
            prepare.slackware_bootstrap(self.root,self.scripts)
        self.assertEqual(seen[0][1]&0o111,0)
        self.assertTrue(seen[0][2].startswith('/bootstrap-scripts/bin:'))
        self.assertTrue((self.scripts/'bin/cat').is_symlink())
        self.assertTrue((self.root/'dev/null').is_file())
        self.assertEqual(stat.S_IMODE(self.ldconfig.stat().st_mode),0o755)
        call.assert_called_once_with(['chroot',self.root,'/sbin/ldconfig'])

    def test_ldconfig_mode_restored_if_bootstrap_fails(self):
        with patch.object(prepare.subprocess,'check_output',return_value='cat\n'), \
             patch.object(prepare.subprocess,'run',side_effect=OSError('fixture failure')):
            with self.assertRaisesRegex(OSError,'fixture failure'):
                prepare.slackware_bootstrap(self.root,self.scripts)
        self.assertEqual(stat.S_IMODE(self.ldconfig.stat().st_mode),0o755)

    def test_unowned_null_symlink_is_not_followed(self):
        target = Path(self.temporary.name)/'keep'
        target.write_text('keep')
        (self.root/'dev/null').symlink_to(target)
        with self.assertRaisesRegex(ValueError,'unexpected Slackware'):
            prepare.slackware_bootstrap(self.root,self.scripts)
        self.assertEqual(target.read_text(),'keep')


if __name__ == '__main__':
    unittest.main()
