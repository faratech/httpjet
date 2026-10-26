#!/usr/bin/env python3
"""Exercise rootfs extraction boundaries without mounting or booting a host disk."""

import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import rootfs


class RootfsExtraction(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='httpjet-rootfs-test-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def archive(self, entries):
        result = self.work / 'input.tar.gz'
        with tarfile.open(result, 'w:gz') as archive:
            for name, kind, content in entries:
                member = tarfile.TarInfo(name)
                member.uid, member.gid = os.geteuid(), os.getegid()
                member.mode = 0o755 if kind == 'directory' else 0o644
                if kind == 'directory':
                    member.type = tarfile.DIRTYPE
                    archive.addfile(member)
                elif kind in ('symlink', 'hardlink'):
                    member.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
                    member.linkname = content
                    archive.addfile(member)
                else:
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
        return result

    def test_regular_files_and_guest_links_are_preserved(self):
        archive = self.archive([
            ('root/bin', 'directory', None),
            ('root/bin/tool', 'file', b'qualification fixture'),
            ('root/bin/other', 'hardlink', 'root/bin/tool'),
            ('root/lib64', 'symlink', '/usr/lib64'),
        ])
        destination = self.work / 'root'
        evidence = rootfs.extract_rootfs(archive, destination, 'root')
        self.assertEqual(evidence['members'], 4)
        self.assertEqual((destination / 'bin/tool').read_bytes(), b'qualification fixture')
        self.assertEqual((destination / 'bin/tool').stat().st_ino, (destination / 'bin/other').stat().st_ino)
        self.assertEqual(os.readlink(destination / 'lib64'), '/usr/lib64')

    def test_absolute_and_parent_paths_cannot_escape(self):
        for name in ('../outside', '/outside', 'root/../../outside'):
            with self.subTest(name=name):
                archive = self.archive([(name, 'file', b'bad')])
                with self.assertRaisesRegex(ValueError, 'unsafe'):
                    rootfs.extract_rootfs(archive, self.work / ('root-' + str(len(list(self.work.iterdir())))))
        self.assertFalse((self.work / 'outside').exists())

    def test_symlink_parent_is_never_followed_during_extraction(self):
        outside = self.work / 'outside'
        outside.mkdir()
        archive = self.archive([('etc', 'symlink', str(outside)), ('etc/overwrite', 'file', b'bad')])
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            rootfs.extract_rootfs(archive, self.work / 'root')
        self.assertEqual(list(outside.iterdir()), [])

    def test_hardlink_to_an_external_path_is_rejected(self):
        archive = self.archive([('link', 'hardlink', '../outside')])
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            rootfs.extract_rootfs(archive, self.work / 'root')

    def test_injection_replaces_only_final_link_inside_guest_tree(self):
        root = self.work / 'root'
        root.mkdir()
        outside = self.work / 'outside'
        outside.write_text('keep')
        (root / 'resolv.conf').symlink_to(outside)
        rootfs.inject(root, 'resolv.conf', b'guest resolver', 0o600)
        self.assertEqual(outside.read_text(), 'keep')
        self.assertEqual((root / 'resolv.conf').read_bytes(), b'guest resolver')
        (root / 'parent').symlink_to(self.work)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            rootfs.inject(root, 'parent/outside', b'bad', 0o600)
        self.assertEqual(outside.read_text(), 'keep')

    def test_locked_input_mismatch_is_rejected_before_extraction(self):
        body = b'pinned rootfs bytes'
        source = {'url': 'https://example.invalid/rootfs.tar.gz',
                  'sha256': hashlib.sha256(body).hexdigest()}
        with patch.object(rootfs, 'download', side_effect=lambda url, path: path.write_bytes(body)):
            result = rootfs.locked_blob(source, self.work, 'download')
        self.assertEqual(result.read_bytes(), body)
        with patch.object(rootfs, 'download', side_effect=lambda url, path: path.write_bytes(b'changed')):
            with self.assertRaisesRegex(ValueError, 'checksum'):
                rootfs.locked_blob(source, self.work, 'bad-download')

    def test_candidate_local_input_requires_exact_manifest_binding(self):
        artifacts = self.work / 'artifacts'
        artifacts.mkdir()
        body = b'prepared target filesystem'
        artifact = artifacts / 'prepared-rootfs.tar.gz'
        artifact.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        source = {'artifact': artifact.name, 'sha256': digest}
        manifest = {'artifacts': {artifact.name: {'sha256': digest, 'size': len(body)}}}
        result = rootfs.locked_blob(source, self.work, 'accepted', artifacts, manifest)
        self.assertEqual(result.read_bytes(), body)
        with self.assertRaisesRegex(ValueError, 'manifest'):
            rootfs.locked_blob(source, self.work, 'no-manifest', artifacts)
        artifact.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'manifest'):
            rootfs.locked_blob(source, self.work, 'changed', artifacts, manifest)
        artifact.unlink()
        artifact.symlink_to(result)
        with self.assertRaisesRegex(ValueError, 'manifest'):
            rootfs.locked_blob(source, self.work, 'symlink', artifacts, manifest)


if __name__ == '__main__':
    unittest.main()
