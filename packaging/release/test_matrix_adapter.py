#!/usr/bin/env python3
"""Qualification adapter contract tests; these do not boot or qualify an OS."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import matrix_vm
import release
import support

class MatrixAdapter(unittest.TestCase):
    def test_row_cli_dispatches_versioned_controller(self):
        result=subprocess.run([sys.executable,str(Path(matrix_vm.__file__).with_name('vm.py')),'--row','unit','--help'],text=True,capture_output=True,check=True)
        self.assertIn('--row ROW',result.stdout);self.assertIn('--fixtures',result.stdout)
        self.assertNotIn('--distro',result.stdout)
    def test_cloud_init_leaves_ca_to_guest_distribution_adapter(self):
        value=matrix_vm.init_data({'id':'unit-rpm','route':'rpm'},'ssh-ed25519 UNIT',None)
        document=json.loads(value.removeprefix('#cloud-config\n'))
        self.assertEqual(document['runcmd'],[])
        self.assertFalse(any('anchors' in item['path'] for item in document['write_files']))
        self.assertIn('httpjet-qualification.local',document['write_files'][0]['content'])
    def test_artifact_assets_require_manifest_hash_and_regular_file(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-image-unit-') as temporary:
            root=Path(temporary);artifacts=root/'artifacts';artifacts.mkdir();output=root/'output';output.mkdir()
            source=artifacts/'image.tar';source.write_bytes(b'UNIT IMAGE NOT BOOTABLE')
            digest=release.sha(source);asset={'artifact':source.name,'sha256':digest}
            manifest={'artifacts':{source.name:{'sha256':digest,'size':source.stat().st_size}}}
            path=matrix_vm.source_asset(asset,output,'copied',artifacts,manifest)
            self.assertEqual(path.read_bytes(),source.read_bytes())
            source.write_bytes(b'CHANGED')
            with self.assertRaises(ValueError):matrix_vm.source_asset(asset,output,'changed',artifacts,manifest)
            source.unlink();source.symlink_to(path)
            with self.assertRaises(ValueError):matrix_vm.source_asset(asset,output,'symlink',artifacts,manifest)
    def test_runtime_requires_large_matching_protocol_bodies(self):
        row=support.rows()[0];runtime={'status':'passed','uid':10001,'no_multishot_accept':True,
            'protocols':{name:True for name in ('http','tls','h2','h3')},'body_size':1024*1024,
            'body_sha256':'a'*64,'hashes':{name:'a'*64 for name in ('http','tls','h2','h3')}}
        checks={};matrix_vm.runtime_checks(row,checks,runtime)
        self.assertEqual(checks['large-transfer'],'passed')
        for change in ({'body_size':1},{'hashes':{'http':'b'*64}},{'no_multishot_accept':False}):
            bad=copy.deepcopy(runtime);bad.update(change)
            with self.assertRaises(ValueError):matrix_vm.runtime_checks(row,{},bad)
    def test_failed_rootfs_builder_still_reclaims_its_private_staging_tree(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-rootfs-cleanup-') as temporary:
            root=Path(temporary);artifacts=root/'candidate';artifacts.mkdir()
            (artifacts/'qualification-images.json').write_text('{"artifacts":{}}')
            work=SimpleNamespace(path=root,release_base='https://example.invalid/releases')
            row={'id':'alpine-unit','executor':'rootfs','architecture':'amd64'}
            calls=[]
            def invoke(arguments,**kwargs):
                calls.append(arguments)
                if len(calls)==1:
                    (root/'rootfs').mkdir()
                    raise subprocess.CalledProcessError(1,arguments)
            with patch.object(matrix_vm.os,'geteuid',return_value=1000), \
                 patch.object(matrix_vm,'command',side_effect=invoke):
                with self.assertRaises(subprocess.CalledProcessError):
                    with matrix_vm.image_session(row,{},work,root/'ssh',{},None,artifacts,{}):pass
            self.assertEqual(len(calls),2)
            self.assertEqual(calls[1][:3],['sudo','-n',sys.executable])
            self.assertIn(str(root/'rootfs'),[str(value) for value in calls[1]])

if __name__=='__main__':unittest.main()
