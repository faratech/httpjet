#!/usr/bin/env python3
"""Controller handoff fixtures only; these do not qualify a CoreOS image."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import matrix_vm
import release
import support

class CoreosDispatch(unittest.TestCase):
    def test_evidence_binds_exact_image_and_rejects_permission_noise(self):
        with tempfile.TemporaryDirectory(prefix='httpjet-coreos-adapter-unit-') as temporary:
            root=Path(temporary);artifacts=root/'artifacts';artifacts.mkdir();output=root/'output';output.mkdir()
            row=next(item for item in support.rows() if item['executor']=='coreos');arch=row['architecture']
            image={'artifact':'UNIT-ONLY-oci.tar','image_id':'sha256:'+'1'*64}
            manifest={'schema':2,**support.identity('1.2.3-1'),'binaries':{arch:{'artifact':'UNIT-ONLY.tar.gz','binary_sha256':'b'*64}},
                'artifacts':{'UNIT-ONLY.tar.gz':{'sha256':'a'*64},image['artifact']:{'sha256':'c'*64}},'oci_images':{arch:image}}
            release.write_json(artifacts/'manifest.json',manifest)
            lock={'UNIT-ONLY':'not a CoreOS input'}
            runtime={'status':'passed','uid':10001,'binary_sha256':'b'*64,'no_multishot_accept':True,
                'protocols':{name:True for name in ('http','tls','h2','h3')},'body_size':1024*1024,'body_sha256':'d'*64,
                'hashes':{name:'d'*64 for name in ('http','tls','h2','h3')}}
            positive={'status':'passed','uid':10001,'global_policy_changed':False,'operations':{name:True for name in ('setup','register_probe','enter_nop')}}
            negative={'status':'expected_failure','uid':10001,'global_policy_changed':False,'errno':1,'exit_code':1,'ready_file_created':False}
            log=root/'UNIT-ONLY.log';log.write_text('UNIT ONLY: no VM was booted\n')
            observation={'runtime':runtime,'service':{'uid':10001,'binary_sha256':'b'*64},'positive':positive,'negative':negative,
                'image':{'sha256':'e'*64,'origin':'https://example.invalid/UNIT-ONLY'},
                'checks':{name:'passed' for name in row['checks']},'files':{'uring-denial-log':log},'log':log}
            loader=Mock();definition=SimpleNamespace(loader=loader);module=SimpleNamespace(qualify=Mock(return_value=observation))
            args=SimpleNamespace(artifacts=artifacts,output=output,timeout=1)
            with patch('importlib.util.spec_from_file_location',return_value=definition),patch('importlib.util.module_from_spec',return_value=module):
                matrix_vm.qualify_coreos(args,row,manifest,lock,root)
                result=release.load(output/(row['id']+'.json'))
                self.assertEqual(result['container_image_id'],image['image_id'])
                self.assertEqual(result['manifest_sha256'],release.sha(artifacts/'manifest.json'))
                self.assertIn('uring-denial-log',{item['role'] for item in result['evidence'].values()})
                negative['errno']=13
                with self.assertRaisesRegex(ValueError,'denial proof'):matrix_vm.qualify_coreos(args,row,manifest,lock,root)

if __name__=='__main__':unittest.main()
