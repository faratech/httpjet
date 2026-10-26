#!/usr/bin/env python3
"""CoreOS definition, locked inputs and asynchronous readiness regressions."""
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
SPEC=importlib.util.spec_from_file_location('httpjet_coreos',HERE/'coreos-check.py')
coreos=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(coreos)


class CoreOS(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='httpjet-coreos-test-');self.addCleanup(self.temporary.cleanup)
        self.work=Path(self.temporary.name)
        self.row={'architecture':'amd64','executor':'coreos','route':'immutable'}
        self.lock={'definition':{'recipe':'packaging/release/images/coreos.bu','sha256':coreos.tree_hash(HERE/'images')},
                   'cloud':{'url':'https://example.invalid/coreos.qcow2.xz','format':'qcow2.xz','sha256':'0'*64,'uncompressed_sha256':'1'*64}}
        self.ports={'ssh':22022,'http':22080,'tls':22443,'quic':22443}
        self.name='httpjet-coreos-'+'a'*32

    def test_ignition_has_persistent_native_unit_and_no_python_or_os_layering(self):
        value=coreos.ignition('ssh-ed25519 AAAA fixture',self.name)
        self.assertEqual(value['ignition']['version'],'3.5.0')
        unit=next(v for v in value['systemd']['units'] if v['name']==coreos.UNIT)
        self.assertTrue(unit['enabled']);body=unit['contents']
        for flag in ('--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user=10001:10001','--network=host'):
            self.assertIn(flag,body)
        self.assertIn('/var/lib/httpjet-qualification',body)
        self.assertNotIn('python',body);self.assertNotIn('rpm-ostree',body)
        self.assertIn({'name':'zincati.service','mask':True},value['systemd']['units'])

    def test_ignition_does_not_allow_injected_key_or_container_name(self):
        with self.assertRaises(ValueError):coreos.ignition('ssh-ed25519 AAAA\nother','bad')
        with self.assertRaises(ValueError):coreos.ignition('ssh-ed25519 AAAA fixture','container; command')

    def test_qemu_has_explicit_loopback_forwards_ignition_and_tcg(self):
        arguments=coreos.qemu_args('amd64','/work',self.ports);text=' '.join(arguments)
        self.assertIn('tcg,thread=multi',text);self.assertNotIn('kvm',text)
        self.assertIn('name=opt/com.coreos/config,file=/work/ignition.json',text)
        self.assertIn('hostfwd=udp:127.0.0.1:22443-:18443',text)

    def test_definition_mismatch_rejects_before_download(self):
        self.lock['definition']['sha256']='f'*64
        with mock.patch.object(coreos.release_api,'download') as download:
            with self.assertRaisesRegex(ValueError,'definition differs'):
                with coreos._machine(self.row,self.lock,self.work,'ssh-ed25519 AAAA fixture',self.ports,self.name):pass
            download.assert_not_called()

    def test_decoded_cloud_hash_rejects_before_docker(self):
        compressed=lzma.compress(b'wrong decoded base')
        self.lock['cloud']['sha256']=hashlib.sha256(compressed).hexdigest()
        with mock.patch.object(coreos.release_api,'download',side_effect=lambda u,p:p.write_bytes(compressed)),mock.patch.object(coreos.subprocess,'run') as execute:
            with self.assertRaisesRegex(ValueError,'decoded image mismatch'):
                with coreos._machine(self.row,self.lock,self.work,'ssh-ed25519 AAAA fixture',self.ports,self.name):pass
            execute.assert_not_called()

    def test_ready_retries_missing_and_created_container(self):
        guest=mock.Mock();guest.inspect.side_effect=[RuntimeError('not created yet'),{'State':{'Running':False,'Status':'created'}},{'State':{'Running':True}}]
        guest.podman.return_value=subprocess.CompletedProcess([],0,b'1\n')
        with mock.patch.object(coreos.time,'sleep') as sleep:
            coreos.ready(guest,self.name,coreos.time.monotonic()+5,lambda:True)
        self.assertEqual(guest.inspect.call_count,3);self.assertEqual(sleep.call_count,2)

    def test_ready_rejects_an_actually_exited_app(self):
        guest=mock.Mock();guest.inspect.return_value={'State':{'Running':False,'Status':'exited'}}
        with self.assertRaisesRegex(RuntimeError,'exited before activation'):
            coreos.ready(guest,self.name,coreos.time.monotonic()+5,lambda:True)

    def test_ready_is_bounded_when_container_never_exists(self):
        guest=mock.Mock();guest.inspect.side_effect=RuntimeError('not created')
        clock=[0]
        with mock.patch.object(coreos.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(coreos.time,'sleep',side_effect=lambda _:clock.__setitem__(0,clock[0]+1)):
            with self.assertRaises(TimeoutError):coreos.ready(guest,self.name,2,lambda:True)
        self.assertEqual(clock[0],2)

    def test_runtime_rejects_root_identity_before_marking_pass(self):
        guest=mock.Mock();guest.podman.return_value=subprocess.CompletedProcess([],0,b'Uid:\t0 0 0 0\nGid:\t0 0 0 0\n')
        with self.assertRaisesRegex(ValueError,'identity mismatch'):
            coreos.sandbox(guest,self.name,{'uid':10001,'gid':10001})

    def test_private_fixture_key_is_cleaned_on_failure(self):
        path=self.work/'fixture-key';path.write_text('disposable fixture key')
        with self.assertRaises(RuntimeError):
            with coreos.private_key_lifetime(path):raise RuntimeError('test failure')
        self.assertFalse(path.exists())

    def denied_guest(self,text,uid=10001,ready=False):
        guest=mock.Mock();guest.policy.return_value='0'
        record=json.dumps({'mode':'deny-exec','uid':uid,'global_policy_changed':False})+'\n'
        guest.podman.return_value=subprocess.CompletedProcess([],1,(record+text).encode())
        guest.script.side_effect=[subprocess.CompletedProcess([],0,b''),subprocess.CompletedProcess([],1 if ready else 0,b'')]
        return guest

    def test_denial_requires_real_uring_eperm(self):
        guest=self.denied_guest('failed to build monoio runtime: Operation not permitted (os error 1)\n')
        value=coreos.negative_probe(guest,{'probe_path':'/probe','binary_path':'/server','image_id':'sha256:fixture'},self.work)
        self.assertEqual(value['status'],'expected_failure');self.assertEqual(value['errno'],1)

    def test_denial_rejects_port_collision(self):
        guest=self.denied_guest('failed to build monoio runtime: Address already in use (os error 98)\n')
        with self.assertRaisesRegex(ValueError,'genuinely block'):
            coreos.negative_probe(guest,{'probe_path':'/probe','binary_path':'/server','image_id':'sha256:fixture'},self.work)

    def test_denial_rejects_unrelated_permission_error(self):
        guest=self.denied_guest('cannot open configuration: Operation not permitted (os error 1)\n')
        with self.assertRaisesRegex(ValueError,'genuinely block'):
            coreos.negative_probe(guest,{'probe_path':'/probe','binary_path':'/server','image_id':'sha256:fixture'},self.work)

    def test_denial_rejects_readiness_or_root_identity(self):
        for options in ({'ready':True},{'uid':0}):
            with self.subTest(options=options):
                guest=self.denied_guest('failed to build monoio runtime: Operation not permitted (os error 1)\n',**options)
                with self.assertRaisesRegex(ValueError,'genuinely block'):
                    coreos.negative_probe(guest,{'probe_path':'/probe','binary_path':'/server','image_id':'sha256:fixture'},self.work)


if __name__=='__main__':unittest.main()
