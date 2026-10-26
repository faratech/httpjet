#!/usr/bin/env python3
"""Controller logic only: fake filesystem/processes; no host service/package ops."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('httpjet_guest_v2',Path(__file__).with_name('guest-v2.py'))
guest=importlib.util.module_from_spec(spec);spec.loader.exec_module(guest)

class Simulated(guest.Controller):
    version='1.0.0-1'
    is_active=True
    is_enabled=True
    restart_inactive=False
    def __init__(self,*args):
        super().__init__(*args);self.transitions=[];self.calls=[]
    def reset_budget(self):pass
    def active(self):return self.is_active
    def enabled(self):return self.is_enabled
    def installed_version(self):return self.version
    def wait_http(self):
        if not self.is_active:raise guest.GuestError('not active')
    def inspect(self):
        self.report['service']={'scope':'installed-init-service','uid':1234,'gid':1234,'pid':100,'binary_sha256':'test','init':'systemd','no_multishot_accept':True}
        return self.report['service']
    def denial(self):pass
    def bootstrap(self,version=None,**kwargs):
        self.version=version or self.release_id
        return subprocess.CompletedProcess([],0,'','')
    def target(self,release_id,local=False):
        self.transitions.append((self.version,release_id,self.is_active,self.is_enabled))
        self.version=release_id
        if self.restart_inactive:self.is_active=True
    def service_action(self,action):
        if action=='start':self.is_active=True
        elif action=='stop':self.is_active=False
        elif action=='enable':self.is_enabled=True
        elif action=='disable':self.is_enabled=False
        else:raise AssertionError('unhandled fake service action')
    def command(self,args,**kwargs):
        self.calls.append(args)
        if args[:2]==['/usr/local/sbin/httpjetctl','rollback']:
            self.version=args[args.index('--version')+1]
        elif args[:2]==['/usr/local/sbin/httpjetctl','uninstall']:
            self.is_active=False;self.is_enabled=False
        else:raise AssertionError('unexpected external command: '+str(args))
        return subprocess.CompletedProcess(args,0,'','')

class GuestControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='httpjet-guest-unit-');self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.work=self.root/'work';self.work.mkdir()
        self.spec={'schema':2,'row':{'route':'portable','init':'systemd','architecture':'amd64','checks':['install','update','rollback','uninstall','content-preserved'],'no_multishot_accept':True},
                   'manifest':{'release_id':'1.0.0-1','binaries':{'amd64':{'binary_sha256':'test'}}},
                   'baseline':{'kind':'first-release-fixture','release_id':'1.0.0-0','forward_release_id':'1.0.0-2'},'expected_welcome':'expected-welcome'}
        self.controller=Simulated(self.spec,self.work)
        configuration=self.root/'etc/httpjet/conf/vhosts/default.xml';configuration.parent.mkdir(parents=True);configuration.write_text('operator configuration')
        content=self.root/'var/www/httpjet/operator-content.txt';content.parent.mkdir(parents=True);content.write_text('operator-owned\n')
        self.controller.state_file.write_text(json.dumps({'uid':1234,'binary_sha256':'test','content':'operator-owned\n','configuration_sha256':guest.sha(configuration)}))
    def mapped(self,value):
        path=Path(value)
        if path.is_absolute():
            try:path.relative_to(self.root)
            except ValueError:return self.root/path.relative_to('/')
        return path
    def test_exercise_has_real_distinct_optout_transitions_and_only_row_checks(self):
        with patch.object(guest,'Path',side_effect=self.mapped):self.controller.exercise()
        self.assertIn(('1.0.0-1','1.0.0-2',False,False),self.controller.transitions)
        self.assertIn(('1.0.0-2','1.0.0-1',False,True),self.controller.transitions)
        self.assertEqual(self.controller.report['checks'],{'update':'passed','rollback':'passed','content-preserved':'passed','uninstall':'passed'})
        self.assertEqual(self.controller.report['optouts'],{'disabled_stopped_real_transition':True,'enabled_stopped_real_transition':True})
        self.assertEqual(self.controller.version,'1.0.0-1')
    def test_restarted_disabled_service_aborts_without_claiming_later_checks(self):
        self.controller.restart_inactive=True
        with patch.object(guest,'Path',side_effect=self.mapped):
            with self.assertRaisesRegex(guest.GuestError,'opted-out'):self.controller.exercise()
        self.assertNotIn('uninstall',self.controller.report['checks'])
        self.assertNotIn('content-preserved',self.controller.report['checks'])
    def test_baseline_hash_fails_before_any_native_transaction(self):
        spec=json.loads(json.dumps(self.spec));spec['row']['route']='deb';spec['baseline'].update(deb='baseline.deb',deb_sha256='0'*64)
        controller=Simulated(spec,self.work);(self.work/'baseline.deb').write_bytes(b'not the approved baseline')
        with self.assertRaisesRegex(guest.GuestError,'hash'):controller.local_baseline()
        self.assertEqual(controller.calls,[])
    def test_rpm_6_lowercase_signature_is_verified_before_baseline_use(self):
        spec=json.loads(json.dumps(self.spec));spec['row']['route']='rpm'
        path=self.work/'baseline.rpm';path.write_bytes(b'unit-only baseline')
        spec['baseline'].update(rpm=path.name,rpm_sha256=guest.sha(path))
        controller=guest.Controller(spec,self.work)
        valid='Header OpenPGP V4 EdDSA/SHA256 signature, key fingerprint: abc: OK\nHeader SHA256 digest: OK\n'
        with patch.object(guest.shutil,'which',return_value='rpmkeys'), \
             patch.object(controller,'command',return_value=subprocess.CompletedProcess([],0,valid,'')):
            self.assertEqual(controller.local_baseline(),path)
        for invalid in ('Header OpenPGP signature: NOKEY\n','Header OpenPGP signature: BAD\nHeader SHA256 digest: OK\n'):
            with patch.object(guest.shutil,'which',return_value='rpmkeys'), \
                 patch.object(controller,'command',return_value=subprocess.CompletedProcess([],0,invalid,'')):
                with self.assertRaisesRegex(guest.GuestError,'signature'):controller.local_baseline()
    def test_relative_fixture_paths_reject_escape(self):
        for value in ('/etc/shadow','../baseline.deb'):
            with self.assertRaises(guest.GuestError):self.controller.relative(value)
    def test_mark_never_invents_host_probe_or_protocol_results(self):
        self.controller.mark('tls');self.controller.mark('io-uring-positive');self.controller.mark('artifact-signature')
        self.assertEqual(self.controller.report['checks'],{})
    def test_inspect_requires_actual_single_shot_argv_and_nonroot_uid(self):
        controller=guest.Controller(self.spec,self.work)
        proc=self.root/'proc/123';proc.mkdir(parents=True)
        (proc/'status').write_text('Uid:\t1234\t1234\t1234\t1234\nGid:\t1234\t1234\t1234\t1234\nGroups:\t1234\n')
        binary=self.root/'httpjet';binary.write_bytes(b'authenticated test ELF bytes')
        (proc/'exe').symlink_to(binary)
        runtime=self.root/'run/httpjet';runtime.mkdir(parents=True);(runtime/'ready').write_text('123\n')
        self.spec['manifest']['binaries']['amd64']['binary_sha256']=guest.sha(binary)
        (proc/'cmdline').write_bytes(b'httpjet\0--no-php\0')
        with patch.object(controller,'command',return_value=subprocess.CompletedProcess([],0,'123\n','')),patch.object(guest,'Path',side_effect=self.mapped):
            with self.assertRaisesRegex(guest.GuestError,'single-shot'):controller.inspect()
            (proc/'cmdline').write_bytes(b'httpjet\0--no-php\0--no-multishot-accept\0')
            result=controller.inspect()
        self.assertEqual(result['scope'],'installed-init-service')
        self.assertEqual(result['pid'],123)
        self.assertTrue(result['no_multishot_accept'])

if __name__=='__main__':unittest.main()
