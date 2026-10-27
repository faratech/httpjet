#!/usr/bin/env python3
"""Bounded supervisor discovery; application readiness and errors stay strict."""
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('httpjet_runit_test',Path(__file__).with_name('manage.py'))
generic=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(generic)

class RunitReadiness(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='httpjet-runit-test-');self.addCleanup(self.temporary.cleanup)
        self.manager=generic.Manager(Path(self.temporary.name));self.service=self.manager.path('/etc/sv/httpjet')

    def test_delayed_supervisor_is_ready_before_up_and_application_wait(self):
        clock=[0.0];state={'init':'runit'};observed=[]
        def run(arguments,**options):
            observed.append(arguments[1])
            return subprocess.CompletedProcess(arguments,0 if arguments[1]!='status' or observed.count('status')>=3 else 1)
        with patch.object(generic.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(generic.time,'sleep',side_effect=lambda delay:clock.__setitem__(0,clock[0]+delay)), \
             patch.object(generic,'run',side_effect=run),patch.object(self.manager,'check_profile'), \
             patch.object(self.manager,'load',return_value=state),patch.object(self.manager,'wait_ready') as application:
            self.manager.service('start',state)
        self.assertEqual(observed,['status','status','status','up']);application.assert_called_once_with(state)

    def test_absent_or_hung_supervisor_times_out_without_attempting_up(self):
        for hung in (False,True):
            clock=[0.0];calls=[]
            def run(arguments,**options):
                calls.append((arguments,options))
                if hung:raise subprocess.TimeoutExpired(arguments,options['timeout'])
                return subprocess.CompletedProcess(arguments,1)
            with self.subTest(hung=hung),patch.object(generic.time,'monotonic',side_effect=lambda:clock[0]), \
                 patch.object(generic.time,'sleep',side_effect=lambda delay:clock.__setitem__(0,clock[0]+delay)), \
                 patch.object(generic,'run',side_effect=run),self.assertRaisesRegex(generic.InstallError,'supervisor did not become ready'):
                self.manager.wait_runit_supervisor(self.service,timeout=0.4)
            self.assertLessEqual(clock[0],0.4)
            self.assertTrue(all(args[1]=='status' and 0<options['timeout']<=0.4 for args,options in calls))

    def test_actual_up_error_is_not_retried_or_hidden(self):
        def run(arguments,**options):
            if arguments[1]=='up':raise subprocess.CalledProcessError(1,arguments)
            return subprocess.CompletedProcess(arguments,0)
        with patch.object(generic,'run',side_effect=run) as calls,patch.object(self.manager,'check_profile'), \
             patch.object(self.manager,'wait_ready') as application,self.assertRaises(subprocess.CalledProcessError):
            self.manager.service('start',{'init':'runit'})
        self.assertEqual([call.args[0][1] for call in calls.call_args_list],['status','up']);application.assert_not_called()

    def test_runit_start_keeps_the_supervisor_owned_process_birth_epoch(self):
        state={'init':'runit','launch_tick':200}
        with patch.object(self.manager,'prepare',side_effect=AssertionError('controller must not replace supervisor epoch')), \
             patch.object(self.manager,'service') as service:
            self.manager.start(state)
        self.assertEqual(state['launch_tick'],200);service.assert_called_once_with('start',state)

    def test_other_init_profiles_keep_controller_preparation(self):
        for init in ('systemd','openrc','sysv','none'):
            sequence=[];state={'init':init}
            with self.subTest(init=init),patch.object(self.manager,'prepare',side_effect=lambda state:sequence.append('prepare')), \
                 patch.object(self.manager,'service',side_effect=lambda action,state:sequence.append(action)):
                self.manager.start(state)
            self.assertEqual(sequence,['prepare','start'])

    @unittest.skipUnless(shutil.which('sv') and shutil.which('runsvdir'),'real supervisor proof requires runit tools')
    def test_real_delayed_runsv_and_stale_fifo(self):
        self.service.mkdir(parents=True);script=self.service/'run';script.write_text('#!/bin/sh\nexec sleep 600\n');script.chmod(0o755)
        (self.service/'down').touch();active=Path(self.temporary.name)/'active';active.mkdir();link=active/'httpjet';link.symlink_to(self.service)
        old=subprocess.run(['sv','up',self.service],capture_output=True)
        self.assertNotEqual(old.returncode,0);self.assertIn(b'supervise/ok',old.stdout+old.stderr)
        processes=[]
        def launch():
            time.sleep(0.3);processes.append(subprocess.Popen(['runsvdir',active],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        thread=threading.Thread(target=launch,daemon=True);thread.start();started=time.monotonic()
        try:
            self.manager.wait_runit_supervisor(self.service,timeout=3)
            self.assertGreaterEqual(time.monotonic()-started,0.2)
            subprocess.run(['sv','up',self.service],check=True,capture_output=True)
        finally:
            thread.join();link.unlink(missing_ok=True)
            subprocess.run(['sv','-w','2','force-stop',self.service],capture_output=True)
            subprocess.run(['sv','exit',self.service],capture_output=True)
            for process in processes:
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                process.wait(timeout=3)
        stale=Path(self.temporary.name)/'stale';(stale/'supervise').mkdir(parents=True);os.mkfifo(stale/'supervise/ok')
        with self.assertRaisesRegex(generic.InstallError,'supervisor did not become ready'):
            self.manager.wait_runit_supervisor(stale,timeout=0.3)

if __name__=='__main__':unittest.main()
