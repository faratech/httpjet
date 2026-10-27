#!/usr/bin/env python3
"""Retry only idempotent cloud-init status on SSH255, never real failures."""
import io
import subprocess
import unittest
from unittest.mock import patch
import matrix_vm

class CloudInitWait(unittest.TestCase):
    def test_transport_close_retries_with_one_fixed_budget(self):
        clock=[10.0];calls=[];transcript=io.BytesIO()
        def remote(*args,**options):
            calls.append((args,options));clock[0]+=100 if len(calls)==1 else 1
            return subprocess.CompletedProcess(['ssh-status'],255 if len(calls)==1 else 0,stdout=None)
        with patch.object(matrix_vm,'ssh',side_effect=remote),patch.object(matrix_vm.time,'monotonic',side_effect=lambda:clock[0]),patch.object(matrix_vm.time,'sleep',side_effect=lambda value:clock.__setitem__(0,clock[0]+value)):
            matrix_vm.wait_cloud_init(None,{'ssh':22},None,transcript,1000,lambda:True)
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[0][1]['timeout'],600);self.assertEqual(calls[1][1]['timeout'],498)
        self.assertEqual(calls[1][0][3],['sudo','-n','cloud-init','status','--wait'])
        self.assertIn(b'(255)',transcript.getvalue())
    def test_arm_larger_budget_does_not_reset_after_transport_retry(self):
        clock=[0.0];calls=[]
        def remote(*args,**options):
            calls.append(options['timeout']);clock[0]+=100 if len(calls)==1 else 1
            return subprocess.CompletedProcess(['ssh-status'],255 if len(calls)==1 else 0,stdout=None)
        with patch.object(matrix_vm,'ssh',side_effect=remote),patch.object(matrix_vm.time,'monotonic',side_effect=lambda:clock[0]),patch.object(matrix_vm.time,'sleep',side_effect=lambda value:clock.__setitem__(0,clock[0]+value)):
            matrix_vm.wait_cloud_init(None,{'ssh':22},None,io.BytesIO(),5000,lambda:True,architecture='arm64')
        self.assertEqual(calls,[1800,1698])
    def test_arm_budget_is_clipped_by_existing_row_deadline(self):
        with patch.object(matrix_vm,'ssh',return_value=subprocess.CompletedProcess(['ssh-status'],0,stdout=None)) as remote,patch.object(matrix_vm.time,'monotonic',return_value=100):
            matrix_vm.wait_cloud_init(None,{'ssh':22},None,io.BytesIO(),400,lambda:True,architecture='arm64')
        self.assertEqual(remote.call_args.kwargs['timeout'],300)
    def test_arm_exit2_and_timeout_are_not_retried(self):
        with patch.object(matrix_vm,'ssh',return_value=subprocess.CompletedProcess(['ssh-status'],2,stdout=None)) as remote,patch.object(matrix_vm.time,'sleep') as sleep:
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                matrix_vm.wait_cloud_init(None,{'ssh':22},None,io.BytesIO(),matrix_vm.time.monotonic()+2000,lambda:True,architecture='arm64')
        self.assertEqual(caught.exception.returncode,2);self.assertEqual(remote.call_count,1);sleep.assert_not_called()
        with patch.object(matrix_vm,'ssh',side_effect=subprocess.TimeoutExpired('status',1800)) as remote,patch.object(matrix_vm.time,'sleep') as sleep:
            with self.assertRaises(subprocess.TimeoutExpired):
                matrix_vm.wait_cloud_init(None,{'ssh':22},None,io.BytesIO(),matrix_vm.time.monotonic()+2000,lambda:True,architecture='arm64')
        self.assertEqual(remote.call_count,1);sleep.assert_not_called()

    def test_real_failure_including_exit2_is_never_retried(self):
        for code in (1,2,126,127):
            with self.subTest(code=code),patch.object(matrix_vm,'ssh',return_value=subprocess.CompletedProcess(['ssh-status'],code,stdout=None)) as remote,patch.object(matrix_vm.time,'sleep') as sleep:
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    matrix_vm.wait_cloud_init(None,{'ssh':22},None,io.BytesIO(),matrix_vm.time.monotonic()+10,lambda:True)
                self.assertEqual(caught.exception.returncode,code);self.assertEqual(remote.call_count,1);sleep.assert_not_called()
    def test_repeated_transport_failures_stop_at_original_deadline(self):
        clock=[0.0];calls=[]
        def remote(*args,**options):
            calls.append(options['timeout']);return subprocess.CompletedProcess(['ssh-status'],255,stdout=None)
        with patch.object(matrix_vm,'ssh',side_effect=remote),patch.object(matrix_vm.time,'monotonic',side_effect=lambda:clock[0]),patch.object(matrix_vm.time,'sleep',side_effect=lambda value:clock.__setitem__(0,clock[0]+value)):
            with self.assertRaises(TimeoutError):matrix_vm.wait_cloud_init(None,{'ssh':22},None,io.BytesIO(),3,lambda:True)
        self.assertEqual(clock[0],3);self.assertEqual(calls,[3,1])
    def test_query_timeout_is_not_retried(self):
        with patch.object(matrix_vm,'ssh',side_effect=subprocess.TimeoutExpired('status',1)) as remote,patch.object(matrix_vm.time,'sleep') as sleep:
            with self.assertRaises(subprocess.TimeoutExpired):matrix_vm.wait_cloud_init(None,{'ssh':22},None,io.BytesIO(),matrix_vm.time.monotonic()+10,lambda:True)
        self.assertEqual(remote.call_count,1);sleep.assert_not_called()

    def test_vm_exit_aborts_before_another_status_query(self):
        with patch.object(matrix_vm,'ssh',return_value=subprocess.CompletedProcess(['ssh-status'],255,stdout=None)) as remote,patch.object(matrix_vm.time,'sleep'):
            alive=iter([True,False])
            with self.assertRaisesRegex(RuntimeError,'VM exited'):
                matrix_vm.wait_cloud_init(None,{'ssh':22},None,io.BytesIO(),matrix_vm.time.monotonic()+10,lambda:next(alive))
        self.assertEqual(remote.call_count,1)

if __name__=='__main__':unittest.main()
