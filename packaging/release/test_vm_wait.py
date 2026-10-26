#!/usr/bin/env python3
"""Check reboot and SSH retry policy without booting a guest or issuing SSH."""

import subprocess
import unittest
from unittest.mock import patch

import vm


class Clock:
    def __init__(self):
        self.now = 0
        self.delays = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.delays.append(seconds)
        self.now += seconds


class GuestReadiness(unittest.TestCase):
    def test_timeout_is_retried_then_readiness_succeeds(self):
        clock = Clock()
        ready = subprocess.CompletedProcess(["ssh"], 0, "ready\n")
        def first_timeout(*args, **kwargs):
            if clock.now == 0:
                clock.now += kwargs["timeout"]
                raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
            return ready
        with patch.object(vm.subprocess, "run", side_effect=first_timeout) as execute:
            actual = vm.wait_probe(["ssh"], deadline=40, clock=clock.clock, sleep=clock.sleep)
        self.assertIs(actual, ready)
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(clock.delays, [5])

    def test_reboot_waits_for_new_identity_after_connection_refusal(self):
        clock = Clock()
        results = [subprocess.CompletedProcess(["ssh"], 255, ""),
                   subprocess.CompletedProcess(["ssh"], 0, "old-boot\n"),
                   subprocess.CompletedProcess(["ssh"], 0, "new-boot\n")]
        with patch.object(vm.subprocess, "run", side_effect=results):
            actual = vm.wait_probe(
                ["ssh"], deadline=30, clock=clock.clock, sleep=clock.sleep,
                success=lambda result: result.returncode == 0 and result.stdout.strip() != "old-boot")
        self.assertEqual(actual.stdout.strip(), "new-boot")
        self.assertEqual(clock.now, 10)

    def test_readiness_failures_keep_the_original_deadline(self):
        clock = Clock()
        with patch.object(vm.subprocess, "run", return_value=subprocess.CompletedProcess(["ssh"], 1, "")) as execute:
            with self.assertRaisesRegex(TimeoutError, "deadline"):
                vm.wait_probe(["ssh"], deadline=12, clock=clock.clock, sleep=clock.sleep)
        self.assertEqual(clock.now, 12)
        self.assertEqual([call.kwargs["timeout"] for call in execute.call_args_list], [10, 7, 2])

    def test_timeout_at_deadline_does_not_start_another_probe(self):
        clock = Clock()
        def timeout(*args, **kwargs):
            clock.now += kwargs["timeout"]
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
        with patch.object(vm.subprocess, "run", side_effect=timeout) as execute:
            with self.assertRaises(TimeoutError):
                vm.wait_probe(["ssh"], deadline=3, clock=clock.clock, sleep=clock.sleep)
        self.assertEqual(clock.now, 3)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(clock.delays, [])

    def test_exited_vm_fails_before_ssh(self):
        clock = Clock()
        with patch.object(vm.subprocess, "run") as execute:
            with self.assertRaisesRegex(RuntimeError, "VM exited"):
                vm.wait_probe(["ssh"], deadline=30, alive=lambda: False,
                              clock=clock.clock, sleep=clock.sleep)
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
