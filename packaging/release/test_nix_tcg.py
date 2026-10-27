#!/usr/bin/env python3
"""Nix launcher rejects hardware acceleration before build/network activity."""
import os
from pathlib import Path
import subprocess
import unittest
import declarative

class NixTcg(unittest.TestCase):
    def guard(self,visible):
        script=declarative.nix_script('x86_64-linux','https://example.invalid/releases',{'ssh':22022,'http':22080,'tls':22443,'quic':22443},False,False)
        guard=script.split('export NIX_REMOTE=local',1)[0]
        intercept='''test() {
  if [[ "$*" == '-e /dev/kvm' ]]; then return "$TEST_KVM_RESULT"; fi
  builtin test "$@"
}
'''
        return subprocess.run(['/bin/bash','-c',intercept+guard+'\nprintf "guard passed\\n"\n'],env={**os.environ,'TEST_KVM_RESULT':'0' if visible else '1'},capture_output=True,text=True)
    def test_visible_kvm_fails_before_builder_runs(self):
        result=self.guard(True)
        self.assertNotEqual(result.returncode,0);self.assertIn('must not expose /dev/kvm',result.stderr)
        self.assertNotIn('guard passed',result.stdout)
    def test_no_kvm_retains_tcg_fallback(self):
        result=self.guard(False)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('guard passed',result.stdout)
    def test_recipe_avoids_conflicting_accelerator_flags(self):
        text=(Path(__file__).resolve().parents[2]/'packaging/nix/qualification.nix').read_text()
        self.assertNotIn('"-accel"',text);self.assertIn('qemu.forceAccel = false;',text)

if __name__=='__main__':unittest.main()
