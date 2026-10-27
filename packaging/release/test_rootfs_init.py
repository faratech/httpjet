#!/usr/bin/env python3
"""Qualification network config/handoff without touching host interfaces."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT=Path(__file__).with_name('rootfs-init.sh')
FUNCTIONS=SCRIPT.read_text().split('recipe=$(cat /httpjet-qualification-recipe)',1)[0]

class RootfsNetwork(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='httpjet-network-unit-');self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
    def shell(self,body,*arguments,check=True):
        return subprocess.run(['/bin/sh','-c',FUNCTIONS+'\n'+body,'network-unit',*map(str,arguments)],capture_output=True,text=True,check=check)
    def test_config_uses_actual_interface_and_static_qemu_route(self):
        for interface in ('ens3','eth0','enp0s8'):
            target=self.root/interface/'interfaces'
            self.shell('write_alpine_network_config "$1" "$2"',target,interface)
            data=target.read_text()
            self.assertIn('auto lo\niface lo inet loopback\n',data)
            self.assertIn('auto '+interface+'\niface '+interface+' inet static\n',data)
            self.assertIn('address 10.0.2.15/24\n',data);self.assertIn('gateway 10.0.2.2\n',data)
    def test_invalid_or_loopback_target_rejected_before_write(self):
        for interface in ('','lo','ens3\nauto wrong'):
            target=self.root/'interfaces'
            result=self.shell('write_alpine_network_config "$1" "$2"',target,interface,check=False)
            self.assertNotEqual(result.returncode,0);self.assertFalse(target.exists())
    def test_handoff_removes_only_bootstrap_state_before_real_init(self):
        target=self.root/'real-init';target.write_text('#!/bin/sh\nprintf "init\\n" >> "$LOG"\n');target.chmod(0o755)
        for recipe in ('alpine','gentoo-openrc'):
            log=self.root/(recipe+'.log')
            self.shell('''LOG=$1; export LOG
write_alpine_network_config() { printf 'config %s %s\\n' "$1" "$2" >> "$LOG"; }
ip() { printf 'ip %s\\n' "$*" >> "$LOG"; }
recipe=$3; interface=ens3; target_init=$2
exec_target_init
''',log,target,recipe)
            self.assertEqual(log.read_text().splitlines(),(['config /etc/network/interfaces ens3',
                'ip route del default via 10.0.2.2 dev ens3','ip address del 10.0.2.15/24 dev ens3'] if recipe=='alpine' else [])+['init'])

if __name__=='__main__':unittest.main()
