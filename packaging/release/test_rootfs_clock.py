#!/usr/bin/env python3
"""Guest clock correction tests; no host clock is ever changed."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import rootfs

FUNCTIONS=Path(__file__).with_name('rootfs-init.sh').read_text().split('recipe=$(cat /httpjet-qualification-recipe)',1)[0]
EPOCH=1793060000

class RootfsClock(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='httpjet-clock-unit-');self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
    def clock(self,before,seed=str(EPOCH)):
        seed_file=self.root/'seed';seed_file.write_text(seed+'\n')
        state=self.root/'state';state.write_text(str(before)+'\n');calls=self.root/'sets'
        script=FUNCTIONS+'''
MOCK_STATE=$2; MOCK_CALLS=$3
date() {
    if [ "$1" = -u ] && [ "$2" = +%s ]; then cat "$MOCK_STATE";
    elif [ "$1" = -u ] && [ "$2" = -s ]; then
        printf '%s\\n' "$3" >> "$MOCK_CALLS"
        printf '%s\\n' "${3#@}" > "$MOCK_STATE"
    else return 93; fi
}
initialize_guest_clock "$1"
'''
        result=subprocess.run(['/bin/sh','-c',script,'clock-unit',str(seed_file),str(state),str(calls)],capture_output=True,text=True)
        return result,state.read_text().strip(),calls.read_text().splitlines() if calls.exists() else []
    def test_uninitialized_epoch_uses_controller_seed_and_logs_correction(self):
        result,after,calls=self.clock(0)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(after,str(EPOCH));self.assertEqual(calls,['@'+str(EPOCH)])
        self.assertIn('before=0 controller='+str(EPOCH),result.stdout)
    def test_proper_clock_is_never_reset(self):
        result,after,calls=self.clock(EPOCH+60)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(after,str(EPOCH+60));self.assertEqual(calls,[])
    def test_initialized_clock_outside_window_fails_without_rollback(self):
        for before in (EPOCH-301,EPOCH+7201):
            with self.subTest(before=before):
                result,after,calls=self.clock(before)
                self.assertNotEqual(result.returncode,0);self.assertEqual(after,str(before));self.assertEqual(calls,[])
                self.assertIn('outside controller qualification window',result.stderr)
    def test_invalid_seed_fails_before_changing_clock(self):
        for seed in ('0','999','not-an-epoch','-123','999999999999999999'):
            with self.subTest(seed=seed):
                result,after,calls=self.clock(0,seed)
                self.assertNotEqual(result.returncode,0);self.assertEqual(after,'0');self.assertEqual(calls,[])
    def test_builder_seeds_current_controller_time_not_source_epoch(self):
        with patch.object(rootfs.time,'time',return_value=EPOCH+0.8),patch.dict(os.environ,{'SOURCE_DATE_EPOCH':'0'}):
            value=rootfs.seed_controller_clock(self.root)
        path=self.root/'httpjet-qualification-controller-epoch'
        self.assertEqual(value,EPOCH);self.assertEqual(path.read_text(),str(EPOCH)+'\n');self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
    def test_bad_controller_clock_fails_before_seed_write(self):
        with patch.object(rootfs.time,'time',return_value=0),self.assertRaisesRegex(ValueError,'controller UTC'):
            rootfs.seed_controller_clock(self.root)
        self.assertFalse((self.root/'httpjet-qualification-controller-epoch').exists())

if __name__=='__main__':unittest.main()
