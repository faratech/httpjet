#!/usr/bin/env python3
"""Use one trusted GnuPG implementation; failures never select another one."""
import importlib.util
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('httpjet_gpg_test',Path(__file__).with_name('manage.py'))
generic=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(generic)
FINGERPRINT='A'*40

class GnuPGSelection(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='httpjet-gpg-selection-');self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)

    def verify(self):
        generic.verify_signature(self.root/'manifest',self.root/'signature',self.root/'key',FINGERPRINT,self.root/'home')

    def success(self,command,**options):
        self.assertEqual(options['env'],{'PATH':generic.TRUSTED_PATH})
        return subprocess.CompletedProcess(command,0,'pub:-:::::::::\nfpr:::::::::'+FINGERPRINT+'\n','')

    def test_gpg2_preferred_using_the_same_clean_path_as_execution(self):
        with patch.dict(os.environ,{'PATH':'/untrusted'}),patch.object(generic.shutil,'which',return_value='/usr/bin/gpg2') as which, \
             patch.object(generic.subprocess,'run',side_effect=self.success) as calls:
            self.verify()
        which.assert_called_once_with('gpg2',path=generic.TRUSTED_PATH)
        self.assertEqual(len(calls.call_args_list),3)
        self.assertTrue(all(c.args[0][0]=='/usr/bin/gpg2' for c in calls.call_args_list))
        self.assertIn('--verify',calls.call_args_list[-1].args[0])

    def test_gpg_is_used_only_when_gpg2_is_unavailable(self):
        def available(name,*,path):
            self.assertEqual(path,generic.TRUSTED_PATH)
            return None if name=='gpg2' else '/usr/bin/gpg'
        with patch.object(generic.shutil,'which',side_effect=available),patch.object(generic.subprocess,'run',side_effect=self.success) as calls:
            self.verify()
        self.assertTrue(all(c.args[0][0]=='/usr/bin/gpg' for c in calls.call_args_list))

    def test_selected_import_or_signature_failure_never_falls_back(self):
        for stage in ('--import','--verify'):
            def failure(command,**options):
                if stage in command:raise subprocess.CalledProcessError(2,command)
                return self.success(command,**options)
            with self.subTest(stage=stage),patch.object(generic.shutil,'which',return_value='/usr/bin/gpg2') as which, \
                 patch.object(generic.subprocess,'run',side_effect=failure) as calls,self.assertRaises(subprocess.CalledProcessError):
                self.verify()
            which.assert_called_once_with('gpg2',path=generic.TRUSTED_PATH)
            self.assertTrue(all(c.args[0][0]=='/usr/bin/gpg2' for c in calls.call_args_list))

    def test_fingerprint_mismatch_remains_fatal_without_alternate_tool(self):
        def wrong(command,**options):
            value=self.success(command,**options)
            value.stdout=value.stdout.replace(FINGERPRINT,'B'*40)
            return value
        with patch.object(generic.shutil,'which',return_value='/usr/bin/gpg2') as which, \
             patch.object(generic.subprocess,'run',side_effect=wrong) as calls,self.assertRaisesRegex(generic.InstallError,'primary fingerprint'):
            self.verify()
        which.assert_called_once();self.assertFalse(any('--verify' in c.args[0] for c in calls.call_args_list))

    @unittest.skipUnless(shutil.which('gpg'),'real GnuPG unavailable')
    def test_real_ed25519_verification_uses_gpg2_and_never_legacy_on_bad_signature(self):
        real=shutil.which('gpg');signer=self.root/'signer';signer.mkdir(mode=0o700)
        tool=[real,'--batch','--homedir',str(signer)]
        try:
            subprocess.run(tool+['--pinentry-mode','loopback','--passphrase','','--quick-generate-key',
                'GPG2 UNIT ONLY <unit@example.invalid>','ed25519','sign','1d'],check=True,capture_output=True)
            listing=subprocess.run(tool+['--with-colons','--fingerprint'],check=True,capture_output=True,text=True).stdout
            fingerprint=next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
            public=self.root/'public.asc';public.write_bytes(subprocess.run(tool+['--armor','--export'],check=True,capture_output=True).stdout)
            document=self.root/'document';document.write_bytes(b'UNIT ONLY signed payload\n');signature=self.root/'signature.asc'
            subprocess.run(tool+['--armor','--detach-sign','--output',str(signature),str(document)],check=True,capture_output=True)
            directory=self.root/'bin';directory.mkdir()
            modern=directory/'gpg2';modern.write_text('#!/bin/sh\nexec '+real+' "$@"\n');modern.chmod(0o755)
            legacy=directory/'gpg';marker=self.root/'legacy-used'
            legacy.write_text('#!/bin/sh\ntouch '+str(marker)+'\nexit 77\n');legacy.chmod(0o755)
            with patch.object(generic,'TRUSTED_PATH',str(directory)+':'+generic.TRUSTED_PATH):
                generic.verify_signature(document,signature,public,fingerprint,self.root/'verification')
                document.write_bytes(b'TAMPERED payload\n')
                with self.assertRaises(subprocess.CalledProcessError):
                    generic.verify_signature(document,signature,public,fingerprint,self.root/'verification')
            self.assertFalse(marker.exists())
        finally:
            subprocess.run(['gpgconf','--homedir',str(signer),'--kill','all'],capture_output=True)

if __name__=='__main__':unittest.main()
