#!/usr/bin/env python3
"""Policy fixtures only; these do not qualify any operating system."""
import copy
from datetime import datetime,timedelta,timezone
import hashlib,json,unittest
import support
class SupportTests(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(support.identity('0.1.10-1')['tag'],'v0.1.10')
        self.assertEqual(support.identity('0.1.10',2)['release_id'],'0.1.10-2')
        self.assertEqual(support.identity('0.1.10-2')['tag'],'v0.1.10-2')
        for value in ('0.1.10-0','0.1.10--1','01.1.10-1','0.1.10-1;true'):
            with self.assertRaises(ValueError):support.identity(value)
        with self.assertRaises(ValueError):support.identity('0.1.10',True)
    def test_required_platforms(self):
        policy=support.load_policy();rows=policy['rows']
        self.assertTrue(all(row['required'] and row['no_multishot_accept'] for row in rows))
        self.assertTrue({'debian','ubuntu','rocky','fedora','alpine','void','devuan','arch','gentoo','slackware','nixos','guix','fedora-coreos','oci-alpine'}.issubset({r['distro'] for r in rows}))
        self.assertEqual({r['architecture'] for r in rows},{'amd64','arm64'})
        self.assertEqual(len(rows),len({r['id'] for r in rows}))
        self.assertEqual(policy['runtime']['transport'],'io_uring');self.assertFalse(policy['runtime']['fallback'])
    def test_pointer_lifetime(self):
        now=datetime(2026,10,26,tzinfo=timezone.utc)
        pointer={'issued_at':now.strftime('%Y-%m-%dT%H:%M:%SZ'),'expires_at':(now+timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')}
        support.validate_window(pointer,now)
        for expires in (now-timedelta(seconds=1),now+timedelta(days=31)):
            pointer['expires_at']=expires.strftime('%Y-%m-%dT%H:%M:%SZ')
            with self.assertRaises(ValueError):support.validate_window(pointer,now)
    def fixture(self):
        row=support.rows()[0];lock={'cloud':{'url':'https://example.invalid/image','sha256':'f'*64}}
        manifest={**support.identity('1.2.3-2'),'binaries':{'amd64':{'artifact':'fixture.tar.gz','binary_sha256':'b'*64}},'artifacts':{'fixture.tar.gz':{'sha256':'a'*64}}}
        receipt={'schema':2,'row_id':row['id'],'release_id':manifest['release_id'],'architecture':row['architecture'],'route':row['route'],'init':row['init'],
                 'status':'passed','manifest_sha256':'c'*64,'payload_sha256':'a'*64,'binary_sha256':'b'*64,
                 'service_uid':10001,'checks':{name:'passed' for name in row['checks']},
                 'image':{'sha256':'d'*64,'origin':'https://example.invalid/image','input_sha256':hashlib.sha256(json.dumps(lock,sort_keys=True,separators=(',',':')).encode()).hexdigest()},
                 'io_uring':{'positive':{'status':'passed','uid':10001,'operations':{'setup':True,'register_probe':True,'enter_nop':True},'global_policy_changed':False},
                             'negative':{'status':'expected_failure','uid':10001,'exit_code':1,'errno':1,'ready_file_created':False,'global_policy_changed':False}},
                 'kernel':{'no_multishot_accept':True}}
        return row,lock,manifest,receipt
    def test_receipt_rejects_skips_wrong_bytes_and_permission_noise(self):
        row,lock,manifest,receipt=self.fixture();support.verify_row(row,receipt,manifest,'c'*64,lock)
        edits=[lambda r:r['checks'].pop('http'),lambda r:r.update(payload_sha256='0'*64),
               lambda r:r['io_uring']['negative'].update(errno=13),lambda r:r['io_uring']['negative'].update(ready_file_created=True),
               lambda r:r['io_uring']['positive'].update(uid=0),lambda r:r['kernel'].update(no_multishot_accept=False)]
        for edit in edits:
            changed=copy.deepcopy(receipt);edit(changed)
            with self.assertRaises(ValueError):support.verify_row(row,changed,manifest,'c'*64,lock)
    def test_image_input_substitution(self):
        row,lock,manifest,receipt=self.fixture();lock['cloud']['sha256']='0'*64
        with self.assertRaises(ValueError):support.verify_row(row,receipt,manifest,'c'*64,lock)
if __name__=='__main__':unittest.main()
