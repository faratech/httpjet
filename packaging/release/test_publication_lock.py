#!/usr/bin/env python3
"""Conditional object-store lock semantics with an in-memory S3 fixture."""
import hashlib
import io
import json
import unittest
import urllib.error
from unittest.mock import patch
import publish_v2

class Reply(io.BytesIO):
    def __init__(self,data=b'',etag=None):
        super().__init__(data);self.headers={'ETag':etag} if etag else {}
class Store:
    def __init__(self):self.objects={};self.calls=[]
    def request(self,method,key,data=b'',headers=None):
        headers=headers or {};self.calls.append((method,key,headers))
        old=self.objects.get(key)
        if headers.get('if-none-match')=='*' and old is not None:
            raise urllib.error.HTTPError(key,412,'Precondition Failed',{},None)
        if 'if-match' in headers and (old is None or old[1]!=headers['if-match']):
            raise urllib.error.HTTPError(key,412,'Precondition Failed',{},None)
        if method=='PUT':
            etag='"'+hashlib.sha256(data).hexdigest()+'"';self.objects[key]=(data,etag);return Reply(etag=etag)
        if method=='GET':
            if old is None:raise urllib.error.HTTPError(key,404,'Not Found',{},None)
            return Reply(old[0],old[1])
        if method=='DELETE':del self.objects[key];return Reply()
        raise AssertionError(method)
class PublicationLock(unittest.TestCase):
    def test_overlapping_publisher_cannot_acquire_or_write(self):
        store=Store()
        with publish_v2.publication_lock(store,'a'*64):
            original=store.objects[publish_v2.LOCK_KEY]
            with self.assertRaisesRegex(ValueError,'locked'):
                with publish_v2.publication_lock(store,'b'*64):self.fail('overlap acquired lock')
            self.assertEqual(store.objects[publish_v2.LOCK_KEY],original)
        self.assertEqual(json.loads(store.objects[publish_v2.LOCK_KEY][0])['state'],'released')
        self.assertFalse(any(method=='DELETE' for method,_,_ in store.calls))
        with publish_v2.publication_lock(store,'b'*64):pass
        self.assertIn('if-match',store.calls[-1][2])
    def test_failure_retains_lock_without_time_based_recovery(self):
        store=Store()
        with patch('sys.stderr',new=io.StringIO()),self.assertRaisesRegex(RuntimeError,'metadata failed'):
            with publish_v2.publication_lock(store,'a'*64):raise RuntimeError('metadata failed')
        self.assertEqual(json.loads(store.objects[publish_v2.LOCK_KEY][0])['state'],'held')
        with self.assertRaisesRegex(ValueError,'locked'):
            with publish_v2.publication_lock(store,'a'*64):pass
    def test_lock_release_cannot_delete_changed_owner(self):
        store=Store()
        with patch('sys.stderr',new=io.StringIO()),self.assertRaises(urllib.error.HTTPError):
            with publish_v2.publication_lock(store,'a'*64):
                store.objects[publish_v2.LOCK_KEY]=(b'operator replacement','"different"')
        self.assertEqual(store.objects[publish_v2.LOCK_KEY][0],b'operator replacement')

if __name__=='__main__':unittest.main()
