#!/usr/bin/env python3
"""Conditional publication of a completely qualified schema-2 site snapshot."""
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import tempfile
import snapshot
import universal

LOCK_KEY='_httpjet/publication.lock'

@contextmanager
def publication_lock(store,stable_sha256):
    """Serialize all native metadata/pointer pairs, including manual publishers.

    A failed publisher retains its lock. Time does not prove that its process
    stopped, so recovery is an explicit operator action after inspecting it.
    """
    token=secrets.token_hex(32)
    document={'schema':1,'state':'held','token':token,'stable_sha256':stable_sha256,
              'created_at':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
              'run_id':os.environ.get('GITHUB_RUN_ID'),'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT')}
    encode=lambda value:json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
    data=encode(document);condition={'if-none-match':'*'}
    try:
        with store.request('GET',LOCK_KEY) as response:
            previous=json.loads(response.read());old_etag=response.headers.get('ETag')
        if previous.get('schema')!=1 or previous.get('state')!='released' or not old_etag:
            raise ValueError('publication is locked; inspect _httpjet/publication.lock before explicit recovery')
        condition={'if-match':old_etag}
    except urllib.error.HTTPError as error:
        if error.code!=404:raise
    def headers(payload,compare):
        return {**compare,'content-type':'application/json','cache-control':'no-store',
                'x-amz-meta-sha256':hashlib.sha256(payload).hexdigest()}
    try:
        with store.request('PUT',LOCK_KEY,data,headers(data,condition)) as response:
            etag=response.headers.get('ETag')
    except urllib.error.HTTPError as error:
        if error.code in (409,412):raise ValueError('publication is locked; inspect _httpjet/publication.lock before explicit recovery') from error
        raise
    try:
        if not etag:raise ValueError('S3 provider must return the conditional lock ETag')
        with store.request('GET',LOCK_KEY) as response:
            if response.read()!=data:raise ValueError('S3 provider did not preserve the acquired lock')
        yield document
        released=encode({**document,'state':'released','released_at':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')})
        with store.request('PUT',LOCK_KEY,released,headers(released,{'if-match':etag})):pass
    except BaseException:
        print('Publication lock retained after failure: '+LOCK_KEY+' token='+token,
              file=sys.stderr,flush=True)
        raise

def publish(args):
    from publish import S3
    info=snapshot.verify(args.snapshot,args.public_key,args.fingerprint)
    store=S3()
    with publication_lock(store,info['stable_sha256']):
        return publish_locked(args,store,info)

def publish_locked(args,store,info):
    b=universal.api();marker='releases/stable.json';heads={}
    for name in (marker,'apt/dists/stable/InRelease','rpm/x86_64/repodata/repomd.xml','rpm/aarch64/repodata/repomd.xml'):
        head=store.head(name)
        heads[name]={'if-match':{k.lower():v for k,v in head.items()}['etag']} if head else {'if-none-match':'*'}
    if 'if-match' in heads[marker]:
        with tempfile.TemporaryDirectory(prefix='httpjet-current-pointer-') as temporary:
            path=Path(temporary)/'stable.json'
            for name in ('stable.json','stable.json.asc'):
                with store.request('GET','releases/'+name) as response:(path.parent/name).write_bytes(response.read())
            universal.verify_signed(path,Path(str(path)+'.asc'),args.public_key)
            previous=b.load(path)
            if b.sha(path)!=info.get('previous_stable_sha256'):raise ValueError('stable changed after staging; fetch current state again')
            if args.previous_pointer and b.sha(path)!=b.sha(args.previous_pointer):raise ValueError('refresh pointer changed')
            if universal.release_tuple(info['release_id'])<universal.release_tuple(previous['release_id']):raise ValueError('automatic release downgrade is forbidden')
    elif info.get('previous_stable_sha256') is not None or args.previous_pointer:
        raise ValueError('previous stable repository disappeared')
    for path in snapshot.order(args.snapshot):
        name=path.relative_to(args.snapshot).as_posix()
        store.put(name,path,snapshot.immutable(name),heads.get(name))
        print('published '+name)
