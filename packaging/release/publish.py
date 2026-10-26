#!/usr/bin/env python3
"""Publish a qualified snapshot to S3-compatible storage; InRelease commits last.

Environment: HTTPJET_S3_ENDPOINT (HTTPS), HTTPJET_S3_BUCKET,
HTTPJET_S3_REGION (default auto), AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
optional AWS_SESSION_TOKEN. Endpoint uses path-style bucket addressing.
The bucket is served as https://packages.httpjet.net, with objects below apt/.
"""
import argparse
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
import hashlib
import hmac
import os
from pathlib import Path, PurePosixPath
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from release import load, run, sha, validate_key, verify_artifacts, verify_qualification


def signature(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).digest()

class S3:
    def __init__(self):
        self.endpoint = os.environ['HTTPJET_S3_ENDPOINT'].rstrip('/')
        self.bucket = os.environ['HTTPJET_S3_BUCKET']
        self.region = os.environ.get('HTTPJET_S3_REGION') or 'auto'
        if not self.endpoint.startswith('https://') or '/' in self.bucket:
            raise ValueError('an HTTPS S3 endpoint and plain bucket name are required')
        self.access = os.environ['AWS_ACCESS_KEY_ID']; self.secret = os.environ['AWS_SECRET_ACCESS_KEY']

    def request(self, method, key, data=b'', headers=None):
        path = urllib.parse.quote('/' + self.bucket + '/' + key, safe='/~')
        host = urllib.parse.urlsplit(self.endpoint).netloc
        if urllib.parse.urlsplit(self.endpoint).path:
            raise ValueError('S3 endpoint must not contain a path')
        now = datetime.now(timezone.utc); day = now.strftime('%Y%m%d'); stamp = now.strftime('%Y%m%dT%H%M%SZ')
        digest = hashlib.sha256(data).hexdigest()
        fields = {'host': host, 'x-amz-content-sha256': digest, 'x-amz-date': stamp}
        fields.update({k.lower(): v.strip() for k,v in (headers or {}).items()})
        if os.environ.get('AWS_SESSION_TOKEN'):
            fields['x-amz-security-token'] = os.environ['AWS_SESSION_TOKEN']
        signed = ';'.join(sorted(fields))
        canonical = '\n'.join((method, path, '', ''.join(k + ':' + fields[k] + '\n' for k in sorted(fields)), signed, digest))
        scope = f'{day}/{self.region}/s3/aws4_request'
        message = '\n'.join(('AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()))
        signing = signature(signature(signature(signature(('AWS4' + self.secret).encode(), day), self.region), 's3'), 'aws4_request')
        fields['authorization'] = f'AWS4-HMAC-SHA256 Credential={self.access}/{scope}, SignedHeaders={signed}, Signature={hmac.new(signing,message.encode(),hashlib.sha256).hexdigest()}'
        request = urllib.request.Request(self.endpoint + path, data=data if method == 'PUT' else None, headers=fields, method=method)
        # No redirects: do not forward signing credentials to another endpoint.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        return urllib.request.build_opener(NoRedirect()).open(request, timeout=180)

    def head(self, key):
        try:
            with self.request('HEAD', key) as response:
                return dict(response.headers.items())
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def put(self, key, path, immutable=False, condition=None):
        payload = path.read_bytes(); digest = hashlib.sha256(payload).hexdigest()
        headers = {'x-amz-meta-sha256': digest,
                   'cache-control': 'public,max-age=31536000,immutable' if immutable else 'no-cache,max-age=0,must-revalidate',
                   'content-type': 'text/plain; charset=utf-8' if path.name in ('InRelease','Release','Release.gpg','install.sh') else 'application/octet-stream'}
        if immutable:
            headers['if-none-match'] = '*'
        elif condition:
            headers.update(condition)
        try:
            with self.request('PUT', key, payload, headers):
                pass
        except urllib.error.HTTPError as error:
            if not immutable or error.code != 412:
                raise
            head = {k.lower():v for k,v in self.head(key).items()}
            if head.get('x-amz-meta-sha256') != digest or int(head.get('content-length', '-1')) != len(payload):
                raise ValueError('refusing to replace immutable object ' + key) from error


def verified_release(signed, key):
    with tempfile.TemporaryDirectory(prefix='httpjet-verify-') as temporary:
        ring = Path(temporary) / 'archive.gpg'
        run(['gpg','--batch','--yes','--dearmor','--output',ring,key])
        return run(['gpgv','--keyring',ring,'--output','-',signed])


def verify_snapshot(snapshot, key, expected):
    if load(snapshot/'publication.json').get('schema')==2:
        import snapshot as contracts
        return contracts.verify(snapshot,key,expected)
    validate_key(key, expected)
    publication = load(snapshot / 'publication.json')
    if publication['qualified'] is not True or publication['archive_fingerprint'] != expected:
        raise ValueError('only qualified snapshots with the approved archive key may be published')
    signed = snapshot / 'dists/stable/InRelease'
    release = verified_release(signed, key)
    if sha(signed) != publication['inrelease_sha256'] or release != (signed.parent/'Release').read_text():
        raise ValueError('signed Release mismatch')
    fields = dict(line.split(': ',1) for line in release.splitlines() if ': ' in line and not line.startswith(' '))
    now=datetime.now(timezone.utc)
    issued=parsedate_to_datetime(fields['Date']); expires=parsedate_to_datetime(fields['Valid-Until'])
    if issued>now+timedelta(hours=1) or expires<=now or expires<=issued or expires-issued>timedelta(days=30,minutes=1):
        raise ValueError('expired or invalid signed Date/Valid-Until')
    if fields['X-Httpjet-Archive-Fingerprint'] != expected:
        raise ValueError('Release key identity mismatch')
    section = None; signed_names=set()
    for line in release.splitlines():
        if not line.startswith(' '):
            section = line.rstrip(':')
        elif section == 'SHA256':
            digest,size,name = line.split()
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('unsafe signed metadata path')
            signed_names.add(name)
            local = signed.parent / name
            if sha(local) != digest or local.stat().st_size != int(size):
                raise ValueError('signed index hash mismatch')
    for arch in ('amd64','arm64'):
        relative=f'main/binary-{arch}/Packages'
        if relative not in signed_names or relative+'.gz' not in signed_names:
            raise ValueError('Release does not authenticate every architecture index')
        for stanza in (signed.parent/relative).read_text().strip().split('\n\n'):
            entry=dict(line.split(': ',1) for line in stanza.splitlines() if ': ' in line and not line.startswith(' '))
            name=PurePosixPath(entry['Filename'])
            if name.is_absolute() or '..' in name.parts or not entry['Filename'].startswith('pool/main/h/httpjet/'):
                raise ValueError('unsafe signed package path')
            package=snapshot/entry['Filename']
            if package.is_symlink() or sha(package)!=entry['SHA256'] or package.stat().st_size!=int(entry['Size']):
                raise ValueError('signed package index does not match pool bytes')
    for blob in snapshot.glob('dists/stable/main/binary-*/by-hash/SHA256/*'):
        if blob.is_symlink() or sha(blob)!=blob.name:
            raise ValueError('by-hash object name does not match bytes')
    candidate = snapshot/'releases'/('v'+publication['version'])
    if sha(candidate/'manifest.json') != fields['X-Httpjet-Manifest-SHA256'] or sha(candidate/'qualification.json') != fields['X-Httpjet-Qualification-SHA256']:
        raise ValueError('Release does not bind this qualification')
    with tempfile.TemporaryDirectory(prefix='httpjet-qualified-') as temporary:
        assembled = Path(temporary)
        for path in candidate.iterdir():
            if path.is_file():
                os.link(path, assembled/path.name)
        manifest = load(assembled/'manifest.json')
        for name in manifest['artifacts']:
            if not name.endswith('.deb'):
                continue
            os.link(snapshot/'pool/main/h/httpjet'/name, assembled/name)
        verify_artifacts(assembled,manifest); verify_qualification(assembled)
    if sha(snapshot/'install.sh') != fields['X-Httpjet-Installer-SHA256'] or key.read_bytes() != (snapshot/'httpjet-archive-keyring.asc').read_bytes():
        raise ValueError('installer/public key do not match signed Release')
    return publication


def publication_order(snapshot):
    if (snapshot/'publication.json').exists() and load(snapshot/'publication.json').get('schema')==2:
        import snapshot as contracts
        return contracts.order(snapshot)
    files = [p for p in snapshot.rglob('*') if p.is_file() and p.name != 'publication.json']
    def order(path):
        name = path.relative_to(snapshot).as_posix()
        immutable = name.startswith(('pool/','releases/')) or '/by-hash/' in name
        return (0 if immutable else 2 if name == 'dists/stable/InRelease' else 1, name)
    return sorted(files,key=order)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot',type=Path);parser.add_argument('--public-key',required=True,type=Path)
    parser.add_argument('--fingerprint',required=True);parser.add_argument('--previous-inrelease',type=Path);parser.add_argument('--previous-pointer',type=Path)
    args=parser.parse_args()
    if load(args.snapshot/'publication.json').get('schema')==2:
        import publish_v2
        return publish_v2.publish(args)
    info=verify_snapshot(args.snapshot,args.public_key,args.fingerprint)
    store=S3(); marker='apt/dists/stable/InRelease'; previous=store.head(marker)
    if previous:
        with store.request('GET',marker) as response:
            previous_bytes=response.read()
        if args.previous_inrelease and hashlib.sha256(previous_bytes).hexdigest()!=sha(args.previous_inrelease):
            raise ValueError('stable changed since refresh download; retry from current signed state')
        with tempfile.TemporaryDirectory() as temporary:
            old=Path(temporary)/'InRelease';old.write_bytes(previous_bytes)
            text=verified_release(old,args.public_key)
        old_version=next(line.split(': ',1)[1] for line in text.splitlines() if line.startswith('X-Httpjet-Version: '))
        if tuple(map(int,info['version'].split('.'))) < tuple(map(int,old_version.split('.'))):
            raise ValueError('refusing automatic stable downgrade')
        etag={k.lower():v for k,v in previous.items()}['etag']
        condition={'if-match':etag}
    else:
        if args.previous_inrelease:
            raise ValueError('refresh requires existing stable repository')
        condition={'if-none-match':'*'}
    for path in publication_order(args.snapshot):
        name=path.relative_to(args.snapshot).as_posix()
        immutable=name.startswith(('pool/','releases/')) or '/by-hash/' in name
        store.put('apt/'+name,path,immutable,condition if name=='dists/stable/InRelease' else None)
        print('published '+name)

if __name__=='__main__':
    main()
