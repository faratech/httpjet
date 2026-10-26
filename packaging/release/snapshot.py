#!/usr/bin/env python3
"""Read-only verification of a schema-2 staged publication boundary."""
from datetime import datetime,timedelta,timezone
from email.utils import parsedate_to_datetime
from pathlib import Path,PurePosixPath
import gzip
import re
import xml.etree.ElementTree as ET
import support
import universal

def api():return universal.api()

def safe_relative(name,prefix):
    path=PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or not name.startswith(prefix):raise ValueError('unsafe repository object path')
    return name

def verify_apt(root,manifest,expected,installer):
    b=api()
    from publish import verified_release
    signed=root/'dists/stable/InRelease';text=verified_release(signed,root/'httpjet-archive-keyring.asc')
    if text!=(signed.parent/'Release').read_text():raise ValueError('APT clearsigned document mismatch')
    fields=dict(line.split(': ',1) for line in text.splitlines() if ': ' in line and not line.startswith(' '))
    now=datetime.now(timezone.utc);issued=parsedate_to_datetime(fields['Date']);expires=parsedate_to_datetime(fields['Valid-Until'])
    if issued>now+timedelta(hours=1) or expires<=now or expires<=issued or expires-issued>timedelta(days=30,minutes=1):raise ValueError('expired APT metadata')
    if fields.get('X-Httpjet-Release-ID')!=manifest['release_id'] or fields.get('X-Httpjet-Archive-Fingerprint')!=expected or fields.get('X-Httpjet-Installer-SHA256')!=b.sha(installer):raise ValueError('APT release/installer identity mismatch')
    names=set();section=None
    for line in text.splitlines():
        if not line.startswith(' '):section=line.rstrip(':')
        elif section=='SHA256':
            digest,size,name=line.split();safe_relative(name,'main/');path=signed.parent/name
            if b.sha(path)!=digest or path.stat().st_size!=int(size):raise ValueError('signed APT index mismatch')
            names.add(name)
    for arch in support.ARCHES:
        relative=f'main/binary-{arch}/Packages'
        if relative not in names or relative+'.gz' not in names:raise ValueError('missing authenticated APT architecture')
        for stanza in (signed.parent/relative).read_text().strip().split('\n\n'):
            item=dict(line.split(': ',1) for line in stanza.splitlines() if ': ' in line and not line.startswith(' '))
            path=root/safe_relative(item['Filename'],'pool/main/h/httpjet/')
            if path.is_symlink() or b.sha(path)!=item['SHA256'] or path.stat().st_size!=int(item['Size']):raise ValueError('APT pool does not match signed index')
    for blob in root.glob('dists/stable/main/binary-*/by-hash/SHA256/*'):
        if blob.is_symlink() or b.sha(blob)!=blob.name:raise ValueError('invalid by-hash object')
    return fields

def verify_rpm(root,key):
    b=api();ns={'r':'http://linux.duke.edu/metadata/repo','p':'http://linux.duke.edu/metadata/common'}
    for arch in ('x86_64','aarch64'):
        repository=root/arch;document=repository/'repodata/repomd.xml'
        universal.verify_signed(document,Path(str(document)+'.asc'),key)
        for data in ET.parse(document).findall('r:data',ns):
            relative=data.find('r:location',ns).get('href');checksum=data.find('r:checksum',ns)
            if checksum.get('type')!='sha256':raise ValueError('RPM metadata needs SHA256')
            path=repository/safe_relative(relative,'repodata/')
            if b.sha(path)!=checksum.text:raise ValueError('RPM metadata hash mismatch')
            if data.get('type')=='primary':
                for item in ET.fromstring(gzip.decompress(path.read_bytes())).findall('p:package',ns):
                    location=item.find('p:location',ns).get('href');digest=item.find('p:checksum',ns)
                    package=repository/safe_relative(location,'Packages/')
                    if digest.get('type')!='sha256' or b.sha(package)!=digest.text:raise ValueError('RPM carrier differs from signed repository')

def verify(snapshot,key,expected):
    b=api();b.validate_key(key,expected);publication=b.load(snapshot/'publication.json')
    if publication.get('schema')!=2 or publication.get('qualified') is not True or publication.get('archive_fingerprint')!=expected:raise ValueError('publication requires a qualified schema-2 release')
    pointer=snapshot/'releases/stable.json';universal.verify_signed(pointer,Path(str(pointer)+'.asc'),key)
    stable=b.load(pointer);support.validate_window(stable)
    if stable['release_id']!=publication['release_id'] or b.sha(pointer)!=publication['stable_sha256']:raise ValueError('signed stable pointer mismatch')
    directory=snapshot/'releases'/support.identity(stable['release_id'])['release_id']
    for name in ('manifest.json','qualification.json'):universal.verify_signed(directory/name,directory/(name+'.asc'),key)
    manifest=b.load(directory/'manifest.json')
    if (b.sha(directory/'manifest.json')!=stable['manifest_sha256'] or (directory/'manifest.json').stat().st_size!=stable['manifest_size']
        or b.sha(directory/'qualification.json')!=stable['qualification_sha256'] or manifest['archive_fingerprint']!=expected):raise ValueError('stable pointer does not bind manifest and matrix proof')
    universal.verify_artifacts(directory,manifest);universal.verify_qualification(directory)
    allowed=set(manifest['artifacts'])|{'manifest.json','manifest.json.asc','qualification.json','qualification.json.asc','SHA256SUMS','install.sh'}
    for target in b.load(directory/'qualification.json')['targets']:
        allowed.update((target['receipt'],target['log']));allowed.update(target.get('evidence',{}))
    if any(path.is_symlink() or not path.is_file() or path.name not in allowed for path in directory.iterdir()):
        raise ValueError('release snapshot contains unbound/private/fixture objects')
    if {path.name for path in (snapshot/'releases').iterdir() if path.is_dir()}!={manifest['release_id']}:
        raise ValueError('publication snapshot contains another release or private qualification fixture')
    if {path.name for path in snapshot.iterdir()}!={'publication.json','apt','rpm','releases'}:
        raise ValueError('publication snapshot has unexpected top-level objects')
    fields=verify_apt(snapshot/'apt',manifest,expected,snapshot/'apt/install.sh')
    if fields.get('X-Httpjet-Manifest-SHA256')!=stable['manifest_sha256'] or fields.get('X-Httpjet-Qualification-SHA256')!=stable['qualification_sha256']:raise ValueError('native and universal release identities disagree')
    if (directory/'install.sh').read_bytes()!=(snapshot/'apt/install.sh').read_bytes() or key.read_bytes()!=(snapshot/'apt/httpjet-archive-keyring.asc').read_bytes():raise ValueError('bootstrap/public key mismatch')
    verify_rpm(snapshot/'rpm',key)
    return publication

def order(snapshot):
    def priority(path):
        name=path.relative_to(snapshot).as_posix()
        immutable=(name.startswith('releases/') and not name.startswith('releases/stable.json')) or name.startswith('apt/pool/') or '/by-hash/' in name or '/Packages/' in name or ('/repodata/' in name and not name.endswith(('repomd.xml','repomd.xml.asc')))
        rank=0 if immutable else 1
        if name.endswith('/repodata/repomd.xml'):rank=2
        if name=='apt/dists/stable/InRelease':rank=3
        if name=='releases/stable.json.asc':rank=4
        if name=='releases/stable.json':rank=5
        return rank,name
    return sorted((path for path in snapshot.rglob('*') if path.is_file() and path.name!='publication.json'),key=priority)

def immutable(name):
    return ((name.startswith('releases/') and not name.startswith('releases/stable.json')) or name.startswith('apt/pool/')
            or '/by-hash/' in name or '/Packages/' in name or ('/repodata/' in name and not name.endswith(('repomd.xml','repomd.xml.asc'))))
