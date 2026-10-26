#!/usr/bin/env python3
"""Inspect payloads without extracting administrator-controlled archive paths."""
import io
from pathlib import Path,PurePosixPath
import stat
import subprocess
import tarfile
import tempfile
import hashlib

MAX_BINARY=256*1024*1024

def sha_bytes(value):return hashlib.sha256(value).hexdigest()

def tar_binary(path,release_id):
    expected=f'httpjet-{release_id}/bin/httpjet';found=None;names=set();total=0
    with tarfile.open(path,'r:*') as archive:
        for member in archive:
            name=member.name.rstrip('/');parts=PurePosixPath(name)
            if (parts.is_absolute() or '..' in parts.parts or '\\' in name or '\x00' in name
                or not (name==f'httpjet-{release_id}' or name.startswith(f'httpjet-{release_id}/'))
                or name in names or member.mode & 0o7000 or not (member.isdir() or member.isfile())):
                raise ValueError('unsafe/duplicate payload archive member')
            names.add(name);total+=member.size
            if member.size>MAX_BINARY or total>MAX_BINARY*4:raise ValueError('payload exceeds release size limits')
            if name==expected:
                if not member.isfile() or not member.mode & 0o111:raise ValueError('payload binary is not executable regular file')
                found=archive.extractfile(member).read()
    if found is None:raise ValueError('payload has no canonical binary path')
    return found

def rpm_binary(path):
    process=subprocess.run(['rpm2cpio',str(path)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stream=io.BytesIO(process.stdout);found=None
    while True:
        header=stream.read(110)
        if not header:break
        if len(header)!=110 or header[:6] not in (b'070701',b'070702'):raise ValueError('unsupported RPM cpio payload')
        fields=[int(header[6+i*8:14+i*8],16) for i in range(13)]
        mode,size,namesize=fields[1],fields[6],fields[11]
        if namesize<1 or namesize>16384 or size>MAX_BINARY:raise ValueError('invalid RPM member size')
        name=stream.read(namesize).rstrip(b'\0').decode('utf-8');stream.read(-(110+namesize)%4)
        data=stream.read(size)
        if len(data)!=size:raise ValueError('truncated RPM payload')
        stream.read(-size%4)
        if name=='TRAILER!!!':break
        if name.removeprefix('./')=='usr/bin/httpjet':
            if found is not None or stat.S_IFMT(mode)!=stat.S_IFREG:raise ValueError('duplicate/nonregular RPM binary')
            found=data
    if found is None:raise ValueError('RPM has no /usr/bin/httpjet')
    return found

def verify_carrier_binary(path,kind,expected):
    if kind=='rpm':data=rpm_binary(path)
    elif kind=='deb':
        with tempfile.TemporaryDirectory(prefix='httpjet-carrier-') as temporary:
            subprocess.run(['dpkg-deb','-x',str(path),temporary],check=True,stdout=subprocess.DEVNULL)
            data=(Path(temporary)/'usr/bin/httpjet').read_bytes()
    else:raise ValueError('unknown carrier kind')
    if sha_bytes(data)!=expected:raise ValueError('carrier ELF differs from universal payload')

def oci_binary(path,architecture):
    """Verify a docker-save archive's layer/config identities without loading it."""
    import json
    import posixpath
    mapping={'amd64':'amd64','arm64':'arm64'}
    with tarfile.open(path,'r:*') as outer:
        members={}
        for member in outer:
            name=member.name.removeprefix('./')
            if member.isdir():continue
            if not member.isfile() or name in members or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts:
                raise ValueError('unsafe OCI archive member')
            members[name]=member
        if 'manifest.json' not in members:raise ValueError('expected docker-save manifest')
        manifest=json.load(outer.extractfile(members['manifest.json']))
        if len(manifest)!=1:raise ValueError('OCI archive must contain exactly one image')
        item=manifest[0];configuration=item['Config']
        if configuration not in members:raise ValueError('OCI config is missing')
        config_bytes=outer.extractfile(members[configuration]).read();config=json.loads(config_bytes)
        if config.get('architecture')!=mapping[architecture] or config.get('os')!='linux':raise ValueError('OCI architecture mismatch')
        settings=config.get('config',{})
        if settings.get('User')!='10001:10001' or settings.get('Entrypoint')!=['/usr/bin/httpjet']:
            raise ValueError('OCI image must use the qualified unprivileged entrypoint')
        binary=None;qualifier=None;diffs=[]
        for name in item['Layers']:
            if name not in members:raise ValueError('OCI layer is missing')
            layer_bytes=outer.extractfile(members[name]).read()
            if layer_bytes.startswith(b'\x1f\x8b'):
                import gzip
                layer_bytes=gzip.decompress(layer_bytes)
            diffs.append('sha256:'+sha_bytes(layer_bytes))
            with tarfile.open(fileobj=io.BytesIO(layer_bytes),mode='r:*') as layer:
                for entry in layer:
                    relative=entry.name.removeprefix('./').lstrip('/')
                    if '..' in PurePosixPath(relative).parts:raise ValueError('unsafe OCI layer path')
                    if relative in ('usr/bin/.wh.httpjet','usr/libexec/httpjet/.wh.io-uring-probe'):raise ValueError('OCI removes required executable')
                    if relative in ('usr/bin/httpjet','usr/libexec/httpjet/io-uring-probe'):
                        if not entry.isfile() or entry.size>MAX_BINARY or entry.mode & 0o7000:raise ValueError('unsafe OCI executable')
                        data=layer.extractfile(entry).read()
                        if relative=='usr/bin/httpjet':binary=data
                        else:qualifier=data
        if config.get('rootfs',{}).get('diff_ids')!=diffs:raise ValueError('OCI layer digest mismatch')
        if binary is None or qualifier is None:raise ValueError('OCI image omits server/probe')
        return {'binary':binary,'qualifier':qualifier,'image_id':'sha256:'+sha_bytes(config_bytes),'config':config}
