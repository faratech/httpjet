#!/usr/bin/env python3
"""Resolve official, checksum-locked qualification inputs before candidate signing."""
import argparse,base64,hashlib,json,os,re,shutil,subprocess,tempfile,urllib.request
from pathlib import Path
import support
from release import download,sha,write_json

def text(url):
    if not url.startswith('https://'):raise ValueError('image metadata requires HTTPS')
    with urllib.request.urlopen(url,timeout=45) as response:
        if not response.url.startswith('https://'):raise ValueError('image metadata downgraded HTTPS')
        return response.read().decode()

def sums(document,algorithm):
    result={};length={'sha256':64,'sha512':128}[algorithm]
    for line in document.splitlines():
        match=re.fullmatch(r'(?:SHA256|SHA512) \(([^)]+)\) = ([0-9a-fA-F]+)',line.strip())
        if match and len(match[2])==length:result[match[1]]=match[2].lower();continue
        match=re.match(r'^([0-9a-fA-F]{'+str(length)+r'})\s+\*?(.+?)\s*$',line)
        if match:result[match[2].removeprefix('./')]=match[1].lower()
    return result

def materialize(asset,cache):
    path=cache/asset['sha256']/Path(asset['url'].split('?')[0]).name;path.parent.mkdir(parents=True,exist_ok=True)
    if not path.exists():download(asset['url'],path)
    if sha(path)!=asset['sha256']:raise ValueError('locked image source checksum mismatch')
    return path

def asset(url,digest,algorithm,cache,format=None):
    if algorithm=='sha256':result={'url':url,'sha256':digest}
    else:
        path=cache/(algorithm+'-'+digest)/Path(url.split('?')[0]).name;path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists():download(url,path)
        with path.open('rb') as stream:actual=hashlib.file_digest(stream,algorithm).hexdigest()
        if actual!=digest:raise ValueError('official source checksum mismatch')
        result={'url':url,'sha256':sha(path),'publisher_checksum':algorithm+':'+digest}
    if format:result['format']=format
    return result

def kernel(arch):
    base='https://cloud-images.ubuntu.com/releases/noble/release/unpacked'
    checks=sums(text(base+'/SHA256SUMS'),'sha256');prefix='ubuntu-24.04-server-cloudimg-'+arch
    return ({'url':base+'/'+prefix+'-vmlinuz-generic','sha256':checks[prefix+'-vmlinuz-generic']},
            {'url':base+'/'+prefix+'-initrd-generic','sha256':checks[prefix+'-initrd-generic']})

def tree_hash(directory):
    h=hashlib.sha256()
    for path in sorted(directory.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:h.update(path.relative_to(directory).as_posix().encode()+b'\0'+bytes.fromhex(sha(path)))
    return h.hexdigest()
def oci_reference(repository,tag,arch):
    token=json.loads(text('https://auth.docker.io/token?service=registry.docker.io&scope=repository:'+repository+':pull'))['token']
    accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json'
    request=urllib.request.Request('https://registry-1.docker.io/v2/'+repository+'/manifests/'+tag,headers={'Authorization':'Bearer '+token,'Accept':accept})
    with urllib.request.urlopen(request,timeout=45) as response:raw=response.read()
    document=json.loads(raw)
    if 'manifests' in document:
        matching=[entry for entry in document['manifests'] if entry.get('platform',{}).get('os')=='linux' and entry.get('platform',{}).get('architecture')==arch]
        if len(matching)!=1:raise ValueError('official OCI index lacks one native architecture')
        digest=matching[0]['digest']
    else:digest='sha256:'+hashlib.sha256(raw).hexdigest()
    if not re.fullmatch('sha256:[0-9a-f]{64}',digest):raise ValueError('invalid registry digest')
    return {'image':'docker.io/'+repository+'@'+digest,'sha256':digest[7:],'origin':'https://registry-1.docker.io/v2/'+repository+'/manifests/'+tag}

def cloud(row,cache):
    source=row['source'];base=source['base'];filename=source['file'];algorithm=source['algorithm']
    checks=sums(text(base+'/'+source['checksums']),algorithm)
    if filename not in checks:
        # Some mirrors publish per-image checksum documents.
        checks.update(sums(text(base+'/'+filename+'.CHECKSUM'),algorithm))
    return {'cloud':asset(base+'/'+filename,checks[filename],algorithm,cache,'qcow2'),'init':row['init']}

def raw_rootfs(row,cache):
    recipe=row['source']['recipe'];arch={'amd64':'x86_64','arm64':'aarch64'}[row['architecture']]
    if recipe=='alpine':
        import yaml
        base='https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/'+arch
        entries=yaml.safe_load(text(base+'/latest-releases.yaml'))
        entry=next(item for item in entries if item.get('flavor')=='alpine-minirootfs')
        source=asset(base+'/'+entry['file'],entry['sha256'],'sha256',cache,'tar.gz');target='/sbin/openrc-init'
    elif recipe=='void-musl':
        base='https://repo-default.voidlinux.org/live/current';checks=sums(text(base+'/sha256sum.txt'),'sha256')
        names=sorted(name for name in checks if re.fullmatch('void-'+arch+r'-musl-ROOTFS-[0-9]{8}\.tar\.xz',name))
        if not names:raise ValueError('official Void index has no musl ROOTFS')
        source=asset(base+'/'+names[-1],checks[names[-1]],'sha256',cache,'tar.xz');target='/sbin/runit'
    elif recipe=='arch':
        base='https://geo.mirror.pkgbuild.com/iso/latest';checks=sums(text(base+'/sha256sums.txt'),'sha256')
        filename='archlinux-bootstrap-x86_64.tar.zst';source=asset(base+'/'+filename,checks[filename],'sha256',cache,'tar.zst')
        source['strip_prefix']='root.x86_64';target='/sbin/init'
    elif recipe=='gentoo-openrc':
        base='https://distfiles.gentoo.org/releases/arm64/autobuilds'
        entry=re.search(r'^([0-9TZ]+/stage3-arm64-openrc-[0-9TZ]+\.tar\.xz)\s+[0-9]+$',text(base+'/latest-stage3-arm64-openrc.txt'),re.M)
        if not entry:raise ValueError('official Gentoo stage index has no canonical stage3')
        relative=entry[1];checks=sums(text(base+'/'+relative+'.DIGESTS'),'sha512');filename=relative.rsplit('/',1)[1]
        source=asset(base+'/'+relative,checks.get(filename,checks.get(relative)),'sha512',cache,'tar.xz');target='/sbin/init'
    else:raise ValueError('prepared-media recipe must use prepare_media')
    source.setdefault('strip_prefix','');k,i=kernel(row['architecture'])
    return {'rootfs':source,'kernel':k,'initrd':i,'init':target,'bootstrap':recipe,'prepared':False}
def prepare_media(row,cache,output):
    recipe=row['source']['recipe']
    if recipe=='devuan-sysv':
        base='https://files.devuan.org/devuan_excalibur/minimal-live'
        names=re.findall(r'href="(devuan_excalibur_[0-9.]+_amd64_minimal-live\.iso)"',text(base+'/'))
        if not names:raise ValueError('official Devuan minimal-live ISO not found')
        filename=sorted(names,key=lambda s:tuple(map(int,re.search(r'excalibur_([0-9.]+)_amd64',s)[1].split('.'))))[-1]
        checks=sums(text(base+'/'+filename+'.sha256'),'sha256');source=asset(base+'/'+filename,checks[filename],'sha256',cache,'iso')
    elif recipe=='slackware-sysv':
        source={'url':'https://mirrors.slackware.com/slackware/slackware-iso/slackware64-15.0-iso/slackware64-15.0-install-dvd.iso',
                'sha256':'4b32d575097f2238fa9dc1cd753286493a4be95a3004e9b1e81748b4f1d0c5da','format':'iso',
                'checksum_origin':'https://mirrors.slackware.com/slackware/slackware-iso/slackware64-15.0-iso/slackware64-15.0-install-dvd.iso.mirrorlist'}
    else:raise ValueError('unexpected media recipe')
    iso=materialize(source,cache);name='qualification-rootfs-'+row['id']+'.tar.gz';target=output/name
    subprocess.run(['python3',str(Path(__file__).parent/'images/prepare-rootfs.py'),recipe,str(iso),source['sha256'],str(target)],check=True)
    k,i=kernel(row['architecture'])
    lock={'rootfs':{'artifact':name,'sha256':sha(target),'format':'tar.gz','strip_prefix':'','origin':source['url']},
          'kernel':k,'initrd':i,'init':'/sbin/init','bootstrap':recipe,'prepared':False,'installation_media':source}
    return lock,{name:{'sha256':sha(target),'size':target.stat().st_size,'architecture':row['architecture'],'origin':source['url']}}

def special(row,root):
    kind=row['executor'];arch=row['architecture'];system={'amd64':'x86_64-linux','arm64':'aarch64-linux'}[arch]
    if kind=='cloud-lock':
        entries=json.loads(text('https://fedoraproject.org/releases.json'));machine={'amd64':'x86_64','arm64':'aarch64'}[arch]
        candidates=[item for item in entries if str(item.get('version','')).isdigit() and item.get('arch')==machine and item.get('variant')=='Cloud' and item.get('link','').endswith('.qcow2')]
        if not candidates:raise ValueError('Fedora catalog has no stable QCOW2 image')
        latest=max(int(item['version']) for item in candidates);entry=next(item for item in candidates if int(item['version'])==latest)
        return {'cloud':{'url':entry['link'],'sha256':entry['sha256'],'format':'qcow2','origin':'https://fedoraproject.org/releases.json'},'init':'systemd'}
    if kind=='coreos':
        stream=json.loads(text('https://builds.coreos.fedoraproject.org/streams/stable.json'));machine={'amd64':'x86_64','arm64':'aarch64'}[arch]
        entry=stream['architectures'][machine]['artifacts']['qemu']['formats']['qcow2.xz']['disk']
        return {'cloud':{'url':entry['location'],'sha256':entry['sha256'],'format':'qcow2.xz','uncompressed_sha256':entry['uncompressed-sha256']},
                'definition':{'recipe':'packaging/release/images/coreos.bu','sha256':tree_hash(root/'packaging/release/images')},'init':'systemd'}
    if kind=='oci':return {'oci':oci_reference('library/alpine','3',arch),'init':'foreground'}
    if kind=='nix-image':
        return {'definition':{'origin':'https://github.com/NixOS/nixpkgs/commit/1f607aa79b6356ed45d3cd3c8079c196e79efa2c',
                             'recipe':'packaging/nix/qualification.nix','sha256':tree_hash(root/'packaging/nix'),'system':system},
                'builder':{'image':'docker.io/nixos/nix@sha256:f159a58f390677f41e8e900a74b6e2f9c7f27b364122ae6acf7a652ce6c551c0'},'init':'systemd'}
    if kind=='guix-image':
        return {'definition':{'origin':'https://codeberg.org/guix/guix/commit/ae27c30d2900d30af80abc99c6deb4ec5c2be87f',
                             'recipe':'packaging/guix/qualification.scm','sha256':tree_hash(root/'packaging/guix'),'system':system},
                'channels_sha256':sha(root/'packaging/guix/channels.scm'),'init':'shepherd'}
    raise ValueError('unknown source resolver')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--cache',type=Path,required=True)
    args=parser.parse_args();root=Path(__file__).resolve().parents[2]
    if args.output.exists():raise ValueError('image lock output must not exist')
    args.output.mkdir(parents=True);args.cache.mkdir(parents=True,exist_ok=True)
    release_id=re.search(r'\(([^)]+)\)',(root/'debian/changelog').read_text().splitlines()[0])[1];support.identity(release_id)
    locks={};artifacts={}
    for row in support.rows():
        if row['executor']=='cloud':lock=cloud(row,args.cache)
        elif row['executor']=='rootfs':
            if row['source']['recipe'] in ('devuan-sysv','slackware-sysv'):
                lock,prepared=prepare_media(row,args.cache,args.output);artifacts.update(prepared)
            else:lock=raw_rootfs(row,args.cache)
        else:lock=special(row,root)
        if row['distro'] in ('rocky','fedora','fedora-coreos'):
            lock['operator_configuration']={'scope':'disposable-qualification-image','io_uring_disabled':0,'record_stock_policy':True}
        locks[row['id']]=lock
    write_json(args.output/'qualification-images.json',{'schema':1,'release_id':release_id,'matrix_sha256':support.digest(support.POLICY),'rows':locks,'artifacts':artifacts,
               'oci_bases':{arch:oci_reference('library/alpine','3',arch) for arch in support.ARCHES}})
if __name__=='__main__':main()
