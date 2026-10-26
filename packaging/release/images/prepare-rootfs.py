#!/usr/bin/env python3
"""Derive locked rootfs tarballs from official media inside a private container."""
import argparse,gzip,hashlib,os,re,shutil,subprocess,tempfile
from pathlib import Path
BASE='debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8'
def call(command,**kwargs):return subprocess.run([str(x) for x in command],check=True,**kwargs)
def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def inside(kind,source,output,work=Path('/work')):
    # The runner owns /work, but the builder container creates its extracted
    # tree as root. Remove only the directory allocated by this invocation so
    # the unprivileged runner can clean its TemporaryDirectory on every path.
    root=work/'root'
    root.mkdir()
    try:
        return inside_tree(kind,source,output,work,root)
    finally:
        if root.is_symlink():root.unlink()
        elif root.exists():shutil.rmtree(root)

def inside_tree(kind,source,output,work,root):
    listing=subprocess.check_output(['bsdtar','-tf',str(source)],text=True).splitlines()
    if kind=='devuan-sysv':
        matches=[name for name in listing if name.rstrip('/').endswith('filesystem.squashfs')]
        if len(matches)!=1:raise ValueError('official live ISO must have one root squashfs')
        squash=work/'root.squashfs'
        with squash.open('wb') as stream:call(['bsdtar','-xOf',source,matches[0]],stdout=stream)
        root.rmdir();call(['unsquashfs','-no-progress','-d',root,squash])
    elif kind=='slackware-sysv':
        libraries={'libffi','expat','libxml2','libxslt','libidn2','libunistring','libpsl','nghttp2','brotli','sqlite','readline','libgcrypt','libgpg-error','gmp','nettle','p11-kit','libtasn1','gnutls','libassuan','npth','libksba','pinentry','libssh2','libcap-ng','libseccomp','libtirpc','libnsl','python2'}
        packages=[]
        for name in listing:
            match=re.fullmatch(r'(?:\./)?slackware64/(a|n|l|d)/([^/]+\.t[xg]z)',name)
            if not match:continue
            series,filename=match.groups();package=filename.rsplit('-',3)[0]
            if ((series in ('a','n') and not package.startswith(('kernel-','kernel_'))) or series=='l' and package in libraries or series=='d' and package=='python3'):
                packages.append((name,filename))
        if not packages:raise ValueError('official Slackware ISO has no packages')
        scripts=root/'bootstrap-scripts';scripts.mkdir()
        for index,(member,name) in enumerate(sorted(packages)):
            archive=work/name
            with archive.open('wb') as stream:call(['bsdtar','-xOf',source,member],stdout=stream)
            call(['tar','-xf',archive,'-C',root])
            doinst=root/'install/doinst.sh'
            if doinst.exists():shutil.copyfile(doinst,scripts/f'{index:04}.sh')
            shutil.rmtree(root/'install',ignore_errors=True)
        bootstrap=root/'bootstrap-packages';bootstrap.mkdir()
        shutil.copyfile('/bin/busybox',scripts/'busybox');(scripts/'busybox').chmod(0o755)
        # Static bootstrap shell creates the original package symlinks before
        # native glibc tools can run. Final package installation is mandatory.
        for script in sorted(scripts.glob('[0-9]*.sh')):
            subprocess.run(['chroot',str(root),'/bootstrap-scripts/busybox','sh','/bootstrap-scripts/'+script.name],check=False)
        for _,name in sorted(packages):shutil.copyfile(work/name,bootstrap/name)
        runner=scripts/'run'
        runner.write_text('#!/bin/bash\nset -e\nfor package in /bootstrap-packages/*.t?z; do\n  /sbin/installpkg "$package"\ndone\n')
        call(['chroot',root,'/bin/bash','/bootstrap-scripts/run'])
        shutil.rmtree(scripts);shutil.rmtree(bootstrap)
        mirrors=root/'etc/slackpkg/mirrors'
        if mirrors.exists():mirrors.write_text('https://mirrors.slackware.com/slackware/slackware64-15.0/\n')
    else:raise ValueError('unknown prepared rootfs recipe')
    for path in (root/'etc/ssh').glob('ssh_host_*'):
        if path.is_file() or path.is_symlink():path.unlink()
    machine=root/'etc/machine-id'
    if machine.exists() and not machine.is_symlink():machine.write_text('')
    with output.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as compressed:
        process=subprocess.Popen(['tar','--sort=name','--numeric-owner','-C',str(root),'-cf','-','.'],stdout=subprocess.PIPE)
        shutil.copyfileobj(process.stdout,compressed);process.stdout.close()
        if process.wait()!=0:raise RuntimeError('rootfs archive creation failed')
    # The caller is the unprivileged runner, not the container's root account.
    output.chmod(0o644)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('recipe',choices=('devuan-sysv','slackware-sysv'));parser.add_argument('source',type=Path)
    parser.add_argument('sha256');parser.add_argument('output',type=Path);parser.add_argument('--inside',action='store_true')
    args=parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}',args.sha256) or digest(args.source)!=args.sha256:raise ValueError('installation-media SHA256 mismatch')
    if args.output.exists():raise ValueError('prepared rootfs output must not exist')
    if args.inside:
        if not Path('/.dockerenv').exists() or args.source!=Path('/source.iso'):
            raise ValueError('internal preparation runs only in the isolated builder container')
        return inside(args.recipe,args.source,args.output)
    with tempfile.TemporaryDirectory(prefix='httpjet-prepared-rootfs-') as temporary:
        work=Path(temporary);context=work/'context';context.mkdir()
        (context/'Containerfile').write_text('FROM '+BASE+'\nRUN apt-get update && apt-get install -y --no-install-recommends python3 libarchive-tools squashfs-tools tar xz-utils gzip busybox-static\n')
        call(['docker','build','--file',context/'Containerfile','--iidfile',work/'image',context])
        args.output.parent.mkdir(parents=True,exist_ok=True)
        call(['docker','run','--rm','--network=none','--volume',str(args.source.resolve())+':/source.iso:ro',
              '--volume',str(Path(__file__).resolve())+':/prepare.py:ro','--volume',str(work)+':/work',
              (work/'image').read_text().strip(),'python3','/prepare.py',args.recipe,'/source.iso',args.sha256,'/work/rootfs.tar.gz','--inside'])
        shutil.copyfile(work/'rootfs.tar.gz',args.output)

if __name__=='__main__':main()
