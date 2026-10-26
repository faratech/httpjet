#!/usr/bin/env python3
"""Derive locked rootfs tarballs from official media inside a private container."""
import argparse,gzip,hashlib,os,re,shutil,stat,subprocess,tempfile
from pathlib import Path
BASE='debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8'
def call(command,**kwargs):return subprocess.run([str(x) for x in command],check=True,**kwargs)
def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def slackware_packages(listing):
    libraries={'libffi','expat','libxml2','libxslt','libidn2','libunistring','libpsl','nghttp2','brotli','sqlite','readline','libgcrypt','libgpg-error','gmp','nettle','p11-kit','libtasn1','gnutls','libassuan','npth','libksba','pinentry','libssh2','libcap-ng','libseccomp','libtirpc','libnsl','python2'}
    packages=[]
    for name in listing:
        match=re.fullmatch(r'(?:\./)?slackware64/(a|ap|n|l|d)/([^/]+\.t[xg]z)',name)
        if not match:continue
        series,filename=match.groups();package=filename.rsplit('-',3)[0]
        if ((series in ('a','n') and not package.startswith(('kernel-','kernel_')))
            or series=='l' and package in libraries or series=='d' and package=='python3'
            or series=='ap' and package=='slackpkg'):
            packages.append((name,filename))
    if not packages:raise ValueError('official Slackware ISO has no packages')
    return packages

def slackware_bootstrap(root,scripts):
    # The temporary host filesystem may be mounted nodev. A regular temporary
    # sink lets package scripts redirect output until the guest mounts devtmpfs.
    dev=root/'dev'
    if dev.is_symlink() or not dev.is_dir():raise ValueError('Slackware bootstrap needs its own /dev directory')
    null=dev/'null'
    try:mode=null.lstat().st_mode
    except FileNotFoundError:pass
    else:
        if not (stat.S_ISCHR(mode) or stat.S_ISREG(mode)):
            raise ValueError('unexpected Slackware /dev/null type')
        null.unlink()
    null.touch(mode=0o666);null.chmod(0o666)

    # The glibc package stores its shared libraries under lib64/incoming.
    # Until its own post-install script has installed those libraries, the
    # target ldconfig cannot run. Trigger that script's documented fallback.
    ldconfig=root/'sbin/ldconfig'
    if ldconfig.is_symlink() or not ldconfig.is_file():raise ValueError('Slackware ldconfig is missing')
    original_mode=stat.S_IMODE(ldconfig.stat().st_mode)
    applets=scripts/'bin';applets.mkdir()
    names=subprocess.check_output([str(scripts/'busybox'),'--list'],text=True).splitlines()
    for name in names:
        if not name or '/' in name or name in ('.','..'):raise ValueError('invalid BusyBox applet')
        (applets/name).symlink_to('../busybox')
    environment={**os.environ,'PATH':'/bootstrap-scripts/bin:/sbin:/bin:/usr/sbin:/usr/bin'}
    ldconfig.chmod(original_mode & ~0o111)
    try:
        for script in sorted(scripts.glob('[0-9]*.sh')):
            subprocess.run(['chroot',str(root),'/bootstrap-scripts/busybox','sh',
                            '/bootstrap-scripts/'+script.name],check=False,env=environment)
    finally:
        ldconfig.chmod(original_mode)
    call(['chroot',root,'/sbin/ldconfig'])

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
        packages=slackware_packages(listing)
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
        # Seed the extracted packages so native tools can run their original
        # installation scripts. The full package transaction still follows.
        slackware_bootstrap(root,scripts)
        for _,name in sorted(packages):shutil.copyfile(work/name,bootstrap/name)
        runner=scripts/'run'
        # The devs package reinstalls a device node for /dev/null. On a nodev
        # host mount that node cannot be opened, so install it last and restore
        # a temporary regular sink for first boot until devtmpfs is mounted.
        runner.write_text('#!/bin/bash\nset -e\ndevs=\nfor package in /bootstrap-packages/*.t?z; do\n'
                          '  case "$package" in /bootstrap-packages/devs-*.t?z) devs=$package; continue;; esac\n'
                          '  /sbin/installpkg "$package"\ndone\n'
                          '[ -n "$devs" ]\n/sbin/installpkg "$devs"\n'
                          'rm -f /dev/null\n: > /dev/null\nchmod 666 /dev/null\n')
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
