#!/usr/bin/env python3
"""Qualify one exact candidate in a disposable, native-architecture QEMU/TCG VM.

Requires qemu-system-{x86,arm}, qemu-utils, cloud-image-utils, openssh-client,
openssl and (arm64) qemu-efi-aarch64. No KVM, Docker, or host service changes.
Official cloud images are checked against the publisher's HTTPS checksum file;
resolved SHA512, image URL, package hashes and complete guest log enter receipt.
"""
import argparse
import functools
import hashlib
import http.server
from https_fixture import HTTPSFixtureServer
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from release import ARCHES, CHECKS, DISTROS, download, load, render_installer, run, sha, write_json


def image_spec(distro, arch):
    if distro.startswith('debian'):
        number=distro.removeprefix('debian'); codename={'12':'bookworm','13':'trixie'}[number]
        base=f'https://cloud.debian.org/images/cloud/{codename}/latest'
        return base,f'debian-{number}-genericcloud-{arch}.qcow2','SHA512SUMS','sha512'
    number=distro.removeprefix('ubuntu');codename={'24.04':'noble','26.04':'resolute'}[number]
    return f'https://cloud-images.ubuntu.com/releases/{codename}/release',f'ubuntu-{number}-server-cloudimg-{arch}.img','SHA256SUMS','sha256'


def get_image(work, distro, arch):
    base,name,sums,algorithm=image_spec(distro,arch)
    checksum=work/sums;download(base+'/'+sums,checksum)
    matches=[line.split()[0] for line in checksum.read_text().splitlines() if len(line.split())==2 and line.split()[1].lstrip('*./')==name]
    if len(matches)!=1 or not re.fullmatch('[0-9a-f]{'+str(hashlib.new(algorithm).digest_size*2)+'}',matches[0]):
        raise ValueError('official checksum list does not identify exactly one cloud image')
    image=work/name;download(base+'/'+name,image)
    with image.open('rb') as stream:
        actual=hashlib.file_digest(stream,algorithm).hexdigest()
    if actual!=matches[0]:
        raise ValueError('cloud image checksum mismatch')
    with image.open('rb') as stream:
        identity=hashlib.file_digest(stream,'sha512').hexdigest()
    return image,base+'/'+name,identity


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def fixture_baseline(package, output, version):
    # A first-release packaging fixture, never misrepresented as old runtime code.
    with tempfile.TemporaryDirectory(prefix='httpjet-baseline-') as temporary:
        extracted=Path(temporary)/'package';run(['dpkg-deb','-R',package,extracted])
        control=extracted/'DEBIAN/control'
        body=re.sub(r'^Version: .+$','Version: '+version+'-0',control.read_text(),flags=re.M)
        control.write_text(body)
        run(['dpkg-deb','--build','--root-owner-group',extracted,output])


def ssh_args(key, port, known):
    return ['ssh','-i',key,'-p',str(port),'-o','BatchMode=yes','-o','ConnectTimeout=5',
            '-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(known),'qualifier@127.0.0.1']


def wait_probe(command, *, deadline, success=lambda result: result.returncode == 0,
               alive=lambda: True, label='VM probe', interval=5, timeout=10,
               clock=time.monotonic, sleep=time.sleep):
    """Retry SSH timeouts/refusals and readiness failures within one fixed deadline."""
    while clock() < deadline:
        if not alive():
            raise RuntimeError(label + ': VM exited')
        remaining=deadline-clock()
        if remaining <= 0:
            break
        try:
            result=subprocess.run([str(x) for x in command], text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=min(timeout,remaining))
        except subprocess.TimeoutExpired:
            result=None
        if result is not None and success(result):
            return result
        remaining=deadline-clock()
        if remaining > 0:
            sleep(min(interval,remaining))
    raise TimeoutError(label + ': deadline expired')

def main():
    import sys
    if '--row' in sys.argv:
        import matrix_vm
        return matrix_vm.main()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--distro',choices=DISTROS,required=True);parser.add_argument('--architecture',choices=ARCHES,required=True)
    parser.add_argument('--artifacts',type=Path,required=True);parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--public-key',type=Path,required=True);parser.add_argument('--fingerprint',required=True)
    parser.add_argument('--previous-deb',type=Path);parser.add_argument('--first-release',action='store_true')
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--timeout',type=int,default=1800)
    args=parser.parse_args()
    native={'x86_64':'amd64','aarch64':'arm64'}.get(os.uname().machine)
    if native!=args.architecture:
        raise ValueError('qualification VM must run on its native architecture')
    manifest=load(args.artifacts/'manifest.json');package=args.artifacts/manifest['packages'][args.architecture]
    if sha(package)!=manifest['artifacts'][package.name]['sha256']:
        raise ValueError('candidate package hash mismatch')
    if not args.previous_deb and not args.first_release:
        raise ValueError('supply previous signed stable .deb, or explicit --first-release')
    args.output.mkdir(parents=True,exist_ok=True)
    target=args.distro+'-'+args.architecture; log=args.output/(target+'.log')
    with tempfile.TemporaryDirectory(prefix='httpjet-vm-') as temporary, log.open('w') as transcript:
        work=Path(temporary);image,image_url,image_sha512=get_image(work,args.distro,args.architecture)
        key=work/'ssh';run(['ssh-keygen','-q','-t','ed25519','-N','','-f',key])
        user_data=work/'user-data'
        user_data.write_text('#cloud-config\nusers:\n  - name: qualifier\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - '+key.with_suffix('.pub').read_text().strip()+'\nssh_pwauth: false\ndisable_root: true\n')
        metadata=work/'meta-data';metadata.write_text('instance-id: httpjet-qualification\nlocal-hostname: httpjet-qualification\n')
        seed=work/'seed.img';run(['cloud-localds',seed,user_data,metadata])
        overlay=work/'overlay.qcow2';run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',image,overlay])
        run(['qemu-img','resize',overlay,'+8G'])
        payload=work/'payload';payload.mkdir();shutil.copyfile(Path(__file__).with_name('guest-lifecycle.sh'),payload/'guest-lifecycle.sh')
        baseline=payload/'baseline.deb'
        if args.previous_deb:
            shutil.copyfile(args.previous_deb,baseline);baseline_kind='previous-stable'
        else:
            fixture_baseline(package,baseline,manifest['version']);baseline_kind='first-release-fixture'
        baseline_version=run(['dpkg-deb','-f',baseline,'Version']).strip()
        cert=payload/'test-ca.crt';private=work/'test-tls.key'
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=httpjet-qualification',
             '-addext','subjectAltName=IP:10.0.2.2','-keyout',private,'-out',cert],stderr=subprocess.DEVNULL)
        serve=work/'serve';serve.mkdir();shutil.copytree(args.snapshot,serve/'apt')
        server=HTTPSFixtureServer(('127.0.0.1',0),functools.partial(http.server.SimpleHTTPRequestHandler,directory=serve))
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,private)
        server.socket=tls.wrap_socket(server.socket,server_side=True)
        render_installer(Path(__file__).parents[1]/'installer/install.sh.in',payload/'install.sh',args.public_key,args.fingerprint,
                         'https://10.0.2.2:'+str(server.server_port)+'/apt')
        serving=threading.Thread(target=server.serve_forever,daemon=True);serving.start()
        port=unused_port();known=work/'known_hosts'
        command=['qemu-system-x86_64' if args.architecture=='amd64' else 'qemu-system-aarch64',
                 '-accel','tcg,thread=multi','-smp','2','-m','2048','-nographic',
                 '-drive','file='+str(overlay)+',if=virtio,format=qcow2',
                 '-drive','file='+str(seed)+',if=virtio,format=raw',
                 '-netdev',f'user,id=n,hostfwd=tcp:127.0.0.1:{port}-:22','-device','virtio-net-pci,netdev=n']
        if args.architecture=='arm64':
            firmware=next((p for p in (Path('/usr/share/AAVMF/AAVMF_CODE.fd'),Path('/usr/share/qemu-efi-aarch64/QEMU_EFI.fd')) if p.is_file()),None)
            if not firmware:
                raise ValueError('arm64 qualification requires qemu-efi-aarch64 firmware')
            command+=['-machine','virt','-cpu','max','-bios',str(firmware)]
        else:
            command+=['-cpu','max']
        console=work/'console.log'
        with console.open('wb') as serial:
            vm=subprocess.Popen(command,stdout=serial,stderr=subprocess.STDOUT)
            try:
                ssh=ssh_args(key,port,known);deadline=time.monotonic()+args.timeout
                wait_probe(ssh+['true'],deadline=deadline,alive=lambda: vm.poll() is None,label='initial SSH boot')
                subprocess.run([str(x) for x in ssh+['sudo cloud-init status --wait']],check=True,timeout=300,stdout=transcript,stderr=subprocess.STDOUT)
                # tar streams keep payload filenames exact without SCP version differences.
                archive=subprocess.Popen(['tar','-C',str(payload),'-cf','-','.'],stdout=subprocess.PIPE)
                try:
                    subprocess.run([str(x) for x in ssh+['mkdir -p /tmp/httpjet-qualification && tar -xf - -C /tmp/httpjet-qualification']],
                                   stdin=archive.stdout,check=True,timeout=180,stdout=transcript,stderr=subprocess.STDOUT)
                    archive.stdout.close()
                    if archive.wait()!=0:
                        raise RuntimeError('payload tar failed')
                finally:
                    if archive.poll() is None:
                        archive.terminate();archive.wait()
                result=subprocess.run([str(x) for x in ssh+['sudo bash /tmp/httpjet-qualification/guest-lifecycle.sh '+manifest['version']+'-1 '+baseline_version]],
                                      timeout=max(1,deadline-time.monotonic()),stdout=transcript,stderr=subprocess.STDOUT)
                if result.returncode!=0:
                    subprocess.run([str(x) for x in ssh+['sudo journalctl -u httpjet --no-pager -n 200']],timeout=30,stdout=transcript,stderr=subprocess.STDOUT)
                    raise RuntimeError('guest lifecycle failed; inspect '+str(log))
                alive=lambda: vm.poll() is None
                boot_command=ssh+['cat /proc/sys/kernel/random/boot_id']
                boot_id=lambda result: result.returncode==0 and re.fullmatch(r'[0-9a-f-]{36}',result.stdout.strip()) is not None
                old_boot=wait_probe(boot_command,deadline=deadline,alive=alive,success=boot_id,label='pre-reboot identity').stdout.strip()
                try:
                    subprocess.run([str(x) for x in ssh+['sudo systemctl reboot']],timeout=min(15,max(1,deadline-time.monotonic())),stdout=transcript,stderr=subprocess.STDOUT)
                except subprocess.TimeoutExpired:
                    # Reboot may drop SSH before its exit status reaches this client.
                    pass
                reboot_deadline=min(deadline,time.monotonic()+300)
                wait_probe(boot_command,deadline=reboot_deadline,alive=alive,
                           success=lambda result: boot_id(result) and result.stdout.strip()!=old_boot,label='reboot SSH identity')
                functional=ssh+['sudo systemctl is-active --quiet httpjet && curl --max-time 5 --fail --silent http://127.0.0.1/ > /tmp/reboot-response && cmp /usr/share/httpjet/welcome/index.html /tmp/reboot-response && test "$(cat /var/www/httpjet/operator-content.txt)" = operator-owned']
                wait_probe(functional,deadline=reboot_deadline,alive=alive,label='postboot HTTP readiness')
                transcript.write('HTTPJET_CHECK reboot passed\n')
            finally:
                vm.terminate()
                try:
                    vm.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    vm.kill();vm.wait()
                server.shutdown();server.server_close()
                transcript.flush()
                shutil.copyfile(console,args.output/(target+'-console.log'))
        transcript.flush()
        passed=re.findall(r'^HTTPJET_CHECK ([a-z-]+) passed$',log.read_text(),re.M)
        if sorted(passed)!=sorted(CHECKS):
            raise ValueError('guest did not complete every required lifecycle check')
        receipt={'schema':1,'status':'passed','runner':'qemu-tcg','distro':args.distro,'architecture':args.architecture,
                 'manifest_sha256':sha(args.artifacts/'manifest.json'),'package_sha256':sha(package),
                 'image_url':image_url,'image_sha512':image_sha512,'baseline_kind':baseline_kind,
                 'baseline_version':baseline_version,'baseline_sha256':sha(baseline),
                 'checks':{name:'passed' for name in CHECKS},'log':log.name,'log_sha256':sha(log)}
        write_json(args.output/(target+'.json'),receipt)
        print('qualified '+target+' '+receipt['package_sha256'])

if __name__=='__main__':
    main()
