#!/usr/bin/env python3
"""Execute one authenticated support row; a missing executor never becomes a pass."""
import argparse,sys,contextlib,functools,gzip,hashlib,http.server,io,json,lzma,os,pwd,re,shlex,shutil,socket,ssl,subprocess,tarfile,tempfile,threading,time
from pathlib import Path
import payload,support,universal
import release as b
import vm

ROOT=Path(__file__).resolve().parents[2]

def json_digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def write(path,value):b.write_json(path,value)
def command(args,**kwargs):return subprocess.run([str(x) for x in args],check=True,**kwargs)
def port(udp=False):
    while True:
        with socket.socket() as tcp:
            tcp.bind(('127.0.0.1',0));number=tcp.getsockname()[1]
            if not udp:return number
            try:
                with socket.socket(type=socket.SOCK_DGRAM) as datagram:datagram.bind(('127.0.0.1',number))
                return number
            except OSError:continue

def ssh(key,number,known,args,*,output=None,timeout=1800,check=True,cwd=None):
    invocation=[str(x) for x in vm.ssh_args(key,number,known)]+[(('cd '+shlex.quote(cwd)+' && ') if cwd else '')+shlex.join([str(x) for x in args])]
    return subprocess.run(invocation,check=check,stdout=output or subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)

def send_tree(key,number,known,source,target):
    archive=subprocess.Popen(['tar','-C',str(source),'-cf','-','.'],stdout=subprocess.PIPE)
    invocation=[str(x) for x in vm.ssh_args(key,number,known)]+['mkdir -p '+shlex.quote(target)+' && tar -xf - -C '+shlex.quote(target)]
    try:
        subprocess.run(invocation,stdin=archive.stdout,check=True,timeout=300)
        archive.stdout.close()
        if archive.wait()!=0:raise RuntimeError('qualification input transfer failed')
    finally:
        if archive.poll() is None:archive.terminate();archive.wait()

def receive(key,number,known,remote,local):
    with local.open('wb') as output:ssh(key,number,known,['sudo','-n','cat',remote],output=output,timeout=60)

def source_asset(asset,work,name,artifacts=None,artifact_manifest=None):
    path=work/name
    if asset.get('artifact'):
        filename=b.filename(asset['artifact']);expected=artifact_manifest['artifacts'][filename]
        source=artifacts/filename
        if source.is_symlink() or expected['sha256']!=asset['sha256'] or b.sha(source)!=expected['sha256'] or source.stat().st_size!=expected['size']:raise ValueError('local qualification asset is not authenticated')
        shutil.copyfile(source,path)
    elif asset.get('origin')=='https://fedoraproject.org/releases.json':
        import fedora_image
        fedora_image.fetch(asset,path)
    else:b.download(asset['url'],path)
    if b.sha(path)!=asset['sha256']:raise ValueError('qualification image checksum mismatch')
    return path

def init_data(row,key,certificate):
    # Cloud-init is image construction input, never an installer host mutation.
    # Omit unused command modules: cloud-init rejects an empty runcmd array.
    packages=['openssh-server','sudo','curl','ca-certificates','gnupg2' if row['route']=='rpm' else 'gnupg','util-linux','python3','tar','gzip']
    return '#cloud-config\n'+json.dumps({'users':[{'name':'qualifier','sudo':'ALL=(ALL) NOPASSWD:ALL','shell':'/bin/bash','ssh_authorized_keys':[key]}],
       'ssh_pwauth':False,'disable_root':True,'manage_etc_hosts':False,'package_update':True,'packages':packages,
       'write_files':[{'path':'/etc/hosts','permissions':'0644','content':'127.0.0.1 localhost\n::1 localhost\n10.0.2.2 httpjet-qualification.local\n'},
                      {'path':'/run/httpjet-disposable-qualification','permissions':'0600','content':'controlled QEMU qualification image\n'}]},indent=2)+'\n'
@contextlib.contextmanager
def image_session(row,lock,work,key,ports,certificate,artifacts,manifest,previous_manifest=None):
    if row['executor'] in ('nix-image','guix-image'):
        import declarative
        with declarative.run(row,lock,artifacts/'manifest.json',work.release_base,key.with_suffix('.pub'),work.path/'declarative',ports,
                             previous_manifest=previous_manifest,test_ca=certificate) as session:yield session
        return
    root=work.path;seed=None;kernel=None;initrd=None;kernel_args=None
    if row['executor']=='rootfs':
        rowfile=root/'row.json';lockfile=root/'image-lock.json';image_manifest=root/'image-artifacts.json'
        write(rowfile,row);write(lockfile,lock);write(image_manifest,{'artifacts':b.load(artifacts/'qualification-images.json').get('artifacts',{})})
        build=root/'rootfs'
        prefix=[] if os.geteuid()==0 else ['sudo','-n']
        # The isolated builder may leave root-owned staging even if extraction
        # fails. Reclaim only this invocation's tree on both success and error.
        reclaim="""import os,stat,sys
root=sys.argv[1];uid=int(sys.argv[2]);gid=int(sys.argv[3])
for directory,dirs,files in os.walk(root,topdown=True,followlinks=False):
    os.chown(directory,uid,gid,follow_symlinks=False)
    os.chmod(directory,stat.S_IMODE(os.stat(directory,follow_symlinks=False).st_mode)|0o700,follow_symlinks=False)
    for name in dirs+files:os.chown(os.path.join(directory,name),uid,gid,follow_symlinks=False)
"""
        try:
            command(prefix+[sys.executable,ROOT/'packaging/release/rootfs.py','--row',rowfile,'--lock',lockfile,'--public-key',key.with_suffix('.pub'),
                            '--output',build,'--artifact-directory',artifacts,'--artifact-manifest',image_manifest])
        finally:
            if prefix and build.is_dir() and not build.is_symlink():
                command(prefix+[sys.executable,'-c',reclaim,build,os.getuid(),os.getgid()])
        result=b.load(build/'rootfs-evidence.json');base=Path(result['disk']);format=result['format'];kernel=Path(result['kernel']);initrd=Path(result['initrd']);kernel_args=result['kernel_args']
        if row['architecture']=='arm64' and kernel.read_bytes()[:2]==b'\x1f\x8b':
            decoded=root/'Image';decoded.write_bytes(gzip.decompress(kernel.read_bytes()));kernel=decoded
        image={'kind':'rootfs-source','sha256':lock['rootfs']['sha256'],'origin':lock['rootfs'].get('origin',lock['rootfs'].get('url','candidate-artifact'))}
    else:
        base=source_asset(lock['cloud'],root,'base-image');format='qcow2'
        if lock['cloud'].get('format')=='qcow2.xz':
            decoded=root/'base.qcow2';decoded.write_bytes(lzma.decompress(base.read_bytes()));base=decoded
            if lock['cloud'].get('uncompressed_sha256') and b.sha(base)!=lock['cloud']['uncompressed_sha256']:raise ValueError('decompressed cloud image checksum mismatch')
        image={'kind':'cloud-source','sha256':lock['cloud']['sha256'],'origin':lock['cloud'].get('origin',lock['cloud'].get('url','candidate-artifact'))}
        userdata=root/'user-data';userdata.write_text(init_data(row,key.with_suffix('.pub').read_text().strip(),certificate))
        metadata=root/'meta-data';metadata.write_text('instance-id: httpjet-'+row['id']+'\nlocal-hostname: httpjet-qualification\n')
        seed=root/'seed.img';command(['cloud-localds',seed,userdata,metadata])
    overlay=root/'guest.qcow2';command(['qemu-img','create','-f','qcow2','-F',format,'-b',base,overlay])
    if row['executor']!='rootfs':command(['qemu-img','resize',overlay,'+12G'])
    program='qemu-system-aarch64' if row['architecture']=='arm64' else 'qemu-system-x86_64'
    forwards=f"user,id=n,hostfwd=tcp:127.0.0.1:{ports['ssh']}-:22,hostfwd=tcp:127.0.0.1:{ports['http']}-:18080,hostfwd=tcp:127.0.0.1:{ports['tls']}-:18443,hostfwd=udp:127.0.0.1:{ports['quic']}-:18443"
    args=[program,'-accel','tcg,thread=multi','-smp','2','-m','2048','-nographic','-cpu','max',
          '-drive',f'file={overlay},if=virtio,format=qcow2','-netdev',forwards,'-device','virtio-net-pci,netdev=n']
    if seed:args+=['-drive',f'file={seed},if=virtio,format=raw']
    if row['architecture']=='arm64':
        args+=['-machine','virt']
        if not kernel:
            firmware=next((p for p in (Path('/usr/share/AAVMF/AAVMF_CODE.fd'),Path('/usr/share/qemu-efi-aarch64/QEMU_EFI.fd')) if p.is_file()),None)
            if not firmware:raise ValueError('ARM qualification needs EFI firmware')
            args+=['-bios',firmware]
    if kernel:args+=['-kernel',kernel,'-initrd',initrd,'-append',kernel_args]
    with (root/'console.log').open('wb') as console:
        process=subprocess.Popen([str(x) for x in args],stdout=console,stderr=subprocess.STDOUT)
        try:yield {'process':process,'image':image,'console':str(root/'console.log')}
        finally:
            process.terminate()
            try:process.wait(timeout=20)
            except subprocess.TimeoutExpired:process.kill();process.wait()
def inputs(row,manifest,artifacts,work,certificate,key,bootstrap,baseline,ssh_public):
    directory=work.path/'payload';directory.mkdir();release_id=manifest['release_id']
    for name in ('probe.py','protocols.py','guest-v2.py','declarative-guest.py','operator-prepare.py'):
        source=ROOT/'packaging/release'/name
        if not source.is_file():raise ValueError('required qualification controller is missing: '+name)
        shutil.copyfile(source,directory/name)
    qualifier=next(name for name,description in manifest['artifacts'].items() if description['kind']=='qualifier' and description['architecture']==row['architecture'])
    shutil.copyfile(artifacts/qualifier,directory/'io-uring-probe');(directory/'io-uring-probe').chmod(0o755)
    shutil.copyfile(bootstrap,directory/'install.sh');shutil.copyfile(certificate,directory/'test-ca.crt');shutil.copyfile(key,directory/'test-key.pem');(directory/'test-key.pem').chmod(0o600)
    shutil.copyfile(ssh_public,directory/'ssh-public.key')
    archive=artifacts/manifest['binaries'][row['architecture']]['artifact']
    with tarfile.open(archive,'r:*') as opened:
        member=opened.getmember(f'httpjet-{release_id}/share/httpjet/welcome/index.html')
        (directory/'expected-welcome').write_bytes(opened.extractfile(member).read())
    for kind in ('deb','rpm'):
        if baseline.get(kind):
            source=Path(baseline[kind]);target=directory/('baseline.'+kind);shutil.copyfile(source,target)
            baseline[kind]=target.name
    specification={'schema':2,'row':row,'manifest':manifest,'baseline':baseline,'expected_welcome':'expected-welcome',
                   'certificate':'test-ca.crt','bootstrap':'install.sh','image_lock':None}
    if row['route'] in ('nixos','guix'):
        source=directory/'declarative-source';shutil.copytree(ROOT/'packaging/guix',source,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        system={'amd64':'x86_64-linux','arm64':'aarch64-linux'}[row['architecture']]
        binary=manifest['binaries'][row['architecture']];artifact=manifest['artifacts'][binary['artifact']]
        values={'release-id':release_id,'uri':work.release_base+'/'+release_id+'/'+binary['artifact'],
                'sha256':artifact['sha256'],'binary-sha256':binary['binary_sha256'],'system':system}
        (directory/'release-lock.scm').write_text('(use-modules (httpjet packages))\n(httpjet-binary-package\n'+''.join('  #:'+field+' '+json.dumps(value)+'\n' for field,value in values.items())+')\n')
        specification['declarative']={'source':'declarative-source','release_lock':'release-lock.scm','ssh_key':'ssh-public.key','ca':'test-ca.crt','system':system}
        if baseline.get('manifest_path'):
            previous=b.load(Path(baseline['manifest_path']));prior=previous['binaries'][row['architecture']];item=previous['artifacts'][prior['artifact']]
            values={'release-id':previous['release_id'],'uri':work.release_base+'/'+previous['release_id']+'/'+prior['artifact'],
                    'sha256':item['sha256'],'binary-sha256':prior['binary_sha256'],'system':system}
            (directory/'previous-release-lock.scm').write_text('(use-modules (httpjet packages))\n(httpjet-binary-package\n'+''.join('  #:'+field+' '+json.dumps(value)+'\n' for field,value in values.items())+')\n')
            specification['declarative']['previous_lock']='previous-release-lock.scm'
    return directory,specification

def append_evidence(output,row_id,name,source,role):
    target=output/(row_id+'-'+name);shutil.copyfile(source,target)
    return target.name,{'sha256':b.sha(target),'size':target.stat().st_size,'role':role}

def run_guest_phase(key,ports,known,remote,phase,spec,out,transcript):
    ssh(key,ports['ssh'],known,['sudo','-n','python3','-B',remote+'/guest-v2.py',phase,'--spec',remote+'/spec.json','--output',remote+'/'+out.name],output=transcript,cwd=remote)
    receive(key,ports['ssh'],known,remote+'/'+out.name,out)
    return b.load(out)
def reboot_guest(key,ports,known,transcript):
    # BusyBox reboot signals are not the openrc-init shutdown protocol. Select
    # the real PID 1 interface instead of inferring it from service management.
    init=ssh(key,ports['ssh'],known,['cat','/proc/1/comm']).stdout.decode().strip()
    command=['openrc-shutdown','--reboot','now'] if init=='openrc-init' else ['reboot']
    try:
        ssh(key,ports['ssh'],known,['sudo','-n',*command],output=transcript,timeout=15,check=False)
    except subprocess.TimeoutExpired:pass

def runtime_checks(row,completed,runtime):
    support.verify_runtime(runtime)
    for protocol in ('http','tls','h2','h3'):
        if protocol in row['checks']:completed[protocol]='passed'
    if 'large-transfer' in row['checks']:completed['large-transfer']='passed'

def receipt(row,manifest,image_lock,image,service_uid,checks,positive,negative,runtime,baseline,log,evidence,output,container=None):
    value={'schema':2,'row_id':row['id'],'release_id':manifest['release_id'],'architecture':row['architecture'],'route':row['route'],'init':row['init'],
           'status':'passed','manifest_sha256':b.sha(output.parent/'manifest.json') if (output.parent/'manifest.json').exists() else None,
           'payload_sha256':manifest['artifacts'][manifest['binaries'][row['architecture']]['artifact']]['sha256'],
           'binary_sha256':manifest['binaries'][row['architecture']]['binary_sha256'],'service_uid':service_uid,
           'checks':{name:checks[name] for name in row['checks'] if name in checks},'image':{**image,'input_sha256':json_digest(image_lock)},
           'io_uring':{'positive':positive,'negative':negative},'kernel':{'no_multishot_accept':runtime['no_multishot_accept']},
           'baseline_kind':baseline['kind'],'log':log.name,'log_sha256':b.sha(log),'evidence':evidence}
    if container:value.update(container_image_id=container['image_id'],container_image_sha256=manifest['artifacts'][container['artifact']]['sha256'])
    return value

def qualify_oci(args,row,manifest,image_lock,work):
    output=args.output;report=work/'oci.json';metadata=args.artifacts/f"provenance-{row['architecture']}.json"
    image=manifest['oci_images'][row['architecture']]
    engine=args.engine;host=os.environ.get('HTTPJET_QUALIFICATION_DOCKER_HOST',os.environ.get('DOCKER_HOST'))
    loader=[engine]+(['--host',host] if host and engine=='docker' else [])+['load','--input',str(args.artifacts/image['artifact'])]
    command(loader)
    helper=[sys.executable,ROOT/'packaging/release/oci-check.py','--metadata',metadata,'--architecture',row['architecture'],'--engine',engine,'--output',report]
    environment=os.environ.copy()
    if host:environment['DOCKER_HOST']=host
    elevated=os.geteuid()!=0
    if elevated:
        forwarded=['env']+[name+'='+environment[name] for name in ('DOCKER_HOST','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH') if environment.get(name)]
        helper=['sudo','-n',*forwarded,*helper]
    try:command(helper,env=environment)
    finally:
        if elevated:
            cleanup='import os,sys; p=sys.argv[1]; u=int(sys.argv[2]); g=int(sys.argv[3]); '+ \
                    '[(os.chown(os.path.join(d,n),u,g,follow_symlinks=False)) for d,ds,fs in os.walk(p,followlinks=False) for n in ds+fs]; os.chown(p,u,g,follow_symlinks=False)'
            command(['sudo','-n',sys.executable,'-c',cleanup,work,os.getuid(),os.getgid()])
    data=b.load(report)
    if data['status']!='passed' or data['image_id']!=image['image_id']:raise ValueError('OCI image was not qualified')
    runtime=data['runtime'];checks={'artifact-signature':'passed','static-elf':'passed'};runtime_checks(row,checks,runtime)
    observed={'unprivileged':data['sandbox']['uid']>0,'io-uring-positive':data['positive']['status']=='passed',
              'io-uring-negative':data['negative']['status']=='expected_failure','restart':data.get('restart') is True,
              'content-preserved':data.get('volume_preserved') is True,'readonly-rootfs':data['sandbox'].get('readonly_rootfs') is True}
    for name,passed in observed.items():
        if not passed:raise ValueError('OCI observation did not pass: '+name)
        if name in row['checks']:checks[name]='passed'
    positive=data['positive'];negative=data['negative'];evidence={};prefix=row['id']
    # The harness measures the whole sandbox lifetime's global policy value.
    positive.setdefault('global_policy_changed',data['global_policy_changed'])
    for name,value,role in [('uring-positive.json',positive,'uring-positive'),('uring-negative.json',negative,'uring-negative'),('runtime.json',runtime,'runtime')]:
        path=work/name;write(path,value);filename,item=append_evidence(output,prefix,name,path,role);evidence[filename]=item
    denied=work/(report.stem+'.work')/'negative.log';filename,item=append_evidence(output,prefix,'uring-denial.log',denied,'uring-denial-log');evidence[filename]=item
    log=output/(prefix+'.log');log.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
    value=receipt(row,manifest,image_lock,{'kind':'oci-image','sha256':manifest['artifacts'][image['artifact']]['sha256'],'origin':image.get('base',image['image_id'])},
                  data['sandbox']['uid'],checks,positive,negative,runtime,{'kind':'not-applicable-container'},log,evidence,output/(prefix+'.json'),image)
    value['manifest_sha256']=b.sha(args.artifacts/'manifest.json')
    support.verify_row(row,value,manifest,value['manifest_sha256'],image_lock)
    write(output/(prefix+'.json'),value)
def prepare_site(args,manifest,root):
    serve=root/'serve';shutil.copytree(args.snapshot,serve,copy_function=os.link)
    previous_manifest=None;baseline={'kind':'first-release-fixture'}
    if args.previous.is_dir():
        old=b.load(args.previous/'manifest.json');previous_manifest=args.previous/'manifest.json';directory=serve/'releases'/old['release_id'];directory.mkdir(parents=True,exist_ok=True)
        for name in (*old['artifacts'],'manifest.json','manifest.json.asc'):
            if (args.previous/name).exists():universal.copy(args.previous/name,directory/name)
        baseline.update(kind='previous-stable',release_id=old['release_id'],manifest_path=str(previous_manifest),
                        deb=str(args.previous/old['packages'][args.row_object['architecture']]),rpm=str(args.previous/old['rpm_packages'][args.row_object['architecture']]))
        baseline['deb_sha256']=b.sha(Path(baseline['deb']));baseline['rpm_sha256']=b.sha(Path(baseline['rpm']))
    else:
        if not args.first_release_marker.is_file() or not (args.fixtures/'fixture-catalog.json').is_file():raise ValueError('first release requires explicitly labelled lifecycle fixtures')
        catalog=b.load(args.fixtures/'fixture-catalog.json')
        if catalog['source_release_id']!=manifest['release_id']:raise ValueError('first-release fixtures identify another candidate')
        for source in (args.fixtures/'releases').iterdir():shutil.copytree(source,serve/'releases'/source.name)
        native=catalog['native_baselines'][args.row_object['architecture']]
        baseline.update(native,deb=str(args.fixtures/native['deb']),rpm=str(args.fixtures/native['rpm']),forward_release_id=catalog['forward_release_id'])
    return serve,baseline,previous_manifest

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--row',required=True);parser.add_argument('--artifacts',type=Path,required=True);parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--public-key',type=Path,required=True);parser.add_argument('--fingerprint',required=True)
    parser.add_argument('--previous',type=Path,default=Path('previous'));parser.add_argument('--fixtures',type=Path,default=Path('qualification-fixtures'))
    parser.add_argument('--first-release-marker',type=Path,default=Path('first-release-fixture'));parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--timeout',type=int,default=7200);parser.add_argument('--engine',choices=('docker','podman'),default='docker')
    args=parser.parse_args();manifest=b.load(args.artifacts/'manifest.json');support.identity_from_manifest(manifest)
    b.validate_key(args.public_key,args.fingerprint);signature=args.snapshot/'releases'/manifest['release_id']/'manifest.json.asc'
    universal.verify_signed(args.artifacts/'manifest.json',signature,args.public_key);universal.verify_artifacts(args.artifacts,manifest)
    policy=support.bound_policy(args.artifacts,manifest);row=next((entry for entry in policy['rows'] if entry['id']==args.row),None)
    if row is None:raise ValueError('row is not in authenticated support policy')
    args.row_object=row
    if {'x86_64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(os.uname().machine)!=row['architecture']:raise ValueError('qualification must run on native architecture')
    images=b.load(args.artifacts/'qualification-images.json');image_lock=images['rows'][row['id']]
    args.output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='httpjet-matrix-') as temporary:
        from types import SimpleNamespace
        root=Path(temporary);root.chmod(0o711)
        if row['executor']=='oci':return qualify_oci(args,row,manifest,image_lock,root)
        if row['executor']=='coreos':return qualify_coreos(args,row,manifest,image_lock,root)
        serve,baseline,previous_manifest=prepare_site(args,manifest,root)
        key=root/'ssh';command(['ssh-keygen','-q','-t','ed25519','-N','','-f',key])
        cert=root/'test-ca.crt';private=root/'test-key.pem'
        command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=httpjet-qualification',
                 '-addext','subjectAltName=DNS:portable.test,DNS:localhost,DNS:httpjet-qualification.local,IP:127.0.0.1,IP:10.0.2.2','-keyout',private,'-out',cert],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(http.server.SimpleHTTPRequestHandler,directory=serve))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,private);server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            source_base='https://httpjet-qualification.local:'+str(server.server_port)
            work=SimpleNamespace(path=root,release_base=source_base+'/releases')
            bootstrap=root/'install.sh';b.render_installer(ROOT/'packaging/installer/install.sh.in',bootstrap,args.public_key,args.fingerprint,source_base+'/apt')
            ports={'ssh':port(),'http':port(),'tls':port(True)};ports['quic']=ports['tls'];known=root/'known_hosts'
            payload_dir,specification=inputs(row,manifest,args.artifacts,work,cert,private,bootstrap,baseline,key.with_suffix('.pub'))
            specification['image_lock']=image_lock;write(payload_dir/'spec.json',specification)
            with image_session(row,image_lock,work,key,ports,cert,args.artifacts,manifest,previous_manifest) as session:
                execute_session(args,row,manifest,image_lock,session,work,key,ports,known,payload_dir,specification,cert)
        finally:server.shutdown();server.server_close()
def execute_session(args,row,manifest,image_lock,session,work,key,ports,known,payload_dir,specification,certificate):
    output=args.output;prefix=row['id'];remote='/var/tmp/httpjet-qualification-'+prefix;log=output/(prefix+'.log')
    deadline=time.monotonic()+args.timeout;process=session['process'];base_ssh=vm.ssh_args(key,ports['ssh'],known)
    evidence={};checks={'artifact-signature':'passed','static-elf':'passed'}
    with log.open('wb') as transcript:
        try:
            vm.wait_probe([*base_ssh,'true'],deadline=deadline,alive=lambda:process.poll() is None,label='matrix SSH boot')
            if row['executor'] in ('cloud','cloud-lock'):
                ssh(key,ports['ssh'],known,['sudo','-n','cloud-init','status','--wait'],output=transcript,timeout=600)
            send_tree(key,ports['ssh'],known,payload_dir,remote)
            if image_lock.get('operator_configuration'):
                ssh(key,ports['ssh'],known,['sudo','-n','python3','-B',remote+'/operator-prepare.py','--spec',remote+'/spec.json','--probe',remote+'/io-uring-probe','--output',remote+'/operator.json'],output=transcript)
                path=work.path/'operator.json';receive(key,ports['ssh'],known,remote+'/operator.json',path)
                name,item=append_evidence(output,prefix,'operator.json',path,'image-operator-configuration');evidence[name]=item
            if row['route'] in ('nixos','guix'):
                ssh(key,ports['ssh'],known,['sudo','-n','python3','-B',remote+'/declarative-guest.py','--mode','install','--spec',remote+'/spec.json','--output',remote+'/install.json'],output=transcript,cwd=remote)
                receive(key,ports['ssh'],known,remote+'/install.json',work.path/'install.json');install=b.load(work.path/'install.json')
            else:
                install=run_guest_phase(key,ports,known,remote,'install',work.path/'spec.json',work.path/'install.json',transcript)
            service=install['service'];checks.update(install['checks']);uid,gid=service['uid'],service['gid']
            if uid<=0 or service['binary_sha256']!=manifest['binaries'][row['architecture']]['binary_sha256']:raise ValueError('installed service does not run the source payload as its account')
            checks['unprivileged']='passed'
            path=work.path/'service.json';write(path,service);name,item=append_evidence(output,prefix,'service.json',path,'service');evidence[name]=item
            common=['sudo','-n','python3','-B',remote+'/probe.py']
            ssh(key,ports['ssh'],known,[*common,'positive','--probe',remote+'/io-uring-probe','--uid',uid,'--gid',gid,'--output',remote+'/uring-positive.json'],output=transcript)
            positive_file=work.path/'uring-positive.json';receive(key,ports['ssh'],known,remote+'/uring-positive.json',positive_file);positive=b.load(positive_file)
            if positive['status']!='passed':raise ValueError('service account cannot perform mandatory io_uring operations')
            checks['io-uring-positive']='passed'
            runtime_remote=remote+'/runtime'
            ssh(key,ports['ssh'],known,['sudo','-n','python3','-B',remote+'/protocols.py','start','--binary',service['executable'],'--directory',runtime_remote,
                '--uid',uid,'--gid',gid,'--certificate',remote+'/test-ca.crt','--key',remote+'/test-key.pem','--http-port',18080,'--tls-port',18443,'--no-multishot-accept'],output=transcript)
            server=work.path/'server.json';receive(key,ports['ssh'],known,runtime_remote+'/server.json',server)
            runtime_file=work.path/'runtime.json'
            command([sys.executable,ROOT/'packaging/release/protocols.py','check','--server-json',server,'--certificate',certificate,
                     '--host','127.0.0.1','--http-port',ports['http'],'--tls-port',ports['tls'],'--output',runtime_file],stdout=transcript,stderr=subprocess.STDOUT)
            runtime=b.load(runtime_file);runtime_checks(row,checks,runtime)
            ssh(key,ports['ssh'],known,[*common,'negative','--probe',remote+'/io-uring-probe','--uid',uid,'--gid',gid,'--server',runtime_remote+'/httpjet',
                                     '--root',runtime_remote,'--output',remote+'/uring-negative.json','--no-multishot-accept'],output=transcript)
            negative_file=work.path/'uring-negative.json';receive(key,ports['ssh'],known,remote+'/uring-negative.json',negative_file);negative=b.load(negative_file)
            if negative['status']!='expected_failure':raise ValueError('process-scoped policy denial did not fail as required')
            checks['io-uring-negative']='passed'
            denied=work.path/'uring-negative.log';receive(key,ports['ssh'],known,remote+'/'+b.filename(negative['log']),denied)
            ssh(key,ports['ssh'],known,['sudo','-n','python3','-B',remote+'/protocols.py','stop','--directory',runtime_remote],output=transcript)
            if row['route'] in ('nixos','guix'):
                ssh(key,ports['ssh'],known,['sudo','-n','python3','-B',remote+'/declarative-guest.py','--spec',remote+'/spec.json','--output',remote+'/exercise.json'],output=transcript,cwd=remote)
                exercise_file=work.path/'exercise.json';receive(key,ports['ssh'],known,remote+'/exercise.json',exercise_file);exercise=b.load(exercise_file)
            else:exercise=run_guest_phase(key,ports,known,remote,'exercise',work.path/'spec.json',work.path/'exercise.json',transcript)
            checks.update(exercise['checks'])
            old_boot=ssh(key,ports['ssh'],known,['cat','/proc/sys/kernel/random/boot_id']).stdout.decode().strip()
            reboot_guest(key,ports,known,transcript)
            reboot_deadline=min(deadline,time.monotonic()+600)
            def changed(result):return result.returncode==0 and bool(re.fullmatch('[0-9a-f-]{36}',result.stdout.strip())) and result.stdout.strip()!=old_boot
            vm.wait_probe([*base_ssh,'cat /proc/sys/kernel/random/boot_id'],deadline=reboot_deadline,alive=lambda:process.poll() is None,success=changed,label='matrix reboot')
            if row['route'] in ('nixos','guix'):
                ssh(key,ports['ssh'],known,['sudo','-n','python3','-B',remote+'/declarative-guest.py','--mode','inspect','--spec',remote+'/spec.json','--output',remote+'/after-reboot.json'],output=transcript,cwd=remote)
                receive(key,ports['ssh'],known,remote+'/after-reboot.json',work.path/'after-reboot.json');final=b.load(work.path/'after-reboot.json')
            else:final=run_guest_phase(key,ports,known,remote,'inspect',work.path/'spec.json',work.path/'after-reboot.json',transcript)
            checks.update(final['checks'])
            if final['service']['uid']!=uid or final['service']['binary_sha256']!=service['binary_sha256']:raise ValueError('reboot changed installed service identity')
            checks['reboot']='passed';image=dict(session['image'])
            if image_lock.get('operator_configuration'):image['operator_configuration']=b.load(work.path/'operator.json')
            for name,source,role in [('uring-positive.json',positive_file,'uring-positive'),('uring-negative.json',negative_file,'uring-negative'),
                                     ('uring-denial.log',denied,'uring-denial-log'),('runtime.json',runtime_file,'runtime')]:
                filename,item=append_evidence(output,prefix,name,source,role);evidence[filename]=item
            for name,source,role in [('install.json',work.path/'install.json','lifecycle-install'),('exercise.json',work.path/'exercise.json','lifecycle-exercise'),
                                     ('after-reboot.json',work.path/'after-reboot.json','service-reboot')]:
                filename,item=append_evidence(output,prefix,name,source,role);evidence[filename]=item
            transcript.flush()
            document=receipt(row,manifest,image_lock,image,uid,checks,positive,negative,runtime,specification['baseline'],log,evidence,output/(prefix+'.json'))
            document['manifest_sha256']=b.sha(args.artifacts/'manifest.json')
            support.verify_row(row,document,manifest,document['manifest_sha256'],image_lock)
            write(output/(prefix+'.json'),document)
        finally:
            transcript.flush()
            console=Path(session.get('console',session.get('log',work.path/'console.log')))
            if console.exists():shutil.copyfile(console,output/(prefix+'-console.log'))

def qualify_coreos(args,row,manifest,image_lock,work):
    import importlib.util
    definition=importlib.util.spec_from_file_location('httpjet_coreos_qualification',ROOT/'packaging/release/coreos-check.py')
    module=importlib.util.module_from_spec(definition);definition.loader.exec_module(module)
    observation=module.qualify(row,image_lock,manifest,args.artifacts,work/'coreos',args.timeout)
    runtime=observation['runtime'];service=observation['service'];checks=dict(observation['checks'])
    checks.update({'artifact-signature':'passed','static-elf':'passed'});runtime_checks(row,checks,runtime)
    if service['uid']<=0 or service['binary_sha256']!=manifest['binaries'][row['architecture']]['binary_sha256']:
        raise ValueError('immutable container did not run the source payload unprivileged')
    checks['unprivileged']='passed';positive=observation['positive'];negative=observation['negative'];evidence={}
    for name,value,role in [('uring-positive.json',positive,'uring-positive'),('uring-negative.json',negative,'uring-negative'),('runtime.json',runtime,'runtime'),('service.json',service,'service')]:
        path=work/name;write(path,value);filename,item=append_evidence(args.output,row['id'],name,path,role);evidence[filename]=item
    files=observation.get('files',{})
    if 'uring-denial-log' not in files:raise ValueError('CoreOS omitted real denial diagnostics')
    for role,source in files.items():
        filename,item=append_evidence(args.output,row['id'],Path(source).name,Path(source),role);evidence[filename]=item
    log=args.output/(row['id']+'.log');shutil.copyfile(observation['log'],log)
    image=manifest['oci_images'][row['architecture']]
    result=receipt(row,manifest,image_lock,observation['image'],service['uid'],checks,positive,negative,runtime,
                   {'kind':'not-applicable-container'},log,evidence,args.output/(row['id']+'.json'),image)
    result['manifest_sha256']=b.sha(args.artifacts/'manifest.json')
    support.verify_row(row,result,manifest,result['manifest_sha256'],image_lock)
    write(args.output/(row['id']+'.json'),result)

if __name__=='__main__':main()
