#!/usr/bin/env python3
"""Schema-2 release manifests and cross-distribution publication."""
from datetime import datetime,timedelta,timezone
import os
from pathlib import Path
import re
import shutil
import tempfile
import support
import payload
BASE='https://packages.httpjet.net/releases'
def api():
    import release
    return release
def sign(path,key):
    api().run(['gpg','--batch','--yes','--pinentry-mode','loopback','--local-user',key,'--armor','--detach-sign','--digest-algo','SHA256','--output',str(path)+'.asc',path])
def verify_signed(path,signature,key):
    with tempfile.TemporaryDirectory(prefix='httpjet-signature-') as temporary:
        ring=Path(temporary)/'archive.gpg'
        api().run(['gpg','--batch','--yes','--dearmor','--output',ring,key])
        api().run(['gpgv','--keyring',ring,signature,path])
def expected_kind(name):
    if name.endswith('.deb'):return 'keyring-deb' if name.startswith('httpjet-archive-keyring_') else 'deb'
    if name.endswith('.rpm'):return 'keyring-rpm' if name.startswith('httpjet-archive-keyring-') else 'rpm'
    if name.endswith('-static.tar.gz'):return 'portable'
    if '-source.tar.' in name:return 'source'
    if name.startswith('provenance-'):return 'provenance'
    if name.endswith('.buildinfo'):return 'buildinfo'
    if name=='support-matrix.json':return 'qualification-policy'
    return 'license'
def image_reference(value):
    if value.startswith('docker.io/'):return value
    if value.startswith('library/'):return 'docker.io/'+value
    if '/' not in value.split('@',1)[0]:return 'docker.io/library/'+value
    return value

def carrier_arch(name):
    if '_all.deb' in name or '.noarch.rpm' in name:return 'all'
    if '_amd64.deb' in name or '.x86_64.rpm' in name:return 'amd64'
    if '_arm64.deb' in name or '.aarch64.rpm' in name:return 'arm64'
    return None

def rpm_signature_verified(report):
    # RPM 6 prints "signature" in lowercase; RPM 4 prints "Signature".
    return (not re.search(r'\b(?:NOKEY|NOT\s+OK)\b',report,re.IGNORECASE)
            and bool(re.search(r'\bsignature[^\n]*:\s*OK\s*$',report,re.IGNORECASE|re.MULTILINE)))

def verify_rpm_signatures(directory,manifest):
    """Verify final carrier signatures using only the release-scoped archive key."""
    b=api();ident=support.identity_from_manifest(manifest)
    name=f"httpjet-archive-keyring_{ident['release_id']}_all.deb"
    if name not in manifest['artifacts']:raise ValueError('archive keyring carrier is missing')
    with tempfile.TemporaryDirectory(prefix='httpjet-release-rpm-trust-') as temporary:
        root=Path(temporary);tree=root/'keyring';database=root/'rpmdb';database.mkdir()
        b.run(['dpkg-deb','--extract',directory/name,tree])
        key=tree/'usr/share/keyrings/httpjet-archive-keyring.asc'
        if key.is_symlink() or not key.is_file():raise ValueError('archive keyring payload is missing')
        b.validate_key(key,manifest['archive_fingerprint'])
        b.run(['rpm','--dbpath',database,'--initdb'])
        b.run(['rpmkeys','--dbpath',database,'--import',key])
        carriers=[name for name,item in manifest['artifacts'].items() if item['kind'] in ('rpm','keyring-rpm')]
        if len(carriers)!=3:raise ValueError('expected both RPM architectures and one shared keyring')
        for name in carriers:
            report=b.run(['rpmkeys','--dbpath',database,'--checksig','--verbose',directory/name])
            if not rpm_signature_verified(report):
                raise ValueError('RPM carrier signature did not verify: '+name)

def create_manifest(directory,output):
    b=api();builds=[b.load(directory/f'provenance-{arch}.json') for arch in support.ARCHES]
    first=builds[0];ident=support.identity(first['release_id'])
    signatures=b.load(directory/'carrier-signatures.json') if (directory/'carrier-signatures.json').exists() else {}
    artifacts={};binaries={};packages={};rpms={};oci_images={}
    for arch,build in zip(support.ARCHES,builds):
        for field in ('release_id','commit','source_date_epoch','archive_fingerprint'):
            if build[field]!=first[field]:raise ValueError('builders disagree on '+field)
        if build['architecture']!=arch or build.get('rustc_version')!='1.99.1':raise ValueError('architecture/toolchain mismatch')
        if '--no-multishot-accept' not in build.get('compatibility_flags',[]):raise ValueError('fresh compatibility launch profile was not attested')
        if build.get('tag')!=ident['tag']:raise ValueError('tag does not identify package revision')
        target={'amd64':'x86_64-unknown-linux-musl','arm64':'aarch64-unknown-linux-musl'}[arch]
        if build.get('target',build.get('build_target'))!=target:raise ValueError('payload must be attested musl build')
        for name,declared in build['artifacts'].items():
            b.filename(name);path=directory/name;current=b.sha(path)
            description=dict(declared);description.setdefault('kind',expected_kind(name))
            description.setdefault('architecture',carrier_arch(name) or (arch if description['kind']=='portable' else 'source'))
            description.setdefault('libc','musl' if description['kind'] in ('portable','deb','rpm','qualifier') else 'none')
            if current!=declared['sha256']:
                signed=signatures.get(name,{})
                if (description['kind'] not in ('rpm','keyring-rpm') or signed.get('unsigned_sha256')!=declared['sha256']
                    or signed.get('sha256')!=current or signed.get('fingerprint')!=first['archive_fingerprint']):
                    raise ValueError('artifact differs from native provenance: '+name)
                description['unsigned_sha256']=declared['sha256'];description['sha256']=current;description['size']=path.stat().st_size
            elif path.stat().st_size!=declared['size']:raise ValueError('artifact size mismatch')
            if name in artifacts and artifacts[name]!=description:raise ValueError('common artifact mismatch: '+name)
            artifacts[name]=description
        tar_name=f"httpjet-{ident['release_id']}-linux-{arch}-static.tar.gz"
        if tar_name not in artifacts:raise ValueError('missing universal payload')
        binary=payload.tar_binary(directory/tar_name,ident['release_id']);binary_hash=payload.sha_bytes(binary)
        declared_binary=build.get('binary_sha256',build.get('binaries',{}).get(arch,{}).get('binary_sha256'))
        if declared_binary!=binary_hash:raise ValueError('payload ELF differs from native attestation')
        with tempfile.TemporaryDirectory(prefix='httpjet-static-elf-') as temporary:
            executable=Path(temporary)/'httpjet';executable.write_bytes(binary);b.validate_elf(executable,arch,'musl')
        binaries[arch]={'artifact':tar_name,'binary_sha256':binary_hash,'libc':'musl'}
        package=f"httpjet_{ident['release_id']}_{arch}.deb"
        if package not in artifacts:raise ValueError('missing Debian carrier')
        control=b.run(['dpkg-deb','-f',directory/package,'Package','Version','Architecture'])
        if control!=f"Package: httpjet\nVersion: {ident['release_id']}\nArchitecture: {arch}\n":raise ValueError('Debian identity mismatch')
        payload.verify_carrier_binary(directory/package,'deb',binary_hash);packages[arch]=package
        rpm_arch={'amd64':'x86_64','arm64':'aarch64'}[arch];rpm=f"httpjet-{ident['release_id']}.{rpm_arch}.rpm"
        if rpm not in artifacts or rpm not in signatures:raise ValueError('missing signed RPM carrier')
        control=b.run(['rpm','-qp','--qf','%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n',directory/rpm])
        if control!=f"httpjet\n{ident['upstream_version']}\n{ident['revision']}\n{rpm_arch}\n":raise ValueError('RPM identity mismatch')
        payload.verify_carrier_binary(directory/rpm,'rpm',binary_hash);rpms[arch]=rpm
        oci=build.get('oci_images',{}).get(arch)
        if oci:
            image=payload.oci_binary(directory/oci['artifact'],arch)
            if image['image_id']!=oci['image_id'] or payload.sha_bytes(image['binary'])!=binary_hash:raise ValueError('OCI image differs from source payload')
            oci_images[arch]=oci
        name=f'provenance-{arch}.json';artifacts[name]={'kind':'provenance','architecture':arch,'libc':'musl','sha256':b.sha(directory/name),'size':(directory/name).stat().st_size}
    if set(oci_images)!=set(support.ARCHES):raise ValueError('both architectures require source-bound OCI images')
    if not re.fullmatch('[0-9a-f]{40}',first['commit']):raise ValueError('invalid source commit')
    for name in (f"httpjet-archive-keyring_{ident['release_id']}_all.deb",f"httpjet-archive-keyring-{ident['release_id']}.noarch.rpm"):
        if name not in artifacts:raise ValueError('missing keyring carrier')
    shutil.copyfile(support.POLICY,directory/'support-matrix.json')
    descriptor=support.policy_descriptor(directory/'support-matrix.json')
    artifacts['support-matrix.json']={**{k:descriptor[k] for k in ('sha256','size')},'kind':'qualification-policy','architecture':'all','libc':'none'}
    if (directory/'qualification-images.json').exists():
        images=b.load(directory/'qualification-images.json')
        if images.get('matrix_sha256')!=descriptor['sha256'] or set(images.get('rows',{}))!={row['id'] for row in support.load_policy()['rows']}:
            raise ValueError('image locks do not cover the exact support matrix')
        for arch,image_descriptor in oci_images.items():
            if image_reference(image_descriptor.get('base_image',image_descriptor.get('base','')))!=image_reference(images['oci_bases'][arch]['image']):
                raise ValueError('OCI builder did not use the authenticated native base image')
        for name,item in images.get('artifacts',{}).items():
            path=directory/b.filename(name)
            if b.sha(path)!=item['sha256'] or path.stat().st_size!=item['size']:raise ValueError('prepared rootfs artifact mismatch')
            # Auxiliary OS images stay in the CI candidate artifact. Their hashes
            # are bound by this signed lock, not published as software downloads.
        name='qualification-images.json';artifacts[name]={'kind':'qualification-inputs','architecture':'all','libc':'none','sha256':b.sha(directory/name),'size':(directory/name).stat().st_size}
    if signatures:
        name='carrier-signatures.json';artifacts[name]={'kind':'provenance','architecture':'all','libc':'none','sha256':b.sha(directory/name),'size':(directory/name).stat().st_size}
    manifest={'schema':2,**ident,'commit':first['commit'],'source_date_epoch':first['source_date_epoch'],
              'archive_fingerprint':first['archive_fingerprint'],'runtime':support.load_policy()['runtime'],'support_matrix':descriptor,'binaries':binaries,
              'packages':packages,'rpm_packages':rpms,'oci_images':oci_images,'artifacts':artifacts}
    verify_rpm_signatures(directory,manifest)
    b.write_json(output,manifest)
    (directory/'SHA256SUMS').write_text(''.join(f"{data['sha256']}  {name}\n" for name,data in sorted(artifacts.items()))+f"{b.sha(output)}  {output.name}\n")

def verify_artifacts(directory,manifest):
    b=api();support.identity_from_manifest(manifest)
    if manifest.get('test_fixture'):raise ValueError('qualification fixtures cannot be published')
    if manifest.get('schema')!=2 or set(manifest['binaries'])!=set(support.ARCHES):raise ValueError('invalid universal manifest')
    allowed={'portable','deb','keyring-deb','rpm','keyring-rpm','source','license','buildinfo','qualifier','provenance','qualification-policy','qualification-inputs','qualification-image','oci-image'}
    for name,description in manifest['artifacts'].items():
        path=directory/b.filename(name)
        if type(description.get('size')) is not int or description['size']<0 or not re.fullmatch('[0-9a-f]{64}',description.get('sha256','')):raise ValueError('invalid artifact hash/size')
        if (path.is_symlink() or not path.is_file() or b.sha(path)!=description['sha256'] or path.stat().st_size!=description['size']
            or description['kind'] not in allowed or description['architecture'] not in (*support.ARCHES,'all','source') or description['libc'] not in ('musl','none')):
            raise ValueError('artifact descriptor/bytes mismatch: '+name)
    verify_rpm_signatures(directory,manifest)
    policy=support.bound_policy(directory,manifest)
    if manifest.get('runtime')!=policy['runtime']:raise ValueError('manifest runtime contract differs from support policy')
    if 'qualification-images.json' not in manifest['artifacts']:raise ValueError('release omits authenticated image locks')
    images=b.load(directory/'qualification-images.json')
    if images.get('release_id')!=manifest['release_id'] or images.get('matrix_sha256')!=manifest['support_matrix']['sha256'] or set(images.get('rows',{}))!={row['id'] for row in policy['rows']}:
        raise ValueError('image locks do not bind this release and matrix')
    if set(manifest.get('oci_images',{}))!=set(support.ARCHES):raise ValueError('manifest omits required OCI architectures')
    for arch,descriptor in manifest['binaries'].items():
        artifact=manifest['artifacts'][descriptor['artifact']]
        if artifact['kind']!='portable' or artifact['architecture']!=arch or artifact['libc']!='musl' or descriptor['libc']!='musl':raise ValueError('invalid binary descriptor')
        if payload.sha_bytes(payload.tar_binary(directory/descriptor['artifact'],manifest['release_id']))!=descriptor['binary_sha256']:
            raise ValueError('universal payload binary hash mismatch')
    for arch,descriptor in manifest['oci_images'].items():
        image=payload.oci_binary(directory/descriptor['artifact'],arch)
        if image['image_id']!=descriptor['image_id'] or payload.sha_bytes(image['binary'])!=manifest['binaries'][arch]['binary_sha256']:
            raise ValueError('OCI image identity differs from authenticated payload')
        base=descriptor.get('base_layer_diffids',[])
        if not base or image['config']['rootfs']['diff_ids'][:len(base)]!=base or descriptor.get('base_architecture')!=arch or image_reference(descriptor.get('base_image',descriptor.get('base','')))!=image_reference(images['oci_bases'][arch]['image']):
            raise ValueError('OCI image base/source architecture was not qualified')
def sign_carriers(directory,key,expected):
    b=api();b.validate_key(key,expected);original={}
    for arch in support.ARCHES:
        build=b.load(directory/f'provenance-{arch}.json')
        for name,description in build['artifacts'].items():
            path=directory/b.filename(name)
            if b.sha(path)!=description['sha256'] or path.stat().st_size!=description['size']:raise ValueError('unsigned native artifact mismatch')
            if name.endswith('.rpm'):
                if name in original and original[name]!=description['sha256']:raise ValueError('unsigned RPM builders disagree')
                original[name]=description['sha256']
    signatures={}
    with tempfile.TemporaryDirectory(prefix='httpjet-rpm-keys-') as temporary:
        database=Path(temporary)/'rpmdb';database.mkdir()
        b.run(['rpm','--dbpath',database,'--initdb'])
        b.run(['rpmkeys','--dbpath',database,'--import',key])
        for name,initial in sorted(original.items()):
            path=directory/name
            before=b.run(['rpm','-qp','--qf','%{PAYLOADDIGEST}',path]).strip()
            b.run(['rpmsign','--define','__gpg /usr/bin/gpg','--define','_gpg_name '+expected,'--define','_gpg_path '+os.environ['GNUPGHOME'],'--addsign',path])
            verification=b.run(['rpmkeys','--dbpath',database,'--checksig','--verbose',path])
            if not rpm_signature_verified(verification):raise ValueError('RPM signature did not verify')
            if b.run(['rpm','-qp','--qf','%{PAYLOADDIGEST}',path]).strip()!=before:raise ValueError('signing changed RPM payload')
            signatures[name]={'unsigned_sha256':initial,'sha256':b.sha(path),'fingerprint':expected,'payload_digest':before}
    b.write_json(directory/'carrier-signatures.json',signatures)

def qualify(directory,receipts,output):
    b=api();manifest=b.load(directory/'manifest.json');verify_artifacts(directory,manifest)
    policy=support.bound_policy(directory,manifest);images=b.load(directory/'qualification-images.json')['rows'];evidence=[]
    for row in policy['rows']:
        receipt=receipts/(row['id']+'.json');document=b.load(receipt)
        support.verify_row(row,document,manifest,b.sha(directory/'manifest.json'),images[row['id']])
        log=receipts/b.filename(document['log'])
        if b.sha(log)!=document['log_sha256']:raise ValueError('qualification log mismatch')
        attachments=document.get('evidence',{})
        if not {'uring-positive','uring-negative','uring-denial-log','runtime'}.issubset({item.get('role') for item in attachments.values()}):
            raise ValueError('receipt omits inspectable runtime/probe evidence')
        for name,item in attachments.items():
            source=receipts/b.filename(name)
            if b.sha(source)!=item['sha256'] or source.stat().st_size!=item['size']:raise ValueError('receipt attachment mismatch')
            shutil.copyfile(source,directory/name)
        for path in (receipt,log):shutil.copyfile(path,directory/path.name)
        evidence.append({'row_id':row['id'],'receipt':receipt.name,'sha256':b.sha(receipt),'log':log.name,'log_sha256':b.sha(log),'evidence':attachments})
    qualification={'schema':2,'release_id':manifest['release_id'],'manifest_sha256':b.sha(directory/'manifest.json'),
                   'support_matrix_sha256':manifest['support_matrix']['sha256'],'status':'passed','targets':evidence}
    verify_qualification(directory,qualification)
    b.write_json(output,qualification)

def verify_qualification(directory,document=None):
    b=api();manifest=b.load(directory/'manifest.json');qualification=document if document is not None else b.load(directory/'qualification.json')
    policy=support.bound_policy(directory,manifest);expected={row['id']:row for row in policy['rows']};images=b.load(directory/'qualification-images.json')['rows'];seen=set()
    if (qualification.get('schema')!=2 or qualification.get('status')!='passed' or qualification.get('release_id')!=manifest['release_id']
        or qualification.get('manifest_sha256')!=b.sha(directory/'manifest.json') or qualification.get('support_matrix_sha256')!=manifest['support_matrix']['sha256']):
        raise ValueError('qualification does not bind this release and support policy')
    for target in qualification['targets']:
        if target['row_id'] not in expected or target['row_id'] in seen:raise ValueError('unknown/duplicate matrix proof')
        receipt=directory/b.filename(target['receipt']);log=directory/b.filename(target['log'])
        if b.sha(receipt)!=target['sha256'] or b.sha(log)!=target['log_sha256']:raise ValueError('qualification evidence hash mismatch')
        document=b.load(receipt);support.verify_row(expected[target['row_id']],document,manifest,b.sha(directory/'manifest.json'),images[target['row_id']])
        attachments=document.get('evidence',{})
        if attachments!=target.get('evidence'):raise ValueError('qualification attachment catalog mismatch')
        roles={}
        for name,item in attachments.items():
            path=directory/b.filename(name)
            if b.sha(path)!=item['sha256'] or path.stat().st_size!=item['size']:raise ValueError('qualification attachment bytes changed')
            roles[item.get('role')]=path
        if not {'uring-positive','uring-negative','uring-denial-log','runtime'}.issubset(roles):raise ValueError('missing runtime evidence')
        if b.load(roles['uring-positive'])!=document['io_uring']['positive'] or b.load(roles['uring-negative'])!=document['io_uring']['negative']:
            raise ValueError('probe receipt differs from attached evidence')
        runtime=b.load(roles['runtime'])
        support.verify_runtime(runtime,document['service_uid'],document['binary_sha256'])
        if expected[target['row_id']]['route'] not in ('oci','immutable'):
            if 'service' not in roles:raise ValueError('receipt omits installed init-service evidence')
            service=b.load(roles['service'])
            if service.get('scope')!='installed-init-service' or service.get('uid')!=document['service_uid'] or service.get('binary_sha256')!=document['binary_sha256'] or service.get('init')!=document['init'] or service.get('no_multishot_accept') is not True:
                raise ValueError('service namespace/identity was not observed under its init')
        if document['log_sha256']!=target['log_sha256']:raise ValueError('receipt log identity mismatch')
        seen.add(target['row_id'])
    if seen!=set(expected):raise ValueError('every required versioned matrix row must pass before publication')
def copy(source,destination):
    b=api();destination.parent.mkdir(parents=True,exist_ok=True)
    if destination.exists():
        if b.sha(source)!=b.sha(destination):raise ValueError('immutable object collision: '+str(destination))
        return
    try:os.link(source,destination)
    except OSError:shutil.copyfile(source,destination)

def apt_repository(directory,output,manifest,previous,key,expected,qualified,now):
    b=api();root=output/'apt';pool=root/'pool/main/h/httpjet';pool.mkdir(parents=True)
    if previous:
        for path in (previous/'history').rglob('*.deb'):copy(path,pool/path.name)
    for name in manifest['artifacts']:
        if name.endswith('.deb'):copy(directory/name,pool/name)
    packages=b.run(['apt-ftparchive','packages','pool'],cwd=root)
    import gzip
    for arch in support.ARCHES:
        stanzas=[s for s in packages.strip().split('\n\n') if re.search(r'^Architecture: (?:'+arch+r'|all)$',s,re.M)]
        if len(stanzas)<2:raise ValueError('APT needs daemon and keyring for both architectures')
        index=root/f'dists/stable/main/binary-{arch}/Packages';index.parent.mkdir(parents=True)
        index.write_text('\n\n'.join(stanzas)+'\n\n');index.with_suffix('.gz').write_bytes(gzip.compress(index.read_bytes(),mtime=0))
        for path in (index,index.with_suffix('.gz')):copy(path,index.parent/'by-hash/SHA256'/b.sha(path))
    metadata=b.run(['apt-ftparchive','release','dists/stable'],cwd=root)
    metadata='\n'.join(line for line in metadata.splitlines() if not line.startswith('Date:'))+'\n'
    fields={'Origin':'httpjet','Label':'httpjet','Suite':'stable','Codename':'stable','Architectures':'amd64 arm64',
            'Components':'main','Acquire-By-Hash':'yes','Date':b.format_datetime(now,usegmt=True),
            'Valid-Until':b.format_datetime(now+timedelta(days=30),usegmt=True),'X-Httpjet-Version':manifest['upstream_version'],
            'X-Httpjet-Release-ID':manifest['release_id'],'X-Httpjet-Manifest-SHA256':b.sha(directory/'manifest.json'),
            'X-Httpjet-Qualification-SHA256':b.sha(directory/'qualification.json') if qualified else 'unqualified',
            'X-Httpjet-Archive-Fingerprint':expected,'X-Httpjet-Installer-SHA256':b.sha(output/'apt/install.sh')}
    release=root/'dists/stable/Release';release.write_text(''.join(f'{k}: {v}\n' for k,v in fields.items())+metadata)
    b.run(['gpg','--batch','--yes','--pinentry-mode','loopback','--local-user',expected,'--digest-algo','SHA256','--clearsign','--output',release.with_name('InRelease'),release])
    sign(release,expected);shutil.copyfile(str(release)+'.asc',release.with_name('Release.gpg'))

def rpm_repository(directory,output,manifest,previous,key,expected):
    b=api()
    for arch,rpm_arch in (('amd64','x86_64'),('arm64','aarch64')):
        root=output/'rpm'/rpm_arch;pool=root/'Packages';pool.mkdir(parents=True)
        if previous:
            for path in (previous/'history').rglob('*.rpm'):
                if path.name.endswith(('.'+rpm_arch+'.rpm','.noarch.rpm')):copy(path,pool/path.name)
        for name in manifest['artifacts']:
            if name.endswith(('.'+rpm_arch+'.rpm','.noarch.rpm')):copy(directory/name,pool/name)
        b.run(['createrepo_c','--checksum','sha256','--compress-type','gz','--unique-md-filenames','--revision',str(manifest['source_date_epoch']),'--set-timestamp-to-revision',root])
        sign(root/'repodata/repomd.xml',expected)
        copy(key,root/'archive-key.asc')

def stage(directory,output,key,expected,template,repository=None,candidate=False,now=None,previous=None,installer_helper=None):
    b=api();b.validate_key(key,expected)
    if output.exists():raise ValueError('snapshot output must not exist')
    manifest=b.load(directory/'manifest.json');verify_artifacts(directory,manifest)
    if manifest['archive_fingerprint']!=expected:raise ValueError('release uses another signing key')
    if not candidate:verify_qualification(directory)
    output.mkdir(parents=True);release=output/'releases'/manifest['release_id'];release.mkdir(parents=True)
    for name in manifest['artifacts']:copy(directory/name,release/name)
    for name in ('manifest.json','SHA256SUMS'):copy(directory/name,release/name)
    if not candidate:
        copy(directory/'qualification.json',release/'qualification.json')
        for target in b.load(directory/'qualification.json')['targets']:
            for field in ('receipt','log'):copy(directory/b.filename(target[field]),release/target[field])
            for name in target.get('evidence',{}):copy(directory/b.filename(name),release/name)
    (output/'apt').mkdir()
    same=previous and b.load(previous/'manifest.json').get('release_id')==manifest['release_id']
    if same and (b.sha(previous/'manifest.json')!=b.sha(directory/'manifest.json') or (not candidate and b.sha(previous/'qualification.json')!=b.sha(directory/'qualification.json'))):
        raise ValueError('published release is immutable; increment package revision')
    if same:
        for name in ('manifest.json.asc','qualification.json.asc'):
            if (previous/name).exists():copy(previous/name,release/name)
        copy(previous/'approved-install.sh',output/'apt/install.sh')
    else:
        b.render_installer(template,output/'apt/install.sh',key,expected,repository or b.REPO_URL,installer_helper=installer_helper)
    for name in ('manifest.json',)+(() if candidate else ('qualification.json',)):
        if not (release/(name+'.asc')).exists():sign(release/name,expected)
    copy(output/'apt/install.sh',release/'install.sh');copy(key,output/'apt/httpjet-archive-keyring.asc')
    now=now or datetime.now(timezone.utc)
    apt_repository(directory,output,manifest,previous,key,expected,not candidate,now)
    rpm_repository(directory,output,manifest,previous,key,expected)
    pointer={'schema':2,'release_id':manifest['release_id'],'manifest_sha256':b.sha(release/'manifest.json'),
             'manifest_size':(release/'manifest.json').stat().st_size,'issued_at':now.strftime('%Y-%m-%dT%H:%M:%SZ'),
             'expires_at':(now+timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ'),'archive_fingerprint':expected,
             'qualification_sha256':b.sha(release/'qualification.json') if not candidate else 'unqualified'}
    b.write_json(output/'releases/stable.json',pointer);sign(output/'releases/stable.json',expected)
    b.write_json(output/'publication.json',{'schema':2,'qualified':not candidate,'release_id':manifest['release_id'],
                 'archive_fingerprint':expected,'manifest_sha256':b.sha(release/'manifest.json'),
                 'qualification_sha256':pointer['qualification_sha256'],'stable_sha256':b.sha(output/'releases/stable.json'),
                 'previous_stable_sha256':b.sha(previous/'current-stable.json') if previous and (previous/'current-stable.json').exists() else None})
    return output
def release_tuple(value):
    value=support.identity(value)
    return (*map(int,value['upstream_version'].split('.')),value['revision'])

def signed_apt_history(repository,directory,key,manifest):
    b=api();signed=directory/'history.InRelease';b.download(repository+'/dists/stable/InRelease',signed)
    from publish import verified_release
    document=verified_release(signed,key);fields=dict(line.split(': ',1) for line in document.splitlines() if ': ' in line and not line.startswith(' '))
    issued=b.parsedate_to_datetime(fields['Date']);expires=b.parsedate_to_datetime(fields['Valid-Until']);now=datetime.now(timezone.utc)
    if issued>now+timedelta(hours=1) or expires<=now or expires<=issued or expires-issued>timedelta(days=30,minutes=1):raise ValueError('expired APT history metadata')
    if fields.get('X-Httpjet-Release-ID')!=manifest['release_id'] or fields.get('X-Httpjet-Manifest-SHA256')!=b.sha(directory/'manifest.json') or fields.get('X-Httpjet-Installer-SHA256')!=b.sha(directory/'approved-install.sh'):
        raise ValueError('APT metadata does not match current signed universal release')
    digests={};section=None
    for line in document.splitlines():
        if not line.startswith(' '):section=line.rstrip(':')
        elif section=='SHA256':
            digest,size,name=line.split();digests[name]=(digest,int(size))
    for arch in support.ARCHES:
        relative=f'main/binary-{arch}/Packages';index=directory/f'previous-Packages-{arch}'
        b.download(repository+'/dists/stable/'+relative,index)
        if (b.sha(index),index.stat().st_size)!=digests[relative]:raise ValueError('APT history index mismatch')
        for stanza in index.read_text().strip().split('\n\n'):
            row=dict(line.split(': ',1) for line in stanza.splitlines() if ': ' in line and not line.startswith(' '))
            if row['Package'] not in ('httpjet','httpjet-archive-keyring') or row['Architecture'] not in (arch,'all'):raise ValueError('unexpected APT history package')
            if release_tuple(row['Version'])>release_tuple(manifest['release_id']):continue
            name=b.filename(row['Filename'].removeprefix('pool/main/h/httpjet/'))
            if row['Filename']!='pool/main/h/httpjet/'+name:raise ValueError('unsafe historical package path')
            path=directory/'history/deb'/name;path.parent.mkdir(parents=True,exist_ok=True)
            if not path.exists():b.download(repository+'/'+row['Filename'],path)
            if b.sha(path)!=row['SHA256'] or path.stat().st_size!=int(row['Size']):raise ValueError('historical Debian carrier mismatch')

def signed_rpm_history(base,directory,key,manifest):
    import gzip
    import xml.etree.ElementTree as ET
    b=api();ns={'r':'http://linux.duke.edu/metadata/repo','p':'http://linux.duke.edu/metadata/common'}
    for arch in ('x86_64','aarch64'):
        root=directory/('rpm-history-'+arch);root.mkdir()
        metadata=root/'repomd.xml';b.download(base+'/'+arch+'/repodata/repomd.xml',metadata);b.download(base+'/'+arch+'/repodata/repomd.xml.asc',Path(str(metadata)+'.asc'))
        verify_signed(metadata,Path(str(metadata)+'.asc'),key)
        primary=ET.parse(metadata).find("r:data[@type='primary']",ns)
        if primary is None:raise ValueError('RPM repository has no primary index')
        location=primary.find('r:location',ns).get('href');checksum=primary.find('r:checksum',ns)
        if not location.startswith('repodata/') or '/' in location.removeprefix('repodata/') or checksum.get('type')!='sha256':raise ValueError('unsafe RPM metadata reference')
        path=root/'primary.xml.gz';b.download(base+'/'+arch+'/'+location,path)
        if b.sha(path)!=checksum.text:raise ValueError('RPM primary checksum mismatch')
        document=gzip.decompress(path.read_bytes())
        for package in ET.fromstring(document).findall('p:package',ns):
            name=package.findtext('p:name',namespaces=ns);package_arch=package.findtext('p:arch',namespaces=ns)
            version=package.find('p:version',ns)
            if name not in ('httpjet','httpjet-archive-keyring') or package_arch not in (arch,'noarch'):raise ValueError('unexpected RPM history package')
            if release_tuple(version.get('ver')+'-'+version.get('rel'))>release_tuple(manifest['release_id']):continue
            location=package.find('p:location',ns).get('href');basename=b.filename(location.removeprefix('Packages/'))
            if location!='Packages/'+basename:raise ValueError('unsafe RPM package location')
            checksum=package.find('p:checksum',ns)
            if checksum.get('type')!='sha256':raise ValueError('RPM package checksum must be SHA256')
            path=directory/'history/rpm'/basename;path.parent.mkdir(parents=True,exist_ok=True)
            if not path.exists():b.download(base+'/'+arch+'/'+location,path)
            if b.sha(path)!=checksum.text:raise ValueError('historical RPM carrier mismatch')

def fetch_current(repository,output,key,expected,release_base=BASE):
    b=api();b.validate_key(key,expected);output.mkdir(parents=True,exist_ok=False)
    pointer=output/'current-stable.json';signature=Path(str(pointer)+'.asc')
    b.download(release_base+'/stable.json',pointer);b.download(release_base+'/stable.json.asc',signature);verify_signed(pointer,signature,key)
    current=b.load(pointer);support.validate_window(current)
    if current.get('schema')!=2 or current.get('archive_fingerprint')!=expected or not re.fullmatch('[0-9a-f]{64}',current.get('qualification_sha256','')):raise ValueError('current pointer has no approved qualification/key')
    ident=support.identity(current['release_id']);base=release_base+'/'+ident['release_id']
    for name in ('manifest.json','manifest.json.asc','qualification.json','qualification.json.asc'):
        b.download(base+'/'+name,output/name)
    verify_signed(output/'manifest.json',output/'manifest.json.asc',key);verify_signed(output/'qualification.json',output/'qualification.json.asc',key)
    if b.sha(output/'manifest.json')!=current['manifest_sha256'] or (output/'manifest.json').stat().st_size!=current['manifest_size'] or b.sha(output/'qualification.json')!=current['qualification_sha256']:raise ValueError('current pointer hash mismatch')
    manifest=b.load(output/'manifest.json');support.identity_from_manifest(manifest)
    if manifest['release_id']!=current['release_id']:raise ValueError('current pointer version mismatch')
    for name in manifest['artifacts']:b.download(base+'/'+b.filename(name),output/name)
    for target in b.load(output/'qualification.json')['targets']:
        for field in ('receipt','log'):b.download(base+'/'+b.filename(target[field]),output/target[field])
        for name in target.get('evidence',{}):b.download(base+'/'+b.filename(name),output/name)
    for name in ('SHA256SUMS','install.sh'):b.download(base+'/'+name,output/('approved-install.sh' if name=='install.sh' else name))
    verify_artifacts(output,manifest);verify_qualification(output)
    signed_apt_history(repository,output,key,manifest)
    signed_rpm_history(repository.removesuffix('/apt')+'/rpm',output,key,manifest)
    return output
