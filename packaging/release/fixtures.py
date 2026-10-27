#!/usr/bin/env python3
"""Create private first-release lifecycle fixtures, never publication artifacts."""
import argparse,copy,gzip,io,json,os,re,shutil,subprocess,tarfile,tempfile
from pathlib import Path
import payload,support,universal
from release import load,sha,write_json,run,validate_key

def build_environment(manifest):
    epoch=manifest.get('source_date_epoch')
    if type(epoch) is not int or not 0<=epoch<=0xffffffff:
        raise ValueError('fixture source_date_epoch must be an unsigned 32-bit integer')
    return {**os.environ,'SOURCE_DATE_EPOCH':str(epoch)}

def portable(source,target,old_id,new_id):
    with tarfile.open(source,'r:*') as original,target.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w|') as result:
        for member in original:
            item=copy.copy(member)
            if item.name==f'httpjet-{old_id}':item.name=f'httpjet-{new_id}'
            elif item.name.startswith(f'httpjet-{old_id}/'):item.name=f'httpjet-{new_id}/'+item.name.split('/',1)[1]
            else:raise ValueError('fixture source has unexpected payload root')
            if item.issym() or item.islnk():raise ValueError('fixture source links are forbidden')
            result.addfile(item,original.extractfile(member) if member.isfile() else None)

def native_fixture(directory,manifest,arch,output,key,fingerprint):
    environment=build_environment(manifest)
    if arch not in support.ARCHES:raise ValueError('unsupported native fixture architecture')
    old=manifest['release_id'];upstream=manifest['upstream_version'];revision=manifest['revision']-1
    # On initial revision use -0 only as a native package-manager test fixture.
    fixture_id=upstream+'-'+str(revision);deb=directory/manifest['packages'][arch]
    with tempfile.TemporaryDirectory(prefix='httpjet-native-fixture-') as temporary:
        work=Path(temporary);tree=work/'deb';run(['dpkg-deb','-R',deb,tree])
        control=tree/'DEBIAN/control';control.write_text(re.sub(r'^Version: .+$','Version: '+fixture_id,control.read_text(),flags=re.M))
        deb_out=output/f'baseline-{arch}.deb';run(['dpkg-deb','--build','--root-owner-group',tree,deb_out],env=environment)
        payload.verify_carrier_binary(deb_out,'deb',manifest['binaries'][arch]['binary_sha256'])
        top=work/'rpm'
        for child in ('SOURCES','BUILD','BUILDROOT','RPMS','SRPMS','SPECS'):(top/child).mkdir(parents=True)
        package=work/f'httpjet-{fixture_id}-payload';package.mkdir()
        run(['bsdtar','-xf',directory/manifest['rpm_packages'][arch],'-C',package])
        # The key belongs to the separate keyring package and is supplied as Source1.
        source=top/'SOURCES'/f'httpjet-{fixture_id}-payload.tar.gz'
        with tarfile.open(source,'w:gz') as archive:archive.add(package,arcname=package.name)
        shutil.copyfile(key,top/'SOURCES/archive-keyring.asc')
        root=Path(__file__).resolve().parents[2]
        shutil.copyfile(root/'packaging/rpm/preinstall.sh',top/'SOURCES/preinstall.sh')
        rpm_arch={'amd64':'x86_64','arm64':'aarch64'}[arch]
        run(['rpmbuild','-bb','--target',rpm_arch,'--define','_topdir '+str(top),'--define','httpjet_version '+upstream,
             '--define','httpjet_revision '+str(revision),'--define','use_source_date_epoch_as_buildtime 1',
             '--define','clamp_mtime_to_source_date_epoch 1',root/'packaging/rpm/httpjet.spec'],env=environment)
        rpm_out=output/f'baseline-{arch}.rpm';shutil.copyfile(top/'RPMS'/rpm_arch/f'httpjet-{fixture_id}.{rpm_arch}.rpm',rpm_out)
        run(['rpmsign','--define','__gpg /usr/bin/gpg','--define','_gpg_name '+fingerprint,'--define','_gpg_path '+os.environ['GNUPGHOME'],'--addsign',rpm_out])
        payload.verify_carrier_binary(rpm_out,'rpm',manifest['binaries'][arch]['binary_sha256'])
    return {'release_id':fixture_id,'deb':deb_out.name,'deb_sha256':sha(deb_out),'rpm':rpm_out.name,'rpm_sha256':sha(rpm_out)}

def create(directory,output,key,fingerprint):
    validate_key(key,fingerprint);manifest=load(directory/'manifest.json')
    if manifest.get('schema')!=2 or manifest.get('test_fixture') or manifest.get('archive_fingerprint')!=fingerprint:raise ValueError('fixture source must be real schema-2 candidate')
    build_environment(manifest)
    universal.verify_artifacts(directory,manifest)
    if output.exists():raise ValueError('fixture output must not exist')
    output.mkdir(parents=True);ident=support.identity(manifest['upstream_version'],manifest['revision']+1)
    release=output/'releases'/ident['release_id'];release.mkdir(parents=True)
    fixture=copy.deepcopy(manifest);fixture.update(ident);fixture['test_fixture']=True;fixture['fixture_kind']='first-release-forward-lifecycle-only';fixture['artifacts']={};fixture['binaries']={}
    natives={}
    for arch in support.ARCHES:
        name=f"httpjet-{ident['release_id']}-linux-{arch}-static.tar.gz"
        portable(directory/manifest['binaries'][arch]['artifact'],release/name,manifest['release_id'],ident['release_id'])
        fixture['artifacts'][name]={'kind':'portable','architecture':arch,'libc':'musl','sha256':sha(release/name),'size':(release/name).stat().st_size}
        fixture['binaries'][arch]={'artifact':name,'libc':'musl','binary_sha256':manifest['binaries'][arch]['binary_sha256']}
        natives[arch]=native_fixture(directory,manifest,arch,output,key,fingerprint)
    write_json(release/'manifest.json',fixture);universal.sign(release/'manifest.json',fingerprint)
    write_json(output/'fixture-catalog.json',{'schema':1,'kind':'first-release-fixture','source_release_id':manifest['release_id'],
                 'forward_release_id':ident['release_id'],'native_baselines':natives,'warning':'Exercises packaging transitions with identical candidate ELF; never proves older runtime compatibility.'})

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--public-key',type=Path,required=True);parser.add_argument('--fingerprint',required=True)
    args=parser.parse_args();create(args.directory,args.output,args.public_key,args.fingerprint)
if __name__=='__main__':main()
