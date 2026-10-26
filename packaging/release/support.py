#!/usr/bin/env python3
"""Versioned support policy and canonical immutable release identities."""
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re

POLICY = Path(__file__).with_name('support-matrix.json')
ARCHES = ('amd64','arm64')
VERSION = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'

def identity(value, revision=None):
    match=re.fullmatch('('+VERSION+r')-([1-9][0-9]*)',value)
    if match:
        upstream=match.group(1); number=int(match.group(2))
        if revision is not None and number!=revision:raise ValueError('conflicting package revision')
    else:
        if not re.fullmatch(VERSION,value):raise ValueError('release identity must be X.Y.Z-N')
        upstream=value;number=1 if revision is None else revision
    if type(number) is not int or number<1:raise ValueError('package revision must be a positive integer')
    return {'version':upstream,'upstream_version':upstream,'revision':number,'package_revision':number,
            'release_id':upstream+'-'+str(number),'tag':'v'+upstream+('' if number==1 else '-'+str(number))}

def identity_from_manifest(manifest):
    result=identity(manifest['release_id'])
    for field,value in result.items():
        if manifest.get(field)!=value:raise ValueError('release identity mismatch: '+field)
    return result

def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def load_policy(path=POLICY):
    policy=json.loads(Path(path).read_text())
    if policy.get('schema')!=1 or not policy.get('id') or not policy.get('rows'):raise ValueError('invalid support matrix')
    ids=set()
    for row in policy['rows']:
        if not re.fullmatch('[a-z0-9][a-z0-9._-]+',row['id']) or row['id'] in ids:raise ValueError('invalid/duplicate support row')
        ids.add(row['id'])
        if row['architecture'] not in ARCHES or row['required'] is not True:raise ValueError('matrix rows must be explicit required targets')
        if not row['checks'] or len(row['checks'])!=len(set(row['checks'])):raise ValueError('empty/duplicate qualification checks')
        if row['executor'] not in ('cloud','cloud-lock','rootfs','nix-image','guix-image','coreos','oci'):raise ValueError('unknown qualification executor')
    if policy.get('runtime')!={'transport':'io_uring','fallback':False,'global_policy_changes':False,'libc':'fully-static-musl'}:
        raise ValueError('matrix weakens mandatory runtime policy')
    return policy

def rows(path=POLICY):return load_policy(path)['rows']

def policy_descriptor(path=POLICY):
    policy=load_policy(path)
    return {'id':policy['id'],'file':'support-matrix.json','sha256':digest(path),'size':Path(path).stat().st_size}

def bound_policy(directory,manifest):
    descriptor=manifest['support_matrix'];name=descriptor['file']
    if name!='support-matrix.json':raise ValueError('unexpected support policy filename')
    path=Path(directory)/name
    if digest(path)!=descriptor['sha256'] or path.stat().st_size!=descriptor['size']:raise ValueError('support matrix hash mismatch')
    policy=load_policy(path)
    if policy['id']!=descriptor['id']:raise ValueError('support matrix identity mismatch')
    return policy

def utc_timestamp(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',value):
        raise ValueError('timestamp must be UTC YYYY-MM-DDTHH:MM:SSZ')
    return datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)

def validate_window(document,now=None):
    issued=utc_timestamp(document['issued_at']);expires=utc_timestamp(document['expires_at'])
    now=now or datetime.now(timezone.utc)
    if issued>now+timedelta(hours=1) or expires<=now or expires<=issued or expires-issued>timedelta(days=30):
        raise ValueError('expired or invalid signed release lifetime')
    return issued,expires

def verify_runtime(runtime,uid=None,binary_sha256=None):
    protocols={'http','tls','h2','h3'}
    if (runtime.get('status')!='passed' or type(runtime.get('uid')) is not int or runtime['uid']<=0
        or runtime.get('no_multishot_accept') is not True
        or any(runtime.get('protocols',{}).get(name) is not True for name in protocols)):
        raise ValueError('runtime did not prove every qualified unprivileged protocol')
    if uid is not None and runtime['uid']!=uid:raise ValueError('runtime identity differs from service')
    if binary_sha256 is not None and runtime.get('binary_sha256')!=binary_sha256:raise ValueError('runtime binary differs from payload')
    if (type(runtime.get('body_size')) is not int or runtime['body_size']<1024*1024
        or not re.fullmatch('[0-9a-f]{64}',runtime.get('body_sha256',''))
        or set(runtime.get('hashes',{}))!=protocols
        or set(runtime['hashes'].values())!={runtime['body_sha256']}):
        raise ValueError('runtime omitted matching full large bodies for every protocol')

def verify_row(row,receipt,manifest,manifest_sha,image_lock=None):
    if receipt.get('schema')!=2 or receipt.get('row_id')!=row['id'] or receipt.get('release_id')!=manifest['release_id']:
        raise ValueError('receipt has another matrix/release identity')
    if receipt.get('architecture')!=row['architecture'] or receipt.get('route')!=row['route'] or receipt.get('init')!=row['init']:
        raise ValueError('receipt platform does not match support row')
    if receipt.get('manifest_sha256')!=manifest_sha or receipt.get('status')!='passed':raise ValueError('receipt does not qualify this manifest')
    binary=manifest['binaries'][row['architecture']];artifact=manifest['artifacts'][binary['artifact']]
    if receipt.get('payload_sha256')!=artifact['sha256'] or receipt.get('binary_sha256')!=binary['binary_sha256']:
        raise ValueError('receipt identifies different payload/binary bytes')
    if row['route'] in ('oci','immutable'):
        image=manifest['oci_images'][row['architecture']]
        if receipt.get('container_image_id')!=image['image_id'] or receipt.get('container_image_sha256')!=manifest['artifacts'][image['artifact']]['sha256']:
            raise ValueError('receipt did not qualify the exact OCI image')
    checks=receipt.get('checks',{})
    if set(checks)!=set(row['checks']) or any(v!='passed' for v in checks.values()):raise ValueError('incomplete/failed matrix qualification')
    source=receipt.get('image',{})
    if image_lock is None or source.get('input_sha256')!=hashlib.sha256(json.dumps(image_lock,sort_keys=True,separators=(',',':')).encode()).hexdigest():
        raise ValueError('receipt does not identify authenticated image inputs')
    if not re.fullmatch(r'[0-9a-f]{64}',source.get('sha256','')) or not source.get('origin'):
        raise ValueError('receipt lacks resolved image/rootfs identity')
    if image_lock.get('selinux'):
        expected=image_lock['selinux'];observed=source.get('selinux',{})
        if (observed.get('mode')!='Enforcing' or any(observed.get(k)!=v for k,v in expected.items())
            or not re.fullmatch('[0-9a-f]{64}',observed.get('base_template_sha256',''))):
            raise ValueError('receipt lacks its enforcing dedicated SELinux policy proof')
    if image_lock.get('operator_configuration'):
        setup=source.get('operator_configuration',{})
        if setup.get('scope')!='disposable-qualification-image' or setup.get('before') not in (None,'0','1','2') or setup.get('after') not in (None,'0') or type(setup.get('changed')) is not bool:
            raise ValueError('locked operator image preparation was not recorded')
        if setup['changed']:
            stock=setup.get('stock_probe',{})
            if setup['before'] not in ('1','2') or setup['after']!='0' or stock.get('uid',0)<=0:
                raise ValueError('operator setup lacks its measured stock-policy proof')
            if setup['before']=='2' and (stock.get('status')!='failed' or stock.get('errno')!=1):
                raise ValueError('stock disabled policy was not observed as blocked')
    evidence=receipt.get('io_uring',{})
    positive=evidence.get('positive',{});negative=evidence.get('negative',{})
    if (positive.get('status')!='passed' or type(positive.get('uid')) is not int or positive['uid']<=0
        or positive.get('global_policy_changed') is not False or receipt.get('service_uid')!=positive['uid']):
        raise ValueError('io_uring positive proof must run as the service account')
    if any(positive.get('operations',{}).get(name) is not True for name in ('setup','register_probe','enter_nop')):
        raise ValueError('io_uring proof omits required operations')
    if (negative.get('status')!='expected_failure' or type(negative.get('uid')) is not int or negative['uid']<=0
        or type(negative.get('exit_code')) is not int or negative['exit_code']==0 or negative.get('errno') not in ('EPERM',1)
        or negative.get('global_policy_changed') is not False or negative.get('ready_file_created') is not False
        or negative.get('uid')!=positive['uid']):raise ValueError('missing process-scoped io_uring denial proof')
    if receipt.get('kernel',{}).get('no_multishot_accept') is not row['no_multishot_accept']:
        raise ValueError('kernel compatibility launch flags were not qualified')
