#!/usr/bin/env python3
"""Generate native package locks from an authenticated schema-2 release manifest."""
import argparse
import json
from pathlib import Path
import re
from release import load,validate_key
import support
import universal
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--signature',type=Path,required=True)
parser.add_argument('--public-key',type=Path,required=True);parser.add_argument('--fingerprint',required=True)
parser.add_argument('--architecture',choices=support.ARCHES,required=True)
parser.add_argument('--release-base',default=universal.BASE);parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args();validate_key(args.public_key,args.fingerprint);universal.verify_signed(args.manifest,args.signature,args.public_key)
manifest=load(args.manifest);support.identity_from_manifest(manifest)
if manifest.get('schema')!=2 or manifest.get('archive_fingerprint')!=args.fingerprint:raise ValueError('untrusted native package manifest')
if not re.fullmatch(r'https://[A-Za-z0-9.:-]+(?:/[A-Za-z0-9._~-]+)+',args.release_base):raise ValueError('native package base must be HTTPS')
binary=manifest['binaries'][args.architecture];artifact=manifest['artifacts'][binary['artifact']]
if binary['libc']!='musl' or artifact['architecture']!=args.architecture or artifact['libc']!='musl':raise ValueError('wrong native package payload')
args.output.mkdir(parents=True,exist_ok=False)
(args.output/'manifest.json').write_bytes(args.manifest.read_bytes())
system={'amd64':'x86_64-linux','arm64':'aarch64-linux'}[args.architecture]
values={'release-id':manifest['release_id'],'uri':args.release_base+'/'+manifest['release_id']+'/'+binary['artifact'],
        'sha256':artifact['sha256'],'binary-sha256':binary['binary_sha256'],'system':system}
(args.output/'release-lock.scm').write_text('(use-modules (httpjet packages))\n(httpjet-binary-package\n'+''.join('  #:'+key+' '+json.dumps(value)+'\n' for key,value in values.items())+')\n')
