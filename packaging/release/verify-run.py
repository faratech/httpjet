#!/usr/bin/env python3
"""Accept qualification artifacts only from our successful release-tag workflow."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request
from release import USER_AGENT, load, verify_artifacts, verify_qualification
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('run_id');parser.add_argument('directory',type=Path)
args=parser.parse_args()
if not re.fullmatch('[0-9]+',args.run_id):
    raise ValueError('numeric GitHub run id required')
repository=os.environ['GITHUB_REPOSITORY']
headers={'User-Agent':USER_AGENT,'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
def get(path):
    request=urllib.request.Request('https://api.github.com/repos/'+repository+'/'+path,headers=headers)
    with urllib.request.urlopen(request,timeout=30) as response:
        return json.load(response)
manifest=load(args.directory/'manifest.json')
if manifest.get('schema')!=2:raise ValueError('promotion requires versioned Linux-wide qualification')
verify_artifacts(args.directory,manifest);verify_qualification(args.directory)
run=get('actions/runs/'+args.run_id)
if (run['conclusion']!='success' or run['status']!='completed' or run['event'] not in ('push','workflow_dispatch')
    or run['path']!='.github/workflows/installer-release.yml' or run['head_sha']!=manifest['commit']
    or run['head_repository']['full_name']!=repository):
    raise ValueError('artifact run is not our successful release-tag qualification')
reference=get('git/ref/tags/'+manifest['tag'])['object']
for _ in range(5):
    if reference['type']=='commit':
        break
    if reference['type']!='tag':
        raise ValueError('release reference does not identify a commit')
    reference=get('git/tags/'+reference['sha'])['object']
if reference['type']!='commit' or reference['sha']!=manifest['commit']:
    raise ValueError('release tag no longer identifies qualified source commit')
matrix=get('contents/packaging/release/support-matrix.json?ref='+manifest['commit'])
if hashlib.sha256(base64.b64decode(matrix['content'])).hexdigest()!=manifest['support_matrix']['sha256']:
    raise ValueError('qualification policy differs from verified source commit')
print('verified source identity and every required support-matrix receipt')
