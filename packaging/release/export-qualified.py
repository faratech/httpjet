#!/usr/bin/env python3
"""Export verified software/proof objects without private VM input archives."""
import argparse,shutil
from pathlib import Path
from release import load,filename
import universal
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('source',type=Path);parser.add_argument('output',type=Path)
args=parser.parse_args();manifest=load(args.source/'manifest.json')
universal.verify_artifacts(args.source,manifest);universal.verify_qualification(args.source)
if args.output.exists():raise ValueError('qualified output must not exist')
args.output.mkdir();names=set(manifest['artifacts'])|{'manifest.json','SHA256SUMS','qualification.json'}
for target in load(args.source/'qualification.json')['targets']:
    names.update((target['receipt'],target['log']));names.update(target.get('evidence',{}))
for name in sorted(names):shutil.copyfile(args.source/filename(name),args.output/name)
