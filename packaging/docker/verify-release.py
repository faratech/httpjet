#!/usr/bin/env python3
"""Authenticate the current release and its architecture-specific OCI carrier."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'release'))
import release
import support
import universal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('architecture', choices=('amd64', 'arm64'))
    parser.add_argument('run_id')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[1-9][0-9]*', args.run_id):
        raise ValueError('candidate run id must be numeric')
    repository = os.environ['GITHUB_REPOSITORY']
    if repository != 'faratech/httpjet':
        raise ValueError('unexpected public repository')
    run = json.loads(subprocess.check_output(['gh', 'api', f'repos/{repository}/actions/runs/{args.run_id}']))
    jobs = json.loads(subprocess.check_output(['gh', 'api', f'repos/{repository}/actions/runs/{args.run_id}/jobs?per_page=100']))['jobs']
    if run['status'] != 'completed' or run['conclusion'] != 'success' or run['path'] != '.github/workflows/installer-release.yml' or run['head_repository']['full_name'] != repository:
        raise ValueError('candidate must come from the completed public release workflow')
    for name in ('candidate', 'native (amd64, ubuntu-24.04)', 'native (arm64, ubuntu-24.04-arm)'):
        if not any(job['name'] == name and job['conclusion'] == 'success' for job in jobs):
            raise ValueError('native build or signing job did not succeed: ' + name)
    fingerprint = release.fingerprint(os.environ['ARCHIVE_FINGERPRINT'])
    with tempfile.TemporaryDirectory(prefix='httpjet-container-trust-') as temporary:
        root = Path(temporary)
        key = root / 'archive.asc'
        key.write_text(os.environ['ARCHIVE_KEY'])
        release.validate_key(key, fingerprint)
        candidate_manifest = args.candidate / 'candidate/manifest.json'
        candidate = release.load(candidate_manifest)
        ident = support.identity_from_manifest(candidate)
        manifest = args.candidate / 'snapshot/releases' / ident['release_id'] / 'manifest.json'
        universal.verify_signed(manifest, manifest.with_name('manifest.json.asc'), key)
        if release.sha(manifest) != release.sha(candidate_manifest):
            raise ValueError('candidate manifest differs from signed snapshot')
        if candidate['archive_fingerprint'] != fingerprint or run['head_sha'] != candidate['commit'] or run['head_branch'] != ident['tag']:
            raise ValueError('candidate source identity mismatch')
        target = subprocess.check_output(['git', 'rev-parse', ident['tag'] + '^{commit}'], text=True).strip()
        if target != candidate['commit']:
            raise ValueError('release tag no longer identifies the candidate')
        pointer = root / 'stable.json'
        release.download('https://httpjet-packages.pages.dev/releases/stable.json', pointer)
        release.download('https://httpjet-packages.pages.dev/releases/stable.json.asc', root / 'stable.json.asc')
        universal.verify_signed(pointer, root / 'stable.json.asc', key)
        stable = release.load(pointer)
        support.validate_window(stable)
        if (stable.get('archive_fingerprint') != fingerprint or stable.get('release_id') != ident['release_id']
                or stable.get('manifest_sha256') != release.sha(manifest) or stable.get('manifest_size') != manifest.stat().st_size):
            raise ValueError('candidate is not the currently published signed release')
        image = candidate['oci_images'][args.architecture]
        name = release.filename(image['artifact'])
        descriptor = candidate['artifacts'][name]
        archive = args.candidate / 'candidate' / name
        if (archive.is_symlink() or not archive.is_file() or archive.stat().st_size != descriptor['size']
                or release.sha(archive) != descriptor['sha256'] or image['archive_sha256'] != descriptor['sha256']
                or image['binary_sha256'] != candidate['binaries'][args.architecture]['binary_sha256']
                or image['architecture'] != args.architecture or not re.fullmatch(r'sha256:[0-9a-f]{64}', image['image_id'])):
            raise ValueError('OCI carrier does not match the signed release')
        args.output.write_text(json.dumps({'release_id': ident['release_id'], 'tag': ident['tag'],
                                          'commit': candidate['commit'], 'archive': str(archive),
                                          'image_id': image['image_id'], 'manifest_sha256': release.sha(manifest)})+'\n')
        print('Authenticated current release and OCI carrier for ' + args.architecture)


if __name__ == '__main__':
    main()
