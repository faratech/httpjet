#!/usr/bin/env python3
"""Assemble an explicitly unqualified signed candidate; never deploy or test."""
import argparse
from pathlib import Path
import re
import tempfile
import xml.etree.ElementTree as ET
import pages
import release
import snapshot
import support
import universal

REPOSITORY = 'faratech/httpjet'
STATUS = 'publication-status.json'
NOTES = 'RELEASE-NOTES.txt'
METADATA = ('manifest.json', 'manifest.json.asc', STATUS, NOTES, 'SHA256SUMS')


def github_names(release_id):
    return {'install.sh', f'httpjet-{release_id}-linux-amd64-static.tar.gz',
            f'httpjet-{release_id}-linux-arm64-static.tar.gz',
            f'httpjet_{release_id}_amd64.deb', f'httpjet_{release_id}_arm64.deb',
            f'httpjet-{release_id}.x86_64.rpm', f'httpjet-{release_id}.aarch64.rpm'}


def regular_tree(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('publication input is not a regular directory: '+str(root))
    result = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('publication input contains a symlink or special file: '+str(path))
        if path.is_file(): result.append(path)
    return result


def verify_candidate(root, key, fingerprint, previous=None):
    release.validate_key(key, fingerprint)
    native = root/'snapshot'
    publication = release.load(native/'publication.json')
    if (publication.get('schema') != 2 or publication.get('qualified') is not False
            or publication.get('qualification_sha256') != 'unqualified'
            or publication.get('archive_fingerprint') != fingerprint):
        raise ValueError('build-only publication requires an explicitly unqualified candidate')
    pointer = native/'releases/stable.json'
    universal.verify_signed(pointer, Path(str(pointer)+'.asc'), key)
    selected = release.load(pointer)
    support.validate_window(selected)
    identity = support.identity(selected['release_id'])
    directory = native/'releases'/identity['release_id']
    regular_tree(directory)
    manifest_path = directory/'manifest.json'
    universal.verify_signed(manifest_path, directory/'manifest.json.asc', key)
    manifest = release.load(manifest_path)
    support.identity_from_manifest(manifest)
    if (selected.get('schema') != 2 or selected.get('qualification_sha256') != 'unqualified'
            or selected.get('archive_fingerprint') != fingerprint
            or manifest.get('archive_fingerprint') != fingerprint
            or selected['release_id'] != manifest['release_id']
            or publication['release_id'] != manifest['release_id']
            or release.sha(pointer) != publication['stable_sha256']
            or release.sha(manifest_path) != selected['manifest_sha256']
            or release.sha(manifest_path) != publication['manifest_sha256']
            or manifest_path.stat().st_size != selected['manifest_size']):
        raise ValueError('signed candidate selector does not bind this manifest/publication')
    if any(item['kind'] == 'qualification-image' for item in manifest['artifacts'].values()):
        raise ValueError('private qualification images cannot be published as software')
    metadata_only=publication.get('metadata_only') is True
    if metadata_only:
        if previous is None:raise ValueError('metadata-only refresh requires authenticated previous publication')
        old,_,status=universal._verify_build_only_current(previous,key,fingerprint)
        if (old['release_id']!=manifest['release_id'] or release.sha(previous/'manifest.json')!=release.sha(manifest_path)
            or publication.get('previous_stable_sha256')!=release.sha(previous/'current-stable.json')):
            raise ValueError('metadata-only refresh changed the authenticated release')
        for name in ('manifest.json','manifest.json.asc','publication-status.json','RELEASE-NOTES.txt'):
            if (directory/name).read_bytes()!=(previous/name).read_bytes():raise ValueError('immutable release metadata changed')
        if (directory/'install.sh').read_bytes()!=(previous/'approved-install.sh').read_bytes():raise ValueError('immutable installer changed')
    else:
        universal.verify_artifacts(directory, manifest)
    if release.sha(root/'candidate/manifest.json') != release.sha(manifest_path):
        raise ValueError('candidate and signed snapshot identify different manifests')
    for name, item in manifest['artifacts'].items():
        source = root/'candidate'/release.filename(name)
        if metadata_only and name not in universal._build_only_names(manifest) and not name.endswith(('.deb','.rpm')):continue
        if source.is_symlink() or not source.is_file() or pages.descriptor(source) != {'sha256': item['sha256'], 'size': item['size']}:
            raise ValueError('candidate artifact differs from signed snapshot: '+name)
    if metadata_only:
        with tempfile.TemporaryDirectory(prefix='httpjet-refresh-rpm-') as temporary:
            database=Path(temporary)/'rpmdb';database.mkdir()
            release.run(['rpm','--dbpath',database,'--initdb']);release.run(['rpmkeys','--dbpath',database,'--import',key])
            for name in manifest['artifacts']:
                if name.endswith('.rpm'):
                    report=release.run(['rpmkeys','--dbpath',database,'--checksig','--verbose',root/'candidate'/name])
                    if not universal.rpm_signature_verified(report):raise ValueError('native RPM archive signature did not verify')
    allowed = set(manifest['artifacts']) | {'manifest.json', 'manifest.json.asc', 'SHA256SUMS', 'install.sh'}
    if metadata_only:allowed=universal._build_only_names(manifest)|set(manifest['packages'].values())|set(manifest['rpm_packages'].values())|{'manifest.json','manifest.json.asc','SHA256SUMS','publication-status.json','RELEASE-NOTES.txt'}
    if {path.name for path in directory.iterdir()} != allowed:
        raise ValueError('candidate release directory contains unbound/private files')
    for name in (universal._build_only_names(manifest)|set(manifest['packages'].values())|set(manifest['rpm_packages'].values()))-{'install.sh'}:
        if pages.descriptor(directory/name)!=pages.descriptor(root/'candidate'/name):raise ValueError('public Linux archive changed in refresh')
    sums = ''.join(f"{item['sha256']}  {name}\n" for name, item in sorted(manifest['artifacts'].items())) + release.sha(manifest_path)+'  manifest.json\n'
    if (directory/'SHA256SUMS').read_text() != sums: raise ValueError('checksum catalog mismatch')
    if (directory/'install.sh').read_bytes() != (native/'apt/install.sh').read_bytes(): raise ValueError('installer mismatch')
    if key.read_bytes() != (native/'apt/httpjet-archive-keyring.asc').read_bytes(): raise ValueError('public key mismatch')
    fields = snapshot.verify_apt(native/'apt', manifest, fingerprint, native/'apt/install.sh')
    if fields.get('X-Httpjet-Manifest-SHA256') != release.sha(manifest_path) or fields.get('X-Httpjet-Qualification-SHA256') != 'unqualified':
        raise ValueError('signed APT identity mismatch')
    detached = native/'apt/dists/stable/Release.gpg'
    if detached.exists(): universal.verify_signed(detached.with_name('Release'), detached, key)
    snapshot.verify_rpm(native/'rpm', key)
    return native, directory, manifest, publication


def assemble(root, assets, site, key, fingerprint, run_id, previous=None):
    if not re.fullmatch('[0-9]+', run_id): raise ValueError('numeric source run ID required')
    if assets.exists() or site.exists(): raise ValueError('publication outputs must not exist')
    native, directory, manifest, publication = verify_candidate(root, key, fingerprint, previous)
    releases = {}; retained = {}
    if previous is not None:
        old = pages.read_index(previous, key, fingerprint, previous/'current-stable.json')
        if old['repository'] != REPOSITORY or publication.get('previous_stable_sha256') != old['stable_sha256']:
            raise ValueError('retention does not match staged previous publication')
        if universal.release_tuple(manifest['release_id']) < universal.release_tuple(old['release_id']):
            raise ValueError('publication cannot downgrade stable')
        releases = dict(old['releases']); retained = old['objects']
    elif publication.get('previous_stable_sha256'):
        raise ValueError('existing publication requires authenticated retention')
    assets.mkdir(parents=True); site.mkdir(parents=True)
    for name in sorted(github_names(manifest['release_id'])): pages.checked_copy(directory/name, assets/name)
    metadata_root = site/'releases'/manifest['release_id']; metadata_root.mkdir(parents=True)
    for name in ('manifest.json', 'manifest.json.asc', 'SHA256SUMS'): pages.checked_copy(directory/name, metadata_root/name)
    status = {'schema': 1, 'publication_mode': 'build-only', 'full_matrix_qualified': False,
              'release_id': manifest['release_id'], 'manifest_sha256': release.sha(directory/'manifest.json'),
              'source_commit': manifest['commit'], 'source_run_id': run_id, 'archive_fingerprint': fingerprint,
              'notice': 'The full support-matrix lifecycle qualification was not completed. This release is not fully qualified.'}
    release.write_json(metadata_root/STATUS, status)
    (metadata_root/NOTES).write_text('HTTPJet '+manifest['release_id']+'\n\n'+status['notice']+'\nSigned source-built candidate artifacts are published at the operator\'s request.\nio_uring is required.\nSource commit: '+manifest['commit']+'\nSource run: https://github.com/'+REPOSITORY+'/actions/runs/'+run_id+'\n')
    entry = {'tag': manifest['tag'], 'assets': {path.name: pages.descriptor(path) for path in [*regular_tree(assets), *regular_tree(metadata_root)]}}
    rid = manifest['release_id']
    if rid in releases and (releases[rid]['tag'] != entry['tag'] or any(name in releases[rid]['assets'] and releases[rid]['assets'][name] != item for name, item in entry['assets'].items())):
        raise ValueError('immutable published asset bytes changed')
    releases[rid] = entry
    if len(releases) > pages.MAX_REDIRECTS: raise ValueError('Pages redirect history exceeds 100 rules')
    for name, item in retained.items():
        path = previous/'pages-retention'/name
        if pages.descriptor(path) != item: raise ValueError('retained native object changed')
        pages.checked_copy(path, site/name)
    for branch in ('apt', 'rpm'):
        for path in regular_tree(native/branch):
            name = path.relative_to(native).as_posix(); pages.relative(name)
            pages.file_descriptor(pages.descriptor(path), pages.MAX_FILE)
            if name.startswith('apt/pool/') or '/Packages/' in name:
                item = manifest['artifacts'].get(release.filename(path.name), retained.get(name))
                if item is None or pages.descriptor(path) != {field: item[field] for field in ('sha256', 'size')}:
                    raise ValueError('native repository package differs from authenticated artifact: '+name)
            pages.checked_copy(path, site/name)
    for name in ('stable.json', 'stable.json.asc'):
        pages.checked_copy(native/'releases'/name, site/'releases'/name)
    redirects = ''.join(f'/releases/{version}/{name} https://github.com/{REPOSITORY}/releases/download/{value["tag"]}/{name} 302\n'
                        for version, value in sorted(releases.items()) for name in sorted(github_names(version) & set(value['assets'])))
    if len(redirects.splitlines()) > 2000: raise ValueError('Pages static redirect limit exceeded')
    if any(len(line) > 1000 for line in redirects.splitlines()): raise ValueError('Pages redirect line too long')
    (site/'_redirects').write_text(redirects)
    (site/'_headers').write_text(pages.HEADERS)
    (site/'404.html').write_text(pages.NOT_FOUND)
    objects = {}
    for path in regular_tree(site):
        name = path.relative_to(site).as_posix(); pages.relative(name)
        item = pages.descriptor(path); pages.file_descriptor(item, pages.MAX_FILE); objects[name] = item
    if len(objects)+2 > pages.MAX_FILES: raise ValueError('Pages file limit exceeded')
    index = {'schema': 1, 'release_id': rid, 'repository': REPOSITORY, 'archive_fingerprint': fingerprint,
             'stable_sha256': publication['stable_sha256'], 'releases': releases, 'site_objects': objects,
             'objects': {name: item for name, item in objects.items() if pages.static_release_metadata(name) or name.startswith(('apt/', 'rpm/')) and snapshot.immutable(name)}}
    release.write_json(site/pages.INDEX, index); universal.sign(site/pages.INDEX, fingerprint)
    universal.verify_signed(site/pages.INDEX, site/(pages.INDEX+'.asc'), key)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate', 'assets', 'pages', 'public-key'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--previous', type=Path)
    args = parser.parse_args()
    previous = args.previous or (args.candidate/'previous' if (args.candidate/'previous').is_dir() else None)
    assemble(args.candidate, args.assets, args.pages, args.public_key, args.fingerprint, args.run_id, previous)
    print('Assembled signed build-only publication. Full lifecycle qualification is incomplete.')


if __name__ == '__main__': main()
