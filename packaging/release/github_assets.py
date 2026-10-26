#!/usr/bin/env python3
"""Select and publish only hash-bound, qualified GitHub release assets.

The qualification job prepares subjects attested in the source-build workflow.
Promotion prepares the same subjects plus its rendered installer/signatures.
Publication is retryable without overwriting an existing release or asset; a
partial release remains a draft until every uploaded digest matches.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request

import release
import snapshot as contracts
import support
import universal

GENERATED = ('install.sh', 'manifest.json.asc', 'qualification.json.asc',
             'httpjet-archive-keyring.asc')
API = 'https://api.github.com'
UPLOADS = 'https://uploads.github.com'


def software_names(manifest):
    """The manifest contains software, not private prepared OS images."""
    support.identity_from_manifest(manifest)
    names = {release.filename(name) for name, item in manifest['artifacts'].items()
             if item['kind'] != 'qualification-image'}
    required = set()
    for arch in support.ARCHES:
        required.update((manifest['binaries'][arch]['artifact'],
                         manifest['packages'][arch], manifest['rpm_packages'][arch],
                         manifest['oci_images'][arch]['artifact']))
    ident = manifest['release_id']
    required.update((f'httpjet-archive-keyring_{ident}_all.deb',
                     f'httpjet-archive-keyring-{ident}.noarch.rpm',
                     f'httpjet-{ident}-source.tar.xz', 'support-matrix.json',
                     'qualification-images.json'))
    if not required.issubset(names):
        raise ValueError('manifest omits a required software/provenance asset')
    if names.intersection(GENERATED) or names.intersection(('manifest.json', 'qualification.json', 'SHA256SUMS')):
        raise ValueError('manifest artifact collides with release metadata')
    return sorted(names | {'manifest.json', 'qualification.json', 'SHA256SUMS'})


def copy_regular(source, destination):
    if source.is_symlink() or not source.is_file():
        raise ValueError('release asset is not a regular file: '+str(source))
    shutil.copyfile(source, destination)
    if release.sha(source) != release.sha(destination):
        raise ValueError('release asset changed during assembly: '+str(source))


def prepare_qualified(directory, output):
    directory, output = Path(directory), Path(output)
    manifest = release.load(directory/'manifest.json')
    universal.verify_artifacts(directory, manifest)
    universal.verify_qualification(directory)
    names = software_names(manifest)
    output.mkdir(mode=0o755)
    for name in names: copy_regular(directory/name, output/name)
    return names


def prepare_snapshot(root, key, fingerprint, output, generated):
    root, key, output, generated = map(Path, (root, key, output, generated))
    publication = contracts.verify(root, key, fingerprint)
    directory = root/'releases'/publication['release_id']
    manifest = release.load(directory/'manifest.json')
    names = software_names(manifest)
    output.mkdir(mode=0o755); generated.mkdir(mode=0o755)
    for name in names: copy_regular(directory/name, output/name)
    for name in GENERATED:
        source = root/'apt'/name if name == 'httpjet-archive-keyring.asc' else directory/name
        copy_regular(source, output/name)
        copy_regular(output/name, generated/name)
    return names


def validate_tag_context(manifest, repository, ref, sha):
    if repository != 'faratech/httpjet':
        raise ValueError('public release must originate from faratech/httpjet')
    identity = support.identity_from_manifest(manifest)
    if ref != 'refs/tags/'+identity['tag'] or sha != manifest['commit']:
        raise ValueError('promotion must run from the exact qualified public release tag and commit')
    return identity['tag']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Github:
    """Minimal authenticated API wrapper; redirects never receive credentials."""
    def __init__(self, repository, token):
        if repository != 'faratech/httpjet' or not token:
            raise ValueError('public repository and GitHub token are required')
        self.repository, self.token = repository, token
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, body=None, *, upload=False, content_type=None):
        host = UPLOADS if upload else API
        if not path.startswith('/repos/'+self.repository+'/'):
            raise ValueError('unexpected GitHub API path')
        headers = {'Authorization':'Bearer '+self.token, 'Accept':'application/vnd.github+json',
                   'X-GitHub-Api-Version':'2022-11-28'}
        if content_type: headers['Content-Type'] = content_type
        request = urllib.request.Request(host+path, data=body, headers=headers, method=method)
        with self.opener.open(request, timeout=180) as response:
            return json.load(response)

    def json(self, method, path, body=None):
        encoded = json.dumps(body, separators=(',', ':')).encode() if body is not None else None
        return self.request(method, path, encoded, content_type='application/json' if encoded else None)


def expected_assets(directory):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('release asset directory must be a directory')
    result = {}
    for path in directory.iterdir():
        release.filename(path.name)
        if path.is_symlink() or not path.is_file(): raise ValueError('unsafe GitHub release asset')
        if path.stat().st_size >= 2 * 1024**3: raise ValueError('GitHub release asset must be under 2 GiB')
        result[path.name] = {'sha256': release.sha(path), 'size': path.stat().st_size}
    if not result: raise ValueError('empty GitHub release asset directory')
    if len(result) > 1000: raise ValueError('GitHub release asset count exceeds 1000')
    return result


def check_asset(asset, descriptor):
    if (asset.get('state') != 'uploaded' or asset.get('size') != descriptor['size']
        or asset.get('digest') != 'sha256:'+descriptor['sha256']):
        raise ValueError('existing GitHub release asset differs from qualified bytes: '+asset.get('name','?'))


def verify_asset_set(directory, manifest, expected):
    required = set(software_names(manifest)) | set(GENERATED)
    if set(expected) != required:
        raise ValueError('GitHub release asset set differs from qualified manifest')
    for name, descriptor in manifest['artifacts'].items():
        if descriptor['kind'] == 'qualification-image': continue
        actual = expected[name]
        if actual['sha256'] != descriptor['sha256'] or actual['size'] != descriptor['size']:
            raise ValueError('GitHub release asset differs from signed manifest: '+name)
    qualification = release.load(Path(directory)/'qualification.json')
    if (qualification.get('status') != 'passed' or qualification.get('release_id') != manifest['release_id']
        or qualification.get('manifest_sha256') != expected['manifest.json']['sha256']
        or qualification.get('support_matrix_sha256') != manifest['support_matrix']['sha256']):
        raise ValueError('GitHub release qualification does not bind the manifest')


def release_body(tag, commit, manifest_hash):
    marker = '<!-- httpjet-qualified '+manifest_hash+' '+commit+' -->'
    release_id = support.identity(tag.removeprefix('v'))['release_id']
    source = f'--repo faratech/httpjet --source-ref refs/tags/{tag} --source-digest {commit} --deny-self-hosted-runners'
    return (f'HTTPJet {tag} is built and qualified from public commit `{commit}`.\n\n'
            'The release includes signed packages, portable static archives, corresponding source and '
            'the rendered installer. Linux io_uring is required. Package repositories and '
            'installation details are documented in the repository README.\n\n'
            '### Verify GitHub build provenance\n\n'
            '```sh\n'
            f'gh attestation verify httpjet-{release_id}-linux-amd64-static.tar.gz {source} '
            '--signer-workflow faratech/httpjet/.github/workflows/installer-release.yml\n'
            f'gh attestation verify install.sh {source} '
            '--signer-workflow faratech/httpjet/.github/workflows/installer-publish.yml\n'
            '```\n\n'+marker+'\n')


def pages(client, path):
    result = []
    for page in range(1, 21):
        items = client.json('GET', path+'?per_page=100&page='+str(page))
        if not isinstance(items, list): raise ValueError('invalid GitHub paginated response')
        result.extend(items)
        if len(items) < 100: return result
    raise ValueError('GitHub pagination limit exceeded')


def tag_commit(client, repository, tag):
    prefix = '/repos/'+repository+'/git/'
    reference = client.json('GET', prefix+'ref/tags/'+urllib.parse.quote(tag, safe=''))['object']
    for _ in range(5):
        if reference['type'] == 'commit': return reference['sha']
        if reference['type'] != 'tag': raise ValueError('release tag does not point to a commit')
        reference = client.json('GET', prefix+'tags/'+reference['sha'])['object']
    raise ValueError('release tag nesting is too deep')


def asset_map(client, prefix, release_id):
    result = {}
    for asset in pages(client, prefix+'/'+str(release_id)+'/assets'):
        name = asset['name']
        if name in result: raise ValueError('duplicate GitHub release asset name')
        result[name] = asset
    return result


def publish(directory, manifest, repository, ref, sha, client):
    tag = validate_tag_context(manifest, repository, ref, sha)
    if tag_commit(client, repository, tag) != sha:
        raise ValueError('public release tag changed after qualification')
    expected = expected_assets(directory)
    verify_asset_set(directory, manifest, expected)
    manifest_hash = release.sha(Path(directory)/'manifest.json')
    if release.load(Path(directory)/'manifest.json') != manifest:
        raise ValueError('GitHub assets are not bound to the qualified manifest')
    prefix = '/repos/'+repository+'/releases'
    # The by-tag API only guarantees published releases. The authenticated
    # listing also includes drafts, which is essential for safe retries.
    matching = [item for item in pages(client, prefix) if item.get('tag_name') == tag]
    if len(matching) > 1: raise ValueError('multiple GitHub releases share the tag')
    if matching:
        current = matching[0]
    else:
        current = client.json('POST', prefix, {'tag_name':tag, 'target_commitish':sha,
            'name':'httpjet '+tag, 'body':release_body(tag, sha, manifest_hash), 'draft':True, 'prerelease':False})
    marker = '<!-- httpjet-qualified '+manifest_hash+' '+sha+' -->'
    if current.get('tag_name') != tag or marker not in (current.get('body') or ''):
        raise ValueError('existing release is not the matching qualified publication')
    existing = asset_map(client, prefix, current['id'])
    if set(existing)-set(expected):
        raise ValueError('existing release contains an unexpected asset')
    for name, asset in existing.items(): check_asset(asset, expected[name])
    missing = sorted(set(expected)-set(existing))
    if missing and not current.get('draft'):
        raise ValueError('cannot add assets to an already published release')
    release_id = current['id']
    for name in missing:
        path = Path(directory)/name
        asset = client.request('POST', prefix+'/'+str(release_id)+'/assets?name='+urllib.parse.quote(name, safe=''),
                               path.read_bytes(), upload=True, content_type='application/octet-stream')
        check_asset(asset, expected[name])
    current = client.json('GET', prefix+'/'+str(release_id))
    actual = asset_map(client, prefix, release_id)
    if set(actual) != set(expected): raise ValueError('GitHub release asset set is incomplete')
    for name, asset in actual.items(): check_asset(asset, expected[name])
    if tag_commit(client, repository, tag) != sha:
        raise ValueError('public release tag changed during upload')
    if current.get('draft'):
        current = client.json('PATCH', prefix+'/'+str(release_id), {'draft':False, 'make_latest':'true'})
    if current.get('draft') or current.get('tag_name') != tag:
        raise ValueError('GitHub release did not become public for the qualified tag')
    return current['html_url']


def safe_download_url(url):
    parts = urllib.parse.urlsplit(url)
    hostname = parts.hostname or ''
    if (parts.scheme != 'https' or parts.username or parts.password
        or not (hostname == 'github.com' or hostname.endswith('.githubusercontent.com'))):
        raise ValueError('GitHub asset redirect left the approved HTTPS hosts')


class DownloadRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, url):
        safe_download_url(url)
        return super().redirect_request(request, fp, code, msg, headers, url)


def public_asset(opener, url, descriptor):
    safe_download_url(url)
    request = urllib.request.Request(url, headers={'Cache-Control':'no-cache'})
    with opener.open(request, timeout=60) as response:
        safe_download_url(response.url)
        digest = hashlib.sha256(); total = 0
        while block := response.read(1024*1024):
            total += len(block)
            if total > descriptor['size']: raise ValueError('public GitHub asset exceeds its qualified size')
            digest.update(block)
    if total != descriptor['size'] or digest.hexdigest() != descriptor['sha256']:
        raise ValueError('public GitHub asset differs from qualified bytes')


def verify_public(directory, manifest, repository, ref, sha, opener=None):
    tag = validate_tag_context(manifest, repository, ref, sha)
    expected = expected_assets(directory)
    verify_asset_set(directory, manifest, expected)
    opener = opener or urllib.request.build_opener(DownloadRedirect())
    base = 'https://github.com/'+repository+'/releases/'
    urls = [(base+'download/'+urllib.parse.quote(tag,safe='')+'/'+urllib.parse.quote(name,safe=''), expected[name])
            for name in sorted(expected)]
    urls.append((base+'latest/download/install.sh', expected['install.sh']))
    for url, descriptor in urls:
        for attempt in range(12):
            try:
                public_asset(opener, url, descriptor)
                break
            except (urllib.error.URLError, TimeoutError):
                if attempt == 11: raise
                time.sleep(5)
        print('verified public GitHub asset '+url)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    child = sub.add_parser('qualified'); child.add_argument('--directory',type=Path,required=True); child.add_argument('--output',type=Path,required=True)
    child = sub.add_parser('snapshot'); child.add_argument('--snapshot',type=Path,required=True); child.add_argument('--public-key',type=Path,required=True)
    child.add_argument('--fingerprint',required=True); child.add_argument('--output',type=Path,required=True); child.add_argument('--generated',type=Path,required=True)
    child = sub.add_parser('publish'); child.add_argument('--directory',type=Path,required=True)
    child = sub.add_parser('verify-public'); child.add_argument('--directory',type=Path,required=True)
    args = parser.parse_args()
    if args.action == 'qualified': names = prepare_qualified(args.directory,args.output)
    elif args.action == 'snapshot': names = prepare_snapshot(args.snapshot,args.public_key,args.fingerprint,args.output,args.generated)
    else:
        manifest = release.load(args.directory/'manifest.json')
        repository, ref, sha = (os.environ[key] for key in ('GITHUB_REPOSITORY','GITHUB_REF','GITHUB_SHA'))
        if args.action == 'publish':
            print(publish(args.directory,manifest,repository,ref,sha,Github(repository,os.environ['GH_TOKEN'])))
        else:
            verify_public(args.directory,manifest,repository,ref,sha)
        return
    print('Prepared '+str(len(names))+' qualified software/metadata subjects')


if __name__ == '__main__': main()
