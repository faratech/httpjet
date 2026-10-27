#!/usr/bin/env python3
"""Project a qualified snapshot onto static Pages without discarding history."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

import release
import snapshot
import support
import universal

ORIGIN = 'https://httpjet-packages.pages.dev'
PROJECT = 'httpjet-packages'
WRANGLER = '4.153.0'
MAX_FILE = 25 * 1024 * 1024
MAX_FILES = 20000
MAX_REDIRECTS = 100
INDEX = 'pages-index.json'
HEADERS = '/*\n  Cache-Control: no-store\n  X-Content-Type-Options: nosniff\n'
NOT_FOUND = '<!doctype html><meta charset="utf-8"><title>Not found</title><p>Not found</p>\n'
BOOTSTRAP = '<!doctype html><meta charset="utf-8"><title>httpjet package archive</title><p>No qualified release has been published.</p>\n'


def bootstrap(output):
    if output.exists(): raise ValueError('bootstrap output must not exist')
    output.mkdir(parents=True)
    for name, body in (('index.html', BOOTSTRAP), ('404.html', NOT_FOUND), ('_headers', HEADERS)):
        (output / name).write_text(body)


def public_request(url, method='GET', data=None):
    return urllib.request.Request(url, method=method, data=data, headers={'User-Agent': release.USER_AGENT})


def probe_bootstrap(base=ORIGIN, read_only=False):
    for method in ('GET', 'HEAD'):
        request = public_request(base + '/', method=method)
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            if response.status != 200 or not response.url.startswith('https://') or 'no-store' not in response.headers.get('Cache-Control', ''):
                raise ValueError('bootstrap origin is not an uncached HTTPS 200')
            if body != (BOOTSTRAP.encode() if method == 'GET' else b''):
                raise ValueError('bootstrap bytes changed or a package release is already live')
    missing = '/releases/bootstrap-missing-' + uuid.uuid4().hex + '.json'
    for path in ('/releases/stable.json', missing):
        for method in ('GET', 'HEAD'):
            try:
                urllib.request.urlopen(public_request(base + path, method=method), timeout=30).close()
            except urllib.error.HTTPError as error:
                if error.code != 404 or error.url != base + path: raise
                error.close()
            else: raise ValueError('bootstrap missing object must return actual 404')
    write_status = None
    if not read_only:
        try:
            urllib.request.urlopen(public_request(base + missing, data=b'bootstrap-readonly-test', method='PUT'), timeout=30).close()
        except urllib.error.HTTPError as error:
            if error.code not in (403, 404, 405): raise
            write_status = error.code; error.close()
        else: raise ValueError('static Pages origin accepted a public write')
        try:
            urllib.request.urlopen(public_request(base + missing), timeout=30).close()
        except urllib.error.HTTPError as error:
            if error.code != 404: raise
            error.close()
        else: raise ValueError('public write created a Pages object')
    return {'status': 'passed', 'scope': 'empty-pages-bootstrap-only', 'origin': base,
            'index_sha256': hashlib.sha256(BOOTSTRAP.encode()).hexdigest(), 'missing_status': 404,
            'write_status': write_status, 'write_tested': not read_only, 'package_release_live': False}


def public_http_diagnostic(error):
    """Bounded public-response evidence; never print cookies or request secrets."""
    allowed = {'server', 'cf-ray', 'cf-mitigated', 'content-type', 'cache-control', 'location', 'www-authenticate'}
    headers = {name: value[:2048] for name, value in error.headers.items() if name.lower() in allowed}
    return {'status': error.code, 'url': error.url, 'headers': headers,
            'body_prefix': error.read(4096).decode('utf-8', errors='replace')}


def descriptor(path):
    return {'sha256': release.sha(path), 'size': path.stat().st_size}


def static_release_metadata(value):
    return bool(re.fullmatch(r'releases/[0-9]+\.[0-9]+\.[0-9]+-[1-9][0-9]*/(?:manifest\.json(?:\.asc)?|publication-status\.json|RELEASE-NOTES\.txt|SHA256SUMS)', value))


def relative(value, immutable=False):
    path = PurePosixPath(value)
    if (not isinstance(value, str) or path.is_absolute() or '\\' in value
            or any(part in ('', '.', '..') for part in value.split('/'))
            or not re.fullmatch(r'[A-Za-z0-9_./+~-]+', value)):
        raise ValueError('unsafe Pages object path')
    if immutable and not static_release_metadata(value) and (not value.startswith(('apt/', 'rpm/')) or not snapshot.immutable(value)):
        raise ValueError('retention accepts only immutable native repository objects')
    if not immutable and value not in ('404.html', '_headers', '_redirects') and not value.startswith(('apt/', 'rpm/', 'releases/stable.json')) and not static_release_metadata(value):
        raise ValueError('unexpected Pages public object')
    return value


def file_descriptor(value, limit=None):
    if (not isinstance(value, dict) or set(value) != {'sha256', 'size'}
            or not re.fullmatch('[0-9a-f]{64}', value.get('sha256', ''))
            or type(value.get('size')) is not int or value['size'] < 0
            or limit is not None and value['size'] > limit):
        raise ValueError('invalid Pages file descriptor')


def read_index(directory, key, fingerprint, pointer):
    release.validate_key(key, fingerprint)
    universal.verify_signed(directory / INDEX, directory / (INDEX + '.asc'), key)
    value = release.load(directory / INDEX)
    support.identity(value['release_id'])
    if (value.get('schema') != 1 or value.get('archive_fingerprint') != fingerprint
            or value.get('stable_sha256') != release.sha(pointer)
            or value['release_id'] != release.load(pointer)['release_id']
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value.get('repository', ''))):
        raise ValueError('Pages index is not bound to the current authenticated pointer')
    for name, item in value['objects'].items():
        relative(name, True); file_descriptor(item, MAX_FILE)
        if value['site_objects'].get(name) != item:
            raise ValueError('retained object differs from authenticated Pages site index')
    for name, item in value['site_objects'].items():
        relative(name); file_descriptor(item, MAX_FILE)
    for rid, entry in value['releases'].items():
        if entry['tag'] != support.identity(rid)['tag']:
            raise ValueError('retained redirect tag differs from canonical release identity')
        for name, item in entry['assets'].items():
            release.filename(name); file_descriptor(item)
    if value['release_id'] not in value['releases'] or len(value['releases']) > MAX_REDIRECTS:
        raise ValueError('Pages redirect history exceeds the static platform contract')
    if len(value['site_objects']) + 2 > MAX_FILES:
        raise ValueError('Pages file count exceeds platform limit')
    return value


def fetch_retention(base, output, key, fingerprint, pointer):
    for name in (INDEX, INDEX + '.asc'):
        release.download(base + '/' + name, output / name)
    value = read_index(output, key, fingerprint, pointer)
    target = output / 'pages-retention'; target.mkdir()
    for name, item in value['objects'].items():
        path = target / name; path.parent.mkdir(parents=True, exist_ok=True)
        release.download(base + '/' + name, path)
        if descriptor(path) != item:
            raise ValueError('retained Pages object changed: ' + name)
    return value


def precondition(publication, key, fingerprint, base=ORIGIN):
    """An actual missing pointer permits first publication; 403 never does."""
    url = base + '/releases/stable.json'
    with tempfile.TemporaryDirectory(prefix='httpjet-pages-precondition-') as temporary:
        current = Path(temporary) / 'stable.json'
        try:
            release.download(url, current)
        except urllib.error.HTTPError as error:
            if error.code != 404 or error.url != url or publication.get('previous_stable_sha256'):
                raise
            error.close(); return
        expected = publication.get('previous_stable_sha256')
        if release.sha(current) not in (expected, publication['stable_sha256']):
            raise ValueError('Pages stable changed since authenticated staging; refresh and retry')
        signature = Path(str(current) + '.asc')
        release.download(url + '.asc', signature)
        universal.verify_signed(current, signature, key)
        value = release.load(current); support.validate_window(value)
        if value.get('schema') != 2 or value.get('archive_fingerprint') != fingerprint:
            raise ValueError('current Pages pointer uses a different signing identity')
        if universal.release_tuple(value['release_id']) > universal.release_tuple(publication['release_id']):
            raise ValueError('Pages stable cannot automatically downgrade')


def checked_copy(source, target):
    if source.is_symlink() or not source.is_file():
        raise ValueError('Pages accepts only regular public files')
    if target.exists():
        if target.is_symlink() or descriptor(target) != descriptor(source):
            raise ValueError('immutable Pages object cannot be replaced: ' + str(target))
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target); target.chmod(0o644)


def project(source, output, key, fingerprint, previous=None, repository='faratech/httpjet'):
    if output.exists():
        raise ValueError('Pages output must not exist')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('invalid GitHub release repository')
    info = snapshot.verify(source, key, fingerprint)
    precondition(info, key, fingerprint)
    releases = {}; retained = {}
    if previous:
        old = read_index(previous, key, fingerprint, previous / 'current-stable.json')
        if old['repository'] != repository or info.get('previous_stable_sha256') != old['stable_sha256']:
            raise ValueError('Pages retention does not match staged previous publication')
        if universal.release_tuple(info['release_id']) < universal.release_tuple(old['release_id']):
            raise ValueError('Pages stable cannot automatically downgrade')
        releases = dict(old['releases']); retained = old['objects']
    elif info.get('previous_stable_sha256'):
        raise ValueError('existing Pages history requires its authenticated retention index')
    rid = info['release_id']; root = source / 'releases' / rid
    assets = {release.filename(path.name): descriptor(path) for path in root.iterdir()}
    entry = {'tag': support.identity(rid)['tag'], 'assets': assets}
    if rid in releases and releases[rid] != entry:
        raise ValueError('published GitHub release asset set is immutable')
    releases[rid] = entry
    if len(releases) > MAX_REDIRECTS:
        raise ValueError('Pages 100 dynamic redirect limit reached; history was not pruned')
    output.mkdir(parents=True)
    for name, item in retained.items():
        path = previous / 'pages-retention' / name
        if path.is_symlink() or descriptor(path) != item:
            raise ValueError('authenticated retained Pages file changed: ' + name)
        checked_copy(path, output / name)
    for branch in ('apt', 'rpm'):
        for path in sorted((source / branch).rglob('*')):
            if path.is_symlink(): raise ValueError('Pages source cannot contain symlinks')
            if path.is_file():
                name = path.relative_to(source).as_posix(); relative(name)
                checked_copy(path, output / name)
    for name in ('stable.json', 'stable.json.asc'):
        checked_copy(source / 'releases' / name, output / 'releases' / name)
    redirects = ''.join(f'/releases/{version}/* https://github.com/{repository}/releases/download/{item["tag"]}/:splat 302\n'
                        for version, item in sorted(releases.items()))
    if any(len(line) > 1000 for line in redirects.splitlines()): raise ValueError('Pages redirect exceeds platform line limit')
    (output / '_redirects').write_text(redirects)
    (output / '_headers').write_text(HEADERS)
    (output / '404.html').write_text(NOT_FOUND)
    site = {}
    for path in sorted(output.rglob('*')):
        if path.is_file():
            name = path.relative_to(output).as_posix(); item = descriptor(path)
            relative(name); file_descriptor(item, MAX_FILE); site[name] = item
    if len(site) + 2 > MAX_FILES: raise ValueError('Pages 20000 file limit exceeded')
    value = {'schema': 1, 'release_id': rid, 'repository': repository, 'archive_fingerprint': fingerprint,
             'stable_sha256': info['stable_sha256'], 'releases': releases, 'site_objects': site,
             'objects': {name: item for name, item in site.items() if name.startswith(('apt/', 'rpm/')) and snapshot.immutable(name)}}
    release.write_json(output / INDEX, value); universal.sign(output / INDEX, fingerprint)
    for path in (output / INDEX, output / (INDEX + '.asc')):
        file_descriptor(descriptor(path), MAX_FILE)
    return value


def verify(directory, key, fingerprint, base=ORIGIN):
    value = read_index(directory, key, fingerprint, directory / 'releases/stable.json')
    local = dict(value['site_objects'])
    local.update({name: descriptor(directory / name) for name in (INDEX, INDEX + '.asc')})
    if {path.relative_to(directory).as_posix() for path in directory.rglob('*') if path.is_file()} != set(local):
        raise ValueError('Pages directory contains unbound files')
    with tempfile.TemporaryDirectory(prefix='httpjet-pages-public-') as temporary:
        target = Path(temporary) / 'object'
        for name, item in sorted(local.items()):
            path = directory / name
            if path.is_symlink() or descriptor(path) != item: raise ValueError('projected Pages file changed')
            # Cloudflare consumes these control files; they are not public assets.
            if name in ('_headers', '_redirects', '404.html'): continue
            for attempt in range(12):
                try:
                    release.download(base + '/' + name, target)
                    if descriptor(target) != item: raise ValueError('public Pages bytes differ: ' + name)
                    break
                except (urllib.error.URLError, TimeoutError, ValueError):
                    if name in value['objects'] or attempt == 11: raise
                    time.sleep(2)
        missing = base + '/releases/missing-' + uuid.uuid4().hex + '.json'
        try:
            release.download(missing, target)
        except urllib.error.HTTPError as error:
            if error.code != 404 or error.url != missing: raise
            error.close()
        else:
            raise ValueError('Pages missing objects must return a real 404')
    return {'status': 'passed', 'release_id': value['release_id'], 'stable_sha256': value['stable_sha256'],
            'pages_index_sha256': release.sha(directory / INDEX), 'objects': len(local) - 2, 'missing_status': 404}


def deploy(source, directory, key, fingerprint, receipt, github_directory=None):
    from publish import S3
    from publish_v2 import publication_lock
    info = snapshot.verify(source, key, fingerprint)
    index = read_index(directory, key, fingerprint, directory / 'releases/stable.json')
    if index['stable_sha256'] != info['stable_sha256']:
        raise ValueError('Pages projection differs from qualified publication')
    if receipt.resolve().is_relative_to(directory.resolve()):
        raise ValueError('deployment receipt must remain outside the public Pages tree')
    if github_directory:
        import github_assets
        manifest = release.load(github_directory / 'manifest.json')
        if release.sha(github_directory / 'manifest.json') != release.sha(source / 'releases' / info['release_id'] / 'manifest.json'):
            raise ValueError('GitHub promotion assets differ from the Pages publication')
        repository, ref, commit = (os.environ[name] for name in ('GITHUB_REPOSITORY', 'GITHUB_REF', 'GITHUB_SHA'))
        github_assets.validate_tag_context(manifest, repository, ref, commit)
    with publication_lock(S3(), info['stable_sha256']):
        precondition(info, key, fingerprint)
        subprocess.run(['npx', '--yes', 'wrangler@' + WRANGLER, 'pages', 'deploy', str(directory),
                        '--project-name', PROJECT, '--branch', 'main', '--commit-dirty=true'], check=True)
        report = verify(directory, key, fingerprint)
        subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('check-public.py')),
                        str(source), '--without-website-redirect'], check=True)
        report['public_release_redirects_verified'] = True
        if github_directory:
            github_assets.promote_latest(github_directory, manifest, repository, ref, commit,
                                         github_assets.Github(repository, os.environ['GH_TOKEN']))
            github_assets.verify_public(github_directory, manifest, repository, ref, commit, require_latest=True)
            report['github_latest_verified'] = True
        release.write_json(receipt, {**report, 'project': PROJECT, 'origin': ORIGIN, 'wrangler': WRANGLER})
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='command', required=True)
    blank = sub.add_parser('bootstrap'); blank.add_argument('--output', type=Path, required=True)
    probe = sub.add_parser('probe-bootstrap'); probe.add_argument('--receipt', type=Path, required=True)
    probe.add_argument('--read-only', action='store_true')
    create = sub.add_parser('project'); create.add_argument('--snapshot', type=Path, required=True)
    create.add_argument('--output', type=Path, required=True); create.add_argument('--previous', type=Path)
    create.add_argument('--repository', default='faratech/httpjet')
    public = sub.add_parser('verify'); public.add_argument('--directory', type=Path, required=True)
    publish = sub.add_parser('deploy'); publish.add_argument('--snapshot', type=Path, required=True)
    publish.add_argument('--directory', type=Path, required=True); publish.add_argument('--receipt', type=Path, required=True)
    publish.add_argument('--github-assets', type=Path)
    for child in (create, public, publish):
        child.add_argument('--public-key', type=Path, required=True); child.add_argument('--fingerprint', required=True)
    args = parser.parse_args()
    if args.command == 'bootstrap':
        bootstrap(args.output)
    elif args.command == 'probe-bootstrap':
        try:
            result = probe_bootstrap(read_only=args.read_only)
        except urllib.error.HTTPError as error:
            print(json.dumps(public_http_diagnostic(error), sort_keys=True), file=sys.stderr)
            raise
        release.write_json(args.receipt, result); print(result)
    elif args.command == 'project':
        project(args.snapshot, args.output, args.public_key, args.fingerprint, args.previous, args.repository)
    elif args.command == 'verify':
        print(verify(args.directory, args.public_key, args.fingerprint))
    else:
        print(deploy(args.snapshot, args.directory, args.public_key, args.fingerprint, args.receipt, args.github_assets))


if __name__ == '__main__': main()
