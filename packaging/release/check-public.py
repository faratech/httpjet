#!/usr/bin/env python3
"""Compare publicly served package metadata with a qualified snapshot."""
import argparse
import hashlib
from pathlib import Path
import urllib.request
from release import sha, load, REPO_URL

ORIGIN = REPO_URL.removesuffix('/apt')


def objects(snapshot, website_redirect=True):
    site = (snapshot / 'apt').exists()
    installer = snapshot / ('apt/install.sh' if site else 'install.sh')
    result = [
        (ORIGIN + '/apt/dists/stable/InRelease',
         snapshot / ('apt/dists/stable/InRelease' if site else 'dists/stable/InRelease')),
        (ORIGIN + '/apt/install.sh', installer),
    ]
    if website_redirect:
        result.append(('https://httpjet.net/install.sh', installer))
    if site:
        for name in ('releases/stable.json', 'releases/stable.json.asc',
                     'rpm/x86_64/repodata/repomd.xml', 'rpm/x86_64/repodata/repomd.xml.asc',
                     'rpm/aarch64/repodata/repomd.xml', 'rpm/aarch64/repodata/repomd.xml.asc'):
            result.append((ORIGIN + '/' + name, snapshot / name))
        release_id = load(snapshot / 'publication.json')['release_id']
        for name in ('manifest.json', 'manifest.json.asc', 'qualification.json', 'qualification.json.asc'):
            relative = f'releases/{release_id}/{name}'
            result.append((ORIGIN + '/' + relative, snapshot / relative))
    return result


def verify(snapshot, website_redirect=True):
    for remote, local in objects(snapshot, website_redirect):
        request = urllib.request.Request(remote, headers={'Cache-Control': 'no-cache'})
        with urllib.request.urlopen(request, timeout=30) as response:
            if not response.url.startswith('https://'):
                raise ValueError('public download left HTTPS')
            actual = hashlib.file_digest(response, 'sha256').hexdigest()
        if actual != sha(local):
            raise ValueError('public bytes differ from staged release: ' + remote)
        print('verified public ' + remote)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--without-website-redirect', action='store_true',
                        help='verify package-host objects without requiring the optional website redirect')
    args = parser.parse_args()
    verify(args.snapshot, not args.without_website_redirect)


if __name__ == '__main__':
    main()
