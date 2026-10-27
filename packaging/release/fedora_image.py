#!/usr/bin/env python3
"""Fetch one checksum-locked Fedora cloud image through approved HTTPS locations."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

import release

CATALOG = 'https://fedoraproject.org/releases.json'
RETRY_STATUS = {404, 410, 500, 502, 503, 504}


class UnsafeRedirect(ValueError):
    pass


def https(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise UnsafeRedirect('Fedora image redirects must remain HTTPS without credentials')
    return parts


def public_location(url):
    parts = urllib.parse.urlsplit(url)
    return (parts.hostname or '') + parts.path


def locations(asset):
    parts = https(asset['url'])
    if (asset.get('origin') != CATALOG or asset.get('format') != 'qcow2'
        or parts.hostname not in ('download.fedoraproject.org', 'dl.fedoraproject.org')
        or parts.port not in (None, 443) or parts.query or parts.fragment
        or not re.fullmatch(r'/pub/fedora/linux/releases/[0-9]+/Cloud/(?:aarch64|x86_64)/images/[A-Za-z0-9_.+-]+\.qcow2', parts.path)
        or not re.fullmatch('[0-9a-f]{64}', asset.get('sha256', ''))):
        raise ValueError('Fedora fallback requires the exact official catalog URL and locked SHA256')
    direct = 'https://dl.fedoraproject.org' + parts.path
    archive = 'https://archives.fedoraproject.org/pub/archive/fedora/' + parts.path.removeprefix('/pub/fedora/')
    return list(dict.fromkeys((asset['url'], direct, archive)))


class Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, events):
        self.events = events

    def redirect_request(self, request, fp, code, message, headers, target):
        self.events.append({'status': code, 'from': public_location(request.full_url),
                            'to': public_location(target)})
        https(target)
        return super().redirect_request(request, fp, code, message, headers, target)


def observation(url, events, **fields):
    record = {'scope': 'locked-fedora-image-fetch', 'requested': public_location(url),
              'redirects': list(events), **fields}
    print(json.dumps(record, sort_keys=True), flush=True)
    return record


def probe(asset, opener=None):
    """Observe the locked URL's live redirect selection; HEAD proves no hash."""
    results = []
    for url in locations(asset):
        events = []
        client = opener if opener is not None else urllib.request.build_opener(Redirect(events))
        request = urllib.request.Request(url, headers={'User-Agent': release.USER_AGENT,
            'Cache-Control': 'no-cache'}, method='HEAD')
        try:
            with client.open(request, timeout=30) as response:
                https(response.url)
                results.append(observation(url, events, method='HEAD', status=response.status,
                    final=public_location(response.url), checksum_verified=False))
        except urllib.error.HTTPError as error:
            results.append(observation(url, events, method='HEAD', status=error.code,
                final=public_location(error.url), checksum_verified=False))
            error.close()
        except (urllib.error.URLError, TimeoutError, UnsafeRedirect) as error:
            results.append(observation(url, events, method='HEAD', error_type=type(error).__name__,
                checksum_verified=False))
    return results


def fetch(asset, path, opener=None):
    """Use the same filename/version/hash; never select a replacement release."""
    candidates = locations(asset)
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise ValueError('Fedora image destination must not already exist')
    path.parent.mkdir(parents=True, exist_ok=True)
    attempts = []
    last_error = None
    with tempfile.TemporaryDirectory(prefix='httpjet-fedora-', dir=path.parent) as temporary:
        pending = Path(temporary) / 'image.part'
        for url in candidates:
            events = []
            client = opener if opener is not None else urllib.request.build_opener(Redirect(events))
            request = urllib.request.Request(url, headers={'User-Agent': release.USER_AGENT,
                                                         'Cache-Control': 'no-cache'})
            try:
                with client.open(request, timeout=90) as response:
                    https(response.url)
                    if response.status != 200:
                        raise ValueError('Fedora image download did not return a complete HTTP 200')
                    digest = hashlib.sha256()
                    with pending.open('wb') as destination:
                        while block := response.read(1024 * 1024):
                            destination.write(block)
                            digest.update(block)
                if digest.hexdigest() != asset['sha256']:
                    raise ValueError('Fedora image differs from the locked SHA256')
                os.replace(pending, path)
                attempts.append(observation(url, events, status=200, final=public_location(response.url),
                                            sha256=asset['sha256'], checksum_verified=True))
                return {'sha256': asset['sha256'], 'attempts': attempts}
            except urllib.error.HTTPError as error:
                attempts.append(observation(url, events, status=error.code, final=public_location(error.url)))
                if error.code not in RETRY_STATUS:
                    error.close()
                    raise
                error.close()
                last_error = error
            except (urllib.error.URLError, TimeoutError, UnsafeRedirect) as error:
                attempts.append(observation(url, events, error_type=type(error).__name__))
                last_error = error
    raise RuntimeError('locked Fedora image unavailable at all approved HTTPS locations') from last_error
