#!/usr/bin/env python3
"""Check private R2 CAS credentials using one disposable random object."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import urllib.error
import urllib.request

import pages
import release
from publish import S3
from release import write_json

PREFIX = '_httpjet/credential-probes/'
# Retired delivery hosts are privacy checks, never installer download origins.
PUBLIC_HOSTS = {'retired-custom': 'https://packages.httpjet.net',
                'disabled-r2dev': 'https://pub-22c33cd3d4ff48beb44bc3ce0abfcb87.r2.dev'}


def etag(response):
    value = response.headers.get('ETag')
    if not value or value.startswith('W/') or '\r' in value or '\n' in value:
        raise ValueError('private storage must return a strong conditional-write ETag')
    return value


def read_object(store, key):
    with store.request('GET', key) as response:
        data = response.read(4097)
        if len(data) > 4096:
            raise ValueError('private probe object exceeded its small fixture size')
        return data, etag(response)


def put_object(store, key, data, condition):
    headers = {**condition, 'content-type': 'application/json', 'cache-control': 'no-store',
               'x-amz-meta-sha256': hashlib.sha256(data).hexdigest()}
    with store.request('PUT', key, data, headers) as response:
        return etag(response)


def rejected_put(store, key, data, condition):
    try:
        put_object(store, key, data, condition)
    except urllib.error.HTTPError as error:
        try:
            if error.code != 412:
                raise
        finally:
            error.close()
    else:
        raise ValueError('private storage ignored a conditional PUT precondition')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *arguments, **options):
        return None


def public_denial(key, opener=None):
    opener = opener or urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    result = {}
    for name, host in PUBLIC_HOSTS.items():
        request = urllib.request.Request(host + '/' + key,
            headers={'Cache-Control': 'no-store', 'User-Agent': release.USER_AGENT}, method='GET')
        try:
            with opener.open(request, timeout=30):
                raise ValueError('private probe object is publicly accessible through ' + name)
        except urllib.error.HTTPError as error:
            try:
                if error.code not in (401, 403, 404):
                    raise
                result[name] = error.code
            finally:
                error.close()
    return result


def remove_object(store, key):
    with store.request('DELETE', key):
        pass
    try:
        with store.request('GET', key):
            raise ValueError('private probe object remained readable after cleanup')
    except urllib.error.HTTPError as error:
        try:
            if error.code != 404:
                raise
        finally:
            error.close()


def probe(store=None, public_opener=None):
    store = store if store is not None else S3()
    nonce = secrets.token_hex(32)
    key = PREFIX + nonce + '.json'
    initial = json.dumps({'scope': 'temporary-credential-probe', 'nonce': nonce, 'phase': 1}).encode()
    updated = json.dumps({'scope': 'temporary-credential-probe', 'nonce': nonce, 'phase': 2}).encode()
    rejected = json.dumps({'scope': 'temporary-credential-probe', 'nonce': nonce, 'phase': 'must-reject'}).encode()
    checks = {}
    # A lost response may have created our unique object. A definite initial
    # 4xx does not authorize deleting a preexisting name collision.
    cleanup = True
    try:
        try:
            first = put_object(store, key, initial, {'if-none-match': '*'})
        except urllib.error.HTTPError as error:
            if 400 <= error.code < 500:
                cleanup = False
            error.close()
            raise
        if read_object(store, key) != (initial, first):
            raise ValueError('private create readback changed')
        checks['create-if-absent'] = 'passed'
        rejected_put(store, key, rejected, {'if-none-match': '*'})
        if read_object(store, key) != (initial, first):
            raise ValueError('rejected duplicate create changed the private object')
        checks['duplicate-create-rejected'] = 'passed'
        second = put_object(store, key, updated, {'if-match': first})
        if second == first or read_object(store, key) != (updated, second):
            raise ValueError('private compare-and-swap did not advance the observed object')
        checks['replace-if-matches'] = 'passed'
        denied = public_denial(key, public_opener)
        checks['known-object-public-access-denied'] = 'passed'
        rejected_put(store, key, rejected, {'if-match': first})
        if read_object(store, key) != (updated, second):
            raise ValueError('rejected stale ETag changed the private object')
        checks['stale-etag-rejected'] = 'passed'
    finally:
        if cleanup:
            try:
                remove_object(store, key)
                checks['delete-and-authenticated-404'] = 'passed'
            except Exception as error:
                if isinstance(error, urllib.error.HTTPError):
                    error.close()
                raise RuntimeError('private probe cleanup failed for ' + key) from error
    return {'schema': 1, 'status': 'passed', 'scope': 'random-private-object-only',
            'object_key': key, 'object_deleted': True, 'publication_lock_touched': False,
            'checks': checks, 'public_access': denied}


def pages_readonly(opener=None):
    opener = opener or urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    for method in ('GET', 'HEAD'):
        request = urllib.request.Request(pages.ORIGIN + '/',
            headers={'User-Agent': release.USER_AGENT}, method=method)
        with opener.open(request, timeout=30) as response:
            if (response.status != 200 or response.url != pages.ORIGIN + '/'
                or 'no-store' not in response.headers.get('Cache-Control', '')
                or response.read(4097) != (pages.BOOTSTRAP.encode() if method == 'GET' else b'')):
                raise ValueError('Pages bootstrap is not the expected uncached HTTPS object')
    missing = '/releases/private-probe-missing-' + secrets.token_hex(16) + '.json'
    for path in ('/releases/stable.json', missing):
        for method in ('GET', 'HEAD'):
            url = pages.ORIGIN + path
            try:
                request = urllib.request.Request(url, headers={'User-Agent': release.USER_AGENT}, method=method)
                with opener.open(request, timeout=30):
                    raise ValueError('Pages bootstrap missing object did not return 404')
            except urllib.error.HTTPError as error:
                try:
                    if error.code != 404 or error.url != url:
                        raise
                finally:
                    error.close()
    return {'schema': 1, 'status': 'passed', 'scope': 'empty-pages-bootstrap-only',
            'origin': pages.ORIGIN, 'methods': ['GET', 'HEAD'], 'missing_status': 404,
            'index_sha256': hashlib.sha256(pages.BOOTSTRAP.encode()).hexdigest(), 'package_release_live': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--pages-only', action='store_true')
    args = parser.parse_args()
    write_json(args.receipt, pages_readonly() if args.pages_only else probe())
    print('Origin checks passed; publication lock untouched.')


if __name__ == '__main__':
    main()
