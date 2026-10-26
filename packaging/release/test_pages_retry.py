#!/usr/bin/env python3
"""Late-promotion retry with real GPG/APT staging; no real OS is qualified."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import pages
import release
import test_universal_repository as fixtures
import universal


class SameVersionRetry(unittest.TestCase):
    def test_fresh_fetch_stage_and_projection_preserve_immutable_github_assets(self):
        # Reuse only the explicitly labelled non-executable fixture generator.
        # GPG, APT, snapshot/qualification checks and Pages retention run for real.
        class Fixture(fixtures.UniversalRepository): pass
        Fixture.setUpClass(); self.addCleanup(Fixture.doClassCleanups)
        case=Fixture('test_signed_schema2_snapshot_and_publication_order')
        case.setUp(); self.addCleanup(case.doCleanups)
        first=case.stage(); first_site=case.work/'first-pages'
        with mock.patch.object(pages,'precondition'):
            first_index=pages.project(first,first_site,case.key,case.fingerprint)
        rid=case.ident['release_id']
        def download(url,target):
            parsed=urllib.parse.urlsplit(url)
            self.assertEqual(parsed.scheme,'https'); self.assertEqual(parsed.netloc,'httpjet-packages.pages.dev')
            relative=parsed.path.lstrip('/')
            # Resolve the exact generated redirect into the immutable GitHub
            # asset fixture; public HTTPS redirect behavior has separate tests.
            origin=first if relative.startswith('releases/'+rid+'/') else first_site
            source=origin/relative
            if not source.is_file():raise urllib.error.HTTPError(url,404,'fixture missing',{},None)
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        def rpm_history(base,output,key,manifest):
            # Fixture RPMs are synthetic. Recover their immutable bytes while
            # the real APT history adapter and all release signatures run.
            target=output/'history/rpm';target.mkdir(parents=True)
            for path in (first/'rpm').glob('*/Packages/*.rpm'):shutil.copyfile(path,target/path.name)
        previous=case.work/'freshly-fetched'
        with mock.patch.object(release,'download',side_effect=download), \
             mock.patch.object(universal,'signed_rpm_history',side_effect=rpm_history):
            universal.fetch_current(release.REPO_URL,previous,case.key,case.fingerprint)
        old_pointer=release.sha(previous/'current-stable.json')
        self.assertEqual(old_pointer,first_index['stable_sha256'])
        retry=case.work/'retry-snapshot'
        universal.stage(case.directory,retry,case.key,case.fingerprint,
                        fixtures.ROOT/'packaging/installer/install.sh.in',previous=previous,
                        now=datetime.now(timezone.utc)+timedelta(seconds=2))
        with mock.patch.object(release,'download',side_effect=download):
            retry_index=pages.project(retry,case.work/'retry-pages',case.key,case.fingerprint,previous=previous)
        before={path.name:pages.descriptor(path) for path in (first/'releases'/rid).iterdir()}
        after={path.name:pages.descriptor(path) for path in (retry/'releases'/rid).iterdir()}
        self.assertEqual(before,after,'same-tag GitHub assets/signatures must remain exact')
        self.assertEqual(first_index['releases'],retry_index['releases'])
        self.assertNotEqual(first_index['stable_sha256'],retry_index['stable_sha256'])
        self.assertEqual(release.load(retry/'publication.json')['previous_stable_sha256'],old_pointer)
        self.assertEqual((first_site/'_redirects').read_bytes(),(case.work/'retry-pages/_redirects').read_bytes())
        self.assertNotEqual((first_site/pages.INDEX).read_bytes(),(case.work/'retry-pages'/pages.INDEX).read_bytes())


if __name__=='__main__':unittest.main()
