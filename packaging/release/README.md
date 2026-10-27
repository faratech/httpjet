# Linux installer releases

The release flow is **build → sign → publish**. A full distribution lifecycle
matrix is not a release requirement and does not run automatically. Build-only
releases state that full matrix qualification was not completed; they do not
manufacture passed receipts or claim full qualification.

## Build and publish

1. Export the reviewed public source and create its canonical release tag on
   public `main`. Release IDs use `X.Y.Z-N`: revision 1 uses tag `vX.Y.Z`, later
   packaging revisions use `vX.Y.Z-N`. Increment the revision to change published
   software or installer bytes.
2. `installer-release.yml` builds native amd64 and arm64 static musl payloads,
   packages DEB/RPM/portable archives and OCI carriers, and signs the candidate
   in `httpjet-candidate-signing`. The payload is source-bound and each carrier
   contains the same architecture-specific ELF. No client Rust toolchain or PGO
   profile is required. Linux io_uring is required.
3. The successful candidate job uploads `signed-candidate`, containing software,
   a signed native-repository snapshot, its public key, and authenticated prior
   history when present. It creates no lifecycle fixtures. Prepared OS inputs
   stay outside public software downloads.
4. `installer-publish-now.yml` publishes after the build workflow completes, or
   accepts a manual `candidate_run_id`. It checks the exact public tag/commit and
   successful native/signing jobs, then authenticates the archive signatures and
   artifact hashes. The protected `httpjet-stable` job publishes the immutable
   GitHub assets with latest disabled, deploys the complete Pages snapshot under
   the publisher lease, then marks the GitHub release latest.

Use the signed candidate already produced by a completed signing job when an
older workflow's optional matrix was cancelled. Its overall run does not need a
successful matrix. Do not upload the Actions artifact directory indiscriminately:
old artifacts may contain private OS inputs or intentionally labelled test
fixtures. `publish_build_only.py` selects only authenticated software and emits
an explicit `publication-status.json` and `RELEASE-NOTES.txt`.

The existing `installer-publish.yml` qualified-release path is retained for its
older artifact format; it is not the normal build-only release path.

## Signatures, files and hosting

The schema-2 manifest binds package/archive sizes, SHA256 hashes, source commit,
archive fingerprint and native build provenance. RPM headers are signed before
manifest creation. The manifest, stable selector, APT metadata and RPM repository
metadata are authenticated with the archive key. Static ELF checks reject a
dynamic interpreter, DT_NEEDED libraries, GLIBC references and wrong architecture.

Public package hosting is `https://httpjet-packages.pages.dev/`:

```
apt/install.sh                         rendered bootstrap and embedded public key
apt/dists/stable/                      signed APT metadata and by-hash indexes
apt/pool/                              native Debian packages
rpm/x86_64/ and rpm/aarch64/           signed RPM packages and RPM-MD metadata
releases/stable.json(.asc)             signed current selector
releases/X.Y.Z-N/                      redirects to immutable GitHub release assets
pages-index.json(.asc)                 signed native history and asset hash catalog
```

Source archives, OCI images and other large assets remain on GitHub Releases.
The signed Pages index preserves old native packages and release redirects and
binds the build-only publication notice to its release, manifest and original
source run. Build-only pointers retain `qualification_sha256: "unqualified"`.
Pages projections enforce its 25 MiB per-file, 20,000-file and 100 dynamic-redirect
limits. The optional `https://httpjet.net/install.sh` website redirect is separate
from package publication.

## Metadata refresh

`installer-refresh.yml` runs weekly on Monday at 04:13 UTC and supports manual
execution. It authenticates the current selector, manifest, packages and retained
history. Explicit `--universal --allow-unqualified` fetching additionally binds
the build-only status and release notes through the signed Pages index; default
fetching continues to require qualification.

Refresh keeps the exact release ID, software, manifest signatures, approved
installer and original source-run identity. It renews the signed selector and
APT/RPM metadata, with a maximum selector/APT lifetime of 30 days, and deploys a
complete replacement Pages snapshot under the same publication lease. It does not
build software, run a distro matrix, select a newer release or rewrite immutable
GitHub assets. Qualified older publications remain supported. Expired or altered
current metadata aborts refresh. Approve a protected scheduled job before its
current metadata expires.

## Credentials and publication lease

Configure protected `httpjet-candidate-signing` and `httpjet-stable` environments.
Both signing jobs use `HTTPJET_ARCHIVE_PRIVATE_KEY` only in an ephemeral private
GPG home. The approved public key and full primary fingerprint are repository
variables `HTTPJET_ARCHIVE_PUBLIC_KEY` and `HTTPJET_ARCHIVE_FINGERPRINT`. Never put
private keys in the checkout or artifacts.

The stable environment also needs `CLOUDFLARE_API_TOKEN` with Pages Write access,
`CLOUDFLARE_ACCOUNT_ID`, and private lease credentials
`HTTPJET_S3_ACCESS_KEY_ID` / `HTTPJET_S3_SECRET_ACCESS_KEY`. Repository variables
`HTTPJET_S3_ENDPOINT`, `HTTPJET_S3_BUCKET` and `HTTPJET_S3_REGION` identify the
HTTPS S3-compatible lease store. Wrangler is pinned by the release tooling.
Public package bytes are served by Pages and GitHub, not by this private bucket.
These workflows do not provision credentials, environment reviewers, DNS, website
routes or hosting projects.

All publishers share `_httpjet/publication.lock` and the Actions concurrency group
`httpjet-apt-stable`. The private endpoint must support strongly consistent
conditional PUT. A missing lock is acquired with `If-None-Match: *`; a released
record is acquired using its exact ETag and `If-Match`. Completion conditionally
writes the owned record as `released`. No DELETE or automatic timeout takeover is
used; see the [R2 conditional-write contract](https://developers.cloudflare.com/r2/api/s3/api/).

A failed publisher retains a held record. Before recovery, inspect its owner/run
and the authenticated public metadata, prove the publisher has stopped, and
reconcile its partial publication. Only then conditionally write the reviewed
record as `released` using the exact reviewed ETag. Never overwrite a changed
record or replace immutable release assets to force a retry.
