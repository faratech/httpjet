# Linux installer release operations (schema 2)

This pipeline builds and qualifies one shared static payload per architecture,
then distributes it through DEB, RPM, a portable tarball and OCI. It does not
provision signing credentials, public hosting, website routes, GitHub environment
protection, or an already-qualified stable release.

## Identity and build contract

The canonical release ID is `X.Y.Z-N`. Revision 1 uses tag `vX.Y.Z`; packaging
revisions use `vX.Y.Z-N`. Cargo keeps upstream version `X.Y.Z`, while package
metadata, manifests, URLs and versioned installations use the complete release
ID. Increment the packaging revision instead of replacing published bytes.

Native amd64 and arm64 builders use pinned Rust/C toolchains and baseline CPU
flags. Source export, locked dependencies and the pinned source-built zstd trainer
are bound to the build session. Client machines need no Rust toolchain. Static
musl ELF validation rejects an interpreter, DT_NEEDED libraries, GLIBC references,
wrong architecture and newer declared CPU requirements. No host PGO is reused.

Carrier packaging consumes the source-bound payload without rewriting its ELF.
DEB, RPM, portable tar and OCI inspections must recover the same binary SHA256.
Nix/Guix definitions also copy the fixed-hash payload without ELF fixups. Complete
corresponding source, dependency/license notices and per-architecture provenance
accompany the software. RPM headers are signed and verified before the final
manifest records their signed hashes; payload identity must remain unchanged.

## Publication boundary

Configure protected GitHub environments `httpjet-candidate-signing` and
`httpjet-stable`, with reviewers and restricted deployment tags/branches. Each
signing environment supplies `HTTPJET_ARCHIVE_PRIVATE_KEY` for batch GPG in a
private temporary home. Private keys must never enter checkout, artifacts or the
bucket. Repository variables provide:

- `HTTPJET_ARCHIVE_PUBLIC_KEY`: the approved ASCII-armored public key.
- `HTTPJET_ARCHIVE_FINGERPRINT`: its complete uppercase primary fingerprint.
- `HTTPJET_FIRST_RELEASE=true`: initial bootstrap only, permitting an actual 404
  for `releases/stable.json` to select labelled lifecycle fixtures. Other failures
  still abort. Remove it after the first publication.
- `HTTPJET_S3_ENDPOINT`, `HTTPJET_S3_BUCKET`, `HTTPJET_S3_REGION`: an HTTPS,
  path-style S3-compatible endpoint without an endpoint path. Region defaults to
  `auto` when unset.

The stable environment supplies `HTTPJET_S3_ACCESS_KEY_ID` and
`HTTPJET_S3_SECRET_ACCESS_KEY`, mapped to AWS credential variables by the workflow.
The endpoint must provide strongly consistent atomic conditional PUT.
Permissions cover reads and conditional writes to `apt/`, `rpm/`, `releases/`
and the persistent publication record under `_httpjet/`. DELETE is not required.
Preserve object bytes/cache headers and retain old immutable objects indefinitely.

The site layout is:

```
apt/                                  # signed APT metadata, pool, bootstrap/key
rpm/x86_64/                           # signed RPM-MD repository
rpm/aarch64/
releases/X.Y.Z-N/                      # manifest(.asc), software, proof objects
releases/stable.json                   # authenticated current selector
releases/stable.json.asc
```

Serve it as `https://packages.httpjet.net/`. The promotion workflow verifies the
package-host bytes, then publishes the rendered installer and qualified artifacts
as GitHub Release assets. It verifies every public asset against the staged bytes,
including `releases/latest/download/install.sh`. An operator may additionally
deploy `website-redirects` to provide `https://httpjet.net/install.sh`; that
website alias is optional and is not deployed by the release workflow.

## Candidate and qualification

1. Export the reviewed public source, retain the existing public-only CI files,
   and create the canonical tag on the resulting public commit. Record the mapping
   to the reviewed internal source separately. The native jobs source-build both
   static payloads and carriers from that public tag. OCI derivation uses an
   authenticated architecture-specific base and the same ELF. Test/prebuilt
   shortcuts cannot authorize a release.
2. Resolve and hash-lock image inputs against the versioned
   `support-matrix.json`. Prepared OS archives remain workflow artifacts;
   published locks/evidence describe their hashes. Public-repository workflow
   artifacts may be accessible to others, so do not place credentials in them.
   The OS archives are qualification inputs, not software release downloads.
3. Approve candidate signing. The job signs RPMs, builds the schema-2 manifest and
   signs a local unpublishable test site. It receives no hosting credentials.
   Previous stable inputs are authenticated through the signed selector/manifests.
   First-release native lower-version and portable forward-version fixtures are
   explicit same-ELF packaging tests, not evidence about an older runtime.
4. Run every required support row on its native architecture. The current policy
   has 25 rows across mutable package/portable systems, declarative NixOS/Guix,
   immutable CoreOS and OCI. Missing executors, failed boots, unavailable probes
   and omitted checks fail closed; they never become passed or skipped receipts.
   Mutable guests exercise real version transitions, state opt-outs, config/data,
   source denial and lifecycle. Host probes/protocol clients and reboot checks
   retain their actual scope, UID, flags, hashes and logs. Declarative systems use
   native generations; CoreOS uses its OCI/systemd route, without an OS rebase.
5. Assemble qualification only after all required rows and attachments verify.
   The qualification run attests the final signed software and source assets.
   Dispatch promotion **from the exact public release tag** with that successful
   qualification run ID, review its evidence, then approve the stable environment.
   Promotion verifies the run/tag/commit, renders the bootstrap/helper from the
   qualified commit, and attests those newly generated files separately. The GitHub
   release job verifies both workflows' attestations before publishing assets.
   No stable pointer advances from a candidate or incomplete matrix.

For a direct row invocation, see `matrix_vm.py --help`. It consumes authenticated
artifacts, the candidate site, approved image locks and previous/fixture inputs.
Run qualification only in disposable environments and retain console/guest logs
on failures. These commands install tools and services inside those guests.

## Commit, locking and refresh

The universal manifest and qualification have detached archive signatures. The
signed stable selector binds the release ID, manifest SHA256/size, qualification,
issued time and expiry. Its maximum lifetime is 30 days. APT has matching signed
Date/Valid-Until metadata and by-hash indexes; RPM requires signed packages and
signed repomd metadata. Default selection refuses a silent version downgrade.

Immutable software/proof/index objects upload first. Native commit metadata and
the signed stable selector follow with conditional replacement. All writers must
use the bucket-scoped conditional `_httpjet/publication.lock`; GitHub's shared
publication concurrency group also serializes the normal promotion/refresh jobs.
The weekly refresh authenticates the current selector, reuses that exact release,
qualification and approved bootstrap, and refreshes expiry without choosing a
new tag or package. A scheduled refresh also waits for the `httpjet-stable`
environment's required reviewer; approve it before metadata expires. Expired
current metadata stops the job for investigation.

The persistent lock has `held` and `released` states. A missing record is acquired
with `If-None-Match: *`; a released record is acquired with `If-Match` against its
exact ETag. Successful completion writes `released` through conditional PUT using
the owned held-record ETag. No DELETE is required. See the
[R2 S3 API conditional-write contract](https://developers.cloudflare.com/r2/api/s3/api/)
when provisioning an endpoint.

Failures retain `held`; no timeout-based takeover is allowed. Inspect the record's
owner/token/run identity and current authenticated metadata, prove that publisher
has stopped, and reconcile partial metadata from its known signed snapshot. Only
then write the reviewed record with state `released`, using exact-ETag conditional
PUT. With authorized credentials already configured:

```sh
# HTTPJET_REVIEWED_LOCK_ETAG is the exact ETag reviewed by the operator.
PYTHONPATH=packaging/release python3 - <<'UNLOCK'
import json, os, tempfile
from pathlib import Path
from publish import S3
store = S3()
key = '_httpjet/publication.lock'
expected = os.environ['HTTPJET_REVIEWED_LOCK_ETAG']
with store.request('GET', key) as response:
    if response.headers['ETag'] != expected:
        raise SystemExit('Lock changed since review; investigate again')
    record = json.load(response)
if record.get('state') != 'held':
    raise SystemExit('Expected the reviewed held record')
record['state'] = 'released'
with tempfile.TemporaryDirectory(prefix='httpjet-lock-recovery-') as temporary:
    document = Path(temporary) / 'released.json'
    document.write_text(json.dumps(record, sort_keys=True) + '\n')
    store.put(key, document, condition={'if-match': expected})
UNLOCK
```

Do not use unconditional writes, deletion, automatic timeout recovery or a
publisher that bypasses the record. Verify conditional-write support before
allowing publication.

## Current evidence and limits

Local checks have exercised the amd64 static payload and common-carrier byte
identity, real signed portable lifecycle on Alpine/BusyBox, real generic Debian
systemd lifecycle including notification/reboot/state opt-outs, protocol clients,
and a non-root read-only OCI case. A raw Alpine/OpenRC image has booted with its
actual PID 1 and non-root SSH; that boot proof alone is not installer lifecycle
qualification. Nix expressions/package bytes have been checked separately.

Those results do not establish all 25 rows, ARM64 runtime, a complete NixOS/Guix
generation lifecycle or CoreOS qualification. Definitions, source inspection,
component probes and fixture runs are not substitutes. Inspect the public
qualification and promotion workflow runs for the actual release status.
