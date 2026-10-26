#!/usr/bin/env bash
# Source-build one native static payload, then verify each package carrier.
set -euo pipefail
[ "$#" -eq 4 ] || { echo 'usage: build.sh vX.Y.Z[-N] NEW_OUTPUT_DIR PUBLIC_KEY FINGERPRINT' >&2; exit 2; }
release_tag=$1
release_output=$(realpath -m "$2")
release_key=$(realpath "$3")
release_fingerprint=$4
release_root=$(git rev-parse --show-toplevel)
for release_hook in HTTPJET_PACKAGE_TEST HTTPJET_TEST_PREBUILT HTTPJET_BUILD_SESSION HTTPJET_CARRIER_RECEIPT; do
  [ -z "${!release_hook+x}" ] || { echo 'release refuses inherited carrier/test hooks' >&2; exit 1; }
done
release_id=$(dpkg-parsechangelog -l"$release_root/debian/changelog" -S Version)
release_version=${release_id%-*}
release_revision=${release_id##*-}
[[ "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$release_revision" =~ ^[1-9][0-9]*$ ]] || { echo 'expected X.Y.Z-N release identity' >&2; exit 1; }
release_expected_tag="v$release_id"
if [ "$release_revision" = 1 ]; then release_expected_tag="v$release_version"; fi
[ "$release_tag" = "$release_expected_tag" ] || { echo 'tag/release identity mismatch' >&2; exit 1; }
release_commit=$(git rev-parse "${release_tag}^{commit}")
[ "$(git rev-parse HEAD)" = "$release_commit" ] || { echo 'checkout differs from tag' >&2; exit 1; }
release_arch=$(dpkg --print-architecture)
case "$release_arch:$(uname -m)" in amd64:x86_64|arm64:aarch64) ;; *) echo 'native architecture required' >&2; exit 1;; esac
. /etc/os-release
[ "$ID:$VERSION_ID" = debian:12 ] || { echo 'Debian12 builder required' >&2; exit 1; }
[ "$(rustc --version | awk '{print $2}')" = 1.99.1 ] || { echo 'Rust1.99.1 required' >&2; exit 1; }
[ ! -e "$release_output" ] || { echo 'output already exists' >&2; exit 1; }
python3 - "$release_root" "$release_version" "$release_key" "$release_fingerprint" <<'PY'
import importlib.util,pathlib,sys,tomllib
root=pathlib.Path(sys.argv[1])
assert tomllib.loads((root/'Cargo.toml').read_text())['workspace']['package']['version']==sys.argv[2], 'tag/Cargo mismatch'
spec=importlib.util.spec_from_file_location('release',root/'packaging/release/release.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.validate_key(pathlib.Path(sys.argv[3]),sys.argv[4])
PY
release_work=$(mktemp -d)
trap 'rm -rf "$release_work"' EXIT
release_source="$release_work/httpjet-$release_id"
bash "$release_root/packaging/release/bootstrap-trainer.sh" "$release_work/trainer"
export PATH="$release_work/trainer/bin:$PATH"
bash "$release_root/scripts/export-public-source.sh" "$release_source" "$release_tag"
install -m0644 "$release_key" "$release_source/packaging/debian/archive-keyring.asc"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(bash "$release_root/packaging/release/source-date-epoch.sh" "$release_tag")
cd "$release_source"
cargo vendor --locked vendor/registry > "$release_work/vendor-config"
mkdir -p .cargo
cat >> .cargo/config.toml <<'EOF'

[source.crates-io]
replace-with = "vendored-release-sources"
[source.vendored-release-sources]
directory = "vendor/registry"
EOF
mkdir -m0755 "$release_output"
python3 scripts/check-dependency-licenses.py --write "$release_output/dependency-licenses.md"
cp LICENSE THIRD_PARTY_NOTICES.md "$release_output/"
release_session="$release_work/source-session"
python3 packaging/release/build-session.py session "$release_source" "$release_session" "$release_commit" "$release_tag" "$release_arch" "$release_id" "$SOURCE_DATE_EPOCH"
python3 packaging/release/build-session.py compile "$release_session"
python3 packaging/release/package-carriers.py "$release_source" "$release_session" "$release_output" "$release_arch" "$release_id"
bash packaging/release/build-probe.sh "$release_arch" "$release_output/io-uring-probe-$release_arch"
cp packaging/release/io-uring-probe.c "$release_output/"
python3 packaging/release/release.py elf "$release_session/httpjet" "$release_arch" --libc musl > "$release_work/elf.json"
make -f debian/rules clean
rm -rf target
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner --exclude='*/__pycache__' -C "$release_work" -cJf "$release_output/httpjet-$release_id-source.tar.xz" "httpjet-$release_id"
python3 - "$release_root" "$release_output" "$release_work" "$release_version" "$release_revision" "$release_arch" "$release_commit" "$release_fingerprint" "$SOURCE_DATE_EPOCH" "$release_tag" <<'PY'
import importlib.util,pathlib,sys
root,out,work=map(pathlib.Path,sys.argv[1:4]); version,revision,arch,commit,fpr,epoch,tag=sys.argv[4:]
spec=importlib.util.spec_from_file_location('release',root/'packaging/release/release.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
rid=version+'-'+revision; carriers=m.load(out/f'carriers-{arch}.json'); artifacts={}
for path in sorted(out.iterdir()):
    name=path.name
    if not path.is_file():continue
    artifact_arch,libc=arch,'musl'
    if name==carriers['package']:kind='deb'
    elif name==carriers['rpm_package']:kind='rpm'
    elif name==carriers['keyring_deb']:kind,artifact_arch,libc='keyring-deb','all','none'
    elif name==carriers['keyring_rpm']:kind,artifact_arch,libc='keyring-rpm','all','none'
    elif name==carriers['portable']:kind='portable'
    elif name.endswith('-source.tar.xz') or name=='io-uring-probe.c':kind,artifact_arch,libc='source','source','none'
    elif name.startswith('io-uring-probe-'):kind='qualifier'
    elif name.endswith('.buildinfo'):kind,libc='buildinfo','none'
    elif name.startswith('carriers-'):kind,libc='provenance','none'
    else:kind,artifact_arch,libc='license','all','none'
    artifacts[name]={'sha256':m.sha(path),'size':path.stat().st_size,'kind':kind,'architecture':artifact_arch,'libc':libc}
p={'schema':2,'version':version,'upstream_version':version,'revision':int(revision),'package_revision':int(revision),
 'release_id':rid,'debian_version':rid,'tag':tag,'commit':commit,'architecture':arch,'archive_fingerprint':fpr,
 'rustc_version':'1.99.1','source_date_epoch':int(epoch),'builder':'native Debian12/Rust1.99.1; static musl source payload; authenticated same-run carriers',
 'features':[],'compatibility_flags':['--no-multishot-accept'],'libc':'musl',
 'target':{'amd64':'x86_64-unknown-linux-musl','arm64':'aarch64-unknown-linux-musl'}[arch],
 'elf':m.load(work/'elf.json'),'dictionary_trainer':m.load(work/'trainer/trainer.json'),
 'source_tree_sha256':carriers['source_tree_sha256'],'binary_sha256':carriers['binary_sha256'],
 'binaries':{arch:{'artifact':carriers['portable'],'binary_sha256':carriers['binary_sha256'],'libc':'musl'}},
 'packages':{arch:carriers['package']},'rpm_packages':{arch:carriers['rpm_package']},
 'package':carriers['package'],'rpm_package':carriers['rpm_package'],'artifacts':artifacts}
m.write_json(out/f'provenance-{arch}.json',p)
PY
echo "native static release artifacts: $release_output"
