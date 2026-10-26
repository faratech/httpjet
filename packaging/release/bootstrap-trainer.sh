#!/usr/bin/env bash
# Build the exact synthetic-dictionary trainer natively, never install globally.
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo 'usage: bootstrap-trainer.sh NEW_TOOL_ROOT' >&2; exit 2
fi
trainer_root=$(realpath -m "$1")
trainer_version=1.5.7
trainer_url=https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
# Primary upstream checksum: same release's zstd-1.5.7.tar.gz.sha256 asset.
trainer_sha256=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3
[ ! -e "$trainer_root" ] || { echo 'trainer output must not already exist' >&2; exit 1; }
for trainer_command in curl make cc tar sha256sum install python3; do
  command -v "$trainer_command" >/dev/null || { echo "trainer needs $trainer_command" >&2; exit 1; }
done
case "$(uname -m)" in
  x86_64) trainer_cflags='-O2 -march=x86-64 -mtune=generic' ;;
  aarch64|arm64) trainer_cflags='-O2 -march=armv8-a -mtune=generic' ;;
  *) echo 'trainer must build natively on amd64 or arm64' >&2; exit 1 ;;
esac
trainer_jobs=${CARGO_BUILD_JOBS:-2}
[[ "$trainer_jobs" =~ ^[1-9][0-9]*$ ]] || { echo 'CARGO_BUILD_JOBS must be positive' >&2; exit 1; }
mkdir -m0700 -p "$trainer_root"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --retry 3 --connect-timeout 15 --max-time 180 "$trainer_url" -o "$trainer_root/source.tar.gz"
if ! printf '%s  %s\n' "$trainer_sha256" "$trainer_root/source.tar.gz" | sha256sum --check --status; then
  echo 'pinned zstd 1.5.7 source checksum mismatch; refusing extraction' >&2
  exit 1
fi
# A mismatched download is rejected before any extraction or compiler invocation.
tar --no-same-owner --no-same-permissions -xzf "$trainer_root/source.tar.gz" -C "$trainer_root"
make -C "$trainer_root/zstd-$trainer_version/programs" -j "$trainer_jobs" zstd \
  CFLAGS="$trainer_cflags" HAVE_ZLIB=0 HAVE_LZMA=0 HAVE_LZ4=0
install -d "$trainer_root/bin"
install -m0755 "$trainer_root/zstd-$trainer_version/programs/zstd" "$trainer_root/bin/zstd"
if ! "$trainer_root/bin/zstd" --version | grep -Eq 'v1\.5\.7([ ,]|$)'; then
  echo 'native dictionary trainer did not report the required zstd 1.5.7 version' >&2
  exit 1
fi
python3 - "$trainer_root/trainer.json" "$trainer_url" "$trainer_sha256" <<'PY'
import json,pathlib,sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({'version':'1.5.7','source_url':sys.argv[2],
    'source_sha256':sys.argv[3],'kind':'native source-built dictionary trainer'},sort_keys=True)+'\n')
PY
