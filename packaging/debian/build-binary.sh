#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo"

key=packaging/debian/archive-keyring.asc
if [ ! -s "$key" ]; then
    echo "httpjet: supply the real public archive key at $key before building packages" >&2
    exit 1
fi
if [ "$(head -n 1 "$key")" != '-----BEGIN PGP PUBLIC KEY BLOCK-----' ] \
    || [ "$(tail -n 1 "$key")" != '-----END PGP PUBLIC KEY BLOCK-----' ]; then
    echo "httpjet: archive-keyring.asc must be an ASCII-armored public key, never private key material" >&2
    exit 1
fi
key_home=$(mktemp -d)
trap 'rm -rf "$key_home"' EXIT HUP INT TERM
if ! key_metadata=$(gpg --batch --homedir "$key_home" --show-keys --with-colons "$key" 2>/dev/null); then
    echo "httpjet: archive-keyring.asc is not a readable public archive key" >&2
    exit 1
fi
if ! printf '%s\n' "$key_metadata" | awk -F: '
        $1 == "pub" && $2 !~ /^[reid]$/ && $12 ~ /[sS]/ \
            && ($7 == "" || $7 == 0 || $7 > systime()) { count++ }
        $1 == "sec" { bad=1 }
        END { exit !(count > 0 && !bad) }
    '; then
    echo "httpjet: archive-keyring.asc must contain a valid, nonrevoked, unexpired public signing key" >&2
    exit 1
fi

version=$(python3 -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("Cargo.toml").read_text())["workspace"]["package"]["version"])')
package_version=$(dpkg-parsechangelog -S Version)
if [ "${package_version%-*}" != "$version" ]; then
    echo "httpjet: Debian upstream version must match Cargo version $version" >&2
    exit 1
fi

install -d debian/build
if [ "${HTTPJET_PACKAGE_TEST:-}" = 1 ]; then
    if [ -z "${HTTPJET_TEST_PREBUILT:-}" ] || [ ! -x "$HTTPJET_TEST_PREBUILT" ]; then
        echo "httpjet: packaging tests require an explicit executable HTTPJET_TEST_PREBUILT" >&2
        exit 1
    fi
    case "$HTTPJET_TEST_PREBUILT" in
        /*) ;;
        *) echo "httpjet: test binary must have an absolute path" >&2; exit 1 ;;
    esac
    install -m 0755 "$HTTPJET_TEST_PREBUILT" debian/build/httpjet
    exit 0
fi
if [ -n "${HTTPJET_PACKAGE_TEST:-}${HTTPJET_TEST_PREBUILT:-}" ]; then
    echo "httpjet: prebuilt binaries are permitted only for explicit isolated packaging tests" >&2
    exit 1
fi

package_arch=$(dpkg-architecture -qDEB_HOST_ARCH)
case "$package_arch" in amd64|arm64) ;; *) echo 'httpjet: unsupported architecture' >&2; exit 1 ;; esac
if [ -n "${HTTPJET_BUILD_SESSION:-}${HTTPJET_CARRIER_RECEIPT:-}" ]; then
    [ -n "${HTTPJET_BUILD_SESSION:-}" ] && [ -n "${HTTPJET_CARRIER_RECEIPT:-}" ] \
        || { echo 'httpjet: source-build session and receipt must be supplied together' >&2; exit 1; }
    python3 packaging/release/build-session.py consume "$HTTPJET_BUILD_SESSION" "$HTTPJET_CARRIER_RECEIPT" \
        "$repo" "$package_arch" "$package_version" debian/build/httpjet
else
    bash packaging/release/build-musl.sh "$package_arch" "$repo/debian/build/httpjet"
fi
