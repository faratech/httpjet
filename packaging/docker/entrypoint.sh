#!/bin/sh
set -eu
umask 077
tls=/var/lib/httpjet/tls
[ ! -L "$tls" ] || { echo 'httpjet: refusing symlink TLS directory' >&2; exit 1; }
mkdir -p "$tls"
key=$tls/default.key
cert=$tls/default.crt
if [ -e "$key" ] || [ -L "$key" ] || [ -e "$cert" ] || [ -L "$cert" ]; then
    [ -f "$key" ] && [ ! -L "$key" ] && [ -f "$cert" ] && [ ! -L "$cert" ] \
        || { echo 'httpjet: incomplete or unsafe TLS pair; restore it explicitly' >&2; exit 1; }
else
    temporary=$(mktemp -d "$tls/.new.XXXXXX")
    trap 'rm -rf "$temporary"' EXIT HUP INT TERM
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
        -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1' \
        -addext 'basicConstraints=critical,CA:FALSE' \
        -keyout "$temporary/default.key" -out "$temporary/default.crt" 2>/dev/null
    chmod 0600 "$temporary/default.key"
    chmod 0644 "$temporary/default.crt"
    mv "$temporary/default.key" "$key"
    mv "$temporary/default.crt" "$cert"
    rmdir "$temporary"
    trap - EXIT HUP INT TERM
    echo 'httpjet: generated a self-signed HTTPS certificate; browsers will warn until you configure a trusted certificate.'
fi
exec /usr/bin/httpjet "$@"
