#!/bin/sh
set -eu
if [ "$1" -eq 1 ]; then
    for table in /proc/net/tcp /proc/net/tcp6; do
        [ ! -r "$table" ] || ! awk '$2 ~ /:(0050|01BB)$/ && $4 == "0A" { found=1 } END { exit !found }' "$table" \
            || { echo 'httpjet: TCP port 80 or 443 is occupied; stop the existing server explicitly' >&2; exit 1; }
    done
    for candidate in /usr/bin/httpjet /usr/local/bin/httpjet /usr/local/sbin/httpjet \
        /usr/local/httpjet/bin/httpjet /etc/httpjet/conf/httpd_config.xml \
        /etc/systemd/system/httpjet.service /etc/systemd/system/httpjet.service.d \
        /usr/lib/systemd/system/httpjet.service; do
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            echo "httpjet: refusing unmanaged installation at $candidate" >&2
            exit 1
        fi
    done
fi
account=$(getent passwd httpjet || true)
if [ -z "$account" ]; then
    if ! getent group httpjet >/dev/null; then groupadd --system httpjet; fi
    shell=$(command -v nologin)
    useradd --system --gid httpjet --home-dir /var/lib/httpjet --no-create-home --shell "$shell" httpjet
else
    IFS=: read -r name password uid gid comment home shell <<EOF
$account
EOF
    group_gid=$(getent group httpjet | cut -d: -f3)
    if [ "$uid" -eq 0 ] || [ "$gid" != "$group_gid" ] || [ "$home" != /var/lib/httpjet ] \
        || { [ "$shell" != /sbin/nologin ] && [ "$shell" != /usr/sbin/nologin ]; }; then
        echo 'httpjet: existing account is not the dedicated httpjet service account' >&2
        exit 1
    fi
fi
