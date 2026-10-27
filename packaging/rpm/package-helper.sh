#!/bin/sh
# Verified RPM scriptlets only. Transaction state is outside app-owned storage.
set -eu
transaction_dir=/run/httpjet-package
transaction_file=$transaction_dir/pending
require_private_transaction_dir() {
    if [ ! -e "$transaction_dir" ] && [ ! -L "$transaction_dir" ]; then mkdir -m0700 "$transaction_dir"; fi
    [ ! -L "$transaction_dir" ] && [ -d "$transaction_dir" ] \
        && [ "$(stat -c '%u:%a' "$transaction_dir")" = 0:700 ] \
        || { echo 'httpjet: unsafe package transaction directory' >&2; exit 1; }
}
case "$1" in
    configure)
        count=$2
        release_id=$3
        require_private_transaction_dir
        mode=upgrade
        if [ "$count" -eq 1 ]; then
            mode=fresh
            if [ ! -e /var/www/httpjet ] && [ ! -L /var/www/httpjet ]; then
                install -d -m0755 /var/www
                if mkdir -m0755 /var/www/httpjet; then
                    install -m0644 /usr/share/httpjet/welcome/index.html /var/www/httpjet/index.html
                fi
            fi
        fi
        /usr/libexec/httpjet/setup-tls '' httpjet "$mode"
        temporary=$(mktemp "$transaction_dir/pending.XXXXXX")
        printf '%s %s\n' "$release_id" "$mode" > "$temporary"
        chmod 0600 "$temporary"
        mv -f "$temporary" "$transaction_file"
        ;;
    commit)
        release_id=$2
        require_private_transaction_dir
        [ -f "$transaction_file" ] && [ ! -L "$transaction_file" ] \
            || { echo 'httpjet: missing package transaction state' >&2; exit 1; }
        read -r recorded_release mode < "$transaction_file"
        [ "$recorded_release" = "$release_id" ] \
            || { echo 'httpjet: package transaction identity mismatch' >&2; exit 1; }
        case "$mode" in fresh|upgrade) ;; *) exit 1 ;; esac
        # Check as the serving account before manager reload or any restart.
        if ! env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin runuser -u httpjet -- \
            /usr/bin/httpjet --root /etc/httpjet check --strict; then
            rm -f "$transaction_file"
            echo 'httpjet: candidate configuration failed; existing process was left running' >&2
            exit 1
        fi
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload
            if [ "$mode" = fresh ]; then
                systemctl enable httpjet.service
                systemctl start httpjet.service
            else
                enabled=$(systemctl is-enabled httpjet.service 2>/dev/null || true)
                case "$enabled" in masked|masked-runtime) ;; *) systemctl try-restart httpjet.service ;; esac
            fi
        fi
        rm -f "$transaction_file"
        rmdir "$transaction_dir" 2>/dev/null || true
        ;;
    *) echo 'httpjet: unknown package action' >&2; exit 2 ;;
esac
