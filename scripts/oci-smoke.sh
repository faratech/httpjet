#!/usr/bin/env bash
# Build and exercise the hardened OCI example without privileged mode,
# added capabilities, or an unconfined seccomp profile.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE="${HTTPJET_OCI_IMAGE:-httpjet:smoke}"
RUN_ID="${GITHUB_RUN_ID:-$$}-${RANDOM}"
NAME="httpjet-oci-smoke-${RUN_ID}"
DATA_VOLUME="${NAME}-data"
LOG_VOLUME="${NAME}-logs"
CERT_DIR="$(mktemp -d)"

cleanup() {
    "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
    "$ENGINE" volume rm "$DATA_VOLUME" "$LOG_VOLUME" >/dev/null 2>&1 || true
    rm -rf "$CERT_DIR"
}
trap cleanup EXIT

command -v "$ENGINE" >/dev/null || {
    echo "container engine not found: $ENGINE" >&2
    exit 1
}
command -v openssl >/dev/null || {
    echo "openssl is required for the ephemeral smoke certificate" >&2
    exit 1
}
python3 -c 'import aioquic' 2>/dev/null || {
    echo "Python aioquic is required for the HTTP/3 smoke request" >&2
    exit 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=example.test \
    -addext subjectAltName=DNS:example.test \
    -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt" >/dev/null 2>&1
chown 10001:10001 "$CERT_DIR/tls.key" "$CERT_DIR/tls.crt"
chown 10001:10001 "$CERT_DIR"
chmod 0750 "$CERT_DIR"
chmod 0400 "$CERT_DIR/tls.key"
chmod 0444 "$CERT_DIR/tls.crt"

"$ENGINE" build --file "$ROOT/packaging/oci/Containerfile" --tag "$IMAGE" "$ROOT"
"$ENGINE" volume create "$DATA_VOLUME" >/dev/null
"$ENGINE" volume create "$LOG_VOLUME" >/dev/null

"$ENGINE" run --detach --name "$NAME" \
    --user 10001:10001 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --security-opt "seccomp=$ROOT/packaging/oci/seccomp-httpjet.json" \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
    --mount "type=bind,src=$CERT_DIR,dst=/run/httpjet-certs,readonly" \
    --mount "type=volume,src=$DATA_VOLUME,dst=/var/lib/httpjet" \
    --mount "type=volume,src=$LOG_VOLUME,dst=/etc/httpjet/litespeed/logs" \
    --publish 127.0.0.1::8080/tcp \
    --publish 127.0.0.1::8443/tcp \
    --publish 127.0.0.1::8443/udp \
    "$IMAGE" >/dev/null

for _ in $(seq 1 40); do
    status="$("$ENGINE" inspect --format '{{.State.Health.Status}}' "$NAME")"
    case "$status" in
        healthy) break ;;
        unhealthy)
            "$ENGINE" logs "$NAME" >&2
            echo "container became unhealthy" >&2
            exit 1
            ;;
    esac
    sleep 1
done
[ "${status:-}" = healthy ] || {
    "$ENGINE" logs "$NAME" >&2
    echo "container did not become ready" >&2
    exit 1
}

[ "$("$ENGINE" inspect --format '{{.HostConfig.Privileged}}' "$NAME")" = false ]
[ "$("$ENGINE" inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$NAME")" = true ]
[ "$("$ENGINE" inspect --format '{{.Config.User}}' "$NAME")" = 10001:10001 ]
[ "$("$ENGINE" exec "$NAME" id -u)" = 10001 ]
[ "$("$ENGINE" inspect --format '{{json .HostConfig.CapAdd}}' "$NAME")" = null ]
[ "$("$ENGINE" inspect --format '{{json .HostConfig.CapDrop}}' "$NAME")" = '["ALL"]' ]
SECURITY_OPT="$("$ENGINE" inspect --format '{{json .HostConfig.SecurityOpt}}' "$NAME")"
grep -q 'no-new-privileges' <<<"$SECURITY_OPT"
grep -q 'seccomp=' <<<"$SECURITY_OPT"
! grep -q 'unconfined' <<<"$SECURITY_OPT"

HTTP_PORT="$("$ENGINE" port "$NAME" 8080/tcp | sed -n '1s/.*://p')"
HTTPS_PORT="$("$ENGINE" port "$NAME" 8443/tcp | sed -n '1s/.*://p')"
UDP_MAPPING="$("$ENGINE" port "$NAME" 8443/udp)"
H3_PORT="$(sed -n '1s/.*://p' <<<"$UDP_MAPPING")"
[ -n "$HTTP_PORT" ] && [ -n "$HTTPS_PORT" ] && [ -n "$UDP_MAPPING" ]

body="$(curl --noproxy '*' --fail --silent --show-error \
    --header 'Host: example.test' "http://127.0.0.1:${HTTP_PORT}/")"
grep -q 'httpjet OCI example' <<<"$body"
body="$(curl --noproxy '*' --fail --silent --show-error --insecure \
    --resolve "example.test:${HTTPS_PORT}:127.0.0.1" \
    "https://example.test:${HTTPS_PORT}/")"
grep -q 'httpjet OCI example' <<<"$body"

H3_RESULT="$(python3 "$ROOT/scripts/h3get.py" example.test / 127.0.0.1 "$H3_PORT")"
grep -q 'status=200' <<<"$H3_RESULT"

"$ENGINE" logs "$NAME" 2>&1 | grep -q 'h3/QUIC up'
echo "PASS: non-root read-only OCI smoke; HTTP=${HTTP_PORT}/tcp HTTPS=${HTTPS_PORT}/tcp H3=${UDP_MAPPING}"
