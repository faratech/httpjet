# Hardened OCI example

This directory is an adoption example, not a prescription for an existing
deployment.

The image runs httpjet as numeric UID/GID `10001:10001`, binds unprivileged
ports, declares separate TCP and UDP exposure for HTTPS/HTTP3, and requires no
Linux capabilities. The compose example additionally uses a read-only root
filesystem, drops every capability, sets `no-new-privileges`, and provides a
small `noexec,nosuid,nodev` `/tmp` tmpfs. Because Moby's default seccomp
allowlist omits io_uring, `seccomp-httpjet.json` is the pinned Moby default plus
only `io_uring_setup`, `io_uring_enter`, and `io_uring_register`.

## Required certificate and writable mounts

The example intentionally contains no private key. Before starting it, place a
certificate for `example.test` at `packaging/oci/certs/tls.crt` and its key at
`packaging/oci/certs/tls.key`. Both must be readable by UID 10001; keep the key
mode at 0400. For a local-only certificate:

```bash
mkdir -p packaging/oci/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=example.test -addext subjectAltName=DNS:example.test \
  -keyout packaging/oci/certs/tls.key \
  -out packaging/oci/certs/tls.crt
chown 10001:10001 packaging/oci/certs packaging/oci/certs/tls.key packaging/oci/certs/tls.crt
chmod 0400 packaging/oci/certs/tls.key
chmod 0444 packaging/oci/certs/tls.crt
```

The filesystem contract is explicit:

| Path | Access | Purpose |
|---|---|---|
| `/run/httpjet-certs` | read-only | TLS certificate and private key |
| `/var/lib/httpjet` | read-write | page-cache files and integrity key |
| `/etc/httpjet/litespeed/logs` | read-write | access/error logs |
| `/etc/httpjet/litespeed/conf` and `example` | image read-only | LiteSpeed XML and static content |
| `/tmp` | bounded tmpfs | temporary runtime files |

Do not mount the Docker socket, host root, production LSWS configuration, or an
unrelated application document root into this example.

## Build and run

```bash
docker compose -f packaging/oci/compose.yaml up --build
```

The published ports are deliberately protocol-qualified:

- `8080/tcp`: HTTP/1.1 and h2c;
- `8443/tcp`: TLS HTTP/1.1 and HTTP/2;
- `8443/udp`: HTTP/3/QUIC.

Publishing `8443/tcp` alone does not expose HTTP/3. Permit the UDP port through
the host and cloud firewalls too. The TLS response advertises the same UDP port
with Alt-Svc.

The image health check calls the loopback-only `/__hj_cache_ready` endpoint on
HTTP port 8080. The example enables a small persistent page-cache solely so
that readiness represents completion of the boot scan; it does not probe or
warm a user URL.

## io_uring requirements and failure policy

httpjet has no epoll or privileged fallback. The container host must be Linux
with an io_uring-capable kernel, and the OCI runtime's seccomp policy must permit
the io_uring syscalls used by monoio. The Compose example and smoke gate use the
supplied profile, derived from Moby profiles commit
`61eaf32614c7c71b60bd8927d3e6a4ffc8ff1f31`; review/rebase it when changing the
container runtime. A policy denial is a startup/test failure. Do not work around
it with `--privileged`, `--cap-add`, or `seccomp=unconfined`; update the runtime
policy narrowly or use a supported runtime/host. Rootless engines may also
impose memlock, UDP, or io_uring restrictions and must be validated
independently.

A hand-written `docker run` command must pass
`--security-opt seccomp=/absolute/path/to/seccomp-httpjet.json` explicitly; an
image cannot select its own host seccomp policy.

The example binds only ports above 1024, needs no `CAP_NET_BIND_SERVICE`, and
does not request host networking, devices, PID/IPC namespaces, or elevated
memory-lock limits. HTTP/3 uses the ordinary published UDP socket, not a device.

## Reproducible smoke gate

```bash
bash scripts/oci-smoke.sh
```

The gate requires Python `aioquic` (the CI job pins version 1.3.0), builds the
image, generates a one-day synthetic certificate, and runs
with a read-only root filesystem, UID 10001, all capabilities dropped, and
`no-new-privileges`. It requires the readiness health check, HTTP and HTTPS
content checks, a real HTTP/3 request through the published UDP port, and the
`h3/QUIC up` signal. It
never retries with privileged mode or an unconfined seccomp profile.

The test uses ephemeral ports, named volumes, and a temporary certificate. It
does not touch production sockets, configuration, cache, certificates, or
services.
