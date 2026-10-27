# Docker and WSL 2

The `ghcr.io/faratech/httpjet` Linux image supports amd64 and arm64. It is
built from the signed release binary and published with a GitHub Actions
attestation. The image runs as UID/GID 10001, serves a static welcome page and
creates a unique self-signed certificate in a persistent volume.

## Start with Docker Compose

Install Docker Engine with Compose, or Docker Desktop using **Linux containers**
and its WSL 2 backend. The Linux kernel and container runtime must permit
io_uring. Docker's default seccomp profile blocks the io_uring syscalls, so the
Compose file uses the supplied narrowly adjusted profile. Other host policies,
including Docker Desktop's configuration, may still block io_uring.

In a new directory, download the Compose file and its seccomp profile:

```sh
curl -fsSLo compose.yaml https://raw.githubusercontent.com/faratech/httpjet/main/packaging/docker/compose.yaml
curl -fsSLo seccomp-httpjet.json https://raw.githubusercontent.com/faratech/httpjet/main/packaging/oci/seccomp-httpjet.json
docker compose up -d
```

Visit `http://localhost:8080/` or `https://localhost:8443/`. The HTTPS
certificate is self-signed, so browsers warn until a trusted certificate is
configured. HTTP is not redirected automatically. To publish different host
ports, edit the two `ports` entries in `compose.yaml`. Port 8443 here is HTTPS
over TCP; this simple container profile does not enable HTTP/3.

```sh
docker compose logs httpjet
docker compose down
```

`down` leaves the named state and log volumes in place. The state volume holds
the certificate and key, so they persist across container recreation. To serve
custom static files, create `./public` and uncomment its read-only mount in
`compose.yaml`; files must be readable by UID 10001. To use a trusted certificate,
mount an appropriate LiteSpeed-compatible configuration and certificate/key
readable by UID 10001 and set the secure listener's `keyFile` and `certFile`.
The optional volume comment is only for site content, not certificate storage.

If startup reports io_uring is unavailable, check the WSL 2/Linux kernel and
container runtime policies. The image does not change host kernel settings or
provide an epoll fallback. Do not replace the provided seccomp profile with an
unconfined or privileged container to bypass the error.

## Microsoft WSL Containers (`wslc`)

Microsoft's [WSL Containers](https://learn.microsoft.com/windows/wsl/wsl-container)
is a separate container runtime; it does not require Docker Desktop. It can pull
the public `ghcr.io/faratech/httpjet:latest` OCI image, but **httpjet does not
currently start in the WSL Containers environment we tested**. On a Windows
Server 2025 GitHub runner using `wslc` 3.0.3, the image's unprivileged
`io_uring_setup` probe returned `EPERM`. The kernel reported
`io_uring_disabled=0` and one seccomp filter was active. In a controlled check
inside the same kind of session, its internal Docker CLI ran the same image and
user with the supplied per-container seccomp profile: the io_uring setup,
register and NOP probe passed. This points to the default container filter as
the restriction. [Comparison run](https://github.com/faratech/httpjet/actions/runs/40460449802).

WSL Containers 3.0.3 does not expose Docker's `--security-opt seccomp=...`
CLI option; the Docker Compose profile above therefore cannot be passed to
`wslc` that way. An isolated internal-Docker experiment initialized httpjet's
HTTP and HTTPS listeners with that profile, but the session-local HTTP probe did
not return the welcome page; Windows port forwarding was not verified. Direct
Docker API/CLI launches do not automatically register `wslc`'s Windows port
relay. [Server experiment](https://github.com/faratech/httpjet/actions/runs/40460619946).
The internal session is a low-level route, not a supported one-command `wslc`
configuration. httpjet requires io_uring and has no epoll fallback. Do not
claim `wslc` compatibility until the full Windows-facing path works.

To check your own WSL Containers installation from PowerShell, first ensure WSL
is up to date (`wsl --update`, then `wslc version`). Microsoft documents WSL
2.9.3 or later for this feature. The following command runs the image's
unprivileged io_uring diagnostic without starting the web server:

```powershell
wslc run --rm --entrypoint /bin/sh ghcr.io/faratech/httpjet:latest -c 'exec /usr/libexec/httpjet/io-uring-probe'
```

A JSON result with `status: passed` means this probe worked; a failed result
with `operation: setup` and `errno: 1` means the runtime or host denied setup.
A passing probe alone does not verify HTTP, HTTPS, networking or persistence.

## Docker Desktop on Windows with WSL 2

Enable Docker Desktop's WSL 2 engine and use Linux containers. When using a WSL
terminal, enable integration for that distribution in Docker Desktop. See
[Docker's WSL 2 setup](https://docs.docker.com/desktop/features/wsl/). Run the
Compose commands above inside the integrated distribution; keep the project and
static files in its Linux filesystem where possible. The two published ports
are accessible from the Windows browser as `localhost:8080` and
`localhost:8443` when Docker Desktop port forwarding is functioning.

To download the same files from PowerShell instead:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/faratech/httpjet/main/packaging/docker/compose.yaml -OutFile compose.yaml
Invoke-WebRequest https://raw.githubusercontent.com/faratech/httpjet/main/packaging/oci/seccomp-httpjet.json -OutFile seccomp-httpjet.json
docker compose up -d
```

## Install directly in a WSL 2 distribution

The regular Linux installer can also run inside WSL 2 if its kernel permits
io_uring. Check `wsl.exe --list --verbose` from PowerShell; WSL 1 is not
supported. With systemd enabled, use the standard Linux install commands in the
[project README](../../README.md#install-on-linux). If the distribution does not
run systemd, use the explicit foreground route:

```sh
curl -fsSLo install.sh https://github.com/faratech/httpjet/releases/latest/download/install.sh
sudo sh ./install.sh --method binary --init none
sudo httpjetctl run
```

The last command stays in the foreground. For service management, follow
[Microsoft's systemd instructions](https://learn.microsoft.com/windows/wsl/systemd)
and restart the affected WSL distribution. A WSL service does not by itself keep
the distribution running. Availability of io_uring depends on the actual kernel
and runtime; WSL 2 and Docker Desktop have not been validated on every version.
