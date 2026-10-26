# CoreOS: signed OCI archive and persistent Podman service

Use the signed release OCI archive with rootful Podman. The app runs as
`10001:10001`; CoreOS needs no Python, OS rebase or RPM layering for this route.

On a controller with GnuPG, verify `manifest.json.asc` against the approved
archive key and full fingerprint. Select `oci_images[ARCH].artifact`, verify
its SHA256 against the authenticated manifest, and retain its exact `image_id`.
Obtain `packaging/oci/seccomp-httpjet.json` and
`packaging/release/images/httpjet-container.cil` from the matching hash-verified
source archive. Transfer these files and the OCI archive over authenticated SSH and confirm the
archive's SHA256 again on CoreOS using native `sha256sum`, then:

```sh
sudo podman load --input /var/tmp/httpjet-release-oci.tar
sudo podman image inspect sha256:APPROVED_IMAGE_CONFIG_ID
```

The CoreOS image must provide enforcing SELinux, `/usr/sbin/semodule`, and the
packaged Udica base template `/usr/share/udica/templates/base_container.cil`.
Use the approved CoreOS image and its authenticated container-selinux package;
an image without that template needs a separately provisioned compatible image.
The local enforcing-policy proof observed base-template SHA256
`c95d8badacc674ace0d2fed4fbee4d28d2a92799b23fd5cc30cfb444ee8896b7`.
Qualification records the actual template hash alongside the dedicated policy
hash and domain; that component proof does not qualify every CoreOS image.

Install the verified files as root-owned mode 0644:

```sh
test "$(getenforce)" = Enforcing
test -r /usr/share/udica/templates/base_container.cil
sha256sum /usr/share/udica/templates/base_container.cil
sudo install -d -o root -g root -m 0755 /etc/httpjet
sudo install -o root -g root -m 0644 /var/tmp/seccomp-httpjet.json /etc/httpjet/seccomp.json
sudo install -o root -g root -m 0644 /var/tmp/httpjet-container.cil /etc/selinux/httpjet-container.cil
```

Create `/etc/systemd/system/httpjet-selinux-policy.service` with this persistent
loader. It installs the dedicated `httpjet_container.process` domain from the
packaged base and the authenticated CIL before the app starts:

```ini
[Unit]
Description=httpjet dedicated container SELinux policy
Before=httpjet.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/semodule -i /usr/share/udica/templates/base_container.cil /etc/selinux/httpjet-container.cil
RemainAfterExit=yes
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
```

The policy inherits the packaged container base and network domain, adding only
`create`, `map`, `read` and `write` for `io_uring_t:anon_inode` to this dedicated
domain. The app must use the explicit label below. SELinux stays enforcing;
permissions for the default `container_t` domain remain unchanged. The loader
does not change global io_uring policy, disable labels, or grant capabilities.

Put your content, or the verified payload's welcome page, in persistent
`/var/lib/httpjet/site`, readable by UID 10001. This owned
`/etc/systemd/system/httpjet.service` publishes HTTP 80 to unprivileged 8080:

```ini
[Unit]
Description=httpjet Podman service
After=network-online.target httpjet-selinux-policy.service
Wants=network-online.target
Requires=httpjet-selinux-policy.service

[Service]
Type=simple
ExecStartPre=-/usr/bin/podman rm --ignore --force httpjet
ExecStart=/usr/bin/podman run --name httpjet --pull=never --user=10001:10001 --publish=80:8080/tcp --read-only --cap-drop=ALL --security-opt=no-new-privileges --security-opt=label=type:httpjet_container.process --security-opt=seccomp=/etc/httpjet/seccomp.json --ulimit=memlock=8388608:8388608 --mount=type=tmpfs,dst=/run/httpjet,tmpfs-size=16m,tmpfs-mode=0750,U,noexec,nosuid,nodev --mount=type=tmpfs,dst=/var/log/httpjet,tmpfs-size=16m,tmpfs-mode=0750,U,noexec,nosuid,nodev --volume=/var/lib/httpjet/site:/var/www/httpjet:ro,z sha256:APPROVED_IMAGE_CONFIG_ID
ExecStop=/usr/bin/podman stop --ignore --time=25 httpjet
ExecStopPost=-/usr/bin/podman rm --ignore --force httpjet
Restart=on-failure
RestartSec=2
TimeoutStopSec=30
KillMode=none

[Install]
WantedBy=multi-user.target
```

The tmpfs `U` option assigns each mount to the container UID/GID while retaining
mode 0750 and the size and execution restrictions.

Replace the image ID with the verified manifest value. Run
`sudo systemctl daemon-reload` and
`sudo systemctl enable --now httpjet-selinux-policy.service httpjet.service`.
Confirm `getenforce` remains `Enforcing` and
`sudo podman inspect --format '{{.ProcessLabel}}' httpjet` reports the dedicated
`httpjet_container.process` type. Ignition can install the CIL and enable both
units when provisioning a new machine.
The adjacent `coreos.bu` is a disposable qualification recipe with test-specific
update/policy controls; use your operator configuration for production.

Defaults are HTTP with PHP, TLS, page cache and management listeners disabled.
TLS needs explicit configuration, read-only certificate/key mounts readable by
UID 10001, and a matching HTTPS command override. HTTP/3 also needs UDP published,
for example host 443 to container 8443 on both TCP and UDP.

The host kernel/seccomp policy and final service identity must permit io_uring;
the image/installer never changes global policy to enable it. Journal output
persists normally; the shown run/log tmpfs is disposable. Persistent logs need
an explicitly owned writable volume. Keep `/var/lib/httpjet/site` and operator
state/log volumes across restart, reboot and uninstall. Uninstall only the owned
unit/container; do not broadly prune volumes. Local build/container evidence
does not replace the complete signed CoreOS VM qualification gate.
