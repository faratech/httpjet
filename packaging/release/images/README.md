# CoreOS: signed OCI archive and persistent Podman service

Use the signed release OCI archive with rootful Podman. The app runs as
`10001:10001`; CoreOS needs no Python, OS rebase or RPM layering for this route.

On a controller with GnuPG, verify `manifest.json.asc` against the approved
archive key and full fingerprint. Select `oci_images[ARCH].artifact`, verify
its SHA256 against the authenticated manifest, and retain its exact `image_id`.
Obtain `packaging/oci/seccomp-httpjet.json` from the matching hash-verified
source archive. Transfer both files over authenticated SSH and confirm the
archive's SHA256 again on CoreOS using native `sha256sum`, then:

```sh
sudo podman load --input /var/tmp/httpjet-release-oci.tar
sudo podman image inspect sha256:APPROVED_IMAGE_CONFIG_ID
```

Put your content, or the verified payload's welcome page, in persistent
`/var/lib/httpjet/site`, readable by UID 10001. Install the verified seccomp
file as `/etc/httpjet/seccomp.json`, root-owned and mode 0644. This owned
`/etc/systemd/system/httpjet.service` publishes HTTP 80 to unprivileged 8080:

```ini
[Unit]
Description=httpjet Podman service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/podman rm --ignore --force httpjet
ExecStart=/usr/bin/podman run --name httpjet --pull=never --user=10001:10001 --publish=80:8080/tcp --read-only --cap-drop=ALL --security-opt=no-new-privileges --security-opt=seccomp=/etc/httpjet/seccomp.json --ulimit=memlock=8388608:8388608 --tmpfs=/run/httpjet:rw,noexec,nosuid,nodev,size=16m,mode=0750,uid=10001,gid=10001 --tmpfs=/var/log/httpjet:rw,noexec,nosuid,nodev,size=16m,mode=0750,uid=10001,gid=10001 --volume=/var/lib/httpjet/site:/var/www/httpjet:ro,z sha256:APPROVED_IMAGE_CONFIG_ID
ExecStop=/usr/bin/podman stop --ignore --time=25 httpjet
ExecStopPost=-/usr/bin/podman rm --ignore --force httpjet
Restart=on-failure
RestartSec=2
TimeoutStopSec=30
KillMode=none

[Install]
WantedBy=multi-user.target
```

Replace the image ID with the verified manifest value. Run
`sudo systemctl daemon-reload` and `sudo systemctl enable --now httpjet.service`.
Ignition can install/enable this same unit when provisioning a new machine.
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
