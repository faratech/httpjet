# Generic service controller

Archive root httpjet-X.Y.Z-N/ contains bin/httpjet, shared defaults under
share/httpjet/{conf,welcome}, and these helpers under share/httpjet/services.
Signed JSON metadata and full tarball SHA256/size are authenticated before
extraction. Traversal, links, devices, duplicates and expanded-size excesses fail.

Versioned payloads live in /opt/httpjet/releases/ID. /usr/local/bin/httpjet points
directly to an ELF and switches by atomic rename. Root-private
/var/lib/httpjet-installer/state.json tracks identity, method, init, versions and
owned-file hashes.

```
sudo httpjetctl update
sudo httpjetctl update --version 0.1.10-1
sudo httpjetctl rollback
sudo httpjetctl rollback --version 0.1.9-2
sudo httpjetctl start
sudo httpjetctl stop
sudo httpjetctl enable
sudo httpjetctl disable
sudo httpjetctl status
sudo httpjetctl run       # foreground; launcher drops root
sudo httpjetctl uninstall
```

Upgrades validate configuration as the recorded non-root account before switching.
Only previously running services restart. Stopped/disabled states and edited
config/content/unit files are retained. Failed activation restores old binaries
and helpers, then attempts to restart a previously running release. Edited
privileged helpers cause a refusal rather than implicit adoption.

Uninstall stops the owned service and removes unchanged owned programs. Config,
content, logs, account and ownership tombstone remain. Modified releases are
reported and retained. Clearing the record is an explicit migration step; native
packages never automatically adopt it.

Every adapter serves as the dedicated httpjet account, recorded without a UID
cutoff. systemd grants only CAP_NET_BIND_SERVICE. Other adapters use util-linux
setpriv to drop UID/GID, initialize only the target account groups, constrain capabilities and apply
no-new-privileges. The launcher clears environment before Python and daemon exec.
Web requests are never served as root.

Startup uses serve --ready-file /run/httpjet/ready, with service-owned 0750 parent
and private decimal-PID marker published only after activation. Control verifies
exact PID, non-root UID, versioned executable and process start time before
signalling. Only proven owned stale markers are removed. Unknown supervisors use
explicit --init none and httpjetctl run; automatic boot integration is not claimed.

Portable defaults use single-shot io_uring accept. Multishot is an optional
acceleration for separately qualified environments; no alternate transport is used.
Slackware rc.local hooks preserve original bytes and modes, and refuse to make an
existing disabled administrator hook executable. Root supervisor PID files live
outside the worker-writable runtime directory. Logs open only after UID drop.
