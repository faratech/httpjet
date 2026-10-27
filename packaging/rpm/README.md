# Native RPM carrier

The RPM carries the same verified static ELF as the Debian package and portable
archive. Build it through `packaging/release/build.sh`; arbitrary prebuilt files
are not a production package input. Package versions are `X.Y.Z-N`, with RPM
architectures `x86_64` and `aarch64`. The independent noarch archive-keyring RPM
owns `/etc/pki/rpm-gpg/RPM-GPG-KEY-httpjet`.

The source builder supplies only a public key. Its unsigned RPMs are signing
inputs for the protected candidate-signing job. That job must sign both RPMs
before final carrier hashes and signed rpm-md metadata are generated. Never
disable package or repository signature checks.

Configuration uses RPM `%config(noreplace)`. Welcome content is seeded only on
a first install into a new document root. Upgrades do not recreate deleted
sites, and removal preserves website data, nonempty state/log directories and
the dedicated account. Modified RPM configuration may remain as `.rpmsave`.

Old upgrade scriptlets never stop/restart the process. The new package checks
configuration as the service account in `%posttrans`, with a cleared environment,
before reload/restart. Stopped, disabled and masked services retain their state.
Failed validation leaves the previous process running. RPM does not roll
installed files back on scriptlet failure; repair the reported configuration or
permissions before retrying activation.

Qualify on SELinux-enforcing hosts without disabling SELinux or changing global
io_uring policy. Unavailable/denied io_uring is an explicit prerequisite failure.

Fresh installations serve HTTP on port 80 and HTTPS on port 443. Each machine
generates its own self-signed certificate; browsers warn until a trusted certificate
is configured. The private key is `/etc/httpjet/tls/default.key` (root:httpjet, 0640);
the certificate is `/etc/httpjet/tls/default.crt`. Both survive upgrades.
`/etc/httpjet/listeners.env` controls the packaged HTTPS bind address. Existing
HTTP-only installations retain their settings. No automatic HTTPS redirect is added.
To install a trusted certificate, set the HTTPS listener's `keyFile` and `certFile`
in `/etc/httpjet/conf/httpd_config.xml`, validate with `check --strict`, and restart
the service. Firewall access to TCP 443 must also be permitted by the administrator.
