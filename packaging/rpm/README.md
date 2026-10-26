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
