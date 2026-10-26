# Native Debian and Ubuntu packages

The native DEB carrier targets compatible Debian/Ubuntu-family amd64 and arm64
hosts with systemd and usable unprivileged Linux io_uring. Release qualifications
record the tested distribution versions. The default service serves a
static welcome page over HTTP on port 80. TLS, PHP, page caching, metrics and
management listeners are disabled.
Fresh native profiles use `--no-multishot-accept`, retaining io_uring while
avoiding an optional accept acceleration on older compatible kernels. Custom
production units are not modified by the installer source changes.

The binary is `/usr/bin/httpjet`; configuration is rooted at `/etc/httpjet`;
the administrator's document root is `/var/www/httpjet`. The dedicated system
account is `httpjet`. Package upgrade validation runs as that account through
`runuser` with a cleared environment before any service restart; unreadable
configuration fails before stopping the old process. systemd manages `/run/httpjet`, `/var/lib/httpjet` and
`/var/log/httpjet`. The service only receives `CAP_NET_BIND_SERVICE` and starts
after a strict configuration check. `Type=notify` readiness has a 30-second
startup deadline.

## Build

Build natively for each architecture in the pinned Debian 12 Rust builder used
by release CI. Rust 1.99.1 and the `debian/control` build dependencies are
required. Supply the real ASCII-armored public signing key as
`packaging/debian/archive-keyring.asc`; a missing or invalid key fails the build.
The keyring package installs it as
`/usr/share/keyrings/httpjet-archive-keyring.asc` (the install rule renames it).
The bootstrap source must use that key through its repository-scoped
`Signed-By` entry.

```sh
dpkg-buildpackage -us -uc -b
```

The build uses the native `*-unknown-linux-musl` Rust target, musl-gcc, no
optional features, static CRT and explicit Rust/C baseline CPU flags. It never
uses native CPU flags or host PGO. ELF validation requires no interpreter,
no shared-library dependencies and no GLIBC symbol requirements. musl-tools
and the matching Rust 1.99.1 target component are builder prerequisites.

The Debian upstream version must equal Cargo's version; revision `N` yields the
canonical release identity `X.Y.Z-N`. The source producer creates a private
same-run receipt binding source tree, tag, commit, architecture and binary
digest. Carrier packaging accepts that authenticated receipt, preserves the
ELF bytes and independently compares extracted DEB/RPM/tar payload hashes.
This production interface is separate from the isolated test-only bypass.

An isolated package-lifecycle test may set `HTTPJET_PACKAGE_TEST=1` together
with `HTTPJET_TEST_PREBUILT=/absolute/path/to/binary`. These variables must be
absent from release jobs. They are not an installation or release interface.

## Lifecycle

Install and upgrade through APT. Native debhelper service helpers preserve
disabled/masked service state and use `try-restart` on upgrades, leaving a
manually stopped service stopped. Fresh installs start through the Debian
service helper; upgrades never force a start. A first package install refuses existing unmanaged httpjet binaries,
configuration or service definitions. Existing administrator configuration is
managed as dpkg conffiles.

The welcome template lives at `/usr/share/httpjet/welcome/index.html`. Package
configuration copies it into `/var/www/httpjet/index.html` only on a first
installation and only if the document root did not exist. Upgrades do not
recreate a document root removed by the administrator. Existing directories, files and symlinks are untouched,
including an empty existing directory. The inline default vhost rewrite denies
PHP-like suffixes before static dispatch, including path-info forms.

`apt remove httpjet` stops/removes the packaged server while preserving its
configuration. `apt purge httpjet` removes package conffiles and empty
`/var/lib/httpjet` and `/var/log/httpjet` directories. The default package creates
no persistent page cache. Nonempty state/log directories, including administrator
certificates and log history, are retained. Both removal and purge preserve
website content and the system account. The separately installed archive-keyring package keeps
APT trust available when the server is removed. Removing a package never
changes firewalls, sysctls or another web server.

Run the isolated maintainer-script tests with:

```sh
python3 -B packaging/debian/test_lifecycle.py
python3 -B packaging/debian/test_build_key.py
python3 -B packaging/debian/test_clean.py
python3 -B packaging/release/test_build_session.py
python3 -B packaging/rpm/test_scriptlets.py
python3 -B packaging/debian/test_default_config.py --binary /absolute/path/to/httpjet
```

VM release gates must additionally prove service startup, notification
readiness, welcome-body identity, disabled-service upgrades, administrator
configuration/content preservation, port conflicts and remove/purge/reinstall
against the actual built packages. Local maintainer tests do not substitute
for these VM results.
