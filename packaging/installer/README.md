# Linux bootstrap installer

The publisher renders one POSIX shell script from install.sh.in, embedding the
approved public key/fingerprint, repository URLs and exact stdlib controller from
packaging/services/manage.py. Generic downloads authenticate the signed manifest
and complete tarball hash/size before extraction or executing downloaded code.

```
sudo sh install.sh
sudo sh install.sh --method binary --init openrc
sudo sh install.sh --method binary --init none --version 0.1.10-1
```

--method auto|package|binary chooses native APT/RPM on matching mutable systemd
systems or the common static payload elsewhere. No OS-version allowlist is used.
Architecture, managers, init state and prerequisites are detected. Existing owners
retain their method; unmanaged/native/generic conversions need explicit migration.
--init accepts auto, systemd, openrc, runit, sysv or none. Unknown supervisors need
explicit none: install without starting/enabling, then use the foreground route.
NixOS/Guix receive declarative instructions before writes. rpm-ostree requires an
image/layered integration.

APT uses deb822 Signed-By and an independent keyring package. RPM enables package
and repository metadata signature checks. Native reruns retain edited conffiles
and stopped/disabled states. Explicit --version X.Y.Z-N permits downgrades. Generic
stable selection authenticates expiry and rejects implicit downgrades. Existing
package-owned signing keyrings remain intact.

Generic prerequisites are CA certificates, curl, full GPG, Python 3.8+ and
util-linux setpriv with ambient capabilities. Missing tools are installed through
recognized APT/RPM/APK/pacman/XBPS managers; unknown managers get a clear prerequisite
list. Python and setpriv remain runtime dependencies for generic services. BusyBox
shell/account tools are supported; minimal BusyBox setpriv is insufficient. No
client Rust toolchain is needed.

Static musl payloads target native amd64/arm64. io_uring must work under the final
account and sandbox; denials abort without global kernel-policy changes. OS names
and kernel versions do not prove compatibility. Published support requires the
real release qualification matrix, not only local contract tests.

```
python3 -B -m unittest discover -s packaging/installer -p 'test_*.py'
python3 -B -m unittest discover -s packaging/services -p 'test_*.py'
sh -n packaging/installer/install.sh.in
```

Tests use isolated filesystems and mocked package/service operations. Real GPG
cases use disposable test keys. Host packages/accounts/services and production
signing credentials remain untouched.
