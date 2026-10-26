%{!?httpjet_version:%global httpjet_version 0.1.10}
%{!?httpjet_revision:%global httpjet_revision 4}
Name: httpjet
Version: %{httpjet_version}
Release: %{httpjet_revision}
Summary: Static Rust HTTP server with LiteSpeed-compatible configuration
License: GPL-3.0-only
URL: https://httpjet.net
Source0: httpjet-%{version}-%{release}-payload.tar.gz
Source1: archive-keyring.asc
Source2: preinstall.sh
Requires: systemd
Requires(pre): /usr/sbin/useradd, /usr/sbin/groupadd, /usr/bin/getent
Requires(post): /usr/bin/stat, /usr/bin/mktemp
Requires(posttrans): /usr/sbin/runuser, /usr/bin/env, /usr/bin/systemctl
AutoReqProv: no
%global debug_package %{nil}
# Carrier tools must not rewrite the verified static ELF payload.
%global __os_install_post %{nil}

%description
httpjet is a native, fully static Linux web server. The default service serves
HTTP on port 80 as a dedicated unprivileged account. PHP, TLS, page caching and
management listeners require explicit administrator configuration.

%package archive-keyring
Summary: Public signing key for the httpjet package archive
BuildArch: noarch
AutoReqProv: no
Requires(post): /usr/bin/rpmkeys

%description archive-keyring
Public archive signing key, independently installable from the web server.

%prep
%setup -q -n httpjet-%{version}-%{release}-payload

%build

%install
mkdir -p %{buildroot}
cp -a ./* %{buildroot}/
install -D -m0644 %{SOURCE1} %{buildroot}/etc/pki/rpm-gpg/RPM-GPG-KEY-httpjet
find %{buildroot} -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

%pre -f %{SOURCE2}

%post
/usr/libexec/httpjet/package-helper configure "$1" "%{version}-%{release}"

%posttrans
/usr/libexec/httpjet/package-helper commit "%{version}-%{release}"

%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl stop httpjet.service || true
    systemctl disable httpjet.service || true
fi

%postun
# An old upgrade scriptlet must never restart the newly installed binary.
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
if [ "$1" -eq 0 ]; then rmdir /var/lib/httpjet /var/log/httpjet 2>/dev/null || true; fi

%post archive-keyring
rpmkeys --import /etc/pki/rpm-gpg/RPM-GPG-KEY-httpjet

%files
%defattr(-,root,root,-)
/usr/bin/httpjet
%dir /usr/libexec/httpjet
/usr/libexec/httpjet/package-helper
/usr/lib/systemd/system/httpjet.service
%dir /etc/httpjet
%dir /etc/httpjet/conf
%dir /etc/httpjet/conf/vhosts
%config(noreplace) /etc/httpjet/conf/httpd_config.xml
%config(noreplace) /etc/httpjet/conf/mime.properties
%config(noreplace) /etc/httpjet/conf/vhosts/default.xml
/usr/share/httpjet/welcome/index.html
%dir /usr/share/httpjet
%dir /usr/share/httpjet/welcome
%dir /usr/share/doc/httpjet
%dir /usr/share/licenses/httpjet
%doc /usr/share/doc/httpjet/README.md
%doc /usr/share/doc/httpjet/THIRD_PARTY_NOTICES.md
%license /usr/share/licenses/httpjet/LICENSE

%files archive-keyring
%defattr(-,root,root,-)
/etc/pki/rpm-gpg/RPM-GPG-KEY-httpjet

%changelog
* Mon Oct 26 2026 httpjet contributors - 0.1.10-4
- Select one canonical noarch RPM keyring for both target architectures.
- Use Podman-compatible owned tmpfs mounts for CoreOS qualification.

* Mon Oct 26 2026 httpjet contributors - 0.1.10-3
- Resolve the source timestamp from the release tag's commit.

* Mon Oct 26 2026 httpjet contributors - 0.1.10-2
- Publish qualified Linux carriers with GitHub build provenance.

* Mon Oct 26 2026 httpjet contributors - 0.1.10-1
- Native static payload with validation before transaction restart.
