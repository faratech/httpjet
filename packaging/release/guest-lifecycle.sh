#!/bin/bash
# Root inside the disposable cloud-image VM only.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cd /tmp/httpjet-qualification
version=$1
baseline=$2
check() { printf 'HTTPJET_CHECK %s passed\n' "$1"; }
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates python3
install -m0644 test-ca.crt /usr/local/share/ca-certificates/httpjet-qualification.crt
update-ca-certificates
python3 -m http.server 80 --bind 0.0.0.0 > /tmp/occupied.log 2>&1 &
occupied_pid=$!
trap 'kill "$occupied_pid" 2>/dev/null || true' EXIT
sleep 1
if sh install.sh --version "$version"; then echo 'bootstrap stole occupied port' >&2; exit 1; fi
kill -0 "$occupied_pid"
! dpkg-query -W -f='${Status}' httpjet 2>/dev/null | grep -qx 'install ok installed'
kill "$occupied_pid"; wait "$occupied_pid" || true
trap - EXIT
check occupied-port
sh install.sh --version "$version"
systemctl is-active --quiet httpjet
check install
curl --fail --silent http://127.0.0.1/ > /tmp/welcome-response
cmp /usr/share/httpjet/welcome/index.html /tmp/welcome-response
check http
sh install.sh --version "$version"
check rerun
for suffix in php PHP php8 phtml phar phps php.br php.gz.br; do
  printf '<?php SECRET-QUALIFICATION-SOURCE' > "/var/www/httpjet/probe.$suffix"
  for tail in '' /pathinfo; do
    code=$(curl --silent -o /tmp/source-response -w '%{http_code}' "http://127.0.0.1/probe.$suffix$tail")
    test "$code" = 403
    ! grep -q SECRET-QUALIFICATION-SOURCE /tmp/source-response
  done
done
check scripts-denied
dd if=/dev/urandom of=/var/www/httpjet/bridge-test.bin bs=1048576 count=1 status=none
curl --fail --silent -H 'Accept-Encoding: identity' http://127.0.0.1/bridge-test.bin > /tmp/bridge-response
cmp /var/www/httpjet/bridge-test.bin /tmp/bridge-response
check bridged-transfer
systemctl restart httpjet
curl --fail --silent http://127.0.0.1/ > /tmp/restart-response
cmp /usr/share/httpjet/welcome/index.html /tmp/restart-response
check restart
! pgrep -x lsphp
! systemctl show --property=ExecStart --value httpjet | grep -E -- '--page-cache|--lsphp-external'
check no-php-no-cache
printf '\n<!-- qualification administrator edit -->\n' >> /etc/httpjet/conf/vhosts/default.xml
printf 'operator-owned\n' > /var/www/httpjet/operator-content.txt
printf 'preserved certificate fixture\n' > /var/lib/httpjet/operator-certificate.pem
printf 'preserved history fixture\n' > /var/log/httpjet/operator-history.log
config_hash=$(sha256sum /etc/httpjet/conf/vhosts/default.xml)
systemctl disable --now httpjet
sh install.sh --version "$version"
! systemctl is-active --quiet httpjet
! systemctl is-enabled --quiet httpjet
systemctl enable --now httpjet
systemctl stop httpjet
sh install.sh --version "$version"
! systemctl is-active --quiet httpjet
systemctl is-enabled --quiet httpjet
systemctl start httpjet
apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold ./baseline.deb
systemctl disable --now httpjet
apt-get install -y -o Dpkg::Options::=--force-confold "httpjet=$version"
! systemctl is-active --quiet httpjet
! systemctl is-enabled --quiet httpjet
systemctl enable --now httpjet
apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold ./baseline.deb
systemctl stop httpjet
apt-get install -y -o Dpkg::Options::=--force-confold "httpjet=$version"
! systemctl is-active --quiet httpjet
systemctl is-enabled --quiet httpjet
systemctl start httpjet
test "$(dpkg-query -W -f='${Version}' httpjet)" = "$version"
test "$(sha256sum /etc/httpjet/conf/vhosts/default.xml)" = "$config_hash"
test "$(cat /var/www/httpjet/operator-content.txt)" = operator-owned
systemctl is-active --quiet httpjet
check upgrade
apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold ./baseline.deb
test "$(dpkg-query -W -f='${Version}' httpjet)" = "$baseline"
test "$(sha256sum /etc/httpjet/conf/vhosts/default.xml)" = "$config_hash"
check downgrade
apt-get install -y -o Dpkg::Options::=--force-confold "httpjet=$version"
check config-preserved
systemctl stop httpjet
install -d /run/systemd/system/httpjet.service.d
cat > /run/systemd/system/httpjet.service.d/qualification-deny.conf <<'EOF'
[Service]
Restart=no
SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register
SystemCallErrorNumber=EPERM
EOF
systemctl daemon-reload
systemctl reset-failed httpjet
if systemctl start httpjet; then echo 'io_uring-denied service unexpectedly started' >&2; exit 1; fi
! systemctl is-active --quiet httpjet
rm /run/systemd/system/httpjet.service.d/qualification-deny.conf
systemctl daemon-reload
systemctl reset-failed httpjet
systemctl start httpjet
curl --fail --silent http://127.0.0.1/ > /dev/null
check io-uring-denied
apt-get remove -y httpjet
! systemctl is-active --quiet httpjet
test -f /etc/httpjet/conf/vhosts/default.xml
test "$(cat /var/www/httpjet/operator-content.txt)" = operator-owned
check remove
apt-get purge -y httpjet
test "$(dpkg-query -W -f='${Status}' httpjet-archive-keyring)" = 'install ok installed'
test -s /usr/share/keyrings/httpjet-archive-keyring.asc
test ! -f /etc/httpjet/conf/vhosts/default.xml
test "$(cat /var/www/httpjet/operator-content.txt)" = operator-owned
test "$(cat /var/lib/httpjet/operator-certificate.pem)" = 'preserved certificate fixture'
test "$(cat /var/log/httpjet/operator-history.log)" = 'preserved history fixture'
check purge

apt-get install -y "httpjet=$version" httpjet-archive-keyring
systemctl is-active --quiet httpjet
test "$(cat /var/www/httpjet/operator-content.txt)" = operator-owned
curl --fail --silent http://127.0.0.1/ > /tmp/reinstalled-response
cmp /usr/share/httpjet/welcome/index.html /tmp/reinstalled-response
check reinstall
