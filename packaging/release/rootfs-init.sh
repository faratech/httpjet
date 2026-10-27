#!/bin/sh
# Executes only as PID 1 in a disposable qualification guest.
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
write_alpine_network_config() {
    network_config=$1
    network_interface=$2
    case "$network_interface" in
        ''|lo|*[!a-zA-Z0-9_.:-]*) printf 'Invalid qualification network interface\n' >&2; return 1 ;;
    esac
    mkdir -p "${network_config%/*}"
    cat > "$network_config" <<EOF
# Disposable QEMU user network, configured by real OpenRC networking.
auto lo
iface lo inet loopback

auto $network_interface
iface $network_interface inet static
    address 10.0.2.15/24
    gateway 10.0.2.2
EOF
}
exec_target_init() {
    [ -x "$target_init" ]
    if [ "$recipe" = alpine ]; then
        write_alpine_network_config /etc/network/interfaces "$interface"
        # Let OpenRC configure its own address/route/state on every boot.
        ip route del default via 10.0.2.2 dev "$interface" 2>/dev/null || :
        ip address del 10.0.2.15/24 dev "$interface" 2>/dev/null || :
    fi
    exec "$target_init"
}
recipe=$(cat /httpjet-qualification-recipe)
target_init=$(cat /httpjet-qualification-target-init)
mkdir -p /proc /sys /dev /run /tmp
mount -t proc proc /proc 2>/dev/null || :
mount -t sysfs sysfs /sys 2>/dev/null || :
mount -t devtmpfs devtmpfs /dev 2>/dev/null || :
mkdir -p /dev/shm
chmod 1777 /tmp
ip link set lo up
for candidate in /sys/class/net/*; do
    interface=${candidate##*/}
    [ "$interface" = lo ] && continue
    ip link set "$interface" up
    ip address add 10.0.2.15/24 dev "$interface" 2>/dev/null || :
    ip route replace default via 10.0.2.2 dev "$interface"
    break
done
rm -f /etc/resolv.conf
printf 'nameserver 10.0.2.3\n' > /etc/resolv.conf
if ! grep -q 'httpjet-qualification.local' /etc/hosts; then
    printf '\n10.0.2.2 httpjet-qualification.local\n' >> /etc/hosts
fi
if [ -f /httpjet-qualification-initialized ]; then
    exec_target_init
fi
if [ ! -f /httpjet-qualification-prepared ]; then
    case "$recipe" in
        alpine)
            apk add --no-cache openrc openrc-init openssh sudo curl ca-certificates gnupg util-linux python3 tar gzip
            ;;
        void-musl)
            xbps-install -Sy xbps
            xbps-install -Sy base-system runit-void iproute2 openssh sudo curl ca-certificates gnupg util-linux python3 tar gzip
            ;;
        devuan-sysv)
            created_policy=0
            if [ ! -e /usr/sbin/policy-rc.d ]; then
                printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
                chmod 0755 /usr/sbin/policy-rc.d
                created_policy=1
            fi
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y --no-install-recommends openssh-server sudo curl ca-certificates gnupg util-linux python3
            [ "$created_policy" = 0 ] || rm /usr/sbin/policy-rc.d
            ;;
        arch)
            pacman-key --init
            pacman-key --populate archlinux
            pacman -Syu --noconfirm --needed systemd systemd-sysvcompat iproute2 openssh sudo curl ca-certificates gnupg util-linux python
            ;;
        gentoo-openrc)
            emerge-webrsync
            emerge --getbinpkg --usepkgonly net-misc/openssh app-admin/sudo net-misc/curl \
                app-misc/ca-certificates app-crypt/gnupg sys-apps/util-linux dev-lang/python
            ;;
        slackware-sysv)
            slackpkg -batch=on -default_answer=y update gpg
            slackpkg -batch=on -default_answer=y update
            slackpkg -batch=on -default_answer=y install openssh sudo curl ca-certificates gnupg util-linux python3
            ;;
        *) printf 'Unknown qualification recipe: %s\n' "$recipe" >&2; exit 1 ;;
    esac
fi
for program in sshd ssh-keygen sudo curl python3; do
    command -v "$program" >/dev/null || { printf 'Qualification prerequisite missing: %s\n' "$program" >&2; exit 1; }
done
if ! id qualifier >/dev/null 2>&1; then
    if command -v useradd >/dev/null; then
        useradd -m -s /bin/sh qualifier
    else
        adduser -D -s /bin/sh qualifier
    fi
fi
[ "$(id -u qualifier)" -ne 0 ]
passwd -d qualifier
mkdir -p /home/qualifier/.ssh /etc/sudoers.d /run/sshd
cp /httpjet-qualification-ssh.pub /home/qualifier/.ssh/authorized_keys
chmod 0700 /home/qualifier/.ssh
chmod 0600 /home/qualifier/.ssh/authorized_keys
chown -R "qualifier:$(id -gn qualifier)" /home/qualifier
printf 'qualifier ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/httpjet-qualification
chmod 0440 /etc/sudoers.d/httpjet-qualification
if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers; then
    printf '\n#includedir /etc/sudoers.d\n' >> /etc/sudoers
fi
ssh-keygen -A
cat > /etc/ssh/sshd_config <<'EOF'
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers qualifier
UsePAM no
UseDNS no
PidFile /run/sshd.pid
Subsystem sftp internal-sftp
EOF
case "$recipe" in
    alpine) rc-update add networking boot; rc-update add sshd default ;;
    gentoo-openrc) rc-update add sshd default ;;
    void-musl)
        mkdir -p /etc/runit/runsvdir/default
        ln -s /etc/sv/sshd /etc/runit/runsvdir/default/sshd
        ;;
    devuan-sysv) update-rc.d ssh defaults ;;
    arch) systemctl enable sshd.service ;;
    slackware-sysv) chmod 0755 /etc/rc.d/rc.sshd ;;
esac
[ -x "$target_init" ] || { printf 'Locked target init is unavailable: %s\n' "$target_init" >&2; exit 1; }
printf '1\n' > /httpjet-qualification-initialized
chmod 0600 /httpjet-qualification-initialized
rm -f /httpjet-qualification-ssh.pub
exec_target_init
