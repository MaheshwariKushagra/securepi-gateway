#!/bin/bash
# SecurePi Gateway - one-command installer (ENHANCEMENT-PLAN.md step 8.2).
#
# Turns a fresh Ubuntu Server 24.04 machine into a SecurePi Gateway, or checks
# an existing one. Run it ON THE GATEWAY, as root, from a copy of this
# repository (see docs/INSTALL.md for the full procedure):
#
#   sudo ./gateway/install.sh --check     report what would change; change nothing
#   sudo ./gateway/install.sh             install or update
#
# Idempotent: every step compares what is there with what should be there and
# changes only the difference. Running it twice changes nothing the second
# time. It never overwrites credentials, the DNS filter's configuration, the
# database, the HTTPS-inspection CA or the console's TLS key once they exist,
# never disables or removes anything, and backs up every file it replaces as
# <file>.bak-install-<timestamp>.
#
# HTTPS inspection (Tier 2) is installed in its OFF state: the proxy runs, but
# no device is enrolled and the per-device site map is empty, so nothing is
# decrypted for anyone until an operator switches it on for one device.
#
# Settings (environment variables; the defaults are the Dell Vostro 3501 the
# project was built on):
#   WAN_IF=wlp2s0            Wi-Fi interface that joins the upstream network
#   MGMT_IF=enp1s0           wired management interface (SSH only)
#   MGMT_ADDR=192.168.2.5/24 static address on MGMT_IF
#   AP_SSID=SecurePi-Test    the project LAN's network name
#   AP_COUNTRY=IN            regulatory domain for hostapd
#   AP_CHANNEL=6             initial channel (follows the uplink afterwards)
#   AP_PASSPHRASE            asked for at a hidden prompt if hostapd has no config yet
#   UPLINK_SSID              asked for only if no netplan file configures WAN_IF
#   TIMEZONE=Asia/Kolkata    the console shows times in the system timezone
#   INSTALL_DPI=yes          install HTTPS inspection (in its off state)
#   INSTALL_EVAL_TOOLS=yes   install the evaluation tools in /opt/securepi-eval
#   ENABLE_RUN_MONITOR=no    enable the evaluation run monitor service
#   TEST_WITHOUT_WIFI=no     VM testing only: no radio - ap0 is a dummy
#                            interface and hostapd/uplink steps are skipped
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
MODE=apply
case "${1:-}" in
    --check) MODE=check ;;
    "") ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "usage: sudo $0 [--check]" >&2; exit 2 ;;
esac

: "${WAN_IF:=wlp2s0}"
: "${MGMT_IF:=enp1s0}"
: "${MGMT_ADDR:=192.168.2.5/24}"
: "${AP_SSID:=SecurePi-Test}"
: "${AP_COUNTRY:=IN}"
: "${AP_CHANNEL:=6}"
: "${TIMEZONE:=Asia/Kolkata}"
: "${UPLINK_SSID:=}"
: "${INSTALL_DPI:=yes}"
: "${INSTALL_EVAL_TOOLS:=yes}"
: "${ENABLE_RUN_MONITOR:=no}"
: "${TEST_WITHOUT_WIFI:=no}"

# The exact AdGuard Home release the project was built and measured with,
# with the SHA-256 of each release archive (from the release's checksums.txt;
# the amd64 binary inside matches the gateway's byte for byte).
AGH_VERSION=v0.107.79
AGH_SHA256_amd64=c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f
AGH_SHA256_arm64=3f7893c18e8aaadc456d0452839190561c306ca95175a2254958be80a769c1ae

# Versions the project was tested with (Ubuntu 24.04 archive, 10 Oct 2026).
# A different version is reported as a warning, not an error.
TESTED_VERSIONS="suricata=1:7.0.3-1build3 hostapd=2:2.10-21ubuntu0.4 nftables=1.0.9-1build1
python3-fastapi=0.101.0-3 python3-starlette=0.31.1-1 python3-pydantic=1.10.14-1
python3-uvicorn=0.27.1-1 python3-jinja2=3.1.2-1ubuntu1.3"

PACKAGES="suricata suricata-update hostapd iw wpasupplicant nftables conntrack
python3 python3-fastapi python3-starlette python3-pydantic python3-uvicorn python3-jinja2
python3-multipart python3-yaml python3-venv
bind9-dnsutils curl jq rsync patch openssl apache2-utils ethtool tcpdump iproute2"
# The test harness and evaluation tools need these (attack traffic only ever
# runs between the harness's own network namespaces).
EVAL_PACKAGES="nmap hydra iperf3 openssh-server"

TS=$(date +%Y%m%d-%H%M%S)
CHANGES=0
WARNINGS=0
DAEMON_RELOAD=no
NEW_CONSOLE_PASSWORD=""
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ------------------------------------------------------------- helpers --

step() { echo; echo "==> $*"; }
say()  { echo "   $*"; }
warn() { echo "   WARNING: $*"; WARNINGS=$((WARNINGS + 1)); }
die()  { echo "ERROR: $*" >&2; exit 1; }

# Every change goes through this. In --check mode it only reports and
# returns 1 (so the caller skips the change); otherwise it reports and
# returns 0.
would() {
    CHANGES=$((CHANGES + 1))
    if [ "$MODE" = check ]; then
        echo "   would: $*"
        return 1
    fi
    echo "   change: $*"
    return 0
}

# put_file SOURCE DEST MODE OWNER:GROUP - install SOURCE as DEST unless DEST
# already has the same content, mode and owner. A replaced file is kept as
# DEST.bak-install-<timestamp>.
put_file() {
    local src=$1 dst=$2 mode=$3 owner=$4
    local want_mode=$((8#$mode))
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        local cur_mode cur_owner
        cur_mode=$((8#$(stat -c %a "$dst")))
        cur_owner=$(stat -c %U:%G "$dst")
        if [ "$cur_mode" -ne "$want_mode" ] || [ "$cur_owner" != "$owner" ]; then
            if would "set $dst to $mode $owner (is $(stat -c %a "$dst") $cur_owner)"; then
                chmod "$mode" "$dst"
                chown "$owner" "$dst"
            fi
        fi
        return 0
    fi
    local what="install $dst"
    [ -f "$dst" ] && what="replace $dst (old copy kept as $dst.bak-install-$TS)"
    if would "$what"; then
        [ -f "$dst" ] && cp -p "$dst" "$dst.bak-install-$TS"
        install -D -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$src" "$dst"
        case "$dst" in /etc/systemd/system/*) DAEMON_RELOAD=yes ;; esac
    fi
}

# render FILE - print FILE with this machine's interface names in place of
# the Dell's (wlp2s0 / enp1s0). Identical to FILE with the default settings.
render() {
    sed -e "s/wlp2s0/$WAN_IF/g" -e "s/enp1s0/$MGMT_IF/g" "$1"
}

put_rendered() {
    local src=$1 dst=$2 mode=$3 owner=$4
    render "$src" > "$TMP/rendered"
    put_file "$TMP/rendered" "$dst" "$mode" "$owner"
}

ensure_dir() {
    local dir=$1 mode=$2 owner=$3
    if [ ! -d "$dir" ]; then
        if would "create directory $dir ($mode $owner)"; then
            install -d -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$dir"
        fi
    fi
}

ensure_enabled() {
    local unit=$1
    if ! systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        if would "enable $unit"; then
            [ "$DAEMON_RELOAD" = yes ] && { systemctl daemon-reload; DAEMON_RELOAD=no; }
            systemctl enable "$unit" >/dev/null 2>&1
        fi
    fi
}

ensure_active() {
    local unit=$1
    if ! systemctl is-active --quiet "$unit" 2>/dev/null; then
        if would "start $unit"; then
            [ "$DAEMON_RELOAD" = yes ] && { systemctl daemon-reload; DAEMON_RELOAD=no; }
            systemctl start "$unit" || warn "$unit did not start - see: journalctl -u $unit -n 40"
        fi
    fi
}

reload_units() {
    if [ "$DAEMON_RELOAD" = yes ] && [ "$MODE" = apply ]; then
        systemctl daemon-reload
        DAEMON_RELOAD=no
    fi
}

random_secret() {
    # 24 characters from [A-Za-z0-9], from the kernel's CSPRNG.
    openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-24
}

# ---------------------------------------------------------- 1. preflight --

step "1/14  preflight"
[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0 ${1:-}"
[ -f "$REPO/app/webapp.py" ] && [ -f "$REPO/gateway/nftables.conf" ] || die "run from a full copy of the repository ($REPO)"
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = ubuntu ] && [ "${VERSION_ID:-}" = "24.04" ] || warn "tested on Ubuntu 24.04 only; this is ${PRETTY_NAME:-unknown}"
ARCH=$(dpkg --print-architecture)
case "$ARCH" in amd64|arm64) ;; *) die "unsupported architecture $ARCH (amd64 or arm64)" ;; esac
ip link show "$MGMT_IF" >/dev/null 2>&1 || die "management interface $MGMT_IF not found (set MGMT_IF; see 'ip -br link')"
if [ "$TEST_WITHOUT_WIFI" != yes ]; then
    ip link show "$WAN_IF" >/dev/null 2>&1 || die "Wi-Fi interface $WAN_IF not found (set WAN_IF; see 'iw dev')"
    if ! iw list 2>/dev/null | sed -n '/Supported interface modes/,/Band/p' | grep -q '\* AP$'; then
        die "the Wi-Fi radio does not support AP mode (iw list); see GATEWAY-SETUP-RUNBOOK.md §0"
    fi
fi
say "repository $REPO ($(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout')), mode $MODE, $PRETTY_NAME $ARCH"
say "WAN_IF=$WAN_IF MGMT_IF=$MGMT_IF MGMT_ADDR=$MGMT_ADDR AP_SSID=$AP_SSID TIMEZONE=$TIMEZONE TEST_WITHOUT_WIFI=$TEST_WITHOUT_WIFI"

# -------------------------------------------------------- 2. host settings --

step "2/14  host settings: timezone, no sleep, lid ignored, IPv4 forwarding"
if [ "$(timedatectl show -p Timezone --value 2>/dev/null)" != "$TIMEZONE" ]; then
    # The console renders times in the system timezone (gateway/REBOOT-SAFETY.md).
    if would "set the timezone to $TIMEZONE"; then timedatectl set-timezone "$TIMEZONE"; fi
fi
for target in sleep.target suspend.target hibernate.target hybrid-sleep.target; do
    if [ "$(systemctl is-enabled "$target" 2>/dev/null || true)" != masked ]; then
        if would "mask $target (a gateway must never suspend)"; then systemctl mask "$target" >/dev/null 2>&1; fi
    fi
done
put_file "$REPO/gateway/logind-securepi.conf" /etc/systemd/logind.conf.d/99-securepi.conf 644 root:root
put_file "$REPO/gateway/sysctl-securepi.conf" /etc/sysctl.d/99-securepi.conf 644 root:root
if [ "$(sysctl -n net.ipv4.ip_forward)" != 1 ]; then
    if would "enable IPv4 forwarding now (sysctl --system)"; then sysctl --system >/dev/null; fi
fi

# ------------------------------------------------------------ 3. packages --

step "3/14  packages from the Ubuntu archive"
ALL_PACKAGES="$PACKAGES"
[ "$INSTALL_EVAL_TOOLS" = yes ] && ALL_PACKAGES="$ALL_PACKAGES $EVAL_PACKAGES"
MISSING=""
for p in $ALL_PACKAGES; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || MISSING="$MISSING $p"
done
if [ -n "$MISSING" ]; then
    if would "apt-get install$MISSING"; then
        apt-get update -q
        # shellcheck disable=SC2086  # one word per package, on purpose
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q $MISSING
    fi
fi
for pair in $TESTED_VERSIONS; do
    p=${pair%%=*}; want=${pair#*=}
    have=$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null || true)
    [ -z "$have" ] || [ "$have" = "$want" ] || warn "$p is $have, the project was tested with $want"
done

# ------------------------------------------------------------- 4. network --

step "4/14  network: management link, Wi-Fi uplink, access point"
# Management link: a static address with no gateway and no DNS, so it never
# takes the default route from the Wi-Fi uplink.
if ! grep -qs "$MGMT_IF" /etc/netplan/*.yaml; then
    cat > "$TMP/01-ethernet.yaml" <<EOF
network:
  version: 2
  ethernets:
    $MGMT_IF:
      # Management link to the development machine. Static, no gateway, no DNS
      # (written by gateway/install.sh).
      dhcp4: false
      addresses:
        - $MGMT_ADDR
EOF
    put_file "$TMP/01-ethernet.yaml" /etc/netplan/01-ethernet.yaml 600 root:root
    NETPLAN_CHANGED=yes
fi
if [ "$TEST_WITHOUT_WIFI" != yes ]; then
    # Wi-Fi uplink: only written when no netplan file configures WAN_IF yet.
    # More networks can be added later with: sudo securepi-add-uplink "Name"
    if ! grep -qs "$WAN_IF" /etc/netplan/*.yaml; then
        if [ "$MODE" = check ]; then
            would "configure the Wi-Fi uplink on $WAN_IF (asks for UPLINK_SSID and its password)" || true
        else
            [ -n "$UPLINK_SSID" ] || read -r -p "Upstream Wi-Fi network name for $WAN_IF: " UPLINK_SSID
            read -r -s -p "Wi-Fi password for \"$UPLINK_SSID\": " UPLINK_PW; echo
            [ ${#UPLINK_PW} -ge 8 ] || die "WPA2 passwords are at least 8 characters"
            CHANGES=$((CHANGES + 1)); say "change: write /etc/netplan/99-wifi.yaml for \"$UPLINK_SSID\""
            # The password goes to python through the environment, never argv.
            UPLINK_SSID="$UPLINK_SSID" UPLINK_PW="$UPLINK_PW" WAN_IF="$WAN_IF" python3 - <<'PY'
import os, yaml
cfg = {"network": {"version": 2, "wifis": {os.environ["WAN_IF"]: {
    "dhcp4": True,
    "access-points": {os.environ["UPLINK_SSID"]: {"password": os.environ["UPLINK_PW"]}}}}}}
old = os.umask(0o077)
with open("/etc/netplan/99-wifi.yaml", "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
os.umask(old)
PY
            unset UPLINK_PW
            NETPLAN_CHANGED=yes
        fi
    fi
fi
if [ "${NETPLAN_CHANGED:-no}" = yes ] && [ "$MODE" = apply ]; then
    netplan generate
    # Applying can briefly drop links; run this installer from the local
    # console or over the management link it has just configured.
    netplan apply
    sleep 5
fi

# The access point: a virtual interface ap0 on the same radio, 10.10.0.1/24.
put_rendered "$REPO/gateway/securepi-ap0-up" /usr/local/sbin/securepi-ap0-up 755 root:root
put_rendered "$REPO/gateway/systemd/securepi-ap0.service" /etc/systemd/system/securepi-ap0.service 644 root:root
if [ "$TEST_WITHOUT_WIFI" = yes ]; then
    # No radio in a VM: a dummy ap0 with the AP's address, so everything that
    # binds 10.10.0.1 (DNS filter, console, proxy) can be installed and tested.
    if ! ip link show ap0 >/dev/null 2>&1; then
        if would "create a dummy ap0 with 10.10.0.1/24 (TEST_WITHOUT_WIFI)"; then
            ip link add ap0 type dummy
            ip addr add 10.10.0.1/24 dev ap0
            ip link set ap0 up
        fi
    fi
else
    if [ ! -f /etc/hostapd/hostapd.conf ]; then
        if [ "$MODE" = check ]; then
            would "write /etc/hostapd/hostapd.conf for \"$AP_SSID\" (asks for AP_PASSPHRASE)" || true
        else
            if [ -z "${AP_PASSPHRASE:-}" ]; then
                read -r -s -p "Passphrase for the $AP_SSID access point (8-63 characters): " AP_PASSPHRASE; echo
            fi
            [ ${#AP_PASSPHRASE} -ge 8 ] && [ ${#AP_PASSPHRASE} -le 63 ] || die "the AP passphrase must be 8-63 characters"
            sed -e "s/^ssid=.*/ssid=$AP_SSID/" -e "s/^country_code=.*/country_code=$AP_COUNTRY/" \
                -e "s/^channel=.*/channel=$AP_CHANNEL/" "$REPO/gateway/hostapd.conf" \
                | grep -v '^wpa_passphrase=' > "$TMP/hostapd.conf"
            echo "wpa_passphrase=$AP_PASSPHRASE" >> "$TMP/hostapd.conf"
            unset AP_PASSPHRASE
            # 600: the file holds the Wi-Fi passphrase (STAGE8-RECORD.md M-5).
            put_file "$TMP/hostapd.conf" /etc/hostapd/hostapd.conf 600 root:root
        fi
    else
        # Never replace an existing config (it holds the real passphrase, and
        # securepi-ap-follow-uplink manages its channel). Check what matters.
        grep -q '^ap_isolate=1' /etc/hostapd/hostapd.conf || warn "/etc/hostapd/hostapd.conf has no ap_isolate=1 (client isolation, step 1.7)"
        grep -q '^interface=ap0' /etc/hostapd/hostapd.conf || warn "/etc/hostapd/hostapd.conf does not use interface=ap0"
        if [ "$(stat -c %a /etc/hostapd/hostapd.conf)" != 600 ]; then
            if would "chmod 600 /etc/hostapd/hostapd.conf (it holds the Wi-Fi passphrase; is $(stat -c %a /etc/hostapd/hostapd.conf))"; then
                chmod 600 /etc/hostapd/hostapd.conf
            fi
        fi
    fi
    # No /etc/default/hostapd needed: Ubuntu 24.04's hostapd.service already
    # sets DAEMON_CONF=/etc/hostapd/hostapd.conf.
    # Ubuntu ships hostapd.service masked until it has a configuration.
    if [ "$(systemctl is-enabled hostapd 2>/dev/null || true)" = masked ]; then
        if would "unmask hostapd"; then systemctl unmask hostapd >/dev/null 2>&1; fi
    fi
    put_rendered "$REPO/gateway/securepi-ap-follow-uplink" /usr/local/sbin/securepi-ap-follow-uplink 755 root:root
    put_rendered "$REPO/gateway/securepi-ap-follow-uplink.service" /etc/systemd/system/securepi-ap-follow-uplink.service 644 root:root
    put_rendered "$REPO/gateway/securepi-add-uplink" /usr/local/sbin/securepi-add-uplink 755 root:root
    reload_units
    for unit in securepi-ap0 hostapd securepi-ap-follow-uplink; do ensure_enabled $unit; done
    for unit in securepi-ap0 hostapd securepi-ap-follow-uplink; do ensure_active $unit; done
fi
reload_units

# ------------------------------------------------------------ 5. firewall --

step "5/14  firewall (/etc/nftables.conf)"
render "$REPO/gateway/nftables.conf" > "$TMP/nftables.conf"
if ! cmp -s "$TMP/nftables.conf" /etc/nftables.conf; then
    nft -c -f "$TMP/nftables.conf" || die "gateway/nftables.conf does not load (nft -c); nothing changed"
    put_file "$TMP/nftables.conf" /etc/nftables.conf 644 root:root
    if [ "$MODE" = apply ]; then
        # A full load flushes the dynamic sets (quarantine, enrolled, DoH
        # resolvers); the orchestrator restores its sets within one cycle and
        # securepi-doh-refresh refills the DoH set (run below).
        nft -f /etc/nftables.conf
    fi
fi
ensure_enabled nftables

# ------------------------------------------------ 6. users and data dirs --

step "6/14  service user, data directories, privileged helper (setup-privilege-separation.sh)"
NEED_PRIVSEP=no
getent group securepi >/dev/null || NEED_PRIVSEP=yes
getent passwd securepi-web >/dev/null || NEED_PRIVSEP=yes
cmp -s "$REPO/gateway/securepi-web-helper" /usr/local/sbin/securepi-web-helper 2>/dev/null || NEED_PRIVSEP=yes
cmp -s "$REPO/gateway/securepi-web-sudoers" /etc/sudoers.d/securepi-web 2>/dev/null || NEED_PRIVSEP=yes
for d in /var/lib/securepi /var/lib/securepi-dpi /etc/securepi; do
    [ "$(stat -c '%a %U:%G' "$d" 2>/dev/null)" = "2770 root:securepi" ] || NEED_PRIVSEP=yes
done
if [ "$NEED_PRIVSEP" = yes ]; then
    if would "run gateway/setup-privilege-separation.sh (group securepi, user securepi-web, data directories, helper, sudoers)"; then
        bash "$REPO/gateway/setup-privilege-separation.sh"
    fi
fi

# ------------------------------------------------------------ 7. app code --

step "7/14  console, ingest and engine code (/opt/securepi), command-line tools"
ensure_dir /opt/securepi 755 root:root
# The same copy `make deploy` makes (no --delete: files are only added or
# updated), plus the two gateway scripts its units run.
CODE_CHANGES=$(rsync -rlpc --dry-run --itemize-changes --no-owner --no-group --exclude '__pycache__' \
    --exclude '*.pyc' --exclude '.DS_Store' "$REPO/app/" "$REPO/dpi/adfilter_rules.py" /opt/securepi/ \
    | grep -c '^>f' || true)
if [ "$CODE_CHANGES" -gt 0 ]; then
    if would "copy $CODE_CHANGES changed file(s) from app/ (and dpi/adfilter_rules.py) to /opt/securepi"; then
        rsync -rlpc --no-owner --no-group --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' \
            "$REPO/app/" "$REPO/dpi/adfilter_rules.py" /opt/securepi/
        chown -R root:root /opt/securepi
        RESTART_APP=yes
    fi
fi
put_file "$REPO/gateway/setup-test-harness.sh" /opt/securepi/setup-test-harness.sh 755 root:root
put_file "$REPO/gateway/refresh-doh-set.sh" /opt/securepi/refresh-doh-set.sh 755 root:root
put_rendered "$REPO/gateway/securepi" /usr/local/bin/securepi 755 root:root
put_file "$REPO/gateway/battery" /usr/local/bin/battery 755 root:root
put_file "$REPO/gateway/sni-capture" /usr/local/bin/sni-capture 755 root:root
if [ "$(readlink /usr/local/bin/securepi-db 2>/dev/null)" != /opt/securepi/status.py ]; then
    if would "link /usr/local/bin/securepi-db -> /opt/securepi/status.py"; then
        ln -sf /opt/securepi/status.py /usr/local/bin/securepi-db
    fi
fi

# ------------------------------------------------- 8. TLS and credentials --

step "8/14  console TLS certificate and passwords"
if [ ! -f /opt/securepi-tls/ca.crt ]; then
    if would "create the console's CA and certificate (gateway/generate-console-tls.sh)"; then
        bash "$REPO/gateway/generate-console-tls.sh" >/dev/null
    fi
fi
if [ ! -f /etc/securepi/console-password ]; then
    if would "create the console password (user securepi; shown once at the end)"; then
        NEW_CONSOLE_PASSWORD=$(random_secret)
        # Hashed by the console's own code (PBKDF2-SHA256, session_auth.py);
        # the plaintext goes through the environment, never argv.
        PW="$NEW_CONSOLE_PASSWORD" python3 - <<'PY'
import os, sys
sys.path.insert(0, "/opt/securepi")
import session_auth
session_auth.write_password_file("/etc/securepi/console-password",
                                 session_auth.hash_password(os.environ["PW"]))
PY
        chown root:securepi /etc/securepi/console-password
        chmod 660 /etc/securepi/console-password
    fi
fi
if [ ! -f /etc/securepi/dns-password ]; then
    if [ -f /opt/AdGuardHome/AdGuardHome.yaml ]; then
        warn "/opt/AdGuardHome/AdGuardHome.yaml exists but /etc/securepi/dns-password does not: the console cannot talk to the DNS filter. Put the 'securepi' user's plaintext password in /etc/securepi/dns-password (root:securepi 660)."
    elif would "create the DNS filter's admin password (/etc/securepi/dns-password)"; then
        random_secret > /etc/securepi/dns-password
        chown root:securepi /etc/securepi/dns-password
        chmod 660 /etc/securepi/dns-password
    fi
fi

# -------------------------------------------------- 9. the DNS filter --

step "9/14  DNS filter and DHCP: AdGuard Home $AGH_VERSION"
if [ -x /opt/AdGuardHome/AdGuardHome ] && /opt/AdGuardHome/AdGuardHome --version 2>/dev/null | grep -q "version $AGH_VERSION\$"; then
    :
else
    if would "download AdGuard Home $AGH_VERSION ($ARCH), verify its SHA-256 and install it in /opt/AdGuardHome"; then
        case "$ARCH" in
            amd64) want_sha=$AGH_SHA256_amd64 ;;
            arm64) want_sha=$AGH_SHA256_arm64 ;;
        esac
        curl -fsSL --max-time 300 -o "$TMP/agh.tar.gz" \
            "https://github.com/AdguardTeam/AdGuardHome/releases/download/$AGH_VERSION/AdGuardHome_linux_$ARCH.tar.gz"
        echo "$want_sha  $TMP/agh.tar.gz" | sha256sum -c --quiet - || die "AdGuard Home download failed its SHA-256 check"
        tar -xzf "$TMP/agh.tar.gz" -C "$TMP"
        install -d -m 700 -o root -g root /opt/AdGuardHome
        install -m 755 -o root -g root "$TMP/AdGuardHome/AdGuardHome" /opt/AdGuardHome/AdGuardHome
        RESTART_AGH=yes
    fi
fi
if [ ! -f /opt/AdGuardHome/AdGuardHome.yaml ]; then
    if would "write /opt/AdGuardHome/AdGuardHome.yaml from gateway/adguard/AdGuardHome.yaml.template"; then
        # bcrypt hash of the admin password, as AdGuard Home's documentation
        # recommends generating it (htpasswd from apache2-utils).
        HASH=$(htpasswd -inBC 10 "" < /etc/securepi/dns-password | tr -d ':\n')
        sed "s|ADGUARD_PASSWORD_HASH_PLACEHOLDER|$HASH|" "$REPO/gateway/adguard/AdGuardHome.yaml.template" \
            | grep -v '^#' > "$TMP/AdGuardHome.yaml"
        install -d -m 700 -o root -g root /opt/AdGuardHome
        install -m 600 -o root -g root "$TMP/AdGuardHome.yaml" /opt/AdGuardHome/AdGuardHome.yaml
        RESTART_AGH=yes
    fi
else
    # Never overwritten; check what the rest of the system depends on.
    grep -q '^  address: 127.0.0.1:3000$' /opt/AdGuardHome/AdGuardHome.yaml || warn "AdGuard Home's admin API is not on 127.0.0.1:3000 (app/adguard.py expects it)"
    grep -q '^  - name: securepi$' /opt/AdGuardHome/AdGuardHome.yaml || warn "AdGuard Home has no admin user 'securepi' (app/adguard.py logs in as it)"
fi
put_file "$REPO/gateway/systemd/AdGuardHome.service" /etc/systemd/system/AdGuardHome.service 644 root:root
put_file "$REPO/gateway/AdGuardHome.service.d/securepi-wait-for-ap0.conf" \
    /etc/systemd/system/AdGuardHome.service.d/securepi-wait-for-ap0.conf 644 root:root
reload_units
ensure_enabled AdGuardHome
if [ "${RESTART_AGH:-no}" = yes ] && [ "$MODE" = apply ]; then systemctl restart AdGuardHome; fi
ensure_active AdGuardHome

# ------------------------------------------------------------ 10. the IDS --

step "10/14  IDS: Suricata configuration, rules, log rotation, test harness"
PATCH="$REPO/gateway/suricata-securepi.patch"
if patch --dry-run -R -s -f /etc/suricata/suricata.yaml < "$PATCH" >/dev/null 2>&1; then
    :   # the project's four changes are already in place
elif patch --dry-run -s -f /etc/suricata/suricata.yaml < "$PATCH" >/dev/null 2>&1; then
    if would "apply gateway/suricata-securepi.patch to /etc/suricata/suricata.yaml (HOME_NET, community-id, DHCP extended, capture on ap0 and veth-atk)"; then
        cp -p /etc/suricata/suricata.yaml "/etc/suricata/suricata.yaml.bak-install-$TS"
        patch -s /etc/suricata/suricata.yaml < "$PATCH"
        RESTART_IDS=yes
    fi
else
    warn "/etc/suricata/suricata.yaml has changes gateway/suricata-securepi.patch does not match; apply its four changes by hand"
fi
put_file "$REPO/gateway/systemd/securepi-test-harness.service" /etc/systemd/system/securepi-test-harness.service 644 root:root
put_file "$REPO/gateway/systemd/suricata.service.d/override.conf" /etc/systemd/system/suricata.service.d/override.conf 644 root:root
reload_units
ensure_enabled securepi-test-harness
ensure_active securepi-test-harness
if [ ! -s /var/lib/suricata/rules/suricata.rules ]; then
    if would "download the ET Open rules (suricata-update)"; then
        suricata-update -q || warn "suricata-update failed - the IDS has no rules until it succeeds"
        RESTART_IDS=yes
    fi
fi
# IDS log rotation by size and day, independent of AC power (3 October 2026).
if ! cmp -s "$REPO/gateway/logrotate-suricata.conf" /etc/securepi/logrotate-suricata.conf 2>/dev/null \
   || ! cmp -s "$REPO/gateway/securepi-ids-logrotate.timer" /etc/systemd/system/securepi-ids-logrotate.timer 2>/dev/null \
   || ! cmp -s "$REPO/gateway/securepi-ids-logrotate.service" /etc/systemd/system/securepi-ids-logrotate.service 2>/dev/null \
   || [ -f /etc/logrotate.d/suricata ]; then
    if would "install the IDS log rotation (gateway/install-ids-logrotate.sh)"; then
        bash "$REPO/gateway/install-ids-logrotate.sh" >/dev/null
    fi
fi
ensure_enabled suricata
if [ "${RESTART_IDS:-no}" = yes ] && [ "$MODE" = apply ]; then systemctl restart suricata; fi
ensure_active suricata

# ---------------------------------------------------------- 11. database --

step "11/14  database (/var/lib/securepi/securepi.db)"
if [ ! -f /var/lib/securepi/securepi.db ]; then
    if would "create the database from /opt/securepi/schema.sql"; then
        python3 -c "import sys; sys.path.insert(0, '/opt/securepi'); import ingest; ingest.open_db().close()"
        # 664 and group securepi so the console (securepi-web) can write it;
        # SQLite gives its -wal and -shm files the same permissions.
        chown root:securepi /var/lib/securepi/securepi.db
        chmod 664 /var/lib/securepi/securepi.db
    fi
fi

# ------------------------------------------------------- 12. core services --

step "12/14  core services and timers"
for unit in securepi-ingest.service securepi-engine.service securepi-static.service \
            securepi-doh-refresh.service securepi-doh-refresh.timer \
            securepi-intel-refresh.service securepi-intel-refresh.timer; do
    put_file "$REPO/gateway/systemd/$unit" "/etc/systemd/system/$unit" 644 root:root
done
put_file "$REPO/gateway/securepi-web.service" /etc/systemd/system/securepi-web.service 644 root:root
if [ -e /sys/class/backlight/intel_backlight/brightness ]; then
    # A laptop used as a headless gateway: panel off while it runs.
    put_file "$REPO/gateway/systemd/securepi-backlight-off.service" /etc/systemd/system/securepi-backlight-off.service 644 root:root
    BACKLIGHT=yes
fi
reload_units
for unit in securepi-ingest securepi-engine securepi-web securepi-static \
            securepi-doh-refresh.timer securepi-intel-refresh.timer; do
    ensure_enabled $unit
done
[ "${BACKLIGHT:-no}" = yes ] && ensure_enabled securepi-backlight-off
if [ "${RESTART_APP:-no}" = yes ] && [ "$MODE" = apply ]; then
    # The order make deploy uses: ingest owns the schema the other two read.
    systemctl restart securepi-ingest securepi-engine securepi-web 2>/dev/null || true
fi
for unit in securepi-ingest securepi-engine securepi-web securepi-static \
            securepi-doh-refresh.timer securepi-intel-refresh.timer; do
    ensure_active $unit
done
# First fill of the DoH resolver set and the threat-intel blocklist (both
# also run daily from their timers). Failures here are not fatal.
# nftables.conf seeds the DoH set with 14 well-known resolvers; a refresh
# loads ~1,400 from HaGeZi's list (refresh-doh-set.sh refuses fewer than
# 500), so anything under 500 means "not refreshed since the ruleset was
# last loaded". Since M-15 (STAGE8-RECORD.md) the timer also runs 2 minutes
# after every boot, so this is only for a first install or a manual
# `nft -f /etc/nftables.conf`.
DOH_COUNT=$(nft -j list set inet filter doh_resolvers 2>/dev/null | jq '.nftables[1].set.elem | length' 2>/dev/null || echo 0)
if [ "${DOH_COUNT:-0}" -lt 500 ]; then
    if would "refresh the DoH resolver set (it has $DOH_COUNT entries, only the static seed)"; then
        /opt/securepi/refresh-doh-set.sh || warn "DoH set refresh failed (retried daily)"
    fi
fi
if [ ! -s /opt/securepi/static/ioc-domains.txt ]; then
    if would "first threat-intel refresh (securepi-intel-refresh.service)"; then
        systemctl start securepi-intel-refresh.service || warn "threat-intel refresh failed (retried daily)"
    fi
fi

# ------------------------------------------- 13. HTTPS inspection (off) --

step "13/14  HTTPS inspection, installed in its off state (dpi/)"
if [ "$INSTALL_DPI" = yes ]; then
    DPI_DIFF=no
    if [ -x /opt/securepi-dpi/bin/python3 ]; then
        /opt/securepi-dpi/bin/python3 -m pip freeze --disable-pip-version-check 2>/dev/null | sort > "$TMP/dpi-have"
        grep -v '^#' "$REPO/dpi/requirements-dpi.txt" | grep . | sort > "$TMP/dpi-want"
        cmp -s "$TMP/dpi-have" "$TMP/dpi-want" || { DPI_DIFF=yes; say "the proxy environment's packages differ from dpi/requirements-dpi.txt"; }
    else
        DPI_DIFF=yes
    fi
    for pair in securepi_adfilter.py:/opt/securepi-dpi/securepi_adfilter.py \
                adfilter_rules.py:/opt/securepi-dpi/adfilter_rules.py \
                dpi-gate.sh:/opt/securepi-dpi/dpi-gate.sh \
                securepi-dpi.service:/etc/systemd/system/securepi-dpi.service \
                securepi-ca-server.service:/etc/systemd/system/securepi-ca-server.service; do
        cmp -s "$REPO/dpi/${pair%%:*}" "${pair#*:}" 2>/dev/null || { DPI_DIFF=yes; say "differs: ${pair#*:}"; }
    done
    [ -f /var/lib/securepi-dpi/device-sites.json ] || DPI_DIFF=yes
    [ "$(stat -c %U:%G /var/log/securepi 2>/dev/null)" = root:root ] || { DPI_DIFF=yes; say "/var/log/securepi is not root:root"; }
    if [ "$DPI_DIFF" = yes ]; then
        if would "install or update the proxy (dpi/deploy-dpi.sh; nothing is enrolled, so nothing is decrypted)"; then
            bash "$REPO/dpi/deploy-dpi.sh"
        fi
    fi
    if ! cmp -s "$REPO/dpi/privacy_canary.py" /opt/securepi-dpi/privacy_canary.py 2>/dev/null \
       || ! cmp -s "$REPO/dpi/securepi-privacy-canary.service" /etc/systemd/system/securepi-privacy-canary.service 2>/dev/null; then
        if would "install or update the privacy canary (dpi/deploy-privacy-canary.sh)"; then
            bash "$REPO/dpi/deploy-privacy-canary.sh"
        fi
    fi
    # The demo's "canary goes red" helper (docs/DEMO.md); runs only when called.
    if [ -d /opt/securepi-dpi ] || [ "$MODE" = check ]; then
        put_file "$REPO/dpi/canary_demo.py" /opt/securepi-dpi/canary_demo.py 755 root:root
    fi
else
    say "skipped (INSTALL_DPI=$INSTALL_DPI)"
fi

# -------------------------------------------------- 14. evaluation tools --

step "14/14  evaluation tools (/opt/securepi-eval)"
if [ "$INSTALL_EVAL_TOOLS" = yes ]; then
    ensure_dir /opt/securepi-eval 755 root:root
    for spec in gateway/battery.py:755 gateway/chaos.py:644 gateway/collect_run.sh:755 \
                gateway/run_monitor.py:755 gateway/throughput_sweep.py:755 tools/run_report.py:755 \
                gateway/dns_ab.py:755 gateway/dash_latency.py:755 gateway/demo_attacks.py:755; do
        f=${spec%%:*}
        put_rendered "$REPO/$f" "/opt/securepi-eval/$(basename "$f")" "${spec##*:}" root:root
    done
    put_file "$REPO/gateway/securepi-run-monitor.service" /etc/systemd/system/securepi-run-monitor.service 644 root:root
    reload_units
    if [ "$ENABLE_RUN_MONITOR" = yes ]; then
        ensure_enabled securepi-run-monitor
        ensure_active securepi-run-monitor
    elif systemctl is-enabled --quiet securepi-run-monitor 2>/dev/null; then
        say "securepi-run-monitor is enabled (left as it is; the installer never disables anything)"
    fi
else
    say "skipped (INSTALL_EVAL_TOOLS=$INSTALL_EVAL_TOOLS)"
fi
reload_units

# ------------------------------------------------------------ summary --

echo
echo "================================================================"
if [ "$MODE" = check ]; then
    echo " CHECK ONLY - nothing was changed."
    echo " $CHANGES change(s) would be made, $WARNINGS warning(s)."
else
    echo " Done: $CHANGES change(s) made, $WARNINGS warning(s)."
    echo
    echo " Service check (every always-on service in /opt/securepi/services.list):"
    DOWN=""
    while read -r svc; do
        case "$svc" in ''|\#*) continue ;; esac
        if [ "$TEST_WITHOUT_WIFI" = yes ]; then
            case "$svc" in hostapd|securepi-ap-follow-uplink|securepi-ap0) continue ;; esac
        fi
        [ "$INSTALL_DPI" = yes ] || case "$svc" in securepi-dpi|securepi-privacy-canary|securepi-ca-server) continue ;; esac
        systemctl is-active --quiet "$svc" || DOWN="$DOWN $svc"
    done < /opt/securepi/services.list
    if [ -z "$DOWN" ]; then echo "   all active"; else echo "   NOT active:$DOWN"; fi
    echo "   DNS filter blocks doubleclick.net: $(dig +short +time=3 @10.10.0.1 doubleclick.net | head -1)"
    echo "   console: $(curl -sk -o /dev/null -w '%{http_code}' https://10.10.0.1:8000/login) (200 expected)"
    if [ -n "$NEW_CONSOLE_PASSWORD" ]; then
        echo
        echo " Console password for user 'securepi' (shown ONCE - save it now,"
        echo " then change it on the console's Settings page):"
        echo "   $NEW_CONSOLE_PASSWORD"
    fi
    echo
    echo " Next: docs/INSTALL.md, 'After installing'."
fi
echo "================================================================"
