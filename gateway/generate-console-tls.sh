#!/bin/bash
# SecurePi Gateway - generate the console's own TLS certificate
# (ENHANCEMENT-PLAN.md step 3.2: "TLS on the console (console CA,
# separate from the DPI CA)").
#
# Run this ON THE DELL, once. It creates a private root CA that exists
# only to vouch for THIS gateway's own console, plus a leaf certificate
# the console's web server presents.
#
# This is deliberately NOT the same CA `dpi/deploy-dpi.sh` generates
# (mitmproxy's own, used for step 5.6's HTTPS inspection). That CA lets
# the gateway impersonate any allowlisted site once a device trusts it -
# a much bigger thing to hand out trust for than "this one console is
# who it says it is". Keeping the two separate means trusting the
# console for TLS never implies trusting inspected traffic, and a
# problem with one CA (compromise, expiry, a mistaken --force) never
# touches the other's trust.
#
# Idempotent by refusal, not by silent overwrite: rerunning this without
# --force leaves an existing CA alone, since silently replacing it would
# break trust on every device that already installed the current one -
# the same "no silent, wide-blast-radius default" caution
# ENHANCEMENT-PLAN.md finding A2 already applies to Tier 2 enrollment.
set -e

TLS_DIR=/opt/securepi-tls
FORCE="${1:-}"

if [ -f "$TLS_DIR/ca.crt" ] && [ "$FORCE" != "--force" ]; then
    echo "$TLS_DIR/ca.crt already exists - not overwriting."
    echo "Pass --force to regenerate (this invalidates trust on every"
    echo "device, including the Mac, that already installed the current CA)."
    exit 1
fi

echo "==> 1/3  creating $TLS_DIR"
sudo mkdir -p "$TLS_DIR"
# 755, not 700: matches dpi/deploy-dpi.sh's own CA directory
# (/opt/securepi-dpi/ca, also root:root 755) - the two files that
# actually need protecting (the CA and leaf private keys) are each
# individually 600 below regardless of the directory's own mode, and a
# 700 directory was tried first here, live, and immediately found to
# block even reading the public ca.crt over `scp` as the non-root
# `maheshwari` user - the exact way an operator needs to fetch it to
# trust it on the Mac (see README's "HTTPS only" section).
sudo chmod 755 "$TLS_DIR"

echo "==> 2/3  generating the console CA"
# EC P-256: modern, fast, and universally supported by the two browsers
# this console is actually used from (see the redesign notes in
# NEXT-SESSION.md - Chromium and Safari 18+).
#
# 10-year validity: this CA never signs anything but this gateway's own
# console, so a long local trust anchor is proportionate. Contrast with
# the DPI CA's deliberately SHORT 90-day rotation (step 5.6d) - that one
# is trusted to vouch for OTHER sites' identity, which is exactly the
# kind of trust a short lifetime and forced rotation exists to bound.
sudo openssl ecparam -name prime256v1 -genkey -noout -out "$TLS_DIR/ca.key"
sudo openssl req -x509 -new -key "$TLS_DIR/ca.key" -sha256 -days 3650 \
    -subj "/O=SecurePi Gateway/CN=SecurePi Console CA" \
    -out "$TLS_DIR/ca.crt"

echo "==> 3/3  generating the console's own leaf certificate, signed by that CA"
# SANs cover every address a browser might actually be pointed at:
# 10.10.0.1 for a device browsing directly on SecurePi-Test, and both
# localhost and 127.0.0.1 for the Mac's SSH tunnel (mac-tunnel.sh) -
# TLS hostname verification checks the URL's own host against these,
# not the address traffic is actually routed to underneath.
sudo openssl ecparam -name prime256v1 -genkey -noout -out "$TLS_DIR/console.key"
sudo openssl req -new -key "$TLS_DIR/console.key" \
    -subj "/O=SecurePi Gateway/CN=SecurePi Gateway Console" \
    -out "$TLS_DIR/console.csr"
sudo tee "$TLS_DIR/console.ext" >/dev/null <<'EXT'
subjectAltName = DNS:localhost, IP:10.10.0.1, IP:127.0.0.1
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE
EXT
# 825 days: the longest TLS leaf validity Apple's ATS will trust even
# once its issuing CA is trusted (checked against Apple's published
# requirement before picking this number, not guessed) - the Mac is
# this console's primary browser.
sudo openssl x509 -req -in "$TLS_DIR/console.csr" -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" \
    -CAcreateserial -days 825 -sha256 -extfile "$TLS_DIR/console.ext" \
    -out "$TLS_DIR/console.crt"
sudo rm -f "$TLS_DIR/console.csr" "$TLS_DIR/console.ext"

# Explicit filenames, not a "$TLS_DIR"/*.key glob: $TLS_DIR is
# chmod 700 root-owned, so the invoking (non-root) shell can't list its
# contents to expand a glob before sudo ever runs - a real bug caught
# live on the gateway's first run, where it left the literal,
# unexpanded pattern passed to chown/chmod, which then failed with
# "No such file or directory" (harmlessly: openssl's own default
# permissions - 600 on keys, 644 on certs, root:root throughout, since
# every file above was written by a sudo'd process - already matched
# what these lines were trying to enforce, confirmed with `sudo ls -la`
# before this was fixed rather than assumed safe).
sudo chown root:root "$TLS_DIR/ca.key" "$TLS_DIR/ca.crt" "$TLS_DIR/console.key" "$TLS_DIR/console.crt"
sudo chmod 600 "$TLS_DIR/ca.key" "$TLS_DIR/console.key"
sudo chmod 644 "$TLS_DIR/ca.crt" "$TLS_DIR/console.crt"

# console.key needs to be group-readable once step 3.3's privilege
# separation is in place - the web console (securepi-web, unprivileged
# since that step) loads this file itself to serve TLS, and a 600
# root-only key blocked it outright the first time these two steps'
# ordering was actually exercised live (this script ran before the
# 3.3 group existed, so the key was left root-only until 3.3's own
# setup script - or a rerun of this one, after that group exists -
# fixed it). ca.key is deliberately left untouched at 600 root-only:
# nothing at runtime ever needs it, only a future re-run of this
# script to sign a new leaf certificate.
if getent group securepi >/dev/null; then
    sudo chown root:securepi "$TLS_DIR/console.key"
    sudo chmod 640 "$TLS_DIR/console.key"
fi

echo
echo "================================================================"
echo " DONE."
echo
echo " Point the console at the new certificate:"
echo "   sudo cp gateway/securepi-web.service /etc/systemd/system/securepi-web.service"
echo "   sudo systemctl daemon-reload"
echo "   sudo systemctl restart securepi-web"
echo
echo " Trust the CA on the Mac, once, so there's no browser warning:"
echo "   scp maheshwari@192.168.2.5:$TLS_DIR/ca.crt /tmp/securepi-console-ca.crt"
echo "   sudo security add-trusted-cert -d -r trustRoot \\"
echo "       -k /Library/Keychains/System.keychain /tmp/securepi-console-ca.crt"
echo
echo " Then browse: https://localhost:8000 (via mac-tunnel.sh), or"
echo "              https://10.10.0.1:8000  (directly on SecurePi-Test)"
echo "================================================================"
